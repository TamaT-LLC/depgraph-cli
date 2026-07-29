#![feature(rustc_private)]

extern crate rustc_driver;
extern crate rustc_interface;
extern crate rustc_middle;
#[macro_use]
extern crate rustc_public;

mod rustc_private_bridge;

use std::{
    collections::{BTreeMap, HashMap},
    env,
    fs::{self, OpenOptions},
    io::Write,
    path::{Component, Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use rustc_public::{
    CrateDef, CrateItem, ItemKind, all_local_items,
    mir::{
        Body, ConstOperand, NonDivergingIntrinsic, Operand, Place, ProjectionElem, Rvalue,
        StatementKind, TerminatorKind,
        mono::{Instance, InstanceKind as PublicInstanceKind},
    },
    ty::{ConstantKind, IntTy, RigidTy, Ty, TyConstKind, TyKind, UintTy},
};
use serde::Serialize;
use sha2::{Digest, Sha256};

const SCHEMA_VERSION: &str = "depgraph-rust-compiler-precise-v1";
const RUSTC_COMMIT: &str = "3d50c25bc66853bf0ad205529d0f305a1d841b5e";
const MAX_BODIES: usize = 100_000;
const MAX_ATOMS: usize = 1_000_000;
const MAX_OUTPUT_BYTES: usize = 16 * 1024 * 1024;
const MAX_TYPE_DEPTH: usize = 32;

#[derive(Clone, Serialize)]
struct Unit {
    schema_version: &'static str,
    digest: String,
    attempt_digest: String,
    invocation_id: String,
    unit_id: String,
    package_id: String,
    target_digest: String,
    source_path: String,
    source_sha256: String,
    profile_digest: String,
    compiler_pack_manifest_sha256: String,
    rustc_commit: &'static str,
    query_capabilities: Vec<String>,
    instances: Vec<CompilerInstance>,
    calls: Vec<CompilerCall>,
    bodies: Vec<MirBody>,
    unsupported: Vec<Unsupported>,
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
    instances: &'a [CompilerInstance],
    calls: &'a [CompilerCall],
    bodies: &'a [MirBody],
    unsupported: &'a [Unsupported],
}

#[derive(Clone, Serialize)]
struct CompilerInstance {
    instance_id: String,
    kind: CompilerInstanceKind,
    variant: String,
    definition_path: String,
    symbol_name: String,
    generic_arguments: Vec<CompilerGenericArgument>,
    definition: Option<Definition>,
    compiler_generated: bool,
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum CompilerInstanceKind {
    Function,
    Method,
    Closure,
    Coroutine,
    Static,
    Shim,
    DropGlue,
    Intrinsic,
    External,
}

#[derive(Clone, Serialize)]
struct CompilerGenericArgument {
    kind: CompilerGenericArgumentKind,
    value: String,
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum CompilerGenericArgumentKind {
    Type,
    Constant,
}

#[derive(Clone, Serialize)]
struct CompilerCall {
    call_id: String,
    caller_instance_id: String,
    block_ordinal: u32,
    operation_ordinal: u32,
    relation: CompilerCallRelation,
    resolution: CompilerCallResolution,
    evidence: CompilerCallEvidence,
    target_instance_ids: Vec<String>,
    span: Option<Span>,
    reason_code: Option<CompilerCallReason>,
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum CompilerCallRelation {
    Calls,
    MayCall,
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum CompilerCallResolution {
    Resolved,
    Candidate,
    UnknownTarget,
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum CompilerCallEvidence {
    Observed,
    Candidate,
    Unknown,
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum CompilerCallReason {
    FnPointerUnbounded,
    VirtualDispatch,
    UnresolvedInstance,
    UnsupportedCallee,
}

#[derive(Clone, Serialize)]
struct MirBody {
    body_id: String,
    kind: BodyKind,
    definition: Definition,
    span: Span,
    types: Vec<MirType>,
    constants: Vec<Constant>,
    locals: Vec<Local>,
    places: Vec<MirPlace>,
    blocks: Vec<Block>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "snake_case")]
enum BodyKind {
    Function,
    Method,
    Closure,
    Async,
    Coroutine,
    Const,
    Static,
}

#[derive(Clone, Serialize)]
struct Definition {
    definition_id: String,
    path: String,
    span: Span,
}

#[derive(Clone, Serialize)]
struct Span {
    source_path: String,
    source_sha256: String,
    start_line: u32,
    start_column: u32,
    end_line: u32,
    end_column: u32,
}

#[derive(Clone, Serialize)]
struct MirType {
    type_id: String,
    kind: String,
    arguments: Vec<String>,
    definition_id: Option<String>,
    mutability: Option<String>,
    value: Option<String>,
    unsupported_reason: Option<String>,
}

#[derive(Clone, Serialize)]
struct Constant {
    constant_id: String,
    type_id: String,
    kind: String,
    value: Option<String>,
    definition_id: Option<String>,
    unsupported_reason: Option<String>,
    span: Span,
}

#[derive(Clone, Serialize)]
struct Local {
    local_id: String,
    ordinal: u32,
    role: String,
    type_id: String,
    span: Span,
}

#[derive(Clone, Serialize)]
struct MirPlace {
    place_id: String,
    local_id: String,
    projections: Vec<Projection>,
    type_id: String,
}

#[derive(Clone, Serialize)]
struct Projection {
    kind: String,
    index: Option<u64>,
    from: Option<u64>,
    to: Option<u64>,
    from_end: Option<bool>,
    type_id: Option<String>,
    local_id: Option<String>,
}

#[derive(Clone, Serialize)]
struct Block {
    block_id: String,
    ordinal: u32,
    operations: Vec<Operation>,
    successors: Vec<String>,
}

#[derive(Clone, Serialize)]
struct Operation {
    operation_id: String,
    ordinal: u32,
    kind: String,
    span: Span,
    places: Vec<String>,
    constants: Vec<String>,
    unsupported_reason: Option<String>,
}

#[derive(Clone, Serialize, PartialEq, Eq, PartialOrd, Ord)]
struct Unsupported {
    scope_id: String,
    construct_kind: String,
    reason_code: String,
}

struct ExtractContext {
    workspace: PathBuf,
    cargo_home: PathBuf,
    fallback_span: Option<Span>,
    body_id: String,
    types: BTreeMap<String, MirType>,
    constants: BTreeMap<String, Constant>,
    places: BTreeMap<String, MirPlace>,
    local_ids: Vec<String>,
    unsupported: Vec<Unsupported>,
}

fn main() {
    if let Err(error) = execute() {
        eprintln!("depgraph-rustc-query: {error:#}");
        std::process::exit(87);
    }
}

fn execute() -> Result<()> {
    validate_environment_identity()?;
    let mut args = env::args().collect::<Vec<_>>();
    let rustc = required_absolute_file("DEPGRAPH_QUERY_RUSTC")?;
    args[0] = rustc.to_string_lossy().into_owned();
    if !args
        .iter()
        .any(|argument| argument == "--sysroot" || argument.starts_with("--sysroot="))
    {
        let sysroot = rustc
            .parent()
            .and_then(Path::parent)
            .context("attested rustc path has no sysroot")?;
        args.push("--sysroot".to_owned());
        args.push(sysroot.to_string_lossy().into_owned());
    }
    run!(&args, || {
        let result = extract_unit();
        ControlFlow::<(), Result<()>>::Continue(result)
    })
    .map_err(|error| anyhow::anyhow!("pinned compiler query failed: {error:?}"))?
}

fn extract_unit() -> Result<()> {
    let mut bodies = Vec::new();
    let mut unsupported = Vec::new();
    let unit_id = required_text("DEPGRAPH_QUERY_UNIT_ID")?;
    let package_id = required_text("DEPGRAPH_QUERY_PACKAGE_ID")?;
    let target_digest = required_digest("DEPGRAPH_QUERY_TARGET_DIGEST")?;
    let profile_digest = required_digest("DEPGRAPH_QUERY_PROFILE_DIGEST")?;
    let workspace = required_absolute_directory("DEPGRAPH_QUERY_WORKSPACE_ROOT")?;
    let cargo_home = required_absolute_directory("DEPGRAPH_QUERY_CARGO_HOME")?;
    let compiler_pack_manifest_sha256 = required_digest("DEPGRAPH_QUERY_PACK_MANIFEST_SHA256")?;
    let (mono_items, global_asm_count) = rustc_private_bridge::collect_mono_items();
    if global_asm_count != 0 {
        bail!("compiler-selected global assembly is outside the typed mono-item contract");
    }
    if mono_items.len() > MAX_ATOMS {
        bail!("compiler-selected mono item count exceeds its limit");
    }
    let identity = InstanceIdentityContext {
        unit_id: &unit_id,
        package_id: &package_id,
        target_digest: &target_digest,
        profile_digest: &profile_digest,
        compiler_pack_manifest_sha256: &compiler_pack_manifest_sha256,
        workspace: &workspace,
        cargo_home: &cargo_home,
    };
    let mut instance_by_id = BTreeMap::new();
    let mut instance_ids = HashMap::new();
    let mut callable_items = Vec::new();
    for item in mono_items {
        let extracted = reviewed_compiler_instance(item, &identity)?;
        if let rustc_private_bridge::ReviewedMonoItem::Function { instance, .. } = item {
            instance_ids.insert(instance, extracted.instance_id.clone());
            callable_items.push(instance);
        }
        if instance_by_id
            .insert(extracted.instance_id.clone(), extracted)
            .is_some()
        {
            bail!("compiler-selected mono item identity is not unique");
        }
    }
    let mut pending_calls = Vec::new();
    for instance in callable_items {
        let caller_instance_id = instance_ids
            .get(&instance)
            .context("compiler-selected caller identity is unavailable")?;
        if let Some(body) = instance.body() {
            pending_calls.extend(extract_instance_calls(
                instance,
                caller_instance_id,
                &body,
                &workspace,
                &cargo_home,
            )?);
        }
    }
    let mut calls = Vec::with_capacity(pending_calls.len());
    for pending in pending_calls {
        let mut target_instance_ids = Vec::with_capacity(pending.targets.len());
        for target in pending.targets {
            let target_id = if let Some(target_id) = instance_ids.get(&target) {
                target_id.clone()
            } else {
                let extracted = public_compiler_instance(target, &identity)?;
                let target_id = extracted.instance_id.clone();
                instance_by_id.entry(target_id.clone()).or_insert(extracted);
                instance_ids.insert(target, target_id.clone());
                target_id
            };
            target_instance_ids.push(target_id);
        }
        target_instance_ids.sort();
        target_instance_ids.dedup();
        let call_id = digest_json(&(
            pending.caller_instance_id.as_str(),
            pending.block_ordinal,
            pending.operation_ordinal,
            &pending.relation,
            &pending.resolution,
            &pending.evidence,
            &target_instance_ids,
            &pending.span,
            &pending.reason_code,
        ))?;
        calls.push(CompilerCall {
            call_id,
            caller_instance_id: pending.caller_instance_id,
            block_ordinal: pending.block_ordinal,
            operation_ordinal: pending.operation_ordinal,
            relation: pending.relation,
            resolution: pending.resolution,
            evidence: pending.evidence,
            target_instance_ids,
            span: pending.span,
            reason_code: pending.reason_code,
        });
    }
    calls.sort_by(|left, right| left.call_id.cmp(&right.call_id));
    if calls
        .windows(2)
        .any(|window| window[0].call_id == window[1].call_id)
    {
        bail!("compiler call identity is not unique");
    }
    let instances = instance_by_id.into_values().collect::<Vec<_>>();
    for item in all_local_items() {
        if bodies.len() >= MAX_BODIES {
            bail!("typed MIR body count exceeds its limit");
        }
        if let Some(body) = item.body() {
            let extracted = extract_body(
                item,
                body,
                &unit_id,
                &package_id,
                &target_digest,
                &profile_digest,
                &workspace,
                &cargo_home,
            )?;
            unsupported.extend(extracted.1);
            bodies.push(extracted.0);
        }
    }
    bodies.sort_by(|left, right| left.body_id.cmp(&right.body_id));
    unsupported.sort();
    unsupported.dedup();
    let mut unit = Unit {
        schema_version: SCHEMA_VERSION,
        digest: String::new(),
        attempt_digest: required_digest("DEPGRAPH_QUERY_ATTEMPT_DIGEST")?,
        invocation_id: required_digest("DEPGRAPH_QUERY_INVOCATION_ID")?,
        unit_id,
        package_id,
        target_digest,
        source_path: required_text("DEPGRAPH_QUERY_SOURCE_PATH")?,
        source_sha256: required_digest("DEPGRAPH_QUERY_SOURCE_SHA256")?,
        profile_digest,
        compiler_pack_manifest_sha256,
        rustc_commit: RUSTC_COMMIT,
        query_capabilities: vec![
            "monomorphized_call_graph".to_owned(),
            "typed_mir".to_owned(),
        ],
        instances,
        calls,
        bodies,
        unsupported,
    };
    unit.digest = digest_json(&UnitIdentity {
        attempt_digest: &unit.attempt_digest,
        invocation_id: &unit.invocation_id,
        unit_id: &unit.unit_id,
        package_id: &unit.package_id,
        target_digest: &unit.target_digest,
        source_path: &unit.source_path,
        source_sha256: &unit.source_sha256,
        profile_digest: &unit.profile_digest,
        compiler_pack_manifest_sha256: &unit.compiler_pack_manifest_sha256,
        rustc_commit: unit.rustc_commit,
        query_capabilities: &unit.query_capabilities,
        instances: &unit.instances,
        calls: &unit.calls,
        bodies: &unit.bodies,
        unsupported: &unit.unsupported,
    })?;
    let bytes = canonical_json_bytes(&unit)?;
    if bytes.len() > MAX_OUTPUT_BYTES {
        bail!("typed MIR unit exceeds its byte limit");
    }
    let output = required_absolute_directory("DEPGRAPH_QUERY_OUTPUT_DIR")?;
    write_new(
        &output.join(format!("mir-{}.json", unit.invocation_id)),
        &bytes,
    )
}

#[allow(clippy::too_many_arguments)]
fn extract_body(
    item: CrateItem,
    body: Body,
    unit_id: &str,
    package_id: &str,
    target_digest: &str,
    profile_digest: &str,
    workspace: &Path,
    cargo_home: &Path,
) -> Result<(MirBody, Vec<Unsupported>)> {
    let definition_span = convert_span(item.span(), workspace, cargo_home, None)?;
    let path = item.name();
    validate_text(&path)?;
    let definition_id = digest_json(&(
        path.as_str(),
        definition_span.source_path.as_str(),
        definition_span.source_sha256.as_str(),
        definition_span.start_line,
        definition_span.start_column,
        definition_span.end_line,
        definition_span.end_column,
    ))?;
    let definition = Definition {
        definition_id,
        path,
        span: definition_span.clone(),
    };
    let kind = body_kind(item);
    let body_id = digest_json(&(
        unit_id,
        package_id,
        target_digest,
        profile_digest,
        &kind,
        &definition,
    ))?;
    let span = convert_span(body.span, workspace, cargo_home, Some(&definition_span))?;
    let mut context = ExtractContext {
        workspace: workspace.to_path_buf(),
        cargo_home: cargo_home.to_path_buf(),
        fallback_span: Some(definition_span),
        body_id: body_id.clone(),
        types: BTreeMap::new(),
        constants: BTreeMap::new(),
        places: BTreeMap::new(),
        local_ids: Vec::new(),
        unsupported: Vec::new(),
    };

    let argument_count = body.arg_locals().len();
    let mut locals = Vec::with_capacity(body.locals().len());
    for (ordinal, local) in body.local_decls() {
        let ordinal = u32::try_from(ordinal).context("typed MIR local ordinal overflowed")?;
        let local_id = digest_json(&(body_id.as_str(), "local", ordinal))?;
        context.local_ids.push(local_id.clone());
        let type_id = intern_type(&mut context, local.ty, 0)?;
        locals.push(Local {
            local_id,
            ordinal,
            role: if ordinal == 0 {
                "return"
            } else if usize::try_from(ordinal).unwrap_or(usize::MAX) <= argument_count {
                "argument"
            } else {
                "local"
            }
            .to_owned(),
            type_id,
            span: convert_span(
                local.span,
                &context.workspace,
                &context.cargo_home,
                context.fallback_span.as_ref(),
            )?,
        });
    }

    let mut blocks = Vec::with_capacity(body.blocks.len());
    for (block_ordinal, block) in body.blocks.iter().enumerate() {
        let block_ordinal =
            u32::try_from(block_ordinal).context("typed MIR block ordinal overflowed")?;
        let block_id = digest_json(&(body_id.as_str(), "block", block_ordinal))?;
        let mut operations = Vec::with_capacity(block.statements.len() + 1);
        for statement in &block.statements {
            let ordinal =
                u32::try_from(operations.len()).context("typed MIR operation overflowed")?;
            operations.push(statement_operation(
                &mut context,
                &body,
                &block_id,
                ordinal,
                statement,
            )?);
        }
        let ordinal = u32::try_from(operations.len()).context("typed MIR operation overflowed")?;
        operations.push(terminator_operation(
            &mut context,
            &body,
            &block_id,
            ordinal,
            &block.terminator,
        )?);
        let mut successors = block
            .terminator
            .successors()
            .into_iter()
            .map(|target| {
                let target = u32::try_from(target).context("typed MIR successor overflowed")?;
                digest_json(&(body_id.as_str(), "block", target))
            })
            .collect::<Result<Vec<_>>>()?;
        successors.sort();
        successors.dedup();
        blocks.push(Block {
            block_id,
            ordinal: block_ordinal,
            operations,
            successors,
        });
    }
    let mut types = context.types.into_values().collect::<Vec<_>>();
    types.sort_by(|left, right| left.type_id.cmp(&right.type_id));
    let mut constants = context.constants.into_values().collect::<Vec<_>>();
    constants.sort_by(|left, right| left.constant_id.cmp(&right.constant_id));
    let mut places = context.places.into_values().collect::<Vec<_>>();
    places.sort_by(|left, right| left.place_id.cmp(&right.place_id));
    // Keep this admission formula identical to the parent validator: nested
    // projections, operations, and successors are DTO atoms too.
    let nested_atoms = places
        .iter()
        .try_fold(0_usize, |total, place| {
            total.checked_add(place.projections.len())
        })
        .and_then(|total| {
            blocks.iter().try_fold(total, |total, block| {
                total
                    .checked_add(block.operations.len())
                    .and_then(|total| total.checked_add(block.successors.len()))
            })
        });
    let total_atoms = nested_atoms.and_then(|nested_atoms| {
        types
            .len()
            .checked_add(constants.len())
            .and_then(|count| count.checked_add(locals.len()))
            .and_then(|count| count.checked_add(places.len()))
            .and_then(|count| count.checked_add(blocks.len()))
            .and_then(|count| count.checked_add(nested_atoms))
    });
    if total_atoms.is_none_or(|count| count > MAX_ATOMS) {
        bail!("typed MIR body exceeds its atom count limit");
    }
    Ok((
        MirBody {
            body_id,
            kind,
            definition,
            span,
            types,
            constants,
            locals,
            places,
            blocks,
        },
        context.unsupported,
    ))
}

fn body_kind(item: CrateItem) -> BodyKind {
    match item.kind() {
        ItemKind::Const | ItemKind::Ctor(_) => BodyKind::Const,
        ItemKind::Static => BodyKind::Static,
        ItemKind::Fn => match item.ty().kind() {
            TyKind::RigidTy(RigidTy::Closure(..)) => BodyKind::Closure,
            TyKind::RigidTy(RigidTy::Coroutine(..) | RigidTy::CoroutineClosure(..)) => {
                BodyKind::Coroutine
            }
            TyKind::RigidTy(RigidTy::FnDef(function, _)) if function.asyncness().is_async() => {
                BodyKind::Async
            }
            TyKind::RigidTy(RigidTy::FnDef(function, _))
                if function.associated_item().is_some() =>
            {
                BodyKind::Method
            }
            _ => BodyKind::Function,
        },
    }
}

struct InstanceIdentityContext<'a> {
    unit_id: &'a str,
    package_id: &'a str,
    target_digest: &'a str,
    profile_digest: &'a str,
    compiler_pack_manifest_sha256: &'a str,
    workspace: &'a Path,
    cargo_home: &'a Path,
}

struct PendingCall {
    caller_instance_id: String,
    block_ordinal: u32,
    operation_ordinal: u32,
    relation: CompilerCallRelation,
    resolution: CompilerCallResolution,
    evidence: CompilerCallEvidence,
    targets: Vec<Instance>,
    span: Option<Span>,
    reason_code: Option<CompilerCallReason>,
}

fn reviewed_compiler_instance(
    item: rustc_private_bridge::ReviewedMonoItem,
    context: &InstanceIdentityContext<'_>,
) -> Result<CompilerInstance> {
    use rustc_private_bridge::{
        ReviewedInstanceKind as InstanceKind, ReviewedMonoItem, ReviewedShimKind,
    };
    match item {
        ReviewedMonoItem::Function { instance, kind } => {
            let (variant, kind, compiler_generated) = match kind {
                InstanceKind::Item => ("item".to_owned(), source_instance_kind(instance), false),
                InstanceKind::Intrinsic => (
                    "intrinsic".to_owned(),
                    CompilerInstanceKind::Intrinsic,
                    true,
                ),
                InstanceKind::LlvmIntrinsic => (
                    "llvm_intrinsic".to_owned(),
                    CompilerInstanceKind::Intrinsic,
                    true,
                ),
                InstanceKind::Virtual { vtable_index } => (
                    format!("virtual:{vtable_index}"),
                    CompilerInstanceKind::External,
                    true,
                ),
                InstanceKind::Shim(shim) => {
                    let variant = match shim {
                        ReviewedShimKind::Vtable => "shim_vtable",
                        ReviewedShimKind::Reify => "shim_reify",
                        ReviewedShimKind::FnPtr => "shim_fn_ptr",
                        ReviewedShimKind::ClosureOnce => "shim_closure_once",
                        ReviewedShimKind::CoroutineClosure => "shim_coroutine_closure",
                        ReviewedShimKind::ThreadLocal => "shim_thread_local",
                        ReviewedShimKind::FutureDropPoll => "shim_future_drop_poll",
                        ReviewedShimKind::DropGlue => "shim_drop_glue",
                        ReviewedShimKind::Clone => "shim_clone",
                        ReviewedShimKind::FnPtrAddr => "shim_fn_ptr_addr",
                        ReviewedShimKind::AsyncDropGlueCtor => "shim_async_drop_glue_ctor",
                        ReviewedShimKind::AsyncDropGlue => "shim_async_drop_glue",
                    };
                    let kind = if matches!(
                        shim,
                        ReviewedShimKind::DropGlue
                            | ReviewedShimKind::AsyncDropGlueCtor
                            | ReviewedShimKind::AsyncDropGlue
                    ) {
                        CompilerInstanceKind::DropGlue
                    } else {
                        CompilerInstanceKind::Shim
                    };
                    (variant.to_owned(), kind, true)
                }
            };
            compiler_instance(instance, kind, variant, compiler_generated, context)
        }
        ReviewedMonoItem::Static(definition) => {
            let definition_path = definition.name();
            validate_text(&definition_path)?;
            let source_definition = if definition.krate().is_local {
                source_definition(
                    definition_path.clone(),
                    definition.span(),
                    context.workspace,
                    context.cargo_home,
                )
                .ok()
            } else {
                None
            };
            let kind = if definition.krate().is_local {
                CompilerInstanceKind::Static
            } else {
                CompilerInstanceKind::External
            };
            let variant = "static".to_owned();
            let symbol_name = Instance::from(definition).mangled_name();
            validate_text(&symbol_name)?;
            let generic_arguments = Vec::new();
            let compiler_generated = false;
            let mut extracted = CompilerInstance {
                instance_id: String::new(),
                kind,
                variant,
                definition_path,
                symbol_name,
                generic_arguments,
                definition: source_definition,
                compiler_generated,
            };
            extracted.instance_id = compiler_instance_id(context, &extracted)?;
            Ok(extracted)
        }
    }
}

fn public_compiler_instance(
    instance: Instance,
    context: &InstanceIdentityContext<'_>,
) -> Result<CompilerInstance> {
    let (kind, variant, compiler_generated) = match instance.kind {
        PublicInstanceKind::Item => (source_instance_kind(instance), "item".to_owned(), false),
        PublicInstanceKind::Intrinsic => (
            CompilerInstanceKind::Intrinsic,
            "intrinsic".to_owned(),
            true,
        ),
        PublicInstanceKind::LlvmIntrinsic => (
            CompilerInstanceKind::Intrinsic,
            "llvm_intrinsic".to_owned(),
            true,
        ),
        PublicInstanceKind::Virtual { idx } => (
            CompilerInstanceKind::External,
            format!("virtual:{idx}"),
            true,
        ),
        PublicInstanceKind::Shim => (
            CompilerInstanceKind::Shim,
            "shim_public_fallback".to_owned(),
            true,
        ),
    };
    compiler_instance(instance, kind, variant, compiler_generated, context)
}

fn compiler_instance(
    instance: Instance,
    mut kind: CompilerInstanceKind,
    variant: String,
    compiler_generated: bool,
    context: &InstanceIdentityContext<'_>,
) -> Result<CompilerInstance> {
    let definition_path = instance.def.name();
    let symbol_name = instance.mangled_name();
    validate_text(&definition_path)?;
    validate_text(&symbol_name)?;
    validate_text(&variant)?;
    let is_local = instance.def.krate().is_local;
    if !is_local
        && matches!(
            kind,
            CompilerInstanceKind::Function | CompilerInstanceKind::Method
        )
    {
        kind = CompilerInstanceKind::External;
    }
    let generic_arguments = compiler_generic_arguments(&instance.args())?;
    let definition = if is_local && !compiler_generated {
        source_definition(
            definition_path.clone(),
            instance.def.span(),
            context.workspace,
            context.cargo_home,
        )
        .ok()
    } else {
        None
    };
    let mut extracted = CompilerInstance {
        instance_id: String::new(),
        kind,
        variant,
        definition_path,
        symbol_name,
        generic_arguments,
        definition,
        compiler_generated,
    };
    extracted.instance_id = compiler_instance_id(context, &extracted)?;
    Ok(extracted)
}

fn source_instance_kind(instance: Instance) -> CompilerInstanceKind {
    let Ok(item) = CrateItem::try_from(instance) else {
        return if instance.def.krate().is_local {
            CompilerInstanceKind::Function
        } else {
            CompilerInstanceKind::External
        };
    };
    match body_kind(item) {
        BodyKind::Method => CompilerInstanceKind::Method,
        BodyKind::Closure => CompilerInstanceKind::Closure,
        BodyKind::Async | BodyKind::Coroutine => CompilerInstanceKind::Coroutine,
        BodyKind::Function | BodyKind::Const | BodyKind::Static => CompilerInstanceKind::Function,
    }
}

fn compiler_instance_id(
    context: &InstanceIdentityContext<'_>,
    instance: &CompilerInstance,
) -> Result<String> {
    digest_json(&(
        context.unit_id,
        context.package_id,
        context.target_digest,
        context.profile_digest,
        context.compiler_pack_manifest_sha256,
        RUSTC_COMMIT,
        &instance.kind,
        instance.variant.as_str(),
        instance.definition_path.as_str(),
        instance.symbol_name.as_str(),
        &instance.generic_arguments,
        &instance.definition,
        instance.compiler_generated,
    ))
}

fn source_definition(
    path: String,
    span: rustc_public::ty::Span,
    workspace: &Path,
    cargo_home: &Path,
) -> Result<Definition> {
    let span = convert_span(span, workspace, cargo_home, None)?;
    let definition_id = digest_json(&(
        path.as_str(),
        span.source_path.as_str(),
        span.source_sha256.as_str(),
        span.start_line,
        span.start_column,
        span.end_line,
        span.end_column,
    ))?;
    Ok(Definition {
        definition_id,
        path,
        span,
    })
}

fn compiler_generic_arguments(
    arguments: &rustc_public::ty::GenericArgs,
) -> Result<Vec<CompilerGenericArgument>> {
    let mut values = Vec::new();
    for argument in &arguments.0 {
        let (kind, value) = match argument {
            rustc_public::ty::GenericArgKind::Lifetime(_) => continue,
            rustc_public::ty::GenericArgKind::Type(ty) => {
                (CompilerGenericArgumentKind::Type, canonical_type(*ty, 0)?)
            }
            rustc_public::ty::GenericArgKind::Const(value) => (
                CompilerGenericArgumentKind::Constant,
                canonical_type_const(value, 0)?,
            ),
        };
        validate_text(&value)?;
        values.push(CompilerGenericArgument { kind, value });
    }
    Ok(values)
}

fn canonical_generic_arguments(
    arguments: &rustc_public::ty::GenericArgs,
    depth: usize,
) -> Result<String> {
    let mut values = Vec::new();
    for argument in &arguments.0 {
        match argument {
            rustc_public::ty::GenericArgKind::Lifetime(_) => {}
            rustc_public::ty::GenericArgKind::Type(ty) => {
                values.push(format!("type:{}", canonical_type(*ty, depth + 1)?));
            }
            rustc_public::ty::GenericArgKind::Const(value) => {
                values.push(format!("const:{}", canonical_type_const(value, depth + 1)?));
            }
        }
    }
    Ok(values.join(","))
}

fn canonical_type(ty: Ty, depth: usize) -> Result<String> {
    if depth > MAX_TYPE_DEPTH {
        bail!("compiler instance type exceeds its nesting depth limit");
    }
    let value = match ty.kind() {
        TyKind::Param(value) => format!("param:{}:{}", value.index, value.name),
        TyKind::Bound(index, value) => format!("bound:{index}:{}", value.var),
        TyKind::Alias(kind, value) => format!(
            "alias:{}:{}<{}>",
            canonical_alias_name(kind),
            value.def_id.name(),
            canonical_generic_arguments(&value.args, depth + 1)?
        ),
        TyKind::RigidTy(rigid) => match rigid {
            RigidTy::Bool => "bool".to_owned(),
            RigidTy::Char => "char".to_owned(),
            RigidTy::Int(value) => canonical_int_name(value).to_owned(),
            RigidTy::Uint(value) => canonical_uint_name(value).to_owned(),
            RigidTy::Float(value) => canonical_float_name(value).to_owned(),
            RigidTy::Adt(definition, arguments) => format!(
                "adt:{}<{}>",
                definition.name(),
                canonical_generic_arguments(&arguments, depth + 1)?
            ),
            RigidTy::Foreign(definition) => format!("foreign:{}", definition.name()),
            RigidTy::Str => "str".to_owned(),
            RigidTy::Array(element, count) => format!(
                "array:{};{}",
                canonical_type(element, depth + 1)?,
                canonical_type_const(&count, depth + 1)?
            ),
            RigidTy::Pat(base, _) => format!("pattern:{}", canonical_type(base, depth + 1)?),
            RigidTy::Slice(element) => {
                format!("slice:{}", canonical_type(element, depth + 1)?)
            }
            RigidTy::RawPtr(element, mutability) => format!(
                "raw_ptr:{}:{}",
                mutability_name(mutability),
                canonical_type(element, depth + 1)?
            ),
            RigidTy::Ref(_, element, mutability) => {
                format!(
                    "ref:{}:{}",
                    mutability_name(mutability),
                    canonical_type(element, depth + 1)?
                )
            }
            RigidTy::FnDef(definition, arguments) => format!(
                "fn:{}<{}>",
                definition.name(),
                canonical_generic_arguments(&arguments, depth + 1)?
            ),
            RigidTy::FnPtr(signature) => {
                let signature = signature.value;
                let mut values = signature
                    .inputs()
                    .iter()
                    .map(|ty| canonical_type(*ty, depth + 1))
                    .collect::<Result<Vec<_>>>()?;
                values.push(canonical_type(signature.output(), depth + 1)?);
                format!(
                    "fn_ptr:{}:{}:{}:{}",
                    canonical_safety_name(signature.safety),
                    canonical_abi_name(&signature.abi),
                    signature.c_variadic,
                    values.join(",")
                )
            }
            RigidTy::Closure(definition, arguments) => format!(
                "closure:{}<{}>",
                definition.name(),
                canonical_generic_arguments(&arguments, depth + 1)?
            ),
            RigidTy::Coroutine(definition, arguments) => format!(
                "coroutine:{}<{}>",
                definition.name(),
                canonical_generic_arguments(&arguments, depth + 1)?
            ),
            RigidTy::CoroutineClosure(definition, arguments) => format!(
                "coroutine_closure:{}<{}>",
                definition.name(),
                canonical_generic_arguments(&arguments, depth + 1)?
            ),
            RigidTy::Dynamic(predicates, _) => {
                let mut values = Vec::new();
                for predicate in predicates {
                    let value = match predicate.value {
                        rustc_public::ty::ExistentialPredicate::Trait(value) => format!(
                            "trait:{}<{}>",
                            value.def_id.name(),
                            canonical_generic_arguments(&value.generic_args, depth + 1)?
                        ),
                        rustc_public::ty::ExistentialPredicate::Projection(value) => format!(
                            "projection:{}<{}>",
                            value.def_id.name(),
                            canonical_generic_arguments(&value.generic_args, depth + 1)?
                        ),
                        rustc_public::ty::ExistentialPredicate::AutoTrait(value) => {
                            format!("auto:{}", value.name())
                        }
                    };
                    values.push(value);
                }
                values.sort();
                format!("dynamic:{}", values.join("+"))
            }
            RigidTy::Never => "never".to_owned(),
            RigidTy::Tuple(values) => format!(
                "tuple:{}",
                values
                    .into_iter()
                    .map(|ty| canonical_type(ty, depth + 1))
                    .collect::<Result<Vec<_>>>()?
                    .join(",")
            ),
            RigidTy::CoroutineWitness(definition, arguments) => format!(
                "coroutine_witness:{}<{}>",
                definition.name(),
                canonical_generic_arguments(&arguments, depth + 1)?
            ),
        },
    };
    validate_text(&value)?;
    Ok(value)
}

fn canonical_alias_name(value: rustc_public::ty::AliasKind) -> &'static str {
    match value {
        rustc_public::ty::AliasKind::Projection => "projection",
        rustc_public::ty::AliasKind::Inherent => "inherent",
        rustc_public::ty::AliasKind::Opaque => "opaque",
        rustc_public::ty::AliasKind::Free => "free",
    }
}

fn canonical_safety_name(value: rustc_public::mir::Safety) -> &'static str {
    match value {
        rustc_public::mir::Safety::Safe => "safe",
        rustc_public::mir::Safety::Unsafe => "unsafe",
    }
}

fn canonical_abi_name(value: &rustc_public::ty::Abi) -> String {
    use rustc_public::ty::Abi;

    let unwind = |name: &str, unwind: bool| format!("{name}:unwind={unwind}");
    match value {
        Abi::Rust => "rust".to_owned(),
        Abi::C { unwind: value } => unwind("c", *value),
        Abi::Cdecl { unwind: value } => unwind("cdecl", *value),
        Abi::Stdcall { unwind: value } => unwind("stdcall", *value),
        Abi::Fastcall { unwind: value } => unwind("fastcall", *value),
        Abi::Vectorcall { unwind: value } => unwind("vectorcall", *value),
        Abi::Thiscall { unwind: value } => unwind("thiscall", *value),
        Abi::Aapcs { unwind: value } => unwind("aapcs", *value),
        Abi::Win64 { unwind: value } => unwind("win64", *value),
        Abi::SysV64 { unwind: value } => unwind("sysv64", *value),
        Abi::PtxKernel => "ptx_kernel".to_owned(),
        Abi::Msp430Interrupt => "msp430_interrupt".to_owned(),
        Abi::X86Interrupt => "x86_interrupt".to_owned(),
        Abi::GpuKernel => "gpu_kernel".to_owned(),
        Abi::EfiApi => "efi_api".to_owned(),
        Abi::AvrInterrupt => "avr_interrupt".to_owned(),
        Abi::AvrNonBlockingInterrupt => "avr_non_blocking_interrupt".to_owned(),
        Abi::CCmseNonSecureCall => "ccmse_non_secure_call".to_owned(),
        Abi::CCmseNonSecureEntry => "ccmse_non_secure_entry".to_owned(),
        Abi::System { unwind: value } => unwind("system", *value),
        Abi::RustCall => "rust_call".to_owned(),
        Abi::Unadjusted => "unadjusted".to_owned(),
        Abi::RustCold => "rust_cold".to_owned(),
        Abi::RiscvInterruptM => "riscv_interrupt_m".to_owned(),
        Abi::RiscvInterruptS => "riscv_interrupt_s".to_owned(),
        Abi::RustPreserveNone => "rust_preserve_none".to_owned(),
        Abi::RustTail => "rust_tail".to_owned(),
        Abi::RustInvalid => "rust_invalid".to_owned(),
        Abi::Custom => "custom".to_owned(),
        Abi::Swift => "swift".to_owned(),
    }
}

fn canonical_int_name(value: IntTy) -> &'static str {
    match value {
        IntTy::Isize => "isize",
        IntTy::I8 => "i8",
        IntTy::I16 => "i16",
        IntTy::I32 => "i32",
        IntTy::I64 => "i64",
        IntTy::I128 => "i128",
    }
}

fn canonical_uint_name(value: UintTy) -> &'static str {
    match value {
        UintTy::Usize => "usize",
        UintTy::U8 => "u8",
        UintTy::U16 => "u16",
        UintTy::U32 => "u32",
        UintTy::U64 => "u64",
        UintTy::U128 => "u128",
    }
}

fn canonical_float_name(value: rustc_public::ty::FloatTy) -> &'static str {
    match value {
        rustc_public::ty::FloatTy::F16 => "f16",
        rustc_public::ty::FloatTy::F32 => "f32",
        rustc_public::ty::FloatTy::F64 => "f64",
        rustc_public::ty::FloatTy::F128 => "f128",
    }
}

fn canonical_type_const(value: &rustc_public::ty::TyConst, depth: usize) -> Result<String> {
    if depth > MAX_TYPE_DEPTH {
        bail!("compiler instance constant exceeds its nesting depth limit");
    }
    Ok(match value.kind() {
        TyConstKind::Param(value) => format!("param:{}:{}", value.index, value.name),
        TyConstKind::Bound(index, variable) => format!("bound:{index}:{variable}"),
        TyConstKind::Unevaluated(definition, arguments) => format!(
            "unevaluated:{}<{}>",
            definition.name(),
            canonical_generic_arguments(arguments, depth + 1)?
        ),
        TyConstKind::Value(ty, allocation) => format!(
            "value:{}:{}",
            canonical_type(*ty, depth + 1)?,
            allocation
                .read_uint()
                .map(|value| value.to_string())
                .or_else(|_| allocation.read_int().map(|value| value.to_string()))
                .context("compiler instance constant value is not a scalar")?
        ),
        TyConstKind::ZSTValue(ty) => format!("zero_sized:{}", canonical_type(*ty, depth + 1)?),
    })
}

fn extract_instance_calls(
    _caller: Instance,
    caller_instance_id: &str,
    body: &Body,
    workspace: &Path,
    cargo_home: &Path,
) -> Result<Vec<PendingCall>> {
    let fn_pointer_candidates = collect_fn_pointer_candidates(body)?;
    let mut calls = Vec::new();
    for (block_index, block) in body.blocks.iter().enumerate() {
        let block_ordinal =
            u32::try_from(block_index).context("call graph block ordinal overflowed")?;
        let operation_ordinal = u32::try_from(block.statements.len())
            .context("call graph operation ordinal overflowed")?;
        let span = convert_span(
            block.terminator.source_info.span,
            workspace,
            cargo_home,
            None,
        )
        .ok();
        match &block.terminator.kind {
            TerminatorKind::Call { func, .. } => {
                let ty = func.ty(body.locals()).ok().map(|ty| ty.kind());
                let call = match ty {
                    Some(TyKind::RigidTy(RigidTy::FnDef(definition, arguments))) => {
                        match Instance::resolve(definition, &arguments) {
                            Ok(target)
                                if matches!(target.kind, PublicInstanceKind::Virtual { .. }) =>
                            {
                                unknown_call(
                                    caller_instance_id,
                                    block_ordinal,
                                    operation_ordinal,
                                    span,
                                    CompilerCallReason::VirtualDispatch,
                                )
                            }
                            Ok(target) => resolved_call(
                                caller_instance_id,
                                block_ordinal,
                                operation_ordinal,
                                span,
                                target,
                            ),
                            Err(_) => unknown_call(
                                caller_instance_id,
                                block_ordinal,
                                operation_ordinal,
                                span,
                                CompilerCallReason::UnresolvedInstance,
                            ),
                        }
                    }
                    Some(TyKind::RigidTy(RigidTy::FnPtr(_))) => {
                        let targets = operand_local(func)
                            .and_then(|local| fn_pointer_candidates.get(&local))
                            .cloned()
                            .unwrap_or_default();
                        if targets.is_empty() {
                            unknown_call(
                                caller_instance_id,
                                block_ordinal,
                                operation_ordinal,
                                span,
                                CompilerCallReason::FnPointerUnbounded,
                            )
                        } else {
                            candidate_call(
                                caller_instance_id,
                                block_ordinal,
                                operation_ordinal,
                                span,
                                targets,
                            )
                        }
                    }
                    _ => unknown_call(
                        caller_instance_id,
                        block_ordinal,
                        operation_ordinal,
                        span,
                        CompilerCallReason::UnsupportedCallee,
                    ),
                };
                calls.push(call);
            }
            TerminatorKind::Drop { place, .. } => {
                if let Ok(ty) = place.ty(body.locals()) {
                    let target = Instance::resolve_drop_in_place(ty);
                    if !target.is_empty_shim() {
                        calls.push(resolved_call(
                            caller_instance_id,
                            block_ordinal,
                            operation_ordinal,
                            span,
                            target,
                        ));
                    }
                }
            }
            _ => {}
        }
    }
    Ok(calls)
}

fn collect_fn_pointer_candidates(body: &Body) -> Result<HashMap<usize, Vec<Instance>>> {
    let mut candidates = HashMap::<usize, Vec<Instance>>::new();
    for _ in 0..=body.blocks.len() {
        let mut changed = false;
        for block in &body.blocks {
            for statement in &block.statements {
                let StatementKind::Assign(destination, rvalue) = &statement.kind else {
                    continue;
                };
                if !destination.projection.is_empty() {
                    continue;
                }
                let values = match rvalue {
                    Rvalue::Cast(_, operand, _) | Rvalue::Use(operand, _) => {
                        operand_fn_pointer_candidates(operand, body, &candidates)?
                    }
                    _ => Vec::new(),
                };
                let entry = candidates.entry(destination.local).or_default();
                for value in values {
                    if !entry.contains(&value) {
                        entry.push(value);
                        changed = true;
                    }
                }
            }
        }
        if !changed {
            break;
        }
    }
    Ok(candidates)
}

fn operand_fn_pointer_candidates(
    operand: &Operand,
    body: &Body,
    candidates: &HashMap<usize, Vec<Instance>>,
) -> Result<Vec<Instance>> {
    if let TyKind::RigidTy(RigidTy::FnDef(definition, arguments)) =
        operand.ty(body.locals())?.kind()
    {
        return Ok(Instance::resolve_for_fn_ptr(definition, &arguments)
            .ok()
            .into_iter()
            .collect());
    }
    Ok(operand_local(operand)
        .and_then(|local| candidates.get(&local))
        .cloned()
        .unwrap_or_default())
}

fn operand_local(operand: &Operand) -> Option<usize> {
    match operand {
        Operand::Copy(place) | Operand::Move(place) if place.projection.is_empty() => {
            Some(place.local)
        }
        Operand::Copy(_) | Operand::Move(_) | Operand::Constant(_) | Operand::RuntimeChecks(_) => {
            None
        }
    }
}

fn resolved_call(
    caller_instance_id: &str,
    block_ordinal: u32,
    operation_ordinal: u32,
    span: Option<Span>,
    target: Instance,
) -> PendingCall {
    PendingCall {
        caller_instance_id: caller_instance_id.to_owned(),
        block_ordinal,
        operation_ordinal,
        relation: CompilerCallRelation::Calls,
        resolution: CompilerCallResolution::Resolved,
        evidence: CompilerCallEvidence::Observed,
        targets: vec![target],
        span,
        reason_code: None,
    }
}

fn candidate_call(
    caller_instance_id: &str,
    block_ordinal: u32,
    operation_ordinal: u32,
    span: Option<Span>,
    targets: Vec<Instance>,
) -> PendingCall {
    PendingCall {
        caller_instance_id: caller_instance_id.to_owned(),
        block_ordinal,
        operation_ordinal,
        relation: CompilerCallRelation::MayCall,
        resolution: CompilerCallResolution::Candidate,
        evidence: CompilerCallEvidence::Candidate,
        targets,
        span,
        reason_code: None,
    }
}

fn unknown_call(
    caller_instance_id: &str,
    block_ordinal: u32,
    operation_ordinal: u32,
    span: Option<Span>,
    reason: CompilerCallReason,
) -> PendingCall {
    PendingCall {
        caller_instance_id: caller_instance_id.to_owned(),
        block_ordinal,
        operation_ordinal,
        relation: CompilerCallRelation::MayCall,
        resolution: CompilerCallResolution::UnknownTarget,
        evidence: CompilerCallEvidence::Unknown,
        targets: Vec::new(),
        span,
        reason_code: Some(reason),
    }
}

fn statement_operation(
    context: &mut ExtractContext,
    body: &Body,
    block_id: &str,
    ordinal: u32,
    statement: &rustc_public::mir::Statement,
) -> Result<Operation> {
    let (kind, places, constants, unsupported) = match &statement.kind {
        StatementKind::Assign(place, rvalue) => {
            let mut places = vec![intern_place(context, body, place)?];
            let mut constants = Vec::new();
            collect_rvalue(context, body, rvalue, &mut places, &mut constants)?;
            ("assign", places, constants, None)
        }
        StatementKind::FakeRead(_, place) => (
            "fake_read",
            vec![intern_place(context, body, place)?],
            Vec::new(),
            None,
        ),
        StatementKind::SetDiscriminant { place, .. } => (
            "set_discriminant",
            vec![intern_place(context, body, place)?],
            Vec::new(),
            None,
        ),
        StatementKind::StorageLive(local) => (
            "storage_live",
            vec![intern_place(context, body, &Place::from(*local))?],
            Vec::new(),
            None,
        ),
        StatementKind::StorageDead(local) => (
            "storage_dead",
            vec![intern_place(context, body, &Place::from(*local))?],
            Vec::new(),
            None,
        ),
        StatementKind::PlaceMention(place) => (
            "place_mention",
            vec![intern_place(context, body, place)?],
            Vec::new(),
            None,
        ),
        StatementKind::AscribeUserType { place, .. } => (
            "ascribe_user_type",
            vec![intern_place(context, body, place)?],
            Vec::new(),
            None,
        ),
        StatementKind::Intrinsic(intrinsic) => {
            let mut places = Vec::new();
            let mut constants = Vec::new();
            match intrinsic {
                NonDivergingIntrinsic::Assume(operand) => {
                    collect_operand(context, body, operand, &mut places, &mut constants)?;
                }
                NonDivergingIntrinsic::CopyNonOverlapping(copy) => {
                    for operand in [&copy.src, &copy.dst, &copy.count] {
                        collect_operand(context, body, operand, &mut places, &mut constants)?;
                    }
                }
            }
            ("intrinsic", places, constants, None)
        }
        StatementKind::Coverage(_) => (
            "coverage",
            Vec::new(),
            Vec::new(),
            Some("unsupported_statement"),
        ),
        StatementKind::ConstEvalCounter => ("const_eval_counter", Vec::new(), Vec::new(), None),
        StatementKind::Nop => ("nop", Vec::new(), Vec::new(), None),
    };
    operation(
        context,
        block_id,
        ordinal,
        kind,
        statement.source_info.span,
        places,
        constants,
        unsupported,
    )
}

fn terminator_operation(
    context: &mut ExtractContext,
    body: &Body,
    block_id: &str,
    ordinal: u32,
    terminator: &rustc_public::mir::Terminator,
) -> Result<Operation> {
    let mut places = Vec::new();
    let mut constants = Vec::new();
    let (kind, unsupported) = match &terminator.kind {
        TerminatorKind::Goto { .. } => ("goto", None),
        TerminatorKind::SwitchInt { discr, .. } => {
            collect_operand(context, body, discr, &mut places, &mut constants)?;
            ("switch_int", None)
        }
        TerminatorKind::Resume => ("resume", None),
        TerminatorKind::Abort => ("abort", None),
        TerminatorKind::Return => ("return", None),
        TerminatorKind::Unreachable => ("unreachable", None),
        TerminatorKind::Drop { place, .. } => {
            places.push(intern_place(context, body, place)?);
            ("drop", None)
        }
        TerminatorKind::Call {
            func,
            args,
            destination,
            ..
        } => {
            collect_operand(context, body, func, &mut places, &mut constants)?;
            for argument in args {
                collect_operand(context, body, argument, &mut places, &mut constants)?;
            }
            places.push(intern_place(context, body, destination)?);
            ("call", None)
        }
        TerminatorKind::Assert { cond, .. } => {
            collect_operand(context, body, cond, &mut places, &mut constants)?;
            ("assert", None)
        }
        TerminatorKind::InlineAsm { operands, .. } => {
            for operand in operands {
                if let Some(value) = &operand.in_value {
                    collect_operand(context, body, value, &mut places, &mut constants)?;
                }
                if let Some(place) = &operand.out_place {
                    places.push(intern_place(context, body, place)?);
                }
            }
            ("inline_asm", Some("unsupported_terminator"))
        }
    };
    operation(
        context,
        block_id,
        ordinal,
        kind,
        terminator.source_info.span,
        places,
        constants,
        unsupported,
    )
}

#[allow(clippy::too_many_arguments)]
fn operation(
    context: &mut ExtractContext,
    block_id: &str,
    ordinal: u32,
    kind: &str,
    span: rustc_public::ty::Span,
    mut places: Vec<String>,
    mut constants: Vec<String>,
    unsupported_reason: Option<&str>,
) -> Result<Operation> {
    places.sort();
    places.dedup();
    constants.sort();
    constants.dedup();
    let operation_id = digest_json(&(context.body_id.as_str(), block_id, ordinal, kind))?;
    if let Some(reason) = unsupported_reason {
        context.unsupported.push(Unsupported {
            scope_id: operation_id.clone(),
            construct_kind: kind.to_owned(),
            reason_code: reason.to_owned(),
        });
    }
    Ok(Operation {
        operation_id,
        ordinal,
        kind: kind.to_owned(),
        span: convert_span(
            span,
            &context.workspace,
            &context.cargo_home,
            context.fallback_span.as_ref(),
        )?,
        places,
        constants,
        unsupported_reason: unsupported_reason.map(str::to_owned),
    })
}

fn collect_rvalue(
    context: &mut ExtractContext,
    body: &Body,
    rvalue: &Rvalue,
    places: &mut Vec<String>,
    constants: &mut Vec<String>,
) -> Result<()> {
    match rvalue {
        Rvalue::AddressOf(_, place)
        | Rvalue::CopyForDeref(place)
        | Rvalue::Discriminant(place)
        | Rvalue::Len(place)
        | Rvalue::Ref(_, _, place)
        | Rvalue::Reborrow(_, _, place) => places.push(intern_place(context, body, place)?),
        Rvalue::Aggregate(_, operands) => {
            for operand in operands {
                collect_operand(context, body, operand, places, constants)?;
            }
        }
        Rvalue::BinaryOp(_, left, right) | Rvalue::CheckedBinaryOp(_, left, right) => {
            collect_operand(context, body, left, places, constants)?;
            collect_operand(context, body, right, places, constants)?;
        }
        Rvalue::Cast(_, operand, _)
        | Rvalue::Repeat(operand, _)
        | Rvalue::UnaryOp(_, operand)
        | Rvalue::Use(operand, _) => {
            collect_operand(context, body, operand, places, constants)?;
        }
        Rvalue::ThreadLocalRef(_) => {}
    }
    Ok(())
}

fn collect_operand(
    context: &mut ExtractContext,
    body: &Body,
    operand: &Operand,
    places: &mut Vec<String>,
    constants: &mut Vec<String>,
) -> Result<()> {
    match operand {
        Operand::Copy(place) | Operand::Move(place) => {
            places.push(intern_place(context, body, place)?);
        }
        Operand::Constant(constant) => {
            constants.push(intern_constant(context, constant)?);
        }
        Operand::RuntimeChecks(_) => {}
    }
    Ok(())
}

fn intern_place(context: &mut ExtractContext, body: &Body, place: &Place) -> Result<String> {
    let ordinal = place.local;
    let local_id = context
        .local_ids
        .get(ordinal)
        .context("typed MIR place local is out of bounds")?
        .clone();
    let mut projections = Vec::new();
    let mut unsupported_projection = false;
    for element in &place.projection {
        projections.push(match element {
            ProjectionElem::Deref => empty_projection("deref"),
            ProjectionElem::Field(index, ty) => Projection {
                kind: "field".to_owned(),
                index: Some(u64::try_from(*index).context("field index overflowed")?),
                type_id: Some(intern_type(context, *ty, 0)?),
                ..empty_projection("field")
            },
            ProjectionElem::Index(local) => Projection {
                kind: "index".to_owned(),
                local_id: Some(
                    context
                        .local_ids
                        .get(*local)
                        .context("projection index local is out of bounds")?
                        .clone(),
                ),
                ..empty_projection("index")
            },
            ProjectionElem::ConstantIndex {
                offset,
                min_length,
                from_end,
            } => Projection {
                kind: "constant_index".to_owned(),
                index: Some(*offset),
                to: Some(*min_length),
                from_end: Some(*from_end),
                ..empty_projection("constant_index")
            },
            ProjectionElem::Subslice { from, to, from_end } => Projection {
                kind: "subslice".to_owned(),
                from: Some(*from),
                to: Some(*to),
                from_end: Some(*from_end),
                ..empty_projection("subslice")
            },
            ProjectionElem::Downcast(_) => {
                unsupported_projection = true;
                Projection {
                    kind: "downcast".to_owned(),
                    ..empty_projection("downcast")
                }
            }
            ProjectionElem::OpaqueCast(ty) => Projection {
                kind: "opaque_cast".to_owned(),
                type_id: Some(intern_type(context, *ty, 0)?),
                ..empty_projection("opaque_cast")
            },
        });
    }
    let type_id = intern_type(context, place.ty(body.locals())?, 0)?;
    let place_id = digest_json(&(
        context.body_id.as_str(),
        local_id.as_str(),
        &projections,
        type_id.as_str(),
    ))?;
    if unsupported_projection {
        context.unsupported.push(Unsupported {
            scope_id: place_id.clone(),
            construct_kind: "downcast".to_owned(),
            reason_code: "unsupported_projection".to_owned(),
        });
    }
    context
        .places
        .entry(place_id.clone())
        .or_insert_with(|| MirPlace {
            place_id: place_id.clone(),
            local_id,
            projections,
            type_id,
        });
    Ok(place_id)
}

fn empty_projection(kind: &str) -> Projection {
    Projection {
        kind: kind.to_owned(),
        index: None,
        from: None,
        to: None,
        from_end: None,
        type_id: None,
        local_id: None,
    }
}

fn intern_constant(context: &mut ExtractContext, constant: &ConstOperand) -> Result<String> {
    let type_id = intern_type(context, constant.ty(), 0)?;
    let span = convert_span(
        constant.span,
        &context.workspace,
        &context.cargo_home,
        context.fallback_span.as_ref(),
    )?;
    let (kind, value, definition_id, unsupported_reason) = match constant.const_.kind() {
        ConstantKind::Ty(value) => ("type", Some(type_const_value(value)), None, None),
        ConstantKind::Allocated(_) => ("allocated", None, None, Some("unsupported_constant")),
        ConstantKind::Unevaluated(value) => (
            "unevaluated",
            None,
            Some(definition_id(value.def.name(), value.def.span(), context)?),
            Some("unsupported_constant"),
        ),
        ConstantKind::Param(value) => (
            "parameter",
            Some(format!("{}:{}", value.index, value.name)),
            None,
            None,
        ),
        ConstantKind::ZeroSized => ("zero_sized", None, None, None),
    };
    let constant_id = digest_json(&(
        context.body_id.as_str(),
        type_id.as_str(),
        kind,
        &value,
        &definition_id,
        &unsupported_reason,
        &span,
    ))?;
    if let Some(reason) = unsupported_reason {
        context.unsupported.push(Unsupported {
            scope_id: constant_id.clone(),
            construct_kind: kind.to_owned(),
            reason_code: reason.to_owned(),
        });
    }
    context
        .constants
        .entry(constant_id.clone())
        .or_insert_with(|| Constant {
            constant_id: constant_id.clone(),
            type_id,
            kind: kind.to_owned(),
            value,
            definition_id,
            unsupported_reason: unsupported_reason.map(str::to_owned),
            span,
        });
    Ok(constant_id)
}

fn intern_type(context: &mut ExtractContext, ty: Ty, depth: usize) -> Result<String> {
    if depth >= MAX_TYPE_DEPTH {
        return type_atom(
            context,
            "unsupported",
            Vec::new(),
            None,
            None,
            None,
            Some("depth_limit"),
        );
    }
    let (kind, arguments, mutability, value, unsupported) = match ty.kind() {
        TyKind::RigidTy(rigid) => match rigid {
            RigidTy::Bool => atom("bool"),
            RigidTy::Char => atom("char"),
            RigidTy::Int(value) => atom(match value {
                IntTy::Isize => "isize",
                IntTy::I8 => "i8",
                IntTy::I16 => "i16",
                IntTy::I32 => "i32",
                IntTy::I64 => "i64",
                IntTy::I128 => "i128",
            }),
            RigidTy::Uint(value) => atom(match value {
                UintTy::Usize => "usize",
                UintTy::U8 => "u8",
                UintTy::U16 => "u16",
                UintTy::U32 => "u32",
                UintTy::U64 => "u64",
                UintTy::U128 => "u128",
            }),
            RigidTy::Float(value) => atom(match value {
                rustc_public::ty::FloatTy::F16 => "f16",
                rustc_public::ty::FloatTy::F32 => "f32",
                rustc_public::ty::FloatTy::F64 => "f64",
                rustc_public::ty::FloatTy::F128 => "f128",
            }),
            RigidTy::Str => atom("str"),
            RigidTy::Never => atom("never"),
            RigidTy::Slice(inner) => composite(context, "slice", &[inner], depth)?,
            RigidTy::Array(inner, length) => {
                let mut value = composite(context, "array", &[inner], depth)?;
                value.3 = Some(type_const_value(&length));
                value
            }
            RigidTy::RawPtr(inner, mutability) => {
                let mut value = composite(context, "raw_pointer", &[inner], depth)?;
                value.2 = Some(mutability_name(mutability));
                value
            }
            RigidTy::Ref(_, inner, mutability) => {
                let mut value = composite(context, "reference", &[inner], depth)?;
                value.2 = Some(mutability_name(mutability));
                value
            }
            RigidTy::Tuple(values) => composite(context, "tuple", &values, depth)?,
            RigidTy::FnDef(definition, arguments) => {
                generic_type(context, "function", definition.name(), &arguments, depth)?
            }
            RigidTy::Adt(definition, arguments) => {
                generic_type(context, "adt", definition.name(), &arguments, depth)?
            }
            RigidTy::Closure(definition, arguments) => {
                generic_type(context, "closure", definition.name(), &arguments, depth)?
            }
            RigidTy::Coroutine(definition, arguments) => {
                generic_type(context, "coroutine", definition.name(), &arguments, depth)?
            }
            RigidTy::CoroutineClosure(definition, arguments) => generic_type(
                context,
                "coroutine_closure",
                definition.name(),
                &arguments,
                depth,
            )?,
            RigidTy::Foreign(definition) => (
                "foreign".to_owned(),
                Vec::new(),
                None,
                Some(definition.name()),
                Some("unsupported_type"),
            ),
            RigidTy::FnPtr(_) => unsupported_type("function_pointer"),
            RigidTy::Pat(..) => unsupported_type("pattern"),
            RigidTy::Dynamic(..) => unsupported_type("dynamic"),
            RigidTy::CoroutineWitness(..) => unsupported_type("coroutine_witness"),
        },
        TyKind::Alias(_, value) => {
            let (arguments, constants) = generic_arguments(context, &value.args, depth)?;
            let name = if constants.is_empty() {
                value.def_id.name()
            } else {
                format!("{}|{}", value.def_id.name(), constants.join(","))
            };
            (
                "alias".to_owned(),
                arguments,
                None,
                Some(name),
                Some("unsupported_type"),
            )
        }
        TyKind::Param(value) => (
            "parameter".to_owned(),
            Vec::new(),
            None,
            Some(format!("{}:{}", value.index, value.name)),
            None,
        ),
        TyKind::Bound(index, value) => (
            "bound".to_owned(),
            Vec::new(),
            None,
            Some(format!("{index}:{}", value.var)),
            Some("unsupported_type"),
        ),
    };
    type_atom(
        context,
        &kind,
        arguments,
        None,
        mutability,
        value,
        unsupported,
    )
}

type TypeParts = (
    String,
    Vec<String>,
    Option<String>,
    Option<String>,
    Option<&'static str>,
);

fn atom(kind: &str) -> TypeParts {
    (kind.to_owned(), Vec::new(), None, None, None)
}

fn unsupported_type(kind: &str) -> TypeParts {
    (
        kind.to_owned(),
        Vec::new(),
        None,
        None,
        Some("unsupported_type"),
    )
}

fn composite(
    context: &mut ExtractContext,
    kind: &str,
    values: &[Ty],
    depth: usize,
) -> Result<TypeParts> {
    let arguments = values
        .iter()
        .map(|value| intern_type(context, *value, depth + 1))
        .collect::<Result<Vec<_>>>()?;
    Ok((kind.to_owned(), arguments, None, None, None))
}

fn generic_type(
    context: &mut ExtractContext,
    kind: &str,
    definition: String,
    arguments: &rustc_public::ty::GenericArgs,
    depth: usize,
) -> Result<TypeParts> {
    let (arguments, constant_arguments) = generic_arguments(context, arguments, depth)?;
    let value = if constant_arguments.is_empty() {
        definition
    } else {
        format!("{definition}|{}", constant_arguments.join(","))
    };
    Ok((kind.to_owned(), arguments, None, Some(value), None))
}

fn generic_arguments(
    context: &mut ExtractContext,
    arguments: &rustc_public::ty::GenericArgs,
    depth: usize,
) -> Result<(Vec<String>, Vec<String>)> {
    let mut types = Vec::new();
    let mut constants = Vec::new();
    for argument in &arguments.0 {
        match argument {
            rustc_public::ty::GenericArgKind::Type(ty) => {
                types.push(intern_type(context, *ty, depth + 1)?);
            }
            rustc_public::ty::GenericArgKind::Const(value) => {
                constants.push(type_const_value(value));
            }
            rustc_public::ty::GenericArgKind::Lifetime(_) => {}
        }
    }
    Ok((types, constants))
}

#[allow(clippy::too_many_arguments)]
fn type_atom(
    context: &mut ExtractContext,
    kind: &str,
    arguments: Vec<String>,
    definition_id: Option<String>,
    mutability: Option<String>,
    value: Option<String>,
    unsupported_reason: Option<&str>,
) -> Result<String> {
    let type_id = digest_json(&(
        kind,
        &arguments,
        &definition_id,
        &mutability,
        &value,
        &unsupported_reason,
    ))?;
    if let Some(reason) = unsupported_reason {
        context.unsupported.push(Unsupported {
            scope_id: type_id.clone(),
            construct_kind: kind.to_owned(),
            reason_code: reason.to_owned(),
        });
    }
    context
        .types
        .entry(type_id.clone())
        .or_insert_with(|| MirType {
            type_id: type_id.clone(),
            kind: kind.to_owned(),
            arguments,
            definition_id,
            mutability,
            value,
            unsupported_reason: unsupported_reason.map(str::to_owned),
        });
    Ok(type_id)
}

fn type_const_value(value: &rustc_public::ty::TyConst) -> String {
    match value.kind() {
        TyConstKind::Param(value) => format!("param:{}:{}", value.index, value.name),
        TyConstKind::Bound(index, variable) => format!("bound:{index}:{variable}"),
        TyConstKind::Unevaluated(definition, _) => format!("unevaluated:{}", definition.name()),
        TyConstKind::Value(_, _) => value
            .eval_target_usize()
            .map(|value| value.to_string())
            .unwrap_or_else(|_| "value:unsupported".to_owned()),
        TyConstKind::ZSTValue(_) => "zero_sized".to_owned(),
    }
}

fn mutability_name(value: rustc_public::mir::Mutability) -> String {
    match value {
        rustc_public::mir::Mutability::Mut => "mutable",
        rustc_public::mir::Mutability::Not => "immutable",
    }
    .to_owned()
}

fn definition_id(
    path: String,
    span: rustc_public::ty::Span,
    context: &ExtractContext,
) -> Result<String> {
    let span = convert_span(
        span,
        &context.workspace,
        &context.cargo_home,
        context.fallback_span.as_ref(),
    )?;
    digest_json(&(
        path.as_str(),
        span.source_path.as_str(),
        span.source_sha256.as_str(),
        span.start_line,
        span.start_column,
        span.end_line,
        span.end_column,
    ))
}

fn convert_span(
    span: rustc_public::ty::Span,
    workspace: &Path,
    cargo_home: &Path,
    fallback: Option<&Span>,
) -> Result<Span> {
    let filename = span.get_filename();
    let path = PathBuf::from(&filename);
    let resolved = if path.is_absolute() {
        path
    } else {
        workspace.join(path)
    };
    let canonical = resolved.canonicalize().ok();
    let logical = canonical.as_ref().and_then(|path| {
        if let Ok(relative) = path.strip_prefix(workspace) {
            logical_path("repo://", relative).ok()
        } else if let Ok(relative) = path.strip_prefix(cargo_home) {
            logical_path("cargo-home://", relative).ok()
        } else {
            None
        }
    });
    let Some((source_path, source_sha256)) = logical.zip(
        canonical
            .as_ref()
            .and_then(|path| fs::read(path).ok())
            .map(|bytes| digest_bytes(&bytes)),
    ) else {
        return fallback
            .cloned()
            .context("compiler span is outside the staged source roots");
    };
    let lines = span.get_lines();
    Ok(Span {
        source_path,
        source_sha256,
        start_line: u32::try_from(lines.start_line).context("span start line overflowed")?,
        start_column: u32::try_from(lines.start_col).context("span start column overflowed")?,
        end_line: u32::try_from(lines.end_line).context("span end line overflowed")?,
        end_column: u32::try_from(lines.end_col).context("span end column overflowed")?,
    })
}

fn logical_path(prefix: &str, relative: &Path) -> Result<String> {
    if relative.as_os_str().is_empty()
        || relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_) | Component::CurDir))
    {
        bail!("compiler span path is not canonical");
    }
    let logical = format!("{prefix}{}", relative.to_string_lossy().replace('\\', "/"));
    validate_text(&logical)?;
    Ok(logical)
}

fn validate_environment_identity() -> Result<()> {
    if required_text("DEPGRAPH_QUERY_RUSTC_COMMIT")? != RUSTC_COMMIT {
        bail!("compiler query rustc commit is not the pinned compatibility unit");
    }
    for key in [
        "DEPGRAPH_QUERY_ATTEMPT_DIGEST",
        "DEPGRAPH_QUERY_INVOCATION_ID",
        "DEPGRAPH_QUERY_TARGET_DIGEST",
        "DEPGRAPH_QUERY_SOURCE_SHA256",
        "DEPGRAPH_QUERY_PROFILE_DIGEST",
        "DEPGRAPH_QUERY_PACK_MANIFEST_SHA256",
    ] {
        required_digest(key)?;
    }
    Ok(())
}

fn required_text(key: &str) -> Result<String> {
    let value = env::var(key).with_context(|| format!("{key} is unavailable"))?;
    validate_text(&value)?;
    Ok(value)
}

fn required_digest(key: &str) -> Result<String> {
    let value = required_text(key)?;
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("{key} is not a SHA-256 digest");
    }
    Ok(value)
}

fn required_absolute_file(key: &str) -> Result<PathBuf> {
    let path = PathBuf::from(env::var_os(key).with_context(|| format!("{key} is unavailable"))?);
    let canonical = path
        .canonicalize()
        .with_context(|| format!("{key} is unavailable"))?;
    if !path.is_absolute() || !canonical.is_file() {
        bail!("{key} is not an absolute regular file");
    }
    Ok(canonical)
}

fn required_absolute_directory(key: &str) -> Result<PathBuf> {
    let path = PathBuf::from(env::var_os(key).with_context(|| format!("{key} is unavailable"))?);
    let metadata = fs::symlink_metadata(&path).with_context(|| format!("{key} is unavailable"))?;
    if !path.is_absolute() || metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("{key} is not a real absolute directory");
    }
    path.canonicalize()
        .with_context(|| format!("{key} is unavailable"))
}

fn validate_text(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 4_096
        || value.chars().any(char::is_control)
        || value.contains("DefId(")
        || value.contains("TyCtxt")
        || value.contains("AllocId(")
        || value.contains("0x")
    {
        bail!("compiler query text is invalid or contains an internal representation");
    }
    Ok(())
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .context("typed MIR output already exists or cannot be created")?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn canonical_json_bytes(value: &impl Serialize) -> Result<Vec<u8>> {
    let mut value = serde_json::to_value(value)?;
    sort_json(&mut value);
    Ok(serde_json::to_vec(&value)?)
}

fn digest_json(value: &impl Serialize) -> Result<String> {
    Ok(digest_bytes(&canonical_json_bytes(value)?))
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
