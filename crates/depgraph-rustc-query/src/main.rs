#![feature(rustc_private)]

extern crate rustc_driver;
extern crate rustc_interface;
extern crate rustc_middle;
#[macro_use]
extern crate rustc_public;

use std::{
    collections::BTreeMap,
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
    bodies: &'a [MirBody],
    unsupported: &'a [Unsupported],
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
    if bodies.is_empty() {
        bail!("pinned compiler returned no local typed MIR bodies");
    }
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
        compiler_pack_manifest_sha256: required_digest("DEPGRAPH_QUERY_PACK_MANIFEST_SHA256")?,
        rustc_commit: RUSTC_COMMIT,
        query_capabilities: vec!["typed_mir".to_owned()],
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
    if types
        .len()
        .checked_add(constants.len())
        .and_then(|count| count.checked_add(locals.len()))
        .and_then(|count| count.checked_add(places.len()))
        .and_then(|count| count.checked_add(blocks.len()))
        .is_none_or(|count| count > MAX_ATOMS)
    {
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
