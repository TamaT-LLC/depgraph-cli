use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, bail};
use depgraph_protocol::{
    CommonFields, CompletenessLevel, Condition, Coverage, DependencySite, DependencySiteEvent,
    EdgeUpsert, Evidence, EvidenceKind, GraphEdge, GraphNode, NodeUpsert, Phase, Precision,
    Profile, ProfileCompleted, ProfileDeclared, ProtocolEvent, ResolutionStatus, ScanCompleted,
    ScanStarted, build_edge_stable_id, build_site_stable_id, stable_id_from_value,
};
use depgraph_store::{
    EdgeRecord, GraphSnapshot, NodeRecord, ProfileRecord, SiteRecord, canonical_effective_input_id,
};
use serde::Serialize;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use crate::{
    BuildAudit, BuildOutcomeKind, COMPILER_PACK_RUST_RELEASE, COMPILER_PACK_RUSTC_COMMIT,
    COMPILER_PACK_TOOLCHAIN_CHANNEL, COMPILER_PRECISE_CONTRACT_VERSION,
    COMPILER_PRECISE_INVOCATION_ADAPTER, COMPILER_PRECISE_INVOCATION_ADAPTER_VERSION,
    CompilerPackAttestation, RustCargoUnitGraph, RustCompilerCallResolution,
    RustCompilerInvocationLedger, RustCompilerMirLedger, RustCompilerMirSpan, RustCompilerMirUnit,
    compiler_invocation_attempt_digest, validate_compiler_invocation_ledger_identity,
    validate_compiler_invocation_unit_graph, validate_compiler_mir_ledger_identity,
};

pub const COMPILER_PRECISE_GRAPH_CONTRACT_VERSION: &str = "rust-compiler-precise-graph-v1";
pub const COMPILER_PRECISE_GRAPH_CAPABILITY: &str =
    "cargo-unit-typed-mir-monomorphized-call-graph-v1";

fn sha256(bytes: impl AsRef<[u8]>) -> String {
    hex::encode(Sha256::digest(bytes.as_ref()))
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Stable profile identity for one exact compiler pack and Cargo unit graph.
/// The compiler-pack root is deliberately excluded so another checkout and
/// another extraction directory produce the same canonical graph.
pub fn compiler_precise_profile_id(
    host: &str,
    target: &str,
    compiler_pack_manifest_sha256: &str,
    unit_graph_digest: &str,
) -> Result<String> {
    if host.is_empty()
        || target.is_empty()
        || !is_digest(compiler_pack_manifest_sha256)
        || !is_digest(unit_graph_digest)
    {
        bail!("compiler-precise profile compatibility identity is invalid");
    }
    let digest = sha256(serde_json::to_vec(&json!({
        "contract_version": COMPILER_PRECISE_CONTRACT_VERSION,
        "graph_contract_version": COMPILER_PRECISE_GRAPH_CONTRACT_VERSION,
        "host": host,
        "target": target,
        "compiler_pack_manifest_sha256": compiler_pack_manifest_sha256,
        "unit_graph_digest": unit_graph_digest,
    }))?);
    Ok(format!("rust:compiler-precise:{digest}"))
}

fn enum_string(value: &impl Serialize) -> Result<String> {
    serde_json::to_value(value)?
        .as_str()
        .map(ToOwned::to_owned)
        .context("compiler-precise enum did not serialize as a string")
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

fn build_properties(
    context: &EvidenceContext<'_>,
    logical_path: &str,
    artifact_digest: &str,
    unit: Option<&RustCompilerMirUnit>,
) -> BTreeMap<String, Value> {
    let mut properties = BTreeMap::from([
        ("build_run_id".to_owned(), json!(context.audit.run_id)),
        ("profile_id".to_owned(), json!(context.audit.profile_id)),
        (
            "command_plan_digest".to_owned(),
            json!(context.audit.command_plan_digest),
        ),
        (
            "toolchain_executable_digest".to_owned(),
            json!(context.audit.toolchain_executable_digest),
        ),
        (
            "environment_key_set_digest".to_owned(),
            json!(context.audit.environment_key_set_digest),
        ),
        (
            "validated_output_digest".to_owned(),
            json!(context.audit.validated_output_digest),
        ),
        ("logical_artifact_path".to_owned(), json!(logical_path)),
        ("artifact_digest".to_owned(), json!(artifact_digest)),
        (
            "contract_version".to_owned(),
            json!(COMPILER_PRECISE_CONTRACT_VERSION),
        ),
        (
            "graph_contract_version".to_owned(),
            json!(COMPILER_PRECISE_GRAPH_CONTRACT_VERSION),
        ),
        (
            "compiler_pack_manifest_sha256".to_owned(),
            json!(context.pack.manifest_sha256),
        ),
        (
            "compiler_pack_target".to_owned(),
            json!(context.pack.target),
        ),
        ("rustc_commit".to_owned(), json!(COMPILER_PACK_RUSTC_COMMIT)),
        ("unit_graph_digest".to_owned(), json!(context.graph.digest)),
        (
            "invocation_ledger_digest".to_owned(),
            json!(context.invocations.digest),
        ),
        ("mir_ledger_digest".to_owned(), json!(context.mir.digest)),
        (
            "compiler_attempt_digest".to_owned(),
            json!(context.mir.attempt_digest),
        ),
    ]);
    if let Some(unit) = unit {
        properties.insert("unit_id".to_owned(), json!(unit.unit_id));
        properties.insert("mir_unit_digest".to_owned(), json!(unit.digest));
    }
    properties
}

struct EvidenceContext<'a> {
    audit: &'a BuildAudit,
    pack: &'a CompilerPackAttestation,
    graph: &'a RustCargoUnitGraph,
    invocations: &'a RustCompilerInvocationLedger,
    mir: &'a RustCompilerMirLedger,
}

impl EvidenceContext<'_> {
    fn evidence(
        &self,
        logical_path: &str,
        artifact_digest: &str,
        unit: Option<&RustCompilerMirUnit>,
        span: Option<&RustCompilerMirSpan>,
    ) -> Vec<Evidence> {
        let primary = Evidence {
            kind: EvidenceKind::Build,
            extractor: self.audit.adapter.clone(),
            extractor_version: self.audit.adapter_version.clone(),
            path: Some(span.map_or_else(
                || logical_path.to_owned(),
                |value| value.source_path.clone(),
            )),
            start_line: span.map(|value| value.start_line),
            start_column: span.map(|value| value.start_column),
            end_line: span.map(|value| value.end_line),
            end_column: span.map(|value| value.end_column),
            detail: Some("validated compiler-precise graph evidence".to_owned()),
            properties: build_properties(self, logical_path, artifact_digest, unit),
        };
        let mut evidence = vec![primary];
        if let Some(span) = span {
            evidence.push(Evidence {
                kind: EvidenceKind::Source,
                extractor: "compiler-source-correlation".to_owned(),
                extractor_version: COMPILER_PRECISE_GRAPH_CONTRACT_VERSION.to_owned(),
                path: Some(span.source_path.clone()),
                start_line: Some(span.start_line),
                start_column: Some(span.start_column),
                end_line: Some(span.end_line),
                end_column: Some(span.end_column),
                detail: Some(
                    "supporting source span; compiler evidence remains build-scoped".into(),
                ),
                properties: BTreeMap::from([(
                    "source_sha256".to_owned(),
                    json!(span.source_sha256),
                )]),
            });
        }
        evidence
    }
}

struct GraphArtifact<'a> {
    logical_path: &'a str,
    digest: &'a str,
    unit: Option<&'a RustCompilerMirUnit>,
}

fn generated_node(
    kind: &str,
    identity: Value,
    display_name: String,
    mut properties: Map<String, Value>,
    context: &EvidenceContext<'_>,
    artifact: GraphArtifact<'_>,
) -> GraphNode {
    let id = stable_id_from_value(kind, &identity);
    properties.insert("build_generated".to_owned(), Value::Bool(true));
    properties.insert("build_identity".to_owned(), identity);
    let mut provenance = build_properties(
        context,
        artifact.logical_path,
        artifact.digest,
        artifact.unit,
    );
    provenance.insert("observer".to_owned(), json!(context.audit.adapter));
    provenance.insert(
        "observer_version".to_owned(),
        json!(context.audit.adapter_version),
    );
    properties.insert(
        "build_provenance".to_owned(),
        serde_json::to_value(provenance).expect("BTreeMap serialization cannot fail"),
    );
    GraphNode {
        id: id.clone(),
        kind: kind.to_owned(),
        locator: format!(
            "build://{}/{logical_path}#{id}",
            COMPILER_PRECISE_INVOCATION_ADAPTER,
            logical_path = artifact.logical_path,
        ),
        display_name: Some(display_name),
        properties: properties.into_iter().collect(),
    }
}

fn materialize_generated_node(snapshot: &GraphSnapshot, node: GraphNode) -> Result<GraphNode> {
    let Some(existing) = snapshot.nodes.iter().find(|item| item.id == node.id) else {
        return Ok(node);
    };
    let mut expected = serde_json::to_value(&node)?;
    let mut actual = serde_json::to_value(base_node(existing)?)?;
    expected
        .get_mut("properties")
        .and_then(Value::as_object_mut)
        .and_then(|properties| properties.remove("build_provenance"));
    actual
        .get_mut("properties")
        .and_then(Value::as_object_mut)
        .and_then(|properties| properties.remove("build_provenance"));
    if expected != actual {
        bail!(
            "compiler-precise node {} conflicts with the existing build layer",
            node.id
        );
    }
    base_node(existing)
}

fn insert_node(nodes: &mut BTreeMap<String, GraphNode>, node: GraphNode) -> Result<()> {
    if let Some(previous) = nodes.get(&node.id)
        && previous != &node
    {
        bail!(
            "compiler-precise graph contains conflicting node {}",
            node.id
        );
    }
    nodes.insert(node.id.clone(), node);
    Ok(())
}

struct RelationInput<'a> {
    source: &'a str,
    targets: Vec<String>,
    kind: &'a str,
    specifier: String,
    status: ResolutionStatus,
    reason: Option<String>,
    evidence: Vec<Evidence>,
}

fn site_matches(existing: &SiteRecord, expected: &DependencySite) -> Result<bool> {
    Ok(existing.source == expected.source
        && existing.kind == expected.kind
        && existing.specifier.as_deref() == Some(expected.specifier.as_str())
        && existing.profile_id == expected.profile_id
        && existing.resolution_status == enum_string(&expected.resolution_status)?
        && existing.precision == "observed"
        && existing.condition == serde_json::to_value(&expected.condition)?
        && existing.target_ids == expected.target_ids
        && existing.reason == expected.reason)
}

fn edge_matches(existing: &EdgeRecord, expected: &GraphEdge) -> Result<bool> {
    Ok(existing.site_id == expected.site_id
        && existing.source == expected.source
        && existing.target == expected.target
        && existing.kind == expected.kind
        && existing.phase == "build"
        && existing.environment == "build"
        && existing.profile_id == expected.profile_id
        && existing.resolution_status == enum_string(&expected.resolution_status)?
        && existing.precision == "observed"
        && existing.condition == serde_json::to_value(&expected.condition)?
        && existing.generated)
}

fn add_relation(
    snapshot: &GraphSnapshot,
    sites: &mut BTreeMap<String, DependencySite>,
    edges: &mut BTreeMap<String, GraphEdge>,
    audit: &BuildAudit,
    mut input: RelationInput<'_>,
) -> Result<()> {
    input.targets.sort();
    input.targets.dedup();
    let mut site = DependencySite {
        id: "pending".to_owned(),
        source: input.source.to_owned(),
        kind: input.kind.to_owned(),
        specifier: input.specifier,
        resolution_status: input.status,
        target_ids: input.targets,
        profile_id: audit.profile_id.clone(),
        condition: Condition::default().canonicalize(),
        precision: Precision::Observed,
        reason: input.reason,
        evidence: input.evidence.clone(),
    };
    site.id = build_site_stable_id(&site)?;
    let expected_edges = site
        .target_ids
        .iter()
        .map(|target| {
            let mut edge = GraphEdge {
                id: "pending".to_owned(),
                source: site.source.clone(),
                target: target.clone(),
                kind: site.kind.clone(),
                site_id: Some(site.id.clone()),
                phase: Phase::Build,
                environment: Some("build".to_owned()),
                profile_id: site.profile_id.clone(),
                condition: site.condition.clone(),
                resolution_status: site.resolution_status,
                precision: Precision::Observed,
                generated: true,
                evidence: input.evidence.clone(),
            };
            edge.id = build_edge_stable_id(&edge)?;
            Ok::<_, anyhow::Error>(edge)
        })
        .collect::<Result<Vec<_>>>()?;

    if let Some(existing) = snapshot.sites.iter().find(|item| item.id == site.id) {
        if !site_matches(existing, &site)?
            || expected_edges.iter().any(|edge| {
                snapshot
                    .edges
                    .iter()
                    .find(|item| item.id == edge.id)
                    .is_none_or(|existing| !edge_matches(existing, edge).unwrap_or(false))
            })
        {
            bail!(
                "compiler-precise relation {} conflicts with an existing evidence layer",
                site.id
            );
        }
        return Ok(());
    }
    if expected_edges
        .iter()
        .any(|edge| snapshot.edges.iter().any(|item| item.id == edge.id))
    {
        bail!("compiler-precise graph found an orphaned existing edge");
    }
    if let Some(previous) = sites.get(&site.id)
        && previous != &site
    {
        bail!(
            "compiler-precise graph contains conflicting site {}",
            site.id
        );
    }
    sites.insert(site.id.clone(), site);
    for edge in expected_edges {
        if let Some(previous) = edges.get(&edge.id)
            && previous != &edge
        {
            bail!(
                "compiler-precise graph contains conflicting edge {}",
                edge.id
            );
        }
        edges.insert(edge.id.clone(), edge);
    }
    Ok(())
}

fn compiler_parent_profile<'a>(
    snapshot: &'a GraphSnapshot,
    audit: &BuildAudit,
) -> Result<&'a ProfileRecord> {
    let mut candidates = snapshot
        .profiles
        .iter()
        .filter(|profile| profile.language == "rust" && profile.id != audit.profile_id)
        .filter(|profile| {
            profile
                .properties
                .get("profile_phase")
                .and_then(Value::as_str)
                != Some("build")
        })
        .collect::<Vec<_>>();
    if let Some(target) = audit.target.as_deref() {
        candidates.retain(|profile| profile.target.as_deref() == Some(target));
    }
    candidates.sort_by(|left, right| left.id.cmp(&right.id));
    match candidates.as_slice() {
        [profile] => Ok(*profile),
        [] => bail!("compiler-precise graph has no compatible safe Rust parent profile"),
        _ => bail!("compiler-precise graph has multiple compatible safe Rust parent profiles"),
    }
}

fn source_node_for_path<'a>(
    snapshot: &'a GraphSnapshot,
    source_path: &str,
) -> Option<&'a NodeRecord> {
    let relative = source_path.strip_prefix("repo://")?;
    snapshot
        .nodes
        .iter()
        .find(|node| node.kind == "file" && node.display_name == relative)
}

fn logical_path(ledger: &RustCompilerMirLedger, kind: &str, digest: &str) -> String {
    format!(
        ".depgraph/compiler-precise/{}/{kind}/{digest}.json",
        ledger.digest
    )
}

fn validate_complete_attempt(
    audit: &BuildAudit,
    pack: &CompilerPackAttestation,
    graph: &RustCargoUnitGraph,
    invocations: &RustCompilerInvocationLedger,
    mir: &RustCompilerMirLedger,
) -> Result<()> {
    validate_compiler_invocation_unit_graph(graph)?;
    validate_compiler_invocation_ledger_identity(invocations, graph)?;
    validate_compiler_mir_ledger_identity(mir, graph, invocations, pack)?;
    for digest in [
        &pack.manifest_sha256,
        &pack.closed_tree_sha256,
        &pack.cargo_sha256,
        &pack.rustc_sha256,
        &pack.wrapper_sha256,
        &pack.query_sha256,
    ] {
        if !is_digest(digest) {
            bail!("compiler pack attestation contains an invalid digest");
        }
    }
    let expected_profile = compiler_precise_profile_id(
        &pack.host,
        &pack.target,
        &pack.manifest_sha256,
        &graph.digest,
    )?;
    let expected_attempt = compiler_invocation_attempt_digest(
        &audit.source_root_digest,
        &audit.command_plan_digest,
        &pack.manifest_sha256,
        &graph.digest,
    )?;
    if audit.outcome != BuildOutcomeKind::Completed
        || audit.adapter != COMPILER_PRECISE_INVOCATION_ADAPTER
        || audit.adapter_version != COMPILER_PRECISE_INVOCATION_ADAPTER_VERSION
        || audit.profile_id != expected_profile
        || audit.target.as_deref() != Some(pack.target.as_str())
        || audit.toolchain_executable_digest != pack.cargo_sha256
        || audit
            .validated_output_digest
            .as_deref()
            .is_none_or(|value| !is_digest(value))
        || pack.contract_version != COMPILER_PRECISE_CONTRACT_VERSION
        || invocations.attempt_digest != expected_attempt
        || invocations
            .entries
            .iter()
            .any(|entry| entry.rustc_sha256 != pack.rustc_sha256)
    {
        bail!("compiler-precise attempt is incomplete or compatibility-mismatched");
    }
    Ok(())
}

pub fn compiler_precise_graph_events(
    snapshot: &GraphSnapshot,
    audit: &BuildAudit,
    pack: &CompilerPackAttestation,
    graph: &RustCargoUnitGraph,
    invocations: &RustCompilerInvocationLedger,
    mir: &RustCompilerMirLedger,
) -> Result<Vec<ProtocolEvent>> {
    validate_complete_attempt(audit, pack, graph, invocations, mir)?;
    let parent = compiler_parent_profile(snapshot, audit)?;
    let context = EvidenceContext {
        audit,
        pack,
        graph,
        invocations,
        mir,
    };
    let mut nodes = BTreeMap::<String, GraphNode>::new();
    let mut sites = BTreeMap::<String, DependencySite>::new();
    let mut edges = BTreeMap::<String, GraphEdge>::new();
    let mir_units = mir
        .entries
        .iter()
        .map(|unit| (unit.unit_id.as_str(), unit))
        .collect::<BTreeMap<_, _>>();
    let mut unit_node_ids = BTreeMap::<&str, String>::new();

    for unit in &graph.units {
        let path = logical_path(mir, "unit", &unit.unit_id);
        let mir_unit = mir_units.get(unit.unit_id.as_str()).copied();
        let artifact_digest = mir_unit.map_or(unit.unit_id.as_str(), |value| value.digest.as_str());
        let node = generated_node(
            "rust_compiler_unit",
            json!({
                "contract_version": COMPILER_PRECISE_CONTRACT_VERSION,
                "graph_contract_version": COMPILER_PRECISE_GRAPH_CONTRACT_VERSION,
                "profile_id": audit.profile_id,
                "compiler_pack_manifest_sha256": pack.manifest_sha256,
                "unit_graph_digest": graph.digest,
                "unit_id": unit.unit_id,
            }),
            format!("Cargo unit {}", unit.target.name),
            Map::from_iter([
                ("language".to_owned(), json!("rust")),
                ("package_id".to_owned(), json!(unit.package_id)),
                (
                    "cargo_target".to_owned(),
                    serde_json::to_value(&unit.target)?,
                ),
                (
                    "cargo_profile".to_owned(),
                    serde_json::to_value(&unit.profile)?,
                ),
                ("platform".to_owned(), json!(unit.platform)),
                ("mode".to_owned(), json!(unit.mode)),
                ("features".to_owned(), json!(unit.features)),
                ("is_std".to_owned(), json!(unit.is_std)),
                (
                    "is_root".to_owned(),
                    json!(graph.roots.contains(&unit.unit_id)),
                ),
                ("unit_id".to_owned(), json!(unit.unit_id)),
                (
                    "mir_unit_digest".to_owned(),
                    json!(mir_unit.map(|value| &value.digest)),
                ),
            ]),
            &context,
            GraphArtifact {
                logical_path: &path,
                digest: artifact_digest,
                unit: mir_unit,
            },
        );
        let node = materialize_generated_node(snapshot, node)?;
        unit_node_ids.insert(unit.unit_id.as_str(), node.id.clone());
        insert_node(&mut nodes, node)?;
    }

    for unit in &graph.units {
        let source = unit_node_ids
            .get(unit.unit_id.as_str())
            .context("compiler Cargo unit node is missing")?;
        for dependency in &unit.dependencies {
            let target = unit_node_ids
                .get(dependency.unit_id.as_str())
                .context("compiler Cargo dependency node is missing")?
                .clone();
            let path = logical_path(mir, "unit", &unit.unit_id);
            add_relation(
                snapshot,
                &mut sites,
                &mut edges,
                audit,
                RelationInput {
                    source,
                    targets: vec![target],
                    kind: "depends_on_cargo_unit",
                    specifier: dependency.extern_crate_name.clone(),
                    status: ResolutionStatus::Resolved,
                    reason: None,
                    evidence: context.evidence(&path, &unit.unit_id, None, None),
                },
            )?;
        }
    }

    for unit in &mir.entries {
        let unit_node = unit_node_ids
            .get(unit.unit_id.as_str())
            .context("typed MIR Cargo unit node is missing")?;
        for body in &unit.bodies {
            let path = logical_path(mir, "body", &body.body_id);
            let node = generated_node(
                "rust_mir_body",
                json!({
                    "contract_version": COMPILER_PRECISE_CONTRACT_VERSION,
                    "graph_contract_version": COMPILER_PRECISE_GRAPH_CONTRACT_VERSION,
                    "profile_id": audit.profile_id,
                    "unit_id": unit.unit_id,
                    "body_id": body.body_id,
                }),
                body.definition.path.clone(),
                Map::from_iter([
                    ("language".to_owned(), json!("rust")),
                    ("unit_id".to_owned(), json!(unit.unit_id)),
                    ("body_id".to_owned(), json!(body.body_id)),
                    ("body_kind".to_owned(), serde_json::to_value(&body.kind)?),
                    (
                        "definition".to_owned(),
                        serde_json::to_value(&body.definition)?,
                    ),
                    ("source_span".to_owned(), serde_json::to_value(&body.span)?),
                    ("type_count".to_owned(), json!(body.types.len())),
                    ("constant_count".to_owned(), json!(body.constants.len())),
                    ("local_count".to_owned(), json!(body.locals.len())),
                    ("place_count".to_owned(), json!(body.places.len())),
                    ("block_count".to_owned(), json!(body.blocks.len())),
                ]),
                &context,
                GraphArtifact {
                    logical_path: &path,
                    digest: &body.body_id,
                    unit: Some(unit),
                },
            );
            let node = materialize_generated_node(snapshot, node)?;
            insert_node(&mut nodes, node.clone())?;
            add_relation(
                snapshot,
                &mut sites,
                &mut edges,
                audit,
                RelationInput {
                    source: unit_node,
                    targets: vec![node.id.clone()],
                    kind: "contains_typed_mir_body",
                    specifier: body.body_id.clone(),
                    status: ResolutionStatus::Resolved,
                    reason: None,
                    evidence: context.evidence(&path, &body.body_id, Some(unit), Some(&body.span)),
                },
            )?;
            if let Some(source) = source_node_for_path(snapshot, &body.span.source_path) {
                let source = base_node(source)?;
                insert_node(&mut nodes, source.clone())?;
                add_relation(
                    snapshot,
                    &mut sites,
                    &mut edges,
                    audit,
                    RelationInput {
                        source: &source.id,
                        targets: vec![node.id],
                        kind: "observes_typed_mir",
                        specifier: body.definition.definition_id.clone(),
                        status: ResolutionStatus::Resolved,
                        reason: None,
                        evidence: context.evidence(
                            &path,
                            &body.body_id,
                            Some(unit),
                            Some(&body.span),
                        ),
                    },
                )?;
            }
        }

        let mut instance_node_ids = BTreeMap::<&str, String>::new();
        for instance in &unit.instances {
            let path = logical_path(mir, "instance", &instance.instance_id);
            let node = generated_node(
                "rust_compiler_instance",
                json!({
                    "contract_version": COMPILER_PRECISE_CONTRACT_VERSION,
                    "graph_contract_version": COMPILER_PRECISE_GRAPH_CONTRACT_VERSION,
                    "profile_id": audit.profile_id,
                    "unit_id": unit.unit_id,
                    "instance_id": instance.instance_id,
                }),
                instance.symbol_name.clone(),
                Map::from_iter([
                    ("language".to_owned(), json!("rust")),
                    ("unit_id".to_owned(), json!(unit.unit_id)),
                    ("instance_id".to_owned(), json!(instance.instance_id)),
                    (
                        "instance_kind".to_owned(),
                        serde_json::to_value(instance.kind)?,
                    ),
                    ("variant".to_owned(), json!(instance.variant)),
                    (
                        "definition_path".to_owned(),
                        json!(instance.definition_path),
                    ),
                    ("symbol_name".to_owned(), json!(instance.symbol_name)),
                    (
                        "generic_arguments".to_owned(),
                        serde_json::to_value(&instance.generic_arguments)?,
                    ),
                    (
                        "definition".to_owned(),
                        serde_json::to_value(&instance.definition)?,
                    ),
                    (
                        "compiler_generated".to_owned(),
                        json!(instance.compiler_generated),
                    ),
                ]),
                &context,
                GraphArtifact {
                    logical_path: &path,
                    digest: &instance.instance_id,
                    unit: Some(unit),
                },
            );
            let node = materialize_generated_node(snapshot, node)?;
            instance_node_ids.insert(instance.instance_id.as_str(), node.id.clone());
            insert_node(&mut nodes, node.clone())?;
            add_relation(
                snapshot,
                &mut sites,
                &mut edges,
                audit,
                RelationInput {
                    source: unit_node,
                    targets: vec![node.id],
                    kind: "contains_compiler_instance",
                    specifier: instance.instance_id.clone(),
                    status: ResolutionStatus::Resolved,
                    reason: None,
                    evidence: context.evidence(
                        &path,
                        &instance.instance_id,
                        Some(unit),
                        instance.definition.as_ref().map(|value| &value.span),
                    ),
                },
            )?;
        }

        for call in &unit.calls {
            let source = instance_node_ids
                .get(call.caller_instance_id.as_str())
                .context("compiler call caller node is missing")?;
            let path = logical_path(mir, "call", &call.call_id);
            let (targets, status, reason) = match call.resolution {
                RustCompilerCallResolution::Resolved => (
                    call.target_instance_ids
                        .iter()
                        .map(|id| {
                            instance_node_ids
                                .get(id.as_str())
                                .cloned()
                                .with_context(|| format!("compiler call target {id} is missing"))
                        })
                        .collect::<Result<Vec<_>>>()?,
                    ResolutionStatus::Resolved,
                    None,
                ),
                RustCompilerCallResolution::Candidate => (
                    call.target_instance_ids
                        .iter()
                        .map(|id| {
                            instance_node_ids
                                .get(id.as_str())
                                .cloned()
                                .with_context(|| format!("compiler call candidate {id} is missing"))
                        })
                        .collect::<Result<Vec<_>>>()?,
                    ResolutionStatus::Candidates,
                    None,
                ),
                RustCompilerCallResolution::UnknownTarget => {
                    let reason = call
                        .reason_code
                        .as_ref()
                        .context("unknown compiler call has no reason")?;
                    let reason_name = enum_string(reason)?;
                    let unknown_path = logical_path(mir, "unknown-target", &call.call_id);
                    let unknown = generated_node(
                        "unknown_target",
                        json!({
                            "contract_version": COMPILER_PRECISE_CONTRACT_VERSION,
                            "graph_contract_version": COMPILER_PRECISE_GRAPH_CONTRACT_VERSION,
                            "profile_id": audit.profile_id,
                            "unit_id": unit.unit_id,
                            "call_id": call.call_id,
                            "reason": reason_name,
                        }),
                        format!("unknown compiler target ({reason_name})"),
                        Map::from_iter([
                            ("language".to_owned(), json!("rust")),
                            ("unit_id".to_owned(), json!(unit.unit_id)),
                            ("call_id".to_owned(), json!(call.call_id)),
                            ("reason".to_owned(), json!(reason_name)),
                        ]),
                        &context,
                        GraphArtifact {
                            logical_path: &unknown_path,
                            digest: &call.call_id,
                            unit: Some(unit),
                        },
                    );
                    let unknown = materialize_generated_node(snapshot, unknown)?;
                    insert_node(&mut nodes, unknown.clone())?;
                    (
                        vec![unknown.id],
                        ResolutionStatus::Unresolved,
                        Some(reason_name),
                    )
                }
            };
            add_relation(
                snapshot,
                &mut sites,
                &mut edges,
                audit,
                RelationInput {
                    source,
                    targets,
                    kind: match call.relation {
                        crate::RustCompilerCallRelation::Calls => "calls",
                        crate::RustCompilerCallRelation::MayCall => "may_call",
                    },
                    specifier: call.call_id.clone(),
                    status,
                    reason,
                    evidence: context.evidence(
                        &path,
                        &call.call_id,
                        Some(unit),
                        call.span.as_ref(),
                    ),
                },
            )?;
        }
    }

    let mut environment = parent
        .environment
        .as_object()
        .cloned()
        .context("safe Rust parent profile environment must be an object")?
        .into_iter()
        .collect::<BTreeMap<_, _>>();
    environment.insert("phase".to_owned(), json!("build"));
    let features = graph
        .units
        .iter()
        .flat_map(|unit| unit.features.iter().cloned())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let body_count = mir
        .entries
        .iter()
        .map(|unit| unit.bodies.len())
        .sum::<usize>();
    let instance_count = mir
        .entries
        .iter()
        .map(|unit| unit.instances.len())
        .sum::<usize>();
    let call_count = mir
        .entries
        .iter()
        .map(|unit| unit.calls.len())
        .sum::<usize>();
    let unsupported_count = mir
        .entries
        .iter()
        .map(|unit| unit.unsupported.len())
        .sum::<usize>();
    let profile = Profile {
        id: audit.profile_id.clone(),
        language: "rust".to_owned(),
        toolchain: Some(json!({
            "channel": COMPILER_PACK_TOOLCHAIN_CHANNEL,
            "rust_release": COMPILER_PACK_RUST_RELEASE,
            "rustc_commit": COMPILER_PACK_RUSTC_COMMIT,
            "compiler_pack_manifest_sha256": pack.manifest_sha256,
        })),
        command: Some(audit.command_arguments.join(" ")),
        target: Some(pack.target.clone()),
        features,
        environment,
        source_revision: None,
        properties: BTreeMap::from([
            (
                "profile_contract".to_owned(),
                json!("phase-parent-effective-v1"),
            ),
            ("profile_phase".to_owned(), json!("build")),
            ("parent_profile_id".to_owned(), json!(parent.id)),
            (
                "effective_input_id".to_owned(),
                json!(canonical_effective_input_id(parent)),
            ),
            (
                "compiler_precise_contract".to_owned(),
                json!(COMPILER_PRECISE_CONTRACT_VERSION),
            ),
            (
                "compiler_precise_graph_contract".to_owned(),
                json!(COMPILER_PRECISE_GRAPH_CONTRACT_VERSION),
            ),
            (
                "build_capability".to_owned(),
                json!(COMPILER_PRECISE_GRAPH_CAPABILITY),
            ),
            ("observer".to_owned(), json!(audit.adapter)),
            ("observer_version".to_owned(), json!(audit.adapter_version)),
            ("project_code_executed".to_owned(), Value::Bool(true)),
            ("precision".to_owned(), json!("observed")),
            ("compiler_pack_host".to_owned(), json!(pack.host)),
            ("compiler_pack_target".to_owned(), json!(pack.target)),
            (
                "compiler_pack_manifest_sha256".to_owned(),
                json!(pack.manifest_sha256),
            ),
            ("unit_graph_digest".to_owned(), json!(graph.digest)),
            (
                "invocation_ledger_digest".to_owned(),
                json!(invocations.digest),
            ),
            ("mir_ledger_digest".to_owned(), json!(mir.digest)),
            ("cargo_unit_count".to_owned(), json!(graph.units.len())),
            ("typed_mir_body_count".to_owned(), json!(body_count)),
            ("compiler_instance_count".to_owned(), json!(instance_count)),
            ("compiler_call_count".to_owned(), json!(call_count)),
            (
                "unsupported_construct_count".to_owned(),
                json!(unsupported_count),
            ),
            (
                "query_capabilities".to_owned(),
                json!(["monomorphized_call_graph", "typed_mir"]),
            ),
            (
                "completeness_scope".to_owned(),
                json!("admitted-cargo-units-and-query-capabilities"),
            ),
            (
                "safe_semantic_completeness_claimed".to_owned(),
                Value::Bool(false),
            ),
        ]),
    };
    let mut counts = BTreeMap::<String, u64>::new();
    for site in sites.values() {
        *counts
            .entry(enum_string(&site.resolution_status)?)
            .or_default() += 1;
    }
    let coverage = Coverage {
        profiles: 1,
        files_discovered: 0,
        files_analyzed: 0,
        files_skipped: 0,
        dependency_sites: sites.len().try_into().unwrap_or(u64::MAX),
        resolved: counts.get("resolved").copied().unwrap_or(0),
        candidates: counts.get("candidates").copied().unwrap_or(0),
        external: 0,
        unresolved: counts.get("unresolved").copied().unwrap_or(0),
        unsupported_syntax: if sites.is_empty() {
            0
        } else {
            unsupported_count.try_into().unwrap_or(u64::MAX)
        },
        project_code_executed: true,
        completeness: vec![CompletenessLevel::BuildObserved],
        reasons: if sites.is_empty() {
            Vec::new()
        } else {
            mir.entries
                .iter()
                .flat_map(|unit| unit.unsupported.iter().map(|item| item.reason_code.clone()))
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect()
        },
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

pub fn compiler_precise_graph_ndjson(
    snapshot: &GraphSnapshot,
    audit: &BuildAudit,
    pack: &CompilerPackAttestation,
    graph: &RustCargoUnitGraph,
    invocations: &RustCompilerInvocationLedger,
    mir: &RustCompilerMirLedger,
) -> Result<Vec<u8>> {
    let events = compiler_precise_graph_events(snapshot, audit, pack, graph, invocations, mir)?;
    let mut output = Vec::new();
    for event in events {
        serde_json::to_writer(&mut output, &event)?;
        output.push(b'\n');
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use std::{io::Cursor, path::Path};

    use depgraph_protocol::validate_build_ndjson;
    use depgraph_store::Store;
    use serde_json::json;

    use super::*;
    use crate::{
        CancellationToken, ExportFormat, NetworkIsolation, RustCargoProfile, RustCargoStrip,
        RustCargoTarget, RustCargoUnit, RustCompilerCallEvidence, RustCompilerCallReason,
        RustCompilerCallRelation, RustCompilerGenericArgument, RustCompilerMirBlock,
        RustCompilerMirBody, RustCompilerMirBodyKind, RustCompilerMirDefinition,
        RustCompilerMirLocal, RustCompilerMirOperation, RustCompilerMirPlace,
        RustCompilerMirProjection, RustCompilerMirType, RustCompilerMonoInstance,
        RustCompilerMonoInstanceKind, compiler_invocation_entry_digest,
        compiler_invocation_ledger_digest, compiler_mir_ledger_digest, compiler_mir_unit_digest,
        compiler_unit_graph_digest, execute_bounded_query, export,
        parse_and_type_check_bounded_query, plan_bounded_query, stage_build_evidence, why,
    };

    #[derive(Clone)]
    struct Fixture {
        audit: BuildAudit,
        pack: CompilerPackAttestation,
        graph: RustCargoUnitGraph,
        invocations: RustCompilerInvocationLedger,
        mir: RustCompilerMirLedger,
    }

    fn canonical_digest(value: &impl Serialize) -> Result<String> {
        fn sort(value: &mut Value) {
            match value {
                Value::Array(values) => {
                    for value in values {
                        sort(value);
                    }
                }
                Value::Object(object) => {
                    let mut entries = std::mem::take(object).into_iter().collect::<Vec<_>>();
                    entries.sort_by(|left, right| left.0.cmp(&right.0));
                    for (key, mut value) in entries {
                        sort(&mut value);
                        object.insert(key, value);
                    }
                }
                _ => {}
            }
        }
        let mut value = serde_json::to_value(value)?;
        sort(&mut value);
        Ok(sha256(serde_json::to_vec(&value)?))
    }

    fn definition(path: &str, span: &RustCompilerMirSpan) -> Result<RustCompilerMirDefinition> {
        Ok(RustCompilerMirDefinition {
            definition_id: canonical_digest(&(
                path,
                span.source_path.as_str(),
                span.source_sha256.as_str(),
                span.start_line,
                span.start_column,
                span.end_line,
                span.end_column,
            ))?,
            path: path.to_owned(),
            span: span.clone(),
        })
    }

    struct InstanceContext<'a> {
        unit_id: &'a str,
        package_id: &'a str,
        target_digest: &'a str,
        profile_digest: &'a str,
        pack: &'a CompilerPackAttestation,
    }

    fn instance(
        context: &InstanceContext<'_>,
        kind: RustCompilerMonoInstanceKind,
        path: &str,
        symbol: &str,
        definition: Option<RustCompilerMirDefinition>,
    ) -> Result<RustCompilerMonoInstance> {
        let variant = "item";
        let arguments = Vec::<RustCompilerGenericArgument>::new();
        let generated = false;
        Ok(RustCompilerMonoInstance {
            instance_id: canonical_digest(&(
                context.unit_id,
                context.package_id,
                context.target_digest,
                context.profile_digest,
                context.pack.manifest_sha256.as_str(),
                COMPILER_PACK_RUSTC_COMMIT,
                &kind,
                variant,
                path,
                symbol,
                &arguments,
                &definition,
                generated,
            ))?,
            kind,
            variant: variant.to_owned(),
            definition_path: path.to_owned(),
            symbol_name: symbol.to_owned(),
            generic_arguments: arguments,
            definition,
            compiler_generated: generated,
        })
    }

    struct CallSpec {
        relation: crate::RustCompilerCallRelation,
        resolution: RustCompilerCallResolution,
        evidence: RustCompilerCallEvidence,
        targets: Vec<String>,
        reason: Option<RustCompilerCallReason>,
    }

    fn call(
        caller: &str,
        ordinal: u32,
        span: &RustCompilerMirSpan,
        mut spec: CallSpec,
    ) -> Result<crate::RustCompilerCall> {
        spec.targets.sort();
        let call_id = canonical_digest(&(
            caller,
            0_u32,
            ordinal,
            &spec.relation,
            &spec.resolution,
            &spec.evidence,
            &spec.targets,
            Some(span),
            &spec.reason,
        ))?;
        Ok(crate::RustCompilerCall {
            call_id,
            caller_instance_id: caller.to_owned(),
            block_ordinal: 0,
            operation_ordinal: ordinal,
            relation: spec.relation,
            resolution: spec.resolution,
            evidence: spec.evidence,
            target_instance_ids: spec.targets,
            span: Some(span.clone()),
            reason_code: spec.reason,
        })
    }

    fn fixture(run_id: &str) -> Result<Fixture> {
        let pack = CompilerPackAttestation {
            contract_version: COMPILER_PRECISE_CONTRACT_VERSION.to_owned(),
            host: "x86_64-unknown-linux-gnu".to_owned(),
            target: "x86_64-unknown-linux-gnu".to_owned(),
            manifest_sha256: "a".repeat(64),
            closed_tree_sha256: "b".repeat(64),
            cargo_sha256: "c".repeat(64),
            rustc_sha256: "d".repeat(64),
            wrapper_sha256: "e".repeat(64),
            query_sha256: "f".repeat(64),
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
        let unit_id = "unit-fixture".to_owned();
        let package_id = "path+repo://.#0.1.0".to_owned();
        let graph_unit = RustCargoUnit {
            unit_id: unit_id.clone(),
            package_id: package_id.clone(),
            target: target.clone(),
            profile: profile.clone(),
            platform: Some(pack.target.clone()),
            mode: "build".to_owned(),
            features: vec!["feature-a".to_owned()],
            is_std: false,
            dependencies: Vec::new(),
        };
        let roots = vec![unit_id.clone()];
        let graph = RustCargoUnitGraph {
            schema_version: crate::COMPILER_PRECISE_UNIT_GRAPH_SCHEMA_VERSION.to_owned(),
            digest: compiler_unit_graph_digest(std::slice::from_ref(&graph_unit), &roots)?,
            units: vec![graph_unit],
            roots,
        };
        let source_root_digest = "6".repeat(64);
        let command_plan_digest = "7".repeat(64);
        let attempt_digest = compiler_invocation_attempt_digest(
            &source_root_digest,
            &command_plan_digest,
            &pack.manifest_sha256,
            &graph.digest,
        )?;
        let canonical_argv = vec!["--crate-name".to_owned(), "fixture".to_owned()];
        let mut invocation = crate::RustCompilerInvocation {
            unit_id: unit_id.clone(),
            invocation_id: "1".repeat(64),
            invocation_digest: String::new(),
            crate_name: "fixture".to_owned(),
            crate_types: vec!["lib".to_owned()],
            source_path: target.src_path.clone(),
            source_sha256: "2".repeat(64),
            profile_digest: canonical_digest(&profile)?,
            edition: target.edition.clone(),
            target: Some(pack.target.clone()),
            mode: "build".to_owned(),
            features: vec!["feature-a".to_owned()],
            canonical_argv: canonical_argv.clone(),
            argv_digest: canonical_digest(&canonical_argv)?,
            rustc_sha256: pack.rustc_sha256.clone(),
            rustc_verbose_sha256: "3".repeat(64),
            terminal_status: "completed".to_owned(),
            exit_code: 0,
        };
        invocation.invocation_digest = compiler_invocation_entry_digest(&invocation)?;
        let invocation_entries = vec![invocation.clone()];
        let invocations = RustCompilerInvocationLedger {
            schema_version: crate::COMPILER_INVOCATION_LEDGER_SCHEMA_VERSION.to_owned(),
            digest: compiler_invocation_ledger_digest(
                &attempt_digest,
                &graph.digest,
                &invocation_entries,
            )?,
            attempt_digest: attempt_digest.clone(),
            unit_graph_digest: graph.digest.clone(),
            entries: invocation_entries,
        };
        let span = RustCompilerMirSpan {
            source_path: target.src_path.clone(),
            source_sha256: invocation.source_sha256.clone(),
            start_line: 1,
            start_column: 1,
            end_line: 1,
            end_column: 24,
        };
        let root_definition = definition("fixture::root", &span)?;
        let body_id = canonical_digest(&(
            unit_id.as_str(),
            package_id.as_str(),
            canonical_digest(&target)?.as_str(),
            invocation.profile_digest.as_str(),
            RustCompilerMirBodyKind::Function,
            &root_definition,
        ))?;
        let unit_type = RustCompilerMirType {
            type_id: canonical_digest(&(
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
            local_id: canonical_digest(&(body_id.as_str(), "local", 0_u32))?,
            ordinal: 0,
            role: "return".to_owned(),
            type_id: unit_type.type_id.clone(),
            span: span.clone(),
        };
        let place = RustCompilerMirPlace {
            place_id: canonical_digest(&(
                body_id.as_str(),
                local.local_id.as_str(),
                Vec::<RustCompilerMirProjection>::new(),
                unit_type.type_id.as_str(),
            ))?,
            local_id: local.local_id.clone(),
            projections: Vec::new(),
            type_id: unit_type.type_id.clone(),
        };
        let block_id = canonical_digest(&(body_id.as_str(), "block", 0_u32))?;
        let operation = RustCompilerMirOperation {
            operation_id: canonical_digest(&(
                body_id.as_str(),
                block_id.as_str(),
                0_u32,
                "return",
            ))?,
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
            definition: root_definition.clone(),
            span: span.clone(),
            types: vec![unit_type],
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
        let target_digest = canonical_digest(&target)?;
        let instance_context = InstanceContext {
            unit_id: &unit_id,
            package_id: &package_id,
            target_digest: &target_digest,
            profile_digest: &invocation.profile_digest,
            pack: &pack,
        };
        let caller = instance(
            &instance_context,
            RustCompilerMonoInstanceKind::Function,
            "fixture::root",
            "_RNvCfixture4root",
            Some(root_definition),
        )?;
        let callee = instance(
            &instance_context,
            RustCompilerMonoInstanceKind::Function,
            "fixture::callee",
            "_RNvCfixture6callee",
            Some(definition("fixture::callee", &span)?),
        )?;
        let external = instance(
            &instance_context,
            RustCompilerMonoInstanceKind::External,
            "external::callback",
            "_RNvCexternal8callback",
            None,
        )?;
        let mut instances = vec![caller.clone(), callee.clone(), external.clone()];
        instances.sort_by(|left, right| left.instance_id.cmp(&right.instance_id));
        let mut calls = vec![
            call(
                &caller.instance_id,
                0,
                &span,
                CallSpec {
                    relation: RustCompilerCallRelation::Calls,
                    resolution: RustCompilerCallResolution::Resolved,
                    evidence: RustCompilerCallEvidence::Observed,
                    targets: vec![callee.instance_id.clone()],
                    reason: None,
                },
            )?,
            call(
                &caller.instance_id,
                1,
                &span,
                CallSpec {
                    relation: RustCompilerCallRelation::MayCall,
                    resolution: RustCompilerCallResolution::Candidate,
                    evidence: RustCompilerCallEvidence::Candidate,
                    targets: vec![callee.instance_id, external.instance_id],
                    reason: None,
                },
            )?,
            call(
                &caller.instance_id,
                2,
                &span,
                CallSpec {
                    relation: RustCompilerCallRelation::MayCall,
                    resolution: RustCompilerCallResolution::UnknownTarget,
                    evidence: RustCompilerCallEvidence::Unknown,
                    targets: Vec::new(),
                    reason: Some(RustCompilerCallReason::FnPointerUnbounded),
                },
            )?,
        ];
        calls.sort_by(|left, right| left.call_id.cmp(&right.call_id));
        let mut mir_unit = RustCompilerMirUnit {
            schema_version: crate::COMPILER_PRECISE_MIR_SCHEMA_VERSION.to_owned(),
            digest: String::new(),
            attempt_digest: attempt_digest.clone(),
            invocation_id: invocation.invocation_id,
            unit_id,
            package_id,
            target_digest,
            source_path: invocation.source_path,
            source_sha256: invocation.source_sha256,
            profile_digest: invocation.profile_digest,
            compiler_pack_manifest_sha256: pack.manifest_sha256.clone(),
            rustc_commit: COMPILER_PACK_RUSTC_COMMIT.to_owned(),
            query_capabilities: vec![
                "monomorphized_call_graph".to_owned(),
                "typed_mir".to_owned(),
            ],
            instances,
            calls,
            bodies: vec![body],
            unsupported: Vec::new(),
        };
        mir_unit.digest = compiler_mir_unit_digest(&mir_unit)?;
        let mir_entries = vec![mir_unit];
        let mir = RustCompilerMirLedger {
            schema_version: crate::COMPILER_PRECISE_MIR_LEDGER_SCHEMA_VERSION.to_owned(),
            digest: compiler_mir_ledger_digest(
                &attempt_digest,
                &graph.digest,
                &invocations.digest,
                &mir_entries,
            )?,
            attempt_digest,
            unit_graph_digest: graph.digest.clone(),
            invocation_ledger_digest: invocations.digest.clone(),
            entries: mir_entries,
        };
        let audit = BuildAudit {
            schema_version: crate::BUILD_SUPERVISOR_VERSION.to_owned(),
            run_id: run_id.to_owned(),
            adapter: COMPILER_PRECISE_INVOCATION_ADAPTER.to_owned(),
            adapter_version: COMPILER_PRECISE_INVOCATION_ADAPTER_VERSION.to_owned(),
            profile_id: compiler_precise_profile_id(
                &pack.host,
                &pack.target,
                &pack.manifest_sha256,
                &graph.digest,
            )?,
            command_program: "cargo".to_owned(),
            command_arguments: vec![
                "build".to_owned(),
                "--frozen".to_owned(),
                "--offline".to_owned(),
                "--target".to_owned(),
                pack.target.clone(),
            ],
            command_plan_digest,
            logical_cwd: ".".to_owned(),
            source_root_digest,
            toolchain_executable_digest: pack.cargo_sha256.clone(),
            toolchain_version: Some("cargo 1.99.0-nightly".to_owned()),
            target: Some(pack.target.clone()),
            environment_keys: Vec::new(),
            environment_key_set_digest: "8".repeat(64),
            redacted_secret_key_count: 0,
            timeout_seconds: 900,
            stdout_limit_bytes: 1024,
            stderr_limit_bytes: 1024,
            network_policy: "deny".to_owned(),
            network_isolation: NetworkIsolation::Enforced,
            isolation_diagnostic: None,
            started_at: "2026-07-29T00:00:00.000Z".to_owned(),
            finished_at: "2026-07-29T00:00:01.000Z".to_owned(),
            duration_millis: 1000,
            outcome: BuildOutcomeKind::Completed,
            exit_code: Some(0),
            stdout_truncated: false,
            stderr_truncated: false,
            validated_output_digest: Some("9".repeat(64)),
            diagnostic_code: None,
        };
        Ok(Fixture {
            audit,
            pack,
            graph,
            invocations,
            mir,
        })
    }

    fn base_protocol(root: &str) -> String {
        let coverage = json!({
            "profiles": 1,
            "files_discovered": 0,
            "files_analyzed": 0,
            "files_skipped": 0,
            "dependency_sites": 0,
            "resolved": 0,
            "candidates": 0,
            "external": 0,
            "unresolved": 0,
            "unsupported_syntax": 0,
            "project_code_executed": false,
            "completeness": ["syntax-complete"],
            "reasons": []
        });
        [
            json!({"event":"scan_started","protocol_version":"1.0","scan_id":"safe-base","adapter":"rust","adapter_version":"0.1.0","seq":1,"root":root,"project_code_executed":false,"safe_mode":true}),
            json!({"event":"profile_declared","protocol_version":"1.0","scan_id":"safe-base","adapter":"rust","adapter_version":"0.1.0","seq":2,"profile":{"id":"rust:safe:fixture","language":"rust","toolchain":"rust 1.93.1","command":"scan","target":"x86_64-unknown-linux-gnu","features":["feature-a"],"environment":{},"source_revision":"fixture","properties":{"analysis":"syntax+hir"}}}),
            json!({"event":"node_upsert","protocol_version":"1.0","scan_id":"safe-base","adapter":"rust","adapter_version":"0.1.0","seq":3,"node":{"id":"file:fixture","kind":"file","locator":"src/lib.rs","display_name":"src/lib.rs","properties":{"language":"rust"}}}),
            json!({"event":"profile_completed","protocol_version":"1.0","scan_id":"safe-base","adapter":"rust","adapter_version":"0.1.0","seq":4,"profile_id":"rust:safe:fixture","coverage":coverage}),
            json!({"event":"scan_completed","protocol_version":"1.0","scan_id":"safe-base","adapter":"rust","adapter_version":"0.1.0","seq":5,"coverage":coverage}),
        ]
        .into_iter()
        .map(|event| serde_json::to_string(&event).expect("base event"))
        .collect::<Vec<_>>()
        .join("\n")
    }

    fn store_with_base(root: &Path) -> Result<Store> {
        let mut store = Store::open_in_memory()?;
        store.start_scan_with_revision("safe-base", root, false, Some("fixture"))?;
        for line in base_protocol(&root.to_string_lossy()).lines() {
            store.ingest_event(&serde_json::from_str(line)?)?;
        }
        store.finish_scan("safe-base", "completed", None, true)?;
        Ok(store)
    }

    fn promote(store: &mut Store, fixture: &Fixture) -> Result<()> {
        let audit = serde_json::to_value(&fixture.audit)?;
        store.save_build_audit(&audit)?;
        store.start_build_attempt("safe-base", &audit)?;
        let base = store.load_snapshot("safe-base")?;
        let ndjson = compiler_precise_graph_ndjson(
            &base,
            &fixture.audit,
            &fixture.pack,
            &fixture.graph,
            &fixture.invocations,
            &fixture.mir,
        )?;
        validate_build_ndjson(Cursor::new(&ndjson))?;
        stage_build_evidence(store, &fixture.audit.run_id, Cursor::new(ndjson))?;
        store.finish_build_attempt(&fixture.audit.run_id, "completed", None, true)
    }

    #[test]
    fn compiler_graph_is_promoted_and_visible_to_why_query_and_exports() -> Result<()> {
        let fixture = fixture("compiler-build-1")?;
        let mut store = store_with_base(Path::new("/fixture"))?;
        promote(&mut store, &fixture)?;
        let snapshot = store.load_snapshot("safe-base")?;

        assert!(
            snapshot
                .nodes
                .iter()
                .any(|node| node.kind == "rust_mir_body")
        );
        assert!(
            snapshot
                .edges
                .iter()
                .all(|edge| edge.phase != "build" || edge.precision == "observed")
        );
        assert!(snapshot.profiles.iter().any(|profile| {
            profile.id == fixture.audit.profile_id
                && profile
                    .properties
                    .get("safe_semantic_completeness_claimed")
                    .and_then(Value::as_bool)
                    == Some(false)
        }));
        let caller = snapshot
            .nodes
            .iter()
            .find(|node| node.properties.get("symbol_name") == Some(&json!("_RNvCfixture4root")))
            .context("caller node")?;
        let callee = snapshot
            .nodes
            .iter()
            .find(|node| node.properties.get("symbol_name") == Some(&json!("_RNvCfixture6callee")))
            .context("callee node")?;
        let explanation = why(&snapshot, &caller.id, &callee.id)?;
        assert!(explanation.path_found);
        assert!(
            explanation
                .steps
                .iter()
                .all(|step| step.edge.phase == "build" && step.edge.precision == "observed")
        );

        let typed = parse_and_type_check_bounded_query(
            "MATCH p = (source:\"rust_compiler_instance\")-[\"calls\"*1..1]->(target:\"rust_compiler_instance\") RETURN source.id, target.id, p.id ORDER BY source.id, target.id, p.id ASC LIMIT 10",
        )?;
        let plan = plan_bounded_query(&typed, "compiler-snapshot", &snapshot)?;
        assert!(plan.admitted, "{:?}", plan.reasons);
        let result = execute_bounded_query(&typed, &plan, &snapshot, &CancellationToken::new())?;
        assert!(!result.rows.is_empty());
        for format in [ExportFormat::Json, ExportFormat::Dot, ExportFormat::Mermaid] {
            assert!(export(&snapshot, format)?.contains("calls"));
        }
        Ok(())
    }

    #[test]
    fn repeated_promotion_is_byte_stable_and_failure_rolls_back() -> Result<()> {
        let first = fixture("compiler-build-1")?;
        let mut store = store_with_base(Path::new("/fixture"))?;
        promote(&mut store, &first)?;
        let first_snapshot = store.load_snapshot("safe-base")?;
        let first_json = export(&first_snapshot, ExportFormat::Json)?;

        let mut other_checkout = store_with_base(Path::new("/different/checkout"))?;
        promote(&mut other_checkout, &first)?;
        let other_snapshot = other_checkout.load_snapshot("safe-base")?;
        assert_eq!(export(&other_snapshot, ExportFormat::Json)?, first_json);
        assert_eq!(other_snapshot.coverage, first_snapshot.coverage);
        assert_eq!(other_snapshot.evidence, first_snapshot.evidence);

        let second = fixture("compiler-build-2")?;
        promote(&mut store, &second)?;
        let repeated = store.load_snapshot("safe-base")?;
        assert_eq!(export(&repeated, ExportFormat::Json)?, first_json);
        assert_eq!(repeated.coverage, first_snapshot.coverage);
        assert_eq!(repeated.evidence, first_snapshot.evidence);

        let failed = fixture("compiler-build-invalid")?;
        let audit = serde_json::to_value(&failed.audit)?;
        store.save_build_audit(&audit)?;
        store.start_build_attempt("safe-base", &audit)?;
        let current_id = store.current_snapshot_id()?.context("current snapshot")?;
        let current = store.load_completed_snapshot(&current_id)?;
        let mut incomplete = failed.mir.clone();
        incomplete.entries[0].calls.pop();
        assert!(
            compiler_precise_graph_ndjson(
                &current,
                &failed.audit,
                &failed.pack,
                &failed.graph,
                &failed.invocations,
                &incomplete,
            )
            .is_err()
        );
        store.finish_build_attempt(
            &failed.audit.run_id,
            "security_failed",
            Some("compiler-precise-coverage-invalid"),
            false,
        )?;
        assert_eq!(
            store.current_snapshot_id()?.as_deref(),
            Some(current_id.as_str())
        );
        assert_eq!(store.load_completed_snapshot(&current_id)?, current);
        Ok(())
    }
}
