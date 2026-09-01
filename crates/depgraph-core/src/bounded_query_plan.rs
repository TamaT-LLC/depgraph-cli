use std::collections::{BTreeMap, BTreeSet};

use depgraph_store::{EdgeRecord, EvidenceRecord, GraphSnapshot, NodeRecord, SiteRecord};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::{
    BOUNDED_QUERY_CONTRACT_VERSION, EntityType, Literal, QueryDirection, ScalarOperator,
    TypedExpression, TypedProjection, TypedQuery, TypedQueryAst,
};

pub const BOUNDED_QUERY_PLAN_SCHEMA_VERSION: &str = "bounded-query-plan-v1";
pub const BOUNDED_QUERY_LIMIT_VERSION: &str = "bounded-query-limits-v1";
pub const BOUNDED_QUERY_STATISTICS_VERSION: &str = "bounded-query-statistics-v1";

const STATE_BYTES: u64 = 256;
const ADJACENCY_EDGE_BYTES: u64 = 64;
const NODE_INDEX_BYTES: u64 = 32;
const SITE_INDEX_BYTES: u64 = 32;
const EVIDENCE_INDEX_BYTES: u64 = 32;
const SCALAR_PROJECTION_WEIGHT: u64 = 1;
const NODE_PROJECTION_WEIGHT: u64 = 4;
const PATH_PROJECTION_WEIGHT: u64 = 16;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BoundedQueryLimits {
    pub source_node_tests: u64,
    pub traversal_states: u64,
    pub edge_tests: u64,
    pub site_tests: u64,
    pub evidence_tests: u64,
    pub result_rows: u64,
    pub serialized_output_bytes: u64,
    pub deterministic_cost: u64,
    pub working_memory_bytes: u64,
    pub deadline_milliseconds: u64,
}

impl Default for BoundedQueryLimits {
    fn default() -> Self {
        Self {
            source_node_tests: 10_000,
            traversal_states: 50_000,
            edge_tests: 200_000,
            site_tests: 100_000,
            evidence_tests: 200_000,
            result_rows: 10_000,
            serialized_output_bytes: 16 * 1024 * 1024,
            deterministic_cost: 1_000_000,
            working_memory_bytes: 128 * 1024 * 1024,
            deadline_milliseconds: 5_000,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ClosedFieldByteBounds {
    pub node: BTreeMap<String, u64>,
    pub edge: BTreeMap<String, u64>,
    pub site: BTreeMap<String, u64>,
    pub evidence: BTreeMap<String, u64>,
    pub node_entity: u64,
    pub edge_entity: u64,
    pub site_entity: u64,
    pub evidence_entity: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SnapshotCardinalityStatistics {
    pub statistics_version: String,
    pub snapshot_id: String,
    pub graph_digest: String,
    pub node_count: u64,
    pub profile_count: u64,
    pub edge_count: u64,
    pub site_count: u64,
    pub evidence_count: u64,
    pub nodes_by_kind: BTreeMap<String, u64>,
    pub edges_by_kind: BTreeMap<String, u64>,
    pub edges_by_profile: BTreeMap<String, u64>,
    pub edges_by_phase: BTreeMap<String, u64>,
    pub maximum_forward_degree_by_kind: BTreeMap<String, u64>,
    pub maximum_reverse_degree_by_kind: BTreeMap<String, u64>,
    pub sites_by_kind: BTreeMap<String, u64>,
    pub sites_by_profile: BTreeMap<String, u64>,
    pub evidence_by_kind: BTreeMap<String, u64>,
    pub max_evidence_per_edge: u64,
    pub max_evidence_per_site: u64,
    pub closed_field_byte_bounds: ClosedFieldByteBounds,
    pub metadata_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct QueryCardinalityInputs {
    pub source_nodes: u64,
    pub target_nodes: u64,
    pub eligible_edges: u64,
    pub maximum_adjacency_degree: u64,
    pub existential_predicates: u64,
    pub site_predicates: u64,
    pub evidence_predicates: u64,
    pub maximum_associated_evidence_per_edge: u64,
    pub endpoint_pairs: u64,
    pub projection_width: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BoundedQueryOperatorKind {
    NodeIdLookup,
    NodeKindScan,
    BoundedNodeScan,
    CanonicalAdjacencyBuild,
    BoundedForwardBfs,
    BoundedReverseBfs,
    AssociatedSiteFilter,
    AssociatedEvidenceFilter,
    Project,
    Distinct,
    CanonicalSort,
    Limit,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BoundedQueryOperatorPlan {
    pub operator: BoundedQueryOperatorKind,
    pub worst_case_rows: u64,
    pub worst_case_visits: u64,
    pub worst_case_tests: u64,
    pub worst_case_serialized_bytes: u64,
    pub cost: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BoundedQueryResourceBounds {
    pub source_node_tests: u64,
    pub traversal_states: u64,
    pub edge_tests: u64,
    pub site_tests: u64,
    pub evidence_tests: u64,
    pub result_rows: u64,
    pub serialized_output_bytes: u64,
    pub working_memory_bytes: u64,
    pub deterministic_cost: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct QueryAdmissionReason {
    pub code: String,
    pub resource: String,
    pub observed: u64,
    pub limit: u64,
    pub remediation: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BoundedQueryPlan {
    pub schema_version: String,
    pub contract_version: String,
    pub limit_version: String,
    pub typed_ast_digest: String,
    pub snapshot_id: String,
    pub graph_digest: String,
    pub redacted_typed_ast_shape: Value,
    pub snapshot_statistics: SnapshotCardinalityStatistics,
    pub cardinality_inputs: QueryCardinalityInputs,
    pub operators: Vec<BoundedQueryOperatorPlan>,
    pub bounds: BoundedQueryResourceBounds,
    pub limits: BoundedQueryLimits,
    pub admitted: bool,
    pub reasons: Vec<QueryAdmissionReason>,
    pub plan_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundedQueryPlanningError {
    pub code: &'static str,
    pub message: &'static str,
}

impl std::fmt::Display for BoundedQueryPlanningError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for BoundedQueryPlanningError {}

pub type BoundedQueryPlanningResult<T> = Result<T, BoundedQueryPlanningError>;

/// Computes the portable graph digest used by bounded-query planning.
///
/// Only the closed query-visible graph is included. Scan roots, checkout
/// paths, timestamps, arbitrary properties, diagnostics, and SQLite row order
/// are deliberately excluded.
#[must_use]
pub fn bounded_query_graph_digest(snapshot: &GraphSnapshot) -> String {
    let mut nodes = snapshot.nodes.iter().map(closed_node).collect::<Vec<_>>();
    let mut edges = snapshot.edges.iter().map(closed_edge).collect::<Vec<_>>();
    let mut sites = snapshot.sites.iter().map(closed_site).collect::<Vec<_>>();
    let mut evidence = snapshot
        .evidence
        .iter()
        .map(closed_evidence)
        .collect::<Vec<_>>();
    sort_values(&mut nodes);
    sort_values(&mut edges);
    sort_values(&mut sites);
    sort_values(&mut evidence);
    digest_json(
        "bounded-query-graph",
        &json!({
            "schema": BOUNDED_QUERY_STATISTICS_VERSION,
            "nodes": nodes,
            "edges": edges,
            "sites": sites,
            "evidence": evidence,
        }),
    )
}

#[must_use]
pub fn collect_bounded_query_statistics(
    _snapshot_id: &str,
    snapshot: &GraphSnapshot,
) -> SnapshotCardinalityStatistics {
    let graph_digest = bounded_query_graph_digest(snapshot);
    let mut statistics = SnapshotCardinalityStatistics {
        statistics_version: BOUNDED_QUERY_STATISTICS_VERSION.to_owned(),
        snapshot_id: bounded_query_snapshot_id(&graph_digest),
        graph_digest,
        node_count: usize_u64(snapshot.nodes.len()),
        profile_count: usize_u64(snapshot.profiles.len()),
        edge_count: usize_u64(snapshot.edges.len()),
        site_count: usize_u64(snapshot.sites.len()),
        evidence_count: usize_u64(snapshot.evidence.len()),
        nodes_by_kind: counts(snapshot.nodes.iter().map(|item| item.kind.as_str())),
        edges_by_kind: counts(snapshot.edges.iter().map(|item| item.kind.as_str())),
        edges_by_profile: counts(snapshot.edges.iter().map(|item| item.profile_id.as_str())),
        edges_by_phase: counts(snapshot.edges.iter().map(|item| item.phase.as_str())),
        maximum_forward_degree_by_kind: maximum_degree_cardinalities(
            &snapshot.edges,
            QueryDirection::Forward,
        ),
        maximum_reverse_degree_by_kind: maximum_degree_cardinalities(
            &snapshot.edges,
            QueryDirection::Reverse,
        ),
        sites_by_kind: counts(snapshot.sites.iter().map(|item| item.kind.as_str())),
        sites_by_profile: counts(snapshot.sites.iter().map(|item| item.profile_id.as_str())),
        evidence_by_kind: counts(snapshot.evidence.iter().map(|item| item.kind.as_str())),
        max_evidence_per_edge: maximum_evidence_per_owner(&snapshot.evidence, "edge"),
        max_evidence_per_site: maximum_evidence_per_owner(&snapshot.evidence, "site"),
        closed_field_byte_bounds: closed_field_byte_bounds(snapshot),
        metadata_digest: String::new(),
    };
    statistics.metadata_digest = statistics_digest(&statistics);
    statistics
}

pub fn plan_bounded_query(
    query: &TypedQuery,
    snapshot_id: &str,
    snapshot: &GraphSnapshot,
) -> BoundedQueryPlanningResult<BoundedQueryPlan> {
    plan_bounded_query_with_limits(query, snapshot_id, snapshot, BoundedQueryLimits::default())
}

pub fn plan_bounded_query_with_limits(
    query: &TypedQuery,
    snapshot_id: &str,
    snapshot: &GraphSnapshot,
    limits: BoundedQueryLimits,
) -> BoundedQueryPlanningResult<BoundedQueryPlan> {
    let statistics = collect_bounded_query_statistics(snapshot_id, snapshot);
    plan_bounded_query_from_verified_statistics(query, statistics, limits)
}

pub fn plan_bounded_query_with_statistics(
    query: &TypedQuery,
    snapshot: &GraphSnapshot,
    statistics: SnapshotCardinalityStatistics,
) -> BoundedQueryPlanningResult<BoundedQueryPlan> {
    validate_statistics(snapshot, &statistics)?;
    plan_bounded_query_from_verified_statistics(query, statistics, BoundedQueryLimits::default())
}

fn plan_bounded_query_from_verified_statistics(
    query: &TypedQuery,
    statistics: SnapshotCardinalityStatistics,
    limits: BoundedQueryLimits,
) -> BoundedQueryPlanningResult<BoundedQueryPlan> {
    if query.digest != crate::typed_query_ast_digest(&query.ast) {
        return Err(planning_error(
            "query_typed_ast_digest_mismatch",
            "typed query AST digest does not match its canonical payload",
        ));
    }

    let cardinality = query_cardinality_inputs(&query.ast, &statistics);
    let source_operator = choose_source_operator(&query.ast);
    let relationship = &query.ast.match_clause.relationship;

    let traversal_states = traversal_state_bound(
        cardinality.source_nodes,
        statistics.node_count,
        cardinality.eligible_edges,
        relationship.max_depth,
        cardinality.existential_predicates,
    );
    let states_before_last_depth = traversal_state_bound(
        cardinality.source_nodes,
        statistics.node_count,
        cardinality.eligible_edges,
        relationship.max_depth.saturating_sub(1),
        cardinality.existential_predicates,
    );
    let edge_tests = multiply(
        states_before_last_depth,
        cardinality.maximum_adjacency_degree,
    );
    let site_tests = if cardinality.site_predicates == 0 {
        0
    } else {
        multiply(edge_tests, cardinality.site_predicates)
    };
    let evidence_tests = if cardinality.evidence_predicates == 0 {
        0
    } else {
        multiply(
            multiply(edge_tests, cardinality.maximum_associated_evidence_per_edge),
            cardinality.evidence_predicates,
        )
    };
    let result_rows = u64::from(query.ast.limit).min(cardinality.endpoint_pairs);
    let row_bytes = projected_row_byte_bound(&query.ast, &statistics, &cardinality);
    let serialized_output_bytes = uniform_json_array_byte_bound(result_rows, row_bytes);
    let projection_cost = multiply(cardinality.projection_width, u64::from(query.ast.limit));
    let sort_rows = u64::from(query.ast.limit).min(cardinality.endpoint_pairs);
    let sort_cost = multiply(2, sort_rows);
    let serialization_cost = ceil_div(serialized_output_bytes, 64);
    let deterministic_cost = [
        cardinality.source_nodes,
        multiply(2, traversal_states),
        multiply(4, edge_tests),
        multiply(4, site_tests),
        multiply(8, evidence_tests),
        projection_cost,
        sort_cost,
        serialization_cost,
    ]
    .into_iter()
    .fold(0, add);
    let working_memory_bytes = [
        multiply(traversal_states, STATE_BYTES),
        multiply(cardinality.eligible_edges, ADJACENCY_EDGE_BYTES),
        multiply(statistics.node_count, NODE_INDEX_BYTES),
        multiply(statistics.site_count, SITE_INDEX_BYTES),
        multiply(statistics.evidence_count, EVIDENCE_INDEX_BYTES),
        serialized_output_bytes,
    ]
    .into_iter()
    .fold(0, add);

    let bounds = BoundedQueryResourceBounds {
        source_node_tests: cardinality.source_nodes,
        traversal_states,
        edge_tests,
        site_tests,
        evidence_tests,
        result_rows,
        serialized_output_bytes,
        working_memory_bytes,
        deterministic_cost,
    };
    let mut operators = vec![
        operator(
            source_operator,
            cardinality.source_nodes,
            0,
            cardinality.source_nodes,
            0,
            cardinality.source_nodes,
        ),
        operator(
            BoundedQueryOperatorKind::CanonicalAdjacencyBuild,
            cardinality.eligible_edges,
            0,
            edge_tests,
            0,
            multiply(4, edge_tests),
        ),
        operator(
            match relationship.direction {
                QueryDirection::Forward => BoundedQueryOperatorKind::BoundedForwardBfs,
                QueryDirection::Reverse => BoundedQueryOperatorKind::BoundedReverseBfs,
            },
            cardinality.endpoint_pairs,
            traversal_states,
            0,
            0,
            multiply(2, traversal_states),
        ),
    ];
    if cardinality.site_predicates > 0 {
        operators.push(operator(
            BoundedQueryOperatorKind::AssociatedSiteFilter,
            cardinality.endpoint_pairs,
            0,
            site_tests,
            0,
            multiply(4, site_tests),
        ));
    }
    if cardinality.evidence_predicates > 0 {
        operators.push(operator(
            BoundedQueryOperatorKind::AssociatedEvidenceFilter,
            cardinality.endpoint_pairs,
            0,
            evidence_tests,
            0,
            multiply(8, evidence_tests),
        ));
    }
    operators.push(operator(
        BoundedQueryOperatorKind::Project,
        result_rows,
        0,
        0,
        serialized_output_bytes,
        projection_cost,
    ));
    if query.ast.return_clause.distinct {
        operators.push(operator(
            BoundedQueryOperatorKind::Distinct,
            result_rows,
            0,
            0,
            serialized_output_bytes,
            0,
        ));
    }
    operators.push(operator(
        BoundedQueryOperatorKind::CanonicalSort,
        sort_rows,
        0,
        0,
        serialized_output_bytes,
        sort_cost,
    ));
    operators.push(operator(
        BoundedQueryOperatorKind::Limit,
        result_rows,
        0,
        0,
        serialized_output_bytes,
        serialization_cost,
    ));

    let reasons = admission_reasons(&bounds, &limits);
    let mut plan = BoundedQueryPlan {
        schema_version: BOUNDED_QUERY_PLAN_SCHEMA_VERSION.to_owned(),
        contract_version: BOUNDED_QUERY_CONTRACT_VERSION.to_owned(),
        limit_version: BOUNDED_QUERY_LIMIT_VERSION.to_owned(),
        typed_ast_digest: query.digest.clone(),
        snapshot_id: statistics.snapshot_id.clone(),
        graph_digest: statistics.graph_digest.clone(),
        redacted_typed_ast_shape: redacted_typed_query_shape(&query.ast),
        snapshot_statistics: statistics,
        cardinality_inputs: cardinality,
        operators,
        bounds,
        limits,
        admitted: reasons.is_empty(),
        reasons,
        plan_digest: String::new(),
    };
    plan.plan_digest = bounded_query_plan_digest(&plan);
    Ok(plan)
}

#[must_use]
pub fn bounded_query_plan_digest(plan: &BoundedQueryPlan) -> String {
    let mut payload = plan.clone();
    payload.plan_digest.clear();
    digest_json(
        "bounded-query-plan",
        &serde_json::to_value(payload).expect("bounded query plan serialization cannot fail"),
    )
}

#[must_use]
pub fn canonical_bounded_query_plan_json(plan: &BoundedQueryPlan) -> String {
    serde_json::to_string(plan).expect("bounded query plan serialization cannot fail")
}

#[must_use]
pub fn redacted_typed_query_shape(ast: &TypedQueryAst) -> Value {
    let mut shape =
        serde_json::to_value(ast).expect("typed bounded query AST serialization cannot fail");
    redact_string_literals(&mut shape);
    for pointer in ["/match_clause/source/kind", "/match_clause/target/kind"] {
        if let Some(value) = shape.pointer_mut(pointer) {
            redact_string_slot(value);
        }
    }
    if let Some(Value::Array(kinds)) = shape.pointer_mut("/match_clause/relationship/kinds") {
        for kind in kinds {
            redact_string_slot(kind);
        }
    }
    shape
}

fn validate_statistics(
    snapshot: &GraphSnapshot,
    statistics: &SnapshotCardinalityStatistics,
) -> BoundedQueryPlanningResult<()> {
    if statistics.statistics_version != BOUNDED_QUERY_STATISTICS_VERSION {
        return Err(planning_error(
            "query_statistics_version_invalid",
            "snapshot statistics version is not supported",
        ));
    }
    if statistics.metadata_digest != statistics_digest(statistics) {
        return Err(planning_error(
            "query_statistics_digest_mismatch",
            "snapshot statistics digest does not match its canonical payload",
        ));
    }
    let observed = collect_bounded_query_statistics(&statistics.snapshot_id, snapshot);
    if statistics.graph_digest != observed.graph_digest {
        return Err(planning_error(
            "query_snapshot_graph_digest_mismatch",
            "snapshot graph digest does not match its canonical closed graph",
        ));
    }
    if &observed != statistics {
        return Err(planning_error(
            "query_statistics_cardinality_mismatch",
            "snapshot statistics do not match the selected snapshot",
        ));
    }
    Ok(())
}

pub(crate) fn bounded_query_snapshot_id(graph_digest: &str) -> String {
    let digest = graph_digest
        .strip_prefix("bounded-query-graph:sha256:")
        .expect("bounded query graph digests use their fixed namespace");
    format!("snapshot:sha256:{digest}")
}

fn statistics_digest(statistics: &SnapshotCardinalityStatistics) -> String {
    let mut payload = statistics.clone();
    payload.metadata_digest.clear();
    digest_json(
        "bounded-query-statistics",
        &serde_json::to_value(payload).expect("bounded query statistics serialization cannot fail"),
    )
}

fn query_cardinality_inputs(
    ast: &TypedQueryAst,
    statistics: &SnapshotCardinalityStatistics,
) -> QueryCardinalityInputs {
    let source_nodes = if has_source_id_lookup(ast) {
        1.min(statistics.node_count)
    } else {
        ast.match_clause
            .source
            .kind
            .as_ref()
            .and_then(|kind| statistics.nodes_by_kind.get(kind))
            .copied()
            .unwrap_or_else(|| {
                if ast.match_clause.source.kind.is_some() {
                    0
                } else {
                    statistics.node_count
                }
            })
    };
    let target_nodes = ast
        .match_clause
        .target
        .kind
        .as_ref()
        .and_then(|kind| statistics.nodes_by_kind.get(kind))
        .copied()
        .unwrap_or_else(|| {
            if ast.match_clause.target.kind.is_some() {
                0
            } else {
                statistics.node_count
            }
        });
    let kinds = ast
        .match_clause
        .relationship
        .kinds
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let eligible_edges = kinds
        .iter()
        .map(|kind| statistics.edges_by_kind.get(*kind).copied().unwrap_or(0))
        .fold(0, add);
    let maximum_degrees = match ast.match_clause.relationship.direction {
        QueryDirection::Forward => &statistics.maximum_forward_degree_by_kind,
        QueryDirection::Reverse => &statistics.maximum_reverse_degree_by_kind,
    };
    let maximum_adjacency_degree = kinds
        .iter()
        .map(|kind| maximum_degrees.get(*kind).copied().unwrap_or(0))
        .fold(0, add)
        .min(eligible_edges);
    let (existential_predicates, site_predicates, evidence_predicates) =
        quantifier_counts(ast.where_clause.as_ref());
    QueryCardinalityInputs {
        source_nodes,
        target_nodes,
        eligible_edges,
        maximum_adjacency_degree,
        existential_predicates,
        site_predicates,
        evidence_predicates,
        maximum_associated_evidence_per_edge: add(
            statistics.max_evidence_per_edge,
            statistics.max_evidence_per_site,
        ),
        endpoint_pairs: multiply(source_nodes, target_nodes),
        projection_width: ast
            .return_clause
            .projections
            .iter()
            .map(projection_weight)
            .fold(0, add),
    }
}

fn projection_weight(projection: &TypedProjection) -> u64 {
    match projection {
        TypedProjection::Binding(binding) => match binding.entity_type {
            EntityType::Node => NODE_PROJECTION_WEIGHT,
            EntityType::Path => PATH_PROJECTION_WEIGHT,
            _ => SCALAR_PROJECTION_WEIGHT,
        },
        TypedProjection::Field(_) => SCALAR_PROJECTION_WEIGHT,
    }
}

fn traversal_state_bound(
    sources: u64,
    nodes: u64,
    edges: u64,
    maximum_depth: u8,
    existential_predicates: u64,
) -> u64 {
    if sources == 0 || nodes == 0 {
        return 0;
    }
    let predicate_states = if existential_predicates >= 63 {
        u64::MAX
    } else {
        1_u64 << existential_predicates
    };
    let mut used_edge_sets = 1;
    let mut combinations = 1;
    for depth in 1..=u64::from(maximum_depth).min(edges) {
        combinations = multiply_then_div(combinations, edges - depth + 1, depth);
        used_edge_sets = add(used_edge_sets, combinations);
    }
    multiply(
        sources,
        multiply(nodes, multiply(predicate_states, used_edge_sets)),
    )
}

fn projected_row_byte_bound(
    ast: &TypedQueryAst,
    statistics: &SnapshotCardinalityStatistics,
    cardinality: &QueryCardinalityInputs,
) -> u64 {
    // Result rows have the fixed canonical shape `[projection, ...]`. Projection
    // labels are therefore not serialized as object keys; the enclosing result
    // carries the typed projection list through its plan digest.
    let projection_bytes = ast
        .return_clause
        .projections
        .iter()
        .map(|projection| projection_byte_bound(projection, ast, statistics, cardinality))
        .fold(0, add);
    heterogeneous_json_array_byte_bound(
        usize_u64(ast.return_clause.projections.len()),
        projection_bytes,
    )
}

fn projection_byte_bound(
    projection: &TypedProjection,
    ast: &TypedQueryAst,
    statistics: &SnapshotCardinalityStatistics,
    cardinality: &QueryCardinalityInputs,
) -> u64 {
    let fields = &statistics.closed_field_byte_bounds;
    match projection {
        TypedProjection::Binding(binding) => match binding.entity_type {
            EntityType::Node => fields.node_entity,
            EntityType::Path => {
                let depth = u64::from(ast.match_clause.relationship.max_depth);
                let evidence_count =
                    multiply(depth, cardinality.maximum_associated_evidence_per_edge);
                json_object_byte_bound(&[
                    ("id", stable_id_json_byte_bound("query-path")),
                    ("depth", json_bytes(&json!(depth))),
                    (
                        "direction",
                        json_bytes(&json!(QueryDirection::Forward))
                            .max(json_bytes(&json!(QueryDirection::Reverse))),
                    ),
                    (
                        "nodes",
                        uniform_json_array_byte_bound(add(depth, 1), fields.node_entity),
                    ),
                    (
                        "edges",
                        uniform_json_array_byte_bound(depth, fields.edge_entity),
                    ),
                    (
                        "sites",
                        uniform_json_array_byte_bound(depth, fields.site_entity),
                    ),
                    (
                        "evidence",
                        uniform_json_array_byte_bound(evidence_count, fields.evidence_entity),
                    ),
                ])
            }
            _ => 4,
        },
        TypedProjection::Field(field) => {
            let table = match field.entity_type {
                EntityType::Node => &fields.node,
                EntityType::Edge => &fields.edge,
                EntityType::Site => &fields.site,
                EntityType::Evidence => &fields.evidence,
                EntityType::Path => {
                    return match field.field.as_str() {
                        "id" => 87,
                        "depth" => 20,
                        "direction" => 9,
                        _ => 4,
                    };
                }
            };
            table.get(&field.field).copied().unwrap_or(4)
        }
    }
}

fn admission_reasons(
    bounds: &BoundedQueryResourceBounds,
    limits: &BoundedQueryLimits,
) -> Vec<QueryAdmissionReason> {
    let resources = [
        (
            "source_node_tests",
            bounds.source_node_tests,
            limits.source_node_tests,
            "add an exact source id or source kind predicate",
        ),
        (
            "traversal_states",
            bounds.traversal_states,
            limits.traversal_states,
            "reduce path depth, edge kinds, or existential path predicates",
        ),
        (
            "edge_tests",
            bounds.edge_tests,
            limits.edge_tests,
            "reduce path depth or relationship kinds",
        ),
        (
            "site_tests",
            bounds.site_tests,
            limits.site_tests,
            "reduce path depth or site predicates",
        ),
        (
            "evidence_tests",
            bounds.evidence_tests,
            limits.evidence_tests,
            "reduce path depth or evidence predicates",
        ),
        (
            "result_rows",
            bounds.result_rows,
            limits.result_rows,
            "lower LIMIT",
        ),
        (
            "serialized_output_bytes",
            bounds.serialized_output_bytes,
            limits.serialized_output_bytes,
            "lower LIMIT or project fewer fields",
        ),
        (
            "working_memory_bytes",
            bounds.working_memory_bytes,
            limits.working_memory_bytes,
            "reduce path depth, relationship kinds, or output width",
        ),
        (
            "deterministic_cost",
            bounds.deterministic_cost,
            limits.deterministic_cost,
            "reduce path depth, relationship kinds, or path predicates",
        ),
    ];
    resources
        .into_iter()
        .filter(|(_, observed, limit, _)| observed > limit)
        .map(
            |(resource, observed, limit, remediation)| QueryAdmissionReason {
                code: "query_plan_budget_exceeded".to_owned(),
                resource: resource.to_owned(),
                observed,
                limit,
                remediation: remediation.to_owned(),
            },
        )
        .collect()
}

fn choose_source_operator(ast: &TypedQueryAst) -> BoundedQueryOperatorKind {
    if has_source_id_lookup(ast) {
        BoundedQueryOperatorKind::NodeIdLookup
    } else if ast.match_clause.source.kind.is_some() {
        BoundedQueryOperatorKind::NodeKindScan
    } else {
        BoundedQueryOperatorKind::BoundedNodeScan
    }
}

fn has_source_id_lookup(ast: &TypedQueryAst) -> bool {
    ast.where_clause
        .as_ref()
        .is_some_and(|expression| conjunct_has_source_id_lookup(expression, ast))
}

fn conjunct_has_source_id_lookup(expression: &TypedExpression, ast: &TypedQueryAst) -> bool {
    match expression {
        TypedExpression::Scalar(predicate) => {
            predicate.field.binding == ast.match_clause.source.binding.name
                && predicate.field.field == "id"
                && matches!(
                    predicate.operator,
                    ScalarOperator::Equal(Literal::String(_))
                )
        }
        TypedExpression::And(terms) => terms
            .iter()
            .any(|term| conjunct_has_source_id_lookup(term, ast)),
        TypedExpression::Or(_) | TypedExpression::Not(_) | TypedExpression::Quantifier(_) => false,
    }
}

fn quantifier_counts(expression: Option<&TypedExpression>) -> (u64, u64, u64) {
    let Some(expression) = expression else {
        return (0, 0, 0);
    };
    match expression {
        TypedExpression::Or(terms) | TypedExpression::And(terms) => terms
            .iter()
            .map(|term| quantifier_counts(Some(term)))
            .fold((0, 0, 0), |left, right| {
                (
                    add(left.0, right.0),
                    add(left.1, right.1),
                    add(left.2, right.2),
                )
            }),
        TypedExpression::Not(inner) => quantifier_counts(Some(inner)),
        TypedExpression::Scalar(_) => (0, 0, 0),
        TypedExpression::Quantifier(predicate) => match predicate.binding.entity_type {
            EntityType::Site => (1, 1, 0),
            EntityType::Evidence => (1, 0, 1),
            EntityType::Edge => (0, 0, 0),
            _ => (0, 0, 0),
        },
    }
}

fn maximum_degree_cardinalities(
    edges: &[EdgeRecord],
    direction: QueryDirection,
) -> BTreeMap<String, u64> {
    let mut cardinalities = BTreeMap::<String, BTreeMap<String, u64>>::new();
    for edge in edges {
        let node = match direction {
            QueryDirection::Forward => &edge.source,
            QueryDirection::Reverse => &edge.target,
        };
        *cardinalities
            .entry(node.clone())
            .or_default()
            .entry(edge.kind.clone())
            .or_default() += 1;
    }
    let mut maximums = BTreeMap::<String, u64>::new();
    for by_kind in cardinalities.into_values() {
        for (kind, count) in by_kind {
            let maximum = maximums.entry(kind).or_default();
            *maximum = (*maximum).max(count);
        }
    }
    maximums
}

fn closed_field_byte_bounds(snapshot: &GraphSnapshot) -> ClosedFieldByteBounds {
    let node_values = snapshot.nodes.iter().map(closed_node).collect::<Vec<_>>();
    let edge_values = snapshot.edges.iter().map(closed_edge).collect::<Vec<_>>();
    let site_values = snapshot.sites.iter().map(closed_site).collect::<Vec<_>>();
    let evidence_values = snapshot
        .evidence
        .iter()
        .map(closed_evidence)
        .collect::<Vec<_>>();
    ClosedFieldByteBounds {
        node: field_bounds(
            &node_values,
            &["id", "kind", "locator", "display_name"],
            false,
        ),
        edge: field_bounds(
            &edge_values,
            &[
                "id",
                "kind",
                "phase",
                "environment",
                "profile_id",
                "resolution_status",
                "precision",
                "condition",
                "generated",
            ],
            false,
        ),
        site: field_bounds(
            &site_values,
            &[
                "id",
                "kind",
                "specifier",
                "profile_id",
                "resolution_status",
                "precision",
                "condition",
                "reason",
            ],
            true,
        ),
        evidence: field_bounds(
            &evidence_values,
            &[
                "owner_type",
                "kind",
                "extractor",
                "extractor_version",
                "path",
                "start_line",
                "start_column",
                "end_line",
                "end_column",
                "ordinal",
            ],
            false,
        ),
        node_entity: maximum_json_bytes(&node_values),
        edge_entity: maximum_json_bytes(&edge_values),
        site_entity: maximum_json_bytes(&site_values).max(4),
        evidence_entity: maximum_json_bytes(&evidence_values),
    }
}

fn field_bounds(values: &[Value], fields: &[&str], nullable: bool) -> BTreeMap<String, u64> {
    fields
        .iter()
        .map(|field| {
            let mut maximum = if nullable { 4 } else { 0 };
            for value in values {
                if let Some(field_value) = value.get(field) {
                    maximum = maximum.max(json_bytes(field_value));
                }
            }
            ((*field).to_owned(), maximum)
        })
        .collect()
}

fn closed_node(node: &NodeRecord) -> Value {
    json!({
        "id": node.id,
        "kind": node.kind,
        "locator": node.locator,
        "display_name": node.display_name,
    })
}

fn closed_edge(edge: &EdgeRecord) -> Value {
    json!({
        "id": edge.id,
        "kind": edge.kind,
        "phase": edge.phase,
        "environment": edge.environment,
        "profile_id": edge.profile_id,
        "resolution_status": edge.resolution_status,
        "precision": edge.precision,
        "condition": canonical_condition(&edge.condition),
        "generated": edge.generated,
        "source": edge.source,
        "target": edge.target,
        "site_id": edge.site_id,
    })
}

fn closed_site(site: &SiteRecord) -> Value {
    let mut target_ids = site.target_ids.clone();
    target_ids.sort();
    target_ids.dedup();
    json!({
        "id": site.id,
        "kind": site.kind,
        "specifier": site.specifier,
        "profile_id": site.profile_id,
        "resolution_status": site.resolution_status,
        "precision": site.precision,
        "condition": canonical_condition(&site.condition),
        "reason": site.reason,
        "source": site.source,
        "target_ids": target_ids,
    })
}

fn closed_evidence(evidence: &EvidenceRecord) -> Value {
    json!({
        "owner_type": evidence.owner_type,
        "owner_id": evidence.owner_id,
        "ordinal": evidence.ordinal,
        "kind": evidence.kind,
        "extractor": evidence.extractor,
        "extractor_version": evidence.extractor_version,
        "path": evidence.path,
        "start_line": evidence.start_line,
        "start_column": evidence.start_column,
        "end_line": evidence.end_line,
        "end_column": evidence.end_column,
    })
}

fn canonical_condition(condition: &Value) -> String {
    crate::render_condition(&canonicalize_json(condition))
}

fn canonicalize_json(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut entries = map.iter().collect::<Vec<_>>();
            entries.sort_by(|left, right| left.0.cmp(right.0));
            let mut canonical = serde_json::Map::new();
            for (key, child) in entries {
                canonical.insert(key.clone(), canonicalize_json(child));
            }
            Value::Object(canonical)
        }
        Value::Array(values) => Value::Array(values.iter().map(canonicalize_json).collect()),
        value => value.clone(),
    }
}

fn maximum_evidence_per_owner(evidence: &[EvidenceRecord], owner_type: &str) -> u64 {
    let mut counts = BTreeMap::<&str, u64>::new();
    for item in evidence.iter().filter(|item| item.owner_type == owner_type) {
        *counts.entry(item.owner_id.as_str()).or_default() += 1;
    }
    counts.values().copied().max().unwrap_or(0)
}

fn redact_string_literals(value: &mut Value) {
    match value {
        Value::Object(map) => {
            if map.get("kind").and_then(Value::as_str) == Some("string")
                && let Some(Value::String(literal)) = map.get("value")
            {
                let digest = digest_bytes("query-literal", literal.as_bytes());
                let byte_length = literal.len();
                map.insert(
                    "value".to_owned(),
                    json!({
                        "scalar_type": "string",
                        "byte_length": byte_length,
                        "digest": digest,
                    }),
                );
                return;
            }
            for child in map.values_mut() {
                redact_string_literals(child);
            }
        }
        Value::Array(values) => {
            for child in values {
                redact_string_literals(child);
            }
        }
        _ => {}
    }
}

fn redact_string_slot(value: &mut Value) {
    let Value::String(literal) = value else {
        return;
    };
    *value = json!({
        "scalar_type": "string",
        "byte_length": literal.len(),
        "digest": digest_bytes("query-literal", literal.as_bytes()),
    });
}

fn operator(
    operator: BoundedQueryOperatorKind,
    rows: u64,
    visits: u64,
    tests: u64,
    bytes: u64,
    cost: u64,
) -> BoundedQueryOperatorPlan {
    BoundedQueryOperatorPlan {
        operator,
        worst_case_rows: rows,
        worst_case_visits: visits,
        worst_case_tests: tests,
        worst_case_serialized_bytes: bytes,
        cost,
    }
}

fn counts<'a>(items: impl Iterator<Item = &'a str>) -> BTreeMap<String, u64> {
    let mut counts = BTreeMap::new();
    for item in items {
        *counts.entry(item.to_owned()).or_default() += 1;
    }
    counts
}

fn maximum_json_bytes(values: &[Value]) -> u64 {
    values.iter().map(json_bytes).max().unwrap_or(0)
}

fn json_bytes(value: &Value) -> u64 {
    usize_u64(
        serde_json::to_vec(value)
            .expect("closed bounded query field serialization cannot fail")
            .len(),
    )
}

fn stable_id_json_byte_bound(namespace: &str) -> u64 {
    json_bytes(&Value::String(format!(
        "{namespace}:sha256:{}",
        "0".repeat(64)
    )))
}

fn heterogeneous_json_array_byte_bound(item_count: u64, item_bytes: u64) -> u64 {
    add(add(2, item_bytes), item_count.saturating_sub(1))
}

fn uniform_json_array_byte_bound(item_count: u64, item_byte_bound: u64) -> u64 {
    heterogeneous_json_array_byte_bound(item_count, multiply(item_count, item_byte_bound))
}

fn json_object_byte_bound(fields: &[(&str, u64)]) -> u64 {
    let members = fields
        .iter()
        .map(|(key, value_bytes)| {
            add(
                add(json_bytes(&Value::String((*key).to_owned())), 1),
                *value_bytes,
            )
        })
        .fold(0, add);
    add(add(2, members), usize_u64(fields.len()).saturating_sub(1))
}

fn sort_values(values: &mut [Value]) {
    values.sort_by_cached_key(|value| {
        serde_json::to_vec(value).expect("closed bounded query graph serialization cannot fail")
    });
}

fn digest_json(namespace: &str, value: &Value) -> String {
    digest_bytes(
        namespace,
        &serde_json::to_vec(value).expect("canonical bounded query serialization cannot fail"),
    )
}

fn digest_bytes(namespace: &str, bytes: &[u8]) -> String {
    format!("{namespace}:sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn add(left: u64, right: u64) -> u64 {
    left.saturating_add(right)
}

fn multiply(left: u64, right: u64) -> u64 {
    left.saturating_mul(right)
}

fn multiply_then_div(value: u64, multiplier: u64, divisor: u64) -> u64 {
    value
        .checked_mul(multiplier)
        .map(|product| product / divisor)
        .unwrap_or(u64::MAX)
}

fn ceil_div(value: u64, divisor: u64) -> u64 {
    value / divisor + u64::from(!value.is_multiple_of(divisor))
}

fn usize_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

fn planning_error(code: &'static str, message: &'static str) -> BoundedQueryPlanningError {
    BoundedQueryPlanningError { code, message }
}

#[cfg(test)]
mod tests {
    use depgraph_store::{CoverageRecord, GraphSnapshot, ProfileMatrixRecord, ScanRecord};
    use serde::Deserialize;
    use serde_json::{Value, json};

    use super::{
        BoundedQueryOperatorKind, BoundedQueryPlanningError, bounded_query_graph_digest,
        canonical_bounded_query_plan_json, collect_bounded_query_statistics, plan_bounded_query,
        plan_bounded_query_with_statistics, redacted_typed_query_shape,
    };
    use crate::parse_and_type_check_bounded_query;

    fn query(limit: u32, depth: u8, where_clause: &str) -> crate::TypedQuery {
        parse_and_type_check_bounded_query(&format!(
            r#"MATCH p = (source:"route")-["calls"*1..{depth}]->(target:"service"){where_clause} RETURN source.id, target.id, p ORDER BY source.id LIMIT {limit}"#
        ))
        .unwrap()
    }

    fn snapshot(order_reversed: bool) -> GraphSnapshot {
        let mut nodes = vec![
            depgraph_store::NodeRecord {
                id: "node:route".into(),
                kind: "route".into(),
                locator: "route:/".into(),
                display_name: "Route".into(),
                properties: json!({"ignored": "secret"}),
            },
            depgraph_store::NodeRecord {
                id: "node:service".into(),
                kind: "service".into(),
                locator: "service:api".into(),
                display_name: "API".into(),
                properties: json!({}),
            },
        ];
        let mut sites = vec![depgraph_store::SiteRecord {
            id: "site:1".into(),
            source: "node:route".into(),
            kind: "call".into(),
            specifier: Some("api".into()),
            profile_id: "profile:a".into(),
            resolution_status: "resolved".into(),
            precision: "exact".into(),
            condition: json!({"all": []}),
            target_ids: vec!["node:service".into()],
            reason: None,
        }];
        let mut edges = vec![depgraph_store::EdgeRecord {
            id: "edge:1".into(),
            site_id: Some("site:1".into()),
            source: "node:route".into(),
            target: "node:service".into(),
            kind: "calls".into(),
            phase: "semantic".into(),
            environment: "production".into(),
            profile_id: "profile:a".into(),
            resolution_status: "resolved".into(),
            precision: "exact".into(),
            condition: json!({"all": []}),
            generated: false,
        }];
        let mut evidence = vec![depgraph_store::EvidenceRecord {
            owner_type: "edge".into(),
            owner_id: "edge:1".into(),
            ordinal: 0,
            kind: "source".into(),
            extractor: "test".into(),
            extractor_version: "1".into(),
            path: "src/lib.rs".into(),
            start_line: 1,
            start_column: 1,
            end_line: 1,
            end_column: 2,
            detail: Some("not query-visible".into()),
            properties: json!({"ignored": true}),
        }];
        if order_reversed {
            nodes.reverse();
            sites.reverse();
            edges.reverse();
            evidence.reverse();
        }
        GraphSnapshot {
            scan: ScanRecord {
                id: "scan:test".into(),
                root: if order_reversed {
                    "/different/checkout".into()
                } else {
                    "/checkout".into()
                },
                status: "completed".into(),
                strict: false,
                started_at: "2026-01-01T00:00:00Z".into(),
                completed_at: Some("2026-01-01T00:00:01Z".into()),
                project_code_executed: false,
                error: None,
                parent_snapshot_id: None,
                source_revision: None,
                health_policy_config_digest: None,
                health_analyzer_version: None,
                health_finding_contract_version: None,
            },
            profiles: Vec::new(),
            nodes,
            sites,
            edges,
            evidence,
            diagnostics: Vec::new(),
            file_coverage: Vec::new(),
            adapter_logs: Vec::new(),
            coverage: CoverageRecord::default(),
            profile_matrix: ProfileMatrixRecord::default(),
        }
    }

    #[test]
    fn plan_and_graph_digest_ignore_row_order_checkout_and_non_visible_fields() {
        let mut first_snapshot = snapshot(false);
        let mut second_snapshot = snapshot(true);
        second_snapshot.nodes[0].properties = json!({"different": "private"});
        second_snapshot.evidence[0].detail = Some("different private detail".into());
        first_snapshot.edges[0].condition = json!({"all": [], "any": [{"field": "x"}]});
        let mut reversed_condition = serde_json::Map::new();
        reversed_condition.insert("any".into(), json!([{"field": "x"}]));
        reversed_condition.insert("all".into(), json!([]));
        second_snapshot.edges[0].condition = Value::Object(reversed_condition);
        let typed = query(10, 2, "");

        assert_eq!(
            bounded_query_graph_digest(&first_snapshot),
            bounded_query_graph_digest(&second_snapshot)
        );
        let first = plan_bounded_query(&typed, "snapshot:checkout-one", &first_snapshot).unwrap();
        let second = plan_bounded_query(&typed, "snapshot:checkout-two", &second_snapshot).unwrap();
        assert_eq!(first.snapshot_id, second.snapshot_id);
        assert_eq!(first.plan_digest, second.plan_digest);
        assert_eq!(
            canonical_bounded_query_plan_json(&first),
            canonical_bounded_query_plan_json(&second)
        );
    }

    #[test]
    fn explain_and_execute_can_share_the_exact_plan_digest() {
        let typed = query(
            10,
            1,
            r#" WHERE source.id = "credential-like-but-safe" AND SOME evidence IN EVIDENCE(p) SATISFIES evidence.path STARTS WITH "src/""#,
        );
        let plan = plan_bounded_query(&typed, "snapshot:stable", &snapshot(false)).unwrap();
        assert!(plan.admitted);
        assert_eq!(plan.plan_digest, super::bounded_query_plan_digest(&plan));
        assert_eq!(
            plan.bounds.deterministic_cost,
            plan.operators
                .iter()
                .map(|operator| operator.cost)
                .sum::<u64>()
        );
        assert_eq!(
            plan.operators[0].operator,
            BoundedQueryOperatorKind::NodeIdLookup
        );
    }

    #[test]
    fn redacted_shape_never_contains_raw_string_literals() {
        let typed = query(
            1,
            1,
            r#" WHERE source.locator STARTS WITH "private-prefix""#,
        );
        let shape = redacted_typed_query_shape(&typed.ast);
        let rendered = serde_json::to_string(&shape).unwrap();
        assert!(!rendered.contains("private-prefix"));
        assert!(!rendered.contains("\"route\""));
        assert!(!rendered.contains("\"calls\""));
        assert!(rendered.contains("\"byte_length\":14"));
        assert!(rendered.contains("query-literal:sha256:"));
    }

    #[test]
    fn limit_does_not_reduce_traversal_or_test_bounds() {
        let mut selected = snapshot(false);
        for index in 0..4 {
            selected.nodes.push(depgraph_store::NodeRecord {
                id: format!("node:service:{index}"),
                kind: "service".into(),
                locator: format!("service:{index}"),
                display_name: format!("Service {index}"),
                properties: json!({}),
            });
        }
        let small = plan_bounded_query(&query(1, 2, ""), "snapshot:stable", &selected).unwrap();
        let large = plan_bounded_query(&query(10, 2, ""), "snapshot:stable", &selected).unwrap();
        assert_eq!(small.bounds.traversal_states, large.bounds.traversal_states);
        assert_eq!(small.bounds.edge_tests, large.bounds.edge_tests);
        assert!(small.bounds.serialized_output_bytes < large.bounds.serialized_output_bytes);
    }

    #[test]
    fn projected_path_json_never_exceeds_the_planned_serialized_byte_bound() {
        let mut selected = snapshot(false);
        let maximum = "x".repeat(512);
        for node in &mut selected.nodes {
            node.id = format!("node:{maximum}");
            node.locator = format!("locator:{maximum}");
            node.display_name = maximum.clone();
        }
        selected.edges[0].id = format!("edge:{maximum}");
        selected.edges[0].profile_id = format!("profile:{maximum}");
        selected.edges[0].condition = json!({"all":[{"value":maximum}]});
        selected.sites[0].id = format!("site:{maximum}");
        selected.sites[0].specifier = Some(maximum.clone());
        selected.sites[0].profile_id = format!("profile:{maximum}");
        selected.sites[0].condition = json!({"all":[{"value":maximum}]});
        selected.evidence[0].owner_id = selected.edges[0].id.clone();
        selected.evidence[0].path = format!("src/{maximum}.rs");
        let mut site_evidence = selected.evidence[0].clone();
        site_evidence.owner_type = "site".into();
        site_evidence.owner_id = selected.sites[0].id.clone();
        selected.evidence.push(site_evidence);

        let depth = 8_u8;
        let typed = query(1, depth, "");
        let plan = plan_bounded_query(&typed, "snapshot:stable", &selected).unwrap();
        let statistics = &plan.snapshot_statistics.closed_field_byte_bounds;
        let largest_node = selected
            .nodes
            .iter()
            .map(super::closed_node)
            .max_by_key(super::json_bytes)
            .unwrap();
        let largest_edge = selected
            .edges
            .iter()
            .map(super::closed_edge)
            .max_by_key(super::json_bytes)
            .unwrap();
        let largest_site = selected
            .sites
            .iter()
            .map(super::closed_site)
            .max_by_key(super::json_bytes)
            .unwrap();
        let largest_evidence = selected
            .evidence
            .iter()
            .map(super::closed_evidence)
            .max_by_key(super::json_bytes)
            .unwrap();
        assert_eq!(super::json_bytes(&largest_node), statistics.node_entity);
        assert_eq!(super::json_bytes(&largest_edge), statistics.edge_entity);
        assert_eq!(super::json_bytes(&largest_site), statistics.site_entity);
        assert_eq!(
            super::json_bytes(&largest_evidence),
            statistics.evidence_entity
        );

        let depth = u64::from(depth);
        let evidence_count = depth * plan.cardinality_inputs.maximum_associated_evidence_per_edge;
        let path = json!({
            "id": format!("query-path:sha256:{}", "f".repeat(64)),
            "depth": depth,
            "direction": "forward",
            "nodes": vec![largest_node; usize::try_from(depth + 1).unwrap()],
            "edges": vec![largest_edge; usize::try_from(depth).unwrap()],
            "sites": vec![largest_site; usize::try_from(depth).unwrap()],
            "evidence": vec![
                largest_evidence;
                usize::try_from(evidence_count).unwrap()
            ],
        });
        let row = json!([selected.nodes[0].id, selected.nodes[1].id, path,]);
        let actual_rows = json!([row]);
        assert!(
            super::json_bytes(&actual_rows) <= plan.bounds.serialized_output_bytes,
            "actual={} planned={}",
            super::json_bytes(&actual_rows),
            plan.bounds.serialized_output_bytes
        );
    }

    #[test]
    fn tampered_statistics_and_graph_payload_fail_closed() {
        let selected = snapshot(false);
        let typed = query(10, 1, "");
        let mut statistics = collect_bounded_query_statistics("snapshot:stable", &selected);
        statistics.node_count += 1;
        let error = plan_bounded_query_with_statistics(&typed, &selected, statistics).unwrap_err();
        assert_eq!(error.code, "query_statistics_digest_mismatch");

        let mut statistics = collect_bounded_query_statistics("snapshot:stable", &selected);
        statistics.metadata_digest = {
            statistics.node_count += 1;
            super::statistics_digest(&statistics)
        };
        let error = plan_bounded_query_with_statistics(&typed, &selected, statistics).unwrap_err();
        assert!(matches!(
            error,
            BoundedQueryPlanningError {
                code: "query_statistics_cardinality_mismatch",
                ..
            }
        ));

        let mut changed_snapshot = selected.clone();
        let statistics = collect_bounded_query_statistics("snapshot:stable", &selected);
        changed_snapshot.nodes[0].display_name = "tampered".into();
        let error =
            plan_bounded_query_with_statistics(&typed, &changed_snapshot, statistics).unwrap_err();
        assert_eq!(error.code, "query_snapshot_graph_digest_mismatch");
    }

    #[test]
    fn boundary_and_overflow_plans_reject_before_execution() {
        let mut selected = snapshot(false);
        for index in 0..1_000 {
            selected.edges.push(depgraph_store::EdgeRecord {
                id: format!("edge:{index:02}"),
                site_id: None,
                source: "node:route".into(),
                target: "node:service".into(),
                kind: "calls".into(),
                phase: "semantic".into(),
                environment: "production".into(),
                profile_id: "profile:a".into(),
                resolution_status: "resolved".into(),
                precision: "exact".into(),
                condition: json!({}),
                generated: false,
            });
        }
        let plan = plan_bounded_query(&query(1, 8, ""), "snapshot:large", &selected).unwrap();
        assert!(!plan.admitted);
        assert!(plan.reasons.iter().any(|reason| {
            matches!(
                reason.resource.as_str(),
                "traversal_states" | "edge_tests" | "deterministic_cost"
            )
        }));
        assert!(plan.bounds.traversal_states > plan.limits.traversal_states);
        assert_eq!(plan.bounds.traversal_states, u64::MAX);
    }

    #[test]
    fn hard_limit_boundaries_are_inclusive() {
        let limits = super::BoundedQueryLimits::default();
        let mut bounds = super::BoundedQueryResourceBounds {
            source_node_tests: limits.source_node_tests,
            traversal_states: limits.traversal_states,
            edge_tests: limits.edge_tests,
            site_tests: limits.site_tests,
            evidence_tests: limits.evidence_tests,
            result_rows: limits.result_rows,
            serialized_output_bytes: limits.serialized_output_bytes,
            working_memory_bytes: limits.working_memory_bytes,
            deterministic_cost: limits.deterministic_cost,
        };
        assert!(super::admission_reasons(&bounds, &limits).is_empty());
        bounds.source_node_tests += 1;
        let reasons = super::admission_reasons(&bounds, &limits);
        assert_eq!(reasons.len(), 1);
        assert_eq!(reasons[0].resource, "source_node_tests");
        assert_eq!(reasons[0].code, "query_plan_budget_exceeded");
    }

    #[test]
    fn plan_json_contains_every_hard_limit_and_stable_rejection() {
        let plan =
            plan_bounded_query(&query(10, 1, ""), "snapshot:stable", &snapshot(false)).unwrap();
        let value: Value = serde_json::from_str(&canonical_bounded_query_plan_json(&plan)).unwrap();
        assert_eq!(value["schema_version"], "bounded-query-plan-v1");
        assert_eq!(value["limit_version"], "bounded-query-limits-v1");
        assert_eq!(value["limits"]["deadline_milliseconds"], 5_000);
        assert!(value["limits"]["working_memory_bytes"].as_u64().is_some());
    }

    #[derive(Deserialize)]
    struct PlanGoldenFixture {
        query: String,
        graph_digest: String,
        plan_digest: String,
    }

    #[test]
    fn plan_digest_matches_golden_explain_fixture() {
        let fixture: PlanGoldenFixture =
            serde_json::from_str(include_str!("../tests/fixtures/bounded_query_plan_v1.json"))
                .unwrap();
        let typed = parse_and_type_check_bounded_query(&fixture.query).unwrap();
        let plan = plan_bounded_query(&typed, "snapshot:stable", &snapshot(false)).unwrap();
        assert_eq!(plan.graph_digest, fixture.graph_digest);
        assert_eq!(plan.plan_digest, fixture.plan_digest);
    }
}
