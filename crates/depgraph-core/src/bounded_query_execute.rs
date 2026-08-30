use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet},
    time::{Duration, Instant},
};

use depgraph_protocol::{canonical_json, stable_id_from_value};
use depgraph_store::{EdgeRecord, EvidenceRecord, GraphSnapshot, NodeRecord, SiteRecord};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::bounded_query_plan::bounded_query_snapshot_id;
use crate::bounded_query_type::TypedQuantifierPredicate;
use crate::{
    BOUNDED_QUERY_CONTRACT_VERSION, BoundedQueryLimits, BoundedQueryPlan, CancellationToken,
    EntityType, Literal, QueryDirection, ScalarOperator, SortDirection, TypedEntityExpression,
    TypedExpression, TypedProjection, TypedQuery, TypedScalarPredicate, bounded_query_graph_digest,
    bounded_query_plan_digest, render_condition, typed_query_ast_digest,
};

pub const BOUNDED_QUERY_RESULT_SCHEMA_VERSION: &str = "bounded-query-result-v1";

const EXECUTION_STATE_BYTES: u64 = 256;
const EXECUTION_ADJACENCY_EDGE_BYTES: u64 = 64;
const EXECUTION_NODE_INDEX_BYTES: u64 = 32;
const EXECUTION_SITE_INDEX_BYTES: u64 = 32;
const EXECUTION_EVIDENCE_INDEX_BYTES: u64 = 32;

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct BoundedQueryExecutionOptions {
    pub limits: BoundedQueryLimits,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BoundedQueryExecutionMetrics {
    pub source_node_tests: u64,
    pub traversal_states: u64,
    pub edge_tests: u64,
    pub site_tests: u64,
    pub evidence_tests: u64,
    pub result_rows: u64,
    pub serialized_output_bytes: u64,
    pub working_memory_bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BoundedQueryResult {
    pub schema_version: String,
    pub contract_version: String,
    pub plan_digest: String,
    pub snapshot_id: String,
    pub graph_digest: String,
    pub complete: bool,
    pub rows: Vec<Vec<Value>>,
    pub metrics: BoundedQueryExecutionMetrics,
    pub result_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct BoundedQueryExecutionError {
    pub code: &'static str,
    pub resource: Option<&'static str>,
    pub observed: Option<u64>,
    pub limit: Option<u64>,
    #[serde(skip)]
    message: &'static str,
}

impl std::fmt::Display for BoundedQueryExecutionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)?;
        if let (Some(resource), Some(observed), Some(limit)) =
            (self.resource, self.observed, self.limit)
        {
            write!(
                formatter,
                "; resource={resource}; observed={observed}; limit={limit}"
            )?;
        }
        Ok(())
    }
}

impl std::error::Error for BoundedQueryExecutionError {}

pub type BoundedQueryExecutionResult<T> = Result<T, BoundedQueryExecutionError>;

pub fn bounded_query_result_digest(result: &BoundedQueryResult) -> String {
    let mut payload =
        serde_json::to_value(result).expect("bounded query result serialization cannot fail");
    payload["result_digest"] = Value::String(String::new());
    stable_id_from_value("bounded-query-result", &payload)
}

pub fn execute_bounded_query(
    query: &TypedQuery,
    plan: &BoundedQueryPlan,
    snapshot: &GraphSnapshot,
    cancellation: &CancellationToken,
) -> BoundedQueryExecutionResult<BoundedQueryResult> {
    execute_bounded_query_with_options(
        query,
        plan,
        snapshot,
        cancellation,
        BoundedQueryExecutionOptions::default(),
    )
}

pub fn execute_bounded_query_with_options(
    query: &TypedQuery,
    plan: &BoundedQueryPlan,
    snapshot: &GraphSnapshot,
    cancellation: &CancellationToken,
    options: BoundedQueryExecutionOptions,
) -> BoundedQueryExecutionResult<BoundedQueryResult> {
    cancellation_check(cancellation)?;
    validate_execution_inputs(query, plan, snapshot, &options)?;
    if !plan.admitted {
        return Err(execution_error(
            "query_plan_not_admitted",
            "bounded query plan was rejected before execution",
        ));
    }

    let mut executor = Executor::new(query, plan, snapshot, cancellation, options)?;
    executor.run()
}

fn validate_execution_inputs(
    query: &TypedQuery,
    plan: &BoundedQueryPlan,
    snapshot: &GraphSnapshot,
    options: &BoundedQueryExecutionOptions,
) -> BoundedQueryExecutionResult<()> {
    if query.digest != typed_query_ast_digest(&query.ast)
        || plan.plan_digest != bounded_query_plan_digest(plan)
    {
        return Err(execution_error(
            "query_execution_contract_mismatch",
            "typed query or plan digest does not match its canonical payload",
        ));
    }
    let graph_digest = bounded_query_graph_digest(snapshot);
    if graph_digest != plan.graph_digest
        || plan.snapshot_id != bounded_query_snapshot_id(&graph_digest)
        || plan.snapshot_statistics.graph_digest != graph_digest
        || plan.snapshot_statistics.snapshot_id != plan.snapshot_id
    {
        return Err(execution_error(
            "query_execution_snapshot_mismatch",
            "selected snapshot does not match the validated query plan",
        ));
    }
    validate_lowered_limits(&options.limits, &plan.limits)?;
    if plan.bounds.deterministic_cost > options.limits.deterministic_cost {
        return Err(resource_error(
            "deterministic_cost",
            plan.bounds.deterministic_cost,
            options.limits.deterministic_cost,
        ));
    }
    Ok(())
}

fn validate_lowered_limits(
    requested: &BoundedQueryLimits,
    hard: &BoundedQueryLimits,
) -> BoundedQueryExecutionResult<()> {
    let pairs = [
        (requested.source_node_tests, hard.source_node_tests),
        (requested.traversal_states, hard.traversal_states),
        (requested.edge_tests, hard.edge_tests),
        (requested.site_tests, hard.site_tests),
        (requested.evidence_tests, hard.evidence_tests),
        (requested.result_rows, hard.result_rows),
        (
            requested.serialized_output_bytes,
            hard.serialized_output_bytes,
        ),
        (requested.deterministic_cost, hard.deterministic_cost),
        (requested.working_memory_bytes, hard.working_memory_bytes),
        (requested.deadline_milliseconds, hard.deadline_milliseconds),
    ];
    if pairs.into_iter().any(|(requested, hard)| requested > hard) {
        return Err(execution_error(
            "query_execution_limits_invalid",
            "execution limits may lower but never raise the planned hard limits",
        ));
    }
    Ok(())
}

struct Executor<'a> {
    query: &'a TypedQuery,
    plan: &'a BoundedQueryPlan,
    cancellation: &'a CancellationToken,
    options: BoundedQueryExecutionOptions,
    started: Instant,
    nodes: BTreeMap<&'a str, &'a NodeRecord>,
    edges: BTreeMap<&'a str, &'a EdgeRecord>,
    sites: BTreeMap<&'a str, &'a SiteRecord>,
    evidence: BTreeMap<(&'a str, &'a str), Vec<&'a EvidenceRecord>>,
    adjacency: BTreeMap<&'a str, Vec<&'a EdgeRecord>>,
    some_predicates: Vec<&'a TypedQuantifierPredicate>,
    metrics: BoundedQueryExecutionMetrics,
    staged: RowStager,
}

impl<'a> Executor<'a> {
    fn new(
        query: &'a TypedQuery,
        plan: &'a BoundedQueryPlan,
        snapshot: &'a GraphSnapshot,
        cancellation: &'a CancellationToken,
        options: BoundedQueryExecutionOptions,
    ) -> BoundedQueryExecutionResult<Self> {
        let started = Instant::now();
        let kinds = query
            .ast
            .match_clause
            .relationship
            .kinds
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        construction_guard(started, cancellation, options.limits.deadline_milliseconds)?;
        let mut eligible_edge_count = 0_u64;
        for edge in &snapshot.edges {
            construction_guard(started, cancellation, options.limits.deadline_milliseconds)?;
            if kinds.contains(edge.kind.as_str()) {
                eligible_edge_count = eligible_edge_count.saturating_add(1);
            }
        }
        let initial_memory = eligible_edge_count
            .saturating_mul(EXECUTION_ADJACENCY_EDGE_BYTES)
            .saturating_add(
                usize_u64(snapshot.nodes.len()).saturating_mul(EXECUTION_NODE_INDEX_BYTES),
            )
            .saturating_add(
                usize_u64(snapshot.sites.len()).saturating_mul(EXECUTION_SITE_INDEX_BYTES),
            )
            .saturating_add(
                usize_u64(snapshot.evidence.len()).saturating_mul(EXECUTION_EVIDENCE_INDEX_BYTES),
            );
        if initial_memory > options.limits.working_memory_bytes {
            return Err(resource_error(
                "working_memory_bytes",
                initial_memory,
                options.limits.working_memory_bytes,
            ));
        }

        let mut nodes = BTreeMap::new();
        for node in &snapshot.nodes {
            construction_guard(started, cancellation, options.limits.deadline_milliseconds)?;
            if nodes.insert(node.id.as_str(), node).is_some() {
                return Err(execution_error(
                    "query_execution_snapshot_mismatch",
                    "selected snapshot contains duplicate node identifiers",
                ));
            }
        }
        let mut sites = BTreeMap::new();
        for site in &snapshot.sites {
            construction_guard(started, cancellation, options.limits.deadline_milliseconds)?;
            if sites.insert(site.id.as_str(), site).is_some() {
                return Err(execution_error(
                    "query_execution_snapshot_mismatch",
                    "selected snapshot contains duplicate site identifiers",
                ));
            }
        }
        let mut evidence = BTreeMap::<(&str, &str), Vec<&EvidenceRecord>>::new();
        for item in &snapshot.evidence {
            construction_guard(started, cancellation, options.limits.deadline_milliseconds)?;
            evidence
                .entry((item.owner_type.as_str(), item.owner_id.as_str()))
                .or_default()
                .push(item);
        }
        for records in evidence.values_mut() {
            records.sort_by(evidence_order);
        }

        let direction = query.ast.match_clause.relationship.direction;
        let mut edges = BTreeMap::new();
        let mut adjacency = BTreeMap::<&str, Vec<&EdgeRecord>>::new();
        for edge in &snapshot.edges {
            construction_guard(started, cancellation, options.limits.deadline_milliseconds)?;
            if !kinds.contains(edge.kind.as_str()) {
                continue;
            }
            if edges.insert(edge.id.as_str(), edge).is_some() {
                return Err(execution_error(
                    "query_execution_snapshot_mismatch",
                    "selected snapshot contains duplicate edge identifiers",
                ));
            }
            let node = match direction {
                QueryDirection::Forward => edge.source.as_str(),
                QueryDirection::Reverse => edge.target.as_str(),
            };
            adjacency.entry(node).or_default().push(edge);
        }
        for outgoing in adjacency.values_mut() {
            outgoing.sort_by(|left, right| {
                left.id.cmp(&right.id).then_with(|| {
                    traversed_node_id(left, direction).cmp(traversed_node_id(right, direction))
                })
            });
        }

        let mut some_predicates = Vec::new();
        if let Some(expression) = query.ast.where_clause.as_ref() {
            collect_some_predicates(expression, &mut some_predicates);
        }
        construction_guard(started, cancellation, options.limits.deadline_milliseconds)?;
        let staged = RowStager::new(query);
        Ok(Self {
            query,
            plan,
            cancellation,
            options,
            started,
            nodes,
            edges,
            sites,
            evidence,
            adjacency,
            some_predicates,
            metrics: BoundedQueryExecutionMetrics {
                source_node_tests: 0,
                traversal_states: 0,
                edge_tests: 0,
                site_tests: 0,
                evidence_tests: 0,
                result_rows: 0,
                serialized_output_bytes: 2,
                working_memory_bytes: initial_memory,
            },
            staged,
        })
    }

    fn run(&mut self) -> BoundedQueryExecutionResult<BoundedQueryResult> {
        self.guard()?;
        let sources = self.source_nodes()?;
        for source in sources {
            self.guard()?;
            self.run_source(source)?;
        }
        self.guard()?;

        let rows = self.staged.rows();
        let serialized_output_bytes = serialized_rows_bytes(&rows);
        self.check_resource(
            "result_rows",
            usize_u64(rows.len()),
            self.options.limits.result_rows,
        )?;
        self.check_resource(
            "serialized_output_bytes",
            serialized_output_bytes,
            self.options.limits.serialized_output_bytes,
        )?;
        self.metrics.result_rows = usize_u64(rows.len());
        self.metrics.serialized_output_bytes = serialized_output_bytes;
        self.refresh_memory()?;

        let mut result = BoundedQueryResult {
            schema_version: BOUNDED_QUERY_RESULT_SCHEMA_VERSION.to_owned(),
            contract_version: BOUNDED_QUERY_CONTRACT_VERSION.to_owned(),
            plan_digest: self.plan.plan_digest.clone(),
            snapshot_id: self.plan.snapshot_id.clone(),
            graph_digest: self.plan.graph_digest.clone(),
            complete: true,
            rows,
            metrics: self.metrics.clone(),
            result_digest: String::new(),
        };
        result.result_digest = bounded_query_result_digest(&result);
        self.cancellation
            .run_if_active(|| result)
            .ok_or_else(cancelled_error)
    }

    fn source_nodes(&mut self) -> BoundedQueryExecutionResult<Vec<&'a NodeRecord>> {
        let source_pattern = &self.query.ast.match_clause.source;
        if self.plan.cardinality_inputs.source_nodes == 0 {
            return Ok(Vec::new());
        }
        if let Some(source_id) = source_id_lookup(self.query) {
            self.increment_source_tests()?;
            let source = self.nodes.get(source_id).copied().filter(|node| {
                source_pattern
                    .kind
                    .as_ref()
                    .is_none_or(|kind| node.kind == *kind)
                    && self.source_predicates_match(node)
            });
            return Ok(source.into_iter().collect());
        }
        let mut sources = Vec::new();
        let candidates = self.nodes.values().copied().collect::<Vec<_>>();
        for node in candidates {
            if source_pattern
                .kind
                .as_ref()
                .is_some_and(|kind| node.kind != *kind)
            {
                continue;
            }
            self.increment_source_tests()?;
            if self.source_predicates_match(node) {
                sources.push(node);
            }
        }
        sources.sort_by(|left, right| left.id.cmp(&right.id));
        Ok(sources)
    }

    fn source_predicates_match(&self, source: &NodeRecord) -> bool {
        let Some(expression) = self.query.ast.where_clause.as_ref() else {
            return true;
        };
        let source_binding = self.query.ast.match_clause.source.binding.name.as_str();
        let witness = Witness {
            node_ids: vec![source.id.clone()],
            edge_ids: Vec::new(),
            used_edges: BTreeSet::new(),
            site_ids: BTreeSet::new(),
            existential_bits: 0,
        };
        let matches = |expression: &TypedExpression| {
            let mut some_index = 0;
            evaluate_expression(
                expression,
                EvaluationContext {
                    query: self.query,
                    source,
                    target: source,
                    witness: &witness,
                    edges: &self.edges,
                },
                &mut some_index,
            )
        };
        match expression {
            TypedExpression::And(terms) => terms
                .iter()
                .filter(|term| expression_references_only_source(term, source_binding))
                .all(matches),
            _ if expression_references_only_source(expression, source_binding) => {
                matches(expression)
            }
            _ => true,
        }
    }

    fn run_source(&mut self, source: &'a NodeRecord) -> BoundedQueryExecutionResult<()> {
        let initial = Witness {
            node_ids: vec![source.id.clone()],
            edge_ids: Vec::new(),
            used_edges: BTreeSet::new(),
            site_ids: BTreeSet::new(),
            existential_bits: 0,
        };
        let initial_key = StateKey::from_witness(&initial);
        let mut current = BTreeMap::from([(initial_key, initial)]);
        self.increment_state()?;
        let mut resolved_targets = BTreeSet::new();
        let minimum_depth = self.query.ast.match_clause.relationship.min_depth;
        let maximum_depth = self.query.ast.match_clause.relationship.max_depth;

        for depth in 0..=maximum_depth {
            self.guard()?;
            if depth >= minimum_depth {
                let mut layer_matches = BTreeMap::<String, Witness>::new();
                for witness in current.values() {
                    let target_id = witness
                        .node_ids
                        .last()
                        .expect("bounded query witness always has a node");
                    if resolved_targets.contains(target_id) {
                        continue;
                    }
                    let Some(target) = self.nodes.get(target_id.as_str()).copied() else {
                        continue;
                    };
                    if !self.target_kind_matches(target)
                        || !self.where_matches(source, target, witness)
                    {
                        continue;
                    }
                    match layer_matches.entry(target.id.clone()) {
                        std::collections::btree_map::Entry::Vacant(entry) => {
                            entry.insert(witness.clone());
                        }
                        std::collections::btree_map::Entry::Occupied(mut entry) => {
                            if witness_order(witness, entry.get()) == Ordering::Less {
                                entry.insert(witness.clone());
                            }
                        }
                    }
                }
                for (target_id, witness) in layer_matches {
                    let target = self.nodes[target_id.as_str()];
                    let row = self.project_row(source, target, &witness)?;
                    self.staged.insert(row);
                    self.refresh_staged_metrics()?;
                    resolved_targets.insert(target_id);
                }
            }
            if depth == maximum_depth {
                break;
            }

            let mut next = BTreeMap::<StateKey, Witness>::new();
            let states = current.into_values().collect::<Vec<_>>();
            for witness in states {
                self.guard()?;
                let current_id = witness
                    .node_ids
                    .last()
                    .expect("bounded query witness always has a node");
                let outgoing = self
                    .adjacency
                    .get(current_id.as_str())
                    .cloned()
                    .unwrap_or_default();
                for edge in outgoing {
                    self.increment_edge_tests()?;
                    if witness.used_edges.contains(&edge.id) {
                        continue;
                    }
                    let next_node_id =
                        traversed_node_id(edge, self.query.ast.match_clause.relationship.direction);
                    if !self.nodes.contains_key(next_node_id) {
                        continue;
                    }
                    let candidate = self.extend_witness(&witness, edge, next_node_id)?;
                    let key = StateKey::from_witness(&candidate);
                    match next.entry(key) {
                        std::collections::btree_map::Entry::Vacant(entry) => {
                            self.increment_state()?;
                            entry.insert(candidate);
                        }
                        std::collections::btree_map::Entry::Occupied(mut entry) => {
                            if witness_order(&candidate, entry.get()) == Ordering::Less {
                                entry.insert(candidate);
                            }
                        }
                    }
                }
            }
            current = next;
            if current.is_empty() {
                break;
            }
        }
        Ok(())
    }

    fn target_kind_matches(&self, target: &NodeRecord) -> bool {
        self.query
            .ast
            .match_clause
            .target
            .kind
            .as_ref()
            .is_none_or(|kind| target.kind == *kind)
    }

    fn extend_witness(
        &mut self,
        witness: &Witness,
        edge: &EdgeRecord,
        next_node_id: &str,
    ) -> BoundedQueryExecutionResult<Witness> {
        let mut candidate = witness.clone();
        candidate.edge_ids.push(edge.id.clone());
        candidate.node_ids.push(next_node_id.to_owned());
        candidate.used_edges.insert(edge.id.clone());

        let new_site = edge
            .site_id
            .as_deref()
            .filter(|site_id| !candidate.site_ids.contains(*site_id))
            .and_then(|site_id| self.sites.get(site_id).copied());
        if let Some(site) = new_site {
            candidate.site_ids.insert(site.id.clone());
        }
        let edge_evidence = self
            .evidence
            .get(&("edge", edge.id.as_str()))
            .cloned()
            .unwrap_or_default();
        let site_evidence = new_site
            .and_then(|site| self.evidence.get(&("site", site.id.as_str())))
            .cloned()
            .unwrap_or_default();

        for index in 0..self.some_predicates.len() {
            let bit = 1_u64 << index;
            if candidate.existential_bits & bit != 0 {
                continue;
            }
            let predicate = self.some_predicates[index];
            let matched = match predicate.binding.entity_type {
                EntityType::Site => {
                    if let Some(site) = new_site {
                        self.increment_site_tests()?;
                        evaluate_entity_expression(&predicate.expression, EntityView::Site(site))
                    } else {
                        false
                    }
                }
                EntityType::Evidence => {
                    let mut matched = false;
                    for evidence in edge_evidence.iter().chain(site_evidence.iter()) {
                        self.increment_evidence_tests()?;
                        if evaluate_entity_expression(
                            &predicate.expression,
                            EntityView::Evidence(evidence),
                        ) {
                            matched = true;
                            break;
                        }
                    }
                    matched
                }
                _ => false,
            };
            if matched {
                candidate.existential_bits |= bit;
            }
        }
        Ok(candidate)
    }

    fn where_matches(&self, source: &NodeRecord, target: &NodeRecord, witness: &Witness) -> bool {
        let Some(expression) = self.query.ast.where_clause.as_ref() else {
            return true;
        };
        let mut some_index = 0;
        evaluate_expression(
            expression,
            EvaluationContext {
                query: self.query,
                source,
                target,
                witness,
                edges: &self.edges,
            },
            &mut some_index,
        )
    }

    fn project_row(
        &self,
        source: &NodeRecord,
        target: &NodeRecord,
        witness: &Witness,
    ) -> BoundedQueryExecutionResult<Vec<Value>> {
        let path = self.path_value(source, target, witness)?;
        self.query
            .ast
            .return_clause
            .projections
            .iter()
            .map(|projection| project_value(projection, self.query, source, target, witness, &path))
            .collect()
    }

    fn path_value(
        &self,
        source: &NodeRecord,
        target: &NodeRecord,
        witness: &Witness,
    ) -> BoundedQueryExecutionResult<Value> {
        let direction = direction_name(self.query.ast.match_clause.relationship.direction);
        let path_id = stable_id_from_value(
            "query-path",
            &json!({
                "contract_version": BOUNDED_QUERY_CONTRACT_VERSION,
                "snapshot_id": self.plan.snapshot_id,
                "direction": direction,
                "source_id": source.id,
                "target_id": target.id,
                "edge_ids": witness.edge_ids,
            }),
        );
        let nodes = witness
            .node_ids
            .iter()
            .map(|node_id| {
                self.nodes
                    .get(node_id.as_str())
                    .copied()
                    .map(closed_node_value)
                    .ok_or_else(|| {
                        execution_error(
                            "query_execution_snapshot_mismatch",
                            "witness references a missing node",
                        )
                    })
            })
            .collect::<BoundedQueryExecutionResult<Vec<_>>>()?;
        let path_edges = witness
            .edge_ids
            .iter()
            .map(|edge_id| {
                self.edges
                    .get(edge_id.as_str())
                    .copied()
                    .map(closed_edge_value)
                    .ok_or_else(|| {
                        execution_error(
                            "query_execution_snapshot_mismatch",
                            "witness references a missing edge",
                        )
                    })
            })
            .collect::<BoundedQueryExecutionResult<Vec<_>>>()?;
        let path_sites = witness
            .site_ids
            .iter()
            .filter_map(|site_id| self.sites.get(site_id.as_str()).copied())
            .map(closed_site_value)
            .collect::<Vec<_>>();
        let mut path_evidence = Vec::new();
        for edge_id in &witness.edge_ids {
            path_evidence.extend(
                self.evidence
                    .get(&("edge", edge_id.as_str()))
                    .into_iter()
                    .flatten()
                    .copied(),
            );
        }
        for site_id in &witness.site_ids {
            path_evidence.extend(
                self.evidence
                    .get(&("site", site_id.as_str()))
                    .into_iter()
                    .flatten()
                    .copied(),
            );
        }
        path_evidence.sort_by(evidence_order);
        path_evidence.dedup_by(|left, right| evidence_order(left, right) == Ordering::Equal);
        let path_evidence = path_evidence
            .into_iter()
            .map(closed_evidence_value)
            .collect::<Vec<_>>();

        Ok(json!({
            "id": path_id,
            "depth": witness.edge_ids.len(),
            "direction": direction,
            "nodes": nodes,
            "edges": path_edges,
            "sites": path_sites,
            "evidence": path_evidence,
        }))
    }

    fn increment_source_tests(&mut self) -> BoundedQueryExecutionResult<()> {
        self.metrics.source_node_tests = self.metrics.source_node_tests.saturating_add(1);
        self.check_resource(
            "source_node_tests",
            self.metrics.source_node_tests,
            self.options.limits.source_node_tests,
        )
    }

    fn increment_state(&mut self) -> BoundedQueryExecutionResult<()> {
        self.metrics.traversal_states = self.metrics.traversal_states.saturating_add(1);
        self.check_resource(
            "traversal_states",
            self.metrics.traversal_states,
            self.options.limits.traversal_states,
        )?;
        self.refresh_memory()
    }

    fn increment_edge_tests(&mut self) -> BoundedQueryExecutionResult<()> {
        self.guard()?;
        self.metrics.edge_tests = self.metrics.edge_tests.saturating_add(1);
        self.check_resource(
            "edge_tests",
            self.metrics.edge_tests,
            self.options.limits.edge_tests,
        )
    }

    fn increment_site_tests(&mut self) -> BoundedQueryExecutionResult<()> {
        self.metrics.site_tests = self.metrics.site_tests.saturating_add(1);
        self.check_resource(
            "site_tests",
            self.metrics.site_tests,
            self.options.limits.site_tests,
        )
    }

    fn increment_evidence_tests(&mut self) -> BoundedQueryExecutionResult<()> {
        self.metrics.evidence_tests = self.metrics.evidence_tests.saturating_add(1);
        self.check_resource(
            "evidence_tests",
            self.metrics.evidence_tests,
            self.options.limits.evidence_tests,
        )
    }

    fn refresh_staged_metrics(&mut self) -> BoundedQueryExecutionResult<()> {
        self.metrics.result_rows = usize_u64(self.staged.len());
        self.metrics.serialized_output_bytes = self.staged.serialized_bytes();
        self.check_resource(
            "result_rows",
            self.metrics.result_rows,
            self.options.limits.result_rows,
        )?;
        self.check_resource(
            "serialized_output_bytes",
            self.metrics.serialized_output_bytes,
            self.options.limits.serialized_output_bytes,
        )?;
        self.refresh_memory()
    }

    fn refresh_memory(&mut self) -> BoundedQueryExecutionResult<()> {
        let adjacency = u64::try_from(self.adjacency.values().map(Vec::len).sum::<usize>())
            .unwrap_or(u64::MAX)
            .saturating_mul(EXECUTION_ADJACENCY_EDGE_BYTES);
        let indexes = usize_u64(self.nodes.len())
            .saturating_mul(EXECUTION_NODE_INDEX_BYTES)
            .saturating_add(usize_u64(self.sites.len()).saturating_mul(EXECUTION_SITE_INDEX_BYTES))
            .saturating_add(
                usize_u64(self.evidence.values().map(Vec::len).sum::<usize>())
                    .saturating_mul(EXECUTION_EVIDENCE_INDEX_BYTES),
            );
        let states = self
            .metrics
            .traversal_states
            .saturating_mul(EXECUTION_STATE_BYTES);
        self.metrics.working_memory_bytes = adjacency
            .saturating_add(indexes)
            .saturating_add(states)
            .saturating_add(self.metrics.serialized_output_bytes);
        self.check_resource(
            "working_memory_bytes",
            self.metrics.working_memory_bytes,
            self.options.limits.working_memory_bytes,
        )
    }

    fn check_resource(
        &self,
        resource: &'static str,
        observed: u64,
        limit: u64,
    ) -> BoundedQueryExecutionResult<()> {
        if observed > limit {
            Err(resource_error(resource, observed, limit))
        } else {
            Ok(())
        }
    }

    fn guard(&self) -> BoundedQueryExecutionResult<()> {
        cancellation_check(self.cancellation)?;
        if self.started.elapsed()
            >= Duration::from_millis(self.options.limits.deadline_milliseconds)
        {
            return Err(deadline_error(self.options.limits.deadline_milliseconds));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct StateKey {
    current_node_id: String,
    depth: usize,
    existential_bits: u64,
    used_edge_ids: Vec<String>,
}

impl StateKey {
    fn from_witness(witness: &Witness) -> Self {
        Self {
            current_node_id: witness
                .node_ids
                .last()
                .expect("bounded query witness always has a node")
                .clone(),
            depth: witness.edge_ids.len(),
            existential_bits: witness.existential_bits,
            used_edge_ids: witness.used_edges.iter().cloned().collect(),
        }
    }
}

#[derive(Clone, Debug)]
struct Witness {
    node_ids: Vec<String>,
    edge_ids: Vec<String>,
    used_edges: BTreeSet<String>,
    site_ids: BTreeSet<String>,
    existential_bits: u64,
}

struct EvaluationContext<'a> {
    query: &'a TypedQuery,
    source: &'a NodeRecord,
    target: &'a NodeRecord,
    witness: &'a Witness,
    edges: &'a BTreeMap<&'a str, &'a EdgeRecord>,
}

#[derive(Clone, Copy)]
enum EntityView<'a> {
    Node(&'a NodeRecord),
    Path {
        id: Option<&'a str>,
        depth: u64,
        direction: &'static str,
    },
    Edge(&'a EdgeRecord),
    Site(&'a SiteRecord),
    Evidence(&'a EvidenceRecord),
}

fn evaluate_expression(
    expression: &TypedExpression,
    context: EvaluationContext<'_>,
    some_index: &mut usize,
) -> bool {
    match expression {
        TypedExpression::Or(terms) => {
            let mut matched = false;
            for term in terms {
                matched |= evaluate_expression(term, EvaluationContext { ..context }, some_index);
            }
            matched
        }
        TypedExpression::And(terms) => {
            let mut matched = true;
            for term in terms {
                matched &= evaluate_expression(term, EvaluationContext { ..context }, some_index);
            }
            matched
        }
        TypedExpression::Not(inner) => !evaluate_expression(inner, context, some_index),
        TypedExpression::Scalar(predicate) => {
            let binding = predicate.field.binding.as_str();
            let entity = if binding == context.query.ast.match_clause.source.binding.name {
                EntityView::Node(context.source)
            } else if binding == context.query.ast.match_clause.target.binding.name {
                EntityView::Node(context.target)
            } else {
                EntityView::Path {
                    id: None,
                    depth: usize_u64(context.witness.edge_ids.len()),
                    direction: direction_name(
                        context.query.ast.match_clause.relationship.direction,
                    ),
                }
            };
            evaluate_scalar_predicate(predicate, entity)
        }
        TypedExpression::Quantifier(predicate) => match predicate.binding.entity_type {
            EntityType::Edge => context.witness.edge_ids.iter().all(|edge_id| {
                context.edges.get(edge_id.as_str()).is_some_and(|edge| {
                    evaluate_entity_expression(&predicate.expression, EntityView::Edge(edge))
                })
            }),
            EntityType::Site | EntityType::Evidence => {
                let bit = 1_u64 << *some_index;
                *some_index += 1;
                context.witness.existential_bits & bit != 0
            }
            _ => false,
        },
    }
}

fn evaluate_entity_expression(expression: &TypedEntityExpression, entity: EntityView<'_>) -> bool {
    match expression {
        TypedEntityExpression::Or(terms) => terms
            .iter()
            .any(|term| evaluate_entity_expression(term, entity)),
        TypedEntityExpression::And(terms) => terms
            .iter()
            .all(|term| evaluate_entity_expression(term, entity)),
        TypedEntityExpression::Not(inner) => !evaluate_entity_expression(inner, entity),
        TypedEntityExpression::Scalar(predicate) => evaluate_scalar_predicate(predicate, entity),
    }
}

fn evaluate_scalar_predicate(predicate: &TypedScalarPredicate, entity: EntityView<'_>) -> bool {
    let Some(left) = entity_field_value(entity, &predicate.field.field) else {
        return false;
    };
    match &predicate.operator {
        ScalarOperator::Equal(literal) => left == literal_value(literal),
        ScalarOperator::NotEqual(literal) => left != literal_value(literal),
        ScalarOperator::Less(literal) => {
            scalar_order(&left, &literal_value(literal)) == Some(Ordering::Less)
        }
        ScalarOperator::LessOrEqual(literal) => matches!(
            scalar_order(&left, &literal_value(literal)),
            Some(Ordering::Less | Ordering::Equal)
        ),
        ScalarOperator::Greater(literal) => {
            scalar_order(&left, &literal_value(literal)) == Some(Ordering::Greater)
        }
        ScalarOperator::GreaterOrEqual(literal) => matches!(
            scalar_order(&left, &literal_value(literal)),
            Some(Ordering::Greater | Ordering::Equal)
        ),
        ScalarOperator::StartsWith(Literal::String(prefix)) => left
            .as_str()
            .is_some_and(|value| value.as_bytes().starts_with(prefix.as_bytes())),
        ScalarOperator::StartsWith(_) => false,
        ScalarOperator::In(literals) => literals
            .iter()
            .any(|literal| left == literal_value(literal)),
    }
}

fn entity_field_value(entity: EntityView<'_>, field: &str) -> Option<Value> {
    match entity {
        EntityView::Node(node) => match field {
            "id" => Some(json!(node.id)),
            "kind" => Some(json!(node.kind)),
            "locator" => Some(json!(node.locator)),
            "display_name" => Some(json!(node.display_name)),
            _ => None,
        },
        EntityView::Path {
            id,
            depth,
            direction,
        } => match field {
            "id" => Some(id.map_or(Value::Null, |id| json!(id))),
            "depth" => Some(json!(depth)),
            "direction" => Some(json!(direction)),
            _ => None,
        },
        EntityView::Edge(edge) => match field {
            "id" => Some(json!(edge.id)),
            "kind" => Some(json!(edge.kind)),
            "phase" => Some(json!(edge.phase)),
            "environment" => Some(json!(edge.environment)),
            "profile_id" => Some(json!(edge.profile_id)),
            "resolution_status" => Some(json!(edge.resolution_status)),
            "precision" => Some(json!(edge.precision)),
            "condition" => Some(json!(render_condition(&edge.condition))),
            "generated" => Some(json!(edge.generated)),
            _ => None,
        },
        EntityView::Site(site) => match field {
            "id" => Some(json!(site.id)),
            "kind" => Some(json!(site.kind)),
            "specifier" => Some(site.specifier.clone().map_or(Value::Null, Value::String)),
            "profile_id" => Some(json!(site.profile_id)),
            "resolution_status" => Some(json!(site.resolution_status)),
            "precision" => Some(json!(site.precision)),
            "condition" => Some(json!(render_condition(&site.condition))),
            "reason" => Some(site.reason.clone().map_or(Value::Null, Value::String)),
            _ => None,
        },
        EntityView::Evidence(evidence) => match field {
            "owner_type" => Some(json!(evidence.owner_type)),
            "kind" => Some(json!(evidence.kind)),
            "extractor" => Some(json!(evidence.extractor)),
            "extractor_version" => Some(json!(evidence.extractor_version)),
            "path" => Some(json!(evidence.path)),
            "start_line" => Some(json!(evidence.start_line)),
            "start_column" => Some(json!(evidence.start_column)),
            "end_line" => Some(json!(evidence.end_line)),
            "end_column" => Some(json!(evidence.end_column)),
            "ordinal" => u64::try_from(evidence.ordinal).ok().map(Value::from),
            _ => None,
        },
    }
}

fn literal_value(literal: &Literal) -> Value {
    match literal {
        Literal::String(value) => json!(value),
        Literal::Unsigned(value) => json!(value),
        Literal::Boolean(value) => json!(value),
        Literal::Null => Value::Null,
    }
}

fn scalar_order(left: &Value, right: &Value) -> Option<Ordering> {
    match (left, right) {
        (Value::String(left), Value::String(right)) => Some(left.as_bytes().cmp(right.as_bytes())),
        (Value::Number(left), Value::Number(right)) => Some(left.as_u64()?.cmp(&right.as_u64()?)),
        _ => None,
    }
}

fn collect_some_predicates<'a>(
    expression: &'a TypedExpression,
    predicates: &mut Vec<&'a TypedQuantifierPredicate>,
) {
    match expression {
        TypedExpression::Or(terms) | TypedExpression::And(terms) => {
            for term in terms {
                collect_some_predicates(term, predicates);
            }
        }
        TypedExpression::Not(inner) => {
            collect_some_predicates(inner, predicates);
        }
        TypedExpression::Quantifier(predicate)
            if matches!(
                predicate.binding.entity_type,
                EntityType::Site | EntityType::Evidence
            ) =>
        {
            predicates.push(predicate);
        }
        TypedExpression::Scalar(_) | TypedExpression::Quantifier(_) => {}
    }
}

fn expression_references_only_source(expression: &TypedExpression, source_binding: &str) -> bool {
    match expression {
        TypedExpression::Or(terms) | TypedExpression::And(terms) => terms
            .iter()
            .all(|term| expression_references_only_source(term, source_binding)),
        TypedExpression::Not(inner) => expression_references_only_source(inner, source_binding),
        TypedExpression::Scalar(predicate) => predicate.field.binding == source_binding,
        TypedExpression::Quantifier(_) => false,
    }
}

fn source_id_lookup(query: &TypedQuery) -> Option<&str> {
    fn find<'a>(expression: &'a TypedExpression, source_binding: &str) -> Option<&'a str> {
        match expression {
            TypedExpression::Scalar(predicate)
                if predicate.field.binding == source_binding && predicate.field.field == "id" =>
            {
                match &predicate.operator {
                    ScalarOperator::Equal(Literal::String(value)) => Some(value),
                    _ => None,
                }
            }
            TypedExpression::And(terms) => terms.iter().find_map(|term| find(term, source_binding)),
            _ => None,
        }
    }
    query
        .ast
        .where_clause
        .as_ref()
        .and_then(|expression| find(expression, &query.ast.match_clause.source.binding.name))
}

fn project_value(
    projection: &TypedProjection,
    query: &TypedQuery,
    source: &NodeRecord,
    target: &NodeRecord,
    witness: &Witness,
    path: &Value,
) -> BoundedQueryExecutionResult<Value> {
    match projection {
        TypedProjection::Binding(binding) => match binding.entity_type {
            EntityType::Node => {
                if binding.name == query.ast.match_clause.source.binding.name {
                    Ok(closed_node_value(source))
                } else {
                    Ok(closed_node_value(target))
                }
            }
            EntityType::Path => Ok(path.clone()),
            _ => Err(execution_error(
                "query_execution_contract_mismatch",
                "projection contains a non-top-level binding",
            )),
        },
        TypedProjection::Field(field) => {
            let entity = match field.entity_type {
                EntityType::Node => {
                    if field.binding == query.ast.match_clause.source.binding.name {
                        EntityView::Node(source)
                    } else {
                        EntityView::Node(target)
                    }
                }
                EntityType::Path => EntityView::Path {
                    id: path.get("id").and_then(Value::as_str),
                    depth: usize_u64(witness.edge_ids.len()),
                    direction: direction_name(query.ast.match_clause.relationship.direction),
                },
                _ => {
                    return Err(execution_error(
                        "query_execution_contract_mismatch",
                        "projection contains a quantified field",
                    ));
                }
            };
            entity_field_value(entity, &field.field).ok_or_else(|| {
                execution_error(
                    "query_execution_contract_mismatch",
                    "projection field is not available",
                )
            })
        }
    }
}

fn closed_node_value(node: &NodeRecord) -> Value {
    json!({
        "id": node.id,
        "kind": node.kind,
        "locator": node.locator,
        "display_name": node.display_name,
    })
}

fn closed_edge_value(edge: &EdgeRecord) -> Value {
    json!({
        "id": edge.id,
        "kind": edge.kind,
        "phase": edge.phase,
        "environment": edge.environment,
        "profile_id": edge.profile_id,
        "resolution_status": edge.resolution_status,
        "precision": edge.precision,
        "condition": render_condition(&edge.condition),
        "generated": edge.generated,
    })
}

fn closed_site_value(site: &SiteRecord) -> Value {
    json!({
        "id": site.id,
        "kind": site.kind,
        "specifier": site.specifier,
        "profile_id": site.profile_id,
        "resolution_status": site.resolution_status,
        "precision": site.precision,
        "condition": render_condition(&site.condition),
        "reason": site.reason,
    })
}

fn closed_evidence_value(evidence: &EvidenceRecord) -> Value {
    json!({
        "owner_type": evidence.owner_type,
        "kind": evidence.kind,
        "extractor": evidence.extractor,
        "extractor_version": evidence.extractor_version,
        "path": evidence.path,
        "start_line": evidence.start_line,
        "start_column": evidence.start_column,
        "end_line": evidence.end_line,
        "end_column": evidence.end_column,
        "ordinal": evidence.ordinal.max(0) as u64,
    })
}

struct RowStager {
    projections: Vec<TypedProjection>,
    order_by: Vec<crate::TypedOrderItem>,
    distinct: bool,
    limit: usize,
    rows: Vec<Vec<Value>>,
}

impl RowStager {
    fn new(query: &TypedQuery) -> Self {
        Self {
            projections: query.ast.return_clause.projections.clone(),
            order_by: query.ast.order_by.clone(),
            distinct: query.ast.return_clause.distinct,
            limit: usize::try_from(query.ast.limit).unwrap_or(usize::MAX),
            rows: Vec::new(),
        }
    }

    fn insert(&mut self, row: Vec<Value>) {
        if self.distinct && self.rows.iter().any(|existing| existing == &row) {
            return;
        }
        self.rows.push(row);
        let projections = &self.projections;
        let order_by = &self.order_by;
        self.rows
            .sort_by(|left, right| row_order(left, right, projections, order_by));
        if self.rows.len() > self.limit {
            self.rows.truncate(self.limit);
        }
    }

    fn len(&self) -> usize {
        self.rows.len()
    }

    fn serialized_bytes(&self) -> u64 {
        serialized_rows_bytes(&self.rows)
    }

    fn rows(&self) -> Vec<Vec<Value>> {
        self.rows.clone()
    }
}

fn row_order(
    left: &[Value],
    right: &[Value],
    projections: &[TypedProjection],
    order_by: &[crate::TypedOrderItem],
) -> Ordering {
    if order_by.is_empty() {
        return canonical_json(&json!(left))
            .as_bytes()
            .cmp(canonical_json(&json!(right)).as_bytes());
    }
    for item in order_by {
        let Some(index) = projections
            .iter()
            .position(|projection| projection == &item.projection)
        else {
            continue;
        };
        let ordering = ordered_value(&left[index], &right[index], item.direction);
        if ordering != Ordering::Equal {
            return ordering;
        }
    }
    canonical_json(&json!(left))
        .as_bytes()
        .cmp(canonical_json(&json!(right)).as_bytes())
}

fn ordered_value(left: &Value, right: &Value, direction: SortDirection) -> Ordering {
    match (left.is_null(), right.is_null()) {
        (true, false) => return Ordering::Less,
        (false, true) => return Ordering::Greater,
        _ => {}
    }
    let ordering = match (left, right) {
        (Value::String(left), Value::String(right)) => left.as_bytes().cmp(right.as_bytes()),
        (Value::Number(left), Value::Number(right)) => left.as_u64().cmp(&right.as_u64()),
        (Value::Bool(left), Value::Bool(right)) => left.cmp(right),
        _ => canonical_json(left)
            .as_bytes()
            .cmp(canonical_json(right).as_bytes()),
    };
    match direction {
        SortDirection::Ascending => ordering,
        SortDirection::Descending => ordering.reverse(),
    }
}

fn witness_order(left: &Witness, right: &Witness) -> Ordering {
    left.edge_ids
        .cmp(&right.edge_ids)
        .then(left.node_ids.cmp(&right.node_ids))
}

fn traversed_node_id(edge: &EdgeRecord, direction: QueryDirection) -> &str {
    match direction {
        QueryDirection::Forward => &edge.target,
        QueryDirection::Reverse => &edge.source,
    }
}

fn direction_name(direction: QueryDirection) -> &'static str {
    match direction {
        QueryDirection::Forward => "forward",
        QueryDirection::Reverse => "reverse",
    }
}

fn evidence_order(left: &&EvidenceRecord, right: &&EvidenceRecord) -> Ordering {
    left.owner_type
        .cmp(&right.owner_type)
        .then(left.owner_id.cmp(&right.owner_id))
        .then(left.ordinal.cmp(&right.ordinal))
        .then(left.kind.cmp(&right.kind))
        .then(left.path.cmp(&right.path))
        .then(left.start_line.cmp(&right.start_line))
        .then(left.start_column.cmp(&right.start_column))
        .then(left.end_line.cmp(&right.end_line))
        .then(left.end_column.cmp(&right.end_column))
        .then(left.extractor.cmp(&right.extractor))
        .then(left.extractor_version.cmp(&right.extractor_version))
}

fn serialized_rows_bytes(rows: &[Vec<Value>]) -> u64 {
    u64::try_from(
        serde_json::to_vec(rows)
            .expect("bounded query rows serialization cannot fail")
            .len(),
    )
    .unwrap_or(u64::MAX)
}

fn cancellation_check(cancellation: &CancellationToken) -> BoundedQueryExecutionResult<()> {
    if cancellation.is_cancelled() {
        Err(cancelled_error())
    } else {
        Ok(())
    }
}

fn construction_guard(
    started: Instant,
    cancellation: &CancellationToken,
    deadline_milliseconds: u64,
) -> BoundedQueryExecutionResult<()> {
    cancellation_check(cancellation)?;
    if started.elapsed() >= Duration::from_millis(deadline_milliseconds) {
        Err(deadline_error(deadline_milliseconds))
    } else {
        Ok(())
    }
}

fn cancelled_error() -> BoundedQueryExecutionError {
    execution_error(
        "query_execution_cancelled",
        "bounded query execution was cancelled",
    )
}

fn deadline_error(limit: u64) -> BoundedQueryExecutionError {
    BoundedQueryExecutionError {
        code: "query_execution_deadline_exceeded",
        resource: Some("deadline_milliseconds"),
        observed: None,
        limit: Some(limit),
        message: "bounded query execution exceeded the monotonic deadline",
    }
}

fn resource_error(resource: &'static str, observed: u64, limit: u64) -> BoundedQueryExecutionError {
    BoundedQueryExecutionError {
        code: "query_execution_resource_exhausted",
        resource: Some(resource),
        observed: Some(observed),
        limit: Some(limit),
        message: "bounded query execution exhausted an admitted resource limit",
    }
}

fn execution_error(code: &'static str, message: &'static str) -> BoundedQueryExecutionError {
    BoundedQueryExecutionError {
        code,
        resource: None,
        observed: None,
        limit: None,
        message,
    }
}

fn usize_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use depgraph_store::{CoverageRecord, GraphSnapshot, ProfileMatrixRecord, ScanRecord};
    use serde_json::{Value, json};

    use super::{
        BoundedQueryExecutionOptions, bounded_query_result_digest, execute_bounded_query,
        execute_bounded_query_with_options,
    };
    use crate::{CancellationToken, parse_and_type_check_bounded_query, plan_bounded_query};

    fn node(id: &str, kind: &str) -> depgraph_store::NodeRecord {
        depgraph_store::NodeRecord {
            id: id.into(),
            kind: kind.into(),
            locator: format!("{kind}:{id}"),
            display_name: id.into(),
            properties: json!({"private": format!("property-{id}")}),
        }
    }

    fn edge(
        id: &str,
        source: &str,
        target: &str,
        site_id: Option<&str>,
    ) -> depgraph_store::EdgeRecord {
        depgraph_store::EdgeRecord {
            id: id.into(),
            site_id: site_id.map(str::to_owned),
            source: source.into(),
            target: target.into(),
            kind: "calls".into(),
            phase: "semantic".into(),
            environment: "production".into(),
            profile_id: "profile:a".into(),
            resolution_status: "resolved".into(),
            precision: "exact".into(),
            condition: json!({"all": []}),
            generated: false,
        }
    }

    fn snapshot(reverse_records: bool) -> GraphSnapshot {
        let mut nodes = vec![
            node("node:a", "route"),
            node("node:b", "module"),
            node("node:c", "module"),
            node("node:d", "service"),
            node("node:e", "service"),
        ];
        let mut edges = vec![
            edge("edge:a1", "node:a", "node:b", Some("site:a1")),
            edge("edge:a2", "node:b", "node:d", None),
            edge("edge:b1", "node:a", "node:b", Some("site:b1")),
            edge("edge:c1", "node:a", "node:c", None),
            edge("edge:c2", "node:c", "node:d", None),
            edge("edge:d1", "node:a", "node:e", None),
            edge("edge:z1", "node:b", "node:a", None),
        ];
        let mut sites = vec![
            depgraph_store::SiteRecord {
                id: "site:a1".into(),
                source: "node:a".into(),
                kind: "call".into(),
                specifier: Some("ordinary".into()),
                profile_id: "profile:a".into(),
                resolution_status: "resolved".into(),
                precision: "exact".into(),
                condition: json!({"all": []}),
                target_ids: vec!["node:b".into()],
                reason: None,
            },
            depgraph_store::SiteRecord {
                id: "site:b1".into(),
                source: "node:a".into(),
                kind: "call".into(),
                specifier: Some("special".into()),
                profile_id: "profile:a".into(),
                resolution_status: "resolved".into(),
                precision: "exact".into(),
                condition: json!({"all": []}),
                target_ids: vec!["node:b".into()],
                reason: Some("approved".into()),
            },
        ];
        let mut evidence = vec![
            depgraph_store::EvidenceRecord {
                owner_type: "edge".into(),
                owner_id: "edge:b1".into(),
                ordinal: 0,
                kind: "special".into(),
                extractor: "test".into(),
                extractor_version: "1".into(),
                path: "src/special.rs".into(),
                start_line: 1,
                start_column: 1,
                end_line: 1,
                end_column: 2,
                detail: Some("private edge detail".into()),
                properties: json!({"private": "edge"}),
            },
            depgraph_store::EvidenceRecord {
                owner_type: "site".into(),
                owner_id: "site:b1".into(),
                ordinal: 0,
                kind: "site-special".into(),
                extractor: "test".into(),
                extractor_version: "1".into(),
                path: "src/site.rs".into(),
                start_line: 2,
                start_column: 1,
                end_line: 2,
                end_column: 2,
                detail: Some("private site detail".into()),
                properties: json!({"private": "site"}),
            },
        ];
        if reverse_records {
            nodes.reverse();
            edges.reverse();
            sites.reverse();
            evidence.reverse();
        }
        GraphSnapshot {
            scan: ScanRecord {
                id: "scan:test".into(),
                root: if reverse_records {
                    "/other/checkout".into()
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

    fn execute(
        query: &str,
        selected: &GraphSnapshot,
    ) -> super::BoundedQueryExecutionResult<super::BoundedQueryResult> {
        let typed = parse_and_type_check_bounded_query(query).unwrap();
        let plan = plan_bounded_query(&typed, "snapshot:stable", selected).unwrap();
        assert!(plan.admitted, "{:?}", plan.reasons);
        execute_bounded_query(&typed, &plan, selected, &CancellationToken::new())
    }

    fn path_edge_ids(result: &super::BoundedQueryResult) -> Vec<String> {
        result.rows[0][0]["edges"]
            .as_array()
            .unwrap()
            .iter()
            .map(|edge| edge["id"].as_str().unwrap().to_owned())
            .collect()
    }

    #[test]
    fn forward_and_reverse_bfs_choose_one_canonical_shortest_witness() {
        let selected = snapshot(false);
        let forward = execute(
            r#"MATCH p = (source:"route")-["calls"*1..4]->(target:"service") WHERE target.id = "node:d" RETURN p LIMIT 10"#,
            &selected,
        )
        .unwrap();
        assert_eq!(forward.rows.len(), 1);
        assert_eq!(path_edge_ids(&forward), ["edge:a1", "edge:a2"]);
        assert_eq!(forward.rows[0][0]["direction"], "forward");

        let reverse = execute(
            r#"MATCH p = (source:"service")<-["calls"*1..4]-(target:"route") WHERE source.id = "node:d" RETURN p LIMIT 10"#,
            &selected,
        )
        .unwrap();
        assert_eq!(reverse.rows.len(), 1);
        assert_eq!(path_edge_ids(&reverse), ["edge:a2", "edge:a1"]);
        assert_eq!(reverse.rows[0][0]["direction"], "reverse");
    }

    #[test]
    fn existential_bits_and_used_edge_sets_preserve_later_valid_paths() {
        let result = execute(
            r#"MATCH p = (source:"route")-["calls"*1..3]->(target:"service")
               WHERE target.id = "node:d"
                 AND SOME evidence IN EVIDENCE(p) SATISFIES evidence.kind = "special"
               RETURN p LIMIT 10"#,
            &snapshot(false),
        )
        .unwrap();
        assert_eq!(path_edge_ids(&result), ["edge:b1", "edge:a2"]);
        assert!(result.metrics.traversal_states > 5);

        let site = execute(
            r#"MATCH p = (source:"route")-["calls"*1..3]->(target:"service")
               WHERE target.id = "node:d"
                 AND SOME site IN SITES(p) SATISFIES site.reason = "approved"
               RETURN p LIMIT 10"#,
            &snapshot(false),
        )
        .unwrap();
        assert_eq!(path_edge_ids(&site), ["edge:b1", "edge:a2"]);
    }

    #[test]
    fn every_edge_cycle_and_alternate_paths_remain_bounded_and_canonical() {
        let result = execute(
            r#"MATCH p = (source:"route")-["calls"*1..4]->(target:"service")
               WHERE EVERY edge IN EDGES(p) SATISFIES edge.phase = "semantic"
                 AND p.depth >= 1
               RETURN p LIMIT 10"#,
            &snapshot(false),
        )
        .unwrap();
        assert_eq!(result.rows.len(), 2);
        let rendered = serde_json::to_string(&result.rows).unwrap();
        assert!(!rendered.contains("private edge detail"));
        assert!(!rendered.contains("\"properties\""));
        assert!(result.metrics.edge_tests <= 200_000);
        assert!(result.metrics.traversal_states <= 50_000);
    }

    #[test]
    fn result_order_distinct_limit_and_work_are_deterministic() {
        let selected = snapshot(false);
        let descending = execute(
            r#"MATCH p = (source:"route")-["calls"*1..3]->(target:"service")
               RETURN target.id ORDER BY target.id DESC LIMIT 1"#,
            &selected,
        )
        .unwrap();
        assert_eq!(descending.rows, vec![vec![json!("node:e")]]);

        let distinct = execute(
            r#"MATCH p = (source:"route")-["calls"*1..3]->(target:"service")
               RETURN DISTINCT target.kind LIMIT 10"#,
            &selected,
        )
        .unwrap();
        assert_eq!(distinct.rows, vec![vec![json!("service")]]);

        let small = execute(
            r#"MATCH p = (source:"route")-["calls"*1..3]->(target:"service")
               RETURN target.id LIMIT 1"#,
            &selected,
        )
        .unwrap();
        let large = execute(
            r#"MATCH p = (source:"route")-["calls"*1..3]->(target:"service")
               RETURN target.id LIMIT 10"#,
            &selected,
        )
        .unwrap();
        assert_eq!(small.metrics.edge_tests, large.metrics.edge_tests);
        assert_eq!(
            small.metrics.traversal_states,
            large.metrics.traversal_states
        );
    }

    #[test]
    fn source_only_predicates_filter_before_traversal() {
        let result = execute(
            r#"MATCH p = (source)-["calls"*1..3]->(target:"service")
               WHERE source.locator STARTS WITH "missing:"
               RETURN target.id LIMIT 10"#,
            &snapshot(false),
        )
        .unwrap();
        assert!(result.rows.is_empty());
        assert_eq!(result.metrics.source_node_tests, 5);
        assert_eq!(result.metrics.traversal_states, 0);
        assert_eq!(result.metrics.edge_tests, 0);
    }

    #[test]
    fn result_and_path_digest_ignore_snapshot_record_and_checkout_order() {
        let query = r#"MATCH p = (source:"route")-["calls"*1..3]->(target:"service")
                       WHERE target.id = "node:d" RETURN p LIMIT 10"#;
        let first = execute(query, &snapshot(false)).unwrap();
        let second = execute(query, &snapshot(true)).unwrap();
        assert_eq!(first.rows, second.rows);
        assert_eq!(first.plan_digest, second.plan_digest);
        assert_eq!(first.result_digest, second.result_digest);
        assert_eq!(first.result_digest, bounded_query_result_digest(&first));
        assert_eq!(first.rows[0][0]["id"], second.rows[0][0]["id"]);
    }

    #[test]
    fn cancellation_deadline_and_resource_caps_return_no_partial_result() {
        let selected = snapshot(false);
        let query = parse_and_type_check_bounded_query(
            r#"MATCH p = (source:"route")-["calls"*1..4]->(target:"service") RETURN p LIMIT 10"#,
        )
        .unwrap();
        let plan = plan_bounded_query(&query, "snapshot:stable", &selected).unwrap();
        assert!(plan.admitted);

        let cancelled = CancellationToken::new();
        cancelled.cancel();
        assert_eq!(
            execute_bounded_query(&query, &plan, &selected, &cancelled)
                .unwrap_err()
                .code,
            "query_execution_cancelled"
        );

        for (resource, lower) in [
            ("deadline_milliseconds", 0_u64),
            ("traversal_states", 0),
            ("edge_tests", 0),
            ("result_rows", 0),
            ("serialized_output_bytes", 1),
            ("working_memory_bytes", 0),
        ] {
            let mut options = BoundedQueryExecutionOptions::default();
            match resource {
                "deadline_milliseconds" => {
                    options.limits.deadline_milliseconds = lower;
                }
                "traversal_states" => {
                    options.limits.traversal_states = lower;
                }
                "edge_tests" => options.limits.edge_tests = lower,
                "result_rows" => options.limits.result_rows = lower,
                "serialized_output_bytes" => {
                    options.limits.serialized_output_bytes = lower;
                }
                "working_memory_bytes" => {
                    options.limits.working_memory_bytes = lower;
                }
                _ => unreachable!(),
            }
            let error = execute_bounded_query_with_options(
                &query,
                &plan,
                &selected,
                &CancellationToken::new(),
                options,
            )
            .unwrap_err();
            if resource == "deadline_milliseconds" {
                assert_eq!(error.code, "query_execution_deadline_exceeded");
            } else {
                assert_eq!(error.code, "query_execution_resource_exhausted");
                assert_eq!(error.resource, Some(resource));
            }
        }
    }

    #[test]
    fn tampered_plan_query_or_snapshot_is_rejected_before_rows_exist() {
        let selected = snapshot(false);
        let query = parse_and_type_check_bounded_query(
            r#"MATCH p = (source:"route")-["calls"*1..2]->(target:"service") RETURN p LIMIT 10"#,
        )
        .unwrap();
        let plan = plan_bounded_query(&query, "snapshot:stable", &selected).unwrap();

        let mut tampered_plan = plan.clone();
        tampered_plan.snapshot_id = "snapshot:other".into();
        assert_eq!(
            execute_bounded_query(&query, &tampered_plan, &selected, &CancellationToken::new(),)
                .unwrap_err()
                .code,
            "query_execution_contract_mismatch"
        );

        let mut tampered_snapshot = selected.clone();
        tampered_snapshot.edges[0].phase = "runtime".into();
        assert_eq!(
            execute_bounded_query(&query, &plan, &tampered_snapshot, &CancellationToken::new(),)
                .unwrap_err()
                .code,
            "query_execution_snapshot_mismatch"
        );

        let mut duplicate_snapshot = selected.clone();
        duplicate_snapshot.nodes.push(selected.nodes[0].clone());
        let duplicate_plan =
            plan_bounded_query(&query, "snapshot:duplicate", &duplicate_snapshot).unwrap();
        assert_eq!(
            execute_bounded_query(
                &query,
                &duplicate_plan,
                &duplicate_snapshot,
                &CancellationToken::new(),
            )
            .unwrap_err()
            .code,
            "query_execution_snapshot_mismatch"
        );

        let mut tampered_query = query.clone();
        tampered_query.ast.limit = 1;
        assert_eq!(
            execute_bounded_query(&tampered_query, &plan, &selected, &CancellationToken::new(),)
                .unwrap_err()
                .code,
            "query_execution_contract_mismatch"
        );
    }

    #[test]
    fn explicit_null_first_order_is_stable() {
        let rows = vec![
            vec![Value::String("z".into())],
            vec![Value::Null],
            vec![Value::String("a".into())],
        ];
        let projections = vec![crate::TypedProjection::Field(crate::TypedFieldReference {
            binding: "target".into(),
            entity_type: crate::EntityType::Node,
            field: "id".into(),
            scalar_type: crate::ScalarType::String,
            nullable: false,
        })];
        let order = vec![crate::TypedOrderItem {
            projection: projections[0].clone(),
            direction: crate::SortDirection::Descending,
        }];
        let mut sorted = rows;
        sorted.sort_by(|left, right| super::row_order(left, right, &projections, &order));
        assert_eq!(sorted[0][0], Value::Null);
        assert_eq!(sorted[1][0], json!("z"));
    }

    #[test]
    fn generated_parser_type_planner_executor_corpus_is_total_and_deterministic() {
        fn exercise(query: &str, selected: &GraphSnapshot) -> String {
            let typed = match parse_and_type_check_bounded_query(query) {
                Ok(typed) => typed,
                Err(error) => {
                    return format!("diagnostic:{}:{:?}", error.code, error.class);
                }
            };
            let plan = match plan_bounded_query(&typed, "snapshot:fuzz", selected) {
                Ok(plan) => plan,
                Err(error) => return format!("planning-error:{}:{}", error.code, error),
            };
            if !plan.admitted {
                return crate::canonical_bounded_query_plan_json(&plan);
            }
            match execute_bounded_query(&typed, &plan, selected, &CancellationToken::new()) {
                Ok(result) => depgraph_protocol::canonical_json(
                    &serde_json::to_value(result).expect("result serializes"),
                ),
                Err(error) => format!("execution-error:{}:{error}", error.code),
            }
        }

        let selected = snapshot(false);
        let seed = br#"MATCH p = (source:"route")-["calls"*1..4]->(target:"service")
WHERE source.id = "node:a"
  AND EVERY edge IN EDGES(p) SATISFIES edge.phase = "semantic"
  AND SOME evidence IN EVIDENCE(p) SATISFIES evidence.path STARTS WITH "src/"
RETURN DISTINCT source.id, target.id, p
ORDER BY source.id, target.id, p ASC
LIMIT 10"#;
        let mut state = 0xd1b5_4a32_d192_ed03_u64;
        for case in 0..1_024_usize {
            let mut input = seed.to_vec();
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let index = (state as usize) % input.len();
            match case % 4 {
                0 => input[index] = state as u8,
                1 => {
                    input.insert(index, state as u8);
                }
                2 => {
                    input.remove(index);
                }
                _ => {
                    let end = (index + (state as usize % 31)).min(input.len());
                    input.drain(index..end);
                }
            }
            let query = String::from_utf8_lossy(&input).into_owned();
            let first = std::panic::catch_unwind(|| exercise(&query, &selected))
                .expect("bounded query pipeline must not panic on generated input");
            let second = std::panic::catch_unwind(|| exercise(&query, &selected))
                .expect("bounded query pipeline must remain total on replay");
            assert_eq!(first, second, "generated corpus case {case}");
        }
    }

    #[test]
    fn ten_thousand_node_hostile_graph_is_admitted_or_rejected_before_any_partial_result() {
        let node_count = 10_001_usize;
        let mut selected = snapshot(false);
        selected.nodes = (0..node_count)
            .map(|index| node(&format!("node:{index:05}"), "file"))
            .collect();
        selected.sites.clear();
        selected.evidence.clear();
        selected.edges = (0..node_count - 1)
            .map(|index| {
                let mut record = edge(
                    &format!("edge:{index:05}"),
                    &format!("node:{index:05}"),
                    &format!("node:{:05}", index + 1),
                    None,
                );
                record.kind = "imports".to_owned();
                record
            })
            .collect();

        let hostile = parse_and_type_check_bounded_query(
            r#"MATCH p = (source:"file")-["imports"*1..8]->(target:"file")
               RETURN target.id LIMIT 1"#,
        )
        .unwrap();
        let rejected = plan_bounded_query(&hostile, "snapshot:hostile-10000", &selected).unwrap();
        assert!(!rejected.admitted);
        assert!(rejected.reasons.iter().any(|reason| {
            matches!(
                reason.resource.as_str(),
                "traversal_states" | "edge_tests" | "deterministic_cost"
            )
        }));
        let error =
            execute_bounded_query(&hostile, &rejected, &selected, &CancellationToken::new())
                .unwrap_err();
        assert!(matches!(
            error.code,
            "query_plan_not_admitted" | "query_execution_resource_exhausted"
        ));

        let bounded = parse_and_type_check_bounded_query(
            r#"MATCH p = (source:"file")-["__depgraph_test_missing_v1__"*1..1]->(target:"file")
               WHERE source.id = "node:00000"
               RETURN source.id, target.id, p.id
               ORDER BY source.id, target.id, p.id ASC
               LIMIT 1"#,
        )
        .unwrap();
        let plan = plan_bounded_query(&bounded, "snapshot:hostile-10000", &selected).unwrap();
        assert!(plan.admitted, "{:?}", plan.reasons);
        let first =
            execute_bounded_query(&bounded, &plan, &selected, &CancellationToken::new()).unwrap();
        let second =
            execute_bounded_query(&bounded, &plan, &selected, &CancellationToken::new()).unwrap();
        assert!(first.rows.is_empty());
        assert_eq!(first.rows, second.rows);
        assert_eq!(first.result_digest, second.result_digest);
        assert!(first.metrics.edge_tests <= plan.limits.edge_tests);
        assert!(first.metrics.traversal_states <= plan.limits.traversal_states);
    }
}
