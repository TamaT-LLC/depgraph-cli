/// Maximum number of dependency edges that may be represented in one returned path.
pub const MAX_DEPENDENCY_PATH_STEPS: usize = 1_000;

/// Maximum number of node identifiers in a returned closed cycle, including the closing ID.
pub const MAX_CYCLE_NODE_IDS: usize = 1_000;

/// Maximum number of public evidence records materialized for one graph edge or site.
pub const MAX_GRAPH_EVIDENCE_ITEMS: usize = 64;

/// Maximum number of correlation difference reasons materialized for one unresolved site.
pub const MAX_UNRESOLVED_CORRELATION_REASONS: usize = 16;

/// Maximum number of distinct dependency phases retained for one unresolved site.
pub const MAX_UNRESOLVED_PHASES: usize = 4;

/// Maximum number of phase-coverage entries materialized for one public graph path step.
///
/// This is deliberately independent of the cumulative preprocessing budget: a single malformed
/// profile entry must not be able to consume an entire request budget before failing closed.
pub const MAX_GRAPH_PHASE_COVERAGE_ITEMS: usize = 64;

/// Maximum number of retained [`crate::query::PathStep`] values across one impact response.
///
/// This independently bounds the quadratic sum of path prefixes in wide/deep reverse graphs,
/// even when the graph itself remains within the node and edge traversal limits.
pub const MAX_IMPACT_MATERIALIZED_PATH_STEPS: usize = 50_000;

/// Maximum preprocessing/materialization work retained by one graph-service operation.
///
/// Request `max_nodes` and `max_edges` remain traversal-result limits; preprocessing over the
/// immutable snapshot uses this separate fixed service ceiling so unrelated records cannot change
/// their meaning.
pub const MAX_GRAPH_SERVICE_PREPROCESSING_WORK_ITEMS: usize =
    crate::query::MAX_INTERACTIVE_QUERY_TRAVERSAL;
