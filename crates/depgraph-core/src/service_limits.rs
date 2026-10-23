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

/// Maximum snapshot-wide work of one cycle or unresolved listing: indexing
/// every node, edge, evidence record, site, and profile correlation, the
/// strongly connected component search over every edge of the level, and the
/// materialization of every matching item. The path steps of dependency listing, path explanation,
/// and impact count their scans of every evidence record, profile
/// correlation, and profile entry against it too (Issue #620). So do the
/// snapshot-wide steps of impact: its preflight over every node, site, edge,
/// and evidence record, the edge adjacency of each direction, and the runtime
/// context index.
///
/// Each snapshot record is visited a bounded number of times, so this work
/// grows with the snapshot rather than with the request, and the ceiling is
/// the one hotspot analysis uses for its whole-snapshot work
/// ([`MAX_HOTSPOT_PREPROCESSING_WORK_ITEMS`]). Request `max_traversal` bounds only what the request returns: the edge visits
/// that build the returned representative cycles and the unresolved sites of
/// one page. Counting the whole
/// snapshot against `max_traversal` (default 50,000) made both listings fail
/// on a snapshot of about 250 files (Issues #617 / #618). A generated snapshot
/// of that shape (23,500 sites, 6,750 of them unresolved, 30,000 edges,
/// 53,500 evidence records, 25,251 nodes) uses 187,751 items for unresolved
/// listing and 57,301 for file-level cycles. The path-step scans of a Rust HIR
/// snapshot of depgraph-cli itself (795,912 evidence records, 120,263
/// correlations with 209,051 edge IDs, 89 profile entries) use 1,245,578.
pub const MAX_GRAPH_SNAPSHOT_SCAN_WORK_ITEMS: usize = 16_000_000;

/// Maximum findings in one health response or one analyzed range. Summary
/// counts may span more ranges without retaining all of their finding bodies.
pub const MAX_HEALTH_FINDINGS: usize = 10_000;

/// Maximum health execution ranges (planned plus re-split halves) for one
/// snapshot-scoped request. Each range and each phase is bounded by
/// [`MAX_GRAPH_SERVICE_PREPROCESSING_WORK_ITEMS`]; this caps the total.
pub const MAX_HEALTH_RANGES: u32 = 256;

/// Maximum rows the health range planner may read (aggregates and sorted
/// index scans only) before failing closed.
pub const MAX_HEALTH_PLANNER_ROWS: u64 = 4 * MAX_GRAPH_SERVICE_PREPROCESSING_WORK_ITEMS as u64;

/// Maximum times one health range that overran its estimate is split in half.
pub const MAX_HEALTH_RANGE_RESPLIT_DEPTH: u8 = 4;

/// Upper bound of one health range checkpoint file.
pub const MAX_HEALTH_RANGE_CHECKPOINT_BYTES: usize = 64 * 1024 * 1024;

/// Maximum blockers retained on one health finding.
pub const MAX_HEALTH_BLOCKERS_PER_FINDING: usize = 32;

/// Maximum evidence references retained on one health finding.
pub const MAX_HEALTH_EVIDENCE_PER_FINDING: usize = 64;

/// Maximum remediations retained on one health finding.
pub const MAX_HEALTH_REMEDIATIONS_PER_FINDING: usize = 8;

/// Maximum suppressions retained on one health finding.
pub const MAX_HEALTH_SUPPRESSIONS_PER_FINDING: usize = 8;

/// Maximum values accepted by one health request filter.
pub const MAX_HEALTH_FILTER_ITEMS: usize = 1_024;

/// Maximum hotspot subjects scored together in one request, which also bounds
/// the findings one hotspot response returns.
///
/// Hotspot layers are rank-normalized over every subject, so subjects cannot be
/// split into pages or ranges the way other health findings are, and a Rust HIR
/// snapshot records parameters, locals, and closures as subjects. This is
/// therefore separate from [`MAX_HEALTH_FINDINGS`]: the HIR snapshot of
/// depgraph-cli itself had 69,900 subjects (Issue #590).
pub const MAX_HOTSPOT_SUBJECTS: usize = 250_000;

/// Maximum hotspot analysis work: subject discovery, the interned edge view,
/// batched reverse impact, and finding construction.
///
/// The work grows with nodes plus edges and with the reverse closures of the
/// subjects, so a fixed graph-service budget does not scale with HIR
/// snapshots. The HIR snapshot of depgraph-cli itself (212,915 nodes, 245,923
/// edges) used 3,561,396 items, 2,892,858 of them for reverse impact, and
/// about 1.3 seconds (Issue #590).
pub const MAX_HOTSPOT_PREPROCESSING_WORK_ITEMS: usize = 16_000_000;

/// Longest accepted hotspot path (churn filter or result prefix), in bytes.
pub const MAX_HOTSPOT_PATH_BYTES: usize = 512;

/// Maximum Git commits admitted into one hotspot churn window.
pub const MAX_HEALTH_CHURN_COMMITS: u32 = 512;

/// Maximum bytes read from one live manifest fallback.
pub const MAX_HEALTH_MANIFEST_BYTES: usize = 1024 * 1024;

/// Maximum live manifests read for one snapshot-scoped health request.
pub const MAX_HEALTH_MANIFESTS: usize = 1_024;

/// Maximum aggregate manifest bytes retained by one health request.
pub const MAX_HEALTH_TOTAL_MANIFEST_BYTES: usize = 16 * 1024 * 1024;
