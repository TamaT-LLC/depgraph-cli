use std::{collections::BTreeSet, fmt::Write as _};

use depgraph_core::service::{
    MAX_GRAPH_EXPORT_EDGES, MAX_GRAPH_EXPORT_NODES, MAX_HEALTH_FILTER_ITEMS, MAX_HOTSPOT_PATH_BYTES,
};
use depgraph_core::{
    DEFAULT_STRUCTURAL_EDGE_SELECTION, DepgraphCapability, DepgraphCapabilitySet,
    HOTSPOT_SUBJECT_KINDS, MAX_DEPENDENCY_EDGE_KINDS, StructuralEdgeSelection,
};
use schemars::{JsonSchema, SchemaGenerator, generate::SchemaSettings};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use crate::{
    AgentCompletedSnapshot, AgentContext, AgentCycle, AgentCycleLevel, AgentDaemonStatus,
    AgentDependenciesOutput, AgentDoctor, AgentEdgeDetail, AgentEdgesOutput, AgentEvidence,
    AgentGraphExportResponse, AgentHealthAudit, AgentHealthFindingDetail, AgentHealthFindingsPage,
    AgentHealthHotspots, AgentHealthSummary, AgentId, AgentImpactResponse, AgentLabel,
    AgentLocator, AgentNamedSnapshot, AgentNode, AgentNodeSummary, AgentOperation,
    AgentPathResponse, AgentPolicyEvaluationResponse, AgentProfilePlan, AgentQueryRow,
    AgentRepositoryInitOutcome, AgentRepositoryList, AgentRuntimeValidationResponse, AgentSite,
    AgentSnapshotDiffResponse, AgentToken, AgentUnresolved, Cursor, ErrorEnvelope, IdempotencyKey,
    LogicalRepositoryId, MCP_TOOLS_CONTRACT_VERSION, OperationId, Page, PortableTerminalOutput,
    RepositoryRelativePath, SnapshotId, SnapshotName, SuccessEnvelope,
};

#[allow(dead_code)]
#[derive(JsonSchema)]
#[serde(untagged)]
enum ExactToolOutput<T> {
    Success(SuccessEnvelope<T>),
    Error(ErrorEnvelope),
}

#[allow(dead_code)]
#[derive(JsonSchema)]
#[serde(untagged)]
enum ExactOperationResultOutput {
    Success(Box<PortableTerminalOutput>),
    Error(ErrorEnvelope),
}

macro_rules! define_cli_actions {
    ($($variant:ident => $stable_id:literal),+ $(,)?) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
        #[repr(usize)]
        pub enum CliAction {
            $($variant),+
        }

        impl CliAction {
            #[must_use]
            pub const fn stable_id(self) -> &'static str {
                match self {
                    $(Self::$variant => $stable_id),+
                }
            }
        }

        pub const ALL_CLI_ACTIONS: &[CliAction] = &[$(CliAction::$variant),+];
        const CLI_ACTION_COUNT: usize = ALL_CLI_ACTIONS.len();
    };
}

define_cli_actions! {
    Init => "init",
    Scan => "scan",
    ProfilesPlan => "profiles_plan",
    DaemonStart => "daemon_start",
    DaemonStatus => "daemon_status",
    DaemonStop => "daemon_stop",
    ResolveBuild => "resolve_build",
    Doctor => "doctor",
    Deps => "deps",
    Dependents => "dependents",
    Why => "why",
    Impact => "impact",
    Cycles => "cycles",
    Unresolved => "unresolved",
    Query => "query",
    RuntimeValidate => "runtime_validate",
    RuntimeImport => "runtime_import",
    SnapshotCreate => "snapshot_create",
    SnapshotList => "snapshot_list",
    SnapshotShow => "snapshot_show",
    Diff => "diff",
    Policy => "policy",
    Export => "export",
    HealthSummary => "health_summary",
    HealthFindings => "health_findings",
    HealthFindingGet => "health_finding_get",
    Audit => "audit",
    Hotspots => "hotspots",
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapabilityProfile {
    Read,
    StoreWrite,
    RepositoryWrite,
    DaemonControl,
    ProjectExec,
}

impl CapabilityProfile {
    #[must_use]
    pub const fn required_capabilities(self) -> &'static [DepgraphCapability] {
        match self {
            Self::Read => &[DepgraphCapability::Read],
            Self::StoreWrite => &[DepgraphCapability::Read, DepgraphCapability::StoreWrite],
            Self::RepositoryWrite => &[
                DepgraphCapability::Read,
                DepgraphCapability::RepositoryWrite,
            ],
            Self::DaemonControl => &[
                DepgraphCapability::Read,
                DepgraphCapability::StoreWrite,
                DepgraphCapability::DaemonControl,
            ],
            Self::ProjectExec => &[
                DepgraphCapability::Read,
                DepgraphCapability::StoreWrite,
                DepgraphCapability::ProjectExec,
            ],
        }
    }

    pub fn capabilities(self) -> Result<DepgraphCapabilitySet, String> {
        DepgraphCapabilitySet::try_new(self.required_capabilities().iter().copied())
            .map_err(|error| error.to_string())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolAuthorization {
    FixedCapabilities,
    OperationRequiredCapabilities,
}

impl ToolAuthorization {
    const fn as_str(self) -> &'static str {
        match self {
            Self::FixedCapabilities => "fixed_capabilities",
            Self::OperationRequiredCapabilities => "operation_required_capabilities",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationBehavior {
    Immediate,
    MayCreateDurableOperation,
    AlwaysCreatesDurableOperation,
}

impl OperationBehavior {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Immediate => "immediate",
            Self::MayCreateDurableOperation => "may_create_durable_operation",
            Self::AlwaysCreatesDurableOperation => "always_creates_durable_operation",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ToolDefinition {
    name: &'static str,
    description: &'static str,
    input_schema: Map<String, Value>,
    output_schema: Map<String, Value>,
    cli_actions: &'static [CliAction],
    required_capabilities: &'static [DepgraphCapability],
    authorization: ToolAuthorization,
    operation_behavior: OperationBehavior,
}

impl ToolDefinition {
    #[must_use]
    pub const fn name(&self) -> &'static str {
        self.name
    }

    #[must_use]
    pub const fn description(&self) -> &'static str {
        self.description
    }

    #[must_use]
    pub fn input_schema(&self) -> &Map<String, Value> {
        &self.input_schema
    }

    #[must_use]
    pub fn output_schema(&self) -> &Map<String, Value> {
        &self.output_schema
    }

    #[must_use]
    pub const fn cli_actions(&self) -> &'static [CliAction] {
        self.cli_actions
    }

    #[must_use]
    pub const fn required_capabilities(&self) -> &'static [DepgraphCapability] {
        self.required_capabilities
    }

    #[must_use]
    pub const fn authorization(&self) -> ToolAuthorization {
        self.authorization
    }

    #[must_use]
    pub const fn operation_behavior(&self) -> OperationBehavior {
        self.operation_behavior
    }
}

#[derive(Debug, Clone)]
pub struct ToolCatalog {
    tools: Vec<ToolDefinition>,
    canonical_bytes: Vec<u8>,
    sha256: String,
}

impl ToolCatalog {
    pub fn for_capabilities(capabilities: &DepgraphCapabilitySet) -> Result<Self, String> {
        let mut names = BTreeSet::new();
        let mut tools = TOOL_SPECS
            .iter()
            .filter(|spec| capabilities.contains_all(spec.required_capabilities))
            .map(|spec| {
                if !names.insert(spec.name) {
                    return Err(format!("duplicate static MCP tool name: {}", spec.name));
                }
                Ok(ToolDefinition {
                    name: spec.name,
                    description: spec.description,
                    input_schema: input_schema(spec),
                    output_schema: output_schema(spec),
                    cli_actions: spec.cli_actions,
                    required_capabilities: spec.required_capabilities,
                    authorization: spec.authorization,
                    operation_behavior: spec.operation_behavior,
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        tools.sort_unstable_by_key(|tool| tool.name);
        let canonical_bytes = canonical_catalog_bytes(&tools)?;
        let digest = Sha256::digest(&canonical_bytes);
        let mut sha256 = String::with_capacity(digest.len() * 2);
        for byte in digest {
            write!(&mut sha256, "{byte:02x}").expect("writing to String cannot fail");
        }
        Ok(Self {
            tools,
            canonical_bytes,
            sha256,
        })
    }

    #[must_use]
    pub fn tools(&self) -> &[ToolDefinition] {
        &self.tools
    }

    #[must_use]
    pub fn tool(&self, name: &str) -> Option<&ToolDefinition> {
        self.tools
            .binary_search_by_key(&name, |tool| tool.name)
            .ok()
            .map(|index| &self.tools[index])
    }

    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    #[must_use]
    pub fn sha256(&self) -> &str {
        &self.sha256
    }
}

#[derive(Debug, Clone, Copy)]
struct ToolSpec {
    name: &'static str,
    description: &'static str,
    input_fields: &'static [&'static str],
    cli_actions: &'static [CliAction],
    required_capabilities: &'static [DepgraphCapability],
    authorization: ToolAuthorization,
    operation_behavior: OperationBehavior,
}

const READ: &[DepgraphCapability] = &[DepgraphCapability::Read];
const STORE_WRITE: &[DepgraphCapability] =
    &[DepgraphCapability::Read, DepgraphCapability::StoreWrite];
const REPOSITORY_WRITE: &[DepgraphCapability] = &[
    DepgraphCapability::Read,
    DepgraphCapability::RepositoryWrite,
];
const DAEMON_CONTROL: &[DepgraphCapability] = &[
    DepgraphCapability::Read,
    DepgraphCapability::StoreWrite,
    DepgraphCapability::DaemonControl,
];
const PROJECT_EXEC: &[DepgraphCapability] = &[
    DepgraphCapability::Read,
    DepgraphCapability::StoreWrite,
    DepgraphCapability::ProjectExec,
];

macro_rules! tool_spec {
    ($name:literal, $description:literal, [$($field:literal),* $(,)?], [$($action:expr),* $(,)?], $capabilities:expr, $authorization:expr, $operation:expr) => {
        ToolSpec {
            name: $name,
            description: $description,
            input_fields: &[$($field),*],
            cli_actions: &[$($action),*],
            required_capabilities: $capabilities,
            authorization: $authorization,
            operation_behavior: $operation,
        }
    };
}

const TOOL_SPECS: &[ToolSpec] = &[
    tool_spec!(
        "get_context",
        "Get logical repository identity, enabled capabilities, and current snapshot context. repository_id is optional on every tool and defaults to the repository this server is bound to; the returned repository_id, repository_list, and INVALID_ARGUMENT error.details.available_repository_ids all report the valid value.",
        [],
        [],
        READ,
        ToolAuthorization::FixedCapabilities,
        OperationBehavior::Immediate
    ),
    tool_spec!(
        "repository_list",
        "List the logical repositories this server can address, each with its latest completed snapshot summary. Use the returned repository_id for other tools, or omit repository_id to use the server's default (bound) repository. Host-private root and Store paths are never returned.",
        [],
        [],
        READ,
        ToolAuthorization::FixedCapabilities,
        OperationBehavior::Immediate
    ),
    tool_spec!(
        "agent_node_get",
        "Get one graph node using the frozen agent node contract.",
        ["node_id", "snapshot"],
        [],
        READ,
        ToolAuthorization::FixedCapabilities,
        OperationBehavior::Immediate
    ),
    tool_spec!(
        "agent_nodes_list",
        "List graph nodes using bounded text and kind filters.",
        [
            "query",
            "match_mode",
            "snapshot",
            "kinds",
            "cursor",
            "limit"
        ],
        [],
        READ,
        ToolAuthorization::FixedCapabilities,
        OperationBehavior::Immediate
    ),
    tool_spec!(
        "agent_sites_list",
        "List bounded dependency sites using the frozen agent site contract. node_id keeps the sites whose source is that node. site_id keeps only that one site (an empty page when the ID is unknown), so the site_id of an edge from agent_edges_list or a dependency list resolves to its specifier, resolution and evidence, including the import specifier and binding when recorded, in one call. Both filters may be combined.",
        ["snapshot", "node_id", "site_id", "cursor", "limit"],
        [],
        READ,
        ToolAuthorization::FixedCapabilities,
        OperationBehavior::Immediate
    ),
    tool_spec!(
        "agent_edges_list",
        "List bounded dependency edges incident to one node using the frozen agent edge contract. Complete edges carry their evidence, including the import specifier and binding when recorded, and are often 0.5 to 1 KB each, so one page of a hub file can exceed an Agent host's result limit. Use detail=summary to drop evidence bodies and state fields shared by the page once (each edge keeps site_id and evidence_count), edge_kinds to keep only some kinds such as imports, and a smaller limit with the returned next_cursor to page. Every edge kind, structural edges (contains, declares, generated_from) included, is listed unless edge_kinds is given. For a file-level view with unique source/target repository paths, call graph_dependencies_list or graph_dependents_list with selector id:<node_id> and detail=paths.",
        [
            "snapshot",
            "node_id",
            "direction",
            "edge_kinds",
            "detail",
            "cursor",
            "limit"
        ],
        [],
        READ,
        ToolAuthorization::FixedCapabilities,
        OperationBehavior::Immediate
    ),
    tool_spec!(
        "agent_evidence_list",
        "List bounded evidence records using the frozen agent evidence contract.",
        ["snapshot", "site_id", "cursor", "limit"],
        [],
        READ,
        ToolAuthorization::FixedCapabilities,
        OperationBehavior::Immediate
    ),
    tool_spec!(
        "snapshot_list",
        "List immutable completed snapshots with bounded pagination.",
        ["cursor", "limit"],
        [CliAction::SnapshotList],
        READ,
        ToolAuthorization::FixedCapabilities,
        OperationBehavior::Immediate
    ),
    tool_spec!(
        "snapshot_get",
        "Show one immutable completed snapshot and its provenance.",
        ["snapshot"],
        [CliAction::SnapshotShow],
        READ,
        ToolAuthorization::FixedCapabilities,
        OperationBehavior::Immediate
    ),
    tool_spec!(
        "profile_plan_get",
        "Plan repository analysis profiles without mutating the store.",
        ["profile_budget", "profiles_document", "profiles_file"],
        [CliAction::ProfilesPlan],
        READ,
        ToolAuthorization::FixedCapabilities,
        OperationBehavior::Immediate
    ),
    tool_spec!(
        "daemon_get",
        "Read the repository daemon lifecycle status.",
        [],
        [CliAction::DaemonStatus],
        READ,
        ToolAuthorization::FixedCapabilities,
        OperationBehavior::Immediate
    ),
    tool_spec!(
        "doctor_get",
        "Run bounded repository and store health diagnostics.",
        ["details"],
        [CliAction::Doctor],
        READ,
        ToolAuthorization::FixedCapabilities,
        OperationBehavior::Immediate
    ),
    tool_spec!(
        "graph_dependencies_list",
        "Traverse outgoing dependency edges from one selector. Use detail to shrink the response: paths returns only unique source/target paths and edge kinds, summary drops evidence and states shared edge fields once in common, full (default) returns every edge with its evidence in the previous shape, without import facts. Evidence of one edge, including its import specifier and binding, is available individually through agent_sites_list and agent_evidence_list with the edge's site_id. Structural edges (contains: a package contains a file, declares: a file declares a symbol, generated_from: a generated file comes from its source) describe graph organization rather than a dependency and are excluded by default, so the result counts only dependent or dependency edges; pass structural_edges=include to follow them as well. edge_kinds restricts the traversal to an allowlist of edge kinds. Both selections apply during traversal, so total_items and traversed_edges count only the selected edges.",
        [
            "selector",
            "snapshot",
            "transitive",
            "phases",
            "profiles",
            "sessions",
            "environments",
            "max_traversal",
            "edge_kinds",
            "structural_edges",
            "detail",
            "cursor",
            "limit"
        ],
        [CliAction::Deps],
        READ,
        ToolAuthorization::FixedCapabilities,
        OperationBehavior::Immediate
    ),
    tool_spec!(
        "graph_dependents_list",
        "Traverse incoming dependency edges from one selector. Use detail to shrink the response: paths returns only unique source/target paths and edge kinds, summary drops evidence and states shared edge fields once in common, full (default) returns every edge with its evidence in the previous shape, without import facts. Evidence of one edge, including its import specifier and binding, is available individually through agent_sites_list and agent_evidence_list with the edge's site_id. Structural edges (contains: a package contains a file, declares: a file declares a symbol, generated_from: a generated file comes from its source) describe graph organization rather than a dependency and are excluded by default, so the result counts only dependent or dependency edges; pass structural_edges=include to follow them as well. edge_kinds restricts the traversal to an allowlist of edge kinds. Both selections apply during traversal, so total_items and traversed_edges count only the selected edges.",
        [
            "selector",
            "snapshot",
            "transitive",
            "phases",
            "profiles",
            "sessions",
            "environments",
            "max_traversal",
            "edge_kinds",
            "structural_edges",
            "detail",
            "cursor",
            "limit"
        ],
        [CliAction::Dependents],
        READ,
        ToolAuthorization::FixedCapabilities,
        OperationBehavior::Immediate
    ),
    tool_spec!(
        "graph_path_get",
        "Explain a bounded dependency path between two selectors.",
        [
            "from",
            "to",
            "snapshot",
            "phases",
            "profiles",
            "sessions",
            "environments",
            "max_traversal"
        ],
        [CliAction::Why],
        READ,
        ToolAuthorization::FixedCapabilities,
        OperationBehavior::Immediate
    ),
    tool_spec!(
        "graph_impact_get",
        "Compute bounded reverse dependency impact for a selector.",
        [
            "selector",
            "snapshot",
            "changed_since",
            "depth",
            "profiles",
            "conditions",
            "phases",
            "sessions",
            "environments",
            "max_nodes",
            "max_edges",
            "cursor",
            "limit"
        ],
        [CliAction::Impact],
        READ,
        ToolAuthorization::FixedCapabilities,
        OperationBehavior::Immediate
    ),
    tool_spec!(
        "graph_cycles_list",
        "List bounded dependency cycles for an immutable snapshot.",
        ["snapshot", "level", "max_traversal", "cursor", "limit"],
        [CliAction::Cycles],
        READ,
        ToolAuthorization::FixedCapabilities,
        OperationBehavior::Immediate
    ),
    tool_spec!(
        "graph_unresolved_list",
        "List bounded unresolved dependency evidence.",
        ["snapshot", "kinds", "max_traversal", "cursor", "limit"],
        [CliAction::Unresolved],
        READ,
        ToolAuthorization::FixedCapabilities,
        OperationBehavior::Immediate
    ),
    tool_spec!(
        "graph_query",
        "Execute a bounded read-only graph query. query is one statement in this grammar, not a command name or JSON: MATCH p = (a[:\"<node kind>\"])-[\"<edge kind>\"[|\"<edge kind>\"...]*<min>..<max>]->(b[:\"<node kind>\"]) [WHERE <predicate>] RETURN <binding or binding.field>[, ...] [ORDER BY <projection> [ASC|DESC][, ...]] LIMIT <1-10000>. Write <-[...]- for the reverse direction; depth is 1..8; kinds are double-quoted strings such as \"file\", \"module\", \"symbol\" and \"imports\", \"depends_on\", \"calls\". Node fields are id, kind, locator, display_name; file locators look like file:src/lib.rs. Predicates compare binding.field with =, !=, <, <=, >, >=, STARTS WITH, or IN [...], combined with AND, OR, NOT, and parentheses. Example (direct importers of one file): MATCH p = (source:\"file\")-[\"imports\"*1..1]->(target:\"file\") WHERE target.locator = \"file:src/cart.rs\" RETURN source.locator ORDER BY source.locator ASC LIMIT 100. A rejected query returns INVALID_ARGUMENT with error.details.kind=query_diagnostic: code and clause name what the parser expected, token_class names the token it found, and line, column, byte_offset locate it; the query text is not echoed. graph_dependents_list and graph_dependencies_list answer single-node questions without a query.",
        ["query", "query_file", "snapshot", "cursor", "limit"],
        [CliAction::Query],
        READ,
        ToolAuthorization::FixedCapabilities,
        OperationBehavior::Immediate
    ),
    tool_spec!(
        "runtime_trace_validate",
        "Validate a runtime trace without importing it.",
        ["trace", "trace_file", "snapshot", "cursor", "limit"],
        [CliAction::RuntimeValidate],
        READ,
        ToolAuthorization::FixedCapabilities,
        OperationBehavior::Immediate
    ),
    tool_spec!(
        "snapshot_diff_get",
        "Compare two immutable completed snapshots.",
        ["from", "to", "kinds"],
        [CliAction::Diff],
        READ,
        ToolAuthorization::FixedCapabilities,
        OperationBehavior::Immediate
    ),
    tool_spec!(
        "policy_evaluate",
        "Evaluate configured dependency policy between snapshots.",
        ["from", "to"],
        [CliAction::Policy],
        READ,
        ToolAuthorization::FixedCapabilities,
        OperationBehavior::Immediate
    ),
    tool_spec!(
        "graph_export",
        "Render a bounded export directly in the tool response.",
        ["format", "snapshot", "selector", "max_nodes", "max_edges"],
        [CliAction::Export],
        READ,
        ToolAuthorization::FixedCapabilities,
        OperationBehavior::Immediate
    ),
    tool_spec!(
        "health_summary_get",
        "Summarize snapshot-scoped code-health findings. Confidence is confirmed, probable, or indeterminate. Summary excludes audit and hotspot findings. confirmed is reserved for unused-file, unused-export, unused-type, and unused-dependency when every applicable profile is semantic-complete and no hard blocker remains; test-only-dependency and manifest-mismatch are capped at probable. Plain snapshots are analyzed in bounded store ranges; execution reports the ranges, per-phase work, and checkpoint reuse. allow_partial_ranges opts into a partial view when some ranges fail after re-splitting: partial becomes true, every finding carries an incomplete_coverage blocker, and the digest never matches a complete collection.",
        ["snapshot", "kinds", "allow_partial_ranges"],
        [CliAction::HealthSummary],
        READ,
        ToolAuthorization::FixedCapabilities,
        OperationBehavior::Immediate
    ),
    tool_spec!(
        "health_findings_list",
        "List snapshot-scoped unused-file, unused-export, unused-type, unused-dependency, test-only-dependency, and manifest-mismatch findings. confirmed is reserved for the four unused kinds; test-only-dependency and manifest-mismatch are capped at probable. Read blockers before treating a finding as unused. Plain snapshots are analyzed in bounded store ranges; execution reports the ranges, per-phase work, and checkpoint reuse. allow_partial_ranges opts into a partial view when some ranges fail after re-splitting: partial becomes true, every finding carries an incomplete_coverage blocker, and the digest never matches a complete collection.",
        [
            "snapshot",
            "kinds",
            "severities",
            "confidences",
            "allow_partial_ranges",
            "cursor",
            "limit"
        ],
        [CliAction::HealthFindings],
        READ,
        ToolAuthorization::FixedCapabilities,
        OperationBehavior::Immediate
    ),
    tool_spec!(
        "health_finding_get",
        "Explain one snapshot-scoped health finding by stable ID. Input-scoped audit or hotspot IDs return a deterministic invalid-input error; use health_audit_get or health_hotspots_list instead.",
        ["snapshot", "finding_id"],
        [CliAction::HealthFindingGet],
        READ,
        ToolAuthorization::FixedCapabilities,
        OperationBehavior::Immediate
    ),
    tool_spec!(
        "health_audit_get",
        "Audit merge-base(changed, HEAD)..HEAD against a snapshot pair. The changed input is the comparison base and changed_oid identifies request-start HEAD. Comparable audit findings are capped at probable. Without a comparable base snapshot, blast radius remains evaluable while new-cycle, new-boundary, and public-api checks return indeterminate placeholders.",
        ["snapshot", "changed", "base_snapshot", "cursor", "limit"],
        [CliAction::Audit],
        READ,
        ToolAuthorization::FixedCapabilities,
        OperationBehavior::Immediate
    ),
    tool_spec!(
        "health_hotspots_list",
        "Rank graph hotspots with integer basis-point scores. Each finding exposes a closed hotspot_scores breakdown for fan-in, fan-out, reverse impact, Git churn, and runtime (raw, normalized basis points, weight basis points, and availability) plus total. The fan-in raw value counts every edge record in the snapshot whose target is the subject: all edge kinds, structural contains, declares and generated_from included, every phase and profile, and each record separately, so several edges from one source (different sites, kinds or profiles) each count. Fan-out counts the edges whose source is the subject the same way, and reverse impact counts the distinct transitive dependents over every edge. These raw values can therefore differ from graph_dependents_list, which excludes structural edges by default and with detail=paths lists unique (source, target, kind). To rank by fan-in alone, set weight_fan_in to 10000 and the other weights to 0. Hotspots are capped at probable confidence; missing Git churn or runtime observation contributes 0 without renormalizing weights. path_prefixes and node_kinds narrow the returned findings after scoring, so scores and finding IDs equal the unfiltered ranking; churn_path_filter only narrows the Git churn input.",
        [
            "snapshot",
            "churn_commit_limit",
            "churn_path_filter",
            "path_prefixes",
            "node_kinds",
            "weight_fan_in",
            "weight_fan_out",
            "weight_reverse_impact",
            "weight_git_churn",
            "weight_runtime",
            "cursor",
            "limit"
        ],
        [CliAction::Hotspots],
        READ,
        ToolAuthorization::FixedCapabilities,
        OperationBehavior::Immediate
    ),
    tool_spec!(
        "operation_get",
        "Read durable operation state and progress.",
        ["operation_id"],
        [],
        READ,
        ToolAuthorization::FixedCapabilities,
        OperationBehavior::Immediate
    ),
    tool_spec!(
        "operation_result",
        "Read a completed durable operation result.",
        ["operation_id"],
        [],
        READ,
        ToolAuthorization::FixedCapabilities,
        OperationBehavior::Immediate
    ),
    tool_spec!(
        "operation_cancel",
        "Cancel a durable operation after reauthorizing its recorded capability set.",
        ["operation_id"],
        [],
        READ,
        ToolAuthorization::OperationRequiredCapabilities,
        OperationBehavior::Immediate
    ),
    tool_spec!(
        "scan_submit",
        "Start a bounded repository scan and persist its immutable result.",
        ["idempotency_key", "strict", "no_cache"],
        [CliAction::Scan],
        STORE_WRITE,
        ToolAuthorization::FixedCapabilities,
        OperationBehavior::AlwaysCreatesDurableOperation
    ),
    tool_spec!(
        "snapshot_name_create",
        "Create a durable name for an immutable completed snapshot.",
        ["name", "snapshot"],
        [CliAction::SnapshotCreate],
        STORE_WRITE,
        ToolAuthorization::FixedCapabilities,
        OperationBehavior::Immediate
    ),
    tool_spec!(
        "runtime_trace_import_submit",
        "Validate and import runtime trace evidence into the store.",
        ["idempotency_key", "trace", "trace_file", "snapshot"],
        [CliAction::RuntimeImport],
        STORE_WRITE,
        ToolAuthorization::FixedCapabilities,
        OperationBehavior::AlwaysCreatesDurableOperation
    ),
    tool_spec!(
        "repository_init",
        "Initialize repository configuration with explicit repository-write consent.",
        ["force"],
        [CliAction::Init],
        REPOSITORY_WRITE,
        ToolAuthorization::FixedCapabilities,
        OperationBehavior::Immediate
    ),
    tool_spec!(
        "export_file",
        "Render a bounded graph export to a confined repository-relative file.",
        [
            "idempotency_key",
            "output_path",
            "overwrite",
            "format",
            "snapshot",
            "selector",
            "max_nodes",
            "max_edges"
        ],
        [],
        REPOSITORY_WRITE,
        ToolAuthorization::FixedCapabilities,
        OperationBehavior::AlwaysCreatesDurableOperation
    ),
    tool_spec!(
        "daemon_start_submit",
        "Start the repository daemon with store-write and daemon-control consent.",
        ["idempotency_key", "strict"],
        [CliAction::DaemonStart],
        DAEMON_CONTROL,
        ToolAuthorization::FixedCapabilities,
        OperationBehavior::AlwaysCreatesDurableOperation
    ),
    tool_spec!(
        "daemon_stop",
        "Stop the repository daemon with store-write and daemon-control consent.",
        ["idempotency_key"],
        [CliAction::DaemonStop],
        DAEMON_CONTROL,
        ToolAuthorization::FixedCapabilities,
        OperationBehavior::AlwaysCreatesDurableOperation
    ),
    tool_spec!(
        "resolve_build_submit",
        "Execute the approved project build resolver after the Agent host independently confirms project-code risk; acknowledgement records the decision but does not authorize it.",
        [
            "idempotency_key",
            "acknowledgement",
            "rust_compiler_precise"
        ],
        [CliAction::ResolveBuild],
        PROJECT_EXEC,
        ToolAuthorization::FixedCapabilities,
        OperationBehavior::AlwaysCreatesDurableOperation
    ),
];

const _: () = validate_static_catalog();

const fn validate_static_catalog() {
    let mut covered = [0_u8; CLI_ACTION_COUNT];
    let mut tool_index = 0;
    while tool_index < TOOL_SPECS.len() {
        let spec = &TOOL_SPECS[tool_index];
        assert!(!spec.required_capabilities.is_empty());
        assert!(matches!(
            spec.required_capabilities[0],
            DepgraphCapability::Read
        ));
        let mut action_index = 0;
        while action_index < spec.cli_actions.len() {
            let index = spec.cli_actions[action_index] as usize;
            assert!(covered[index] == 0);
            covered[index] = 1;
            action_index += 1;
        }
        tool_index += 1;
    }
    let mut index = 0;
    while index < covered.len() {
        assert!(covered[index] == 1);
        index += 1;
    }
}

fn input_schema(spec: &ToolSpec) -> Map<String, Value> {
    let mut properties = Map::new();
    properties.insert(
        "contract_version".to_owned(),
        json!({
            "type": "string",
            "const": MCP_TOOLS_CONTRACT_VERSION,
            "default": MCP_TOOLS_CONTRACT_VERSION,
            "description": CONTRACT_VERSION_DESCRIPTION
        }),
    );
    properties.insert("repository_id".to_owned(), repository_id_schema(spec.name));
    for field in spec.input_fields {
        properties.insert((*field).to_owned(), field_schema(spec.name, field));
    }
    let required = required_input_fields(spec.name).to_vec();
    let mut schema = json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": format!("{}_input", spec.name),
        "type": "object",
        "properties": properties,
        "required": required,
        "additionalProperties": false
    });
    if spec.name == "profile_plan_get" {
        schema
            .as_object_mut()
            .expect("input schema is an object")
            .insert(
                "allOf".to_owned(),
                json!([
                    {"not": {"required": ["profile_budget", "profiles_document"]}},
                    {"not": {"required": ["profile_budget", "profiles_file"]}},
                    {"not": {"required": ["profiles_document", "profiles_file"]}}
                ]),
            );
    }
    if matches!(
        spec.name,
        "graph_query" | "runtime_trace_validate" | "runtime_trace_import_submit"
    ) {
        let (inline, file) = if spec.name == "graph_query" {
            ("query", "query_file")
        } else {
            ("trace", "trace_file")
        };
        schema
            .as_object_mut()
            .expect("input schema is an object")
            .insert(
                "oneOf".to_owned(),
                json!([{"required": [inline]}, {"required": [file]}]),
            );
    }
    json_object(schema)
}

fn output_schema(spec: &ToolSpec) -> Map<String, Value> {
    match spec.name {
        "get_context" => {
            return exact_success_output_schema::<AgentContext>(spec.name);
        }
        "repository_list" => {
            return exact_success_output_schema::<AgentRepositoryList>(spec.name);
        }
        "agent_node_get" => {
            return exact_success_output_schema::<AgentNode>(spec.name);
        }
        "agent_sites_list" => {
            return exact_success_output_schema::<Page<AgentSite>>(spec.name);
        }
        "agent_edges_list" => {
            return exact_success_output_schema::<AgentEdgesOutput>(spec.name);
        }
        "agent_evidence_list" => {
            return exact_success_output_schema::<Page<AgentEvidence>>(spec.name);
        }
        "agent_nodes_list" => {
            return exact_success_output_schema::<Page<AgentNodeSummary>>(spec.name);
        }
        "snapshot_list" => {
            return exact_success_output_schema::<Page<AgentNamedSnapshot>>(spec.name);
        }
        "snapshot_get" => {
            return exact_success_output_schema::<AgentCompletedSnapshot>(spec.name);
        }
        "snapshot_name_create" => {
            return exact_success_output_schema::<AgentNamedSnapshot>(spec.name);
        }
        "profile_plan_get" => {
            return exact_success_output_schema::<AgentProfilePlan>(spec.name);
        }
        "daemon_get" => {
            return exact_success_output_schema::<AgentDaemonStatus>(spec.name);
        }
        "doctor_get" => {
            return exact_success_output_schema::<AgentDoctor>(spec.name);
        }
        "graph_dependencies_list" | "graph_dependents_list" => {
            return exact_success_output_schema::<AgentDependenciesOutput>(spec.name);
        }
        "graph_path_get" => {
            return exact_success_output_schema::<AgentPathResponse>(spec.name);
        }
        "graph_impact_get" => {
            return exact_success_output_schema::<AgentImpactResponse>(spec.name);
        }
        "graph_cycles_list" => {
            return exact_success_output_schema::<Page<AgentCycle>>(spec.name);
        }
        "graph_unresolved_list" => {
            return exact_success_output_schema::<Page<AgentUnresolved>>(spec.name);
        }
        "graph_query" => {
            return exact_success_output_schema::<Page<AgentQueryRow>>(spec.name);
        }
        "runtime_trace_validate" => {
            return exact_success_output_schema::<AgentRuntimeValidationResponse>(spec.name);
        }
        "snapshot_diff_get" => {
            return exact_success_output_schema::<AgentSnapshotDiffResponse>(spec.name);
        }
        "policy_evaluate" => {
            return exact_success_output_schema::<AgentPolicyEvaluationResponse>(spec.name);
        }
        "graph_export" => {
            return exact_success_output_schema::<AgentGraphExportResponse>(spec.name);
        }
        "health_summary_get" => {
            return exact_success_output_schema::<AgentHealthSummary>(spec.name);
        }
        "health_findings_list" => {
            return exact_success_output_schema::<AgentHealthFindingsPage>(spec.name);
        }
        "health_finding_get" => {
            return exact_success_output_schema::<AgentHealthFindingDetail>(spec.name);
        }
        "health_audit_get" => {
            return exact_success_output_schema::<AgentHealthAudit>(spec.name);
        }
        "health_hotspots_list" => {
            return exact_success_output_schema::<AgentHealthHotspots>(spec.name);
        }
        "repository_init" => {
            return exact_success_output_schema::<AgentRepositoryInitOutcome>(spec.name);
        }
        "operation_get" | "operation_cancel" => {
            return exact_success_output_schema::<AgentOperation>(spec.name);
        }
        "operation_result" => return exact_operation_result_output_schema(spec.name),
        _ => {}
    }
    let immediate = json!({
        "type": "object",
        "properties": {
            "contract_version": {"type": "string", "const": MCP_TOOLS_CONTRACT_VERSION},
            "repository_id": {"type": "string", "minLength": 1, "maxLength": 256},
            "result": true,
            "diagnostics": {
                "type": "array",
                "maxItems": 1024,
                "items": {"type": "object", "additionalProperties": false}
            },
            "pagination": {
                "type": ["object", "null"],
                "properties": {
                    "next_cursor": {"type": ["string", "null"], "maxLength": 4096},
                    "total": {"type": ["integer", "null"], "minimum": 0}
                },
                "required": ["next_cursor", "total"],
                "additionalProperties": false
            }
        },
        "required": ["contract_version", "repository_id", "result", "diagnostics", "pagination"],
        "additionalProperties": false
    });
    let mut schema = match spec.operation_behavior {
        OperationBehavior::Immediate => json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "title": format!("{}_output", spec.name),
            "$ref": "#/$defs/immediate",
            "$defs": {"immediate": immediate}
        }),
        OperationBehavior::MayCreateDurableOperation => json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "title": format!("{}_output", spec.name),
            "oneOf": [
                {"$ref": "#/$defs/immediate"},
                {"$ref": "#/$defs/accepted_operation"}
            ],
            "$defs": {
                "immediate": immediate,
                "accepted_operation": accepted_operation_output_schema()
            }
        }),
        OperationBehavior::AlwaysCreatesDurableOperation => json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "title": format!("{}_output", spec.name),
            "$ref": "#/$defs/accepted_operation",
            "$defs": {"accepted_operation": accepted_operation_output_schema()}
        }),
    };
    add_error_output_branch(&mut schema);
    json_object(schema)
}

fn add_error_output_branch(schema: &mut Value) {
    let mut error_schema = serde_json::to_value(
        SchemaSettings::draft2020_12()
            .for_serialize()
            .into_generator()
            .into_root_schema_for::<ErrorEnvelope>(),
    )
    .expect("closed error envelope schema serializes");
    let error = error_schema
        .as_object_mut()
        .expect("error envelope schema is an object");
    error.remove("$schema");
    error.remove("title");
    let error_definitions = error.remove("$defs").unwrap_or_else(|| json!({}));

    let root = schema
        .as_object_mut()
        .expect("operation output schema is an object");
    let definitions = root
        .get_mut("$defs")
        .and_then(Value::as_object_mut)
        .expect("operation output schema has definitions");
    for (name, definition) in error_definitions
        .as_object()
        .expect("error definitions are an object")
    {
        assert!(
            definitions
                .insert(name.clone(), definition.clone())
                .is_none(),
            "error definition {name} collides with an operation output definition"
        );
    }
    definitions.insert("error_envelope".to_owned(), Value::Object(error.clone()));

    let error_reference = json!({"$ref": "#/$defs/error_envelope"});
    if let Some(reference) = root.remove("$ref") {
        root.insert(
            "oneOf".to_owned(),
            json!([{ "$ref": reference }, error_reference]),
        );
    } else {
        root.get_mut("oneOf")
            .and_then(Value::as_array_mut)
            .expect("multi-shape operation output uses oneOf")
            .push(error_reference);
    }
}

fn exact_success_output_schema<T: JsonSchema>(tool_name: &str) -> Map<String, Value> {
    let mut schema = serde_json::to_value(
        SchemaSettings::draft2020_12()
            .for_serialize()
            .into_generator()
            .into_root_schema_for::<ExactToolOutput<T>>(),
    )
    .expect("closed success envelope schemas serialize");
    schema
        .as_object_mut()
        .expect("root success envelope schema is an object")
        .insert("title".to_owned(), json!(format!("{tool_name}_output")));
    json_object(schema)
}

fn exact_operation_result_output_schema(tool_name: &str) -> Map<String, Value> {
    let mut schema = serde_json::to_value(
        SchemaSettings::draft2020_12()
            .for_serialize()
            .into_generator()
            .into_root_schema_for::<ExactOperationResultOutput>(),
    )
    .expect("closed terminal output schemas serialize");
    schema
        .as_object_mut()
        .expect("root terminal output schema is an object")
        .insert("title".to_owned(), json!(format!("{tool_name}_output")));
    json_object(schema)
}

fn accepted_operation_output_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "contract_version": {
                "type": "string",
                "const": MCP_TOOLS_CONTRACT_VERSION
            },
            "result_type": {"type": "string", "const": "operation_accepted"},
            "operation_id": {
                "type": "string",
                "pattern": "^op_[0-9a-f]{32,128}$"
            },
            "status": {"type": "string", "const": "queued"},
            "recovery": {
                "type": "object",
                "properties": {
                    "status": {"type": "string", "const": "operation_get"},
                    "result": {"type": "string", "const": "operation_result"},
                    "cancel": {"type": "string", "const": "operation_cancel"}
                },
                "required": ["status", "result", "cancel"],
                "additionalProperties": false
            }
        },
        "required": ["contract_version", "result_type", "operation_id", "status", "recovery"],
        "additionalProperties": false
    })
}

/// Hotspot path lists share the service's byte bound: `maxLength` is a
/// conservative character cap and the extension carries the exact UTF-8 limit.
fn hotspot_path_item_schema() -> Value {
    json!({
        "type": "string",
        "minLength": 1,
        "maxLength": MAX_HOTSPOT_PATH_BYTES,
        "x-depgraph-maxUtf8Bytes": MAX_HOTSPOT_PATH_BYTES
    })
}

/// Node selector with the not-found and ambiguity contract (Issue #565).
fn node_selector_schema() -> Value {
    let mut schema = scalar_schema::<AgentLocator>();
    schema
        .as_object_mut()
        .expect("selector schema is an object")
        .insert(
            "description".to_owned(),
            json!("Node selector such as path:src/lib.rs, symbol:<name>, or id:<stable-id>. When it matches no node in the snapshot the tool returns NOT_FOUND with error.details {kind: argument, argument: <this argument>, reason: no_matching_node}; when it matches several nodes it returns INVALID_ARGUMENT with reason ambiguous_selector, and id:<stable-id> selects one."),
        );
    schema
}

fn field_schema(tool_name: &str, field: &str) -> Value {
    match field {
        "query" if tool_name == "graph_query" => json!({
            "type": "string",
            "minLength": 1,
            "description": "Bounded graph query text is limited to 65536 UTF-8 bytes by the service.",
            "x-depgraph-maxUtf8Bytes": 65536
        }),
        "query" => json!({
            "type": "string",
            "minLength": 1,
            "description": "Query text is limited to 256 UTF-8 bytes by the handler; JSON Schema maxLength is intentionally omitted because it counts Unicode characters.",
            "x-depgraph-maxUtf8Bytes": 256
        }),
        "match_mode" => {
            json!({"type": "string", "enum": ["exact", "prefix", "contains"]})
        }
        "direction" => {
            json!({"type": "string", "enum": ["both", "incoming", "outgoing"]})
        }
        "edge_kinds" if tool_name == "agent_edges_list" => json!({
            "type": "array",
            "maxItems": MAX_DEPENDENCY_EDGE_KINDS,
            "uniqueItems": true,
            "items": scalar_schema::<AgentToken>(),
            "description": "List only edges of these kinds, such as imports, depends_on, type_uses or calls. Empty or omitted means every kind, structural kinds (contains, declares, generated_from) included. Applied before paging, so total_items counts only the selected edges. A cursor is bound to the selection."
        }),
        "edge_kinds" => json!({
            "type": "array",
            "maxItems": MAX_DEPENDENCY_EDGE_KINDS,
            "uniqueItems": true,
            "items": scalar_schema::<AgentToken>(),
            "description": "Follow only edges of these kinds, such as imports, depends_on, type_uses or calls. Empty or omitted means every kind, subject to structural_edges. When structural_edges is omitted, the allowlist alone decides, so structural kinds (contains, declares, generated_from) may be listed. Listing a structural kind with an explicit structural_edges=exclude is contradictory and returns INVALID_ARGUMENT. Applied during traversal, so total_items and traversed_edges count only the selected edges. A cursor is bound to the selection."
        }),
        "structural_edges" => json!({
            "type": "string",
            "enum": [StructuralEdgeSelection::Include.as_str(), StructuralEdgeSelection::Exclude.as_str()],
            "default": DEFAULT_STRUCTURAL_EDGE_SELECTION.as_str(),
            "description": "Whether to follow structural edges: contains (a package contains a file), declares (a file declares a symbol) and generated_from (a generated file comes from its source). They describe graph organization, not dependencies. Defaults to exclude, which counts only files that actually depend on (or are depended on by) the selector; use include to follow structural edges as well. When edge_kinds is given, the allowlist alone decides and omission does not exclude structural kinds. A cursor is bound to the selection."
        }),
        "detail" if tool_name == "agent_edges_list" => json!({
            "type": "string",
            "enum": [AgentEdgeDetail::Summary.as_str(), AgentEdgeDetail::Full.as_str()],
            "default": AgentEdgeDetail::Full.as_str(),
            "description": "Output granularity. full (default) is byte-identical to the response without detail: a page of complete edges with evidence. summary returns detail, common and an edges page whose items carry id, source_id, target_id, kind, site_id and evidence_count without evidence bodies; phase, resolution_status, precision, profile_id and condition are stated once in common when every edge of the page shares the value, and per edge otherwise; common applies to that page only. To read evidence bodies, repeat the request with detail=full (the edge evidence is not listed by agent_evidence_list, which returns site evidence), or resolve an edge's site_id with agent_sites_list. A cursor is bound to its detail."
        }),
        "detail" => json!({
            "type": "string",
            "enum": ["paths", "summary", "full"],
            "default": "full",
            "description": "Output granularity. full (default) is byte-identical to the response without detail. summary returns each edge as id, source_id, target_id, kind, site_id and evidence_count, and states phase, resolution_status, precision, profile_id and condition once in common when every traversed edge shares the value. paths returns unique source/target repository paths (the node ID when a node has no path) with the edge kind. A cursor is bound to its detail."
        }),
        "cursor" => scalar_schema::<Cursor>(),
        "operation_id" => scalar_schema::<OperationId>(),
        "idempotency_key" => scalar_schema::<IdempotencyKey>(),
        "node_id" | "site_id" => scalar_schema::<AgentId>(),
        // Export resolves its selector outside the graph traversal tools, so
        // it does not promise their not-found and ambiguity details.
        "selector" if matches!(tool_name, "graph_export" | "export_file") => {
            scalar_schema::<AgentLocator>()
        }
        "selector" => node_selector_schema(),
        "from" | "to" if matches!(tool_name, "snapshot_diff_get" | "policy_evaluate") => {
            snapshot_selector_schema()
        }
        "from" | "to" => node_selector_schema(),
        "changed_since" => scalar_schema::<AgentLabel>(),
        "level" => scalar_schema::<AgentCycleLevel>(),
        "name" => scalar_schema::<SnapshotName>(),
        "snapshot" => snapshot_selector_schema(),
        "format" if matches!(tool_name, "graph_export" | "export_file") => {
            json!({"type": "string", "enum": ["json", "dot", "mermaid", "graphml"]})
        }
        "strict"
        | "no_cache"
        | "force"
        | "overwrite"
        | "details"
        | "rust_compiler_precise"
        | "transitive" => {
            json!({"type": "boolean"})
        }
        "acknowledgement" => json!({
            "type": "boolean",
            "description": "must be true after independent Agent-host human confirmation; it does not grant authorization or capabilities, or replace that confirmation."
        }),
        "allow_partial_ranges" => json!({
            "type": "boolean",
            "description": "Return the findings of the completed health ranges when some ranges fail after re-splitting, instead of a resource-exhausted error. The result is marked partial, every finding carries an incomplete_coverage blocker, and no finding is confirmed. Defaults to false."
        }),
        "profile_budget" => json!({"type": "integer", "minimum": 1, "maximum": 32}),
        "depth" => json!({"type": "integer", "minimum": 0}),
        "limit" | "max_depth" | "max_paths" => {
            json!({"type": "integer", "minimum": 1})
        }
        "max_nodes" if matches!(tool_name, "graph_export" | "export_file") => {
            json!({
                "type": "integer",
                "minimum": 1,
                "maximum": MAX_GRAPH_EXPORT_NODES,
                "description": "Largest node count of the exported graph. A larger selection returns RESOURCE_EXHAUSTED with error.details limit export_nodes, the selected count as observed, and argument max_nodes."
            })
        }
        "max_edges" if matches!(tool_name, "graph_export" | "export_file") => {
            json!({
                "type": "integer",
                "minimum": 1,
                "maximum": MAX_GRAPH_EXPORT_EDGES,
                "description": "Largest edge count of the exported graph. A larger selection returns RESOURCE_EXHAUSTED with error.details limit export_edges, the selected count as observed, and argument max_edges."
            })
        }
        "max_nodes" if tool_name == "graph_impact_get" => {
            json!({
                "type": "integer",
                "minimum": 1,
                "maximum": 1000000,
                "description": "Unique nodes the impact traversal may keep (default 10000). A traversal that reaches it returns RESOURCE_EXHAUSTED with error.details limit impact_nodes and argument max_nodes."
            })
        }
        "max_edges" if tool_name == "graph_impact_get" => {
            json!({
                "type": "integer",
                "minimum": 1,
                "maximum": 1000000,
                "description": "Unique edges the impact traversal may keep (default 50000). A traversal that reaches it returns RESOURCE_EXHAUSTED with error.details limit impact_edges and argument max_edges."
            })
        }
        "max_nodes" | "max_edges" => {
            json!({"type": "integer", "minimum": 1, "maximum": 1000000})
        }
        // Cycle and unresolved listing count per-phase work and report a
        // plain RESOURCE_EXHAUSTED without resource_limit details.
        "max_traversal" if matches!(tool_name, "graph_cycles_list" | "graph_unresolved_list") => {
            json!({
                "type": "integer",
                "minimum": 1,
                "maximum": 1000000,
                "description": "Work bound of each preprocessing, traversal and finalization phase. A request that hits it returns RESOURCE_EXHAUSTED without error.details."
            })
        }
        "max_traversal" => json!({
            "type": "integer",
            "minimum": 1,
            "maximum": 1000000,
            "description": "Edge visit bound of the traversal, default 50000. A request that hits a bound returns RESOURCE_EXHAUSTED whose error.details (kind resource_limit) names the limit, its maximum, the observed work when known, and argument=max_traversal when this argument moves the bound; remediation increase_limit means a larger max_traversal can succeed."
        }),
        "profiles_document" => json!({
            "type": "string",
            "minLength": 1,
            "description": "Inline profile JSON is limited to 1048576 UTF-8 bytes by the handler.",
            "x-depgraph-maxUtf8Bytes": 1048576
        }),
        "profiles_file" | "output_path" => scalar_schema::<RepositoryRelativePath>(),
        "query_file" | "trace_file" => scalar_schema::<RepositoryRelativePath>(),
        "selectors" => json!({
            "type": "array",
            "maxItems": 1024,
            "items": scalar_schema::<AgentLocator>()
        }),
        "churn_path_filter" => json!({
            "type": "array",
            "maxItems": MAX_HEALTH_FILTER_ITEMS,
            "items": hotspot_path_item_schema(),
            "description": "Repository-relative paths that narrow only the Git churn input (the git_churn layer). It does not remove findings from the result; use path_prefixes for that."
        }),
        "path_prefixes" => json!({
            "type": "array",
            "maxItems": MAX_HEALTH_FILTER_ITEMS,
            "items": hotspot_path_item_schema(),
            "description": "Return only findings whose repository-relative path starts with one of these prefixes at a directory boundary: src/lib matches src/lib and src/lib/a.ts but not src/library.rs. No leading /, trailing /, . or .. components. Findings without a path never match. Applied after scoring, unlike churn_path_filter which only narrows the Git churn input. Empty or omitted means no restriction."
        }),
        "node_kinds" => json!({
            "type": "array",
            "maxItems": MAX_HEALTH_FILTER_ITEMS,
            "items": {"type": "string", "enum": HOTSPOT_SUBJECT_KINDS},
            "description": "Return only findings whose subject is one of these hotspot node kinds. Applied after scoring, so scores and finding IDs are unchanged. Empty or omitted means every kind."
        }),
        "kinds" | "profiles" | "conditions" | "phases" | "sessions" | "environments"
        | "severities" | "confidences" => json!({
            "type": "array",
            "maxItems": 1024,
            "items": {"type": "string", "minLength": 1, "maxLength": 4096}
        }),
        "finding_id" => scalar_schema::<AgentId>(),
        "changed" => scalar_schema::<AgentLabel>(),
        "base_snapshot" => snapshot_selector_schema(),
        "churn_commit_limit" => json!({"type": "integer", "minimum": 1, "maximum": 512}),
        "weight_fan_in"
        | "weight_fan_out"
        | "weight_reverse_impact"
        | "weight_git_churn"
        | "weight_runtime" => {
            json!({"type": "integer", "minimum": 0, "maximum": 10000})
        }
        _ => json!({"type": "string", "minLength": 1, "maxLength": 1048576}),
    }
}

// Issue #570: the contract version is optional like repository_id. Omitting it
// selects the version this server implements; an explicit unknown value is still
// rejected so a client never silently runs against a different contract.
const CONTRACT_VERSION_DESCRIPTION: &str = "Optional tool contract version. When omitted, the tool uses the contract this server implements (depgraph-mcp-tools-v1, the default). An explicit value other than depgraph-mcp-tools-v1 fails with INVALID_ARGUMENT.";

const REPOSITORY_ID_DESCRIPTION: &str = "Optional logical repository ID. When omitted, the tool uses the repository this server is bound to (the default). Discover valid values with repository_list or get_context; an unknown value fails with INVALID_ARGUMENT whose error.details.available_repository_ids lists the valid IDs.";

// Operation handles stay bound to the repository that created them, so a foreign
// repository_id is an authorization failure rather than an input correction hint.
const OPERATION_REPOSITORY_ID_DESCRIPTION: &str = "Optional. Defaults to the repository bound to this server. Operation handles are bound to the repository that created them; a different repository_id returns CAPABILITY_DENIED without details. Use repository_list or get_context to read the bound id.";

fn repository_id_schema(tool_name: &str) -> Value {
    let description = match tool_name {
        "operation_get" | "operation_result" | "operation_cancel" => {
            OPERATION_REPOSITORY_ID_DESCRIPTION
        }
        _ => REPOSITORY_ID_DESCRIPTION,
    };
    let mut schema = scalar_schema::<LogicalRepositoryId>();
    schema
        .as_object_mut()
        .expect("logical repository ID schema is an object")
        .insert("description".to_owned(), json!(description));
    schema
}

fn snapshot_selector_schema() -> Value {
    json!({
        "oneOf": [
            {"type": "string", "pattern": "^[Cc][Uu][Rr][Rr][Ee][Nn][Tt]$"},
            scalar_schema::<SnapshotId>(),
            scalar_schema::<SnapshotName>()
        ]
    })
}

fn scalar_schema<T: JsonSchema>() -> Value {
    serde_json::to_value(T::json_schema(&mut SchemaGenerator::default()))
        .expect("contract scalar schemas serialize")
}

fn required_input_fields(tool_name: &str) -> &'static [&'static str] {
    match tool_name {
        "agent_nodes_list" => &["query", "match_mode"],
        "agent_node_get" | "agent_edges_list" => &["node_id"],
        "agent_evidence_list" => &["site_id"],
        "snapshot_get" => &["snapshot"],
        "graph_dependencies_list" | "graph_dependents_list" | "graph_impact_get" => &["selector"],
        "graph_path_get" | "snapshot_diff_get" | "policy_evaluate" => &["from", "to"],
        "graph_export" => &["format"],
        "operation_get" | "operation_result" | "operation_cancel" => &["operation_id"],
        "scan_submit" | "runtime_trace_import_submit" | "daemon_start_submit" | "daemon_stop" => {
            &["idempotency_key"]
        }
        "resolve_build_submit" => &[
            "idempotency_key",
            "acknowledgement",
            "rust_compiler_precise",
        ],
        "export_file" => &["idempotency_key", "output_path", "format"],
        "snapshot_name_create" => &["name"],
        "health_finding_get" => &["finding_id"],
        "health_audit_get" => &["changed"],
        _ => &[],
    }
}

fn json_object(value: Value) -> Map<String, Value> {
    value
        .as_object()
        .cloned()
        .expect("catalog schemas are object literals")
}

fn canonical_catalog_bytes(tools: &[ToolDefinition]) -> Result<Vec<u8>, String> {
    let value = Value::Array(
        tools
            .iter()
            .map(|tool| {
                json!({
                    "authorization": tool.authorization.as_str(),
                    "cli_actions": tool.cli_actions.iter().map(|action| action.stable_id()).collect::<Vec<_>>(),
                    "description": tool.description,
                    "input_schema": tool.input_schema,
                    "name": tool.name,
                    "operation_behavior": tool.operation_behavior.as_str(),
                    "output_schema": tool.output_schema,
                    "required_capabilities": tool.required_capabilities.iter().map(capability_name).collect::<Vec<_>>()
                })
            })
            .collect(),
    );
    serde_json::to_vec(&value).map_err(|error| format!("failed to serialize tool catalog: {error}"))
}

const fn capability_name(capability: &DepgraphCapability) -> &'static str {
    match capability {
        DepgraphCapability::Read => "read",
        DepgraphCapability::StoreWrite => "store_write",
        DepgraphCapability::RepositoryWrite => "repository_write",
        DepgraphCapability::DaemonControl => "daemon_control",
        DepgraphCapability::ProjectExec => "project_exec",
    }
}
