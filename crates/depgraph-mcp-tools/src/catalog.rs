use std::{collections::BTreeSet, fmt::Write as _};

use depgraph_core::service::{MAX_GRAPH_EXPORT_EDGES, MAX_GRAPH_EXPORT_NODES};
use depgraph_core::{DepgraphCapability, DepgraphCapabilitySet};
use schemars::{JsonSchema, SchemaGenerator, generate::SchemaSettings};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use crate::{
    AgentCompletedSnapshot, AgentContext, AgentCycle, AgentCycleLevel, AgentDaemonStatus,
    AgentDependenciesResponse, AgentDoctor, AgentEdge, AgentEvidence, AgentGraphExportResponse,
    AgentHealthAudit, AgentHealthFindingDetail, AgentHealthFindingsPage, AgentHealthHotspots,
    AgentHealthSummary, AgentId, AgentImpactResponse, AgentLabel, AgentLocator, AgentNamedSnapshot,
    AgentNode, AgentNodeSummary, AgentOperation, AgentPathResponse, AgentPolicyEvaluationResponse,
    AgentProfilePlan, AgentQueryRow, AgentRepositoryInitOutcome, AgentRuntimeValidationResponse,
    AgentSite, AgentSnapshotDiffResponse, AgentUnresolved, Cursor, ErrorEnvelope, IdempotencyKey,
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
        "Get logical repository identity, enabled capabilities, and current snapshot context.",
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
        "List bounded dependency sites using the frozen agent site contract.",
        ["snapshot", "node_id", "cursor", "limit"],
        [],
        READ,
        ToolAuthorization::FixedCapabilities,
        OperationBehavior::Immediate
    ),
    tool_spec!(
        "agent_edges_list",
        "List bounded dependency edges using the frozen agent edge contract.",
        ["snapshot", "node_id", "direction", "cursor", "limit"],
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
        "Traverse outgoing dependency edges from one selector.",
        [
            "selector",
            "snapshot",
            "transitive",
            "phases",
            "profiles",
            "sessions",
            "environments",
            "max_traversal",
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
        "Traverse incoming dependency edges from one selector.",
        [
            "selector",
            "snapshot",
            "transitive",
            "phases",
            "profiles",
            "sessions",
            "environments",
            "max_traversal",
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
        "Execute a bounded read-only graph query.",
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
        "Summarize snapshot-scoped code-health findings. Confidence is confirmed, probable, or indeterminate. Summary excludes audit and hotspot findings. confirmed is reserved for unused-file, unused-export, unused-type, and unused-dependency when every applicable profile is semantic-complete and no hard blocker remains; test-only-dependency and manifest-mismatch are capped at probable.",
        ["snapshot", "kinds"],
        [CliAction::HealthSummary],
        READ,
        ToolAuthorization::FixedCapabilities,
        OperationBehavior::Immediate
    ),
    tool_spec!(
        "health_findings_list",
        "List snapshot-scoped unused-file, unused-export, unused-type, unused-dependency, test-only-dependency, and manifest-mismatch findings. confirmed is reserved for the four unused kinds; test-only-dependency and manifest-mismatch are capped at probable. Read blockers before treating a finding as unused.",
        [
            "snapshot",
            "kinds",
            "severities",
            "confidences",
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
        "Rank graph hotspots with integer basis-point scores. Each finding exposes a closed hotspot_scores breakdown for fan-in, fan-out, reverse impact, Git churn, and runtime (raw, normalized basis points, weight basis points, and availability) plus total. Hotspots are capped at probable confidence; missing Git churn or runtime observation contributes 0 without renormalizing weights.",
        [
            "snapshot",
            "churn_commit_limit",
            "churn_path_filter",
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
        json!({"type": "string", "const": MCP_TOOLS_CONTRACT_VERSION}),
    );
    properties.insert(
        "repository_id".to_owned(),
        scalar_schema::<LogicalRepositoryId>(),
    );
    for field in spec.input_fields {
        properties.insert((*field).to_owned(), field_schema(spec.name, field));
    }
    let mut required = vec!["contract_version", "repository_id"];
    required.extend_from_slice(required_input_fields(spec.name));
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
        "agent_node_get" => {
            return exact_success_output_schema::<AgentNode>(spec.name);
        }
        "agent_sites_list" => {
            return exact_success_output_schema::<Page<AgentSite>>(spec.name);
        }
        "agent_edges_list" => {
            return exact_success_output_schema::<Page<AgentEdge>>(spec.name);
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
            return exact_success_output_schema::<AgentDependenciesResponse>(spec.name);
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
        "cursor" => scalar_schema::<Cursor>(),
        "operation_id" => scalar_schema::<OperationId>(),
        "idempotency_key" => scalar_schema::<IdempotencyKey>(),
        "node_id" | "site_id" => scalar_schema::<AgentId>(),
        "selector" => scalar_schema::<AgentLocator>(),
        "from" | "to" if matches!(tool_name, "snapshot_diff_get" | "policy_evaluate") => {
            snapshot_selector_schema()
        }
        "from" | "to" => scalar_schema::<AgentLocator>(),
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
        "profile_budget" => json!({"type": "integer", "minimum": 1, "maximum": 32}),
        "depth" => json!({"type": "integer", "minimum": 0}),
        "limit" | "max_depth" | "max_paths" => {
            json!({"type": "integer", "minimum": 1})
        }
        "max_nodes" if matches!(tool_name, "graph_export" | "export_file") => {
            json!({"type": "integer", "minimum": 1, "maximum": MAX_GRAPH_EXPORT_NODES})
        }
        "max_edges" if matches!(tool_name, "graph_export" | "export_file") => {
            json!({"type": "integer", "minimum": 1, "maximum": MAX_GRAPH_EXPORT_EDGES})
        }
        "max_nodes" | "max_edges" => {
            json!({"type": "integer", "minimum": 1, "maximum": 1000000})
        }
        "max_traversal" => json!({"type": "integer", "minimum": 1, "maximum": 1000000}),
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
        "kinds" | "profiles" | "conditions" | "phases" | "sessions" | "environments"
        | "severities" | "confidences" | "churn_path_filter" => json!({
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
