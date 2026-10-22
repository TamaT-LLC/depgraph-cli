use std::path::PathBuf;

use depgraph_core::{
    DEFAULT_STRUCTURAL_EDGE_SELECTION, DepgraphCapability, DepgraphCapabilitySet,
    MAX_DEPENDENCY_EDGE_KINDS,
};
use depgraph_mcp_tools::{
    ALL_CLI_ACTIONS, AgentCurrentSnapshot, AgentNamedSnapshot, AgentRepositoryList,
    AgentRepositorySummary, CapabilityProfile, CliAction, IdempotencyKey,
    MAX_IDEMPOTENCY_KEY_CHARS, OperationAccepted, OperationBehavior, OperationId,
    STANDARD_JSON_SCHEMA_FORMATS, SuccessEnvelope, ToolAuthorization, ToolCatalog,
};

use serde_json::{Value, json};

fn success_output_schema(output: &serde_json::Map<String, Value>) -> &Value {
    let branches = output
        .get("oneOf")
        .or_else(|| output.get("anyOf"))
        .and_then(Value::as_array)
        .expect("output schema has success/error branches");
    let reference = branches[0]["$ref"]
        .as_str()
        .expect("first output branch is the success reference");
    let definition = reference
        .strip_prefix("#/$defs/")
        .expect("success reference resolves in root definitions");
    &output["$defs"][definition]
}

const EXPECTED_TOOL_NAMES: &[&str] = &[
    "agent_edges_list",
    "agent_evidence_list",
    "agent_node_get",
    "agent_nodes_list",
    "agent_sites_list",
    "daemon_get",
    "daemon_start_submit",
    "daemon_stop",
    "doctor_get",
    "export_file",
    "get_context",
    "graph_cycles_list",
    "graph_dependencies_list",
    "graph_dependents_list",
    "graph_export",
    "graph_fan_in_list",
    "graph_impact_get",
    "graph_path_get",
    "graph_query",
    "graph_unresolved_list",
    "health_audit_get",
    "health_finding_get",
    "health_findings_list",
    "health_hotspots_list",
    "health_summary_get",
    "operation_cancel",
    "operation_get",
    "operation_result",
    "policy_evaluate",
    "profile_plan_get",
    "repository_init",
    "repository_list",
    "resolve_build_submit",
    "runtime_trace_import_submit",
    "runtime_trace_validate",
    "scan_submit",
    "snapshot_diff_get",
    "snapshot_get",
    "snapshot_list",
    "snapshot_name_create",
];

#[test]
fn full_catalog_is_complete_unique_and_name_sorted() {
    let capabilities = DepgraphCapabilitySet::try_new([
        DepgraphCapability::Read,
        DepgraphCapability::StoreWrite,
        DepgraphCapability::RepositoryWrite,
        DepgraphCapability::DaemonControl,
        DepgraphCapability::ProjectExec,
    ])
    .unwrap();
    let catalog = ToolCatalog::for_capabilities(&capabilities).unwrap();
    let names = catalog
        .tools()
        .iter()
        .map(|tool| tool.name())
        .collect::<Vec<_>>();

    assert_eq!(names, EXPECTED_TOOL_NAMES);
    assert_eq!(catalog.tools().len(), 40);
}

/// Tools handled by the operation-handle path, which keeps foreign repository IDs as
/// authorization failures instead of input correction hints.
const OPERATION_HANDLE_TOOLS: [&str; 3] = ["operation_get", "operation_result", "operation_cancel"];

#[test]
fn issue_540_repository_id_is_optional_and_documented_for_every_tool() {
    let catalog = ToolCatalog::for_capabilities(&full_capabilities()).unwrap();
    for tool in catalog.tools() {
        let input = tool.input_schema();
        let required = input["required"].as_array().unwrap();
        assert!(
            !required.contains(&Value::String("repository_id".to_owned())),
            "{} still requires repository_id",
            tool.name()
        );
        assert!(
            !required.contains(&Value::String("contract_version".to_owned())),
            "{} still requires contract_version",
            tool.name()
        );
        let contract_version = &input["properties"]["contract_version"];
        assert_eq!(contract_version["const"], "depgraph-mcp-tools-v1");
        assert_eq!(contract_version["default"], "depgraph-mcp-tools-v1");
        let description = contract_version["description"]
            .as_str()
            .unwrap_or_else(|| panic!("{} contract_version has no description", tool.name()));
        for expected in ["Optional", "depgraph-mcp-tools-v1", "INVALID_ARGUMENT"] {
            assert!(
                description.contains(expected),
                "{} contract_version description lacks {expected}: {description}",
                tool.name()
            );
        }
        let repository_id = &input["properties"]["repository_id"];
        assert_eq!(repository_id["pattern"], "^[A-Za-z0-9][A-Za-z0-9._:+-]*$");
        let description = repository_id["description"]
            .as_str()
            .unwrap_or_else(|| panic!("{} repository_id has no description", tool.name()));
        let is_operation_tool = OPERATION_HANDLE_TOOLS.contains(&tool.name());
        let (expected, forbidden): (&[&str], &[&str]) = if is_operation_tool {
            (
                &[
                    "Optional",
                    "repository_list",
                    "CAPABILITY_DENIED",
                    "without details",
                ],
                &["INVALID_ARGUMENT", "available_repository_ids"],
            )
        } else {
            (
                &[
                    "Optional",
                    "repository_list",
                    "INVALID_ARGUMENT",
                    "available_repository_ids",
                ],
                &["CAPABILITY_DENIED"],
            )
        };
        for expected in expected {
            assert!(
                description.contains(expected),
                "{} repository_id description lacks {expected}: {description}",
                tool.name()
            );
        }
        for forbidden in forbidden {
            assert!(
                !description.contains(forbidden),
                "{} repository_id description must not mention {forbidden}: {description}",
                tool.name()
            );
        }
    }

    let operation_description = catalog.tool("operation_get").unwrap().input_schema()["properties"]
        ["repository_id"]["description"]
        .clone();
    let read_description = catalog.tool("get_context").unwrap().input_schema()["properties"]
        ["repository_id"]["description"]
        .clone();
    assert_ne!(operation_description, read_description);

    let context = catalog.tool("get_context").unwrap();
    let validator =
        jsonschema::draft202012::new(&Value::Object(context.input_schema().clone())).unwrap();
    assert!(validator.is_valid(&serde_json::json!({"contract_version": "depgraph-mcp-tools-v1"})));
    assert!(validator.is_valid(&serde_json::json!({})));
    assert!(validator.is_valid(&serde_json::json!({"repository_id": "repository"})));
    assert!(!validator.is_valid(&serde_json::json!({"contract_version": "depgraph-mcp-tools-v2"})));
    assert!(validator.is_valid(&serde_json::json!({
        "contract_version": "depgraph-mcp-tools-v1",
        "repository_id": "repository"
    })));
    assert!(
        context.description().contains("repository_list"),
        "get_context description must point to repository_list"
    );
}

#[test]
fn issue_540_repository_list_is_an_immediate_read_only_tool_with_a_closed_output() {
    let catalog = ToolCatalog::for_capabilities(&DepgraphCapabilitySet::read_only()).unwrap();
    let list = catalog
        .tool("repository_list")
        .expect("repository_list is part of the read-only profile");
    assert_eq!(list.required_capabilities(), &[DepgraphCapability::Read]);
    assert_eq!(list.authorization(), ToolAuthorization::FixedCapabilities);
    assert_eq!(list.operation_behavior(), OperationBehavior::Immediate);
    assert!(list.cli_actions().is_empty());
    assert_eq!(list.input_schema()["required"], serde_json::json!([]));
    let mut fields = list.input_schema()["properties"]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect::<Vec<_>>();
    fields.sort_unstable();
    assert_eq!(fields, ["contract_version", "repository_id"]);
    for expected in ["repository_id", "default"] {
        assert!(
            list.description().contains(expected),
            "repository_list description lacks {expected}"
        );
    }
    assert_eq!(
        success_output_schema(list.output_schema())["properties"]["result"]["$ref"],
        "#/$defs/AgentRepositoryList"
    );

    let output = Value::Object(list.output_schema().clone());
    let validator = jsonschema::draft202012::new(&output).unwrap();
    let result = AgentRepositoryList::new(vec![AgentRepositorySummary::new(
        "repository".parse().unwrap(),
        AgentCurrentSnapshot::unavailable(),
    )])
    .unwrap();
    let envelope = SuccessEnvelope::new("repository".parse().unwrap(), None, result);
    let mut value = serde_json::to_value(envelope).unwrap();
    assert!(validator.is_valid(&value));
    value["result"]["repositories"][0]["root"] = Value::String("/abs/path".to_owned());
    assert!(
        !validator.is_valid(&value),
        "repository_list output must not admit an absolute root"
    );
}

#[test]
fn issue_543_health_hotspots_list_advertises_result_filters() {
    let catalog = ToolCatalog::for_capabilities(&DepgraphCapabilitySet::read_only()).unwrap();
    let hotspots = catalog.tool("health_hotspots_list").unwrap();
    let input = hotspots.input_schema();
    let properties = input["properties"].as_object().unwrap();

    let prefixes = &properties["path_prefixes"];
    assert_eq!(prefixes["type"], "array");
    assert_eq!(prefixes["maxItems"], 1024);
    assert_eq!(prefixes["items"]["type"], "string");
    assert_eq!(prefixes["items"]["minLength"], 1);
    assert_eq!(prefixes["items"]["maxLength"], 512);
    let description = prefixes["description"].as_str().unwrap();
    for expected in ["directory boundary", "src/library.rs", "churn_path_filter"] {
        assert!(
            description.contains(expected),
            "path_prefixes description lacks {expected}: {description}"
        );
    }

    let kinds = &properties["node_kinds"];
    assert_eq!(kinds["type"], "array");
    assert_eq!(
        kinds["items"]["enum"],
        serde_json::json!(["file", "module", "symbol", "type", "route"])
    );
    assert!(
        kinds["description"]
            .as_str()
            .unwrap()
            .contains("after scoring")
    );

    // Both path lists share the service's 512-byte path bound: maxLength is
    // the conservative character cap and the extension carries the byte cap.
    let churn_paths = &properties["churn_path_filter"];
    for paths in [prefixes, churn_paths] {
        assert_eq!(paths["maxItems"], 1024, "{paths}");
        assert_eq!(
            paths["items"],
            serde_json::json!({
                "type": "string",
                "minLength": 1,
                "maxLength": 512,
                "x-depgraph-maxUtf8Bytes": 512
            }),
            "{paths}"
        );
    }
    let churn = properties["churn_path_filter"]["description"]
        .as_str()
        .expect("churn_path_filter documents that it does not filter results");
    assert!(churn.contains("path_prefixes"), "{churn}");
    assert!(
        hotspots.description().contains("path_prefixes")
            && hotspots.description().contains("node_kinds"),
        "{}",
        hotspots.description()
    );
    let required = input["required"].as_array().unwrap();
    assert!(!required.contains(&Value::String("path_prefixes".to_owned())));
    assert!(!required.contains(&Value::String("node_kinds".to_owned())));

    let validator = jsonschema::draft202012::new(&Value::Object(input.clone())).unwrap();
    let mut arguments = serde_json::json!({
        "contract_version": "depgraph-mcp-tools-v1",
        "path_prefixes": ["src/lib"],
        "node_kinds": ["file", "symbol"]
    });
    assert!(validator.is_valid(&arguments));
    arguments["node_kinds"] = serde_json::json!(["package"]);
    assert!(!validator.is_valid(&arguments));
    arguments["node_kinds"] = serde_json::json!([]);
    arguments["path_prefixes"] = serde_json::json!([""]);
    assert!(!validator.is_valid(&arguments));
}

#[test]
fn idempotency_key_catalog_limit_matches_the_validated_scalar() {
    let catalog = ToolCatalog::for_capabilities(&full_capabilities()).unwrap();
    for tool_name in [
        "scan_submit",
        "runtime_trace_import_submit",
        "export_file",
        "daemon_start_submit",
        "daemon_stop",
        "resolve_build_submit",
    ] {
        let schema =
            &catalog.tool(tool_name).unwrap().input_schema()["properties"]["idempotency_key"];
        assert_eq!(schema["minLength"], 1);
        assert_eq!(schema["maxLength"], MAX_IDEMPOTENCY_KEY_CHARS);
        assert_eq!(schema["pattern"], r"^[^\u0000-\u001f\u007f-\u009f]+$");
    }

    assert!(IdempotencyKey::parse("x".repeat(MAX_IDEMPOTENCY_KEY_CHARS)).is_ok());
    assert!(IdempotencyKey::parse("界".repeat(MAX_IDEMPOTENCY_KEY_CHARS)).is_ok());
    assert!(IdempotencyKey::parse("").is_err());
    assert!(IdempotencyKey::parse("x".repeat(MAX_IDEMPOTENCY_KEY_CHARS + 1)).is_err());
    assert!(IdempotencyKey::parse("has\u{0000}control").is_err());
    assert!(IdempotencyKey::parse("has\u{0085}control").is_err());
}

#[test]
fn resolve_build_requires_acknowledgement_exact_mode_and_project_exec_authority() {
    let catalog = ToolCatalog::for_capabilities(&full_capabilities()).unwrap();
    let build = catalog.tool("resolve_build_submit").unwrap();
    assert_eq!(
        build.input_schema()["required"],
        serde_json::json!([
            "idempotency_key",
            "acknowledgement",
            "rust_compiler_precise"
        ])
    );
    assert_eq!(
        build.required_capabilities(),
        &[
            DepgraphCapability::Read,
            DepgraphCapability::StoreWrite,
            DepgraphCapability::ProjectExec,
        ]
    );
    assert_eq!(
        build.input_schema()["properties"]["acknowledgement"]["type"],
        "boolean"
    );
    let acknowledgement_description =
        build.input_schema()["properties"]["acknowledgement"]["description"]
            .as_str()
            .unwrap();
    assert!(acknowledgement_description.contains("must be true"));
    assert!(acknowledgement_description.contains("does not grant authorization"));

    let input = Value::Object(build.input_schema().clone());
    let validator = jsonschema::draft202012::new(&input).unwrap();
    let valid = serde_json::json!({
        "contract_version": "depgraph-mcp-tools-v1",
        "repository_id": "repository",
        "idempotency_key": "build-1",
        "acknowledgement": true,
        "rust_compiler_precise": true
    });
    assert!(validator.is_valid(&valid));
    for missing in ["acknowledgement", "rust_compiler_precise"] {
        let mut invalid = valid.clone();
        invalid.as_object_mut().unwrap().remove(missing);
        assert!(!validator.is_valid(&invalid));
    }
}

#[test]
fn daemon_control_inputs_require_a_bounded_idempotency_key_and_remain_closed() {
    let catalog = ToolCatalog::for_capabilities(&full_capabilities()).unwrap();
    let start = catalog.tool("daemon_start_submit").unwrap();
    let stop = catalog.tool("daemon_stop").unwrap();

    assert_eq!(
        start.input_schema()["required"],
        serde_json::json!(["idempotency_key"])
    );
    assert_eq!(
        stop.input_schema()["required"],
        serde_json::json!(["idempotency_key"])
    );
    assert_eq!(
        start.input_schema()["properties"]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        [
            "contract_version",
            "repository_id",
            "idempotency_key",
            "strict"
        ]
    );
    assert_eq!(
        stop.input_schema()["properties"]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        ["contract_version", "repository_id", "idempotency_key"]
    );
}

#[test]
fn repository_write_catalog_exposes_only_fixed_root_init_and_durable_export_file() {
    let read_only = ToolCatalog::for_capabilities(&DepgraphCapabilitySet::read_only()).unwrap();
    assert!(read_only.tool("repository_init").is_none());
    assert!(read_only.tool("export_file").is_none());

    let capabilities = DepgraphCapabilitySet::try_new([
        DepgraphCapability::Read,
        DepgraphCapability::RepositoryWrite,
    ])
    .unwrap();
    let catalog = ToolCatalog::for_capabilities(&capabilities).unwrap();
    let init = catalog.tool("repository_init").unwrap();
    let mut init_fields = init.input_schema()["properties"]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect::<Vec<_>>();
    init_fields.sort_unstable();
    assert_eq!(init_fields, ["contract_version", "force", "repository_id"]);
    assert_eq!(init.operation_behavior(), OperationBehavior::Immediate);
    assert_eq!(
        success_output_schema(init.output_schema())["properties"]["result"]["$ref"],
        "#/$defs/AgentRepositoryInitOutcome"
    );

    let export = catalog.tool("export_file").unwrap();
    let mut export_fields = export.input_schema()["properties"]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect::<Vec<_>>();
    export_fields.sort_unstable();
    assert_eq!(
        export_fields,
        [
            "contract_version",
            "format",
            "idempotency_key",
            "max_edges",
            "max_nodes",
            "output_path",
            "overwrite",
            "repository_id",
            "selector",
            "snapshot",
        ]
    );
    assert_eq!(
        export.operation_behavior(),
        OperationBehavior::AlwaysCreatesDurableOperation
    );
    let export_output = Value::Object(export.output_schema().clone()).to_string();
    assert!(export_output.contains("operation_accepted"));
    let operation_result = catalog.tool("operation_result").unwrap();
    assert!(
        Value::Object(operation_result.output_schema().clone())
            .to_string()
            .contains("AgentExportOutcome")
    );
}

#[test]
fn every_cli_leaf_action_has_a_catalog_mapping() {
    assert_eq!(ALL_CLI_ACTIONS.len(), 28);
    let capabilities = DepgraphCapabilitySet::try_new([
        DepgraphCapability::Read,
        DepgraphCapability::StoreWrite,
        DepgraphCapability::RepositoryWrite,
        DepgraphCapability::DaemonControl,
        DepgraphCapability::ProjectExec,
    ])
    .unwrap();
    let mut covered = ToolCatalog::for_capabilities(&capabilities)
        .unwrap()
        .tools()
        .iter()
        .flat_map(|tool| tool.cli_actions().iter().copied())
        .collect::<Vec<_>>();
    covered.sort_unstable();
    covered.dedup();

    let mut expected = ALL_CLI_ACTIONS.to_vec();
    expected.sort_unstable();
    assert_eq!(covered, expected);
    assert!(
        ToolCatalog::for_capabilities(&capabilities)
            .unwrap()
            .tool("graph_dependencies_list")
            .unwrap()
            .cli_actions()
            .contains(&CliAction::Deps)
    );
    assert!(
        ToolCatalog::for_capabilities(&capabilities)
            .unwrap()
            .tool("graph_dependents_list")
            .unwrap()
            .cli_actions()
            .contains(&CliAction::Dependents)
    );
}

#[test]
fn agent_projection_inputs_encode_runtime_id_and_direction_validation() {
    let catalog = ToolCatalog::for_capabilities(&DepgraphCapabilitySet::read_only()).unwrap();
    let sites = catalog.tool("agent_sites_list").unwrap();
    let edges = catalog.tool("agent_edges_list").unwrap();

    assert_eq!(
        sites.input_schema()["properties"]["node_id"]["pattern"],
        "^[A-Za-z0-9][A-Za-z0-9._:@+-]*$"
    );
    assert_eq!(
        edges.input_schema()["properties"]["direction"],
        serde_json::json!({"type": "string", "enum": ["both", "incoming", "outgoing"]})
    );
}

#[test]
fn graph_dependency_and_path_tools_advertise_their_exact_closed_contracts() {
    let catalog = ToolCatalog::for_capabilities(&DepgraphCapabilitySet::read_only()).unwrap();
    for name in ["graph_dependencies_list", "graph_dependents_list"] {
        let tool = catalog.tool(name).expect("dependency tool");
        let mut fields = tool.input_schema()["properties"]
            .as_object()
            .expect("input properties")
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>();
        fields.sort_unstable();
        assert_eq!(
            fields,
            [
                "contract_version",
                "cursor",
                "detail",
                "edge_kinds",
                "environments",
                "limit",
                "max_traversal",
                "phases",
                "profiles",
                "repository_id",
                "rollup",
                "selector",
                "sessions",
                "snapshot",
                "structural_edges",
                "transitive",
            ]
        );
        assert_eq!(tool.operation_behavior(), OperationBehavior::Immediate);
        assert_eq!(
            success_output_schema(tool.output_schema())["properties"]["result"]["$ref"],
            "#/$defs/AgentDependenciesOutput"
        );
    }

    let path = catalog.tool("graph_path_get").expect("path tool");
    let mut fields = path.input_schema()["properties"]
        .as_object()
        .expect("input properties")
        .keys()
        .map(String::as_str)
        .collect::<Vec<_>>();
    fields.sort_unstable();
    assert_eq!(
        fields,
        [
            "contract_version",
            "detail",
            "environments",
            "from",
            "max_traversal",
            "phases",
            "profiles",
            "repository_id",
            "sessions",
            "snapshot",
            "to",
        ]
    );
    assert_eq!(path.operation_behavior(), OperationBehavior::Immediate);
    assert_eq!(
        success_output_schema(path.output_schema())["properties"]["result"]["$ref"],
        "#/$defs/AgentPathOutput"
    );
}

#[test]
fn issue_303_graph_tools_advertise_exact_closed_immediate_contracts() {
    let catalog = ToolCatalog::for_capabilities(&DepgraphCapabilitySet::read_only()).unwrap();
    for (name, expected_fields, result_ref) in [
        (
            "graph_impact_get",
            vec![
                "changed_since",
                "conditions",
                "contract_version",
                "cursor",
                "depth",
                "environments",
                "limit",
                "max_edges",
                "max_nodes",
                "phases",
                "profiles",
                "repository_id",
                "selector",
                "sessions",
                "snapshot",
            ],
            "#/$defs/AgentImpactResponse",
        ),
        (
            "graph_cycles_list",
            vec![
                "contract_version",
                "cursor",
                "level",
                "limit",
                "max_traversal",
                "repository_id",
                "snapshot",
            ],
            "#/$defs/Page",
        ),
        (
            "graph_unresolved_list",
            vec![
                "contract_version",
                "cursor",
                "kinds",
                "limit",
                "max_traversal",
                "repository_id",
                "snapshot",
            ],
            "#/$defs/Page",
        ),
    ] {
        let tool = catalog.tool(name).unwrap();
        let mut fields = tool.input_schema()["properties"]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>();
        fields.sort_unstable();
        assert_eq!(fields, expected_fields);
        assert_eq!(tool.operation_behavior(), OperationBehavior::Immediate);
        assert_eq!(
            success_output_schema(tool.output_schema())["properties"]["result"]["$ref"],
            result_ref
        );
    }

    let impact = catalog.tool("graph_impact_get").unwrap();
    assert_eq!(
        impact.input_schema()["properties"]["depth"],
        serde_json::json!({"type":"integer","minimum":0})
    );
    assert_eq!(
        impact.input_schema()["properties"]["conditions"]["type"],
        "array"
    );
    assert_eq!(
        catalog.tool("graph_cycles_list").unwrap().input_schema()["properties"]["level"]["enum"],
        serde_json::json!(["package", "file", "symbol", "type", "route"])
    );
}

#[test]
fn issue_304_query_and_runtime_validate_advertise_exact_one_confined_inputs() {
    let catalog = ToolCatalog::for_capabilities(&DepgraphCapabilitySet::read_only()).unwrap();
    for (name, expected_fields, result_ref) in [
        (
            "graph_query",
            vec![
                "contract_version",
                "cursor",
                "limit",
                "query",
                "query_file",
                "repository_id",
                "snapshot",
            ],
            "#/$defs/Page",
        ),
        (
            "runtime_trace_validate",
            vec![
                "contract_version",
                "cursor",
                "limit",
                "repository_id",
                "snapshot",
                "trace",
                "trace_file",
            ],
            "#/$defs/AgentRuntimeValidationResponse",
        ),
    ] {
        let tool = catalog.tool(name).unwrap();
        let mut fields = tool.input_schema()["properties"]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>();
        fields.sort_unstable();
        assert_eq!(fields, expected_fields);
        assert_eq!(tool.operation_behavior(), OperationBehavior::Immediate);
        assert_eq!(tool.input_schema()["oneOf"].as_array().unwrap().len(), 2);
        assert_eq!(
            success_output_schema(tool.output_schema())["properties"]["result"]["$ref"],
            result_ref
        );
    }

    let query = catalog.tool("graph_query").unwrap();
    assert_eq!(
        query.input_schema()["properties"]["query"]["x-depgraph-maxUtf8Bytes"],
        65_536
    );
    for field in ["query_file", "trace_file"] {
        let tool = if field == "query_file" {
            query
        } else {
            catalog.tool("runtime_trace_validate").unwrap()
        };
        assert!(
            tool.input_schema()["properties"][field]["allOf"]
                .as_array()
                .is_some_and(|constraints| !constraints.is_empty()),
            "{field} must retain the closed repository-relative path constraints"
        );
        let input_schema = serde_json::Value::Object(tool.input_schema().clone());
        let schema = jsonschema::draft202012::new(&input_schema).unwrap();
        let inline_field = if field == "query_file" {
            "query"
        } else {
            "trace"
        };
        let valid = serde_json::json!({
            "contract_version": "depgraph-mcp-tools-v1",
            "repository_id": "repository",
            (field): "fixtures/input.json"
        });
        assert!(schema.is_valid(&valid));
        for invalid_path in ["/absolute/input.json", "../escape.json"] {
            let invalid = serde_json::json!({
                "contract_version": "depgraph-mcp-tools-v1",
                "repository_id": "repository",
                (field): invalid_path
            });
            assert!(!schema.is_valid(&invalid));
        }
        let neither = serde_json::json!({
            "contract_version": "depgraph-mcp-tools-v1",
            "repository_id": "repository"
        });
        assert!(!schema.is_valid(&neither));
        let both = serde_json::json!({
            "contract_version": "depgraph-mcp-tools-v1",
            "repository_id": "repository",
            (field): "fixtures/input.json",
            (inline_field): "inline"
        });
        assert!(!schema.is_valid(&both));
    }
}

#[test]
fn profiles_include_dependencies_and_default_excludes_privileged_tools() {
    assert_eq!(
        CapabilityProfile::Read.required_capabilities(),
        &[DepgraphCapability::Read]
    );
    assert_eq!(
        CapabilityProfile::StoreWrite.required_capabilities(),
        &[DepgraphCapability::Read, DepgraphCapability::StoreWrite]
    );
    assert_eq!(
        CapabilityProfile::RepositoryWrite.required_capabilities(),
        &[
            DepgraphCapability::Read,
            DepgraphCapability::RepositoryWrite
        ]
    );
    assert_eq!(
        CapabilityProfile::DaemonControl.required_capabilities(),
        &[
            DepgraphCapability::Read,
            DepgraphCapability::StoreWrite,
            DepgraphCapability::DaemonControl
        ]
    );
    assert_eq!(
        CapabilityProfile::ProjectExec.required_capabilities(),
        &[
            DepgraphCapability::Read,
            DepgraphCapability::StoreWrite,
            DepgraphCapability::ProjectExec
        ]
    );

    let catalog = ToolCatalog::for_capabilities(&DepgraphCapabilitySet::read_only()).unwrap();
    for name in [
        "scan_submit",
        "snapshot_name_create",
        "runtime_trace_import_submit",
        "repository_init",
        "daemon_start_submit",
        "daemon_stop",
        "resolve_build_submit",
    ] {
        assert!(catalog.tool(name).is_none(), "default exposed {name}");
    }
    assert!(catalog.tool("daemon_get").is_some());
}

#[test]
fn operation_cancel_is_always_discoverable_but_requires_record_capabilities() {
    let catalog = ToolCatalog::for_capabilities(&DepgraphCapabilitySet::read_only()).unwrap();
    let cancel = catalog.tool("operation_cancel").unwrap();

    assert_eq!(cancel.required_capabilities(), &[DepgraphCapability::Read]);
    assert_eq!(
        cancel.authorization(),
        ToolAuthorization::OperationRequiredCapabilities
    );
}

#[test]
fn operation_baseline_tools_advertise_their_exact_closed_outputs() {
    let catalog = ToolCatalog::for_capabilities(&DepgraphCapabilitySet::read_only()).unwrap();
    let operation_id = format!("op_{}", "a".repeat(32));
    let operation = serde_json::json!({
        "contract_version": "depgraph-mcp-tools-v1",
        "repository_id": "repository",
        "result": {
            "operation_id": operation_id,
            "status": "queued",
            "progress": {"completed_units": 0, "total_units": 1},
            "timestamps": {"created_at_ms": 1000, "updated_at_ms": 1000},
            "retention": {"execution_deadline_ms": 2000, "retain_until_ms": 3000}
        }
    });
    for name in ["operation_get", "operation_cancel"] {
        let tool = catalog.tool(name).unwrap();
        let output = Value::Object(tool.output_schema().clone());
        let encoded = output.to_string();
        assert!(encoded.contains("AgentOperation"), "{name}: {encoded}");
        assert!(!encoded.contains("\"result\":true"), "{name}: {encoded}");
        let validator = jsonschema::draft202012::new(&output).unwrap();
        assert!(
            validator.is_valid(&operation),
            "{name} rejected {operation}"
        );
        let mut raw = operation.clone();
        raw["result"]["journal_payload"] = serde_json::json!({"arbitrary": true});
        assert!(
            !validator.is_valid(&raw),
            "{name} accepted raw journal data"
        );
    }

    let terminal_daemon = serde_json::json!({
        "contract_version": "depgraph-mcp-tools-v1",
        "repository_id": "repository",
        "result": {
            "action": "stop",
            "phase": "stopped"
        }
    });
    let result_tool = catalog.tool("operation_result").unwrap();
    let result_output = Value::Object(result_tool.output_schema().clone());
    let encoded = result_output.to_string();
    assert!(encoded.contains("AgentDaemonControlOutcome"), "{encoded}");
    assert!(!encoded.contains("AgentDaemonStatus"), "{encoded}");
    assert!(!encoded.contains("AgentOperation\""), "{encoded}");
    assert!(!encoded.contains("\"result\":true"), "{encoded}");
    let validator = jsonschema::draft202012::new(&result_output).unwrap();
    assert!(validator.is_valid(&terminal_daemon));
    assert!(
        !validator.is_valid(&operation),
        "operation_result advertised AgentOperation"
    );
    assert!(!validator.is_valid(&serde_json::json!({
        "contract_version": "depgraph-mcp-tools-v1",
        "repository_id": "repository",
        "result": {"arbitrary": true}
    })));
}

#[test]
fn catalog_schemas_compile_are_closed_and_are_deterministic() {
    let capabilities = full_capabilities();
    let first = ToolCatalog::for_capabilities(&capabilities).unwrap();
    let second = ToolCatalog::for_capabilities(&capabilities).unwrap();

    assert_eq!(first.canonical_bytes(), second.canonical_bytes());
    assert_eq!(first.sha256(), second.sha256());
    assert_eq!(first.sha256().len(), 64);

    for tool in first.tools() {
        for (kind, schema) in [
            ("input", tool.input_schema()),
            ("output", tool.output_schema()),
        ] {
            let schema = Value::Object(schema.clone());
            jsonschema::options()
                .with_draft(jsonschema::Draft::Draft202012)
                .build(&schema)
                .unwrap_or_else(|error| panic!("{} {kind} schema failed: {error}", tool.name()));
            assert_closed_object_nodes(&schema, tool.name(), kind);
        }
    }
}

#[test]
fn tool_specific_required_fields_and_scalar_contracts_are_preserved() {
    let catalog = ToolCatalog::for_capabilities(&full_capabilities()).unwrap();

    for tool in catalog.tools() {
        let properties = tool.input_schema()["properties"].as_object().unwrap();
        for required in tool.input_schema()["required"].as_array().unwrap() {
            let required = required.as_str().unwrap();
            assert!(
                properties.contains_key(required),
                "{} requires undeclared property {required}",
                tool.name()
            );
        }
    }

    let evidence = catalog.tool("agent_evidence_list").unwrap();
    assert!(
        evidence.input_schema()["required"]
            .as_array()
            .unwrap()
            .contains(&Value::String("site_id".to_owned()))
    );

    let policy = catalog.tool("policy_evaluate").unwrap();
    for field in ["from", "to"] {
        assert!(
            policy.input_schema()["required"]
                .as_array()
                .unwrap()
                .contains(&Value::String(field.to_owned()))
        );
    }

    let snapshot = catalog.tool("snapshot_get").unwrap();
    let snapshot_schema = Value::Object(snapshot.input_schema().clone());
    let snapshot_validator = jsonschema::validator_for(&snapshot_schema).unwrap();
    for locator in [
        "current",
        "CURRENT",
        "release-1",
        "snapshot:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    ] {
        assert!(snapshot_validator.is_valid(&serde_json::json!({
            "contract_version": "depgraph-mcp-tools-v1",
            "repository_id": "repo",
            "snapshot": locator
        })));
    }
    for locator in [
        "latest",
        "a-name-that-is-more-than-sixty-four-bytes-and-therefore-invalid-for-snapshots",
        "snapshot:sha256:not-a-valid-digest",
    ] {
        assert!(!snapshot_validator.is_valid(&serde_json::json!({
            "contract_version": "depgraph-mcp-tools-v1",
            "repository_id": "repo",
            "snapshot": locator
        })));
    }

    let path = catalog.tool("graph_path_get").unwrap();
    let required = path.input_schema()["required"].as_array().unwrap();
    for field in ["from", "to"] {
        assert!(required.contains(&Value::String(field.to_owned())));
    }
    assert!(!required.contains(&Value::String("repository_id".to_owned())));

    let operation = catalog.tool("operation_get").unwrap();
    assert_eq!(
        operation.input_schema()["properties"]["operation_id"]["pattern"],
        "^op_[0-9a-f]{32,128}$"
    );
    assert!(
        operation.input_schema()["required"]
            .as_array()
            .unwrap()
            .contains(&Value::String("operation_id".to_owned()))
    );

    let nodes = catalog.tool("agent_nodes_list").unwrap();
    assert_eq!(
        nodes.input_schema()["properties"]["query"]["x-depgraph-maxUtf8Bytes"],
        256
    );
    assert!(
        nodes.input_schema()["properties"]["query"]["description"]
            .as_str()
            .is_some_and(|description| description.contains("UTF-8 bytes"))
    );
    assert!(
        nodes.input_schema()["properties"]["query"]
            .get("maxLength")
            .is_none(),
        "JSON Schema maxLength counts Unicode characters, not UTF-8 bytes"
    );
    let nodes_schema = Value::Object(nodes.input_schema().clone());
    let nodes_validator = jsonschema::validator_for(&nodes_schema).unwrap();
    for query in ["あ".repeat(85), "あ".repeat(86)] {
        assert!(nodes_validator.is_valid(&serde_json::json!({
            "contract_version": "depgraph-mcp-tools-v1",
            "repository_id": "repo",
            "query": query,
            "match_mode": "contains"
        })));
    }
    assert_eq!(
        nodes.input_schema()["properties"]["match_mode"]["enum"],
        serde_json::json!(["exact", "prefix", "contains"])
    );
    assert_eq!(
        nodes.input_schema()["properties"]["cursor"]["pattern"],
        "^[A-Za-z0-9_~.-]+$"
    );
    assert_eq!(
        nodes.input_schema()["properties"]["cursor"]["maxLength"],
        4096
    );
    assert_eq!(
        nodes.input_schema()["properties"]["repository_id"]["pattern"],
        "^[A-Za-z0-9][A-Za-z0-9._:+-]*$"
    );
    assert_eq!(
        nodes.input_schema()["properties"]["repository_id"]["maxLength"],
        128
    );

    let context = catalog.tool("get_context").unwrap();
    assert_eq!(context.input_schema()["required"], serde_json::json!([]));
}

#[test]
fn durable_operation_output_schema_accepts_the_v1_wire_contract() {
    let capabilities = full_capabilities();
    let catalog = ToolCatalog::for_capabilities(&capabilities).unwrap();
    let scan = catalog.tool("scan_submit").unwrap();
    assert_eq!(
        scan.operation_behavior(),
        OperationBehavior::AlwaysCreatesDurableOperation
    );
    let schema = Value::Object(scan.output_schema().clone());
    let validator = jsonschema::validator_for(&schema).unwrap();
    let operation_id = OperationId::parse(format!("op_{}", "a".repeat(32))).unwrap();
    let payload = serde_json::to_value(OperationAccepted::new(operation_id)).unwrap();
    assert!(validator.is_valid(&payload));
}

#[test]
fn store_write_tools_have_closed_inputs_outputs_and_remain_capability_filtered() {
    let catalog = ToolCatalog::for_capabilities(&full_capabilities()).unwrap();
    let scan = catalog.tool("scan_submit").unwrap();
    assert_eq!(
        scan.input_schema()["required"],
        serde_json::json!(["idempotency_key"])
    );
    assert_eq!(
        scan.input_schema()["properties"]["idempotency_key"]["maxLength"],
        256
    );

    let create = catalog.tool("snapshot_name_create").unwrap();
    let output = Value::Object(create.output_schema().clone());
    let validator = jsonschema::validator_for(&output).unwrap();
    let named: AgentNamedSnapshot = serde_json::from_value(serde_json::json!({
        "name": "baseline",
        "named_at": "2026-08-08T00:00:00.000Z",
        "snapshot": {
            "snapshot_id": format!("snapshot:sha256:{}", "a".repeat(64)),
            "names": ["baseline"],
            "status": "completed",
            "source_kind": "scan",
            "source_attempt_id": "scan:fixture",
            "scan_id": "scan:fixture",
            "runtime_session_ids": [],
            "profile_ids": [],
            "created_at": "2026-08-08T00:00:00.000Z",
            "coverage": {
                "profiles":0,"files_discovered":0,"files_analyzed":0,"files_skipped":0,
                "dependency_sites":0,"resolved":0,"candidates":0,"external":0,
                "unresolved":0,"unsupported_syntax":0,"project_code_executed":false,
                "completeness":["syntax-complete"],"reasons":[]
            }
        }
    }))
    .unwrap();
    let envelope = SuccessEnvelope::new(
        "repository".parse().unwrap(),
        Some(
            format!("snapshot:sha256:{}", "a".repeat(64))
                .parse()
                .unwrap(),
        ),
        named,
    );
    assert!(validator.is_valid(&serde_json::to_value(envelope).unwrap()));

    let runtime = catalog.tool("runtime_trace_import_submit").unwrap();
    assert_eq!(
        runtime.input_schema()["required"],
        serde_json::json!(["idempotency_key"])
    );
    let runtime_input = Value::Object(runtime.input_schema().clone());
    let runtime_validator = jsonschema::draft202012::new(&runtime_input).unwrap();
    let common = serde_json::json!({
        "contract_version":"depgraph-mcp-tools-v1",
        "repository_id":"repository",
        "idempotency_key":"runtime-import"
    });
    for valid in [
        serde_json::json!({"trace":"{}"}),
        serde_json::json!({"trace_file":"traces/runtime.json"}),
    ] {
        let mut input = common.clone();
        input
            .as_object_mut()
            .unwrap()
            .extend(valid.as_object().unwrap().clone());
        assert!(runtime_validator.is_valid(&input));
    }
    assert!(!runtime_validator.is_valid(&common));
    let mut both = common;
    both["trace"] = serde_json::json!("{}");
    both["trace_file"] = serde_json::json!("traces/runtime.json");
    assert!(!runtime_validator.is_valid(&both));

    let read_only = ToolCatalog::for_capabilities(&DepgraphCapabilitySet::read_only()).unwrap();
    assert!(read_only.tool("scan_submit").is_none());
    assert!(read_only.tool("snapshot_name_create").is_none());
    assert!(read_only.tool("runtime_trace_import_submit").is_none());
}

#[test]
fn lifecycle_tool_inputs_and_exact_output_contracts_are_frozen() {
    let catalog = ToolCatalog::for_capabilities(&DepgraphCapabilitySet::read_only()).unwrap();
    let profile = catalog.tool("profile_plan_get").unwrap();
    let daemon = catalog.tool("daemon_get").unwrap();
    let doctor = catalog.tool("doctor_get").unwrap();

    assert_eq!(
        profile.input_schema()["properties"]["profile_budget"],
        serde_json::json!({"type":"integer","minimum":1,"maximum":32})
    );
    assert_eq!(
        profile.input_schema()["properties"]["profiles_document"]["x-depgraph-maxUtf8Bytes"],
        1_048_576
    );
    let profile_input = Value::Object(profile.input_schema().clone());
    let validator = jsonschema::draft202012::new(&profile_input).unwrap();
    let common = serde_json::json!({
        "contract_version":"depgraph-mcp-tools-v1",
        "repository_id":"repository"
    });
    assert!(validator.is_valid(&common));
    for invalid in [
        serde_json::json!({
            "contract_version":"depgraph-mcp-tools-v1","repository_id":"repository",
            "profile_budget":1,"profiles_document":"{}"
        }),
        serde_json::json!({
            "contract_version":"depgraph-mcp-tools-v1","repository_id":"repository",
            "profile_budget":1,"profiles_file":"profiles.json"
        }),
        serde_json::json!({
            "contract_version":"depgraph-mcp-tools-v1","repository_id":"repository",
            "profiles_document":"{}","profiles_file":"profiles.json"
        }),
        serde_json::json!({
            "contract_version":"depgraph-mcp-tools-v1","repository_id":"repository",
            "profiles_file":"../private.json"
        }),
    ] {
        assert!(!validator.is_valid(&invalid), "accepted {invalid}");
    }

    for (tool, definition) in [
        (profile, "AgentProfilePlan"),
        (daemon, "AgentDaemonStatus"),
        (doctor, "AgentDoctor"),
    ] {
        let output = Value::Object(tool.output_schema().clone());
        let encoded = output.to_string();
        assert!(
            encoded.contains(definition),
            "{} omitted {definition}",
            tool.name()
        );
        jsonschema::draft202012::new(&output)
            .unwrap_or_else(|error| panic!("{} output did not compile: {error}", tool.name()));
    }
    assert_ne!(profile.output_schema(), daemon.output_schema());
    assert_ne!(daemon.output_schema(), doctor.output_schema());
}

#[test]
fn canonical_catalog_matches_checked_in_golden() {
    let catalog = ToolCatalog::for_capabilities(&full_capabilities()).unwrap();
    let fixture_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let json_path = fixture_dir.join("mcp_tool_catalog_v1.json");
    let digest_path = fixture_dir.join("mcp_tool_catalog_v1.sha256");

    if std::env::var_os("DEPGRAPH_UPDATE_CATALOG_GOLDEN").is_some() {
        std::fs::create_dir_all(&fixture_dir).unwrap();
        std::fs::write(&json_path, catalog.canonical_bytes()).unwrap();
        std::fs::write(&digest_path, format!("{}\n", catalog.sha256())).unwrap();
    }

    assert_eq!(std::fs::read(json_path).unwrap(), catalog.canonical_bytes());
    assert_eq!(
        std::fs::read_to_string(digest_path).unwrap().trim(),
        catalog.sha256()
    );
}

fn full_capabilities() -> DepgraphCapabilitySet {
    DepgraphCapabilitySet::try_new([
        DepgraphCapability::Read,
        DepgraphCapability::StoreWrite,
        DepgraphCapability::RepositoryWrite,
        DepgraphCapability::DaemonControl,
        DepgraphCapability::ProjectExec,
    ])
    .unwrap()
}

fn assert_closed_object_nodes(value: &Value, tool: &str, kind: &str) {
    match value {
        Value::Object(object) => {
            if object.get("type").and_then(Value::as_str) == Some("object") {
                assert_eq!(
                    object.get("additionalProperties"),
                    Some(&Value::Bool(false)),
                    "{tool} {kind} has an open object schema: {object:?}"
                );
            }
            for nested in object.values() {
                assert_closed_object_nodes(nested, tool, kind);
            }
        }
        Value::Array(values) => {
            for nested in values {
                assert_closed_object_nodes(nested, tool, kind);
            }
        }
        _ => {}
    }
}

#[test]
fn issue_542_dependency_lists_advertise_detail_and_one_output_shape_per_detail() {
    let catalog = ToolCatalog::for_capabilities(&DepgraphCapabilitySet::read_only()).unwrap();
    for name in ["graph_dependencies_list", "graph_dependents_list"] {
        let tool = catalog.tool(name).expect("dependency tool");
        let detail = &tool.input_schema()["properties"]["detail"];
        assert_eq!(detail["type"], "string", "{name}");
        assert_eq!(
            detail["enum"],
            json!(["paths", "summary", "full"]),
            "{name}"
        );
        assert_eq!(detail["default"], "full", "{name}");
        let description = detail["description"].as_str().expect("detail description");
        for expected in ["common", "evidence_count", "paths", "byte-identical"] {
            assert!(
                description.contains(expected),
                "{name} detail description lacks {expected}: {description}"
            );
        }
        assert!(
            !tool.input_schema()["required"]
                .as_array()
                .unwrap()
                .contains(&json!("detail")),
            "{name} detail is optional"
        );
        for expected in ["agent_evidence_list", "agent_sites_list", "detail"] {
            assert!(
                tool.description().contains(expected),
                "{name} description lacks {expected}: {}",
                tool.description()
            );
        }

        let output = tool.output_schema();
        let definitions = output["$defs"].as_object().expect("output definitions");
        let branches = definitions["AgentDependenciesOutput"]["oneOf"]
            .as_array()
            .expect("one output branch per detail");
        assert_eq!(branches.len(), 3, "{name}");
        for definition in [
            "AgentDependenciesResponse",
            "AgentDependenciesSummaryResponse",
            "AgentDependencyPathsResponse",
        ] {
            assert!(
                branches
                    .iter()
                    .any(|branch| branch["$ref"] == format!("#/$defs/{definition}")),
                "{name} output lacks {definition}"
            );
        }
        assert!(
            definitions["AgentDependenciesResponse"]["properties"]
                .get("detail")
                .is_none(),
            "{name} full output keeps the legacy shape"
        );
    }
}

#[test]
fn issue_541_dependency_lists_advertise_edge_kind_selection() {
    let catalog = ToolCatalog::for_capabilities(&DepgraphCapabilitySet::read_only()).unwrap();
    for name in ["graph_dependencies_list", "graph_dependents_list"] {
        let tool = catalog.tool(name).expect("dependency tool");
        let properties = &tool.input_schema()["properties"];
        let required = tool.input_schema()["required"].as_array().unwrap();
        for field in ["edge_kinds", "structural_edges"] {
            assert!(
                !required.contains(&json!(field)),
                "{name} {field} is optional"
            );
        }

        let edge_kinds = &properties["edge_kinds"];
        assert_eq!(edge_kinds["type"], "array", "{name}");
        assert_eq!(edge_kinds["maxItems"], MAX_DEPENDENCY_EDGE_KINDS, "{name}");
        assert_eq!(edge_kinds["uniqueItems"], true, "{name}");
        assert_eq!(edge_kinds["items"]["type"], "string", "{name}");
        assert_eq!(
            edge_kinds["items"]["pattern"], "^[a-z][a-z0-9._:-]*$",
            "{name}"
        );
        assert_eq!(edge_kinds["items"]["maxLength"], 64, "{name}");
        let description = edge_kinds["description"].as_str().unwrap();
        for expected in [
            "Empty or omitted",
            "structural_edges",
            "allowlist alone decides",
            "explicit structural_edges=exclude",
            "INVALID_ARGUMENT",
            "traversed_edges",
        ] {
            assert!(
                description.contains(expected),
                "{name} edge_kinds description lacks {expected}: {description}"
            );
        }

        let structural = &properties["structural_edges"];
        assert_eq!(structural["type"], "string", "{name}");
        assert_eq!(structural["enum"], json!(["include", "exclude"]), "{name}");
        assert_eq!(
            structural["default"],
            DEFAULT_STRUCTURAL_EDGE_SELECTION.as_str(),
            "{name}"
        );
        let description = structural["description"].as_str().unwrap();
        for expected in [
            "contains",
            "declares",
            "generated_from",
            "Defaults to exclude",
            "include",
            "edge_kinds",
            "cursor",
        ] {
            assert!(
                description.contains(expected),
                "{name} structural_edges description lacks {expected}: {description}"
            );
        }

        for expected in [
            "contains",
            "declares",
            "generated_from",
            "excluded by default",
            "structural_edges=include",
            "edge_kinds",
        ] {
            assert!(
                tool.description().contains(expected),
                "{name} description lacks {expected}: {}",
                tool.description()
            );
        }
        assert!(
            !tool.description().contains("included by default"),
            "{name} description still claims the old default"
        );
    }
}

/// Collects every `format` keyword with its JSON pointer (Issue #568).
fn collect_formats(value: &Value, pointer: &str, found: &mut Vec<(String, String)>) {
    match value {
        Value::Object(object) => {
            if let Some(format) = object.get("format").and_then(Value::as_str) {
                found.push((pointer.to_owned(), format.to_owned()));
            }
            for (key, child) in object {
                collect_formats(child, &format!("{pointer}/{key}"), found);
            }
        }
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                collect_formats(item, &format!("{pointer}/{index}"), found);
            }
        }
        _ => {}
    }
}

#[test]
fn issue_568_tool_schemas_use_only_standard_formats_and_bound_integers() {
    let catalog = ToolCatalog::for_capabilities(&full_capabilities()).unwrap();
    let mut integers = 0_usize;
    for tool in catalog.tools() {
        for (side, schema) in [
            ("input", tool.input_schema()),
            ("output", tool.output_schema()),
        ] {
            let schema = Value::Object(schema.clone());
            let mut found = Vec::new();
            collect_formats(&schema, "#", &mut found);
            for (pointer, format) in &found {
                assert!(
                    STANDARD_JSON_SCHEMA_FORMATS.contains(&format.as_str()),
                    "{} {side} schema uses non-standard format {format:?} at {pointer}",
                    tool.name()
                );
            }
            integers += count_bounded_integers(&schema);
        }
    }
    assert!(integers > 0, "the catalog has integer fields with bounds");

    // Ranges that the removed formats implied are kept as bounds.
    let nodes = catalog.tool("agent_nodes_list").unwrap();
    let output = Value::Object(nodes.output_schema().clone());
    let total_items = find_property(&output, "total_items").expect("page output has total_items");
    assert_eq!(total_items["minimum"], 0, "{total_items}");
    assert_eq!(total_items["maximum"], u64::MAX, "{total_items}");
}

fn count_bounded_integers(value: &Value) -> usize {
    match value {
        Value::Object(object) => {
            let own = usize::from(
                object.get("type") == Some(&json!("integer"))
                    && object.contains_key("minimum")
                    && object.contains_key("maximum"),
            );
            own + object.values().map(count_bounded_integers).sum::<usize>()
        }
        Value::Array(items) => items.iter().map(count_bounded_integers).sum(),
        _ => 0,
    }
}

fn find_property<'a>(value: &'a Value, name: &str) -> Option<&'a Value> {
    match value {
        Value::Object(object) => object
            .get("properties")
            .and_then(|properties| properties.get(name))
            .or_else(|| object.values().find_map(|child| find_property(child, name))),
        Value::Array(items) => items.iter().find_map(|item| find_property(item, name)),
        _ => None,
    }
}
