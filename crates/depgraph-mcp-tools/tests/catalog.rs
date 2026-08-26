use std::path::PathBuf;

use depgraph_core::{DepgraphCapability, DepgraphCapabilitySet};
use depgraph_mcp_tools::{
    ALL_CLI_ACTIONS, AgentNamedSnapshot, CapabilityProfile, CliAction, IdempotencyKey,
    MAX_IDEMPOTENCY_KEY_CHARS, OperationAccepted, OperationBehavior, OperationId, SuccessEnvelope,
    ToolAuthorization, ToolCatalog,
};

use serde_json::Value;

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
    assert_eq!(catalog.tools().len(), 38);
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
            "contract_version",
            "repository_id",
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
        serde_json::json!(["contract_version", "repository_id", "idempotency_key"])
    );
    assert_eq!(
        stop.input_schema()["required"],
        serde_json::json!(["contract_version", "repository_id", "idempotency_key"])
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
                "environments",
                "limit",
                "max_traversal",
                "phases",
                "profiles",
                "repository_id",
                "selector",
                "sessions",
                "snapshot",
                "transitive",
            ]
        );
        assert_eq!(tool.operation_behavior(), OperationBehavior::Immediate);
        assert_eq!(
            success_output_schema(tool.output_schema())["properties"]["result"]["$ref"],
            "#/$defs/AgentDependenciesResponse"
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
        "#/$defs/AgentPathResponse"
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
    for field in ["contract_version", "repository_id", "from", "to"] {
        assert!(required.contains(&Value::String(field.to_owned())));
    }

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
    assert_eq!(
        context.input_schema()["required"],
        serde_json::json!(["contract_version", "repository_id"])
    );
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
        serde_json::json!(["contract_version", "repository_id", "idempotency_key"])
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
        serde_json::json!(["contract_version", "repository_id", "idempotency_key"])
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
