use std::path::PathBuf;

use depgraph_core::{DepgraphCapability, DepgraphCapabilitySet};
use depgraph_mcp_tools::{
    ALL_CLI_ACTIONS, CapabilityProfile, CliAction, OperationAccepted, OperationBehavior,
    OperationId, ToolAuthorization, ToolCatalog,
};

use serde_json::Value;

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
    "graph_cycles_list",
    "graph_dependencies_list",
    "graph_dependents_list",
    "graph_export",
    "graph_impact_get",
    "graph_path_get",
    "graph_query",
    "graph_unresolved_list",
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
    assert_eq!(catalog.tools().len(), 31);
}

#[test]
fn every_cli_leaf_action_has_a_catalog_mapping() {
    assert_eq!(ALL_CLI_ACTIONS.len(), 23);
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
