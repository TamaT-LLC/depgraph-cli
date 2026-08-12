use std::{path::Path, process::Command};

use depgraph_mcp_tools::{
    AgentArtifactId, AgentContext, AgentError, AgentLocator, AgentNode, AgentNodeSummary,
    AgentOperation, AgentSourceSpan, MCP_TOOLS_SCHEMA_ID, Page, RepositoryRelativePath,
    TaskAccepted, canonical_schema_bytes, canonical_schema_sha256, mcp_tools_v1_schema,
};
use serde_json::{Value, json};

const CHECKED_IN_SCHEMA: &[u8] =
    include_bytes!("../../../schemas/depgraph-mcp-tools-v1.schema.json");
const CHECKED_IN_DIGEST: &[u8] = include_bytes!("fixtures/depgraph-mcp-tools-v1.schema.sha256");
const OPERATION_ID: &str = "op_0123456789abcdef0123456789abcdef";
const SNAPSHOT_ID: &str =
    "snapshot:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn schema_value() -> Value {
    serde_json::to_value(mcp_tools_v1_schema()).expect("schema is serializable")
}

#[test]
fn issue_305_shared_schema_publishes_new_closed_response_definitions() {
    let schema = schema_value();
    let definitions = schema["$defs"].as_object().expect("schema definitions");

    for definition in [
        "AgentSnapshotDiffResponse",
        "AgentPolicyEvaluationResponse",
        "AgentGraphExportResponse",
    ] {
        let value = definitions
            .get(definition)
            .unwrap_or_else(|| panic!("missing {definition} definition"));
        assert_eq!(value["additionalProperties"], false);
    }
}

#[test]
fn issue_314_shared_schema_publishes_repository_init_outcome_and_success_envelope() {
    let schema = schema_value();
    let definitions = schema["$defs"].as_object().expect("schema definitions");
    let outcome = definitions
        .get("AgentRepositoryInitOutcome")
        .expect("repository init outcome definition");
    assert_eq!(outcome["additionalProperties"], false);
    assert_eq!(
        outcome["properties"]["output_path"]["const"],
        ".depgraph.toml"
    );
    assert!(definitions.values().any(|definition| {
        definition["properties"]["result"]["$ref"] == "#/$defs/AgentRepositoryInitOutcome"
    }));
}

#[test]
fn issue_310_shared_schema_publishes_the_closed_operation_projection() {
    let schema = schema_value();
    let definitions = schema["$defs"].as_object().expect("schema definitions");
    for definition in [
        "AgentOperation",
        "AgentOperationProgress",
        "AgentOperationTimestamps",
        "AgentOperationRetention",
    ] {
        assert_eq!(
            definitions[definition]["additionalProperties"], false,
            "{definition} is not closed"
        );
    }
    let valid = json!({
        "operation_id": OPERATION_ID,
        "status": "queued",
        "progress": {"completed_units": 0, "total_units": 1},
        "timestamps": {"created_at_ms": 1000, "updated_at_ms": 1000},
        "retention": {"execution_deadline_ms": 2000, "retain_until_ms": 3000}
    });
    let wrapper = json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$defs": schema["$defs"].clone(),
        "$ref": "#/$defs/AgentOperation"
    });
    let validator = jsonschema::draft202012::new(&wrapper).unwrap();
    assert!(validator.is_valid(&valid));
    assert!(serde_json::from_value::<AgentOperation>(valid).is_ok());

    let terminal_output = &definitions["PortableTerminalOutput"];
    assert_eq!(
        terminal_output["anyOf"]
            .as_array()
            .expect("terminal output is a closed union")
            .len(),
        5
    );
    let terminal_schema = terminal_output.to_string();
    assert!(!terminal_schema.contains("AgentOperation"));
    let terminal_branches = terminal_output["anyOf"]
        .as_array()
        .expect("terminal output is a closed union")
        .iter()
        .map(|branch| {
            branch["$ref"]
                .as_str()
                .and_then(|reference| reference.strip_prefix("#/$defs/"))
                .and_then(|definition| definitions.get(definition))
                .expect("terminal output branch resolves to a definition")
                .to_string()
        })
        .collect::<String>();
    assert!(terminal_branches.contains("AgentScanOutcome"));
    assert!(terminal_branches.contains("AgentRuntimeOutcome"));
    assert!(terminal_branches.contains("AgentExportOutcome"));
    assert!(terminal_branches.contains("AgentBuildOutcome"));
}

#[test]
fn issue_316_shared_schema_closes_build_outcome_and_host_risk() {
    let schema = schema_value();
    let definitions = schema["$defs"].as_object().expect("schema definitions");
    for definition in ["AgentBuildOutcome", "AgentBuildHostRisk"] {
        assert_eq!(definitions[definition]["additionalProperties"], false);
    }
    assert_eq!(
        definitions["AgentBuildOutcome"]["properties"]["mutation_diagnostics"]["maxItems"],
        depgraph_mcp_tools::MAX_AGENT_BUILD_MUTATION_DIAGNOSTICS
    );
    assert!(
        definitions["AgentBuildOutcome"]["properties"]["snapshot_id"]["anyOf"]
            .as_array()
            .expect("build snapshot ID is nullable")
            .iter()
            .any(|branch| branch["type"] == "null")
    );
    assert_eq!(
        definitions["AgentBuildHostRisk"]["required"],
        json!([
            "human_confirmation_required",
            "acknowledgement_is_not_authorization",
            "source_mutation_possible",
            "network_access_possible"
        ])
    );
}

#[test]
fn issue_313_schema_closes_runtime_import_outcome_and_terminal_union() {
    let schema = schema_value();
    let definitions = schema["$defs"].as_object().expect("schema definitions");
    let outcome = &definitions["AgentRuntimeOutcome"];
    assert_eq!(outcome["additionalProperties"], false);
    assert_eq!(
        outcome["required"],
        json!([
            "import_id",
            "session_id",
            "snapshot_id",
            "status",
            "deduplicated"
        ])
    );
    assert_eq!(
        definitions["AgentRuntimeStatus"]["enum"],
        json!(["completed", "partial"])
    );
    assert!(
        definitions["PortableTerminalOutput"]["anyOf"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|branch| branch["$ref"].as_str())
            .filter_map(|reference| reference.strip_prefix("#/$defs/"))
            .filter_map(|definition| definitions.get(definition))
            .any(|branch| branch.to_string().contains("AgentRuntimeOutcome"))
    );
}

#[test]
fn issue_305_schema_closes_artifact_enums_scalars_and_collection_bounds() {
    let schema = schema_value();
    let definitions = schema["$defs"].as_object().unwrap();
    assert_eq!(
        definitions["SnapshotId"]["pattern"],
        r"^snapshot:sha256:[0-9a-f]{64}$"
    );
    assert_eq!(
        definitions["SnapshotDiffCollectionDigest"]["pattern"],
        r"^snapshot-diff-collection:sha256:[0-9a-f]{64}$"
    );
    assert_eq!(
        definitions["PolicyConfigDigest"]["pattern"],
        r"^policy-config:sha256:[0-9a-f]{64}$"
    );
    assert_eq!(definitions["Sha256Digest"]["pattern"], r"^[0-9a-f]{64}$");
    for (definition, max_bytes) in [
        ("AgentArtifactId", 1_024_u64),
        ("AgentPolicyText", 4_096_u64),
        (
            "AgentGraphExportContent",
            u64::from(depgraph_mcp_tools::MAX_PAGE_BYTES),
        ),
    ] {
        assert_eq!(
            definitions[definition]["x-depgraph-maxUtf8Bytes"], max_bytes,
            "missing UTF-8 byte bound for {definition}"
        );
        assert!(
            definitions[definition]["description"]
                .as_str()
                .is_some_and(|description| description.contains("UTF-8 bytes")),
            "missing UTF-8 byte description for {definition}"
        );
        assert!(
            definitions[definition].get("maxLength").is_none(),
            "JSON Schema maxLength counts Unicode characters, not UTF-8 bytes"
        );
    }
    assert_eq!(
        definitions["AgentSnapshotDiffResponse"]["properties"]["changes"]["maxItems"],
        50_000
    );
    for field in ["api_changes", "violations", "annotations"] {
        assert_eq!(
            definitions["AgentPolicyEvaluationResponse"]["properties"][field]["maxItems"], 50_000,
            "missing policy {field} maxItems"
        );
    }

    let validator_for = |definition: &str| {
        let wrapper = json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$defs": schema["$defs"].clone(),
            "$ref": format!("#/$defs/{definition}"),
        });
        jsonschema::draft202012::new(&wrapper).unwrap()
    };
    let over_byte_limit = "あ".repeat(342);
    assert!(validator_for("AgentArtifactId").is_valid(&json!(&over_byte_limit)));
    assert!(
        serde_json::from_value::<AgentArtifactId>(json!(&over_byte_limit)).is_err(),
        "Serde must enforce the authoritative UTF-8 byte bound"
    );
    let digest = "a".repeat(64);
    let diff = validator_for("AgentSnapshotDiffResponse");
    let valid_diff = json!({
        "schema_version":"depgraph-snapshot-diff-service-v1",
        "from_snapshot_id":SNAPSHOT_ID,
        "to_snapshot_id":SNAPSHOT_ID,
        "total_changes":0,
        "empty":true,
        "changes":[],
        "collection_digest":format!("snapshot-diff-collection:sha256:{digest}")
    });
    assert!(diff.is_valid(&valid_diff));
    for (field, value) in [
        ("schema_version", json!("v1")),
        ("to_snapshot_id", json!("current")),
        ("collection_digest", json!(digest.clone())),
    ] {
        let mut invalid = valid_diff.clone();
        invalid[field] = value;
        assert!(!diff.is_valid(&invalid), "schema accepted invalid {field}");
    }

    let change = validator_for("AgentSnapshotDiffChange");
    assert!(!change.is_valid(&json!({
        "record_type":"raw_record",
        "change_type":"changed",
        "id":"node:a",
        "changed_fields":[]
    })));
    assert!(!change.is_valid(&json!({
        "record_type":"node",
        "change_type":"changed",
        "id":"node:a",
        "changed_fields":(0..=256).map(|index| format!("field_{index}")).collect::<Vec<_>>()
    })));

    let violation = validator_for("AgentPolicyViolation");
    assert!(!violation.is_valid(&json!({
        "id":format!("policy-violation:sha256:{digest}"),
        "rule_id":"rule-a",
        "severity":"fatal",
        "message":"bounded",
        "source_id":"node:a",
        "target_id":"node:b",
        "suppressed":false
    })));

    let export = validator_for("AgentGraphExportResponse");
    let valid_export = json!({
        "schema_version":"depgraph-graph-export-service-v1",
        "snapshot_id":SNAPSHOT_ID,
        "format":"json",
        "media_type":"application/json",
        "content":"{}",
        "content_sha256":digest,
        "output_bytes":2,
        "node_count":0,
        "edge_count":0
    });
    assert!(export.is_valid(&valid_export));
    for (field, value) in [
        ("format", json!("raw")),
        ("media_type", json!("text/plain")),
        ("content_sha256", json!("A".repeat(64))),
        ("node_count", json!(50_001)),
        ("edge_count", json!(100_001)),
    ] {
        let mut invalid = valid_export.clone();
        invalid[field] = value;
        assert!(
            !export.is_valid(&invalid),
            "schema accepted invalid {field}"
        );
    }
}

fn inject_unknown(mut instance: Value) -> Value {
    instance
        .as_object_mut()
        .expect("representative value must be an object")
        .insert("unexpected".to_owned(), Value::Bool(true));
    instance
}

fn assert_definition_rejects_unknown(
    schema: &Value,
    definition: &str,
    case: &str,
    instance: Value,
) {
    let wrapper = json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$defs": schema["$defs"].clone(),
        "$ref": format!("#/$defs/{definition}"),
    });
    let validator = jsonschema::draft202012::new(&wrapper)
        .unwrap_or_else(|error| panic!("{definition} schema did not compile: {error}"));
    let invalid = inject_unknown(instance);
    assert!(
        !validator.is_valid(&invalid),
        "{case} schema accepted an unknown field: {invalid}"
    );
}

#[test]
fn generated_schema_is_valid_draft_2020_12_and_rejects_unknown_fields() {
    let schema = schema_value();
    assert_eq!(schema["$id"], json!(MCP_TOOLS_SCHEMA_ID));
    assert!(
        jsonschema::draft202012::meta::is_valid(&schema),
        "generated catalog must be a valid Draft 2020-12 schema"
    );
    jsonschema::draft202012::new(&schema).expect("generated catalog compiles");

    let cases = [
        (
            "CommonRequest",
            "CommonRequest",
            json!({"contract_version":"depgraph-mcp-tools-v1","repository_id":"repo-1"}),
        ),
        (
            "SnapshotSelector",
            "SnapshotSelector::Current",
            json!({"kind":"current"}),
        ),
        (
            "SnapshotSelector",
            "SnapshotSelector::Name",
            json!({"kind":"name","name":"baseline"}),
        ),
        (
            "SnapshotSelector",
            "SnapshotSelector::Id",
            json!({"kind":"id","snapshot_id":SNAPSHOT_ID}),
        ),
        (
            "PageRequest",
            "PageRequest",
            json!({"max_items":100,"max_bytes":1048576}),
        ),
        (
            "AgentSourcePosition",
            "AgentSourcePosition",
            json!({"line":1,"column":2}),
        ),
        (
            "AgentSourceSpan",
            "AgentSourceSpan",
            json!({"path":"src/lib.rs","start":{"line":1,"column":2},"end":{"line":3,"column":4}}),
        ),
        (
            "AgentEvidence",
            "AgentEvidence",
            json!({"kind":"semantic","extractor":"rust-analyzer","extractor_version":"0.0.330"}),
        ),
        (
            "AgentNode",
            "AgentNode",
            json!({"id":"node:src","kind":"module","locator":"repo://src/lib.rs"}),
        ),
        (
            "AgentNodeSummary",
            "AgentNodeSummary",
            json!({"id":"node:src","kind":"module","locator":"repo://src/lib.rs","display_name":"crate::lib"}),
        ),
        (
            "AgentContext",
            "AgentContext::Unavailable",
            json!({"repository_id":"repo-1","enabled_capabilities":["read"],"snapshot":{"available":false}}),
        ),
        (
            "AgentSite",
            "AgentSite",
            json!({"id":"site:1","source_id":"node:src","kind":"import","specifier":"crate::dependency","resolution_status":"resolved","profile_id":"profile:default","target_ids":[],"evidence":[]}),
        ),
        (
            "AgentEdge",
            "AgentEdge",
            json!({"id":"edge:1","source_id":"node:src","target_id":"node:dependency","kind":"imports","phase":"semantic","resolution_status":"resolved","precision":"exact","profile_id":"profile:default","evidence":[]}),
        ),
        (
            "AgentPathStep",
            "AgentPathStep",
            json!({
                "source":{"id":"node:src","kind":"module","locator":"repo://src/lib.rs"},
                "edge":{"id":"edge:1","source_id":"node:src","target_id":"node:dependency","kind":"imports","phase":"semantic","resolution_status":"resolved","precision":"exact","profile_id":"profile:default","evidence":[]},
                "target":{"id":"node:dependency","kind":"module","locator":"repo://src/dependency.rs"}
            }),
        ),
        (
            "AgentDependenciesResponse",
            "AgentDependenciesResponse",
            json!({
                "root":{"id":"node:src","kind":"module","locator":"repo://src/lib.rs"},
                "direction":"outgoing",
                "transitive":false,
                "traversal_complete":true,
                "traversed_edges":0,
                "edges":{"items":[],"returned_items":0,"total_items":0,"complete":true}
            }),
        ),
        (
            "AgentPathResponse",
            "AgentPathResponse",
            json!({
                "from":{"id":"node:src","kind":"module","locator":"repo://src/lib.rs"},
                "to":{"id":"node:dependency","kind":"module","locator":"repo://src/dependency.rs"},
                "path_found":false,
                "traversed_edges":0,
                "steps":[]
            }),
        ),
        (
            "AgentChangedSince",
            "AgentChangedSince",
            json!({
                "requested_ref":"HEAD",
                "resolved_ref":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "merge_base":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "head":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "changed_paths":1,
                "mapped_nodes":1
            }),
        ),
        (
            "AgentImpact",
            "AgentImpact",
            json!({
                "node":{"id":"node:src","kind":"module","locator":"repo://src/lib.rs"},
                "depth":0,
                "changed_node_id":"node:src",
                "dependency_path":[]
            }),
        ),
        (
            "AgentImpactResponse",
            "AgentImpactResponse",
            json!({
                "root":{"id":"node:src","kind":"module","locator":"repo://src/lib.rs"},
                "root_impacted":true,
                "impacts":{"items":[],"returned_items":0,"total_items":0,"complete":true}
            }),
        ),
        (
            "AgentCycle",
            "AgentCycle",
            json!({"level":"file","node_ids":["node:src","node:src"]}),
        ),
        (
            "AgentUnresolved",
            "AgentUnresolved",
            json!({
                "site":{"id":"site:1","source_id":"node:src","kind":"import","specifier":"crate::dependency","resolution_status":"unresolved","profile_id":"profile:default","target_ids":[],"evidence":[]},
                "phases":["source"],
                "effective_profile_id":"profile:default",
                "correlation_status":"unobserved",
                "observed_difference_reasons":["not_observed"]
            }),
        ),
        (
            "AgentSnapshot",
            "AgentSnapshot::Available",
            json!({"availability":"available","snapshot_id":SNAPSHOT_ID,"name":"baseline"}),
        ),
        (
            "AgentSnapshot",
            "AgentSnapshot::Unavailable",
            json!({"availability":"unavailable"}),
        ),
        (
            "Page",
            "Page<AgentNode>",
            json!({"items":[],"returned_items":0,"total_items":0,"complete":true}),
        ),
        (
            "SuccessEnvelope",
            "SuccessEnvelope<AgentNode>",
            json!({"contract_version":"depgraph-mcp-tools-v1","repository_id":"repo-1","result":{"id":"node:src","kind":"module","locator":"repo://src/lib.rs"}}),
        ),
        (
            "AgentErrorDetails",
            "AgentErrorDetails::RequiredCapability",
            json!({"kind":"required_capability","capability":"read"}),
        ),
        (
            "AgentErrorDetails",
            "AgentErrorDetails::ResourceLimit",
            json!({"kind":"resource_limit","limit":"page_items","maximum":1000}),
        ),
        (
            "AgentErrorDetails",
            "AgentErrorDetails::Operation",
            json!({"kind":"operation","operation_id":OPERATION_ID}),
        ),
        (
            "AgentError",
            "AgentError",
            json!({"code":"OPERATION_NOT_READY","category":"state","retryable":true,"remediation":"poll_operation"}),
        ),
        (
            "ErrorEnvelope",
            "ErrorEnvelope",
            json!({"contract_version":"depgraph-mcp-tools-v1","repository_id":"repo-1","error":{"code":"OPERATION_NOT_READY","category":"state","retryable":true,"remediation":"poll_operation"}}),
        ),
        (
            "OperationRecoveryTools",
            "OperationRecoveryTools",
            json!({"status":"operation_get","result":"operation_result","cancel":"operation_cancel"}),
        ),
        (
            "OperationAccepted",
            "OperationAccepted",
            json!({"contract_version":"depgraph-mcp-tools-v1","result_type":"operation_accepted","operation_id":OPERATION_ID,"status":"queued","recovery":{"status":"operation_get","result":"operation_result","cancel":"operation_cancel"}}),
        ),
        (
            "TaskAccepted",
            "TaskAccepted",
            json!({"resultType":"task","taskId":OPERATION_ID,"status":"working","createdAtMs":1700000000000_u64,"updatedAtMs":1700000000100_u64,"pollIntervalMs":1000,"ttlMs":604800000_u64}),
        ),
        (
            "DurableSubmitResult",
            "DurableSubmitResult::Baseline",
            json!({"contract_version":"depgraph-mcp-tools-v1","result_type":"operation_accepted","operation_id":OPERATION_ID,"status":"queued","recovery":{"status":"operation_get","result":"operation_result","cancel":"operation_cancel"}}),
        ),
        (
            "DurableSubmitResult",
            "DurableSubmitResult::Task",
            json!({"resultType":"task","taskId":OPERATION_ID,"status":"working","createdAtMs":1700000000000_u64,"updatedAtMs":1700000000100_u64,"pollIntervalMs":1000,"ttlMs":604800000_u64}),
        ),
    ];
    for (definition, case, instance) in cases {
        assert_definition_rejects_unknown(&schema, definition, case, instance);
    }
}

#[test]
fn generated_schema_matches_recovery_and_snapshot_semantic_invariants() {
    let schema = schema_value();
    let validator_for = |definition: &str| {
        let wrapper = json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$defs": schema["$defs"].clone(),
            "$ref": format!("#/$defs/{definition}"),
        });
        jsonschema::draft202012::new(&wrapper)
            .unwrap_or_else(|error| panic!("{definition} schema did not compile: {error}"))
    };

    let recovery = validator_for("OperationRecoveryTools");
    assert!(recovery.is_valid(&json!({
        "status":"operation_get",
        "result":"operation_result",
        "cancel":"operation_cancel"
    })));
    assert!(!recovery.is_valid(&json!({
        "status":"operation_result",
        "result":"operation_get",
        "cancel":"operation_cancel"
    })));

    let snapshot = validator_for("AgentSnapshot");
    assert!(snapshot.is_valid(&json!({
        "availability":"available",
        "snapshot_id":SNAPSHOT_ID,
        "name":"baseline"
    })));
    assert!(snapshot.is_valid(&json!({"availability":"unavailable"})));
    for invalid in [
        json!({"availability":"available"}),
        json!({"availability":"unavailable","snapshot_id":SNAPSHOT_ID}),
        json!({"availability":"unavailable","name":"baseline"}),
    ] {
        assert!(
            !snapshot.is_valid(&invalid),
            "snapshot schema accepted {invalid}"
        );
    }
}

#[test]
fn issue_303_schema_closes_cycle_and_unresolved_enums_and_bounds() {
    let schema = schema_value();
    let validator_for = |definition: &str| {
        let wrapper = json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$defs": schema["$defs"].clone(),
            "$ref": format!("#/$defs/{definition}"),
        });
        jsonschema::draft202012::new(&wrapper).unwrap()
    };
    let cycle = validator_for("AgentCycle");
    assert!(cycle.is_valid(&json!({
        "level":"file", "node_ids":["node:src","node:src"]
    })));
    assert!(!cycle.is_valid(&json!({
        "level":"directory", "node_ids":["node:src","node:src"]
    })));
    assert!(!cycle.is_valid(&json!({
        "level":"file", "node_ids":[]
    })));

    let unresolved = validator_for("AgentUnresolved");
    let sample = json!({
        "site":{"id":"site:1","source_id":"node:src","kind":"import","specifier":"crate::dependency","resolution_status":"unresolved","profile_id":"profile:default","target_ids":[],"evidence":[]},
        "phases":["source"],
        "correlation_status":"unobserved",
        "observed_difference_reasons":["not_observed"]
    });
    assert!(unresolved.is_valid(&sample));
    let mut invalid = sample.clone();
    invalid["correlation_status"] = json!("private");
    assert!(!unresolved.is_valid(&invalid));
    let mut invalid = sample.clone();
    invalid["phases"] = json!(["source", "semantic", "build", "runtime", "source"]);
    assert!(!unresolved.is_valid(&invalid));
    let mut invalid = sample;
    invalid["observed_difference_reasons"] = json!(["private"]);
    assert!(!unresolved.is_valid(&invalid));
}

#[test]
fn schema_preflight_requires_authoritative_semantic_deserialization() {
    let schema = schema_value();
    let schema_accepts = |definition: &str, instance: &Value| {
        let wrapper = json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$defs": schema["$defs"].clone(),
            "$ref": format!("#/$defs/{definition}"),
        });
        let validator = jsonschema::draft202012::new(&wrapper)
            .unwrap_or_else(|error| panic!("{definition} schema did not compile: {error}"));
        validator.is_valid(instance)
    };

    let cases = [
        (
            "AgentError",
            json!({"code":"OPERATION_NOT_READY","category":"input","retryable":true,"remediation":"poll_operation"}),
        ),
        (
            "AgentSourceSpan",
            json!({"path":"src/lib.rs","start":{"line":3,"column":1},"end":{"line":2,"column":1}}),
        ),
        (
            "Page",
            json!({"items":[],"returned_items":1,"total_items":1,"complete":true}),
        ),
        (
            "TaskAccepted",
            json!({"resultType":"task","taskId":OPERATION_ID,"status":"working","createdAtMs":1700000000100_u64,"updatedAtMs":1700000000000_u64,"pollIntervalMs":1000,"ttlMs":604800000_u64}),
        ),
    ];
    for (definition, instance) in cases {
        assert!(schema_accepts(definition, &instance));
        let rejected = match definition {
            "AgentError" => serde_json::from_value::<AgentError>(instance).is_err(),
            "AgentSourceSpan" => serde_json::from_value::<AgentSourceSpan>(instance).is_err(),
            "Page" => serde_json::from_value::<Page<AgentNode>>(instance).is_err(),
            "TaskAccepted" => serde_json::from_value::<TaskAccepted>(instance).is_err(),
            _ => unreachable!("closed semantic-difference corpus"),
        };
        assert!(
            rejected,
            "{definition} semantic validator accepted invalid data"
        );
    }

    let byte_oversized_component = Value::String("é".repeat(255));
    assert!(schema_accepts(
        "RepositoryRelativePath",
        &byte_oversized_component
    ));
    assert!(serde_json::from_value::<RepositoryRelativePath>(byte_oversized_component).is_err());

    let byte_oversized_locator = Value::String("é".repeat(1024));
    assert!(schema_accepts("AgentLocator", &byte_oversized_locator));
    assert!(serde_json::from_value::<AgentLocator>(byte_oversized_locator).is_err());
}

fn assert_all_object_schemas_are_closed(value: &Value, path: &str, objects: &mut usize) {
    match value {
        Value::Object(object) => {
            if object.get("type") == Some(&Value::String("object".to_owned())) {
                *objects += 1;
                assert_eq!(
                    object.get("additionalProperties"),
                    Some(&Value::Bool(false)),
                    "object schema at {path} is not closed"
                );
            }
            for (key, child) in object {
                assert_all_object_schemas_are_closed(child, &format!("{path}/{key}"), objects);
            }
        }
        Value::Array(array) => {
            for (index, child) in array.iter().enumerate() {
                assert_all_object_schemas_are_closed(child, &format!("{path}/{index}"), objects);
            }
        }
        _ => {}
    }
}

#[test]
fn every_generated_object_schema_has_additional_properties_false() {
    let schema = schema_value();
    let mut objects = 0;
    assert_all_object_schemas_are_closed(&schema, "#", &mut objects);
    assert_eq!(objects, 159, "review newly added object schemas explicitly");
}

#[test]
fn schema_bytes_digest_checked_in_file_and_generation_policy_are_exact() {
    let first = canonical_schema_bytes();
    let second = canonical_schema_bytes();
    assert_eq!(first, second, "canonical bytes changed across runs");

    let first_digest = canonical_schema_sha256();
    let second_digest = canonical_schema_sha256();
    assert_eq!(
        first_digest, second_digest,
        "schema digest changed across runs"
    );
    if std::env::var_os("DEPGRAPH_UPDATE_SCHEMA_GOLDEN").is_some() {
        let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
        std::fs::write(
            manifest.join("../../schemas/depgraph-mcp-tools-v1.schema.json"),
            &first,
        )
        .expect("update checked-in schema");
        std::fs::write(
            manifest.join("tests/fixtures/depgraph-mcp-tools-v1.schema.sha256"),
            first_digest.as_bytes(),
        )
        .expect("update schema digest");
    }
    assert_eq!(first_digest.as_bytes(), CHECKED_IN_DIGEST);
    assert_eq!(first.as_slice(), CHECKED_IN_SCHEMA);
    assert!(
        !CHECKED_IN_SCHEMA.ends_with(b"\n"),
        "canonical schema fixture and generate-schema output omit trailing LF"
    );

    let parsed: Value = serde_json::from_slice(CHECKED_IN_SCHEMA).expect("checked-in schema JSON");
    assert_eq!(
        depgraph_mcp_tools::canonical_json_bytes(&parsed).expect("re-canonicalize schema"),
        CHECKED_IN_SCHEMA
    );
}

#[test]
fn generate_schema_stdout_is_the_exact_checked_in_document() {
    let output = Command::new(env!("CARGO_BIN_EXE_generate-schema"))
        .output()
        .expect("run generate-schema");
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    assert_eq!(output.stdout, CHECKED_IN_SCHEMA);
    assert!(!output.stdout.ends_with(b"\n"));
}

#[test]
fn schema_rejects_closed_dto_prohibition_corpus() {
    let schema = schema_value();
    for forbidden in ["metadata", "properties", "root", "store_path"] {
        let mut node = json!({"id":"node:src","kind":"module","locator":"repo://src/lib.rs"});
        node[forbidden] = json!({"arbitrary": true});
        let wrapper = json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$defs": schema["$defs"].clone(),
            "$ref": "#/$defs/AgentNode",
        });
        let validator = jsonschema::draft202012::new(&wrapper).expect("node schema compiles");
        assert!(
            !validator.is_valid(&node),
            "AgentNode schema accepted {forbidden}"
        );
    }
    let node_summary = json!({
        "id":"node:src",
        "kind":"module",
        "locator":"repo://src/lib.rs",
        "display_name":"crate::lib",
        "path":"/absolute/must-not-cross"
    });
    let wrapper = json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$defs": schema["$defs"].clone(),
        "$ref": "#/$defs/AgentNodeSummary",
    });
    assert!(
        !jsonschema::draft202012::new(&wrapper)
            .expect("summary schema compiles")
            .is_valid(&node_summary)
    );
    assert!(serde_json::from_value::<AgentNodeSummary>(node_summary).is_err());

    let absolute_context = json!({
        "repository_id":"/absolute/repository",
        "enabled_capabilities":["read"],
        "snapshot":{"available":false}
    });
    assert!(serde_json::from_value::<AgentContext>(absolute_context).is_err());
    for forbidden in ["detail", "raw", "raw_evidence_detail", "stderr"] {
        let mut evidence =
            json!({"kind":"semantic","extractor":"rust-analyzer","extractor_version":"0.0.330"});
        evidence[forbidden] = json!("raw compiler output");
        let wrapper = json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$defs": schema["$defs"].clone(),
            "$ref": "#/$defs/AgentEvidence",
        });
        let validator = jsonschema::draft202012::new(&wrapper).expect("evidence schema compiles");
        assert!(
            !validator.is_valid(&evidence),
            "AgentEvidence schema accepted {forbidden}"
        );
    }
}

#[test]
fn lifecycle_agent_schemas_are_closed_and_prohibit_sensitive_doctor_fields() {
    let schema = schema_value();
    let validator_for = |definition: &str| {
        let wrapper = json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$defs": schema["$defs"].clone(),
            "$ref": format!("#/$defs/{definition}"),
        });
        jsonschema::draft202012::new(&wrapper)
            .unwrap_or_else(|error| panic!("{definition} schema did not compile: {error}"))
    };

    let doctor = json!({
        "report_kind": "details",
        "diagnostic_root_source": "explicit",
        "protocol_version": "1.0",
        "graph_schema_version": "1.0",
        "store_schema_version": 16,
        "cache_contract_version": 2,
        "cache_entries": {"syntax":0,"semantic":0,"build":0,"compiler_precise":0},
        "impact_query_cache_contract_version": 1,
        "impact_query_cache_entries": 0,
        "recent_cache_events": [],
        "toolchains": [],
        "supported_baselines": [],
        "workers": [{
            "adapter":"rust",
            "available":true,
            "version":"0.4.0",
            "protocol":"1.0",
            "integrity":"verified",
            "root_launch_allowed":true
        }],
        "compiler_pack": {
            "status":"available",
            "release_page":"https://github.com/TamaT-LLC/depgraph-cli/releases",
            "fallback_policy":"unsupported-no-fallback",
            "diagnostic":"the configured compiler pack is verified and available",
            "remediation":"the compiler pack is ready for compiler-precise analysis"
        },
        "latest_attempt": {
            "scan_id":"scan:fixture",
            "status":"completed",
            "project_code_executed":false,
            "coverage": {
                "profiles":1,"files_discovered":1,"files_analyzed":1,"files_skipped":0,
                "dependency_sites":0,"resolved":0,"candidates":0,"external":0,
                "unresolved":0,"unsupported_syntax":0,"project_code_executed":false,
                "completeness":["syntax-complete"],"reasons":[]
            },
            "file_coverage":[],
            "profiles":[{"id":"rust:safe","language":"rust","features":[]}],
            "diagnostics":[{"id":"diagnostic:fixture","severity":"warning","code":"fixture.warning","path":"src/lib.rs"}],
            "cache_events":[]
        }
    });
    let doctor_validator = validator_for("Doctor");
    assert!(doctor_validator.is_valid(&doctor));

    for field in [
        "root",
        "diagnostic_root",
        "store_path",
        "toolchain_remediation",
        "runtime_integrity",
        "runtime_requirements",
    ] {
        let mut invalid = doctor.clone();
        invalid[field] = json!("/private/secret");
        assert!(
            !doctor_validator.is_valid(&invalid),
            "doctor schema accepted {field}"
        );
    }
    for field in ["command", "error", "root_launch_error", "stderr", "logs"] {
        let mut invalid = doctor.clone();
        invalid["workers"][0][field] = json!("/usr/bin/private-worker --secret");
        assert!(
            !doctor_validator.is_valid(&invalid),
            "doctor worker schema accepted {field}"
        );
    }
    for field in ["environment", "properties", "command", "compiler_command"] {
        let mut invalid = doctor.clone();
        invalid["latest_attempt"]["profiles"][0][field] = json!({"secret":"value"});
        assert!(
            !doctor_validator.is_valid(&invalid),
            "doctor profile schema accepted {field}"
        );
    }
    for field in ["message", "properties", "raw", "stderr"] {
        let mut invalid = doctor.clone();
        invalid["latest_attempt"]["diagnostics"][0][field] = json!("private output");
        assert!(
            !doctor_validator.is_valid(&invalid),
            "doctor diagnostic schema accepted {field}"
        );
    }

    for definition in ["AgentProfilePlan", "AgentDaemonStatus", "AgentDoctor"] {
        assert!(
            schema["$defs"].get(definition).is_some(),
            "missing {definition}"
        );
    }
}

#[test]
fn repository_path_schema_rejects_the_portability_corpus() {
    let schema = schema_value();
    let wrapper = json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$defs": schema["$defs"].clone(),
        "$ref": "#/$defs/RepositoryRelativePath",
    });
    let validator = jsonschema::draft202012::new(&wrapper).expect("path schema compiles");
    for valid in ["src/lib.rs", ".git/config", "console", "com10.log"] {
        assert!(
            validator.is_valid(&json!(valid)),
            "schema rejected {valid:?}"
        );
        assert!(RepositoryRelativePath::parse(valid).is_ok());
    }
    for invalid in [
        "/etc/passwd",
        "./src/lib.rs",
        "src/../secret",
        "src\\lib.rs",
        "C:/Windows/win.ini",
        "C:Windows/win.ini",
        "C:\\Windows\\win.ini",
        "\\\\server\\share\\file",
        "\\\\?\\UNC\\server\\share\\file",
        "public.txt:private",
        "nested/public.txt:private",
        "src//lib.rs",
        "src/lib.rs/",
        "CON",
        "nested/nul.txt",
        "nested/Com1.log",
        "nested/LPT9",
    ] {
        assert!(
            !validator.is_valid(&json!(invalid)),
            "path schema accepted {invalid:?}"
        );
    }
}

#[test]
fn agent_locator_schema_rejects_absolute_path_escape_hatches() {
    let schema = schema_value();
    let wrapper = json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$defs": schema["$defs"].clone(),
        "$ref": "#/$defs/AgentLocator",
    });
    let validator = jsonschema::draft202012::new(&wrapper).expect("locator schema compiles");

    assert!(validator.is_valid(&json!("repo://src/lib.rs")));
    assert!(validator.is_valid(&json!("crate::dependency")));
    assert!(validator.is_valid(&json!("@scope/package")));
    for invalid in [
        "repo:///Users/alice/private",
        "repo://../private",
        "repo://C:/Windows/win.ini",
        "custom:/absolute/path",
        "custom:C:/Windows/win.ini",
        "custom:C:\\Windows\\win.ini",
        "custom://server/share",
        "C:/Windows/win.ini",
        "C:\\Windows\\win.ini",
        "C:secret",
        "custom:C:secret",
        "//server/share",
        "\\\\server\\share",
        "custom:file:/etc/passwd",
        "file:src/lib.rs",
        "opaque\nsecret",
        "repo://src\tsecret/lib.rs",
    ] {
        assert!(
            !validator.is_valid(&json!(invalid)),
            "AgentLocator schema accepted non-portable locator {invalid:?}"
        );
    }
}

#[test]
fn schema_fixture_path_is_the_documented_repository_location() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../schemas/depgraph-mcp-tools-v1.schema.json");
    assert_eq!(
        std::fs::read(path).expect("read checked-in schema"),
        CHECKED_IN_SCHEMA
    );
}
