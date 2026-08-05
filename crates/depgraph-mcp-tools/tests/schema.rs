use std::{path::Path, process::Command};

use depgraph_mcp_tools::{
    AgentError, AgentLocator, AgentNode, AgentSourceSpan, MCP_TOOLS_SCHEMA_ID, Page,
    RepositoryRelativePath, TaskAccepted, canonical_schema_bytes, canonical_schema_sha256,
    mcp_tools_v1_schema,
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
    assert_eq!(objects, 28, "review newly added object schemas explicitly");
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
