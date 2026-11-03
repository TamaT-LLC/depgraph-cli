use std::{fs, path::Path};

use serde_json::{Value, json};

fn assert_closed_draft202012_schema(schema: &Value) {
    fn visit(value: &Value) {
        match value {
            Value::Array(items) => items.iter().for_each(visit),
            Value::Object(object) => {
                if object.get("type").and_then(Value::as_str) == Some("object") {
                    assert_eq!(
                        object.get("additionalProperties"),
                        Some(&Value::Bool(false)),
                        "object schema must be closed"
                    );
                }
                object.values().for_each(visit);
            }
            _ => {}
        }
    }
    visit(schema);
}

fn repository_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crate is nested under the repository root")
}

fn read_json(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path).expect("fixture is readable"))
        .expect("fixture is valid JSON")
}

#[test]
fn issue_357_report_and_answers_validate_against_their_closed_schemas() {
    let root = repository_root();
    let report_schema = read_json(&root.join("schemas/agent-dogfood-report-v1.schema.json"));
    assert!(jsonschema::draft202012::meta::is_valid(&report_schema));
    let report_validator =
        jsonschema::draft202012::new(&report_schema).expect("report schema compiles");
    let evidence = root.join("fixtures/agent-dogfood-v1/evidence/v0.5.0-rc.7");
    let report = read_json(&evidence.join("report.json"));
    assert!(report_validator.is_valid(&report));

    let mut report_with_unknown_field = report.clone();
    report_with_unknown_field["unreviewed"] = json!(true);
    assert!(!report_validator.is_valid(&report_with_unknown_field));

    let answer_schema = read_json(&root.join("fixtures/agent-dogfood-v1/answer.schema.json"));
    assert!(jsonschema::draft202012::meta::is_valid(&answer_schema));
    let answer_validator =
        jsonschema::draft202012::new(&answer_schema).expect("answer schema compiles");
    let safety_schema = read_json(&root.join("fixtures/agent-dogfood-v1/safety.schema.json"));
    assert!(jsonschema::draft202012::meta::is_valid(&safety_schema));
    let safety_validator =
        jsonschema::draft202012::new(&safety_schema).expect("safety schema compiles");
    for arm in ["baseline", "mcp"] {
        for ordinal in 1..=3 {
            let answer = read_json(&evidence.join(format!("{arm}-{ordinal}.answer.json")));
            assert!(
                answer_validator.is_valid(&answer),
                "{arm}-{ordinal} answer does not match the checked-in schema"
            );
            let safety = read_json(&evidence.join(format!("{arm}-{ordinal}.safety.json")));
            assert!(
                safety_validator.is_valid(&safety),
                "{arm}-{ordinal} safety evidence does not match the checked-in schema"
            );
        }
    }
}

#[test]
fn issue_436_v2_pinned_report_answers_and_safety_validate_against_closed_schemas() {
    let root = repository_root();
    let fixture = root.join("fixtures/agent-dogfood-v2");
    let spec = read_json(&fixture.join("spec.json"));
    assert_eq!(spec["schema_version"], "agent-dogfood-spec-v2");
    assert_eq!(spec["release_status"], "pinned");
    assert_eq!(spec["release"]["tag"], "v0.5.4-rc.2");

    let evidence = fixture.join("evidence/v0.5.4-rc.2");
    assert!(
        evidence.is_dir(),
        "pinned v2 evidence directory is readable"
    );

    let report_schema = read_json(&root.join("schemas/agent-dogfood-report-v2.schema.json"));
    assert!(jsonschema::draft202012::meta::is_valid(&report_schema));
    let report_validator =
        jsonschema::draft202012::new(&report_schema).expect("v2 report schema compiles");
    assert_closed_draft202012_schema(&report_schema);
    let report = read_json(&evidence.join("report.json"));
    assert!(report_validator.is_valid(&report));

    let mut report_with_unknown_field = report.clone();
    report_with_unknown_field["unreviewed"] = json!(true);
    assert!(!report_validator.is_valid(&report_with_unknown_field));

    let mut report_with_duplicate_sample = report.clone();
    report_with_duplicate_sample["samples"][1] = report_with_duplicate_sample["samples"][0].clone();
    assert!(!report_validator.is_valid(&report_with_duplicate_sample));

    let mut report_with_duplicate_gate = report.clone();
    report_with_duplicate_gate["gate"]["checks"][1] =
        report_with_duplicate_gate["gate"]["checks"][0].clone();
    assert!(!report_validator.is_valid(&report_with_duplicate_gate));

    let mut report_with_unsafe_artifact = report.clone();
    report_with_unsafe_artifact["inputs"]["environment"]["path"] = json!("..");
    assert!(!report_validator.is_valid(&report_with_unsafe_artifact));

    let answer_schema = read_json(&fixture.join("answer.schema.json"));
    assert!(jsonschema::draft202012::meta::is_valid(&answer_schema));
    let answer_validator =
        jsonschema::draft202012::new(&answer_schema).expect("v2 answer schema compiles");
    assert_closed_draft202012_schema(&answer_schema);

    let safety_schema = read_json(&fixture.join("safety.schema.json"));
    assert!(jsonschema::draft202012::meta::is_valid(&safety_schema));
    let safety_validator =
        jsonschema::draft202012::new(&safety_schema).expect("v2 safety schema compiles");
    assert_closed_draft202012_schema(&safety_schema);

    let required = answer_schema["properties"]["claims"]["required"]
        .as_array()
        .expect("v2 answer schema lists required claims");
    for claim in [
        "health_unused_findings",
        "health_finding_detail",
        "health_hotspots",
        "health_audit_base",
    ] {
        assert!(
            required.iter().any(|value| value == claim),
            "v2 answer schema must require {claim}"
        );
    }

    for arm in ["baseline", "mcp"] {
        for ordinal in 1..=3 {
            let sample_id = format!("{arm}-{ordinal}");
            let answer = read_json(&evidence.join(format!("{sample_id}.answer.json")));
            assert!(
                answer_validator.is_valid(&answer),
                "{sample_id} answer does not match the checked-in v2 schema"
            );
            let mut answer_with_unknown_field = answer.clone();
            answer_with_unknown_field["unreviewed"] = json!(true);
            assert!(!answer_validator.is_valid(&answer_with_unknown_field));

            let safety = read_json(&evidence.join(format!("{sample_id}.safety.json")));
            assert!(
                safety_validator.is_valid(&safety),
                "{sample_id} safety evidence does not match the checked-in v2 schema"
            );
            let mut safety_with_unknown_field = safety.clone();
            safety_with_unknown_field["unreviewed"] = json!(true);
            assert!(!safety_validator.is_valid(&safety_with_unknown_field));
        }
    }
}
