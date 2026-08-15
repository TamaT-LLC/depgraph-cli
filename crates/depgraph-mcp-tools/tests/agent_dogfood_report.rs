use std::{fs, path::Path};

use serde_json::{Value, json};

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
