use depgraph_protocol::{
    MAX_EVENT_LINE_BYTES, PROTOCOL_SCHEMA, ProtocolError, ProtocolEvent, ProtocolValidator,
    validate_ndjson, validate_safe_ndjson,
};
use pretty_assertions::assert_eq;
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::io::Cursor;

const GOLDEN: &str = include_str!("fixtures/protocol-v1.golden.ndjson");

#[test]
fn golden_stream_contains_and_validates_all_nine_event_types() {
    let validated = validate_ndjson(Cursor::new(GOLDEN)).expect("golden stream must validate");
    let names: BTreeSet<_> = validated
        .events
        .iter()
        .map(ProtocolEvent::event_name)
        .collect();
    assert_eq!(
        names,
        BTreeSet::from([
            "scan_started",
            "profile_declared",
            "node_upsert",
            "edge_upsert",
            "dependency_site",
            "diagnostic",
            "file_completed",
            "profile_completed",
            "scan_completed",
        ])
    );
    assert_eq!(validated.nodes.len(), 2);
    assert_eq!(validated.edges.len(), 1);
    assert_eq!(validated.sites.len(), 1);
    assert_eq!(
        validated.edges["edge:sha256:import"].condition.render(),
        "(mode == \"production\" && runtime == \"server\")"
    );
}

#[test]
fn json_schema_is_draft_2020_12_and_lists_nine_events() {
    let schema: Value = serde_json::from_str(PROTOCOL_SCHEMA).expect("schema must be valid JSON");
    assert_eq!(
        schema["$schema"],
        "https://json-schema.org/draft/2020-12/schema"
    );
    assert_eq!(schema["oneOf"].as_array().unwrap().len(), 9);
    assert!(jsonschema::draft202012::meta::is_valid(&schema));
    let validator = jsonschema::draft202012::new(&schema).expect("schema must compile");
    for line in GOLDEN.lines() {
        let event: Value = serde_json::from_str(line).unwrap();
        assert!(validator.is_valid(&event), "schema rejected {event}");
    }
}

#[test]
fn strict_safe_scan_api_rejects_non_safe_execution_without_changing_compatible_mode() {
    validate_safe_ndjson(Cursor::new(GOLDEN)).expect("golden stream is a safe scan");

    let mut coverage = empty_coverage();
    coverage["project_code_executed"] = true.into();
    let input = minimal_stream(
        json!({
            "event": "scan_started",
            "root": "/fixture",
            "project_code_executed": true,
            "safe_mode": false
        }),
        json!({"event": "scan_completed", "coverage": coverage}),
    );
    validate_ndjson(Cursor::new(&input)).expect("compatible mode accepts explicit execution");
    let error = validate_safe_ndjson(Cursor::new(input)).unwrap_err();
    assert!(matches!(error, ProtocolError::UnsafeScanMode { .. }));
}

#[test]
fn unknown_optional_fields_are_accepted() {
    let input = minimal_stream(
        json!({
            "event": "scan_started",
            "root": "/fixture",
            "project_code_executed": false,
            "safe_mode": true,
            "future_optional": {"nested": true}
        }),
        json!({
            "event": "scan_completed",
            "coverage": empty_coverage(),
            "future_summary": "accepted"
        }),
    );
    validate_ndjson(Cursor::new(input)).expect("unknown optional fields must be ignored");
}

#[test]
fn nullable_optional_profile_collections_are_backward_compatible() {
    let mut events = golden_values();
    events[1]["profile"]["features"] = Value::Null;
    events[1]["profile"]["environment"] = Value::Null;
    events[1]["profile"]["properties"] = Value::Null;
    let input = values_to_ndjson(events);
    assert!(schema_accepts_stream(&input));
    let validated = validate_ndjson(Cursor::new(input)).unwrap();
    let profile = &validated.profiles["web:production:server"];
    assert!(profile.features.is_empty());
    assert!(profile.environment.is_empty());
    assert!(profile.properties.is_empty());
}

#[test]
fn unknown_event_is_rejected() {
    let line = with_common(json!({"event": "future_event"}), 1);
    let error = validate_ndjson(Cursor::new(format!("{line}\n"))).unwrap_err();
    assert!(matches!(error, ProtocolError::Json { line: 1, .. }));
}

#[test]
fn missing_required_common_field_is_rejected() {
    let line = json!({
        "event": "scan_started",
        "protocol_version": "1.0",
        "scan_id": "scan-test",
        "adapter": "test",
        "seq": 1,
        "root": "/fixture",
        "project_code_executed": false,
        "safe_mode": true
    });
    let error = validate_ndjson(Cursor::new(format!("{line}\n"))).unwrap_err();
    assert!(matches!(error, ProtocolError::Json { line: 1, .. }));
}

#[test]
fn event_before_scan_started_is_rejected() {
    let line = with_common(
        json!({"event": "scan_completed", "coverage": empty_coverage()}),
        1,
    );
    let error = validate_ndjson(Cursor::new(format!("{line}\n"))).unwrap_err();
    assert!(matches!(error, ProtocolError::MissingScanStarted { .. }));
}

#[test]
fn non_monotonic_sequence_is_rejected() {
    let first = with_common(
        json!({
            "event": "scan_started",
            "root": "/fixture",
            "project_code_executed": false,
            "safe_mode": true
        }),
        2,
    );
    let second = with_common(
        json!({"event": "scan_completed", "coverage": empty_coverage()}),
        2,
    );
    let error = validate_ndjson(Cursor::new(format!("{first}\n{second}\n"))).unwrap_err();
    assert!(matches!(
        error,
        ProtocolError::NonMonotonicSequence {
            previous: 2,
            found: 2
        }
    ));
}

#[test]
fn conflicting_upsert_is_rejected_but_identical_upsert_is_allowed() {
    let events: Vec<ProtocolEvent> = GOLDEN
        .lines()
        .take(3)
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let mut validator = ProtocolValidator::new();
    for event in events {
        validator.push(event).unwrap();
    }

    let original: Value = serde_json::from_str(GOLDEN.lines().nth(2).unwrap()).unwrap();
    let mut identical = original.clone();
    identical["seq"] = 4.into();
    validator
        .push(serde_json::from_value(identical).unwrap())
        .expect("identical upsert is idempotent");

    let mut conflicting = original;
    conflicting["seq"] = 5.into();
    conflicting["node"]["locator"] = "src/other.ts".into();
    let error = validator
        .push(serde_json::from_value(conflicting).unwrap())
        .unwrap_err();
    assert!(matches!(
        error,
        ProtocolError::ConflictingUpsert { entity: "node", .. }
    ));
}

#[test]
fn site_and_edge_status_mismatch_is_rejected() {
    let mut lines: Vec<Value> = GOLDEN
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    lines[4]["edge"]["resolution_status"] = "external".into();
    let input = lines
        .into_iter()
        .map(|line| line.to_string())
        .collect::<Vec<_>>()
        .join("\n");
    let error = validate_ndjson(Cursor::new(input)).unwrap_err();
    assert!(matches!(error, ProtocolError::Invariant(_)));
}

#[test]
fn resolved_site_must_not_target_external_or_unknown_sentinels() {
    for kind in ["external_system", "unknown_target"] {
        let mut events = golden_values();
        events[3]["node"]["kind"] = json!(kind);
        let error = validate_ndjson(Cursor::new(values_to_ndjson(events))).unwrap_err();
        assert!(
            matches!(error, ProtocolError::Invariant(_)),
            "resolved target kind {kind} must be rejected"
        );
    }
}

#[test]
fn scan_coverage_completeness_must_equal_the_profile_intersection() {
    let mut events = golden_values();
    events[8]["coverage"]["completeness"] = json!([]);
    let error = validate_ndjson(Cursor::new(values_to_ndjson(events))).unwrap_err();
    assert!(
        matches!(error, ProtocolError::Invariant(message) if message.contains("profile intersection"))
    );
}

#[test]
fn semantic_completeness_requires_syntax_completeness() {
    let mut events = rust_semantic_complete_values();
    for coverage_index in [8, 9] {
        events[coverage_index]["coverage"]["completeness"] = json!(["semantic-complete"]);
    }
    let error = validate_ndjson(Cursor::new(values_to_ndjson(events))).unwrap_err();
    assert!(
        matches!(error, ProtocolError::Invariant(message) if message.contains("must also report syntax-complete"))
    );
}

#[test]
fn non_rust_semantic_completeness_remains_independent_from_syntax_completeness() {
    let mut events = golden_values();
    for coverage_index in [8, 9] {
        events[coverage_index]["coverage"]["completeness"] = json!(["semantic-complete"]);
    }
    validate_ndjson(Cursor::new(values_to_ndjson(events)))
        .expect("protocol 1.0 non-Rust profiles may report semantic completeness independently");
}

#[test]
fn scan_coverage_must_preserve_rust_hir_backend_failure_reason() {
    let mut events = rust_semantic_complete_values();
    for coverage_index in [8, 9] {
        events[coverage_index]["coverage"]["completeness"] = json!(["syntax-complete"]);
    }
    events[8]["coverage"]["reasons"] = json!(["rust-hir-backend-failure"]);
    events[9]["coverage"]["reasons"] = json!([]);

    let error = validate_ndjson(Cursor::new(values_to_ndjson(events))).unwrap_err();
    assert!(
        matches!(error, ProtocolError::Invariant(message) if message.contains("omits blocking profile reason rust-hir-backend-failure"))
    );
}

#[test]
fn rust_hir_backend_failure_cannot_claim_semantic_completeness() {
    let mut events = rust_semantic_complete_values();
    for coverage_index in [8, 9] {
        events[coverage_index]["coverage"]["reasons"] = json!(["rust-hir-backend-failure"]);
    }

    let error = validate_ndjson(Cursor::new(values_to_ndjson(events))).unwrap_err();
    assert!(
        matches!(error, ProtocolError::Invariant(message) if message.contains("cannot report rust-hir-backend-failure"))
    );
}

#[test]
fn rust_semantic_completeness_accepts_resolved_candidate_and_external_sites() {
    validate_ndjson(Cursor::new(values_to_ndjson(
        rust_semantic_complete_values(),
    )))
    .expect("eligible Rust coverage may report semantic completeness");

    let mut candidate = rust_semantic_complete_values();
    for (event_index, key) in [(4, "edge"), (5, "site")] {
        let payload = &mut candidate[event_index][key];
        payload["resolution_status"] = json!("candidates");
        payload["precision"] = json!("overapprox");
    }
    for coverage_index in [8, 9] {
        candidate[coverage_index]["coverage"]["resolved"] = json!(0);
        candidate[coverage_index]["coverage"]["candidates"] = json!(1);
    }
    validate_ndjson(Cursor::new(values_to_ndjson(candidate)))
        .expect("candidate sites do not make an otherwise complete Rust profile incomplete");

    let mut external = rust_semantic_complete_values();
    external[3]["node"]["kind"] = json!("external_system");
    for (event_index, key) in [(4, "edge"), (5, "site")] {
        let payload = &mut external[event_index][key];
        payload["resolution_status"] = json!("external");
        payload["precision"] = json!("heuristic");
    }
    for coverage_index in [8, 9] {
        external[coverage_index]["coverage"]["resolved"] = json!(0);
        external[coverage_index]["coverage"]["external"] = json!(1);
    }
    validate_ndjson(Cursor::new(values_to_ndjson(external)))
        .expect("external sites do not make an otherwise complete Rust profile incomplete");
}

#[test]
fn rust_semantic_completeness_requires_zero_incomplete_coverage_counts() {
    for (field, value) in [
        ("files_skipped", 1),
        ("unsupported_syntax", 1),
        ("project_code_executed", 1),
    ] {
        let mut events = rust_semantic_complete_values();
        if field == "files_skipped" {
            events[8]["coverage"]["files_analyzed"] = json!(0);
        }
        events[8]["coverage"][field] = if field == "project_code_executed" {
            json!(true)
        } else {
            json!(value)
        };
        let error = validate_ndjson(Cursor::new(values_to_ndjson(events))).unwrap_err();
        assert!(
            matches!(error, ProtocolError::Invariant(message) if message.contains(field)),
            "Rust semantic completeness accepted {field}"
        );
    }

    let mut unresolved = rust_semantic_complete_values();
    unresolved[3]["node"]["kind"] = json!("unknown_target");
    unresolved[5]["site"]["resolution_status"] = json!("unresolved");
    unresolved[5]["site"]["precision"] = json!("heuristic");
    unresolved[5]["site"]["reason"] = json!("target is unknown");
    unresolved[4]["edge"]["resolution_status"] = json!("unresolved");
    unresolved[4]["edge"]["precision"] = json!("heuristic");
    unresolved[8]["coverage"]["resolved"] = json!(0);
    unresolved[8]["coverage"]["unresolved"] = json!(1);
    let error = validate_ndjson(Cursor::new(values_to_ndjson(unresolved))).unwrap_err();
    assert!(matches!(error, ProtocolError::Invariant(message) if message.contains("unresolved")));
}

#[test]
fn rust_semantic_completeness_requires_exact_backend_properties() {
    let cases = [
        ("analysis", json!("syntax")),
        ("analysis_backend", json!("static-syntax")),
        ("rust_hir_backend", json!("disabled")),
        ("rust_hir_status", json!("import-type-call-graph-partial")),
        ("rust_hir_project_model", json!("unavailable")),
        (
            "rust_hir_enable_gate",
            json!("fallback-and-release-gates-pending"),
        ),
        ("crate_graph_source", json!("static-manifest-fallback")),
        ("cargo_metadata_input", json!("project-cargo")),
        ("rust_toolchain_probe_status", json!("unsupported")),
        ("rust_hir_toolchain_status", json!("unsupported")),
        ("proc_macro_expansion", json!("enabled")),
        ("build_script_policy", json!("enabled")),
        ("proc_macro_policy", json!("enabled")),
        ("rust_hir_semantic_issue_count", json!(1)),
        ("project_code_executed", json!(true)),
        ("project_toolchain_executed", json!(true)),
        ("build_scripts_executed", json!(true)),
        ("proc_macros_executed", json!(true)),
    ];
    for (property, replacement) in cases {
        let mut events = rust_semantic_complete_values();
        events[1]["profile"]["properties"][property] = replacement;
        let error = validate_ndjson(Cursor::new(values_to_ndjson(events))).unwrap_err();
        assert!(
            matches!(error, ProtocolError::Invariant(message) if message.contains(property)),
            "Rust semantic completeness accepted invalid {property}"
        );
    }
}

#[test]
fn safe_profile_cannot_hide_project_code_execution() {
    for mut events in [golden_values(), rust_semantic_complete_values()] {
        events[8]["coverage"]["project_code_executed"] = json!(true);
        let error = validate_safe_ndjson(Cursor::new(values_to_ndjson(events))).unwrap_err();
        assert!(
            matches!(error, ProtocolError::Invariant(message) if message.contains("safe-mode profile"))
        );
    }
}

#[test]
fn edge_condition_may_narrow_a_multi_environment_site() {
    let mut events = golden_values();
    events[4]["edge"]["condition"] = json!({
        "op":"all",
        "conditions":[
            {"op":"eq", "key":"mode", "value":"production"},
            {"op":"eq", "key":"environment", "value":"browser"}
        ]
    });
    validate_ndjson(Cursor::new(values_to_ndjson(events)))
        .expect("an edge may select one conditioned target of a broader site");
}

#[test]
fn schema_and_typed_validator_reject_the_same_field_shape_violations() {
    let cases = [
        (1, vec!["profile", "toolchain"], json!([])),
        (2, vec!["node", "id"], json!("")),
        (
            4,
            vec!["edge", "condition"],
            json!({"op":"eq", "key":"mode", "value":{"nested":true}}),
        ),
        (
            4,
            vec!["edge", "condition"],
            json!({"op":"in", "key":"mode", "values":[["production"]]}),
        ),
        (4, vec!["edge", "condition"], json!({"op":"true"})),
        (4, vec!["edge", "evidence", "0", "start_line"], json!(0)),
        (4, vec!["edge", "evidence", "0", "path"], json!("")),
        (
            8,
            vec!["coverage", "completeness"],
            json!(["syntax-complete", "syntax-complete"]),
        ),
        (7, vec!["skipped"], json!(true)),
    ];
    for (line, path, replacement) in cases {
        let mut events = golden_values();
        set_json_path(&mut events[line], &path, replacement);
        let input = values_to_ndjson(events);
        assert!(
            !schema_accepts_stream(&input),
            "schema unexpectedly accepted {path:?}"
        );
        assert!(
            validate_ndjson(Cursor::new(input)).is_err(),
            "typed validator unexpectedly accepted {path:?}"
        );
    }
}

#[test]
fn typed_validator_rejects_reversed_spans() {
    let mut events = golden_values();
    events[4]["edge"]["evidence"][0]["start_line"] = 2.into();
    events[4]["edge"]["evidence"][0]["end_line"] = 1.into();
    let error = validate_ndjson(Cursor::new(values_to_ndjson(events))).unwrap_err();
    assert!(matches!(error, ProtocolError::Invariant(_)));
}

#[test]
fn dependency_sites_and_edges_require_explainable_evidence() {
    let cases = [
        (4, vec!["edge", "evidence"], json!([])),
        (5, vec!["site", "evidence"], json!([])),
        (
            4,
            vec!["edge", "evidence"],
            json!([{
                "kind": "source",
                "extractor": "typescript-static",
                "extractor_version": "0.1.0",
                "properties": {}
            }]),
        ),
        (
            5,
            vec!["site", "evidence"],
            json!([{
                "kind": "source",
                "extractor": "typescript-static",
                "extractor_version": "0.1.0",
                "properties": {}
            }]),
        ),
    ];

    for (line, path, replacement) in cases {
        let mut events = golden_values();
        set_json_path(&mut events[line], &path, replacement);
        let input = values_to_ndjson(events);
        assert!(
            !schema_accepts_stream(&input),
            "schema unexpectedly accepted missing evidence/span at {path:?}"
        );
        assert!(
            validate_ndjson(Cursor::new(input)).is_err(),
            "typed validator unexpectedly accepted missing evidence/span at {path:?}"
        );
    }
}

#[test]
fn build_and_runtime_edges_may_use_non_source_evidence_without_a_span() {
    let mut events = golden_values();
    events[4]["edge"]["phase"] = json!("build");
    events[4]["edge"]["evidence"] = json!([{
        "kind": "build",
        "extractor": "build-observer",
        "extractor_version": "0.1.0",
        "properties": {}
    }]);
    let input = values_to_ndjson(events);
    assert!(schema_accepts_stream(&input));
    validate_ndjson(Cursor::new(input)).expect("non-source evidence remains protocol-compatible");
}

#[test]
fn skipped_sites_is_backward_compatible_and_conserves_the_file_ledger() {
    let validated = validate_ndjson(Cursor::new(GOLDEN)).unwrap();
    let file = validated
        .events
        .iter()
        .find_map(|event| match event {
            ProtocolEvent::FileCompleted(file) => Some(file),
            _ => None,
        })
        .unwrap();
    assert_eq!(file.skipped_sites, 0, "missing v1 field defaults to zero");

    let mut events = golden_values();
    events[7]["discovered_sites"] = 2.into();
    events[7]["skipped_sites"] = 1.into();
    events[7]["skipped"] = true.into();
    events[7]["reason"] = "one site could not be emitted".into();
    for coverage_index in [8, 9] {
        events[coverage_index]["coverage"]["files_analyzed"] = 0.into();
        events[coverage_index]["coverage"]["files_skipped"] = 1.into();
    }
    let input = values_to_ndjson(events);
    assert!(schema_accepts_stream(&input));
    validate_ndjson(Cursor::new(input)).expect("expected=produced+skipped ledger must validate");

    let mut invalid = golden_values();
    invalid[7]["discovered_sites"] = 2.into();
    let error = validate_ndjson(Cursor::new(values_to_ndjson(invalid))).unwrap_err();
    assert!(matches!(error, ProtocolError::Invariant(_)));
}

#[test]
fn coverage_conservation_applies_to_profile_and_scan_summaries() {
    for event_index in [8, 9] {
        let mut events = golden_values();
        events[event_index]["coverage"]["files_discovered"] = 2.into();
        let error = validate_ndjson(Cursor::new(values_to_ndjson(events))).unwrap_err();
        assert!(
            matches!(error, ProtocolError::Invariant(_)),
            "coverage event at index {event_index} must conserve analyzed + skipped"
        );
    }
}

#[test]
fn payload_after_profile_completion_is_rejected() {
    let mut validator = ProtocolValidator::new();
    for line in GOLDEN.lines().take(9) {
        validator
            .push(serde_json::from_str(line).unwrap())
            .expect("golden prefix must validate");
    }
    let mut node: Value = serde_json::from_str(GOLDEN.lines().nth(2).unwrap()).unwrap();
    node["seq"] = 10.into();
    let error = validator
        .push(serde_json::from_value(node).unwrap())
        .unwrap_err();
    assert!(matches!(
        error,
        ProtocolError::PayloadAfterProfileCompletion {
            found: "node_upsert"
        }
    ));
}

#[test]
fn evidence_path_must_stay_within_the_scan_root() {
    let mut lines: Vec<Value> = GOLDEN
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    lines[4]["edge"]["evidence"][0]["path"] = "../secret.txt".into();
    let input = lines
        .into_iter()
        .map(|line| line.to_string())
        .collect::<Vec<_>>()
        .join("\n");
    let error = validate_ndjson(Cursor::new(input)).unwrap_err();
    assert!(matches!(error, ProtocolError::UnsafePath { .. }));
}

#[cfg(unix)]
#[test]
fn evidence_symlink_must_not_escape_the_scan_root() {
    use std::os::unix::fs::symlink;

    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    symlink(outside.path(), root.path().join("escape")).unwrap();

    let mut events = golden_values();
    events[0]["root"] = root.path().to_string_lossy().into_owned().into();
    // The leaf need not exist: resolving the longest existing ancestor still
    // exposes that the symlinked directory leaves the repository.
    events[4]["edge"]["evidence"][0]["path"] = "escape/missing.ts".into();
    let error = validate_ndjson(Cursor::new(values_to_ndjson(events))).unwrap_err();
    assert!(matches!(error, ProtocolError::UnsafePath { .. }));
}

#[test]
fn oversized_line_is_rejected_before_deserialization() {
    let input = vec![b'x'; MAX_EVENT_LINE_BYTES + 1];
    let error = validate_ndjson(Cursor::new(input)).unwrap_err();
    assert!(matches!(error, ProtocolError::LineTooLong { line: 1, .. }));
}

fn minimal_stream(first: Value, second: Value) -> String {
    format!("{}\n{}\n", with_common(first, 1), with_common(second, 2))
}

fn with_common(mut value: Value, seq: u64) -> Value {
    let object = value.as_object_mut().unwrap();
    object.insert("protocol_version".into(), "1.0".into());
    object.insert("scan_id".into(), "scan-test".into());
    object.insert("adapter".into(), "test".into());
    object.insert("adapter_version".into(), "0.1.0".into());
    object.insert("seq".into(), seq.into());
    value
}

fn empty_coverage() -> Value {
    json!({
        "profiles": 0,
        "files_discovered": 0,
        "files_analyzed": 0,
        "files_skipped": 0,
        "dependency_sites": 0,
        "resolved": 0,
        "candidates": 0,
        "external": 0,
        "unresolved": 0,
        "unsupported_syntax": 0,
        "project_code_executed": false,
        "completeness": [],
        "reasons": []
    })
}

fn golden_values() -> Vec<Value> {
    GOLDEN
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

fn rust_semantic_complete_values() -> Vec<Value> {
    let mut events = golden_values();
    for event in &mut events {
        event["adapter"] = json!("rust");
    }
    events[1]["profile"]["id"] = json!("rust:test");
    events[1]["profile"]["language"] = json!("rust");
    events[1]["profile"]["properties"] = json!({
        "analysis": "syntax+hir-imports-types-calls",
        "analysis_backend": "static-syntax+rust-analyzer-hir",
        "rust_hir_backend": "rust-analyzer-hir",
        "rust_hir_status": "import-type-call-graph-emitted",
        "rust_hir_project_model": "ready",
        "rust_hir_enable_gate": "release-gate-pending",
        "crate_graph_source": "confined-cargo-metadata",
        "cargo_metadata_input": "confined-mirror",
        "rust_toolchain_probe_status": "compatible",
        "rust_hir_toolchain_status": "compatible",
        "proc_macro_expansion": "disabled",
        "build_script_policy": "disabled",
        "proc_macro_policy": "disabled",
        "rust_hir_semantic_issue_count": 0,
        "project_code_executed": false,
        "project_toolchain_executed": false,
        "build_scripts_executed": false,
        "proc_macros_executed": false
    });
    events[4]["edge"]["profile_id"] = json!("rust:test");
    events[5]["site"]["profile_id"] = json!("rust:test");
    events[6]["diagnostic"]["profile_id"] = json!("rust:test");
    events[8]["profile_id"] = json!("rust:test");
    for coverage_index in [8, 9] {
        events[coverage_index]["coverage"]["completeness"] =
            json!(["syntax-complete", "semantic-complete"]);
    }
    events
}

fn values_to_ndjson(values: Vec<Value>) -> String {
    values
        .into_iter()
        .map(|value| value.to_string())
        .collect::<Vec<_>>()
        .join("\n")
}

fn schema_accepts_stream(input: &str) -> bool {
    let schema: Value = serde_json::from_str(PROTOCOL_SCHEMA).unwrap();
    let validator = jsonschema::draft202012::new(&schema).unwrap();
    input.lines().all(|line| {
        serde_json::from_str::<Value>(line).is_ok_and(|event| validator.is_valid(&event))
    })
}

fn set_json_path(value: &mut Value, path: &[&str], replacement: Value) {
    if let Some((head, tail)) = path.split_first() {
        if tail.is_empty() {
            if let Ok(index) = head.parse::<usize>() {
                value[index] = replacement;
            } else {
                value[*head] = replacement;
            }
        } else if let Ok(index) = head.parse::<usize>() {
            set_json_path(&mut value[index], tail, replacement);
        } else {
            set_json_path(&mut value[*head], tail, replacement);
        }
    }
}
