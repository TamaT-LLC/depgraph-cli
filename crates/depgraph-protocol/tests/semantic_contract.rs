use depgraph_protocol::{
    DependencySite, Evidence, EvidenceKind, GraphEdge, PROTOCOL_SCHEMA, Phase, Precision,
    ProtocolEvent, ResolutionStatus, stable_id_from_value, validate_safe_ndjson,
    validate_safe_semantic_ndjson,
};
use pretty_assertions::assert_eq;
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::io::Cursor;

const SOURCE_GOLDEN: &str = include_str!("fixtures/protocol-v1.golden.ndjson");
const SEMANTIC_GOLDEN: &str = include_str!("fixtures/protocol-v1.semantic.golden.ndjson");
const RUST_SEMANTIC_GOLDEN: &str = include_str!("fixtures/protocol-v1.rust-semantic.golden.ndjson");

#[test]
fn source_and_semantic_fixtures_remain_protocol_v1_compatible() {
    let schema: Value = serde_json::from_str(PROTOCOL_SCHEMA).expect("schema must be valid JSON");
    let validator = jsonschema::draft202012::new(&schema).expect("schema must compile");

    for (name, fixture) in [("source", SOURCE_GOLDEN), ("semantic", SEMANTIC_GOLDEN)] {
        for line in fixture.lines() {
            let event: Value = serde_json::from_str(line).expect("fixture line must be JSON");
            assert!(
                validator.is_valid(&event),
                "schema rejected {name} event: {event}"
            );
        }
        validate_safe_ndjson(Cursor::new(fixture))
            .unwrap_or_else(|error| panic!("Rust validator rejected {name} fixture: {error}"));
        if name == "semantic" {
            assert!(
                semantic_schema_accepts_stream(fixture),
                "semantic Schema definitions rejected the semantic fixture"
            );
            let validated = validate_safe_semantic_ndjson(Cursor::new(fixture))
                .unwrap_or_else(|error| panic!("semantic validator rejected fixture: {error}"));
            assert_eq!(validated.events.len(), 18);
            assert_eq!(validated.nodes.len(), 6);
            assert_eq!(validated.edges.len(), 4);
            assert_eq!(validated.sites.len(), 3);
        }
    }
}

#[test]
fn rust_semantic_fixture_remains_protocol_v1_compatible() {
    let schema: Value = serde_json::from_str(PROTOCOL_SCHEMA).expect("schema must be valid JSON");
    let validator = jsonschema::draft202012::new(&schema).expect("schema must compile");

    for line in RUST_SEMANTIC_GOLDEN.lines() {
        let event: Value = serde_json::from_str(line).expect("Rust semantic fixture line");
        assert!(
            validator.is_valid(&event),
            "schema rejected Rust semantic event: {event}"
        );
    }
    validate_safe_ndjson(Cursor::new(RUST_SEMANTIC_GOLDEN))
        .expect("base validator must accept the Rust semantic fixture");
    assert!(
        semantic_schema_accepts_stream(RUST_SEMANTIC_GOLDEN),
        "semantic Schema definitions rejected the Rust semantic fixture"
    );

    let validated = rust_semantic_fixture();
    assert_eq!(validated.events.len(), 16);
    assert_eq!(validated.nodes.len(), 7);
    assert_eq!(validated.edges.len(), 4);
    assert!(validated.sites.is_empty());

    let events = rust_semantic_values();
    assert_sorted_event_ids(&events, "node_upsert", "node");
    assert_sorted_event_ids(&events, "edge_upsert", "edge");
    let completed_coverages: Vec<_> = events
        .iter()
        .filter(|event| {
            matches!(
                event["event"].as_str(),
                Some("profile_completed" | "scan_completed")
            )
        })
        .map(|event| &event["coverage"])
        .collect();
    assert_eq!(completed_coverages.len(), 2);
    assert!(completed_coverages.iter().all(|coverage| {
        coverage["completeness"] == json!(["syntax-complete"])
            && !coverage["completeness"]
                .as_array()
                .expect("coverage completeness array")
                .contains(&json!("semantic-complete"))
    }));
}

#[test]
fn rust_semantic_nodes_and_site_less_relations_follow_their_hash_contract() {
    let validated = rust_semantic_fixture();
    let semantic_nodes: Vec<_> = validated
        .nodes
        .values()
        .filter(|node| matches!(node.kind.as_str(), "symbol" | "type"))
        .collect();
    assert_eq!(semantic_nodes.len(), 6);
    assert!(
        validated.nodes.values().any(|node| node.kind == "module"),
        "the syntax module owner must survive the semantic union"
    );

    for node in semantic_nodes {
        assert_eq!(node.properties["language"], "rust");
        assert_eq!(
            node.properties["crate_identity"],
            "Cargo.toml#lib:rust_semantic_fixture:src/lib.rs"
        );
        let identity = &node.properties["canonical_identity"];
        assert!(identity.is_object());
        assert_eq!(node.id, stable_id_from_value(&node.kind, identity));
        assert_eq!(identity["language"], node.properties["language"]);
        assert_eq!(
            identity["package_locator"],
            node.properties["package_locator"]
        );
        let kind_property = if node.kind == "symbol" {
            "symbol_kind"
        } else {
            "type_kind"
        };
        assert_eq!(identity[kind_property], node.properties[kind_property]);
    }

    let relation_kinds: BTreeSet<_> = validated
        .edges
        .values()
        .map(|edge| edge.kind.as_str())
        .collect();
    assert_eq!(
        relation_kinds,
        BTreeSet::from(["declares", "extends", "implements", "instantiates"])
    );
    for edge in validated.edges.values() {
        assert_eq!(edge.site_id, None, "{} must remain site-less", edge.kind);
        assert_semantic_edge(edge, ResolutionStatus::Resolved, Precision::Exact);
        assert_eq!(edge.environment.as_deref(), Some("any"));
        let evidence = primary_semantic_evidence(&edge.evidence);
        assert_eq!(evidence.extractor, "rust-analyzer-hir");
        assert_eq!(evidence.extractor_version, "0.0.330");
        assert_eq!(evidence.properties["backend"], "rust-analyzer-library");
        assert_eq!(
            evidence.properties["rust_analyzer_revision"],
            "8954b66d43225e62c92e8bbcc8500191b5cceb1e"
        );

        let input = json!({
            "condition": edge.condition.canonicalized(),
            "kind": edge.kind,
            "profile_id": edge.profile_id,
            "source": edge.source,
            "target": edge.target,
            "path": evidence.path.as_deref().expect("semantic evidence path"),
            "span": {
                "start_line": evidence.start_line.expect("start line"),
                "start_column": evidence.start_column.expect("start column"),
                "end_line": evidence.end_line.expect("end line"),
                "end_column": evidence.end_column.expect("end column"),
            },
        });
        assert_eq!(edge.id, stable_id_from_value("edge", &input));
    }
}

#[test]
fn semantic_symbol_and_type_nodes_use_their_canonical_identity_hash() {
    let validated = semantic_fixture();
    assert_eq!(validated.nodes.len(), 6);

    for node in validated.nodes.values() {
        assert!(matches!(node.kind.as_str(), "symbol" | "type"));
        assert_eq!(node.properties["language"], "go");
        assert!(
            node.properties["package_locator"]
                .as_str()
                .is_some_and(|locator| locator.starts_with("go:"))
        );
        let kind_property = if node.kind == "symbol" {
            "symbol_kind"
        } else {
            "type_kind"
        };
        assert!(
            node.properties[kind_property].as_str().is_some(),
            "{} must have {kind_property}",
            node.id
        );
        let identity = &node.properties["canonical_identity"];
        assert!(
            identity.is_object(),
            "{} must expose its hash input",
            node.id
        );
        assert_eq!(node.id, stable_id_from_value(&node.kind, identity));
        assert_eq!(identity["language"], node.properties["language"]);
        assert_eq!(
            identity["package_locator"],
            node.properties["package_locator"]
        );
        assert_eq!(identity[kind_property], node.properties[kind_property]);
        if node.kind == "symbol" {
            assert!(
                identity["identity_kind"].as_str().is_some(),
                "{} must discriminate named and source-anchored identities",
                node.id
            );
        }
    }

    let local = validated
        .nodes
        .values()
        .find(|node| node.properties["symbol_kind"] == "local_variable")
        .expect("local symbol identity");
    let identity = &local.properties["canonical_identity"];
    assert_eq!(identity["identity_kind"], "local");
    assert!(
        validated
            .nodes
            .contains_key(identity["enclosing_symbol"].as_str().unwrap())
    );
    assert_eq!(identity["relative_path"], "cmd/service/main.go");
    assert!(identity["span"].is_object());
}

#[test]
fn semantic_type_use_and_direct_call_are_resolved_exact_dependencies() {
    let validated = semantic_fixture();

    let type_use = edge_by_kind(&validated.edges, "type_uses");
    assert_semantic_edge(type_use, ResolutionStatus::Resolved, Precision::Exact);
    assert!(matches!(
        validated.nodes[&type_use.source].kind.as_str(),
        "symbol" | "type"
    ));
    assert_eq!(validated.nodes[&type_use.target].kind, "type");
    let type_site = site_for_edge(&validated.sites, type_use);
    assert_eq!(type_site.kind, "type_use");
    assert_eq!(
        type_site.target_ids.as_slice(),
        std::slice::from_ref(&type_use.target)
    );
    assert_semantic_evidence(&type_site.evidence);

    let direct_call = edge_by_kind(&validated.edges, "calls");
    assert_semantic_edge(direct_call, ResolutionStatus::Resolved, Precision::Exact);
    assert_eq!(validated.nodes[&direct_call.source].kind, "symbol");
    assert_eq!(validated.nodes[&direct_call.target].kind, "symbol");
    let direct_site = site_for_edge(&validated.sites, direct_call);
    assert_eq!(direct_site.kind, "call");
    assert_eq!(
        direct_site.target_ids.as_slice(),
        std::slice::from_ref(&direct_call.target)
    );
    assert_semantic_evidence(&direct_site.evidence);
}

#[test]
fn candidate_calls_share_one_stable_site_and_have_one_edge_per_target() {
    let validated = semantic_fixture();
    let site = validated
        .sites
        .values()
        .find(|site| site.resolution_status == ResolutionStatus::Candidates)
        .expect("candidate call site");
    assert_eq!(site.kind, "call");
    assert_eq!(site.precision, Precision::Overapprox);
    assert_eq!(site.target_ids.len(), 2);
    assert_semantic_evidence(&site.evidence);

    let edges: Vec<_> = validated
        .edges
        .values()
        .filter(|edge| edge.site_id.as_deref() == Some(&site.id))
        .collect();
    assert_eq!(edges.len(), 2);
    let edge_targets: BTreeSet<_> = edges.iter().map(|edge| edge.target.clone()).collect();
    assert_eq!(
        edge_targets,
        site.target_ids.iter().cloned().collect::<BTreeSet<_>>()
    );
    for edge in edges {
        assert_eq!(edge.kind, "may_call");
        assert_semantic_edge(edge, ResolutionStatus::Candidates, Precision::Overapprox);
        assert_eq!(edge.evidence[0].properties["algorithm"], "rta");
    }
}

#[test]
fn semantic_site_and_edge_ids_follow_the_documented_hash_inputs() {
    let validated = semantic_fixture();
    for site in validated.sites.values() {
        let evidence = primary_semantic_evidence(&site.evidence);
        let input = site_identity(site, evidence);
        assert_eq!(site.id, stable_id_from_value("site", &input));
    }
    for edge in validated.edges.values() {
        let input = json!({
            "kind": edge.kind,
            "site_id": edge.site_id.as_deref().expect("semantic edge site"),
            "target": edge.target,
        });
        assert_eq!(edge.id, stable_id_from_value("edge", &input));
    }
}

#[test]
fn source_and_semantic_events_survive_typed_round_trips() {
    for fixture in [SOURCE_GOLDEN, SEMANTIC_GOLDEN, RUST_SEMANTIC_GOLDEN] {
        for line in fixture.lines() {
            let event: ProtocolEvent = serde_json::from_str(line).expect("typed event");
            let encoded = serde_json::to_string(&event).expect("serialize typed event");
            let reparsed: ProtocolEvent = serde_json::from_str(&encoded).expect("reparse event");
            assert_eq!(reparsed, event);
        }
    }
}

#[test]
fn semantic_fixture_uses_the_canonical_event_and_target_order() {
    let events = semantic_values();
    let event_names: Vec<_> = events
        .iter()
        .map(|event| event["event"].as_str().expect("event name"))
        .collect();
    assert_eq!(
        event_names,
        [
            "scan_started",
            "profile_declared",
            "node_upsert",
            "node_upsert",
            "node_upsert",
            "node_upsert",
            "node_upsert",
            "node_upsert",
            "dependency_site",
            "dependency_site",
            "dependency_site",
            "edge_upsert",
            "edge_upsert",
            "edge_upsert",
            "edge_upsert",
            "file_completed",
            "profile_completed",
            "scan_completed",
        ]
    );
    assert_sorted_event_ids(&events, "node_upsert", "node");
    assert_sorted_event_ids(&events, "dependency_site", "site");
    assert_sorted_event_ids(&events, "edge_upsert", "edge");

    let candidate = events
        .iter()
        .find_map(|event| {
            (event["event"] == "dependency_site"
                && event["site"]["resolution_status"] == "candidates")
                .then_some(&event["site"])
        })
        .expect("candidate site");
    let targets = candidate["target_ids"].as_array().expect("target IDs");
    assert!(
        targets
            .windows(2)
            .all(|pair| pair[0].as_str() < pair[1].as_str())
    );
}

#[test]
fn schema_and_rust_validator_reject_invalid_semantic_contract_values() {
    let mut missing_identity = semantic_values();
    let symbol = missing_identity
        .iter_mut()
        .find(|event| event["event"] == "node_upsert" && event["node"]["kind"] == "symbol")
        .expect("symbol event");
    symbol["node"]["properties"]
        .as_object_mut()
        .expect("node properties")
        .remove("canonical_identity");

    let mut wrong_evidence_kind = semantic_values();
    let edge = wrong_evidence_kind
        .iter_mut()
        .find(|event| event["event"] == "edge_upsert")
        .expect("semantic edge");
    edge["edge"]["evidence"][0]["kind"] = json!("source");

    let mut wrong_precision = semantic_values();
    let edge = wrong_precision
        .iter_mut()
        .find(|event| event["event"] == "edge_upsert" && event["edge"]["kind"] == "calls")
        .expect("direct-call edge");
    let site_id = edge["edge"]["site_id"]
        .as_str()
        .expect("semantic site ID")
        .to_owned();
    edge["edge"]["precision"] = json!("heuristic");
    let site = wrong_precision
        .iter_mut()
        .find(|event| event["event"] == "dependency_site" && event["site"]["id"] == site_id)
        .expect("linked semantic site");
    site["site"]["precision"] = json!("heuristic");

    for (name, events) in [
        ("missing identity", missing_identity),
        ("wrong evidence kind", wrong_evidence_kind),
        ("wrong precision", wrong_precision),
    ] {
        let input = values_to_ndjson(events);
        assert!(schema_accepts_stream(&input));
        let base_result = validate_safe_ndjson(Cursor::new(&input));
        assert!(base_result.is_ok(), "{name}: {base_result:?}");
        assert!(!semantic_schema_accepts_stream(&input));
        assert!(validate_safe_semantic_ndjson(Cursor::new(input)).is_err());
    }
}

#[test]
fn rust_validator_recomputes_semantic_hashes_and_enforces_candidate_order() {
    let mut wrong_hash = semantic_values();
    let symbol = wrong_hash
        .iter_mut()
        .find(|event| {
            event["event"] == "node_upsert"
                && event["node"]["properties"]["symbol_kind"] == "local_variable"
        })
        .expect("unreferenced local symbol event");
    symbol["node"]["id"] =
        json!("symbol:sha256:0000000000000000000000000000000000000000000000000000000000000000");
    let input = values_to_ndjson(wrong_hash);
    assert!(schema_accepts_stream(&input));
    assert!(validate_safe_ndjson(Cursor::new(&input)).is_ok());
    assert!(validate_safe_semantic_ndjson(Cursor::new(input)).is_err());

    let mut reversed_targets = semantic_values();
    let target_ids = reversed_targets
        .iter_mut()
        .find(|event| {
            event["event"] == "dependency_site"
                && event["site"]["resolution_status"] == "candidates"
        })
        .expect("candidate site")["site"]["target_ids"]
        .as_array_mut()
        .expect("candidate targets");
    target_ids.reverse();
    let input = values_to_ndjson(reversed_targets);
    assert!(schema_accepts_stream(&input));
    assert!(validate_safe_ndjson(Cursor::new(&input)).is_ok());
    assert!(validate_safe_semantic_ndjson(Cursor::new(input)).is_err());

    let mut mismatched_site_kind = semantic_values();
    let site = mismatched_site_kind
        .iter_mut()
        .find(|event| {
            event["event"] == "dependency_site"
                && event["site"]["resolution_status"] == "candidates"
        })
        .expect("candidate site");
    site["site"]["kind"] = json!("import");
    let input = values_to_ndjson(mismatched_site_kind);
    assert!(schema_accepts_stream(&input));
    assert!(validate_safe_ndjson(Cursor::new(&input)).is_ok());
    assert!(validate_safe_semantic_ndjson(Cursor::new(input)).is_err());
}

#[test]
fn local_symbol_identity_cannot_use_the_named_branch_or_a_type_enclosure() {
    let mut disguised_local = semantic_values();
    let local = disguised_local
        .iter_mut()
        .find(|event| {
            event["event"] == "node_upsert"
                && event["node"]["properties"]["symbol_kind"] == "local_variable"
        })
        .expect("local symbol");
    let original = local["node"]["properties"]["canonical_identity"].clone();
    local["node"]["properties"]["canonical_identity"] = json!({
        "identity_kind": "named",
        "language": original["language"],
        "package_locator": original["package_locator"],
        "resolver_identity": "example.com/acme/app/cmd/service.run.handler",
        "symbol_kind": "local_variable",
    });
    local["node"]["id"] = json!(stable_id_from_value(
        "symbol",
        &local["node"]["properties"]["canonical_identity"],
    ));
    let input = values_to_ndjson(disguised_local);
    assert!(schema_accepts_stream(&input));
    assert!(validate_safe_ndjson(Cursor::new(&input)).is_ok());
    assert!(!semantic_schema_accepts_stream(&input));
    assert!(validate_safe_semantic_ndjson(Cursor::new(input)).is_err());

    let mut type_enclosure = semantic_values();
    let type_id = type_enclosure
        .iter()
        .find(|event| event["event"] == "node_upsert" && event["node"]["kind"] == "type")
        .expect("type node")["node"]["id"]
        .clone();
    let local = type_enclosure
        .iter_mut()
        .find(|event| {
            event["event"] == "node_upsert"
                && event["node"]["properties"]["symbol_kind"] == "local_variable"
        })
        .expect("local symbol");
    local["node"]["properties"]["canonical_identity"]["enclosing_symbol"] = type_id;
    local["node"]["id"] = json!(stable_id_from_value(
        "symbol",
        &local["node"]["properties"]["canonical_identity"],
    ));
    let input = values_to_ndjson(type_enclosure);
    assert!(schema_accepts_stream(&input));
    assert!(semantic_schema_accepts_stream(&input));
    assert!(validate_safe_ndjson(Cursor::new(&input)).is_ok());
    assert!(validate_safe_semantic_ndjson(Cursor::new(input)).is_err());
}

#[test]
fn base_protocol_keeps_semantic_kind_strings_open_for_legacy_v1_events() {
    let mut events: Vec<Value> = SOURCE_GOLDEN
        .lines()
        .map(|line| serde_json::from_str(line).expect("source fixture JSON"))
        .collect();
    events
        .iter_mut()
        .find(|event| event["event"] == "node_upsert")
        .expect("source node")["node"]["kind"] = json!("symbol");
    events
        .iter_mut()
        .find(|event| event["event"] == "dependency_site")
        .expect("source site")["site"]["kind"] = json!("call");
    events
        .iter_mut()
        .find(|event| event["event"] == "edge_upsert")
        .expect("source edge")["edge"]["kind"] = json!("calls");

    let input = values_to_ndjson(events);
    assert!(schema_accepts_stream(&input));
    validate_safe_ndjson(Cursor::new(&input))
        .expect("base protocol-v1 validator must preserve its open vocabulary");
    assert!(!semantic_schema_accepts_stream(&input));
    assert!(validate_safe_semantic_ndjson(Cursor::new(input)).is_err());
}

#[test]
fn candidate_semantic_calls_may_have_a_single_overapproximate_target() {
    let mut events = semantic_values();
    let candidate_site = events
        .iter_mut()
        .find(|event| {
            event["event"] == "dependency_site"
                && event["site"]["resolution_status"] == "candidates"
        })
        .expect("candidate site");
    let site_id = candidate_site["site"]["id"]
        .as_str()
        .expect("site ID")
        .to_owned();
    let kept_target = candidate_site["site"]["target_ids"][0]
        .as_str()
        .expect("candidate target")
        .to_owned();
    candidate_site["site"]["target_ids"] = json!([kept_target]);
    events.retain(|event| {
        event["event"] != "edge_upsert"
            || event["edge"]["site_id"] != site_id
            || event["edge"]["target"] == kept_target
    });
    resequence(&mut events);

    let input = values_to_ndjson(events);
    assert!(schema_accepts_stream(&input));
    assert!(semantic_schema_accepts_stream(&input));
    validate_safe_semantic_ndjson(Cursor::new(input))
        .expect("one conservative candidate remains candidates/overapprox");
}

#[test]
fn candidate_calls_require_the_analysis_algorithm_on_site_and_edges() {
    let mut missing_site_algorithm = semantic_values();
    missing_site_algorithm
        .iter_mut()
        .find(|event| {
            event["event"] == "dependency_site"
                && event["site"]["resolution_status"] == "candidates"
        })
        .expect("candidate site")["site"]["evidence"][0]["properties"]
        .as_object_mut()
        .expect("evidence properties")
        .remove("algorithm");

    let mut missing_edge_algorithm = semantic_values();
    missing_edge_algorithm
        .iter_mut()
        .find(|event| event["event"] == "edge_upsert" && event["edge"]["kind"] == "may_call")
        .expect("candidate edge")["edge"]["evidence"][0]["properties"]
        .as_object_mut()
        .expect("evidence properties")
        .remove("algorithm");

    for events in [missing_site_algorithm, missing_edge_algorithm] {
        let input = values_to_ndjson(events);
        assert!(schema_accepts_stream(&input));
        assert!(validate_safe_ndjson(Cursor::new(&input)).is_ok());
        assert!(!semantic_schema_accepts_stream(&input));
        assert!(validate_safe_semantic_ndjson(Cursor::new(input)).is_err());
    }
}

#[test]
fn site_identity_uses_primary_evidence_even_with_additional_support() {
    let mut events = semantic_values();
    let site = events
        .iter_mut()
        .find(|event| {
            event["event"] == "dependency_site" && event["site"]["specifier"] == "service.Start"
        })
        .expect("direct call site");
    site["site"]["evidence"]
        .as_array_mut()
        .expect("site evidence")
        .push(json!({
            "kind": "source",
            "extractor": "go-parser",
            "extractor_version": "0.1.0",
            "path": "cmd/service/main.go",
            "start_line": 1,
            "start_column": 1,
            "end_line": 1,
            "end_column": 8,
            "properties": {}
        }));
    let input = values_to_ndjson(events);
    assert!(schema_accepts_stream(&input));
    validate_safe_semantic_ndjson(Cursor::new(input))
        .expect("supporting evidence must not change the primary-span site identity");
}

#[test]
fn external_and_unresolved_semantic_calls_use_the_documented_sentinels() {
    for (status, precision, target_kind, reason) in [
        ("external", "exact", "external_system", None),
        ("external", "heuristic", "external_system", None),
        (
            "unresolved",
            "heuristic",
            "unknown_target",
            Some("callee_not_resolved"),
        ),
    ] {
        let input = direct_call_with_sentinel(status, precision, target_kind, reason);
        assert!(schema_accepts_stream(&input));
        validate_safe_semantic_ndjson(Cursor::new(input)).unwrap_or_else(|error| {
            panic!("{status}/{precision} semantic call must validate: {error}")
        });
    }
}

#[test]
fn semantic_dependency_without_a_complete_span_fails_schema_and_rust_validation() {
    let mut events = semantic_values();
    let edge_index = events
        .iter()
        .position(|event| event["event"] == "edge_upsert")
        .expect("semantic edge");
    events[edge_index]["edge"]["evidence"][0]
        .as_object_mut()
        .expect("evidence object")
        .remove("end_column");

    let schema: Value = serde_json::from_str(PROTOCOL_SCHEMA).expect("schema JSON");
    let validator = jsonschema::draft202012::new(&schema).expect("schema compiles");
    assert!(!validator.is_valid(&events[edge_index]));

    let input = values_to_ndjson(events);
    assert!(validate_safe_ndjson(Cursor::new(input)).is_err());
}

fn semantic_fixture() -> depgraph_protocol::ValidatedProtocol {
    validate_safe_semantic_ndjson(Cursor::new(SEMANTIC_GOLDEN))
        .expect("semantic fixture must validate")
}

fn rust_semantic_fixture() -> depgraph_protocol::ValidatedProtocol {
    validate_safe_semantic_ndjson(Cursor::new(RUST_SEMANTIC_GOLDEN))
        .expect("Rust semantic fixture must validate")
}

fn semantic_values() -> Vec<Value> {
    SEMANTIC_GOLDEN
        .lines()
        .map(|line| serde_json::from_str(line).expect("fixture JSON"))
        .collect()
}

fn rust_semantic_values() -> Vec<Value> {
    RUST_SEMANTIC_GOLDEN
        .lines()
        .map(|line| serde_json::from_str(line).expect("Rust semantic fixture JSON"))
        .collect()
}

fn values_to_ndjson(events: Vec<Value>) -> String {
    events
        .into_iter()
        .map(|event| event.to_string())
        .collect::<Vec<_>>()
        .join("\n")
}

fn schema_accepts_stream(input: &str) -> bool {
    let schema: Value = serde_json::from_str(PROTOCOL_SCHEMA).expect("schema JSON");
    let validator = jsonschema::draft202012::new(&schema).expect("schema compiles");
    input.lines().all(|line| {
        serde_json::from_str::<Value>(line).is_ok_and(|event| validator.is_valid(&event))
    })
}

fn semantic_schema_accepts_stream(input: &str) -> bool {
    let schema: Value = serde_json::from_str(PROTOCOL_SCHEMA).expect("schema JSON");
    input.lines().all(|line| {
        let event: Value = match serde_json::from_str(line) {
            Ok(event) => event,
            Err(_) => return false,
        };
        match event["event"].as_str() {
            Some("node_upsert")
                if matches!(event["node"]["kind"].as_str(), Some("symbol" | "type")) =>
            {
                semantic_definition_accepts(&schema, "semantic_node", &event["node"])
            }
            Some("edge_upsert")
                if matches!(
                    event["edge"]["kind"].as_str(),
                    Some("type_uses" | "calls" | "may_call")
                ) =>
            {
                semantic_definition_accepts(&schema, "semantic_edge", &event["edge"])
            }
            Some("dependency_site")
                if matches!(event["site"]["kind"].as_str(), Some("call" | "type_use")) =>
            {
                semantic_definition_accepts(&schema, "semantic_site", &event["site"])
            }
            _ => true,
        }
    })
}

fn semantic_definition_accepts(schema: &Value, definition: &str, payload: &Value) -> bool {
    let wrapper = json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$defs": schema["$defs"].clone(),
        "$ref": format!("#/$defs/{definition}"),
    });
    jsonschema::draft202012::new(&wrapper)
        .unwrap_or_else(|error| panic!("semantic Schema definition {definition} compiles: {error}"))
        .is_valid(payload)
}

fn resequence(events: &mut [Value]) {
    for (index, event) in events.iter_mut().enumerate() {
        event["seq"] = json!(index + 1);
    }
}

fn assert_sorted_event_ids(events: &[Value], event_name: &str, payload: &str) {
    let ids: Vec<_> = events
        .iter()
        .filter(|event| event["event"] == event_name)
        .map(|event| event[payload]["id"].as_str().expect("payload ID"))
        .collect();
    assert!(
        ids.windows(2).all(|pair| pair[0] < pair[1]),
        "{event_name} payload IDs are not sorted: {ids:?}"
    );
}

fn direct_call_with_sentinel(
    status: &str,
    precision: &str,
    target_kind: &str,
    reason: Option<&str>,
) -> String {
    let mut events = semantic_values();
    let target_id = stable_id_from_value(
        target_kind,
        &json!({"locator": format!("semantic:{target_kind}")}),
    );
    let first_site = events
        .iter()
        .position(|event| event["event"] == "dependency_site")
        .expect("site events");
    events.insert(
        first_site,
        json!({
            "event": "node_upsert",
            "protocol_version": "1.0",
            "scan_id": "scan-semantic-golden",
            "adapter": "go",
            "adapter_version": "0.1.0",
            "seq": 0,
            "node": {
                "id": target_id,
                "kind": target_kind,
                "locator": format!("semantic:{target_kind}"),
                "display_name": target_kind,
                "properties": {}
            }
        }),
    );
    events[2..=first_site].sort_by(|left, right| {
        left["node"]["id"]
            .as_str()
            .cmp(&right["node"]["id"].as_str())
    });

    let site = events
        .iter_mut()
        .find(|event| {
            event["event"] == "dependency_site" && event["site"]["specifier"] == "service.Start"
        })
        .expect("direct call site");
    site["site"]["resolution_status"] = json!(status);
    site["site"]["precision"] = json!(precision);
    site["site"]["target_ids"] = json!([target_id]);
    if let Some(reason) = reason {
        site["site"]["reason"] = json!(reason);
    } else {
        site["site"]
            .as_object_mut()
            .expect("site object")
            .remove("reason");
    }

    let edge = events
        .iter_mut()
        .find(|event| event["event"] == "edge_upsert" && event["edge"]["kind"] == "calls")
        .expect("direct call edge");
    edge["edge"]["target"] = json!(target_id);
    edge["edge"]["resolution_status"] = json!(status);
    edge["edge"]["precision"] = json!(precision);
    edge["edge"]["id"] = json!(stable_id_from_value(
        "edge",
        &json!({
            "kind": "calls",
            "site_id": edge["edge"]["site_id"],
            "target": target_id,
        }),
    ));

    for event in &mut events {
        if matches!(
            event["event"].as_str(),
            Some("profile_completed" | "scan_completed")
        ) {
            event["coverage"]["resolved"] = json!(1);
            event["coverage"][status] = json!(1);
        }
    }
    let first_edge = events
        .iter()
        .position(|event| event["event"] == "edge_upsert")
        .expect("edge events");
    let last_edge = events
        .iter()
        .rposition(|event| event["event"] == "edge_upsert")
        .expect("edge events");
    events[first_edge..=last_edge].sort_by(|left, right| {
        left["edge"]["id"]
            .as_str()
            .cmp(&right["edge"]["id"].as_str())
    });
    for (index, event) in events.iter_mut().enumerate() {
        event["seq"] = json!(index + 1);
    }
    values_to_ndjson(events)
}

fn edge_by_kind<'a>(
    edges: &'a std::collections::BTreeMap<String, GraphEdge>,
    kind: &str,
) -> &'a GraphEdge {
    edges
        .values()
        .find(|edge| edge.kind == kind)
        .unwrap_or_else(|| panic!("missing {kind} edge"))
}

fn site_for_edge<'a>(
    sites: &'a std::collections::BTreeMap<String, DependencySite>,
    edge: &GraphEdge,
) -> &'a DependencySite {
    sites
        .get(edge.site_id.as_deref().expect("semantic edge site"))
        .expect("edge must reference its site")
}

fn assert_semantic_edge(
    edge: &GraphEdge,
    resolution_status: ResolutionStatus,
    precision: Precision,
) {
    assert_eq!(edge.phase, Phase::Semantic);
    assert_eq!(edge.resolution_status, resolution_status);
    assert_eq!(edge.precision, precision);
    assert_semantic_evidence(&edge.evidence);
}

fn assert_semantic_evidence(evidence: &[Evidence]) {
    primary_semantic_evidence(evidence);
}

fn primary_semantic_evidence(evidence: &[Evidence]) -> &Evidence {
    let item = evidence.first().expect("primary semantic evidence");
    assert_eq!(item.kind, EvidenceKind::Semantic);
    assert!(
        item.path.is_some()
            && item.start_line.is_some()
            && item.start_column.is_some()
            && item.end_line.is_some()
            && item.end_column.is_some(),
        "primary semantic evidence must have a complete source span"
    );
    item
}

fn site_identity(site: &DependencySite, evidence: &Evidence) -> Value {
    let condition = serde_json::to_value(&site.condition).expect("condition JSON");
    json!({
        "condition": condition,
        "kind": site.kind,
        "path": evidence.path.as_deref().expect("span path"),
        "profile_id": site.profile_id,
        "source": site.source,
        "span": {
            "end_column": evidence.end_column.expect("end column"),
            "end_line": evidence.end_line.expect("end line"),
            "start_column": evidence.start_column.expect("start column"),
            "start_line": evidence.start_line.expect("start line"),
        }
    })
}
