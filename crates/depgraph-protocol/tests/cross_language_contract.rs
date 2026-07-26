use std::io::Cursor;

use depgraph_protocol::{
    CROSS_LANGUAGE_CONTRACT_VERSION, CROSS_LANGUAGE_SCHEMA, CrossLanguageAdapterDelta,
    PROTOCOL_SCHEMA, ProtocolError, ProtocolEvent, cross_language_graph_digest,
    validate_cross_language_adapter_delta, validate_cross_language_contract, validate_safe_ndjson,
};
use serde_json::{Value, json};

const GOLDEN: &str = include_str!("fixtures/protocol-v1.cross-language.golden.ndjson");

fn golden_values() -> Vec<Value> {
    GOLDEN
        .lines()
        .map(|line| serde_json::from_str(line).expect("golden line"))
        .collect()
}

fn serialize_values(values: &[Value]) -> String {
    values
        .iter()
        .map(|value| serde_json::to_string(value).expect("event"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn validate_values(values: &[Value]) -> Result<(), ProtocolError> {
    validate_safe_ndjson(Cursor::new(serialize_values(values))).map(|_| ())
}

fn profile_event_mut(values: &mut [Value]) -> &mut Value {
    values
        .iter_mut()
        .find(|event| event["event"] == "profile_declared")
        .expect("profile event")
}

fn events_by_relation_mut<'a>(values: &'a mut [Value], format: &str) -> Vec<&'a mut Value> {
    values
        .iter_mut()
        .filter(|event| {
            matches!(
                event["event"].as_str(),
                Some("dependency_site" | "edge_upsert")
            ) && event
                .get(if event["event"] == "dependency_site" {
                    "site"
                } else {
                    "edge"
                })
                .and_then(|value| value["evidence"][0]["properties"]["format"].as_str())
                == Some(format)
        })
        .collect()
}

#[test]
fn cross_format_golden_is_accepted_by_protocol_contract_and_schema() {
    let protocol =
        validate_safe_ndjson(Cursor::new(GOLDEN)).expect("cross-language golden validates");
    validate_cross_language_contract(&protocol).expect("explicit common contract validates");
    assert_eq!(protocol.nodes.len(), 4);
    assert_eq!(protocol.sites.len(), 2);
    assert_eq!(protocol.edges.len(), 2);

    let schema: Value = serde_json::from_str(CROSS_LANGUAGE_SCHEMA).expect("schema JSON");
    assert!(jsonschema::draft202012::meta::is_valid(&schema));
    let validator = jsonschema::draft202012::new(&schema).expect("schema compiles");
    let values = golden_values();
    let protocol_schema: Value = serde_json::from_str(PROTOCOL_SCHEMA).expect("protocol schema");
    let protocol_validator =
        jsonschema::draft202012::new(&protocol_schema).expect("protocol schema compiles");
    for event in &values {
        assert!(
            protocol_validator.is_valid(event),
            "protocol schema rejected {event}"
        );
    }
    let profile = values
        .iter()
        .find(|event| event["event"] == "profile_declared")
        .expect("profile");
    for value in [
        &profile["profile"]["properties"]["cross_language_profile_identity"],
        &profile["profile"]["properties"]["cross_language_completeness"],
    ] {
        assert!(validator.is_valid(value), "schema rejected {value}");
    }
    for event in &values {
        if event["event"] == "node_upsert" {
            assert!(
                validator.is_valid(&event["node"]["properties"]["canonical_identity"]),
                "schema rejected node identity"
            );
        }
        if matches!(
            event["event"].as_str(),
            Some("dependency_site" | "edge_upsert")
        ) {
            let owner = if event["event"] == "dependency_site" {
                "site"
            } else {
                "edge"
            };
            assert!(
                validator.is_valid(&event[owner]["evidence"][0]["properties"]),
                "schema rejected evidence properties"
            );
        }
    }
}

#[test]
fn graph_digest_is_independent_of_record_and_checkout_order() {
    let protocol = validate_safe_ndjson(Cursor::new(GOLDEN)).unwrap();
    let profiles = protocol.profiles.into_values().collect::<Vec<_>>();
    let nodes = protocol.nodes.into_values().collect::<Vec<_>>();
    let sites = protocol.sites.into_values().collect::<Vec<_>>();
    let edges = protocol.edges.into_values().collect::<Vec<_>>();
    let expected = cross_language_graph_digest(&profiles, &nodes, &edges, &sites).unwrap();

    let mut reordered_profiles = profiles;
    let mut reordered_nodes = nodes;
    let mut reordered_sites = sites;
    let mut reordered_edges = edges;
    reordered_profiles.reverse();
    reordered_nodes.reverse();
    reordered_sites.reverse();
    reordered_edges.reverse();
    assert_eq!(
        cross_language_graph_digest(
            &reordered_profiles,
            &reordered_nodes,
            &reordered_edges,
            &reordered_sites,
        )
        .unwrap(),
        expected
    );
}

#[test]
fn adapter_delta_is_accepted_or_rejected_as_one_complete_closure() {
    let protocol = validate_safe_ndjson(Cursor::new(GOLDEN)).unwrap();
    let mut delta = CrossLanguageAdapterDelta {
        contract_version: CROSS_LANGUAGE_CONTRACT_VERSION.to_owned(),
        profile: protocol.profiles.into_values().next().unwrap(),
        nodes: protocol.nodes.into_values().collect(),
        sites: protocol.sites.into_values().collect(),
        edges: protocol.edges.into_values().collect(),
    };
    let digest = validate_cross_language_adapter_delta(&delta).unwrap();
    assert!(digest.starts_with("cross-language-graph:sha256:"));

    delta
        .profile
        .properties
        .get_mut(depgraph_protocol::CROSS_LANGUAGE_COMPLETENESS_PROPERTY)
        .unwrap()["entries"][0]["edge_count"] = json!(3);
    assert!(validate_cross_language_adapter_delta(&delta).is_err());
}

#[test]
fn endpoint_proof_evidence_and_coverage_mutations_fail_atomically() {
    let cases = [
        {
            let mut values = golden_values();
            for event in events_by_relation_mut(&mut values, "graphql") {
                let owner = if event["event"] == "dependency_site" {
                    "site"
                } else {
                    "edge"
                };
                event[owner]["evidence"][0]["properties"]["mapping_kind"] =
                    json!("manual_declaration");
            }
            ("name-only exact mapping", values)
        },
        {
            let mut values = golden_values();
            for event in events_by_relation_mut(&mut values, "openapi") {
                let owner = if event["event"] == "dependency_site" {
                    "site"
                } else {
                    "edge"
                };
                event[owner]["source"] = json!(
                    "operation:sha256:29a4d4f80f77eda34e1bd4dcbba886868f122d358a9c77691a44f2133cc31bb4"
                );
            }
            ("invalid endpoint matrix", values)
        },
        {
            let mut values = golden_values();
            for event in events_by_relation_mut(&mut values, "graphql") {
                let owner = if event["event"] == "dependency_site" {
                    "site"
                } else {
                    "edge"
                };
                event[owner]["evidence"][0]["properties"]
                    .as_object_mut()
                    .unwrap()
                    .remove("contract_digest");
            }
            ("dangling primary evidence", values)
        },
        {
            let mut values = golden_values();
            profile_event_mut(&mut values)["profile"]["properties"]["cross_language_completeness"]
                ["entries"][0]["node_count"] = json!(3);
            ("coverage count drift", values)
        },
        {
            let mut values = golden_values();
            profile_event_mut(&mut values)["profile"]["properties"]["cross_language_completeness"]
                ["entries"][0]["capability"] = json!("graphql-contract-v2");
            ("unknown capability", values)
        },
        {
            let mut values = golden_values();
            let edge = events_by_relation_mut(&mut values, "graphql")
                .into_iter()
                .find(|event| event["event"] == "edge_upsert")
                .unwrap();
            edge["edge"]["condition"] = json!({"op":"eq","key":"environment","value":"server"});
            ("site/edge condition drift", values)
        },
    ];

    for (name, values) in cases {
        let error = validate_values(&values).expect_err(name);
        assert!(
            matches!(error, ProtocolError::Invariant(_)),
            "{name} returned {error}"
        );
    }
}

#[test]
fn schema_rejects_unsafe_identity_and_spelling_only_mapping_extensions() {
    let schema: Value = serde_json::from_str(CROSS_LANGUAGE_SCHEMA).unwrap();
    let validator = jsonschema::draft202012::new(&schema).unwrap();
    let profile_id =
        "profile:sha256:7c716c425956ccc1d5e890947954e1ceeaaba70f574c2e5e0696c7538920ce7e";
    let unsafe_identity = json!({
        "contract_version":"cross-language-contract-v1",
        "format":"openapi",
        "repository_contract_locator":"https://user:secret@example.test/api?token=x",
        "format_version":"3.1.1",
        "coordinate":"get /users/{id}",
        "profile_id":profile_id
    });
    let name_mapping = json!({
        "contract_version":"cross-language-contract-v1",
        "format":"openapi",
        "profile_id":profile_id,
        "format_version":"3.1.1",
        "contract_digest":format!("sha256:{}", "a".repeat(64)),
        "occurrence_kind":"calls_operation",
        "mapping_kind":"name_match"
    });
    assert!(!validator.is_valid(&unsafe_identity));
    assert!(!validator.is_valid(&name_mapping));
}

#[test]
fn cross_language_profile_claim_is_not_silently_accepted_as_open_protocol_data() {
    let mut values = golden_values();
    profile_event_mut(&mut values)["profile"]["id"] =
        json!(format!("profile:sha256:{}", "0".repeat(64)));
    for event in &mut values {
        if let Some(profile_id) = event.get_mut("profile_id") {
            *profile_id = json!(format!("profile:sha256:{}", "0".repeat(64)));
        }
    }
    assert!(validate_values(&values).is_err());

    let names = validate_safe_ndjson(Cursor::new(GOLDEN))
        .unwrap()
        .events
        .iter()
        .map(ProtocolEvent::event_name)
        .collect::<Vec<_>>();
    assert_eq!(names.first(), Some(&"scan_started"));
    assert_eq!(names.last(), Some(&"scan_completed"));

    let mut evidence_only = validate_safe_ndjson(Cursor::new(GOLDEN)).unwrap();
    for profile in evidence_only.profiles.values_mut() {
        profile.language = "other".to_owned();
        profile.properties.clear();
    }
    for node in evidence_only.nodes.values_mut() {
        node.properties.clear();
    }
    assert!(
        validate_cross_language_contract(&evidence_only).is_err(),
        "cross-language evidence must not bypass a missing profile claim"
    );
}

#[test]
fn claimed_profile_nodes_require_the_common_canonical_identity() {
    let mut values = golden_values();
    let node = values
        .iter_mut()
        .find(|event| event["event"] == "node_upsert")
        .expect("node event");
    node["node"]["properties"]
        .as_object_mut()
        .unwrap()
        .remove("canonical_identity");
    assert!(validate_values(&values).is_err());
}
