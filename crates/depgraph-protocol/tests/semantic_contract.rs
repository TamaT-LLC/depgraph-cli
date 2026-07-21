use depgraph_protocol::{
    Condition, DependencySite, Evidence, EvidenceKind, GraphEdge, PROTOCOL_SCHEMA, Phase,
    Precision, ProtocolEvent, ResolutionStatus, stable_id_from_value, validate_safe_ndjson,
    validate_safe_semantic_ndjson,
};
use pretty_assertions::assert_eq;
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::io::Cursor;

const SOURCE_GOLDEN: &str = include_str!("fixtures/protocol-v1.golden.ndjson");
const SEMANTIC_GOLDEN: &str = include_str!("fixtures/protocol-v1.semantic.golden.ndjson");
const RUST_SEMANTIC_GOLDEN: &str = include_str!("fixtures/protocol-v1.rust-semantic.golden.ndjson");
const FRAMEWORK_SEMANTIC_GOLDEN: &str =
    include_str!("fixtures/protocol-v1.framework-semantic.golden.ndjson");

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
fn framework_semantic_fixture_is_strict_and_protocol_v1_compatible() {
    assert!(schema_accepts_stream(FRAMEWORK_SEMANTIC_GOLDEN));
    assert!(semantic_schema_accepts_stream(FRAMEWORK_SEMANTIC_GOLDEN));
    validate_safe_ndjson(Cursor::new(FRAMEWORK_SEMANTIC_GOLDEN))
        .expect("base protocol 1.0 validator must remain compatible");
    let validated = validate_safe_semantic_ndjson(Cursor::new(FRAMEWORK_SEMANTIC_GOLDEN))
        .expect("framework semantic golden fixture must validate");
    assert_eq!(validated.nodes.len(), 2);
    assert_eq!(validated.sites.len(), 1);
    assert_eq!(validated.edges.len(), 1);
    assert_eq!(validated.sites.values().next().unwrap().kind, "route_entry");
}

#[test]
fn all_framework_semantic_node_kinds_use_canonical_identity_hashes() {
    let mut events = framework_semantic_values();
    let profile_id = "profile:web-framework-golden";
    let package_locator = "npm:workspace:web-app@1.0.0#.";
    let extra = [
        (
            "server_function",
            "server_function_kind",
            "loader",
            json!({
                "framework":"tanstack-start",
                "package_locator":package_locator,
                "server_function_kind":"loader",
                "environment":"server",
                "resolver_identity":"npm:workspace:web-app@1.0.0#.::src/server.ts#loadProducts",
            }),
        ),
        (
            "middleware",
            "middleware_kind",
            "request",
            json!({
                "framework":"tanstack-start",
                "package_locator":package_locator,
                "middleware_kind":"request",
                "environment":"server",
                "resolver_identity":"npm:workspace:web-app@1.0.0#.::src/middleware.ts#auth",
                "scope":"/products",
            }),
        ),
    ];
    let insert_at = events
        .iter()
        .position(|event| event["event"] == "dependency_site")
        .expect("framework dependency site");
    for (offset, (kind, kind_property, kind_value, identity)) in extra.into_iter().enumerate() {
        let node_id = stable_id_from_value(kind, &identity);
        let mut properties = json!({
            "framework":"tanstack-start",
            "package_locator":package_locator,
            "environment":"server",
            "profile_id":profile_id,
            "canonical_identity":identity,
        });
        properties[kind_property] = json!(kind_value);
        events.insert(
            insert_at + offset,
            json!({
                "event":"node_upsert",
                "protocol_version":"1.0",
                "scan_id":"scan-framework-semantic-golden",
                "adapter":"web",
                "adapter_version":"0.1.0",
                "seq":0,
                "node":{
                    "id":node_id,
                    "kind":kind,
                    "locator":format!("framework-{kind}:{node_id}"),
                    "display_name":kind_value,
                    "properties":properties,
                },
            }),
        );
    }
    resequence(&mut events);
    let input = values_to_ndjson(events);
    assert!(semantic_schema_accepts_stream(&input));
    validate_safe_semantic_ndjson(Cursor::new(input))
        .expect("all four framework semantic node kinds must validate");
}

#[test]
fn framework_semantic_contract_rejects_invalid_endpoints_and_provenance() {
    let mut invalid_endpoint = framework_semantic_values();
    let component_id = node_id_by_display_name(&invalid_endpoint, "ProductsPage");
    reassign_site_target(&mut invalid_endpoint, "route_entry", &component_id);
    let error = validate_safe_semantic_ndjson(Cursor::new(values_to_ndjson(invalid_endpoint)))
        .expect_err("route_entry must target a route");
    assert!(error.to_string().contains("incompatible target"));

    let mut invalid_version = framework_semantic_values();
    for event in &mut invalid_version {
        if matches!(
            event["event"].as_str(),
            Some("dependency_site" | "edge_upsert")
        ) {
            let payload = if event["event"] == "dependency_site" {
                "site"
            } else {
                "edge"
            };
            event[payload]["evidence"][0]["extractor_version"] = json!("0.2.0");
        }
    }
    let error = validate_safe_semantic_ndjson(Cursor::new(values_to_ndjson(invalid_version)))
        .expect_err("unapproved framework extractor version must fail");
    assert!(error.to_string().contains("next-static-adapter@0.1.0"));

    let mut invalid_condition = framework_semantic_values();
    let edge = invalid_condition
        .iter_mut()
        .find(|event| event["event"] == "edge_upsert")
        .expect("framework edge");
    edge["edge"]["environment"] = json!("browser");
    let error = validate_safe_semantic_ndjson(Cursor::new(values_to_ndjson(invalid_condition)))
        .expect_err("edge environment must be represented by the condition");
    assert!(error.to_string().contains("not allowed by its condition"));
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
fn rust_import_reexport_and_type_use_follow_the_strict_semantic_contract() {
    let input = values_to_ndjson(rust_semantic_dependency_values());
    assert!(schema_accepts_stream(&input));
    assert!(semantic_schema_accepts_stream(&input));
    let validated = validate_safe_semantic_ndjson(Cursor::new(input))
        .expect("Rust semantic dependency fixture must validate");

    for (site_kind, edge_kind, source_kinds, target_kinds) in [
        (
            "rust_use",
            "imports",
            &["module", "symbol"][..],
            &["module", "symbol", "type"][..],
        ),
        (
            "rust_reexport",
            "reexports",
            &["module"][..],
            &["module", "symbol", "type"][..],
        ),
        (
            "type_use",
            "type_uses",
            &["symbol", "type"][..],
            &["type"][..],
        ),
    ] {
        let site = validated
            .sites
            .values()
            .find(|site| site.kind == site_kind)
            .unwrap_or_else(|| panic!("missing {site_kind} site"));
        assert!(!site.specifier.is_empty());
        assert!(source_kinds.contains(&validated.nodes[&site.source].kind.as_str()));
        assert_eq!(site.evidence[0].kind, EvidenceKind::Semantic);
        assert_eq!(site.evidence[1].kind, EvidenceKind::Source);
        assert_eq!(
            site.id,
            stable_id_from_value("site", &site_identity(site, &site.evidence[0]))
        );

        let linked: Vec<_> = validated
            .edges
            .values()
            .filter(|edge| edge.site_id.as_deref() == Some(site.id.as_str()))
            .collect();
        assert_eq!(linked.len(), site.target_ids.len());
        for edge in linked {
            assert_eq!(edge.kind, edge_kind);
            assert_eq!(edge.phase, Phase::Semantic);
            assert_eq!(edge.condition, site.condition);
            assert!(target_kinds.contains(&validated.nodes[&edge.target].kind.as_str()));
            assert_eq!(edge.evidence[0].kind, EvidenceKind::Semantic);
            assert_eq!(edge.evidence[1].kind, EvidenceKind::Source);
            assert_eq!(
                edge.id,
                stable_id_from_value(
                    "edge",
                    &json!({
                        "kind": edge.kind,
                        "site_id": site.id,
                        "target": edge.target,
                    }),
                )
            );
        }
    }
}

#[test]
fn web_import_reexport_and_type_use_follow_the_strict_semantic_contract() {
    let input = values_to_ndjson(web_semantic_dependency_values());
    assert!(schema_accepts_stream(&input));
    assert!(semantic_schema_accepts_stream(&input));
    let validated = validate_safe_semantic_ndjson(Cursor::new(input))
        .expect("Web semantic dependency fixture must validate");

    for (site_kind, edge_kind, target_kind) in [
        ("web_import", "imports", "type"),
        ("web_reexport", "reexports", "type"),
        ("type_use", "type_uses", "type"),
    ] {
        let site = validated
            .sites
            .values()
            .find(|site| site.kind == site_kind)
            .unwrap_or_else(|| panic!("missing {site_kind} site"));
        let source = &validated.nodes[&site.source];
        assert_eq!(source.kind, "file");
        assert_eq!(
            source.properties.get("language").and_then(Value::as_str),
            Some("typescript")
        );
        assert_eq!(site.evidence[0].kind, EvidenceKind::Semantic);
        assert_eq!(site.evidence[1].kind, EvidenceKind::Source);
        assert_eq!(
            site.id,
            stable_id_from_value("site", &site_identity(site, &site.evidence[0]))
        );
        let linked = validated
            .edges
            .values()
            .filter(|edge| edge.site_id.as_deref() == Some(site.id.as_str()))
            .collect::<Vec<_>>();
        assert_eq!(linked.len(), site.target_ids.len());
        for edge in linked {
            assert_eq!(edge.kind, edge_kind);
            assert_eq!(edge.phase, Phase::Semantic);
            assert_eq!(edge.source, site.source);
            assert_eq!(edge.profile_id, site.profile_id);
            assert_eq!(edge.condition, site.condition);
            assert_eq!(edge.resolution_status, site.resolution_status);
            assert_eq!(edge.precision, site.precision);
            assert_eq!(validated.nodes[&edge.target].kind, target_kind);
            assert_eq!(edge.evidence[0].kind, EvidenceKind::Semantic);
            assert_eq!(edge.evidence[1].kind, EvidenceKind::Source);
        }
    }
}

#[test]
fn web_import_and_reexport_preserve_valid_empty_module_specifiers() {
    for site_kind in ["web_import", "web_reexport"] {
        let mut events = web_semantic_dependency_values();
        events
            .iter_mut()
            .find(|event| event["event"] == "dependency_site" && event["site"]["kind"] == site_kind)
            .unwrap_or_else(|| panic!("missing {site_kind} site"))["site"]["specifier"] = json!("");
        let input = values_to_ndjson(events);
        assert!(schema_accepts_stream(&input));
        assert!(semantic_schema_accepts_stream(&input));
        let validated = validate_safe_semantic_ndjson(Cursor::new(input))
            .unwrap_or_else(|error| panic!("empty {site_kind} specifier must validate: {error}"));
        assert!(
            validated
                .sites
                .values()
                .any(|site| site.kind == site_kind && site.specifier.is_empty())
        );
    }
}

#[test]
fn web_semantic_edge_may_narrow_its_site_condition() {
    let mut events = web_semantic_dependency_values();
    let site_index = events
        .iter()
        .position(|event| {
            event["event"] == "dependency_site" && event["site"]["kind"] == "web_import"
        })
        .expect("Web import site");
    let old_id = events[site_index]["site"]["id"]
        .as_str()
        .expect("Web import site ID")
        .to_owned();
    let edge_condition: Condition =
        serde_json::from_value(events[site_index]["site"]["condition"].clone())
            .expect("Web condition");
    events[site_index]["site"]["condition"] = serde_json::to_value(
        Condition::Any {
            conditions: vec![
                edge_condition,
                Condition::Eq {
                    key: "environment".into(),
                    value: json!("worker"),
                },
            ],
        }
        .canonicalized(),
    )
    .expect("canonical Web condition");
    let new_id = rehash_json_site(&mut events[site_index]["site"]);
    for event in events.iter_mut().filter(|event| {
        event["event"] == "edge_upsert"
            && event["edge"]["site_id"].as_str() == Some(old_id.as_str())
    }) {
        event["edge"]["site_id"] = json!(new_id);
        rehash_json_edge(&mut event["edge"]);
    }
    sort_site_events(&mut events);
    sort_edge_events(&mut events);
    resequence(&mut events);

    let validated = validate_safe_semantic_ndjson(Cursor::new(values_to_ndjson(events)))
        .expect("Web target edge may narrow its multi-environment site condition");
    let site = &validated.sites[&new_id];
    let edge = validated
        .edges
        .values()
        .find(|edge| edge.site_id.as_deref() == Some(new_id.as_str()))
        .expect("linked Web import edge");
    assert_ne!(edge.condition, site.condition);
}

#[test]
fn web_semantic_candidates_and_sentinels_are_strict() {
    let mut candidates = web_semantic_dependency_values();
    let second_target = node_id_by_display_name(&candidates, "WebTargetB");
    let site_index = candidates
        .iter()
        .position(|event| {
            event["event"] == "dependency_site" && event["site"]["kind"] == "web_import"
        })
        .expect("Web import site");
    let site_id = candidates[site_index]["site"]["id"]
        .as_str()
        .expect("Web import site ID")
        .to_owned();
    let mut targets = candidates[site_index]["site"]["target_ids"]
        .as_array()
        .expect("Web import targets")
        .clone();
    targets.push(json!(second_target));
    targets.sort_by(|left, right| left.as_str().cmp(&right.as_str()));
    candidates[site_index]["site"]["target_ids"] = Value::Array(targets);
    candidates[site_index]["site"]["resolution_status"] = json!("candidates");
    candidates[site_index]["site"]["precision"] = json!("overapprox");
    let edge_index = candidates
        .iter()
        .position(|event| event["event"] == "edge_upsert" && event["edge"]["site_id"] == site_id)
        .expect("Web import edge");
    candidates[edge_index]["edge"]["resolution_status"] = json!("candidates");
    candidates[edge_index]["edge"]["precision"] = json!("overapprox");
    let mut second_edge = candidates[edge_index].clone();
    second_edge["edge"]["target"] = json!(second_target);
    rehash_json_edge(&mut second_edge["edge"]);
    let file_completed = candidates
        .iter()
        .position(|event| event["event"] == "file_completed")
        .expect("file completion");
    candidates.insert(file_completed, second_edge);
    sort_edge_events(&mut candidates);
    for event in &mut candidates {
        if matches!(
            event["event"].as_str(),
            Some("profile_completed" | "scan_completed")
        ) {
            event["coverage"]["resolved"] = json!(2);
            event["coverage"]["candidates"] = json!(1);
        }
    }
    resequence(&mut candidates);
    validate_safe_semantic_ndjson(Cursor::new(values_to_ndjson(candidates.clone())))
        .expect("sorted Web semantic candidates must validate");
    let target_ids = candidates[site_index]["site"]["target_ids"]
        .as_array_mut()
        .expect("candidate targets");
    target_ids.swap(0, 1);
    let error = validate_safe_semantic_ndjson(Cursor::new(values_to_ndjson(candidates)))
        .expect_err("unsorted Web candidates must fail");
    assert!(
        error
            .to_string()
            .contains("target IDs must be unique and sorted")
    );

    for (status, precision, target_id, target_kind, reason) in [
        (
            "external",
            "exact",
            "external-system:web:package",
            "external_system",
            None,
        ),
        (
            "unresolved",
            "heuristic",
            "unknown:web:dependency",
            "unknown_target",
            Some("TypeChecker could not resolve the module"),
        ),
    ] {
        let mut events = web_semantic_dependency_values();
        insert_plain_node(&mut events, target_id, target_kind);
        reassign_site_target(&mut events, "web_import", target_id);
        let site_id = semantic_site_id(&events, "web_import");
        let site = events
            .iter_mut()
            .find(|event| event["event"] == "dependency_site" && event["site"]["id"] == site_id)
            .expect("Web import site");
        site["site"]["resolution_status"] = json!(status);
        site["site"]["precision"] = json!(precision);
        if let Some(reason) = reason {
            site["site"]["reason"] = json!(reason);
        }
        let edge = linked_edge_mut(&mut events, &site_id);
        edge["resolution_status"] = json!(status);
        edge["precision"] = json!(precision);
        for event in &mut events {
            if matches!(
                event["event"].as_str(),
                Some("profile_completed" | "scan_completed")
            ) {
                event["coverage"]["resolved"] = json!(2);
                event["coverage"][status] = json!(1);
            }
        }
        resequence(&mut events);
        validate_safe_semantic_ndjson(Cursor::new(values_to_ndjson(events)))
            .unwrap_or_else(|error| panic!("Web {status} sentinel must validate: {error}"));
    }
}

#[test]
fn web_sites_require_web_sources_without_weakening_rust_type_use_sources() {
    let mut wrong_web_language = web_semantic_dependency_values();
    wrong_web_language
        .iter_mut()
        .find(|event| event["node"]["display_name"] == "src/index.ts")
        .expect("Web source file")["node"]["properties"]["language"] = json!("rust");
    let error = validate_safe_semantic_ndjson(Cursor::new(values_to_ndjson(wrong_web_language)))
        .expect_err("Web sites with a Rust source must fail");
    assert!(
        error
            .to_string()
            .contains("must declare language=typescript or javascript")
    );

    let mut rust_file_source = rust_semantic_dependency_values();
    let source_id = "file:rust-semantic-type-use-source";
    insert_plain_node(&mut rust_file_source, source_id, "file");
    rust_file_source
        .iter_mut()
        .find(|event| event["node"]["id"] == source_id)
        .expect("Rust source file")["node"]["properties"] = json!({"language":"rust"});
    reassign_site_source(&mut rust_file_source, "type_use", source_id);
    let error = validate_safe_semantic_ndjson(Cursor::new(values_to_ndjson(rust_file_source)))
        .expect_err("Rust semantic type-use with a file source must fail");
    assert!(
        error
            .to_string()
            .contains("symbol/type node (or a Web file fallback)"),
        "{error}"
    );
}

#[test]
fn rust_semantic_import_candidates_are_sorted_and_emit_one_edge_per_target() {
    let input = values_to_ndjson(rust_semantic_candidate_values());
    assert!(schema_accepts_stream(&input));
    assert!(semantic_schema_accepts_stream(&input));
    let validated = validate_safe_semantic_ndjson(Cursor::new(input))
        .expect("sorted Rust semantic import candidates must validate");
    let site = validated
        .sites
        .values()
        .find(|site| site.kind == "rust_use")
        .expect("Rust use site");
    assert_eq!(site.resolution_status, ResolutionStatus::Candidates);
    assert_eq!(site.precision, Precision::Overapprox);
    assert_eq!(site.target_ids.len(), 2);
    assert!(site.target_ids.windows(2).all(|pair| pair[0] < pair[1]));
    let linked: Vec<_> = validated
        .edges
        .values()
        .filter(|edge| edge.site_id.as_deref() == Some(site.id.as_str()))
        .collect();
    assert_eq!(linked.len(), 2);
    assert!(linked.iter().all(|edge| {
        edge.kind == "imports"
            && edge.resolution_status == ResolutionStatus::Candidates
            && edge.precision == Precision::Overapprox
    }));
}

#[test]
fn rust_semantic_direct_calls_enforce_language_condition_and_stable_mapping() {
    let input = values_to_ndjson(rust_semantic_call_values());
    assert!(schema_accepts_stream(&input));
    assert!(semantic_schema_accepts_stream(&input));
    let validated = validate_safe_semantic_ndjson(Cursor::new(input))
        .expect("Rust semantic direct call must validate");
    let site = validated
        .sites
        .values()
        .find(|site| site.kind == "call")
        .expect("Rust call site");
    assert_eq!(site.resolution_status, ResolutionStatus::Resolved);
    assert_eq!(site.precision, Precision::Exact);
    assert_eq!(site.target_ids.len(), 1);
    assert_eq!(validated.nodes[&site.source].properties["language"], "rust");
    assert_eq!(
        validated.nodes[&site.target_ids[0]].properties["language"],
        "rust"
    );
    assert_eq!(
        site.id,
        stable_id_from_value("site", &site_identity(site, &site.evidence[0]))
    );

    let edge = validated
        .edges
        .values()
        .find(|edge| edge.site_id.as_deref() == Some(site.id.as_str()))
        .expect("Rust calls edge");
    assert_eq!(edge.kind, "calls");
    assert_eq!(edge.phase, Phase::Semantic);
    assert_eq!(edge.condition, site.condition);
    assert_eq!(edge.source, site.source);
    assert_eq!(edge.target, site.target_ids[0]);
    assert_eq!(
        edge.id,
        stable_id_from_value(
            "edge",
            &json!({
                "kind": "calls",
                "site_id": site.id,
                "target": edge.target,
            }),
        )
    );
}

#[test]
fn rust_semantic_candidate_calls_require_algorithm_on_site_and_edges() {
    let events = rust_semantic_candidate_call_values();
    let input = values_to_ndjson(events.clone());
    assert!(schema_accepts_stream(&input));
    assert!(semantic_schema_accepts_stream(&input));
    let validated = validate_safe_semantic_ndjson(Cursor::new(input))
        .expect("Rust semantic candidate call must validate");
    let site = validated
        .sites
        .values()
        .find(|site| site.kind == "call")
        .expect("Rust candidate call site");
    assert_eq!(site.resolution_status, ResolutionStatus::Candidates);
    assert_eq!(site.precision, Precision::Overapprox);
    assert_eq!(
        site.evidence[0].properties["algorithm"],
        "rust-analyzer-local-trait-impls-v1"
    );
    let edge = validated
        .edges
        .values()
        .find(|edge| edge.site_id.as_deref() == Some(site.id.as_str()))
        .expect("Rust may_call edge");
    assert_eq!(edge.kind, "may_call");
    assert_eq!(
        edge.evidence[0].properties["algorithm"],
        "rust-analyzer-local-trait-impls-v1"
    );

    for owner in ["site", "edge"] {
        let mut missing = events.clone();
        let site_id = semantic_site_id(&missing, "call");
        let properties = if owner == "site" {
            &mut missing
                .iter_mut()
                .find(|event| event["event"] == "dependency_site" && event["site"]["id"] == site_id)
                .expect("candidate call site")["site"]["evidence"][0]["properties"]
        } else {
            &mut linked_edge_mut(&mut missing, &site_id)["evidence"][0]["properties"]
        };
        properties
            .as_object_mut()
            .expect("semantic evidence properties")
            .remove("algorithm");
        let input = values_to_ndjson(missing);
        assert!(schema_accepts_stream(&input), "{owner} algorithm case");
        assert!(validate_safe_ndjson(Cursor::new(&input)).is_ok());
        assert!(
            validate_safe_semantic_ndjson(Cursor::new(input)).is_err(),
            "Rust candidate call accepted without {owner} algorithm"
        );
    }
}

#[test]
fn rust_semantic_call_contract_rejects_language_condition_and_mapping_drift() {
    let mut cases = Vec::<(&str, Vec<Value>)>::new();

    let mut wrong_source_language = rust_semantic_call_values();
    let call_site_id = semantic_site_id(&wrong_source_language, "call");
    let source_id = wrong_source_language
        .iter()
        .find(|event| event["event"] == "dependency_site" && event["site"]["id"] == call_site_id)
        .expect("Rust call site")["site"]["source"]
        .as_str()
        .expect("call source")
        .to_owned();
    wrong_source_language
        .iter_mut()
        .find(|event| event["event"] == "node_upsert" && event["node"]["id"] == source_id)
        .expect("call source node")["node"]["properties"]["language"] = json!("go");
    cases.push(("source language", wrong_source_language));

    let mut wrong_target_language = rust_semantic_call_values();
    let call_site_id = semantic_site_id(&wrong_target_language, "call");
    let target_id = wrong_target_language
        .iter()
        .find(|event| event["event"] == "dependency_site" && event["site"]["id"] == call_site_id)
        .expect("Rust call site")["site"]["target_ids"][0]
        .as_str()
        .expect("call target")
        .to_owned();
    wrong_target_language
        .iter_mut()
        .find(|event| event["event"] == "node_upsert" && event["node"]["id"] == target_id)
        .expect("call target node")["node"]["properties"]["language"] = json!("go");
    cases.push(("target language", wrong_target_language));

    let mut mismatched_condition = rust_semantic_call_values();
    let call_site_id = semantic_site_id(&mismatched_condition, "call");
    linked_edge_mut(&mut mismatched_condition, &call_site_id)["condition"] =
        json!({"op":"eq","key":"rust.feature","value":"other"});
    cases.push(("edge/site condition", mismatched_condition));

    let mut wrong_mapping = rust_semantic_call_values();
    let call_site_id = semantic_site_id(&wrong_mapping, "call");
    let edge = linked_edge_mut(&mut wrong_mapping, &call_site_id);
    edge["kind"] = json!("depends_on");
    rehash_json_edge(edge);
    cases.push(("call edge mapping", wrong_mapping));

    let mut unstable_site_id = rust_semantic_call_values();
    let old_site_id = semantic_site_id(&unstable_site_id, "call");
    let edge = linked_edge_mut(&mut unstable_site_id, &old_site_id);
    edge["site_id"] = json!("site:not-the-canonical-hash");
    rehash_json_edge(edge);
    unstable_site_id
        .iter_mut()
        .find(|event| event["event"] == "dependency_site" && event["site"]["id"] == old_site_id)
        .expect("Rust call site")["site"]["id"] = json!("site:not-the-canonical-hash");
    cases.push(("stable site mapping", unstable_site_id));

    for (name, events) in cases {
        let input = values_to_ndjson(events);
        assert!(schema_accepts_stream(&input), "base Schema rejected {name}");
        assert!(
            validate_safe_ndjson(Cursor::new(&input)).is_ok(),
            "base validator rejected open-vocabulary {name} case"
        );
        assert!(
            validate_safe_semantic_ndjson(Cursor::new(input)).is_err(),
            "strict validator accepted Rust call {name} drift"
        );
    }
}

#[test]
fn rust_semantic_imports_use_the_documented_external_and_unresolved_sentinels() {
    for (status, precision, target_id, target_kind, reason) in [
        (
            "external",
            "exact",
            "external-system:rust:serde",
            "external_system",
            None,
        ),
        (
            "unresolved",
            "heuristic",
            "unknown-target:rust:broken-use",
            "unknown_target",
            Some("HIR import target could not be resolved"),
        ),
    ] {
        let mut events = rust_semantic_dependency_values();
        insert_plain_node(&mut events, target_id, target_kind);
        reassign_site_target(&mut events, "rust_use", target_id);
        let site_id = semantic_site_id(&events, "rust_use");
        let site = events
            .iter_mut()
            .find(|event| event["event"] == "dependency_site" && event["site"]["id"] == site_id)
            .expect("Rust use site");
        site["site"]["resolution_status"] = json!(status);
        site["site"]["precision"] = json!(precision);
        if let Some(reason) = reason {
            site["site"]["reason"] = json!(reason);
        }
        let edge = linked_edge_mut(&mut events, &site_id);
        edge["resolution_status"] = json!(status);
        edge["precision"] = json!(precision);
        for event in &mut events {
            if matches!(
                event["event"].as_str(),
                Some("profile_completed" | "scan_completed")
            ) {
                event["coverage"]["resolved"] = json!(2);
                event["coverage"][status] = json!(1);
            }
        }
        let input = values_to_ndjson(events);
        assert!(schema_accepts_stream(&input));
        assert!(semantic_schema_accepts_stream(&input));
        validate_safe_semantic_ndjson(Cursor::new(input)).unwrap_or_else(|error| {
            panic!("Rust semantic import {status}/{precision} must validate: {error}")
        });
    }
}

#[test]
fn semantic_dependency_recognition_is_primary_evidence_driven() {
    validate_safe_semantic_ndjson(Cursor::new(SOURCE_GOLDEN))
        .expect("source-phase imports on a non-semantic site remain protocol-v1 compatible");
    let rust_source_dependencies = values_to_ndjson(rust_source_dependency_values());
    assert!(semantic_schema_accepts_stream(&rust_source_dependencies));
    let validated = validate_safe_semantic_ndjson(Cursor::new(rust_source_dependencies))
        .expect("source-primary rust_use/rust_reexport/type_use sites remain backward compatible");
    let type_use = validated
        .sites
        .values()
        .find(|site| site.kind == "type_use")
        .expect("source-primary type_use site");
    assert_eq!(type_use.evidence[0].kind, EvidenceKind::Source);
    assert_eq!(type_use.resolution_status, ResolutionStatus::External);
    assert_eq!(type_use.precision, Precision::Heuristic);
    let type_use_edge = validated
        .edges
        .values()
        .find(|edge| edge.site_id.as_deref() == Some(type_use.id.as_str()))
        .expect("source-primary type_use edge");
    assert_eq!(type_use_edge.kind, "type_uses");
    assert_eq!(type_use_edge.phase, Phase::Source);

    let mut unresolved = rust_source_dependency_values();
    set_source_type_use_resolution(
        &mut unresolved,
        "unresolved",
        "heuristic",
        "unknown-target:rust:source-type-use",
        "unknown_target",
        Some("semantic type resolution was unavailable"),
    );
    let unresolved = values_to_ndjson(unresolved);
    assert!(semantic_schema_accepts_stream(&unresolved));
    let validated = validate_safe_semantic_ndjson(Cursor::new(unresolved))
        .expect("unresolved/heuristic source-primary type_use must validate");
    let type_use = validated
        .sites
        .values()
        .find(|site| site.kind == "type_use")
        .expect("unresolved source-primary type_use site");
    assert_eq!(type_use.resolution_status, ResolutionStatus::Unresolved);
    assert_eq!(type_use.precision, Precision::Heuristic);
}

#[test]
fn source_fallback_contract_rejects_mutated_primary_evidence_and_metadata() {
    let mut cases = Vec::<(&str, Vec<Value>)>::new();

    let mut resolved_type_use = rust_source_dependency_values();
    let concrete_target = node_id_by_display_name(&resolved_type_use, "Envelope");
    set_source_type_use_resolution(
        &mut resolved_type_use,
        "resolved",
        "heuristic",
        &concrete_target,
        "type",
        None,
    );
    cases.push((
        "source-primary type_use uses resolved status",
        resolved_type_use,
    ));

    let mut exact_type_use = rust_source_dependency_values();
    let type_use_id = semantic_site_id(&exact_type_use, "type_use");
    exact_type_use
        .iter_mut()
        .find(|event| event["event"] == "dependency_site" && event["site"]["id"] == type_use_id)
        .expect("source type-use site")["site"]["precision"] = json!("exact");
    linked_edge_mut(&mut exact_type_use, &type_use_id)["precision"] = json!("exact");
    cases.push((
        "source-primary type_use uses exact precision",
        exact_type_use,
    ));

    let mut incomplete_site_primary = rust_source_dependency_values();
    let type_use_id = semantic_site_id(&incomplete_site_primary, "type_use");
    let site = incomplete_site_primary
        .iter_mut()
        .find(|event| event["event"] == "dependency_site" && event["site"]["id"] == type_use_id)
        .expect("source type-use site");
    let supporting = site["site"]["evidence"][0].clone();
    site["site"]["evidence"]
        .as_array_mut()
        .expect("site evidence")
        .push(supporting);
    let primary = site["site"]["evidence"][0]
        .as_object_mut()
        .expect("primary site evidence");
    for field in [
        "path",
        "start_line",
        "start_column",
        "end_line",
        "end_column",
    ] {
        primary.remove(field);
    }
    cases.push((
        "source fallback site primary evidence has an incomplete span",
        incomplete_site_primary,
    ));

    let mut incomplete_edge_primary = rust_source_dependency_values();
    let type_use_id = semantic_site_id(&incomplete_edge_primary, "type_use");
    let edge = linked_edge_mut(&mut incomplete_edge_primary, &type_use_id);
    let supporting = edge["evidence"][0].clone();
    edge["evidence"]
        .as_array_mut()
        .expect("edge evidence")
        .push(supporting);
    let primary = edge["evidence"][0]
        .as_object_mut()
        .expect("primary edge evidence");
    for field in [
        "path",
        "start_line",
        "start_column",
        "end_line",
        "end_column",
    ] {
        primary.remove(field);
    }
    cases.push((
        "source fallback edge primary evidence has an incomplete span",
        incomplete_edge_primary,
    ));

    let mut mismatched_anchor = rust_source_dependency_values();
    let type_use_id = semantic_site_id(&mismatched_anchor, "type_use");
    linked_edge_mut(&mut mismatched_anchor, &type_use_id)["evidence"][0]["extractor"] =
        json!("different-source-extractor");
    cases.push((
        "source fallback primary evidence anchors differ",
        mismatched_anchor,
    ));

    let mut mismatched_condition = rust_source_dependency_values();
    let type_use_id = semantic_site_id(&mismatched_condition, "type_use");
    let site_condition = mismatched_condition
        .iter()
        .find(|event| event["event"] == "dependency_site" && event["site"]["id"] == type_use_id)
        .expect("source type-use site")["site"]["condition"]
        .clone();
    linked_edge_mut(&mut mismatched_condition, &type_use_id)["condition"] = json!({
        "op": "all",
        "conditions": [
            site_condition,
            {"op": "eq", "key": "rust.feature", "value": "extra"}
        ]
    });
    cases.push((
        "source fallback edge condition narrows its site",
        mismatched_condition,
    ));

    let mut mismatched_source = rust_source_dependency_values();
    let type_use_id = semantic_site_id(&mismatched_source, "type_use");
    let other_source = node_id_by_display_name(&mismatched_source, "crate");
    linked_edge_mut(&mut mismatched_source, &type_use_id)["source"] = json!(other_source);
    cases.push((
        "source fallback edge source differs from its site",
        mismatched_source,
    ));

    let mut mismatched_status = rust_source_dependency_values();
    let type_use_id = semantic_site_id(&mismatched_status, "type_use");
    linked_edge_mut(&mut mismatched_status, &type_use_id)["resolution_status"] =
        json!("candidates");
    cases.push((
        "source fallback edge status differs from its site",
        mismatched_status,
    ));

    let mut mismatched_precision = rust_source_dependency_values();
    let type_use_id = semantic_site_id(&mismatched_precision, "type_use");
    linked_edge_mut(&mut mismatched_precision, &type_use_id)["precision"] = json!("exact");
    cases.push((
        "source fallback edge precision differs from its site",
        mismatched_precision,
    ));

    for (name, events) in cases {
        let input = values_to_ndjson(events);
        assert!(schema_accepts_stream(&input), "base Schema rejected {name}");
        assert!(
            semantic_schema_accepts_stream(&input),
            "strict Schema unexpectedly rejected source fallback mutation {name}"
        );
        assert!(
            validate_safe_semantic_ndjson(Cursor::new(input)).is_err(),
            "strict Rust validator accepted {name}"
        );
    }
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
fn site_less_definition_relations_are_strictly_validated() {
    let mutate_edge = |events: &mut [Value], kind: &str, update: &dyn Fn(&mut Value)| {
        let edge = events
            .iter_mut()
            .find(|event| event["event"] == "edge_upsert" && event["edge"]["kind"] == kind)
            .unwrap_or_else(|| panic!("missing {kind} definition relation"));
        update(&mut edge["edge"]);
    };

    let mut bad_hash = rust_semantic_values();
    mutate_edge(&mut bad_hash, "declares", &|edge| {
        edge["id"] = json!(format!("edge:sha256:{}", "0".repeat(64)));
    });

    let mut wrong_phase = rust_semantic_values();
    mutate_edge(&mut wrong_phase, "extends", &|edge| {
        edge["phase"] = json!("source");
    });

    let mut wrong_resolution = rust_semantic_values();
    mutate_edge(&mut wrong_resolution, "implements", &|edge| {
        edge["resolution_status"] = json!("external");
    });

    let mut wrong_precision = rust_semantic_values();
    mutate_edge(&mut wrong_precision, "instantiates", &|edge| {
        edge["precision"] = json!("heuristic");
    });

    let mut source_primary = rust_semantic_values();
    mutate_edge(&mut source_primary, "declares", &|edge| {
        edge["evidence"][0]["kind"] = json!("source");
    });

    let mut linked_to_site = rust_semantic_values();
    mutate_edge(&mut linked_to_site, "extends", &|edge| {
        edge["site_id"] = json!("site:sha256:forbidden");
    });

    let mut wrong_endpoint = rust_semantic_values();
    let module_id = node_id_by_display_name(&wrong_endpoint, "crate");
    mutate_edge(&mut wrong_endpoint, "implements", &|edge| {
        edge["target"] = json!(module_id);
        rehash_definition_edge(edge);
    });

    for (name, events) in [
        ("canonical edge ID", bad_hash),
        ("semantic phase", wrong_phase),
        ("resolved status", wrong_resolution),
        ("exact precision", wrong_precision),
        ("semantic primary evidence", source_primary),
        ("site-less relation", linked_to_site),
        ("compatible endpoints", wrong_endpoint),
    ] {
        let input = values_to_ndjson(events);
        assert!(
            validate_safe_semantic_ndjson(Cursor::new(input)).is_err(),
            "strict semantic validator accepted definition relation with invalid {name}"
        );
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
fn go_value_references_are_strict_symbol_dependencies() {
    let events = go_value_reference_values();
    let input = values_to_ndjson(events.clone());
    assert!(schema_accepts_stream(&input));
    assert!(semantic_schema_accepts_stream(&input));
    let validated = validate_safe_semantic_ndjson(Cursor::new(input))
        .expect("Go value-reference fixture must validate");

    let reference = edge_by_kind(&validated.edges, "references");
    assert_semantic_edge(reference, ResolutionStatus::Resolved, Precision::Exact);
    assert_eq!(validated.nodes[&reference.source].kind, "symbol");
    assert_eq!(validated.nodes[&reference.target].kind, "symbol");
    let site = site_for_edge(&validated.sites, reference);
    assert_eq!(site.kind, "value_reference");
    assert_eq!(
        site.target_ids.as_slice(),
        std::slice::from_ref(&reference.target)
    );
    assert_eq!(site.evidence[0].extractor, "go-types");

    let mut wrong_target = events;
    let type_id = wrong_target
        .iter()
        .find(|event| event["event"] == "node_upsert" && event["node"]["kind"] == "type")
        .expect("semantic type node")["node"]["id"]
        .as_str()
        .expect("type ID")
        .to_owned();
    reassign_site_target(&mut wrong_target, "value_reference", &type_id);
    let input = values_to_ndjson(wrong_target);
    assert!(schema_accepts_stream(&input));
    assert!(semantic_schema_accepts_stream(&input));
    assert!(
        validate_safe_semantic_ndjson(Cursor::new(input))
            .expect_err("value reference to a type must be rejected")
            .to_string()
            .contains("must be a symbol node")
    );
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
fn rust_semantic_dependency_contract_rejects_wrong_mapping_and_invariants() {
    let mut cases = Vec::<(&str, Vec<Value>, bool)>::new();

    let mut wrong_edge_kind = rust_semantic_dependency_values();
    let use_site_id = semantic_site_id(&wrong_edge_kind, "rust_use");
    let edge = linked_edge_mut(&mut wrong_edge_kind, &use_site_id);
    edge["kind"] = json!("reexports");
    rehash_json_edge(edge);
    cases.push(("rust_use mapped to reexports", wrong_edge_kind, true));

    let mut unrelated_edge_kind = rust_semantic_dependency_values();
    let use_site_id = semantic_site_id(&unrelated_edge_kind, "rust_use");
    let edge = linked_edge_mut(&mut unrelated_edge_kind, &use_site_id);
    edge["kind"] = json!("depends_on");
    rehash_json_edge(edge);
    cases.push((
        "semantic rust_use site linked to an unrelated edge kind",
        unrelated_edge_kind,
        false,
    ));

    let mut mixed_phases = rust_semantic_candidate_values();
    let use_site_id = semantic_site_id(&mixed_phases, "rust_use");
    linked_edge_mut(&mut mixed_phases, &use_site_id)["phase"] = json!("source");
    cases.push((
        "semantic rust_use site mixes source and semantic edges",
        mixed_phases,
        false,
    ));

    for phase in ["build", "runtime"] {
        let mut wrong_phase = rust_semantic_dependency_values();
        let use_site_id = semantic_site_id(&wrong_phase, "rust_use");
        linked_edge_mut(&mut wrong_phase, &use_site_id)["phase"] = json!(phase);
        cases.push((
            if phase == "build" {
                "semantic rust_use site linked to a build edge"
            } else {
                "semantic rust_use site linked to a runtime edge"
            },
            wrong_phase,
            false,
        ));
    }

    let mut semantic_type_use_with_source_edge = rust_semantic_dependency_values();
    let type_use_site_id = semantic_site_id(&semantic_type_use_with_source_edge, "type_use");
    linked_edge_mut(&mut semantic_type_use_with_source_edge, &type_use_site_id)["phase"] =
        json!("source");
    cases.push((
        "semantic-primary type_use site linked to a source edge",
        semantic_type_use_with_source_edge,
        false,
    ));

    let mut source_type_use_with_semantic_edge = rust_source_dependency_values();
    let type_use_site_id = semantic_site_id(&source_type_use_with_semantic_edge, "type_use");
    linked_edge_mut(&mut source_type_use_with_semantic_edge, &type_use_site_id)["phase"] =
        json!("semantic");
    cases.push((
        "source-primary type_use fallback uses a semantic edge",
        source_type_use_with_semantic_edge,
        true,
    ));

    let mut wrong_reexport_source = rust_semantic_dependency_values();
    let symbol_id = node_id_by_display_name(&wrong_reexport_source, "exercise");
    reassign_site_source(&mut wrong_reexport_source, "rust_reexport", &symbol_id);
    cases.push((
        "rust_reexport source is not a module",
        wrong_reexport_source,
        true,
    ));

    let mut wrong_source_language = rust_semantic_dependency_values();
    let module = wrong_source_language
        .iter_mut()
        .find(|event| event["event"] == "node_upsert" && event["node"]["display_name"] == "crate")
        .expect("Rust module source");
    module["node"]["properties"]["language"] = json!("go");
    cases.push((
        "Rust semantic source language is not rust",
        wrong_source_language,
        true,
    ));

    let mut wrong_import_target = rust_semantic_dependency_values();
    insert_file_node(&mut wrong_import_target, "file:invalid-import-target");
    reassign_site_target(
        &mut wrong_import_target,
        "rust_use",
        "file:invalid-import-target",
    );
    cases.push((
        "rust_use concrete target is not semantic",
        wrong_import_target,
        true,
    ));

    let mut mismatched_condition = rust_semantic_dependency_values();
    let use_site_id = semantic_site_id(&mismatched_condition, "rust_use");
    linked_edge_mut(&mut mismatched_condition, &use_site_id)["condition"] =
        json!({"op":"eq","key":"rust.feature","value":"other"});
    cases.push((
        "Rust semantic edge condition differs from its site",
        mismatched_condition,
        true,
    ));

    let mut reversed_candidates = rust_semantic_candidate_values();
    reversed_candidates
        .iter_mut()
        .find(|event| event["event"] == "dependency_site" && event["site"]["kind"] == "rust_use")
        .expect("Rust use site")["site"]["target_ids"]
        .as_array_mut()
        .expect("candidate targets")
        .reverse();
    cases.push((
        "Rust semantic candidates are not sorted",
        reversed_candidates,
        true,
    ));

    let mut mismatched_primary_extractor = rust_semantic_dependency_values();
    let use_site_id = semantic_site_id(&mismatched_primary_extractor, "rust_use");
    linked_edge_mut(&mut mismatched_primary_extractor, &use_site_id)["evidence"][0]["extractor"] =
        json!("different-semantic-extractor");
    cases.push((
        "site and edge primary evidence anchors differ",
        mismatched_primary_extractor,
        true,
    ));

    let mut empty_specifier = rust_semantic_dependency_values();
    empty_specifier
        .iter_mut()
        .find(|event| event["event"] == "dependency_site" && event["site"]["kind"] == "rust_use")
        .expect("Rust use site")["site"]["specifier"] = json!("");
    cases.push(("semantic site specifier is empty", empty_specifier, false));

    for (name, events, semantic_schema_accepts) in cases {
        let input = values_to_ndjson(events);
        assert!(schema_accepts_stream(&input), "base Schema rejected {name}");
        assert_eq!(
            semantic_schema_accepts_stream(&input),
            semantic_schema_accepts,
            "unexpected strict Schema result for {name}"
        );
        assert!(
            validate_safe_semantic_ndjson(Cursor::new(input)).is_err(),
            "strict Rust validator accepted {name}"
        );
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
fn source_phase_definition_vocabulary_remains_strictly_compatible() {
    let mut events: Vec<Value> = SOURCE_GOLDEN
        .lines()
        .map(|line| serde_json::from_str(line).expect("source fixture JSON"))
        .collect();
    let edge = events
        .iter_mut()
        .find(|event| event["event"] == "edge_upsert")
        .expect("source edge");
    edge["edge"]["kind"] = json!("declares");
    edge["edge"]["phase"] = json!("source");
    edge["edge"]["evidence"][0]["kind"] = json!("source");

    let input = values_to_ndjson(events);
    assert!(schema_accepts_stream(&input));
    assert!(semantic_schema_accepts_stream(&input));
    validate_safe_semantic_ndjson(Cursor::new(input))
        .expect("source-phase vocabulary must not be mistaken for a semantic definition relation");
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

fn go_value_reference_values() -> Vec<Value> {
    let mut events = semantic_values();
    let site_index = events
        .iter()
        .position(|event| {
            event["event"] == "dependency_site"
                && event["site"]["kind"] == "call"
                && event["site"]["specifier"] == "service.Start"
        })
        .expect("direct Go call site");
    let old_id = events[site_index]["site"]["id"]
        .as_str()
        .expect("call site ID")
        .to_owned();
    events[site_index]["site"]["kind"] = json!("value_reference");
    events[site_index]["site"]["evidence"][0]["extractor"] = json!("go-types");
    events[site_index]["site"]["evidence"][0]["extractor_version"] = json!("0.1.0");
    events[site_index]["site"]["evidence"][0]["detail"] = json!("first-class function reference");
    events[site_index]["site"]["evidence"][0]["properties"] = json!({
        "object_kind": "function",
        "occurrence_kind": "identifier",
        "resolver_identity": "example.com/acme/service.Start",
    });
    let new_id = rehash_json_site(&mut events[site_index]["site"]);
    let evidence = events[site_index]["site"]["evidence"].clone();
    let edge = linked_edge_mut(&mut events, &old_id);
    edge["kind"] = json!("references");
    edge["site_id"] = json!(new_id);
    edge["evidence"] = evidence;
    rehash_json_edge(edge);
    sort_site_events(&mut events);
    sort_edge_events(&mut events);
    resequence(&mut events);
    events
}

fn rust_semantic_values() -> Vec<Value> {
    RUST_SEMANTIC_GOLDEN
        .lines()
        .map(|line| serde_json::from_str(line).expect("Rust semantic fixture JSON"))
        .collect()
}

fn rust_semantic_dependency_values() -> Vec<Value> {
    let mut events = rust_semantic_values();
    let module_id = node_id_by_display_name(&events, "crate");
    let function_id = node_id_by_display_name(&events, "exercise");
    let envelope_id = node_id_by_display_name(&events, "Envelope");
    let named_id = node_id_by_display_name(&events, "Named");
    let profile_id = "cargo:rust-semantic-fixture:debug:host";
    let crate_identity = "Cargo.toml#lib:rust_semantic_fixture:src/lib.rs";
    let condition = json!({
        "op": "eq",
        "key": "rust.crate_instance",
        "value": crate_identity,
    });
    let dependencies = [
        (
            "rust_use",
            "imports",
            module_id.as_str(),
            envelope_id.as_str(),
            "crate::domain::Envelope",
            1_u64,
            5_u64,
            28_u64,
            "use-tree-leaf",
        ),
        (
            "rust_reexport",
            "reexports",
            module_id.as_str(),
            named_id.as_str(),
            "crate::domain::Named",
            2_u64,
            9_u64,
            29_u64,
            "reexport-tree-leaf",
        ),
        (
            "type_use",
            "type_uses",
            function_id.as_str(),
            envelope_id.as_str(),
            "crate::domain::Envelope<u32>",
            3_u64,
            24_u64,
            36_u64,
            "signature-type-reference",
        ),
    ];

    let mut site_events = Vec::new();
    let mut edge_events = Vec::new();
    for (
        site_kind,
        edge_kind,
        source,
        target,
        specifier,
        line,
        start_column,
        end_column,
        hir_kind,
    ) in dependencies
    {
        let primary = json!({
            "kind": "semantic",
            "extractor": "rust-analyzer-hir",
            "extractor_version": "0.0.330",
            "path": "src/lib.rs",
            "start_line": line,
            "start_column": start_column,
            "end_line": line,
            "end_column": end_column,
            "detail": format!("HIR {site_kind} occurrence"),
            "properties": {
                "backend": "rust-analyzer-library",
                "rust_analyzer_revision": "8954b66d43225e62c92e8bbcc8500191b5cceb1e",
                "crate_identity": crate_identity,
                "active_cfg": ["debug_assertions", "unix"],
                "hir_kind": hir_kind,
                "resolver": "rust-analyzer-hir",
            },
        });
        let source_evidence = json!({
            "kind": "source",
            "extractor": "rust-syntax",
            "extractor_version": "0.1.0",
            "path": "src/lib.rs",
            "start_line": line,
            "start_column": start_column,
            "end_line": line,
            "end_column": end_column,
            "detail": format!("syntax evidence for {site_kind}"),
            "properties": {},
        });
        let mut site = json!({
            "id": "pending",
            "source": source,
            "kind": site_kind,
            "specifier": specifier,
            "resolution_status": "resolved",
            "target_ids": [target],
            "profile_id": profile_id,
            "condition": condition,
            "precision": "exact",
            "evidence": [primary, source_evidence],
        });
        let site_id = rehash_json_site(&mut site);
        let mut edge = json!({
            "id": "pending",
            "source": source,
            "target": target,
            "kind": edge_kind,
            "site_id": site_id,
            "phase": "semantic",
            "environment": "any",
            "profile_id": profile_id,
            "condition": condition,
            "resolution_status": "resolved",
            "precision": "exact",
            "generated": false,
            "evidence": site["evidence"].clone(),
        });
        rehash_json_edge(&mut edge);
        site_events.push(json!({
            "event": "dependency_site",
            "protocol_version": "1.0",
            "scan_id": "scan-rust-semantic-golden",
            "adapter": "rust",
            "adapter_version": "0.1.0",
            "seq": 0,
            "site": site,
        }));
        edge_events.push(json!({
            "event": "edge_upsert",
            "protocol_version": "1.0",
            "scan_id": "scan-rust-semantic-golden",
            "adapter": "rust",
            "adapter_version": "0.1.0",
            "seq": 0,
            "edge": edge,
        }));
    }
    site_events.sort_by(|left, right| {
        left["site"]["id"]
            .as_str()
            .cmp(&right["site"]["id"].as_str())
    });
    let first_edge = events
        .iter()
        .position(|event| event["event"] == "edge_upsert")
        .expect("Rust semantic edge events");
    events.splice(first_edge..first_edge, site_events);
    let file_completed = events
        .iter()
        .position(|event| event["event"] == "file_completed")
        .expect("Rust file completion");
    events.splice(file_completed..file_completed, edge_events);
    sort_edge_events(&mut events);

    let file = events
        .iter_mut()
        .find(|event| event["event"] == "file_completed")
        .expect("Rust file completion");
    file["discovered_sites"] = json!(3);
    file["emitted_sites"] = json!(3);
    for event in &mut events {
        if matches!(
            event["event"].as_str(),
            Some("profile_completed" | "scan_completed")
        ) {
            event["coverage"]["dependency_sites"] = json!(3);
            event["coverage"]["resolved"] = json!(3);
        }
    }
    resequence(&mut events);
    events
}

fn web_semantic_dependency_values() -> Vec<Value> {
    let mut events = rust_semantic_dependency_values();
    let source_id = node_id_by_display_name(&events, "crate");
    let source = events
        .iter_mut()
        .find(|event| event["node"]["id"] == source_id)
        .expect("module source node");
    source["node"]["kind"] = json!("file");
    source["node"]["locator"] = json!("file://src/index.ts");
    source["node"]["display_name"] = json!("src/index.ts");
    source["node"]["properties"] = json!({
        "language":"typescript",
        "path":"src/index.ts",
    });
    let web_type_node = |display_name: &str| {
        let identity = json!({
            "language":"typescript",
            "package_locator":"npm:workspace:web-semantic-fixture@1.0.0#.",
            "type_kind":"interface",
            "resolver_identity":format!("npm:workspace:web-semantic-fixture@1.0.0#.::module:src/target.ts#{display_name}"),
        });
        let id = stable_id_from_value("type", &identity);
        json!({
            "event":"node_upsert",
            "protocol_version":"1.0",
            "scan_id":"scan-rust-semantic-golden",
            "adapter":"rust",
            "adapter_version":"0.1.0",
            "seq":0,
            "node":{
                "id":id,
                "kind":"type",
                "locator":format!("typescript-type:{id}"),
                "display_name":display_name,
                "properties":{
                    "language":"typescript",
                    "package_locator":"npm:workspace:web-semantic-fixture@1.0.0#.",
                    "type_kind":"interface",
                    "canonical_identity":identity,
                },
            },
        })
    };
    let target_a = web_type_node("WebTargetA");
    let target_b = web_type_node("WebTargetB");
    let target_id = target_a["node"]["id"]
        .as_str()
        .expect("Web target ID")
        .to_owned();
    let first_site = events
        .iter()
        .position(|event| event["event"] == "dependency_site")
        .expect("dependency sites");
    events.insert(first_site, target_a);
    events.insert(first_site + 1, target_b);
    events.retain(|event| {
        event["event"] != "edge_upsert" || event["edge"]["site_id"].as_str().is_some()
    });

    for (old_kind, site_kind, edge_kind) in [
        ("rust_use", "web_import", "imports"),
        ("rust_reexport", "web_reexport", "reexports"),
        ("type_use", "type_use", "type_uses"),
    ] {
        let site_index = events
            .iter()
            .position(|event| {
                event["event"] == "dependency_site"
                    && event["site"]["kind"].as_str() == Some(old_kind)
            })
            .unwrap_or_else(|| panic!("missing {old_kind} site"));
        let old_site_id = events[site_index]["site"]["id"]
            .as_str()
            .expect("old site ID")
            .to_owned();
        events[site_index]["site"]["kind"] = json!(site_kind);
        events[site_index]["site"]["source"] = json!(source_id);
        events[site_index]["site"]["target_ids"] = json!([target_id]);
        let new_site_id = rehash_json_site(&mut events[site_index]["site"]);
        let edge = events
            .iter_mut()
            .find(|event| {
                event["event"] == "edge_upsert"
                    && event["edge"]["site_id"].as_str() == Some(old_site_id.as_str())
            })
            .unwrap_or_else(|| panic!("missing {old_kind} edge"));
        edge["edge"]["source"] = json!(source_id);
        edge["edge"]["kind"] = json!(edge_kind);
        edge["edge"]["site_id"] = json!(new_site_id);
        edge["edge"]["target"] = json!(target_id);
        rehash_json_edge(&mut edge["edge"]);
    }
    sort_edge_events(&mut events);
    resequence(&mut events);
    events
}

fn framework_semantic_values() -> Vec<Value> {
    FRAMEWORK_SEMANTIC_GOLDEN
        .lines()
        .map(|line| serde_json::from_str(line).expect("framework semantic golden line"))
        .collect()
}

fn rust_semantic_candidate_values() -> Vec<Value> {
    let mut events = rust_semantic_dependency_values();
    let second_target = node_id_by_display_name(&events, "Named");
    let site_index = events
        .iter()
        .position(|event| {
            event["event"] == "dependency_site" && event["site"]["kind"] == "rust_use"
        })
        .expect("Rust use site");
    let site_id = events[site_index]["site"]["id"]
        .as_str()
        .expect("Rust use site ID")
        .to_owned();
    let mut targets = events[site_index]["site"]["target_ids"]
        .as_array()
        .expect("Rust use targets")
        .clone();
    targets.push(json!(second_target));
    targets.sort_by(|left, right| left.as_str().cmp(&right.as_str()));
    events[site_index]["site"]["target_ids"] = Value::Array(targets);
    events[site_index]["site"]["resolution_status"] = json!("candidates");
    events[site_index]["site"]["precision"] = json!("overapprox");

    let edge_index = events
        .iter()
        .position(|event| event["event"] == "edge_upsert" && event["edge"]["site_id"] == site_id)
        .expect("Rust use edge");
    events[edge_index]["edge"]["resolution_status"] = json!("candidates");
    events[edge_index]["edge"]["precision"] = json!("overapprox");
    let mut second_edge = events[edge_index].clone();
    second_edge["edge"]["target"] = json!(second_target);
    rehash_json_edge(&mut second_edge["edge"]);
    let file_completed = events
        .iter()
        .position(|event| event["event"] == "file_completed")
        .expect("Rust file completion");
    events.insert(file_completed, second_edge);
    sort_edge_events(&mut events);
    for event in &mut events {
        if matches!(
            event["event"].as_str(),
            Some("profile_completed" | "scan_completed")
        ) {
            event["coverage"]["resolved"] = json!(2);
            event["coverage"]["candidates"] = json!(1);
        }
    }
    resequence(&mut events);
    events
}

fn rust_semantic_call_values() -> Vec<Value> {
    let mut events = rust_semantic_dependency_values();
    let source_id = node_id_by_display_name(&events, "exercise");
    let source_index = events
        .iter()
        .position(|event| event["event"] == "node_upsert" && event["node"]["id"] == source_id)
        .expect("Rust call source node");
    let mut target_event = events[source_index].clone();
    let resolver_identity = "Cargo.toml#lib:rust_semantic_fixture:src/lib.rs::crate::callee";
    target_event["seq"] = json!(0);
    target_event["node"]["locator"] =
        json!("rust-symbol:Cargo.toml#lib:rust_semantic_fixture:src/lib.rs::crate::callee");
    target_event["node"]["display_name"] = json!("callee");
    target_event["node"]["properties"]["resolver_identity"] = json!(resolver_identity);
    target_event["node"]["properties"]["canonical_identity"]["resolver_identity"] =
        json!(resolver_identity);
    target_event["node"]["properties"]["source_span"] = json!({
        "start_line": 10,
        "start_column": 1,
        "end_line": 10,
        "end_column": 16,
    });
    let target_id = stable_id_from_value(
        "symbol",
        &target_event["node"]["properties"]["canonical_identity"],
    );
    target_event["node"]["id"] = json!(target_id);

    let first_site = events
        .iter()
        .position(|event| event["event"] == "dependency_site")
        .expect("Rust dependency sites");
    events.insert(first_site, target_event);
    let first_node = events
        .iter()
        .position(|event| event["event"] == "node_upsert")
        .expect("Rust nodes");
    let last_node = events
        .iter()
        .rposition(|event| event["event"] == "node_upsert")
        .expect("Rust nodes");
    events[first_node..=last_node].sort_by(|left, right| {
        left["node"]["id"]
            .as_str()
            .cmp(&right["node"]["id"].as_str())
    });

    let profile_id = "cargo:rust-semantic-fixture:debug:host";
    let crate_identity = "Cargo.toml#lib:rust_semantic_fixture:src/lib.rs";
    let condition = json!({
        "op": "eq",
        "key": "rust.crate_instance",
        "value": crate_identity,
    });
    let primary = json!({
        "kind": "semantic",
        "extractor": "rust-analyzer-hir",
        "extractor_version": "0.0.330",
        "path": "src/lib.rs",
        "start_line": 5,
        "start_column": 5,
        "end_line": 5,
        "end_column": 13,
        "detail": "HIR exact function call",
        "properties": {
            "backend": "rust-analyzer-library",
            "rust_analyzer_revision": "8954b66d43225e62c92e8bbcc8500191b5cceb1e",
            "crate_identity": crate_identity,
            "active_cfg": ["debug_assertions", "unix"],
            "hir_kind": "function-call",
            "dispatch": "static",
        },
    });
    let source_evidence = json!({
        "kind": "source",
        "extractor": "rust-syntax",
        "extractor_version": "0.1.0",
        "path": "src/lib.rs",
        "start_line": 5,
        "start_column": 5,
        "end_line": 5,
        "end_column": 13,
        "detail": "syntax evidence for call",
        "properties": {},
    });
    let mut site = json!({
        "id": "pending",
        "source": source_id,
        "kind": "call",
        "specifier": "callee",
        "resolution_status": "resolved",
        "target_ids": [target_id],
        "profile_id": profile_id,
        "condition": condition,
        "precision": "exact",
        "evidence": [primary, source_evidence],
    });
    let site_id = rehash_json_site(&mut site);
    let mut edge = json!({
        "id": "pending",
        "source": source_id,
        "target": target_id,
        "kind": "calls",
        "site_id": site_id,
        "phase": "semantic",
        "environment": "any",
        "profile_id": profile_id,
        "condition": condition,
        "resolution_status": "resolved",
        "precision": "exact",
        "generated": false,
        "evidence": site["evidence"].clone(),
    });
    rehash_json_edge(&mut edge);

    let first_edge = events
        .iter()
        .position(|event| event["event"] == "edge_upsert")
        .expect("Rust semantic edges");
    events.insert(
        first_edge,
        json!({
            "event": "dependency_site",
            "protocol_version": "1.0",
            "scan_id": "scan-rust-semantic-golden",
            "adapter": "rust",
            "adapter_version": "0.1.0",
            "seq": 0,
            "site": site,
        }),
    );
    sort_site_events(&mut events);
    let file_completed = events
        .iter()
        .position(|event| event["event"] == "file_completed")
        .expect("Rust file completion");
    events.insert(
        file_completed,
        json!({
            "event": "edge_upsert",
            "protocol_version": "1.0",
            "scan_id": "scan-rust-semantic-golden",
            "adapter": "rust",
            "adapter_version": "0.1.0",
            "seq": 0,
            "edge": edge,
        }),
    );
    sort_edge_events(&mut events);

    let file = events
        .iter_mut()
        .find(|event| event["event"] == "file_completed")
        .expect("Rust file completion");
    file["discovered_sites"] = json!(4);
    file["emitted_sites"] = json!(4);
    for event in &mut events {
        if matches!(
            event["event"].as_str(),
            Some("profile_completed" | "scan_completed")
        ) {
            event["coverage"]["dependency_sites"] = json!(4);
            event["coverage"]["resolved"] = json!(4);
        }
    }
    resequence(&mut events);
    events
}

fn rust_semantic_candidate_call_values() -> Vec<Value> {
    let mut events = rust_semantic_call_values();
    let site_id = semantic_site_id(&events, "call");
    let site = events
        .iter_mut()
        .find(|event| event["event"] == "dependency_site" && event["site"]["id"] == site_id)
        .expect("Rust candidate call site");
    site["site"]["resolution_status"] = json!("candidates");
    site["site"]["precision"] = json!("overapprox");
    site["site"]["evidence"][0]["properties"]["algorithm"] =
        json!("rust-analyzer-local-trait-impls-v1");

    let edge = linked_edge_mut(&mut events, &site_id);
    edge["kind"] = json!("may_call");
    edge["resolution_status"] = json!("candidates");
    edge["precision"] = json!("overapprox");
    edge["evidence"][0]["properties"]["algorithm"] = json!("rust-analyzer-local-trait-impls-v1");
    rehash_json_edge(edge);
    sort_edge_events(&mut events);
    for event in &mut events {
        if matches!(
            event["event"].as_str(),
            Some("profile_completed" | "scan_completed")
        ) {
            event["coverage"]["resolved"] = json!(3);
            event["coverage"]["candidates"] = json!(1);
        }
    }
    resequence(&mut events);
    events
}

fn rust_source_dependency_values() -> Vec<Value> {
    let mut events = rust_semantic_dependency_values();
    for event in &mut events {
        match event["event"].as_str() {
            Some("dependency_site")
                if matches!(
                    event["site"]["kind"].as_str(),
                    Some("rust_use" | "rust_reexport" | "type_use")
                ) =>
            {
                event["site"]["evidence"] = json!([event["site"]["evidence"][1].clone()]);
            }
            Some("edge_upsert")
                if matches!(
                    event["edge"]["kind"].as_str(),
                    Some("imports" | "reexports" | "type_uses")
                ) =>
            {
                event["edge"]["phase"] = json!("source");
                event["edge"]["evidence"] = json!([event["edge"]["evidence"][1].clone()]);
            }
            _ => {}
        }
    }
    set_source_type_use_resolution(
        &mut events,
        "external",
        "heuristic",
        "external-system:rust:source-type-use",
        "external_system",
        None,
    );
    resequence(&mut events);
    events
}

fn set_source_type_use_resolution(
    events: &mut Vec<Value>,
    status: &str,
    precision: &str,
    target_id: &str,
    target_kind: &str,
    reason: Option<&str>,
) {
    let target_exists = events.iter().any(|event| {
        event["event"] == "node_upsert" && event["node"]["id"].as_str() == Some(target_id)
    });
    if !target_exists {
        insert_plain_node(events, target_id, target_kind);
    }
    reassign_site_target(events, "type_use", target_id);
    let site_id = semantic_site_id(events, "type_use");
    let site = events
        .iter_mut()
        .find(|event| event["event"] == "dependency_site" && event["site"]["id"] == site_id)
        .expect("source fallback type-use site");
    site["site"]["resolution_status"] = json!(status);
    site["site"]["precision"] = json!(precision);
    if let Some(reason) = reason {
        site["site"]["reason"] = json!(reason);
    } else {
        site["site"]
            .as_object_mut()
            .expect("dependency site object")
            .remove("reason");
    }
    let edge = linked_edge_mut(events, &site_id);
    edge["resolution_status"] = json!(status);
    edge["precision"] = json!(precision);

    for event in events.iter_mut() {
        if !matches!(
            event["event"].as_str(),
            Some("profile_completed" | "scan_completed")
        ) {
            continue;
        }
        event["coverage"]["resolved"] = json!(if status == "resolved" { 3 } else { 2 });
        event["coverage"]["candidates"] = json!(if status == "candidates" { 1 } else { 0 });
        event["coverage"]["external"] = json!(if status == "external" { 1 } else { 0 });
        event["coverage"]["unresolved"] = json!(if status == "unresolved" { 1 } else { 0 });
    }
    resequence(events);
}

fn values_to_ndjson(events: Vec<Value>) -> String {
    events
        .into_iter()
        .map(|event| event.to_string())
        .collect::<Vec<_>>()
        .join("\n")
}

fn node_id_by_display_name(events: &[Value], display_name: &str) -> String {
    events
        .iter()
        .find(|event| {
            event["event"] == "node_upsert"
                && event["node"]["display_name"].as_str() == Some(display_name)
        })
        .unwrap_or_else(|| panic!("missing node {display_name}"))["node"]["id"]
        .as_str()
        .expect("node ID")
        .to_owned()
}

fn semantic_site_id(events: &[Value], site_kind: &str) -> String {
    events
        .iter()
        .find(|event| {
            event["event"] == "dependency_site" && event["site"]["kind"].as_str() == Some(site_kind)
        })
        .unwrap_or_else(|| panic!("missing {site_kind} site"))["site"]["id"]
        .as_str()
        .expect("site ID")
        .to_owned()
}

fn linked_edge_mut<'a>(events: &'a mut [Value], site_id: &str) -> &'a mut Value {
    &mut events
        .iter_mut()
        .find(|event| {
            event["event"] == "edge_upsert" && event["edge"]["site_id"].as_str() == Some(site_id)
        })
        .unwrap_or_else(|| panic!("missing edge for site {site_id}"))["edge"]
}

fn rehash_json_site(site: &mut Value) -> String {
    let primary = &site["evidence"][0];
    let id = stable_id_from_value(
        "site",
        &json!({
            "condition": site["condition"],
            "kind": site["kind"],
            "path": primary["path"],
            "profile_id": site["profile_id"],
            "source": site["source"],
            "span": {
                "end_column": primary["end_column"],
                "end_line": primary["end_line"],
                "start_column": primary["start_column"],
                "start_line": primary["start_line"],
            },
        }),
    );
    site["id"] = json!(id);
    id
}

fn rehash_json_edge(edge: &mut Value) {
    edge["id"] = json!(stable_id_from_value(
        "edge",
        &json!({
            "kind": edge["kind"],
            "site_id": edge["site_id"],
            "target": edge["target"],
        }),
    ));
}

fn reassign_site_source(events: &mut [Value], site_kind: &str, source: &str) {
    let site_index = events
        .iter()
        .position(|event| {
            event["event"] == "dependency_site" && event["site"]["kind"].as_str() == Some(site_kind)
        })
        .unwrap_or_else(|| panic!("missing {site_kind} site"));
    let old_id = events[site_index]["site"]["id"]
        .as_str()
        .expect("old site ID")
        .to_owned();
    events[site_index]["site"]["source"] = json!(source);
    let new_id = rehash_json_site(&mut events[site_index]["site"]);
    for event in events.iter_mut().filter(|event| {
        event["event"] == "edge_upsert"
            && event["edge"]["site_id"].as_str() == Some(old_id.as_str())
    }) {
        event["edge"]["source"] = json!(source);
        event["edge"]["site_id"] = json!(new_id);
        rehash_json_edge(&mut event["edge"]);
    }
    resequence(events);
}

fn reassign_site_target(events: &mut [Value], site_kind: &str, target: &str) {
    let site_index = events
        .iter()
        .position(|event| {
            event["event"] == "dependency_site" && event["site"]["kind"].as_str() == Some(site_kind)
        })
        .unwrap_or_else(|| panic!("missing {site_kind} site"));
    let site_id = events[site_index]["site"]["id"]
        .as_str()
        .expect("site ID")
        .to_owned();
    events[site_index]["site"]["target_ids"] = json!([target]);
    let edge = linked_edge_mut(events, &site_id);
    edge["target"] = json!(target);
    rehash_json_edge(edge);
}

fn insert_file_node(events: &mut Vec<Value>, id: &str) {
    insert_plain_node(events, id, "file");
}

fn insert_plain_node(events: &mut Vec<Value>, id: &str, kind: &str) {
    let first_site = events
        .iter()
        .position(|event| event["event"] == "dependency_site")
        .expect("dependency sites");
    events.insert(
        first_site,
        json!({
            "event": "node_upsert",
            "protocol_version": "1.0",
            "scan_id": "scan-rust-semantic-golden",
            "adapter": "rust",
            "adapter_version": "0.1.0",
            "seq": 0,
            "node": {
                "id": id,
                "kind": kind,
                "locator": format!("fixture:{kind}:{id}"),
                "display_name": id,
                "properties": {},
            },
        }),
    );
    resequence(events);
}

fn sort_edge_events(events: &mut [Value]) {
    let first = events
        .iter()
        .position(|event| event["event"] == "edge_upsert")
        .expect("edge events");
    let last = events
        .iter()
        .rposition(|event| event["event"] == "edge_upsert")
        .expect("edge events");
    events[first..=last].sort_by(|left, right| {
        left["edge"]["id"]
            .as_str()
            .cmp(&right["edge"]["id"].as_str())
    });
}

fn sort_site_events(events: &mut [Value]) {
    let first = events
        .iter()
        .position(|event| event["event"] == "dependency_site")
        .expect("dependency-site events");
    let last = events
        .iter()
        .rposition(|event| event["event"] == "dependency_site")
        .expect("dependency-site events");
    events[first..=last].sort_by(|left, right| {
        left["site"]["id"]
            .as_str()
            .cmp(&right["site"]["id"].as_str())
    });
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
    let events: Vec<Value> = match input.lines().map(serde_json::from_str).collect() {
        Ok(events) => events,
        Err(_) => return false,
    };
    let strict_dependency_site_ids: BTreeSet<_> = events
        .iter()
        .filter(|event| {
            event["event"] == "dependency_site"
                && matches!(
                    event["site"]["kind"].as_str(),
                    Some(
                        "type_use"
                            | "value_reference"
                            | "rust_use"
                            | "rust_reexport"
                            | "web_import"
                            | "web_reexport"
                            | "renders"
                            | "hydrates"
                            | "client_boundary"
                            | "server_boundary"
                            | "route_entry"
                            | "parent_route"
                            | "loads"
                            | "before_load"
                            | "navigates_to"
                            | "masks_to"
                            | "rpc_call"
                            | "client_stub_for"
                            | "handled_by"
                            | "uses_middleware"
                    )
                )
                && event["site"]["evidence"][0]["kind"] == "semantic"
        })
        .filter_map(|event| event["site"]["id"].as_str())
        .collect();

    events.iter().all(|event| match event["event"].as_str() {
        Some("node_upsert")
            if matches!(event["node"]["kind"].as_str(), Some("symbol" | "type"))
                || (matches!(
                    event["node"]["kind"].as_str(),
                    Some("component" | "route" | "server_function" | "middleware")
                ) && event["node"]["properties"]["canonical_identity"].is_object()) =>
        {
            semantic_definition_accepts(&schema, "semantic_node", &event["node"])
        }
        Some("edge_upsert")
            if matches!(
                event["edge"]["kind"].as_str(),
                Some(
                    "calls"
                        | "may_call"
                        | "references"
                        | "renders"
                        | "hydrates"
                        | "client_boundary"
                        | "server_boundary"
                        | "route_entry"
                        | "parent_route"
                        | "loads"
                        | "before_load"
                        | "navigates_to"
                        | "masks_to"
                        | "rpc_call"
                        | "client_stub_for"
                        | "handled_by"
                        | "uses_middleware"
                )
            ) || (matches!(
                event["edge"]["kind"].as_str(),
                Some("declares" | "extends" | "implements" | "instantiates")
            ) && (event["edge"]["phase"] == "semantic"
                || event["edge"]["evidence"][0]["kind"] == "semantic"))
                || event["edge"]["site_id"]
                    .as_str()
                    .is_some_and(|site_id| strict_dependency_site_ids.contains(site_id)) =>
        {
            semantic_definition_accepts(&schema, "semantic_edge", &event["edge"])
        }
        Some("dependency_site")
            if event["site"]["kind"] == "call"
                || event["site"]["id"]
                    .as_str()
                    .is_some_and(|site_id| strict_dependency_site_ids.contains(site_id)) =>
        {
            semantic_definition_accepts(&schema, "semantic_site", &event["site"])
        }
        _ => true,
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

fn rehash_definition_edge(edge: &mut Value) {
    let evidence = &edge["evidence"][0];
    edge["id"] = json!(stable_id_from_value(
        "edge",
        &json!({
            "condition": edge["condition"],
            "kind": edge["kind"],
            "path": evidence["path"],
            "profile_id": edge["profile_id"],
            "source": edge["source"],
            "span": {
                "end_column": evidence["end_column"],
                "end_line": evidence["end_line"],
                "start_column": evidence["start_column"],
                "start_line": evidence["start_line"],
            },
            "target": edge["target"],
        }),
    ));
}
