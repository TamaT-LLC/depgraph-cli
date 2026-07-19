use depgraph_protocol::{
    CompletenessLevel, EvidenceKind, Phase, Precision, ProtocolEvent, ResolutionStatus,
    stable_id_from_value, validate_ndjson, validate_safe_semantic_ndjson,
};
use depgraph_rust_worker::{
    ADAPTER_VERSION, RUST_ANALYZER_CRATE_VERSION, RUST_ANALYZER_REVISION,
    RUST_ANALYZER_SALSA_VERSION, build_events, scan,
};
use std::{
    collections::BTreeSet,
    fs,
    io::Cursor,
    path::{Path, PathBuf},
    process::Command,
};

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/workspace")
}

fn security_fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/security")
}

fn semantic_fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/semantic")
}

#[test]
fn typed_output_validates_and_contains_all_nine_events() {
    let result = scan(&fixture()).unwrap();
    let events = build_events("rust-fixture", &result).unwrap();
    let mut ndjson = Vec::new();
    for event in &events {
        serde_json::to_writer(&mut ndjson, event).unwrap();
        ndjson.push(b'\n');
    }
    let validated = validate_safe_semantic_ndjson(Cursor::new(&ndjson)).unwrap();
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
    assert!(
        validated
            .edges
            .values()
            .any(|edge| edge.phase == Phase::Source)
    );
    assert!(
        validated
            .edges
            .values()
            .any(|edge| edge.phase == Phase::Semantic)
    );
    assert!(validated.edges.values().all(|edge| match edge.phase {
        Phase::Source => edge.evidence.iter().all(|evidence| {
            evidence.kind == EvidenceKind::Source
                && evidence.extractor == "rust-static"
                && evidence.extractor_version == ADAPTER_VERSION
        }),
        Phase::Semantic => {
            edge.evidence.first().is_some_and(|evidence| {
                evidence.kind == EvidenceKind::Semantic
                    && evidence.extractor == "rust-analyzer-hir"
                    && evidence.extractor_version == RUST_ANALYZER_CRATE_VERSION
            }) && edge.evidence.iter().skip(1).all(|evidence| {
                (evidence.kind == EvidenceKind::Semantic
                    && evidence.extractor == "rust-analyzer-hir"
                    && evidence.extractor_version == RUST_ANALYZER_CRATE_VERSION)
                    || (evidence.kind == EvidenceKind::Source
                        && evidence.extractor == "rust-static"
                        && evidence.extractor_version == ADAPTER_VERSION)
            })
        }
        Phase::Build | Phase::Runtime => false,
    }));
    assert!(
        validated
            .diagnostics
            .keys()
            .all(|id| id.starts_with("diagnostic:sha256:"))
    );
    assert!(result.coverage.unsupported_syntax > 0);
    assert!(result.coverage.completeness.is_empty());
}

#[test]
fn hir_import_type_call_graph_emits_exact_nodes_sites_and_relations() {
    let result = scan(&semantic_fixture()).unwrap();
    let events = build_events("rust-semantic-fixture", &result).unwrap();
    let mut ndjson = Vec::new();
    for event in &events {
        serde_json::to_writer(&mut ndjson, event).unwrap();
        ndjson.push(b'\n');
    }
    validate_safe_semantic_ndjson(Cursor::new(ndjson)).unwrap();

    assert_eq!(
        result.profile.properties["analysis"],
        "syntax+hir-imports-types-calls"
    );
    assert_eq!(
        result.profile.properties["analysis_backend"],
        "static-syntax+rust-analyzer-hir"
    );
    assert_eq!(
        result.profile.properties["rust_hir_status"],
        "import-type-call-graph-emitted"
    );
    assert_eq!(
        result.profile.properties["rust_hir_semantic_issue_count"],
        0
    );
    assert!(
        !result
            .coverage
            .completeness
            .contains(&CompletenessLevel::SemanticComplete)
    );

    let semantic_nodes: Vec<_> = result
        .nodes
        .iter()
        .filter(|node| matches!(node.kind.as_str(), "symbol" | "type"))
        .collect();
    assert!(!semantic_nodes.is_empty());
    for node in &semantic_nodes {
        let identity = &node.properties["canonical_identity"];
        assert_eq!(node.id, stable_id_from_value(&node.kind, identity));
        assert_eq!(node.properties["language"], "rust");
        if let Some(path) = node
            .properties
            .get("source_path")
            .and_then(|path| path.as_str())
        {
            assert!(!Path::new(path).is_absolute());
        } else {
            assert!(matches!(
                node.properties
                    .get("symbol_kind")
                    .or_else(|| node.properties.get("type_kind"))
                    .and_then(serde_json::Value::as_str),
                Some("function_instance" | "generic_instance")
            ));
        }
        let serialized = serde_json::to_string(identity).unwrap();
        assert!(!serialized.contains(semantic_fixture().to_string_lossy().as_ref()));
        assert!(!serialized.contains("external:"));
    }

    let symbol_kinds: BTreeSet<_> = semantic_nodes
        .iter()
        .filter(|node| node.kind == "symbol")
        .filter_map(|node| node.properties["symbol_kind"].as_str())
        .collect();
    assert!(
        [
            "function",
            "method",
            "associated_function",
            "associated_constant",
            "field",
            "enum_variant",
            "impl",
            "parameter",
            "local_variable",
            "function_instance",
        ]
        .into_iter()
        .all(|kind| symbol_kinds.contains(kind))
    );
    let type_kinds: BTreeSet<_> = semantic_nodes
        .iter()
        .filter(|node| node.kind == "type")
        .filter_map(|node| node.properties["type_kind"].as_str())
        .collect();
    assert!(
        [
            "struct",
            "enum",
            "trait",
            "type_alias",
            "associated_type",
            "type_parameter",
            "generic_instance",
        ]
        .into_iter()
        .all(|kind| type_kinds.contains(kind))
    );
    assert!(!semantic_nodes.iter().any(|node| {
        node.kind == "symbol"
            && node.properties["symbol_kind"] == "function_instance"
            && node.properties["resolver_identity"]
                .as_str()
                .is_some_and(|resolver| resolver.contains("Envelope::value"))
    }));
    assert!(semantic_nodes.iter().any(|node| {
        node.kind == "type"
            && node.properties["type_kind"] == "generic_instance"
            && node.properties["type_arguments"]
                .as_array()
                .is_some_and(|arguments| {
                    arguments.iter().any(|argument| argument == "T=builtin:u32")
                })
    }));

    let semantic_edges: Vec<_> = result
        .edges
        .iter()
        .filter(|edge| edge.phase == Phase::Semantic)
        .collect();
    assert!(!semantic_edges.is_empty());
    let structural_edges: Vec<_> = semantic_edges
        .iter()
        .copied()
        .filter(|edge| edge.site_id.is_none())
        .collect();
    for edge in &structural_edges {
        assert!(matches!(
            edge.kind.as_str(),
            "declares" | "extends" | "implements" | "instantiates"
        ));
        assert_eq!(edge.site_id, None);
        assert_eq!(edge.resolution_status, ResolutionStatus::Resolved);
        assert_eq!(edge.precision, Precision::Exact);
        assert!(edge.condition.render().contains("rust.crate_instance"));
        let primary = edge.evidence.first().expect("semantic evidence");
        assert_eq!(primary.kind, EvidenceKind::Semantic);
        assert_eq!(primary.extractor, "rust-analyzer-hir");
        assert_eq!(primary.extractor_version, RUST_ANALYZER_CRATE_VERSION);
        assert!(
            primary
                .path
                .as_deref()
                .is_some_and(|path| !Path::new(path).is_absolute())
        );
        assert!(primary.start_line.is_some_and(|line| line > 0));
        assert!(primary.start_column.is_some_and(|column| column > 0));
        assert!(primary.end_line.is_some_and(|line| line > 0));
        assert!(primary.end_column.is_some_and(|column| column > 0));
        assert_eq!(
            primary.properties["rust_analyzer_revision"],
            RUST_ANALYZER_REVISION
        );
        let span = serde_json::json!({
            "start_line": primary.start_line.unwrap(),
            "start_column": primary.start_column.unwrap(),
            "end_line": primary.end_line.unwrap(),
            "end_column": primary.end_column.unwrap(),
        });
        assert_eq!(
            edge.id,
            stable_id_from_value(
                "edge",
                &serde_json::json!({
                    "condition": edge.condition,
                    "kind": edge.kind,
                    "profile_id": edge.profile_id,
                    "source": edge.source,
                    "target": edge.target,
                    "path": primary.path.as_deref().unwrap(),
                    "span": span,
                }),
            )
        );
    }

    let node_id = |resolver: &str| {
        semantic_nodes
            .iter()
            .find(|node| {
                node.properties
                    .get("resolver_identity")
                    .and_then(serde_json::Value::as_str)
                    == Some(resolver)
            })
            .map(|node| node.id.as_str())
            .unwrap_or_else(|| panic!("missing semantic node {resolver}"))
    };
    let crate_key = "Cargo.toml#lib:rust_semantic_fixture:src/lib.rs";
    let identified = node_id(&format!("{crate_key}::crate::domain::Identified"));
    let named = node_id(&format!("{crate_key}::crate::domain::Named"));
    let record = node_id(&format!("{crate_key}::crate::domain::Record"));
    assert!(semantic_edges.iter().any(|edge| {
        edge.kind == "extends" && edge.source == named && edge.target == identified
    }));
    assert!(semantic_edges.iter().any(|edge| {
        edge.kind == "implements" && edge.source == record && edge.target == identified
    }));
    assert!(semantic_edges.iter().any(|edge| {
        edge.kind == "implements" && edge.source == record && edge.target == named
    }));
    assert!(
        semantic_edges
            .iter()
            .any(|edge| edge.kind == "instantiates")
    );
    let dependency_sites: Vec<_> = result
        .sites
        .iter()
        .filter(|site| {
            matches!(
                site.kind.as_str(),
                "rust_use" | "rust_reexport" | "type_use" | "call"
            ) && site
                .evidence
                .first()
                .is_some_and(|evidence| evidence.kind == EvidenceKind::Semantic)
        })
        .collect();
    assert!(!dependency_sites.is_empty());
    assert_eq!(
        result.profile.properties["rust_hir_semantic_site_count"],
        dependency_sites.len() as u64
    );
    for site in &dependency_sites {
        let primary = site.evidence.first().expect("semantic site evidence");
        assert_eq!(primary.kind, EvidenceKind::Semantic);
        assert_eq!(primary.extractor, "rust-analyzer-hir");
        assert_eq!(primary.extractor_version, RUST_ANALYZER_CRATE_VERSION);
        assert!(
            primary
                .path
                .as_deref()
                .is_some_and(|path| !Path::new(path).is_absolute())
        );
        assert!(primary.start_line.is_some_and(|line| line > 0));
        assert!(primary.start_column.is_some_and(|column| column > 0));
        assert!(primary.end_line.is_some_and(|line| line > 0));
        assert!(primary.end_column.is_some_and(|column| column > 0));
        if site.kind == "call" && primary.properties["call_syntax"] == "macro_boundary" {
            assert_eq!(
                primary.properties["macro_provenance"],
                "declarative-expansion-boundary"
            );
        } else {
            assert_eq!(primary.properties["macro_provenance"], "direct-source");
        }
        assert!(site.target_ids.windows(2).all(|pair| pair[0] < pair[1]));
        assert_eq!(
            site.id,
            stable_id_from_value(
                "site",
                &serde_json::json!({
                    "condition": site.condition,
                    "kind": site.kind,
                    "path": primary.path.as_deref().unwrap(),
                    "profile_id": site.profile_id,
                    "source": site.source,
                    "span": {
                        "start_line": primary.start_line.unwrap(),
                        "start_column": primary.start_column.unwrap(),
                        "end_line": primary.end_line.unwrap(),
                        "end_column": primary.end_column.unwrap(),
                    }
                }),
            )
        );
        let linked_edges: Vec<_> = semantic_edges
            .iter()
            .copied()
            .filter(|edge| edge.site_id.as_deref() == Some(site.id.as_str()))
            .collect();
        assert_eq!(linked_edges.len(), site.target_ids.len());
        for edge in linked_edges {
            assert_eq!(edge.source, site.source);
            assert_eq!(edge.resolution_status, site.resolution_status);
            assert_eq!(edge.precision, site.precision);
            assert_eq!(edge.condition, site.condition);
            assert_eq!(edge.evidence[0], site.evidence[0]);
            assert_eq!(
                edge.id,
                stable_id_from_value(
                    "edge",
                    &serde_json::json!({
                        "kind": edge.kind,
                        "site_id": site.id,
                        "target": edge.target,
                    }),
                )
            );
        }
    }

    let import = dependency_sites
        .iter()
        .find(|site| site.kind == "rust_use" && site.specifier == "domain::Named as NameContract")
        .expect("resolved alias import");
    assert_eq!(import.resolution_status, ResolutionStatus::Resolved);
    assert_eq!(import.precision, Precision::Exact);
    assert_eq!(import.target_ids, [named]);
    assert!(import.evidence.iter().skip(1).any(|evidence| {
        evidence.kind == EvidenceKind::Source && evidence.extractor == "rust-static"
    }));

    let reexport = dependency_sites
        .iter()
        .find(|site| {
            site.kind == "rust_reexport" && site.specifier == "domain::Envelope as PublicEnvelope"
        })
        .expect("resolved alias re-export");
    assert_eq!(reexport.resolution_status, ResolutionStatus::Resolved);
    assert!(dependency_sites.iter().any(|site| {
        site.kind == "rust_reexport"
            && site.specifier == "domain::*"
            && site.resolution_status == ResolutionStatus::Resolved
    }));
    assert!(dependency_sites.iter().any(|site| {
        site.kind == "rust_use"
            && site.specifier == "std::path::PathBuf"
            && site.resolution_status == ResolutionStatus::External
            && site.precision == Precision::Heuristic
    }));
    assert!(dependency_sites.iter().any(|site| {
        site.kind == "rust_use"
            && site.specifier == "missing::BrokenImport as MissingImport"
            && site.resolution_status == ResolutionStatus::Unresolved
            && site.reason.is_some()
    }));

    let record_type_use = dependency_sites
        .iter()
        .find(|site| site.kind == "type_use" && site.specifier == "domain::Record")
        .expect("resolved signature type use");
    assert_eq!(
        record_type_use.resolution_status,
        ResolutionStatus::Resolved
    );
    assert_eq!(record_type_use.target_ids, [record]);
    assert!(dependency_sites.iter().any(|site| {
        site.kind == "type_use"
            && site.specifier == "std::path::PathBuf"
            && site.resolution_status == ResolutionStatus::External
    }));
    assert!(dependency_sites.iter().any(|site| {
        site.kind == "type_use"
            && site.specifier == "PathBuf"
            && site.resolution_status == ResolutionStatus::External
            && site.precision == Precision::Heuristic
            && site.evidence[0].properties["heuristic_basis"]
                .as_str()
                .is_some_and(|reason| reason.contains("std::path::PathBuf"))
    }));
    assert!(dependency_sites.iter().any(|site| {
        site.kind == "type_use"
            && site.specifier == "MissingImport"
            && site.resolution_status == ResolutionStatus::Unresolved
            && site.evidence[0].properties["type_use_context"] == "body"
    }));
    assert!(dependency_sites.iter().any(|site| {
        site.kind == "type_use"
            && site.specifier == "Sized"
            && site.resolution_status == ResolutionStatus::Unresolved
    }));
    assert!(dependency_sites.iter().any(|site| {
        site.kind == "type_use"
            && site.specifier == "missing::Thing"
            && site.resolution_status == ResolutionStatus::Unresolved
            && site.reason.is_some()
    }));
    assert!(dependency_sites.iter().any(|site| {
        site.kind == "type_use"
            && site.specifier == "PublicEnvelope"
            && site.condition.render().contains("rust.cfg")
    }));
}

#[test]
fn hir_call_graph_classifies_exact_candidate_external_and_unresolved_dispatch() {
    let result = scan(&semantic_fixture()).unwrap();
    let call_sites: Vec<_> = result
        .sites
        .iter()
        .filter(|site| {
            site.kind == "call"
                && site
                    .evidence
                    .first()
                    .is_some_and(|evidence| evidence.path.as_deref() == Some("src/calls.rs"))
        })
        .collect();
    assert_eq!(
        result.profile.properties["rust_hir_semantic_call_site_count"],
        result
            .sites
            .iter()
            .filter(|site| site.kind == "call")
            .count() as u64
    );

    let site_at = |line: u32, specifier: &str| {
        call_sites
            .iter()
            .copied()
            .find(|site| site.specifier == specifier && site.evidence[0].start_line == Some(line))
            .unwrap_or_else(|| panic!("missing call site {specifier:?} at src/calls.rs:{line}"))
    };
    let node = |id: &str| {
        result
            .nodes
            .iter()
            .find(|node| node.id == id)
            .unwrap_or_else(|| panic!("missing call target node {id}"))
    };
    let target = |line: u32, specifier: &str| {
        let site = site_at(line, specifier);
        assert_eq!(site.target_ids.len(), 1, "{specifier} at line {line}");
        node(&site.target_ids[0])
    };

    let direct = site_at(91, "direct_target");
    assert_eq!(direct.resolution_status, ResolutionStatus::Resolved);
    assert_eq!(direct.precision, Precision::Exact);
    assert_eq!(direct.evidence[0].properties["dispatch"], "static");
    assert_eq!(
        target(91, "direct_target").display_name.as_deref(),
        Some("direct_target")
    );

    let generic = target(92, "generic_target");
    assert_eq!(generic.properties["symbol_kind"], "function_instance");
    assert!(
        generic.properties["resolver_identity"]
            .as_str()
            .is_some_and(|identity| identity.ends_with("generic_target::<T=builtin:u32>"))
    );
    for (line, specifier) in [(102, "GenericWorker::create"), (103, "copied")] {
        let generic_impl = target(line, specifier);
        assert_eq!(generic_impl.properties["symbol_kind"], "function_instance");
        assert_eq!(
            generic_impl.properties["type_arguments"],
            serde_json::json!(["T=builtin:u32"])
        );
    }

    assert_eq!(
        target(90, "Worker::new").properties["symbol_kind"],
        "associated_function"
    );
    assert_eq!(target(94, "inherent").properties["symbol_kind"], "method");
    assert_eq!(
        site_at(94, "inherent").evidence[0].properties["dispatch"],
        "method_static"
    );
    let concrete_trait = target(95, "dispatch");
    assert!(
        concrete_trait.properties["resolver_identity"]
            .as_str()
            .is_some_and(
                |identity| identity.contains("Worker as") && identity.ends_with("::dispatch")
            )
    );
    assert_eq!(
        site_at(95, "dispatch").evidence[0].properties["dispatch"],
        "method_static"
    );
    let default_method = target(96, "defaulted");
    assert_eq!(
        default_method.properties["symbol_kind"],
        "function_instance"
    );
    assert_eq!(
        site_at(96, "defaulted").evidence[0].properties["dispatch"],
        "trait_default_static"
    );
    let associated = target(97, "ClosedDispatch::associated");
    assert_eq!(associated.properties["symbol_kind"], "associated_function");
    assert!(
        associated.properties["resolver_identity"]
            .as_str()
            .is_some_and(
                |identity| identity.contains("Worker as") && identity.ends_with("::associated")
            )
    );
    let associated_default = target(98, "ClosedDispatch::associated_default");
    assert_eq!(
        associated_default.properties["symbol_kind"],
        "function_instance"
    );
    assert_eq!(
        site_at(98, "ClosedDispatch::associated_default").evidence[0].properties["dispatch"],
        "trait_associated_default_static"
    );

    let dynamic = site_at(107, "dispatch");
    let generic_dispatch = site_at(111, "dispatch");
    for candidate_site in [dynamic, generic_dispatch] {
        assert_eq!(
            candidate_site.resolution_status,
            ResolutionStatus::Candidates
        );
        assert_eq!(candidate_site.precision, Precision::Overapprox);
        assert_eq!(candidate_site.target_ids.len(), 2);
        assert_eq!(
            candidate_site.evidence[0].properties["algorithm"],
            "rust-analyzer-local-trait-impls-v1"
        );
        assert!(
            candidate_site
                .target_ids
                .windows(2)
                .all(|pair| pair[0] < pair[1])
        );
        let identities: Vec<_> = candidate_site
            .target_ids
            .iter()
            .map(|id| node(id).properties["resolver_identity"].as_str().unwrap())
            .collect();
        assert!(
            identities
                .iter()
                .any(|identity| identity.contains("Worker as"))
        );
        assert!(
            identities
                .iter()
                .any(|identity| identity.contains("Backup as"))
        );
    }
    assert_eq!(dynamic.target_ids, generic_dispatch.target_ids);
    let dynamic_default = site_at(107, "defaulted");
    assert_eq!(
        dynamic_default.resolution_status,
        ResolutionStatus::Candidates
    );
    assert_eq!(dynamic_default.precision, Precision::Overapprox);
    assert_eq!(dynamic_default.target_ids.len(), 1);
    assert_eq!(
        dynamic_default.evidence[0].properties["algorithm"],
        "rust-analyzer-local-trait-impls-v1"
    );

    let single_pointer = site_at(136, "single");
    let multiple_pointers = site_at(136, "alias");
    for candidate_site in [single_pointer, multiple_pointers] {
        assert_eq!(
            candidate_site.resolution_status,
            ResolutionStatus::Candidates
        );
        assert_eq!(candidate_site.precision, Precision::Overapprox);
        assert_eq!(
            candidate_site.evidence[0].properties["algorithm"],
            "rust-immutable-fn-pointer-flow-v1"
        );
        assert!(
            candidate_site
                .target_ids
                .windows(2)
                .all(|pair| pair[0] < pair[1])
        );
    }
    assert_eq!(single_pointer.target_ids.len(), 1);
    assert_eq!(multiple_pointers.target_ids.len(), 2);
    assert!(
        multiple_pointers
            .target_ids
            .contains(&single_pointer.target_ids[0])
    );

    let closure_call = site_at(125, "closure");
    assert_eq!(
        node(&closure_call.source).display_name.as_deref(),
        Some("closure_calls")
    );
    assert_eq!(
        node(&closure_call.target_ids[0]).properties["symbol_kind"],
        "closure"
    );
    assert_eq!(closure_call.evidence[0].properties["dispatch"], "closure");
    let closure_body_call = site_at(124, "direct_target");
    assert_eq!(
        node(&closure_body_call.source).properties["symbol_kind"],
        "closure"
    );
    let inline_closure_call = site_at(125, "<closure>");
    assert_eq!(
        node(&inline_closure_call.target_ids[0]).properties["symbol_kind"],
        "closure"
    );
    let inline_closure_body = site_at(125, "alternate_target");
    assert_eq!(
        inline_closure_body.source,
        inline_closure_call.target_ids[0]
    );

    let external = site_at(144, "std::mem::size_of");
    assert_eq!(external.resolution_status, ResolutionStatus::External);
    assert_eq!(external.precision, Precision::Heuristic);
    assert_eq!(node(&external.target_ids[0]).kind, "external_system");
    let external_alias = site_at(148, "external_size");
    assert_eq!(external_alias.resolution_status, ResolutionStatus::External);
    assert_eq!(external_alias.precision, Precision::Heuristic);
    assert_eq!(
        external_alias.evidence[0].properties["dispatch"],
        "external"
    );
    let unresolved = site_at(152, "missing_call");
    assert_eq!(unresolved.resolution_status, ResolutionStatus::Unresolved);
    assert_eq!(unresolved.precision, Precision::Heuristic);
    assert_eq!(node(&unresolved.target_ids[0]).kind, "unknown_target");
    assert!(
        unresolved
            .reason
            .as_deref()
            .is_some_and(|reason| !reason.is_empty())
    );
    let unknown_pointer = site_at(140, "callback");
    assert_eq!(
        unknown_pointer.resolution_status,
        ResolutionStatus::Unresolved
    );
    assert_eq!(
        unknown_pointer.evidence[0].properties["dispatch"],
        "function_pointer"
    );
    let open_trait = site_at(120, "open_dispatch");
    assert_eq!(open_trait.resolution_status, ResolutionStatus::Unresolved);
    assert!(
        open_trait
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("public trait"))
    );

    let macro_boundary = site_at(156, "generated_call!");
    assert_eq!(
        macro_boundary.resolution_status,
        ResolutionStatus::Unresolved
    );
    assert_eq!(
        macro_boundary.evidence[0].properties["dispatch"],
        "macro_boundary"
    );
    assert_eq!(
        macro_boundary.evidence[0].properties["macro_provenance"],
        "declarative-expansion-boundary"
    );
    assert_eq!(
        macro_boundary.evidence[0].properties["generated_call_count"],
        1
    );
    let macro_edges: Vec<_> = result
        .edges
        .iter()
        .filter(|edge| edge.site_id.as_deref() == Some(macro_boundary.id.as_str()))
        .collect();
    assert_eq!(macro_edges.len(), 1);
    assert!(macro_edges[0].generated);

    let conditioned = site_at(161, "direct_target");
    let rendered_condition = conditioned.condition.render();
    assert!(rendered_condition.contains("rust.cfg.unix"));
    assert!(rendered_condition.contains("rust.cfg.windows"));
    let match_arm_conditioned = site_at(174, "direct_target");
    assert!(
        match_arm_conditioned
            .condition
            .render()
            .contains("rust.cfg.unix")
    );
    assert!(!call_sites.iter().any(|site| {
        site.specifier == "TupleConstructor" || site.evidence[0].start_line == Some(167)
    }));

    for site in call_sites {
        assert!(site.target_ids.windows(2).all(|pair| pair[0] < pair[1]));
        let linked_edges: Vec<_> = result
            .edges
            .iter()
            .filter(|edge| edge.site_id.as_deref() == Some(site.id.as_str()))
            .collect();
        assert_eq!(linked_edges.len(), site.target_ids.len());
        let expected_kind = if site.resolution_status == ResolutionStatus::Candidates {
            "may_call"
        } else {
            "calls"
        };
        assert!(linked_edges.iter().all(|edge| edge.kind == expected_kind));
    }
}

#[test]
fn external_aliases_follow_lexical_module_paths_and_narrower_cfg() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("external-alias-scope");
    write_minimal_crate(
        &root,
        "external-alias-scope",
        r#"#[cfg(any(unix, windows))]
use std::path::PathBuf;

#[cfg(any(unix, windows))]
mod nested {
    use std::path::PathBuf as LocalBuf;

    #[cfg(target_pointer_width = "64")]
    pub fn accepts(_: super::PathBuf, _: self::LocalBuf) {}
}
"#,
    );

    let result = scan(&root).unwrap();
    for specifier in ["super::PathBuf", "self::LocalBuf"] {
        let site = result
            .sites
            .iter()
            .find(|site| site.kind == "type_use" && site.specifier == specifier)
            .unwrap_or_else(|| panic!("missing type-use site {specifier}"));
        assert_eq!(site.resolution_status, ResolutionStatus::External);
        assert_eq!(site.precision, Precision::Heuristic);
        assert_eq!(site.evidence[0].kind, EvidenceKind::Semantic);
        assert!(site.condition.render().contains("rust.cfg"));
        assert!(
            site.evidence[0].properties["heuristic_basis"]
                .as_str()
                .is_some_and(|reason| reason.contains("std::path::PathBuf"))
        );
    }
}

#[test]
fn external_aliases_follow_cross_file_crate_and_super_paths() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("external-alias-cross-file");
    write_minimal_crate(
        &root,
        "external-alias-cross-file",
        "use std::path::PathBuf;\npub mod child;\n",
    );
    fs::write(
        root.join("src/child.rs"),
        "pub fn accepts(_: crate::PathBuf, _: super::PathBuf) {}\n",
    )
    .unwrap();

    let result = scan(&root).unwrap();
    for specifier in ["crate::PathBuf", "super::PathBuf"] {
        let site = result
            .sites
            .iter()
            .find(|site| site.kind == "type_use" && site.specifier == specifier)
            .unwrap_or_else(|| panic!("missing type-use site {specifier}"));
        assert_eq!(site.resolution_status, ResolutionStatus::External);
        assert_eq!(site.precision, Precision::Heuristic);
        assert_eq!(site.evidence[0].kind, EvidenceKind::Semantic);
        assert!(
            site.evidence[0].properties["heuristic_basis"]
                .as_str()
                .is_some_and(|reason| reason.contains("std::path::PathBuf"))
        );
    }
}

#[test]
fn extern_crate_alias_resolves_external_type_use() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("extern-crate-alias");
    write_minimal_crate(
        &root,
        "extern-crate-alias",
        "extern crate std as sys;\npub fn accepts(_: sys::path::PathBuf) {}\n",
    );

    let result = scan(&root).unwrap();
    assert!(result.sites.iter().any(|site| {
        site.kind == "extern_crate"
            && site.specifier == "std as sys"
            && site.resolution_status == ResolutionStatus::External
    }));
    let type_use = result
        .sites
        .iter()
        .find(|site| site.kind == "type_use" && site.specifier == "sys::path::PathBuf")
        .expect("extern crate alias type use");
    assert_eq!(type_use.resolution_status, ResolutionStatus::External);
    assert_eq!(type_use.precision, Precision::Heuristic);
    assert_eq!(type_use.evidence[0].kind, EvidenceKind::Semantic);
    assert!(
        type_use.evidence[0].properties["heuristic_basis"]
            .as_str()
            .is_some_and(|reason| reason.contains("std"))
    );
}

#[test]
fn hir_import_type_graph_is_repeatable_and_checkout_independent() {
    let first_temp = tempfile::tempdir().unwrap();
    let second_temp = tempfile::tempdir().unwrap();
    let first_root = first_temp.path().join("one");
    let second_root = second_temp.path().join("two");
    copy_tree(&semantic_fixture(), &first_root);
    copy_tree(&semantic_fixture(), &second_root);

    let first = scan(&first_root).unwrap();
    let repeated = scan(&first_root).unwrap();
    let second = scan(&second_root).unwrap();
    let semantic_nodes = |result: &depgraph_rust_worker::ScanResult| {
        result
            .nodes
            .iter()
            .filter(|node| matches!(node.kind.as_str(), "symbol" | "type"))
            .cloned()
            .collect::<Vec<_>>()
    };
    let semantic_edges = |result: &depgraph_rust_worker::ScanResult| {
        result
            .edges
            .iter()
            .filter(|edge| edge.phase == Phase::Semantic)
            .cloned()
            .collect::<Vec<_>>()
    };
    let semantic_sites = |result: &depgraph_rust_worker::ScanResult| {
        result
            .sites
            .iter()
            .filter(|site| {
                site.evidence
                    .first()
                    .is_some_and(|evidence| evidence.kind == EvidenceKind::Semantic)
            })
            .cloned()
            .collect::<Vec<_>>()
    };
    assert_eq!(semantic_nodes(&first), semantic_nodes(&repeated));
    assert_eq!(semantic_edges(&first), semantic_edges(&repeated));
    assert_eq!(semantic_sites(&first), semantic_sites(&repeated));
    assert_eq!(first.profile, repeated.profile);
    assert_eq!(first.nodes, repeated.nodes);
    assert_eq!(first.edges, repeated.edges);
    assert_eq!(first.sites, repeated.sites);
    assert_eq!(first.diagnostics, repeated.diagnostics);
    assert_eq!(first.coverage, repeated.coverage);
    assert_eq!(first.files, repeated.files);
    assert_eq!(semantic_nodes(&first), semantic_nodes(&second));
    assert_eq!(semantic_edges(&first), semantic_edges(&second));
    assert_eq!(semantic_sites(&first), semantic_sites(&second));
    assert_eq!(first.profile, second.profile);
    assert_eq!(first.nodes, second.nodes);
    assert_eq!(first.edges, second.edges);
    assert_eq!(first.sites, second.sites);
    assert_eq!(first.diagnostics, second.diagnostics);
    assert_eq!(first.coverage, second.coverage);
    assert_eq!(first.files, second.files);

    let deterministic_events = |result: &depgraph_rust_worker::ScanResult| {
        build_events("deterministic-rust-scan", result)
            .unwrap()
            .into_iter()
            .skip(1)
            .map(|event| serde_json::to_value(event).unwrap())
            .collect::<Vec<_>>()
    };
    assert_eq!(
        deterministic_events(&first),
        deterministic_events(&repeated)
    );
    assert_eq!(deterministic_events(&first), deterministic_events(&second));
}

#[test]
fn ambiguous_shared_module_use_remains_one_candidate_site() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("candidate-use");
    write_minimal_crate(
        &root,
        "candidate-use",
        r#"#[path = "shared.rs"]
pub mod left;
#[path = "shared.rs"]
pub mod right;
"#,
    );
    fs::write(
        root.join("src/shared.rs"),
        "pub mod child { pub struct Item; }\nuse self::child::Item;\n",
    )
    .unwrap();

    let result = scan(&root).unwrap();
    let sites: Vec<_> = result
        .sites
        .iter()
        .filter(|site| site.kind == "rust_use" && site.specifier == "self::child::Item")
        .collect();
    assert_eq!(sites.len(), 1);
    let site = sites[0];
    assert_eq!(site.resolution_status, ResolutionStatus::Candidates);
    assert_eq!(site.precision, Precision::Overapprox);
    assert_eq!(site.target_ids.len(), 2);
    assert!(site.target_ids.windows(2).all(|pair| pair[0] < pair[1]));
    let linked: Vec<_> = result
        .edges
        .iter()
        .filter(|edge| edge.site_id.as_deref() == Some(site.id.as_str()))
        .collect();
    assert_eq!(linked.len(), 2);
    assert!(linked.iter().all(|edge| {
        edge.phase == Phase::Source
            && edge.resolution_status == ResolutionStatus::Candidates
            && edge.precision == Precision::Overapprox
    }));
    assert_eq!(result.coverage.candidates, 1);
}

#[test]
fn hir_use_with_distinct_namespace_targets_is_semantic_candidates() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("namespace-candidates");
    write_minimal_crate(
        &root,
        "namespace-candidates",
        r#"pub mod defs {
    pub mod dual {}
    pub fn dual() {}
}
use defs::dual;
"#,
    );

    let result = scan(&root).unwrap();
    let sites: Vec<_> = result
        .sites
        .iter()
        .filter(|site| site.kind == "rust_use" && site.specifier == "defs::dual")
        .collect();
    assert_eq!(sites.len(), 1);
    let site = sites[0];
    assert_eq!(site.resolution_status, ResolutionStatus::Candidates);
    assert_eq!(site.precision, Precision::Overapprox);
    assert_eq!(site.target_ids.len(), 2);
    assert_eq!(site.evidence[0].kind, EvidenceKind::Semantic);
    let linked: Vec<_> = result
        .edges
        .iter()
        .filter(|edge| edge.site_id.as_deref() == Some(site.id.as_str()))
        .collect();
    assert_eq!(linked.len(), 2);
    assert!(linked.iter().all(|edge| {
        edge.phase == Phase::Semantic
            && edge.kind == "imports"
            && edge.resolution_status == ResolutionStatus::Candidates
            && edge.precision == Precision::Overapprox
    }));
}

#[test]
fn ambiguous_type_use_is_preserved_once_as_source_fallback() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("ambiguous-type-fallback");
    write_minimal_crate(
        &root,
        "ambiguous-type-fallback",
        r#"#[path = "shared.rs"]
pub mod left;
#[path = "shared.rs"]
pub mod right;
"#,
    );
    fs::write(
        root.join("src/shared.rs"),
        "pub struct Local;\npub fn accepts(_: Local, _: std::path::PathBuf) {}\n",
    )
    .unwrap();

    let result = scan(&root).unwrap();
    let sites: Vec<_> = result
        .sites
        .iter()
        .filter(|site| site.kind == "type_use" && site.specifier == "Local")
        .collect();
    assert_eq!(sites.len(), 1);
    let site = sites[0];
    assert_eq!(site.resolution_status, ResolutionStatus::Unresolved);
    assert_eq!(site.precision, Precision::Heuristic);
    assert_eq!(site.evidence[0].kind, EvidenceKind::Source);
    assert_eq!(
        site.evidence[0].properties["semantic_refinement"],
        "unavailable"
    );
    assert_eq!(site.target_ids.len(), 1);
    assert!(
        result
            .nodes
            .iter()
            .any(|node| { node.id == site.target_ids[0] && node.kind == "unknown_target" })
    );
    let linked: Vec<_> = result
        .edges
        .iter()
        .filter(|edge| edge.site_id.as_deref() == Some(site.id.as_str()))
        .collect();
    assert_eq!(linked.len(), 1);
    assert_eq!(linked[0].phase, Phase::Source);
    assert_eq!(linked[0].kind, "type_uses");
    let external = result
        .sites
        .iter()
        .find(|site| site.kind == "type_use" && site.specifier == "std::path::PathBuf")
        .expect("source fallback external type use");
    assert_eq!(external.resolution_status, ResolutionStatus::External);
    assert_eq!(external.precision, Precision::Heuristic);
    assert_eq!(external.evidence[0].kind, EvidenceKind::Source);
    assert!(result.files.iter().any(|file| {
        file.path == "src/shared.rs" && file.discovered_sites == file.emitted_sites
    }));
}

#[test]
fn test_mode_skips_ambiguous_source_bound_locals_and_instances() {
    let output = Command::new(env!("CARGO_BIN_EXE_depgraph-rust-worker"))
        .arg("--root")
        .arg(semantic_fixture())
        .arg("--scan-id")
        .arg("semantic-test-mode")
        .env("DEPGRAPH_PROFILE_CONFIG", r#"{"rust_mode":"test"}"#)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "test-mode worker failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let validated = validate_safe_semantic_ndjson(Cursor::new(output.stdout)).unwrap();
    let profile = validated.profiles.values().next().unwrap();
    assert_eq!(
        profile.properties["rust_hir_status"],
        "import-type-call-graph-partial"
    );
    assert_eq!(profile.properties["rust_hir_semantic_issue_count"], 3);
    assert_eq!(
        validated
            .diagnostics
            .values()
            .filter(|diagnostic| diagnostic.code == "RUST_HIR_SOURCE_CONTEXT_AMBIGUOUS")
            .count(),
        3
    );
    assert!(
        validated
            .nodes
            .values()
            .any(|node| { node.kind == "symbol" && node.properties["symbol_kind"] == "function" })
    );
    assert!(!validated.nodes.values().any(|node| {
        node.kind == "symbol"
            && matches!(
                node.properties["symbol_kind"].as_str(),
                Some("parameter" | "local_variable" | "function_instance")
            )
    }));
    assert!(
        !validated.nodes.values().any(|node| {
            node.kind == "type" && node.properties["type_kind"] == "generic_instance"
        })
    );
}

#[test]
fn invalid_source_discards_the_hir_delta_and_preserves_syntax_output() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("broken");
    copy_tree(&semantic_fixture(), &root);
    fs::write(
        root.join("src/lib.rs"),
        "pub mod domain;\npub fn broken( {\n",
    )
    .unwrap();

    let result = scan(&root).unwrap();
    assert!(
        result
            .nodes
            .iter()
            .all(|node| !matches!(node.kind.as_str(), "symbol" | "type"))
    );
    assert!(result.edges.iter().all(|edge| edge.phase == Phase::Source));
    assert_eq!(
        result.profile.properties["analysis_backend"],
        "static-syntax"
    );
    assert_eq!(
        result.profile.properties["rust_hir_project_model"],
        "unavailable"
    );
    assert!(
        result
            .diagnostics
            .iter()
            .any(|diagnostic| { diagnostic.code == "RUST_HIR_CRATE_GRAPH_UNAVAILABLE" })
    );
    assert!(result.nodes.iter().any(|node| node.kind == "module"));
}

#[test]
fn external_and_unresolved_types_do_not_become_fake_exact_semantic_nodes() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("unresolved");
    fs::create_dir_all(root.join("src")).unwrap();
    fs::write(
        root.join("Cargo.toml"),
        "[package]\nname='unresolved-types'\nversion='0.1.0'\nedition='2024'\n",
    )
    .unwrap();
    fs::write(
        root.join("Cargo.lock"),
        "version = 4\n\n[[package]]\nname = \"unresolved-types\"\nversion = \"0.1.0\"\n",
    )
    .unwrap();
    fs::write(
        root.join("src/lib.rs"),
        r#"pub struct Local;
pub trait LocalTrait {}
pub fn accepts(_: std::path::PathBuf, _: missing::Thing) {}
impl missing::Trait for Local {}
impl LocalTrait for std::path::PathBuf {}
"#,
    )
    .unwrap();

    let result = scan(&root).unwrap();
    assert!(result.nodes.iter().any(|node| {
        node.kind == "type"
            && node.properties["resolver_identity"]
                .as_str()
                .is_some_and(|resolver| resolver.ends_with("::Local"))
    }));
    assert!(result.nodes.iter().any(|node| {
        node.kind == "symbol"
            && node
                .properties
                .get("resolver_identity")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|resolver| resolver.ends_with("::accepts"))
    }));
    assert!(!result.nodes.iter().any(|node| {
        matches!(node.kind.as_str(), "symbol" | "type")
            && node
                .properties
                .get("resolver_identity")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|identity| {
                    identity.contains("PathBuf") || identity.contains("missing::Thing")
                })
    }));
    assert!(
        result
            .diagnostics
            .iter()
            .any(|diagnostic| { diagnostic.code == "RUST_HIR_IMPL_TRAIT_TARGET_UNAVAILABLE" })
    );
    assert!(
        result
            .diagnostics
            .iter()
            .any(|diagnostic| { diagnostic.code == "RUST_HIR_IMPL_SELF_TYPE_UNREPRESENTABLE" })
    );
    assert_eq!(
        result.profile.properties["rust_hir_status"],
        "import-type-call-graph-partial"
    );
}

#[test]
fn generated_derive_definitions_are_not_promoted_to_ordinary_exact_nodes() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("derive");
    write_minimal_crate(
        &root,
        "derive-fixture",
        r#"#[derive(Clone)]
pub struct Derived { pub value: u32 }
macro_rules! generated_impl {
    () => { impl Derived { pub fn generated(&self) {} } };
}
generated_impl!();
"#,
    );

    let result = scan(&root).unwrap();
    assert!(result.nodes.iter().any(|node| {
        node.kind == "type"
            && node.properties["resolver_identity"]
                .as_str()
                .is_some_and(|resolver| resolver.ends_with("::Derived"))
    }));
    assert!(
        !result
            .nodes
            .iter()
            .any(|node| { node.kind == "symbol" && node.properties["symbol_kind"] == "impl" })
    );
    assert!(result.diagnostics.iter().any(|diagnostic| {
        diagnostic.code == "RUST_HIR_GENERATED_IMPL_SKIPPED"
            || diagnostic.code == "RUST_HIR_GENERATED_DEFINITION_SKIPPED"
    }));
}

#[test]
fn const_generic_instances_are_skipped_instead_of_collapsing_exact_ids() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("const-generics");
    write_minimal_crate(
        &root,
        "const-generic-fixture",
        r#"pub struct Inner<T, const N: usize> { pub value: T }
pub struct Outer<T> { pub value: T }
pub fn first(value: u8) -> Outer<Inner<u8, 1>> {
    Outer::<Inner<u8, 1>> { value: Inner::<u8, 1> { value } }
}
pub fn second(value: u8) -> Outer<Inner<u8, 2>> {
    Outer::<Inner<u8, 2>> { value: Inner::<u8, 2> { value } }
}
"#,
    );

    let result = scan(&root).unwrap();
    assert!(
        !result.nodes.iter().any(|node| {
            node.kind == "type" && node.properties["type_kind"] == "generic_instance"
        })
    );
    assert!(
        result
            .diagnostics
            .iter()
            .any(|diagnostic| { diagnostic.code == "RUST_HIR_CONST_GENERIC_INSTANCE_SKIPPED" })
    );
    assert_eq!(
        result.profile.properties["rust_hir_status"],
        "import-type-call-graph-partial"
    );
}

#[test]
fn closure_bodies_have_exact_owners_while_unrepresented_anonymous_bodies_are_skipped() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("local-boundaries");
    write_minimal_crate(
        &root,
        "local-boundary-fixture",
        r#"pub struct Boxed<T> { pub value: T }
pub struct ConstDefault<const N: usize = { let signature_local = 1; signature_local }>;

pub fn signature(_: [u8; { let signature_fn_local = 1; signature_fn_local }]) {}

pub fn patterns(value: Option<(u32, u32)>) {
    let (Some((chosen, _)) | Some((_, chosen))) = value else { return; };
    let closure_value = |closure_input: u32| {
        let inside_closure = closure_input;
        Boxed::<u32> { value: inside_closure }
    };
    let _ = (chosen, closure_value);
}

pub fn target() {}
pub fn anonymous_future() {
    let _future = async { target() };
}
"#,
    );

    let result = scan(&root).unwrap();
    assert_ne!(result.profile.properties["rust_hir_status"], "failed");
    assert!(result.nodes.iter().any(|node| {
        node.kind == "symbol"
            && node.properties["symbol_kind"] == "function"
            && node.display_name.as_deref() == Some("patterns")
    }));
    assert_eq!(
        result
            .nodes
            .iter()
            .filter(|node| {
                node.kind == "symbol"
                    && node.properties["symbol_kind"] == "local_variable"
                    && node.display_name.as_deref() == Some("chosen")
            })
            .count(),
        1
    );
    assert!(!result.nodes.iter().any(|node| {
        node.kind == "symbol"
            && matches!(
                node.display_name.as_deref(),
                Some("signature_local" | "signature_fn_local")
            )
    }));
    let closure = result
        .nodes
        .iter()
        .find(|node| node.kind == "symbol" && node.properties["symbol_kind"] == "closure")
        .expect("closure node");
    for name in ["closure_input", "inside_closure"] {
        let local = result
            .nodes
            .iter()
            .find(|node| node.kind == "symbol" && node.display_name.as_deref() == Some(name))
            .unwrap_or_else(|| panic!("closure local {name}"));
        assert_eq!(
            local.properties["canonical_identity"]["enclosing_symbol"],
            closure.id
        );
    }
    let closure_instance = result
        .nodes
        .iter()
        .find(|node| {
            node.kind == "type"
                && node.properties["type_kind"] == "generic_instance"
                && node
                    .properties
                    .get("resolver_identity")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|resolver| resolver.contains("Boxed::<T=builtin:u32>"))
        })
        .expect("generic instance inside closure");
    assert!(result.edges.iter().any(|edge| {
        edge.kind == "instantiates"
            && edge.source == closure.id
            && edge.target == closure_instance.id
    }));
    assert!(
        !result
            .sites
            .iter()
            .any(|site| { site.kind == "call" && site.specifier == "target" })
    );
    assert!(
        result
            .diagnostics
            .iter()
            .any(|diagnostic| { diagnostic.code == "RUST_HIR_ANONYMOUS_CALLER_UNREPRESENTED" })
    );
    assert!(
        result
            .diagnostics
            .iter()
            .any(|diagnostic| { diagnostic.code == "RUST_HIR_ANONYMOUS_BODY_DEFINITION_SKIPPED" })
    );
}

#[test]
fn implicit_self_and_partial_dyn_bounds_do_not_collapse_generic_instances() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("implicit-types");
    write_minimal_crate(
        &root,
        "implicit-type-fixture",
        r#"pub struct Wrap<T> { pub value: T }
pub struct Borrowed<'a, T> { pub value: &'a T }
pub trait Marker {}
pub trait First { fn wrapped() -> Wrap<Self> where Self: Sized; }
pub trait Second { fn wrapped() -> Wrap<Self> where Self: Sized; }
pub fn dynamic(value: &dyn Marker) -> Wrap<&dyn Marker> { Wrap { value } }
pub fn borrowed<'a>(value: &'a u8) -> Borrowed<'a, u8> {
    Borrowed::<u8> { value }
}
"#,
    );

    let result = scan(&root).unwrap();
    assert!(
        !result.nodes.iter().any(|node| {
            node.kind == "type" && node.properties["type_kind"] == "generic_instance"
        })
    );
    assert!(
        result
            .diagnostics
            .iter()
            .any(|diagnostic| { diagnostic.code == "RUST_HIR_GENERIC_INSTANCE_UNREPRESENTABLE" })
    );
    assert!(
        result
            .diagnostics
            .iter()
            .any(|diagnostic| { diagnostic.code == "RUST_HIR_LIFETIME_GENERIC_INSTANCE_SKIPPED" })
    );
    assert_eq!(
        result.profile.properties["rust_hir_status"],
        "import-type-call-graph-partial"
    );
}

#[test]
fn extracts_cargo_targets_conditions_modules_and_safe_mode_sites() {
    let result = scan(&fixture()).unwrap();
    assert!(
        result
            .nodes
            .iter()
            .filter(|node| node.kind == "package_instance")
            .all(|node| node.properties["cargo_model"] == "metadata")
    );
    assert!(!result.nodes.iter().any(|node| {
        node.display_name.as_deref() == Some("ignored-non-member")
            || node.locator.contains("ignored/")
    }));
    assert!(
        result
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "CARGO_METADATA_FROZEN")
    );
    assert_eq!(result.profile.properties["rust_hir_project_model"], "ready");
    assert_eq!(
        result.profile.properties["rust_hir_enable_gate"],
        "release-gate-pending"
    );
    assert_eq!(
        result.profile.properties["rust_hir_backend"],
        "rust-analyzer-hir"
    );
    assert!(matches!(
        result.profile.properties["rust_hir_status"].as_str(),
        Some("import-type-call-graph-emitted" | "import-type-call-graph-partial")
    ));
    assert_eq!(
        result.profile.properties["crate_graph_source"],
        "confined-cargo-metadata"
    );
    assert!(
        result.profile.properties["rust_hir_project_file_count"]
            .as_u64()
            .is_some_and(|count| count > 0)
    );
    assert!(
        result.profile.properties["rust_hir_project_crate_count"]
            .as_u64()
            .is_some_and(|count| count > 0)
    );
    assert!(
        result.profile.properties["rust_hir_project_external_count"]
            .as_u64()
            .is_some_and(|count| count > 0)
    );
    assert!(
        result
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "RUST_HIR_PROJECT_MODEL_READY")
    );
    assert_eq!(
        result
            .diagnostics
            .iter()
            .filter(|diagnostic| { diagnostic.code == "RUST_HIR_EXTERNAL_DEFINITION_UNAVAILABLE" })
            .count(),
        1
    );
    assert!(
        result
            .coverage
            .reasons
            .iter()
            .any(|reason| reason == "rust-hir-external-definition-unavailable")
    );
    assert!(result.nodes.iter().any(|node| {
        node.kind == "build_unit" && node.properties["target_kind"] == "custom-build"
    }));
    assert!(result.nodes.iter().any(|node| node.kind == "module"));
    assert!(result.sites.iter().any(|site| {
        site.kind == "cargo_dependency"
            && site.specifier == "unix_local"
            && site.condition.render().contains("rust.cfg.unix")
    }));
    assert!(result.sites.iter().any(|site| {
        site.kind == "cargo_dependency"
            && site.specifier == "dev_local"
            && site.condition.render().contains("cargo.dependency_kind")
    }));
    assert!(result.sites.iter().any(|site| site.kind == "rust_reexport"));
    assert!(result.sites.iter().any(|site| site.kind == "extern_crate"));
    assert!(result.sites.iter().any(|site| site.kind == "include_str"));
    assert!(result.sites.iter().any(|site| {
        site.kind == "include"
            && site.specifier.contains("OUT_DIR")
            && site.resolution_status == ResolutionStatus::Unresolved
            && site
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("OUT_DIR"))
    }));
    assert!(
        result
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "RUST_HIR_OUT_DIR_UNAVAILABLE")
    );
    assert!(
        result
            .coverage
            .reasons
            .iter()
            .any(|reason| reason == "rust-hir-out-dir-unavailable")
    );
    assert!(result.sites.iter().any(|site| {
        site.kind == "build_script_execution"
            && site.resolution_status == ResolutionStatus::Unresolved
    }));
    assert!(result.sites.iter().any(|site| {
        site.kind == "proc_macro_execution"
            && site.resolution_status == ResolutionStatus::Unresolved
    }));
    assert!(
        result
            .nodes
            .iter()
            .any(|node| node.kind == "external_system")
    );
    assert!(
        result
            .nodes
            .iter()
            .any(|node| node.kind == "unknown_target")
    );
}

#[test]
fn safe_scan_never_executes_config_build_script_or_proc_macro() {
    let temp = tempfile::tempdir().unwrap();
    let copied = temp.path().join("workspace");
    copy_tree(&fixture(), &copied);
    let result = scan(&copied).unwrap();
    assert!(!copied.join("BUILD_SCRIPT_EXECUTED").exists());
    assert!(!copied.join("PROC_MACRO_EXECUTED").exists());
    assert!(!copied.join("CONFIG_EXECUTED").exists());
    assert!(!result.coverage.project_code_executed);
}

#[test]
fn macro_and_build_environment_boundaries_are_explicitly_ledgered() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("macro-boundaries");
    write_minimal_crate(
        &root,
        "macro-boundaries",
        r#"#![doc = include_str!(concat!(env!("OUT_DIR"), "/crate.md"))]
#[derive(Debug, ExternalDerive)]
#[external::marker]
pub struct Item;

#[derive(Foo + Bar)]
pub struct InvalidAttribute;

#[unsafe(export_name = env!("SYMBOL"))]
pub extern "C" fn exported() {}

external::expand!();
pub const GENERATED: &str = env!("OUT_DIR");
"#,
    );

    let result = scan(&root).unwrap();

    let proc_macro_sites: Vec<_> = result
        .sites
        .iter()
        .filter(|site| site.kind == "proc_macro_expansion")
        .collect();
    assert!(proc_macro_sites.len() >= 3, "sites: {:?}", result.sites);
    assert!(proc_macro_sites.iter().all(|site| {
        site.resolution_status == ResolutionStatus::Unresolved && !site.target_ids.is_empty()
    }));
    assert!(result.sites.iter().any(|site| {
        site.kind == "macro_expansion"
            && site.specifier == "external::expand!"
            && site.resolution_status == ResolutionStatus::Unresolved
    }));
    let out_dir = result
        .sites
        .iter()
        .find(|site| site.kind == "build_environment" && site.specifier == "OUT_DIR")
        .expect("OUT_DIR build environment boundary");
    assert_eq!(out_dir.resolution_status, ResolutionStatus::Unresolved);
    assert!(result.sites.iter().any(|site| {
        site.kind == "build_environment"
            && site.specifier == "SYMBOL"
            && site.resolution_status == ResolutionStatus::Unresolved
    }));
    assert!(result.sites.iter().any(|site| {
        site.kind == "include_str"
            && site.specifier.contains("OUT_DIR")
            && site.resolution_status == ResolutionStatus::Unresolved
    }));
    assert!(result.sites.iter().any(|site| {
        site.kind == "unsupported_attribute"
            && site.specifier.starts_with("derive(")
            && site.resolution_status == ResolutionStatus::Unresolved
    }));
    assert!(
        result
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "PROC_MACRO_EXPANSION_NOT_EXECUTED")
    );
    assert!(
        result
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "MACRO_EXPANSION_NOT_EVALUATED")
    );
    assert!(
        result
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "RUST_HIR_OUT_DIR_UNAVAILABLE")
    );
    assert!(
        result
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "RUST_ATTRIBUTE_UNSUPPORTED")
    );
    assert!(result.coverage.unsupported_syntax > 0);
    assert!(
        result
            .coverage
            .reasons
            .iter()
            .any(|reason| reason == "proc-macro-expansion-not-executed")
    );
    assert!(
        result
            .coverage
            .reasons
            .iter()
            .any(|reason| reason == "macro-expansion-not-evaluated")
    );
    assert!(
        result
            .coverage
            .reasons
            .iter()
            .any(|reason| reason == "rust-hir-out-dir-unavailable")
    );
    assert!(
        !result
            .coverage
            .completeness
            .contains(&CompletenessLevel::SemanticComplete)
    );
    assert!(!result.coverage.project_code_executed);
}

#[test]
fn armed_security_fixture_proves_safe_scan_does_not_execute_project_code() {
    let temp = tempfile::tempdir().unwrap();
    let safe_copy = temp.path().join("safe");
    copy_tree(&security_fixture(), &safe_copy);
    let result = scan(&safe_copy).unwrap();
    for marker in [
        "BUILD_SCRIPT_EXECUTED",
        "PROC_MACRO_EXECUTED",
        "CONFIG_EXECUTED",
    ] {
        assert!(
            !safe_copy.join(marker).exists(),
            "safe scan created {marker}"
        );
    }
    assert!(!result.coverage.project_code_executed);
    assert_eq!(result.profile.properties["rust_hir_backend"], "disabled");
    assert_eq!(result.profile.properties["rust_hir_status"], "not-invoked");
    assert_eq!(
        result.profile.properties["rust_hir_toolchain_status"],
        "unsupported"
    );
    assert_eq!(
        result.profile.properties["rust_toolchain_declaration_status"],
        "valid"
    );
    assert_eq!(
        result.profile.properties["rust_toolchain_probe_status"],
        result.profile.properties["rust_toolchain_observed"]["status"]
    );
    assert!(
        result
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "RUST_HIR_TOOLCHAIN_UNSUPPORTED")
    );
    assert_eq!(result.profile.properties["build_script_policy"], "disabled");
    assert_eq!(result.profile.properties["proc_macro_policy"], "disabled");
    assert_eq!(result.profile.properties["project_code_executed"], false);
    assert_eq!(
        result.profile.properties["project_toolchain_executed"],
        false
    );
    assert!(result.edges.iter().all(|edge| edge.phase == Phase::Source));
    assert!(result.sites.iter().any(|site| {
        site.kind == "macro_expansion"
            && site.specifier == "security_macro::touch!"
            && site.resolution_status == ResolutionStatus::Unresolved
    }));
    for (site_kind, diagnostic_code, coverage_reason) in [
        (
            "build_script_execution",
            "BUILD_SCRIPT_NOT_EXECUTED",
            "build-script-not-executed",
        ),
        (
            "proc_macro_execution",
            "PROC_MACRO_NOT_EXECUTED",
            "proc-macro-not-executed",
        ),
    ] {
        let site = result
            .sites
            .iter()
            .find(|site| site.kind == site_kind)
            .unwrap_or_else(|| panic!("missing {site_kind} site"));
        assert_eq!(site.resolution_status, ResolutionStatus::Unresolved);
        assert!(
            site.reason
                .as_deref()
                .is_some_and(|reason| reason.contains("does not execute"))
        );
        assert!(!site.target_ids.is_empty());
        assert!(site.target_ids.iter().all(|target| {
            result
                .nodes
                .iter()
                .any(|node| node.id == *target && node.kind == "unknown_target")
        }));
        assert!(
            result
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == diagnostic_code)
        );
        assert!(
            result
                .coverage
                .reasons
                .iter()
                .any(|reason| reason == coverage_reason)
        );
    }
    assert!(
        !result
            .coverage
            .completeness
            .contains(&CompletenessLevel::SemanticComplete)
    );

    let armed_copy = temp.path().join("armed");
    copy_tree(&security_fixture(), &armed_copy);
    let status = Command::new("cargo")
        .args(["check", "--offline", "--locked"])
        .current_dir(&armed_copy)
        .env_remove("RUSTC_WRAPPER")
        .env("RUSTUP_TOOLCHAIN", "1.93.1")
        .env("CARGO_TARGET_DIR", temp.path().join("armed-target"))
        .status()
        .unwrap();
    assert!(status.success(), "security fixture must remain buildable");
    for marker in [
        "BUILD_SCRIPT_EXECUTED",
        "PROC_MACRO_EXECUTED",
        "CONFIG_EXECUTED",
    ] {
        assert!(
            armed_copy.join(marker).exists(),
            "fixture did not arm {marker}"
        );
    }
}

#[test]
fn missing_cargo_preserves_static_syntax_graph_without_semantic_completeness() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("simple-crate");
    let empty_path = temp.path().join("empty-path");
    fs::create_dir_all(root.join("src")).unwrap();
    fs::create_dir_all(&empty_path).unwrap();
    fs::write(
        root.join("Cargo.toml"),
        "[package]\nname='simple-crate'\nversion='0.1.0'\nedition='2024'\n",
    )
    .unwrap();
    fs::write(
        root.join("src/lib.rs"),
        "pub mod model;\npub use model::Thing;\n",
    )
    .unwrap();
    fs::write(root.join("src/model.rs"), "pub struct Thing;\n").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_depgraph-rust-worker"))
        .arg("--root")
        .arg(&root)
        .arg("--scan-id")
        .arg("missing-cargo-fallback")
        .env("PATH", &empty_path)
        .env_remove("DEPGRAPH_PROFILE_CONFIG")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "fallback worker failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let validated = validate_ndjson(Cursor::new(output.stdout)).unwrap();
    assert!(
        validated
            .diagnostics
            .values()
            .any(|diagnostic| diagnostic.code == "CARGO_METADATA_FALLBACK")
    );
    let profile = validated.profiles.values().next().unwrap();
    assert_eq!(profile.properties["analysis_backend"], "static-syntax");
    assert_eq!(profile.properties["rust_hir_backend"], "disabled");
    assert_eq!(profile.properties["rust_hir_status"], "not-invoked");
    assert_eq!(profile.properties["rust_hir_project_model"], "not-invoked");
    assert_eq!(
        profile.properties["rust_hir_enable_gate"],
        "toolchain-unsupported"
    );
    assert_eq!(
        profile.properties["crate_graph_source"],
        "static-manifest-fallback"
    );
    assert_eq!(
        profile.properties["rust_toolchain_probe_status"],
        "unavailable"
    );
    assert_eq!(
        profile.properties["rust_hir_toolchain_status"],
        "unavailable"
    );
    assert_eq!(profile.properties["syntax_fallback"], "enabled");
    assert!(validated.nodes.values().any(|node| node.kind == "module"));
    assert!(validated.sites.values().any(|site| {
        site.kind == "rust_reexport"
            && site.specifier == "model::Thing"
            && site.resolution_status == ResolutionStatus::Resolved
    }));
    assert!(
        validated
            .edges
            .values()
            .all(|edge| edge.phase == Phase::Source)
    );

    let coverage = validated
        .events
        .iter()
        .find_map(|event| match event {
            ProtocolEvent::ScanCompleted(completed) => Some(&completed.coverage),
            _ => None,
        })
        .expect("scan coverage");
    assert!(!coverage.project_code_executed);
    assert!(
        coverage
            .reasons
            .iter()
            .any(|reason| reason == "cargo-metadata-fallback")
    );
    assert!(
        coverage
            .reasons
            .iter()
            .any(|reason| reason == "rust-hir-unsupported")
    );
    assert!(
        coverage
            .completeness
            .contains(&CompletenessLevel::SyntaxComplete)
    );
    assert!(
        !coverage
            .completeness
            .contains(&CompletenessLevel::SemanticComplete)
    );
}

#[test]
fn ready_project_model_keeps_missing_modules_in_the_unresolved_ledger() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("missing-module");
    fs::create_dir_all(root.join("src")).unwrap();
    fs::write(
        root.join("Cargo.toml"),
        "[package]\nname='missing-module'\nversion='0.1.0'\nedition='2024'\n",
    )
    .unwrap();
    fs::write(root.join("src/lib.rs"), "pub mod missing;\n").unwrap();

    let result = scan(&root).unwrap();
    let site = result
        .sites
        .iter()
        .find(|site| site.kind == "module_declaration" && site.specifier == "missing")
        .unwrap();
    assert_eq!(site.resolution_status, ResolutionStatus::Unresolved);
    assert!(result.coverage.unresolved > 0);
    assert!(
        !result
            .coverage
            .completeness
            .contains(&CompletenessLevel::SemanticComplete)
    );
    if result.profile.properties["rust_hir_toolchain_status"] == "compatible" {
        assert_eq!(result.profile.properties["rust_hir_project_model"], "ready");
    }
}

#[test]
fn static_fallback_respects_members_exclude_and_lock_versions() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fallback");
    let result = scan(&root).unwrap();
    assert!(
        result
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "CARGO_METADATA_FALLBACK")
    );
    assert!(
        result
            .diagnostics
            .iter()
            .any(|diagnostic| { diagnostic.code == "RUST_HIR_CRATE_GRAPH_UNAVAILABLE" })
    );
    assert_eq!(
        result.profile.properties["rust_hir_project_model"],
        "unavailable"
    );
    assert_eq!(
        result.profile.properties["rust_hir_enable_gate"],
        "crate-graph-unavailable"
    );
    assert_eq!(
        result.profile.properties["crate_graph_source"],
        "static-manifest-fallback"
    );
    assert_eq!(result.profile.properties["rust_hir_project_file_count"], 0);
    assert_eq!(result.profile.properties["rust_hir_project_crate_count"], 0);
    assert_eq!(
        result.profile.properties["rust_hir_project_external_count"],
        0
    );
    assert!(
        result
            .coverage
            .reasons
            .iter()
            .any(|reason| reason == "rust-hir-crate-graph-unavailable")
    );
    let package_names: BTreeSet<_> = result
        .nodes
        .iter()
        .filter(|node| node.kind == "package_instance")
        .filter_map(|node| node.display_name.as_deref())
        .collect();
    assert_eq!(
        package_names,
        BTreeSet::from(["auto-member", "included", "member"])
    );
    assert!(
        !result
            .nodes
            .iter()
            .any(|node| { node.locator.contains("excluded") || node.locator.contains("ignored") })
    );
    assert!(result.nodes.iter().any(|node| {
        node.kind == "external_system" && node.locator == "cargo:registry-dep@9.8.7"
    }));
    assert!(result.sites.iter().any(|site| {
        site.specifier == "registry-dep"
            && site.evidence.iter().any(|evidence| {
                evidence.properties["lock_resolved"] == true
                    && evidence.properties["lock_path"] == "Cargo.lock"
            })
    }));
}

#[test]
fn outside_path_dependency_is_anonymized_in_graph_and_diagnostic() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("root");
    let outside = temp.path().join("outside-secret-name");
    fs::create_dir_all(root.join("src")).unwrap();
    fs::create_dir_all(outside.join("src")).unwrap();
    fs::write(
        root.join("Cargo.toml"),
        r#"[package]
name = "root-package"
version = "0.1.0"
edition = "2024"

[dependencies]
outside_alias = { package = "outside-package", version = "4.5.6", path = "../outside-secret-name" }
"#,
    )
    .unwrap();
    fs::write(root.join("src/lib.rs"), "use outside_alias::Thing;\n").unwrap();
    fs::write(
        root.join("Cargo.lock"),
        r#"version = 4

[[package]]
name = "root-package"
version = "0.1.0"
dependencies = ["outside-package 4.5.6"]

[[package]]
name = "outside-package"
version = "4.5.6"
"#,
    )
    .unwrap();
    fs::write(
        outside.join("Cargo.toml"),
        "[package]\nname='outside-package'\nversion='4.5.6'\nedition='2024'\n",
    )
    .unwrap();
    fs::write(outside.join("src/lib.rs"), "pub struct Thing;\n").unwrap();

    let result = scan(&root).unwrap();
    let external = result
        .nodes
        .iter()
        .find(|node| {
            node.kind == "external_system"
                && node.display_name.as_deref() == Some("outside-package")
        })
        .unwrap();
    assert!(
        external
            .locator
            .starts_with("cargo-path:outside-package@4.5.6#outside-")
    );
    assert!(!external.locator.contains("outside-secret-name"));
    let diagnostic = result
        .diagnostics
        .iter()
        .find(|diagnostic| diagnostic.code == "EXTERNAL_PATH_DEPENDENCY")
        .unwrap();
    assert!(!diagnostic.message.contains("outside-secret-name"));
    let graph_payload = serde_json::to_string(&(&result.nodes, &result.diagnostics)).unwrap();
    assert!(!graph_payload.contains(&outside.to_string_lossy().to_string()));
}

#[cfg(unix)]
#[test]
fn include_symlink_cannot_resolve_outside_the_scan_root() {
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("root");
    let outside = temp.path().join("outside-secret.txt");
    fs::create_dir_all(root.join("src")).unwrap();
    fs::write(
        root.join("Cargo.toml"),
        "[package]\nname='confined-include'\nversion='0.1.0'\nedition='2024'\n",
    )
    .unwrap();
    fs::write(
        root.join("src/lib.rs"),
        "pub const DATA: &str = include_str!(\"secret.txt\");\n",
    )
    .unwrap();
    fs::write(&outside, "must not be inventoried").unwrap();
    symlink(&outside, root.join("src/secret.txt")).unwrap();

    let result = scan(&root).unwrap();
    let site = result
        .sites
        .iter()
        .find(|site| site.kind == "include_str")
        .unwrap();
    assert_eq!(site.resolution_status, ResolutionStatus::Unresolved);
    assert!(!result.nodes.iter().any(|node| {
        node.locator.contains("outside-secret")
            || node
                .properties
                .values()
                .any(|value| value == "must not be inventoried")
    }));
}

#[test]
fn configured_rust_profile_is_canonical() {
    let first = worker_profile(
        r#"{"rust_features":[" serde ","fast","serde",""] ,"rust_targets":["wasm32-unknown-unknown"," aarch64-apple-darwin "]}"#,
    );
    let second = worker_profile(
        r#"{"rust_features":["fast","serde"],"rust_targets":["aarch64-apple-darwin","wasm32-unknown-unknown"]}"#,
    );
    assert_eq!(first, second);
    assert!(first.id.starts_with("profile:sha256:"));
    assert_eq!(first.features, ["default", "fast", "serde"]);
    assert_eq!(
        first.target.as_deref(),
        Some("aarch64-apple-darwin,wasm32-unknown-unknown")
    );
    if first.properties["rust_hir_toolchain_status"] == "compatible" {
        assert_eq!(first.properties["rust_hir_project_model"], "unsupported");
        assert_eq!(
            first.properties["rust_hir_enable_gate"],
            "input-unsupported"
        );
    }

    let different_target = worker_profile(
        r#"{"rust_features":["fast","serde"],"rust_targets":["x86_64-unknown-linux-gnu"]}"#,
    );
    assert_ne!(first.id, different_target.id);
}

#[test]
fn configured_rust_mode_reaches_the_safe_project_builder() {
    let check = worker_profile(r#"{"rust_mode":"check"}"#);
    let test = worker_profile(r#"{"rust_mode":"test"}"#);

    assert_eq!(check.command.as_deref(), Some("check"));
    assert_eq!(test.command.as_deref(), Some("test"));
    assert_eq!(test.properties["rust_mode"], "test");
    assert_ne!(check.id, test.id);
    if test.properties["rust_hir_toolchain_status"] == "compatible" {
        assert_eq!(test.properties["rust_hir_project_model"], "ready");
        assert!(
            test.properties["rust_hir_project_crate_count"]
                .as_u64()
                .zip(check.properties["rust_hir_project_crate_count"].as_u64())
                .is_some_and(|(test_count, check_count)| test_count > check_count)
        );
    }
}

#[test]
fn default_rust_profile_has_stable_hashed_host_identity() {
    let first = worker_profile("{}");
    let second = worker_profile("{}");
    assert_eq!(first.id, second.id);
    assert!(first.id.starts_with("profile:sha256:"));
    let target = first.target.as_deref().expect("default host target");
    assert!(!target.is_empty());
    assert_eq!(first.environment["rust.host_target"], target);
    assert_eq!(first.properties["effective_target"], target);
    assert_eq!(
        first.properties["rust_hir_integration_policy"],
        "pinned-rust-analyzer-library"
    );
    assert_eq!(
        first.properties["rust_analyzer_version"],
        RUST_ANALYZER_CRATE_VERSION
    );
    assert_eq!(
        first.properties["rust_analyzer_revision"],
        RUST_ANALYZER_REVISION
    );
    assert_eq!(
        first.properties["rust_analyzer_salsa_version"],
        RUST_ANALYZER_SALSA_VERSION
    );
    let probe_status = first.properties["rust_toolchain_probe_status"]
        .as_str()
        .expect("toolchain probe status");
    assert!(matches!(
        probe_status,
        "compatible" | "unsupported" | "unavailable"
    ));
    if probe_status == "compatible" {
        assert_eq!(
            first.properties["analysis"],
            "syntax+hir-imports-types-calls"
        );
        assert_eq!(
            first.properties["analysis_backend"],
            "static-syntax+rust-analyzer-hir"
        );
        assert_eq!(first.properties["rust_hir_backend"], "rust-analyzer-hir");
        assert!(matches!(
            first.properties["rust_hir_status"].as_str(),
            Some("import-type-call-graph-emitted" | "import-type-call-graph-partial")
        ));
    } else {
        assert_eq!(first.properties["analysis"], "syntax");
        assert_eq!(first.properties["analysis_backend"], "static-syntax");
        assert_eq!(first.properties["rust_hir_backend"], "disabled");
        assert_eq!(first.properties["rust_hir_status"], "not-invoked");
    }
    assert_eq!(
        first.properties["rust_toolchain_observed"]["status"],
        probe_status
    );
    assert_eq!(first.properties["rust_hir_toolchain_status"], probe_status);
    if probe_status == "compatible" {
        assert_eq!(first.properties["rust_hir_project_model"], "ready");
        assert_eq!(
            first.properties["rust_hir_enable_gate"],
            "release-gate-pending"
        );
        assert!(
            first.properties["rust_hir_project_file_count"]
                .as_u64()
                .is_some_and(|count| count > 0)
        );
        assert!(
            first.properties["rust_hir_project_crate_count"]
                .as_u64()
                .is_some_and(|count| count > 0)
        );
        assert!(
            first.properties["rust_hir_project_external_count"]
                .as_u64()
                .is_some_and(|count| count > 0)
        );
    } else {
        assert_eq!(first.properties["rust_hir_project_model"], "not-invoked");
        assert_eq!(
            first.properties["rust_hir_enable_gate"],
            "toolchain-unsupported"
        );
    }
    assert_eq!(
        first.properties["rust_toolchain_declaration_status"],
        "absent"
    );
    assert_eq!(first.properties["rust_hir_scaffold"], "available");
    assert_eq!(first.properties["rust_toolchain_baseline"], "1.93.1");
    assert_eq!(
        first.properties["crate_graph_source_policy"],
        "confined-cargo-metadata-or-static-manifest"
    );
    assert_eq!(first.properties["cargo_metadata_input"], "confined-mirror");
    assert_eq!(first.properties["syntax_fallback"], "enabled");
    assert_eq!(first.properties["build_script_policy"], "disabled");
    assert_eq!(first.properties["proc_macro_policy"], "disabled");
    assert_eq!(first.properties["project_code_executed"], false);
    assert_eq!(first.properties["project_toolchain_executed"], false);
    assert_eq!(first.properties["build_scripts_executed"], false);
    assert_eq!(first.properties["proc_macros_executed"], false);
}

#[test]
fn unsupported_target_is_explicitly_ledgered_for_the_hir_project_model() {
    let output = Command::new(env!("CARGO_BIN_EXE_depgraph-rust-worker"))
        .arg("--root")
        .arg(fixture())
        .arg("--scan-id")
        .arg("unsupported-hir-target")
        .env(
            "DEPGRAPH_PROFILE_CONFIG",
            r#"{"rust_targets":["wasm32-unknown-unknown"]}"#,
        )
        .output()
        .unwrap();
    assert!(output.status.success());
    let validated = validate_ndjson(Cursor::new(output.stdout)).unwrap();
    let profile = validated.profiles.values().next().unwrap();
    if profile.properties["rust_hir_toolchain_status"] != "compatible" {
        assert_eq!(profile.properties["rust_hir_project_model"], "not-invoked");
        return;
    }
    assert_eq!(profile.properties["rust_hir_project_model"], "unsupported");
    assert_eq!(
        profile.properties["rust_hir_enable_gate"],
        "input-unsupported"
    );
    assert_eq!(
        profile.properties["crate_graph_source"],
        "confined-cargo-metadata"
    );
    assert!(
        validated
            .diagnostics
            .values()
            .any(|diagnostic| diagnostic.code == "RUST_HIR_INPUT_UNSUPPORTED")
    );
    let coverage = validated
        .events
        .iter()
        .find_map(|event| match event {
            ProtocolEvent::ScanCompleted(completed) => Some(&completed.coverage),
            _ => None,
        })
        .expect("scan coverage");
    assert!(
        coverage
            .reasons
            .iter()
            .any(|reason| reason == "rust-hir-unsupported")
    );
}

#[test]
fn unsupported_edition_is_explicit_and_preserves_the_syntax_graph() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("unsupported-edition");
    write_minimal_crate(&root, "unsupported-edition", "pub struct SyntaxOnly;\n");
    fs::write(
        root.join("Cargo.toml"),
        "[package]\nname='unsupported-edition'\nversion='0.1.0'\nedition='2099'\n",
    )
    .unwrap();

    let result = scan(&root).unwrap();
    if result.profile.properties["rust_hir_toolchain_status"] != "compatible" {
        assert_eq!(
            result.profile.properties["rust_hir_project_model"],
            "not-invoked"
        );
        return;
    }

    assert_eq!(
        result.profile.properties["rust_hir_project_model"],
        "unsupported"
    );
    assert_eq!(
        result.profile.properties["rust_hir_enable_gate"],
        "input-unsupported"
    );
    assert!(
        result
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "RUST_HIR_INPUT_UNSUPPORTED")
    );
    assert!(
        result
            .coverage
            .reasons
            .iter()
            .any(|reason| reason == "rust-hir-unsupported")
    );
    assert!(result.nodes.iter().any(|node| node.kind == "file"));
    assert!(
        result
            .edges
            .iter()
            .all(|edge| edge.phase != Phase::Semantic)
    );
    assert!(
        !result
            .coverage
            .completeness
            .contains(&CompletenessLevel::SemanticComplete)
    );
}

#[test]
fn resolves_canonical_nested_modules_cfg_attr_paths_and_unlocked_ranges() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("module-resolution");
    for directory in ["src/left", "src/right"] {
        fs::create_dir_all(root.join(directory)).unwrap();
    }
    fs::write(
        root.join("Cargo.toml"),
        r#"[package]
name = "module-resolution"
version = "0.1.0"
edition = "2024"

[dependencies]
range-only = ">=1, <2"
"#,
    )
    .unwrap();
    fs::write(
        root.join("src/lib.rs"),
        r#"mod left;
mod right;
#[cfg_attr(unix, path = "unix_impl.rs")]
mod platform;
pub use crate::left::common::Left;
pub use crate::right::common::Right;
"#,
    )
    .unwrap();
    fs::write(
        root.join("src/left.rs"),
        r#"pub mod common;
pub use self::common::Left;
pub mod nested {
    pub use super::common::Left;
}
"#,
    )
    .unwrap();
    fs::write(
        root.join("src/right.rs"),
        "pub mod common;\npub use self::common::Right;\n",
    )
    .unwrap();
    fs::write(root.join("src/left/common.rs"), "pub struct Left;\n").unwrap();
    fs::write(root.join("src/right/common.rs"), "pub struct Right;\n").unwrap();
    fs::write(
        root.join("src/unix_impl.rs"),
        "pub const KIND: &str = \"unix\";\n",
    )
    .unwrap();
    fs::write(
        root.join("src/platform.rs"),
        "pub const KIND: &str = \"default\";\n",
    )
    .unwrap();

    let result = scan(&root).unwrap();
    let assert_target_path =
        |specifier: &str, evidence_path: &str, module_path: &str, item: &str| {
            let site = result
                .sites
                .iter()
                .find(|site| {
                    site.specifier == specifier
                        && site
                            .evidence
                            .iter()
                            .any(|evidence| evidence.path.as_deref() == Some(evidence_path))
                })
                .unwrap_or_else(|| panic!("missing {specifier} in {evidence_path}"));
            assert_eq!(site.resolution_status, ResolutionStatus::Resolved);
            assert_eq!(site.precision, Precision::Exact);
            assert_eq!(site.target_ids.len(), 1);
            let target = result
                .nodes
                .iter()
                .find(|node| node.id == site.target_ids[0])
                .expect("resolved import target");
            if let Some(resolver) = target.properties["resolver_identity"].as_str() {
                assert!(
                    resolver.ends_with(&format!("::crate::{module_path}::{item}")),
                    "unexpected semantic resolver {resolver}"
                );
            } else {
                assert_eq!(
                    target.properties["canonical_module_path"].as_str(),
                    Some(module_path)
                );
            }
        };
    assert_target_path("self::common::Left", "src/left.rs", "left::common", "Left");
    assert_target_path(
        "self::common::Right",
        "src/right.rs",
        "right::common",
        "Right",
    );
    assert_target_path("super::common::Left", "src/left.rs", "left::common", "Left");
    assert_target_path(
        "crate::left::common::Left",
        "src/lib.rs",
        "left::common",
        "Left",
    );
    assert_target_path(
        "crate::right::common::Right",
        "src/lib.rs",
        "right::common",
        "Right",
    );

    let platform_sites: Vec<_> = result
        .sites
        .iter()
        .filter(|site| {
            site.kind == "module_declaration"
                && site
                    .evidence
                    .iter()
                    .any(|evidence| evidence.path.as_deref() == Some("src/lib.rs"))
                && matches!(site.specifier.as_str(), "platform" | "unix_impl.rs")
        })
        .collect();
    assert_eq!(platform_sites.len(), 2);
    assert!(platform_sites.iter().all(|site| {
        site.resolution_status == ResolutionStatus::Resolved
            && site.condition.render().contains("rust.cfg.unix")
    }));
    assert!(
        platform_sites
            .iter()
            .any(|site| site.condition.render().contains("!("))
    );

    let range = result
        .sites
        .iter()
        .find(|site| site.kind == "cargo_dependency" && site.specifier == "range-only")
        .unwrap();
    assert_eq!(range.resolution_status, ResolutionStatus::External);
    assert_eq!(range.precision, Precision::Heuristic);
    assert!(
        range
            .reason
            .as_deref()
            .unwrap()
            .contains("not lock-resolved")
    );
}

#[test]
fn expands_default_feature_aliases_consistently_for_metadata_and_fallback() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("feature-profile");
    fs::create_dir_all(root.join("src")).unwrap();
    fs::create_dir_all(root.join("optional-dep/src")).unwrap();
    fs::write(
        root.join("Cargo.toml"),
        r#"[package]
name = "feature-profile"
version = "0.1.0"
edition = "2024"

[features]
default = ["full"]
full = ["json"]
json = ["dep:optional_dep"]

[dependencies]
optional_dep = { package = "optional-dep", path = "optional-dep", optional = true }
anyhow = "=1.0.103"
"#,
    )
    .unwrap();
    fs::write(
        root.join("src/lib.rs"),
        "#[cfg(feature = \"json\")] pub fn enabled() {}\n",
    )
    .unwrap();
    fs::write(
        root.join("optional-dep/Cargo.toml"),
        "[package]\nname='optional-dep'\nversion='0.1.0'\nedition='2024'\n",
    )
    .unwrap();
    fs::write(root.join("optional-dep/src/lib.rs"), "pub struct Value;\n").unwrap();
    fs::write(
        root.join("Cargo.lock"),
        r#"version = 4

[[package]]
name = "feature-profile"
version = "0.1.0"
dependencies = ["anyhow", "optional-dep"]

[[package]]
name = "anyhow"
version = "1.0.103"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "2a4385e2e34eb35d6b3efe798b9eb88096925d87726c0798709bf56d9ed84af3"

[[package]]
name = "optional-dep"
version = "0.1.0"
"#,
    )
    .unwrap();

    let metadata = scan(&root).unwrap();
    assert!(
        metadata
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "CARGO_METADATA_FROZEN")
    );
    assert_eq!(metadata.profile.features, ["default", "full", "json"]);
    assert!(metadata.profile.id.starts_with("profile:sha256:"));
    assert_eq!(
        metadata.profile.properties["requested_features"],
        serde_json::json!([])
    );
    assert_eq!(
        metadata.profile.properties["expanded_features"],
        serde_json::json!(["default", "full", "json"])
    );
    let metadata_condition = metadata
        .sites
        .iter()
        .find(|site| site.kind == "cargo_dependency" && site.specifier == "optional_dep")
        .unwrap()
        .condition
        .clone();
    assert!(metadata_condition.render().contains("rust.feature"));
    assert!(metadata_condition.render().contains("json"));

    fs::write(root.join("Cargo.lock"), "[[package").unwrap();
    let empty_path = temp.path().join("empty-path");
    fs::create_dir_all(&empty_path).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_depgraph-rust-worker"))
        .arg("--root")
        .arg(&root)
        .arg("--scan-id")
        .arg("feature-fallback")
        .env("PATH", &empty_path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "fallback worker failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let fallback = validate_ndjson(Cursor::new(output.stdout)).unwrap();
    assert!(
        fallback
            .diagnostics
            .values()
            .any(|diagnostic| diagnostic.code == "CARGO_METADATA_FALLBACK"),
        "diagnostics: {:?}",
        fallback
            .diagnostics
            .values()
            .map(|diagnostic| diagnostic.code.as_str())
            .collect::<Vec<_>>()
    );
    let fallback_profile = fallback.profiles.values().next().unwrap();
    assert_eq!(fallback_profile.features, metadata.profile.features);
    assert_eq!(fallback_profile.id, metadata.profile.id);
    let fallback_condition = fallback
        .sites
        .values()
        .find(|site| site.kind == "cargo_dependency" && site.specifier == "optional_dep")
        .unwrap()
        .condition
        .clone();
    assert_eq!(fallback_condition, metadata_condition);
}

#[test]
fn graph_ids_are_independent_of_checkout_and_regenerated_lockfile() {
    let first_temp = tempfile::tempdir().unwrap();
    let second_temp = tempfile::tempdir().unwrap();
    let first_root = first_temp.path().join("one");
    let second_root = second_temp.path().join("two");
    copy_tree(&fixture(), &first_root);
    copy_tree(&fixture(), &second_root);
    let first = scan(&first_root).unwrap();
    fs::remove_file(second_root.join("Cargo.lock")).unwrap();
    let second = scan(&second_root).unwrap();

    assert_eq!(
        first.profile.properties["crate_graph_source"],
        "confined-cargo-metadata"
    );
    assert_eq!(
        second.profile.properties["crate_graph_source"],
        "confined-cargo-metadata"
    );
    assert!(first.edges.iter().any(|edge| edge.phase == Phase::Semantic));
    assert!(
        second
            .edges
            .iter()
            .any(|edge| edge.phase == Phase::Semantic)
    );
    assert_eq!(
        first.nodes.iter().map(|node| &node.id).collect::<Vec<_>>(),
        second.nodes.iter().map(|node| &node.id).collect::<Vec<_>>()
    );
    assert_eq!(
        first.sites.iter().map(|site| &site.id).collect::<Vec<_>>(),
        second.sites.iter().map(|site| &site.id).collect::<Vec<_>>()
    );
    assert_eq!(
        first.edges.iter().map(|edge| &edge.id).collect::<Vec<_>>(),
        second.edges.iter().map(|edge| &edge.id).collect::<Vec<_>>()
    );
}

#[test]
fn metadata_fallback_is_explicit_and_checkout_stable() {
    let metadata_temp = tempfile::tempdir().unwrap();
    let first_temp = tempfile::tempdir().unwrap();
    let second_temp = tempfile::tempdir().unwrap();
    let metadata_root = metadata_temp.path().join("metadata");
    let first_root = first_temp.path().join("fallback-one");
    let second_root = second_temp.path().join("fallback-two");
    copy_tree(&fixture(), &metadata_root);
    copy_tree(&fixture(), &first_root);
    copy_tree(&fixture(), &second_root);
    fs::write(first_root.join("Cargo.lock"), "[[package").unwrap();
    fs::write(second_root.join("Cargo.lock"), "[[package").unwrap();

    let metadata = scan(&metadata_root).unwrap();
    let first = scan(&first_root).unwrap();
    let repeated = scan(&first_root).unwrap();
    let second = scan(&second_root).unwrap();
    assert!(
        metadata
            .edges
            .iter()
            .any(|edge| edge.phase == Phase::Semantic)
    );

    for fallback in [&first, &repeated, &second] {
        assert_eq!(
            fallback.profile.properties["crate_graph_source"],
            "static-manifest-fallback"
        );
        assert_eq!(
            fallback.profile.properties["rust_hir_status"],
            "not-invoked"
        );
        assert!(
            fallback
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "CARGO_METADATA_FALLBACK")
        );
        assert!(
            fallback
                .coverage
                .reasons
                .iter()
                .any(|reason| reason == "rust-hir-crate-graph-unavailable")
        );
        assert!(
            !fallback
                .nodes
                .iter()
                .any(|node| matches!(node.kind.as_str(), "symbol" | "type"))
        );
        assert!(
            !fallback
                .edges
                .iter()
                .any(|edge| edge.phase == Phase::Semantic)
        );
    }

    let graph_ids = |result: &depgraph_rust_worker::ScanResult| {
        let node_ids = result
            .nodes
            .iter()
            .map(|node| node.id.clone())
            .collect::<BTreeSet<_>>();
        let site_ids = result
            .sites
            .iter()
            .map(|site| site.id.clone())
            .collect::<BTreeSet<_>>();
        let edge_ids = result
            .edges
            .iter()
            .map(|edge| edge.id.clone())
            .collect::<BTreeSet<_>>();
        (node_ids, site_ids, edge_ids)
    };
    assert_eq!(graph_ids(&first), graph_ids(&repeated));
    assert_eq!(graph_ids(&first), graph_ids(&second));
    for candidate in [&repeated, &second] {
        assert_eq!(first.profile, candidate.profile);
        assert_eq!(first.nodes, candidate.nodes);
        assert_eq!(first.sites, candidate.sites);
        assert_eq!(first.edges, candidate.edges);
        assert_eq!(first.diagnostics, candidate.diagnostics);
        assert_eq!(first.files, candidate.files);
        assert_eq!(first.coverage, candidate.coverage);
    }
    let deterministic_events = |result: &depgraph_rust_worker::ScanResult| {
        build_events("deterministic-fallback-scan", result)
            .unwrap()
            .into_iter()
            .skip(1)
            .map(|event| serde_json::to_value(event).unwrap())
            .collect::<Vec<_>>()
    };
    assert_eq!(
        deterministic_events(&first),
        deterministic_events(&repeated)
    );
    assert_eq!(deterministic_events(&first), deterministic_events(&second));
}

#[test]
fn real_worker_stdout_passes_the_shared_validator() {
    let output = Command::new(env!("CARGO_BIN_EXE_depgraph-rust-worker"))
        .arg("--root")
        .arg(fixture())
        .arg("--scan-id")
        .arg("cli-fixture")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "worker failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let validated = validate_ndjson(Cursor::new(output.stdout)).unwrap();
    assert!(!validated.nodes.is_empty());
    assert!(!validated.sites.is_empty());
}

#[test]
fn binary_reports_protocol_version() {
    let output = Command::new(env!("CARGO_BIN_EXE_depgraph-rust-worker"))
        .arg("--version")
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert_eq!(
        stdout.trim(),
        format!(
            "depgraph-rust-worker {ADAPTER_VERSION} (protocol 1.0; rust-analyzer {RUST_ANALYZER_CRATE_VERSION}; rust-analyzer-revision {RUST_ANALYZER_REVISION}; salsa {RUST_ANALYZER_SALSA_VERSION})"
        )
    );
}

#[test]
fn release_gate_environment_requires_the_exact_verified_value() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("release-gate");
    write_minimal_crate(&root, "release-gate", "pub struct Thing;\n");

    for (value, expected) in [
        ("release-gate-verified", "release-gate-verified"),
        ("verified", "release-gate-pending"),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_depgraph-rust-worker"))
            .arg("--root")
            .arg(&root)
            .arg("--scan-id")
            .arg(format!("release-gate-{value}"))
            .env_remove("DEPGRAPH_PROFILE_CONFIG")
            .env("DEPGRAPH_RUST_RELEASE_GATE", value)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "release-gate worker failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let validated = validate_safe_semantic_ndjson(Cursor::new(output.stdout)).unwrap();
        let profile = validated.profiles.values().next().unwrap();
        assert_eq!(profile.properties["rust_hir_enable_gate"], expected);
        assert_eq!(
            profile.properties["rust_analyzer_version"],
            RUST_ANALYZER_CRATE_VERSION
        );
        assert_eq!(
            profile.properties["rust_analyzer_revision"],
            RUST_ANALYZER_REVISION
        );
        assert_eq!(
            profile.properties["rust_analyzer_salsa_version"],
            RUST_ANALYZER_SALSA_VERSION
        );
        assert!(
            validated
                .events
                .iter()
                .find_map(|event| match event {
                    ProtocolEvent::ScanCompleted(completed) => Some(&completed.coverage),
                    _ => None,
                })
                .is_some_and(|coverage| coverage
                    .completeness
                    .contains(&CompletenessLevel::SemanticComplete))
        );
    }
}

fn worker_profile(profile_config: &str) -> depgraph_protocol::Profile {
    let output = Command::new(env!("CARGO_BIN_EXE_depgraph-rust-worker"))
        .arg("--root")
        .arg(fixture())
        .arg("--scan-id")
        .arg("profile-fixture")
        .env("DEPGRAPH_PROFILE_CONFIG", profile_config)
        .output()
        .unwrap();
    assert!(output.status.success());
    validate_ndjson(Cursor::new(output.stdout))
        .unwrap()
        .profiles
        .into_values()
        .next()
        .unwrap()
}

fn copy_tree(source: &Path, destination: &Path) {
    fs::create_dir_all(destination).unwrap();
    for entry in fs::read_dir(source).unwrap() {
        let entry = entry.unwrap();
        let destination_path = destination.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &destination_path);
        } else {
            fs::copy(entry.path(), destination_path).unwrap();
        }
    }
}

fn write_minimal_crate(root: &Path, package_name: &str, source: &str) {
    fs::create_dir_all(root.join("src")).unwrap();
    fs::write(
        root.join("Cargo.toml"),
        format!("[package]\nname='{package_name}'\nversion='0.1.0'\nedition='2024'\n"),
    )
    .unwrap();
    fs::write(
        root.join("Cargo.lock"),
        format!("version = 4\n\n[[package]]\nname = \"{package_name}\"\nversion = \"0.1.0\"\n"),
    )
    .unwrap();
    fs::write(root.join("src/lib.rs"), source).unwrap();
}
