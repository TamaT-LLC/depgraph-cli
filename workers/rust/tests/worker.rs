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
    assert!(validated.edges.values().all(|edge| {
        edge.evidence.iter().all(|evidence| match edge.phase {
            Phase::Source => {
                evidence.kind == EvidenceKind::Source
                    && evidence.extractor == "rust-static"
                    && evidence.extractor_version == ADAPTER_VERSION
            }
            Phase::Semantic => {
                evidence.kind == EvidenceKind::Semantic
                    && evidence.extractor == "rust-analyzer-hir"
                    && evidence.extractor_version == RUST_ANALYZER_CRATE_VERSION
            }
            Phase::Build | Phase::Runtime => false,
        })
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
fn hir_definition_graph_emits_exact_nodes_and_structural_relations() {
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
        "syntax+hir-definitions"
    );
    assert_eq!(
        result.profile.properties["analysis_backend"],
        "static-syntax+rust-analyzer-hir"
    );
    assert_eq!(
        result.profile.properties["rust_hir_status"],
        "definition-graph-emitted"
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
    for edge in &semantic_edges {
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
    assert!(
        !result
            .sites
            .iter()
            .any(|site| matches!(site.kind.as_str(), "call" | "type_use"))
    );
}

#[test]
fn hir_definition_graph_is_repeatable_and_checkout_independent() {
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
    assert_eq!(semantic_nodes(&first), semantic_nodes(&repeated));
    assert_eq!(semantic_edges(&first), semantic_edges(&repeated));
    assert_eq!(semantic_nodes(&first), semantic_nodes(&second));
    assert_eq!(semantic_edges(&first), semantic_edges(&second));
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
        "definition-graph-partial"
    );
    assert_eq!(profile.properties["rust_hir_semantic_issue_count"], 2);
    assert_eq!(
        validated
            .diagnostics
            .values()
            .filter(|diagnostic| diagnostic.code == "RUST_HIR_SOURCE_CONTEXT_AMBIGUOUS")
            .count(),
        2
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
        "definition-graph-partial"
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
        "definition-graph-partial"
    );
}

#[test]
fn ambiguous_locals_and_anonymous_bodies_are_skipped_without_losing_the_delta() {
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
                Some("closure_input" | "inside_closure" | "signature_local" | "signature_fn_local")
            )
    }));
    assert!(
        !result.nodes.iter().any(|node| {
            node.kind == "type" && node.properties["type_kind"] == "generic_instance"
        })
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
        "definition-graph-partial"
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
        "import-call-and-release-gates-pending"
    );
    assert_eq!(
        result.profile.properties["rust_hir_backend"],
        "rust-analyzer-hir"
    );
    assert!(matches!(
        result.profile.properties["rust_hir_status"].as_str(),
        Some("definition-graph-emitted" | "definition-graph-partial")
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
        assert_eq!(first.properties["analysis"], "syntax+hir-definitions");
        assert_eq!(
            first.properties["analysis_backend"],
            "static-syntax+rust-analyzer-hir"
        );
        assert_eq!(first.properties["rust_hir_backend"], "rust-analyzer-hir");
        assert!(matches!(
            first.properties["rust_hir_status"].as_str(),
            Some("definition-graph-emitted" | "definition-graph-partial")
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
            "import-call-and-release-gates-pending"
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
    let module_path_for_site = |specifier: &str, evidence_path: &str| {
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
        result
            .nodes
            .iter()
            .find(|node| node.id == site.target_ids[0])
            .and_then(|node| node.properties["canonical_module_path"].as_str())
            .unwrap()
            .to_owned()
    };
    assert_eq!(
        module_path_for_site("self::common::Left", "src/left.rs"),
        "left::common"
    );
    assert_eq!(
        module_path_for_site("self::common::Right", "src/right.rs"),
        "right::common"
    );
    assert_eq!(
        module_path_for_site("super::common::Left", "src/left.rs"),
        "left::common"
    );
    assert_eq!(
        module_path_for_site("crate::left::common::Left", "src/lib.rs"),
        "left::common"
    );
    assert_eq!(
        module_path_for_site("crate::right::common::Right", "src/lib.rs"),
        "right::common"
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
fn graph_ids_are_independent_of_checkout_and_metadata_fallback() {
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
