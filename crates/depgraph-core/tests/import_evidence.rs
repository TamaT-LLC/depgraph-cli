//! Issue #544: import evidence projection (specifier and imported binding).

use std::path::Path;

use anyhow::Result;
use depgraph_core::CancellationToken;
use depgraph_core::import_evidence::{
    ImportBindingKind, ImportSiteHint, MAX_IMPORT_NAME_BYTES, MAX_IMPORT_SPECIFIER_BYTES,
    project_import_evidence,
};
use depgraph_core::service::{
    DepgraphCapabilitySet, DepgraphService, DepgraphServiceConfig, DepgraphServiceLimits,
    EdgeDirection, SnapshotLocator,
};
use depgraph_store::Store;
use serde_json::{Value, json};

fn ts_semantic_properties(occurrence_kind: &str) -> Value {
    json!({
        "backend": "typescript-native-compiler",
        "compiler_source": "bundled",
        "compiler_version": "7.0.2",
        "analysis_mode": "semantic-import-type-call-graph",
        "profile_id": "web:default",
        "project_code_executed": false,
        "occurrence_kind": occurrence_kind,
        "target_basis": "typechecker",
        "type_only": false,
        "module_specifier": "@/lib/foo",
        "imported_name": "fooHelper"
    })
}

#[test]
fn typescript_named_import_projects_specifier_binding_and_imported_name() {
    let import = project_import_evidence(&ts_semantic_properties("named_import"), None)
        .expect("TypeScript named import has import evidence");
    assert_eq!(import.specifier(), "@/lib/foo");
    assert_eq!(import.binding_kind(), Some(ImportBindingKind::Named));
    assert_eq!(import.imported_name(), Some("fooHelper"));
    assert_eq!(import.local_name(), None);
    assert!(!import.type_only());
}

#[test]
fn typescript_occurrence_kinds_map_to_the_closed_binding_kinds() {
    for (occurrence, expected) in [
        ("default_import", ImportBindingKind::Default),
        ("named_import", ImportBindingKind::Named),
        ("namespace_import", ImportBindingKind::Namespace),
        ("import_equals", ImportBindingKind::ImportEquals),
        ("side_effect_import", ImportBindingKind::SideEffect),
        ("require_call", ImportBindingKind::Require),
        ("dynamic_import", ImportBindingKind::Dynamic),
        ("import_type", ImportBindingKind::ImportType),
        ("named_reexport", ImportBindingKind::NamedReexport),
        ("namespace_reexport", ImportBindingKind::NamespaceReexport),
        ("export_star", ImportBindingKind::ExportStar),
    ] {
        let import = project_import_evidence(&ts_semantic_properties(occurrence), None)
            .unwrap_or_else(|| panic!("{occurrence} is an import occurrence"));
        assert_eq!(import.binding_kind(), Some(expected), "{occurrence}");
    }
    for not_import in [
        "type_reference",
        "type_query",
        "call_expression",
        "heritage_type",
    ] {
        assert!(
            project_import_evidence(&ts_semantic_properties(not_import), None).is_none(),
            "{not_import} is not import evidence"
        );
    }
}

#[test]
fn typescript_type_only_flag_is_carried() {
    let mut properties = ts_semantic_properties("named_import");
    properties["type_only"] = json!(true);
    let import = project_import_evidence(&properties, None).expect("type-only import");
    assert!(import.type_only());
}

#[test]
fn typescript_supporting_syntax_evidence_uses_the_site_specifier() {
    let properties = json!({"profile_id": "web:default", "occurrence_kind": "default_import"});
    let import = project_import_evidence(
        &properties,
        Some(ImportSiteHint::new(
            "web_import",
            Some("./components/Button"),
        )),
    )
    .expect("supporting evidence borrows the site specifier");
    assert_eq!(import.specifier(), "./components/Button");
    assert_eq!(import.binding_kind(), Some(ImportBindingKind::Default));
    assert_eq!(import.imported_name(), None);
    assert!(project_import_evidence(&properties, None).is_none());
}

#[test]
fn rust_use_projects_target_path_last_segment_and_alias() {
    let properties = json!({
        "target_specifier": "crate::domain::Named",
        "glob": false,
        "reexport": false,
        "namespaces": ["types"],
        "alias": "NameContract"
    });
    let import = project_import_evidence(&properties, None).expect("Rust use");
    assert_eq!(import.specifier(), "crate::domain::Named");
    assert_eq!(import.binding_kind(), Some(ImportBindingKind::Named));
    assert_eq!(import.imported_name(), Some("Named"));
    assert_eq!(import.local_name(), Some("NameContract"));

    let glob = json!({"target_specifier": "crate::prelude", "glob": true, "reexport": true, "namespaces": []});
    let import = project_import_evidence(&glob, None).expect("Rust glob re-export");
    assert_eq!(import.binding_kind(), Some(ImportBindingKind::GlobReexport));
    assert_eq!(import.imported_name(), None);

    let glob = json!({"target_specifier": "crate::prelude", "glob": true, "reexport": false, "namespaces": []});
    assert_eq!(
        project_import_evidence(&glob, None).and_then(|import| import.binding_kind()),
        Some(ImportBindingKind::Glob)
    );

    let reexport = json!({"target_specifier": "self::child::Item", "glob": false, "reexport": true, "namespaces": []});
    let import = project_import_evidence(&reexport, None).expect("Rust named re-export");
    assert_eq!(
        import.binding_kind(),
        Some(ImportBindingKind::NamedReexport)
    );
    assert_eq!(import.imported_name(), Some("Item"));

    let extern_crate = json!({"target_specifier": "serde", "alias": "serde_crate"});
    let import = project_import_evidence(&extern_crate, None).expect("extern crate");
    assert_eq!(import.specifier(), "serde");
    assert_eq!(import.binding_kind(), Some(ImportBindingKind::ExternCrate));
    assert_eq!(import.imported_name(), None);
    assert_eq!(import.local_name(), Some("serde_crate"));
}

#[test]
fn site_specifier_only_fallback_covers_syntax_and_go_import_sites() {
    let empty = json!({});
    let go = project_import_evidence(
        &empty,
        Some(ImportSiteHint::new("import", Some("example.com/pkg/util"))),
    )
    .expect("Go import site");
    assert_eq!(go.specifier(), "example.com/pkg/util");
    assert_eq!(go.binding_kind(), None);
    assert_eq!(go.imported_name(), None);

    for (kind, expected, type_only) in [
        (
            "side_effect_import",
            Some(ImportBindingKind::SideEffect),
            false,
        ),
        ("dynamic_import", Some(ImportBindingKind::Dynamic), false),
        ("require", Some(ImportBindingKind::Require), false),
        ("type_import", None, true),
        (
            "type_import_equals",
            Some(ImportBindingKind::ImportEquals),
            true,
        ),
        ("reexport", Some(ImportBindingKind::Reexport), false),
        ("type_reexport", Some(ImportBindingKind::Reexport), true),
    ] {
        let import = project_import_evidence(&empty, Some(ImportSiteHint::new(kind, Some("./x"))))
            .unwrap_or_else(|| panic!("{kind} is an import-like site"));
        assert_eq!(import.binding_kind(), expected, "{kind}");
        assert_eq!(import.type_only(), type_only, "{kind}");
    }

    for kind in [
        "embed",
        "call",
        "cgo_import",
        "type_use",
        "rust_use",
        "extern_crate",
    ] {
        assert!(
            project_import_evidence(&empty, Some(ImportSiteHint::new(kind, Some("x")))).is_none(),
            "{kind} has no site-only import evidence"
        );
    }
    assert!(project_import_evidence(&empty, Some(ImportSiteHint::new("import", None))).is_none());
    assert!(project_import_evidence(&empty, None).is_none());
}

#[test]
fn oversized_control_and_credential_shaped_values_are_omitted() {
    let mut oversized = ts_semantic_properties("named_import");
    oversized["module_specifier"] = json!("a".repeat(MAX_IMPORT_SPECIFIER_BYTES + 1));
    assert!(project_import_evidence(&oversized, None).is_none());

    let mut at_limit = ts_semantic_properties("named_import");
    at_limit["module_specifier"] = json!("a".repeat(MAX_IMPORT_SPECIFIER_BYTES));
    assert!(project_import_evidence(&at_limit, None).is_some());

    let mut control = ts_semantic_properties("named_import");
    control["module_specifier"] = json!("./a\nb");
    assert!(project_import_evidence(&control, None).is_none());

    let mut empty = ts_semantic_properties("named_import");
    empty["module_specifier"] = json!("");
    assert!(project_import_evidence(&empty, None).is_none());

    let mut credential = ts_semantic_properties("named_import");
    credential["module_specifier"] = json!("https://example.test/mod.js?token=abc123");
    assert!(project_import_evidence(&credential, None).is_none());

    let mut bearer = ts_semantic_properties("named_import");
    bearer["module_specifier"] = json!("ghp_0123456789abcdef0123456789abcdef");
    assert!(project_import_evidence(&bearer, None).is_none());

    let mut name = ts_semantic_properties("named_import");
    name["imported_name"] = json!("x".repeat(MAX_IMPORT_NAME_BYTES + 1));
    let import = project_import_evidence(&name, None).expect("specifier survives a bad name");
    assert_eq!(import.specifier(), "@/lib/foo");
    assert_eq!(import.imported_name(), None);

    let mut secret_name = ts_semantic_properties("named_import");
    secret_name["imported_name"] = json!("apiKey");
    let import = project_import_evidence(&secret_name, None).expect("specifier survives");
    assert_eq!(import.imported_name(), None);

    let mut non_string = ts_semantic_properties("named_import");
    non_string["module_specifier"] = json!(42);
    assert!(project_import_evidence(&non_string, None).is_none());
}

#[test]
fn arbitrary_properties_are_never_projected() {
    let properties = json!({"secret": "PROCESS_SECRET", "absolute": "/private/root"});
    assert!(project_import_evidence(&properties, None).is_none());
}

fn service(root: &Path, store_path: &Path) -> Result<DepgraphService> {
    Ok(DepgraphService::new(DepgraphServiceConfig::new(
        root,
        store_path,
        DepgraphCapabilitySet::read_only(),
        DepgraphServiceLimits::default(),
    )?))
}

fn evidence(path: &str, line: u64, kind: &str, properties: Value) -> Value {
    json!({
        "kind": kind,
        "extractor": "fixture",
        "extractor_version": "1.0",
        "path": path,
        "start_line": line,
        "start_column": 1,
        "end_line": line,
        "end_column": 20,
        "detail": "PRIVATE_DETAIL",
        "properties": properties
    })
}

fn seed_import_graph(store: &mut Store, root: &Path) -> Result<()> {
    let scan_id = "issue-544";
    store.start_scan_with_revision(scan_id, root, false, Some("revision-544"))?;
    let coverage = json!({
        "profiles": 1,
        "files_discovered": 0,
        "files_analyzed": 0,
        "files_skipped": 0,
        "dependency_sites": 4,
        "resolved": 4,
        "candidates": 0,
        "external": 0,
        "unresolved": 0,
        "unsupported_syntax": 0,
        "project_code_executed": false,
        "completeness": ["syntax-complete"],
        "reasons": []
    });
    let common = |event: &str, seq: u64| {
        json!({
            "event": event,
            "protocol_version": "1.0",
            "scan_id": scan_id,
            "adapter": "fixture",
            "adapter_version": "1.0",
            "seq": seq
        })
    };
    let mut seq = 1;
    let mut next = || {
        seq += 1;
        seq
    };
    let mut started = common("scan_started", 1);
    started["root"] = json!(root);
    started["project_code_executed"] = json!(false);
    started["safe_mode"] = json!(true);
    store.ingest_event(&started)?;
    let mut profile = common("profile_declared", next());
    profile["profile"] = json!({
        "id": "fixture:safe",
        "language": "fixture",
        "features": [],
        "environment": {},
        "properties": {}
    });
    store.ingest_event(&profile)?;
    for (id, path) in [
        ("node:app", "src/app.ts"),
        ("node:foo", "src/lib/foo.ts"),
        ("node:lib", "src/lib.rs"),
        ("node:main", "main.go"),
        ("node:util", "pkg/util/util.go"),
    ] {
        let mut node = common("node_upsert", next());
        node["node"] = json!({
            "id": id,
            "kind": "file",
            "locator": format!("repo://{path}"),
            "display_name": path,
            "properties": {"path": path}
        });
        store.ingest_event(&node)?;
    }
    let sites = [
        (
            "site:ts",
            "node:app",
            "web_import",
            "@/lib/foo",
            "node:foo",
            vec![
                evidence(
                    "src/app.ts",
                    1,
                    "semantic",
                    ts_semantic_properties("named_import"),
                ),
                evidence(
                    "src/app.ts",
                    1,
                    "source",
                    json!({"profile_id": "web:default", "occurrence_kind": "named_import"}),
                ),
            ],
        ),
        (
            "site:rust",
            "node:lib",
            "rust_use",
            "crate::domain::Named as NameContract",
            "node:foo",
            vec![evidence(
                "src/lib.rs",
                2,
                "semantic",
                json!({
                    "target_specifier": "crate::domain::Named",
                    "glob": false,
                    "reexport": false,
                    "namespaces": ["types"],
                    "alias": "NameContract"
                }),
            )],
        ),
        (
            "site:go",
            "node:main",
            "import",
            "example.com/pkg/util",
            "node:util",
            vec![evidence("main.go", 3, "source", json!({}))],
        ),
        (
            "site:embed",
            "node:main",
            "embed",
            "assets/*",
            "node:util",
            vec![evidence("main.go", 4, "source", json!({}))],
        ),
    ];
    for (id, source, kind, specifier, target, site_evidence) in sites {
        let mut site = common("dependency_site", next());
        site["site"] = json!({
            "id": id,
            "source": source,
            "kind": kind,
            "specifier": specifier,
            "resolution_status": "resolved",
            "target_ids": [target],
            "profile_id": "fixture:safe",
            "condition": {"op": "all", "conditions": []},
            "precision": "exact",
            "evidence": site_evidence.clone()
        });
        store.ingest_event(&site)?;
        let mut edge = common("edge_upsert", next());
        edge["edge"] = json!({
            "id": format!("edge:{}", &id[5..]),
            "site_id": id,
            "source": source,
            "target": target,
            "kind": "imports",
            "phase": "semantic",
            "environment": "host",
            "profile_id": "fixture:safe",
            "resolution_status": "resolved",
            "precision": "exact",
            "condition": {"op": "all", "conditions": []},
            "generated": false,
            "evidence": site_evidence
        });
        store.ingest_event(&edge)?;
    }
    let mut completed_profile = common("profile_completed", next());
    completed_profile["profile_id"] = json!("fixture:safe");
    completed_profile["coverage"] = coverage.clone();
    store.ingest_event(&completed_profile)?;
    let mut completed = common("scan_completed", next());
    completed["coverage"] = coverage;
    store.ingest_event(&completed)?;
    store.finish_scan(scan_id, "completed", None, true)?;
    Ok(())
}

#[test]
fn agent_evidence_projections_carry_import_evidence_for_sites_and_edges() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let root = temp.path().join("repo");
    std::fs::create_dir_all(&root)?;
    let store_path = temp.path().join("store.sqlite");
    let mut store = Store::open(&store_path)?;
    seed_import_graph(&mut store, &root)?;
    drop(store);
    let service = service(&root, &store_path)?;
    let cancellation = CancellationToken::new();
    let snapshot = service
        .resolve_snapshot_id_cancellable(&SnapshotLocator::parse("current")?, &cancellation)?;

    let ts = service.list_site_evidence_page(&snapshot, "site:ts", 0, 10, &cancellation)?;
    let imports = ts
        .items()
        .iter()
        .map(|item| item.import().expect("TypeScript evidence has import"))
        .collect::<Vec<_>>();
    assert_eq!(imports.len(), 2);
    assert!(
        imports
            .iter()
            .all(|import| import.specifier() == "@/lib/foo")
    );
    assert!(
        imports
            .iter()
            .all(|import| import.binding_kind() == Some(ImportBindingKind::Named))
    );
    assert!(
        imports
            .iter()
            .any(|import| import.imported_name() == Some("fooHelper"))
    );

    let rust = service.list_site_evidence_page(&snapshot, "site:rust", 0, 10, &cancellation)?;
    let import = rust.items()[0]
        .import()
        .expect("Rust use evidence has import");
    assert_eq!(import.specifier(), "crate::domain::Named");
    assert_eq!(import.local_name(), Some("NameContract"));

    let go = service.list_site_evidence_page(&snapshot, "site:go", 0, 10, &cancellation)?;
    let import = go.items()[0]
        .import()
        .expect("Go import site falls back to specifier");
    assert_eq!(import.specifier(), "example.com/pkg/util");
    assert_eq!(import.binding_kind(), None);

    let embed = service.list_site_evidence_page(&snapshot, "site:embed", 0, 10, &cancellation)?;
    assert!(embed.items()[0].import().is_none());

    let sites = service.list_sites_page(&snapshot, Some("node:main"), 0, 10, &cancellation)?;
    let go_site = sites
        .items()
        .iter()
        .find(|site| site.id() == "site:go")
        .expect("Go site");
    assert_eq!(
        go_site.evidence()[0]
            .import()
            .map(|import| import.specifier()),
        Some("example.com/pkg/util")
    );

    let edges = service.list_edges_page(
        &snapshot,
        "node:main",
        EdgeDirection::Outgoing,
        0,
        10,
        &cancellation,
    )?;
    let go_edge = edges
        .items()
        .iter()
        .find(|edge| edge.id() == "edge:go")
        .expect("Go edge");
    assert_eq!(
        go_edge.evidence()[0]
            .import()
            .map(|import| import.specifier()),
        Some("example.com/pkg/util"),
        "edge evidence uses its site's specifier"
    );
    let embed_edge = edges
        .items()
        .iter()
        .find(|edge| edge.id() == "edge:embed")
        .expect("embed edge");
    assert!(embed_edge.evidence()[0].import().is_none());
    Ok(())
}
