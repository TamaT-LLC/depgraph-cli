use std::path::Path;

use anyhow::Result;
use depgraph_core::service::{
    DependenciesRequest, DependencyDirection, DepgraphCapabilitySet, DepgraphService,
    DepgraphServiceConfig, DepgraphServiceError, DepgraphServiceLimits, ExplainPathRequest,
};
use depgraph_core::{CancellationToken, GraphQueryFilter};
use depgraph_store::Store;
use serde_json::json;

fn service(root: &Path, store_path: &Path) -> Result<DepgraphService> {
    Ok(DepgraphService::new(DepgraphServiceConfig::new(
        root,
        store_path,
        DepgraphCapabilitySet::read_only(),
        DepgraphServiceLimits::default(),
    )?))
}

fn seed_graph(store: &mut Store, root: &Path, scan_id: &str, revision: &str) -> Result<String> {
    store.start_scan_with_revision(scan_id, root, false, Some(revision))?;
    let coverage = json!({
        "profiles": 2,
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
    let mut events = Vec::new();
    let mut started = common("scan_started", 1);
    started["root"] = json!(root);
    started["project_code_executed"] = json!(false);
    started["safe_mode"] = json!(true);
    events.push(started);
    for (offset, profile_id) in ["fixture:alpha", "fixture:beta"].into_iter().enumerate() {
        let mut profile = common("profile_declared", offset as u64 + 2);
        profile["profile"] = json!({
            "id": profile_id,
            "language": "fixture",
            "features": [],
            "environment": {},
            "properties": {}
        });
        events.push(profile);
    }
    for (offset, id) in ["node:e", "node:d", "node:c", "node:b", "node:a"]
        .into_iter()
        .enumerate()
    {
        let name = id.trim_start_matches("node:");
        let mut node = common("node_upsert", offset as u64 + 4);
        node["node"] = json!({
            "id": id,
            "kind": "module",
            "locator": format!("repo://src/{name}.rs"),
            "display_name": format!("fixture::{name}"),
            "properties": {
                "path": format!("src/{name}.rs"),
                "private": root.join("must-not-leak")
            }
        });
        events.push(node);
    }
    for (offset, (id, source, target, phase, profile)) in [
        ("edge:z", "node:a", "node:c", "semantic", "fixture:beta"),
        ("edge:d", "node:b", "node:d", "source", "fixture:alpha"),
        ("edge:c", "node:c", "node:d", "semantic", "fixture:beta"),
        ("edge:b", "node:a", "node:b", "source", "fixture:alpha"),
        ("edge:a", "node:e", "node:a", "source", "fixture:alpha"),
    ]
    .into_iter()
    .enumerate()
    {
        let mut edge = common("edge_upsert", offset as u64 + 9);
        edge["edge"] = json!({
            "id": id,
            "source": source,
            "target": target,
            "kind": "imports",
            "phase": phase,
            "environment": "host",
            "profile_id": profile,
            "resolution_status": "resolved",
            "precision": "exact",
            "condition": {"op": "all", "conditions": []},
            "generated": false,
            "evidence": [{
                "kind": phase,
                "extractor": "fixture",
                "extractor_version": "1.0",
                "path": root.join(format!("private-{id}.rs")),
                "start_line": 1,
                "start_column": 1,
                "end_line": 1,
                "end_column": 2,
                "properties": {"secret": "must-not-leak"}
            }]
        });
        events.push(edge);
    }
    for (offset, profile_id) in ["fixture:alpha", "fixture:beta"].into_iter().enumerate() {
        let mut completed = common("profile_completed", offset as u64 + 14);
        completed["profile_id"] = json!(profile_id);
        let mut profile_coverage = coverage.clone();
        profile_coverage["profiles"] = json!(1);
        completed["coverage"] = profile_coverage;
        events.push(completed);
    }
    let mut completed = common("scan_completed", 16);
    completed["coverage"] = coverage;
    events.push(completed);
    for event in events {
        store.ingest_event(&event)?;
    }
    store.finish_scan(scan_id, "completed", None, true)?;
    Ok(store
        .current_snapshot_id()?
        .expect("completed graph snapshot is promoted"))
}

#[test]
fn dependencies_own_legacy_direction_transitivity_filters_and_canonical_order() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("repository");
    let store_path = temporary.path().join("cache/graph.db");
    std::fs::create_dir_all(&root)?;
    let mut writer = Store::open(&store_path)?;
    let snapshot_id = seed_graph(&mut writer, &root, "graph-one", "revision-one")?;
    writer.create_snapshot_name("baseline", &snapshot_id)?;
    let service = service(&root, &store_path)?;
    let cancellation = CancellationToken::new();

    let mut snapshot = service.start_snapshot_request("baseline")?;
    let direct = service.dependencies(
        &mut snapshot,
        &DependenciesRequest::try_new(
            "id:node:a",
            DependencyDirection::Outgoing,
            false,
            GraphQueryFilter::default(),
            100,
        )?,
        &cancellation,
    )?;
    assert!(direct.complete());
    assert_eq!(direct.snapshot_id().as_str(), snapshot_id);
    assert_eq!(direct.traversal().root.id, "node:a");
    assert_eq!(
        direct
            .items()
            .iter()
            .map(|item| item.step.edge.id.as_str())
            .collect::<Vec<_>>(),
        ["edge:b", "edge:z"]
    );

    let transitive = service.dependencies(
        &mut snapshot,
        &DependenciesRequest::try_new(
            "id:node:a",
            DependencyDirection::Outgoing,
            true,
            GraphQueryFilter::new(
                vec!["source".to_owned()],
                vec!["fixture:alpha".to_owned()],
                Vec::new(),
                Vec::new(),
            )?,
            100,
        )?,
        &cancellation,
    )?;
    assert_eq!(
        transitive
            .items()
            .iter()
            .map(|item| item.step.edge.id.as_str())
            .collect::<Vec<_>>(),
        ["edge:b", "edge:d"]
    );

    let incoming = service.dependencies(
        &mut snapshot,
        &DependenciesRequest::try_new(
            "id:node:d",
            DependencyDirection::Incoming,
            false,
            GraphQueryFilter::default(),
            100,
        )?,
        &cancellation,
    )?;
    assert_eq!(
        incoming
            .items()
            .iter()
            .map(|item| item.step.edge.id.as_str())
            .collect::<Vec<_>>(),
        ["edge:c", "edge:d"]
    );
    Ok(())
}

#[test]
fn dependencies_are_bounded_and_keep_the_request_snapshot_pinned() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("repository");
    let store_path = temporary.path().join("cache/graph.db");
    std::fs::create_dir_all(&root)?;
    let mut writer = Store::open(&store_path)?;
    let first_id = seed_graph(&mut writer, &root, "graph-one", "revision-one")?;
    let service = service(&root, &store_path)?;
    let mut snapshot = service.start_snapshot_request("current")?;

    let second_id = seed_graph(&mut writer, &root, "graph-two", "revision-two")?;
    assert_ne!(first_id, second_id);
    let bounded = service.dependencies(
        &mut snapshot,
        &DependenciesRequest::try_new(
            "id:node:a",
            DependencyDirection::Outgoing,
            true,
            GraphQueryFilter::default(),
            1,
        )?,
        &CancellationToken::new(),
    )?;
    assert_eq!(bounded.snapshot_id().as_str(), first_id);
    assert!(!bounded.complete());
    assert_eq!(bounded.traversed_edges(), 1);
    assert_eq!(bounded.items().len(), 1);

    let pinned_path = service.explain_path(
        &mut snapshot,
        &ExplainPathRequest::try_new("id:node:a", "id:node:d", GraphQueryFilter::default(), 100)?,
        &CancellationToken::new(),
    )?;
    assert_eq!(pinned_path.snapshot_id().as_str(), first_id);
    assert!(pinned_path.path().path_found);
    assert_eq!(
        pinned_path
            .path()
            .steps
            .iter()
            .map(|step| step.edge.id.as_str())
            .collect::<Vec<_>>(),
        ["edge:b", "edge:d"]
    );
    Ok(())
}

#[test]
fn explain_path_is_canonical_and_never_reports_false_after_exhaustion() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("repository");
    let store_path = temporary.path().join("cache/graph.db");
    std::fs::create_dir_all(&root)?;
    let mut writer = Store::open(&store_path)?;
    seed_graph(&mut writer, &root, "graph-one", "revision-one")?;
    let service = service(&root, &store_path)?;
    let mut snapshot = service.start_snapshot_request("current")?;
    let cancellation = CancellationToken::new();

    let found = service.explain_path(
        &mut snapshot,
        &ExplainPathRequest::try_new("id:node:a", "id:node:d", GraphQueryFilter::default(), 100)?,
        &cancellation,
    )?;
    assert!(found.path().path_found);
    assert_eq!(
        found
            .path()
            .steps
            .iter()
            .map(|step| step.edge.id.as_str())
            .collect::<Vec<_>>(),
        ["edge:b", "edge:d"]
    );

    let exhausted = service
        .explain_path(
            &mut snapshot,
            &ExplainPathRequest::try_new("id:node:a", "id:node:e", GraphQueryFilter::default(), 1)?,
            &cancellation,
        )
        .unwrap_err();
    assert!(matches!(exhausted, DepgraphServiceError::ResourceExhausted));

    let unreachable = service.explain_path(
        &mut snapshot,
        &ExplainPathRequest::try_new("id:node:d", "id:node:e", GraphQueryFilter::default(), 100)?,
        &cancellation,
    )?;
    assert!(!unreachable.path().path_found);
    assert!(unreachable.path().steps.is_empty());
    Ok(())
}
