use std::{fs, path::Path, process::Command};

use anyhow::Result;
use depgraph_core::service::{
    CyclesRequest, DEFAULT_STRUCTURAL_EDGE_SELECTION, DependenciesRequest, DependencyDirection,
    DepgraphCapabilitySet, DepgraphResourceLimit, DepgraphService, DepgraphServiceConfig,
    DepgraphServiceError, DepgraphServiceLimits, EdgeKindFilter, ExplainPathRequest, ImpactRequest,
    MAX_CYCLE_NODE_IDS, MAX_DEPENDENCY_EDGE_KIND_BYTES, MAX_DEPENDENCY_EDGE_KINDS,
    MAX_DEPENDENCY_PATH_STEPS, MAX_GRAPH_EVIDENCE_ITEMS, STRUCTURAL_EDGE_KINDS,
    StructuralEdgeSelection, UnresolvedRequest, is_structural_edge_kind,
};
use depgraph_core::{
    CancellationToken, ChangedSetImpactRequest, CycleLevel, GraphQueryFilter, ImpactFilters,
};
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
        "dependency_sites": 1,
        "resolved": 0,
        "candidates": 0,
        "external": 0,
        "unresolved": 1,
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
    for (offset, id) in ["file:cycle-a", "file:cycle-b"].into_iter().enumerate() {
        let name = id.trim_start_matches("file:");
        let mut node = common("node_upsert", offset as u64 + 9);
        node["node"] = json!({
            "id": id,
            "kind": "file",
            "locator": format!("repo://src/{name}.rs"),
            "display_name": name,
            "properties": {"path": format!("src/{name}.rs")}
        });
        events.push(node);
    }
    let mut unknown = common("node_upsert", 11);
    unknown["node"] = json!({
        "id": "unknown:missing",
        "kind": "unknown_target",
        "locator": "id:unknown:missing",
        "display_name": "fixture:missing",
        "properties": {}
    });
    events.push(unknown);
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
        let mut edge = common("edge_upsert", offset as u64 + 12);
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
    for (offset, (id, source, target)) in [
        ("edge:cycle-a", "file:cycle-a", "file:cycle-b"),
        ("edge:cycle-b", "file:cycle-b", "file:cycle-a"),
    ]
    .into_iter()
    .enumerate()
    {
        let mut edge = common("edge_upsert", offset as u64 + 17);
        edge["edge"] = json!({
            "id": id,
            "source": source,
            "target": target,
            "kind": "imports",
            "phase": "source",
            "environment": "host",
            "profile_id": "fixture:alpha",
            "resolution_status": "resolved",
            "precision": "exact",
            "condition": {"op": "all", "conditions": []},
            "generated": false
        });
        events.push(edge);
    }
    let mut site = common("dependency_site", 19);
    site["site"] = json!({
        "id": "site:unresolved",
        "source": "node:e",
        "kind": "import",
        "specifier": "fixture:missing",
        "resolution_status": "unresolved",
        "target_ids": ["unknown:missing"],
        "profile_id": "fixture:alpha",
        "condition": {"op": "all", "conditions": []},
        "precision": "exact",
        "reason": "package_not_found"
    });
    events.push(site);
    let mut unresolved_edge = common("edge_upsert", 20);
    unresolved_edge["edge"] = json!({
        "id": "edge:unresolved",
        "site_id": "site:unresolved",
        "source": "node:e",
        "target": "unknown:missing",
        "kind": "imports",
        "phase": "source",
        "environment": "host",
        "profile_id": "fixture:alpha",
        "resolution_status": "unresolved",
        "precision": "exact",
        "condition": {"op": "all", "conditions": []},
        "generated": false
    });
    events.push(unresolved_edge);
    for (offset, profile_id) in ["fixture:alpha", "fixture:beta"].into_iter().enumerate() {
        let mut completed = common("profile_completed", offset as u64 + 21);
        completed["profile_id"] = json!(profile_id);
        let mut profile_coverage = coverage.clone();
        profile_coverage["profiles"] = json!(1);
        if profile_id == "fixture:beta" {
            profile_coverage["dependency_sites"] = json!(0);
            profile_coverage["unresolved"] = json!(0);
        }
        completed["coverage"] = profile_coverage;
        events.push(completed);
    }
    let mut completed = common("scan_completed", 23);
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

fn seed_edge_graph(
    store: &mut Store,
    root: &Path,
    scan_id: &str,
    revision: &str,
    nodes: &[(String, String, Option<String>)],
    edges: &[(String, String, String)],
    edge_evidence_count: usize,
) -> Result<String> {
    store.start_scan_with_revision(scan_id, root, false, Some(revision))?;
    let coverage = json!({
        "profiles": 1,
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
            "adapter": "bounded-graph-fixture",
            "adapter_version": "1.0",
            "seq": seq
        })
    };
    let mut seq = 1_u64;
    let mut started = common("scan_started", seq);
    started["root"] = json!(root);
    started["project_code_executed"] = json!(false);
    started["safe_mode"] = json!(true);
    store.ingest_event(&started)?;
    seq += 1;
    let mut profile = common("profile_declared", seq);
    profile["profile"] = json!({
        "id": "fixture:bounded",
        "language": "fixture",
        "features": [],
        "environment": {},
        "properties": {}
    });
    store.ingest_event(&profile)?;
    for (id, kind, path) in nodes {
        seq += 1;
        let mut node = common("node_upsert", seq);
        node["node"] = json!({
            "id": id,
            "kind": kind,
            "locator": format!("id:{id}"),
            "display_name": id,
            "properties": path.as_ref().map_or_else(
                || json!({}),
                |path| json!({"path": path})
            )
        });
        store.ingest_event(&node)?;
    }
    for (id, source, target) in edges {
        seq += 1;
        let mut edge = common("edge_upsert", seq);
        edge["edge"] = json!({
            "id": id,
            "source": source,
            "target": target,
            "kind": "imports",
            "phase": "source",
            "environment": "host",
            "profile_id": "fixture:bounded",
            "resolution_status": "resolved",
            "precision": "exact",
            "condition": {"op": "all", "conditions": []},
            "generated": false
        });
        if edge_evidence_count > 0 {
            edge["edge"]["evidence"] = json!(
                (0..edge_evidence_count)
                    .map(|ordinal| json!({
                        "kind": "source",
                        "extractor": "bounded-graph-fixture",
                        "extractor_version": "1.0",
                        "path": "src/evidence.rs",
                        "start_line": ordinal + 1,
                        "start_column": 1,
                        "end_line": ordinal + 1,
                        "end_column": 2,
                        "properties": {}
                    }))
                    .collect::<Vec<_>>()
            );
        }
        store.ingest_event(&edge)?;
    }
    seq += 1;
    let mut profile_completed = common("profile_completed", seq);
    profile_completed["profile_id"] = json!("fixture:bounded");
    profile_completed["coverage"] = coverage.clone();
    store.ingest_event(&profile_completed)?;
    seq += 1;
    let mut completed = common("scan_completed", seq);
    completed["coverage"] = coverage;
    store.ingest_event(&completed)?;
    store.finish_scan(scan_id, "completed", None, true)?;
    Ok(store
        .current_snapshot_id()?
        .expect("completed bounded graph snapshot is promoted"))
}

fn run_git(root: &Path, arguments: &[&str]) -> std::process::Output {
    Command::new("git")
        .arg("-C")
        .arg(root)
        .args(arguments)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .expect("run Git fixture command")
}

fn assert_git_success(root: &Path, arguments: &[&str]) -> String {
    let output = run_git(root, arguments);
    assert!(
        output.status.success(),
        "git {arguments:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .expect("Git fixture output is UTF-8")
        .trim()
        .to_owned()
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
    );
    assert!(matches!(
        bounded,
        Err(DepgraphServiceError::ResourceLimitExceeded {
            limit: DepgraphResourceLimit::MaxTraversal,
            maximum: 1,
            observed: Some(1),
        })
    ));
    let bounded_dependents = service.dependencies(
        &mut snapshot,
        &DependenciesRequest::try_new(
            "id:node:d",
            DependencyDirection::Incoming,
            true,
            GraphQueryFilter::default(),
            1,
        )?,
        &CancellationToken::new(),
    );
    assert!(matches!(
        bounded_dependents,
        Err(DepgraphServiceError::ResourceLimitExceeded {
            limit: DepgraphResourceLimit::MaxTraversal,
            maximum: 1,
            observed: Some(1),
        })
    ));

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
fn dependency_evidence_cap_is_enforced_at_the_shared_service_boundary() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("repository");
    let store_path = temporary.path().join("cache/graph.db");
    fs::create_dir_all(&root)?;
    let nodes = vec![
        ("evidence:source".to_owned(), "module".to_owned(), None),
        ("evidence:target".to_owned(), "module".to_owned(), None),
    ];
    let edges = vec![(
        "evidence:edge".to_owned(),
        "evidence:source".to_owned(),
        "evidence:target".to_owned(),
    )];
    let mut writer = Store::open(&store_path)?;
    seed_edge_graph(
        &mut writer,
        &root,
        "evidence-at-limit",
        "revision-evidence-at-limit",
        &nodes,
        &edges,
        MAX_GRAPH_EVIDENCE_ITEMS,
    )?;
    drop(writer);
    let graph_service = service(&root, &store_path)?;
    let request = DependenciesRequest::try_new(
        "id:evidence:source",
        DependencyDirection::Outgoing,
        false,
        GraphQueryFilter::default(),
        100,
    )?;
    let mut snapshot = graph_service.start_snapshot_request("current")?;
    let exact = graph_service.dependencies(&mut snapshot, &request, &CancellationToken::new())?;
    assert_eq!(exact.items().len(), 1);
    assert_eq!(
        exact.items()[0].step.evidence.len(),
        MAX_GRAPH_EVIDENCE_ITEMS
    );
    drop(snapshot);

    let mut writer = Store::open(&store_path)?;
    seed_edge_graph(
        &mut writer,
        &root,
        "evidence-over-limit",
        "revision-evidence-over-limit",
        &nodes,
        &edges,
        MAX_GRAPH_EVIDENCE_ITEMS + 1,
    )?;
    drop(writer);
    let mut snapshot = graph_service.start_snapshot_request("current")?;
    assert!(matches!(
        graph_service.dependencies(&mut snapshot, &request, &CancellationToken::new()),
        Err(DepgraphServiceError::ResourceExhausted)
    ));
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
    // max_traversal bounds the edges the search visits, and the error names
    // that bound and the visits made when it stopped (Issue #565).
    assert!(matches!(
        exhausted,
        DepgraphServiceError::ResourceLimitExceeded {
            limit: DepgraphResourceLimit::MaxTraversal,
            maximum: 1,
            observed: Some(1),
        }
    ));

    let unreachable = service.explain_path(
        &mut snapshot,
        &ExplainPathRequest::try_new("id:node:d", "id:node:e", GraphQueryFilter::default(), 100)?,
        &cancellation,
    )?;
    assert!(!unreachable.path().path_found);
    assert!(unreachable.path().steps.is_empty());
    Ok(())
}

#[test]
fn dependency_and_path_requests_enforce_the_canonical_traversal_maximum() -> Result<()> {
    let maximum = depgraph_core::MAX_INTERACTIVE_QUERY_TRAVERSAL;
    assert!(
        DependenciesRequest::try_new(
            "id:node:a",
            DependencyDirection::Outgoing,
            true,
            GraphQueryFilter::default(),
            maximum,
        )
        .is_ok()
    );
    assert!(
        ExplainPathRequest::try_new(
            "id:node:a",
            "id:node:b",
            GraphQueryFilter::default(),
            maximum,
        )
        .is_ok()
    );

    let over_maximum = maximum + 1;
    assert!(matches!(
        DependenciesRequest::try_new(
            "id:node:a",
            DependencyDirection::Outgoing,
            true,
            GraphQueryFilter::default(),
            over_maximum,
        ),
        Err(DepgraphServiceError::ArgumentOutOfRange {
            argument: "max_traversal",
            minimum: 1,
            maximum: 1_000_000,
        })
    ));
    assert!(matches!(
        ExplainPathRequest::try_new(
            "id:node:a",
            "id:node:b",
            GraphQueryFilter::default(),
            over_maximum,
        ),
        Err(DepgraphServiceError::ArgumentOutOfRange {
            argument: "max_traversal",
            minimum: 1,
            maximum: 1_000_000,
        })
    ));
    Ok(())
}

#[test]
fn impact_dependency_paths_accept_1000_steps_and_reject_1001_without_partial_success() -> Result<()>
{
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("repository");
    let store_path = temporary.path().join("cache/graph.db");
    fs::create_dir_all(root.join("changed"))?;
    assert_git_success(&root, &["init", "--quiet"]);
    assert_git_success(&root, &["config", "user.email", "test@example.invalid"]);
    assert_git_success(&root, &["config", "user.name", "Test"]);
    assert_git_success(&root, &["commit", "--quiet", "--allow-empty", "-m", "base"]);
    let base = assert_git_success(&root, &["rev-parse", "HEAD"]);
    fs::write(root.join("changed/dependency.rs"), "pub fn changed() {}\n")?;
    assert_git_success(&root, &["add", "changed/dependency.rs"]);
    assert_git_success(&root, &["commit", "--quiet", "-m", "changed"]);
    let head = assert_git_success(&root, &["rev-parse", "HEAD"]);

    let chain = |steps: usize| {
        let nodes = (0..=steps)
            .map(|index| {
                (
                    format!("chain:{index:04}"),
                    "module".to_owned(),
                    (index == steps).then(|| "changed/dependency.rs".to_owned()),
                )
            })
            .collect::<Vec<_>>();
        let edges = (0..steps)
            .map(|index| {
                (
                    format!("chain-edge:{index:04}"),
                    format!("chain:{index:04}"),
                    format!("chain:{:04}", index + 1),
                )
            })
            .collect::<Vec<_>>();
        (nodes, edges)
    };

    let (nodes, edges) = chain(MAX_DEPENDENCY_PATH_STEPS);
    let mut writer = Store::open(&store_path)?;
    seed_edge_graph(
        &mut writer,
        &root,
        "path-at-limit",
        &head,
        &nodes,
        &edges,
        0,
    )?;
    drop(writer);
    let graph_service = service(&root, &store_path)?;
    let request = ImpactRequest::try_new(
        "id:chain:0000",
        Some(base.clone()),
        ImpactFilters::new(None, Vec::new(), Vec::new(), nodes.len(), edges.len())?,
    )?;
    let mut snapshot = graph_service.start_snapshot_request("current")?;
    let at_limit = graph_service.impact(&mut snapshot, &request, &CancellationToken::new())?;
    assert!(at_limit.impact().complete);
    assert_eq!(at_limit.impact().impacts.len(), 1);
    assert_eq!(
        at_limit.impact().impacts[0].dependency_path.len(),
        MAX_DEPENDENCY_PATH_STEPS
    );
    drop(snapshot);

    let over_limit_steps = MAX_DEPENDENCY_PATH_STEPS + 1;
    let (nodes, edges) = chain(over_limit_steps);
    let mut writer = Store::open(&store_path)?;
    seed_edge_graph(
        &mut writer,
        &root,
        "path-over-limit",
        &head,
        &nodes,
        &edges,
        0,
    )?;
    drop(writer);
    let request = ImpactRequest::try_new(
        "id:chain:0000",
        Some(base),
        ImpactFilters::new(None, Vec::new(), Vec::new(), nodes.len(), edges.len())?,
    )?;
    let mut snapshot = graph_service.start_snapshot_request("current")?;
    assert!(matches!(
        graph_service.impact(&mut snapshot, &request, &CancellationToken::new()),
        Err(DepgraphServiceError::ResourceLimitExceeded {
            limit: DepgraphResourceLimit::ImpactPathSteps,
            maximum: 1_000,
            observed: None,
        })
    ));
    Ok(())
}

#[test]
fn impact_wide_deep_graph_exhausts_cumulative_path_materialization_without_partial_success()
-> Result<()> {
    const DEPTH: usize = 400;
    const WIDTH: usize = 600;

    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("repository");
    let store_path = temporary.path().join("cache/graph.db");
    fs::create_dir_all(&root)?;
    let mut nodes = vec![("impact:root".to_owned(), "module".to_owned(), None)];
    nodes.extend(
        (1..=DEPTH).map(|index| (format!("impact:deep:{index:04}"), "module".to_owned(), None)),
    );
    nodes.extend(
        (0..WIDTH).map(|index| (format!("impact:wide:{index:04}"), "module".to_owned(), None)),
    );
    let mut edges = vec![(
        "impact-edge:deep:0001".to_owned(),
        "impact:deep:0001".to_owned(),
        "impact:root".to_owned(),
    )];
    edges.extend((2..=DEPTH).map(|index| {
        (
            format!("impact-edge:deep:{index:04}"),
            format!("impact:deep:{index:04}"),
            format!("impact:deep:{:04}", index - 1),
        )
    }));
    edges.extend((0..WIDTH).map(|index| {
        (
            format!("impact-edge:wide:{index:04}"),
            format!("impact:wide:{index:04}"),
            format!("impact:deep:{DEPTH:04}"),
        )
    }));
    let mut writer = Store::open(&store_path)?;
    seed_edge_graph(
        &mut writer,
        &root,
        "impact-materialization-budget",
        "revision-budget",
        &nodes,
        &edges,
        0,
    )?;
    drop(writer);

    let graph_service = service(&root, &store_path)?;
    let request = ImpactRequest::try_new(
        "id:impact:root",
        None,
        ImpactFilters::new(None, Vec::new(), Vec::new(), nodes.len(), edges.len())?,
    )?;
    let mut snapshot = graph_service.start_snapshot_request("current")?;
    assert!(matches!(
        graph_service.impact(&mut snapshot, &request, &CancellationToken::new()),
        Err(DepgraphServiceError::ResourceLimitExceeded {
            limit: DepgraphResourceLimit::ImpactPathSteps,
            maximum: 50_000,
            observed: None,
        })
    ));
    Ok(())
}

#[test]
fn cycle_representation_accepts_1000_ids_and_rejects_1001_without_partial_success() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("repository");
    let store_path = temporary.path().join("cache/graph.db");
    fs::create_dir_all(&root)?;
    let ring = |returned_ids: usize| {
        let unique_nodes = returned_ids - 1;
        let nodes = (0..unique_nodes)
            .map(|index| (format!("cycle:{index:04}"), "file".to_owned(), None))
            .collect::<Vec<_>>();
        let edges = (0..unique_nodes)
            .map(|index| {
                (
                    format!("cycle-edge:{index:04}"),
                    format!("cycle:{index:04}"),
                    format!("cycle:{:04}", (index + 1) % unique_nodes),
                )
            })
            .collect::<Vec<_>>();
        (nodes, edges)
    };

    let (nodes, edges) = ring(MAX_CYCLE_NODE_IDS);
    let mut writer = Store::open(&store_path)?;
    seed_edge_graph(
        &mut writer,
        &root,
        "cycle-at-limit",
        "revision-cycle-at-limit",
        &nodes,
        &edges,
        0,
    )?;
    drop(writer);
    let graph_service = service(&root, &store_path)?;
    let mut snapshot = graph_service.start_snapshot_request("current")?;
    let at_limit = graph_service.cycles(
        &mut snapshot,
        &CyclesRequest::try_new(CycleLevel::File, 50_000)?,
        &CancellationToken::new(),
    )?;
    assert_eq!(at_limit.cycles().len(), 1);
    assert_eq!(at_limit.cycles()[0].node_ids.len(), MAX_CYCLE_NODE_IDS);
    assert_eq!(
        at_limit.cycles()[0].node_ids.first(),
        at_limit.cycles()[0].node_ids.last()
    );
    drop(snapshot);

    let (nodes, edges) = ring(MAX_CYCLE_NODE_IDS + 1);
    let mut writer = Store::open(&store_path)?;
    seed_edge_graph(
        &mut writer,
        &root,
        "cycle-over-limit",
        "revision-cycle-over-limit",
        &nodes,
        &edges,
        0,
    )?;
    drop(writer);
    let mut snapshot = graph_service.start_snapshot_request("current")?;
    assert!(matches!(
        graph_service.cycles(
            &mut snapshot,
            &CyclesRequest::try_new(CycleLevel::File, 50_000)?,
            &CancellationToken::new(),
        ),
        Err(DepgraphServiceError::ResourceExhausted)
    ));
    Ok(())
}

#[test]
fn changed_since_service_error_never_discloses_raw_git_stderr() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("repository");
    let store_path = temporary.path().join("cache/graph.db");
    fs::create_dir_all(&root)?;
    assert_git_success(&root, &["init", "--quiet"]);
    assert_git_success(&root, &["config", "user.email", "test@example.invalid"]);
    assert_git_success(&root, &["config", "user.name", "Test"]);
    assert_git_success(&root, &["commit", "--quiet", "--allow-empty", "-m", "head"]);
    let head = assert_git_success(&root, &["rev-parse", "HEAD"]);

    // Inject a hostile absolute path into raw Git stderr via object alternates.
    // Missing-gitdir failures on Git 2.54+ report "(null)" and no longer echo the
    // path, so alternates keep the redaction precondition portable across versions.
    const SECRET_MARKER: &str = "Bearer-review-secret";
    let private_alternate = temporary
        .path()
        .join(format!("private-absolute-{SECRET_MARKER}"))
        .join("objects");
    assert!(private_alternate.is_absolute());
    let alternates = root.join(".git/objects/info/alternates");
    fs::create_dir_all(alternates.parent().unwrap())?;
    fs::write(&alternates, format!("{}\n", private_alternate.display()))?;
    let leaky = run_git(&root, &["cat-file", "-p", "HEAD"]);
    let leaky_stderr = String::from_utf8_lossy(&leaky.stderr);
    assert!(
        leaky_stderr.contains(SECRET_MARKER),
        "precondition: raw Git stderr must mention the hostile alternate path; got {leaky_stderr:?}"
    );
    assert!(
        leaky_stderr.contains(private_alternate.to_string_lossy().as_ref()),
        "precondition: raw Git stderr must mention the absolute alternate path; got {leaky_stderr:?}"
    );

    let private_git = temporary
        .path()
        .join(format!("private-absolute-{SECRET_MARKER}.git"));
    fs::rename(root.join(".git"), &private_git)?;
    fs::write(
        root.join(".git"),
        format!("gitdir: {}\n", private_git.display()),
    )?;
    assert_eq!(assert_git_success(&root, &["rev-parse", "HEAD"]), head);

    let nodes = vec![("git:root".to_owned(), "module".to_owned(), None)];
    let mut writer = Store::open(&store_path)?;
    seed_edge_graph(
        &mut writer,
        &root,
        "git-stderr-redaction",
        &head,
        &nodes,
        &[],
        0,
    )?;
    drop(writer);
    fs::rename(&private_git, temporary.path().join("relocated.git"))?;
    let raw_failure = run_git(&root, &["rev-parse", "--show-prefix"]);
    assert!(
        !raw_failure.status.success(),
        "relocated gitdir must make Git fail; stderr={:?} stdout={:?}",
        String::from_utf8_lossy(&raw_failure.stderr),
        String::from_utf8_lossy(&raw_failure.stdout)
    );

    let graph_service = service(&root, &store_path)?;
    let request = ImpactRequest::try_new(
        "id:git:root",
        Some("HEAD".to_owned()),
        ImpactFilters::new(None, Vec::new(), Vec::new(), 1, 1)?,
    )?;
    let mut snapshot = graph_service.start_snapshot_request("current")?;
    let error = graph_service
        .impact(&mut snapshot, &request, &CancellationToken::new())
        .expect_err("hostile Git failure must fail closed");
    assert!(matches!(error, DepgraphServiceError::GraphQuery { .. }));
    let public_error = format!("{:#}", anyhow::Error::new(error));
    assert!(public_error.contains("read-only Git query failed"));
    let private_alternate = private_alternate.to_string_lossy();
    let private_git = private_git.to_string_lossy();
    let raw_failure_stderr = String::from_utf8_lossy(&raw_failure.stderr);
    for forbidden in [
        leaky_stderr.trim(),
        raw_failure_stderr.trim(),
        SECRET_MARKER,
        private_alternate.as_ref(),
        private_git.as_ref(),
    ] {
        if forbidden.is_empty() {
            continue;
        }
        assert!(
            !public_error.contains(forbidden),
            "service error disclosed hostile Git stderr fragment {forbidden:?}: {public_error}"
        );
    }
    Ok(())
}

#[test]
fn changed_path_count_is_independent_from_the_impact_node_limit() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("repository");
    let store_path = temporary.path().join("cache/graph.db");
    fs::create_dir_all(root.join("changed"))?;
    assert_git_success(&root, &["init", "--quiet"]);
    assert_git_success(&root, &["config", "user.email", "test@example.invalid"]);
    assert_git_success(&root, &["config", "user.name", "Test"]);
    assert_git_success(&root, &["commit", "--quiet", "--allow-empty", "-m", "base"]);
    let base = assert_git_success(&root, &["rev-parse", "HEAD"]);
    let changed_path_count = 5_usize;
    for index in 0..changed_path_count {
        fs::write(
            root.join(format!("changed/{index}.rs")),
            format!("// {index}\n"),
        )?;
    }
    assert_git_success(&root, &["add", "changed"]);
    assert_git_success(&root, &["commit", "--quiet", "-m", "changed paths"]);
    let head = assert_git_success(&root, &["rev-parse", "HEAD"]);

    let nodes = vec![(
        "changed:root".to_owned(),
        "module".to_owned(),
        Some("changed/0.rs".to_owned()),
    )];
    let mut writer = Store::open(&store_path)?;
    seed_edge_graph(
        &mut writer,
        &root,
        "changed-path-count-independent",
        &head,
        &nodes,
        &[],
        0,
    )?;
    drop(writer);

    let graph_service = service(&root, &store_path)?;
    let request = ImpactRequest::try_new(
        "id:changed:root",
        Some(base),
        ImpactFilters::new(None, Vec::new(), Vec::new(), 1, 1)?,
    )?;
    let mut snapshot = graph_service.start_snapshot_request("current")?;
    let result = graph_service.impact(&mut snapshot, &request, &CancellationToken::new())?;
    assert!(result.impact().complete);
    assert_eq!(result.impact().mappings.len(), changed_path_count);
    assert_eq!(result.impact().changed_nodes.len(), 1);
    assert_eq!(result.impact().impacts.len(), 1);
    assert_eq!(result.impact().impacts[0].node.id, "changed:root");
    Ok(())
}

fn init_fixture_repository(root: &Path, files: &[&str]) -> Result<String> {
    fs::create_dir_all(root.join("src"))?;
    assert_git_success(root, &["init", "--quiet"]);
    assert_git_success(root, &["config", "user.email", "test@example.invalid"]);
    assert_git_success(root, &["config", "user.name", "Test"]);
    for file in files {
        fs::write(root.join(file), format!("// {file}\n"))?;
        assert_git_success(root, &["add", file]);
    }
    assert_git_success(root, &["commit", "--quiet", "-m", "base"]);
    Ok(assert_git_success(root, &["rev-parse", "HEAD"]))
}

fn changed_set_impact_fixture(root: &Path, store_path: &Path) -> Result<(String, DepgraphService)> {
    let head = init_fixture_repository(root, &["src/a.rs", "src/b.rs", "src/c.rs"])?;
    let node =
        |id: &str, path: Option<&str>| (id.to_owned(), "file".to_owned(), path.map(str::to_owned));
    let nodes = vec![
        node("a", Some("src/a.rs")),
        node("b", Some("src/b.rs")),
        node("c", Some("src/c.rs")),
        node("x", None),
        node("y", None),
        node("z", None),
    ];
    let edge = |id: &str, source: &str, target: &str| {
        (id.to_owned(), source.to_owned(), target.to_owned())
    };
    let edges = vec![
        edge("x-a", "x", "a"),
        edge("y-b", "y", "b"),
        edge("z-x", "z", "x"),
        edge("z-y", "z", "y"),
        edge("y-c", "y", "c"),
    ];
    let mut writer = Store::open(store_path)?;
    seed_edge_graph(
        &mut writer,
        root,
        "changed-set-impact",
        &head,
        &nodes,
        &edges,
        0,
    )?;
    drop(writer);
    fs::write(root.join("src/a.rs"), "// a changed\n")?;
    fs::write(root.join("src/b.rs"), "// b changed\n")?;
    fs::write(root.join("src/untracked.rs"), "// new\n")?;
    Ok((head, service(root, store_path)?))
}

#[test]
fn changed_set_impact_returns_the_whole_changed_set_in_one_call() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("repository");
    let store_path = temporary.path().join("cache/graph.db");
    let (head, graph_service) = changed_set_impact_fixture(&root, &store_path)?;

    let request = ChangedSetImpactRequest::try_new(
        "HEAD",
        ImpactFilters::new(None, Vec::new(), Vec::new(), 100, 100)?,
    )?;
    let mut snapshot = graph_service.start_snapshot_request("current")?;
    let result =
        graph_service.impact_changed_set(&mut snapshot, &request, &CancellationToken::new())?;
    let impact = result.impact();
    assert_eq!(result.scan_id(), "changed-set-impact");
    assert_eq!(impact.mode, "changed_set");
    assert!(impact.complete);
    assert_eq!(impact.changed_set.head, head);
    let impacts = impact
        .impacts
        .iter()
        .map(|item| {
            (
                item.node.id.as_str(),
                item.depth,
                item.changed_paths.clone(),
            )
        })
        .collect::<Vec<_>>();
    let a = vec!["src/a.rs".to_owned()];
    let b = vec!["src/b.rs".to_owned()];
    let both = vec!["src/a.rs".to_owned(), "src/b.rs".to_owned()];
    assert_eq!(
        impacts,
        [
            ("a", 0, a.clone()),
            ("b", 0, b.clone()),
            ("x", 1, a),
            ("y", 1, b),
            ("z", 2, both),
        ]
    );
    assert_eq!(impact.unmapped.len(), 1);
    assert_eq!(
        impact.unmapped[0].new_path.as_deref(),
        Some("src/untracked.rs")
    );
    assert_eq!(impact.unmapped[0].reason, "not_in_snapshot");
    Ok(())
}

#[test]
fn changed_set_impact_rejects_a_snapshot_that_does_not_match_head() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("repository");
    let store_path = temporary.path().join("cache/graph.db");
    let (_head, graph_service) = changed_set_impact_fixture(&root, &store_path)?;
    assert_git_success(
        &root,
        &["commit", "--quiet", "--allow-empty", "-m", "ahead"],
    );

    let request = ChangedSetImpactRequest::try_new(
        "HEAD~1",
        ImpactFilters::new(None, Vec::new(), Vec::new(), 100, 100)?,
    )?;
    let mut snapshot = graph_service.start_snapshot_request("current")?;
    let error = graph_service
        .impact_changed_set(&mut snapshot, &request, &CancellationToken::new())
        .expect_err("a snapshot older than HEAD must not be compared");
    assert!(matches!(
        error,
        DepgraphServiceError::SnapshotWorktreeMismatch
    ));
    Ok(())
}

#[test]
fn changed_set_impact_request_and_limits_fail_closed() -> Result<()> {
    let filters = ImpactFilters::new(None, Vec::new(), Vec::new(), 100, 100)?;
    for invalid in ["", "-x", "bad\nref"] {
        assert!(matches!(
            ChangedSetImpactRequest::try_new(invalid, filters.clone()),
            Err(DepgraphServiceError::InvalidInput)
        ));
    }

    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("repository");
    let store_path = temporary.path().join("cache/graph.db");
    let (_head, graph_service) = changed_set_impact_fixture(&root, &store_path)?;
    let request = ChangedSetImpactRequest::try_new(
        "HEAD",
        ImpactFilters::new(None, Vec::new(), Vec::new(), 3, 100)?,
    )?;
    let mut snapshot = graph_service.start_snapshot_request("current")?;
    assert!(matches!(
        graph_service.impact_changed_set(&mut snapshot, &request, &CancellationToken::new()),
        Err(DepgraphServiceError::ResourceLimitExceeded {
            limit: DepgraphResourceLimit::ImpactNodes,
            maximum: 3,
            observed: None,
        })
    ));
    Ok(())
}

#[test]
fn issue_303_service_methods_are_canonical_bounded_and_cancellable() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("repository");
    let store_path = temporary.path().join("cache/graph.db");
    std::fs::create_dir_all(&root)?;
    let mut writer = Store::open(&store_path)?;
    let snapshot_id = seed_graph(&mut writer, &root, "issue-303", "revision-303")?;
    writer.create_snapshot_name("baseline", &snapshot_id)?;
    assert_eq!(writer.impact_query_cache_entry_count()?, 0);
    drop(writer);
    let service = service(&root, &store_path)?;
    let cancellation = CancellationToken::new();

    let impact_request = ImpactRequest::try_new(
        "id:node:a",
        None,
        ImpactFilters::new(None, Vec::new(), Vec::new(), 100, 100)?,
    )?;
    let mut snapshot = service.start_snapshot_request("current")?;
    let first = service.impact(&mut snapshot, &impact_request, &cancellation)?;
    let second = service.impact(&mut snapshot, &impact_request, &cancellation)?;
    assert_eq!(first.impact(), second.impact());
    assert!(first.impact().complete);
    assert_eq!(
        first
            .impact()
            .impacts
            .iter()
            .map(|item| item.node.id.as_str())
            .collect::<Vec<_>>(),
        ["node:a", "node:e"]
    );
    let mut named_snapshot = service.start_snapshot_request("baseline")?;
    assert!(matches!(
        service.impact(
            &mut named_snapshot,
            &ImpactRequest::try_new(
                "id:node:a",
                Some("HEAD".to_owned()),
                ImpactFilters::new(None, Vec::new(), Vec::new(), 100, 100)?,
            )?,
            &cancellation,
        ),
        Err(DepgraphServiceError::InvalidInput)
    ));

    let cycles = service.cycles(
        &mut snapshot,
        &CyclesRequest::try_new(CycleLevel::File, 100)?,
        &cancellation,
    )?;
    assert_eq!(cycles.cycles().len(), 1);
    assert_eq!(
        cycles.cycles()[0].node_ids,
        ["file:cycle-a", "file:cycle-b", "file:cycle-a"]
    );

    let unresolved = service.unresolved(
        &mut snapshot,
        &UnresolvedRequest::try_new(Vec::new(), 100)?,
        &cancellation,
    )?;
    assert_eq!(unresolved.items().len(), 1);
    assert_eq!(unresolved.items()[0].site.id, "site:unresolved");
    assert!(
        unresolved.items()[0]
            .effective_profile_id
            .as_deref()
            .is_some_and(|id| id.starts_with("effective-profile:sha256:"))
    );
    assert!(
        !unresolved.items()[0].phase_coverage.is_empty(),
        "indexed effective-profile coverage must be preserved"
    );

    let mut exhausted_snapshot = service.start_snapshot_request("current")?;
    assert!(matches!(
        service.impact(
            &mut exhausted_snapshot,
            &ImpactRequest::try_new(
                "id:node:a",
                None,
                ImpactFilters::new(None, Vec::new(), Vec::new(), 1, 100)?,
            )?,
            &cancellation,
        ),
        Err(DepgraphServiceError::ResourceLimitExceeded {
            limit: DepgraphResourceLimit::ImpactNodes,
            maximum: 1,
            observed: None,
        })
    ));
    assert!(matches!(
        service.cycles(
            &mut exhausted_snapshot,
            &CyclesRequest::try_new(CycleLevel::File, 1)?,
            &cancellation,
        ),
        // Building the representative cycle a -> b -> a visits two edges.
        Err(DepgraphServiceError::ResourceLimitExceeded {
            limit: DepgraphResourceLimit::MaxTraversal,
            maximum: 1,
            observed: Some(2),
        })
    ));
    // max_traversal bounds the matching unresolved sites (Issue #617): the
    // one unresolved site fits in 1.
    assert_eq!(
        service
            .unresolved(
                &mut exhausted_snapshot,
                &UnresolvedRequest::try_new(Vec::new(), 1)?,
                &cancellation,
            )?
            .items()
            .len(),
        1
    );

    let cancelled = CancellationToken::new();
    assert!(cancelled.cancel());
    for error in [
        service
            .impact(&mut snapshot, &impact_request, &cancelled)
            .unwrap_err(),
        service
            .cycles(
                &mut snapshot,
                &CyclesRequest::try_new(CycleLevel::File, 100)?,
                &cancelled,
            )
            .unwrap_err(),
        service
            .unresolved(
                &mut snapshot,
                &UnresolvedRequest::try_new(Vec::new(), 100)?,
                &cancelled,
            )
            .unwrap_err(),
    ] {
        assert!(matches!(error, DepgraphServiceError::Cancelled));
    }

    assert_eq!(
        Store::open_read_only(&store_path)?.impact_query_cache_entry_count()?,
        0
    );
    Ok(())
}

// Issue #541: dependency lists can drop structural edges and select edge kinds.

const ISSUE_541_EDGES: &[(&str, &str, &str, &str)] = &[
    ("edge:contains-a", "package:app", "file:a", "contains"),
    ("edge:contains-b", "package:app", "file:b", "contains"),
    ("edge:declares-d", "file:a", "symbol:d", "declares"),
    ("edge:generated-a", "file:gen", "file:a", "generated_from"),
    ("edge:import-b", "file:b", "file:a", "imports"),
    ("edge:import-c", "file:c", "file:a", "imports"),
    ("edge:type-c", "file:c", "file:a", "type_uses"),
];

fn seed_issue_541_graph(store: &mut Store, root: &Path) -> Result<String> {
    store.start_scan_with_revision("issue-541", root, false, Some("revision-541"))?;
    let coverage = json!({
        "profiles": 1,
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
    let mut seq = 0_u64;
    let mut next = |event: &str| {
        seq += 1;
        json!({
            "event": event,
            "protocol_version": "1.0",
            "scan_id": "issue-541",
            "adapter": "fixture",
            "adapter_version": "1.0",
            "seq": seq
        })
    };
    let mut started = next("scan_started");
    started["root"] = json!(root);
    started["project_code_executed"] = json!(false);
    started["safe_mode"] = json!(true);
    store.ingest_event(&started)?;
    let mut profile = next("profile_declared");
    profile["profile"] = json!({
        "id": "fixture:issue-541",
        "language": "fixture",
        "features": [],
        "environment": {},
        "properties": {}
    });
    store.ingest_event(&profile)?;
    for (id, kind, path) in [
        ("package:app", "package", None),
        ("file:a", "file", Some("src/a.rs")),
        ("file:b", "file", Some("src/b.rs")),
        ("file:c", "file", Some("src/c.rs")),
        ("file:gen", "file", Some("src/gen.rs")),
        ("symbol:d", "symbol", None),
    ] {
        let mut node = next("node_upsert");
        node["node"] = json!({
            "id": id,
            "kind": kind,
            "locator": format!("id:{id}"),
            "display_name": id,
            "properties": path.map_or_else(|| json!({}), |path| json!({"path": path}))
        });
        store.ingest_event(&node)?;
    }
    for (id, source, target, kind) in ISSUE_541_EDGES {
        let mut edge = next("edge_upsert");
        edge["edge"] = json!({
            "id": id,
            "source": source,
            "target": target,
            "kind": kind,
            "phase": "source",
            "environment": "host",
            "profile_id": "fixture:issue-541",
            "resolution_status": "resolved",
            "precision": "exact",
            "condition": {"op": "all", "conditions": []},
            "generated": false
        });
        store.ingest_event(&edge)?;
    }
    let mut profile_completed = next("profile_completed");
    profile_completed["profile_id"] = json!("fixture:issue-541");
    profile_completed["coverage"] = coverage.clone();
    store.ingest_event(&profile_completed)?;
    let mut completed = next("scan_completed");
    completed["coverage"] = coverage;
    store.ingest_event(&completed)?;
    store.finish_scan("issue-541", "completed", None, true)?;
    Ok(store
        .current_snapshot_id()?
        .expect("completed issue 541 snapshot is promoted"))
}

fn issue_541_request(selector: &str, direction: DependencyDirection) -> DependenciesRequest {
    DependenciesRequest::try_new(selector, direction, true, GraphQueryFilter::default(), 100)
        .expect("valid dependency request")
}

fn issue_541_edge_ids(result: &depgraph_core::service::DependenciesResult) -> Vec<String> {
    let mut ids = result
        .items()
        .iter()
        .map(|item| item.step.edge.id.clone())
        .collect::<Vec<_>>();
    ids.sort();
    ids
}

#[test]
fn issue_541_structural_edge_kinds_are_defined_once_and_default_excludes_them() {
    assert_eq!(
        STRUCTURAL_EDGE_KINDS,
        ["contains", "declares", "generated_from"]
    );
    for kind in STRUCTURAL_EDGE_KINDS {
        assert!(is_structural_edge_kind(kind), "{kind}");
    }
    for kind in ["imports", "depends_on", "type_uses", "calls", "contain"] {
        assert!(!is_structural_edge_kind(kind), "{kind}");
    }
    // v0.7.0 excludes structural edges by default (breaking change); callers
    // restore the previous traversal with an explicit include.
    assert_eq!(
        DEFAULT_STRUCTURAL_EDGE_SELECTION,
        StructuralEdgeSelection::Exclude
    );
    assert_eq!(
        StructuralEdgeSelection::default(),
        StructuralEdgeSelection::Exclude
    );
    assert!(!EdgeKindFilter::default().is_unrestricted());
    for kind in STRUCTURAL_EDGE_KINDS {
        assert!(!EdgeKindFilter::default().allows(kind), "{kind}");
    }
    assert!(EdgeKindFilter::default().allows("imports"));
    let request = issue_541_request("id:file:a", DependencyDirection::Incoming);
    assert_eq!(request.edge_kind_filter(), &EdgeKindFilter::default());
    assert!(request.edge_kind_filter().edge_kinds().is_empty());
    assert_eq!(
        request.edge_kind_filter().structural_edges(),
        DEFAULT_STRUCTURAL_EDGE_SELECTION
    );
    assert!(EdgeKindFilter::unrestricted().is_unrestricted());
    assert_eq!(
        EdgeKindFilter::unrestricted().structural_edges(),
        StructuralEdgeSelection::Include
    );
    assert_eq!(StructuralEdgeSelection::Include.as_str(), "include");
    assert_eq!(StructuralEdgeSelection::Exclude.as_str(), "exclude");
    assert_eq!(
        StructuralEdgeSelection::parse("exclude"),
        Some(StructuralEdgeSelection::Exclude)
    );
    assert_eq!(StructuralEdgeSelection::parse("Exclude"), None);
}

#[test]
fn issue_541_excluding_structural_edges_counts_only_dependency_edges() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("repository");
    let store_path = temporary.path().join("cache/graph.db");
    std::fs::create_dir_all(&root)?;
    let mut writer = Store::open(&store_path)?;
    seed_issue_541_graph(&mut writer, &root)?;
    let service = service(&root, &store_path)?;
    let cancellation = CancellationToken::new();
    let mut snapshot = service.start_snapshot_request("current")?;

    let legacy = service.dependencies(
        &mut snapshot,
        &issue_541_request("id:file:a", DependencyDirection::Incoming)
            .with_edge_kind_filter(Vec::new(), Some(StructuralEdgeSelection::Include))?,
        &cancellation,
    )?;
    assert_eq!(
        issue_541_edge_ids(&legacy),
        [
            "edge:contains-a",
            "edge:contains-b",
            "edge:generated-a",
            "edge:import-b",
            "edge:import-c",
            "edge:type-c"
        ]
    );
    assert_eq!(legacy.traversed_edges(), 6);

    let excluded = service.dependencies(
        &mut snapshot,
        &issue_541_request("id:file:a", DependencyDirection::Incoming)
            .with_edge_kind_filter(Vec::new(), Some(StructuralEdgeSelection::Exclude))?,
        &cancellation,
    )?;
    assert!(excluded.complete());
    assert_eq!(
        issue_541_edge_ids(&excluded),
        ["edge:import-b", "edge:import-c", "edge:type-c"]
    );
    assert_eq!(excluded.traversed_edges(), 3);
    let default = service.dependencies(
        &mut snapshot,
        &issue_541_request("id:file:a", DependencyDirection::Incoming),
        &cancellation,
    )?;
    assert_eq!(
        issue_541_edge_ids(&default),
        issue_541_edge_ids(&excluded),
        "the default excludes structural edges"
    );
    assert_eq!(default.traversed_edges(), excluded.traversed_edges());
    let mut dependent_nodes = excluded
        .traversal()
        .nodes
        .iter()
        .map(|node| node.id.as_str())
        .collect::<Vec<_>>();
    dependent_nodes.sort_unstable();
    assert_eq!(dependent_nodes, ["file:b", "file:c"]);

    let outgoing = service.dependencies(
        &mut snapshot,
        &issue_541_request("id:file:a", DependencyDirection::Outgoing)
            .with_edge_kind_filter(Vec::new(), Some(StructuralEdgeSelection::Exclude))?,
        &cancellation,
    )?;
    assert!(outgoing.items().is_empty(), "declares is structural");
    assert_eq!(outgoing.traversed_edges(), 0);

    let package = service.dependencies(
        &mut snapshot,
        &issue_541_request("id:package:app", DependencyDirection::Outgoing)
            .with_edge_kind_filter(Vec::new(), Some(StructuralEdgeSelection::Exclude))?,
        &cancellation,
    )?;
    assert!(package.items().is_empty(), "contains is structural");
    assert!(package.traversal().nodes.is_empty());
    Ok(())
}

#[test]
fn issue_541_edge_kind_allowlist_selects_kinds_and_counts_only_them() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("repository");
    let store_path = temporary.path().join("cache/graph.db");
    std::fs::create_dir_all(&root)?;
    let mut writer = Store::open(&store_path)?;
    seed_issue_541_graph(&mut writer, &root)?;
    let service = service(&root, &store_path)?;
    let cancellation = CancellationToken::new();
    let mut snapshot = service.start_snapshot_request("current")?;

    let imports = service.dependencies(
        &mut snapshot,
        &issue_541_request("id:file:a", DependencyDirection::Incoming).with_edge_kind_filter(
            vec!["imports".to_owned()],
            Some(StructuralEdgeSelection::Exclude),
        )?,
        &cancellation,
    )?;
    assert_eq!(
        issue_541_edge_ids(&imports),
        ["edge:import-b", "edge:import-c"]
    );
    assert_eq!(imports.traversed_edges(), 2);

    let with_structure = service.dependencies(
        &mut snapshot,
        &issue_541_request("id:file:a", DependencyDirection::Incoming).with_edge_kind_filter(
            vec!["imports".to_owned(), "contains".to_owned()],
            Some(StructuralEdgeSelection::Include),
        )?,
        &cancellation,
    )?;
    assert_eq!(
        issue_541_edge_ids(&with_structure),
        [
            "edge:contains-a",
            "edge:contains-b",
            "edge:import-b",
            "edge:import-c"
        ]
    );
    assert_eq!(with_structure.traversed_edges(), 4);

    let unknown = service.dependencies(
        &mut snapshot,
        &issue_541_request("id:file:a", DependencyDirection::Incoming).with_edge_kind_filter(
            vec!["calls".to_owned()],
            Some(StructuralEdgeSelection::Include),
        )?,
        &cancellation,
    )?;
    assert!(unknown.items().is_empty());
    assert_eq!(unknown.traversed_edges(), 0);
    Ok(())
}

#[test]
fn issue_541_edge_kind_filter_is_validated_sorted_and_rejects_contradictions() {
    let request = || issue_541_request("id:file:a", DependencyDirection::Incoming);
    for structural in STRUCTURAL_EDGE_KINDS {
        assert!(
            matches!(
                request().with_edge_kind_filter(
                    vec!["imports".to_owned(), structural.to_owned()],
                    Some(StructuralEdgeSelection::Exclude)
                ),
                Err(DepgraphServiceError::InvalidInput)
            ),
            "{structural} contradicts structural_edges=exclude"
        );
        assert!(
            request()
                .with_edge_kind_filter(
                    vec![structural.to_owned()],
                    Some(StructuralEdgeSelection::Include)
                )
                .is_ok()
        );
    }
    for kind in [
        String::new(),
        "Imports".to_owned(),
        "1imports".to_owned(),
        "type uses".to_owned(),
        "imports\n".to_owned(),
        "a".repeat(MAX_DEPENDENCY_EDGE_KIND_BYTES + 1),
    ] {
        assert!(
            matches!(
                request().with_edge_kind_filter(
                    vec![kind.clone()],
                    Some(StructuralEdgeSelection::Include)
                ),
                Err(DepgraphServiceError::InvalidInput)
            ),
            "{kind:?} must be rejected"
        );
    }
    assert!(
        request()
            .with_edge_kind_filter(
                vec!["a".repeat(MAX_DEPENDENCY_EDGE_KIND_BYTES)],
                Some(StructuralEdgeSelection::Include)
            )
            .is_ok()
    );
    let too_many = (0..=MAX_DEPENDENCY_EDGE_KINDS)
        .map(|index| format!("kind{index}"))
        .collect::<Vec<_>>();
    assert!(matches!(
        request().with_edge_kind_filter(too_many, Some(StructuralEdgeSelection::Include)),
        Err(DepgraphServiceError::InvalidInput)
    ));
    let at_limit = (0..MAX_DEPENDENCY_EDGE_KINDS)
        .map(|index| format!("kind{index}"))
        .collect::<Vec<_>>();
    assert!(
        request()
            .with_edge_kind_filter(at_limit, Some(StructuralEdgeSelection::Include))
            .is_ok()
    );

    let normalized = request()
        .with_edge_kind_filter(
            vec![
                "type_uses".to_owned(),
                "imports".to_owned(),
                "type_uses".to_owned(),
            ],
            Some(StructuralEdgeSelection::Exclude),
        )
        .expect("valid selection");
    assert_eq!(
        normalized.edge_kind_filter().edge_kinds(),
        ["imports", "type_uses"]
    );
    // An allowlist alone decides the traversal, so its identity does not
    // depend on structural_edges once the contradiction check has passed.
    assert_eq!(
        normalized.edge_kind_filter().structural_edges(),
        StructuralEdgeSelection::Include
    );
    assert!(!normalized.edge_kind_filter().is_unrestricted());
    for structural_edges in [None, Some(StructuralEdgeSelection::Include)] {
        let equivalent = request()
            .with_edge_kind_filter(
                vec!["imports".to_owned(), "type_uses".to_owned()],
                structural_edges,
            )
            .expect("valid selection");
        assert_eq!(
            equivalent.edge_kind_filter(),
            normalized.edge_kind_filter(),
            "{structural_edges:?}"
        );
    }
}

#[test]
fn issue_541_omitted_structural_edges_lets_an_allowlist_name_structural_kinds() {
    let request = || issue_541_request("id:file:a", DependencyDirection::Incoming);
    for structural in STRUCTURAL_EDGE_KINDS {
        let omitted = request()
            .with_edge_kind_filter(vec![structural.to_owned()], None)
            .unwrap_or_else(|error| panic!("{structural} with omitted mode: {error:?}"));
        assert!(
            omitted.edge_kind_filter().allows(structural),
            "{structural}"
        );
        assert!(
            !omitted.edge_kind_filter().allows("imports"),
            "{structural}"
        );
        let included = request()
            .with_edge_kind_filter(
                vec![structural.to_owned()],
                Some(StructuralEdgeSelection::Include),
            )
            .expect("explicit include");
        assert_eq!(omitted.edge_kind_filter(), included.edge_kind_filter());
        assert!(matches!(
            request().with_edge_kind_filter(
                vec![structural.to_owned()],
                Some(StructuralEdgeSelection::Exclude)
            ),
            Err(DepgraphServiceError::InvalidInput)
        ));
    }
    let omitted_without_allowlist = request()
        .with_edge_kind_filter(Vec::new(), None)
        .expect("default selection");
    assert_eq!(
        omitted_without_allowlist.edge_kind_filter(),
        &EdgeKindFilter::default()
    );
    assert_eq!(
        omitted_without_allowlist
            .edge_kind_filter()
            .structural_edges(),
        DEFAULT_STRUCTURAL_EDGE_SELECTION
    );
}

// Issue #617 / #618: unresolved and cycles on a mid-sized snapshot.

#[path = "../support/issue_617_fixture.rs"]
mod issue_617_fixture;
use issue_617_fixture::{Issue617Shape, seed_issue_617_graph};

#[test]
fn issue_617_618_default_max_traversal_lists_unresolved_and_cycles_of_a_mid_sized_snapshot()
-> Result<()> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("repository");
    let store_path = temporary.path().join("cache/graph.db");
    std::fs::create_dir_all(&root)?;
    let shape = Issue617Shape::MID_SIZED;
    let mut writer = Store::open(&store_path)?;
    seed_issue_617_graph(&mut writer, &root, shape)?;
    drop(writer);
    let service = service(&root, &store_path)?;
    let cancellation = CancellationToken::new();
    let mut snapshot = service.start_snapshot_request("current")?;
    let default = depgraph_core::DEFAULT_INTERACTIVE_QUERY_MAX_TRAVERSAL;

    // Before the fix, the snapshot indexing alone counted 130,501 work items
    // for unresolved listing and 55,751 for file cycles against the default
    // max_traversal of 50,000.
    let unresolved = service.unresolved(
        &mut snapshot,
        &UnresolvedRequest::try_new(Vec::new(), default)?,
        &cancellation,
    )?;
    let unresolved_count = shape.files * shape.unresolved_per_file;
    assert_eq!(unresolved.items().len(), unresolved_count);
    assert!(
        unresolved
            .items()
            .iter()
            .all(|item| item.site.resolution_status == "unresolved" && item.evidence.len() == 1)
    );

    let file_cycles = service.cycles(
        &mut snapshot,
        &CyclesRequest::try_new(CycleLevel::File, default)?,
        &cancellation,
    )?;
    assert_eq!(file_cycles.cycles().len(), shape.files / shape.ring);
    assert_eq!(
        file_cycles.cycles()[0].node_ids,
        (0..=shape.ring)
            .map(|file| format!("file:{:04}", file % shape.ring))
            .collect::<Vec<_>>()
    );
    let symbol_cycles = service.cycles(
        &mut snapshot,
        &CyclesRequest::try_new(CycleLevel::Symbol, default)?,
        &cancellation,
    )?;
    assert!(symbol_cycles.cycles().is_empty());

    // max_traversal bounds the matching unresolved sites and reports how many
    // matched, so the caller knows which value succeeds.
    let short = UnresolvedRequest::try_new(Vec::new(), unresolved_count - 1)?;
    let error = service
        .unresolved(&mut snapshot, &short, &cancellation)
        .expect_err("one matching site above max_traversal fails");
    assert!(matches!(
        error,
        DepgraphServiceError::ResourceLimitExceeded {
            limit: DepgraphResourceLimit::MaxTraversal,
            maximum,
            observed: Some(observed),
        } if maximum == (unresolved_count - 1) as u64 && observed == unresolved_count as u64
    ));
    assert_eq!(
        error.to_string(),
        "request exhausted a service resource limit: max_traversal=6749 (observed 6750)"
    );
    let exact = UnresolvedRequest::try_new(Vec::new(), unresolved_count)?;
    assert_eq!(
        service
            .unresolved(&mut snapshot, &exact, &cancellation)?
            .items()
            .len(),
        unresolved_count
    );

    // A paged listing counts only the sites of one page against
    // max_traversal, so a page of 100 passes a max_traversal of 100 although
    // 6,750 sites match, and still reports every match.
    let paged = UnresolvedRequest::try_new(Vec::new(), 100)?.with_page_items(100)?;
    assert_eq!(
        service
            .unresolved(&mut snapshot, &paged, &cancellation)?
            .items()
            .len(),
        unresolved_count
    );
    let wide_page = UnresolvedRequest::try_new(Vec::new(), 100)?.with_page_items(101)?;
    assert!(matches!(
        service.unresolved(&mut snapshot, &wide_page, &cancellation),
        Err(DepgraphServiceError::ResourceLimitExceeded {
            limit: DepgraphResourceLimit::MaxTraversal,
            maximum: 100,
            observed: Some(101),
        })
    ));

    // The component search visits every ring edge forward and backward
    // against the snapshot-wide budget only. Choosing each representative
    // cycle visits every ring edge once more, and those visits count toward
    // max_traversal.
    let ring_edge_visits = shape.files;
    let node_ids = |cycles: &[depgraph_core::CycleResult]| {
        cycles
            .iter()
            .map(|cycle| cycle.node_ids.clone())
            .collect::<Vec<_>>()
    };
    let at_limit = service.cycles(
        &mut snapshot,
        &CyclesRequest::try_new(CycleLevel::File, ring_edge_visits)?,
        &cancellation,
    )?;
    assert_eq!(node_ids(at_limit.cycles()), node_ids(file_cycles.cycles()));
    assert!(matches!(
        service.cycles(
            &mut snapshot,
            &CyclesRequest::try_new(CycleLevel::File, ring_edge_visits - 1)?,
            &cancellation,
        ),
        Err(DepgraphServiceError::ResourceLimitExceeded {
            limit: DepgraphResourceLimit::MaxTraversal,
            maximum,
            observed: Some(observed),
        }) if maximum == (ring_edge_visits - 1) as u64 && observed == ring_edge_visits as u64
    ));
    Ok(())
}

#[test]
fn issue_617_out_of_range_max_traversal_names_the_argument_and_its_range() {
    for value in [0, depgraph_core::MAX_INTERACTIVE_QUERY_TRAVERSAL + 1] {
        for error in [
            CyclesRequest::try_new(CycleLevel::File, value).unwrap_err(),
            UnresolvedRequest::try_new(Vec::new(), value).unwrap_err(),
        ] {
            assert!(matches!(
                error,
                DepgraphServiceError::ArgumentOutOfRange {
                    argument: "max_traversal",
                    minimum: 1,
                    maximum: 1_000_000,
                }
            ));
            assert_eq!(
                error.to_string(),
                "invalid service input: max_traversal must be in 1..=1000000"
            );
        }
    }
}

// Issue #620: dependency listing and path explanation on a large snapshot.

/// Canonical digest of the dependency pages and explained paths of the
/// Issue #617 fixture, recorded with origin/main `3d7c7fd` before the path
/// steps stopped counting the snapshot-wide evidence and correlation scans
/// against the request work budget.
const ISSUE_620_MID_SIZED_QUERY_DIGEST: &str =
    "f7d63d2dceeee9ef36ca19fbdaa782d6dde36a034140613bc8c1097b4cd3a409";

fn issue_620_query_digest(
    service: &DepgraphService,
    snapshot: &mut depgraph_core::service::SnapshotReadRequest,
    cancellation: &CancellationToken,
) -> Result<String> {
    use sha2::{Digest, Sha256};
    let default = depgraph_core::DEFAULT_INTERACTIVE_QUERY_MAX_TRAVERSAL;
    let mut hasher = Sha256::new();
    let mut correlated_steps = 0_usize;
    for (selector, direction, transitive) in [
        ("id:file:0000", DependencyDirection::Outgoing, false),
        ("id:file:0000", DependencyDirection::Incoming, false),
        ("id:file:0000", DependencyDirection::Outgoing, true),
        ("id:file:0123", DependencyDirection::Incoming, true),
        ("id:symbol:0001:050", DependencyDirection::Incoming, false),
        ("id:unknown:missing", DependencyDirection::Incoming, false),
    ] {
        let found = service.dependencies(
            snapshot,
            &DependenciesRequest::try_new(
                selector,
                direction,
                transitive,
                GraphQueryFilter::default(),
                default,
            )?,
            cancellation,
        )?;
        assert!(found.complete(), "{selector}");
        assert!(!found.items().is_empty(), "{selector}");
        // The digest covers the evidence and profile correlation each step
        // carries, not only the edges.
        assert!(
            found
                .items()
                .iter()
                .all(|item| !item.step.evidence.is_empty()),
            "{selector}"
        );
        correlated_steps += found
            .items()
            .iter()
            .filter(|item| item.step.effective_profile_id.is_some())
            .count();
        hasher.update(serde_json::to_vec(&found.traversal().root)?);
        hasher.update(serde_json::to_vec(&found.traversal().nodes)?);
        hasher.update(serde_json::to_vec(found.items())?);
    }
    assert!(correlated_steps > 0);
    for (from, to) in [
        ("id:file:0000", "id:file:0009"),
        ("id:file:0005", "id:symbol:0051:050"),
    ] {
        let explained = service.explain_path(
            snapshot,
            &ExplainPathRequest::try_new(from, to, GraphQueryFilter::default(), default)?,
            cancellation,
        )?;
        assert!(explained.path().path_found, "{from} -> {to}");
        hasher.update(serde_json::to_vec(explained.path())?);
        hasher.update(serde_json::to_vec(explained.items())?);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

#[test]
fn issue_620_mid_sized_dependency_pages_and_paths_are_unchanged() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("repository");
    let store_path = temporary.path().join("cache/graph.db");
    std::fs::create_dir_all(&root)?;
    let mut writer = Store::open(&store_path)?;
    seed_issue_617_graph(&mut writer, &root, Issue617Shape::MID_SIZED)?;
    drop(writer);
    let service = service(&root, &store_path)?;
    let cancellation = CancellationToken::new();
    let mut snapshot = service.start_snapshot_request("current")?;
    let digest = issue_620_query_digest(&service, &mut snapshot, &cancellation)?;
    assert_eq!(digest, ISSUE_620_MID_SIZED_QUERY_DIGEST);
    Ok(())
}
