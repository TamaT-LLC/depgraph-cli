use std::{fs, path::Path, process::Command};

use anyhow::Result;
use depgraph_core::service::{
    CyclesRequest, DependenciesRequest, DependencyDirection, DepgraphCapabilitySet,
    DepgraphService, DepgraphServiceConfig, DepgraphServiceError, DepgraphServiceLimits,
    ExplainPathRequest, ImpactRequest, MAX_CYCLE_NODE_IDS, MAX_DEPENDENCY_PATH_STEPS,
    MAX_GRAPH_EVIDENCE_ITEMS, UnresolvedRequest,
};
use depgraph_core::{CancellationToken, CycleLevel, GraphQueryFilter, ImpactFilters};
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
        Err(DepgraphServiceError::ResourceExhausted)
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
        Err(DepgraphServiceError::ResourceExhausted)
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
        Err(DepgraphServiceError::InvalidInput)
    ));
    assert!(matches!(
        ExplainPathRequest::try_new(
            "id:node:a",
            "id:node:b",
            GraphQueryFilter::default(),
            over_maximum,
        ),
        Err(DepgraphServiceError::InvalidInput)
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
        Err(DepgraphServiceError::ResourceExhausted)
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
        Err(DepgraphServiceError::ResourceExhausted)
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
        Err(DepgraphServiceError::ResourceExhausted)
    ));
    assert!(matches!(
        service.cycles(
            &mut exhausted_snapshot,
            &CyclesRequest::try_new(CycleLevel::File, 1)?,
            &cancellation,
        ),
        Err(DepgraphServiceError::ResourceExhausted)
    ));
    assert!(matches!(
        service.unresolved(
            &mut exhausted_snapshot,
            &UnresolvedRequest::try_new(Vec::new(), 1)?,
            &cancellation,
        ),
        Err(DepgraphServiceError::ResourceExhausted)
    ));

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
