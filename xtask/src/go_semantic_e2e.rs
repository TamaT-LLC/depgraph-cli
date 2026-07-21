use std::{
    collections::BTreeMap,
    fs,
    path::Path,
    process::{Command, Output},
};

use anyhow::{Context, Result, bail, ensure};
use serde::Deserialize;
use serde_json::{Value, json};

const BUILD: &str = "example.com/semantic/model.Build";
const CYCLE_LEFT: &str = "example.com/semantic/model.CycleLeft";
const CYCLE_RIGHT: &str = "example.com/semantic/model.CycleRight";
const DIRECT_CALL_MATRIX: &str = "example.com/semantic/model.DirectCallMatrix";
const EXTERNAL_CALL: &str = "example.com/semantic/model.ExternalCall";
const INPUT: &str = "example.com/semantic/model.Input";
const OUTPUT_TO_INPUT: &str = "example.com/semantic/model.outputToInput";
const WORKER: &str = "example.com/semantic/model.Worker";

pub(crate) fn run_development(workspace_root: &Path, target_dir: &Path) -> Result<()> {
    let workspace_root = workspace_root
        .canonicalize()
        .context("failed to canonicalize the workspace root")?;
    let target_dir = if target_dir.is_absolute() {
        target_dir.to_path_buf()
    } else {
        workspace_root.join(target_dir)
    };

    run_checked(
        Command::new("cargo")
            .args(["build", "--locked", "-p", "depgraph-cli"])
            .current_dir(&workspace_root),
        "build the depgraph CLI for the Go semantic end-to-end gate",
    )?;

    let worker_build = tempfile::tempdir().context("create the Go worker build directory")?;
    let worker = worker_build
        .path()
        .join(executable_name("depgraph-go-worker"));
    run_checked(
        Command::new("go")
            .args(["build", "-trimpath", "-o"])
            .arg(&worker)
            .arg("./cmd/depgraph-go-worker")
            .env("GOTOOLCHAIN", "local")
            .env("GOFLAGS", "-mod=readonly")
            .current_dir(workspace_root.join("workers/go")),
        "build the Go worker for the semantic end-to-end gate",
    )?;

    let cli = target_dir.join("debug").join(executable_name("depgraph"));
    verify(&workspace_root, &cli, Some(&worker))
}

pub(crate) fn verify(
    workspace_root: &Path,
    cli: &Path,
    worker_override: Option<&Path>,
) -> Result<()> {
    let workspace_root = workspace_root
        .canonicalize()
        .context("failed to canonicalize the workspace root")?;
    let cli = cli
        .canonicalize()
        .with_context(|| format!("Go semantic E2E CLI is missing: {}", cli.display()))?;
    let worker_override = worker_override
        .map(|worker| {
            worker
                .canonicalize()
                .with_context(|| format!("Go semantic E2E worker is missing: {}", worker.display()))
        })
        .transpose()?;

    let root = tempfile::tempdir().context("create the Go semantic E2E directory")?;
    let semantic_root = root.path().join("semantic");
    let vta_root = root.path().join("semantic-vta");
    let fallback_root = root.path().join("fallback-workspace");
    let dependency_root_a = root.path().join("dependency-snapshot-a");
    let dependency_root_b = root.path().join("nested/dependency-snapshot-b");
    copy_tree(
        &workspace_root.join("workers/go/internal/worker/testdata/semantic"),
        &semantic_root,
    )?;
    copy_tree(
        &workspace_root.join("workers/go/internal/worker/testdata/semantic"),
        &vta_root,
    )?;
    fs::write(
        vta_root.join(".depgraph.toml"),
        "schema_version = 1\n\n[profiles]\ngo_call_graph = \"vta\"\n",
    )?;
    copy_tree(
        &workspace_root.join("workers/go/internal/worker/testdata/workspace"),
        &fallback_root,
    )?;
    for destination in [&dependency_root_a, &dependency_root_b] {
        copy_tree(
            &workspace_root.join("workers/go/internal/worker/testdata/dependency_snapshot"),
            destination,
        )?;
    }

    let module_cache = root.path().join("empty-module-cache");
    let go_path = root.path().join("empty-gopath");
    fs::create_dir_all(&module_cache)?;
    fs::create_dir_all(&go_path)?;
    let runner = Runner {
        cli: &cli,
        worker_override: worker_override.as_deref(),
        module_cache: &module_cache,
        go_path: &go_path,
    };

    verify_semantic_graph(&runner, root.path(), &semantic_root)?;
    verify_vta_graph(&runner, root.path(), &vta_root)?;
    verify_fallback_safety(&runner, root.path(), &fallback_root)?;
    verify_dependency_snapshot(&runner, root.path(), &dependency_root_a, &dependency_root_b)?;
    println!("Go semantic CLI end-to-end gate passed");
    Ok(())
}

fn verify_dependency_snapshot(
    runner: &Runner<'_>,
    temp: &Path,
    first_fixture: &Path,
    second_fixture: &Path,
) -> Result<()> {
    let first_store = temp.join("dependency-snapshot-a.db");
    let second_store = temp.join("dependency-snapshot-b.db");
    let changed_store = temp.join("dependency-snapshot-changed.db");
    let first_scan = runner.scan(&first_store, first_fixture)?;
    let second_scan = runner.scan(&second_store, second_fixture)?;
    ensure!(
        first_scan["status"] == "completed" && second_scan["status"] == "completed",
        "dependency snapshot fixture scans did not complete: first={first_scan} second={second_scan}"
    );
    let first_export = runner.export_json(&first_store)?;
    let second_export = runner.export_json(&second_store)?;
    let first_profile = graph_array(
        first_export
            .get("graph")
            .context("first dependency snapshot export has no graph")?,
        "profiles",
    )?
    .iter()
    .find(|profile| profile["language"] == "go")
    .context("first dependency snapshot export has no Go profile")?;
    let second_profile = graph_array(
        second_export
            .get("graph")
            .context("second dependency snapshot export has no graph")?,
        "profiles",
    )?
    .iter()
    .find(|profile| profile["language"] == "go")
    .context("second dependency snapshot export has no Go profile")?;
    ensure!(
        first_profile["properties"]["go_dependency_snapshot_status"] == "complete"
            && first_profile["properties"]["go_dependency_snapshot_schema"]
                == "go-offline-dependency-snapshot-v1"
            && first_profile["properties"]["go_dependency_snapshot_files"]
                .as_str()
                .is_some_and(|count| count.parse::<u64>().is_ok_and(|count| count > 0)),
        "dependency snapshot profile omitted its complete fingerprint metadata: {first_profile}"
    );
    ensure!(
        first_profile["id"] == second_profile["id"]
            && first_profile["properties"]["go_dependency_snapshot_fingerprint"]
                == second_profile["properties"]["go_dependency_snapshot_fingerprint"],
        "equivalent dependency snapshots changed identity across checkout roots: first={first_profile} second={second_profile}"
    );

    fs::write(
        second_fixture.join("dep/value.go"),
        "package dep\n\nfunc Value() string { return \"changed\" }\n",
    )?;
    let changed_scan = runner.scan(&changed_store, second_fixture)?;
    ensure!(
        changed_scan["status"] == "completed",
        "changed dependency snapshot scan did not complete: {changed_scan}"
    );
    let changed_export = runner.export_json(&changed_store)?;
    let changed_profile = graph_array(
        changed_export
            .get("graph")
            .context("changed dependency snapshot export has no graph")?,
        "profiles",
    )?
    .iter()
    .find(|profile| profile["language"] == "go")
    .context("changed dependency snapshot export has no Go profile")?;
    ensure!(
        first_profile["id"] != changed_profile["id"]
            && first_profile["properties"]["go_dependency_snapshot_fingerprint"]
                != changed_profile["properties"]["go_dependency_snapshot_fingerprint"],
        "dependency source content changed without invalidating profile identity: first={first_profile} changed={changed_profile}"
    );
    for profile in [first_profile, second_profile, changed_profile] {
        let encoded = serde_json::to_string(profile)?;
        ensure!(
            !encoded.contains(&first_fixture.display().to_string())
                && !encoded.contains(&second_fixture.display().to_string())
                && !encoded.contains(&runner.module_cache.display().to_string()),
            "dependency snapshot profile leaked a checkout/cache path: {encoded}"
        );
    }
    Ok(())
}

fn verify_vta_graph(runner: &Runner<'_>, temp: &Path, fixture: &Path) -> Result<()> {
    let first_store = temp.join("semantic-vta-one.db");
    let second_store = temp.join("semantic-vta-two.db");
    let first_scan = runner.scan(&first_store, fixture)?;
    let second_scan = runner.scan(&second_store, fixture)?;
    assert_semantic_scan(&first_scan)?;
    assert_semantic_scan(&second_scan)?;
    let first_export = runner.export_json(&first_store)?;
    let second_export = runner.export_json(&second_store)?;
    ensure!(
        graph_projection(&first_export)? == graph_projection(&second_export)?,
        "two opt-in VTA scans produced different nodes/sites/edges/coverage"
    );

    let graph = first_export
        .get("graph")
        .context("VTA JSON export has no graph")?;
    let profile = graph_array(graph, "profiles")?
        .iter()
        .find(|profile| profile["language"] == "go")
        .context("VTA export has no Go profile")?;
    ensure!(
        profile["properties"]["go_call_graph_requested"] == "vta"
            && matches!(
                profile["properties"]["go_call_graph_vta_status"].as_str(),
                Some("applied" | "partial")
            ),
        "VTA profile lost its requested/effective outcome: {profile}"
    );

    let sites = graph_array(graph, "sites")?;
    let edges = graph_array(graph, "edges")?;
    let evidence = graph_array(graph, "evidence")?;
    let mut vta_sites = 0_u64;
    let mut singleton_sites = 0_u64;
    for site in sites
        .iter()
        .filter(|site| site["kind"] == "call" && site["resolution_status"] == "candidates")
    {
        let site_id = required_str(site, "id", "VTA candidate site")?;
        let targets = site["target_ids"]
            .as_array()
            .context("VTA candidate site has no target_ids")?;
        let primary = evidence
            .iter()
            .find(|item| item["owner_type"] == "site" && item["owner_id"] == site_id)
            .with_context(|| format!("VTA candidate site {site_id} has no stored evidence"))?;
        let algorithm = primary["properties"]["algorithm"]
            .as_str()
            .unwrap_or_default();
        if algorithm == "vta" {
            vta_sites += 1;
            ensure!(
                primary["properties"]["fallback_reason"] == "none",
                "applied VTA site reported a fallback: {primary}"
            );
        } else {
            ensure!(
                matches!(algorithm, "rta" | "cha")
                    && primary["properties"]["fallback_reason"] != "none",
                "VTA fallback did not name its effective algorithm/reason: {primary}"
            );
        }
        ensure!(
            primary["properties"]["requested_algorithm"] == "vta"
                && primary["properties"]["candidate_count"].as_u64() == Some(targets.len() as u64),
            "VTA candidate evidence lost requested algorithm or candidate count: {primary}"
        );
        if targets.len() == 1 {
            singleton_sites += 1;
            ensure!(
                site["precision"] == "overapprox",
                "VTA singleton candidate was promoted to exact: {site}"
            );
        }
        for edge in edges.iter().filter(|edge| edge["site_id"] == site_id) {
            let edge_id = required_str(edge, "id", "VTA candidate edge")?;
            let edge_primary = evidence
                .iter()
                .find(|item| item["owner_type"] == "edge" && item["owner_id"] == edge_id)
                .with_context(|| format!("VTA candidate edge {edge_id} has no stored evidence"))?;
            ensure!(
                edge["kind"] == "may_call"
                    && edge["precision"] == "overapprox"
                    && edge_primary["properties"] == primary["properties"],
                "VTA edge and site evidence disagree: site={primary} edge={edge_primary}"
            );
        }
    }
    ensure!(
        vta_sites > 0 && singleton_sites > 0,
        "VTA E2E did not exercise an applied singleton refinement"
    );
    Ok(())
}

struct Runner<'a> {
    cli: &'a Path,
    worker_override: Option<&'a Path>,
    module_cache: &'a Path,
    go_path: &'a Path,
}

impl Runner<'_> {
    fn command(&self) -> Command {
        let mut command = Command::new(self.cli);
        command
            .env("GOMODCACHE", self.module_cache)
            .env("GOPATH", self.go_path);
        if let Some(worker) = self.worker_override {
            command.env("DEPGRAPH_GO_WORKER", worker);
        } else {
            command.env_remove("DEPGRAPH_GO_WORKER");
        }
        command
    }

    fn scan(&self, store: &Path, fixture: &Path) -> Result<Value> {
        self.scan_with_optional_path(store, fixture, None)
    }

    fn scan_with_path(&self, store: &Path, fixture: &Path, path: &Path) -> Result<Value> {
        ensure!(
            path.is_absolute(),
            "the fallback E2E PATH must be absolute: {}",
            path.display()
        );
        self.scan_with_optional_path(store, fixture, Some(path))
    }

    fn scan_with_optional_path(
        &self,
        store: &Path,
        fixture: &Path,
        path: Option<&Path>,
    ) -> Result<Value> {
        let mut command = self.command();
        if let Some(path) = path {
            command.env("PATH", path);
        }
        command
            .arg("--store")
            .arg(store)
            .arg("scan")
            .arg(fixture)
            .arg("--json");
        checked_json(&mut command, "scan the Go fixture")
    }

    fn query(&self, store: &Path, arguments: &[&str]) -> Result<Value> {
        let mut command = self.command();
        command.arg("--store").arg(store).args(arguments);
        checked_json(
            &mut command,
            &format!("run depgraph {}", arguments.join(" ")),
        )
    }

    fn export_json(&self, store: &Path) -> Result<Value> {
        self.query(store, &["export", "--format", "json"])
    }

    fn export_text(&self, store: &Path, format: &str) -> Result<String> {
        let mut command = self.command();
        command
            .arg("--store")
            .arg(store)
            .args(["export", "--format", format]);
        let output = checked_output(&mut command, &format!("export the graph as {format}"))?;
        String::from_utf8(output.stdout).context("depgraph export returned non-UTF-8 output")
    }
}

fn verify_semantic_graph(runner: &Runner<'_>, temp: &Path, fixture: &Path) -> Result<()> {
    let first_store = temp.join("semantic-one.db");
    let second_store = temp.join("semantic-two.db");
    let first_scan = runner.scan(&first_store, fixture)?;
    let second_scan = runner.scan(&second_store, fixture)?;
    assert_semantic_scan(&first_scan)?;
    assert_semantic_scan(&second_scan)?;

    let first_export = runner.export_json(&first_store)?;
    let second_export = runner.export_json(&second_store)?;
    ensure!(
        graph_projection(&first_export)? == graph_projection(&second_export)?,
        "two CLI scans of the Go semantic fixture produced different nodes/sites/edges/coverage"
    );
    ensure!(
        first_export["graph"] == second_export["graph"],
        "two CLI scans produced different Go profiles/evidence/diagnostics"
    );
    ensure!(
        first_scan["coverage"] == first_export["graph"]["coverage"],
        "scan and exported semantic coverage disagree"
    );

    let graph = first_export
        .get("graph")
        .context("semantic JSON export has no graph")?;
    assert_ledger(graph)?;
    let expected = load_expected_graph(fixture)?;
    let expected_node_ids = assert_expected_graph(&expected, graph)?;
    let nodes = graph_array(graph, "nodes")?;
    let sites = graph_array(graph, "sites")?;
    let edges = graph_array(graph, "edges")?;
    let evidence = graph_array(graph, "evidence")?;
    verify_call_graph_boundaries(runner, &first_store, graph)?;

    let build_id = require_node(nodes, "symbol", BUILD, "function")?;
    let cycle_left_id = require_node(nodes, "symbol", CYCLE_LEFT, "function")?;
    let cycle_right_id = require_node(nodes, "symbol", CYCLE_RIGHT, "function")?;
    let direct_id = require_node(nodes, "symbol", DIRECT_CALL_MATRIX, "function")?;
    let external_call_id = require_node(nodes, "symbol", EXTERNAL_CALL, "function")?;
    let output_to_input_id = require_node(nodes, "symbol", OUTPUT_TO_INPUT, "function")?;
    let input_id = require_node(nodes, "type", INPUT, "struct")?;
    require_node(nodes, "type", WORKER, "interface")?;

    let build_type_use = require_edge(
        edges,
        &build_id,
        &input_id,
        "type_uses",
        "resolved",
        "exact",
    )?;
    require_edge(
        edges,
        &cycle_left_id,
        &cycle_right_id,
        "calls",
        "resolved",
        "exact",
    )?;
    require_edge(
        edges,
        &cycle_right_id,
        &cycle_left_id,
        "calls",
        "resolved",
        "exact",
    )?;
    let direct_call = require_edge(
        edges,
        &direct_id,
        &external_call_id,
        "calls",
        "resolved",
        "exact",
    )?;
    let candidate_call = require_edge(
        edges,
        &direct_id,
        &external_call_id,
        "may_call",
        "candidates",
        "overapprox",
    )?;
    let value_reference = require_edge(
        edges,
        &build_id,
        &output_to_input_id,
        "references",
        "resolved",
        "exact",
    )?;

    for edge in [build_type_use, direct_call, value_reference] {
        require_edge_evidence(evidence, edge, "go-types")?;
    }
    require_edge_evidence(evidence, candidate_call, "go-ssa")?;
    let candidate_site_id = required_str(candidate_call, "site_id", "candidate edge")?;
    let candidate_site = sites
        .iter()
        .find(|site| site["id"] == candidate_site_id)
        .context("candidate edge has no stored dependency site")?;
    ensure!(
        candidate_site["resolution_status"] == "candidates"
            && candidate_site["precision"] == "overapprox"
            && candidate_site["target_ids"]
                .as_array()
                .is_some_and(|targets| targets.iter().any(|target| target == &external_call_id)),
        "candidate dependency site lost its target/status/precision contract: {candidate_site}"
    );

    let ids = SemanticFixtureIds {
        build: build_id,
        input: input_id,
        output_to_input: output_to_input_id,
        direct: direct_id,
        direct_edge: required_str(direct_call, "id", "direct call edge")?.to_owned(),
        candidate_edge: required_str(candidate_call, "id", "candidate call edge")?.to_owned(),
        cycle_left: cycle_left_id,
        cycle_right: cycle_right_id,
        reference_edge: required_str(value_reference, "id", "value-reference edge")?.to_owned(),
    };
    verify_queries(runner, &first_store, &second_store, &ids)?;

    let first_dot = runner.export_text(&first_store, "dot")?;
    let second_dot = runner.export_text(&second_store, "dot")?;
    let first_mermaid = runner.export_text(&first_store, "mermaid")?;
    let second_mermaid = runner.export_text(&second_store, "mermaid")?;
    ensure!(first_dot == second_dot, "DOT export changed between scans");
    ensure!(
        first_mermaid == second_mermaid,
        "Mermaid export changed between scans"
    );
    assert_expected_visual_exports(
        &expected,
        &expected_node_ids,
        graph,
        &first_dot,
        &first_mermaid,
    )?;
    Ok(())
}

fn verify_call_graph_boundaries(runner: &Runner<'_>, store: &Path, graph: &Value) -> Result<()> {
    let nodes = graph_array(graph, "nodes")?;
    let sites = graph_array(graph, "sites")?;
    let evidence = graph_array(graph, "evidence")?;
    let diagnostics = graph_array(graph, "diagnostics")?;
    let expected = BTreeMap::from([
        ("assembly_declaration", 2_u64),
        ("assembly_implementation", 1),
        ("cgo_import", 1),
        ("go_linkname", 1),
        ("native_callback", 1),
        ("native_header", 1),
        ("native_library", 1),
        ("plugin", 1),
        ("reflection_call", 2),
        ("reflection_call_slice", 1),
        ("reflection_field_lookup", 2),
        ("reflection_make_func", 1),
        ("reflection_method_lookup", 2),
        ("unsafe", 1),
    ]);
    let mut counts = BTreeMap::<&str, u64>::new();
    let mut unresolved_boundary_ids = Vec::<String>::new();
    for primary in evidence.iter().filter(|item| {
        item["owner_type"] == "site" && item["properties"]["callgraph_boundary"].as_str().is_some()
    }) {
        let boundary = required_str(
            primary
                .get("properties")
                .context("boundary evidence has no properties")?,
            "callgraph_boundary",
            "boundary evidence",
        )?;
        *counts.entry(boundary).or_default() += 1;
        let site_id = required_str(primary, "owner_id", "boundary evidence")?;
        let site = sites
            .iter()
            .find(|site| site["id"] == site_id)
            .with_context(|| format!("boundary evidence has no site {site_id}"))?;
        let reason = primary["properties"]["boundary_reason"]
            .as_str()
            .context("boundary evidence has no dedicated reason")?;
        ensure!(
            !reason.is_empty() && site["profile_id"].as_str().is_some(),
            "boundary site lost reason/profile identity: site={site} evidence={primary}"
        );
        let diagnostic = diagnostics
            .iter()
            .find(|diagnostic| {
                diagnostic["code"] == "go_callgraph_limit"
                    && diagnostic["properties"]["site_id"] == site_id
            })
            .with_context(|| format!("boundary site {site_id} has no correlated diagnostic"))?;
        ensure!(
            diagnostic["properties"]["boundary"] == boundary
                && diagnostic["properties"]["reason"] == reason
                && diagnostic["path"] == primary["path"]
                && diagnostic["start_line"] == primary["start_line"]
                && diagnostic["start_column"] == primary["start_column"]
                && diagnostic["end_line"] == primary["end_line"]
                && diagnostic["end_column"] == primary["end_column"],
            "boundary diagnostic and site evidence disagree: diagnostic={diagnostic} evidence={primary}"
        );
        if site["resolution_status"] == "unresolved" {
            unresolved_boundary_ids.push(site_id.to_owned());
            ensure!(
                site["precision"] == "heuristic"
                    && site["reason"] == reason
                    && site["target_ids"].as_array().is_some_and(|targets| {
                        targets.len() == 1
                            && nodes.iter().any(|node| {
                                node["id"] == targets[0] && node["kind"] == "unknown_target"
                            })
                    }),
                "unresolved boundary invented an exact/candidate target: {site}"
            );
        }
    }
    ensure!(
        counts == expected,
        "Go boundary fixture counts changed: {counts:?}"
    );
    let profile = graph_array(graph, "profiles")?
        .iter()
        .find(|profile| profile["language"] == "go")
        .context("boundary export has no Go profile")?;
    let expected_total = expected.values().sum::<u64>();
    ensure!(
        profile["properties"]["go_callgraph_boundary_status"] == "observed"
            && profile["properties"]["go_callgraph_boundary_site_count"]
                .as_str()
                .and_then(|value| value.parse::<u64>().ok())
                == Some(expected_total)
            && profile["properties"]["go_callgraph_boundary_completeness_policy"]
                == "semantic-complete-allowed-with-explicit-boundaries"
            && string_array_contains(&graph["coverage"]["completeness"], "semantic-complete"),
        "Go profile lost boundary/completeness metadata: {profile}"
    );

    let unresolved = runner.query(store, &["unresolved", "--json"])?;
    let unresolved_items = unresolved["data"]
        .as_array()
        .context("Go unresolved query has no data array")?;
    for site_id in unresolved_boundary_ids {
        ensure!(
            unresolved_items.iter().any(|item| {
                item["site"]["id"] == site_id
                    && item["site"]["reason"]
                        .as_str()
                        .is_some_and(|reason| !reason.is_empty())
                    && item["evidence"].as_array().is_some_and(|items| {
                        items.iter().any(|item| {
                            item["properties"]["callgraph_boundary"].as_str().is_some()
                                && item["properties"]["boundary_reason"].as_str().is_some()
                        })
                    })
            }),
            "unresolved query omitted boundary site {site_id} or its reason/evidence"
        );
    }
    Ok(())
}

struct SemanticFixtureIds {
    build: String,
    input: String,
    output_to_input: String,
    direct: String,
    direct_edge: String,
    candidate_edge: String,
    cycle_left: String,
    cycle_right: String,
    reference_edge: String,
}

fn verify_queries(
    runner: &Runner<'_>,
    first_store: &Path,
    second_store: &Path,
    ids: &SemanticFixtureIds,
) -> Result<()> {
    let deps = runner.query(
        first_store,
        &["deps", &format!("symbol:{DIRECT_CALL_MATRIX}"), "--json"],
    )?;
    ensure!(
        deps["data"]["root"]["id"] == ids.direct && deps["data"]["root"]["kind"] == "symbol",
        "symbol selector did not resolve DirectCallMatrix: {deps}"
    );
    let dependency_edges = deps["data"]["edges"]
        .as_array()
        .context("deps result has no edges")?;
    for expected in [&ids.direct_edge, &ids.candidate_edge] {
        ensure!(
            dependency_edges
                .iter()
                .any(|edge| edge["id"] == expected.as_str()),
            "deps omitted expected semantic edge {expected}"
        );
        ensure!(
            deps["data"]["steps"].as_array().is_some_and(|steps| {
                steps.iter().any(|step| {
                    step["edge"]["id"] == expected.as_str()
                        && step["evidence"].as_array().is_some_and(|items| {
                            items.iter().any(|item| item["kind"] == "semantic")
                        })
                })
            }),
            "deps omitted semantic evidence for edge {expected}"
        );
    }

    let type_query = runner.query(first_store, &["deps", &format!("type:{INPUT}"), "--json"])?;
    ensure!(
        type_query["data"]["root"]["id"] == ids.input
            && type_query["data"]["root"]["kind"] == "type",
        "type selector did not resolve Input: {type_query}"
    );

    let dependents = runner.query(
        first_store,
        &["dependents", &format!("type:{INPUT}"), "--json"],
    )?;
    ensure!(
        dependents["data"]["root"]["id"] == ids.input
            && dependents["data"]["root"]["kind"] == "type"
            && dependents["data"]["edges"].as_array().is_some_and(|edges| {
                edges.iter().any(|edge| {
                    edge["source"] == ids.build
                        && edge["target"] == ids.input
                        && edge["kind"] == "type_uses"
                        && edge["phase"] == "semantic"
                        && edge["resolution_status"] == "resolved"
                        && edge["precision"] == "exact"
                })
            })
            && dependents["data"]["steps"].as_array().is_some_and(|steps| {
                steps.iter().any(|step| {
                    step["edge"]["source"] == ids.build
                        && step["edge"]["target"] == ids.input
                        && step["edge"]["kind"] == "type_uses"
                        && step["evidence"].as_array().is_some_and(|items| {
                            items.iter().any(|item| {
                                item["kind"] == "semantic" && item["extractor"] == "go-types"
                            })
                        })
                })
            }),
        "dependents did not retain Build -> Input type_uses with semantic evidence: {dependents}"
    );

    let why = runner.query(
        first_store,
        &[
            "why",
            &format!("symbol:{BUILD}"),
            &format!("type:{INPUT}"),
            "--json",
        ],
    )?;
    let why_steps = why["data"]["steps"]
        .as_array()
        .context("why result has no steps")?;
    ensure!(
        why["data"]["path_found"] == true
            && why["data"]["from"]["id"] == ids.build
            && why["data"]["to"]["id"] == ids.input
            && why_steps.len() == 1
            && why_steps[0]["edge"]["kind"] == "type_uses"
            && why_steps[0]["edge"]["phase"] == "semantic"
            && why_steps[0]["edge"]["resolution_status"] == "resolved"
            && why_steps[0]["edge"]["precision"] == "exact"
            && why_steps[0]["evidence"][0]["kind"] == "semantic"
            && why_steps[0]["evidence"][0]["extractor"] == "go-types",
        "why did not retain the semantic type relation and its evidence: {why}"
    );

    let reference_why = runner.query(
        first_store,
        &[
            "why",
            &format!("symbol:{BUILD}"),
            &format!("symbol:{OUTPUT_TO_INPUT}"),
            "--json",
        ],
    )?;
    ensure!(
        reference_why["data"]["path_found"] == true
            && reference_why["data"]["from"]["id"] == ids.build
            && reference_why["data"]["to"]["id"] == ids.output_to_input
            && reference_why["data"]["steps"]
                .as_array()
                .is_some_and(|steps| {
                    steps.len() == 1
                        && steps[0]["edge"]["id"] == ids.reference_edge
                        && steps[0]["edge"]["kind"] == "references"
                        && steps[0]["evidence"].as_array().is_some_and(|items| {
                            items.iter().any(|item| {
                                item["kind"] == "semantic" && item["extractor"] == "go-types"
                            })
                        })
                }),
        "why did not retain the Go value reference and its evidence: {reference_why}"
    );

    let first_cycles = runner.query(first_store, &["cycles", "--level", "symbol", "--json"])?;
    let second_cycles = runner.query(second_store, &["cycles", "--level", "symbol", "--json"])?;
    ensure!(
        first_cycles["data"] == second_cycles["data"],
        "symbol cycle query changed between scans"
    );
    let (start, other) = if ids.cycle_left < ids.cycle_right {
        (ids.cycle_left.as_str(), ids.cycle_right.as_str())
    } else {
        (ids.cycle_right.as_str(), ids.cycle_left.as_str())
    };
    ensure!(
        first_cycles["data"].as_array().is_some_and(|cycles| {
            cycles.iter().any(|cycle| {
                cycle["level"] == "symbol"
                    && cycle["node_ids"].as_array().is_some_and(|ids| {
                        ids.len() == 3 && ids[0] == start && ids[1] == other && ids[2] == start
                    })
            })
        }),
        "cycles did not expose the CycleLeft/CycleRight semantic cycle: {first_cycles}"
    );
    Ok(())
}

fn verify_fallback_safety(runner: &Runner<'_>, temp: &Path, fixture: &Path) -> Result<()> {
    let marker = fixture.join("app/lib/generator-was-run");
    let go_work_sum = fixture.join("go.work.sum");
    let go_sum = fixture.join("app/go.sum");
    for path in [&marker, &go_work_sum, &go_sum] {
        ensure!(
            !path.exists(),
            "fallback safety fixture was dirty before the scan: {}",
            path.display()
        );
    }
    let protected_paths = [
        fixture.join("go.work"),
        fixture.join("app/go.mod"),
        fixture.join("shared/go.mod"),
        fixture.join("replaced/go.mod"),
    ];
    let before = protected_paths
        .iter()
        .map(fs::read)
        .collect::<std::io::Result<Vec<_>>>()?;

    let default_path_store = temp.join("default-path-fallback.db");
    let default_path_scan = runner.scan(&default_path_store, fixture)?;
    assert_parser_fallback_scan(
        runner,
        &default_path_store,
        &default_path_scan,
        "default-PATH",
        expected_default_path_go_packages_status(cfg!(target_os = "windows")),
    )?;

    let empty_path = temp.join("empty-path");
    fs::create_dir_all(&empty_path)?;
    let empty_path = empty_path
        .canonicalize()
        .context("failed to canonicalize the empty fallback PATH")?;
    let empty_path_store = temp.join("empty-path-fallback.db");
    let empty_path_scan = runner.scan_with_path(&empty_path_store, fixture, &empty_path)?;
    assert_parser_fallback_scan(
        runner,
        &empty_path_store,
        &empty_path_scan,
        "empty-PATH",
        "fallback",
    )?;

    for (path, original) in protected_paths.iter().zip(before) {
        ensure!(
            fs::read(path)? == original,
            "safe fallback scans modified {}",
            path.display()
        );
    }
    for path in [&marker, &go_work_sum, &go_sum] {
        ensure!(
            !path.exists(),
            "safe fallback scans created {}",
            path.display()
        );
    }
    Ok(())
}

fn expected_default_path_go_packages_status(target_is_windows: bool) -> &'static str {
    // This armed workspace retains independent typed modules on Unix. The
    // Windows go/packages load has no active typed packages, so its safe,
    // deterministic result is a full parser fallback instead.
    if target_is_windows {
        "fallback"
    } else {
        "partial"
    }
}

fn assert_parser_fallback_scan(
    runner: &Runner<'_>,
    store: &Path,
    scan: &Value,
    scenario: &str,
    expected_status: &str,
) -> Result<()> {
    ensure!(
        scan["status"] == "completed"
            && scan["exit_code"] == 0
            && scan["coverage"]["project_code_executed"] == false,
        "{scenario} parser-fallback scan failed its safe completion contract: {scan}"
    );
    ensure!(
        string_array_contains(&scan["coverage"]["completeness"], "syntax-complete")
            && !string_array_contains(&scan["coverage"]["completeness"], "semantic-complete")
            && string_array_contains(&scan["coverage"]["reasons"], "go-packages-parser-fallback"),
        "{scenario} parser-fallback scan lost its explicit completeness/reason ledger: {scan}"
    );

    let exported = runner.export_json(store)?;
    ensure!(
        scan["coverage"] == exported["graph"]["coverage"],
        "{scenario} parser-fallback scan and export coverage disagree"
    );
    let graph = exported
        .get("graph")
        .with_context(|| format!("{scenario} parser-fallback JSON export has no graph"))?;
    assert_ledger(graph)?;
    ensure!(
        !graph_array(graph, "nodes")?.is_empty()
            && !graph_array(graph, "sites")?.is_empty()
            && graph["coverage"]["dependency_sites"]
                .as_u64()
                .is_some_and(|count| count > 0),
        "{scenario} parser fallback returned an empty parser graph: {graph}"
    );
    if expected_status == "fallback" {
        ensure!(
            graph_array(graph, "nodes")?
                .iter()
                .all(|node| node["kind"] != "symbol" && node["kind"] != "type")
                && graph_array(graph, "edges")?
                    .iter()
                    .all(|edge| edge["phase"] != "semantic"),
            "{scenario} full parser fallback unexpectedly retained semantic nodes or edges: {graph}"
        );
    }
    let go_profile = graph_array(graph, "profiles")?
        .iter()
        .find(|profile| profile["language"] == "go")
        .with_context(|| format!("{scenario} parser-fallback export has no Go profile"))?;
    ensure!(
        go_profile["properties"]["go_packages_status"] == expected_status
            && go_profile["coverage"]["project_code_executed"] == false,
        "{scenario} Go profile lost expected {expected_status}/safety metadata: {go_profile}"
    );
    Ok(())
}

fn assert_semantic_scan(scan: &Value) -> Result<()> {
    ensure!(
        scan["status"] == "completed"
            && scan["exit_code"] == 0
            && scan["coverage"]["project_code_executed"] == false
            && scan["coverage"]["candidates"].as_u64().unwrap_or(0) > 0
            && string_array_contains(&scan["coverage"]["completeness"], "semantic-complete"),
        "Go semantic scan failed its completion/safety/candidate contract: {scan}"
    );
    Ok(())
}

fn assert_ledger(graph: &Value) -> Result<()> {
    let profiles = graph_array(graph, "profiles")?;
    let sites = graph_array(graph, "sites")?;
    let file_coverage = graph_array(graph, "file_coverage")?;
    let coverage = graph
        .get("coverage")
        .context("exported graph has no aggregate coverage")?;
    let mut statuses = BTreeMap::<&str, u64>::new();
    for site in sites {
        let status = site["resolution_status"]
            .as_str()
            .context("dependency site has no resolution_status")?;
        *statuses.entry(status).or_default() += 1;
    }
    for status in ["resolved", "candidates", "external", "unresolved"] {
        ensure!(
            coverage[status].as_u64().unwrap_or(u64::MAX)
                == statuses.get(status).copied().unwrap_or(0),
            "coverage count for {status} does not match dependency sites"
        );
    }
    ensure!(
        coverage["dependency_sites"].as_u64() == Some(sites.len() as u64)
            && coverage["profiles"].as_u64() == Some(profiles.len() as u64)
            && coverage["files_discovered"].as_u64()
                == Some(
                    coverage["files_analyzed"].as_u64().unwrap_or(0)
                        + coverage["files_skipped"].as_u64().unwrap_or(0)
                )
            && coverage["project_code_executed"] == false,
        "aggregate coverage ledger is not conserved: {coverage}"
    );
    for file in file_coverage {
        ensure!(
            file["discovered_sites"].as_u64()
                == Some(
                    file["emitted_sites"].as_u64().unwrap_or(u64::MAX)
                        + file["skipped_sites"].as_u64().unwrap_or(u64::MAX)
                ),
            "file coverage ledger is not conserved: {file}"
        );
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExpectedGraph {
    schema_version: String,
    scope: String,
    nodes: Vec<ExpectedNode>,
    relations: Vec<ExpectedRelation>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExpectedNode {
    locator: String,
    kind: String,
    semantic_kind: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExpectedRelation {
    source_locator: String,
    target_locator: String,
    site_kind: String,
    kind: String,
    phase: String,
    resolution_status: String,
    precision: String,
    evidence: ExpectedEvidence,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExpectedEvidence {
    kind: String,
    extractor: String,
    extractor_version: String,
    path: String,
    start_line: u64,
    start_column: u64,
    end_line: u64,
    end_column: u64,
    properties: BTreeMap<String, String>,
}

fn load_expected_graph(fixture: &Path) -> Result<ExpectedGraph> {
    let path = fixture.join("expected-graph.json");
    let expected: ExpectedGraph = serde_json::from_slice(
        &fs::read(&path).with_context(|| format!("failed to read {}", path.display()))?,
    )
    .with_context(|| format!("invalid expected graph {}", path.display()))?;
    ensure!(
        expected.schema_version == "1.0",
        "unsupported Go semantic expected graph schema {}",
        expected.schema_version
    );
    ensure!(
        expected.scope == "required_semantic_subgraph",
        "unsupported Go semantic expected graph scope {}",
        expected.scope
    );
    ensure!(
        !expected.nodes.is_empty() && !expected.relations.is_empty(),
        "Go semantic expected graph must contain nodes and relations"
    );
    Ok(expected)
}

fn assert_expected_graph(
    expected: &ExpectedGraph,
    graph: &Value,
) -> Result<BTreeMap<String, String>> {
    let nodes = graph_array(graph, "nodes")?;
    let sites = graph_array(graph, "sites")?;
    let edges = graph_array(graph, "edges")?;
    let evidence = graph_array(graph, "evidence")?;
    let mut node_ids = BTreeMap::<String, String>::new();
    for contract in &expected.nodes {
        let node = nodes
            .iter()
            .find(|node| node["locator"] == contract.locator && node["kind"] == contract.kind)
            .with_context(|| {
                format!(
                    "expected graph node is missing: {} ({})",
                    contract.locator, contract.kind
                )
            })?;
        let kind_property = if contract.kind == "symbol" {
            "symbol_kind"
        } else if contract.kind == "type" {
            "type_kind"
        } else {
            bail!(
                "expected graph uses unsupported semantic node kind {}",
                contract.kind
            );
        };
        ensure!(
            node["properties"][kind_property] == contract.semantic_kind,
            "expected graph node {} has the wrong semantic kind: {node}",
            contract.locator
        );
        node_ids.insert(
            contract.locator.clone(),
            required_str(node, "id", &contract.locator)?.to_owned(),
        );
    }

    for contract in &expected.relations {
        let source = node_ids.get(&contract.source_locator).with_context(|| {
            format!(
                "expected relation source has no node contract: {}",
                contract.source_locator
            )
        })?;
        let target = node_ids.get(&contract.target_locator).with_context(|| {
            format!(
                "expected relation target has no node contract: {}",
                contract.target_locator
            )
        })?;
        let matched =
            find_expected_relation(contract, source, target, sites, edges, evidence).is_some();
        ensure!(
            matched,
            "expected semantic relation is missing: {} --{}--> {} ({}, {})",
            contract.source_locator,
            contract.kind,
            contract.target_locator,
            contract.resolution_status,
            contract.precision
        );
    }
    Ok(node_ids)
}

fn find_expected_relation<'a>(
    contract: &ExpectedRelation,
    source: &str,
    target: &str,
    sites: &[Value],
    edges: &'a [Value],
    evidence: &[Value],
) -> Option<&'a Value> {
    edges
        .iter()
        .find(|edge| expected_relation_matches(contract, source, target, edge, sites, evidence))
}

fn expected_relation_matches(
    contract: &ExpectedRelation,
    source: &str,
    target: &str,
    edge: &Value,
    sites: &[Value],
    evidence: &[Value],
) -> bool {
    if edge["source"] != source
        || edge["target"] != target
        || edge["kind"] != contract.kind
        || edge["phase"] != contract.phase
        || edge["resolution_status"] != contract.resolution_status
        || edge["precision"] != contract.precision
    {
        return false;
    }
    let Some(site_id) = edge.get("site_id").and_then(Value::as_str) else {
        return false;
    };
    let Some(site) = sites.iter().find(|site| site["id"] == site_id) else {
        return false;
    };
    let Some(edge_id) = edge.get("id").and_then(Value::as_str) else {
        return false;
    };
    site["source"] == source
        && site["kind"] == contract.site_kind
        && site["resolution_status"] == contract.resolution_status
        && site["precision"] == contract.precision
        && site["target_ids"]
            .as_array()
            .is_some_and(|targets| targets.iter().any(|candidate| candidate == target))
        && evidence.iter().any(|item| {
            item["owner_type"] == "site"
                && item["owner_id"] == site_id
                && expected_evidence_matches(item, &contract.evidence)
        })
        && evidence.iter().any(|item| {
            item["owner_type"] == "edge"
                && item["owner_id"] == edge_id
                && expected_evidence_matches(item, &contract.evidence)
        })
}

fn expected_evidence_matches(item: &Value, expected: &ExpectedEvidence) -> bool {
    item["kind"] == expected.kind
        && item["extractor"] == expected.extractor
        && item["extractor_version"] == expected.extractor_version
        && item["path"] == expected.path
        && item["start_line"].as_u64() == Some(expected.start_line)
        && item["start_column"].as_u64() == Some(expected.start_column)
        && item["end_line"].as_u64() == Some(expected.end_line)
        && item["end_column"].as_u64() == Some(expected.end_column)
        && expected.properties.iter().all(|(key, value)| {
            item["properties"].get(key).and_then(Value::as_str) == Some(value.as_str())
        })
}

fn require_node(
    nodes: &[Value],
    kind: &str,
    resolver_identity: &str,
    semantic_kind: &str,
) -> Result<String> {
    let node = nodes
        .iter()
        .find(|node| {
            node["kind"] == kind
                && node["properties"]["canonical_identity"]["resolver_identity"]
                    == resolver_identity
        })
        .with_context(|| format!("missing {kind} node {resolver_identity}"))?;
    let kind_property = if kind == "symbol" {
        "symbol_kind"
    } else {
        "type_kind"
    };
    ensure!(
        node["properties"][kind_property] == semantic_kind,
        "{resolver_identity} has an unexpected {kind_property}: {node}"
    );
    Ok(required_str(node, "id", resolver_identity)?.to_owned())
}

fn require_edge<'a>(
    edges: &'a [Value],
    source: &str,
    target: &str,
    kind: &str,
    status: &str,
    precision: &str,
) -> Result<&'a Value> {
    edges
        .iter()
        .find(|edge| {
            edge["source"] == source
                && edge["target"] == target
                && edge["kind"] == kind
                && edge["phase"] == "semantic"
                && edge["resolution_status"] == status
                && edge["precision"] == precision
        })
        .with_context(|| {
            format!("missing semantic {kind} edge {source} -> {target} ({status}, {precision})")
        })
}

fn require_edge_evidence(evidence: &[Value], edge: &Value, extractor: &str) -> Result<()> {
    let edge_id = required_str(edge, "id", "semantic edge")?;
    let item = evidence
        .iter()
        .find(|item| {
            item["owner_type"] == "edge"
                && item["owner_id"] == edge_id
                && item["kind"] == "semantic"
                && item["extractor"] == extractor
        })
        .with_context(|| format!("edge {edge_id} has no {extractor} semantic evidence"))?;
    let path = required_str(item, "path", "semantic evidence")?;
    ensure!(
        !path.is_empty()
            && !Path::new(path).is_absolute()
            && !path.contains('\\')
            && item["start_line"].as_u64().unwrap_or(0) > 0
            && item["start_column"].as_u64().unwrap_or(0) > 0
            && item["end_line"].as_u64().unwrap_or(0) > 0
            && item["end_column"].as_u64().unwrap_or(0) > 0,
        "edge {edge_id} has invalid normalized evidence: {item}"
    );
    Ok(())
}

fn assert_expected_visual_exports(
    expected: &ExpectedGraph,
    node_ids: &BTreeMap<String, String>,
    graph: &Value,
    dot: &str,
    mermaid: &str,
) -> Result<()> {
    let nodes = graph_array(graph, "nodes")?;
    let sites = graph_array(graph, "sites")?;
    let edges = graph_array(graph, "edges")?;
    let evidence = graph_array(graph, "evidence")?;
    let mut mermaid_indexes = BTreeMap::<&str, usize>::new();
    for (index, node) in nodes.iter().enumerate() {
        mermaid_indexes.insert(required_str(node, "id", "semantic graph node")?, index);
    }

    for contract in &expected.nodes {
        let node_id = node_ids
            .get(&contract.locator)
            .with_context(|| format!("visual node is missing: {}", contract.locator))?;
        let node = nodes
            .iter()
            .find(|node| node["id"] == node_id.as_str())
            .with_context(|| format!("visual graph node is missing for {node_id}"))?;
        let display_name = required_str(node, "display_name", "semantic graph node")?;
        let kind = required_str(node, "kind", "semantic graph node")?;
        let dot_node = format!(
            "  \"{}\" [label=\"{}\\n({})\"];",
            dot_escape(node_id),
            dot_escape(display_name),
            dot_escape(kind)
        );
        ensure!(
            dot.lines().any(|line| line == dot_node),
            "DOT export omitted the expected exact node declaration: {dot_node}"
        );

        let index = mermaid_indexes
            .get(node_id.as_str())
            .with_context(|| format!("Mermaid node alias is missing for {node_id}"))?;
        let mermaid_node = format!(
            "  n{index}[\"{}\\n({})\"]",
            mermaid_escape(display_name),
            mermaid_escape(kind)
        );
        ensure!(
            mermaid.lines().any(|line| line == mermaid_node),
            "Mermaid export omitted the expected exact node declaration: {mermaid_node}"
        );
    }

    for contract in &expected.relations {
        let source = node_ids.get(&contract.source_locator).with_context(|| {
            format!(
                "visual relation source is missing: {}",
                contract.source_locator
            )
        })?;
        let target = node_ids.get(&contract.target_locator).with_context(|| {
            format!(
                "visual relation target is missing: {}",
                contract.target_locator
            )
        })?;
        let edge = find_expected_relation(contract, source, target, sites, edges, evidence)
            .with_context(|| {
                format!(
                    "cannot render missing expected relation: {} --{}--> {}",
                    contract.source_locator, contract.kind, contract.target_locator
                )
            })?;
        let label = visual_edge_label(edge)?;
        let dot_edge = format!(
            "  \"{}\" -> \"{}\" [label=\"{}\"];",
            dot_escape(source),
            dot_escape(target),
            dot_escape(&label)
        );
        ensure!(
            dot.lines().any(|line| line == dot_edge),
            "DOT export omitted the expected endpoint/label pair: {dot_edge}"
        );

        let source_index = mermaid_indexes
            .get(source.as_str())
            .with_context(|| format!("Mermaid source alias is missing for {source}"))?;
        let target_index = mermaid_indexes
            .get(target.as_str())
            .with_context(|| format!("Mermaid target alias is missing for {target}"))?;
        let mermaid_edge = format!(
            "  n{source_index} -->|\"{}\"| n{target_index}",
            mermaid_escape(&label)
        );
        ensure!(
            mermaid.lines().any(|line| line == mermaid_edge),
            "Mermaid export omitted the expected alias endpoint/label pair: {mermaid_edge}"
        );
    }
    Ok(())
}

fn visual_edge_label(edge: &Value) -> Result<String> {
    Ok(format!(
        "{} [{}; {}; {}; {}]",
        required_str(edge, "kind", "semantic edge")?,
        required_str(edge, "resolution_status", "semantic edge")?,
        required_str(edge, "precision", "semantic edge")?,
        required_str(edge, "profile_id", "semantic edge")?,
        required_str(edge, "condition_text", "semantic edge")?
    ))
}

fn dot_escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

fn mermaid_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('|', "&#124;")
        .replace('`', "&#96;")
        .replace('"', "&quot;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('\n', " ")
}

fn graph_projection(export: &Value) -> Result<Value> {
    let graph = export
        .get("graph")
        .context("JSON export has no graph object")?;
    Ok(json!({
        "nodes": graph.get("nodes").context("JSON export has no nodes")?,
        "sites": graph.get("sites").context("JSON export has no sites")?,
        "edges": graph.get("edges").context("JSON export has no edges")?,
        "coverage": graph.get("coverage").context("JSON export has no coverage")?,
    }))
}

fn graph_array<'a>(graph: &'a Value, field: &str) -> Result<&'a [Value]> {
    graph
        .get(field)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .with_context(|| format!("exported graph has no {field} array"))
}

fn required_str<'a>(value: &'a Value, field: &str, context: &str) -> Result<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .with_context(|| format!("{context} has no string {field}"))
}

fn string_array_contains(value: &Value, expected: &str) -> bool {
    value
        .as_array()
        .is_some_and(|items| items.iter().any(|item| item == expected))
}

fn checked_json(command: &mut Command, description: &str) -> Result<Value> {
    let output = checked_output(command, description)?;
    serde_json::from_slice(&output.stdout).with_context(|| {
        format!(
            "{description} returned invalid JSON: {}",
            String::from_utf8_lossy(&output.stdout)
        )
    })
}

fn checked_output(command: &mut Command, description: &str) -> Result<Output> {
    let display = format!("{command:?}");
    let output = command
        .output()
        .with_context(|| format!("failed to {description}: {display}"))?;
    if !output.status.success() {
        bail!(
            "failed to {description}: {display} exited with {}\nstdout:\n{}\nstderr:\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(output)
}

fn run_checked(command: &mut Command, description: &str) -> Result<()> {
    let display = format!("{command:?}");
    let status = command
        .status()
        .with_context(|| format!("failed to {description}: {display}"))?;
    ensure!(
        status.success(),
        "failed to {description}: {display} exited with {status}"
    );
    Ok(())
}

fn copy_tree(source: &Path, destination: &Path) -> Result<()> {
    fs::create_dir_all(destination).with_context(|| {
        format!(
            "failed to create fixture directory {}",
            destination.display()
        )
    })?;
    for entry in fs::read_dir(source)
        .with_context(|| format!("failed to read fixture directory {}", source.display()))?
    {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let target = destination.join(entry.file_name());
        if file_type.is_dir() {
            copy_tree(&entry.path(), &target)?;
        } else if file_type.is_file() {
            fs::copy(entry.path(), &target).with_context(|| {
                format!(
                    "failed to copy fixture file {} to {}",
                    entry.path().display(),
                    target.display()
                )
            })?;
        } else {
            bail!(
                "unsupported entry in Go semantic E2E fixture: {}",
                entry.path().display()
            );
        }
    }
    Ok(())
}

fn executable_name(name: &str) -> String {
    if cfg!(windows) {
        format!("{name}.exe")
    } else {
        name.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::expected_default_path_go_packages_status;

    #[test]
    fn default_path_go_packages_status_is_platform_specific() {
        assert_eq!(expected_default_path_go_packages_status(false), "partial");
        assert_eq!(expected_default_path_go_packages_status(true), "fallback");
    }
}
