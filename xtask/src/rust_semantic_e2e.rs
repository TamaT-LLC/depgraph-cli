use std::{
    collections::BTreeMap,
    fs,
    path::Path,
    process::{Command, Output},
};

use anyhow::{Context, Result, bail, ensure};
use serde_json::Value;

const RUST_ANALYZER_VERSION: &str = "0.0.330";
const RUST_ANALYZER_REVISION: &str = "8954b66d43225e62c92e8bbcc8500191b5cceb1e";
const SALSA_VERSION: &str = "0.26.1";
const TOOLCHAIN_BASELINE: &str = "1.93.1";
const RUSTC_BASELINE_COMMIT: &str = "01f6ddf7588f42ae2d7eb0a2f21d44e8e96674cf";
const CARGO_BASELINE_COMMIT: &str = "083ac5135f967fd9dc906ab057a2315861c7a80d";
const HIR_INTEGRATION_POLICY: &str = "pinned-rust-analyzer-library";
const SYSROOT_CONTRACT_VERSION: &str = "rust-src-data-tree-v1";
const SYSROOT_COMPONENT_VERSION: &str = "1.93.1+rustc.01f6ddf7588f42ae2d7eb0a2f21d44e8e96674cf";
const SYSROOT_SOURCE_LAYOUT: &str = "rustup-rust-src-library-v1";

#[cfg(test)]
const CRATE_KEY: &str = "Cargo.toml#lib:rust_release_semantic_fixture:src/lib.rs";
const BUILD: &str = "Cargo.toml#lib:rust_release_semantic_fixture:src/lib.rs::crate::build";
const TRANSFORM: &str = "Cargo.toml#lib:rust_release_semantic_fixture:src/lib.rs::crate::transform";
const INPUT: &str = "Cargo.toml#lib:rust_release_semantic_fixture:src/lib.rs::crate::Input";
const OUTPUT: &str = "Cargo.toml#lib:rust_release_semantic_fixture:src/lib.rs::crate::Output";
const CYCLE_LEFT: &str =
    "Cargo.toml#lib:rust_release_semantic_fixture:src/lib.rs::crate::cycle_left";
const CYCLE_RIGHT: &str =
    "Cargo.toml#lib:rust_release_semantic_fixture:src/lib.rs::crate::cycle_right";
const STANDARD_CALL: &str =
    "Cargo.toml#lib:rust_release_semantic_fixture:src/lib.rs::crate::standard_call";
const STANDARD_TYPES: &str =
    "Cargo.toml#lib:rust_release_semantic_fixture:src/lib.rs::crate::standard_types";

/// Build the development CLI/worker pair and run the same semantic gate used
/// by an extracted release archive. A development override deliberately
/// expects the pre-release profile gate; packaged callers pass no override and
/// therefore require the release verifier gate.
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
            .args([
                "build",
                "--locked",
                "-p",
                "depgraph-cli",
                "-p",
                "depgraph-rust-worker",
            ])
            .current_dir(&workspace_root),
        "build the depgraph CLI and Rust worker for the semantic end-to-end gate",
    )?;

    let cli = target_dir.join("debug").join(executable_name("depgraph"));
    let worker = target_dir
        .join("debug")
        .join(executable_name("depgraph-rust-worker"));
    verify(&workspace_root, &cli, Some(&worker))
}

/// Verify a real CLI and SQLite store against the release-semantic fixture.
///
/// `worker_override == None` is reserved for an extracted packaged layout and
/// requires `release-gate-verified`. Development callers must provide their
/// explicitly built worker and retain `release-gate-pending`.
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
        .with_context(|| format!("Rust semantic E2E CLI is missing: {}", cli.display()))?;
    let worker_override = worker_override
        .map(|worker| {
            worker.canonicalize().with_context(|| {
                format!("Rust semantic E2E worker is missing: {}", worker.display())
            })
        })
        .transpose()?;
    let expected_release_gate = expected_release_gate(worker_override.as_deref());
    let expect_attested_sysroot = worker_override.is_none();

    let root = tempfile::tempdir().context("create the Rust semantic E2E directory")?;
    let first_fixture = root.path().join("fixture-one");
    let second_fixture = root.path().join("fixture-two");
    let forbidden_rust_src = root.path().join("forbidden-rust-src/library/std/src");
    fs::create_dir_all(&forbidden_rust_src)?;
    fs::write(
        forbidden_rust_src.join("lib.rs"),
        "compile_error!(\"system/project rust-src must not be loaded\");\n",
    )?;
    let fixture_source = workspace_root.join("workers/rust/tests/fixtures/release-semantic");
    copy_tree(&fixture_source, &first_fixture)?;
    copy_tree(&fixture_source, &second_fixture)?;
    let first_fixture = first_fixture
        .canonicalize()
        .context("canonicalize the first Rust semantic fixture")?;
    let second_fixture = second_fixture
        .canonicalize()
        .context("canonicalize the second Rust semantic fixture")?;

    let runner = Runner {
        cli: &cli,
        worker_override: worker_override.as_deref(),
        neutral_cwd: root.path(),
        forbidden_rust_src: &forbidden_rust_src,
    };
    let first_store = root.path().join("semantic-one.db");
    let second_store = root.path().join("semantic-two.db");
    let first_scan = runner.scan(&first_store, &first_fixture)?;
    let second_scan = runner.scan(&second_store, &second_fixture)?;
    assert_semantic_scan(&first_scan, expect_attested_sysroot)?;
    assert_semantic_scan(&second_scan, expect_attested_sysroot)?;
    ensure!(
        first_scan["coverage"] == second_scan["coverage"],
        "two Rust semantic CLI scans produced different aggregate coverage"
    );
    ensure!(
        first_scan["diagnostics"] == second_scan["diagnostics"],
        "two Rust semantic CLI scans produced different diagnostics"
    );

    let first_json = runner.export_text(&first_store, "json")?;
    let second_json = runner.export_text(&second_store, "json")?;
    ensure!(
        first_json == second_json,
        "canonical Rust semantic JSON export changed between scans"
    );
    let first_dot = runner.export_text(&first_store, "dot")?;
    let second_dot = runner.export_text(&second_store, "dot")?;
    ensure!(
        first_dot == second_dot,
        "canonical Rust semantic DOT export changed between scans"
    );
    let first_mermaid = runner.export_text(&first_store, "mermaid")?;
    let second_mermaid = runner.export_text(&second_store, "mermaid")?;
    ensure!(
        first_mermaid == second_mermaid,
        "canonical Rust semantic Mermaid export changed between scans"
    );

    let first_export: Value =
        serde_json::from_str(&first_json).context("Rust semantic JSON export is not valid JSON")?;
    let second_export: Value = serde_json::from_str(&second_json)
        .context("second Rust semantic JSON export is not valid JSON")?;
    let first_graph = first_export
        .get("graph")
        .context("Rust semantic JSON export has no graph")?;
    let second_graph = second_export
        .get("graph")
        .context("second Rust semantic JSON export has no graph")?;
    for field in [
        "profiles",
        "nodes",
        "sites",
        "edges",
        "evidence",
        "diagnostics",
        "file_coverage",
        "coverage",
    ] {
        ensure!(
            first_graph.get(field) == second_graph.get(field),
            "Rust semantic {field} changed between scans"
        );
    }
    ensure!(
        first_scan["coverage"] == first_graph["coverage"],
        "scan report and canonical export disagree on Rust semantic coverage"
    );

    assert_profile(first_graph, expected_release_gate, expect_attested_sysroot)?;
    assert_ledger(first_graph)?;
    assert_normalized_paths(first_graph)?;
    let ids = assert_required_semantic_graph(first_graph, expect_attested_sysroot)?;
    verify_queries(&runner, &first_store, &second_store, &ids)?;
    assert_visual_exports(first_graph, &ids, &first_dot, &first_mermaid)?;

    for volatile_root in [&first_fixture, &second_fixture, &forbidden_rust_src] {
        ensure!(
            !first_json.contains(&volatile_root.to_string_lossy().to_string()),
            "canonical Rust semantic export leaked temporary fixture root {}",
            volatile_root.display()
        );
    }
    println!("Rust semantic CLI end-to-end gate passed ({expected_release_gate})");
    Ok(())
}

fn expected_release_gate(worker_override: Option<&Path>) -> &'static str {
    if worker_override.is_some() {
        "release-gate-pending"
    } else {
        "release-gate-verified"
    }
}

struct Runner<'a> {
    cli: &'a Path,
    worker_override: Option<&'a Path>,
    neutral_cwd: &'a Path,
    forbidden_rust_src: &'a Path,
}

impl Runner<'_> {
    fn command(&self) -> Command {
        let mut command = Command::new(self.cli);
        command
            .current_dir(self.neutral_cwd)
            .env("RUST_SRC_PATH", self.forbidden_rust_src);
        if let Some(worker) = self.worker_override {
            command.env("DEPGRAPH_RUST_WORKER", worker);
        } else {
            command.env_remove("DEPGRAPH_RUST_WORKER");
        }
        command
    }

    fn scan(&self, store: &Path, fixture: &Path) -> Result<Value> {
        let mut command = self.command();
        command
            .arg("--store")
            .arg(store)
            .arg("scan")
            .arg(fixture)
            .args(["--strict", "--json"]);
        checked_json(&mut command, "scan the Rust release-semantic fixture")
    }

    fn query(&self, store: &Path, arguments: &[&str]) -> Result<Value> {
        let mut command = self.command();
        command.arg("--store").arg(store).args(arguments);
        checked_json(
            &mut command,
            &format!("run depgraph {}", arguments.join(" ")),
        )
    }

    fn export_text(&self, store: &Path, format: &str) -> Result<String> {
        let mut command = self.command();
        command
            .arg("--store")
            .arg(store)
            .args(["export", "--format", format]);
        let output = checked_output(&mut command, &format!("export the Rust graph as {format}"))?;
        String::from_utf8(output.stdout)
            .with_context(|| format!("depgraph {format} export returned non-UTF-8 output"))
    }
}

fn assert_semantic_scan(scan: &Value, expect_attested_sysroot: bool) -> Result<()> {
    let coverage = &scan["coverage"];
    ensure!(
        scan["status"] == "completed"
            && scan["exit_code"] == 0
            && coverage["project_code_executed"] == false,
        "Rust semantic scan failed its safe completion contract: {scan}"
    );
    ensure!(
        coverage["files_skipped"] == 0
            && coverage["unsupported_syntax"] == 0
            && coverage["unresolved"] == 0
            && coverage["dependency_sites"].as_u64().unwrap_or(0) > 0,
        "Rust semantic scan failed its complete resolution contract: {coverage}"
    );
    ensure!(
        string_array_contains(&coverage["completeness"], "syntax-complete"),
        "Rust semantic scan did not report syntax completeness: {coverage}"
    );
    if expect_attested_sysroot {
        ensure!(
            coverage["resolved"].as_u64().unwrap_or(0) + coverage["external"].as_u64().unwrap_or(0)
                == coverage["dependency_sites"].as_u64().unwrap_or(u64::MAX)
                && coverage["candidates"] == 0,
            "packaged Rust mixed-phase scan did not conserve resolved and external sites: {coverage}"
        );
    } else {
        ensure!(
            coverage["resolved"].as_u64().unwrap_or(0) + coverage["external"].as_u64().unwrap_or(0)
                == coverage["dependency_sites"].as_u64().unwrap_or(u64::MAX)
                && !string_array_contains(&coverage["completeness"], "semantic-complete"),
            "development Rust semantic scan incorrectly promoted an unattested sysroot: {coverage}"
        );
    }
    Ok(())
}

fn assert_profile(
    graph: &Value,
    expected_release_gate: &str,
    expect_attested_sysroot: bool,
) -> Result<()> {
    let profiles = graph_array(graph, "profiles")?;
    ensure!(
        profiles.len() == 1 && profiles[0]["language"] == "rust",
        "release-semantic export must contain exactly one Rust profile: {profiles:?}"
    );
    let profile = &profiles[0];
    let properties = &profile["properties"];
    ensure!(
        profile["toolchain"]["adapter_version"] == env!("CARGO_PKG_VERSION"),
        "Rust profile toolchain adapter version does not match the release: {}",
        profile["toolchain"]
    );
    for (field, expected) in [
        ("analysis", "syntax+hir-imports-types-calls"),
        ("analysis_backend", "static-syntax+rust-analyzer-hir"),
        ("cargo_metadata_input", "confined-mirror"),
        ("crate_graph_source", "confined-cargo-metadata"),
        ("rust_analyzer_version", RUST_ANALYZER_VERSION),
        ("rust_analyzer_revision", RUST_ANALYZER_REVISION),
        ("rust_analyzer_salsa_version", SALSA_VERSION),
        ("rust_hir_backend", "rust-analyzer-hir"),
        ("rust_hir_project_model", "ready"),
        ("rust_hir_enable_gate", expected_release_gate),
        ("rust_hir_integration_policy", HIR_INTEGRATION_POLICY),
        (
            "rust_hir_sysroot_contract_version",
            SYSROOT_CONTRACT_VERSION,
        ),
        (
            "rust_hir_sysroot_component_version",
            SYSROOT_COMPONENT_VERSION,
        ),
        ("rust_hir_sysroot_source_layout", SYSROOT_SOURCE_LAYOUT),
        ("rust_toolchain_baseline", TOOLCHAIN_BASELINE),
        ("rust_hir_toolchain_status", "compatible"),
    ] {
        ensure!(
            properties[field] == expected,
            "Rust semantic profile property {field} must be {expected:?}: {properties}"
        );
    }
    let attestation = &properties["rust_hir_toolchain_attestation"];
    ensure!(
        attestation["contract"] == "installed-verified-rust-toolchain-v1"
            && attestation["status"] == "compatible"
            && matches!(
                attestation["selection"].as_str(),
                Some("host-default" | "installed-verified-baseline")
            )
            && attestation["rustc"]["release"] == TOOLCHAIN_BASELINE
            && attestation["rustc"]["commit_hash"] == RUSTC_BASELINE_COMMIT
            && attestation["cargo"]["release"] == TOOLCHAIN_BASELINE
            && attestation["cargo"]["commit_hash"] == CARGO_BASELINE_COMMIT
            && attestation["rustc"]["host"] == attestation["cargo"]["host"]
            && ["rustc", "cargo"].into_iter().all(|tool| {
                attestation[tool]["sha256"].as_str().is_some_and(|digest| {
                    digest.len() == "sha256:".len() + 64 && digest.starts_with("sha256:")
                })
            }),
        "Rust semantic profile lost its exact toolchain attestation: {properties}"
    );
    for field in [
        "build_scripts_executed",
        "proc_macros_executed",
        "project_code_executed",
        "project_toolchain_executed",
    ] {
        ensure!(
            properties[field] == false,
            "Rust semantic profile unexpectedly enabled {field}: {properties}"
        );
    }
    ensure!(
        properties["proc_macro_expansion"] == "disabled"
            && properties["rust_hir_semantic_node_count"]
                .as_u64()
                .is_some_and(|count| count > 0)
            && properties["rust_hir_semantic_site_count"]
                .as_u64()
                .is_some_and(|count| count > 0)
            && properties["rust_hir_semantic_relation_count"]
                .as_u64()
                .is_some_and(|count| count > 0)
            && properties["rust_hir_semantic_call_site_count"] == 4,
        "Rust semantic profile lost its HIR completion counters: {properties}"
    );
    if expect_attested_sysroot {
        ensure!(
            properties["rust_hir_status"] == "import-type-call-graph-emitted"
                && properties["rust_hir_semantic_issue_count"] == 0
                && properties["rust_hir_sysroot_status"] == "attested"
                && properties["rust_hir_sysroot_crate_count"] == 3
                && properties["rust_hir_sysroot_file_count"]
                    .as_u64()
                    .is_some_and(|count| count > 0)
                && properties["rust_hir_project_external_count"] == 0,
            "packaged Rust profile lost its attested sysroot contract: {properties}"
        );
    } else {
        ensure!(
            properties["rust_hir_status"] == "import-type-call-graph-partial"
                && properties["rust_hir_semantic_issue_count"]
                    .as_u64()
                    .is_some_and(|count| count > 0)
                && properties["rust_hir_sysroot_status"] == "unavailable"
                && properties["rust_hir_sysroot_crate_count"] == 0
                && properties["rust_hir_sysroot_file_count"] == 0
                && properties["rust_hir_project_external_count"]
                    .as_u64()
                    .is_some_and(|count| count > 0),
            "development Rust profile unexpectedly claimed an attested sysroot: {properties}"
        );
    }
    ensure!(
        profile["coverage"] == graph["coverage"],
        "Rust profile coverage and aggregate coverage disagree"
    );
    Ok(())
}

fn assert_ledger(graph: &Value) -> Result<()> {
    let profiles = graph_array(graph, "profiles")?;
    let sites = graph_array(graph, "sites")?;
    let evidence = graph_array(graph, "evidence")?;
    let diagnostics = graph_array(graph, "diagnostics")?;
    let file_coverage = graph_array(graph, "file_coverage")?;
    let coverage = graph
        .get("coverage")
        .context("Rust semantic graph has no aggregate coverage")?;

    let mut statuses = BTreeMap::<&str, u64>::new();
    for site in sites {
        let status = required_str(site, "resolution_status", "dependency site")?;
        *statuses.entry(status).or_default() += 1;
    }
    for status in ["resolved", "candidates", "external", "unresolved"] {
        ensure!(
            coverage[status].as_u64().unwrap_or(u64::MAX)
                == statuses.get(status).copied().unwrap_or(0),
            "Rust semantic coverage count for {status} does not match dependency sites"
        );
    }
    ensure!(
        coverage["dependency_sites"].as_u64() == Some(sites.len() as u64)
            && coverage["profiles"].as_u64() == Some(profiles.len() as u64)
            && coverage["files_discovered"].as_u64()
                == Some(
                    coverage["files_analyzed"].as_u64().unwrap_or(0)
                        + coverage["files_skipped"].as_u64().unwrap_or(0),
                )
            && coverage["project_code_executed"] == false,
        "Rust semantic aggregate coverage ledger is not conserved: {coverage}"
    );
    for file in file_coverage {
        ensure!(
            file["discovered_sites"].as_u64()
                == Some(
                    file["emitted_sites"].as_u64().unwrap_or(u64::MAX)
                        + file["skipped_sites"].as_u64().unwrap_or(u64::MAX),
                ),
            "Rust semantic file coverage ledger is not conserved: {file}"
        );
    }
    ensure!(
        evidence.iter().any(|item| {
            item["kind"] == "semantic"
                && item["extractor"] == "rust-analyzer-hir"
                && item["extractor_version"] == RUST_ANALYZER_VERSION
                && item["properties"]["rust_analyzer_revision"] == RUST_ANALYZER_REVISION
        }),
        "Rust semantic graph has no pinned rust-analyzer evidence"
    );
    for required in [
        "CARGO_METADATA_FROZEN",
        "RUST_HIR_PROJECT_MODEL_READY",
        "RUST_HIR_SEMANTIC_GRAPH_READY",
        "SAFE_SCAN",
    ] {
        ensure!(
            diagnostics.iter().any(|item| item["code"] == required),
            "Rust semantic diagnostics are missing {required}"
        );
    }
    ensure!(
        diagnostics.iter().all(|item| {
            item["code"] != "RUST_HIR_BACKEND_FAILURE" && item["severity"] != "error"
        }),
        "Rust semantic release gate retained a backend failure/error diagnostic: {diagnostics:?}"
    );
    Ok(())
}

fn assert_normalized_paths(graph: &Value) -> Result<()> {
    for item in graph_array(graph, "evidence")? {
        if let Some(path) = item["path"].as_str() {
            assert_normalized_relative_path(path, "evidence")?;
        }
    }
    for item in graph_array(graph, "diagnostics")? {
        if let Some(path) = item["path"].as_str() {
            assert_normalized_relative_path(path, "diagnostic")?;
        }
    }
    for item in graph_array(graph, "file_coverage")? {
        assert_normalized_relative_path(
            required_str(item, "path", "file coverage")?,
            "file coverage",
        )?;
    }
    for node in graph_array(graph, "nodes")? {
        if let Some(path) = node["properties"]["source_path"].as_str() {
            assert_normalized_relative_path(path, "semantic node source")?;
        }
    }
    Ok(())
}

fn assert_normalized_relative_path(path: &str, context: &str) -> Result<()> {
    ensure!(
        !path.is_empty() && !Path::new(path).is_absolute() && !path.contains('\\'),
        "Rust semantic {context} path is not canonical repository-relative UTF-8: {path:?}"
    );
    Ok(())
}

struct FixtureIds {
    main_file: String,
    package: String,
    build: String,
    transform: String,
    input: String,
    output: String,
    cycle_left: String,
    cycle_right: String,
    build_call: String,
    build_input: String,
    left_right_call: String,
    right_left_call: String,
    main_package_import: String,
}

fn assert_required_semantic_graph(
    graph: &Value,
    expect_attested_sysroot: bool,
) -> Result<FixtureIds> {
    let nodes = graph_array(graph, "nodes")?;
    let sites = graph_array(graph, "sites")?;
    let edges = graph_array(graph, "edges")?;
    let evidence = graph_array(graph, "evidence")?;

    let main_file = require_display_node(nodes, "file", "src/main.rs")?;
    let package = require_display_node(nodes, "package_instance", "rust-release-semantic-fixture")?;
    let build = require_node(nodes, "symbol", BUILD, "function")?;
    let transform = require_node(nodes, "symbol", TRANSFORM, "function")?;
    let input = require_node(nodes, "type", INPUT, "struct")?;
    let output = require_node(nodes, "type", OUTPUT, "struct")?;
    let cycle_left = require_node(nodes, "symbol", CYCLE_LEFT, "function")?;
    let cycle_right = require_node(nodes, "symbol", CYCLE_RIGHT, "function")?;
    let standard_call = require_node(nodes, "symbol", STANDARD_CALL, "function")?;
    let standard_types = require_node(nodes, "symbol", STANDARD_TYPES, "function")?;

    let build_call = require_edge(edges, &build, &transform, "calls")?;
    let build_input = require_edge(edges, &build, &input, "type_uses")?;
    require_edge(edges, &build, &output, "type_uses")?;
    require_edge(edges, &transform, &input, "type_uses")?;
    require_edge(edges, &transform, &output, "type_uses")?;
    let left_right_call = require_edge(edges, &cycle_left, &cycle_right, "calls")?;
    let right_left_call = require_edge(edges, &cycle_right, &cycle_left, "calls")?;
    let main_package_imports = edges
        .iter()
        .filter(|edge| {
            edge["source"] == main_file
                && edge["target"] == package
                && edge["kind"] == "imports"
                && edge["phase"] == "source"
                && edge["resolution_status"] == "resolved"
                && edge["precision"] == "exact"
        })
        .collect::<Vec<_>>();
    ensure!(
        main_package_imports.len() == 1,
        "src/main.rs must retain exactly one source-phase package import alongside HIR refinement: {main_package_imports:?}"
    );
    let main_package_import = main_package_imports[0];
    let main_package_site_id = required_str(main_package_import, "site_id", "main package import")?;
    let main_package_site = sites
        .iter()
        .find(|site| site["id"] == main_package_site_id)
        .context("main package import has no source dependency site")?;
    ensure!(
        main_package_site["source"] == main_file
            && main_package_site["kind"] == "rust_use"
            && main_package_site["target_ids"]
                .as_array()
                .is_some_and(|targets| {
                    targets.len() == 1 && targets[0] == Value::String(package.clone())
                })
            && evidence.iter().any(|item| {
                item["owner_type"] == "edge"
                    && item["owner_id"] == main_package_import["id"]
                    && item["kind"] == "source"
                    && item["extractor"] == "rust-static"
                    && item["path"] == "src/main.rs"
            }),
        "source package import lost its file owner, exact package target, or source evidence: edge={main_package_import}, site={main_package_site}"
    );
    let refined_main_imports = edges
        .iter()
        .filter(|edge| {
            edge["target"] == input
                && edge["kind"] == "imports"
                && edge["phase"] == "semantic"
                && edge["resolution_status"] == "resolved"
                && edge["precision"] == "exact"
        })
        .filter(|edge| {
            evidence.iter().any(|item| {
                item["owner_type"] == "edge"
                    && item["owner_id"] == edge["id"]
                    && item["kind"] == "semantic"
                    && item["extractor"] == "rust-analyzer-hir"
                    && item["path"] == "src/main.rs"
            })
        })
        .collect::<Vec<_>>();
    ensure!(
        refined_main_imports.len() == 1,
        "src/main.rs must have exactly one HIR-refined import for Input: {refined_main_imports:?}"
    );
    for edge in [build_call, build_input, left_right_call, right_left_call] {
        assert_dependency_edge_contract(edge, sites, evidence)?;
    }
    if expect_attested_sysroot {
        let semantic_edges = edges
            .iter()
            .filter(|edge| edge["phase"] == "semantic")
            .collect::<Vec<_>>();
        let semantic_dependency_edges = semantic_edges
            .iter()
            .filter(|edge| edge["site_id"].as_str().is_some())
            .collect::<Vec<_>>();
        ensure!(
            !semantic_edges.is_empty()
                && semantic_edges.iter().all(|edge| {
                    edge["resolution_status"] == "resolved" && edge["precision"] == "exact"
                })
                && !semantic_dependency_edges.is_empty()
                && semantic_dependency_edges.iter().all(|edge| {
                    edge["site_id"].as_str().is_some_and(|site_id| {
                        sites.iter().any(|site| {
                            site["id"] == site_id
                                && site["resolution_status"] == "resolved"
                                && site["precision"] == "exact"
                        })
                    })
                }),
            "packaged Rust graph did not exactly resolve every semantic-phase edge: {semantic_edges:?}"
        );
        let abort = require_sysroot_node(nodes, "symbol", "abort", "std")?;
        let vec = require_sysroot_node(nodes, "type", "Vec", "alloc")?;
        let string = require_sysroot_node(nodes, "type", "String", "alloc")?;
        let range = require_sysroot_node(nodes, "type", "Range", "core")?;
        for edge in [
            require_edge(edges, &standard_call, &abort, "calls")?,
            require_edge(edges, &standard_call, &vec, "type_uses")?,
            require_edge(edges, &standard_types, &string, "type_uses")?,
            require_edge(edges, &standard_types, &range, "type_uses")?,
        ] {
            assert_dependency_edge_contract(edge, sites, evidence)?;
        }
        for target in [&abort, &vec, &string, &range] {
            ensure!(
                sites.iter().any(|site| {
                    matches!(site["kind"].as_str(), Some("rust_use" | "extern_crate"))
                        && site["resolution_status"] == "resolved"
                        && site["precision"] == "exact"
                        && site["target_ids"]
                            .as_array()
                            .is_some_and(|targets| targets.iter().any(|id| id == target))
                }),
                "attested sysroot target {target} has no exact import site"
            );
        }
    }

    Ok(FixtureIds {
        main_file,
        package,
        build,
        transform,
        input,
        output,
        cycle_left,
        cycle_right,
        build_call: required_str(build_call, "id", "build call edge")?.to_owned(),
        build_input: required_str(build_input, "id", "build input edge")?.to_owned(),
        left_right_call: required_str(left_right_call, "id", "left cycle edge")?.to_owned(),
        right_left_call: required_str(right_left_call, "id", "right cycle edge")?.to_owned(),
        main_package_import: required_str(main_package_import, "id", "main package import edge")?
            .to_owned(),
    })
}

fn require_display_node(nodes: &[Value], kind: &str, display_name: &str) -> Result<String> {
    let matches = nodes
        .iter()
        .filter(|node| node["kind"] == kind && node["display_name"] == display_name)
        .collect::<Vec<_>>();
    ensure!(
        matches.len() == 1,
        "expected exactly one {kind} node named {display_name}, found {}: {matches:?}",
        matches.len()
    );
    let node = matches[0];
    Ok(required_str(node, "id", display_name)?.to_owned())
}

fn require_sysroot_node(
    nodes: &[Value],
    kind: &str,
    display_name: &str,
    crate_name: &str,
) -> Result<String> {
    let node = nodes
        .iter()
        .find(|node| {
            node["kind"] == kind
                && node["display_name"] == display_name
                && node["properties"]["bundled_sysroot"] == true
                && node["properties"]["crate_identity"] == format!("rust-sysroot#{crate_name}")
                && node["properties"]["external"] == false
        })
        .with_context(|| {
            format!("missing exact bundled sysroot {kind} node {crate_name}::{display_name}")
        })?;
    Ok(required_str(node, "id", display_name)?.to_owned())
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
        .with_context(|| format!("missing Rust semantic {kind} node {resolver_identity}"))?;
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
) -> Result<&'a Value> {
    edges
        .iter()
        .find(|edge| {
            edge["source"] == source
                && edge["target"] == target
                && edge["kind"] == kind
                && edge["phase"] == "semantic"
                && edge["resolution_status"] == "resolved"
                && edge["precision"] == "exact"
        })
        .with_context(|| format!("missing exact Rust semantic {kind} edge {source} -> {target}"))
}

fn assert_dependency_edge_contract(
    edge: &Value,
    sites: &[Value],
    evidence: &[Value],
) -> Result<()> {
    let edge_id = required_str(edge, "id", "semantic dependency edge")?;
    let site_id = required_str(edge, "site_id", "semantic dependency edge")?;
    let site = sites
        .iter()
        .find(|site| site["id"] == site_id)
        .with_context(|| format!("semantic edge {edge_id} has no dependency site {site_id}"))?;
    ensure!(
        site["source"] == edge["source"]
            && site["resolution_status"] == "resolved"
            && site["precision"] == "exact"
            && site["target_ids"]
                .as_array()
                .is_some_and(|targets| targets.iter().any(|target| target == &edge["target"])),
        "semantic edge/site contract diverged: edge={edge}, site={site}"
    );
    for (owner_type, owner_id) in [("edge", edge_id), ("site", site_id)] {
        let item = evidence
            .iter()
            .find(|item| {
                item["owner_type"] == owner_type
                    && item["owner_id"] == owner_id
                    && item["kind"] == "semantic"
                    && item["extractor"] == "rust-analyzer-hir"
            })
            .with_context(|| {
                format!("{owner_type} {owner_id} has no rust-analyzer semantic evidence")
            })?;
        ensure!(
            item["extractor_version"] == RUST_ANALYZER_VERSION
                && item["properties"]["rust_analyzer_revision"] == RUST_ANALYZER_REVISION
                && item["properties"]["backend"] == "rust-analyzer-library"
                && item["path"] == "src/lib.rs"
                && item["start_line"].as_u64().unwrap_or(0) > 0
                && item["start_column"].as_u64().unwrap_or(0) > 0
                && item["end_line"].as_u64().unwrap_or(0) > 0
                && item["end_column"].as_u64().unwrap_or(0) > 0,
            "{owner_type} {owner_id} has invalid pinned semantic evidence: {item}"
        );
    }
    Ok(())
}

fn verify_queries(
    runner: &Runner<'_>,
    first_store: &Path,
    second_store: &Path,
    ids: &FixtureIds,
) -> Result<()> {
    let file_deps = runner.query(
        first_store,
        &["deps", "path:src/main.rs", "--all", "--json"],
    )?;
    ensure!(
        file_deps["data"]["root"]["id"] == ids.main_file
            && file_deps["data"]["edges"]
                .as_array()
                .is_some_and(|edges| edges
                    .iter()
                    .any(|edge| edge["id"] == ids.main_package_import)),
        "Rust deps omitted the retained src/main.rs -> package import: {file_deps}"
    );

    let file_to_package = runner.query(
        first_store,
        &[
            "why",
            "path:src/main.rs",
            "package:rust-release-semantic-fixture",
            "--json",
        ],
    )?;
    ensure!(
        file_to_package["data"]["path_found"] == true
            && file_to_package["data"]["from"]["id"] == ids.main_file
            && file_to_package["data"]["to"]["id"] == ids.package
            && file_to_package["data"]["steps"]
                .as_array()
                .is_some_and(|steps| {
                    steps.len() == 1
                        && steps[0]["edge"]["id"] == ids.main_package_import
                        && steps[0]["edge"]["phase"] == "source"
                        && steps[0]["evidence"].as_array().is_some_and(|items| {
                            items.iter().any(|item| {
                                item["kind"] == "source"
                                    && item["extractor"] == "rust-static"
                                    && item["path"] == "src/main.rs"
                            })
                        })
                }),
        "Rust why did not retain src/main.rs -> package connectivity and source evidence: {file_to_package}"
    );

    let deps = runner.query(
        first_store,
        &["deps", &format!("symbol:{BUILD}"), "--all", "--json"],
    )?;
    ensure!(
        deps["data"]["root"]["id"] == ids.build && deps["data"]["root"]["kind"] == "symbol",
        "Rust symbol selector did not resolve build: {deps}"
    );
    for expected in [&ids.build_call, &ids.build_input] {
        assert_query_edge(&deps, expected)?;
    }

    let type_query = runner.query(
        first_store,
        &["deps", &format!("type:{INPUT}"), "--all", "--json"],
    )?;
    ensure!(
        type_query["data"]["root"]["id"] == ids.input
            && type_query["data"]["root"]["kind"] == "type",
        "Rust type selector did not resolve Input: {type_query}"
    );

    let dependents = runner.query(
        first_store,
        &["dependents", &format!("type:{INPUT}"), "--all", "--json"],
    )?;
    ensure!(
        dependents["data"]["root"]["id"] == ids.input
            && dependents["data"]["edges"]
                .as_array()
                .is_some_and(|edges| { edges.iter().any(|edge| edge["id"] == ids.build_input) }),
        "Rust dependents omitted build -> Input: {dependents}"
    );
    assert_query_edge(&dependents, &ids.build_input)?;

    let why = runner.query(
        first_store,
        &[
            "why",
            &format!("symbol:{BUILD}"),
            &format!("type:{INPUT}"),
            "--json",
        ],
    )?;
    ensure!(
        why["data"]["path_found"] == true
            && why["data"]["from"]["id"] == ids.build
            && why["data"]["to"]["id"] == ids.input
            && why["data"]["steps"].as_array().is_some_and(|steps| {
                steps.len() == 1
                    && steps[0]["edge"]["id"] == ids.build_input
                    && steps[0]["edge"]["kind"] == "type_uses"
                    && steps[0]["evidence"].as_array().is_some_and(|items| {
                        items.iter().any(|item| {
                            item["kind"] == "semantic" && item["extractor"] == "rust-analyzer-hir"
                        })
                    })
            }),
        "Rust why did not retain build -> Input semantic evidence: {why}"
    );

    let first_cycles = runner.query(first_store, &["cycles", "--level", "symbol", "--json"])?;
    let second_cycles = runner.query(second_store, &["cycles", "--level", "symbol", "--json"])?;
    ensure!(
        first_cycles["data"] == second_cycles["data"],
        "Rust symbol cycle query changed between scans"
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
                    && cycle["node_ids"].as_array().is_some_and(|nodes| {
                        nodes.len() == 3
                            && nodes[0] == start
                            && nodes[1] == other
                            && nodes[2] == start
                    })
            })
        }),
        "Rust cycles did not expose cycle_left/cycle_right: {first_cycles}"
    );
    Ok(())
}

fn assert_query_edge(query: &Value, expected_edge_id: &str) -> Result<()> {
    ensure!(
        query["data"]["edges"]
            .as_array()
            .is_some_and(|edges| edges.iter().any(|edge| edge["id"] == expected_edge_id)),
        "query omitted expected Rust semantic edge {expected_edge_id}: {query}"
    );
    ensure!(
        query["data"]["steps"].as_array().is_some_and(|steps| {
            steps.iter().any(|step| {
                step["edge"]["id"] == expected_edge_id
                    && step["edge"]["phase"] == "semantic"
                    && step["edge"]["resolution_status"] == "resolved"
                    && step["edge"]["precision"] == "exact"
                    && step["evidence"].as_array().is_some_and(|items| {
                        items.iter().any(|item| {
                            item["kind"] == "semantic"
                                && item["extractor"] == "rust-analyzer-hir"
                                && item["extractor_version"] == RUST_ANALYZER_VERSION
                                && item["properties"]["rust_analyzer_revision"]
                                    == RUST_ANALYZER_REVISION
                        })
                    })
            })
        }),
        "query omitted pinned semantic evidence for edge {expected_edge_id}: {query}"
    );
    Ok(())
}

fn assert_visual_exports(graph: &Value, ids: &FixtureIds, dot: &str, mermaid: &str) -> Result<()> {
    ensure!(
        dot.starts_with("digraph depgraph {\n") && mermaid.starts_with("flowchart LR\n"),
        "Rust semantic visual exports have invalid headers"
    );
    let nodes = graph_array(graph, "nodes")?;
    let edges = graph_array(graph, "edges")?;
    let indexes = nodes
        .iter()
        .enumerate()
        .filter_map(|(index, node)| Some((node["id"].as_str()?, index)))
        .collect::<BTreeMap<_, _>>();

    for id in [
        &ids.build,
        &ids.transform,
        &ids.input,
        &ids.output,
        &ids.cycle_left,
        &ids.cycle_right,
    ] {
        let node = nodes
            .iter()
            .find(|node| node["id"] == id.as_str())
            .with_context(|| format!("visual export node {id} is missing from JSON"))?;
        let display_name = required_str(node, "display_name", "visual export node")?;
        let kind = required_str(node, "kind", "visual export node")?;
        let dot_line = format!(
            "  \"{}\" [label=\"{}\\n({})\"];",
            dot_escape(id),
            dot_escape(display_name),
            dot_escape(kind)
        );
        ensure!(
            dot.lines().any(|line| line == dot_line),
            "DOT export omitted exact node declaration {dot_line}"
        );
        let index = indexes
            .get(id.as_str())
            .with_context(|| format!("Mermaid alias is missing for {id}"))?;
        let mermaid_line = format!(
            "  n{index}[\"{}\\n({})\"]",
            mermaid_escape(display_name),
            mermaid_escape(kind)
        );
        ensure!(
            mermaid.lines().any(|line| line == mermaid_line),
            "Mermaid export omitted exact node declaration {mermaid_line}"
        );
    }

    for edge_id in [
        &ids.build_call,
        &ids.build_input,
        &ids.left_right_call,
        &ids.right_left_call,
    ] {
        let edge = edges
            .iter()
            .find(|edge| edge["id"] == edge_id.as_str())
            .with_context(|| format!("visual export edge {edge_id} is missing from JSON"))?;
        let source = required_str(edge, "source", "visual export edge")?;
        let target = required_str(edge, "target", "visual export edge")?;
        let label = visual_edge_label(edge)?;
        let dot_line = format!(
            "  \"{}\" -> \"{}\" [label=\"{}\"];",
            dot_escape(source),
            dot_escape(target),
            dot_escape(&label)
        );
        ensure!(
            dot.lines().any(|line| line == dot_line),
            "DOT export omitted exact edge declaration {dot_line}"
        );
        let source_index = indexes
            .get(source)
            .with_context(|| format!("Mermaid source alias is missing for {source}"))?;
        let target_index = indexes
            .get(target)
            .with_context(|| format!("Mermaid target alias is missing for {target}"))?;
        let mermaid_line = format!(
            "  n{source_index} -->|\"{}\"| n{target_index}",
            mermaid_escape(&label)
        );
        ensure!(
            mermaid.lines().any(|line| line == mermaid_line),
            "Mermaid export omitted exact edge declaration {mermaid_line}"
        );
    }
    Ok(())
}

fn visual_edge_label(edge: &Value) -> Result<String> {
    Ok(format!(
        "{} [{}; {}; {}; {}; {}]",
        required_str(edge, "kind", "visual export edge")?,
        required_str(edge, "phase", "visual export edge")?,
        required_str(edge, "resolution_status", "visual export edge")?,
        required_str(edge, "precision", "visual export edge")?,
        required_str(edge, "profile_id", "visual export edge")?,
        required_str(edge, "condition_text", "visual export edge")?
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

fn graph_array<'a>(graph: &'a Value, field: &str) -> Result<&'a [Value]> {
    graph
        .get(field)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .with_context(|| format!("Rust semantic graph has no {field} array"))
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
            "failed to create Rust semantic fixture directory {}",
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
                    "failed to copy Rust semantic fixture file {} to {}",
                    entry.path().display(),
                    target.display()
                )
            })?;
        } else {
            bail!(
                "unsupported entry in Rust semantic E2E fixture: {}",
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
    use super::*;

    #[test]
    fn fixture_resolver_constants_share_the_release_crate_key() {
        for identity in [BUILD, TRANSFORM, INPUT, OUTPUT, CYCLE_LEFT, CYCLE_RIGHT] {
            assert!(identity.starts_with(CRATE_KEY));
        }
    }

    #[test]
    fn development_and_packaged_gate_selection_is_unambiguous() {
        assert_eq!(
            expected_release_gate(Some(Path::new("worker"))),
            "release-gate-pending"
        );
        assert_eq!(expected_release_gate(None), "release-gate-verified");
    }

    #[test]
    fn display_node_lookup_rejects_ambiguous_matches() {
        let nodes = [
            serde_json::json!({"id": "file:one", "kind": "file", "display_name": "src/main.rs"}),
            serde_json::json!({"id": "file:two", "kind": "file", "display_name": "src/main.rs"}),
        ];

        let error = require_display_node(&nodes, "file", "src/main.rs").unwrap_err();

        assert!(
            error
                .to_string()
                .contains("expected exactly one file node named src/main.rs, found 2")
        );
    }
}
