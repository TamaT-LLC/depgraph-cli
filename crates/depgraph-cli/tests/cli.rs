use std::{fs, path::Path};

use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::json;

fn run_git(root: &std::path::Path, arguments: &[&str]) -> String {
    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(root)
        .args(arguments)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git {:?}: {}",
        arguments,
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

fn seed_safe_rust_scan(
    store_path: &std::path::Path,
    root: &std::path::Path,
    app_manifest_path: &str,
) {
    let mut store = depgraph_store::Store::open(store_path).unwrap();
    store.start_scan("safe-rust-scan", root, false).unwrap();
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
            "scan_id": "safe-rust-scan",
            "adapter": "rust",
            "adapter_version": "0.1.0",
            "seq": seq
        })
    };
    let mut events = Vec::new();
    let mut started = common("scan_started", 1);
    started["root"] = json!(root.to_string_lossy());
    started["project_code_executed"] = json!(false);
    started["safe_mode"] = json!(true);
    events.push(started);
    let mut profile = common("profile_declared", 2);
    profile["profile"] = json!({
        "id": "rust:safe",
        "language": "rust",
        "features": [],
        "environment": {},
        "properties": {"project_code_executed": false}
    });
    events.push(profile);
    for (seq, node) in [
        json!({
            "id": "package:app", "kind": "package_instance", "locator": "cargo:app@0.1.0",
            "display_name": "supervisor-fixture",
            "properties": {
                "ecosystem": "cargo", "name": "supervisor-fixture", "version": "0.1.0",
                "manifest_path": app_manifest_path, "safe_marker": "preserved"
            }
        }),
        json!({
            "id": "package:macro", "kind": "package_instance", "locator": "cargo:fixture-macro@0.1.0",
            "display_name": "fixture-macro",
            "properties": {
                "ecosystem": "cargo", "name": "fixture-macro", "version": "0.1.0",
                "manifest_path": "macro/Cargo.toml"
            }
        }),
    ]
    .into_iter()
    .enumerate()
    {
        let mut event = common("node_upsert", seq as u64 + 3);
        event["node"] = node;
        events.push(event);
    }
    let mut profile_completed = common("profile_completed", 5);
    profile_completed["profile_id"] = json!("rust:safe");
    profile_completed["coverage"] = coverage.clone();
    events.push(profile_completed);
    let mut completed = common("scan_completed", 6);
    completed["coverage"] = coverage;
    events.push(completed);
    for event in &events {
        store.ingest_event(event).unwrap();
    }
    store
        .finish_scan("safe-rust-scan", "completed", None, true)
        .unwrap();
}

fn seed_runtime_trace_snapshot(store_path: &Path, root: &Path) {
    let mut store = depgraph_store::Store::open(store_path).unwrap();
    store
        .start_scan_with_revision("runtime-base", root, false, Some("abc123"))
        .unwrap();
    let coverage = json!({
        "profiles": 1,
        "files_discovered": 0,
        "files_analyzed": 0,
        "files_skipped": 0,
        "dependency_sites": 1,
        "resolved": 1,
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
            "scan_id": "runtime-base",
            "adapter": "fixture",
            "adapter_version": "1.0",
            "seq": seq
        })
    };
    let mut started = common("scan_started", 1);
    started["root"] = json!(root.to_string_lossy());
    started["project_code_executed"] = json!(false);
    started["safe_mode"] = json!(true);
    store.ingest_event(&started).unwrap();

    let mut profile = common("profile_declared", 2);
    profile["profile"] = json!({
        "id": "profile:web",
        "language": "typescript",
        "target": "server",
        "features": ["next"],
        "environment": {"mode":"production"},
        "source_revision": "abc123",
        "properties": {}
    });
    store.ingest_event(&profile).unwrap();

    for (offset, node) in [
        json!({
            "id":"workspace:web",
            "kind":"workspace",
            "locator":"workspace://repository:test",
            "display_name":"fixture",
            "properties":{"repository_identity":"repository:test"}
        }),
        json!({
            "id":"file:server",
            "kind":"file",
            "locator":"file://src/server.ts",
            "display_name":"server.ts",
            "properties":{"path":"src/server.ts"}
        }),
        json!({
            "id":"route:users",
            "kind":"route",
            "locator":"framework-route:/api/users",
            "display_name":"/api/users",
            "properties":{}
        }),
    ]
    .into_iter()
    .enumerate()
    {
        let mut event = common("node_upsert", offset as u64 + 3);
        event["node"] = node;
        store.ingest_event(&event).unwrap();
    }
    let evidence = json!([{
        "kind":"source","extractor":"fixture","extractor_version":"1.0",
        "path":"src/server.ts","start_line":1,"start_column":1,
        "end_line":1,"end_column":8,"detail":"static dependency","properties":{}
    }]);
    let mut site = common("dependency_site", 6);
    site["site"] = json!({
        "id":"site:static","source":"file:server","kind":"import",
        "specifier":"framework-route:/api/users","resolution_status":"resolved",
        "target_ids":["route:users"],"profile_id":"profile:web",
        "condition":{"op":"true"},"precision":"exact","reason":null,
        "evidence":evidence
    });
    store.ingest_event(&site).unwrap();
    let mut edge = common("edge_upsert", 7);
    edge["edge"] = json!({
        "id":"edge:static","source":"file:server","target":"route:users",
        "kind":"imports","site_id":"site:static","phase":"source",
        "environment":"production","profile_id":"profile:web",
        "condition":{"op":"true"},"resolution_status":"resolved",
        "precision":"exact","generated":false,"evidence":evidence
    });
    store.ingest_event(&edge).unwrap();
    let mut profile_completed = common("profile_completed", 8);
    profile_completed["profile_id"] = json!("profile:web");
    profile_completed["coverage"] = coverage.clone();
    store.ingest_event(&profile_completed).unwrap();
    let mut completed = common("scan_completed", 9);
    completed["coverage"] = coverage;
    store.ingest_event(&completed).unwrap();
    store
        .finish_scan("runtime-base", "completed", None, true)
        .unwrap();
}

fn seed_bounded_query_snapshot(store_path: &Path, root: &Path) {
    let mut store = depgraph_store::Store::open(store_path).unwrap();
    store
        .start_scan_with_revision("query-base", root, false, Some("query-revision"))
        .unwrap();
    let coverage = json!({
        "profiles": 1,
        "files_discovered": 0,
        "files_analyzed": 0,
        "files_skipped": 0,
        "dependency_sites": 2,
        "resolved": 2,
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
            "scan_id": "query-base",
            "adapter": "fixture",
            "adapter_version": "1.0",
            "seq": seq
        })
    };
    let mut started = common("scan_started", 1);
    started["root"] = json!(root.to_string_lossy());
    started["project_code_executed"] = json!(false);
    started["safe_mode"] = json!(true);
    store.ingest_event(&started).unwrap();

    let mut profile = common("profile_declared", 2);
    profile["profile"] = json!({
        "id": "profile:web",
        "language": "typescript",
        "target": "server",
        "features": [],
        "environment": {"mode":"production"},
        "source_revision": "query-revision",
        "properties": {}
    });
    store.ingest_event(&profile).unwrap();

    for (offset, node) in [
        json!({
            "id":"workspace:apps",
            "kind":"workspace",
            "locator":"workspace://apps",
            "display_name":"apps",
            "properties":{"path":"apps"}
        }),
        json!({
            "id":"workspace:services",
            "kind":"workspace",
            "locator":"workspace://services",
            "display_name":"services",
            "properties":{"path":"services"}
        }),
        json!({
            "id":"file:client",
            "kind":"file",
            "locator":"file://apps/client.ts",
            "display_name":"client.ts",
            "properties":{"path":"apps/client.ts","workspace_id":"workspace:apps"}
        }),
        json!({
            "id":"file:server",
            "kind":"file",
            "locator":"file://services/server.ts",
            "display_name":"server.ts",
            "properties":{"path":"services/server.ts","workspace_id":"workspace:services"}
        }),
        json!({
            "id":"route:users",
            "kind":"route",
            "locator":"framework-route:/api/users",
            "display_name":"/api/users",
            "properties":{"workspace_id":"workspace:services"}
        }),
    ]
    .into_iter()
    .enumerate()
    {
        let mut event = common("node_upsert", offset as u64 + 3);
        event["node"] = node;
        store.ingest_event(&event).unwrap();
    }

    let condition = json!({
        "op":"all",
        "conditions":[{"op":"eq","key":"mode","value":"production"}]
    });
    let client_evidence = json!([{
        "kind":"source","extractor":"fixture","extractor_version":"1.0",
        "path":"apps/client.ts","start_line":1,"start_column":1,
        "end_line":1,"end_column":16,"detail":"private client detail","properties":{"private":true}
    }]);
    let mut client_site = common("dependency_site", 8);
    client_site["site"] = json!({
        "id":"site:client-server","source":"file:client","kind":"call",
        "specifier":"services/server","resolution_status":"resolved",
        "target_ids":["file:server"],"profile_id":"profile:web",
        "condition":condition,"precision":"exact","reason":"workspace-call",
        "evidence":client_evidence
    });
    store.ingest_event(&client_site).unwrap();
    let mut client_edge = common("edge_upsert", 9);
    client_edge["edge"] = json!({
        "id":"edge:client-server","source":"file:client","target":"file:server",
        "kind":"calls","site_id":"site:client-server","phase":"semantic",
        "environment":"production","profile_id":"profile:web",
        "condition":condition,"resolution_status":"resolved",
        "precision":"exact","generated":false,"evidence":client_evidence
    });
    store.ingest_event(&client_edge).unwrap();

    let server_evidence = json!([{
        "kind":"source","extractor":"fixture","extractor_version":"1.0",
        "path":"services/server.ts","start_line":2,"start_column":1,
        "end_line":2,"end_column":20,"detail":"private server detail","properties":{"private":true}
    }]);
    let mut server_site = common("dependency_site", 10);
    server_site["site"] = json!({
        "id":"site:server-route","source":"file:server","kind":"import",
        "specifier":"framework-route:/api/users","resolution_status":"resolved",
        "target_ids":["route:users"],"profile_id":"profile:web",
        "condition":condition,"precision":"exact","reason":null,
        "evidence":server_evidence
    });
    store.ingest_event(&server_site).unwrap();
    let mut server_edge = common("edge_upsert", 11);
    server_edge["edge"] = json!({
        "id":"edge:server-route","source":"file:server","target":"route:users",
        "kind":"imports","site_id":"site:server-route","phase":"source",
        "environment":"production","profile_id":"profile:web",
        "condition":condition,"resolution_status":"resolved",
        "precision":"exact","generated":false,"evidence":server_evidence
    });
    store.ingest_event(&server_edge).unwrap();

    let mut profile_completed = common("profile_completed", 12);
    profile_completed["profile_id"] = json!("profile:web");
    profile_completed["coverage"] = coverage.clone();
    store.ingest_event(&profile_completed).unwrap();
    let mut completed = common("scan_completed", 13);
    completed["coverage"] = coverage;
    store.ingest_event(&completed).unwrap();
    store
        .finish_scan("query-base", "completed", None, true)
        .unwrap();
}

const BOUNDED_QUERY_CLI_FIXTURE: &str = r#"MATCH p = (source:"file")-["calls"|"imports"*1..2]->(target:"route")
WHERE EVERY edge IN EDGES(p) SATISFIES
        edge.profile_id = "profile:web"
        AND edge.phase IN ["semantic", "source"]
        AND edge.condition STARTS WITH "mode"
  AND SOME site IN SITES(p) SATISFIES
        site.specifier STARTS WITH "services/"
  AND SOME evidence IN EVIDENCE(p) SATISFIES
        evidence.path STARTS WITH "apps/"
  AND source.locator STARTS WITH "file://apps/"
RETURN source.id, target.id, p
ORDER BY source.id, target.id, p ASC
LIMIT 10"#;

#[test]
fn bounded_query_cli_is_read_only_canonical_and_filters_closed_evidence() {
    let root = tempfile::tempdir().unwrap();
    let other_checkout = tempfile::tempdir().unwrap();
    let store_path = root.path().join("query.sqlite");
    seed_bounded_query_snapshot(&store_path, root.path());
    let before = fs::read(&store_path).unwrap();

    let _writer_lock = depgraph_core::acquire_store_writer_lock(&store_path).unwrap();
    let first = Command::cargo_bin("depgraph")
        .unwrap()
        .current_dir(root.path())
        .arg("--store")
        .arg(&store_path)
        .args(["query", "--query", BOUNDED_QUERY_CLI_FIXTURE, "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let second = Command::cargo_bin("depgraph")
        .unwrap()
        .current_dir(other_checkout.path())
        .arg("--store")
        .arg(&store_path)
        .args(["query", "--query", BOUNDED_QUERY_CLI_FIXTURE, "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert_eq!(first, second);
    let selected = Command::cargo_bin("depgraph")
        .unwrap()
        .current_dir(root.path())
        .arg("--store")
        .arg(&store_path)
        .args([
            "--scan-id",
            "query-base",
            "query",
            "--query",
            BOUNDED_QUERY_CLI_FIXTURE,
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert_eq!(first, selected);
    let rendered = String::from_utf8(first).unwrap();
    let value: serde_json::Value = serde_json::from_str(&rendered).unwrap();
    assert_eq!(rendered.trim(), depgraph_protocol::canonical_json(&value));
    assert_eq!(value["schema_version"], "bounded-query-result-v1");
    assert_eq!(value["complete"], true);
    assert_eq!(value["rows"].as_array().unwrap().len(), 1);
    assert_eq!(value["rows"][0][0], "file:client");
    assert_eq!(value["rows"][0][1], "route:users");
    assert_eq!(
        value["rows"][0][2]["nodes"][0]["locator"],
        "file://apps/client.ts"
    );
    assert_eq!(
        value["rows"][0][2]["nodes"][1]["locator"],
        "file://services/server.ts"
    );
    assert_eq!(value["rows"][0][2]["edges"].as_array().unwrap().len(), 2);
    assert_eq!(value["rows"][0][2]["edges"][0]["profile_id"], "profile:web");
    assert_eq!(value["rows"][0][2]["edges"][0]["phase"], "semantic");
    assert_eq!(value["rows"][0][2]["edges"][1]["phase"], "source");
    assert_eq!(value["rows"][0][2]["sites"][0]["id"], "site:client-server");
    assert_eq!(value["rows"][0][2]["evidence"][0]["path"], "apps/client.ts");
    assert!(
        value["result_digest"]
            .as_str()
            .unwrap()
            .starts_with("bounded-query-result:sha256:")
    );
    assert!(!rendered.contains("private client detail"));
    assert!(!rendered.contains("\"properties\""));
    assert_eq!(fs::read(&store_path).unwrap(), before);
    drop(_writer_lock);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        let original = fs::metadata(&store_path).unwrap().permissions();
        let mut read_only = original.clone();
        read_only.set_mode(0o444);
        fs::set_permissions(&store_path, read_only).unwrap();
        Command::cargo_bin("depgraph")
            .unwrap()
            .current_dir(root.path())
            .arg("--store")
            .arg(&store_path)
            .args(["query", "--query", BOUNDED_QUERY_CLI_FIXTURE, "--json"])
            .assert()
            .success();
        fs::set_permissions(&store_path, original).unwrap();
    }

    Command::cargo_bin("depgraph")
        .unwrap()
        .current_dir(root.path())
        .arg("--store")
        .arg(&store_path)
        .args(["query", "--query", BOUNDED_QUERY_CLI_FIXTURE])
        .assert()
        .success()
        .stdout(predicate::str::contains("query: complete"))
        .stdout(predicate::str::contains("source.id: \"file:client\""))
        .stdout(predicate::str::contains("\"owner_type\":\"edge\""))
        .stdout(predicate::str::contains(
            "result: bounded-query-result:sha256:",
        ));
}

#[test]
fn bounded_query_file_explain_and_failure_exit_contracts_are_stable() {
    let root = tempfile::tempdir().unwrap();
    let store_path = root.path().join("query.sqlite");
    seed_bounded_query_snapshot(&store_path, root.path());
    fs::write(
        root.path().join("query.depgraph"),
        BOUNDED_QUERY_CLI_FIXTURE,
    )
    .unwrap();

    let explain = Command::cargo_bin("depgraph")
        .unwrap()
        .current_dir(root.path())
        .arg("--store")
        .arg(&store_path)
        .args(["query", "--file", "query.depgraph", "--explain", "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let explain = String::from_utf8(explain).unwrap();
    let plan: serde_json::Value = serde_json::from_str(&explain).unwrap();
    assert_eq!(explain.trim(), depgraph_protocol::canonical_json(&plan));
    assert_eq!(plan["schema_version"], "bounded-query-plan-v1");
    assert_eq!(plan["admitted"], true);
    assert!(
        plan["plan_digest"]
            .as_str()
            .unwrap()
            .starts_with("bounded-query-plan:sha256:")
    );
    let redacted_shape = depgraph_protocol::canonical_json(&plan["redacted_typed_ast_shape"]);
    assert!(!redacted_shape.contains("profile:web"));
    assert!(!redacted_shape.contains("src/"));

    let empty = r#"MATCH p = (source:"missing")-["imports"*1..1]->(target:"route")
                    RETURN target.id LIMIT 1"#;
    Command::cargo_bin("depgraph")
        .unwrap()
        .current_dir(root.path())
        .arg("--store")
        .arg(&store_path)
        .args(["query", "--query", empty, "--json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"complete\":true"))
        .stdout(predicate::str::contains("\"rows\":[]"));

    let existential_terms = (0..16)
        .map(|index| {
            format!(
                "SOME evidence{index} IN EVIDENCE(p) SATISFIES evidence{index}.kind = \"source\""
            )
        })
        .collect::<Vec<_>>()
        .join(" AND ");
    let rejected = format!(
        "MATCH p = (source:\"file\")-[\"imports\"*1..8]->(target:\"route\") \
         WHERE {existential_terms} RETURN target.id LIMIT 1"
    );
    Command::cargo_bin("depgraph")
        .unwrap()
        .current_dir(root.path())
        .arg("--store")
        .arg(&store_path)
        .args(["query", "--query", &rejected])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("query_plan_budget_exceeded"))
        .stdout(predicate::str::is_empty());

    Command::cargo_bin("depgraph")
        .unwrap()
        .current_dir(root.path())
        .arg("--store")
        .arg(&store_path)
        .args([
            "query",
            "--query",
            r#"MATCH p = (source)-["imports"*1..1]->(target)
               WHERE source.unknown = "x" RETURN target.id LIMIT 1"#,
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("query_field_unknown"));

    Command::cargo_bin("depgraph")
        .unwrap()
        .current_dir(root.path())
        .arg("--store")
        .arg(root.path().join("missing.sqlite"))
        .args(["query", "--query", BOUNDED_QUERY_CLI_FIXTURE])
        .assert()
        .code(3)
        .stdout(predicate::str::is_empty());

    {
        let mut store = depgraph_store::Store::open(&store_path).unwrap();
        store
            .start_scan("failed-query-scan", root.path(), false)
            .unwrap();
        store
            .finish_scan(
                "failed-query-scan",
                "failed",
                Some("fixture failure"),
                false,
            )
            .unwrap();
    }
    Command::cargo_bin("depgraph")
        .unwrap()
        .current_dir(root.path())
        .arg("--store")
        .arg(&store_path)
        .args([
            "--scan-id",
            "failed-query-scan",
            "query",
            "--query",
            BOUNDED_QUERY_CLI_FIXTURE,
        ])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("query_snapshot_unavailable"))
        .stdout(predicate::str::is_empty());

    Command::cargo_bin("depgraph")
        .unwrap()
        .current_dir(root.path())
        .arg("--store")
        .arg(&store_path)
        .args(["query"])
        .assert()
        .code(2);
    Command::cargo_bin("depgraph")
        .unwrap()
        .current_dir(root.path())
        .arg("--store")
        .arg(&store_path)
        .args([
            "query",
            "--query",
            BOUNDED_QUERY_CLI_FIXTURE,
            "--file",
            "query.depgraph",
        ])
        .assert()
        .code(2);

    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(
            root.path().join("query.depgraph"),
            root.path().join("linked.depgraph"),
        )
        .unwrap();
        Command::cargo_bin("depgraph")
            .unwrap()
            .current_dir(root.path())
            .arg("--store")
            .arg(&store_path)
            .args(["query", "--file", "linked.depgraph"])
            .assert()
            .code(4)
            .stderr(predicate::str::contains("query_file_symlink_rejected"));
    }

    let credential = r#"MATCH p = (source)-["imports"*1..1]->(target)
                        WHERE source.id = "token=abcdefghijklmnopqrstuvwxyz123456"
                        RETURN target.id LIMIT 1"#;
    Command::cargo_bin("depgraph")
        .unwrap()
        .current_dir(root.path())
        .arg("--store")
        .arg(root.path().join("must-not-be-opened.sqlite"))
        .args(["query", "--query", credential])
        .assert()
        .code(4)
        .stderr(predicate::str::contains("query_literal_credential_shape"))
        .stderr(predicate::str::contains("abcdefghijklmnopqrstuvwxyz").not());
}

fn seed_cli_diff_snapshot(
    store_path: &std::path::Path,
    root: &std::path::Path,
    scan_id: &str,
    name: &str,
    target: bool,
) -> String {
    let mut store = depgraph_store::Store::open(store_path).unwrap();
    store
        .start_scan_with_revision(
            scan_id,
            root,
            false,
            Some(if target { "revision-2" } else { "revision-1" }),
        )
        .unwrap();
    let coverage = json!({
        "profiles": 1,
        "files_discovered": 0,
        "files_analyzed": 0,
        "files_skipped": 0,
        "dependency_sites": 1,
        "resolved": if target { 0 } else { 1 },
        "candidates": 0,
        "external": 0,
        "unresolved": if target { 1 } else { 0 },
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
    started["root"] = json!(root.to_string_lossy());
    started["project_code_executed"] = json!(false);
    started["safe_mode"] = json!(true);
    events.push(started);
    let mut profile = common("profile_declared", 2);
    profile["profile"] = json!({
        "id": "fixture:safe",
        "language": "go",
        "features": [],
        "environment": {"version": if target { 2 } else { 1 }},
        "properties": {}
    });
    events.push(profile);
    let shared = json!({
        "id": "file:shared",
        "kind": "file",
        "locator": "file:src/shared.go",
        "display_name": "src/shared.go",
        "properties": {"path": "src/shared.go", "version": if target { 2 } else { 1 }}
    });
    let moved = if target {
        json!({
            "id": "file:new",
            "kind": "file",
            "locator": "file:src/new.go",
            "display_name": "src/new.go",
            "properties": {
                "path": "src/new.go",
                "package_locator": "go:example.test/fixture",
                "content_hash": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            }
        })
    } else {
        json!({
            "id": "file:old",
            "kind": "file",
            "locator": "file:src/old.go",
            "display_name": "src/old.go",
            "properties": {
                "path": "src/old.go",
                "package_locator": "go:example.test/fixture",
                "content_hash": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            }
        })
    };
    let symbol = if target {
        json!({
            "id": "symbol:added",
            "kind": "symbol",
            "locator": "go:fixture#Added",
            "display_name": "Added",
            "properties": {}
        })
    } else {
        json!({
            "id": "symbol:removed",
            "kind": "symbol",
            "locator": "go:fixture#Removed",
            "display_name": "Removed",
            "properties": {}
        })
    };
    let unknown = json!({
        "id": "unknown:missing",
        "kind": "unknown_target",
        "locator": "unknown:example.test/dependency",
        "display_name": "example.test/dependency",
        "properties": {}
    });
    for (offset, node) in [shared, moved, symbol, unknown].into_iter().enumerate() {
        let mut event = common("node_upsert", offset as u64 + 3);
        event["node"] = node;
        events.push(event);
    }
    let (site_id, edge_id, phase, status, target_id, path, line) = if target {
        (
            "site:new",
            "edge:new",
            "semantic",
            "unresolved",
            "unknown:missing",
            "src/new.go",
            7,
        )
    } else {
        (
            "site:old",
            "edge:old",
            "source",
            "resolved",
            "file:shared",
            "src/old.go",
            3,
        )
    };
    let evidence = json!([{
        "kind": if target { "semantic" } else { "source" },
        "extractor": "fixture",
        "extractor_version": "1.0",
        "path": path,
        "start_line": line,
        "start_column": 1,
        "end_line": line,
        "end_column": 8,
        "detail": if target { "unresolved import" } else { "resolved import" },
        "properties": {}
    }]);
    let mut site = common("dependency_site", 7);
    site["site"] = json!({
        "id": site_id,
        "source": if target { "file:new" } else { "file:old" },
        "kind": "import",
        "specifier": "example.test/dependency",
        "resolution_status": status,
        "target_ids": [target_id],
        "profile_id": "fixture:safe",
        "condition": {"op": "all", "conditions": []},
        "precision": "exact",
        "reason": if target { Some("package_not_found") } else { None::<&str> },
        "evidence": evidence
    });
    events.push(site);
    let mut edge = common("edge_upsert", 8);
    edge["edge"] = json!({
        "id": edge_id,
        "source": if target { "file:new" } else { "file:old" },
        "target": target_id,
        "kind": "imports",
        "site_id": site_id,
        "phase": phase,
        "environment": "host",
        "profile_id": "fixture:safe",
        "condition": {"op": "all", "conditions": []},
        "resolution_status": status,
        "precision": "exact",
        "generated": false,
        "evidence": evidence
    });
    events.push(edge);
    let mut profile_completed = common("profile_completed", 9);
    profile_completed["profile_id"] = json!("fixture:safe");
    profile_completed["coverage"] = coverage.clone();
    events.push(profile_completed);
    let mut completed = common("scan_completed", 10);
    completed["coverage"] = coverage;
    events.push(completed);
    for event in events {
        store.ingest_event(&event).unwrap();
    }
    store.finish_scan(scan_id, "completed", None, true).unwrap();
    let snapshot_id = store
        .snapshot_id_for_source("scan", scan_id)
        .unwrap()
        .unwrap();
    store.create_snapshot_name(name, &snapshot_id).unwrap();
    snapshot_id
}

fn seed_policy_snapshot(
    store_path: &std::path::Path,
    root: &std::path::Path,
    scan_id: &str,
    name: &str,
    remove_public_api: bool,
) -> String {
    let mut store = depgraph_store::Store::open(store_path).unwrap();
    store
        .start_scan_with_revision(
            scan_id,
            root,
            false,
            Some(if remove_public_api {
                "policy-revision-2"
            } else {
                "policy-revision-1"
            }),
        )
        .unwrap();
    let coverage = json!({
        "profiles": 1,
        "files_discovered": 0,
        "files_analyzed": 0,
        "files_skipped": 0,
        "dependency_sites": if remove_public_api { 0 } else { 1 },
        "resolved": if remove_public_api { 0 } else { 1 },
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
    started["root"] = json!(root.to_string_lossy());
    started["project_code_executed"] = json!(false);
    started["safe_mode"] = json!(true);
    events.push(started);
    let mut profile = common("profile_declared", 2);
    profile["profile"] = json!({
        "id": "fixture:safe",
        "language": "go",
        "features": [],
        "environment": {"mode": "production"},
        "properties": {}
    });
    events.push(profile);
    let consumer = json!({
        "id": "symbol:consumer",
        "kind": "symbol",
        "locator": "go:fixture#Consumer",
        "display_name": "Consumer",
        "properties": {
            "profile_id": "fixture:safe",
            "source_path": "src/consumer.go",
            "source_span": {
                "start_line": 3,
                "start_column": 1,
                "end_line": 3,
                "end_column": 20
            }
        }
    });
    let public_api = json!({
        "id": "symbol:public-api",
        "kind": "symbol",
        "locator": "go:fixture#PublicAPI",
        "display_name": "PublicAPI",
        "properties": {
            "profile_id": "fixture:safe",
            "source_path": "src/public.go",
            "source_span": {
                "start_line": 5,
                "start_column": 1,
                "end_line": 5,
                "end_column": 24
            },
            "signature": "func PublicAPI() string"
        }
    });
    let mut seq = 3_u64;
    for node in std::iter::once(consumer).chain((!remove_public_api).then_some(public_api)) {
        let mut event = common("node_upsert", seq);
        event["node"] = node;
        events.push(event);
        seq += 1;
    }
    if !remove_public_api {
        let evidence = json!([{
            "kind": "source",
            "extractor": "fixture",
            "extractor_version": "1.0",
            "path": "src/consumer.go",
            "start_line": 3,
            "start_column": 1,
            "end_line": 3,
            "end_column": 20,
            "properties": {}
        }]);
        let mut site = common("dependency_site", seq);
        site["site"] = json!({
            "id": "site:consumer-public-api",
            "source": "symbol:consumer",
            "kind": "import",
            "specifier": "PublicAPI",
            "resolution_status": "resolved",
            "target_ids": ["symbol:public-api"],
            "profile_id": "fixture:safe",
            "condition": {"op": "all", "conditions": []},
            "precision": "exact",
            "evidence": evidence
        });
        events.push(site);
        seq += 1;
        let mut edge = common("edge_upsert", seq);
        edge["edge"] = json!({
            "id": "edge:consumer-public-api",
            "source": "symbol:consumer",
            "target": "symbol:public-api",
            "kind": "imports",
            "site_id": "site:consumer-public-api",
            "phase": "source",
            "environment": "host",
            "profile_id": "fixture:safe",
            "condition": {"op": "all", "conditions": []},
            "resolution_status": "resolved",
            "precision": "exact",
            "generated": false,
            "evidence": evidence
        });
        events.push(edge);
        seq += 1;
    }
    let mut profile_completed = common("profile_completed", seq);
    profile_completed["profile_id"] = json!("fixture:safe");
    profile_completed["coverage"] = coverage.clone();
    events.push(profile_completed);
    seq += 1;
    let mut completed = common("scan_completed", seq);
    completed["coverage"] = coverage;
    events.push(completed);
    for event in events {
        store.ingest_event(&event).unwrap();
    }
    store.finish_scan(scan_id, "completed", None, true).unwrap();
    let snapshot_id = store
        .snapshot_id_for_source("scan", scan_id)
        .unwrap()
        .unwrap();
    store.create_snapshot_name(name, &snapshot_id).unwrap();
    snapshot_id
}

fn seed_large_cli_diff_snapshot(
    store: &mut depgraph_store::Store,
    root: &std::path::Path,
    scan_id: &str,
    version: u64,
    node_count: usize,
) -> String {
    store
        .start_scan_with_revision(
            scan_id,
            root,
            false,
            Some(&format!("large-revision-{version}")),
        )
        .unwrap();
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
    let mut started = common("scan_started", 1);
    started["root"] = json!(root.to_string_lossy());
    started["project_code_executed"] = json!(false);
    started["safe_mode"] = json!(true);
    store.ingest_event(&started).unwrap();
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
    let mut profile = common("profile_declared", 2);
    profile["profile"] = json!({
        "id": "fixture:large",
        "language": "go",
        "features": [],
        "environment": {},
        "properties": {}
    });
    store.ingest_event(&profile).unwrap();
    for index in (0..node_count).rev() {
        let mut node = common("node_upsert", (node_count - index) as u64 + 2);
        node["node"] = json!({
            "id": format!("file:{index:05}"),
            "kind": "file",
            "locator": format!("file:src/{index:05}.go"),
            "display_name": format!("src/{index:05}.go"),
            "properties": {"version": version}
        });
        store.ingest_event(&node).unwrap();
    }
    let mut profile_completed = common("profile_completed", node_count as u64 + 3);
    profile_completed["profile_id"] = json!("fixture:large");
    profile_completed["coverage"] = coverage.clone();
    store.ingest_event(&profile_completed).unwrap();
    let mut completed = common("scan_completed", node_count as u64 + 4);
    completed["coverage"] = coverage;
    store.ingest_event(&completed).unwrap();
    store.finish_scan(scan_id, "completed", None, true).unwrap();
    store
        .snapshot_id_for_source("scan", scan_id)
        .unwrap()
        .unwrap()
}

#[test]
fn init_writes_only_the_versioned_config() {
    let root = tempfile::tempdir().unwrap();
    Command::cargo_bin("depgraph")
        .unwrap()
        .args(["init", root.path().to_str().unwrap()])
        .assert()
        .success();
    let config = fs::read_to_string(root.path().join(".depgraph.toml")).unwrap();
    assert!(config.contains("schema_version = 1"));
    assert!(!root.path().join(".depgraph").exists());
}

#[test]
fn runtime_validate_matches_golden_trace_without_mutating_the_store() {
    let root = tempfile::tempdir().unwrap();
    let cache = tempfile::tempdir().unwrap();
    let store_path = cache.path().join("graph.db");
    seed_runtime_trace_snapshot(&store_path, root.path());
    let trace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../depgraph-core/tests/fixtures/runtime-trace-v1.golden.json");

    let run = || {
        Command::cargo_bin("depgraph")
            .unwrap()
            .args([
                "--store",
                store_path.to_str().unwrap(),
                "runtime",
                "validate",
                trace.to_str().unwrap(),
                "--json",
            ])
            .output()
            .unwrap()
    };
    let first = run();
    let second = run();
    assert!(first.status.success(), "{:?}", first.stderr);
    assert_eq!(first.stdout, second.stdout);
    let output: serde_json::Value = serde_json::from_slice(&first.stdout).unwrap();
    assert_eq!(output["schema_version"], "1.0");
    assert_eq!(output["command"], "runtime.validate");
    assert_eq!(output["scan_id"], "runtime-base");
    assert_eq!(output["data"]["profile_match"]["status"], "resolved");
    assert_eq!(
        output["data"]["profile_match"]["parent_profile_id"],
        "profile:web"
    );
    assert_eq!(output["data"]["summary"]["events"], 3);
    assert_eq!(output["data"]["summary"]["resolved_targets"], 1);
    assert_eq!(output["data"]["summary"]["external_targets"], 1);
    assert_eq!(output["data"]["summary"]["unresolved_targets"], 1);
    assert_eq!(
        output["data"]["events"][0]["source"]["node_id"],
        "file:server"
    );
    assert_eq!(
        output["data"]["events"][0]["target"]["node_id"],
        "route:users"
    );
    assert!(
        output["data"]["events"][0]["id"]
            .as_str()
            .unwrap()
            .starts_with("runtime-event:sha256:")
    );
    assert!(
        !String::from_utf8(first.stdout)
            .unwrap()
            .contains(root.path().to_str().unwrap())
    );

    let store = depgraph_store::Store::open(&store_path).unwrap();
    assert_eq!(
        store.latest_successful_id().unwrap().as_deref(),
        Some("runtime-base")
    );
}

#[test]
fn node_reference_collector_trace_passes_runtime_validate_and_import() {
    let root = tempfile::tempdir().unwrap();
    let cache = tempfile::tempdir().unwrap();
    let store_path = cache.path().join("graph.db");
    seed_runtime_trace_snapshot(&store_path, root.path());
    let trace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../workers/web/test/fixtures/runtime-collector/next.expected.json");

    let validate = Command::cargo_bin("depgraph")
        .unwrap()
        .args([
            "--store",
            store_path.to_str().unwrap(),
            "runtime",
            "validate",
            trace.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        validate.status.success(),
        "{}",
        String::from_utf8_lossy(&validate.stderr)
    );
    let validate: serde_json::Value = serde_json::from_slice(&validate.stdout).unwrap();
    assert_eq!(validate["command"], "runtime.validate");
    assert_eq!(validate["data"]["summary"]["events"], 4);
    assert_eq!(validate["data"]["profile_match"]["status"], "resolved");

    let import = Command::cargo_bin("depgraph")
        .unwrap()
        .args([
            "--store",
            store_path.to_str().unwrap(),
            "runtime",
            "import",
            trace.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        import.status.success(),
        "{}",
        String::from_utf8_lossy(&import.stderr)
    );
    let import: serde_json::Value = serde_json::from_slice(&import.stdout).unwrap();
    assert_eq!(import["command"], "runtime.import");
    assert_eq!(import["data"]["deduplicated"], false);
    assert!(
        import["data"]["session_id"]
            .as_str()
            .unwrap()
            .starts_with("runtime-session:sha256:")
    );
    let snapshot_id = import["data"]["snapshot_id"].as_str().unwrap();
    let snapshot = depgraph_store::Store::open(&store_path)
        .unwrap()
        .load_completed_snapshot(snapshot_id)
        .unwrap();
    assert_eq!(
        snapshot
            .edges
            .iter()
            .filter(|edge| edge.phase == "runtime")
            .count(),
        4
    );
    assert!(snapshot.evidence.iter().any(|evidence| {
        evidence
            .properties
            .get("source_session_id")
            .and_then(serde_json::Value::as_str)
            == Some("next-runtime-001")
    }));
}

#[test]
fn runtime_import_is_atomic_deduplicated_queryable_and_deterministic() {
    let root = tempfile::tempdir().unwrap();
    let cache = tempfile::tempdir().unwrap();
    let store_path = cache.path().join("graph.db");
    seed_runtime_trace_snapshot(&store_path, root.path());
    let trace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../depgraph-core/tests/fixtures/runtime-trace-v1.golden.json");
    let base_snapshot_id = depgraph_store::Store::open(&store_path)
        .unwrap()
        .current_snapshot_id()
        .unwrap()
        .unwrap();

    let import = || {
        Command::cargo_bin("depgraph")
            .unwrap()
            .args([
                "--store",
                store_path.to_str().unwrap(),
                "runtime",
                "import",
                trace.to_str().unwrap(),
                "--json",
            ])
            .output()
            .unwrap()
    };
    let first = import();
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let first_json: serde_json::Value = serde_json::from_slice(&first.stdout).unwrap();
    assert_eq!(first_json["command"], "runtime.import");
    assert_eq!(first_json["scan_id"], "runtime-base");
    assert_eq!(first_json["data"]["status"], "partial");
    assert_eq!(first_json["data"]["deduplicated"], false);
    let runtime_snapshot_id = first_json["data"]["snapshot_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let runtime_session_id = first_json["data"]["session_id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_ne!(runtime_snapshot_id, base_snapshot_id);

    let store = depgraph_store::Store::open(&store_path).unwrap();
    assert_eq!(
        store.current_snapshot_id().unwrap().as_deref(),
        Some(runtime_snapshot_id.as_str())
    );
    let metadata = store
        .completed_snapshot(&runtime_snapshot_id)
        .unwrap()
        .unwrap();
    assert_eq!(metadata.source_kind, "runtime");
    assert_eq!(
        metadata.runtime_session_ids.as_slice(),
        std::slice::from_ref(&runtime_session_id)
    );
    let snapshot = store.load_completed_snapshot(&runtime_snapshot_id).unwrap();
    assert!(snapshot.edges.iter().any(|edge| {
        edge.id == "edge:static" && edge.phase == "source" && edge.precision == "exact"
    }));
    assert_eq!(
        store
            .load_completed_snapshot(&base_snapshot_id)
            .unwrap()
            .edges
            .iter()
            .map(|edge| edge.id.as_str())
            .collect::<Vec<_>>(),
        ["edge:static"]
    );
    assert_eq!(
        snapshot
            .edges
            .iter()
            .filter(|edge| edge.phase == "runtime")
            .count(),
        3
    );
    assert_eq!(
        snapshot
            .nodes
            .iter()
            .filter(|node| {
                node.properties
                    .get("runtime_only")
                    .and_then(serde_json::Value::as_bool)
                    == Some(true)
            })
            .count(),
        2
    );
    assert!(snapshot.profiles.iter().any(|profile| {
        profile
            .properties
            .get("profile_phase")
            .and_then(serde_json::Value::as_str)
            == Some("runtime")
    }));
    let runtime_profile_id = snapshot
        .profiles
        .iter()
        .find(|profile| {
            profile
                .properties
                .get("profile_phase")
                .and_then(serde_json::Value::as_str)
                == Some("runtime")
        })
        .unwrap()
        .id
        .clone();
    assert!(
        snapshot
            .diagnostics
            .iter()
            .any(|diagnostic| { diagnostic.code == "RUNTIME_TARGET_UNMATCHED" })
    );
    drop(store);

    let second = import();
    assert!(
        second.status.success(),
        "{}",
        String::from_utf8_lossy(&second.stderr)
    );
    let second_json: serde_json::Value = serde_json::from_slice(&second.stdout).unwrap();
    assert_eq!(second_json["data"]["snapshot_id"], runtime_snapshot_id);
    assert_eq!(second_json["data"]["session_id"], runtime_session_id);
    assert_eq!(second_json["data"]["deduplicated"], true);

    let mut second_trace: serde_json::Value =
        serde_json::from_slice(&fs::read(&trace).unwrap()).unwrap();
    second_trace["session"]["id"] = json!("session-002");
    second_trace["session"]["started_at"] = json!("2026-07-23T01:00:00Z");
    second_trace["session"]["ended_at"] = json!("2026-07-23T01:00:04Z");
    second_trace["events"][0]["source"] = json!({"kind":"node","node_id":"file:server"});
    second_trace["events"][0]["target"] = json!({"kind":"node","node_id":"route:users"});
    for (index, event) in second_trace["events"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .enumerate()
    {
        event["timestamp"] = json!(format!("2026-07-23T01:00:0{}Z", index + 1));
    }
    let second_trace_path = cache.path().join("runtime-session-002.json");
    fs::write(
        &second_trace_path,
        serde_json::to_vec_pretty(&second_trace).unwrap(),
    )
    .unwrap();
    let second_import = Command::cargo_bin("depgraph")
        .unwrap()
        .args([
            "--store",
            store_path.to_str().unwrap(),
            "runtime",
            "import",
            second_trace_path.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        second_import.status.success(),
        "{}",
        String::from_utf8_lossy(&second_import.stderr)
    );
    let second_import: serde_json::Value = serde_json::from_slice(&second_import.stdout).unwrap();
    assert_eq!(second_import["data"]["deduplicated"], false);
    let two_session_snapshot_id = second_import["data"]["snapshot_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let store = depgraph_store::Store::open(&store_path).unwrap();
    let two_session_snapshot = store
        .load_completed_snapshot(&two_session_snapshot_id)
        .unwrap();
    assert_eq!(
        store
            .runtime_sessions_for_snapshot(&two_session_snapshot_id)
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        two_session_snapshot
            .edges
            .iter()
            .filter(|edge| edge.phase == "runtime")
            .count(),
        3,
        "sessions must deduplicate graph edges"
    );
    assert_eq!(
        two_session_snapshot
            .evidence
            .iter()
            .filter(|evidence| evidence.kind == "runtime")
            .count(),
        12
    );
    let calls = two_session_snapshot
        .edges
        .iter()
        .find(|edge| {
            edge.phase == "runtime" && edge.kind == "calls" && edge.source == "file:server"
        })
        .unwrap();
    let context = depgraph_store::runtime_context_for_edge(&two_session_snapshot, calls);
    assert_eq!(context.source_session_ids, ["session-001", "session-002"]);
    assert_eq!(context.observation_count, 4);
    assert_eq!(
        context.first_observed_at.as_deref(),
        Some("2026-07-23T00:00:01Z")
    );
    assert_eq!(
        context.last_observed_at.as_deref(),
        Some("2026-07-23T01:00:01Z")
    );
    drop(store);

    let deps = Command::cargo_bin("depgraph")
        .unwrap()
        .args([
            "--store",
            store_path.to_str().unwrap(),
            "deps",
            "id:file:server",
            "--phase",
            "runtime",
            "--profile",
            runtime_profile_id.as_str(),
            "--session",
            "session-001",
            "--environment",
            "production",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        deps.status.success(),
        "{}",
        String::from_utf8_lossy(&deps.stderr)
    );
    let deps: serde_json::Value = serde_json::from_slice(&deps.stdout).unwrap();
    assert_eq!(deps["data"]["edges"].as_array().unwrap().len(), 1);
    assert!(
        deps["data"]["edges"]
            .as_array()
            .unwrap()
            .iter()
            .all(|edge| edge["phase"] == "runtime")
    );

    let why = Command::cargo_bin("depgraph")
        .unwrap()
        .args([
            "--store",
            store_path.to_str().unwrap(),
            "why",
            "id:file:server",
            "id:route:users",
            "--phase",
            "runtime",
            "--session",
            "session-002",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(why.status.success());
    let why: serde_json::Value = serde_json::from_slice(&why.stdout).unwrap();
    assert_eq!(why["data"]["path_found"], true);
    assert_eq!(
        why["data"]["steps"][0]["evidence"][0]["properties"]["source_session_id"],
        "session-002"
    );

    let dependents = Command::cargo_bin("depgraph")
        .unwrap()
        .args([
            "--store",
            store_path.to_str().unwrap(),
            "dependents",
            "id:route:users",
            "--phase",
            "runtime",
            "--environment",
            "nodejs-24",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(dependents.status.success());
    let dependents: serde_json::Value = serde_json::from_slice(&dependents.stdout).unwrap();
    assert_eq!(dependents["data"]["edges"].as_array().unwrap().len(), 1);

    let impact = Command::cargo_bin("depgraph")
        .unwrap()
        .args([
            "--store",
            store_path.to_str().unwrap(),
            "impact",
            "id:route:users",
            "--phase",
            "runtime",
            "--session",
            "session-001",
            "--environment",
            "test-region-1",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(impact.status.success());
    let impact: serde_json::Value = serde_json::from_slice(&impact.stdout).unwrap();
    assert_eq!(impact["data"]["filters"]["phases"], json!(["runtime"]));
    assert_eq!(
        impact["data"]["filters"]["sessions"],
        json!(["session-001"])
    );

    let export = || {
        Command::cargo_bin("depgraph")
            .unwrap()
            .args([
                "--store",
                store_path.to_str().unwrap(),
                "export",
                "--format",
                "json",
                "--phase",
                "runtime",
                "--session",
                "session-001",
            ])
            .output()
            .unwrap()
    };
    let export_first = export();
    let export_second = export();
    assert!(export_first.status.success());
    assert_eq!(export_first.stdout, export_second.stdout);
    let exported: serde_json::Value = serde_json::from_slice(&export_first.stdout).unwrap();
    assert_eq!(exported["graph"]["edges"].as_array().unwrap().len(), 3);
    assert_eq!(exported["graph"]["evidence"].as_array().unwrap().len(), 6);
    assert!(
        exported["graph"]["edges"]
            .as_array()
            .unwrap()
            .iter()
            .all(|edge| edge["phase"] == "runtime")
    );
    for format in ["dot", "mermaid", "graphml"] {
        let render = || {
            Command::cargo_bin("depgraph")
                .unwrap()
                .args([
                    "--store",
                    store_path.to_str().unwrap(),
                    "export",
                    "--format",
                    format,
                    "--phase",
                    "runtime",
                    "--session",
                    "session-001",
                ])
                .output()
                .unwrap()
        };
        let rendered_first = render();
        let rendered_second = render();
        assert!(rendered_first.status.success());
        assert_eq!(rendered_first.stdout, rendered_second.stdout);
        let rendered = String::from_utf8(rendered_first.stdout).unwrap();
        if format == "graphml" {
            assert!(rendered.contains("<graphml xmlns="));
            assert!(rendered.contains("<data key=\"e_phase\">runtime</data>"));
            assert!(rendered.contains("<data key=\"g_evidence_json\">"));
        } else {
            assert!(rendered.contains("[runtime;"));
        }
    }

    let diff = || {
        Command::cargo_bin("depgraph")
            .unwrap()
            .args([
                "--store",
                store_path.to_str().unwrap(),
                "diff",
                base_snapshot_id.as_str(),
                two_session_snapshot_id.as_str(),
                "--phase",
                "runtime",
                "--json",
            ])
            .output()
            .unwrap()
    };
    let diff_first = diff();
    let diff_second = diff();
    assert!(
        diff_first.status.success(),
        "{}",
        String::from_utf8_lossy(&diff_first.stderr)
    );
    assert_eq!(diff_first.stdout, diff_second.stdout);
    let diff: serde_json::Value = serde_json::from_slice(&diff_first.stdout).unwrap();
    assert_eq!(diff["data"]["edges"]["added"].as_array().unwrap().len(), 3);

    let current_before_failure = depgraph_store::Store::open(&store_path)
        .unwrap()
        .current_snapshot_id()
        .unwrap();
    let malformed = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../depgraph-core/tests/fixtures/runtime-trace-v1.malformed.json");
    Command::cargo_bin("depgraph")
        .unwrap()
        .args([
            "--store",
            store_path.to_str().unwrap(),
            "runtime",
            "import",
            malformed.to_str().unwrap(),
        ])
        .assert()
        .failure();
    let store = depgraph_store::Store::open(&store_path).unwrap();
    assert_eq!(store.current_snapshot_id().unwrap(), current_before_failure);
    assert_eq!(
        store
            .runtime_sessions_for_snapshot(&two_session_snapshot_id)
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn runtime_validate_rejects_malformed_and_secret_input_with_bounded_errors() {
    let root = tempfile::tempdir().unwrap();
    let cache = tempfile::tempdir().unwrap();
    let store_path = cache.path().join("graph.db");
    seed_runtime_trace_snapshot(&store_path, root.path());
    let unopened_store_path = cache.path().join("must-not-be-opened.db");
    let fixture = |name: &str| {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../depgraph-core/tests/fixtures")
            .join(name)
    };

    Command::cargo_bin("depgraph")
        .unwrap()
        .args([
            "--store",
            unopened_store_path.to_str().unwrap(),
            "runtime",
            "validate",
            fixture("runtime-trace-v1.malformed.json").to_str().unwrap(),
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("repository-relative path"))
        .stderr(predicate::str::contains("../outside.ts").not());
    assert!(!unopened_store_path.exists());

    Command::cargo_bin("depgraph")
        .unwrap()
        .args([
            "--store",
            unopened_store_path.to_str().unwrap(),
            "runtime",
            "validate",
            fixture("runtime-trace-v1.secret.json").to_str().unwrap(),
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("secret"))
        .stderr(predicate::str::contains("fixture-secret-value").not());
    assert!(!unopened_store_path.exists());

    Command::cargo_bin("depgraph")
        .unwrap()
        .args([
            "--store",
            unopened_store_path.to_str().unwrap(),
            "runtime",
            "validate",
            fixture("runtime-trace-v1.golden.json").to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("read-only"));
    assert!(!unopened_store_path.exists());
}

#[test]
fn snapshot_create_list_and_show_are_canonical_and_scriptable() {
    let root = tempfile::tempdir().unwrap();
    let cache = tempfile::tempdir().unwrap();
    let store_path = cache.path().join("graph.db");
    seed_safe_rust_scan(&store_path, root.path(), "Cargo.toml");

    let created = Command::cargo_bin("depgraph")
        .unwrap()
        .args([
            "--store",
            store_path.to_str().unwrap(),
            "snapshot",
            "create",
            "baseline",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(created.status.success(), "{:?}", created.stderr);
    let created: serde_json::Value = serde_json::from_slice(&created.stdout).unwrap();
    assert_eq!(created["schema_version"], "1.0");
    assert_eq!(created["command"], "snapshot.create");
    assert_eq!(created["data"]["name"], "baseline");
    assert_eq!(created["data"]["snapshot"]["status"], "completed");
    let snapshot_id = created["data"]["snapshot"]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(snapshot_id.starts_with("snapshot:sha256:"));

    Command::cargo_bin("depgraph")
        .unwrap()
        .args([
            "--store",
            store_path.to_str().unwrap(),
            "snapshot",
            "create",
            "alpha",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("created snapshot name: alpha"));

    let list = || {
        Command::cargo_bin("depgraph")
            .unwrap()
            .args([
                "--store",
                store_path.to_str().unwrap(),
                "snapshot",
                "list",
                "--json",
            ])
            .output()
            .unwrap()
    };
    let first_list = list();
    let second_list = list();
    assert!(first_list.status.success(), "{:?}", first_list.stderr);
    assert_eq!(first_list.stdout, second_list.stdout);
    let listed: serde_json::Value = serde_json::from_slice(&first_list.stdout).unwrap();
    assert_eq!(listed["command"], "snapshot.list");
    assert_eq!(listed["data"][0]["name"], "alpha");
    assert_eq!(listed["data"][1]["name"], "baseline");
    assert_eq!(listed["data"][0]["id"], snapshot_id);
    assert_eq!(listed["data"][0]["status"], "completed");
    assert_eq!(
        listed["data"][0]["source_revision"],
        serde_json::Value::Null
    );
    assert_eq!(listed["data"][0]["profile_ids"], json!(["rust:safe"]));
    assert_eq!(
        listed["data"][0]["coverage"]["completeness"],
        json!(["syntax-complete"])
    );

    let show = |selector: &str| {
        Command::cargo_bin("depgraph")
            .unwrap()
            .args([
                "--store",
                store_path.to_str().unwrap(),
                "snapshot",
                "show",
                selector,
                "--json",
            ])
            .output()
            .unwrap()
    };
    let by_name = show("BASELINE");
    let by_id = show(&snapshot_id);
    assert!(by_name.status.success(), "{:?}", by_name.stderr);
    assert!(by_id.status.success(), "{:?}", by_id.stderr);
    let by_name: serde_json::Value = serde_json::from_slice(&by_name.stdout).unwrap();
    let by_id: serde_json::Value = serde_json::from_slice(&by_id.stdout).unwrap();
    assert_eq!(by_name["data"], by_id["data"]);
    assert_eq!(by_name["data"]["names"], json!(["alpha", "baseline"]));
    assert_eq!(by_name["data"]["scan_id"], "safe-rust-scan");

    Command::cargo_bin("depgraph")
        .unwrap()
        .args([
            "--store",
            store_path.to_str().unwrap(),
            "snapshot",
            "show",
            "current",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains(format!("snapshot: {snapshot_id}")))
        .stdout(predicate::str::contains("names: alpha,baseline"))
        .stdout(predicate::str::contains("status: completed"))
        .stdout(predicate::str::contains("revision: unknown"))
        .stdout(predicate::str::contains("profiles: rust:safe"))
        .stdout(predicate::str::contains("coverage:"));
}

#[test]
fn snapshot_commands_reject_duplicates_reserved_names_missing_snapshots_and_failed_attempts() {
    let root = tempfile::tempdir().unwrap();
    let cache = tempfile::tempdir().unwrap();
    let store_path = cache.path().join("graph.db");
    seed_safe_rust_scan(&store_path, root.path(), "Cargo.toml");

    Command::cargo_bin("depgraph")
        .unwrap()
        .args([
            "--store",
            store_path.to_str().unwrap(),
            "snapshot",
            "create",
            "baseline",
        ])
        .assert()
        .success();
    Command::cargo_bin("depgraph")
        .unwrap()
        .args([
            "--store",
            store_path.to_str().unwrap(),
            "snapshot",
            "create",
            "BASELINE",
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("already exists"));
    for invalid in ["current", "latest", "snapshot:short", "contains space"] {
        Command::cargo_bin("depgraph")
            .unwrap()
            .args([
                "--store",
                store_path.to_str().unwrap(),
                "snapshot",
                "create",
                invalid,
            ])
            .assert()
            .code(2)
            .stderr(predicate::str::contains("snapshot name"));
    }
    Command::cargo_bin("depgraph")
        .unwrap()
        .args([
            "--store",
            store_path.to_str().unwrap(),
            "snapshot",
            "show",
            "missing",
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("was not found"));

    {
        let mut store = depgraph_store::Store::open(&store_path).unwrap();
        store
            .start_scan("failed-attempt", root.path(), false)
            .unwrap();
        store
            .finish_scan("failed-attempt", "failed", Some("worker failed"), false)
            .unwrap();
    }
    Command::cargo_bin("depgraph")
        .unwrap()
        .args([
            "--store",
            store_path.to_str().unwrap(),
            "--scan-id",
            "failed-attempt",
            "snapshot",
            "create",
            "failed-name",
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("has no completed snapshot"));

    let empty_store = cache.path().join("empty.db");
    Command::cargo_bin("depgraph")
        .unwrap()
        .args([
            "--store",
            empty_store.to_str().unwrap(),
            "snapshot",
            "create",
            "first",
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains(
            "no current completed snapshot is available",
        ));
}

#[test]
fn diff_is_canonical_filterable_and_exposes_human_evidence() {
    let root = tempfile::tempdir().unwrap();
    let cache = tempfile::tempdir().unwrap();
    let store_path = cache.path().join("graph.db");
    let baseline_id =
        seed_cli_diff_snapshot(&store_path, root.path(), "diff-baseline", "baseline", false);
    let target_id = seed_cli_diff_snapshot(&store_path, root.path(), "diff-target", "target", true);

    let run_json = |extra: &[&str]| {
        let mut arguments = vec![
            "--store",
            store_path.to_str().unwrap(),
            "diff",
            "BASELINE",
            target_id.as_str(),
            "--json",
        ];
        arguments.extend_from_slice(extra);
        Command::cargo_bin("depgraph")
            .unwrap()
            .args(arguments)
            .output()
            .unwrap()
    };
    let first = run_json(&[]);
    let second = run_json(&[]);
    assert!(first.status.success(), "{:?}", first.stderr);
    assert_eq!(first.stdout, second.stdout);
    let output: serde_json::Value = serde_json::from_slice(&first.stdout).unwrap();
    assert_eq!(output["schema_version"], "1.0");
    assert_eq!(output["command"], "diff");
    assert_eq!(output["data"]["from_snapshot_id"], baseline_id);
    assert_eq!(output["data"]["to_snapshot_id"], target_id);
    assert_eq!(output["data"]["filters"]["kind"], json!([]));
    assert_eq!(
        output["data"]["summary"]["nodes"],
        json!({
            "added": 1,
            "removed": 1,
            "changed": 1
        })
    );
    assert_eq!(output["data"]["summary"]["renames"]["confirmed"], 1);
    assert_eq!(output["data"]["renames"][0]["old_id"], "file:old");
    assert_eq!(output["data"]["renames"][0]["new_id"], "file:new");
    assert_eq!(output["data"]["sites"]["added"][0]["id"], "site:new");
    assert_eq!(output["data"]["edges"]["added"][0]["id"], "edge:new");
    assert_eq!(
        output["data"]["evidence"]["added"][0]["owner_id"],
        "edge:new"
    );

    let symbol = run_json(&["--kind", "symbol"]);
    assert!(symbol.status.success(), "{:?}", symbol.stderr);
    let symbol: serde_json::Value = serde_json::from_slice(&symbol.stdout).unwrap();
    assert_eq!(symbol["data"]["nodes"]["added"][0]["id"], "symbol:added");
    assert_eq!(
        symbol["data"]["nodes"]["removed"][0]["id"],
        "symbol:removed"
    );
    assert_eq!(symbol["data"]["sites"]["added"], json!([]));
    assert!(symbol["data"].get("coverage").is_none());

    Command::cargo_bin("depgraph")
        .unwrap()
        .args([
            "--store",
            store_path.to_str().unwrap(),
            "diff",
            "baseline",
            "target",
            "--kind",
            "symbol",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("coverage: excluded by filters"));

    let profile = run_json(&["--profile", "fixture:safe"]);
    assert!(profile.status.success(), "{:?}", profile.stderr);
    let profile: serde_json::Value = serde_json::from_slice(&profile.stdout).unwrap();
    assert_eq!(
        profile["data"]["profiles"]["changed"][0]["id"],
        "fixture:safe"
    );
    assert_eq!(profile["data"]["sites"]["added"][0]["id"], "site:new");
    assert_eq!(profile["data"]["nodes"]["added"], json!([]));

    let phase = run_json(&["--phase", "semantic"]);
    assert!(phase.status.success(), "{:?}", phase.stderr);
    let phase: serde_json::Value = serde_json::from_slice(&phase.stdout).unwrap();
    assert_eq!(phase["data"]["edges"]["added"][0]["id"], "edge:new");
    assert_eq!(phase["data"]["sites"]["added"], json!([]));

    let status = run_json(&["--status", "unresolved"]);
    assert!(status.status.success(), "{:?}", status.stderr);
    let status: serde_json::Value = serde_json::from_slice(&status.stdout).unwrap();
    assert_eq!(status["data"]["sites"]["added"][0]["id"], "site:new");
    assert_eq!(status["data"]["edges"]["added"][0]["id"], "edge:new");
    assert_eq!(
        status["data"]["evidence"]["added"]
            .as_array()
            .unwrap()
            .len(),
        2
    );

    Command::cargo_bin("depgraph")
        .unwrap()
        .args([
            "--store",
            store_path.to_str().unwrap(),
            "diff",
            "baseline",
            "target",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("total changes:"))
        .stdout(predicate::str::contains(
            "R [file; exact] file:old -> file:new",
        ))
        .stdout(predicate::str::contains(
            "evidence: edge:edge:new#0 [semantic fixture@1.0] src/new.go:7:1-7:8",
        ));
}

#[test]
fn diff_empty_and_selector_errors_have_stable_exit_codes() {
    let root = tempfile::tempdir().unwrap();
    let cache = tempfile::tempdir().unwrap();
    let store_path = cache.path().join("graph.db");
    let snapshot_id =
        seed_cli_diff_snapshot(&store_path, root.path(), "diff-empty", "baseline", false);
    let output = Command::cargo_bin("depgraph")
        .unwrap()
        .args([
            "--store",
            store_path.to_str().unwrap(),
            "diff",
            "baseline",
            snapshot_id.as_str(),
            "--json",
        ])
        .output()
        .unwrap();
    assert!(output.status.success(), "{:?}", output.stderr);
    let output: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(output["data"]["summary"]["empty"], true);
    assert_eq!(output["data"]["summary"]["total_changes"], 0);
    assert_eq!(output["data"]["from_snapshot_id"], snapshot_id);
    assert_eq!(output["data"]["to_snapshot_id"], snapshot_id);

    {
        let mut store = depgraph_store::Store::open(&store_path).unwrap();
        store
            .start_scan("failed-diff-attempt", root.path(), false)
            .unwrap();
        store
            .finish_scan(
                "failed-diff-attempt",
                "failed",
                Some("worker failed"),
                false,
            )
            .unwrap();
    }
    for selector in ["missing", "failed-diff-attempt"] {
        Command::cargo_bin("depgraph")
            .unwrap()
            .args([
                "--store",
                store_path.to_str().unwrap(),
                "diff",
                selector,
                "baseline",
            ])
            .assert()
            .code(2)
            .stderr(predicate::str::contains("snapshot selector"));
    }
    Command::cargo_bin("depgraph")
        .unwrap()
        .args([
            "--store",
            store_path.to_str().unwrap(),
            "diff",
            "baseline",
            "baseline",
            "--kind",
            "",
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains(
            "diff kind filter must not be empty",
        ));
}

#[test]
fn policy_command_reports_public_api_impact_and_safe_github_annotation() {
    let root = tempfile::tempdir().unwrap();
    let cache = tempfile::tempdir().unwrap();
    let store_path = cache.path().join("graph.db");
    fs::create_dir(root.path().join("src")).unwrap();
    fs::write(
        root.path().join("src/consumer.go"),
        "package fixture\n\nfunc Consumer() {}\n",
    )
    .unwrap();
    fs::write(
        root.path().join("src/public.go"),
        "package fixture\n\n// PublicAPI\n\nfunc PublicAPI() string { return \"safe\" }\n",
    )
    .unwrap();
    let baseline_id = seed_policy_snapshot(
        &store_path,
        root.path(),
        "policy-baseline",
        "policy-baseline",
        false,
    );
    let target_id = seed_policy_snapshot(
        &store_path,
        root.path(),
        "policy-target",
        "policy-target",
        true,
    );
    fs::write(
        root.path().join(".depgraph.toml"),
        r#"
schema_version = 1

[policy]
schema_version = "1.0"

[[policy.rules]]
id = "stable-public-api"
kind = "public_api_change"
severity = "error"
source = { kind = "symbol", field = "id", match = "exact", value = "symbol:consumer", cardinality = "one", exclude = [], scope = { paths = [], packages = [] } }
target = { kind = "symbol", field = "id", match = "exact", value = "symbol:public-api", cardinality = "one", exclude = [], scope = { paths = [], packages = [] } }
profiles = { include = [{ match = "exact", value = "fixture:safe" }], exclude = [] }
condition = { op = "all", conditions = [] }
precisions = ["exact"]
resolution_statuses = ["resolved"]
evidence = { kinds = ["source"], minimum_spans = 1, primary_only = true }
"#,
    )
    .unwrap();

    let run = |mode: &str| {
        Command::cargo_bin("depgraph")
            .unwrap()
            .current_dir(root.path())
            .args([
                "--store",
                store_path.to_str().unwrap(),
                "policy",
                "policy-baseline",
                "policy-target",
                mode,
            ])
            .output()
            .unwrap()
    };
    let json_output = run("--json");
    let repeated_json_output = run("--json");
    assert_eq!(
        json_output.status.code(),
        Some(1),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&json_output.stdout),
        String::from_utf8_lossy(&json_output.stderr)
    );
    assert_eq!(json_output.stdout, repeated_json_output.stdout);
    assert_eq!(json_output.stderr, repeated_json_output.stderr);
    let report: serde_json::Value = serde_json::from_slice(&json_output.stdout).unwrap();
    assert_eq!(report["command"], "policy");
    assert_eq!(report["data"]["from_snapshot_id"], baseline_id);
    assert_eq!(report["data"]["to_snapshot_id"], target_id);
    assert_eq!(
        report["data"]["result"]["api_changes"][0]["kind"],
        "removed"
    );
    assert_eq!(
        report["data"]["result"]["violations"][0]["dependency_path"][0]["edge_id"],
        "edge:consumer-public-api"
    );
    assert_eq!(
        report["data"]["result"]["violations"][0]["evidence"]
            .as_array()
            .unwrap()
            .iter()
            .map(|span| span["path"].as_str().unwrap())
            .collect::<Vec<_>>(),
        vec!["src/consumer.go", "src/public.go"]
    );
    assert_eq!(report["data"]["result"]["exit_code"], 1);

    let annotations = run("--github-annotations");
    assert_eq!(annotations.status.code(), Some(1));
    let annotations = String::from_utf8(annotations.stdout).unwrap();
    assert!(annotations.starts_with(
        "::error file=src/consumer.go,line=3,col=1,endLine=3,endColumn=20,title=depgraph policy stable-public-api::"
    ));
    assert!(!annotations.contains(&root.path().to_string_lossy().to_string()));
    assert!(!annotations.contains("super-secret-value"));

    Command::cargo_bin("depgraph")
        .unwrap()
        .current_dir(root.path())
        .args([
            "--store",
            store_path.to_str().unwrap(),
            "policy",
            "policy-baseline",
            "policy-target",
            "--json",
            "--github-annotations",
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains(
            "cannot be used with '--github-annotations'",
        ));
}

#[test]
fn large_diff_json_is_complete_sorted_and_repeatable() {
    const NODE_COUNT: usize = 2_048;
    let root = tempfile::tempdir().unwrap();
    let cache = tempfile::tempdir().unwrap();
    let store_path = cache.path().join("graph.db");
    let mut store = depgraph_store::Store::open(&store_path).unwrap();
    let from_id =
        seed_large_cli_diff_snapshot(&mut store, root.path(), "large-from", 1, NODE_COUNT);
    let to_id = seed_large_cli_diff_snapshot(&mut store, root.path(), "large-to", 2, NODE_COUNT);
    drop(store);
    let run = || {
        Command::cargo_bin("depgraph")
            .unwrap()
            .args([
                "--store",
                store_path.to_str().unwrap(),
                "diff",
                from_id.as_str(),
                to_id.as_str(),
                "--json",
            ])
            .output()
            .unwrap()
    };
    let first = run();
    let second = run();
    assert!(first.status.success(), "{:?}", first.stderr);
    assert_eq!(first.stdout, second.stdout);
    let output: serde_json::Value = serde_json::from_slice(&first.stdout).unwrap();
    let changed = output["data"]["nodes"]["changed"].as_array().unwrap();
    assert_eq!(changed.len(), NODE_COUNT);
    assert_eq!(changed.first().unwrap()["id"], "file:00000");
    assert_eq!(changed.last().unwrap()["id"], "file:02047");
    assert_eq!(output["data"]["summary"]["nodes"]["changed"], NODE_COUNT);
}

#[test]
fn impact_changed_set_is_read_only_deterministic_and_maps_renames() {
    let root = tempfile::tempdir().unwrap();
    let cache = tempfile::tempdir().unwrap();
    let store_path = cache.path().join("graph.db");
    let git_trace_path = cache.path().join("git-trace.log");
    run_git(root.path(), &["init", "--quiet"]);
    run_git(
        root.path(),
        &["config", "user.email", "test@example.invalid"],
    );
    run_git(root.path(), &["config", "user.name", "Test"]);
    fs::create_dir(root.path().join("src")).unwrap();
    fs::write(root.path().join("src/old.go"), "package fixture\n").unwrap();
    run_git(root.path(), &["add", "src/old.go"]);
    run_git(root.path(), &["commit", "--quiet", "-m", "base"]);
    let base = run_git(root.path(), &["rev-parse", "HEAD"]);
    run_git(root.path(), &["mv", "src/old.go", "src/new.go"]);
    run_git(root.path(), &["commit", "--quiet", "-m", "rename"]);
    fs::write(
        root.path().join("src/new.go"),
        "package fixture\n// dirty\n",
    )
    .unwrap();
    fs::write(root.path().join("src/untracked.go"), "package fixture\n").unwrap();
    let status_before = run_git(root.path(), &["status", "--porcelain=v1"]);

    seed_cli_diff_snapshot(
        &store_path,
        root.path(),
        "impact-baseline",
        "impact-baseline",
        false,
    );
    seed_cli_diff_snapshot(
        &store_path,
        root.path(),
        "impact-target",
        "impact-target",
        true,
    );

    let run_json = || {
        Command::cargo_bin("depgraph")
            .unwrap()
            .env("GIT_TRACE", &git_trace_path)
            .args([
                "--store",
                store_path.to_str().unwrap(),
                "--scan-id",
                "impact-target",
                "impact",
                "path:src/new.go",
                "--changed",
                base.as_str(),
                "--json",
            ])
            .output()
            .unwrap()
    };
    let first = run_json();
    let second = run_json();
    assert!(first.status.success(), "{:?}", first.stderr);
    assert_eq!(first.stdout, second.stdout);
    let output: serde_json::Value = serde_json::from_slice(&first.stdout).unwrap();
    assert_eq!(output["schema_version"], "1.0");
    assert_eq!(output["command"], "impact");
    assert_eq!(output["scan_id"], "impact-target");
    assert_eq!(output["data"]["root"]["id"], "file:new");
    assert_eq!(output["data"]["root_impacted"], true);
    assert_eq!(output["data"]["complete"], true);
    assert!(
        output["data"]["changed_set"]["changes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|change| {
                change["status"] == "renamed"
                    && change["old_path"] == "src/old.go"
                    && change["new_path"] == "src/new.go"
            })
    );
    assert!(
        output["data"]["mappings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|mapping| {
                mapping["change"]["status"] == "renamed"
                    && mapping["new_node_ids"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|id| id == "file:new")
            })
    );
    assert_eq!(
        run_git(root.path(), &["status", "--porcelain=v1"]),
        status_before
    );
    assert!(!root.path().join(".git/index.lock").exists());
    assert!(!git_trace_path.exists());

    Command::cargo_bin("depgraph")
        .unwrap()
        .args([
            "--store",
            store_path.to_str().unwrap(),
            "--scan-id",
            "impact-target",
            "impact",
            "path:src/new.go",
            "--changed",
            base.as_str(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("renamed src/old.go -> src/new.go"))
        .stdout(predicate::str::contains(
            "result: impacted=true complete=true",
        ));
}

#[test]
fn warm_impact_queries_reuse_snapshot_and_filter_scoped_bounded_cache_entries() {
    let root = tempfile::tempdir().unwrap();
    let cache = tempfile::tempdir().unwrap();
    let store_path = cache.path().join("graph.db");
    seed_cli_diff_snapshot(
        &store_path,
        root.path(),
        "impact-cache-target",
        "impact-cache-target",
        true,
    );

    let run = |extra: &[&str]| {
        let mut arguments = vec![
            "--store",
            store_path.to_str().unwrap(),
            "--scan-id",
            "impact-cache-target",
            "impact",
            "path:src/new.go",
        ];
        arguments.extend_from_slice(extra);
        Command::cargo_bin("depgraph")
            .unwrap()
            .args(arguments)
            .output()
            .unwrap()
    };
    let first = run(&["--json"]);
    let second = run(&["--json"]);
    assert!(first.status.success(), "{:?}", first.stderr);
    assert!(second.status.success(), "{:?}", second.stderr);
    assert_eq!(first.stdout, second.stdout);
    let store = depgraph_store::Store::open(&store_path).unwrap();
    assert_eq!(store.impact_query_cache_entry_count().unwrap(), 1);
    drop(store);

    let filtered = run(&["--depth", "1", "--json"]);
    assert!(filtered.status.success(), "{:?}", filtered.stderr);
    let filtered: serde_json::Value = serde_json::from_slice(&filtered.stdout).unwrap();
    assert_eq!(filtered["data"]["filters"]["depth"], 1);
    let store = depgraph_store::Store::open(&store_path).unwrap();
    assert_eq!(store.impact_query_cache_entry_count().unwrap(), 2);
}

#[test]
fn empty_safe_scan_uses_external_store_and_reports_json() {
    let root = tempfile::tempdir().unwrap();
    let cache = tempfile::tempdir().unwrap();
    let store = cache.path().join("graph.db");
    Command::cargo_bin("depgraph")
        .unwrap()
        .args([
            "--store",
            store.to_str().unwrap(),
            "scan",
            root.path().to_str().unwrap(),
            "--json",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"status\": \"completed\""))
        .stdout(predicate::str::contains("\"project_code_executed\": false"));
    Command::cargo_bin("depgraph")
        .unwrap()
        .args([
            "--store",
            store.to_str().unwrap(),
            "scan",
            root.path().to_str().unwrap(),
            "--json",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"layer\": \"semantic\""))
        .stdout(predicate::str::contains("\"outcome\": \"hit\""))
        .stdout(predicate::str::contains("\"reason\": \"validated\""));
    Command::cargo_bin("depgraph")
        .unwrap()
        .args([
            "--store",
            store.to_str().unwrap(),
            "scan",
            root.path().to_str().unwrap(),
            "--no-cache",
            "--json",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"outcome\": \"reject\""))
        .stdout(predicate::str::contains(
            "\"reason\": \"disabled-by-request\"",
        ));
    Command::cargo_bin("depgraph")
        .unwrap()
        .current_dir(root.path())
        .args(["--store", store.to_str().unwrap(), "doctor", "--json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"store_schema_version\": 13"))
        .stdout(predicate::str::contains("\"cache_contract_version\": 1"))
        .stdout(predicate::str::contains(
            "\"impact_query_cache_contract_version\": 1",
        ))
        .stdout(predicate::str::contains("\"semantic\": 1"));
    assert!(store.exists());
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
}

#[test]
fn writer_commands_respect_the_store_writer_lock() {
    let root = tempfile::tempdir().unwrap();
    let cache = tempfile::tempdir().unwrap();
    let store = cache.path().join("graph.db");
    let _store_writer_lock = depgraph_core::acquire_store_writer_lock(&store).unwrap();

    Command::cargo_bin("depgraph")
        .unwrap()
        .args([
            "--store",
            store.to_str().unwrap(),
            "scan",
            root.path().to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "another store writer is already running for store",
        ));

    Command::cargo_bin("depgraph")
        .unwrap()
        .current_dir(root.path())
        .args([
            "--store",
            store.to_str().unwrap(),
            "snapshot",
            "create",
            "locked",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "another store writer is already running for store",
        ));

    Command::cargo_bin("depgraph")
        .unwrap()
        .args([
            "--store",
            store.to_str().unwrap(),
            "resolve",
            "--build",
            root.path().to_str().unwrap(),
            "--allow-project-code",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "another store writer is already running for store",
        ));
}

#[test]
fn build_mode_refuses_implicit_or_missing_consent_without_executing_project_code() {
    let root = tempfile::tempdir().unwrap();
    let cache = tempfile::tempdir().unwrap();
    let marker = root.path().join("PROJECT_BUILD_EXECUTED");
    let package_json = format!(
        r#"{{"scripts":{{"build":"node -e \"require('fs').writeFileSync('{}','unsafe')\""}}}}"#,
        marker.display()
    );
    serde_json::from_str::<serde_json::Value>(&package_json).unwrap();
    fs::write(root.path().join("package.json"), package_json).unwrap();

    for ci in ["false", "true"] {
        Command::cargo_bin("depgraph")
            .unwrap()
            .env("CI", ci)
            .env("DEPGRAPH_ALLOW_PROJECT_CODE", "1")
            .args([
                "--store",
                cache.path().join(format!("{ci}.db")).to_str().unwrap(),
                "resolve",
                "--build",
                root.path().to_str().unwrap(),
            ])
            .assert()
            .code(4)
            .stdout(predicate::str::is_empty())
            .stderr(predicate::str::contains("permission denied"))
            .stderr(predicate::str::contains("--allow-project-code"));
    }

    assert!(!marker.exists());
    assert!(!cache.path().join("false.db").exists());
    assert!(!cache.path().join("true.db").exists());

    Command::cargo_bin("depgraph")
        .unwrap()
        .args([
            "resolve",
            "--build",
            root.path().join("missing").to_str().unwrap(),
        ])
        .assert()
        .code(4)
        .stderr(predicate::str::contains("permission denied"));
}

#[test]
fn compiler_precise_refuses_missing_consent_before_paths_pack_or_store() {
    let temp = tempfile::tempdir().unwrap();
    let store = temp.path().join("must-not-exist.db");
    Command::cargo_bin("depgraph")
        .unwrap()
        .env("DEPGRAPH_ALLOW_PROJECT_CODE", "1")
        .env("DEPGRAPH_RUST_COMPILER_PRECISE", "1")
        .args([
            "--store",
            store.to_str().unwrap(),
            "resolve",
            "--build",
            temp.path().join("missing-project").to_str().unwrap(),
            "--rust-compiler-precise",
            "--compiler-pack-requirement",
            temp.path().join("missing-pack.json").to_str().unwrap(),
        ])
        .assert()
        .code(4)
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::contains(
            "--build`, `--allow-project-code`, and `--rust-compiler-precise",
        ));
    assert!(!store.exists());
}

#[test]
fn consented_build_mode_runs_project_code_only_in_the_supervised_staging_area() {
    let root = tempfile::tempdir().unwrap();
    let cache = tempfile::tempdir().unwrap();
    let marker = root.path().join("PROJECT_BUILD_EXECUTED");
    fs::write(
        root.path().join("Cargo.toml"),
        "[workspace]\nmembers=['macro']\nresolver='2'\n\n[package]\nname='supervisor-fixture'\nversion='0.1.0'\nedition='2024'\n\n[dependencies]\nfixture-macro={path='macro'}\n",
    )
    .unwrap();
    fs::write(
        root.path().join("Cargo.lock"),
        "version = 4\n\n[[package]]\nname = \"fixture-macro\"\nversion = \"0.1.0\"\n\n[[package]]\nname = \"supervisor-fixture\"\nversion = \"0.1.0\"\ndependencies = [\n \"fixture-macro\",\n]\n",
    )
    .unwrap();
    fs::create_dir(root.path().join("src")).unwrap();
    fs::write(
        root.path().join("src/lib.rs"),
        "use fixture_macro::Observed;\n#[derive(Observed)]\npub struct Fixture;\ninclude!(concat!(env!(\"OUT_DIR\"), \"/generated.rs\"));\n",
    )
    .unwrap();
    fs::create_dir_all(root.path().join("macro/src")).unwrap();
    fs::write(
        root.path().join("macro/Cargo.toml"),
        "[package]\nname='fixture-macro'\nversion='0.1.0'\nedition='2024'\n\n[lib]\nproc-macro=true\n",
    )
    .unwrap();
    fs::write(
        root.path().join("macro/src/lib.rs"),
        "extern crate proc_macro;\nuse proc_macro::TokenStream;\n#[proc_macro_derive(Observed)]\npub fn observed(_: TokenStream) -> TokenStream { TokenStream::new() }\n",
    )
    .unwrap();
    fs::write(
        root.path().join("build.rs"),
        r#"fn main() {
    let supervised = std::path::PathBuf::from(std::env::var_os("DEPGRAPH_OUTPUT_DIR").unwrap());
    std::fs::write(supervised.join("PROJECT_BUILD_EXECUTED"), b"yes").unwrap();
    let out = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
    std::fs::write(out.join("generated.rs"), b"pub const GENERATED: bool = true;\n").unwrap();
    println!("cargo:rustc-cfg=observed_cfg");
    println!("cargo:rustc-env=OBSERVED_ENV=hidden-env-value");
    println!("cargo:rustc-env=API_TOKEN=super-secret-token");
    println!("cargo:rustc-link-search=native={}", out.display());
    if cfg!(target_os = "windows") {
        println!("cargo:rustc-link-lib=dylib=kernel32");
    } else if cfg!(target_os = "macos") {
        println!("cargo:rustc-link-lib=framework=CoreFoundation");
    } else {
        println!("cargo:rustc-link-lib=dylib=dl");
    }
}
"#,
    )
    .unwrap();

    let store_path = cache.path().join("graph.db");
    seed_safe_rust_scan(&store_path, root.path(), "Cargo.toml");

    Command::cargo_bin("depgraph")
        .unwrap()
        .args([
            "--store",
            store_path.to_str().unwrap(),
            "resolve",
            "--build",
            root.path().to_str().unwrap(),
            "--allow-project-code",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("status: Completed"))
        .stdout(predicate::str::contains("project code executed: true"))
        .stdout(predicate::str::contains("build evidence: promoted"))
        .stdout(predicate::str::contains("build cache: stored"))
        .stderr(predicate::str::contains("network isolation"));

    assert!(!marker.exists());
    assert!(store_path.exists());
    let store = depgraph_store::Store::open(&store_path).unwrap();
    assert_eq!(store.cache_entry_counts().unwrap().build, 1);
    assert!(
        store
            .recent_cache_events(20)
            .unwrap()
            .iter()
            .any(|event| event.layer == depgraph_store::CacheLayer::Build
                && event.outcome == "stored")
    );
    let audit = store.latest_build_audit().unwrap().unwrap().audit;
    let serialized = serde_json::to_string(&audit).unwrap();
    assert_eq!(audit["outcome"], "completed");
    assert_eq!(
        audit["toolchain_version"]
            .as_str()
            .unwrap()
            .split(' ')
            .next(),
        Some("cargo")
    );
    assert!(!serialized.contains(&root.path().to_string_lossy().to_string()));
    assert!(!serialized.contains("hidden-env-value"));
    assert!(!serialized.contains("super-secret-token"));
    if let Some(home) = std::env::var_os("HOME") {
        assert!(!serialized.contains(&home.to_string_lossy().to_string()));
    }
    assert!(!serialized.contains("depgraph-build-"));
    let snapshot = store.load_snapshot("safe-rust-scan").unwrap();
    assert!(
        !store
            .scan("safe-rust-scan")
            .unwrap()
            .unwrap()
            .project_code_executed
    );
    assert!(snapshot.nodes.iter().any(|node| {
        node.kind == "package_instance" && node.properties["safe_marker"] == "preserved"
    }));
    for kind in [
        "build_script_run",
        "build_output_directory",
        "proc_macro_binary",
        "native_library",
    ] {
        assert!(
            snapshot.nodes.iter().any(|node| node.kind == kind),
            "missing {kind}"
        );
    }
    for kind in [
        "executes_build_script",
        "generates_out_dir",
        "compiles_proc_macro",
        "links_native_library",
    ] {
        assert!(
            snapshot.edges.iter().any(|edge| edge.kind == kind),
            "missing {kind}"
        );
    }
    assert!(snapshot.coverage.project_code_executed);
    assert!(
        snapshot
            .coverage
            .completeness
            .iter()
            .any(|level| level == "build-observed")
    );
    let build_nodes_json = serde_json::to_string(
        &snapshot
            .nodes
            .iter()
            .filter(|node| node.properties["build_generated"] == true)
            .collect::<Vec<_>>(),
    )
    .unwrap();
    assert!(!build_nodes_json.contains("hidden-env-value"));
    assert!(!build_nodes_json.contains("super-secret-token"));
    assert!(!build_nodes_json.contains(&root.path().to_string_lossy().to_string()));
    drop(store);

    let run_json = |arguments: &[&str]| {
        let output = Command::cargo_bin("depgraph")
            .unwrap()
            .args(["--store", store_path.to_str().unwrap()])
            .args(arguments)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "args={arguments:?}\nstdout={}\nstderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap()
    };
    let doctor = run_json(&["doctor", "--json"]);
    assert_eq!(
        doctor["latest_attempt"]["profile_matrix"]["entries"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert!(doctor["latest_attempt"]["profile_matrix"]["phase_coverage"]["static"].is_object());
    assert!(doctor["latest_attempt"]["profile_matrix"]["phase_coverage"]["build"].is_object());

    let exported = run_json(&["export", "--format", "json"]);
    assert_eq!(
        exported["graph"]["profile_matrix"]["schema_version"],
        "profile-matrix-v1"
    );
    assert!(
        exported["graph"]["profile_matrix"]["correlations"]
            .as_array()
            .unwrap()
            .iter()
            .all(|correlation| correlation["status"] == "additional")
    );

    let deps = run_json(&["deps", "id:package:app", "--json"]);
    let steps = deps["data"]["steps"].as_array().unwrap();
    assert!(!steps.is_empty());
    assert!(steps.iter().all(|step| {
        step["effective_profile_id"].is_string()
            && step["correlation_status"] == "additional"
            && step["phase_coverage"]["build"].is_object()
    }));

    Command::cargo_bin("depgraph")
        .unwrap()
        .args([
            "resolve",
            "--build",
            root.path().join("missing").to_str().unwrap(),
            "--allow-project-code",
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("does not exist"));
}

#[cfg(unix)]
#[test]
fn cli_cancellation_stops_the_supervised_build_and_retains_the_safe_snapshot() {
    use std::{process::Stdio, thread, time::Duration};

    let root = tempfile::tempdir().unwrap();
    let cache = tempfile::tempdir().unwrap();
    let store_path = cache.path().join("graph.db");
    let ready = root.path().join("BUILD_READY");
    fs::write(
        root.path().join("Cargo.toml"),
        "[package]\nname='cancel-fixture'\nversion='0.1.0'\nedition='2024'\n",
    )
    .unwrap();
    fs::write(
        root.path().join("Cargo.lock"),
        "version = 4\n\n[[package]]\nname = \"cancel-fixture\"\nversion = \"0.1.0\"\n",
    )
    .unwrap();
    fs::create_dir(root.path().join("src")).unwrap();
    fs::write(root.path().join("src/lib.rs"), "pub fn fixture() {}\n").unwrap();
    fs::write(
        root.path().join("build.rs"),
        format!(
            "fn main() {{ std::fs::write({:?}, b\"ready\").unwrap(); std::thread::sleep(std::time::Duration::from_secs(60)); }}\n",
            ready.to_string_lossy()
        ),
    )
    .unwrap();
    seed_safe_rust_scan(&store_path, root.path(), "Cargo.toml");

    let child = std::process::Command::new(env!("CARGO_BIN_EXE_depgraph"))
        .args([
            "--store",
            store_path.to_str().unwrap(),
            "resolve",
            "--build",
            root.path().to_str().unwrap(),
            "--allow-project-code",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    for _ in 0..1_000 {
        if ready.exists() {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    assert!(
        ready.exists(),
        "supervised build never reached its cancellation fixture"
    );
    let signal = std::process::Command::new("kill")
        .args(["-INT", &child.id().to_string()])
        .status()
        .unwrap();
    assert!(signal.success());
    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(3));
    assert!(String::from_utf8_lossy(&output.stdout).contains("status: Cancelled"));

    let store = depgraph_store::Store::open(&store_path).unwrap();
    let audit = store.latest_build_audit().unwrap().unwrap();
    assert_eq!(audit.audit["outcome"], "cancelled");
    let attempt = store.build_attempt(&audit.run_id).unwrap().unwrap();
    assert_eq!(attempt.status, "cancelled");
    let snapshot = store.load_snapshot("safe-rust-scan").unwrap();
    assert!(
        snapshot
            .nodes
            .iter()
            .all(|node| node.properties["build_generated"] != true)
    );
}

#[test]
fn daemon_cli_reports_completed_attempt_and_stops_cleanly() {
    use std::{process::Stdio, thread, time::Duration};

    struct ChildGuard(Option<std::process::Child>);

    impl Drop for ChildGuard {
        fn drop(&mut self) {
            if let Some(child) = &mut self.0 {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }

    let root = tempfile::tempdir().unwrap();
    let cache = tempfile::tempdir().unwrap();
    let store_path = Path::new("graph.db");
    let status_path = cache.path().join("graph.db.daemon-status.json");
    let mut child = ChildGuard(Some(
        std::process::Command::new(env!("CARGO_BIN_EXE_depgraph"))
            .args([
                "--store",
                store_path.to_str().unwrap(),
                "daemon",
                "start",
                root.path().to_str().unwrap(),
            ])
            .current_dir(cache.path())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    ));

    for _ in 0..1_000 {
        if status_path.exists() {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    assert!(status_path.exists(), "daemon did not publish its status");
    fs::write(root.path().join("watched.rs"), "fn watched() {}\n").unwrap();

    let mut completed = None;
    for _ in 0..1_000 {
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_depgraph"))
            .args([
                "--store",
                store_path.to_str().unwrap(),
                "daemon",
                "status",
                root.path().to_str().unwrap(),
                "--json",
            ])
            .current_dir(cache.path())
            .output()
            .unwrap();
        assert!(output.status.success());
        let status: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        if status["last_completed_attempt"].is_object() {
            completed = Some(status);
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    let completed = completed.expect("daemon did not complete the watched scan");
    assert_eq!(completed["phase"], "idle");
    assert_eq!(
        completed["last_completed_attempt"]["changes"][0]["new_path"],
        "watched.rs"
    );

    let stopped = std::process::Command::new(env!("CARGO_BIN_EXE_depgraph"))
        .args([
            "--store",
            store_path.to_str().unwrap(),
            "daemon",
            "stop",
            root.path().to_str().unwrap(),
            "--json",
        ])
        .current_dir(cache.path())
        .output()
        .unwrap();
    assert!(stopped.status.success());
    let stopped_status: serde_json::Value = serde_json::from_slice(&stopped.stdout).unwrap();
    assert_eq!(stopped_status["phase"], "stopped");

    let output = child.0.take().unwrap().wait_with_output().unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("daemon: stopped"));
}

#[test]
fn daemon_stop_rejects_stale_status_without_waiting_for_the_timeout() {
    use std::{process::Stdio, thread, time::Duration};

    let root = tempfile::tempdir().unwrap();
    let cache = tempfile::tempdir().unwrap();
    let store_path = cache.path().join("graph.db");
    let status_path = cache.path().join("graph.db.daemon-status.json");
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_depgraph"))
        .args([
            "--store",
            store_path.to_str().unwrap(),
            "daemon",
            "start",
            root.path().to_str().unwrap(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    for _ in 0..1_000 {
        if status_path.exists() {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    assert!(status_path.exists(), "daemon did not publish its status");
    child.kill().unwrap();
    child.wait().unwrap();
    let _foreground_writer = depgraph_core::acquire_store_writer_lock(&store_path).unwrap();

    Command::cargo_bin("depgraph")
        .unwrap()
        .args([
            "--store",
            store_path.to_str().unwrap(),
            "daemon",
            "stop",
            root.path().to_str().unwrap(),
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("daemon status").and(predicate::str::contains("stale")));
}

#[test]
fn failed_rust_build_correlation_finalizes_the_attempt_without_promoting_a_delta() {
    let root = tempfile::tempdir().unwrap();
    let cache = tempfile::tempdir().unwrap();
    let store_path = cache.path().join("graph.db");
    fs::write(
        root.path().join("Cargo.toml"),
        "[package]\nname='correlation-fixture'\nversion='0.1.0'\nedition='2024'\n",
    )
    .unwrap();
    fs::write(
        root.path().join("Cargo.lock"),
        "version = 4\n\n[[package]]\nname = \"correlation-fixture\"\nversion = \"0.1.0\"\n",
    )
    .unwrap();
    fs::create_dir(root.path().join("src")).unwrap();
    fs::write(root.path().join("src/lib.rs"), "pub fn fixture() {}\n").unwrap();
    fs::write(
        root.path().join("build.rs"),
        "fn main() { let out = std::path::PathBuf::from(std::env::var_os(\"OUT_DIR\").unwrap()); std::fs::write(out.join(\"observed.txt\"), b\"observed\").unwrap(); }\n",
    )
    .unwrap();
    seed_safe_rust_scan(&store_path, root.path(), "unrelated/Cargo.toml");

    Command::cargo_bin("depgraph")
        .unwrap()
        .args([
            "--store",
            store_path.to_str().unwrap(),
            "resolve",
            "--build",
            root.path().to_str().unwrap(),
            "--allow-project-code",
        ])
        .assert()
        .code(4)
        .stderr(predicate::str::contains(
            "build observation could not be correlated",
        ));

    let store = depgraph_store::Store::open(&store_path).unwrap();
    let audit = store.latest_build_audit().unwrap().unwrap();
    let attempt = store.build_attempt(&audit.run_id).unwrap().unwrap();
    assert_eq!(attempt.status, "security_failed");
    assert_eq!(
        attempt.error.as_deref(),
        Some("build-observation-correlation-failed")
    );
    assert_eq!(
        store.current_build_attempt_id("safe-rust-scan").unwrap(),
        None
    );
    let snapshot = store.load_snapshot("safe-rust-scan").unwrap();
    assert!(
        snapshot
            .nodes
            .iter()
            .all(|node| node.properties["build_generated"] != true)
    );
}

#[test]
fn resolve_requires_the_explicit_build_mode_selector() {
    let root = tempfile::tempdir().unwrap();
    Command::cargo_bin("depgraph")
        .unwrap()
        .args([
            "resolve",
            root.path().to_str().unwrap(),
            "--allow-project-code",
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("--build"));

    Command::cargo_bin("depgraph")
        .unwrap()
        .args(["resolve", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--build"))
        .stdout(predicate::str::contains("--allow-project-code"))
        .stdout(predicate::str::contains("untrusted project code"));
}

#[cfg(unix)]
fn write_worker(path: &std::path::Path, body: &str) {
    use std::os::unix::fs::PermissionsExt;

    fs::write(path, format!("#!/bin/sh\nset -eu\n{body}\n")).unwrap();
    let mut permissions = fs::metadata(path).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions).unwrap();
}

#[cfg(unix)]
fn fixture_root() -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    fs::write(
        root.path().join("go.mod"),
        "module example.test/fixture\n\ngo 1.26.1\n",
    )
    .unwrap();
    root
}

#[cfg(unix)]
const PARSE_ARGS: &str = r#"
root=''
scan=''
while [ "$#" -gt 0 ]; do
  case "$1" in
    --root) root="$2"; shift 2 ;;
    --scan-id) scan="$2"; shift 2 ;;
    *) shift ;;
  esac
done
"#;

#[cfg(unix)]
fn common_event(event: &str, seq: u64, payload: &str, extra_arguments: &str) -> String {
    format!(
        r#"printf '{{"event":"{event}","protocol_version":"1.0","scan_id":"%s","adapter":"go","adapter_version":"0.1.0","seq":{seq}{payload}}}\n' "$scan"{extra_arguments}"#
    )
}

#[cfg(unix)]
fn complete_worker(node_id: &str) -> String {
    let coverage = r#"{"profiles":1,"files_discovered":1,"files_analyzed":1,"files_skipped":0,"dependency_sites":0,"resolved":0,"candidates":0,"external":0,"unresolved":0,"unsupported_syntax":0,"project_code_executed":false,"completeness":["syntax-complete"],"reasons":[]}"#;
    [
        PARSE_ARGS.to_owned(),
        common_event(
            "scan_started",
            1,
            r#", "root":"%s","project_code_executed":false,"safe_mode":true"#,
            r#" "$root""#,
        ),
        common_event(
            "profile_declared",
            2,
            r#", "profile":{"id":"go:test","language":"go","features":[],"environment":{},"properties":{}}"#,
            "",
        ),
        common_event(
            "node_upsert",
            3,
            &format!(r#", "node":{{"id":"{node_id}","kind":"file","locator":"file://go.mod","properties":{{}}}}"#),
            "",
        ),
        common_event(
            "file_completed",
            4,
            r#", "path":"go.mod","discovered_sites":0,"emitted_sites":0,"skipped":false"#,
            "",
        ),
        common_event(
            "profile_completed",
            5,
            &format!(r#", "profile_id":"go:test","coverage":{coverage}"#),
            "",
        ),
        common_event(
            "scan_completed",
            6,
            &format!(r#", "coverage":{coverage}"#),
            "",
        ),
    ]
    .join("\n")
}

#[cfg(unix)]
fn coverage(sites: u64, resolved: u64, unresolved: u64) -> String {
    format!(
        r#"{{"profiles":1,"files_discovered":1,"files_analyzed":1,"files_skipped":0,"dependency_sites":{sites},"resolved":{resolved},"candidates":0,"external":0,"unresolved":{unresolved},"unsupported_syntax":0,"project_code_executed":false,"completeness":["syntax-complete"],"reasons":[]}}"#
    )
}

#[cfg(unix)]
fn graph_worker(reverse_payload_order: bool) -> String {
    let mut payload = [
        (
            "node_upsert",
            r#", "node":{"id":"file:source","kind":"file","locator":"file://go.mod","display_name":"go.mod","properties":{"path":"go.mod"}}"#.to_owned(),
        ),
        (
            "node_upsert",
            r#", "node":{"id":"file:one","kind":"file","locator":"file://src/shared-one.go","display_name":"shared","properties":{"path":"src/shared-one.go"}}"#.to_owned(),
        ),
        (
            "node_upsert",
            r#", "node":{"id":"file:two","kind":"file","locator":"file://src/shared-two.go","display_name":"shared","properties":{"path":"src/shared-two.go"}}"#.to_owned(),
        ),
        (
            "dependency_site",
            r#", "site":{"id":"site:one","source":"file:source","kind":"import","specifier":"./src/shared-one","resolution_status":"resolved","target_ids":["file:one"],"profile_id":"go:test","condition":{"op":"all","conditions":[]},"precision":"exact","evidence":[{"kind":"source","extractor":"fixture","extractor_version":"1.0","path":"go.mod","start_line":1,"start_column":1,"end_line":1,"end_column":2,"properties":{}}]}"#.to_owned(),
        ),
        (
            "dependency_site",
            r#", "site":{"id":"site:two","source":"file:source","kind":"import","specifier":"./src/shared-two","resolution_status":"resolved","target_ids":["file:two"],"profile_id":"go:test","condition":{"op":"all","conditions":[]},"precision":"exact","evidence":[{"kind":"source","extractor":"fixture","extractor_version":"1.0","path":"go.mod","start_line":1,"start_column":2,"end_line":1,"end_column":3,"properties":{}}]}"#.to_owned(),
        ),
        (
            "edge_upsert",
            r#", "edge":{"id":"edge:one","source":"file:source","target":"file:one","kind":"imports","site_id":"site:one","phase":"source","environment":"host","profile_id":"go:test","condition":{"op":"all","conditions":[]},"resolution_status":"resolved","precision":"exact","generated":false,"evidence":[{"kind":"source","extractor":"fixture","extractor_version":"1.0","path":"go.mod","start_line":1,"start_column":1,"end_line":1,"end_column":2,"properties":{}}]}"#.to_owned(),
        ),
        (
            "edge_upsert",
            r#", "edge":{"id":"edge:two","source":"file:source","target":"file:two","kind":"imports","site_id":"site:two","phase":"source","environment":"host","profile_id":"go:test","condition":{"op":"all","conditions":[]},"resolution_status":"resolved","precision":"exact","generated":false,"evidence":[{"kind":"source","extractor":"fixture","extractor_version":"1.0","path":"go.mod","start_line":1,"start_column":2,"end_line":1,"end_column":3,"properties":{}}]}"#.to_owned(),
        ),
    ];
    if reverse_payload_order {
        payload.reverse();
    }

    let summary = coverage(2, 2, 0);
    let mut lines = vec![
        PARSE_ARGS.to_owned(),
        common_event(
            "scan_started",
            1,
            r#", "root":"%s","project_code_executed":false,"safe_mode":true"#,
            r#" "$root""#,
        ),
        common_event(
            "profile_declared",
            2,
            r#", "profile":{"id":"go:test","language":"go","features":[],"environment":{},"properties":{}}"#,
            "",
        ),
    ];
    lines.extend(
        payload
            .iter()
            .enumerate()
            .map(|(index, (event, payload))| common_event(event, index as u64 + 3, payload, "")),
    );
    lines.extend([
        common_event(
            "file_completed",
            10,
            r#", "path":"go.mod","discovered_sites":2,"emitted_sites":2,"skipped_sites":0,"skipped":false"#,
            "",
        ),
        common_event(
            "profile_completed",
            11,
            &format!(r#", "profile_id":"go:test","coverage":{summary}"#),
            "",
        ),
        common_event(
            "scan_completed",
            12,
            &format!(r#", "coverage":{summary}"#),
            "",
        ),
    ]);
    lines.join("\n")
}

#[cfg(unix)]
struct SemanticGraphFixture {
    worker: String,
    alpha_id: String,
    beta_id: String,
    only_symbol_id: String,
    shared_type_id: String,
    only_type_id: String,
    alpha_beta_edge_id: String,
}

#[cfg(unix)]
fn semantic_graph_worker() -> SemanticGraphFixture {
    use depgraph_protocol::stable_id_from_value;
    use serde_json::json;

    const PACKAGE_LOCATOR: &str = "go:example.test/fixture@workspace#example.test/fixture";
    const PROFILE_ID: &str = "go:test";

    let summary = coverage(2, 2, 0);
    let symbol_identity = |resolver_identity: &str| {
        json!({
            "identity_kind": "named",
            "language": "go",
            "package_locator": PACKAGE_LOCATOR,
            "resolver_identity": resolver_identity,
            "symbol_kind": "function"
        })
    };
    let type_identity = |resolver_identity: &str| {
        json!({
            "language": "go",
            "package_locator": PACKAGE_LOCATOR,
            "resolver_identity": resolver_identity,
            "type_kind": "named"
        })
    };

    let alpha_identity = symbol_identity("example.test/fixture.Alpha");
    let beta_identity = symbol_identity("example.test/fixture.Beta");
    let only_symbol_identity = symbol_identity("example.test/fixture.OnlySymbol");
    let shared_type_identity = type_identity("example.test/fixture.Shared");
    let only_type_identity = type_identity("example.test/fixture.OnlyType");
    let alpha_id = stable_id_from_value("symbol", &alpha_identity);
    let beta_id = stable_id_from_value("symbol", &beta_identity);
    let only_symbol_id = stable_id_from_value("symbol", &only_symbol_identity);
    let shared_type_id = stable_id_from_value("type", &shared_type_identity);
    let only_type_id = stable_id_from_value("type", &only_type_identity);

    let semantic_evidence = |line: u64| {
        json!([{
            "kind": "semantic",
            "extractor": "go-types",
            "extractor_version": "1.0",
            "path": "main.go",
            "start_line": line,
            "start_column": 2,
            "end_line": line,
            "end_column": 18,
            "detail": "resolved calls",
            "properties": {"relation": "calls"}
        }])
    };
    let condition = json!({"op": "all", "conditions": []});
    let alpha_evidence = semantic_evidence(10);
    let beta_evidence = semantic_evidence(20);

    let site_id = |source: &str, line: u64| {
        stable_id_from_value(
            "site",
            &json!({
                "condition": condition,
                "kind": "call",
                "path": "main.go",
                "profile_id": PROFILE_ID,
                "source": source,
                "span": {
                    "end_column": 18,
                    "end_line": line,
                    "start_column": 2,
                    "start_line": line
                }
            }),
        )
    };
    let alpha_beta_site_id = site_id(&alpha_id, 10);
    let beta_alpha_site_id = site_id(&beta_id, 20);
    let edge_id = |site_id: &str, target: &str| {
        stable_id_from_value(
            "edge",
            &json!({"kind": "calls", "site_id": site_id, "target": target}),
        )
    };
    let alpha_beta_edge_id = edge_id(&alpha_beta_site_id, &beta_id);
    let beta_alpha_edge_id = edge_id(&beta_alpha_site_id, &alpha_id);

    let mut lines = vec![
        PARSE_ARGS.to_owned(),
        common_event(
            "scan_started",
            1,
            r#", "root":"%s","project_code_executed":false,"safe_mode":true"#,
            r#" "$root""#,
        ),
        common_event(
            "profile_declared",
            2,
            r#", "profile":{"id":"go:test","language":"go","features":[],"environment":{},"properties":{}}"#,
            "",
        ),
    ];

    let semantic_properties = |kind: &str, identity: serde_json::Value| {
        let mut properties = json!({
            "language": "go",
            "package_locator": PACKAGE_LOCATOR,
            "canonical_identity": identity
        });
        properties[kind] = if kind == "symbol_kind" {
            json!("function")
        } else {
            json!("named")
        };
        properties
    };
    let mut nodes = [
        json!({
            "id": alpha_id,
            "kind": "symbol",
            "locator": "go://example.test/fixture.Alpha",
            "display_name": "Shared",
            "properties": semantic_properties("symbol_kind", alpha_identity)
        }),
        json!({
            "id": beta_id,
            "kind": "symbol",
            "locator": "go://example.test/fixture.Beta",
            "display_name": "Shared",
            "properties": semantic_properties("symbol_kind", beta_identity)
        }),
        json!({
            "id": only_symbol_id,
            "kind": "symbol",
            "locator": "go://example.test/fixture.OnlySymbol",
            "display_name": "OnlySymbol",
            "properties": semantic_properties("symbol_kind", only_symbol_identity)
        }),
        json!({
            "id": shared_type_id,
            "kind": "type",
            "locator": "go://example.test/fixture.Shared",
            "display_name": "Shared",
            "properties": semantic_properties("type_kind", shared_type_identity)
        }),
        json!({
            "id": only_type_id,
            "kind": "type",
            "locator": "go://example.test/fixture.OnlyType",
            "display_name": "OnlyType",
            "properties": semantic_properties("type_kind", only_type_identity)
        }),
    ];
    nodes.sort_by(|left, right| left["id"].as_str().cmp(&right["id"].as_str()));
    for (index, node) in nodes.iter().enumerate() {
        lines.push(common_event(
            "node_upsert",
            index as u64 + 3,
            &format!(r#", "node":{node}"#),
            "",
        ));
    }

    let mut sites = [
        json!({
            "id": alpha_beta_site_id,
            "source": alpha_id,
            "kind": "call",
            "specifier": "Beta",
            "resolution_status": "resolved",
            "target_ids": [beta_id],
            "profile_id": PROFILE_ID,
            "condition": condition,
            "precision": "exact",
            "evidence": alpha_evidence
        }),
        json!({
            "id": beta_alpha_site_id,
            "source": beta_id,
            "kind": "call",
            "specifier": "Alpha",
            "resolution_status": "resolved",
            "target_ids": [alpha_id],
            "profile_id": PROFILE_ID,
            "condition": condition,
            "precision": "exact",
            "evidence": beta_evidence
        }),
    ];
    sites.sort_by(|left, right| left["id"].as_str().cmp(&right["id"].as_str()));
    for (index, site) in sites.iter().enumerate() {
        lines.push(common_event(
            "dependency_site",
            index as u64 + 8,
            &format!(r#", "site":{site}"#),
            "",
        ));
    }

    let mut edges = [
        json!({
            "id": alpha_beta_edge_id,
            "source": alpha_id,
            "target": beta_id,
            "kind": "calls",
            "site_id": alpha_beta_site_id,
            "phase": "semantic",
            "environment": "host",
            "profile_id": PROFILE_ID,
            "condition": condition,
            "resolution_status": "resolved",
            "precision": "exact",
            "generated": false,
            "evidence": alpha_evidence
        }),
        json!({
            "id": beta_alpha_edge_id,
            "source": beta_id,
            "target": alpha_id,
            "kind": "calls",
            "site_id": beta_alpha_site_id,
            "phase": "semantic",
            "environment": "host",
            "profile_id": PROFILE_ID,
            "condition": condition,
            "resolution_status": "resolved",
            "precision": "exact",
            "generated": false,
            "evidence": beta_evidence
        }),
    ];
    edges.sort_by(|left, right| left["id"].as_str().cmp(&right["id"].as_str()));
    for (index, edge) in edges.iter().enumerate() {
        lines.push(common_event(
            "edge_upsert",
            index as u64 + 10,
            &format!(r#", "edge":{edge}"#),
            "",
        ));
    }
    lines.extend([
        common_event(
            "file_completed",
            12,
            r#", "path":"main.go","discovered_sites":2,"emitted_sites":2,"skipped_sites":0,"skipped":false"#,
            "",
        ),
        common_event(
            "profile_completed",
            13,
            &format!(r#", "profile_id":"go:test","coverage":{summary}"#),
            "",
        ),
        common_event(
            "scan_completed",
            14,
            &format!(r#", "coverage":{summary}"#),
            "",
        ),
    ]);
    SemanticGraphFixture {
        worker: lines.join("\n"),
        alpha_id,
        beta_id,
        only_symbol_id,
        shared_type_id,
        only_type_id,
        alpha_beta_edge_id,
    }
}

#[cfg(unix)]
fn unresolved_worker() -> String {
    let summary = coverage(1, 0, 1);
    [
        PARSE_ARGS.to_owned(),
        common_event(
            "scan_started",
            1,
            r#", "root":"%s","project_code_executed":false,"safe_mode":true"#,
            r#" "$root""#,
        ),
        common_event(
            "profile_declared",
            2,
            r#", "profile":{"id":"go:test","language":"go","features":[],"environment":{},"properties":{}}"#,
            "",
        ),
        common_event(
            "node_upsert",
            3,
            r#", "node":{"id":"file:source","kind":"file","locator":"file://go.mod","display_name":"go.mod","properties":{"path":"go.mod"}}"#,
            "",
        ),
        common_event(
            "node_upsert",
            4,
            r#", "node":{"id":"unknown:go","kind":"unknown_target","locator":"unknown://go","display_name":"unknown Go target","properties":{}}"#,
            "",
        ),
        common_event(
            "dependency_site",
            5,
            r#", "site":{"id":"site:missing","source":"file:source","kind":"import","specifier":"example.test/missing","resolution_status":"unresolved","target_ids":["unknown:go"],"profile_id":"go:test","condition":{"op":"all","conditions":[]},"precision":"exact","reason":"package_not_found","evidence":[{"kind":"source","extractor":"fixture","extractor_version":"1.0","path":"go.mod","start_line":1,"start_column":1,"end_line":1,"end_column":2,"properties":{}}]}"#,
            "",
        ),
        common_event(
            "edge_upsert",
            6,
            r#", "edge":{"id":"edge:missing","source":"file:source","target":"unknown:go","kind":"imports","site_id":"site:missing","phase":"source","environment":"host","profile_id":"go:test","condition":{"op":"all","conditions":[]},"resolution_status":"unresolved","precision":"exact","generated":false,"evidence":[{"kind":"source","extractor":"fixture","extractor_version":"1.0","path":"go.mod","start_line":1,"start_column":1,"end_line":1,"end_column":2,"properties":{}}]}"#,
            "",
        ),
        common_event(
            "file_completed",
            7,
            r#", "path":"go.mod","discovered_sites":1,"emitted_sites":1,"skipped_sites":0,"skipped":false"#,
            "",
        ),
        common_event(
            "profile_completed",
            8,
            &format!(r#", "profile_id":"go:test","coverage":{summary}"#),
            "",
        ),
        common_event(
            "scan_completed",
            9,
            &format!(r#", "coverage":{summary}"#),
            "",
        ),
    ]
    .join("\n")
}

#[cfg(unix)]
fn scan_with_worker(
    root: &std::path::Path,
    store: &std::path::Path,
    worker: &std::path::Path,
    strict: bool,
) -> std::process::Output {
    let mut command = Command::cargo_bin("depgraph").unwrap();
    command.env("DEPGRAPH_GO_WORKER", worker).args([
        "--store",
        store.to_str().unwrap(),
        "scan",
        root.to_str().unwrap(),
    ]);
    if strict {
        command.arg("--strict");
    }
    command.arg("--json").output().unwrap()
}

#[cfg(unix)]
fn rust_fixture_root(worker_timeout_seconds: u64) -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    fs::write(
        root.path().join("Cargo.toml"),
        "[package]\nname='rust-failure-fixture'\nversion='0.1.0'\nedition='2024'\n",
    )
    .unwrap();
    fs::write(
        root.path().join(".depgraph.toml"),
        format!("schema_version = 1\n[scan]\nworker_timeout_seconds = {worker_timeout_seconds}\n"),
    )
    .unwrap();
    root
}

#[cfg(unix)]
fn rust_common_event(event: &str, seq: u64, payload: &str, extra_arguments: &str) -> String {
    format!(
        r#"printf '{{"event":"{event}","protocol_version":"1.0","scan_id":"%s","adapter":"rust","adapter_version":"0.1.0","seq":{seq}{payload}}}\n' "$scan"{extra_arguments}"#
    )
}

#[cfg(unix)]
fn rust_failure_worker(action: &str, stderr: &str) -> String {
    [
        PARSE_ARGS.to_owned(),
        rust_common_event(
            "scan_started",
            1,
            r#", "root":"%s","project_code_executed":false,"safe_mode":true"#,
            r#" "$root""#,
        ),
        rust_common_event(
            "profile_declared",
            2,
            r#", "profile":{"id":"rust:test","language":"rust","features":[],"environment":{},"properties":{}}"#,
            "",
        ),
        rust_common_event(
            "node_upsert",
            3,
            r#", "node":{"id":"file:rust-prefix","kind":"file","locator":"file://Cargo.toml","properties":{}}"#,
            "",
        ),
        format!("printf '%s' {stderr:?} >&2"),
        action.to_owned(),
    ]
    .join("\n")
}

#[cfg(unix)]
fn rust_typed_backend_failure_worker() -> String {
    let coverage = r#"{"profiles":1,"files_discovered":1,"files_analyzed":1,"files_skipped":0,"dependency_sites":0,"resolved":0,"candidates":0,"external":0,"unresolved":0,"unsupported_syntax":0,"project_code_executed":false,"completeness":["syntax-complete"],"reasons":["rust-hir-backend-failure"]}"#;
    [
        PARSE_ARGS.to_owned(),
        rust_common_event(
            "scan_started",
            1,
            r#", "root":"%s","project_code_executed":false,"safe_mode":true"#,
            r#" "$root""#,
        ),
        rust_common_event(
            "profile_declared",
            2,
            r#", "profile":{"id":"rust:test","language":"rust","features":[],"environment":{},"properties":{"analysis":"syntax","rust_hir_status":"failed"}}"#,
            "",
        ),
        rust_common_event(
            "file_completed",
            3,
            r#", "path":"Cargo.toml","discovered_sites":0,"emitted_sites":0,"skipped_sites":0,"skipped":false"#,
            "",
        ),
        rust_common_event(
            "profile_completed",
            4,
            &format!(r#", "profile_id":"rust:test","coverage":{coverage}"#),
            "",
        ),
        rust_common_event(
            "scan_completed",
            5,
            &format!(r#", "coverage":{coverage}"#),
            "",
        ),
    ]
    .join("\n")
}

#[cfg(unix)]
fn scan_with_rust_worker(
    root: &std::path::Path,
    store: &std::path::Path,
    worker: &std::path::Path,
) -> std::process::Output {
    Command::cargo_bin("depgraph")
        .unwrap()
        .env("DEPGRAPH_RUST_WORKER", worker)
        .args([
            "--store",
            store.to_str().unwrap(),
            "scan",
            root.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap()
}

#[cfg(unix)]
#[test]
fn failed_attempt_keeps_partial_graph_without_replacing_latest_success() {
    let root = fixture_root();
    let temp = tempfile::tempdir().unwrap();
    let store = temp.path().join("graph.db");
    let complete = temp.path().join("complete.sh");
    write_worker(&complete, &complete_worker("file:normal"));
    let first = Command::cargo_bin("depgraph")
        .unwrap()
        .env("DEPGRAPH_GO_WORKER", &complete)
        .args([
            "--store",
            store.to_str().unwrap(),
            "scan",
            root.path().to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(
        first.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&first.stdout)
    );

    let partial = temp.path().join("partial.sh");
    let partial_body = [
        PARSE_ARGS.to_owned(),
        common_event(
            "scan_started",
            1,
            r#", "root":"%s","project_code_executed":false,"safe_mode":true"#,
            r#" "$root""#,
        ),
        common_event(
            "profile_declared",
            2,
            r#", "profile":{"id":"go:test","language":"go","features":[],"environment":{},"properties":{}}"#,
            "",
        ),
        common_event(
            "node_upsert",
            3,
            r#", "node":{"id":"file:partial","kind":"file","locator":"file://partial.go","properties":{}}"#,
            "",
        ),
        "printf 'not-json\\n'".to_owned(),
    ]
    .join("\n");
    write_worker(&partial, &partial_body);
    let failed = Command::cargo_bin("depgraph")
        .unwrap()
        .env("DEPGRAPH_GO_WORKER", &partial)
        .args([
            "--store",
            store.to_str().unwrap(),
            "scan",
            root.path().to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(failed.status.code(), Some(3));
    let failed_json: serde_json::Value = serde_json::from_slice(&failed.stdout).unwrap();
    assert_eq!(failed_json["status"], "partial");
    let partial_scan = failed_json["scan_id"].as_str().unwrap();

    let latest = Command::cargo_bin("depgraph")
        .unwrap()
        .args([
            "--store",
            store.to_str().unwrap(),
            "export",
            "--format",
            "json",
        ])
        .output()
        .unwrap();
    assert!(latest.status.success());
    let latest = String::from_utf8(latest.stdout).unwrap();
    assert!(latest.contains("file:normal"));
    assert!(!latest.contains("file:partial"));

    let partial_export = Command::cargo_bin("depgraph")
        .unwrap()
        .args([
            "--store",
            store.to_str().unwrap(),
            "--scan-id",
            partial_scan,
            "export",
            "--format",
            "json",
        ])
        .output()
        .unwrap();
    assert!(partial_export.status.success());
    assert!(
        String::from_utf8(partial_export.stdout)
            .unwrap()
            .contains("file:partial")
    );

    let doctor = Command::cargo_bin("depgraph")
        .unwrap()
        .args(["--store", store.to_str().unwrap(), "doctor", "--json"])
        .output()
        .unwrap();
    let doctor: serde_json::Value = serde_json::from_slice(&doctor.stdout).unwrap();
    assert_eq!(doctor["latest_attempt"]["status"], "partial");
}

#[cfg(unix)]
#[test]
fn rust_worker_failures_are_partial_exit_three_and_canonically_stable() {
    let root = rust_fixture_root(10);
    let timeout_root = rust_fixture_root(1);
    let temp = tempfile::tempdir().unwrap();
    let scenarios = [
        ("panic", "exit 101", "volatile-panic-stderr", "nonzero-exit"),
        (
            "stderr-spoof",
            "exit 101",
            "timed out; security policy; volatile stderr",
            "nonzero-exit",
        ),
        ("path-spoof", "exit 101", "ordinary stderr", "nonzero-exit"),
        (
            "timeout",
            "exec sleep 10",
            "volatile-timeout-stderr",
            "timeout",
        ),
        (
            "malformed",
            "printf 'not-json\\n'",
            "volatile-malformed-stderr",
            "malformed-protocol",
        ),
        (
            "nonzero-malformed",
            "printf 'not-json\\n'; exit 101",
            "volatile-nonzero-malformed-stderr",
            "nonzero-exit",
        ),
    ];
    let mut first_nonzero = None;

    for (name, action, raw_stderr, expected_kind) in scenarios {
        let worker = if name == "path-spoof" {
            let directory = temp.path().join("timed out security policy");
            fs::create_dir(&directory).unwrap();
            directory.join("worker.sh")
        } else {
            temp.path().join(format!("{name}-worker.sh"))
        };
        write_worker(&worker, &rust_failure_worker(action, raw_stderr));
        let store = temp.path().join(format!("{name}.db"));
        let scan_root = if name == "timeout" {
            timeout_root.path()
        } else {
            root.path()
        };
        let output = scan_with_rust_worker(scan_root, &store, &worker);
        assert_eq!(
            output.status.code(),
            Some(3),
            "scenario={name}\nstdout={}\nstderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["status"], "partial", "scenario={name}");
        assert!(
            !report["coverage"]["completeness"]
                .as_array()
                .unwrap()
                .contains(&serde_json::json!("semantic-complete")),
            "scenario={name}"
        );
        let stable_reason = format!("worker-failure:rust:{expected_kind}");
        assert!(
            report["coverage"]["reasons"]
                .as_array()
                .unwrap()
                .contains(&serde_json::Value::String(stable_reason.clone())),
            "scenario={name}: {}",
            report["coverage"]
        );
        let failure = report["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .find(|diagnostic| diagnostic["code"] == "worker-failure")
            .unwrap();
        assert_eq!(failure["message"], stable_reason);
        let canonical = serde_json::json!({
            "coverage": report["coverage"],
            "diagnostics": report["diagnostics"],
        });
        let serialized = serde_json::to_string(&canonical).unwrap();
        assert!(!serialized.contains(worker.to_string_lossy().as_ref()));
        assert!(!serialized.contains(raw_stderr));

        if name == "panic" {
            first_nonzero = Some(canonical);
        }
    }

    let worker = temp.path().join("other-checkout-panic-worker.sh");
    write_worker(
        &worker,
        &rust_failure_worker("exit 101", "different-volatile-stderr"),
    );
    let repeated =
        scan_with_rust_worker(root.path(), &temp.path().join("panic-repeated.db"), &worker);
    assert_eq!(repeated.status.code(), Some(3));
    let repeated: serde_json::Value = serde_json::from_slice(&repeated.stdout).unwrap();
    assert_eq!(
        first_nonzero.unwrap(),
        serde_json::json!({
            "coverage": repeated["coverage"],
            "diagnostics": repeated["diagnostics"],
        })
    );
}

#[cfg(unix)]
#[test]
fn strict_rust_hir_backend_failure_is_policy_failed_exit_one() {
    let root = rust_fixture_root(10);
    let temp = tempfile::tempdir().unwrap();
    let worker = temp.path().join("typed-backend-failure.sh");
    write_worker(&worker, &rust_typed_backend_failure_worker());
    let output = Command::cargo_bin("depgraph")
        .unwrap()
        .env("DEPGRAPH_RUST_WORKER", &worker)
        .args([
            "--store",
            temp.path().join("strict.db").to_str().unwrap(),
            "scan",
            root.path().to_str().unwrap(),
            "--strict",
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(1),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["status"], "policy_failed");
    assert!(
        report["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .any(|diagnostic| {
                diagnostic["code"] == "strict-policy"
                    && diagnostic["message"]
                        .as_str()
                        .is_some_and(|message| message.contains("rust_hir_backend_failure=true"))
            })
    );
}

#[cfg(unix)]
#[test]
fn unsafe_worker_is_a_security_exit() {
    let root = fixture_root();
    let temp = tempfile::tempdir().unwrap();
    let worker = temp.path().join("unsafe.sh");
    let body = [
        PARSE_ARGS.to_owned(),
        common_event(
            "scan_started",
            1,
            r#", "root":"%s","project_code_executed":true,"safe_mode":false"#,
            r#" "$root""#,
        ),
    ]
    .join("\n");
    write_worker(&worker, &body);
    Command::cargo_bin("depgraph")
        .unwrap()
        .env("DEPGRAPH_GO_WORKER", &worker)
        .args([
            "--store",
            temp.path().join("graph.db").to_str().unwrap(),
            "scan",
            root.path().to_str().unwrap(),
            "--json",
        ])
        .assert()
        .code(4)
        .stdout(predicate::str::contains("security_failed"));

    let worker = temp.path().join("unsafe-profile.sh");
    let unsafe_coverage = r#"{"profiles":1,"files_discovered":0,"files_analyzed":0,"files_skipped":0,"dependency_sites":0,"resolved":0,"candidates":0,"external":0,"unresolved":0,"unsupported_syntax":0,"project_code_executed":true,"completeness":[],"reasons":[]}"#;
    let body = [
        PARSE_ARGS.to_owned(),
        common_event(
            "scan_started",
            1,
            r#", "root":"%s","project_code_executed":false,"safe_mode":true"#,
            r#" "$root""#,
        ),
        common_event(
            "profile_declared",
            2,
            r#", "profile":{"id":"go:test","language":"go","features":[],"environment":{},"properties":{}}"#,
            "",
        ),
        common_event(
            "profile_completed",
            3,
            &format!(r#", "profile_id":"go:test","coverage":{unsafe_coverage}"#),
            "",
        ),
    ]
    .join("\n");
    write_worker(&worker, &body);
    Command::cargo_bin("depgraph")
        .unwrap()
        .env("DEPGRAPH_GO_WORKER", &worker)
        .args([
            "--store",
            temp.path().join("profile.db").to_str().unwrap(),
            "scan",
            root.path().to_str().unwrap(),
            "--json",
        ])
        .assert()
        .code(4)
        .stdout(predicate::str::contains("security_failed"));
}

#[cfg(unix)]
#[test]
fn project_local_worker_override_is_rejected_before_execution() {
    let root = fixture_root();
    let worker = root.path().join("project-worker.sh");
    let marker = root.path().join("PROJECT_WORKER_EXECUTED");
    write_worker(&worker, "printf executed > PROJECT_WORKER_EXECUTED\nexit 0");
    let store = tempfile::tempdir().unwrap();

    Command::cargo_bin("depgraph")
        .unwrap()
        .current_dir(root.path())
        .env("DEPGRAPH_GO_WORKER", &worker)
        .args([
            "--store",
            store.path().join("graph.db").to_str().unwrap(),
            "scan",
            ".",
            "--json",
        ])
        .assert()
        .code(4)
        .stdout(predicate::str::contains("security_failed"));
    assert!(!marker.exists());
}

#[cfg(unix)]
#[test]
fn safe_scan_does_not_resolve_node_git_or_node_options_from_the_repository() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("project");
    fs::create_dir(&root).unwrap();
    fs::write(
        root.join("package.json"),
        r#"{"name":"safe-path-fixture","private":true}"#,
    )
    .unwrap();
    write_worker(&root.join("node"), "printf unsafe > NODE_EXECUTED\nexit 91");
    write_worker(&root.join("git"), "printf unsafe > GIT_EXECUTED\nexit 91");
    write_worker(
        &root.join("cargo"),
        "printf unsafe > CARGO_EXECUTED\nexit 91",
    );
    write_worker(
        &root.join("rustc"),
        "printf unsafe > RUSTC_EXECUTED\nexit 91",
    );
    write_worker(
        &root.join("rustc-wrapper"),
        "printf unsafe > RUSTC_WRAPPER_EXECUTED\nexit 91",
    );
    write_worker(
        &root.join("rustc-workspace-wrapper"),
        "printf unsafe > RUSTC_WORKSPACE_WRAPPER_EXECUTED\nexit 91",
    );
    fs::write(
        root.join("project-hook.cjs"),
        "require('node:fs').writeFileSync('NODE_OPTIONS_EXECUTED', 'unsafe')\n",
    )
    .unwrap();

    let worker = temp.path().join("web-worker.mjs");
    fs::write(
        &worker,
        r#"const args = process.argv.slice(2);
const root = args[args.indexOf("--root") + 1];
const scan = args[args.indexOf("--scan-id") + 1];
const common = {protocol_version:"1.0",scan_id:scan,adapter:"web",adapter_version:"0.1.0"};
const coverage = {profiles:1,files_discovered:0,files_analyzed:0,files_skipped:0,dependency_sites:0,resolved:0,candidates:0,external:0,unresolved:0,unsupported_syntax:0,project_code_executed:false,completeness:["syntax-complete"],reasons:[]};
const events = [
  {event:"scan_started",...common,seq:1,root,project_code_executed:false,safe_mode:true},
  {event:"profile_declared",...common,seq:2,profile:{id:"web:test",language:"web",features:[],environment:{},properties:{typescript_analysis_mode:"semantic-definition-graph",typescript_project_model_status:"ready",typescript_typechecker_status:"definition-graph-emitted",typescript_definition_graph_status:"ready",typescript_semantic_graph_emission:"definition-graph-v1",typescript_semantic_node_count:"0",typescript_semantic_relation_count:"0",typescript_semantic_issue_count:"0",typescript_release_gate:"release-gate-pending"}}},
  {event:"profile_completed",...common,seq:3,profile_id:"web:test",coverage},
  {event:"scan_completed",...common,seq:4,coverage}
];
for (const event of events) console.log(JSON.stringify(event));
"#,
    )
    .unwrap();
    let mut paths = vec![std::path::PathBuf::from(".")];
    paths.extend(std::env::split_paths(&std::env::var_os("PATH").unwrap()));
    let path = std::env::join_paths(paths).unwrap();
    let first_store = temp.path().join("web-before-pack.db");
    let first = Command::cargo_bin("depgraph")
        .unwrap()
        .current_dir(&root)
        .env("PATH", &path)
        .env("NODE_OPTIONS", "--require ./project-hook.cjs")
        .env("RUSTC", root.join("rustc"))
        .env("RUSTC_WRAPPER", root.join("rustc-wrapper"))
        .env(
            "RUSTC_WORKSPACE_WRAPPER",
            root.join("rustc-workspace-wrapper"),
        )
        .env("DEPGRAPH_WEB_WORKER", &worker)
        .args([
            "--store",
            first_store.to_str().unwrap(),
            "scan",
            ".",
            "--json",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"status\": \"completed\""))
        .get_output()
        .stdout
        .clone();

    let compiler_pack = root.join(".depgraph/compiler-pack");
    fs::create_dir_all(&compiler_pack).unwrap();
    fs::write(
        compiler_pack.join("manifest.json"),
        r#"{"schema_version":"hostile-safe-scan-canary"}"#,
    )
    .unwrap();
    for executable in ["cargo", "rustc", "rustc-wrapper", "rustc-workspace-wrapper"] {
        write_worker(
            &compiler_pack.join(executable),
            &format!("printf unsafe > {}_PACK_EXECUTED\nexit 91", executable),
        );
    }

    let second_store = temp.path().join("web-after-pack.db");
    let second = Command::cargo_bin("depgraph")
        .unwrap()
        .current_dir(&root)
        .env("PATH", &path)
        .env("NODE_OPTIONS", "--require ./project-hook.cjs")
        .env("RUSTC", root.join("rustc"))
        .env("RUSTC_WRAPPER", root.join("rustc-wrapper"))
        .env(
            "RUSTC_WORKSPACE_WRAPPER",
            root.join("rustc-workspace-wrapper"),
        )
        .env("DEPGRAPH_WEB_WORKER", &worker)
        .args([
            "--store",
            second_store.to_str().unwrap(),
            "scan",
            ".",
            "--json",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"status\": \"completed\""))
        .get_output()
        .stdout
        .clone();

    let cache_keys = |output: &[u8]| {
        serde_json::from_slice::<serde_json::Value>(output).unwrap()["cache_events"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|event| event["cache_key"].as_str().map(ToOwned::to_owned))
            .collect::<Vec<_>>()
    };
    let first_cache_keys = cache_keys(&first);
    assert!(!first_cache_keys.is_empty());
    assert_eq!(first_cache_keys, cache_keys(&second));

    let export = |store: &std::path::Path| {
        Command::cargo_bin("depgraph")
            .unwrap()
            .args([
                "--store",
                store.to_str().unwrap(),
                "export",
                "--format",
                "json",
            ])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone()
    };
    assert_eq!(export(&first_store), export(&second_store));
    assert!(!root.join("NODE_EXECUTED").exists());
    assert!(!root.join("GIT_EXECUTED").exists());
    assert!(!root.join("CARGO_EXECUTED").exists());
    assert!(!root.join("RUSTC_EXECUTED").exists());
    assert!(!root.join("RUSTC_WRAPPER_EXECUTED").exists());
    assert!(!root.join("RUSTC_WORKSPACE_WRAPPER_EXECUTED").exists());
    assert!(!root.join("NODE_OPTIONS_EXECUTED").exists());
    for executable in ["cargo", "rustc", "rustc-wrapper", "rustc-workspace-wrapper"] {
        assert!(!root.join(format!("{executable}_PACK_EXECUTED")).exists());
    }
}

#[cfg(unix)]
#[test]
fn worker_subprocess_path_does_not_resolve_repository_cargo() {
    let root = fixture_root();
    write_worker(
        &root.path().join("cargo"),
        "printf unsafe > CARGO_EXECUTED\nexit 91",
    );
    let temp = tempfile::tempdir().unwrap();
    let worker = temp.path().join("go-worker.sh");
    write_worker(
        &worker,
        &format!(
            "cargo --version >/dev/null\n{}",
            complete_worker("file:safe")
        ),
    );
    let mut paths = vec![std::path::PathBuf::from(".")];
    paths.extend(std::env::split_paths(&std::env::var_os("PATH").unwrap()));
    let path = std::env::join_paths(paths).unwrap();

    Command::cargo_bin("depgraph")
        .unwrap()
        .current_dir(root.path())
        .env("PATH", path)
        .env("DEPGRAPH_GO_WORKER", &worker)
        .args([
            "--store",
            temp.path().join("go.db").to_str().unwrap(),
            "scan",
            ".",
            "--json",
        ])
        .assert()
        .success();
    assert!(!root.path().join("CARGO_EXECUTED").exists());
}

#[test]
fn usage_and_invalid_config_are_exit_two() {
    Command::cargo_bin("depgraph")
        .unwrap()
        .arg("not-an-mvp-command")
        .assert()
        .code(2)
        .stderr(predicate::str::contains("Usage:"));

    let root = tempfile::tempdir().unwrap();
    let cache = tempfile::tempdir().unwrap();
    fs::write(root.path().join(".depgraph.toml"), "schema_version = 99\n").unwrap();
    Command::cargo_bin("depgraph")
        .unwrap()
        .args([
            "--store",
            cache.path().join("graph.db").to_str().unwrap(),
            "scan",
            root.path().to_str().unwrap(),
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains(
            "unsupported config schema_version 99",
        ));

    fs::write(
        root.path().join(".depgraph.toml"),
        "schema_version = 1\n[scan]\nworker_timout_seconds = 5\n",
    )
    .unwrap();
    Command::cargo_bin("depgraph")
        .unwrap()
        .args([
            "--store",
            cache.path().join("graph-unknown.db").to_str().unwrap(),
            "scan",
            root.path().to_str().unwrap(),
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("unknown field"));

    fs::write(
        root.path().join(".depgraph.toml"),
        "schema_version = 1\n[scan]\nworker_timeout_seconds = 0\n",
    )
    .unwrap();
    Command::cargo_bin("depgraph")
        .unwrap()
        .args([
            "--store",
            cache.path().join("graph-zero.db").to_str().unwrap(),
            "scan",
            root.path().to_str().unwrap(),
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains(
            "worker_timeout_seconds must be at least 1",
        ));

    fs::write(
        root.path().join(".depgraph.toml"),
        "schema_version = 1\n[policy]\nschema_version = '2.0'\n",
    )
    .unwrap();
    Command::cargo_bin("depgraph")
        .unwrap()
        .args([
            "--store",
            cache
                .path()
                .join("graph-policy-version.db")
                .to_str()
                .unwrap(),
            "scan",
            root.path().to_str().unwrap(),
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains(
            "unsupported policy schema_version 2.0",
        ));
}

#[test]
fn corrupt_store_is_an_operational_exit_three() {
    let root = tempfile::tempdir().unwrap();
    let store = root.path().join("corrupt.db");
    fs::write(&store, b"not a sqlite database").unwrap();
    Command::cargo_bin("depgraph")
        .unwrap()
        .args(["--store", store.to_str().unwrap(), "doctor"])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("error:"));
}

#[cfg(unix)]
#[test]
fn strict_unresolved_scan_is_exit_one_and_does_not_replace_success() {
    let root = fixture_root();
    let temp = tempfile::tempdir().unwrap();
    let store = temp.path().join("graph.db");
    let worker = temp.path().join("unresolved.sh");
    write_worker(&worker, &unresolved_worker());

    let successful = scan_with_worker(root.path(), &store, &worker, false);
    assert_eq!(
        successful.status.code(),
        Some(0),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&successful.stdout),
        String::from_utf8_lossy(&successful.stderr)
    );
    let successful: serde_json::Value = serde_json::from_slice(&successful.stdout).unwrap();

    let strict = scan_with_worker(root.path(), &store, &worker, true);
    assert_eq!(
        strict.status.code(),
        Some(1),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&strict.stdout),
        String::from_utf8_lossy(&strict.stderr)
    );
    let strict: serde_json::Value = serde_json::from_slice(&strict.stdout).unwrap();
    assert_eq!(strict["status"], "policy_failed");
    assert_eq!(strict["coverage"]["unresolved"], 1);
    assert!(
        strict["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .any(|diagnostic| {
                diagnostic["code"] == "strict-policy"
                    && diagnostic["message"]
                        .as_str()
                        .is_some_and(|message| message.contains("unresolved=1 (max 0)"))
            })
    );

    let latest = Command::cargo_bin("depgraph")
        .unwrap()
        .args(["--store", store.to_str().unwrap(), "doctor", "--json"])
        .output()
        .unwrap();
    assert!(latest.status.success());
    let latest: serde_json::Value = serde_json::from_slice(&latest.stdout).unwrap();
    assert_eq!(latest["latest_attempt"]["status"], "policy_failed");

    let default_export = Command::cargo_bin("depgraph")
        .unwrap()
        .args([
            "--store",
            store.to_str().unwrap(),
            "export",
            "--format",
            "json",
        ])
        .output()
        .unwrap();
    assert!(default_export.status.success());
    assert_ne!(
        successful["scan_id"], strict["scan_id"],
        "the two attempts must have distinct identities"
    );
}

#[cfg(unix)]
#[test]
fn nonzero_worker_exit_is_exit_three_and_keeps_its_valid_prefix() {
    let root = fixture_root();
    let temp = tempfile::tempdir().unwrap();
    let store = temp.path().join("graph.db");
    let worker = temp.path().join("crash.sh");
    let body = [
        PARSE_ARGS.to_owned(),
        common_event(
            "scan_started",
            1,
            r#", "root":"%s","project_code_executed":false,"safe_mode":true"#,
            r#" "$root""#,
        ),
        common_event(
            "profile_declared",
            2,
            r#", "profile":{"id":"go:test","language":"go","features":[],"environment":{},"properties":{}}"#,
            "",
        ),
        common_event(
            "node_upsert",
            3,
            r#", "node":{"id":"file:before-crash","kind":"file","locator":"file://before-crash.go","properties":{}}"#,
            "",
        ),
        "printf 'worker exploded\\n' >&2".to_owned(),
        "exit 17".to_owned(),
    ]
    .join("\n");
    write_worker(&worker, &body);

    let failed = scan_with_worker(root.path(), &store, &worker, false);
    assert_eq!(failed.status.code(), Some(3));
    let failed: serde_json::Value = serde_json::from_slice(&failed.stdout).unwrap();
    assert_eq!(failed["status"], "partial");
    assert!(
        failed["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .any(|diagnostic| {
                diagnostic["code"] == "worker-failure"
                    && diagnostic["message"]
                        .as_str()
                        .is_some_and(|message| message == "worker-failure:go:nonzero-exit")
            })
    );

    let explicit = Command::cargo_bin("depgraph")
        .unwrap()
        .args([
            "--store",
            store.to_str().unwrap(),
            "--scan-id",
            failed["scan_id"].as_str().unwrap(),
            "export",
            "--format",
            "json",
        ])
        .output()
        .unwrap();
    assert!(explicit.status.success());
    assert!(
        String::from_utf8(explicit.stdout)
            .unwrap()
            .contains("file:before-crash")
    );
}

#[cfg(unix)]
#[test]
fn architecture_policy_violation_is_reported_end_to_end() {
    let root = fixture_root();
    fs::write(
        root.path().join(".depgraph.toml"),
        r#"
schema_version = 1

[policy]
schema_version = "1.0"

[[policy.rules]]
id = "no-root-to-shared"
kind = "forbidden_dependency"
severity = "error"
source = { kind = "file", field = "path", match = "exact", value = "go.mod", cardinality = "one", exclude = [], scope = { paths = [], packages = [] } }
target = { kind = "file", field = "path", match = "glob", value = "src/**", cardinality = "many", exclude = [], scope = { paths = [], packages = [] } }
profiles = { include = [{ match = "exact", value = "go:test" }], exclude = [] }
condition = { op = "all", conditions = [] }
precisions = ["exact"]
resolution_statuses = ["resolved"]
evidence = { kinds = ["source"], minimum_spans = 1, primary_only = true }
"#,
    )
    .unwrap();
    let temp = tempfile::tempdir().unwrap();
    let store = temp.path().join("graph.db");
    let worker = temp.path().join("graph.sh");
    write_worker(&worker, &graph_worker(false));

    let output = scan_with_worker(root.path(), &store, &worker, false);

    assert_eq!(
        output.status.code(),
        Some(1),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["status"], "policy_failed");
    assert_eq!(report["exit_code"], 1);
    assert_eq!(report["policy"]["summary"]["errors"], 2);
    assert_eq!(
        report["policy"]["violations"][0]["rule_id"],
        "no-root-to-shared"
    );
    assert_eq!(
        report["policy"]["violations"][0]["dependency_path"][0]["source_id"],
        "file:source"
    );
    assert_eq!(
        report["policy"]["violations"][0]["evidence"][0]["path"],
        "go.mod"
    );
    let store = depgraph_store::Store::open(&store).unwrap();
    assert!(store.current_snapshot_id().unwrap().is_none());
}

#[cfg(unix)]
#[test]
fn ambiguous_bare_selector_lists_candidates_and_explicit_selector_works() {
    let root = fixture_root();
    let temp = tempfile::tempdir().unwrap();
    let store = temp.path().join("graph.db");
    let worker = temp.path().join("graph.sh");
    write_worker(&worker, &graph_worker(false));
    let scan = scan_with_worker(root.path(), &store, &worker, false);
    assert_eq!(
        scan.status.code(),
        Some(0),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&scan.stdout),
        String::from_utf8_lossy(&scan.stderr)
    );

    Command::cargo_bin("depgraph")
        .unwrap()
        .args([
            "--store",
            store.to_str().unwrap(),
            "deps",
            "shared",
            "--json",
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("is ambiguous"))
        .stderr(predicate::str::contains("file://src/shared-one.go"))
        .stderr(predicate::str::contains("file://src/shared-two.go"));

    let explicit = Command::cargo_bin("depgraph")
        .unwrap()
        .args([
            "--store",
            store.to_str().unwrap(),
            "deps",
            "path:src/shared-one.go",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(explicit.status.success());
    let explicit: serde_json::Value = serde_json::from_slice(&explicit.stdout).unwrap();
    assert_eq!(explicit["data"]["root"]["id"], "file:one");

    let no_path = Command::cargo_bin("depgraph")
        .unwrap()
        .args([
            "--store",
            store.to_str().unwrap(),
            "why",
            "path:src/shared-one.go",
            "path:src/shared-two.go",
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(no_path.status.code(), Some(0));
    let no_path: serde_json::Value = serde_json::from_slice(&no_path.stdout).unwrap();
    assert_eq!(no_path["data"]["path_found"], false);
    assert_eq!(no_path["data"]["steps"], serde_json::json!([]));

    Command::cargo_bin("depgraph")
        .unwrap()
        .args([
            "--store",
            store.to_str().unwrap(),
            "why",
            "path:src/shared-one.go",
            "path:src/shared-two.go",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "no dependency path exists from file://src/shared-one.go to file://src/shared-two.go",
        ));

    Command::cargo_bin("depgraph")
        .unwrap()
        .args([
            "--store",
            store.to_str().unwrap(),
            "why",
            "path:missing.go",
            "path:src/shared-two.go",
            "--json",
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("did not match any node"));
}

#[cfg(unix)]
#[test]
fn semantic_selectors_cycles_and_query_evidence_are_exposed() {
    let root = fixture_root();
    let temp = tempfile::tempdir().unwrap();
    let store = temp.path().join("graph.db");
    let worker = temp.path().join("semantic-graph.sh");
    let fixture = semantic_graph_worker();
    write_worker(&worker, &fixture.worker);

    let contract_output = std::process::Command::new(&worker)
        .args([
            "--root",
            root.path().to_str().unwrap(),
            "--scan-id",
            "semantic-contract-check",
        ])
        .output()
        .unwrap();
    assert!(
        contract_output.status.success(),
        "semantic fixture worker failed: {}",
        String::from_utf8_lossy(&contract_output.stderr)
    );
    depgraph_protocol::validate_safe_semantic_ndjson(std::io::Cursor::new(&contract_output.stdout))
        .expect("CLI semantic fixture must satisfy the strict semantic contract");

    let scan = scan_with_worker(root.path(), &store, &worker, false);
    assert_eq!(
        scan.status.code(),
        Some(0),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&scan.stdout),
        String::from_utf8_lossy(&scan.stderr)
    );

    let query = |arguments: &[&str]| {
        let output = Command::cargo_bin("depgraph")
            .unwrap()
            .args(["--store", store.to_str().unwrap()])
            .args(arguments)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "args={arguments:?}\nstdout={}\nstderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        output
    };

    let symbol = query(&["deps", "symbol:OnlySymbol", "--json"]);
    let symbol: serde_json::Value = serde_json::from_slice(&symbol.stdout).unwrap();
    assert_eq!(symbol["data"]["root"]["id"], fixture.only_symbol_id);
    assert_eq!(symbol["data"]["root"]["kind"], "symbol");

    let r#type = query(&["deps", "type:Shared", "--json"]);
    let r#type: serde_json::Value = serde_json::from_slice(&r#type.stdout).unwrap();
    assert_eq!(r#type["data"]["root"]["id"], fixture.shared_type_id);
    assert_eq!(r#type["data"]["root"]["kind"], "type");

    for (selector, excluded_id) in [
        ("symbol:OnlyType", fixture.only_type_id.as_str()),
        ("type:OnlySymbol", fixture.only_symbol_id.as_str()),
    ] {
        Command::cargo_bin("depgraph")
            .unwrap()
            .args([
                "--store",
                store.to_str().unwrap(),
                "deps",
                selector,
                "--json",
            ])
            .assert()
            .code(2)
            .stderr(predicate::str::contains("did not match any node"))
            .stderr(predicate::str::contains(excluded_id).not());
    }

    Command::cargo_bin("depgraph")
        .unwrap()
        .args([
            "--store",
            store.to_str().unwrap(),
            "deps",
            "symbol:Shared",
            "--json",
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("is ambiguous"))
        .stderr(predicate::str::contains(format!(
            "go://example.test/fixture.Alpha (symbol, id:{})",
            fixture.alpha_id
        )))
        .stderr(predicate::str::contains(format!(
            "go://example.test/fixture.Beta (symbol, id:{})",
            fixture.beta_id
        )))
        .stderr(predicate::str::contains(format!("id:{}", fixture.shared_type_id)).not());

    let alpha_selector = format!("id:{}", fixture.alpha_id);
    let beta_selector = format!("id:{}", fixture.beta_id);
    let deps = query(&["deps", &alpha_selector, "--json"]);
    let deps: serde_json::Value = serde_json::from_slice(&deps.stdout).unwrap();
    assert_eq!(deps["data"]["root"]["id"], fixture.alpha_id);
    assert_eq!(deps["data"]["edges"][0]["id"], fixture.alpha_beta_edge_id);
    assert_eq!(
        deps["data"]["steps"][0]["edge"]["id"],
        fixture.alpha_beta_edge_id
    );
    assert_eq!(deps["data"]["steps"][0]["evidence"][0]["kind"], "semantic");
    assert_eq!(
        deps["data"]["steps"][0]["evidence"][0]["properties"]["relation"],
        "calls"
    );

    let dependents = query(&["dependents", &beta_selector, "--json"]);
    let dependents: serde_json::Value = serde_json::from_slice(&dependents.stdout).unwrap();
    assert_eq!(
        dependents["data"]["steps"][0]["evidence"][0]["kind"],
        "semantic"
    );

    let why = query(&["why", &alpha_selector, &beta_selector, "--json"]);
    let why: serde_json::Value = serde_json::from_slice(&why.stdout).unwrap();
    assert_eq!(why["data"]["steps"][0]["edge"]["phase"], "semantic");
    assert_eq!(why["data"]["steps"][0]["evidence"][0]["kind"], "semantic");

    let exported = query(&["export", "--format", "json"]);
    let exported: serde_json::Value = serde_json::from_slice(&exported.stdout).unwrap();
    let semantic_edges = exported["graph"]["edges"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|edge| edge["phase"] == "semantic" && edge["kind"] == "calls")
        .collect::<Vec<_>>();
    assert_eq!(semantic_edges.len(), 2);
    assert!(
        exported["graph"]["evidence"]
            .as_array()
            .unwrap()
            .iter()
            .any(|evidence| {
                evidence["owner_type"] == "edge"
                    && evidence["owner_id"] == fixture.alpha_beta_edge_id
                    && evidence["kind"] == "semantic"
                    && evidence["extractor"] == "go-types"
            })
    );

    for arguments in [
        vec!["deps", alpha_selector.as_str()],
        vec!["dependents", beta_selector.as_str()],
        vec!["why", alpha_selector.as_str(), beta_selector.as_str()],
    ] {
        let output = query(&arguments);
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(
            stdout
                .contains("evidence semantic main.go:10:2-10:18 via go-types@1.0 (resolved calls)")
        );
        if arguments[0] == "why" {
            assert!(stdout.starts_with("go://example.test/fixture.Alpha\n"));
            assert!(stdout.contains(&format!(
                "  --calls [semantic; resolved; exact; go:test]--> {}",
                fixture.beta_id
            )));
            assert!(stdout.contains("      condition: true"));
        } else {
            assert!(stdout.contains(&format!(
                "{} --calls [semantic; resolved; exact; go:test]--> {}",
                fixture.alpha_id, fixture.beta_id
            )));
            assert!(stdout.contains("    condition: true"));
        }
    }

    let cycles = query(&["cycles", "--level", "symbol", "--json"]);
    let repeated_cycles = query(&["cycles", "--level", "symbol", "--json"]);
    assert_eq!(cycles.stdout, repeated_cycles.stdout);
    let cycles: serde_json::Value = serde_json::from_slice(&cycles.stdout).unwrap();
    let (first, second) = if fixture.alpha_id < fixture.beta_id {
        (&fixture.alpha_id, &fixture.beta_id)
    } else {
        (&fixture.beta_id, &fixture.alpha_id)
    };
    assert_eq!(
        cycles["data"],
        serde_json::json!([{
            "level": "symbol",
            "node_ids": [first, second, first]
        }])
    );
}

#[cfg(unix)]
#[test]
fn query_commands_report_traversal_evidence_cycles_doctor_and_unresolved_sites() {
    let root = fixture_root();
    let temp = tempfile::tempdir().unwrap();
    let store = temp.path().join("graph.db");
    let graph = temp.path().join("graph.sh");
    write_worker(&graph, &graph_worker(false));
    let scan = scan_with_worker(root.path(), &store, &graph, false);
    assert_eq!(scan.status.code(), Some(0));

    let query = |arguments: &[&str]| {
        let output = Command::cargo_bin("depgraph")
            .unwrap()
            .args(["--store", store.to_str().unwrap()])
            .args(arguments)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "args={arguments:?}\nstdout={}\nstderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap()
    };

    let deps = query(&["deps", "path:go.mod", "--json"]);
    assert_eq!(deps["data"]["edges"].as_array().unwrap().len(), 2);
    let dependents = query(&["dependents", "path:src/shared-one.go", "--json"]);
    assert_eq!(
        dependents["data"]["nodes"][0]["id"],
        serde_json::Value::String("file:source".to_owned())
    );
    let why = query(&["why", "path:go.mod", "path:src/shared-one.go", "--json"]);
    assert_eq!(why["data"]["steps"].as_array().unwrap().len(), 1);
    assert_eq!(
        why["data"]["steps"][0]["evidence"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let cycles = query(&["cycles", "--level", "file", "--json"]);
    assert!(cycles["data"].as_array().unwrap().is_empty());
    let doctor = query(&["doctor", "--json"]);
    assert_eq!(doctor["protocol_version"], "1.0");
    assert_eq!(doctor["latest_attempt"]["status"], "completed");
    assert_eq!(
        doctor["latest_attempt"]["profiles"][0]["coverage"]["profiles"],
        1
    );

    let unresolved_worker_path = temp.path().join("unresolved.sh");
    write_worker(&unresolved_worker_path, &unresolved_worker());
    let unresolved_scan = scan_with_worker(root.path(), &store, &unresolved_worker_path, false);
    assert_eq!(unresolved_scan.status.code(), Some(0));
    let unresolved = query(&["unresolved", "--json"]);
    assert_eq!(unresolved["data"].as_array().unwrap().len(), 1);
    assert_eq!(unresolved["data"][0]["site"]["id"], "site:missing");
    assert_eq!(
        unresolved["data"][0]["evidence"].as_array().unwrap().len(),
        1
    );
}

#[cfg(unix)]
#[test]
fn exports_are_byte_identical_across_scan_ids_and_event_order() {
    let root = fixture_root();
    let temp = tempfile::tempdir().unwrap();
    let store = temp.path().join("graph.db");
    let forward_worker = temp.path().join("forward.sh");
    let reverse_worker = temp.path().join("reverse.sh");
    write_worker(&forward_worker, &graph_worker(false));
    write_worker(&reverse_worker, &graph_worker(true));

    let forward = scan_with_worker(root.path(), &store, &forward_worker, false);
    assert_eq!(forward.status.code(), Some(0));
    let forward: serde_json::Value = serde_json::from_slice(&forward.stdout).unwrap();
    let reverse = scan_with_worker(root.path(), &store, &reverse_worker, false);
    assert_eq!(
        reverse.status.code(),
        Some(0),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&reverse.stdout),
        String::from_utf8_lossy(&reverse.stderr)
    );
    let reverse: serde_json::Value = serde_json::from_slice(&reverse.stdout).unwrap();

    for format in ["json", "dot", "mermaid", "graphml"] {
        let first = Command::cargo_bin("depgraph")
            .unwrap()
            .args([
                "--store",
                store.to_str().unwrap(),
                "--scan-id",
                forward["scan_id"].as_str().unwrap(),
                "export",
                "--format",
                format,
            ])
            .output()
            .unwrap();
        let second = Command::cargo_bin("depgraph")
            .unwrap()
            .args([
                "--store",
                store.to_str().unwrap(),
                "--scan-id",
                reverse["scan_id"].as_str().unwrap(),
                "export",
                "--format",
                format,
            ])
            .output()
            .unwrap();
        assert!(first.status.success());
        assert!(second.status.success());
        assert_eq!(
            first.stdout, second.stdout,
            "{format} export was not stable"
        );
    }

    let graphml_path = temp.path().join("graph.graphml");
    let graphml_file = Command::cargo_bin("depgraph")
        .unwrap()
        .args([
            "--store",
            store.to_str().unwrap(),
            "--scan-id",
            forward["scan_id"].as_str().unwrap(),
            "export",
            "--format",
            "graphml",
            "--output",
            graphml_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(graphml_file.status.success());
    assert!(graphml_file.stdout.is_empty());
    let graphml = std::fs::read_to_string(graphml_path).unwrap();
    assert!(graphml.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"));
    assert!(graphml.contains("attr.name=\"depgraph.edge.condition\""));
}

fn write_profile_plan_fixture(root: &Path) {
    fs::create_dir_all(root.join("src")).unwrap();
    fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"profile-plan-fixture\"\nversion = \"0.1.0\"\n",
    )
    .unwrap();
    fs::write(root.join("src/lib.rs"), "pub fn fixture() {}\n").unwrap();
}

#[test]
fn profiles_plan_is_read_only_explainable_and_checkout_independent() {
    let first = tempfile::tempdir().unwrap();
    let second = tempfile::tempdir().unwrap();
    write_profile_plan_fixture(first.path());
    write_profile_plan_fixture(second.path());

    let run = |root: &Path, json: bool| {
        let mut command = Command::cargo_bin("depgraph").unwrap();
        command.args(["profiles", "plan", root.to_str().unwrap()]);
        if json {
            command.arg("--json");
        }
        command.output().unwrap()
    };
    let first_json = run(first.path(), true);
    let second_json = run(second.path(), true);
    assert!(
        first_json.status.success(),
        "{}",
        String::from_utf8_lossy(&first_json.stderr)
    );
    assert!(second_json.status.success());
    assert_eq!(first_json.stdout, second_json.stdout);
    let preview: serde_json::Value = serde_json::from_slice(&first_json.stdout).unwrap();
    assert_eq!(preview["plan"]["selection_mode"], "automatic");
    assert_eq!(
        preview["plan"]["input"]["language_families"],
        json!(["rust"])
    );
    assert_eq!(preview["plan"]["summary"]["selected_profile_count"], 1);
    assert_eq!(preview["config_migration"]["status"], "default_equivalent");
    assert!(!first.path().join(".depgraph").exists());

    let human = run(first.path(), false);
    assert!(human.status.success());
    let human = String::from_utf8(human.stdout).unwrap();
    assert!(human.contains("profiles: 1 selected / 1 eligible"));
    assert!(human.contains("candidate profile:sha256:"));
    assert!(human.contains("selected profile:sha256:"));
    assert!(human.contains("config migration:"));
}

#[test]
fn profiles_plan_enforces_budget_and_explicit_all_or_error_boundaries() {
    let root = tempfile::tempdir().unwrap();
    write_profile_plan_fixture(root.path());
    let root_path = root.path().to_str().unwrap();

    Command::cargo_bin("depgraph")
        .unwrap()
        .args(["profiles", "plan", root_path, "--profile-budget", "0"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("profile-budget must be 1..=32"));

    let automatic = Command::cargo_bin("depgraph")
        .unwrap()
        .args(["profiles", "plan", root_path, "--json"])
        .output()
        .unwrap();
    assert!(automatic.status.success());
    let automatic: serde_json::Value = serde_json::from_slice(&automatic.stdout).unwrap();
    let axes = automatic["plan"]["profiles"][0]["axes"].clone();
    let mut unsupported_axes = axes.clone();
    unsupported_axes["target"] = json!("unsupported-target");
    let unsupported = root.path().join("unsupported-profiles.json");
    fs::write(
        &unsupported,
        serde_json::to_vec(&json!({
            "contract_version": "default-profile-selection-v1",
            "profiles": [unsupported_axes]
        }))
        .unwrap(),
    )
    .unwrap();
    Command::cargo_bin("depgraph")
        .unwrap()
        .args([
            "profiles",
            "plan",
            root_path,
            "--profiles-file",
            unsupported.to_str().unwrap(),
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("unavailable Rust target"));

    let explicit_value = json!({
        "contract_version": "default-profile-selection-v1",
        "profiles": [axes]
    });
    let first_file = root.path().join("profiles-a.json");
    let second_file = root.path().join("profiles-b.json");
    fs::write(
        &first_file,
        serde_json::to_vec_pretty(&explicit_value).unwrap(),
    )
    .unwrap();
    fs::write(&second_file, serde_json::to_vec(&explicit_value).unwrap()).unwrap();

    let run_explicit = |path: &Path| {
        Command::cargo_bin("depgraph")
            .unwrap()
            .args([
                "profiles",
                "plan",
                root_path,
                "--profiles-file",
                path.to_str().unwrap(),
                "--json",
            ])
            .output()
            .unwrap()
    };
    let first = run_explicit(&first_file);
    let second = run_explicit(&second_file);
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    assert!(second.status.success());
    assert_eq!(first.stdout, second.stdout);
    let explicit: serde_json::Value = serde_json::from_slice(&first.stdout).unwrap();
    assert_eq!(explicit["plan"]["selection_mode"], "explicit");
    assert_eq!(explicit["plan"]["summary"]["selected_profile_count"], 1);
    assert_eq!(explicit["plan"]["summary"]["omitted_profile_count"], 0);
    assert!(explicit["plan"]["discovery"].as_array().unwrap().is_empty());

    Command::cargo_bin("depgraph")
        .unwrap()
        .args([
            "profiles",
            "plan",
            root_path,
            "--profile-budget",
            "2",
            "--profiles-file",
            first_file.to_str().unwrap(),
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("cannot be used with"));

    let secret = "fixture-do-not-echo";
    let invalid = root.path().join("invalid-profiles.json");
    fs::write(
        &invalid,
        format!(
            r#"{{"contract_version":"default-profile-selection-v1","profiles":[],"api_token":"{secret}"}}"#
        ),
    )
    .unwrap();
    Command::cargo_bin("depgraph")
        .unwrap()
        .args([
            "profiles",
            "plan",
            root_path,
            "--profiles-file",
            invalid.to_str().unwrap(),
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("forbidden secret-bearing field"))
        .stderr(predicate::str::contains(secret).not());
}

#[cfg(unix)]
#[test]
fn profiles_plan_rejects_symlinked_explicit_files_as_security_errors() {
    use std::os::unix::fs::symlink;

    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::NamedTempFile::new().unwrap();
    write_profile_plan_fixture(root.path());
    let link = root.path().join("profiles.json");
    symlink(outside.path(), &link).unwrap();

    Command::cargo_bin("depgraph")
        .unwrap()
        .args([
            "profiles",
            "plan",
            root.path().to_str().unwrap(),
            "--profiles-file",
            link.to_str().unwrap(),
        ])
        .assert()
        .code(4)
        .stderr(predicate::str::contains("unsafe explicit profiles file"));
}
