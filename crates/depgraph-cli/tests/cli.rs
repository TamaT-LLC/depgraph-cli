use std::fs;

use assert_cmd::Command;
use predicates::prelude::*;

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
    assert!(store.exists());
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
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
fn safe_scan_does_not_resolve_node_or_node_options_from_the_repository() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("project");
    fs::create_dir(&root).unwrap();
    fs::write(
        root.join("package.json"),
        r#"{"name":"safe-path-fixture","private":true}"#,
    )
    .unwrap();
    write_worker(&root.join("node"), "printf unsafe > NODE_EXECUTED\nexit 91");
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
  {event:"profile_declared",...common,seq:2,profile:{id:"web:test",language:"web",features:[],environment:{},properties:{}}},
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

    Command::cargo_bin("depgraph")
        .unwrap()
        .current_dir(&root)
        .env("PATH", path)
        .env("NODE_OPTIONS", "--require ./project-hook.cjs")
        .env("DEPGRAPH_WEB_WORKER", &worker)
        .args([
            "--store",
            temp.path().join("web.db").to_str().unwrap(),
            "scan",
            ".",
            "--json",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"status\": \"completed\""));
    assert!(!root.join("NODE_EXECUTED").exists());
    assert!(!root.join("NODE_OPTIONS_EXECUTED").exists());
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
                        .is_some_and(|message| message.contains("exited with exit status: 17"))
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

    for format in ["json", "dot", "mermaid"] {
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
}
