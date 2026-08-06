use std::{
    fs,
    io::{BufRead as _, BufReader, Read as _, Write as _},
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    sync::OnceLock,
    time::{Duration, Instant},
};

use assert_cmd::Command as AssertCommand;
use depgraph_core::{
    CompilerPackBuildComponent, CompilerPackBuildSpec, CompilerPackRequirement,
    build_compiler_pack, compiler_pack_host_target, read_compiler_pack_requirement,
    verify_compiler_pack,
};
use depgraph_store::Store;
use rusqlite::Connection;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use wait_timeout::ChildExt as _;

const EOF_DEADLINE: Duration = Duration::from_secs(5);

#[derive(Debug, Eq, PartialEq)]
struct StoreInvariant {
    digest: String,
    row_count: u64,
    current_snapshot_id: Option<String>,
}

fn store_invariant(path: &Path) -> StoreInvariant {
    let digest = format!("{:x}", Sha256::digest(fs::read(path).unwrap()));
    let connection = Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .unwrap();
    let mut table_statement = connection
        .prepare(
            "SELECT name FROM sqlite_schema
              WHERE type='table' AND name NOT LIKE 'sqlite_%'
              ORDER BY name",
        )
        .unwrap();
    let tables = table_statement
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    let row_count = tables
        .iter()
        .map(|table| {
            let quoted = table.replace('"', "\"\"");
            connection
                .query_row(&format!("SELECT COUNT(*) FROM \"{quoted}\""), [], |row| {
                    row.get::<_, u64>(0)
                })
                .unwrap()
        })
        .sum();
    let current_snapshot_id = Store::open_read_only(path)
        .unwrap()
        .current_snapshot_id()
        .unwrap();
    StoreInvariant {
        digest,
        row_count,
        current_snapshot_id,
    }
}

fn seed_issue_300_store(path: &Path, root: &Path) -> String {
    let mut store = Store::open(path).unwrap();
    store
        .start_scan_with_revision("issue-300", root, false, Some("revision-300"))
        .unwrap();
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
            "scan_id": "issue-300",
            "adapter": "rust",
            "adapter_version": "0.1.0",
            "seq": seq
        })
    };
    let mut started = common("scan_started", 1);
    started["root"] = json!(root);
    started["project_code_executed"] = json!(false);
    started["safe_mode"] = json!(true);
    store.ingest_event(&started).unwrap();
    let mut profile = common("profile_declared", 2);
    profile["profile"] = json!({
        "id": "rust:safe",
        "language": "rust",
        "features": [],
        "environment": {"API_TOKEN": "PROCESS_PROFILE_SECRET"},
        "properties": {"compiler_command": "/usr/bin/rustc --crate-name process-secret"}
    });
    store.ingest_event(&profile).unwrap();
    for (seq, node) in [
        json!({
            "id": "node:zeta",
            "kind": "module",
            "locator": "repo://src/zeta.rs",
            "display_name": "crate::zeta",
            "properties": {"root": root, "secret": "PROCESS_SECRET"}
        }),
        json!({
            "id": "node:alpha",
            "kind": "module",
            "locator": "repo://src/alpha.rs#fixture",
            "display_name": "crate::alpha::fixture",
            "properties": {"root": root, "secret": "PROCESS_SECRET"}
        }),
    ]
    .into_iter()
    .enumerate()
    {
        let mut event = common("node_upsert", seq as u64 + 3);
        event["node"] = node;
        store.ingest_event(&event).unwrap();
    }
    let mut profile_completed = common("profile_completed", 5);
    profile_completed["profile_id"] = json!("rust:safe");
    profile_completed["coverage"] = coverage.clone();
    store.ingest_event(&profile_completed).unwrap();
    let mut completed = common("scan_completed", 6);
    completed["coverage"] = coverage;
    store.ingest_event(&completed).unwrap();
    store
        .save_adapter_log(
            "issue-300",
            "rust",
            "PROCESS_WORKER_LOG_SECRET /usr/bin/rustc",
            false,
        )
        .unwrap();
    store
        .finish_scan("issue-300", "completed", None, true)
        .unwrap();
    let snapshot_id = store.current_snapshot_id().unwrap().unwrap();
    store.create_snapshot_name("zeta", &snapshot_id).unwrap();
    store.create_snapshot_name("alpha", &snapshot_id).unwrap();
    drop(store);
    snapshot_id
}

fn seed_issue_302_store(path: &Path, root: &Path) -> String {
    let mut store = Store::open(path).unwrap();
    store
        .start_scan_with_revision("issue-302", root, false, Some("revision-302"))
        .unwrap();
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
            "scan_id": "issue-302",
            "adapter": "fixture",
            "adapter_version": "1.0",
            "seq": seq
        })
    };
    let mut started = common("scan_started", 1);
    started["root"] = json!(root);
    started["project_code_executed"] = json!(false);
    started["safe_mode"] = json!(true);
    store.ingest_event(&started).unwrap();
    let mut profile = common("profile_declared", 2);
    profile["profile"] = json!({
        "id": "fixture:safe",
        "language": "fixture",
        "features": [],
        "environment": {},
        "properties": {"private": root}
    });
    store.ingest_event(&profile).unwrap();
    for (offset, name) in ["d", "c", "b", "a"].into_iter().enumerate() {
        let mut node = common("node_upsert", offset as u64 + 3);
        node["node"] = json!({
            "id": format!("node:{name}"),
            "kind": "module",
            "locator": format!("repo://src/{name}.rs"),
            "display_name": format!("fixture::{name}"),
            "properties": {"path": format!("src/{name}.rs"), "secret": root}
        });
        store.ingest_event(&node).unwrap();
    }
    for (offset, (id, source, target)) in [
        ("edge:z", "node:a", "node:c"),
        ("edge:d", "node:b", "node:d"),
        ("edge:c", "node:c", "node:d"),
        ("edge:b", "node:a", "node:b"),
    ]
    .into_iter()
    .enumerate()
    {
        let mut edge = common("edge_upsert", offset as u64 + 7);
        edge["edge"] = json!({
            "id": id,
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
            "evidence": [{
                "kind": "semantic",
                "extractor": "fixture",
                "extractor_version": "1.0",
                "path": root.join(format!("private-{id}.rs")),
                "start_line": 1,
                "start_column": 1,
                "end_line": 1,
                "end_column": 2,
                "detail": "PRIVATE_DETAIL",
                "properties": {"secret": "PROCESS_GRAPH_SECRET"}
            }]
        });
        store.ingest_event(&edge).unwrap();
    }
    let mut profile_completed = common("profile_completed", 11);
    profile_completed["profile_id"] = json!("fixture:safe");
    profile_completed["coverage"] = coverage.clone();
    store.ingest_event(&profile_completed).unwrap();
    let mut completed = common("scan_completed", 12);
    completed["coverage"] = coverage;
    store.ingest_event(&completed).unwrap();
    store
        .finish_scan("issue-302", "completed", None, true)
        .unwrap();
    let snapshot_id = store.current_snapshot_id().unwrap().unwrap();
    store
        .create_snapshot_name("baseline", &snapshot_id)
        .unwrap();
    snapshot_id
}

struct RequirementFixture {
    _temp: tempfile::TempDir,
    path: PathBuf,
}

impl RequirementFixture {
    fn path(&self) -> &Path {
        &self.path
    }
}

fn requirement() -> &'static RequirementFixture {
    static FIXTURE: OnceLock<RequirementFixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let pack = temp.path().join("pack");
        fs::create_dir(&source).unwrap();
        let component = |name: &str, files: Vec<String>| CompilerPackBuildComponent {
            name: name.to_owned(),
            archive_sha256: "0".repeat(64),
            source: format!(
                "https://static.rust-lang.org/dist/2026-07-17/{name}-nightly-fixture.tar.xz"
            ),
            files,
        };
        let host = compiler_pack_host_target()
            .expect("process tests run on a supported compiler-pack host")
            .to_owned();
        let spec = CompilerPackBuildSpec {
            host: host.clone(),
            target: host.clone(),
            release_checksum_reference: format!("release-checksums:v0.4.0/compiler-pack-{host}"),
            cargo_path: "toolchain/cargo/bin/cargo".to_owned(),
            rustc_path: "toolchain/rustc/bin/rustc".to_owned(),
            wrapper_path: "bin/depgraph-rustc-wrapper".to_owned(),
            query_path: "bin/depgraph-rustc-query".to_owned(),
            wrapper_protocol_schema_path: "schemas/depgraph-rust-compiler-precise-v1.schema.json"
                .to_owned(),
            components: vec![
                component("cargo", vec!["toolchain/cargo/bin/cargo".to_owned()]),
                component(
                    "llvm-tools",
                    vec!["toolchain/llvm-tools/bin/llvm-config".to_owned()],
                ),
                component(
                    "rust-src",
                    vec!["toolchain/rust-src/library/core/src/lib.rs".to_owned()],
                ),
                component(
                    "rust-std",
                    vec!["toolchain/rust-std/lib/libstd.rlib".to_owned()],
                ),
                component("rustc", vec!["toolchain/rustc/bin/rustc".to_owned()]),
                component(
                    "rustc-dev",
                    vec!["toolchain/rustc-dev/lib/librustc_driver.rlib".to_owned()],
                ),
            ],
        };
        for component in &spec.components {
            for relative in &component.files {
                let path = source.join(relative);
                fs::create_dir_all(path.parent().unwrap()).unwrap();
                fs::write(path, format!("fixture:{}", component.name)).unwrap();
            }
        }
        for relative in [
            spec.wrapper_path.as_str(),
            spec.query_path.as_str(),
            spec.wrapper_protocol_schema_path.as_str(),
            "licenses/LICENSE-APACHE",
            "licenses/LICENSE-MIT",
        ] {
            let path = source.join(relative);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, b"fixture").unwrap();
        }
        for relative in [
            spec.cargo_path.as_str(),
            spec.rustc_path.as_str(),
            spec.wrapper_path.as_str(),
            spec.query_path.as_str(),
        ] {
            make_executable(&source.join(relative));
        }
        let verified = build_compiler_pack(&source, &pack, &spec).unwrap();
        let requirement = CompilerPackRequirement {
            root: pack,
            expected_manifest_sha256: verified.attestation.manifest_sha256,
            release_checksum_reference: spec.release_checksum_reference,
            host: spec.host,
            target: spec.target,
        };
        verify_compiler_pack(&requirement).unwrap();
        let path = temp.path().join("requirement.json");
        fs::write(&path, serde_json::to_vec(&requirement).unwrap()).unwrap();
        let parsed = read_compiler_pack_requirement(&path).unwrap();
        verify_compiler_pack(&parsed).unwrap();
        RequirementFixture { _temp: temp, path }
    })
}

#[cfg(unix)]
fn make_executable(path: &Path) {
    use std::os::unix::fs::PermissionsExt as _;
    let mut permissions = fs::metadata(path).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions).unwrap();
}

#[cfg(not(unix))]
fn make_executable(_path: &Path) {}

fn command(
    root: &std::path::Path,
    store: &std::path::Path,
    requirement: &std::path::Path,
) -> Command {
    let binary = AssertCommand::cargo_bin("depgraph-mcp").unwrap();
    let mut command = Command::new(binary.get_program());
    command
        .args(binary.get_args())
        .arg("--root")
        .arg(root)
        .arg("--store")
        .arg(store)
        .arg("--compiler-pack-requirement")
        .arg(requirement)
        .arg("--capability")
        .arg("read")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

fn run_with_stdin(mut command: Command, stdin: &[u8]) -> Output {
    let mut child = command.spawn().unwrap();
    child.stdin.as_mut().unwrap().write_all(stdin).unwrap();
    drop(child.stdin.take());
    let mut stdout = child.stdout.take().unwrap();
    let mut stderr = child.stderr.take().unwrap();
    let stdout_reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout.read_to_end(&mut bytes).unwrap();
        bytes
    });
    let stderr_reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        stderr.read_to_end(&mut bytes).unwrap();
        bytes
    });
    let started = Instant::now();
    let status = child
        .wait_timeout(EOF_DEADLINE)
        .unwrap()
        .unwrap_or_else(|| panic!("process did not exit within {EOF_DEADLINE:?}"));
    assert!(started.elapsed() <= EOF_DEADLINE, "EOF deadline exceeded");
    Output {
        status,
        stdout: stdout_reader.join().unwrap(),
        stderr: stderr_reader.join().unwrap(),
    }
}

fn assert_json_rpc_only(stdout: &[u8]) -> Vec<Value> {
    assert!(!stdout.is_empty());
    String::from_utf8(stdout.to_vec())
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).expect("stdout must only contain JSON-RPC"))
        .collect()
}

fn call_issue_300_tool(root: &Path, store: &Path, name: &str, arguments: Value) -> Value {
    let input = format!(
        "{}\n{}\n",
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2026-07-28",
                "capabilities": {},
                "clientInfo": {"name": "issue-300-test", "version": "1"}
            }
        }),
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments}
        })
    );
    let output = run_with_stdin(command(root, store, requirement().path()), input.as_bytes());
    assert!(
        output.status.success(),
        "{name} stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty(), "{name} wrote stderr");
    let messages = assert_json_rpc_only(&output.stdout);
    assert_eq!(messages.len(), 2, "{name} response count");
    assert_eq!(messages[1]["id"], 2);
    messages[1]["result"].clone()
}

fn issue_300_catalog_and_results(
    root: &Path,
    store: &Path,
    calls: &[(&str, Value)],
) -> (Vec<Value>, Vec<Value>) {
    let mut messages = vec![
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2026-07-28",
                "capabilities": {},
                "clientInfo": {"name": "issue-300-schema-test", "version": "1"}
            }
        }),
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {}
        }),
    ];
    messages.extend(calls.iter().enumerate().map(|(index, (name, arguments))| {
        json!({
            "jsonrpc": "2.0",
            "id": index + 3,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments}
        })
    }));
    let mut input = messages
        .iter()
        .map(Value::to_string)
        .collect::<Vec<_>>()
        .join("\n");
    input.push('\n');
    let output = run_with_stdin(command(root, store, requirement().path()), input.as_bytes());
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    let responses = assert_json_rpc_only(&output.stdout);
    let tools = responses
        .iter()
        .find(|response| response["id"] == 2)
        .unwrap()["result"]["tools"]
        .as_array()
        .unwrap()
        .clone();
    let results = (0..calls.len())
        .map(|index| {
            responses
                .iter()
                .find(|response| response["id"] == index + 3)
                .unwrap()["result"]
                .clone()
        })
        .collect();
    (tools, results)
}

struct InteractiveMcp {
    child: std::process::Child,
    stdin: std::process::ChildStdin,
    stdout: BufReader<std::process::ChildStdout>,
}

impl InteractiveMcp {
    fn start(root: &Path, store: &Path) -> Self {
        let mut child = command(root, store, requirement().path()).spawn().unwrap();
        let stdin = child.stdin.take().unwrap();
        let stdout = BufReader::new(child.stdout.take().unwrap());
        Self {
            child,
            stdin,
            stdout,
        }
    }

    fn request(&mut self, request: Value) -> Value {
        writeln!(self.stdin, "{request}").unwrap();
        self.stdin.flush().unwrap();
        let mut line = String::new();
        self.stdout.read_line(&mut line).unwrap();
        assert!(!line.is_empty(), "MCP server closed before responding");
        serde_json::from_str(&line).expect("MCP stdout response is JSON")
    }

    fn finish(mut self) {
        drop(self.stdin);
        let status = self
            .child
            .wait_timeout(EOF_DEADLINE)
            .unwrap()
            .expect("interactive MCP server exits after EOF");
        assert!(status.success());
        let mut stderr = Vec::new();
        self.child
            .stderr
            .take()
            .unwrap()
            .read_to_end(&mut stderr)
            .unwrap();
        assert!(
            stderr.is_empty(),
            "stderr: {}",
            String::from_utf8_lossy(&stderr)
        );
    }
}

fn seed_issue_300_bulk_rows(store_path: &Path, root: &Path) -> String {
    let mut store = Store::open(store_path).unwrap();
    store
        .start_scan_with_revision("issue-300-bulk", root, false, Some("revision-300-bulk"))
        .unwrap();
    store
        .ingest_event(&json!({
            "event": "scan_started",
            "protocol_version": "1.0",
            "scan_id": "issue-300-bulk",
            "adapter": "fixture",
            "adapter_version": "0.1.0",
            "seq": 1,
            "root": root,
            "project_code_executed": false,
            "safe_mode": true
        }))
        .unwrap();
    for index in 0..1_105 {
        let id = format!("node:bulk:{index:04}");
        let kind = if index < 100 { "function" } else { "module" };
        let locator = format!("repo://bulk/{index:04}.rs");
        let display_name = format!("bulk::{index:04}");
        store
            .ingest_event(&json!({
                "event": "node_upsert",
                "protocol_version": "1.0",
                "scan_id": "issue-300-bulk",
                "adapter": "fixture",
                "adapter_version": "0.1.0",
                "seq": index + 2,
                "node": {
                    "id": id,
                    "kind": kind,
                    "locator": locator,
                    "display_name": display_name,
                    "properties": {}
                }
            }))
            .unwrap();
    }
    store
        .ingest_event(&json!({
            "event": "scan_completed",
            "protocol_version": "1.0",
            "scan_id": "issue-300-bulk",
            "adapter": "fixture",
            "adapter_version": "0.1.0",
            "seq": 1_107,
            "coverage": {
                "profiles": 0,
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
            }
        }))
        .unwrap();
    store
        .finish_scan("issue-300-bulk", "completed", None, true)
        .unwrap();
    let snapshot_id = store.current_snapshot_id().unwrap().unwrap();
    drop(store);

    let mut connection = Connection::open(store_path).unwrap();
    let transaction = connection.transaction().unwrap();
    for index in 0..999 {
        transaction
            .execute(
                "INSERT INTO snapshot_names(name, snapshot_id, named_at)
                 VALUES (?1, ?2, '2026-08-06T00:00:00.000Z')",
                rusqlite::params![format!("bulk-{index:04}"), snapshot_id],
            )
            .unwrap();
    }
    transaction.commit().unwrap();
    snapshot_id
}

fn issue_300_arguments(repository_id: &str) -> Value {
    json!({
        "contract_version": "depgraph-mcp-tools-v1",
        "repository_id": repository_id
    })
}

fn assert_tool_text_matches_structured(result: &Value) {
    let text: Value = serde_json::from_str(result["content"][0]["text"].as_str().unwrap())
        .expect("tool text content is canonical JSON");
    assert_eq!(text, result["structuredContent"]);
}

fn run_depgraph_cli_json(arguments: &[&std::ffi::OsStr]) -> Value {
    let binary = AssertCommand::cargo_bin("depgraph").unwrap();
    let output = Command::new(binary.get_program())
        .args(binary.get_args())
        .args(arguments)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "CLI failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

fn daemon_status_path(store: &Path) -> PathBuf {
    let mut path = store.as_os_str().to_os_string();
    path.push(".daemon-status.json");
    PathBuf::from(path)
}

#[test]
fn get_context_succeeds_when_the_store_has_no_completed_snapshot() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("repository");
    let store_path = temporary.path().join("store.sqlite");
    fs::create_dir(&root).unwrap();
    Store::open(&store_path).unwrap();
    let before = store_invariant(&store_path);

    let result = call_issue_300_tool(
        &root,
        &store_path,
        "get_context",
        issue_300_arguments("repository"),
    );
    assert_eq!(result["isError"], false);
    let structured = &result["structuredContent"];
    assert_eq!(structured["repository_id"], "repository");
    assert_eq!(structured["result"]["repository_id"], "repository");
    assert_eq!(
        structured["result"]["enabled_capabilities"],
        json!(["read"])
    );
    assert_eq!(
        structured["result"]["snapshot"],
        json!({"available": false})
    );
    assert_eq!(before, store_invariant(&store_path));
}

#[test]
fn issue_300_catalog_tools_call_real_handlers_and_leave_the_store_unchanged() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("repository");
    let store_path = temporary.path().join("store.sqlite");
    fs::create_dir(&root).unwrap();
    let snapshot_id = seed_issue_300_store(&store_path, &root);
    let calls = [
        ("get_context", issue_300_arguments("repository")),
        (
            "agent_nodes_list",
            json!({
                "contract_version": "depgraph-mcp-tools-v1",
                "repository_id": "repository",
                "snapshot": "current",
                "query": "fixture",
                "match_mode": "contains",
                "limit": 10
            }),
        ),
        (
            "snapshot_list",
            json!({
                "contract_version": "depgraph-mcp-tools-v1",
                "repository_id": "repository",
                "limit": 10
            }),
        ),
        (
            "snapshot_get",
            json!({
                "contract_version": "depgraph-mcp-tools-v1",
                "repository_id": "repository",
                "snapshot": "current"
            }),
        ),
    ];

    let mut results = Vec::new();
    for (name, arguments) in calls {
        let before = store_invariant(&store_path);
        let result = call_issue_300_tool(&root, &store_path, name, arguments);
        assert_eq!(result["isError"], false, "{name}: {result}");
        let structured = &result["structuredContent"];
        assert_eq!(structured["repository_id"], "repository");
        let encoded = structured.to_string();
        assert!(!encoded.contains(root.to_string_lossy().as_ref()));
        assert!(!encoded.contains(store_path.to_string_lossy().as_ref()));
        assert!(!encoded.contains("PROCESS_SECRET"));
        assert!(!encoded.contains("properties"));
        assert_eq!(before, store_invariant(&store_path), "{name} mutated store");
        results.push((name, result));
    }

    let nodes = &results[1].1["structuredContent"]["result"];
    assert_eq!(nodes["items"].as_array().unwrap().len(), 1);
    let mut node_fields = nodes["items"][0]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect::<Vec<_>>();
    node_fields.sort_unstable();
    assert_eq!(node_fields, ["display_name", "id", "kind", "locator"]);
    let snapshots = &results[2].1["structuredContent"]["result"]["items"];
    assert_eq!(snapshots[0]["name"], "alpha");
    assert_eq!(snapshots[1]["name"], "zeta");
    assert_eq!(
        results[3].1["structuredContent"]["result"]["snapshot_id"],
        snapshot_id
    );
}

#[test]
fn issue_302_graph_handlers_page_canonically_explain_paths_and_fail_closed_on_exhaustion() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("repository");
    let store_path = temporary.path().join("store.sqlite");
    fs::create_dir(&root).unwrap();
    let snapshot_id = seed_issue_302_store(&store_path, &root);
    let before = store_invariant(&store_path);
    let mut mcp = InteractiveMcp::start(&root, &store_path);
    let initialized = mcp.request(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2026-07-28",
            "capabilities": {},
            "clientInfo": {"name": "issue-302-test", "version": "1"}
        }
    }));
    assert_eq!(initialized["id"], 1);

    let first = mcp.request(json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "graph_dependencies_list",
            "arguments": {
                "contract_version": "depgraph-mcp-tools-v1",
                "repository_id": "repository",
                "snapshot": "baseline",
                "selector": "id:node:a",
                "transitive": true,
                "phases": ["semantic"],
                "max_traversal": 100,
                "limit": 1
            }
        }
    }));
    let first = &first["result"];
    assert_eq!(first["isError"], false, "{first}");
    assert_tool_text_matches_structured(first);
    let structured = &first["structuredContent"];
    assert_eq!(structured["snapshot_id"], snapshot_id);
    assert_eq!(structured["result"]["direction"], "outgoing");
    assert_eq!(structured["result"]["traversal_complete"], true);
    assert_eq!(structured["result"]["edges"]["items"][0]["id"], "edge:b");
    assert_eq!(structured["result"]["edges"]["complete"], false);
    let repeated = mcp.request(json!({
        "jsonrpc": "2.0",
        "id": 21,
        "method": "tools/call",
        "params": {
            "name": "graph_dependencies_list",
            "arguments": {
                "contract_version": "depgraph-mcp-tools-v1",
                "repository_id": "repository",
                "snapshot": "baseline",
                "selector": "id:node:a",
                "transitive": true,
                "phases": ["semantic"],
                "max_traversal": 100,
                "limit": 1
            }
        }
    }));
    let repeated = &repeated["result"];
    assert_eq!(repeated["isError"], false, "{repeated}");
    assert_eq!(
        repeated["structuredContent"].to_string(),
        structured.to_string(),
        "same snapshot and filter must reproduce the first structured page byte-for-byte"
    );
    assert_eq!(
        repeated["structuredContent"]["result"]["edges"]["next_cursor"],
        structured["result"]["edges"]["next_cursor"],
        "same snapshot and filter must reproduce the next cursor byte-for-byte"
    );
    let cursor = structured["result"]["edges"]["next_cursor"].clone();
    let encoded = structured.to_string();
    assert!(!encoded.contains(root.to_string_lossy().as_ref()));
    assert!(!encoded.contains("PROCESS_GRAPH_SECRET"));
    assert!(!encoded.contains("PRIVATE_DETAIL"));
    assert!(!encoded.contains("properties"));

    let second = mcp.request(json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "graph_dependencies_list",
            "arguments": {
                "contract_version": "depgraph-mcp-tools-v1",
                "repository_id": "repository",
                "snapshot": "baseline",
                "selector": "id:node:a",
                "transitive": true,
                "phases": ["semantic"],
                "max_traversal": 100,
                "limit": 3,
                "cursor": cursor.clone()
            }
        }
    }));
    let second = &second["result"];
    assert_eq!(second["isError"], false, "{second}");
    assert_eq!(
        second["structuredContent"]["result"]["edges"]["items"][0]["id"],
        "edge:c"
    );

    let mismatched = mcp.request(json!({
        "jsonrpc": "2.0",
        "id": 31,
        "method": "tools/call",
        "params": {
            "name": "graph_dependencies_list",
            "arguments": {
                "contract_version": "depgraph-mcp-tools-v1",
                "repository_id": "repository",
                "snapshot": "baseline",
                "selector": "id:node:a",
                "transitive": false,
                "phases": ["semantic"],
                "max_traversal": 100,
                "limit": 1,
                "cursor": cursor
            }
        }
    }));
    assert_eq!(mismatched["result"]["isError"], true);
    assert_eq!(
        mismatched["result"]["structuredContent"]["error"]["code"],
        "CURSOR_MISMATCH"
    );

    let path = mcp.request(json!({
        "jsonrpc": "2.0",
        "id": 4,
        "method": "tools/call",
        "params": {
            "name": "graph_path_get",
            "arguments": {
                "contract_version": "depgraph-mcp-tools-v1",
                "repository_id": "repository",
                "snapshot": "current",
                "from": "id:node:a",
                "to": "id:node:d",
                "max_traversal": 100
            }
        }
    }));
    let path = &path["result"];
    assert_eq!(path["isError"], false, "{path}");
    assert_eq!(path["structuredContent"]["result"]["path_found"], true);
    assert_eq!(
        path["structuredContent"]["result"]["steps"][0]["edge"]["id"],
        "edge:b"
    );
    assert_eq!(
        path["structuredContent"]["result"]["steps"][1]["edge"]["id"],
        "edge:d"
    );

    let exhausted = mcp.request(json!({
        "jsonrpc": "2.0",
        "id": 5,
        "method": "tools/call",
        "params": {
            "name": "graph_path_get",
            "arguments": {
                "contract_version": "depgraph-mcp-tools-v1",
                "repository_id": "repository",
                "from": "id:node:a",
                "to": "id:node:d",
                "max_traversal": 1
            }
        }
    }));
    let exhausted = &exhausted["result"];
    assert_eq!(exhausted["isError"], true, "{exhausted}");
    assert_eq!(
        exhausted["structuredContent"]["error"]["code"],
        "RESOURCE_EXHAUSTED"
    );
    assert!(exhausted["structuredContent"].get("result").is_none());

    mcp.finish();
    assert_eq!(before, store_invariant(&store_path));
}

#[test]
fn issue_302_real_results_validate_against_advertised_and_shared_schemas() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("repository");
    let store_path = temporary.path().join("store.sqlite");
    fs::create_dir(&root).unwrap();
    seed_issue_302_store(&store_path, &root);
    let calls = [
        (
            "graph_dependencies_list",
            json!({
                "contract_version": "depgraph-mcp-tools-v1",
                "repository_id": "repository",
                "snapshot": "current",
                "selector": "id:node:a",
                "transitive": true,
                "max_traversal": 100,
                "limit": 100
            }),
        ),
        (
            "graph_dependents_list",
            json!({
                "contract_version": "depgraph-mcp-tools-v1",
                "repository_id": "repository",
                "snapshot": "current",
                "selector": "id:node:d",
                "max_traversal": 100,
                "limit": 100
            }),
        ),
        (
            "graph_path_get",
            json!({
                "contract_version": "depgraph-mcp-tools-v1",
                "repository_id": "repository",
                "snapshot": "current",
                "from": "id:node:a",
                "to": "id:node:d",
                "max_traversal": 100
            }),
        ),
    ];
    let (tools, results) = issue_300_catalog_and_results(&root, &store_path, &calls);
    let shared_schema: Value = serde_json::from_slice(include_bytes!(
        "../../../schemas/depgraph-mcp-tools-v1.schema.json"
    ))
    .unwrap();
    let shared = jsonschema::draft202012::new(&shared_schema).unwrap();
    for ((name, _), result) in calls.iter().zip(results) {
        assert_eq!(result["isError"], false, "{name}: {result}");
        let structured = &result["structuredContent"];
        let advertised_schema =
            tools.iter().find(|tool| tool["name"] == *name).unwrap()["outputSchema"].clone();
        jsonschema::draft202012::new(&advertised_schema)
            .unwrap()
            .validate(structured)
            .unwrap_or_else(|error| panic!("{name} advertised schema: {error}"));
        shared
            .validate(structured)
            .unwrap_or_else(|error| panic!("{name} shared schema: {error}"));
    }
}

#[test]
fn issue_302_cli_and_mcp_share_dependency_and_path_semantics() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("repository");
    let store_path = temporary.path().join("store.sqlite");
    fs::create_dir(&root).unwrap();
    seed_issue_302_store(&store_path, &root);

    let cli = |arguments: &[&str]| {
        let binary = AssertCommand::cargo_bin("depgraph").unwrap();
        let output = Command::new(binary.get_program())
            .args(binary.get_args())
            .current_dir(&root)
            .arg("--store")
            .arg(&store_path)
            .args(arguments)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "CLI stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice::<Value>(&output.stdout).unwrap()
    };
    let mcp = |name: &str, arguments| {
        let result = call_issue_300_tool(&root, &store_path, name, arguments);
        assert_eq!(result["isError"], false, "{name}: {result}");
        result
    };
    let cli_edge_ids = |document: &Value| {
        document["data"]["edges"]
            .as_array()
            .unwrap()
            .iter()
            .map(|edge| edge["id"].as_str().unwrap().to_owned())
            .collect::<Vec<_>>()
    };
    let mcp_edge_ids = |document: &Value| {
        document["structuredContent"]["result"]["edges"]["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|edge| edge["id"].as_str().unwrap().to_owned())
            .collect::<Vec<_>>()
    };
    let comparable_node = |node: &Value| {
        json!({
            "id": node["id"],
            "kind": node["kind"],
            "locator": node["locator"],
            "display_name": node["display_name"],
        })
    };
    let cli_path_edge_ids = |document: &Value| {
        document["data"]["steps"]
            .as_array()
            .unwrap()
            .iter()
            .map(|step| step["edge"]["id"].as_str().unwrap().to_owned())
            .collect::<Vec<_>>()
    };
    let mcp_path_edge_ids = |document: &Value| {
        document["structuredContent"]["result"]["steps"]
            .as_array()
            .unwrap()
            .iter()
            .map(|step| step["edge"]["id"].as_str().unwrap().to_owned())
            .collect::<Vec<_>>()
    };

    let cli_dependencies = cli(&[
        "deps",
        "id:node:a",
        "--transitive",
        "--phase",
        "semantic",
        "--all",
        "--json",
    ]);
    let mcp_dependencies = mcp(
        "graph_dependencies_list",
        json!({
            "contract_version":"depgraph-mcp-tools-v1",
            "repository_id":"repository",
            "selector":"id:node:a",
            "transitive":true,
            "phases":["semantic"],
            "max_traversal":100,
            "limit":100
        }),
    );
    assert_eq!(
        mcp_dependencies["structuredContent"]["result"]["direction"],
        "outgoing"
    );
    assert_eq!(
        comparable_node(&mcp_dependencies["structuredContent"]["result"]["root"]),
        comparable_node(&cli_dependencies["data"]["root"])
    );
    assert_eq!(cli_dependencies["data"]["root"]["id"], "node:a");
    assert_eq!(
        mcp_edge_ids(&mcp_dependencies),
        cli_edge_ids(&cli_dependencies)
    );
    assert_eq!(
        cli_edge_ids(&cli_dependencies),
        ["edge:b", "edge:c", "edge:d", "edge:z"]
    );

    let cli_dependents = cli(&[
        "dependents",
        "id:node:d",
        "--transitive",
        "--phase",
        "semantic",
        "--all",
        "--json",
    ]);
    let mcp_dependents = mcp(
        "graph_dependents_list",
        json!({
            "contract_version":"depgraph-mcp-tools-v1",
            "repository_id":"repository",
            "selector":"id:node:d",
            "transitive":true,
            "phases":["semantic"],
            "max_traversal":100,
            "limit":100
        }),
    );
    assert_eq!(
        mcp_dependents["structuredContent"]["result"]["direction"],
        "incoming"
    );
    assert_eq!(
        comparable_node(&mcp_dependents["structuredContent"]["result"]["root"]),
        comparable_node(&cli_dependents["data"]["root"])
    );
    assert_eq!(cli_dependents["data"]["root"]["id"], "node:d");
    assert_eq!(mcp_edge_ids(&mcp_dependents), cli_edge_ids(&cli_dependents));
    assert_eq!(
        cli_edge_ids(&cli_dependents),
        ["edge:b", "edge:c", "edge:d", "edge:z"]
    );

    let cli_path = cli(&["why", "id:node:a", "id:node:d", "--json"]);
    let mcp_path = mcp(
        "graph_path_get",
        json!({
            "contract_version":"depgraph-mcp-tools-v1",
            "repository_id":"repository",
            "from":"id:node:a",
            "to":"id:node:d",
            "max_traversal":100
        }),
    );
    assert_eq!(
        comparable_node(&mcp_path["structuredContent"]["result"]["from"]),
        comparable_node(&cli_path["data"]["from"])
    );
    assert_eq!(
        comparable_node(&mcp_path["structuredContent"]["result"]["to"]),
        comparable_node(&cli_path["data"]["to"])
    );
    assert_eq!(cli_path["data"]["from"]["id"], "node:a");
    assert_eq!(cli_path["data"]["to"]["id"], "node:d");
    assert_eq!(mcp_path["structuredContent"]["result"]["path_found"], true);
    assert_eq!(
        mcp_path["structuredContent"]["result"]["path_found"],
        cli_path["data"]["path_found"]
    );
    assert_eq!(mcp_path_edge_ids(&mcp_path), cli_path_edge_ids(&cli_path));
    assert_eq!(cli_path_edge_ids(&cli_path), ["edge:b", "edge:d"]);
}

#[test]
fn real_issue_300_successes_validate_against_advertised_and_checked_in_schemas() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("repository");
    let store_path = temporary.path().join("store.sqlite");
    fs::create_dir(&root).unwrap();
    seed_issue_300_store(&store_path, &root);
    let calls = [
        ("get_context", issue_300_arguments("repository")),
        (
            "agent_nodes_list",
            json!({
                "contract_version": "depgraph-mcp-tools-v1",
                "repository_id": "repository",
                "query": "fixture",
                "match_mode": "contains",
                "limit": 10
            }),
        ),
        (
            "snapshot_list",
            json!({
                "contract_version": "depgraph-mcp-tools-v1",
                "repository_id": "repository",
                "limit": 10
            }),
        ),
        (
            "snapshot_get",
            json!({
                "contract_version": "depgraph-mcp-tools-v1",
                "repository_id": "repository",
                "snapshot": "current"
            }),
        ),
    ];
    let (tools, results) = issue_300_catalog_and_results(&root, &store_path, &calls);
    let shared_schema: Value = serde_json::from_slice(include_bytes!(
        "../../../schemas/depgraph-mcp-tools-v1.schema.json"
    ))
    .unwrap();
    let shared = jsonschema::draft202012::new(&shared_schema).unwrap();
    let mut failures = Vec::new();

    for ((name, _), result) in calls.iter().zip(results) {
        assert_eq!(result["isError"], false, "{name}: {result}");
        let structured = &result["structuredContent"];
        let advertised_schema =
            tools.iter().find(|tool| tool["name"] == *name).unwrap()["outputSchema"].clone();
        let advertised = jsonschema::draft202012::new(&advertised_schema).unwrap();
        if let Err(error) = advertised.validate(structured) {
            failures.push(format!("{name}: advertised output schema: {error}"));
        }
        if let Err(error) = shared.validate(structured) {
            failures.push(format!("{name}: checked-in shared schema: {error}"));
        }
    }
    assert!(failures.is_empty(), "schema mismatches: {failures:?}");
}

fn prepare_issue_301_repository(root: &Path, store_path: &Path) {
    fs::create_dir_all(root.join("src")).unwrap();
    fs::write(
        root.join("Cargo.toml"),
        "[package]\nname='issue-301-fixture'\nversion='0.1.0'\n",
    )
    .unwrap();
    fs::write(root.join("src/lib.rs"), "pub fn fixture() {}\n").unwrap();
    fs::write(
        root.join("build.rs"),
        "fn main() { std::fs::write(\"project-code-ran\", \"bad\").unwrap(); }\n",
    )
    .unwrap();
    fs::write(
        daemon_status_path(store_path),
        serde_json::to_vec(&json!({
            "schema_version": "daemon-status-v1",
            "root": root,
            "phase": "idle",
            "started_at": "2026-08-06T00:00:00Z",
            "stopped_at": null,
            "debounce_milliseconds": 100,
            "pending_change_count": 0,
            "active_attempt_id": null,
            "last_completed_attempt": null,
            "last_failed_attempt": null,
            "last_cancelled_attempt": null,
            "last_watcher_error": "PROCESS_WATCHER_SECRET /private/watcher",
            "recovered_attempts": {"scan_attempt_ids": [], "build_attempt_ids": []}
        }))
        .unwrap(),
    )
    .unwrap();
}

#[test]
fn issue_301_cli_and_mcp_lifecycle_results_are_equivalent_and_immutable() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("repository");
    let store_path = temporary.path().join("store.sqlite");
    fs::create_dir(&root).unwrap();
    seed_issue_300_store(&store_path, &root);
    prepare_issue_301_repository(&root, &store_path);
    let before = store_invariant(&store_path);

    let cli_automatic = run_depgraph_cli_json(&[
        "--store".as_ref(),
        store_path.as_os_str(),
        "profiles".as_ref(),
        "plan".as_ref(),
        root.as_os_str(),
        "--json".as_ref(),
    ]);
    let profiles_document = serde_json::to_string(&json!({
        "contract_version": "default-profile-selection-v1",
        "profiles": [cli_automatic["plan"]["profiles"][0]["axes"]]
    }))
    .unwrap();
    let profiles_path = root.join("profiles.json");
    fs::write(&profiles_path, &profiles_document).unwrap();
    let cli_profile = run_depgraph_cli_json(&[
        "--store".as_ref(),
        store_path.as_os_str(),
        "profiles".as_ref(),
        "plan".as_ref(),
        root.as_os_str(),
        "--profiles-file".as_ref(),
        profiles_path.as_os_str(),
        "--json".as_ref(),
    ]);
    let mcp_profile = call_issue_300_tool(
        &root,
        &store_path,
        "profile_plan_get",
        json!({
            "contract_version": "depgraph-mcp-tools-v1",
            "repository_id": "repository",
            "profiles_document": profiles_document
        }),
    );
    assert_eq!(mcp_profile["isError"], false, "{mcp_profile}");
    assert_tool_text_matches_structured(&mcp_profile);
    assert_eq!(mcp_profile["structuredContent"]["result"], cli_profile);

    let cli_daemon = run_depgraph_cli_json(&[
        "--store".as_ref(),
        store_path.as_os_str(),
        "daemon".as_ref(),
        "status".as_ref(),
        root.as_os_str(),
        "--json".as_ref(),
    ]);
    let mcp_daemon = call_issue_300_tool(
        &root,
        &store_path,
        "daemon_get",
        issue_300_arguments("repository"),
    );
    assert_eq!(mcp_daemon["isError"], false, "{mcp_daemon}");
    assert_tool_text_matches_structured(&mcp_daemon);
    assert_eq!(mcp_daemon["structuredContent"]["result"], cli_daemon);
    assert!(!cli_daemon.to_string().contains("PROCESS_WATCHER_SECRET"));
    assert!(cli_daemon.get("root").is_none());

    let cli_doctor = run_depgraph_cli_json(&[
        "--store".as_ref(),
        store_path.as_os_str(),
        "doctor".as_ref(),
        "--root".as_ref(),
        root.as_os_str(),
        "--compiler-pack-requirement".as_ref(),
        requirement().path().as_os_str(),
        "--details".as_ref(),
        "--json".as_ref(),
    ]);
    let mcp_doctor = call_issue_300_tool(
        &root,
        &store_path,
        "doctor_get",
        json!({
            "contract_version": "depgraph-mcp-tools-v1",
            "repository_id": "repository",
            "details": true
        }),
    );
    assert_eq!(mcp_doctor["isError"], false, "{mcp_doctor}");
    assert_tool_text_matches_structured(&mcp_doctor);
    assert_eq!(mcp_doctor["structuredContent"]["result"], cli_doctor);
    let doctor = cli_doctor.to_string();
    for forbidden in [
        "PROCESS_PROFILE_SECRET",
        "PROCESS_WORKER_LOG_SECRET",
        "/usr/bin/rustc",
        root.to_string_lossy().as_ref(),
    ] {
        assert!(!doctor.contains(forbidden), "doctor leaked {forbidden:?}");
    }
    assert!(!root.join("project-code-ran").exists());
    assert_eq!(before, store_invariant(&store_path));
}

#[test]
fn issue_301_lifecycle_successes_validate_against_exact_advertised_and_shared_schemas() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("repository");
    let store_path = temporary.path().join("store.sqlite");
    fs::create_dir(&root).unwrap();
    seed_issue_300_store(&store_path, &root);
    prepare_issue_301_repository(&root, &store_path);
    let calls = [
        (
            "profile_plan_get",
            json!({
                "contract_version": "depgraph-mcp-tools-v1",
                "repository_id": "repository"
            }),
        ),
        ("daemon_get", issue_300_arguments("repository")),
        (
            "doctor_get",
            json!({
                "contract_version": "depgraph-mcp-tools-v1",
                "repository_id": "repository",
                "details": true
            }),
        ),
    ];
    let before = store_invariant(&store_path);
    let (tools, results) = issue_300_catalog_and_results(&root, &store_path, &calls);
    let shared_schema: Value = serde_json::from_slice(include_bytes!(
        "../../../schemas/depgraph-mcp-tools-v1.schema.json"
    ))
    .unwrap();
    let shared = jsonschema::draft202012::new(&shared_schema).unwrap();
    for ((name, arguments), result) in calls.iter().zip(results) {
        assert_eq!(result["isError"], false, "{name}: {result}");
        assert_tool_text_matches_structured(&result);
        let tool = tools.iter().find(|tool| tool["name"] == *name).unwrap();
        let output = jsonschema::draft202012::new(&tool["outputSchema"]).unwrap();
        output
            .validate(&result["structuredContent"])
            .unwrap_or_else(|error| panic!("{name} advertised output: {error}"));
        shared
            .validate(&result["structuredContent"])
            .unwrap_or_else(|error| panic!("{name} shared output: {error}"));

        let mut unknown = arguments.clone();
        unknown["unknown"] = json!(true);
        let input = jsonschema::draft202012::new(&tool["inputSchema"]).unwrap();
        assert!(
            !input.is_valid(&unknown),
            "{name} input accepted unknown key"
        );
    }
    assert_eq!(before, store_invariant(&store_path));
}

#[test]
fn issue_301_profile_file_security_failures_are_typed_and_redacted() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("repository");
    let store_path = temporary.path().join("store.sqlite");
    fs::create_dir(&root).unwrap();
    seed_issue_300_store(&store_path, &root);
    prepare_issue_301_repository(&root, &store_path);
    let before = store_invariant(&store_path);

    let traversal = call_issue_300_tool(
        &root,
        &store_path,
        "profile_plan_get",
        json!({
            "contract_version": "depgraph-mcp-tools-v1",
            "repository_id": "repository",
            "profiles_file": "../PROCESS_TRAVERSAL_SECRET.json"
        }),
    );
    assert_eq!(traversal["isError"], true);
    assert_eq!(
        traversal["structuredContent"]["error"]["code"],
        "INVALID_ARGUMENT"
    );
    assert!(!traversal.to_string().contains("PROCESS_TRAVERSAL_SECRET"));

    let conflicting = call_issue_300_tool(
        &root,
        &store_path,
        "profile_plan_get",
        json!({
            "contract_version": "depgraph-mcp-tools-v1",
            "repository_id": "repository",
            "profile_budget": 1,
            "profiles_document": "{}"
        }),
    );
    assert_eq!(conflicting["isError"], true);
    assert_eq!(
        conflicting["structuredContent"]["error"]["code"],
        "INVALID_ARGUMENT"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        let outside = temporary.path().join("PROCESS_SYMLINK_SECRET.json");
        fs::write(&outside, b"{}").unwrap();
        symlink(&outside, root.join("profiles-link.json")).unwrap();
        let symlinked = call_issue_300_tool(
            &root,
            &store_path,
            "profile_plan_get",
            json!({
                "contract_version": "depgraph-mcp-tools-v1",
                "repository_id": "repository",
                "profiles_file": "profiles-link.json"
            }),
        );
        assert_eq!(symlinked["isError"], true);
        assert_eq!(
            symlinked["structuredContent"]["error"]["code"],
            "INTEGRITY_FAILURE"
        );
        assert!(!symlinked.to_string().contains("PROCESS_SYMLINK_SECRET"));
    }
    assert_eq!(before, store_invariant(&store_path));
}

#[test]
fn cursor_paging_traverses_more_than_one_thousand_filtered_nodes_and_snapshot_names() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("repository");
    let store_path = temporary.path().join("store.sqlite");
    fs::create_dir(&root).unwrap();
    seed_issue_300_store(&store_path, &root);
    seed_issue_300_bulk_rows(&store_path, &root);

    let mut mcp = InteractiveMcp::start(&root, &store_path);
    let initialized = mcp.request(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2026-07-28",
            "capabilities": {},
            "clientInfo": {"name": "issue-300-paging-test", "version": "1"}
        }
    }));
    assert_eq!(initialized["id"], 1);

    let mut request_id = 2_u64;
    let mut node_ids = Vec::new();
    let mut cursor = None;
    loop {
        let response = mcp.request(json!({
            "jsonrpc": "2.0",
            "id": request_id,
            "method": "tools/call",
            "params": {
                "name": "agent_nodes_list",
                "arguments": {
                    "contract_version": "depgraph-mcp-tools-v1",
                    "repository_id": "repository",
                    "query": "bulk",
                    "match_mode": "contains",
                    "kinds": ["module"],
                    "cursor": cursor,
                    "limit": 1000
                }
            }
        }));
        let result = &response["result"];
        assert_eq!(result["isError"], false, "{result}");
        let page = &result["structuredContent"]["result"];
        assert_eq!(page["total_items"], 1_005);
        node_ids.extend(
            page["items"]
                .as_array()
                .unwrap()
                .iter()
                .map(|item| item["id"].as_str().unwrap().to_owned()),
        );
        if page["complete"] == true {
            break;
        }
        cursor = Some(page["next_cursor"].clone());
        request_id += 1;
    }
    assert_eq!(node_ids.len(), 1_005);
    assert!(node_ids.windows(2).all(|pair| pair[0] < pair[1]));
    assert_eq!(node_ids.first().unwrap(), "node:bulk:0100");
    assert_eq!(node_ids.last().unwrap(), "node:bulk:1104");

    let mut names = Vec::new();
    let mut cursor = None;
    for _ in 0..64 {
        request_id += 1;
        let response = mcp.request(json!({
            "jsonrpc": "2.0",
            "id": request_id,
            "method": "tools/call",
            "params": {
                "name": "snapshot_list",
                "arguments": {
                    "contract_version": "depgraph-mcp-tools-v1",
                    "repository_id": "repository",
                    "cursor": cursor,
                    "limit": 1000
                }
            }
        }));
        let result = &response["result"];
        assert_eq!(result["isError"], false, "{result}");
        let page = &result["structuredContent"]["result"];
        assert_eq!(page["total_items"], 1_001);
        names.extend(
            page["items"]
                .as_array()
                .unwrap()
                .iter()
                .map(|item| item["name"].as_str().unwrap().to_owned()),
        );
        if page["complete"] == true {
            cursor = None;
            break;
        }
        cursor = Some(page["next_cursor"].clone());
    }
    assert!(cursor.is_none(), "snapshot cursor did not complete");
    assert_eq!(names.len(), 1_001);
    assert!(names.windows(2).all(|pair| pair[0] < pair[1]));
    mcp.finish();
}

#[test]
fn issue_300_handler_maps_oversized_utf8_query_to_a_typed_error() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("repository");
    let store_path = temporary.path().join("store.sqlite");
    fs::create_dir(&root).unwrap();
    seed_issue_300_store(&store_path, &root);

    let accepted = call_issue_300_tool(
        &root,
        &store_path,
        "agent_nodes_list",
        json!({
            "contract_version": "depgraph-mcp-tools-v1",
            "repository_id": "repository",
            "snapshot": "current",
            "query": "あ".repeat(85),
            "match_mode": "contains",
            "limit": 10
        }),
    );
    assert_eq!(accepted["isError"], false);

    let result = call_issue_300_tool(
        &root,
        &store_path,
        "agent_nodes_list",
        json!({
            "contract_version": "depgraph-mcp-tools-v1",
            "repository_id": "repository",
            "snapshot": "current",
            "query": "あ".repeat(86),
            "match_mode": "contains",
            "limit": 10
        }),
    );
    assert_eq!(result["isError"], true);
    assert_eq!(
        result["structuredContent"]["error"]["code"],
        "INVALID_ARGUMENT"
    );
}

#[test]
fn startup_parse_failure_is_redacted_and_stdout_is_empty() {
    let binary = AssertCommand::cargo_bin("depgraph-mcp").unwrap();
    let output = Command::new(binary.get_program())
        .args(binary.get_args())
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8_lossy(&output.stderr),
        "depgraph-mcp: invalid startup configuration\n"
    );
}

#[test]
fn invalid_capability_dependency_is_redacted_before_service_setup() {
    let root = tempfile::tempdir().unwrap();
    let requirement = requirement();
    let output = run_with_stdin(
        {
            let mut command = command(
                root.path(),
                &root.path().join("store.sqlite"),
                requirement.path(),
            );
            command.args(["--capability", "daemon-control"]);
            command
        },
        b"",
    );
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8_lossy(&output.stderr),
        "depgraph-mcp: invalid startup configuration\n"
    );
}

#[test]
fn invalid_compiler_requirement_does_not_echo_secret_path_or_content() {
    let root = tempfile::tempdir().unwrap();
    let secret = root.path().join("secret-filename-and-content.json");
    std::fs::write(&secret, "TOP_SECRET_COMPILER_REQUIREMENT_CONTENT").unwrap();
    let output = run_with_stdin(
        command(root.path(), &root.path().join("store.sqlite"), &secret),
        b"",
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(stderr, "depgraph-mcp: invalid startup configuration\n");
    assert!(!stderr.contains("secret-filename-and-content") && !stderr.contains("TOP_SECRET"));
}

#[test]
fn unverifiable_compiler_pack_does_not_echo_secret_root() {
    let root = tempfile::tempdir().unwrap();
    let requirement = root.path().join("requirement.json");
    fs::write(
        &requirement,
        serde_json::to_vec(&json!({
            "root": root.path().join("secret-missing-compiler-pack"),
            "expected_manifest_sha256": "0".repeat(64),
            "release_checksum_reference":
                "release-checksums:v0.4.0/compiler-pack-x86_64-unknown-linux-gnu",
            "host": "x86_64-unknown-linux-gnu",
            "target": "x86_64-unknown-linux-gnu"
        }))
        .unwrap(),
    )
    .unwrap();
    let output = run_with_stdin(
        command(root.path(), &root.path().join("store.sqlite"), &requirement),
        b"",
    );
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(stderr, "depgraph-mcp: invalid startup configuration\n");
    assert!(!stderr.contains("secret-missing-compiler-pack"));
}

#[test]
fn unsafe_root_and_store_settings_are_redacted() {
    let root = tempfile::tempdir().unwrap();
    let requirement = requirement();

    for (unsafe_root, unsafe_store, secret) in [
        (
            root.path().join("secret-missing-root"),
            root.path().join("store.sqlite"),
            "secret-missing-root",
        ),
        (
            root.path().to_path_buf(),
            Path::new("secret-relative-store.sqlite").to_path_buf(),
            "secret-relative-store",
        ),
    ] {
        let output = run_with_stdin(
            command(&unsafe_root, &unsafe_store, requirement.path()),
            b"",
        );
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert_eq!(stderr, "depgraph-mcp: invalid startup configuration\n");
        assert!(!stderr.contains(secret));
    }
}

#[test]
fn initializes_legacy_2025_11_25() {
    initializes("2025-11-25");
}

#[test]
fn initializes_modern_2026_07_28() {
    initializes("2026-07-28");
}

#[test]
fn tools_list_is_profile_filtered_static_sorted_and_repeatable() {
    let root = tempfile::tempdir().unwrap();
    let requirement = requirement();

    let read_only = tools_list(
        command(
            root.path(),
            &root.path().join("read-store.sqlite"),
            requirement.path(),
        ),
        25,
    );
    assert_eq!(
        read_only,
        EXPECTED_READ_ONLY_TOOLS
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
    );

    let mut full_command = command(
        root.path(),
        &root.path().join("full-store.sqlite"),
        requirement.path(),
    );
    full_command.args([
        "--capability",
        "store-write",
        "--capability",
        "repository-write",
        "--capability",
        "daemon-control",
        "--capability",
        "project-exec",
    ]);
    let full = tools_list(full_command, 32);
    assert!(full.contains(&"scan_submit".to_owned()));
    assert!(full.contains(&"repository_init".to_owned()));
    assert!(full.contains(&"daemon_start_submit".to_owned()));
    assert!(full.contains(&"resolve_build_submit".to_owned()));
}

const EXPECTED_READ_ONLY_TOOLS: &[&str] = &[
    "agent_edges_list",
    "agent_evidence_list",
    "agent_node_get",
    "agent_nodes_list",
    "agent_sites_list",
    "daemon_get",
    "doctor_get",
    "get_context",
    "graph_cycles_list",
    "graph_dependencies_list",
    "graph_dependents_list",
    "graph_export",
    "graph_impact_get",
    "graph_path_get",
    "graph_query",
    "graph_unresolved_list",
    "operation_cancel",
    "operation_get",
    "operation_result",
    "policy_evaluate",
    "profile_plan_get",
    "runtime_trace_validate",
    "snapshot_diff_get",
    "snapshot_get",
    "snapshot_list",
];

fn tools_list(command: Command, expected_count: usize) -> Vec<String> {
    let input = concat!(
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2026-07-28\",\"capabilities\":{},\"clientInfo\":{\"name\":\"catalog-test\",\"version\":\"1\"}}}\n",
        "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\",\"params\":{}}\n",
        "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/list\",\"params\":{}}\n"
    );
    let output = run_with_stdin(command, input.as_bytes());
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    let messages = assert_json_rpc_only(&output.stdout);
    assert_eq!(messages.len(), 3);
    assert_eq!(
        messages[0]["result"]["capabilities"]["tools"]["listChanged"],
        false
    );
    assert_eq!(messages[1]["result"], messages[2]["result"]);

    let tools = messages[1]["result"]["tools"].as_array().unwrap();
    assert_eq!(tools.len(), expected_count);
    let names = tools
        .iter()
        .map(|tool| {
            assert!(
                tool["description"]
                    .as_str()
                    .is_some_and(|value| !value.is_empty())
            );
            assert!(tool["inputSchema"].is_object());
            assert!(tool["outputSchema"].is_object());
            tool["name"].as_str().unwrap().to_owned()
        })
        .collect::<Vec<_>>();
    let mut sorted = names.clone();
    sorted.sort_unstable();
    assert_eq!(names, sorted);
    names
}

#[test]
fn trace_logging_does_not_expose_untrusted_request_content() {
    const SECRET: &str = "TOP_SECRET_MCP_REQUEST_PAYLOAD";

    let root = tempfile::tempdir().unwrap();
    let requirement = requirement();
    let mut process = command(
        root.path(),
        &root.path().join("store.sqlite"),
        requirement.path(),
    );
    process.args(["--log-level", "trace"]);
    let input = format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{{\"protocolVersion\":\"2026-07-28\",\"capabilities\":{{}},\"clientInfo\":{{\"name\":\"{SECRET}\",\"version\":\"1\"}}}}}}\n"
    );
    let output = run_with_stdin(process, input.as_bytes());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(output.status.success(), "stderr: {stderr}");
    assert!(!stderr.contains(SECRET));
    assert!(stderr.len() <= 16 * 1024);
    assert_json_rpc_only(&output.stdout);
}

#[test]
fn exact_one_mib_lf_frame_is_accepted() {
    exact_one_mib_frame_is_accepted_with_terminator(b"\n");
}

#[test]
fn exact_one_mib_crlf_frame_is_accepted() {
    exact_one_mib_frame_is_accepted_with_terminator(b"\r\n");
}

fn exact_one_mib_frame_is_accepted_with_terminator(terminator: &[u8]) {
    const MAX_FRAME_BYTES: usize = 1024 * 1024;

    let root = tempfile::tempdir().unwrap();
    let requirement = requirement();
    let mut request = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2026-07-28",
            "capabilities": {},
            "clientInfo": {"name": "test", "version": "1"},
            "_meta": {"padding": ""}
        }
    });
    let base_len = serde_json::to_vec(&request).unwrap().len();
    request["params"]["_meta"]["padding"] = json!("x".repeat(MAX_FRAME_BYTES - base_len));
    let mut input = serde_json::to_vec(&request).unwrap();
    assert_eq!(input.len(), MAX_FRAME_BYTES);
    input.extend_from_slice(terminator);

    let output = run_with_stdin(
        command(
            root.path(),
            &root.path().join("store.sqlite"),
            requirement.path(),
        ),
        &input,
    );
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    let messages = assert_json_rpc_only(&output.stdout);
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0]["result"]["protocolVersion"], "2026-07-28");
}

#[test]
fn malformed_json_is_ignored_and_the_next_valid_frame_is_processed() {
    let root = tempfile::tempdir().unwrap();
    let requirement = requirement();
    let input = b"{not-json}\n{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2026-07-28\",\"capabilities\":{},\"clientInfo\":{\"name\":\"test\",\"version\":\"1\"}}}\n";

    let output = run_with_stdin(
        command(
            root.path(),
            &root.path().join("store.sqlite"),
            requirement.path(),
        ),
        input,
    );
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    let messages = assert_json_rpc_only(&output.stdout);
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0]["id"], 1);
    assert_eq!(messages[0]["result"]["protocolVersion"], "2026-07-28");
}

fn initializes(protocol_version: &str) {
    let root = tempfile::tempdir().unwrap();
    let requirement = requirement();
    let input = if protocol_version == "2025-11-25" {
        format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{{\"protocolVersion\":\"{protocol_version}\",\"capabilities\":{{}},\"clientInfo\":{{\"name\":\"test\",\"version\":\"1\"}}}}}}\n{{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"ping\",\"params\":{{}}}}\n"
        )
    } else {
        format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{{\"protocolVersion\":\"{protocol_version}\",\"capabilities\":{{}},\"clientInfo\":{{\"name\":\"test\",\"version\":\"1\"}}}}}}\n"
        )
    };
    let output = run_with_stdin(
        command(
            root.path(),
            &root.path().join("store.sqlite"),
            requirement.path(),
        ),
        input.as_bytes(),
    );
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stderr.is_empty(),
        "unexpected stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let messages = assert_json_rpc_only(&output.stdout);
    let expected_len = if protocol_version == "2025-11-25" {
        2
    } else {
        1
    };
    assert_eq!(messages.len(), expected_len);
    assert_eq!(messages[0]["result"]["protocolVersion"], protocol_version);
    assert_eq!(messages[0]["result"]["serverInfo"]["name"], "depgraph-mcp");
    if protocol_version == "2025-11-25" {
        assert_eq!(messages[1], json!({"jsonrpc":"2.0", "id":2, "result":{}}));
    }
}

#[test]
fn oversized_newline_frame_is_rejected_before_deserialization() {
    let root = tempfile::tempdir().unwrap();
    let requirement = requirement();
    let input = format!(
        "{{\"jsonrpc\":\"2.0\",\"padding\":\"{}\"}}\n",
        "x".repeat(1024 * 1024)
    );
    let output = run_with_stdin(
        command(
            root.path(),
            &root.path().join("store.sqlite"),
            requirement.path(),
        ),
        input.as_bytes(),
    );
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8_lossy(&output.stderr),
        "depgraph-mcp: inbound message rejected\n"
    );
}

#[test]
fn oversized_partial_frame_is_rejected_before_deserialization() {
    let root = tempfile::tempdir().unwrap();
    let requirement = requirement();
    for input in [
        vec![b'x'; 1024 * 1024 + 1],
        [vec![b'x'; 1024 * 1024], vec![b'\r']].concat(),
    ] {
        let output = run_with_stdin(
            command(
                root.path(),
                &root.path().join("store.sqlite"),
                requirement.path(),
            ),
            &input,
        );
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert_eq!(
            String::from_utf8_lossy(&output.stderr),
            "depgraph-mcp: inbound message rejected\n"
        );
    }
}

#[test]
fn real_eof_exits_successfully_before_five_second_deadline() {
    let root = tempfile::tempdir().unwrap();
    let requirement = requirement();
    let output = run_with_stdin(
        command(
            root.path(),
            &root.path().join("store.sqlite"),
            requirement.path(),
        ),
        b"",
    );
    assert!(output.status.success());
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
}
