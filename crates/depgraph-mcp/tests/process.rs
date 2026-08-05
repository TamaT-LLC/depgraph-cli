use std::{
    fs,
    io::{Read as _, Write as _},
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
use serde_json::{Value, json};
use wait_timeout::ChildExt as _;

const EOF_DEADLINE: Duration = Duration::from_secs(5);

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
        24,
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
    let full = tools_list(full_command, 31);
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
