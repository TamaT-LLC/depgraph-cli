use std::{
    fs,
    io::{BufRead as _, BufReader, Read as _, Write as _},
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    sync::OnceLock,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use assert_cmd::Command as AssertCommand;
use depgraph_core::{
    CompilerPackBuildComponent, CompilerPackBuildSpec, CompilerPackRequirement, DepgraphCapability,
    DepgraphCapabilitySet, DepgraphServiceConfig, DepgraphServiceLimits, build_compiler_pack,
    compiler_pack_host_target, read_compiler_pack_requirement, verify_compiler_pack,
};
use depgraph_mcp_tools::{
    AgentDaemonStatus, AgentError, AgentErrorCode, AgentErrorDetails, AgentRemediation,
    ErrorEnvelope, LogicalRepositoryId, SuccessEnvelope,
};
use depgraph_operation::{
    CanonicalJson, LeaseOwner, OperationJournal, OperationKind, OperationManager, SubmitRequest,
    operation_journal_path,
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

fn source_tree_digest(root: &Path) -> String {
    fn collect_files(root: &Path, directory: &Path, files: &mut Vec<PathBuf>) {
        let mut entries = fs::read_dir(directory)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect::<Vec<_>>();
        entries.sort();
        for path in entries {
            if path.is_dir() {
                collect_files(root, &path, files);
            } else if path.is_file() {
                files.push(path.strip_prefix(root).unwrap().to_owned());
            }
        }
    }

    let mut files = Vec::new();
    collect_files(root, root, &mut files);
    let mut digest = Sha256::new();
    for relative in files {
        digest.update(relative.to_string_lossy().as_bytes());
        digest.update([0]);
        digest.update(fs::read(root.join(&relative)).unwrap());
        digest.update([0]);
    }
    format!("{:x}", digest.finalize())
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
    let mut workspace = common("node_upsert", 11);
    workspace["node"] = json!({
        "id": "workspace:repository",
        "kind": "workspace",
        "locator": "workspace:repository",
        "display_name": "repository",
        "properties": {"repository_identity": "workspace:repository"}
    });
    store.ingest_event(&workspace).unwrap();
    let mut profile_completed = common("profile_completed", 12);
    profile_completed["profile_id"] = json!("fixture:safe");
    profile_completed["coverage"] = coverage.clone();
    store.ingest_event(&profile_completed).unwrap();
    let mut completed = common("scan_completed", 13);
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

fn issue_306_long_condition() -> Value {
    let values = (0..40)
        .map(|index| Value::String(format!("enabled-{index:02}")))
        .collect::<Vec<_>>();
    json!({
        "op": "in",
        "key": "feature",
        "values": values
    })
}

fn issue_306_oversized_condition() -> Value {
    json!({
        "op": "eq",
        "key": "oversized",
        "value": "x".repeat(64 * 1024 + 1)
    })
}

fn seed_issue_303_store(path: &Path, root: &Path, source_revision: &str) -> String {
    let mut store = Store::open(path).unwrap();
    store
        .start_scan_with_revision("issue-303", root, false, Some(source_revision))
        .unwrap();
    let coverage = json!({
        "profiles": 1,
        "files_discovered": 0,
        "files_analyzed": 0,
        "files_skipped": 0,
        "dependency_sites": 3,
        "resolved": 0,
        "candidates": 0,
        "external": 0,
        "unresolved": 3,
        "unsupported_syntax": 0,
        "project_code_executed": false,
        "completeness": ["syntax-complete"],
        "reasons": []
    });
    let common = |event: &str, seq: u64| {
        json!({
            "event": event,
            "protocol_version": "1.0",
            "scan_id": "issue-303",
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
        "environment": {"secret": "PROCESS_303_PROFILE_SECRET"},
        "properties": {"private": root}
    });
    store.ingest_event(&profile).unwrap();
    for (offset, (id, kind, path)) in [
        ("node:root", "file", "src/root.rs"),
        ("node:dependent-a", "file", "src/dependent-a.rs"),
        ("node:dependent-b", "file", "src/dependent-b.rs"),
        ("node:cycle-a", "file", "src/cycle-a.rs"),
        ("node:cycle-b", "file", "src/cycle-b.rs"),
        ("unknown:missing", "unknown_target", "src/missing.rs"),
    ]
    .into_iter()
    .enumerate()
    {
        let mut node = common("node_upsert", offset as u64 + 3);
        node["node"] = json!({
            "id": id,
            "kind": kind,
            "locator": format!("repo://{path}"),
            "display_name": id,
            "properties": {"path": path, "secret": "PROCESS_303_NODE_SECRET", "root": root}
        });
        store.ingest_event(&node).unwrap();
    }
    for (offset, (id, source, target)) in [
        ("edge:impact-a", "node:dependent-a", "node:root"),
        ("edge:impact-b", "node:dependent-b", "node:dependent-a"),
        ("edge:cycle-a", "node:cycle-a", "node:cycle-b"),
        ("edge:cycle-b", "node:cycle-b", "node:cycle-a"),
    ]
    .into_iter()
    .enumerate()
    {
        let condition = if id == "edge:impact-a" {
            issue_306_long_condition()
        } else {
            json!({"op": "all", "conditions": []})
        };
        let mut edge = common("edge_upsert", offset as u64 + 9);
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
            "condition": condition,
            "generated": false,
            "evidence": [{
                "kind": "semantic",
                "extractor": "fixture",
                "extractor_version": "1.0",
                "path": "src/root.rs",
                "start_line": 1,
                "start_column": 1,
                "end_line": 1,
                "end_column": 2,
                "detail": "PROCESS_303_EVIDENCE_SECRET",
                "properties": {"secret": "PROCESS_303_PROPERTY_SECRET", "absolute": root}
            }]
        });
        store.ingest_event(&edge).unwrap();
    }
    let mut site = common("dependency_site", 13);
    site["site"] = json!({
    "id": "site:missing",
    "source": "node:dependent-b",
    "kind": "import",
    "specifier": "fixture:missing",
    "resolution_status": "unresolved",
    "target_ids": ["unknown:missing"],
    "profile_id": "fixture:safe",
    "condition": {"op": "all", "conditions": []},
    "precision": "exact",
    "reason": "package_not_found",
    "evidence": [
        {
            "kind": "source",
            "extractor": "fixture",
            "extractor_version": "1.0",
            "path": "src/dependent-b.rs",
            "start_line": 3,
            "start_column": 1,
            "end_line": 3,
            "end_column": 9,
            "detail": "PROCESS_303_SITE_DETAIL_SECRET",
            "properties": {"secret": "PROCESS_303_SITE_PROPERTY_SECRET", "absolute": root}
        },
        {
            "kind": "source",
            "extractor": "fixture",
            "extractor_version": "1.0",
            "path": "src/dependent-b.rs",
            "start_line": 4,
            "start_column": 1,
            "end_line": 4,
            "end_column": 9,
            "detail": "PROCESS_303_SITE_DETAIL_SECRET",
            "properties": {"secret": "PROCESS_303_SITE_PROPERTY_SECRET", "absolute": root}
        },
        {
            "kind": "source",
            "extractor": "fixture",
            "extractor_version": "1.0",
            "path": "src/dependent-b.rs",
            "start_line": 5,
            "start_column": 1,
            "end_line": 5,
            "end_column": 9,
            "detail": "PROCESS_303_SITE_DETAIL_SECRET",
            "properties": {"secret": "PROCESS_303_SITE_PROPERTY_SECRET", "absolute": root}
        }
    ]
    });
    store.ingest_event(&site).unwrap();
    for (seq, id) in [(14, "site:omega"), (15, "site:zeta")] {
        let mut extra_site = common("dependency_site", seq);
        extra_site["site"] = json!({
        "id": id,
        "source": "node:dependent-b",
        "kind": "import",
        "specifier": format!("fixture:{id}"),
        "resolution_status": "unresolved",
        "target_ids": ["unknown:missing"],
        "profile_id": "fixture:safe",
        "condition": {"op": "all", "conditions": []},
        "precision": "exact",
        "reason": "package_not_found",
        "evidence": []
        });
        store.ingest_event(&extra_site).unwrap();
    }
    for (seq, id, site_id) in [
        (16, "edge:missing", "site:missing"),
        (17, "edge:omega", "site:omega"),
        (18, "edge:zeta", "site:zeta"),
    ] {
        let mut unresolved_edge = common("edge_upsert", seq);
        unresolved_edge["edge"] = json!({
        "id": id,
        "site_id": site_id,
        "source": "node:dependent-b",
        "target": "unknown:missing",
        "kind": "imports",
        "phase": "source",
        "environment": "host",
        "profile_id": "fixture:safe",
        "resolution_status": "unresolved",
        "precision": "exact",
        "condition": {"op": "all", "conditions": []},
        "generated": false
        });
        store.ingest_event(&unresolved_edge).unwrap();
    }
    for (seq, id) in [(19, "node:oversized-source"), (20, "node:oversized-target")] {
        let mut node = common("node_upsert", seq);
        node["node"] = json!({
            "id": id,
            "kind": "file",
            "locator": format!("repo://src/{id}.rs"),
            "display_name": id,
            "properties": {"path": format!("src/{id}.rs")}
        });
        store.ingest_event(&node).unwrap();
    }
    let mut oversized_edge = common("edge_upsert", 21);
    oversized_edge["edge"] = json!({
        "id": "edge:oversized",
        "source": "node:oversized-source",
        "target": "node:oversized-target",
        "kind": "imports",
        "phase": "semantic",
        "environment": "host",
        "profile_id": "fixture:safe",
        "resolution_status": "resolved",
        "precision": "exact",
        "condition": issue_306_oversized_condition(),
        "generated": false
    });
    store.ingest_event(&oversized_edge).unwrap();
    let mut profile_completed = common("profile_completed", 22);
    profile_completed["profile_id"] = json!("fixture:safe");
    profile_completed["coverage"] = coverage.clone();
    store.ingest_event(&profile_completed).unwrap();
    let mut completed = common("scan_completed", 23);
    completed["coverage"] = coverage;
    store.ingest_event(&completed).unwrap();
    store
        .finish_scan("issue-303", "completed", None, true)
        .unwrap();
    let snapshot_id = store.current_snapshot_id().unwrap().unwrap();
    store
        .create_snapshot_name("issue-303", &snapshot_id)
        .unwrap();
    snapshot_id
}

fn issue_303_git(root: &Path, arguments: &[&str]) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(arguments)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git {arguments:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

fn prepare_issue_303_repository(root: &Path) -> String {
    fs::create_dir_all(root.join("src")).unwrap();
    for name in ["root", "dependent-a", "dependent-b", "cycle-a", "cycle-b"] {
        fs::write(root.join(format!("src/{name}.rs")), format!("// {name}\n")).unwrap();
    }
    issue_303_git(root, &["init", "--quiet"]);
    issue_303_git(root, &["config", "user.email", "test@example.invalid"]);
    issue_303_git(root, &["config", "user.name", "Issue 303 Test"]);
    issue_303_git(root, &["add", "src"]);
    issue_303_git(root, &["commit", "--quiet", "-m", "fixture"]);
    issue_303_git(root, &["rev-parse", "HEAD"])
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
        Self::start_with_capabilities(root, store, &[])
    }

    fn start_with_capabilities(root: &Path, store: &Path, capabilities: &[&str]) -> Self {
        let mut command = command(root, store, requirement().path());
        for capability in capabilities {
            command.args(["--capability", capability]);
        }
        let mut child = command.spawn().unwrap();
        let stdin = child.stdin.take().unwrap();
        let stdout = BufReader::new(child.stdout.take().unwrap());
        Self {
            child,
            stdin,
            stdout,
        }
    }

    fn send(&mut self, message: Value) {
        writeln!(self.stdin, "{message}").unwrap();
        self.stdin.flush().unwrap();
    }

    fn read_response(&mut self) -> Value {
        let mut line = String::new();
        self.stdout.read_line(&mut line).unwrap();
        if line.is_empty() {
            let status = self.child.try_wait().unwrap();
            let mut stderr = Vec::new();
            if status.is_some() {
                self.child
                    .stderr
                    .as_mut()
                    .unwrap()
                    .read_to_end(&mut stderr)
                    .unwrap();
            }
            panic!(
                "MCP server closed before responding: status={status:?}, stderr={}",
                String::from_utf8_lossy(&stderr)
            );
        }
        serde_json::from_str(&line).expect("MCP stdout response is JSON")
    }

    fn request(&mut self, request: Value) -> Value {
        self.send(request);
        self.read_response()
    }

    fn notify(&mut self, notification: Value) {
        self.send(notification);
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

fn interactive_tool_call(mcp: &mut InteractiveMcp, id: u64, name: &str, arguments: Value) -> Value {
    mcp.request(json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": {"name": name, "arguments": arguments}
    }))["result"]
        .clone()
}

fn initialize_interactive_mcp(mcp: &mut InteractiveMcp, id: u64) {
    let initialized = mcp.request(json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "initialize",
        "params": {
            "protocolVersion": "2026-07-28",
            "capabilities": {},
            "clientInfo": {"name": "operation-recovery-test", "version": "1"}
        }
    }));
    assert_eq!(initialized["result"]["protocolVersion"], "2026-07-28");
}

fn initialize_tasks_mcp(
    mcp: &mut InteractiveMcp,
    id: u64,
    protocol_version: &str,
    declares_tasks: bool,
) -> Value {
    let capabilities = if declares_tasks {
        json!({"extensions": {"io.modelcontextprotocol/tasks": {}}})
    } else {
        json!({})
    };
    mcp.request(json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "initialize",
        "params": {
            "protocolVersion": protocol_version,
            "capabilities": capabilities,
            "clientInfo": {"name": "tasks-test", "version": "1"}
        }
    }))
}

fn process_now_ms() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap()
}

fn operation_service_config(
    root: &Path,
    store: &Path,
    capabilities: impl IntoIterator<Item = DepgraphCapability>,
) -> DepgraphServiceConfig {
    DepgraphServiceConfig::new(
        root,
        store,
        DepgraphCapabilitySet::try_new(capabilities).unwrap(),
        DepgraphServiceLimits::default(),
    )
    .unwrap()
}

fn operation_journal_state_digest(config: &DepgraphServiceConfig) -> [u8; 32] {
    let connection = Connection::open(operation_journal_path(config)).unwrap();
    let mut digest = Sha256::new();
    for query in [
        "SELECT * FROM operations ORDER BY operation_id",
        "SELECT * FROM runner_handoffs ORDER BY operation_id",
        "SELECT * FROM operation_tombstones ORDER BY operation_id",
    ] {
        digest.update((query.len() as u64).to_le_bytes());
        digest.update(query.as_bytes());
        let mut statement = connection.prepare(query).unwrap();
        let column_count = statement.column_count();
        let mut rows = statement.query([]).unwrap();
        while let Some(row) = rows.next().unwrap() {
            use rusqlite::types::ValueRef;
            digest.update([0xff]);
            for index in 0..column_count {
                match row.get_ref(index).unwrap() {
                    ValueRef::Null => digest.update([0]),
                    ValueRef::Integer(value) => {
                        digest.update([1]);
                        digest.update(value.to_le_bytes());
                    }
                    ValueRef::Real(value) => {
                        digest.update([2]);
                        digest.update(value.to_bits().to_le_bytes());
                    }
                    ValueRef::Text(value) => {
                        digest.update([3]);
                        digest.update((value.len() as u64).to_le_bytes());
                        digest.update(value);
                    }
                    ValueRef::Blob(value) => {
                        digest.update([4]);
                        digest.update((value.len() as u64).to_le_bytes());
                        digest.update(value);
                    }
                }
            }
        }
    }
    digest.finalize().into()
}

fn issue_310_daemon_status() -> AgentDaemonStatus {
    serde_json::from_value(json!({
        "schema_version": "depgraph-daemon-v1",
        "phase": "stopped",
        "started_at": "2026-08-08T00:00:00.000Z",
        "stopped_at": "2026-08-08T00:00:01.000Z",
        "debounce_milliseconds": 0,
        "pending_change_count": 0,
        "recovered_attempts": {
            "scan_attempt_ids": [],
            "build_attempt_ids": []
        }
    }))
    .unwrap()
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
    let traversal_exhausted = mcp.request(json!({
        "jsonrpc": "2.0",
        "id": 22,
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
                "max_traversal": 1,
                "limit": 1
            }
        }
    }));
    let traversal_exhausted = &traversal_exhausted["result"];
    assert_eq!(
        traversal_exhausted["isError"], true,
        "{traversal_exhausted}"
    );
    assert_eq!(
        traversal_exhausted["structuredContent"]["error"]["code"],
        "RESOURCE_EXHAUSTED"
    );
    assert!(
        traversal_exhausted["structuredContent"]
            .get("result")
            .is_none()
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
fn issue_303_cli_mcp_parity_schemas_redaction_and_fail_closed_contracts() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("repository");
    let store_path = temporary.path().join("store.sqlite");
    let source_revision = prepare_issue_303_repository(&root);
    seed_issue_303_store(&store_path, &root, &source_revision);
    let before = store_invariant(&store_path);

    let cli = |arguments: &[&str]| {
        let binary = AssertCommand::cargo_bin("depgraph").unwrap();
        let output = Command::new(binary.get_program())
            .args(binary.get_args())
            .current_dir(&root)
            .arg("--store")
            .arg(&store_path)
            .arg("--scan-id")
            .arg("issue-303")
            .args(arguments)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "CLI {arguments:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice::<Value>(&output.stdout).unwrap()
    };
    let cli_impact = cli(&["impact", "id:node:root", "--json"]);
    let cli_cycles = cli(&["cycles", "--level", "file", "--json"]);
    let cli_unresolved = cli(&["unresolved", "--all", "--json"]);

    let common = || {
        json!({
            "contract_version": "depgraph-mcp-tools-v1",
            "repository_id": "repository",
            "snapshot": "current"
        })
    };
    let mut mcp = InteractiveMcp::start(&root, &store_path);
    let initialized = mcp.request(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2026-07-28",
            "capabilities": {},
            "clientInfo": {"name": "issue-303-test", "version": "1"}
        }
    }));
    assert_eq!(initialized["id"], 1);
    let listed = mcp.request(json!({
        "jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}
    }));
    let tools = listed["result"]["tools"].as_array().unwrap();

    let mut impact_arguments = common();
    impact_arguments["selector"] = json!("id:node:root");
    impact_arguments["max_nodes"] = json!(100);
    impact_arguments["max_edges"] = json!(100);
    impact_arguments["limit"] = json!(1);
    let impact = interactive_tool_call(&mut mcp, 3, "graph_impact_get", impact_arguments.clone());
    assert_eq!(impact["isError"], false, "{impact}");
    assert_tool_text_matches_structured(&impact);
    let impact_cursor = impact["structuredContent"]["result"]["impacts"]["next_cursor"]
        .as_str()
        .expect("impact fixture produces more than one item")
        .to_owned();
    let impact_repeat =
        interactive_tool_call(&mut mcp, 4, "graph_impact_get", impact_arguments.clone());
    assert_eq!(
        impact_repeat["structuredContent"], impact["structuredContent"],
        "the canonical first page must be byte-stable"
    );
    let mut full_impact_arguments = impact_arguments.clone();
    full_impact_arguments["limit"] = json!(100);
    let full_impact =
        interactive_tool_call(&mut mcp, 30, "graph_impact_get", full_impact_arguments);
    assert_eq!(full_impact["isError"], false, "{full_impact}");
    let mut cursor_mismatch_arguments = impact_arguments.clone();
    cursor_mismatch_arguments["cursor"] = json!(impact_cursor);
    cursor_mismatch_arguments["depth"] = json!(1);
    let cursor_mismatch =
        interactive_tool_call(&mut mcp, 5, "graph_impact_get", cursor_mismatch_arguments);
    assert_eq!(cursor_mismatch["isError"], true, "{cursor_mismatch}");
    assert_eq!(
        cursor_mismatch["structuredContent"]["error"]["code"],
        "CURSOR_MISMATCH"
    );

    let mut cycles_arguments = common();
    cycles_arguments["level"] = json!("file");
    cycles_arguments["max_traversal"] = json!(100);
    cycles_arguments["limit"] = json!(100);
    let cycles = interactive_tool_call(&mut mcp, 6, "graph_cycles_list", cycles_arguments.clone());
    assert_eq!(cycles["isError"], false, "{cycles}");
    assert_eq!(
        cycles["structuredContent"]["result"]["items"][0]["level"],
        "file"
    );

    let mut unresolved_arguments = common();
    unresolved_arguments["max_traversal"] = json!(100);
    unresolved_arguments["limit"] = json!(100);
    let unresolved = interactive_tool_call(
        &mut mcp,
        7,
        "graph_unresolved_list",
        unresolved_arguments.clone(),
    );
    assert_eq!(unresolved["isError"], false, "{unresolved}");
    assert_eq!(
        unresolved["structuredContent"]["result"]["items"][0]["site"]["id"],
        "site:missing"
    );
    assert!(
        unresolved["structuredContent"]["result"]["items"][0]["effective_profile_id"]
            .as_str()
            .is_some_and(|id| id.starts_with("effective-profile:sha256:"))
    );

    let mcp_impact_ids = full_impact["structuredContent"]["result"]["impacts"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["node"]["id"].as_str().unwrap().to_owned())
        .collect::<Vec<_>>();
    let cli_impact_ids = cli_impact["data"]["impacts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["node"]["id"].as_str().unwrap().to_owned())
        .collect::<Vec<_>>();
    assert_eq!(mcp_impact_ids, cli_impact_ids);
    let mcp_cycles = cycles["structuredContent"]["result"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["node_ids"].clone())
        .collect::<Vec<_>>();
    let cli_cycles = cli_cycles["data"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["node_ids"].clone())
        .collect::<Vec<_>>();
    assert_eq!(mcp_cycles, cli_cycles);
    let mcp_unresolved = unresolved["structuredContent"]["result"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["site"]["id"].clone())
        .collect::<Vec<_>>();
    let cli_unresolved = cli_unresolved["data"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["site"]["id"].clone())
        .collect::<Vec<_>>();
    assert_eq!(mcp_unresolved, cli_unresolved);

    fs::write(root.join("src/root.rs"), "// root\n// dirty\n").unwrap();
    let mut changed_arguments = common();
    changed_arguments["selector"] = json!("id:node:root");
    changed_arguments["changed_since"] = json!("HEAD");
    changed_arguments["max_nodes"] = json!(100);
    changed_arguments["max_edges"] = json!(100);
    changed_arguments["limit"] = json!(100);
    let changed = interactive_tool_call(&mut mcp, 8, "graph_impact_get", changed_arguments.clone());
    assert_eq!(changed["isError"], false, "{changed}");
    assert!(
        changed["structuredContent"]["result"]["changed_since"]["changed_paths"]
            .as_u64()
            .unwrap()
            >= 1
    );
    assert!(
        changed["structuredContent"]["result"]["changed_since"]["mapped_nodes"]
            .as_u64()
            .unwrap()
            >= 1
    );

    let mut named_changed = changed_arguments.clone();
    named_changed["snapshot"] = json!("issue-303");
    let named_changed = interactive_tool_call(&mut mcp, 9, "graph_impact_get", named_changed);
    assert_eq!(named_changed["isError"], true, "{named_changed}");
    assert_eq!(
        named_changed["structuredContent"]["error"]["code"],
        "INVALID_ARGUMENT"
    );

    for (id, name, mut arguments) in [
        (10, "graph_impact_get", impact_arguments.clone()),
        (11, "graph_cycles_list", cycles_arguments.clone()),
        (12, "graph_unresolved_list", unresolved_arguments.clone()),
    ] {
        if name == "graph_impact_get" {
            arguments["max_nodes"] = json!(1);
            arguments["max_edges"] = json!(100);
        } else {
            arguments["max_traversal"] = json!(1);
        }
        let exhausted = interactive_tool_call(&mut mcp, id, name, arguments);
        assert_eq!(exhausted["isError"], true, "{name}: {exhausted}");
        assert_eq!(
            exhausted["structuredContent"]["error"]["code"],
            "RESOURCE_EXHAUSTED"
        );
        assert!(exhausted["structuredContent"].get("result").is_none());
    }

    issue_303_git(&root, &["add", "src/root.rs"]);
    issue_303_git(&root, &["commit", "--quiet", "-m", "advance head"]);
    let mismatched = interactive_tool_call(&mut mcp, 13, "graph_impact_get", changed_arguments);
    assert_eq!(mismatched["isError"], true, "{mismatched}");
    assert_eq!(
        mismatched["structuredContent"]["error"]["code"],
        "SNAPSHOT_WORKTREE_MISMATCH"
    );
    assert!(mismatched["structuredContent"].get("result").is_none());

    let shared_schema: Value = serde_json::from_slice(include_bytes!(
        "../../../schemas/depgraph-mcp-tools-v1.schema.json"
    ))
    .unwrap();
    let shared = jsonschema::draft202012::new(&shared_schema).unwrap();
    for (name, result) in [
        ("graph_impact_get", &impact),
        ("graph_impact_get", &full_impact),
        ("graph_cycles_list", &cycles),
        ("graph_unresolved_list", &unresolved),
        ("graph_impact_get", &changed),
    ] {
        let structured = &result["structuredContent"];
        let advertised_schema =
            tools.iter().find(|tool| tool["name"] == name).unwrap()["outputSchema"].clone();
        jsonschema::draft202012::new(&advertised_schema)
            .unwrap()
            .validate(structured)
            .unwrap_or_else(|error| panic!("{name} advertised schema: {error}"));
        shared
            .validate(structured)
            .unwrap_or_else(|error| panic!("{name} shared schema: {error}"));
        assert_tool_text_matches_structured(result);
        let encoded = structured.to_string();
        for forbidden in [
            root.to_string_lossy().as_ref(),
            "PROCESS_303_",
            "properties",
            "SITE_DETAIL_SECRET",
            "EVIDENCE_SECRET",
        ] {
            assert!(!encoded.contains(forbidden), "{name} leaked {forbidden}");
        }
    }

    mcp.finish();
    assert_eq!(before, store_invariant(&store_path));
}

#[test]
fn issue_304_query_and_runtime_validate_have_cli_mcp_parity_and_fail_closed_security() {
    const QUERY: &str = r#"MATCH p = (source:"module")-["imports"*1..1]->(target:"module")
RETURN source.id, target.id LIMIT 10"#;
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("repository");
    let store_path = temporary.path().join("store.sqlite");
    fs::create_dir(&root).unwrap();
    let snapshot_id = seed_issue_302_store(&store_path, &root);
    fs::write(root.join("query.depgraph"), QUERY).unwrap();
    let trace = json!({
        "schema_version": "1.0",
        "repository": {"identity": "workspace:repository", "revision": "revision-302"},
        "session": {
            "id": "session-304",
            "started_at": "2026-08-07T00:00:00Z",
            "ended_at": "2026-08-07T00:00:01Z",
            "profile": {"language": "fixture", "features": []},
            "environment": {"name": "test"},
            "redaction": {"redacted_value_count": 1}
        },
        "events": [{
            "sequence": 1,
            "timestamp": "2026-08-07T00:00:00Z",
            "dependency_kind": "imports",
            "source": {"kind": "node", "node_id": "node:a"},
            "target": {"kind": "node", "node_id": "node:b"},
            "count": 1,
            "redaction": {"redacted_value_count": 1}
        }]
    });
    fs::write(root.join("trace.json"), trace.to_string()).unwrap();
    let before = store_invariant(&store_path);

    let mut mcp = InteractiveMcp::start(&root, &store_path);
    let initialized = mcp.request(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2026-07-28",
            "capabilities": {},
            "clientInfo": {"name": "issue-304-test", "version": "1"}
        }
    }));
    assert_eq!(initialized["id"], 1);
    let listed = mcp.request(json!({
        "jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}
    }));
    let tools = listed["result"]["tools"].as_array().unwrap();
    let common = || {
        json!({
            "contract_version": "depgraph-mcp-tools-v1",
            "repository_id": "repository",
            "snapshot": "current"
        })
    };

    let mut query_arguments = common();
    query_arguments["query"] = json!(QUERY);
    query_arguments["limit"] = json!(1);
    let first = interactive_tool_call(&mut mcp, 3, "graph_query", query_arguments.clone());
    assert_eq!(first["isError"], false, "{first}");
    assert_tool_text_matches_structured(&first);
    assert_eq!(first["structuredContent"]["snapshot_id"], snapshot_id);
    assert_eq!(
        first["structuredContent"]["result"]["items"][0]["values"][0],
        json!({"kind":"text","value":"node:a"})
    );
    let query_cursor = first["structuredContent"]["result"]["next_cursor"]
        .as_str()
        .expect("query fixture has a second row")
        .to_owned();
    let repeated = interactive_tool_call(&mut mcp, 4, "graph_query", query_arguments.clone());
    assert_eq!(repeated["structuredContent"], first["structuredContent"]);

    let mut file_arguments = common();
    file_arguments["query_file"] = json!("query.depgraph");
    file_arguments["limit"] = json!(1);
    let file_query = interactive_tool_call(&mut mcp, 5, "graph_query", file_arguments);
    assert_eq!(file_query["isError"], false, "{file_query}");
    assert_eq!(file_query["structuredContent"], first["structuredContent"]);

    let mut next_arguments = query_arguments.clone();
    next_arguments["cursor"] = json!(query_cursor.clone());
    let next = interactive_tool_call(&mut mcp, 6, "graph_query", next_arguments);
    assert_eq!(next["isError"], false, "{next}");
    assert_ne!(next["structuredContent"], first["structuredContent"]);
    assert_ne!(
        next["structuredContent"]["result"]["items"],
        first["structuredContent"]["result"]["items"]
    );

    let mut mismatched_arguments = common();
    mismatched_arguments["query"] = json!(QUERY.replace("source.id, target.id", "target.id"));
    mismatched_arguments["limit"] = json!(1);
    mismatched_arguments["cursor"] = json!(query_cursor);
    let mismatched = interactive_tool_call(&mut mcp, 7, "graph_query", mismatched_arguments);
    assert_eq!(mismatched["isError"], true);
    assert_eq!(
        mismatched["structuredContent"]["error"]["code"],
        "CURSOR_MISMATCH"
    );

    let existential_terms = (0..16)
        .map(|index| {
            format!(
                "SOME evidence{index} IN EVIDENCE(p) SATISFIES evidence{index}.kind = \"source\""
            )
        })
        .collect::<Vec<_>>()
        .join(" AND ");
    let hostile_query = format!(
        "MATCH p = (source:\"module\")-[\"imports\"*1..8]->(target:\"module\") \
         WHERE {existential_terms} RETURN target.id LIMIT 1"
    );
    let mut hostile_arguments = common();
    hostile_arguments["query"] = json!(hostile_query);
    let rejected = interactive_tool_call(&mut mcp, 8, "graph_query", hostile_arguments);
    assert_eq!(rejected["isError"], true, "{rejected}");
    assert_eq!(
        rejected["structuredContent"]["error"]["code"],
        "QUERY_REJECTED"
    );

    let mut runtime_file_arguments = common();
    runtime_file_arguments["trace_file"] = json!("trace.json");
    runtime_file_arguments["limit"] = json!(1);
    let runtime_file = interactive_tool_call(
        &mut mcp,
        9,
        "runtime_trace_validate",
        runtime_file_arguments,
    );
    assert_eq!(runtime_file["isError"], false, "{runtime_file}");
    assert_tool_text_matches_structured(&runtime_file);
    assert_eq!(
        runtime_file["structuredContent"]["result"]["summary"]["events"],
        1
    );
    assert_eq!(
        runtime_file["structuredContent"]["result"]["events"]["items"][0]["source"]["node_id"],
        "node:a"
    );
    let mut runtime_inline_arguments = common();
    runtime_inline_arguments["trace"] = json!(trace.to_string());
    runtime_inline_arguments["limit"] = json!(1);
    let runtime_inline = interactive_tool_call(
        &mut mcp,
        10,
        "runtime_trace_validate",
        runtime_inline_arguments,
    );
    assert_eq!(runtime_inline["isError"], false, "{runtime_inline}");
    assert_eq!(
        runtime_inline["structuredContent"],
        runtime_file["structuredContent"]
    );

    let shared_schema: Value = serde_json::from_slice(include_bytes!(
        "../../../schemas/depgraph-mcp-tools-v1.schema.json"
    ))
    .unwrap();
    let shared = jsonschema::draft202012::new(&shared_schema).unwrap();
    for (name, result) in [
        ("graph_query", &first),
        ("runtime_trace_validate", &runtime_file),
    ] {
        let structured = &result["structuredContent"];
        let advertised =
            tools.iter().find(|tool| tool["name"] == name).unwrap()["outputSchema"].clone();
        jsonschema::draft202012::new(&advertised)
            .unwrap()
            .validate(structured)
            .unwrap_or_else(|error| panic!("{name} advertised schema: {error}"));
        shared
            .validate(structured)
            .unwrap_or_else(|error| panic!("{name} shared schema: {error}"));
    }
    mcp.finish();

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
            "CLI {arguments:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice::<Value>(&output.stdout).unwrap()
    };
    let cli_query = cli(&["query", "--query", QUERY, "--json"]);
    let mcp_first_values = first["structuredContent"]["result"]["items"][0]["values"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value["value"].clone())
        .collect::<Vec<_>>();
    assert_eq!(cli_query["rows"][0].as_array().unwrap(), &mcp_first_values);
    let cli_runtime = cli(&["runtime", "validate", "--file", "trace.json", "--json"]);
    assert_eq!(
        cli_runtime["data"]["summary"],
        runtime_file["structuredContent"]["result"]["summary"]
    );
    assert_eq!(
        cli_runtime["data"]["events"][0]["id"],
        runtime_file["structuredContent"]["result"]["events"]["items"][0]["id"]
    );
    assert_eq!(before, store_invariant(&store_path));
}

#[test]
fn issue_305_diff_policy_and_inline_export_have_cli_mcp_parity_and_shared_schema_coverage() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("repository");
    let store_path = temporary.path().join("store.sqlite");
    fs::create_dir(&root).unwrap();
    let snapshot_id = seed_issue_302_store(&store_path, &root);
    let before = store_invariant(&store_path);

    let mut mcp = InteractiveMcp::start(&root, &store_path);
    mcp.request(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2026-07-28",
            "capabilities": {},
            "clientInfo": {"name": "issue-305-test", "version": "1"}
        }
    }));
    let listed = mcp.request(json!({
        "jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}
    }));
    let tools = listed["result"]["tools"].as_array().unwrap();
    let common = json!({
        "contract_version": "depgraph-mcp-tools-v1",
        "repository_id": "repository",
        "from": "current",
        "to": "current"
    });
    let diff = interactive_tool_call(&mut mcp, 3, "snapshot_diff_get", common.clone());
    assert_eq!(diff["isError"], false, "{diff}");
    assert_tool_text_matches_structured(&diff);
    assert_eq!(diff["structuredContent"]["snapshot_id"], snapshot_id);
    let policy = interactive_tool_call(&mut mcp, 4, "policy_evaluate", common);
    assert_eq!(policy["isError"], false, "{policy}");
    assert_tool_text_matches_structured(&policy);
    let export = interactive_tool_call(
        &mut mcp,
        5,
        "graph_export",
        json!({
            "contract_version": "depgraph-mcp-tools-v1",
            "repository_id": "repository",
            "snapshot": "current",
            "format": "json"
        }),
    );
    assert_eq!(export["isError"], false, "{export}");
    assert_tool_text_matches_structured(&export);

    let shared_schema: Value = serde_json::from_slice(include_bytes!(
        "../../../schemas/depgraph-mcp-tools-v1.schema.json"
    ))
    .unwrap();
    let shared = jsonschema::draft202012::new(&shared_schema).unwrap();
    for (name, result) in [
        ("snapshot_diff_get", &diff),
        ("policy_evaluate", &policy),
        ("graph_export", &export),
    ] {
        let structured = &result["structuredContent"];
        let advertised =
            tools.iter().find(|tool| tool["name"] == name).unwrap()["outputSchema"].clone();
        jsonschema::draft202012::new(&advertised)
            .unwrap()
            .validate(structured)
            .unwrap_or_else(|error| panic!("{name} advertised schema: {error}"));
        shared
            .validate(structured)
            .unwrap_or_else(|error| panic!("{name} shared schema: {error}"));
    }
    mcp.finish();

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
            "CLI {arguments:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output.stdout
    };

    let cli_diff: Value =
        serde_json::from_slice(&cli(&["diff", "current", "current", "--json"])).unwrap();
    assert_eq!(
        cli_diff["data"]["from_snapshot_id"],
        diff["structuredContent"]["result"]["from_snapshot_id"]
    );
    assert_eq!(
        cli_diff["data"]["to_snapshot_id"],
        diff["structuredContent"]["result"]["to_snapshot_id"]
    );
    assert_eq!(
        cli_diff["data"]["summary"]["total_changes"],
        diff["structuredContent"]["result"]["total_changes"]
    );
    assert_eq!(
        cli_diff["data"]["collection_digest"],
        diff["structuredContent"]["result"]["collection_digest"]
    );

    let cli_policy: Value =
        serde_json::from_slice(&cli(&["policy", "current", "current", "--json"])).unwrap();
    for field in ["from_snapshot_id", "to_snapshot_id", "collection_digest"] {
        assert_eq!(
            cli_policy["data"][field], policy["structuredContent"]["result"][field],
            "policy field {field}"
        );
    }
    for field in ["result_id", "policy_config_digest", "summary"] {
        assert_eq!(
            cli_policy["data"]["result"][field], policy["structuredContent"]["result"][field],
            "policy result field {field}"
        );
    }
    let cli_export_bytes = cli(&["export", "--format", "json"]);
    let cli_export_content = String::from_utf8(cli_export_bytes).expect("CLI JSON export is UTF-8");
    let cli_export: Value =
        serde_json::from_str(&cli_export_content).expect("CLI JSON export is valid JSON");
    let mcp_export = &export["structuredContent"]["result"];
    assert_eq!(mcp_export["snapshot_id"], snapshot_id);
    assert_eq!(mcp_export["format"], "json");
    let mcp_content = mcp_export["content"].as_str().unwrap();
    let mcp_graph = serde_json::from_str::<Value>(mcp_content).unwrap();
    assert_eq!(cli_export_content, mcp_content);
    assert_eq!(cli_export, mcp_graph);
    let digest = sha2::Sha256::digest(cli_export_content.as_bytes());
    assert_eq!(mcp_export["content_sha256"], format!("{digest:x}"));
    assert_eq!(
        mcp_export["output_bytes"],
        u64::try_from(cli_export_content.len()).unwrap()
    );
    let root_text = root.to_string_lossy().into_owned();
    for forbidden in [
        "properties",
        "PROCESS_GRAPH_SECRET",
        "PRIVATE_DETAIL",
        root_text.as_str(),
    ] {
        assert!(
            !cli_export_content.contains(forbidden),
            "canonical CLI/MCP export disclosed {forbidden}"
        );
    }
    assert_eq!(before, store_invariant(&store_path));
}

#[test]
fn issue_304_hostile_inputs_are_rejected_before_missing_store_access_without_echo() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("repository");
    let missing_store = temporary.path().join("must-not-open.sqlite");
    fs::create_dir(&root).unwrap();
    let secret = "fixture-secret-value";
    let credential_query = format!(
        "MATCH p = (source)-[\"imports\"*1..1]->(target) \
         WHERE source.id = \"token={secret}\" RETURN target.id LIMIT 1"
    );
    let calls = [
        (
            "graph_query",
            json!({
                "contract_version":"depgraph-mcp-tools-v1",
                "repository_id":"repository",
                "query":credential_query
            }),
        ),
        (
            "runtime_trace_validate",
            json!({
                "contract_version":"depgraph-mcp-tools-v1",
                "repository_id":"repository",
                "trace": json!({"authorization":secret}).to_string()
            }),
        ),
        (
            "graph_query",
            json!({
                "contract_version":"depgraph-mcp-tools-v1",
                "repository_id":"repository",
                "query_file":root.join("absolute-secret.query")
            }),
        ),
    ];
    for (name, arguments) in calls {
        let result = call_issue_300_tool(&root, &missing_store, name, arguments);
        assert_eq!(result["isError"], true, "{name}: {result}");
        assert_eq!(
            result["structuredContent"]["error"]["code"],
            "INVALID_ARGUMENT"
        );
        let encoded = result.to_string();
        assert!(!encoded.contains(secret));
        assert!(!encoded.contains(root.to_string_lossy().as_ref()));
        assert!(!missing_store.exists());
    }
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
fn cursor_paging_stays_pinned_when_current_snapshot_advances_concurrently() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("repository");
    let store_path = temporary.path().join("store.sqlite");
    fs::create_dir(&root).unwrap();
    seed_issue_300_store(&store_path, &root);
    let pinned_snapshot = seed_issue_300_bulk_rows(&store_path, &root);

    let mut mcp = InteractiveMcp::start(&root, &store_path);
    let initialized = mcp.request(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2026-07-28",
            "capabilities": {},
            "clientInfo": {"name": "issue-306-snapshot-pinning", "version": "1"}
        }
    }));
    assert_eq!(initialized["id"], 1);

    let first = interactive_tool_call(
        &mut mcp,
        2,
        "agent_nodes_list",
        json!({
            "contract_version": "depgraph-mcp-tools-v1",
            "repository_id": "repository",
            "snapshot": pinned_snapshot,
            "query": "bulk",
            "match_mode": "contains",
            "kinds": ["module"],
            "limit": 1000
        }),
    );
    assert_eq!(first["isError"], false, "{first}");
    assert_eq!(
        first["structuredContent"]["result"]["items"]
            .as_array()
            .unwrap()
            .len(),
        1000
    );
    let cursor = first["structuredContent"]["result"]["next_cursor"].clone();
    assert!(cursor.is_string());

    let advanced_snapshot = seed_issue_302_store(&store_path, &root);
    assert_ne!(advanced_snapshot, pinned_snapshot);
    assert_eq!(
        Store::open_read_only(&store_path)
            .unwrap()
            .current_snapshot_id()
            .unwrap()
            .unwrap(),
        advanced_snapshot
    );

    let second = interactive_tool_call(
        &mut mcp,
        3,
        "agent_nodes_list",
        json!({
            "contract_version": "depgraph-mcp-tools-v1",
            "repository_id": "repository",
            "snapshot": pinned_snapshot,
            "query": "bulk",
            "match_mode": "contains",
            "kinds": ["module"],
            "cursor": cursor,
            "limit": 1000
        }),
    );
    assert_eq!(second["isError"], false, "{second}");
    let second_ids = second["structuredContent"]["result"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["id"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        second_ids,
        [
            "node:bulk:1100",
            "node:bulk:1101",
            "node:bulk:1102",
            "node:bulk:1103",
            "node:bulk:1104",
        ]
    );
    assert_eq!(second["structuredContent"]["result"]["complete"], true);
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
fn issue_311_tasks_negotiation_preserves_modern_and_legacy_baselines() {
    let root = tempfile::tempdir().unwrap();

    let mut tasks = InteractiveMcp::start(root.path(), &root.path().join("tasks.sqlite"));
    let initialized = initialize_tasks_mcp(&mut tasks, 1, "2026-07-28", true);
    assert_eq!(
        initialized["result"]["capabilities"]["extensions"]["io.modelcontextprotocol/tasks"],
        json!({})
    );
    let tasks_tools = tasks.request(json!({
        "jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}
    }))["result"]["tools"]
        .clone();
    let unknown = tasks.request(json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tasks/get",
        "params": {"taskId": "op_ffffffffffffffffffffffffffffffff"}
    }));
    assert_eq!(unknown["error"]["code"], -32602);
    tasks.finish();

    for (index, protocol) in ["2026-07-28", "2025-11-25"].into_iter().enumerate() {
        let store = root.path().join(format!("baseline-{index}.sqlite"));
        let mut baseline = InteractiveMcp::start(root.path(), &store);
        let initialized =
            initialize_tasks_mcp(&mut baseline, 10, protocol, protocol == "2025-11-25");
        let advertised =
            &initialized["result"]["capabilities"]["extensions"]["io.modelcontextprotocol/tasks"];
        if protocol == "2026-07-28" {
            assert!(advertised.is_object());
        } else {
            assert!(advertised.is_null());
        }
        let baseline_tools = baseline.request(json!({
            "jsonrpc": "2.0", "id": 11, "method": "tools/list", "params": {}
        }))["result"]["tools"]
            .clone();
        assert_eq!(baseline_tools, tasks_tools);
        let unavailable = baseline.request(json!({
            "jsonrpc": "2.0",
            "id": 12,
            "method": "tasks/get",
            "params": {"taskId": "op_ffffffffffffffffffffffffffffffff"}
        }));
        assert_eq!(
            unavailable["error"]["code"],
            if protocol == "2026-07-28" {
                -32021
            } else {
                -32601
            }
        );
        for (id, method, params) in [
            (
                13,
                "tasks/update",
                json!({
                    "taskId": "op_ffffffffffffffffffffffffffffffff",
                    "inputResponses": {}
                }),
            ),
            (
                14,
                "tasks/cancel",
                json!({"taskId": "op_ffffffffffffffffffffffffffffffff"}),
            ),
        ] {
            let response = baseline.request(json!({
                "jsonrpc": "2.0", "id": id, "method": method, "params": params
            }));
            assert_eq!(response["error"]["code"], unavailable["error"]["code"]);
        }
        baseline.finish();
    }

    let request_meta = |protocol: &str, declares_tasks: bool| {
        let client_capabilities = if declares_tasks {
            json!({"extensions": {"io.modelcontextprotocol/tasks": {}}})
        } else {
            json!({})
        };
        json!({
            "io.modelcontextprotocol/protocolVersion": protocol,
            "io.modelcontextprotocol/clientCapabilities": client_capabilities
        })
    };

    let mut request_scoped =
        InteractiveMcp::start(root.path(), &root.path().join("request-scoped.sqlite"));
    initialize_tasks_mcp(&mut request_scoped, 20, "2026-07-28", false);
    let declared_on_request = request_scoped.request(json!({
        "jsonrpc": "2.0",
        "id": 21,
        "method": "tasks/get",
        "params": {
            "taskId": "op_ffffffffffffffffffffffffffffffff",
            "_meta": request_meta("2026-07-28", true)
        }
    }));
    assert_eq!(declared_on_request["error"]["code"], -32602);
    for (id, method, params) in [
        (
            22,
            "tasks/update",
            json!({
                "taskId": "op_ffffffffffffffffffffffffffffffff",
                "inputResponses": {},
                "_meta": request_meta("2026-07-28", true)
            }),
        ),
        (
            23,
            "tasks/cancel",
            json!({
                "taskId": "op_ffffffffffffffffffffffffffffffff",
                "_meta": request_meta("2026-07-28", true)
            }),
        ),
    ] {
        let response = request_scoped
            .request(json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}));
        assert_eq!(response["error"]["code"], -32602);
    }
    request_scoped.finish();

    let mut no_carry = InteractiveMcp::start(root.path(), &root.path().join("no-carry.sqlite"));
    initialize_tasks_mcp(&mut no_carry, 30, "2026-07-28", true);
    let omitted_on_request = no_carry.request(json!({
        "jsonrpc": "2.0",
        "id": 31,
        "method": "tasks/get",
        "params": {
            "taskId": "op_ffffffffffffffffffffffffffffffff",
            "_meta": request_meta("2026-07-28", false)
        }
    }));
    assert_eq!(omitted_on_request["error"]["code"], -32021);
    for (id, method, params) in [
        (
            33,
            "tasks/update",
            json!({
                "taskId": "op_ffffffffffffffffffffffffffffffff",
                "inputResponses": {},
                "_meta": request_meta("2026-07-28", false)
            }),
        ),
        (
            34,
            "tasks/cancel",
            json!({
                "taskId": "op_ffffffffffffffffffffffffffffffff",
                "_meta": request_meta("2026-07-28", false)
            }),
        ),
    ] {
        let response = no_carry
            .request(json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}));
        assert_eq!(response["error"]["code"], -32021);
    }
    let legacy_on_request = no_carry.request(json!({
        "jsonrpc": "2.0",
        "id": 32,
        "method": "tasks/get",
        "params": {
            "taskId": "op_ffffffffffffffffffffffffffffffff",
            "_meta": request_meta("2025-11-25", true)
        }
    }));
    assert_eq!(legacy_on_request["error"]["code"], -32601);
    for (id, method, params) in [
        (
            35,
            "tasks/update",
            json!({
                "taskId": "op_ffffffffffffffffffffffffffffffff",
                "inputResponses": {},
                "_meta": request_meta("2025-11-25", true)
            }),
        ),
        (
            36,
            "tasks/cancel",
            json!({
                "taskId": "op_ffffffffffffffffffffffffffffffff",
                "_meta": request_meta("2025-11-25", true)
            }),
        ),
    ] {
        let response = no_carry
            .request(json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}));
        assert_eq!(response["error"]["code"], -32601);
    }
    no_carry.finish();

    let mut stateless = InteractiveMcp::start(root.path(), &root.path().join("stateless.sqlite"));
    let discovered = stateless.request(json!({
        "jsonrpc": "2.0",
        "id": 40,
        "method": "server/discover",
        "params": {"_meta": request_meta("2026-07-28", false)}
    }));
    assert!(
        discovered["result"]["capabilities"]["extensions"]["io.modelcontextprotocol/tasks"]
            .is_object()
    );
    let stateless_task = stateless.request(json!({
        "jsonrpc": "2.0",
        "id": 41,
        "method": "tasks/get",
        "params": {
            "taskId": "op_ffffffffffffffffffffffffffffffff",
            "_meta": request_meta("2026-07-28", true)
        }
    }));
    assert_eq!(stateless_task["error"]["code"], -32602);
    stateless.finish();
}

#[test]
fn issue_311_tasks_reconnect_result_idempotency_and_authorized_cancel_conform() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("repository");
    let store_path = temporary.path().join("graph.sqlite");
    fs::create_dir(&root).unwrap();
    let full_config = operation_service_config(
        &root,
        &store_path,
        [
            DepgraphCapability::Read,
            DepgraphCapability::StoreWrite,
            DepgraphCapability::DaemonControl,
        ],
    );
    let repository_id = LogicalRepositoryId::parse(full_config.logical_repository_id()).unwrap();
    let submitted_at_ms = process_now_ms();
    let deadline_ms = submitted_at_ms + 120_000;
    let completed_request = SubmitRequest::new(
        &full_config,
        OperationKind::DaemonStop,
        &json!({"fixture": "tasks-completed"}),
        b"issue-311-completed",
        deadline_ms,
    )
    .unwrap();
    let cancel_request = SubmitRequest::new(
        &full_config,
        OperationKind::DaemonStop,
        &json!({"fixture": "tasks-cancel"}),
        b"issue-311-cancel",
        deadline_ms,
    )
    .unwrap();
    let failed_request = SubmitRequest::new(
        &full_config,
        OperationKind::DaemonStop,
        &json!({"fixture": "tasks-failed"}),
        b"issue-311-failed",
        deadline_ms,
    )
    .unwrap();
    let mut manager = OperationManager::open(&full_config).unwrap();
    let completed_id = manager
        .submit(&completed_request, submitted_at_ms)
        .unwrap()
        .operation_id()
        .clone();
    let cancel_id = manager
        .submit(&cancel_request, submitted_at_ms + 1)
        .unwrap()
        .operation_id()
        .clone();
    let failed_id = manager
        .submit(&failed_request, submitted_at_ms + 2)
        .unwrap()
        .operation_id()
        .clone();
    let retried = manager
        .submit(&completed_request, submitted_at_ms + 3)
        .unwrap();
    assert!(!retried.created());
    assert_eq!(retried.operation_id(), &completed_id);
    drop(manager);

    let mut journal = OperationJournal::open(&full_config).unwrap();
    journal
        .acquire_lease(
            &repository_id,
            &cancel_id,
            &LeaseOwner::parse("issue-311-cancel").unwrap(),
            b"issue-311-cancel-lease",
            submitted_at_ms + 3,
            submitted_at_ms + 60_000,
        )
        .unwrap();
    journal
        .acquire_lease(
            &repository_id,
            &completed_id,
            &LeaseOwner::parse("issue-311-complete").unwrap(),
            b"issue-311-complete-lease",
            submitted_at_ms + 3,
            submitted_at_ms + 60_000,
        )
        .unwrap();
    journal
        .acquire_lease(
            &repository_id,
            &failed_id,
            &LeaseOwner::parse("issue-311-failed").unwrap(),
            b"issue-311-failed-lease",
            submitted_at_ms + 4,
            submitted_at_ms + 60_000,
        )
        .unwrap();
    let envelope = SuccessEnvelope::new(repository_id.clone(), None, issue_310_daemon_status());
    journal
        .complete(
            &repository_id,
            &completed_id,
            b"issue-311-complete-lease",
            CanonicalJson::new(serde_json::to_value(&envelope).unwrap()).unwrap(),
            submitted_at_ms + 4,
        )
        .unwrap();
    let failure = ErrorEnvelope::new(
        repository_id.clone(),
        AgentError::new(
            AgentErrorCode::ResourceExhausted,
            false,
            AgentRemediation::Retry,
            Some(AgentErrorDetails::Operation {
                operation_id: failed_id.clone(),
            }),
        ),
    );
    journal
        .fail(
            &repository_id,
            &failed_id,
            b"issue-311-failed-lease",
            CanonicalJson::new(serde_json::to_value(&failure).unwrap()).unwrap(),
            submitted_at_ms + 5,
        )
        .unwrap();
    drop(journal);

    let mut denied = InteractiveMcp::start(&root, &store_path);
    initialize_tasks_mcp(&mut denied, 1, "2026-07-28", true);
    let completed = denied.request(json!({
        "jsonrpc": "2.0", "id": 2, "method": "tasks/get",
        "params": {"taskId": completed_id.as_str()}
    }));
    assert_eq!(completed["result"]["taskId"], completed_id.as_str());
    assert_eq!(completed["result"]["status"], "completed");
    assert_eq!(completed["result"]["result"]["isError"], false);
    assert_eq!(
        completed["result"]["result"]["structuredContent"]["result"]["phase"],
        "stopped"
    );
    assert!(
        completed["result"]["createdAt"]
            .as_str()
            .unwrap()
            .ends_with('Z')
    );
    assert!(completed["result"]["ttlMs"].as_u64().is_some());

    let before_update = operation_journal_state_digest(&full_config);
    let updated = denied.request(json!({
        "jsonrpc": "2.0", "id": 19, "method": "tasks/update",
        "params": {
            "taskId": completed_id.as_str(),
            "inputResponses": {"unknown-response-key": {"secret": "ignored"}}
        }
    }));
    assert!(updated.get("error").is_none());
    assert_eq!(operation_journal_state_digest(&full_config), before_update);
    let unknown_update = denied.request(json!({
        "jsonrpc": "2.0", "id": 21, "method": "tasks/update",
        "params": {
            "taskId": "op_ffffffffffffffffffffffffffffffff",
            "inputResponses": {}
        }
    }));
    assert_eq!(unknown_update["error"]["code"], -32602);
    assert_eq!(operation_journal_state_digest(&full_config), before_update);

    let failed = denied.request(json!({
        "jsonrpc": "2.0", "id": 20, "method": "tasks/get",
        "params": {"taskId": failed_id.as_str()}
    }));
    assert_eq!(failed["result"]["status"], "completed");
    assert_eq!(failed["result"]["result"]["isError"], true);
    assert_eq!(
        failed["result"]["result"]["structuredContent"]["error"]["code"],
        "RESOURCE_EXHAUSTED"
    );

    let working = denied.request(json!({
        "jsonrpc": "2.0", "id": 3, "method": "tasks/get",
        "params": {"taskId": cancel_id.as_str()}
    }));
    assert_eq!(working["result"]["taskId"], cancel_id.as_str());
    assert_eq!(working["result"]["status"], "working");
    assert_eq!(working["result"]["pollIntervalMs"], 1_000);

    let before_denied = operation_journal_state_digest(&full_config);
    let cancel_denied = denied.request(json!({
        "jsonrpc": "2.0", "id": 4, "method": "tasks/cancel",
        "params": {"taskId": cancel_id.as_str()}
    }));
    assert_eq!(cancel_denied["error"]["code"], -32600);
    assert_eq!(operation_journal_state_digest(&full_config), before_denied);
    denied.finish();

    let mut authorized = InteractiveMcp::start_with_capabilities(
        &root,
        &store_path,
        &["store-write", "daemon-control"],
    );
    initialize_tasks_mcp(&mut authorized, 10, "2026-07-28", true);
    let reconnected = authorized.request(json!({
        "jsonrpc": "2.0", "id": 11, "method": "tasks/get",
        "params": {"taskId": completed_id.as_str()}
    }));
    assert_eq!(reconnected["result"], completed["result"]);

    let cancelled = authorized.request(json!({
        "jsonrpc": "2.0", "id": 12, "method": "tasks/cancel",
        "params": {"taskId": cancel_id.as_str()}
    }));
    assert!(cancelled.get("error").is_none());
    let after_first_cancel = operation_journal_state_digest(&full_config);
    let repeated = authorized.request(json!({
        "jsonrpc": "2.0", "id": 13, "method": "tasks/cancel",
        "params": {"taskId": cancel_id.as_str()}
    }));
    assert!(repeated.get("error").is_none());
    assert_eq!(
        operation_journal_state_digest(&full_config),
        after_first_cancel
    );
    let cancellation_requested = authorized.request(json!({
        "jsonrpc": "2.0", "id": 14, "method": "tasks/get",
        "params": {"taskId": cancel_id.as_str()}
    }));
    assert_eq!(cancellation_requested["result"]["status"], "working");
    let mut journal = OperationJournal::open(&full_config).unwrap();
    journal
        .mark_cancelled(
            &repository_id,
            &cancel_id,
            b"issue-311-cancel-lease",
            process_now_ms(),
        )
        .unwrap();
    drop(journal);
    let terminal = authorized.request(json!({
        "jsonrpc": "2.0", "id": 15, "method": "tasks/get",
        "params": {"taskId": cancel_id.as_str()}
    }));
    assert_eq!(terminal["result"]["status"], "cancelled");
    authorized.finish();
}

#[test]
fn issue_311_tasks_request_cancellation_prevents_mutation_and_server_recovers() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("repository");
    let store_path = temporary.path().join("graph.sqlite");
    fs::create_dir(&root).unwrap();
    let config = operation_service_config(
        &root,
        &store_path,
        [
            DepgraphCapability::Read,
            DepgraphCapability::StoreWrite,
            DepgraphCapability::DaemonControl,
        ],
    );
    let request = SubmitRequest::new(
        &config,
        OperationKind::DaemonStop,
        &json!({"fixture": "tasks-runtime-cancellation"}),
        b"issue-311-runtime-cancellation",
        process_now_ms() + 60_000,
    )
    .unwrap();
    let task_id = OperationManager::open(&config)
        .unwrap()
        .submit(&request, process_now_ms())
        .unwrap()
        .operation_id()
        .clone();
    let before = operation_journal_state_digest(&config);

    for (id, method, params) in [
        (30, "tasks/get", json!({"taskId": task_id.as_str()})),
        (
            31,
            "tasks/update",
            json!({"taskId": task_id.as_str(), "inputResponses": {}}),
        ),
        (32, "tasks/cancel", json!({"taskId": task_id.as_str()})),
    ] {
        let mut mcp = InteractiveMcp::start_with_capabilities(
            &root,
            &store_path,
            &["store-write", "daemon-control"],
        );
        initialize_tasks_mcp(&mut mcp, 1, "2026-07-28", true);

        let blocker = Connection::open(operation_journal_path(&config)).unwrap();
        blocker
            .execute_batch("PRAGMA journal_mode = DELETE; BEGIN EXCLUSIVE;")
            .unwrap();
        mcp.send(json!({
            "jsonrpc": "2.0", "id": id, "method": method, "params": params
        }));
        std::thread::sleep(Duration::from_millis(75));
        mcp.notify(json!({
            "jsonrpc": "2.0",
            "method": "notifications/cancelled",
            "params": {"requestId": id, "reason": "issue-311-fixture"}
        }));
        std::thread::sleep(Duration::from_millis(75));
        blocker.execute_batch("ROLLBACK").unwrap();
        let probe_id = id + 100;
        mcp.send(json!({
            "jsonrpc": "2.0", "id": probe_id, "method": "tools/list", "params": {}
        }));
        let recovered = mcp.read_response();
        assert_eq!(recovered["id"], probe_id);
        assert!(recovered["result"]["tools"].is_array());
        std::thread::sleep(Duration::from_millis(75));
        mcp.finish();
        assert_eq!(operation_journal_state_digest(&config), before);
    }
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

#[test]
fn issue_310_operation_baseline_recovers_across_processes_and_reauthorizes_cancel() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("repository");
    let store_path = temporary.path().join("graph.sqlite");
    fs::create_dir(&root).unwrap();
    let full_config = operation_service_config(
        &root,
        &store_path,
        [
            DepgraphCapability::Read,
            DepgraphCapability::StoreWrite,
            DepgraphCapability::DaemonControl,
        ],
    );
    let repository_id = LogicalRepositoryId::parse(full_config.logical_repository_id()).unwrap();
    let submitted_at_ms = process_now_ms();
    let deadline_ms = submitted_at_ms + 120_000;
    let recoverable_request = SubmitRequest::new(
        &full_config,
        OperationKind::DaemonStop,
        &json!({"fixture": "reconnect"}),
        b"issue-310-reconnect",
        deadline_ms,
    )
    .unwrap();
    let mut manager = OperationManager::open(&full_config).unwrap();
    let recoverable = manager
        .submit(&recoverable_request, submitted_at_ms)
        .unwrap();
    let recoverable_id = recoverable.operation_id().clone();
    let cancellable_id = manager
        .submit(
            &SubmitRequest::new(
                &full_config,
                OperationKind::ScanSubmit,
                &json!({"fixture": "cancel"}),
                b"issue-310-cancel",
                deadline_ms,
            )
            .unwrap(),
            submitted_at_ms + 1,
        )
        .unwrap()
        .operation_id()
        .clone();
    let hostile_id = manager
        .submit(
            &SubmitRequest::new(
                &full_config,
                OperationKind::DaemonStop,
                &json!({"fixture": "hostile-terminal"}),
                b"issue-310-hostile-terminal",
                deadline_ms,
            )
            .unwrap(),
            submitted_at_ms + 2,
        )
        .unwrap()
        .operation_id()
        .clone();
    let mismatched_id = manager
        .submit(
            &SubmitRequest::new(
                &full_config,
                OperationKind::ScanSubmit,
                &json!({"fixture": "mismatched-terminal"}),
                b"issue-310-mismatched-terminal",
                deadline_ms,
            )
            .unwrap(),
            submitted_at_ms + 3,
        )
        .unwrap()
        .operation_id()
        .clone();
    let typed_failure_id = manager
        .submit(
            &SubmitRequest::new(
                &full_config,
                OperationKind::ScanSubmit,
                &json!({"fixture": "typed-terminal-error"}),
                b"issue-310-typed-terminal-error",
                deadline_ms,
            )
            .unwrap(),
            submitted_at_ms + 4,
        )
        .unwrap()
        .operation_id()
        .clone();
    drop(manager);

    let mut retried_manager = OperationManager::open(&full_config).unwrap();
    let retried = retried_manager
        .submit(&recoverable_request, submitted_at_ms + 5)
        .unwrap();
    assert!(!retried.created());
    assert_eq!(retried.operation_id(), &recoverable_id);
    drop(retried_manager);

    let mut journal = OperationJournal::open(&full_config).unwrap();
    journal
        .acquire_lease(
            &repository_id,
            &cancellable_id,
            &LeaseOwner::parse("issue-310-running").unwrap(),
            b"issue-310-running-lease",
            submitted_at_ms + 5,
            submitted_at_ms + 60_000,
        )
        .unwrap();
    journal
        .acquire_lease(
            &repository_id,
            &hostile_id,
            &LeaseOwner::parse("issue-310-hostile").unwrap(),
            b"issue-310-hostile-lease",
            submitted_at_ms + 5,
            submitted_at_ms + 60_000,
        )
        .unwrap();
    journal
        .complete(
            &repository_id,
            &hostile_id,
            b"issue-310-hostile-lease",
            CanonicalJson::new(json!({
                "raw_journal_secret": "MUST_NOT_REACH_AGENT"
            }))
            .unwrap(),
            submitted_at_ms + 6,
        )
        .unwrap();
    journal
        .acquire_lease(
            &repository_id,
            &mismatched_id,
            &LeaseOwner::parse("issue-310-mismatched").unwrap(),
            b"issue-310-mismatched-lease",
            submitted_at_ms + 5,
            submitted_at_ms + 60_000,
        )
        .unwrap();
    let mismatched_envelope =
        SuccessEnvelope::new(repository_id.clone(), None, issue_310_daemon_status());
    journal
        .complete(
            &repository_id,
            &mismatched_id,
            b"issue-310-mismatched-lease",
            CanonicalJson::new(serde_json::to_value(&mismatched_envelope).unwrap()).unwrap(),
            submitted_at_ms + 6,
        )
        .unwrap();
    journal
        .acquire_lease(
            &repository_id,
            &typed_failure_id,
            &LeaseOwner::parse("issue-310-typed-failure").unwrap(),
            b"issue-310-typed-failure-lease",
            submitted_at_ms + 5,
            submitted_at_ms + 60_000,
        )
        .unwrap();
    let typed_failure_envelope = ErrorEnvelope::new(
        repository_id.clone(),
        AgentError::new(
            AgentErrorCode::ResourceExhausted,
            false,
            AgentRemediation::Retry,
            Some(AgentErrorDetails::Operation {
                operation_id: typed_failure_id.clone(),
            }),
        ),
    );
    journal
        .fail(
            &repository_id,
            &typed_failure_id,
            b"issue-310-typed-failure-lease",
            CanonicalJson::new(serde_json::to_value(&typed_failure_envelope).unwrap()).unwrap(),
            submitted_at_ms + 6,
        )
        .unwrap();
    drop(journal);

    let operation_arguments = |operation_id: &depgraph_mcp_tools::OperationId| {
        json!({
            "contract_version": "depgraph-mcp-tools-v1",
            "repository_id": "repository",
            "operation_id": operation_id
        })
    };

    let mut first_server = InteractiveMcp::start(&root, &store_path);
    initialize_interactive_mcp(&mut first_server, 1);
    let queued = interactive_tool_call(
        &mut first_server,
        2,
        "operation_get",
        operation_arguments(&recoverable_id),
    );
    assert_eq!(queued["isError"], false);
    assert_eq!(queued["structuredContent"]["result"]["status"], "queued");
    assert_eq!(
        queued["structuredContent"]["result"]["operation_id"],
        recoverable_id.as_str()
    );
    assert_tool_text_matches_structured(&queued);

    let not_ready = interactive_tool_call(
        &mut first_server,
        3,
        "operation_result",
        operation_arguments(&recoverable_id),
    );
    assert_eq!(not_ready["isError"], true);
    assert_eq!(
        not_ready["structuredContent"]["error"]["code"],
        "OPERATION_NOT_READY"
    );
    assert_eq!(
        not_ready["structuredContent"]["error"]["details"]["operation_id"],
        recoverable_id.as_str()
    );
    assert_tool_text_matches_structured(&not_ready);

    let running = interactive_tool_call(
        &mut first_server,
        4,
        "operation_get",
        operation_arguments(&cancellable_id),
    );
    assert_eq!(running["structuredContent"]["result"]["status"], "running");

    let before_denied = operation_journal_state_digest(&full_config);
    let denied = interactive_tool_call(
        &mut first_server,
        5,
        "operation_cancel",
        operation_arguments(&cancellable_id),
    );
    assert_eq!(denied["isError"], true);
    assert_eq!(
        denied["structuredContent"]["error"]["code"],
        "CAPABILITY_DENIED"
    );
    assert_eq!(operation_journal_state_digest(&full_config), before_denied);

    let repository_denied = interactive_tool_call(
        &mut first_server,
        6,
        "operation_get",
        json!({
            "contract_version": "depgraph-mcp-tools-v1",
            "repository_id": "foreign-repository",
            "operation_id": recoverable_id
        }),
    );
    assert_eq!(
        repository_denied["structuredContent"]["error"]["code"],
        "CAPABILITY_DENIED"
    );
    assert_eq!(operation_journal_state_digest(&full_config), before_denied);

    let hostile = interactive_tool_call(
        &mut first_server,
        7,
        "operation_result",
        operation_arguments(&hostile_id),
    );
    assert_eq!(hostile["isError"], true);
    assert_eq!(
        hostile["structuredContent"]["error"]["code"],
        "INTEGRITY_FAILURE"
    );
    assert!(!hostile.to_string().contains("MUST_NOT_REACH_AGENT"));

    let mismatched = interactive_tool_call(
        &mut first_server,
        8,
        "operation_result",
        operation_arguments(&mismatched_id),
    );
    assert_eq!(mismatched["isError"], true);
    assert_eq!(
        mismatched["structuredContent"]["error"]["code"],
        "INTEGRITY_FAILURE"
    );
    assert!(!mismatched.to_string().contains("depgraph-daemon-v1"));

    let typed_failure = interactive_tool_call(
        &mut first_server,
        9,
        "operation_result",
        operation_arguments(&typed_failure_id),
    );
    assert_eq!(typed_failure["isError"], true);
    assert_eq!(
        typed_failure["structuredContent"],
        serde_json::to_value(&typed_failure_envelope).unwrap()
    );
    assert_tool_text_matches_structured(&typed_failure);
    first_server.finish();

    let terminal_at_ms = submitted_at_ms + 7;
    let terminal_envelope =
        SuccessEnvelope::new(repository_id.clone(), None, issue_310_daemon_status());
    let mut journal = OperationJournal::open(&full_config).unwrap();
    journal
        .acquire_lease(
            &repository_id,
            &recoverable_id,
            &LeaseOwner::parse("issue-310-reconnected-runner").unwrap(),
            b"issue-310-reconnected-lease",
            terminal_at_ms - 1,
            terminal_at_ms + 30_000,
        )
        .unwrap();
    journal
        .complete(
            &repository_id,
            &recoverable_id,
            b"issue-310-reconnected-lease",
            CanonicalJson::new(serde_json::to_value(&terminal_envelope).unwrap()).unwrap(),
            terminal_at_ms,
        )
        .unwrap();
    drop(journal);

    let mut restarted = InteractiveMcp::start(&root, &store_path);
    initialize_interactive_mcp(&mut restarted, 10);
    let terminal = interactive_tool_call(
        &mut restarted,
        11,
        "operation_get",
        operation_arguments(&recoverable_id),
    );
    assert_eq!(
        terminal["structuredContent"]["result"]["status"],
        "completed"
    );
    let recovered_result = interactive_tool_call(
        &mut restarted,
        12,
        "operation_result",
        operation_arguments(&recoverable_id),
    );
    assert_eq!(recovered_result["isError"], false);
    assert_eq!(
        recovered_result["structuredContent"],
        serde_json::to_value(&terminal_envelope).unwrap()
    );
    assert_tool_text_matches_structured(&recovered_result);
    restarted.finish();

    let mut privileged = InteractiveMcp::start_with_capabilities(
        &root,
        &store_path,
        &["store-write", "daemon-control"],
    );
    initialize_interactive_mcp(&mut privileged, 20);
    let before_unknown = operation_journal_state_digest(&full_config);
    let unknown_cancel = interactive_tool_call(
        &mut privileged,
        21,
        "operation_cancel",
        json!({
            "contract_version": "depgraph-mcp-tools-v1",
            "repository_id": "repository",
            "operation_id": "op_ffffffffffffffffffffffffffffffff"
        }),
    );
    assert_eq!(unknown_cancel["isError"], true);
    assert_eq!(
        unknown_cancel["structuredContent"]["error"]["code"],
        "NOT_FOUND"
    );
    assert_eq!(operation_journal_state_digest(&full_config), before_unknown);

    let cancelled = interactive_tool_call(
        &mut privileged,
        22,
        "operation_cancel",
        operation_arguments(&cancellable_id),
    );
    assert_eq!(cancelled["isError"], false);
    assert_eq!(
        cancelled["structuredContent"]["result"]["status"],
        "cancelling"
    );

    let mut journal = OperationJournal::open(&full_config).unwrap();
    journal
        .mark_cancelled(
            &repository_id,
            &cancellable_id,
            b"issue-310-running-lease",
            process_now_ms(),
        )
        .unwrap();
    drop(journal);
    let cancelled_result = interactive_tool_call(
        &mut privileged,
        23,
        "operation_result",
        operation_arguments(&cancellable_id),
    );
    assert_eq!(cancelled_result["isError"], true);
    assert_eq!(
        cancelled_result["structuredContent"]["error"]["code"],
        "CANCELLED"
    );
    assert_tool_text_matches_structured(&cancelled_result);

    let before_terminal_noop = operation_journal_state_digest(&full_config);
    let terminal_noop = interactive_tool_call(
        &mut privileged,
        24,
        "operation_cancel",
        operation_arguments(&recoverable_id),
    );
    assert_eq!(terminal_noop["isError"], false);
    assert_eq!(
        terminal_noop["structuredContent"]["result"]["status"],
        "completed"
    );
    assert_eq!(
        operation_journal_state_digest(&full_config),
        before_terminal_noop
    );
    privileged.finish();
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
fn issue_306_protocol_revisions_share_catalog_and_schema_valid_typed_errors() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("repository");
    let store_path = temporary.path().join("store.sqlite");
    fs::create_dir(&root).unwrap();
    seed_issue_300_store(&store_path, &root);
    let pinned_snapshot = seed_issue_303_store(&store_path, &root, "revision-306");
    let store_before = store_invariant(&store_path);
    let source_before = source_tree_digest(&root);
    let shared_schema: Value = serde_json::from_slice(include_bytes!(
        "../../../schemas/depgraph-mcp-tools-v1.schema.json"
    ))
    .unwrap();
    let shared = jsonschema::draft202012::new(&shared_schema).unwrap();
    let mut catalogs = Vec::new();

    for protocol_version in ["2025-11-25", "2026-07-28"] {
        let mut mcp = InteractiveMcp::start(&root, &store_path);
        let initialized = mcp.request(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": protocol_version,
                "capabilities": {},
                "clientInfo": {"name": "issue-306-test", "version": "1"}
            }
        }));
        assert_eq!(initialized["result"]["protocolVersion"], protocol_version);
        mcp.notify(json!({
            "jsonrpc": "2.0",
            "method": "notifications/cancelled",
            "params": {"requestId": 999_999, "reason": "fixture cancellation"}
        }));
        let listed = mcp.request(json!({
            "jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}
        }));
        let tools = listed["result"]["tools"].as_array().unwrap().clone();
        let context_arguments = json!({
            "contract_version": "depgraph-mcp-tools-v1",
            "repository_id": "repository"
        });
        let context = interactive_tool_call(&mut mcp, 3, "get_context", context_arguments.clone());
        let repeated_context = interactive_tool_call(&mut mcp, 4, "get_context", context_arguments);
        assert_eq!(context, repeated_context, "{protocol_version} determinism");
        assert_eq!(context["isError"], false, "{protocol_version}: {context}");
        assert_tool_text_matches_structured(&context);
        let context_schema = tools
            .iter()
            .find(|tool| tool["name"] == "get_context")
            .unwrap()["outputSchema"]
            .clone();
        jsonschema::draft202012::new(&context_schema)
            .unwrap()
            .validate(&context["structuredContent"])
            .unwrap_or_else(|validation| {
                panic!("{protocol_version} advertised success schema: {validation}")
            });
        shared
            .validate(&context["structuredContent"])
            .unwrap_or_else(|validation| {
                panic!("{protocol_version} shared success schema: {validation}")
            });
        let read_only_calls = [
            (
                "agent_edges_list",
                json!({"contract_version":"depgraph-mcp-tools-v1", "repository_id":"repository", "node_id":"node:root", "snapshot":pinned_snapshot, "limit":1}),
                Some(false),
            ),
            (
                "agent_evidence_list",
                json!({"contract_version":"depgraph-mcp-tools-v1", "repository_id":"repository", "site_id":"site:missing", "snapshot":pinned_snapshot, "limit":1}),
                Some(false),
            ),
            (
                "agent_node_get",
                json!({"contract_version":"depgraph-mcp-tools-v1", "repository_id":"repository", "node_id":"node:root", "snapshot":pinned_snapshot}),
                Some(false),
            ),
            (
                "agent_nodes_list",
                json!({"contract_version":"depgraph-mcp-tools-v1", "repository_id":"repository", "query":"node:", "match_mode":"prefix", "snapshot":pinned_snapshot, "limit":1}),
                None,
            ),
            (
                "agent_sites_list",
                json!({"contract_version":"depgraph-mcp-tools-v1", "repository_id":"repository", "snapshot":pinned_snapshot, "limit":1}),
                Some(false),
            ),
            (
                "daemon_get",
                json!({"contract_version":"depgraph-mcp-tools-v1", "repository_id":"repository"}),
                None,
            ),
            (
                "doctor_get",
                json!({"contract_version":"depgraph-mcp-tools-v1", "repository_id":"repository", "details":false}),
                None,
            ),
            (
                "get_context",
                json!({"contract_version":"depgraph-mcp-tools-v1", "repository_id":"repository"}),
                Some(false),
            ),
            (
                "graph_cycles_list",
                json!({"contract_version":"depgraph-mcp-tools-v1", "repository_id":"repository", "snapshot":pinned_snapshot, "limit":1}),
                None,
            ),
            (
                "graph_dependencies_list",
                json!({"contract_version":"depgraph-mcp-tools-v1", "repository_id":"repository", "selector":"node:root", "snapshot":pinned_snapshot, "limit":1}),
                None,
            ),
            (
                "graph_dependents_list",
                json!({"contract_version":"depgraph-mcp-tools-v1", "repository_id":"repository", "selector":"node:root", "snapshot":pinned_snapshot, "limit":1}),
                Some(false),
            ),
            (
                "graph_export",
                json!({"contract_version":"depgraph-mcp-tools-v1", "repository_id":"repository", "format":"json", "snapshot":pinned_snapshot}),
                None,
            ),
            (
                "graph_impact_get",
                json!({"contract_version":"depgraph-mcp-tools-v1", "repository_id":"repository", "selector":"node:root", "snapshot":pinned_snapshot, "limit":1}),
                None,
            ),
            (
                "graph_path_get",
                json!({"contract_version":"depgraph-mcp-tools-v1", "repository_id":"repository", "from":"node:dependent-a", "to":"node:root", "snapshot":pinned_snapshot}),
                Some(false),
            ),
            (
                "graph_query",
                json!({"contract_version":"depgraph-mcp-tools-v1", "repository_id":"repository"}),
                None,
            ),
            (
                "graph_unresolved_list",
                json!({"contract_version":"depgraph-mcp-tools-v1", "repository_id":"repository", "snapshot":pinned_snapshot, "limit":1}),
                None,
            ),
            (
                "operation_cancel",
                json!({"contract_version":"depgraph-mcp-tools-v1", "repository_id":"repository", "operation_id":"op_00000000000000000000000000000000"}),
                None,
            ),
            (
                "operation_get",
                json!({"contract_version":"depgraph-mcp-tools-v1", "repository_id":"repository", "operation_id":"op_00000000000000000000000000000000"}),
                None,
            ),
            (
                "operation_result",
                json!({"contract_version":"depgraph-mcp-tools-v1", "repository_id":"repository", "operation_id":"op_00000000000000000000000000000000"}),
                None,
            ),
            (
                "policy_evaluate",
                json!({"contract_version":"depgraph-mcp-tools-v1", "repository_id":"repository", "from":pinned_snapshot, "to":pinned_snapshot}),
                None,
            ),
            (
                "profile_plan_get",
                json!({"contract_version":"depgraph-mcp-tools-v1", "repository_id":"repository"}),
                None,
            ),
            (
                "runtime_trace_validate",
                json!({"contract_version":"depgraph-mcp-tools-v1", "repository_id":"repository"}),
                None,
            ),
            (
                "snapshot_diff_get",
                json!({"contract_version":"depgraph-mcp-tools-v1", "repository_id":"repository", "from":pinned_snapshot, "to":pinned_snapshot}),
                None,
            ),
            (
                "snapshot_get",
                json!({"contract_version":"depgraph-mcp-tools-v1", "repository_id":"repository", "snapshot":pinned_snapshot}),
                None,
            ),
            (
                "snapshot_list",
                json!({"contract_version":"depgraph-mcp-tools-v1", "repository_id":"repository", "limit":1}),
                None,
            ),
        ];
        let advertised_names = tools
            .iter()
            .map(|tool| tool["name"].as_str().unwrap())
            .collect::<Vec<_>>();
        let called_names = read_only_calls
            .iter()
            .map(|(tool_name, _, _)| *tool_name)
            .collect::<Vec<_>>();
        assert_eq!(called_names, advertised_names, "{protocol_version}");
        for (offset, (tool_name, arguments, expected_error)) in
            read_only_calls.into_iter().enumerate()
        {
            let response =
                interactive_tool_call(&mut mcp, 100 + offset as u64, tool_name, arguments);
            assert!(response["isError"].is_boolean(), "{tool_name}: {response}");
            if let Some(expected_error) = expected_error {
                assert_eq!(
                    response["isError"], expected_error,
                    "{protocol_version} {tool_name}: {response}"
                );
            }
            if matches!(
                tool_name,
                "agent_edges_list"
                    | "graph_dependents_list"
                    | "graph_impact_get"
                    | "graph_path_get"
            ) {
                let expected_condition =
                    depgraph_core::query::render_condition(&issue_306_long_condition());
                assert!(
                    expected_condition.len() > depgraph_mcp_tools::MAX_AGENT_LABEL_BYTES,
                    "fixture must cover the former label boundary"
                );
                let projected_condition = match tool_name {
                    "agent_edges_list" => {
                        &response["structuredContent"]["result"]["items"][0]["condition"]
                    }
                    "graph_dependents_list" => {
                        &response["structuredContent"]["result"]["edges"]["items"][0]["condition"]
                    }
                    "graph_impact_get" => {
                        response["structuredContent"]["result"]["impacts"]["items"]
                            .as_array()
                            .into_iter()
                            .flatten()
                            .flat_map(|impact| {
                                impact["dependency_path"].as_array().into_iter().flatten()
                            })
                            .map(|step| &step["edge"]["condition"])
                            .next()
                            .expect("impact fixture contains the conditional dependency edge")
                    }
                    "graph_path_get" => {
                        &response["structuredContent"]["result"]["steps"][0]["edge"]["condition"]
                    }
                    _ => unreachable!(),
                };
                assert_eq!(
                    projected_condition.as_str(),
                    Some(expected_condition.as_str()),
                    "{protocol_version} {tool_name}: long conditional edge metadata must be preserved"
                );
            }
            assert_tool_text_matches_structured(&response);
            let schema =
                tools.iter().find(|tool| tool["name"] == tool_name).unwrap()["outputSchema"]
                    .clone();
            jsonschema::draft202012::new(&schema)
                .unwrap()
                .validate(&response["structuredContent"])
                .unwrap_or_else(|validation| {
                    panic!("{protocol_version} {tool_name} schema: {validation}")
                });
        }
        let invalid_sites = interactive_tool_call(
            &mut mcp,
            29,
            "agent_sites_list",
            json!({"contract_version":"depgraph-mcp-tools-v1", "repository_id":"repository", "node_id":"not an agent id", "limit":1}),
        );
        assert_eq!(invalid_sites["isError"], true, "{invalid_sites}");
        assert_eq!(
            invalid_sites["structuredContent"]["error"]["code"],
            "INVALID_ARGUMENT"
        );
        assert_tool_text_matches_structured(&invalid_sites);
        let node = interactive_tool_call(
            &mut mcp,
            30,
            "agent_node_get",
            json!({"contract_version":"depgraph-mcp-tools-v1", "repository_id":"repository", "node_id":"node:missing"}),
        );
        assert_eq!(node["isError"], true);
        assert_eq!(node["structuredContent"]["error"]["code"], "NOT_FOUND");
        let zero_sites = interactive_tool_call(
            &mut mcp,
            31,
            "agent_sites_list",
            json!({"contract_version":"depgraph-mcp-tools-v1", "repository_id":"repository", "node_id":"node:root", "limit":1}),
        );
        assert_eq!(zero_sites["isError"], false, "{zero_sites}");
        assert_eq!(
            zero_sites["structuredContent"]["result"]["items"],
            json!([])
        );
        let missing_evidence = interactive_tool_call(
            &mut mcp,
            32,
            "agent_evidence_list",
            json!({"contract_version":"depgraph-mcp-tools-v1", "repository_id":"repository", "site_id":"site:absent", "limit":1}),
        );
        assert_eq!(missing_evidence["isError"], true, "{missing_evidence}");
        assert_eq!(
            missing_evidence["structuredContent"]["error"]["code"],
            "NOT_FOUND"
        );
        let error = interactive_tool_call(
            &mut mcp,
            5,
            "snapshot_get",
            json!({
                "contract_version": "depgraph-mcp-tools-v1",
                "repository_id": "repository",
                "snapshot": "does-not-exist"
            }),
        );
        assert_eq!(error["isError"], true, "{protocol_version}: {error}");
        assert_eq!(
            error["structuredContent"]["error"]["code"], "NOT_FOUND",
            "{protocol_version}: {error}"
        );
        assert_tool_text_matches_structured(&error);
        for tool in &tools {
            let tool_name = tool["name"].as_str().unwrap();
            jsonschema::draft202012::new(&tool["outputSchema"])
                .unwrap_or_else(|validation| {
                    panic!("{protocol_version} {tool_name} schema compile: {validation}")
                })
                .validate(&error["structuredContent"])
                .unwrap_or_else(|validation| {
                    panic!("{protocol_version} {tool_name} error schema: {validation}")
                });
        }
        shared
            .validate(&error["structuredContent"])
            .unwrap_or_else(|validation| {
                panic!("{protocol_version} shared error schema: {validation}")
            });
        catalogs.push(Value::Array(tools));
        mcp.finish();
    }

    assert_eq!(catalogs[0].to_string(), catalogs[1].to_string());
    assert_eq!(store_before, store_invariant(&store_path));
    assert_eq!(source_before, source_tree_digest(&root));
}

#[test]
fn issue_306_oversized_conditions_fail_closed_with_exact_limit_across_protocol_revisions() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("repository");
    let store_path = temporary.path().join("store.sqlite");
    fs::create_dir(&root).unwrap();
    seed_issue_300_store(&store_path, &root);
    let pinned_snapshot = seed_issue_303_store(&store_path, &root, "revision-306-oversized");
    let store_before = store_invariant(&store_path);
    let source_before = source_tree_digest(&root);

    for protocol_version in ["2025-11-25", "2026-07-28"] {
        let mut mcp = InteractiveMcp::start(&root, &store_path);
        let initialized = mcp.request(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": protocol_version,
                "capabilities": {},
                "clientInfo": {"name": "issue-306-oversized-test", "version": "1"}
            }
        }));
        assert_eq!(initialized["result"]["protocolVersion"], protocol_version);
        let listed = mcp.request(json!({
            "jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}
        }));
        let tools = listed["result"]["tools"].as_array().unwrap();

        for (offset, (tool_name, arguments)) in [
            (
                "agent_edges_list",
                json!({"contract_version":"depgraph-mcp-tools-v1", "repository_id":"repository", "node_id":"node:oversized-source", "snapshot":pinned_snapshot, "limit":1}),
            ),
            (
                "graph_dependents_list",
                json!({"contract_version":"depgraph-mcp-tools-v1", "repository_id":"repository", "selector":"node:oversized-target", "snapshot":pinned_snapshot, "limit":1}),
            ),
            (
                "graph_impact_get",
                json!({"contract_version":"depgraph-mcp-tools-v1", "repository_id":"repository", "selector":"node:oversized-target", "snapshot":pinned_snapshot, "limit":1}),
            ),
            (
                "graph_path_get",
                json!({"contract_version":"depgraph-mcp-tools-v1", "repository_id":"repository", "from":"node:oversized-source", "to":"node:oversized-target", "snapshot":pinned_snapshot}),
            ),
        ]
        .into_iter()
        .enumerate()
        {
            let response =
                interactive_tool_call(&mut mcp, 10 + offset as u64, tool_name, arguments);
            assert_eq!(
                response["isError"], true,
                "{protocol_version} {tool_name}: {response}"
            );
            assert_eq!(
                response["structuredContent"]["error"]["code"],
                "RESOURCE_EXHAUSTED"
            );
            assert_eq!(
                response["structuredContent"]["error"]["details"],
                json!({
                    "kind": "resource_limit",
                    "limit": "output_bytes",
                    "maximum": 64 * 1024
                }),
                "{protocol_version} {tool_name}: {response}"
            );
            assert_tool_text_matches_structured(&response);
            let schema = tools
                .iter()
                .find(|tool| tool["name"] == tool_name)
                .unwrap()["outputSchema"]
                .clone();
            jsonschema::draft202012::new(&schema)
                .unwrap()
                .validate(&response["structuredContent"])
                .unwrap_or_else(|validation| {
                    panic!("{protocol_version} {tool_name} oversized schema: {validation}")
                });
        }
        mcp.finish();
    }

    assert_eq!(store_before, store_invariant(&store_path));
    assert_eq!(source_before, source_tree_digest(&root));
}

#[test]
fn issue_306_agent_list_pages_are_stable_and_reject_current_cursor_after_advance() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("repository");
    let store_path = temporary.path().join("store.sqlite");
    fs::create_dir(&root).unwrap();
    let pinned_snapshot = seed_issue_303_store(&store_path, &root, "revision-306-pages");
    let common = json!({
        "contract_version": "depgraph-mcp-tools-v1",
        "repository_id": "repository",
        "limit": 1
    });
    let mut mcp = InteractiveMcp::start(&root, &store_path);
    assert_eq!(
        mcp.request(json!({"jsonrpc":"2.0", "id":1, "method":"initialize", "params": {
            "protocolVersion":"2026-07-28", "capabilities":{}, "clientInfo":{"name":"issue-306-pages", "version":"1"}
        }}))["id"],
        1
    );
    let requests = [
        (
            "agent_sites_list",
            json!({}),
            json!({"node_id":"node:root"}),
            3,
        ),
        (
            "agent_edges_list",
            json!({"node_id":"node:dependent-b"}),
            json!({"node_id":"node:dependent-b", "direction":"incoming"}),
            4,
        ),
        (
            "agent_evidence_list",
            json!({"site_id":"site:missing"}),
            json!({"site_id":"site:omega"}),
            3,
        ),
    ];
    let mut cursors = Vec::new();
    let mut first_pages = Vec::new();
    for (offset, (tool, extra, _, total_items)) in requests.iter().enumerate() {
        let mut arguments = common.clone();
        arguments["snapshot"] = json!(pinned_snapshot);
        arguments
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        let first = interactive_tool_call(&mut mcp, 2 + offset as u64, tool, arguments.clone());
        assert_eq!(first["isError"], false, "{tool}: {first}");
        assert_tool_text_matches_structured(&first);
        assert_eq!(
            first["structuredContent"]["result"]["total_items"], *total_items,
            "{tool}"
        );
        assert_eq!(
            first["structuredContent"]["result"]["items"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        let repeated = interactive_tool_call(&mut mcp, 10 + offset as u64, tool, arguments);
        assert_eq!(
            repeated["structuredContent"], first["structuredContent"],
            "{tool}"
        );
        cursors.push(first["structuredContent"]["result"]["next_cursor"].clone());
        first_pages.push(first);
    }

    let advanced_snapshot = seed_issue_302_store(&store_path, &root);
    assert_ne!(advanced_snapshot, pinned_snapshot);
    for (offset, ((tool, extra, changed_filter, total_items), cursor)) in
        requests.iter().zip(&cursors).enumerate()
    {
        let mut ids = first_pages[offset]["structuredContent"]["result"]["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(Value::to_string)
            .collect::<Vec<_>>();
        let mut next_cursor = cursor.clone();
        let mut page_index = 0_u64;
        while !next_cursor.is_null() {
            let mut pinned = common.clone();
            pinned["snapshot"] = json!(pinned_snapshot);
            pinned["cursor"] = next_cursor;
            pinned
                .as_object_mut()
                .unwrap()
                .extend(extra.as_object().unwrap().clone());
            let continued = interactive_tool_call(
                &mut mcp,
                100 + offset as u64 * 10 + page_index,
                tool,
                pinned,
            );
            assert_eq!(continued["isError"], false, "pinned {tool}: {continued}");
            ids.extend(
                continued["structuredContent"]["result"]["items"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(Value::to_string),
            );
            next_cursor = continued["structuredContent"]["result"]["next_cursor"].clone();
            page_index += 1;
        }
        assert_eq!(ids.len(), *total_items as usize, "{tool}");
        let mut sorted_ids = ids.clone();
        sorted_ids.sort();
        assert_eq!(ids, sorted_ids, "{tool} ordering");

        let mut changed = common.clone();
        changed["snapshot"] = json!(pinned_snapshot);
        changed["cursor"] = cursor.clone();
        changed
            .as_object_mut()
            .unwrap()
            .extend(changed_filter.as_object().unwrap().clone());
        let filter_mismatch = interactive_tool_call(&mut mcp, 200 + offset as u64, tool, changed);
        assert_eq!(
            filter_mismatch["isError"], true,
            "filter {tool}: {filter_mismatch}"
        );
        assert_eq!(
            filter_mismatch["structuredContent"]["error"]["code"], "CURSOR_MISMATCH",
            "filter {tool}"
        );

        let mut current = common.clone();
        current["snapshot"] = json!("current");
        current["cursor"] = cursor.clone();
        current
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        let mismatched = interactive_tool_call(&mut mcp, 30 + offset as u64, tool, current);
        assert_eq!(mismatched["isError"], true, "current {tool}: {mismatched}");
        assert_eq!(
            mismatched["structuredContent"]["error"]["code"], "CURSOR_MISMATCH",
            "current {tool}"
        );
    }
    mcp.finish();
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
