#![cfg(unix)]

use depgraph_protocol::{ProtocolEvent, validate_ndjson};
use std::{
    fs,
    io::Cursor,
    os::unix::fs::{PermissionsExt, symlink},
    path::{Path, PathBuf},
    process::{Command, Output},
};

const RUSTC_SCRIPT: &str = r#"#!/bin/sh
set -eu
if [ "${1-}" = "--version" ]; then
  printf '%s\n' \
    'rustc 1.93.1 (01f6ddf75 2026-04-14)' \
    'binary: rustc' \
    'commit-hash: 01f6ddf7588f42ae2d7eb0a2f21d44e8e96674cf' \
    'commit-date: 2026-04-14' \
    'host: x86_64-unknown-linux-gnu' \
    'release: 1.93.1' \
    'LLVM version: 22.1.0'
  exit 0
fi
exit 64
"#;

const REJECTING_CARGO_SCRIPT: &str = r#"#!/bin/sh
set -eu
case "${1-}" in
  --version)
    printf '%s\n' \
      'cargo 1.93.1 (083ac5135 2026-04-14)' \
      'release: 1.93.1' \
      'commit-hash: 083ac5135f967fd9dc906ab057a2315861c7a80d' \
      'commit-date: 2026-04-14' \
      'host: x86_64-unknown-linux-gnu'
    exit 0
    ;;
  metadata)
    : > "${0%/*}/cargo-metadata-invoked"
    exit 65
    ;;
esac
exit 64
"#;

const SUCCESSFUL_CARGO_SCRIPT: &str = r#"#!/bin/sh
set -eu
case "${1-}" in
  --version)
    printf '%s\n' \
      'cargo 1.93.1 (083ac5135 2026-04-14)' \
      'release: 1.93.1' \
      'commit-hash: 083ac5135f967fd9dc906ab057a2315861c7a80d' \
      'commit-date: 2026-04-14' \
      'host: x86_64-unknown-linux-gnu'
    exit 0
    ;;
  metadata)
    shift
    manifest=''
    while [ "$#" -gt 0 ]; do
      if [ "$1" = '--manifest-path' ]; then
        manifest=$2
        shift 2
      else
        shift
      fi
    done
    if [ -z "$manifest" ]; then
      exit 66
    fi
    printf '%s\n' "$manifest" > "${0%/*}/received-manifest-path"
    printf '%s\n' "$PWD" > "${0%/*}/received-cargo-cwd"
    root=${manifest%/*}
    package_id="path+file://$root#safe-package@0.1.0"
    printf '%s\n' "{\"packages\":[{\"id\":\"$package_id\",\"name\":\"safe-package\",\"version\":\"0.1.0\",\"edition\":\"2024\",\"manifest_path\":\"$manifest\",\"features\":{},\"dependencies\":[],\"targets\":[{\"name\":\"safe_package\",\"kind\":[\"lib\"],\"crate_types\":[\"lib\"],\"src_path\":\"$root/src/lib.rs\"}]}],\"workspace_members\":[\"$package_id\"],\"workspace_default_members\":[\"$package_id\"],\"resolve\":null,\"target_directory\":\"$root/target\",\"version\":1,\"workspace_root\":\"$root\",\"metadata\":null}"
    exit 0
    ;;
esac
exit 64
"#;

struct Harness {
    _temp: tempfile::TempDir,
    root: PathBuf,
    outside: PathBuf,
    bin: PathBuf,
}

impl Harness {
    fn rejecting() -> Self {
        Self::new(REJECTING_CARGO_SCRIPT)
    }

    fn successful() -> Self {
        Self::new(SUCCESSFUL_CARGO_SCRIPT)
    }

    fn new(cargo_script: &str) -> Self {
        let temp = tempfile::tempdir().expect("temporary test directory");
        let root = temp.path().join("repository");
        let outside = temp.path().join("outside");
        let bin = temp.path().join("fake-bin");
        fs::create_dir_all(root.join("src")).expect("repository source directory");
        fs::create_dir_all(outside.join("src")).expect("outside source directory");
        fs::create_dir_all(&bin).expect("fake tool directory");
        write_executable(&bin.join("rustc"), RUSTC_SCRIPT);
        write_executable(&bin.join("cargo"), cargo_script);
        fs::write(root.join("src/main.rs"), "fn main() {}\n").expect("root binary source");
        fs::write(root.join("src/lib.rs"), "pub struct Local;\n").expect("root library source");
        fs::write(
            outside.join("Cargo.toml"),
            "[package]\nname='outside-secret'\nversion='9.9.9'\nedition='2024'\n",
        )
        .expect("outside manifest");
        fs::write(
            outside.join("src/lib.rs"),
            "pub const OUTSIDE_SECRET: &str = \"must-not-be-read\";\n",
        )
        .expect("outside source");
        fs::write(
            outside.join("secret.rs"),
            "pub const UNKNOWN_PATH_SECRET: &str = \"must-not-be-read\";\n",
        )
        .expect("unknown-key outside source");
        Self {
            _temp: temp,
            root,
            outside,
            bin,
        }
    }

    fn write_root(&self, manifest: &str) {
        fs::write(self.root.join("Cargo.toml"), manifest).expect("root manifest");
        fs::write(
            self.root.join("Cargo.lock"),
            "version = 4\n\n[[package]]\nname = 'root-package'\nversion = '0.1.0'\n",
        )
        .expect("root lockfile");
    }

    fn write_safe_root(&self) {
        fs::write(
            self.root.join("Cargo.toml"),
            "[package]\nname='safe-package'\nversion='0.1.0'\nedition='2024'\n",
        )
        .expect("safe root manifest");
        fs::write(
            self.root.join("Cargo.lock"),
            "version = 4\n\n[[package]]\nname = 'safe-package'\nversion = '0.1.0'\n",
        )
        .expect("safe root lockfile");
    }

    fn metadata_marker(&self) -> PathBuf {
        self.bin.join("cargo-metadata-invoked")
    }

    fn run(&self, scan_id: &str) -> Output {
        Command::new(env!("CARGO_BIN_EXE_depgraph-rust-worker"))
            .arg("--root")
            .arg(&self.root)
            .arg("--scan-id")
            .arg(scan_id)
            .env_clear()
            .env("PATH", &self.bin)
            .env("LC_ALL", "C")
            .output()
            .expect("run Rust worker")
    }
}

#[test]
fn external_workspace_member_is_rejected_before_cargo_metadata() {
    let harness = Harness::rejecting();
    harness.write_root(
        r#"[package]
name = "root-package"
version = "0.1.0"
edition = "2024"

[workspace]
members = ["../outside"]
resolver = "3"
"#,
    );

    assert_preflight_rejection(&harness, "outside-workspace-member");
}

#[test]
fn external_path_dependency_is_rejected_before_cargo_metadata() {
    let harness = Harness::rejecting();
    harness.write_root(
        r#"[package]
name = "root-package"
version = "0.1.0"
edition = "2024"

[dependencies]
outside-secret = { path = "../outside" }
"#,
    );

    assert_preflight_rejection(&harness, "outside-path-dependency");
}

#[test]
fn symlinked_workspace_member_is_rejected_before_cargo_metadata() {
    let harness = Harness::rejecting();
    symlink(&harness.outside, harness.root.join("linked-member"))
        .expect("workspace member symlink");
    harness.write_root(
        r#"[package]
name = "root-package"
version = "0.1.0"
edition = "2024"

[workspace]
members = ["linked-member"]
resolver = "3"
"#,
    );

    assert_preflight_rejection(&harness, "symlinked-workspace-member");
}

#[test]
fn symlinked_target_is_rejected_before_cargo_metadata() {
    let harness = Harness::rejecting();
    let outside_source = harness.outside.join("outside-target.rs");
    fs::write(
        &outside_source,
        "pub const OUTSIDE_TARGET: &str = \"must-not-be-read\";\n",
    )
    .expect("outside target source");
    symlink(&outside_source, harness.root.join("src/linked.rs")).expect("target symlink");
    harness.write_root(
        r#"[package]
name = "root-package"
version = "0.1.0"
edition = "2024"

[lib]
path = "src/linked.rs"
"#,
    );

    assert_preflight_rejection(&harness, "symlinked-target");
}

#[test]
fn unknown_path_bearing_cargo_key_is_rejected_before_cargo_metadata() {
    let harness = Harness::rejecting();
    harness.write_root(
        r#"[package]
name = "root-package"
version = "0.1.0"
edition = "2024"
future-path = "../outside/secret.rs"
"#,
    );

    assert_preflight_rejection(&harness, "unknown-path-key");
}

#[test]
fn glob_patch_replace_absolute_and_local_sources_are_rejected_before_metadata() {
    let cases = [
        (
            "workspace-glob",
            r#"[package]
name = "root-package"
version = "0.1.0"
edition = "2024"

[workspace]
members = ["crates/*"]
"#
            .to_owned(),
        ),
        (
            "external-patch",
            r#"[package]
name = "root-package"
version = "0.1.0"
edition = "2024"

[patch.crates-io]
outside = { path = "../outside" }
"#
            .to_owned(),
        ),
        (
            "external-replace",
            r#"[package]
name = "root-package"
version = "0.1.0"
edition = "2024"

[replace]
"outside:1.0.0" = { path = "../outside" }
"#
            .to_owned(),
        ),
        (
            "local-git-source",
            r#"[package]
name = "root-package"
version = "0.1.0"
edition = "2024"

[dependencies]
outside = { git = "file:///outside/repository" }
"#
            .to_owned(),
        ),
        (
            "legacy-project-path",
            r#"[package]
name = "root-package"
version = "0.1.0"
edition = "2024"

[project]
workspace = "../outside"
"#
            .to_owned(),
        ),
        (
            "custom-default-target",
            r#"[package]
name = "root-package"
version = "0.1.0"
edition = "2024"
default-target = "../outside/custom-target.json"
"#
            .to_owned(),
        ),
        (
            "custom-forced-target",
            r#"[package]
name = "root-package"
version = "0.1.0"
edition = "2024"
forced-target = "../outside/custom-target.json"
"#
            .to_owned(),
        ),
        (
            "windows-drive-relative-target",
            r#"[package]
name = "root-package"
version = "0.1.0"
edition = "2024"

[lib]
path = "C:drive-relative.rs"
"#
            .to_owned(),
        ),
    ];
    for (scan_id, manifest) in cases {
        let harness = Harness::rejecting();
        harness.write_root(&manifest);
        assert_preflight_rejection(&harness, scan_id);
    }

    let harness = Harness::rejecting();
    harness.write_root(&format!(
        "[package]\nname = \"root-package\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\n[lib]\npath = {:?}\n",
        harness.outside.join("outside-target.rs")
    ));
    assert_preflight_rejection(&harness, "external-absolute-target");
}

#[test]
fn failed_ancestor_manifests_block_nested_cargo_metadata() {
    for kind in ["malformed", "symlinked", "nonregular"] {
        let harness = Harness::rejecting();
        fs::create_dir_all(harness.root.join("nested/src")).expect("nested source directory");
        fs::write(
            harness.root.join("nested/Cargo.toml"),
            "[package]\nname='nested-package'\nversion='0.1.0'\nedition='2024'\n",
        )
        .expect("nested manifest");
        fs::write(
            harness.root.join("nested/src/lib.rs"),
            "pub struct Nested;\n",
        )
        .expect("nested source");
        match kind {
            "symlinked" => symlink(
                harness.outside.join("Cargo.toml"),
                harness.root.join("Cargo.toml"),
            )
            .expect("ancestor manifest symlink"),
            "nonregular" => fs::create_dir(harness.root.join("Cargo.toml"))
                .expect("nonregular ancestor manifest"),
            _ => fs::write(harness.root.join("Cargo.toml"), "[workspace\n")
                .expect("malformed ancestor manifest"),
        }

        let output = harness.run(&format!("{kind}-ancestor-manifest"));
        assert!(
            output.status.success(),
            "worker failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!harness.metadata_marker().exists());
        let validated = validate_ndjson(Cursor::new(output.stdout)).expect("valid fallback output");
        assert!(
            validated
                .diagnostics
                .values()
                .any(|diagnostic| diagnostic.code == "CARGO_METADATA_FALLBACK")
        );
        assert!(validated.nodes.values().any(|node| {
            node.kind == "package_instance"
                && node.display_name.as_deref() == Some("nested-package")
                && node.properties["cargo_model"] == "static-fallback"
        }));
    }
}

#[test]
fn safe_metadata_uses_a_mirror_and_reverse_maps_cargo_paths() {
    let harness = Harness::successful();
    harness.write_safe_root();

    let output = harness.run("safe-cargo-mirror");
    assert!(
        output.status.success(),
        "worker failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let received = fs::read_to_string(harness.bin.join("received-manifest-path"))
        .expect("fake Cargo received a manifest path");
    let received = PathBuf::from(received.trim());
    assert!(received.is_absolute());
    assert_eq!(
        received.file_name(),
        Some(std::ffi::OsStr::new("Cargo.toml"))
    );
    assert!(
        !received.starts_with(&harness.root),
        "Cargo received the original repository manifest: {}",
        received.display()
    );
    let cargo_cwd = fs::read_to_string(harness.bin.join("received-cargo-cwd"))
        .expect("fake Cargo working directory");
    assert_eq!(Path::new(cargo_cwd.trim()).parent(), None);

    let mirror_root = received.parent().expect("mirror manifest parent");
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 worker output");
    assert!(
        !stdout.contains(&mirror_root.to_string_lossy().to_string()),
        "temporary mirror path leaked into protocol output"
    );
    let validated = validate_ndjson(Cursor::new(stdout.as_bytes())).expect("valid worker NDJSON");
    assert!(
        validated
            .diagnostics
            .values()
            .any(|diagnostic| diagnostic.code == "CARGO_METADATA_FROZEN")
    );
    assert!(!validated.diagnostics.values().any(|diagnostic| {
        matches!(
            diagnostic.code.as_str(),
            "CARGO_METADATA_FALLBACK" | "RUST_HIR_CRATE_GRAPH_UNAVAILABLE"
        )
    }));
    assert!(validated.nodes.values().any(|node| {
        node.kind == "package_instance"
            && node.display_name.as_deref() == Some("safe-package")
            && node.properties["cargo_model"] == "metadata"
    }));
    assert!(
        validated.nodes.values().any(|node| {
            node.kind == "build_unit" && node.properties["src_path"] == "src/lib.rs"
        })
    );
    assert!(validated.events.iter().any(|event| matches!(
        event,
        ProtocolEvent::ScanCompleted(completed) if !completed.coverage.project_code_executed
    )));
}

#[test]
fn different_mirror_directories_produce_identical_protocol_output() {
    let harness = Harness::successful();
    harness.write_safe_root();

    let first = harness.run("mirror-determinism");
    assert!(first.status.success());
    let first_manifest = fs::read_to_string(harness.bin.join("received-manifest-path"))
        .expect("first mirror manifest");
    let second = harness.run("mirror-determinism");
    assert!(second.status.success());
    let second_manifest = fs::read_to_string(harness.bin.join("received-manifest-path"))
        .expect("second mirror manifest");

    assert_ne!(first_manifest, second_manifest);
    assert_eq!(first.stdout, second.stdout);
    assert_eq!(first.stderr, second.stderr);
}

fn assert_preflight_rejection(harness: &Harness, scan_id: &str) {
    let output = harness.run(scan_id);
    assert!(
        output.status.success(),
        "worker failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !harness.metadata_marker().exists(),
        "cargo metadata was invoked despite a rejected preflight"
    );

    let stdout = String::from_utf8(output.stdout).expect("UTF-8 worker output");
    assert!(!stdout.contains("must-not-be-read"));
    assert!(!stdout.contains(&harness.outside.to_string_lossy().to_string()));
    let validated = validate_ndjson(Cursor::new(stdout.as_bytes())).expect("valid worker NDJSON");

    for code in [
        "CARGO_METADATA_FALLBACK",
        "RUST_HIR_CRATE_GRAPH_UNAVAILABLE",
    ] {
        assert!(
            validated
                .diagnostics
                .values()
                .any(|diagnostic| diagnostic.code == code),
            "missing diagnostic {code}"
        );
    }
    assert!(validated.nodes.values().any(|node| {
        node.kind == "package_instance"
            && node.display_name.as_deref() == Some("root-package")
            && node.properties["cargo_model"] == "static-fallback"
    }));
    assert!(
        validated
            .nodes
            .values()
            .any(|node| { node.kind == "file" && node.locator == "file:src/main.rs" })
    );

    for expected in ["Cargo.toml", "src/main.rs"] {
        assert!(
            validated.events.iter().any(|event| matches!(
                event,
                ProtocolEvent::FileCompleted(file) if file.path == expected
            )),
            "missing file inventory for {expected}"
        );
    }

    let completed = validated
        .events
        .iter()
        .find_map(|event| match event {
            ProtocolEvent::ScanCompleted(completed) => Some(completed),
            _ => None,
        })
        .expect("scan completed event");
    assert!(!completed.coverage.project_code_executed);
    for reason in [
        "cargo-metadata-fallback",
        "rust-hir-crate-graph-unavailable",
    ] {
        assert!(
            completed
                .coverage
                .reasons
                .iter()
                .any(|candidate| candidate == reason),
            "missing coverage reason {reason}"
        );
    }
    assert!(validated.events.iter().any(|event| matches!(
        event,
        ProtocolEvent::ScanStarted(started) if !started.project_code_executed && started.safe_mode
    )));
}

fn write_executable(path: &Path, source: &str) {
    fs::write(path, source).expect("write fake tool");
    let mut permissions = fs::metadata(path)
        .expect("fake tool metadata")
        .permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions).expect("make fake tool executable");
}
