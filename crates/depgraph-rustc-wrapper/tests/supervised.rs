#![cfg(unix)]

use std::{collections::BTreeMap, fs, path::Path, process::Command};

use anyhow::{Context, Result};
use depgraph_core::{
    BuildOutcomeKind, COMPILER_INVOCATION_RECORD_SCHEMA, CompilerPackBuildComponent,
    CompilerPackBuildSpec, CompilerPackRequirement, RustCargoProfile, RustCargoStrip,
    RustCargoTarget, RustCargoUnit, RustCargoUnitGraph, build_compiler_pack,
    create_compiler_precise_invocation_request, create_compiler_precise_unit_graph_request,
    execute_build_request,
};
use sha2::{Digest, Sha256};

#[tokio::test]
async fn wrapper_conserves_target_build_script_and_proc_macro_units() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let project = temporary.path().join("project");
    fs::create_dir_all(project.join("src"))?;
    fs::write(
        project.join("Cargo.toml"),
        "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\nedition = \"2024\"\nbuild = \"build.rs\"\n\n[workspace]\n",
    )?;
    fs::write(project.join("Cargo.lock"), "version = 4\n")?;
    fs::write(project.join("src/lib.rs"), "pub fn fixture() {}\n")?;
    fs::write(project.join("build.rs"), "fn main() {}\n")?;
    fs::write(project.join("proc.rs"), "extern crate proc_macro;\n")?;

    let cargo_script = r#"#!/bin/sh
if [ "$1" = "--version" ]; then
  printf 'cargo 1.99.0-nightly\n'
  exit 0
fi
workspace=$(pwd)
if [ "$*" = "build --frozen --offline --unit-graph -Z unstable-options --target x86_64-unknown-linux-gnu" ]; then
  printf '{"version":1,"units":[{"pkg_id":"path+file://%s#0.1.0","target":{"kind":["lib"],"crate_types":["lib"],"name":"fixture","src_path":"%s/src/lib.rs","edition":"2024","doc":true,"doctest":true,"test":true},"profile":{"name":"dev","opt_level":"0","lto":"false","codegen_units":null,"debuginfo":2,"split_debuginfo":null,"debug_assertions":true,"overflow_checks":true,"rpath":false,"incremental":false,"panic":"unwind","strip":{"deferred":"None"},"codegen_backend":null},"platform":"x86_64-unknown-linux-gnu","mode":"build","features":[],"dependencies":[{"index":2,"extern_crate_name":"build_script"},{"index":3,"extern_crate_name":"fixture_macro"}]},{"pkg_id":"path+file://%s#0.1.0","target":{"kind":["custom-build"],"crate_types":["bin"],"name":"build-script-build","src_path":"%s/build.rs","edition":"2024","doc":false,"doctest":false,"test":false},"profile":{"name":"dev","opt_level":"0","lto":"false","codegen_units":null,"debuginfo":2,"split_debuginfo":null,"debug_assertions":true,"overflow_checks":true,"rpath":false,"incremental":false,"panic":"unwind","strip":{"deferred":"None"},"codegen_backend":null},"platform":null,"mode":"build","features":[],"dependencies":[]},{"pkg_id":"path+file://%s#0.1.0","target":{"kind":["custom-build"],"crate_types":["bin"],"name":"build-script-build","src_path":"%s/build.rs","edition":"2024","doc":false,"doctest":false,"test":false},"profile":{"name":"dev","opt_level":"0","lto":"false","codegen_units":null,"debuginfo":2,"split_debuginfo":null,"debug_assertions":true,"overflow_checks":true,"rpath":false,"incremental":false,"panic":"unwind","strip":{"deferred":"None"},"codegen_backend":null},"platform":"x86_64-unknown-linux-gnu","mode":"run-custom-build","features":[],"dependencies":[{"index":1,"extern_crate_name":"build_script_build"}]},{"pkg_id":"path+file://%s#0.1.0","target":{"kind":["proc-macro"],"crate_types":["proc-macro"],"name":"fixture-macro","src_path":"%s/proc.rs","edition":"2024","doc":true,"doctest":false,"test":true},"profile":{"name":"dev","opt_level":"0","lto":"false","codegen_units":null,"debuginfo":2,"split_debuginfo":null,"debug_assertions":true,"overflow_checks":true,"rpath":false,"incremental":false,"panic":"unwind","strip":{"deferred":"None"},"codegen_backend":null},"platform":null,"mode":"build","features":[],"dependencies":[]}],"roots":[0]}\n' "$workspace" "$workspace" "$workspace" "$workspace" "$workspace" "$workspace" "$workspace" "$workspace"
  exit 0
fi
if [ "$*" != "build --frozen --offline --target x86_64-unknown-linux-gnu" ]; then
  exit 91
fi
"$RUSTC_WRAPPER" "$RUSTC" --crate-name fixture --crate-type lib --edition 2024 --target x86_64-unknown-linux-gnu src/lib.rs || exit $?
"$RUSTC_WRAPPER" "$RUSTC" --crate-name build_script_build --crate-type bin --edition 2024 build.rs || exit $?
"$RUSTC_WRAPPER" "$RUSTC" --crate-name fixture_macro --crate-type proc-macro --edition 2024 proc.rs || exit $?
"#;
    let rustc_script = r#"#!/bin/sh
if [ "$1" = "-vV" ]; then
  printf 'rustc 1.99.0-nightly\nbinary: rustc\ncommit-hash: 3d50c25bc66853bf0ad205529d0f305a1d841b5e\nhost: x86_64-unknown-linux-gnu\nrelease: 1.99.0-nightly\n'
  exit 0
fi
exit 0
"#;
    let requirement = compiler_pack_fixture(
        temporary.path(),
        cargo_script,
        rustc_script,
        Path::new(env!("CARGO_BIN_EXE_depgraph-rustc-wrapper")),
    )?;

    let unit_request = create_compiler_precise_unit_graph_request(&project, requirement.clone())?;
    let unit_outcome = execute_build_request(&unit_request).await?;
    assert_eq!(unit_outcome.audit.outcome, BuildOutcomeKind::Completed);
    let graph = unit_outcome
        .rust_cargo_unit_graph
        .context("unit graph stage produced no graph")?;
    assert_eq!(graph.units.len(), 4);
    let invocation_request = create_compiler_precise_invocation_request(
        &project,
        requirement,
        graph,
        unit_outcome.audit.source_root_digest,
    )?;
    let outcome = execute_build_request(&invocation_request).await?;
    assert_eq!(
        outcome.audit.outcome,
        BuildOutcomeKind::Completed,
        "{:?}",
        outcome.audit
    );
    assert!(outcome.project_code_executed);
    let ledger = outcome
        .rust_compiler_invocation_ledger
        .context("compiler invocation ledger is missing")?;
    assert_eq!(ledger.entries.len(), 3);
    assert!(
        ledger
            .entries
            .iter()
            .any(|entry| entry.crate_types == ["proc-macro"])
    );
    assert!(
        ledger
            .entries
            .iter()
            .any(|entry| entry.crate_name == "build_script_build")
    );
    let mir = outcome
        .rust_compiler_mir_ledger
        .context("typed MIR ledger is missing")?;
    assert_eq!(mir.entries.len(), 3);
    assert_eq!(
        mir.entries
            .iter()
            .map(|entry| entry.bodies.len())
            .sum::<usize>(),
        3
    );
    let serialized = serde_json::to_string(&ledger)?;
    assert!(!serialized.contains(temporary.path().to_string_lossy().as_ref()));
    let audit = serde_json::to_string(&outcome.audit)?;
    assert!(!audit.contains(temporary.path().to_string_lossy().as_ref()));
    Ok(())
}

#[test]
fn wrapper_rejects_nesting_response_escape_and_rustc_substitution_before_compile() -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    let temporary = tempfile::tempdir()?;
    let workspace = temporary.path().join("workspace");
    let cargo_home = temporary.path().join("cargo-home");
    let output = temporary.path().join("output");
    let ledger = output.join("ledger");
    let pack = temporary.path().join("pack");
    for directory in [&workspace, &cargo_home, &output, &ledger, &pack] {
        fs::create_dir_all(directory)?;
    }
    fs::create_dir(workspace.join("src"))?;
    fs::write(workspace.join("src/lib.rs"), "pub fn fixture() {}\n")?;
    let marker = temporary.path().join("compiler-started");
    let rustc = pack.join("rustc");
    fs::write(
        &rustc,
        format!(
            "#!/bin/sh\nif [ \"$1\" = \"-vV\" ]; then printf 'fixture-rustc-vv\\nhost: x86_64-unknown-linux-gnu\\n'; exit 0; fi\nprintf started > '{}'\n",
            marker.display()
        ),
    )?;
    let mut permissions = fs::metadata(&rustc)?.permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&rustc, permissions)?;
    let verbose = b"fixture-rustc-vv\nhost: x86_64-unknown-linux-gnu\n";
    let expected_graph = output.join("expected-unit-graph.json");
    let units = vec![RustCargoUnit {
        unit_id: "cargo-unit:fixture".to_owned(),
        package_id: "path+repo://.#0.1.0".to_owned(),
        target: RustCargoTarget {
            kind: vec!["lib".to_owned()],
            crate_types: vec!["lib".to_owned()],
            name: "fixture".to_owned(),
            src_path: "repo://src/lib.rs".to_owned(),
            edition: "2024".to_owned(),
            doc: true,
            doctest: true,
            test: true,
        },
        profile: RustCargoProfile {
            name: "dev".to_owned(),
            opt_level: "0".to_owned(),
            lto: "false".to_owned(),
            codegen_units: None,
            debuginfo: Some(2),
            split_debuginfo: None,
            debug_assertions: true,
            overflow_checks: true,
            rpath: false,
            incremental: false,
            panic: "unwind".to_owned(),
            strip: RustCargoStrip::Deferred("None".to_owned()),
            codegen_backend: None,
        },
        platform: None,
        mode: "build".to_owned(),
        features: Vec::new(),
        is_std: false,
        dependencies: Vec::new(),
    }];
    let roots = vec!["cargo-unit:fixture".to_owned()];
    let graph = RustCargoUnitGraph {
        schema_version: "depgraph-rust-cargo-unit-graph-v1".to_owned(),
        digest: hex::encode(Sha256::digest(serde_json::to_vec(&(&units, &roots))?)),
        units,
        roots,
    };
    fs::write(&expected_graph, serde_json::to_vec(&graph)?)?;
    let environment = BTreeMap::from([
        ("CARGO_HOME", cargo_home.to_string_lossy().into_owned()),
        ("DEPGRAPH_COMPILER_ATTEMPT_DIGEST", "b".repeat(64)),
        (
            "DEPGRAPH_COMPILER_EXPECTED_UNIT_GRAPH",
            expected_graph.to_string_lossy().into_owned(),
        ),
        (
            "DEPGRAPH_COMPILER_EXPECTED_RUSTC",
            rustc.to_string_lossy().into_owned(),
        ),
        (
            "DEPGRAPH_COMPILER_EXPECTED_RUSTC_SHA256",
            hex::encode(Sha256::digest(fs::read(&rustc)?)),
        ),
        (
            "DEPGRAPH_COMPILER_EXPECTED_RUSTC_VERBOSE_SHA256",
            hex::encode(Sha256::digest(verbose)),
        ),
        (
            "DEPGRAPH_COMPILER_LEDGER_DIR",
            ledger.to_string_lossy().into_owned(),
        ),
        (
            "DEPGRAPH_COMPILER_OUTPUT_ROOT",
            output.to_string_lossy().into_owned(),
        ),
        (
            "DEPGRAPH_COMPILER_PACK_ROOT",
            pack.to_string_lossy().into_owned(),
        ),
        (
            "DEPGRAPH_COMPILER_WORKSPACE_ROOT",
            workspace.to_string_lossy().into_owned(),
        ),
    ]);
    let wrapper = Path::new(env!("CARGO_BIN_EXE_depgraph-rustc-wrapper"));

    let nested = run_wrapper(
        wrapper,
        &workspace,
        &environment,
        &rustc,
        &[
            "--crate-name",
            "fixture",
            "--crate-type",
            "lib",
            "--edition",
            "2024",
            "src/lib.rs",
        ],
        true,
    )?;
    assert!(!nested.status.success());
    let nested_stderr = String::from_utf8_lossy(&nested.stderr);
    assert!(
        nested_stderr.contains("nested compiler wrapper"),
        "{nested_stderr}"
    );

    let response = run_wrapper(
        wrapper,
        &workspace,
        &environment,
        &rustc,
        &[
            "--crate-name",
            "fixture",
            "--crate-type",
            "lib",
            "--edition",
            "2024",
            "@outside.rsp",
        ],
        false,
    )?;
    assert!(!response.status.success());
    let response_stderr = String::from_utf8_lossy(&response.stderr);
    assert!(
        response_stderr.contains("response files"),
        "{response_stderr}"
    );

    let escaped_source = temporary.path().join("escaped.rs");
    fs::write(&escaped_source, "pub fn escaped() {}\n")?;
    let escaped = run_wrapper(
        wrapper,
        &workspace,
        &environment,
        &rustc,
        &[
            "--crate-name",
            "fixture",
            "--crate-type",
            "lib",
            "--edition",
            "2024",
            escaped_source
                .to_str()
                .context("escaped source path is not UTF-8")?,
        ],
        false,
    )?;
    assert!(!escaped.status.success());
    let escaped_stderr = String::from_utf8_lossy(&escaped.stderr);
    assert!(
        escaped_stderr.contains("rustc path escapes"),
        "{escaped_stderr}"
    );

    let shadow = pack.join("shadow-rustc");
    fs::copy(&rustc, &shadow)?;
    let substituted = run_wrapper(
        wrapper,
        &workspace,
        &environment,
        &shadow,
        &[
            "--crate-name",
            "fixture",
            "--crate-type",
            "lib",
            "--edition",
            "2024",
            "src/lib.rs",
        ],
        false,
    )?;
    assert!(!substituted.status.success());
    let substituted_stderr = String::from_utf8_lossy(&substituted.stderr);
    assert!(
        substituted_stderr.contains("actual rustc path"),
        "{substituted_stderr}"
    );
    assert!(!marker.exists());
    assert_eq!(fs::read_dir(ledger)?.count(), 0);
    Ok(())
}

fn run_wrapper(
    wrapper: &Path,
    workspace: &Path,
    environment: &BTreeMap<&str, String>,
    rustc: &Path,
    arguments: &[&str],
    nested: bool,
) -> Result<std::process::Output> {
    let mut command = Command::new(wrapper);
    command
        .current_dir(workspace)
        .env_clear()
        .envs(environment)
        .arg(rustc)
        .args(arguments);
    if nested {
        command.env("DEPGRAPH_COMPILER_WRAPPER_ACTIVE", "1");
    }
    command.output().context("failed to execute wrapper")
}

fn compiler_pack_fixture(
    root: &Path,
    cargo_script: &str,
    rustc_script: &str,
    wrapper_binary: &Path,
) -> Result<CompilerPackRequirement> {
    use std::os::unix::fs::PermissionsExt as _;

    let source = root.join("compiler-pack-source");
    let pack = root.join("compiler-pack");
    fs::create_dir(&source)?;
    let component = |name: &str, files: Vec<String>| CompilerPackBuildComponent {
        name: name.to_owned(),
        archive_sha256: hex::encode(Sha256::digest(format!("archive:{name}"))),
        source: format!(
            "https://static.rust-lang.org/dist/2026-07-17/{name}-nightly-fixture.tar.xz"
        ),
        files,
    };
    let spec = CompilerPackBuildSpec {
        host: "x86_64-unknown-linux-gnu".to_owned(),
        target: "x86_64-unknown-linux-gnu".to_owned(),
        release_checksum_reference:
            "release-checksums:v0.5.0/compiler-pack-x86_64-unknown-linux-gnu".to_owned(),
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
            fs::create_dir_all(path.parent().context("fixture file has no parent")?)?;
            fs::write(&path, format!("fixture:{}", component.name))?;
        }
    }
    for relative in [
        spec.wrapper_protocol_schema_path.as_str(),
        "licenses/LICENSE-APACHE",
        "licenses/LICENSE-MIT",
    ] {
        let path = source.join(relative);
        fs::create_dir_all(path.parent().context("fixture file has no parent")?)?;
        fs::write(path, b"fixture")?;
    }
    fs::write(
        source.join(&spec.wrapper_protocol_schema_path),
        COMPILER_INVOCATION_RECORD_SCHEMA,
    )?;
    fs::write(source.join(&spec.cargo_path), cargo_script)?;
    fs::write(source.join(&spec.rustc_path), rustc_script)?;
    let wrapper = source.join(&spec.wrapper_path);
    fs::create_dir_all(wrapper.parent().context("wrapper has no parent")?)?;
    fs::copy(wrapper_binary, &wrapper)?;
    fs::write(source.join(&spec.query_path), QUERY_FIXTURE)?;
    let sysroot = source.join("toolchain/rustc");
    fs::create_dir_all(sysroot.join("lib"))?;
    fs::create_dir_all(
        sysroot
            .join("lib/rustlib")
            .join("x86_64-unknown-linux-gnu")
            .join("lib"),
    )?;
    for relative in [
        &spec.cargo_path,
        &spec.rustc_path,
        &spec.wrapper_path,
        &spec.query_path,
    ] {
        let path = source.join(relative);
        let mut permissions = fs::metadata(&path)?.permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(path, permissions)?;
    }
    let verified = build_compiler_pack(&source, &pack, &spec)?;
    Ok(CompilerPackRequirement {
        root: pack,
        expected_manifest_sha256: verified.attestation.manifest_sha256,
        release_checksum_reference: spec.release_checksum_reference,
        host: spec.host,
        target: spec.target,
    })
}

const QUERY_FIXTURE: &str = r#"#!/usr/bin/python3
import hashlib
import json
import os
import subprocess
import sys

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()

def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()

status = subprocess.run([os.environ["DEPGRAPH_COMPILER_EXPECTED_RUSTC"], *sys.argv[1:]])
if status.returncode != 0:
    raise SystemExit(status.returncode)
source_path = os.environ["DEPGRAPH_QUERY_SOURCE_PATH"]
source_sha = os.environ["DEPGRAPH_QUERY_SOURCE_SHA256"]
span = {
    "source_path": source_path,
    "source_sha256": source_sha,
    "start_line": 1,
    "start_column": 1,
    "end_line": 1,
    "end_column": 1,
}
crate_name = sys.argv[sys.argv.index("--crate-name") + 1]
definition_path = f"{crate_name}::fixture"
definition_id = digest([
    definition_path, source_path, source_sha, 1, 1, 1, 1,
])
definition = {
    "definition_id": definition_id,
    "path": definition_path,
    "span": span,
}
body_id = digest([
    os.environ["DEPGRAPH_QUERY_UNIT_ID"],
    os.environ["DEPGRAPH_QUERY_PACKAGE_ID"],
    os.environ["DEPGRAPH_QUERY_TARGET_DIGEST"],
    os.environ["DEPGRAPH_QUERY_PROFILE_DIGEST"],
    "function",
    definition,
])
type_id = digest(["unit", [], None, None, None, None])
local_id = digest([body_id, "local", 0])
place_id = digest([body_id, local_id, [], type_id])
block_id = digest([body_id, "block", 0])
operation_id = digest([body_id, block_id, 0, "return"])
body = {
    "body_id": body_id,
    "kind": "function",
    "definition": definition,
    "span": span,
    "types": [{
        "type_id": type_id,
        "kind": "unit",
        "arguments": [],
        "definition_id": None,
        "mutability": None,
        "value": None,
        "unsupported_reason": None,
    }],
    "constants": [],
    "locals": [{
        "local_id": local_id,
        "ordinal": 0,
        "role": "return",
        "type_id": type_id,
        "span": span,
    }],
    "places": [{
        "place_id": place_id,
        "local_id": local_id,
        "projections": [],
        "type_id": type_id,
    }],
    "blocks": [{
        "block_id": block_id,
        "ordinal": 0,
        "operations": [{
            "operation_id": operation_id,
            "ordinal": 0,
            "kind": "return",
            "span": span,
            "places": [],
            "constants": [],
            "unsupported_reason": None,
        }],
        "successors": [],
    }],
}
instance_id = digest([
    os.environ["DEPGRAPH_QUERY_UNIT_ID"],
    os.environ["DEPGRAPH_QUERY_PACKAGE_ID"],
    os.environ["DEPGRAPH_QUERY_TARGET_DIGEST"],
    os.environ["DEPGRAPH_QUERY_PROFILE_DIGEST"],
    os.environ["DEPGRAPH_QUERY_PACK_MANIFEST_SHA256"],
    os.environ["DEPGRAPH_QUERY_RUSTC_COMMIT"],
    "function",
    "item",
    definition_path,
    "fixture_symbol",
    [],
    definition,
    False,
])
instance = {
    "instance_id": instance_id,
    "kind": "function",
    "variant": "item",
    "definition_path": definition_path,
    "symbol_name": "fixture_symbol",
    "generic_arguments": [],
    "definition": definition,
    "compiler_generated": False,
}
unit = {
    "schema_version": "depgraph-rust-compiler-precise-v1",
    "digest": "",
    "attempt_digest": os.environ["DEPGRAPH_QUERY_ATTEMPT_DIGEST"],
    "invocation_id": os.environ["DEPGRAPH_QUERY_INVOCATION_ID"],
    "unit_id": os.environ["DEPGRAPH_QUERY_UNIT_ID"],
    "package_id": os.environ["DEPGRAPH_QUERY_PACKAGE_ID"],
    "target_digest": os.environ["DEPGRAPH_QUERY_TARGET_DIGEST"],
    "source_path": source_path,
    "source_sha256": source_sha,
    "profile_digest": os.environ["DEPGRAPH_QUERY_PROFILE_DIGEST"],
    "compiler_pack_manifest_sha256": os.environ["DEPGRAPH_QUERY_PACK_MANIFEST_SHA256"],
    "rustc_commit": os.environ["DEPGRAPH_QUERY_RUSTC_COMMIT"],
    "query_capabilities": ["monomorphized_call_graph", "typed_mir"],
    "instances": [instance],
    "calls": [],
    "bodies": [body],
    "unsupported": [],
}
identity = {key: value for key, value in unit.items() if key not in ("schema_version", "digest")}
unit["digest"] = digest(identity)
output = os.path.join(
    os.environ["DEPGRAPH_QUERY_OUTPUT_DIR"],
    f"mir-{unit['invocation_id']}.json",
)
with open(output, "x", encoding="utf-8") as file:
    file.write(json.dumps(unit, sort_keys=True, separators=(",", ":")))
"#;
