#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

output="${DEPGRAPH_COMPILER_HOSTILE_REPORT:-dist/compiler-precise-hostile-e2e.json}"
if [[ "$(uname -s)" != "Linux" ]]; then
  echo "compiler-precise hostile E2E requires Linux" >&2
  exit 1
fi
bwrap="$(command -v bwrap || true)"
if [[ -z "$bwrap" ]]; then
  echo "compiler-precise hostile E2E requires bubblewrap" >&2
  exit 1
fi
bwrap="$(readlink -f "$bwrap")"
bwrap_mode=$((8#$(stat -c '%a' "$bwrap")))
if [[ "$(stat -c '%u' "$bwrap")" != "0" ]] || (( (bwrap_mode & 8#022) != 0 )); then
  echo "bubblewrap must be root-owned and not group/world writable" >&2
  exit 1
fi
if ! "$bwrap" \
  --die-with-parent \
  --unshare-user \
  --unshare-net \
  --ro-bind / / \
  -- /usr/bin/true; then
  echo "compiler-precise hostile E2E requires usable user and network namespaces" >&2
  exit 1
fi

export CARGO_NET_OFFLINE=true
cargo test --offline -p depgraph-core --lib --locked build::tests
cargo test --offline -p depgraph-core --lib --locked compiler_precise::tests
cargo test --offline -p depgraph-core --lib --locked compiler_invocation::tests
cargo test --offline -p depgraph-core --lib --locked compiler_mir::tests
cargo test --offline -p depgraph-core --lib --locked compiler_precise_graph::tests
cargo test --offline -p depgraph-core --lib --locked compiler_pack::tests
cargo test --offline -p depgraph-store --lib --locked completed_build_delta_unions_layers_without_overwriting_base_and_failed_delta_is_discarded
cargo test --offline -p depgraph-rustc-wrapper --test supervised --locked
cargo test --offline -p depgraph-cli --test cli --locked compiler_precise
cargo test --offline -p depgraph-cli --test cli --locked safe_scan_does_not_resolve_node_git_or_node_options_from_the_repository
cargo test --offline -p depgraph-cli --bin depgraph --locked issue_317_
cargo test --offline -p depgraph-core --lib --locked service_graph::tests::issue_317_
cargo test --offline -p depgraph-mcp --test process --locked issue_317_

fixture_secret="depgraph-hostile-parent-secret-must-not-leak"
DEPGRAPH_HOSTILE_PARENT_SECRET="$fixture_secret" \
  cargo test --offline -p depgraph-core --lib --locked \
  build::tests::enforced_hostile_boundary_denies_parent_secret_network_and_private_paths \
  -- --ignored --exact

if git grep -n -E 'unsafe[[:space:]]*\{' -- \
  crates/depgraph-core/src/build.rs \
  crates/depgraph-rustc-wrapper/src \
  crates/depgraph-rustc-query/src/rustc_private_bridge.rs
then
  echo "compiler-precise hostile boundary introduced an unsafe block" >&2
  exit 1
fi

mkdir -p "$(dirname "$output")"
bwrap_sha256="$(sha256sum "$bwrap" | cut -d ' ' -f 1)"
bwrap_version="$("$bwrap" --version)"
source_revision="$(git rev-parse HEAD)"
python3 - "$output" "$bwrap_sha256" "$bwrap_version" "$source_revision" <<'PY'
import json
import sys

output, bwrap_sha256, bwrap_version, source_revision = sys.argv[1:]
report = {
    "schema_version": "compiler-precise-hostile-e2e-v1",
    "source_revision": source_revision,
    "decision": "allow",
    "boundary": {
        "platform": "linux",
        "profile": "linux-bubblewrap-v1",
        "filesystem_isolation": "enforced",
        "network_isolation": "enforced",
        "process_isolation": "enforced",
        "host_root_mounted": False,
        "system_runtime_read_only": True,
        "workspace_read_only": True,
        "compiler_pack_read_only": True,
        "writable_mounts": ["run-cache", "run-home", "run-output", "run-temporary"],
        "parent_source_mounted": False,
        "store_mounted": False,
        "private_paths_mounted": False,
        "bubblewrap_version": bwrap_version,
        "bubblewrap_sha256": bwrap_sha256,
    },
    "fixture_groups": [
        "project-code-build-script-proc-macro-descendant-secret-network-host-linker-alias",
        "cargo-config-wrapper-rustc-runner-linker-response-rustflags-path-shadow",
        "artifact-stale-foreign-symlink-escape-duplicate-truncated-oversized-postflight",
        "failure-cargo-rustc-ice-panic-protocol-crash-signal-timeout-cancel-disk-output-terminal",
        "redaction-cleanup-last-snapshot-product-rollback-safe-scan",
        "mcp-cli-capability-path-cancel-recovery-security-matrix",
    ],
    "reason_codes": [
        "build-child-failed",
        "build-child-signalled",
        "build-timeout",
        "build-cancelled",
        "build-output-limit",
        "build-output-security-policy",
        "compiler-pack-postflight-failed",
        "rust-compiler-unit-graph-child-failed",
        "rust-compiler-unit-graph-child-signalled",
        "rust-compiler-unit-graph-invalid",
        "rust-compiler-invocation-child-failed",
        "rust-compiler-invocation-child-signalled",
        "rust-compiler-typed-mir-invalid",
    ],
    "rollback": {
        "partial_delta_promoted": False,
        "previous_completed_snapshot_preserved": True,
        "previous_completed_build_layer_preserved": True,
        "temporary_output_preserved": False,
    },
    "mcp_security_matrix": {
        "cli_leaf_actions": 23,
        "capability_profiles": [
            "read",
            "store-write",
            "repository-write",
            "daemon-control",
            "project-exec",
            "full",
        ],
        "durable_operation_kinds": [
            "scan_submit",
            "runtime_trace_import_submit",
            "export_file",
            "daemon_start_submit",
            "daemon_stop",
            "resolve_build_submit",
        ],
        "path_boundaries": [
            "profile-input",
            "query-input",
            "runtime-input",
            "repository-output",
            "graph-path-selector",
        ],
        "denied_cancel_mutates_journal": False,
        "forged_operation_executes": False,
        "source_tree_preserved": True,
        "external_canary_preserved": True,
    },
    "unsafe_internal_api_inventory": {
        "new_unsafe_blocks": 0,
        "rustc_private_module": "crates/depgraph-rustc-query/src/rustc_private_bridge.rs",
        "private_queries": [
            "rustc_middle::ty::tls::with",
            "TyCtxt::collect_and_partition_mono_items",
            "CodegenUnit::items",
            "rustc_middle::mono::MonoItem",
            "rustc_middle::ty::InstanceKind",
            "rustc_middle::ty::ShimKind",
            "rustc_public::rustc_internal::stable",
        ],
    },
}
with open(output, "w", encoding="utf-8", newline="\n") as handle:
    json.dump(report, handle, indent=2, sort_keys=True)
    handle.write("\n")
PY

if grep -F "$fixture_secret" "$output" >/dev/null; then
  echo "hostile evidence retained the fixture secret" >&2
  exit 1
fi
echo "compiler-precise hostile E2E passed: $output"
