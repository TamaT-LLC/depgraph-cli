# Compiler-precise hostile execution and rollback E2E

- Evidence contract: `compiler-precise-hostile-e2e-v1`
- CI job: `compiler-precise-hostile`
- Gate: `scripts/compiler-precise-hostile-e2e.sh`
- Scope: `compiler-precise-rust-v1`
- filesystem isolation: enforced
- network isolation: enforced
- process isolation: enforced

CI path filter: on pull requests the job reports the required check name but
runs the expensive hostile steps only when related paths change (`Cargo.toml` /
`Cargo.lock`, compiler, CLI, MCP, operation, and store crates, hostile
scripts/docs, or `.github/workflows/ci.yml`).
`main` push and `workflow_dispatch` always run the full gate; unrelated PRs skip
heavy steps and still succeed.

## Enforced boundary

The hostile and release gate runs on Linux through
`linux-bubblewrap-v1`. The supervisor creates new user, mount, IPC, PID,
network, and UTS namespaces. The sandbox receives a read-only `/usr` runtime,
the read-only staged workspace, and the read-only verified compiler pack.
Only the run-owned home, cache, output, and temporary directories are writable.
The original source checkout, depgraph store, parent private files, credentials,
and all other host paths are absent from the mount namespace. The network
namespace has no host interfaces or routes.

The gate verifies the network boundary against a parent-only loopback listener,
not an Internet timeout. It also places readable credential and store canaries
outside the sandbox and requires the hostile child to observe neither. The
parent process receives a secret-shaped fixture variable; `env_clear` and the
allowlist keep it out of the child, audit, and machine-readable evidence.
Timeout and cancellation terminate the complete bubblewrap/process-group tree.

Linux compiler-precise unit-graph and invocation requests always select this
enforced boundary and fail if the trusted bubblewrap executable is unavailable.
There is no implicit fallback to host execution. Generic build adapters and the
macOS and Windows supervisor tests continue to report `best-effort`. They verify
environment clearing, path selection, output bounds, and process-tree cleanup,
but do not claim a filesystem or network sandbox. Stable target support remains
blocked on the five-target release gate.

The Ubuntu 24.04 hosted CI runner enables unprivileged user namespaces on its
ephemeral VM before the gate because the image's default AppArmor sysctl blocks
bubblewrap namespace creation. The gate preflights both the user and network
namespaces before any fixture runs; failure is terminal and does not fall back
to host execution.

## Fixture and evidence matrix

| Dimension | Fixtures and authoritative checks |
| --- | --- |
| Project code | `wrapper_conserves_target_build_script_and_proc_macro_units`, `consented_build_mode_runs_project_code_only_in_the_supervised_staging_area`, and the ignored enforced-boundary test cover benign/armed build-script and proc-macro units, descendant cleanup, parent-secret access, private/store canaries, and a parent-only network listener. |
| Injection | `neutral_config_rejects_all_executable_selectors_with_bounded_reasons`, `compiler_precise_unit_graph_is_supervised_without_starting_rustc_or_hooks`, and `wrapper_rejects_nesting_response_escape_and_rustc_substitution_before_compile` cover Cargo config, both wrapper variables, rustc override, runner/linker, response files, encoded or executable rustflags, and project PATH shadowing. |
| Artifacts | Compiler-pack, invocation-ledger, and typed-MIR tests cover fresh attempt identity, stale/foreign attempt identity, symlink and non-regular entries, path escape, duplicate records/units, truncated and unknown protocol records, per-file and aggregate bounds, and postflight pack tamper. |
| Failure | Supervisor and compiler validators cover Cargo/rustc nonzero exit, signal/crash, ICE/panic-shaped child failure, protocol/schema drift, timeout, cancellation, disk/output limits, missing terminal records, incomplete MIR, and descendant reap. |
| Rollback | `repeated_promotion_is_byte_stable_and_failure_rolls_back` and `completed_build_delta_unions_layers_without_overwriting_base_and_failed_delta_is_discarded` compare the completed snapshot and build layer before and after rejected promotion. No failure publishes a partial delta. |
| Safe invariant | Safe-scan CLI tests keep Cargo, rustc, wrappers, project hooks, repository PATH entries, and `NODE_OPTIONS` dormant. Adding an armed `.depgraph/compiler-pack` canary leaves exported graph bytes and syntax/semantic cache keys unchanged. Compiler-pack inputs are used only by the explicit three-part `resolve --build --allow-project-code --rust-compiler-precise` consent path. |
| MCP security matrix | Issue #317 tests parse every real clap leaf and require one static catalog mapping, compare exact live `tools/list` results for read/store-write/repository-write/daemon-control/project-exec/full profiles, deny direct calls to undiscoverable effects before store or journal access, and deny cancel for all six durable operation kinds without changing operation or handoff rows. The file/path corpus covers POSIX escape, Windows prefix/UNC/ADS/device aliases, symlink parents/finals, prompt/credential-shaped inputs, and forged operation kinds. |

The CI artifact `compiler-precise-hostile-<commit>` contains the canonical JSON
report. It binds the source revision, bubblewrap version and SHA-256, enforced
boundary properties, exercised fixture groups, accepted reason-code inventory,
rollback result, the closed `mcp_security_matrix`, and reviewed internal API
inventory. The MCP matrix records only fixed action/profile/operation/path
inventories and boolean invariant outcomes. It contains no raw child stream,
environment value, source path, store path, prompt, credential, or secret.

## Failure reasons and cleanup

Hostile failures are retained only as a bounded audit outcome and one of these
stage-specific reason codes:

- `rust-compiler-unit-graph-child-failed` or
  `rust-compiler-unit-graph-child-signalled`;
- `rust-compiler-unit-graph-invalid`;
- `rust-compiler-invocation-child-failed` or
  `rust-compiler-invocation-child-signalled`;
- `rust-compiler-typed-mir-invalid`;
- `compiler-pack-postflight-failed`;
- `build-child-failed`, `build-child-signalled`, `build-timeout`,
  `build-cancelled`, `build-output-limit`, or
  `build-output-security-policy`;
- `project-source-mutation-detected` or `project-source-postflight-failed`.

Every non-completed outcome clears the validated unit graph, invocation ledger,
typed-MIR ledger, converted graph, and output digest before store promotion.
The run-owned directory is deleted after process-tree termination. A retry uses
a new empty run root.

The source postflight audit is separate from the staged-workspace digest. It
reports `source_non_mutation_guaranteed: true` only when the supervisor selected
the enforced Linux namespace and the original admitted source fingerprint is
unchanged after child-tree termination. On best-effort hosts an unchanged
fingerprint is detection evidence only, never a non-mutation guarantee; a
detected change is retained as a typed security-failed audit and is never
promoted or cached.

## Unsafe and internal API inventory

The Linux namespace command builder, build supervisor, compiler wrapper, and
the reviewed private bridge add no `unsafe` block. The hostile gate fails if
one appears in those files.

The only `rustc_private` module remains
`crates/depgraph-rustc-query/src/rustc_private_bridge.rs`. Its closed inventory
is:

- `rustc_middle::ty::tls::with`;
- `TyCtxt::collect_and_partition_mono_items(())`;
- `CodegenUnit::items()`;
- exhaustive `rustc_middle::mono::MonoItem`,
  `rustc_middle::ty::InstanceKind`, and `ShimKind` matching; and
- immediate conversion with `rustc_public::rustc_internal::stable`.

The existing Unix process-group calls and Windows Job Object calls are isolated
in `crates/depgraph-core/src/worker.rs`; this stage adds no OS FFI. Bubblewrap
is treated as a CI/runtime boundary executable: it must canonicalize to a
root-owned file with no group/world write bit, and its version and SHA-256 are
recorded in evidence.
