# ADR: Opt-in Rust compiler-precise backend

- Status: Accepted
- Date: 2026-07-25
- Decision ID: `PROJ-ARC-001-ADR-002`
- Issue: `PROJ-ARC-001-TASK-081` / #149
- Contract: `compiler-precise-rust-v1`

## Context

The default Rust adapter is a safe, bundled rust-analyzer HIR backend. It reads
the confined repository inventory and an attested `rust-src` data tree, but it
does not run Cargo builds, build scripts, proc macros, project wrappers, or
project-selected compilers. That boundary must remain the default.

Some questions require the compiler's exact build-unit selection and
post-type-checking state:

- the same package compiled more than once with different features, targets,
  profiles, or dependency kinds;
- typed MIR after the selected compiler has resolved and normalized types;
- concrete compiler instances and monomorphized items;
- compiler-generated shims, drop glue, and calls that do not exist as a single
  source-level HIR definition.

Cargo's unit graph is a nightly, unstable JSON interface. `rustc_private` is
also unstable, has a compiler-internal linkage boundary, and requires the
`rustc-dev` and `llvm-tools` components when used with official toolchains.
Cargo can select or nest `RUSTC`, `RUSTC_WRAPPER`, and
`RUSTC_WORKSPACE_WRAPPER` from environment and configuration. A compiler-precise
backend therefore cannot be treated as a more accurate form of safe scan. It is
an explicitly consented build observation that executes untrusted project code
and consumes unstable, untrusted output.

## Decision

Adopt an opt-in compiler-precise backend behind the existing supervised build
boundary. The exact contract is `compiler-precise-rust-v1`.

The future CLI selector is:

```text
depgraph resolve --build PATH --allow-project-code --rust-compiler-precise
```

`--rust-compiler-precise` does not exist until the staged implementation below
adds it. The existing `resolve --build --allow-project-code` command continues
to perform the current build-observation contract and does not implicitly
enable compiler queries.

The three flags are independent mandatory gates:

- `--build` selects the supervised execution mode.
- `--allow-project-code` grants consent for this invocation only.
- `--rust-compiler-precise` requests the compiler-precise capability.

Configuration, environment, CI detection, TTY state, a previous invocation, or
an unresolved safe scan may not supply any of these gates. Consent is checked
before path canonicalization, project configuration, compiler-pack probing,
store creation, or child execution.

The backend runs only inside the existing run-specific staged workspace,
process-tree supervisor, neutral environment, bounded output, timeout/cancel,
and atomic build-attempt transaction. It never runs in the `scan` command or in
the safe Rust worker.

## Exact compatibility unit

The first accepted unit is:

| Field | Exact value |
| --- | --- |
| Contract | `compiler-precise-rust-v1` |
| Toolchain channel | `nightly-2026-07-17` |
| Rust / Cargo release | `1.99.0-nightly` |
| rustc commit | `3d50c25bc66853bf0ad205529d0f305a1d841b5e` |
| Official channel manifest | `2026-07-17/channel-rust-nightly.toml` |
| Channel manifest SHA-256 | `e8598e1b6ab58a60209ba3ac8e5dd3a0f799719829dede0306b4daf1769b52c9` |
| Required components | `cargo`, `rustc`, `rust-std`, `rust-src`, `rustc-dev`, `llvm-tools` |
| Cargo unit graph | `version=1` |
| Wrapper output | `depgraph-rust-compiler-precise-v1` |
| Graph evidence | `phase=build`, `precision=observed` |

The compatibility identity also contains the host and compilation target,
component archive and extracted-tree SHA-256 values, compiler-pack manifest
digest, compiler wrapper executable digest, wrapper protocol/schema digest,
command-plan digest, source/lock digest, Cargo unit-graph digest, target
selection, feature set, Cargo profile, panic strategy, optimization level, LTO,
codegen-unit count, and enabled compiler-query capability set.

`nightly` without a date, a short commit prefix, version text alone, or matching
component names are not sufficient identity. Every component and every regular
file in the closed compiler-pack tree is attested. Unknown, missing, additional,
changed, symlinked, non-regular, or host-incompatible entries fail before
project code starts.

Updating any listed toolchain value, compiler API, output field, query
capability, or component tree creates a new tested compatibility unit. A
release may retain `compiler-precise-rust-v1` only when the output contract is
backward compatible; otherwise it introduces a new contract version.

## Distribution and attestation

The normal depgraph archive does not embed a mutable nightly installation.
Compiler support is delivered as a separately downloadable, target-specific,
first-party compiler pack. Each pack contains the exact official components,
the compiler wrapper, a closed-tree manifest, checksums, SPDX SBOM, license
inventory, source provenance, and a signature/checksum reference from the
depgraph release.

The core verifies the pack before staging a project and again after the child
tree stops. The supervisor exposes it read-only where the platform can enforce
that property. A changed postflight digest is `security_failed`, even if the
compiler process returned success.

The core invokes the pack's absolute `cargo` and `rustc` paths directly.
`rustup`, PATH lookup, automatic toolchain/component installation, system
toolchains, project-local toolchains, `RUSTUP_TOOLCHAIN`, and network download
are forbidden. A missing compiler pack produces an actionable unsupported
diagnostic; it never falls back to another nightly, stable rustc, rust-analyzer,
or artifact parsing while claiming compiler-precise output.

## Threat model

| Zone or input | Trust | Required control |
| --- | --- | --- |
| depgraph parent, store, protocol validators | trusted product boundary | Never load compiler libraries, proc-macro libraries, project libraries, or compiler artifacts into the parent |
| compiler-pack manifest and unopened tree | conditionally trusted supply-chain input | Verify signature/checksum reference, closed tree, component provenance, host, full digests, SBOM, and licenses before use |
| staged source, manifest, lockfile, Cargo config | untrusted input | Confined regular-file inventory; parse and project only allowlisted static settings into a generated neutral Cargo config |
| build scripts, proc macros, compiler plugins, linked tools, and descendants | untrusted executable code | Invocation-only consent, isolated process tree, neutral secrets-free environment, timeout/cancel, network policy, bounded output |
| Cargo unit graph, wrapper argv, diagnostics, stdout/stderr | untrusted child output | Bounded capture, strict versioned schema, path normalization, count conservation, no raw stream persistence |
| wrapper process after rustc starts | compromised-capable child | Treat output as untrusted because a proc macro shares the compiler process; do not give the wrapper a signing key or parent/store access |
| MIR and monomorphized query values | unstable compiler-internal data | Convert in the child to a bounded versioned DTO; never serialize `DefId`, `TyCtxt`, allocation addresses, or debug text as identity |
| target, incremental, rmeta, rlib, object, and dep-info files | untrusted artifacts | Fresh run directory only; no pre-existing artifact read; validate regular-file confinement, size, digest, producer, and attempt before any admitted read |
| previously completed safe/build snapshot | trusted committed state | Preserve byte-for-byte until the entire compiler-precise delta validates and commits atomically |

Explicit consent acknowledges that project code can attack the compiler child
and any host boundary the platform cannot enforce. It does not make project
code trusted and is not represented as a sandbox guarantee. Local execution
may report network isolation as `best-effort`; release and hostile-fixture CI
must use an outer environment that reports it as `enforced`.

Issue #248 implements that enforced environment as
`linux-bubblewrap-v1`: the child receives new user, mount, IPC, PID, network,
and UTS namespaces, a read-only staged workspace and compiler pack, and only
run-owned writable directories. The original checkout, store, parent private
paths, and host network are not mounted. The executable must be root-owned and
non-writable, and its version and digest are recorded in the
[`compiler-precise-hostile-e2e-v1`](../50_test/compiler-precise-hostile-e2e.md)
evidence. Linux compiler-precise unit-graph and invocation requests always use
this boundary and fail closed when it is unavailable; they never fall back to
direct host execution.

The child environment starts from `env_clear`. It contains only versioned
allowlisted values and run-specific home/cache/output paths. Secret values and
secret-like keys are absent. Project settings that can choose executables or
inject code are rejected or replaced with attested values, including:

- `build.rustc`, `build.rustc-wrapper`, and
  `build.rustc-workspace-wrapper`;
- `RUSTC`, `RUSTC_WRAPPER`, `RUSTC_WORKSPACE_WRAPPER`, and Cargo equivalents;
- target/host runner, linker, rustdoc wrapper, credential provider, and shell
  alias;
- unstable Cargo configuration not explicitly admitted by this contract;
- encoded rustflags that load plugins, select arbitrary linkers, read response
  files outside the staged tree, or write outside run-owned output.

Static target, feature, profile, and allowlisted `cfg`/rustflags settings may be
projected into a generated neutral config after canonical validation. Rejected
settings produce a bounded reason and no compiler invocation.

## Execution pipeline

One attempt has the following ordered phases:

1. Verify invocation consent, repository inventory, lockfile availability,
   compiler pack, host/target support, neutral configuration, and resource
   policy. Create no store delta.
2. Run the attested Cargo with `--frozen --offline --unit-graph
   -Z unstable-options` against the same package/target/feature/profile
   selection. Validate unit-graph `version=1`, bounds, root reachability,
   package/source confinement, and canonical ordering.
3. Start a fresh Cargo target directory, set the attested compiler wrapper as
   the only `RUSTC_WRAPPER` for all admitted units, and force
   `RUSTC_WORKSPACE_WRAPPER` empty. Record every compiler invocation and match
   it one-to-one to the admitted unit graph before accepting query output.
4. Inside each wrapper invocation, validate the actual rustc path and verbose
   identity, then enter the pinned compiler through `rustc_public` where its
   capability is sufficient. A minimal reviewed `rustc_private` bridge may be
   used only for the monomorphized-item queries not exposed by the public
   nightly facade.
5. Emit typed MIR and instance data as one bounded
   `depgraph-rust-compiler-precise-v1` DTO per unit into a run-owned output
   directory. Use canonical crate/item/instance identities derived from
   package locator, target, source definition, generic arguments, and compiler
   compatibility unit. Raw internal indices, host paths, and compiler debug
   strings are forbidden.
6. After the process tree exits, validate invocation/unit conservation,
   protocol/schema, source spans, targets, instance ownership, edge endpoints,
   evidence digests, byte/count limits, and compiler-pack postflight identity.
7. Union the complete delta with the selected completed base snapshot in one
   transaction. Any missing unit, missing terminal record, partial compiler
   result, inconsistency, or failed postflight discards the entire
   compiler-precise delta.

Stage 2 does not execute rustc according to Cargo's unit-graph contract, but it
still reads attacker-controlled Cargo inputs and is kept inside the same
supervisor boundary. Stages 3 onward can run build scripts and proc macros.

## Graph and evidence contract

Compiler output augments rather than replaces safe HIR or existing build
evidence.

- Cargo units are canonical build-profile records, not source symbols.
- A typed MIR body belongs to one canonical source definition and one exact
  compiler compatibility/profile identity.
- A monomorphized item is a canonical instance of a source definition,
  compiler-generated shim, drop glue, virtual-call shim, or allocation. The
  kind is explicit; generated items are never assigned a fabricated source
  span.
- An exact compiler-selected call is `calls / resolved / observed` only when
  the queried instance has one admitted target. Compiler-reported finite
  alternatives remain candidate `may_call`; an unknown or unrepresentable
  target remains a reason-coded `unknown_target`.
- Primary evidence contains contract, compiler pack, rustc commit, wrapper,
  unit graph, unit, command plan, profile, MIR/instance DTO, and attempt
  digests. Source/HIR evidence is supporting evidence and is not overwritten.
- Compiler-precise completeness applies only to the admitted unit roots and
  query capabilities. It does not imply safe semantic completeness, runtime
  reachability, or coverage of targets/features outside the selected unit
  graph.
- Same source identity with different target, features, Cargo profile, panic,
  optimization, or compiler pack remains in a different profile. Cross-profile
  merging is forbidden.

The stable graph/store compatibility unit is the versioned DTO and canonical
graph conversion, not rustc's internal Rust types. No `rustc_private` type
crosses the child process boundary.

The first compatibility unit's reviewed private bridge is limited to
`rustc_middle::ty::tls::with`,
`TyCtxt::collect_and_partition_mono_items(())`, `CodegenUnit::items()`, and
exhaustive classification of `rustc_middle::mono::MonoItem` plus
`rustc_middle::ty::{InstanceKind, ShimKind}`. Each item is immediately converted
with `rustc_public::rustc_internal::stable`; the bridge returns only public
`Instance`/`StaticDef` values and its own closed classification enums. It
contains no `unsafe`, rejects global assembly as unrepresented, and relies on
exhaustive matches plus the pinned nightly build to fail closed on compiler API
drift. Adding any query, private type, fallback string representation, or
`unsafe` operation requires the security review gate below.

## Failure and rollback

The following outcomes fail closed with no partial promotion:

- compiler pack or postflight mismatch;
- unsupported host/target or missing exact component;
- Cargo unit-graph version drift, malformed graph, or invocation mismatch;
- project wrapper/compiler/linker injection;
- source, artifact, response-file, or output path escape;
- symlink, special file, count/byte/time limit, or disk budget violation;
- compiler error, ICE, panic, crash, signal, timeout, cancellation, or
  descendant leak;
- proc-macro/build-script failure or incomplete terminal ledger;
- unknown DTO field/version, invalid identity/span/edge, or coverage mismatch.

Failure records only a bounded, redacted audit and reason. Raw compiler output,
environment values, MIR debug text, and temporary absolute paths are not
persisted. The last completed snapshot and any previous completed build layer
remain unchanged. A retry starts with a new empty target/output directory.

There is no automatic retry with another toolchain or compiler API. Product
rollback restores the compiler pack, wrapper, schema, compatibility table, and
tests to the previous complete unit atomically. Safe `scan` remains available
as a separate explicit invocation; it is not a hidden fallback result for a
failed compiler-precise request.

## Options considered

| Option | Decision | Reason |
| --- | --- | --- |
| Exact compiler pack + supervised all-unit Cargo compiler wrapper | Adopted | Preserves Cargo's real unit selection while containing unstable compiler linkage and all project execution in the existing child-process boundary |
| `rustc_public` facade first, minimal reviewed internal bridge | Adopted | Reduces direct `TyCtxt` surface while retaining a path to monomorphized items absent from the facade |
| Stable `cargo metadata` plus HIR inference | Rejected | Cannot represent per-unit feature/target/profile duplication or compiler instances |
| `--unit-graph` alone | Rejected as complete backend | Provides build units but no typed MIR or monomorphized item graph |
| Parse pre-existing `rmeta`, `rlib`, incremental, or object files | Rejected | Producer and compiler identity are not trustworthy, formats are unstable, and artifact parsing expands the parent attack surface |
| Load a compiler plugin or rustc libraries into depgraph core | Rejected | A compiler/proc-macro failure would cross the trusted store/orchestration boundary |
| Use project/system `RUSTC_WRAPPER` or an arbitrary installed nightly | Rejected | Executable identity, nesting, component closure, and reproducibility cannot be attested |
| Bundle a rolling nightly in every normal depgraph archive | Rejected | Makes default safe distribution large and mutable and couples stable releases to nightly availability |
| Run `rustup` to acquire a missing component | Rejected | Introduces network, mutable user state, and time-of-use drift |
| Sign output inside the wrapper | Rejected | Project proc macros can share and compromise the wrapper process; a signing key there would not establish trust |

## Security review gates

Security review by the security owner and the Rust adapter maintainer is
required before any stage is marked supported, and again for:

- a toolchain date/commit or component-tree update;
- a new `rustc_private` crate, query, override, callback, or unsafe bridge;
- a new Cargo unstable feature or admitted project configuration key;
- any artifact reader, linker/runner allowance, or expanded filesystem/network
  boundary;
- a protocol/schema change or new graph promotion;
- a new host/target tier or a claim stronger than `best-effort` isolation.

Review evidence includes the compiler-pack provenance/SBOM/license closure,
closed-tree tamper tests, unsafe/internal API inventory, hostile fixtures,
resource-limit tests, platform isolation statement, redaction review, and
rollback drill. Until those artifacts pass, doctor reports the backend as
`unsupported` or `experimental`; release metadata may not claim it as stable.
The hostile execution, isolation, redaction, and rollback evidence is maintained
in
[`docs/50_test/compiler-precise-hostile-e2e.md`](../50_test/compiler-precise-hostile-e2e.md).

## Staged implementation and acceptance matrix

Each follow-up is sized for one to three engineering days and produces a
separately reviewable vertical increment.

| Stage | Size | Completion condition | Depends on |
| --- | --- | --- | --- |
| Compiler-pack manifest and verifier | 2-3 days | Build one target pack; verify channel manifest, full component/tree closure, wrapper digest, SBOM/licenses, pre/postflight tamper and no rustup fallback | None |
| Consent, neutral Cargo config, and unit graph | 2-3 days | Add the CLI selector and early refusal; reject execution-bearing config; validate bounded canonical unit-graph v1 without starting rustc | Compiler pack |
| Wrapper invocation ledger | 2-3 days | Match exact wrapper/rustc identity and every admitted Cargo unit invocation, including dependency, build-script, and proc-macro units, one-to-one to the unit graph; reject nesting, extra/missing units, path leaks, and partial terminal records | Unit graph |
| Typed MIR DTO vertical slice | 2-3 days | Emit and validate local function/closure/async typed MIR, canonical places/types/constants, source correlation, bounds, and deterministic DTO; no call promotion yet | Wrapper ledger |
| Monomorphized item and call slice | 2-3 days | Represent functions, generic instances, shims, drop glue, and exact/candidate/unknown calls without raw compiler IDs | Typed MIR |
| Atomic graph promotion and query/export | 2-3 days | Union build-phase observed nodes/sites/edges; support doctor/why/JSON/DOT/Mermaid; preserve safe evidence and profile separation | Instance slice |
| Hostile execution and rollback E2E (implemented in #248) | 2-3 days | Exercise build script/proc macro, malicious config/wrapper, artifact escape/tamper, ICE/crash/timeout/cancel, secret non-leakage, and last-snapshot preservation under enforced CI isolation | Promotion |
| Five-target release gate (implemented in #249) | 2-3 days | Linux/macOS x64/arm64 and Windows x64 packs pass extraction, attestation, semantic fixture, determinism, benchmark, SBOM/license, aggregate compatibility, and rollback gates | Hostile E2E |

The typed MIR vertical slice uses an independently attested
`depgraph-rustc-query` executable in the compiler pack. The stable workspace
does not link compiler libraries. The query child is built only with the
pinned nightly, enters through `rustc_public::run!`, and emits one DTO per
validated wrapper invocation. The parent independently rejects unknown
schema/fields, raw compiler identity/debug/address text, unconfined spans,
dangling atoms, and count/byte/depth overflow before retaining the ledger as
audit-only evidence. Call promotion remains a later stage.

The cross-stage acceptance matrix contains:

| Dimension | Required cases |
| --- | --- |
| Language | editions 2015, 2018, 2021, 2024; library/bin/test/example; workspace/path dependency |
| Unit identity | normal/build/dev dependency, resolver v2 duplication, feature split, host/target split, profile/panic/opt/LTO/codegen-unit split |
| MIR | function, method, closure, async/coroutine, generic substitution, const/static, unwind/drop terminators, unsupported construct |
| Instances | generic function/type method, closure, shim, drop glue, intrinsic/external, exact direct call, finite candidate, unknown target |
| Project code | benign and armed build scripts/proc macros; descendant process; secret read attempt; network attempt |
| Injection | project `.cargo/config`, both wrapper variables, rustc override, runner/linker, response file, encoded rustflags, PATH shadow |
| Artifacts | fresh same-attempt artifact, stale/pre-existing artifact, symlink, path escape, duplicate, truncation, oversized tree, postflight toolchain change |
| Failure | Cargo/rustc error, ICE/panic, protocol drift, crash/signal, timeout, cancel, disk/output limit, missing terminal record |
| Determinism | repeated run and different checkout produce byte-identical canonical graph for the same source/lock/compiler/profile identity |
| Rollback | every failure leaves the previous completed snapshot and build layer byte-identical |
| Platforms | Tier 1 macOS/Linux and Tier 2 Windows compiler packs, with unsupported host/target producing no fallback |
| Safe invariant | `scan` starts no Cargo/rustc/wrapper/project process and its output/cache identity is unchanged by compiler-pack presence |

No stage may promote `compiler-precise` support based only on happy-path unit
tests. The applicable hostile, rollback, and deterministic cases are mandatory
at every promotion boundary.

Issue #249 implements the release closure as
[`compiler-pack-five-target-release-v1`](../50_test/compiler-precise-five-target-release.md).
The five native pack jobs publish archives separately from normal product
archives, and `verify-compiler-packs` requires the exact target set before the
stable release gate can pass.
Release compatibility and doctor output expose the supported targets, exact
toolchain and schema identity, query capabilities, separate distribution, and
`unsupported-no-fallback` policy.

## Consequences

This decision provides a route to exact compiler-instance evidence without
weakening the default safe scan or importing compiler internals into the core.
It also creates a large optional supply-chain artifact and a maintenance cost
for every pinned nightly update. Compiler-precise results are trustworthy as
bounded observations of one attested toolchain/profile attempt, not as proof
that hostile project code reported truthful intent or that other build profiles
behave identically.

## References

- [Cargo unstable `unit-graph`](https://doc.rust-lang.org/cargo/reference/unstable.html#unit-graph)
- [Cargo compiler wrapper configuration](https://doc.rust-lang.org/cargo/reference/config.html#buildrustc-wrapper)
- [Rust Unstable Book: `rustc_private`](https://doc.rust-lang.org/beta/unstable-book/language-features/rustc-private.html)
- [Nightly `rustc_public` compiler interface](https://doc.rust-lang.org/nightly/nightly-rustc/rustc_public/compiler_interface/struct.CompilerInterface.html)
- [Pinned nightly channel manifest](https://static.rust-lang.org/dist/2026-07-17/channel-rust-nightly.toml)
