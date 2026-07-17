# Rust worker

The Rust worker produces a deterministic static syntax graph. It
reads confined Cargo manifests, lockfiles, and Rust source, preflights every
Cargo-visible path, and constructs a worker-owned mirror containing only
admitted manifests, lockfiles, and target-discovery layout. It runs
`cargo metadata --format-version 1 --no-deps --frozen --offline` against the
mirror from a neutral working directory and falls back to its static manifest
model when preflight, mirror construction, the command, or DTO validation
fails. Rust source is parsed with `syn`. The worker links an exact-pinned
rust-analyzer library set and, for a compatible toolchain/target and confined
Cargo DTO, constructs an inventory-only multi-file VFS, local `CrateGraph`,
per-crate cfg, and analysis database. The production scan now queries that
database for the HIR definition and dependency graph: canonical `symbol` and
`type` nodes, site-less `declares`, `extends`, `implements`, and `instantiates`
relations, HIR-refined import/re-export sites, semantic `type_uses`, and
exact/candidate calls are validated and atomically unioned with the syntax
graph. The final fallback/release gates remain, so the worker does not yet
claim `semantic-complete`.

Preflight rejects ambiguous globs, symlinks, out-of-root workspace members and
path dependencies, and unknown Cargo path-bearing fields before Cargo starts.
Known absolute paths must map to admitted inventory entries and are rewritten
to the mirror; the original repository manifest path is never passed to Cargo.
Standalone package roots receive an empty mirror-only workspace boundary so
Cargo cannot discover a workspace manifest in temporary-directory ancestors.
When the inventory root has no admitted manifest, the mirror project root owns
a virtual guard workspace. Path dependencies outside a selected nested
workspace therefore stop at worker-owned input, even when Cargo rejects them
and the scanner uses its static fallback.
Raw Cargo DTO paths are mapped back to repository-relative inventory IDs or
original confined canonical paths before leaving the metadata boundary. Raw
`path+file://` package IDs are used only to match DTO workspace members, and
mirror paths, temporary Cargo homes, and target directories never participate
in profile or graph identity, diagnostics, evidence, or coverage. The remapped
DTO now feeds the safe project model when the compatibility gates pass. Static
Cargo fallback remains syntax-only and is recorded as a crate-graph-unavailable
diagnostic and coverage reason; it is never silently treated as equivalent HIR
input.

The metadata command uses `env_clear`, a sanitized absolute `PATH`, neutral
worker-owned writable homes, Cargo home, temporary and target directories,
empty compiler wrappers, offline/frozen mode, and `RUSTUP_AUTO_INSTALL=0`.
Only a canonical Rustup home outside the scan root may be retained for a
resolved system rustup proxy. The neutral version probe uses the same
no-download/no-project-write boundary with timeout and output limits.

## Selected semantic backend

The selected semantic backend is an exact-pinned set of rust-analyzer library
crates linked into `depgraph-rust-worker`: `ra_ap_* = 0.0.330`, from upstream
revision `8954b66d43225e62c92e8bbcc8500191b5cceb1e`, with the Salsa dependency
set pinned to `0.26.1`. Version `0.0.331` was evaluated and rejected because
its HIR type crate uses unstable if-let guards and does not compile with the
verified Rust `1.93.1` baseline.

The original smoke scaffold lowers only caller-supplied bytes through virtual
`/lib.rs`. The completed safe project-model slice generalizes that boundary to
the admitted source inventory for selected workspace and active path packages.
It assigns deterministic virtual file IDs, adds profile-selected workspace
targets and active in-root path dependencies as local crates, and reconstructs
edition plus feature, target, and test cfg per crate. Registry,
git, unmodeled path, build, and sysroot dependencies stay in a deterministic
sidecar sentinel ledger instead of being loaded into the database. Custom
targets, build scripts, proc-macro targets, incomplete crate models, and static
Cargo fallback remain explicit diagnostic/coverage entries.

Neither path discovers a Cargo workspace or reads a repository file on demand.
The project model does not load `rust-project.json`, `.cargo/config*`, sysroot
or registry source, build output, or proc-macro libraries, and it does not run
build scripts or child processes. The implemented semantic pass emits stable
named/local symbol and type identities, definition relations, HIR-resolved
import/re-export sites, signature/field/bound/type-alias/body `type_uses`, and
exact/candidate call sites into an isolated delta. Each HIR-refined dependency
keeps semantic primary evidence plus its supporting syntax evidence. The
scanner validates nodes, sites, edges, and file coverage together before
unioning the delta with the static syntax graph.
Recognized type occurrences that cannot enter the exact delta remain once as
source-phase external or unresolved fallback sites. A call that cannot be
proved exact or represented by a complete, finite candidate set remains
external or unresolved instead of being promoted speculatively.

`profiles.rust_mode` accepts `check` (default), `build`, or `test`. Test mode
adds separate `cfg(test)` lib/bin harness crates when Cargo enables them and
applies each example/test/bench target's Cargo `test` flag. Dev dependencies
are enabled only for workspace units that Cargo selects; dependency-only
packages never load their own tests or dev dependencies. Target
`required-features` and effective target editions are preserved. The current
safe cfg profile is intentionally normalized to debug assertions plus unwind
panic semantics; cfg-affecting Cargo `dev`/`test` profile overrides are
classified as typed unsupported input. Direct `cfg`/`cfg_attr` and
syntactically direct, unqualified `cfg!` predicates are conservatively
validated. A declarative macro expansion that contains calls is retained as one
generated, unresolved call boundary at the invocation span with macro
provenance; generated calls are not individually up-mapped to ordinary source
calls. Name resolution and cfg created by expansion remain part of the later
semantic slice.

`rust_hir_project_model=ready` means the atomic VFS, crate graph, and cfg input
were constructed. Semantic extraction success is reported separately as
`rust_hir_status=import-type-call-graph-emitted` or
`import-type-call-graph-partial`; neither means that all fallback conditions
were classified. Missing modules and includes remain
unresolved syntax sites with coverage reasons, so the profile cannot yet claim
`semantic-complete`.

An external `rust-analyzer` LSP process is not selected. Its project-loading
path can start Cargo, build-script, proc-macro, and flycheck services, while
project `.cargo/config` and `rust-toolchain.toml` influence command or
toolchain selection. LSP also adds a second process protocol without exposing
the complete HIR facade needed by the graph extractor. Keeping the unstable
library API inside the existing worker preserves the protocol boundary and
lets the core isolate a panic or crash by terminating that worker.

The rust-analyzer project documents these constraints in its
[security notes](https://rust-analyzer.github.io/book/security.html),
[configuration reference](https://rust-analyzer.github.io/book/configuration),
and [architecture overview](https://rust-analyzer.github.io/book/contributing/architecture.html).

## HIR safe scan boundary

The current Cargo-facing phase may:

- read regular manifest, lockfile, and target-layout inputs whose canonical
  paths remain inside the scan root;
- reject unconfined path-bearing input before Cargo starts;
- run the resolved system `cargo` only against the worker-owned admitted mirror
  from a neutral environment;
- map `workspace_root`, package manifests, target sources, and dependency paths
  from the raw DTO to admitted inventory identities, rejecting the entire DTO
  when any path is unknown, outside the mirror, or unregistered;
- probe resolved system Cargo and rustc versions for the future HIR enable gate
  using a neutral directory, cleared project environment,
  `RUSTUP_AUTO_INSTALL=0`, timeout, and output limit.

The completed safe project-model, definition, and dependency slices now:

- consume the already-admitted manifests and source bytes to build an in-memory
  multi-file VFS, per-crate cfg set, and local crate graph;
- retain external, sysroot, build, proc-macro, unsupported, and incomplete
  inputs in a deterministic sidecar or diagnostic/coverage ledger;
- query only that confined database for canonical `symbol` / `type` definitions
  and site-less `declares` / `extends` / `implements` / `instantiates`
  relations;
- resolve leaf-level module aliases (including `use` and `extern crate` aliases),
  cross-file `self` / `crate` / `super` paths, globs, imports, re-exports, and
  named declaration/body type uses;
- resolve statically unique function, associated-function, method, generic
  instance, and closure calls as exact `calls`, and preserve complete finite
  closed-trait or immutable local function-pointer target sets as candidate
  `may_call` edges without promoting singleton dynamic sets to exact;
- retain external calls, incomplete/open dispatch, unknown function-pointer
  flow, and call-bearing macro expansion boundaries as explicit external or
  unresolved dependency sites;
  classify every emitted site as resolved, candidates, external, or unresolved;
  and replace the matching syntax import occurrence instead of duplicating it;
- preserve canonical cfg/feature/target conditions, semantic primary evidence,
  supporting source evidence, and direct-source macro provenance, then atomically
  union the validated node/site/edge/file-ledger delta with the syntax graph.

Block-local aliases whose external definition source is unavailable are kept
as unresolved type-use sites; the worker does not leak those aliases into the
surrounding module or infer unqualified prelude names without exact HIR proof.

The remaining semantic and release slices may also:

- complete the final fallback/coverage matrix and determine when a selected
  profile is eligible for `semantic-complete`;
- read a release-owned, checksum-verified sysroot snapshot after that component
  is introduced by the HIR implementation.

Safe mode must not:

- start a project-local or system `rust-analyzer` server;
- execute `cargo check`, rustc wrappers, project `.cargo/config`, project
  toolchain overrides, build scripts, procedural macros, or macro dynamic
  libraries;
- read generated output from outside the canonical scan root;
- fetch a toolchain, target, crate, or index entry from the network;
- claim `semantic-complete` when the HIR input, cfg, sysroot, build-script
  output, or macro expansion is incomplete.

Build scripts and proc macros remain explicit unresolved dependency sites.
Their side effects are covered by the armed fixture under
`tests/fixtures/security`; `project_code_executed` must remain `false`.

## Toolchain compatibility

The current verified Rust baseline is `1.93.1`. Syntax inventory remains
best-effort outside that baseline. The worker probes the resolved system
`rustc` and Cargo pair from a neutral environment and records whether it
matches the exact baseline. The rust-analyzer revision is selected, the smoke
scaffold and deterministic multi-file project model are available, and Cargo
metadata input reads are confined. When those inputs are compatible, the HIR
definition, import/re-export, type-use, and call graph is emitted now; the final
fallback/coverage matrix and release gate remain incomplete. A
verified sysroot is additionally required only when the profile claims exact
standard-library resolution.

| Project/toolchain state | Current result | HIR eligibility after the remaining gates |
| --- | --- | --- |
| Exact `1.93.1`, supported target, and complete confined crate graph | Static syntax graph plus HIR definitions, refined imports/re-exports, `type_uses`, and exact/candidate calls; status is `import-type-call-graph-emitted` or `import-type-call-graph-partial` | Final fallback and release gates remain |
| No project toolchain declaration | The neutral probe decides eligibility; an exact compatible pair may emit the import/type/call graph | Eligible only when every effective input is the verified baseline |
| Older, newer, or nightly declaration | `RUST_TOOLCHAIN_BEST_EFFORT`; static syntax graph | Syntax fallback; never `semantic-complete` |
| Custom or malformed declaration, unreadable file, or external symlink | Static syntax graph with `RUST_TOOLCHAIN_INVALID` and `RUST_HIR_TOOLCHAIN_UNSUPPORTED` | Fail-closed syntax fallback; never HIR-eligible |
| Cargo preflight rejects the input, mirror/DTO validation fails, or frozen/offline Cargo is unavailable | `CARGO_METADATA_FALLBACK`; static manifest, syntax graph, and file ledger are retained | Syntax fallback with a stable coverage reason; raw Cargo stderr and temporary paths are not exposed |
| Build script or proc macro is required | Unresolved site plus `BUILD_SCRIPT_NOT_EXECUTED` or `PROC_MACRO_NOT_EXECUTED` | Partial HIR only; never execute project code in safe mode |
| Typed HIR semantic-extractor failure | The node/site/edge/file-ledger delta is discarded atomically and the syntax graph is preserved with `RUST_HIR_BACKEND_FAILURE` | Partial coverage; never `semantic-complete` |
| HIR panic, timeout, or malformed internal result | Worker failure; it is not downgraded to syntax success | The core keeps other adapter results but does not relabel syntax as semantic success |
| Release-owned backend/sysroot bytes are missing or changed | The final package/release gate is not complete yet | Once closed, security failure occurs before analysis with no project/system fallback |

`syntax-complete` means all supported syntax dependency sites were classified.
It does not imply HIR resolution. A successfully emitted import/type/call graph
is also insufficient for `semantic-complete`: the final fallback/coverage
matrix must first be complete for the selected profile.

## Profile metadata

Every Rust profile records the following policy fields. Semantic-backend
values are outcome-dependent; fallback paths retain the syntax-only values.

| Property | Current value |
| --- | --- |
| `analysis` | `syntax+hir-imports-types-calls` after successful semantic extraction; otherwise `syntax` |
| `analysis_backend` | `static-syntax+rust-analyzer-hir` after successful semantic extraction; otherwise `static-syntax` |
| `rust_hir_backend` | `rust-analyzer-hir` when invoked; otherwise `disabled` |
| `rust_hir_status` | `import-type-call-graph-emitted`, `import-type-call-graph-partial`, `failed`, or `not-invoked` |
| `rust_hir_scaffold` | `available` |
| `rust_hir_project_model` | `ready` after deterministic construction; otherwise `not-invoked`, `unavailable`, or `unsupported` |
| `rust_hir_enable_gate` | `fallback-and-release-gates-pending` after import/type/call emission; `semantic-backend-failure` on typed failure; otherwise `semantic-emission-pending`, `toolchain-unsupported`, `crate-graph-unavailable`, or `input-unsupported` |
| `rust_hir_project_file_count` | Number of admitted inventory files in the safe VFS; `0` when no model is available |
| `rust_hir_project_crate_count` | Number of workspace/path local crates in the safe graph; `0` when no model is available |
| `rust_hir_project_external_count` | Number of external/sysroot sidecar entries; `0` when no model is available |
| `rust_hir_semantic_node_count` | Number of HIR nodes emitted by the current slice, including deterministic external/unresolved sentinels |
| `rust_hir_semantic_relation_count` | Number of semantic structural and dependency edges emitted by the current slice |
| `rust_hir_semantic_site_count` | Number of HIR-refined import/re-export, semantic type-use, and call sites |
| `rust_hir_semantic_call_site_count` | Number of semantic call sites, including exact, candidate, external, unresolved, and generated macro boundaries |
| `rust_hir_semantic_issue_count` | Number of recoverable semantic-extraction issues; nonzero yields `import-type-call-graph-partial` |
| `rust_hir_cfg_profile` | `debug-unwind`; cfg-affecting custom Cargo profile overrides are typed unsupported input |
| `rust_mode` | Selected safe project mode: `check`, `build`, or `test` |
| `rust_hir_integration_policy` | `pinned-rust-analyzer-library` |
| `rust_analyzer_version` | `0.0.330` |
| `rust_analyzer_revision` | `8954b66d43225e62c92e8bbcc8500191b5cceb1e` |
| `rust_analyzer_salsa_version` | `0.26.1` |
| `rust_toolchain_baseline` | `1.93.1` |
| `rust_toolchain_probe_status` | Raw neutral system probe: `compatible`, `unsupported`, or `unavailable` |
| `rust_hir_toolchain_status` | Effective HIR gate after combining the raw probe and project declaration |
| `rust_toolchain_declaration_status` | `absent`, `valid`, or fail-closed `invalid` |
| `rust_toolchain_observed` | Sanitized observed `rustc` / Cargo versions, commits, and hosts, or a bounded failure reason |
| `cargo_metadata_input` | `confined-mirror` |
| `crate_graph_source_policy` | `confined-cargo-metadata-or-static-manifest` |
| `crate_graph_source` | `confined-cargo-metadata`, `static-manifest-fallback`, or `none` |
| `syntax_fallback` | `enabled` |
| `build_script_policy` | `disabled` |
| `proc_macro_policy` | `disabled` |
| `project_code_executed` | `false` |
| `project_toolchain_executed` | `false` |
| `build_scripts_executed` | `false` |
| `proc_macros_executed` | `false` |

The profile records the selected rust-analyzer and Salsa versions, upstream
revision, neutral toolchain probe, confined crate-graph source, and semantic
graph status/counts. A future profile that claims exact standard-library
resolution must additionally record its effective sysroot version. Backend and
toolchain revisions that can change graph identity must participate in the
profile or evidence identity.

The profile records only the stable confined-metadata policy and status. It
never records the mirror root, mirror manifest path, temporary Cargo/Rustup
home, or temporary target directory. Those paths are execution details rather
than reproducibility inputs.

## Fallback contract

A recoverable project compatibility failure preserves the static nodes, sites,
edges, and file ledger. It emits a stable diagnostic, adds a stable coverage
reason, retains `syntax-complete` only if the syntax ledger is complete, and
omits `semantic-complete`. The scanner never silently drops a recognized site.
Preflight and DTO failures use repository-relative inventory paths and bounded
reason categories; raw Cargo stderr, mirror paths, and rejected external path
values do not become diagnostic messages or identities.

The HIR import/type/call graph requires a validated confined Cargo crate graph, so a
real metadata fallback intentionally omits HIR `symbol` / `type` nodes and
semantic nodes, sites, and relations. Metadata success and static fallback are
different analysis outcomes: because their effective crate/target models differ, neither
the full graph nor target/module syntax identities are required to match across
those outcomes. Each outcome remains checkout-independent and repeatable for
the same inputs. The missing semantic delta must be explicit in profile
properties, diagnostics, and coverage. Full HIR graph equality is required
only when the confined dependency snapshot, toolchain, requested profile, and
semantic capability are the same; the final cross-outcome fallback matrix is
tracked by Issue #29.

Integrity failures are different: the current core already treats a missing or
modified release-owned worker as a security error. Before the HIR semantic
backend is declared release-ready, its release gate must additionally reject
worker/backend version mismatches and release-root symlinks as security errors.
None of these cases may fall back to a project binary, system rust-analyzer, or
an unverified sysroot.

## Release and upgrade gate

The selected rust-analyzer libraries are statically linked into
`depgraph-rust-worker`, so the existing worker SHA-256 in
`release-manifest.json` is their executable integrity boundary. Exact
`ra_ap_*` packages must also appear in `Cargo.lock`, the SPDX SBOM, and the
third-party license inventory. Any non-linked sysroot or backend data must be a
named data-tree release component with a canonical whole-tree checksum;
missing, added, modified, or symlinked content must be rejected before the
worker starts. The current runtime-component schema requires an executable
entrypoint, so a `data-tree` kind with an optional entrypoint and matching
verifier must be added before shipping rust-src.

An upgrade changes the Rust baseline, rust-analyzer revision, and any bundled
sysroot as one compatibility unit. Before merging it must:

1. pin exact dependency versions and record the upstream revision;
2. build on every Tier 1 release target;
3. pass supported, older, newer, missing-toolchain, broken-source, cfg/feature,
   build-script, and proc-macro fixtures;
4. prove two identical scans have identical profiles, nodes, sites, edges,
   diagnostics, coverage, and output order;
5. prove marker files are absent and `project_code_executed=false`;
6. verify release worker/component checksums, SBOM, licenses, and fail-closed
   tamper cases.

## HIR implementation slices

The follow-up can be delivered in dependency order without crossing the safe
scan boundary:

1. **Completed 2026-07-17 — pin and smoke-test the backend:** exact `ra_ap_*`
   versions, upstream revision metadata, neutral Cargo/rustc version probes, a
   minimal in-memory HIR smoke test, SBOM/license assertions, and no project
   loading; prove absent toolchains cause no download or user/project write.
2. **Completed 2026-07-17 — confine Cargo input reads:** reject
   ambiguous/external workspace, path, patch, replace, glob, symlink, and
   unknown path-bearing input before Cargo starts; run metadata only against a
   neutral mirror of admitted manifests, lockfile, and target-discovery layout;
   map raw DTO paths back to inventory IDs; and prove temporary paths do not
   enter graph/profile/diagnostic identity. Semantic queries remained disabled
   in this slice.
3. **Completed 2026-07-17 — build the safe project model:** translate the
   admitted Cargo DTO, target, crate-scoped features, and target/test cfg values
   into a deterministic inventory-only VFS, local `CrateGraph`, and analysis
   database; retain external/sysroot and unsupported/incomplete inputs in the
   sidecar/diagnostic ledger while keeping sysroot source, project config,
   build scripts, and proc macros unloaded and unexecuted.
4. **Completed 2026-07-17 — emit the HIR definition graph:** add canonical
   `symbol` / `type` identities and semantic source evidence, then emit
   site-less `declares`, `extends`, `implements`, and `instantiates` relations
   as a strictly validated delta that is atomically unioned with the syntax
   graph. This slice did not emit dependency sites or claim `semantic-complete`.
5. **Completed 2026-07-17 — resolve imports and type uses:** emit leaf-level
   import/re-export and declaration/body type-use sites/edges with
   resolved/candidates/external/unresolved classification, canonical conditions,
   semantic/source evidence, syntax replacement keys, conservative source
   fallback, and an atomic file coverage ledger. Call sites and
   `semantic-complete` remain out of scope.
6. **Completed 2026-07-17 — resolve calls:** emit exact `calls` for statically
   unique function, associated-function, method, generic-instance, and closure
   targets; preserve complete finite closed-trait and immutable local
   function-pointer sets as candidate `may_call`; and retain external,
   unresolved, and call-bearing macro boundaries with canonical condition,
   span, evidence, provenance, and deterministic ordering.
7. **Issue #29 — harden fallback and determinism (1–2 days):** test unsupported
   toolchains, incomplete crate graphs, broken source, HIR failures, repeated
   scans, and preservation of the static graph; only this final semantic slice
   may establish the conditions for `semantic-complete`.
8. **Close the release gate (2–3 days):** make worker/backend version mismatch
   and release-root symlinks fail closed, add a data-tree component schema for
   any sysroot input, and run the armed security fixture from extracted Tier 1
   archives.
