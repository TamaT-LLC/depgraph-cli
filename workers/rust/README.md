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
graph. The final fallback/coverage matrix is complete, and an eligible profile
can now claim `semantic-complete` only when a core-attested bundled sysroot is
also present and every dependency site is exact-resolved. Source/development
execution intentionally retains `rust_hir_enable_gate=release-gate-pending`,
reports the sysroot unavailable, and never claims semantic completeness. After
core verifies the extracted archive, exact Rust backend, and complete sysroot
data tree, the packaged worker receives `release-gate-verified` and the
canonical sysroot root as its release-ready input.

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
edition plus feature, target, and test cfg per crate. Registry, git, unmodeled
path, and build dependencies stay in a deterministic sidecar sentinel ledger.
For a core-attested packaged release only, the pinned bundled `core`, `alloc`,
and `std` inventories enter a separate library VFS and crate graph; otherwise
sysroot dependencies also remain sentinels. Local dependency injection follows
the effective crate root: ordinary crates receive `std` and `core`, `no_std`
crates receive `core`, and `alloc`/an explicitly restored `std` are added only
for an active root-level `extern crate`. `no_core` fails closed because its
lang-item environment is outside the safe model. Custom targets, build scripts,
proc-macro targets, incomplete crate models, and static Cargo fallback remain
explicit diagnostic/coverage entries.

Neither path discovers a Cargo workspace or reads a repository file on demand.
The project model does not load `rust-project.json`, `.cargo/config*`, project
or system sysroot/registry source, build output, or proc-macro libraries, and
it does not run build scripts or child processes. The only admitted
non-repository source is the core-verified bundled sysroot data tree. The
implemented semantic pass emits stable named/local and bundled-sysroot symbol
and type identities, definition relations, HIR-resolved import/re-export and
`extern crate` sites, signature/field/bound/type-alias/body `type_uses`, and
exact/candidate call sites into an isolated delta. Each HIR-refined dependency
keeps semantic primary evidence plus its supporting syntax evidence. The
scanner validates nodes, sites, edges, and file coverage together before
unioning the delta with the static syntax graph.
Recognized type occurrences that cannot enter the exact delta remain once as
source-phase fallback sites. The fallback resolver recognizes standard-prelude
types and manifest dependencies as external/heuristic, and may emit a
source-backed `type` node with resolved/heuristic status when an explicit path
or module-scope import matches a condition-compatible local declaration.
The vocabulary follows the crate edition and fails closed for `no_std` and
`no_implicit_prelude`; an explicit local declaration is checked before a
prelude or dependency root. Everything else remains unresolved with its
original span. A call that cannot
be proved exact or represented by a complete, finite candidate set remains
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
validated, including recursive `all` / `any` / single-operand `not` arity.
Other built-in attributes remain explicit `unsupported_attribute` boundaries
until their shape, value, and placement have an attribute-specific validator;
generic `syn::Meta` parse success alone never permits `semantic-complete`. A
declarative macro expansion that contains calls is retained as one
generated, unresolved call boundary at the invocation span with macro
provenance; generated calls are not individually up-mapped to ordinary source
calls. Name resolution and cfg created by expansion remain explicit
unsupported or unresolved coverage boundaries unless the safe inputs classify
them exactly.

`rust_hir_project_model=ready` means the atomic VFS, crate graph, and cfg input
were constructed. Semantic extraction success is reported separately as
`rust_hir_status=import-type-call-graph-emitted` or
`import-type-call-graph-partial`. A profile claims `semantic-complete` only
when it also has `syntax-complete`, uses the exact compatible HIR backend and
`confined-cargo-metadata`, has a `ready` project model and
`import-type-call-graph-emitted` status, records
`rust_hir_semantic_issue_count=0`, and reports zero skipped files, unsupported
syntax, and unresolved sites. Candidate and external sites are classified
outcomes and do not block completeness. Missing modules and includes remain
unresolved syntax sites with coverage reasons and therefore do block it.

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

The completed safe project-model, definition, dependency, and fallback slices
now:

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
  retain each matching source-phase file/package import projection alongside
  its HIR-refined module/symbol occurrence, without duplicating either phase;
- preserve canonical cfg/feature/target conditions, semantic primary evidence,
  supporting source evidence, and direct-source macro provenance, then atomically
  union the validated node/site/edge/file-ledger delta with the syntax graph.

Block-local aliases are kept out of the file/module import index, so they
cannot leak into another lexical scope. The fallback recognizes the fixed
standard-prelude vocabulary only as heuristic and checks an explicit local
declaration or module-scope import first. Exact HIR continues to replace those
fallback sites whenever the compatible semantic backend is available.

Unsupported toolchain/edition/target input, confined metadata fallback, broken
source or attribute payloads, missing modules/includes, nested `OUT_DIR`
includes/environment macros, build scripts, proc macros, unverified bang-macro
identity, and unavailable external definitions all receive deterministic
diagnostic/coverage or dependency-site ledger entries. A typed semantic backend
failure discards the complete semantic delta atomically, preserves the syntax
graph, and is a strict-policy failure. A panic, timeout, cancellation, or
malformed worker result is a worker failure; the core preserves other adapter
results and records the overall scan as partial with exit code `3`.

Issue #146 ships the Rust `1.93.1` standard-library source from the pinned
`rust-src` component as the whole-tree-checked `rust-stdlib-source` `data-tree`.
Its release identity includes rustc commit
`01f6ddf7588f42ae2d7eb0a2f21d44e8e96674cf`, normalized layout, root, license,
SBOM package, and complete-tree digest. Missing, added, modified, symlinked, or
toolchain-mismatched content fails closed. Issue #147 consumes that tree only
after core attestation, rechecks its pinned `SOURCE.json`, maps `core`, `alloc`,
and `std` into deterministic library VFS/crate roots, and emits exact
standard-library symbol/type/import/type-use/direct-call nodes and edges with
attested source paths. Development, mismatched, missing, or unsupported-target
execution preserves syntax/local HIR output without `semantic-complete`;
neither path falls back implicitly to project or system backend/sysroot bytes.

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
best-effort outside that baseline. The worker records the neutral host-default
`rustc` and Cargo observation, but HIR eligibility does not depend on that
default remaining pinned. It first asks Rustup for the already-installed exact
`1.93.1` pair with `RUSTUP_AUTO_INSTALL=0`, confines both paths to the external
Rustup toolchain store, and verifies release, commit, host, and executable
SHA-256 before and after confined Cargo metadata. It falls back to the neutral
host pair only when that pair itself is the exact baseline. No toolchain is
downloaded or switched. The rust-analyzer revision is statically linked and
attested, Cargo metadata input reads are confined, and the same effective pair
identity participates in the semantic cache key. A verified bundled `rust-src`
tree is additionally required for exact standard-library resolution and
`semantic-complete`.

| Project/toolchain state | Current result | Semantic completeness / release status |
| --- | --- | --- |
| Exact `1.93.1`, supported target, complete confined crate graph, and core-attested bundled sysroot | Static syntax graph plus HIR definitions, refined imports/re-exports/`extern crate`, `type_uses`, exact/candidate calls, and exact `std` / `core` / `alloc` targets | `semantic-complete` only with `syntax-complete`, exact compatible HIR, confined metadata, attested sysroot, `ready` / `emitted`, issue count `0`, and skipped / unsupported / candidates / external / unresolved all `0`; source/development runs retain syntax/local HIR but never promote an unattested sysroot |
| No project toolchain declaration, newer host default, exact baseline already installed | The raw host observation remains visible, while the installed verified pair emits the import/type/call graph | Eligible when the effective pair and every other completeness input are verified |
| No compatible installed or host-default pair | Static syntax graph with `RUST_HIR_TOOLCHAIN_UNSUPPORTED` and the exact `rustup toolchain install 1.93.1 --profile minimal --component rust-src` remediation | Syntax fallback; Rustup auto-install remains disabled |
| Older, newer, or nightly declaration | `RUST_TOOLCHAIN_BEST_EFFORT`; static syntax graph | Syntax fallback; never `semantic-complete` |
| Custom or malformed declaration, unreadable file, or external symlink | Static syntax graph with `RUST_TOOLCHAIN_INVALID` and `RUST_HIR_TOOLCHAIN_UNSUPPORTED` | Fail-closed syntax fallback; never HIR-eligible |
| Cargo preflight rejects the input, mirror/DTO validation fails, or frozen/offline Cargo is unavailable | `CARGO_METADATA_FALLBACK`; static manifest, syntax graph, and file ledger are retained | Syntax fallback with a stable coverage reason; raw Cargo stderr and temporary paths are not exposed |
| A built-in attribute has no attribute-specific shape/value/placement validator | `unsupported_attribute` site plus `RUST_ATTRIBUTE_UNSUPPORTED`; nested expression-shaped macro arguments are still inventoried | Conservative incomplete ledger; generic `Meta` parsing never proves compiler validity |
| An unqualified bang macro or derive identity cannot be proven built-in/non-procedural | Generic `macro_expansion` or `proc_macro_expansion` unresolved site; nested expression-shaped `include!` / `env!` arguments are inventoried recursively | Conservative incomplete ledger; names are not trusted because local/imported macros can shadow built-ins |
| `#![no_std]`, active `cfg_attr(..., no_std)`, or `#![no_core]` changes implicit sysroot injection | `no_std` receives only `core` plus active root-level explicit sysroot crates; `no_core` keeps syntax output and rejects the HIR project model | Never attach `std`/`alloc` merely because the bundled crates exist; unsupported `no_core` never claims `semantic-complete` |
| `OUT_DIR` include, build script, or proc macro is required | Unresolved site plus `RUST_HIR_OUT_DIR_UNAVAILABLE`, `BUILD_SCRIPT_NOT_EXECUTED`, or `PROC_MACRO_NOT_EXECUTED` | Ledgered partial HIR only; never execute or read generated project output in safe mode |
| External definition is unavailable | Classified external or unresolved site plus stable coverage evidence | Analysis continues, but either classification blocks `semantic-complete` |
| Typed HIR semantic-extractor failure | The node/site/edge/file-ledger delta is discarded atomically and the syntax graph is preserved with `RUST_HIR_BACKEND_FAILURE` | Strict-policy failure; never `semantic-complete` |
| HIR panic, timeout, cancellation, or malformed result | Worker failure; it is not downgraded to syntax success | Other adapter results remain, but the scan is partial with exit `3` |
| A release artifact/component is missing, changed, added to a checked tree, or symlinked; or the Rust backend manifest/handshake differs | The package verifier and core attestation reject the archive before analysis | `security_failed`, exit `4`, and no development/project/system backend or sysroot fallback |

`syntax-complete` means all supported syntax dependency sites were classified.
It does not imply HIR resolution. The complete condition is the conjunction of
`syntax-complete`, exact compatible HIR, `confined-cargo-metadata`, a `ready`
project model, `import-type-call-graph-emitted`, semantic issue count `0`,
`project_code_executed=false`, and zero skipped, unsupported, and unresolved
counts, with an attested three-crate sysroot and zero candidate/external sites.
A source/development result is still `release-gate-pending`, retains syntax and
local HIR analysis, and deliberately does not claim `semantic-complete`; only a
core-attested packaged worker receives `release-gate-verified`.

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
| `rust_hir_enable_gate` | `release-gate-pending` after successful source/development emission; `release-gate-verified` only when core has verified the packaged manifest, worker/backend unit, and bundled sysroot data tree; `semantic-backend-failure` on typed failure; otherwise `semantic-emission-pending`, `toolchain-unsupported`, `crate-graph-unavailable`, or `input-unsupported` |
| `rust_hir_project_file_count` | Number of admitted inventory files in the safe VFS; `0` when no model is available |
| `rust_hir_project_crate_count` | Number of workspace/path local crates in the safe graph; `0` when no model is available |
| `rust_hir_project_external_count` | Number of external sidecar entries, including sysroot sentinels when no attested sysroot is admitted; `0` when none or no model is available |
| `rust_hir_sysroot_status` | `attested` only after the verified handoff and pinned source-identity/inventory checks; otherwise `pending`, `unavailable`, or `not-invoked` |
| `rust_hir_sysroot_file_count` | Number of bounded UTF-8 `.rs` files in the admitted `core` / `alloc` / `std` inventory |
| `rust_hir_sysroot_crate_count` | `3` for the admitted `core` / `alloc` / `std` crate graph; otherwise `0` |
| `rust_hir_sysroot_contract_version` | `rust-src-data-tree-v1` |
| `rust_hir_sysroot_component_version` | `1.93.1+rustc.01f6ddf7588f42ae2d7eb0a2f21d44e8e96674cf` |
| `rust_hir_sysroot_source_layout` | `rustup-rust-src-library-v1` |
| `rust_hir_semantic_node_count` | Number of HIR nodes emitted by the current slice, including deterministic external/unresolved sentinels |
| `rust_hir_semantic_relation_count` | Number of semantic structural and dependency edges emitted by the current slice |
| `rust_hir_semantic_site_count` | Number of HIR-refined import/re-export, semantic type-use, and call sites |
| `rust_hir_semantic_call_site_count` | Number of semantic call sites, including exact, candidate, external, unresolved, and generated macro boundaries |
| `rust_hir_semantic_issue_count` | Number of recoverable semantic-extraction issues; nonzero yields `import-type-call-graph-partial` |
| `rust_hir_active_cfg_by_crate` | Canonical crate-identity-to-active-cfg map shared by HIR evidence; semantic evidence refers to this profile property through `active_cfg_source` instead of repeating the same cfg vector per record |

### Performance audit

`DEPGRAPH_SCAN_PROFILE=1 depgraph scan <root> --no-cache --json` adds an
attempt-local top-level `performance.phases` report. It is not stored in the
profile or canonical graph, so elapsed time cannot perturb graph IDs,
determinism, cache identity, or exports. The Rust worker reports confined
discovery/metadata, syntax graph, model planning, VFS bytes, crate graph,
database apply, HIR semantic walk, source finalization, protocol build/write,
event counts, and protocol bytes. Core adds worker wall time, protocol ingest,
SQLite validation/promotion time and database bytes, and total scan wall time.
HIR occurrence indexes borrow the source inventory, and crate-level active cfg
is stored once in `rust_hir_active_cfg_by_crate`; this bounds cloning and wire
size without dropping the cfg context addressable from each evidence record.

`scripts/benchmark-mvp.sh` exercises those phases against the deterministic
31-source-file Rust fixture in cold-store, `--no-cache`, and validated warm-hit
modes. Cold and no-cache scans share the existing 10-second ceiling, warm scan
has a 4-second ceiling / 2-second product target, and their canonical graph,
coverage, diagnostics, safety ledger, and project-code execution flag must
remain equal.
| `rust_hir_cfg_profile` | `debug-unwind`; cfg-affecting custom Cargo profile overrides are typed unsupported input |
| `rust_mode` | Selected safe project mode: `check`, `build`, or `test` |
| `rust_hir_integration_policy` | `pinned-rust-analyzer-library` |
| `rust_analyzer_version` | `0.0.330` |
| `rust_analyzer_revision` | `8954b66d43225e62c92e8bbcc8500191b5cceb1e` |
| `rust_analyzer_salsa_version` | `0.26.1` |
| `rust_toolchain_baseline` | `1.93.1` |
| `rust_toolchain_probe_status` | Raw neutral system probe: `compatible`, `unsupported`, or `unavailable` |
| `rust_hir_toolchain_status` | Effective HIR gate after combining the raw probe and project declaration |
| `rust_hir_toolchain_selection` | `installed-verified-baseline`, `host-default`, or fail-closed `unavailable` |
| `rust_hir_toolchain_attestation` | Selection contract plus exact rustc/Cargo release, commit, host, and executable SHA-256; contains no absolute path |
| `rust_hir_toolchain_remediation` | `null` when eligible; otherwise an executable install or declaration-repair action |
| `rust_toolchain_declaration_status` | `absent`, `valid`, or fail-closed `invalid` |
| `rust_toolchain_observed` | Sanitized observed `rustc` / Cargo versions, commits, and hosts, or a bounded failure reason |
| `cargo_metadata_input` | `confined-mirror` |
| `crate_graph_source_policy` | `confined-cargo-metadata-or-static-manifest` |
| `crate_graph_source` | `confined-cargo-metadata`, `static-manifest-fallback`, or `none` |
| `syntax_fallback` | `enabled` |
| `rust_syntax_fallback_summary` | `rust-syntax-fallback-summary-v1`: deterministic `syntax_proven` / `hir_required` / `macro_execution_required` counts, site-kind counts, unresolved-kind counts, and separate remediation |
| `build_script_policy` | `disabled` |
| `proc_macro_policy` | `disabled` |
| `proc_macro_expansion` | `disabled` |
| `project_code_executed` | `false` |
| `project_toolchain_executed` | `false` |
| `build_scripts_executed` | `false` |
| `proc_macros_executed` | `false` |

The profile records the selected rust-analyzer and Salsa versions, upstream
revision, neutral toolchain probe, confined crate-graph source, semantic graph
status/counts, and the effective bundled-sysroot contract/component/layout.
Backend, toolchain, and sysroot revisions that can change graph identity
participate in profile or canonical semantic identity.

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

Occurrence-heavy macro, proc-macro, unsupported-attribute, unsupported
macro-argument, and build-environment warnings use
`rust-fallback-diagnostic-summary-v1`. One diagnostic is emitted per stable
code/site-kind/resolution-class cause. Its JSON properties retain the complete
site-set count/digest, bounded per-path counts/digest, total count, distinct
HIR-vs-macro remediation, and at most five representative site IDs and source
evidence records. Every affected site carries the same stable diagnostic-group
key, so the relationship and every source span remain authoritative without
making one diagnostic line grow with occurrence count.
`RUST_SYNTAX_FALLBACK_SUMMARY` exposes the same cause classification in both
human output and JSON diagnostics.

The HIR import/type/call graph requires a validated confined Cargo crate graph, so a
real metadata fallback intentionally omits HIR `symbol` / `type` nodes and
semantic nodes, sites, and relations. Metadata success and static fallback are
different analysis outcomes: because their effective crate/target models differ, neither
the full graph nor target/module syntax identities are required to match across
those outcomes. Each outcome remains checkout-independent and repeatable for
the same inputs. The missing semantic delta must be explicit in profile
properties, diagnostics, and coverage. Full HIR graph equality is required
only when the confined dependency snapshot, toolchain, requested profile, and
semantic capability are the same. Issue #29 fixed this cross-outcome fallback
matrix and requires repeated scans and equivalent checkouts to produce the same
profile, graph, diagnostics, ledger, and canonical ordering within each
effective outcome.

A typed recoverable HIR failure discards every semantic node, site, edge, and
file-ledger delta atomically and records `rust-hir-backend-failure`; strict mode
fails even if configured skipped/unsupported/unresolved thresholds would
otherwise pass. Panic, timeout, cancellation, and malformed worker output are
process/protocol failures instead and make the scan partial with exit `3`.

Integrity failures are different: the package verifier and core attestation
treat a missing, added, modified, or symlinked release artifact/component,
release-root symlink, and worker/backend manifest or handshake mismatch as a
security error before analysis. The verified core alone injects the exact
`release-gate-verified` value into the packaged Rust worker. None of these cases
falls back to a development/project binary, system rust-analyzer, or an
unverified sysroot.

## Release and upgrade gate

The selected rust-analyzer libraries are statically linked into
`depgraph-rust-worker`, so the existing worker SHA-256 in
`release-manifest.json` is their executable integrity boundary. Exact
`ra_ap_*` packages must also appear in `Cargo.lock`, the SPDX SBOM, and the
third-party license inventory. Any non-linked sysroot or backend data must be a
named data-tree release component with a canonical whole-tree checksum;
missing, added, modified, or symlinked content must be rejected before the
worker starts. The implemented runtime-component schema distinguishes an
`executable-tree`, which requires an executable entrypoint, from a `data-tree`,
whose entrypoint is optional. The current archive includes the pinned Rust
`1.93.1` `rust-src` library tree at `libexec/rust-sysroot`, records its complete
license/SBOM identity, and never searches for project or system replacements.

An upgrade changes the Rust baseline, rustc/Cargo commit matrix,
rust-analyzer revision, and bundled sysroot as one compatibility unit. Patch
releases may add an exact stable row only with its full cross-platform
attestation and fixtures; they never accept a release range or floating
channel. Before merging an upgrade it must:

1. pin exact dependency versions and record the upstream revision;
2. build on every Tier 1 release target and the Windows package target;
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
   `semantic-complete` were out of scope for this slice and were completed by
   Issues #28 and #29.
6. **Completed 2026-07-17 — resolve calls:** emit exact `calls` for statically
   unique function, associated-function, method, generic-instance, and closure
   targets; preserve complete finite closed-trait and immutable local
   function-pointer sets as candidate `may_call`; and retain external,
   unresolved, and call-bearing macro boundaries with canonical condition,
   span, evidence, provenance, and deterministic ordering.
7. **Completed 2026-07-17 — harden fallback and determinism (Issue #29):**
   classify unsupported toolchains, incomplete crate graphs, broken source,
   `OUT_DIR`, build/proc/external boundaries, and HIR failures; preserve the
   static graph atomically; prove repeated-scan/checkout determinism; and permit
   `semantic-complete` only under the exact zero-issue/zero-gap conditions.
8. **Completed 2026-07-19 — close the package/release gate (Issue #30):**
   fail closed on every artifact/component or backend attestation mismatch and
   symlink; support executable-tree/data-tree components; verify extracted
   archive query/export/determinism E2E and complete rust-analyzer/Salsa
   SBOM/license closure; and run Tier 1, Windows, and benchmark gates. Source
   builds remain `release-gate-pending`; only core-attested archives emit
   `release-gate-verified`.
9. **Completed 2026-07-25 — package the Rust sysroot (Issue #146):** normalize
   the exact Rust `1.93.1` `rust-src` library tree into a licensed/SBOM-recorded
   data-tree compatibility unit, pin its source identity and complete-tree
   digest, and reject missing, added, tampered, symlinked, or cross-target
   inconsistent inputs before worker launch.
10. **Completed 2026-07-25 — resolve the attested sysroot (Issue #147):** pass
    only core-verified sysroot roots into the packaged worker, revalidate the
    compatibility identity and bounded inventory, create separate
    `core`/`alloc`/`std` library VFS and crate roots, emit exact
    symbol/type/import/type-use/direct-call edges, and prove fallback plus
    repeated packaged-scan/export determinism.
