# Rust worker

The Rust worker currently produces a deterministic static syntax graph. It
reads confined Cargo manifests, lockfiles, and Rust source, preflights every
Cargo-visible path, and constructs a worker-owned mirror containing only
admitted manifests, lockfiles, and target-discovery layout. It runs
`cargo metadata --format-version 1 --no-deps --frozen --offline` against the
mirror from a neutral working directory and falls back to its static manifest
model when preflight, mirror construction, the command, or DTO validation
fails. Rust source is parsed with `syn`. The worker links an exact-pinned
rust-analyzer library set and exposes an inventory-only HIR smoke scaffold, but
the production scan does not invoke that scaffold or emit semantic graph
events. Its profile therefore remains `analysis=syntax`,
`rust_hir_backend=disabled`, and `rust_hir_status=not-invoked`.

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
in profile or graph identity, diagnostics, evidence, or coverage. This closes
the Cargo read-confinement slice, but the DTO remains a syntax-inventory input:
the multi-file HIR project model and semantic emission are still follow-up
work.

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

The current scaffold lowers only caller-supplied, already-admitted UTF-8 bytes
through a virtual `/lib.rs`, a minimal in-memory `CrateGraph`, and a worker-owned
VFS. It does not discover a Cargo workspace, read repository files, load a
sysroot, start a process, enable proc macros, or emit protocol graph events.
The follow-up safe project model will construct the full rust-analyzer
`CrateGraph`, cfg set, and VFS from bytes and confined Cargo DTOs that the safe
scanner has already admitted. HIR results will then be emitted as semantic
evidence alongside, rather than in place of, the static syntax graph.

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

These implemented Cargo operations do not enable HIR. After the remaining safe
project-model and release gates are complete, HIR safe mode may additionally:

- consume the already-admitted manifests and source bytes to build an in-memory
  multi-file VFS, cfg set, and crate graph;
- expand declarative macros in memory when their input is completely known;
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
scaffold is available, and Cargo metadata input reads are confined. HIR
nevertheless stays disabled until the confined DTO is translated into a
compatible multi-file project model and the remaining semantic and release
gates are complete. A verified sysroot is additionally required only when the
profile claims standard-library resolution.

| Project/toolchain state | Current result | HIR eligibility after the remaining gates |
| --- | --- | --- |
| Exact `1.93.1`, supported target, and complete confined crate graph; verified sysroot when standard-library resolution is claimed | Static syntax graph plus a ready scaffold diagnostic; HIR is not invoked | Eligible for rust-analyzer `0.0.330` after the safe project-model and release gates pass |
| No project toolchain declaration | Static syntax graph using the worker baseline as metadata | Eligible only when every effective input is the verified baseline |
| Older, newer, or nightly declaration | `RUST_TOOLCHAIN_BEST_EFFORT`; static syntax graph | Syntax fallback; never `semantic-complete` |
| Custom or malformed declaration, unreadable file, or external symlink | Static syntax graph with `RUST_TOOLCHAIN_INVALID` and `RUST_HIR_TOOLCHAIN_UNSUPPORTED` | Fail-closed syntax fallback; never HIR-eligible |
| Cargo preflight rejects the input, mirror/DTO validation fails, or frozen/offline Cargo is unavailable | `CARGO_METADATA_FALLBACK`; static manifest, syntax graph, and file ledger are retained | Syntax fallback with a stable coverage reason; raw Cargo stderr and temporary paths are not exposed |
| Build script or proc macro is required | Unresolved site plus `BUILD_SCRIPT_NOT_EXECUTED` or `PROC_MACRO_NOT_EXECUTED` | Partial HIR only; never execute project code in safe mode |
| HIR panic, timeout, or malformed internal result | Not applicable while HIR is disabled | Worker failure; the core keeps other adapter results but does not relabel syntax as semantic success |
| Release-owned backend/sysroot bytes are missing or changed | Not applicable while HIR is disabled | Security failure before analysis; no project/system fallback |

`syntax-complete` means all supported syntax dependency sites were classified.
It does not imply HIR resolution. `semantic-complete` may be added only when the
selected profile finishes the pinned HIR pass without an incomplete input.

## Profile metadata

Every current Rust profile records the following policy fields. These are
runtime facts, not a claim that the future backend already ran.

| Property | Current value |
| --- | --- |
| `analysis` | `syntax` |
| `analysis_backend` | `static-syntax` |
| `rust_hir_backend` | `disabled` |
| `rust_hir_status` | `not-invoked` |
| `rust_hir_scaffold` | `available` |
| `rust_hir_enable_gate` | `safe-project-model-pending` for a compatible effective HIR toolchain status; otherwise `toolchain-unsupported` |
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
| `syntax_fallback` | `enabled` |
| `build_script_policy` | `disabled` |
| `proc_macro_policy` | `disabled` |
| `project_code_executed` | `false` |
| `project_toolchain_executed` | `false` |
| `build_scripts_executed` | `false` |
| `proc_macros_executed` | `false` |

The profile already records the selected rust-analyzer and Salsa versions,
upstream revision, and neutral toolchain probe. When HIR graph emission is
enabled, it must additionally record the effective sysroot version, confined
crate-graph source, and completed HIR status. Backend and toolchain revisions
that can change graph identity must also participate in the profile identity
or evidence identity.

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

Integrity failures are different: the current core already treats a missing or
modified release-owned worker as a security error. Before HIR is enabled, its
release gate must additionally reject worker/backend version mismatches and
release-root symlinks as security errors. None of these cases may fall back to
a project binary, system rust-analyzer, or an unverified sysroot.

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
   enter graph/profile/diagnostic identity. HIR remains disabled.
3. **Build the safe project model (2–3 days):** translate the admitted Cargo
   DTO/static model, target, features, and cfg values into an in-memory VFS and
   `CrateGraph`; keep build scripts, proc macros, project config, and toolchain
   execution disabled.
4. **Emit semantic identities (2–3 days):** add canonical Rust symbol/type
   identities, nodes, source spans, semantic evidence, and protocol contract
   tests while retaining syntax nodes and edges.
5. **Resolve imports and type uses (2–3 days):** emit import, re-export, and
   type-use sites/edges with exact/candidate/unresolved classification and a
   complete ledger.
6. **Resolve calls (2–3 days):** add exact direct-call edges and conservative
   candidate calls for dynamic dispatch, trait methods, closures, and function
   pointers.
7. **Harden fallback and determinism (1–2 days):** test unsupported toolchains,
   incomplete crate graphs, broken source, HIR failures, repeated scans, and
   preservation of the static graph without `semantic-complete`.
8. **Close the release gate (2–3 days):** make worker/backend version mismatch
   and release-root symlinks fail closed, add a data-tree component schema for
   any sysroot input, and run the armed security fixture from extracted Tier 1
   archives.
