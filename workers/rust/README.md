# Rust worker

The Rust worker currently produces a deterministic static syntax graph. It
reads confined Cargo manifests, lockfiles, and Rust source, attempts
`cargo metadata --format-version 1 --no-deps --frozen --offline` from a neutral
working directory, and falls back to its static manifest model when that
command is unavailable. Rust source is parsed with `syn`; rust-analyzer HIR is
not loaded or invoked in the current release.

The current Cargo path validates workspace members after Cargo returns. A
manifest such as `members = ["../outside"]` can therefore make Cargo read an
out-of-root manifest before the result is filtered. Current metadata remains a
best-effort syntax-inventory input and is not eligible for HIR. HIR stays
disabled until a preflight plus confined Cargo-visible input mirror prevents
that read. The current metadata command now sets `RUSTUP_AUTO_INSTALL=0`, but a
no-download/no-write gate for all future probes remains required.

## Selected semantic backend

The planned semantic backend is an exact-pinned set of rust-analyzer library
crates linked into `depgraph-rust-worker`. The worker will construct the
rust-analyzer `CrateGraph`, cfg set, and VFS from bytes and Cargo DTOs that the
safe scanner has already admitted. HIR results will be emitted as semantic
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

After the enable gates above are complete, HIR safe mode may:

- read regular files whose canonical paths remain inside the scan root;
- after a path/symlink preflight, run the resolved system `cargo` only against
  a confined mirror containing admitted manifests, lockfiles, and the source
  layout needed for target discovery (or safe explicit target placeholders),
  with known absolute paths rewritten to the mirror and unknown ones rejected;
- probe resolved system Cargo and rustc versions for the HIR enable gate using
  a neutral directory, cleared project environment, `RUSTUP_AUTO_INSTALL=0`,
  timeout, and output limit;
- parse manifests and source in the worker and build an in-memory crate graph;
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
best-effort outside that baseline. HIR is disabled until an exact
rust-analyzer revision and compatible crate-graph/toolchain inputs have passed
the release gate. A verified sysroot is additionally required only when the
profile claims standard-library resolution.

| Project/toolchain state | Current result | HIR eligibility after implementation |
| --- | --- | --- |
| Exact `1.93.1`, supported target, and complete crate graph; verified sysroot when standard-library resolution is claimed | Static syntax graph | Eligible for the pinned HIR backend |
| No project toolchain declaration | Static syntax graph using the worker baseline as metadata | Eligible only when every effective input is the verified baseline |
| Older, newer, or nightly declaration | `RUST_TOOLCHAIN_BEST_EFFORT`; static syntax graph | Syntax fallback; never `semantic-complete` |
| Custom or malformed declaration | Static syntax graph; the current parser may not emit a toolchain diagnostic | The HIR gate must emit `RUST_HIR_INPUT_UNSUPPORTED` and use syntax fallback |
| Cargo missing or frozen/offline metadata fails | `CARGO_METADATA_FALLBACK`; static manifest and syntax graph | Syntax fallback with `cargo-metadata-fallback` coverage reason |
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
| `rust_hir_integration_policy` | `pinned-rust-analyzer-library` |
| `rust_analyzer_revision` | `not-bundled` |
| `rust_toolchain_baseline` | `1.93.1` |
| `crate_graph_source_policy` | `cargo-metadata-or-static-manifest` |
| `syntax_fallback` | `enabled` |
| `build_script_policy` | `disabled` |
| `proc_macro_policy` | `disabled` |
| `project_code_executed` | `false` |
| `project_toolchain_executed` | `false` |
| `build_scripts_executed` | `false` |
| `proc_macros_executed` | `false` |

When HIR is implemented, the profile must record the actual pinned
rust-analyzer revision, effective Rust/sysroot version, crate-graph source, and
HIR status. Backend and toolchain revisions that can change graph identity must
also participate in the profile identity or evidence identity.

## Fallback contract

A recoverable project compatibility failure preserves the static nodes, sites,
edges, and file ledger. It emits a stable diagnostic, adds a stable coverage
reason, retains `syntax-complete` only if the syntax ledger is complete, and
omits `semantic-complete`. The scanner never silently drops a recognized site.

Integrity failures are different: the current core already treats a missing or
modified release-owned worker as a security error. Before HIR is enabled, its
release gate must additionally reject worker/backend version mismatches and
release-root symlinks as security errors. None of these cases may fall back to
a project binary, system rust-analyzer, or an unverified sysroot.

## Release and upgrade gate

The selected rust-analyzer libraries will be statically linked into
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

1. **Pin and smoke-test the backend (1 day):** add exact `ra_ap_*` versions,
   upstream revision metadata, neutral Cargo/rustc version probes, a minimal
   in-memory HIR smoke test, SBOM/license assertions, and no project loading;
   prove absent toolchains cause no download or user/project write.
2. **Confine Cargo input reads (1–2 days):** reject ambiguous/external
   workspace, path, patch, replace, glob, symlink, and unknown absolute paths,
   then run metadata only against a mirror of admitted manifests, lockfile, and
   target-discovery layout while mapping temporary paths back to inventory IDs.
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
