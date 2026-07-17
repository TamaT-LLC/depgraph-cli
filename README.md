# depgraph

`depgraph` is a local-first CLI that extracts explainable dependency graphs from Rust, Go, TypeScript/JavaScript, Next.js, Astro, TanStack Router, and TanStack Start repositories.

Every recognized dependency site is retained as `resolved`, `candidates`, `external`, or `unresolved`. Edges carry their profile, canonical condition, precision, and source evidence; condition-specific package targets retain their own edge condition. Skipped and unsupported input is reported through the coverage ledger rather than silently dropped.

The MVP implements the architecture described in [the system design](docs/40_arch_design/arch-dependency-graph-cli-system-design.md): a Rust core, isolated Rust/Go/Web workers using protocol `1.0` NDJSON, an immutable SQLite evidence store, graph queries, and deterministic JSON/DOT/Mermaid export.

## Supported MVP graph

- Cargo workspace/package/target/dependency and Rust file/module/import/re-export,
  HIR symbol/type/type-use, exact call, and conservative candidate call sites
- Go workspace/module/package variant/file/import, symbol/type/direct call/candidate call, build constraint, test, embed, generated, vendor, and cgo sites
- npm/pnpm/Yarn/Bun workspace/package/file and ESM/CJS/type-only/dynamic import sites
- Next.js App/Pages filesystem routes
- Astro pages/endpoints and frontmatter imports
- TanStack file routes and existing generated route trees

Rust HIR final fallback/coverage handling is complete. A profile claims
`semantic-complete` only when syntax coverage is complete, the exact compatible
HIR backend uses confined Cargo metadata with a ready project model and an
emitted graph, the semantic issue count is zero, and skipped, unsupported, and
unresolved counts are all zero. Candidate and external sites are allowed. The
successful profile remains `rust_hir_enable_gate=release-gate-pending`: Issue
#30 package/release verification is not implemented, so this is not a
release-ready claim. Web symbol/type/call analysis, code-based routes, server
functions, build observation, runtime traces, incremental updates, snapshots,
and architecture policies belong to later milestones.

## Build

The pinned development baseline is Rust 1.93.1, Go 1.26.1, Node.js 24.18.0, and pnpm 10.33.0.

```sh
cargo xtask build
```

This builds `target/debug/depgraph`, the Rust and Go worker binaries, and the bundled Web worker. The Web worker contains TypeScript 7.0.2 but requires the supported Node.js runtime.

To run every formatting, lint, contract, worker, and fixture test:

```sh
cargo xtask test
```

## Usage

```sh
# Optional tracked configuration. Scan works without it.
depgraph init .

# Safe static scan. The target repository is not modified.
depgraph scan /path/to/repository
depgraph scan /path/to/repository --strict

depgraph doctor --json
depgraph deps path:src/app.ts --transitive
depgraph dependents package:example
depgraph why path:src/app.ts route:/products/$id
depgraph cycles --level file

# Go semantic graph queries use canonical resolver identities.
depgraph deps symbol:example.com/semantic/model.Build --transitive
depgraph dependents type:example.com/semantic/model.Worker --json
depgraph why symbol:example.com/semantic/model.Build type:example.com/semantic/model.Input --json
depgraph cycles --level symbol

# If a selector is ambiguous, rerun it with a stable ID from the candidates.
depgraph deps "id:$STABLE_ID" --json

depgraph unresolved --json
depgraph export --format json --output graph.json
depgraph export --format dot > graph.dot
depgraph export --format mermaid > graph.mmd
```

SQLite is stored under the operating system cache directory, keyed by the canonical repository root. Use global `--store PATH` for a specific database and global `--scan-id ID` to inspect a retained partial scan. Queries default to the latest successful scan; `doctor` reports the latest attempt.

Selectors accept `id:`, `path:`, `package:`, `route:`, `symbol:`, and `type:` prefixes. `symbol:` and `type:` only match their respective node kind. A bare or prefixed selector must resolve unambiguously; when candidates are reported, copy the complete stable ID (for example `symbol:sha256:...`) and retry as `id:<stable-id>`.

## Safe-scan boundary

The default scan reads source, manifests, lockfiles, static JSON/JSONC configuration, and existing generated files. It does not execute project configuration, plugins, package managers, generators, build scripts, proc macros, or project-local TypeScript. The Web worker uses bundled TypeScript. Go requests typed syntax and type information through `go/packages` with networking, telemetry, external drivers, cgo, toolchain download, and repository writes disabled, then retains the standard-parser inventory as its fallback. Cargo metadata is attempted only in frozen/offline/no-deps mode against a preflighted, worker-owned input mirror from a neutral working directory.

Worker and toolchain lookup uses a canonical absolute `PATH`: relative entries, the scan root, and symlink aliases into the scan root are removed. Child environments omit execution hooks such as `NODE_OPTIONS`; direct reads resolve symlinks and remain confined to the canonical repository root. Release workers and runtime assets are checksum verified, and packaged builds fail closed when their manifest or bundled layout is missing.

Executable or unsupported configuration becomes a diagnostic or unresolved site. `project_code_executed` remains `false` in worker profiles, coverage, stored scans, and `doctor` output. Security fixtures contain configs/generators that would create marker files if they were executed.

## Strict policy and exit codes

The default `.depgraph.toml` strict policy permits zero skipped files, unsupported syntax, or unresolved sites. Candidate and external dependencies alone do not fail strict mode.

A typed Rust HIR backend failure atomically discards the semantic delta,
preserves the syntax graph, and fails strict policy. A Rust worker panic,
timeout, cancellation, or malformed protocol result leaves the overall scan
partial with exit code `3`.

| Code | Meaning |
| ---: | --- |
| 0 | Operation completed without a policy violation |
| 1 | Graph or coverage policy violation |
| 2 | CLI usage, selector, or configuration error |
| 3 | Worker, toolchain, graph validation, or protocol failure |
| 4 | Project-code execution permission or security-policy failure |

Failed/partial scans and diagnostics remain stored, but only a complete policy-passing scan advances the `latest successful` pointer.

## Repository layout

- `crates/depgraph-protocol`: typed protocol, canonical conditions/IDs, JSON Schema, and state-machine validation
- `crates/depgraph-store`: SQLite migrations, immutable scan staging, ledger, and evidence persistence
- `crates/depgraph-core` / `crates/depgraph-cli`: worker supervision, queries, export, doctor, and CLI UX
- `workers/rust`, `workers/go`, `workers/web`: ecosystem-native safe static adapters
- `xtask`: reproducible build, full quality checks, release archives, checksums, SBOM, and license inventory

Run `cargo xtask package` to create a native archive under `dist/`. Release archives place `depgraph` under `bin/`, compatible workers under `libexec/`, and include a checksum-verified release manifest, protocol schema, SPDX SBOM, and third-party license inventory.

The Issue #30 Rust HIR package/release verifier remains unimplemented; package
creation alone does not make the HIR backend release-ready.
