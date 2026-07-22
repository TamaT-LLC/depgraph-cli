# depgraph

`depgraph` is a local-first CLI that extracts explainable dependency graphs from Rust, Go, TypeScript/JavaScript, Next.js, Astro, TanStack Router, and TanStack Start repositories.

Every recognized dependency site is retained as `resolved`, `candidates`, `external`, or `unresolved`. Edges carry their profile, canonical condition, precision, and source evidence; condition-specific package targets retain their own edge condition. Skipped and unsupported input is reported through the coverage ledger rather than silently dropped.

The MVP implements the architecture described in [the system design](docs/40_arch_design/arch-dependency-graph-cli-system-design.md): a Rust core, isolated Rust/Go/Web workers using protocol `1.0` NDJSON, an immutable SQLite evidence store, graph queries, and deterministic JSON/DOT/Mermaid export.

The current Milestone 2 prerelease is [`v0.2.0-rc.1`](docs/releases/v0.2.0-rc.1.md).

## Supported MVP graph

- Cargo workspace/package/target/dependency and Rust file/module/import/re-export,
  HIR symbol/type/type-use, exact call, and conservative candidate call sites
- Go workspace/module/package variant/file/import, symbol/type/direct call/candidate call, build constraint, test, embed, generated, vendor, and cgo sites
- npm/pnpm/Yarn/Bun workspace/package/file plus TypeScript/JavaScript symbol/type/import/re-export/type-use, exact call, and conservative candidate call sites
- Next.js App/Pages routes, route components, render and parent-route relations, client/server boundaries, and statically resolvable dynamic components
- Astro pages/endpoints, component render relations, hydration boundaries, frontmatter imports, content collections, and assets
- TanStack Router file/code/virtual routes, generated route trees, loaders, `beforeLoad`, lazy routes, context, and route masks
- TanStack Start server functions, RPC relations, server routes, and middleware chains

Rust HIR final fallback/coverage handling is complete. A profile claims
`semantic-complete` only when syntax coverage is complete, the exact compatible
HIR backend uses confined Cargo metadata with a ready project model and an
emitted graph, the semantic issue count is zero, and skipped, unsupported, and
unresolved counts are all zero. Candidate and external sites are allowed.
Source/development builds intentionally report
`rust_hir_enable_gate=release-gate-pending`. After the core verifies an
extracted release archive, including its Rust backend attestation, it starts the
packaged worker with `release-gate-verified`; only that attested path may emit a
release-ready profile. Issue #30 package/release verification was completed on
2026-07-19. A Web profile can likewise claim `semantic-complete` only with the
bundled isolated compiler, a ready/emitted v2 graph, zero skipped, unsupported,
unresolved, semantic-issue, and compiler diagnostic counts, and
`project_code_executed=false`. Candidate and external Web sites are allowed.
Detected Next.js, Astro, TanStack Router, and TanStack Start profiles must also
complete their versioned framework semantic capability ledger. Code-based
routes beyond the safe static boundary, framework-specific build observers,
runtime traces, incremental updates, snapshot diff CLI/impact, and architecture policies
remain later milestones. The supervised build protocol and atomic evidence
union foundation are available separately under the explicit-consent boundary.

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

# Privileged build-observation consent form.
depgraph resolve --build /path/to/repository --allow-project-code

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

# Name and inspect immutable completed snapshots.
depgraph snapshot create baseline
depgraph snapshot list --json
depgraph snapshot show baseline
depgraph snapshot show snapshot:sha256:... --json

depgraph export --format json --output graph.json
depgraph export --format dot > graph.dot
depgraph export --format mermaid > graph.mmd
```

SQLite is stored under the operating system cache directory, keyed by the canonical repository root. Use global `--store PATH` for a specific database and global `--scan-id ID` to inspect a retained partial scan. Queries default to the latest successful scan; `doctor` reports the latest attempt.

`snapshot create` names the current completed snapshot; global `--scan-id ID` may instead select the completed snapshot produced by that scan and its latest promoted build. Failed or incomplete attempts cannot be named. Names are immutable, case-insensitively unique, 1–64 ASCII characters, begin with a letter or digit, and otherwise use letters, digits, `.`, `_`, or `-`. `current` and `latest` are reserved, and existing names are never overwritten. `snapshot show` accepts a name, a `snapshot:sha256:...` stable ID, or `current`. List and detail JSON are emitted in canonical order.

Selectors accept `id:`, `path:`, `package:`, `route:`, `symbol:`, and `type:` prefixes. `symbol:` and `type:` only match their respective node kind. A bare or prefixed selector must resolve unambiguously; when candidates are reported, copy the complete stable ID (for example `symbol:sha256:...`) and retry as `id:<stable-id>`.

## Safe-scan boundary

The default scan reads source, manifests, lockfiles, static JSON/JSONC configuration, and existing generated files. It does not execute project configuration, plugins, package managers, generators, build scripts, proc macros, or project-local TypeScript. The Web worker uses bundled TypeScript. Go requests typed syntax and type information through `go/packages` with networking, telemetry, external drivers, cgo, toolchain download, and repository writes disabled, then retains the standard-parser inventory as its fallback. The Go profile records a canonical offline dependency snapshot status/fingerprint derived from admitted module-cache, vendor, in-repository replacement, checksum, and manifest inputs; checkout/cache absolute paths, the standard library, build cache, temporary data, and unused cache entries are excluded. Cargo metadata is attempted only in frozen/offline/no-deps mode against a preflighted, worker-owned input mirror from a neutral working directory.

Worker and toolchain lookup uses a canonical absolute `PATH`: relative entries, the scan root, and symlink aliases into the scan root are removed. Child environments omit execution hooks such as `NODE_OPTIONS`; direct reads resolve symlinks and remain confined to the canonical repository root. Release manifests, workers, schemas, runtime component trees, and every declared artifact are checksum verified; symlinks, missing entries, changed bytes, and undeclared tree contents fail closed before a packaged worker starts.

Executable or unsupported configuration becomes a diagnostic or unresolved site. `project_code_executed` remains `false` in worker profiles, coverage, stored scans, and `doctor` output. Security fixtures contain configs/generators that would create marker files if they were executed.

## Build-mode consent boundary

`depgraph resolve --build [PATH]` is a separate, privileged mode because build tools, executable configuration, plugins, lifecycle scripts, Rust build scripts, and proc macros may run arbitrary project code. It never prompts. Each invocation must include `--allow-project-code`; configuration, environment variables, `CI=true`, TTY state, and previous consent cannot grant permission. Missing consent is rejected before path/config/store/toolchain processing with exit code `4`.

The explicit-consent guard is enforced before path, configuration, store, or tool processing. A consented Rust workspace with `Cargo.toml` and `Cargo.lock` is executed by the versioned build supervisor using Cargo. Next.js, Astro, and TanStack Start projects declare a direct Node entrypoint and pinned observer contract in `package.json`; shell commands and package-manager lifecycle resolution are not accepted:

```json
{
  "depgraph": {
    "build": {
      "adapter": "next",
      "entrypoint": "depgraph-build.mjs",
      "version": "16.2.10",
      "timeout_seconds": 900
    }
  }
}
```

The allowed Web adapter values are `next`, `astro`, and `tanstack-start`. The relative entrypoint must integrate the release-provided observer named by `DEPGRAPH_OBSERVER` (and `NEXT_ADAPTER_PATH` for Next) into the real build lifecycle. It runs in a temporary staged workspace using canonical system Node, a cleared allowlisted environment, temporary HOME/cache/output, bounded output, timeout/cancellation, and cross-platform process-tree cleanup. Every launched attempt saves a secret-free audit containing command metadata, logical paths, environment key names, limits, isolation capability, and outcome; raw stdout/stderr and temporary or host paths are not persisted. Network isolation is reported as `best-effort` unless an outer namespace/container enforces it.

Validated observer output uses `phase=build`, `precision=observed`, and primary `kind=build` evidence tied to the supervisor audit digests. The Next/Astro/TanStack Start observer entrypoints and their observation-to-protocol converter are separate checksum-attested release artifacts; missing, undeclared, or changed bytes fail closed before project code starts. Schema-v7 stores the delta in an attempt transaction and exposes it to `deps`, `dependents`, `why`, and exports only after completed promotion. Source and semantic rows remain immutable; matching and conflicting build observations coexist as separate layers, with conflicts carrying both provenance sets. Failed, partial, timed-out, cancelled, malformed, or unauthorized deltas are discarded and never replace the current completed graph.

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

Run `cargo xtask package` to create a native archive under `dist/`. Release archives place `depgraph` under `bin/`, compatible workers under `libexec/`, and include the project's complete `LICENSE-MIT` and `LICENSE-APACHE` texts, a checksum-verified release manifest, protocol schema, SPDX SBOM, and a separate third-party license inventory. The release manifest declares `MIT OR Apache-2.0` and attests both project license files independently from `THIRD_PARTY_LICENSES.txt`. The release gate fixes Rust/Cargo `1.93.1`; the Rust worker manifest records the linked backend unit, rust-analyzer `0.0.330` at revision `8954b66d43225e62c92e8bbcc8500191b5cceb1e` with Salsa `0.26.1`. The Web worker manifest records the exact TypeScript version, the complete Web semantic capability set, and its Astro and TypeScript runtime components.

The package verifier extracts the archive and validates the manifest, both project licenses, every artifact and runtime component, Rust and Web worker handshakes, per-framework scan/query/export E2E, cross-checkout JSON/DOT/Mermaid determinism, and the complete runtime SBOM and third-party license closure. Missing, added, modified, symlinked, or version-mismatched license, Web worker, Astro parser, TypeScript compiler, or schema input fails before worker launch. Runtime components distinguish an `executable-tree` with an executable entrypoint from a `data-tree` whose entrypoint is optional. No sysroot or `rust-src` is currently bundled, and packaged scans never fall back implicitly to project or system backend/sysroot bytes. Tier 1 Linux/macOS package gates and Windows safety/determinism smoke cover the Web semantic archive contract.

## License

Licensed under either [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE) at your option.

Copyright (c) 2026 TamaT LLC.
