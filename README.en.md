# depgraph

[Japanese](README.md) | English

[![CI](https://github.com/TamaT-LLC/depgraph-cli/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/TamaT-LLC/depgraph-cli/actions/workflows/ci.yml)
[![GitHub Release](https://img.shields.io/github/v/release/TamaT-LLC/depgraph-cli)](https://github.com/TamaT-LLC/depgraph-cli/releases/latest)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

`depgraph` is a local-first CLI that builds explainable dependency graphs from
Rust, Go, TypeScript, and JavaScript code. It brings Next.js, Astro, TanStack
Router, and TanStack Start routes, components, and server functions into the
same graph as language-level dependencies.

A dependency edge alone is not enough to judge the impact of a change.
`depgraph` retains dependency sites, analysis evidence, conditions, precision,
profiles, and unresolved reasons so you can ask both why a dependency exists
and how much of the codebase was analyzed.

## Find what you need

| Goal | Go to |
| --- | --- |
| Run the first scan | [First scan](#first-scan) |
| Check supported languages and extraction coverage | [Supported code and graph](#supported-code-and-graph) |
| Install a binary | [Install official packages](#install-official-packages) |
| Find CLI examples | [CLI examples](#cli-examples) |
| Use depgraph from an Agent host | [MCP stdio server](#mcp-stdio-server) |
| Understand the static-analysis safety boundary | [Safe-scan boundary](#safe-scan-boundary) |
| Understand when project code may run | [Build-mode consent boundary](#build-mode-consent-boundary) |
| Read the design and contracts | [the system design](docs/40_arch_design/arch-dependency-graph-cli-system-design.md) |
| Contribute to the project | [Project status and public collaboration](#project-status-and-public-collaboration) |

## First scan

After extracting an official package and adding `depgraph` to `PATH`, scan a
repository with the **safe static-analysis** mode. This mode does not execute
repository configuration, plugins, build scripts, or package managers.

```sh
depgraph scan /path/to/repository
depgraph doctor
```

Results are stored in an SQLite Store under the operating system cache
directory, keyed by the canonical repository root. To use a fixed location,
pass a global option such as
`depgraph --store /path/to/depgraph.sqlite scan /path/to/repository`.
Configuration is optional; `.depgraph.toml` is written only when you run
`depgraph init /path/to/repository`.

After scanning, use selectors to inspect files and packages in the graph.
Replace `src/app.ts` below with an actual path in the target repository.

```sh
# Dependencies used by this file
depgraph deps path:src/app.ts --transitive

# Nodes that depend on this file
depgraph dependents path:src/app.ts --transitive

# Dependency paths and evidence between two nodes
depgraph why path:src/app.ts package:example

# Impact of a change
depgraph impact path:src/app.ts --changed origin/main

# A shareable Mermaid graph
depgraph export --format mermaid > graph.mmd
```

`depgraph scan --strict` is intended for CI and rejects skipped files,
unsupported syntax, and unresolved sites. For normal exploration, start with
the default scan and use `doctor` and `unresolved` to inspect coverage.

## Questions and commands

| Question | Command | Result |
| --- | --- | --- |
| What does this node depend on? | `deps <SELECTOR>` | Outgoing dependencies from the selected node |
| What depends on this node? | `dependents <SELECTOR>` | Incoming dependencies to the selected node |
| Why does this dependency exist? | `why <FROM> <TO>` | Paths, conditions, and source locations between two nodes |
| What does a change affect? | `impact <SELECTOR>` | Reverse dependency paths and affected nodes |
| Are there dependency cycles? | `cycles` | Package-, file-, or symbol-level cycles |
| What could not be analyzed? | `unresolved` | The unresolved ledger with reasons and source locations |
| What is the analysis state? | `doctor` | Worker, toolchain, coverage, and cache state |
| What changed between snapshots? | `snapshot`, `diff` | Additions, removals, changes, and renames between completed graphs |
| Do architecture rules pass? | `policy` | Forbidden dependencies, boundary violations, and public API changes |
| What was observed at runtime? | `runtime validate`, `runtime import` | Integration of validated traces with the static graph |
| How can I export the graph? | `export` | JSON, DOT, Mermaid, or GraphML |
| Which files, exports, types, or dependencies look unused? | `health`, `health list`, `cleanup` | Snapshot-scoped findings with confidence and blockers. Summary excludes audit and hotspot results |
| What risk did a Git change introduce? | `audit --changed <GIT_REF>` | New cycles, boundary violations, public API changes, and blast radius in `merge-base(GIT_REF, HEAD)..HEAD`; `changed_oid` identifies the audited HEAD. Without a base snapshot, the three comparison checks are indeterminate while blast radius remains evaluable |
| Where are the graph hotspots? | `hotspots` | Integer basis-point ranks from fan-in, fan-out, reverse impact, Git churn, and runtime observation |
| How can an Agent inspect it? | `agent-config`, `depgraph-mcp` | MCP host configuration bound to a verified package. The `health_*` tools share the same confidence limits |

**Confidence** on `health` findings means: `confirmed` is unused across every applicable analyzed profile, those profiles are semantic-complete, and no hard blocker remains; `probable` has no observed usage and no hard blocker but applicable profiles are only syntax-complete; `indeterminate` is blocked by incomplete or missing coverage/surface evidence, public surface, entry points, dynamic loading, candidates, unresolved sites, unanalyzed profiles, manifest drift, or a missing/mismatched audit base. Source is never changed automatically. Finding `suppressions` remain a wire-compatible output-only/deferred field in v1: there is no CLI, MCP, or policy input path, and built-in analyzers always return an empty array. Audit before/after pairs compare the schema-18 policy digest, analyzer version, and finding-contract version; missing or mismatched provenance fails closed as `incomparable-policy` or `incomparable-contract`.

A **selector** identifies a graph node on the CLI. The accepted prefixes are
`id:`, `path:`, `package:`, `route:`, `symbol:`, and `type:`. If more than one
candidate matches, pass the complete Stable ID returned by the command as
`id:<stable-id>`.

## Supported code and graph

| Target | Main extracted elements |
| --- | --- |
| Rust | Cargo workspace/package/target, module, import, re-export, symbol, type, type-use, exact call, candidate call |
| Go | workspace, module, package variant, build constraint, import, symbol, type, generic instance, direct call, candidate call, cgo boundary |
| TypeScript and JavaScript | npm/pnpm/Yarn/Bun workspace, package, file, TypeScript/JavaScript symbol/type/import/re-export/type-use, exact call, candidate call |
| Next.js | App Router and Pages Router, route component, render relation, parent route, client/server boundary, statically resolvable dynamic component |
| Astro | page, endpoint, component, hydration boundary, frontmatter import, content collection, asset |
| TanStack Router | file route, code route, virtual route, generated route tree, loader, `beforeLoad`, lazy route, context, route mask |
| TanStack Start | server function, RPC relation, server route, middleware chain |

Every dependency site recognized by static analysis is classified as one of:

- **`resolved`**: the evidence identifies exactly one target.
- **`candidates`**: analysis found a finite candidate set but cannot prove a
  unique target.
- **`external`**: the target is outside the repository, such as a standard
  library or third-party package.
- **`unresolved`**: the dependency site is known, but its target cannot be
  identified safely.

This classification prevents guessed unresolved dependencies from being
promoted to `resolved`. Skipped and unsupported input is recorded in the
**Coverage Ledger**, allowing graph results and analysis completeness to be
evaluated separately.

## Install official packages

The following installation guidance applies after the official Release and
post-publish evidence exist. `v0.5.4` provides native packages for Linux x86-64,
Linux ARM64, macOS Intel, macOS Apple Silicon, and Windows x86-64. `v0.5.0` was
distributed only through GitHub Releases; npm distribution starts with `v0.5.1`
under TamaT LLC's `@tamat-llc` organization scope.

`npm i -g @tamat-llc/depgraph` installs the verified native package for the
same five targets without an install-time external download. The npm launcher
requires Node.js 24 or later. The `depgraph` CLI runs entirely from the npm
package. `depgraph-mcp` is included as well, but starting the MCP server also
requires the compiler pack for the same version and target from the GitHub
Release to be verified and extracted, with its requirement file supplied.

See the [npm release procedure](docs/50_test/npm-release-procedure.md) for
publication status and initial bootstrap details. Choose the `TARGET` for your
environment below.

| Environment | `TARGET` |
| --- | --- |
| Linux x86-64 | `x86_64-unknown-linux-gnu` |
| Linux ARM64 | `aarch64-unknown-linux-gnu` |
| macOS Intel | `x86_64-apple-darwin` |
| macOS Apple Silicon | `aarch64-apple-darwin` |
| Windows x86-64 | `x86_64-pc-windows-msvc` |

After publication, use GitHub CLI on macOS or Linux to download the archive and checksum.

```sh
VERSION=0.5.4
TARGET=aarch64-apple-darwin
ARCHIVE="depgraph-${VERSION}-${TARGET}.tar.gz"

gh release download "v${VERSION}" \
  --repo TamaT-LLC/depgraph-cli \
  --pattern "${ARCHIVE}" \
  --pattern "${ARCHIVE}.sha256"
```

Verify the checksum before extracting the archive. Use `shasum` on macOS and
`sha256sum` on Linux.

```sh
# macOS
shasum -a 256 --check "${ARCHIVE}.sha256"

# Linux
sha256sum --check "${ARCHIVE}.sha256"

tar -xzf "${ARCHIVE}"
"./depgraph-${VERSION}-${TARGET}/bin/depgraph" --version
```

On Windows, download `.zip` and `.zip.sha256` from the same Release, verify
them with `Get-FileHash -Algorithm SHA256`, and extract with `Expand-Archive`.
The release SBOM, license inventory, and compatibility information are included
in the archive.

## Build from source

The pinned development toolchains are Rust 1.93.1, Go 1.26.1, Node.js 24.18.0, and pnpm 10.33.0.
From the repository root, build the CLI and the Rust, Go, and Web workers with:

```sh
cargo xtask build
target/debug/depgraph --version
```

Use `cargo xtask test` to run formatting, lint, contract, worker, and fixture
tests together. Development workflow and command details are in
[CONTRIBUTING.md](CONTRIBUTING.md).

## Releases and compatibility

`main` implements the `0.5.4` contract documented in the
[`v0.5.4` release notes](docs/releases/v0.5.4.md). A stable release is valid
only when the
[`v0.5.4` GitHub Release](https://github.com/TamaT-LLC/depgraph-cli/releases/tag/v0.5.4)
and its post-publish evidence exist and agree.
The MVP implements the architecture described in [the system design](docs/40_arch_design/arch-dependency-graph-cli-system-design.md).

Every v0.5 archive includes the native MCP server, durable
operation runner, and versioned Agent tool/operation schema.
The worker protocol remains at `1.0` for v0.5, with Store
schema `18`, operation journal schema `5`, `depgraph-mcp-tools-v1`, and
`depgraph-operation-v1`.

`v0.4.0` is a historical reserved baseline; no `v0.4.0` stable GitHub Release
was published. Its contract remains in the historical
[`v0.4.0` contract](docs/releases/v0.4.0.md). Earlier release candidates are
documented as [`v0.4.0-rc.6`](docs/releases/v0.4.0-rc.6.md),
[`v0.4.0-rc.2`](docs/releases/v0.4.0-rc.2.md),
[`v0.4.0-rc.1`](docs/releases/v0.4.0-rc.1.md), and
[`v0.2.0-rc.1`](docs/releases/v0.2.0-rc.1.md).

See the [`v0.5.4` release notes](docs/releases/v0.5.4.md) for the complete
compatibility tuple, Store migrations, rollback procedure, and known limits.

## Project status and public collaboration

The supported line is conditionally anchored by the verified `v0.5.4` Release.
`v0.5.4` becomes the current stable release after the official Release and its
post-publish evidence are public. Until then, `v0.5.3` remains stable and
release candidates are historical evaluation artifacts. Product support is
best effort, without response-time or resolution-time SLAs.

Follow [SUPPORT.md](SUPPORT.md) for usage questions and bug reports. Read
[CONTRIBUTING.md](CONTRIBUTING.md) before opening an issue or pull request, and
see [GOVERNANCE.md](GOVERNANCE.md) for decision-making and maintainer roles.
Participation is governed by [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

Never report a suspected vulnerability through a public issue; use the private
channel documented in [SECURITY.md](SECURITY.md). The project is licensed under
[MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.

## Analysis completeness

**`semantic-complete`** means that a profile's semantic analysis met the
defined completeness requirements. It does not mean that missing dependencies
were guessed. The marker is emitted only when syntax analysis completes, a
compatible validated semantic backend produces a graph, and the counts for
semantic issues, skipped input, unsupported input, and unresolved sites are all
zero. Explicit `candidates` and `external` sites do not prevent the marker.

The Rust semantic backend uses confined Cargo metadata, a ready project model,
and the verified Rust `1.93.1` toolchain. `depgraph` sets
`RUSTUP_AUTO_INSTALL=0`; if the toolchain is absent, it reports installation
instructions instead of installing it implicitly. Source builds report
`rust_hir_enable_gate=release-gate-pending`; only a worker launched from a
verified Release Archive can report `release-gate-verified`.

Web `semantic-complete` requires the bundled isolated TypeScript compiler, an
emitted v2 graph, and zero skipped, unsupported, unresolved, semantic-issue,
and compiler-diagnostic counts. Detected Next.js, Astro, TanStack Router, and
TanStack Start projects must also complete the matching Framework Capability
Ledger.

Beyond the static graph, depgraph supports architecture policy, GitHub
annotations, runtime traces, immutable snapshots, snapshot diff, Git
changed-set impact, GraphML, and a watcher daemon. Build observation is a
separate permission boundary; only an explicitly consented invocation may run
code from the target project.

## Development quality checks

Run all formatting, lint, contract, worker, and fixture tests with:

```sh
cargo xtask test
```

The reproducible performance gate uses pinned toolchains and deterministically
generated fixtures.

```sh
scripts/benchmark-mvp.sh
```

The benchmark creates fixtures with 100, 1,000, and 10,000 source files plus a
31-source-file Rust HIR fixture. Results are written to
`dist/benchmark-report.json` and `dist/cache-hit-benchmark-report.json`. It
measures cold scans, one-file incremental scans, impact queries, semantic cache
hits, and cold and warm Rust HIR runs. Each fixture must preserve canonical
graph and coverage equivalence, and the median cache hit must be at least 5%
faster.

## CLI examples

```sh
# Optional tracked-project configuration; scanning works without it.
depgraph init .

# Safe static analysis; does not modify the target repository.
depgraph scan /path/to/repository
depgraph scan /path/to/repository --strict
depgraph scan /path/to/repository --no-cache

# Inspect profile selection without starting workers or changing the Store.
depgraph profiles plan /path/to/repository
depgraph profiles plan /path/to/repository --profile-budget 8 --json
depgraph profiles plan /path/to/repository --profiles-file profiles.json --json

# Run the watcher daemon in the foreground; inspect or stop it elsewhere.
depgraph daemon start /path/to/repository
depgraph daemon status /path/to/repository --json
depgraph daemon stop /path/to/repository

# Privileged build observation; every invocation requires explicit consent.
depgraph resolve --build /path/to/repository --allow-project-code

depgraph doctor --json
depgraph doctor --details --json
depgraph doctor --root /path/to/repository --json
depgraph deps path:src/app.ts --transitive --max-items 100 --max-bytes 1048576
depgraph deps path:src/app.ts --transitive --cursor "$NEXT_CURSOR" --json
depgraph deps path:src/app.ts --transitive --all --json
depgraph dependents package:example
depgraph why path:src/app.ts route:/products/$id
depgraph impact path:src/app.ts
depgraph impact package:example --changed origin/main --depth 4
depgraph impact route:/products/$id --changed HEAD~1 --profile web:production:server --json
depgraph cycles --level file

# Use canonical resolver identities in the Go semantic graph.
depgraph deps symbol:example.com/semantic/model.Build --transitive
depgraph dependents type:example.com/semantic/model.Worker --json
depgraph why symbol:example.com/semantic/model.Build type:example.com/semantic/model.Input --json
depgraph cycles --level symbol

# If a selector is ambiguous, retry with a returned Stable ID.
depgraph deps "id:$STABLE_ID" --json

depgraph unresolved --max-items 100 --json
depgraph unresolved --all --json

# Validate an external runtime trace against the graph without changing the Store.
depgraph runtime validate --file runtime-trace.json
depgraph runtime validate --file runtime-trace.json --json

# Name and inspect a completed immutable snapshot.
depgraph snapshot create baseline
depgraph snapshot list --json
depgraph snapshot show baseline
depgraph snapshot show snapshot:sha256:... --json

# Compare completed snapshots by name or Stable ID.
depgraph diff baseline current
depgraph diff baseline current --json
depgraph diff baseline current --kind symbol --profile web:production:server
depgraph diff baseline current --phase semantic --status unresolved

depgraph export --format json --output graph.json
depgraph export --format dot > graph.dot
depgraph export --format mermaid > graph.mmd
depgraph export --format graphml --output graph.graphml
```

### MCP stdio server

`depgraph-mcp` is the packaged native MCP stdio server. Its safe default is the
`read` capability: no store mutation, repository write, daemon control, or
project-code execution is enabled. It requires an existing fixed repository
root, an explicit absolute store-file path, and the validated compiler-pack
requirement published for the host.

#### Scoped setup for Codex, Claude Code, Cursor, and Grok

After installing an official stable `depgraph` release, run this command from
any directory inside the Git repository that the Agent host should inspect:

```sh
depgraph mcp setup --host codex
```

`--host` accepts `codex`, `claude`, `cursor`, and `grok`. Project scope is the
default. Use `--scope user` when the entry should live in the user's host
configuration instead:

```sh
depgraph mcp setup --host cursor --scope user
```

| Host | Project scope (default) | User scope |
|---|---|---|
| Codex | `.codex/config.toml` | `~/.codex/config.toml` |
| Claude Code | `.mcp.json` | `~/.claude.json` |
| Cursor | `.cursor/mcp.json` | `~/.cursor/mcp.json` |
| Grok | `.grok/config.toml` | `~/.grok/config.toml` |

The command resolves and seals the nearest canonical Git root before making a
network request or write. It downloads the exact stable release and compiler
pack for the invoking CLI version and native target, verifies GitHub's asset
digests, checksum sidecars, release manifest, compiler-pack closure, and
post-publish evidence, and stores the verified runtime and compiler pack in a
version/target shared OS cache. It derives a separate Store outside the
repository, creates the initial snapshot with the non-executing safe scan,
performs the packaged `initialize`, `tools/list`, and `get_context` preflight,
then atomically merges only the selected host entry. Existing unrelated
settings are retained. Codex and Grok TOML edits also retain comments and
layout. The installed entry contains absolute paths and fixes the server to
this root, Store, compiler-pack requirement, and read-only capability.

Project scope uses the server name `depgraph`. User scope uses a deterministic
`depgraph-<repository-id>` name, so several repository-bound servers can share
one user configuration without replacing each other.

Restart or refresh the selected host after setup. Claude Code asks for trust
before loading a project-scoped `.mcp.json` entry.
Rerunning setup is idempotent: verified shared artifacts and a valid current
snapshot are reused. Use the lifecycle commands from the same repository:

```sh
depgraph mcp status --host codex
depgraph mcp update --host codex
depgraph mcp uninstall --host codex
```

Repeat both `--host` and `--scope user` for a user-scoped binding. Omitting
`--scope` always selects project scope.

`status` independently rechecks the official release metadata, cached bytes,
package closure, Store/root snapshot, exact project entry, and live MCP
preflight. Setup, update, and uninstall are serialized by one repository
lifecycle lock. A separate per-file lock under the canonical user home
serializes host configuration changes across repositories and CLI versions,
preventing concurrent user-scope merges from replacing each other. `update`
reconciles to the invoking CLI version and refreshes the safe snapshot.
`uninstall` requires the complete managed read-only launch tuple, always
establishes exclusions for scans, daemons, and durable operation runners, then
removes only the matching scoped entry. Repository state is removed after the
last entry with an owned launch tuple for the invoking CLI version and host
target is gone; older-release and same-named unrelated entries do not retain it.
Empty writer/runner lock
sentinels remain so a live coordination file is never unlinked; shared verified
artifacts remain for other repositories. Pass `--root /absolute/path/to/repository` when running
outside the checkout. If you choose a custom Store with the global
`--store /absolute/path/to/graph.db` option, put it before `mcp` and repeat the
same option for every lifecycle command.

Setup requires a real `curl` executable outside the repository and an exact
published stable release for the CLI version. An invalid/ambiguous Git root,
home or filesystem root, unexpected symlink, changed GitHub asset, malformed
host configuration, or failed package/MCP preflight stops without publishing a
partial host entry. After an interrupted download or extraction, rerun the
same command; process-held cache locks are released on exit and incomplete
temporary content is ignored. If `status` reports drift or a missing snapshot,
run `update`; if the host still shows the old entry after a successful check,
restart or refresh it. See the
[MCP Agent host operations runbook](docs/50_test/mcp-agent-host-operations.md)
for the ownership model and detailed recovery table.

#### Low-level host configuration generation

`agent-config` remains the low-level workflow for custom capability profiles or
operators who manage host files themselves. It prints
a verified entry to stdout and never edits a host file or creates/migrates the
Store. Replace the path placeholders below with canonical absolute paths and
`TARGET_TRIPLE` with the release host target; Agent hosts must not rely on shell
or environment expansion.

The command authenticates the supplied inputs against
the official release's closed post-publish evidence, verifies the archive and
exact checksum sidecar, binds the extracted manifest to that archive, checks
every MCP/runner/schema/worker sibling, validates the compiler pack and fixed
root/Store snapshot, and performs `initialize`, `tools/list`, and `get_context`
before printing a host entry. The default profile is `read`; stdout contains
only the requested configuration and no host file is edited. Diagnostics and
the exact capability closure and effect summary go to stderr.

Download `release-post-publish-evidence-RELEASE_TAG.json` from the same
[official GitHub Release](https://github.com/TamaT-LLC/depgraph-cli/releases),
then obtain that asset's SHA-256 independently from GitHub's release-asset API
over HTTPS. Strip the `sha256:` prefix and pass the remaining 64 lowercase hex
characters below. Do not calculate this trusted value from the downloaded
evidence file or any local archive/sidecar: that would make a forged local set
self-authenticating. For example, the API field can be read with

```sh
gh api "repos/TamaT-LLC/depgraph-cli/releases/tags/RELEASE_TAG" \
  --jq '.assets[] | select(.name == "release-post-publish-evidence-RELEASE_TAG.json") | .digest | sub("^sha256:"; "")'
```

```sh
/absolute/path/to/depgraph-0.5.4-TARGET_TRIPLE/bin/depgraph agent-config \
  --root /absolute/path/to/repository \
  --store /absolute/path/to/state/depgraph.sqlite \
  --release-archive /absolute/path/to/depgraph-0.5.4-TARGET_TRIPLE.tar.gz \
  --release-checksum /absolute/path/to/depgraph-0.5.4-TARGET_TRIPLE.tar.gz.sha256 \
  --release-evidence /absolute/path/to/release-post-publish-evidence-RELEASE_TAG.json \
  --trusted-release-evidence-sha256 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  --release-manifest /absolute/path/to/depgraph-0.5.4-TARGET_TRIPLE/release-manifest.json \
  --compiler-pack-requirement /absolute/path/to/depgraph-compiler-pack-0.5.4-TARGET_TRIPLE.requirement.json \
  --host codex
```

Use the matching `.zip` and `.zip.sha256` paths on Windows. `--host` accepts
`codex`, `claude-desktop`, or `vscode`. A missing current snapshot fails before
server launch and reports an exact argv array for a separate safe scan; the
onboarding command itself never creates or migrates the Store. Non-read
profiles are selected explicitly with `--profile store-write`,
`repository-write`, `daemon-control`, `project-exec`, or `full` and require
`--acknowledge-privileged-effects`. `project-exec`/`full` also require
`--acknowledge-project-exec-human-confirmation`.

<!-- depgraph-mcp-package-smoke:command -->
```sh
/absolute/path/to/depgraph-0.5.4-TARGET_TRIPLE/bin/depgraph-mcp \
  --root /absolute/path/to/repository \
  --store /absolute/path/to/state/depgraph.sqlite \
  --capability read \
  --compiler-pack-requirement /absolute/path/to/compiler-pack-requirement.json \
  --log-level warn
```

The equivalent Claude Desktop entry is read-only. This is also the generic JSON
form to copy unless an operator has approved a narrower privileged use case.

<!-- depgraph-mcp-package-smoke:read -->
```json
{
  "mcpServers": {
    "depgraph": {
      "command": "/absolute/path/to/depgraph-0.5.4-TARGET_TRIPLE/bin/depgraph-mcp",
      "args": [
        "--root", "/absolute/path/to/repository",
        "--store", "/absolute/path/to/state/depgraph.sqlite",
        "--capability", "read",
        "--compiler-pack-requirement", "/absolute/path/to/compiler-pack-requirement.json",
        "--log-level", "warn"
      ]
    }
  }
}
```

The fixed root and store form a trust boundary: use a separate private store per
repository, keep it outside the repository when possible, and launch the MCP
server, sibling operation runner, schema, manifest, and workers from one
official-evidence-bound release archive. stdout is reserved for
newline-delimited MCP JSON-RPC; bounded diagnostics go to stderr.

Privileged profiles are explicit replacements for the read-only entry, not a
runtime elevation mechanism. Complete Agent host examples for `store-write`,
`repository-write`, `daemon-control`, `project-exec`, and `full`, together with
human-confirmation rules, durable polling/reconnect/cancel, timeout and TTL
values, upgrade/rollback steps, and troubleshooting, are in the
[MCP Agent host operations runbook](docs/50_test/mcp-agent-host-operations.md).
In particular, `acknowledgement: true` on `resolve_build_submit` only records an
independent host decision; it does not grant `project-exec` or replace human
confirmation. Only enforced isolation plus a successful source postflight can
claim source non-mutation; best-effort isolation cannot.

The [packaged MCP Agent dogfood benchmark](docs/50_test/agent-dogfood-benchmark.md)
compares the same fixed code-investigation corpus with and without this MCP
server. The checked-in `v0.5.0-rc.7` evidence records all three samples per arm,
91.67% MCP accuracy, 100% major-claim recall, zero false exact claims, and a
side-effect-free read-only run.

Modern protocol `2026-07-28` can negotiate MCP Tasks. Its `taskId` is the same
durable ID exposed by `operation_get`, `operation_result`, and
`operation_cancel`; legacy `2025-11-25` and Tasks-unaware hosts use those
portable tools directly. stdio disconnect does not cancel work. Reconnect with
the same root, store, capability profile, and compiler-pack requirement, then
poll the saved ID. Read calls have a 30-second budget, durable submission has a
2-second handle-return budget, and an accepted operation has a one-hour
execution deadline. Follow the returned `pollIntervalMs`,
`execution_deadline_ms`, and `retain_until_ms` rather than guessing locally.

Inbound MCP JSON messages are limited to 1 MiB before JSON deserialization;
the server fails closed when that bound is exceeded. The requirement file must
be a regular non-symlink file no larger than 1 MiB; its manifest, closed tree,
host/target, checksum reference, and artifact integrity are verified by
`depgraph-core` before the server accepts MCP input.

SQLite is stored under the operating system cache directory, keyed by the canonical repository root. Use global `--store PATH` for a specific database and global `--scan-id ID` to inspect a retained partial scan. Queries default to the latest successful scan; `doctor` reports the latest attempt.

`doctor` emits a bounded summary by default. The summary reads diagnostic
counts and at most 64 cause groups plus five representative diagnostics
without loading diagnostic payload JSON, graph evidence, or adapter stderr.
Completed build and runtime overlays are projected into the same bounded counts.
Use `doctor --details` for the complete retained attempt payload.
The diagnostic root defaults to the latest attempt's stored root, falling
back to the current working directory only when the store has no attempt;
`--root PATH` selects it explicitly. Worker `available`, version, protocol,
and integrity describe an isolated artifact handshake and therefore do not
change with the invoking directory. `root_launch_allowed` and
`root_launch_error` separately report whether that artifact may be launched
for the diagnostic root, preserving the development-artifact-inside-root
security boundary.

`deps`, `dependents`, and `unresolved` use the versioned
`depgraph-interactive-query-page-v1` contract unless `--all` is explicit.
The defaults are 100 canonical items, a 1 MiB canonical JSON document, and
50,000 visited edges for dependency traversal. `--max-items`, `--max-bytes`,
and `--max-traversal` lower or raise those bounded limits within the hard
caps. A truncated page returns `complete:false`, a stable diagnostic code,
an immutable `snapshot_id`, and a snapshot/query-bound `next_cursor`; the
cursor resumes the canonical item order without overlap or gaps and is
rejected after a newer build snapshot is promoted for the same scan. The byte
count covers the compact UTF-8 JSON document (the terminal newline is transport
framing). A traversal-limit result has no continuation after its admitted result set; raise
`--max-traversal` or narrow filters. `--all` preserves the legacy complete
query shape, while `export` remains the streaming full-graph interface.

`profiles plan` is read-only and uses only a bounded static inventory. Its human
and canonical JSON output includes every selected, omitted, and policy-excluded
profile with rank evidence and the schema-v1 configuration migration
diagnostic. `--profile-budget` accepts `1..=32` while reserving every detected
language baseline. `--profiles-file` instead reads a confined, non-symlink,
UTF-8 JSON file of at most 64 KiB; it is all-or-error and cannot be combined
with `--profile-budget`.

GraphML exports use standard directed `node` and `edge` elements with generated
XML-safe element IDs. The original stable IDs, kinds, phase, profile,
condition, precision, resolution, and environment remain available through
typed GraphML keys. Complete profile, dependency-site, and evidence records use
canonical JSON graph properties, with explicit owner references that allow the
records to be reconstructed without source-store access. `--output` writes
GraphML incrementally through a bounded buffer into a sibling temporary file,
then atomically replaces the destination only after export succeeds.

## Architecture policy contract

Architecture rules live in the versioned `[policy]` section of `.depgraph.toml`.
This example forbids production UI files from depending directly on internal
data files and limits a suppression to one legacy source file:

```toml
[policy]
schema_version = "1.0"

[[policy.rules]]
id = "no-ui-to-data"
kind = "forbidden_dependency"
severity = "error"
source = { kind = "file", field = "path", match = "glob", value = "src/ui/**", cardinality = "many", exclude = [], scope = { paths = [{ match = "glob", value = "src/**" }], packages = [] } }
target = { kind = "file", field = "path", match = "glob", value = "src/data/internal/**", cardinality = "many", exclude = [], scope = { paths = [{ match = "glob", value = "src/**" }], packages = [] } }
profiles = { include = [{ match = "prefix", value = "profile:" }], exclude = [] }
condition = { op = "eq", key = "mode", value = "production" }
precisions = ["exact", "observed"]
resolution_statuses = ["resolved"]
evidence = { kinds = ["source", "semantic"], minimum_spans = 1, primary_only = true }

[[policy.suppressions]]
id = "legacy-ui-data"
rule_id = "no-ui-to-data"
reason = "Legacy adapter is isolated until its scheduled migration."
scope = { source = { kind = "file", field = "path", match = "exact", value = "src/ui/legacy-adapter.ts", cardinality = "one", exclude = [], scope = { paths = [{ match = "exact", value = "src/ui/legacy-adapter.ts" }], packages = [] } }, profiles = { include = [{ match = "prefix", value = "profile:" }], exclude = [] } }
```

Selectors support `package`, `file`, `symbol`, `type`, `route`, and
`component` nodes. `runtime_boundary` requires a `route` or `component`
source and a `component` target; `public_api_change` targets only `symbol`,
`type`, or `route`.
`field` chooses stable ID, normalized repository path, locator, or display-name
matching; `match` is `exact`, `prefix`, or the bounded `*` / `**` / `?` glob
grammar. The normalized `path` field is available only for `file` selectors.
`cardinality = "one"` rejects both zero and multiple matches rather than
silently choosing the first; `"many"` evaluates every match in canonical
order. Repository/package scope is applied before exclusions, and neither can
broaden the selector.

Every rule declares source and target selectors, severity, profile and
condition filters, admitted precision/status values, and its evidence
requirement. `dependency_depth`, `fan_in`, and `fan_out` rules additionally
require `threshold = { max = ... }`. Suppressions require a reason and a
non-empty source, target, profile, or condition scope; a condition used as the
only bound must not be statically always true. Unknown versions, rule kinds,
properties, and invalid or duplicate IDs fail closed as configuration errors.
The machine-readable result contract uses stable violation IDs, dependency
paths, repository-relative evidence spans, applied suppressions, and exit code
`1` whenever an unsuppressed error remains.

During `depgraph scan`, policy selectors are resolved against the validated
staging graph and profile, condition, precision, resolution-status, and
evidence filters are applied before evaluation. `layer_boundary` and
`forbidden_dependency` evaluate admitted direct edges; `cycle` reuses the
package/file/symbol/route cycle query per profile; and `dependency_depth`,
`fan_in`, and `fan_out` evaluate deterministic threshold witnesses. The scan
JSON includes the complete `policy` result. An active error finishes the
attempt as `policy_failed` with exit code `1` and does not replace the current
completed snapshot; warnings and suppressed violations remain visible while
allowing promotion.

`runtime_boundary` is also evaluated during scan. It follows a deterministic
route/component path to an explicit `client_boundary` or `server_boundary`
edge in the same profile; the rule condition is evaluated against that
boundary edge, including framework facts such as `next.runtime`. No default
server/client boundary is inferred.

`public_api_change` is evaluated between completed snapshots:

```sh
depgraph policy baseline current --json
depgraph policy baseline current --github-annotations
```

The report classifies selected public symbols, types, and routes as `added`,
`removed`, or `changed`. Added APIs are compatible; removed and changed APIs
are breaking and become violations when a configured baseline source has an
impact path to the old API. Each violation links the change ID, baseline
dependency path, profile/condition, and declaration evidence. `--json` emits
the versioned machine-readable report and annotations. `--github-annotations`
emits only escaped `warning`/`error` workflow commands for unsuppressed
violations, using validated repository-relative paths and one-origin
positions; scan roots, environment values, evidence details, and absolute
paths are not included. Active errors return `1`; warning-only and
suppressed-only results return `0`.

The matching JSON Schema is
[`schemas/depgraph-policy-v1.schema.json`](schemas/depgraph-policy-v1.schema.json).

## Runtime trace import contract

`depgraph runtime validate (--trace TRACE|--file REPOSITORY_RELATIVE_FILE)` reads
the versioned `1.0` JSON contract,
matches it against the selected completed snapshot, and produces deterministic
`runtime-event:sha256:...` identities without changing the store.
`depgraph runtime import TRACE` performs the same validation and atomically
publishes a new immutable runtime snapshot:

```sh
depgraph runtime import runtime-trace.json --json
depgraph deps id:file:server --phase runtime --session session-001
depgraph dependents id:route:users --phase runtime --environment production
depgraph why id:file:server id:route:users --phase runtime
depgraph impact id:route:users --phase runtime --profile profile:sha256:...
depgraph export --format json --phase runtime --session session-001
depgraph export --format graphml --phase runtime --session session-001
depgraph diff baseline current --phase runtime --json
```

Runtime child profiles declare their static/semantic parent and canonical
effective input. Matching observations from multiple sessions reuse the same
runtime-only sentinel, site, and edge identities; evidence remains per session
with source session/environment, observation count, duration, first/last
timestamp, event IDs, and redaction count. External and unresolved locators are
retained as explicit `runtime_only` sentinel nodes with fixed reasons rather
than being forged into repository nodes. Reimporting the same validated session
is idempotent.

The document identifies a repository, session, profile, environment, and an
ordered event stream. Each source and target uses one explicit locator form:
stable node ID, exact graph locator, canonical repository-relative path,
external identity, or an unresolved reason. Repository identity must match a
workspace node ID, locator, or `repository_identity` property in the selected
snapshot. Revision is checked when both sides provide it. Node ID and locator
matches must be unique; missing or ambiguous locators remain `unresolved`, and
collector-declared external targets remain `external`. Validation never
invents a repository node.

Input is bounded to 16 MiB, 100,000 events, 4,096-character strings, and 32 JSON
levels. UTF-8, exact version, strict fields, RFC 3339 session bounds, increasing
sequence numbers, and portable paths are required. Absolute paths, `..`, file
URI hosts, drive-like `:` segments, backslashes, unknown properties,
secret-bearing fields, and common raw credential forms fail closed with bounded
errors. Production output marked
`session.collector_contract_version=runtime-collector-v1` also rejects raw
HTTP(S) graph locators and HTTP targets containing
userinfo/path/query/fragment. Unmarked trace v1 input retains its existing
compatibility behavior without claiming the production collector guarantee.
Environment variables, headers, and secrets are represented only by
sorted/deduplicated names and redaction counts; their values are not part of the
contract or output.

The matching JSON Schema is
[`schemas/depgraph-runtime-trace-v1.schema.json`](schemas/depgraph-runtime-trace-v1.schema.json).
Production SDK lifecycle, buffer, flush, retry, sequence, clock, file/stdout/OTLP
transport, redaction, and rate-limit behavior are fixed separately by
[`runtime-collector-v1`](schemas/depgraph-runtime-collector-v1.schema.json) and
the
[collector ADR](docs/40_arch_design/adr-production-runtime-collector-v1.md).
All transports converge on the same trace v1 JSON; vendor spans are adapted
outside core.

The Node.js/TypeScript reference implementation is built as
`workers/web/dist/depgraph-runtime-collector.mjs`. Its typed module, call,
route, and RPC APIs redact URL credentials/path/query/fragment before
admission, assign contiguous acceptance-order sequence numbers, apply bounded
drop-newest backpressure, and coalesce immutable-prefix flushes across file,
stdout, and OTLP sinks. A disabled instance does not read clocks, call a sink,
or install timers. See the
[Web worker runtime collector guide](workers/web/README.md#nodejstypescript-runtime-collector).
Native archives ship the same module at
`libexec/depgraph-runtime-collector.mjs`. Its `runtime-collector-v1`
compatibility unit and SHA-256 are fixed by the release manifest, represented
as a first-party SPDX package, and exercised from real fixture observation
through validate/import/query/GraphML export by every package gate.

Store schema v13 retains the v10 profile-independent `syntax`,
profile-dependent `semantic`, and observed `build` cache tables plus the v11
normalized runtime session/node/site/edge/evidence/diagnostic/import tables.
Schema v12 added durable `worker-delta-v1` staging bound to the exact current completed
snapshot and canonical base/result graph digests. Applying a staged delta
revalidates its event stream and referential integrity inside one SQLite
transaction, recomputes the prospective completed snapshot ID, and preserves
unchanged graph payloads and stable IDs. Failed, cancelled, or crash-recovered
attempts never move the current snapshot pointer and are removed by the
existing unreferenced-attempt garbage collector.
Schema v13 adds a snapshot-, selector-, and filter-scoped impact result cache
for warm queries issued by independent CLI processes. Cache payloads use a
versioned content-addressed key and digest, are capped at 128 entries and 8 MiB
per entry with transactional monotonic LRU ordering, and are discarded on
contract, snapshot, JSON, or digest mismatch.
Git changed-set impact bypasses this cache so dirty worktree state is always
read afresh. Cache maintenance is best-effort, so a concurrent SQLite writer
cannot make the impact query fail; an unrecorded LRU touch becomes a cache miss
and uses the normal query path. A cache hit deserializes the same canonical
`ImpactResult`, so ordering, depth/profile/condition/runtime filters, diagnostics,
and JSON or human rendering are unchanged.
Runtime rows, the completed snapshot, its source mapping, and the current
pointer are committed in one SQLite transaction; any failure rolls back the
entire session and leaves the previous completed snapshot queryable. Existing
source/semantic/build graph records are immutable and runtime union only adds
`phase=runtime`, `precision=observed` records. Cache keys continue to use
contract v1 canonical digests of repository-relative file bytes,
manifest/lock/config inputs, adapter/protocol artifacts, toolchain/framework
identities, profiles, and generated artifact fingerprints; checkout, cache,
and temporary absolute paths are not key dimensions. A semantic hit is reused
only after cache contract v2 key, completed-snapshot, and canonical payload
reference integrity checks. The validated content-addressed snapshot is
atomically aliased to the fresh scan attempt without cloning every graph row;
an intervening SQLite writer invalidates the promotion proof.
Repository-internal file symlinks remain cacheable by fingerprinting the link
identity and confined target content, then revalidating those proofs immediately
before the cache-hit transaction commits. Policy evaluation paths that require
a cloned staging graph use a worker rescan when symlink proofs are present.
Root-out, dangling, looped, non-file, changed, or unreadable symlinks fail
closed; the rejection diagnostic reports only the safe repository-relative
link path. Unknown versions, corruption, unsafe inventory bounds, and
dependency snapshots that cannot be re-derived before scanning are also
explicit misses/rejections. `scan --no-cache` bypasses lookup and storage. Scan
JSON/text and `doctor` expose cache hit/miss/reject reasons without adding cache
bookkeeping to the canonical graph.

`snapshot create` names the current completed snapshot; global `--scan-id ID` may instead select the completed snapshot produced by that scan and its latest promoted build. Failed or incomplete attempts cannot be named. Names are immutable, case-insensitively unique, 1–64 ASCII characters, begin with a letter or digit, and otherwise use letters, digits, `.`, `_`, or `-`. `current` and `latest` are reserved, and existing names are never overwritten. `snapshot show` accepts a name, a `snapshot:sha256:...` stable ID, or `current`. List and detail JSON are emitted in canonical order.

`diff` accepts two completed snapshot names, stable IDs, or `current`; failed and incomplete attempt IDs are rejected with exit code `2`. Human output starts with node/site/edge/evidence/profile/coverage/rename counts and follows with canonical change details plus primary source evidence. `--json` emits the versioned `diff` command envelope with normalized filters, a summary, and the canonical before/after records. Repeatable `--kind`, `--profile`, `--phase`, and `--status` filters use exact matching and AND semantics; a record type that does not expose a selected dimension is excluded rather than guessed through an implicit graph join.

`impact <SELECTOR>` follows incoming dependencies from the selected node and reports a deterministic dependency path, rendered condition, profile correlation, and source evidence for every result. With `--changed <GIT_REF>`, depgraph reads both committed changes from `merge-base(GIT_REF, HEAD)..HEAD` and staged, unstaged, and untracked worktree changes without taking Git locks or invoking external diff/textconv helpers. Changed and renamed paths are correlated to file and semantic node identities through canonical node properties and stored evidence. The selector is the focus: it must depend on a mapped changed node, then reverse traversal reports the focus and its dependents. Repeatable `--profile`, `--condition`, `--phase`, `--session`, and `--environment` filters are exact; runtime environment matching includes its name, runtime, and region. `--depth`, `--max-nodes`, and `--max-edges` bound traversal, and a reached safety limit is returned as `complete=false` with an explicit diagnostic rather than silently truncating results.

`daemon start` uses the platform-recommended recursive filesystem watcher and a configurable `[daemon].debounce_milliseconds` (default `200`). VCS metadata, dependency/build output directories, the graph store, and daemon control files are ignored; tracked generated source such as `generated`, `*.generated.*`, `*.g.rs`, and `routeTree.gen.ts` remains observable. A burst is normalized into deterministic added/modified/deleted/renamed changes. Before repository-complete planning, one existing Web source write is checked with a canonical token-and-position fingerprint that permits harmless trailing trivia while retaining graph-affecting syntax, evidence positions, directives, tags, and quoted comment module candidates. If it is unchanged, the core sends a one-node `worker-delta-request-v1` projection and atomically promotes a sparse parent-snapshot overlay containing only the updated content hash. Status records versioned base-projection, worker capability, worker analysis, store-commit, and total timings. Any semantic or evidence-position change explicitly falls back to `incremental-plan-v1`; bounded scoped plans use the complete canonical delta contract, while legacy workers, workspace replans, unsupported adapter combinations, and complete-reanalysis closures above 4,096 paths use the atomic full scan. A newer burst cancels both capability probes and active scans, then requeues their changes; failed batches retry with bounded backoff. Shutdown cancels an active scan, performs one final pending-batch flush, waits for worker process-tree cleanup, and never promotes the cancelled attempt. Status uses schema `daemon-status-v1` and exposes active, last completed, last failed, last cancelled, watcher-error, and crash-recovery state. Public CLI and MCP JSON retain release evidence through a path-free invalidation summary containing only the schema version, mode, base profile-plan digest, and affected-profile count; raw invalidation plans and internal errors remain private. `[daemon].ignored_paths` accepts normalized repository-relative path prefixes.

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

The allowed Web adapter values are `next`, `astro`, `tanstack-router`, and
`tanstack-start`. The relative entrypoint must integrate the release-provided
observer named by `DEPGRAPH_OBSERVER` (and `NEXT_ADAPTER_PATH` for Next) into
the real build lifecycle. It runs in a temporary staged workspace using
canonical system Node, a cleared allowlisted environment, temporary
HOME/cache/output, bounded output, timeout/cancellation, and cross-platform
process-tree cleanup. Every launched attempt saves a secret-free audit
containing command metadata, logical paths, environment key names, limits,
isolation capability, and outcome; raw stdout/stderr and temporary or host
paths are not persisted. Network isolation is reported as `best-effort` unless
an outer namespace/container enforces it.

Validated observer output uses the shared `framework-build-graph-v1` contract:
`phase=build`, `precision=observed`, canonical production
profile/conditions, and primary `kind=build` evidence tied to the supervisor
audit digests. Generated node, site, and edge IDs exclude the attempt ID and
include the contract version; matching source/semantic nodes are reused only
when byte-identical. Repeated builds reuse the exact stored generated nodes and
omit already-promoted site, edge, and diagnostic IDs; a stable site with a new
target remains a conflict. The Next.js observer projects the stable 16.2+
Adapter API route/output manifests into `next-build-observation-v2`: ordinary,
RSC, and data variants share one canonical route; prerenders retain their
observed parent route; metadata routes, chunks, and server/client/edge/static
boundaries remain explicit. Raw output/build IDs and checkout roots never enter
portable identity. A dynamic target that was not observed is retained as an
`unresolved` edge to an `unknown_target` with a bounded reason, never promoted
to a guessed `resolved` edge. TanStack Start v1 production RPCs use
`tanstack-start-build-observation-v2`: the provider transform, resolver
manifest, client/SSR stubs, generated module roles, and manifest importer must
agree before an RPC ID is exact. A suffix-looking final ID is not separately
claimed as a collision unless the compiler exposes that fact. Missing static targets
remain unresolved and only build-correlated middleware chains receive observed
edges. The Next/Astro/TanStack Router/TanStack Start observer entrypoints and
their observation-to-protocol converter are separate checksum-attested release
artifacts; missing, undeclared, or changed bytes fail closed before project
code starts. The release compatibility unit pins the four observer
versions, observation schemas, dynamic capabilities, and runtime paths under
`dynamic-framework-evidence-release-gate-v1`. Every native package gate runs
the same static/semantic/build union fixture through filtered queries,
snapshot diff, impact, policy, JSON/GraphML export, checkout determinism, and
failed-build rollback. The observer and converter bundles are dependency-free
first-party SPDX packages with exact checksums, and the aggregate verifier
requires the same five-artifact closure from every target archive. The store saves the delta in an attempt transaction and
exposes it to `deps`, `dependents`, `why`, and exports only after completed
promotion. Source and semantic rows remain immutable; matching and conflicting
build observations coexist as separate layers, with conflicts carrying both
provenance sets. Failed, partial, timed-out, cancelled, malformed, unsupported,
or unauthorized deltas are discarded and never replace the current completed
graph.

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
- `crates/depgraph-rustc-wrapper`: attested all-unit rustc wrapper and bounded start/terminal ledger emitter
- `crates/depgraph-core` / `crates/depgraph-cli`: worker supervision, queries, export, doctor, and CLI UX
- `workers/rust`, `workers/go`, `workers/web`: ecosystem-native safe static adapters
- `xtask`: reproducible build, full quality checks, release archives, checksums, SBOM, and license inventory

## Compiler pack and release verification

The opt-in Rust compiler-precise toolchain is distributed separately from the
normal archive. `cargo xtask compiler-pack SOURCE OUTPUT --spec SPEC.json`
builds one target-specific, closed-tree pack from pre-extracted official
components and their sorted file ownership inventory. The resulting manifest
digest must be published through the referenced release checksum set; the core
requires that external digest and verifies the pack before project staging and
again after the supervised process tree has stopped. It never downloads through
rustup or falls back to PATH, system, or project toolchains.

Release tags build separate compiler packs for Linux x86-64/ARM64, macOS
Intel/Apple Silicon, and Windows x86-64 with `cargo xtask
compiler-pack-package`. Each native job verifies archive extraction,
closed-tree attestation, wrapper/query handshakes, typed MIR and monomorphized
call semantics, cross-checkout determinism, resource budgets, legal/provenance
metadata, tamper rejection, and rollback. `cargo xtask
verify-compiler-pack-assets` requires all five packs to share
`compiler-pack-five-target-release-v1`, the pinned toolchain/rustc/schema/query
identity, and the canonical semantic shape before the stable release gate can
publish them. Release metadata and `doctor --json` expose this separate
distribution and its `unsupported-no-fallback` policy.

Download the four assets for the depgraph version and host target from the
same [GitHub release](https://github.com/TamaT-LLC/depgraph-cli/releases). The
release tag may be the stable tag or its matching release candidate. The v0.5
example below becomes downloadable only after that candidate is published;
the normal depgraph archive and compiler pack must come from one release run.

```bash
version=0.5.4
release_tag=v0.5.4
target=x86_64-unknown-linux-gnu # doctor --json reports compiler_pack.host_target
name="depgraph-compiler-pack-${version}-${target}"

gh release download "$release_tag" \
  --repo TamaT-LLC/depgraph-cli \
  --pattern "$name.tar.gz" \
  --pattern "$name.tar.gz.sha256" \
  --pattern "$name.requirement.json" \
  --pattern "$name.smoke.json" \
  --dir "$name"
(cd "$name" && sha256sum --check "$name.tar.gz.sha256" && tar -xzf "$name.tar.gz")
depgraph doctor --compiler-pack-requirement "$name/$name.requirement.json"
```

Use `shasum -a 256 --check` on macOS. On Windows, download the `.zip` and
`.zip.sha256` assets, verify the SHA-256 with `Get-FileHash`, and extract with
`Expand-Archive` into the directory containing the requirement JSON. The
requirement's relative `root` then resolves to the extracted pack. A missing,
wrong-version, wrong-target, or modified pack remains unavailable; `doctor`
prints the exact expected asset names and depgraph never falls back to another
compiler.

The first compiler-precise execution stage is explicitly selected with all
three invocation gates and a release-bound requirement document:

```text
depgraph resolve --build PATH --allow-project-code --rust-compiler-precise \
  --compiler-pack-requirement compiler-pack-requirement.json
```

The requirement JSON contains `root`, `expected_manifest_sha256`,
`release_checksum_reference`, `host`, and `target`; a relative `root` is
resolved beside the requirement document. This stage replaces project Cargo
configuration with a deterministic offline projection after rejecting compiler,
wrapper, runner, linker, credential-provider, alias, environment, and unsafe
rustflag injection. It runs only the attested Cargo with `--frozen --offline
--unit-graph -Z unstable-options`, validates and canonicalizes unit graph v1,
and does not start rustc, build scripts, or proc macros. Registry and Git
dependencies are copied from an existing host Cargo cache into a bounded,
run-owned, credentials-free subset before Cargo starts; their source paths are
accepted only inside that staged Cargo home and normalized as
`cargo-home://...`. No network lookup or direct host-cache path is exposed to
the child or persisted DTO. A second supervised stage starts a fresh target,
fixes the attested wrapper as the only `RUSTC_WRAPPER`, verifies the exact
rustc path, executable digest, and `-vV` identity, and conserves one bounded
start/terminal ledger pair for every admitted target, dependency, build-script,
and proc-macro compiler unit. Nested wrappers, response/path escape,
extra/missing/duplicate units, partial terminals, or compiler substitution fail
the whole attempt. The canonical ledger contains staged logical paths and
digests rather than host paths or raw process streams. Later compiler-precise
stages add compiler query output; the ledger stage still does not promote graph
evidence.

Run `rustup component add rust-src --toolchain 1.93.1` once, then `cargo xtask package` to create a native archive under `dist/`. Release archives place `depgraph` and `depgraph-mcp` under `bin/`, compatible workers and `depgraph-operation-runner` under `libexec/`, and include the project's complete `LICENSE-MIT` and `LICENSE-APACHE` texts, checksum-verified protocol and `depgraph-mcp-tools-v1` schemas, an SPDX SBOM, and a separate third-party license inventory. The release manifest declares `MIT OR Apache-2.0`, attests both project license files independently from `THIRD_PARTY_LICENSES.txt`, and binds the MCP server and runner digests to `rmcp 3.1.0`, MCP revision `2026-07-28`, `depgraph-mcp-tools-v1`, and `depgraph-operation-v1`. The SBOM and license inventory include the complete shipped rmcp dependency closure and an Apache-2.0 notice. The release gate fixes Rust/Cargo `1.93.1`; the Rust worker manifest records the linked backend unit, rust-analyzer `0.0.330` at revision `8954b66d43225e62c92e8bbcc8500191b5cceb1e` with Salsa `0.26.1`. It also carries `rust-stdlib-source@1.93.1+rustc.01f6ddf7588f42ae2d7eb0a2f21d44e8e96674cf` under `libexec/rust-sysroot` as a licensed, SBOM-recorded `data-tree` copied only from that pinned toolchain's `rust-src` and independently matched to the known normalized digest `cc5465ef70b933d2a80c30472468abb9f8ab297fc767bd6433b2f6f554f4f0e7`. The Web worker manifest records the exact TypeScript version, the complete Web semantic capability set, and its Astro and TypeScript runtime components.

The package verifier extracts the archive and validates the manifest, both project licenses, every artifact and runtime component, MCP/Rust/Web handshakes, per-framework scan/query/export E2E, dynamic framework build query/diff/impact/policy/JSON/GraphML E2E, cross-checkout determinism, rollback, and the complete runtime SBOM and third-party license closure. Missing, added, modified, symlinked, or version-mismatched license, MCP server/runner/schema/SDK metadata, Web worker, build observer/converter, Astro parser, TypeScript compiler, Rust sysroot source, or schema input fails before worker launch. Runtime components distinguish an `executable-tree` with an executable entrypoint from a `data-tree` whose entrypoint is optional. The aggregate release verifier requires all five target archives to attest identical MCP schema and Rust sysroot source bytes. After core verifies that data tree, it hands the canonical root to the packaged Rust worker; the worker rechecks the pinned source identity, builds separate library VFS roots for `core`, `alloc`, and `std`, and emits exact standard-library import, type-use, and direct-call edges. Development, mismatched, missing, unsupported-target, and tampered inputs preserve syntax output without `semantic-complete`, and neither packaging nor scanning falls back implicitly to project or system `rust-src` or backend bytes. Tier 1 Linux/macOS package gates and Windows safety/determinism smoke cover the MCP, Web semantic, dynamic framework, and Rust sysroot archive contracts.

`mcp-package-smoke-v3` also runs `depgraph agent-config` for all three host
formats from a clean temporary home, verifies the complete package/root/Store/
compiler-pack tuple against a separately pinned `release-post-publish-evidence-v1`
digest, connects through the generated read-only launch arguments, and rejects
any repository, private Store, host-config, or journal mutation. Its report
records `agent_host_release_evidence_contract_version` and requires
`agent_host_release_trust_verified=true`.
The CLI runtime closure for this archive preflight (`flate2`, `tar`, `zip`, and
their transitive dependencies) is included in the SBOM and third-party license
inventory.

## License

Licensed under either [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE) at your option.

Copyright (c) 2026 TamaT LLC.
