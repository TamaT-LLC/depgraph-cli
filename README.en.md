# depgraph

[Japanese](README.md) | English

[![CI](https://github.com/TamaT-LLC/depgraph-cli/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/TamaT-LLC/depgraph-cli/actions/workflows/ci.yml)
[![GitHub Release](https://img.shields.io/github/v/release/TamaT-LLC/depgraph-cli)](https://github.com/TamaT-LLC/depgraph-cli/releases/latest)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

`depgraph` is a CLI that turns your code's dependencies into a graph and
answers questions such as "what could this change break?" and "why does this
file depend on that one?", with the source locations that prove each answer.
It covers Rust, Go, and TypeScript/JavaScript, and puts Next.js, Astro, and
TanStack routes into the same graph. It runs on your machine and does not
execute your project's code.

## What it helps with

**Check the impact of a change before review.**
List everything that depends on the files you changed since `main`.

```sh
depgraph impact path:src/lib/cart.ts --changed main
```

**Find out why a dependency exists.**
Show the dependency path between two files, with the import or call that
creates each step.

```sh
depgraph why path:src/app/checkout/page.tsx path:src/lib/cart.ts
```

**Let an AI agent ask the same questions.**
Register depgraph as a read-only MCP server for Claude Code, Codex, Cursor, or
Grok.

```sh
depgraph mcp setup --host claude
```

## Introduction video

This video (about 56 seconds) walks through the three use cases above. The
narration and on-screen text are in English.

https://github.com/user-attachments/assets/e9a34a03-5d62-4902-b735-a2d8639833fe

## Try it in 30 seconds

```sh
# Install (macOS Apple Silicon / Linux)
brew install tamat-llc/tap/depgraph
# Or install with npm (Node.js 24 or later)
npm i -g @tamat-llc/depgraph

# Run inside the repository you want to inspect
cd /path/to/your-repository
depgraph scan .
depgraph impact path:src/lib/cart.ts --changed main
depgraph why path:src/app/checkout/page.tsx path:src/lib/cart.ts
```

Replace `src/lib/cart.ts` and the other paths with files in your repository.

- `scan` only reads files. It does not run build scripts, plugins, or package
  managers.
- Results are saved in a database under your OS cache directory, one per
  repository. Your repository is not modified.
- Run `depgraph doctor` to see how much of the code was analyzed.

## Common commands

| Question | Command |
| --- | --- |
| What does this file use? | `depgraph deps path:src/app.ts --transitive` |
| What uses this file? | `depgraph dependents path:src/app.ts --transitive` |
| Why does A depend on B? | `depgraph why path:src/app.ts path:src/lib/db.ts` |
| What does my change affect? | `depgraph impact path:src/app.ts --changed origin/main` |
| What could not be analyzed? | `depgraph unresolved` |
| Is the analysis healthy? | `depgraph doctor` |
| Can I share the graph? | `depgraph export --format mermaid > graph.mmd` |

Commands take a *selector* that names what you want to look at:

- `path:src/app.ts` selects a file by its repository-relative path.
- `package:example` selects a workspace package by name.
- `id:<stable-id>` selects a node by the exact ID that depgraph printed,
  which is useful when a name matches more than one node.

The [usage guide](docs/guide/usage.en.md) lists every command, scan setting,
exit code, and many more examples.

## Use from AI agents (MCP)

`depgraph mcp setup` downloads the matching official release, verifies it,
creates the first snapshot with a safe scan, and adds a `depgraph` entry to the
host configuration. Run it inside the Git repository the agent should inspect.

| `--host` | Agent | Project configuration file |
| --- | --- | --- |
| `claude` | Claude Code | `.mcp.json` |
| `codex` | Codex | `.codex/config.toml` |
| `cursor` | Cursor | `.cursor/mcp.json` |
| `grok` | Grok | `.grok/config.toml` |

Add `--scope user` to write the user configuration instead. After setup,
restart or reload the agent. Use the same `--host` (and `--scope`) with these
commands to manage the entry:

```sh
depgraph mcp status --host claude
depgraph mcp update --host claude
depgraph mcp uninstall --host claude
```

The installed server is read-only: it cannot change the Store, write to the
repository, or run project code. Privileged profiles, manual configuration with
`agent-config`, and troubleshooting are covered in the
[MCP Agent host operations runbook](docs/50_test/mcp-agent-host-operations.md).

## Supported languages and frameworks

| Target | Main extracted elements |
| --- | --- |
| Rust | Cargo workspace/package/target, module, import, re-export, symbol, type, type-use, exact call, candidate call |
| Go | workspace, module, package variant, build constraint, import, symbol, type, generic instance, direct call, candidate call, cgo boundary |
| TypeScript and JavaScript | npm/pnpm/Yarn/Bun workspace, package, file, TypeScript/JavaScript symbol/type/import/re-export/type-use, exact call, candidate call |
| Next.js | App Router and Pages Router, route component, render relation, parent route, client/server boundary, statically resolvable dynamic component |
| Astro | page, endpoint, component, hydration boundary, frontmatter import, content collection, asset |
| TanStack Router | file route, code route, virtual route, generated route tree, loader, `beforeLoad`, lazy route, context, route mask |
| TanStack Start | server function, RPC relation, server route, middleware chain |

depgraph does not guess. When a dependency cannot be pinned to one target, it is
reported as a candidate set or as unresolved, with the reason. See
[how dependency sites are classified](docs/guide/usage.en.md#how-dependency-sites-are-classified).

## Installation

`v0.6.3` provides Linux x86-64, Linux ARM64, macOS Apple Silicon, and Windows
x86-64 packages. Intel macOS is not supported.

- **Homebrew** (macOS Apple Silicon / Linux): `brew install tamat-llc/tap/depgraph`
- **npm** (Node.js 24 or later): `npm i -g @tamat-llc/depgraph`
- **GitHub Release**: download the archive for your `TARGET` from the
  [Releases page](https://github.com/TamaT-LLC/depgraph-cli/releases).

| Environment | `TARGET` |
| --- | --- |
| Linux x86-64 | `x86_64-unknown-linux-gnu` |
| Linux ARM64 | `aarch64-unknown-linux-gnu` |
| macOS Apple Silicon | `aarch64-apple-darwin` |
| Windows x86-64 | `x86_64-pc-windows-msvc` |

Checksum verification, Windows steps, and the compiler pack used by
`depgraph-mcp` are described in the [installation guide](docs/guide/install.en.md).

## Safety

The default scan reads source files, manifests, lockfiles, and static
configuration only. It does not run project configuration, plugins, package
managers, generators, build scripts, or proc macros. A default scan records
`project_code_executed` as `false`.

The only mode that may run project code is
`depgraph resolve --build PATH --allow-project-code`. It requires that flag on
every run; without it, the command stops with exit code `4` before doing
anything. See the
[safe-scan boundary](docs/reference/safe-scan-boundary.md) and the
[build-mode consent boundary](docs/reference/build-mode.md).

## Documentation

| I want to... | Read |
| --- | --- |
| Learn every command, setting, and exit code | [Usage guide](docs/guide/usage.en.md) |
| Install, verify archives, or build from source | [Installation guide](docs/guide/install.en.md) |
| Check release compatibility and Store schema | [Releases and compatibility](docs/guide/compatibility.en.md) |
| Connect an AI agent in detail | [MCP Agent host operations](docs/50_test/mcp-agent-host-operations.md) |
| Read detailed CLI contracts | [CLI behavior reference](docs/reference/cli-behavior.md) |
| Enforce architecture rules | [Architecture policy contract](docs/reference/architecture-policy.md) |
| Import runtime traces | [Runtime trace import contract](docs/reference/runtime-trace.md) |
| Understand the design | [the system design (Japanese)](docs/40_arch_design/arch-dependency-graph-cli-system-design.md) |
| Browse all documents | [Documentation index (Japanese)](docs/00_index/index.md) |

## Project status and public collaboration

The supported line is currently anchored by the published `v0.6.3` Release.
Changes on `main` after that tag are development changes. See the
[`v0.6.3` release notes](https://github.com/TamaT-LLC/depgraph-cli/releases/tag/v0.6.3)
on GitHub Releases for what it contains.
Product support is best effort, without response-time or resolution-time SLAs.

Follow [SUPPORT.md](SUPPORT.md) for usage questions and bug reports. Read
[CONTRIBUTING.md](CONTRIBUTING.md) before opening an issue or pull request, and
see [GOVERNANCE.md](GOVERNANCE.md) for decision-making and maintainer roles.
Participation is governed by [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

Never report a suspected vulnerability through a public issue; use the private
channel documented in [SECURITY.md](SECURITY.md).

## Contributing

The pinned development toolchains are Rust 1.93.1, Go 1.26.1, Node.js 24.18.0, and pnpm 10.33.0.
Build the CLI and workers with `cargo xtask build`, and run every check with
`cargo xtask test`. See [CONTRIBUTING.md](CONTRIBUTING.md) for the full
workflow.

## License

Licensed under either [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE) at your option.

Copyright (c) 2026 TamaT LLC.
