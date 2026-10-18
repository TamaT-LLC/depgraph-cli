# depgraph verification map

This directory is the maintained source for verifying the user-facing behavior of the `depgraph` CLI. Read this index before driving, then use the matching feature file as the recipe. All commands assume `V=.claude/skills/verify-depgraph/scripts/vdg` from the repository root.

## Baseline preconditions

- `$V launch` finished with `vdg: ready run=<id> ...`, so the fixture crate `vdg-fixture` (`src/lib.rs`, `src/cart.rs`, `src/checkout.rs`, git branch `main`, one commit) is scanned into the sandbox Store.
- `$V doctor` ends with `vdg doctor: run <id> is worth driving`.
- Only the Rust worker is available unless launch used `--all-workers`.
- Never drive a Store that this run did not create. Never pass the default OS cache path as `--store`.

## Driving conventions

- Start every recipe from the baseline state unless its preconditions say otherwise. A recipe that mutates the fixture (`$V fixture-change`) needs a fresh `$V launch` before recipes that expect the baseline.
- Run every `depgraph` call as `$V run <label> -- <args>`; never call `target/debug/depgraph` directly against a real repository.
- Use selectors, not hash ids: `path:src/cart.rs`, `symbol:checkout::pay`. Hash ids (`file:sha256:...`) change with content.
- Assert on `--json` fields with `jq`; use the first text summary line only as a human cross-check.
- Treat every command as literal; keep quoted selectors and flags unchanged.

## Proof and skip reporting

- CLI proof is `<label>.cmd`, `.stdout`, `.stderr`, `.exit` in `$($V evidence-dir)`, plus a `vdg note` line stating the jq assertion and its result.
- Capture the scan that produced the snapshot and the query that reads it; for mutations capture before and after.
- A mutation proof includes a second read-only view (another query, or `doctor --json` `latest_successful_scan_id`).
- Record the feature ID (from `Sub-features`) in the `vdg run` label, for example `impact-selector`.
- Report an unreachable path with the attempted command and the unmet precondition. Do not report a skipped entry point as verified through a different path.

## Feature entry contract

Each feature file starts with an H1 title and one paragraph describing the user-visible behavior, then exactly four H2 sections in this order: `Sub-features`, `How to get to it (user POV)`, `Driving it with vdg` (starts with `Preconditions:`; labeled bullets pairing a user action with an exact command and observable result), `Gotchas`.

## Features

- [Safe scan](./scan.md) covers `scan`, `--json`, `--strict`, `--plan`, rescans and cache reuse.
- [Dependencies and dependents](./deps-dependents.md) covers `deps` and `dependents`, direct and transitive.
- [Why](./why.md) covers the explained shortest path between two selectors, including the no-path case.
- [Impact](./impact.md) covers reverse impact for a selector and for a Git changed set (`--changed`).
- [Analysis health](./doctor-unresolved.md) covers `doctor` and `unresolved`.

## Not yet mapped

- `depgraph-mcp` stdio server and `depgraph mcp setup|status|update|uninstall`, `agent-config`: need a verified compiler pack / official release download; see `SKILL.md`.
- Go and Web adapters (Go modules, TS/JS, Next.js, Astro, TanStack routes): need `$V launch --all-workers` and a fixture of that ecosystem.
- `export`, `cycles`, `snapshot`/`diff`/`policy`, `health`/`cleanup`/`audit`/`hotspots`, `query`, `runtime`, `daemon`, `resolve --build` (project-code execution, exit 4 without `--allow-project-code`).
