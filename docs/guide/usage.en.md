# Usage guide

[日本語](usage.md) | English

This guide continues from the [README](../../README.en.md). It covers scan
settings, the full command list, how to read results, exit codes, and a
complete set of CLI examples.

## Scan settings and resuming

Results are stored in an SQLite Store under the operating system cache
directory, keyed by the canonical repository root. To use a fixed location,
pass a global option such as
`depgraph --store /path/to/depgraph.sqlite scan /path/to/repository`.
Configuration is optional; `.depgraph.toml` is written only when you run
`depgraph init /path/to/repository`.

Go and Web scans discover directories and workspaces before processing logical
units and source batches. Run `scan` again with the same Store to reuse completed
work after validating its inputs and worker compatibility. There is no default
whole-scan deadline. Each worker has inactivity, memory, output, and concurrency
limits. In `.depgraph.toml`, `[scan]` supports `max_unit_source_files` (default 2,048),
`max_unit_source_bytes` (8 MiB), `max_context_source_bytes` (64 MiB),
`max_concurrent_units` (2), `max_worker_memory_bytes` (2 GiB), and
`worker_timeout_seconds` (300 seconds without progress). Set
`total_budget_seconds` when an explicit whole-scan time budget is needed.
`scan --split-plan [--json]` explains, without launching workers, each execution
unit's ownership scope, the scope its loader actually reads, reference-only
inputs, work estimate, split reasons, and the parallelism decision (see the
[pre-split planning ADR](../40_arch_design/adr-presplit-analysis-planning.md)).
See [integration validation](../40_arch_design/resumable-analysis-validation.md)
for batching, interruption, recovery, and dependency invalidation checks.

To inspect an incomplete attempt, take its `scan_id` from `scan --json` and select
it explicitly, for example `depgraph --scan-id "attempt:$SCAN_ID" deps path:src/app.ts --json`.
The result identifies its incomplete analysis and coverage while the existing
completed snapshot remains current. This selector works with `deps`,
`dependents`, `why`, `impact`, `cycles`, `unresolved`, health, and graph export.
Named snapshots, diff, policy, bounded query, and runtime validation use
completed snapshots.

## Commands by question

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
| Where are the graph hotspots? | `hotspots` | Integer basis-point ranks from fan-in, fan-out, reverse impact, Git churn, and runtime observation. Each finding exposes `hotspot_scores` with raw, normalized, weight, available, and total fields; confidence is capped at `probable` |
| How can an Agent inspect it? | `agent-config`, `depgraph-mcp` | MCP host configuration bound to a verified package. The `health_*` tools share the same confidence limits |

### Selecting edge kinds in dependency lists

`deps` and `dependents` return structural edges alongside dependency edges.
The structural edges are `contains` (a package contains a file), `declares`
(a file declares a symbol), and `generated_from` (a generated file comes from
its source). To count the files that actually depend on a node, drop them with
`--structural-edges exclude`. When omitted, the mode is `include` and
structural edges stay in the result as before.

```bash
depgraph dependents path:src/a.ts --structural-edges exclude --json
depgraph deps path:src/app.ts --transitive --edge-kind imports --edge-kind type_uses --json
```

- `--edge-kind` selects the edge kinds to follow. It is repeatable, and only
  edges of the listed kinds are followed.
- The selection applies during traversal, so item counts and
  `traversed_items` cover only the selected edges.
- Combining `--structural-edges exclude` with a structural `--edge-kind` is
  contradictory and fails.
- A `--cursor` from a different selection is rejected.

The MCP `graph_dependencies_list` and `graph_dependents_list` tools accept the
same selection as `edge_kinds` and `structural_edges`.

## Reading code-health confidence

Confidence on `health` findings reserves `confirmed` for `unused-file`,
`unused-export`, `unused-type`, and `unused-dependency`. It means the subject is
unused across every applicable analyzed profile, those profiles are
semantic-complete, and no hard blocker remains.

- `test-only-dependency`, `manifest-mismatch`, audit, and hotspot findings are
  not proof of unusedness and are capped at `probable`.
- For unused findings, `probable` means there is no observed usage and no hard
  blocker, but applicable profiles are only syntax-complete.
- `indeterminate` is blocked by incomplete or missing coverage/surface
  evidence, public surface, entry points, dynamic loading, candidates,
  unresolved sites, unanalyzed profiles, manifest drift, or a
  missing/mismatched audit base.

To inspect only some directories or node kinds, narrow the hotspot results
with `--path-prefix` and `--node-kind`. Both flags are repeatable.

```bash
depgraph hotspots --path-prefix src/lib --node-kind file --node-kind symbol --json
```

- `--path-prefix` matches repository-relative paths at a directory boundary:
  `src/lib` matches `src/lib/a.ts` but not `src/library.ts`. Findings without
  a path never match.
- `--node-kind` accepts `file`, `module`, `symbol`, `type`, or `route`.
- Filters apply after scoring, so normalized scores and finding IDs equal the
  unfiltered ranking. The `collection_digest` differs per filter.
- `--churn-path` only narrows the Git churn input and never removes findings.

The MCP `health_hotspots_list` tool accepts the same filters as `path_prefixes`
and `node_kinds`.

Read the typed hotspot score layers (`fan_in`, `fan_out`, `reverse_impact`,
`git_churn`, `runtime`, and `total`) instead of parsing `reason`. Finding
`suppressions` remain a wire-compatible output-only/deferred field in v1: there
is no CLI, MCP, or policy input path, and built-in analyzers always return an
empty array. Audits compare the policy digest, analyzer version, and
finding-contract version that Store schema 18 and later record for each
snapshot; missing or mismatched provenance fails closed as
`incomparable-policy` or `incomparable-contract`. `v0.6.3` uses Store schema
19. The published `v0.5.4` artifact uses Store schema 17 and is outside this
audit provenance contract. Source is never changed automatically. The complete
contract is in the
[code-health finding ADR](../40_arch_design/adr-code-health-finding-contract.md).

## Selectors

A **selector** identifies a graph node on the CLI. The accepted prefixes are
`id:`, `path:`, `package:`, `route:`, `symbol:`, and `type:`. Next.js App
Router routes have a source node (`next:/checkout`) and a semantic node
(`next:app:page:/checkout`), so `route:/checkout` can be ambiguous; use the
display name (`route:next:app:page:/checkout`) or an `id:` from the reported
candidates. If more than one candidate matches, pass the complete Stable ID
returned by the command as `id:<stable-id>`.

In the `v0.6.4` release candidate, `package:` also matches external dependency packages
such as npm packages (`package:stripe`, `package:stripe@18.0.0`, or the full
locator `package://npm:stripe@18.0.0#node_modules/stripe`). The published
`v0.6.3` release does not support this form. See the
[CLI behavior reference](../reference/cli-behavior.md#selectors) for the full
selector rules.

## How dependency sites are classified

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

A profile is marked **`semantic-complete`** only when its semantic analysis
met every completeness requirement; it never means that missing dependencies
were guessed. See [analysis completeness](../reference/analysis-completeness.md)
for the exact conditions.

## Strict policy and exit codes

The default `.depgraph.toml` strict policy permits zero skipped files, unsupported syntax, or unresolved sites. Candidate and external dependencies alone do not fail strict mode.

`depgraph scan --strict` is intended for CI and rejects skipped files,
unsupported syntax, and unresolved sites. For normal exploration, start with
the default scan and use `doctor` and `unresolved` to inspect coverage.

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

## CLI examples

```sh
# Optional tracked-project configuration; scanning works without it.
depgraph init .

# Safe static analysis; does not modify the target repository.
depgraph scan /path/to/repository
depgraph scan /path/to/repository --strict
depgraph scan /path/to/repository --no-cache
depgraph scan /path/to/repository --plan --json
depgraph scan /path/to/repository --split-plan --json

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
depgraph resolve --build /path/to/repository --allow-project-code --json

depgraph doctor --json
depgraph doctor --details --json
depgraph doctor --root /path/to/repository --json
depgraph deps path:src/app.ts --transitive --max-items 100 --max-bytes 1048576
depgraph deps path:src/app.ts --transitive --cursor "$NEXT_CURSOR" --json
depgraph deps path:src/app.ts --transitive --all --json
depgraph dependents package:example
depgraph why path:src/app.ts 'route:/products/$id'
depgraph impact path:src/app.ts
depgraph impact package:example --changed origin/main --depth 4
depgraph impact 'route:/products/$id' --changed HEAD~1 --profile web:production:server --json
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

## More detail

- [CLI behavior reference](../reference/cli-behavior.md): Store, bounded
  queries, snapshots, diff, impact, the watcher daemon, and selectors
- [Architecture policy contract](../reference/architecture-policy.md)
- [Runtime trace import contract](../reference/runtime-trace.md)
- [Safe-scan boundary](../reference/safe-scan-boundary.md)
- [Build-mode consent boundary](../reference/build-mode.md)
