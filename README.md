# depgraph

`depgraph` is a local-first CLI that extracts explainable dependency graphs from Rust, Go, TypeScript/JavaScript, Next.js, Astro, TanStack Router, and TanStack Start repositories.

Every recognized dependency site is retained as `resolved`, `candidates`, `external`, or `unresolved`. Edges carry their profile, canonical condition, precision, and source evidence; condition-specific package targets retain their own edge condition. Skipped and unsupported input is reported through the coverage ledger rather than silently dropped.

The MVP implements the architecture described in [the system design](docs/40_arch_design/arch-dependency-graph-cli-system-design.md): a Rust core, isolated Rust/Go/Web workers using protocol `1.0` NDJSON, an immutable SQLite evidence store, graph queries, and deterministic JSON/DOT/Mermaid/GraphML export.

The current stable release is [`v0.4.0`](docs/releases/v0.4.0.md).
The Milestone 4 release candidate and previous Milestone 2 semantic-graph
candidate remain documented as [`v0.4.0-rc.1`](docs/releases/v0.4.0-rc.1.md)
and
[`v0.2.0-rc.1`](docs/releases/v0.2.0-rc.1.md).

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
complete their versioned framework semantic capability ledger. Architecture
policy evaluation and GitHub annotations, collector-independent runtime trace
validation and persistent runtime evidence union, immutable snapshots,
diff/impact, deterministic GraphML, the supervised build protocol, validated
syntax/semantic/build cache storage, transactional incremental invalidation
planning, and the cross-platform watcher daemon are available.

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

To run the reproducible performance gate with the pinned toolchains:

```sh
scripts/benchmark-mvp.sh
```

The benchmark generates a deterministic 10,000-source-file fixture and writes
`dist/benchmark-report.json`. It records cold safe initial scans, watcher-driven
one-file incremental scans, cold and warm file/package impact queries, platform
and toolchain metadata, every raw sample, and the configured regression/noise
policy. The gate also proves that the changed file was observed while graph
topology, dependency sites, evidence, and coverage were conserved. CI and tag
release workflows upload the same versioned report as an artifact; release
publication verifies it before publishing.

## Usage

```sh
# Optional tracked configuration. Scan works without it.
depgraph init .

# Safe static scan. The target repository is not modified.
depgraph scan /path/to/repository
depgraph scan /path/to/repository --strict
depgraph scan /path/to/repository --no-cache

# Foreground watcher daemon; status and stop work from another process.
depgraph daemon start /path/to/repository
depgraph daemon status /path/to/repository --json
depgraph daemon stop /path/to/repository

# Privileged build-observation consent form.
depgraph resolve --build /path/to/repository --allow-project-code

depgraph doctor --json
depgraph deps path:src/app.ts --transitive
depgraph dependents package:example
depgraph why path:src/app.ts route:/products/$id
depgraph impact path:src/app.ts
depgraph impact package:example --changed origin/main --depth 4
depgraph impact route:/products/$id --changed HEAD~1 --profile web:production:server --json
depgraph cycles --level file

# Go semantic graph queries use canonical resolver identities.
depgraph deps symbol:example.com/semantic/model.Build --transitive
depgraph dependents type:example.com/semantic/model.Worker --json
depgraph why symbol:example.com/semantic/model.Build type:example.com/semantic/model.Input --json
depgraph cycles --level symbol

# If a selector is ambiguous, rerun it with a stable ID from the candidates.
depgraph deps "id:$STABLE_ID" --json

depgraph unresolved --json

# Validate and match an external runtime trace without changing the store.
depgraph runtime validate runtime-trace.json
depgraph runtime validate runtime-trace.json --json

# Name and inspect immutable completed snapshots.
depgraph snapshot create baseline
depgraph snapshot list --json
depgraph snapshot show baseline
depgraph snapshot show snapshot:sha256:... --json

# Compare completed snapshots by name or stable ID.
depgraph diff baseline current
depgraph diff baseline current --json
depgraph diff baseline current --kind symbol --profile web:production:server
depgraph diff baseline current --phase semantic --status unresolved

depgraph export --format json --output graph.json
depgraph export --format dot > graph.dot
depgraph export --format mermaid > graph.mmd
depgraph export --format graphml --output graph.graphml
```

SQLite is stored under the operating system cache directory, keyed by the canonical repository root. Use global `--store PATH` for a specific database and global `--scan-id ID` to inspect a retained partial scan. Queries default to the latest successful scan; `doctor` reports the latest attempt.

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

`depgraph runtime validate TRACE` reads the versioned `1.0` JSON contract,
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
only after key, contract, completed-snapshot, and canonical payload integrity
checks, then copied into a fresh scan attempt and validated before promotion.
Unknown versions, corruption, symlinks, unsafe inventory bounds, and
dependency snapshots that cannot be re-derived before scanning are explicit
misses/rejections. `scan --no-cache` bypasses lookup and storage. Scan
JSON/text and `doctor` expose cache hit/miss/reject reasons without adding
cache bookkeeping to the canonical graph.

`snapshot create` names the current completed snapshot; global `--scan-id ID` may instead select the completed snapshot produced by that scan and its latest promoted build. Failed or incomplete attempts cannot be named. Names are immutable, case-insensitively unique, 1–64 ASCII characters, begin with a letter or digit, and otherwise use letters, digits, `.`, `_`, or `-`. `current` and `latest` are reserved, and existing names are never overwritten. `snapshot show` accepts a name, a `snapshot:sha256:...` stable ID, or `current`. List and detail JSON are emitted in canonical order.

`diff` accepts two completed snapshot names, stable IDs, or `current`; failed and incomplete attempt IDs are rejected with exit code `2`. Human output starts with node/site/edge/evidence/profile/coverage/rename counts and follows with canonical change details plus primary source evidence. `--json` emits the versioned `diff` command envelope with normalized filters, a summary, and the canonical before/after records. Repeatable `--kind`, `--profile`, `--phase`, and `--status` filters use exact matching and AND semantics; a record type that does not expose a selected dimension is excluded rather than guessed through an implicit graph join.

`impact <SELECTOR>` follows incoming dependencies from the selected node and reports a deterministic dependency path, rendered condition, profile correlation, and source evidence for every result. With `--changed <GIT_REF>`, depgraph reads both committed changes from `merge-base(GIT_REF, HEAD)..HEAD` and staged, unstaged, and untracked worktree changes without taking Git locks or invoking external diff/textconv helpers. Changed and renamed paths are correlated to file and semantic node identities through canonical node properties and stored evidence. The selector is the focus: it must depend on a mapped changed node, then reverse traversal reports the focus and its dependents. Repeatable `--profile`, `--condition`, `--phase`, `--session`, and `--environment` filters are exact; runtime environment matching includes its name, runtime, and region. `--depth`, `--max-nodes`, and `--max-edges` bound traversal, and a reached safety limit is returned as `complete=false` with an explicit diagnostic rather than silently truncating results.

`daemon start` uses the platform-recommended recursive filesystem watcher and a configurable `[daemon].debounce_milliseconds` (default `200`). VCS metadata, dependency/build output directories, the graph store, and daemon control files are ignored; tracked generated source such as `generated`, `*.generated.*`, `*.g.rs`, and `routeTree.gen.ts` remains observable. A burst is normalized into deterministic added/modified/deleted/renamed changes. Before repository-complete planning, one existing Web source write is checked with a canonical token-and-position fingerprint that permits harmless trailing trivia while retaining graph-affecting syntax, evidence positions, directives, tags, and quoted comment module candidates. If it is unchanged, the core sends a one-node `worker-delta-request-v1` projection and atomically promotes a sparse parent-snapshot overlay containing only the updated content hash. Status records versioned base-projection, worker capability, worker analysis, store-commit, and total timings. Any semantic or evidence-position change explicitly falls back to `incremental-plan-v1`; bounded scoped plans use the complete canonical delta contract, while legacy workers, workspace replans, unsupported adapter combinations, and complete-reanalysis closures above 4,096 paths use the atomic full scan. A newer burst cancels both capability probes and active scans, then requeues their changes; failed batches retry with bounded backoff. Shutdown cancels an active scan, performs one final pending-batch flush, waits for worker process-tree cleanup, and never promotes the cancelled attempt. Status uses schema `daemon-status-v1` and exposes active, last completed, last failed, last cancelled, watcher-error, and crash-recovery state. `[daemon].ignored_paths` accepts normalized repository-relative path prefixes.

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
- `crates/depgraph-core` / `crates/depgraph-cli`: worker supervision, queries, export, doctor, and CLI UX
- `workers/rust`, `workers/go`, `workers/web`: ecosystem-native safe static adapters
- `xtask`: reproducible build, full quality checks, release archives, checksums, SBOM, and license inventory

Run `rustup component add rust-src --toolchain 1.93.1` once, then `cargo xtask package` to create a native archive under `dist/`. Release archives place `depgraph` under `bin/`, compatible workers under `libexec/`, and include the project's complete `LICENSE-MIT` and `LICENSE-APACHE` texts, a checksum-verified release manifest, protocol schema, SPDX SBOM, and a separate third-party license inventory. The release manifest declares `MIT OR Apache-2.0` and attests both project license files independently from `THIRD_PARTY_LICENSES.txt`. The release gate fixes Rust/Cargo `1.93.1`; the Rust worker manifest records the linked backend unit, rust-analyzer `0.0.330` at revision `8954b66d43225e62c92e8bbcc8500191b5cceb1e` with Salsa `0.26.1`. It also carries `rust-stdlib-source@1.93.1+rustc.01f6ddf7588f42ae2d7eb0a2f21d44e8e96674cf` under `libexec/rust-sysroot` as a licensed, SBOM-recorded `data-tree` copied only from that pinned toolchain's `rust-src` and independently matched to the known normalized digest `cc5465ef70b933d2a80c30472468abb9f8ab297fc767bd6433b2f6f554f4f0e7`. The Web worker manifest records the exact TypeScript version, the complete Web semantic capability set, and its Astro and TypeScript runtime components.

The package verifier extracts the archive and validates the manifest, both project licenses, every artifact and runtime component, Rust and Web worker handshakes, per-framework scan/query/export E2E, dynamic framework build query/diff/impact/policy/JSON/GraphML E2E, cross-checkout determinism, rollback, and the complete runtime SBOM and third-party license closure. Missing, added, modified, symlinked, or version-mismatched license, Web worker, build observer/converter, Astro parser, TypeScript compiler, Rust sysroot source, or schema input fails before worker launch. Runtime components distinguish an `executable-tree` with an executable entrypoint from a `data-tree` whose entrypoint is optional. The aggregate release verifier requires all five target archives to attest identical Rust sysroot source bytes. After core verifies that data tree, it hands the canonical root to the packaged Rust worker; the worker rechecks the pinned source identity, builds separate library VFS roots for `core`, `alloc`, and `std`, and emits exact standard-library import, type-use, and direct-call edges. Development, mismatched, missing, unsupported-target, and tampered inputs preserve syntax output without `semantic-complete`, and neither packaging nor scanning falls back implicitly to project or system `rust-src` or backend bytes. Tier 1 Linux/macOS package gates and Windows safety/determinism smoke cover the Web semantic, dynamic framework, and Rust sysroot archive contracts.

## License

Licensed under either [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE) at your option.

Copyright (c) 2026 TamaT LLC.
