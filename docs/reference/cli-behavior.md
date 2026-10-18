# CLI behavior reference

[Back to the README](../../README.en.md) · [Usage guide](../guide/usage.en.md)

This page collects the detailed CLI contracts for the Store, queries, snapshots,
impact analysis, the watcher daemon, and selectors. For a task-oriented
introduction, start with the [usage guide](../guide/usage.en.md).

## Store location and scan selection

SQLite is stored under the operating system cache directory, keyed by the canonical repository root. Use global `--store PATH` for a specific database and global `--scan-id ID` to inspect a retained partial scan. Queries default to the latest successful scan; `doctor` reports the latest attempt.

## doctor

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

## Bounded interactive queries

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

## Profile planning

`profiles plan` is read-only and uses only a bounded static inventory. Its human
and canonical JSON output includes every selected, omitted, and policy-excluded
profile with rank evidence and the schema-v1 configuration migration
diagnostic. `--profile-budget` accepts `1..=32` while reserving every detected
language baseline. `--profiles-file` instead reads a confined, non-symlink,
UTF-8 JSON file of at most 64 KiB; it is all-or-error and cannot be combined
with `--profile-budget`.

## GraphML export

GraphML exports use standard directed `node` and `edge` elements with generated
XML-safe element IDs. The original stable IDs, kinds, phase, profile,
condition, precision, resolution, and environment remain available through
typed GraphML keys. Complete profile, dependency-site, and evidence records use
canonical JSON graph properties, with explicit owner references that allow the
records to be reconstructed without source-store access. `--output` writes
GraphML incrementally through a bounded buffer into a sibling temporary file,
then atomically replaces the destination only after export succeeds.

## Store schema and caches

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

## Snapshots and diff

`snapshot create` names the current completed snapshot; global `--scan-id ID` may instead select the completed snapshot produced by that scan and its latest promoted build. Failed or incomplete attempts cannot be named. Names are immutable, case-insensitively unique, 1–64 ASCII characters, begin with a letter or digit, and otherwise use letters, digits, `.`, `_`, or `-`. `current` and `latest` are reserved, and existing names are never overwritten. `snapshot show` accepts a name, a `snapshot:sha256:...` stable ID, or `current`. List and detail JSON are emitted in canonical order.

`diff` accepts two completed snapshot names, stable IDs, or `current`; failed and incomplete attempt IDs are rejected with exit code `2`. Human output starts with node/site/edge/evidence/profile/coverage/rename counts and follows with canonical change details plus primary source evidence. `--json` emits the versioned `diff` command envelope with normalized filters, a summary, and the canonical before/after records. Repeatable `--kind`, `--profile`, `--phase`, and `--status` filters use exact matching and AND semantics; a record type that does not expose a selected dimension is excluded rather than guessed through an implicit graph join.

## Impact and Git changed sets

`impact <SELECTOR>` follows incoming dependencies from the selected node and reports a deterministic dependency path, rendered condition, profile correlation, and source evidence for every result. With `--changed <GIT_REF>`, depgraph reads both committed changes from `merge-base(GIT_REF, HEAD)..HEAD` and staged, unstaged, and untracked worktree changes without taking Git locks or invoking external diff/textconv helpers. Changed and renamed paths are correlated to file and semantic node identities through canonical node properties and stored evidence. The selector is the focus: it must depend on a mapped changed node, then reverse traversal reports the focus and its dependents. Repeatable `--profile`, `--condition`, `--phase`, `--session`, and `--environment` filters are exact; runtime environment matching includes its name, runtime, and region. `--depth`, `--max-nodes`, and `--max-edges` bound traversal, and a reached safety limit is returned as `complete=false` with an explicit diagnostic rather than silently truncating results.

`impact --changed <GIT_REF>` without a selector runs in changed-set mode. Every node mapped from the changed paths becomes a depth-0 source, and a single multi-source reverse traversal over one Store read reports everything that depends on any of them. To populate `changed_paths`, a bounded reverse traversal then runs per changed path within the nodes already reached; if this attribution exceeds the service preprocessing work limit, the query fails with `ResourceExhausted` (exit code `3`) rather than returning partial attribution. JSON uses `data.mode = "changed_set"`. Each `impacts[]` entry carries the node, its `depth` (distance from the nearest changed node; changed nodes are 0), `changed_node_id`, `changed_paths` (every changed path reaching the node), and a `dependency_path` that runs from the impacted node to the changed node. Changes that map to no node are listed in `unmapped[]` with `status`, `old_path`, `new_path`, and a `reason` of `deleted` or `not_in_snapshot`. The result also includes `mappings`, `changed_nodes`, `diagnostics`, `complete`, `filters`, and `changed_set`. Filters, depth, and the same HEAD requirement apply: a scan `source_revision` that differs from HEAD exits with `2`. Running with neither a selector nor `--changed` is a usage error with exit code `2`. Like other changed-set impact, this mode bypasses the impact result cache.

## Watcher daemon

`daemon start` uses the platform-recommended recursive filesystem watcher and a configurable `[daemon].debounce_milliseconds` (default `200`). VCS metadata, dependency/build output directories, the graph store, and daemon control files are ignored; tracked generated source such as `generated`, `*.generated.*`, `*.g.rs`, and `routeTree.gen.ts` remains observable. A burst is normalized into deterministic added/modified/deleted/renamed changes. Before repository-complete planning, one existing Web source write is checked with a canonical token-and-position fingerprint that permits harmless trailing trivia while retaining graph-affecting syntax, evidence positions, directives, tags, and quoted comment module candidates. If it is unchanged, the core sends a one-node `worker-delta-request-v1` projection and atomically promotes a sparse parent-snapshot overlay containing only the updated content hash. Status records versioned base-projection, worker capability, worker analysis, store-commit, and total timings. Any semantic or evidence-position change explicitly falls back to `incremental-plan-v1`; bounded scoped plans use the complete canonical delta contract, while legacy workers, workspace replans, unsupported adapter combinations, and complete-reanalysis closures above 4,096 paths use the atomic full scan. A newer burst cancels both capability probes and active scans, then requeues their changes; failed batches retry with bounded backoff. Shutdown cancels an active scan, performs one final pending-batch flush, waits for worker process-tree cleanup, and never promotes the cancelled attempt. Status uses schema `daemon-status-v1` and exposes active, last completed, last failed, last cancelled, watcher-error, and crash-recovery state. Public CLI and MCP JSON retain release evidence through a path-free invalidation summary containing only the schema version, mode, base profile-plan digest, and affected-profile count; raw invalidation plans and internal errors remain private. `[daemon].ignored_paths` accepts normalized repository-relative path prefixes.

## Selectors

Selectors accept `id:`, `path:`, `package:`, `route:`, `symbol:`, and `type:` prefixes. `symbol:` and `type:` only match their respective node kind. `package:` matches workspace package instances and external dependency packages (by display name, `name@version`, or full `package://` locator), but not semantic `external://` boundaries. A bare or prefixed selector must resolve unambiguously; when candidates are reported, copy the complete stable ID (for example `symbol:sha256:...`) and retry as `id:<stable-id>`.

External dependency packages as `package:` targets (by display name,
`name@version`, or a full `package://` locator) are available in the `v0.6.4` release candidate but are
not part of the published `v0.6.3` release. In `v0.6.3`, `package:`
does not select external dependency packages.
