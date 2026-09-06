# ADR: Analysis units, source batches, and resumable execution

- Status: Implemented
- Date: 2026-09-06
- Related issues: #459, #462, #463, #464, #465, #466, #467

The acceptance matrix in
[resumable-analysis-validation.md](resumable-analysis-validation.md) records
the passing pinned local gate, public integration fixture, and separate
benchmark measurements. CI verification is required before merge.

## Decision

Scans discover the repository structure first and save validated work as it finishes.
Go modules and Web projects keep their compiler context while source batches bound each worker's output.
The repository root stays fixed throughout discovery, analysis, and queries.

`depgraph scan <root> --plan --json` exposes the static plan without launching workers or opening a Store.
Nested Web workspace declarations use their declaring directory as the glob and configuration base.
The nearest workspace governs membership and package-name lookup; excluded packages have independent name scopes.
Workspace membership remains in the plan graph without making every sibling's source an input to every other project.

## Worker contract

Workers advertise `analysis-source-batch-v1` to accept `depgraph-analysis-unit-v2` requests.
Requests bind a logical unit, stage, chunk ID/index/count, context fingerprint, and three path sets:

| Field | Meaning |
| --- | --- |
| `context_paths` | All source files owned by the logical module or project |
| `source_paths` | Source files whose records this request may emit |
| `auxiliary_paths` | Metadata or assembly records emitted by this request only |

The scheduler emits syntax work before semantic work.
Go workers also advertising `analysis-unit-typed-v1` receive a separate `typed` stage between them.
Each later stage waits until all preceding chunks of its own unit have been saved and ingested; other units can proceed concurrently.
Web stages use source batches; TypeScript retains the project context while AST transfer and dependency extraction select the current batch.
Go syntax parses selected files, while typed and semantic processing each retain one complete module context.
`go/packages` and SSA require a consistent universe of package objects.
[Go validation](analysis-unit-go-validation.md) records the compiler boundary and measured repeated work.

The typed stage saves declarations, type references, and relations that do not require SSA.
Its completed stream uses `syntax-complete` and the explicit `go_typed_stage_complete="true"` profile property; it never claims `semantic-complete` by itself.
The final semantic stage performs SSA and establishes full semantic coverage only when all required stages and contexts join.
If SSA stops, the completed typed graph remains available in the partial attempt and can be reused after restart.
Go compiler objects cannot be restored from graph records, so SSA reconstructs its type universe on restart even when the typed graph checkpoint is reused.
No checkpoint is available inside an unfinished `packages.Load` or SSA builder call.

Auxiliary output belongs to one syntax chunk.
Cross-unit dependency targets are allowed, but source evidence and file coverage must belong to the request.
Each child gets a private repository inventory, which the supervisor checks for modification before accepting output.
Chunk IDs are execution metadata; canonical graph identities and logical profiles remain independent of chunk size, completion order, and reuse.
Web files retain their configured base-profile identity across projects and stages, so an ordinary `path:` query selects one file.
Shared file and semantic-definition records carry the sorted union of their verified logical `profile_ids`; `profile_id` is the first member for legacy consumers.
The join requires all other fields, including source hashes, package ownership, definition identity, and source locations, to agree.
A conflicting payload aborts that unit's ingestion instead of silently replacing an earlier result.

A Go worker advertising only `analysis-unit-v1` retains the module/stage v1 request.
Rust and workers without unit support retain repository requests.
Discovery or input-proof failure also preserves this fallback and its existing diagnostics.

## Resources and progress

Progressing scans have no default aggregate deadline.
CLI, durable MCP operations, and daemon scans use the same executor.
A caller may configure an explicit total budget in `.depgraph.toml`:

```toml
[scan]
worker_timeout_seconds = 300
max_worker_memory_bytes = 2147483648
max_concurrent_units = 2
max_unit_source_files = 128
# Omission means no aggregate deadline.
# total_budget_seconds = 7200
```

The worker timeout measures inactivity during normal scans.
New completed phases and increasing work counters extend it; duplicate messages and phase starts do not.
A compiler API that cannot report intermediate progress remains subject to this budget.
Standalone worker and delta requests retain their existing timeout contract.

The supervisor samples each process tree's memory every 250 ms and terminates it on excess or accounting failure.
Linux and macOS account for process-group resident memory; Windows uses [Job Object peak committed memory](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_extended_limit_information), which Windows continuously tracks.
Sampling allows a brief overshoot between observations.
Protocol, line, and retained-stderr byte limits remain per worker.

Concurrency and buffered results share the configured admission window.
Results enter the Store in plan order, regardless of completion order.
Cancellation stops admission and reaps active process trees.
The total-budget guard also cancels during synchronous discovery.
Its supported range is 1 through 30,931,200 seconds, leaving seven days of terminal retention within the operation journal's existing maximum retention window.

Progress includes unit ID, adapter, stage, status, duration, protocol-event count, reuse, and failure reason.
An observer belongs to one scan future.
MCP projects completed work into operation progress; discovery may replace the initial 0/1 estimate once.
Daemon status exposes active analysis and retains final analysis with the attempt.

## Checkpoints and input changes

Validated streams are disposable sidecars beside the Store:

    .depgraph/analysis-checkpoints-v1/<store-name-digest>/<unit-key-digest>.json

Keys bind the request, inputs, worker artifact and arguments, runtime/toolchain, configuration, profiles, and checkout root.
V2 keys include the logical dependency closure and auxiliary inputs, including assembly and embedded assets.
Unrelated units can retain syntax and eligible typed/semantic checkpoints across scans.
Unknown dependencies conservatively include the adapter's input set.
Go typed and semantic reuse also require a scoped dependency witness for repository-local replacements, workspace members, or inventory-covered vendored files.
A checksum entry alone does not certify the bytes in an external module cache, so unproved remote dependencies disable typed/semantic reuse while retaining syntax checkpoints.

Writes use a temporary file and atomic rename.
The temporary stream remains invisible to checkpoint readers until Store ingestion accepts the complete unit; rejected units discard their staged file.
Reads check envelope, checksum, limits, expected key, and the complete protocol again.
Corrupt, mismatched, or truncated entries become cache misses; unfinished streams are never reused.
`--no-cache` disables checkpoint reads and writes.

Daemon changes against an analysis-unit snapshot use this same scheduler and valid checkpoints.
Legacy graph deltas cannot carry the immutable unit ledger and are rejected by Store before staging or publication.
The check follows sparse semantic-noop overlays to their effective parent snapshot; legacy repository snapshots retain their existing delta path.
Entry count and total size are bounded, with older entries pruned.

A shared content witness is checked before reuse, before saving new results, and before publication.
Changed input or plans prevent publication of a mixed completed snapshot.
The Store writer lock and operation lease retain scan ownership and publication authority.
Removing sidecars does not affect published snapshots.

## Partial results and compatibility

`current` still selects the latest completed snapshot.
A terminal partial result is selected explicitly with `attempt:<scan_id>`.
Its metadata identifies the attempt, input/plan identity, coverage, and incomplete work.
Active staging results are not immutable selections, and partial attempts cannot be named as completed snapshots.
Incomplete analysis blocks confirmed unused findings.

Graph exports selected with `attempt:<scan_id>` carry the same bounded partial
metadata in every format: JSON uses a `partial` object, DOT and Mermaid use a
leading comment, and GraphML uses graph-level `depgraph.partial` data. The
metadata contains the attempt status, the aggregate analysis coverage, and
ledger counts; it does not copy the unbounded per-unit ledger or store paths.
Completed export bytes and the completed-only Agent graph response contract
remain unchanged.

Store schema 19 adds analysis metadata and a unit/stage/chunk ledger.
Completed snapshot integrity covers these records.
Schema 18 snapshots retain their prior integrity contract; migration does not invent historical unit coverage.
Unknown future schemas fail closed.

Journal schema 6 preserves finite deadlines when migrating schema 5.
New scans without an explicit budget use a reserved internal deadline sentinel.
The public operation v2 projection returns null deadline and null active retention instead of that sentinel.
Terminal retention starts when the operation settles.
MCP Tasks have null TTL during these scans and finite TTL afterward.
Other operation kinds keep finite deadlines and cannot use the scan sentinel.

Worker v1 requests and existing finite operation responses remain readable.
New Store/journal versions and checkpoint identities are validated before use.
Older readers must reject newer storage versions and must not interpret missing coverage as complete.

## Rejected alternatives

Increasing one repository timeout would still discard completed work.
Treating directories as independent repositories would break workspace imports and local replacements.
Splitting Go SSA into independent package universes would change call-graph meaning.
Running package managers or project hooks during discovery would cross the static-analysis boundary.
