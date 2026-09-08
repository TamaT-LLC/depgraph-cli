# ADR: Pre-split analysis planning by dependency scope and work estimate

- Status: Implemented (plan, contract, and the shipped Go package loader)
- Date: 2026-09-07
- Issue: #465 (parent #464; consumers #463 Go bounded loader, #467 health range loading; follow-up #480 retained batch numbering; closer alignment #482)
- Contract: depgraph-analysis-split-plan-v1 (`schemas/depgraph-analysis-split-plan-v1.schema.json`)
- Request binding: the optional `split` object of a `depgraph-analysis-unit-v2` request
- Worker capabilities: analysis-loader-scope-v1, analysis-go-package-loader-v1
- Configuration: `scan.max_unit_source_bytes`, `scan.max_context_source_bytes`

[Static discovery](adr-resumable-analysis-units.md) decides which repository
files belong to which logical unit. [Unit execution](adr-analysis-unit-execution.md)
decides how a worker receives a unit, saves it, and how partial results are
selected. This record fills the step between them: how each logical unit is
turned into execution units before any worker starts, and how that decision
is explained, reproduced, conveyed to the worker, and revised.
[resumable-analysis-validation.md](resumable-analysis-validation.md) lists the
fixture and tests that verify it.

## Context

The scheduler already partitioned source batches, but the partition was an
implicit function of one file-count budget spread across `analysis_schedule.rs`
and the workers. It could not say, for one piece of work, which files the
worker's compiler would actually read, which inputs were needed only for
reference, how much work that was expected to be, or why the unit had or had
not been split. A Web semantic batch that only partitions output looked the
same as a Go syntax batch that really bounds the parser's input. A large single
Go package could not be expressed as anything other than one whole-module
request, so a timeout in it discarded all of its work and offered no smaller
retry. Issue #463 needs a request-level contract for a bounded
`packages.Load` scope, and issue #467 needs to know which execution units
cover a query range and whether their saved results are still valid after the
plan changes.

## Decision

Adopt depgraph-analysis-split-plan-v1 as the pre-split planning contract. The
core (`crates/depgraph-core/src/analysis_split.rs`) exposes:

    plan_analysis_split(plan, input) -> AnalysisSplitPlan
    resplit_execution_unit(plan, current, input, execution_unit_id, trigger) -> AnalysisResplitPlan
    plan_default_split(root, config, plan) -> AnalysisSplitPlan
    measure_source_sizes(root, plan) -> sizes
    static_context_paths(plan, unit) -> paths
    AnalysisAdapterBoundary::{go_module_loader, go_package_loader, web_project_loader, for_capabilities}
    AnalysisExecutionUnit::binding(split_plan_id) -> AnalysisSplitBinding

`AnalysisSplitInput` carries the budget copied from `ScanConfig`
(`AnalysisSplitBudget`), the splittable boundary each negotiated worker can
honour (`AnalysisAdapterBoundary`), owned source sizes by repository-relative
path, the worker context closure of every unit, and the ordered refinement
history. The planner is a pure function of these inputs and the discovery
plan. It never reads file contents, never runs project code, and never probes
a worker; the scheduler supplies the negotiated boundaries and
`depgraph scan --split-plan [--json]` uses the shipped defaults.

The scheduler (`prepare_analysis_schedule`) now derives every source-batch
work item from the split plan instead of chunking by itself, and exposes the
plan as `AnalysisSchedule::split_plan`. For a worker that did not negotiate
loader scope, the request JSON, chunk identity, and path sets are unchanged
from the previous chunking, so existing checkpoints and worker validation keep
working; the boundary's `loader_scope` flag (below) is what keeps that true.

### Roots

Three roots stay distinct throughout planning and execution:

| Root | Meaning | Where it appears |
| --- | --- | --- |
| Repository root | The canonical scan directory; the confinement boundary and the base for every repository-relative path | Passed to the worker separately (`--root`); never serialized into an ID |
| Unit root | The repository-relative directory of a logical unit's manifest (or `.` for a repository fallback); an ownership and scheduling hint | `ownership.unit_root`, request `unit_root` |
| Configuration base | The repository root's `.depgraph.toml`; nested Web workspace declarations use their declaring directory as the glob and configuration base | `AnalysisSplitBudget::from_config`, discovery configuration fingerprints |

Execution unit IDs derive from the contract version, logical unit ID, stage,
ownership paths, loader kind, loader paths, and reference depth. Absolute
checkout paths, sizes, timestamps, and directory order are excluded, so the
same checkout at another path produces the same IDs.

### What every execution unit explains

An `AnalysisExecutionUnit` is one worker request. It carries:

- `ownership` (`AnalysisOwnershipScope`): the files whose results the request
  may emit, their package roots, and the unit's context group.
- `loader` (`AnalysisLoaderScope`): what the worker's compiler or loader
  actually reads. `kind` is `files`, `package`, `module`, `project`, or
  `repository`; `paths` and `package_roots` are loaded completely and always
  cover the ownership paths; `reference_paths` are read only at
  `reference_depth` (`paths_only`, `declarations`, or `bodies`) and are
  disjoint from `paths`; `reference_unit_ids` names the other logical units in
  the dependency closure; `input_split` is true exactly when `paths` is a
  strict subset of the unit's full source context.
- `estimate` (`AnalysisWorkEstimate`): stage, owned/loader/reference file
  counts and source bytes, dependency closure size, a relative ordering
  `weight`, and `over_budget` when the estimate exceeds a budget the adapter
  boundary cannot split away. The weight is a heuristic for ordering and
  admission, not a time or memory prediction; the plan says so in
  `limitations` (`estimates_are_heuristic`).
- `budget` (`AnalysisExecutionBudget`): the individual worker timeout, memory,
  protocol and stderr limits, and the file, byte, and context-byte budgets the
  unit was planned against.
- `split_kind` and `split_reasons`: `whole`, `output_batch`, `input_batch`, or
  `staged_bodies`, with reasons `unit_fits_budget`, `source_file_budget`,
  `source_byte_budget`, `context_byte_budget`,
  `adapter_boundary_unsplittable`, `cycle_group_retained`,
  `staged_after_declarations`, and `refined`.
- `prerequisite_ids`: the execution units of the preceding stage of the same
  logical unit that must be saved and ingested first.

### Budgets and boundaries decide scope and parallelism first

`AnalysisSplitBudget` copies `scan.max_concurrent_units`,
`scan.max_unit_source_files`, the new `scan.max_unit_source_bytes` (default
8 MiB of owned source per execution unit) and `scan.max_context_source_bytes`
(default 64 MiB per loader context), the worker timeout, memory limit, protocol
and stderr limits, and the optional total budget. `max_context_source_bytes`
must be at least `max_unit_source_bytes`.

An `AnalysisAdapterBoundary` lists, per stage, the loader kind, reference
depth, split granularity (`file` or `package`), and whether the worker can
split output, split input, or stage bodies after a declaration stage. It also
records in `loader_scope` whether the worker advertised
`analysis-loader-scope-v1`. The shipped boundaries are:

| Boundary | Selected when | Syntax | Typed | Semantic |
| --- | --- | --- | --- | --- |
| `go-module-loader(-typed)` | Go worker with `analysis-source-batch-v1` (and `analysis-unit-typed-v1`); also the fallback for a worker advertising `analysis-go-package-loader-v1` without `analysis-loader-scope-v1` | files, input split | module, unsplittable | module, unsplittable |
| `go-package-loader` | Go worker advertising both `analysis-loader-scope-v1` and `analysis-go-package-loader-v1` (#463 target); `loader_scope` is always true | files, input split | package, declaration references, input split | package, declaration references, staged bodies per file |
| `web-project-loader` | Web worker with `analysis-source-batch-v1` | files, input split | – | project, output split only |

The bounded package scope reaches a worker only through the `split` binding,
which is sent after `analysis-loader-scope-v1` alone. A worker that advertised
the package loader without it would be planned as bounded but execute whole
modules, so `for_capabilities` keeps the module loader for it, and the planner
rejects any boundary that bounds a typed or semantic loader below the whole
context while `loader_scope` is false.

For each unit and stage the planner partitions the ownership scope by the
stage's granularity until each batch fits the file and byte budgets, then
derives the loader scope from the boundary: a whole-context loader reads the
unit's full context closure, a bounded loader reads the batch and references
the rest. Partitioning happens only where the boundary allows a split; a
stage that cannot be split stays one execution unit and reports
`adapter_boundary_unsplittable` together with the budget it exceeds.

The byte budget partitions only a boundary whose `loader_scope` is true. A
worker that did not negotiate loader scope is partitioned by file count
alone, exactly as the scheduler chunked before this record, so its requests,
chunk identities, and checkpoints are unchanged. Its byte budget still enters
the estimate: an owned batch above `max_unit_source_bytes` is reported
`over_budget` with `source_byte_budget` and `adapter_boundary_unsplittable`,
because that boundary offers no byte-bounded partition, and a refinement can
still divide it. The shipped Go and Web workers have not negotiated loader
scope, so `current_defaults()` and `scan --split-plan` describe them this way.

The parallelism decision (`AnalysisParallelism`) is made in the same pass.
Execution units are laid out in waves of at most `max_concurrent_units`,
each unit no earlier than the wave after its prerequisites. The plan reports
the effective concurrency the plan can actually use, the admitted worker
memory bound (`max_worker_memory_bytes × effective_concurrency`, zero for a
plan without execution units), and the estimated weight per wave. The
scheduler admits work in the same adapter-major, stage-major order the plan
was built in.

### Dependencies, cycles, shared inputs, and a staged large package

The loader scope of a whole-context unit includes every source of the
transitive resolved input dependency closure and of the executable units that
own those dependency roots, so a Go module that imports a workspace sibling
loads that sibling's sources and a Web application loads its workspace
package. A bounded unit keeps the same closure as `reference_paths` and
`reference_unit_ids`; out-of-unit references are never dropped from the plan,
only moved from loaded to referenced. Shared inputs appear in the loader or
reference scope of every unit that needs them and in the ownership scope of
exactly one.

`context_groups` computes strongly connected components over resolved input
dependency edges only. The discovery plan's dependency groups also follow
workspace-membership and context edges, which make every workspace member
topologically cyclic; the analysis context has to stay together only for
genuine input cycles. A cyclic group is recorded on every member's ownership
(`context_group_id`, `context_group_unit_ids`, `cyclic_group`), and any stage
that reads declarations or bodies of its references reports
`cycle_group_retained`. The planner never places members of a cyclic group into
separate loader contexts.

A large single package cannot be split at the package granularity. With the
`go-package-loader` boundary it is expressed as a staged split: one typed
execution unit loads the package with declaration-level references and is
reported over budget when it must be, then the semantic stage owns file
batches of the package (`staged_bodies`, reason `staged_after_declarations`)
whose loader reads the batch's bodies and only the declarations of the rest,
with the typed unit as prerequisite. The public fixture's `services/big`
module models this through synthetic sizes.

### Re-splitting after the estimate is exceeded

`resplit_execution_unit` records an `AnalysisSplitRefinement`
(`execution_unit_id`, trigger `worker_timeout`, `worker_memory`,
`output_limit`, or `estimate_exceeded`) and rebuilds the plan with the
refinement appended. A refined batch is divided at its byte midpoint along the
stage's granularity; the two halves report `refined`. Refinements are part of
the split plan identity, so the same discovery plan, budget, boundaries, and
refinement history reproduce the same plan.

The relationship to existing state is explicit in `AnalysisResplitPlan`:

- `plan_id` and every logical unit `input_fingerprint` are unchanged. A
  re-split is not a discovery change and never invalidates the repository
  input proof.
- `split_plan_id` changes; `previous_split_plan_id` names the plan it replaces.
- `saved_results` classifies every execution unit of both plans as
  `retained` (same ID, inputs, checkpoint key, and published
  `batch_index`/`batch_count`; saved results stay valid),
  `superseded` (the refined unit; its saved results are discarded), or
  `replacement` (new units without saved results). Only the refined unit is
  superseded. A sibling that is already a batch of the same stage keeps the
  chunk numbering its profile and ledger row already carry; replacements
  take a new index that does not collide with retained siblings, with a
  `batch_count` large enough for the worker's `chunk_index < chunk_count`
  check. Coverage still requires a uniform `0..count` set when every row of
  a stage shares one `chunk_count`; after a re-split the retained sibling
  keeps its published count and completeness is the source-path partition.
  The runtime applies a `Split` only when that numbering is unchanged
  for every retained unit (otherwise recovery after `memory-limit` would be
  deferred). Later stages of the same logical unit keep their identity and
  saved results because chunking does not enter their key; only their
  `prerequisite_ids` now name the replacements.
- When the target cannot be split (`single_granule`, `adapter_boundary`, or
  `unknown_execution_unit`) the outcome is `unsplittable` and the execution
  units are unchanged, so every result is `retained`. The refinement still
  enters the returned plan's history: `refinements` carries it, it is listed
  in `unsplittable_refinements` with the `refinement_unsplittable` limitation,
  and `split_plan_id` changes accordingly. A stored plan therefore explains its
  own history, and an executor does not retry the same refinement blindly.
- Every refinement of a plan's history is either applied or reported. One that
  names no execution unit of the plan built from the current input, for
  example a target already replaced by an earlier refinement or a history
  carried into a plan with different boundaries, is reported as
  `unknown_execution_unit` rather than dropped. `resplit_execution_unit`
  reports an unknown target the same way; only inputs that do not reproduce
  the current plan (a different discovery plan, budget, boundaries, sizes, or
  contexts) are rejected as errors, because the saved-result dispositions are
  only meaningful against the plan they were computed from.

Refinements live in the plan, not in `.depgraph.toml`. Changing a budget in
the configuration changes the configuration fingerprint and therefore the
execution digest of every checkpoint, as before; a re-split keeps the
configuration and so keeps the checkpoints of unaffected units. Executing
re-splits automatically inside the scheduler is not part of this record; the
contract fixes what such an executor may and may not reuse.

### Conveying the plan to the worker

A worker that advertises `analysis-loader-scope-v1` receives the
`AnalysisSplitBinding` as the `split` object of its v2 request: the contract
version, `split_plan_id`, `execution_unit_id`, `split_kind`, and an
`AnalysisLoaderBinding` (`kind`, `paths`, `package_roots`, `reference_depth`,
`reference_paths`, `input_split`). Estimates, budgets, and unit IDs stay in the
core. A worker that did not advertise the capability receives the unchanged
request; both Go and Web workers reject unknown fields, so the binding is only
ever sent after negotiation.

The binding makes output-only splitting distinguishable from input splitting:
an `output_batch` has `input_split = false` and a loader that covers the whole
context, an `input_batch` or `staged_bodies` unit has `input_split = true` and
a non-empty `reference_paths`. A worker honouring the binding loads at least
`loader.paths`, never fewer, and reports `analysis_loader_scope = applied`
when it loaded exactly that scope or `widened` when it had to load more, along
with `analysis_split_plan_id`, `analysis_execution_unit_id`,
`analysis_split_kind`, `analysis_loader_kind`, and
`analysis_loader_input_split` profile properties.

The Go worker validates and echoes the binding now (`analysis_split.go`):
`loader.paths` must cover `source_paths`, reference paths must be disjoint
from loaded paths, `input_split` must agree with the presence of reference
paths, and `whole` requires a single chunk. A syntax request must bind a
`files` loader whose `paths` equal `source_paths`: the parser reads exactly
the owned files, so a wider loader scope could only be honoured by reading
less than requested, and the worker rejects it instead of reporting `applied`
for a scope it never read. The planner never produces such a binding, because
a syntax boundary reads paths only and its loader scope is its ownership. The
shipped Go worker advertises `analysis-loader-scope-v1` together with
`analysis-go-package-loader-v1` and honours the binding for typed and
semantic stages: `analysis_loader_scope=applied`, targets type-checked from
source, dependencies from export data, CHA only over the declared program
scope. A worker that does not advertise those capabilities still loads the
complete module and reports `widened` for a `package` request. The Web
worker is unchanged.

### Re-analysis triggers

The split plan does not introduce new invalidation inputs. A logical unit is
re-analysed when its discovery input fingerprint changes: source content,
manifest, repository configuration or lockfile, selected profile, analyzer
identity, or a resolved dependency's fingerprint, and conservatively for every
same-adapter unit when a dependency is unknown. A budget change in
`.depgraph.toml` changes the configuration fingerprint and the execution
digest, so all Go/Web checkpoints are rerun once; the discovery plan ID and
unit input fingerprints are not affected by budgets. A worker artifact or
toolchain change changes the execution digest. A re-split changes only the
split plan ID and the refined execution units.

### Unit states

Execution units keep the unit ledger states of the execution ADR: `queued`,
`running`, `completed`, `failed`, `cancelled`, and `unanalysed`, with `reused`
marking a checkpoint hit. The split plan adds two plan-level dispositions that
are not ledger states: `superseded` and `replacement` in a re-split result.
An `over_budget` execution unit is still planned and executed; the flag tells
the executor that the unit may exhaust its individual budget and that its
adapter boundary offers no smaller retry.

### Per-unit budgets

Every execution unit keeps its individual `worker_timeout_seconds` inactivity
deadline, progress extension, process-group `max_worker_memory_bytes`,
`max_protocol_bytes`, and `max_stderr_bytes`, regardless of its estimate. The
optional `total_budget_seconds` remains the only aggregate deadline. The
parallelism decision bounds concurrently admitted units and therefore the
admitted worker memory. Estimates influence order and admission only; they
never relax a limit.

### Partial results and snapshot publication

Partial-result selection with `attempt:<scan_id>` and completed-snapshot
publication follow the execution ADR. The split plan constrains them in two
ways: a completed snapshot requires every execution unit of the current split
plan to be ingested, and an executor that adopts a re-split must treat
`superseded` results as absent before publication. Health and queries over a
partial attempt continue to keep confirmed unused findings blocked while any
execution unit of a profile is incomplete. Issue #467 can map a query range to
execution units through `ownership.source_paths` and follow `reference_paths`
to the context it depends on.

### Compatibility

- Configuration: `scan.max_unit_source_bytes` and
  `scan.max_context_source_bytes` are additive with defaults; existing files
  load unchanged. Because the configuration fingerprint covers the whole
  `ScanConfig`, upgrading changes the execution digest once and Go/Web
  checkpoints are rerun on the first scan after the upgrade.
- Worker protocol: the request stays `depgraph-analysis-unit-v2`; `split` is
  additive and negotiated. Profile properties are additive. Chunk IDs, path
  sets, and field order are unchanged for existing workers: the byte budget
  partitions only a worker that advertised `analysis-loader-scope-v1`, so a
  unit above `scan.max_unit_source_bytes` keeps the file-count chunks it had.
- Store and operation journal: no schema change. The unit ledger keeps
  `chunk_id`, `chunk_index`, and `chunk_count`; execution unit IDs are derived
  and not persisted by this record. Snapshot identity, checkpoint keys, and
  journal deadlines are unchanged.
- Discovery contract: depgraph-analysis-plan-v1 is unchanged; the split plan
  references it by `plan_id` and `plan_input_digest`.
- CLI: `depgraph scan --split-plan [--json]` is a new read-only flag;
  `--plan --json` output is unchanged.

### Verification

The public synthetic fixture `fixtures/analysis-split-plan-v1` contains a Go
workspace (`services/api` importing `services/shared`, a two-module cycle
`services/cycle-a`/`services/cycle-b`, a module outside the workspace, and
`services/big`, made large through `sizes.json`) and a nested pnpm workspace
whose application imports a workspace package. `expected/split-plans.json` is
the projection of three scenarios (`current-workers-default-budget`,
`current-workers-two-file-budget`, `go-package-loader-default-budget`); set
`DEPGRAPH_UPDATE_FIXTURES=1` to regenerate it after an intentional change.

`crates/depgraph-core/tests/analysis_split_contract.rs` verifies, against the
fixture: the projection golden; the same input produces the same plan across
checkouts and runs; a budget change changes the plan but not the discovery
plan ID or any unit input fingerprint; out-of-unit references stay in the
loader or reference scope; the large single package is a staged split; the
cycle group is kept in one context; a re-split supersedes only the refined
unit and keeps the other saved results; loader scope and ownership scope are
distinguishable; parallelism is decided before execution and respects
prerequisites; measured sizes match fixture bytes and drive byte splits; the
bounded package boundary requires the loader-scope capability and a bounded
boundary without it is rejected; a worker without loader scope keeps the
file-count partition for the 16 MiB synthetic package while the negotiated
worker is byte-split; a plan without execution units admits no worker memory;
and the split plan, re-split plan, and worker binding satisfy the closed
schema. `analysis_schedule.rs` verifies, with an owned source above the 8 MiB
budget, that requests for a worker without loader scope are byte-identical to
the previous chunking and that the binding is attached, and the byte budget
applied, only after negotiation. The Go worker tests in
`analysis_split_test.go` cover strict decoding, rejection of an output-only
split posing as an input split, rejection of a syntax loader scope wider than
`source_paths`, and unchanged results and identities when the binding is
echoed. `crates/depgraph-cli/tests/cli.rs` verifies `scan --split-plan`
without workers or a Store.

## Limitations

Estimates are byte and file counts weighted by stage and reference depth;
they are not measurements of compiler work. Missing sizes count as zero and are
reported as `source_sizes_incomplete`. A whole-context loader that must be
retained is reported as `whole_context_loader_retained`. The planner cannot
know that a worker widened its loader scope until the worker reports it. The
re-split contract fixes identities and dispositions; automatic re-split
execution, bounded Go loading, and health range loading are the consumers'
work. Parent #464 stays open until the original trial target completes a
fresh scan, ordinary health, and same-input resume on unchanged per-unit
limits; public synthetic fixtures in
[resumable-analysis-validation.md](resumable-analysis-validation.md) are
necessary and not sufficient.

## Rejected alternatives

Deriving a bounded loader scope from directory structure alone was rejected
because Go and TypeScript resolution crosses directories through workspaces,
replacements, and path mappings; the plan follows resolved dependency edges
instead. Encoding the budget into the discovery plan was rejected because a
budget change would then change the plan ID and every unit input fingerprint,
discarding results that are still valid. Sending the whole execution unit to
the worker was rejected because estimates and budgets are scheduler state; the
worker only needs the loader target and an identity to echo. Letting the
worker silently load less than the requested scope was rejected because
ownership results would then be computed against an incomplete context.
