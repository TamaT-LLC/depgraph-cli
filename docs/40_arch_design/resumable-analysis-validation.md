# Resumable analysis integration validation

`cargo xtask resumable-analysis-e2e` builds the CLI and the real Go and Web
workers, then runs a generated public repository through the shared scheduler
and Store. CI's existing Web job runs this command on Linux after the Web
worker gate, preserving the eight-job identity required by the release evidence
verifier; it moved there from the Go job because `go test -race` already fills
that job's wall clock. The fixture contains no source or configuration copied
from a private repository.

The Go application uses a local replacement module and has a separate,
unrelated module. A nested pnpm workspace uses an inline `packages` list with a
trailing comment and contains an application and a shared package, with a
workspace import, path mapping, a type reference, a re-export,
and a source cycle. Both Web projects call the TypeScript standard library so
the public graph also exercises one shared external sentinel across units. The
test installs no fixture dependencies and executes no fixture code. Its Go
subprocesses use offline module resolution. It checks that the persisted
`package_dependency` site resolves to the internal shared package, independently
of the TypeScript path mapping. The regression failed with `unresolved` before
Core and the Web worker were aligned on the static pnpm list syntax.

The test compares a scan with 128 files per batch and one worker against a
scan with one file per batch and two workers. It repeats the second scan in a
new CLI process and checks checkpoint reuse. Comparison includes the public
JSON export and the persisted profile, node, site, edge, evidence, diagnostic,
file coverage, profile coverage, and aggregate coverage records. Only attempt
and scheduling metadata are outside this graph comparison; graph IDs,
conditions, source locations, and profile payloads remain intact.

A failed TypeScript project-model chunk publishes bounded fallback metadata:
an unknown package manager, an empty lockfile, and an empty feature list.
Canonical profile joining records which metadata fields were observed. It
treats unobserved fallback values as unknown, carries a known value from a
successful sibling, and rejects disagreements between known values. A real
zero count or empty configuration value remains known after a failed sibling
joins it. Permutation tests verify this distinction across three or more
chunks, so failed chunks cannot erase previously established context.

The interruption case pauses the real Go worker before SSA, sends SIGINT to
the CLI, and reads the terminal partial attempt with an explicit `attempt:`
selector. Validated syntax and typed records must remain readable. A new CLI
process resumes the same Store, reuses its completed checkpoints, and produces
the same complete graph as the uninterrupted run.

The Web interruption case pauses the real semantic worker after its syntax
batch has completed, sends SIGINT, and reads the partial export and health
findings from the attempt. The wrapper is outside the fixture and keeps the
same path and bytes for the resumed process; an external sentinel makes only
the first semantic request stop. The resumed CLI must reuse the Web syntax
checkpoint, rerun the incomplete semantic stage, and reproduce the complete
graph. This case begins with an existing completed snapshot and confirms that
cancellation leaves both its identity and the default graph unchanged. Explicit
partial `deps`, `dependents`, `why`, and `impact` queries are checked against the
partial attempt's own stored edge, profile, condition, and evidence records.
Health findings for the partial attempt must keep `unused-file`
confidence below `confirmed`.

Go stage profiles can have the same environment and features while carrying
different `contains` evidence. Health shares the condition axes, represents
each file with a common no-edge state and only the observed stage exceptions,
and indexes package usage by condition group before projecting it onto files.
Original stage IDs remain in blockers, and every stage contributes to the
group's completeness. The `health::unused::tests::issue_467` regressions cover
inactive-stage imports, missing `contains` evidence, missing profile records,
ambiguous package candidates, and incomplete-stage confidence.
`issue_467_many_stage_imports_share_package_projection_work` uses 64 equivalent
profiles and 128 production files. It completes within 4,000 work steps; the
former file/profile traversal alone required 8,192. The configured health
limits are unchanged, and required blocker generation remains budgeted and
cancellable.

Health also builds applicable profile membership, missing-profile metadata, and
completeness once for each language family needed by the snapshot. It preserves
explicit profile additions and cross-language fixture profiles, and checks usage
against the profiles that actually supplied an edge. The public
`issue_467_shared_applicable_profile_set_bounds_many_web_subjects` fixture uses
48 Web profiles plus one fixture profile and 120 file/symbol/type subjects. It
finishes within 4,000 work steps and preserves the used subject and missing-profile
semantics. This removes repeated profile work without merging distinct Web
profiles. Health requests still have an aggregate work budget; a sufficiently
large graph can reach that limit even after these repeated evaluations are shared.

The Web input identity cases then change `frontend/apps/web/tsconfig.json`
and verify that the Web application unit is rerun while unrelated workspace
units remain reusable. The repository-wide Go unit is also rerun because its
input scope includes ancestor configuration; the independent Go modules keep
their checkpoints. A fresh scan under the changed configuration must have the
same graph. After restoring the configuration, a byte-distinct Web worker
wrapper that delegates to the real artifact must rerun Web units while Go
units remain reusable, and the resulting graph must still match the baseline.

Go/Web checkpoint admission uses `execution_digest` and `validate_work_inputs`
in `analysis_schedule.rs`. The digest binds the selected profile plan,
configuration, worker artifact, and that worker's toolchain identity.
`analysis_unit_execution_digest_rejects_profile_config_artifact_and_toolchain_changes_for_go_and_web`
checks both adapters against an accepted baseline, then changes the profile
plan, configuration, artifact bytes, and toolchain identity independently.
The toolchain case substitutes a different fingerprint in the shared digest
and admission path; the other cases use the actual input validation entry point.
`survives_reopen_and_rejects_changed_inputs_and_tampering` checks the generic
checkpoint's persisted key and payload validation. The adjacent scan-cache
identity tests cover profile selection and worker identity separately; they
are not Go/Web runtime checkpoint E2E tests. The CLI fixture exercises source,
configuration, dependency, and worker-artifact replacement; it does not
install a second compiler or mutate the host toolchain.

Selective invalidation is checked against a fresh Store after every kind of
dependency change. Editing the unrelated Go module must preserve the other
Go checkpoints. Editing the replacement dependency must rerun that module and
its importer. Editing the Web shared package must rerun its importing project
while preserving valid Go results. `deps`, `dependents`, `why`, and `impact`
must all follow the workspace dependency across project boundaries, with each
returned edge, condition, profile, and provenance row compared to the
persisted graph.

Set `DEPGRAPH_RESUMABLE_REPORT` to a file path to retain the compact timing and
reuse report. `DEPGRAPH_RESUMABLE_KEEP_FIXTURE=1` retains the temporary fixture
for debugging. The optional `DEPGRAPH_RESUMABLE_GO_ONLY=1` isolates the Go
boundary; CI runs both adapters and uploads the report as the
`resumable-analysis-report` artifact.

## Ranged health collection

`cargo xtask health-range-e2e` is the evidence gate for the health side of
#467: snapshot-scoped health no longer loads the whole `GraphSnapshot` for a
plain input but plans bounded store ranges, analyzes each range under the
unchanged per-range budget, and reuses per-range checkpoints. The same Web CI
job runs it after the resumable fixture and uploads the report as the
`health-range-report` artifact, keeping the eight-job identity. The xtask
writes the report before it raises the verdict on every path — fixture
generation failure, a runner that exited without its own report, a CLI
failure, or a failed comparison — with `gate.passed`, `gate.failure`, the
`generate` and `runner_step` exit codes and read errors, the runner report
when it exists, and the CLI envelope; the upload step runs whenever the gate
step ran, so a failure leaves its evidence in the artifact.

The fixture is public and synthetic. `crates/depgraph-core/tests/support/health_range_fixture.rs`
generates a Go-shaped worker protocol stream (`go` adapter, `depgraph-protocol`
v1 events) for a configurable shape and ingests it through the public
`Store::start_scan_with_revision` / `ingest_events` / `finish_scan` API, so the
store contains the same rows a real scan would write. Node IDs sort by package,
file, and symbol; the `caller_after_callee` option places every caller in a
later package than its callee, so the only usage of a subject always sits in a
later range. Other options add a mutual import cycle, a second module owning
the same package path (a `candidates` site), a heuristic dynamic import site,
an unanalysed analysis unit in the coverage ledger, and a hub symbol called
from every other symbol. Fixture generation streams events in 4,096-event
chunks; it never holds the stream in memory.

The over-limit shape (64 packages × 8 files × 8 symbols, 24 equivalent Go
stage profiles, every symbol called from the next package) produced 333,554
events, 219,456 edges, 108,864 sites, and a 655 MiB store. Measured in this
checkout on 2026-09-07 with a debug build:

| Path | Outcome | Work steps | Peak RSS |
| --- | --- | ---: | ---: |
| Whole snapshot, unchanged 1,000,000 budget | `resource_exhausted` | > 1,000,000 | 1,739,456 KiB after load and control |
| Whole snapshot, unbounded control | completed, 72 unused findings | 1,861,274 | (same process) |
| Ranged service path, production limits | completed, 72 identical findings, `partial_ranges: false` | planner 122,246; context 38,190; 4 ranges totalling 1,349,052 with a maximum of 433,340; dependency load 333,016; dependency matching 764,315 | 487,188 KiB |
| Ranged, second request in the same process | 4 of 4 ranges reused from checkpoints | 0 range steps | 494,080 KiB |
| `depgraph health --json` on the same store | `execution.mode = ranged`, 4 of 4 ranges reused, counts equal | — | 510,040 KiB |

Fixture generation ran in a separate process (140 seconds, 4,983,400 KiB peak
because scan promotion still validates the canonical snapshot in memory), so
the ranged measurements exclude it. The whole-snapshot load alone took 18
seconds. Elapsed times and RSS are observations of this development build, not
product limits; the xtask asserts the contract facts only: the whole-snapshot
path exhausts the single budget, every range completes within the unchanged
per-range limit, the unused findings are identical, the second request reuses
every checkpoint, and the CLI envelope reports the same ranged execution.

`crates/depgraph-core/tests/health_range.rs` covers the remaining acceptance
items on smaller shapes with the same generator: the planner reads aggregates
only and is deterministic; the planner, global context, and range loaders each
charge their own budget and fail closed at `MAX_HEALTH_PLANNER_ROWS` /
`MAX_HEALTH_RANGES`; a symbol used only from a later range is not reported in
either sort order; ranged findings equal whole-snapshot findings on every public
shape (cycle, same-path modules, dynamic import, incomplete unit, later-range
callers); incomplete analysis units keep every ranged finding unconfirmed;
range-order permutations, and interruption after each range followed by resume,
produce byte-identical findings; foreign or stale checkpoints are misses and an
unwritable checkpoint directory degrades to no checkpoints; an overrunning
range is re-split and a hub subject that cannot fit fails closed unless the
partial view is requested; the partial view is opt-in and never shares a digest
with a complete collection; plan estimates bound the measured range work; and
the diagnostics serialize with a stable shape. `crates/depgraph-mcp/tests/process.rs`
checks that `health_summary_get` / `health_findings_list` report the same
`execution` accounting as the CLI, accept `allow_partial_ranges`, and reject a
non-boolean value. `crates/depgraph-cli/tests/cli.rs`
(`issue_467_health_reports_ranged_execution_for_plain_and_whole_snapshot_for_layered`)
checks that a plain snapshot is collected in ranges with one `scan` layer while
a runtime-session child reports `mode: whole_snapshot`, the `runtime_sessions`
and `scan` layers, and zero ranges.

The item of #467 that refers to the original private test repository cannot be
verified from this public checkout; the maintainer must run
`cargo run -p depgraph-core --example health_range_e2e -- --store <store> --root <repo> --report <file>`
against that store. The report of a `--store` run contains counts, work,
timings, and digests only.

## Epic #464 pre-split integration

Child issues #465 (planning contract, PR #472 / #474), #463 (Go package
loader, PR #477), and #467 (ranged health, PR #475) are merged on `main`.
Closing the parent requires those children **and** the 2026-09-07 reopen
items below. The #470 foundation row in the matrix still holds; this
section is the remaining pre-split contract.

| Reopen item | Public evidence | Result |
| --- | --- | --- |
| Same input and budget plan the same execution units before heavy analysis | `same_input_produces_the_same_split_plan_across_checkouts_and_runs`, `parallelism_is_decided_before_execution_and_respects_prerequisites`, `cargo test -p depgraph-cli --test cli scan_split_plan_explains_execution_units_without_starting_workers_or_writing_a_store` | Pass. `depgraph scan --split-plan` writes no store and starts no worker. |
| Splits for many-package repositories and large single packages reduce loaded input and simultaneous retention | `cargo xtask go-loader-scope-e2e` at the unchanged 192 MiB per-unit limit (`scripts/go-loader-scope-e2e.mjs`) | Pass on `564c064` (this checkout, 2026-09-07). Fan-out (64×8): whole-module peak 574.7 MiB, control `partial` at 192 MiB; package batches `completed` at 92.3 MiB, resume 27/27 reused. 1,024-file package: whole-module peak 604.1 MiB, control `partial` at 192 MiB; `staged_bodies` `completed` at 86.7 MiB (74 typed + 74 semantic), resume 222/222 reused. Production `max_worker_memory_bytes` stays 2 GiB. |
| Health store load and preprocess split so repo-wide cumulative volume alone cannot fail the request | `cargo xtask health-range-e2e`; `whole_graph_over_the_budget_completes_in_ranges_under_the_same_budget` | Pass. Whole-snapshot control is `resource_exhausted` at the unchanged 1,000,000 budget; ranged path completes 4 ranges (max 433,340 steps) with 72 identical findings. |
| Out-of-unit refs, cycles, and coverage preserved; graph / evidence / findings match across split and resume | `out_of_unit_references_are_retained_in_loader_and_reference_scope`, `cycle_group_is_kept_in_one_analysis_context`; Go e2e canonical-graph equality vs the module-loader control; `ranged_findings_equal_whole_snapshot_findings_on_every_public_shape`, `range_order_permutations_produce_identical_findings`, `interrupt_after_each_range_then_resume_matches_the_uninterrupted_run`; `cargo xtask resumable-analysis-e2e` | Pass. Split vs resume of the same loader mode keeps nodes, sites, exact edges, evidence, and coverage. Package-mode vs the module-loader control matches those payloads too; CHA `may_call` is the one declared exception (a subset under `package-with-declaration-deps`). |
| Memory-limit re-split of one pre-split batch keeps retained siblings and applies replacements without raising limits | `resplit_of_a_pre_split_batch_keeps_retained_chunk_numbering`, `chained_resplit_of_a_pre_split_batch_keeps_successful_siblings`, `resplit_of_pre_split_typed_batches_keeps_retained_work_item_numbering`, `v2_typed_rows_may_mix_chunk_counts_after_a_resplit`, `resplit_of_one_pre_split_batch_keeps_retained_chunk_and_coverage_joins` | Pass. A 3-file public package pre-split into 2 typed batches keeps the sibling `batch_index`/`batch_count` so scan recovery is `applied`, not `deferred`. Replacements keep the same per-unit memory budget and are not treated as saved successes. A second re-split of a still-splittable replacement leaves the original sibling retained. Replaying the recorded refinement history reproduces the plan. Store coverage requires every unique slot in `0..max(chunk_count)` and the complete owned-source partition, including mixed retained+replacement generations. |
| A public synthetic fixture that used to hit the limit now completes without raising per-unit limits | Go e2e control `partial` vs package path `completed` at 192 MiB; health-range whole-snapshot `"resource_exhausted"` vs ranged complete at 1,000,000 | Pass. Do not close on scan JSON `status: "partial"` or health-range e2e `"resource_exhausted"` (from internal `HealthAnalysisError::ResourceExhausted`). Public JSON success is `status: "completed"` with `partial_ranges: false`. |
| Original private trial target: scan and health complete | Requires a run by a maintainer with access to the original target; public fixtures provide separate evidence. See the required verification below. | Required before closing #464; tracked in #482. |

**Large single package vs `staged_bodies`.** Semantic work is still
file-batch `staged_bodies`, not package-granular SSA: `ssautil.Packages` has
no per-function build, and CHA needs the package's SSA. Each staged batch
still sees every owned declaration (`go_loader_target_files` equals the
package file count) and type-checks only a subset of bodies, so compiler
context is kept while simultaneous retention shrinks. The 1,024-file fixture
completing at the unchanged 192 MiB limit with that split is the epic's
"huge single project" evidence; adding more packages is not enough on its
own.

**Declared limits that this epic does not over-claim.** Absence of
`go_call_graph_program_scope` means whole-program. `analysis_loader_mode`
and `go_call_graph_program_scope` are merge identity keys, not coverage
`profile_axes`. Package-mode CHA is not exact whole-program RTA.

**Required maintainer verification of the original trial target**.
This is a prerequisite for closing #464 and #482. Public fixture results do
not replace it. Keep target names, paths, configuration, measurements, and raw
reports private; publish only the tested depgraph commit and completion verdict.

`--no-cache` disables the unit checkpoint store
(`ScanCacheMode::Disabled`), so a cold-scan check and a resume check cannot
share one command line.

```text
# 1. Fresh scan + health. Public JSON must be status: "completed" with
#    partial_ranges: false. Reject scan status: "partial". The internal
#    HealthAnalysisError::ResourceExhausted maps to e2e
#    whole_snapshot.bounded.outcome "resource_exhausted"; that is a control
#    failure, not a public JSON field.
depgraph --store /tmp/trial.sqlite scan /path/to/repository --no-cache --json
depgraph --store /tmp/trial.sqlite health --json

# 2. Resume on a separate store. First invocation writes unit checkpoints
#    (do not pass --no-cache). Interrupt, then resume the same store.
depgraph --store /tmp/trial-resume.sqlite scan /path/to/repository --json
# interrupt, then:
depgraph --store /tmp/trial-resume.sqlite scan /path/to/repository --json

# 3. Optional unbounded health control (counts, work, timings, digests only):
cargo run -p depgraph-core --example health_range_e2e -- --store /tmp/trial.sqlite --root /path/to/repository --report /tmp/trial-health-report.json
```

Require the fresh scan to report `status=completed`, then run normal `health`
against that completed snapshot and require `partial_ranges=false`. A health
request with `--scan-id attempt:...` can finish every range of a partial graph;
that does not establish scan completion and cannot satisfy this requirement.
Keep individual resource limits and the target unchanged. In the checkpoint
store, finish a scan and repeat it to verify reuse of valid units, then repeat
health and compare findings and digests. Capture commit, conditions, unit count,
peak RSS, completeness, findings, work, and digests in the private record.
If any required check is incomplete or fails, leave #464 and #482 open.

## Regression checks for #479 and #480

`cargo xtask resumable-analysis-e2e` also runs
`scripts/analysis-resplit-e2e.mjs` on POSIX. Its public five-file Go fixture
starts with multiple batches and a fixed 192 MiB worker limit. A wrapper
forces larger batches over that limit, then pauses a replacement so the test
can interrupt and restart the CLI. A separate run exceeds the output cap
under the same fixture configuration, after emitting a valid partial stream,
and must recover by refinement as well. An unsplittable run keeps the valid
leaf prefixes as partial evidence and cannot confirm unused findings.
The test checks repeated refinement,
retained syntax/typed checkpoints, completed replacement execution, and equal
graph, evidence, and coverage against a run without injected failures.
Semantic results produced before all typed references are bound remain
ineligible for checkpoint reuse and are replayed conservatively.
Applied refinements are stored atomically as disposable planning hints beside
the unit checkpoints. The cache key binds the original split plan, input
contents, root and unit execution witnesses. A new process rebuilds the plan
from those refinements before dispatch; malformed or stale hints fall back to
the original plan, and `--no-cache` neither reads nor writes them. Restoring a
plan does not bypass unit input, protocol or reference validation. The restart
fixture removes the injected failure before resuming, so reuse must work even
when the original larger units would now succeed.

A separate two-package fixture verifies that an unchanged second scan reuses
both semantic units and that editing the referenced package invalidates them.
Its result must match a fresh scan after the edit. Go's no-follow, loader,
fingerprint, and race tests run in the regular Linux CI job and the macOS
leg of full CI. These public regressions supplement the original-target completion requirement above.

The Web integration fixture also checks projects with several frameworks.
Each source-batch profile declares only the frameworks in its projected
completeness ledger; TypeChecker counters exclude framework-specific records.
An incomplete framework ledger prevents semantic-complete coverage and keeps
its diagnostic reason. Nested units accept repository-root workspace manifests
while rejecting sibling manifests and traversal paths. The worker, core, and
packager agree on the `analysis-source-batch-v1` capability.
Astro endpoint batches explicitly request the bounded set of HTTP method
export proofs, so exact handler resolution does not depend on imports in
another unit.
The scheduler assigns static TanStack configuration witnesses to the first
semantic batch, including batches without a file route.
Assigned TanStack configuration ASTs remain available to the virtual route
collector within the existing AST budget, without adding native dependency
occurrences from auxiliary files or emitting their routes in sibling batches.
Build observations select the matching framework semantic profile among v2
logical units; syntax and unrelated framework profiles are excluded, while
multiple matching semantic parents still reject the observation.
Web stage joins compare the base profile and selected configuration rather
than the stage's emitted framework feature list. Syntax keeps its empty
framework semantic ledger, while a matching completed semantic stage can
establish aggregate semantic completeness. Different base profiles, selected
inputs, and unknown dependencies still prevent that join; Go build tags remain
part of the configuration identity.

Compiler timeouts dispose the IPC request queue before reaping the compiler.
The worker flushes its failure frames and stderr before exiting with code 124,
so pending replies and upstream partial-frame timers cannot replace the timeout
outcome or prevent resource resplitting. A synthetic compiler holds an open
snapshot and floods filesystem callbacks to exercise this shutdown path.
The package-loader memory gate retains superseded attempts in its report but
checks the completed replacement units against the original memory limit and
requires complete durable analysis coverage before comparing their graphs.

Completion validation aggregates site status counts in its existing site pass
instead of rescanning every site for each profile. A public synthetic test
checks SQLite work growth as the profile and site counts increase.

Canonical exports retain logical profiles and graph counts. Per-execution
counters stay in validated worker/checkpoint streams, so the integration gate
checks graph evidence, profile memberships, coverage, and diagnostics rather
than requiring those counters on canonical profiles. It also compares exports
from independent checkouts.

## Acceptance matrix

The matrix maps the six child issues (#459, #462, #463, #465, #466, #467)
and the parent #464. Extra rows `#464 (pre-split)` and `#467 (health split)`
are the 2026-09-07 reopen items, not additional issues. Checks below were
run in this checkout on 2026-09-06, then re-verified for the reopen items
on `main` at `564c064`.
The full `cargo xtask test` gate passed with Rust 1.93.1, Go 1.26.1,
Node.js 24.18.0, and pnpm 10.33.0 on macOS arm64. It included 1,798 passing
Rust tests in 50 suites, Node launcher/release tests, Go race/vet and real-worker
E2E, Rust real-worker E2E, 270 passing Web tests, and the resumable integration
fixture. One opt-in Web benchmark test is skipped in the regular suite; its
separate measured run is documented in the linked benchmark report.
`pnpm quality` also passed. The subsequent shared-applicability optimization
passed all 715 Core library tests, including 28 unused-analysis tests, along with
formatting and Core clippy. CI repeats the relevant checks against the PR head
and retains its integration report separately from these local measurements.

| Issue | Acceptance boundary | Test or command | Evidence status |
| --- | --- | --- | --- |
| #459 | Nested workspace discovery, same-name package scopes, exclusions, and static-only operation | `cd workers/web && pnpm test`; `imports.test.ts` tests `repository-root scans discover nested pnpm workspaces and resolve local packages`, `inline pnpm workspace lists preserve nested package ownership and imports`, `independent nested workspaces keep same-name packages and lock scopes separate`, and `pnpm workspace declarations own their scope and keep exclusions absolute` | Passed in the full Web suite and mixed integration fixture |
| #462 | Web project batches preserve compiler context, semantic targets, diagnostics, and canonical graph behavior | `cd workers/web && pnpm test`; `analysis-unit.test.ts` (`semantic source batches keep context targets while bounding dependency traversal`, `semantic source batches retain ambient declarations in the full compiler context`, `source batch size and order preserve one canonical graph`); `analysis-unit-issues.test.ts` (`batch semantic issue counts describe emitted diagnostics while context failures stay incomplete`); `DEPGRAPH_WEB_BENCHMARK=1 pnpm exec tsx --test test/analysis-unit-benchmark.test.ts` | Full Web suite, quality, and 1,024-file semantic benchmark passed; canonical joins also pass failed-chunk permutation and shared-external membership regressions |
| #463 | Remaining pre-split: lightweight listing then bounded loader and budget; package units that do not re-load the module; staged bodies for a large single package; cross-unit types, calls, and cycles with declared CHA completeness; public fixture where the whole-module path fails the same per-unit memory limit the package path completes; maintainer verification of the original private tree | `cargo xtask go-loader-scope-e2e`; Go `TestSyntheticAnalysisUnitCanonicalProjection`, `TestGoLoader*`, `TestAnalysisSplit*`, `TestReleaseGoSSASyntaxAfterBuildDropsLoaderTrees`; Core `go_package_execution_units_join_into_one_logical_profile`, `go_semantic_batches_join_their_call_graph_outcome`, `package_semantic_checkpoints_bind_the_typed_reference_fingerprint`, `reference_digest_extends_the_key`; store `v2_typed_rows_may_partition_the_owned_sources` | Package-bounded hybrid loader, declared CHA program scope, shared scan GOCACHE, reference fingerprint in `UnitCheckpointKey.reference_digest`, syntax drop after SSA, mapping progress, and the public 64-by-8 / 1,024-file evidence gate. The original private repository item needs the maintainer's `depgraph scan --no-cache --json` on that tree (aggregates only). See [Go validation](analysis-unit-go-validation.md) |
| #464 | Repository-first planning, unit scheduling, interruption/restart, invalidation, and public fixture evidence | `cargo xtask resumable-analysis-e2e` (calls `scripts/resumable-analysis-e2e.mjs`) | Passed: 13 baseline units, 22 split units, and all 22 reused after process restart; interruption and invalidation checks also passed |
| #464 (pre-split) | Same input and budget plan execution units before heavy analysis; many-package and large-single-package input/retention shrink; ranged health load and preprocess; graph/evidence/findings match across split and resume; public over-limit fixtures complete without raising per-unit limits. Completion on the original private trial tree is also required before closing #464. | `cargo test -p depgraph-core --test analysis_split_contract`; `cargo xtask go-loader-scope-e2e`; `cargo xtask health-range-e2e`; `cargo xtask resumable-analysis-e2e`; `cargo test -p depgraph-core --test health_range`. See "Epic #464 pre-split integration". | Passed on `main` at `564c064` (re-run 2026-09-07): children #465/#463/#467 merged; Go e2e at 192 MiB (fan-out 92.3 MiB complete vs 574.7 MiB control `partial`; 1,024-file `staged_bodies` 86.7 MiB complete vs 604.1 MiB control `partial`); health-range 4 ranges complete vs whole-snapshot `resource_exhausted` at 1,000,000. Original-target scan+health requires separate private evidence before the Epic can close. |
| #465 | Pre-split planning contract: explainable execution units, budget- and boundary-driven scope and parallelism before execution, dependency/cycle/shared-input retention, staged large package, re-split dispositions, the worker loader binding, and the review follow-ups (loader-scope capability required for the bounded package boundary, file-count-only partition and byte-identical requests for workers without loader scope, zero admitted memory for an empty plan, exact syntax loader scope in the Go worker) | `cargo test -p depgraph-core --test analysis_split_contract` (16 tests over `fixtures/analysis-split-plan-v1`, golden `expected/split-plans.json`); `cargo test -p depgraph-core loader_scope_binding_is_attached_only_after_negotiation_and_keeps_requests_stable`; `cd workers/go && go test ./internal/worker -run TestAnalysisSplit`; `cd workers/go && go test ./internal/worker -run TestReadAnalysisUnitRequestAcceptsSplit`; `cargo test -p depgraph-cli --test cli scan_split_plan_explains_execution_units_without_starting_workers_or_writing_a_store` | Passed locally on 2026-09-07; see [the pre-split planning ADR](adr-presplit-analysis-planning.md) |
| #466 | Atomic checkpoint publication, failure/cancel retention, resource limits, and Store/journal compatibility | `cargo test -p depgraph-core incomplete_semantics_remain_readable_but_are_not_reused`; `cargo test -p depgraph-core typed_checkpoint_requires_a_completed_typed_graph_without_claiming_ssa`; `cargo test -p depgraph-store analysis_unit_snapshots_reject_legacy_delta_and_staging_without_losing_the_ledger`; `cargo test -p depgraph-store analysis_unit_gate_follows_preexisting_semantic_noop_overlay_ancestors` | Passed in the pinned full Rust gate, including fake-clock aggregate-budget behavior, atomic ledger/checkpoint, input-proof snapshot identity, and metadata-only terminal summary regressions |
| #467 | Cross-unit `deps`, `dependents`, `why`, and `impact`, exact stored provenance, partial selection, and conservative unused confidence | `cargo xtask resumable-analysis-e2e`; query assertions are in `scripts/resumable-analysis-query-assertions.mjs`; `cargo test -p depgraph-core incomplete_analysis_units_cannot_confirm_unused_files_in_otherwise_complete_profiles`; `cargo test -p depgraph-core health::unused::tests::issue_467` | Passed: all four partial queries with exact stored provenance, unchanged current completed snapshot, canonical graph equality, 8 partial unused-file findings with no confirmed confidence, and equivalent-stage health work/provenance regressions |
| #467 (health split) | Range planning without the full `GraphSnapshot`, per-range budgets with saved results and resume, cross-range usage, preserved profile/condition/evidence/missing-profile/coverage/layer semantics, unconfirmed findings while ranges are missing, identical findings for normal / reordered / interrupted runs, and a public over-limit fixture | `cargo xtask health-range-e2e`; `cargo test -p depgraph-core --test health_range` (19 tests); `cargo test -p depgraph-mcp --test process issue_423_health_tools_are_read_only_redacted_and_match_cli_parity` | Passed: the whole-snapshot control is `resource_exhausted` at the unchanged 1,000,000 budget while the ranged path completes 4 ranges (maximum 433,340 steps) with identical findings and full checkpoint reuse; see "Ranged health collection". The original private repository item needs the maintainer's run of the `--store` evidence runner |

The measured public fixture produced 13 profiles, 54 nodes, 111 edges, and
162 evidence records. Its baseline scan took 8.637 seconds, the split scan
11.660 seconds, and the fully reused scan 6.464 seconds. These elapsed times
are observations from this development build, not product performance limits.

The report records unit counts, reuse, graph payload counts, interruption and
re-execution counters, and elapsed time. Its `stages` section records unit and
reuse counts and summed worker duration for each adapter and stage. Summed
worker duration includes parallel work and is separate from scan elapsed time.
RSS is measured by the separate Go and Web fixtures linked below. The Web
1,024-file fixture records Node RSS at phase progress events; these observations
exclude the native compiler child process and are not a CI threshold. Local
measurements remain separate from the CI result required before merge.

## Additional boundaries

The integration fixture complements these focused checks:

- [Go validation](analysis-unit-go-validation.md) covers same-name module
  instances, reversed batch order, a 1,024-file package, typed and SSA progress,
  and repeated loading of shared compiler inputs.
- [Web AST bounds](analysis-unit-web-ast-bounds.md) records the 1,024-file
  project benchmark and the limits of native compiler context reuse.
- Core executor tests cover inactivity, explicit total budgets, process-group
  memory, protocol/output limits, cancellation, invalid checkpoints, and a
  typed checkpoint surviving a failed semantic stage. Resource-limit enforcement
  and checkpoint retention are verified at their shared executor boundaries; the
  large Go compiler-context benchmark does not deliberately force a memory-limit
  failure.
  `progressing_scheduler_outlives_legacy_aggregate_deadline_with_fake_clock`
  advances virtual time past the former 300-second aggregate deadline. The
  normal configuration completes all four fixture units; the same clock with
  an explicit 300-second budget cancels through the shared budget decision.
- Store tests cover immutable expected-unit ledgers, atomic unit ingestion,
  complete stage joins, snapshot seals, migrations, and conservative
  completeness when a stage or dependency scope is missing.
  Snapshot identities include the input and analysis proof while excluding
  whether the proof came from a reused checkpoint. Metadata projection tests
  deny graph-payload reads while recording incomplete coverage and returning
  terminal status, diagnostics, and cache events.
- MCP process tests exercise durable scan submission, client reconnection,
  terminal v2 results, and completed snapshot naming. Operation journal tests
  cover recovery and lease races. Daemon tests observe the same executor's
  live unit progress. These service fixtures do not measure nonempty Go/Web
  checkpoint reuse themselves; the real-worker interruption/reuse measurement
  is the CLI fixture above, which uses the shared executor.

Worker unit tests and the existing Rust workspace, Go race/vet, Web quality,
protocol/schema, and release compatibility gates remain part of validation.

The fixed release query still returns no rows and remains identical across
checkout-equivalent scans. Its pinned native digests must be regenerated when
the canonical analysis graph changes. The manual CI input
`extra_native_packages` adds Linux ARM64 and Intel macOS package validation to
the regular Linux x64, Apple Silicon macOS, and Windows checks; it does not
publish release artifacts or skip any compatibility assertion.
