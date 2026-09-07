# Resumable analysis integration validation

`cargo xtask resumable-analysis-e2e` builds the CLI and the real Go and Web
workers, then runs a generated public repository through the shared scheduler
and Store. CI's existing Go job runs this command on Linux, preserving the
eight-job identity required by the release evidence verifier. The fixture
contains no source or configuration copied from a private repository.

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

## Acceptance matrix

The matrix maps the six issue contracts to checks run in this checkout on
2026-09-06. The full `cargo xtask test` gate passed with Rust 1.93.1, Go 1.26.1,
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
| #463 | Go syntax, typed, and semantic prefixes retain module context, local replacements, and stage eligibility | `cd workers/go && GOTOOLCHAIN=local GOFLAGS=-mod=readonly go test ./internal/worker -run 'Test(SyntheticAnalysisUnitCanonicalProjection|ScanAnalysisUnitTypedStage|AnalysisUnitTypedStage)' -count=1 -v`; `go test ./internal/worker -run '^$' -bench '^BenchmarkSyntheticAnalysisUnitLarge$' -benchtime=1x -count=1 -v` | Go race/vet, real-worker E2E, and mixed integration passed; the separately measured 1,024-file benchmark is recorded in Go validation |
| #464 | Repository-first planning, unit scheduling, interruption/restart, invalidation, and public fixture evidence | `cargo xtask resumable-analysis-e2e` (calls `scripts/resumable-analysis-e2e.mjs`) | Passed: 13 baseline units, 22 split units, and all 22 reused after process restart; interruption and invalidation checks also passed |
| #465 | Pre-split planning contract: explainable execution units, budget- and boundary-driven scope and parallelism before execution, dependency/cycle/shared-input retention, staged large package, re-split dispositions, the worker loader binding, and the review follow-ups (loader-scope capability required for the bounded package boundary, file-count-only partition and byte-identical requests for workers without loader scope, zero admitted memory for an empty plan, exact syntax loader scope in the Go worker) | `cargo test -p depgraph-core --test analysis_split_contract` (16 tests over `fixtures/analysis-split-plan-v1`, golden `expected/split-plans.json`); `cargo test -p depgraph-core loader_scope_binding_is_attached_only_after_negotiation_and_keeps_requests_stable`; `cd workers/go && go test ./internal/worker -run 'TestAnalysisSplit|TestReadAnalysisUnitRequestAcceptsSplit'`; `cargo test -p depgraph-cli --test cli scan_split_plan_explains_execution_units_without_starting_workers_or_writing_a_store` | Passed locally on 2026-09-07; see [the pre-split planning ADR](adr-presplit-analysis-planning.md) |
| #466 | Atomic checkpoint publication, failure/cancel retention, resource limits, and Store/journal compatibility | `cargo test -p depgraph-core incomplete_semantics_remain_readable_but_are_not_reused`; `cargo test -p depgraph-core typed_checkpoint_requires_a_completed_typed_graph_without_claiming_ssa`; `cargo test -p depgraph-store analysis_unit_snapshots_reject_legacy_delta_and_staging_without_losing_the_ledger`; `cargo test -p depgraph-store analysis_unit_gate_follows_preexisting_semantic_noop_overlay_ancestors` | Passed in the pinned full Rust gate, including fake-clock aggregate-budget behavior, atomic ledger/checkpoint, input-proof snapshot identity, and metadata-only terminal summary regressions |
| #467 | Cross-unit `deps`, `dependents`, `why`, and `impact`, exact stored provenance, partial selection, and conservative unused confidence | `cargo xtask resumable-analysis-e2e`; query assertions are in `scripts/resumable-analysis-query-assertions.mjs`; `cargo test -p depgraph-core incomplete_analysis_units_cannot_confirm_unused_files_in_otherwise_complete_profiles`; `cargo test -p depgraph-core health::unused::tests::issue_467` | Passed: all four partial queries with exact stored provenance, unchanged current completed snapshot, canonical graph equality, 8 partial unused-file findings with no confirmed confidence, and equivalent-stage health work/provenance regressions |

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
