# Go analysis-unit validation

The Go source-batch implementation preserves the canonical graph when one
large package is split into different source batches. The check uses a
generated fixture, so it does not contain repository-specific source or
measurements.

## Fixture and test

`TestSyntheticAnalysisUnitCanonicalProjection` creates eleven modules under a
temporary repository. The application module has one package with 48 Go
files. It requires eight local dependency modules and one shared module whose
replacement points to `same-a`. A second directory, `same-b`, declares the
same module path but is outside that replacement. This makes module-instance
identity observable without relying on a network module.

The test scans the application package in three ways:

- one 48-file syntax request;
- seven syntax requests with seven files per batch; and
- the same seven requests in reverse execution order.

The normalized projection maps references to repository-relative target
identity. It removes request chunk fields and profile IDs from the comparison,
then compares node payloads, edges, sites, evidence, conditions, file ledgers,
coverage, and stage-level profile properties. Structural `contains` edges stay
in the projection. A conflicting payload for one logical target fails the
test.

The semantic stage without a split binding remains one full-module
operation: this is the pre-#463 baseline a legacy request still gets. It
checks that typed loading and SSA progress are reported and that semantic
output is marked `full_module`. The test also scans `same-a` semantically to
measure the typed files loaded again by a second unit. Package-bounded
requests are covered by `analysis_split_scan_test.go`, `go_loader_scan_test.go`,
and `cargo xtask go-loader-scope-e2e`.

Workers advertising `analysis-unit-typed-v1` add a typed stage between
syntax and semantic work. A request without a package-loader split binding
is still one full-module chunk. A request that carries `split.loader.kind=package`
type-checks only the bound package roots from source and references
dependencies from export data; bodies of a large package are staged across
file batches. The typed stream emits type declarations, type references,
implements relations, and type-resolved calls without invoking SSA. Its
normal COMPLETE stream retains only `syntax-complete`; `go_typed_stage_complete`
is the string property `"true"` only after both the typed load and extraction
succeed. A failed load
or extraction sets it to `"false"` and adds `go-typed-incomplete`. The semantic
stage remains the only stage that may claim `semantic-complete`.

The typed stream is the durable graph boundary for resumable semantic work.
Go's `types.Package`, `types.Info`, and SSA objects are process-local, so a
semantic retry reconstructs the compiler universe from the fixed repository
inventory. The retry reuses the validated typed graph and does not claim to
reuse serialized compiler objects. A worker killed before the typed stream is
validated cannot produce a typed checkpoint; an SSA failure leaves a typed
checkpoint eligible while keeping semantic reuse disabled.

Typed loading and SSA of a module-loader unit retain the full declared
compiler context and remain subject to the configured worker memory budget.
A package-loader unit retains only the target packages' syntax and bodies;
dependencies contribute export-data declarations. A context that exceeds the
budget leaves its unit incomplete, while earlier validated units remain
reusable. Syntax source-batch size controls syntax work; a package that
alone exceeds the estimate is staged (`staged_bodies`) rather than raising
the per-unit limit.

Run the focused check with:

```text
cd workers/go
GOTOOLCHAIN=local GOFLAGS=-mod=readonly go test ./internal/worker -run TestSyntheticAnalysisUnitCanonicalProjection -count=1 -v
```

## Measurements

One run on Go 1.26.1, darwin/arm64, on 2026-09-06 produced the following
values. The test reports wall time and samples the worker process RSS every
five milliseconds with `ps`; the values are observations rather than pass or
fail thresholds.

| Stage | Work shape | Wall time | Peak RSS |
| --- | --- | ---: | ---: |
| Syntax | one 48-file request | 11 ms | 13,715,720 bytes |
| Syntax | seven 7-file requests | 58 ms | 14,387,464 bytes |
| Semantic | one full-module request | 413 ms | 19,663,112 bytes |

The application semantic request loaded ten local module instances, ten local
packages, and 57 local typed files. A second semantic request for `same-a`
loaded one more typed file. The measured total was 58 typed-file loads over
two requests, against 57 unique context files: one duplicate load and zero
cross-unit typed-object reuse. The worker keeps semantic loading and SSA
construction atomic because `go/packages` and the SSA builder do not expose a
safe checkpoint boundary inside either operation.

## What the check establishes

The single request and the seven source batches have the same normalized graph
and evidence. Reversing batch completion order produces the same projection.
The replacement requirement and import resolve to the `same-a` module
instance. The `same-a` and `same-b` units receive different package-instance
IDs even though they declare the same module path.

The syntax profile remains a source-batch profile, while the semantic profile
remains a full-module profile. Chunk-specific profile fields are retained in
the emitted protocol stream for scheduling and checkpoint joins; they are
excluded only from the stage-level equivalence projection.

The fixture does not measure a production repository or establish a fixed
performance target. Its purpose is to catch graph drift, source-scope leaks,
incorrect duplicate-module identity, and unexpected typed-load reuse claims
when batch size or completion order changes.

## Explicit large-package benchmark

`BenchmarkSyntheticAnalysisUnitLarge` is separate from the correctness test so
the regular worker suite does not create a large compiler universe. It creates
one `app` package with 1,024 Go files and eight functions in every file (8,192
functions), plus eight local dependencies and two directories declaring the
same module path. The semantic request loads the complete module context. The
syntax case is measured once as one request and once as eight 128-file source
batches.

Run the benchmark explicitly with one iteration:

```text
cd workers/go
GOTOOLCHAIN=local GOFLAGS=-mod=readonly go test ./internal/worker -run '^$' -bench '^BenchmarkSyntheticAnalysisUnitLarge$' -benchtime=1x -count=1 -v
```

One run on Go 1.26.1, darwin/arm64, Apple M3, on 2026-09-06 produced these
observations. RSS is sampled from the worker test process every five
milliseconds. The benchmark runs its subcases in one process, so the process
baseline is shared between rows.

| Stage | Work shape | Wall time | Peak RSS | Progress events | Typed packages | Typed files |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| Syntax | one 1,024-file request | 137 ms | 32,069,912 bytes | 1,026 | 0 | 0 |
| Syntax | eight 128-file requests | 492 ms | 32,069,912 bytes | 1,040 | 0 | 0 |
| Semantic | one full-module request | 1,203 ms | 177,600,824 bytes | 1,050 | 10 | 1,033 |

The benchmark is a repeatable performance guard and a resource observation;
it does not impose a machine-specific time or RSS threshold. The worker keeps
the typed load and SSA build atomic, so the semantic row measures their full
compiler context and cannot claim typed-object reuse across separate units.
This benchmark observes a successful compiler load; it does not force a memory
limit failure. The common executor tests separately cover worker-tree memory
enforcement and preservation of validated checkpoints after stage failure.

## Package-bounded hybrid loader (#463)

The shipped Go worker advertises `analysis-loader-scope-v1` and
`analysis-go-package-loader-v1`. The scheduler binds typed and semantic
requests to package roots; the worker's hybrid loader then:

1. lists the module with metadata only (`./...`, no types);
2. loads dependency export data (`go list -export` of the dependency
   patterns, never of the target);
3. type-checks each target variant in process with a full `types.Info`.

SSA is built with `ssautil.Packages` over that declared program
(`package-with-declaration-deps`). CHA is the only call-graph algorithm;
RTA/VTA require bodies on every dependency and are not attempted. After
`ssa.Program.Build` the worker drops `Syntax` and `TypesInfo` before CHA and
mapping, and reports `go_ssa_mapping` progress every 64 pending call sites.
The core sets `GOMEMLIMIT` to 75% of `scan.max_worker_memory_bytes` on every
Go worker, leaving headroom for memory outside the Go runtime and child
processes. The 250 ms RSS watch still enforces the configured limit over the
whole process tree. The hybrid loader forwards the decimal-byte runtime
limit to `go list` children and sets `-p=1` and `GOMAXPROCS=1` to bound
compiler concurrency.

Dependency export-data builds use `-gcflags=all=-N -l` because analysis
consumes their type declarations without running their executable code.
Disabling optimization and inlining reduces compilation memory. For package
loads, Core supplies `scan.worker_timeout_seconds` through
`DEPGRAPH_GO_LOAD_TIMEOUT_SECONDS`; its total worker deadline remains in
force. Direct library callers without that input retain the 30-second
default. Invalid or overflowing timeout values also use that default.

### Completeness and identity

- Absence of `go_call_graph_program_scope` means whole-program. Package
  units emit `package-with-declaration-deps`.
- Dynamic function-value calls whose targets could be closures defined in
  dependencies are `unresolved` (`function_value_dispatch`); interface
  invokes keep `candidates/overapprox` with the same candidate IDs as
  whole-program CHA. The package CHA driver restores method sets of
  export-data named types (`T` and `*T`), including unexported dependency
  types that whole-program CHA only materialises when some body instantiates
  them (conservative over-approximation on dead dependency types).
- Same-path modules stay distinct by directory; local `replace` resolves to
  the in-repo directory; test variants keep `ForTest`. Type objects never
  cross loads.
- `analysis_loader_mode` and `go_call_graph_program_scope` are not coverage
  profile axes. Package chunks of one module share a logical profile with a
  whole-module unit of the same module. Canonical profile merge still
  requires those keys to match; a re-split replaces the promoted unit rather
  than folding mixed loader modes.

### Public evidence gate

`cargo xtask go-loader-scope-e2e` generates two public fixtures (64 packages
× 8 files with tests and a `cmd/app` main; one 1,024-file package) and runs
them at one reduced per-unit memory limit that is never raised above the
shipped default. A control worker advertising only the module-loader
capabilities fails its typed and semantic units at that limit; the shipped
package-bounded path completes, reports `go_loader_syntax_packages ==
go_loader_target_packages`, never type-checks a body twice within a stage,
and reproduces the control's nodes, sites, exact edges, evidence, and
coverage. CHA `may_call` edges of a package batch are a declared subset of
whole-program CHA: an interface call is resolved only against implementers
in that batch's SSA program (`package-with-declaration-deps`). Resume
replays every staged batch. CI uploads the per-unit table as
`go-loader-scope-report`.

The original trial tree is not in CI and is a **required closer for epic
#464**, not an optional follow-up. Public fixtures are necessary and not
sufficient. A maintainer who can reach that tree must complete the required scan,
ordinary health, and same-input resume checklist in
[resumable-analysis-validation.md](resumable-analysis-validation.md)
("Required private-trial closer") and comment on #464 before the epic
closes. The Go half of a cold scan is:

```text
depgraph --store /tmp/trial.sqlite scan /path/to/repository --no-cache --json
```

Accept only top-level `"status": "completed"`. Keep unit count, peak RSS,
completeness, and other measurements in the private record. Do not publish
private paths, digests, or measurements. Resume and ordinary health
commands live in the same validation section; `cargo xtask
go-loader-scope-e2e` does not take `--store` / `--root`.

### Checkpoint invalidation

Typed and semantic checkpoint keys of a package-bounded unit include
`UnitCheckpointKey.reference_digest`, the digest of the worker-reported
`go_reference_fingerprint` values of the overlapping typed prerequisites.
Syntax checkpoints are unchanged. The first scan after the dependency
snapshot moved from the observed NeedDeps load to the module-wide metadata
listing invalidates typed and semantic checkpoints once.

Linux and macOS generate that fingerprint by walking each confined path
component with `openat(2)` and `O_NOFOLLOW` (via `golang.org/x/sys/unix`;
the `syscall` package exports `Openat` only on Linux). The same module
listing therefore produces the same digest on both hosts, and a second
scan reuses package semantic checkpoints until an in-repo dependency
source changes. Platforms without a no-follow open omit
`go_reference_fingerprint`; Core then leaves `reference_digest` unbound
and does not read or write those semantic checkpoints.
