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

The semantic stage runs once for the complete application module. It checks
that typed loading and SSA progress are reported and that semantic output is
marked `full_module`. The test also scans `same-a` semantically to measure the
typed files loaded again by a second unit.

Workers advertising `analysis-unit-typed-v1` add a single typed stage between
syntax and semantic work. The typed request is always one full-module chunk.
It emits type declarations, type references, implements relations, and
type-resolved calls without invoking SSA. Its normal COMPLETE stream retains
only `syntax-complete`; `go_typed_stage_complete` is the string property
`"true"` only after both the typed load and extraction succeed. A failed load
or extraction sets it to `"false"` and adds `go-typed-incomplete`. The semantic
stage remains the only stage that may claim `semantic-complete`.

The typed stream is the durable graph boundary for resumable semantic work.
Go's `types.Package`, `types.Info`, and SSA objects are process-local, so a
semantic retry reconstructs the compiler universe from the fixed repository
inventory. The retry reuses the validated typed graph and does not claim to
reuse serialized compiler objects. A worker killed before the typed stream is
validated cannot produce a typed checkpoint; an SSA failure leaves a typed
checkpoint eligible while keeping semantic reuse disabled.

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
