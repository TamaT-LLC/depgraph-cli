# ADR: Static analysis-unit planning for resumable scans

- Status: Implemented
- Date: 2026-09-06
- Issue: #465 (parent #464)
- Contract: depgraph-analysis-plan-v1
- Worker capabilities: analysis-source-batch-v1 (v2), analysis-unit-v1 (legacy Go v1)

The acceptance matrix in
[resumable-analysis-validation.md](resumable-analysis-validation.md) records
the passing pinned local gate, public integration fixture, and separate
benchmark measurements. CI verification is required before merge. Public
fixture evidence is necessary and not sufficient for parent #464: the
original trial target must complete scan and health before that epic
closes.

## Context

The previous scan command started one language worker for each adapter at the
repository root. A large repository can therefore spend its
entire job budget in one worker even when a large part of the result is
already usable. A timeout also discards the distinction between a slow unit,
a failed unit, and a repository that is still making progress.

Resumable execution needs a deterministic plan before any worker is started.
The plan must preserve the compiler or package resolution context that crosses
directory boundaries. Treating every directory as an independent repository
would lose workspace members, local replacements, and sibling references.
The plan also needs an identity that survives moving a checkout to another
path, while changes to source, configuration, profile, analyzer, or a
repository dependency invalidate the correct work.

Discovery is a static operation. Running a project package manager, build
script, compiler, or project code during discovery would change the security
boundary and make planning depend on mutable tool state.

## Decision

Adopt depgraph-analysis-plan-v1 as the common planning contract. The core
exposes:

    discover_analysis_plan(root, config, input) -> AnalysisPlan
    plan_analysis_units(root, config, optional_store_path) -> AnalysisPlan

The second entry point is a scheduler convenience. Its store path is an
invocation binding and is never included in the plan input. Store databases,
WAL or SHM files, checkpoints, and generated state remain excluded by the
existing repository inventory rules.

The serialized plan contains:

- a contract version and portable repository root token;
- a repository identity, inventory digest, plan ID, and input digest;
- source, manifest, configuration, profile, and analyzer fingerprints;
- executable and context analysis units;
- resolved, external, and unknown dependency references;
- strongly connected dependency groups, including cyclic groups; and
- explicit static-discovery limitations.

The actual checkout path is not serialized into an ID. Repository identity
uses the origin identity when the checkout contains a readable Git origin
configuration and otherwise uses an unbound repository identity. A source or
manifest edit therefore changes fingerprints and invalidation entries without
changing the logical repository binding.

## Unit and adapter boundary

Each unit has a repository-relative unit root, an adapter, a stable ID, a
locator, source and configuration scopes, and dependency witnesses. The
stable ID is derived from the contract, adapter, unit kind, unit root, and
locator. Absolute checkout paths, timestamps, inode values, locale, and
directory iteration order are excluded.

The static planner emits these unit kinds:

| Adapter | Executable units | Context units |
| --- | --- | --- |
| Rust | one repository adapter fallback | Cargo workspace and package records |
| Go | one unit per go.mod, or a repository fallback without go.mod | go.work and source-directory package records |
| Web | one project per package.json, with workspace roots kept as context | Web workspace records |

Executable ownership chooses the most specific unit root for a source path, so
nested Go modules and Web projects do not receive the same source file merely
because they are descendants of one another. Context records retain manifest
ownership and resolution evidence without causing duplicate worker execution.
Rust keeps its repository-wide fallback until a Rust worker advertises the
unit capability.

The repository root remains fixed while a worker processes a unit. Unit root
is a source ownership and scheduling hint; it does not authorize resolving
outside the repository root or executing project code. A unit-capable worker
must receive the repository root binding separately from the portable unit
root and source paths. Source batches use
`contract_version = depgraph-analysis-unit-v2` after negotiating
`analysis-source-batch-v1`. The legacy Go `analysis-unit-v1` capability retains
its v1 request shape. See [the execution contract](adr-analysis-unit-execution.md)
for stage, full-context, auxiliary-input, and checkpoint bindings, and
[pre-split planning](adr-presplit-analysis-planning.md) for how each unit is
divided into execution units with explicit ownership, loader, and reference
scopes before any worker starts.

## Dependency graph

Manifest dependencies, workspace members, local path replacements, and
conservative source import observations are represented as dependency
references. A resolved reference contains the target unit ID. An external
reference intentionally has no target. An unknown reference means static
discovery could not prove whether the target is repository-local; it is never
silently promoted to external or resolved.

The plan computes strongly connected components over resolved unit edges.
Cycles are a scheduling group and do not become a tree merely because the
source directories form a tree. Cross-unit processing must retain the
repository root and the complete dependency group context.

Package names and module names are not unique identity by themselves. The
canonical unit identity includes its repository-relative root. If duplicate
module or project names make a source reference ambiguous, the reference is
unknown and the affected adapter is conservatively invalidated.

Web resolution uses the nearest workspace that includes the package. A pnpm
workspace file, including a YAML-only root, takes precedence over the root
package's JSON workspace list. Negative patterns exclude members. An excluded
package remains an independent executable project with its own resolution
scope. Package and lockfile lookup never falls through into a sibling
workspace. Workspace-member edges retain topology; only actual dependency
edges propagate input invalidation.

Go replacement planning follows the worker's active-workspace boundary. Only
the repository-root `go.work` is active for a root scan; a module listed by its
`use` entries receives that workspace's replacement directives, while a
module outside the workspace uses its own `go.mod` replacements with
`GOWORK=off`. A versioned workspace replacement takes precedence over a
wildcard replacement, and conflicting directives at the same precedence are
unknown. Local replacement paths are resolved relative to the manifest that
declares them and must resolve to a discovered, root-confined `go.mod`; a
module-path replacement remains external. The active `go.work` is included in
each governed module's manifest fingerprint, so edits to workspace membership
or replacement rules invalidate those members and their dependency closure.
Portable planning treats absolute `use` and local replacement paths as
unknown, even when they might name an in-root path; the worker's later
confinement check remains authoritative for those directives.

## Fingerprints and invalidation

The plan keeps separate fingerprints for source content, manifest content,
repository configuration and lockfiles, selected profile definitions, and
the analyzer identity. Configuration inputs include workspace declarations and
manager lockfiles such as pnpm-workspace.yaml, go.work.sum, and bun.lock, as
well as TypeScript, framework, stylesheet, and JSON data files present in the
inventory. A unit input fingerprint combines its own component fingerprints
with a dependency fingerprint. This initial inventory is a conservative static
witness rather than proof of every file a compiler or framework can read.

The dependency fingerprint includes direct witnesses and the transitive
resolved dependency closure. This makes a checkpoint key change when a
dependency's source, manifest, configuration, profile, analyzer, or static
dependency witness changes. A unit with an unknown dependency also includes a
fingerprint for every unit in the same adapter. This is deliberately
conservative: an unknown repository-local edge cannot allow a stale result to
be reused.

Source-batch syntax checkpoints use a dependency-scoped content witness.
The witness includes the unit's sources, manifests, ancestor configuration,
auxiliary inputs, and the transitive dependency closure. Unknown dependencies
conservatively include the adapter scope. A change in an unrelated known unit
does not invalidate this key. A repository-wide witness is checked before
reuse and before writing or publishing new work to reject changes during a
scan. Store files, sidecars, checkpoints, and generated state are excluded.
Legacy Go v1 requests retain their repository-wide syntax witness. Semantic
reuse additionally requires the adapter's compiler and external-dependency
proof; static unit planning alone cannot establish it.

Package-bounded Go typed and semantic checkpoints add the worker-reported
`go_reference_fingerprint` of the in-repo import closure the typed stage
actually loaded. Core stores that digest in `UnitCheckpointKey.reference_digest`
so the static `input_digest` can still equal the request's context
fingerprint. Linux and macOS produce that fingerprint with the same
`openat`/`O_NOFOLLOW` walk; other platforms omit it and Core leaves
`reference_digest` unbound. Keys that omit the field serialize as they did
before, so existing module-loader checkpoint files stay valid. Changing an
in-repo dependency that a package imports therefore invalidates that package's
typed and semantic checkpoints while leaving unrelated packages reusable.

The Go dependency snapshot that feeds base and logical profile IDs is
computed from the module-wide metadata listing (`go list` without types),
not from the packages observed during a NeedDeps typed load. Every package
chunk of a module therefore shares the same snapshot. The first scan after
this snapshot-source change invalidates typed and semantic checkpoints once;
syntax checkpoints are kept.

`go_call_graph_program_scope` and `analysis_loader_mode` are not coverage
`profile_axes`: a whole-module unit and package-bounded chunks of the same
module still share one logical profile identity. `merge_logical_profile`
treats both keys as configuration identity, so units that disagree cannot
be folded into one canonical profile. In this planner a module is either
promoted as a whole or executed as package batches (a memory/time re-split
supersedes the promoted unit), so those keys agree in practice. Absence of
`go_call_graph_program_scope` means whole-program, which keeps historical
streams byte-identical.

AnalysisPlan::invalidation_from reports Added, Removed, SourceChanged,
ManifestChanged, ConfigChanged, ProfileChanged, AnalyzerChanged,
DependencyChanged, and UnknownDependency reasons. Direct changes seed the
plan, and dependency changes propagate through the current reverse graph.
The planner does not claim that static invalidation is a proof of semantic
completeness.

## Profiles

Input profile IDs are stable definition IDs. Each unit derives scoped
execution IDs from the adapter, unit ID, and definition ID. This prevents two
unit ledgers from colliding while preserving definition IDs for stable graph
nodes and snapshots. Chunk execution IDs are validated on the wire and then
normalized to the logical unit-stage profile before graph ingestion. Chunk
identity and progress remain in the execution ledger. Workers without a
negotiated capability retain the whole-adapter fallback.

Profile planning and unit planning remain separate contracts. Profile planning
chooses target, environment, mode, and feature or tag candidates. Unit
planning chooses repository ownership, source scope, dependency context, and
invalidation. A profile change therefore invalidates unit work without
pretending that profile selection discovered a new source unit.

## Static and security boundaries

The planner reuses repository inventory enumeration, ignore rules, generated
directory exclusions, symlink handling, and nested repository boundaries. It
reads Cargo, Go, and Web manifests as bounded data. It does not execute
Cargo, Go, npm, pnpm, yarn, a framework CLI, compiler hooks, scripts, or
project code.

Dynamic imports, generated sources not present in the inventory, conditional
resolution, toolchain-specific package selection, and semantic call graphs
may remain unknown. The plan records these limitations and workers must keep
their existing completeness and unresolved-site semantics. A partial plan or
partial unit result must not be presented as proof that an unobserved node is
unused. Before reusing or promoting a checkpoint, the executor must also verify
the worker/runtime identity, the complete effective input set, and any external
dependency or toolchain proof required by that worker. A matching plan
fingerprint alone cannot certify semantic checkpoint reuse when those inputs
are outside static discovery.

## Compatibility and rejected alternatives

The plan remains an additive v1 contract. Source-batch execution uses worker
contract v2, Store schema 19, and operation journal schema 6. Existing
whole-adapter requests remain supported; completed snapshots and finite v1
operation records remain readable. The execution ADR specifies migrations,
partial-attempt selection, and the failure behavior for incompatible state.

Treating every directory as an independent unit was rejected because it loses
workspace and compiler resolution context. Increasing one repository-wide
timeout was rejected because it still discards completed work and cannot
explain which unit made progress. Running package managers during discovery was
rejected because it executes untrusted project behavior and makes a plan
depend on mutable external state.
