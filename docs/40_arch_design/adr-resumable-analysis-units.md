# ADR: Static analysis-unit planning for resumable scans

- Status: Proposed
- Date: 2026-09-06
- Issue: #465
- Contract: depgraph-analysis-plan-v1
- Worker capability: analysis-unit-v1 (advertised by `--version` capabilities)

## Context

The scan command currently receives a repository root and starts a language
worker for the whole adapter. A large repository can therefore spend its
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

The initial static planner emits these unit kinds:

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
root and source paths. An executable unit request uses
`contract_version = depgraph-analysis-unit-v1`; this is distinct from the
`analysis-unit-v1` capability name returned by `--version`.

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

Go syntax checkpoints add a repository-wide content witness to the static
unit-ownership fingerprint. The witness covers every file selected by the
repository inventory, including auxiliary files such as assembly sources and
embedding inputs. When the bounded persistent-cache fingerprint is eligible,
its `file_content` digest is reused; when cache limits reject that fingerprint,
the executor streams the same inventory without those cache limits. Store
databases and their WAL or SHM sidecars, `.depgraph` state, and the existing
generated-state exclusions remain outside the witness. A shared witness is
checked once before checkpoint reuse, then recomputed before each newly written
checkpoint and again before publication so a file change during execution
cannot be saved under the earlier key. If the witness cannot be obtained, the
Go unit capability is not scheduled and the repository-worker fallback keeps
the ordinary scan available. Legacy whole-adapter scans retain their existing
cache and publication safeguards.

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
nodes and snapshots. Until workers negotiate depgraph-analysis-unit-v1, the
existing whole-adapter worker may continue using the definition profile
selection at its repository fallback boundary.

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

The plan is an additive core contract. Existing whole-adapter worker requests,
Store snapshots, and operation journal records remain valid until their
respective execution and integration issues adopt the plan. Checkpoint
persistence, worker scheduling, process supervision, and graph integration are
separate responsibilities.

Treating every directory as an independent unit was rejected because it loses
workspace and compiler resolution context. Increasing one repository-wide
timeout was rejected because it still discards completed work and cannot
explain which unit made progress. Running package managers during discovery was
rejected because it executes untrusted project behavior and makes a plan
depend on mutable external state.
