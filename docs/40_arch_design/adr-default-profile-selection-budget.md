# ADR: Default profile selection and exploration budget

- Status: Accepted
- Date: 2026-07-25
- Decision ID: `PROJ-ARC-001-ADR-004`
- Issue: `PROJ-ARC-001-TASK-083` / #151
- Contract: `default-profile-selection-v1`

## Context

Rust features/targets/modes, Go platforms/tags/cgo, and Web
environment/module/framework axes can describe many valid analysis profiles.
A Cartesian product is neither a meaningful default nor a bounded operation:

- Cargo features are unified within a selected build and are intended to be
  additive, but repositories can define mutually exclusive features;
- Go build constraints can mention many GOOS/GOARCH/tag combinations, while
  cgo availability also depends on an external compiler;
- Web package exports, runtime environments, and framework build environments
  select ordered or tool-specific branches rather than independent Boolean
  dimensions;
- build and runtime profiles require consent or external evidence and cannot be
  inferred as safe-scan defaults.

The current configuration schema normalizes one selection per adapter through
`rust_features`, `rust_targets`, `rust_mode`, `go_tags`, `go_call_graph`, and
`web_environments`. It does not yet plan a multi-profile matrix. Empty Rust
features/targets, `rust_mode=check`, empty Go tags,
`go_call_graph=rta-cha`, and Web `browser + server` are the existing defaults.
This ADR preserves that behavior until the staged implementation introduces a
planner.

A default planner must select useful profiles deterministically, remain
bounded for a 10,000-file repository and beyond, expose everything it omits,
and let a user request a precise matrix without silently weakening it.

## Decision

Adopt `default-profile-selection-v1`.

The planner has four ordered phases:

1. derive a canonical planning input and repository size class without
   executing project code;
2. create one mandatory baseline for every detected language family;
3. discover bounded single-axis alternatives and rank them by declared intent
   and additional static coverage;
4. select up to the effective budget, then emit the selected, omitted, and
   policy-excluded ledger in canonical order.

The default planner never enumerates a target × feature × mode × environment
Cartesian product. Every automatic alternative differs from its language
baseline in exactly one axis. A combination of two or more non-baseline axis
choices requires an explicit selection file.

This is a planning contract, not an implicit activation of new CLI flags. The
future CLI and configuration fields described below do not exist until their
staged implementation lands. Existing schema v1 configuration continues to
produce its current one-selection-per-adapter behavior.

## Canonical planning input

The selection identity is the canonical JSON digest of:

- `contract_version=default-profile-selection-v1`;
- normalized repository source/manifest/config/lock inventory and its digest;
- detected language families, packages, build units, target/feature/tag and
  environment declarations;
- exact adapter, parser, protocol, and toolchain compatibility identities;
- the attested Rust and Go host target used by the safe backend when no single
  repository default target exists;
- normalized tracked profile configuration and an explicit selection-file
  digest, when present;
- planner limit/version values and supported-axis capability set.

Absolute checkout/cache/tool paths, directory iteration order, locale, clock,
mtime, inode, process ID, scan ID, unallowlisted environment values, CI
detection, terminal state, network availability, and previous scan results are
not planning input.

“Same input” means the same canonical repository inventory, compatibility
unit, host-target context, tracked selection data, and planner limits. Two
checkouts with that same input must produce byte-identical candidate IDs,
selection ranks, selected/omitted sets, reasons, and canonical output. A
different attested host target is a different input and must be visible in the
plan instead of being hidden as nondeterminism.

Input discovery follows the normal safe inventory boundary: regular files
only, repository-relative canonical locators, no out-of-root symlink follow,
bounded bytes/files/depth, no project config/module execution, and no network.
Dynamic configuration is ledgered and never guessed.

## Repository size and budget

The size classifier uses two values derived before language workers start:

- `relevant_source_files`: admitted Rust, Go, Web, schema, generated-source,
  and supported framework source files after canonical ignore/confinement;
- `build_units`: statically declared Rust package targets, Go package variants,
  Web workspace packages, and detected framework environment roots after
  canonical deduplication.

A repository belongs to a class only when both limits in that row are met. If
either value exceeds a row, classification continues to the next row.

| Repository class | Relevant source files | Build units | Default total profile cap |
| --- | ---: | ---: | ---: |
| `tiny` | `<= 1,000` | `<= 25` | `16` |
| `small` | `<= 10,000` | `<= 100` | `10` |
| `medium` | `<= 50,000` | `<= 500` | `6` |
| `large` | otherwise within inventory limits | otherwise within inventory limits | `4` |

The cap is total selected safe root profiles, including mandatory baselines.
Rust, Go, and Web currently require at most three baselines, so the large
budget preserves one for every detected family. Adding a fourth independently
executed language family is compatible; adding a fifth requires a new planner
contract or a raised large-repository minimum before that adapter can be a
default.

The hard cap is `32` selected root profiles for auto and explicit safe scan.
Automatic discovery also has a hard cap of `256` eligible candidates per
language and `512` in total. A set that exactly exhausts the admitted input at
a cap is complete. Evidence that another candidate exists beyond either cap is
an incomplete planning outcome with a fixed overflow reason; the planner never
truncates the candidate universe and then reports it as fully considered.

Profile count is the stable user-facing budget unit. Worker time, protocol
bytes, files, graph entities, parser depth, and query traversal retain their
independent lower-level hard limits. A larger profile budget never raises
those safety limits.

The future `--profile-budget N` overrides the size-class total cap only for
automatic planning. `N` must be `1..=32` and at least the number of mandatory
baselines. Lower or higher values are explicit planning input. It cannot be
combined with an explicit selection file.

## Mandatory language baselines

Baselines are selected before optional ranking. An unavailable or unsupported
baseline remains selected with its normal coverage failure; the planner does
not replace it with a superficially successful alternative.

### Rust

The Rust baseline is:

- `mode=check`;
- exactly one statically valid repository default target when one is declared,
  otherwise the attested worker host target;
- Cargo default-feature closure for the selected workspace packages;
- normal library/binary targets plus the manifest target inventory needed to
  account for skipped test/example/bench/build/proc-macro boundaries;
- pinned safe HIR backend and bundled-sysroot status from the compatibility
  context.

If repository configuration declares multiple default targets, the attested
host is the baseline and every declared target becomes a separate optional
target candidate. `--all-features` is never an automatic baseline or
alternative.

### Go

The Go baseline is:

- attested Go host `GOOS/GOARCH`;
- no user build tags;
- `CGO_ENABLED=0`;
- normal, internal-test, and external-test package variants represented by the
  existing safe package model;
- `go_call_graph=rta-cha`;
- the canonical offline dependency snapshot status/fingerprint.

The planner does not enable cgo, VTA, a cross compiler, or a user tag merely
because the source mentions it. cgo stays a ledgered native boundary in safe
scan; executable/link evidence remains explicit-consent build work.

### Web and frameworks

The Web baseline is the current production semantic profile with canonical
`browser + server` environments, the bundled TypeScript compiler, neutral
Bundler resolution conditions, and statically detected framework capabilities.
Frameworks attach their capabilities to this profile; one profile is not
created per detected framework.

`edge`, `worker`, development, and test alternatives are optional only when
supported static source/manifest/framework declarations prove that the
environment exists. Dynamic config is not executed to create a candidate.

### Cross-language, build, and runtime profiles

Cross-language format capabilities attach to the compatible selected language
profile set according to `cross-language-contract-v1`; they do not multiply
the root profile count. Build profiles are never auto-selected because they
require `--build --allow-project-code`. Runtime profiles exist only after a
validated trace is supplied. Neither can consume an auto safe-profile slot or
be used to fill an omitted safe profile.

## Automatic candidate generation

After baselines, each language may emit only the following single-axis
alternatives:

| Language | Allowed automatic alternative | Baseline axes retained |
| --- | --- | --- |
| Rust | one statically declared target; `mode=test` when test/dev targets exist; no-default feature closure; one root feature and its manifest closure | all axes except target, mode, or feature set respectively |
| Go | one statically evidenced GOOS/GOARCH pair; one source-declared user build tag | all axes except platform or tag respectively; cgo remains off and call graph remains RTA/CHA |
| Web | one statically evidenced `edge` or `worker` environment; one development or test environment | toolchain/package/framework inputs and all axes except environment respectively |

Rust feature candidates are computed from manifest data only. Features are
sorted by normalized package locator and feature name; optional dependency
closures are canonical. The planner does not assume additivity, pair features,
or synthesize all-features. Go platform candidates require a valid filename or
`//go:build` constraint; arbitrary strings are not platform evidence. A tag
candidate must occur in a parsed build expression and cannot be a toolchain
release/platform tag. Web candidates require recognized source/framework
roles; package-export branches remain ordered conditions inside a profile
rather than independent Boolean candidates.

Every candidate has:

- a stable candidate/profile identity;
- exactly one `baseline_profile_id`;
- one changed axis and canonical value;
- declaration provenance and complete repository-relative evidence;
- statically estimated newly covered files and conditional dependency
  occurrences;
- bounded unsupported/dynamic reasons known before execution.

The planner first bounds and validates candidate records, then deduplicates by
canonical profile identity. It never partially retains a malformed candidate.

## Ranking and canonical selection

All baselines are selected first. Optional selection then uses a deterministic
greedy set-cover ranking. After each selection, `new_files` and
`new_dependency_occurrences` are recomputed against the union already covered.
The next candidate is the minimum lexicographic tuple:

```text
(
  declaration_tier ascending,
  new_dependency_occurrences descending,
  new_files descending,
  dimension_priority ascending,
  language_priority ascending,
  canonical_profile_id UTF-8 bytes ascending
)
```

The fixed tiers are:

1. `0`: a normalized tracked `.depgraph.toml` axis declaration;
2. `1`: a target/environment alternative that covers otherwise inactive
   source or dependency declarations;
3. `2`: a test/development mode with repository test/dev evidence;
4. `3`: an individual Rust feature or Go user tag.

Dimension priority is `target=0`, `environment=1`, `mode=2`,
`feature_or_tag=3`. Language priority is `rust=0`, `go=1`, `web=2`. These
values break exact coverage ties only; they do not bypass baseline reservation
or a higher declaration/coverage rank.

Selection rank is retained for explain output. The persisted and JSON selected,
omitted, and candidate arrays are independently sorted by canonical profile ID
using UTF-8 byte order. Worker launch order cannot affect the plan or final
graph order.

Tracked schema-v1 profile fields are normalized into tier-0 single-axis
candidates where possible. A legacy configuration that changes multiple axes
continues to describe its current single adapter selection during migration;
the new planner does not silently split it into combinations. The schema
migration must show the exact v1-to-v2 interpretation in `profiles plan`.

## Explicit override contract

The future CLI is:

```text
depgraph profiles plan PATH [--profile-budget N] [--json]
depgraph scan PATH [--profile-budget N]
depgraph scan PATH --profiles-file FILE
```

`profiles plan` is read-only, uses the same safe inventory, and does not launch
language workers. Human and JSON output show the contract/version, planning
input digest, compatibility/host context, repository class/counts, effective
cap, every baseline/candidate, rank inputs, selected/omitted set, policy
exclusions, discovery overflow, and completeness.

`--profiles-file` is a strict JSON document with
`contract_version=default-profile-selection-v1` and a `profiles` array. Every
entry fully specifies its language-specific axes; unknown/missing fields,
duplicate canonical profiles, unknown language/capability, unnormalized
feature/tag/environment lists, an unavailable package/target, build/runtime
phase, or a count above `32` is a config/usage error before worker launch or
store mutation. File order has no semantic meaning. The core validates and
canonical-sorts the complete set.

An explicit file replaces auto selection and all legacy profile-axis fields.
It cannot be combined with `--profile-budget`. The core does not truncate it,
fill missing languages, add baselines, retry with auto selection, or fall back
to schema-v1 defaults. Its content digest, not its absolute path, enters
planning identity. The input must be a bounded UTF-8 regular file; symlinks,
special files, oversized input, secret-shaped fields, and unknown schema
versions fail closed without echoing raw content.

An explicit selection is complete relative to the exact requested set. It does
not claim that unrequested repository profiles do not exist, and the plan/store
retain `selection_mode=explicit`.

## Omission, truncation, and CLI semantics

Automatic planning records:

- `eligible_profile_count`, `selected_profile_count`,
  `omitted_profile_count`;
- `candidate_discovery_complete` and per-language discovered/overflow counts;
- selected/omitted profile IDs and rank evidence;
- policy-excluded axes/combinations;
- `selection_complete`, repository class, effective/hard cap, and planner
  contract/version.

Every eligible but unselected candidate receives
`default_profile_budget_exhausted`. Candidate discovery overflow receives
`default_profile_candidate_limit_exceeded`. A declared dynamic/unsupported axis
receives a bounded format-specific reason. Combinations are never materialized,
but each detected dimension reports
`default_profile_combination_requires_explicit_selection`; when a bounded
combination count can be calculated without enumeration it is included as a
count.

`doctor --json` and human `doctor` expose the same canonical plan summary,
omitted candidates, evidence, and remediation (`--profile-budget` or
`--profiles-file`). Normal scan output prints:

```text
profiles: 10 selected / 14 eligible; 4 omitted by small-repository budget 10
```

Budget omission or discovery overflow sets aggregate
`default_profile_matrix_complete=false`. Selected profiles retain their own
syntax/semantic completeness, and a non-strict scan may promote a completed
snapshot scoped to the selected set, but it must print a warning and cannot
claim a complete default matrix. `--strict` treats an incomplete default matrix
as policy exit `1` and does not promote it. An explicit complete request has no
auto omissions and may set the aggregate selection status to
`explicit-complete`.

Failure behavior is:

| Condition | Exit/result |
| --- | --- |
| auto budget omission | exit `0` with warning and completed selected-scope snapshot; exit `1` under `--strict` |
| candidate discovery overflow | same as auto omission, with overflow reason |
| invalid budget or explicit file | exit `2` before workers/store mutation |
| unsafe selection input | exit `4`, bounded non-echoing diagnostic |
| selected worker/toolchain/protocol failure | existing exit `3`; no alternate-profile retry |

No mode reports budget omission only on stderr while emitting a complete JSON
claim. Human, JSON, coverage, doctor, snapshot, and audit representations derive
from the same stored plan.

## Security and resource boundary

| Threat | Required control |
| --- | --- |
| Feature/target/tag/environment explosion | Baselines plus single-axis candidates only; 256/language, 512 discovery, 32 selection hard caps |
| Host- or order-dependent selection | Attested host is explicit input; canonical parse/dedup/rank/sort; no locale/iteration/time/CI inputs |
| Project code during planning | Static bounded inventory only; no Cargo build, build script, proc macro, JS config/plugin, cgo compiler, or generator |
| Malicious explicit selection | Strict versioned JSON, bounded regular file, unknown-field rejection, canonical axis validation, no raw-content diagnostic |
| Silent coverage loss | Per-candidate omission/overflow ledger, aggregate incomplete state, doctor/remediation, strict failure |
| Budget used to raise lower safety limits | Profile cap is independent; parser/worker/protocol/store/query limits never increase |
| Cross-profile evidence confusion | Exact selected profile identity on every result; no result reuse across incompatible axes |
| Failure-driven substitution | No retry with a cheaper/different profile and no promotion of an unrequested baseline |

The planner does not read system/project executables to discover target support.
Capabilities come from the already attested adapter/toolchain contract.
Malformed manifest/config input may reduce candidate knowledge only with a
coverage reason; it cannot produce a complete plan.

## Staged implementation

Each row is one independently reviewable one-to-three-day follow-up Issue.

| Order | Slice | Estimate | Depends on | Exit criterion |
| ---: | --- | --- | --- | --- |
| 1 | Selection DTO/schema, canonical IDs, ledger, validator, and golden fixture | Implemented in #183 | This ADR | Rust/core/schema accept only canonical closed plans |
| 2 | Safe inventory size classifier, caps, candidate bounds, and plan digest | Implemented in #184 | 1 | Boundary fixtures select tiny/small/medium/large deterministically |
| 3 | Rust baseline and single-axis target/mode/feature candidates | 2-3 days | 1-2 | Default/no-default/feature/target/test fixtures never form a product |
| 4 | Go baseline and platform/tag candidates | 2-3 days | 1-2 | GOOS/GOARCH/tag fixtures are deterministic; cgo/VTA remain non-auto |
| 5 | Web/framework baseline and environment candidates | 2-3 days | 1-2 | browser/server baseline and evidenced edge/worker/dev/test alternatives validate |
| 6 | Greedy ranking, budget omission, aggregate coverage, doctor, and strict behavior | 2-3 days | 3-5 | Reordered polyglot fixture yields byte-identical selected/omitted output |
| 7 | `profiles plan`, `--profile-budget`, strict profiles-file schema, and v1 config migration | 2-3 days | 6 | Explicit requests are all-or-error and auto planning is explainable |
| 8 | Cache/incremental binding and five-target package/release gate | 2-3 days | 7 | Plan digest invalidates correctly; Linux/macOS/Windows package tests pass |

## Acceptance matrix

| Case | Required result |
| --- | --- |
| Empty repository | Zero candidates/selected profiles, complete canonical plan |
| Rust + Go + Web repository under large budget | All three baselines selected before every optional candidate |
| Same repository/config in another checkout | Byte-identical plan IDs, ranks, selected/omitted arrays, and reasons |
| Reordered manifests/features/tags/environments | Same canonical plan and worker launch set |
| At each file/build-unit size boundary | Exact documented class and total cap; crossing either dimension selects the larger class |
| Many features, targets, tags, and environments | Baselines plus single-axis candidates only; no Cartesian product |
| More eligible candidates than size budget | Stable highest-ranked set; every omitted candidate has `default_profile_budget_exhausted` |
| More than discovery hard cap | Fixed overflow reason, incomplete matrix, no complete claim |
| Equal coverage candidates | Fixed dimension/language/profile-ID tie-break, independent of discovery order |
| Explicit multi-axis combination | Accepted only through a valid profiles file and retained exactly |
| Explicit set above 32 or with unsupported target | Exit `2` before worker/store activity; no partial execution or auto fallback |
| Auto omission in normal/strict scan | Normal exit `0` warning and selected-scope snapshot; strict exit `1` and non-promotion |
| Worker failure for a selected profile | Exit `3`; never substitute an omitted or baseline profile |
| Planning input containing symlink/dynamic config/secret field | Confined incomplete reason or security exit without content echo |
| Build/runtime evidence present | Never added to safe default profiles or used to increase the budget |

The representative polyglot fixture contains:

- Rust default/no-default/root features, mutually exclusive-looking feature
  names, test targets, one repository target and multiple target-specific
  dependencies;
- Go host and non-host file suffixes, compound build constraints, user tags,
  test variants, and a cgo boundary;
- Web browser/server code, detected edge/worker roles, ordered package exports,
  and Next/Astro/TanStack static framework evidence.

Tests run the fixture with reordered input, two checkouts, every repository
class boundary, budgets from baseline count through `32`, candidate overflow,
invalid explicit files, worker failure, and strict/non-strict CLI behavior.

## Options considered

### Full Cartesian product

Rejected. Most combinations are meaningless or contradictory, and work grows
multiplicatively before any evidence shows that a combination is useful.

### Only one host profile per language

Rejected as the long-term default. It is bounded but silently misses
repository-evidenced target, test, tag, and Web environment branches.

### Enable all Rust features and all Go tags

Rejected. Cargo does not guarantee mutually compatible features, Go tags do
not have an “all” semantic, and both choices can activate configurations no
user runs.

### Time-based adaptive exploration

Rejected. Runner speed, load, cache warmth, and scheduling would change the
selected set. Fixed inventory classes and profile counts are explainable and
deterministic.

### Silently truncate explicit requests

Rejected. Explicit selection is a user contract. An infeasible request fails
before execution and tells the user which cap or capability is violated.

### Treat omitted auto candidates as complete

Rejected. The selected graph is useful and may be stored, but coverage and
doctor must distinguish selected-profile completeness from default-matrix
completeness.

## Consequences

Default scans remain useful across all detected language families and gain
additional profiles where static evidence predicts new coverage. Planning cost
and selected work are bounded independently of the theoretical matrix.

The conservative single-axis policy will miss dependencies that appear only
under a combination of non-default axes. That is intentional and visible:
doctor points to the explicit selection mechanism, while a versioned profiles
file can request the exact combination without making every default scan pay
for it.

The planner adds new stored/audit metadata and a future config migration. Until
those implementation slices land, existing schema-v1 behavior remains the
product contract and this ADR is the normative gate for changing it.

## References

- Cargo features: https://doc.rust-lang.org/cargo/reference/features.html
- Cargo dependency and feature resolver:
  https://doc.rust-lang.org/cargo/reference/resolver.html
- Go build constraints: https://pkg.go.dev/cmd/go#hdr-Build_constraints
- Go cgo command: https://pkg.go.dev/cmd/cgo
- Node.js package exports and conditions:
  https://nodejs.org/api/packages.html
- TypeScript module resolution:
  https://www.typescriptlang.org/docs/handbook/modules/reference
