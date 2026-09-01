# ADR: Explainable code-health finding contract

- Status: Accepted
- Date: 2026-08-26
- Decision ID: `PROJ-ARC-001-ADR-009`
- Issue: `PROJ-ARC-004` / #423
- Contract: `depgraph-health-finding-v1`

## Context

`depgraph` already stores a semantic dependency graph, coverage ledger,
unresolved sites, profile matrix, completed snapshots, and optional runtime
evidence. Users and Agent hosts still cannot ask the next questions through a
shared, versioned contract:

- which files, public exports, types, or declared dependencies appear unused;
- whether a Git change introduced a new cycle, boundary violation, public API
  change, or wide blast radius;
- which nodes are graph hotspots under a deterministic score.

Those answers must stay explainable. Incomplete coverage, public surface,
dynamic loading, candidates, unresolved sites, unanalyzed profiles, and
snapshot-external input must not be silently promoted to `confirmed`. CLI and
MCP must share one read-only service so finding IDs and collection digests
match.

Dedicated commands remain the product surface. This ADR does not add
auto-deletion, clone/duplication detection, complexity metrics, or a second
MCP-only analyzer.

## Decision

Adopt `depgraph-health-finding-v1` as the single compatibility unit for every
code-health API. CLI (`health`, `health list`, `health show`, `cleanup`,
`audit`, `hotspots`) and MCP (`health_summary_get`, `health_findings_list`,
`health_finding_get`, `health_audit_get`, `health_hotspots_list`) call the same
`DepgraphService` methods and serialize the same `HealthFinding` values.

No second finding DTO family is introduced. MCP remains on
`depgraph-mcp-tools-v1`; this contract is the domain unit those tools project.

### Finding schema

A finding is a closed record:

| Field | Role |
| --- | --- |
| `id` | stable finding ID (`finding:sha256:<hex>`) |
| `kind` | closed kebab-case kind name |
| `severity` | `error` / `warning` / `info` |
| `confidence` | `confirmed` / `probable` / `indeterminate` |
| `subject_id` / `subject_kind` | target graph node |
| `location` | repository-relative path and optional source span |
| `profile_scope` | present only for explicitly profile-scoped findings |
| `reason` | human-readable explanation (not an ID input) |
| `blockers` | why `confirmed` is refused or a comparison degraded |
| `evidence` | closed references to edges, sites, or evidence rows |
| `remediations` | next-step hints, never automatic edits |
| `suppressions` | recorded suppressions that matched this finding |
| `analyzer_version` | independent analyzer field |
| `fingerprint` | content digest; excluded from its own payload |

`health_summary` aggregates snapshot-scoped kinds only. Audit and hotspot
findings are returned only by `health_audit` / `health_hotspots`, already
detail-expanded.

### Kind classification

| Scope | Kinds | Recalculation input |
| --- | --- | --- |
| snapshot-scoped | `unused-file`, `unused-export`, `unused-type`, `unused-dependency`, `test-only-dependency`, `manifest-mismatch` | one pinned snapshot plus the request-fixed manifest digest |
| input-scoped | `new-cycle`, `new-boundary-violation`, `public-api-change`, `wide-blast-radius`, `hotspot` | snapshot pair and/or changed OID, churn window, weights |

`health_findings` and `health_finding_get` serve snapshot-scoped kinds only.
An input-scoped finding ID is a deterministic `InvalidInput` with remediation
pointing at `health_audit` / `health_hotspots`.

### Stable finding ID

Inputs, in this order, are hashed as canonical JSON:

1. contract version `depgraph-health-finding-v1`
2. kind name
3. subject node stable ID
4. profile scope discriminator, or JSON `null`
5. structural witness key (for example manifest relative path plus dependency
   name, or the canonical cycle rotation)

Excluded: analyzer version, severity, confidence, reason text, evidence count,
blockers, remediations, fingerprint, collection digest, and baseline
transition.

Compatible analyzer improvements keep the kind name and therefore the ID.
Incompatible kind semantics rename the kind (`unused-export-v2`). During
migration the old kind remains readable in existing baselines; there is no
automatic rewrite and no coexistence window that maps old IDs to new IDs.

### Fingerprint

Fingerprint is `sha256:<hex>` of the finding's canonical JSON after removing
`fingerprint`, `collection_digest`, and any baseline transition field. Those
derived fields never enter the hashed payload.

### Collection digest

`collection:sha256:<hex>` over canonical JSON of:

- contract version
- sorted finding IDs
- input identity: snapshot ID (audit uses the before/after pair), optional
  manifest digest, changed OID, churn window, and hotspot weights
- audit's pinned policy configuration digest

### Baseline transitions

A baseline file stores ID, fingerprint, severity, confidence, and a resolved
flag. Application order:

1. match current findings to baseline by stable ID
2. classify the transition
3. apply severity / confidence thresholds
4. classify the process exit

| Transition | Condition | Default gate |
| --- | --- | --- |
| `new` | ID absent from baseline | violation when the finding meets threshold |
| `changed` | ID matches, fingerprint differs, actionability did not rise | pass |
| `regressed` | ID matches and actionability rose | violation when the current finding meets threshold |
| `resolved` | baseline ID is absent from the current result | pass; record resolved |
| `reappeared` | a resolved baseline ID appears again | violation when the finding meets threshold |

Actionability rises when confidence moves `indeterminate → probable →
confirmed`, when severity moves `info → warning → error`, or when blockers
that had prevented `confirmed` disappear and confidence becomes `confirmed`.
`indeterminate → confirmed` is therefore `regressed` and cannot be treated as
a silent `changed`.

Default thresholds: severity `warning` and confidence `probable`. Default
violation transitions: `new`, `regressed`, `reappeared`. The set is
configurable but cannot invent a sixth transition.

### Confidence promotion

Judgement uses the union of every applicable profile in the snapshot.

- Incoming-edge-zero means every applicable profile has zero usage edges.
- Applicable profiles come from the profile matrix. A profile that could own
  the subject but is missing from the snapshot adds `profile-not-analyzed`.
- `confirmed` also requires every applicable profile to be
  `semantic-complete` or stronger.

A finding stays at `probable` when usage is absent and every hard blocker is
absent, but completeness is only `syntax-complete`. Any hard blocker forces
`indeterminate`.

Hard blockers: `public-surface`, `entry-point`, `dynamic-loading`,
`candidate`, `unresolved`, `heuristic-precision`, `overapprox-precision`,
`coverage-omission`, `generated-artifact`, `profile-not-analyzed`,
`incomplete-coverage`, `manifest-drift`, `insufficient-surface-evidence`,
`missing-base-snapshot`, `base-snapshot-mismatch`, `worktree-dirty`,
`incomparable-profile-matrix`, `incomparable-coverage`,
`incomparable-policy`, `incomparable-contract`.

Score-layer blockers (`churn-unavailable`, `runtime-not-observed`) degrade
that layer to zero and do not, by themselves, invent a `confirmed` unused
finding.

Rejected alternatives for promotion:

- treat a single profile's incoming-edge-zero as `confirmed`
- treat `candidates` / `unresolved` as proof of use or as proof of unused
- skip coverage omission because a later profile looks complete
- promote on heuristic or overapprox edges alone

### Suppression

A suppression is an explicit baseline or policy record keyed by stable finding
ID (optionally plus a human ticket). It never deletes source. It is recorded
on the finding and does not rewrite the ID. Suppressions do not convert
`indeterminate` into `confirmed`.

### Snapshot provenance

The current store already records optional `source_revision` on scans and
completed snapshots. That field is the Git HEAD OID (`git rev-parse --verify
HEAD`) when Git is available.

This ADR keeps store schema `17`. It does not add a worktree digest column.
Audit treats `source_revision` as the commit OID when present, looks up a
base snapshot by that field plus optional `--base-snapshot`, and live-checks
worktree dirtiness at request start. Missing `source_revision` is
`missing-base-snapshot` (or prevents OID binding for `--changed`).

Rejected: stuffing a worktree hash into `source_revision` (the field is an
OID today); bumping the store schema only to store a dirty bit that can be
observed live.

### Manifest identity

Snapshot sites (`cargo_dependency`, `module_requirement`,
`package_dependency` and peer/optional variants) are the primary unused
dependency input. Manifest file bytes are not stored. When a live fallback
read is required, the service reads each confined manifest once at request
start, binds the sha256, and compares it to any snapshot file hash that
exists. A missing snapshot hash is not evidence of equality: it degrades in
the same way as a mismatched or unavailable manifest. Drift adds
`manifest-drift` and forces `indeterminate`. Reads use the repository's
bounded, no-follow file primitive so symlink components and read-time swaps
fail closed. The digest enters the collection digest and pagination cursor.

### Audit snapshot pair

`health_audit` treats `--changed` as the comparison base, resolves it together
with HEAD and their merge base, and reads the normalized
`merge-base(--changed, HEAD)..HEAD` committed/worktree/untracked changed set
exactly once at request start. `changed_oid` identifies that request-start HEAD,
not the comparison-base ref. It then pins after (current snapshot) and before (explicit selector or
deterministic `source_revision == merge-base` lookup) in one read scope.
Comparison functions accept only that pinned scope; they never rerun Git.
The before/after role order and a canonical changed-set digest bind the result,
collection digest, and cursor.

Default mismatch policy is degrade, not reject:

- explicit base whose `source_revision` ≠ base OID → `base-snapshot-mismatch`
- changed-set worktree/untracked sources, or after snapshot revision unequal
  to the request-start HEAD → `worktree-dirty`
- missing before snapshot → blast radius remains evaluable; cycle / boundary /
  API new checks return `indeterminate` placeholders with
  `missing-base-snapshot`
- incomparable profile matrix, completeness retreat, or contract mismatch →
  the affected new-check degrades

Policy configuration is read once when the audit scope opens. If a comparable
before snapshot exists, the policy evaluator runs against the pinned before /
after pair at that point; the resulting boundary violation IDs are retained in
the scope and never recomputed while the scope is consumed. A boundary audit
finding therefore uses the evaluator's stable `PolicyViolation.id`, not a
diagnostic code or message substring. Audits do not claim historical policy
comparability: policy provenance and policy-change comparison remain outside
this contract and are reserved for #439. When no boundary policy rule is
configured, the boundary ID set is empty; audit does not infer a boundary or
blocker from graph diagnostics. The public graph-only analyzer compatibility
wrapper therefore always passes an empty boundary-ID set unless the service
audit path explicitly supplies evaluator output.

Before/after correspondence uses the policy rule ID, source/target IDs,
profile, and ordered dependency node path. It deliberately excludes edge IDs
and evidence positions because a dependency-site line move can change those
authenticated `PolicyViolation.id` inputs without introducing a new boundary
violation. Correspondence first preserves exact before/after
`PolicyViolation.id` matches, then pairs remaining occurrences by the semantic
key above. Multiplicity is preserved, so adding another violation on the same
node path still yields one new finding whose subject is an after-side
`PolicyViolation.id`.

When all raw IDs in a semantic group change at the same time as a parallel
occurrence is added, neither `PolicyResult` contains movement provenance that
can distinguish the physical moved and added sites. The finding therefore
uses a deterministic surplus after-side ID as the evaluator representative of
the increased multiplicity; it does not claim that representative is the
source-level added occurrence. Consumers must use the semantic key and count
increase for newness, rather than infer line-level causality from that ID.

Canonical identities:

- cycle: node-ID rotation starting at the lexicographically smallest ID
- boundary: existing policy violation stable ID
- public API: existing `public_api_change` plus snapshot symbol/signature
  diff restricted to classified public surface
- blast radius: reverse `impact()` over the changed set; a
  `wide-blast-radius` finding is emitted only when the set difference between
  impacted nodes and changed subjects contains at least two nodes. This fixed
  v1 threshold is not request-configurable; a future contract revision may
  introduce an explicitly versioned override.

### Hotspot score

All arithmetic uses integer basis points in `0..=10_000`. Floating point is
forbidden.

Each layer (fan-in, fan-out, reverse-impact size, Git churn, runtime
observation) is rank-normalized: sort unique values ascending, assign the
same rank to ties, map `rank * 10_000 / max_rank`, or `0` when `max_rank`
is `0`.

Default weights, each `0..=10_000` and summing to `10_000`:

| Layer | Default |
| --- | ---: |
| fan-in | `2500` |
| fan-out | `1500` |
| reverse impact | `2500` |
| Git churn | `2000` |
| runtime | `1500` |

Request weights outside `0..=10_000` or whose sum exceeds `10_000` are
`InvalidInput`. A missing layer contributes `0` and does **not** renormalize
the remaining weights. Tie-break: score descending, then subject node ID
ascending. The returned finding order preserves that rank, and each finding
states both raw layer values and normalized basis-point values.

Default churn window: at most `512` commits from a request-start OID, commit
OID order, optional canonical repository-relative path filter. Git output and
each per-commit query are byte-bounded and cancellable. Any partial Git failure
discards the partial counts, records `churn-unavailable`, and uses churn `0`.

### CLI names and exit codes

| CLI | Service | MCP |
| --- | --- | --- |
| `depgraph health` | `health_summary` | `health_summary_get` |
| `depgraph health list` / `depgraph cleanup --kind` | `health_findings` | `health_findings_list` |
| `depgraph health show <ID>` | `health_finding_get` | `health_finding_get` |
| `depgraph audit --changed <GIT_REF>` | `health_audit` | `health_audit_get` |
| `depgraph hotspots` | `health_hotspots` | `health_hotspots_list` |

Exit codes stay on the existing 0–4 contract:

| Code | Health meaning |
| ---: | --- |
| `0` | complete result and no configured gate violation |
| `1` | baseline gate violation (`new` / `regressed` / `reappeared` at threshold) |
| `2` | invalid input, unknown snapshot-scoped lookup, input-scoped ID on `show` |
| `3` | store / integrity / internal failure |
| `4` | path confinement or other security policy |

`health` / `cleanup` never edit the source tree.

## Scope boundary

Included: the five read-only APIs, the kind table above, baseline files for
CI, MCP READ tools, and packaging of those tools.

Excluded: source mutation, treating incomplete evidence as `confirmed`,
clone/duplication/complexity/feature-flag detectors, relaxing safe-scan or
read-only MCP defaults, and a CLI-independent MCP analyzer.

## Options considered

### Separate contracts for unused, audit, and hotspot

Rejected. Parity and baseline comparison require one ID space and one
fingerprint rule.

### Use fingerprint as the baseline key

Rejected. Analyzer wording or evidence-count changes would churn every ID and
explode `new` violations.

### Treat fingerprint-only diffs as always existing

Rejected. Confidence or severity upgrades would hide regressions.

### Import a generic issue-tracker schema

Rejected. The product needs graph-specific blockers, snapshot pinning, and
byte-deterministic digests.

### Bump store schema to store worktree digests

Rejected for v1. `source_revision` already holds the HEAD OID. Dirty
worktrees are observable live. A schema 18 bump remains available if a later
issue needs an attested worktree digest inside the snapshot identity.

## Consequences

Users and Agent hosts get explainable unused, audit, and hotspot findings
with stable IDs suitable for CI baselines. Promotion is conservative: missing
profiles, public surface, and incomplete coverage stay visible as blockers.

The contract cannot answer questions that need source mutation or
unbounded language-specific visibility data the graph does not store. Those
findings remain `indeterminate` with
`insufficient-surface-evidence` rather than guessed `confirmed`.

## References

- [Semantic Dependency Graph CLI system design](arch-dependency-graph-cli-system-design.md)
- [MCP Agent Tools](arch-mcp-agent-tools.md)
- Issue #423
