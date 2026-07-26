# ADR: Bounded read-only graph query language

- Status: Accepted
- Date: 2026-07-25
- Decision ID: `PROJ-ARC-001-ADR-005`
- Issue: `PROJ-ARC-001-TASK-084` / #152
- Contract: `bounded-graph-query-v1`

## Context

The current CLI deliberately provides dedicated commands for common questions:

- `deps` and `dependents` traverse from one exact selector;
- `why` returns one deterministic shortest path between two selectors;
- `impact` performs bounded reverse traversal from one selector or a Git
  changed set;
- `cycles` and `unresolved` return fixed analyses;
- `diff` and `policy` compare two completed snapshots with domain-specific
  semantics.

Those commands are safer and easier to document than a general language. They
should remain the preferred interface for their existing use cases. They do
not, however, compose selection, traversal, profile, phase, condition, and
evidence predicates into one read-only operation.

The missing cases are narrow but recurring:

| Use case | Why the dedicated commands are insufficient |
| --- | --- |
| Find every public route or symbol that reaches a selected external system | `deps` accepts one selector rather than a typed set of starting nodes |
| Find cross-kind paths such as route → component → symbol → package | `why` requires both endpoints and cannot select endpoint sets by type |
| Triage paths supported by runtime or build evidence from a particular extractor or repository path | existing traversal filters phase/profile/session/environment, but not typed evidence fields |
| Compare semantic/build/runtime paths across selected profiles inside one completed snapshot | command flags can filter exact profiles but cannot express endpoint and path predicates together |
| Explore a prospective architecture rule before committing it to policy configuration | `policy` evaluates the versioned rule contract rather than an ad hoc read-only pattern |

These cases do not require mutations, arbitrary recursion, user-defined
functions, joins across snapshots, or a complete implementation of Cypher,
GQL, SQL, Datalog, or CodeQL. Importing one of those languages would also
import a much larger grammar, execution surface, and denial-of-service risk
than this local-first CLI needs.

## Decision

Adopt `bounded-graph-query-v1` as an opt-in, read-only query language over one
immutable completed snapshot.

The MVP is intentionally a small graph-pattern language:

- one linear directed pattern;
- one source node variable, one canonical path variable, and one target node
  variable;
- an explicit path depth range with a hard upper bound;
- typed predicates over fixed Node, Edge, Site, Evidence, and Path fields;
- exact profile/phase/condition and bounded evidence filters;
- explicit projection and mandatory result limit;
- parse, type-check, plan, and cost admission before execution;
- canonical shortest-path semantics instead of enumerating every matching
  path.

Existing dedicated commands remain stable and preferred. The query language is
not a replacement for `deps`, `dependents`, `why`, `impact`, `cycles`,
`unresolved`, `diff`, `policy`, or export. The implementation may internally
reuse their canonical selector, filtering, traversal, evidence, and output
primitives only after the new planner applies the stricter contract below.

This ADR defines a future capability. It does not activate a `query` command in
the current release by documentation alone.

## Scope boundary

### Included in v1

- a completed snapshot selected through the existing global `--store` and
  `--scan-id` behavior;
- forward or reverse traversal;
- one edge-kind set and a depth range `1..=8`;
- source/target node-kind constraints;
- predicates joined by `AND`, `OR`, and `NOT`;
- scalar comparison, membership, and normalized string prefix;
- `EVERY` edge predicate over a path;
- `SOME` site or evidence predicate associated with a path;
- canonical row projection, ordering, deduplication, and limit;
- human, canonical JSON, and plan-explain output.

### Excluded from v1

- graph or store mutation, scan/build/runtime import, policy suppression, file
  output, and project-code execution;
- unbounded or user-defined recursion;
- multiple `MATCH` clauses, joins, subqueries, `UNION`, optional patterns,
  negated path existence, and cross-snapshot queries;
- arbitrary functions, arithmetic, aggregation, grouping, windowing, regex,
  glob, fuzzy search, full-text search, and dynamic property lookup;
- arbitrary JSON `properties`, evidence `detail`, adapter logs, raw build
  audit, raw runtime data, and secret-bearing input;
- all-path enumeration, repeated-edge walks, user-selected traversal
  algorithm, and unbounded shortest path;
- network, filesystem, environment, process, clock, locale, or VCS access from
  an expression.

A future feature must revise the contract and cost model before entering this
scope. It cannot be added as an untyped function or parser special case.

## Query input and CLI

The future CLI is:

```text
depgraph query --query QUERY [--json]
depgraph query --file FILE [--json]
depgraph query --query QUERY --explain [--json]
```

`--query` and `--file` conflict. The existing global `--store` and `--scan-id`
select one completed snapshot; no query-local snapshot identifier is accepted.
The command opens the store read-only and never requests a writer lock.

`--file` accepts one UTF-8 regular file of at most `64 KiB`. It rejects
symlinks, special files, path escape after normalization, size change during
read, invalid UTF-8, and a file outside the caller-selected repository
boundary. Query-file content is data, never a module or command. The absolute
input path is not part of query identity.

Command-line and file input share the same byte, token, string, nesting, and
AST limits. Diagnostics report a stable code, clause/token class, and
one-origin line/column plus byte offset. They never echo a string literal, raw
query line, absolute path, or nearby source text.

Before store access, the bounded lexer applies the existing credential-shape
policy to string literals. A recognized token, private-key, URL-userinfo, or
credential-assignment form is a security failure without value echo. This is
not a general content classifier: only versioned release redaction shapes are
rejected, and the diagnostic identifies that policy version rather than the
matched text.

## MVP grammar

Keywords are ASCII and case-insensitive. Identifiers are ASCII
`[A-Za-z_][A-Za-z0-9_]{0,63}` and case-sensitive. String literals are JSON
strings with valid Unicode scalar values. Integers are canonical unsigned
decimal without a sign or leading zero, except `0`.

The normative EBNF is:

```text
query          = match, [ where ], return, [ order_by ], limit, [ ";" ] ;
match          = "MATCH", path_var, "=", node, relationship, node ;
path_var       = identifier ;
node           = "(", identifier, [ ":", string ], ")" ;
relationship   = left_rel | right_rel ;
left_rel       = "<-", "[", kind_set, "*", depth, "]", "-" ;
right_rel      = "-", "[", kind_set, "*", depth, "]", "->" ;
kind_set       = string, { "|", string } ;
depth          = positive_uint, "..", positive_uint ;

where          = "WHERE", expression ;
expression     = or_term ;
or_term        = and_term, { "OR", and_term } ;
and_term       = not_term, { "AND", not_term } ;
not_term       = [ "NOT" ], primary ;
primary        = "(", expression, ")" | scalar_predicate
               | edge_quantifier | site_quantifier | evidence_quantifier ;
scalar_predicate
               = field, scalar_operator, literal
               | field, "IN", "[", literal, { ",", literal }, "]" ;
scalar_operator
               = "=" | "!=" | "<" | "<=" | ">" | ">="
               | "STARTS", "WITH" ;
edge_quantifier
               = "EVERY", identifier, "IN", "EDGES", "(", path_var, ")",
                 "SATISFIES", entity_expression ;
site_quantifier
               = "SOME", identifier, "IN", "SITES", "(", path_var, ")",
                 "SATISFIES", entity_expression ;
evidence_quantifier
               = "SOME", identifier, "IN", "EVIDENCE", "(", path_var, ")",
                 "SATISFIES", entity_expression ;
entity_expression
               = entity_term, { ( "AND" | "OR" ), entity_term } ;
entity_term    = [ "NOT" ], ( scalar_predicate
               | "(", entity_expression, ")" ) ;

return         = "RETURN", [ "DISTINCT" ], projection,
                 { ",", projection } ;
projection     = identifier | field ;
order_by       = "ORDER", "BY", order_item, { ",", order_item } ;
order_item     = projection, [ "ASC" | "DESC" ] ;
limit          = "LIMIT", positive_uint ;

field          = identifier, ".", identifier ;
literal        = string | uint | "true" | "false" | "null" ;
```

The parser accepts exactly one statement. Comments, escaped identifiers,
parameters, interpolation, semicolon-separated statements, and trailing
tokens are invalid. `LIMIT` is required and must be `1..=10,000`.

An example is:

```text
MATCH p = (source:"route")-["renders"|"calls"|"imports"*1..4]->(target:"external_system")
WHERE source.locator STARTS WITH "route:"
  AND EVERY edge IN EDGES(p) SATISFIES
      edge.phase IN ["semantic", "build", "runtime"]
      AND edge.profile_id IN ["profile-a", "profile-b"]
  AND SOME evidence IN EVIDENCE(p) SATISFIES
      evidence.kind IN ["build", "runtime"]
      AND evidence.path STARTS WITH "apps/web/"
RETURN DISTINCT source.id, target.id, p
ORDER BY source.id, target.id, p ASC
LIMIT 200
```

The quoted kind syntax reflects protocol 1.0's open string vocabulary. A kind
not present in the selected snapshot is a valid empty match, not an invitation
to load another adapter.

## Type system

The type checker binds exactly three top-level values:

| Binding | Type |
| --- | --- |
| first node identifier | `Node` |
| path identifier before `=` | `Path` |
| second node identifier | `Node` |

Quantifiers introduce one lexically scoped `Edge`, `Site`, or `Evidence`.
Bindings cannot shadow each other, keywords, or a top-level value. A
quantified binding is not visible in `RETURN` or `ORDER BY`.
Its `SATISFIES` body may reference only that introduced binding; it cannot
capture a Node, Path, or another quantified binding.

The closed v1 fields are:

| Type | Fields |
| --- | --- |
| `Node` | `id`, `kind`, `locator`, `display_name` as string |
| `Path` | `id` as string, `depth` as unsigned integer, `direction` as string |
| `Edge` | `id`, `kind`, `phase`, `environment`, `profile_id`, `resolution_status`, `precision`, `condition` as string; `generated` as Boolean |
| `Site` | `id`, `kind`, `specifier`, `profile_id`, `resolution_status`, `precision`, `condition`, `reason` as nullable string |
| `Evidence` | `owner_type`, `kind`, `extractor`, `extractor_version`, `path` as string; `start_line`, `start_column`, `end_line`, `end_column`, `ordinal` as unsigned integer |

`condition` is the existing canonical rendered condition, not raw JSON.
`Path.id` is available only in `RETURN` and `ORDER BY`; a `WHERE` predicate may
use `Path.depth` or `Path.direction` but cannot select by the witness digest.
This keeps path predicate evaluation inside the documented dominance state
instead of making an edge-order-dependent ID an untracked filter.
`SITES(p)` contains the distinct non-null sites referenced by path edges.
`EVIDENCE(p)` contains canonical evidence owned by those edges and associated
sites. It does not include node evidence, diagnostic properties, adapter logs,
or unrelated records.

`=` and `!=` require identical scalar types, except that a nullable field may
be compared with `null`. Ordering operators require two strings or two
unsigned integers. `STARTS WITH` requires strings, validates the right operand
as a normalized non-empty prefix, and is byte-prefix comparison over UTF-8; it
is not path traversal, glob, locale collation, or case folding. `IN` requires
`1..=64` unique literals of the field's scalar type in canonical order after
normalization.

Profile filtering uses exact `edge.profile_id` or `site.profile_id`.
Phase/status/precision filtering uses their fixed string values. Evidence
filtering cannot read arbitrary `properties` or `detail`; new safe fields
require a contract revision or an explicitly versioned field-table extension.

Every edge in a matched path must pass an `EVERY edge` predicate. A query
without one admits all edge fields allowed by the relationship kind set.
`SOME site` and `SOME evidence` require at least one associated record to pass;
they never turn missing evidence into a match.

## Traversal semantics

The source node set is every node of the first declared kind, or every node
when that optional kind is omitted, that satisfies all top-level predicates
referring only to that source. It is sorted by node ID and remains subject to
the source-test cap. The target kind is likewise optional. The executor builds
canonical adjacency from edges whose kind occurs in the relationship kind set
and whose edge predicate passes.

For each source, bounded breadth-first traversal runs in ascending edge-ID then
target-node-ID order. It:

- follows the declared direction;
- visits depths from the declared minimum through maximum;
- never repeats one edge in a path;
- applies the target kind/predicate before emitting a row;
- applies site/evidence existential predicates to the candidate path;
- emits at most one path for a `(source_id, target_id)` pair.

That path is the shortest eligible path. Equal-length alternatives are resolved
by the lexicographically smallest sequence of edge IDs, then node IDs. The
stable path ID is a digest of contract version, selected snapshot ID,
direction, source ID, target ID, and the chosen edge-ID sequence.

Path-dependent predicates make `(source, node, depth)` alone an unsafe
dominance key. For example, two same-depth witnesses may reach one node while
only the lexicographically later witness has satisfied a `SOME evidence`
predicate. The executor therefore represents each admitted partial witness as:

```text
(
  source_id,
  current_node_id,
  depth,
  satisfied_existential_predicate_bitset,
  used_edge_id_set
)
```

Each `SOME site` / `SOME evidence` predicate has one bit. A bit becomes set
when any associated record satisfies that predicate. `EVERY edge` is checked
before an edge is admitted. A partial witness is dominated only by an
already-admitted witness with the identical tuple above; the lexicographically
smaller edge-ID then node-ID sequence wins that exact state. Different
predicate bits or used-edge sets remain distinct even at the same node/depth.

The language therefore performs bounded reachability with a canonical emitted
witness; it does not emit or materialize every complete Cypher-style path
match. It may explore multiple partial witnesses required to preserve
path-dependent predicates, and those product states are included in planning
and hard limits. Cycles remain visible when the target is reached through a
non-repeated edge sequence.

Rows are assembled only after the full admitted execution succeeds. `DISTINCT`
deduplicates canonical projected tuples. Default row order is the canonical
JSON byte order of projected values; explicit `ORDER BY` may reference only
projections and uses code-point-independent UTF-8 byte order with null first.
A projected `Node` is the closed `id/kind/locator/display_name` view, not its
stored `properties`. A projected `Path` contains those closed node views, the
closed Edge/Site fields, and closed admitted Evidence fields in stable
ID/ordinal order. It never serializes arbitrary properties, evidence detail,
diagnostics, logs, audits, or raw runtime records.

## Planner and cost model

Planning is a pure function of:

- `contract_version=bounded-graph-query-v1`;
- canonical typed AST digest;
- completed snapshot ID and verified graph digest;
- exact node/edge/site/evidence counts, per-kind/profile/phase cardinality,
  and canonical serialized byte bounds for the closed result fields;
- the number of existential path predicates and the deterministic upper bound
  of `(node, depth, predicate-bitset, used-edge-set)` product states;
- fixed planner/executor limit version.

Checkout path, store path, query-file path, SQLite row order, locale, wall
clock, runner speed, cache warmth, terminal, CI state, and previous query
results are not planning input.

The planner chooses only these operators:

1. `NodeIdLookup`, `NodeKindScan`, or `BoundedNodeScan`;
2. `CanonicalAdjacencyBuild`;
3. `BoundedForwardBfs` or `BoundedReverseBfs`;
4. `AssociatedSiteFilter`;
5. `AssociatedEvidenceFilter`;
6. `Project`, `Distinct`, `CanonicalSort`, and `Limit`.

No operator can invoke SQLite dynamic SQL supplied by the query. Store reads
use fixed prepared statements or a validated in-memory snapshot.

Cost units are deterministic upper bounds:

```text
cost =
    1 * admitted source-node tests
  + 2 * admitted node visits
  + 4 * admitted edge tests
  + 4 * admitted site tests
  + 8 * admitted evidence tests
  + projection_width * LIMIT
  + 2 * canonical sort row bound
  + ceil(serialized output upper bound / 64)
```

Scalar, Node, and Path projection weights are fixed by the limit version;
every path entity has already paid its node/edge/site/evidence test cost.
`canonical sort row bound` is the lesser of `LIMIT` and the worst-case
endpoint-pair count. The serialized output upper bound uses validated closed
field lengths and the maximum number of records that an admitted path/row can
contain; it never assumes an early match or compression.

Cardinality metadata may lower a bound only when it is integrity-checked
against the selected completed snapshot. Missing, stale, or unknown metadata
uses the full snapshot cardinality. Runtime sampling, early result discovery,
wall-clock estimates, or cache hits never make an over-budget plan admissible.

The hard limits are:

| Resource | Limit |
| --- | ---: |
| Query bytes / tokens / AST nodes | `64 KiB` / `4,096` / `512` |
| Expression nesting / existential path predicates / list literals / projections | `16` / `16` / `64` / `32` |
| Minimum/maximum path depth | `1` / `8` |
| Source nodes tested | `10,000` |
| Unique traversal states / edge tests | `50,000` / `200,000` |
| Site / evidence tests | `100,000` / `200,000` |
| Result rows / serialized output | `10,000` / `16 MiB` |
| Deterministic cost units | `1,000,000` |
| Executor working memory | `128 MiB` |
| Monotonic execution deadline | `5 s` |

`LIMIT` bounds output, not work, and cannot make an otherwise over-budget
traversal admissible. Users may lower limits through future flags, but cannot
raise these hard caps. A release may lower a default only with a visible limit
version; raising a hard cap requires security/performance review and a contract
revision.

## Explain contract

`--explain` performs input validation, parse, type checking, snapshot integrity
validation, and planning, but not traversal. Human and JSON output include:

- contract and limit version;
- query AST digest and selected snapshot/graph digest;
- canonical typed AST shape; string literals appear only as scalar type, byte
  length, and digest, while Boolean, null, and bounded integer literals are
  normalized;
- chosen operators and direction;
- snapshot/cardinality inputs;
- per-operator worst-case rows/visits/tests/cost;
- total cost and every hard limit;
- `admitted=true|false` and stable reasons/remediation.

Explain never executes a partial plan to improve an estimate. The JSON explain
schema is versioned and uses the same admission decision as execution. An
admitted execution includes the plan digest in its result.

The monotonic deadline is a final safety backstop, not a planning estimate.
Two executions that both complete have byte-identical results, but an
exceptionally slow host may fail closed at the deadline rather than weakening
the plan or returning a different complete row set.

## Failure and exit semantics

| Condition | Exit/result |
| --- | --- |
| Valid complete query, including zero rows | exit `0`; canonical complete result |
| Syntax, unknown field, type, binding, depth, or limit error | exit `2` before traversal |
| Deterministic plan exceeds a count/cost cap | exit `1`, `query_plan_budget_exceeded`, no rows |
| Executor reaches a visit/test/output/memory/deadline cap despite an admitted plan | exit `1`, stable exhausted-cap reason, discard staged rows |
| Missing/incomplete snapshot or store/integrity/internal failure | existing exit `3`, no result rows |
| Unsafe query file/path/encoding, credential-shaped literal, or input race | exit `4` with bounded non-echoing diagnostic |

There is no partial-success mode in v1. A budget/deadline failure does not emit
the prefix found before failure, store/cache it as complete, retry with a
smaller depth, omit evidence, switch algorithms, or fall back to a dedicated
command. Cancellation follows the same all-or-error staging rule.

All failures leave the store and selected snapshot byte-identical. Parse,
explain, zero-result, rejected, cancelled, and failed queries do not create
attempt rows or update access time. A future cache must be content-addressed by
snapshot/graph, typed AST, plan, and limit digests and must preserve this
contract.

## Security boundary

| Threat | Required control |
| --- | --- |
| Mutation or project execution | Read-only store; closed grammar without write/import/resolve functions; no worker or project process |
| Recursive/path explosion | One linear pattern, explicit `1..=8`, one emitted canonical witness, predicate/used-edge-aware partial-state planning, fixed state/edge/cost caps |
| Predicate or regex denial of service | Closed scalar operators only; no regex/glob/functions/arithmetic/dynamic JSON |
| Evidence or secret exfiltration | Closed safe field table; no properties/detail/log/audit/raw trace; bounded canonical result |
| Query injection into SQLite | Typed AST to fixed operators/prepared reads; query text is never SQL |
| Filesystem/symlink race | Bounded regular-file inspection, confinement, pre/post metadata, UTF-8 validation, non-echoing errors |
| Order/host nondeterminism | Verified snapshot/cardinality input, canonical adjacency/BFS/tie-break/sort, no locale/clock/cache input |
| Budget bypass via `LIMIT` or explain | Work admitted before execution; limit bounds output only; explain and execute share one plan |
| Partial result mistaken for complete | Stage rows; all-or-error result; fixed incomplete reason and nonzero exit |

The language is not a sandbox for third-party query code. It is a closed data
contract interpreted by first-party parser/planner/executor components.

## Staged implementation

Each row is one independently reviewable one-to-three-day follow-up Issue.

| Order | Slice | Estimate | Depends on | Exit criterion |
| ---: | --- | --- | --- | --- |
| 1 | Lexer/parser, bounded input reader, canonical AST, and malformed corpus | Implemented in #177 | This ADR | Grammar accepts only one bounded statement and never echoes hostile literals |
| 2 | Closed type checker, field registry, canonical AST digest, and golden plans | Implemented in #178 | 1 | Node/Path/Edge/Site/Evidence bindings and operators reject every invalid combination |
| 3 | Snapshot cardinality statistics, fixed operator planner, cost admission, and explain schema | Implemented in #179 | 2 | Explain and execute admission are byte-identical across checkouts and SQLite row orders |
| 4 | Canonical forward/reverse BFS executor, site/evidence filters, staging, and cancellation | 2-3 days | 3 | One shortest witness per endpoint pair; every cap is all-or-error |
| 5 | CLI human/JSON output, read-only store integration, profile/phase/condition/evidence fixtures | 2-3 days | 4 | Multi-root and cross-kind use cases work without changing a snapshot |
| 6 | Fuzz/property tests, hostile large-graph benchmark, and five-target package/release gate | 2-3 days | 5 | Parser/planner/executor survive malformed/budget fixtures; all native archives agree |

Parser, planner, and executor remain separate components delivered by separate
Issues. The parser cannot directly traverse, the planner cannot access raw
query text, and the executor accepts only a validated typed plan carrying exact
snapshot, graph, contract, and limit digests.

## Acceptance matrix

| Case | Required result |
| --- | --- |
| Existing `deps` / `why` / `impact` / `policy` use case | Dedicated command remains the documented preferred interface and unchanged |
| Multi-root route-to-external query | Canonical shortest witness for every admitted endpoint pair |
| Reverse cross-kind query | Same endpoint/path set across discovery and SQLite row orders |
| Exact profile/phase/condition filters | Only matching edges enter adjacency; site/evidence predicates govern emitted paths |
| Runtime/build evidence prefix filter | Only associated safe evidence fields are read; no properties/detail/log leakage |
| Two equal shortest witnesses | Lexicographically smallest edge-ID then node-ID sequence |
| Two same-node/depth partial witnesses with different evidence satisfaction or used edges | Both states remain explorable; only an identical state is lexicographically dominated |
| `Path.id` in `WHERE` | Exit `2`; witness ID is projection/order-only |
| Cycle under depth 8 | Terminates without repeated edge and emits at most one witness per endpoint pair |
| Missing kind or zero match | Exit `0` with complete empty rows |
| Depth 0, depth 9, missing/large limit, unknown field, or type mismatch | Exit `2` before traversal |
| Plan above node/edge/evidence/cost cap despite `LIMIT 1` | Exit `1` before execution with `query_plan_budget_exceeded` |
| Runtime deadline or output cap | Staged rows discarded; exit `1`; no partial JSON |
| Query file symlink, mutation during read, invalid UTF-8, or credential-shaped literal | Exit `4`, no content echo or store access |
| Same query/snapshot in another checkout | Byte-identical AST/plan digests and, when both complete, result digest/canonical JSON |
| Read-only store permissions | Query and explain succeed without writer lock or any changed database byte |
| Cancel during traversal | Nonzero all-or-error result; no cache/attempt/store mutation |
| Five-target packaged query | Same result and plan digest on Linux, macOS, and Windows archives |

The representative fixture includes Rust, Go, Web/framework, cross-language,
external, unresolved, build, and runtime edges; multiple profiles and
conditions; shared source/target pairs; equal-length paths; cycles; edge/site
evidence; empty/nullable fields; and enough fan-out to cross each boundary by
one.

## Options considered

### Do not add a query language

Rejected. Dedicated commands remain superior for common workflows, but adding
one command per combination of multi-root, cross-kind, profile, phase,
condition, and evidence predicates would duplicate traversal semantics and
still leave exploratory policy design awkward.

### Adopt full Cypher/openCypher or ISO GQL

Rejected for v1. Their pattern and projection concepts are useful references,
but optional/multiple patterns, joins, subqueries, aggregation, functions,
updates, and broad variable-length path semantics are outside this product's
bounded local use case. Calling the subset “Cypher” would also promise
compatibility that it does not provide.

### Adopt CodeQL/QL or Datalog

Rejected. Recursive predicates, libraries, user-defined relations, compilation,
and whole-program query packs are powerful for security analysis but create a
much larger trusted language/runtime surface. `depgraph` already stores the
semantic graph and needs only bounded evidence-aware reachability.

### Expose SQL over the SQLite store

Rejected. The schema is an internal versioned representation, raw SQL couples
users to migrations, and SQLite read-only mode alone does not bound joins,
recursive common-table expressions, functions, output, or sensitive fields.

### Enumerate every matching path

Rejected. The number of simple paths can be exponential even with a depth
bound. A canonical shortest witness per endpoint pair is deterministic,
explainable, and sufficient for the accepted use cases.

### Allow partial results when a budget is exhausted

Rejected. Prefixes depend on traversal and limit details and are easy to
mistake for complete architecture evidence. V1 stages rows and returns
all-or-error.

## Consequences

Users gain one compositional escape hatch without weakening the dedicated
commands or safe-scan boundary. Typed profile, phase, condition, site, and
evidence predicates make exploratory architecture questions reproducible, and
the plan digest makes an admitted execution auditable.

The deliberately small grammar will not express joins, aggregations, arbitrary
properties, all paths, or cross-snapshot analysis. Users may process canonical
JSON externally or request a future contract revision, while established
`diff`, `impact`, and `policy` commands retain richer domain-specific
semantics.

Implementation requires new parser, typed plan, snapshot statistics, executor,
CLI, fuzz, and package-gate work. Until those staged slices land, the existing
commands are the only product contract.

## References

- openCypher specification and grammar resources:
  https://opencypher.org/resources/
- Neo4j Cypher graph patterns and bounded variable-length paths:
  https://neo4j.com/docs/cypher-manual/current/patterns/
- Neo4j Cypher query plans:
  https://neo4j.com/docs/cypher-manual/current/planning-and-tuning/
- CodeQL recursion and least-fixed-point semantics:
  https://codeql.github.com/docs/ql-language-reference/recursion/
- SQLite progress handler:
  https://www.sqlite.org/c3ref/progress_handler.html
