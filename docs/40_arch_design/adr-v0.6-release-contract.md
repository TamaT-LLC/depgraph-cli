# ADR: v0.6 release, migration, and source contract

- Status: Accepted
- Date: 2026-09-13
- Decision ID: `PROJ-ARC-001-ADR-011`
- Related: `PROJ-ARC-001-ADR-007`, `PROJ-ARC-001-ADR-009`, Issues #423, #436, #440, #464, #482
- Contract: `stable-release-gate-v2`

## Decision

The next stable release is `v0.6.0`. It is a minor release from current
`main`, not a patch to the published `v0.5.4` contract. The release moves the
Store boundary from schema `17` to schema `19` and publishes the code-health
contract and API changes that have remained on the post-`v0.5.4` development
line.

The v0.6.0 compatibility tuple is:

| Surface | Exact contract |
| --- | --- |
| Product and Rust / Go / Web adapters | `0.6.0` |
| Previous stable release | `v0.5.4`, Store schema `17` |
| Worker protocol / graph schema | `1.0` |
| SQLite Store | schema `19` |
| Durable operation journal | schema `6` |
| MCP tool DTO | `depgraph-mcp-tools-v1` |
| Operation DTO | `depgraph-operation-v2` |
| Agent host configuration | `depgraph-agent-host-config-v1` |
| Code-health finding | `depgraph-health-finding-v1` |
| Packaged MCP smoke | `mcp-package-smoke-v3` |
| Stable source / release gate | `stable-release-gate-v2` |
| Maintenance ref | `refs/heads/release/0.6` |

At publication, the signed `v0.6.0` tag, remote `main`, and
`refs/heads/release/0.6` must identify the same reviewed commit. That commit
must pass the exact Full CI run, the stable source guard, the five-target
package gates, and the post-publish evidence checks. The candidate SHA is not
chosen by this ADR; it is recorded only after the release candidate is frozen
and Full CI has passed. The baseline status is maintenance-ref-pinned.

## Immutable v0.5.4 boundary

The published `v0.5.4` release remains immutable history. Its annotated tag
object is
`0affa3af15a4854f78a2c6d4b1308e4647c39f88`, and its peeled source commit is
`ea16edec63e88923c7d169152caedbf4285b4713`. The artifact writes Store schema
`17`; its release assets and post-publish evidence are not replaced or
relabelled.

The existing `refs/heads/release/0.5` remains the v0.5 maintenance line. It is
not rewritten or reused as the v0.6 maintenance ref. A Store migrated to
schema `19` by v0.6.0 cannot be opened by the published `v0.5.4` binary.

## Code-health compatibility boundary

The v0.6.0 release includes the read-only code-health APIs exposed by the CLI
and MCP. They use one shared `depgraph-health-finding-v1` domain contract:

- CLI: `health`, `health list`, `health show`, `cleanup`, `audit`, and
  `hotspots`.
- MCP: `health_summary_get`, `health_findings_list`, `health_finding_get`,
  `health_audit_get`, and `health_hotspots_list`.
- Current hotspot output includes a closed `hotspot_scores` object with the
  five score layers. `confirmed` remains reserved for findings that prove
  unusedness; hotspot confidence is capped at `probable`.

The development API also changes `score_hotspots` to return `Result` and adds
`HotspotAnalysisError::InvalidInput`, cancellation, and resource errors.
Callers that construct current hotspot `HealthFinding` values directly must
populate the score field, and Agent DTO projection must emit the closed score
object for hotspot findings. Non-hotspot findings omit it. Legacy hotspot wire
input may still omit the field or provide null, but current v0.6.0 hotspot
output may not.

Store schema `18` adds policy-digest, analyzer-version, and finding-contract
provenance columns. New scans bind those values in a v2 completed-snapshot
storage seal. Schema-17 scans migrate transactionally after their legacy v1
seal is verified and may remain provenance-less; comparisons with missing or
mismatched provenance fail closed as `incomparable-policy` or
`incomparable-contract`.

## Bounded analysis and resume

Store schema `19` adds the durable ledger for analysis attempts and units.
Go and Web work is planned in bounded units, with valid completed checkpoints
retained across interruption. Go uses package-scoped loading and staged bodies
for large packages; health loads and evaluates bounded Store ranges. Budget
exhaustion remains explicit partial output rather than a completed result.

The private acceptance run on `5a1587dd372f22854ae2a75deb0cf9b787f133ed`
completed fresh scan, ordinary health, and same-input interruption/resume on
macOS arm64 with unchanged product limits. Issues [#482](https://github.com/TamaT-LLC/depgraph-cli/issues/482)
and [#464](https://github.com/TamaT-LLC/depgraph-cli/issues/464) record the
completion. This source-level acceptance complements the package gates; it
is not evidence that every repository or platform has been exercised.

## Migration and rollback

Operators stop writers and back up the database together with its WAL and SHM
files before migration. The v0.6.0 gate verifies the pinned schema-13 release fixture,
transactional migration to schema `19`, completed graph identity, and an
unchanged rollback copy.

Rollback restores the complete pre-migration database/WAL/SHM set before
starting the v0.5.4 binary. Downgrade-in-place and copying individual SQLite
tables are forbidden. The operation journal advances from schema `5` to `6`,
and the operation DTO advances from v1 to `depgraph-operation-v2`. Back up the
operation journal and its WAL/SHM alongside the Store before opening it with
v0.6.0. Rollback restores both complete pre-upgrade sets; newer journal rows
and DTOs must not be passed to the older binary. The worker protocol and MCP
tool contract remain v1.

## Rejected alternatives

- Publishing current `main` as `v0.5.5` was rejected because Store schema 19
  and the public code-health API create a new compatibility boundary.
- Reusing `release/0.5` was rejected because it would mix the immutable v0.5
  source history with the v0.6 maintenance line.
- Leaving the package at `0.5.4` was rejected because its runtime identity
  would incorrectly match the published schema-17 artifact.

## Release and support conditions

The release PR adds [`v0.6.0` release notes](../releases/v0.6.0.md) and keeps
the version change with the release documentation. CI must be green and
Greptile must have no unresolved findings before merge. Release and workflow
changes additionally require the manual Full CI run on the frozen `main`
commit.

The signed tag is created only after the exact source and maintenance-ref
checks pass. Release builds all five native targets, verifies the compiler
packs and code-health CLI/MCP parity, and publishes the evidence-bound asset
closure. npm publication follows successful GitHub Release and post-publish
verification.

Until the official `v0.6.0` Release and matching evidence exist, `v0.5.4`
remains the supported stable line. Current `main` and v0.6.0 release
candidates are evaluation artifacts and must not be mixed with the v0.5.4
binary, workers, Store, or compiler pack.

## Consequences

- ADR-007 remains the historical v0.5 release contract; this ADR defines the
  separate v0.6 minor boundary.
- Existing v0.5.4 tags, assets, evidence, source SHA, and schema-17 behavior
  remain reproducible and unchanged.
- Consumers of the post-`v0.5.4` development code-health API must migrate to
  the v0.6.0 return types and closed hotspot output before using the stable
  package.
- The exact candidate SHA and publication date remain release-time values and
  are not embedded in this source document.
