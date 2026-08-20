# ADR: v0.5 release, migration, and source contract

- Status: Accepted
- Date: 2026-08-13
- Updated: 2026-08-20
- Decision ID: `PROJ-ARC-001-ADR-007`
- Issue: `PROJ-ARC-003-TASK-001` / #355
- Contract: `stable-release-gate-v2`

## Context

The latest published GitHub Release is `v0.4.0-rc.6`. No `v0.4.0` stable GitHub Release was published. The reserved `v0.4.0` baseline commit and
`release/0.4` ref predate the MCP server and durable operation runner now on
`main`. Publishing current `main` as `v0.4.0` would therefore misidentify both
the source and the compatibility boundary.

Current `main` writes Store schema `17`, while the published rc.6 package
writes schema `13`. MCP also introduces a separate operation journal at schema
`5` and two public Agent contracts. Those surfaces need one minor-release
identity and an explicit upgrade source before another release candidate can
be built.

## Decision

The next stable product version is `0.5.0`. Cargo workspace packages, Rust,
Go, and Web worker handshakes, native binaries, release manifests, SBOM
package versions, archive paths, and executable documentation examples all
use the exact base version `0.5.0`. Release tags are either `v0.5.0` or a
canonical `v0.5.0-rc.N`, where `N` is a positive decimal integer without a
leading zero.

The v0.5 compatibility tuple is:

| Surface | Exact contract |
| --- | --- |
| Product and adapters | `0.5.0` |
| Worker protocol / graph schema | `1.0` |
| SQLite Store | schema `17` |
| Durable operation journal | schema `5` |
| MCP tool DTO | `depgraph-mcp-tools-v1` |
| Operation DTO | `depgraph-operation-v1` |
| Agent host configuration | `depgraph-agent-host-config-v1` |
| Agent onboarding release evidence | `release-post-publish-evidence-v1` |
| Packaged MCP smoke | `mcp-package-smoke-v2` |
| Release gate | `stable-release-gate-v2` |
| Packaged smoke | `stable-v0.5.0-packaged-smoke-v1` |

The existing `v0.4.0-rc.N` tags, GitHub Releases, reserved `v0.4.0` baseline
commit, baseline tree/digest, and `refs/heads/release/0.4` are immutable
history. They are not relabeled, moved, deleted, or treated as a supported
stable release.

## Upgrade evidence

The canonical v0.5 upgrade source is the published `v0.4.0-rc.6` Store schema
`13`. The repository pins
`xtask/fixtures/v0.4.0-rc.6-store-v13.sql` at SHA-256
`43fe0dda73d03be9b8fff2ed9ff8ce888ad96e41e78335a1117646475c937150`.
It was produced with the official aarch64 Apple archive from tag commit
`bb5dbe67e737cf50f07d90e6f4c8b7658c631184`; the archive SHA-256 is
`9dfde55ce04f940464c1d9215d165fb6786264f1b40fe4dd2c01a7b210eb18c3`
and its `depgraph` binary SHA-256 is
`c7d97ea0b2f4af388b6cd3ad7b69f41ac1ac5df65dadf7c20f749d4082f0fca4`.
That binary opened the official rc.1 schema-11 fixture and transactionally
migrated it to schema 13 without changing the completed snapshot identity.

The v0.5 package and unit gates verify fixture checksum, transactional
migration to schema 17, the exact immutable snapshot ID, node/site/edge/
evidence counts, integrity, and post-migration snapshot naming. The rc.1
schema-11 and v0.2 schema-5 fixtures remain independent historical migration
tests.

Before migration, operators stop all writers and copy the database together
with any WAL/SHM files. Tests retain the pre-upgrade database bytes and prove
the rollback copy is unchanged. An rc.6 or other older binary must not be used
to open the schema-17 database. Rollback means stopping v0.5, preserving the
schema-17 database for diagnosis, restoring the complete byte-for-byte
pre-upgrade backup set, and only then starting the old binary.

## Candidate, baseline, and maintenance policy

The first candidate is `v0.5.0-rc.1`; a changed candidate receives the next
RC number and no pushed tag or asset is replaced. Canonical RC tags bind their
exact source SHA and may exercise the complete release gate.

The stable baseline status is `maintenance-ref-pinned`. A `v0.5.0` Release is
allowed only when the signed annotated tag source, remote `main`, and the
initial `refs/heads/release/0.5` ref identify the same reviewed commit and an
exact eight-job `workflow_dispatch` Full CI run succeeded for that `main`
head. The default-branch source guard cancels the Release run and deletes a
mismatched tag; `stable-release-gate-v2` independently validates the refs,
source tree, Full CI evidence, and the digest-pinned Agent dogfood report.

The runtime gate records the selected commit, tree, canonical
`release-baseline-v1` digest, and Full CI identity in `stable-release-gate.json`.
The post-publish record then binds those values to the signed tag object,
Release run, and exact public asset closure. This external record avoids
attempting to embed a commit SHA in its own source tree.

### 2026-08-20 patch-release amendment

`v0.5.1` is the first patch release under the npm distribution contract.
Compatible fixes still land on `main` first through reviewed pull requests.
After the exact `main` candidate passes Full CI, `release/0.5` advances from
the previous stable baseline to that same commit by fast-forward only. The
signed patch tag, remote `main`, and `release/0.5` therefore share one source
SHA when publication begins.

The earlier instruction to cherry-pick fixes into `release/0.5` is superseded.
A cherry-pick creates a different commit SHA and cannot satisfy the existing
exact-source gate. Force-pushes and history rewrites remain forbidden. Main is
frozen between candidate selection and completion of the source-identity
check.

## Consequences

- v0.4 remains reproducible history without claiming a release that does not
  exist on GitHub.
- v0.5 RCs validate real packages while stable publication remains fail-closed
  unless the exact main/maintenance/tag/Full-CI identity is present.
- Store and operation-journal compatibility are separate and explicit.
- Fixture, version, tag, manifest, and documentation drift fail tests before
  publication.
