# Releases and compatibility

[日本語](compatibility.md) | English

The stable `v0.6.3` artifact implements the contract documented in the
[`v0.6.3` release notes](../releases/v0.6.3.md). `main` may contain
post-tag development changes that are not part of that published artifact. A
stable release is valid only when the
[`v0.6.3` GitHub Release](https://github.com/TamaT-LLC/depgraph-cli/releases/tag/v0.6.3)
and its post-publish evidence exist and agree.
The MVP implements the architecture described in [the system design](../40_arch_design/arch-dependency-graph-cli-system-design.md).

The patch release `v0.6.3` retains the v0.6.0
Store schema `19` together with the `depgraph-health-finding-v1` code-health
contract, the CLI `health` / `cleanup` / `audit` / `hotspots` APIs, and their MCP
projections. No new storage migration is introduced from v0.6.0.

Every v0.5 archive includes the native MCP server, durable
operation runner, and versioned Agent tool/operation schema.
The worker protocol remains at `1.0` for v0.5. The current development
compatibility tuple is Store
schema `19`, operation journal schema `6`, `depgraph-mcp-tools-v1`, and
`depgraph-operation-v2`.
The published `v0.5.4` artifact uses Store schema `17`. Current post-tag
`main` uses Store schema `19`; a Store migrated to schema 19 cannot be opened
by the published `v0.5.4` binary.

`v0.4.0` is a historical reserved baseline; no `v0.4.0` stable GitHub Release
was published. Its contract remains in the historical
[`v0.4.0` contract](../releases/v0.4.0.md). Earlier release candidates are
documented as [`v0.4.0-rc.6`](../releases/v0.4.0-rc.6.md),
[`v0.4.0-rc.2`](../releases/v0.4.0-rc.2.md),
[`v0.4.0-rc.1`](../releases/v0.4.0-rc.1.md), and
[`v0.2.0-rc.1`](../releases/v0.2.0-rc.1.md).

See the [`v0.6.3` release notes](../releases/v0.6.3.md) for the release
compatibility tuple, Store migrations, rollback procedure, and known limits.
The historical schema-17 contract remains in the
[`v0.5.4` release notes](../releases/v0.5.4.md).
The `v0.6.3` fixes and compatibility guarantees are recorded in the
[`v0.6.3` release notes](../releases/v0.6.3.md).
