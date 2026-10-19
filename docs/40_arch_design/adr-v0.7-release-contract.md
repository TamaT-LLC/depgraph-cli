# ADR: v0.7 release and dependency-list compatibility

- Status: Proposed
- Date: 2026-10-19
- Related: [v0.6 contract](adr-v0.6-release-contract.md), #540–#544, #550
- Contract: `stable-release-gate-v2`

## Decision

v0.7.0 introduces a separate `refs/heads/release/0.7` maintenance line because dependency lists now exclude structural edges by default. The signed tag, remote `main`, and this maintenance ref must identify the same reviewed commit after the exact ten-job Full CI succeeds. The v0.6 maintenance ref and published releases remain immutable history.

MCP `graph_dependencies_list` / `graph_dependents_list` and CLI `deps` / `dependents` exclude `contains`, `declares`, and `generated_from` by default. Callers that need the previous traversal use `structural_edges: "include"` or `--structural-edges include`. Explicit edge-kind allowlists retain their documented precedence. Old default cursors must be restarted; cursors with explicit structural inclusion remain compatible. `why` and `impact` traversal retain their existing behavior.

## Persisted and wire contracts

Store schema `19`, operation journal schema `6`, worker protocol `1.0`, `depgraph-mcp-tools-v1`, and `depgraph-operation-v2` remain unchanged. No new storage migration is required from v0.6.4. Additive MCP fields and `repository_list` require consumers using closed DTO deserialization to update their crate.

The schema-13 migration fixture, schema-17 v0.5.4 history, code-health dogfood reports, package checks, four native targets, compiler packs, SBOM, licenses, and post-publish evidence remain required. Native query/profile digest pins must come from measured semantic and cross-checkout determinism checks for v0.7.0; observation runs do not authorize publication.

## Release conditions

The release PR requires the existing local gate, green PR checks, resolved review conversations, and independent approval. The frozen main commit then passes the exact ten-job Full CI with `extra_native_packages=true`. Only that source may create `release/0.7` and the signed annotated `v0.7.0` tag. Release publication, public-byte verification, npm Trusted Publishing, and the Homebrew update follow the existing procedures.

Until the official v0.7.0 Release and matching post-publish evidence exist, v0.6.4 remains the supported stable release. See [the v0.7.0 release notes](../releases/v0.7.0.md) for user migration steps.
