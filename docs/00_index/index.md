# ドキュメントインデックス

| ID | Layer | Feature | Scope | Title | Status |
| --- | --- | --- | --- | --- | --- |
| PROJ-ARC-001 | L4 | dependency-graph | feature | アーキテクチャ設計: Semantic Dependency Graph CLI | Active |
| PROJ-ARC-002 | L4 | mcp-agent-tools | feature | [アーキテクチャ設計: MCP Agent Tools](../40_arch_design/arch-mcp-agent-tools.md) | Active |

## Architecture Decision Records

| ID | Parent | Title | Status |
| --- | --- | --- | --- |
| PROJ-ARC-001-ADR-001 | PROJ-ARC-001 | [Production runtime collector v1 contract](../40_arch_design/adr-production-runtime-collector-v1.md) | Accepted |
| PROJ-ARC-001-ADR-002 | PROJ-ARC-001 | [Opt-in Rust compiler-precise backend](../40_arch_design/adr-rust-compiler-precise-backend.md) | Accepted |
| PROJ-ARC-001-ADR-003 | PROJ-ARC-001 | [Cross-language adapter common contract](../40_arch_design/adr-cross-language-adapter-contract.md) | Accepted |
| PROJ-ARC-001-ADR-004 | PROJ-ARC-001 | [Default profile selection and exploration budget](../40_arch_design/adr-default-profile-selection-budget.md) | Accepted |
| PROJ-ARC-001-ADR-005 | PROJ-ARC-001 | [Bounded read-only graph query language](../40_arch_design/adr-bounded-graph-query-language.md) | Accepted |
| PROJ-ARC-001-ADR-006 | PROJ-ARC-001 | [Public OSS readiness and release governance](../40_arch_design/adr-public-oss-release-governance.md) | Accepted |
| PROJ-ARC-001-ADR-007 | PROJ-ARC-001 | [v0.5 release, migration, and source contract](../40_arch_design/adr-v0.5-release-contract.md) | Accepted |
| PROJ-ARC-001-ADR-008 | PROJ-ARC-001 | [npm distribution for the native CLI](../40_arch_design/adr-npm-distribution.md) | Accepted |

## 運用手順

- [GitHub Actionsを使ったリリース手順](../50_test/release-procedure.md)
- [npmリリース手順](../50_test/npm-release-procedure.md)
- [MCP Agent host operations](../50_test/mcp-agent-host-operations.md)
- [Packaged MCP Agent dogfood benchmark](../50_test/agent-dogfood-benchmark.md)

## 統計

### レイヤー別

| Layer | Count |
| --- | ---: |
| L0 | 0 |
| L1 | 0 |
| L2 | 0 |
| L3 | 0 |
| L4 | 2 |
| L5 | 0 |
| Total | 2 |

### ステータス別

| Status | Count |
| --- | ---: |
| Draft | 0 |
| Active | 2 |
| Deprecated | 0 |

### 機能別

| Feature | Count |
| --- | ---: |
| dependency-graph | 1 |
| mcp-agent-tools | 1 |

## 更新履歴

- 2026-08-26: `v0.5.4`のリリースノートとCodex／Claude Code／Cursor／Grokのproject/user scope自動MCPセットアップを追加
- 2026-08-25: `v0.5.3`のリリースノートとWindows公開後canary修正を追加
- 2026-08-24: `v0.5.2`のリリースノートと現行release contractを追加
- 2026-08-19: `PROJ-ARC-001-ADR-008` とnpmリリース手順を追加
- 2026-08-16: verified packageからAgent host設定を生成・接続検証するonboarding契約を追加
- 2026-08-16: packaged MCP Agent dogfood benchmarkの再実行手順と固定evidenceを追加
- 2026-08-13: `PROJ-ARC-001-ADR-007` と v0.5 release contractを追加
- 2026-08-12: MCP Agent hostのcapability、確認、reconnect、timeout、upgrade運用手順を追加
- 2026-08-05: `PROJ-ARC-002` のMCP Tasks decisionを追加し、`Q-002`をResolvedへ更新
- 2026-08-02: GitHub Actionsを使ったリリース手順を追加
- 2026-07-25: `PROJ-ARC-001-ADR-006` を追加
- 2026-07-25: `PROJ-ARC-001-ADR-005` を追加
- 2026-07-25: `PROJ-ARC-001-ADR-004` を追加
- 2026-07-25: `PROJ-ARC-001-ADR-003` を追加
- 2026-07-25: `PROJ-ARC-001-ADR-002` を追加
- 2026-07-24: `PROJ-ARC-001-ADR-001` を追加
- 2026-07-15: `PROJ-ARC-001` を追加
- 2026-07-15: Milestone 0〜1 MVP実装に伴い `PROJ-ARC-001` をActiveへ更新
