# リリースと互換性

日本語 | [English](compatibility.en.md)

stable `v0.6.3` artifactは、[`v0.6.3`リリースノート](../releases/v0.6.3.md)に記載した契約を実装している。
`main`にはtag後の開発変更が含まれる場合があり、公開済みartifactの契約を自動的に更新しない。
正式版は、[`v0.6.3` GitHub Release](https://github.com/TamaT-LLC/depgraph-cli/releases/tag/v0.6.3)と公開後証跡が一致するときに限り有効である。
MVPは[システム設計](../40_arch_design/arch-dependency-graph-cli-system-design.md)に記載したアーキテクチャを実装している。

patch release `v0.6.3`は、v0.6.0のStore schema `19`と説明可能なcode-health契約／APIを維持する。
`depgraph-health-finding-v1`、CLIの`health`／`cleanup`／`audit`／`hotspots`、および対応するMCP APIがこの境界に含まれる。
v0.6.0から新たな保存形式の移行はない。

すべてのv0.5アーカイブには、ネイティブMCPサーバー、永続的な操作ランナー、バージョン管理されたエージェント用ツール／操作スキーマが含まれる。
現行開発版のワーカープロトコルは`1.0`、操作ジャーナルスキーマは`6`であり、`depgraph-mcp-tools-v1`と`depgraph-operation-v2`を使用する。
公開済み`v0.5.4` artifactのStore schemaは`17`である。
current `main`はStore schema `19`を使用し、schema 19へ移行したStoreを公開済み`v0.5.4` binaryで開くことはできない。

`v0.4.0`は予約済みベースラインの履歴記録であり、正式版は公開されなかった。
履歴上の契約は[`v0.4.0`の契約](../releases/v0.4.0.md)に残している。
過去のリリース候補は[`v0.4.0-rc.6`](../releases/v0.4.0-rc.6.md)、[`v0.4.0-rc.2`](../releases/v0.4.0-rc.2.md)、[`v0.4.0-rc.1`](../releases/v0.4.0-rc.1.md)、[`v0.2.0-rc.1`](../releases/v0.2.0-rc.1.md)で確認できる。

リリースの互換性タプル、ストア移行、ロールバック、既知の制約は[`v0.6.3`リリースノート](../releases/v0.6.3.md)を参照する。
過去のschema 17の契約は[`v0.5.4`リリースノート](../releases/v0.5.4.md)に保持する。
