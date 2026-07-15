# depgraph-cli

Rust、Go、Next.js、Astro、TanStack Router / Start を対象に、依存箇所を根拠・条件・精度付きのグラフとして抽出する CLI の設計リポジトリです。

現在は設計フェーズです。SDA 形式のアーキテクチャ設計は次を参照してください。

- [アーキテクチャ設計](docs/40_arch_design/arch-dependency-graph-cli-system-design.md)
- [ドキュメントインデックス](docs/00_index/index.md)

## 設計上の保証

静的解析で実行時の依存先を常に一意決定することはできません。本プロジェクトでは、すべての依存箇所を `resolved`、`candidates`、`external`、`unresolved` のいずれかへ分類し、未解決箇所を黙って捨てないことを保証の中心に据えます。
