# depgraph

日本語 | [English](README.en.md)

[![CI](https://github.com/TamaT-LLC/depgraph-cli/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/TamaT-LLC/depgraph-cli/actions/workflows/ci.yml)
[![GitHub Release](https://img.shields.io/github/v/release/TamaT-LLC/depgraph-cli)](https://github.com/TamaT-LLC/depgraph-cli/releases/latest)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

`depgraph`は、コードの依存関係をグラフにして、「この変更でどこが壊れうるか」「なぜこのファイルがあのファイルに依存しているか」を根拠付きで答えるCLIです。
Rust・Go・TypeScript/JavaScriptと、Next.js・Astro・TanStackのルートを1つのグラフで扱います。
手元のマシンで動き、プロジェクトのコードは実行しません。

## こんなときに役立ちます

**レビュー前に変更の影響を確認する**

`main`から変更したファイルに依存している箇所を一覧にします。

```sh
depgraph impact path:src/lib/cart.ts --changed main
```

**依存している理由を調べる**

2つのファイルを結ぶ依存経路と、それぞれの段を生むimportや呼び出しの位置を表示します。

```sh
depgraph why path:src/app/checkout/page.tsx path:src/lib/cart.ts
```

**AIエージェントからも同じ質問をする**

Claude Code、Codex、Cursor、Grokに、読み取り専用のMCPサーバーとして登録します。

```sh
depgraph mcp setup --host claude
```

## 紹介動画

上の3つの使い方を約60秒で紹介しています（日本語ナレーション付き）。

https://github.com/user-attachments/assets/255258db-3527-47a4-b675-cd907a6ca34e

## 30秒で試す

```sh
# インストール（macOS Apple Silicon / Linux）
brew install tamat-llc/tap/depgraph
# npmでも導入できます（Node.js 24以上）
npm i -g @tamat-llc/depgraph

# 調べたいリポジトリの中で実行します
cd /path/to/your-repository
depgraph scan .
depgraph impact path:src/lib/cart.ts --changed main
depgraph why path:src/app/checkout/page.tsx path:src/lib/cart.ts
```

`src/lib/cart.ts`などのパスは、お使いのリポジトリにあるファイルに置き換えてください。

- `scan`はファイルを読むだけです。ビルドスクリプト、プラグイン、パッケージマネージャーは実行しません。
- 解析結果は、リポジトリごとにOSのキャッシュディレクトリ内のデータベースへ保存されます。リポジトリ自体は変更しません。
- どこまで解析できたかは`depgraph doctor`で確認できます。

## よく使うコマンド

| 知りたいこと | コマンド |
| --- | --- |
| このファイルが使っているもの | `depgraph deps path:src/app.ts --transitive` |
| このファイルを使っているもの | `depgraph dependents path:src/app.ts --transitive` |
| AがBに依存している理由 | `depgraph why path:src/app.ts path:src/lib/db.ts` |
| 変更の影響範囲 | `depgraph impact path:src/app.ts --changed origin/main` |
| 解析できなかった箇所 | `depgraph unresolved` |
| 解析の状態 | `depgraph doctor` |
| グラフの共有 | `depgraph export --format mermaid > graph.mmd` |

コマンドには、調べたい対象を指定する「セレクター」を渡します。

- `path:src/app.ts`は、リポジトリ内のパスでファイルを指定します。
- `package:example`は、workspaceのパッケージを名前で指定します。
- `id:<stable-id>`は、depgraphが表示したIDでそのまま指定します。名前が複数の対象に当てはまるときに使います。

すべてのコマンド、スキャンの設定、終了コード、実行例は[使い方ガイド](docs/guide/usage.md)にまとめています。

## AIエージェントから使う（MCP）

`depgraph mcp setup`は、対応する公式リリースを取得して検証し、安全なスキャンで最初のsnapshotを作ってから、ホストの設定に`depgraph`のエントリーを追加します。
エージェントに調べさせたいGitリポジトリの中で実行してください。

| `--host` | エージェント | プロジェクトの設定ファイル |
| --- | --- | --- |
| `claude` | Claude Code | `.mcp.json` |
| `codex` | Codex | `.codex/config.toml` |
| `cursor` | Cursor | `.cursor/mcp.json` |
| `grok` | Grok | `.grok/config.toml` |

ユーザー単位の設定に書き込む場合は`--scope user`を付けます。
設定後は、エージェントを再起動または再読み込みしてください。
エントリーの管理には、同じ`--host`（と`--scope`）を付けて次のコマンドを使います。

```sh
depgraph mcp status --host claude
depgraph mcp update --host claude
depgraph mcp uninstall --host claude
```

### ツールが取得できないとき

Claude Codeでdepgraphのtoolsが取得できず、次のエラーになることがあります。

```text
request _meta is missing or has malformed required fields: io.modelcontextprotocol/protocolVersion, io.modelcontextprotocol/clientCapabilities
```

登録済みの`depgraph-mcp`が古いことが原因の可能性があります。
v0.6.1で発生を確認し、v0.6.4では接続できることを確認しています。
`depgraph mcp setup`は、実行中のCLIと同じ版の公式リリースをホストの設定に結び付けます。
そのため、CLI本体を更新してから`setup`を再実行してください。

1. CLIをv0.6.4以降に更新します（`brew upgrade depgraph`、`npm i -g @tamat-llc/depgraph`など）。
2. `depgraph --version`で版を確認します。
3. リポジトリ内で`depgraph mcp setup --host claude`を再実行します（ユーザー単位なら`--scope user`も付けます）。
4. `depgraph mcp status --host claude`で状態を確認します（ユーザー単位なら`--scope user`も付けます）。
5. エージェントを再起動または再読み込みします。

登録されるサーバーは読み取り専用です。
解析結果の保存先の変更、リポジトリへの書き込み、プロジェクトコードの実行はできません。
権限付きのプロファイル、`agent-config`による手動設定、トラブルシューティングは[MCPエージェントホスト運用手順](docs/50_test/mcp-agent-host-operations.md)（英語）を参照してください。

## 対応する言語とフレームワーク

| 対象 | 抽出する主な要素 |
| --- | --- |
| Rust | Cargoワークスペース、パッケージ、ターゲット、モジュール、インポート、再エクスポート、シンボル、型、型利用、確定呼び出し、呼び出し候補 |
| Go | ワークスペース、モジュール、パッケージ派生形、ビルド条件、インポート、シンボル、型、ジェネリック実体、直接呼び出し、呼び出し候補、cgo境界 |
| TypeScriptとJavaScript | npm、pnpm、Yarn、Bunワークスペース、パッケージ、ファイル、シンボル、型、インポート、再エクスポート、型利用、確定呼び出し、呼び出し候補 |
| Next.js | App RouterとPages Router、ルートコンポーネント、描画関係、親ルート、クライアント／サーバー境界、静的に解決できる動的コンポーネント |
| Astro | ページ、エンドポイント、コンポーネント、ハイドレーション境界、フロントマターのインポート、コンテンツコレクション、アセット |
| TanStack Router | ファイルルート、コードルート、仮想ルート、生成済みルートツリー、ローダー、`beforeLoad`、遅延ルート、コンテキスト、ルートマスク |
| TanStack Start | サーバー関数、RPC関係、サーバールート、ミドルウェアチェーン |

depgraphは依存先を推測で決めません。
1つに特定できない依存は、候補の集合または未解決として理由付きで報告します（[依存箇所の分類](docs/guide/usage.md#依存箇所の分類)）。

## インストール

`v0.7.3`は、Linux x86-64、Linux ARM64、macOS Apple Silicon、Windows x86-64向けの4ターゲットを提供します。
Intel macOSには対応していません。

- **Homebrew**（macOS Apple Silicon / Linux）：`brew install tamat-llc/tap/depgraph`
- **npm**（Node.js 24以上）：`npm i -g @tamat-llc/depgraph`
- **GitHub Release**：[Releasesページ](https://github.com/TamaT-LLC/depgraph-cli/releases)から`TARGET`に合うアーカイブを取得します。

| 環境 | `TARGET` |
| --- | --- |
| Linux x86-64 | `x86_64-unknown-linux-gnu` |
| Linux ARM64 | `aarch64-unknown-linux-gnu` |
| macOS Apple Silicon | `aarch64-apple-darwin` |
| Windows x86-64 | `x86_64-pc-windows-msvc` |

チェックサムの検証、Windowsでの手順、`depgraph-mcp`が使うcompiler packは[インストールガイド](docs/guide/install.md)で説明しています。

## 安全性について

既定のスキャンは、ソース、マニフェスト、ロックファイル、静的な設定ファイルを読むだけです。
プロジェクトの設定、プラグイン、パッケージマネージャー、ジェネレーター、ビルドスクリプト、手続きマクロは実行しません。
既定のスキャンでは、`project_code_executed`は`false`と記録されます。

プロジェクトのコードを実行しうるのは`depgraph resolve --build PATH --allow-project-code`だけです。
実行のたびにこのフラグが必要で、付いていなければ何も処理せずに終了コード`4`で終了します。
詳しくは[安全なスキャンの境界](docs/reference/safe-scan-boundary.ja.md)と[ビルドモードの同意境界](docs/reference/build-mode.ja.md)を参照してください。

## ドキュメント案内

| やりたいこと | 読む場所 |
| --- | --- |
| すべてのコマンド、設定、終了コードを知る | [使い方ガイド](docs/guide/usage.md) |
| インストール、アーカイブの検証、ソースからのビルド | [インストールガイド](docs/guide/install.md) |
| リリースの互換性とStore schemaを確認する | [リリースと互換性](docs/guide/compatibility.md) |
| AIエージェントとの連携を詳しく知る | [MCPエージェントホスト運用手順（英語）](docs/50_test/mcp-agent-host-operations.md) |
| CLIの詳細な契約を読む | [CLI動作リファレンス（英語）](docs/reference/cli-behavior.md) |
| アーキテクチャの規則を検査する | [アーキテクチャポリシー契約（英語）](docs/reference/architecture-policy.md) |
| 実行時トレースを取り込む | [実行時トレースの取り込み契約（英語）](docs/reference/runtime-trace.md) |
| 設計を理解する | [システム設計](docs/40_arch_design/arch-dependency-graph-cli-system-design.md) |
| すべての文書を探す | [ドキュメントインデックス](docs/00_index/index.md) |

## プロジェクトの状況と公開コラボレーション

現在のサポート対象は、公開済み`v0.6.4`リリースです。
そのtagより後の`main`の変更は開発版として扱います。
次のリリースの変更と移行手順は[`v0.7.3`リリースノート](docs/releases/v0.7.3.md)を参照してください。
製品サポートはベストエフォートであり、応答時間や解決時間のSLAは設けていません。

利用上の質問と不具合報告は[SUPPORT.md](SUPPORT.md)の案内に従ってください。
IssueやPull Requestを作成する前に[CONTRIBUTING.md](CONTRIBUTING.md)を確認してください。
意思決定とメンテナーの役割は[GOVERNANCE.md](GOVERNANCE.md)にあります。
参加者には[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)が適用されます。

脆弱性の可能性がある内容は公開Issueへ投稿せず、[SECURITY.md](SECURITY.md)に記載した非公開窓口へ報告してください。

## 開発に参加する

開発用の固定ツールチェーンは、Rust 1.93.1、Go 1.26.1、Node.js 24.18.0、pnpm 10.33.0です。
`cargo xtask build`でCLIとワーカーをビルドし、`cargo xtask test`ですべての検査を実行します。
開発の流れは[CONTRIBUTING.md](CONTRIBUTING.md)を参照してください。

<a id="license"></a>
## ライセンス

[MIT](LICENSE-MIT)または[Apache-2.0](LICENSE-APACHE)のいずれかを選択できます。

Copyright (c) 2026 TamaT LLC.
