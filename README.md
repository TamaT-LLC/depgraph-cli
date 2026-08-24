# depgraph

日本語 | [English](README.en.md)

[![CI](https://github.com/TamaT-LLC/depgraph-cli/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/TamaT-LLC/depgraph-cli/actions/workflows/ci.yml)
[![GitHub Release](https://img.shields.io/github/v/release/TamaT-LLC/depgraph-cli)](https://github.com/TamaT-LLC/depgraph-cli/releases/latest)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

`depgraph`は、Rust、Go、TypeScript、JavaScriptのコードから、説明可能な依存グラフを構築するローカルファーストのCLIである。
Next.js、Astro、TanStack Router、TanStack Startが持つルート、コンポーネント、サーバー関数の関係も、言語の依存関係と同じグラフへ統合する。

依存関係の有無だけでは、変更の影響を判断できない。
`depgraph`は、依存箇所、解析根拠、成立条件、解析精度、プロファイル、未解決理由を保存し、「なぜ依存しているか」と「どこまで解析できたか」を問い合わせ可能にする。

## 目的別の案内

| 目的 | 読む場所 |
| --- | --- |
| まず動かす | [最初のスキャン](#最初のスキャン) |
| 対応言語と抽出範囲を確認する | [対応するコードとグラフ](#対応するコードとグラフ) |
| バイナリを導入する | [公式パッケージの導入](#公式パッケージの導入) |
| CLIの実行例を探す | [CLIコマンド例](#cliコマンド例) |
| エージェントホストから使う | [MCP stdioサーバー](#mcp-stdioサーバー) |
| 安全な静的解析の境界を確認する | [安全なスキャンの境界](#安全なスキャンの境界) |
| プロジェクトコードを実行する条件を確認する | [ビルドモードの同意境界](#ビルドモードの同意境界) |
| 詳細な技術契約を確認する | [英語版の詳細仕様](#英語版の詳細仕様) |
| 開発へ参加する | [プロジェクトの状況と公開コラボレーション](#プロジェクトの状況と公開コラボレーション) |

## 最初のスキャン

公式パッケージを展開して`depgraph`を`PATH`へ追加したら、対象リポジトリを**安全な静的解析**でスキャンする。
このモードは、対象リポジトリの設定、プラグイン、ビルドスクリプト、パッケージマネージャーを実行しない。

```sh
depgraph scan /path/to/repository
depgraph doctor
```

解析結果は、正規化したリポジトリルートごとにOSのキャッシュディレクトリ内のSQLiteストアへ保存される。
保存先を固定する場合は、`depgraph --store /path/to/depgraph.sqlite scan /path/to/repository`のようにグローバルオプションを指定する。
設定ファイルは必須ではなく、`depgraph init /path/to/repository`を実行した場合だけ`.depgraph.toml`を書き込む。

スキャン後は、ファイルやパッケージをセレクターで指定してグラフを調べる。
次の例にある`src/app.ts`は、対象リポジトリ内の実際のパスへ置き換える。

```sh
# このファイルが利用している依存先
depgraph deps path:src/app.ts --transitive

# このファイルを利用している依存元
depgraph dependents path:src/app.ts --transitive

# 二つのノードを結ぶ依存経路と根拠
depgraph why path:src/app.ts package:example

# 変更による影響範囲
depgraph impact path:src/app.ts --changed origin/main

# 共有用のMermaidグラフ
depgraph export --format mermaid > graph.mmd
```

`depgraph scan --strict`は、スキップ、未対応構文、未解決箇所を許容しないCI向けの実行である。
通常の探索では、まず既定のスキャンを実行し、`doctor`と`unresolved`で解析範囲を確認する。

## 調査目的とコマンド

| 調べたいこと | コマンド | 得られる情報 |
| --- | --- | --- |
| 依存先 | `deps <SELECTOR>` | 選択したノードから出る依存関係 |
| 依存元 | `dependents <SELECTOR>` | 選択したノードへ入る依存関係 |
| 依存理由 | `why <FROM> <TO>` | 二つのノードを結ぶ経路、条件、ソース位置 |
| 変更影響 | `impact <SELECTOR>` | 逆向きの依存経路と影響を受けるノード |
| 循環依存 | `cycles` | パッケージ、ファイル、シンボル単位の循環 |
| 解析できなかった箇所 | `unresolved` | 理由とソース位置を含む未解決台帳 |
| 解析状態 | `doctor` | ワーカー、ツールチェーン、カバレッジ、キャッシュの状態 |
| スナップショット差分 | `snapshot`、`diff` | 完了済みグラフ間の追加、削除、変更、名前変更 |
| アーキテクチャ規則 | `policy` | 禁止依存、境界違反、公開API変更 |
| 実行時依存 | `runtime validate`、`runtime import` | 検証済みトレースと静的グラフの統合結果 |
| グラフ出力 | `export` | JSON、DOT、Mermaid、GraphML |
| エージェントからの調査 | `agent-config`、`depgraph-mcp` | 検証済みパッケージに結び付いたMCPホスト設定 |

**セレクター**は、グラフ内のノードをCLIから指定するための表現である。
`id:`、`path:`、`package:`、`route:`、`symbol:`、`type:`を受け付ける。
候補が複数ある場合は、コマンドが返した完全な安定IDを`id:<stable-id>`として指定する。

## 対応するコードとグラフ

| 対象 | 抽出する主な要素 |
| --- | --- |
| Rust | Cargoワークスペース、パッケージ、ターゲット、モジュール、インポート、再エクスポート、シンボル、型、型利用、確定呼び出し、呼び出し候補 |
| Go | ワークスペース、モジュール、パッケージ派生形、ビルド条件、インポート、シンボル、型、ジェネリック実体、直接呼び出し、呼び出し候補、cgo境界 |
| TypeScriptとJavaScript | npm、pnpm、Yarn、Bunワークスペース、パッケージ、ファイル、シンボル、型、インポート、再エクスポート、型利用、確定呼び出し、呼び出し候補 |
| Next.js | App RouterとPages Router、ルートコンポーネント、描画関係、親ルート、クライアント／サーバー境界、静的に解決できる動的コンポーネント |
| Astro | ページ、エンドポイント、コンポーネント、ハイドレーション境界、フロントマターのインポート、コンテンツコレクション、アセット |
| TanStack Router | ファイルルート、コードルート、仮想ルート、生成済みルートツリー、ローダー、`beforeLoad`、遅延ルート、コンテキスト、ルートマスク |
| TanStack Start | サーバー関数、RPC関係、サーバールート、ミドルウェアチェーン |

静的解析で認識した依存箇所は、次のいずれかに分類される。

- **`resolved`**：根拠から依存先を一意に特定できた。
- **`candidates`**：有限の候補集合までは絞り込めたが、一意性を証明できない。
- **`external`**：標準ライブラリや外部パッケージなど、リポジトリ外の依存先である。
- **`unresolved`**：依存箇所は認識したが、依存先を安全に特定できない。

この分類は「未解決の依存を推測で`resolved`へ昇格する」ことを避けるためにある。
スキップした入力と未対応の入力はカバレッジ台帳へ記録する。
利用者は、抽出したグラフと解析範囲の完全性を分けて評価できる。

## 公式パッケージの導入

以下は、公式Releaseと公開後証跡が揃った後に適用される導入案内である。
`v0.5.3`は、Linux x86-64、Linux ARM64、macOS Intel、macOS Apple Silicon、Windows x86-64向けのネイティブパッケージを提供する。
`v0.5.0`はGitHub Releaseのみで配布し、npm版は`v0.5.1`から提供する。
npm版はTamaT LLCの組織スコープ`@tamat-llc`から公開する。

`npm i -g @tamat-llc/depgraph`により、同じ5ターゲットの検証済みネイティブパッケージを導入できる。
インストールスクリプトによる外部ダウンロードは行わない。
npm版のランチャーにはNode.js 24以上が必要である。
`depgraph` CLIはnpmから導入したパッケージだけで実行できる。
`depgraph-mcp`も同じnpmパッケージから導入されるが、MCPサーバーの起動には同じバージョンとターゲットのGitHub Releaseにあるコンパイラーパックを検証して展開し、その要件ファイルを追加で指定する。
公開状態と初回導入は[npmリリース手順](docs/50_test/npm-release-procedure.md)で確認する。

対象に対応する`TARGET`は次の値から選ぶ。

| 環境 | `TARGET` |
| --- | --- |
| Linux x86-64 | `x86_64-unknown-linux-gnu` |
| Linux ARM64 | `aarch64-unknown-linux-gnu` |
| macOS Intel | `x86_64-apple-darwin` |
| macOS Apple Silicon | `aarch64-apple-darwin` |
| Windows x86-64 | `x86_64-pc-windows-msvc` |

公開完了後、macOSまたはLinuxでは、GitHub CLIでアーカイブとチェックサムを取得できる。

```sh
VERSION=0.5.3
TARGET=aarch64-apple-darwin
ARCHIVE="depgraph-${VERSION}-${TARGET}.tar.gz"

gh release download "v${VERSION}" \
  --repo TamaT-LLC/depgraph-cli \
  --pattern "${ARCHIVE}" \
  --pattern "${ARCHIVE}.sha256"
```

ダウンロード後にチェックサムを検証してから展開する。
macOSでは`shasum`、Linuxでは`sha256sum`を使う。

```sh
# macOS
shasum -a 256 --check "${ARCHIVE}.sha256"

# Linux
sha256sum --check "${ARCHIVE}.sha256"

tar -xzf "${ARCHIVE}"
"./depgraph-${VERSION}-${TARGET}/bin/depgraph" --version
```

Windowsでは同じリリースから`.zip`と`.zip.sha256`を取得し、`Get-FileHash -Algorithm SHA256`で照合してから`Expand-Archive`で展開する。
リリースのSBOM、ライセンス一覧、互換性情報はアーカイブに同梱される。

## ソースからのビルド

開発用の固定ツールチェーンは、Rust 1.93.1、Go 1.26.1、Node.js 24.18.0、pnpm 10.33.0である。
リポジトリのルートで次を実行すると、CLIとRust、Go、Webの各ワーカーをビルドする。

```sh
cargo xtask build
target/debug/depgraph --version
```

フォーマット、リント、契約テスト、ワーカーテスト、フィクスチャーテストをまとめて実行する場合は`cargo xtask test`を使う。
開発手順と必要なコマンドは[CONTRIBUTING.md](CONTRIBUTING.md)に記載している。

## リリースと互換性

`main`は[`v0.5.3`リリースノート](docs/releases/v0.5.3.md)に記載した`0.5.3`契約を実装している。
正式版は、[`v0.5.3` GitHub Release](https://github.com/TamaT-LLC/depgraph-cli/releases/tag/v0.5.3)と公開後証跡が一致するときに限り有効である。
MVPは[システム設計](docs/40_arch_design/arch-dependency-graph-cli-system-design.md)に記載したアーキテクチャを実装している。

すべてのv0.5アーカイブには、ネイティブMCPサーバー、永続的な操作ランナー、バージョン管理されたエージェント用ツール／操作スキーマが含まれる。
v0.5のワーカープロトコルは`1.0`、ストアスキーマは`17`、操作ジャーナルスキーマは`5`であり、`depgraph-mcp-tools-v1`と`depgraph-operation-v1`を使用する。

`v0.4.0`は予約済みベースラインの履歴記録であり、正式版は公開されなかった。
履歴上の契約は[`v0.4.0`の契約](docs/releases/v0.4.0.md)に残している。
過去のリリース候補は[`v0.4.0-rc.6`](docs/releases/v0.4.0-rc.6.md)、[`v0.4.0-rc.2`](docs/releases/v0.4.0-rc.2.md)、[`v0.4.0-rc.1`](docs/releases/v0.4.0-rc.1.md)、[`v0.2.0-rc.1`](docs/releases/v0.2.0-rc.1.md)で確認できる。

完全な互換性タプル、ストア移行、ロールバック、既知の制約は[`v0.5.3`リリースノート](docs/releases/v0.5.3.md)を参照する。

## プロジェクトの状況と公開コラボレーション

サポート対象は、検証済みの`v0.5.3`リリースを条件として確定する。
`v0.5.3`は、公式リリースと公開後証跡の公開後に現在の安定版となる。
それまでは`v0.5.2`が安定版であり、リリース候補は評価用の過去の配布物である。
製品サポートはベストエフォートであり、応答時間や解決時間のSLAは設けていない。

利用上の質問と不具合報告は[SUPPORT.md](SUPPORT.md)の案内に従う。
IssueやPull Requestを作成する前に[CONTRIBUTING.md](CONTRIBUTING.md)を確認し、意思決定とメンテナーの役割は[GOVERNANCE.md](GOVERNANCE.md)を参照する。
参加者には[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)が適用される。

脆弱性の可能性がある内容は公開Issueへ投稿せず、[SECURITY.md](SECURITY.md)に記載した非公開窓口へ報告する。
ライセンスは[MIT](LICENSE-MIT)または[Apache-2.0](LICENSE-APACHE)から選択できる。

## 解析結果の完全性

**`semantic-complete`**は、プロファイルのセマンティック解析が所定の完全性条件を満たしたことを示す。
「依存関係を推測で補完した」という印ではない。
構文解析が完了し、互換性を検証したセマンティックバックエンドがグラフを生成し、セマンティック問題、スキップ、未対応、未解決がすべて0件になったプロファイルだけに付与される。
`candidates`と`external`は状態が明示されるため、この判定を妨げない。

Rustのセマンティックバックエンドは、隔離したCargoメタデータ、準備済みプロジェクトモデル、検証済みRust `1.93.1`ツールチェーンを使用する。
`depgraph`は`RUSTUP_AUTO_INSTALL=0`を設定し、必要なツールチェーンがない場合は暗黙にインストールせず、導入手順を診断へ出力する。
ソースビルドは`rust_hir_enable_gate=release-gate-pending`を報告し、検証済みリリースアーカイブから起動したワーカーだけが`release-gate-verified`を報告できる。

Webの`semantic-complete`は、同梱した隔離済みTypeScriptコンパイラー、生成済みv2グラフ、0件のスキップ、未対応、未解決、セマンティック問題、コンパイラー診断を要求する。
Next.js、Astro、TanStack Router、TanStack Startを検出した場合は、対応するフレームワーク能力台帳の完了も要求する。

静的グラフに加えて、アーキテクチャポリシー、GitHub注釈、実行時トレース、不変スナップショット、スナップショット差分、Git変更集合の影響分析、GraphML、監視デーモンを利用できる。
ビルド観測は別の権限境界に置かれ、明示的な同意がある実行だけが対象プロジェクトのコードを起動する。

## 開発時の品質検証

すべてのフォーマット、リント、契約、ワーカー、フィクスチャーテストを実行する。

```sh
cargo xtask test
```

再現可能な性能ゲートは、固定ツールチェーンと決定的に生成したフィクスチャーを使用する。

```sh
scripts/benchmark-mvp.sh
```

ベンチマークは100、1,000、10,000ソースファイルのフィクスチャーと、31ソースファイルのRust HIRフィクスチャーを生成する。
結果は`dist/benchmark-report.json`と`dist/cache-hit-benchmark-report.json`へ保存する。
測定対象にはコールドスキャン、1ファイルの増分スキャン、影響クエリー、セマンティックキャッシュヒット、Rust HIRのコールド実行とウォーム実行を含む。
各フィクスチャーでは正規グラフとカバレッジの一致を保ち、キャッシュヒットの中央値が5%以上高速であることを検証する。

## CLIコマンド例

```sh
# 任意の追跡対象設定。設定がなくてもスキャンできる。
depgraph init .

# 安全な静的解析。対象リポジトリを変更しない。
depgraph scan /path/to/repository
depgraph scan /path/to/repository --strict
depgraph scan /path/to/repository --no-cache

# ワーカーの起動やストアの変更をせず、プロファイル選択を確認する。
depgraph profiles plan /path/to/repository
depgraph profiles plan /path/to/repository --profile-budget 8 --json
depgraph profiles plan /path/to/repository --profiles-file profiles.json --json

# 前景で監視デーモンを起動し、別のプロセスから状態確認と停止を行う。
depgraph daemon start /path/to/repository
depgraph daemon status /path/to/repository --json
depgraph daemon stop /path/to/repository

# 権限を伴うビルド観測。実行ごとに明示的な同意が必要になる。
depgraph resolve --build /path/to/repository --allow-project-code

depgraph doctor --json
depgraph doctor --details --json
depgraph doctor --root /path/to/repository --json
depgraph deps path:src/app.ts --transitive --max-items 100 --max-bytes 1048576
depgraph deps path:src/app.ts --transitive --cursor "$NEXT_CURSOR" --json
depgraph deps path:src/app.ts --transitive --all --json
depgraph dependents package:example
depgraph why path:src/app.ts route:/products/$id
depgraph impact path:src/app.ts
depgraph impact package:example --changed origin/main --depth 4
depgraph impact route:/products/$id --changed HEAD~1 --profile web:production:server --json
depgraph cycles --level file

# Goのセマンティックグラフでは正規リゾルバーIDを使う。
depgraph deps symbol:example.com/semantic/model.Build --transitive
depgraph dependents type:example.com/semantic/model.Worker --json
depgraph why symbol:example.com/semantic/model.Build type:example.com/semantic/model.Input --json
depgraph cycles --level symbol

# セレクターが曖昧な場合は、候補に含まれる安定IDで再実行する。
depgraph deps "id:$STABLE_ID" --json

depgraph unresolved --max-items 100 --json
depgraph unresolved --all --json

# ストアを変更せず、外部の実行時トレースを検証してグラフと照合する。
depgraph runtime validate --file runtime-trace.json
depgraph runtime validate --file runtime-trace.json --json

# 完了済みの不変スナップショットに名前を付けて確認する。
depgraph snapshot create baseline
depgraph snapshot list --json
depgraph snapshot show baseline
depgraph snapshot show snapshot:sha256:... --json

# 名前または安定IDで完了済みスナップショットを比較する。
depgraph diff baseline current
depgraph diff baseline current --json
depgraph diff baseline current --kind symbol --profile web:production:server
depgraph diff baseline current --phase semantic --status unresolved

depgraph export --format json --output graph.json
depgraph export --format dot > graph.dot
depgraph export --format mermaid > graph.mmd
depgraph export --format graphml --output graph.graphml
```

## MCP stdioサーバー

`depgraph-mcp`は、ネイティブパッケージに含まれるMCP stdioサーバーである。
既定の`read`権限では、ストアの変更、リポジトリへの書き込み、デーモン制御、プロジェクトコードの実行を許可しない。
固定したリポジトリルート、絶対パスで指定したストア、検証済みコンパイラーパックの要件ファイルが必要になる。

公式stable版の`depgraph`を導入した後、対象Gitリポジトリ内で次を実行すると、artifactの取得と検証、安全な初回スキャン、package/MCP preflight、project-scopedなCodex設定のatomic mergeまでを一括して行える。

```sh
depgraph mcp setup --host codex
```

既定ではruntimeとcompiler packをversion／target単位で共有し、ストアと`.codex/config.toml`はcanonical repository rootごとに分離する。
設定はread-onlyで固定され、既存の無関係なCodex設定、コメント、書式を保持する。
完了後はCodexを再起動する。
再実行はidempotentであり、運用には次のコマンドを使う。

```sh
depgraph mcp status --host codex
depgraph mcp update --host codex
depgraph mcp uninstall --host codex
```

`status`はartifact、Store binding、snapshot、host設定、MCP接続を再検証する。
`update`は実行中CLIのversionへ整合させてsafe snapshotを更新する。
`setup`／`update`／`uninstall`は同じrepository lifecycle lockで直列化される。
`uninstall`は管理cache配下の完全なread-only起動tupleを所有権として検証し、state未作成の場合もscan、daemon、durable operation runnerの排他を必ず確立してからrepository固有の設定とstateだけを削除し、共有artifactと安全な再利用に必要な空のlock sentinelを残す。
中断後は同じ`setup`を再実行する。
root判定、公開Release、cache、設定、再起動の問題は[MCPエージェントホスト運用手順](docs/50_test/mcp-agent-host-operations.md)のtroubleshootingを参照する。

リリース証跡の検証、`agent-config`によるホスト設定、権限プロファイル、再接続、キャンセルの詳細は、[英語版のMCP stdioサーバー節](README.en.md#mcp-stdio-server)と[MCPエージェントホスト運用手順](docs/50_test/mcp-agent-host-operations.md)を参照する。

## 安全なスキャンの境界

既定のスキャンは、ソース、マニフェスト、ロックファイル、静的なJSON／JSONC設定、既存の生成済みファイルを読み取る。
プロジェクト設定、プラグイン、パッケージマネージャー、ジェネレーター、ビルドスクリプト、手続きマクロ、プロジェクト内のTypeScriptは実行しない。
Webワーカーは同梱したTypeScriptを使用し、GoとCargoの解析もネットワークやリポジトリ書き込みを無効にしたオフライン境界内で行う。

ワーカーとツールチェーンの探索には正規化した絶対`PATH`を使い、相対要素、スキャンルート、そのルートを指すシンボリックリンクを除外する。
リリースマニフェスト、ワーカー、スキーマ、実行時部品、宣言済み成果物は、パッケージ済みワーカーを起動する前にチェックサムを検証する。

実行形式または未対応の設定は、診断か未解決箇所として記録する。
ワーカープロファイル、カバレッジ、保存済みスキャン、`doctor`の`project_code_executed`は`false`のままである。
完全な境界は[英語版の安全なスキャン節](README.en.md#safe-scan-boundary)を参照する。

## ビルドモードの同意境界

`depgraph resolve --build [PATH]`は、ビルドツール、実行可能な設定、プラグイン、ライフサイクルスクリプト、Rustのビルドスクリプトや手続きマクロが任意のプロジェクトコードを実行し得るため、独立した特権モードとして扱う。
対話的な確認は行わず、実行のたびに`--allow-project-code`を明示しなければならない。
設定、環境変数、`CI=true`、TTYの状態、過去の同意によって権限を付与することはできない。
同意がない場合は、パス、設定、ストア、ツールチェーンを処理する前に終了コード`4`で拒否する。

ビルド監督、隔離、監査記録、フレームワーク観測、コンパイラー精密モードの完全な契約は[英語版のビルドモード節](README.en.md#build-mode-consent-boundary)を参照する。

## 厳格ポリシーと終了コード

既定の`.depgraph.toml`の厳格ポリシーでは、スキップしたファイル、未対応構文、未解決箇所を許容しない。
候補依存と外部依存だけでは厳格モードの失敗にならない。

| コード | 意味 |
| ---: | --- |
| 0 | ポリシー違反なしで処理が完了した |
| 1 | グラフまたはカバレッジのポリシー違反 |
| 2 | CLIの使用方法、セレクター、設定のエラー |
| 3 | ワーカー、ツールチェーン、グラフ検証、プロトコルの失敗 |
| 4 | プロジェクトコード実行権限またはセキュリティポリシーの失敗 |

失敗または部分的なスキャンと診断は保存されるが、`latest successful`が指す先を更新するのは、ポリシーを通過した完全なスキャンだけである。

## リポジトリ構成

- `crates/depgraph-protocol`：型付きプロトコル、正規条件／ID、JSON Schema、状態機械の検証
- `crates/depgraph-store`：SQLite移行、不変スキャンのステージング、台帳、根拠の永続化
- `crates/depgraph-rustc-wrapper`：検証済みの全ユニット用rustcラッパーと有界な開始／終了台帳の出力
- `crates/depgraph-core`、`crates/depgraph-cli`：ワーカー監督、クエリー、出力、診断、CLI操作
- `workers/rust`、`workers/go`、`workers/web`：各エコシステム向けの安全な静的解析アダプター
- `xtask`：再現可能なビルド、全品質検証、リリースアーカイブ、チェックサム、SBOM、ライセンス一覧

## 英語版の詳細仕様

言語ごとのREADMEを混在させないため、長い技術契約と運用手順は英語版へ集約している。

- [アーキテクチャポリシー契約](README.en.md#architecture-policy-contract)
- [実行時トレースの取り込み契約](README.en.md#runtime-trace-import-contract)
- [安全なスキャンの完全な境界](README.en.md#safe-scan-boundary)
- [ビルドモードの完全な同意境界](README.en.md#build-mode-consent-boundary)
- [コンパイラーパックとリリース検証](README.en.md#compiler-pack-and-release-verification)

<a id="license"></a>
## ライセンス

[MIT](LICENSE-MIT)または[Apache-2.0](LICENSE-APACHE)のいずれかを選択できる。

Copyright (c) 2026 TamaT LLC.
