# インストールガイド

日本語 | [English](install.en.md)

[README](../../README.md)には最短の導入コマンドだけを載せています。
このガイドでは、配布経路ごとの導入方法、アーカイブの検証、ソースからのビルドを説明します。

以下のダウンロード例は、公開済みの `v0.6.4` を使います。

## 対応ターゲット

`v0.6.4`は、Linux x86-64、Linux ARM64、macOS Apple Silicon、Windows x86-64の4ターゲットを提供します。
Intel macOSには対応していません。
公式Releaseと公開後証跡がそろった版を使ってください。

## Homebrew（macOS Apple Silicon / Linux）

```sh
brew install tamat-llc/tap/depgraph
```

初回の導入後はtap名を省略できます。

```sh
brew install depgraph
brew upgrade depgraph
```

tapを追加済みで信頼設定がない場合は、先に`brew trust --formula tamat-llc/tap/depgraph`を実行します。
Node.js 24系と、ワーカー・schema・ライセンスを含む公式パッケージが入ります。
HomebrewのNode.jsが検証済みの`24.18.0`と異なる場合、Web解析は診断付きのbest-effortになります。
Go / Rustの解析には、対象プロジェクトのツールチェーンとオフラインの依存関係が必要です。
`depgraph-mcp`の起動には、後述する同じ版・ターゲットのcompiler packも必要です。
公開・更新の手順は[Homebrewリリース手順](../50_test/homebrew-release-procedure.md)を参照してください。

## npm / GitHub Release

`v0.5.0`はGitHub Releaseだけで配布し、npm版は`v0.5.1`から提供しています。
npm版はTamaT LLCの組織スコープ`@tamat-llc`から公開しています。

`npm i -g @tamat-llc/depgraph`で、macOS Apple Silicon、Linux x86-64 / ARM64、Windows x86-64向けの検証済みネイティブパッケージを導入できます。
インストールスクリプトによる外部ダウンロードは行いません。
npm版のランチャーにはNode.js 24以上が必要です。
`depgraph` CLIは、npmから導入したパッケージだけで動きます。
`depgraph-mcp`も同じnpmパッケージに含まれます。
ただしMCPサーバーを起動するには、同じバージョンとターゲットのGitHub Releaseにあるcompiler packを検証して展開し、その要件ファイルを指定する必要があります。
公開状態と初回導入は[npmリリース手順](../50_test/npm-release-procedure.md)で確認できます。

`TARGET`は、環境に合わせて次の値から選びます。

| 環境 | `TARGET` |
| --- | --- |
| Linux x86-64 | `x86_64-unknown-linux-gnu` |
| Linux ARM64 | `aarch64-unknown-linux-gnu` |
| macOS Apple Silicon | `aarch64-apple-darwin` |
| Windows x86-64 | `x86_64-pc-windows-msvc` |

macOSまたはLinuxでは、GitHub CLIでアーカイブとチェックサムを取得できます。

```sh
VERSION=0.6.4
TARGET=aarch64-apple-darwin
ARCHIVE="depgraph-${VERSION}-${TARGET}.tar.gz"

gh release download "v${VERSION}" \
  --repo TamaT-LLC/depgraph-cli \
  --pattern "${ARCHIVE}" \
  --pattern "${ARCHIVE}.sha256"
```

ダウンロードしたら、チェックサムを検証してから展開します。
macOSでは`shasum`、Linuxでは`sha256sum`を使います。

```sh
# macOS
shasum -a 256 --check "${ARCHIVE}.sha256"

# Linux
sha256sum --check "${ARCHIVE}.sha256"

tar -xzf "${ARCHIVE}"
"./depgraph-${VERSION}-${TARGET}/bin/depgraph" --version
```

配布物がその環境で正しく動くかは、このリポジトリのルートで次の1コマンドを実行して確認できます。
チェックサムは`<archive>.sha256`から自動で読み取ります。

```sh
cargo xtask verify-release-archive --archive "/absolute/path/to/${ARCHIVE}"
```

このコマンドは、チェックアウトと同じバージョンのネイティブアーカイブだけを受け付けます。
manifestで宣言された必須成果物の整合性、`doctor`、Web / Rust / Go scan、query / export、MCP onboardingとoperationを一時ディレクトリで検証します。
追跡対象のソースや通常のStoreは変更しません。
完全なnative package gateを実行するため、環境によっては30分以上かかります。
対象は通常アーカイブ単体です。
RC tag、公開後証跡、compiler pack archiveの真正性は、公開後検証で別に確認します。

Windowsでは、同じリリースから`.zip`と`.zip.sha256`を取得します。
`Get-FileHash -Algorithm SHA256`で照合してから、`Expand-Archive`で展開してください。
リリースのSBOM、ライセンス一覧、互換性情報はアーカイブに同梱されています。

## `depgraph-mcp`のcompiler pack

`depgraph-mcp`とopt-inのRust compiler-precise modeには、同じリリース・ターゲットのcompiler packが必要です。
通常は`depgraph mcp setup`が自動で取得・検証します。
手動で取得・検証する手順は[コンパイラーパックとリリース検証](../reference/compiler-pack-and-release-verification.md)（英語）を参照してください。

## ソースからのビルド

開発用の固定ツールチェーンは、Rust 1.93.1、Go 1.26.1、Node.js 24.18.0、pnpm 10.33.0です。
リポジトリのルートで次を実行すると、CLIとRust、Go、Webの各ワーカーをビルドします。

```sh
cargo xtask build
target/debug/depgraph --version
```

フォーマット、リント、契約テスト、ワーカーテスト、フィクスチャーテストをまとめて実行する場合は`cargo xtask test`を使います。
開発手順と必要なコマンドは[CONTRIBUTING.md](../../CONTRIBUTING.md)に記載しています。
