# ビルドモードの同意境界

[English](build-mode.md) | 日本語

`depgraph resolve --build [PATH]`は、ビルドツール、実行可能な設定、プラグイン、ライフサイクルスクリプト、Rustのビルドスクリプトや手続きマクロが任意のプロジェクトコードを実行し得るため、独立した特権モードとして扱う。
対話的な確認は行わず、実行のたびに`--allow-project-code`を明示しなければならない。
設定、環境変数、`CI=true`、TTYの状態、過去の同意によって権限を付与することはできない。
同意がない場合は、パス、設定、ストア、ツールチェーンを処理する前に終了コード`4`で拒否する。
一時ワークスペースにコピーするとき、`node_modules` 配下のリポジトリ内シンボリックリンクは保持し、正規化したリンク先をコピー先内部の相対パスに置き換える。
pnpm の isolated layout で複数バージョンが共存しても、Node が実体パスを起点に依存を解決できる。パッケージマネージャーや `.npmrc` の検出は不要。
それ以外のリポジトリ内リンクは従来どおり実体化する。シンボリックリンクを作成できない環境で依存を実体化するフォールバックは行わない。
祖先ディレクトリへ戻るリンクと `.git` / `.depgraph` / リポジトリ直下の `target` / `.next` を指すリンクはコピーしない。
リポジトリ外・存在しない対象・通常ファイルやディレクトリ以外を指すリンクは拒否する。dangling link は黙って省略せず、依存の再インストールなどで修復するか、不要なリンクを明示的に除外する。
`.depgraph.toml` の `[build] ignored_paths` にリポジトリ相対プレフィックスを書くと、その配下とそこを指すリンクはステージング対象から外れる。未知の `[build]` キーはエラーになる。
Next の Node.js トレースに含まれる `node_modules` 内のディレクトリリンクは、参照先の範囲と観測前後の同一性を確認し、リンク構造の digest として記録する。
トレース対象の通常ファイルは別に内容をハッシュし、未観測のパッケージ全体を再帰走査しない。主出力・fallback・Wasm のリンクは引き続き認めない。
Edge の asset 名がビルド出力ディレクトリ基準の場合も、絶対パスと同じリポジトリ内ファイルを指すことを確認し、記録はリポジトリ相対パスに統一する。
Next 出力の ID は型と意味上のバリアントごとに検証し、ページと事前生成結果が同じ ID を使う場合も保持する。親参照は一意な主リクエスト経路に限り、同じバリアント内の重複や親の欠落・曖昧さは拒否する。
サーバーと Edge が共有するトレース済みファイルは、役割を含むノード ID で両方の読み込み関係を保持する。
Web のビルド証跡変換は入力・標準出力それぞれ 64 MiB、標準エラーの保持量 64 KiB、30 秒の上限を持つ。両出力を同時に読み、保持量を制限し、切り詰め・標準エラー・異常終了・検証失敗があれば全体を拒否する。runtime trace と query の上限は変更しない。
失敗時は redacted な stderr 末尾と一時ログパスを表示し、`--json` で機械可読な診断を返す。監査記録には raw stderr を残さない。

`Cargo.toml`と`Cargo.lock`を持つRustワークスペースはCargoで実行する。
Webプロジェクトは`package.json`にバージョン付きの`depgraph.build`実行プランを宣言する。シェルコマンドやnpm/pnpm/yarnのlifecycleは受け付けない。

```json
{
  "depgraph": {
    "build": {
      "adapter": "next",
      "entrypoint": "scripts/depgraph-build.mjs",
      "version": "16.2.3",
      "timeout_seconds": 900
    }
  }
}
```

各フィールドは厳格に検証され、未知のフィールドは設定ミスに気づけるよう拒否される。

| フィールド | 型 | 意味 |
| --- | --- | --- |
| `adapter` | 文字列 | `next`・`astro`・`tanstack-router`・`tanstack-start`のいずれか。リリースに固定された観測契約を選択する |
| `entrypoint` | 文字列 | リポジトリ相対パスのNodeスクリプト。`node <entrypoint>`として引数なしで起動される。絶対パスと`..`は拒否され、ファイルが存在しなければならない |
| `version` | 文字列 | 空でない対象フレームワークのバージョン（例: `"16.2.3"`）。JSON文字列でなければならず、数値は拒否される。AstroとTanStack系アダプターには`DEPGRAPH_ASTRO_VERSION`・`DEPGRAPH_TANSTACK_ROUTER_VERSION`・`DEPGRAPH_TANSTACK_START_VERSION`として渡される |
| `timeout_seconds` | 整数（省略可） | ビルド全体のタイムアウト（秒）。許容範囲は1〜3600で、既定は`900` |

entrypointの起動規約は次のとおりである。

- ビルドはリポジトリの一時的なステージングコピーの中で、そのルートを作業ディレクトリとして実行される。entrypointはソースを変更してはならない（変更は実行後のソース監査で失敗になる）。
- `node <entrypoint>`にCLI引数は渡されない。設定は環境変数で渡される。`DEPGRAPH_OBSERVER`はリリース同梱の観測モジュールのパス（Nextには`NEXT_ADAPTER_PATH`としても渡される）、観測結果は`DEPGRAPH_OUTPUT_DIR`へ書き出される。
- スクリプトは実際のフレームワークビルド（例: `next build`のspawn）を起動し、その終了コードで終了することが期待される。`next.config.ts`やフレームワークのバイナリを直接`entrypoint`に指定しても、観測がビルドライフサイクルへ組み込まれないため動作しない。

最小のNext.js向けentrypointの例:

```js
// scripts/depgraph-build.mjs
import { spawnSync } from "node:child_process";

const result = spawnSync(
  process.execPath,
  ["node_modules/next/dist/bin/next", "build"],
  { stdio: "inherit" },
);
process.exit(result.status ?? 1);
```

Next.jsではこの例で完結する。Next.js 16.2以降では、entrypoint自身はobserverをimportせず、`next build`が環境変数`NEXT_ADAPTER_PATH`を読み取ってリリース同梱アダプターのビルドフック（`modifyConfig`・`onBuildComplete`）を呼び出し、観測結果を`DEPGRAPH_OUTPUT_DIR`へ書き出す。この自動組み込みこそが、entrypointに本物の`next build`プロセスの起動を求める理由である。

コピーして使えるNext.js向けスクリプトは[docs/examples/next-depgraph-build.mjs](../examples/next-depgraph-build.mjs)にもある。
プランが無い場合（`depgraph`キー自体が無い、または`{"depgraph":{}}`のように`build`だけが欠ける場合）のエラーは雛形と`depgraph resolve --help`への案内を含む。`depgraph init`は`.depgraph.toml`だけを書き、`package.json`は変更しない。

ビルド監督、隔離、監査記録、フレームワーク観測の完全な契約は[英語版](build-mode.md)を参照する。
コンパイラー精密モードは[コンパイラーパックとリリース検証](compiler-pack-and-release-verification.md)を参照する。
