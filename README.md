# depgraph

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
| Agentホストから使う | [MCP stdioサーバー](#mcp-stdioサーバー) |
| 安全な静的解析の境界を確認する | [Safe-scan boundary](#safe-scan-boundary) |
| プロジェクトコードを実行する条件を確認する | [Build-mode consent boundary](#build-mode-consent-boundary) |
| 設計と契約を確認する | [システム設計](docs/40_arch_design/arch-dependency-graph-cli-system-design.md) |
| 開発へ参加する | [プロジェクトへの参加](#project-status-and-public-collaboration) |

## 最初のスキャン

公式パッケージを展開して`depgraph`を`PATH`へ追加したら、対象リポジトリを**安全な静的解析**でスキャンする。
このモードは、対象リポジトリの設定、プラグイン、ビルドスクリプト、パッケージマネージャーを実行しない。

```sh
depgraph scan /path/to/repository
depgraph doctor
```

解析結果は、Canonical Repository RootごとにOSのキャッシュディレクトリ内のSQLite Storeへ保存される。
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
| 解析状態 | `doctor` | Worker、ツールチェーン、カバレッジ、キャッシュの状態 |
| スナップショット差分 | `snapshot`、`diff` | 完了済みグラフ間の追加、削除、変更、名前変更 |
| アーキテクチャ規則 | `policy` | 禁止依存、境界違反、公開API変更 |
| 実行時依存 | `runtime validate`、`runtime import` | 検証済みトレースと静的グラフの統合結果 |
| グラフ出力 | `export` | JSON、DOT、Mermaid、GraphML |
| Agentからの調査 | `agent-config`、`depgraph-mcp` | 検証済みパッケージに結び付いたMCPホスト設定 |

**セレクター**は、グラフ内のノードをCLIから指定するための表現である。
`id:`、`path:`、`package:`、`route:`、`symbol:`、`type:`を受け付ける。
候補が複数ある場合は、コマンドが返した完全なStable IDを`id:<stable-id>`として指定する。

## 対応するコードとグラフ

| 対象 | 抽出する主な要素 |
| --- | --- |
| Rust | Cargo workspace、package、target、module、import、re-export、symbol、type、type-use、exact call、candidate call |
| Go | workspace、module、package variant、build constraint、import、symbol、type、generic instance、direct call、candidate call、cgo境界 |
| TypeScriptとJavaScript | npm、pnpm、Yarn、Bun workspace、package、file、TypeScript/JavaScript symbol/type/import/re-export/type-use、exact call、candidate call |
| Next.js | App RouterとPages Router、route component、render関係、親ルート、client/server境界、静的に解決できるdynamic component |
| Astro | page、endpoint、component、hydration境界、frontmatter import、content collection、asset |
| TanStack Router | file route、code route、virtual route、generated route tree、loader、`beforeLoad`、lazy route、context、route mask |
| TanStack Start | server function、RPC関係、server route、middleware chain |

静的解析で認識した依存箇所は、次のいずれかに分類される。

- **`resolved`**：根拠から依存先を一意に特定できた。
- **`candidates`**：有限の候補集合までは絞り込めたが、一意性を証明できない。
- **`external`**：標準ライブラリや外部パッケージなど、リポジトリ外の依存先である。
- **`unresolved`**：依存箇所は認識したが、依存先を安全に特定できない。

この分類は「未解決の依存を推測で`resolved`へ昇格する」ことを避けるためにある。
スキップした入力と未対応の入力は**Coverage Ledger**へ記録する。
利用者は、抽出したグラフと解析範囲の完全性を分けて評価できる。

## 公式パッケージの導入

`v0.5.1`は、Linux x86-64、Linux ARM64、macOS Intel、macOS Apple Silicon、Windows x86-64向けのネイティブパッケージを提供する。
`v0.5.0`はGitHub Releaseのみで配布し、npm版は`v0.5.1`から提供する。
npm版はTamaT LLCのorganization scopeである`@tamat-llc`から公開する。
`npm i -g @tamat-llc/depgraph`により同じ5 targetの検証済みnative packageを導入でき、install scriptによる外部downloadは行わない。
公開状態と初回bootstrapは[npmリリース手順](docs/50_test/npm-release-procedure.md)で確認する。
対象に対応する`TARGET`は次の値から選ぶ。

| 環境 | `TARGET` |
| --- | --- |
| Linux x86-64 | `x86_64-unknown-linux-gnu` |
| Linux ARM64 | `aarch64-unknown-linux-gnu` |
| macOS Intel | `x86_64-apple-darwin` |
| macOS Apple Silicon | `aarch64-apple-darwin` |
| Windows x86-64 | `x86_64-pc-windows-msvc` |

macOSまたはLinuxでは、GitHub CLIでアーカイブとチェックサムを取得できる。

```sh
VERSION=0.5.1
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

Windowsでは同じReleaseから`.zip`と`.zip.sha256`を取得し、`Get-FileHash -Algorithm SHA256`で照合してから`Expand-Archive`で展開する。
リリースのSBOM、ライセンス一覧、互換性情報はアーカイブに同梱される。

## ソースからのビルド

開発用の固定ツールチェーンは、Rust 1.93.1, Go 1.26.1, Node.js 24.18.0, and pnpm 10.33.0 である。
リポジトリのルートで次を実行すると、CLIとRust、Go、Webの各Workerをビルドする。

```sh
cargo xtask build
target/debug/depgraph --version
```

フォーマット、Lint、契約テスト、Workerテスト、Fixtureテストをまとめて実行する場合は`cargo xtask test`を使う。
開発手順と必要なコマンドは[CONTRIBUTING.md](CONTRIBUTING.md)に記載している。

## リリースと互換性

`main`は[`v0.5.1` release notes](docs/releases/v0.5.1.md)に記載した`0.5.1`契約を実装している。
正式版は、[`v0.5.1` GitHub Release](https://github.com/TamaT-LLC/depgraph-cli/releases/tag/v0.5.1)と公開後証跡が一致するときに限り有効である。
The MVP implements the architecture described in [the system design](docs/40_arch_design/arch-dependency-graph-cli-system-design.md).

Every v0.5 archive includes the native MCP server, durable
operation runner, and versioned Agent tool/operation schema.
The worker protocol remains at `1.0` for v0.5, with Store
schema `17`, operation journal schema `5`, `depgraph-mcp-tools-v1`, and
`depgraph-operation-v1`.

`v0.4.0`は予約済みベースラインの履歴記録であり、正式版は公開されなかった（no `v0.4.0` stable GitHub Release was published）。
履歴上の契約は[`v0.4.0` contract](docs/releases/v0.4.0.md)に残している。
過去のRelease Candidateは[`v0.4.0-rc.6`](docs/releases/v0.4.0-rc.6.md)、[`v0.4.0-rc.2`](docs/releases/v0.4.0-rc.2.md)、[`v0.4.0-rc.1`](docs/releases/v0.4.0-rc.1.md)、[`v0.2.0-rc.1`](docs/releases/v0.2.0-rc.1.md)で確認できる。

完全な互換性タプル、Store移行、ロールバック、既知の制約は[`v0.5.1` release notes](docs/releases/v0.5.1.md)を参照する。

## Project status and public collaboration

The supported line is conditionally anchored by the verified `v0.5.1` Release.
`v0.5.1`は、公式Releaseとpost-publish evidenceの公開後に現在の安定版となる。
それまでは`v0.5.0`が安定版であり、Release Candidateは評価用の過去の配布物である。
製品サポートはベストエフォートであり、応答時間や解決時間のSLAは設けていない。

利用上の質問と不具合報告は[SUPPORT.md](SUPPORT.md)の案内に従う。
IssueやPull Requestを作成する前に[CONTRIBUTING.md](CONTRIBUTING.md)を確認し、意思決定とメンテナーの役割は[GOVERNANCE.md](GOVERNANCE.md)を参照する。
参加者には[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)が適用される。

脆弱性の可能性がある内容は公開Issueへ投稿せず、[SECURITY.md](SECURITY.md)に記載した非公開窓口へ報告する。
ライセンスは[MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE)から選択できる。

## 解析結果の完全性

**`semantic-complete`**は、プロファイルのセマンティック解析が所定の完全性条件を満たしたことを示す。
「依存関係を推測で補完した」という印ではない。
構文解析が完了し、互換性を検証したSemantic Backendがグラフを生成し、Semantic Issue、スキップ、未対応、未解決がすべて0件になったプロファイルだけに付与される。
`candidates`と`external`は状態が明示されるため、この判定を妨げない。

RustのSemantic Backendは、隔離したCargo Metadata、準備済みProject Model、検証済みRust `1.93.1`ツールチェーンを使用する。
`depgraph`は`RUSTUP_AUTO_INSTALL=0`を設定し、必要なツールチェーンがない場合は暗黙にインストールせず、導入手順を診断へ出力する。
ソースビルドは`rust_hir_enable_gate=release-gate-pending`を報告し、検証済みRelease Archiveから起動したWorkerだけが`release-gate-verified`を報告できる。

Webの`semantic-complete`は、同梱した隔離済みTypeScript Compiler、生成済みv2グラフ、0件のスキップ、未対応、未解決、Semantic Issue、Compiler Diagnosticを要求する。
Next.js、Astro、TanStack Router、TanStack Startを検出した場合は、対応するFramework Capability Ledgerの完了も要求する。

静的グラフに加えて、Architecture Policy、GitHub Annotation、Runtime Trace、Immutable Snapshot、Snapshot Diff、Git Changed-set Impact、GraphML、監視Daemonを利用できる。
ビルド観測は別の権限境界に置かれ、明示的な同意がある実行だけが対象プロジェクトのコードを起動する。

## 開発時の品質検証

すべてのFormat、Lint、Contract、Worker、Fixture Testを実行する。

```sh
cargo xtask test
```

再現可能なPerformance Gateは、固定ツールチェーンと決定的に生成したFixtureを使用する。

```sh
scripts/benchmark-mvp.sh
```

Benchmarkは100、1,000、10,000ソースファイルのFixtureと、31ソースファイルのRust HIR Fixtureを生成する。
結果は`dist/benchmark-report.json`と`dist/cache-hit-benchmark-report.json`へ保存する。
測定対象にはCold Scan、1ファイルのIncremental Scan、Impact Query、Semantic Cache Hit、Rust HIRのCold実行とWarm実行を含む。
各FixtureではCanonical GraphとCoverageの一致を保ち、Cache Hitの中央値が5%以上高速であることを検証する。

## CLIコマンド例

```sh
# 任意の追跡対象設定。設定がなくてもスキャンできる。
depgraph init .

# 安全な静的解析。対象リポジトリを変更しない。
depgraph scan /path/to/repository
depgraph scan /path/to/repository --strict
depgraph scan /path/to/repository --no-cache

# Workerの起動やStoreの変更をせず、プロファイル選択を確認する。
depgraph profiles plan /path/to/repository
depgraph profiles plan /path/to/repository --profile-budget 8 --json
depgraph profiles plan /path/to/repository --profiles-file profiles.json --json

# 前景で監視Daemonを起動し、別のプロセスから状態確認と停止を行う。
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

# GoのセマンティックグラフではCanonical Resolver Identityを使う。
depgraph deps symbol:example.com/semantic/model.Build --transitive
depgraph dependents type:example.com/semantic/model.Worker --json
depgraph why symbol:example.com/semantic/model.Build type:example.com/semantic/model.Input --json
depgraph cycles --level symbol

# セレクターが曖昧な場合は、候補に含まれるStable IDで再実行する。
depgraph deps "id:$STABLE_ID" --json

depgraph unresolved --max-items 100 --json
depgraph unresolved --all --json

# Storeを変更せず、外部Runtime Traceを検証してグラフと照合する。
depgraph runtime validate --file runtime-trace.json
depgraph runtime validate --file runtime-trace.json --json

# 完了済みImmutable Snapshotに名前を付けて確認する。
depgraph snapshot create baseline
depgraph snapshot list --json
depgraph snapshot show baseline
depgraph snapshot show snapshot:sha256:... --json

# 名前またはStable IDで完了済みSnapshotを比較する。
depgraph diff baseline current
depgraph diff baseline current --json
depgraph diff baseline current --kind symbol --profile web:production:server
depgraph diff baseline current --phase semantic --status unresolved

depgraph export --format json --output graph.json
depgraph export --format dot > graph.dot
depgraph export --format mermaid > graph.mmd
depgraph export --format graphml --output graph.graphml
```

### MCP stdioサーバー

`depgraph-mcp` is the packaged native MCP stdio server. Its safe default is the
`read` capability: no store mutation, repository write, daemon control, or
project-code execution is enabled. It requires an existing fixed repository
root, an explicit absolute store-file path, and the validated compiler-pack
requirement published for the host. Replace the path placeholders below with
canonical absolute paths and `TARGET_TRIPLE` with the release host target; Agent
hosts must not rely on shell or environment expansion.

The recommended onboarding command authenticates the downloaded inputs against
the official release's closed post-publish evidence, verifies the archive and
exact checksum sidecar, binds the extracted manifest to that archive, checks
every MCP/runner/schema/worker sibling, validates the compiler pack and fixed
root/Store snapshot, and performs `initialize`, `tools/list`, and `get_context`
before printing a host entry. The default profile is `read`; stdout contains
only the requested configuration and no host file is edited. Diagnostics and
the exact capability closure and effect summary go to stderr.

Download `release-post-publish-evidence-RELEASE_TAG.json` from the same
[official GitHub Release](https://github.com/TamaT-LLC/depgraph-cli/releases),
then obtain that asset's SHA-256 independently from GitHub's release-asset API
over HTTPS. Strip the `sha256:` prefix and pass the remaining 64 lowercase hex
characters below. Do not calculate this trusted value from the downloaded
evidence file or any local archive/sidecar: that would make a forged local set
self-authenticating. For example, the API field can be read with

```sh
gh api "repos/TamaT-LLC/depgraph-cli/releases/tags/RELEASE_TAG" \
  --jq '.assets[] | select(.name == "release-post-publish-evidence-RELEASE_TAG.json") | .digest | sub("^sha256:"; "")'
```

```sh
/absolute/path/to/depgraph-0.5.1-TARGET_TRIPLE/bin/depgraph agent-config \
  --root /absolute/path/to/repository \
  --store /absolute/path/to/state/depgraph.sqlite \
  --release-archive /absolute/path/to/depgraph-0.5.1-TARGET_TRIPLE.tar.gz \
  --release-checksum /absolute/path/to/depgraph-0.5.1-TARGET_TRIPLE.tar.gz.sha256 \
  --release-evidence /absolute/path/to/release-post-publish-evidence-RELEASE_TAG.json \
  --trusted-release-evidence-sha256 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  --release-manifest /absolute/path/to/depgraph-0.5.1-TARGET_TRIPLE/release-manifest.json \
  --compiler-pack-requirement /absolute/path/to/depgraph-compiler-pack-0.5.1-TARGET_TRIPLE.requirement.json \
  --host codex
```

Use the matching `.zip` and `.zip.sha256` paths on Windows. `--host` accepts
`codex`, `claude-desktop`, or `vscode`. A missing current snapshot fails before
server launch and reports an exact argv array for a separate safe scan; the
onboarding command itself never creates or migrates the Store. Non-read
profiles are selected explicitly with `--profile store-write`,
`repository-write`, `daemon-control`, `project-exec`, or `full` and require
`--acknowledge-privileged-effects`. `project-exec`/`full` also require
`--acknowledge-project-exec-human-confirmation`.

<!-- depgraph-mcp-package-smoke:command -->
```sh
/absolute/path/to/depgraph-0.5.1-TARGET_TRIPLE/bin/depgraph-mcp \
  --root /absolute/path/to/repository \
  --store /absolute/path/to/state/depgraph.sqlite \
  --capability read \
  --compiler-pack-requirement /absolute/path/to/compiler-pack-requirement.json \
  --log-level warn
```

The equivalent Claude Desktop entry is read-only. This is also the generic JSON
form to copy unless an operator has approved a narrower privileged use case.

<!-- depgraph-mcp-package-smoke:read -->
```json
{
  "mcpServers": {
    "depgraph": {
      "command": "/absolute/path/to/depgraph-0.5.1-TARGET_TRIPLE/bin/depgraph-mcp",
      "args": [
        "--root", "/absolute/path/to/repository",
        "--store", "/absolute/path/to/state/depgraph.sqlite",
        "--capability", "read",
        "--compiler-pack-requirement", "/absolute/path/to/compiler-pack-requirement.json",
        "--log-level", "warn"
      ]
    }
  }
}
```

The fixed root and store form a trust boundary: use a separate private store per
repository, keep it outside the repository when possible, and launch the MCP
server, sibling operation runner, schema, manifest, and workers from one
official-evidence-bound release archive. stdout is reserved for
newline-delimited MCP JSON-RPC; bounded diagnostics go to stderr.

Privileged profiles are explicit replacements for the read-only entry, not a
runtime elevation mechanism. Complete Agent host examples for `store-write`,
`repository-write`, `daemon-control`, `project-exec`, and `full`, together with
human-confirmation rules, durable polling/reconnect/cancel, timeout and TTL
values, upgrade/rollback steps, and troubleshooting, are in the
[MCP Agent host operations runbook](docs/50_test/mcp-agent-host-operations.md).
In particular, `acknowledgement: true` on `resolve_build_submit` only records an
independent host decision; it does not grant `project-exec` or replace human
confirmation. Only enforced isolation plus a successful source postflight can
claim source non-mutation; best-effort isolation cannot.

The [packaged MCP Agent dogfood benchmark](docs/50_test/agent-dogfood-benchmark.md)
compares the same fixed code-investigation corpus with and without this MCP
server. The checked-in `v0.5.0-rc.7` evidence records all three samples per arm,
91.67% MCP accuracy, 100% major-claim recall, zero false exact claims, and a
side-effect-free read-only run.

Modern protocol `2026-07-28` can negotiate MCP Tasks. Its `taskId` is the same
durable ID exposed by `operation_get`, `operation_result`, and
`operation_cancel`; legacy `2025-11-25` and Tasks-unaware hosts use those
portable tools directly. stdio disconnect does not cancel work. Reconnect with
the same root, store, capability profile, and compiler-pack requirement, then
poll the saved ID. Read calls have a 30-second budget, durable submission has a
2-second handle-return budget, and an accepted operation has a one-hour
execution deadline. Follow the returned `pollIntervalMs`,
`execution_deadline_ms`, and `retain_until_ms` rather than guessing locally.

Inbound MCP JSON messages are limited to 1 MiB before JSON deserialization;
the server fails closed when that bound is exceeded. The requirement file must
be a regular non-symlink file no larger than 1 MiB; its manifest, closed tree,
host/target, checksum reference, and artifact integrity are verified by
`depgraph-core` before the server accepts MCP input.

SQLite is stored under the operating system cache directory, keyed by the canonical repository root. Use global `--store PATH` for a specific database and global `--scan-id ID` to inspect a retained partial scan. Queries default to the latest successful scan; `doctor` reports the latest attempt.

`doctor` emits a bounded summary by default. The summary reads diagnostic
counts and at most 64 cause groups plus five representative diagnostics
without loading diagnostic payload JSON, graph evidence, or adapter stderr.
Completed build and runtime overlays are projected into the same bounded counts.
Use `doctor --details` for the complete retained attempt payload.
The diagnostic root defaults to the latest attempt's stored root, falling
back to the current working directory only when the store has no attempt;
`--root PATH` selects it explicitly. Worker `available`, version, protocol,
and integrity describe an isolated artifact handshake and therefore do not
change with the invoking directory. `root_launch_allowed` and
`root_launch_error` separately report whether that artifact may be launched
for the diagnostic root, preserving the development-artifact-inside-root
security boundary.

`deps`, `dependents`, and `unresolved` use the versioned
`depgraph-interactive-query-page-v1` contract unless `--all` is explicit.
The defaults are 100 canonical items, a 1 MiB canonical JSON document, and
50,000 visited edges for dependency traversal. `--max-items`, `--max-bytes`,
and `--max-traversal` lower or raise those bounded limits within the hard
caps. A truncated page returns `complete:false`, a stable diagnostic code,
an immutable `snapshot_id`, and a snapshot/query-bound `next_cursor`; the
cursor resumes the canonical item order without overlap or gaps and is
rejected after a newer build snapshot is promoted for the same scan. The byte
count covers the compact UTF-8 JSON document (the terminal newline is transport
framing). A traversal-limit result has no continuation after its admitted result set; raise
`--max-traversal` or narrow filters. `--all` preserves the legacy complete
query shape, while `export` remains the streaming full-graph interface.

`profiles plan` is read-only and uses only a bounded static inventory. Its human
and canonical JSON output includes every selected, omitted, and policy-excluded
profile with rank evidence and the schema-v1 configuration migration
diagnostic. `--profile-budget` accepts `1..=32` while reserving every detected
language baseline. `--profiles-file` instead reads a confined, non-symlink,
UTF-8 JSON file of at most 64 KiB; it is all-or-error and cannot be combined
with `--profile-budget`.

GraphML exports use standard directed `node` and `edge` elements with generated
XML-safe element IDs. The original stable IDs, kinds, phase, profile,
condition, precision, resolution, and environment remain available through
typed GraphML keys. Complete profile, dependency-site, and evidence records use
canonical JSON graph properties, with explicit owner references that allow the
records to be reconstructed without source-store access. `--output` writes
GraphML incrementally through a bounded buffer into a sibling temporary file,
then atomically replaces the destination only after export succeeds.

## Architecture policy contract

Architecture rules live in the versioned `[policy]` section of `.depgraph.toml`.
This example forbids production UI files from depending directly on internal
data files and limits a suppression to one legacy source file:

```toml
[policy]
schema_version = "1.0"

[[policy.rules]]
id = "no-ui-to-data"
kind = "forbidden_dependency"
severity = "error"
source = { kind = "file", field = "path", match = "glob", value = "src/ui/**", cardinality = "many", exclude = [], scope = { paths = [{ match = "glob", value = "src/**" }], packages = [] } }
target = { kind = "file", field = "path", match = "glob", value = "src/data/internal/**", cardinality = "many", exclude = [], scope = { paths = [{ match = "glob", value = "src/**" }], packages = [] } }
profiles = { include = [{ match = "prefix", value = "profile:" }], exclude = [] }
condition = { op = "eq", key = "mode", value = "production" }
precisions = ["exact", "observed"]
resolution_statuses = ["resolved"]
evidence = { kinds = ["source", "semantic"], minimum_spans = 1, primary_only = true }

[[policy.suppressions]]
id = "legacy-ui-data"
rule_id = "no-ui-to-data"
reason = "Legacy adapter is isolated until its scheduled migration."
scope = { source = { kind = "file", field = "path", match = "exact", value = "src/ui/legacy-adapter.ts", cardinality = "one", exclude = [], scope = { paths = [{ match = "exact", value = "src/ui/legacy-adapter.ts" }], packages = [] } }, profiles = { include = [{ match = "prefix", value = "profile:" }], exclude = [] } }
```

Selectors support `package`, `file`, `symbol`, `type`, `route`, and
`component` nodes. `runtime_boundary` requires a `route` or `component`
source and a `component` target; `public_api_change` targets only `symbol`,
`type`, or `route`.
`field` chooses stable ID, normalized repository path, locator, or display-name
matching; `match` is `exact`, `prefix`, or the bounded `*` / `**` / `?` glob
grammar. The normalized `path` field is available only for `file` selectors.
`cardinality = "one"` rejects both zero and multiple matches rather than
silently choosing the first; `"many"` evaluates every match in canonical
order. Repository/package scope is applied before exclusions, and neither can
broaden the selector.

Every rule declares source and target selectors, severity, profile and
condition filters, admitted precision/status values, and its evidence
requirement. `dependency_depth`, `fan_in`, and `fan_out` rules additionally
require `threshold = { max = ... }`. Suppressions require a reason and a
non-empty source, target, profile, or condition scope; a condition used as the
only bound must not be statically always true. Unknown versions, rule kinds,
properties, and invalid or duplicate IDs fail closed as configuration errors.
The machine-readable result contract uses stable violation IDs, dependency
paths, repository-relative evidence spans, applied suppressions, and exit code
`1` whenever an unsuppressed error remains.

During `depgraph scan`, policy selectors are resolved against the validated
staging graph and profile, condition, precision, resolution-status, and
evidence filters are applied before evaluation. `layer_boundary` and
`forbidden_dependency` evaluate admitted direct edges; `cycle` reuses the
package/file/symbol/route cycle query per profile; and `dependency_depth`,
`fan_in`, and `fan_out` evaluate deterministic threshold witnesses. The scan
JSON includes the complete `policy` result. An active error finishes the
attempt as `policy_failed` with exit code `1` and does not replace the current
completed snapshot; warnings and suppressed violations remain visible while
allowing promotion.

`runtime_boundary` is also evaluated during scan. It follows a deterministic
route/component path to an explicit `client_boundary` or `server_boundary`
edge in the same profile; the rule condition is evaluated against that
boundary edge, including framework facts such as `next.runtime`. No default
server/client boundary is inferred.

`public_api_change` is evaluated between completed snapshots:

```sh
depgraph policy baseline current --json
depgraph policy baseline current --github-annotations
```

The report classifies selected public symbols, types, and routes as `added`,
`removed`, or `changed`. Added APIs are compatible; removed and changed APIs
are breaking and become violations when a configured baseline source has an
impact path to the old API. Each violation links the change ID, baseline
dependency path, profile/condition, and declaration evidence. `--json` emits
the versioned machine-readable report and annotations. `--github-annotations`
emits only escaped `warning`/`error` workflow commands for unsuppressed
violations, using validated repository-relative paths and one-origin
positions; scan roots, environment values, evidence details, and absolute
paths are not included. Active errors return `1`; warning-only and
suppressed-only results return `0`.

The matching JSON Schema is
[`schemas/depgraph-policy-v1.schema.json`](schemas/depgraph-policy-v1.schema.json).

## Runtime trace import contract

`depgraph runtime validate (--trace TRACE|--file REPOSITORY_RELATIVE_FILE)` reads
the versioned `1.0` JSON contract,
matches it against the selected completed snapshot, and produces deterministic
`runtime-event:sha256:...` identities without changing the store.
`depgraph runtime import TRACE` performs the same validation and atomically
publishes a new immutable runtime snapshot:

```sh
depgraph runtime import runtime-trace.json --json
depgraph deps id:file:server --phase runtime --session session-001
depgraph dependents id:route:users --phase runtime --environment production
depgraph why id:file:server id:route:users --phase runtime
depgraph impact id:route:users --phase runtime --profile profile:sha256:...
depgraph export --format json --phase runtime --session session-001
depgraph export --format graphml --phase runtime --session session-001
depgraph diff baseline current --phase runtime --json
```

Runtime child profiles declare their static/semantic parent and canonical
effective input. Matching observations from multiple sessions reuse the same
runtime-only sentinel, site, and edge identities; evidence remains per session
with source session/environment, observation count, duration, first/last
timestamp, event IDs, and redaction count. External and unresolved locators are
retained as explicit `runtime_only` sentinel nodes with fixed reasons rather
than being forged into repository nodes. Reimporting the same validated session
is idempotent.

The document identifies a repository, session, profile, environment, and an
ordered event stream. Each source and target uses one explicit locator form:
stable node ID, exact graph locator, canonical repository-relative path,
external identity, or an unresolved reason. Repository identity must match a
workspace node ID, locator, or `repository_identity` property in the selected
snapshot. Revision is checked when both sides provide it. Node ID and locator
matches must be unique; missing or ambiguous locators remain `unresolved`, and
collector-declared external targets remain `external`. Validation never
invents a repository node.

Input is bounded to 16 MiB, 100,000 events, 4,096-character strings, and 32 JSON
levels. UTF-8, exact version, strict fields, RFC 3339 session bounds, increasing
sequence numbers, and portable paths are required. Absolute paths, `..`, file
URI hosts, drive-like `:` segments, backslashes, unknown properties,
secret-bearing fields, and common raw credential forms fail closed with bounded
errors. Production output marked
`session.collector_contract_version=runtime-collector-v1` also rejects raw
HTTP(S) graph locators and HTTP targets containing
userinfo/path/query/fragment. Unmarked trace v1 input retains its existing
compatibility behavior without claiming the production collector guarantee.
Environment variables, headers, and secrets are represented only by
sorted/deduplicated names and redaction counts; their values are not part of the
contract or output.

The matching JSON Schema is
[`schemas/depgraph-runtime-trace-v1.schema.json`](schemas/depgraph-runtime-trace-v1.schema.json).
Production SDK lifecycle, buffer, flush, retry, sequence, clock, file/stdout/OTLP
transport, redaction, and rate-limit behavior are fixed separately by
[`runtime-collector-v1`](schemas/depgraph-runtime-collector-v1.schema.json) and
the
[collector ADR](docs/40_arch_design/adr-production-runtime-collector-v1.md).
All transports converge on the same trace v1 JSON; vendor spans are adapted
outside core.

The Node.js/TypeScript reference implementation is built as
`workers/web/dist/depgraph-runtime-collector.mjs`. Its typed module, call,
route, and RPC APIs redact URL credentials/path/query/fragment before
admission, assign contiguous acceptance-order sequence numbers, apply bounded
drop-newest backpressure, and coalesce immutable-prefix flushes across file,
stdout, and OTLP sinks. A disabled instance does not read clocks, call a sink,
or install timers. See the
[Web worker runtime collector guide](workers/web/README.md#nodejstypescript-runtime-collector).
Native archives ship the same module at
`libexec/depgraph-runtime-collector.mjs`. Its `runtime-collector-v1`
compatibility unit and SHA-256 are fixed by the release manifest, represented
as a first-party SPDX package, and exercised from real fixture observation
through validate/import/query/GraphML export by every package gate.

Store schema v13 retains the v10 profile-independent `syntax`,
profile-dependent `semantic`, and observed `build` cache tables plus the v11
normalized runtime session/node/site/edge/evidence/diagnostic/import tables.
Schema v12 added durable `worker-delta-v1` staging bound to the exact current completed
snapshot and canonical base/result graph digests. Applying a staged delta
revalidates its event stream and referential integrity inside one SQLite
transaction, recomputes the prospective completed snapshot ID, and preserves
unchanged graph payloads and stable IDs. Failed, cancelled, or crash-recovered
attempts never move the current snapshot pointer and are removed by the
existing unreferenced-attempt garbage collector.
Schema v13 adds a snapshot-, selector-, and filter-scoped impact result cache
for warm queries issued by independent CLI processes. Cache payloads use a
versioned content-addressed key and digest, are capped at 128 entries and 8 MiB
per entry with transactional monotonic LRU ordering, and are discarded on
contract, snapshot, JSON, or digest mismatch.
Git changed-set impact bypasses this cache so dirty worktree state is always
read afresh. Cache maintenance is best-effort, so a concurrent SQLite writer
cannot make the impact query fail; an unrecorded LRU touch becomes a cache miss
and uses the normal query path. A cache hit deserializes the same canonical
`ImpactResult`, so ordering, depth/profile/condition/runtime filters, diagnostics,
and JSON or human rendering are unchanged.
Runtime rows, the completed snapshot, its source mapping, and the current
pointer are committed in one SQLite transaction; any failure rolls back the
entire session and leaves the previous completed snapshot queryable. Existing
source/semantic/build graph records are immutable and runtime union only adds
`phase=runtime`, `precision=observed` records. Cache keys continue to use
contract v1 canonical digests of repository-relative file bytes,
manifest/lock/config inputs, adapter/protocol artifacts, toolchain/framework
identities, profiles, and generated artifact fingerprints; checkout, cache,
and temporary absolute paths are not key dimensions. A semantic hit is reused
only after cache contract v2 key, completed-snapshot, and canonical payload
reference integrity checks. The validated content-addressed snapshot is
atomically aliased to the fresh scan attempt without cloning every graph row;
an intervening SQLite writer invalidates the promotion proof.
Repository-internal file symlinks remain cacheable by fingerprinting the link
identity and confined target content, then revalidating those proofs immediately
before the cache-hit transaction commits. Policy evaluation paths that require
a cloned staging graph use a worker rescan when symlink proofs are present.
Root-out, dangling, looped, non-file, changed, or unreadable symlinks fail
closed; the rejection diagnostic reports only the safe repository-relative
link path. Unknown versions, corruption, unsafe inventory bounds, and
dependency snapshots that cannot be re-derived before scanning are also
explicit misses/rejections. `scan --no-cache` bypasses lookup and storage. Scan
JSON/text and `doctor` expose cache hit/miss/reject reasons without adding cache
bookkeeping to the canonical graph.

`snapshot create` names the current completed snapshot; global `--scan-id ID` may instead select the completed snapshot produced by that scan and its latest promoted build. Failed or incomplete attempts cannot be named. Names are immutable, case-insensitively unique, 1–64 ASCII characters, begin with a letter or digit, and otherwise use letters, digits, `.`, `_`, or `-`. `current` and `latest` are reserved, and existing names are never overwritten. `snapshot show` accepts a name, a `snapshot:sha256:...` stable ID, or `current`. List and detail JSON are emitted in canonical order.

`diff` accepts two completed snapshot names, stable IDs, or `current`; failed and incomplete attempt IDs are rejected with exit code `2`. Human output starts with node/site/edge/evidence/profile/coverage/rename counts and follows with canonical change details plus primary source evidence. `--json` emits the versioned `diff` command envelope with normalized filters, a summary, and the canonical before/after records. Repeatable `--kind`, `--profile`, `--phase`, and `--status` filters use exact matching and AND semantics; a record type that does not expose a selected dimension is excluded rather than guessed through an implicit graph join.

`impact <SELECTOR>` follows incoming dependencies from the selected node and reports a deterministic dependency path, rendered condition, profile correlation, and source evidence for every result. With `--changed <GIT_REF>`, depgraph reads both committed changes from `merge-base(GIT_REF, HEAD)..HEAD` and staged, unstaged, and untracked worktree changes without taking Git locks or invoking external diff/textconv helpers. Changed and renamed paths are correlated to file and semantic node identities through canonical node properties and stored evidence. The selector is the focus: it must depend on a mapped changed node, then reverse traversal reports the focus and its dependents. Repeatable `--profile`, `--condition`, `--phase`, `--session`, and `--environment` filters are exact; runtime environment matching includes its name, runtime, and region. `--depth`, `--max-nodes`, and `--max-edges` bound traversal, and a reached safety limit is returned as `complete=false` with an explicit diagnostic rather than silently truncating results.

`daemon start` uses the platform-recommended recursive filesystem watcher and a configurable `[daemon].debounce_milliseconds` (default `200`). VCS metadata, dependency/build output directories, the graph store, and daemon control files are ignored; tracked generated source such as `generated`, `*.generated.*`, `*.g.rs`, and `routeTree.gen.ts` remains observable. A burst is normalized into deterministic added/modified/deleted/renamed changes. Before repository-complete planning, one existing Web source write is checked with a canonical token-and-position fingerprint that permits harmless trailing trivia while retaining graph-affecting syntax, evidence positions, directives, tags, and quoted comment module candidates. If it is unchanged, the core sends a one-node `worker-delta-request-v1` projection and atomically promotes a sparse parent-snapshot overlay containing only the updated content hash. Status records versioned base-projection, worker capability, worker analysis, store-commit, and total timings. Any semantic or evidence-position change explicitly falls back to `incremental-plan-v1`; bounded scoped plans use the complete canonical delta contract, while legacy workers, workspace replans, unsupported adapter combinations, and complete-reanalysis closures above 4,096 paths use the atomic full scan. A newer burst cancels both capability probes and active scans, then requeues their changes; failed batches retry with bounded backoff. Shutdown cancels an active scan, performs one final pending-batch flush, waits for worker process-tree cleanup, and never promotes the cancelled attempt. Status uses schema `daemon-status-v1` and exposes active, last completed, last failed, last cancelled, watcher-error, and crash-recovery state. Public CLI and MCP JSON retain release evidence through a path-free invalidation summary containing only the schema version, mode, base profile-plan digest, and affected-profile count; raw invalidation plans and internal errors remain private. `[daemon].ignored_paths` accepts normalized repository-relative path prefixes.

Selectors accept `id:`, `path:`, `package:`, `route:`, `symbol:`, and `type:` prefixes. `symbol:` and `type:` only match their respective node kind. A bare or prefixed selector must resolve unambiguously; when candidates are reported, copy the complete stable ID (for example `symbol:sha256:...`) and retry as `id:<stable-id>`.

## Safe-scan boundary

The default scan reads source, manifests, lockfiles, static JSON/JSONC configuration, and existing generated files. It does not execute project configuration, plugins, package managers, generators, build scripts, proc macros, or project-local TypeScript. The Web worker uses bundled TypeScript. Go requests typed syntax and type information through `go/packages` with networking, telemetry, external drivers, cgo, toolchain download, and repository writes disabled, then retains the standard-parser inventory as its fallback. The Go profile records a canonical offline dependency snapshot status/fingerprint derived from admitted module-cache, vendor, in-repository replacement, checksum, and manifest inputs; checkout/cache absolute paths, the standard library, build cache, temporary data, and unused cache entries are excluded. Cargo metadata is attempted only in frozen/offline/no-deps mode against a preflighted, worker-owned input mirror from a neutral working directory.

Worker and toolchain lookup uses a canonical absolute `PATH`: relative entries, the scan root, and symlink aliases into the scan root are removed. Child environments omit execution hooks such as `NODE_OPTIONS`; direct reads resolve symlinks and remain confined to the canonical repository root. Release manifests, workers, schemas, runtime component trees, and every declared artifact are checksum verified; symlinks, missing entries, changed bytes, and undeclared tree contents fail closed before a packaged worker starts.

Executable or unsupported configuration becomes a diagnostic or unresolved site. `project_code_executed` remains `false` in worker profiles, coverage, stored scans, and `doctor` output. Security fixtures contain configs/generators that would create marker files if they were executed.

## Build-mode consent boundary

`depgraph resolve --build [PATH]` is a separate, privileged mode because build tools, executable configuration, plugins, lifecycle scripts, Rust build scripts, and proc macros may run arbitrary project code. It never prompts. Each invocation must include `--allow-project-code`; configuration, environment variables, `CI=true`, TTY state, and previous consent cannot grant permission. Missing consent is rejected before path/config/store/toolchain processing with exit code `4`.

The explicit-consent guard is enforced before path, configuration, store, or tool processing. A consented Rust workspace with `Cargo.toml` and `Cargo.lock` is executed by the versioned build supervisor using Cargo. Next.js, Astro, and TanStack Start projects declare a direct Node entrypoint and pinned observer contract in `package.json`; shell commands and package-manager lifecycle resolution are not accepted:

```json
{
  "depgraph": {
    "build": {
      "adapter": "next",
      "entrypoint": "depgraph-build.mjs",
      "version": "16.2.10",
      "timeout_seconds": 900
    }
  }
}
```

The allowed Web adapter values are `next`, `astro`, `tanstack-router`, and
`tanstack-start`. The relative entrypoint must integrate the release-provided
observer named by `DEPGRAPH_OBSERVER` (and `NEXT_ADAPTER_PATH` for Next) into
the real build lifecycle. It runs in a temporary staged workspace using
canonical system Node, a cleared allowlisted environment, temporary
HOME/cache/output, bounded output, timeout/cancellation, and cross-platform
process-tree cleanup. Every launched attempt saves a secret-free audit
containing command metadata, logical paths, environment key names, limits,
isolation capability, and outcome; raw stdout/stderr and temporary or host
paths are not persisted. Network isolation is reported as `best-effort` unless
an outer namespace/container enforces it.

Validated observer output uses the shared `framework-build-graph-v1` contract:
`phase=build`, `precision=observed`, canonical production
profile/conditions, and primary `kind=build` evidence tied to the supervisor
audit digests. Generated node, site, and edge IDs exclude the attempt ID and
include the contract version; matching source/semantic nodes are reused only
when byte-identical. Repeated builds reuse the exact stored generated nodes and
omit already-promoted site, edge, and diagnostic IDs; a stable site with a new
target remains a conflict. The Next.js observer projects the stable 16.2+
Adapter API route/output manifests into `next-build-observation-v2`: ordinary,
RSC, and data variants share one canonical route; prerenders retain their
observed parent route; metadata routes, chunks, and server/client/edge/static
boundaries remain explicit. Raw output/build IDs and checkout roots never enter
portable identity. A dynamic target that was not observed is retained as an
`unresolved` edge to an `unknown_target` with a bounded reason, never promoted
to a guessed `resolved` edge. TanStack Start v1 production RPCs use
`tanstack-start-build-observation-v2`: the provider transform, resolver
manifest, client/SSR stubs, generated module roles, and manifest importer must
agree before an RPC ID is exact. A suffix-looking final ID is not separately
claimed as a collision unless the compiler exposes that fact. Missing static targets
remain unresolved and only build-correlated middleware chains receive observed
edges. The Next/Astro/TanStack Router/TanStack Start observer entrypoints and
their observation-to-protocol converter are separate checksum-attested release
artifacts; missing, undeclared, or changed bytes fail closed before project
code starts. The release compatibility unit pins the four observer
versions, observation schemas, dynamic capabilities, and runtime paths under
`dynamic-framework-evidence-release-gate-v1`. Every native package gate runs
the same static/semantic/build union fixture through filtered queries,
snapshot diff, impact, policy, JSON/GraphML export, checkout determinism, and
failed-build rollback. The observer and converter bundles are dependency-free
first-party SPDX packages with exact checksums, and the aggregate verifier
requires the same five-artifact closure from every target archive. The store saves the delta in an attempt transaction and
exposes it to `deps`, `dependents`, `why`, and exports only after completed
promotion. Source and semantic rows remain immutable; matching and conflicting
build observations coexist as separate layers, with conflicts carrying both
provenance sets. Failed, partial, timed-out, cancelled, malformed, unsupported,
or unauthorized deltas are discarded and never replace the current completed
graph.

## Strict policy and exit codes

The default `.depgraph.toml` strict policy permits zero skipped files, unsupported syntax, or unresolved sites. Candidate and external dependencies alone do not fail strict mode.

A typed Rust HIR backend failure atomically discards the semantic delta,
preserves the syntax graph, and fails strict policy. A Rust worker panic,
timeout, cancellation, or malformed protocol result leaves the overall scan
partial with exit code `3`.

| Code | Meaning |
| ---: | --- |
| 0 | Operation completed without a policy violation |
| 1 | Graph or coverage policy violation |
| 2 | CLI usage, selector, or configuration error |
| 3 | Worker, toolchain, graph validation, or protocol failure |
| 4 | Project-code execution permission or security-policy failure |

Failed/partial scans and diagnostics remain stored, but only a complete policy-passing scan advances the `latest successful` pointer.

## Repository layout

- `crates/depgraph-protocol`: typed protocol, canonical conditions/IDs, JSON Schema, and state-machine validation
- `crates/depgraph-store`: SQLite migrations, immutable scan staging, ledger, and evidence persistence
- `crates/depgraph-rustc-wrapper`: attested all-unit rustc wrapper and bounded start/terminal ledger emitter
- `crates/depgraph-core` / `crates/depgraph-cli`: worker supervision, queries, export, doctor, and CLI UX
- `workers/rust`, `workers/go`, `workers/web`: ecosystem-native safe static adapters
- `xtask`: reproducible build, full quality checks, release archives, checksums, SBOM, and license inventory

The opt-in Rust compiler-precise toolchain is distributed separately from the
normal archive. `cargo xtask compiler-pack SOURCE OUTPUT --spec SPEC.json`
builds one target-specific, closed-tree pack from pre-extracted official
components and their sorted file ownership inventory. The resulting manifest
digest must be published through the referenced release checksum set; the core
requires that external digest and verifies the pack before project staging and
again after the supervised process tree has stopped. It never downloads through
rustup or falls back to PATH, system, or project toolchains.

Release tags build separate compiler packs for Linux x86-64/ARM64, macOS
Intel/Apple Silicon, and Windows x86-64 with `cargo xtask
compiler-pack-package`. Each native job verifies archive extraction,
closed-tree attestation, wrapper/query handshakes, typed MIR and monomorphized
call semantics, cross-checkout determinism, resource budgets, legal/provenance
metadata, tamper rejection, and rollback. `cargo xtask
verify-compiler-pack-assets` requires all five packs to share
`compiler-pack-five-target-release-v1`, the pinned toolchain/rustc/schema/query
identity, and the canonical semantic shape before the stable release gate can
publish them. Release metadata and `doctor --json` expose this separate
distribution and its `unsupported-no-fallback` policy.

Download the four assets for the depgraph version and host target from the
same [GitHub release](https://github.com/TamaT-LLC/depgraph-cli/releases). The
release tag may be the stable tag or its matching release candidate. The v0.5
example below becomes downloadable only after that candidate is published;
the normal depgraph archive and compiler pack must come from one release run.

```bash
version=0.5.1
release_tag=v0.5.1
target=x86_64-unknown-linux-gnu # doctor --json reports compiler_pack.host_target
name="depgraph-compiler-pack-${version}-${target}"

gh release download "$release_tag" \
  --pattern "$name.tar.gz" \
  --pattern "$name.tar.gz.sha256" \
  --pattern "$name.requirement.json" \
  --pattern "$name.smoke.json" \
  --dir "$name"
(cd "$name" && sha256sum --check "$name.tar.gz.sha256" && tar -xzf "$name.tar.gz")
depgraph doctor --compiler-pack-requirement "$name/$name.requirement.json"
```

Use `shasum -a 256 --check` on macOS. On Windows, download the `.zip` and
`.zip.sha256` assets, verify the SHA-256 with `Get-FileHash`, and extract with
`Expand-Archive` into the directory containing the requirement JSON. The
requirement's relative `root` then resolves to the extracted pack. A missing,
wrong-version, wrong-target, or modified pack remains unavailable; `doctor`
prints the exact expected asset names and depgraph never falls back to another
compiler.

The first compiler-precise execution stage is explicitly selected with all
three invocation gates and a release-bound requirement document:

```text
depgraph resolve --build PATH --allow-project-code --rust-compiler-precise \
  --compiler-pack-requirement compiler-pack-requirement.json
```

The requirement JSON contains `root`, `expected_manifest_sha256`,
`release_checksum_reference`, `host`, and `target`; a relative `root` is
resolved beside the requirement document. This stage replaces project Cargo
configuration with a deterministic offline projection after rejecting compiler,
wrapper, runner, linker, credential-provider, alias, environment, and unsafe
rustflag injection. It runs only the attested Cargo with `--frozen --offline
--unit-graph -Z unstable-options`, validates and canonicalizes unit graph v1,
and does not start rustc, build scripts, or proc macros. Registry and Git
dependencies are copied from an existing host Cargo cache into a bounded,
run-owned, credentials-free subset before Cargo starts; their source paths are
accepted only inside that staged Cargo home and normalized as
`cargo-home://...`. No network lookup or direct host-cache path is exposed to
the child or persisted DTO. A second supervised stage starts a fresh target,
fixes the attested wrapper as the only `RUSTC_WRAPPER`, verifies the exact
rustc path, executable digest, and `-vV` identity, and conserves one bounded
start/terminal ledger pair for every admitted target, dependency, build-script,
and proc-macro compiler unit. Nested wrappers, response/path escape,
extra/missing/duplicate units, partial terminals, or compiler substitution fail
the whole attempt. The canonical ledger contains staged logical paths and
digests rather than host paths or raw process streams. Later compiler-precise
stages add compiler query output; the ledger stage still does not promote graph
evidence.

Run `rustup component add rust-src --toolchain 1.93.1` once, then `cargo xtask package` to create a native archive under `dist/`. Release archives place `depgraph` and `depgraph-mcp` under `bin/`, compatible workers and `depgraph-operation-runner` under `libexec/`, and include the project's complete `LICENSE-MIT` and `LICENSE-APACHE` texts, checksum-verified protocol and `depgraph-mcp-tools-v1` schemas, an SPDX SBOM, and a separate third-party license inventory. The release manifest declares `MIT OR Apache-2.0`, attests both project license files independently from `THIRD_PARTY_LICENSES.txt`, and binds the MCP server and runner digests to `rmcp 3.1.0`, MCP revision `2026-07-28`, `depgraph-mcp-tools-v1`, and `depgraph-operation-v1`. The SBOM and license inventory include the complete shipped rmcp dependency closure and an Apache-2.0 notice. The release gate fixes Rust/Cargo `1.93.1`; the Rust worker manifest records the linked backend unit, rust-analyzer `0.0.330` at revision `8954b66d43225e62c92e8bbcc8500191b5cceb1e` with Salsa `0.26.1`. It also carries `rust-stdlib-source@1.93.1+rustc.01f6ddf7588f42ae2d7eb0a2f21d44e8e96674cf` under `libexec/rust-sysroot` as a licensed, SBOM-recorded `data-tree` copied only from that pinned toolchain's `rust-src` and independently matched to the known normalized digest `cc5465ef70b933d2a80c30472468abb9f8ab297fc767bd6433b2f6f554f4f0e7`. The Web worker manifest records the exact TypeScript version, the complete Web semantic capability set, and its Astro and TypeScript runtime components.

The package verifier extracts the archive and validates the manifest, both project licenses, every artifact and runtime component, MCP/Rust/Web handshakes, per-framework scan/query/export E2E, dynamic framework build query/diff/impact/policy/JSON/GraphML E2E, cross-checkout determinism, rollback, and the complete runtime SBOM and third-party license closure. Missing, added, modified, symlinked, or version-mismatched license, MCP server/runner/schema/SDK metadata, Web worker, build observer/converter, Astro parser, TypeScript compiler, Rust sysroot source, or schema input fails before worker launch. Runtime components distinguish an `executable-tree` with an executable entrypoint from a `data-tree` whose entrypoint is optional. The aggregate release verifier requires all five target archives to attest identical MCP schema and Rust sysroot source bytes. After core verifies that data tree, it hands the canonical root to the packaged Rust worker; the worker rechecks the pinned source identity, builds separate library VFS roots for `core`, `alloc`, and `std`, and emits exact standard-library import, type-use, and direct-call edges. Development, mismatched, missing, unsupported-target, and tampered inputs preserve syntax output without `semantic-complete`, and neither packaging nor scanning falls back implicitly to project or system `rust-src` or backend bytes. Tier 1 Linux/macOS package gates and Windows safety/determinism smoke cover the MCP, Web semantic, dynamic framework, and Rust sysroot archive contracts.

`mcp-package-smoke-v2` also runs `depgraph agent-config` for all three host
formats from a clean temporary home, verifies the complete package/root/Store/
compiler-pack tuple against a separately pinned `release-post-publish-evidence-v1`
digest, connects through the generated read-only launch arguments, and rejects
any repository, private Store, host-config, or journal mutation. Its report
records `agent_host_release_evidence_contract_version` and requires
`agent_host_release_trust_verified=true`.
The CLI runtime closure for this archive preflight (`flate2`, `tar`, `zip`, and
their transitive dependencies) is included in the SBOM and third-party license
inventory.

## License

Licensed under either [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE) at your option.

Copyright (c) 2026 TamaT LLC.
