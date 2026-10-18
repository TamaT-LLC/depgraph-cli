# 設計メモ: GitHub Action による PR 影響範囲コメント

- Status: Draft（試作段階の設計メモ。ADR ではない）
- Date: 2026-10-18
- Parent: `PROJ-ARC-001`
- 試作の置き場所: `.github/actions/pr-impact/`、`.github/workflows/depgraph-pr-impact.yml`

## 結論

PR に「この変更で影響を受けるルートとパッケージ」を根拠つきで自動コメントする Action を、現行の CLI だけで試作できる。
ただし変更ファイル全体の影響範囲を 1 コマンドで出す手段が CLI に無いので、試作では変更ファイルごとに `depgraph impact path:<file> --json` を呼んで Action 側で集約する。
この方式は暫定であり、CLI に「セレクター省略の `impact --changed`」が入った時点で 1 コマンドに置き換える。

fork PR では `pull_request_target` を使わない。
`pull_request` の read-only ジョブで解析してコメント本文を artifact にし、コメント投稿は `workflow_run` で起動する別 workflow が担う。
今回の dry-run は前半だけを実装し、Step Summary と artifact で確認する。

置き場所は、試作がこのリポジトリの `.github/actions/pr-impact/`、公開は別リポジトリ `TamaT-LLC/depgraph-action` を推奨する。

## 目的と範囲

告知前の見せ場として、PR に影響ルート・影響パッケージとその根拠を自動コメントする。

次の 2 つは非目標で、後回しにする。

- ポリシー違反で CI を落とすゲート
- 影響範囲に絞ったテスト実行

静的解析だけで動き、プロジェクトのコードは実行しない（[Safe-scan boundary](../reference/safe-scan-boundary.ja.md) の 5-14 行目）。
このため fork PR のコードを解析しても、build script などが走ることはない。

## 現行 CLI でできること、できないこと

### impact はセレクター必須

`impact <SELECTOR>` はセレクターが必須である（`crates/depgraph-cli/src/main.rs:302-334`、`crates/depgraph-core/src/service_graph.rs:49-82`）。

`--changed <ref>` を付けても、意味論は「セレクターを焦点にする」ものになる。
セレクターから順方向に変更ノードへ届けば `root_impacted=true` となり、`impacts` はセレクター自身の逆方向到達集合である（`crates/depgraph-core/src/impact.rs:1230-1351`、`docs/reference/cli-behavior.md:122`）。
変更ファイル全体を起点にした影響範囲は、1 コマンドでは出せない。

### --changed まわりの制約

`--changed` は内部で git の merge-base、diff、untracked を読む（`impact.rs:279-406`）。
scan の `source_revision` と HEAD が一致しないと exit 2 になる（`service_graph.rs:513-516`）。
Action は head.sha を checkout して、その同じ revision を scan する必要がある。

上限を超えると `complete=false` になる。
`docs/reference/cli-behavior.md:122` は「部分結果を `complete=false` で返す」と書くが、サービス層は `ResourceExhausted` を返し、CLI では exit 3 になる（`service_graph.rs:538-540`）。
文書と実装が食い違っているため、Action からは上限超過の部分結果が得られず、そのファイルは `error` として終了コードと先頭のメッセージつきでコメントに残る。

### audit --changed は件数しか出ない

`audit --changed` は変更集合全体の reverse_impact を計算する。
しかし出力は WideBlastRadius finding の件数だけで、ノード一覧も根拠も出ない（`crates/depgraph-core/src/health/audit.rs:260-316, 517-563`）。

### scan のプロファイル指定

`scan` に `--profile` は無い。
プロファイルは `.depgraph.toml` の `[profiles]` で決まる（`crates/depgraph-core/src/config.rs:70-76`）。
`impact` の `--profile` はエッジの絞り込みであり、解析対象の選択ではない。

### JSON スキーマが無い

impact と why の JSON は `schemas/` にスキーマが無く、serde 構造体が唯一の定義である。

- `ImpactResult`: `crates/depgraph-core/src/impact.rs:237-249`
- `PathStep` と `WhyResult`: `crates/depgraph-core/src/query.rs:514-531`
- `EvidenceRecord`: `crates/depgraph-store/src/records.rs:403-417`

Action はこれらの形に依存するため、CLI のバージョンを固定して使い、形が変わったら Action のテストで検知する。

### 終了コードと Store

終了コードは [usage.md](../guide/usage.md) の 115-131 行目にある。

| コード | 意味 |
| ---: | --- |
| 0 | ポリシー違反なしで完了 |
| 1 | グラフまたはカバレッジのポリシー違反 |
| 2 | 使用方法、セレクター、設定のエラー |
| 3 | ワーカー、ツールチェーン、グラフ検証、プロトコルの失敗 |
| 4 | プロジェクトコード実行権限またはセキュリティポリシーの失敗 |

Store の既定の場所は、リポジトリの絶対パスのハッシュで決まる（`config.rs:302-318`）。
キャッシュキー自体は絶対パスを含まない（`docs/reference/cli-behavior.md:66-112`）。
runner のチェックアウト先が変わっても Store の中身は再利用できるが、既定の場所は変わる。
そこで Action は Store の場所を `--store` で固定する。

## 試作の方式（暫定）

流れは次のとおり（実装は `collect.mjs`）。

1. `git diff --name-status -z --find-renames --relative <merge-base> <head>` で変更ファイルを列挙する。base は `base-ref` と head の merge-base に解決する。リネームとコピーは新しいパスで扱い、削除されたファイルは照会しない。head だけを scan するので、削除されたファイルのノードはグラフにない。report では `changed_files[].status` を `deleted` として残し、件数を数えられるようにする。コメントでは削除されたファイルの影響（消えたルートなど）を計算していないと件数付きで明記し、「影響を受けるノードは見つかりませんでした」は削除されたファイルを除く変更に限って書く。変更が削除だけのときは、この一文を出さない。
2. `depgraph scan`（`strict` が true なら `--strict`）を head.sha で実行する。Store は `--store` で固定する。
3. 変更ファイルごとに `depgraph impact path:<file> --json` を呼ぶ。`profiles`、`max-nodes`、`max-edges` はここで渡す。
4. `depth > 0` の影響ノードを id で重複排除する。同じノードに複数のファイルから届くときは、最も浅い経路を残し、起点のファイルを `reached_from` に集める。kind が `route` と `package_instance` のものを一覧にし、それ以外は件数の内訳だけ出す。
5. 根拠は `impacts[].dependency_path` の各 PathStep の edge kind と evidence を使う。

`dependency_path` は `why --json` の `steps` と同じ PathStep 形なので、`why` を追加で呼ぶ必要がない。
結果は `depgraph-pr-impact-report-v0` 形式の `report.json` に書き、`render.mjs` が `comment.md` に変換する。

実データで試すと、素朴な呼び出しでは足りず、`collect.mjs` に次の補正を入れた。

- `path:` セレクターは完全一致ではなく、見つからないときにサフィックス一致へフォールバックする。別ファイルの impact が exit 0 で返りうるので、`data.root` が変更ファイル自身かを確認し、違えば unmapped にする。exit 2 の ambiguous のときは、候補から完全一致を探して `id:` で再試行する。ファイルノードの locator は Go が `file:<path>`、web が `file://<path>` で、形が揃っていない。
- impact の exit 2 はセレクターの不一致に限らず、入力検証エラーや snapshot が無いときにも返る。stderr の 1 行目が `selector "..." did not match any node` か `selector "..." is ambiguous;` のときだけ unmapped にし、それ以外の exit 2 は error として終了コードとメッセージ先頭を残す。error があると report は不完全扱いになり、コメントは「影響は見つかりませんでした」と断定しない。
- strict 違反（status `policy_failed`、exit 1）や部分結果（status `partial`、exit 3）の scan は completed として保存されず、既定の impact は exit 2 になり、全ファイルが unmapped に見える。このため `scan.json` の `scan_id` を使い、`--scan-id=attempt:<scan_id>` でその scan を明示して照会する。
- impact の envelope には `partial` が加わっている。`impacts` には変更ファイル自身が depth 0 で入るので除く。`dependency_path` は影響ノードから変更ファイルへ向かう順である。同じ位置の evidence が重複して返るので、表示時に取り除く。

Action の失敗条件は、scan が使えるグラフを作れなかったとき（状態 `failed`）だけにした。
strict の exit 1 と部分結果の exit 3 では失敗させず、コメントに状態を書く。
scan が `failed` のとき、または exit 1 / 3 で `scan.json` から attempt の `scan_id` を取れなかったときは impact を呼ばず、全ファイルを「scan 結果を照会できないため未解析」としてコメントに出し、report は不完全扱いにする。影響ゼロとは表示しない。

呼び出し回数は変更ファイル数に比例するため、`max-files`（既定 200）で上限を置く。
超えた分は照会せず、コメントの折りたたみ内に件数と先頭の数件を書き、`report.json` では不完全扱いにする。
warm impact は 1 回数十 ms と測定されている（`docs/releases/v0.4.0-rc.1.md:116-135`、macOS 上の file impact 中央値 31 ms）。
しかし実際の collect は、呼び出しごとに Store を開き直すため 1 ファイル約 1.5 秒かかる。

グラフに対応づけられなかったファイル（ドキュメントや設定ファイルなど）は、コメント末尾の折りたたみに理由つきで出す。
黙って捨てると、影響なしと誤読されるからである。

## Action の入出力

### 入力

| 入力 | 内容 |
| --- | --- |
| `base-ref` | 比較元。PR の `base.sha` を推奨する。merge-base を取るため `fetch-depth: 0` か、base までの履歴が要る |
| `strict` | true で `scan --strict`。exit 1 はコメントで報告するだけで、ジョブは落とさない |
| `profiles` | 改行区切りで `impact` の `--profile` に渡す。scan 側のプロファイル指定は CLI の不足機能（後述） |
| `version` / `depgraph-path` | 使う CLI のバージョン（既定 `0.6.4`）、または用意済みバイナリのパス。後者を指定すると取得しない |
| `max-files` / `max-nodes` / `max-edges` | 呼び出し回数（既定 200）と、`impact` の探索上限。探索上限は CLI と同じ 1〜1,000,000 で、範囲外は collect の開始前に失敗させる |
| `post-comment` / `github-token` | 同一リポジトリの PR で、同じジョブからコメントするとき（既定は false）。トークンに `pull-requests: write` が要る。`github-token` はリリース取得にも使う |
| `pr-number` | コメント先の PR 番号。既定は `github.event.pull_request.number` |
| `comment-author` | 更新対象にするコメントの投稿者。`github-actions[bot]` に加えて指定できる |
| `working-directory` | monorepo の解析ルート |

出力は `report-path`、`comment-path`、`scan-exit-code`、`impacted-count` である。
成果物（`store.db`、`scan.json`、`report.json`、`comment.md`）は `$RUNNER_TEMP/depgraph-pr-impact/` に置く。

checkout は head.sha を指定する。
`refs/pull/N/merge` を checkout すると、コメントの根拠リンクが指すコミットが PR 上から消えてしまうためである。

このリポジトリの試作 workflow は checkout を 2 回に分ける。
Action は base.sha から `.depgraph-trusted/` に取り（`.github/actions/pr-impact` だけの sparse checkout）、`uses: ./.depgraph-trusted/.github/actions/pr-impact` で実行する。
解析対象の head.sha は `pr/` に fetch-depth 0 で取り、`working-directory: pr` として渡す。
scan と git diff はこの別リポジトリの中で走り、`git rev-parse --show-prefix` は空になるので、blob リンクは head のリポジトリルート基準のパスになる。
理由は後述の「1 段目で信頼する範囲」に書く。

## インストール

GitHub Release（`TamaT-LLC/depgraph-cli`）から `gh release download` で次の 2 つを取る。

- `depgraph-{ver}-{target}.tar.gz`
- 同名に `.sha256` を付けたサイドカー

`install.sh` はサイドカーが取得したアーカイブ自身の名前を指す 64 桁の digest 1 行であることを確かめてから、`sha256sum --check --strict`（なければ `shasum -a 256 --check`）で検証して展開する。
`version` は `X.Y.Z` か `X.Y.Z-rc.N` の形だけを受け付ける。

現在のリリースには集約した `SHA256SUMS` も、署名や attestation も無い（`.github/workflows/release.yml`、`xtask/src/main.rs:2900-2919` のサイドカー名検査）。
サイドカーは同じ Release に置かれているため、Release が改ざんされれば両方が差し替わる。
改善案は 2 つある。

- release.yml で artifact attestation を発行し、Action が `gh attestation verify` で検証する。
- Action 側に version から sha256 への表を埋め込んでピン留めする。Action のレビューを通した値だけが使われる。

対応 target は release.yml の 4 つである。

| 環境 | target |
| --- | --- |
| Linux x86-64 | `x86_64-unknown-linux-gnu` |
| Linux arm64 | `aarch64-unknown-linux-gnu` |
| macOS Apple Silicon | `aarch64-apple-darwin` |
| Windows x86-64 | `x86_64-pc-windows-msvc`（`.zip`） |

`install.sh` が対応するのは Linux x86-64 / arm64 と macOS Apple Silicon だけである。
Intel mac には target が無く、Windows は `.zip` で形式が違うため、どちらもエラーにする。

npm（`@tamat-llc`）や Homebrew 経由でも入れられるが、バージョンを固定してチェックサムを確かめる経路が増えるだけで、Action にとって利点は小さい。
GitHub Release 直取得が最も検証しやすい。

## キャッシュ

Store を `--store $RUNNER_TEMP/depgraph/graph.db` に固定し、`actions/cache` で保存と復元をする案である。

- key: `depgraph-store-{os}-{version}-{head sha}`
- restore-keys: `depgraph-store-{os}-{version}-` の前方一致で、base ブランチ側のキャッシュを再利用する

GitHub の仕様として、PR から保存したキャッシュは PR の ref にスコープされ、base ブランチには書けない。
そのため、main への push で Store を温める workflow を別に用意しないと、PR は初回 scan から始まる。

`actions/cache` は `.github/actions-policy.json` に未登録である。
導入するときは SHA の登録とレビューが要る。
試作では導入せず、毎回 fresh scan にする。

## コメントの形式

コメントは 1 件だけにする。
本文の先頭に隠しマーカー `<!-- depgraph-pr-impact -->` を置き、push のたびに同じコメントを探して更新する（`comment.mjs`）。
探すときは、マーカーを含み、かつ投稿者が `github-actions[bot]` か `comment-author` のものだけを対象にする。マーカーを引用しただけの他人のコメントは上書きしない。

構成は次の順である（`render.mjs`）。

1. 見出しとサマリー行（変更ファイル数、影響ルート数、影響パッケージ数、その他ノード数、scan の状態）
2. scan が失敗または部分結果、strict 違反のときの注意書き
3. 影響ルートの表と影響パッケージの表（名前、深さ、起点の変更ファイル。各 100 行まで）
4. 根拠。項目ごとに `<details>` で折りたたみ、影響ノードから変更ファイルへ向かう経路を edge kind と、head.sha の blob リンクつき `path:line` で示す。経路は 20 ステップ、1 ステップの evidence は 3 件まで
5. 解析できなかったファイル・対象外のファイル（折りたたみ）。対応ノードが無いもの、エラー、削除、scan 失敗による未解析、`max-files` 超過
6. フッター（CLI のバージョン、静的解析でありコードを実行していないこと、merge-base と head の短縮 SHA）

リポジトリ由来の文字列はすべて Markdown と HTML をエスケープして埋め込む。
PR の作者がパスやノード名を通じて、リンクやメンションを仕込めないようにするためである。

以下は形式を示す架空の例であり、実在のリポジトリの結果ではない。

````markdown
<!-- depgraph-pr-impact -->
### depgraph: この PR の影響範囲

変更ファイル 4 件 / 影響ルート 2 件 / 影響パッケージ 2 件 / その他ノード 0 件 / scan 成功

#### 影響ルート（2 件）

| ルート | 深さ | 起点の変更ファイル |
| --- | ---: | --- |
| GET /api/orders | 3 | packages/orders-core/src/price.ts |
| POST /api/orders | 3 | packages/orders-core/src/price.ts |

#### 影響パッケージ（2 件）

| パッケージ | 深さ | 起点の変更ファイル |
| --- | ---: | --- |
| packages/orders-api | 2 | packages/orders-core/src/price.ts |
| apps/web | 4 | packages/orders-core/src/price.ts |

#### 根拠

<details>
<summary>ルート GET /api/orders（深さ 3）</summary>

影響ノードから変更ファイルへ向かう依存の経路:

1. `routes` — [apps/web/src/routes/orders.ts:8](https://github.com/example/repo/blob/0123abc.../apps/web/src/routes/orders.ts#L8)
2. `imports` — [packages/orders-api/src/handler.ts:12](https://github.com/example/repo/blob/0123abc.../packages/orders-api/src/handler.ts#L12)
3. `imports` — [packages/orders-core/src/index.ts:3](https://github.com/example/repo/blob/0123abc.../packages/orders-core/src/index.ts#L3)

</details>

<details>
<summary>解析できなかったファイル・対象外のファイル（1 件）</summary>

- docs/orders.md — グラフ上に対応するノードがありません

</details>

---
<sub>depgraph 0.6.4 による静的解析の結果です。プロジェクトのコードは実行していません。 base 89abcde → head 0123abc</sub>
````

コメントの上限は 65536 文字だが、実装は余裕を見て 60000 文字を上限にしている。
根拠の `<details>` は、ルート、パッケージの順に本文の予算へ収まる分だけ入れ、入らない分は件数を書いて `report.json` に誘導する。
それでも超えたときは、本文を行単位で切り詰めて開いたままの `<details>` を閉じる。
サマリー行と表は先頭にあるため、最後まで残る。

## fork PR と権限

`pull_request_target` は使わない。
PR のコードを書き込み権限つきで checkout する、典型的な脆弱性パターンを避けるためである。
このリポジトリの xtask も禁止している（`xtask/src/project_metadata.rs` の `verify_workflow_policy_text`、210 行目付近）。

### 方式

2 つの workflow に分ける。

1. `pull_request` で起動する read-only のジョブが scan と impact を実行し、`comment.md` と PR 番号を artifact にする。
2. `workflow_run` で起動する別 workflow が `pull-requests: write` だけを持つ。PR のコードは checkout せず、artifact をデータとして読む。PR 番号は数値かを検証し、本文のサイズ上限を確かめ、マーカーを付けてコメントを upsert する。

同一リポジトリの PR だけを対象にするなら、1 つのジョブで `post-comment: true` にしてもよい。

### 1 段目で信頼する範囲

1 段目は静的解析なので、fork のプロジェクトコードは走らない。
ただし Action 自身と depgraph バイナリは信頼済みのものを使う必要がある。

head.sha を workspace ルートに checkout して `uses: ./.github/actions/pr-impact` とすると、PR の head 側の `action.yml` とスクリプトが使われる。
fork PR の作者は `action.yml` や `collect.mjs` を書き換えて、レポートを作る処理そのものを差し替えられる。
対策は次のとおり。

- 外部公開版では `TamaT-LLC/depgraph-action@<sha>` のようにコミット SHA で固定して使う。
- このリポジトリの試作は、Action を base.sha から取得し、PR の head は解析対象のデータとして別ディレクトリに置く（「Action の入出力」節の末尾にある 2 回の checkout）。PR が書き換えた `action.yml` やスクリプトは実行されない。manual dispatch はメンテナが選んだ ref なので、その ref の Action を信頼する。
- base に Action がまだ無いとき（Action を追加する最初の PR がそうである）は、PR 側の Action にフォールバックせず dry-run をスキップする。workflow は `::notice::` を出し、Action と artifact の upload を飛ばして成功で終わる。Action が base に入った後の PR から dry-run が動く。
- 解析対象側の `.depgraph.toml` などは depgraph の設定として読まれるが、これは解析データとして扱う範囲であり、プロジェクトコードは実行しない。
- 2 段目の workflow は artifact を信用せず、検証してから投稿する。

この分離で守れるのは「PR の変更を解析する道具」が PR 自身に差し替えられないことである。
`pull_request` イベントでは workflow 定義自体も PR のマージコミット側のものが使われるので、fork は workflow を書き換えて任意の処理を走らせることはできる。
その場合でも、ジョブは `contents: read` だけで secrets も渡らないので、他の CI ジョブと同じ境界にとどまる。
そうして作られた artifact は信頼できないので、2 段目が検証してから使う前提は変わらない。

### このリポジトリでの導入条件

xtask は未知の workflow 名に write 権限があると拒否する（`project_metadata.rs:475-479` の既定分岐）。
2 段目をこのリポジトリに入れるには、xtask に専用の分岐を足し、独立したレビューを受ける必要がある（`CONTRIBUTING.md:82-87`）。
今回の dry-run は 1 段目だけで、Step Summary と artifact で確認する。

## 置き場所の比較

候補は 3 つある。

- A: リポジトリ直下の `action.yml`（`uses: TamaT-LLC/depgraph-cli@v0.6.x`）
- B: 別リポジトリ `TamaT-LLC/depgraph-action`
- C: このリポジトリの `.github/actions/pr-impact/`（試作の置き場所）

| 観点 | A: 直下 | B: 別リポジトリ | C: .github/actions |
| --- | --- | --- | --- |
| Marketplace 掲載 | 可（直下の `action.yml` が必須） | 可 | 不可 |
| バージョニング | CLI のタグと共用。メジャータグ `v1` を打てない | Action 独自の `v1`、`v1.2.3` を使える | このリポジトリの ref に従う |
| release.yml との衝突 | `v*` タグで CLI リリースが走る | 衝突しない | 衝突しない |
| CLI リリースとの結合 | 強い。Action と CLI を同時に直せる | 弱い。CLI の更新に追従が要る | 強い |
| xtask の検査 | 同左 | 対象外 | 後述のガード拡張が要る |
| 利用者から見た URL | `TamaT-LLC/depgraph-cli@v0.6.x` | `TamaT-LLC/depgraph-action@v1` | `./.github/actions/pr-impact`（同一リポジトリ内のみ） |

xtask の検査範囲は `.github/workflows` だけで、`action.yml` の中の `uses` は検査対象に入っていない。
C や A に置くなら、`.github/actions/**` の `uses` が `actions-policy.json` に載った SHA だけを指すように、ガードを広げる必要がある。

`scripts/ci-affected-scope.sh` は、未知のパスを fail-closed で全ジョブ実行にする。
`.github/actions/` は force-all にも ignore にも載っていないため、変更すると go / web の重いステップも走る。壊れはしないが、頻繁に直すなら ignore への登録を検討する（その変更も xtask のレビュー対象）。
なお新しいテスト（`scripts/tests/pr-impact.test.mjs`）は、`ci.yml` と xtask の node テスト列挙に別途追加している。

推奨は、試作は C、公開は B である。

- CLI のタグ `v*` で release.yml が走るため、A では Action のメジャータグを打てず、Marketplace の通常の運用ができない。
- B なら Action の更新頻度と CLI のリリース頻度を切り離せる。
- B のリポジトリには CLI のソースもリリース権限も無いので、Action に渡る権限の面でも小さく保てる。

CLI との結合は、Action の `version` 入力で CLI のバージョンを指定し、Action の CI が最新の CLI リリースで E2E を回すことで管理する。

## CLI 側に足りない機能

優先度の高い順に並べる。上の 3 つが入れば、試作の補正の大半と 1 ファイルずつの照会が要らなくなる。

1. 変更集合全体を起点にする `impact --changed`（セレクター省略）。複数始点の逆方向 BFS にし、複数セレクターを 1 回で受けられる形でもよい。`main.rs:303-304`、`ImpactRequest`、`impact_cancellable`（`impact.rs:1202-1403`）、`map_changed_set`（`impact.rs:917-1048`）を再利用できる。現状は 1 件ごとに Store を開き直し、1 ファイルあたり約 1.5 秒かかる。
2. 完全一致のファイルセレクター（`file:` など）、またはサフィックス一致のフォールバックを無効にするオプション。
3. strict 違反や部分結果の scan に対する impact。`attempt:` を自動で参照するか、採用する scan id を明示できるようにする。今は既定の照会が exit 2 になり、全ファイルが unmapped に見える。
4. 上限超過や部分結果でも `complete=false` で結果を返し、ドキュメントとの食い違いを解消する。部分結果時、Go のファイル単位 impact が import 先へ伝わらない問題も含む。
5. base 側の削除とリネームの検出。head だけ scan すると、消えたルートが見えない。base も scan して diff を取る補助が要る。
6. `contains` エッジ経由で、所属パッケージが常に影響ありになるノイズ。エッジ種別での除外フィルタを足す。
7. scan の exclude（testdata、fixtures）と、ワーカーのメモリ上限の調整手段。
8. 解析対象外のファイル（yml、md、`Cargo.toml` など）と、解析したがグラフに無いファイルの区別。
9. kind による集約とフィルタ（`route`、`package_instance`）。
10. scan / impact / why の JSON Schema を `schemas/` に置いて安定契約にする。
11. Markdown 出力や `--github-annotations` の impact / audit への拡張。
12. `scan --json` に Store のパスを含める。
13. scan 時のプロファイル指定（`scan --profile`）。
14. audit の blast radius にノード一覧と根拠を出す。
15. パス一覧からの入力（`--paths-from`）。git に依存せず、PR の diff API の結果を渡せる。

## E2E の結果

- `install.sh` は v0.6.4 の取得とチェックサム検証に成功した（約 35 秒）。改ざんした archive と不正な `VERSION` では exit 1 になることを確認した。
- 小さな Next.js fixture では scan が 3 秒で exit 0 になり、ルート `next:app:page:/users/$id` を深さ 4 で検出した。
- このリポジトリ自身では scan が 138 秒で exit 3 になった。Rust worker がメモリ上限 2GiB を超え、Go worker が testdata の fixture で `outside the local module closure` を出したためである。
- collect は 1 ファイル約 1.5 秒で、34 ファイルに約 53 秒かかった。34 件中 28 件が unmapped だった。

## 未決事項と次の一手

- このリポジトリでの dry-run は、現状では部分結果のコメントになる。見せ場としては、小さな fixture や Web 系のリポジトリでのデモが向く。
- 外部公開リポジトリ `TamaT-LLC/depgraph-action` の作成
- `workflow_run` 側の workflow の実装と、xtask の専用分岐、独立レビュー
- `actions/cache` の導入（`actions-policy.json` への SHA 登録を含む）と、main push で Store を温める workflow
- チェックサムのピン方式（attestation か、埋め込み表か）
- ゲート化（ポリシー違反で CI を落とす）は後回し。CLI の 1、3、4 が入ってから検討する
