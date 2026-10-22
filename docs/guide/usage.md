# 使い方ガイド

日本語 | [English](usage.en.md)

このガイドは[README](../../README.md)の続きです。
スキャンの設定、コマンドの一覧、結果の読み方、終了コード、CLIの実行例をまとめています。

## スキャンの設定と再開

解析結果は、リポジトリごとにOSのキャッシュディレクトリ内のSQLiteファイル（Store）へ保存されます。
保存先を固定したい場合は、`depgraph --store /path/to/depgraph.sqlite scan /path/to/repository`のようにグローバルオプションを指定します。
設定ファイルは必須ではありません。
`depgraph init /path/to/repository`を実行したときだけ`.depgraph.toml`を書き込みます。

Go・Webのスキャンは、先にディレクトリとworkspaceを調べてから、解析単位とsource batchごとに処理します。
同じ保存先で`scan`を再実行すると、入力とworkerの互換性を確かめたうえで、完了済みの処理を再利用します。
既定では全体の時間制限はありません。
個々のworkerの無進捗時間、メモリ、出力量、同時実行数を制限します。

`.depgraph.toml`の`[scan]`では、次の上限を変更できます。

| キー | 既定値 |
| --- | --- |
| `max_unit_source_files` | 2,048 |
| `max_unit_source_bytes` | 8 MiB |
| `max_context_source_bytes` | 64 MiB |
| `max_concurrent_units` | 2 |
| `max_worker_memory_bytes` | 6 GiB |
| `max_protocol_bytes` | 1 GiB |
| `worker_timeout_seconds` | 無進捗 300 秒 |

全体の時間予算が必要な場合は`total_budget_seconds`を指定します。
`scan --split-plan [--json]`は、workerを起動せずに分割の計画を表示します。
各実行単位の所有範囲、ローダーが実際に読む範囲、参照のみの入力、処理量の見積もり、分割理由、並列度の決定が分かります（[事前分割計画 ADR](../40_arch_design/adr-presplit-analysis-planning.md)）。
分割・中断・再開・依存変更の検証方法は[統合検証](../40_arch_design/resumable-analysis-validation.md)に記載しています。

未完了の試行を調べる場合は、`scan --json`の`scan_id`を使って`depgraph --scan-id "attempt:$SCAN_ID" deps path:src/app.ts --json`のように明示します。
結果には未完了であることと解析範囲が含まれ、既存の完了snapshotは置き換わりません。
`deps`、`dependents`、`why`、`impact`、`cycles`、`unresolved`、healthとgraph exportで利用できます。
名前付きsnapshot、diff、policy、bounded query、runtime validationは完了snapshotを使います。

## 調べたいこととコマンド

| 調べたいこと | コマンド | 得られる情報 |
| --- | --- | --- |
| 依存先 | `deps <SELECTOR>` | 選択したノードから出る依存関係 |
| 依存元 | `dependents <SELECTOR>` | 選択したノードへ入る依存関係 |
| 依存理由 | `why <FROM> <TO>` | 二つのノードを結ぶ経路、条件、ソース位置 |
| 変更影響 | `impact <SELECTOR>`、`impact --changed <GIT_REF>` | 逆向きの依存経路と影響を受けるノード。セレクターを省略すると、変更ファイル全体の影響範囲を 1 回で返す |
| 循環依存 | `cycles` | パッケージ、ファイル、シンボル単位の循環 |
| 解析できなかった箇所 | `unresolved` | 理由とソース位置を含む未解決台帳 |
| 解析状態 | `doctor` | ワーカー、ツールチェーン、カバレッジ、キャッシュの状態 |
| スナップショット差分 | `snapshot`、`diff` | 完了済みグラフ間の追加、削除、変更、名前変更 |
| アーキテクチャ規則 | `policy` | 禁止依存、境界違反、公開API変更 |
| 実行時依存 | `runtime validate`、`runtime import` | 検証済みトレースと静的グラフの統合結果 |
| グラフ出力 | `export` | JSON、DOT、Mermaid、GraphML |
| 未使用のfile / export / type / dependency | `health`、`health list`、`cleanup` | snapshot-scoped finding、confidence、blocker。summaryにはaudit / hotspotを含みません |
| 変更差分のリスク | `audit --changed <GIT_REF>` | `merge-base(GIT_REF, HEAD)..HEAD` の新規cycle、境界違反、公開API変更、blast radius。`changed_oid`は監査対象のHEADです。base snapshotが無い場合、3つの比較検査はindeterminateになり、blast radiusは評価されます |
| グラフ由来のhotspot | `hotspots` | fan-in / fan-out / reverse impact / Git churn / runtimeの整数basis-point順位。各findingの`hotspot_scores`にraw、正規化値、weight、available、totalを構造化して出力します。confidenceの上限は`probable`です |
| エージェントからの調査 | `agent-config`、`depgraph-mcp` | 検証済みパッケージに結び付いたMCPホスト設定。`health_*` toolも上と同じ判定の限界を持ちます |

### 依存一覧の辺種別を絞り込む

`deps`と`dependents`は、既定では依存の辺だけを辿り、構造上の辺を除きます。
構造上の辺は`contains`（パッケージがファイルを含む）、`declares`（ファイルがシンボルを宣言する）、`generated_from`（生成ファイルが元のファイルから作られる）の3種類です。
そのため既定の件数は、依存しているファイルの数になります。
v0.6.4までと同じく構造上の辺も辿りたい場合は、`--structural-edges include`を指定します。

```bash
depgraph dependents path:src/a.ts --json
depgraph dependents path:src/a.ts --structural-edges include --json
depgraph deps path:src/app.ts --transitive --edge-kind imports --edge-kind type_uses --json
```

- `--edge-kind`は辿る辺の種類を指定します。複数回指定でき、指定した種類の辺だけを辿ります。
- 絞り込みは走査の段階でかけます。そのため、件数と走査数（CLIのページ出力では`traversed_items`、MCPの応答では`traversed_edges`）は選んだ辺だけを数えます。
- `--edge-kind`を指定した場合は、指定した種類だけで辿る辺が決まります。`--structural-edges`を省略していれば、`--edge-kind contains`のように構造上の辺も指定できます。
- `--structural-edges exclude`を明示し、構造上の辺を`--edge-kind`にも指定すると、矛盾する指定としてエラーになります。
- 絞り込み条件を変えた場合、前の`--cursor`は使えません。v0.6.4までに取得したcursorは、`--structural-edges include`を指定したときだけ使えます。

MCPの`graph_dependencies_list`と`graph_dependents_list`では、同じ意味の`edge_kinds`と`structural_edges`を使います。

### dependents と impact の結果の違い（symbol 単位の依存）

同じファイルでも、`dependents`と`impact`の結果の大きさは大きく違うことがあります。
例えば Rust HIR を通した depgraph-cli 自身の Store では、`crates/depgraph-core/src/config.rs`の`dependents`は 12 ファイル、`impact`は 146 ファイルでした。`--rollup symbols`で symbol の依存をまとめると 17 ファイルになり、そのうち 5 ファイルは`dependents`の一覧にないファイルでした。

- `dependents` / `deps`は、選んだノードに直接つながる辺だけを返します。既定では構造上の辺も除きます。
- `impact`は、すべての種類の辺を逆向きに推移的にたどります。構造上の辺（モジュールがファイルを宣言する`declares`など）も、その先の semantic の辺もたどります。
- Rust HIR と Web の semantic 解析が出す辺（`calls`、`type_uses`、`imports`など）は、symbol / type / module のノードに張られます。file のノードには張られません。そのため、ファイルを選んだ`dependents` / `deps`には symbol 単位の依存が出ません。
- crate をまたぐ import（`use depgraph_core::...`）は、syntax 解析では相手の package に結び付き、file → file の辺になりません。re-export 越しの import（`pub use`を経由した`use`）は、同じ crate の中なら syntax 解析が re-export をたどって定義元の file に結び付けます。ただし、曖昧な glob や`cfg`ごとに先が変わる re-export など、たどれない場合は途中のモジュールの file に残ります。HIR ではこれらが module / type / symbol への semantic の辺になるので、ファイルの`dependents` / `deps`には出ません。

ファイル単位で symbol の依存を見たいときは、`--rollup symbols`を付けます。

```bash
depgraph dependents path:crates/depgraph-core/src/config.rs --rollup symbols --json
depgraph deps path:crates/depgraph-core/src/lib.rs --rollup symbols
```

- 辺の一覧（`items`、`total_items`、`traversed_items`）は、オプションなしのときと同じです。まとめた結果は別のフィールド`symbol_rollup`に入ります。新しい辺は作りません。
- まとめる対象は、選んだファイルが所有するノードの semantic の辺です。ノードの`source_path`がそのファイルを指すか、そのファイルがノードを`declares`しているとき、そのファイルが所有すると見なします。
- `dependents`では、所有するノードへ入る辺を、辺が書かれたファイル（辺の evidence の path）ごとにまとめます。`deps`では、そのファイルに書かれた出る辺を、相手のノードを所有するファイルごとにまとめます。`mod name;`で宣言した Rust のモジュールは宣言したファイルが所有しますが、モジュールのファイルに書いた`use`は、そのファイルの`deps`に出ます。
- `symbol_rollup.files[]`の各要素は、`path`、`node_id`、`edge_count`、kind ごとの件数`edge_kinds`、元の辺の ID（ID 順に最大 16 件の`edge_ids`）を持ちます。`file_edge`は、そのファイルとの直接の辺が辺の一覧にもあるかを示します。
- 相手にファイルがない辺（外部 crate、解決できなかった呼び出し先など）は`unattributed_edges`に数えます。
- `--edge-kind`と`--phase`などの絞り込みは、まとめる辺にもかかります。構造上の辺はまとめません。`--transitive`とは一緒に使えません。
- snapshot に semantic の辺が 1 本もないとき（Rust を syntax-only で解析した Store など）は、`status`が`no_semantic_edges`になります。理由は`analysis_degradations`で確かめます。選んだノードがファイルでないときは`root_not_file`です。

MCPの`graph_dependencies_list`と`graph_dependents_list`では、同じ意味の`rollup: "symbols"`を使います。

## health の confidence の読み方

`health`の結果には、どこまで確信できるかを示すconfidenceが付きます。

- `confirmed`は`unused-file`、`unused-export`、`unused-type`、`unused-dependency`にだけ使います。
  適用対象の解析済みprofileすべてで未使用かつsemantic-completeであり、hard blockerがないことを表します。
- `test-only-dependency`、`manifest-mismatch`、audit、hotspotは未使用の証明ではないため、`probable`が上限です。
- unused findingの`probable`は、使用もhard blockerも見つからないものの、適用対象profileがsyntax-completeまでの状態です。
- `indeterminate`は、coverageやsurface証拠の不足、公開surface、entry point、動的ロード、candidate、unresolved、profile未走査、manifest driftなどのblockerにより断定できない状態です。

hotspotの層の充足は`hotspot_scores.available`で確認します。

特定のディレクトリや種類のhotspotだけを見たい場合は、`--path-prefix`と`--node-kind`で結果を絞り込みます。
どちらも複数回指定できます。

```bash
depgraph hotspots --path-prefix src/lib --node-kind file --node-kind symbol --json
```

- `--path-prefix`はリポジトリ相対パスにディレクトリ境界で前方一致します。
  `src/lib`は`src/lib/a.ts`に一致し、`src/library.ts`には一致しません。
  パスを持たないfindingは一致しません。
- `--node-kind`は`file`、`module`、`symbol`、`type`、`route`のいずれかです。
- 絞り込みは採点の後にかけます。
  そのため、スコアの正規化とfinding IDは絞り込まない場合と同じ値になります。
  `collection_digest`は絞り込み条件ごとに変わります。
- `--churn-path`はGit churnの入力だけを絞り、結果のfindingは減らしません。

MCPの`health_hotspots_list`では、同じ意味の`path_prefixes`と`node_kinds`を使います。

fan-inのrawは、snapshot内でそのnodeをtargetとするedgeの件数です。
構造辺（`contains`、`declares`、`generated_from`）を含むすべての辺種別、phase、profileを数え、同じsourceからの複数のedge（siteや辺種別、profileの違い）もそれぞれ1件と数えます。
fan-outはsourceの側を同じ規則で数え、reverse impactはすべての辺を逆にたどった推移的な依存元を重複なしで数えます。
そのため、構造辺を既定で除外し、`detail: "paths"`では(source, target, kind)の組で重複を除く`graph_dependents_list`の件数とは一致しないことがあります。
fan-inだけで順位を付けるには、`weight_fan_in`（CLIでは`--weight-fan-in`）を10000、他のweightを0にします。

findingの`suppressions`は、v1ではwire互換性のために残している出力専用のfieldです。
CLI、MCP、policyからの入力経路はなく、組み込みanalyzerは常に空配列を返します。
auditは、Store schema 18以降が保存するpolicy digest、analyzer version、finding contract versionを比較します。
provenanceの欠落や差異は、fail-closedで`incomparable-policy`または`incomparable-contract`として扱います。
`v0.6.3`はStore schema 19を使います。
公開済みstable `v0.5.4` artifactのStoreはschema 17であり、このprovenance契約の対象外です。
sourceを自動で変更することはありません。
完全な契約は[code-health finding ADR](../40_arch_design/adr-code-health-finding-contract.md)を参照してください。

## セレクター（調べたい対象の指定方法）

**セレクター**は、グラフ内のファイルやパッケージなどをCLIから指定するための書き方です。
`id:`、`path:`、`package:`、`route:`、`symbol:`、`type:`を受け付けます。
Next.js App Routerではsource版（`next:/checkout`）とsemantic版（`next:app:page:/checkout`）のrouteノードがあるため、`route:/checkout`は曖昧になることがあります。
その場合は`route:next:app:page:/checkout`のように表示名で指定するか、エラーの候補にある`id:`を使います。
候補が複数ある場合は、コマンドが返した完全な安定IDを`id:<stable-id>`として指定します。

`v0.6.4` のリリース候補では、`package:`でnpmなどの外部依存パッケージも指定できます。
`package:stripe`、`package:stripe@18.0.0`、`package://npm:stripe@18.0.0#node_modules/stripe`のようなlocator完全指定が使えます。
公開済みの`v0.6.3`はこの指定に対応していません。
詳しい規則は[CLI動作リファレンス（英語）](../reference/cli-behavior.md#selectors)を参照してください。

## 依存箇所の分類

静的解析で認識した依存箇所は、次のいずれかに分類されます。

- **`resolved`**：根拠から依存先を一意に特定できました。
- **`candidates`**：有限の候補までは絞り込めましたが、一意とは証明できません。
- **`external`**：標準ライブラリや外部パッケージなど、リポジトリ外の依存先です。
- **`unresolved`**：依存箇所は見つかりましたが、依存先を安全に特定できません。

この分類は、未解決の依存を推測で`resolved`へ格上げしないためのものです。
スキップした入力と未対応の入力はカバレッジ台帳へ記録します。
そのため、抽出したグラフと解析範囲の完全性を分けて評価できます。

## 解析結果の完全性

**`semantic-complete`**は、プロファイルのセマンティック解析が所定の完全性条件を満たしたことを示します。
「依存関係を推測で補った」という印ではありません。
構文解析が完了し、互換性を検証したセマンティックバックエンドがグラフを生成し、セマンティック問題、スキップ、未対応、未解決がすべて0件になったプロファイルだけに付きます。
`candidates`と`external`は状態が明示されるため、この判定を妨げません。
RustとWebの詳しい条件は[解析結果の完全性（英語）](../reference/analysis-completeness.md)を参照してください。

## 厳格ポリシーと終了コード

既定の`.depgraph.toml`の厳格ポリシーでは、スキップしたファイル、未対応構文、未解決箇所を許容しません。
候補依存と外部依存だけでは厳格モードの失敗になりません。
`depgraph scan --strict`はCI向けの実行です。
普段の調査では既定のスキャンを使い、`doctor`と`unresolved`で解析範囲を確認してください。

| コード | 意味 |
| ---: | --- |
| 0 | ポリシー違反なしで処理が完了した |
| 1 | グラフまたはカバレッジのポリシー違反 |
| 2 | CLIの使用方法、セレクター、設定のエラー |
| 3 | ワーカー、ツールチェーン、グラフ検証、プロトコルの失敗 |
| 4 | プロジェクトコード実行権限またはセキュリティポリシーの失敗 |

失敗または部分的なスキャンと診断も保存されます。
ただし、`latest successful`が指す先を更新するのは、ポリシーを通過した完全なスキャンだけです。

## 変更ファイル全体の影響範囲

`impact --changed <GIT_REF>` のセレクターを省略すると、変更されたファイル全体を起点に逆向きの影響範囲を返します。
グラフの読み込みは 1 回だけで、影響範囲は全変更ノードを起点にした 1 回の逆向き探索で求めます。
そのため、ファイルごとに `impact` を実行するより速くなります。
`changed_paths` を求めるために、取り込んだ範囲の中で変更パスごとの逆向き探索を追加で行います。
この追加探索が作業量の上限を超えると、終了コード 3 で失敗します。
セレクターを付けた `--changed` は従来どおり、そのセレクターを注目点にします。

`--json` では `data.mode` が `changed_set` になります。主なフィールドは次のとおりです。

- `impacts[]`: `node`、`depth`、`changed_node_id`、`changed_paths`、`dependency_path`
  - `depth` は最も近い変更ノードからの距離で、変更ノード自身は 0 です。
  - `changed_paths` は、そのノードに届く変更パスのすべてです。
  - `dependency_path` は、影響ノードから変更ノードの順に並びます。
- `unmapped[]`: グラフに対応付けられなかった変更です。`status`、`old_path`、`new_path`、`reason` を持ちます。
  - `reason` は、Git 上で削除された場合の `deleted` か、スナップショットに無い場合の `not_in_snapshot` です。
- `mappings`、`changed_nodes`、`diagnostics`、`complete`、`filters`、`changed_set`

終了コードは次のとおりです。

- セレクターも `--changed` も無い場合は 2 です。
- スキャンの `source_revision` が HEAD と一致しない場合は 2 です。
- 探索の上限を超えた場合は 3 です。

## CLIコマンド例

```sh
# 任意の追跡対象設定です。設定がなくてもスキャンできます。
depgraph init .

# 安全な静的解析です。対象リポジトリを変更しません。
depgraph scan /path/to/repository
depgraph scan /path/to/repository --strict
depgraph scan /path/to/repository --no-cache
depgraph scan /path/to/repository --plan --json
depgraph scan /path/to/repository --split-plan --json

# ワーカーの起動やストアの変更をせずに、プロファイル選択を確認します。
depgraph profiles plan /path/to/repository
depgraph profiles plan /path/to/repository --profile-budget 8 --json
depgraph profiles plan /path/to/repository --profiles-file profiles.json --json

# 前景で監視デーモンを起動し、別のプロセスから状態確認と停止を行います。
depgraph daemon start /path/to/repository
depgraph daemon status /path/to/repository --json
depgraph daemon stop /path/to/repository

# 権限を伴うビルド観測です。実行ごとに明示的な同意が必要です。
depgraph resolve --build /path/to/repository --allow-project-code
depgraph resolve --build /path/to/repository --allow-project-code --json

depgraph doctor --json
depgraph doctor --details --json
depgraph doctor --root /path/to/repository --json
depgraph deps path:src/app.ts --transitive --max-items 100 --max-bytes 1048576
depgraph deps path:src/app.ts --transitive --cursor "$NEXT_CURSOR" --json
depgraph deps path:src/app.ts --transitive --all --json
depgraph dependents package:example
depgraph why path:src/app.ts 'route:/products/$id'
depgraph impact path:src/app.ts
depgraph impact package:example --changed origin/main --depth 4
depgraph impact 'route:/products/$id' --changed HEAD~1 --profile web:production:server --json

# セレクターを省略すると、変更されたファイル全体を起点にした影響範囲を返します。
depgraph impact --changed origin/main
depgraph impact --changed origin/main --depth 4 --json
depgraph cycles --level file

# Goのセマンティックグラフでは正規リゾルバーIDを使います。
depgraph deps symbol:example.com/semantic/model.Build --transitive
depgraph dependents type:example.com/semantic/model.Worker --json
depgraph why symbol:example.com/semantic/model.Build type:example.com/semantic/model.Input --json
depgraph cycles --level symbol

# セレクターが曖昧な場合は、候補に含まれる安定IDで再実行します。
depgraph deps "id:$STABLE_ID" --json

depgraph unresolved --max-items 100 --json
depgraph unresolved --all --json

# ストアを変更せずに、外部の実行時トレースを検証してグラフと照合します。
depgraph runtime validate --file runtime-trace.json
depgraph runtime validate --file runtime-trace.json --json

# 完了済みの不変スナップショットに名前を付けて確認します。
depgraph snapshot create baseline
depgraph snapshot list --json
depgraph snapshot show baseline
depgraph snapshot show snapshot:sha256:... --json

# 名前または安定IDで完了済みスナップショットを比較します。
depgraph diff baseline current
depgraph diff baseline current --json
depgraph diff baseline current --kind symbol --profile web:production:server
depgraph diff baseline current --phase semantic --status unresolved

depgraph export --format json --output graph.json
depgraph export --format dot > graph.dot
depgraph export --format mermaid > graph.mmd
depgraph export --format graphml --output graph.graphml
```

## さらに詳しく

- [CLI動作リファレンス（英語）](../reference/cli-behavior.md)：Store、bounded query、snapshot、diff、impact、監視デーモン、セレクター
- [アーキテクチャポリシー契約（英語）](../reference/architecture-policy.md)
- [実行時トレースの取り込み契約（英語）](../reference/runtime-trace.md)
- [安全なスキャンの境界](../reference/safe-scan-boundary.ja.md)
- [ビルドモードの同意境界](../reference/build-mode.ja.md)
