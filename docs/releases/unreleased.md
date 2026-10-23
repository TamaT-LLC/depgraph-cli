# 未リリース

v0.7.2 向けの変更と移行手順は [v0.7.2 リリースノート](v0.7.2.md) を参照してください。
公式 Release と公開後証跡が揃うまでは、v0.7.1 が公開済み stable です。

## 大きな Store で unresolved と symbol 単位の cycles が既定値で通るようにし、export の上限を CLI から広げられるようにする

Rust HIR を通した depgraph-cli 自身の Store（v0.7.2 で計測。resolved 156,650、unresolved 100,440、evidence 約 100 万）で、次の 4 点が使いにくかった。

- CLI の `depgraph unresolved` と MCP の `graph_unresolved_list` が、`--max-items 10` / `limit` や `--kind call` / `kinds` を付けても、既定の `max_traversal`（50,000）で失敗していた。#619 以降、`max_traversal` は一致した unresolved site の総数を数えていた。
- `depgraph cycles --level symbol` が `max_traversal=50000` で失敗し、エラーに `observed` が出なかった。
- CLI の `depgraph export` には、MCP の `max_nodes` に当たる上限を広げる手段がなく、`export_nodes=50000 (observed 217340)` で失敗していた。
- テキスト出力の edge 行が `file:sha256:…` の ID だけで、何の依存か分からなかった。

変更:

- `unresolved` / `graph_unresolved_list` の `max_traversal` は、返す site の数を数える。ページングする一覧なので、1 ページ分（`--max-items` / `limit`）だけを数え、`--all` では一致したすべてを数える。`total_items` と summary は従来どおり一致したすべてを数え、全件の選択・並べ替え・組み立ては固定の上限（16,000,000）で数える。
- `cycles` / `graph_cycles_list` の `max_traversal` は、返す代表 cycle を組み立てるときに訪れる edge の数を数える。強連結成分を探す順方向・逆方向の探索は、level の全 edge を結果に関係なく訪ねるので、固定の上限（16,000,000）で数える。`max_traversal` を超えたときは、必要だった訪問数を `observed` に入れる。
- CLI の `export` に `--max-nodes`（既定 50,000）と `--max-edges`（既定 100,000）を足す。どちらも `impact --max-nodes` と同じ 1..=1,000,000 を受け付ける。MCP の `graph_export` は inline で返すので、上限（50,000 / 100,000）を変えない。
- CLI は上限に当たったとき、エラーの次の行に `hint:` を出し、広げるオプションと必要な値を案内する（例: `hint: rerun with --max-traversal 126128 or more (accepted 1..=1000000)`）。標準出力の export が 16 MiB を超えたときは `--output` を、`--output` の 512 MiB を超えたときは `--phase` / `--profile` やより小さい `--format` を案内する。
- `deps` / `dependents`（`--rollup symbols` を含む）/ `why` / `impact` / `cycles` のテキストの edge 行は、ID の後ろに括弧で、file ならリポジトリからの相対パス、それ以外なら表示名と定義元のファイルを出す（例: `file:sha256:… (crates/depgraph-core/src/config.rs) --imports [...]--> …`）。
- `--rollup` などで JSON に加わる分も含め、テキストの `output_bytes` を JSON の `serialized_output_bytes` と同じ値にする。

dev build で scan した depgraph-cli 自身の Store（node 242,187、unresolved 126,128、edge 414,093、evidence 1,038,255）で、`unresolved` は既定値・`--max-items 10`・`--kind call` のいずれも通り、`cycles --level symbol` は 137 件を返す（代表 cycle の組み立てで訪れる edge は 999）。

互換性:

- 既定値と上限の値は変えない。
- `unresolved` / `graph_unresolved_list` は、従来通っていた要求はそのまま通る。ページの大きさが `max_traversal` 以下なら、一致した site が多くても通るようになる。`--all` は従来どおり一致したすべてを数える。
- `cycles` / `graph_cycles_list` は、従来通っていた要求はそのまま通り、より小さい `max_traversal` でも通る。上限超過の details に `observed` が加わる。
- テキスト出力の edge 行と `cycles` の行の形が変わる。JSON の出力は変わらない。テキストの `output_bytes` は、`--rollup` や partial metadata、`analysis_degradations` があるときに JSON と同じ値になるよう大きくなる。
- `export` で `--output` に書けるのは 512 MiB までのまま。上の Store の全体を JSON で書くと約 2.1 GB になり、`output_bytes` の上限に当たる。`--format dot`（約 170 MB）や `--phase source`（約 250 MB）なら書ける。
- core の `UnresolvedRequest` に `with_page_items`、`CyclesResult` に `nodes`、`GraphExportRequest` に `try_new_local` と定数 `MAX_LOCAL_GRAPH_EXPORT_NODES` / `MAX_LOCAL_GRAPH_EXPORT_EDGES` が加わる。tool catalog の `max_traversal` の説明が変わり、その digest が変わる。shared schema と `contract_version` は変えない。

## HIR を通した大きな Store で impact が失敗する問題を直す

Rust HIR を通した depgraph-cli 自身の Store で、CLI の `depgraph impact` と MCP の `graph_impact_get` が、selector・`--depth`・`--max-nodes` に関係なく失敗していた問題を直す。CLI は `request exhausted a service resource limit: preprocessing_work_items=1000000 (observed 1020958)` を出して終了コード 3 で終わり、MCP は `RESOURCE_EXHAUSTED` と `{"kind":"resource_limit","limit":"preprocessing_work_items","maximum":1000000,"observed":1020958}` の details を返していた。`--changed` / `changed_since` の経路も同じだった。v0.7.2 の #620 の修正は path step の後処理だけを直したもので、impact にはほかにも snapshot 全体に比例する作業を返す結果に比例する作業と同じ上限（1,000,000）で数えている箇所が残っていた。

- impact の前処理は、node・site・edge・evidence の件数を 1 つずつ 1,000,000 と比べていた。上の Store は evidence だけで 1,020,958 件ある。この検査をやめ、全 node・全 site・全 edge・全 evidence を 1 回ずつ訪ねる作業の合計を、cycles / unresolved の索引や #620 の走査と同じ固定の上限（16,000,000）で数える。上の Store では 1,959,234 になる。
- filter を通る全 edge を並べる adjacency（向きごと）と、`--session` / `--environment` を指定したときの runtime context の索引も、snapshot 全体に比例するので 16,000,000 で数える。上の Store の adjacency は向きごとに 1,229,916 で、前処理の検査を直しても 1,000,000 を超えていた。
- selector の解決、変更したファイルと node の対応付け、`changed_paths` の帰属、返す dependency path の組み立ては、従来どおり 1,000,000 で数える。
- 上の Store で `crates/depgraph-core/src/config.rs` の impact は 304 件（148 ファイル）、`--changed HEAD` は 652 件を返す。MCP の `graph_impact_get` も同じ 304 件を返す。返す内容と順序は変えない。1,000,000 を超える evidence と edge を足した生成 snapshot で、足す前と同じ結果を返すことを回帰テストで確かめた。

互換性:

- 既定値と上限の値は変えない。`--depth` / `--max-nodes` / `--max-edges` の意味も変えない。
- 前処理が 16,000,000 に当たったときは、`preprocessing_work_items` の `maximum` が 16,000,000 になり、`observed` は付かない。従来は `maximum` 1,000,000 と、上限を超えたレコード数を `observed` に返していた。

## v0.7.2 のリリースノートの訂正

v0.7.2 のリリースノートの「HIR を通した大きな Store で deps / dependents が失敗する問題を直す」では、同じ経路を通る `depgraph impact` と MCP の `graph_impact_get` も直ったと読める書き方をしたが、誤りだった。v0.7.2 でも impact は上の理由で失敗する。この版で直す（詳細は [v0.7.2 リリースノートの「訂正」](v0.7.2.md#訂正)）。
