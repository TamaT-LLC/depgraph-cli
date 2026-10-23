# 未リリース

v0.7.2 向けの変更と移行手順は [v0.7.2 リリースノート](v0.7.2.md) を参照してください。
公式 Release と公開後証跡が揃うまでは、v0.7.1 が公開済み stable です。

## HIR を通した大きな Store で impact が失敗する問題を直す

Rust HIR を通した depgraph-cli 自身の Store で、CLI の `depgraph impact` と MCP の `graph_impact_get` が、selector・`--depth`・`--max-nodes` に関係なく `request exhausted a service resource limit: preprocessing_work_items=1000000 (observed 1020958)`（終了コード 3）で失敗していた問題を直す。`--changed` / `changed_since` の経路も同じだった。v0.7.2 の #620 の修正は path step の後処理だけを直したもので、impact にはほかにも snapshot 全体に比例する作業を返す結果に比例する作業と同じ上限（1,000,000）で数えている箇所が残っていた。

- impact の前処理は、node・site・edge・evidence の件数を 1 つずつ 1,000,000 と比べていた。上の Store は evidence だけで 1,020,958 件ある。この検査をやめ、全 node・全 site・全 edge・全 evidence を 1 回ずつ訪ねる作業の合計を、cycles / unresolved の索引や #620 の走査と同じ固定の上限（16,000,000）で数える。上の Store では 1,959,234 になる。
- filter を通る全 edge を並べる adjacency（向きごと）と、`--session` / `--environment` を指定したときの runtime context の索引も、snapshot 全体に比例するので 16,000,000 で数える。上の Store の adjacency は向きごとに 1,229,916 で、前処理の検査を直しても 1,000,000 を超えていた。
- selector の解決、変更したファイルと node の対応付け、`changed_paths` の帰属、返す dependency path の組み立ては、従来どおり 1,000,000 で数える。
- 上の Store で `crates/depgraph-core/src/config.rs` の impact は 304 件（148 ファイル）、`--changed HEAD` は 652 件を返す。MCP の `graph_impact_get` も同じ 304 件を返す。返す内容と順序は変えない。1,000,000 を超える evidence と edge を足した生成 snapshot で、足す前と同じ結果を返すことを回帰テストで確かめた。

互換性:

- 既定値と上限の値は変えない。`--depth` / `--max-nodes` / `--max-edges` の意味も変えない。
- 前処理が 16,000,000 に当たったときは、`preprocessing_work_items` の `maximum` が 16,000,000 になり、`observed` は付かない。従来は `maximum` 1,000,000 と、上限を超えたレコード数を `observed` に返していた。

## v0.7.2 のリリースノートの訂正

v0.7.2 のリリースノートの「HIR を通した大きな Store で deps / dependents が失敗する問題を直す」では、同じ経路を通る `depgraph impact` と MCP の `graph_impact_get` も直ったと読める書き方をしたが、誤りだった。v0.7.2 でも impact は上の理由で失敗する。この版で直す（詳細は [v0.7.2 リリースノートの「訂正」](v0.7.2.md#訂正)）。
