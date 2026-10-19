# 未リリース

v0.7.0 向けの変更と移行手順は [v0.7.0 リリースノート](v0.7.0.md) を参照してください。
公式 Release と公開後証跡が揃うまでは、v0.6.4 が公開済み stable です。

## MCP のエラー応答に原因の詳細を含める

MCP ツールのエラー応答 `error.details` に、原因を特定できる情報を追加する（[#565](https://github.com/TamaT-LLC/depgraph-cli/issues/565)）。
`contract_version` は `depgraph-mcp-tools-v1` のままで、既存のフィールドと `details` の既存の形は変えない。

- `RESOURCE_EXHAUSTED` の `details`（`kind: "resource_limit"`）に、当たった上限の `limit` と `maximum` に加えて、止まった時点の処理量 `observed` と、上限を動かせる引数 `argument`（例: `max_traversal`）を任意フィールドとして含める。`limit` に `snapshot_edges` と `preprocessing_work_items` を追加する。引数を上げれば通る場合、`remediation` は `narrow_query` ではなく `increase_limit` になる。
- `INVALID_ARGUMENT` の `details` に `kind: "argument"` を追加し、問題の引数名 `argument` と理由 `reason`（`missing` / `unknown_argument` / `invalid_value` / `out_of_range` / `too_many_items` / `ambiguous_selector`）を返す。スキーマにない引数は名前を返さない。
- セレクターに一致するノードがない場合は、`INVALID_ARGUMENT` ではなく `NOT_FOUND`（`reason: "no_matching_node"`）を返す。
- `graph_query` の不正な query には `kind: "query_diagnostic"` を返し、失敗したコード、構文の節、見つかったトークンの種類、行・列・バイト位置を示す。query の本文は返さない。ツール説明に構文と例を載せる。
- CLI の `deps` / `dependents` / `why` がトラバーサル上限で止まったときのメッセージに、上限名と値を付け足す（例: `request exhausted a service resource limit: max_traversal=1 (observed 1)`）。終了コードは変えない。

`depgraph-mcp-tools` crate の型で応答を `deny_unknown_fields` 付きで Deserialize している利用者は、追加された要素を受け取るために crate を更新する。
存在しないパスを渡したときに `INVALID_ARGUMENT` を前提としていた利用者は、`NOT_FOUND` も扱う。

## 修正

- 大きなリポジトリで、MCP の `health_hotspots_list` と CLI の `depgraph hotspots` が `path_prefixes` / `node_kinds` / `limit` で絞り込んでも resource limit（`RESOURCE_EXHAUSTED`、exit 3）で失敗していた問題を直す。reverse impact を subject ごとに探索せず、最大 64 subject をまとめて 1 回の探索で数えるようにして、スコア計算の作業量を減らした。score、順位、finding ID、fingerprint は従来の計算と同じで、絞り込みは従来どおりスコア計算の後に適用する（[#562](https://github.com/TamaT-LLC/depgraph-cli/issues/562)）。
- MCP の `graph_path_get` と CLI の `depgraph why` が、snapshot の edge 数が `max_traversal`（既定 50,000）を超えると、1 ホップの経路でも resource limit で失敗していた問題を直す。`max_traversal` は探索で訪れた edge の数だけを制限し、隣接表の構築は他の依存クエリと同じ snapshot 全体の前処理上限で制限する（[#562](https://github.com/TamaT-LLC/depgraph-cli/issues/562)）。
- MCP の `agent_nodes_list` が、worker 由来の `file:` などの locator を持つノードを返すときに `INTEGRITY_FAILURE` で失敗していた問題を直す。返すノードの locator を `id:` に置き換えるようにした（[#563](https://github.com/TamaT-LLC/depgraph-cli/issues/563)）。
- Rust の syntax 解析で `use crate::a::Item` などのパスを、`mod a;` を宣言したファイルではなくモジュール `a` の本体ファイルへの依存として記録する。HIR が予算超過で syntax-only に落ちた scan でも、crate 内のファイルの被依存が `mod` 宣言の 1 件だけにならない（[#564](https://github.com/TamaT-LLC/depgraph-cli/issues/564)）。
- 同じモジュールにある同名の sysroot 定義（`std::fs::read` と `impl Read for File` の `read` など）が同じ ID になり、Rust の HIR 結果全体が破棄されていた問題を修正する（[#564](https://github.com/TamaT-LLC/depgraph-cli/issues/564)）。
- Rust worker の大規模ワークスペースでの HIR 結果の統合を速くし、ピークメモリを下げる。site ごとに全 edge を走査していた検証と診断集約を索引引きにし、HIR の統合時に rust-analyzer のデータベースとグラフの複製を同時に保持しないようにする（[#564](https://github.com/TamaT-LLC/depgraph-cli/issues/564)）。
- npm launcher が platform 別の optional package を見つけられないとき、実行中の Node.js が `engines`（`>=24.0.0`）を満たすかを先に確かめる。満たさない場合は、Node.js の不足が原因で npm が platform package を入れなかったことと切り替え方を表示する。npx から起動された場合は、Node.js を切り替えても npx が不完全なインストール先を再利用し続けるため、`npm cache npx rm <key>` で消すキーとディレクトリも表示する（[#567](https://github.com/TamaT-LLC/depgraph-cli/issues/567)）。
- `depgraph mcp setup` / `update` は、safe scan が走る場合、リリース資産の取得と scan の前に TypeScript/JavaScript 解析用の Node.js を検査し、`>=24.0.0` を満たさなければ検出した Node.js のパスとバージョン、切り替え方を示して即座に失敗する。`package.json` を含まないリポジトリでは Node.js を要求しない（[#567](https://github.com/TamaT-LLC/depgraph-cli/issues/567)）。
