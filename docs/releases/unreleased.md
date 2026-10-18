# 未リリース

v0.6.4 までの変更は [v0.6.4 リリースノート](v0.6.4.md) を参照してください。
以下は v0.7.0 に向けた未リリースの変更である。

## 破壊的変更: 依存一覧は構造辺を既定で除外する

MCP の `graph_dependencies_list` / `graph_dependents_list` と CLI の `depgraph deps` / `depgraph dependents` は、既定で構造辺（`contains`、`declares`、`generated_from`）を辿らない（[#541](https://github.com/TamaT-LLC/depgraph-cli/issues/541)）。
構造辺は「パッケージがファイルを含む」「ファイルが symbol を宣言する」「生成ファイルが元ファイルから生成される」というグラフの構成を表し、依存関係ではない。
既定の結果、`total_items`、`traversed_edges` は依存辺だけを数える。
たとえば `package:` セレクターから `contains` で辿っていた依存一覧は、既定では空になる。
`edge_kinds` / `--edge-kind` を指定した場合は、許可リストだけで辿る辺が決まる。`structural_edges` / `--structural-edges` を省略していれば、`contains` などの構造辺も指定できる。exclude を明示して構造辺も許可リストに含めた場合だけ、`INVALID_ARGUMENT`（CLI はエラー終了）になる。

移行手順は次のとおり。

- 従来どおり全種別を辿るには、MCP では `structural_edges: "include"`、CLI では `--structural-edges include` を指定する。
- 既定の依存一覧で発行された cursor は、選択した辺種別に束縛される。v0.6.4 以前に取得した cursor を既定の呼び出しへ渡すと `CURSOR_MISMATCH` になるため、先頭ページから取り直す。`structural_edges: "include"` / `--structural-edges include` を明示した呼び出しでは、従来の cursor をそのまま使える。
- `why` / `impact` の経路探索は変わらない。

## 追加機能

- `depgraph impact --changed <GIT_REF>` をセレクターなしで実行すると、変更されたファイル全体を起点にした逆方向の影響範囲を 1 回で返す。JSON は `data.mode = "changed_set"` で、影響ノードごとの `depth`、届いた変更パス `changed_paths`、対応付けられなかった変更 `unmapped` を含む。セレクター付きの `--changed` は従来どおり。
- MCP の全ツールで `repository_id` を省略できるようにし、省略時はサーバーが束縛するリポジトリを使う。束縛されたリポジトリと最新スナップショットの要約を返す `repository_list` を追加する（[#540](https://github.com/TamaT-LLC/depgraph-cli/issues/540)）。
- `graph_dependencies_list` / `graph_dependents_list` に出力粒度 `detail`（`paths` / `summary` / `full`、既定 `full`）を追加する（[#542](https://github.com/TamaT-LLC/depgraph-cli/issues/542)）。
- `health_hotspots_list` に `path_prefixes` と `node_kinds` の絞り込みを、CLI の `hotspots` に `--path-prefix` と `--node-kind` を追加する。score と finding ID は絞り込み前と変わらない（[#543](https://github.com/TamaT-LLC/depgraph-cli/issues/543)）。
- MCP の `agent_evidence_list` / `agent_sites_list` / `agent_edges_list` が返す import 根拠に、任意フィールド `import` として import の specifier と取り込んだシンボル（`imported_name` / `local_name` など）を含める。依存一覧の `detail: "full"` は従来と同じ形のままで `import` を含まない（[#544](https://github.com/TamaT-LLC/depgraph-cli/issues/544)）。

## 互換性の注意

v0.6.1 の `depgraph-mcp` を現在の Claude Code に登録すると、tools を取得できず `request _meta is missing or has malformed required fields: io.modelcontextprotocol/protocolVersion, io.modelcontextprotocol/clientCapabilities` で失敗する。
v0.6.4 では接続できることを確認している。
`depgraph mcp setup` は実行中の CLI と同じ版の公式リリースを結び付けるため、CLI を v0.6.4 以降へ更新してから `depgraph mcp setup --host claude`（user scope なら `--scope user` も付ける）を再実行する。
手順は README の「ツールが取得できないとき」を参照する。

v0.6.4 以前の `depgraph-mcp-tools` crate の型で応答を `deny_unknown_fields` 付きで Deserialize している利用者は、追加された要素（`AgentEvidence` の `import`、`repository_list` ツール、`error.details` の `kind: "repository"` など）を受け取るために crate を更新する。
