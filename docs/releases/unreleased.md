# 未リリース

v0.7.0 向けの変更と移行手順は [v0.7.0 リリースノート](v0.7.0.md) を参照してください。
公式 Release と公開後証跡が揃うまでは、v0.6.4 が公開済み stable です。

## 修正

- 大きなリポジトリで、MCP の `health_hotspots_list` と CLI の `depgraph hotspots` が `path_prefixes` / `node_kinds` / `limit` で絞り込んでも resource limit（`RESOURCE_EXHAUSTED`、exit 3）で失敗していた問題を直す。reverse impact を subject ごとに探索せず、最大 64 subject をまとめて 1 回の探索で数えるようにして、スコア計算の作業量を減らした。score、順位、finding ID、fingerprint は従来の計算と同じで、絞り込みは従来どおりスコア計算の後に適用する（[#562](https://github.com/TamaT-LLC/depgraph-cli/issues/562)）。
- MCP の `graph_path_get` と CLI の `depgraph why` が、snapshot の edge 数が `max_traversal`（既定 50,000）を超えると、1 ホップの経路でも resource limit で失敗していた問題を直す。`max_traversal` は探索で訪れた edge の数だけを制限し、隣接表の構築は他の依存クエリと同じ snapshot 全体の前処理上限で制限する（[#562](https://github.com/TamaT-LLC/depgraph-cli/issues/562)）。
