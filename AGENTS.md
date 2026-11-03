# AGENTS.md

この repository で作業する agent への規則と、各規則を強制するものの表です。規則を足すときは、強制する仕組みを同じ変更で足してください。仕組みで防げない判断の規則だけを、失敗の例と一緒にここへ書きます。

| 規則 | 強制するもの |
| --- | --- |
| CLI の process テストは、終了コードを `.code(N)` で固定する。`.failure()` は 0 以外のどの終了コードでも通る。 | `clippy.toml` の `disallowed-methods`。CI の `cargo clippy --workspace --all-targets --locked -- -D warnings` が失敗する。 |
| `vdg run` の手順は、失敗を期待するときに `--expect-exit N` を書く。 | `.claude/skills/verify-depgraph/scripts/vdg` の `cmd_run`。`--expect-exit` を省くと終了コード 0 を要求する。 |
| リリースノートと docs に書く挙動は、コードかテストで確かめてから書く。 | なし。判断の規則なので、下の例を読む。 |
| テストの assert を `if let` や絞り込みのループの中だけに置かない。 | なし。判断の規則なので、下の例を読む。 |

## リリースノートと docs に書く挙動を確かめる

`docs/releases/` と `docs/` に書く挙動は、応答型、エラー変換、テストを開いて確かめてから書いてください。次の誤りは、どれも CodeRabbit か後の PR が見つけたものです。

- #582 は、`agent_nodes_list` も `repository_path` を返すと書きました。応答型 `AgentNodeSummary` にこの field はなく、返すのは `agent_node_get` だけでした。tool ごとに応答型を開いてください。
- #630 は、CLI の終了コード 3 と MCP の `RESOURCE_EXHAUSTED` を 1 文にまとめ、MCP も終了コードを返すように読める文を書きました。CLI と MCP の挙動は別の文で書いてください。
- #594 は、同じ上限について 64 subject と 256 subject の記述を並べ、どちらが今の値か読めない書き方をしました。新しい項目を足すときは、同じ機能の既存の項目と数値を突き合わせてください。
- #627 は、各項目を 1 回ずつ走査すると説明しながら、その合計と合わない作業量を書きました。内訳を書くときは足し算を確かめてください。
- #582 は、v0.7.1 のノートに「Rust の `unused-file` の finding ID は変わらない」と書きました。実際には変わり、#607 が公開後に訂正しました。互換性の主張は、変更前と変更後の binary で実測してください。

## assert を条件の中だけに置かない

assert が条件の中にしかないと、fixture がその条件を満たさないときにテストは何も確かめずに通ります。

- #584 のテストは `if let Some(cursor) = ...["next_cursor"].as_str() { ... }` の中で 2 ページ目を確かめていました。fixture で一致する node は 1 つだけで、`next_cursor` が出ないため、中の assert は一度も走りませんでした。Rust では `let Some(cursor) = ... else { panic!(...) };` か `.expect(...)` を使い、分岐に入ることも固定してください。
- #558 の Go のテストは、`for _, edge := range result.Edges` の中で `edge.SiteID == site.ID` の edge だけを比べていました。一致する edge が 0 本でもテストは通ります。一致した件数を数え、期待した件数でなければ失敗させてください。
