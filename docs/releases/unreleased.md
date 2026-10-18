# 未リリース

v0.6.4 までの変更は [v0.6.4 リリースノート](v0.6.4.md) を参照してください。

## 追加

- `depgraph impact --changed <GIT_REF>` をセレクターなしで実行すると、変更されたファイル全体を起点にした逆方向の影響範囲を 1 回で返す。JSON は `data.mode = "changed_set"` で、影響ノードごとの `depth`、届いた変更パス `changed_paths`、対応付けられなかった変更 `unmapped` を含む。セレクター付きの `--changed` は従来どおり。

## 互換性の注意

v0.6.1 の `depgraph-mcp` を現在の Claude Code に登録すると、tools を取得できず `request _meta is missing or has malformed required fields: io.modelcontextprotocol/protocolVersion, io.modelcontextprotocol/clientCapabilities` で失敗する。
v0.6.4 では接続できることを確認している。
`depgraph mcp setup` は実行中の CLI と同じ版の公式リリースを結び付けるため、CLI を v0.6.4 以降へ更新してから `depgraph mcp setup --host claude`（user scope なら `--scope user` も付ける）を再実行する。
手順は README の「ツールが取得できないとき」を参照する。
