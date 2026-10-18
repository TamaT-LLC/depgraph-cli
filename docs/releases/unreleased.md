# 未リリース

v0.6.4 までの変更は [v0.6.4 リリースノート](v0.6.4.md) を参照してください。

## 追加

- `depgraph impact --changed <GIT_REF>` をセレクターなしで実行すると、変更されたファイル全体を起点にした逆方向の影響範囲を 1 回で返す。JSON は `data.mode = "changed_set"` で、影響ノードごとの `depth`、届いた変更パス `changed_paths`、対応付けられなかった変更 `unmapped` を含む。セレクター付きの `--changed` は従来どおり。
