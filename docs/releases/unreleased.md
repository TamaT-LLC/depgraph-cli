# 未リリース

v0.7.1 向けの変更と移行手順は [v0.7.1 リリースノート](v0.7.1.md) を参照してください。
公式 Release と公開後証跡が揃うまでは、v0.7.0 が公開済み stable です。

## MCP のエラー応答の details を残りのツールにも付ける

v0.7.1 で MCP のエラー応答に原因の詳細を含めた（[#565](https://github.com/TamaT-LLC/depgraph-cli/issues/565)）のに続けて、details のないエラーが残っていたツールも同じ形に揃える（[#581](https://github.com/TamaT-LLC/depgraph-cli/issues/581)）。

- `snapshot` / `from` / `to` に snapshot 名・stable ID・`current` 以外の値（`latest` など）を渡したときの `INVALID_ARGUMENT` に、`{"kind":"argument","argument":"snapshot"|"from"|"to","reason":"invalid_value"}` を付ける。値そのものは返さない。
- `graph_dependencies_list` / `graph_dependents_list` の `edge_kinds` が不正なときは、`agent_edges_list` と同じく `argument: "edge_kinds"` と `invalid_value` / `too_many_items` を返す。
- `agent_sites_list` の `site_id` / `node_id`、`agent_node_get` / `agent_edges_list` の `node_id`、`agent_evidence_list` の `site_id`、`agent_nodes_list` / `graph_unresolved_list` の `kinds`、`graph_impact_get` の `conditions`、`resolve_build_submit` の `acknowledgement` / `rust_compiler_precise` の不正値にも、引数名と理由を付ける。
- impact、health、hotspot、snapshot diff、policy、export の上限超過の `RESOURCE_EXHAUSTED` に `kind: "resource_limit"` の details を付ける。`limit` に `impact_nodes` / `impact_edges`（`max_nodes` / `max_edges` で広げられる）、`impact_path_steps`、`changed_paths`、`health_findings`、`health_finding_items`、`health_manifests`、`artifact_items`、`artifact_work_items`、`export_nodes` / `export_edges`（`max_nodes` / `max_edges`）を追加する。health と hotspot の作業量の上限は、既存の `preprocessing_work_items` として返す。
- `graph_export` のセレクターに一致するノードがない場合は、依存一覧と同じく `NOT_FOUND`（`argument: "selector"`、`reason: "no_matching_node"`）を返す。これまでは details のない `INVALID_ARGUMENT` だった。CLI の `export` も、上限やセレクターの失敗を同じ文言で示す。終了コードは変えない。

## Go の file node にリポジトリ相対パスを持たせる

Go worker が出す file node（通常の Go ソース、アセンブリ、`//go:embed` の対象）に、リポジトリ相対パスの `path` property を記録する（[#591](https://github.com/TamaT-LLC/depgraph-cli/issues/591)）。
これまで Go の file のパスは locator `file:<path>` と表示名にしかなかった。core の hotspot は `path` がないと `manifest_path` を読むため、Go のソースとアセンブリの file は `location` と Git churn が `go.mod` に結び付いていた。`//go:embed` の対象は `manifest_path` も持たないため、`location` がなく churn は 0 だった。

- `depgraph hotspots` と MCP の `health_hotspots_list` で、Go の file の finding の `location` が `go.mod` ではなく各ファイルになる。`--path-prefix` / `path_prefixes` で Go のファイルを絞り込めるようになる（従来は `go.mod` のパスでしか一致しなかった）。
- Git churn が各 Go ファイルに対応付けられ、hotspot の `git_churn` layer に反映される（従来は `go.mod` の churn だった）。
- `unused-file` の finding に `location` が付く。
- Go の file も Rust / TypeScript と同じく、パスで entry point（`main.go`、`/cmd/` 配下）と生成物（`/generated/` 配下など）に分類される。該当するファイルの `unused-file` には `entry-point` / `generated-artifact` の blocker が付く。
- file node の `manifest_path` は残す。依存の health 解析は引き続き `manifest_path` から所属する `go.mod` を引く。
- Go の package（node kind `module`）は変えない。package はディレクトリで、宣言元の 1 ファイルがないため、hotspot の `location` と churn は従来どおり `go.mod` になる。

互換性:

- churn layer は rank 正規化なので、Go のファイルだけでなく、Go を含むワークスペースの hotspot の score と順位が変わる。hotspot の fingerprint は score と `location` を含むため、あわせて変わる。hotspot の finding ID は変わらない。
- Go の `unused-file` は、finding ID と fingerprint の両方が変わる。finding ID の witness に、従来は locator `file:<path>` を、今後は `location` のパスを使うため。finding ID で suppression や baseline を管理している場合は、再 scan 後に付け直す。
- 変化は Go を再 scan した snapshot にだけ現れる。scan cache の key は worker バイナリの内容を含むので、更新後の scan で古い結果は再利用されない。Store の移行は不要。hotspot や `unused-file` の fingerprint を baseline に保存している場合は、再 scan 後に baseline を作り直す。
- v0.7.1 で残した MCP 層の locator `file:<path>` からのパスの補完（[#566](https://github.com/TamaT-LLC/depgraph-cli/issues/566)）は、再 scan していない Store の file node が引き続き使う。

## Go の symbol / type に宣言元の位置を持たせ、health の location に行番号を出す

Go worker が出す symbol（名前付き、ローカル、クロージャ、package の初期化）と type のノードに、宣言元ファイルのリポジトリ相対パス `source_path` と、宣言の範囲 `source_span`（`start_line` / `start_column` / `end_line` / `end_column`、1 始まり）を記録する（[#596](https://github.com/TamaT-LLC/depgraph-cli/issues/596)）。Rust / Web worker の symbol / type と同じ形で、値は `declares` relation の evidence と同じ位置になる。generic の instance は、もとの generic の宣言の位置を持つ。
これまで Go の symbol / type は宣言元のパスも行番号も property に持たなかったため、hotspot と `unused-export` / `unused-type` の `location` が null で、Git churn は 0 だった。

あわせて core の health が、入れ子の `source_span` から行・列を読むようにする。これまで `unused-export` / `unused-type` はトップレベルの `start_line` などしか読まず、hotspot は行番号を常に空にしていたため、Rust / Web の symbol / type も `location` にパスしかなかった。

- `depgraph hotspots` と MCP の `health_hotspots_list` で、Go の symbol / type の finding に `location`（宣言元のファイルと行・列）が付く。`--path-prefix` / `path_prefixes` で Go の symbol / type も絞り込める。
- Git churn が Go の symbol / type の宣言元ファイルに対応付けられ、hotspot の `git_churn` layer に反映される。
- `unused-export` / `unused-type` の finding の `location` に、Go は宣言元のパスと行・列が、Rust / Web は行・列が付く。
- hotspot の `location` にも、`source_span` を持つノード（Rust / Go / Web の symbol / type）は行・列が付く。file など `source_span` のないノードは従来どおりパスだけになる。トップレベルの `start_line` などを持つノードは、従来どおりそちらを優先する。
- Go の symbol / type も、パスで entry point（`main.go`、`/cmd/` 配下）と生成物（`/generated/` 配下など）に分類される。これにより、`main.go` や `/cmd/` 配下の非公開の `main` 関数やクロージャが、`entry-point` の blocker 付き・confidence `indeterminate` の `unused-export` として新たに報告される（depgraph-cli 自身の `workers/go` で 5 件）。
- `canonical_identity` とノード ID は変えない（property の追加だけ）。

互換性:

- churn layer は rank 正規化なので、Go を含むワークスペースの hotspot の score と順位が変わる。hotspot の fingerprint は score と `location` を含むため、Go の symbol / type はすべて変わる。Rust / Web の symbol / type の hotspot も、`location` に行・列が加わるため fingerprint が変わる（score と順位は変わらない）。hotspot の finding ID は変わらない。
- Go の `unused-export` / `unused-type` は、finding ID と fingerprint の両方が変わる。finding ID の witness に、従来は locator を、今後は `location` のパスを使うため。finding ID で suppression や baseline を管理している場合は、再 scan 後に付け直す。
- Rust / Web の `unused-export` / `unused-type` は、finding ID は変わらず、`location` に行・列が加わるため fingerprint が変わる。Rust / Web の変化は core の更新だけで現れ、再 scan は不要。
- Go の変化は Go を再 scan した snapshot にだけ現れる。scan cache の key は worker バイナリの内容を含むので、更新後の scan で古い結果は再利用されない。Store の移行は不要。hotspot や unused の fingerprint を baseline に保存している場合は、再 scan 後に baseline を作り直す。
- 更新の前後の snapshot を `depgraph diff` で比べると、Go の symbol / type のノードは `properties` の変更として出る。

## 追加機能

- 解析の精度が落ちた profile を、依存一覧の応答に示す（[#579](https://github.com/TamaT-LLC/depgraph-cli/issues/579)）。MCP の `graph_dependencies_list` / `graph_dependents_list`（`full` / `summary` / `paths` のすべて）と CLI の `deps` / `dependents --json` は、snapshot に精度の落ちた profile があるとき、任意フィールド `analysis_degradations` に profile ごとの `profile_id`、`language`、`analysis_mode`（Rust が rust-analyzer HIR なしで動いた `syntax-only`）、`reasons`（worker が HIR を省いた `rust-hir-memory-budget`、core が worker のメモリ超過後に syntax-only で再実行した `rust-hir-syntax-only-fallback`）を返す。CLI のテキスト出力では先頭に `degraded analysis: ...` の行を出す。劣化のない snapshot の応答は従来とバイト単位で同じ。`depgraph-mcp-tools` crate の型で応答を `deny_unknown_fields` 付きで Deserialize している利用者は、このフィールドを受け取るために crate を更新する。
- MCP の `graph_path_get` に出力粒度 `detail`（`full` / `summary` / `paths`、既定 `full`）を追加する。`summary` は経路の各辺を evidence なしで返し、共通の `phase` などを `common` に 1 回だけ出す。`paths` は各辺を source / target のパス（パスのないノードは ID）と辺の種類だけで返す。省略時の応答は従来と同じ（[#566](https://github.com/TamaT-LLC/depgraph-cli/issues/566)）。
- Rust の `mod foo;`（site kind `module_declaration`）の evidence に、MCP の `import`（`specifier` と `local_name` に module 名、`binding_kind: "module_declaration"`）を付ける。`binding_kind` に値 `module_declaration` が加わる（[#566](https://github.com/TamaT-LLC/depgraph-cli/issues/566)）。

## 修正

- MCP ツールの入力・出力 Schema と、`schemas/` の `depgraph-mcp-tools-v1` / `depgraph-agent-scan-outcome-v2` Schema から、JSON Schema 2020-12 にない `format`（`uint8` / `uint16` / `uint32` / `uint64` / `int64`）を除く。整数の範囲は同じ値を受け付ける `minimum` / `maximum` で表す。Claude Code など Ajv を使う MCP クライアントが接続時に出していた `unknown format "…" ignored` の警告（ツール一覧 1 回で 1,134 件）が出なくなる。`contract_version` は `depgraph-mcp-tools-v1` のままで、受け付ける値は変わらない（[#568](https://github.com/TamaT-LLC/depgraph-cli/issues/568)）。
- Rust worker のピークメモリを下げる。dependency site に結び付いた edge は、出力するまで site の evidence を共有し、同じ evidence の複製を保持しない。depgraph-cli 自身の HIR 解析で、worker のピーク RSS は 4.18 GiB から 3.68 GiB に下がった（attested sysroot あり）。出力する event stream はバイト単位で変わらない。既定の上限（2 GiB）にはまだ収まらないため、既定設定では引き続き syntax-only に切り替わる（[#578](https://github.com/TamaT-LLC/depgraph-cli/issues/578)）。
- Rust worker の出力とピークメモリをさらに減らす。core は Rust worker に evidence の compact encoding（`compact-evidence-v1`）を要求し、worker は site と同じ evidence を edge に書かず、HIR の evidence がすべて同じ値で持つ property（`backend` / `rust_analyzer_version` / `rust_analyzer_revision` / `active_cfg_source`）を profile に 1 回だけ書く。core は取り込み時に元の形へ戻すため、Store の内容と CLI / MCP の出力は変わらない。要求を知らない worker は従来の形で出力し、core はそれも受け付ける。depgraph-cli 自身の HIR 解析（attested sysroot あり）で、worker の出力は 806 MiB から 634 MiB に下がった。ピーク RSS は、前項の変更を含む build を同じ入力で計測し直した値（3.58 GiB。前項の 3.68 GiB とは計測回の違い）から 3.48 GiB に下がった。既定の上限（メモリ 2 GiB、出力 256 MiB）にはまだ収まらないため、既定設定では引き続き syntax-only に切り替わる（[#578](https://github.com/TamaT-LLC/depgraph-cli/issues/578)）。
- Rust HIR を通した大規模な snapshot（depgraph-cli 自身で node 212,915 件、hotspot の subject 69,900 件）で、CLI の `depgraph hotspots` と MCP の `health_hotspots_list` が resource limit で失敗していた問題を直す。hotspot はこれまで health の finding 数の上限（10,000）と graph service の前処理の作業量の上限（1,000,000）を流用していたため、hotspot 専用の上限 `MAX_HOTSPOT_SUBJECTS`（subject 数と返す finding 数、250,000）と `MAX_HOTSPOT_PREPROCESSING_WORK_ITEMS`（作業量、16,000,000）を設けた。reverse impact は、v0.7.1 で最大 64 subject ずつまとめて数えていたバッチを最大 256 subject に広げ、作業量を約半分にした（上の snapshot で約 356 万）。score、順位、finding ID、fingerprint は従来の計算と同じで、health の他の finding の上限は変えない（[#590](https://github.com/TamaT-LLC/depgraph-cli/issues/590)）。

## v0.7.1 のリリースノートの訂正

v0.7.1 のリリースノートでは、Rust の file node に `path` を持たせた変更（[#577](https://github.com/TamaT-LLC/depgraph-cli/issues/577)、[#582](https://github.com/TamaT-LLC/depgraph-cli/pull/582)）で Rust の `unused-file` の finding ID は変わらないと書いたが、誤りだった。finding ID と fingerprint の両方が変わり、`src/lib.rs` などが entry point に分類されて `entry-point` の blocker が付き、confidence が下がる場合がある。finding ID で suppression や baseline を管理している場合は、Rust を再 scan した後に付け直す（詳細は [v0.7.1 リリースノートの「訂正」](v0.7.1.md#訂正)、[#607](https://github.com/TamaT-LLC/depgraph-cli/pull/607)）。
