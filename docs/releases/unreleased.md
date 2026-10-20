# 未リリース

v0.7.0 向けの変更と移行手順は [v0.7.0 リリースノート](v0.7.0.md) を参照してください。
公式 Release と公開後証跡が揃うまでは、v0.6.4 が公開済み stable です。

## MCP のエラー応答に原因の詳細を含める

MCP ツールのエラー応答 `error.details` に、原因を特定できる情報を追加する（[#565](https://github.com/TamaT-LLC/depgraph-cli/issues/565)）。
`contract_version` は `depgraph-mcp-tools-v1` のままで、既存のフィールドと `details` の既存の形は変えない。

- `RESOURCE_EXHAUSTED` の `details`（`kind: "resource_limit"`）に、当たった上限の `limit` と `maximum` に加えて、止まった時点の処理量 `observed` と、上限を動かせる引数 `argument`（例: `max_traversal`）を任意フィールドとして含める。`limit` に、依存一覧が隣接表の構築で調べる snapshot の edge 数 `snapshot_edges` と、selector の解決や `graph_path_get` の隣接表の構築などに共通する前処理の作業量 `preprocessing_work_items` を追加する。`graph_path_get` が探索中に `max_traversal` に達した場合は、依存一覧と同じ `traversal_items` を返す。引数を上げれば通る場合、`remediation` は `narrow_query` ではなく `increase_limit` になる。
- `INVALID_ARGUMENT` の `details` に `kind: "argument"` を追加し、問題の引数名 `argument` と理由 `reason`（`missing` / `unknown_argument` / `invalid_value` / `out_of_range` / `too_many_items` / `ambiguous_selector`）を返す。スキーマにない引数は名前を返さない。
- セレクターに一致するノードがない場合は、`INVALID_ARGUMENT` ではなく `NOT_FOUND`（`reason: "no_matching_node"`）を返す。
- `graph_query` の不正な query には `kind: "query_diagnostic"` を返し、失敗したコード、構文の節、見つかったトークンの種類、行・列・バイト位置を示す。query の本文は返さない。ツール説明に構文と例を載せる。
- CLI の `deps` / `dependents` / `why` がトラバーサル上限で止まったときのメッセージに、上限名と値を付け足す（例: `request exhausted a service resource limit: max_traversal=1 (observed 1)`）。終了コードは変えない。

`depgraph-mcp-tools` crate の型で応答を `deny_unknown_fields` 付きで Deserialize している利用者は、追加された要素を受け取るために crate を更新する。
存在しないパスを渡したときに `INVALID_ARGUMENT` を前提としていた利用者は、`NOT_FOUND` も扱う。

続けて、details のないエラーが残っていたツールも同じ形に揃える（[#581](https://github.com/TamaT-LLC/depgraph-cli/issues/581)）。

- `snapshot` / `from` / `to` に snapshot 名・stable ID・`current` 以外の値（`latest` など）を渡したときの `INVALID_ARGUMENT` に、`{"kind":"argument","argument":"snapshot"|"from"|"to","reason":"invalid_value"}` を付ける。値そのものは返さない。
- `graph_dependencies_list` / `graph_dependents_list` の `edge_kinds` が不正なときは、`agent_edges_list` と同じく `argument: "edge_kinds"` と `invalid_value` / `too_many_items` を返す。
- `agent_sites_list` の `site_id` / `node_id`、`agent_node_get` / `agent_edges_list` の `node_id`、`agent_evidence_list` の `site_id`、`agent_nodes_list` / `graph_unresolved_list` の `kinds`、`graph_impact_get` の `conditions`、`resolve_build_submit` の `acknowledgement` / `rust_compiler_precise` の不正値にも、引数名と理由を付ける。
- impact、health、hotspot、snapshot diff、policy、export の上限超過の `RESOURCE_EXHAUSTED` に `kind: "resource_limit"` の details を付ける。`limit` に `impact_nodes` / `impact_edges`（`max_nodes` / `max_edges` で広げられる）、`impact_path_steps`、`changed_paths`、`health_findings`、`health_finding_items`、`health_manifests`、`artifact_items`、`artifact_work_items`、`export_nodes` / `export_edges`（`max_nodes` / `max_edges`）を追加する。health と hotspot の作業量の上限は、既存の `preprocessing_work_items` として返す。
- `graph_export` のセレクターに一致するノードがない場合は、依存一覧と同じく `NOT_FOUND`（`argument: "selector"`、`reason: "no_matching_node"`）を返す。これまでは details のない `INVALID_ARGUMENT` だった。CLI の `export` も、上限やセレクターの失敗を同じ文言で示す。終了コードは変えない。

## Rust の file node にリポジトリ相対パスを持たせる

Rust worker が出す file node（`include!` 由来を含む）と `include_str!` / `include_bytes!` 由来の asset node に、リポジトリ相対パスの `path` property を記録する。crate root の module node にも、他の module node と同じく宣言元ファイルの `source_path` を記録する（[#577](https://github.com/TamaT-LLC/depgraph-cli/issues/577)）。
これまで Rust の file のパスは locator `file:<path>` と表示名にしかなく、property からパスを読む core の health 解析では、パスのないノードとして扱われていた。

- `depgraph hotspots` と MCP の `health_hotspots_list` で、Rust の file と crate root の module の finding に `location` が付く。`--path-prefix` / `path_prefixes` で Rust のファイルを絞り込めるようになる（従来は 0 件だった）。
- Git churn が Rust のファイルと crate root の module に対応付けられ、hotspot の `git_churn` layer に反映される（従来は 0）。
- `unused-file` の finding に `location` が付く。
- MCP の `agent_node_get` の `repository_path` と、依存一覧 `detail: "paths"` のパスは、`path` property から取る。

互換性:

- churn layer は rank 正規化なので、Rust のファイルだけでなく、Rust を含むワークスペースのほぼすべての hotspot の score と順位が変わる。hotspot の fingerprint は score と `location` を含むため、あわせて変わる。finding ID は変わらない。
- Rust の `unused-file` の fingerprint は、`location` が付くため変わる。finding ID は変わらない。
- 変化は Rust を再 scan した snapshot にだけ現れる。既存の snapshot は再 scan するまで従来のままで、Store の移行は不要。hotspot や `unused-file` の fingerprint を baseline に保存している場合は、再 scan 後に baseline を作り直す。
- MCP 層の locator `file:<path>` からのパスの補完（[#566](https://github.com/TamaT-LLC/depgraph-cli/issues/566)）は残す。再 scan していない Store の file node が引き続き使う（Go の file node も [#591](https://github.com/TamaT-LLC/depgraph-cli/issues/591) で `path` を持つようになった）。

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

## 追加機能

- MCP ツールの `contract_version` を省略可能にする。`repository_id` と同じく全ツールの入力 Schema の `required` から外し、省略時はサーバーが実装する `depgraph-mcp-tools-v1` として扱う。明示した未知の版は従来どおり `INVALID_ARGUMENT`（`argument: "contract_version"`、`reason: "invalid_value"`）で拒否する（[#570](https://github.com/TamaT-LLC/depgraph-cli/issues/570)）。
- 解析の精度が落ちた profile を、依存一覧の応答に示す（[#579](https://github.com/TamaT-LLC/depgraph-cli/issues/579)）。MCP の `graph_dependencies_list` / `graph_dependents_list`（`full` / `summary` / `paths` のすべて）と CLI の `deps` / `dependents --json` は、snapshot に精度の落ちた profile があるとき、任意フィールド `analysis_degradations` に profile ごとの `profile_id`、`language`、`analysis_mode`（Rust が rust-analyzer HIR なしで動いた `syntax-only`）、`reasons`（worker が HIR を省いた `rust-hir-memory-budget`、core が worker のメモリ超過後に syntax-only で再実行した `rust-hir-syntax-only-fallback`）を返す。CLI のテキスト出力では先頭に `degraded analysis: ...` の行を出す。劣化のない snapshot の応答は従来とバイト単位で同じ。`depgraph-mcp-tools` crate の型で応答を `deny_unknown_fields` 付きで Deserialize している利用者は、このフィールドを受け取るために crate を更新する。
- MCP の `graph_path_get` に出力粒度 `detail`（`full` / `summary` / `paths`、既定 `full`）を追加する。`summary` は経路の各辺を evidence なしで返し、共通の `phase` などを `common` に 1 回だけ出す。`paths` は各辺を source / target のパス（パスのないノードは ID）と辺の種類だけで返す。省略時の応答は従来と同じ（[#566](https://github.com/TamaT-LLC/depgraph-cli/issues/566)）。
- Rust の `mod foo;`（site kind `module_declaration`）の evidence に、MCP の `import`（`specifier` と `local_name` に module 名、`binding_kind: "module_declaration"`）を付ける。`binding_kind` に値 `module_declaration` が加わる（[#566](https://github.com/TamaT-LLC/depgraph-cli/issues/566)）。
- MCP の `agent_edges_list` に、辺種別の許可リスト `edge_kinds` と出力粒度 `detail`（`summary` / `full`、既定 `full`）を追加する。`summary` は evidence 本体を省き、ページ内で共通の `phase` / `profile_id` などを `common` に 1 回だけ出し、各辺に `site_id` と `evidence_count` を残す。`agent_sites_list` に `site_id` を追加し、1 件の site を ID で取得できるようにする。どちらも省略時の応答と cursor は従来と同じ（[#566](https://github.com/TamaT-LLC/depgraph-cli/issues/566)）。
- `health_hotspots_list` の説明と利用ガイドに、fan-in / fan-out / reverse impact の数え方と、fan-in だけで順位を付ける weight の指定を書く（[#566](https://github.com/TamaT-LLC/depgraph-cli/issues/566)）。

## 修正

- MCP の `doctor_get` が rust / go / web の worker をすべて `available: false`（`integrity: unavailable`）と表示し、MCP の `scan_submit` が worker を起動できず `security_failed` になっていた問題を直す。release の worker 検証は実行中の executable が core（`bin/depgraph`）であることを求めていたため、MCP server と operation runner のプロセスでは worker を見つけられなかった。`mcp setup` の safe scan は core を起動するので完了しており、doctor の表示と食い違っていた。release manifest が固定パスと checksum で attest している MCP server（`bin/depgraph-mcp`）と operation runner（`libexec/depgraph-operation-runner`）も、実行中の executable として受け入れる（[#569](https://github.com/TamaT-LLC/depgraph-cli/issues/569)）。
- `doctor` と `doctor_get` の各 worker に、判定の経路と理由を追加する。`resolution`（worker を見つけた経路）、`artifact`（release root からの相対パス）、`runtime_requirement`、`unavailable_reason` と `root_launch_blocked_reason`（false にした検査のコード）、`scan_impact`（scan で worker が使われるか、その adapter の unit が失敗するか、scan が `security_failed` になるか）、固定文の `diagnostic` と `remediation` を返す。既存のフィールドは変えず、スキーマでは新しいフィールドを任意にしたので、以前のサーバーの応答もそのまま検証を通る。CLI の `doctor` の人間向け出力にも worker ごとの行を加える（[#569](https://github.com/TamaT-LLC/depgraph-cli/issues/569)）。
- doctor の `toolchains` の node は、depgraph を起動したプロセスの `PATH` で最初に見つかる Node.js を表す。MCP では Agent host の環境なので、ターミナルの Node.js と違うことがある。Web worker がその Node.js で動かない場合は `unavailable_reason: "runtime-requirement-unmet"` で示す（[#569](https://github.com/TamaT-LLC/depgraph-cli/issues/569)）。
- MCP ツールの入力・出力 Schema と、`schemas/` の `depgraph-mcp-tools-v1` / `depgraph-agent-scan-outcome-v2` Schema から、JSON Schema 2020-12 にない `format`（`uint8` / `uint16` / `uint32` / `uint64` / `int64`）を除く。整数の範囲は同じ値を受け付ける `minimum` / `maximum` で表す。Claude Code など Ajv を使う MCP クライアントが接続時に出していた `unknown format "…" ignored` の警告（ツール一覧 1 回で 1,134 件）が出なくなる。`contract_version` は `depgraph-mcp-tools-v1` のままで、受け付ける値は変わらない（[#568](https://github.com/TamaT-LLC/depgraph-cli/issues/568)）。
- 大きなリポジトリで、MCP の `health_hotspots_list` と CLI の `depgraph hotspots` が `path_prefixes` / `node_kinds` / `limit` で絞り込んでも resource limit（`RESOURCE_EXHAUSTED`、exit 3）で失敗していた問題を直す。reverse impact を subject ごとに探索せず、最大 64 subject をまとめて 1 回の探索で数えるようにして、スコア計算の作業量を減らした。score、順位、finding ID、fingerprint は従来の計算と同じで、絞り込みは従来どおりスコア計算の後に適用する（[#562](https://github.com/TamaT-LLC/depgraph-cli/issues/562)）。
- MCP の `graph_path_get` と CLI の `depgraph why` が、snapshot の edge 数が `max_traversal`（既定 50,000）を超えると、1 ホップの経路でも resource limit で失敗していた問題を直す。`max_traversal` は探索で訪れた edge の数だけを制限し、隣接表の構築は他の依存クエリと同じ snapshot 全体の前処理上限で制限する（[#562](https://github.com/TamaT-LLC/depgraph-cli/issues/562)）。
- MCP の `agent_nodes_list` が、worker 由来の `file:` などの locator を持つノードを返すときに `INTEGRITY_FAILURE` で失敗していた問題を直す。返すノードの locator を `id:` に置き換えるようにした（[#563](https://github.com/TamaT-LLC/depgraph-cli/issues/563)）。
- Rust の syntax 解析で `use crate::a::Item` などのパスを、`mod a;` を宣言したファイルではなくモジュール `a` の本体ファイルへの依存として記録する。HIR が予算超過で syntax-only に落ちた scan でも、crate 内のファイルの被依存が `mod` 宣言の 1 件だけにならない（[#564](https://github.com/TamaT-LLC/depgraph-cli/issues/564)）。
- 同じモジュールにある同名の sysroot 定義（`std::fs::read` と `impl Read for File` の `read` など）が同じ ID になり、Rust の HIR 結果全体が破棄されていた問題を修正する（[#564](https://github.com/TamaT-LLC/depgraph-cli/issues/564)）。
- Rust worker の大規模ワークスペースでの HIR 結果の統合を速くし、ピークメモリを下げる。site ごとに全 edge を走査していた検証と診断集約を索引引きにし、HIR の統合時に rust-analyzer のデータベースとグラフの複製を同時に保持しないようにする（[#564](https://github.com/TamaT-LLC/depgraph-cli/issues/564)）。
- Rust worker のピークメモリを下げる。dependency site に結び付いた edge は、出力するまで site の evidence を共有し、同じ evidence の複製を保持しない。depgraph-cli 自身の HIR 解析で、worker のピーク RSS は 4.18 GiB から 3.68 GiB に下がった（attested sysroot あり）。出力する event stream はバイト単位で変わらない。既定の上限（2 GiB）にはまだ収まらないため、既定設定では引き続き syntax-only に切り替わる（[#578](https://github.com/TamaT-LLC/depgraph-cli/issues/578)）。
- npm launcher が platform 別の optional package を見つけられないとき、実行中の Node.js が `engines`（`>=24.0.0`）を満たすかを先に確かめる。満たさない場合は、Node.js の不足が原因で npm が platform package を入れなかったことと切り替え方を表示する。npx から起動された場合は、Node.js を切り替えても npx が不完全なインストール先を再利用し続けるため、`npm cache npx rm <key>` で消すキーとディレクトリも表示する（[#567](https://github.com/TamaT-LLC/depgraph-cli/issues/567)）。
- `depgraph mcp setup` / `update` は、safe scan が走る場合、リリース資産の取得と scan の前に TypeScript/JavaScript 解析用の Node.js を検査し、`>=24.0.0` を満たさなければ検出した Node.js のパスとバージョン、切り替え方を示して即座に失敗する。`package.json` を含まないリポジトリでは Node.js を要求しない（[#567](https://github.com/TamaT-LLC/depgraph-cli/issues/567)）。
- Rust の file node が MCP の `repository_path` と依存一覧 `detail: "paths"` でパスではなく node ID で返っていた問題を直す。locator `file:<path>` のパスを検証してから使う（[#566](https://github.com/TamaT-LLC/depgraph-cli/issues/566)）。
- Rust の syntax-only 解析（`rust-static`）の `use` / `pub use` / `extern crate` の evidence に、HIR 解析と同じ import 先・glob・re-export・別名を記録する。MCP の `import` に specifier と取り込んだ名前が出るようになり、CLI の JSON 出力の evidence `properties` にも同じキーが加わる（[#566](https://github.com/TamaT-LLC/depgraph-cli/issues/566)）。
- Rust HIR を通した大規模な snapshot（depgraph-cli 自身で node 212,915 件、hotspot の subject 69,900 件）で、CLI の `depgraph hotspots` と MCP の `health_hotspots_list` が resource limit で失敗していた問題を直す。hotspot はこれまで health の finding 数の上限（10,000）と graph service の前処理の作業量の上限（1,000,000）を流用していたため、hotspot 専用の上限 `MAX_HOTSPOT_SUBJECTS`（subject 数と返す finding 数、250,000）と `MAX_HOTSPOT_PREPROCESSING_WORK_ITEMS`（作業量、16,000,000）を設けた。reverse impact は最大 256 subject をまとめて数えるようにして作業量を約半分にした（上の snapshot で約 356 万）。score、順位、finding ID、fingerprint は従来の計算と同じで、health の他の finding の上限は変えない（[#590](https://github.com/TamaT-LLC/depgraph-cli/issues/590)）。
