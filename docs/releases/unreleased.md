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
- Go の package（node kind `module`）の file node は持たない。package の hotspot の扱いは次の節（[#595](https://github.com/TamaT-LLC/depgraph-cli/issues/595)）で変える。

互換性:

- churn layer は rank 正規化なので、Go のファイルだけでなく、Go を含むワークスペースの hotspot の score と順位が変わる。hotspot の fingerprint は score と `location` を含むため、あわせて変わる。hotspot の finding ID は変わらない。
- Go の `unused-file` は、finding ID と fingerprint の両方が変わる。finding ID の witness に、従来は locator `file:<path>` を、今後は `location` のパスを使うため。finding ID で suppression や baseline を管理している場合は、再 scan 後に付け直す。
- 変化は Go を再 scan した snapshot にだけ現れる。scan cache の key は worker バイナリの内容を含むので、更新後の scan で古い結果は再利用されない。Store の移行は不要。hotspot や `unused-file` の fingerprint を baseline に保存している場合は、再 scan 後に baseline を作り直す。
- v0.7.1 で残した MCP 層の locator `file:<path>` からのパスの補完（[#566](https://github.com/TamaT-LLC/depgraph-cli/issues/566)）は、再 scan していない Store の file node が引き続き使う。

## Go の package の hotspot を go.mod に結び付けない

Go の package（node kind `module`、locator `go-package:<import path>`）の hotspot の `location` と Git churn を、所属する module の `go.mod` ではなく package のディレクトリに対応付ける（[#595](https://github.com/TamaT-LLC/depgraph-cli/issues/595)）。
Go の package はディレクトリで、package node は `path` / `source_path` を持たず、所属する module の `manifest_path`（`go.mod`）だけを持つ。core の hotspot はパスがないと `manifest_path` を読むため、package の `location` と churn が `go.mod` になっていた。

- `depgraph hotspots` と MCP の `health_hotspots_list` で、Go の package の finding の `location` が package のディレクトリ（package node の `relative_dir`。例: `internal/worker`）になる。module のルートの package（`relative_dir` が `.`）は `location` を持たない。`--path-prefix` / `path_prefixes` で package をディレクトリで絞り込めるようになる。
- package の Git churn は、そのディレクトリ直下にある Go の file node（`_test.go` とアセンブリを含む）の churn の合計になる。サブディレクトリ（別の package）、`go.mod` / `go.sum` などの Go 以外のファイル、`//go:embed` の対象は数えない。Go の file node にパスがない snapshot（#591 より前の Go worker で scan したもの）では 0 になる。
- package node の `manifest_path` は残す。Go worker の semantic 解析は引き続き `manifest_path` で package と `go.mod` を照合する。
- 他の node の扱いは変えない。`manifest_path` へのフォールバックは、Go の package 以外（パスを持たない古い snapshot の Go の file node など）では従来どおり使う。Rust / npm の package（node kind `package_instance`）は hotspot の対象ではない。

互換性:

- churn layer は rank 正規化なので、Go の package だけでなく、Go を含むワークスペースの hotspot の score と順位が変わる。hotspot の fingerprint は score と `location` を含むため、あわせて変わる（Go の package は `location` が変わるので、score が同じでも fingerprint が変わる）。hotspot の finding ID は変わらない。
- hotspot は問い合わせのたびに snapshot から計算するので、再 scan は要らない。更新後の CLI / MCP で既存の snapshot を問い合わせると反映される。package の churn に Go のファイルのパスを使うため、#591 の Go worker で再 scan した snapshot で集計される。Store の移行は不要。hotspot の fingerprint を baseline に保存している場合は、作り直す。
- `unused-file` などの unused 系の finding は変わらない（Go の package は unused 系の対象ではなく、unused 系の `location` は `manifest_path` を読まない）。

## 既定のメモリ・出力上限を引き上げる

`.depgraph.toml` の `[scan]` の既定値を、depgraph-cli 自身の Rust HIR 解析の実測にもとづいて引き上げる（[#598](https://github.com/TamaT-LLC/depgraph-cli/issues/598)）。

| キー | 旧 | 新 |
| --- | --- | --- |
| `max_worker_memory_bytes`（worker 1 つのプロセスツリーのメモリ） | 2 GiB | 6 GiB |
| `max_protocol_bytes`（worker 1 回の出力） | 256 MiB | 1 GiB |

- depgraph-cli 自身の HIR 解析で、Rust worker のピーク RSS は attested sysroot ありで 3.18〜3.48 GiB、sysroot なしで 2.4〜2.56 GiB、出力は 647〜698 MiB だった。旧上限ではどちらも超えるため、既定設定では Rust が syntax-only に切り替わっていた（`rust-hir-memory-budget`）。新しい上限はメモリで約 1.7 倍、出力で約 1.4 倍の余裕がある。
- depgraph-cli 規模のリポジトリでも、既定設定のまま Rust を rust-analyzer HIR で解析する（imports、型、呼び出しの edge が入る）。depgraph-cli 自身を既定設定で scan すると、Store の node は 63,115 件から 225,842 件に、edge は 127,778 件から 286,513 件になった（Web の行を含む）。内容は、従来の版で上限を広げて HIR 解析した Store と同じになる。そのかわり、この規模では scan 中の CLI の peak memory footprint が約 3.5 GiB から約 5 GiB に、Rust worker のピーク RSS が約 0.76 GiB から 2.5〜3.5 GiB に増える。
- 上限は確保する量ではなく、超えたら worker を止める閾値である。上限を超えない規模のリポジトリでは、使うメモリも出力も変わらない。ただし同時に動く worker（`max_concurrent_units`、既定 2）はそれぞれこの上限まで使えるため、2 つが並んだときの上限の合計（`scan --split-plan` の `admitted_memory_bytes`）は 12 GiB になる。
- Go worker に渡す `GOMEMLIMIT` は従来どおり `max_worker_memory_bytes` の 3/4（新しい既定で 4.5 GiB）。
- core が Rust worker の出力を取り込むときのメモリを減らした。受け取った event を 1 件ずつ compact な JSON で持ち、種類ごとに並べ替えるときの複製と、検証時の event 列の二重保持をやめた。depgraph-cli 自身を上限を広げて HIR で解析したとき、CLI の peak memory footprint は 10.8 GiB から約 5 GiB に下がった（macOS、`/usr/bin/time -l`）。Store の内容と CLI / MCP の出力は変わらない。

互換性:

- 旧上限を使いたい場合（メモリの小さいマシンで、超えたら syntax-only に切り替えたい場合など）は、`.depgraph.toml` の `[scan]` で `max_worker_memory_bytes = 2147483648` と `max_protocol_bytes = 268435456` を指定する。
- `depgraph init` で作った `.depgraph.toml` には、作った時点の既定値が書き込まれている。旧版で作ったファイルは旧上限（`max_worker_memory_bytes = 2147483648`、`max_protocol_bytes = 268435456`）を指定したままなので、新しい既定を使うにはその 2 行を消すか書き換える。
- `scan --split-plan --json` の `budget` と `admitted_memory_bytes` は新しい既定値で計算される。execution unit の分け方と ID は変わらない。

## 追加機能

- 解析の精度が落ちた profile を、依存一覧の応答に示す（[#579](https://github.com/TamaT-LLC/depgraph-cli/issues/579)）。MCP の `graph_dependencies_list` / `graph_dependents_list`（`full` / `summary` / `paths` のすべて）と CLI の `deps` / `dependents --json` は、snapshot に精度の落ちた profile があるとき、任意フィールド `analysis_degradations` に profile ごとの `profile_id`、`language`、`analysis_mode`（Rust が rust-analyzer HIR なしで動いた `syntax-only`）、`reasons`（worker が HIR を省いた `rust-hir-memory-budget`、core が worker のメモリ超過後に syntax-only で再実行した `rust-hir-syntax-only-fallback`）を返す。CLI のテキスト出力では先頭に `degraded analysis: ...` の行を出す。劣化のない snapshot の応答は従来とバイト単位で同じ。`depgraph-mcp-tools` crate の型で応答を `deny_unknown_fields` 付きで Deserialize している利用者は、このフィールドを受け取るために crate を更新する。
- MCP の `graph_path_get` に出力粒度 `detail`（`full` / `summary` / `paths`、既定 `full`）を追加する。`summary` は経路の各辺を evidence なしで返し、共通の `phase` などを `common` に 1 回だけ出す。`paths` は各辺を source / target のパス（パスのないノードは ID）と辺の種類だけで返す。省略時の応答は従来と同じ（[#566](https://github.com/TamaT-LLC/depgraph-cli/issues/566)）。
- MCP の `agent_edges_list` の `detail` に値 `imports` を追加する。ファイル単位の `(source, target)` の組ごとに、`source_id` / `target_id`、パス、辺の種類と件数、その組で import した名前（`specifier`、`binding_kind`、`imported_name`、`local_name`、`type_only`。最大 256 件で、`import_count` に総数）を返す。TypeScript は import 名を、ファイル間の imports 辺ではなく symbol などへの semantic 辺にだけ記録するため、同じ source と specifier の辺を 1 つの import 文として組にまとめる。`direction: "incoming"` で、あるファイルを import している各ファイルと、それぞれが取り込む名前を 1 回で得られる。depgraph-cli 自身の Store では、`crates/depgraph-core/src/lib.rs` の imports / reexports 974 本から名前を得るのに、`detail: "full"`（`limit: 100`）のページングで 10 回・応答計約 1.83 MB かかっていたのが、110 組を 4 回・計約 340 KB で得られる。1 ページは `limit` に加えて 48 KiB で切り、続きは `next_cursor` で取る。省略時と `full` の応答は従来と同じ（[#566](https://github.com/TamaT-LLC/depgraph-cli/issues/566)）。
- MCP の `get_context` に出力粒度 `detail`（`summary` / `full`、既定 `full`）を追加する。`summary` は current snapshot の `profile_ids` の一覧を `profile_count` に置き換える。depgraph-cli 自身の Store（profile 89 個）で応答が 18,164 byte から 3,438 byte になる。省略時と `full` の応答は従来と同じで、`snapshot_get` / `snapshot_list` は変えない（[#566](https://github.com/TamaT-LLC/depgraph-cli/issues/566)）。
- MCP に読み取り tool `graph_fan_in_list` を追加する。node（既定は file）を、直接依存する重複なしの node 数（fan-in）の順に並べ、`fan_in`、`edge_count`、パスを返す。数える辺は既定で `graph_dependents_list` と同じく構造辺以外で、`edge_kinds`、`node_kinds`、`path_prefixes` で絞れる。`health_hotspots_list` の fan-in は構造辺を含む全 edge record の件数なので値が異なる（depgraph-cli 自身の Store で `crates/depgraph-core/src/lib.rs` は hotspot の fan-in 464 に対し 28）。tool が 1 つ増えるため MCP の tool catalog の digest が変わる（[#566](https://github.com/TamaT-LLC/depgraph-cli/issues/566)）。
- `depgraph-mcp-tools` crate では、`AgentEdgeDetail` に `Imports`、`AgentEdgesOutput` に `Imports` の variant が加わり、`get_context` の出力型が `AgentContextOutput` になる。これらの enum を網羅的に match している利用者は更新が要る。
- Rust の `mod foo;`（site kind `module_declaration`）の evidence に、MCP の `import`（`specifier` と `local_name` に module 名、`binding_kind: "module_declaration"`）を付ける。`binding_kind` に値 `module_declaration` が加わる（[#566](https://github.com/TamaT-LLC/depgraph-cli/issues/566)）。

## 修正

- MCP の `agent_node_get` が、Web worker の file node（locator `file://…`）で `repository_path` を返していなかった問題を直す。`agent_node_get` は node の properties を読まず、locator `file:<path>` からのパスの補完（[#566](https://github.com/TamaT-LLC/depgraph-cli/issues/566)）は `file://` を対象にしないため、Web の file node はどの経路でもパスが埋まらなかった。今後は対象の 1 node だけ properties を読み、依存一覧や impact の root と同じく `path` / `source_path` property から `repository_path` を返す。Rust / Go の file node と、`path` を持たない古い Store の file node の値は変わらない。`agent_node_get` の output schema と `agent_nodes_list` の応答は変えない（[#601](https://github.com/TamaT-LLC/depgraph-cli/issues/601)）。
- MCP ツールの入力・出力 Schema と、`schemas/` の `depgraph-mcp-tools-v1` / `depgraph-agent-scan-outcome-v2` Schema から、JSON Schema 2020-12 にない `format`（`uint8` / `uint16` / `uint32` / `uint64` / `int64`）を除く。整数の範囲は同じ値を受け付ける `minimum` / `maximum` で表す。Claude Code など Ajv を使う MCP クライアントが接続時に出していた `unknown format "…" ignored` の警告（ツール一覧 1 回で 1,134 件）が出なくなる。`contract_version` は `depgraph-mcp-tools-v1` のままで、受け付ける値は変わらない（[#568](https://github.com/TamaT-LLC/depgraph-cli/issues/568)）。
- Rust worker のピークメモリを下げる。dependency site に結び付いた edge は、出力するまで site の evidence を共有し、同じ evidence の複製を保持しない。depgraph-cli 自身の HIR 解析で、worker のピーク RSS は 4.18 GiB から 3.68 GiB に下がった（attested sysroot あり）。出力する event stream はバイト単位で変わらない。この変更だけでは旧既定の上限（2 GiB）に収まらなかった（[#578](https://github.com/TamaT-LLC/depgraph-cli/issues/578)）。既定の上限は「既定のメモリ・出力上限を引き上げる」で引き上げた。
- Rust worker の出力とピークメモリをさらに減らす。core は Rust worker に evidence の compact encoding（`compact-evidence-v1`）を要求し、worker は site と同じ evidence を edge に書かず、HIR の evidence がすべて同じ値で持つ property（`backend` / `rust_analyzer_version` / `rust_analyzer_revision` / `active_cfg_source`）を profile に 1 回だけ書く。core は取り込み時に元の形へ戻すため、Store の内容と CLI / MCP の出力は変わらない。要求を知らない worker は従来の形で出力し、core はそれも受け付ける。depgraph-cli 自身の HIR 解析（attested sysroot あり）で、worker の出力は 806 MiB から 634 MiB に下がった。ピーク RSS は、前項の変更を含む build を同じ入力で計測し直した値（3.58 GiB。前項の 3.68 GiB とは計測回の違い）から 3.48 GiB に下がった。この変更だけでは旧既定の上限（メモリ 2 GiB、出力 256 MiB）に収まらなかった（[#578](https://github.com/TamaT-LLC/depgraph-cli/issues/578)）。既定の上限は「既定のメモリ・出力上限を引き上げる」で引き上げた。
- Rust HIR を通した大規模な snapshot（depgraph-cli 自身で node 212,915 件、hotspot の subject 69,900 件）で、CLI の `depgraph hotspots` と MCP の `health_hotspots_list` が resource limit で失敗していた問題を直す。hotspot はこれまで health の finding 数の上限（10,000）と graph service の前処理の作業量の上限（1,000,000）を流用していたため、hotspot 専用の上限 `MAX_HOTSPOT_SUBJECTS`（subject 数と返す finding 数、250,000）と `MAX_HOTSPOT_PREPROCESSING_WORK_ITEMS`（作業量、16,000,000）を設けた。reverse impact は、v0.7.1 で最大 64 subject ずつまとめて数えていたバッチを最大 256 subject に広げ、作業量を約半分にした（上の snapshot で約 356 万）。score、順位、finding ID、fingerprint は従来の計算と同じで、health の他の finding の上限は変えない（[#590](https://github.com/TamaT-LLC/depgraph-cli/issues/590)）。
- 範囲指定（`node_id` / `site_id`）のない MCP の `agent_sites_list` が、`limit: 100` でも読み取りの deadline（30 秒）を超えて `RESOURCE_EXHAUSTED` を返していた問題を直す。これまでは、ページを切り出す前に対象のすべての site の evidence を組み立て、しかも site ごとに snapshot の evidence 全件を走査していた。今後は site を ID 順に並べてページを切り出してから、そのページの site の evidence だけを、evidence を 1 回走査して owner ごとにまとめた索引から組み立てる。`agent_edges_list` も同じ方法でページ内の edge の evidence だけを組み立てる。depgraph-cli 自身の Store（node 73,238、edge 247,109、site 220,553、evidence 528,451）で、範囲指定のない `agent_sites_list`（`limit: 100`）が deadline 内に返るようになった。ページの内容、順序、`total_items`、cursor は従来と同じ。snapshot 全体の読み込み（[#599](https://github.com/TamaT-LLC/depgraph-cli/issues/599)）は別に扱う（[#600](https://github.com/TamaT-LLC/depgraph-cli/issues/600)）。
- MCP サーバーの読み取りツールが、呼び出しのたびに completed snapshot の storage seal（snapshot 全体のハッシュ）を計算し直し、snapshot 全体を SQLite から組み立て直していたため、大規模な Store で 1 回 3〜30 秒かかっていた問題を直す。MCP サーバーのプロセス内で、検証済みの seal と組み立て済みの snapshot（最新の 1 つ）を、Store が変わらない間だけ再利用する。変化は、DB 本体と WAL の stat（inode、サイズ、mtime、ctime）と、SQLite の `PRAGMA data_version`（どの接続の commit でも変わる）で判定し、Store のファイルを SQLite の外で開くことはしない。commit、checkpoint、ファイルの置き換え、SQLite を通さない書き換え（stat が変わるもの）で Store が変わると、次の呼び出しで seal を検証し直し、snapshot を読み直す。読み取り中の接続が開いているファイルがパスの指すファイルと違う（rename で置き換えられた）場合は再利用しない。再利用は Unix だけで行う。上の変化のあとの seal の改ざん検出と、`current` が新しい snapshot を指したときに新しい内容を返すことは変わらない。ただし、stat も変えずに DB 本体を直接書き換えた場合（timestamp の粒度が粗いファイルシステムで、seal を検証した読み取りと同じ tick 内に書き換えた場合など）は、次に Store が変わるまで検出しない。depgraph-cli 自身の Store（node 73,238、edge 247,109、site 220,553、evidence 528,451）で、Store を変えずに続けた 2 回目以降の呼び出しは、`get_context` / `snapshot_list` / `snapshot_get` が約 7.5 秒から 0.01 秒未満、`agent_node_get` / `agent_nodes_list` が約 3.8 秒から約 0.3 秒、`agent_sites_list` / `agent_edges_list` / `agent_evidence_list` が約 4.5 秒から 0.05 秒未満、`graph_dependencies_list` などの graph 系が約 4.5 秒から約 0.2〜0.7 秒になった（graph 系と health 系、snapshot diff の比較元も、組み立て済みの snapshot を複製せずに共有する）。Store が変わった直後の 1 回目は従来と同程度かかる。そのかわり、組み立てた snapshot 1 つ分のメモリ（この Store で約 1.5 GB）を MCP サーバーが保持し続ける。CLI は従来どおり毎回読み込む。応答の内容、ページ、cursor は変わらない（[#599](https://github.com/TamaT-LLC/depgraph-cli/issues/599)）。

## v0.7.1 のリリースノートの訂正

v0.7.1 のリリースノートでは、Rust の file node に `path` を持たせた変更（[#577](https://github.com/TamaT-LLC/depgraph-cli/issues/577)、[#582](https://github.com/TamaT-LLC/depgraph-cli/pull/582)）で Rust の `unused-file` の finding ID は変わらないと書いたが、誤りだった。finding ID と fingerprint の両方が変わり、`src/lib.rs` などが entry point に分類されて `entry-point` の blocker が付き、confidence が下がる場合がある。finding ID で suppression や baseline を管理している場合は、Rust を再 scan した後に付け直す（詳細は [v0.7.1 リリースノートの「訂正」](v0.7.1.md#訂正)、[#607](https://github.com/TamaT-LLC/depgraph-cli/pull/607)）。
