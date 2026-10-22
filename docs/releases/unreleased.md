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

## 既定の max_traversal で cycles と unresolved が失敗する問題を直す

約 250 ファイル規模のリポジトリでも、CLI の `depgraph unresolved` / `depgraph cycles` と MCP の `graph_unresolved_list` / `graph_cycles_list` が、既定の `max_traversal`（50,000）のまま `RESOURCE_EXHAUSTED` で失敗していた問題を直す（[#617](https://github.com/TamaT-LLC/depgraph-cli/issues/617)、[#618](https://github.com/TamaT-LLC/depgraph-cli/issues/618)）。
どちらも、返す件数とは関係なく snapshot 全体の索引（全 node・edge・evidence・site・profile correlation）を `max_traversal` で数えていた。生成したフィクスチャ（node 25,251、site 23,500 のうち unresolved 6,750、edge 30,000、evidence 53,500）では、索引だけで unresolved が 130,501、file 単位の cycles が 55,751 になり、既定値を超えていた。`limit` / `--max-items` で絞っても減らなかった。

- snapshot の索引、cycle 探索の node ごとの手順、結果の組み立ては、`max_traversal` ではなく固定の上限（16,000,000。hotspot の作業量の上限と同じ値）で数える。上のフィクスチャで unresolved は 187,751、file 単位の cycles は 57,301 になる。
- `cycles` / `graph_cycles_list` の `max_traversal` は、cycle 探索が訪れる依存 edge の数を数える（依存一覧の `max_traversal` と同じ意味）。上のフィクスチャの file 単位では 750。
- `unresolved` / `graph_unresolved_list` の `max_traversal` は、`--kind` / `kinds` に一致した unresolved site の数を数える。上のフィクスチャでは 6,750。
- 上限に当たったときは、MCP の `RESOURCE_EXHAUSTED` に `{"kind":"resource_limit","limit":"traversal_items","maximum":…,"argument":"max_traversal"}` を付け、unresolved では一致した site の数を `observed` に入れる。引数を上げれば通る場合の `remediation` は `increase_limit` になる。固定の上限に当たった場合は `limit: "preprocessing_work_items"` と `narrow_query` を返す。CLI のメッセージにも上限名と値を出す（例: `request exhausted a service resource limit: max_traversal=6749 (observed 6750)`）。終了コードは 3 のまま。
- 範囲外の `max_traversal` には許される範囲を示す。CLI は `invalid service input: max_traversal must be in 1..=1000000`（終了コード 2 のまま）、MCP は `INVALID_ARGUMENT` の `details`（`kind: "argument"`、`reason: "out_of_range"`）に任意フィールド `minimum` / `maximum` を付ける。CLI では `deps` / `dependents` / `why` も同じメッセージになる。
- #618 の「CLI の `depgraph cycles` は成功し、MCP の `graph_cycles_list` は失敗する」という食い違いは、計測時に CLI と MCP が別々の scan（別の Store と snapshot）を読んでいたことによる。CLI と MCP は同じ既定値で同じ関数を呼ぶので、作業量が 50,000 付近の snapshot では、snapshot のわずかな差で結果が分かれ得る。上のフィクスチャでも、file あたりの symbol を 40 にすると（node 10,251）修正前の file 単位の cycles は 40,751 で通り、100 にすると（node 25,251）55,751 で失敗した。同じ Store では CLI と MCP が同じ cycle を返すことを回帰テストで確かめた。

互換性:

- 既定値（50,000）と上限（1,000,000）は変えない。`deps` / `dependents` / `impact` / `why` の作業量の数え方と既定値も変えない。
- `cycles` / `unresolved` の `max_traversal` の意味が変わる。unresolved は、一致した site の数が従来の組み立ての作業量より少ないので、従来の値で通っていた要求はそのまま通り、より小さな値（例: unresolved site 1 件の snapshot に `max_traversal: 1`）でも通るようになる。cycles も多くの場合はより小さな値で通るが、node 数に比べて edge の多い cycle では、順方向・逆方向・代表 cycle の探索で訪れる edge の合計が従来の段階ごとの作業量を上回り、従来通っていた値で上限に当たることがある。
- `graph_cycles_list` / `graph_unresolved_list` の上限超過は、details のない `RESOURCE_EXHAUSTED`（`narrow_query`）から、details 付きの `RESOURCE_EXHAUSTED`（多くは `increase_limit`）に変わる。site ごとの evidence 数などの構造上の上限は、従来どおり details なしで返す。
- core の `DepgraphServiceError` に variant `ArgumentOutOfRange` が加わる。範囲外の `max_traversal` は `InvalidInput` ではなくこの variant になる。網羅的に match している `depgraph-core` の利用者は更新が要る。
- `depgraph-mcp-tools` の `AgentErrorDetails::Argument` に任意フィールド `minimum` / `maximum` が加わる。範囲を持たない値のシリアライズ結果は従来と同じ。`deny_unknown_fields` で Deserialize している古い crate の利用者は、受け取るために crate を更新する。shared schema（`depgraph-mcp-tools-v1`）と tool catalog の digest が変わる。`contract_version` は変えない。

## HIR を通した大きな Store で deps / dependents が失敗する問題を直す

Rust HIR を通した depgraph-cli 自身の Store で、CLI の `depgraph deps` / `depgraph dependents` が selector に関係なく `request exhausted a service resource limit`（終了コード 3）で失敗していた問題を直す（[#620](https://github.com/TamaT-LLC/depgraph-cli/issues/620)）。`--max-traversal 1000000` を付けても同じだった。同じ経路を通る `depgraph why` / `depgraph impact` と、MCP の `graph_dependencies_list` / `graph_dependents_list` / `graph_path_get` / `graph_impact_get` も同じ理由で失敗していた。

返す edge の evidence と profile correlation を集めるとき、snapshot の全 evidence・全 profile correlation・全 profile entry を 1 回ずつ走査する。この走査を、返す edge に比例する作業と同じ上限（1,000,000）で数えていた。HIR を通した depgraph-cli 自身の Store（evidence 795,912、profile correlation 120,263、その edge ID 209,051、profile entry 89）では、走査だけで 1,245,578 になり、返す edge が 12 本でも上限を超えていた。

- snapshot 全体の走査は、cycles / unresolved の索引と同じ固定の上限（16,000,000）で数える。返す edge に比例する作業（evidence の集約と複製、path step の組み立てなど）は、従来どおり 1,000,000 で数える。上の Store で `crates/depgraph-core/src/config.rs` の `deps` は 2,012、`dependents` は 194 になる。
- 上限に当たったときは、どちらの上限かを示す。CLI は `request exhausted a service resource limit: preprocessing_work_items=<上限>`（終了コード 3 のまま）、MCP は `RESOURCE_EXHAUSTED` に `{"kind":"resource_limit","limit":"preprocessing_work_items","maximum":…}` と `narrow_query` を付ける。従来は上限名のない `RESOURCE_EXHAUSTED` だった。
- 返す node・edge・path step・evidence・correlation の内容と順序は変わらない。修正前のコードで記録した依存一覧と path の digest が一致することを回帰テストで確かめた。

互換性:

- 既定値と上限の値は変えない。`--max-traversal` / `max_traversal` の意味も変えない。
- `deps` / `dependents` / `why` / `impact` の後処理の上限超過は、details のない `RESOURCE_EXHAUSTED` から `preprocessing_work_items` の details 付きに変わる。edge ごとの evidence 数などの構造上の上限は、従来どおり details なしで返す。

## Rust の use を re-export の先の定義元 file に結び付ける

Rust の syntax 解析で、`use crate::Config` のようにモジュールの中の名前を指す `use` を、そのモジュールにある `pub use` の re-export をたどって、名前を定義している file に結び付ける（[#622](https://github.com/TamaT-LLC/depgraph-cli/issues/622)）。
これまでは、`crate::` / `self::` / `super::` のパスをモジュール本体の file に解決したところで止めていた（[#575](https://github.com/TamaT-LLC/depgraph-cli/pull/575)）。そのため、`crates/depgraph-core/src/lib.rs` の `pub use config::{Config, ...}` を経由して `Config` を使う `service_lifecycle.rs` などは、`config.rs` ではなく `lib.rs` の dependents に出ていた。file 単位の依存は HIR の有無に関係なくこの syntax の辺から作るので、HIR を通した Store でも同じだった。

- たどる re-export は、モジュールの直下（関数の本体の外）にある `pub use` / `pub(crate) use` などの private でない `use`。`pub use path::{X, ...}`、`pub use path::X as Y`、glob の `pub use path::*` を対象にし、複数段の連鎖もたどる。
- glob は、名前を定義または re-export していると分かるモジュールがちょうど 1 つあるときだけたどる。名前が複数の glob から来る場合、同名の item・private な `use` がモジュール自身にある場合（glob より優先される）、glob の先の item が private な場合はたどらない。
- 次の場合は、その段のモジュール（最初の段なら従来の解決先）に残す。同じ名前の re-export が `cfg` ごとに別の file を指す場合、同じ名前の item と re-export が別の名前空間に並ぶ場合、re-export の先が enum の variant など syntax の索引にないモジュールの下にある場合。
- 循環する re-export と、8 段を超える連鎖はたどらず、従来の解決先に残す。
- crate をまたぐパス（`use depgraph_core::Config`、`pub use serde::Serialize` の先）は従来どおり package に結び付け、たどらない。
- 辺の kind（`imports` / `reexports`）、site の ID、evidence の `target_specifier` / `glob` / `reexport` / `alias` は変えない。たどった re-export は evidence の property `reexport_chain`（各段の `path`、`line`、`target_specifier`）に記録する。MCP の `import` の射影はこの property を読まないので、`import` の内容は変わらない。

depgraph-cli 自身（origin/main `70958ce`）の syntax-only と HIR の scan で、結果は同じだった。

- 解決先の変わった `rust_use` / `rust_reexport` の site は 1,121 件。file から file への依存の組（構造辺を除く）は 700 組から 860 組になった（追加 219、削除 59）。
- `crates/depgraph-core/src/config.rs` の file の dependents は 7 件から 12 件になり、`service_lifecycle.rs`、`daemon.rs`、`service_artifacts.rs`、`service_store_write.rs`、`profile_selection_preview.rs` が加わった。`crates/depgraph-core/src/lib.rs` は 30 件から 4 件、`crates/depgraph-mcp-tools/src/lib.rs` は 15 件から 0 件になった。
- 新しい解決先 1,121 件は、すべて名前を定義している file だった（1,046 件は定義を直接確認し、75 件は `crates/depgraph-mcp-tools/src/scalar.rs` の `string_newtype!` が生成する型）。

互換性:

- 解決先が変わった site の `target_ids` と、その site の edge（edge ID は target を含む）が変わる。re-export で名前を集約している file（crate root の `lib.rs`、`mod.rs` など）の dependents・fan-in・reverse impact が減り、定義元の file のそれが増える。`deps` / `dependents` / `why` / `impact` の結果も同じように変わる。
- hotspot は、fan-in と reverse impact の layer が rank 正規化なので、re-export を使うワークスペースの score と順位が変わり、fingerprint もあわせて変わる。finding ID は変わらない。上の syntax-only の Store では、9,440 件の finding のうち 9,437 件の fingerprint が変わり、上位 10 件の顔ぶれも変わった。
- health の `unused-file` は、crate root を指していた依存がなくなることで、crate root の `lib.rs` に新しく出ることがある。上の Store では `crates/depgraph-mcp-tools/src/lib.rs` に 1 件増えた。crate root は `entry-point` の blocker で `indeterminate` になる。既存の finding の ID は変わらない。
- 変化は Rust を再 scan した snapshot にだけ現れる。scan cache の key は worker バイナリの内容を含むので、更新後の scan で古い結果は再利用されない。Store の移行は不要。hotspot の fingerprint を baseline に保存している場合は、再 scan 後に作り直す。
- symbol（HIR の semantic 辺の先）への依存を file にまとめる表示は、この変更の対象外。

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

## TS / Web の構造解析の route ノードに定義元ファイルのパスを持たせる

Web worker の構造解析が出す route ノード（Next.js、Astro、TanStack Router、TanStack Start のファイルベースの route と、TanStack の生成 route tree の route）に、定義元ファイルのリポジトリ相対パスを `source_path` property として記録する（[#597](https://github.com/TamaT-LLC/depgraph-cli/issues/597)）。
これまで構造解析の route ノードは `framework` / `pattern` などしか持たず、パスがなかった。core の hotspot は `path` → `source_path` → `relative_path` → `manifest_path` の順にパスを読むため、これらの route は `location` が null で、Git churn が 0 だった。意味解析の route ノードは従来から `source_path` を持っており、同じキーと同じ基準（scan root からの相対パス）に揃える。

- `depgraph hotspots` と MCP の `health_hotspots_list` で、構造解析の route の finding に `location` が付き、Git churn が定義元ファイルの値になる。`--path-prefix` / `path_prefixes` で route も絞り込めるようになる。
- 1 つの route ノードに複数のファイルが対応する場合（Next.js の同じ URL の `page` と `layout` / `loading` など、TanStack のファイル route と生成 route tree の同じ `fullPath`）は、route を定義するファイル（`page`、`route`、Pages Router のページと API route、Astro の page / endpoint、TanStack のファイル route）を優先し、次にそれ以外のファイル、最後に生成 route tree を選ぶ。同順位はパスの辞書順で決める。分割 scan の各 analysis unit も同じファイルを選ぶ。
- route ノードの ID は変わらない（ID の計算にパスを含めない）。

互換性:

- churn layer は rank 正規化なので、route の定義元ファイルに Git の変更履歴があるワークスペースでは、hotspot の score と順位が変わる。hotspot の fingerprint は `location` を含むため、構造解析の route の hotspot は score が同じでも fingerprint が変わる。hotspot の finding ID は変わらない。
- `depgraph health list` の finding（`unused-file` など）は、finding ID も fingerprint も変わらない。
- 変化は Web を再 scan した snapshot にだけ現れる。scan cache の key は worker バイナリの内容を含むので、更新後の scan で古い結果は再利用されない。Store の移行は不要。hotspot の fingerprint を baseline に保存している場合は、再 scan 後に baseline を作り直す。

## Go の symbol / type に宣言元の位置を持たせ、health の location に行番号を出す

Go worker が出す symbol（名前付き、ローカル、クロージャ、package の初期化）と type のノードに、宣言元ファイルのリポジトリ相対パス `source_path` と、宣言の範囲 `source_span`（`start_line` / `start_column` / `end_line` / `end_column`、1 始まり）を記録する（[#596](https://github.com/TamaT-LLC/depgraph-cli/issues/596)）。Rust / Web worker の symbol / type と同じ形で、値は `declares` relation の evidence と同じ位置になる。generic の instance は、もとの generic の宣言の位置を持つ。package 単位に分割した scan で、ある unit が別の unit の package の symbol / type を参照するとき（依存側は export data から読む）も、その unit は宣言元の unit と同じ `source_path` / `source_span` を出す。分割の仕方によってノードの property は変わらない。
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
