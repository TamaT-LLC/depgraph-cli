# GitHub Actionsを使ったリリース手順

このリポジトリでは、日常の変更確認と配布物の検証を分ける。
PRと`main` pushでは高速CIを実行し、手動CIと`v*`タグではフルビルドを実行する。

## イベントごとの実行範囲

| イベント | Workflow | 実行内容 | 目的 |
| --- | --- | --- | --- |
| PR | CI | Rust、Go、Web、compiler-precise hostile E2E（hostile は関連 path 変更時のみ。main push / workflow_dispatch は常時） | マージ前の回帰検出 |
| `main` push | CI | Rust、Go、Web、compiler-precise hostile E2E（hostile 含む4ジョブを常時） | マージ結果の確認 |
| `workflow_dispatch` | CI | 上記4ジョブ（hostile 常時）、benchmark、Linux / macOS integration、Windows smoke | タグ作成前のフルCI |
| `v*`タグのpush | Release | quality、hostile E2E、benchmark、全5 targetのarchiveとcompiler pack、aggregate verification | 配布物の構築と公開 |
| `workflow_dispatch` | Release post-publish recovery | 固定済みv0.5.0 Release、元run、evidence、公開Linux archiveのread-only canary | 公開後orchestration失敗の復旧証明 |

GreptileはGitHub Actionsのジョブではないが、PRをマージする前に未解決の指摘を残さない。
PRまたは`main` pushでbenchmark、integration、windows-smokeが`skipped`になるのは正常である。
PRで compiler-precise hostile が関連 path 変更なしにより重いステップを実行しない場合も、ジョブ自体は success を返す（required check を壊さない）。

## リリース準備

1. バージョン変更とrelease noteを一つのPRにまとめる。
   現行契約ではbase versionは`0.5.1`である。
2. release noteを`docs/releases/<タグ名>.md`として追加する。
3. タグ名をworkspace versionと一致する`vX.Y.Z`または`vX.Y.Z-rc.N`にする。
4. `N`には先頭ゼロのない正整数を使う。
5. PRのCIをgreenにし、Greptileの未解決指摘をゼロにしてから`main`へマージする。

Release workflowは、タグ名と同名のrelease noteが存在し、タグ名とworkspace versionが一致する場合だけ公開へ進む。
`v0.4.0`と`v0.4.0-rc.N`はcurrent packageでは拒否される。
現行の`v0.5.1` stableはbaseline statusを`maintenance-ref-pinned`とする。
tag source、remote `main`、`refs/heads/release/0.5`、source tree、exact Full CI、固定Agent dogfood reportのいずれかが一致しなければ、default-branch source guardまたは`stable-release-gate-v2`がfail closedで拒否する。
公開済み`v0.5.0`のsource SHAは履歴検証用に固定し、現行candidateのSHAとして再利用しない。

## タグ作成前のフルCI

`main`へのマージを一時停止し、リリース対象commitを固定する。
GitHubのActions画面で`CI`を選び、`Run workflow`から`main`を指定して実行する。

CLIを使う場合は次のように実行する。

```bash
git fetch origin main
candidate="$(git rev-parse origin/main)"

gh workflow run CI --ref main
gh run list \
  --workflow CI \
  --event workflow_dispatch \
  --branch main \
  --limit 5
run_id=123456789 # 表示されたdatabase IDへ置き換える
gh run watch "$run_id" --exit-status
gh run view "$run_id" --json headSha,conclusion,url
```

表示された`headSha`が`candidate`と一致し、全ジョブが成功したことを確認する。
確認が終わるまで`main`へ別の変更をマージしない。

post-publish evidenceはGitHub Actions APIが返すjob表示名を完全一致で検証する。
matrix jobの暗黙の表示名は、空文字を除くnon-empty matrix値をすべて含むため、
workflowのmatrix axisを追加・変更した場合は実際の`gh run view --json jobs`出力と
validatorのjob identityを同時に更新する。期待値の定数からtest inputを生成するだけでは
API driftを検出できない。既知の実API応答
`xtask/fixtures/v0.5.0-rc.6-full-ci-run-31867648482.json`を独立fixtureとして固定し、
完全な8 job名と改変拒否をunit testで維持する。

## リリースタグの作成

フルCIを通過したcommitへ署名付きannotated tagを作成する。GitHub APIでtag
objectの署名が`valid`、`unknown_key`、または`unverified_email`として構文・署名付き
payloadを保持していることをRelease workflowが再確認する。`unsigned`、不正署名、
lightweight tagは公開前に拒否する。
publish jobはlocal checkoutのtag refを信頼せず、GitHub Git Data APIからremote
`refs/tags/<tag>`を取得してobject typeが`tag`であることを要求する。
`actions/checkout`の既定shallow tag checkoutはpeeled commitを同名のlocal tag refへ
配置するため、local `git rev-parse <tag>^{tag}`では正しいremote annotated tagを検証
できない。署名payloadとpeeled commitの検証にはremote tag object SHAだけを使う。
次の例では、`release_tag`を実際のタグ名へ置き換える。

```bash
release_tag="vX.Y.Z-rc.N" # 現行stableでは v0.5.1

git fetch origin main
test "$(git rev-parse origin/main)" = "$candidate"
test -f "docs/releases/${release_tag}.md"

git tag -s "$release_tag" "$candidate" -m "depgraph $release_tag"
git verify-tag "$release_tag"
git push origin "refs/tags/$release_tag"
```

v0.5の最初の候補は`v0.5.0-rc.1`とし、修正後はRC番号を増やす。
push済みtagを移動・再利用しない。
初回stable `v0.5.0`では、GA PRをmergeした後に`main`を一時freezeし、exact Full CIを通過した同一SHAで`refs/heads/release/0.5`を作成した。
`v0.5.1`以降のpatch releaseでは、同じexact-source条件を維持したまま、既存の`release/0.5`をcandidateへfast-forwardする。

```bash
git fetch origin main release/0.5
test "$candidate" = "$(git ls-remote origin refs/heads/main | awk '{print $1}')"
maintenance="$(git rev-parse origin/release/0.5)"
git merge-base --is-ancestor "$maintenance" "$candidate"
git push origin "$candidate:refs/heads/release/0.5"
test "$candidate" = "$(git ls-remote origin refs/heads/release/0.5 | awk '{print $1}')"
git rev-parse "$candidate^{tree}"
printf '%s\n' \
  release-baseline-v1 \
  repository=TamaT-LLC/depgraph-cli \
  version=0.5.1 \
  commit="$candidate" |
  shasum -a 256
```

このfast-forwardは、review済みでFull CIを通過した`main`のexact commitだけを対象にする。
`release/0.5`側で新しいmerge commitやcherry-pickを作らず、force-pushや履歴書き換えも行わない。
その後だけsigned annotated `v0.5.1` tagを同じSHAへpushする。
default-branch source guardはRelease run要求時に三つのrefを照合し、不一致またはmaintenance refの404ならrunをcancelしてtagを削除する。
API通信・認証・5xxや`main`取得不能は検証不能としてrunをfail closedでcancelする一方、signed tagは再試行用に保持し、ref不一致と混同しない。
tag側のstable gateはGitHub APIから`main` headのexact eight-job Full CIを再取得し、`agent-dogfood-report-v1`の固定SHA-256 `3e80eef4481e990984577b8269c5c2eee4c9f17df7a5b4a8ffd3648f6342f12b`と全14 gateを再計算する。
exact commit、tree、baseline digest、Full CI、Release run、tag object、asset closureの最終記録は`stable-release-gate.json`と`release-post-publish-evidence-v0.5.1.json`であり、commitが自分自身のSHAをsourceへ埋め込む自己参照は使わない。

タグのpushによってRelease workflowが起動する。
Release workflowはタグ付きcommitから配布物を再構築するため、手動CIのartifactを公開には流用しない。

## Release workflowの確認

Actions画面でタグに対応するRelease runを開き、すべてのgateが成功するまで監視する。
CLIを使う場合は次のように確認する。

```bash
gh run list \
  --workflow Release \
  --branch "$release_tag" \
  --limit 5
release_run_id=123456789 # 表示されたdatabase IDへ置き換える
gh run watch "$release_run_id" --exit-status
gh release view "$release_tag"
```

Releaseはquality、benchmark、hostile E2E、通常archive、compiler pack、aggregate reportを検証する。
通常archiveの各5 targetには`bin/depgraph-mcp`（Windowsは`.exe`）、
`libexec/depgraph-operation-runner`（Windowsは`.exe`）、
`schemas/depgraph-mcp-tools-v1.schema.json`が含まれる。`release-manifest.json`は
両binaryとschemaのSHA-256、tool/operation contract、`rmcp 3.1.0`、MCP revision
`2026-07-28`をattestし、SBOMとthird-party inventoryはrmcp dependency closureと
Apache-2.0 noticeを含む。`verify-release-assets`とstable gateの`mcp-five-target` checkは、
欠損、改変、version drift、target間schema driftを拒否する。

各native jobのMCP sidecarは`mcp-package-smoke-v2`である。従来のprotocol/catalog、
durable recovery、stdio purityに加え、`depgraph-agent-host-config-v1`からCodex、
Claude Desktop、VS Codeのread-only設定をclean temporary homeで生成する。公開前smokeは
closed synthetic `release-post-publish-evidence-v1`と別計算したtrusted digestを用い、
archive/checksum/manifest/sibling executable/schema/worker、target固有compiler-pack requirement、
root seal、private Store/current snapshotをpreflightしたうえで、生成されたlaunch tupleから
`initialize`、`tools/list`、`get_context`へ接続する。sidecarはevidence contract versionと
`agent_host_release_trust_verified=true`を記録する。source、Store、home、operation journalの
不変が一つでも崩れたpackageは公開対象にしない。archive preflightのruntime dependencyである`flate2`、
`tar`、`zip`とそのtransitive closureもSBOMとthird-party license inventoryの対象であり、
build/test-only dependencyとして除外してはならない。
Store不変性はmain databaseとWALのbyte完全一致で判定する。read connection自身がlock/index
として更新するSQLite `-shm`は存在とsizeを固定し、内容digestには含めない。operation
journal、そのWAL/SHM/rollback journal、runner purge lockはすべて不存在でなければならない。
すべてのpre-publish gateが成功した後だけ、最終`publish`ジョブがGitHub Releaseと検証済みassetを公開する。
同じjobの公開後再取得・Agent host canaryまで成功しなければRelease workflow全体はsuccessにならない。
`-rc.N`を含むタグはprereleaseとして公開される。

Store upgradeでは、公式`v0.4.0-rc.6` schema-13 fixtureの固定checksum、schema 17へのtransactional migration、completed graph identity、rollback copyのbyte不変をrelease gateが検証する。実運用でもwriterを停止し、databaseとWAL/SHMを一組でbackupしてchecksumを記録する。旧binaryでschema-17 databaseを開くdowngrade-in-placeは禁止し、rollback時はmigrated databaseを退避してbackup一式をrestoreしてから旧binaryを起動する。

## 公開後の再取得検証

最終`publish`ジョブはGitHub Releaseを作成した後、公開assetを新しいdirectoryへ
再取得する。v0.5 release closureでは、通常archive、checksum、query / cross-language /
MCP smokeが5 targetで25点、compiler pack、checksum、requirement、smokeが5 targetで
20点、benchmark / cache-hit / hostile / 二つのaggregate / stable gateが6点の計51点である。

再取得した通常archiveには`cargo xtask verify-release-assets`、compiler packには
`cargo xtask verify-compiler-pack-assets`を再実行する。これによりchecksum、manifest、
SBOM、project / third-party license、protocol / Agent schema、native binary handshake、
safe scan reconnect、stdout purity、root seal、compiler semantic / rollbackを公開byteだけで
再検証する。benchmark二種も公開reportを入力に再検証し、再生成aggregate reportが
公開reportおよび元のworkflow artifactとbyte一致することを要求する。

さらに51点すべてについてpublic downloadとworkflow artifactのfilename、size、SHA-256
が一致しなければ失敗する。`release-post-publish-evidence-v1` JSONは、candidate commit /
tree、署名tag object、exact manual full-CI runと8 job、Release run、51 asset digest、
aggregate digest、asset-set digestを記録する。最終jobはこのJSONを同じGitHub Releaseへ
追加し、もう一度downloadしてbyte一致を確認してからsuccessになる。最終jobの
job-scoped tokenは、Full CIのrun/jobを読むための`actions: read`と、Releaseへ成果物を
公開するための`contents: write`だけを持つ。
公開後検証は「その時点の最新run」を再選択せず、`stable-release-gate.json`が記録した
同一`full_ci_run_id`を再取得し、SHA、branch、8 job、job-set digestまで一致させる。

最後にLinux x86-64の公開archiveを新しいdirectoryへ展開し、固定polyglot fixtureを
公開`depgraph`でsafe scanする。GitHub release-asset APIからpost-publish evidenceの
SHA-256を独立取得し、公開archive/checksum、展開manifest、compiler-pack requirement、
repository、Storeを入力に、公開binaryの`agent-config --host claude-desktop`をread-only
defaultで実行する。このcanaryはarchive真正性、root seal、Store/current snapshot、全sibling、
compiler requirement、`initialize`、`tools/list`、`get_context`、source/Store不変を同時に
再検証する。共通`scripts/release-post-publish-canary.sh`はこれらすべてのfile/directory入力を
`realpath`で絶対パスへ固定してから公開binaryへ渡す。checkout-built product binaryを
実行経路へ混ぜない。

公開後は、対象commit、release note、5 targetのarchive、compiler pack、checksum、
検証report、`release-post-publish-evidence-<tag>.json`が同じタグに結び付いていることを
確認する。checkout内のproduct binaryや未公開package artifactを公開後verificationの
代用品にしてはならない。

### v0.5.0のimmutable post-publish recovery

最初のstable Release run `31928961757`は、51点の公開assetを再取得・検証し、52点目の
`release-post-publish-evidence-v0.5.0.json`をupload、再取得、digest照合した後、最後の
Agent host canaryへ相対file pathを渡したため失敗した。公開binaryが
`preflight input file paths must be absolute`として拒否したのは意図したsecurity policyであり、
失敗はworkflow orchestration側にある。元runはfailureのまま保持し、再実行、削除、checkの
上書き、tag移動、asset置換を行わない。

`Release post-publish recovery` workflowは入力なし、`main`限定、`actions: read`と
`contents: read`だけで実行する。v0.5.0のcommit、tree、signed annotated tag object、
exact Full CI run `31923533506`、元Release run、元17 jobの結論集合、evidenceのSHA-256
`13e253b3759a9729f43ff8dbe6f6a48191770681b02a57cb5197bc908ab77524`を固定する。
公開archive内のWeb workerはNode.js 24以上を要求するため、workflowは元Release jobと同じ
Node.js 24.18.0をcanary前に固定する。このruntime setupを省略したrunner既定Nodeでの
scan failureを、公開packageの不良やimmutable release closureの失敗として扱ってはならない。
GitHub Release APIの52 assetをevidence内の51 asset inventoryと照合し、evidence、Linux
archiveとchecksum、同targetのcompiler-pack archiveとchecksum、compiler-pack requirementを
公開面から再取得する。digest検証後にcompiler packをcanary専用outputへ展開し、requirementを
同じ親へbyte-identicalに配置する。その後、共通canaryへ絶対パスを渡してsafe scan、
`agent-config`、`initialize`、`tools/list`、`get_context`を完走する。GitHub Releaseへのmutation
APIは呼ばず、green recovery runを元runとpost-publish evidenceに連結した復旧証明とする。

## 失敗時の扱い

runner障害や一時的なdownload失敗でsourceを変更しない場合は、同じRelease runの失敗jobを再実行できる。

コード、設定、release noteの修正が必要な場合は、push済みタグをforce updateしない。
修正PRを`main`へマージし、手動フルCIを再実行して、次のRC番号または次のversionのタグを作成する。

公開assetとpost-publish evidenceがすでにbyte一致で閉じた後のread-only canary orchestration
だけに不具合があった場合は、対象tag、source、元run、evidence digestを固定した専用recovery
workflowで残りの検証を完走できる。recoveryは元runをsuccessに見せかけず、公開面を変更せず、
元runの成功済みstepと失敗原因をGitHub Actions APIおよびlogから再確認しなければならない。

公開済みreleaseのassetやタグは置き換えない。
配布後に不具合が見つかった場合は、影響範囲をrelease noteへ記録し、修正版を新しいpatch versionとして公開する。

## 通常運用

通常のPRでは高速CIとGreptileだけを完了条件にする。
OS固有処理、toolchain、依存関係、package、release workflow、性能契約を変更するPRでは、マージ前にも`workflow_dispatch`で対象branchのフルCIを実行する。
リリース時は`main`のフルCIを一度通し、そのexact commitへタグを作成する。
