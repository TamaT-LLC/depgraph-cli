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

GreptileはGitHub Actionsのジョブではないが、PRをマージする前に未解決の指摘を残さない。
PRまたは`main` pushでbenchmark、integration、windows-smokeが`skipped`になるのは正常である。
PRで compiler-precise hostile が関連 path 変更なしにより重いステップを実行しない場合も、ジョブ自体は success を返す（required check を壊さない）。

## リリース準備

1. バージョン変更とrelease noteを一つのPRにまとめる。現行契約ではbase versionは`0.5.0`である。
2. release noteを`docs/releases/<タグ名>.md`として追加する。
3. タグ名をworkspace versionと一致する`vX.Y.Z`または`vX.Y.Z-rc.N`にする。
4. `N`には先頭ゼロのない正整数を使う。
5. PRのCIをgreenにし、Greptileの未解決指摘をゼロにしてから`main`へマージする。

Release workflowは、タグ名と同名のrelease noteが存在し、タグ名とworkspace versionが一致する場合だけ公開へ進む。`v0.4.0`と`v0.4.0-rc.N`はcurrent packageでは拒否される。`v0.5.0` stableはbaseline statusが`candidate-unpinned`の間、default-branch source guardと`stable-release-gate-v2`の双方がfail closedで拒否する。

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
release_tag="vX.Y.Z-rc.N"

git fetch origin main
test "$(git rev-parse origin/main)" = "$candidate"
test -f "docs/releases/${release_tag}.md"

git tag -s "$release_tag" "$candidate" -m "depgraph $release_tag"
git verify-tag "$release_tag"
git push origin "refs/tags/$release_tag"
```

v0.5の最初の候補は`v0.5.0-rc.1`とし、修正後はRC番号を増やす。push済みtagを移動・再利用しない。stable `v0.5.0`を作成する前に、GA PRでfull CIがgreenなexact commit、tree、canonical baseline digestを記録し、`candidate-unpinned` guardをそのcommitだけを許可するguardへ変更し、同じcommitから`refs/heads/release/0.5`を作る。

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
すべてのgateが成功した後だけ、最終`publish`ジョブがGitHub Releaseと検証済みassetを公開する。
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
追加し、もう一度downloadしてbyte一致を確認してからsuccessになる。

公開後は、対象commit、release note、5 targetのarchive、compiler pack、checksum、
検証report、`release-post-publish-evidence-<tag>.json`が同じタグに結び付いていることを
確認する。checkout内のproduct binaryや未公開package artifactを公開後verificationの
代用品にしてはならない。

## 失敗時の扱い

runner障害や一時的なdownload失敗でsourceを変更しない場合は、同じRelease runの失敗jobを再実行できる。

コード、設定、release noteの修正が必要な場合は、push済みタグをforce updateしない。
修正PRを`main`へマージし、手動フルCIを再実行して、次のRC番号または次のversionのタグを作成する。

公開済みreleaseのassetやタグは置き換えない。
配布後に不具合が見つかった場合は、影響範囲をrelease noteへ記録し、修正版を新しいpatch versionとして公開する。

## 通常運用

通常のPRでは高速CIとGreptileだけを完了条件にする。
OS固有処理、toolchain、依存関係、package、release workflow、性能契約を変更するPRでは、マージ前にも`workflow_dispatch`で対象branchのフルCIを実行する。
リリース時は`main`のフルCIを一度通し、そのexact commitへタグを作成する。
