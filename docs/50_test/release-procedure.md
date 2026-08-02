# GitHub Actionsを使ったリリース手順

このリポジトリでは、日常の変更確認と配布物の検証を分ける。
PRと`main` pushでは高速CIを実行し、手動CIと`v*`タグではフルビルドを実行する。

## イベントごとの実行範囲

| イベント | Workflow | 実行内容 | 目的 |
| --- | --- | --- | --- |
| PR | CI | Rust、Go、Web、compiler-precise hostile E2E | マージ前の回帰検出 |
| `main` push | CI | PRと同じ4ジョブ | マージ結果の確認 |
| `workflow_dispatch` | CI | 上記4ジョブ、benchmark、Linux / macOS integration、Windows smoke | タグ作成前のフルCI |
| `v*`タグのpush | Release | quality、hostile E2E、benchmark、全5 targetのarchiveとcompiler pack、aggregate verification | 配布物の構築と公開 |

GreptileはGitHub Actionsのジョブではないが、PRをマージする前に未解決の指摘を残さない。
PRまたは`main` pushでbenchmark、integration、windows-smokeが`skipped`になるのは正常である。

## リリース準備

1. バージョン変更とrelease noteを一つのPRにまとめる。
2. release noteを`docs/releases/<タグ名>.md`として追加する。
3. タグ名をworkspace versionと一致する`vX.Y.Z`または`vX.Y.Z-rc.N`にする。
4. `N`には先頭ゼロのない正整数を使う。
5. PRのCIをgreenにし、Greptileの未解決指摘をゼロにしてから`main`へマージする。

Release workflowはタグ名と同名のrelease noteを読む。
ファイルがない場合やタグ名とworkspace versionが一致しない場合は、公開前に失敗する。

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

フルCIを通過したcommitへannotated tagを作成する。
次の例では、`release_tag`を実際のタグ名へ置き換える。

```bash
release_tag="vX.Y.Z-rc.N"

git fetch origin main
test "$(git rev-parse origin/main)" = "$candidate"
test -f "docs/releases/${release_tag}.md"

git tag -a "$release_tag" "$candidate" -m "depgraph $release_tag"
git push origin "refs/tags/$release_tag"
```

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
すべてのgateが成功した後だけ、最終`publish`ジョブがGitHub Releaseと検証済みassetを公開する。
`-rc.N`を含むタグはprereleaseとして公開される。

公開後は、対象commit、release note、5 targetのarchive、compiler pack、checksum、検証reportが同じタグに結び付いていることを確認する。

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
