# 公開候補の最終監査手順

## この手順が扱う範囲

この手順は、`public-readiness-v1` の最終監査から公開後の初期観測までを扱う。

監査結果は証跡であり、リポジトリの可視性を変更する命令ではない。

本番リポジトリの可視性は、TamaT-LLC の Organization Owner が候補Commitと変更時間帯を明示的に承認した場合に限って変更できる。

承認がない場合、検証結果が `allow` でもリポジトリを非公開のまま維持する。

## 監査を始める条件

最終監査は、次の担当がOrganization管理下のTeamとして割り当てられた後に始める。

- **証跡作成者**：候補を凍結し、監査入力と証跡を作成する。
- **Gate承認者**：担当Gateの証跡を独立に再検証する。
- **最終承認者**：Security、Legal、Release、Organization Ownerの各役割として同一の証跡Manifestを承認する。
- **変更作業者**：承認された時間帯にGitHub設定を変更する。
- **インシデント担当者**：停止条件に達した場合に書き込み停止と封じ込めを実行する。

証跡作成、Gate承認、最終承認には、それぞれ異なる認証済みTeam identityを使う。

個人のメールアドレス、アクセストークン、秘密値、端末上の絶対Pathは、公開可能な証跡へ記録しない。

## 証跡の保存先

監査中の生成物は、Git管理外の `dist/public-readiness/final/` に保存する。

```sh
mkdir -p dist/public-readiness/final
```

生のScanner結果やGitHub API応答に機密情報が含まれる可能性があるため、公開可能なBundleへ入れるのはDigest、件数、Pattern ID、非機密の是正証明だけとする。

監査担当者は、生の証跡をOrganization管理下のアクセス制限された保存先へ移し、保存期間と削除責任者を記録する。

## 候補Commitを凍結する

候補Commitは、監査用の変更を `main` へMergeした後に決める。

新しいCommit、Tag、Release asset、Actions run、IssueやPull Requestの添付が発生した場合、影響を受けるGateを再実行する。

新しいCloneでRemoteを取得し、作業Treeと `origin/main` が一致することを確認する。

```sh
git fetch --prune origin
git status --porcelain=v1
git rev-parse HEAD
git rev-parse origin/main
```

`git status --porcelain=v1` の出力が空であり、二つのCommit IDが一致した場合だけ先へ進む。

候補Commitは40文字の小文字16進数で記録する。

## 九つのGateを閉じる

各Gateは、[Public OSS readiness and release governance](../40_arch_design/adr-public-oss-release-governance.md)のPass条件と証跡要件を満たす必要がある。

| Gate | 最終監査で固定する入力 | 停止条件 |
| --- | --- | --- |
| `candidate-and-surface` | 候補Commit、Remote ref一覧、公開対象Surface、書き込み凍結期間 | HEAD不一致、収集漏れ、凍結後の変更 |
| `governance-and-community` | README、Community文書、Team割り当て、Link検査 | 担当Team不在、Placeholder、匿名閲覧失敗 |
| `history-and-secrets` | 全refのObject closure、共同作業履歴、Actions資産、Fresh mirror再検査 | 未解決Finding、資格情報の未失効、収集未完了 |
| `incident-readiness` | 連絡経路、権限者、Tabletop結果、初期観測の当番 | 24時間の初動担当不在、封じ込め手順未検証 |
| `legal-and-provenance` | 全Assetと依存関係、SBOM、License、脆弱性、DCO判断 | 権利不明、High以上の未解決脆弱性、法務承認なし |
| `migration-dry-run` | 一時Repositoryでの演習、設定復元、匿名Smoke、後片付け | 本番を演習対象に指定、設定不一致、Smoke失敗 |
| `release-and-support` | 同一候補のCI、Release Gate、5 TargetのArtifact、Support方針 | 候補不一致、Gate拒否、署名やArtifact closureの未検証 |
| `repository-controls` | Redact済みGitHub設定、Ruleset、Access review、Security設定 | API権限不足、Ruleset不在、意図しないAccess、設定差分 |
| `security-and-disclosure` | Disclosure演習、Workflow権限、Action固定、Security担当 | 公開Issueへの誘導、可変Action ref、担当者不在 |

一時Repositoryでの演習には、[Public migration rehearsal](public-migration-rehearsal.md)を使う。

本番Repositoryを演習先として指定した入力は、Evaluatorが必ず拒否する。

GitHub設定はRedact済みSnapshotから検証する。

```sh
cargo xtask github-settings-verify \
  dist/public-readiness/final/github-settings-snapshot.json \
  --output dist/public-readiness/final/github-settings-evaluation.json
```

このコマンドがAPI権限不足、部分収集、設定差分のいずれかを検出した場合、`repository-controls` は `reject` とする。

## Bundleを検証する

証跡作成者は、九つのEvidenceとGate、四つの最終承認を `public-readiness-v1` Bundleへまとめる。

Bundleは[`schemas/public-readiness-v1.schema.json`](../../schemas/public-readiness-v1.schema.json)に従う。

検証時の期待値はBundleから読み戻さず、凍結後に独立に観測した値を渡す。

- `candidate_commit`：`origin/main` のHEAD。
- `audited_refs_digest`：最終Remote ref一覧とFresh mirror再検査が共有するDigest。
- `github_settings_digest`：Redact済みGitHub設定SnapshotのDigest。
- `governance_tree_digest`：承認済みCommunityとGovernance文書TreeのDigest。
- `release_gate_digest`：同じ候補Commitに対するStable release gateのDigest。

```sh
cargo xtask public-readiness-verify \
  dist/public-readiness/final/public-readiness-bundle.json \
  --candidate-commit <40-hex-origin-main-head> \
  --audited-refs-digest <64-hex-final-refs-digest> \
  --github-settings-digest <64-hex-settings-digest> \
  --governance-tree-digest <64-hex-governance-tree-digest> \
  --release-gate-digest <64-hex-release-gate-digest> \
  --output dist/public-readiness/final/public-readiness-evaluation.json
```

コマンドは可視性やGitHub設定を変更せず、Bundleを解釈できた場合はDigestと拒否理由だけを含む評価結果を出力する。

Bundleを解釈できない場合、入力が欠けている場合、内容が改変されている場合、候補状態が一致しない場合、未解決Findingがある場合、独立承認が成立しない場合は非0で終了する。

終了Codeが0であり、評価結果の `decision` が `allow` である場合だけ、Organization Ownerへ変更承認を依頼できる。

## 変更時間帯を承認する

Organization Ownerの承認Statementは、候補Commit、Evidence manifest Digest、GitHub設定Digest、役割割り当て、開始時刻、終了時刻、変更作業者、インシデント担当者を固定する。

承認StatementのDigestを証跡へ記録し、承認本文はOrganization管理下の記録として保管する。

次のいずれかが満たせない場合、変更時間帯を開始しない。

- Organization OwnerとSecurity、Legal、Releaseの承認が同じEvidence manifestを参照している。
- 変更作業者とインシデント担当者が時間帯中に対応できる。
- Remote HEAD、ref Digest、GitHub設定Digestが最終検証時から変わっていない。
- RulesetとSecurity設定を復元する操作が事前に演習されている。
- 匿名Smokeを実行する別SessionとNetworkが利用できる。

## 本番変更と停止条件

本番変更は承認された時間帯に限り、[ADRのGate 8](../40_arch_design/adr-public-oss-release-governance.md#gate-8-migration-dry-run-and-change-window)の順序で実行する。

書き込みを停止した後で候補状態を再検証し、可視性変更、Ruleset復元、Security機能の有効化、設定検証、匿名Smokeの順に進める。

次の事象を一つでも検出した場合、通常書き込みを再開せず、インシデント封じ込めへ移る。

- 候補Commitまたはref Digestが変わった。
- 必須Rulesetを有効化できない。
- GitHub設定Verifierが `reject` を返した。
- Private vulnerability reportingが利用できない。
- 匿名Clone、Archive、Community link、Template、Actions、Release、PackageのSmokeが失敗した。
- 秘密情報、個人情報、権利不明Assetを新たに検出した。

非公開へ戻す操作は、公開済みCloneやDownloadを回収しない。

そのため、封じ込め後も資格情報の失効、GitHub Supportへの削除依頼、関係者への通知、証跡保全を継続する。

## 公開後の初期観測

通常書き込みは、GitHub設定Verifierと匿名Smokeがともに成功した後に再開する。

初期観測の担当者は、承認された観測期間中にActions、Issue、Pull Request、Security report、ReleaseとPackageの可用性、Access変更を確認する。

観測結果は秘密値を含まない時系列記録として保存し、異常がある場合は変更時間帯と同じインシデント経路へ連絡する。

観測期間の終了後、Organization Ownerは変更記録、設定評価、匿名Smoke、未解決事象を確認して作業をCloseする。
