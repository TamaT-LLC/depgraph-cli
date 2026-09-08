# 未リリース

## 大規模解析の再分割と macOS の再利用

メモリ上限・タイムアウト・出力量上限で失敗した batch を再分割するとき、成功済みの batch の番号を保持するように修正した。
保存側も再分割の世代を考慮し、全 batch の存在・番号の一意性・解析範囲を確認してから完了と判定する。
再分割が終わるまで失敗時の部分出力を一時保存し、置き換え前後の profile が衝突しないようにした。
回復できない場合は部分結果を保持する。
大きなprotocol出力の検証は専用の処理スレッドで行い、別workerのパイプ読み取りや上限監視を妨げないようにした。
個別の資源上限は変更しない。
事前の依存計画では、Go のモジュール名の最長一致、Web の import 構文、Node 標準モジュール、TypeScript のパス別名・継承設定、ロック済みの外部依存を扱う。
文字列や Markdown のコード例を参照先と誤認して、解析済みの単位を未完了と判定する問題を修正した。
解決できない参照は引き続き不明として記録し、継承設定も再利用時の入力確認に含める。
全単位の実行完了と意味解析の確実性を分け、未解決参照だけを理由に scan を partial としない。
その場合も集計に semantic-complete を付けず、診断を保持し、health の未使用確定を抑止する。
Web の内蔵 TypeScript コンパイラーのタイムアウトも再分割対象として扱い、汎用の失敗で止まらないようにした。

macOS の Go 解析でも、リポジトリ内依存の参照 fingerprint を生成できるようにした。
Linux と共通の `openat` と `O_NOFOLLOW` による読み込みを使い、参照元の変更を検出しながら package semantic の結果を再利用する。
追加依存は Go 公式拡張パッケージ `golang.org/x/sys v0.47.0`（BSD-3-Clause）で、`workers/go/go.mod` と `go.sum` に固定している。

元の試験対象での scan と health の完了確認は、Epic #464 の必須条件として扱う。
公開合成 fixture の成功や、部分グラフに対する health の成功だけでは完了扱いにしない。

関連: [#479](https://github.com/TamaT-LLC/depgraph-cli/issues/479)、[#480](https://github.com/TamaT-LLC/depgraph-cli/issues/480)、[#482](https://github.com/TamaT-LLC/depgraph-cli/issues/482)。
