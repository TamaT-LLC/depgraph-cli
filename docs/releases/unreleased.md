# 未リリース

## 大規模解析の再分割と macOS の再利用

メモリ上限・タイムアウト・出力量上限で失敗した batch を再分割するとき、成功済みの batch の番号を保持するように修正した。
保存側も再分割の世代を考慮し、全 batch の存在・番号の一意性・解析範囲を確認してから完了と判定する。
再分割が終わるまで失敗時の部分出力を一時保存し、置き換え前後の profile が衝突しないようにした。
回復できない場合は部分結果を保持する。
大きなprotocol出力の検証は専用の処理スレッドで行い、別workerのパイプ読み取りや上限監視を妨げないようにした。
個別の資源上限は変更しない。

macOS の Go 解析でも、リポジトリ内依存の参照 fingerprint を生成できるようにした。
Linux と共通の `openat` と `O_NOFOLLOW` による読み込みを使い、参照元の変更を検出しながら package semantic の結果を再利用する。
追加依存は Go 公式拡張パッケージ `golang.org/x/sys v0.47.0`（BSD-3-Clause）で、`workers/go/go.mod` と `go.sum` に固定している。

元の試験対象での scan と health の完了確認は、Epic #464 の必須条件として扱う。
公開合成 fixture の成功や、部分グラフに対する health の成功だけでは完了扱いにしない。

関連: [#479](https://github.com/TamaT-LLC/depgraph-cli/issues/479)、[#480](https://github.com/TamaT-LLC/depgraph-cli/issues/480)、[#482](https://github.com/TamaT-LLC/depgraph-cli/issues/482)。
