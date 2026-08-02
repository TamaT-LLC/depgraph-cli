# Build cache reuse

この文書は、通常のRust / Web buildに対するpre-execution cache reuseの検証境界を定義する。

Rust compiler-preciseは通常build cacheを共有せず、専用の
`rust-compiler-precise-validated-cache-v1` entryと診断を使う。
専用contractのcold／warm release matrixは
[`compiler-precise-five-target-release.md`](compiler-precise-five-target-release.md)で定義する。

## Admission identity

Cache keyはbuild開始前に計算し、次の入力を含む。

- staged source treeのcontent digest
- stagingされる空ディレクトリとfile permissionのmetadata digest
- manifest、lockfile、build configのcontent digest
- effective profile ID
- adapter kind、version、artifact digest
- toolchain executable digestとversion
- command plan、environment key set、target、protocol version
- build layerの親となるimmutable base snapshot ID

Build run ID、開始・終了時刻、validated output digestは入力ではないためkeyへ含めない。

## Hit validation

Warm lookupはcache metadataとpayload digestを検証する。

参照先はintegrity検証済みのcompleted build snapshotであり、現在のsnapshotと一致しなければならない。

Build attemptのbase snapshotはkeyのbase bindingと一致し、対応するauditはcompletedかつvalidated outputを持たなければならない。

CLIはlookup後に入力identityを再計算し、sourceまたはtoolchainが検証中に変化した場合はreuseを拒否する。

Hit eventとcache usage countはSQLite immediate transaction内で更新し、source content、空ディレクトリ、file permissionをcommit直前に再検証する。

このpre-commit proofが失敗した場合はtransactionをrollbackし、hitを公開せずproject codeを実行する経路へ戻る。

Hit時はproject codeを実行せず、新しいbuild audit、build attempt、evidence、snapshot、cache entryを作らない。

## Test matrix

| Fixture | Cold run | Warm run | Invariant |
| --- | --- | --- | --- |
| Rust build script / proc macro | `stored` | `hit` | snapshot ID、audit run ID、cache entry count、JSON exportが同一 |
| Next.js production build | `stored` | `hit` | `project code executed: false`かつJSON exportがbyte-identical |
| Corrupt build cache payload | `reject` | validated rebuild後に`stored` | corrupt payloadをreuseせず置換可能 |
| Source / control / profile / adapter / toolchain / base change | `miss`または`reject` | 新しいsafe baseのadmissionが必要 | stale keyをreuseせず既存snapshotを維持 |

## Commands

Rustのcold / warm回帰はCLI integration testで実行する。

```text
cargo test -p depgraph-cli --test cli consented_build_mode_runs_project_code_only_in_the_supervised_staging_area -- --exact
```

Next.jsのcold / warm回帰はrelease benchmark fixtureに含まれる。

```text
cargo xtask test
```
