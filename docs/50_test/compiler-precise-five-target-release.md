# Compiler-precise five-target release gate

この文書は、`compiler-pack-five-target-release-v1` の release 証跡を定義する。

## 対象

release workflow は次の target ごとに compiler pack を構築する。

| OS | target | archive |
| --- | --- | --- |
| Linux x86-64 | `x86_64-unknown-linux-gnu` | `tar.gz` |
| Linux ARM64 | `aarch64-unknown-linux-gnu` | `tar.gz` |
| macOS Intel | `x86_64-apple-darwin` | `tar.gz` |
| macOS Apple Silicon | `aarch64-apple-darwin` | `tar.gz` |
| Windows x86-64 | `x86_64-pc-windows-msvc` | `zip` |

通常の `depgraph` archive と compiler pack は別の matrix job と artifact name を使う。
通常 archive の verifier は compiler-pack file を許可しないため、compiler pack を通常配布物へ混入させる変更は release gate で失敗する。

## Target gate

各 native runner は公式 channel manifest の SHA-256 を検証し、`nightly-2026-07-17` の rustup component inventory に記録された file だけを pack source へコピーする。
対象 component は `cargo`、`llvm-tools`、`rust-src`、`rust-std`、`rustc`、`rustc-dev` の六つである。
wrapper、query child、protocol schema、license は component inventory と別の owner として closed-tree manifest に記録する。

各 archive は展開後に core verifier を再実行する。
verifier は manifest、directory、file、executable bit、component owner、SBOM、license inventory、provenance、release checksum reference を検証する。
wrapper と query child は `depgraph-compiler-component-handshake-v1` を返し、contract、protocol、MIR schema、rustc commit、query capability を実体から照合する。

各 target の semantic fixture は同じ Git commit から二つの checkout を作る。
両 checkout で safe scan、compiler-precise resolve、JSON export を実行する。
raw export の SHA-256 は、run ごとに変わる build run ID、ledger digest、artifact locator を含む監査証跡として個別に保持する。
cross-checkout gate は、これらの run-scoped provenance と派生 site ID を除き、node の意味属性と source、target、kind を含む edge 関係を正規化した semantic graph の byte 一致を要求する。
cross-target semantic fixtureはtyped MIR body、generic instance、direct call、static constantを含み、`monomorphized_call_graph`と`typed_mir`のquery capabilityを検証する。
packaged build-script fixtureは`OUT_DIR`に生成したRustソースをライブラリから利用し、`custom-build`のcompile/run両Cargo unit、atomic promotion、doctor、deps、why、JSON exportを検証する。
空の`build.rs`だけを持つ最小fixtureも別storeで実行し、compiler-precise resolveが成功することを確認する。

各native targetの代表fixtureは同じstore・同じ入力でresolveを2回実行する。
Cold runは`project code executed: true`、`build cache lookup: miss (not-found)`、`build cache: stored`を返す。
Warm runは3つのconsent flagを再度要求し、`project code executed: false`、`build cache lookup: hit (validated)`、`build cache: hit`を返す。
Cold／warmのJSON exportは`build_run_id`、attempt ID、時刻など実行固有provenanceを除いて同一でなければならない。
`OUT_DIR` fixtureのwarm exportでもcustom-build compile/run unit、typed MIR、compiler instance/call evidenceを維持し、doctor、deps、whyが成功しなければならない。

resource gate は archive を 4 GiB 以下、closed tree を 8 GiB 以下、file を 250,000 件以下、semantic gate を 10 分以下に制限する。
verifier は archive の圧縮サイズを展開前に検証し、展開中も path、entry type、重複、明示的な親 directory、file 数、directory 数、展開 byte 数を上限内に固定する。
上限超過は target smoke を生成せず release を停止する。

## Rollback gate

成功済み store に対して次の三つの失敗を実行する。

- pack root が存在しない。
- requirement の target が manifest と一致しない。
- query executable が archive 展開後に改変されている。

三つの失敗は `unsupported` と no-fallback 診断を返さなければならない。
失敗後の JSON export は成功直後の export と byte-identical でなければならない。
別 toolchain、PATH 上の compiler、safe scan result を compiler-precise 成功として返す処理は許可しない。

別のsingle-package fixtureではbuild scriptを意図的に非zero終了させる。
この失敗は`rust-compiler-build-script-failed`、検証済みCargo unit ID、`custom-build / run-custom-build`分類だけを返し、build scriptがstderrへ出した秘密fixture値を返してはならない。
失敗前後のJSON exportはbyte-identicalであり、compiler invocationやCargo unitの部分graphをpromotionしてはならない。

Compiler cacheのpayload、base binding、pack attestation、ledger digestの改ざんは`reject (corrupt)`となり、同じ呼び出しのcold実行が成功するまでcurrent snapshotを変更してはならない。
Warm promotionのpre-commit検証を意図的に失敗させるrollback testは、新しいaudit、attempt、snapshot、cache hit eventが一件も残らないことを確認する。

## Aggregate gate

`cargo xtask verify-compiler-pack-assets` は五つの archive、checksum、requirement、target smoke を exact file set として検証する。
aggregate report は `compiler-pack-five-target-verification-v1` である。

全 target は次の compatibility unit を共有しなければならない。

- release contract と compiler contract
- manifest schema と MIR schema
- nightly channel、Rust release、rustc commit、channel manifest digest
- wrapper protocol
- query capability
- separate distribution と `unsupported-no-fallback` policy

target ごとの executable digest と component tree digest は native artifact なので一致を要求しない。
一方、node kind、edge kind、typed MIR body、instance、call、constant の canonical semantic shape は一致を要求する。

stable release gate は通常 archive の aggregate report、benchmark report、compiler-pack aggregate report を独立した入力として検証する。
`compiler-pack` と `verify-compiler-packs` の workflow result が `success` でない場合も release を拒否する。
さらに、通常 archive とcompiler packのrelease version、五つのtarget集合、compiler compatibility unitを直接比較し、同一release runの対応するassetだけを許可する。
未公開のimmutable `v0.4.0` baselineは従来どおり元の固定commitだけを許可し、current packageとしては公開しない。v0.5 pack付きの公開検証には同一base versionのcanonicalな`v0.5.0-rc.N` tagだけを許可する。RC tagはworkflowのexact source SHAへ結合し、sequenceは先頭ゼロを含まない正整数に限る。stable `v0.5.0`はGA baselineがpinされるまで拒否する。

## 実行

target runner では次の command を実行する。

```text
cargo xtask compiler-pack-package \
  --channel-manifest channel-rust-nightly-2026-07-17.toml
```

aggregate runner では次の command を実行する。

```text
cargo xtask verify-compiler-pack-assets compiler-artifacts
```
