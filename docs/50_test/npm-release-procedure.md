# npmリリース手順

この手順は、検証済みGitHub Releaseを`@tamat-llc/depgraph`と5つのnative packageへ
変換し、npm Trusted Publishingで公開する境界を定める。
アーキテクチャ上の決定は
[`PROJ-ARC-001-ADR-008`](../40_arch_design/adr-npm-distribution.md)を参照する。

## 対象

npmへ公開するpackageは次の6つである。

- `@tamat-llc/depgraph`
- `@tamat-llc/depgraph-darwin-arm64`
- `@tamat-llc/depgraph-darwin-x64`
- `@tamat-llc/depgraph-linux-arm64-gnu`
- `@tamat-llc/depgraph-linux-x64-gnu`
- `@tamat-llc/depgraph-win32-x64`

`@depgraph/web-worker`はnative archiveへ組み込む内部Workerであり、npmへ
直接公開しない。
既存の`v0.5.0`はGitHub Releaseのみで配布する。
最初のnpm stableは、この仕組みを含む`v0.5.1`である。

## 通常の公開フロー

GitHub Releaseの公開とpost-publish evidenceの生成が完了した後、release
maintainerは`.github/workflows/npm-release.yml`を対象stable tagへdispatchする。

```sh
gh workflow run npm-release.yml --ref "vX.Y.Z"
```

prerelease tag、branch ref、`main`と異なるcommit、lightweight tag、未署名tag、
draft/prerelease GitHub Release、post-publish evidenceがないRelease、evidenceが
指す`Release` workflow runがsuccessでない場合は公開対象にならない。

`prepare` jobは`actions: read`と`contents: read`だけを持ち、次を実行する。

1. `main`、signed annotated tag、GitHub Release、successful Release runを照合する。
2. 公開済み5 targetのarchive、checksum、3種類のsmoke reportを取得する。
3. `cargo xtask verify-release-assets release-assets`で公開byteを再検証する。
4. `npm/scripts/build-packages.mjs`で6つのtarballと
   `npm-package-set.json`を生成する。
5. Linux x64のnative packageとroot packageを`--ignore-scripts`で導入し、
   version、MCP binary、safe scanを確認する。
6. package setを同一workflow内の短期artifactとして保存する。

`publish` jobはGitHub Environment `npm`の承認後に実行する。
このjobはcheckoutせず、repository scriptも実行せず、同一runのpackage-set
artifactだけを入力にする。
各tarballのSHA-256、package名、version、repository、`private`と`scripts`の
不存在を再確認し、5つのnative packageを先に、`@tamat-llc/depgraph`を最後に公開する。
同じversionがすでに存在する場合はregistry上のintegrityとrepositoryが一致する
ときだけskipするため、部分失敗後の再実行は安全である。
`npm publish`の成功後にregistryのread APIが一時的に`E404`を返す場合がある。
workflowは約30分を上限に同じversionの可視化を待ち、integrityが一致してから次の
packageへ進む。
待機中は同じversionを再公開しない。
`E404`以外の参照失敗とintegrity不一致は直ちに失敗させる。

GitHub Environment `npm`は`repo-knowledge-mcp`と同じ保護設定にする。
`TakehiroT`または`Fuelda`のいずれか1名の承認を必要とし、self-reviewを禁止する。
対象refはtag `v*`だけに限定し、repository administratorのbypassは許可する。
Environment secretは登録しない。

## ローカルでのpackage生成確認

GitHub Releaseから通常archive、checksum、query smoke、cross-language smoke、
MCP smokeの25ファイルを`release-assets/`へ取得する。
compiler packやaggregate reportはこのdirectoryへ混ぜない。

```sh
cargo xtask verify-release-assets release-assets
node npm/scripts/build-packages.mjs \
  --release-assets release-assets \
  --output npm-dist
jq . npm-dist/npm-package-set.json
```

出力directoryは処理開始時に存在してはならない。
生成器は既存directoryを削除または上書きしない。
確認後は各tarballについて`name`、`version`、`integrity`、`sha256`、file count、
unpacked sizeをinventoryと照合する。

host向けnative tarballとroot tarballを同時にtemporary projectへ導入し、
lifecycle scriptなしで起動できることを確認する。

```sh
npm install \
  --ignore-scripts \
  --no-audit \
  --no-fund \
  ./npm-dist/tamat-llc-depgraph-linux-x64-gnu-VERSION.tgz \
  ./npm-dist/tamat-llc-depgraph-VERSION.tgz
./node_modules/.bin/depgraph --version
./node_modules/.bin/depgraph-mcp --version
```

## 初回bootstrap

npmは存在しないpackageへTrusted Publisherを設定できない。
初回だけ、2FAを有効にしたowner accountで6 packageの
`0.0.0-bootstrap.0`を`bootstrap` dist-tagへ対話的に公開する。
各bootstrap packageに含めるのは`package.json`、`README.md`、2種類のlicenseだけ
とし、`bin`、`scripts`、`dependencies`、`optionalDependencies`は定義しない。
名前、repository、license、公開範囲はstable packageと一致させる。
package名はすべて`@tamat-llc` scopeに置き、`--access public`を明示する。
長期tokenやGitHub Actions secretは作成しない。

次の生成器は既存の出力directoryを上書きせず、6つのpackageとSHA-256付き
inventoryを作成する。

```sh
node npm/scripts/build-bootstrap-packages.mjs --output npm-bootstrap
jq . npm-bootstrap/npm-bootstrap-set.json
```

公開前にinventory、各tarballのfile list、package metadataを確認する。
inventory順に`bootstrap` tagへ公開し、root packageは最後にする。

```sh
npx --yes npm@11.15.0 publish \
  ./npm-bootstrap/PACKAGE_TARBALL \
  --access public \
  --tag bootstrap
```

公開後は次の値を6 packageすべてで確認する。

```sh
npm view PACKAGE_NAME@0.0.0-bootstrap.0 \
  name version dist-tags repository.url --json
```

npm registryは`--tag bootstrap`を指定しても、初回versionだけのpackageへ
`latest`を追加する場合がある。
この状態で`latest`の削除が拒否された場合、versionをunpublishしない。
代わりにexact bootstrap versionを直ちにdeprecateする。

```sh
npx --yes npm@11.15.0 deprecate \
  'PACKAGE_NAME@0.0.0-bootstrap.0' \
  'Bootstrap placeholder only; install a supported stable version after it is published.'
```

最初のsupported stable versionをOIDCで公開するとき、workflowの`latest`指定が
bootstrap versionからstable versionへtagを移す。
5つのnative packageがすべて存在するまでroot packageを公開しない。

初回公開直後、npm CLI 11.15.0以降で各packageへ同じtrustを設定する。

```sh
npm trust github PACKAGE_NAME \
  --file npm-release.yml \
  --repo TamaT-LLC/depgraph-cli \
  --env npm \
  --allow-publish \
  --yes
```

6 packageすべてについて設定し、`npm trust list PACKAGE_NAME`でrepository、
workflow、environment、permissionを確認する。
`tamat-llc:developers` teamが6 packageへread-write accessを持つことも確認する。

```sh
npm access list packages tamat-llc:developers
```

その後、npmのpackage settingsでtraditional token publicationを禁止する。
同じ作業時間内に、通常の公開フローから最初のsupported stable versionをOIDCで
公開する。
これにより、利用者が導入する最初のstable versionにもnpm provenanceが付く。

新規packageが`Package name triggered spam detection`で拒否された場合、別名や
metadata変更による回避を試みない。
成功済みpackageのintegrityを照合し、bootstrap versionをdeprecateしてTrusted
Publisherを設定したうえで、未作成package名をnpm Supportへ解除依頼する。
5つのnative packageが揃うまでroot packageは未公開のまま維持する。

## 旧unscoped bootstrap package

組織所有を決定する前に、次の4 packageへbootstrap versionを公開した。

- `depgraph-cli-darwin-arm64`
- `depgraph-cli-darwin-x64`
- `depgraph-cli-linux-arm64-gnu`
- `depgraph-cli-linux-x64-gnu`

これらのpackageへstable versionは公開しない。
`0.0.0-bootstrap.0`はdeprecatedのまま維持し、案内文をorganization scopeの`@tamat-llc/depgraph`へ向ける。
unscopedのroot packageとWindows packageは公開していないため、新たに予約しない。

## 失敗時

native packageの途中で失敗した場合はroot packageを公開しない。
workflowを再実行すると、公開済みtarballはintegrity一致時だけskipされ、残りから
再開する。
ただし、`npm publish`が成功してregistryの可視化を待っている間は再実行しない。
同じname/versionのintegrityが異なる場合、削除や上書きを試みず、新しいpatch
versionで作り直す。

GitHub Release、tag、native archive、npm tarballは公開後に置き換えない。
誤った`latest` dist-tagだけを修正する場合も、対象versionとpackage-set evidenceを
記録してから独立した管理操作として行う。
