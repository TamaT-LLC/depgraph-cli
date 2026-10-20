#!/usr/bin/env bash
set -euo pipefail
orchestration="$(cd "$(dirname "$0")/.." && pwd)"
source_root="$(realpath "$1")"
work="${RUNNER_TEMP}/depgraph-v071-publication-recovery"
mkdir -p "$work/public" "$work/workflow" "$work/flat" "$work/normal" "$work/compiler" "$work/redownload"
cd "$source_root"
test "$(git rev-parse HEAD)" = "26aacf9b839fd5ba9d824c2efcff2efc7084aec8"
gh release download v0.7.1 --repo TamaT-LLC/depgraph-cli --dir "$work/public"
gh run download 39417728460 --repo TamaT-LLC/depgraph-cli --dir "$work/workflow"
python3 - "$work" <<'PY'
import pathlib,sys,os
w=pathlib.Path(sys.argv[1])
for name in ['release-post-publish-evidence-v0.7.1.json','release-recovery-evidence-v0.7.1.json']:
 p=w/'public'/name
 if p.exists():p.rename(w/('existing-'+name))
public={p.name:p for p in (w/'public').iterdir() if p.is_file()}
assert len(public)==42
for p in (w/'workflow').rglob('*'):
 if p.is_file() and p.name in public:
  target=w/'flat'/p.name
  if target.exists():assert target.read_bytes()==p.read_bytes()
  else:os.link(p,target)
assert {p.name for p in (w/'flat').iterdir()}==set(public)
normal=[p for n,p in public.items() if n.startswith('depgraph-0.7.1-')]
compiler=[p for n,p in public.items() if n.startswith('depgraph-compiler-pack-0.7.1-')]
assert len(normal)==20 and len(compiler)==16
for directory,files in [('normal',normal),('compiler',compiler)]:
 for p in files:os.link(p,w/directory/p.name)
PY
cargo xtask verify-release-assets "$work/normal"
cargo xtask verify-compiler-pack-assets "$work/compiler"
RECOVERY_WORK="$work" node --input-type=module - <<'JS'
import {readFileSync} from 'node:fs';
import {verifyReport} from './scripts/benchmark-report.mjs';
import {verifyCacheHitReport} from './scripts/cache-hit-benchmark.mjs';
const w=process.env.RECOVERY_WORK, source='26aacf9b839fd5ba9d824c2efcff2efc7084aec8';
verifyReport(JSON.parse(readFileSync(`${w}/public/benchmark-report.json`)),source);
verifyCacheHitReport(JSON.parse(readFileSync(`${w}/public/cache-hit-benchmark-report.json`)),source);
JS
cmp "$work/normal/release-verification.json" "$work/public/release-verification.json"
cmp "$work/compiler/compiler-pack-verification.json" "$work/public/compiler-pack-verification.json"
gh run view 39417632590 --repo TamaT-LLC/depgraph-cli --json databaseId,headSha,headBranch,conclusion,event,url,jobs \
 | jq '{database_id:.databaseId,head_sha:.headSha,head_branch:.headBranch,event,conclusion,url,jobs:[.jobs[]|{name,conclusion}]}' > "$work/full-ci.json"
evidence="$work/release-post-publish-evidence-v0.7.1.json"
cargo xtask release-post-publish-evidence "$work/flat" "$work/public" "$work/full-ci.json" \
 --tag v0.7.1 --source-sha 26aacf9b839fd5ba9d824c2efcff2efc7084aec8 \
 --source-tree 2f90e406026c34e176c265d28cf7007b72d24d31 \
 --tag-object-sha f645898c08eac1b032362277dcb2f51c5fb85c1f --tag-signature-verification unknown_key \
 --release-run-id 39417728460 --release-run-url https://github.com/TamaT-LLC/depgraph-cli/actions/runs/39417728460 --output "$evidence"
if [[ -f "$work/existing-release-post-publish-evidence-v0.7.1.json" ]]; then
 cmp "$evidence" "$work/existing-release-post-publish-evidence-v0.7.1.json"
else
 gh release upload v0.7.1 "$evidence" --repo TamaT-LLC/depgraph-cli
fi
gh release download v0.7.1 --repo TamaT-LLC/depgraph-cli --pattern release-post-publish-evidence-v0.7.1.json --dir "$work/redownload"
cmp "$evidence" "$work/redownload/release-post-publish-evidence-v0.7.1.json"
trusted="$(gh api repos/TamaT-LLC/depgraph-cli/releases/tags/v0.7.1 --jq '.assets[]|select(.name=="release-post-publish-evidence-v0.7.1.json")|.digest|ltrimstr("sha256:")')"
scripts/release-post-publish-canary.sh v0.7.1 "$work/public" "$evidence" "$trusted" workers/web/test/fixtures/polyglot "$work/canary"
proof="$work/release-recovery-evidence-v0.7.1.json"
python3 "$orchestration/scripts/verify-v071-recovery.py" record "$proof"
if [[ -f "$work/existing-release-recovery-evidence-v0.7.1.json" ]]; then
 cmp "$proof" "$work/existing-release-recovery-evidence-v0.7.1.json"
else
 gh release upload v0.7.1 "$proof" --repo TamaT-LLC/depgraph-cli
fi
