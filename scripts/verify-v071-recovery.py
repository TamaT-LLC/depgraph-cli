#!/usr/bin/env python3
"""Record/verify the one-time owner-authorized immutable v0.7.1 recovery."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

REPO = 'TamaT-LLC/depgraph-cli'
TAG = 'v0.7.1'
SOURCE = '26aacf9b839fd5ba9d824c2efcff2efc7084aec8'
TREE = '2f90e406026c34e176c265d28cf7007b72d24d31'
TAG_OBJECT = 'f645898c08eac1b032362277dcb2f51c5fb85c1f'
ORIGINAL = 39417728460
FULL_CI = 39417632590
EVIDENCE = 'release-post-publish-evidence-v0.7.1.json'
CERTIFICATE = 'release-recovery-evidence-v0.7.1.json'
WORKFLOW = '.github/workflows/release-v071-recovery.yml'
OWNER = '全部バイパスしてリリースまでやっていいよ'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def api(path, binary=False):
    args = ['gh', 'api']
    if binary:
        args += ['-H', 'Accept: application/octet-stream']
    data = subprocess.check_output(args + [f'repos/{REPO}/{path}'])
    return data if binary else json.loads(data)


def download(asset):
    data = api(f'releases/assets/{asset["id"]}', True)
    require(len(data) == asset['size'] and 'sha256:' + hashlib.sha256(data).hexdigest() == asset['digest'], 'public asset digest mismatch')
    return data


def inventory(assets):
    result = {a['name']: a for a in assets}
    require(len(result) == len(assets), 'duplicate assets')
    return result


def run_identity(run, name, path, branch, event, sha, conclusion):
    require(run['name'] == name and run['path'] == path and run['head_branch'] == branch and run['event'] == event and run['head_sha'] == sha, 'workflow identity mismatch')
    require(run['repository']['full_name'] == REPO and run['head_repository']['full_name'] == REPO, 'foreign workflow')
    require(run['status'] == 'completed' and run['conclusion'] == conclusion, 'workflow conclusion mismatch')


def public_facts():
    release = api(f'releases/tags/{TAG}')
    require(release['tag_name'] == TAG and not release['draft'] and not release['prerelease'], 'not public stable v0.7.1')
    assets = inventory(release['assets'])
    ref = api(f'git/ref/tags/{TAG}')
    require(ref['object']['type'] == 'tag' and ref['object']['sha'] == TAG_OBJECT, 'signed tag changed')
    tag = api(f'git/tags/{TAG_OBJECT}')
    require(tag['object']['type'] == 'commit' and tag['object']['sha'] == SOURCE and tag['verification']['signature'] and tag['verification']['reason'] in ('valid', 'unknown_key', 'unverified_email'), 'tag source/signature changed')
    require(api(f'git/commits/{SOURCE}')['tree']['sha'] == TREE, 'source tree changed')
    original = api(f'actions/runs/{ORIGINAL}')
    run_identity(original, 'Release', '.github/workflows/release.yml', TAG, 'push', SOURCE, 'failure')
    jobs = api(f'actions/runs/{ORIGINAL}/jobs?per_page=100')['jobs']
    require(sum(j['conclusion'] == 'success' for j in jobs) == 14 and [j['name'] for j in jobs if j['conclusion'] == 'failure'] == ['publish'], 'original artifact gates changed')
    ci = api(f'actions/runs/{FULL_CI}')
    run_identity(ci, 'CI', '.github/workflows/ci.yml', 'main', 'workflow_dispatch', SOURCE, 'success')
    ci_jobs = api(f'actions/runs/{FULL_CI}/jobs?per_page=100')['jobs']
    require(len(ci_jobs) == 10 and all(j['conclusion'] == 'success' for j in ci_jobs), 'exact Full CI incomplete')
    evidence = json.loads(download(assets[EVIDENCE]))
    require(evidence['schema_version'] == 'release-post-publish-evidence-v1' and evidence['repository'] == REPO and evidence['tag'] == TAG and evidence['release_version'] == '0.7.1' and evidence['decision'] == 'allow', 'invalid publication evidence')
    require(evidence['candidate']['commit'] == SOURCE and evidence['candidate']['tree'] == TREE and evidence['candidate']['tag_object'] == TAG_OBJECT and evidence['full_ci']['run_id'] == FULL_CI and evidence['full_ci']['head_sha'] == SOURCE and evidence['release_workflow']['run_id'] == ORIGINAL and evidence['release_workflow']['head_sha'] == SOURCE, 'evidence identity mismatch')
    require(evidence['workflow_public_asset_identity'] is True and evidence['public_download_reverified'] is True, 'public bytes not verified')
    closure = {n: a for n, a in assets.items() if n not in (EVIDENCE, CERTIFICATE)}
    require(len(closure) == len(evidence['assets']) == 42 and {a['name'] for a in evidence['assets']} == set(closure), 'public closure changed')
    for claim in evidence['assets']:
        actual = closure[claim['name']]
        require(actual['size'] == claim['bytes'] and actual['digest'] == 'sha256:' + claim['sha256'], 'public inventory changed')
    return release, assets


def verify():
    release, assets = public_facts()
    require(len(assets) == 44, 'recovery closure must contain 44 assets')
    proof = json.loads(download(assets[CERTIFICATE]))
    require(proof['schema_version'] == 'depgraph-v071-publication-recovery-v1' and proof['repository'] == REPO and proof['tag'] == TAG and proof['decision'] == 'allow', 'invalid recovery proof')
    require(proof['source'] == {'commit': SOURCE, 'tree': TREE, 'tag_object': TAG_OBJECT} and proof['original_release_run'] == ORIGINAL and proof['original_release_conclusion'] == 'failure' and proof['full_ci_run'] == FULL_CI, 'recovery source mismatch')
    require(proof['owner_instruction'] == OWNER and proof['checks'] == {'workflow_public_asset_identity': True, 'public_download_reverified': True, 'agent_host_canary': True, 'post_publish_native_onboarding': 'owner-waived'}, 'recovery checks/waiver changed')
    recovery = api(f'actions/runs/{proof["recovery_workflow"]["run_id"]}')
    run_identity(recovery, 'v0.7.1 publication recovery', WORKFLOW, 'main', 'workflow_dispatch', proof['recovery_workflow']['head_sha'], 'success')
    expected = [{'name': a['name'], 'bytes': a['size'], 'sha256': a['digest'].removeprefix('sha256:')} for a in sorted(assets.values(), key=lambda a: a['name']) if a['name'] != CERTIFICATE]
    require(proof['assets'] == expected, 'recovered public inventory changed')
    print(f'verified immutable {TAG} recovery run {recovery["id"]}; original failure retained')
    if os.environ.get('GITHUB_OUTPUT'):
        with open(os.environ['GITHUB_OUTPUT'], 'a') as output:
            output.write(f'release_tag={TAG}\nrelease_version=0.7.1\nrelease_source_sha={SOURCE}\n')
    return proof


def record(path):
    require(os.environ.get('GITHUB_REPOSITORY') == REPO and os.environ.get('GITHUB_REF') == 'refs/heads/main' and os.environ.get('GITHUB_WORKFLOW') == 'v0.7.1 publication recovery', 'record only in canonical recovery workflow')
    release, assets = public_facts()
    entries = [{'name': a['name'], 'bytes': a['size'], 'sha256': a['digest'].removeprefix('sha256:')} for a in sorted(assets.values(), key=lambda a: a['name']) if a['name'] != CERTIFICATE]
    require(len(entries) == 43, 'expected 42 unchanged assets and new evidence')
    proof = {'schema_version': 'depgraph-v071-publication-recovery-v1', 'repository': REPO, 'tag': TAG, 'decision': 'allow', 'source': {'commit': SOURCE, 'tree': TREE, 'tag_object': TAG_OBJECT}, 'original_release_run': ORIGINAL, 'original_release_conclusion': 'failure', 'full_ci_run': FULL_CI, 'owner_instruction': OWNER, 'reason': 'Original publication uploaded 42 verified assets, then stopped at a leftover version==0.7.0 assertion. Original failure, tag and assets are preserved.', 'checks': {'workflow_public_asset_identity': True, 'public_download_reverified': True, 'agent_host_canary': True, 'post_publish_native_onboarding': 'owner-waived'}, 'recovery_workflow': {'run_id': int(os.environ['GITHUB_RUN_ID']), 'head_sha': os.environ['GITHUB_SHA'], 'path': WORKFLOW}, 'assets': entries}
    Path(path).write_text(json.dumps(proof, ensure_ascii=False, indent=2) + '\n')


if __name__ == '__main__':
    if sys.argv[1:] == ['verify']:
        verify()
    elif len(sys.argv) == 3 and sys.argv[1] == 'record':
        record(sys.argv[2])
    else:
        raise SystemExit('usage: verify-v071-recovery.py verify | record <output>')
