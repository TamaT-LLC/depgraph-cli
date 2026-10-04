#!/usr/bin/env bash
# Apply a preverified formula through a PR; never execute code from the writable tap checkout.
set -euo pipefail

tag="${1:?stable tag required}"
formula="${2:?verified formula path required}"
dry_run="${3:-true}"
[[ "${tag}" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]
[[ "${dry_run}" == true || "${dry_run}" == false ]]
[[ -f "${formula}" ]]
formula="$(cd "$(dirname "${formula}")" && pwd -P)/$(basename "${formula}")"
grep -Fq "/releases/download/${tag}/" "${formula}"
readonly tap_repository="TamaT-LLC/homebrew-tap"
readonly formula_path="Formula/depgraph.rb"
readonly branch="depgraph-${tag}"
work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT

# Transient Git configuration keeps the App token out of disk configuration and remote URLs.
if [[ -n "${GH_TOKEN:-}" ]]; then
  export GIT_CONFIG_COUNT=1
  export GIT_CONFIG_KEY_0=http.https://github.com/.extraheader
  export GIT_CONFIG_VALUE_0="AUTHORIZATION: basic $(printf 'x-access-token:%s' "${GH_TOKEN}" | base64 | tr -d '\n')"
fi
export GIT_TERMINAL_PROMPT=0

git clone --quiet --branch main --single-branch "https://github.com/${tap_repository}.git" "${work}/tap"
cd "${work}/tap"
test -f "${formula_path}"
current_version="$(sed -n 's|.*releases/download/v\([0-9.]*\)/.*|\1|p' "${formula_path}" | sort -u)"
python3 - "${current_version}" "${tag#v}" <<'PY'
import sys
current, requested = (tuple(map(int, v.split('.'))) for v in sys.argv[1:])
if current > requested:
    raise SystemExit('refusing to downgrade the tap')
PY
if cmp -s "${formula_path}" "${formula}"; then
  echo "depgraph ${tag} already matches the tap; no PR needed."
  exit 0
fi
if [[ "${current_version}" == "${tag#v}" ]]; then
  echo "error: existing same-version formula differs; manual review required" >&2
  exit 1
fi
cp "${formula}" "${formula_path}"
git diff -- "${formula_path}"
if [[ "${dry_run}" == true ]]; then
  echo "Dry run: token/clone succeeded; no push or PR."
  exit 0
fi

# Reuse an existing branch only if it has exactly the expected formula-only change.
if git ls-remote --exit-code --heads origin "refs/heads/${branch}" >/dev/null; then
  git fetch --quiet origin "refs/heads/${branch}:refs/remotes/origin/${branch}"
  git show "origin/${branch}:${formula_path}" > "${work}/existing.rb"
  cmp "${work}/existing.rb" "${formula}"
  test "$(git diff --name-only "origin/main...origin/${branch}")" = "${formula_path}"
else
  git switch --quiet -c "${branch}"
  bot_id="$(gh api 'users/tamat-homebrew-tap[bot]' --jq .id)"
  [[ "${bot_id}" =~ ^[1-9][0-9]*$ ]]
  git add -- "${formula_path}"
  git -c user.name='tamat-homebrew-tap[bot]' \
    -c "user.email=${bot_id}+tamat-homebrew-tap[bot]@users.noreply.github.com" \
    commit --quiet -m "depgraph ${tag#v}"
  test "$(git diff --name-only origin/main...HEAD)" = "${formula_path}"
  git push --quiet origin "HEAD:refs/heads/${branch}"
fi
pr_url="$(gh pr list --repo "${tap_repository}" --base main --head "${branch}" --state open \
  --json url --jq '.[0].url // empty')"
if [[ -z "${pr_url}" ]]; then
  cat > "${work}/body.md" <<BODY
Update depgraph to [${tag}](https://github.com/TamaT-LLC/depgraph-cli/releases/tag/${tag}).

The formula was generated only after verifying the signed stable tag, successful full CI/Release,
public post-publish evidence, and the archive/checksum identities for all four Homebrew targets.
The tap CI verifies the formula again and tests installation and worker integrity.
BODY
  pr_url="$(gh pr create --repo "${tap_repository}" --base main --head "${branch}" \
    --title "depgraph ${tag#v}" --body-file "${work}/body.md")"
fi
# Human merges the verified PR; automatic merge waits for all platform checks to become required.
echo "${pr_url}"
