#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -ne 0 ]]; then
  echo "v0.5.0 post-publish recovery accepts no mutable inputs" >&2
  exit 2
fi

readonly expected_repository="TamaT-LLC/depgraph-cli"
readonly release_tag="v0.5.0"
readonly source_sha="f1071178d3888503b6e02d4aec5e058f0b87d035"
readonly source_tree="2e1825dda4493acf581dbad9ef66f8f3a44bb734"
readonly tag_object_sha="dd81d5f108fb8fc3db1afcad62d422c9d9c34415"
readonly release_run_id="31928961757"
readonly full_ci_run_id="31923533506"
readonly evidence_name="release-post-publish-evidence-v0.5.0.json"
readonly evidence_sha256="13e253b3759a9729f43ff8dbe6f6a48191770681b02a57cb5197bc908ab77524"
readonly original_job_set_sha256="ee353899c59140ef067ec521023163a5acd81ff5e57acda3f33d64e9c239a443"

for command in gh git jq realpath sha256sum; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "v0.5.0 post-publish recovery requires $command" >&2
    exit 1
  fi
done
if [[ "${GITHUB_REPOSITORY:-}" != "$expected_repository" || "${GITHUB_REF:-}" != "refs/heads/main" ]]; then
  echo "v0.5.0 post-publish recovery must run from the canonical main branch" >&2
  exit 1
fi
if [[ ! "${GITHUB_SHA:-}" =~ ^[0-9a-f]{40}$ || -z "${GH_TOKEN:-}" ]]; then
  echo "v0.5.0 post-publish recovery requires canonical GitHub Actions identity" >&2
  exit 1
fi
if [[ ! "${RUNNER_TEMP:-}" = /* || -L "${RUNNER_TEMP}" ]]; then
  echo "v0.5.0 post-publish recovery requires an absolute non-symlink runner temp" >&2
  exit 1
fi

workspace_root="$(git rev-parse --show-toplevel)"
workspace_root="$(realpath "$workspace_root")"
recovery_root="${RUNNER_TEMP}/depgraph-v0.5.0-post-publish-recovery"
if [[ -e "$recovery_root" ]]; then
  echo "v0.5.0 post-publish recovery directory must start absent" >&2
  exit 1
fi
mkdir -p "$recovery_root/public"
public_root="$(realpath "$recovery_root/public")"

main_head="$(gh api "repos/${expected_repository}/git/ref/heads/main" --jq '.object.sha')"
maintenance_head="$(gh api "repos/${expected_repository}/git/ref/heads/release/0.5" --jq '.object.sha')"
test "$main_head" = "$GITHUB_SHA"
test "$maintenance_head" = "$source_sha"
gh api "repos/${expected_repository}/compare/${source_sha}...${GITHUB_SHA}" \
  > "$recovery_root/source-descendant.json"
jq -e --arg source "$source_sha" '
  (.status == "ahead" or .status == "identical") and
  .merge_base_commit.sha == $source
' "$recovery_root/source-descendant.json" >/dev/null

gh api "repos/${expected_repository}/git/ref/tags/${release_tag}" > "$recovery_root/tag-ref.json"
jq -e --arg tag "$release_tag" --arg object "$tag_object_sha" '
  .ref == ("refs/tags/" + $tag) and
  .object.type == "tag" and
  .object.sha == $object
' "$recovery_root/tag-ref.json" >/dev/null
gh api "repos/${expected_repository}/git/tags/${tag_object_sha}" > "$recovery_root/tag-object.json"
jq -e --arg tag "$release_tag" --arg source "$source_sha" '
  .tag == $tag and
  .object.type == "commit" and
  .object.sha == $source and
  (.verification.signature | type == "string" and length > 0) and
  .verification.reason == "unknown_key"
' "$recovery_root/tag-object.json" >/dev/null
test "$(gh api "repos/${expected_repository}/git/commits/${source_sha}" --jq '.tree.sha')" = "$source_tree"

gh api "repos/${expected_repository}/actions/runs/${release_run_id}" \
  > "$recovery_root/original-release-metadata.json"
jq -e \
  --argjson run_id "$release_run_id" \
  --arg source "$source_sha" \
  --arg tag "$release_tag" '
  .id == $run_id and
  .name == "Release" and
  .path == ".github/workflows/release.yml" and
  .event == "push" and
  .head_branch == $tag and
  .head_sha == $source and
  .run_attempt == 1 and
  .status == "completed" and
  .conclusion == "failure"
' "$recovery_root/original-release-metadata.json" >/dev/null
gh run view "$release_run_id" --repo "$expected_repository" \
  --json databaseId,name,workflowName,event,headBranch,headSha,status,conclusion,url,jobs \
  > "$recovery_root/original-release-run.json"
jq -e \
  --argjson run_id "$release_run_id" \
  --arg source "$source_sha" \
  --arg tag "$release_tag" '
  .databaseId == $run_id and
  .name == "Release" and
  .workflowName == "Release" and
  .event == "push" and
  .headBranch == $tag and
  .headSha == $source and
  .status == "completed" and
  .conclusion == "failure" and
  .url == ("https://github.com/TamaT-LLC/depgraph-cli/actions/runs/" + ($run_id | tostring)) and
  (.jobs | length) == 17
' "$recovery_root/original-release-run.json" >/dev/null
actual_job_set_sha256="$(
  jq -c '[.jobs[] | {name,conclusion}] | sort_by(.name)' \
    "$recovery_root/original-release-run.json" | sha256sum | awk '{print $1}'
)"
test "$actual_job_set_sha256" = "$original_job_set_sha256"
jq -e '
  ([.jobs[] | select(.name == "publish")] | length) == 1 and
  ([.jobs[] | select(.name != "publish" and .conclusion != "success")] | length) == 0 and
  ([.jobs[] | select(.name == "publish") | .steps[] |
    select(.name == "Publish verified stable release") | .conclusion] == ["success"]) and
  ([.jobs[] | select(.name == "publish") | .steps[] |
    select(.conclusion == "failure") | .name] ==
    ["Re-download and attest the public release closure"])
' "$recovery_root/original-release-run.json" >/dev/null
gh run view "$release_run_id" --repo "$expected_repository" --log-failed \
  > "$recovery_root/original-release-failure.log"
grep -Fq \
  'Agent host preflight security policy violation: preflight input file paths must be absolute' \
  "$recovery_root/original-release-failure.log"

gh api "repos/${expected_repository}/releases/tags/${release_tag}" > "$recovery_root/release.json"
jq -e --arg tag "$release_tag" --arg evidence "$evidence_name" --arg digest "sha256:${evidence_sha256}" '
  .tag_name == $tag and
  .target_commitish == "main" and
  .draft == false and
  .prerelease == false and
  (.published_at | type == "string" and length > 0) and
  (.assets | length) == 52 and
  ([.assets[] | select(.state != "uploaded" or (.digest | test("^sha256:[0-9a-f]{64}$") | not))] | length) == 0 and
  ([.assets[] | select(.name == $evidence and .digest == $digest and .size == 11965)] | length) == 1
' "$recovery_root/release.json" >/dev/null

readonly archive_name="depgraph-0.5.0-x86_64-unknown-linux-gnu.tar.gz"
readonly checksum_name="${archive_name}.sha256"
readonly compiler_archive_name="depgraph-compiler-pack-0.5.0-x86_64-unknown-linux-gnu.tar.gz"
readonly compiler_checksum_name="${compiler_archive_name}.sha256"
readonly requirement_name="depgraph-compiler-pack-0.5.0-x86_64-unknown-linux-gnu.requirement.json"
for asset in \
  "$evidence_name" \
  "$archive_name" \
  "$checksum_name" \
  "$compiler_archive_name" \
  "$compiler_checksum_name" \
  "$requirement_name"; do
  gh release download "$release_tag" --repo "$expected_repository" \
    --pattern "$asset" --dir "$public_root"
done
test "$(find "$public_root" -maxdepth 1 -type f | wc -l | tr -d ' ')" = "6"
evidence="$(realpath "$public_root/$evidence_name")"
printf '%s  %s\n' "$evidence_sha256" "$evidence" | sha256sum --check --strict --status -

jq -e \
  --arg source "$source_sha" \
  --arg tree "$source_tree" \
  --arg tag_object "$tag_object_sha" \
  --argjson release_run "$release_run_id" \
  --argjson full_ci_run "$full_ci_run_id" '
  .schema_version == "release-post-publish-evidence-v1" and
  .repository == "TamaT-LLC/depgraph-cli" and
  .release_version == "0.5.0" and
  .tag == "v0.5.0" and
  .decision == "allow" and
  .candidate == {
    commit: $source,
    tree: $tree,
    tag_object: $tag_object,
    tag_signature_verification: "unknown_key"
  } and
  .full_ci.run_id == $full_ci_run and
  .release_workflow == {
    run_id: $release_run,
    url: ("https://github.com/TamaT-LLC/depgraph-cli/actions/runs/" + ($release_run | tostring)),
    head_sha: $source
  } and
  .workflow_public_asset_identity == true and
  .public_download_reverified == true and
  (.assets | length) == 51
' "$evidence" >/dev/null
computed_asset_set_sha256="$(
  jq -j '.assets[] | .name, "\u0000", (.bytes | tostring), "\u0000", .sha256, "\n"' \
    "$evidence" | sha256sum | awk '{print $1}'
)"
test "$computed_asset_set_sha256" = "$(jq -r '.asset_set_sha256' "$evidence")"
jq -e --slurpfile evidence "$evidence" --arg evidence_name "$evidence_name" '
  ($evidence[0].assets | sort_by(.name)) ==
  ([.assets[] | select(.name != $evidence_name) |
    {name: .name, bytes: .size, sha256: (.digest | sub("^sha256:"; ""))}] | sort_by(.name))
' "$recovery_root/release.json" >/dev/null
while IFS=$'\t' read -r asset digest; do
  printf '%s  %s\n' "${digest#sha256:}" "$public_root/$asset" \
    | sha256sum --check --strict --status -
done < <(
  jq -r --argjson names "$(printf '%s\n' "$evidence_name" "$archive_name" "$checksum_name" "$compiler_archive_name" "$compiler_checksum_name" "$requirement_name" | jq -Rsc 'split("\n")[:-1]')" '
    .assets[] | select(.name as $name | $names | index($name)) | [.name, .digest] | @tsv
  ' "$recovery_root/release.json"
)

gh run view "$full_ci_run_id" --repo "$expected_repository" \
  --json databaseId,event,headBranch,headSha,status,conclusion,url,jobs \
  > "$recovery_root/full-ci-run.json"
jq -e \
  --argjson run_id "$full_ci_run_id" \
  --arg source "$source_sha" '
  .databaseId == $run_id and
  .event == "workflow_dispatch" and
  .headBranch == "main" and
  .headSha == $source and
  .status == "completed" and
  .conclusion == "success" and
  .url == ("https://github.com/TamaT-LLC/depgraph-cli/actions/runs/" + ($run_id | tostring)) and
  (.jobs | length) == 8 and
  ([.jobs[] | select(.conclusion != "success")] | length) == 0
' "$recovery_root/full-ci-run.json" >/dev/null
jq -S '{
  run_id: .databaseId,
  url,
  head_sha: .headSha,
  head_branch: .headBranch,
  jobs: ([.jobs[] | {name,conclusion}] | sort_by(.name))
}' "$recovery_root/full-ci-run.json" > "$recovery_root/full-ci-normalized.json"
jq -S '.full_ci | .jobs |= sort_by(.name)' "$evidence" > "$recovery_root/evidence-full-ci.json"
cmp --silent "$recovery_root/full-ci-normalized.json" "$recovery_root/evidence-full-ci.json"

"$workspace_root/scripts/release-post-publish-canary.sh" \
  "$release_tag" \
  "$public_root" \
  "$evidence" \
  "$evidence_sha256" \
  "$workspace_root/workers/web/test/fixtures/polyglot" \
  "$recovery_root/canary"

if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
  {
    echo "## v0.5.0 post-publish recovery verified"
    echo
    echo "- Immutable source: \`$source_sha\` (tree \`$source_tree\`)"
    echo "- Original Release run: \`$release_run_id\`; all 16 pre-publish jobs succeeded"
    echo "- Public closure: 51 immutable product assets plus the pinned post-publish evidence"
    echo "- Recovery: published Linux archive Agent host canary passed with absolute inputs"
    echo "- Mutation: none; the tag, Release, and assets were read-only"
  } >> "$GITHUB_STEP_SUMMARY"
fi
