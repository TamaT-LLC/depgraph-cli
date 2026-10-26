#!/usr/bin/env bash
# Decide whether a pull request touches anything the Go or Web CI job checks.
#
#   ci-affected-scope.sh classify <go|web>   reads changed paths on stdin and
#                                            prints true (run) or false (skip)
#   ci-affected-scope.sh decide <go|web>     diffs the pull request and appends
#                                            run=<true|false> to $GITHUB_OUTPUT
#
# The decision fails closed. A path that matches a force pattern, or that no
# ignore pattern covers, makes the job run; the job is skipped only when every
# changed path is on that job's reviewed ignore list. An empty change list, a
# malformed or unreachable base/head, a failed diff, and every event other than
# pull_request also make the job run. The pattern arrays are pinned verbatim by
# `cargo xtask test` (xtask/src/project_metadata.rs), so widening what a job may
# skip requires a reviewed xtask change as well.
#
# The script must run under the bash 3.2 that macOS ships: it avoids empty
# arrays under `set -u` and the `(^|/)` ERE group. Matches read here-strings,
# never pipes: `grep -q` may exit before a writer finishes, and the writer's
# SIGPIPE under pipefail would turn a match into a miss.
set -euo pipefail

# Paths that every gated job must re-check: the workflow and its policy, the
# Rust toolchain and lockfile inputs, the shared xtask driver, and these scripts.
force_all=(
  '^\.github/workflows/'
  '^\.github/actions-policy\.json$'
  '^Cargo\.(toml|lock)$'
  '/Cargo\.(toml|lock)$'
  '^rust-toolchain\.toml$'
  '^\.cargo/'
  '^\.config/'
  '^\.gitattributes$'
  '^workspace-hack/'
  '^xtask/'
  '^scripts/'
)

# Documentation and repository metadata that no Go or Web check reads.
common_ignore=(
  '^docs/'
  '^[^/]+\.md$'
  '^docs\.config\.toml$'
  '^\.github/ISSUE_TEMPLATE/'
  '^\.github/PULL_REQUEST_TEMPLATE\.md$'
  '^\.github/CODEOWNERS$'
  '^\.cursor/'
  '^security/'
)

# The Go worker tests compare against this shared golden fixture.
go_force=(
  '^crates/depgraph-core/tests/fixtures/health/'
)

go_ignore=(
  '^workers/web/'
  '^workers/rust/'
  '^crates/'
  '^npm/'
  '^schemas/'
  '^queries/'
  '^fixtures/'
  '^third_party/'
  '^LICENSE-(APACHE|MIT)$'
)

# The Web job builds depgraph-cli and depgraph-core, which never depend on
# these crates; depgraph-agent-contract is a depgraph-cli dependency and stays.
web_ignore=(
  '^workers/rust/'
  '^crates/depgraph-mcp/'
  '^crates/depgraph-rustc-wrapper/'
  '^crates/depgraph-rustc-query/'
  '^npm/'
)

usage() {
  echo "usage: $0 <decide|classify> <go|web>" >&2
  exit 2
}

matches_any() {
  local path="$1" pattern
  shift
  for pattern in "$@"; do
    if grep -Eq -- "$pattern" <<<"$path"; then
      return 0
    fi
  done
  return 1
}

is_forced() {
  local job="$1" path="$2"
  if matches_any "$path" "${force_all[@]}"; then
    return 0
  fi
  if [ "$job" = go ] && matches_any "$path" "${go_force[@]}"; then
    return 0
  fi
  return 1
}

is_ignored() {
  local job="$1" path="$2"
  if matches_any "$path" "${common_ignore[@]}"; then
    return 0
  fi
  case "$job" in
    go) matches_any "$path" "${go_ignore[@]}" ;;
    web) matches_any "$path" "${web_ignore[@]}" ;;
    *) return 1 ;;
  esac
}

classify() {
  local job="$1" path seen=false
  while IFS= read -r path || [ -n "$path" ]; do
    if [ -z "$path" ]; then
      continue
    fi
    seen=true
    if is_forced "$job" "$path"; then
      echo "ci-affected-scope: $job must run: $path is a shared input" >&2
      echo true
      return 0
    fi
    if is_ignored "$job" "$path"; then
      continue
    fi
    echo "ci-affected-scope: $job must run: $path is not on the $job ignore list" >&2
    echo true
    return 0
  done
  if [ "$seen" = false ]; then
    echo "ci-affected-scope: $job must run: the change list is empty" >&2
    echo true
    return 0
  fi
  echo "ci-affected-scope: $job may skip: every changed path is on the $job ignore list" >&2
  echo false
}

is_commit_sha() {
  grep -Eq '^[0-9a-f]{40}$' <<<"$1"
}

decide() {
  local job="$1" run changed
  case "${CI_EVENT_NAME:-}" in
    pull_request)
      if ! is_commit_sha "${CI_BASE_SHA:-}" || ! is_commit_sha "${CI_HEAD_SHA:-}"; then
        echo "ci-affected-scope: $job must run: base or head SHA is malformed" >&2
        run=true
      # Without --no-renames, a file moved out of a checked directory would
      # be listed only under its new (possibly ignored) path.
      elif ! changed="$(git diff --no-renames --name-only "$CI_BASE_SHA" "$CI_HEAD_SHA")"; then
        echo "ci-affected-scope: $job must run: git diff failed" >&2
        run=true
      else
        # A here-string instead of a pipe: classify may stop reading early,
        # and a SIGPIPE under pipefail would fail the step.
        run="$(classify "$job" <<<"$changed")"
      fi
      ;;
    *) run=true ;;
  esac
  printf 'run=%s\n' "$run" >>"${GITHUB_OUTPUT:?GITHUB_OUTPUT must name the step output file}"
}

if [ "$#" -ne 2 ]; then
  usage
fi
case "$2" in
  go | web) ;;
  *) usage ;;
esac
case "$1" in
  classify) classify "$2" ;;
  decide) decide "$2" ;;
  *) usage ;;
esac
