#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fixture_parent="$(mktemp -d)"
cache="$(mktemp -d)"
raw="$(mktemp -d)"
fixture="$fixture_parent/fixture"
binary="$root/target/release/depgraph"
daemon_pid=""
incremental_store=""

cleanup() {
  if [[ -n "$daemon_pid" ]] && kill -0 "$daemon_pid" 2>/dev/null; then
    "$binary" --store "$incremental_store" daemon stop "$fixture" --json >/dev/null 2>&1 || true
    wait "$daemon_pid" 2>/dev/null || true
  fi
  if [[ "${DEPGRAPH_BENCH_KEEP_TEMP:-0}" == "1" ]]; then
    printf 'benchmark temporary fixture: %s\n' "$fixture_parent" >&2
    printf 'benchmark temporary cache: %s\n' "$cache" >&2
    printf 'benchmark temporary raw data: %s\n' "$raw" >&2
    return
  fi
  rm -rf "$fixture_parent" "$cache" "$raw"
}
trap cleanup EXIT INT TERM

file_count="${DEPGRAPH_BENCH_FILES:-10000}"
samples="${DEPGRAPH_BENCH_SAMPLES:-3}"
query_samples="${DEPGRAPH_QUERY_SAMPLES:-5}"
incremental_timeout_seconds="${DEPGRAPH_INCREMENTAL_TIMEOUT_SECONDS:-120}"
report="${DEPGRAPH_BENCH_REPORT:-$root/dist/benchmark-report.json}"
if ((file_count < 2 || file_count > 100000)); then
  echo "DEPGRAPH_BENCH_FILES must be between 2 and 100000" >&2
  exit 2
fi
if ((samples < 3 || samples > 20)); then
  echo "DEPGRAPH_BENCH_SAMPLES must be between 3 and 20" >&2
  exit 2
fi
if ((query_samples < 3 || query_samples > 50)); then
  echo "DEPGRAPH_QUERY_SAMPLES must be between 3 and 50" >&2
  exit 2
fi
if ((incremental_timeout_seconds < 1 || incremental_timeout_seconds > 600)); then
  echo "DEPGRAPH_INCREMENTAL_TIMEOUT_SECONDS must be between 1 and 600" >&2
  exit 2
fi
incremental_poll_limit="$((incremental_timeout_seconds * 20))"

cd "$root"
node scripts/benchmark-fixture.mjs generate "$fixture" "$file_count" > "$raw/fixture.json"
cargo xtask build --release

now_ms() {
  node -e 'process.stdout.write(String(Date.now()))'
}

measure_silent() {
  local destination="$1"
  shift
  local started finished
  started="$(now_ms)"
  "$@" >/dev/null
  finished="$(now_ms)"
  printf '%d\n' "$((finished - started))" >> "$destination"
}

measure_capture() {
  local destination="$1"
  local output="$2"
  shift 2
  local started finished
  started="$(now_ms)"
  "$@" > "$output"
  finished="$(now_ms)"
  printf '%d\n' "$((finished - started))" >> "$destination"
}

initial_stores=()
for ((sample = 0; sample < samples; sample++)); do
  store="$cache/initial-$sample.db"
  initial_stores+=("$store")
  started="$(now_ms)"
  "$binary" --store "$store" scan "$fixture" --json > "$raw/initial-scan-$sample.json"
  finished="$(now_ms)"
  printf '%d\n' "$((finished - started))" >> "$raw/initial-scan-ms.txt"
done

changed_file="$(node -e '
const fs = require("node:fs");
const manifest = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
process.stdout.write(manifest.changed_file);
' "$fixture/depgraph-benchmark-fixture-v1.json")"
impact_file="$(node -e '
const fs = require("node:fs");
const manifest = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
process.stdout.write(manifest.impact_file);
' "$fixture/depgraph-benchmark-fixture-v1.json")"

# Use separate completed stores so each cold measurement is the first query
# process for that store. Warm measurements follow a priming query.
file_query_store="${initial_stores[0]}"
package_query_store="${initial_stores[1]}"
incremental_store="${initial_stores[2]}"
measure_capture \
  "$raw/cold-file-impact-ms.txt" "$raw/cold-file-impact.json" \
  "$binary" --store "$file_query_store" impact "path:$impact_file" --json
for ((sample = 0; sample < query_samples; sample++)); do
  measure_silent \
    "$raw/warm-file-impact-ms.txt" \
    "$binary" --store "$file_query_store" impact "path:$impact_file" --json
done
measure_capture \
  "$raw/cold-package-impact-ms.txt" "$raw/cold-package-impact.json" \
  "$binary" --store "$package_query_store" impact package:depgraph-benchmark --json
for ((sample = 0; sample < query_samples; sample++)); do
  measure_silent \
    "$raw/warm-package-impact-ms.txt" \
    "$binary" --store "$package_query_store" impact package:depgraph-benchmark --json
done

# Exercise the bounded query planner and executor against the complete
# 10,000-file graph. One exact source plus an absent open-vocabulary edge kind
# proves complete zero-result execution inside the hard work budget; the
# depth-eight real-edge variant proves that the same graph rejects hostile work
# before traversal even with LIMIT 1.
"$binary" --store "$file_query_store" export --format json \
  > "$raw/bounded-query-graph.json"
bounded_query_source="$(node -e '
  const fs = require("node:fs");
  const graph = JSON.parse(fs.readFileSync(process.argv[1], "utf8")).graph;
  const source = graph.nodes.find(
    (node) => node.kind === "file" && node.properties?.path === "src/f00000.ts",
  );
  if (!source?.id) process.exit(1);
  process.stdout.write(source.id);
' "$raw/bounded-query-graph.json")"
bounded_query="MATCH p = (source:\"file\")-[\"__depgraph_benchmark_missing_v1__\"*1..1]->(target:\"file\") WHERE source.id = \"$bounded_query_source\" RETURN source.id, target.id, p.id ORDER BY source.id, target.id, p.id ASC LIMIT 1"
measure_capture \
  "$raw/bounded-query-plan-ms.txt" "$raw/bounded-query-plan.json" \
  "$binary" --store "$file_query_store" query --query "$bounded_query" --explain --json
for ((sample = 1; sample < query_samples; sample++)); do
  measure_silent \
    "$raw/bounded-query-plan-ms.txt" \
    "$binary" --store "$file_query_store" query --query "$bounded_query" --explain --json
done
measure_capture \
  "$raw/bounded-query-execute-ms.txt" "$raw/bounded-query-result.json" \
  "$binary" --store "$file_query_store" query --query "$bounded_query" --json
for ((sample = 1; sample < query_samples; sample++)); do
  measure_silent \
    "$raw/bounded-query-execute-ms.txt" \
    "$binary" --store "$file_query_store" query --query "$bounded_query" --json
done
hostile_query='MATCH p = (source:"file")-["imports"*1..8]->(target:"file") RETURN target.id LIMIT 1'
set +e
"$binary" --store "$file_query_store" query --query "$hostile_query" --explain --json \
  > "$raw/bounded-query-hostile-plan.json"
hostile_status="$?"
set -e
if [[ "$hostile_status" -ne 1 ]]; then
  echo "hostile bounded query plan must be rejected with exit 1" >&2
  exit 1
fi

"$binary" --store "$incremental_store" export --format json \
  > "$raw/graph-before.json"

"$binary" --store "$incremental_store" daemon start "$fixture" --json \
  > "$raw/daemon-final.json" 2> "$raw/daemon.log" &
daemon_pid="$!"

current_status="$raw/daemon-status-current.json"
wait_for_idle() {
  for ((poll = 0; poll < incremental_poll_limit; poll++)); do
    if ! kill -0 "$daemon_pid" 2>/dev/null; then
      echo "benchmark daemon exited before becoming idle" >&2
      wait "$daemon_pid" || true
      exit 1
    fi
    if "$binary" --store "$incremental_store" daemon status "$fixture" --json \
      > "$current_status" 2>/dev/null \
      && node -e '
        const fs = require("node:fs");
        const status = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
        process.exit(status.phase === "idle" ? 0 : 1);
      ' "$current_status"; then
      return
    fi
    sleep 0.05
  done
  echo "benchmark daemon did not become idle within $incremental_timeout_seconds seconds" >&2
  exit 1
}

wait_for_attempt() {
  local previous_attempt="$1"
  local destination="$2"
  for ((poll = 0; poll < incremental_poll_limit; poll++)); do
    if ! kill -0 "$daemon_pid" 2>/dev/null; then
      echo "benchmark daemon exited during an incremental sample" >&2
      wait "$daemon_pid" || true
      exit 1
    fi
    if "$binary" --store "$incremental_store" daemon status "$fixture" --json \
      > "$current_status" 2>/dev/null \
      && node -e '
        const fs = require("node:fs");
        const status = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
        const previous = process.argv[2];
        const changed = process.argv[3];
        const attempt = status.last_completed_attempt;
        // FSEvents may classify an in-place write as Create. Graph conservation
        // proves that this exact path existed before its content hash changed.
        const matched = attempt
          && attempt.attempt_id !== previous
          && attempt.status === "completed"
          && attempt.changes?.length === 1
          && ["added", "modified"].includes(attempt.changes[0].kind)
          && attempt.changes[0].new_path === changed;
        process.exit(matched ? 0 : 1);
      ' "$current_status" "$previous_attempt" "$changed_file"; then
      cp "$current_status" "$destination"
      return
    fi
    sleep 0.05
  done
  echo "incremental benchmark sample did not complete within $incremental_timeout_seconds seconds" >&2
  if [[ -f "$current_status" ]]; then
    cat "$current_status" >&2
  fi
  exit 1
}

wait_for_idle
for ((sample = 0; sample < samples; sample++)); do
  previous_attempt="$(node -e '
    const fs = require("node:fs");
    const status = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
    process.stdout.write(status.last_completed_attempt?.attempt_id ?? "");
  ' "$current_status")"
  started="$(now_ms)"
  node scripts/benchmark-fixture.mjs mutate "$fixture" "$sample" >/dev/null
  wait_for_attempt "$previous_attempt" "$raw/incremental-status-$sample.json"
  finished="$(now_ms)"
  printf '%d\n' "$((finished - started))" >> "$raw/incremental-scan-ms.txt"
  wait_for_idle
done

"$binary" --store "$incremental_store" export --format json \
  > "$raw/graph-after.json"
"$binary" --store "$incremental_store" daemon stop "$fixture" --json \
  > "$raw/daemon-stopped.json"
wait "$daemon_pid"
daemon_pid=""
node scripts/benchmark-fixture.mjs restore "$fixture" >/dev/null

rust_store="$cache/rust.db"
rust_fixture="$root/workers/rust/tests/fixtures/release-semantic"
started="$(now_ms)"
"$binary" --store "$rust_store" scan "$rust_fixture" --json > "$raw/rust-scan.json"
finished="$(now_ms)"
printf '%d\n' "$((finished - started))" > "$raw/rust-scan-ms.txt"
"$binary" --store "$rust_store" export --format json > "$raw/rust-graph.json"
"$binary" --store "$rust_store" cycles --level symbol --json > /dev/null
measure_silent \
  "$raw/rust-query-ms.txt" \
  "$binary" --store "$rust_store" cycles --level symbol --json

build_fixture="$root/workers/web/test/fixtures/polyglot"
build_base_store="$cache/build-base.db"
"$binary" --store "$build_base_store" scan "$build_fixture" --json \
  > "$raw/build-base-scan.json"
started="$(now_ms)"
for app in next-app astro-app start rust-app; do
  build_store="$cache/build-$app.db"
  cp "$build_base_store" "$build_store"
  "$binary" --store "$build_store" resolve --build \
    "$build_fixture/apps/$app" --allow-project-code > /dev/null
  "$binary" --store "$build_store" export --format json \
    > "$raw/build-$app.json"
done
finished="$(now_ms)"
printf '%d\n' "$((finished - started))" > "$raw/build-observation-ms.txt"

DEPGRAPH_BENCH_BINARY="$binary" \
  node scripts/benchmark-report.mjs create "$raw" "$fixture" "$report"
