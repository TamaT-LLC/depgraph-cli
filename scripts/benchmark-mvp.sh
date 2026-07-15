#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fixture="$(mktemp -d)"
cache="$(mktemp -d)"
trap 'rm -rf "$fixture" "$cache"' EXIT

file_count="${DEPGRAPH_BENCH_FILES:-10000}"
scan_limit_ms="${DEPGRAPH_SCAN_LIMIT_MS:-30000}"
query_limit_ms="${DEPGRAPH_QUERY_LIMIT_MS:-500}"

mkdir -p "$fixture/src"
printf '{"name":"depgraph-benchmark","private":true,"type":"module"}\n' > "$fixture/package.json"
for ((index = 0; index < file_count; index++)); do
  current="$(printf '%05d' "$index")"
  if ((index + 1 < file_count)); then
    next="$(printf '%05d' "$((index + 1))")"
    printf 'import "./f%s.js";\nexport const value%s = %d;\n' "$next" "$current" "$index" > "$fixture/src/f${current}.ts"
  else
    printf 'export const value%s = %d;\n' "$current" "$index" > "$fixture/src/f${current}.ts"
  fi
done

cd "$root"
cargo xtask build --release

now_ms() {
  node -e 'process.stdout.write(String(Date.now()))'
}

store="$cache/graph.db"
started="$(now_ms)"
target/release/depgraph --store "$store" scan "$fixture" --json > "$fixture/scan.json"
finished="$(now_ms)"
scan_ms="$((finished - started))"

# Prime SQLite and filesystem caches before the warm-query measurement.
target/release/depgraph --store "$store" deps path:src/f00000.ts > /dev/null
started="$(now_ms)"
target/release/depgraph --store "$store" deps path:src/f00000.ts > /dev/null
finished="$(now_ms)"
query_ms="$((finished - started))"

node -e '
const fs = require("node:fs");
const scan = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
if (scan.status !== "completed" || scan.coverage.files_discovered < Number(process.argv[2])) process.exit(1);
' "$fixture/scan.json" "$file_count"

printf 'safe initial scan: %d ms (%d files; limit %d ms)\n' "$scan_ms" "$file_count" "$scan_limit_ms"
printf 'warm package/file query: %d ms (limit %d ms)\n' "$query_ms" "$query_limit_ms"
test "$scan_ms" -le "$scan_limit_ms"
test "$query_ms" -le "$query_limit_ms"
