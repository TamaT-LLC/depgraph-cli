# Packaged MCP Agent dogfood benchmark

This benchmark measures whether a real Agent can answer dependency and change-
impact questions more accurately with the packaged `depgraph-mcp` server than
with source and Git inspection alone. It is a product-value gate, not another
protocol-conformance test.

The live six-Agent run is an explicit dogfood/release gate. Ordinary pull-
request CI does not spend Agent capacity or require host credentials: it
revalidates the checked-in raw artifacts, deterministic aggregate, schemas, and
golden scoring. Rerun the live gate when the public Agent-facing package,
corpus, host contract, or GA release decision changes.

## Fixed corpus and controls

[`spec.json`](../../fixtures/agent-dogfood-v1/spec.json) fixes 12 claims across
Rust, Go, and TypeScript/Web: node/path discovery, outgoing and incoming
dependencies, impact, unresolved and candidate precision, file and package
cycles, snapshot diffs, and snapshot coverage. The
[`prompt`](../../fixtures/agent-dogfood-v1/prompt.md),
[`answer schema`](../../fixtures/agent-dogfood-v1/answer.schema.json),
[`raw safety schema`](../../fixtures/agent-dogfood-v1/safety.schema.json), and
golden values are versioned with it.

Both arms use the same candidate checkout, prompt, model, reasoning effort,
read-only sandbox, approval policy, 28-call budget, five-minute sample timeout,
and three samples. The baseline has source and Git read tools. The MCP arm adds
only nine fixed `read`-capability graph tools from the downloaded package and
must exercise all eight tools needed by the ordered workflow in every sample.
User configuration and repository rules are ignored, every host is ephemeral,
and no successful sample may be selected or discarded.

This evidence uses the public [`v0.5.0-rc.7` release](https://github.com/TamaT-LLC/depgraph-cli/releases/tag/v0.5.0-rc.7),
which superseded the earlier release-candidate prerequisite while closing the
same v0.5 package contract. The spec pins the release archive, compiler pack,
requirement, packaged smoke, commits, trees, and snapshot IDs by digest.

## Checked-in result

The canonical
[`report.json`](../../fixtures/agent-dogfood-v1/evidence/v0.5.0-rc.7/report.json)
passed all 14 gates. Its directory contains the environment plus the trace,
last host message, normalized answer, raw before/after safety fingerprints, and
scored sample for all three baseline and all three MCP executions.

| Metric | Baseline median | MCP median | MCP gate |
| --- | ---: | ---: | ---: |
| Accuracy | 0% | 91.67% | each sample >= 90% |
| Major-claim recall | 0% | 100% | each sample = 100% |
| False exact claims | 0 | 0 | total = 0 |
| Candidate/unresolved promoted to exact | 0 | 0 | total = 0 |
| Required MCP workflow tools | n/a | 8/8 per sample | each sample = 8/8 |
| Tool calls | 0 | 17 | median <= 28 |
| Tool-result bytes | 0 | 202,404 | median <= 327,680 |
| Elapsed time | 29,496 ms | 132,819 ms | median <= 240,000 ms |
| Effective host tokens | 8,273 | 77,922 | median <= 100,000 |
| Successful setup | 3/3 | 3/3 | each arm = 3/3 |

All MCP samples found all five major dependency/path/impact claims. Each missed
only the non-major file-cycle rendering claim, because that result exposed
opaque node IDs and the Agent did not complete the permitted source mapping.
No sample fabricated an exact result. The baseline correctly marked graph-only
facts insufficient instead of guessing, which explains its zero accuracy.

The observed MCP/baseline median ratios were undefined for calls and result
bytes because both baseline medians were zero, 4.5029 for elapsed time, and
9.4188 for effective tokens. Ratios remain diagnostic: a baseline may correctly
stop with zero graph calls, so the pass/fail contract uses absolute MCP ceilings
plus accuracy-not-below-baseline rather than an undefined or gameable ratio.

Before and after every sample the runner fingerprints the repository, Store,
operation journal, daemon-adjacent state, and matching depgraph process set.
The digest-bound raw safety artifact preserves both snapshots, and offline
verification derives each unchanged/process verdict from them. It also hashes
the trace command inventory and fails closed on anything other than one
non-compound `git`, `rg`, or `sed` read command. All six samples preserved the
state, exposed no privileged MCP tool, executed no project code, and left no
process behind. The exact downloaded package smoke is digest-bound into the
report and proves safe-scan completion after stdio EOF, terminal recovery from
the same operation, read-profile cancellation denial, clean EOF, and
JSON-RPC-only stdout. The server root is fixed at launch; the enabled tool
inputs contain no replacement-root field.

## Reproduce the snapshots

Use a new private working directory and a clean, dedicated clone. Node.js
24.18.0, Git, GitHub CLI, and an authenticated Codex CLI 0.146.0 or newer are
required. This v1 evidence is intentionally fixed to `aarch64-apple-darwin`;
another host target requires a new versioned spec and evidence set.

Download these four public assets from `v0.5.0-rc.7` into a new private assets
directory:

- `depgraph-0.5.0-aarch64-apple-darwin.tar.gz`
- `depgraph-compiler-pack-0.5.0-aarch64-apple-darwin.tar.gz`
- `depgraph-compiler-pack-0.5.0-aarch64-apple-darwin.requirement.json`
- `depgraph-0.5.0-aarch64-apple-darwin.mcp-smoke.json`

Extract both archives into the same `extracted` directory and place the
requirement beside the extracted compiler-pack directory:

```sh
dogfood_assets=/absolute/path/to/new-private-assets
dogfood_extracted="$dogfood_assets/extracted"
mkdir -p "$dogfood_assets" "$dogfood_extracted"

gh release download v0.5.0-rc.7 \
  --repo TamaT-LLC/depgraph-cli \
  --dir "$dogfood_assets" \
  --pattern 'depgraph-0.5.0-aarch64-apple-darwin.tar.gz' \
  --pattern 'depgraph-compiler-pack-0.5.0-aarch64-apple-darwin.tar.gz' \
  --pattern 'depgraph-0.5.0-aarch64-apple-darwin.mcp-smoke.json'
gh release download v0.5.0-rc.7 \
  --repo TamaT-LLC/depgraph-cli \
  --dir "$dogfood_extracted" \
  --pattern 'depgraph-compiler-pack-0.5.0-aarch64-apple-darwin.requirement.json'

tar -xzf "$dogfood_assets/depgraph-0.5.0-aarch64-apple-darwin.tar.gz" \
  -C "$dogfood_extracted"
tar -xzf "$dogfood_assets/depgraph-compiler-pack-0.5.0-aarch64-apple-darwin.tar.gz" \
  -C "$dogfood_extracted"
```

The runner rejects any release, archived/extracted manifest, binary,
requirement, smoke, checkout, tree, or snapshot digest that differs from the
spec.

Create both safe-scan snapshots with the downloaded `depgraph` binary. The
dedicated clone must end at the candidate commit with an empty porcelain status
before running the Agent comparison; the runner rejects tracked, staged, or
untracked drift.

```sh
dogfood_repo=/absolute/path/to/dedicated/depgraph-cli
dogfood_store=/absolute/path/to/private-state/depgraph.sqlite
dogfood_depgraph=/absolute/path/to/extracted/depgraph-0.5.0-aarch64-apple-darwin/bin/depgraph

git -C "$dogfood_repo" checkout --detach ccd71620deb53161b5856c8e93fecae4ffdf163c
"$dogfood_depgraph" scan "$dogfood_repo" --store "$dogfood_store" --json
"$dogfood_depgraph" snapshot create agent-tools-baseline --store "$dogfood_store" --json

git -C "$dogfood_repo" checkout --detach 85dcf029ad4d536b1ffa5f9b148749f2beb95128
"$dogfood_depgraph" scan "$dogfood_repo" --store "$dogfood_store" --json
"$dogfood_depgraph" snapshot create rc7-candidate --store "$dogfood_store" --json
test -z "$(git -C "$dogfood_repo" status --porcelain=v1 --untracked-files=all)"
```

## Run all six samples

Set every path to an existing canonical absolute path. The raw output directory
must not exist yet; this prevents an earlier run from being overwritten or
mixed into a new aggregate.

```sh
export DEPGRAPH_AGENT_DOGFOOD_REPOSITORY=/absolute/path/to/dedicated/depgraph-cli
export DEPGRAPH_AGENT_DOGFOOD_RELEASE_ARCHIVE=/absolute/path/to/depgraph-0.5.0-aarch64-apple-darwin.tar.gz
export DEPGRAPH_AGENT_DOGFOOD_PACKAGE_ROOT=/absolute/path/to/extracted/depgraph-0.5.0-aarch64-apple-darwin
export DEPGRAPH_AGENT_DOGFOOD_COMPILER_PACK_ARCHIVE=/absolute/path/to/depgraph-compiler-pack-0.5.0-aarch64-apple-darwin.tar.gz
export DEPGRAPH_AGENT_DOGFOOD_COMPILER_PACK_REQUIREMENT=/absolute/path/to/extracted/depgraph-compiler-pack-0.5.0-aarch64-apple-darwin.requirement.json
export DEPGRAPH_AGENT_DOGFOOD_STORE=/absolute/path/to/private-state/depgraph.sqlite
export DEPGRAPH_AGENT_DOGFOOD_MCP_SMOKE=/absolute/path/to/depgraph-0.5.0-aarch64-apple-darwin.mcp-smoke.json

dogfood_raw_dir=/absolute/path/to/new-agent-dogfood-evidence
node scripts/agent-dogfood.mjs run \
  fixtures/agent-dogfood-v1/spec.json \
  "$dogfood_raw_dir" \
  "$dogfood_raw_dir/report.json"
```

The runner aborts immediately on a safety invariant, terminates the active host
process group on timeout, tool-budget exhaustion, SIGINT, or SIGTERM, and writes
a typed `setup_blocker`, `tool_or_schema_missing`, `agent_misuse`,
`excessive_context`, or `host_failure` when applicable. If a run fails, preserve
that whole directory for diagnosis and rerun all six samples into another new
directory. Never keep only successful samples or combine samples across runs.

Verify a complete evidence set without contacting an Agent host:

```sh
node scripts/agent-dogfood.mjs verify \
  fixtures/agent-dogfood-v1/spec.json \
  fixtures/agent-dogfood-v1/evidence/v0.5.0-rc.7 \
  fixtures/agent-dogfood-v1/evidence/v0.5.0-rc.7/report.json
node --test scripts/tests/agent-dogfood.test.mjs
```

`aggregate` exists only to recompute a report from one complete fixed raw
directory. It does not discover, rank, or select samples. A canonical evidence
update replaces the entire six-sample directory after review and a passing
gate.
