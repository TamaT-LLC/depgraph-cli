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

## v1 corpus and controls

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
must successfully complete all eight tools needed by the ordered workflow in
every sample. Started, failed, or incomplete MCP calls do not satisfy the gate.
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
| Tool calls | 1 | 17 | median <= 28 |
| Tool-result bytes | 41 | 207,684 | median <= 327,680 |
| Elapsed time | 41,566 ms | 127,444 ms | median <= 240,000 ms |
| Effective host tokens | 12,094 | 59,773 | median <= 100,000 |
| Successful setup | 3/3 | 3/3 | each arm = 3/3 |

All MCP samples found all five major dependency/path/impact claims. Each missed
only the non-major file-cycle rendering claim, because that result exposed
opaque node IDs and the Agent did not complete the permitted source mapping.
No sample fabricated an exact result. The baseline correctly marked graph-only
facts insufficient instead of guessing, which explains its zero accuracy.

The observed MCP/baseline median ratios were 17 calls, 5,065.4634 result bytes,
3.0661 elapsed time, and 4.9424 effective tokens. Ratios remain diagnostic: a
baseline may correctly stop with zero graph calls, so the pass/fail contract
uses absolute MCP ceilings plus accuracy-not-below-baseline rather than an
undefined or gameable ratio.

Before and after every sample the runner fingerprints the repository, Store,
operation journal, daemon-adjacent state, and matching depgraph process set.
The exact zero-process baseline and four fingerprints are predeclared in the
fixed spec and verifier contract before the six-sample run. The digest-bound raw
safety artifact preserves both snapshots, and offline verification requires
both to match that external baseline before deriving each verdict. It also hashes
the trace command inventory and fails closed on anything other than one
non-compound `git`, `rg`, or `sed` read command. The live runner clears inherited
Git and ripgrep configuration, disables system/global Git configuration,
fsmonitor, hooks, external attributes, optional locks, and pager execution,
rejects local Git config outside the closed clone-metadata allowlist, and uses
the fresh raw directory as `ZDOTDIR`. Host authentication reaches Codex through
an explicit environment allowlist, while model-generated shell commands inherit
no host environment and receive only a fixed read-only command environment.
Their source paths are confined to the pinned sparse corpus. All six samples
preserved the state,
exposed no privileged MCP tool, executed no project code, and left no process
behind. The exact downloaded package smoke is digest-bound into the
report and proves safe-scan completion after stdio EOF, terminal recovery from
the same operation, read-profile cancellation denial, clean EOF, and
JSON-RPC-only stdout. The server root is fixed at launch; the enabled tool
inputs contain no replacement-root field.

## Reproduce the snapshots

Use a new private working directory and a clean, dedicated clone. Node.js
24.18.0, Git 2.37 or newer, GitHub CLI, and an authenticated Codex CLI 0.146.0
or newer are required. The sparse worktree tests skip explicitly on older local
Git versions, while CI fails its environment check below this minimum. This v1
evidence is intentionally fixed to `aarch64-apple-darwin`; another host target
requires a new versioned spec and evidence set.

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

## v2 corpus (code health)

[`fixtures/agent-dogfood-v2/`](../../fixtures/agent-dogfood-v2/spec.json)
adds four code-health claims to the v1 corpus (16 claims, 7 major) so a real
Agent host can answer unused-file, hotspot, and audit questions from a
health-capable packaged MCP server. v1 remains frozen: its spec, prompt,
schemas, evidence, and report digest pin are not edited.

| # | id | major | tool | value |
| --- | --- | ---: | --- | --- |
| 13 | `health_unused_findings` | yes | `health_findings_list` | `count=<n>;digest=collection:sha256:<hex>` |
| 14 | `health_finding_detail` | yes | `health_finding_get` | `id=...;kind=...;confidence=...;blockers=...` |
| 15 | `health_hotspots` | no | `health_hotspots_list` | `top=...;score=...;blockers=...` |
| 16 | `health_audit_base` | no | `health_audit_get` | `base_present=...;changed_oid=...;digest=...` |

`workers/web/src/dogfood/unused-health-probe.ts` is an intentionally
unreferenced TypeScript file in the Web analysis profile. It exists so the
candidate snapshot has at least one `unused-file` finding. Do not import it.

### Pinned v2 evidence

v2 is pinned to the public `v0.5.4-rc.2` package. The baseline is
`v0.5.4-rc.1`, and the candidate is `v0.5.4-rc.2`. The checked-in evidence is
under `fixtures/agent-dogfood-v2/evidence/v0.5.4-rc.2/`; ordinary CI verifies
all six samples and the deterministic report without invoking an Agent host.

The snapshots come from a non-shallow, full-history clone with the exact
non-cone sparse-checkout paths declared in `spec.json`. Full Git history keeps
hotspot churn available, while the fixed path set keeps code-health analysis
inside the packaged query budget. The runner rejects a shallow clone, a normal
full working tree, alternate object storage, missing baseline ancestry, or any
sparse path/index drift before starting a sample. It repeats the repository
identity, config, index, and cleanliness checks after every Agent run.

Preflight reconstructs the fixed public archive in a temporary directory and
compares the complete regular-file tree with the supplied package. It also
checks every compiler-pack file against the manifest embedded in the pinned
compiler-pack archive and the adjacent pinned requirement file. The same full
preflight runs after every sample before its evidence is accepted, so a package,
compiler tree, requirement, or smoke artifact changed during execution fails
the whole live run.

The pinned MCP arm exposes 15 read tools and must complete 13 workflow tools in
every sample. `agent_node_get` resolves opaque file-cycle node IDs through the
public DTO before the Agent renders repository paths; source imports are not
accepted as an ID-to-path mapping.
The verifier binds each started/completed MCP call to server `depgraph`, the
candidate snapshot, the fixed ordered arguments, and the preceding result IDs
used for node and finding lookups.

All three MCP samples reached 100% accuracy and 100% major-claim recall. The
median was 25 tool calls, 154,368 tool-result bytes, 191,071 ms, and 89,808
effective tokens. All six samples passed the read-only safety check. The
deterministic report is pinned at
`sha256:7cb90ae38161e375ac080f475de6c8ab36dc18afc3ce243f6cdf7306d759547f`.

`validateSpec`, `run`, `verify`, and `aggregate` require the unused-file filter,
`count>=1`, and a supported finding detail. The runner substitutes
`{{repository.baseline_commit}}` in `prompt.md` with the RC1 OID, and
`prompt_sha256` records the exact bytes sent to the host.

The runner still accepts a `release_status: "pending"` authoring spec through
`lint-spec` only. Every future pin field must contain the literal
`PENDING-RELEASE`; execution, verification, aggregation, and scoring reject
that state. A pinned tag must use `vX.Y.Z-rc.N`, and all asset names and the
packaged manifest must identify the same product version.

v2 host identity is an exact tuple (`cli_version`, model, reasoning effort,
sandbox `read-only`, approval policy `never`). Pin `cli_version` to the
measured `codex --version` string (`codex-cli X.Y.Z`); a bare `X.Y.Z` is
accepted as the same host. `verify` requires every sample identity and
`environment.json` to match that tuple.

### Code-health evaluation

Read blockers before treating a finding as safe to delete. The engine, not
the Agent, owns confidence:

- `confirmed`: reserved for `unused-file`, `unused-export`, `unused-type`, and
  `unused-dependency`. The subject is unused across every applicable analyzed
  profile, those profiles are `semantic-complete`, and no hard blocker remains.
- `probable`: an unused finding has no observed usage or hard blocker, but its
  applicable profiles are only `syntax-complete`. `test-only-dependency`,
  `manifest-mismatch`, audit, and hotspot findings are capped here.
- `indeterminate`: a hard blocker prevents confirmation.

Hard blockers are the 21 kinds other than the two score-layer blockers
`churn-unavailable` and `runtime-not-observed`. For unused findings, score-layer
blockers degrade that scoring layer to zero and do not, by themselves, forbid
`confirmed`; hotspot findings are rankings and are never `confirmed`.
Agents must report the tool's confidence without promotion. For hotspot
results, read the typed `hotspot_scores` object (`fan_in`, `fan_out`,
`reverse_impact`, `git_churn`, `runtime`, and `total`) instead of parsing the
human-readable reason string; each layer includes `raw`,
`normalized_basis_points`, `weight_basis_points`, and `available`.

Primary definitions:

- [Explainable code-health finding contract](../40_arch_design/adr-code-health-finding-contract.md)
- [MCP Agent tools: Code-health host guidance](../40_arch_design/arch-mcp-agent-tools.md)
