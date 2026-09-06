# ADR: Initial analysis-unit execution and checkpoints

- Status: Proposed
- Date: 2026-09-06
- Related issues: #464, #465, #466, #463, #467

## Behavior

`depgraph scan <root> --plan --json` discovers the repository's analysis units
without launching language workers or opening a Store. Normal scans negotiate
the `analysis-unit-v1` worker capability. A capable Go worker receives a module
scope and a `syntax` or `semantic` stage, while the repository root stays fixed.
Rust, Web, and older workers retain their repository-wide request until they
implement the unit contract.

The initial executor runs at most two work items concurrently. It admits only
a two-item window beyond the next result to ingest. Results therefore enter
the Store in plan order even if a later worker finishes first, and the executor
does not buffer the entire repository's outputs. The source inventory is built
once and copied to a separate temporary file for each process. The supervisor
checks that the worker has not changed that inventory before accepting output.

Unit profiles must identify the requested contract, unit, root, and stage.
File coverage and dependency-source evidence must stay in the requested source
scope or its owned manifest/assembly scope. Cross-unit target declarations are
allowed and must agree on their canonical graph identity. Syntax and semantic
stages contribute separate site ledgers; the Store retains one combined file
ledger per adapter and path.

Aggregate semantic completeness requires both a syntax-complete stage and a
semantic-complete stage for the same unit. Completion records are joined after
execution settles, and incomplete pairs remain incomplete. Each profile retains
its own stage coverage, so selecting only a syntax profile does not claim that
semantic analysis is available in that profile.
Store validation independently reconstructs this join from exactly one syntax
and one semantic profile with matching unit, root, and profile axes; unmatched
or incompatible stages cannot establish aggregate semantic completeness.

## Deadlines and progress

The queue has no aggregate elapsed-time limit. During a normal scan,
`scan.worker_timeout_seconds` is an inactivity budget for each worker. A new
completed phase or an increasing work counter extends that budget. Repeated
messages and `started` messages do not extend it. Protocol output and retained
stderr keep their existing byte limits, and cancellation retains process-tree
cleanup. Standalone worker/delta requests keep their existing deadline contract.

This change does not remove an explicit operation/caller deadline or the MCP
runner's existing outer deadline. It does not introduce an OS memory limit or
split a single compiler operation that cannot report intermediate progress.
Those remain follow-up execution controls under #466 and #463.

## Persistence and reuse

Completed, protocol-validated streams are disposable sidecars beside the Store:

    .depgraph/analysis-checkpoints-v1/<store-name-digest>/<unit-key-digest>.json

The key binds the unit and stage, source/input identity, worker artifact and
arguments, toolchain, configuration, profile selection, and actual repository
root. Writes use a temporary file and atomic rename. Reads validate the envelope,
checksum, limits, expected key, and the complete worker protocol again. Unknown,
truncated, or mismatched entries are cache misses. Unfinished worker streams are
never reused. `--no-cache` disables both reads and writes.

Go syntax stages can reuse their static unit fingerprint. Semantic stages also
require the existing semantic cache's dependency proof. In particular, a Go
dependency snapshot that cannot be certified before execution still requires
semantic reanalysis. Static discovery is not a proof of external dependency
stability. Input validation runs before reuse and before saving a result; a
changed plan or cache input prevents publication of a mixed completed snapshot.

The sidecars do not replace operation leases or the operation journal and are
not completed graph snapshots. There is no Store schema migration. The existing
writer lock serializes scans targeting the same Store. Sidecars may be deleted
without affecting published snapshots; their entry count and total size are
bounded, and older entries are pruned.

## Remaining integration

CLI scan results include per-unit final status and whether a result was reused.
The closed MCP result DTO and live operation progress still require a separate
versioned extension. Web project requests and compiler-context partitioning are
tracked by #462. General partial-snapshot querying and completeness-aware graph
queries remain under #467. A failed attempt must not replace the previously
completed snapshot, and an unobserved source must not become evidence of an
unused dependency.

The regression suite covers reopening checkpoints, changed/corrupt inputs,
out-of-order workers, unit-scope violations, progressing and stalled clocks,
source mutation during a scan, and preservation of completed snapshots.
