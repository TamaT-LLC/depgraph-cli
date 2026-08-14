# MCP Agent host operations

This runbook is for an Agent host that launches the packaged `depgraph-mcp`
stdio server. Start with the read-only example in the
[README](../../README.md#mcp-stdio-server-experimental). Copy one privileged
profile below only when its effects are required; do not register several
profiles for the same repository as an accidental privilege fallback.

## Fixed trust boundary

Treat the release directory, repository root, store path, and compiler-pack
requirement as one operator-approved launch tuple.

- Verify the release checksum and `release-manifest.json`, then use
  `bin/depgraph-mcp` from that extracted release. The sibling operation runner,
  schema, workers, and manifest must remain from the same archive.
- Replace every `/absolute/path/to/...` placeholder below with a canonical
  absolute path and `TARGET_TRIPLE` with the release host target before saving
  host configuration. These are documentation placeholders, not environment
  variables for the host to expand.
- `--root` is an existing repository directory. The server seals that root for
  its lifetime; repository-relative input and output cannot switch roots.
- `--store` is one fixed absolute SQLite file for that root. Keep it outside the
  repository when possible, grant it only to the OS account running the Agent
  host, and never share it between unrelated roots. The durable journal is the
  sibling `<store>.operations.sqlite`; WAL/SHM and the runner purge lock are
  part of the same private state boundary.
- The compiler-pack requirement must be a regular, non-symlink file no larger
  than 1 MiB. Its host, target, release checksum reference, manifest, and closed
  pack tree are verified before the server accepts MCP input.
- Server authorization is static. Changing a host allow option requires a new
  server process; an MCP tool request cannot grant a capability to itself.

The read-only README entry is the default. The following examples are complete
replacement entries, not arguments to append to that running entry.

## Store-write profile

Use this profile only for safe scan submission and validated runtime-trace
import. It grants `read` plus `store-write`; it does not permit repository file
writes, daemon control, or project-code execution.

<!-- depgraph-mcp-package-smoke:store-write -->
```json
{
  "mcpServers": {
    "depgraph": {
      "command": "/absolute/path/to/depgraph-0.5.0-TARGET_TRIPLE/bin/depgraph-mcp",
      "args": [
        "--root", "/absolute/path/to/repository",
        "--store", "/absolute/path/to/state/depgraph.sqlite",
        "--capability", "read",
        "--capability", "store-write",
        "--compiler-pack-requirement", "/absolute/path/to/compiler-pack-requirement.json",
        "--log-level", "warn"
      ]
    }
  }
}
```

## Repository-write profile

Use this profile only for fixed-root initialization and confined atomic graph
export. It grants `read` plus `repository-write`; protected store/journal paths,
symlinks, reparse points, and repository escapes remain denied.

<!-- depgraph-mcp-package-smoke:repository-write -->
```json
{
  "mcpServers": {
    "depgraph": {
      "command": "/absolute/path/to/depgraph-0.5.0-TARGET_TRIPLE/bin/depgraph-mcp",
      "args": [
        "--root", "/absolute/path/to/repository",
        "--store", "/absolute/path/to/state/depgraph.sqlite",
        "--capability", "read",
        "--capability", "repository-write",
        "--compiler-pack-requirement", "/absolute/path/to/compiler-pack-requirement.json",
        "--log-level", "warn"
      ]
    }
  }
}
```

## Daemon-control profile

Use this profile only when the Agent must start or stop the watcher daemon. The
valid closure is `read` plus `store-write` plus `daemon-control`; omitting
`store-write` fails server startup.

<!-- depgraph-mcp-package-smoke:daemon-control -->
```json
{
  "mcpServers": {
    "depgraph": {
      "command": "/absolute/path/to/depgraph-0.5.0-TARGET_TRIPLE/bin/depgraph-mcp",
      "args": [
        "--root", "/absolute/path/to/repository",
        "--store", "/absolute/path/to/state/depgraph.sqlite",
        "--capability", "read",
        "--capability", "store-write",
        "--capability", "daemon-control",
        "--compiler-pack-requirement", "/absolute/path/to/compiler-pack-requirement.json",
        "--log-level", "warn"
      ]
    }
  }
}
```

## Project-exec profile

Use this profile only when the host has a real human-confirmation gate for
project code. The valid closure is `read` plus `store-write` plus
`project-exec`; omitting `store-write` fails server startup.

<!-- depgraph-mcp-package-smoke:project-exec -->
```json
{
  "mcpServers": {
    "depgraph": {
      "command": "/absolute/path/to/depgraph-0.5.0-TARGET_TRIPLE/bin/depgraph-mcp",
      "args": [
        "--root", "/absolute/path/to/repository",
        "--store", "/absolute/path/to/state/depgraph.sqlite",
        "--capability", "read",
        "--capability", "store-write",
        "--capability", "project-exec",
        "--compiler-pack-requirement", "/absolute/path/to/compiler-pack-requirement.json",
        "--log-level", "warn"
      ]
    }
  }
}
```

## Full profile

This profile exposes every effect and should be exceptional. Prefer a smaller
single-purpose profile so a compromised Agent cannot fall through to unrelated
effects.

<!-- depgraph-mcp-package-smoke:full -->
```json
{
  "mcpServers": {
    "depgraph": {
      "command": "/absolute/path/to/depgraph-0.5.0-TARGET_TRIPLE/bin/depgraph-mcp",
      "args": [
        "--root", "/absolute/path/to/repository",
        "--store", "/absolute/path/to/state/depgraph.sqlite",
        "--capability", "read",
        "--capability", "store-write",
        "--capability", "repository-write",
        "--capability", "daemon-control",
        "--capability", "project-exec",
        "--compiler-pack-requirement", "/absolute/path/to/compiler-pack-requirement.json",
        "--log-level", "warn"
      ]
    }
  }
}
```

## Capability and confirmation policy

| Profile | Discoverable effects | Host policy |
| --- | --- | --- |
| `read` | bounded context, graph, query, validation, artifact, status, and operation recovery reads | Default; no mutation or project execution |
| `store-write` | safe scan and runtime-trace import | Confirm the selected fixed store/root; no project-code prompt is needed for a safe scan |
| `repository-write` | repository init and confined file export | Confirm destination and overwrite intent before the tool call |
| `daemon-control` | durable daemon start/stop | Confirm the fixed root and the persistent background-process effect |
| `project-exec` | supervised resolve-build submission | Require an independent human decision for every request that can execute project code |
| `full` | all of the above | Apply every relevant confirmation; do not treat this as a convenient default |

For `resolve_build_submit`, four gates have different jobs:

1. The host decides whether a human approved this repository and invocation.
2. Static `project-exec` capability makes the tool discoverable and lets the
   server authorize the recorded capability set.
3. `acknowledgement: true` records that the host already made that decision. It
   is neither authorization nor a substitute for human confirmation. A false or
   missing acknowledgement is rejected before store or child-process effects.
4. The verified compiler-pack requirement supplies release-bound execution
   authority; it is rechecked by the sibling runner.

Project execution always uses a staged, secrets-cleared supervised workspace,
bounded output, timeout, cancellation, and process-tree cleanup. Only
`enforced` Linux namespace isolation plus a successful source postflight can
claim source non-mutation. A `best-effort` result reports that it cannot prevent
source mutation even when the postflight happens to match; the host must not
upgrade that claim.

## Durable operation polling and reconnect

Modern clients negotiate protocol `2026-07-28` and declare the
`io.modelcontextprotocol/tasks` extension. A durable submit then returns a
`taskId`; it is exactly the portable `operation_id`. Clients without Tasks, or
clients using legacy protocol `2025-11-25`, receive the baseline operation
handle instead. Both views refer to the same journal record.

Use this sequence:

1. Generate one stable idempotency key for the logical request and retain the
   returned ID before doing other work. The same key with the same normalized
   root, tool, capabilities, and input recovers the same ID. Reusing it for
   different input returns `IDEMPOTENCY_CONFLICT` and starts no second job.
2. For Tasks, poll `tasks/get` at the advertised `pollIntervalMs` (currently
   1,000 ms). For the portable path, poll `operation_get`. Do not busy-loop.
3. `operation_result` before a terminal state returns typed
   `OPERATION_NOT_READY` with `poll_operation` remediation; keep the same ID and
   poll. Terminal status is `completed`, `failed`, or `cancelled`.
4. A stdio disconnect or server EOF does not cancel durable work. Launch a new
   packaged server with the exact same root, store, capability profile, and
   compiler-pack requirement, renegotiate Tasks if used, then call `tasks/get`
   or `operation_get` with the saved ID. If the submit response itself was
   lost, repeat the submit with the saved idempotency key.
5. Cancel through `tasks/cancel` only after Tasks negotiation, or through
   `operation_cancel` on every host. The reconnecting server must still possess
   every capability recorded by the operation. Read-only or reduced-profile
   cancellation returns `CAPABILITY_DENIED` without changing the journal.
   Cancellation is cooperative; continue polling until terminal. Cancelling an
   already terminal operation is an idempotent no-op.

On Windows, the server inspects the containing Job Object before launching the
detached operation runner. It requests explicit breakaway only when the Job
Object permits it, relies on silent breakaway when configured, and otherwise
keeps the runner inside the host Job Object. In that last case MCP stdio EOF
still does not cancel the runner, but terminating the containing host job does.
Hosts that require work to survive their own job lifetime must permit explicit
or silent breakaway.

The stdio request budgets are 30 seconds for reads and 2 seconds for durable
submission; the 2-second budget is for committing and returning the handle,
not for finishing the operation. A submitted operation has a one-hour execution
deadline. Always use `execution_deadline_ms` and `retain_until_ms` returned by
`operation_get` rather than a local clock guess. Terminal records remain
retrievable for at least seven days; after purge, the idempotency tombstone
reserves the identity for another 30 days. A deadline failure or cancellation
does not promote partial store or repository output.

## Upgrade and rollback policy

The compatibility tuple is the release version, MCP protocol revision, tool
schema `depgraph-mcp-tools-v1`, operation contract `depgraph-operation-v1`, the
store schema declared by that release manifest, and the journal schema owned by
its packaged operation runtime. `2025-11-25` remains a baseline-only legacy
transport; `2026-07-28` adds Tasks without replacing portable operation tools.
Unknown protocol, tool fields, operation records, schemas, or manifest metadata
fail closed.

Upgrade one fixed root/store at a time:

1. Stop the daemon and stop new submissions. Let accepted operations reach a
   terminal state or cancel and poll them to terminal; closing stdio alone is
   not quiescence.
2. Record the package checksum and manifest compatibility values. Back up the
   graph store, `<store>.operations.sqlite`, and their WAL/SHM companions as one
   byte-consistent set while no server, runner, daemon, or CLI process is using
   them.
3. Install the new archive beside the old one. Never mix its MCP server with an
   older sibling runner, schema, manifest, or worker tree.
4. Start the new package with the read-only profile first. Verify initialize,
   `tools/list`, `get_context`, and recovery of retained operation IDs before
   enabling the previously approved privileged profile.
5. For a compatible additive change, pin hosts to the tested package version
   and roll forward deliberately. A contract rename/removal, protocol removal,
   or non-migratable store change requires the release's explicit migration
   procedure; do not infer compatibility from SemVer alone.

To roll back, quiesce the new version, preserve its state separately for
diagnosis, restore the complete pre-upgrade store/journal/WAL/SHM set, and point
the host back to the matching old archive. Never open a migrated database with
an older package or copy individual SQLite tables between versions.

## Troubleshooting

| Symptom | Check and recovery |
| --- | --- |
| Server exits before initialize | Confirm every path is absolute, root exists, store is fixed to that root, at least `read` is granted, capability dependencies are complete, and the compiler-pack requirement is regular and release-compatible. |
| A privileged tool is absent from `tools/list` | The startup profile lacks its exact capability closure. Edit host configuration and restart; a tool call cannot self-elevate. |
| `CAPABILITY_DENIED` on cancel | Reconnect with the same or a strict superset of the operation's original capability set. Do not modify the journal. |
| `OPERATION_NOT_READY` | Poll the same operation at the advertised interval until terminal, then call `operation_result`. Do not resubmit with a new key. |
| Lost submit response | Retry the same normalized request with the same idempotency key and recover the same ID. |
| Operation cannot be found after reconnect | Check exact root/store/profile binding and retained TTL. Do not search another store or reconstruct an ID. After expiry, treat it as expired rather than rerunning automatically. |
| Project execution reports best-effort isolation | Treat source non-mutation as unguaranteed, inspect the typed audit, and move execution to the enforced Linux namespace gate if that guarantee is required. |
| Upgrade rejects schema or manifest data | Stop and use the documented migration path or restore the full backup with its matching package. Do not delete compatibility fields or downgrade in place. |
| Unexpected stdout bytes | stdout belongs only to newline-delimited MCP JSON-RPC. Move host diagnostics to stderr and reject the session if any non-message bytes remain. |

The package gate parses every marked configuration above and the README default,
substitutes temporary canonical paths, and launches only the extracted native
`depgraph-mcp`. It verifies all six capability catalogs, legacy/modern
initialization, durable reconnect, cancellation authorization, and clean stdio
EOF. `cargo xtask test` also rejects missing, duplicated, privileged-default,
or drifted documentation examples before packaging.
