# MCP Agent host operations

This runbook is for an Agent host that launches the packaged `depgraph-mcp`
stdio server. Start with the read-only example in the
[English README](../../README.en.md#mcp-stdio-server). Copy one privileged
profile below only when its effects are required; do not register several
profiles for the same repository as an accidental privilege fallback.

## Repository-scoped Codex onboarding

For the read-only Codex default, use the released CLI from inside the target
Git repository:

```sh
depgraph mcp setup --host codex
```

This is the only workflow in this runbook that owns a host-file mutation. It
must complete the following sequence before atomically replacing
`.codex/config.toml`:

1. Resolve the nearest canonical Git root and reject an invalid worktree
   marker, ambiguous symlink, home directory, or filesystem root before any
   download, scan, or host write.
2. Resolve the exact stable tag `v<invoking CLI version>` and native target
   through the official GitHub release API. Verify the API-provided SHA-256 and
   canonical URL for the release archive/checksum, compiler-pack
   archive/checksum/requirement, and post-publish evidence.
3. Reuse or atomically download those six assets under a shared
   version/target OS cache. Extract bounded archives without absolute paths,
   traversal, links, special entries, duplicates, or cross-package roots.
4. Run the existing package preflight against the extracted `depgraph` before
   scanning. The manifest, evidence, sibling MCP/runner/schema/workers, and
   compiler-pack tree must form one authenticated release closure.
5. Derive the repository-specific Store from canonical root identity outside
   the checkout, run only the default safe scan, and require
   `project_code_executed: false` plus a current completed root-bound snapshot.
6. Run the package preflight again through `initialize`, `tools/list`, and
   `get_context`, then merge the exact read-only entry. No shell expansion,
   ambient executable lookup, mutation capability, or project-exec capability
   is installed.

Setup is idempotent. A process-held cache file lock serializes setup/update,
does not become stale after termination, and leaves incomplete download and
extraction staging invisible. Repeating setup revalidates the public identity
and cached bytes, reuses a valid snapshot, and leaves an exact existing Codex
entry unchanged. Two repositories share only the verified version/target
runtime and compiler pack; their root, Store, journal, and project config stay
separate.

Operate the binding with:

```sh
depgraph mcp status --host codex
depgraph mcp update --host codex
depgraph mcp uninstall --host codex
```

`status` is non-repairing: it re-fetches official metadata and verifies the
cached asset/evidence chain, extracted package, fixed Store/current snapshot,
exact Codex entry, and MCP connection. `update` performs the same reconciliation
as setup for the invoking CLI version and always refreshes the safe snapshot.
Setup, update, and uninstall hold the same repository lifecycle lock in the
validated Git metadata directory through the host configuration mutation, so
setup cannot publish a binding after concurrent cleanup. `uninstall` first
confirms that the installed entry is the exact generated read-only launch tuple
under the managed artifact cache, then always acquires the durable-operation
runner exclusion followed by the Store writer exclusion. It fails before
changing the host file while another lifecycle command, runner, scan, daemon,
or Store writer is active. The operation runner acquires its exclusion before
its first journal open. Missing state directories and persistent lock sentinels
are created first, closing the race before initial Store or journal creation.
With both state guards held, it
removes only that table from the format-preserving TOML document and deletes
the exact Store/journal/SQLite/daemon sidecar family. Empty writer and runner
lock sentinels remain in place so cleanup never unlinks a coordination inode;
the shared artifact cache is retained. A custom global `--store` must be absolute, outside the
repository, and repeated before `mcp` for setup, status, update, and uninstall.

The stable release workflow runs this complete setup, repeated setup, status,
update, and uninstall sequence in clean temporary homes on macOS arm64/x86_64,
Linux arm64/x86_64, and Windows x86_64 after the public post-publish evidence is
available.

## Fixed trust boundary

Treat the release directory, official post-publish evidence, repository root,
store path, and compiler-pack requirement as one operator-approved launch
tuple.

- Download `release-post-publish-evidence-<tag>.json` from the official
  `TamaT-LLC/depgraph-cli` GitHub Release. Obtain its asset digest independently
  from GitHub's release-asset API over HTTPS and pass the bare 64-character
  digest with `--trusted-release-evidence-sha256`. Never derive that trusted
  digest from the local evidence file, archive, checksum, or manifest.
- Pass the evidence file with `--release-evidence`. `agent-config` requires the
  exact official repository, product version/canonical tag, allowed signed-tag
  result, all-green eight-job Full CI and release workflow identities, and the
  sorted 51-asset public closure. It binds the selected archive, checksum, and
  target compiler-pack requirement by exact filename, size, and SHA-256.
- Verify the release checksum and `release-manifest.json`, then use
  `bin/depgraph-mcp` from that evidence-bound extracted release. The sibling
  operation runner, schema, workers, and manifest must remain from the same
  archive.
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

## Generated host quickstarts

Run the packaged `depgraph agent-config` command from the README with one of
the following `--host` values and redirect stdout only after reviewing stderr.
The command never discovers or writes a host configuration path. A successful
diagnostic names the authenticated official release tag and evidence digest.
Merge the single generated `depgraph` entry into an existing host file
yourself; do not replace unrelated host settings.

For Codex, use `--host codex` and merge the output into user
`~/.codex/config.toml` or a trusted project's `.codex/config.toml`. The
read-only profile may be approved statically because its server catalog has no
mutation or project-execution tool; privileged profiles render `prompt`
instead.

<!-- depgraph-agent-config:codex -->
```toml
[mcp_servers.depgraph]
command = "/absolute/path/to/depgraph-0.5.1-TARGET_TRIPLE/bin/depgraph-mcp"
args = ["--root", "/absolute/path/to/repository", "--store", "/absolute/path/to/state/depgraph.sqlite", "--capability", "read", "--compiler-pack-requirement", "/absolute/path/to/compiler-pack-requirement.json", "--log-level", "warn"]
enabled = true
required = true
default_tools_approval_mode = "approve"
```

For Claude Desktop, use `--host claude-desktop`; the exact read-only output is
the `mcpServers` JSON in the README. For VS Code, use `--host vscode` and merge
the following entry into the user or workspace `mcp.json` `servers` object.

<!-- depgraph-agent-config:vscode -->
```json
{
  "servers": {
    "depgraph": {
      "type": "stdio",
      "command": "/absolute/path/to/depgraph-0.5.1-TARGET_TRIPLE/bin/depgraph-mcp",
      "args": [
        "--root",
        "/absolute/path/to/repository",
        "--store",
        "/absolute/path/to/state/depgraph.sqlite",
        "--capability",
        "read",
        "--compiler-pack-requirement",
        "/absolute/path/to/compiler-pack-requirement.json",
        "--log-level",
        "warn"
      ]
    }
  }
}
```

All three formats carry the same absolute launch tuple and exact capability
closure. They do not contain shell expansion, ambient `PATH` lookup, checkout
worker overrides, or a host-file destination.

## Dogfood setup classification

The fixed v0.5.0-rc.7 dogfood evidence recorded zero `setup_blocker`,
`tool_or_schema_missing`, `agent_misuse`, `excessive_context`, and
`host_failure` results across all three MCP samples. The remaining onboarding
risks were therefore classified before implementation rather than inferred
from selected failures:

| Priority | Observed or residual risk | Resolution |
| --- | --- | --- |
| P0 | No observed blocking setup failure | Keep the checked-in 3/3 setup-success gate and do not invent a fallback package path |
| P1 | Manual archive, manifest, target, binary, root, Store, and requirement path mixing | `agent-config` authenticates the official public asset closure through an independently obtained evidence digest and binds the complete tuple before starting the server |
| P1 | Accidental privileged profile or treating acknowledgement as authorization | Read-only remains the default; effect acknowledgement and a separate project-exec human-confirmation responsibility are mandatory |
| P2 | Excessive tool/result context or misuse | The observed 207,684-byte median remained below the 327,680-byte gate with zero typed misuse; hosts may further allow-list task-specific read tools without changing server authority |
| P2 | Empty Store or no current snapshot discovered only after host startup | Preflight stops before launch and returns the packaged safe-scan argv as a distinct Store-write preparation step |

The compiler-pack requirement remains mandatory for read-only startup. The
dogfood evidence achieved 3/3 setup success with the existing requirement and
showed no blocker that would justify weakening the single verified startup
tuple. Consequently this task makes no capability-authority change and needs
no replacement ADR.

## Store-write profile

Use this profile only for safe scan submission and validated runtime-trace
import. It grants `read` plus `store-write`; it does not permit repository file
writes, daemon control, or project-code execution.

<!-- depgraph-mcp-package-smoke:store-write -->
```json
{
  "mcpServers": {
    "depgraph": {
      "command": "/absolute/path/to/depgraph-0.5.1-TARGET_TRIPLE/bin/depgraph-mcp",
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
      "command": "/absolute/path/to/depgraph-0.5.1-TARGET_TRIPLE/bin/depgraph-mcp",
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
      "command": "/absolute/path/to/depgraph-0.5.1-TARGET_TRIPLE/bin/depgraph-mcp",
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
      "command": "/absolute/path/to/depgraph-0.5.1-TARGET_TRIPLE/bin/depgraph-mcp",
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
      "command": "/absolute/path/to/depgraph-0.5.1-TARGET_TRIPLE/bin/depgraph-mcp",
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
| `mcp setup` rejects the root before downloading | Run inside a real Git worktree or pass `--root` to one. Do not use home/filesystem roots, symlinked `.git` markers, or malformed worktree pointers. Correct the root rather than bypassing validation. |
| The exact stable release or one of six setup assets is unavailable | Confirm that the invoking `depgraph --version` has a published non-prerelease GitHub Release with post-publish evidence and a compiler pack for this native target. Upgrade to a published stable CLI; do not substitute a nightly/local archive. |
| Setup was interrupted or the cache failed verification | Rerun the same setup command. Unlocked stale lock files are reusable; partial temporary downloads/extractions are ignored. A digest, evidence, or package-closure mismatch must be repaired with the official release, never by editing cached metadata. |
| `mcp status` reports drift or no current snapshot | Run `depgraph mcp update --host codex` with the same root and optional global Store. It revalidates artifacts/config and refreshes only the safe snapshot. |
| Setup/status succeeds but Codex has no depgraph tools | Mark the checkout trusted so Codex loads project-scoped `.codex/config.toml`, then restart Codex. Inspect the exact file reported by setup; do not copy the entry to an unrelated repository. |
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
