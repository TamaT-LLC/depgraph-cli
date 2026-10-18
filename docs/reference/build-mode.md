# Build-mode consent boundary

English | [日本語](build-mode.ja.md)

`depgraph resolve --build [PATH]` is a separate, privileged mode because build tools, executable configuration, plugins, lifecycle scripts, Rust build scripts, and proc macros may run arbitrary project code. It never prompts. Each invocation must include `--allow-project-code`; configuration, environment variables, `CI=true`, TTY state, and previous consent cannot grant permission. Missing consent is rejected before path/config/store/toolchain processing with exit code `4`.

The explicit-consent guard is enforced before path, configuration, store, or tool processing. A consented Rust workspace with `Cargo.toml` and `Cargo.lock` is executed by the versioned build supervisor using Cargo. Next.js, Astro, and TanStack Start projects declare a direct Node entrypoint and pinned observer contract in `package.json`; shell commands and package-manager lifecycle resolution are not accepted:

```json
{
  "depgraph": {
    "build": {
      "adapter": "next",
      "entrypoint": "scripts/depgraph-build.mjs",
      "version": "16.2.3",
      "timeout_seconds": 900
    }
  }
}
```

Every `depgraph.build` field is validated strictly, and unknown fields are
rejected so misspelled configuration cannot be silently ignored:

| Field | Type | Meaning |
| --- | --- | --- |
| `adapter` | string | One of `next`, `astro`, `tanstack-router`, `tanstack-start`; selects the release-pinned observer contract. |
| `entrypoint` | string | Repository-relative path to a Node script launched as `node <entrypoint>` with no arguments. Absolute paths and `..` segments are rejected, and the file must exist. |
| `version` | string | Non-empty target framework version (for example `"16.2.3"`). It must be a JSON string; a bare number is rejected. Astro and TanStack adapters receive it as `DEPGRAPH_ASTRO_VERSION`, `DEPGRAPH_TANSTACK_ROUTER_VERSION`, or `DEPGRAPH_TANSTACK_START_VERSION`. |
| `timeout_seconds` | integer, optional | Whole-build timeout in seconds; the accepted range is 1–3600 and the default is `900`. |

The entrypoint launch convention is:

- The build runs inside a temporary staged copy of the repository with the
  staged workspace root as the working directory; the entrypoint must leave
  the sources unchanged (mutations fail the run's source audit).
- `node <entrypoint>` receives no CLI arguments. Configuration arrives through
  environment variables: `DEPGRAPH_OBSERVER` names the release-provided
  observer module (Next also receives it as `NEXT_ADAPTER_PATH`), and the
  observer writes its observation artifact into `DEPGRAPH_OUTPUT_DIR`.
- The script is expected to start the real framework build (for example spawn
  `next build`) and exit with the build's exit code. Pointing `entrypoint` at
  `next.config.ts` or at the framework binary itself does not work because
  nothing would integrate the observer into the build lifecycle.

A minimal Next.js entrypoint:

```js
// scripts/depgraph-build.mjs
import { spawnSync } from "node:child_process";

const result = spawnSync(
  process.execPath,
  ["node_modules/next/dist/bin/next", "build"],
  { stdio: "inherit" },
);
process.exit(result.status ?? 1);
```

This example is complete for Next.js: the entrypoint never imports the
observer itself and must not call `modifyConfig` / `onBuildComplete` itself.
Next.js 16.2+ reads `NEXT_ADAPTER_PATH` during `next build` and
invokes the release-provided adapter's build hooks (`modifyConfig`,
`onBuildComplete`), which write the observation artifact into
`DEPGRAPH_OUTPUT_DIR`. That automatic integration is exactly why the
entrypoint must launch the real `next build` process.

A copyable Next.js script also ships as
[`docs/examples/next-depgraph-build.mjs`](../examples/next-depgraph-build.mjs).
A missing `depgraph.build` plan (including `{"depgraph":{}}` with no `build`
object) fails with a copyable template and a pointer to
`depgraph resolve --help`.

The relative entrypoint must integrate the release-provided
observer named by `DEPGRAPH_OBSERVER` (and `NEXT_ADAPTER_PATH` for Next) into
the real build lifecycle. It runs in a temporary staged workspace using
canonical system Node, a cleared allowlisted environment, temporary
HOME/cache/output, bounded output, timeout/cancellation, and cross-platform
process-tree cleanup. In-repository symbolic links inside `node_modules` are
preserved, with their canonical targets rebased to relative paths inside the
staged workspace. This preserves Node's realpath-based nested dependency
resolution, including pnpm's isolated layout with multiple package versions;
no package-manager or `.npmrc` detection is required. Other in-repository
symbolic links are materialized as regular files or directories. A link whose
canonical target leaves the repository, is missing, or is not a regular file
or directory fails closed. Dangling dependency links are not silently skipped:
repair the installation or explicitly exclude the unwanted link. Platforms
must permit creating symbolic links; staging never falls back to flattening
dependencies. Directory links back to an ancestor and links into `.git`, `.depgraph`, or the repository-root
`target` / `.next` directories are omitted rather than copied. `.depgraph.toml` `[build].ignored_paths` excludes repository-relative
prefixes and links to those targets from staging, and unknown `[build]` keys are rejected. `[daemon]
ignored_paths` does not apply to resolve staging. Next's Node.js trace assets
can include dependency directory links themselves: confined `node_modules`
links receive a domain-separated topology digest, while their traced regular
files retain content digests. This does not recursively hash untraced package
contents or admit symlinks as main output, fallback, or Wasm files. Link and
target identity are rechecked to reject changes during observation.
Edge asset hints relative to Next's configured build directory are accepted
only when they identify exactly the same confined artifact as its absolute
path; recorded artifact paths remain repository-relative.
Next output IDs are scoped by type and semantic variant. Prerenders may reuse
their page's raw ID, but each parent reference must resolve to one primary
request route; duplicate variants and missing or ambiguous parents fail closed.
Shared traced files retain separate role-qualified graph identities when used
in both server and Edge contexts, preserving both sets of load relations.
The Web build-evidence converter has separate 64 MiB input and stdout bounds,
a 64 KiB stderr capture bound, and a 30-second deadline. Stdout and stderr are
drained concurrently with capped retention; any truncation, stderr, failed
exit, or invalid protocol/graph rejects the entire result. These are internal
build-conversion limits, separate from runtime trace and query limits. This
admits complete provenance-rich graphs larger than the previous 16 MiB stdout
budget without dropping their sites, edges, or evidence.
Every launched attempt saves a secret-free audit
containing command metadata, logical paths, environment key names, limits,
isolation capability, and outcome; raw stdout/stderr and temporary or host
paths are not persisted in the audit record. On a failed, timed-out, or
cancelled attempt, a redacted stderr tail is printed and a redacted log file
is written under the process temp directory as
`depgraph-build-<run-id>.stderr.log`. `resolve --json` returns `build_run`,
`status`, `diagnostic`, `exit_code`, `log_path`, and `stderr_tail`. Network isolation is reported as `best-effort` unless
an outer namespace/container enforces it.

Validated observer output uses the shared `framework-build-graph-v1` contract:
`phase=build`, `precision=observed`, canonical production
profile/conditions, and primary `kind=build` evidence tied to the supervisor
audit digests. Generated node, site, and edge IDs exclude the attempt ID and
include the contract version; matching source/semantic nodes are reused only
when byte-identical. Repeated builds reuse the exact stored generated nodes and
omit already-promoted site, edge, and diagnostic IDs; a stable site with a new
target remains a conflict. The Next.js observer projects the stable 16.2+
Adapter API route/output manifests into `next-build-observation-v2`: ordinary,
RSC, and data variants share one canonical route; prerenders retain their
observed parent route; metadata routes, chunks, and server/client/edge/static
boundaries remain explicit. Raw output/build IDs and checkout roots never enter
portable identity. A dynamic target that was not observed is retained as an
`unresolved` edge to an `unknown_target` with a bounded reason, never promoted
to a guessed `resolved` edge. TanStack Start v1 production RPCs use
`tanstack-start-build-observation-v2`: the provider transform, resolver
manifest, client/SSR stubs, generated module roles, and manifest importer must
agree before an RPC ID is exact. A suffix-looking final ID is not separately
claimed as a collision unless the compiler exposes that fact. Missing static targets
remain unresolved and only build-correlated middleware chains receive observed
edges. The Next/Astro/TanStack Router/TanStack Start observer entrypoints and
their observation-to-protocol converter are separate checksum-attested release
artifacts; missing, undeclared, or changed bytes fail closed before project
code starts. The release compatibility unit pins the four observer
versions, observation schemas, dynamic capabilities, and runtime paths under
`dynamic-framework-evidence-release-gate-v1`. Every native package gate runs
the same static/semantic/build union fixture through filtered queries,
snapshot diff, impact, policy, JSON/GraphML export, checkout determinism, and
failed-build rollback. The observer and converter bundles are dependency-free
first-party SPDX packages with exact checksums, and the aggregate verifier
requires the same five-artifact closure from every target archive. The store saves the delta in an attempt transaction and
exposes it to `deps`, `dependents`, `why`, and exports only after completed
promotion. Source and semantic rows remain immutable; matching and conflicting
build observations coexist as separate layers, with conflicts carrying both
provenance sets. Failed, partial, timed-out, cancelled, malformed, unsupported,
or unauthorized deltas are discarded and never replace the current completed
graph.
