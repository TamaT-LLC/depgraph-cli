# Architecture policy contract

[Back to the README](../../README.en.md) · [Usage guide](../guide/usage.en.md)

Architecture rules live in the versioned `[policy]` section of `.depgraph.toml`.
This example forbids production UI files from depending directly on internal
data files and limits a suppression to one legacy source file:

```toml
[policy]
schema_version = "1.0"

[[policy.rules]]
id = "no-ui-to-data"
kind = "forbidden_dependency"
severity = "error"
source = { kind = "file", field = "path", match = "glob", value = "src/ui/**", cardinality = "many", exclude = [], scope = { paths = [{ match = "glob", value = "src/**" }], packages = [] } }
target = { kind = "file", field = "path", match = "glob", value = "src/data/internal/**", cardinality = "many", exclude = [], scope = { paths = [{ match = "glob", value = "src/**" }], packages = [] } }
profiles = { include = [{ match = "prefix", value = "profile:" }], exclude = [] }
condition = { op = "eq", key = "mode", value = "production" }
precisions = ["exact", "observed"]
resolution_statuses = ["resolved"]
evidence = { kinds = ["source", "semantic"], minimum_spans = 1, primary_only = true }

[[policy.suppressions]]
id = "legacy-ui-data"
rule_id = "no-ui-to-data"
reason = "Legacy adapter is isolated until its scheduled migration."
scope = { source = { kind = "file", field = "path", match = "exact", value = "src/ui/legacy-adapter.ts", cardinality = "one", exclude = [], scope = { paths = [{ match = "exact", value = "src/ui/legacy-adapter.ts" }], packages = [] } }, profiles = { include = [{ match = "prefix", value = "profile:" }], exclude = [] } }
```

Selectors support `package`, `file`, `symbol`, `type`, `route`, and
`component` nodes. `runtime_boundary` requires a `route` or `component`
source and a `component` target; `public_api_change` targets only `symbol`,
`type`, or `route`.
`field` chooses stable ID, normalized repository path, locator, or display-name
matching; `match` is `exact`, `prefix`, or the bounded `*` / `**` / `?` glob
grammar. The normalized `path` field is available only for `file` selectors.
`cardinality = "one"` rejects both zero and multiple matches rather than
silently choosing the first; `"many"` evaluates every match in canonical
order. Repository/package scope is applied before exclusions, and neither can
broaden the selector.

Every rule declares source and target selectors, severity, profile and
condition filters, admitted precision/status values, and its evidence
requirement. `dependency_depth`, `fan_in`, and `fan_out` rules additionally
require `threshold = { max = ... }`. Suppressions require a reason and a
non-empty source, target, profile, or condition scope; a condition used as the
only bound must not be statically always true. Unknown versions, rule kinds,
properties, and invalid or duplicate IDs fail closed as configuration errors.
The machine-readable result contract uses stable violation IDs, dependency
paths, repository-relative evidence spans, applied suppressions, and exit code
`1` whenever an unsuppressed error remains.

During `depgraph scan`, policy selectors are resolved against the validated
staging graph and profile, condition, precision, resolution-status, and
evidence filters are applied before evaluation. `layer_boundary` and
`forbidden_dependency` evaluate admitted direct edges; `cycle` reuses the
package/file/symbol/route cycle query per profile; and `dependency_depth`,
`fan_in`, and `fan_out` evaluate deterministic threshold witnesses. The scan
JSON includes the complete `policy` result. An active error finishes the
attempt as `policy_failed` with exit code `1` and does not replace the current
completed snapshot; warnings and suppressed violations remain visible while
allowing promotion.

`runtime_boundary` is also evaluated during scan. It follows a deterministic
route/component path to an explicit `client_boundary` or `server_boundary`
edge in the same profile; the rule condition is evaluated against that
boundary edge, including framework facts such as `next.runtime`. No default
server/client boundary is inferred.

`public_api_change` is evaluated between completed snapshots:

```sh
depgraph policy baseline current --json
depgraph policy baseline current --github-annotations
```

The report classifies selected public symbols, types, and routes as `added`,
`removed`, or `changed`. Added APIs are compatible; removed and changed APIs
are breaking and become violations when a configured baseline source has an
impact path to the old API. Each violation links the change ID, baseline
dependency path, profile/condition, and declaration evidence. `--json` emits
the versioned machine-readable report and annotations. `--github-annotations`
emits only escaped `warning`/`error` workflow commands for unsuppressed
violations, using validated repository-relative paths and one-origin
positions; scan roots, environment values, evidence details, and absolute
paths are not included. Active errors return `1`; warning-only and
suppressed-only results return `0`.

The matching JSON Schema is
[`schemas/depgraph-policy-v1.schema.json`](../../schemas/depgraph-policy-v1.schema.json).
