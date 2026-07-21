# depgraph Go worker

`depgraph-go-worker` performs a safe, static inventory and semantic scan of Go
workspaces. It first asks the installed Go toolchain for typed syntax through
`go/packages`, then uses the standard-library parser as the authoritative source
inventory and fallback. When a confined typed load succeeds, `go/types` and
serial SSA facts are emitted as protocol semantic nodes, dependency sites, and
edges. It never runs `go generate`, cgo, project binaries, tests, or source-level
hooks.

The metadata query is deliberately constrained: external package drivers are
disabled, `GOPROXY=off`, `GOTOOLCHAIN=local`, `GOENV=off`,
`GOFLAGS=-mod=readonly`, and `CGO_ENABLED=0` are enforced. The Go command,
HOME/config/cache directories, and a sanitized `go.work` mirror are isolated
from the repository. The isolated user configuration is seeded with Go's
telemetry mode file set to `off`; `GOTELEMETRY` itself is report-only and is not
treated as a control. Repository symlinks are rejected before typed loading,
and official `x/mod` parsing verifies every module/workspace member and local
replacement before the first load. This also prevents `go.work.sum` from being
written into the repository. Missing offline cache entries or toolchain failures
produce module-scoped diagnostics while preserving the parser-derived graph.

`NeedDeps` remains enabled intentionally so the main `go list` query uses
`-export=false` and does not build missing export data. Consequently the typed
pass may parse/type-check transitive dependency source already present in the
offline cache; only packages backed by confined module source are retained, and
a 30-second context deadline is applied per module. The Go type checker is not
context-aware while checking a file set, so completion of the current unit may
extend beyond that deadline.

```sh
go run ./cmd/depgraph-go-worker \
  --root /path/to/repository \
  --scan-id example-scan > events.ndjson
```

Protocol v1.0 NDJSON is written only to stdout; worker logs are written to
stderr. Build a release binary with:

```sh
go build -trimpath -o bin/depgraph-go-worker ./cmd/depgraph-go-worker
```

## Static coverage

- `go.work` membership and workspace-level replacements
- `go.mod` module, require, and local/remote replace directives
- package, normal/internal-test/external-test build units, and files
- source imports, blank imports, vendored packages, and external imports
- explicit and filename-derived build constraints as Boolean conditions
- generated-file markers, `go:embed`, cgo imports, libraries, and headers
- active package/file metadata, test variants, typed syntax, `Types`,
  `TypesInfo`, and `TypesSizes` when the constrained `go/packages` query
  completes

Imports outside the scanned workspace are represented as `external_system`
nodes; malformed relative imports and unmatched embed patterns target an
`unknown_target` node.

## Semantic coverage

For each confined module whose complete `go/packages` load succeeds, the worker
emits `symbol` and `type` nodes for retained declarations, local definitions,
methods, closures, package initializers, named types, and generic function/type
instances. `go/types` evidence backs `declares`, `extends`, `implements`,
`instantiates`, `type_uses`, and value-reference relations.

Variables, constants, fields, and first-class function/method uses emit a
source-spanned `value_reference` site and `references` edge. Repository objects
target their canonical `symbol`; objects outside the repository target an exact
`external_system` sentinel, and objects without a canonical identity retain an
`unknown_target` plus a stable reason. Call callee identifiers, type names, and
package qualifiers remain owned by call, type-use, and import occurrences so a
single identifier occurrence is not counted twice.

Statically resolved functions, methods, closures, and generic instances emit
`calls` edges with `resolution_status=resolved` and `precision=exact`. Builtins
and functions outside the scanned workspace emit exact `calls` edges with
`resolution_status=external`. Go conversions are treated as type uses rather
than calls.

Interface and function-value dispatch is analyzed with serial SSA using
`InstantiateGenerics`. A complete main or test program uses RTA when the call
site is reachable. Libraries, incomplete programs, and RTA-unreachable sites
use conservative CHA. Candidate sites retain `resolution_status=candidates`
and `precision=overapprox`, with one sorted `may_call` edge per candidate. A
singleton candidate is not promoted to an exact call. VTA is not implemented.

`reflect.Value.Call` and `reflect.Value.CallSlice` remain unresolved. `unsafe`,
`go:linkname`, assembly, plugins, cgo/native callbacks, missing offline
dependency bodies, and unmappable SSA functions are reported through
`go_packages_*`, `go_callgraph_limit`, `go_ssa_*`, or `go_call_unresolved`
diagnostics rather than being silently promoted to exact calls.

## Completeness and fallback

The parser-derived source graph is always retained. Typed packages are committed
only when the complete load for their module passes type-data and source
confinement checks. If one module fails, its typed packages are discarded while
independent successful modules may still contribute semantic nodes and edges.

The `go_packages_status` profile property is:

- `loaded`: every confined module completed its typed load
- `partial`: at least one module completed and at least one module or workspace
  load fell back
- `fallback`: no module produced retained typed packages

`partial` and `fallback` add `go-packages-parser-fallback` to the coverage
ledger. Only `loaded` plus a successful semantic/SSA pass adds
`semantic-complete`; a semantic failure after a loaded typed pass adds
`go-semantic-incomplete`. `semantic-complete` means that retained typed input
was processed without an extractor failure. It does not mean every dynamic or
native call was resolved, so it may coexist with `unresolved-sites` or
`go_callgraph_limit` diagnostics.

Safe scans always report `project_code_executed=false`.

## Determinism

Stable identities use canonical SHA-256 input. Modules, packages, nodes, sites,
edges, diagnostics, file coverage, conditions, and candidate target sets are
canonically sorted, and SSA is built serially. For identical source bytes, Go
toolchain, GOOS/GOARCH, configured tags, and offline dependency availability,
two scans produce the same nodes, sites, edges, and coverage. Moving the same
source tree to another absolute checkout root preserves its semantic graph
identity.

The NDJSON envelope contains the caller-provided `scan_id`; graph payloads or
exports should be compared when scan IDs differ. Offline module-cache contents
are not currently fingerprinted into the profile identity, so changed cache
availability can change `loaded`/`partial`/`fallback` and the resulting semantic
graph. Compare toolchain, profile properties, diagnostics, and coverage before
treating two runs as the same deterministic input.

The verified baseline is Go 1.26.1. Other worker or module Go versions continue
on a best-effort basis with diagnostics.

## Verification

From the repository root:

```sh
(cd workers/go && go test -race ./...)
cargo xtask go-semantic-e2e
cargo xtask test
```
