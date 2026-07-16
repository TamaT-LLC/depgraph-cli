# depgraph Go worker

`depgraph-go-worker` performs a safe, static inventory of Go workspaces. It
first asks the installed Go toolchain for typed syntax through `go/packages`,
then uses the standard-library parser as the authoritative source inventory and
fallback. The typed AST and its `go/types.Info` are kept together for semantic
extractors. It never runs `go generate`, cgo, project binaries, tests, or
source-level hooks.

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

The typed model is currently internal; emitting type/object facts and SSA/call
graphs belongs to the following semantic tasks. Imports outside the scanned
workspace are represented as `external_system` nodes; malformed relative
imports and unmatched embed patterns target an `unknown_target` node.
