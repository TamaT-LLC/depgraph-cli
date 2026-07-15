# depgraph Go worker

`depgraph-go-worker` performs a safe, static inventory of Go workspaces. It
first asks the installed Go toolchain for package metadata through
`go/packages`, then uses the standard-library parser as the authoritative
syntax inventory and fallback. It never runs `go generate`, cgo, project
binaries, tests, or source-level hooks.

The metadata query is deliberately constrained: external package drivers are
disabled, `GOPROXY=off`, `GOTOOLCHAIN=local`, `GOENV=off`,
`GOFLAGS=-mod=readonly`, and `CGO_ENABLED=0` are enforced. PATH entries inside
the scan root are rejected, local replacements and workspace members must stay
inside that root, and each invocation has a 30-second timeout. Missing offline
cache entries or toolchain failures produce diagnostics while preserving the
parser-derived graph.

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
- active package/file metadata and test variants when the constrained
  `go/packages` query completes

The worker intentionally does not provide type/object resolution or SSA/call
graphs. Those belong to the semantic milestone. Imports outside the scanned
workspace are represented as `external_system` nodes; malformed relative
imports and unmatched embed patterns target an `unknown_target` node.
