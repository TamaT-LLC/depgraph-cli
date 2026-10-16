# Runtime trace import contract

[Back to the README](../../README.en.md) · [Usage guide](../guide/usage.en.md)

`depgraph runtime validate (--trace TRACE|--file REPOSITORY_RELATIVE_FILE)` reads
the versioned `1.0` JSON contract,
matches it against the selected completed snapshot, and produces deterministic
`runtime-event:sha256:...` identities without changing the store.
`depgraph runtime import TRACE` performs the same validation and atomically
publishes a new immutable runtime snapshot:

```sh
depgraph runtime import runtime-trace.json --json
depgraph deps id:file:server --phase runtime --session session-001
depgraph dependents id:route:users --phase runtime --environment production
depgraph why id:file:server id:route:users --phase runtime
depgraph impact id:route:users --phase runtime --profile profile:sha256:...
depgraph export --format json --phase runtime --session session-001
depgraph export --format graphml --phase runtime --session session-001
depgraph diff baseline current --phase runtime --json
```

Runtime child profiles declare their static/semantic parent and canonical
effective input. Matching observations from multiple sessions reuse the same
runtime-only sentinel, site, and edge identities; evidence remains per session
with source session/environment, observation count, duration, first/last
timestamp, event IDs, and redaction count. External and unresolved locators are
retained as explicit `runtime_only` sentinel nodes with fixed reasons rather
than being forged into repository nodes. Reimporting the same validated session
is idempotent.

The document identifies a repository, session, profile, environment, and an
ordered event stream. Each source and target uses one explicit locator form:
stable node ID, exact graph locator, canonical repository-relative path,
external identity, or an unresolved reason. Repository identity must match a
workspace node ID, locator, or `repository_identity` property in the selected
snapshot. Revision is checked when both sides provide it. Node ID and locator
matches must be unique; missing or ambiguous locators remain `unresolved`, and
collector-declared external targets remain `external`. Validation never
invents a repository node.

Input is bounded to 16 MiB, 100,000 events, 4,096-character strings, and 32 JSON
levels. UTF-8, exact version, strict fields, RFC 3339 session bounds, increasing
sequence numbers, and portable paths are required. Absolute paths, `..`, file
URI hosts, drive-like `:` segments, backslashes, unknown properties,
secret-bearing fields, and common raw credential forms fail closed with bounded
errors. Production output marked
`session.collector_contract_version=runtime-collector-v1` also rejects raw
HTTP(S) graph locators and HTTP targets containing
userinfo/path/query/fragment. Unmarked trace v1 input retains its existing
compatibility behavior without claiming the production collector guarantee.
Environment variables, headers, and secrets are represented only by
sorted/deduplicated names and redaction counts; their values are not part of the
contract or output.

The matching JSON Schema is
[`schemas/depgraph-runtime-trace-v1.schema.json`](../../schemas/depgraph-runtime-trace-v1.schema.json).
Production SDK lifecycle, buffer, flush, retry, sequence, clock, file/stdout/OTLP
transport, redaction, and rate-limit behavior are fixed separately by
[`runtime-collector-v1`](../../schemas/depgraph-runtime-collector-v1.schema.json) and
the
[collector ADR](../40_arch_design/adr-production-runtime-collector-v1.md).
All transports converge on the same trace v1 JSON; vendor spans are adapted
outside core.

The Node.js/TypeScript reference implementation is built as
`workers/web/dist/depgraph-runtime-collector.mjs`. Its typed module, call,
route, and RPC APIs redact URL credentials/path/query/fragment before
admission, assign contiguous acceptance-order sequence numbers, apply bounded
drop-newest backpressure, and coalesce immutable-prefix flushes across file,
stdout, and OTLP sinks. A disabled instance does not read clocks, call a sink,
or install timers. See the
[Web worker runtime collector guide](../../workers/web/README.md#nodejstypescript-runtime-collector).
Native archives ship the same module at
`libexec/depgraph-runtime-collector.mjs`. Its `runtime-collector-v1`
compatibility unit and SHA-256 are fixed by the release manifest, represented
as a first-party SPDX package, and exercised from real fixture observation
through validate/import/query/GraphML export by every package gate.
