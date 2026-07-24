# ADR: Production runtime collector v1 contract

- Status: Accepted
- Date: 2026-07-24
- Decision ID: `PROJ-ARC-001-ADR-001`
- Issue: `PROJ-ARC-001-TASK-069` / #137

## Context

`depgraph-runtime-trace-v1` is the only trusted import boundary for runtime
evidence. A production collector also needs lifecycle, buffering, retry,
transport, clock, and redaction behavior, but those concerns must not make the
core depend on a vendor span format or a particular telemetry SDK.

The collector executes in an application process. Blocking, throwing, retaining
request objects, or exporting raw headers, environment values, URLs, and secret
material can therefore affect both application availability and
confidentiality.

## Decision

Production collectors implement the exact `runtime-collector-v1` SDK contract
described by
[`depgraph-runtime-collector-v1.schema.json`](../../schemas/depgraph-runtime-collector-v1.schema.json).
Every collector instance publishes or embeds one descriptor accepted by that
schema. The descriptor contains behavior and name-only redaction policy; file
paths, endpoints, credentials, header values, and environment values are
out-of-band and must never be copied into it.

The collector contract and import contract are separate compatibility units:

| Boundary | Version | Responsibility |
| --- | --- | --- |
| SDK | `runtime-collector-v1` | Observation acceptance, redaction, sequence, buffer, flush, retry, clock, and sink behavior |
| Canonical output | `depgraph-runtime-trace-v1`, `schema_version=1.0` | Bounded vendor-neutral repository/session/event document |
| Vendor input | Not a core contract | Adapter-specific spans, hooks, request objects, and OTLP resource data |

An unknown collector version, output schema version, field, enum value, or
limit above the trace v1 consumer limits fails closed. Adding or changing a
required SDK behavior requires a new collector contract version. Trace v1
retains its own backward-compatibility rules.

## SDK lifecycle and failure semantics

The state machine is `disabled -> running -> draining -> stopped`.

- A disabled collector returns a no-op handle, installs no instrumentation, and
  performs no I/O or timers.
- `record` is synchronous and non-throwing. It accepts typed dependency
  observations only; arbitrary request, response, environment, or span objects
  are not accepted. Invalid, rate-limited, or over-capacity observations are
  dropped with a bounded reason counter.
- Redaction and canonicalization complete before an observation enters the
  buffer. Only an accepted observation receives a sequence number.
- Concurrent `record` calls are serialized at the acceptance boundary.
  Sequence starts at `1` and is contiguous in acceptance order. Dropped
  observations consume no sequence number.
- `flush` snapshots the complete contiguous prefix without draining it.
  Concurrent flushes coalesce. A retry reuses the byte-identical snapshot and
  never allocates a sequence number.
- `shutdown` is idempotent, enters `draining`, performs one bounded best-effort
  final flush, releases hooks/timers, and enters `stopped`. A timeout or sink
  failure is reported through collector diagnostics and never thrown into the
  application.
- Buffer overflow uses `drop_newest`; it never blocks the application and
  never evicts an already accepted prefix.

The effective admission capacity is the smallest configured event/byte buffer
or trace limit, so no accepted snapshot can exceed 100,000 events or 16 MiB. A
single string is at most 4,096 Unicode scalar values.
`max_events_per_second` is a per-instance token-bucket ceiling; excess events
follow the same pre-sequence drop rule. Retry backoff uses a monotonic clock,
starts at the smaller of `initial_backoff_ms` and `max_backoff_ms`, then clamps
every later delay to `max_backoff_ms`.

Event wall timestamps use UTC RFC 3339. Durations and retry deadlines use an
independent monotonic clock. If the wall clock moves backwards, an accepted
event is clamped to the preceding accepted timestamp. Tests may inject the UTC
and monotonic clocks; production defaults use the platform clocks.

## Canonical event conversion

Module, call, route, and RPC adapters map observations into the existing trace
v1 event fields. They may select only a typed trace locator, dependency kind,
positive count, optional duration, and name-only redaction summary.

Canonical conversion is performed in this order:

1. Copy only the typed allowlisted fields; never retain the source object.
2. Redact header, environment, and configured secret values and increment the
   bounded redaction count. Name arrays are sorted and deduplicated.
3. Convert an HTTP(S) URL to `external` with namespace `http` or `https` and
   name `host[:port]`. Userinfo, path, query, fragment, and percent-encoded
   material are discarded. A raw URL in a graph locator or HTTP external name
   is invalid.
4. Apply string, rate, and buffer limits, then allocate the next sequence.
5. Normalize the timestamp and construct the trace v1 event.
6. Set `session.collector_contract_version=runtime-collector-v1`, serialize
   canonical trace v1 JSON, and run the normal trace v1 validator before a sink
   receives the snapshot.

Transport metadata is not part of the canonical trace. The same accepted
observations therefore produce the same trace v1 document through every sink.

## Transport boundary

All sinks carry an immutable contiguous-prefix trace v1 snapshot with media
type
`application/vnd.tamat.depgraph.runtime-trace.v1+json`.

| Sink | Boundary |
| --- | --- |
| `file` | Write a same-directory temporary regular file, flush it, and atomically replace the destination. Never follow a destination symlink. |
| `stdout` | Emit one complete compact JSON snapshot per line. Collector diagnostics go only to stderr. A consumer selects the greatest valid prefix. |
| `otlp` | Put the exact UTF-8 trace JSON in one OTLP LogRecord body as string or bytes. Attributes may identify contract version, media type, session ID, and prefix end only; they do not contribute event semantics. |

A receiver presented with multiple snapshots for one session selects the
greatest valid contiguous prefix. Repository, revision, session metadata, and
every earlier event must be identical. Conflicting reuse of a session or
sequence, a truncated prefix, a gap, an invalid body, or an oversized snapshot
rejects that session. Raw vendor spans and vendor resource attributes are never
accepted directly by core; an adapter must first produce trace v1.

## Threat model and redaction

The collector assumes application inputs, request metadata, URLs, telemetry
attributes, environment values, sink destinations, and vendor payloads are
untrusted.

| Threat | Required control |
| --- | --- |
| Authorization/cookie/custom header value | Allowlist header names only; redact values before buffering |
| Environment or secret value | Store sorted names and counts only; no value-bearing field exists |
| URL credentials or personal data | Retain only lowercased scheme and canonical `host[:port]`; discard all other components |
| Memory/CPU amplification | Bound strings, events, bytes, rate, nesting, flush time, and retry attempts |
| Application outage | Non-throwing record path, drop-newest backpressure, bounded shutdown |
| Replay/duplicate delivery | Contiguous acceptance sequence and byte-identical retry payload |
| Vendor/core coupling | Vendor adapter terminates before trace v1 validation |
| Secret disclosure in diagnostics | Return fixed bounded reasons and never interpolate raw input |

The core independently rejects forbidden value-bearing fields, common secret
forms, absolute paths, unknown fields, and documents outside trace v1 limits.
Output marked `runtime-collector-v1` additionally rejects raw URL locators and
HTTP targets that are not authority-only. Unmarked trace v1 input keeps its
existing compatibility behavior but does not claim this production collector
redaction guarantee. The negative collector fixture contains a URL credential
and proves both rejection and non-echoing diagnostics.

## Consequences

Reference collectors can be implemented without a core OTLP dependency and can
share one deterministic output contract across file, stdout, and OTLP.
Applications remain isolated from collector failures, while the bounded
drop-newest policy can lose evidence under pressure. Such loss is observable in
collector diagnostics; consumers must not infer completeness from a partial
runtime trace.
