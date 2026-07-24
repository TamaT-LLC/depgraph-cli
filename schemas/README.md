# Schemas

This directory contains versioned, machine-readable contracts shipped with depgraph.
Consumers should select a schema by its declared contract version and fail closed on
unknown versions or properties.

`depgraph-protocol-v1.schema.json` contains both the repository-complete
protocol `1.0` events and the opt-in `worker-delta-v1` event family. Delta mode
is selected only after exact capability negotiation; legacy workers continue
to emit the unchanged full-snapshot stream. The delta schema binds every
mutation to an exact base snapshot and graph digest, and the Rust validator
additionally enforces canonical event ordering, stable IDs, referential
integrity, declared ownership-scope confinement, contiguous evidence ordinals,
per-record coverage conservation, aggregate/profile/file/final-graph coverage
consistency, and complete termination.

`depgraph-policy-v1.schema.json` describes the `.depgraph.toml` architecture policy
contract after conversion to JSON. The Rust validator and the JSON Schema share the
golden fixture in `crates/depgraph-core/tests/fixtures/policy-v1.golden.json`.
Suppressions must be bounded by source, target, profile, or a non-vacuous condition;
statically always-true condition-only suppressions are rejected by both validators.

`depgraph-runtime-trace-v1.schema.json` describes the collector-independent
runtime trace import contract. The contract stores environment, header, and
secret names plus redaction counts, never their values. Repository paths are
portable relative paths; absolute/root-escaping paths, unknown fields,
unsupported versions, and unbounded documents fail closed before matching or
store access.
