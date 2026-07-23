# Schemas

This directory contains versioned, machine-readable contracts shipped with depgraph.
Consumers should select a schema by its declared contract version and fail closed on
unknown versions or properties.

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
