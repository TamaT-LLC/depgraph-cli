# Schemas

This directory contains versioned, machine-readable contracts shipped with depgraph.
Consumers should select a schema by its declared contract version and fail closed on
unknown versions or properties.

`depgraph-compiler-pack-v1.schema.json` describes the separately distributed,
target-specific `compiler-precise-rust-v1` compatibility unit. The manifest
fixes the exact nightly channel, Rust/Cargo release, rustc commit, host/target,
official component archives and extracted trees, compiler wrapper and protocol,
SPDX SBOM, license inventory, source provenance, and the complete regular-file
and directory closure. The core additionally verifies the externally supplied
release checksum, canonical ordering and digests, executable identities, and
all legal/provenance cross-references before and after supervised project code.
Missing, additional, modified, symlinked, non-regular, or host-incompatible
entries fail closed without a rustup, PATH, system, or project-toolchain
fallback.

`depgraph-rust-cargo-unit-graph-v1.schema.json` describes the bounded,
checkout-independent DTO produced from the pinned Cargo unit graph v1 stage.
The core additionally enforces root reachability, index conservation,
canonical ordering and digest recomputation, package/source confinement, and
the absence of duplicate canonical units, roots, or dependencies. Host
temporary paths and Cargo's raw numeric unit indices do not cross this
boundary. Workspace sources use `repo://...`; registry and Git sources are
first copied into the bounded run-owned Cargo home and use
`cargo-home://...`. Paths outside those two staged roots fail closed.

`depgraph-rust-compiler-precise-v1.schema.json` describes the attested
wrapper's bounded start/terminal records and the pinned compiler query child's
typed MIR unit DTO.
`depgraph-rust-compiler-invocation-ledger-v1.schema.json` describes the
parent-validated, checkout-independent invocation conservation ledger.
`depgraph-rust-compiler-precise-mir-ledger-v1.schema.json` describes the
validated typed MIR ledger. The parent
requires exactly one successful pair per admitted non-`run-custom-build` Cargo
unit, recomputes source/profile/argv/compiler identities, rejects extra,
missing, duplicate, partial, nested, response-file, and path-escaping
invocations, and never persists raw stdout, stderr, environment values, or
temporary absolute paths. MIR validation additionally recomputes canonical
body/type/place/constant/span identities, enforces source confinement and
count/byte/depth bounds, and rejects raw compiler IDs, debug/address text,
dangling references, and unknown fields. This stage remains audit-only and
does not promote call edges or modify completed snapshots.

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
store access. Output that declares
`session.collector_contract_version=runtime-collector-v1` additionally rejects
raw URL graph locators and HTTP targets containing anything other than a
bounded redacted authority. An optional event `http` record retains only a
canonical method/route template and bounded OpenAPI, Protobuf, or GraphQL
contract coordinate; raw URL, query, header, body, and credential fields remain
outside the contract.

`depgraph-runtime-collector-v1.schema.json` describes the production collector
SDK behavior that precedes trace import. It fixes non-throwing lifecycle,
bounded drop-newest buffering, immutable-prefix flush and retry, deterministic
sequence/clock behavior, file/stdout/OTLP transport identity, pre-buffer
redaction, and size/rate ceilings. The descriptor contains name-only policy and
never contains a sink endpoint, credential, header value, or environment value.
The canonical payload remains `depgraph-runtime-trace-v1`; vendor spans are not
a core input contract.

`depgraph-ffi-link-observation-v1.schema.json` describes sanitized native
link/export evidence produced only after an explicitly consented build
supervisor run completes. It binds every entry to a static declaration site,
language profile, target triple, architecture, link mode, ABI, requested
library/export symbol, toolchain/link-input identity, and native artifact
digest. Raw linker output, native bytes, paths, environment values, and
credentials are outside the contract. The Rust validator additionally requires
canonical entry order and one entry per declaration site.

`depgraph-default-profile-selection-v1.schema.json` describes the closed,
canonical default-profile planning input and selected/omitted/policy-excluded
ledger. The Rust validator additionally verifies canonical profile, candidate,
input, exclusion, and plan identities; one-axis alternative relationships;
baseline references; sorted unique evidence; and exact ledger/count
conservation. The shared golden and invalid mutation corpus live in
`crates/depgraph-core/tests/fixtures`.

`depgraph-profiles-file-v1.schema.json` describes an explicit all-or-error
profile set. Every entry fully declares canonical Rust, Go, or Web axes; the
file contains at most 32 unique profiles and rejects unknown fields. The Rust
reader additionally confines the file to the repository, rejects symlinks,
special files, invalid UTF-8, secret-shaped content, and documents above
64 KiB, then binds selection identity to canonical content rather than the
checkout path.
