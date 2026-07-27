# ADR: Cross-language adapter common contract and rollout order

- Status: Accepted
- Date: 2026-07-25
- Decision ID: `PROJ-ARC-001-ADR-003`
- Issue: `PROJ-ARC-001-TASK-082` / #150
- Contract: `cross-language-contract-v1`

## Context

OpenAPI, GraphQL, Protocol Buffers, native FFI declarations, and HTTP runtime
observations can all describe a dependency that crosses a language boundary.
They do not, however, establish the same facts:

- an API document establishes contract declarations, not the implementation
  symbol or the deployed endpoint;
- generated client or server code establishes a mapping only when the generator
  inputs and output provenance are known;
- an HTTP trace establishes one observed request, not every possible caller or
  implementation;
- an FFI declaration establishes an ABI-shaped dependency site, while the
  selected library and exported symbol depend on target and link inputs.

Treating a shared spelling such as `GetUser`, `/users/{id}`, or
`create_account` as proof would create plausible but false edges. Treating each
format as an unrelated graph would instead make query, coverage, profile, and
evidence behavior inconsistent. A common contract must therefore define the
identity and proof rules while format adapters retain their own semantics and
security boundary.

## Decision

Adopt `cross-language-contract-v1` as the common identity, dependency-site,
edge, evidence, profile, and completeness contract. Implement format-specific
adapters in this priority order:

1. OpenAPI;
2. Protocol Buffers;
3. GraphQL;
4. HTTP runtime correlation;
5. FFI.

The common validator and golden-fixture harness precede every adapter. HTTP
runtime correlation follows the static contract adapters because an
observation may refine or support an existing operation, but must not invent an
exact static operation. FFI follows the service-contract adapters because its
exact target requires ABI-, target-, and build-specific evidence and therefore
has the highest implementation and release cost.

This ADR reserves the node and relation vocabulary below. It does not make
those kinds available in an existing worker by documentation alone. Each
adapter must add an explicit capability, protocol validator, store/query
compatibility test, and schema migration if its persisted shape requires one.
Protocol 1.0's open vocabulary remains backward compatible, but a producer may
claim `cross-language-contract-v1` only after the common validator accepts the
complete emitted closure.

## Common entity identity

Every cross-language node has a `canonical_identity` object. Its stable ID is
`stable_id_from_value(node.kind, canonical_identity)`. Display names, aliases,
content digests, deployment hostnames, runtime session IDs, and absolute paths
are never identity.

The common identity prefix contains:

```json
{
  "contract_version": "cross-language-contract-v1",
  "format": "openapi | protobuf | graphql | ffi",
  "repository_contract_locator": "relative/path/or/versioned-external-locator",
  "format_version": "adapter-validated-version",
  "coordinate": "format-local-canonical-coordinate"
}
```

`repository_contract_locator` is a normalized repository-relative regular-file
or descriptor-set locator. A canonical external locator contains only a
versioned package/schema registry coordinate or redacted authority; it never
contains URL userinfo, path query data, credentials, or a local absolute path.
The document or descriptor digest belongs in evidence and cache identity, not
the node ID, so a compatible edit does not rename every operation.

| Node kind | Meaning | Format-local coordinate |
| --- | --- | --- |
| `service` | Logical contract owner, independent of a deployment instance | Literal `openapi-service` or `graphql-schema` scoped by the repository contract locator; Protobuf fully qualified service |
| `schema` | Versioned contract document, descriptor namespace, or GraphQL schema | Repository locator plus dialect/package/schema coordinate |
| `operation` | Callable contract entry | OpenAPI canonical method + templated path; Protobuf fully qualified service/method; GraphQL root field coordinate |
| `message` | Named or structurally anchored request, response, input, output, event, or error shape | Fully qualified type name, or parent coordinate + canonical JSON Pointer for an inline shape |
| `native_symbol` | ABI-level imported or exported symbol | target triple + ABI + canonical library identity + exact linker/export symbol |

One admitted OpenAPI description creates one logical service; `info.title` and
`servers` are aliases/deployment data rather than identity. One admitted
GraphQL schema creates one logical service; endpoint roles and deployment
hostnames are profile/evidence rather than identity. An OpenAPI `operationId`, GraphQL
executable-operation name, Protobuf source
alias, language identifier, demangled spelling, and HTTP route label are
aliases. They may be indexed as properties but cannot replace the canonical
coordinate. Two same-named entities from different contract locators, formats,
profiles, ABIs, or package instances remain different nodes.

GraphQL executable operations are dependency occurrences. Their selected root
field coordinates target `operation` nodes; the client-selected operation name
does not create a second service operation. A Protobuf method identity uses its
descriptor's fully qualified service and method, not the generated language
method name. An OpenAPI operation uses its canonical lower-case HTTP method and
normalized templated path; `operationId` is supporting evidence only.
Callback operation coordinates additionally contain the parent operation
coordinate and callback JSON Pointer so they cannot collide with top-level
paths.

## Dependency-site and relation contract

Every detected cross-language occurrence becomes a dependency site, including
one that cannot be mapped. Source-backed sites use the normalized repository
path and complete 1-origin span in their stable ID. Descriptor-, build-, or
runtime-only sites use the admitted artifact/session identity plus a bounded
canonical ordinal; they must not fabricate a source span.

The site and every edge produced from it have the same kind, source, profile,
canonical condition, resolution status, precision, and primary evidence
anchor. Candidate target IDs are sorted and unique. The site ID excludes target
IDs so later resolution does not rename the occurrence; an edge ID contains
site ID, edge kind, and target ID.

| Site / edge kind | Source | Concrete target | Purpose |
| --- | --- | --- | --- |
| `provides_operation` | `service` | `operation` | Contract ownership |
| `accepts_message` | `operation` | `message` | Request, argument, or input shape |
| `returns_message` | `operation` | `message` | Response, result, event, or error shape |
| `references_schema` | `schema` / `message` | `schema` / `message` | `$ref`, GraphQL type reference, or descriptor type reference |
| `calls_operation` | `symbol` / `component` / `server_function` / `operation` | `operation` | Consumer-to-contract call |
| `implemented_by` | `operation` | `symbol` / `server_function` | Provider implementation mapping |
| `generated_from` | generated `file` / `symbol` / `type` | `schema` / `service` / `operation` / `message` | Attested generator provenance |
| `binds_native_symbol` | `symbol` / `build_unit` | `native_symbol` | Language declaration or build unit to ABI symbol |
| `provided_by_library` | `native_symbol` | `native_library` | Exact or candidate link-provider relation |

These relations do not replace existing intra-language `calls`, `rpc_call`,
`handled_by`, or `links` edges. An adapter may emit both when their separate
dependency occurrences and evidence are present; it must not duplicate a
single occurrence under two site IDs.

The common resolution matrix is:

| Status | Target and precision | Requirement |
| --- | --- | --- |
| `resolved` | one concrete target, `exact`, `heuristic`, or `observed` | `exact` requires format-aware static proof; `observed` is allowed only for `phase=build|runtime`; an explicit but non-verifiable manual declaration is `heuristic` |
| `candidates` | one or more concrete targets, `overapprox` | finite, complete-under-the-declared-algorithm set |
| `external` | one `external_system`, `exact` or `heuristic` | canonical external locator is known; no remote content was implied to be scanned |
| `unresolved` | one `unknown_target`, `heuristic` | bounded non-empty reason; never omit the occurrence |

A unique spelling is not format-aware proof. Name-only, path-literal-only,
route-string-only, or demangled-name-only matches are at most heuristic and
normally remain unresolved when another candidate could exist.

## Evidence and mapping proofs

Primary evidence includes `contract_version`, `format`, adapter identity and
version, profile ID, format version, contract/descriptor digest, occurrence
kind, and mapping kind. Source evidence contains a complete relative span.
Descriptor/build/runtime evidence instead contains an admitted artifact
identity and bounded ordinal or event sequence. Supporting evidence is
canonical-JSON sorted after the primary evidence.

A concrete cross-language `calls_operation`, `implemented_by`,
`generated_from`, or `binds_native_symbol` mapping requires one of:

1. an adapter-validated descriptor or generator manifest that maps both
   canonical endpoints and whose inputs/outputs have matching digests;
2. an adapter-validated source map or generated-code map with complete
   repository-relative spans and generator identity;
3. compiler/framework/linker build evidence that observes the exact source and
   target under the same profile;
4. a runtime observation uniquely correlated to an already-declared operation.

Items 1-2 may support a static `exact` edge after the adapter validates the
complete proof. Item 3 emits `phase=build`, `precision=observed`; item 4 emits
`phase=runtime`, `precision=observed`. Observed evidence may support a separate
static mapping only when item 1 or 2 independently proves that mapping; it
never satisfies or promotes a static exact mapping by itself.

Checked-in generated-code comments, naming conventions, adjacent files,
`operationId`, GraphQL resolver property names, Protobuf language method names,
and demangled native names are supporting hints only. A generated file is
mapped only when the admitted descriptor/source-map/generator provenance
matches its current digest. Stale, partial, ambiguous, or mixed-generator
provenance leaves each detected site unresolved and records a bounded reason.

A repository mapping declaration uses the future
`depgraph-cross-language-mapping-v1` data contract. Safe scan parses it as data
without loading a module. A declaration must name both canonical endpoints and
their repository spans. The adapter independently verifies that both
endpoints exist in the same scan. A declaration without tool-produced
provenance may resolve the target but remains `precision=heuristic`; it does
not authorize code execution or remote schema retrieval.

## External references and completeness

Safe scan never downloads a schema, follows a remote `$ref`, performs GraphQL
introspection, invokes `protoc`, loads a generator/plugin, resolves DNS, opens a
network connection, loads a native library, or executes a binary.

- A syntactically valid, versioned remote package/schema coordinate becomes
  `external`.
- A remote URL is reduced to the existing redacted authority contract before
  it can become an external locator. The fragment may identify a local
  reference only when the referenced document was already admitted.
- A missing local reference, unknown format/version, ambiguous mapping, dynamic
  operation, or unbounded candidate set becomes `unresolved`.
- Unsupported/skipped files and every unpromoted mapping are included in the
  coverage ledger. A profile with any required unresolved/skipped contract
  input cannot claim cross-language completeness.

The common completeness capability is
`cross-language-completeness-v1`. It reports each detected format, capability,
input count, node/site/edge count, external/unresolved/skipped count, and
bounded reasons. `complete` means all required format adapters validated their
own closure; it does not mean that runtime-only or dynamically selected
dependencies do not exist.

## Profiles and conditions

A cross-language profile identity contains the contract version, adapter
capability/version, canonical contract-input digest, and the sorted unique
participating language/build/runtime profile IDs. It does not compute a
Cartesian product of unrelated profiles.

Format conditions remain explicit:

- OpenAPI: server choice when statically selected, HTTP method, and media type;
- Protobuf: edition/syntax, package, service, streaming direction, and admitted
  build target;
- GraphQL: schema endpoint role, operation type, directives whose values are
  statically known, and client/server environment;
- HTTP trace: matched static profile plus observed runtime environment/session;
- FFI: target triple, ABI, architecture, link mode, cfg/build tags, and library
  selection.

An edge is emitted only within a compatible intersection of its source,
contract, and target conditions. Unknown or contradictory conditions remain
separate candidates or unresolved; adapters never union them into an
unconditional exact edge. Runtime evidence supports only its matched static
profile and never upgrades another profile.

## Format capability boundaries

### OpenAPI

The first `openapi-contract-v1` slice admits repository-local OpenAPI 3.1.0 and
3.1.1 JSON or YAML regular files. It parses path items, operations, parameters,
request bodies, responses, callbacks, and schema references needed by the
common graph. OpenAPI 3.2.x, overlays, arbitrary extension semantics, and remote
reference bodies require a later explicit capability.

Only repository-relative references inside the admitted inventory are
followed. JSON Pointer, object count, depth, scalar size, total bytes, reference
fan-out, and cycles are bounded. YAML uses a safe data parser with arbitrary
tags disabled and alias expansion bounded. Server variables and examples are
not executed or persisted. Consumer/provider code mapping requires the common
proof rules; a URL literal or `operationId` match alone is not exact.

Generated OpenAPI mappings use strict JSON files ending in
`.depgraph-openapi-generated.json` with schema
`depgraph-openapi-generated-mapping-v1`. The manifest fixes the generator
name/version, OpenAPI locator/version/digest, generated output
locator/digest, language, client/provider role, canonical operation
coordinate, repository symbol coordinate, and complete source span. Safe scan
supports OpenAPI Generator 7, oapi-codegen 2 for Go, and
openapi-typescript 7 for Web. It never starts those tools. The adapter hashes
the admitted manifest, independently reads each confined regular output, and
requires current contract/output digests and an existing canonical operation
before emitting exact `generated_from`, `calls_operation`, or
`implemented_by` edges. Missing, stale, partial, mixed-generator, duplicate,
ambiguous, unsupported, symlinked, or out-of-root claims remain reasoned
unresolved sites. A similarly named generated file without this provenance
creates no exact mapping.

### Protocol Buffers

`protobuf-contract-v1` admits repository `.proto` sources and deterministic
`FileDescriptorSet` inputs. It models fully qualified packages, services,
methods, messages, fields, oneofs, request/response streaming, imports, and
source locations when present. It does not invoke `protoc`, a custom option
interpreter, or a code-generation plugin. Unknown custom options remain
uninterpreted bounded data and cannot create graph edges.

Imports stay inside admitted repository/package inputs. A descriptor without
`SourceCodeInfo` may establish descriptor identity but cannot invent a source
span. Generated-language mapping requires a matching descriptor digest plus a
supported generator manifest/source map; language-specific naming rules alone
are not proof.

Repository descriptor sets use the explicit
`.depgraph-protobuf-descriptor.pb` suffix. Safe scan bounds and decodes the
binary `FileDescriptorSet` directly; it never starts `protoc`. Each admitted
descriptor file name must be a confined repository `.proto` locator and its
package, syntax/edition, imports, public/weak import indexes, nested messages,
fields, services, methods, and streaming flags must match the independently
parsed source model. Exact descriptor evidence is emitted only for a unique
matching descriptor. Missing source, stale or tampered shape, duplicate
provenance, invalid source locations, symlinked descriptors, and out-of-root
names remain explicit incomplete coverage. Descriptor relations without
`SourceCodeInfo` use artifact coordinates and never synthesize a source span.

Generated Protobuf mappings use strict JSON source maps ending in
`.depgraph-protobuf-generated.json` with schema
`depgraph-protobuf-generated-mapping-v1`. Each source map fixes one generator
name/version, source locator/version/digest, descriptor locator/digest,
completeness claim, and a bounded set of generated endpoints. Every endpoint
names its Rust, Go, or Web repository output/digest/span, generated
symbol/type coordinate, contract service/method/message coordinate, role, and
proof kind. Safe scan independently hashes the confined regular output and
requires `proof=generator_source_map`, a complete source map, a unique endpoint
claim, current source/output digests, and the unique admitted descriptor proof.
It never starts a generator.

The v1 support matrix is `prost-build`/`tonic-build` 0.14 for Rust,
`protoc-gen-go` 1.x for Go messages, `protoc-gen-go-grpc` 1.x for Go
services/methods, and `ts-proto` or `@bufbuild/protoc-gen-es` 2.x for Web.
Exact mappings emit `generated_from` plus `calls_operation` or
`implemented_by` for client/provider methods. Naming-only, partial, stale,
mixed-generator, duplicate, unsupported, symlinked, out-of-root, or
descriptor-tampered claims remain reasoned unresolved sites. The profile input
identity and evidence retain generator, source, descriptor, source-map, and
generated-output digests; checkout and generator temporary paths are absent.

### GraphQL

`graphql-contract-v1` admits repository SDL and executable documents. It models
schema roots, field coordinates, named input/output/message shapes, fragments,
and statically evaluable selection dependencies. It does not perform remote
introspection, fetch persisted-query registries, execute directives, load
resolver modules, or assume that a field spelling identifies a resolver.

Safe scan inventories only confined regular `.graphql`, `.graphqls`, and `.gql`
files. It treats SDL extensions as local composition data and resolves schema
roots, named type references, fragment spreads, inline fragments, operation
variables, and field selections only against that admitted inventory. Source
bytes, files, tokens, nesting depth, definitions, and selections are bounded.
GraphQL project configuration and resolver source files are never loaded or
executed.

The contract graph uses a repository SDL document as a schema owner; named
types, directives, and fragments as messages; and named or synthetic
executable definitions as operations. Each schema/type/field/directive,
fragment/type-condition/spread, operation/root/variable, and selection
occurrence is represented by a common-contract site and edge. Built-in scalars
and directives are inert and do not invent repository nodes. Duplicate
definitions, ambiguous schema roots, missing type/field/fragment references,
fragment cycles, malformed or over-budget documents, symlinks, and out-of-root
paths remain explicit reasoned incomplete coverage.

Introspection fields, non-static directive arguments, and federation
directives never become exact local dependencies. They are preserved as
reasoned unresolved boundaries. Checkout paths and file creation order are
absent from canonical identity, profile identity, evidence, and graph output.

Provider `implemented_by` mapping requires a supported framework/compiler map
or explicit repository mapping under the common precision rule. Dynamic field
selection, custom directive behavior, stitched/federated remote schemas, and
resolver chains without complete provenance remain external or unresolved.

GraphQL repository mappings use strict JSON files ending in
`.depgraph-graphql-mapping.json` with schema
`depgraph-graphql-repository-mapping-v1`. Every manifest fixes one supported
compiler or framework name/version, the complete sorted GraphQL input
inventory and aggregate digest, and bounded endpoint mappings. Each mapping
fixes its client or resolver role, Rust/Go/Web language, source document and
operation/field coordinate, repository output/digest/span, endpoint coordinate,
and `compiler_source_map` or `framework_map` proof. Safe scan independently
hashes every confined regular input and output and never starts the named tool
or loads framework code.

The v1 client matrix is `cynic-codegen` 3.x for Rust, `genqlient` 0.8.x for Go,
and `@graphql-codegen/client-preset` 4.x for Web. The resolver matrix is
`async-graphql` 7.x for Rust, `gqlgen` 0.17.x for Go, and
`@graphql-codegen/typescript-resolvers` 4.x for Web. Exact source-map proof
emits `generated_from` plus `calls_operation` or `implemented_by`. Naming-only,
partial, stale, mixed-tool, duplicate, unsupported, symlinked, out-of-root,
ambiguous-field, dynamic endpoint, and federated resolver claims remain
reasoned unresolved sites. Evidence retains tool, GraphQL input, contract
document, mapping manifest, output, and endpoint identities so the source
contract and repository endpoint can be reconstructed without checkout paths.

### HTTP runtime correlation

`http-operation-correlation-v1` consumes only validated
`depgraph-runtime-trace-v1` data. It uses the existing redacted
scheme/authority contract and a validated method plus canonical route template;
raw URL paths, queries, headers, bodies, and credentials are never retained.
It correlates to a static operation only when exactly one compatible operation
exists in the selected profile. Otherwise it emits candidates, external, or
unresolved evidence. The relation remains `phase=runtime`,
`precision=observed`.

Runtime trace v1 carries optional `http` metadata containing only an uppercase
method, canonical route template, optional OpenAPI/Protobuf/GraphQL operation
coordinate, confined contract locator, and format version. The authority and
scheme come from the already-redacted external target locator, so this metadata
cannot reintroduce a URL, query, header, body, or credential. Protobuf and
GraphQL observations require an explicit operation coordinate; OpenAPI may use
its unique method/template coordinate.

The correlator admits only a resolved runtime parent profile present in the
contract profile identity, requires reconstructable static contract evidence,
and requires the runtime source node to exist in the same contract closure. A
unique match appends a `calls_operation` site/edge without changing any static
edge. The runtime evidence binds event, session, environment, authority,
method, route template, static contract digest, and operation identity. Same
input/reimport is idempotent; different sessions remain separately
conditioned. Ambiguous matches, version drift, unmatched profiles/sources, and
undeclared operations stay in a canonical reasoned outcome ledger without an
observed edge.

OpenTelemetry HTTP/RPC semantic-convention spans are vendor input, not a core
contract. A collector adapter must first convert them to the bounded trace v1
contract.

### FFI

`ffi-contract-v1` first inventories Rust `extern`, Go cgo, and supported Web
native-addon declarations as dependency sites. Static declarations identify
the requested ABI/name but do not prove the selected library or export. Exact
`native_symbol` and `provided_by_library` targets require supervised build/link
evidence for the same target profile.

Safe scan does not load, execute, disassemble, or probe a library. Decorated
names, ordinals, symbol versions, weak linkage, platform import libraries,
callbacks, and generated bindings remain target-specific. An unsupported ABI
or missing link evidence stays candidate/unresolved and blocks FFI
completeness.

The static `ffi-contract-v1` inventory admits bounded repository-local source
occurrences for Rust foreign blocks and stable `extern` exports, cgo preamble
prototypes and `//export` declarations, and Web `.node` import/require or
ambient-module declarations. Each emitted `binds_native_symbol` site retains
the source language, import/export direction, ABI, requested library and
symbol, and participating target profile in its canonical condition and source
evidence. A stable local export is a heuristic manual declaration; an import
with a confined explicit library request is only a closed candidate; a bare
Web native package remains external; and missing library/symbol requests,
wildcards, or unsupported ABIs remain unresolved. None of these source-only
states is link/export observation.

The inventory is byte-, file-, declaration-, profile-, and reason-bounded.
Generated sources, Rust macro declarations, cgo headers that would require a C
preprocessor, `//go:linkname`, dynamic native loading, unsafe paths, symlinks,
and unsupported encodings are not expanded or executed. Their occurrences are
conserved in the completeness ledger with fixed reason codes. Candidate and
manual-declaration sites retain `ffi-link-evidence-pending`, so the static
inventory cannot advertise observed FFI completeness before the supervised
link/export adapter supplies same-profile evidence.

The supervised `ffi-link-observation-v1` contract is emitted only from a
completed, explicitly consented build audit with non-truncated validated
output. It contains a canonical one-entry-per-declaration ledger and binds the
build run, participating language profile, target triple, architecture, link
mode, source-root/toolchain/link-input digests, requested ABI/library/symbol,
and observed native artifact digest. Raw linker output, binary content,
environment values, and native paths are never retained or reopened by the
correlator.

Correlation starts from a validated static FFI closure, the completed
supervisor outcome that produced the observation, and an explicit target on
the participating profile. The observation must match the audit run, profile,
target, source-root/toolchain/link-input digests, and cover every eligible
declaration for that profile. A same-profile ABI/library/symbol match appends
separate
`phase=build`, `precision=observed` `binds_native_symbol` and
`provided_by_library` sites/edges; it does not overwrite the static candidate
or heuristic declaration. Partial link output, an unknown or duplicate site,
profile/ABI/library/symbol drift, malformed digest, failed/cancelled build, or
secret-shaped record rejects the entire cloned delta before staging. Reimport
is idempotent, and observations for Linux, macOS, and Windows remain distinct
through their target/profile conditions.

## Security boundary

| Threat | Required control |
| --- | --- |
| SSRF or credential disclosure through references/introspection | No network in safe scan; repository-local admitted references only; authority-only redaction |
| Parser resource exhaustion | Bound bytes, files, tokens, nodes, depth, aliases, references, cycles, descriptors, selections, and diagnostics |
| YAML tags, GraphQL directives, Protobuf options, generator plugins | Parse as inert bounded data; never instantiate or execute them |
| False edge through same-name matching | Require format-local canonical coordinates and one of the enumerated mapping proofs |
| Stale or tampered generated output | Bind generator/descriptor/source-map identity and current input/output digests |
| Secret/schema-content retention | Persist allowlisted identities, digests, spans, counts, and bounded reasons; omit examples, bodies, raw URLs, headers, and option payloads |
| Profile confusion | Require compatible profile/condition intersection; runtime/build evidence cannot cross-promote profiles |
| Native code compromise | No library load in safe scan; exact link observation only under explicit-consent supervised build |
| Partial adapter output | Validate count conservation and complete node/site/edge/evidence closure before atomic promotion |

Unknown versions, fields that alter semantics, unsupported encodings, invalid
references, output overflow, adapter crash, timeout, or cancellation fail
closed for that capability. Previously completed snapshots remain unchanged.

## Rollout order and issue-sized plan

Each row is intended to become one independently reviewable GitHub Issue with
one to three engineering days of scope.

| Order | Slice | Estimate | Depends on | Exit criterion |
| ---: | --- | --- | --- | --- |
| 1 | Common node/site/edge DTO, validator, coverage ledger, and cross-format golden harness | Implemented in #191 | This ADR | Canonical identity, resolution matrix, bounds, closure, and determinism tests pass |
| 2 | OpenAPI 3.1 repository parser and contract graph | Implemented in #192 | 1 | Local JSON/YAML definitions and refs produce service/operation/message graph; hostile refs fail closed |
| 3 | OpenAPI generated-client/provider repository mapping | Implemented in #193 | 2 | Provenance-backed calls/implementation edges and stale/ambiguous negative fixtures pass |
| 4 | Protobuf source/descriptor contract graph | Implemented in #194 | 1 | Service/method/message/import graph is deterministic without invoking `protoc` |
| 5 | Protobuf generated-code mapping | Implemented in #195 | 4 | Descriptor/source-map digests prove language endpoints; naming-only fixtures stay unresolved |
| 6 | GraphQL SDL and executable-document graph | Implemented in #196 | 1 | Field/message/selection graph is complete for admitted files without introspection |
| 7 | GraphQL client/resolver repository mapping | Implemented in #197 | 6 | Supported compiler/framework maps prove endpoints; dynamic/federated cases remain ledgered |
| 8 | HTTP trace-to-operation correlation | Implemented in #198 | 2, 4 or 6; runtime trace v1 | Unique profile match is observed; ambiguous, raw-URL, and secret fixtures fail closed |
| 9 | Rust/Go/Web static FFI declaration inventory | Implemented in #199 | 1 | Every admitted declaration is resolved/candidate/external/unresolved by target profile |
| 10 | FFI supervised link/export evidence | Implemented in #200 | 9; build supervisor | Exact ABI/library/symbol mappings require same-profile link evidence and preserve rollback |
| 11 | Five-target package/query/release gate | 2-3 days | 2-10 implemented capabilities | Linux/macOS/Windows archives attest adapters and pass query, determinism, tamper, SBOM, and license checks |

Rows 2, 4, 6, and 9 may be implemented in parallel after row 1, but the
product priority remains the listed order. Rows 3, 5, and 7 are required before
their format can claim repository-mapping completeness. Row 8 may ship after
one static format mapping is available and must advertise which format
capabilities it can correlate. Row 11 gates only the capabilities present in a
release; it does not require unfinished lower-priority adapters to be silently
marked complete.

## Acceptance matrix

| Case | Required result |
| --- | --- |
| Same operation/message spelling in two documents or formats | Distinct canonical nodes; no name-only cross-edge |
| Repository-local definition/reference | Deterministic definition nodes and exact contract-internal relations with full evidence |
| Remote reference or registry coordinate | No fetch; canonical external or bounded unresolved entry |
| Checked-in generated code without matching provenance | Generated occurrence retained, cross-language mapping unresolved |
| Valid descriptor/source map with current digests | Exact generated mapping under one compatible profile |
| Stale, partial, or ambiguous mapping | Entire mapping delta rejected or ledgered unresolved; no partial exact set |
| GraphQL dynamic/federated resolver | External/unresolved unless a supported complete map proves it |
| HTTP event matching two static operations | Candidates/unresolved; never select by order or spelling |
| HTTP event containing credential/path/query/header/body | Rejected or redacted before persistence; diagnostic does not echo input |
| FFI declaration without link evidence | Declaration site retained; library/export target not exact |
| Same inputs in a second checkout | Byte-identical canonical graph/export, excluding attempt identity |
| Malformed/oversized/cyclic parser input | Bounded fixed diagnostic, incomplete capability, prior snapshot preserved |
| Safe invariant | No network, project code, generator, compiler plugin, introspection, native load, or binary execution |

## Options considered

### One generic URL/RPC/name matcher

Rejected. It cannot distinguish aliases from identity, prove generated-code
origin, model ABI/profile differences, or provide a format-specific
completeness claim.

### Format-specific adapters with no common contract

Rejected. Query semantics, external/unresolved behavior, evidence, profile
intersection, and security limits would drift across adapters.

### Runtime-first discovery

Rejected as the rollout default. Runtime evidence is valuable but
workload-dependent and incomplete. Static contract identities must exist
before a trace can correlate without inventing a contract.

### Generated-code naming conventions as exact proof

Rejected. Generator versions, options, language escaping, collision handling,
and hand-edited output make a unique-looking name insufficient.

### Safe-scan access to remote registries and introspection endpoints

Rejected. It introduces SSRF, credentials, availability, mutable-input, and
reproducibility risks. Explicitly acquired files may be scanned later as
ordinary admitted inputs.

## Security and release gates

Before the first adapter is enabled outside development:

1. protocol and core validators independently enforce canonical identity,
   endpoint kinds, resolution/precision, profile compatibility, count
   conservation, and node/site/edge/evidence closure;
2. parser fuzz/hostile fixtures cover nesting, aliases, cycles, fan-out,
   unknown versions, invalid encodings, remote references, and secret-shaped
   content without echoing input;
3. generated/repository mappings have positive provenance fixtures and
   same-name, stale, partial, ambiguous, and tampered negative fixtures;
4. safe-scan tests prove no network, project code, plugin, generator,
   introspection, native load, or system/project executable fallback;
5. runtime and build mappings preserve phase/precision and cannot promote a
   different profile;
6. two-run and separate-checkout graph, query, and export determinism pass;
7. package manifests attest every enabled adapter/parser artifact and the
   release gate verifies SBOM/license closure and tamper rejection on all
   supported targets.

## Consequences

The graph gains one queryable vocabulary across service contracts, generated
code, observed traffic, and native boundaries while retaining the semantic
differences that make each proof trustworthy. The cost is that initial
coverage is deliberately conservative: many useful-looking name matches remain
unresolved until a descriptor, source map, framework/compiler map, build
observation, or runtime correlation supplies the required evidence.

The rollout can proceed in small issues without forcing all formats into one
release. A capability can be added, tested, and packaged independently, and
the completeness ledger makes absent or unsupported adapters visible instead
of silently treating them as scanned.

## References

- OpenAPI Specification 3.1.1: https://spec.openapis.org/oas/v3.1.1.html
- OpenAPI Specification 3.2.0: https://spec.openapis.org/oas/v3.2.0.html
- GraphQL Specification, September 2025:
  https://spec.graphql.org/September2025/
- Protocol Buffers descriptor schema:
  https://github.com/protocolbuffers/protobuf/blob/main/src/google/protobuf/descriptor.proto
- Rustonomicon, Foreign Function Interface:
  https://doc.rust-lang.org/nomicon/ffi.html
- OpenTelemetry HTTP semantic conventions:
  https://opentelemetry.io/docs/specs/semconv/http/
- OpenTelemetry RPC semantic conventions:
  https://opentelemetry.io/docs/specs/semconv/rpc/
