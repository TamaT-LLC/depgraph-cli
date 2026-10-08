# ADR: TypeScript type queries retain value dependencies

- Status: Implemented
- Date: 2026-10-08
- Issue: #521

## Context

`typeof steps` refers to a value declaration, including when `steps` is a
constant tuple used by `(typeof steps)[number]`. Requiring every `type_use`
target to be a type node discards this dependency. Inferring a named type
from the value also loses the declaration that the query actually references.

## Decision

Keep the `type_use` site and `type_uses` edge and introduce the evidence
occurrence kind `type_query`. The parser attests this occurrence for TypeQuery
nodes and for ImportType nodes whose `isTypeOf` flag is true. These sites
remain `type_only=true`: they occur in type syntax and do not execute a load.

A type query can target a canonical symbol, or a class or enum represented by
a canonical type node. Ordinary type references retain their type-only target
constraint. Raw-delta validation, module export refinement, graph construction,
and the Rust worker protocol validator enforce the same distinction.

Existing version matching between core and worker applies. No persistent
schema migration or new edge kind is required. Unproven bindings remain
unresolved rather than being replaced with a file dependency.

## Validation

Regression fixtures cover local and imported constants, indexed tuple queries,
objects, functions, classes, enums, and inline `typeof import(...)` queries.
Ordinary invalid value-as-type references remain unresolved. Scanner-level
fixtures exercise export-proof refinement in addition to raw compiler results.
