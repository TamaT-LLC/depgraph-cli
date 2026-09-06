# Web source-batch AST boundary

Web source batches keep one TypeScript project context for every request. The
worker places every `context_paths` source in its isolated virtual file system
and opens one native `Program`. This preserves workspace aliases, module
resolution, export proofs, declaration ownership, and TypeChecker queries
across package boundaries.

The JavaScript worker does not request an AST for every context source. For a
syntax request it requests the owned `source_paths`. For a semantic request it
starts with those paths and follows the static module resolver through local
files and workspace package entry points. The resulting closure includes the
context declaration files needed by the TypeChecker. Dependency occurrences
and graph records remain owned by `source_paths`; context-only files are
available as targets and are not emitted as a second source batch. When a
semantic target needs it for protocol ownership validation, the worker may
retain the context file node and its canonical `declares` relation as a
witness. That witness has no file coverage or `contains` edge, so ownership
still belongs to the source batch that contains the file.

The closure is bounded at 4,096 source files per request. The selection is
deterministic: owned paths and discovered targets are processed in repository
relative UTF-8 order. If the bound is reached, the worker emits
`web.typescript_ast_selection_truncated` and withholds semantic completeness.
The scheduler can retry with smaller source batches or a plan that reduces the
context closure. A truncated closure never becomes a semantic-complete result.

The TypeScript async API exposes `Program.getSourceFile` as a per-file AST
operation, but the `Program` and `TypeChecker` are project-wide objects.
Export resolution, declaration merging, module augmentation, global
diagnostics, and cross-file call targets depend on that shared context.
Building a reduced `Program` containing only one source batch can therefore
change native object identity and resolution results. Native compiler objects
also cannot be shared between worker processes. The worker consequently
rebuilds the same full context for each request. Native object identity is
request-local; graph canonical identity and payload formulas remain stable
because every request uses the same repository inventory, workspace mapping,
compiler version, and context paths. Context-only AST objects are released
after DTO extraction, while owned ASTs remain reachable only while framework
collectors consume the owned semantic slice.

Progress reports both sides of the boundary:

- `typescript_ast_selection` reports `context_source_files`,
  `ast_source_files`, `context_target_files`, and `selection_truncated`.
- `typescript_ast_transfer` reports requested and retained source counts and
  UTF-8 byte witnesses. The native API does not expose its serialized AST
  payload size, so `ast_retained_source_bytes` is the exact source-byte
  witness for the retained selection.
- `typescript_context_rebuild` reports the full context count and the
  retained AST count/bytes for that request.

The opt-in public fixture benchmark creates 1,024 source files: 1,023 generated
modules and one shared module. Every generated module has a value import, a
type import, a value re-export, a type re-export, and a typed call into the
shared module. The benchmark scans four 256-file batches and checks that every
cross-file site and edge resolves to the shared definitions. It also records
RSS, phase duration, context rebuild count, and retained AST counts/bytes:

```sh
DEPGRAPH_WEB_BENCHMARK=1 pnpm exec tsx --test test/analysis-unit-benchmark.test.ts
```

The following result was measured on 2026-09-06 at 20:30+09:00 on Darwin
25.3.0 arm64 with Node.js v24.20.0 and pnpm 10.33.0.
It ran sequentially in one process with the bundled TypeScript 7.0.2 worker.
The result is a measurement of this fixture and process, rather than a fixed
memory guarantee.

| Metric | Measured value |
| --- | ---: |
| Source files | 1,024 |
| Chunks | 4 |
| Source files per chunk | 256 |
| Full context source files per request | 1,024 |
| Native compiler context rebuilds | 4 |
| Semantic sites | 6,139 |
| Semantic edges | 6,139 |
| Peak process RSS | 447,725,568 bytes |
| Peak retained AST source files | 257 |
| Peak retained AST source bytes (witness) | 62,562 bytes |
| Retained AST source bytes across chunks | 249,743 bytes |
| Peak context target files | 1 |
| Context source-file input occurrences | 4,096 |

Measured phase totals across the four requests were:

| Phase | Total |
| --- | ---: |
| `framework_semantic` | 0.14 ms |
| `graph_finalize` | 492.35 ms |
| `module_resolver_initialization` | 9.51 ms |
| `route_discovery` | 1.87 ms |
| `source_preparation` | 544.63 ms |
| `source_read` | 517.22 ms |
| `syntax_dependency_resolution` | 163.13 ms |
| `syntax_preextraction` | 504.57 ms |
| `typescript_ast_selection` | 70.92 ms |
| `typescript_ast_transfer` | 131.95 ms |
| `typescript_compiler_setup` | 100.54 ms |
| `typescript_context_rebuild` | 5,839.50 ms |
| `typescript_definition_graph` | 357.02 ms |
| `typescript_dependency_graph` | 3,566.03 ms |
| `typescript_project_open` | 1,578.05 ms |
| `typescript_semantic_diagnostics` | 72.91 ms |
| `typescript_semantic_refinement` | 440.01 ms |
| `typescript_syntax_diagnostics` | 1.18 ms |
| `workspace_discovery` | 12.24 ms |

The TypeScript API has no operation that serializes a project-independent
semantic graph while retaining the original `Program` and `TypeChecker`.
Project references, ambient declarations, global augmentations, and dynamic
or computed module paths can also require context that cannot be inferred
from one file alone. Those cases remain in the full context and are reported
as unresolved or incomplete when the static worker cannot prove them. A
request that reaches the 4,096-file AST selection bound is likewise withheld
from semantic completeness. The scheduler controls concurrent requests and
the worker releases the per-batch AST DTOs after each request; the full native
context is intentionally reconstructed for each request to preserve graph
identity and workspace resolution.
