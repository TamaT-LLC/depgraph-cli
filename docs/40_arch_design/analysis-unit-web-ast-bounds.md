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

The following result was measured on 2026-09-06 at 21:57+09:00 on Darwin
25.3.0 arm64 with Node.js v24.18.0 and pnpm 10.33.0.
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
| Maximum observed Node process RSS | 431,898,624 bytes |
| Peak retained AST source files | 257 |
| Peak retained AST source bytes (witness) | 62,562 bytes |
| Retained AST source bytes across chunks | 249,743 bytes |
| Peak context target files | 1 |
| Context source-file input occurrences | 4,096 |

The table records phase totals across the four requests. RSS was sampled at each
start, checkpoint, and completion event in the Node process; the native compiler
child process is outside this measurement. Nested phase durations overlap, so
their totals cannot be added to obtain scan elapsed time.

| Phase | Total duration | Maximum observed Node RSS |
| --- | ---: | ---: |
| `framework_semantic` | 0.20 ms | 425,721,856 bytes |
| `graph_finalize` | 502.14 ms | 426,016,768 bytes |
| `module_resolver_initialization` | 11.20 ms | 418,938,880 bytes |
| `route_discovery` | 2.44 ms | 418,922,496 bytes |
| `source_preparation` | 670.44 ms | 423,723,008 bytes |
| `source_read` | 640.36 ms | 423,723,008 bytes |
| `syntax_dependency_resolution` | 165.03 ms | 425,508,864 bytes |
| `syntax_preextraction` | 626.85 ms | 423,723,008 bytes |
| `typescript_ast_selection` | 77.31 ms | 424,902,656 bytes |
| `typescript_ast_transfer` | 196.40 ms | 360,464,384 bytes |
| `typescript_compiler_setup` | 124.38 ms | 431,898,624 bytes |
| `typescript_context_rebuild` | 8,027.37 ms | 425,000,960 bytes |
| `typescript_definition_graph` | 467.24 ms | 369,065,984 bytes |
| `typescript_dependency_graph` | 4,997.32 ms | 424,968,192 bytes |
| `typescript_project_open` | 2,131.17 ms | 431,898,624 bytes |
| `typescript_semantic_diagnostics` | 77.43 ms | 425,000,960 bytes |
| `typescript_semantic_refinement` | 490.98 ms | 425,721,856 bytes |
| `typescript_syntax_diagnostics` | 7.66 ms | 360,464,384 bytes |
| `workspace_discovery` | 13.01 ms | 418,922,496 bytes |

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
