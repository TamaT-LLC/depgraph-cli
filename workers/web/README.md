# depgraph web worker

The release entry point is:

```sh
node dist/worker.mjs --root <repository> --scan-id <id>
```

The worker writes protocol `1.0` NDJSON to stdout and operational logs to stderr. It performs a safe, read-only scan and reports `project_code_executed=false` in both the scan and profile metadata.

## TypeScript compiler decision

The MVP is deliberately `bundled-only`. Project-local TypeScript is useful compatibility metadata, but importing it would execute JavaScript supplied by the repository being scanned. It is therefore never a compiler candidate in safe mode.

| Available input | Selection | Metadata and diagnostic | Fallback |
| --- | --- | --- | --- |
| Valid release-adjacent TypeScript 7.0.2 native compiler | Use the bundled compiler for syntax analysis plus the isolated Program / TypeChecker definition, import, re-export, type-use, and exact direct-call graph | `source=bundled`, `version=7.0.2`, `selection=bundled-only` | Not needed |
| Build-produced pinned TypeScript 7.0.2 artifact in development | The build verifies package identity/version and copies the compiler to `dist/typescript`; source-mode tests use only that fixed path | Same bundled metadata | Not needed |
| Project-local TypeScript declaration, lock entry, or in-root `node_modules/typescript/package.json` | Read and report the version as metadata only; continue with bundled 7.0.2 | `web.project_typescript_not_loaded` identifies the detected version and metadata source | Bundled compiler remains selected |
| No project-local TypeScript | Continue with bundled 7.0.2 | No project-local diagnostic | Bundled compiler remains selected |
| Source-mode bundled JavaScript API differs from the verified 7.0.2 baseline | Continue only when a worker-owned build artifact is available; never search the scan root | Record the actual bundled version and emit `web.best_effort_typescript_version` | No project/system fallback; the normal build/release gates reject this state |
| Missing, modified, non-executable, or identity-mismatched bundled compiler | Select nothing and fail the scan | Fatal error on stderr; release verification may reject the artifact before worker startup | `fail-closed`; never try project-local, `PATH`, a package manager, or the network |

The `profile_declared` event records the decision using these stable properties:

| Property | MVP value | Meaning |
| --- | --- | --- |
| `typescript_compiler_source` | `bundled` | Compiler code comes from the trusted worker/release artifact |
| `typescript_compiler_version` | `7.0.2` | Exact selected compiler version |
| `typescript_compiler_selection` | `bundled-only` | Project-local and ambient compilers are not candidates |
| `typescript_compiler_fallback` | `fail-closed` | Compiler failure cannot change the selected trust boundary |
| `typescript_analysis_mode` | `semantic-import-type-call-graph` | Program / TypeChecker emits the cumulative definition + import/re-export/type-use + exact-call slice |
| `typescript_project_local_policy` | `metadata-only` | Local version evidence may be read but local code may not be loaded |
| `typescript_project_local_loaded` | `false` | The local TypeScript module was not imported or executed |
| `typescript_typechecker_status` | `definition-import-type-call-graph-emitted` or `definition-import-type-call-graph-discarded` | The validated cumulative semantic delta was emitted, or a typed late failure discarded it atomically |
| `typescript_definition_graph_status` | `ready` or `failed` | Whether the definition delta passed worker-side validation and atomic union |
| `typescript_project_model_status` | `ready` | The isolated project admitted only inventory roots and bundled standard-library files |
| `typescript_project_config` | `worker-neutral-allowlist` | Static JSON/JSONC `paths` are normalized into worker-owned data using TypeScript 7 declaration-site semantics; `baseUrl`, config code, plugins, transforms, and package-based extends are not loaded |
| `typescript_static_config_files` / `typescript_path_mappings` | decimal counts | Auditable counts of admitted static config files and normalized alias patterns |
| `typescript_module_resolution` | `inventory-only` | Relative and admitted static-alias resolution can see virtual inventory files but not the host or project package tree |
| `typescript_semantic_graph_emission` | `definition-import-type-call-graph-v1` | Canonical definitions plus import/re-export/type-use sites and exact `call`/`calls` edges are allowed; `may_call`, framework semantic edges, and `semantic-complete` remain forbidden |
| `typescript_semantic_node_count` | decimal count | Auditable total of repository-owned `symbol` and `type` nodes; external/unknown sentinels are excluded |
| `typescript_semantic_relation_count` | decimal count | Auditable total of definition relations plus semantic dependency edges |
| `typescript_semantic_site_count` | decimal count | Auditable total of semantic-primary import, re-export, type-use, and call sites |
| `typescript_semantic_call_site_count` | decimal count | Auditable subset of semantic sites whose kind is `call` |
| `typescript_semantic_issue_count` | decimal count | Auditable bounded semantic issue total |
| `typescript_release_gate` | `release-gate-pending` or `release-gate-verified` | Only a core-attested extracted archive receives the verified value |
| `project_code_executed` | `false` | No project code, hook, plugin, script, or executable config ran |

The legacy `bundled_typescript`, `typescript_syntax_compiler`, `typescript_compiler_processes`, and `typescript_project_filesystem` properties remain available for protocol compatibility.

## Safe-read and execution boundary

Safe mode may read inventory-approved source files plus a narrow allowlist of metadata. Every reader confines canonical paths to the canonical scan root; metadata reads do not grant permission to load the corresponding module or executable.

- TypeScript/JavaScript/Astro source bytes needed for lexical or syntactic analysis.
- Workspace `package.json` files, supported text lockfiles, `.pnp.data.json`, and `.git/config` repository identity data.
- In-root installed-package manifests needed for package export resolution or project-local TypeScript version metadata.
- JSON/JSONC TypeScript configuration and recognized framework configuration source needed for static literal extraction.
- Existing generated evidence such as TanStack `routeTree.gen.*`.

Out-of-root symlinks and unreadable files are rejected. Source inventory failures are explicit skipped coverage; unavailable optional metadata is treated as absent or produces a role-specific diagnostic and must never cause module loading. The native TypeScript compiler receives only inventory-approved source bytes, bundled standard-library declarations, and a worker-owned project through an isolated virtual filesystem. The project fixes `moduleResolution=bundler`, `module=preserve`, `target=esnext`, `noEmit`, empty `plugins`/`types`/`typeRoots`, and normalized repository-relative `paths` data admitted from static JSON/JSONC. A child `paths` declaration replaces the complete parent option, substitutions are relative to the config that declared it, and deprecated `baseUrl` is deliberately ignored. Raw tsconfig files, the repository root, and its `node_modules` tree are not visible to the compiler process.

Safe mode must never:

- `import`, `require`, or otherwise initialize project-local TypeScript, framework modules, loaders, or plugins;
- evaluate `.pnp.cjs`, executable configuration, package-manager hooks, lifecycle scripts, or repository commands;
- ask a package manager, `PATH`, or the network to discover or install another compiler;
- follow configuration into an executable `extends`, plugin, transform, or module-resolution hook; or
- fall back from the isolated compiler filesystem to the host or repository filesystem.

Framework configuration files may be read as text. Only supported literal fields such as Next.js `basePath`/`pageExtensions`, Astro `base`/`srcDir`, and TanStack `basepath`/`routesDirectory`/`generatedRouteTree` are applied. Dynamic expressions and executable hooks are not evaluated.

## Failure and diagnostic contract

| Condition | Safe-mode behavior | Reporting |
| --- | --- | --- |
| Project-local TypeScript is outside the verified bundled version, is a range, or cannot be selected safely | Continue with the bundled isolated scaffold; do not load the local package | `web.project_typescript_not_loaded` with the observed version/range and manifest or lockfile source |
| Bundled compiler is missing or fails artifact/identity checks | Abort before emitting a partial graph; do not use another compiler | Fatal stderr error and non-zero worker exit; release preflight can fail earlier |
| Compiler crashes, its protocol fails, or its 30-second internal deadline expires | Close or kill and reap the compiler, abort the scan, and emit no graph result | Bounded failed profile plus `web.typescript_project_model_failed`, stable `compiler_protocol_failure`/`compiler_timeout`, empty completeness, and non-zero worker exit; the core worker deadline remains an outer bound |
| Configuration contains a supported static literal | Apply that literal without evaluating the module | `web.static_config_literal_applied` |
| Configuration contains a dynamic value or executable hook | Ignore the value/hook; do not guess a resolved value | `web.static_config_unresolved` or `web.static_config_runtime_ignored`, plus `web.executable_config_not_executed`; unresolved input reduces completeness where applicable |
| A required workspace manifest, supported lockfile, recognized config, or inventoried source cannot be read or parsed safely | Skip the affected interpretation instead of assuming success | A bounded file-specific diagnostic and incomplete coverage accounting |
| Optional installed-package metadata is absent, malformed, unreadable, or outside the root | Treat the metadata as unavailable; never load package code to recover it | Resolution remains candidate/unresolved where applicable; no compiler selection change |

The absence of a project-local compiler is normal, not an error. A detected local compiler never changes the selected source or version. Fatal compiler or project-model failures publish a bounded failed profile and `web.typescript_project_model_failed` diagnostic, keep completeness empty, and exit non-zero. They never publish syntax-only success or a semantic graph.

## TypeChecker graph-activation acceptance matrix

The isolated Program / TypeChecker now emits the cumulative `definition-import-type-call-graph-v1` slice on every successful Web scan. Imports, re-exports, and named type occurrences remain classified as `resolved`, `candidates`, `external`, or `unresolved`. Every admitted call expression, constructor call, and tagged template that is not a module-loader occurrence is recorded as `resolved`, `external`, or reason-bearing `unresolved`; call sites never use candidate status. Framework semantic edges and `semantic-complete` remain disabled. Semantic output does not change the `bundled-only` compiler decision; any future project-local execution mode requires a separate threat-model decision and an explicit, non-safe profile.

Named repository bindings resolve to canonical `symbol` or `type` nodes. The module-level occurrence kinds `namespace_import`, `side_effect_import`, `empty_import`, `import_equals`, `require_call`, `dynamic_import`, `import_type`, `namespace_reexport`, `empty_reexport`, and `export_star` use a repository `file` as their concrete repository target; no other occurrence may weaken a named binding to its containing file. Empty import/export clauses are preserved as their own module-level occurrences so that `type_only` remains truthful. When the current definition vocabulary cannot represent a repository export, the worker records an explicit fallback reason instead of fabricating exact symbol resolution. Existing source-phase import/re-export sites and edges remain in the graph alongside the semantic sites and are never overwritten.

Every `web_import` and `web_reexport` site uses its evidence file as the source node. A `type_use` site uses its enclosing canonical `symbol` or `type`; only an occurrence without a representable enclosing declaration may fall back to that same evidence `file`. A `call` site always uses a canonical callable symbol, or a deterministic `generated_module_initializer` symbol declared by the source file for top-level execution. This Web-only fallback does not weaken the Rust semantic source contract.

Known Node.js builtin specifiers use canonical `node:*` external identities with `external` status and `exact` precision. Explicit forms such as `node:fs` retain that locator, while valid bare forms such as `fs`, `fs/promises`, and `path` normalize to `node:fs`, `node:fs/promises`, and `node:path`. Unknown `node:*` names fail closed as unresolved and builtins are never synthesized as unknown-version npm packages.

Every TypeChecker-primary import/re-export/type-use site and edge carries a boolean `properties.type_only`. It is always `true` for `type_use` and `import_type`, always `false` for runtime-only side-effect imports, `require()` calls, and dynamic imports, and follows the syntax marker for named/default/namespace imports, `import = require()`, and re-exports. Call evidence deliberately omits import-only metadata and instead records `call_kind`, `dispatch`, the exact occurrence span, and compiler provenance. Missing or contradictory metadata discards the semantic delta atomically.

The same evidence carries `module_specifier` for every import/re-export occurrence and `imported_name` for named/default/namespace bindings, `import = require()`, and type uses. Valid quoted empty module/export names remain empty strings rather than being conflated with missing or computed syntax; quoted `"*"` and `"="` names likewise remain ordinary named bindings. Module specifiers have no reserved `binding:` prefix. Their occurrences are retained as unresolved when they cannot resolve. The public site specifier must equal `module_specifier` for import/re-export sites and `imported_name` for type-use sites. A TypeScript `resolution-mode` attribute is preserved as `resolution_mode=import|require` only when it is the declaration's sole attribute and the complete declaration is type-only, including JSDoc import attributes. The implicit CommonJS phase of `import = require()` is internal resolver state and is never exposed as `resolution_mode`. Legacy `assert` syntax is retained only as an explicit `syntax_invalid` occurrence because the pinned compiler reports TS2880. The worker and core independently attest these shapes; malformed or contradictory metadata discards the semantic delta.

An exact `calls` edge is emitted only when the caller has a canonical execution scope, the resolved signature correlates to one repository declaration, and dispatch is statically closed: a direct function/constructor, static or private method, `super`, or a method invoked on a syntactically fresh instance. Stdlib and workspace-external declarations use an `external_system` sentinel. Function values, overloads, unions, interface signatures, open receiver dispatch, missing declarations, broken source, decorators, class field/static-block initializers, and callable bodies without a canonical definition remain reason-bearing unresolved call sites targeting `unknown_target`; a singleton guess is never promoted to exact, and this slice emits no `may_call` edges.

| Fixture | Required assertion before each later semantic slice activation |
| --- | --- |
| No local TypeScript and ordinary supported sources | The pinned bundled compiler is selected; types and module targets are deterministic; `project_code_executed=false` |
| Local TypeScript exactly matches 7.0.2 | Version is reported as metadata only; the local module is not loaded; bundled compiler identity remains in the profile |
| Older, newer, prerelease, invalid, or semver-range local version | A bounded `web.project_typescript_not_loaded` diagnostic identifies the value and source; no compatibility guess or compiler fallback occurs |
| Multiple workspace packages declare different TypeScript versions | Every distinct package/version source is reported deterministically while one bundled compiler is used for the scan |
| Malicious `node_modules/typescript`, tsconfig plugin, `.pnp.cjs`, or executable framework config | Marker code is never executed and no repository-controlled module appears in the worker/compiler module graph |
| Static JSON/JSONC config with supported options | Only explicitly allowed data affects the neutral program; config plugins and executable `extends` remain disabled |
| Dynamic config, project references, plugin-defined virtual modules, or code-based route construction | Unsupported semantics remain candidate/unresolved with diagnostics and complete ledger accounting, never guessed as exact |
| Missing/corrupt compiler, compiler crash, malformed protocol, and forced timeout | The scan fails closed, terminates its child process, emits no partial graph, and never falls back to local/system code |
| Same repository at different checkout paths and repeated runs | Profile identity, graph IDs, diagnostics, and ordering are stable apart from scan-scoped fields |

TypeChecker release acceptance additionally requires exact evidence spans, separate type and runtime targets where they differ, bounded diagnostics, coverage conservation (`discovered = emitted + skipped`), resource deadlines, and regression tests proving that no project-controlled code executed.

The semantic slice rejects inventories above 50,000 source files before any remote `getSourceFile` AST transfer. The 1,000,000-node limit is enforced while traversing transferred trees because the async compiler API exposes each source AST as one remote object rather than a count-only preflight.

## Static coverage

Static coverage includes npm/pnpm/Yarn/Bun workspace and lockfile discovery (including `.pnp.data.json` without loading `.pnp.cjs`), TypeScript/JavaScript ESM and CommonJS dependency sites, `tsconfig.json`/`jsconfig.json` path aliases, conditional workspace package exports, and filesystem routes for Next.js, Astro, TanStack Router, and TanStack Start. Existing TanStack `routeTree.gen.*` files are treated as generated evidence. Production package edges retain dependency/peer/optional kinds and exclude dev-only manifest declarations.

The bundled TypeScript 7.0.2 lexical API is used for deterministic dependency inventory and context-aware import/require recognition. In addition, one pinned native TypeScript 7.0.2 compiler process parses every `.ts`, `.tsx`, `.mts`, `.cts`, `.js`, `.jsx`, `.mjs`, and `.cjs` file per scan. Syntactic diagnostics drive unsupported-syntax coverage; bounded Program, global, and semantic diagnostics accompany the isolated TypeChecker definition/import/type/call graph. Semantic primary evidence and source supporting evidence retain the canonical source span, profile, and compiler version; candidates and all emitted events use canonical ordering.

Release archives keep the native compiler and its standard library tree under `libexec/typescript/lib`. The release manifest pins the component version, entry point, and canonical whole-tree SHA-256, so the `depgraph` core launcher rejects missing, added, symlinked, or modified files before the Web worker starts. Direct worker execution trusts its adjacent installation and is intended for protocol development; the verified safe-scan integrity contract requires launching through `depgraph`.

Astro frontmatter is parsed by the bundled Astro compiler 4.0.0; the release directory must keep `astro.wasm` next to `worker.mjs`. If compiler positions are unavailable, the worker falls back to a source tokenizer and emits heuristic evidence plus a diagnostic.

`DEPGRAPH_PROFILE_CONFIG` accepts the core-provided JSON object `{ "web_environments": [...] }`. Values are normalized, deduplicated, and sorted into the stable profile identity and canonical edge/site conditions; the default is production browser + server.

TypeChecker semantic diagnostics and the definition/import/re-export/type-use/exact-call graph run inside the isolated compiler boundary. Candidate call inference, plugin-defined virtual modules, and code-based route construction remain unresolved or diagnostic-only in safe mode. A late validation failure discards the complete semantic delta, including its sites, edges, generated module-initializer symbols, and semantic-only sentinels, while retaining the source dependency graph.

Source-phase runtime syntax resolution retains target-specific browser/server/package branches: each candidate edge carries its branch condition, while the dependency site carries their canonical union. TypeChecker semantic refinement instead mirrors the pinned TypeScript Bundler resolver's neutral condition set. It selects `import` or `require` from the actual occurrence (or an accepted resolution-mode attribute), enables `types` and applicable `types@` selectors for value and type-only occurrences alike, accepts `default`, and does not activate browser, node, mode, or arbitrary custom conditions. A semantic site therefore does not become a browser/server candidate merely because both environments are present in the scan profile. Condition objects use declaration-order first-match semantics, so an active `default` shadows later keys. Missing type probes and malformed or nonmatching `types@` selectors continue as the pinned compiler does; terminal invalid or blocked runtime branches, incomplete runtime profile results, and traversal-budget exhaustion fail closed instead of selecting a later runtime condition.
