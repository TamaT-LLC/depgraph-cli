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
| Valid release-adjacent TypeScript 7.0.2 native compiler | Use the bundled compiler for syntax-only analysis | `source=bundled`, `version=7.0.2`, `selection=bundled-only` | Not needed |
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
| `typescript_analysis_mode` | `syntax-only` | No TypeChecker or project module resolution is invoked |
| `typescript_project_local_policy` | `metadata-only` | Local version evidence may be read but local code may not be loaded |
| `typescript_project_local_loaded` | `false` | The local TypeScript module was not imported or executed |
| `typescript_typechecker_status` | `not-invoked` | Type checking is outside the MVP analysis mode |
| `project_code_executed` | `false` | No project code, hook, plugin, script, or executable config ran |

The legacy `bundled_typescript`, `typescript_syntax_compiler`, `typescript_compiler_processes`, and `typescript_project_filesystem` properties remain available for protocol compatibility.

## Safe-read and execution boundary

Safe mode may read inventory-approved source files plus a narrow allowlist of metadata. Every reader confines canonical paths to the canonical scan root; metadata reads do not grant permission to load the corresponding module or executable.

- TypeScript/JavaScript/Astro source bytes needed for lexical or syntactic analysis.
- Workspace `package.json` files, supported text lockfiles, `.pnp.data.json`, and `.git/config` repository identity data.
- In-root installed-package manifests needed for package export resolution or project-local TypeScript version metadata.
- JSON/JSONC TypeScript configuration and recognized framework configuration source needed for static literal extraction.
- Existing generated evidence such as TanStack `routeTree.gen.*`.

Out-of-root symlinks and unreadable files are rejected. Source inventory failures are explicit skipped coverage; unavailable optional metadata is treated as absent or produces a role-specific diagnostic and must never cause module loading. The native TypeScript compiler receives only inventory-approved source bytes through an isolated virtual filesystem and a neutral generated project (`noResolve`, `noLib`, `noCheck`, empty `plugins` and `types`). The repository root, its tsconfig files, and its `node_modules` tree are not visible to the compiler process.

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
| Project-local TypeScript is outside the verified bundled version, is a range, or cannot be selected safely | Continue syntax-only analysis with bundled 7.0.2; do not load the local package | `web.project_typescript_not_loaded` with the observed version/range and manifest or lockfile source |
| Bundled compiler is missing or fails artifact/identity checks | Abort before emitting a partial graph; do not use another compiler | Fatal stderr error and non-zero worker exit; release preflight can fail earlier |
| Compiler crashes, its protocol fails, or its 30-second internal deadline expires | Close or kill the compiler, abort the scan, and emit no partial result | Fatal stderr error and non-zero worker exit; the core worker deadline remains an outer bound |
| Configuration contains a supported static literal | Apply that literal without evaluating the module | `web.static_config_literal_applied` |
| Configuration contains a dynamic value or executable hook | Ignore the value/hook; do not guess a resolved value | `web.static_config_unresolved` or `web.static_config_runtime_ignored`, plus `web.executable_config_not_executed`; unresolved input reduces completeness where applicable |
| A required workspace manifest, supported lockfile, recognized config, or inventoried source cannot be read or parsed safely | Skip the affected interpretation instead of assuming success | A bounded file-specific diagnostic and incomplete coverage accounting |
| Optional installed-package metadata is absent, malformed, unreadable, or outside the root | Treat the metadata as unavailable; never load package code to recover it | Resolution remains candidate/unresolved where applicable; no compiler selection change |

The absence of a project-local compiler is normal, not an error. A detected local compiler never changes the selected source or version. Fatal compiler failures do not produce protocol diagnostics because the worker intentionally does not publish a partial event stream; callers must preserve stderr and the exit status.

## Future TypeChecker acceptance matrix

TypeChecker support must remain disabled until its implementation passes the following matrix on every supported release platform. Adding it must not silently change the `bundled-only` compiler decision; any future project-local execution mode requires a separate threat-model decision and an explicit, non-safe profile.

| Fixture | Required assertion before TypeChecker can be enabled |
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

## Static coverage

Static coverage includes npm/pnpm/Yarn/Bun workspace and lockfile discovery (including `.pnp.data.json` without loading `.pnp.cjs`), TypeScript/JavaScript ESM and CommonJS dependency sites, `tsconfig.json`/`jsconfig.json` path aliases, conditional workspace package exports, and filesystem routes for Next.js, Astro, TanStack Router, and TanStack Start. Existing TanStack `routeTree.gen.*` files are treated as generated evidence. Production package edges retain dependency/peer/optional kinds and exclude dev-only manifest declarations.

The bundled TypeScript 7.0.2 lexical API is used for deterministic dependency inventory and context-aware import/require recognition. In addition, one pinned native TypeScript 7.0.2 compiler process parses every `.ts`, `.tsx`, `.mts`, `.cts`, `.js`, `.jsx`, `.mjs`, and `.cjs` file per scan. Only syntactic diagnostics are requested. Malformed source is therefore reported as unsupported syntax instead of being silently treated as complete.

Release archives keep the native compiler and its standard library tree under `libexec/typescript/lib`. The release manifest pins the component version, entry point, and canonical whole-tree SHA-256, so the `depgraph` core launcher rejects missing, added, symlinked, or modified files before the Web worker starts. Direct worker execution trusts its adjacent installation and is intended for protocol development; the verified safe-scan integrity contract requires launching through `depgraph`.

Astro frontmatter is parsed by the bundled Astro compiler 4.0.0; the release directory must keep `astro.wasm` next to `worker.mjs`. If compiler positions are unavailable, the worker falls back to a source tokenizer and emits heuristic evidence plus a diagnostic.

`DEPGRAPH_PROFILE_CONFIG` accepts the core-provided JSON object `{ "web_environments": [...] }`. Values are normalized, deduplicated, and sorted into the stable profile identity and canonical edge/site conditions; the default is production browser + server.

Type checking, plugin-defined virtual modules, and code-based route construction remain unresolved or diagnostic-only in safe mode.
