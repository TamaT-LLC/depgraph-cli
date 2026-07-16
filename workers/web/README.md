# depgraph web worker

The release entry point is:

```sh
node dist/worker.mjs --root <repository> --scan-id <id>
```

The worker writes protocol `1.0` NDJSON to stdout and operational logs to stderr. It performs a safe, read-only scan: project configuration, plugins, package managers, scripts, and project-local TypeScript are never loaded or executed.

Static coverage includes npm/pnpm/Yarn/Bun workspace and lockfile discovery (including `.pnp.data.json` without loading `.pnp.cjs`), TypeScript/JavaScript ESM and CommonJS dependency sites, `tsconfig.json`/`jsconfig.json` path aliases, conditional workspace package exports, and filesystem routes for Next.js, Astro, TanStack Router, and TanStack Start. Existing TanStack `routeTree.gen.*` files are treated as generated evidence. Production package edges retain dependency/peer/optional kinds and exclude dev-only manifest declarations.

The bundled TypeScript 7.0.2 lexical API is used for deterministic dependency inventory and context-aware import/require recognition. In addition, one pinned native TypeScript 7.0.2 compiler process parses every `.ts`, `.tsx`, `.mts`, `.cts`, `.js`, `.jsx`, `.mjs`, and `.cjs` file per scan. It receives only inventory-approved source bytes through an isolated virtual filesystem and a neutral generated project (`noResolve`, `noLib`, `noCheck`); repository tsconfig files, plugins, package code, and project-local TypeScript are not visible to it. Only syntactic diagnostics are requested. Malformed source is therefore reported as unsupported syntax instead of being silently treated as complete.

Release archives keep the native compiler and its standard library tree under `libexec/typescript/lib`. The release manifest pins the component version, entry point, and canonical whole-tree SHA-256, so missing, added, symlinked, or modified files fail closed before the Web worker starts. Development resolution starts at this worker's own pinned `typescript/package.json` and never searches the scan root. The compiler has a 30-second internal deadline; the core's worker deadline still applies to the complete scan.

Astro frontmatter is parsed by the bundled Astro compiler 4.0.0; the release directory must keep `astro.wasm` next to `worker.mjs`. If compiler positions are unavailable, the worker falls back to a source tokenizer and emits heuristic evidence plus a diagnostic.

`DEPGRAPH_PROFILE_CONFIG` accepts the core-provided JSON object `{ "web_environments": [...] }`. Values are normalized, deduplicated, and sorted into the stable profile identity and canonical edge/site conditions; the default is production browser + server.

Safe config support is deliberately limited to static literals such as Next.js `basePath`/`pageExtensions`, Astro `base`/`srcDir`, and TanStack `basepath`/`routesDirectory`/`generatedRouteTree`. Invalid manifests/configs and unreadable metadata emit diagnostics and remove syntax-complete coverage; dynamic values and executable hooks are ignored with diagnostics. Type checking, plugin-defined virtual modules, and code-based route construction remain unresolved or diagnostic-only in safe mode.
