import { writeFile } from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";

const root = process.cwd();
const secret = ["ASTRO", "BUILD", "FIXTURE", "SECRET"].join("_");
const observerPath = process.env.DEPGRAPH_OBSERVER;
if (!observerPath) process.exit(81);
const { default: createObserver } = await import(pathToFileURL(observerPath).href);
const integration = createObserver({ repoRoot: root });
const route = {
  route: "/",
  pathname: "/",
  pattern: "/",
  patternRegex: /^\/$/,
  entrypoint: "src/pages/index.astro",
  params: [],
  segments: [[{ content: "", dynamic: false, spread: false }]],
  type: "page",
  isPrerendered: true,
  origin: "project",
};
const dynamicRoute = {
  route: "/generated/[slug]",
  pathname: undefined,
  pattern: "/generated/[slug]",
  patternRegex: /^\/generated\/([^/]+?)\/?$/,
  entrypoint: "src/pages/blog/[slug].astro",
  params: ["slug"],
  segments: [
    [{ content: "generated", dynamic: false, spread: false }],
    [{ content: "slug", dynamic: true, spread: false }],
  ],
  type: "page",
  isPrerendered: false,
  origin: "integration",
};
const endpointRoute = {
  route: "/api/status",
  pathname: "/api/status",
  pattern: "/api/status",
  patternRegex: /^\/api\/status\/?$/,
  entrypoint: "src/pages/api/status.ts",
  params: [],
  segments: [
    [{ content: "api", dynamic: false, spread: false }],
    [{ content: "status", dynamic: false, spread: false }],
  ],
  type: "endpoint",
  isPrerendered: false,
  origin: "project",
};
await integration.hooks["astro:config:done"]({
  config: { output: "static", base: "/", trailingSlash: "ignore", integrations: [integration] },
});
await integration.hooks["astro:routes:resolved"]({ routes: [route, dynamicRoute, endpointRoute] });
for (const environment of ["browser", "server"]) {
  let plugin;
  await integration.hooks["astro:build:setup"]({
    target: environment === "browser" ? "client" : "server",
    updateConfig(value) { plugin = value.plugins[0]; },
  });
  const source = path.join(root, "src/pages/index.astro");
  const dynamicSource = path.join(root, "src/pages/blog/[slug].astro");
  const endpointSource = path.join(root, "src/pages/api/status.ts");
  const moduleIds = environment === "browser"
    ? [source]
    : [source, dynamicSource, endpointSource];
  const context = {
    environment: { name: environment },
    meta: { viteVersion: "7.0.6", rollupVersion: "4.0.0", watchMode: false },
    getModuleIds: () => moduleIds.values(),
    getModuleInfo: () => ({ importedIds: [], dynamicallyImportedIds: [], isEntry: true }),
  };
  plugin.configResolved({
    mode: "production",
    base: "/",
    build: { ssr: environment === "server", outDir: path.join(root, "dist", environment) },
    plugins: [plugin],
  });
  plugin.buildStart.call(context);
  plugin.generateBundle.call(context, {}, {
    [`${environment}/entry.mjs`]: {
      type: "chunk",
      fileName: `${environment}/entry.mjs`,
      code: `export const secret = ${JSON.stringify(secret)}`,
      isEntry: true,
      modules: Object.fromEntries(moduleIds.map((id) => [id, {}])),
      imports: [], dynamicImports: [],
      viteMetadata: { importedAssets: new Set(), importedCss: new Set() },
    },
    ...(environment === "server" ? {
      "server/dynamic.mjs": {
        type: "chunk",
        fileName: "server/dynamic.mjs",
        code: "export const dynamicPage = true",
        isEntry: true,
        modules: { [dynamicSource]: {} },
        imports: [], dynamicImports: [],
        viteMetadata: { importedAssets: new Set(), importedCss: new Set() },
      },
      "server/endpoint.mjs": {
        type: "chunk",
        fileName: "server/endpoint.mjs",
        code: "export const endpoint = true",
        isEntry: true,
        modules: { [endpointSource]: {} },
        imports: [], dynamicImports: [],
        viteMetadata: { importedAssets: new Set(), importedCss: new Set() },
      },
    } : {}),
  });
}
await integration.hooks["astro:build:ssr"]({
  manifest: { routes: [route, dynamicRoute, endpointRoute], entryModules: {} },
});
await integration.hooks["astro:build:generated"]({
  routeToHeaders: new Map([[route, {}], [dynamicRoute, {}], [endpointRoute, {}]]),
});
await integration.hooks["astro:build:done"]({
  pages: [{ pathname: "/", secret }],
  dir: pathToFileURL(path.join(root, "dist")),
  assets: new Map([["/", [pathToFileURL(path.join(root, "dist", "index.html"))]]]),
});
await writeFile(path.join(process.env.DEPGRAPH_OUTPUT_DIR, "PROJECT_CODE_EXECUTED"), "astro", "utf8");
