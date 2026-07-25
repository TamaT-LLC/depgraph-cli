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
await integration.hooks["astro:config:done"]({
  config: { output: "static", base: "/", trailingSlash: "ignore", integrations: [integration] },
});
await integration.hooks["astro:routes:resolved"]({ routes: [route] });
for (const environment of ["browser", "server"]) {
  let plugin;
  await integration.hooks["astro:build:setup"]({
    target: environment === "browser" ? "client" : "server",
    updateConfig(value) { plugin = value.plugins[0]; },
  });
  const source = path.join(root, "src/pages/index.astro");
  const context = {
    environment: { name: environment },
    meta: { viteVersion: "7.0.6", rollupVersion: "4.0.0", watchMode: false },
    getModuleIds: () => [source].values(),
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
      modules: { [source]: {} },
      imports: [], dynamicImports: [],
      viteMetadata: { importedAssets: new Set(), importedCss: new Set() },
    },
  });
}
await integration.hooks["astro:build:ssr"]({
  manifest: { routes: [route], entryModules: {} },
});
await integration.hooks["astro:build:generated"]({
  routeToHeaders: new Map([[route, {}]]),
});
await integration.hooks["astro:build:done"]({
  pages: [{ pathname: "/", secret }],
  dir: pathToFileURL(path.join(root, "dist")),
  assets: new Map([["/", [pathToFileURL(path.join(root, "dist", "index.html"))]]]),
});
await writeFile(path.join(process.env.DEPGRAPH_OUTPUT_DIR, "PROJECT_CODE_EXECUTED"), "astro", "utf8");
