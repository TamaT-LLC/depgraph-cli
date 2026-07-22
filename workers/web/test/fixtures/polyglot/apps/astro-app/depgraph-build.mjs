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
  pathname: "/",
  pattern: /^\/$/,
  component: "src/pages/index.astro",
  type: "page",
  prerender: true,
  origin: "project",
};
await integration.hooks["astro:config:done"]({
  config: { output: "static", base: "/", trailingSlash: "ignore", integrations: [integration] },
});
await integration.hooks["astro:routes:resolved"]({ routes: [route] });
let plugin;
await integration.hooks["astro:build:setup"]({
  updateConfig(value) { plugin = value.plugins[0]; },
});
for (const environment of ["browser", "server"]) {
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
await integration.hooks["astro:build:done"]({
  pages: [{ pathname: "/", secret }],
  dir: new URL("file:///ignored/"),
  assets: new Map([[route, ["browser/entry.mjs"]]]),
});
await writeFile(path.join(process.env.DEPGRAPH_OUTPUT_DIR, "PROJECT_CODE_EXECUTED"), "astro", "utf8");
