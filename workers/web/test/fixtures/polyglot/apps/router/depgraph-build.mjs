import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";

const root = process.cwd();
const secret = ["ROUTER", "BUILD", "FIXTURE", "SECRET"].join("_");
const observerPath = process.env.DEPGRAPH_OBSERVER;
if (!observerPath) process.exit(81);
const { default: createObserver } = await import(pathToFileURL(observerPath).href);
const generator = { name: "tanstack:router-generator" };
const plugin = createObserver({
  repoRoot: root,
  basePath: "/router",
  generatedRouteTree: "build-route-tree.txt",
  existingVitePlugins: [generator],
});
await plugin.configResolved({
  root,
  mode: "production",
  base: "/router",
  plugins: [generator, plugin],
});
const relativeModules = [
  "build-route-tree.txt",
  "src/routes/__root.tsx",
  "src/routes/posts.$postId.tsx",
  "src/routes/posts.lazy.tsx",
  "src/virtual/generated-only.tsx",
];
const moduleIds = relativeModules.map((relative) => path.join(root, relative));
const context = {
  environment: { name: "client" },
  meta: { viteVersion: "7.2.2", rollupVersion: "4.53.3", watchMode: false },
  getModuleIds: () => moduleIds.values(),
  getModuleInfo: (id) => ({
    importedIds: id === moduleIds[0]
      ? [moduleIds[1], moduleIds[2], moduleIds[4]]
      : [],
    dynamicallyImportedIds: id === moduleIds[0] ? [moduleIds[3]] : [],
    isEntry: id === moduleIds[0],
  }),
};
plugin.buildStart.call(context);
for (const id of moduleIds) {
  plugin.transform.call(context, await readFile(id, "utf8"), id);
}
plugin.generateBundle.call(context, {}, {
  "assets/router.js": {
    type: "chunk",
    fileName: "assets/router.js",
    code: `export const secret = ${JSON.stringify(secret)}`,
    isEntry: true,
    modules: Object.fromEntries(moduleIds.map((id) => [id, {}])),
    imports: [],
    dynamicImports: [],
  },
});
await plugin.closeBundle.call(context);
await writeFile(path.join(process.env.DEPGRAPH_OUTPUT_DIR, "PROJECT_CODE_EXECUTED"), "router", "utf8");
