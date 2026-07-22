import { writeFile } from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";

const root = process.cwd();
const secret = ["START", "BUILD", "FIXTURE", "SECRET"].join("_");
const observerPath = process.env.DEPGRAPH_OBSERVER;
if (!observerPath) process.exit(81);
const { default: createObserver } = await import(pathToFileURL(observerPath).href);
const plugin = createObserver({ repoRoot: root });
plugin.configResolved({
  mode: "production",
  base: "/",
  environments: { client: {}, ssr: {} },
  plugins: [{ name: "tanstack-start-core:config" }, plugin],
});
const source = path.join(root, "src/server/account.ts");
const provider = `${source}?tss-serverfn-split`;
for (const environment of ["client", "ssr"]) {
  const virtual = "\0virtual:tanstack-start-server-fn-resolver";
  const moduleIds = environment === "client" ? [source] : [source, provider, virtual];
  const context = {
    environment: { name: environment },
    meta: { viteVersion: "7.0.6", rollupVersion: "4.0.0", watchMode: false },
    getModuleIds: () => moduleIds.values(),
    getModuleInfo: (id) => ({
      importedIds: id === virtual ? [provider] : [],
      dynamicallyImportedIds: [],
      isEntry: id === source || id === virtual,
    }),
  };
  plugin.buildStart.call(context);
  if (environment === "client") {
    plugin.transform.call(context, 'const getAccount = createClientRpc("rpc")', source);
  } else {
    plugin.transform.call(context, 'const getAccount = createSsrRpc("rpc")', source);
    plugin.transform.call(
      context,
      `const extracted = createServerRpc({ id: "rpc", name: "getAccount", filename: "src/server/account.ts" }, () => ${JSON.stringify(secret)})`,
      provider,
    );
    plugin.transform.call(
      context,
      'const manifest = { "rpc": { functionName: "getAccount_createServerFn_handler" } }',
      virtual,
    );
  }
  plugin.generateBundle.call(context, {}, {
    [`${environment}/entry.mjs`]: {
      type: "chunk",
      fileName: `${environment}/entry.mjs`,
      code: `export const secret = ${JSON.stringify(secret)}`,
      isEntry: true,
      modules: Object.fromEntries(moduleIds.map((id) => [id, {}])),
      imports: [], dynamicImports: [],
    },
  });
  await plugin.closeBundle.call(context);
}
await writeFile(path.join(process.env.DEPGRAPH_OUTPUT_DIR, "PROJECT_CODE_EXECUTED"), "start", "utf8");
