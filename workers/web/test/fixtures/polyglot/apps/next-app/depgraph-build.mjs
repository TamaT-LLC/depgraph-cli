import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";

const root = process.cwd();
const secret = ["NEXT", "BUILD", "FIXTURE", "SECRET"].join("_");
const observerPath = process.env.DEPGRAPH_OBSERVER;
if (!observerPath || observerPath !== process.env.NEXT_ADAPTER_PATH) process.exit(81);
const { default: observer } = await import(pathToFileURL(observerPath).href);
const output = path.join(root, ".next/server/app/page.js");
const dynamicOutput = path.join(root, ".next/server/app/generated/[id]/page.js");
const asset = path.join(root, ".next/server/chunks/shared.js");
await mkdir(path.dirname(output), { recursive: true });
await mkdir(path.dirname(dynamicOutput), { recursive: true });
await mkdir(path.dirname(asset), { recursive: true });
await writeFile(output, `export const privateToken = ${JSON.stringify(secret)}\n`, "utf8");
await writeFile(dynamicOutput, `export const dynamicToken = ${JSON.stringify(secret)}\n`, "utf8");
await writeFile(asset, "export const shared = true\n", "utf8");
const config = await observer.modifyConfig?.({
  output: "standalone",
  basePath: "",
  trailingSlash: false,
  reactStrictMode: true,
  adapterPath: observerPath,
  env: { API_TOKEN: secret },
}, { phase: "phase-production-build", nextVersion: "16.2.10" });
await observer.onBuildComplete({
  nextVersion: "16.2.10",
  buildId: "private-build-id",
  projectDir: root,
  repoRoot: root,
  distDir: path.join(root, ".next"),
  config,
  routing: {
    beforeMiddleware: [],
    beforeFiles: [],
    afterFiles: [],
    dynamicRoutes: [{
      source: "/generated/[id]",
      sourceRegex: "^/generated/([^/]+?)(?:/)?$",
      destination: "/generated/$1",
    }],
    onMatch: [],
    fallback: [],
    shouldNormalizeNextData: false,
  },
  outputs: {
    pages: [], pagesApi: [], appRoutes: [], prerenders: [], staticFiles: [],
    appPages: [
      {
        id: "private-output-id",
        type: "APP_PAGE",
        pathname: "/",
        sourcePage: "/",
        filePath: output,
        runtime: "nodejs",
        assets: { ".next/server/chunks/shared.js": asset },
        wasmAssets: {},
        config: { env: { API_SECRET: secret } },
      },
      {
        id: "private-dynamic-output-id",
        type: "APP_PAGE",
        pathname: "/generated/[id]",
        sourcePage: "/generated/[id]/page",
        filePath: dynamicOutput,
        runtime: "nodejs",
        assets: {},
        wasmAssets: {},
        config: {},
      },
    ],
  },
});
await writeFile(path.join(process.env.DEPGRAPH_OUTPUT_DIR, "PROJECT_CODE_EXECUTED"), "next", "utf8");
