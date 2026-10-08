import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, realpath, symlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { scan } from "../src/scanner";
import { walkFiles } from "../src/fs";
import { ModuleResolver } from "../src/imports";
import { discoverWorkspace } from "../src/workspace";
import { loadExternalDeclarations } from "../src/external-declarations";

async function fixture(root: string, declarations: boolean): Promise<void> {
  const sources: Record<string, string> = {
    "package.json": JSON.stringify({ name: "fixture", dependencies: { library: "1.0.0" } }),
    "package-lock.json": JSON.stringify({ lockfileVersion: 3, packages: { "": { dependencies: { library: "1.0.0" } }, "node_modules/library": { version: "1.0.0" } } }),
    "index.ts": `import { create, useState, chain } from 'library';
const client = create();
client.run();
const state = useState();
state.update();
chain<string>().map(value => value).finish();
`,
    "node_modules/library/package.json": JSON.stringify({ name: "library", version: "1.0.0", exports: { ".": { types: "./index.d.ts", default: "./index.js" } } }),
    "node_modules/library/index.js": "throw new Error('Project code must never run');",
  };
  if (declarations) {
    sources["node_modules/library/index.d.ts"] = `import type { Client, State, Chain } from './types.js';
export declare function create(): Client;
export declare function useState(): State;
export declare function chain<T>(): Chain<T>;
`;
    sources["node_modules/library/types.d.ts"] = `export interface Client { run(): void; }
export interface State { update(): void; }
export interface Chain<T> { map<U>(callback: (value: T) => U): Chain<U>; finish(): T; }
`;
  }
  for (const [relative, source] of Object.entries(sources)) {
    await mkdir(path.dirname(path.join(root, relative)), { recursive: true });
    await writeFile(path.join(root, relative), source);
  }
}

function calls(model: Awaited<ReturnType<typeof scan>>) {
  return model.sites.filter((site) => site.kind === "call").map((site) => ({
    specifier: site.specifier, status: site.resolution_status, precision: site.precision, reason: site.reason,
    targets: site.target_ids.map((id) => model.nodes.find((node) => node.id === id)?.display_name),
  }));
}

test("bounded declarations resolve returned objects, hook results, and generic chains to the external package", async (context) => {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), "depgraph-external-types-")));
  context.after(async () => rm(root, { recursive: true, force: true }));
  await fixture(root, false);
  const missing = await scan(root, await walkFiles(root));
  const indirect = ["client.run", "state.update", "chain<string>().map", "chain<string>().map(value => value).finish"];
  assert.ok(calls(missing).some((call) => call.status === "unresolved"), JSON.stringify(calls(missing)));
  await fixture(root, true);
  const model = await scan(root, await walkFiles(root));
  const actual = calls(model);
  for (const name of indirect) {
    const call = actual.find((item) => item.specifier === name);
    assert.equal(call?.status, "external", JSON.stringify(actual));
    assert.equal(call?.precision, "exact", JSON.stringify(actual));
    assert.equal(call?.targets.length, 1);
    assert.match(call?.targets[0] ?? "", /^package:npm:library@1\.0\.0#/u);
  }
  assert.ok(!actual.some((call) => call.targets.some((target) => target?.startsWith("typescript:stdlib:"))));
  assert.ok(!model.nodes.some((node) => node.properties.source_path?.toString().includes("node_modules")));
});

async function loader(root: string, limits?: Parameters<typeof loadExternalDeclarations>[3]) {
  const files = await walkFiles(root);
  const workspace = await discoverWorkspace(root, files);
  const resolver = await ModuleResolver.create(workspace, files);
  return await loadExternalDeclarations(root, resolver, [{ sourceFile: path.join(root, "index.ts"), specifier: "library" }], limits);
}

test("declaration bounds and missing references report incomplete context without reading runtime code", async (context) => {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), "depgraph-external-bounds-")));
  context.after(async () => rm(root, { recursive: true, force: true }));
  await fixture(root, true);
  const limited = await loader(root, { files: 1, bytes: 4096, fileBytes: 4096, requests: 10 });
  assert.equal(limited.files.size, 1);
  assert.ok(limited.issues.some((issue) => issue.reason === "external_declaration_file_limit"));
  const bytes = await loader(root, { files: 10, bytes: 8, fileBytes: 8, requests: 10 });
  assert.equal(bytes.files.size, 0);
  assert.ok(bytes.issues.some((issue) => issue.reason === "external_declaration_unreadable_or_byte_limit"));
  await rm(path.join(root, "node_modules/library/types.d.ts"));
  const missing = await loader(root);
  assert.ok(missing.issues.some((issue) => issue.reason === "external_declaration_reference_unavailable"));
  assert.ok([...missing.files.keys()].every((file) => file.endsWith(".d.ts")));
});

test("pnpm in-root symlinks and declaration references stay confined", async (context) => {
  const parent = await realpath(await mkdtemp(path.join(os.tmpdir(), "depgraph-external-pnpm-")));
  context.after(async () => rm(parent, { recursive: true, force: true }));
  const root = path.join(parent, "repo");
  await fixture(root, true);
  const store = path.join(root, "node_modules/.pnpm/library@1.0.0/node_modules/library");
  await mkdir(path.dirname(store), { recursive: true });
  const { rename } = await import("node:fs/promises");
  await rename(path.join(root, "node_modules/library"), store);
  await symlink(".pnpm/library@1.0.0/node_modules/library", path.join(root, "node_modules/library"));
  const loaded = await loader(root);
  assert.equal(loaded.files.size, 2);
  assert.ok([...loaded.files.keys()].every((file) => file.startsWith("node_modules/.pnpm/")));
  await writeFile(path.join(parent, "outside.d.ts"), "declare global { const secret: string; }");
  await rm(path.join(store, "types.d.ts"));
  await symlink(path.join(parent, "outside.d.ts"), path.join(store, "types.d.ts"));
  const escaped = await loader(root);
  assert.equal(escaped.files.size, 1);
  assert.ok(escaped.issues.some((issue) => issue.reason === "external_declaration_reference_unavailable"));
});

test("different import and require type conditions are withheld", async (context) => {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), "depgraph-external-conditions-")));
  context.after(async () => rm(root, { recursive: true, force: true }));
  await fixture(root, true);
  await writeFile(path.join(root, "node_modules/library/package.json"), JSON.stringify({ name: "library", version: "1.0.0", exports: { ".": { import: { types: "./index.d.ts" }, require: { types: "./types.d.ts" } } } }));
  assert.equal((await loader(root)).files.size, 0);
});

test("loaded declarations cannot bypass another subpath's incompatible exports", async (context) => {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), "depgraph-external-no-bypass-")));
  context.after(async () => rm(root, { recursive: true, force: true }));
  await fixture(root, true);
  await writeFile(path.join(root, "node_modules/library/package.json"), JSON.stringify({ name: "library", version: "1.0.0", exports: {
    ".": { import: { types: "./types.d.ts" }, require: { types: "./index.d.ts" } },
    "./public": { types: "./index.d.ts" },
  } }));
  await writeFile(path.join(root, "index.ts"), "import { create as allowed } from 'library/public';\nimport { create as blocked } from 'library';\nallowed().run();\nblocked().run();\n");
  const model = await scan(root, await walkFiles(root));
  const actual = calls(model);
  assert.equal(actual.find((call) => call.specifier === "allowed().run")?.status, "external", JSON.stringify(actual));
  assert.equal(actual.find((call) => call.specifier === "blocked().run")?.status, "unresolved", JSON.stringify(actual));
});

test("installed @types declarations preserve the runtime package boundary", async (context) => {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), "depgraph-external-at-types-")));
  context.after(async () => rm(root, { recursive: true, force: true }));
  await fixture(root, false);
  await writeFile(path.join(root, "node_modules/library/package.json"), JSON.stringify({ name: "library", version: "1.0.0", exports: { ".": "./index.js" } }));
  await mkdir(path.join(root, "node_modules/@types/library"), { recursive: true });
  await writeFile(path.join(root, "node_modules/@types/library/package.json"), JSON.stringify({ name: "@types/library", version: "1.0.1", types: "index.d.ts" }));
  await writeFile(path.join(root, "node_modules/@types/library/index.d.ts"), "export declare function create(): { run(): string };\n");
  await writeFile(path.join(root, "index.ts"), "import { create } from 'library'; create().run();");
  const model = await scan(root, await walkFiles(root));
  const call = calls(model).find((item) => item.specifier === "create().run");
  assert.equal(call?.status, "external", JSON.stringify(calls(model)));
  assert.match(call?.targets[0] ?? "", /^package:npm:library@1\.0\.0#/u);
});


test("declaration issue counters match distinct emitted diagnostics", async (context) => {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), "depgraph-external-issue-count-")));
  context.after(async () => rm(root, { recursive: true, force: true }));
  await fixture(root, true);
  await writeFile(path.join(root, "node_modules/library/index.d.ts"), "import './missing-a.js'; import './types.js'; export declare function create(): unknown;");
  await writeFile(path.join(root, "node_modules/library/types.d.ts"), "import './missing-b.js'; export interface Client { run(): void; }");
  const model = await scan(root, await walkFiles(root));
  const issues = model.diagnostics.filter((diagnostic) => diagnostic.properties?.typescript_dependency_issue === true || diagnostic.properties?.typescript_definition_issue === true);
  assert.equal(model.typeScriptProject.semanticIssues, issues.length);
  assert.equal(model.diagnostics.filter((diagnostic) => diagnostic.properties?.reason === "external_declaration_reference_unavailable").length, 2);
  assert.ok(!model.coverage.completeness.includes("semantic-complete"));
});


test("relative source imports and duplicate package probes do not exhaust the declaration request budget", async (context) => {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), "depgraph-external-requests-")));
  context.after(async () => rm(root, { recursive: true, force: true }));
  await fixture(root, true);
  const files = await walkFiles(root);
  const workspace = await discoverWorkspace(root, files);
  const resolver = await ModuleResolver.create(workspace, files);
  const requests = Array.from({ length: 30 }, (_, index) => [
    { sourceFile: path.join(root, `source-${index}.ts`), specifier: `./relative-${index}` },
    { sourceFile: path.join(root, `source-${index}.ts`), specifier: "library" },
  ]).flat();
  const loaded = await loadExternalDeclarations(root, resolver, requests, { files: 10, bytes: 4096, fileBytes: 4096, requests: 2 });
  assert.equal(loaded.files.size, 2);
  assert.deepEqual(loaded.issues, []);
  assert.deepEqual(Object.keys(loaded.paths), ["library"]);
});
