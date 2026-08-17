import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import {
  extractDependencies,
  extractPotentialTypeScriptModuleSpecifiers,
  ModuleResolver,
  parseStaticJsonc,
  type RawDependency,
} from "../src/imports";
import { analyzeTypeScriptProject } from "../src/typescript-compiler";
import { canonicalizeCondition, WEB_CONDITION } from "../src/types";
import { discoverWorkspace } from "../src/workspace";

function rawDependency(
  specifier: string,
  options: { typeOnly?: boolean; useTypesCondition?: boolean; kind?: string; resolutionMode?: "import" | "require" } = {},
): RawDependency {
  return {
    kind: options.kind ?? "import",
    edgeKind: "imports",
    specifier,
    literal: true,
    typeOnly: options.typeOnly ?? false,
    ...(options.useTypesCondition === undefined ? {} : { useTypesCondition: options.useTypesCondition }),
    ...(options.resolutionMode === undefined ? {} : { resolutionMode: options.resolutionMode }),
    evidence: {
      kind: "source",
      extractor: "test",
      extractor_version: "1",
      path: "index.ts",
      start_line: 1,
      start_column: 1,
      end_line: 1,
      end_column: 1,
    },
  };
}

test("static JSONC parsing preserves string content and rejects unterminated comments", () => {
  assert.deepEqual(
    parseStaticJsonc('\uFEFF{/* leading */"compilerOptions":{"paths":{"literal":[",}",],},},}'),
    { compilerOptions: { paths: { literal: [",}"] } } },
  );
  assert.equal(parseStaticJsonc('{"compilerOptions": {}} /* unterminated'), null);
  assert.equal(parseStaticJsonc('["top-level arrays are not configs"]'), null);
});

test("static JSONC trailing-comma normalization stays bounded for large configs", { timeout: 3_000 }, () => {
  const values = Array.from({ length: 100_000 }, (_, index) => index).join(",");
  const parsed = parseStaticJsonc(`{"values":[${values},],}`);
  const result = parsed?.values;
  assert.ok(Array.isArray(result));
  assert.equal(result.length, 100_000);
  assert.equal(result.at(-1), 99_999);
});

test("neutral path request inventory includes code strings and quoted JSDoc modules", () => {
  const source = [
    'import value from "code-module";',
    "/** @type {import('jsdoc-module').Value} */",
    "/** @import { Other } from \"tag-module\" */",
    "const ordinary = 'conservative-string';",
    "",
  ].join("\n");
  assert.deepEqual(extractPotentialTypeScriptModuleSpecifiers("index.ts", source), [
    "code-module",
    "conservative-string",
    "jsdoc-module",
    "tag-module",
  ]);
});

test("neutral path request inventory stays bounded across regular expressions", { timeout: 1_000 }, () => {
  const source = [
    "const heading = /^#\\s+/m;",
    "const link = /(?=^##\\s+)['\\\"]/m;",
    'import value from "after-regex";',
    "",
  ].join("\n");

  assert.deepEqual(
    extractPotentialTypeScriptModuleSpecifiers("index.ts", source),
    ["after-regex"],
  );
});

test("TypeScript path mappings preserve declaration order without locale-dependent sorting", async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "depgraph-web-path-ordering-"));
  context.after(async () => rm(root, { recursive: true, force: true }));
  await mkdir(path.join(root, "src"), { recursive: true });
  const files = ["package.json", "tsconfig.json", "src/broad.ts", "src/specific.ts"]
    .map((relative) => path.join(root, relative));
  await Promise.all([
    writeFile(files[0]!, JSON.stringify({ name: "path-ordering", version: "1.0.0" })),
    writeFile(files[1]!, JSON.stringify({
      compilerOptions: {
        baseUrl: ".",
        paths: {
          "@/*ä": ["src/broad.ts"],
          "@/*yä": ["src/specific.ts"],
        },
      },
    })),
    writeFile(files[2]!, "export const broad = true;\n"),
    writeFile(files[3]!, "export const specific = true;\n"),
  ]);
  const workspace = await discoverWorkspace(root, files);
  const originalLocaleCompare = String.prototype.localeCompare;
  String.prototype.localeCompare = (): number => {
    throw new Error("localeCompare must not order TypeScript path mappings");
  };
  try {
    const resolver = await ModuleResolver.create(workspace, files);
    assert.deepEqual(
      Object.keys(resolver.typeScriptStaticConfig().paths).filter((pattern) => pattern.startsWith("@/")),
      ["@/*ä", "@/*yä"],
    );
  } finally {
    String.prototype.localeCompare = originalLocaleCompare;
  }
});

test("owner-specific TypeScript paths never leak into the neutral compiler program", async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "depgraph-web-owner-path-isolation-"));
  context.after(async () => rm(root, { recursive: true, force: true }));
  await Promise.all([
    mkdir(path.join(root, "packages", "a", "src"), { recursive: true }),
    mkdir(path.join(root, "packages", "b", "src"), { recursive: true }),
  ]);
  const relatives = [
    "package.json",
    "packages/a/package.json",
    "packages/a/tsconfig.json",
    "packages/a/src/index.ts",
    "packages/a/src/private.ts",
    "packages/b/package.json",
    "packages/b/src/index.ts",
  ];
  const files = relatives.map((relative) => path.join(root, relative));
  await Promise.all([
    writeFile(files[0]!, JSON.stringify({ name: "owner-path-isolation", workspaces: ["packages/*"] })),
    writeFile(files[1]!, JSON.stringify({ name: "owner-path-a", version: "1.0.0" })),
    writeFile(files[2]!, JSON.stringify({ compilerOptions: { paths: { "@private/*": ["src/*"] } } })),
    writeFile(files[3]!, "export {}\n"),
    writeFile(files[4]!, "export interface PrivateType {}\n"),
    writeFile(files[5]!, JSON.stringify({ name: "owner-path-b", version: "1.0.0" })),
    writeFile(files[6]!, "export {}\n"),
  ]);
  const workspace = await discoverWorkspace(root, files);
  const resolver = await ModuleResolver.create(workspace, files);
  const ownerA = workspace.packages.find((record) => record.name === "owner-path-a")!;
  const ownerB = workspace.packages.find((record) => record.name === "owner-path-b")!;
  assert.ok(!Object.hasOwn(resolver.typeScriptStaticConfig().paths, "@private/*"));
  const ownerAUsagePaths = resolver.typeScriptStaticConfig([
    { sourceFile: files[3]!, specifier: "@private/private" },
  ]).paths;
  assert.ok(!Object.hasOwn(ownerAUsagePaths, "@private/*"));
  assert.deepEqual(ownerAUsagePaths["@private/private"], ["packages/a/src/private.ts"]);
  assert.ok(!Object.hasOwn(resolver.typeScriptStaticConfig([
    { sourceFile: files[3]!, specifier: "@private/private" },
    { sourceFile: files[6]!, specifier: "@private/private" },
  ]).paths, "@private/private"));
  assert.equal((await resolver.resolve(rawDependency("@private/private"), files[3]!, ownerA)).status, "resolved");
  const foreignResolution = await resolver.resolve(rawDependency("@private/private"), files[6]!, ownerB);
  assert.equal(foreignResolution.status, "external");
  assert.ok(foreignResolution.targets.every((target) => target.kind !== "file"));
});

test("TypeScript path mapping captures are inserted as literal text", async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "depgraph-web-path-literal-capture-"));
  context.after(async () => rm(root, { recursive: true, force: true }));
  await mkdir(path.join(root, "src"), { recursive: true });
  const files = ["package.json", "tsconfig.json", "index.ts", "src/$&.ts"]
    .map((relative) => path.join(root, relative));
  await Promise.all([
    writeFile(files[0]!, JSON.stringify({ name: "path-literal-capture", version: "1.0.0" })),
    writeFile(files[1]!, JSON.stringify({
      compilerOptions: { paths: { "@special/*": ["src/*"] } },
    })),
    writeFile(files[2]!, "export {};\n"),
    writeFile(files[3]!, "export const literalCapture = true;\n"),
  ]);
  const workspace = await discoverWorkspace(root, files);
  const resolver = await ModuleResolver.create(workspace, files);
  const owner = workspace.packages.find((record) => record.name === "path-literal-capture")!;
  const resolution = await resolver.resolve(rawDependency("@special/$&"), files[2]!, owner);
  assert.equal(
    resolution.targets[0]?.kind === "file" ? resolution.targets[0].absolutePath : null,
    files[3],
  );
});

test("neutral TypeScript paths require identical owner pattern order", async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "depgraph-web-owner-path-order-"));
  context.after(async () => rm(root, { recursive: true, force: true }));
  await Promise.all([
    mkdir(path.join(root, "packages", "a", "src"), { recursive: true }),
    mkdir(path.join(root, "packages", "a", "shared"), { recursive: true }),
    mkdir(path.join(root, "packages", "b", "src"), { recursive: true }),
  ]);
  const relatives = [
    "package.json",
    "packages/a/package.json",
    "packages/a/tsconfig.json",
    "packages/a/src/index.ts",
    "packages/a/shared/value.ts",
    "packages/a/shared/valuesuffix.ts",
    "packages/b/package.json",
    "packages/b/tsconfig.json",
    "packages/b/src/index.ts",
  ];
  const files = relatives.map((relative) => path.join(root, relative));
  await Promise.all([
    writeFile(files[0]!, JSON.stringify({ name: "owner-path-order", workspaces: ["packages/*"] })),
    writeFile(files[1]!, JSON.stringify({ name: "owner-path-order-a", version: "1.0.0" })),
    writeFile(files[2]!, JSON.stringify({ compilerOptions: { paths: {
      "@/*suffix": ["shared/*"],
      "@/*": ["shared/*"],
    } } })),
    writeFile(files[3]!, "export {};\n"),
    writeFile(files[4]!, "export interface Specific {}\n"),
    writeFile(files[5]!, "export interface Broad {}\n"),
    writeFile(files[6]!, JSON.stringify({ name: "owner-path-order-b", version: "1.0.0" })),
    writeFile(files[7]!, JSON.stringify({ compilerOptions: { paths: {
      "@/*": ["../a/shared/*"],
      "@/*suffix": ["../a/shared/*"],
    } } })),
    writeFile(files[8]!, "export {};\n"),
  ]);
  const workspace = await discoverWorkspace(root, files);
  const resolver = await ModuleResolver.create(workspace, files);
  const staticPaths = resolver.typeScriptStaticConfig().paths;
  assert.ok(!Object.hasOwn(staticPaths, "@/*suffix"));
  assert.ok(!Object.hasOwn(staticPaths, "@/*"));
  assert.ok(!Object.hasOwn(resolver.typeScriptStaticConfig([
    { sourceFile: files[3]!, specifier: "@/valuesuffix" },
    { sourceFile: files[8]!, specifier: "@/valuesuffix" },
  ]).paths, "@/valuesuffix"));
  const ownerA = workspace.packages.find((record) => record.name === "owner-path-order-a")!;
  const ownerB = workspace.packages.find((record) => record.name === "owner-path-order-b")!;
  const targetPath = (resolution: Awaited<ReturnType<ModuleResolver["resolve"]>>): string | null => (
    resolution.targets[0]?.kind === "file" ? resolution.targets[0].absolutePath : null
  );
  assert.equal(
    targetPath(await resolver.resolve(rawDependency("@/valuesuffix", { useTypesCondition: true }), files[3]!, ownerA)),
    files[4],
  );
  assert.equal(
    targetPath(await resolver.resolve(rawDependency("@/valuesuffix", { useTypesCondition: true }), files[8]!, ownerB)),
    files[5],
  );
});

test("workspace compiler hints cannot overlap any source-owner path alias", async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "depgraph-web-path-workspace-overlap-"));
  context.after(async () => rm(root, { recursive: true, force: true }));
  await Promise.all([
    mkdir(path.join(root, "packages", "a", "src"), { recursive: true }),
    mkdir(path.join(root, "packages", "a", "local"), { recursive: true }),
    mkdir(path.join(root, "packages", "b", "src"), { recursive: true }),
    mkdir(path.join(root, "packages", "shared"), { recursive: true }),
  ]);
  const relatives = [
    "package.json",
    "packages/a/package.json",
    "packages/a/tsconfig.json",
    "packages/a/src/index.ts",
    "packages/a/local/shared.ts",
    "packages/b/package.json",
    "packages/b/src/index.ts",
    "packages/shared/package.json",
    "packages/shared/index.ts",
  ];
  const files = relatives.map((relative) => path.join(root, relative));
  await Promise.all([
    writeFile(files[0]!, JSON.stringify({ name: "path-workspace-overlap", workspaces: ["packages/*"] })),
    writeFile(files[1]!, JSON.stringify({ name: "path-workspace-overlap-a", version: "1.0.0" })),
    writeFile(files[2]!, JSON.stringify({ compilerOptions: { paths: { "*": ["./local/*"] } } })),
    writeFile(files[3]!, "export {};\n"),
    writeFile(files[4]!, "export interface LocalShared {}\n"),
    writeFile(files[5]!, JSON.stringify({ name: "path-workspace-overlap-b", version: "1.0.0" })),
    writeFile(files[6]!, "export {};\n"),
    writeFile(files[7]!, JSON.stringify({
      name: "shared",
      version: "1.0.0",
      exports: "./index.ts",
    })),
    writeFile(files[8]!, "export interface WorkspaceShared {}\n"),
  ]);
  const workspace = await discoverWorkspace(root, files);
  const resolver = await ModuleResolver.create(workspace, files);
  const staticPaths = resolver.typeScriptStaticConfig().paths;
  assert.ok(!Object.hasOwn(staticPaths, "*"));
  assert.ok(!Object.hasOwn(staticPaths, "shared"));
  assert.ok(!Object.hasOwn(resolver.typeScriptStaticConfig([
    { sourceFile: files[3]!, specifier: "shared" },
    { sourceFile: files[6]!, specifier: "shared" },
  ]).paths, "shared"));
  const ownerA = workspace.packages.find((record) => record.name === "path-workspace-overlap-a")!;
  const ownerB = workspace.packages.find((record) => record.name === "path-workspace-overlap-b")!;
  const targetPath = (resolution: Awaited<ReturnType<ModuleResolver["resolve"]>>): string | null => (
    resolution.targets[0]?.kind === "file" ? resolution.targets[0].absolutePath : null
  );
  assert.equal(
    targetPath(await resolver.resolve(rawDependency("shared", { useTypesCondition: true }), files[3]!, ownerA)),
    files[4],
  );
  assert.equal(
    targetPath(await resolver.resolve(rawDependency("shared", { useTypesCondition: true }), files[6]!, ownerB)),
    files[8],
  );
});

test("workspace compiler hints require identical import and require type targets", async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "depgraph-web-workspace-phase-hint-"));
  context.after(async () => rm(root, { recursive: true, force: true }));
  await Promise.all([
    mkdir(path.join(root, "packages", "consumer", "src"), { recursive: true }),
    mkdir(path.join(root, "packages", "phase-split"), { recursive: true }),
  ]);
  const relatives = [
    "package.json",
    "packages/consumer/package.json",
    "packages/consumer/src/index.ts",
    "packages/phase-split/package.json",
    "packages/phase-split/import.ts",
    "packages/phase-split/require.ts",
    "packages/phase-split/stable.ts",
  ];
  const files = relatives.map((relative) => path.join(root, relative));
  await Promise.all([
    writeFile(files[0]!, JSON.stringify({ name: "workspace-phase-hint", workspaces: ["packages/*"] })),
    writeFile(files[1]!, JSON.stringify({ name: "workspace-phase-consumer", version: "1.0.0" })),
    writeFile(files[2]!, "export {};\n"),
    writeFile(files[3]!, JSON.stringify({
      name: "phase-split",
      version: "1.0.0",
      exports: {
        ".": {
          import: { types: "./import.ts", default: "./import.ts" },
          require: { types: "./require.ts", default: "./require.ts" },
        },
        "./stable": "./stable.ts",
      },
    })),
    writeFile(files[4]!, "export interface ImportType {}\n"),
    writeFile(files[5]!, "export interface RequireType {}\n"),
    writeFile(files[6]!, "export interface StableType {}\n"),
  ]);
  const workspace = await discoverWorkspace(root, files);
  const resolver = await ModuleResolver.create(workspace, files);
  const staticPaths = resolver.typeScriptStaticConfig().paths;
  assert.ok(!Object.hasOwn(staticPaths, "phase-split"));
  assert.deepEqual(staticPaths["phase-split/stable"], ["packages/phase-split/stable.ts"]);
  const owner = workspace.packages.find((record) => record.name === "workspace-phase-consumer")!;
  const targetPath = (resolution: Awaited<ReturnType<ModuleResolver["resolve"]>>): string | null => (
    resolution.targets[0]?.kind === "file" ? resolution.targets[0].absolutePath : null
  );
  assert.equal(
    targetPath(await resolver.resolve(rawDependency("phase-split", { useTypesCondition: true }), files[2]!, owner)),
    files[4],
  );
  assert.equal(
    targetPath(await resolver.resolve(rawDependency("phase-split", {
      kind: "import_equals",
      useTypesCondition: true,
    }), files[2]!, owner)),
    files[5],
  );
});

test("TypeScript paths use the nearest whole-option declaration and its config directory", async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "depgraph-web-path-extends-"));
  context.after(async () => rm(root, { recursive: true, force: true }));
  await mkdir(path.join(root, "configs", "targets"), { recursive: true });
  await mkdir(path.join(root, "src"), { recursive: true });
  const relatives = [
    "package.json",
    "tsconfig.json",
    "configs/base.json",
    "configs/targets/parent.ts",
    "src/child.ts",
    "index.ts",
  ];
  const files = relatives.map((relative) => path.join(root, relative));
  await Promise.all([
    writeFile(files[0]!, JSON.stringify({ name: "path-extends", version: "1.0.0" })),
    writeFile(files[1]!, JSON.stringify({
      extends: "./configs/base.json",
      compilerOptions: {
        baseUrl: "./ignored-by-ts7-paths",
        paths: { "@child": ["src/child"] },
      },
    })),
    writeFile(files[2]!, JSON.stringify({ compilerOptions: { paths: { "@parent": ["./targets/parent"] } } })),
    writeFile(files[3]!, "export const parent = true;\n"),
    writeFile(files[4]!, "export const child = true;\n"),
    writeFile(files[5]!, "export {};\n"),
  ]);
  const workspace = await discoverWorkspace(root, files);
  const resolver = await ModuleResolver.create(workspace, files);
  const owner = workspace.packages[0]!;
  const child = await resolver.resolve(rawDependency("@child"), files[5]!, owner);
  const parent = await resolver.resolve(rawDependency("@parent"), files[5]!, owner);
  assert.equal(child.status, "resolved");
  assert.equal(child.targets[0]?.kind, "file");
  assert.equal(child.targets[0]?.kind === "file" ? child.targets[0].absolutePath : null, files[4]);
  assert.equal(parent.status, "external");
  assert.equal(parent.precision, "heuristic");
  assert.equal(parent.targets[0]?.kind, "external_package");
  assert.equal(parent.targets[0]?.kind === "external_package" ? parent.targets[0].name : null, "@parent");
  assert.deepEqual(Object.keys(resolver.typeScriptStaticConfig().paths).filter((key) => key.startsWith("@")), ["@child"]);
});

test("TypeScript file substitutions and directory package entries select only the first valid file", async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "depgraph-web-file-substitution-"));
  context.after(async () => rm(root, { recursive: true, force: true }));
  await mkdir(path.join(root, "dir"), { recursive: true });
  const relatives = [
    "package.json",
    "tsconfig.json",
    "index.ts",
    "target.d.ts",
    "target.js",
    "component.ts",
    "component.jsx",
    "only.mts",
    "dir/package.json",
    "dir/entry.d.ts",
    "dir/index.ts",
    "dir/typings.d.ts",
    "data.json",
    "asset.md",
    "View.astro",
  ];
  const files = relatives.map((relative) => path.join(root, relative));
  await Promise.all([
    writeFile(files[0]!, JSON.stringify({ name: "file-substitution", version: "1.0.0" })),
    writeFile(files[1]!, JSON.stringify({ compilerOptions: { paths: {
      "@dir": ["dir"],
      "@query/*": ["*"],
      "@asset": ["asset.md"],
      "@multi/*/*": ["component.ts"],
      "@multi-replacement/*": ["component**.ts"],
    } } })),
    writeFile(files[2]!, "export {};\n"),
    writeFile(files[3]!, "export interface Target {}\n"),
    writeFile(files[4]!, "export const target = true;\n"),
    writeFile(files[5]!, "export const component = 'ts';\n"),
    writeFile(files[6]!, "export const component = 'jsx';\n"),
    writeFile(files[7]!, "export const only = true;\n"),
    writeFile(files[8]!, JSON.stringify({ typings: "typings.d.ts", types: "entry.d.ts", main: "index.ts" })),
    writeFile(files[9]!, "export interface DirectoryEntry {}\n"),
    writeFile(files[10]!, "export const directoryIndex = true;\n"),
    writeFile(files[11]!, "export interface PreferredDirectoryEntry {}\n"),
    writeFile(files[12]!, "{}\n"),
    writeFile(files[13]!, "# asset\n"),
    writeFile(files[14]!, "<div />\n"),
  ]);
  const workspace = await discoverWorkspace(root, files);
  const resolver = await ModuleResolver.create(workspace, files);
  const owner = workspace.packages[0]!;
  const targetPath = (resolution: Awaited<ReturnType<ModuleResolver["resolve"]>>): string | null => (
    resolution.targets[0]?.kind === "file" ? resolution.targets[0].absolutePath : null
  );
  assert.equal(targetPath(await resolver.resolve(rawDependency("./target"), files[2]!, owner)), files[3]);
  assert.equal(targetPath(await resolver.resolve(rawDependency("./component.jsx"), files[2]!, owner)), files[5]);
  assert.equal(targetPath(await resolver.resolve(rawDependency("./dir"), files[2]!, owner)), files[11]);
  assert.equal(targetPath(await resolver.resolve(rawDependency("@dir"), files[2]!, owner)), files[11]);
  assert.equal(targetPath(await resolver.resolve(rawDependency("./component?raw"), files[2]!, owner)), files[5]);
  assert.equal((await resolver.resolve(rawDependency("./component?raw", { useTypesCondition: true }), files[2]!, owner)).status, "unresolved");
  assert.equal(targetPath(await resolver.resolve(rawDependency("/component"), files[2]!, owner)), files[5]);
  assert.equal((await resolver.resolve(rawDependency("/component", { useTypesCondition: true }), files[2]!, owner)).status, "unresolved");
  assert.equal(targetPath(await resolver.resolve(rawDependency("@query/component?raw"), files[2]!, owner)), files[5]);
  assert.ok((await resolver.resolve(rawDependency("@query/component?raw", { useTypesCondition: true }), files[2]!, owner))
    .targets.every((target) => target.kind !== "file"));
  assert.equal(targetPath(await resolver.resolve(rawDependency("./data.json"), files[2]!, owner)), files[12]);
  assert.equal(targetPath(await resolver.resolve(rawDependency("./data"), files[2]!, owner)), files[12]);
  assert.equal(targetPath(await resolver.resolve(rawDependency("./asset.md"), files[2]!, owner)), files[13]);
  assert.equal(targetPath(await resolver.resolve(rawDependency("./View.astro"), files[2]!, owner)), files[14]);
  for (const specifier of ["./data.json", "./data", "./asset.md", "./View.astro", "@asset"]) {
    const semantic = await resolver.resolve(rawDependency(specifier, { useTypesCondition: true }), files[2]!, owner);
    assert.ok(semantic.targets.every((target) => target.kind !== "file"), specifier);
  }
  assert.ok((await resolver.resolve(rawDependency("@multi/a/b"), files[2]!, owner))
    .targets.every((target) => target.kind !== "file"));
  assert.ok(!Object.hasOwn(resolver.typeScriptStaticConfig().paths, "@multi-replacement/*"));
  assert.ok((await resolver.resolve(rawDependency("@multi-replacement/a"), files[2]!, owner))
    .targets.every((target) => target.kind !== "file"));
  assert.equal((await resolver.resolve(rawDependency("./only"), files[2]!, owner)).status, "unresolved");
});

test("legacy package fields follow runtime and effective-types precedence independently", async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "depgraph-web-legacy-entry-order-"));
  context.after(async () => rm(root, { recursive: true, force: true }));
  await Promise.all([
    mkdir(path.join(root, "packages", "all-fields"), { recursive: true }),
    mkdir(path.join(root, "packages", "runtime-fields"), { recursive: true }),
    mkdir(path.join(root, "packages", "query-fields"), { recursive: true }),
  ]);
  const relatives = [
    "package.json",
    "index.ts",
    "packages/all-fields/package.json",
    "packages/all-fields/typings.d.ts",
    "packages/all-fields/types.d.ts",
    "packages/all-fields/module.ts",
    "packages/all-fields/main.ts",
    "packages/runtime-fields/package.json",
    "packages/runtime-fields/module.ts",
    "packages/runtime-fields/main.ts",
    "packages/query-fields/package.json",
    "packages/query-fields/types.d.ts",
    "packages/query-fields/main.ts",
  ];
  const files = relatives.map((relative) => path.join(root, relative));
  await Promise.all([
    writeFile(files[0]!, JSON.stringify({
      name: "legacy-order-root",
      workspaces: ["packages/*"],
      dependencies: { "all-fields": "workspace:*", "runtime-fields": "workspace:*", "query-fields": "workspace:*" },
    })),
    writeFile(files[1]!, "export {};\n"),
    writeFile(files[2]!, JSON.stringify({
      name: "all-fields",
      version: "1.0.0",
      typings: "typings.d.ts",
      types: "types.d.ts",
      module: "module.ts",
      main: "main.ts",
    })),
    writeFile(files[3]!, "export interface TypingsEntry {}\n"),
    writeFile(files[4]!, "export interface TypesEntry {}\n"),
    writeFile(files[5]!, "export const moduleEntry = true;\n"),
    writeFile(files[6]!, "export const mainEntry = true;\n"),
    writeFile(files[7]!, JSON.stringify({
      name: "runtime-fields",
      version: "1.0.0",
      module: "module.ts",
      main: "main.ts",
    })),
    writeFile(files[8]!, "export const moduleEntry = true;\n"),
    writeFile(files[9]!, "export const mainEntry = true;\n"),
    writeFile(files[10]!, JSON.stringify({
      name: "query-fields",
      version: "1.0.0",
      types: "types.d.ts?raw",
      main: "main.ts",
    })),
    writeFile(files[11]!, "export interface QueryTypesEntry {}\n"),
    writeFile(files[12]!, "export const queryMainEntry = true;\n"),
  ]);
  const workspace = await discoverWorkspace(root, files);
  const resolver = await ModuleResolver.create(workspace, files);
  const owner = workspace.packages.find((record) => record.name === "legacy-order-root")!;
  const targetPath = (resolution: Awaited<ReturnType<ModuleResolver["resolve"]>>): string | null => (
    resolution.targets[0]?.kind === "file" ? resolution.targets[0].absolutePath : null
  );
  assert.equal(targetPath(await resolver.resolve(rawDependency("all-fields"), files[1]!, owner)), files[5]);
  assert.equal(targetPath(await resolver.resolve(rawDependency("all-fields", { useTypesCondition: true }), files[1]!, owner)), files[3]);
  assert.equal(targetPath(await resolver.resolve(rawDependency("runtime-fields", { useTypesCondition: true }), files[1]!, owner)), files[9]);
  assert.equal(targetPath(await resolver.resolve(rawDependency("query-fields", { useTypesCondition: true }), files[1]!, owner)), files[12]);
});

test("effective-types resolution treats top-level falsy exports as disabled", async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "depgraph-web-falsy-exports-"));
  context.after(async () => rm(root, { recursive: true, force: true }));
  const packages = [
    { name: "null-exports", value: null },
    { name: "false-exports", value: false },
    { name: "zero-exports", value: 0 },
    { name: "empty-exports", value: "" },
  ] as const;
  await Promise.all(packages.map(({ name }) => mkdir(path.join(root, "packages", name), { recursive: true })));
  const relatives = [
    "package.json",
    "index.ts",
    ...packages.flatMap(({ name }) => [
      `packages/${name}/package.json`,
      `packages/${name}/types.d.ts`,
      `packages/${name}/main.js`,
    ]),
  ];
  const files = relatives.map((relative) => path.join(root, relative));
  await Promise.all([
    writeFile(files[0]!, JSON.stringify({
      name: "falsy-exports-root",
      workspaces: ["packages/*"],
      dependencies: Object.fromEntries(packages.map(({ name }) => [name, "workspace:*"])),
    })),
    writeFile(files[1]!, "export {};\n"),
    ...packages.flatMap(({ name, value }, index) => {
      const offset = 2 + index * 3;
      return [
        writeFile(files[offset]!, JSON.stringify({
          name,
          version: "1.0.0",
          exports: value,
          types: "types.d.ts",
          main: "main.js",
        })),
        writeFile(files[offset + 1]!, "export interface TypesEntry {}\n"),
        writeFile(files[offset + 2]!, "export const mainEntry = true;\n"),
      ];
    }),
  ]);
  const workspace = await discoverWorkspace(root, files);
  const resolver = await ModuleResolver.create(workspace, files);
  const owner = workspace.packages.find((record) => record.name === "falsy-exports-root")!;
  for (const { name, value } of packages) {
    const semantic = await resolver.resolve(rawDependency(name, { useTypesCondition: true }), files[1]!, owner);
    assert.equal(
      semantic.targets[0]?.kind === "file" ? path.basename(semantic.targets[0].absolutePath) : null,
      "types.d.ts",
      name,
    );
    const runtime = await resolver.resolve(rawDependency(name), files[1]!, owner);
    if (value === null) {
      assert.equal(runtime.targets[0]?.kind === "file" ? path.basename(runtime.targets[0].absolutePath) : null, "main.js");
    } else {
      assert.equal(runtime.status, "unresolved", name);
    }
  }
});

test("absent or falsy exports disable semantic package self-name resolution", async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "depgraph-web-falsy-self-reference-"));
  context.after(async () => rm(root, { recursive: true, force: true }));
  const cases = [
    { label: "absent", present: false, value: null as unknown },
    { label: "null", present: true, value: null as unknown },
    { label: "false", present: true, value: false as unknown },
    { label: "zero", present: true, value: 0 as unknown },
    { label: "empty", present: true, value: "" as unknown },
  ];
  for (const { label, present, value } of cases) {
    const caseRoot = path.join(root, label);
    await mkdir(caseRoot, { recursive: true });
    const files = ["package.json", "index.ts", "types.d.ts", "main.js"]
      .map((relative) => path.join(caseRoot, relative));
    await Promise.all([
      writeFile(files[0]!, JSON.stringify({
        name: "falsy-self-reference",
        version: "1.0.0",
        ...(present ? { exports: value } : {}),
        types: "types.d.ts",
        main: "main.js",
      })),
      writeFile(files[1]!, "export {};\n"),
      writeFile(files[2]!, "export interface SelfType {}\n"),
      writeFile(files[3]!, "export const selfMain = true;\n"),
    ]);
    const workspace = await discoverWorkspace(caseRoot, files);
    const resolver = await ModuleResolver.create(workspace, files);
    const owner = workspace.packages[0]!;
    const semantic = await resolver.resolve(
      rawDependency("falsy-self-reference", { useTypesCondition: true }),
      files[1]!,
      owner,
    );
    assert.ok(semantic.targets.every((target) => target.kind !== "file"), label);
    assert.ok(!semantic.targets.some((target) => target.kind === "workspace_package"), label);
  }
});

test("package exports use ordered first-match profiles, type fallbacks, and fail-closed partial branches", async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "depgraph-web-ordered-exports-"));
  context.after(async () => rm(root, { recursive: true, force: true }));
  const packageRoot = path.join(root, "packages", "conditional");
  await mkdir(packageRoot, { recursive: true });
  const relatives = [
    "package.json",
    "index.ts",
    "packages/conditional/package.json",
    "packages/conditional/browser.ts",
    "packages/conditional/default.ts",
    "packages/conditional/node.ts",
    "packages/conditional/types.d.ts",
    "packages/conditional/runtime.ts",
    "packages/conditional/safe.ts",
    "packages/conditional/private.ts",
    "packages/conditional/alpha.ts",
    "packages/conditional/beta.ts",
    "packages/conditional/custom-default.ts",
  ];
  const files = relatives.map((relative) => path.join(root, relative));
  await Promise.all([
    writeFile(files[0]!, JSON.stringify({
      name: "ordered-exports-root",
      workspaces: ["packages/*"],
      dependencies: { "conditional-package": "workspace:*" },
    })),
    writeFile(files[1]!, "export {};\n"),
    writeFile(files[2]!, JSON.stringify({
      name: "conditional-package",
      version: "1.0.0",
      exports: {
        ".": {
          browser: "./browser.ts",
          default: "./default.ts",
          node: "./node.ts",
        },
        "./partial": { browser: "./missing.ts", default: "./default.ts" },
        "./array": {
          types: ["./missing.d.ts", "./types.d.ts"],
          default: ["./missing.js", "./runtime.ts"],
        },
        "./supported": { "types@>=7 <8": "./types.d.ts", default: "./runtime.ts" },
        "./caret": { "types@^7.0": "./types.d.ts", default: "./runtime.ts" },
        "./tilde": { "types@~7.0": "./types.d.ts", default: "./runtime.ts" },
        "./wildcard": { "types@7.x": "./types.d.ts", default: "./runtime.ts" },
        "./hyphen": { "types@6 - 7.0.2": "./types.d.ts", default: "./runtime.ts" },
        "./prerelease": { "types@>=7.0.0-beta.1": "./types.d.ts", default: "./runtime.ts" },
        "./disjunction": { "types@^6 || ^7": "./types.d.ts", default: "./runtime.ts" },
        "./build": { "types@7.0.2+build.1": "./types.d.ts", default: "./runtime.ts" },
        "./empty-range": { "types@": "./types.d.ts", default: "./runtime.ts" },
        "./unsupported": { "types@not-a-range": "./types.d.ts", default: "./runtime.ts" },
        "./leading-v": { "types@v7": "./types.d.ts", default: "./runtime.ts" },
        "./partial-build": { "types@7+build": "./types.d.ts", default: "./runtime.ts" },
        "./invalid-build": { "types@7.0.2+???": "./types.d.ts", default: "./runtime.ts" },
        "./overflow": { "types@4294967296": "./types.d.ts", default: "./runtime.ts" },
        "./operator-space": { "types@>= 7": "./types.d.ts", default: "./runtime.ts" },
        "./form-feed-space": { "types@>=7.0.0\f<8.0.0": "./types.d.ts", default: "./runtime.ts" },
        "./next-line-boundary": { "types@\u0085>=7.0.0\u0085": "./types.d.ts", default: "./runtime.ts" },
        "./unicode-space": { "types@>=7.0.0\u00a0<8.0.0": "./types.d.ts", default: "./runtime.ts" },
        "./vertical-tab-space": { "types@>=7.0.0\v<8.0.0": "./types.d.ts", default: "./runtime.ts" },
        "./bom-boundary": { "types@\ufeff>=7.0.0\ufeff": "./types.d.ts", default: "./runtime.ts" },
        "./semantic": { browser: "./browser.ts", types: "./types.d.ts", default: "./runtime.ts" },
        "./semantic-runtime-only": { alpha: "./alpha.ts", production: "./default.ts", types: "./types.d.ts", default: "./runtime.ts" },
        "./empty-array-target": { import: [], default: "./safe.ts" },
        "./scalar-target": { import: 42, default: "./safe.ts" },
        "./type-object": { types: "./missing.d.ts", default: "./types.d.ts" },
        "./query-only": { types: "./types.d.ts?raw" },
        "./*/*": "./alpha.ts",
        "./capture/*": "./safe.ts",
        "./custom": { alpha: "./alpha.ts", beta: "./beta.ts", default: "./custom-default.ts" },
        "./numeric": { "0": "./node.ts", default: "./default.ts" },
        "./unsafe": { browser: "./a/../private.ts", default: "./safe.ts" },
        "./encoded": { browser: "./a/%2e%2e/private.ts", default: "./safe.ts" },
      },
    })),
    ...files.slice(3).map((file) => writeFile(file, `export const value = ${JSON.stringify(path.basename(file))};\n`)),
  ]);
  const workspace = await discoverWorkspace(root, files);
  const resolver = await ModuleResolver.create(workspace, files);
  const owner = workspace.packages.find((record) => record.name === "ordered-exports-root")!;
  assert.ok(!Object.keys(resolver.typeScriptStaticConfig().paths).some((pattern) => pattern.includes("*/*")));
  const paths = (resolution: Awaited<ReturnType<ModuleResolver["resolve"]>>): string[] => resolution.targets
    .filter((target): target is Extract<(typeof resolution.targets)[number], { kind: "file" }> => target.kind === "file")
    .map((target) => path.relative(root, target.absolutePath).replaceAll("\\", "/"))
    .sort();
  assert.equal((await resolver.resolve(rawDependency("conditional-package/*/*"), files[1]!, owner)).status, "unresolved");
  for (const specifier of [
    "conditional-package/capture/node_modules/private",
    "conditional-package/capture/../private",
    "conditional-package/capture/%2e%2e/private",
  ]) {
    assert.equal((await resolver.resolve(rawDependency(specifier), files[1]!, owner)).status, "unresolved", specifier);
  }

  const rootExport = await resolver.resolve(rawDependency("conditional-package"), files[1]!, owner);
  assert.deepEqual(paths(rootExport), [
    "packages/conditional/browser.ts",
    "packages/conditional/default.ts",
  ]);
  assert.ok(!paths(rootExport).includes("packages/conditional/node.ts"));

  const partial = await resolver.resolve(rawDependency("conditional-package/partial"), files[1]!, owner);
  assert.equal(partial.status, "unresolved");
  assert.match(partial.reason ?? "", /partially_unavailable/u);

  const typeArray = await resolver.resolve(rawDependency("conditional-package/array", { typeOnly: true }), files[1]!, owner);
  assert.deepEqual(paths(typeArray), ["packages/conditional/types.d.ts"]);
  const runtimeArray = await resolver.resolve(rawDependency("conditional-package/array"), files[1]!, owner);
  assert.equal(runtimeArray.status, "unresolved");
  assert.match(runtimeArray.reason ?? "", /target_not_found/u);

  const supported = await resolver.resolve(rawDependency("conditional-package/supported", { typeOnly: true }), files[1]!, owner);
  assert.deepEqual(paths(supported), ["packages/conditional/types.d.ts"]);
  for (const subpath of [
    "caret", "tilde", "wildcard", "hyphen", "prerelease", "disjunction", "build", "empty-range",
    "form-feed-space", "next-line-boundary",
  ]) {
    const versioned = await resolver.resolve(rawDependency(`conditional-package/${subpath}`, { typeOnly: true }), files[1]!, owner);
    assert.deepEqual(paths(versioned), ["packages/conditional/types.d.ts"], subpath);
  }
  for (const subpath of [
    "unsupported", "leading-v", "partial-build", "invalid-build", "overflow", "operator-space",
    "unicode-space", "vertical-tab-space", "bom-boundary",
  ]) {
    const unsupported = await resolver.resolve(rawDependency(`conditional-package/${subpath}`, { typeOnly: true }), files[1]!, owner);
    assert.deepEqual(paths(unsupported), ["packages/conditional/runtime.ts"], subpath);
  }
  const typeObject = await resolver.resolve(rawDependency("conditional-package/type-object", { typeOnly: true }), files[1]!, owner);
  assert.deepEqual(paths(typeObject), ["packages/conditional/types.d.ts"]);
  assert.equal((await resolver.resolve(
    rawDependency("conditional-package/query-only", { useTypesCondition: true }),
    files[1]!,
    owner,
  )).status, "unresolved");
  assert.equal((await resolver.resolve(rawDependency("conditional-package/a/b"), files[1]!, owner)).status, "unresolved");
  const syntaxValue = await resolver.resolve(rawDependency("conditional-package/semantic"), files[1]!, owner);
  assert.deepEqual(paths(syntaxValue), ["packages/conditional/browser.ts", "packages/conditional/runtime.ts"]);
  const semanticValue = await resolver.resolve(rawDependency("conditional-package/semantic", { useTypesCondition: true }), files[1]!, owner);
  assert.deepEqual(paths(semanticValue), ["packages/conditional/types.d.ts"]);
  assert.deepEqual(semanticValue.targetConditions, [WEB_CONDITION]);
  const semanticRuntimeConditions = await resolver.resolve(
    rawDependency("conditional-package/semantic-runtime-only", { useTypesCondition: true }),
    files[1]!,
    owner,
  );
  assert.deepEqual(paths(semanticRuntimeConditions), ["packages/conditional/types.d.ts"]);
  for (const subpath of ["empty-array-target", "scalar-target"]) {
    const runtimeInvalid = await resolver.resolve(rawDependency(`conditional-package/${subpath}`), files[1]!, owner);
    assert.equal(runtimeInvalid.status, "unresolved", subpath);
    const semanticFallback = await resolver.resolve(
      rawDependency(`conditional-package/${subpath}`, { useTypesCondition: true }),
      files[1]!,
      owner,
    );
    assert.deepEqual(paths(semanticFallback), ["packages/conditional/safe.ts"], subpath);
  }

  const custom = await resolver.resolve(rawDependency("conditional-package/custom"), files[1]!, owner);
  assert.deepEqual(paths(custom), [
    "packages/conditional/alpha.ts",
    "packages/conditional/beta.ts",
    "packages/conditional/custom-default.ts",
  ]);
  const customCondition = JSON.stringify(custom.condition);
  assert.match(customCondition, /"op":"defined","key":"package\.exports\.condition:alpha"/u);
  assert.match(customCondition, /"op":"not"/u);
  assert.doesNotMatch(customCondition, /"key":"package\.exports\.condition","value":"alpha"/u);
  const numeric = await resolver.resolve(rawDependency("conditional-package/numeric"), files[1]!, owner);
  assert.equal(numeric.status, "unresolved");
  assert.match(numeric.reason ?? "", /target_invalid/u);

  const unsafe = await resolver.resolve(rawDependency("conditional-package/unsafe"), files[1]!, owner);
  assert.equal(unsafe.status, "unresolved");
  assert.ok(!paths(unsafe).includes("packages/conditional/private.ts"));
  const encoded = await resolver.resolve(rawDependency("conditional-package/encoded"), files[1]!, owner);
  assert.equal(encoded.status, "unresolved");
});

test("alias misses fall through and package self-reference wins before external selection", async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "depgraph-web-alias-package-fallback-"));
  context.after(async () => rm(root, { recursive: true, force: true }));
  await mkdir(path.join(root, "src"), { recursive: true });
  await mkdir(path.join(root, "node_modules", "external-package"), { recursive: true });
  await mkdir(path.join(root, "node_modules", "self-package"), { recursive: true });
  const relatives = [
    "package.json",
    "tsconfig.json",
    "index.ts",
    "src/self.ts",
    "node_modules/external-package/package.json",
    "node_modules/external-package/index.js",
    "node_modules/self-package/package.json",
    "node_modules/self-package/index.js",
  ];
  const files = relatives.map((relative) => path.join(root, relative));
  await Promise.all([
    writeFile(files[0]!, JSON.stringify({
      name: "self-package",
      version: "1.0.0",
      exports: "./src/self.ts",
      dependencies: { "external-package": "1.0.0" },
    })),
    writeFile(files[1]!, JSON.stringify({
      compilerOptions: {
        paths: {
          "self-package": ["missing-self.ts"],
          "external-package": ["missing-external.ts"],
        },
      },
    })),
    writeFile(files[2]!, "export {};\n"),
    writeFile(files[3]!, "export const self = true;\n"),
    writeFile(files[4]!, JSON.stringify({ name: "external-package", version: "1.0.0", main: "index.js" })),
    writeFile(files[5]!, "export const external = true;\n"),
    writeFile(files[6]!, JSON.stringify({ name: "self-package", version: "9.0.0", main: "index.js" })),
    writeFile(files[7]!, "export const wrongSelf = true;\n"),
  ]);
  const workspace = await discoverWorkspace(root, files);
  const resolver = await ModuleResolver.create(workspace, files);
  const owner = workspace.packages.find((record) => record.name === "self-package")!;
  const self = await resolver.resolve(rawDependency("self-package"), files[2]!, owner);
  assert.equal(self.status, "resolved");
  assert.equal(self.targets[0]?.kind === "file" ? self.targets[0].absolutePath : null, files[3]);
  const external = await resolver.resolve(rawDependency("external-package"), files[2]!, owner);
  assert.equal(external.status, "external");
  assert.doesNotMatch(external.reason ?? "", /path_alias_target_not_found/u);
});

test("mixed package export-map and condition keys fail closed", async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "depgraph-web-mixed-exports-"));
  context.after(async () => rm(root, { recursive: true, force: true }));
  const packageRoot = path.join(root, "packages", "mixed");
  await mkdir(packageRoot, { recursive: true });
  const relatives = [
    "package.json",
    "index.ts",
    "packages/mixed/package.json",
    "packages/mixed/x.ts",
    "packages/mixed/y.ts",
  ];
  const files = relatives.map((relative) => path.join(root, relative));
  await Promise.all([
    writeFile(files[0]!, JSON.stringify({
      name: "mixed-root",
      workspaces: ["packages/*"],
      dependencies: { "mixed-package": "workspace:*" },
    })),
    writeFile(files[1]!, "export {};\n"),
    writeFile(files[2]!, JSON.stringify({
      name: "mixed-package",
      version: "1.0.0",
      exports: { ".": "./x.ts", default: "./y.ts" },
    })),
    writeFile(files[3]!, "export const x = true;\n"),
    writeFile(files[4]!, "export const y = true;\n"),
  ]);
  const workspace = await discoverWorkspace(root, files);
  const resolver = await ModuleResolver.create(workspace, files);
  const owner = workspace.packages.find((record) => record.name === "mixed-root")!;
  const resolution = await resolver.resolve(rawDependency("mixed-package"), files[1]!, owner);
  assert.equal(resolution.status, "unresolved");
  assert.match(resolution.reason ?? "", /exports_configuration_invalid/u);
});

test("external lookup never falls through a nearer package boundary to a root installation", async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "depgraph-web-nearest-package-"));
  context.after(async () => rm(root, { recursive: true, force: true }));
  const app = path.join(root, "packages", "app");
  const nearest = path.join(app, "node_modules", "nearest-package");
  const upper = path.join(root, "node_modules", "nearest-package");
  const nearestManifestless = path.join(app, "node_modules", "manifestless-package");
  const upperManifestless = path.join(root, "node_modules", "manifestless-package");
  await Promise.all([
    mkdir(nearest, { recursive: true }),
    mkdir(upper, { recursive: true }),
    mkdir(nearestManifestless, { recursive: true }),
    mkdir(upperManifestless, { recursive: true }),
  ]);
  const relatives = [
    "package.json",
    "packages/app/package.json",
    "packages/app/index.ts",
    "packages/app/node_modules/nearest-package/package.json",
    "node_modules/nearest-package/package.json",
    "node_modules/nearest-package/private.js",
    "packages/app/node_modules/manifestless-package/index.js",
    "node_modules/manifestless-package/package.json",
    "node_modules/manifestless-package/index.js",
    "package-lock.json",
  ];
  const files = relatives.map((relative) => path.join(root, relative));
  await Promise.all([
    writeFile(files[0]!, JSON.stringify({ name: "nearest-root", packageManager: "npm@11.0.0", workspaces: ["packages/*"] })),
    writeFile(files[1]!, JSON.stringify({
      name: "nearest-app",
      version: "1.0.0",
      dependencies: { "nearest-package": "1.0.0", "manifestless-package": "^1 || ^2" },
    })),
    writeFile(files[2]!, "export {};\n"),
    writeFile(files[3]!, JSON.stringify({
      name: "nearest-package",
      version: "1.0.0",
      exports: { "./public": "./missing.js" },
    })),
    writeFile(files[4]!, JSON.stringify({
      name: "nearest-package",
      version: "1.0.0",
      exports: { "./private": "./private.js" },
    })),
    writeFile(files[5]!, "export const privateValue = true;\n"),
    writeFile(files[6]!, "export const nearestManifestless = true;\n"),
    writeFile(files[7]!, JSON.stringify({ name: "manifestless-package", version: "9.0.0", main: "index.js" })),
    writeFile(files[8]!, "export const upperManifestless = true;\n"),
    writeFile(files[9]!, JSON.stringify({
      name: "nearest-root",
      lockfileVersion: 3,
      packages: {
        "": { name: "nearest-root" },
        "node_modules/left/node_modules/manifestless-package": { version: "1.2.3" },
        "node_modules/right/node_modules/manifestless-package": { version: "2.3.4" },
      },
    })),
  ]);
  const workspace = await discoverWorkspace(root, files);
  const resolver = await ModuleResolver.create(workspace, files);
  const owner = workspace.packages.find((record) => record.name === "nearest-app")!;
  const resolution = await resolver.resolve(rawDependency("nearest-package/private"), files[2]!, owner);
  assert.equal(resolution.status, "unresolved");
  assert.match(resolution.reason ?? "", /package_subpath_not_exported/u);
  const manifestless = await resolver.resolve(rawDependency("manifestless-package"), files[2]!, owner);
  assert.equal(manifestless.status, "candidates");
  assert.equal(manifestless.precision, "overapprox");
  assert.deepEqual(
    manifestless.targets.map((target) => target.kind === "external_package" ? target.version : null),
    ["1.2.3", "2.3.4"],
  );
  assert.match(manifestless.reason ?? "", /external_package_version_unproven/u);
});

test("external lookup stops at an out-of-root symlink package boundary", async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "depgraph-web-symlink-package-boundary-"));
  const outside = await mkdtemp(path.join(os.tmpdir(), "depgraph-web-outside-package-"));
  context.after(async () => Promise.all([
    rm(root, { recursive: true, force: true }),
    rm(outside, { recursive: true, force: true }),
  ]));
  const app = path.join(root, "packages", "app");
  const upper = path.join(root, "node_modules", "symlink-package");
  const outsidePackage = path.join(outside, "symlink-package");
  await Promise.all([
    mkdir(path.join(app, "src"), { recursive: true }),
    mkdir(path.join(app, "node_modules"), { recursive: true }),
    mkdir(upper, { recursive: true }),
    mkdir(outsidePackage, { recursive: true }),
  ]);
  await symlink(outsidePackage, path.join(app, "node_modules", "symlink-package"), "dir");
  const relatives = [
    "package.json",
    "package-lock.json",
    "packages/app/package.json",
    "packages/app/src/index.ts",
    "node_modules/symlink-package/package.json",
    "node_modules/symlink-package/index.d.ts",
  ];
  const files = relatives.map((relative) => path.join(root, relative));
  await Promise.all([
    writeFile(files[0]!, JSON.stringify({
      name: "symlink-boundary-root",
      packageManager: "npm@11.0.0",
      workspaces: ["packages/*"],
    })),
    writeFile(files[1]!, JSON.stringify({
      name: "symlink-boundary-root",
      lockfileVersion: 3,
      packages: { "node_modules/symlink-package": { version: "9.0.0" } },
    })),
    writeFile(files[2]!, JSON.stringify({
      name: "symlink-boundary-app",
      version: "1.0.0",
      dependencies: { "symlink-package": "9.0.0" },
    })),
    writeFile(files[3]!, "export {};\n"),
    writeFile(files[4]!, JSON.stringify({
      name: "symlink-package",
      version: "9.0.0",
      types: "index.d.ts",
    })),
    writeFile(files[5]!, "export interface UnsafeUpperFallback {}\n"),
  ]);
  const workspace = await discoverWorkspace(root, files);
  const resolver = await ModuleResolver.create(workspace, files);
  const owner = workspace.packages.find((record) => record.name === "symlink-boundary-app")!;
  const resolution = await resolver.resolve(
    rawDependency("symlink-package", { useTypesCondition: true }),
    files[3]!,
    owner,
  );
  assert.equal(resolution.status, "unresolved");
  assert.match(resolution.reason ?? "", /external_package_manifest_invalid/u);
  assert.ok(resolution.targets.every((target) => target.kind !== "file"));
});

test("external lookup starts at each source directory while package imports start at package scope", async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "depgraph-web-source-nearest-package-"));
  context.after(async () => rm(root, { recursive: true, force: true }));
  const app = path.join(root, "packages", "app");
  const installs = [
    { relative: "packages/app/node_modules/source-package", version: "1.0.0" },
    { relative: "packages/app/src/node_modules/source-package", version: "2.0.0" },
    { relative: "packages/app/other/node_modules/source-package", version: "3.0.0" },
  ];
  await Promise.all([
    mkdir(path.join(app, "src", "deep"), { recursive: true }),
    mkdir(path.join(app, "other", "deep"), { recursive: true }),
    ...installs.map(({ relative }) => mkdir(path.join(root, relative), { recursive: true })),
  ]);
  const relatives = [
    "package.json",
    "package-lock.json",
    "packages/app/package.json",
    "packages/app/src/deep/a.ts",
    "packages/app/other/deep/b.ts",
    ...installs.flatMap(({ relative }) => [`${relative}/package.json`, `${relative}/index.d.ts`]),
  ];
  const files = relatives.map((relative) => path.join(root, relative));
  await Promise.all([
    writeFile(files[0]!, JSON.stringify({
      name: "source-nearest-root",
      packageManager: "npm@11.0.0",
      workspaces: ["packages/*"],
    })),
    writeFile(files[1]!, JSON.stringify({
      name: "source-nearest-root",
      lockfileVersion: 3,
      packages: Object.fromEntries(installs.map(({ relative, version }) => [relative, { version }])),
    })),
    writeFile(files[2]!, JSON.stringify({
      name: "source-nearest-app",
      version: "1.0.0",
      dependencies: { "source-package": "*" },
      imports: { "#source-package": "source-package" },
    })),
    writeFile(files[3]!, "export {};\n"),
    writeFile(files[4]!, "export {};\n"),
    ...installs.flatMap(({ version }, index) => {
      const offset = 5 + index * 2;
      return [
        writeFile(files[offset]!, JSON.stringify({
          name: "source-package",
          version,
          exports: {
            ".": { types: "./index.d.ts", default: "./index.d.ts" },
            "./query": { types: "./index.d.ts?raw" },
          },
        })),
        writeFile(files[offset + 1]!, `export interface SourcePackageV${version[0]} {}\n`),
      ];
    }),
  ]);
  const workspace = await discoverWorkspace(root, files);
  const resolver = await ModuleResolver.create(workspace, files);
  const owner = workspace.packages.find((record) => record.name === "source-nearest-app")!;
  const version = (resolution: Awaited<ReturnType<ModuleResolver["resolve"]>>): string | null => (
    resolution.targets[0]?.kind === "external_package" ? resolution.targets[0].version : null
  );
  assert.equal(version(await resolver.resolve(rawDependency("source-package", { useTypesCondition: true }), files[3]!, owner)), "2.0.0");
  assert.equal(version(await resolver.resolve(rawDependency("source-package", { useTypesCondition: true }), files[4]!, owner)), "3.0.0");
  assert.equal(version(await resolver.resolve(rawDependency("#source-package", { useTypesCondition: true }), files[3]!, owner)), "1.0.0");
  assert.equal((await resolver.resolve(
    rawDependency("source-package/query", { useTypesCondition: true }),
    files[3]!,
    owner,
  )).status, "unresolved");
});

test("package imports apply patterns, ordered conditions, and compatible nested package profiles", async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "depgraph-web-package-imports-"));
  context.after(async () => rm(root, { recursive: true, force: true }));
  const environmentPackage = path.join(root, "packages", "environment-package");
  await Promise.all([
    mkdir(path.join(root, "browser"), { recursive: true }),
    mkdir(path.join(root, "server"), { recursive: true }),
    mkdir(environmentPackage, { recursive: true }),
  ]);
  const relatives = [
    "package.json",
    "index.ts",
    "browser/item.ts",
    "server/item.ts",
    "server/nested.ts",
    "packages/environment-package/package.json",
    "packages/environment-package/browser.ts",
    "packages/environment-package/node.ts",
    "tsconfig.json",
  ];
  const files = relatives.map((relative) => path.join(root, relative));
  await Promise.all([
    writeFile(files[0]!, JSON.stringify({
      name: "package-imports-root",
      version: "1.0.0",
      workspaces: ["packages/*"],
      dependencies: { "environment-package": "workspace:*" },
      imports: {
        "#": "./server/nested.ts",
        "#/invalid": "./server/nested.ts",
        "#local/*": { browser: "./browser/*.ts", default: "./server/*.ts" },
        "#typed": { types: ["./missing.d.ts", "./browser/item.ts"], default: "./server/item.ts" },
        "#nested": { browser: "environment-package", default: "./server/nested.ts" },
        "#query": "./browser/item.ts?raw",
        "#multi/*/*": "./server/*.ts",
        "#capture/*": "./server/nested.ts",
        "#alias": "alias",
        "#cycle-a": "#cycle-b",
        "#cycle-b": "#cycle-a",
      },
    })),
    writeFile(files[1]!, "export {};\n"),
    writeFile(files[2]!, "export const item = 'browser';\n"),
    writeFile(files[3]!, "export const item = 'server';\n"),
    writeFile(files[4]!, "export const nested = 'server';\n"),
    writeFile(files[5]!, JSON.stringify({
      name: "environment-package",
      version: "1.0.0",
      exports: { browser: "./browser.ts", node: "./node.ts" },
    })),
    writeFile(files[6]!, "export const environment = 'browser';\n"),
    writeFile(files[7]!, "export const environment = 'node';\n"),
    writeFile(files[8]!, JSON.stringify({ compilerOptions: { paths: { alias: ["server/nested.ts"] } } })),
  ]);
  const workspace = await discoverWorkspace(root, files);
  const resolver = await ModuleResolver.create(workspace, files);
  const owner = workspace.packages.find((record) => record.name === "package-imports-root")!;
  const paths = (resolution: Awaited<ReturnType<ModuleResolver["resolve"]>>): string[] => resolution.targets
    .filter((target): target is Extract<(typeof resolution.targets)[number], { kind: "file" }> => target.kind === "file")
    .map((target) => path.relative(root, target.absolutePath).replaceAll("\\", "/"))
    .sort();
  const pattern = await resolver.resolve(rawDependency("#local/item"), files[1]!, owner);
  assert.deepEqual(paths(pattern), ["browser/item.ts", "server/item.ts"]);
  const nested = await resolver.resolve(rawDependency("#nested"), files[1]!, owner);
  assert.deepEqual(paths(nested), [
    "packages/environment-package/browser.ts",
    "server/nested.ts",
  ]);
  assert.ok(!paths(nested).includes("packages/environment-package/node.ts"));
  const typed = await resolver.resolve(rawDependency("#typed", { typeOnly: true }), files[1]!, owner);
  assert.deepEqual(paths(typed), ["browser/item.ts"]);
  assert.deepEqual(paths(await resolver.resolve(rawDependency("#query"), files[1]!, owner)), ["browser/item.ts"]);
  assert.equal((await resolver.resolve(rawDependency("#query", { useTypesCondition: true }), files[1]!, owner)).status, "unresolved");
  assert.equal((await resolver.resolve(rawDependency("#multi/a/b"), files[1]!, owner)).status, "unresolved");
  assert.equal((await resolver.resolve(rawDependency("#multi/*/*"), files[1]!, owner)).status, "unresolved");
  for (const specifier of ["#capture/node_modules/private", "#capture/../private", "#capture/%2e%2e/private"]) {
    assert.equal((await resolver.resolve(rawDependency(specifier), files[1]!, owner)).status, "unresolved", specifier);
  }
  assert.deepEqual(paths(await resolver.resolve(rawDependency("#alias"), files[1]!, owner)), ["server/nested.ts"]);
  assert.match((await resolver.resolve(rawDependency("#cycle-a"), files[1]!, owner)).reason ?? "", /cycle_or_depth_limit/u);
  const patternRoot = await resolver.resolve(rawDependency("#/invalid"), files[1]!, owner);
  assert.deepEqual(paths(patternRoot), ["server/nested.ts"]);
  const invalid = await resolver.resolve(rawDependency("#"), files[1]!, owner);
  assert.equal(invalid.status, "unresolved");
  assert.match(invalid.reason ?? "", /package_import_specifier_invalid/u);
});

test("condition canonicalization follows protocol UTF-8 ordering for Unicode values", () => {
  assert.deepEqual(canonicalizeCondition({
    op: "in",
    key: "environment",
    // UTF-16 orders the surrogate pair before U+E000; UTF-8/Rust orders U+E000 first.
    values: ["\u{10000}", "\uE000"],
  }), {
    op: "in",
    key: "environment",
    values: ["\uE000", "\u{10000}"],
  });
});

test("extracts ESM, CJS, re-export, type-only, literal and computed imports", () => {
  const source = `
import type { A } from "./a"
import value from "./value"
import "./side-effect"
export { other } from "./other"
const common = require("./common")
const lazy = import("./lazy")
const name = "computed"
const unknown = import(\`./\${name}\`)
`;
  const result = extractDependencies("/repo/source.ts", "source.ts", source);
  assert.deepEqual(result.dependencies.map(({ kind, specifier, literal }) => ({ kind, specifier, literal })), [
    { kind: "type_import", specifier: "./a", literal: true },
    { kind: "import", specifier: "./value", literal: true },
    { kind: "side_effect_import", specifier: "./side-effect", literal: true },
    { kind: "reexport", specifier: "./other", literal: true },
    { kind: "require", specifier: "./common", literal: true },
    { kind: "dynamic_import", specifier: "./lazy", literal: true },
    { kind: "dynamic_import", specifier: "`./${name}`", literal: false },
  ]);
  assert.equal(result.parseErrors.length, 0);
  assert.ok(result.dependencies.every((dependency) => dependency.evidence.start_line > 0 && dependency.evidence.start_column > 0));
});

test("dynamic import options do not change whether the first argument is literal", () => {
  const source = `
const json = import("./data.json", { with: { type: "json" } });
const template = import(\`./other.json\`, { with: { type: "json" } });
const name = "computed.json";
const computed = import(name, { with: { type: "json" } });
`;
  const result = extractDependencies("/repo/options.ts", "options.ts", source);
  assert.deepEqual(result.dependencies.map(({ specifier, literal }) => ({ specifier, literal })), [
    { specifier: "./data.json", literal: true },
    { specifier: "./other.json", literal: true },
    { specifier: 'name, { with: { type: "json" } }', literal: false },
  ]);
  assert.equal(result.parseErrors.length, 0);
});

test("import.meta expressions are not dependency declarations", async () => {
  const source = `
const metadata = (import.meta, { from: "ghost" });
const resolved = import.meta.resolve("also-not-a-static-import");
`;
  const analysis = await analyzeTypeScriptProject(new Map([["meta.ts", source]]));
  assert.deepEqual(analysis.get("meta.ts"), []);
  const result = extractDependencies("/repo/meta.ts", "meta.ts", source, analysis.typeOnlyDependencyRanges.get("meta.ts"));
  assert.deepEqual(result.dependencies, []);
  assert.deepEqual(result.parseErrors, []);
});

test("all-inline type bindings are classified without requiring an AST transfer", () => {
  const source = `
import { type A, type B as C } from "./types";
import { type D, runtime } from "./mixed";
export { type E, type F as G } from "./export-types";
export { type H, runtimeExport } from "./export-mixed";
`;
  const result = extractDependencies("/repo/inline.ts", "inline.ts", source);
  assert.deepEqual(result.dependencies.map(({ kind, specifier, typeOnly }) => ({ kind, specifier, typeOnly })), [
    { kind: "type_import", specifier: "./types", typeOnly: true },
    { kind: "import", specifier: "./mixed", typeOnly: false },
    { kind: "type_reexport", specifier: "./export-types", typeOnly: true },
    { kind: "reexport", specifier: "./export-mixed", typeOnly: false },
  ]);
});

test("native parser metadata separates ImportType, JSDoc, and all-inline type bindings from runtime imports", async () => {
  const typescript = `
import { type InlineA, type InlineB as Renamed } from "./all-inline";
import { type MixedType, runtimeValue } from "./mixed";
export { type ExportedA, type ExportedB as PublicB } from "./all-inline-export";
export { type MixedExport, runtimeExport } from "./mixed-export";
type Query = import("./query").Query;
let annotated: import("./annotation").Annotation;
type Namespace = typeof import("./namespace");
type Nested = Promise<Array<import("./nested").Nested>>;
const runtime = import("./runtime");
const runtimeTypeof = typeof import("./runtime-typeof");
`;
  const javascript = `
/** @type {import("./jsdoc").JSDocType} */
let fromJsDoc;
/** @returns {Promise<import("./jsdoc-return").Result>} */
function returnedFromJsDoc() {}
// Prose mentioning import("./not-a-site") is not a JSDoc type dependency.
`;
  const analysis = await analyzeTypeScriptProject(new Map([
    ["source.ts", typescript],
    ["source.js", javascript],
  ]));
  const typeResult = extractDependencies(
    "/repo/source.ts",
    "source.ts",
    typescript,
    analysis.typeOnlyDependencyRanges.get("source.ts"),
  );
  assert.deepEqual(typeResult.dependencies.map(({ kind, edgeKind, specifier, typeOnly }) => ({ kind, edgeKind, specifier, typeOnly })), [
    { kind: "type_import", edgeKind: "imports", specifier: "./all-inline", typeOnly: true },
    { kind: "import", edgeKind: "imports", specifier: "./mixed", typeOnly: false },
    { kind: "type_reexport", edgeKind: "reexports", specifier: "./all-inline-export", typeOnly: true },
    { kind: "reexport", edgeKind: "reexports", specifier: "./mixed-export", typeOnly: false },
    { kind: "type_import", edgeKind: "imports", specifier: "./query", typeOnly: true },
    { kind: "type_import", edgeKind: "imports", specifier: "./annotation", typeOnly: true },
    { kind: "type_import", edgeKind: "imports", specifier: "./namespace", typeOnly: true },
    { kind: "type_import", edgeKind: "imports", specifier: "./nested", typeOnly: true },
    { kind: "dynamic_import", edgeKind: "lazy_imports", specifier: "./runtime", typeOnly: false },
    { kind: "dynamic_import", edgeKind: "lazy_imports", specifier: "./runtime-typeof", typeOnly: false },
  ]);
  assert.equal(typeResult.parseErrors.length, 0);
  assert.ok(typeResult.dependencies.every((dependency) => (
    dependency.evidence.start_line > 0
    && dependency.evidence.start_column > 0
    && dependency.evidence.end_line >= dependency.evidence.start_line
    && (dependency.evidence.end_line > dependency.evidence.start_line
      || dependency.evidence.end_column > dependency.evidence.start_column)
  )));

  const jsResult = extractDependencies(
    "/repo/source.js",
    "source.js",
    javascript,
    analysis.typeOnlyDependencyRanges.get("source.js"),
  );
  assert.deepEqual(jsResult.dependencies.map(({ kind, edgeKind, specifier, typeOnly }) => ({ kind, edgeKind, specifier, typeOnly })), [
    { kind: "type_import", edgeKind: "imports", specifier: "./jsdoc", typeOnly: true },
    { kind: "type_import", edgeKind: "imports", specifier: "./jsdoc-return", typeOnly: true },
  ]);
  assert.equal(jsResult.parseErrors.length, 0);
});

test("TSX scanner ignores JSX text and attributes but keeps imports in JSX expressions", () => {
  const source = `
export const View = () => (
  <section title={"import('./attribute-text')"} data-label="import('./quoted-attribute')">
    import("./jsx-text")
    {({ nested: { enabled: true } }).nested.enabled && import("./real-expression")}
    import("./false-after-expression")
    {import("./real-second-expression")}
  </section>
);
`;
  const result = extractDependencies("/repo/view.tsx", "view.tsx", source);
  assert.deepEqual(result.dependencies.map(({ kind, specifier, literal }) => ({ kind, specifier, literal })), [
    { kind: "dynamic_import", specifier: "./real-expression", literal: true },
    { kind: "dynamic_import", specifier: "./real-second-expression", literal: true },
  ]);
  assert.equal(result.parseErrors.length, 0);
});

test("Astro extraction only scans frontmatter and preserves source spans", () => {
  const source = `---\nimport Card from "../Card.astro";\n---\n<script>import("runtime-only")</script>`;
  const result = extractDependencies("/repo/page.astro", "page.astro", source);
  assert.equal(result.dependencies.length, 1);
  assert.equal(result.dependencies[0]?.specifier, "../Card.astro");
  assert.equal(result.dependencies[0]?.evidence.start_line, 2);
  assert.equal(result.dependencies[0]?.evidence.extractor, "astro-compiler-frontmatter");
  assert.equal(result.dependencies[0]?.evidence.extractor_version, "4.0.0");
});

test("Astro compiler failures retain an explicit tokenizer fallback reason", () => {
  const result = extractDependencies("/repo/page.astro", "page.astro", "---\nimport Card from '../Card.astro';\n---\n\u0000");
  assert.match(result.fallbackReason ?? "", /control character/u);
});

test("private fields and regex character classes cannot stall the TypeScript scanner", () => {
  const source = `
class Resolver {
  readonly #root = "/repo";

  #resolveFileBase(base: string): string {
    const clean = base.replace(/[?#].*$/u, "");
    return clean;
  }

  async #load(): Promise<void> {
    await import("./from-private-method");
  }
}

import value from "./after-private-class";
`;
  const result = extractDependencies("/repo/resolver.ts", "resolver.ts", source);
  assert.deepEqual(result.dependencies.map(({ kind, specifier }) => ({ kind, specifier })), [
    { kind: "dynamic_import", specifier: "./from-private-method" },
    { kind: "import", specifier: "./after-private-class" },
  ]);
  assert.equal(result.parseErrors.length, 0);
});

test("scanner non-progress is recovered with a diagnostic and later imports remain visible", () => {
  const result = extractDependencies(
    "/repo/malformed.ts",
    "malformed.ts",
    'const invalid = #;\nimport value from "./after-malformed-token";\n',
  );
  assert.deepEqual(result.dependencies.map(({ specifier }) => specifier), ["./after-malformed-token"]);
  assert.equal(result.parseErrors.length, 1);
  assert.match(result.parseErrors[0]?.message ?? "", /scanner made no progress/u);
  assert.equal(result.parseErrors[0]?.evidence.start_line, 1);
});

test("malformed TypeScript module syntax is reported instead of silently completing", () => {
  const result = extractDependencies("/repo/broken.ts", "broken.ts", "import {");
  assert.equal(result.dependencies.length, 0);
  assert.ok(result.parseErrors.some((error) => /CloseBraceToken expected/u.test(error.message)));
  assert.equal(result.parseErrors[0]?.evidence.start_line, 1);
});

test("balanced but invalid import and variable declarations produce parser diagnostics", () => {
  const result = extractDependencies(
    "/repo/broken-balanced.ts",
    "broken-balanced.ts",
    'import { x } "./missing"; const = 1',
  );
  assert.equal(result.dependencies.length, 0);
  assert.ok(result.parseErrors.some((error) => /FromKeyword expected/u.test(error.message)));
  assert.ok(result.parseErrors.some((error) => /variable declaration name/u.test(error.message)));
  assert.ok(result.parseErrors.every((error) => error.evidence.start_line === 1));
});

test("member calls and object methods named import or require are not dependency sites", () => {
  const source = `
const loader = {
  import() { return "not a dependency" },
  require() { return "not a dependency" },
};
loader.import("./member-import");
loader.require("./member-require");
const actual = require("./actual");
const lazy = import("./lazy");
`;
  const result = extractDependencies("/repo/context.ts", "context.ts", source);
  assert.deepEqual(result.dependencies.map(({ kind, specifier }) => ({ kind, specifier })), [
    { kind: "require", specifier: "./actual" },
    { kind: "dynamic_import", specifier: "./lazy" },
  ]);
  assert.equal(result.parseErrors.length, 0);
});
