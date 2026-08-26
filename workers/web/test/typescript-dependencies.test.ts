/**
 * Characterization tests for the public API of `src/typescript-dependencies.ts`.
 *
 * These tests intentionally pin the *current* observable output of each public
 * function so that a pure code-motion split of the module can be reviewed as
 * "tests unchanged, still green". They are not specifications: when behaviour is
 * deliberately changed, the pinned values here are expected to change with it.
 *
 * `test/typescript-semantic.test.ts` keeps its own coarse-grained dependency
 * coverage; the overlap is deliberate because the two files serve different
 * roles.
 */
import assert from "node:assert/strict";
import path from "node:path";
import { test } from "node:test";
import { API, type Checker } from "typescript/unstable/async";
import type { FileSystem, FileSystemEntries } from "typescript/unstable/fs";
import { resolveTypeScriptCompiler } from "../src/typescript-compiler";
import {
  extractTypeScriptRawDefinitionDelta,
  type TypeScriptRawDefinitionDelta,
  type TypeScriptSemanticSource,
} from "../src/typescript-semantic";
import {
  callValidationSpans,
  extractTypeScriptRawDependencyDelta,
  importTypeModuleValidationSpans,
  moduleCallValidationSpans,
  moduleCallValidationSpansFromSyntax,
  nonLiteralModuleValidationSpans,
  typeUseValidationSpans,
  validateTypeScriptRawDependencyDelta,
  type TypeScriptCallValidationSpan,
  type TypeScriptDependencyValidationSource,
  type TypeScriptModuleCallValidationSpan,
  type TypeScriptNonLiteralModuleValidationSpan,
  type TypeScriptRawCallSite,
  type TypeScriptRawDependencyDelta,
  type TypeScriptRawDependencySite,
  type TypeScriptTypeUseValidationSpan,
} from "../src/typescript-dependencies";

// ---------------------------------------------------------------------------
// Compiler harness (mirrors test/typescript-semantic.test.ts)
// ---------------------------------------------------------------------------

function pathKey(value: string): string {
  const normalized = path.normalize(path.resolve(value));
  return process.platform === "win32" ? normalized.toLowerCase() : normalized;
}

function testFileSystem(files: ReadonlyMap<string, string>): FileSystem {
  const content = new Map<string, string>();
  const directories = new Map<string, { path: string; files: Set<string>; directories: Set<string> }>();
  const ensureDirectory = (directory: string): void => {
    let current = path.resolve(directory);
    for (;;) {
      const key = pathKey(current);
      if (!directories.has(key)) directories.set(key, { path: current, files: new Set(), directories: new Set() });
      const parent = path.dirname(current);
      if (parent === current) break;
      const parentKey = pathKey(parent);
      if (!directories.has(parentKey)) directories.set(parentKey, { path: parent, files: new Set(), directories: new Set() });
      directories.get(parentKey)!.directories.add(path.basename(current));
      current = parent;
    }
  };
  for (const [file, source] of files) {
    const absolute = path.resolve(file);
    content.set(pathKey(absolute), source);
    const directory = path.dirname(absolute);
    ensureDirectory(directory);
    directories.get(pathKey(directory))!.files.add(path.basename(absolute));
  }
  return {
    readFile: (fileName): string | null => content.get(pathKey(fileName)) ?? null,
    fileExists: (fileName): boolean => content.has(pathKey(fileName)),
    directoryExists: (directoryName): boolean => directories.has(pathKey(directoryName)),
    getAccessibleEntries: (directoryName): FileSystemEntries => {
      const directory = directories.get(pathKey(directoryName));
      return {
        files: directory ? [...directory.files].sort() : [],
        directories: directory ? [...directory.directories].sort() : [],
      };
    },
    realpath: (fileName): string => path.normalize(path.resolve(fileName)),
  };
}

/**
 * Opens a real TypeScript Program/Checker over an in-memory project rooted at a
 * caller-chosen virtual directory, and hands the live checker plus the worker's
 * own semantic source inventory to `run`.
 */
async function withDependencyProject<T>(
  sources: Readonly<Record<string, string>>,
  virtualRootName: string,
  run: (project: { checker: Checker; inputs: TypeScriptSemanticSource[] }) => Promise<T>,
): Promise<T> {
  const compiler = await resolveTypeScriptCompiler();
  const virtualRoot = path.join(path.parse(process.execPath).root, virtualRootName);
  const config = path.join(virtualRoot, "tsconfig.json");
  const virtualFiles = new Map<string, string>();
  for (const [relativePath, source] of Object.entries(sources)) {
    virtualFiles.set(path.join(virtualRoot, ...relativePath.split("/")), source);
  }
  virtualFiles.set(config, `${JSON.stringify({
    compilerOptions: {
      allowJs: true,
      checkJs: false,
      jsx: "preserve",
      module: "preserve",
      moduleDetection: "force",
      moduleResolution: "bundler",
      noEmit: true,
      noLib: true,
      target: "esnext",
    },
    files: Object.keys(sources).sort(),
  })}\n`);
  const api = new API({
    cwd: path.parse(process.execPath).root,
    fs: testFileSystem(virtualFiles),
    tsserverPath: compiler,
  });
  const snapshot = await api.updateSnapshot({ openProjects: [config] });
  try {
    const project = snapshot.getProjects()[0];
    assert.ok(project);
    const inputs: TypeScriptSemanticSource[] = [];
    for (const relativePath of Object.keys(sources).sort()) {
      const virtualPath = path.join(virtualRoot, ...relativePath.split("/"));
      const sourceFile = await project.program.getSourceFile(virtualPath);
      assert.ok(sourceFile);
      const diagnostics = await project.program.getSyntacticDiagnostics(virtualPath);
      inputs.push({
        relativePath,
        compilerPath: virtualPath,
        expectedText: sources[relativePath]!,
        sourceFile,
        syntacticallyValid: diagnostics.length === 0,
      });
    }
    return await run({ checker: project.checker, inputs });
  } finally {
    await snapshot.dispose();
    await api.close();
  }
}

// ---------------------------------------------------------------------------
// Span snapshots
// ---------------------------------------------------------------------------

interface SpanSnapshot {
  text: string;
  syntacticallyValid: boolean;
  importTypeModuleSpans: Array<{ startOffset: number; endOffset: number }>;
  nonLiteralModuleSpans: TypeScriptNonLiteralModuleValidationSpan[];
  moduleCallSpansFromSyntax: TypeScriptModuleCallValidationSpan[];
  moduleCallSpans: TypeScriptModuleCallValidationSpan[];
  typeUseSpans: TypeScriptTypeUseValidationSpan[];
  callSpans: TypeScriptCallValidationSpan[];
  /** Same source, forced down the parser-only branch of `callValidationSpans`. */
  callSpansForcedLexical: TypeScriptCallValidationSpan[];
  /** Budget shared by the module-call, type-use and call queries, in that order. */
  sharedQueryBudget: number;
}

async function collectSpanSnapshots(
  sources: Readonly<Record<string, string>>,
  virtualRootName: string,
): Promise<Map<string, SpanSnapshot>> {
  return await withDependencyProject(sources, virtualRootName, async ({ checker, inputs }) => {
    const snapshots = new Map<string, SpanSnapshot>();
    for (const source of inputs) {
      const budget = { value: 0 };
      const importTypeModuleSpans = importTypeModuleValidationSpans(source.sourceFile);
      const nonLiteralModuleSpans = nonLiteralModuleValidationSpans(source.sourceFile);
      const moduleCallSpansFromSyntax = moduleCallValidationSpansFromSyntax(source.sourceFile);
      const moduleCallSpans = await moduleCallValidationSpans(checker, source.sourceFile, budget);
      const typeUseSpans = await typeUseValidationSpans(checker, source.sourceFile, budget);
      const callSpans = await callValidationSpans(checker, source.sourceFile, budget, source.syntacticallyValid);
      const callSpansForcedLexical = await callValidationSpans(checker, source.sourceFile, { value: 0 }, false);
      snapshots.set(source.relativePath, {
        text: source.expectedText,
        syntacticallyValid: source.syntacticallyValid,
        importTypeModuleSpans,
        nonLiteralModuleSpans,
        moduleCallSpansFromSyntax,
        moduleCallSpans,
        typeUseSpans,
        callSpans,
        callSpansForcedLexical,
        sharedQueryBudget: budget.value,
      });
    }
    return snapshots;
  });
}

function snapshotFor(snapshots: ReadonlyMap<string, SpanSnapshot>, relativePath: string): SpanSnapshot {
  const snapshot = snapshots.get(relativePath);
  assert.ok(snapshot, `missing span snapshot for ${relativePath}`);
  return snapshot;
}

/** Renders pinned offsets back into source text so the numbers stay auditable. */
function sliceSpans(
  text: string,
  spans: readonly { startOffset: number; endOffset: number }[],
): string[] {
  return spans.map((spanValue) => text.slice(spanValue.startOffset, spanValue.endOffset));
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/** Syntactically valid sources covering every validation-span occurrence kind. */
const SPAN_SOURCES = {
  "src/defs.ts": [
    "export interface Value { readonly id: string }",
    "export class Base { run(): void {} }",
    "export function tag(parts: TemplateStringsArray): string { return parts[0]! }",
    "export const runtime = 1;",
    "",
  ].join("\n"),
  "src/doc.js": [
    '/** @import { Value } from "./defs" */',
    '/** @type {import("./defs").Value} */',
    'export const documented = { id: "js" };',
    "",
  ].join("\n"),
  "src/imported-require.ts": [
    'import require from "other-require";',
    'export const importedCall = require("./imported-target");',
    "",
  ].join("\n"),
  "src/shadow.ts": [
    "function require(value: string): string { return value }",
    'export const shadowed = require("./shadow-target");',
    "",
  ].join("\n"),
  "src/spans.ts": [
    'import { Base, tag, runtime } from "./defs";',
    'type Inline = import("./defs").Value;',
    "interface Holder extends Base { readonly field: Inline }",
    'const dynamic = import("./dynamic-target");',
    'const legacy = require("./require-target");',
    "const computed = require(runtime);",
    "const missing = require();",
    "const built = new Base();",
    "const tagged = tag`literal`;",
    "export function consume(holder: Holder): void { void holder; void dynamic; void legacy; void computed; void missing; void built; void tagged }",
    "",
  ].join("\n"),
};

/**
 * Sources the parser accepts only loosely: grammar-late non-literal module
 * specifiers, and a genuine parse error.
 */
const IRREGULAR_SOURCES = {
  "src/broken.ts": [
    "export function helper(): void {}",
    "export const broken = helper(;",
    'export const loader = require("./broken-target");',
    "",
  ].join("\n"),
  "src/nonliteral.ts": [
    "declare const moduleName: string;",
    "declare const otherModule: string;",
    "declare const referenceName: string;",
    "import fromIdentifier from moduleName;",
    "export * from otherModule;",
    "import equals = require(referenceName);",
    "",
  ].join("\n"),
};

/** Minimal cross-file project exercising imports, re-exports, type uses and calls. */
const DELTA_SOURCES = {
  "src/defs.ts": [
    "export interface Value { readonly id: string }",
    "export function named(): void {}",
    "",
  ].join("\n"),
  "src/main.ts": [
    'import { named, type Value } from "./defs";',
    'export { named as forwarded } from "./defs";',
    "interface Holder { readonly field: Value }",
    'export function run(): Holder { named(); return { field: { id: "x" } } }',
    "",
  ].join("\n"),
};

/** Byte length of `src/main.ts`, which is also its module binding scope. */
const MAIN_LENGTH = 205;

// ---------------------------------------------------------------------------
// Canonical key reconstruction
// ---------------------------------------------------------------------------

const moduleOwnerKey = (
  space: "symbol" | "type",
  relativePath: string,
  exportPath: readonly string[],
): string => `definition:${JSON.stringify(["module", space, relativePath, exportPath])}`;

const symbolDefinitionKey = (semanticKind: string, nameKind: string, owner: string): string =>
  `definition:${JSON.stringify(["symbol", semanticKind, nameKind, owner, null])}`;

const typeDefinitionKey = (semanticKind: string, owner: string): string =>
  `definition:${JSON.stringify(["type", semanticKind, null, owner, null])}`;

const siteKey = (
  source: unknown,
  kind: string,
  relativePath: string,
  startOffset: number,
  endOffset: number,
): string => `site:${JSON.stringify([source, kind, relativePath, startOffset, endOffset])}`;

const DEFS_NAMED = symbolDefinitionKey("function", "named", moduleOwnerKey("symbol", "src/defs.ts", ["named"]));
const DEFS_VALUE = typeDefinitionKey("interface", moduleOwnerKey("type", "src/defs.ts", ["Value"]));
const MAIN_RUN = symbolDefinitionKey("function", "named", moduleOwnerKey("symbol", "src/main.ts", ["run"]));
const MAIN_HOLDER = typeDefinitionKey("interface", moduleOwnerKey("type", "src/main.ts", ["Holder"]));

const MAIN_FILE_SOURCE = { kind: "file", relativePath: "src/main.ts" } as const;
const MAIN_RUN_SOURCE = { kind: "definition", key: MAIN_RUN } as const;
const MAIN_HOLDER_SOURCE = { kind: "definition", key: MAIN_HOLDER } as const;

/** The canonical web condition every occurrence in these fixtures carries. */
const WEB_SITE_CONDITION = {
  op: "all",
  conditions: [
    { op: "eq", key: "mode", value: "production" },
    { op: "in", key: "environment", values: ["browser", "server"] },
  ],
};

// ---------------------------------------------------------------------------
// Dependency delta harness
// ---------------------------------------------------------------------------

interface DependencyDeltaFixture {
  definitions: TypeScriptRawDefinitionDelta;
  dependencies: TypeScriptRawDependencyDelta;
  validationSources: TypeScriptDependencyValidationSource[];
}

/** Mirrors the scanner's production wiring of extraction plus validation input. */
async function extractDependencyDelta(
  sources: Readonly<Record<string, string>>,
  virtualRootName: string,
): Promise<DependencyDeltaFixture> {
  return await withDependencyProject(sources, virtualRootName, async ({ checker, inputs }) => {
    const definitions = await extractTypeScriptRawDefinitionDelta(checker, inputs);
    const dependencies = await extractTypeScriptRawDependencyDelta(
      checker,
      inputs,
      definitions,
      definitions.typeCheckerQueries,
    );
    const budget = { value: 0 };
    const validationSources: TypeScriptDependencyValidationSource[] = [];
    for (const source of inputs) {
      validationSources.push({
        relativePath: source.relativePath,
        text: source.expectedText,
        syntacticallyValid: source.syntacticallyValid,
        importTypeModuleSpans: source.syntacticallyValid
          ? importTypeModuleValidationSpans(source.sourceFile)
          : [],
        moduleCallSpans: source.syntacticallyValid
          ? await moduleCallValidationSpans(checker, source.sourceFile, budget)
          : [],
        nonLiteralModuleSpans: source.syntacticallyValid
          ? nonLiteralModuleValidationSpans(source.sourceFile)
          : [],
        typeUseSpans: source.syntacticallyValid
          ? await typeUseValidationSpans(checker, source.sourceFile, budget)
          : [],
        callSpans: await callValidationSpans(checker, source.sourceFile, budget, source.syntacticallyValid),
      });
    }
    return { definitions, dependencies, validationSources };
  });
}

/** Drops the condition lattice, which every test asserts separately. */
function siteSnapshot(site: TypeScriptRawDependencySite): Record<string, unknown> {
  const { condition: _condition, targetConditions: _targetConditions, ...rest } = site;
  return rest;
}

function callSnapshot(call: TypeScriptRawCallSite): Record<string, unknown> {
  const { condition: _condition, targetConditions: _targetConditions, ...rest } = call;
  return rest;
}

// ---------------------------------------------------------------------------
// importTypeModuleValidationSpans
// ---------------------------------------------------------------------------

test("importTypeModuleValidationSpans pins ImportType and JSDoc @import module spans", async () => {
  const snapshots = await collectSpanSnapshots(SPAN_SOURCES, "__depgraph_ts_deps_import_type__");

  const spans = snapshotFor(snapshots, "src/spans.ts");
  assert.deepStrictEqual(spans.importTypeModuleSpans, [{ startOffset: 66, endOffset: 74 }]);
  assert.deepStrictEqual(sliceSpans(spans.text, spans.importTypeModuleSpans), ['"./defs"']);

  // A JSDoc `@import` tag and an inline `import(...)` type both contribute, and
  // the result is deduplicated then sorted by span.
  const doc = snapshotFor(snapshots, "src/doc.js");
  assert.deepStrictEqual(doc.importTypeModuleSpans, [
    { startOffset: 27, endOffset: 35 },
    { startOffset: 57, endOffset: 65 },
  ]);
  assert.deepStrictEqual(sliceSpans(doc.text, doc.importTypeModuleSpans), ['"./defs"', '"./defs"']);

  // Sources without any module-typed import contribute nothing.
  assert.deepStrictEqual(snapshotFor(snapshots, "src/defs.ts").importTypeModuleSpans, []);
  assert.deepStrictEqual(snapshotFor(snapshots, "src/shadow.ts").importTypeModuleSpans, []);
});

// ---------------------------------------------------------------------------
// nonLiteralModuleValidationSpans
// ---------------------------------------------------------------------------

test("nonLiteralModuleValidationSpans pins grammar-late non-literal module occurrences", async () => {
  const snapshots = await collectSpanSnapshots(IRREGULAR_SOURCES, "__depgraph_ts_deps_non_literal__");
  const nonLiteral = snapshotFor(snapshots, "src/nonliteral.ts");

  // The parser accepts these recovery-parsed specifiers, so the file still
  // reports as syntactically valid.
  assert.equal(nonLiteral.syntacticallyValid, true);
  assert.equal(nonLiteral.text.length, 212);
  assert.deepStrictEqual(nonLiteral.nonLiteralModuleSpans, [
    {
      startOffset: 133,
      endOffset: 143,
      siteKind: "web_import",
      occurrenceKind: "dynamic_import",
      moduleSpecifier: "moduleName",
      importedName: null,
      bindingKind: null,
      bindingScope: null,
      typeOnly: false,
      resolutionMode: null,
      resolutionModeProof: null,
      resolutionModeError: null,
    },
    {
      startOffset: 159,
      endOffset: 170,
      siteKind: "web_reexport",
      occurrenceKind: "export_star",
      moduleSpecifier: "otherModule",
      importedName: null,
      bindingKind: null,
      bindingScope: null,
      typeOnly: false,
      resolutionMode: null,
      resolutionModeProof: null,
      resolutionModeError: null,
    },
    {
      startOffset: 196,
      endOffset: 209,
      siteKind: "web_import",
      occurrenceKind: "import_equals",
      moduleSpecifier: "referenceName",
      importedName: "=",
      bindingKind: "import_equals",
      bindingScope: { startOffset: 0, endOffset: 212 },
      typeOnly: false,
      resolutionMode: null,
      resolutionModeProof: null,
      resolutionModeError: null,
    },
  ]);
  assert.deepStrictEqual(
    sliceSpans(nonLiteral.text, nonLiteral.nonLiteralModuleSpans),
    ["moduleName", "otherModule", "referenceName"],
  );

  // String-literal specifiers are excluded by construction.
  const literalOnly = await collectSpanSnapshots(SPAN_SOURCES, "__depgraph_ts_deps_literal_only__");
  for (const relativePath of Object.keys(SPAN_SOURCES)) {
    assert.deepStrictEqual(snapshotFor(literalOnly, relativePath).nonLiteralModuleSpans, [], relativePath);
  }
});

// ---------------------------------------------------------------------------
// moduleCallValidationSpansFromSyntax
// ---------------------------------------------------------------------------

test("moduleCallValidationSpansFromSyntax pins literal, computed and missing module-call syntax", async () => {
  const snapshots = await collectSpanSnapshots(SPAN_SOURCES, "__depgraph_ts_deps_module_call_syntax__");
  const spans = snapshotFor(snapshots, "src/spans.ts");

  assert.deepStrictEqual(spans.moduleCallSpansFromSyntax, [
    {
      startOffset: 163,
      endOffset: 181,
      occurrenceKind: "dynamic_import",
      syntax: "literal",
      moduleSpecifier: "./dynamic-target",
    },
    {
      startOffset: 207,
      endOffset: 225,
      occurrenceKind: "require_call",
      syntax: "literal",
      moduleSpecifier: "./require-target",
    },
    {
      startOffset: 253,
      endOffset: 260,
      occurrenceKind: "require_call",
      syntax: "computed",
      moduleSpecifier: "runtime",
    },
    {
      startOffset: 279,
      endOffset: 288,
      occurrenceKind: "require_call",
      syntax: "missing",
      moduleSpecifier: "<missing>",
    },
  ]);
  assert.deepStrictEqual(sliceSpans(spans.text, spans.moduleCallSpansFromSyntax), [
    '"./dynamic-target"',
    '"./require-target"',
    "runtime",
    "require()",
  ]);

  // A locally declared `require` and an imported `require` are both lexically
  // shadowed, so neither yields a module call.
  assert.deepStrictEqual(snapshotFor(snapshots, "src/shadow.ts").moduleCallSpansFromSyntax, []);
  assert.deepStrictEqual(snapshotFor(snapshots, "src/imported-require.ts").moduleCallSpansFromSyntax, []);

  // The parser-only variant still reports module calls inside an unparseable file.
  const irregular = await collectSpanSnapshots(IRREGULAR_SOURCES, "__depgraph_ts_deps_module_call_broken__");
  const broken = snapshotFor(irregular, "src/broken.ts");
  assert.equal(broken.syntacticallyValid, false);
  assert.deepStrictEqual(broken.moduleCallSpansFromSyntax, [{
    startOffset: 95,
    endOffset: 112,
    occurrenceKind: "require_call",
    syntax: "literal",
    moduleSpecifier: "./broken-target",
  }]);
  assert.deepStrictEqual(sliceSpans(broken.text, broken.moduleCallSpansFromSyntax), ['"./broken-target"']);
});

// ---------------------------------------------------------------------------
// moduleCallValidationSpans
// ---------------------------------------------------------------------------

test("moduleCallValidationSpans pins checker-confirmed module calls and its query budget", async () => {
  const snapshots = await collectSpanSnapshots(SPAN_SOURCES, "__depgraph_ts_deps_module_call__");
  const spans = snapshotFor(snapshots, "src/spans.ts");

  assert.deepStrictEqual(spans.moduleCallSpans, [
    {
      startOffset: 163,
      endOffset: 181,
      occurrenceKind: "dynamic_import",
      syntax: "literal",
      moduleSpecifier: "./dynamic-target",
    },
    {
      startOffset: 207,
      endOffset: 225,
      occurrenceKind: "require_call",
      syntax: "literal",
      moduleSpecifier: "./require-target",
    },
    {
      startOffset: 253,
      endOffset: 260,
      occurrenceKind: "require_call",
      syntax: "computed",
      moduleSpecifier: "runtime",
    },
    {
      startOffset: 279,
      endOffset: 288,
      occurrenceKind: "require_call",
      syntax: "missing",
      moduleSpecifier: "<missing>",
    },
  ]);

  // With no ambient `require` declaration in scope the checker-confirmed result
  // agrees with the parser-only result on every fixture source.
  for (const relativePath of Object.keys(SPAN_SOURCES)) {
    const snapshot = snapshotFor(snapshots, relativePath);
    assert.deepStrictEqual(snapshot.moduleCallSpans, snapshot.moduleCallSpansFromSyntax, relativePath);
  }

  // Shadowed callees are rejected lexically, before any TypeChecker query is spent.
  assert.equal(snapshotFor(snapshots, "src/shadow.ts").sharedQueryBudget, 0);
  assert.equal(snapshotFor(snapshots, "src/imported-require.ts").sharedQueryBudget, 0);
  assert.equal(snapshotFor(snapshots, "src/defs.ts").sharedQueryBudget, 2);
  assert.equal(snapshotFor(snapshots, "src/doc.js").sharedQueryBudget, 2);
  assert.equal(spans.sharedQueryBudget, 20);
});

// ---------------------------------------------------------------------------
// callValidationSpans
// ---------------------------------------------------------------------------

test("callValidationSpans pins non-module call, new and tagged-template occurrences", async () => {
  const snapshots = await collectSpanSnapshots(SPAN_SOURCES, "__depgraph_ts_deps_calls__");
  const spans = snapshotFor(snapshots, "src/spans.ts");

  // Module loader calls (`import(...)`, ambient `require(...)`) are excluded.
  assert.deepStrictEqual(spans.callSpans, [
    { startOffset: 304, endOffset: 314, occurrenceKind: "new_expression", specifier: "Base" },
    { startOffset: 331, endOffset: 343, occurrenceKind: "tagged_template", specifier: "tag" },
  ]);
  assert.deepStrictEqual(sliceSpans(spans.text, spans.callSpans), ["new Base()", "tag`literal`"]);

  // A shadowed `require` is not a module loader, so it stays a plain call.
  const shadow = snapshotFor(snapshots, "src/shadow.ts");
  assert.deepStrictEqual(shadow.callSpans, [
    { startOffset: 81, endOffset: 107, occurrenceKind: "call_expression", specifier: "require" },
  ]);
  assert.deepStrictEqual(sliceSpans(shadow.text, shadow.callSpans), ['require("./shadow-target")']);

  const imported = snapshotFor(snapshots, "src/imported-require.ts");
  assert.deepStrictEqual(imported.callSpans, [
    { startOffset: 65, endOffset: 93, occurrenceKind: "call_expression", specifier: "require" },
  ]);
  assert.deepStrictEqual(sliceSpans(imported.text, imported.callSpans), ['require("./imported-target")']);

  // Forcing the parser-only branch does not change the result for these sources.
  for (const relativePath of Object.keys(SPAN_SOURCES)) {
    const snapshot = snapshotFor(snapshots, relativePath);
    assert.deepStrictEqual(snapshot.callSpansForcedLexical, snapshot.callSpans, relativePath);
  }

  // An unparseable source still yields its recoverable calls while its
  // `require(...)` loader stays excluded through the lexical branch.
  const irregular = await collectSpanSnapshots(IRREGULAR_SOURCES, "__depgraph_ts_deps_calls_broken__");
  const broken = snapshotFor(irregular, "src/broken.ts");
  assert.equal(broken.syntacticallyValid, false);
  assert.deepStrictEqual(broken.callSpans, [
    { startOffset: 56, endOffset: 63, occurrenceKind: "call_expression", specifier: "helper" },
  ]);
  assert.deepStrictEqual(sliceSpans(broken.text, broken.callSpans), ["helper("]);
});

// ---------------------------------------------------------------------------
// typeUseValidationSpans
// ---------------------------------------------------------------------------

test("typeUseValidationSpans pins type-reference, heritage and inline-import type uses", async () => {
  const snapshots = await collectSpanSnapshots(SPAN_SOURCES, "__depgraph_ts_deps_type_uses__");
  const spans = snapshotFor(snapshots, "src/spans.ts");

  assert.deepStrictEqual(spans.typeUseSpans, [
    {
      startOffset: 76,
      endOffset: 81,
      occurrenceKind: "type_reference",
      terminalName: "Value",
      inlineImportModuleStartOffset: 66,
      inlineImportModuleEndOffset: 74,
    },
    {
      startOffset: 108,
      endOffset: 112,
      occurrenceKind: "heritage_type",
      terminalName: "Base",
      inlineImportModuleStartOffset: null,
      inlineImportModuleEndOffset: null,
    },
    {
      startOffset: 131,
      endOffset: 137,
      occurrenceKind: "type_reference",
      terminalName: "Inline",
      inlineImportModuleStartOffset: null,
      inlineImportModuleEndOffset: null,
    },
    {
      startOffset: 377,
      endOffset: 383,
      occurrenceKind: "type_reference",
      terminalName: "Holder",
      inlineImportModuleStartOffset: null,
      inlineImportModuleEndOffset: null,
    },
  ]);
  assert.deepStrictEqual(sliceSpans(spans.text, spans.typeUseSpans), ["Value", "Base", "Inline", "Holder"]);

  // The terminal name is the exact parser-attested identifier at the span, and
  // an inline import type reports its parent module span.
  for (const spanValue of spans.typeUseSpans) {
    assert.equal(spans.text.slice(spanValue.startOffset, spanValue.endOffset), spanValue.terminalName);
  }
  assert.equal(spans.text.slice(66, 74), '"./defs"');

  // A JSDoc `@type {import("./defs").Value}` is reported as a type reference
  // carrying its inline import module span.
  const doc = snapshotFor(snapshots, "src/doc.js");
  assert.deepStrictEqual(doc.typeUseSpans, [{
    startOffset: 67,
    endOffset: 72,
    occurrenceKind: "type_reference",
    terminalName: "Value",
    inlineImportModuleStartOffset: 57,
    inlineImportModuleEndOffset: 65,
  }]);

  // Unresolved global type names are still reported by name.
  assert.deepStrictEqual(snapshotFor(snapshots, "src/defs.ts").typeUseSpans, [{
    startOffset: 111,
    endOffset: 131,
    occurrenceKind: "type_reference",
    terminalName: "TemplateStringsArray",
    inlineImportModuleStartOffset: null,
    inlineImportModuleEndOffset: null,
  }]);
});

// ---------------------------------------------------------------------------
// extractTypeScriptRawDependencyDelta
// ---------------------------------------------------------------------------

test("extractTypeScriptRawDependencyDelta pins the raw delta and stays deterministic", async () => {
  const first = await extractDependencyDelta(DELTA_SOURCES, "__depgraph_ts_deps_delta_a__");
  const second = await extractDependencyDelta(DELTA_SOURCES, "__depgraph_ts_deps_delta_z__");

  // Determinism: the same inputs produce byte-identical deltas, and the virtual
  // project root never leaks into the result.
  assert.deepStrictEqual(first.dependencies, second.dependencies);

  assert.equal(DELTA_SOURCES["src/main.ts"].length, MAIN_LENGTH);
  assert.deepStrictEqual(first.dependencies.issues, []);
  assert.equal(first.dependencies.sites.length, 5);
  assert.equal(first.dependencies.calls.length, 1);

  assert.deepStrictEqual(first.dependencies.sites.map(siteSnapshot), [
    {
      key: siteKey(MAIN_RUN_SOURCE, "type_use", "src/main.ts", 155, 161),
      kind: "type_use",
      edgeKind: "type_uses",
      source: { kind: "definition", key: MAIN_RUN },
      specifier: "Holder",
      moduleSpecifier: null,
      importedName: "Holder",
      exportPath: null,
      resolutionMode: null,
      resolutionModeProof: null,
      bindingKind: null,
      bindingOrigin: null,
      bindingScope: null,
      typeOnly: true,
      status: "resolved",
      precision: "exact",
      reason: null,
      targets: [{ kind: "definition", key: MAIN_HOLDER }],
      evidence: {
        relativePath: "src/main.ts",
        startOffset: 155,
        endOffset: 161,
        detail: "TypeChecker named type reference occurrence",
        occurrenceKind: "type_reference",
        targetBasis: "canonical_definition",
      },
    },
    {
      key: siteKey(MAIN_HOLDER_SOURCE, "type_use", "src/main.ts", 124, 129),
      kind: "type_use",
      edgeKind: "type_uses",
      source: { kind: "definition", key: MAIN_HOLDER },
      specifier: "Value",
      moduleSpecifier: "./defs",
      importedName: "Value",
      exportPath: ["Value"],
      resolutionMode: null,
      resolutionModeProof: null,
      bindingKind: "named",
      bindingOrigin: {
        siteKey: siteKey(MAIN_FILE_SOURCE, "web_import", "src/main.ts", 21, 26),
        declarationStartOffset: 21,
        declarationEndOffset: 26,
        scopeStartOffset: 0,
        scopeEndOffset: MAIN_LENGTH,
        referenceStartOffset: 124,
        referenceEndOffset: 129,
      },
      bindingScope: null,
      typeOnly: true,
      status: "resolved",
      precision: "exact",
      reason: null,
      targets: [{ kind: "definition", key: DEFS_VALUE }],
      evidence: {
        relativePath: "src/main.ts",
        startOffset: 124,
        endOffset: 129,
        detail: "TypeChecker named type reference occurrence",
        occurrenceKind: "type_reference",
        targetBasis: "canonical_definition",
      },
    },
    {
      key: siteKey(MAIN_FILE_SOURCE, "web_import", "src/main.ts", 21, 26),
      kind: "web_import",
      edgeKind: "imports",
      source: { kind: "file", relativePath: "src/main.ts" },
      specifier: "./defs",
      moduleSpecifier: "./defs",
      importedName: "Value",
      exportPath: ["Value"],
      resolutionMode: null,
      resolutionModeProof: null,
      bindingKind: "named",
      bindingOrigin: null,
      bindingScope: { startOffset: 0, endOffset: MAIN_LENGTH },
      typeOnly: true,
      status: "resolved",
      precision: "exact",
      reason: null,
      targets: [{ kind: "definition", key: DEFS_VALUE }],
      evidence: {
        relativePath: "src/main.ts",
        startOffset: 21,
        endOffset: 26,
        detail: "TypeChecker named import binding occurrence",
        occurrenceKind: "named_import",
        targetBasis: "canonical_definition",
      },
    },
    {
      key: siteKey(MAIN_FILE_SOURCE, "web_import", "src/main.ts", 9, 14),
      kind: "web_import",
      edgeKind: "imports",
      source: { kind: "file", relativePath: "src/main.ts" },
      specifier: "./defs",
      moduleSpecifier: "./defs",
      importedName: "named",
      exportPath: ["named"],
      resolutionMode: null,
      resolutionModeProof: null,
      bindingKind: "named",
      bindingOrigin: null,
      bindingScope: { startOffset: 0, endOffset: MAIN_LENGTH },
      typeOnly: false,
      status: "resolved",
      precision: "exact",
      reason: null,
      targets: [{ kind: "definition", key: DEFS_NAMED }],
      evidence: {
        relativePath: "src/main.ts",
        startOffset: 9,
        endOffset: 14,
        detail: "TypeChecker named import binding occurrence",
        occurrenceKind: "named_import",
        targetBasis: "canonical_definition",
      },
    },
    {
      key: siteKey(MAIN_FILE_SOURCE, "web_reexport", "src/main.ts", 62, 71),
      kind: "web_reexport",
      edgeKind: "reexports",
      source: { kind: "file", relativePath: "src/main.ts" },
      specifier: "./defs",
      moduleSpecifier: "./defs",
      importedName: "named",
      exportPath: ["named"],
      resolutionMode: null,
      resolutionModeProof: null,
      bindingKind: "named",
      bindingOrigin: null,
      bindingScope: null,
      typeOnly: false,
      status: "resolved",
      precision: "exact",
      reason: null,
      targets: [{ kind: "definition", key: DEFS_NAMED }],
      evidence: {
        relativePath: "src/main.ts",
        startOffset: 62,
        endOffset: 71,
        detail: "TypeChecker named re-export binding occurrence",
        occurrenceKind: "named_reexport",
        targetBasis: "canonical_definition",
      },
    },
  ]);

  assert.deepStrictEqual(first.dependencies.calls.map(callSnapshot), [{
    key: siteKey(MAIN_RUN_SOURCE, "call", "src/main.ts", 164, 171),
    source: { kind: "definition", key: MAIN_RUN },
    specifier: "named",
    callKind: "function",
    dispatch: "direct",
    moduleSpecifier: "./defs",
    status: "resolved",
    precision: "exact",
    reason: null,
    algorithm: null,
    targets: [{ kind: "definition", key: DEFS_NAMED }],
    evidence: {
      relativePath: "src/main.ts",
      startOffset: 164,
      endOffset: 171,
      detail: "TypeChecker resolved-signature direct call occurrence",
      occurrenceKind: "call_expression",
      targetBasis: "canonical_definition",
    },
  }]);

  assert.deepStrictEqual(first.dependencies.moduleExports, [
    { relativePath: "src/defs.ts", exportPath: ["Value"], definitionKeys: [DEFS_VALUE] },
    { relativePath: "src/defs.ts", exportPath: ["named"], definitionKeys: [DEFS_NAMED] },
  ]);

  // Every occurrence carries the canonical web condition, aligned per target.
  for (const occurrence of [...first.dependencies.sites, ...first.dependencies.calls]) {
    assert.deepStrictEqual(occurrence.condition, WEB_SITE_CONDITION, occurrence.key);
    assert.equal(occurrence.targetConditions.length, occurrence.targets.length, occurrence.key);
    for (const condition of occurrence.targetConditions) {
      assert.deepStrictEqual(condition, WEB_SITE_CONDITION, occurrence.key);
    }
  }

  // Evidence spans stay inside their source and quote the text they claim.
  const mainText = DELTA_SOURCES["src/main.ts"];
  for (const occurrence of [...first.dependencies.sites, ...first.dependencies.calls]) {
    const { relativePath, startOffset, endOffset } = occurrence.evidence;
    assert.equal(relativePath, "src/main.ts", occurrence.key);
    assert.ok(startOffset >= 0 && endOffset > startOffset && endOffset <= mainText.length, occurrence.key);
  }
  assert.deepStrictEqual(
    first.dependencies.sites.map((site) => mainText.slice(site.evidence.startOffset, site.evidence.endOffset)),
    ["Holder", "Value", "Value", "named", "forwarded"],
  );
  assert.equal(mainText.slice(164, 171), "named()");

  // The dependency pass continues, rather than resets, the definition pass's
  // TypeChecker query counter.
  assert.ok(first.dependencies.typeCheckerQueries > first.definitions.typeCheckerQueries);
  assert.equal(first.dependencies.typeCheckerQueries, second.dependencies.typeCheckerQueries);
});

// ---------------------------------------------------------------------------
// validateTypeScriptRawDependencyDelta
// ---------------------------------------------------------------------------

test("validateTypeScriptRawDependencyDelta accepts the extracted delta and rejects mutations", async () => {
  const fixture = await extractDependencyDelta(DELTA_SOURCES, "__depgraph_ts_deps_validation__");

  assert.doesNotThrow(() => validateTypeScriptRawDependencyDelta(
    fixture.dependencies,
    fixture.definitions,
    fixture.validationSources,
  ));

  const reject = (mutate: (delta: TypeScriptRawDependencyDelta) => void, pattern: RegExp): void => {
    const delta = structuredClone(fixture.dependencies);
    mutate(delta);
    assert.throws(() => validateTypeScriptRawDependencyDelta(
      delta,
      fixture.definitions,
      fixture.validationSources,
    ), pattern);
  };

  // Span mutations: evidence must land exactly on a parser-attested occurrence.
  reject(
    (delta) => { delta.sites[0]!.evidence.startOffset += 1 },
    /raw dependency type-use occurrence contradicts parser context/u,
  );
  reject(
    (delta) => { delta.sites[0]!.evidence.endOffset += 1 },
    /raw dependency type-use occurrence contradicts parser context/u,
  );
  reject(
    (delta) => { delta.calls[0]!.evidence.startOffset += 1 },
    /raw call site does not correlate with its parser occurrence/u,
  );

  // Target mutations: a resolved occurrence cannot be retargeted or emptied.
  reject((delta) => {
    const site = delta.sites.find((candidate) => candidate.kind === "type_use");
    assert.ok(site);
    site.targets = [{ kind: "unknown" }];
  }, /raw dependency status\/precision\/target contract is invalid/u);
  reject((delta) => {
    const site = delta.sites.find((candidate) => candidate.kind === "web_import");
    assert.ok(site);
    site.targets = [{ kind: "file", relativePath: "src/main.ts" }];
  }, /raw named binding target cannot fall back to a file/u);
  reject(
    (delta) => { delta.calls[0]!.targets = [] },
    /raw call site has no target or unaligned target conditions/u,
  );

  // Condition mutations must stay aligned with their per-target conditions.
  reject(
    (delta) => { delta.sites[0]!.targetConditions[0] = { op: "eq", key: "mode", value: "test" } },
    /raw dependency site condition is not the aggregate of its target conditions/u,
  );

  // Evidence cannot be relocated into a source that never attested it.
  reject(
    (delta) => { delta.sites[0]!.evidence.relativePath = "src/defs.ts" },
    /raw dependency evidence is invalid/u,
  );

  // Binding metadata must keep correlating with the parsed import/re-export syntax.
  reject((delta) => {
    const site = delta.sites.find((candidate) => candidate.kind === "web_import");
    assert.ok(site);
    site.moduleSpecifier = "./other";
  }, /raw dependency direct binding syntax does not correlate/u);
  reject((delta) => {
    const site = delta.sites.find((candidate) => candidate.kind === "web_reexport");
    assert.ok(site);
    site.importedName = "missing";
  }, /raw dependency re-export syntax does not correlate/u);
});

test("validateTypeScriptRawDependencyDelta validates source context and span indexes independently", async () => {
  const fixture = await extractDependencyDelta(DELTA_SOURCES, "__depgraph_ts_deps_context_delta__");
  const contextFixtureSources = Object.fromEntries(
    Object.entries({ ...SPAN_SOURCES, ...IRREGULAR_SOURCES })
      .map(([relativePath, text]) => [`validation/${relativePath}`, text]),
  );
  const snapshots = await collectSpanSnapshots(
    contextFixtureSources,
    "__depgraph_ts_deps_context_spans__",
  );
  const contextSources: TypeScriptDependencyValidationSource[] = [...snapshots]
    .map(([relativePath, snapshot]) => ({
      relativePath,
      text: snapshot.text,
      syntacticallyValid: snapshot.syntacticallyValid,
      importTypeModuleSpans: snapshot.importTypeModuleSpans,
      moduleCallSpans: snapshot.moduleCallSpans,
      nonLiteralModuleSpans: snapshot.nonLiteralModuleSpans,
      typeUseSpans: snapshot.typeUseSpans,
      callSpans: snapshot.callSpans,
    }));
  const validationSources = [...fixture.validationSources, ...contextSources];

  const rejectSources = (
    mutate: (sources: TypeScriptDependencyValidationSource[]) => void,
    pattern: RegExp,
  ): void => {
    const sources = structuredClone(validationSources) as TypeScriptDependencyValidationSource[];
    mutate(sources);
    assert.throws(() => validateTypeScriptRawDependencyDelta(
      fixture.dependencies,
      fixture.definitions,
      sources,
    ), pattern);
  };

  rejectSources(
    (sources) => { sources[0]!.relativePath = "../outside.ts" },
    /raw dependency source path is not canonical/u,
  );
  rejectSources(
    (sources) => {
      sources[0] = null as unknown as TypeScriptDependencyValidationSource;
    },
    /raw dependency source is invalid/u,
  );
  rejectSources(
    (sources) => {
      (sources[0] as unknown as { relativePath: unknown }).relativePath = null;
    },
    /raw dependency source path is not canonical/u,
  );
  rejectSources(
    (sources) => { sources.push(structuredClone(sources[0]!)) },
    /raw dependency source path is duplicated/u,
  );
  rejectSources(
    (sources) => {
      (sources[0] as unknown as { text: unknown }).text = null;
    },
    /raw dependency source text is invalid/u,
  );
  rejectSources(
    (sources) => {
      (sources[0] as unknown as { syntacticallyValid: unknown }).syntacticallyValid = "true";
    },
    /raw dependency source syntax validity is invalid/u,
  );

  type SpanField =
    | "importTypeModuleSpans"
    | "moduleCallSpans"
    | "nonLiteralModuleSpans"
    | "typeUseSpans"
    | "callSpans";
  const spanCases: readonly { field: SpanField; errorName: string }[] = [
    { field: "importTypeModuleSpans", errorName: "import-type" },
    { field: "moduleCallSpans", errorName: "module-call" },
    { field: "nonLiteralModuleSpans", errorName: "non-literal module" },
    { field: "typeUseSpans", errorName: "type-use" },
    { field: "callSpans", errorName: "call" },
  ];
  const sourceWithSpan = (
    sources: TypeScriptDependencyValidationSource[],
    field: SpanField,
  ): TypeScriptDependencyValidationSource => {
    const source = sources.find((candidate) => candidate[field].length > 0);
    assert.ok(source, `missing ${field} fixture`);
    return source;
  };

  for (const { field, errorName } of spanCases) {
    rejectSources((sources) => {
      const source = sourceWithSpan(sources, field);
      (source as unknown as Record<SpanField, unknown>)[field] = null;
    }, new RegExp(`raw dependency ${errorName} validation spans are missing`, "u"));
    rejectSources((sources) => {
      const source = sourceWithSpan(sources, field);
      const spans = source[field];
      (source as unknown as Record<SpanField, unknown>)[field] = [
        null,
        ...spans.slice(1),
      ];
    }, new RegExp(`raw dependency ${errorName} validation span is invalid`, "u"));
    rejectSources((sources) => {
      const source = sourceWithSpan(sources, field);
      const spanValue = source[field][0]!;
      spanValue.endOffset = source.text.length + 1;
    }, new RegExp(`raw dependency ${errorName} validation span is invalid`, "u"));
    rejectSources((sources) => {
      const source = sourceWithSpan(sources, field);
      const spans = source[field];
      (source as unknown as Record<SpanField, unknown>)[field] = [
        ...spans,
        structuredClone(spans[0]!),
      ];
    }, new RegExp(`raw dependency ${errorName} validation span is duplicated`, "u"));
  }
});

test("validateTypeScriptRawDependencyDelta preserves phased validation and final closure", async () => {
  const fixture = await extractDependencyDelta(DELTA_SOURCES, "__depgraph_ts_deps_phases__");
  const validate = (delta: TypeScriptRawDependencyDelta): void => {
    validateTypeScriptRawDependencyDelta(delta, fixture.definitions, fixture.validationSources);
  };
  const reject = (mutate: (delta: TypeScriptRawDependencyDelta) => void, pattern: RegExp): void => {
    const delta = structuredClone(fixture.dependencies);
    mutate(delta);
    assert.throws(() => validate(delta), pattern);
  };

  const accepted = structuredClone(fixture.dependencies);
  const acceptedBeforeValidation = structuredClone(accepted);
  assert.doesNotThrow(() => validate(accepted));
  assert.deepStrictEqual(accepted, acceptedBeforeValidation);

  reject((delta) => {
    delta.moduleExports[0]!.definitionKeys[0] = "missing-definition";
  }, /raw module export target is not a canonical definition/u);
  reject((delta) => {
    delta.sites[0]!.evidence.startOffset += 1;
  }, /raw dependency type-use occurrence contradicts parser context/u);
  reject((delta) => {
    const site = delta.sites.find((candidate) => candidate.bindingOrigin !== null);
    assert.ok(site?.bindingOrigin);
    site.bindingOrigin.siteKey = "missing-binding-origin";
  }, /raw dependency binding origin does not correlate/u);
  reject((delta) => {
    delta.sites[0]!.targetConditions = [];
  }, /raw dependency target conditions do not align with targets/u);
  reject((delta) => {
    delta.calls[0]!.dispatch = "open";
  }, /raw call status\/precision\/target contract is invalid/u);

  reject((delta) => {
    delta.moduleExports.reverse();
  }, /raw module export proofs are not strictly sorted/u);
  reject((delta) => {
    delta.sites.reverse();
  }, /raw dependency sites are not strictly sorted/u);
  reject((delta) => {
    delta.calls[0]!.key = "noncanonical-call-key";
  }, /raw call site key is not canonical/u);
  reject((delta) => {
    delta.calls = [];
  }, /parser-confirmed call occurrence is missing from the raw ledger/u);

  // Earlier phases must still win when later ledgers are malformed too.
  reject((delta) => {
    delta.moduleExports[0]!.definitionKeys[0] = "missing-definition";
    delta.calls = [];
  }, /raw module export target is not a canonical definition/u);
  reject((delta) => {
    delta.sites[0]!.targetConditions = [];
    delta.calls = [];
  }, /raw dependency target conditions do not align with targets/u);
  reject((delta) => {
    delta.calls[0]!.targets = [];
    delta.calls[0]!.key = "noncanonical-call-key";
  }, /raw call site has no target or unaligned target conditions/u);
});
