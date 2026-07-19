import assert from "node:assert/strict";
import { test } from "node:test";
import { extractDependencies, parseStaticJsonc } from "../src/imports";
import { analyzeTypeScriptProject } from "../src/typescript-compiler";

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
