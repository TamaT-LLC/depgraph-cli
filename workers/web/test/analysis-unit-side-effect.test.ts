import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { test, type TestContext } from "node:test";
import { parseAnalysisUnitRequest } from "../src/analysis-unit";
import type { ProgressReporter } from "../src/progress";
import { scan } from "../src/scanner";

async function fixture(context: TestContext, sources: ReadonlyMap<string, string>, owned: string[]) {
  const root = await mkdtemp(path.join(os.tmpdir(), "depgraph-side-effect-batch-"));
  context.after(async () => rm(root, { recursive: true, force: true }));
  await mkdir(path.join(root, "src"));
  await writeFile(path.join(root, "package.json"), JSON.stringify({ name: "side-effect-batch", version: "1.0.0", type: "module" }));
  const files = [path.join(root, "package.json")];
  for (const [relative, source] of sources) {
    const file = path.join(root, relative);
    await writeFile(file, source);
    files.push(file);
  }
  const request = parseAnalysisUnitRequest({
    contract_version: "depgraph-analysis-unit-v2", unit_id: "side-effect-batch", adapter: "web", unit_root: ".",
    source_paths: owned, context_paths: [...sources.keys()].sort(), auxiliary_paths: ["package.json"],
    stage: "semantic", chunk_id: "chunk-0", chunk_index: 0, chunk_count: 1,
    context_fingerprint: "a".repeat(64),
  });
  return { root, files, request };
}

test("a long side-effect import chain retains full compiler context without exhausting AST transfer", async (context) => {
  const count = 4_100;
  const names = Array.from({ length: count }, (_, index) => `src/f${String(index).padStart(5, "0")}.ts`);
  const sources = new Map(names.map((name, index) => [name,
    (index + 1 < count ? `import "./${path.basename(names[index + 1]!, ".ts")}.js";\n` : "")
      + `export const value${index} = ${index};\n`,
  ]));
  const { root, files, request } = await fixture(context, sources, names.slice(0, 128));
  let transferred = Number.POSITIVE_INFINITY;
  const progress: ProgressReporter = {
    start() {}, checkpoint() {},
    complete(phase, detail = {}) {
      if (phase === "typescript_ast_transfer") transferred = Number(detail.ast_retained_source_files);
    },
  };
  const model = await scan(root, files, [], progress, request);
  assert.ok(model.coverage.completeness.includes("semantic-complete"), JSON.stringify(model.coverage.reasons));
  assert.equal(model.files.filter((file) => file.path.endsWith(".ts")).length, 128);
  assert.equal(model.typeScriptProject.rootFiles, count);
  assert.ok(transferred < 512);
  assert.ok(!model.diagnostics.some((diagnostic) => diagnostic.code === "web.typescript_ast_selection_truncated"));
  assert.ok(model.sites.some((site) => site.kind === "side_effect_import" || site.kind === "web_import"));
});

test("a file witness is upgraded when a named reexport subsequently needs its declaration closure", async (context) => {
  const { root, files, request } = await fixture(context, new Map([
    ["src/entry.ts", 'import "./a"; import { answer } from "./b"; export const result = answer;\n'],
    ["src/a.ts", 'export { answer } from "./c";\n'],
    ["src/b.ts", 'export { answer } from "./a";\n'],
    ["src/c.ts", "export const answer = 42;\n"],
  ]), ["src/entry.ts"]);
  const model = await scan(root, files, [], undefined, request);
  assert.ok(model.coverage.completeness.includes("semantic-complete"), JSON.stringify(model.coverage.reasons));
  const answer = model.nodes.find((node) => node.kind === "symbol" && node.properties.source_path === "src/c.ts");
  assert.ok(answer);
  assert.ok(model.sites.some((site) => site.target_ids.includes(answer.id)));
});

test("global declarations and context errors survive side-effect-only AST witnesses", async (context) => {
  const { root, files, request } = await fixture(context, new Map([
    ["src/entry.ts", 'import "./a"; export const answer: number = globalAnswer();\n'],
    ["src/a.ts", 'import "./b"; export {};\n'],
    ["src/b.ts", 'import "./globals"; export {};\n'],
    ["src/globals.ts", "export {}; declare global { function globalAnswer(): number; }\n"],
  ]), ["src/entry.ts"]);
  const model = await scan(root, files, [], undefined, request);
  assert.ok(model.coverage.completeness.includes("semantic-complete"), JSON.stringify(model.coverage.reasons));
  const global = model.nodes.find((node) => node.kind === "symbol" && node.display_name === "globalAnswer");
  assert.ok(global);
  assert.ok(model.edges.some((edge) => edge.kind === "calls" && edge.target === global.id));
  await writeFile(path.join(root, "src/b.ts"), 'export const broken: number = "wrong";\n');
  const broken = await scan(root, files, [], undefined, request);
  assert.ok(!broken.coverage.completeness.includes("semantic-complete"));
  assert.ok(broken.coverage.reasons.includes("typescript_semantic_diagnostics_present"));
  await writeFile(path.join(root, "src/b.ts"), "export const broken = ;\n");
  const invalidSyntax = await scan(root, files, [], undefined, request);
  assert.ok(!invalidSyntax.coverage.completeness.includes("semantic-complete"));
  assert.ok(invalidSyntax.coverage.reasons.includes("typescript_definition_graph_incomplete"));
});
