import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { parseAnalysisUnitRequest } from "../src/analysis-unit";
import { scan } from "../src/scanner";

test("batch semantic issue counts describe emitted diagnostics while context failures stay incomplete", async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "depgraph-web-batch-issues-"));
  context.after(async () => rm(root, { recursive: true, force: true }));
  const contents = new Map([
    ["package.json", JSON.stringify({ name: "batch-issues", version: "1.0.0" })],
    ["tsconfig.json", JSON.stringify({ compilerOptions: { module: "preserve", moduleResolution: "bundler", target: "esnext" } })],
    ["src/entry.ts", 'import { broken } from "./broken"; export const result = broken;\n'],
    ["src/broken.ts", "export const broken = ;\n"],
  ]);
  const files = await Promise.all([...contents].map(async ([relative, source]) => {
    const file = path.join(root, relative);
    await mkdir(path.dirname(file), { recursive: true });
    await writeFile(file, source);
    return file;
  }));
  const common = {
    contract_version: "depgraph-analysis-unit-v2" as const,
    unit_id: "web:batch-issues",
    adapter: "web" as const,
    unit_root: ".",
    stage: "semantic" as const,
    context_paths: ["src/broken.ts", "src/entry.ts"],
    auxiliary_paths: [],
    context_fingerprint: "d".repeat(64),
    chunk_id: "chunk-0",
    chunk_index: 0,
    chunk_count: 1,
  };
  const whole = await scan(root, files, [], undefined, parseAnalysisUnitRequest({
    ...common, source_paths: common.context_paths,
  }));
  assert.ok(whole.diagnostics.some((diagnostic) => (
    diagnostic.path === "src/broken.ts" && diagnostic.properties?.typescript_definition_issue === true
  )), "the context source must exercise a semantic definition issue");

  const batch = await scan(root, files, [], undefined, parseAnalysisUnitRequest({
    ...common, source_paths: ["src/entry.ts"],
  }));
  const emittedIssues = batch.diagnostics.filter((diagnostic) => (
    diagnostic.properties?.typescript_definition_issue === true
      || diagnostic.properties?.typescript_dependency_issue === true
  ));
  assert.ok(emittedIssues.length < whole.typeScriptProject.semanticIssues);
  assert.equal(batch.typeScriptProject.semanticIssues, emittedIssues.length);
  assert.ok(!batch.coverage.completeness.includes("semantic-complete"));
  assert.ok(batch.coverage.reasons.includes("typescript_definition_graph_incomplete"));

  await writeFile(path.join(root, "src/broken.ts"), "export const broken: string = 42;\n");
  const contextTypeError = await scan(root, files, [], undefined, parseAnalysisUnitRequest({
    ...common, source_paths: ["src/entry.ts"],
  }));
  assert.equal(contextTypeError.typeScriptProject.semanticIssues, 0);
  assert.ok(contextTypeError.typeScriptProject.semanticDiagnostics > 0);
  assert.ok(!contextTypeError.coverage.completeness.includes("semantic-complete"));
  assert.ok(contextTypeError.coverage.reasons.includes("typescript_semantic_diagnostics_present"));
});
