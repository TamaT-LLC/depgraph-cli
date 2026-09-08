import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import {
  analysisUnitLogicalProfileId,
  analysisUnitProfileId,
  parseAnalysisUnitRequest,
  validateAnalysisUnitForRoot,
} from "../src/analysis-unit";
import { scan } from "../src/scanner";
import { walkFiles } from "../src/fs";
import type { ProgressReporter } from "../src/progress";
import { BASE_PROFILE_ID } from "../src/types";

function stableJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  if (value !== null && typeof value === "object") {
    return `{${Object.entries(value as Record<string, unknown>)
      .filter(([key]) => !["id", "profile_id", "site_id", "file_id"].includes(key))
      .sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0)
      .map(([key, nested]) => `${JSON.stringify(key)}:${stableJson(nested)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function canonicalGraph(model: Awaited<ReturnType<typeof scan>>): Record<string, string[]> {
  const nodeKeys = new Map(model.nodes.map((node) => [
    node.id,
    stableJson({ kind: node.kind, locator: node.locator, display_name: node.display_name, properties: node.properties }),
  ]));
  const siteKeys = new Map(model.sites.map((site) => [
    site.id,
    stableJson({
      ...site,
      source: nodeKeys.get(site.source) ?? `missing:${site.source}`,
      target_ids: site.target_ids.map((id) => nodeKeys.get(id) ?? `missing:${id}`),
    }),
  ]));
  return {
    nodes: [...nodeKeys.values()].sort(),
    sites: [...siteKeys.values()].sort(),
    edges: model.edges.map((edge) => stableJson({
      ...edge,
      source: nodeKeys.get(edge.source) ?? `missing:${edge.source}`,
      target: nodeKeys.get(edge.target) ?? `missing:${edge.target}`,
      site_id: edge.site_id === null ? null : siteKeys.get(edge.site_id) ?? `missing:${edge.site_id}`,
    })).sort(),
    files: model.files.map((file) => stableJson(file)).sort(),
  };
}

function progressRecorder(): { reporter: ProgressReporter; events: Array<{ status: string; phase: string; detail: Record<string, string | number | boolean> }> } {
  const events: Array<{ status: string; phase: string; detail: Record<string, string | number | boolean> }> = [];
  const record = (status: string, phase: string, detail: Readonly<Record<string, string | number | boolean>> = {}): void => {
    events.push({ status, phase, detail: { ...detail } });
  };
  return {
    events,
    reporter: {
      start: (phase, detail) => record("start", phase, detail),
      checkpoint: (phase, detail) => record("checkpoint", phase, detail),
      complete: (phase, detail) => record("complete", phase, detail),
    },
  };
}

test("root workspace manifests stay bounded ancestors of nested analysis units", () => {
  const request = {
    contract_version: "depgraph-analysis-unit-v2",
    unit_id: "web:nested", adapter: "web", unit_root: "apps/web",
    source_paths: ["apps/web/index.ts"], context_paths: ["apps/web/index.ts"],
    auxiliary_paths: ["package.json", "pnpm-workspace.yaml"],
    stage: "syntax", chunk_id: "chunk-0", chunk_index: 0, chunk_count: 1,
    context_fingerprint: "a".repeat(64),
  };
  assert.deepEqual(parseAnalysisUnitRequest(request).auxiliary_paths, request.auxiliary_paths);
  for (const auxiliary of ["apps/other/package.json", "tsconfig.json", "../package.json"]) {
    assert.throws(() => parseAnalysisUnitRequest({ ...request, auxiliary_paths: [auxiliary] }));
  }
});

test("assigned TanStack configuration retains virtual routes without native dependency ownership", async () => {
  const root = fileURLToPath(new URL("./fixtures/polyglot", import.meta.url));
  const source = "apps/router/src/routes/__root.tsx";
  const config = "apps/router/vite.config.ts";
  const request = parseAnalysisUnitRequest({
    contract_version: "depgraph-analysis-unit-v2", unit_id: "web:router", adapter: "web",
    unit_root: "apps/router", source_paths: [source], context_paths: [source],
    auxiliary_paths: ["apps/router/package.json", config, "package.json"],
    stage: "semantic", chunk_id: "chunk-0", chunk_index: 0, chunk_count: 2,
    context_fingerprint: "c".repeat(64),
  });
  const files = await walkFiles(root);
  const model = await scan(root, files, [], undefined, request);
  const virtual = model.nodes.find((node) => node.kind === "route" && node.properties.route_kind === "tanstack-virtual-route");
  assert.ok(virtual);
  const registration = model.sites.find((site) => site.target_ids.includes(virtual.id) && site.kind === "route_entry");
  assert.ok(registration?.evidence.some((item) => item.path === config));
  assert.equal(model.sites.some((site) => site.evidence.some((item) => item.path === config
    && item.extractor === "typescript-native-typechecker")), false);
  const sibling = await scan(root, files, [], undefined, parseAnalysisUnitRequest({
    ...request, chunk_id: "chunk-1", chunk_index: 1, auxiliary_paths: [],
  }));
  assert.equal(sibling.nodes.some((node) => node.properties.route_kind === "tanstack-virtual-route"), false);
});

test("an isolated Astro endpoint obtains its own export proof without another import site", async () => {
  const root = fileURLToPath(new URL("./fixtures/polyglot", import.meta.url));
  const source = "apps/astro-app/src/pages/api/status.ts";
  const request = parseAnalysisUnitRequest({
    contract_version: "depgraph-analysis-unit-v2", unit_id: "web:astro", adapter: "web",
    unit_root: "apps/astro-app", source_paths: [source], context_paths: [source],
    auxiliary_paths: ["apps/astro-app/package.json", "package.json"],
    stage: "semantic", chunk_id: "chunk-0", chunk_index: 0, chunk_count: 1,
    context_fingerprint: "c".repeat(64),
  });
  const model = await scan(root, await walkFiles(root), [], undefined, request);
  const handler = model.sites.find((site) => site.kind === "handled_by");
  assert.equal(handler?.specifier, "GET");
  assert.equal(handler?.resolution_status, "resolved");
  assert.equal(handler?.precision, "exact");
  assert.ok(model.nodes.some((node) => node.kind === "symbol" && node.display_name === "GET"
    && handler?.target_ids.includes(node.id)));
});

test("framework analysis profiles declare exactly their projected completeness ledger", async () => {
  const root = fileURLToPath(new URL("./fixtures/polyglot", import.meta.url));
  const files = await walkFiles(root);
  for (const stage of ["syntax", "semantic"] as const) {
    const request = parseAnalysisUnitRequest({
      contract_version: "depgraph-analysis-unit-v2",
      unit_id: "web:next", adapter: "web", unit_root: "apps/next-app",
      source_paths: ["apps/next-app/src/pages/about.tsx"],
      context_paths: ["apps/next-app/src/pages/about.tsx"],
      auxiliary_paths: ["apps/next-app/package.json", "package.json"],
      stage, chunk_id: "chunk-0", chunk_index: 0, chunk_count: 1,
      context_fingerprint: "b".repeat(64),
    });
    const model = await scan(root, files, [], undefined, request);
    assert.deepEqual(model.detectedFrameworks, model.frameworkSemantic.completionLedger.map((entry) => entry.framework));
    assert.deepEqual(model.detectedFrameworks, stage === "syntax" ? [] : ["next"]);
    const primaryTypeChecker = (record: { evidence: readonly { kind: string; extractor: string }[] }): boolean => (
      record.evidence[0]?.kind === "semantic" && record.evidence[0]?.extractor === "typescript-native-typechecker"
    );
    assert.equal(model.typeScriptProject.semanticRelations, model.edges.filter(primaryTypeChecker).length);
    assert.equal(model.typeScriptProject.semanticSites, model.sites.filter(primaryTypeChecker).length);
    if (model.frameworkSemantic.completionStatus === "incomplete") {
      assert.ok(model.coverage.reasons.includes("framework_semantic_incomplete"));
      assert.ok(!model.coverage.completeness.includes("semantic-complete"));
    }
  }
});

test("analysis-unit profiles differ by chunk while logical stage identity stays stable", () => {
  const common = {
    contract_version: "depgraph-analysis-unit-v2" as const,
    unit_id: "web:project",
    adapter: "web" as const,
    unit_root: ".",
    source_paths: ["src/entry.ts"],
    stage: "semantic" as const,
    context_paths: ["src/entry.ts", "src/shared.ts"],
    auxiliary_paths: [],
    context_fingerprint: "a".repeat(64),
  };
  const first = parseAnalysisUnitRequest({ ...common, chunk_id: "chunk-a", chunk_index: 0, chunk_count: 2 });
  const second = parseAnalysisUnitRequest({ ...common, chunk_id: "chunk-b", chunk_index: 1, chunk_count: 2 });
  assert.notEqual(analysisUnitProfileId(first, BASE_PROFILE_ID), analysisUnitProfileId(second, BASE_PROFILE_ID));
  assert.equal(
    analysisUnitLogicalProfileId(first, BASE_PROFILE_ID),
    analysisUnitLogicalProfileId(second, BASE_PROFILE_ID),
  );
});

test("analysis-unit path lists use protocol UTF-8 ordering", () => {
  const paths = ["src/\uE000.ts", "src/\u{10000}.ts"];
  assert.doesNotThrow(() => parseAnalysisUnitRequest({
    contract_version: "depgraph-analysis-unit-v2",
    unit_id: "web:utf8-paths",
    adapter: "web",
    unit_root: ".",
    source_paths: paths,
    stage: "syntax",
    context_paths: paths,
    auxiliary_paths: [],
    context_fingerprint: "f".repeat(64),
    chunk_id: "chunk-0",
    chunk_index: 0,
    chunk_count: 1,
  }));
});

test("semantic source batches keep context targets while bounding dependency traversal", async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "depgraph-web-analysis-unit-"));
  context.after(async () => rm(root, { recursive: true, force: true }));
  const relativePaths = [
    "package.json",
    "tsconfig.json",
    "src/entry.ts",
    "src/shared.ts",
    "src/other.ts",
  ];
  const contents = [
    JSON.stringify({ name: "analysis-unit-fixture", version: "1.0.0" }),
    JSON.stringify({ compilerOptions: { module: "preserve", moduleResolution: "bundler", target: "esnext" } }),
    'import { shared } from "./shared";\nexport const result = shared();\n',
    'export function shared(): string { return "shared"; }\n',
    'export function other(): string { return "other"; }\n',
  ];
  const files = await Promise.all(relativePaths.map(async (relative, index) => {
    const file = path.join(root, relative);
    await mkdir(path.dirname(file), { recursive: true });
    await writeFile(file, contents[index]!);
    return file;
  }));
  const request = parseAnalysisUnitRequest({
    contract_version: "depgraph-analysis-unit-v2",
    unit_id: "web:analysis-unit-fixture",
    adapter: "web",
    unit_root: ".",
    source_paths: ["src/entry.ts"],
    stage: "semantic",
    context_paths: ["src/entry.ts", "src/other.ts", "src/shared.ts"],
    auxiliary_paths: ["package.json", "tsconfig.json"],
    context_fingerprint: "b".repeat(64),
    chunk_id: "chunk-0",
    chunk_index: 0,
    chunk_count: 1,
  });
  await validateAnalysisUnitForRoot(root, files, request);
  const recorded = progressRecorder();
  const model = await scan(root, files, [], recorded.reporter, request);

  assert.deepEqual(model.files.map((file) => file.path), ["package.json", "src/entry.ts", "tsconfig.json"]);
  assert.ok(model.nodes.some((node) => node.kind === "symbol" && node.properties.source_path === "src/shared.ts"));
  const sharedFile = model.nodes.find((node) => node.kind === "file" && node.properties.path === "src/shared.ts");
  assert.ok(sharedFile, "a context-only declaration file is retained as a semantic target witness");
  assert.ok(!model.files.some((file) => file.path === "src/shared.ts"));
  assert.ok(!model.edges.some((edge) => edge.kind === "contains" && edge.target === sharedFile?.id));
  assert.ok(model.edges.some((edge) => edge.kind === "declares" && edge.source === sharedFile?.id));
  assert.match(String(sharedFile?.properties.content_hash), /^sha256:[0-9a-f]{64}$/u);
  assert.match(String(sharedFile?.properties.analysis_hash), /^sha256:[0-9a-f]{64}$/u);
  assert.ok(!model.nodes.some((node) => node.kind === "file" && node.properties.path === "src/other.ts"));
  assert.ok(model.sites.length > 0);
  assert.ok(model.sites.every((site) => site.evidence.every((evidence) => (
    evidence.path === "src/entry.ts" || evidence.path === "package.json" || evidence.path === "tsconfig.json"
  ))));
  assert.ok(model.coverage.completeness.includes("semantic-complete"));
  const astTransfer = recorded.events.find((event) => event.phase === "typescript_ast_transfer" && event.status === "complete");
  assert.equal(astTransfer?.detail.context_source_files, 3);
  assert.equal(astTransfer?.detail.source_files, 2);
  assert.equal(astTransfer?.detail.ast_retained_source_files, 2);
  assert.ok(Number(astTransfer?.detail.ast_retained_source_bytes) > 0);
  const dependencyProgress = recorded.events.filter((event) => event.phase === "typescript_dependency_graph" && event.status === "start");
  assert.deepEqual(dependencyProgress.at(-1)?.detail, { context_source_files: 3, source_files: 1 });

  const syntaxRequest = parseAnalysisUnitRequest({ ...request, stage: "syntax", chunk_count: 2 });
  const inventoryIssues = [{ path: "package.json", reason: "unreadable_path" as const, detail: "synthetic diagnostic" }];
  const importingBatch = await scan(root, files, inventoryIssues, undefined, syntaxRequest);
  const owningBatch = await scan(root, files, inventoryIssues, undefined, parseAnalysisUnitRequest({
    ...syntaxRequest, source_paths: ["src/shared.ts"], chunk_id: "chunk-1", chunk_index: 1,
  }));
  const importedFile = importingBatch.nodes.find((node) => node.kind === "file" && node.properties.path === "src/shared.ts");
  const ownedFile = owningBatch.nodes.find((node) => node.kind === "file" && node.properties.path === "src/shared.ts");
  assert.ok(importedFile && ownedFile);
  assert.equal(importedFile.id, ownedFile.id);
  assert.equal(importedFile.id, sharedFile.id, "syntax and semantic stages share the same file identity");
  assert.equal(stableJson(importedFile), stableJson(ownedFile), "syntax context file and owner must have identical hash witnesses");
  const otherProject = await scan(root, files, [], undefined, parseAnalysisUnitRequest({
    ...request, unit_id: "web:another-project", source_paths: ["src/shared.ts"],
  }));
  const otherFile = otherProject.nodes.find((node) => node.kind === "file" && node.properties.path === "src/shared.ts");
  assert.ok(otherFile);
  assert.equal(otherFile.id, sharedFile.id, "a referenced file keeps its identity in its owning project");
  assert.equal(stableJson(otherFile), stableJson(sharedFile));
  assert.ok(!importingBatch.files.some((file) => file.path === "src/shared.ts"));
  const importingDiagnostic = importingBatch.diagnostics.find((diagnostic) => diagnostic.code === "web.source_inventory_skipped");
  const owningDiagnostic = owningBatch.diagnostics.find((diagnostic) => diagnostic.code === "web.source_inventory_skipped");
  assert.ok(importingDiagnostic && owningDiagnostic);
  assert.equal(importingDiagnostic.id, owningDiagnostic.id, "one logical diagnostic must not be duplicated per chunk");
});

test("semantic source batches retain ambient declarations in the full compiler context", async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "depgraph-web-analysis-unit-ambient-"));
  context.after(async () => rm(root, { recursive: true, force: true }));
  const relativePaths = [
    "app/package.json",
    "app/src/index.ts",
    "packages/types/global.d.ts",
  ];
  const contents = [
    JSON.stringify({ name: "@fixture/app", version: "1.0.0" }),
    "export const answer: number = globalAnswer();\n",
    "declare function globalAnswer(): number;\n",
  ];
  const files = await Promise.all(relativePaths.map(async (relative, index) => {
    const file = path.join(root, relative);
    await mkdir(path.dirname(file), { recursive: true });
    await writeFile(file, contents[index]!);
    return file;
  }));
  const common = {
    contract_version: "depgraph-analysis-unit-v2" as const,
    unit_id: "web:ambient-context",
    adapter: "web" as const,
    unit_root: "app",
    source_paths: ["app/src/index.ts"],
    stage: "semantic" as const,
    auxiliary_paths: [],
    context_fingerprint: "e".repeat(64),
    chunk_id: "chunk-0",
    chunk_index: 0,
    chunk_count: 1,
  };
  const withoutAmbient = parseAnalysisUnitRequest({
    ...common,
    context_paths: ["app/src/index.ts"],
  });
  const withAmbient = parseAnalysisUnitRequest({
    ...common,
    context_paths: ["app/src/index.ts", "packages/types/global.d.ts"],
  });
  await validateAnalysisUnitForRoot(root, files, withoutAmbient);
  await validateAnalysisUnitForRoot(root, files, withAmbient);

  const incomplete = await scan(root, files, [], undefined, withoutAmbient);
  assert.ok(incomplete.diagnostics.some((diagnostic) => (
    diagnostic.code === "web.typescript_semantic_scaffold_diagnostic"
      && diagnostic.message.includes("Cannot find name 'globalAnswer'")
  )));

  const recorded = progressRecorder();
  const completeContext = await scan(root, files, [], recorded.reporter, withAmbient);
  assert.equal(completeContext.typeScriptProject.semanticDiagnostics, 0);
  assert.ok(!completeContext.diagnostics.some((diagnostic) => (
    diagnostic.code === "web.typescript_semantic_scaffold_diagnostic"
      && diagnostic.message.includes("globalAnswer")
  )));
  const ambientDeclaration = completeContext.nodes.find((node) => (
    node.kind === "symbol"
      && node.display_name === "globalAnswer"
      && node.properties.source_path === "packages/types/global.d.ts"
  ));
  assert.ok(ambientDeclaration, "context-only ambient declaration was omitted from the semantic graph");
  assert.ok(completeContext.edges.some((edge) => (
    edge.kind === "calls"
      && edge.target === ambientDeclaration.id
      && edge.resolution_status === "resolved"
      && edge.evidence.some((evidence) => evidence.path === "app/src/index.ts")
  )), "ambient call did not resolve to its repository declaration");
  const astTransfer = recorded.events.find((event) => (
    event.phase === "typescript_ast_transfer" && event.status === "complete"
  ));
  assert.equal(astTransfer?.detail.context_source_files, 2);
  assert.equal(astTransfer?.detail.requested_source_files, 2);
  assert.equal(astTransfer?.detail.ast_retained_source_files, 2);
});

test("source batch size and order preserve one canonical graph", async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "depgraph-web-analysis-unit-batches-"));
  context.after(async () => rm(root, { recursive: true, force: true }));
  const relativePaths = ["package.json", "tsconfig.json", "src/a.ts", "src/b.ts", "src/shared.ts"];
  const contents = [
    JSON.stringify({ name: "analysis-unit-batches", version: "1.0.0" }),
    JSON.stringify({ compilerOptions: { module: "preserve", moduleResolution: "bundler", target: "esnext" } }),
    'import { shared } from "./shared"; export const a = shared("a");\n',
    'import { shared } from "./shared"; export const b = shared("b");\n',
    'export function shared(value: string): string { return value; }\n',
  ];
  const files = await Promise.all(relativePaths.map(async (relative, index) => {
    const file = path.join(root, relative);
    await mkdir(path.dirname(file), { recursive: true });
    await writeFile(file, contents[index]!);
    return file;
  }));
  const common = {
    contract_version: "depgraph-analysis-unit-v2" as const,
    unit_id: "web:analysis-unit-batches",
    adapter: "web" as const,
    unit_root: ".",
    stage: "semantic" as const,
    context_paths: ["src/a.ts", "src/b.ts", "src/shared.ts"],
    auxiliary_paths: [] as string[],
    context_fingerprint: "c".repeat(64),
  };
  const whole = parseAnalysisUnitRequest({
    ...common,
    source_paths: ["src/a.ts", "src/b.ts"],
    chunk_id: "whole",
    chunk_index: 0,
    chunk_count: 1,
  });
  const first = parseAnalysisUnitRequest({
    ...common,
    source_paths: ["src/a.ts"],
    chunk_id: "first",
    chunk_index: 0,
    chunk_count: 2,
  });
  const second = parseAnalysisUnitRequest({
    ...common,
    source_paths: ["src/b.ts"],
    chunk_id: "second",
    chunk_index: 1,
    chunk_count: 2,
  });
  await validateAnalysisUnitForRoot(root, files, whole);
  const wholeModel = await scan(root, files, [], undefined, whole);
  const firstModel = await scan(root, files, [], undefined, first);
  const secondModel = await scan(root, files, [], undefined, second);
  const merged = {
    ...wholeModel,
    nodes: [...firstModel.nodes, ...secondModel.nodes],
    sites: [...firstModel.sites, ...secondModel.sites],
    edges: [...new Map([...firstModel.edges, ...secondModel.edges].map((edge) => [edge.id, edge])).values()],
    files: [...firstModel.files, ...secondModel.files],
  };
  assert.deepEqual(canonicalGraph(merged), canonicalGraph(wholeModel));
  assert.notDeepEqual(firstModel.sites.map((site) => site.profile_id), secondModel.sites.map((site) => site.profile_id));
});

test("semantic source batches retain transitive workspace dependency context", async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "depgraph-web-analysis-unit-context-"));
  context.after(async () => rm(root, { recursive: true, force: true }));
  const relativePaths = [
    "frontend/package.json",
    "frontend/pnpm-workspace.yaml",
    "frontend/apps/web/package.json",
    "frontend/apps/web/tsconfig.json",
    "frontend/apps/web/src/index.ts",
    "frontend/packages/shared/package.json",
    "frontend/packages/shared/src/index.ts",
  ];
  const contents = [
    JSON.stringify({ name: "frontend", private: true }),
    "packages:\n  - apps/*\n  - packages/*\n",
    JSON.stringify({
      name: "@fixture/web",
      version: "1.0.0",
      dependencies: { "@fixture/shared": "workspace:*" },
    }),
    JSON.stringify({
      compilerOptions: {
        module: "preserve",
        moduleResolution: "bundler",
        target: "esnext",
        paths: { "@fixture/shared": ["../../packages/shared/src/index.ts"] },
      },
    }),
    'import { shared } from "@fixture/shared"; export const result = shared();\n',
    JSON.stringify({
      name: "@fixture/shared",
      version: "1.0.0",
      exports: { types: "./src/index.ts", default: "./src/index.ts" },
    }),
    'export function shared(): string { return "shared"; }\n',
  ];
  const files = await Promise.all(relativePaths.map(async (relative, index) => {
    const file = path.join(root, relative);
    await mkdir(path.dirname(file), { recursive: true });
    await writeFile(file, contents[index]!);
    return file;
  }));
  const request = parseAnalysisUnitRequest({
    contract_version: "depgraph-analysis-unit-v2",
    unit_id: "web:frontend-app",
    adapter: "web",
    unit_root: "frontend/apps/web",
    source_paths: ["frontend/apps/web/src/index.ts"],
    stage: "semantic",
    context_paths: ["frontend/apps/web/src/index.ts"],
    auxiliary_paths: [
      "frontend/apps/web/package.json",
      "frontend/apps/web/tsconfig.json",
      "frontend/package.json",
      "frontend/pnpm-workspace.yaml",
    ],
    context_fingerprint: "d".repeat(64),
    chunk_id: "chunk-0",
    chunk_index: 0,
    chunk_count: 1,
  });
  await validateAnalysisUnitForRoot(root, files, request);
  const recorded = progressRecorder();
  const model = await scan(root, files, [], recorded.reporter, request);

  assert.ok(model.files.some((file) => file.path === "frontend/package.json"));
  assert.ok(model.files.some((file) => file.path === "frontend/pnpm-workspace.yaml"));
  assert.ok(model.nodes.some((node) => (
    (node.kind === "symbol" || node.kind === "type")
      && node.properties.source_path === "frontend/packages/shared/src/index.ts"
  )));
  const sharedSymbol = model.nodes.find((node) => (
    (node.kind === "symbol" || node.kind === "type")
      && node.properties.source_path === "frontend/packages/shared/src/index.ts"
  ));
  assert.ok(sharedSymbol?.properties.package_id);
  assert.ok(model.nodes.some((node) => (
    node.kind === "package_instance"
      && node.id === sharedSymbol?.properties.package_id
      && node.properties.locator === "npm:workspace:@fixture/shared@1.0.0#frontend/packages/shared"
  )));
  assert.ok(model.sites.some((site) => site.specifier === "@fixture/shared"));
  assert.equal(
    model.typeScriptProject.semanticRelations,
    model.edges.filter((edge) => edge.phase === "semantic").length,
  );
  assert.ok(model.coverage.completeness.includes("semantic-complete"));
  const transfer = recorded.events.find((event) => (
    event.phase === "typescript_ast_transfer" && event.status === "complete"
  ));
  assert.equal(transfer?.detail.context_source_files, 2);
  assert.equal(transfer?.detail.source_files, 2);
  assert.equal(transfer?.detail.ast_retained_source_files, 2);
});
