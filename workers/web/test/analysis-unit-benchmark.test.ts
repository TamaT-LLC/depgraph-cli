import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { performance } from "node:perf_hooks";
import { test } from "node:test";
import { parseAnalysisUnitRequest, validateAnalysisUnitForRoot } from "../src/analysis-unit";
import { scan } from "../src/scanner";
import type { ProgressDetail, ProgressReporter } from "../src/progress";

const BENCHMARK_ENABLED = process.env.DEPGRAPH_WEB_BENCHMARK === "1";
const BENCHMARK_FILE_COUNT = 1_024;
const BENCHMARK_BATCH_SIZE = 256;

type ProgressEvent = {
  status: "start" | "checkpoint" | "complete";
  phase: string;
  detail: ProgressDetail;
  at: number;
  rssBytes: number;
};

function recordingProgress(events: ProgressEvent[]): ProgressReporter {
  const record = (status: ProgressEvent["status"], phase: string, detail: ProgressDetail = {}): void => {
    events.push({ status, phase, detail, at: performance.now(), rssBytes: process.memoryUsage().rss });
  };
  return {
    start: (phase, detail) => record("start", phase, detail),
    checkpoint: (phase, detail) => record("checkpoint", phase, detail),
    complete: (phase, detail) => record("complete", phase, detail),
  };
}

function phaseDurations(events: readonly ProgressEvent[]): Record<string, number> {
  const starts = new Map<string, number>();
  const durations = new Map<string, number>();
  for (const event of events) {
    if (event.status === "start") starts.set(event.phase, event.at);
    if (event.status === "complete") {
      const startedAt = starts.get(event.phase);
      if (startedAt !== undefined) durations.set(event.phase, (durations.get(event.phase) ?? 0) + event.at - startedAt);
    }
  }
  return Object.fromEntries([...durations.entries()].sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0)
    .map(([phase, duration]) => [phase, Math.round(duration * 100) / 100]));
}

test("1024-file source-batch benchmark reports bounded transfer and rebuild metrics", { skip: !BENCHMARK_ENABLED }, async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "depgraph-web-analysis-unit-benchmark-"));
  context.after(async () => rm(root, { recursive: true, force: true }));
  const generatedPaths = Array.from({ length: BENCHMARK_FILE_COUNT - 1 }, (_, index) => (
    `src/generated/${String(index).padStart(4, "0")}.ts`
  ));
  const sharedPath = "src/shared.ts";
  const sourcePaths = [...generatedPaths, sharedPath].sort();
  const metadata = ["package.json", "tsconfig.json"];
  await writeFile(path.join(root, "package.json"), JSON.stringify({ name: "public-analysis-unit-benchmark", version: "1.0.0" }));
  await writeFile(path.join(root, "tsconfig.json"), JSON.stringify({
    compilerOptions: { module: "preserve", moduleResolution: "bundler", target: "esnext" },
  }));
  const files = await Promise.all([
    ...metadata.map((relative) => Promise.resolve(path.join(root, relative))),
    ...generatedPaths.map(async (relative, index) => {
      const file = path.join(root, relative);
      await mkdir(path.dirname(file), { recursive: true });
      await writeFile(file, [
        `import { shared } from "../shared";`,
        `import type { Shared } from "../shared";`,
        `export { shared as generatedShared${index} } from "../shared";`,
        `export type { Shared as GeneratedShared${index} } from "../shared";`,
        `export const generated${index}: Shared = shared();`,
        "",
      ].join("\n"));
      return file;
    }),
    (async () => {
      const file = path.join(root, sharedPath);
      await mkdir(path.dirname(file), { recursive: true });
      await writeFile(file, [
        "export type Shared = { value: number };",
        "export function shared(): Shared { return { value: 1 }; }",
        "",
      ].join("\n"));
      return file;
    })(),
  ]);
  const contextPaths = [...sourcePaths].sort();
  const allFiles = [...files].sort();
  const chunks = [];
  for (let offset = 0; offset < sourcePaths.length; offset += BENCHMARK_BATCH_SIZE) {
    const sourceBatch = sourcePaths.slice(offset, offset + BENCHMARK_BATCH_SIZE);
    chunks.push(parseAnalysisUnitRequest({
      contract_version: "depgraph-analysis-unit-v2",
      unit_id: "web:public-analysis-unit-benchmark",
      adapter: "web",
      unit_root: ".",
      source_paths: sourceBatch,
      stage: "semantic",
      context_paths: contextPaths,
      auxiliary_paths: metadata,
      context_fingerprint: "e".repeat(64),
      chunk_id: `benchmark-${chunks.length}`,
      chunk_index: chunks.length,
      chunk_count: Math.ceil(sourcePaths.length / BENCHMARK_BATCH_SIZE),
    }));
  }
  const inventoryStart = performance.now();
  await validateAnalysisUnitForRoot(root, allFiles, chunks[0]!);
  const inventoryDurationMs = performance.now() - inventoryStart;
  let peakRssBytes = process.memoryUsage().rss;
  let totalSourceBytes = 0;
  let maxTransferSourceFiles = 0;
  let maxTransferSourceBytes = 0;
  let maxContextTargetFiles = 0;
  let rebuildCount = 0;
  let ownedFileNodes = 0;
  let semanticSiteCount = 0;
  let semanticEdgeCount = 0;
  const chunkMetrics: Array<Record<string, number>> = [];
  const phaseTotals = new Map<string, number>();
  const phaseObservedRss = new Map<string, number>();
  for (const request of chunks) {
    const events: ProgressEvent[] = [];
    const beforeRss = process.memoryUsage().rss;
    const startedAt = performance.now();
    const model = await scan(root, allFiles, [], recordingProgress(events), request);
    const durationMs = performance.now() - startedAt;
    const afterRss = process.memoryUsage().rss;
    peakRssBytes = Math.max(peakRssBytes, beforeRss, afterRss);
    for (const event of events) {
      peakRssBytes = Math.max(peakRssBytes, event.rssBytes);
      phaseObservedRss.set(event.phase, Math.max(phaseObservedRss.get(event.phase) ?? 0, event.rssBytes));
    }
    const transfer = events.find((event) => event.status === "complete" && event.phase === "typescript_ast_transfer");
    const transferFiles = typeof transfer?.detail.ast_retained_source_files === "number"
      ? transfer.detail.ast_retained_source_files
      : typeof transfer?.detail.source_files === "number" ? transfer.detail.source_files : 0;
    const transferBytes = typeof transfer?.detail.ast_retained_source_bytes === "number"
      ? transfer.detail.ast_retained_source_bytes
      : typeof transfer?.detail.source_bytes === "number" ? transfer.detail.source_bytes : 0;
    const selection = events.find((event) => event.status === "complete" && event.phase === "typescript_ast_selection");
    const contextTargetFiles = typeof selection?.detail.context_target_files === "number"
      ? selection.detail.context_target_files
      : 0;
    maxTransferSourceFiles = Math.max(maxTransferSourceFiles, transferFiles);
    maxTransferSourceBytes = Math.max(maxTransferSourceBytes, transferBytes);
    maxContextTargetFiles = Math.max(maxContextTargetFiles, contextTargetFiles);
    totalSourceBytes += transferBytes;
    rebuildCount += events.filter((event) => event.status === "start" && event.phase === "typescript_context_rebuild").length;
    for (const [phase, phaseDuration] of Object.entries(phaseDurations(events))) {
      phaseTotals.set(phase, (phaseTotals.get(phase) ?? 0) + phaseDuration);
    }
    chunkMetrics.push({
      chunk_index: request.chunk_index,
      source_files: request.source_paths.length,
      rss_before_bytes: beforeRss,
      rss_after_bytes: afterRss,
      duration_ms: Math.round(durationMs * 100) / 100,
      ast_transfer_source_files: transferFiles,
      ast_transfer_source_bytes: transferBytes,
      ast_context_target_files: contextTargetFiles,
    });

    const nodeById = new Map(model.nodes.map((node) => [node.id, node]));
    const sourcePathOf = (id: string): string | undefined => {
      const node = nodeById.get(id);
      const sourcePath = node?.properties.source_path ?? node?.properties.path;
      return typeof sourcePath === "string" ? sourcePath : undefined;
    };
    const semantic = (value: { evidence: Array<{ kind?: string; properties?: Record<string, unknown> }> }): boolean => value.evidence.some((evidence) => (
      evidence.kind === "semantic"
        && evidence.properties?.analysis_mode === "semantic-import-type-call-graph"
    ));
    const semanticSites = model.sites.filter(semantic);
    const semanticEdges = model.edges.filter((edge) => edge.phase === "semantic" && edge.site_id !== null);
    semanticSiteCount += semanticSites.length;
    semanticEdgeCount += semanticEdges.length;
    ownedFileNodes += model.files.filter((file) => file.path.endsWith(".ts")).length;
    for (const relative of request.source_paths.filter((path) => path !== sharedPath)) {
      const ownedSites = semanticSites.filter((site) => sourcePathOf(site.source) === relative);
      const targetFromShared = (site: typeof semanticSites[number]): boolean => site.target_ids.some((target) => (
        sourcePathOf(target) === sharedPath
      ));
      const resolved = (site: typeof semanticSites[number]): boolean => (
        site.resolution_status === "resolved"
          && targetFromShared(site)
          && semanticEdges.some((edge) => edge.site_id === site.id && site.target_ids.includes(edge.target))
      );
      const imported = ownedSites.find((site) => site.kind === "web_import" && site.specifier === "../shared" && resolved(site));
      const typed = ownedSites.find((site) => site.kind === "type_use" && resolved(site));
      const reexported = ownedSites.find((site) => site.kind === "web_reexport" && site.specifier === "../shared" && resolved(site));
      assert.ok(imported, `${relative} has no resolved semantic import of ${sharedPath}`);
      assert.ok(typed, `${relative} has no resolved semantic type use of ${sharedPath}`);
      assert.ok(reexported, `${relative} has no resolved semantic re-export of ${sharedPath}`);
      for (const site of [imported, typed, reexported]) {
        assert.ok(model.edges.some((edge) => edge.site_id === site.id && site.target_ids.includes(edge.target)), `${relative} semantic site has no graph edge`);
      }
    }
  }
  assert.equal(rebuildCount, chunks.length);
  assert.equal(chunks.reduce((sum, request) => sum + request.source_paths.length, 0), BENCHMARK_FILE_COUNT);
  assert.equal(ownedFileNodes, BENCHMARK_FILE_COUNT);
  assert.equal(maxTransferSourceFiles, BENCHMARK_BATCH_SIZE + 1, "semantic import closure retained the whole project instead of one owned batch");
  assert.equal(maxContextTargetFiles, 1);
  assert.ok(maxTransferSourceBytes > 0);
  assert.equal(semanticSiteCount, generatedPaths.length * 6 + 1);
  assert.equal(semanticEdgeCount, semanticSiteCount);
  const metrics = {
    contract: "depgraph-analysis-unit-v2",
    files: BENCHMARK_FILE_COUNT,
    chunk_count: chunks.length,
    batch_size: BENCHMARK_BATCH_SIZE,
    context_source_files: contextPaths.length,
    context_rebuild_count: rebuildCount,
    inventory_duration_ms: Math.round(inventoryDurationMs * 100) / 100,
    peak_rss_bytes: peakRssBytes,
    peak_ast_retained_source_files: maxTransferSourceFiles,
    peak_ast_retained_source_bytes: maxTransferSourceBytes,
    peak_context_target_files: maxContextTargetFiles,
    semantic_sites: semanticSiteCount,
    semantic_edges: semanticEdgeCount,
    ast_transfer_input: {
      source_files_total: chunks.length * BENCHMARK_BATCH_SIZE,
      context_source_files_total: chunks.length * contextPaths.length,
      max_source_files_per_chunk: maxTransferSourceFiles,
      max_context_target_files_per_chunk: maxContextTargetFiles,
      source_bytes_total: totalSourceBytes,
      max_source_bytes_per_chunk: maxTransferSourceBytes,
    },
    phase_duration_ms: Object.fromEntries([...phaseTotals.entries()].sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0)),
    // These samples are taken at Node progress events. They neither sample
    // between events nor include the native compiler's child-process RSS.
    phase_rss_observed_max_bytes: Object.fromEntries([...phaseObservedRss.entries()].sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0)),
    chunks: chunkMetrics,
  };
  console.log(JSON.stringify(metrics));
});
