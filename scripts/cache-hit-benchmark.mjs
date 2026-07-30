#!/usr/bin/env node

import { createHash } from "node:crypto";
import {
  mkdirSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import { dirname, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

export const CACHE_HIT_REPORT_SCHEMA_VERSION =
  "depgraph-cache-hit-benchmark-v1";
export const CACHE_HIT_FIXTURE_SIZES = Object.freeze({
  small: 100,
  medium: 1_000,
  large: 10_000,
});

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function hasExactKeys(value, keys) {
  return (
    isRecord(value)
    && JSON.stringify(Object.keys(value).sort())
      === JSON.stringify([...keys].sort())
  );
}

function jsonFile(path) {
  return JSON.parse(readFileSync(path, "utf8"));
}

function samples(path) {
  const values = readFileSync(path, "utf8")
    .split(/\r?\n/u)
    .filter(Boolean)
    .map(Number);
  if (
    values.length < 3
    || values.length > 20
    || values.some((value) => !Number.isSafeInteger(value) || value < 0)
  ) {
    throw new Error(`cache benchmark samples are invalid: ${path}`);
  }
  return values;
}

function median(values) {
  const ordered = [...values].sort((left, right) => left - right);
  return ordered[Math.floor(ordered.length / 2)];
}

function digest(value) {
  return createHash("sha256")
    .update(JSON.stringify(value))
    .digest("hex");
}

function canonicalGraph(envelope) {
  const graph = envelope?.graph;
  if (!isRecord(graph)) {
    throw new Error("cache benchmark graph export is missing");
  }
  return Object.fromEntries(
    [
      "profiles",
      "nodes",
      "sites",
      "edges",
      "evidence",
      "diagnostics",
      "file_coverage",
      "coverage",
      "profile_matrix",
    ].map((key) => [key, graph[key]]),
  );
}

function validateScanEvidence(rawDir, size, sampleCount) {
  let coverage = null;
  for (let index = 0; index < sampleCount; index += 1) {
    const hit = jsonFile(join(rawDir, `cache-${size}-hit-${index}.json`));
    const bypass = jsonFile(
      join(rawDir, `cache-${size}-bypass-${index}.json`),
    );
    if (
      hit.status !== "completed"
      || bypass.status !== "completed"
      || hit.exit_code !== 0
      || bypass.exit_code !== 0
      || hit.coverage?.project_code_executed !== false
      || JSON.stringify(hit.coverage) !== JSON.stringify(bypass.coverage)
      || !hit.cache_events?.some(
        (event) =>
          event.layer === "semantic"
          && event.outcome === "hit"
          && event.reason === "validated",
      )
      || !bypass.cache_events?.some(
        (event) =>
          event.layer === "semantic"
          && event.outcome === "reject"
          && event.reason === "disabled-by-request",
      )
    ) {
      throw new Error(`cache benchmark scan evidence failed for ${size}`);
    }
    coverage ??= hit.coverage;
    if (JSON.stringify(coverage) !== JSON.stringify(hit.coverage)) {
      throw new Error(`cache benchmark coverage drifted for ${size}`);
    }
  }
  const hitGraph = canonicalGraph(
    jsonFile(join(rawDir, `cache-${size}-hit-graph.json`)),
  );
  const bypassGraph = canonicalGraph(
    jsonFile(join(rawDir, `cache-${size}-bypass-graph.json`)),
  );
  const hitGraphSha256 = digest(hitGraph);
  const bypassGraphSha256 = digest(bypassGraph);
  if (hitGraphSha256 !== bypassGraphSha256) {
    throw new Error(`cache benchmark graph drifted for ${size}`);
  }
  return {
    files_analyzed: coverage.files_analyzed,
    dependency_sites: coverage.dependency_sites,
    project_code_executed: coverage.project_code_executed,
    graph_sha256: hitGraphSha256,
  };
}

export function evaluateCacheHitComparison({
  size,
  sourceFileCount,
  hitSamples,
  bypassSamples,
  minimumImprovementPercent,
  evidence,
}) {
  if (
    CACHE_HIT_FIXTURE_SIZES[size] !== sourceFileCount
    || hitSamples.length !== bypassSamples.length
    || hitSamples.length < 3
    || hitSamples.length > 20
    || [...hitSamples, ...bypassSamples].some(
      (value) => !Number.isSafeInteger(value) || value < 0,
    )
    || !Number.isSafeInteger(minimumImprovementPercent)
    || minimumImprovementPercent < 1
    || minimumImprovementPercent > 20
  ) {
    throw new Error("cache hit comparison contract is invalid");
  }
  const hitMedianMs = median(hitSamples);
  const bypassMedianMs = median(bypassSamples);
  const requiredMaximumMs = Math.floor(
    (bypassMedianMs * (100 - minimumImprovementPercent)) / 100,
  );
  return {
    size,
    source_file_count: sourceFileCount,
    minimum_improvement_percent: minimumImprovementPercent,
    hit_samples_ms: hitSamples,
    bypass_samples_ms: bypassSamples,
    hit_median_ms: hitMedianMs,
    bypass_median_ms: bypassMedianMs,
    required_hit_maximum_ms: requiredMaximumMs,
    improvement_percent:
      bypassMedianMs === 0
        ? 0
        : Number(
          (((bypassMedianMs - hitMedianMs) * 100) / bypassMedianMs).toFixed(2),
        ),
    evidence,
    passed: hitMedianMs <= requiredMaximumMs,
  };
}

export function createCacheHitReport({ rawDir, output }) {
  rawDir = resolve(rawDir);
  output = resolve(output);
  const minimumImprovementPercent = Number(
    process.env.DEPGRAPH_CACHE_HIT_MIN_IMPROVEMENT_PERCENT ?? "5",
  );
  const comparisons = Object.entries(CACHE_HIT_FIXTURE_SIZES).map(
    ([size, sourceFileCount]) => {
      const hitSamples = samples(join(rawDir, `cache-${size}-hit-ms.txt`));
      const bypassSamples = samples(
        join(rawDir, `cache-${size}-bypass-ms.txt`),
      );
      return evaluateCacheHitComparison({
        size,
        sourceFileCount,
        hitSamples,
        bypassSamples,
        minimumImprovementPercent,
        evidence: validateScanEvidence(rawDir, size, hitSamples.length),
      });
    },
  );
  const report = {
    schema_version: CACHE_HIT_REPORT_SCHEMA_VERSION,
    generated_at: new Date().toISOString(),
    commit:
      process.env.GITHUB_SHA
      ?? process.env.DEPGRAPH_CACHE_HIT_COMMIT
      ?? "local",
    minimum_improvement_percent: minimumImprovementPercent,
    comparisons,
    passed: comparisons.every((comparison) => comparison.passed),
  };
  verifyCacheHitReport(report, process.env.GITHUB_SHA);
  mkdirSync(dirname(output), { recursive: true });
  writeFileSync(output, `${JSON.stringify(report, null, 2)}\n`);
  return report;
}

export function verifyCacheHitReport(report, expectedCommit) {
  if (
    !hasExactKeys(report, [
      "schema_version",
      "generated_at",
      "commit",
      "minimum_improvement_percent",
      "comparisons",
      "passed",
    ])
    || report.schema_version !== CACHE_HIT_REPORT_SCHEMA_VERSION
    || !Number.isFinite(Date.parse(report.generated_at))
    || typeof report.commit !== "string"
    || report.commit.length === 0
    || (expectedCommit && report.commit !== expectedCommit)
    || !Number.isSafeInteger(report.minimum_improvement_percent)
    || report.minimum_improvement_percent < 1
    || report.minimum_improvement_percent > 20
    || !Array.isArray(report.comparisons)
    || report.comparisons.length !== 3
  ) {
    throw new Error("cache hit report does not satisfy its release contract");
  }
  const bySize = new Map(
    report.comparisons.map((comparison) => [comparison?.size, comparison]),
  );
  for (const [size, sourceFileCount] of Object.entries(
    CACHE_HIT_FIXTURE_SIZES,
  )) {
    const comparison = bySize.get(size);
    if (
      !hasExactKeys(comparison, [
        "size",
        "source_file_count",
        "minimum_improvement_percent",
        "hit_samples_ms",
        "bypass_samples_ms",
        "hit_median_ms",
        "bypass_median_ms",
        "required_hit_maximum_ms",
        "improvement_percent",
        "evidence",
        "passed",
      ])
      || !hasExactKeys(comparison.evidence, [
        "files_analyzed",
        "dependency_sites",
        "project_code_executed",
        "graph_sha256",
      ])
      || comparison.evidence.project_code_executed !== false
      || !Number.isSafeInteger(comparison.evidence.files_analyzed)
      || comparison.evidence.files_analyzed < sourceFileCount
      || !Number.isSafeInteger(comparison.evidence.dependency_sites)
      || comparison.evidence.dependency_sites < sourceFileCount - 1
      || !/^[0-9a-f]{64}$/u.test(comparison.evidence.graph_sha256)
      || !Number.isFinite(comparison.improvement_percent)
    ) {
      throw new Error("cache hit report does not satisfy its release contract");
    }
    const recomputed = evaluateCacheHitComparison({
      size,
      sourceFileCount,
      hitSamples: comparison.hit_samples_ms,
      bypassSamples: comparison.bypass_samples_ms,
      minimumImprovementPercent: report.minimum_improvement_percent,
      evidence: comparison.evidence,
    });
    if (JSON.stringify(comparison) !== JSON.stringify(recomputed)) {
      throw new Error("cache hit report comparison was not canonical");
    }
  }
  if (
    report.passed !== report.comparisons.every((comparison) => comparison.passed)
    || !report.passed
  ) {
    throw new Error("cache hit report performance gate failed");
  }
  return true;
}

function main(argv) {
  const [command, ...rest] = argv;
  if (command === "create" && rest.length === 2) {
    const report = createCacheHitReport({
      rawDir: rest[0],
      output: rest[1],
    });
    for (const comparison of report.comparisons) {
      process.stdout.write(
        `PASS cache ${comparison.size}: hit ${comparison.hit_median_ms} ms, `
        + `bypass ${comparison.bypass_median_ms} ms, `
        + `improvement ${comparison.improvement_percent}%\n`,
      );
    }
    if (!report.passed) process.exitCode = 1;
    return;
  }
  if (command === "verify" && rest.length === 1) {
    verifyCacheHitReport(jsonFile(rest[0]), process.env.GITHUB_SHA);
    process.stdout.write(`verified cache hit benchmark report: ${rest[0]}\n`);
    return;
  }
  throw new Error(
    "usage: cache-hit-benchmark.mjs create <raw-dir> <output> | verify <report>",
  );
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  main(process.argv.slice(2));
}
