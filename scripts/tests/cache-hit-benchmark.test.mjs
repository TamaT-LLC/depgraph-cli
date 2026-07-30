import assert from "node:assert/strict";
import test from "node:test";

import {
  CACHE_HIT_FIXTURE_SIZES,
  CACHE_HIT_REPORT_SCHEMA_VERSION,
  evaluateCacheHitComparison,
  verifyCacheHitReport,
} from "../cache-hit-benchmark.mjs";

const evidence = {
  files_analyzed: 100,
  dependency_sites: 99,
  project_code_executed: false,
  graph_sha256: "a".repeat(64),
};

test("cache hit comparison uses paired medians and a fixed improvement floor", () => {
  const comparison = evaluateCacheHitComparison({
    size: "small",
    sourceFileCount: 100,
    hitSamples: [80, 82, 400],
    bypassSamples: [100, 105, 110],
    minimumImprovementPercent: 5,
    evidence,
  });
  assert.equal(comparison.hit_median_ms, 82);
  assert.equal(comparison.bypass_median_ms, 105);
  assert.equal(comparison.required_hit_maximum_ms, 99);
  assert.equal(comparison.passed, true);

  const regression = evaluateCacheHitComparison({
    size: "small",
    sourceFileCount: 100,
    hitSamples: [100, 101, 102],
    bypassSamples: [100, 101, 102],
    minimumImprovementPercent: 5,
    evidence,
  });
  assert.equal(regression.passed, false);
});

test("cache hit release report requires every canonical fixture size to pass", () => {
  const comparisons = Object.entries(CACHE_HIT_FIXTURE_SIZES).map(
    ([size, sourceFileCount], index) =>
      evaluateCacheHitComparison({
        size,
        sourceFileCount,
        hitSamples: [80 + index, 82 + index, 84 + index],
        bypassSamples: [100 + index, 102 + index, 104 + index],
        minimumImprovementPercent: 5,
        evidence: {
          ...evidence,
          files_analyzed: sourceFileCount,
          dependency_sites: sourceFileCount - 1,
        },
      }),
  );
  const report = {
    schema_version: CACHE_HIT_REPORT_SCHEMA_VERSION,
    generated_at: "2026-07-30T00:00:00.000Z",
    commit: "e".repeat(40),
    minimum_improvement_percent: 5,
    comparisons,
    passed: true,
  };
  assert.equal(verifyCacheHitReport(report, report.commit), true);

  const forged = structuredClone(report);
  forged.comparisons[0].hit_median_ms += 1;
  assert.throws(
    () => verifyCacheHitReport(forged, report.commit),
    /canonical/,
  );

  for (const mutate of [
    (candidate) => {
      candidate.comparisons[0].evidence.files_analyzed = 0;
    },
    (candidate) => {
      candidate.comparisons[1].evidence.dependency_sites = 0;
    },
    (candidate) => {
      candidate.comparisons[2].evidence.graph_sha256 = "not-a-digest";
    },
  ]) {
    const invalidEvidence = structuredClone(report);
    mutate(invalidEvidence);
    assert.throws(
      () => verifyCacheHitReport(invalidEvidence, report.commit),
      /release contract/,
    );
  }
});
