import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  CACHE_HIT_FIXTURE_SIZES,
  CACHE_HIT_REPORT_SCHEMA_VERSION,
  createCacheHitReport,
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

/** Write valid paired scan evidence that tests can selectively corrupt. */
function rawReportFixture(t, unitReplay = true) {
  const rawDir = mkdtempSync(join(tmpdir(), "depgraph-cache-report-"));
  t.after(() => rmSync(rawDir, { recursive: true, force: true }));
  const write = (name, value) => writeFileSync(join(rawDir, name), JSON.stringify(value));
  for (const [size, files] of Object.entries(CACHE_HIT_FIXTURE_SIZES)) {
    const coverage = {
      files_analyzed: files + 1,
      dependency_sites: (files - 1) * 2,
      project_code_executed: false,
    };
    for (const mode of ["hit", "bypass"]) {
      writeFileSync(join(rawDir, `cache-${size}-${mode}-ms.txt`),
        mode === "hit" ? "80\n81\n82\n" : "100\n101\n102\n");
      const scan = {
        status: "completed",
        exit_code: 0,
        coverage,
        cache_events: [{
          layer: "semantic",
          outcome: mode === "hit" && !unitReplay ? "hit" : "reject",
          reason: mode === "bypass" ? "disabled-by-request"
            : unitReplay ? "analysis-unit-cache-requires-unit-replay" : "validated",
        }],
      };
      if (unitReplay) {
        scan.analysis = {
          units: ["syntax", "semantic"].map((stage) => ({
            unit_id: `analysis-unit:${size}:${stage}:chunk`,
            adapter: "web",
            stage,
            status: "completed",
            reused: mode === "hit",
          })),
        };
        scan.analysis_coverage = {
          contract_version: "depgraph-analysis-unit-v2",
          plan_id: `analysis-plan:${size}`,
          input_digest: `input:${size}`,
          expected_units: 1,
          completed_units: 1,
          semantic_complete_units: 1,
          failed_units: 0,
          unanalysed_units: 0,
          cancelled_units: 0,
          complete: true,
          reasons: [],
        };
      }
      for (let index = 0; index < 3; index += 1) {
        write(`cache-${size}-${mode}-${index}.json`, scan);
      }
      write(`cache-${size}-${mode}-graph.json`, {
        graph: {
          profiles: [], nodes: [{ id: "file:entry", kind: "file" }],
          sites: [], edges: [], evidence: [], diagnostics: [],
          file_coverage: [], coverage, profile_matrix: {},
        },
      });
    }
  }
  return {
    create: () => createCacheHitReport({ rawDir, output: join(rawDir, "report.json") }),
    /** Alter one raw sample while preserving the other paired evidence. */
    mutate(name, update) {
      const value = JSON.parse(readFileSync(join(rawDir, name), "utf8"));
      update(value);
      write(name, value);
    },
  };
}

test("cache report accepts completed unit replay without a whole-snapshot cache hit", (t) => {
  assert.equal(rawReportFixture(t).create().passed, true);
});

test("cache report preserves legacy whole-snapshot cache evidence", (t) => {
  assert.equal(rawReportFixture(t, false).create().passed, true);
});

test("a legacy cache hit can be paired with an uncached repository-scoped scan", (t) => {
  const fixture = rawReportFixture(t, false);
  fixture.mutate("cache-small-bypass-1.json", (scan) => {
    scan.analysis = { units: [{ stage: "repository", status: "completed", reused: false }] };
    scan.analysis_coverage = { contract_version: "depgraph-analysis-unit-v1", complete: true };
  });
  assert.equal(fixture.create().passed, true);
});

for (const [name, mode, mutate] of [
  ["a semantic unit ran again", "hit", (scan) => { scan.analysis.units[1].reused = false; }],
  ["no syntax unit", "hit", (scan) => { scan.analysis.units.shift(); }],
  ["no semantic unit", "hit", (scan) => { scan.analysis.units.pop(); }],
  ["a failed unit", "hit", (scan) => { scan.analysis.units[0].status = "failed"; }],
  ["duplicate units", "hit", (scan) => { scan.analysis.units.push(scan.analysis.units[0]); }],
  ["incomplete coverage", "hit", (scan) => { scan.analysis_coverage.complete = false; }],
  ["missing semantic coverage", "hit", (scan) => { scan.analysis_coverage.semantic_complete_units = 0; }],
  ["missing unit evidence", "hit", (scan) => {
    delete scan.analysis;
    scan.cache_events.push({ layer: "semantic", outcome: "hit", reason: "validated" });
  }],
  ["legacy hit substituted for unit replay", "hit", (scan) => {
    delete scan.analysis;
    delete scan.analysis_coverage;
    scan.cache_events.push({ layer: "semantic", outcome: "hit", reason: "validated" });
  }],
  ["a snapshot hit alongside replayed units", "hit", (scan) => {
    scan.cache_events.push({ layer: "semantic", outcome: "hit", reason: "validated" });
  }],
  ["a snapshot hit alongside uncached units", "bypass", (scan) => {
    scan.cache_events.push({ layer: "semantic", outcome: "hit", reason: "validated" });
  }],
  ["a snapshot hit with an unknown reason", "hit", (scan) => {
    scan.cache_events.push({ layer: "semantic", outcome: "hit", reason: "unknown" });
  }],
  ["missing source-batch cache events", "hit", (scan) => { delete scan.cache_events; }],
  ["no-cache reused a unit", "bypass", (scan) => { scan.analysis.units[0].reused = true; }],
  ["no-cache did not reject caching", "bypass", (scan) => { scan.cache_events = []; }],
  ["different unit set", "bypass", (scan) => { scan.analysis.units[0].unit_id += "changed"; }],
  ["different input", "bypass", (scan) => { scan.analysis_coverage.input_digest += "changed"; }],
  ["partial scan", "hit", (scan) => { scan.status = "partial"; }],
  ["project code executed", "hit", (scan) => { scan.coverage.project_code_executed = true; }],
]) {
  test(`cache report rejects ${name}`, (t) => {
    const fixture = rawReportFixture(t);
    fixture.mutate(`cache-small-${mode}-1.json`, mutate);
    assert.throws(fixture.create, /scan evidence failed/);
  });
}

test("cache report still requires identical replayed and uncached graphs", (t) => {
  const fixture = rawReportFixture(t);
  fixture.mutate("cache-small-bypass-graph.json", (value) => {
    value.graph.nodes[0].id = "file:different";
  });
  assert.throws(fixture.create, /graph drifted/);
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
