import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  fixtureFingerprint,
  generateFixture,
  mutateFixture,
  restoreFixture,
} from "../benchmark-fixture.mjs";
import {
  evaluateMetric,
  EXPECTED_FIXTURE_SHA256,
  orderedSampleNames,
  REPORT_SCHEMA_VERSION,
  verifyReport,
} from "../benchmark-report.mjs";

test("fixture generation is byte-for-byte deterministic and restorable", (t) => {
  const parent = mkdtempSync(join(tmpdir(), "depgraph-benchmark-test-"));
  const rootOne = join(parent, "one");
  const rootTwo = join(parent, "two");
  t.after(async () => {
    const { rm } = await import("node:fs/promises");
    await rm(parent, { recursive: true, force: true });
  });

  const one = generateFixture(rootOne, 8);
  const two = generateFixture(rootTwo, 8);
  assert.deepEqual(one, two);
  assert.equal(fixtureFingerprint(rootOne), one.sha256);
  assert.equal(fixtureFingerprint(rootTwo), two.sha256);
  const canonicalChangedFile = readFileSync(
    join(rootOne, one.changed_file),
    "utf8",
  );
  assert.equal(
    canonicalChangedFile,
    readFileSync(join(rootTwo, two.changed_file), "utf8"),
  );
  assert.throws(() => generateFixture(rootOne, 8), /exist/i);

  mutateFixture(rootOne, 7);
  assert.notEqual(fixtureFingerprint(rootOne), one.sha256);
  assert.equal(
    readFileSync(join(rootOne, one.changed_file), "utf8"),
    `${canonicalChangedFile}// benchmark revision 7\n`,
  );
  restoreFixture(rootOne);
  assert.equal(fixtureFingerprint(rootOne), one.sha256);

  writeFileSync(
    join(rootOne, "depgraph-benchmark-fixture-v1.json"),
    `${JSON.stringify({ ...one, changed_file: "../../escape.ts" })}\n`,
  );
  assert.throws(() => mutateFixture(rootOne, 8), /invalid benchmark fixture/);
});

test("metric gate tolerates one bounded outlier but rejects a clear regression", () => {
  const noisy = evaluateMetric({
    name: "initial",
    cache: "cold",
    samples: [90, 95, 110],
    limitMs: 100,
    noiseAllowancePercent: 20,
    allowedOutliers: 1,
  });
  assert.equal(noisy.passed, true);
  assert.equal(noisy.outlier_count, 1);
  assert.equal(noisy.hard_limit_ms, 120);

  const regression = evaluateMetric({
    name: "initial",
    cache: "cold",
    samples: [90, 130, 140],
    limitMs: 100,
    noiseAllowancePercent: 20,
    allowedOutliers: 1,
  });
  assert.equal(regression.passed, false);
});

test("sample evidence uses numeric order and rejects gaps", () => {
  const names = Array.from(
    { length: 12 },
    (_, index) => `sample-${index}.json`,
  ).reverse();
  assert.deepEqual(
    orderedSampleNames(names, /^sample-(\d+)\.json$/),
    Array.from({ length: 12 }, (_, index) => `sample-${index}.json`),
  );
  assert.throws(
    () =>
      orderedSampleNames(
        ["sample-0.json", "sample-2.json"],
        /^sample-(\d+)\.json$/,
      ),
    /contiguous/,
  );
});

test("release verification requires the complete 10,000-file metric contract", () => {
  const metricInputs = [
    ["safe_initial_scan", "cold_graph_store", true, [10, 11, 12], 80_000, 30_000],
    [
      "one_file_incremental_scan",
      "warm_analysis_cache",
      true,
      [20, 21, 22],
      2_000,
      2_000,
    ],
    ["cold_file_impact", "first_process_query", false, [1], 4_000, 500],
    [
      "warm_file_impact",
      "bounded_impact_query_cache",
      true,
      [1, 1, 2],
      500,
      500,
    ],
    ["cold_package_impact", "first_process_query", false, [1], 4_000, 500],
    [
      "warm_package_impact",
      "bounded_impact_query_cache",
      true,
      [1, 2, 2],
      500,
      500,
    ],
    ["rust_hir_semantic_scan", "cold_graph_store", true, [5], 10_000, 10_000],
    ["warm_rust_symbol_query", "primed_graph_store", true, [1], 4_000, 500],
    [
      "cross_adapter_build_observation",
      "warm_base_snapshot",
      true,
      [10],
      60_000,
      30_000,
    ],
  ];
  const metrics = metricInputs.map(
    ([name, cache, gated, samples, limitMs, productTargetMs]) =>
      evaluateMetric({
        name,
        cache,
        gated,
        samples,
        limitMs,
        productTargetMs,
        noiseAllowancePercent: 20,
        allowedOutliers: 1,
      }),
  );
  const commit = "e".repeat(40);
  const initialScan = {
    status: "completed",
    files_discovered: 10_001,
    files_analyzed: 10_001,
    dependency_sites: 19_998,
    files_skipped: 0,
    unsupported_syntax: 0,
    unresolved: 0,
    completeness: ["semantic-complete", "syntax-complete"],
    project_code_executed: false,
  };
  const incrementalAttempt = {
    status: "completed",
    change_kind: "modified",
    changed_file: "src/f05000.ts",
    base_snapshot_id: `snapshot:sha256:${"1".repeat(64)}`,
    completed_snapshot_id: `snapshot:sha256:${"2".repeat(64)}`,
    invalidation_schema_version: "incremental-plan-v1",
    affected_profiles: 1,
    incremental_trace: {
      schema_version: "daemon-incremental-trace-v1",
      mode: "semantic_noop",
      base_projection_milliseconds: 5,
      worker_capability_milliseconds: 20,
      worker_analysis_milliseconds: 30,
      store_commit_milliseconds: 10,
      total_milliseconds: 70,
    },
  };
  const report = {
    schema_version: REPORT_SCHEMA_VERSION,
    generated_at: "2026-07-24T00:00:00.000Z",
    commit,
    fixture: {
      schema_version: "depgraph-benchmark-fixture-v1",
      source_file_count: 10_000,
      expected_dependency_sites: 9_999,
      changed_file: "src/f05000.ts",
      changed_file_index: 5_000,
      impact_file: "src/f00001.ts",
      impact_expected_dependent_file: "src/f00000.ts",
      sha256: EXPECTED_FIXTURE_SHA256,
    },
    environment: {
      platform: "test",
      architecture: "test",
      runner: { environment: "local" },
      cache_conditions: {
        safe_initial_scan: "test",
        one_file_incremental_scan: "test",
        cold_query: "test",
        warm_query: "test",
      },
      toolchains: {
        cargo: "test",
        depgraph: "test",
        go: "test",
        node: "test",
        pnpm: "test",
        rustc: "test",
      },
    },
    gate: {
      noise_allowance_percent: 20,
      allowed_outliers: 1,
      passed: true,
    },
    conservation: {
      passed: true,
      graph_equal: true,
      coverage_equal: true,
      changed_file_observed: true,
      site_count_complete: true,
      changed_file: "src/f05000.ts",
      expected_dependency_sites: 9_999,
      graph_sha256_before: "a".repeat(64),
      graph_sha256_after: "a".repeat(64),
      coverage_sha256_before: "b".repeat(64),
      coverage_sha256_after: "b".repeat(64),
      changed_file_node_id: "file:test",
      changed_file_content_hash_before: `sha256:${"c".repeat(64)}`,
      changed_file_content_hash_after: `sha256:${"d".repeat(64)}`,
      counts: {
        profiles: 1,
        nodes: 20_003,
        sites: 19_998,
        edges: 40_000,
        evidence: 79_996,
        file_coverage: 10_001,
      },
    },
    evidence: {
      initial_scans: Array.from({ length: 3 }, () => ({ ...initialScan })),
      incremental_attempts: Array.from({ length: 3 }, () => ({
        ...incrementalAttempt,
      })),
      impact_queries: {
        file_root_id: "file:test",
        file_impact_count: 4,
        file_root_observed: true,
        file_expected_dependent_observed: true,
        package_root_id: "package:test",
        package_impact_count: 2,
        package_root_observed: true,
        package_workspace_observed: true,
      },
      rust_semantic_complete: true,
      cross_adapter_build_profiles: [
        "next-app",
        "astro-app",
        "start",
        "rust-app",
      ],
    },
    metrics,
  };
  assert.equal(verifyReport(report, commit), true);

  const missingMetric = structuredClone(report);
  missingMetric.metrics.pop();
  assert.throws(
    () => verifyReport(missingMetric, commit),
    /release contract/,
  );
  const forgedGate = structuredClone(report);
  forgedGate.metrics[0].gated = false;
  assert.throws(
    () => verifyReport(forgedGate, commit),
    /release contract/,
  );
  const missingToolchain = structuredClone(report);
  missingToolchain.environment.toolchains.node = "unavailable: ENOENT";
  assert.throws(
    () => verifyReport(missingToolchain, commit),
    /release contract/,
  );
});
