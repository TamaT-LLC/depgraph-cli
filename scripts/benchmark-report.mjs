#!/usr/bin/env node

import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import {
  mkdirSync,
  readFileSync,
  readdirSync,
  writeFileSync,
} from "node:fs";
import { dirname, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

import {
  FIXTURE_SCHEMA_VERSION,
  fixtureFingerprint,
} from "./benchmark-fixture.mjs";

export const REPORT_SCHEMA_VERSION = "depgraph-benchmark-report-v4";
export const EXPECTED_FIXTURE_SHA256 =
  "f57a6d7d2e22366f5d312f01f038f6f50e2c2fbbd4480b9849ed82a696e97dc1";

const METRIC_CONTRACTS = new Map([
  [
    "safe_initial_scan",
    {
      cache: "cold_graph_store",
      gated: true,
      minimum_samples: 3,
      maximum_samples: 20,
      maximum_limit_ms: 80_000,
      product_target_ms: 30_000,
    },
  ],
  [
    "one_file_incremental_scan",
    {
      cache: "warm_analysis_cache",
      gated: true,
      minimum_samples: 3,
      maximum_samples: 20,
      maximum_limit_ms: 2_000,
      product_target_ms: 2_000,
    },
  ],
  [
    "cold_file_impact",
    {
      cache: "first_process_query",
      gated: false,
      minimum_samples: 1,
      maximum_samples: 1,
      maximum_limit_ms: 4_000,
      product_target_ms: 500,
    },
  ],
  [
    "warm_file_impact",
    {
      cache: "bounded_impact_query_cache",
      gated: true,
      minimum_samples: 3,
      maximum_samples: 50,
      maximum_limit_ms: 500,
      product_target_ms: 500,
    },
  ],
  [
    "cold_package_impact",
    {
      cache: "first_process_query",
      gated: false,
      minimum_samples: 1,
      maximum_samples: 1,
      maximum_limit_ms: 4_000,
      product_target_ms: 500,
    },
  ],
  [
    "warm_package_impact",
    {
      cache: "bounded_impact_query_cache",
      gated: true,
      minimum_samples: 3,
      maximum_samples: 50,
      maximum_limit_ms: 500,
      product_target_ms: 500,
    },
  ],
  [
    "rust_hir_semantic_scan",
    {
      cache: "cold_graph_store",
      gated: true,
      minimum_samples: 1,
      maximum_samples: 1,
      maximum_limit_ms: 10_000,
      product_target_ms: 10_000,
    },
  ],
  [
    "warm_rust_symbol_query",
    {
      cache: "primed_graph_store",
      gated: true,
      minimum_samples: 1,
      maximum_samples: 1,
      maximum_limit_ms: 4_000,
      product_target_ms: 500,
    },
  ],
  [
    "cross_adapter_build_observation",
    {
      cache: "warm_base_snapshot",
      gated: true,
      minimum_samples: 1,
      maximum_samples: 1,
      maximum_limit_ms: 60_000,
      product_target_ms: 30_000,
    },
  ],
]);
const CACHE_CONDITIONS = {
  safe_initial_scan: "fresh SQLite graph store for every sample",
  one_file_incremental_scan:
    "watcher daemon with a completed base snapshot and warm analysis cache",
  cold_query: "first query process against an unqueried completed graph store",
  warm_query:
    "independent query processes using the snapshot/filter-scoped bounded impact query cache after one priming query",
};
const CACHE_CONDITION_KEYS = Object.keys(CACHE_CONDITIONS);
const TOOLCHAIN_KEYS = ["cargo", "depgraph", "go", "node", "pnpm", "rustc"];
const CROSS_ADAPTER_PROFILES = [
  "next-app",
  "astro-app",
  "start",
  "rust-app",
];

function integerEnvironment(name, fallback, minimum = 0) {
  const raw = process.env[name];
  const value = raw === undefined ? fallback : Number(raw);
  if (!Number.isSafeInteger(value) || value < minimum) {
    throw new Error(`${name} must be an integer greater than or equal to ${minimum}`);
  }
  return value;
}

function readSamples(path) {
  const samples = readFileSync(path, "utf8")
    .split(/\r?\n/)
    .filter(Boolean)
    .map(Number);
  if (
    samples.length === 0 ||
    samples.some((sample) => !Number.isSafeInteger(sample) || sample < 0)
  ) {
    throw new Error(`invalid benchmark samples in ${path}`);
  }
  return samples;
}

function median(samples) {
  const ordered = [...samples].sort((left, right) => left - right);
  const middle = Math.floor(ordered.length / 2);
  return ordered.length % 2 === 0
    ? Math.round((ordered[middle - 1] + ordered[middle]) / 2)
    : ordered[middle];
}

export function evaluateMetric({
  name,
  cache,
  samples,
  limitMs,
  productTargetMs = limitMs,
  noiseAllowancePercent,
  allowedOutliers,
  gated = true,
}) {
  if (
    !name ||
    !cache ||
    samples.length === 0 ||
    samples.some((sample) => !Number.isSafeInteger(sample) || sample < 0) ||
    !Number.isSafeInteger(limitMs) ||
    limitMs <= 0 ||
    !Number.isSafeInteger(productTargetMs) ||
    productTargetMs <= 0 ||
    !Number.isSafeInteger(noiseAllowancePercent) ||
    noiseAllowancePercent < 0 ||
    !Number.isSafeInteger(allowedOutliers) ||
    allowedOutliers < 0
  ) {
    throw new Error(`invalid benchmark metric ${name || "<unnamed>"}`);
  }
  const hardLimitMs = Math.floor(
    (limitMs * (100 + noiseAllowancePercent)) / 100,
  );
  const medianMs = median(samples);
  const maximumMs = Math.max(...samples);
  const outlierCount = samples.filter((sample) => sample > limitMs).length;
  const withinLimit =
    medianMs <= limitMs &&
    outlierCount <= allowedOutliers &&
    maximumMs <= hardLimitMs;
  return {
    name,
    unit: "ms",
    cache,
    samples_ms: samples,
    median_ms: medianMs,
    maximum_ms: maximumMs,
    limit_ms: limitMs,
    product_target_ms: productTargetMs,
    hard_limit_ms: hardLimitMs,
    noise_allowance_percent: noiseAllowancePercent,
    allowed_outliers: allowedOutliers,
    outlier_count: outlierCount,
    gated,
    within_limit: withinLimit,
    passed: gated ? withinLimit : true,
  };
}

function jsonFile(path) {
  return JSON.parse(readFileSync(path, "utf8"));
}

function digest(value) {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex");
}

function commandVersion(command, args = ["--version"]) {
  try {
    return execFileSync(command, args, {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    }).trim();
  } catch (error) {
    return `unavailable: ${error.code ?? error.message}`;
  }
}

export function orderedSampleNames(names, pattern) {
  const samples = names
    .map((name) => {
      const match = pattern.exec(name);
      return match ? { index: Number(match[1]), name } : null;
    })
    .filter(Boolean)
    .sort((left, right) => left.index - right.index);
  if (
    samples.some(
      (sample, expectedIndex) =>
        !Number.isSafeInteger(sample.index) ||
        sample.index !== expectedIndex,
    )
  ) {
    throw new Error("benchmark sample files must use contiguous zero-based indices");
  }
  return samples.map((sample) => sample.name);
}

function validateInitialScans(rawDir, fixture) {
  const paths = orderedSampleNames(
    readdirSync(rawDir),
    /^initial-scan-(\d+)\.json$/,
  )
    .map((name) => join(rawDir, name));
  if (paths.length < 3) {
    throw new Error("benchmark requires at least three initial scan samples");
  }
  return paths.map((path) => {
    const scan = jsonFile(path);
    if (
      scan.status !== "completed" ||
      scan.coverage?.files_discovered < fixture.source_file_count ||
      scan.coverage?.files_analyzed < fixture.source_file_count ||
      scan.coverage?.dependency_sites < fixture.expected_dependency_sites ||
      scan.coverage?.files_skipped !== 0 ||
      scan.coverage?.unsupported_syntax !== 0 ||
      scan.coverage?.unresolved !== 0 ||
      !scan.coverage?.completeness?.includes("semantic-complete") ||
      scan.coverage?.project_code_executed !== false
    ) {
      throw new Error(`initial scan conservation failed in ${path}`);
    }
    return {
      status: scan.status,
      files_discovered: scan.coverage.files_discovered,
      files_analyzed: scan.coverage.files_analyzed,
      dependency_sites: scan.coverage.dependency_sites,
      files_skipped: scan.coverage.files_skipped,
      unsupported_syntax: scan.coverage.unsupported_syntax,
      unresolved: scan.coverage.unresolved,
      completeness: scan.coverage.completeness,
      project_code_executed: scan.coverage.project_code_executed,
    };
  });
}

function validateImpactQueries(rawDir, fixture) {
  const file = jsonFile(join(rawDir, "cold-file-impact.json"));
  const packageImpact = jsonFile(join(rawDir, "cold-package-impact.json"));
  const fileImpacts = file.data?.impacts;
  const packageImpacts = packageImpact.data?.impacts;
  const fileRootObserved = fileImpacts?.some(
    (impact) =>
      impact.node?.id === file.data?.root?.id &&
      impact.node?.kind === "file" &&
      impact.depth === 0,
  );
  const fileDependentObserved = fileImpacts?.some(
    (impact) =>
      impact.node?.kind === "file" &&
      impact.node?.properties?.path ===
        fixture.impact_expected_dependent_file &&
      impact.depth === 1,
  );
  const packageRootObserved = packageImpacts?.some(
    (impact) =>
      impact.node?.id === packageImpact.data?.root?.id &&
      impact.node?.kind === "package_instance" &&
      impact.depth === 0,
  );
  const packageWorkspaceObserved = packageImpacts?.some(
    (impact) => impact.node?.kind === "workspace" && impact.depth === 1,
  );
  if (
    file.command !== "impact" ||
    file.data?.complete !== true ||
    file.data?.root?.kind !== "file" ||
    file.data?.root?.properties?.path !== fixture.impact_file ||
    !Array.isArray(fileImpacts) ||
    !fileRootObserved ||
    !fileDependentObserved ||
    packageImpact.command !== "impact" ||
    packageImpact.data?.complete !== true ||
    packageImpact.data?.root?.kind !== "package_instance" ||
    !packageImpact.data?.root?.locator?.includes("depgraph-benchmark") ||
    !Array.isArray(packageImpacts) ||
    !packageRootObserved ||
    !packageWorkspaceObserved
  ) {
    throw new Error("file/package impact benchmark contract is incomplete");
  }
  return {
    file_root_id: file.data.root.id,
    file_impact_count: file.data.impacts?.length ?? 0,
    file_root_observed: fileRootObserved,
    file_expected_dependent_observed: fileDependentObserved,
    package_root_id: packageImpact.data.root.id,
    package_impact_count: packageImpact.data.impacts?.length ?? 0,
    package_root_observed: packageRootObserved,
    package_workspace_observed: packageWorkspaceObserved,
  };
}

function validIncrementalTrace(trace) {
  if (
    trace?.schema_version !== "daemon-incremental-trace-v1" ||
    trace.mode !== "semantic_noop"
  ) {
    return false;
  }
  const phases = [
    trace.base_projection_milliseconds,
    trace.worker_capability_milliseconds,
    trace.worker_analysis_milliseconds,
    trace.store_commit_milliseconds,
  ];
  return (
    [...phases, trace.total_milliseconds].every(
      (value) => Number.isSafeInteger(value) && value >= 0,
    ) &&
    trace.total_milliseconds >= phases.reduce((total, value) => total + value, 0)
  );
}

function validateIncrementalAttempts(rawDir, changedFile) {
  const paths = orderedSampleNames(
    readdirSync(rawDir),
    /^incremental-status-(\d+)\.json$/,
  )
    .map((name) => join(rawDir, name));
  if (paths.length < 3) {
    throw new Error("benchmark requires at least three incremental samples");
  }
  return paths.map((path) => {
    const status = jsonFile(path);
    const attempt = status.last_completed_attempt;
    const trace = attempt?.incremental_trace;
    if (
      attempt?.status !== "completed" ||
      !attempt.base_snapshot_id ||
      !attempt.completed_snapshot_id ||
      !attempt.invalidation_plan ||
      attempt.invalidation_plan.schema_version !== "incremental-plan-v1" ||
      !Array.isArray(attempt.invalidation_plan.affected_profile_ids) ||
      attempt.invalidation_plan.affected_profile_ids.length === 0 ||
      !validIncrementalTrace(trace) ||
      attempt.invalidation_error !== null ||
      attempt.changes?.length !== 1 ||
      !["added", "modified"].includes(attempt.changes[0].kind) ||
      attempt.changes[0].new_path !== changedFile
    ) {
      throw new Error(`incremental attempt validation failed in ${path}`);
    }
    return {
      status: attempt.status,
      change_kind: attempt.changes[0].kind,
      changed_file: attempt.changes[0].new_path,
      base_snapshot_id: attempt.base_snapshot_id,
      completed_snapshot_id: attempt.completed_snapshot_id,
      invalidation_schema_version: attempt.invalidation_plan.schema_version,
      affected_profiles: attempt.invalidation_plan.affected_profile_ids?.length ?? 0,
      incremental_trace: trace,
    };
  });
}

function graphConservation(rawDir, changedFile, expectedDependencySites) {
  const before = jsonFile(join(rawDir, "graph-before.json")).graph;
  const after = jsonFile(join(rawDir, "graph-after.json")).graph;
  if (!before || !after) {
    throw new Error("benchmark graph exports are missing their graph envelope");
  }
  const changedNodeBefore = before.nodes?.find(
    (node) => node.kind === "file" && node.properties?.path === changedFile,
  );
  const changedNodeAfter = after.nodes?.find(
    (node) => node.kind === "file" && node.properties?.path === changedFile,
  );
  if (!changedNodeBefore || !changedNodeAfter) {
    throw new Error("benchmark changed file node is missing from graph conservation");
  }
  const normalizeNodes = (nodes) =>
    nodes.map((node) => {
      if (node.id !== changedNodeBefore.id) return node;
      const properties = { ...node.properties };
      delete properties.content_hash;
      return { ...node, properties };
    });
  const graphKeys = ["profiles", "sites", "edges", "evidence"];
  const coverageKeys = ["file_coverage", "coverage", "profile_matrix"];
  const beforeGraph = Object.fromEntries(
    graphKeys.map((key) => [key, before[key]]),
  );
  beforeGraph.nodes = normalizeNodes(before.nodes);
  const afterGraph = Object.fromEntries(
    graphKeys.map((key) => [key, after[key]]),
  );
  afterGraph.nodes = normalizeNodes(after.nodes);
  const beforeCoverage = Object.fromEntries(
    coverageKeys.map((key) => [key, before[key]]),
  );
  const afterCoverage = Object.fromEntries(
    coverageKeys.map((key) => [key, after[key]]),
  );
  const graphBefore = digest(beforeGraph);
  const graphAfter = digest(afterGraph);
  const coverageBefore = digest(beforeCoverage);
  const coverageAfter = digest(afterCoverage);
  const contentHashBefore = changedNodeBefore.properties?.content_hash;
  const contentHashAfter = changedNodeAfter.properties?.content_hash;
  const changedFileObserved =
    typeof contentHashBefore === "string" &&
    typeof contentHashAfter === "string" &&
    contentHashBefore !== contentHashAfter;
  const siteCount = before.sites?.length ?? 0;
  const siteCountComplete = siteCount >= expectedDependencySites;
  const passed =
    graphBefore === graphAfter &&
    coverageBefore === coverageAfter &&
    changedFileObserved &&
    siteCountComplete;
  return {
    graph_sha256_before: graphBefore,
    graph_sha256_after: graphAfter,
    coverage_sha256_before: coverageBefore,
    coverage_sha256_after: coverageAfter,
    graph_equal: graphBefore === graphAfter,
    coverage_equal: coverageBefore === coverageAfter,
    changed_file: changedFile,
    changed_file_node_id: changedNodeBefore.id,
    changed_file_content_hash_before: contentHashBefore,
    changed_file_content_hash_after: contentHashAfter,
    changed_file_observed: changedFileObserved,
    expected_dependency_sites: expectedDependencySites,
    site_count_complete: siteCountComplete,
    counts: {
      profiles: before.profiles?.length ?? 0,
      nodes: before.nodes?.length ?? 0,
      sites: siteCount,
      edges: before.edges?.length ?? 0,
      evidence: before.evidence?.length ?? 0,
      file_coverage: before.file_coverage?.length ?? 0,
    },
    passed,
  };
}

export function validateRustBenchmarkEvidence(rustScan, rustGraph) {
  const profile = rustGraph.profiles?.find(
    (candidate) => candidate.language === "rust",
  );
  if (
    rustScan.status !== "completed" ||
    rustGraph.coverage?.project_code_executed !== false ||
    !rustGraph.coverage?.completeness?.includes("syntax-complete") ||
    rustGraph.coverage?.completeness?.includes("semantic-complete") ||
    !rustGraph.coverage?.reasons?.includes("rust-hir-sysroot-unavailable") ||
    profile?.properties?.analysis_backend !==
      "static-syntax+rust-analyzer-hir" ||
    profile?.properties?.rust_hir_enable_gate !== "release-gate-pending" ||
    profile?.properties?.rust_hir_status !==
      "import-type-call-graph-partial" ||
    profile?.properties?.rust_hir_sysroot_status !== "unavailable" ||
    profile?.properties?.rust_hir_sysroot_file_count !== 0 ||
    profile?.properties?.rust_hir_sysroot_crate_count !== 0 ||
    !Number.isSafeInteger(
      profile?.properties?.rust_hir_project_external_count,
    ) ||
    profile.properties.rust_hir_project_external_count <= 0
  ) {
    throw new Error("Rust HIR benchmark evidence is incomplete");
  }
  return true;
}

function validateAuxiliaryEvidence(rawDir) {
  const rustScan = jsonFile(join(rawDir, "rust-scan.json"));
  const rustGraph = jsonFile(join(rawDir, "rust-graph.json")).graph;
  validateRustBenchmarkEvidence(rustScan, rustGraph);

  const expected = new Map([
    ["next-app", ["web:build:next", "next-adapter-observer"]],
    ["astro-app", ["web:build:astro", "astro-vite-build-observer"]],
    [
      "start",
      ["web:build:tanstack-start", "tanstack-start-vite-build-observer"],
    ],
    ["rust-app", ["rust:build", "rust-cargo-build-observer"]],
  ]);
  for (const [app, [profileId, observer]] of expected) {
    const graph = jsonFile(join(rawDir, `build-${app}.json`)).graph;
    if (
      !graph.edges.some(
        (edge) =>
          edge.phase === "build" &&
          edge.precision === "observed" &&
          edge.profile_id === profileId,
      ) ||
      !graph.evidence.some(
        (item) => item.kind === "build" && item.extractor === observer,
      ) ||
      !["static", "semantic", "build"].every(
        (phase) => graph.profile_matrix?.phase_coverage?.[phase],
      )
    ) {
      throw new Error(`cross-adapter build benchmark evidence failed for ${app}`);
    }
  }
  return {
    rust_semantic_complete: false,
    rust_development_sysroot_fallback: true,
    cross_adapter_build_profiles: CROSS_ADAPTER_PROFILES,
  };
}

function threshold(name, fallback) {
  return integerEnvironment(name, fallback, 1);
}

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function hasExactKeys(value, keys) {
  return (
    isRecord(value) &&
    JSON.stringify(Object.keys(value).sort()) ===
      JSON.stringify([...keys].sort())
  );
}

function validToolchains(toolchains) {
  return (
    hasExactKeys(toolchains, TOOLCHAIN_KEYS) &&
    Object.values(toolchains).every(
      (value) =>
        typeof value === "string" &&
        value.length > 0 &&
        !value.startsWith("unavailable:"),
    )
  );
}

function validMetrics(report) {
  if (
    !Array.isArray(report.metrics) ||
    report.metrics.length !== METRIC_CONTRACTS.size ||
    !Number.isSafeInteger(report.gate?.noise_allowance_percent) ||
    report.gate.noise_allowance_percent < 0 ||
    report.gate.noise_allowance_percent > 20 ||
    !Number.isSafeInteger(report.gate?.allowed_outliers) ||
    report.gate.allowed_outliers < 0 ||
    report.gate.allowed_outliers > 1
  ) {
    return false;
  }
  const metrics = new Map(
    report.metrics.map((metric) => [metric?.name, metric]),
  );
  if (metrics.size !== METRIC_CONTRACTS.size) return false;

  for (const [name, contract] of METRIC_CONTRACTS) {
    const metric = metrics.get(name);
    if (
      !isRecord(metric) ||
      metric.unit !== "ms" ||
      metric.cache !== contract.cache ||
      metric.gated !== contract.gated ||
      metric.product_target_ms !== contract.product_target_ms ||
      !Array.isArray(metric.samples_ms) ||
      metric.samples_ms.length < contract.minimum_samples ||
      metric.samples_ms.length > contract.maximum_samples ||
      !Number.isSafeInteger(metric.limit_ms) ||
      metric.limit_ms <= 0 ||
      metric.limit_ms > contract.maximum_limit_ms ||
      metric.noise_allowance_percent !==
        report.gate.noise_allowance_percent ||
      metric.allowed_outliers !== report.gate.allowed_outliers
    ) {
      return false;
    }
    let recomputed;
    try {
      recomputed = evaluateMetric({
        name,
        cache: contract.cache,
        samples: metric.samples_ms,
        limitMs: metric.limit_ms,
        productTargetMs: contract.product_target_ms,
        noiseAllowancePercent: report.gate.noise_allowance_percent,
        allowedOutliers: report.gate.allowed_outliers,
        gated: contract.gated,
      });
    } catch {
      return false;
    }
    for (const field of [
      "samples_ms",
      "median_ms",
      "maximum_ms",
      "hard_limit_ms",
      "outlier_count",
      "within_limit",
      "passed",
    ]) {
      if (JSON.stringify(metric[field]) !== JSON.stringify(recomputed[field])) {
        return false;
      }
    }
  }

  const expectedGate = report.metrics
    .filter((metric) => metric.gated)
    .every((metric) => metric.passed);
  return report.gate.passed === expectedGate && expectedGate;
}

function validEvidence(report) {
  const evidence = report.evidence;
  const initialMetric = report.metrics.find(
    (metric) => metric.name === "safe_initial_scan",
  );
  const incrementalMetric = report.metrics.find(
    (metric) => metric.name === "one_file_incremental_scan",
  );
  if (
    !isRecord(evidence) ||
    !Array.isArray(evidence.initial_scans) ||
    evidence.initial_scans.length !== initialMetric.samples_ms.length ||
    !evidence.initial_scans.every(
      (scan) =>
        scan.status === "completed" &&
        scan.files_discovered >= report.fixture.source_file_count &&
        scan.files_analyzed >= report.fixture.source_file_count &&
        scan.dependency_sites >= report.fixture.expected_dependency_sites &&
        scan.files_skipped === 0 &&
        scan.unsupported_syntax === 0 &&
        scan.unresolved === 0 &&
        Array.isArray(scan.completeness) &&
        scan.completeness.includes("semantic-complete") &&
        scan.project_code_executed === false,
    ) ||
    !Array.isArray(evidence.incremental_attempts) ||
    evidence.incremental_attempts.length !==
      incrementalMetric.samples_ms.length ||
    !evidence.incremental_attempts.every(
      (attempt) =>
        attempt.status === "completed" &&
        ["added", "modified"].includes(attempt.change_kind) &&
        attempt.changed_file === report.fixture.changed_file &&
        typeof attempt.base_snapshot_id === "string" &&
        attempt.base_snapshot_id.startsWith("snapshot:sha256:") &&
        typeof attempt.completed_snapshot_id === "string" &&
        attempt.completed_snapshot_id.startsWith("snapshot:sha256:") &&
        attempt.base_snapshot_id !== attempt.completed_snapshot_id &&
        attempt.invalidation_schema_version === "incremental-plan-v1" &&
        Number.isSafeInteger(attempt.affected_profiles) &&
        attempt.affected_profiles > 0 &&
        validIncrementalTrace(attempt.incremental_trace),
    ) ||
    !isRecord(evidence.impact_queries) ||
    typeof evidence.impact_queries.file_root_id !== "string" ||
    evidence.impact_queries.file_root_id.length === 0 ||
    !Number.isSafeInteger(evidence.impact_queries.file_impact_count) ||
    evidence.impact_queries.file_impact_count < 2 ||
    evidence.impact_queries.file_root_observed !== true ||
    evidence.impact_queries.file_expected_dependent_observed !== true ||
    typeof evidence.impact_queries.package_root_id !== "string" ||
    evidence.impact_queries.package_root_id.length === 0 ||
    !Number.isSafeInteger(evidence.impact_queries.package_impact_count) ||
    evidence.impact_queries.package_impact_count < 2 ||
    evidence.impact_queries.package_root_observed !== true ||
    evidence.impact_queries.package_workspace_observed !== true ||
    evidence.rust_semantic_complete !== false ||
    evidence.rust_development_sysroot_fallback !== true ||
    JSON.stringify(evidence.cross_adapter_build_profiles) !==
      JSON.stringify(CROSS_ADAPTER_PROFILES)
  ) {
    return false;
  }
  return true;
}

function validConservation(report) {
  const conservation = report.conservation;
  const unprefixedSha256 = (value) =>
    typeof value === "string" && /^[0-9a-f]{64}$/.test(value);
  const prefixedSha256 = (value) =>
    typeof value === "string" && /^sha256:[0-9a-f]{64}$/.test(value);
  return (
    isRecord(conservation) &&
    conservation.passed === true &&
    conservation.graph_equal === true &&
    conservation.coverage_equal === true &&
    conservation.changed_file_observed === true &&
    conservation.site_count_complete === true &&
    conservation.changed_file === report.fixture.changed_file &&
    conservation.expected_dependency_sites ===
      report.fixture.expected_dependency_sites &&
    unprefixedSha256(conservation.graph_sha256_before) &&
    conservation.graph_sha256_before === conservation.graph_sha256_after &&
    unprefixedSha256(conservation.coverage_sha256_before) &&
    conservation.coverage_sha256_before ===
      conservation.coverage_sha256_after &&
    typeof conservation.changed_file_node_id === "string" &&
    conservation.changed_file_node_id.length > 0 &&
    prefixedSha256(conservation.changed_file_content_hash_before) &&
    prefixedSha256(conservation.changed_file_content_hash_after) &&
    conservation.changed_file_content_hash_before !==
      conservation.changed_file_content_hash_after &&
    isRecord(conservation.counts) &&
    Number.isSafeInteger(conservation.counts.profiles) &&
    conservation.counts.profiles > 0 &&
    Number.isSafeInteger(conservation.counts.nodes) &&
    conservation.counts.nodes >= report.fixture.source_file_count &&
    Number.isSafeInteger(conservation.counts.sites) &&
    conservation.counts.sites >= report.fixture.expected_dependency_sites &&
    Number.isSafeInteger(conservation.counts.edges) &&
    conservation.counts.edges > 0 &&
    Number.isSafeInteger(conservation.counts.evidence) &&
    conservation.counts.evidence > 0 &&
    Number.isSafeInteger(conservation.counts.file_coverage) &&
    conservation.counts.file_coverage >= report.fixture.source_file_count
  );
}

function validEnvironment(environment) {
  return (
    isRecord(environment) &&
    typeof environment.platform === "string" &&
    environment.platform.length > 0 &&
    typeof environment.architecture === "string" &&
    environment.architecture.length > 0 &&
    isRecord(environment.runner) &&
    ["github-actions", "local"].includes(environment.runner.environment) &&
    hasExactKeys(environment.cache_conditions, CACHE_CONDITION_KEYS) &&
    Object.values(environment.cache_conditions).every(
      (value) => typeof value === "string" && value.length > 0,
    ) &&
    validToolchains(environment.toolchains)
  );
}

export function createReport({ rawDir, fixtureDir, output }) {
  rawDir = resolve(rawDir);
  fixtureDir = resolve(fixtureDir);
  output = resolve(output);
  const fixture = jsonFile(
    join(fixtureDir, "depgraph-benchmark-fixture-v1.json"),
  );
  if (
    fixture.schema_version !== FIXTURE_SCHEMA_VERSION ||
    fixture.source_file_count < 2 ||
    fixture.expected_dependency_sites !== fixture.source_file_count - 1 ||
    typeof fixture.impact_file !== "string" ||
    typeof fixture.impact_expected_dependent_file !== "string" ||
    fixture.sha256 !== fixtureFingerprint(fixtureDir)
  ) {
    throw new Error("benchmark fixture manifest or fingerprint is invalid");
  }

  const noiseAllowancePercent = integerEnvironment(
    "DEPGRAPH_NOISE_ALLOWANCE_PERCENT",
    20,
  );
  const allowedOutliers = integerEnvironment(
    "DEPGRAPH_ALLOWED_OUTLIERS",
    1,
  );
  const gatedMetric = (
    name,
    cache,
    sampleFile,
    limitMs,
    productTargetMs = limitMs,
  ) =>
    evaluateMetric({
      name,
      cache,
      samples: readSamples(join(rawDir, sampleFile)),
      limitMs,
      productTargetMs,
      noiseAllowancePercent,
      allowedOutliers,
    });
  const observedMetric = (
    name,
    cache,
    sampleFile,
    limitMs,
    productTargetMs = limitMs,
  ) =>
    evaluateMetric({
      name,
      cache,
      samples: readSamples(join(rawDir, sampleFile)),
      limitMs,
      productTargetMs,
      noiseAllowancePercent,
      allowedOutliers,
      gated: false,
    });

  const queryLimit = threshold("DEPGRAPH_QUERY_LIMIT_MS", 500);
  const metrics = [
    gatedMetric(
      "safe_initial_scan",
      "cold_graph_store",
      "initial-scan-ms.txt",
      threshold("DEPGRAPH_SCAN_LIMIT_MS", 30_000),
      30_000,
    ),
    gatedMetric(
      "one_file_incremental_scan",
      "warm_analysis_cache",
      "incremental-scan-ms.txt",
      threshold("DEPGRAPH_INCREMENTAL_LIMIT_MS", 2_000),
      2_000,
    ),
    observedMetric(
      "cold_file_impact",
      "first_process_query",
      "cold-file-impact-ms.txt",
      queryLimit,
      500,
    ),
    gatedMetric(
      "warm_file_impact",
      "bounded_impact_query_cache",
      "warm-file-impact-ms.txt",
      queryLimit,
      500,
    ),
    observedMetric(
      "cold_package_impact",
      "first_process_query",
      "cold-package-impact-ms.txt",
      queryLimit,
      500,
    ),
    gatedMetric(
      "warm_package_impact",
      "bounded_impact_query_cache",
      "warm-package-impact-ms.txt",
      queryLimit,
      500,
    ),
    gatedMetric(
      "rust_hir_semantic_scan",
      "cold_graph_store",
      "rust-scan-ms.txt",
      threshold("DEPGRAPH_RUST_SCAN_LIMIT_MS", 10_000),
      10_000,
    ),
    gatedMetric(
      "warm_rust_symbol_query",
      "primed_graph_store",
      "rust-query-ms.txt",
      queryLimit,
      500,
    ),
    gatedMetric(
      "cross_adapter_build_observation",
      "warm_base_snapshot",
      "build-observation-ms.txt",
      threshold("DEPGRAPH_BUILD_OBSERVATION_LIMIT_MS", 30_000),
      30_000,
    ),
  ];
  const conservation = graphConservation(
    rawDir,
    fixture.changed_file,
    fixture.expected_dependency_sites,
  );
  const initialScans = validateInitialScans(rawDir, fixture);
  const incrementalAttempts = validateIncrementalAttempts(
    rawDir,
    fixture.changed_file,
  );
  const impactQueries = validateImpactQueries(rawDir, fixture);
  const auxiliaryEvidence = validateAuxiliaryEvidence(rawDir);
  const gatePassed =
    conservation.passed &&
    metrics.filter((metric) => metric.gated).every((metric) => metric.passed);
  const binary =
    process.env.DEPGRAPH_BENCH_BINARY ?? "target/release/depgraph";
  const toolchains = {
    depgraph: commandVersion(binary),
    rustc: commandVersion("rustc", ["-Vv"]),
    cargo: commandVersion("cargo"),
    go: commandVersion("go", ["version"]),
    node: commandVersion("node"),
    pnpm: commandVersion("pnpm"),
  };
  if (!validToolchains(toolchains)) {
    throw new Error("benchmark toolchain metadata is incomplete");
  }
  const report = {
    schema_version: REPORT_SCHEMA_VERSION,
    generated_at: new Date().toISOString(),
    commit:
      process.env.GITHUB_SHA ??
      commandVersion("git", ["rev-parse", "HEAD"]).split(/\r?\n/)[0],
    fixture,
    environment: {
      platform: process.platform,
      architecture: process.arch,
      runner: {
        os: process.env.RUNNER_OS ?? null,
        architecture: process.env.RUNNER_ARCH ?? null,
        name: process.env.RUNNER_NAME ?? null,
        environment: process.env.GITHUB_ACTIONS === "true" ? "github-actions" : "local",
      },
      cache_conditions: CACHE_CONDITIONS,
      toolchains,
    },
    gate: {
      noise_allowance_percent: noiseAllowancePercent,
      allowed_outliers: allowedOutliers,
      passed: gatePassed,
    },
    metrics,
    conservation,
    evidence: {
      initial_scans: initialScans,
      incremental_attempts: incrementalAttempts,
      impact_queries: impactQueries,
      ...auxiliaryEvidence,
    },
  };

  mkdirSync(dirname(output), { recursive: true });
  writeFileSync(output, `${JSON.stringify(report, null, 2)}\n`);
  return report;
}

export function verifyReport(report, expectedCommit = process.env.GITHUB_SHA) {
  if (
    report.schema_version !== REPORT_SCHEMA_VERSION ||
    typeof report.generated_at !== "string" ||
    !Number.isFinite(Date.parse(report.generated_at)) ||
    typeof report.commit !== "string" ||
    !/^[0-9a-f]{40}([0-9a-f]{24})?$/.test(report.commit) ||
    !hasExactKeys(report.fixture, [
      "schema_version",
      "source_file_count",
      "expected_dependency_sites",
      "changed_file",
      "changed_file_index",
      "impact_file",
      "impact_expected_dependent_file",
      "sha256",
    ]) ||
    report.fixture?.schema_version !== FIXTURE_SCHEMA_VERSION ||
    report.fixture?.source_file_count !== 10_000 ||
    report.fixture?.expected_dependency_sites !== 9_999 ||
    report.fixture?.changed_file !== "src/f05000.ts" ||
    report.fixture?.changed_file_index !== 5_000 ||
    report.fixture?.impact_file !== "src/f00001.ts" ||
    report.fixture?.impact_expected_dependent_file !== "src/f00000.ts" ||
    report.fixture?.sha256 !== EXPECTED_FIXTURE_SHA256 ||
    !hasExactKeys(report.gate, [
      "noise_allowance_percent",
      "allowed_outliers",
      "passed",
    ]) ||
    !validMetrics(report) ||
    !validEvidence(report) ||
    !validConservation(report) ||
    !validEnvironment(report.environment) ||
    (expectedCommit && report.commit !== expectedCommit)
  ) {
    throw new Error("benchmark report does not satisfy the release contract");
  }
  return true;
}

function printSummary(report, output) {
  for (const metric of report.metrics) {
    const marker = metric.gated ? (metric.passed ? "PASS" : "FAIL") : "OBSERVED";
    process.stdout.write(
      `${marker} ${metric.name}: median ${metric.median_ms} ms, max ${metric.maximum_ms} ms, limit ${metric.limit_ms} ms (${metric.cache})\n`,
    );
  }
  process.stdout.write(
    `${report.conservation.passed ? "PASS" : "FAIL"} graph/coverage conservation\n`,
  );
  process.stdout.write(`benchmark report: ${output}\n`);
}

function main(argv) {
  const [command, ...rest] = argv;
  if (command === "create" && rest.length === 3) {
    const [rawDir, fixtureDir, output] = rest;
    const report = createReport({ rawDir, fixtureDir, output });
    printSummary(report, resolve(output));
    if (!report.gate.passed) process.exitCode = 1;
    return;
  }
  if (command === "verify" && rest.length === 1) {
    const [path] = rest;
    verifyReport(jsonFile(path));
    process.stdout.write(`verified benchmark report: ${path}\n`);
    return;
  }
  throw new Error(
    "usage: benchmark-report.mjs create RAW_DIR FIXTURE_DIR OUTPUT | verify REPORT",
  );
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(resolve(process.argv[1])).href
) {
  try {
    main(process.argv.slice(2));
  } catch (error) {
    process.stderr.write(`${error.stack ?? error}\n`);
    process.exitCode = 1;
  }
}
