import assert from "node:assert/strict";
import test from "node:test";
import {
  FRAMEWORK_BUILD_GRAPH_CONTRACT_VERSION,
  frameworkBuildCondition,
  frameworkBuildCoverage,
  frameworkBuildEvidence,
  frameworkBuildGeneratedNode,
  frameworkBuildProtocolEvents,
  frameworkBuildRelation,
  frameworkBuildUnresolvedTarget,
  validateFrameworkBuildDelta,
  type FrameworkBuildDescriptor,
  type FrameworkBuildProvenance,
} from "../src/framework-build-contract";
import type { GraphNode } from "../src/types";

const descriptor: FrameworkBuildDescriptor = {
  framework: "tanstack-router",
  observer: "tanstack-router-build-observer",
  observerVersion: "0.1.0",
  capability: "tanstack-router-generated-route-v1",
};

const provenance: FrameworkBuildProvenance = {
  build_run_id: "build-run",
  profile_id: "profile:build",
  command_plan_digest: "a".repeat(64),
  toolchain_executable_digest: "b".repeat(64),
  environment_key_set_digest: "c".repeat(64),
  validated_output_digest: "d".repeat(64),
};

const source: GraphNode = {
  id: "route:safe",
  kind: "route",
  locator: "route://tanstack-router/safe",
  display_name: "/safe",
  properties: {
    framework: "tanstack-router",
    route_pattern: "/safe",
  },
};

function resolvedDelta(currentProvenance = provenance) {
  const evidence = frameworkBuildEvidence(
    descriptor,
    currentProvenance,
    "dist/route-manifest.json",
    "e".repeat(64),
  );
  const target = frameworkBuildGeneratedNode(
    descriptor,
    "file",
    {
      framework: "tanstack-router",
      artifact_kind: "route-chunk",
      logical_path: "dist/routes/safe.js",
      artifact_digest: "f".repeat(64),
      profile_id: currentProvenance.profile_id,
    },
    "dist/routes/safe.js",
    {
      framework: "tanstack-router",
      artifact_kind: "route-chunk",
      logical_path: "dist/routes/safe.js",
      artifact_digest: "f".repeat(64),
      profile_id: currentProvenance.profile_id,
    },
    currentProvenance,
    "dist/routes/safe.js",
    "f".repeat(64),
  );
  const relation = frameworkBuildRelation(
    descriptor,
    source.id,
    target.id,
    "emits",
    "dist/routes/safe.js",
    "browser",
    frameworkBuildCondition("browser", { "tanstack.router.route": "/safe" }),
    evidence,
    currentProvenance.profile_id,
  );
  return {
    nodes: [source, target],
    sites: [relation.site],
    edges: [relation.edge],
    diagnostics: [],
  };
}

test("framework build v1 validates stable observed graph identity and protocol coverage", () => {
  const delta = resolvedDelta();
  validateFrameworkBuildDelta(delta, descriptor, provenance, [source]);

  const repeatProvenance = { ...provenance, build_run_id: "repeat-build-run" };
  const repeat = resolvedDelta(repeatProvenance);
  assert.equal(repeat.nodes[1]?.id, delta.nodes[1]?.id);
  assert.equal(repeat.sites[0]?.id, delta.sites[0]?.id);
  assert.equal(repeat.edges[0]?.id, delta.edges[0]?.id);

  const events = frameworkBuildProtocolEvents(
    ".",
    delta,
    provenance,
    "revision",
    descriptor,
    { toolchain: "vite 7.0.0", command: "vite build" },
  );
  const profile = events.find((event) => event.event === "profile_declared") as Record<string, unknown>;
  const value = profile.profile as Record<string, unknown>;
  assert.ok((value.features as string[]).includes(FRAMEWORK_BUILD_GRAPH_CONTRACT_VERSION));
  assert.equal(
    (value.properties as Record<string, unknown>).framework_build_graph_contract_version,
    FRAMEWORK_BUILD_GRAPH_CONTRACT_VERSION,
  );
  const completed = events.at(-1) as Record<string, unknown>;
  assert.deepEqual((completed.coverage as Record<string, unknown>).completeness, ["build-observed"]);
});

test("unmatched dynamic targets remain unresolved and never become exact edges", () => {
  const evidence = frameworkBuildEvidence(
    descriptor,
    provenance,
    "dist/route-manifest.json",
    "e".repeat(64),
  );
  const unresolved = frameworkBuildUnresolvedTarget(
    descriptor,
    provenance,
    "dynamic_imports",
    source.id,
    "virtual:computed-route",
    "browser",
    frameworkBuildCondition("browser"),
    evidence,
    "framework_build_dynamic_target_unmatched",
  );
  const delta = {
    nodes: [source, unresolved.node],
    sites: [unresolved.site],
    edges: [unresolved.edge],
    diagnostics: [],
  };
  validateFrameworkBuildDelta(delta, descriptor, provenance, [source]);
  assert.equal(unresolved.node.kind, "unknown_target");
  assert.equal(unresolved.site.resolution_status, "unresolved");
  assert.equal(unresolved.edge.resolution_status, "unresolved");
  assert.equal(unresolved.edge.precision, "observed");
  assert.deepEqual(frameworkBuildCoverage(delta.sites), {
    profiles: 1,
    files_discovered: 0,
    files_analyzed: 0,
    files_skipped: 0,
    dependency_sites: 1,
    resolved: 0,
    candidates: 0,
    external: 0,
    unresolved: 1,
    unsupported_syntax: 0,
    project_code_executed: true,
    completeness: ["build-observed"],
    reasons: ["framework_build_dynamic_target_unmatched"],
  });

  const fabricated = {
    ...delta,
    sites: [{ ...unresolved.site, resolution_status: "resolved" as const, reason: null }],
    edges: [{ ...unresolved.edge, resolution_status: "resolved" as const }],
  };
  assert.throws(
    () => validateFrameworkBuildDelta(fabricated, descriptor, provenance, [source]),
    /fabricates its resolution status/u,
  );
});

test("base conflicts and partial or unsupported build completion fail closed", () => {
  const delta = resolvedDelta();
  const conflicting = {
    ...delta,
    nodes: [{ ...source, display_name: "mutated" }, ...delta.nodes.slice(1)],
  };
  assert.throws(
    () => validateFrameworkBuildDelta(conflicting, descriptor, provenance, [source]),
    /conflicts with base node/u,
  );

  assert.deepEqual(
    frameworkBuildCoverage([], { status: "partial", reason: "framework_build_manifest_missing" }),
    {
      profiles: 1,
      files_discovered: 0,
      files_analyzed: 0,
      files_skipped: 0,
      dependency_sites: 0,
      resolved: 0,
      candidates: 0,
      external: 0,
      unresolved: 0,
      unsupported_syntax: 0,
      project_code_executed: true,
      completeness: [],
      reasons: ["framework_build_manifest_missing"],
    },
  );
  assert.throws(
    () => frameworkBuildCoverage([], { status: "unsupported", reason: null }),
    /requires a bounded reason/u,
  );
});
