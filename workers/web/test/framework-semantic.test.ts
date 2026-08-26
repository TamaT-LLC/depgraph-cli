import assert from "node:assert/strict";
import test from "node:test";
import {
  buildFrameworkCompleteness,
  emitFrameworkSemanticRelation,
  mergeFrameworkSemanticDelta,
  WEB_FRAMEWORK_SEMANTIC_CAPABILITY,
  WEB_FRAMEWORK_SEMANTIC_PROFILE_PROPERTIES,
  type FrameworkSemanticDelta,
  type FrameworkSemanticRelationInput,
} from "../src/framework-semantic";
import { stableId } from "../src/ids";
import { canonicalizeCondition, type DependencySite, type Evidence, type GraphEdge, type GraphNode } from "../src/types";

const profileId = "profile:framework-test";
const packageLocator = "npm:workspace:web-app@1.0.0#.";

function relationInput(): FrameworkSemanticRelationInput {
  const evidence: Evidence[] = [{
    kind: "semantic",
    extractor: "fixture-static-adapter",
    extractor_version: "0.1.0",
    path: "src/fixture.tsx",
    start_line: 3,
    start_column: 5,
    end_line: 3,
    end_column: 12,
  }];
  return {
    source: { id: "component:source" },
    targets: [{ id: "route:z" }, { id: "route:a" }, { id: "route:z" }],
    kind: "renders",
    specifier: "./fixture",
    relativePath: "src/fixture.tsx",
    span: { start_line: 3, start_column: 5, end_line: 3, end_column: 12 },
    condition: {
      op: "all",
      conditions: [
        { op: "eq", key: "mode", value: "production" },
        { op: "eq", key: "environment", value: "server" },
        { op: "eq", key: "mode", value: "production" },
      ],
    },
    environment: "server",
    profileId,
    resolutionStatus: "candidates",
    precision: null,
    reason: "fixture_candidates",
    evidence,
    generated: true,
  };
}

const relationContext = {
  conflictSubject: "Fixture semantic collector",
  emptyTargetSubject: "Fixture semantic relation",
};

function fixture(): FrameworkSemanticDelta {
  const componentIdentity = {
    framework: "next",
    package_locator: packageLocator,
    component_kind: "page",
    environment: "server",
    resolver_identity: `${packageLocator}::app/products/page.tsx#default`,
  };
  const routeIdentity = {
    framework: "next",
    package_locator: packageLocator,
    route_kind: "page",
    environment: "server",
    router_instance: "next-app:app",
    route_pattern: "/products",
  };
  const componentId = stableId("component", componentIdentity);
  const routeId = stableId("route", routeIdentity);
  const component: GraphNode = {
    id: componentId,
    kind: "component",
    locator: `framework-component:${componentId}`,
    display_name: "ProductsPage",
    properties: {
      framework: "next", package_locator: packageLocator, component_kind: "page",
      environment: "server", profile_id: profileId, canonical_identity: componentIdentity,
    },
  };
  const route: GraphNode = {
    id: routeId,
    kind: "route",
    locator: `framework-route:${routeId}`,
    display_name: "/products",
    properties: {
      framework: "next", package_locator: packageLocator, route_kind: "page",
      environment: "server", profile_id: profileId, canonical_identity: routeIdentity,
    },
  };
  const condition = canonicalizeCondition({
    op: "all",
    conditions: [
      { op: "eq", key: "mode", value: "production" },
      { op: "eq", key: "environment", value: "server" },
    ],
  });
  const properties = {
    profile_id: profileId,
    framework: "next",
    contract_version: WEB_FRAMEWORK_SEMANTIC_CAPABILITY,
    occurrence_kind: "page_route_entry",
  };
  const sourceProperties = {
    profile_id: profileId,
    framework: "next",
    occurrence_kind: "page_route_entry",
  };
  const primary: Evidence = {
    kind: "semantic", extractor: "next-static-adapter", extractor_version: "0.1.0",
    path: "app/products/page.tsx", start_line: 1, start_column: 1, end_line: 1, end_column: 32,
    properties,
  };
  const supporting: Evidence = { ...primary, kind: "source", properties: sourceProperties };
  const siteId = stableId("site", {
    condition, kind: "route_entry", path: primary.path, profile_id: profileId, source: componentId,
    span: { start_line: 1, start_column: 1, end_line: 1, end_column: 32 },
  });
  const site: DependencySite = {
    id: siteId, source: componentId, kind: "route_entry", specifier: "/products",
    resolution_status: "resolved", target_ids: [routeId], profile_id: profileId,
    condition, precision: "exact", reason: null, evidence: [primary, supporting],
  };
  const edge: GraphEdge = {
    id: stableId("edge", { kind: "route_entry", site_id: siteId, target: routeId }),
    source: componentId, target: routeId, kind: "route_entry", site_id: siteId,
    phase: "semantic", environment: "server", profile_id: profileId, condition,
    resolution_status: "resolved", precision: "exact", generated: false,
    evidence: [primary, supporting],
  };
  return { nodes: [component, route], sites: [site], edges: [edge] };
}

test("framework semantic capability is versioned and starts without an emitted delta", () => {
  assert.deepEqual(WEB_FRAMEWORK_SEMANTIC_PROFILE_PROPERTIES, {
    web_framework_semantic_capability: "framework-semantic-graph-v1",
    web_framework_semantic_status: "not-emitted",
    web_framework_semantic_extractor_version: "0.1.0",
    web_framework_semantic_node_count: "0",
    web_framework_semantic_site_count: "0",
    web_framework_semantic_edge_count: "0",
    web_framework_completeness_capability: "framework-semantic-completeness-v1",
    web_framework_completeness_status: "not-detected",
    web_framework_completeness_issue_count: "0",
    web_framework_completeness_ledger: "[]",
  });
});

test("shared framework relation emission owns canonical identity and target expansion", () => {
  const input = relationInput();
  const inputBytes = JSON.stringify(input);
  const sites = new Map<string, DependencySite>();
  const edges = new Map<string, GraphEdge>();

  emitFrameworkSemanticRelation({ sites, edges }, input, relationContext);

  assert.equal(JSON.stringify(input), inputBytes);
  assert.equal(sites.size, 1);
  assert.equal(edges.size, 2);
  const site = [...sites.values()][0]!;
  const expectedCondition = canonicalizeCondition(input.condition);
  const expectedSiteId = stableId("site", {
    condition: expectedCondition,
    kind: input.kind,
    path: input.relativePath,
    profile_id: profileId,
    source: input.source.id,
    span: input.span,
  });
  assert.equal(site.id, expectedSiteId);
  assert.deepEqual(site.target_ids, ["route:a", "route:z"]);
  assert.deepEqual(site.condition, expectedCondition);
  assert.equal(site.precision, "overapprox");
  assert.deepEqual([...edges.values()].map((edge) => edge.target), ["route:a", "route:z"]);
  for (const edge of edges.values()) {
    assert.equal(edge.id, stableId("edge", { kind: input.kind, site_id: expectedSiteId, target: edge.target }));
    assert.equal(edge.precision, "overapprox");
    assert.equal(edge.generated, true);
    assert.deepEqual(edge.evidence, site.evidence);
  }
});

test("shared framework relation emission reuses equivalent bytes and rejects conflicts atomically", () => {
  const input = relationInput();
  const sites = new Map<string, DependencySite>();
  const edges = new Map<string, GraphEdge>();
  emitFrameworkSemanticRelation({ sites, edges }, input, relationContext);
  const originalSite = [...sites.values()][0]!;
  const originalEdges = [...edges.values()];

  emitFrameworkSemanticRelation({ sites, edges }, input, relationContext);
  assert.strictEqual([...sites.values()][0], originalSite);
  assert.deepEqual([...edges.values()], originalEdges);
  for (const [index, edge] of [...edges.values()].entries()) assert.strictEqual(edge, originalEdges[index]);

  const beforeSiteConflict = JSON.stringify({ sites: [...sites], edges: [...edges] });
  assert.throws(() => emitFrameworkSemanticRelation(
    { sites, edges },
    { ...input, specifier: "./conflicting-fixture" },
    relationContext,
  ), /Fixture semantic collector produced conflicting site/u);
  assert.equal(JSON.stringify({ sites: [...sites], edges: [...edges] }), beforeSiteConflict);

  const conflictingEdge = { ...originalEdges[0]!, environment: "browser" };
  const edgeConflictSites = new Map<string, DependencySite>();
  const edgeConflictEdges = new Map([[conflictingEdge.id, conflictingEdge]]);
  const beforeEdgeConflict = JSON.stringify([...edgeConflictEdges]);
  assert.throws(() => emitFrameworkSemanticRelation(
    { sites: edgeConflictSites, edges: edgeConflictEdges },
    input,
    relationContext,
  ), /Fixture semantic collector produced conflicting edge/u);
  assert.equal(edgeConflictSites.size, 0);
  assert.equal(JSON.stringify([...edgeConflictEdges]), beforeEdgeConflict);

  const emptySites = new Map<string, DependencySite>();
  const emptyEdges = new Map<string, GraphEdge>();
  assert.throws(() => emitFrameworkSemanticRelation(
    { sites: emptySites, edges: emptyEdges },
    { ...input, targets: [] },
    relationContext,
  ), /Fixture semantic relation renders has no target/u);
  assert.equal(emptySites.size, 0);
  assert.equal(emptyEdges.size, 0);
});

test("framework completeness requires only detected slices and preserves partial failures", () => {
  assert.deepEqual(buildFrameworkCompleteness([], new Set(), new Map(), true), {
    completionStatus: "not-detected",
    completionIssueCount: 0,
    completionLedger: [],
  });

  const mixed = buildFrameworkCompleteness(
    ["next", "astro"],
    new Set(["astro", "next"]),
    new Map([["next", new Set(["unresolved:next_dynamic_non_literal_import"])]]),
    true,
  );
  assert.equal(mixed.completionStatus, "incomplete");
  assert.equal(mixed.completionIssueCount, 1);
  assert.deepEqual(mixed.completionLedger.map((entry) => [entry.framework, entry.status]), [
    ["astro", "complete"],
    ["next", "incomplete"],
  ]);
  assert.deepEqual(mixed.completionLedger[0]?.reasons, []);
  assert.deepEqual(mixed.completionLedger[1]?.reasons, ["unresolved:next_dynamic_non_literal_import"]);

  const missingPrerequisite = buildFrameworkCompleteness(
    ["next"],
    new Set(["next"]),
    new Map(),
    false,
  );
  assert.deepEqual(missingPrerequisite.completionLedger[0]?.reasons, [
    "typescript_semantic_prerequisite_incomplete",
  ]);
});

test("validated framework semantic delta is merged into cloned syntax maps", () => {
  const syntaxNode: GraphNode = {
    id: "file:syntax", kind: "file", locator: "file://app.tsx", display_name: "app.tsx", properties: {},
  };
  const baseNodes = new Map([[syntaxNode.id, syntaxNode]]);
  const baseSites = new Map<string, DependencySite>();
  const baseEdges = new Map<string, GraphEdge>();
  const merged = mergeFrameworkSemanticDelta(baseNodes, baseSites, baseEdges, fixture(), {
    profileId,
    capability: WEB_FRAMEWORK_SEMANTIC_CAPABILITY,
  });
  assert.equal(baseNodes.size, 1);
  assert.equal(baseSites.size, 0);
  assert.equal(baseEdges.size, 0);
  assert.equal(merged.nodes.size, 3);
  assert.equal(merged.sites.size, 1);
  assert.equal(merged.edges.size, 1);
});

test("Astro resource loads accept component-to-file endpoints", () => {
  const resource: GraphNode = {
    id: "file:astro-resource",
    kind: "file",
    locator: "file://src/assets/hero.svg",
    display_name: "src/assets/hero.svg",
    properties: { path: "src/assets/hero.svg" },
  };
  const delta = fixture();
  const site = delta.sites[0]!;
  const edge = delta.edges[0]!;
  site.kind = "loads";
  site.specifier = "../assets/hero.svg";
  site.target_ids = [resource.id];
  site.id = stableId("site", {
    condition: site.condition,
    kind: site.kind,
    path: site.evidence[0]!.path,
    profile_id: profileId,
    source: site.source,
    span: { start_line: 1, start_column: 1, end_line: 1, end_column: 32 },
  });
  edge.kind = site.kind;
  edge.target = resource.id;
  edge.site_id = site.id;
  edge.id = stableId("edge", { kind: edge.kind, site_id: site.id, target: resource.id });

  const merged = mergeFrameworkSemanticDelta(
    new Map([[resource.id, resource]]),
    new Map(),
    new Map(),
    delta,
    { profileId, capability: WEB_FRAMEWORK_SEMANTIC_CAPABILITY },
  );
  assert.equal(merged.sites.get(site.id)?.target_ids[0], resource.id);
  assert.equal(merged.edges.get(edge.id)?.target, resource.id);
});

test("unapproved capability and invalid endpoints fail atomically", () => {
  const syntaxNode: GraphNode = {
    id: "file:syntax", kind: "file", locator: "file://app.tsx", display_name: "app.tsx", properties: {},
  };
  const baseNodes = new Map([[syntaxNode.id, syntaxNode]]);
  const baseSites = new Map<string, DependencySite>();
  const baseEdges = new Map<string, GraphEdge>();
  assert.throws(() => mergeFrameworkSemanticDelta(baseNodes, baseSites, baseEdges, fixture(), {
    profileId,
    capability: "framework-semantic-graph-v2",
  }), /unapproved framework semantic capability/u);

  const invalid = fixture();
  invalid.sites[0]!.target_ids = [invalid.nodes[0]!.id];
  invalid.edges[0]!.target = invalid.nodes[0]!.id;
  invalid.edges[0]!.id = stableId("edge", {
    kind: invalid.edges[0]!.kind,
    site_id: invalid.sites[0]!.id,
    target: invalid.nodes[0]!.id,
  });
  assert.throws(() => mergeFrameworkSemanticDelta(baseNodes, baseSites, baseEdges, invalid, {
    profileId,
    capability: WEB_FRAMEWORK_SEMANTIC_CAPABILITY,
  }), /incompatible target/u);
  assert.deepEqual([...baseNodes], [[syntaxNode.id, syntaxNode]]);
  assert.equal(baseSites.size, 0);
  assert.equal(baseEdges.size, 0);
});

test("late provenance failure preserves syntax and earlier TypeScript semantic maps", () => {
  const typescriptNode: GraphNode = {
    id: "symbol:typescript", kind: "symbol", locator: "typescript-symbol:test", display_name: "test", properties: {},
  };
  const baseNodes = new Map([[typescriptNode.id, typescriptNode]]);
  const baseSites = new Map<string, DependencySite>();
  const baseEdges = new Map<string, GraphEdge>();
  const invalid = fixture();
  invalid.edges[0]!.evidence[0]!.extractor_version = "0.2.0";
  assert.throws(() => mergeFrameworkSemanticDelta(baseNodes, baseSites, baseEdges, invalid, {
    profileId,
    capability: WEB_FRAMEWORK_SEMANTIC_CAPABILITY,
  }), /evidence does not match its site|unapproved framework extractor/u);
  assert.deepEqual([...baseNodes], [[typescriptNode.id, typescriptNode]]);
  assert.equal(baseSites.size, 0);
  assert.equal(baseEdges.size, 0);
});
