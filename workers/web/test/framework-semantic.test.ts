import assert from "node:assert/strict";
import test from "node:test";
import {
  mergeFrameworkSemanticDelta,
  WEB_FRAMEWORK_SEMANTIC_CAPABILITY,
  WEB_FRAMEWORK_SEMANTIC_PROFILE_PROPERTIES,
  type FrameworkSemanticDelta,
} from "../src/framework-semantic";
import { stableId } from "../src/ids";
import { canonicalizeCondition, type DependencySite, type Evidence, type GraphEdge, type GraphNode } from "../src/types";

const profileId = "profile:framework-test";
const packageLocator = "npm:workspace:web-app@1.0.0#.";

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
  });
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
