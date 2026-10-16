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

const implementationSymbol: GraphNode = {
  id: "symbol:products-page",
  kind: "symbol",
  locator: "typescript-symbol:products-page",
  display_name: "ProductsPage",
  properties: { source_path: "app/products/page.tsx" },
};
const declarationFile: GraphNode = {
  id: "file:products-page", kind: "file", locator: "file://app/products/page.tsx",
  display_name: "app/products/page.tsx", properties: { path: "app/products/page.tsx" },
};
const componentSpan = { start_line: 2, start_column: 1, end_line: 4, end_column: 2 };

function baseNodes(...extra: GraphNode[]): Map<string, GraphNode> {
  return new Map([implementationSymbol, declarationFile, ...extra].map((node) => [node.id, node]));
}

function implementationEvidence(occurrenceKind: string, span = componentSpan, path = "app/products/page.tsx"): Evidence[] {
  const common = {
    extractor: "next-static-adapter", extractor_version: "0.1.0", path, ...span,
  };
  const shared = { profile_id: profileId, framework: "next", occurrence_kind: occurrenceKind };
  return [
    { kind: "semantic", ...common, properties: { ...shared, contract_version: WEB_FRAMEWORK_SEMANTIC_CAPABILITY } },
    { kind: "source", ...common, properties: shared },
  ];
}

function codeLinkInput(
  kind: "implemented_by" | "declared_in",
  source: GraphNode,
  target: GraphNode,
  overrides: Partial<FrameworkSemanticRelationInput> = {},
): FrameworkSemanticRelationInput {
  return {
    source,
    targets: [target],
    kind,
    specifier: target.kind === "file" ? String(source.properties.source_path) : target.display_name,
    relativePath: "app/products/page.tsx",
    span: componentSpan,
    condition: {
      op: "all",
      conditions: [
        { op: "eq", key: "mode", value: "production" },
        { op: "eq", key: "environment", value: "server" },
      ],
    },
    environment: "server",
    profileId,
    resolutionStatus: "resolved",
    precision: null,
    reason: null,
    evidence: implementationEvidence(kind === "implemented_by" ? "next_component_implementation" : "next_component_declaration"),
    generated: false,
    ...overrides,
  };
}

function implementationInput(
  source: GraphNode,
  target: GraphNode,
  overrides: Partial<FrameworkSemanticRelationInput> = {},
): FrameworkSemanticRelationInput {
  return codeLinkInput("implemented_by", source, target, overrides);
}

function declarationInput(
  source: GraphNode,
  target: GraphNode,
  overrides: Partial<FrameworkSemanticRelationInput> = {},
): FrameworkSemanticRelationInput {
  return codeLinkInput("declared_in", source, target, overrides);
}

function withRelations(
  delta: FrameworkSemanticDelta,
  ...inputs: Array<(component: GraphNode) => FrameworkSemanticRelationInput>
): FrameworkSemanticDelta {
  const component = delta.nodes.find((node) => node.kind === "component")!;
  const sites = new Map<string, DependencySite>();
  const edges = new Map<string, GraphEdge>();
  for (const input of inputs) emitFrameworkSemanticRelation({ sites, edges }, input(component), relationContext);
  return {
    nodes: delta.nodes,
    sites: [...delta.sites, ...sites.values()],
    edges: [...delta.edges, ...edges.values()],
  };
}

/** Adds the given implemented_by relation plus the component's declared_in relation. */
function withImplementation(
  delta: FrameworkSemanticDelta,
  input: (component: GraphNode) => FrameworkSemanticRelationInput = (component) => implementationInput(component, implementationSymbol),
): FrameworkSemanticDelta {
  return withRelations(delta, input, (component) => declarationInput(component, declarationFile));
}

function fixture(): FrameworkSemanticDelta {
  return withImplementation(fixtureWithoutImplementation());
}

function fixtureWithoutImplementation(): FrameworkSemanticDelta {
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
      source_path: "app/products/page.tsx", source_span: componentSpan,
      typescript_definition_id: implementationSymbol.id,
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
  const baseNodesValue = baseNodes(syntaxNode);
  const baseSites = new Map<string, DependencySite>();
  const baseEdges = new Map<string, GraphEdge>();
  const merged = mergeFrameworkSemanticDelta(baseNodesValue, baseSites, baseEdges, fixture(), {
    profileId,
    capability: WEB_FRAMEWORK_SEMANTIC_CAPABILITY,
  });
  assert.equal(baseNodesValue.size, 3);
  assert.equal(baseSites.size, 0);
  assert.equal(baseEdges.size, 0);
  assert.equal(merged.nodes.size, 5);
  assert.equal(merged.sites.size, 3);
  assert.equal(merged.edges.size, 3);
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
    baseNodes(resource),
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
  const baseNodesValue = baseNodes(syntaxNode);
  const baseSites = new Map<string, DependencySite>();
  const baseEdges = new Map<string, GraphEdge>();
  assert.throws(() => mergeFrameworkSemanticDelta(baseNodesValue, baseSites, baseEdges, fixture(), {
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
  assert.throws(() => mergeFrameworkSemanticDelta(baseNodesValue, baseSites, baseEdges, invalid, {
    profileId,
    capability: WEB_FRAMEWORK_SEMANTIC_CAPABILITY,
  }), /incompatible target/u);
  assert.deepEqual([...baseNodesValue.keys()], [implementationSymbol.id, declarationFile.id, syntaxNode.id]);
  assert.equal(baseSites.size, 0);
  assert.equal(baseEdges.size, 0);
});

test("late provenance failure preserves syntax and earlier TypeScript semantic maps", () => {
  const typescriptNode: GraphNode = {
    id: "symbol:typescript", kind: "symbol", locator: "typescript-symbol:test", display_name: "test", properties: {},
  };
  const baseNodesValue = baseNodes(typescriptNode);
  const baseSites = new Map<string, DependencySite>();
  const baseEdges = new Map<string, GraphEdge>();
  const invalid = fixture();
  invalid.edges[0]!.evidence[0]!.extractor_version = "0.2.0";
  assert.throws(() => mergeFrameworkSemanticDelta(baseNodesValue, baseSites, baseEdges, invalid, {
    profileId,
    capability: WEB_FRAMEWORK_SEMANTIC_CAPABILITY,
  }), /evidence does not match its site|unapproved framework extractor/u);
  assert.deepEqual([...baseNodesValue.keys()], [implementationSymbol.id, declarationFile.id, typescriptNode.id]);
  assert.equal(baseSites.size, 0);
  assert.equal(baseEdges.size, 0);
});

function mergeWith(delta: FrameworkSemanticDelta, nodes = baseNodes()): ReturnType<typeof mergeFrameworkSemanticDelta> {
  return mergeFrameworkSemanticDelta(nodes, new Map(), new Map(), delta, {
    profileId,
    capability: WEB_FRAMEWORK_SEMANTIC_CAPABILITY,
  });
}

const otherSpan = { start_line: 9, start_column: 1, end_line: 9, end_column: 2 };

test("implemented_by links each component to its TypeScript definition symbol", () => {
  const merged = mergeWith(fixture());
  const implementations = [...merged.edges.values()].filter((edge) => edge.kind === "implemented_by");
  assert.equal(implementations.length, 1);
  assert.equal(implementations[0]?.target, implementationSymbol.id);
  assert.equal(implementations[0]?.resolution_status, "resolved");
  assert.equal(implementations[0]?.precision, "exact");
});

test("declared_in links each component to its declaring file under a distinct site identity", () => {
  const merged = mergeWith(fixture());
  const declarations = [...merged.edges.values()].filter((edge) => edge.kind === "declared_in");
  assert.equal(declarations.length, 1);
  assert.equal(declarations[0]?.target, declarationFile.id);
  assert.equal(declarations[0]?.resolution_status, "resolved");
  assert.equal(declarations[0]?.precision, "exact");
  const site = merged.sites.get(declarations[0]!.site_id!)!;
  assert.equal(site.specifier, "app/products/page.tsx");
  assert.equal(site.evidence[0]?.properties?.occurrence_kind, "next_component_declaration");
  const implementation = [...merged.sites.values()].find((candidate) => candidate.kind === "implemented_by")!;
  assert.notEqual(site.id, implementation.id);
  assert.deepEqual(site.evidence.map((item) => item.start_line), implementation.evidence.map((item) => item.start_line));
});

test("implemented_by is required exactly once for every component with a definition", () => {
  assert.throws(() => mergeWith(fixtureWithoutImplementation()), /exactly one (implemented_by|declared_in)/u);
  const missingImplementation = withRelations(
    fixtureWithoutImplementation(),
    (component) => declarationInput(component, declarationFile),
  );
  assert.throws(() => mergeWith(missingImplementation), /exactly one implemented_by/u);
  const duplicated = withImplementation(fixture(), (component) => implementationInput(component, implementationSymbol, {
    span: otherSpan,
    evidence: implementationEvidence("next_component_implementation", otherSpan),
  }));
  assert.throws(() => mergeWith(duplicated), /implemented_by|declared_in/u);
});

test("declared_in is required exactly once for every component and server function", () => {
  const missingDeclaration = withRelations(
    fixtureWithoutImplementation(),
    (component) => implementationInput(component, implementationSymbol),
  );
  assert.throws(() => mergeWith(missingDeclaration), /exactly one declared_in/u);
  const duplicated = withRelations(fixture(), (component) => declarationInput(component, declarationFile, {
    span: otherSpan,
    evidence: implementationEvidence("next_component_declaration", otherSpan),
  }));
  assert.throws(() => mergeWith(duplicated), /declared_in/u);
});

test("implemented_by rejects targets other than the declared definition", () => {
  const other: GraphNode = { ...implementationSymbol, id: "symbol:other", display_name: "Other" };
  assert.throws(
    () => mergeWith(withImplementation(fixtureWithoutImplementation(), (component) => implementationInput(component, other)), baseNodes(other)),
    /implemented_by/u,
  );
  assert.throws(
    () => mergeWith(withImplementation(fixtureWithoutImplementation(), (component) => implementationInput(component, declarationFile, {
      evidence: implementationEvidence("next_component_implementation"),
    }))),
    /implemented_by|incompatible target/u,
  );
});

test("declared_in rejects targets other than the declaring file", () => {
  const otherFile: GraphNode = {
    ...declarationFile, id: "file:other", locator: "file://app/other.tsx", display_name: "app/other.tsx",
    properties: { path: "app/other.tsx" },
  };
  const declarationTo = (target: GraphNode, overrides: Partial<FrameworkSemanticRelationInput> = {}) => withRelations(
    fixtureWithoutImplementation(),
    (component) => implementationInput(component, implementationSymbol),
    (component) => declarationInput(component, target, overrides),
  );
  assert.throws(() => mergeWith(declarationTo(otherFile), baseNodes(otherFile)), /declared_in/u);
  assert.throws(() => mergeWith(declarationTo(implementationSymbol, {
    evidence: implementationEvidence("next_component_declaration"),
  })), /declared_in|incompatible target/u);
});

test("implemented_by and declared_in cannot use candidates or a mismatched occurrence kind or specifier", () => {
  assert.throws(() => mergeWith(withImplementation(fixtureWithoutImplementation(), (component) => implementationInput(component, implementationSymbol, {
    resolutionStatus: "candidates",
    evidence: implementationEvidence("next_component_implementation").map((item) => ({
      ...item, properties: { ...item.properties, algorithm: "fixture" },
    })),
  }))), /cannot use candidates|implemented_by/u);
  assert.throws(() => mergeWith(withImplementation(fixtureWithoutImplementation(), (component) => implementationInput(component, implementationSymbol, {
    evidence: implementationEvidence("astro_component_implementation"),
  }))), /occurrence_kind/u);
  assert.throws(() => mergeWith(withImplementation(fixtureWithoutImplementation(), (component) => implementationInput(component, implementationSymbol, {
    specifier: "Other",
  }))), /specifier/u);

  const declarationWith = (overrides: Partial<FrameworkSemanticRelationInput>) => withRelations(
    fixtureWithoutImplementation(),
    (component) => implementationInput(component, implementationSymbol),
    (component) => declarationInput(component, declarationFile, overrides),
  );
  assert.throws(() => mergeWith(declarationWith({
    resolutionStatus: "candidates",
    evidence: implementationEvidence("next_component_declaration").map((item) => ({
      ...item, properties: { ...item.properties, algorithm: "fixture" },
    })),
  })), /cannot use candidates|declared_in/u);
  assert.throws(() => mergeWith(declarationWith({
    evidence: implementationEvidence("next_component_implementation"),
  })), /occurrence_kind/u);
  assert.throws(() => mergeWith(declarationWith({ specifier: "page.tsx" })), /specifier/u);
  assert.throws(() => mergeWith(declarationWith({
    span: otherSpan,
    evidence: implementationEvidence("next_component_declaration", otherSpan),
  })), /anchored/u);
});

test("a source without a definition has declared_in and no implemented_by", () => {
  const delta = fixtureWithoutImplementation();
  const component = delta.nodes.find((node) => node.kind === "component")!;
  const identity = { ...(component.properties.canonical_identity as Record<string, string>), framework: "astro" };
  const astroComponent: GraphNode = {
    ...component,
    id: stableId("component", identity),
    properties: {
      ...component.properties, framework: "astro", canonical_identity: identity,
      typescript_definition_id: null,
    },
  };
  const astroDelta: FrameworkSemanticDelta = { nodes: [astroComponent], sites: [], edges: [] };
  const astroEvidence = (occurrenceKind: string): Evidence[] => implementationEvidence(occurrenceKind).map((item) => ({
    ...item,
    extractor: "astro-static-adapter",
    properties: { ...item.properties, framework: "astro" },
  }));
  const declaration = (source: GraphNode) => declarationInput(source, declarationFile, {
    evidence: astroEvidence("astro_component_declaration"),
  });
  const merged = mergeWith(withRelations(astroDelta, declaration));
  assert.deepEqual([...merged.edges.values()].map((edge) => [edge.kind, edge.target]), [["declared_in", declarationFile.id]]);
  assert.throws(() => mergeWith(withRelations(astroDelta, declaration, (source) => implementationInput(source, declarationFile, {
    evidence: astroEvidence("astro_component_implementation"),
  }))), /implemented_by|incompatible target/u);
  assert.throws(() => mergeWith(withRelations(astroDelta, declaration, (source) => implementationInput(source, implementationSymbol, {
    evidence: astroEvidence("astro_component_implementation"),
  }))), /implemented_by/u);
});
