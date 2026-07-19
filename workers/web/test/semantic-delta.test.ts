import assert from "node:assert/strict";
import { test } from "node:test";
import { stableId } from "../src/ids";
import { mergeTypeScriptDefinitionDelta, type TypeScriptDefinitionDelta } from "../src/semantic-delta";
import { PROFILE_ID, WEB_CONDITION, type GraphEdge, type GraphNode } from "../src/types";

const compilerVersion = "7.0.2";

function fixture(): { baseNode: GraphNode; semanticNode: GraphNode; edge: GraphEdge; delta: TypeScriptDefinitionDelta } {
  const baseNode: GraphNode = {
    id: "file:test",
    kind: "file",
    locator: "file://src/index.ts",
    display_name: "src/index.ts",
    properties: { language: "typescript", path: "src/index.ts" },
  };
  const identity = {
    language: "typescript",
    package_locator: "npm:fixture@1.0.0#.",
    symbol_kind: "function",
    identity_kind: "named",
    resolver_identity: "npm:fixture@1.0.0#.::src/index.ts#run",
  } as const;
  const semanticNode: GraphNode = {
    id: stableId("symbol", identity),
    kind: "symbol",
    locator: "typescript-symbol:npm:fixture@1.0.0#.::src/index.ts#run",
    display_name: "run",
    properties: {
      language: "typescript",
      package_locator: "npm:fixture@1.0.0#.",
      symbol_kind: "function",
      resolver_identity: identity.resolver_identity,
      canonical_identity: identity,
      profile_id: PROFILE_ID,
      source_path: "src/index.ts",
    },
  };
  const evidence = {
    kind: "semantic" as const,
    extractor: "typescript-native-typechecker",
    extractor_version: compilerVersion,
    path: "src/index.ts",
    start_line: 1,
    start_column: 17,
    end_line: 1,
    end_column: 20,
    properties: { backend: "typescript-native-compiler", profile_id: PROFILE_ID },
  };
  const span = {
    start_line: evidence.start_line,
    start_column: evidence.start_column,
    end_line: evidence.end_line,
    end_column: evidence.end_column,
  };
  const edge: GraphEdge = {
    id: stableId("edge", {
      condition: WEB_CONDITION,
      kind: "declares",
      profile_id: PROFILE_ID,
      source: baseNode.id,
      target: semanticNode.id,
      path: evidence.path,
      span,
    }),
    source: baseNode.id,
    target: semanticNode.id,
    kind: "declares",
    site_id: null,
    phase: "semantic",
    environment: "any",
    profile_id: PROFILE_ID,
    condition: WEB_CONDITION,
    resolution_status: "resolved",
    precision: "exact",
    generated: false,
    evidence: [evidence],
  };
  return { baseNode, semanticNode, edge, delta: { nodes: [semanticNode], edges: [edge] } };
}

test("validated TypeScript definition delta is merged into cloned maps", () => {
  const { baseNode, semanticNode, edge, delta } = fixture();
  const baseNodes = new Map([[baseNode.id, baseNode]]);
  const baseEdges = new Map<string, GraphEdge>();
  const merged = mergeTypeScriptDefinitionDelta(baseNodes, baseEdges, delta, { profileId: PROFILE_ID, compilerVersion });
  assert.equal(merged.nodes.get(semanticNode.id), semanticNode);
  assert.equal(merged.edges.get(edge.id), edge);
  assert.deepEqual([...baseNodes], [[baseNode.id, baseNode]]);
  assert.equal(baseEdges.size, 0);
});

test("late definition relation validation failure leaves the syntax maps untouched", () => {
  const { baseNode, edge, delta } = fixture();
  const baseNodes = new Map([[baseNode.id, baseNode]]);
  const baseEdges = new Map<string, GraphEdge>();
  const invalid = {
    nodes: delta.nodes,
    edges: [{ ...edge, id: "edge:sha256:invalid-late-hash" }],
  };
  assert.throws(
    () => mergeTypeScriptDefinitionDelta(baseNodes, baseEdges, invalid, { profileId: PROFILE_ID, compilerVersion }),
    /does not match definition relation identity/u,
  );
  assert.deepEqual([...baseNodes], [[baseNode.id, baseNode]]);
  assert.equal(baseEdges.size, 0);
});

test("duplicate semantic node and relation IDs are rejected without mutating syntax maps", () => {
  const { baseNode, semanticNode, edge, delta } = fixture();
  const baseNodes = new Map([[baseNode.id, baseNode]]);
  const baseEdges = new Map<string, GraphEdge>();
  assert.throws(
    () => mergeTypeScriptDefinitionDelta(
      baseNodes,
      baseEdges,
      { nodes: [semanticNode, semanticNode], edges: delta.edges },
      { profileId: PROFILE_ID, compilerVersion },
    ),
    /repeats node/u,
  );
  assert.throws(
    () => mergeTypeScriptDefinitionDelta(
      baseNodes,
      baseEdges,
      { nodes: delta.nodes, edges: [edge, edge] },
      { profileId: PROFILE_ID, compilerVersion },
    ),
    /repeats edge/u,
  );
  assert.deepEqual([...baseNodes], [[baseNode.id, baseNode]]);
  assert.equal(baseEdges.size, 0);
});

test("final resolver and expanded generic descriptor UTF-16 limits fail atomically", () => {
  const { baseNode, semanticNode } = fixture();
  const baseNodes = new Map([[baseNode.id, baseNode]]);
  const longResolver = "r".repeat(4_097);
  const namedIdentity = {
    ...(semanticNode.properties.canonical_identity as Record<string, string>),
    resolver_identity: longResolver,
  };
  const oversizedNamed: GraphNode = {
    ...semanticNode,
    properties: {
      ...semanticNode.properties,
      resolver_identity: longResolver,
      canonical_identity: namedIdentity,
    },
  };
  assert.throws(
    () => mergeTypeScriptDefinitionDelta(
      baseNodes,
      new Map(),
      { nodes: [oversizedNamed], edges: [] },
      { profileId: PROFILE_ID, compilerVersion },
    ),
    /UTF-16 length limit/u,
  );

  const genericIdentity = {
    language: "typescript",
    package_locator: "npm:fixture@1.0.0#.",
    type_kind: "generic_instance",
    resolver_identity: "generic:fixture",
    generic_origin: "definition:fixture",
    type_arguments: [{ kind: "literal", value_kind: "string", value: "x".repeat(2_048) }],
  };
  const oversizedGeneric: GraphNode = {
    id: stableId("type", genericIdentity),
    kind: "type",
    locator: "typescript-type:oversized",
    display_name: "Oversized<string>",
    properties: {
      language: "typescript",
      package_locator: "npm:fixture@1.0.0#.",
      type_kind: "generic_instance",
      resolver_identity: "generic:fixture",
      canonical_identity: genericIdentity,
      profile_id: PROFILE_ID,
      source_path: "src/index.ts",
    },
  };
  assert.throws(
    () => mergeTypeScriptDefinitionDelta(
      baseNodes,
      new Map(),
      { nodes: [oversizedGeneric], edges: [] },
      { profileId: PROFILE_ID, compilerVersion },
    ),
    /generic type argument exceeds/u,
  );
  assert.deepEqual([...baseNodes], [[baseNode.id, baseNode]]);
});

test("TypeScript and JavaScript definition relations can share one semantic graph", () => {
  const packageLocator = "npm:fixture@1.0.0#.";
  const typeNode = (language: "typescript" | "javascript", name: string, sourcePath: string): GraphNode => {
    const identity = {
      language,
      package_locator: packageLocator,
      type_kind: "class",
      resolver_identity: `${packageLocator}::module:${sourcePath}#${name}`,
    };
    return {
      id: stableId("type", identity),
      kind: "type",
      locator: `${language}-type:${name}`,
      display_name: name,
      properties: {
        language,
        package_locator: packageLocator,
        type_kind: "class",
        resolver_identity: identity.resolver_identity,
        canonical_identity: identity,
        profile_id: PROFILE_ID,
        source_path: sourcePath,
      },
    };
  };
  const child = typeNode("typescript", "Child", "src/child.ts");
  const base = typeNode("javascript", "Base", "src/base.js");
  const childFile = {
    ...fixture().baseNode,
    id: "file:child",
    locator: "file://src/child.ts",
    display_name: "src/child.ts",
    properties: { language: "typescript", path: "src/child.ts" },
  };
  const baseFile = {
    ...fixture().baseNode,
    id: "file:base",
    locator: "file://src/base.js",
    display_name: "src/base.js",
    properties: { language: "javascript", path: "src/base.js" },
  };
  const relation = (source: GraphNode, target: GraphNode, kind: "declares" | "extends", sourcePath: string): GraphEdge => {
    const evidence = {
      kind: "semantic" as const,
      extractor: "typescript-native-typechecker",
      extractor_version: compilerVersion,
      path: sourcePath,
      start_line: 1,
      start_column: 1,
      end_line: 1,
      end_column: 6,
      properties: { profile_id: PROFILE_ID },
    };
    const span = {
      start_line: evidence.start_line,
      start_column: evidence.start_column,
      end_line: evidence.end_line,
      end_column: evidence.end_column,
    };
    return {
      id: stableId("edge", {
        condition: WEB_CONDITION,
        kind,
        profile_id: PROFILE_ID,
        source: source.id,
        target: target.id,
        path: sourcePath,
        span,
      }),
      source: source.id,
      target: target.id,
      kind,
      site_id: null,
      phase: "semantic",
      environment: "any",
      profile_id: PROFILE_ID,
      condition: WEB_CONDITION,
      resolution_status: "resolved",
      precision: "exact",
      generated: false,
      evidence: [evidence],
    };
  };
  const delta = {
    nodes: [child, base],
    edges: [
      relation(childFile, child, "declares", "src/child.ts"),
      relation(baseFile, base, "declares", "src/base.js"),
      relation(child, base, "extends", "src/child.ts"),
    ],
  };

  const merged = mergeTypeScriptDefinitionDelta(
    new Map([[childFile.id, childFile], [baseFile.id, baseFile]]),
    new Map(),
    delta,
    { profileId: PROFILE_ID, compilerVersion },
  );
  assert.ok([...merged.edges.values()].some((edge) => edge.kind === "extends"));
});
