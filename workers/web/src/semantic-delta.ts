import path from "node:path";
import { stableId } from "./ids";
import { compareUtf8, type GraphEdge, type GraphNode, type JsonValue } from "./types";

const DEFINITION_RELATIONS = new Set(["declares", "extends", "implements", "instantiates"]);
const SEMANTIC_NODE_KINDS = new Set(["symbol", "type"]);
const MAX_RESOLVER_IDENTITY_CHARS = 4_096;
const MAX_TYPE_DESCRIPTOR_CHARS = 2_048;

export interface TypeScriptDefinitionDelta {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface TypeScriptDefinitionDeltaOptions {
  profileId: string;
  compilerVersion: string;
}

function objectValue(value: JsonValue | undefined, field: string): Record<string, JsonValue> {
  if (value === null || value === undefined || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${field} must be an object`);
  }
  return value;
}

function stringValue(value: JsonValue | undefined, field: string): string {
  if (typeof value !== "string" || value.length === 0) throw new Error(`${field} must be a non-empty string`);
  return value;
}

function resolverValue(value: JsonValue | undefined, field: string): string {
  const resolver = stringValue(value, field);
  if (resolver.length > MAX_RESOLVER_IDENTITY_CHARS) throw new Error(`${field} exceeds its UTF-16 length limit`);
  return resolver;
}

function positiveInteger(value: JsonValue | undefined, field: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 1 || value > 0xffff_ffff) {
    throw new Error(`${field} must be a positive u32 integer`);
  }
  return value;
}

function validateRelativePath(value: string, field: string): void {
  const portable = value.replaceAll("\\", "/");
  if (
    portable !== value
    || portable.length === 0
    || path.posix.isAbsolute(portable)
    || /^[A-Za-z]:/u.test(portable)
    || portable.includes("\0")
    || portable.split("/").some((part) => part === "" || part === "." || part === "..")
  ) throw new Error(`${field} must be a canonical repository-relative path`);
}

function validateIdentitySpan(value: JsonValue | undefined, field: string): void {
  const span = objectValue(value, field);
  const start = [
    positiveInteger(span.start_line, `${field}.start_line`),
    positiveInteger(span.start_column, `${field}.start_column`),
  ] as const;
  const end = [
    positiveInteger(span.end_line, `${field}.end_line`),
    positiveInteger(span.end_column, `${field}.end_column`),
  ] as const;
  if (end[0] < start[0] || (end[0] === start[0] && end[1] < start[1])) {
    throw new Error(`${field} end precedes its start`);
  }
}

function validateSemanticNode(node: GraphNode, options: TypeScriptDefinitionDeltaOptions): void {
  if (!SEMANTIC_NODE_KINDS.has(node.kind)) throw new Error(`definition delta contains non-semantic node ${node.id}`);
  const language = stringValue(node.properties.language, `${node.id}.properties.language`);
  if (language !== "typescript" && language !== "javascript") {
    throw new Error(`${node.id} has unsupported Web semantic language ${language}`);
  }
  if (stringValue(node.properties.profile_id, `${node.id}.properties.profile_id`) !== options.profileId) {
    throw new Error(`${node.id} belongs to a different profile`);
  }
  if (node.properties.exported !== undefined && node.properties.exported !== true) {
    throw new Error(`${node.id}.properties.exported must be true when present`);
  }
  const packageLocator = stringValue(node.properties.package_locator, `${node.id}.properties.package_locator`);
  const kindProperty = node.kind === "symbol" ? "symbol_kind" : "type_kind";
  const semanticKind = stringValue(node.properties[kindProperty], `${node.id}.properties.${kindProperty}`);
  const identity = objectValue(node.properties.canonical_identity, `${node.id}.properties.canonical_identity`);
  if (
    stringValue(identity.language, `${node.id}.canonical_identity.language`) !== language
    || stringValue(identity.package_locator, `${node.id}.canonical_identity.package_locator`) !== packageLocator
    || stringValue(identity[kindProperty], `${node.id}.canonical_identity.${kindProperty}`) !== semanticKind
  ) throw new Error(`${node.id} canonical identity disagrees with its semantic properties`);

  if (node.kind === "type") {
    const resolver = resolverValue(identity.resolver_identity, `${node.id}.canonical_identity.resolver_identity`);
    if (node.properties.resolver_identity !== resolver) throw new Error(`${node.id} resolver identity properties disagree`);
    if (semanticKind === "generic_instance") {
      resolverValue(identity.generic_origin, `${node.id}.canonical_identity.generic_origin`);
      if (!Array.isArray(identity.type_arguments) || identity.type_arguments.length === 0) {
        throw new Error(`${node.id} generic type arguments must be a non-empty array`);
      }
      for (const argument of identity.type_arguments) {
        if (JSON.stringify(argument).length > MAX_TYPE_DESCRIPTOR_CHARS) {
          throw new Error(`${node.id} generic type argument exceeds its UTF-16 length limit`);
        }
      }
    }
  } else {
    const identityKind = stringValue(identity.identity_kind, `${node.id}.canonical_identity.identity_kind`);
    if (identityKind === "named") {
      const resolver = resolverValue(identity.resolver_identity, `${node.id}.canonical_identity.resolver_identity`);
      if (node.properties.resolver_identity !== resolver) throw new Error(`${node.id} resolver identity properties disagree`);
    } else if (identityKind === "local" || identityKind === "anonymous" || identityKind === "generated") {
      const origin = identityKind === "local" ? identity.enclosing_symbol : identity.generated_from;
      stringValue(origin, `${node.id}.canonical_identity.${identityKind === "local" ? "enclosing_symbol" : "generated_from"}`);
      const relativePath = stringValue(identity.relative_path, `${node.id}.canonical_identity.relative_path`);
      validateRelativePath(relativePath, `${node.id}.canonical_identity.relative_path`);
      validateIdentitySpan(identity.span, `${node.id}.canonical_identity.span`);
    } else {
      throw new Error(`${node.id} has unsupported identity_kind ${identityKind}`);
    }
  }

  const expected = stableId(node.kind, identity);
  if (node.id !== expected) throw new Error(`${node.id} does not match canonical identity ${expected}`);
}

function validateSemanticEdge(
  edge: GraphEdge,
  nodes: ReadonlyMap<string, GraphNode>,
  options: TypeScriptDefinitionDeltaOptions,
): void {
  if (!DEFINITION_RELATIONS.has(edge.kind)) throw new Error(`definition delta contains unsupported relation ${edge.kind}`);
  if (edge.phase !== "semantic" || edge.site_id !== null) throw new Error(`${edge.id} must be a site-less semantic relation`);
  if (edge.resolution_status !== "resolved" || edge.precision !== "exact") {
    throw new Error(`${edge.id} must be resolved/exact`);
  }
  if (edge.profile_id !== options.profileId) throw new Error(`${edge.id} belongs to a different profile`);
  if (edge.environment !== "any") throw new Error(`${edge.id} must use environment=any`);
  const source = nodes.get(edge.source);
  const target = nodes.get(edge.target);
  if (!source || !target) throw new Error(`${edge.id} references a missing endpoint`);
  if (!SEMANTIC_NODE_KINDS.has(target.kind)) throw new Error(`${edge.id} target must be a repository semantic node`);
  if (edge.kind === "declares") {
    if (!SEMANTIC_NODE_KINDS.has(target.kind)) throw new Error(`${edge.id} declares target must be semantic`);
  } else if (edge.kind === "extends" || edge.kind === "implements") {
    if (source.kind !== "type" || target.kind !== "type") throw new Error(`${edge.id} must connect type nodes`);
  } else if (!SEMANTIC_NODE_KINDS.has(source.kind)) {
    throw new Error(`${edge.id} instantiates source must be a semantic node`);
  }
  const primary = edge.evidence[0];
  if (!primary || primary.kind !== "semantic" || primary.extractor !== "typescript-native-typechecker") {
    throw new Error(`${edge.id} lacks primary TypeChecker semantic evidence`);
  }
  if (primary.extractor_version !== options.compilerVersion) throw new Error(`${edge.id} has an unexpected compiler version`);
  if (primary.properties?.profile_id !== edge.profile_id) throw new Error(`${edge.id} semantic evidence belongs to a different profile`);
  validateRelativePath(primary.path, `${edge.id}.evidence.path`);
  if (edge.kind === "declares") {
    if (target.properties.source_path !== primary.path) throw new Error(`${edge.id} target does not anchor its declaration evidence`);
    const sourcePath = source.kind === "file" ? source.properties.path : source.properties.source_path;
    if (sourcePath !== primary.path) throw new Error(`${edge.id} owner does not anchor its declaration evidence`);
  } else if (source.properties.source_path !== primary.path) {
    throw new Error(`${edge.id} source does not anchor its relation evidence`);
  }
  const span = {
    start_line: primary.start_line,
    start_column: primary.start_column,
    end_line: primary.end_line,
    end_column: primary.end_column,
  };
  validateIdentitySpan(span, `${edge.id}.evidence.span`);
  const expected = stableId("edge", {
    condition: edge.condition,
    kind: edge.kind,
    profile_id: edge.profile_id,
    source: edge.source,
    target: edge.target,
    path: primary.path,
    span,
  });
  if (edge.id !== expected) throw new Error(`${edge.id} does not match definition relation identity ${expected}`);
}

/**
 * Validate a complete TypeScript definition delta against a cloned base graph.
 * The caller swaps these maps into the live builder only after this function
 * returns, so any late conflict or contract failure leaves syntax output intact.
 */
export function mergeTypeScriptDefinitionDelta(
  baseNodes: ReadonlyMap<string, GraphNode>,
  baseEdges: ReadonlyMap<string, GraphEdge>,
  delta: TypeScriptDefinitionDelta,
  options: TypeScriptDefinitionDeltaOptions,
): { nodes: Map<string, GraphNode>; edges: Map<string, GraphEdge> } {
  const nodes = new Map(baseNodes);
  const edges = new Map(baseEdges);
  const deltaNodeIds = new Set<string>();
  const deltaResolvers = new Map<string, string>();
  for (const node of [...delta.nodes].sort((left, right) => compareUtf8(left.id, right.id))) {
    if (deltaNodeIds.has(node.id)) throw new Error(`definition delta repeats node ${node.id}`);
    deltaNodeIds.add(node.id);
    validateSemanticNode(node, options);
    const resolver = node.properties.resolver_identity;
    if (typeof resolver === "string") {
      const existingResolver = deltaResolvers.get(resolver);
      if (existingResolver !== undefined && existingResolver !== node.id) {
        throw new Error("definition delta repeats a canonical resolver");
      }
      deltaResolvers.set(resolver, node.id);
    }
    const existing = nodes.get(node.id);
    if (existing && JSON.stringify(existing) !== JSON.stringify(node)) throw new Error(`semantic delta conflicts with node ${node.id}`);
    nodes.set(node.id, existing ?? node);
  }
  const deltaEdgeIds = new Set<string>();
  for (const edge of [...delta.edges].sort((left, right) => compareUtf8(left.id, right.id))) {
    if (deltaEdgeIds.has(edge.id)) throw new Error(`definition delta repeats edge ${edge.id}`);
    deltaEdgeIds.add(edge.id);
    const existing = edges.get(edge.id);
    if (existing && JSON.stringify(existing) !== JSON.stringify(edge)) throw new Error(`semantic delta conflicts with edge ${edge.id}`);
    edges.set(edge.id, existing ?? edge);
  }
  for (const edge of delta.edges) validateSemanticEdge(edge, nodes, options);

  for (const node of delta.nodes.filter((candidate) => candidate.kind === "symbol")) {
    const identity = objectValue(node.properties.canonical_identity, `${node.id}.properties.canonical_identity`);
    const identityKind = stringValue(identity.identity_kind, `${node.id}.canonical_identity.identity_kind`);
    if (identityKind === "named") continue;
    const originField = identityKind === "local" ? "enclosing_symbol" : "generated_from";
    const originId = stringValue(identity[originField], `${node.id}.canonical_identity.${originField}`);
    const origin = nodes.get(originId);
    if (!origin) throw new Error(`${node.id} references missing canonical origin ${originId}`);
    if (identityKind === "local" && origin.kind !== "symbol") {
      throw new Error(`${node.id} local enclosing_symbol must reference a symbol node`);
    }
  }

  const declared = new Set(delta.edges.filter((edge) => edge.kind === "declares").map((edge) => edge.target));
  const instantiated = new Set(delta.edges.filter((edge) => edge.kind === "instantiates").map((edge) => edge.target));
  for (const node of delta.nodes) {
    const semanticKind = node.kind === "symbol" ? node.properties.symbol_kind : node.properties.type_kind;
    const instance = semanticKind === "generic_instance" || semanticKind === "function_instance";
    if (instance ? !instantiated.has(node.id) : !declared.has(node.id)) {
      throw new Error(`${node.id} has no canonical ${instance ? "instantiates" : "declares"} owner relation`);
    }
  }
  return { nodes, edges };
}
