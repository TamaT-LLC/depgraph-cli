import { canonicalJson, stableId } from "./ids";
import {
  canonicalizeCondition,
  compareUtf8,
  type Condition,
  type DependencySite,
  type Evidence,
  type GraphEdge,
  type GraphNode,
  type FrameworkCompletenessEntry,
  type FrameworkSemanticSummary,
  type JsonValue,
  type Precision,
  type ResolutionStatus,
} from "./types";

export const WEB_FRAMEWORK_SEMANTIC_CAPABILITY = "framework-semantic-graph-v1" as const;
export const WEB_FRAMEWORK_SEMANTIC_EXTRACTOR_VERSION = "0.1.0" as const;
export const WEB_FRAMEWORK_COMPLETENESS_CAPABILITY = "framework-semantic-completeness-v1" as const;
export const TYPESCRIPT_SEMANTIC_CAPABILITY = "typescript-definition-import-type-call-graph-v2" as const;
export const WEB_SEMANTIC_RELEASE_CAPABILITIES = Object.freeze([
  "astro-component-render-hydration-v1",
  WEB_FRAMEWORK_COMPLETENESS_CAPABILITY,
  WEB_FRAMEWORK_SEMANTIC_CAPABILITY,
  "next-route-component-boundary-v1",
  "tanstack-router-typed-route-v1",
  "tanstack-start-rpc-middleware-v1",
  TYPESCRIPT_SEMANTIC_CAPABILITY,
  "worker-delta-v1",
] as const);
const REQUIRED_CAPABILITY_BY_FRAMEWORK = new Map([
  ["next", "next-route-component-boundary-v1"],
  ["astro", "astro-component-render-hydration-v1"],
  ["tanstack-router", "tanstack-router-typed-route-v1"],
  ["tanstack-start", "tanstack-start-rpc-middleware-v1"],
] as const);
export const WEB_FRAMEWORK_SEMANTIC_PROFILE_PROPERTIES = Object.freeze({
  web_framework_semantic_capability: WEB_FRAMEWORK_SEMANTIC_CAPABILITY,
  web_framework_semantic_status: "not-emitted",
  web_framework_semantic_extractor_version: WEB_FRAMEWORK_SEMANTIC_EXTRACTOR_VERSION,
  web_framework_semantic_node_count: "0",
  web_framework_semantic_site_count: "0",
  web_framework_semantic_edge_count: "0",
  web_framework_completeness_capability: WEB_FRAMEWORK_COMPLETENESS_CAPABILITY,
  web_framework_completeness_status: "not-detected",
  web_framework_completeness_issue_count: "0",
  web_framework_completeness_ledger: "[]",
} as const);

export function buildFrameworkCompleteness(
  detectedFrameworks: readonly string[],
  emittedFrameworks: ReadonlySet<string>,
  issues: ReadonlyMap<string, ReadonlySet<string>>,
  typeScriptPrerequisiteReady: boolean,
): Pick<FrameworkSemanticSummary, "completionStatus" | "completionIssueCount" | "completionLedger"> {
  const completionLedger: FrameworkCompletenessEntry[] = [...new Set(detectedFrameworks)]
    .sort(compareUtf8)
    .map((framework) => {
      const specificCapability = REQUIRED_CAPABILITY_BY_FRAMEWORK.get(framework as never);
      if (!specificCapability) throw new Error(`unsupported framework completeness contract ${framework}`);
      const requiredCapabilities = [
        TYPESCRIPT_SEMANTIC_CAPABILITY,
        WEB_FRAMEWORK_SEMANTIC_CAPABILITY,
        specificCapability,
      ].sort(compareUtf8);
      const emittedCapabilities = [
        ...(typeScriptPrerequisiteReady ? [TYPESCRIPT_SEMANTIC_CAPABILITY] : []),
        ...(emittedFrameworks.has(framework) ? [WEB_FRAMEWORK_SEMANTIC_CAPABILITY, specificCapability] : []),
      ].sort(compareUtf8);
      const reasons = new Set(issues.get(framework) ?? []);
      if (!typeScriptPrerequisiteReady) reasons.add("typescript_semantic_prerequisite_incomplete");
      if (!emittedFrameworks.has(framework)) reasons.add("framework_semantic_graph_not_emitted");
      const sortedReasons = [...reasons].sort(compareUtf8);
      return {
        framework,
        required_capabilities: requiredCapabilities,
        emitted_capabilities: emittedCapabilities,
        status: sortedReasons.length === 0
          && JSON.stringify(requiredCapabilities) === JSON.stringify(emittedCapabilities)
          ? "complete" as const
          : "incomplete" as const,
        reasons: sortedReasons,
      };
    });
  const completionIssueCount = completionLedger.reduce((sum, entry) => sum + entry.reasons.length, 0);
  return {
    completionStatus: completionLedger.length === 0
      ? "not-detected"
      : completionLedger.every((entry) => entry.status === "complete") ? "complete" : "incomplete",
    completionIssueCount,
    completionLedger,
  };
}

export function frameworkSemanticProfileProperties(
  summary: FrameworkSemanticSummary,
): Record<string, string> {
  return {
    web_framework_semantic_capability: WEB_FRAMEWORK_SEMANTIC_CAPABILITY,
    web_framework_semantic_status: summary.status,
    web_framework_semantic_extractor_version: WEB_FRAMEWORK_SEMANTIC_EXTRACTOR_VERSION,
    web_framework_semantic_node_count: String(summary.nodes),
    web_framework_semantic_site_count: String(summary.sites),
    web_framework_semantic_edge_count: String(summary.edges),
    web_framework_completeness_capability: WEB_FRAMEWORK_COMPLETENESS_CAPABILITY,
    web_framework_completeness_status: summary.completionStatus,
    web_framework_completeness_issue_count: String(summary.completionIssueCount),
    web_framework_completeness_ledger: JSON.stringify(summary.completionLedger),
  };
}

const FRAMEWORK_NODE_KINDS = new Set(["component", "route", "server_function", "middleware"]);
const FRAMEWORK_SITE_KINDS = new Set([
  "renders", "hydrates", "client_boundary", "server_boundary",
  "route_entry", "parent_route", "loads", "before_load",
  "navigates_to", "masks_to", "rpc_call", "client_stub_for",
  "handled_by", "uses_middleware",
]);
const CANDIDATE_SITE_KINDS = new Set([
  "renders", "parent_route", "loads", "before_load", "navigates_to",
  "masks_to", "rpc_call", "handled_by", "uses_middleware",
]);
const EXTRACTOR_BY_FRAMEWORK = new Map([
  ["next", "next-static-adapter"],
  ["astro", "astro-static-adapter"],
  ["tanstack-router", "tanstack-router-static-adapter"],
  ["tanstack-start", "tanstack-start-static-adapter"],
] as const);

export interface FrameworkSemanticDelta {
  nodes: GraphNode[];
  sites: DependencySite[];
  edges: GraphEdge[];
}

export interface FrameworkSemanticDeltaOptions {
  profileId: string;
  capability: string;
}

export interface FrameworkSemanticRelationStore {
  readonly sites: Map<string, DependencySite>;
  readonly edges: Map<string, GraphEdge>;
}

export interface FrameworkSemanticRelationContext {
  readonly conflictSubject: string;
  readonly emptyTargetSubject: string;
}

export interface FrameworkSemanticRelationInput {
  readonly source: Readonly<Pick<GraphNode, "id">>;
  readonly targets: readonly Readonly<Pick<GraphNode, "id">>[];
  readonly kind: string;
  readonly specifier: string;
  readonly relativePath: string;
  readonly span: {
    readonly start_line: number;
    readonly start_column: number;
    readonly end_line: number;
    readonly end_column: number;
  };
  readonly condition: Condition;
  readonly environment: string;
  readonly profileId: string;
  readonly resolutionStatus: ResolutionStatus;
  readonly precision: Precision | null;
  readonly reason: string | null;
  readonly evidence: readonly Evidence[];
  readonly generated: boolean;
}

function defaultPrecision(status: ResolutionStatus): Precision {
  return status === "candidates" ? "overapprox"
    : status === "unresolved" ? "heuristic"
      : "exact";
}

/** Emit one complete site and its target edges after checking every identity conflict. */
export function emitFrameworkSemanticRelation(
  store: FrameworkSemanticRelationStore,
  input: FrameworkSemanticRelationInput,
  context: FrameworkSemanticRelationContext,
): void {
  const targetIds = [...new Set(input.targets.map((target) => target.id))].sort(compareUtf8);
  if (targetIds.length === 0) throw new Error(`${context.emptyTargetSubject} ${input.kind} has no target`);

  const condition = canonicalizeCondition(input.condition);
  const precision = input.precision ?? defaultPrecision(input.resolutionStatus);
  const evidence = [...input.evidence];
  const siteId = stableId("site", {
    condition,
    kind: input.kind,
    path: input.relativePath,
    profile_id: input.profileId,
    source: input.source.id,
    span: input.span,
  });
  const site: DependencySite = {
    id: siteId,
    source: input.source.id,
    kind: input.kind,
    specifier: input.specifier,
    resolution_status: input.resolutionStatus,
    target_ids: targetIds,
    profile_id: input.profileId,
    condition,
    precision,
    reason: input.reason,
    evidence,
  };
  const relationEdges: GraphEdge[] = targetIds.map((target) => ({
    id: stableId("edge", { kind: input.kind, site_id: site.id, target }),
    source: input.source.id,
    target,
    kind: input.kind,
    site_id: site.id,
    phase: "semantic",
    environment: input.environment,
    profile_id: input.profileId,
    condition,
    resolution_status: input.resolutionStatus,
    precision,
    generated: input.generated,
    evidence,
  }));

  const existingSite = store.sites.get(site.id);
  if (existingSite !== undefined && JSON.stringify(existingSite) !== JSON.stringify(site)) {
    throw new Error(`${context.conflictSubject} produced conflicting site ${site.id}`);
  }
  for (const edge of relationEdges) {
    const existingEdge = store.edges.get(edge.id);
    if (existingEdge !== undefined && JSON.stringify(existingEdge) !== JSON.stringify(edge)) {
      throw new Error(`${context.conflictSubject} produced conflicting edge ${edge.id}`);
    }
  }

  store.sites.set(site.id, existingSite ?? site);
  for (const edge of relationEdges) store.edges.set(edge.id, store.edges.get(edge.id) ?? edge);
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

function validateFrameworkNode(node: GraphNode, options: FrameworkSemanticDeltaOptions): void {
  if (!FRAMEWORK_NODE_KINDS.has(node.kind)) throw new Error(`framework delta contains non-framework node ${node.id}`);
  if (stringValue(node.properties.profile_id, `${node.id}.properties.profile_id`) !== options.profileId) {
    throw new Error(`${node.id} belongs to a different profile`);
  }
  const framework = stringValue(node.properties.framework, `${node.id}.properties.framework`);
  if (!EXTRACTOR_BY_FRAMEWORK.has(framework as never)) throw new Error(`${node.id} has unsupported framework ${framework}`);
  const packageLocator = stringValue(node.properties.package_locator, `${node.id}.properties.package_locator`);
  const environment = stringValue(node.properties.environment, `${node.id}.properties.environment`);
  const kindProperty = node.kind === "component" ? "component_kind"
    : node.kind === "route" ? "route_kind"
      : node.kind === "server_function" ? "server_function_kind"
        : "middleware_kind";
  const semanticKind = stringValue(node.properties[kindProperty], `${node.id}.properties.${kindProperty}`);
  const identity = objectValue(node.properties.canonical_identity, `${node.id}.properties.canonical_identity`);
  for (const [field, expected] of [
    ["framework", framework],
    ["package_locator", packageLocator],
    ["environment", environment],
    [kindProperty, semanticKind],
  ] as const) {
    if (stringValue(identity[field], `${node.id}.canonical_identity.${field}`) !== expected) {
      throw new Error(`${node.id} canonical identity disagrees on ${field}`);
    }
  }
  if (node.kind === "route") {
    stringValue(identity.router_instance, `${node.id}.canonical_identity.router_instance`);
    const pattern = stringValue(identity.route_pattern, `${node.id}.canonical_identity.route_pattern`);
    if (!pattern.startsWith("/")) throw new Error(`${node.id} route_pattern must start with /`);
  } else {
    stringValue(identity.resolver_identity, `${node.id}.canonical_identity.resolver_identity`);
    if (node.kind === "middleware") stringValue(identity.scope, `${node.id}.canonical_identity.scope`);
  }
  const expectedId = stableId(node.kind, identity);
  if (node.id !== expectedId) throw new Error(`${node.id} does not match canonical identity ${expectedId}`);
}

function sameAnchor(left: Evidence, right: Evidence): boolean {
  return left.extractor === right.extractor
    && left.extractor_version === right.extractor_version
    && left.path === right.path
    && left.start_line === right.start_line
    && left.start_column === right.start_column
    && left.end_line === right.end_line
    && left.end_column === right.end_column;
}

function validateEvidence(evidence: Evidence[], profileId: string, owner: string): Evidence {
  const primary = evidence[0];
  if (!primary || primary.kind !== "semantic") throw new Error(`${owner} lacks primary semantic evidence`);
  for (const [field, value] of [
    ["path", primary.path],
    ["extractor", primary.extractor],
    ["extractor_version", primary.extractor_version],
  ] as const) stringValue(value, `${owner}.evidence.${field}`);
  for (const [field, value] of [
    ["start_line", primary.start_line], ["start_column", primary.start_column],
    ["end_line", primary.end_line], ["end_column", primary.end_column],
  ] as const) {
    if (!Number.isSafeInteger(value) || value < 1) throw new Error(`${owner}.evidence.${field} must be positive`);
  }
  const properties = primary.properties ?? {};
  const framework = stringValue(properties.framework, `${owner}.evidence.properties.framework`);
  const extractor = EXTRACTOR_BY_FRAMEWORK.get(framework as never);
  if (!extractor || primary.extractor !== extractor || primary.extractor_version !== WEB_FRAMEWORK_SEMANTIC_EXTRACTOR_VERSION) {
    throw new Error(`${owner} has an unapproved framework extractor or version`);
  }
  if (properties.profile_id !== profileId || properties.contract_version !== WEB_FRAMEWORK_SEMANTIC_CAPABILITY) {
    throw new Error(`${owner} semantic evidence has a mismatched profile or contract version`);
  }
  const occurrenceKind = stringValue(properties.occurrence_kind, `${owner}.evidence.properties.occurrence_kind`);
  const support = evidence.slice(1).some((candidate) => candidate.kind === "source"
    && sameAnchor(primary, candidate)
    && candidate.properties?.profile_id === profileId
    && candidate.properties?.framework === framework
    && candidate.properties?.occurrence_kind === occurrenceKind);
  if (!support) throw new Error(`${owner} lacks matching source supporting evidence`);
  const supportingKeys = evidence.slice(1).map((item) => canonicalJson(item as unknown as JsonValue));
  if (supportingKeys.some((value, index) => index > 0 && compareUtf8(supportingKeys[index - 1]!, value) > 0)) {
    throw new Error(`${owner} supporting evidence is not canonically sorted`);
  }
  return primary;
}

function conditionAllowsEnvironment(condition: Condition, environment: string): boolean {
  if (condition.op === "eq" && condition.key === "environment") return condition.value === environment;
  if (condition.op === "in" && condition.key === "environment") return condition.values.includes(environment);
  if (condition.op === "all" || condition.op === "any") {
    return condition.conditions.some((child) => conditionAllowsEnvironment(child, environment));
  }
  return false;
}

function validateResolution(site: DependencySite): void {
  const valid = site.resolution_status === "resolved" ? site.precision === "exact" && site.target_ids.length === 1
    : site.resolution_status === "candidates" ? site.precision === "overapprox" && site.target_ids.length > 0
      : site.resolution_status === "external" ? (site.precision === "exact" || site.precision === "heuristic") && site.target_ids.length === 1
        : site.precision === "heuristic" && site.target_ids.length === 1 && typeof site.reason === "string" && site.reason.length > 0;
  if (!valid) throw new Error(`${site.id} has an invalid resolution, precision, target, or reason shape`);
  if (site.resolution_status === "candidates" && !CANDIDATE_SITE_KINDS.has(site.kind)) {
    throw new Error(`${site.id} kind ${site.kind} cannot use candidates`);
  }
}

function validSourceKind(kind: string, source: GraphNode): boolean {
  if (kind === "renders") return source.kind === "component" || source.kind === "route";
  if (["hydrates", "client_boundary", "server_boundary"].includes(kind)) return source.kind === "component";
  if (kind === "route_entry") return ["file", "symbol", "component", "server_function"].includes(source.kind);
  if (kind === "loads") return source.kind === "component" || source.kind === "route";
  if (["parent_route", "before_load"].includes(kind)) return source.kind === "route";
  if (["navigates_to", "masks_to", "rpc_call"].includes(kind)) return ["component", "route", "symbol"].includes(source.kind);
  if (kind === "client_stub_for") return source.kind === "symbol";
  if (kind === "handled_by" || kind === "uses_middleware") return source.kind === "route" || source.kind === "server_function";
  return false;
}

function validTargetKind(kind: string, target: GraphNode): boolean {
  if (["renders", "hydrates", "client_boundary", "server_boundary"].includes(kind)) return target.kind === "component";
  if (["route_entry", "parent_route", "navigates_to", "masks_to"].includes(kind)) return target.kind === "route";
  if (kind === "loads") return target.kind === "file" || target.kind === "symbol" || target.kind === "server_function";
  if (kind === "before_load") return target.kind === "symbol" || target.kind === "server_function";
  if (kind === "rpc_call" || kind === "client_stub_for") return target.kind === "server_function";
  if (kind === "handled_by") return target.kind === "symbol";
  if (kind === "uses_middleware") return target.kind === "middleware";
  return false;
}

function validateSite(site: DependencySite, nodes: ReadonlyMap<string, GraphNode>, options: FrameworkSemanticDeltaOptions): void {
  if (!FRAMEWORK_SITE_KINDS.has(site.kind)) throw new Error(`framework delta contains unsupported site ${site.kind}`);
  if (site.profile_id !== options.profileId) throw new Error(`${site.id} belongs to a different profile`);
  if (site.specifier.length === 0) throw new Error(`${site.id} must include a specifier`);
  if (site.target_ids.some((id, index) => index > 0 && compareUtf8(site.target_ids[index - 1]!, id) >= 0)) {
    throw new Error(`${site.id} target IDs must be unique and sorted`);
  }
  validateResolution(site);
  const primary = validateEvidence(site.evidence, options.profileId, site.id);
  if (site.resolution_status === "candidates" && typeof primary.properties?.algorithm !== "string") {
    throw new Error(`${site.id} candidate evidence must include an algorithm`);
  }
  const source = nodes.get(site.source);
  if (!source || !validSourceKind(site.kind, source)) throw new Error(`${site.id} has an incompatible source`);
  for (const targetId of site.target_ids) {
    const target = nodes.get(targetId);
    if (!target) throw new Error(`${site.id} references missing target ${targetId}`);
    if (site.resolution_status === "external" ? target.kind !== "external_system"
      : site.resolution_status === "unresolved" ? target.kind !== "unknown_target"
        : !validTargetKind(site.kind, target)) throw new Error(`${site.id} has an incompatible target ${targetId}`);
  }
  const expectedId = stableId("site", {
    condition: canonicalizeCondition(site.condition), kind: site.kind, path: primary.path,
    profile_id: site.profile_id, source: site.source,
    span: { start_line: primary.start_line, start_column: primary.start_column, end_line: primary.end_line, end_column: primary.end_column },
  });
  if (site.id !== expectedId) throw new Error(`${site.id} does not match site identity ${expectedId}`);
}

function validateEdge(edge: GraphEdge, site: DependencySite, nodes: ReadonlyMap<string, GraphNode>, options: FrameworkSemanticDeltaOptions): void {
  if (!FRAMEWORK_SITE_KINDS.has(edge.kind) || edge.kind !== site.kind) throw new Error(`${edge.id} kind does not match its framework site`);
  if (edge.phase !== "semantic" || edge.site_id !== site.id || edge.profile_id !== options.profileId) throw new Error(`${edge.id} is not a profile-scoped semantic site edge`);
  if (edge.source !== site.source || !site.target_ids.includes(edge.target)) throw new Error(`${edge.id} endpoints do not match its site`);
  if (edge.resolution_status !== site.resolution_status || edge.precision !== site.precision) throw new Error(`${edge.id} resolution does not match its site`);
  if (JSON.stringify(canonicalizeCondition(edge.condition)) !== JSON.stringify(canonicalizeCondition(site.condition))) throw new Error(`${edge.id} condition does not match its site`);
  if (edge.environment === "any" || !conditionAllowsEnvironment(edge.condition, edge.environment)) throw new Error(`${edge.id} environment is not allowed by its condition`);
  if (JSON.stringify(edge.evidence) !== JSON.stringify(site.evidence)) throw new Error(`${edge.id} evidence does not match its site`);
  validateEvidence(edge.evidence, options.profileId, edge.id);
  for (const endpointId of [edge.source, edge.target]) {
    const endpoint = nodes.get(endpointId)!;
    if (FRAMEWORK_NODE_KINDS.has(endpoint.kind)
      && (endpoint.properties.profile_id !== options.profileId || endpoint.properties.framework !== edge.evidence[0]!.properties?.framework)) {
      throw new Error(`${edge.id} crosses framework or profile boundaries`);
    }
  }
  const expectedId = stableId("edge", { kind: edge.kind, site_id: site.id, target: edge.target });
  if (edge.id !== expectedId) throw new Error(`${edge.id} does not match edge identity ${expectedId}`);
}

/** Validate a complete framework semantic delta before swapping cloned maps into the live graph. */
export function mergeFrameworkSemanticDelta(
  baseNodes: ReadonlyMap<string, GraphNode>,
  baseSites: ReadonlyMap<string, DependencySite>,
  baseEdges: ReadonlyMap<string, GraphEdge>,
  delta: FrameworkSemanticDelta,
  options: FrameworkSemanticDeltaOptions,
): { nodes: Map<string, GraphNode>; sites: Map<string, DependencySite>; edges: Map<string, GraphEdge> } {
  if (options.capability !== WEB_FRAMEWORK_SEMANTIC_CAPABILITY) throw new Error(`unapproved framework semantic capability ${options.capability}`);
  const nodes = new Map(baseNodes);
  const sites = new Map(baseSites);
  const edges = new Map(baseEdges);
  const deltaNodeIds = new Set<string>();
  for (const node of [...delta.nodes].sort((left, right) => compareUtf8(left.id, right.id))) {
    if (deltaNodeIds.has(node.id)) throw new Error(`framework delta repeats node ${node.id}`);
    deltaNodeIds.add(node.id);
    validateFrameworkNode(node, options);
    const existing = nodes.get(node.id);
    if (existing && JSON.stringify(existing) !== JSON.stringify(node)) throw new Error(`framework delta conflicts with node ${node.id}`);
    nodes.set(node.id, existing ?? node);
  }
  for (const site of [...delta.sites].sort((left, right) => compareUtf8(left.id, right.id))) {
    if (sites.has(site.id)) throw new Error(`framework delta repeats or conflicts with site ${site.id}`);
    validateSite(site, nodes, options);
    sites.set(site.id, site);
  }
  for (const edge of [...delta.edges].sort((left, right) => compareUtf8(left.id, right.id))) {
    if (edges.has(edge.id)) throw new Error(`framework delta repeats or conflicts with edge ${edge.id}`);
    const site = sites.get(edge.site_id ?? "");
    if (!site || !delta.sites.some((candidate) => candidate.id === site.id)) throw new Error(`${edge.id} references a non-delta framework site`);
    validateEdge(edge, site, nodes, options);
    edges.set(edge.id, edge);
  }
  for (const site of delta.sites) {
    const linked = delta.edges.filter((edge) => edge.site_id === site.id);
    if (linked.length !== site.target_ids.length || new Set(linked.map((edge) => edge.target)).size !== site.target_ids.length) {
      throw new Error(`${site.id} target set does not match its edge closure`);
    }
  }
  return { nodes, sites, edges };
}
