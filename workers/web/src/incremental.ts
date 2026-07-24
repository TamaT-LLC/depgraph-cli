import { isDeepStrictEqual } from "node:util";
import { canonicalJson, contentHash, stableId } from "./ids";
import {
  ADAPTER,
  ADAPTER_VERSION,
  PROFILE_ID,
  PROTOCOL_VERSION,
  canonicalizeCondition,
  compareUtf8,
  type Coverage,
  type DependencySite,
  type Evidence,
  type GraphEdge,
  type GraphNode,
  type JsonValue,
  type ScanModel,
} from "./types";
import { analysisContentHash } from "./source-fingerprint";

const DELTA_CONTRACT_VERSION = "worker-delta-v1" as const;
const DELTA_REQUEST_SCHEMA_VERSION = "worker-delta-request-v1" as const;

interface DeltaScope {
  paths: string[];
  package_locators: string[];
  profile_ids: string[];
  artifact_node_ids: string[];
  adapters: string[];
}

interface DeltaFileChange {
  kind: "added" | "modified" | "deleted" | "renamed";
  old_path?: string;
  new_path?: string;
}

type WireSite = Omit<DependencySite, "reason"> & { reason?: string };
type WireEdge = Omit<GraphEdge, "site_id" | "environment"> & {
  site_id?: string;
  environment?: string;
};

interface WireEvidence {
  [key: string]: JsonValue;
}

interface DeltaEvidenceRecord {
  owner_type: "node" | "site" | "edge";
  owner_id: string;
  ordinal: number;
  evidence: WireEvidence;
}

interface DeltaFileCoverage {
  discovered_sites: number;
  emitted_sites: number;
  skipped_sites: number;
  skipped: boolean;
  reason?: string;
}

type DeltaCoverage =
  | { scope: "aggregate"; value: Coverage }
  | { scope: "profile"; profile_id: string; value: Coverage }
  | { scope: "file"; adapter: string; path: string; value: DeltaFileCoverage };

interface WorkerDeltaBaseGraph {
  profiles: string[];
  nodes: GraphNode[];
  sites: WireSite[];
  edges: WireEdge[];
  evidence: DeltaEvidenceRecord[];
  coverage: DeltaCoverage[];
}

export interface WorkerDeltaRequest {
  schema_version: string;
  protocol_version: string;
  scan_id: string;
  adapter: string;
  analysis_mode: "complete" | "semantic_noop";
  base_snapshot_id: string;
  base_graph_digest: string;
  changes: DeltaFileChange[];
  scope: DeltaScope;
  base_graph: WorkerDeltaBaseGraph;
}

type Mutation = Record<string, JsonValue>;
type DeltaEvent = Record<string, JsonValue>;

function jsonValue(value: unknown): JsonValue {
  return value as JsonValue;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function assertSortedUnique(name: string, values: unknown): asserts values is string[] {
  if (
    !Array.isArray(values)
    || values.some((value) => typeof value !== "string" || value.length === 0)
    || values.some((value, index) => index > 0 && compareUtf8(values[index - 1] as string, value as string) >= 0)
  ) {
    throw new Error(`${name} must be a sorted unique string array`);
  }
}

function assertStableId(name: string, value: unknown, namespace?: string): asserts value is string {
  const prefix = namespace === undefined ? "[a-z][a-z0-9_-]*" : namespace;
  if (typeof value !== "string" || !new RegExp(`^${prefix}:sha256:[0-9a-f]{64}$`, "u").test(value)) {
    throw new Error(`${name} is not a stable SHA-256 ID`);
  }
}

function assertDigest(name: string, value: unknown): asserts value is string {
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/u.test(value)) {
    throw new Error(`${name} is not a canonical SHA-256 digest`);
  }
}

function evidenceKey(record: Pick<DeltaEvidenceRecord, "owner_type" | "owner_id" | "ordinal">): string {
  return `${record.owner_type}\0${record.owner_id}\0${String(record.ordinal).padStart(10, "0")}`;
}

function evidenceResultOrder(left: DeltaEvidenceRecord, right: DeltaEvidenceRecord): number {
  const rank = { node: 0, site: 1, edge: 2 } as const;
  return rank[left.owner_type] - rank[right.owner_type]
    || compareUtf8(left.owner_id, right.owner_id)
    || left.ordinal - right.ordinal;
}

function coverageKey(coverage: DeltaCoverage): string {
  switch (coverage.scope) {
    case "aggregate": return "aggregate";
    case "profile": return `profile\0${coverage.profile_id}`;
    case "file": return `file\0${coverage.adapter}\0${coverage.path}`;
  }
}

function coverageMutationKey(coverage: DeltaCoverage): string {
  return coverageKey(coverage);
}

function coverageResultOrder(left: DeltaCoverage, right: DeltaCoverage): number {
  const rank = { aggregate: 0, profile: 1, file: 2 } as const;
  return rank[left.scope] - rank[right.scope] || compareUtf8(coverageKey(left), coverageKey(right));
}

function mapById<T extends { id: string }>(name: string, values: readonly T[]): Map<string, T> {
  const result = new Map<string, T>();
  for (const value of values) {
    if (result.has(value.id)) throw new Error(`worker delta request repeats ${name} ${value.id}`);
    result.set(value.id, value);
  }
  return result;
}

function mapEvidence(values: readonly DeltaEvidenceRecord[]): Map<string, DeltaEvidenceRecord> {
  const result = new Map<string, DeltaEvidenceRecord>();
  for (const value of values) {
    const key = evidenceKey(value);
    if (result.has(key)) throw new Error(`worker delta request repeats evidence ${key}`);
    result.set(key, value);
  }
  return result;
}

function mapCoverage(values: readonly DeltaCoverage[]): Map<string, DeltaCoverage> {
  const result = new Map<string, DeltaCoverage>();
  for (const value of values) {
    const key = coverageKey(value);
    if (result.has(key)) throw new Error(`worker delta request repeats coverage ${key}`);
    result.set(key, value);
  }
  return result;
}

function canonicalEqual(left: unknown, right: unknown): boolean {
  return isDeepStrictEqual(left, right)
    || canonicalJson(jsonValue(left)) === canonicalJson(jsonValue(right));
}

function wireEvidence(item: Evidence): WireEvidence {
  return {
    kind: item.kind,
    extractor: item.extractor,
    extractor_version: item.extractor_version,
    path: item.path,
    start_line: item.start_line,
    start_column: item.start_column,
    end_line: item.end_line,
    end_column: item.end_column,
    ...(item.detail === undefined ? {} : { detail: item.detail }),
    properties: item.properties ?? {},
  };
}

function graphDigest(graph: WorkerDeltaBaseGraph): string {
  const identity = stableId("worker-graph", {
    schema: DELTA_CONTRACT_VERSION,
    profiles: graph.profiles,
    nodes: graph.nodes,
    sites: graph.sites,
    edges: graph.edges,
    evidence: graph.evidence,
    coverage: graph.coverage,
  } as unknown as JsonValue);
  return identity.slice("worker-graph:sha256:".length);
}

export function parseWorkerDeltaRequest(value: unknown, expectedScanId: string): WorkerDeltaRequest {
  if (!isRecord(value)) throw new Error("worker delta request must be an object");
  const request = value as unknown as WorkerDeltaRequest;
  if (request.schema_version !== DELTA_REQUEST_SCHEMA_VERSION) {
    throw new Error(`unsupported worker delta request schema ${String(request.schema_version)}`);
  }
  if (request.protocol_version !== PROTOCOL_VERSION) throw new Error("worker delta request protocol mismatch");
  if (request.scan_id !== expectedScanId || request.adapter !== ADAPTER) {
    throw new Error("worker delta request routing metadata mismatch");
  }
  request.analysis_mode ??= "complete";
  if (!["complete", "semantic_noop"].includes(request.analysis_mode)) {
    throw new Error("worker delta request analysis mode is unsupported");
  }
  assertStableId("worker delta base snapshot", request.base_snapshot_id, "snapshot");
  assertDigest("worker delta base graph", request.base_graph_digest);
  if (!isRecord(request.scope)) throw new Error("worker delta request scope must be an object");
  assertSortedUnique("worker delta request paths", request.scope.paths);
  assertSortedUnique("worker delta request package locators", request.scope.package_locators);
  assertSortedUnique("worker delta request profile IDs", request.scope.profile_ids);
  assertSortedUnique("worker delta request artifact IDs", request.scope.artifact_node_ids);
  assertSortedUnique("worker delta request adapters", request.scope.adapters);
  if (request.scope.adapters.length !== 1 || request.scope.adapters[0] !== ADAPTER) {
    throw new Error("worker delta request must target only the Web adapter");
  }
  if (!Array.isArray(request.changes) || request.changes.length === 0) {
    throw new Error("worker delta request has no file changes");
  }
  const scopedPaths = new Set(request.scope.paths);
  for (const change of request.changes) {
    if (!isRecord(change) || !["added", "modified", "deleted", "renamed"].includes(change.kind)) {
      throw new Error("worker delta request contains an invalid file change");
    }
    const paths = [change.old_path, change.new_path].filter((path): path is string => path !== undefined);
    if (paths.length === 0 || paths.some((path) => !scopedPaths.has(path))) {
      throw new Error("worker delta request change is outside its analysis closure");
    }
  }
  if (!isRecord(request.base_graph)) throw new Error("worker delta request base graph must be an object");
  assertSortedUnique("worker delta request profiles", request.base_graph.profiles);
  for (const field of ["nodes", "sites", "edges", "evidence", "coverage"] as const) {
    if (!Array.isArray(request.base_graph[field])) {
      throw new Error(`worker delta request base graph ${field} must be an array`);
    }
  }
  if (graphDigest(request.base_graph) !== request.base_graph_digest) {
    throw new Error("worker delta request base graph digest mismatch");
  }
  return request;
}

export class IncrementalFallbackError extends Error {}

function hasNamedScopeValue(
  value: JsonValue,
  keys: ReadonlySet<string>,
  candidates: ReadonlySet<string>,
): boolean {
  if (Array.isArray(value)) return value.some((child) => hasNamedScopeValue(child, keys, candidates));
  if (value === null || typeof value !== "object") return false;
  return Object.entries(value).some(([key, child]) => (
    (keys.has(key) && typeof child === "string" && candidates.has(child))
    || hasNamedScopeValue(child, keys, candidates)
  ));
}

function scopedEvidenceOwners(
  scopePaths: ReadonlySet<string>,
  evidence: ReadonlyMap<string, DeltaEvidenceRecord>,
): Record<DeltaEvidenceRecord["owner_type"], Set<string>> {
  const owners = {
    node: new Set<string>(),
    site: new Set<string>(),
    edge: new Set<string>(),
  };
  // A package-sized closure may contain tens of thousands of owners. Index the
  // scoped evidence in one pass instead of rescanning the full evidence map
  // once for every node, site, and edge.
  for (const record of evidence.values()) {
    if (typeof record.evidence.path === "string" && scopePaths.has(record.evidence.path)) {
      owners[record.owner_type].add(record.owner_id);
    }
  }
  return owners;
}

function scopedBaseEntities(
  request: WorkerDeltaRequest,
  nodes: ReadonlyMap<string, GraphNode>,
  sites: ReadonlyMap<string, WireSite>,
  edges: ReadonlyMap<string, WireEdge>,
  evidence: ReadonlyMap<string, DeltaEvidenceRecord>,
): { paths: Set<string>; nodes: Set<string>; sites: Set<string>; edges: Set<string> } {
  const paths = new Set(request.scope.paths);
  const packages = new Set(request.scope.package_locators);
  const profiles = new Set(request.scope.profile_ids);
  const artifacts = new Set(request.scope.artifact_node_ids);
  const evidenceOwners = scopedEvidenceOwners(paths, evidence);
  const namedPathKeys = new Set(["path", "source_path", "manifest_path", "relative_path", "logical_path"]);
  const packageLocatorKeys = new Set(["package_locator"]);
  const profileIdKeys = new Set(["profile_id"]);
  const scopedNodes = new Set(
    [...nodes.values()]
      .filter((node) => (
        artifacts.has(node.id)
        || paths.has(node.locator)
        || (node.kind === "package_instance" && packages.has(node.locator))
        || hasNamedScopeValue(node.properties, namedPathKeys, paths)
        || hasNamedScopeValue(node.properties, packageLocatorKeys, packages)
        || hasNamedScopeValue(node.properties, profileIdKeys, profiles)
        || evidenceOwners.node.has(node.id)
      ))
      .map((node) => node.id),
  );
  const scopedSites = new Set(
    [...sites.values()]
      .filter((site) => (
        profiles.has(site.profile_id)
        || scopedNodes.has(site.source)
        || evidenceOwners.site.has(site.id)
      ))
      .map((site) => site.id),
  );
  const scopedEdges = new Set(
    [...edges.values()]
      .filter((edge) => (
        profiles.has(edge.profile_id)
        || scopedNodes.has(edge.source)
        || scopedNodes.has(edge.target)
        || (edge.site_id !== undefined && scopedSites.has(edge.site_id))
        || evidenceOwners.edge.has(edge.id)
      ))
      .map((edge) => edge.id),
  );
  return { paths, nodes: scopedNodes, sites: scopedSites, edges: scopedEdges };
}

function evidenceIsScoped(
  record: DeltaEvidenceRecord,
  scoped: ReturnType<typeof scopedBaseEntities>,
): boolean {
  const ownerScoped = record.owner_type === "node"
    ? scoped.nodes.has(record.owner_id)
    : record.owner_type === "site"
      ? scoped.sites.has(record.owner_id)
      : scoped.edges.has(record.owner_id);
  return ownerScoped
    || (typeof record.evidence.path === "string" && scoped.paths.has(record.evidence.path));
}

function splitModelEvidence(model: ScanModel): {
  sites: Map<string, WireSite>;
  edges: Map<string, WireEdge>;
  evidence: Map<string, DeltaEvidenceRecord>;
} {
  const evidence: DeltaEvidenceRecord[] = [];
  const sites = model.sites.map((site) => {
    site.evidence.forEach((item, ordinal) => evidence.push({
      owner_type: "site",
      owner_id: site.id,
      ordinal,
      evidence: wireEvidence(item),
    }));
    const { reason, ...payload } = site;
    return {
      ...payload,
      condition: canonicalizeCondition(site.condition),
      ...(reason === null ? {} : { reason }),
      evidence: [],
    };
  });
  const edges = model.edges.map((edge) => {
    edge.evidence.forEach((item, ordinal) => evidence.push({
      owner_type: "edge",
      owner_id: edge.id,
      ordinal,
      evidence: wireEvidence(item),
    }));
    const { site_id: siteId, environment, ...payload } = edge;
    return {
      ...payload,
      condition: canonicalizeCondition(edge.condition),
      ...(siteId === null ? {} : { site_id: siteId }),
      ...(environment === null ? {} : { environment }),
      evidence: [],
    };
  });
  return {
    sites: mapById("site", sites),
    edges: mapById("edge", edges),
    evidence: mapEvidence(evidence),
  };
}

function fileCoverage(model: ScanModel): DeltaCoverage[] {
  return model.files.map((file) => ({
    scope: "file",
    adapter: ADAPTER,
    path: file.path,
    value: {
      discovered_sites: file.expected_sites,
      emitted_sites: file.produced_sites,
      skipped_sites: file.skipped_sites,
      skipped: file.skipped_sites > 0,
      ...(file.skipped_sites > 0 ? { reason: "file_or_site_skipped" } : {}),
    },
  }));
}

function finalAggregateCoverage(
  baseAggregate: Coverage,
  oldWebProfile: Coverage,
  newWebProfile: Coverage,
  profiles: readonly string[],
  sites: ReadonlyMap<string, WireSite>,
  coverage: ReadonlyMap<string, DeltaCoverage>,
): Coverage {
  const profileCoverage = [...coverage.values()]
    .filter((item): item is Extract<DeltaCoverage, { scope: "profile" }> => item.scope === "profile")
    .map((item) => item.value);
  let completeness = profileCoverage[0]?.completeness.slice() ?? [];
  for (const profile of profileCoverage.slice(1)) {
    const levels = new Set(profile.completeness);
    completeness = completeness.filter((level) => levels.has(level));
  }
  const reasons = [...new Set(profileCoverage.flatMap((profile) => profile.reasons))]
    .sort(compareUtf8);
  const siteCounts = {
    resolved: 0,
    candidates: 0,
    external: 0,
    unresolved: 0,
  };
  for (const site of sites.values()) siteCounts[site.resolution_status] += 1;
  const files = [...coverage.values()]
    .filter((item): item is Extract<DeltaCoverage, { scope: "file" }> => item.scope === "file");
  const skipped = files.filter((item) => item.value.skipped).length;
  const adjustedUnsupported = baseAggregate.unsupported_syntax
    - oldWebProfile.unsupported_syntax
    + newWebProfile.unsupported_syntax;
  if (adjustedUnsupported < 0) throw new Error("worker delta aggregate coverage underflow");
  return {
    profiles: profiles.length,
    files_discovered: files.length,
    files_analyzed: files.length - skipped,
    files_skipped: skipped,
    dependency_sites: sites.size,
    ...siteCounts,
    unsupported_syntax: adjustedUnsupported,
    project_code_executed: profileCoverage.some((profile) => profile.project_code_executed),
    completeness,
    reasons,
  };
}

function deltaId(request: WorkerDeltaRequest, mutations: readonly Mutation[]): string {
  return stableId("delta", {
    contract: DELTA_CONTRACT_VERSION,
    base_snapshot_id: request.base_snapshot_id,
    base_graph_digest: request.base_graph_digest,
    scope: request.scope,
    mutations,
  } as unknown as JsonValue);
}

function resultGraph(
  request: WorkerDeltaRequest,
  nodes: ReadonlyMap<string, GraphNode>,
  sites: ReadonlyMap<string, WireSite>,
  edges: ReadonlyMap<string, WireEdge>,
  evidence: ReadonlyMap<string, DeltaEvidenceRecord>,
  coverage: ReadonlyMap<string, DeltaCoverage>,
): WorkerDeltaBaseGraph {
  return {
    profiles: request.base_graph.profiles.slice(),
    nodes: [...nodes.values()].sort((left, right) => compareUtf8(left.id, right.id)),
    sites: [...sites.values()].sort((left, right) => compareUtf8(left.id, right.id)),
    edges: [...edges.values()].sort((left, right) => compareUtf8(left.id, right.id)),
    evidence: [...evidence.values()].sort(evidenceResultOrder),
    coverage: [...coverage.values()].sort(coverageResultOrder),
  };
}

export function deltaEventsFor(model: ScanModel, request: WorkerDeltaRequest): DeltaEvent[] {
  const baseNodes = mapById("node", request.base_graph.nodes);
  const baseSites = mapById("site", request.base_graph.sites);
  const baseEdges = mapById("edge", request.base_graph.edges);
  const baseEvidence = mapEvidence(request.base_graph.evidence);
  const baseCoverage = mapCoverage(request.base_graph.coverage);
  const modelNodes = mapById("node", model.nodes);
  const modelGraph = splitModelEvidence(model);
  const scoped = scopedBaseEntities(request, baseNodes, baseSites, baseEdges, baseEvidence);

  const finalNodes = new Map(baseNodes);
  for (const id of scoped.nodes) if (!modelNodes.has(id)) finalNodes.delete(id);
  for (const [id, node] of modelNodes) finalNodes.set(id, node);

  const finalSites = new Map(baseSites);
  for (const id of scoped.sites) if (!modelGraph.sites.has(id)) finalSites.delete(id);
  for (const [id, site] of modelGraph.sites) finalSites.set(id, site);

  const finalEdges = new Map(baseEdges);
  for (const id of scoped.edges) if (!modelGraph.edges.has(id)) finalEdges.delete(id);
  for (const [id, edge] of modelGraph.edges) finalEdges.set(id, edge);

  const finalEvidence = new Map(baseEvidence);
  for (const [key, record] of baseEvidence) {
    if (evidenceIsScoped(record, scoped) && !modelGraph.evidence.has(key)) {
      finalEvidence.delete(key);
    }
  }
  for (const [key, record] of modelGraph.evidence) finalEvidence.set(key, record);

  const finalCoverage = new Map(baseCoverage);
  const modelFileCoverage = mapCoverage(fileCoverage(model));
  for (const [key, item] of baseCoverage) {
    if (
      item.scope === "file"
      && item.adapter === ADAPTER
      && scoped.paths.has(item.path)
      && !modelFileCoverage.has(key)
    ) {
      finalCoverage.delete(key);
    }
  }
  for (const [key, item] of modelFileCoverage) finalCoverage.set(key, item);
  const profileKey = `profile\0${PROFILE_ID}`;
  const oldProfile = baseCoverage.get(profileKey);
  const oldAggregate = baseCoverage.get("aggregate");
  if (oldProfile?.scope !== "profile" || oldAggregate?.scope !== "aggregate") {
    throw new Error("worker delta request is missing Web profile or aggregate coverage");
  }
  finalCoverage.set(profileKey, { scope: "profile", profile_id: PROFILE_ID, value: model.coverage });
  finalCoverage.set("aggregate", {
    scope: "aggregate",
    value: finalAggregateCoverage(
      oldAggregate.value,
      oldProfile.value,
      model.coverage,
      request.base_graph.profiles,
      finalSites,
      finalCoverage,
    ),
  });

  const evidenceDeletes = [...baseEvidence.entries()]
    .filter(([key]) => !finalEvidence.has(key))
    .map(([, record]) => ({
      event: "evidence_delete",
      evidence_key: {
        owner_type: record.owner_type,
        owner_id: record.owner_id,
        ordinal: record.ordinal,
      },
    }))
    .sort((left, right) => compareUtf8(
      evidenceKey(left.evidence_key),
      evidenceKey(right.evidence_key),
    ));
  const edgeDeletes = [...baseEdges.keys()]
    .filter((id) => !finalEdges.has(id))
    .sort(compareUtf8)
    .map((edge_id) => ({ event: "edge_delete", edge_id }));
  const siteDeletes = [...baseSites.keys()]
    .filter((id) => !finalSites.has(id))
    .sort(compareUtf8)
    .map((site_id) => ({ event: "site_delete", site_id }));
  const nodeDeletes = [...baseNodes.keys()]
    .filter((id) => !finalNodes.has(id))
    .sort(compareUtf8)
    .map((node_id) => ({ event: "node_delete", node_id }));
  const nodeUpserts = [...finalNodes.values()]
    .filter((node) => !canonicalEqual(baseNodes.get(node.id), node))
    .sort((left, right) => compareUtf8(left.id, right.id))
    .map((node) => ({ event: "delta_node_upsert", node }));
  const siteUpserts = [...finalSites.values()]
    .filter((site) => !canonicalEqual(baseSites.get(site.id), site))
    .sort((left, right) => compareUtf8(left.id, right.id))
    .map((site) => ({ event: "site_upsert", site }));
  const edgeUpserts = [...finalEdges.values()]
    .filter((edge) => !canonicalEqual(baseEdges.get(edge.id), edge))
    .sort((left, right) => compareUtf8(left.id, right.id))
    .map((edge) => ({ event: "delta_edge_upsert", edge }));
  const evidenceUpserts = [...finalEvidence.values()]
    .filter((record) => !canonicalEqual(baseEvidence.get(evidenceKey(record)), record))
    .sort((left, right) => compareUtf8(evidenceKey(left), evidenceKey(right)))
    .map((evidence) => ({ event: "evidence_upsert", evidence }));
  const coverageDeletes = [...baseCoverage.values()]
    .filter((coverage) => !finalCoverage.has(coverageKey(coverage)))
    .sort((left, right) => compareUtf8(coverageMutationKey(left), coverageMutationKey(right)))
    .map((coverage) => ({
      event: "coverage_delete",
      coverage_key: coverage.scope === "aggregate"
        ? { scope: "aggregate" }
        : coverage.scope === "profile"
          ? { scope: "profile", profile_id: coverage.profile_id }
          : { scope: "file", adapter: coverage.adapter, path: coverage.path },
    }));
  const coverageUpserts = [...finalCoverage.values()]
    .filter((coverage) => !canonicalEqual(baseCoverage.get(coverageKey(coverage)), coverage))
    .sort((left, right) => compareUtf8(coverageMutationKey(left), coverageMutationKey(right)))
    .map((coverage) => ({ event: "coverage_upsert", coverage }));
  const mutations = [
    ...evidenceDeletes,
    ...edgeDeletes,
    ...siteDeletes,
    ...nodeDeletes,
    ...nodeUpserts,
    ...siteUpserts,
    ...edgeUpserts,
    ...evidenceUpserts,
    ...coverageDeletes,
    ...coverageUpserts,
  ] as unknown as Mutation[];
  if (mutations.length === 0) throw new Error("worker delta request produced no graph mutations");

  const identity = deltaId(request, mutations);
  const common = (event: string, seq: number): DeltaEvent => ({
    event,
    protocol_version: PROTOCOL_VERSION,
    scan_id: request.scan_id,
    adapter: ADAPTER,
    adapter_version: ADAPTER_VERSION,
    seq,
  });
  return [
    {
      ...common("delta_started", 1),
      delta_contract_version: DELTA_CONTRACT_VERSION,
      delta_id: identity,
      base_snapshot_id: request.base_snapshot_id,
      base_graph_digest: request.base_graph_digest,
      scope: jsonValue(request.scope),
    },
    ...mutations.map((mutation, index) => ({
      ...common(String(mutation.event), index + 2),
      ...mutation,
    })),
    {
      ...common("delta_completed", mutations.length + 2),
      delta_contract_version: DELTA_CONTRACT_VERSION,
      delta_id: identity,
      mutation_count: mutations.length,
      result_graph_digest: graphDigest(resultGraph(
        request,
        finalNodes,
        finalSites,
        finalEdges,
        finalEvidence,
        finalCoverage,
      )),
    },
  ];
}

export function semanticNoopDeltaEventsFor(
  source: string,
  request: WorkerDeltaRequest,
): DeltaEvent[] {
  if (request.analysis_mode !== "semantic_noop") {
    throw new Error("semantic no-op delta requires semantic_noop analysis mode");
  }
  if (request.changes.length !== 1 || request.scope.paths.length !== 1) {
    throw new IncrementalFallbackError("semantic no-op delta requires exactly one changed path");
  }
  const change = request.changes[0]!;
  const changedPath = change.new_path;
  if (
    !["added", "modified"].includes(change.kind)
    || changedPath === undefined
    || changedPath !== request.scope.paths[0]
  ) {
    throw new IncrementalFallbackError("semantic no-op delta requires one existing file write");
  }
  const baseNodes = mapById("node", request.base_graph.nodes);
  const fileNodes = [...baseNodes.values()].filter((node) => (
    node.kind === "file"
    && node.properties.path === changedPath
  ));
  if (fileNodes.length !== 1) {
    throw new IncrementalFallbackError("semantic no-op base has no unique changed file node");
  }
  const fileNode = fileNodes[0]!;
  const previousAnalysisHash = fileNode.properties.analysis_hash;
  const nextAnalysisHash = analysisContentHash(source, changedPath);
  if (
    typeof previousAnalysisHash !== "string"
    || previousAnalysisHash !== nextAnalysisHash
  ) {
    throw new IncrementalFallbackError("changed file requires dependency reanalysis");
  }
  const nextContentHash = contentHash(source);
  if (fileNode.properties.content_hash === nextContentHash) {
    throw new IncrementalFallbackError("changed file content is identical to the base");
  }
  const nextNode: GraphNode = {
    ...fileNode,
    properties: {
      ...fileNode.properties,
      content_hash: nextContentHash,
      analysis_hash: nextAnalysisHash,
    },
  };
  const mutation = {
    event: "delta_node_upsert",
    node: nextNode,
  } as unknown as Mutation;
  const mutations = [mutation];
  const identity = deltaId(request, mutations);
  const common = (event: string, seq: number): DeltaEvent => ({
    event,
    protocol_version: PROTOCOL_VERSION,
    scan_id: request.scan_id,
    adapter: ADAPTER,
    adapter_version: ADAPTER_VERSION,
    seq,
  });
  const finalNodes = new Map(baseNodes);
  finalNodes.set(nextNode.id, nextNode);
  return [
    {
      ...common("delta_started", 1),
      delta_contract_version: DELTA_CONTRACT_VERSION,
      delta_id: identity,
      base_snapshot_id: request.base_snapshot_id,
      base_graph_digest: request.base_graph_digest,
      scope: jsonValue(request.scope),
    },
    {
      ...common("delta_node_upsert", 2),
      node: jsonValue(nextNode),
    },
    {
      ...common("delta_completed", 3),
      delta_contract_version: DELTA_CONTRACT_VERSION,
      delta_id: identity,
      mutation_count: 1,
      result_graph_digest: graphDigest(resultGraph(
        request,
        finalNodes,
        mapById("site", request.base_graph.sites),
        mapById("edge", request.base_graph.edges),
        mapEvidence(request.base_graph.evidence),
        mapCoverage(request.base_graph.coverage),
      )),
    },
  ];
}
