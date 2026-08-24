import { canonicalJson, stableId } from "./ids";
import {
  canonicalizeCondition,
  compareUtf8,
  type Condition,
  type Coverage,
  type DependencySite,
  type Diagnostic,
  type Evidence,
  type GraphEdge,
  type GraphNode,
  type JsonValue,
  type ProtocolEvent,
  type ResolutionStatus,
} from "./types";

export const FRAMEWORK_BUILD_GRAPH_CONTRACT_VERSION = "framework-build-graph-v1" as const;

export type FrameworkBuildName = "next" | "astro" | "tanstack-router" | "tanstack-start";

export interface FrameworkBuildDescriptor {
  framework: FrameworkBuildName;
  observer: string;
  observerVersion: string;
  capability: string;
}

export interface FrameworkBuildProvenance {
  build_run_id: string;
  profile_id: string;
  command_plan_digest: string;
  toolchain_executable_digest: string;
  environment_key_set_digest: string;
  validated_output_digest: string;
}

export interface FrameworkBuildDelta {
  nodes: GraphNode[];
  sites: DependencySite[];
  edges: GraphEdge[];
  diagnostics: Diagnostic[];
}

export interface FrameworkBuildProfile {
  toolchain: string;
  command: string;
  features?: readonly string[];
  properties?: Record<string, JsonValue>;
}

export interface FrameworkBuildCompletion {
  status: "complete" | "partial" | "unsupported";
  reason: FrameworkBuildIncompleteReason | null;
}

export type FrameworkBuildIncompleteReason =
  | "framework_build_incomplete"
  | "framework_build_version_unsupported"
  | "framework_build_manifest_missing"
  | "framework_build_hook_missing"
  | "framework_build_dynamic_target_unmatched"
  | "framework_build_generated_identity_conflict";

const FRAMEWORK_BUILD_NODE_KINDS = new Set<GraphNode["kind"]>([
  "route",
  "component",
  "server_function",
  "middleware",
  "module",
  "symbol",
  "file",
  "unknown_target",
]);

const FRAMEWORK_BUILD_RELATION_KINDS = new Set([
  "renders",
  "hydrates",
  "emits",
  "loads",
  "imports",
  "dynamic_imports",
  "routes_in_phase",
  "route_entry",
  "parent_route",
  "before_load",
  "navigates_to",
  "masks_to",
  "observes_definition",
  "client_stub_for",
  "handled_by",
  "uses_middleware",
]);

const FRAMEWORK_BUILD_INCOMPLETE_REASONS = new Set<FrameworkBuildIncompleteReason>([
  "framework_build_incomplete",
  "framework_build_version_unsupported",
  "framework_build_manifest_missing",
  "framework_build_hook_missing",
  "framework_build_dynamic_target_unmatched",
  "framework_build_generated_identity_conflict",
]);

const SHA256 = /^[a-f0-9]{64}$/u;
const MAX_SAFE_STRING = 4_096;

function record(value: JsonValue | undefined, field: string): Record<string, JsonValue> {
  if (value === null || value === undefined || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${field} must be an object`);
  }
  return value;
}

function nonempty(value: unknown, field: string): string {
  if (typeof value !== "string" || value.length === 0 || value.length > MAX_SAFE_STRING
    || /[\u0000-\u001f\u007f]/u.test(value)) {
    throw new Error(`${field} must be a bounded non-empty string`);
  }
  return value;
}

function digest(value: unknown, field: string): string {
  if (typeof value !== "string" || !SHA256.test(value)) {
    throw new Error(`${field} must be a lowercase SHA-256 digest`);
  }
  return value;
}

function canonicalRelativePath(value: unknown, field: string): string {
  const raw = nonempty(value, field).replaceAll("\\", "/");
  if (raw.startsWith("/") || raw.startsWith("//") || /^[a-z]:\//iu.test(raw)) {
    throw new Error(`${field} must be repository-relative`);
  }
  const segments = raw.split("/");
  if (segments.some((segment) => segment === "" || segment === "." || segment === "..")) {
    throw new Error(`${field} must be canonical`);
  }
  return raw;
}

function sameJson(left: unknown, right: unknown): boolean {
  return canonicalJson(left as JsonValue) === canonicalJson(right as JsonValue);
}

function validateDescriptor(descriptor: FrameworkBuildDescriptor): void {
  nonempty(descriptor.framework, "framework build descriptor framework");
  nonempty(descriptor.observer, "framework build descriptor observer");
  nonempty(descriptor.observerVersion, "framework build descriptor observer version");
  nonempty(descriptor.capability, "framework build descriptor capability");
}

export function validateFrameworkBuildProvenance(provenance: FrameworkBuildProvenance): void {
  nonempty(provenance.build_run_id, "framework build provenance build_run_id");
  nonempty(provenance.profile_id, "framework build provenance profile_id");
  for (const field of [
    "command_plan_digest",
    "toolchain_executable_digest",
    "environment_key_set_digest",
    "validated_output_digest",
  ] as const) {
    digest(provenance[field], `framework build provenance ${field}`);
  }
}

function provenanceProperties(
  descriptor: FrameworkBuildDescriptor,
  provenance: FrameworkBuildProvenance,
  logicalArtifactPath: string,
  artifactDigest: string,
): Record<string, JsonValue> {
  return {
    ...provenance,
    framework: descriptor.framework,
    capability: descriptor.capability,
    contract_version: FRAMEWORK_BUILD_GRAPH_CONTRACT_VERSION,
    logical_artifact_path: logicalArtifactPath,
    artifact_digest: artifactDigest,
  };
}

export function frameworkBuildEvidence(
  descriptor: FrameworkBuildDescriptor,
  provenance: FrameworkBuildProvenance,
  logicalArtifactPath: string,
  artifactDigest: string,
  properties: Record<string, JsonValue> = {},
): Evidence {
  validateDescriptor(descriptor);
  validateFrameworkBuildProvenance(provenance);
  const path = canonicalRelativePath(logicalArtifactPath, "framework build evidence path");
  const checksum = digest(artifactDigest, "framework build evidence artifact digest");
  return {
    kind: "build",
    extractor: descriptor.observer,
    extractor_version: descriptor.observerVersion,
    path,
    start_line: 1,
    start_column: 1,
    end_line: 1,
    end_column: 1,
    properties: {
      ...provenanceProperties(descriptor, provenance, path, checksum),
      ...properties,
    },
  };
}

export function frameworkBuildGeneratedNode(
  descriptor: FrameworkBuildDescriptor,
  kind: GraphNode["kind"],
  identity: Record<string, JsonValue>,
  displayName: string,
  properties: Record<string, JsonValue>,
  provenance: FrameworkBuildProvenance,
  logicalArtifactPath: string,
  artifactDigest: string,
): GraphNode {
  if (!FRAMEWORK_BUILD_NODE_KINDS.has(kind)) {
    throw new Error(`framework build graph does not allow generated node kind ${kind}`);
  }
  const path = canonicalRelativePath(logicalArtifactPath, "framework build node logical artifact path");
  const checksum = digest(artifactDigest, "framework build node artifact digest");
  const versionedIdentity: Record<string, JsonValue> = {
    ...identity,
    contract_version: FRAMEWORK_BUILD_GRAPH_CONTRACT_VERSION,
  };
  if (versionedIdentity.framework !== descriptor.framework) {
    throw new Error("framework build node identity disagrees with its descriptor");
  }
  const id = stableId(kind, versionedIdentity);
  return {
    id,
    kind,
    locator: `build://${descriptor.observer}/${encodeURIComponent(path)}#${id}`,
    display_name: nonempty(displayName, "framework build node display name"),
    properties: {
      ...properties,
      framework_build_contract_version: FRAMEWORK_BUILD_GRAPH_CONTRACT_VERSION,
      build_generated: true,
      build_identity: versionedIdentity,
      build_provenance: {
        ...provenance,
        framework: descriptor.framework,
        observer: descriptor.observer,
        observer_version: descriptor.observerVersion,
        capability: descriptor.capability,
        contract_version: FRAMEWORK_BUILD_GRAPH_CONTRACT_VERSION,
        logical_artifact_path: path,
        artifact_digest: checksum,
      },
    },
  };
}

export function frameworkBuildCondition(
  environment: string,
  properties: Readonly<Record<string, string>> = {},
): Condition {
  const normalizedEnvironment = environment === "client" ? "browser" : nonempty(
    environment,
    "framework build condition environment",
  );
  return canonicalizeCondition({
    op: "all",
    conditions: [
      { op: "eq", key: "mode", value: "production" },
      { op: "eq", key: "environment", value: normalizedEnvironment },
      ...Object.entries(properties).map(([key, value]) => ({
        op: "eq" as const,
        key: nonempty(key, "framework build condition key"),
        value: nonempty(value, `framework build condition ${key}`),
      })),
    ],
  });
}

function relationIdentity(
  descriptor: FrameworkBuildDescriptor,
  source: string,
  kind: string,
  specifier: string,
  profileId: string,
  condition: Condition,
  status: ResolutionStatus,
  reason: string | null,
  evidence: Evidence,
): Record<string, JsonValue> {
  return {
    contract_version: FRAMEWORK_BUILD_GRAPH_CONTRACT_VERSION,
    kind,
    source,
    specifier,
    profile_id: profileId,
    condition,
    resolution_status: status,
    precision: "observed",
    reason,
    observer: descriptor.observer,
    observer_version: descriptor.observerVersion,
    validated_output_digest: evidence.properties?.validated_output_digest ?? null,
    anchor: {
      path: evidence.path,
      start_line: evidence.start_line,
      start_column: evidence.start_column,
      end_line: evidence.end_line,
      end_column: evidence.end_column,
    },
  };
}

export function frameworkBuildRelation(
  descriptor: FrameworkBuildDescriptor,
  source: string,
  target: string,
  kind: string,
  specifier: string,
  environment: string,
  condition: Condition,
  evidence: Evidence,
  profileId: string,
  status: "resolved" | "unresolved" = "resolved",
  reason: FrameworkBuildIncompleteReason | null = null,
): { site: DependencySite; edge: GraphEdge } {
  if (!FRAMEWORK_BUILD_RELATION_KINDS.has(kind)) {
    throw new Error(`framework build graph does not allow relation kind ${kind}`);
  }
  if (status === "resolved" && reason !== null) {
    throw new Error("resolved framework build relation must not include a reason");
  }
  if (status === "unresolved" && (reason === null || !FRAMEWORK_BUILD_INCOMPLETE_REASONS.has(reason))) {
    throw new Error("unresolved framework build relation requires a bounded reason");
  }
  const canonicalCondition = canonicalizeCondition(condition);
  const normalizedEnvironment = environment === "client" ? "browser" : environment;
  const siteIdentity = relationIdentity(
    descriptor,
    nonempty(source, "framework build relation source"),
    nonempty(kind, "framework build relation kind"),
    nonempty(specifier, "framework build relation specifier"),
    nonempty(profileId, "framework build relation profile"),
    canonicalCondition,
    status,
    reason,
    evidence,
  );
  const siteId = stableId("site", siteIdentity);
  const site: DependencySite = {
    id: siteId,
    source,
    kind,
    specifier,
    resolution_status: status,
    target_ids: [target],
    profile_id: profileId,
    condition: canonicalCondition,
    precision: "observed",
    reason,
    evidence: [evidence],
  };
  const edge: GraphEdge = {
    id: stableId("edge", {
      contract_version: FRAMEWORK_BUILD_GRAPH_CONTRACT_VERSION,
      kind,
      site_id: siteId,
      target,
      phase: "build",
    }),
    source,
    target,
    kind,
    site_id: siteId,
    phase: "build",
    environment: normalizedEnvironment,
    profile_id: profileId,
    condition: canonicalCondition,
    resolution_status: status,
    precision: "observed",
    generated: true,
    evidence: [evidence],
  };
  return { site, edge };
}

export function frameworkBuildUnresolvedTarget(
  descriptor: FrameworkBuildDescriptor,
  provenance: FrameworkBuildProvenance,
  kind: string,
  source: string,
  specifier: string,
  environment: string,
  condition: Condition,
  evidence: Evidence,
  reason: FrameworkBuildIncompleteReason,
): { node: GraphNode; site: DependencySite; edge: GraphEdge } {
  if (!FRAMEWORK_BUILD_INCOMPLETE_REASONS.has(reason)) {
    throw new Error(`unsupported framework build unresolved reason ${reason}`);
  }
  const path = canonicalRelativePath(
    evidence.properties?.logical_artifact_path,
    "framework build unresolved target logical artifact path",
  );
  const checksum = digest(
    evidence.properties?.artifact_digest,
    "framework build unresolved target artifact digest",
  );
  const node = frameworkBuildGeneratedNode(
    descriptor,
    "unknown_target",
    {
      framework: descriptor.framework,
      relation_kind: kind,
      source,
      specifier,
      environment: environment === "client" ? "browser" : environment,
      reason,
      profile_id: provenance.profile_id,
    },
    `Unresolved ${descriptor.framework} build target`,
    {
      framework: descriptor.framework,
      relation_kind: kind,
      specifier,
      environment: environment === "client" ? "browser" : environment,
      reason,
      profile_id: provenance.profile_id,
    },
    provenance,
    path,
    checksum,
  );
  return {
    node,
    ...frameworkBuildRelation(
      descriptor,
      source,
      node.id,
      kind,
      specifier,
      environment,
      condition,
      evidence,
      provenance.profile_id,
      "unresolved",
      reason,
    ),
  };
}

export function frameworkBuildDiagnostic(
  descriptor: FrameworkBuildDescriptor,
  code: string,
  subject: string,
  profileId: string,
  evidence: Evidence,
  properties: Record<string, JsonValue>,
  severity: Diagnostic["severity"] = "warning",
): Diagnostic {
  const versionedProperties: Record<string, JsonValue> = {
    ...properties,
    framework: descriptor.framework,
    capability: descriptor.capability,
    contract_version: FRAMEWORK_BUILD_GRAPH_CONTRACT_VERSION,
  };
  return {
    id: stableId("diagnostic", { code, subject, profile_id: profileId, properties: versionedProperties }),
    severity,
    code: nonempty(code, "framework build diagnostic code"),
    message: `${code}: ${nonempty(subject, "framework build diagnostic subject")}`,
    path: evidence.path,
    profile_id: profileId,
    evidence: [evidence],
    properties: versionedProperties,
  };
}

export function deduplicateFrameworkBuildRecords<T extends { id: string }>(
  values: readonly T[],
): T[] {
  const unique = new Map<string, T>();
  for (const value of values) {
    const existing = unique.get(value.id);
    if (existing !== undefined && !sameJson(existing, value)) {
      throw new Error(`framework build graph contains conflicting record ${value.id}`);
    }
    unique.set(value.id, value);
  }
  return [...unique.values()].sort((left, right) => compareUtf8(left.id, right.id));
}

function evidenceProvenance(
  evidence: Evidence[],
  descriptor: FrameworkBuildDescriptor,
  provenance: FrameworkBuildProvenance,
  owner: string,
): Evidence {
  const primary = evidence[0];
  if (primary === undefined || primary.kind !== "build") {
    throw new Error(`${owner} lacks primary build evidence`);
  }
  if (primary.extractor !== descriptor.observer || primary.extractor_version !== descriptor.observerVersion) {
    throw new Error(`${owner} has an unapproved observer identity`);
  }
  const properties = primary.properties ?? {};
  if (properties.framework !== descriptor.framework
    || properties.capability !== descriptor.capability
    || properties.contract_version !== FRAMEWORK_BUILD_GRAPH_CONTRACT_VERSION) {
    throw new Error(`${owner} has incompatible framework build evidence`);
  }
  for (const [field, expected] of Object.entries(provenance)) {
    if (properties[field] !== expected) {
      throw new Error(`${owner} evidence disagrees on ${field}`);
    }
  }
  canonicalRelativePath(properties.logical_artifact_path, `${owner} logical artifact path`);
  digest(properties.artifact_digest, `${owner} artifact digest`);
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

function validateGeneratedNode(
  node: GraphNode,
  descriptor: FrameworkBuildDescriptor,
  provenance: FrameworkBuildProvenance,
): void {
  if (!FRAMEWORK_BUILD_NODE_KINDS.has(node.kind)) {
    throw new Error(`framework build graph contains unsupported node kind ${node.kind}`);
  }
  if (node.properties.framework !== descriptor.framework
    || node.properties.framework_build_contract_version !== FRAMEWORK_BUILD_GRAPH_CONTRACT_VERSION
    || node.properties.build_generated !== true) {
    throw new Error(`framework build generated node ${node.id} has incompatible properties`);
  }
  const identity = record(node.properties.build_identity, `${node.id}.build_identity`);
  if (identity.contract_version !== FRAMEWORK_BUILD_GRAPH_CONTRACT_VERSION
    || identity.framework !== descriptor.framework
    || stableId(node.kind, identity) !== node.id) {
    throw new Error(`framework build generated node ${node.id} has a non-canonical stable identity`);
  }
  const buildProvenance = record(node.properties.build_provenance, `${node.id}.build_provenance`);
  for (const [field, expected] of Object.entries({
    ...provenance,
    framework: descriptor.framework,
    observer: descriptor.observer,
    observer_version: descriptor.observerVersion,
    capability: descriptor.capability,
    contract_version: FRAMEWORK_BUILD_GRAPH_CONTRACT_VERSION,
  })) {
    if (buildProvenance[field] !== expected) {
      throw new Error(`framework build generated node ${node.id} provenance disagrees on ${field}`);
    }
  }
  const path = canonicalRelativePath(
    buildProvenance.logical_artifact_path,
    `${node.id}.build_provenance.logical_artifact_path`,
  );
  digest(buildProvenance.artifact_digest, `${node.id}.build_provenance.artifact_digest`);
  if (node.locator !== `build://${descriptor.observer}/${encodeURIComponent(path)}#${node.id}`) {
    throw new Error(`framework build generated node ${node.id} has a non-canonical locator`);
  }
}

function withoutBuildProvenance(node: GraphNode): GraphNode {
  const properties = { ...node.properties };
  delete properties.build_provenance;
  return { ...node, properties };
}

/**
 * Makes a repeated framework build idempotent against an already promoted
 * build layer. Stable generated nodes reuse the exact stored bytes, while
 * sites, edges, and diagnostics that already exist are omitted from the new
 * delta. A changed target for an existing stable site remains a conflict.
 */
export function reconcileFrameworkBuildBaseRecords(
  delta: FrameworkBuildDelta,
  descriptor: FrameworkBuildDescriptor,
  provenance: FrameworkBuildProvenance,
  baseNodes: readonly GraphNode[],
  baseEdges: readonly GraphEdge[],
  baseDiagnosticIds: readonly string[] = [],
): FrameworkBuildDelta {
  const baseNodeById = new Map(baseNodes.map((node) => [node.id, node]));
  const nodes = delta.nodes.map((node) => {
    const existing = baseNodeById.get(node.id);
    if (existing === undefined || sameJson(existing, node)) return node;
    if (node.properties.build_generated !== true
      || existing.properties.build_generated !== true
      || !sameJson(withoutBuildProvenance(existing), withoutBuildProvenance(node))) {
      throw new Error(`framework build graph conflicts with base node ${node.id}`);
    }
    return existing;
  });

  const nodeReconciled = { ...delta, nodes };
  validateFrameworkBuildDelta(nodeReconciled, descriptor, provenance, baseNodes);

  const baseBuildEdges = baseEdges.filter((edge) => edge.phase === "build" && edge.site_id !== null);
  const baseEdgeIds = new Set(baseBuildEdges.map((edge) => edge.id));
  const baseSiteIds = new Set(baseBuildEdges.map((edge) => edge.site_id!));
  const edgeBySite = new Map(delta.edges.map((edge) => [edge.site_id!, edge]));
  const retainedSiteIds = new Set<string>();
  const sites = delta.sites.filter((site) => {
    const edge = edgeBySite.get(site.id);
    if (edge === undefined) {
      throw new Error(`framework build site ${site.id} has no edge during base reconciliation`);
    }
    const siteExists = baseSiteIds.has(site.id);
    const edgeExists = baseEdgeIds.has(edge.id);
    if (siteExists !== edgeExists) {
      throw new Error(`framework build site ${site.id} conflicts with an existing evidence layer`);
    }
    if (!siteExists) retainedSiteIds.add(site.id);
    return !siteExists;
  });
  const edges = delta.edges.filter((edge) => retainedSiteIds.has(edge.site_id!));
  const existingDiagnostics = new Set(baseDiagnosticIds);
  const diagnostics = delta.diagnostics.filter((diagnostic) => !existingDiagnostics.has(diagnostic.id));
  const reconciled = { nodes, sites, edges, diagnostics };
  validateFrameworkBuildDelta(reconciled, descriptor, provenance, baseNodes);
  return reconciled;
}

/** Validates the full dynamic framework build delta before protocol emission. */
export function validateFrameworkBuildDelta(
  delta: FrameworkBuildDelta,
  descriptor: FrameworkBuildDescriptor,
  provenance: FrameworkBuildProvenance,
  baseNodes: readonly GraphNode[],
): void {
  validateDescriptor(descriptor);
  validateFrameworkBuildProvenance(provenance);
  const base = new Map(baseNodes.map((node) => [node.id, node]));
  const nodes = new Map<string, GraphNode>();
  for (const node of delta.nodes) {
    if (nodes.has(node.id)) throw new Error(`framework build graph repeats node ${node.id}`);
    const existing = base.get(node.id);
    if (existing !== undefined) {
      if (!sameJson(existing, node)) {
        throw new Error(`framework build graph conflicts with base node ${node.id}`);
      }
    } else {
      validateGeneratedNode(node, descriptor, provenance);
    }
    nodes.set(node.id, node);
  }

  const sites = new Map<string, DependencySite>();
  for (const site of delta.sites) {
    if (sites.has(site.id)) throw new Error(`framework build graph repeats site ${site.id}`);
    if (!FRAMEWORK_BUILD_RELATION_KINDS.has(site.kind)) {
      throw new Error(`framework build graph contains unsupported site kind ${site.kind}`);
    }
    if (site.profile_id !== provenance.profile_id || site.precision !== "observed") {
      throw new Error(`framework build site ${site.id} has incompatible profile or precision`);
    }
    if (site.target_ids.length !== 1 || site.specifier.length === 0) {
      throw new Error(`framework build site ${site.id} has an invalid target closure`);
    }
    const primary = evidenceProvenance(site.evidence, descriptor, provenance, site.id);
    const canonicalCondition = canonicalizeCondition(site.condition);
    if (!sameJson(site.condition, canonicalCondition)) {
      throw new Error(`framework build site ${site.id} has a non-canonical condition`);
    }
    if (site.resolution_status === "resolved") {
      if (site.reason !== null) throw new Error(`resolved framework build site ${site.id} has a reason`);
    } else if (site.resolution_status === "unresolved") {
      if (site.reason === null
        || !FRAMEWORK_BUILD_INCOMPLETE_REASONS.has(site.reason as FrameworkBuildIncompleteReason)) {
        throw new Error(`unresolved framework build site ${site.id} lacks a bounded reason`);
      }
    } else {
      throw new Error(`framework build site ${site.id} uses unsupported status ${site.resolution_status}`);
    }
    if (!nodes.has(site.source)) {
      throw new Error(`framework build site ${site.id} references missing source ${site.source}`);
    }
    const target = nodes.get(site.target_ids[0]!);
    if (target === undefined) {
      throw new Error(`framework build site ${site.id} references missing target ${site.target_ids[0]}`);
    }
    if (site.resolution_status === "resolved"
      ? target.kind === "unknown_target" || target.kind === "external_system"
      : target.kind !== "unknown_target") {
      throw new Error(`framework build site ${site.id} fabricates its resolution status`);
    }
    const expectedId = stableId("site", relationIdentity(
      descriptor,
      site.source,
      site.kind,
      site.specifier,
      site.profile_id,
      canonicalCondition,
      site.resolution_status,
      site.reason,
      primary,
    ));
    if (site.id !== expectedId) {
      throw new Error(`framework build site ${site.id} has a non-canonical stable identity`);
    }
    sites.set(site.id, site);
  }

  const edges = new Map<string, GraphEdge>();
  for (const edge of delta.edges) {
    if (edges.has(edge.id)) throw new Error(`framework build graph repeats edge ${edge.id}`);
    const site = sites.get(edge.site_id ?? "");
    if (site === undefined
      || edge.kind !== site.kind
      || edge.source !== site.source
      || !site.target_ids.includes(edge.target)
      || edge.phase !== "build"
      || edge.profile_id !== provenance.profile_id
      || edge.precision !== "observed"
      || edge.resolution_status !== site.resolution_status
      || !sameJson(edge.condition, site.condition)
      || !sameJson(edge.evidence, site.evidence)
      || edge.generated !== true) {
      throw new Error(`framework build edge ${edge.id} disagrees with its site`);
    }
    const environment = edge.environment === "client" ? "browser" : edge.environment;
    if (environment === "any" || !conditionAllowsEnvironment(edge.condition, environment)) {
      throw new Error(`framework build edge ${edge.id} has an unbounded environment`);
    }
    evidenceProvenance(edge.evidence, descriptor, provenance, edge.id);
    const expectedId = stableId("edge", {
      contract_version: FRAMEWORK_BUILD_GRAPH_CONTRACT_VERSION,
      kind: edge.kind,
      site_id: site.id,
      target: edge.target,
      phase: "build",
    });
    if (edge.id !== expectedId) {
      throw new Error(`framework build edge ${edge.id} has a non-canonical stable identity`);
    }
    edges.set(edge.id, edge);
  }
  for (const site of sites.values()) {
    const linked = [...edges.values()].filter((edge) => edge.site_id === site.id);
    if (linked.length !== 1 || linked[0]?.target !== site.target_ids[0]) {
      throw new Error(`framework build site ${site.id} does not have an exact edge closure`);
    }
  }
  for (const diagnostic of delta.diagnostics) {
    if (diagnostic.profile_id !== provenance.profile_id
      || diagnostic.properties?.framework !== descriptor.framework
      || diagnostic.properties?.capability !== descriptor.capability
      || diagnostic.properties?.contract_version !== FRAMEWORK_BUILD_GRAPH_CONTRACT_VERSION) {
      throw new Error(`framework build diagnostic ${diagnostic.id} has incompatible provenance`);
    }
    if (diagnostic.evidence !== undefined) {
      evidenceProvenance(diagnostic.evidence, descriptor, provenance, diagnostic.id);
    }
  }
}

export function frameworkBuildCoverage(
  sites: readonly DependencySite[],
  completion: FrameworkBuildCompletion = { status: "complete", reason: null },
): Coverage {
  if (completion.status === "complete" && completion.reason !== null) {
    throw new Error("complete framework build coverage must not include an incomplete reason");
  }
  if (completion.status !== "complete"
    && (completion.reason === null || !FRAMEWORK_BUILD_INCOMPLETE_REASONS.has(completion.reason))) {
    throw new Error("incomplete framework build coverage requires a bounded reason");
  }
  const counts = {
    resolved: 0,
    candidates: 0,
    external: 0,
    unresolved: 0,
  };
  const reasons = new Set<string>();
  for (const site of sites) {
    counts[site.resolution_status] += 1;
    if (site.resolution_status === "unresolved" && site.reason !== null) reasons.add(site.reason);
  }
  if (completion.reason !== null) reasons.add(completion.reason);
  return {
    profiles: 1,
    files_discovered: 0,
    files_analyzed: 0,
    files_skipped: 0,
    dependency_sites: sites.length,
    ...counts,
    unsupported_syntax: 0,
    project_code_executed: true,
    completeness: completion.status === "complete" ? ["build-observed"] : [],
    reasons: [...reasons].sort(compareUtf8),
  };
}

export function frameworkBuildProtocolEvents(
  root: string,
  delta: FrameworkBuildDelta,
  provenance: FrameworkBuildProvenance,
  sourceRevision: string,
  descriptor: FrameworkBuildDescriptor,
  profile: FrameworkBuildProfile,
): ProtocolEvent[] {
  const common = {
    protocol_version: "1.0" as const,
    scan_id: provenance.build_run_id,
    adapter: "web" as const,
    adapter_version: "0.5.3" as const,
  };
  let seq = 0;
  const event = (kind: string, payload: Record<string, unknown>): ProtocolEvent => ({
    ...common,
    event: kind,
    seq: ++seq,
    ...payload,
  });
  const coverage = frameworkBuildCoverage(delta.sites);
  const events: ProtocolEvent[] = [event("scan_started", {
    root,
    safe_mode: false,
    project_code_executed: true,
  })];
  events.push(event("profile_declared", {
    profile: {
      id: provenance.profile_id,
      language: "typescript",
      toolchain: profile.toolchain,
      command: profile.command,
      target: "production",
      features: [
        ...new Set([
          FRAMEWORK_BUILD_GRAPH_CONTRACT_VERSION,
          descriptor.capability,
          ...(profile.features ?? []),
        ]),
      ].sort(compareUtf8),
      environment: { mode: "production" },
      source_revision: sourceRevision,
      properties: {
        ...(profile.properties ?? {}),
        framework: descriptor.framework,
        observer: descriptor.observer,
        observer_version: descriptor.observerVersion,
        framework_build_capability: descriptor.capability,
        framework_build_graph_contract_version: FRAMEWORK_BUILD_GRAPH_CONTRACT_VERSION,
        framework_build_node_count: String(delta.nodes.length),
        framework_build_site_count: String(delta.sites.length),
        framework_build_edge_count: String(delta.edges.length),
        framework_build_diagnostic_count: String(delta.diagnostics.length),
        project_code_executed: true,
      },
    },
  }));
  for (const node of delta.nodes) events.push(event("node_upsert", { node }));
  for (const site of delta.sites) events.push(event("dependency_site", { site }));
  for (const edge of delta.edges) events.push(event("edge_upsert", { edge }));
  for (const diagnostic of delta.diagnostics) events.push(event("diagnostic", { diagnostic }));
  events.push(event("profile_completed", { profile_id: provenance.profile_id, coverage }));
  events.push(event("scan_completed", { coverage }));
  return events;
}
