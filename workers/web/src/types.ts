import { createHash } from "node:crypto";

export const PROTOCOL_VERSION = "1.0" as const;
export const ADAPTER = "web" as const;
export const ADAPTER_VERSION = "0.4.0" as const;

const DEFAULT_WEB_ENVIRONMENTS = ["browser", "server"] as const;

function readWebEnvironments(): { environments: string[]; issue: string | null } {
  const raw = process.env.DEPGRAPH_PROFILE_CONFIG;
  if (!raw) return { environments: [...DEFAULT_WEB_ENVIRONMENTS], issue: null };
  try {
    const parsed: unknown = JSON.parse(raw);
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("profile config must be an object");
    const value = (parsed as Record<string, unknown>).web_environments;
    if (value === undefined) return { environments: [...DEFAULT_WEB_ENVIRONMENTS], issue: null };
    if (!Array.isArray(value) || !value.every((item) => typeof item === "string")) throw new Error("web_environments must be an array of strings");
    const environments = [...new Set(value.map((item) => item.trim().toLowerCase()).filter(Boolean))].sort();
    if (environments.length === 0) return { environments: [...DEFAULT_WEB_ENVIRONMENTS], issue: "web_environments was empty; browser/server defaults were used" };
    return { environments, issue: null };
  } catch (error) {
    return {
      environments: [...DEFAULT_WEB_ENVIRONMENTS],
      issue: `DEPGRAPH_PROFILE_CONFIG was not usable: ${error instanceof Error ? error.message : String(error)}`,
    };
  }
}

const profileSelection = readWebEnvironments();
export const WEB_ENVIRONMENTS = profileSelection.environments;
export const PROFILE_CONFIG_ISSUE = profileSelection.issue;
const profileDigest = createHash("sha256")
  .update(JSON.stringify({ environments: WEB_ENVIRONMENTS, language: "web", mode: "production" }), "utf8")
  .digest("hex");
export const PROFILE_ID = `profile:sha256:${profileDigest}`;

export type JsonPrimitive = string | number | boolean | null;
export type JsonValue = JsonPrimitive | JsonValue[] | { [key: string]: JsonValue };

export type Condition =
  | { op: "all" | "any"; conditions: Condition[] }
  | { op: "not"; condition: Condition }
  | { op: "eq"; key: string; value: JsonPrimitive }
  | { op: "in"; key: string; values: JsonPrimitive[] }
  | { op: "defined"; key: string };

export function compareUtf8(left: string, right: string): number {
  // Rust's protocol canonicalizer sorts serialized JSON as UTF-8 bytes.
  // JavaScript's relational string order uses UTF-16 code units and differs
  // for supplementary-plane characters, which would otherwise change IDs.
  const bytes = Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8"));
  return bytes || (left < right ? -1 : left > right ? 1 : 0);
}

function canonicalConditionList(conditions: readonly Condition[]): Condition[] {
  return [...new Map(conditions
    .map((condition) => [JSON.stringify(condition), condition] as const)
    .sort(([left], [right]) => compareUtf8(left, right))).values()];
}

/** Mirrors the protocol's condition canonicalization before IDs are derived. */
export function canonicalizeCondition(condition: Condition): Condition {
  if (condition.op === "eq" || condition.op === "defined") return { ...condition };
  if (condition.op === "in") {
    const values = [...new Map(condition.values
      .map((value) => [JSON.stringify(value), value] as const)
      .sort(([left], [right]) => compareUtf8(left, right))).values()];
    return values.length === 1
      ? { op: "eq", key: condition.key, value: values[0]! }
      : { op: "in", key: condition.key, values };
  }
  if (condition.op === "not") {
    const child = canonicalizeCondition(condition.condition);
    return child.op === "not" ? child.condition : { op: "not", condition: child };
  }
  const flattened: Condition[] = [];
  for (const value of condition.conditions) {
    const child = canonicalizeCondition(value);
    if (condition.op === "all" && child.op === "all") {
      flattened.push(...child.conditions);
    } else if (condition.op === "any" && child.op === "all" && child.conditions.length === 0) {
      return { op: "all", conditions: [] };
    } else if (condition.op === "any" && child.op === "any") {
      flattened.push(...child.conditions);
    } else {
      flattened.push(child);
    }
  }
  const unique = canonicalConditionList(flattened);
  if (condition.op === "all") {
    if (unique.length === 0) return { op: "all", conditions: [] };
    if (unique.length === 1) return unique[0]!;
    return { op: "all", conditions: unique };
  }
  if (unique.length === 1) return unique[0]!;
  return { op: "any", conditions: unique };
}

export function aggregateConditions(conditions: readonly Condition[]): Condition {
  return canonicalizeCondition({ op: "any", conditions: [...conditions] });
}

export const WEB_CONDITION: Condition = canonicalizeCondition({
  op: "all",
  conditions: [
    { op: "eq", key: "mode", value: "production" },
    { op: "in", key: "environment", values: WEB_ENVIRONMENTS },
  ],
});

export const WEB_UNIVERSAL_ENVIRONMENT = WEB_ENVIRONMENTS.join(",");

export function preferredWebEnvironment(preferred: string): string {
  return WEB_ENVIRONMENTS.includes(preferred) ? preferred : WEB_ENVIRONMENTS[0]!;
}

export type ResolutionStatus = "resolved" | "candidates" | "external" | "unresolved";
export type Precision = "exact" | "overapprox" | "heuristic" | "observed";

export interface Evidence {
  kind: "source" | "semantic" | "build" | "runtime";
  extractor: string;
  extractor_version: string;
  path: string;
  start_line: number;
  start_column: number;
  end_line: number;
  end_column: number;
  detail?: string;
  properties?: Record<string, JsonValue>;
}

export interface GraphNode {
  id: string;
  kind:
    | "workspace"
    | "package_instance"
    | "build_unit"
    | "module"
    | "file"
    | "component"
    | "route"
    | "server_function"
    | "middleware"
    | "symbol"
    | "type"
    | "external_system"
    | "unknown_target";
  locator: string;
  display_name: string;
  properties: Record<string, JsonValue>;
}

export interface DependencySite {
  id: string;
  source: string;
  kind: string;
  specifier: string;
  resolution_status: ResolutionStatus;
  target_ids: string[];
  profile_id: string;
  condition: Condition;
  precision: Precision;
  reason: string | null;
  evidence: Evidence[];
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  kind: string;
  site_id: string | null;
  phase: "source" | "semantic" | "build" | "runtime";
  environment: string;
  profile_id: string;
  condition: Condition;
  resolution_status: ResolutionStatus;
  precision: Precision;
  generated: boolean;
  evidence: Evidence[];
}

export interface Diagnostic {
  id: string;
  severity: "info" | "warning" | "error";
  code: string;
  message: string;
  path: string | null;
  profile_id: string;
  evidence?: Evidence[];
  properties?: Record<string, JsonValue>;
}

export interface FileCoverage {
  file_id: string;
  path: string;
  expected_sites: number;
  produced_sites: number;
  skipped_sites: number;
  resolved: number;
  candidates: number;
  external: number;
  unresolved: number;
  unsupported_syntax: number;
}

export interface Coverage {
  profiles: number;
  files_discovered: number;
  files_analyzed: number;
  files_skipped: number;
  dependency_sites: number;
  resolved: number;
  candidates: number;
  external: number;
  unresolved: number;
  unsupported_syntax: number;
  project_code_executed: boolean;
  completeness: string[];
  reasons: string[];
}

export interface ScanModel {
  nodes: GraphNode[];
  sites: DependencySite[];
  edges: GraphEdge[];
  diagnostics: Diagnostic[];
  files: FileCoverage[];
  coverage: Coverage;
  repositoryIdentity: string;
  packageManager: string;
  lockfile: string | null;
  detectedFrameworks: string[];
  typeScriptProject: TypeScriptProjectSummary;
  frameworkSemantic: FrameworkSemanticSummary;
}

export interface FrameworkSemanticSummary {
  status: "not-emitted" | "emitted" | "discarded";
  nodes: number;
  sites: number;
  edges: number;
  emittedFrameworks: string[];
  pendingFrameworks: string[];
  completionStatus: "not-detected" | "complete" | "incomplete";
  completionIssueCount: number;
  completionLedger: FrameworkCompletenessEntry[];
}

export interface FrameworkCompletenessEntry {
  framework: string;
  required_capabilities: string[];
  emitted_capabilities: string[];
  status: "complete" | "incomplete";
  reasons: string[];
}

export interface TypeScriptProjectSummary {
  status: "ready";
  rootFiles: number;
  programFiles: number;
  staticConfigFiles: number;
  pathMappings: number;
  standardLibraryFiles: number;
  typeCheckerQueries: number;
  semanticDiagnostics: number;
  emittedSemanticDiagnostics: number;
  definitionGraphStatus: "ready" | "failed";
  semanticNodes: number;
  semanticRelations: number;
  semanticSites: number;
  semanticCallSites: number;
  semanticIssues: number;
}

export interface CommonEvent {
  event: string;
  protocol_version: typeof PROTOCOL_VERSION;
  scan_id: string;
  adapter: typeof ADAPTER;
  adapter_version: typeof ADAPTER_VERSION;
  seq: number;
}

export type ProtocolEvent = CommonEvent & Record<string, unknown>;
