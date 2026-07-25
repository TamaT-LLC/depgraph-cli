import { createHash } from "node:crypto";
import { lstat, open, realpath } from "node:fs/promises";
import path from "node:path";
import { canonicalJson, stableId } from "./ids";
import {
  FRAMEWORK_BUILD_GRAPH_CONTRACT_VERSION,
  deduplicateFrameworkBuildRecords,
  frameworkBuildCondition,
  frameworkBuildDiagnostic,
  frameworkBuildEvidence,
  frameworkBuildGeneratedNode,
  frameworkBuildProtocolEvents,
  frameworkBuildRelation,
  reconcileFrameworkBuildBaseRecords,
  validateFrameworkBuildDelta,
  type FrameworkBuildDescriptor,
} from "./framework-build-contract";
import {
  compareUtf8,
  type Condition,
  type DependencySite,
  type Diagnostic,
  type Evidence,
  type GraphEdge,
  type GraphNode,
  type JsonValue,
  type ProtocolEvent,
} from "./types";

export const NEXT_BUILD_OBSERVER = "next-adapter-observer" as const;
export const NEXT_BUILD_OBSERVER_VERSION = "0.2.0" as const;
export const NEXT_BUILD_OBSERVER_CAPABILITY = "next-adapter-api-16.2-v1" as const;
export const NEXT_BUILD_OBSERVATION_SCHEMA = "next-build-observation-v2" as const;
export const NEXT_BUILD_MANIFEST_CONTRACT = "next-adapter-manifests-v1" as const;
export const NEXT_FRAMEWORK_BUILD_DESCRIPTOR: FrameworkBuildDescriptor = Object.freeze({
  framework: "next",
  observer: NEXT_BUILD_OBSERVER,
  observerVersion: NEXT_BUILD_OBSERVER_VERSION,
  capability: NEXT_BUILD_OBSERVER_CAPABILITY,
});

const MAX_OUTPUTS = 20_000;
const MAX_ROUTING_ENTRIES = 20_000;
const MAX_ASSETS_PER_OUTPUT = 2_000;
const MAX_TOTAL_ASSETS = 100_000;
const MAX_METADATA_ENTRIES = 2_000;
const MAX_ARTIFACT_BYTES = 64 * 1024 * 1024;
const MAX_SAFE_STRING = 4_096;
const ROUTING_PHASES = [
  "beforeMiddleware", "beforeFiles", "afterFiles", "dynamicRoutes", "onMatch", "fallback",
] as const;
const ROUTE_OUTPUT_TYPES = new Set(["PAGES", "PAGES_API", "APP_PAGE", "APP_ROUTE", "PRERENDER"]);
const REQUEST_OUTPUT_TYPES = new Set(["PAGES", "PAGES_API", "APP_PAGE", "APP_ROUTE"]);
const OUTPUT_COLLECTIONS = [
  ["pages", "PAGES"],
  ["pagesApi", "PAGES_API"],
  ["appPages", "APP_PAGE"],
  ["appRoutes", "APP_ROUTE"],
  ["prerenders", "PRERENDER"],
  ["staticFiles", "STATIC_FILE"],
] as const;

type Awaitable<T> = T | Promise<T>;
type UnknownRecord = Record<string, unknown>;

export interface NextAdapterModifyContext {
  phase: string;
  nextVersion: string;
}

export interface NextAdapterRoute {
  source?: string;
  sourceRegex: string;
  destination?: string;
  headers?: Record<string, string>;
  has?: unknown[];
  missing?: unknown[];
  status?: number;
  priority?: boolean;
}

export interface NextAdapterOutput {
  id: string;
  type: string;
  pathname: string;
  filePath?: string;
  sourcePage?: string;
  runtime?: "nodejs" | "edge";
  assets?: Record<string, string>;
  wasmAssets?: Record<string, string>;
  immutableHash?: string;
  parentOutputId?: string;
  fallback?: { filePath?: string };
  config?: UnknownRecord;
}

export interface NextAdapterBuildContext {
  routing: Record<string, unknown>;
  outputs: Record<string, unknown>;
  projectDir: string;
  repoRoot: string;
  distDir: string;
  config: UnknownRecord;
  nextVersion: string;
  buildId: string;
}

export interface NextAdapterLike {
  name: string;
  modifyConfig?: (config: UnknownRecord, context: NextAdapterModifyContext) => Awaitable<UnknownRecord>;
  onBuildComplete?: (context: NextAdapterBuildContext) => Awaitable<void>;
}

export interface NextBuildObserverSink {
  write(observation: NextBuildObservation): Awaitable<void>;
}

export interface NextAdapterPreflightInput {
  nextVersion: string;
  configuredAdapterPath: string | null;
  observerAdapterPath: string;
  loadExistingAdapter?: (specifier: string) => Awaitable<unknown>;
  sink: NextBuildObserverSink;
  readArtifact?: ArtifactReader;
}

export interface NextAdapterCapability {
  capability: typeof NEXT_BUILD_OBSERVER_CAPABILITY;
  nextVersion: string;
  existingAdapter: "absent" | "chainable";
}

export type ArtifactReader = (absolutePath: string, logicalPath: string, repoRoot: string) => Awaitable<string>;

export interface NextObservedConfig {
  output: "default" | "standalone" | "export";
  base_path: string;
  trailing_slash: boolean;
  react_strict_mode: boolean | null;
  powered_by_header: boolean | null;
  generate_etags: boolean | null;
  compress: boolean | null;
  adapter_present: boolean;
  environment_key_count: number;
}

export interface NextObservedRoutingEntry {
  phase: typeof ROUTING_PHASES[number];
  source: string | null;
  source_regex_digest: string;
  destination: string | null;
  canonical_route_pattern: string | null;
  variant: "route" | "rsc" | "data" | "segment" | "custom";
  source_present: boolean;
  destination_present: boolean;
  status: number | null;
  priority: boolean;
  header_count: number;
  predicate_count: number;
}

export interface NextObservedAsset {
  logical_path: string;
  digest: string;
  kind: "asset" | "wasm";
  role: "client_chunk" | "server_chunk" | "edge_asset" | "wasm" | "traced_asset";
  boundary: "client" | "server" | "edge";
}

export interface NextObservedOutput {
  output_identity_digest: string;
  type: string;
  pathname: string;
  source_page: string | null;
  canonical_route_pattern: string | null;
  variant: "route" | "rsc" | "data" | "prerender" | "static_route" | "client_chunk" | "static_asset" | "middleware";
  artifact_role: "route_entry" | "rsc_payload" | "data_endpoint" | "prerender" | "static_route" | "client_chunk" | "static_asset" | "middleware";
  boundary: "client" | "server" | "edge" | "static";
  metadata_kind: "robots" | "sitemap" | "manifest" | "favicon" | "icon" | "apple-icon" | "opengraph-image" | "twitter-image" | null;
  runtime: "nodejs" | "edge" | "static";
  logical_artifact_path: string;
  artifact_digest: string;
  assets: NextObservedAsset[];
  parent_output_identity_digest: string | null;
  prerender_group_id: number | null;
  edge_runtime: {
    module_path: string;
    entry_key_digest: string;
    handler_export: "handler";
  } | null;
  config: {
    max_duration: number | null;
    preferred_region_count: number;
    environment_key_count: number;
  };
}

export interface NextObservedManifests {
  contract_version: typeof NEXT_BUILD_MANIFEST_CONTRACT;
  route_manifest_digest: string;
  build_manifest_digest: string;
  route_entry_count: number;
  output_entry_count: number;
}

export interface NextBuildObservation {
  schema_version: typeof NEXT_BUILD_OBSERVATION_SCHEMA;
  observer: typeof NEXT_BUILD_OBSERVER;
  observer_version: typeof NEXT_BUILD_OBSERVER_VERSION;
  capability: typeof NEXT_BUILD_OBSERVER_CAPABILITY;
  next_version: string;
  config: NextObservedConfig;
  manifests: NextObservedManifests;
  routing: NextObservedRoutingEntry[];
  outputs: NextObservedOutput[];
}

export interface NextBuildProvenance {
  build_run_id: string;
  profile_id: string;
  command_plan_digest: string;
  toolchain_executable_digest: string;
  environment_key_set_digest: string;
  validated_output_digest: string;
}

export interface NextBuildGraphInput {
  observation: NextBuildObservation;
  provenance: NextBuildProvenance;
  baseNodes: readonly GraphNode[];
  baseEdges?: readonly GraphEdge[];
  baseDiagnosticIds?: readonly string[];
}

export interface NextBuildGraphDelta {
  nextVersion: string;
  nodes: GraphNode[];
  sites: DependencySite[];
  edges: GraphEdge[];
  diagnostics: Diagnostic[];
}

export class NextBuildObserverError extends Error {
  readonly code: string;

  constructor(code: string) {
    super(code);
    this.name = "NextBuildObserverError";
    this.code = code;
  }
}

export function nextBuildFailureDiagnostic(error: unknown, profileId: string): Diagnostic {
  const code = error instanceof NextBuildObserverError && /^web\.next_build_[a-z0-9_]+$/u.test(error.code)
    ? error.code
    : "web.next_build_observer_failed";
  const properties: Record<string, JsonValue> = {
    framework: "next",
    observer: NEXT_BUILD_OBSERVER,
    observer_version: NEXT_BUILD_OBSERVER_VERSION,
    capability: NEXT_BUILD_OBSERVER_CAPABILITY,
    contract_version: FRAMEWORK_BUILD_GRAPH_CONTRACT_VERSION,
    observer_failure: true,
  };
  return {
    id: stableId("diagnostic", { code, profile_id: profileId, properties }),
    severity: "error",
    code,
    message: `${code}: Next build observation was not promoted`,
    path: null,
    profile_id: profileId,
    properties,
  };
}

function fail(code: string): never {
  throw new NextBuildObserverError(code);
}

function record(value: unknown): UnknownRecord | null {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as UnknownRecord
    : null;
}

function sha256(value: string | Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}

function digestIdentity(value: JsonValue): string {
  return sha256(canonicalJson(value));
}

function boundedString(value: unknown): string | null {
  if (typeof value !== "string" || value.length === 0 || value.length > MAX_SAFE_STRING) return null;
  if ([...value].some((character) => character.charCodeAt(0) < 0x20 || character.charCodeAt(0) === 0x7f)) return null;
  return value;
}

function canonicalRelativePath(value: unknown): string | null {
  const raw = boundedString(value);
  const portable = raw?.replaceAll("\\", "/");
  if (portable === undefined || path.posix.isAbsolute(portable)
    || /^[a-z]:\//iu.test(portable) || portable.startsWith("//")) return null;
  const normalized = path.posix.normalize(portable).replace(/^\.\//u, "");
  if (normalized === "." || normalized === ".." || normalized.startsWith("../") || normalized.includes("/../")) return null;
  return normalized;
}

function logicalFromAbsolute(repoRoot: string, absolutePath: unknown): string | null {
  const raw = boundedString(absolutePath);
  if (raw === null || !path.isAbsolute(raw)) return null;
  const relative = path.relative(path.resolve(repoRoot), path.resolve(raw));
  if (relative === "" || relative.startsWith("..") || path.isAbsolute(relative)) return null;
  return canonicalRelativePath(relative);
}

function canonicalPathname(value: unknown, allowEmpty = false): string | null {
  const raw = boundedString(value);
  if (raw === null) return allowEmpty && value === "" ? "" : null;
  if (!raw.startsWith("/") || raw.includes("\\") || raw.includes("?") || raw.includes("#") || /\s/u.test(raw)) return null;
  const normalized = raw.replace(/\/{2,}/gu, "/");
  return normalized.length > 1 ? normalized.replace(/\/$/u, "") : normalized;
}

function canonicalSourcePage(value: unknown): string | null {
  const raw = boundedString(value);
  if (raw === null || raw.includes("\\") || raw.includes("?") || raw.includes("#") || /\s/u.test(raw)) return null;
  const portable = raw.replace(/^\/+/u, "");
  if (portable === "") return "/";
  const normalized = path.posix.normalize(portable);
  if (normalized === "." || normalized === ".." || normalized.startsWith("../") || normalized.includes("/../")) {
    return null;
  }
  return `/${normalized}`;
}

function replaceBuildId(pathname: string, buildId: string): string {
  return pathname
    .split("/")
    .map((segment) => segment === buildId ? "<build-id>" : segment)
    .join("/");
}

function routeVariant(pathname: string): NextObservedRoutingEntry["variant"] {
  if (pathname.includes("/_next/data/") && pathname.endsWith(".json")) return "data";
  if (pathname.endsWith(".rsc")) return "rsc";
  if (pathname.includes(".segments/") || pathname.endsWith(".segment.rsc")) return "segment";
  return "route";
}

function canonicalRoutePattern(
  pathname: string,
  variant: NextObservedRoutingEntry["variant"],
  buildId: string,
): string | null {
  if (variant === "data") {
    const marker = `/_next/data/${buildId}/`;
    const start = pathname.indexOf(marker);
    if (start < 0 || !pathname.endsWith(".json")) return null;
    const prefix = pathname.slice(0, start);
    const route = pathname.slice(start + marker.length, -".json".length);
    const normalizedRoute = route === "index" ? "" : route.replace(/\/index$/u, "");
    return canonicalPathname(`${prefix}/${normalizedRoute}`.replace(/\/{2,}/gu, "/"));
  }
  if (variant === "rsc") {
    const route = pathname.slice(0, -".rsc".length);
    return canonicalPathname(route.endsWith("/index") ? route.slice(0, -"/index".length) || "/" : route);
  }
  if (variant === "segment") {
    const segmentIndex = pathname.indexOf(".segments/");
    const route = segmentIndex >= 0 ? pathname.slice(0, segmentIndex) : pathname.replace(/\.segment\.rsc$/u, "");
    return canonicalPathname(route.endsWith("/index") ? route.slice(0, -"/index".length) || "/" : route);
  }
  return canonicalPathname(pathname);
}

function outputVariant(type: string, pathname: string, buildId: string): NextObservedOutput["variant"] {
  if (type === "MIDDLEWARE") return "middleware";
  if (type === "PRERENDER") return "prerender";
  if (type === "STATIC_FILE") {
    if (pathname.includes("/_next/static/chunks/")) return "client_chunk";
    return pathname.includes("/_next/static/") ? "static_asset" : "static_route";
  }
  const variant = routeVariant(pathname);
  if (variant === "rsc" || variant === "data") return variant;
  if (variant === "segment") return "rsc";
  return canonicalRoutePattern(pathname, variant, buildId) === null ? "static_asset" : "route";
}

function artifactRole(variant: NextObservedOutput["variant"]): NextObservedOutput["artifact_role"] {
  switch (variant) {
    case "route": return "route_entry";
    case "rsc": return "rsc_payload";
    case "data": return "data_endpoint";
    case "prerender": return "prerender";
    case "static_route": return "static_route";
    case "client_chunk": return "client_chunk";
    case "middleware": return "middleware";
    default: return "static_asset";
  }
}

function metadataKind(
  pathname: string,
  sourcePage: string | null,
): NextObservedOutput["metadata_kind"] {
  const value = `${sourcePage ?? ""}\n${pathname}`.toLowerCase();
  for (const kind of [
    "robots", "sitemap", "manifest", "favicon", "apple-icon", "opengraph-image", "twitter-image", "icon",
  ] as const) {
    if (new RegExp(`(?:^|[/.-])${kind}(?:[/.-]|$)`, "u").test(value)) return kind;
  }
  return null;
}

function assetRole(
  logicalPath: string,
  kind: NextObservedAsset["kind"],
  runtime: NextObservedOutput["runtime"],
): Pick<NextObservedAsset, "role" | "boundary"> {
  if (kind === "wasm") return { role: "wasm", boundary: runtime === "edge" ? "edge" : "server" };
  if (/(?:^|\/)\.next\/static\/chunks\//u.test(logicalPath)) {
    return { role: "client_chunk", boundary: "client" };
  }
  if (/(?:^|\/)\.next\/server\/chunks\//u.test(logicalPath)) {
    return { role: "server_chunk", boundary: "server" };
  }
  return runtime === "edge"
    ? { role: "edge_asset", boundary: "edge" }
    : { role: "traced_asset", boundary: "server" };
}

function supportedVersion(version: string): boolean {
  const match = /^(\d+)\.(\d+)\.(\d+)$/u.exec(version);
  return match !== null && Number(match[1]) === 16 && Number(match[2]) >= 2;
}

export function detectNextAdapterCapability(version: string): NextAdapterCapability {
  if (!supportedVersion(version)) fail("web.next_build_version_unsupported");
  return {
    capability: NEXT_BUILD_OBSERVER_CAPABILITY,
    nextVersion: version,
    existingAdapter: "absent",
  };
}

function validateAdapter(value: unknown): NextAdapterLike {
  try {
    const candidate = record(value);
    if (candidate === null || boundedString(candidate.name) === null) {
      fail("web.next_build_existing_adapter_invalid");
    }
    const name = candidate.name as string;
    const modifyConfig = candidate.modifyConfig;
    const onBuildComplete = candidate.onBuildComplete;
    if ((modifyConfig !== undefined && typeof modifyConfig !== "function")
      || (onBuildComplete !== undefined && typeof onBuildComplete !== "function")) {
      fail("web.next_build_existing_adapter_invalid");
    }
    const normalized: NextAdapterLike = { name };
    if (typeof modifyConfig === "function") {
      normalized.modifyConfig = modifyConfig.bind(candidate) as NonNullable<NextAdapterLike["modifyConfig"]>;
    }
    if (typeof onBuildComplete === "function") {
      normalized.onBuildComplete = onBuildComplete.bind(candidate) as NonNullable<NextAdapterLike["onBuildComplete"]>;
    }
    return normalized;
  } catch (error) {
    if (error instanceof NextBuildObserverError) throw error;
    fail("web.next_build_existing_adapter_invalid");
  }
}

function safeBoolean(value: unknown): boolean | null {
  return typeof value === "boolean" ? value : null;
}

export function sanitizeNextConfig(config: UnknownRecord): NextObservedConfig {
  const output = config.output === "standalone" || config.output === "export" ? config.output : "default";
  const basePath = config.basePath === "" ? "" : canonicalPathname(config.basePath, true);
  if (basePath === null) fail("web.next_build_config_metadata_unsafe");
  const environment = record(config.env);
  if (environment !== null && Object.keys(environment).length > MAX_METADATA_ENTRIES) {
    fail("web.next_build_config_metadata_limit_exceeded");
  }
  return {
    output,
    base_path: basePath,
    trailing_slash: config.trailingSlash === true,
    react_strict_mode: safeBoolean(config.reactStrictMode),
    powered_by_header: safeBoolean(config.poweredByHeader),
    generate_etags: safeBoolean(config.generateEtags),
    compress: safeBoolean(config.compress),
    adapter_present: boundedString(config.adapterPath) !== null,
    environment_key_count: environment === null ? 0 : Object.keys(environment).length,
  };
}

async function defaultArtifactReader(absolutePath: string, _logicalPath: string, repoRoot: string): Promise<string> {
  const [canonicalRoot, canonicalArtifact, before] = await Promise.all([
    realpath(repoRoot),
    realpath(absolutePath),
    lstat(absolutePath),
  ]);
  const relative = path.relative(canonicalRoot, canonicalArtifact);
  if (relative === "" || relative.startsWith("..") || path.isAbsolute(relative)
    || !before.isFile() || before.isSymbolicLink() || before.size > MAX_ARTIFACT_BYTES) {
    fail("web.next_build_artifact_unsafe");
  }
  const handle = await open(absolutePath, "r");
  try {
    const opened = await handle.stat();
    if (!opened.isFile() || opened.size > MAX_ARTIFACT_BYTES
      || opened.dev !== before.dev || opened.ino !== before.ino) {
      fail("web.next_build_artifact_unsafe");
    }
    return sha256(await handle.readFile());
  } finally {
    await handle.close();
  }
}

function sanitizeRouting(
  routing: Record<string, unknown>,
  buildId: string,
): NextObservedRoutingEntry[] {
  const entries: NextObservedRoutingEntry[] = [];
  for (const phase of ROUTING_PHASES) {
    const routes = routing[phase];
    if (routes === undefined) fail("web.next_build_manifest_missing");
    if (!Array.isArray(routes)) fail("web.next_build_manifest_invalid");
    for (const value of routes) {
      if (entries.length >= MAX_ROUTING_ENTRIES) fail("web.next_build_routing_limit_exceeded");
      const route = record(value);
      if (route === null || boundedString(route.sourceRegex) === null) {
        fail("web.next_build_manifest_invalid");
      }
      const rawSource = canonicalPathname(route.source);
      const rawDestination = canonicalPathname(route.destination);
      if ((route.source !== undefined && rawSource === null)
        || (route.destination !== undefined && rawDestination === null)) {
        fail("web.next_build_manifest_invalid");
      }
      const source = rawSource === null ? null : replaceBuildId(rawSource, buildId);
      const destination = rawDestination === null ? null : replaceBuildId(rawDestination, buildId);
      const variant = rawSource === null
        ? "custom"
        : routeVariant(rawSource);
      const routePattern = phase === "dynamicRoutes" && rawSource !== null
        ? canonicalRoutePattern(rawSource, variant, buildId)
        : null;
      const headerCount = record(route.headers) === null ? 0 : Object.keys(record(route.headers)!).length;
      const predicateCount = (Array.isArray(route.has) ? route.has.length : 0)
        + (Array.isArray(route.missing) ? route.missing.length : 0);
      if (headerCount > MAX_METADATA_ENTRIES || predicateCount > MAX_METADATA_ENTRIES) {
        fail("web.next_build_routing_metadata_limit_exceeded");
      }
      entries.push({
        phase,
        source,
        source_regex_digest: sha256((route.sourceRegex as string).replaceAll(buildId, "<build-id>")),
        destination,
        canonical_route_pattern: routePattern,
        variant,
        source_present: route.source !== undefined,
        destination_present: route.destination !== undefined,
        status: Number.isSafeInteger(route.status) && Number(route.status) >= 100 && Number(route.status) <= 599
          ? Number(route.status)
          : null,
        priority: route.priority === true,
        header_count: headerCount,
        predicate_count: predicateCount,
      });
    }
  }
  return entries.sort((left, right) => compareUtf8(
    canonicalJson(left as unknown as JsonValue),
    canonicalJson(right as unknown as JsonValue),
  ));
}

function outputArray(outputs: Record<string, unknown>, key: string): unknown[] {
  const value = outputs[key];
  if (value === undefined) fail("web.next_build_manifest_missing");
  if (!Array.isArray(value)) fail("web.next_build_manifest_invalid");
  return value;
}

interface SanitizedOutputRecord {
  rawId: string;
  rawParentId: string | null;
  output: NextObservedOutput;
}

function stableOutputIdentity(output: NextObservedOutput): string {
  return digestIdentity({
    type: output.type,
    pathname: output.pathname,
    source_page: output.source_page,
    canonical_route_pattern: output.canonical_route_pattern,
    variant: output.variant,
    artifact_role: output.artifact_role,
    boundary: output.boundary,
    metadata_kind: output.metadata_kind,
    runtime: output.runtime,
    logical_artifact_path: output.logical_artifact_path,
    artifact_digest: output.artifact_digest,
    parent_output_identity_digest: output.parent_output_identity_digest,
    prerender_group_id: output.prerender_group_id,
    edge_runtime: output.edge_runtime,
  });
}

async function digestArtifact(
  repoRoot: string,
  absolutePath: unknown,
  logicalHint: unknown,
  readArtifact: ArtifactReader,
): Promise<{ logicalPath: string; digest: string }> {
  const rawAbsolute = boundedString(absolutePath);
  const contained = logicalFromAbsolute(repoRoot, absolutePath);
  const hinted = logicalHint === undefined ? null : canonicalRelativePath(logicalHint);
  if (rawAbsolute === null || contained === null || !path.isAbsolute(rawAbsolute)
    || (logicalHint !== undefined && hinted !== contained)) {
    fail("web.next_build_artifact_path_unsafe");
  }
  const logicalPath = contained;
  let digest: string;
  try {
    digest = await readArtifact(rawAbsolute, logicalPath, repoRoot);
  } catch (error) {
    if (error instanceof NextBuildObserverError) throw error;
    fail("web.next_build_artifact_read_failed");
  }
  if (!/^[a-f0-9]{64}$/u.test(digest)) fail("web.next_build_artifact_digest_invalid");
  return { logicalPath, digest };
}

async function sanitizeOutput(
  raw: unknown,
  expectedType: string,
  repoRoot: string,
  buildId: string,
  readArtifact: ArtifactReader,
): Promise<SanitizedOutputRecord> {
  const output = record(raw);
  if (output === null || boundedString(output.id) === null || output.type !== expectedType) {
    fail("web.next_build_manifest_invalid");
  }
  const pathname = canonicalPathname(output.pathname);
  if (pathname === null) fail("web.next_build_output_pathname_unsafe");
  const sourcePage = output.sourcePage === undefined ? null : canonicalSourcePage(output.sourcePage);
  if (output.sourcePage !== undefined && sourcePage === null) fail("web.next_build_source_page_unsafe");
  const requestOutput = REQUEST_OUTPUT_TYPES.has(expectedType) || expectedType === "MIDDLEWARE";
  if (requestOutput && sourcePage === null) fail("web.next_build_partial_build");
  const runtime: NextObservedOutput["runtime"] = output.runtime === "edge"
    ? "edge"
    : output.runtime === "nodejs"
      ? "nodejs"
      : "static";
  if (requestOutput && runtime === "static") fail("web.next_build_partial_build");
  let variant = outputVariant(expectedType, pathname, buildId);
  let mainPath: unknown = output.filePath;
  if (expectedType === "PRERENDER") mainPath = record(output.fallback)?.filePath;
  if (expectedType !== "PRERENDER" && mainPath === undefined) fail("web.next_build_partial_build");
  const main = mainPath === undefined
    ? { logicalPath: `.next/observed/${sha256(`${expectedType}\0${pathname}`)}.metadata`, digest: sha256(canonicalJson({ expectedType, pathname })) }
    : await digestArtifact(repoRoot, mainPath, undefined, readArtifact);
  if (expectedType === "STATIC_FILE" && variant === "static_route"
    && metadataKind(pathname, sourcePage) === null
    && !/\.(?:html|body)$/u.test(main.logicalPath)) {
    variant = "static_asset";
  }
  const assets: NextObservedAsset[] = [];
  for (const [kind, value] of [["asset", output.assets], ["wasm", output.wasmAssets]] as const) {
    const map = value === undefined ? {} : record(value);
    if (map === null || Object.keys(map).length > MAX_ASSETS_PER_OUTPUT) {
      fail("web.next_build_asset_contract_invalid");
    }
    for (const [logicalHint, absolutePath] of Object.entries(map)) {
      const artifact = await digestArtifact(repoRoot, absolutePath, logicalHint, readArtifact);
      const stableLogicalPath = replaceBuildId(artifact.logicalPath, buildId);
      assets.push({
        logical_path: stableLogicalPath,
        digest: artifact.digest,
        kind,
        ...assetRole(stableLogicalPath, kind, runtime),
      });
    }
  }
  assets.sort((left, right) => compareUtf8(
    canonicalJson(left as unknown as JsonValue),
    canonicalJson(right as unknown as JsonValue),
  ));
  const configRecord = record(output.config);
  if (expectedType !== "STATIC_FILE" && configRecord === null) fail("web.next_build_partial_build");
  const config = configRecord ?? {};
  const preferredRegion = config.preferredRegion;
  const environment = record(config.env);
  if ((Array.isArray(preferredRegion) && preferredRegion.length > MAX_METADATA_ENTRIES)
    || (environment !== null && Object.keys(environment).length > MAX_METADATA_ENTRIES)) {
    fail("web.next_build_output_metadata_limit_exceeded");
  }
  const rawParentId = boundedString(output.parentOutputId);
  const prerenderGroupId = Number.isSafeInteger(output.groupId) && Number(output.groupId) >= 0
    ? Number(output.groupId)
    : null;
  if (expectedType === "PRERENDER" && (rawParentId === null || prerenderGroupId === null)) {
    fail("web.next_build_partial_build");
  }
  const edgeRuntime = record(output.edgeRuntime);
  let sanitizedEdgeRuntime: NextObservedOutput["edge_runtime"] = null;
  if (runtime === "edge") {
    if (edgeRuntime === null || boundedString(edgeRuntime.entryKey) === null
      || edgeRuntime.handlerExport !== "handler") {
      fail("web.next_build_partial_build");
    }
    const modulePath = logicalFromAbsolute(repoRoot, edgeRuntime.modulePath);
    if (modulePath === null || modulePath !== main.logicalPath) fail("web.next_build_manifest_invalid");
    sanitizedEdgeRuntime = {
      module_path: replaceBuildId(modulePath, buildId),
      entry_key_digest: sha256(edgeRuntime.entryKey as string),
      handler_export: "handler",
    };
  } else if (edgeRuntime !== null) {
    fail("web.next_build_manifest_invalid");
  }
  const routePatternVariant: NextObservedRoutingEntry["variant"] = variant === "rsc" || variant === "data"
    ? variant
    : "route";
  const routePattern = ROUTE_OUTPUT_TYPES.has(expectedType) || variant === "static_route"
    ? canonicalRoutePattern(pathname, routePatternVariant, buildId)
    : null;
  const boundary: NextObservedOutput["boundary"] = variant === "client_chunk"
    ? "client"
    : runtime === "edge"
      ? "edge"
      : runtime === "nodejs"
        ? "server"
        : "static";
  const observed: NextObservedOutput = {
    output_identity_digest: "",
    type: expectedType,
    pathname: replaceBuildId(pathname, buildId),
    source_page: sourcePage,
    canonical_route_pattern: routePattern,
    variant,
    artifact_role: artifactRole(variant),
    boundary,
    metadata_kind: routePattern === null ? null : metadataKind(routePattern, sourcePage),
    runtime,
    logical_artifact_path: replaceBuildId(main.logicalPath, buildId),
    artifact_digest: main.digest,
    assets,
    parent_output_identity_digest: null,
    prerender_group_id: prerenderGroupId,
    edge_runtime: sanitizedEdgeRuntime,
    config: {
      max_duration: Number.isSafeInteger(config.maxDuration) && Number(config.maxDuration) >= 0
        ? Number(config.maxDuration)
        : null,
      preferred_region_count: Array.isArray(preferredRegion)
        ? preferredRegion.length
        : typeof preferredRegion === "string" ? 1 : 0,
      environment_key_count: environment === null ? 0 : Object.keys(environment).length,
    },
  };
  observed.output_identity_digest = stableOutputIdentity(observed);
  return {
    rawId: output.id as string,
    rawParentId,
    output: observed,
  };
}

export async function collectNextBuildObservation(
  context: NextAdapterBuildContext,
  readArtifact: ArtifactReader = defaultArtifactReader,
): Promise<NextBuildObservation> {
  detectNextAdapterCapability(context.nextVersion);
  if (boundedString(context.buildId) === null) fail("web.next_build_partial_build");
  if (!path.isAbsolute(context.repoRoot) || !path.isAbsolute(context.projectDir) || !path.isAbsolute(context.distDir)) {
    fail("web.next_build_root_contract_invalid");
  }
  const routingInput = record(context.routing);
  const outputsInput = record(context.outputs);
  if (routingInput === null || outputsInput === null) fail("web.next_build_manifest_missing");
  const routing = sanitizeRouting(routingInput, context.buildId);
  const records: SanitizedOutputRecord[] = [];
  let totalAssets = 0;
  for (const [collection, type] of OUTPUT_COLLECTIONS) {
    for (const raw of outputArray(outputsInput, collection)) {
      if (records.length >= MAX_OUTPUTS) fail("web.next_build_output_limit_exceeded");
      const recordValue = await sanitizeOutput(raw, type, context.repoRoot, context.buildId, readArtifact);
      totalAssets += recordValue.output.assets.length;
      if (totalAssets > MAX_TOTAL_ASSETS) fail("web.next_build_asset_limit_exceeded");
      records.push(recordValue);
    }
  }
  if (outputsInput.middleware !== undefined) {
    if (records.length >= MAX_OUTPUTS) fail("web.next_build_output_limit_exceeded");
    const middleware = await sanitizeOutput(
      outputsInput.middleware,
      "MIDDLEWARE",
      context.repoRoot,
      context.buildId,
      readArtifact,
    );
    totalAssets += middleware.output.assets.length;
    if (totalAssets > MAX_TOTAL_ASSETS) fail("web.next_build_asset_limit_exceeded");
    records.push(middleware);
  }
  const outputIdentityByRawId = new Map<string, string>();
  for (const item of records) {
    const existing = outputIdentityByRawId.get(item.rawId);
    if (existing !== undefined) fail("web.next_build_manifest_invalid");
    outputIdentityByRawId.set(item.rawId, item.output.output_identity_digest);
  }
  for (const item of records) {
    if (item.rawParentId === null) continue;
    const parentIdentity = outputIdentityByRawId.get(item.rawParentId);
    if (parentIdentity === undefined) fail("web.next_build_partial_build");
    item.output.parent_output_identity_digest = parentIdentity;
    item.output.output_identity_digest = stableOutputIdentity(item.output);
  }
  const outputs = records.map((item) => item.output);
  outputs.sort((left, right) => compareUtf8(
    canonicalJson(left as unknown as JsonValue),
    canonicalJson(right as unknown as JsonValue),
  ));
  const manifests: NextObservedManifests = {
    contract_version: NEXT_BUILD_MANIFEST_CONTRACT,
    route_manifest_digest: digestIdentity(routing as unknown as JsonValue),
    build_manifest_digest: digestIdentity(outputs as unknown as JsonValue),
    route_entry_count: routing.length,
    output_entry_count: outputs.length,
  };
  return {
    schema_version: NEXT_BUILD_OBSERVATION_SCHEMA,
    observer: NEXT_BUILD_OBSERVER,
    observer_version: NEXT_BUILD_OBSERVER_VERSION,
    capability: NEXT_BUILD_OBSERVER_CAPABILITY,
    next_version: context.nextVersion,
    config: sanitizeNextConfig(context.config),
    manifests,
    routing,
    outputs,
  };
}

function normalizeHookFailure(code: string, action: () => Awaitable<unknown>): Promise<unknown> {
  return Promise.resolve()
    .then(action)
    .catch((error: unknown) => {
      if (error instanceof NextBuildObserverError) throw error;
      throw new NextBuildObserverError(code);
    });
}

export function composeNextBuildObserver(
  existing: NextAdapterLike | null,
  sink: NextBuildObserverSink,
  readArtifact?: ArtifactReader,
): NextAdapterLike {
  const validated = existing === null ? null : validateAdapter(existing);
  let finalConfig: UnknownRecord | null = null;
  const adapter: NextAdapterLike = {
    name: validated === null ? NEXT_BUILD_OBSERVER : `${NEXT_BUILD_OBSERVER}+${validated.name}`,
    async modifyConfig(config, context) {
      detectNextAdapterCapability(context.nextVersion);
      const modified = validated?.modifyConfig === undefined
        ? config
        : await normalizeHookFailure(
          "web.next_build_existing_adapter_modify_config_failed",
          () => validated.modifyConfig!(config, context),
        );
      const checked = record(modified);
      if (checked === null) fail("web.next_build_existing_adapter_config_invalid");
      finalConfig = checked;
      // Validate the allowlisted projection during config load so unsafe
      // metadata fails before Next starts compilation.
      await normalizeHookFailure("web.next_build_observer_failed", () => sanitizeNextConfig(checked));
      return checked;
    },
    async onBuildComplete(context) {
      detectNextAdapterCapability(context.nextVersion);
      if (validated?.onBuildComplete !== undefined) {
        await normalizeHookFailure(
          "web.next_build_existing_adapter_complete_failed",
          () => validated.onBuildComplete!(context),
        );
      }
      const observation = await normalizeHookFailure(
        "web.next_build_observer_failed",
        () => collectNextBuildObservation({ ...context, config: finalConfig ?? context.config }, readArtifact),
      ) as NextBuildObservation;
      await normalizeHookFailure("web.next_build_observer_sink_failed", () => sink.write(observation));
    },
  };
  return adapter;
}

export async function preflightNextBuildObserver(
  input: NextAdapterPreflightInput,
): Promise<{ adapter: NextAdapterLike; capability: NextAdapterCapability }> {
  const capability = detectNextAdapterCapability(input.nextVersion);
  const configured = input.configuredAdapterPath;
  if (configured === null) {
    return { adapter: composeNextBuildObserver(null, input.sink, input.readArtifact), capability };
  }
  if (boundedString(configured) === null || boundedString(input.observerAdapterPath) === null) {
    fail("web.next_build_adapter_path_invalid");
  }
  if (configured === input.observerAdapterPath) {
    return { adapter: composeNextBuildObserver(null, input.sink, input.readArtifact), capability };
  }
  if (input.loadExistingAdapter === undefined) fail("web.next_build_existing_adapter_chain_unavailable");
  let loaded: unknown;
  try {
    loaded = await input.loadExistingAdapter(configured);
  } catch {
    fail("web.next_build_existing_adapter_load_failed");
  }
  let candidate = loaded;
  try {
    const module = record(loaded);
    if (module !== null && Object.prototype.hasOwnProperty.call(module, "default")) {
      candidate = module.default;
    }
  } catch {
    fail("web.next_build_existing_adapter_invalid");
  }
  const existing = validateAdapter(candidate);
  return {
    adapter: composeNextBuildObserver(existing, input.sink, input.readArtifact),
    capability: { ...capability, existingAdapter: "chainable" },
  };
}

function buildEvidence(
  provenance: NextBuildProvenance,
  logicalArtifactPath: string,
  artifactDigest: string,
): Evidence {
  return frameworkBuildEvidence(
    NEXT_FRAMEWORK_BUILD_DESCRIPTOR,
    provenance,
    logicalArtifactPath,
    artifactDigest,
  );
}

function buildNode(
  kind: GraphNode["kind"],
  identity: Record<string, JsonValue>,
  displayName: string,
  properties: Record<string, JsonValue>,
  provenance: NextBuildProvenance,
  logicalArtifactPath: string,
  artifactDigest: string,
): GraphNode {
  return frameworkBuildGeneratedNode(
    NEXT_FRAMEWORK_BUILD_DESCRIPTOR,
    kind,
    identity,
    displayName,
    properties,
    provenance,
    logicalArtifactPath,
    artifactDigest,
  );
}

function observedCondition(environment: string, extra: Array<{ key: string; value: string }> = []): Condition {
  return frameworkBuildCondition(environment, Object.fromEntries(extra.map(({ key, value }) => [key, value])));
}

function addObservedRelation(
  sites: DependencySite[],
  edges: GraphEdge[],
  source: string,
  target: string,
  kind: string,
  specifier: string,
  environment: string,
  condition: Condition,
  evidence: Evidence,
  profileId: string,
): void {
  const { site, edge } = frameworkBuildRelation(
    NEXT_FRAMEWORK_BUILD_DESCRIPTOR,
    source,
    target,
    kind,
    specifier,
    environment,
    condition,
    evidence,
    profileId,
  );
  sites.push(site);
  edges.push(edge);
}

function routePatternWithoutBasePath(pathname: string, basePath: string): string {
  if (basePath === "") return pathname;
  if (pathname === basePath) return "/";
  return pathname.startsWith(`${basePath}/`) ? pathname.slice(basePath.length) : pathname;
}

function routePatternWithBasePath(pathname: string, basePath: string): string {
  if (basePath === "" || pathname === basePath || pathname.startsWith(`${basePath}/`)) return pathname;
  return pathname === "/" ? basePath : `${basePath}${pathname}`;
}

interface NextRouteCorrelationIndex {
  byPattern: Map<string, GraphNode[]>;
}

function registerNextRoute(index: NextRouteCorrelationIndex, pattern: string, node: GraphNode): void {
  const values = index.byPattern.get(pattern) ?? [];
  if (!values.some((value) => value.id === node.id)) {
    values.push(node);
    values.sort((left, right) => compareUtf8(left.id, right.id));
  }
  index.byPattern.set(pattern, values);
}

function indexNextRoutes(baseNodes: readonly GraphNode[]): NextRouteCorrelationIndex {
  const index: NextRouteCorrelationIndex = { byPattern: new Map() };
  const add = (key: JsonValue | undefined, node: GraphNode): void => {
    if (typeof key !== "string") return;
    registerNextRoute(index, key, node);
  };
  for (const node of baseNodes) {
    if (node.kind !== "route" || node.properties.framework !== "next") continue;
    add(node.properties.route_pattern, node);
    add(node.properties.pattern, node);
  }
  return index;
}

function sourcePageRoutePattern(sourcePage: string): string {
  const withoutSpecial = sourcePage.replace(/\/(?:page|route)$/u, "");
  return withoutSpecial === "" || withoutSpecial === "/index"
    ? "/"
    : withoutSpecial.replace(/\/index$/u, "") || "/";
}

function routeCandidatesForPatterns(
  index: NextRouteCorrelationIndex,
  patterns: ReadonlySet<string>,
): GraphNode[] {
  const matches = new Map<string, GraphNode>();
  for (const pattern of patterns) {
    for (const node of index.byPattern.get(pattern) ?? []) matches.set(node.id, node);
  }
  return [...matches.values()].sort((left, right) => compareUtf8(left.id, right.id));
}

function routeCandidates(
  index: NextRouteCorrelationIndex,
  output: NextObservedOutput,
  basePath: string,
): GraphNode[] {
  if (output.canonical_route_pattern === null) return [];
  const patterns = new Set([
    output.canonical_route_pattern,
    routePatternWithoutBasePath(output.canonical_route_pattern, basePath),
  ]);
  if (output.source_page !== null) {
    const sourcePattern = sourcePageRoutePattern(output.source_page);
    patterns.add(sourcePattern);
    patterns.add(routePatternWithoutBasePath(sourcePattern, basePath));
    patterns.add(routePatternWithBasePath(sourcePattern, basePath));
  }
  const sortedMatches = routeCandidatesForPatterns(index, patterns);
  const semantic = sortedMatches.filter((node) => node.properties.canonical_identity !== undefined);
  const compatibleSemantic = semantic.filter((node) => {
    const routeKind = node.properties.route_kind;
    if (typeof routeKind !== "string") return false;
    if (output.type === "APP_PAGE" || output.type === "PAGES" || output.type === "PRERENDER") {
      return routeKind.endsWith("-page");
    }
    if (output.type === "PAGES_API") return routeKind.endsWith("-api-route");
    if (output.type === "APP_ROUTE") return routeKind.endsWith("-route");
    return false;
  });
  if (compatibleSemantic.length > 0) return compatibleSemantic;
  if (semantic.length > 0) return semantic;
  return sortedMatches;
}

function diagnostic(
  code: string,
  subject: string,
  profileId: string,
  evidence: Evidence,
  properties: Record<string, JsonValue>,
  severity: Diagnostic["severity"] = "warning",
): Diagnostic {
  return frameworkBuildDiagnostic(
    NEXT_FRAMEWORK_BUILD_DESCRIPTOR,
    code,
    subject,
    profileId,
    evidence,
    properties,
    severity,
  );
}

function uniqueById<T extends { id: string }>(values: readonly T[], conflictCode: string): T[] {
  try {
    return deduplicateFrameworkBuildRecords(values);
  } catch {
    fail(conflictCode);
  }
}

function validateNextBuildObservation(observation: NextBuildObservation): void {
  if (observation.schema_version !== NEXT_BUILD_OBSERVATION_SCHEMA
    || observation.capability !== NEXT_BUILD_OBSERVER_CAPABILITY
    || observation.observer !== NEXT_BUILD_OBSERVER
    || observation.observer_version !== NEXT_BUILD_OBSERVER_VERSION
    || observation.manifests?.contract_version !== NEXT_BUILD_MANIFEST_CONTRACT
    || !Array.isArray(observation.routing)
    || !Array.isArray(observation.outputs)) {
    fail("web.next_build_observation_contract_invalid");
  }
  detectNextAdapterCapability(observation.next_version);
  const manifests = observation.manifests;
  if (!/^[a-f0-9]{64}$/u.test(manifests.route_manifest_digest)
    || !/^[a-f0-9]{64}$/u.test(manifests.build_manifest_digest)
    || manifests.route_entry_count !== observation.routing.length
    || manifests.output_entry_count !== observation.outputs.length
    || manifests.route_manifest_digest !== digestIdentity(observation.routing as unknown as JsonValue)
    || manifests.build_manifest_digest !== digestIdentity(observation.outputs as unknown as JsonValue)) {
    fail("web.next_build_observation_contract_invalid");
  }
  const sortedRouting = [...observation.routing].sort((left, right) => compareUtf8(
    canonicalJson(left as unknown as JsonValue),
    canonicalJson(right as unknown as JsonValue),
  ));
  const sortedOutputs = [...observation.outputs].sort((left, right) => compareUtf8(
    canonicalJson(left as unknown as JsonValue),
    canonicalJson(right as unknown as JsonValue),
  ));
  if (canonicalJson(sortedRouting as unknown as JsonValue)
    !== canonicalJson(observation.routing as unknown as JsonValue)
    || canonicalJson(sortedOutputs as unknown as JsonValue)
    !== canonicalJson(observation.outputs as unknown as JsonValue)) {
    fail("web.next_build_observation_contract_invalid");
  }
  for (const routing of observation.routing) {
    if (!ROUTING_PHASES.includes(routing.phase)
      || !/^[a-f0-9]{64}$/u.test(routing.source_regex_digest)
      || (routing.source !== null && canonicalPathname(routing.source) !== routing.source)
      || (routing.destination !== null && canonicalPathname(routing.destination) !== routing.destination)
      || (routing.canonical_route_pattern !== null
        && canonicalPathname(routing.canonical_route_pattern) !== routing.canonical_route_pattern)
      || routing.source_present !== (routing.source !== null)
      || routing.destination_present !== (routing.destination !== null)
      || !["route", "rsc", "data", "segment", "custom"].includes(routing.variant)
      || !Number.isSafeInteger(routing.header_count)
      || !Number.isSafeInteger(routing.predicate_count)
      || routing.header_count < 0
      || routing.predicate_count < 0) {
      fail("web.next_build_observation_contract_invalid");
    }
  }
  const outputIds = new Set<string>();
  const allowedTypes = new Set([...OUTPUT_COLLECTIONS.map(([, type]) => type), "MIDDLEWARE"]);
  const variantsByType: Record<string, ReadonlySet<NextObservedOutput["variant"]>> = {
    PAGES: new Set(["route", "data"]),
    PAGES_API: new Set(["route", "data"]),
    APP_PAGE: new Set(["route", "rsc"]),
    APP_ROUTE: new Set(["route", "rsc"]),
    PRERENDER: new Set(["prerender"]),
    STATIC_FILE: new Set(["static_route", "client_chunk", "static_asset"]),
    MIDDLEWARE: new Set(["middleware"]),
  };
  for (const output of observation.outputs) {
    const hasRoute = ROUTE_OUTPUT_TYPES.has(output.type) || output.variant === "static_route";
    const expectedBoundary = output.variant === "client_chunk"
      ? "client"
      : output.runtime === "edge"
        ? "edge"
        : output.runtime === "nodejs"
          ? "server"
          : "static";
    if (!allowedTypes.has(output.type)
      || variantsByType[output.type]?.has(output.variant) !== true
      || output.artifact_role !== artifactRole(output.variant)
      || output.boundary !== expectedBoundary
      || !["nodejs", "edge", "static"].includes(output.runtime)
      || ((REQUEST_OUTPUT_TYPES.has(output.type) || output.type === "MIDDLEWARE")
        && output.runtime === "static")
      || hasRoute !== (output.canonical_route_pattern !== null)
      || ((REQUEST_OUTPUT_TYPES.has(output.type) || output.type === "MIDDLEWARE")
        && output.source_page === null)
      || (output.metadata_kind !== null && ![
        "robots", "sitemap", "manifest", "favicon", "icon", "apple-icon", "opengraph-image", "twitter-image",
      ].includes(output.metadata_kind))
      || !Array.isArray(output.assets)
      || !/^[a-f0-9]{64}$/u.test(output.output_identity_digest)
      || output.output_identity_digest !== stableOutputIdentity(output)
      || canonicalPathname(output.pathname) === null
      || (output.source_page !== null && canonicalSourcePage(output.source_page) !== output.source_page)
      || (output.canonical_route_pattern !== null
        && canonicalPathname(output.canonical_route_pattern) !== output.canonical_route_pattern)
      || !/^[a-f0-9]{64}$/u.test(output.artifact_digest)
      || canonicalRelativePath(output.logical_artifact_path) !== output.logical_artifact_path
      || (output.type === "PRERENDER")
        !== (output.parent_output_identity_digest !== null && output.prerender_group_id !== null)
      || (output.runtime === "edge") !== (output.edge_runtime !== null)
      || (output.edge_runtime !== null
        && (output.edge_runtime.module_path !== output.logical_artifact_path
          || !/^[a-f0-9]{64}$/u.test(output.edge_runtime.entry_key_digest)
          || output.edge_runtime.handler_export !== "handler"))) {
      fail("web.next_build_observation_contract_invalid");
    }
    if (outputIds.has(output.output_identity_digest)) fail("web.next_build_observation_contract_invalid");
    outputIds.add(output.output_identity_digest);
    for (const asset of output.assets) {
      const expectedAsset = assetRole(asset.logical_path, asset.kind, output.runtime);
      if (canonicalRelativePath(asset.logical_path) !== asset.logical_path
        || !/^[a-f0-9]{64}$/u.test(asset.digest)
        || asset.role !== expectedAsset.role
        || asset.boundary !== expectedAsset.boundary) {
        fail("web.next_build_observation_contract_invalid");
      }
    }
  }
  for (const output of observation.outputs) {
    if (output.parent_output_identity_digest !== null
      && !outputIds.has(output.parent_output_identity_digest)) {
      fail("web.next_build_observation_contract_invalid");
    }
  }
}

export function buildNextObservedGraph(input: NextBuildGraphInput): NextBuildGraphDelta {
  validateNextBuildObservation(input.observation);
  for (const [field, value] of Object.entries(input.provenance)) {
    if (field === "build_run_id" || field === "profile_id") {
      if (boundedString(value) === null) fail("web.next_build_provenance_invalid");
    } else if (!/^[a-f0-9]{64}$/u.test(value)) {
      fail("web.next_build_provenance_invalid");
    }
  }
  const nodes = new Map<string, GraphNode>();
  const sites: DependencySite[] = [];
  const edges: GraphEdge[] = [];
  const diagnostics: Diagnostic[] = [];
  const baseNodeById = new Map(input.baseNodes.map((node) => [node.id, node]));
  const routeIndex = indexNextRoutes(input.baseNodes);
  const renderTargetsByRoute = new Map<string, Set<string>>();
  for (const edge of input.baseEdges ?? []) {
    if (edge.kind !== "renders") continue;
    const targets = renderTargetsByRoute.get(edge.source) ?? new Set<string>();
    targets.add(edge.target);
    renderTargetsByRoute.set(edge.source, targets);
  }
  const addNode = (node: GraphNode): void => {
    const existing = nodes.get(node.id);
    if (existing !== undefined && canonicalJson(existing as unknown as JsonValue) !== canonicalJson(node as unknown as JsonValue)) {
      fail("web.next_build_node_conflict");
    }
    nodes.set(node.id, node);
  };
  const observationDigest = digestIdentity(input.observation.manifests as unknown as JsonValue);
  const observationPath = `.next/depgraph/${observationDigest}.json`;
  const routeByOutputIdentity = new Map<string, GraphNode>();
  const pendingParents: Array<{
    route: GraphNode;
    parentIdentity: string;
    environment: string;
    evidence: Evidence;
  }> = [];
  const boundaryNodes = new Map<string, GraphNode>();
  const boundaryNode = (boundary: NextObservedOutput["boundary"]): GraphNode => {
    const existing = boundaryNodes.get(boundary);
    if (existing !== undefined) return existing;
    const node = buildNode(
      "module",
      { framework: "next", runtime_boundary: boundary, profile_id: input.provenance.profile_id },
      `Next ${boundary} build boundary`,
      {
        framework: "next",
        module_kind: "next-build-runtime-boundary",
        runtime_boundary: boundary,
        profile_id: input.provenance.profile_id,
      },
      input.provenance,
      observationPath,
      observationDigest,
    );
    addNode(node);
    boundaryNodes.set(boundary, node);
    return node;
  };

  for (const output of input.observation.outputs) {
    const evidence = buildEvidence(
      input.provenance,
      output.logical_artifact_path,
      output.artifact_digest,
    );
    const artifactIdentity: Record<string, JsonValue> = {
      framework: "next",
      artifact_kind: output.type,
      logical_artifact_path: output.logical_artifact_path,
      artifact_digest: output.artifact_digest,
      profile_id: input.provenance.profile_id,
    };
    const artifact = buildNode(
      "file",
      artifactIdentity,
      output.logical_artifact_path,
      {
        framework: "next",
        artifact_kind: output.type,
        logical_path: output.logical_artifact_path,
        artifact_digest: output.artifact_digest,
        runtime: output.runtime,
        boundary: output.boundary,
        profile_id: input.provenance.profile_id,
      },
      input.provenance,
      output.logical_artifact_path,
      output.artifact_digest,
    );
    addNode(artifact);
    const condition = observedCondition(output.boundary, [
      { key: "next.output_type", value: output.type },
      { key: "next.output_variant", value: output.variant },
      { key: "next.boundary", value: output.boundary },
      { key: "next.runtime", value: output.runtime },
    ]);
    if (output.canonical_route_pattern === null) {
      let source: GraphNode;
      if (output.variant === "middleware") {
        source = buildNode(
          "middleware",
          {
            framework: "next",
            middleware: output.source_page ?? "/_middleware",
            runtime: output.runtime,
            profile_id: input.provenance.profile_id,
          },
          output.source_page ?? "Next middleware",
          {
            framework: "next",
            middleware_kind: "next-build-middleware",
            source_page: output.source_page,
            runtime: output.runtime,
            profile_id: input.provenance.profile_id,
          },
          input.provenance,
          output.logical_artifact_path,
          output.artifact_digest,
        );
        addNode(source);
      } else {
        source = boundaryNode(output.boundary);
      }
      addObservedRelation(
        sites, edges, source.id, artifact.id, "emits", output.logical_artifact_path,
        output.boundary, condition, evidence, input.provenance.profile_id,
      );
    } else {
      const canonicalPattern = output.canonical_route_pattern;
      const candidates = routeCandidates(routeIndex, output, input.observation.config.base_path);
      let route: GraphNode;
      if (candidates.length === 1) {
        route = candidates[0]!;
        addNode(route);
        const declaredRuntime = route.properties.runtime;
        if ((declaredRuntime === "nodejs" || declaredRuntime === "edge") && declaredRuntime !== output.runtime) {
          diagnostics.push(diagnostic(
            "web.next_build_runtime_drift",
            canonicalPattern,
            input.provenance.profile_id,
            evidence,
            { declared_runtime: declaredRuntime, observed_runtime: output.runtime, route_id: route.id },
          ));
        }
      } else {
        const routeRole = output.metadata_kind === null
          ? output.type.toLowerCase()
          : `metadata:${output.metadata_kind}`;
        const identity: Record<string, JsonValue> = {
          framework: "next",
          route_pattern: canonicalPattern,
          route_role: routeRole,
          profile_id: input.provenance.profile_id,
        };
        route = buildNode(
          "route",
          identity,
          canonicalPattern,
          {
            framework: "next",
            route_pattern: canonicalPattern,
            route_role: routeRole,
            metadata_kind: output.metadata_kind,
            runtime: output.runtime,
            profile_id: input.provenance.profile_id,
            observed_only: true,
          },
          input.provenance,
          output.logical_artifact_path,
          output.artifact_digest,
        );
        addNode(route);
        diagnostics.push(diagnostic(
          candidates.length === 0 ? "web.next_build_route_static_missing" : "web.next_build_route_conflict",
          canonicalPattern,
          input.provenance.profile_id,
          evidence,
          { candidate_count: candidates.length, observed_route_id: route.id },
          candidates.length === 0 ? "info" : "warning",
        ));
      }
      registerNextRoute(routeIndex, canonicalPattern, route);
      registerNextRoute(
        routeIndex,
        routePatternWithoutBasePath(canonicalPattern, input.observation.config.base_path),
        route,
      );
      routeByOutputIdentity.set(output.output_identity_digest, route);
      addObservedRelation(
        sites, edges, route.id, artifact.id, "emits", output.logical_artifact_path,
        output.boundary, condition, evidence, input.provenance.profile_id,
      );
      if (output.parent_output_identity_digest !== null) {
        pendingParents.push({
          route,
          parentIdentity: output.parent_output_identity_digest,
          environment: output.boundary,
          evidence,
        });
      }
      if (candidates.length === 1) {
        const componentIds = [...(renderTargetsByRoute.get(route.id) ?? [])].sort(compareUtf8);
        for (const componentId of componentIds) {
          const component = baseNodeById.get(componentId);
          if (component?.kind !== "component" || component.properties.framework !== "next") continue;
          addNode(component);
          addObservedRelation(
            sites, edges, component.id, artifact.id, "emits", output.logical_artifact_path,
            output.boundary, condition, evidence, input.provenance.profile_id,
          );
        }
      }
    }
    for (const assetValue of output.assets) {
      const assetEvidence = buildEvidence(input.provenance, assetValue.logical_path, assetValue.digest);
      const assetIdentity: Record<string, JsonValue> = {
        framework: "next",
        artifact_kind: assetValue.kind,
        logical_artifact_path: assetValue.logical_path,
        artifact_digest: assetValue.digest,
        profile_id: input.provenance.profile_id,
      };
      const asset = buildNode(
        "file",
        assetIdentity,
        assetValue.logical_path,
        {
          framework: "next",
          artifact_kind: assetValue.kind,
          logical_path: assetValue.logical_path,
          artifact_digest: assetValue.digest,
          asset_role: assetValue.role,
          profile_id: input.provenance.profile_id,
        },
        input.provenance,
        assetValue.logical_path,
        assetValue.digest,
      );
      addNode(asset);
      addObservedRelation(
        sites, edges, artifact.id, asset.id, "loads", assetValue.logical_path,
        assetValue.boundary,
        observedCondition(assetValue.boundary, [
          { key: "next.asset_role", value: assetValue.role },
          { key: "next.output_variant", value: output.variant },
        ]),
        assetEvidence,
        input.provenance.profile_id,
      );
    }
  }

  for (const pending of pendingParents) {
    const parent = routeByOutputIdentity.get(pending.parentIdentity);
    if (parent === undefined) fail("web.next_build_graph_contract_invalid");
    addObservedRelation(
      sites,
      edges,
      pending.route.id,
      parent.id,
      "parent_route",
      parent.display_name,
      pending.environment,
      observedCondition(pending.environment, [{ key: "next.route_parent", value: "prerender" }]),
      pending.evidence,
      input.provenance.profile_id,
    );
  }

  for (const routing of input.observation.routing) {
    const evidence = buildEvidence(input.provenance, observationPath, observationDigest);
    const routingEntryDigest = digestIdentity(routing as unknown as JsonValue);
    const routePattern = routing.source ?? `observed:${routingEntryDigest}`;
    const candidatePatterns = routing.canonical_route_pattern === null
      ? new Set<string>()
      : new Set([
        routing.canonical_route_pattern,
        routePatternWithoutBasePath(routing.canonical_route_pattern, input.observation.config.base_path),
        routePatternWithBasePath(routing.canonical_route_pattern, input.observation.config.base_path),
      ]);
    const candidates = routing.phase === "dynamicRoutes"
      ? routeCandidatesForPatterns(routeIndex, candidatePatterns)
      : [];
    let route: GraphNode;
    if (candidates.length === 1) {
      route = candidates[0]!;
    } else {
      const correlatedDynamic = routing.phase === "dynamicRoutes"
        && routing.canonical_route_pattern !== null
        && candidates.length === 0;
      const canonicalPattern = routing.canonical_route_pattern ?? routePattern;
      const identity: Record<string, JsonValue> = correlatedDynamic
        ? {
          framework: "next",
          route_pattern: canonicalPattern,
          route_role: "dynamic-manifest",
          profile_id: input.provenance.profile_id,
        }
        : {
          framework: "next",
          route_pattern: canonicalPattern,
          routing_phase: routing.phase,
          source_regex_digest: routing.source_regex_digest,
          routing_entry_digest: routingEntryDigest,
          profile_id: input.provenance.profile_id,
        };
      route = buildNode(
        "route",
        identity,
        canonicalPattern,
        correlatedDynamic
          ? {
            framework: "next",
            route_pattern: canonicalPattern,
            route_role: "dynamic-manifest",
            profile_id: input.provenance.profile_id,
            observed_only: true,
          }
          : {
            framework: "next",
            route_pattern: canonicalPattern,
            routing_phase: routing.phase,
            destination: routing.destination,
            status: routing.status,
            priority: routing.priority,
            header_count: routing.header_count,
            predicate_count: routing.predicate_count,
            routing_entry_digest: routingEntryDigest,
            profile_id: input.provenance.profile_id,
          },
        input.provenance,
        observationPath,
        observationDigest,
      );
      if (candidates.length > 1) {
        diagnostics.push(diagnostic(
          "web.next_build_route_conflict",
          canonicalPattern,
          input.provenance.profile_id,
          evidence,
          { candidate_count: candidates.length, observed_route_id: route.id },
        ));
      }
    }
    const phaseNode = buildNode(
      "module",
      { framework: "next", routing_phase: routing.phase, profile_id: input.provenance.profile_id },
      `Next routing phase ${routing.phase}`,
      {
        framework: "next",
        module_kind: "next-routing-phase",
        routing_phase: routing.phase,
        profile_id: input.provenance.profile_id,
      },
      input.provenance,
      observationPath,
      observationDigest,
    );
    addNode(route);
    addNode(phaseNode);
    if (routing.canonical_route_pattern !== null) {
      registerNextRoute(routeIndex, routing.canonical_route_pattern, route);
      registerNextRoute(
        routeIndex,
        routePatternWithoutBasePath(routing.canonical_route_pattern, input.observation.config.base_path),
        route,
      );
    }
    const condition = observedCondition("server", [
      { key: "next.routing_phase", value: routing.phase },
      { key: "next.routing_variant", value: routing.variant },
    ]);
    addObservedRelation(
      sites, edges, route.id, phaseNode.id, "routes_in_phase", routing.source ?? "<regex-only>",
      "server", condition, evidence, input.provenance.profile_id,
    );
  }

  const candidate = {
    nextVersion: input.observation.next_version,
    nodes: [...nodes.values()].sort((left, right) => compareUtf8(left.id, right.id)),
    sites: uniqueById(sites, "web.next_build_site_conflict"),
    edges: uniqueById(edges, "web.next_build_edge_conflict"),
    diagnostics: uniqueById(diagnostics, "web.next_build_diagnostic_conflict"),
  };
  let delta: NextBuildGraphDelta;
  try {
    delta = {
      nextVersion: candidate.nextVersion,
      ...reconcileFrameworkBuildBaseRecords(
        candidate,
        NEXT_FRAMEWORK_BUILD_DESCRIPTOR,
        input.provenance,
        input.baseNodes,
        input.baseEdges ?? [],
        input.baseDiagnosticIds,
      ),
    };
    validateFrameworkBuildDelta(
      delta,
      NEXT_FRAMEWORK_BUILD_DESCRIPTOR,
      input.provenance,
      input.baseNodes,
    );
  } catch {
    fail("web.next_build_graph_contract_invalid");
  }
  return delta;
}

export function nextBuildProtocolEvents(
  root: string,
  delta: NextBuildGraphDelta,
  provenance: NextBuildProvenance,
  sourceRevision: string,
): ProtocolEvent[] {
  return frameworkBuildProtocolEvents(
    root,
    delta,
    provenance,
    sourceRevision,
    NEXT_FRAMEWORK_BUILD_DESCRIPTOR,
    {
      toolchain: `next ${delta.nextVersion}`,
      command: "next build",
      properties: { next_version: delta.nextVersion },
    },
  );
}
