import { createHash } from "node:crypto";
import { lstat, open, realpath } from "node:fs/promises";
import path from "node:path";
import { canonicalJson, stableId } from "./ids";
import {
  canonicalizeCondition,
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
export const NEXT_BUILD_OBSERVER_VERSION = "0.1.0" as const;
export const NEXT_BUILD_OBSERVER_CAPABILITY = "next-adapter-api-16.2-v1" as const;
export const NEXT_BUILD_OBSERVATION_SCHEMA = "next-build-observation-v1" as const;

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
const ROUTE_OUTPUT_TYPES = new Set(["PAGES", "PAGES_API", "APP_PAGE", "APP_ROUTE", "MIDDLEWARE"]);
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
}

export interface NextObservedOutput {
  output_id_digest: string;
  type: string;
  pathname: string;
  source_page: string | null;
  runtime: "nodejs" | "edge" | "static";
  logical_artifact_path: string;
  artifact_digest: string;
  assets: NextObservedAsset[];
  parent_output_id_digest: string | null;
  config: {
    max_duration: number | null;
    preferred_region_count: number;
    environment_key_count: number;
  };
}

export interface NextBuildObservation {
  schema_version: typeof NEXT_BUILD_OBSERVATION_SCHEMA;
  observer: typeof NEXT_BUILD_OBSERVER;
  observer_version: typeof NEXT_BUILD_OBSERVER_VERSION;
  capability: typeof NEXT_BUILD_OBSERVER_CAPABILITY;
  next_version: string;
  build_id_digest: string;
  config: NextObservedConfig;
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

function sanitizeRouting(routing: Record<string, unknown>): NextObservedRoutingEntry[] {
  const entries: NextObservedRoutingEntry[] = [];
  for (const phase of ROUTING_PHASES) {
    const routes = routing[phase];
    if (!Array.isArray(routes)) fail("web.next_build_routing_contract_invalid");
    for (const value of routes) {
      if (entries.length >= MAX_ROUTING_ENTRIES) fail("web.next_build_routing_limit_exceeded");
      const route = record(value);
      if (route === null || boundedString(route.sourceRegex) === null) {
        fail("web.next_build_routing_contract_invalid");
      }
      const source = canonicalPathname(route.source);
      const destination = canonicalPathname(route.destination);
      const headerCount = record(route.headers) === null ? 0 : Object.keys(record(route.headers)!).length;
      const predicateCount = (Array.isArray(route.has) ? route.has.length : 0)
        + (Array.isArray(route.missing) ? route.missing.length : 0);
      if (headerCount > MAX_METADATA_ENTRIES || predicateCount > MAX_METADATA_ENTRIES) {
        fail("web.next_build_routing_metadata_limit_exceeded");
      }
      entries.push({
        phase,
        source,
        source_regex_digest: sha256(route.sourceRegex as string),
        destination,
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
  if (!Array.isArray(value)) fail("web.next_build_output_contract_invalid");
  return value;
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
  readArtifact: ArtifactReader,
): Promise<NextObservedOutput> {
  const output = record(raw);
  if (output === null || boundedString(output.id) === null || output.type !== expectedType) {
    fail("web.next_build_output_contract_invalid");
  }
  const pathname = canonicalPathname(output.pathname);
  if (pathname === null) fail("web.next_build_output_pathname_unsafe");
  const sourcePage = output.sourcePage === undefined ? null : canonicalPathname(output.sourcePage);
  if (output.sourcePage !== undefined && sourcePage === null) fail("web.next_build_source_page_unsafe");
  let mainPath: unknown = output.filePath;
  if (expectedType === "PRERENDER") mainPath = record(output.fallback)?.filePath;
  const main = mainPath === undefined
    ? { logicalPath: `.next/observed/${sha256(`${expectedType}\0${pathname}`)}.metadata`, digest: sha256(canonicalJson({ expectedType, pathname })) }
    : await digestArtifact(repoRoot, mainPath, undefined, readArtifact);
  const assets: NextObservedAsset[] = [];
  for (const [kind, value] of [["asset", output.assets], ["wasm", output.wasmAssets]] as const) {
    const map = value === undefined ? {} : record(value);
    if (map === null || Object.keys(map).length > MAX_ASSETS_PER_OUTPUT) {
      fail("web.next_build_asset_contract_invalid");
    }
    for (const [logicalHint, absolutePath] of Object.entries(map)) {
      const artifact = await digestArtifact(repoRoot, absolutePath, logicalHint, readArtifact);
      assets.push({ logical_path: artifact.logicalPath, digest: artifact.digest, kind });
    }
  }
  assets.sort((left, right) => compareUtf8(
    canonicalJson(left as unknown as JsonValue),
    canonicalJson(right as unknown as JsonValue),
  ));
  const config = record(output.config) ?? {};
  const preferredRegion = config.preferredRegion;
  const environment = record(config.env);
  if ((Array.isArray(preferredRegion) && preferredRegion.length > MAX_METADATA_ENTRIES)
    || (environment !== null && Object.keys(environment).length > MAX_METADATA_ENTRIES)) {
    fail("web.next_build_output_metadata_limit_exceeded");
  }
  return {
    output_id_digest: sha256(output.id as string),
    type: expectedType,
    pathname,
    source_page: sourcePage,
    runtime: output.runtime === "edge" ? "edge" : output.runtime === "nodejs" ? "nodejs" : "static",
    logical_artifact_path: main.logicalPath,
    artifact_digest: main.digest,
    assets,
    parent_output_id_digest: boundedString(output.parentOutputId) === null ? null : sha256(output.parentOutputId as string),
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
}

export async function collectNextBuildObservation(
  context: NextAdapterBuildContext,
  readArtifact: ArtifactReader = defaultArtifactReader,
): Promise<NextBuildObservation> {
  detectNextAdapterCapability(context.nextVersion);
  if (!path.isAbsolute(context.repoRoot) || !path.isAbsolute(context.projectDir) || !path.isAbsolute(context.distDir)) {
    fail("web.next_build_root_contract_invalid");
  }
  const outputs: NextObservedOutput[] = [];
  let totalAssets = 0;
  for (const [collection, type] of OUTPUT_COLLECTIONS) {
    for (const raw of outputArray(context.outputs, collection)) {
      if (outputs.length >= MAX_OUTPUTS) fail("web.next_build_output_limit_exceeded");
      const output = await sanitizeOutput(raw, type, context.repoRoot, readArtifact);
      totalAssets += output.assets.length;
      if (totalAssets > MAX_TOTAL_ASSETS) fail("web.next_build_asset_limit_exceeded");
      outputs.push(output);
    }
  }
  if (context.outputs.middleware !== undefined) {
    if (outputs.length >= MAX_OUTPUTS) fail("web.next_build_output_limit_exceeded");
    const middleware = await sanitizeOutput(context.outputs.middleware, "MIDDLEWARE", context.repoRoot, readArtifact);
    totalAssets += middleware.assets.length;
    if (totalAssets > MAX_TOTAL_ASSETS) fail("web.next_build_asset_limit_exceeded");
    outputs.push(middleware);
  }
  outputs.sort((left, right) => compareUtf8(
    canonicalJson(left as unknown as JsonValue),
    canonicalJson(right as unknown as JsonValue),
  ));
  return {
    schema_version: NEXT_BUILD_OBSERVATION_SCHEMA,
    observer: NEXT_BUILD_OBSERVER,
    observer_version: NEXT_BUILD_OBSERVER_VERSION,
    capability: NEXT_BUILD_OBSERVER_CAPABILITY,
    next_version: context.nextVersion,
    build_id_digest: sha256(context.buildId),
    config: sanitizeNextConfig(context.config),
    routing: sanitizeRouting(context.routing),
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
  return {
    kind: "build",
    extractor: NEXT_BUILD_OBSERVER,
    extractor_version: NEXT_BUILD_OBSERVER_VERSION,
    path: logicalArtifactPath,
    start_line: 1,
    start_column: 1,
    end_line: 1,
    end_column: 1,
    properties: {
      ...provenance,
      logical_artifact_path: logicalArtifactPath,
      artifact_digest: artifactDigest,
      capability: NEXT_BUILD_OBSERVER_CAPABILITY,
    },
  };
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
  const id = stableId(kind, identity);
  return {
    id,
    kind,
    locator: `build://${NEXT_BUILD_OBSERVER}/${encodeURIComponent(logicalArtifactPath)}#${id}`,
    display_name: displayName,
    properties: {
      ...properties,
      build_generated: true,
      build_identity: identity,
      build_provenance: {
        ...provenance,
        observer: NEXT_BUILD_OBSERVER,
        observer_version: NEXT_BUILD_OBSERVER_VERSION,
        logical_artifact_path: logicalArtifactPath,
        artifact_digest: artifactDigest,
      },
    },
  };
}

function observedCondition(environment: string, extra: Array<{ key: string; value: string }> = []): Condition {
  return canonicalizeCondition({
    op: "all",
    conditions: [
      { op: "eq", key: "mode", value: "production" },
      { op: "eq", key: "environment", value: environment },
      ...extra.map(({ key, value }) => ({ op: "eq" as const, key, value })),
    ],
  });
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
  const siteIdentity: Record<string, JsonValue> = {
    kind,
    source,
    specifier,
    profile_id: profileId,
    condition,
    resolution_status: "resolved",
    precision: "observed",
    observer: NEXT_BUILD_OBSERVER,
    observer_version: NEXT_BUILD_OBSERVER_VERSION,
    validated_output_digest: evidence.properties?.validated_output_digest ?? null,
    anchor: {
      path: evidence.path,
      start_line: evidence.start_line,
      start_column: evidence.start_column,
      end_line: evidence.end_line,
      end_column: evidence.end_column,
    },
  };
  const siteId = stableId("site", siteIdentity);
  const site: DependencySite = {
    id: siteId,
    source,
    kind,
    specifier,
    resolution_status: "resolved",
    target_ids: [target],
    profile_id: profileId,
    condition,
    precision: "observed",
    reason: null,
    evidence: [evidence],
  };
  const edge: GraphEdge = {
    id: stableId("edge", { kind, site_id: siteId, target, phase: "build" }),
    source,
    target,
    kind,
    site_id: siteId,
    phase: "build",
    environment,
    profile_id: profileId,
    condition,
    resolution_status: "resolved",
    precision: "observed",
    generated: true,
    evidence: [evidence],
  };
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

function indexNextRoutes(baseNodes: readonly GraphNode[]): NextRouteCorrelationIndex {
  const index: NextRouteCorrelationIndex = { byPattern: new Map() };
  const add = (map: Map<string, GraphNode[]>, key: JsonValue | undefined, node: GraphNode): void => {
    if (typeof key !== "string") return;
    const values = map.get(key) ?? [];
    values.push(node);
    map.set(key, values);
  };
  for (const node of baseNodes) {
    if (node.kind !== "route" || node.properties.framework !== "next") continue;
    add(index.byPattern, node.properties.route_pattern, node);
    add(index.byPattern, node.properties.pattern, node);
  }
  return index;
}

function routeCandidates(
  index: NextRouteCorrelationIndex,
  output: NextObservedOutput,
  basePath: string,
): GraphNode[] {
  const patterns = new Set([output.pathname, routePatternWithoutBasePath(output.pathname, basePath)]);
  if (output.source_page !== null) {
    patterns.add(output.source_page);
    patterns.add(routePatternWithoutBasePath(output.source_page, basePath));
    patterns.add(routePatternWithBasePath(output.source_page, basePath));
  }
  const matches = new Map<string, GraphNode>();
  for (const pattern of patterns) {
    for (const node of index.byPattern.get(pattern) ?? []) matches.set(node.id, node);
  }
  const sortedMatches = [...matches.values()].sort((left, right) => compareUtf8(left.id, right.id));
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
  return {
    id: stableId("diagnostic", { code, subject, profile_id: profileId, properties }),
    severity,
    code,
    message: `${code}: ${subject}`,
    path: evidence.path,
    profile_id: profileId,
    evidence: [evidence],
    properties,
  };
}

function uniqueById<T extends { id: string }>(values: readonly T[], conflictCode: string): T[] {
  const unique = new Map<string, T>();
  for (const value of values) {
    const existing = unique.get(value.id);
    if (existing !== undefined
      && canonicalJson(existing as unknown as JsonValue) !== canonicalJson(value as unknown as JsonValue)) {
      fail(conflictCode);
    }
    unique.set(value.id, value);
  }
  return [...unique.values()].sort((left, right) => compareUtf8(left.id, right.id));
}

export function buildNextObservedGraph(input: NextBuildGraphInput): NextBuildGraphDelta {
  if (input.observation.capability !== NEXT_BUILD_OBSERVER_CAPABILITY
    || input.observation.observer !== NEXT_BUILD_OBSERVER
    || input.observation.observer_version !== NEXT_BUILD_OBSERVER_VERSION) {
    fail("web.next_build_observation_contract_invalid");
  }
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

  for (const output of input.observation.outputs) {
    const evidence = buildEvidence(
      input.provenance,
      output.logical_artifact_path,
      output.artifact_digest,
    );
    const canonicalRoutePattern = output.pathname;
    const candidates = routeCandidates(routeIndex, output, input.observation.config.base_path);
    let route: GraphNode;
    if (candidates.length === 1) {
      route = candidates[0]!;
      addNode(route);
      const declaredRuntime = route.properties.runtime;
      if ((declaredRuntime === "nodejs" || declaredRuntime === "edge") && declaredRuntime !== output.runtime) {
        diagnostics.push(diagnostic(
          "web.next_build_runtime_drift",
          output.pathname,
          input.provenance.profile_id,
          evidence,
          { declared_runtime: declaredRuntime, observed_runtime: output.runtime, route_id: route.id },
        ));
      }
    } else {
      const identity: Record<string, JsonValue> = {
        framework: "next",
        route_pattern: canonicalRoutePattern,
        observed_pathname: output.pathname,
        output_type: output.type,
        runtime: output.runtime,
        profile_id: input.provenance.profile_id,
      };
      route = buildNode(
        "route",
        identity,
        output.pathname,
        {
          framework: "next",
          route_pattern: canonicalRoutePattern,
          observed_pathname: output.pathname,
          output_type: output.type,
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
        output.pathname,
        input.provenance.profile_id,
        evidence,
        { candidate_count: candidates.length, observed_route_id: route.id },
        candidates.length === 0 ? "info" : "warning",
      ));
    }
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
        output_pathname: output.pathname,
        output_id_digest: output.output_id_digest,
        profile_id: input.provenance.profile_id,
      },
      input.provenance,
      output.logical_artifact_path,
      output.artifact_digest,
    );
    addNode(artifact);
    const condition = observedCondition(output.runtime, [
      { key: "next.output_type", value: output.type },
      { key: "next.route", value: output.pathname },
    ]);
    addObservedRelation(
      sites, edges, route.id, artifact.id, "emits", output.logical_artifact_path,
      output.runtime, condition, evidence, input.provenance.profile_id,
    );
    if (candidates.length === 1) {
      const componentIds = [...(renderTargetsByRoute.get(route.id) ?? [])].sort(compareUtf8);
      for (const componentId of componentIds) {
        const component = baseNodeById.get(componentId);
        if (component?.kind !== "component" || component.properties.framework !== "next") continue;
        addNode(component);
        addObservedRelation(
          sites, edges, component.id, artifact.id, "emits", output.logical_artifact_path,
          output.runtime, condition, evidence, input.provenance.profile_id,
        );
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
          profile_id: input.provenance.profile_id,
        },
        input.provenance,
        assetValue.logical_path,
        assetValue.digest,
      );
      addNode(asset);
      addObservedRelation(
        sites, edges, artifact.id, asset.id, "loads", assetValue.logical_path,
        output.runtime, condition, assetEvidence, input.provenance.profile_id,
      );
    }
  }

  const observationDigest = digestIdentity(input.observation as unknown as JsonValue);
  const observationPath = `.next/depgraph/${observationDigest}.json`;
  for (const routing of input.observation.routing) {
    const evidence = buildEvidence(input.provenance, observationPath, observationDigest);
    const routingEntryDigest = digestIdentity(routing as unknown as JsonValue);
    const routePattern = routing.source ?? `observed:${routingEntryDigest}`;
    const route = buildNode(
      "route",
      {
        framework: "next",
        route_pattern: routePattern,
        routing_phase: routing.phase,
        source_regex_digest: routing.source_regex_digest,
        routing_entry_digest: routingEntryDigest,
        profile_id: input.provenance.profile_id,
      },
      routing.source ?? "observed Next routing entry",
      {
        framework: "next",
        route_pattern: routePattern,
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
    const phaseNode = buildNode(
      "unknown_target",
      { framework: "next", routing_phase: routing.phase, profile_id: input.provenance.profile_id },
      `Next routing phase ${routing.phase}`,
      { framework: "next", routing_phase: routing.phase, profile_id: input.provenance.profile_id },
      input.provenance,
      observationPath,
      observationDigest,
    );
    addNode(route);
    addNode(phaseNode);
    const condition = observedCondition("server", [{ key: "next.routing_phase", value: routing.phase }]);
    addObservedRelation(
      sites, edges, route.id, phaseNode.id, "routes_in_phase", routing.source ?? "<regex-only>",
      "server", condition, evidence, input.provenance.profile_id,
    );
  }

  return {
    nextVersion: input.observation.next_version,
    nodes: [...nodes.values()].sort((left, right) => compareUtf8(left.id, right.id)),
    sites: uniqueById(sites, "web.next_build_site_conflict"),
    edges: uniqueById(edges, "web.next_build_edge_conflict"),
    diagnostics: uniqueById(diagnostics, "web.next_build_diagnostic_conflict"),
  };
}

export function nextBuildProtocolEvents(
  root: string,
  delta: NextBuildGraphDelta,
  provenance: NextBuildProvenance,
  sourceRevision: string,
): ProtocolEvent[] {
  const common = {
    protocol_version: "1.0" as const,
    scan_id: provenance.build_run_id,
    adapter: "web" as const,
    adapter_version: "0.2.0-rc.1" as const,
  };
  let seq = 0;
  const event = (kind: string, payload: Record<string, unknown>): ProtocolEvent => ({
    ...common,
    event: kind,
    seq: ++seq,
    ...payload,
  });
  const coverage = {
    profiles: 1,
    files_discovered: 0,
    files_analyzed: 0,
    files_skipped: 0,
    dependency_sites: delta.sites.length,
    resolved: delta.sites.length,
    candidates: 0,
    external: 0,
    unresolved: 0,
    unsupported_syntax: 0,
    project_code_executed: true,
    completeness: ["build-observed"],
    reasons: [],
  };
  const events: ProtocolEvent[] = [event("scan_started", {
    root,
    safe_mode: false,
    project_code_executed: true,
  })];
  events.push(event("profile_declared", {
    profile: {
      id: provenance.profile_id,
      language: "typescript",
      toolchain: `next ${delta.nextVersion}`,
      command: "next build",
      target: "production",
      features: [NEXT_BUILD_OBSERVER_CAPABILITY],
      environment: { mode: "production" },
      source_revision: sourceRevision,
      properties: {
        observer: NEXT_BUILD_OBSERVER,
        observer_version: NEXT_BUILD_OBSERVER_VERSION,
        next_version: delta.nextVersion,
        project_code_executed: true,
      },
    },
  }));
  for (const node of delta.nodes) events.push(event("node_upsert", { node }));
  for (const site of delta.sites) events.push(event("dependency_site", { site }));
  for (const edge of delta.edges) events.push(event("edge_upsert", { edge }));
  for (const item of delta.diagnostics) events.push(event("diagnostic", { diagnostic: item }));
  events.push(event("profile_completed", { profile_id: provenance.profile_id, coverage }));
  events.push(event("scan_completed", { coverage }));
  return events;
}
