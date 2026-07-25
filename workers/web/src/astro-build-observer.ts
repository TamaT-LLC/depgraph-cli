import { createHash } from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";
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
  validateFrameworkBuildProvenance,
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

export const ASTRO_BUILD_OBSERVER = "astro-vite-build-observer" as const;
export const ASTRO_BUILD_OBSERVER_VERSION = "0.2.0" as const;
export const ASTRO_BUILD_OBSERVER_CAPABILITY = "astro-integration-v5-v7-vite-v6-v7-v1" as const;
export const ASTRO_BUILD_OBSERVATION_SCHEMA = "astro-build-observation-v2" as const;
export const ASTRO_BUILD_MANIFEST_CONTRACT = "astro-integration-manifests-v1" as const;
export const ASTRO_FRAMEWORK_BUILD_DESCRIPTOR: FrameworkBuildDescriptor = Object.freeze({
  framework: "astro",
  observer: ASTRO_BUILD_OBSERVER,
  observerVersion: ASTRO_BUILD_OBSERVER_VERSION,
  capability: ASTRO_BUILD_OBSERVER_CAPABILITY,
});

const MAX_SAFE_STRING = 4_096;
const MAX_ROUTES = 20_000;
const MAX_MODULES = 100_000;
const MAX_IMPORTS_PER_MODULE = 20_000;
const MAX_OUTPUTS = 100_000;
const MAX_PLUGIN_NAMES = 20_000;
const MAX_PARAMS_PER_ROUTE = 1_000;
const MAX_GRAPH_TRAVERSAL_STEPS = 2_000_000;
const DEFAULT_TIMEOUT_MS = 10_000;
const MAX_TIMEOUT_MS = 60_000;

type UnknownRecord = Record<string, unknown>;
type Awaitable<T> = T | Promise<T>;
type AstroEnvironment = "browser" | "server";

export interface AstroBuildProvenance {
  build_run_id: string;
  profile_id: string;
  command_plan_digest: string;
  toolchain_executable_digest: string;
  environment_key_set_digest: string;
  validated_output_digest: string;
}

export interface AstroObserverSink {
  write(observation: AstroBuildObservation): Awaitable<void>;
}

export interface AstroBuildObserverOptions {
  astroVersion: string;
  repoRoot: string;
  sink: AstroObserverSink;
  existingIntegrations?: readonly unknown[];
  existingVitePlugins?: readonly unknown[];
  dynamicConfigDetected?: boolean;
  timeoutMs?: number;
}

export interface AstroObserverCapability {
  capability: typeof ASTRO_BUILD_OBSERVER_CAPABILITY;
  astro_version: string;
  existing_integration_count: number;
  existing_vite_plugin_count: number;
}

export interface AstroIntegrationLike {
  name: string;
  hooks: Record<string, (context: UnknownRecord) => Awaitable<void>>;
}

export interface AstroVitePluginLike {
  name: string;
  apply: "build";
  enforce: "post";
  configResolved(config: UnknownRecord): void;
  buildStart(this: UnknownRecord): void;
  generateBundle(this: UnknownRecord, outputOptions: unknown, bundle: UnknownRecord): void;
  buildEnd(this: UnknownRecord, error?: unknown): void;
}

export interface AstroObservedConfig {
  output: "static" | "server";
  base: string;
  trailing_slash: "always" | "never" | "ignore";
  adapter_present: boolean;
  integration_count: number;
  dynamic_config_detected: boolean;
}

export interface AstroObservedRoute {
  route_digest: string;
  route_pattern: string;
  pathname: string | null;
  pattern_digest: string;
  component_id: string;
  component_kind: "project" | "virtual" | "external";
  type: "page" | "endpoint" | "redirect" | "fallback" | "unknown";
  prerender: boolean | null;
  params: Array<{ name: string; spread: boolean }>;
  dynamic: boolean;
  origin: "project" | "internal" | "external" | "unknown";
  injected: boolean;
}

export interface AstroObservedEntryModule {
  module_id: string;
  module_kind: "project" | "virtual" | "external";
  chunk: string;
}

export interface AstroObservedModule {
  module_id: string;
  module_kind: "project" | "virtual" | "external";
  role: "route" | "endpoint" | "island" | "module";
  is_entry: boolean;
  imported_ids: string[];
  dynamic_imported_ids: string[];
}

export interface AstroObservedOutput {
  file_name: string;
  kind: "chunk" | "asset";
  role: "route_chunk" | "endpoint_chunk" | "hydration_chunk" | "client_chunk" | "server_chunk" | "asset";
  boundary: AstroEnvironment;
  digest: string;
  entry: boolean;
  module_ids: string[];
  imported_outputs: string[];
  referenced_assets: string[];
}

export interface AstroObservedManifests {
  contract_version: typeof ASTRO_BUILD_MANIFEST_CONTRACT;
  route_manifest_digest: string;
  asset_manifest_digest: string;
  island_manifest_digest: string;
  vite_manifest_digest: string;
  route_entry_count: number;
  asset_entry_count: number;
  island_entry_count: number;
  output_entry_count: number;
}

export interface AstroObservedViteBuild {
  environment: AstroEnvironment;
  vite_version: string;
  mode: string;
  base: string;
  out_dir: string;
  plugin_count: number;
  observer_plugin_index: number;
  modules: AstroObservedModule[];
  outputs: AstroObservedOutput[];
  failed: boolean;
}

export interface AstroBuildObservation {
  schema_version: typeof ASTRO_BUILD_OBSERVATION_SCHEMA;
  observer: typeof ASTRO_BUILD_OBSERVER;
  observer_version: typeof ASTRO_BUILD_OBSERVER_VERSION;
  capability: typeof ASTRO_BUILD_OBSERVER_CAPABILITY;
  astro_version: string;
  config: AstroObservedConfig;
  manifests: AstroObservedManifests;
  routes: AstroObservedRoute[];
  pages: string[];
  route_assets: Array<{ route_digest: string; assets: string[] }>;
  vite_builds: AstroObservedViteBuild[];
  ssr: {
    middleware_present: boolean;
    route_count: number;
    endpoint_count: number;
    entry_modules: AstroObservedEntryModule[];
  };
  generated: { route_count: number };
}

export interface AstroBuildGraphInput {
  observation: AstroBuildObservation;
  provenance: AstroBuildProvenance;
  baseNodes: readonly GraphNode[];
  baseEdges?: readonly GraphEdge[];
  baseDiagnosticIds?: readonly string[];
}

export interface AstroBuildGraphDelta {
  astroVersion: string;
  viteVersions: string[];
  nodes: GraphNode[];
  sites: DependencySite[];
  edges: GraphEdge[];
  diagnostics: Diagnostic[];
}

export class AstroBuildObserverError extends Error {
  readonly code: string;

  constructor(code: string) {
    super(code);
    this.name = "AstroBuildObserverError";
    this.code = code;
  }
}

function fail(code: string): never {
  throw new AstroBuildObserverError(code);
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

function canonicalPathname(value: unknown, allowEmpty = false): string | null {
  if (allowEmpty && value === "") return "";
  const raw = boundedString(value);
  if (raw === null || !raw.startsWith("/") || raw.includes("\\") || raw.includes("?") || raw.includes("#") || /\s/u.test(raw)) {
    return null;
  }
  const normalized = raw.replace(/\/{2,}/gu, "/");
  return normalized.length > 1 ? normalized.replace(/\/$/u, "") : normalized;
}

function stableVersion(version: unknown, allowedMajors: ReadonlySet<number>, code: string): string {
  const raw = boundedString(version);
  const match = raw === null ? null : /^(\d+)\.(\d+)\.(\d+)$/u.exec(raw);
  if (match === null || !allowedMajors.has(Number(match[1]))) fail(code);
  return raw!;
}

function integrationName(value: unknown, code: string): string {
  const candidate = record(value);
  const name = boundedString(candidate?.name);
  if (candidate === null || name === null) fail(code);
  return name;
}

function validateNames(values: readonly unknown[], ownName: string, code: string): string[] {
  if (values.length > MAX_PLUGIN_NAMES) fail(code);
  const names = values.map((value) => integrationName(value, code));
  if (new Set(names).size !== names.length || names.includes(ownName)) fail(code);
  return names;
}

export function detectAstroObserverCapability(
  astroVersion: string,
  existingIntegrations: readonly unknown[] = [],
  existingVitePlugins: readonly unknown[] = [],
): AstroObserverCapability {
  const version = stableVersion(astroVersion, new Set([5, 6, 7]), "web.astro_build_version_unsupported");
  validateNames(existingIntegrations, ASTRO_BUILD_OBSERVER, "web.astro_build_integration_chain_invalid");
  validateNames(existingVitePlugins, ASTRO_BUILD_OBSERVER, "web.astro_build_plugin_chain_invalid");
  return {
    capability: ASTRO_BUILD_OBSERVER_CAPABILITY,
    astro_version: version,
    existing_integration_count: existingIntegrations.length,
    existing_vite_plugin_count: existingVitePlugins.length,
  };
}

function logicalId(
  rawValue: unknown,
  repoRoot: string,
  allowBareProject = false,
): { id: string; kind: AstroObservedModule["module_kind"] } {
  const raw = boundedString(rawValue);
  if (raw === null) fail("web.astro_build_module_id_unsafe");
  const withoutQuery = raw.split(/[?#]/u, 1)[0]!;
  if (withoutQuery.startsWith("\0") || withoutQuery.startsWith("virtual:")) {
    return { id: `virtual:${sha256(raw)}`, kind: "virtual" };
  }
  let absolute = withoutQuery;
  if (withoutQuery.startsWith("file://")) {
    try {
      absolute = fileURLToPath(withoutQuery);
    } catch {
      fail("web.astro_build_module_id_unsafe");
    }
  }
  if (path.isAbsolute(absolute)) {
    const relative = path.relative(path.resolve(repoRoot), path.resolve(absolute));
    const portable = relative === "" || relative.startsWith("..") || path.isAbsolute(relative)
      ? null
      : canonicalRelativePath(relative);
    return portable === null
      ? { id: `external:${sha256(raw)}`, kind: "external" }
      : { id: portable, kind: "project" };
  }
  if (!allowBareProject && !withoutQuery.startsWith(".")) {
    return { id: `external:${sha256(raw)}`, kind: "external" };
  }
  const portable = canonicalRelativePath(withoutQuery);
  return portable === null
    ? { id: `external:${sha256(raw)}`, kind: "external" }
    : { id: portable, kind: "project" };
}

function sanitizeOutputFile(value: unknown): string {
  const portable = canonicalRelativePath(value);
  if (portable === null) fail("web.astro_build_output_path_unsafe");
  return portable;
}

function setStrings(value: unknown): string[] {
  if (value === undefined) return [];
  if (!(value instanceof Set) || value.size > MAX_OUTPUTS) fail("web.astro_build_vite_metadata_invalid");
  const result = [...value].map(sanitizeOutputFile).sort(compareUtf8);
  return [...new Set(result)];
}

function sanitizeStringArray(value: unknown, sanitizer: (item: unknown) => string, code: string): string[] {
  if (!Array.isArray(value) || value.length > MAX_IMPORTS_PER_MODULE) fail(code);
  return [...new Set(value.map(sanitizer))].sort(compareUtf8);
}

function patternDigest(value: unknown): string {
  if (value instanceof RegExp) return sha256(value.source);
  const candidate = record(value);
  const source = boundedString(candidate?.source) ?? boundedString(value);
  if (source === null) fail("web.astro_build_route_pattern_invalid");
  return sha256(source);
}

function routeType(value: unknown): AstroObservedRoute["type"] {
  return value === "page" || value === "endpoint" || value === "redirect" || value === "fallback"
    ? value
    : "unknown";
}

function routeOrigin(value: unknown): AstroObservedRoute["origin"] {
  return value === "project" || value === "internal" || value === "external"
    ? value
    : "unknown";
}

function routeParams(value: UnknownRecord, routePattern: string): AstroObservedRoute["params"] {
  const spreads = new Map<string, boolean>();
  let partCount = 0;
  if (value.segments !== undefined) {
    if (!Array.isArray(value.segments) || value.segments.length > MAX_PARAMS_PER_ROUTE) {
      fail("web.astro_build_route_params_invalid");
    }
    for (const segment of value.segments) {
      if (!Array.isArray(segment) || segment.length > MAX_PARAMS_PER_ROUTE) {
        fail("web.astro_build_route_params_invalid");
      }
      for (const partValue of segment) {
        partCount += 1;
        if (partCount > MAX_PARAMS_PER_ROUTE) fail("web.astro_build_route_params_invalid");
        const part = record(partValue);
        if (part === null || typeof part.dynamic !== "boolean" || typeof part.spread !== "boolean") {
          fail("web.astro_build_route_params_invalid");
        }
        if (!part.dynamic) continue;
        const raw = boundedString(part.content);
        const name = raw?.replace(/^\.\.\./u, "") ?? null;
        if (name === null || !/^[A-Za-z_][A-Za-z0-9_-]*$/u.test(name)) {
          fail("web.astro_build_route_params_invalid");
        }
        const previous = spreads.get(name);
        if (previous !== undefined && previous !== part.spread) fail("web.astro_build_route_params_invalid");
        spreads.set(name, part.spread);
      }
    }
  }
  let rawParams: unknown[];
  if (value.params === undefined) {
    rawParams = [...routePattern.matchAll(/\[(\.\.\.)?([A-Za-z_][A-Za-z0-9_-]*)\]/gu)]
      .map((match) => `${match[1] ?? ""}${match[2]!}`);
  } else {
    if (!Array.isArray(value.params) || value.params.length > MAX_PARAMS_PER_ROUTE) {
      fail("web.astro_build_route_params_invalid");
    }
    rawParams = value.params;
  }
  const params = rawParams.map((param) => {
    const raw = boundedString(param);
    const spread = raw?.startsWith("...") === true;
    const name = raw?.replace(/^\.\.\./u, "") ?? null;
    if (name === null || !/^[A-Za-z_][A-Za-z0-9_-]*$/u.test(name)) {
      fail("web.astro_build_route_params_invalid");
    }
    return { name, spread: spreads.get(name) ?? spread };
  });
  if (new Set(params.map((param) => param.name)).size !== params.length) {
    fail("web.astro_build_route_params_invalid");
  }
  if (spreads.size > 0 && (spreads.size !== params.length
    || params.some((param) => spreads.get(param.name) !== param.spread))) {
    fail("web.astro_build_route_params_invalid");
  }
  return params;
}

function sanitizeRoute(value: unknown, repoRoot: string): AstroObservedRoute {
  const route = record(value);
  if (route === null) fail("web.astro_build_route_contract_invalid");
  const pathname = route.pathname === undefined || route.pathname === null
    ? null
    : canonicalPathname(route.pathname);
  if (route.pathname !== undefined && route.pathname !== null && pathname === null) {
    fail("web.astro_build_route_pathname_unsafe");
  }
  const routePattern = canonicalPathname(
    route.route ?? (typeof route.pattern === "string" ? route.pattern : pathname),
  );
  if (routePattern === null) fail("web.astro_build_route_pattern_invalid");
  const component = logicalId(route.entrypoint ?? route.component, repoRoot, true);
  const pattern = patternDigest(route.patternRegex ?? route.pattern);
  const params = routeParams(route, routePattern);
  const origin = routeOrigin(route.origin);
  const injected = route.origin !== undefined && origin !== "project";
  const dynamic = params.length > 0 || pathname === null;
  const prerender = typeof route.isPrerendered === "boolean"
    ? route.isPrerendered
    : typeof route.prerender === "boolean"
      ? route.prerender
      : null;
  const identity: Record<string, JsonValue> = {
    route_pattern: routePattern,
    pathname,
    pattern_digest: pattern,
    component_id: component.id,
    component_kind: component.kind,
    type: routeType(route.type),
    prerender,
    params,
    dynamic,
    origin,
    injected,
  };
  return {
    route_digest: digestIdentity(identity),
    route_pattern: routePattern,
    pathname,
    pattern_digest: pattern,
    component_id: component.id,
    component_kind: component.kind,
    type: routeType(route.type),
    prerender,
    params,
    dynamic,
    origin,
    injected,
  };
}

function safeOutput(value: unknown): "static" | "server" {
  return value === "server" ? "server" : "static";
}

function safeTrailingSlash(value: unknown): AstroObservedConfig["trailing_slash"] {
  return value === "always" || value === "never" ? value : "ignore";
}

function normalizeConfig(
  configValue: unknown,
  capability: AstroObserverCapability,
  dynamicConfigDetected: boolean,
): AstroObservedConfig {
  const config = record(configValue);
  if (config === null) fail("web.astro_build_config_contract_invalid");
  const base = config.base === undefined ? "" : config.base === "/" ? "" : canonicalPathname(config.base, true);
  if (base === null) fail("web.astro_build_config_metadata_unsafe");
  if (Array.isArray(config.integrations) && config.integrations.length > MAX_PLUGIN_NAMES) {
    fail("web.astro_build_integration_chain_invalid");
  }
  return {
    output: safeOutput(config.output),
    base,
    trailing_slash: safeTrailingSlash(config.trailingSlash),
    adapter_present: config.adapter !== undefined && config.adapter !== null,
    integration_count: Array.isArray(config.integrations)
      ? config.integrations.length
      : capability.existing_integration_count + 1,
    dynamic_config_detected: dynamicConfigDetected,
  };
}

interface MutableObserverState {
  readonly repoRoot: string;
  readonly capability: AstroObserverCapability;
  readonly sink: AstroObserverSink;
  readonly timeoutMs: number;
  readonly dynamicConfigDetected: boolean;
  readonly expectedIntegrationNames: string[];
  readonly expectedVitePluginNames: string[];
  config: AstroObservedConfig | null;
  routes: AstroObservedRoute[];
  pages: string[];
  routeAssets: Array<{ route_digest: string; assets: string[] }>;
  viteBuilds: Map<AstroEnvironment, AstroObservedViteBuild>;
  ssr: {
    middleware_present: boolean;
    route_count: number;
    endpoint_count: number;
    entry_modules: AstroObservedEntryModule[];
  };
  generated: { route_count: number };
  hooks: {
    routes: boolean;
    config: boolean;
    setup: Set<AstroEnvironment>;
    ssr: boolean;
    generated: boolean;
  };
  wrote: boolean;
}

function timeoutMs(value: number | undefined): number {
  const timeout = value ?? DEFAULT_TIMEOUT_MS;
  if (!Number.isSafeInteger(timeout) || timeout <= 0 || timeout > MAX_TIMEOUT_MS) {
    fail("web.astro_build_timeout_invalid");
  }
  return timeout;
}

async function boundedHook<T>(code: string, timeout: number, operation: () => Awaitable<T>): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      Promise.resolve().then(operation).catch((error: unknown) => {
        if (error instanceof AstroBuildObserverError) throw error;
        fail(code);
      }),
      new Promise<T>((_resolve, reject) => {
        timer = setTimeout(() => reject(new AstroBuildObserverError("web.astro_build_observer_timeout")), timeout);
        timer.unref?.();
      }),
    ]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

function viteEnvironment(
  context: UnknownRecord,
  config: UnknownRecord | null,
  expected?: AstroEnvironment,
): AstroEnvironment {
  const environment = boundedString(record(context.environment)?.name);
  const observed = environment === "client" || environment === "browser"
    ? "browser"
    : environment === "ssr" || environment === "server"
      ? "server"
      : null;
  if (expected !== undefined) {
    if (observed !== null && observed !== expected) fail("web.astro_build_environment_mismatch");
    return expected;
  }
  if (observed !== null) return observed;
  const ssr = record(config?.build)?.ssr;
  return ssr === true || typeof ssr === "string" ? "server" : "browser";
}

function viteMode(value: unknown): string {
  return boundedString(value) ?? "production";
}

function viteBase(value: unknown): string {
  if (value === undefined || value === "/") return "";
  const normalized = canonicalPathname(value, true);
  if (normalized === null) fail("web.astro_build_vite_config_unsafe");
  return normalized;
}

function viteOutDir(value: unknown, repoRoot: string): string {
  const raw = boundedString(value);
  if (raw === null) return "dist";
  if (!path.isAbsolute(raw)) {
    const relative = canonicalRelativePath(raw);
    if (relative === null) fail("web.astro_build_vite_config_unsafe");
    return relative;
  }
  const relative = path.relative(path.resolve(repoRoot), path.resolve(raw));
  const portable = canonicalRelativePath(relative);
  if (portable === null) fail("web.astro_build_vite_config_unsafe");
  return portable;
}

function pluginNames(config: UnknownRecord): string[] {
  const plugins = config.plugins;
  if (!Array.isArray(plugins) || plugins.length > MAX_PLUGIN_NAMES) fail("web.astro_build_vite_config_invalid");
  return plugins.map((plugin) => integrationName(plugin, "web.astro_build_vite_config_invalid"));
}

function validateExpectedChain(names: readonly string[], expected: readonly string[], ownName: string, code: string): number {
  const ownIndexes = names.flatMap((name, index) => name === ownName ? [index] : []);
  if (ownIndexes.length !== 1) fail(code);
  let previousIndex = -1;
  for (const name of expected) {
    const indexes = names.flatMap((candidate, index) => candidate === name ? [index] : []);
    if (indexes.length !== 1 || indexes[0]! <= previousIndex || indexes[0]! >= ownIndexes[0]!) fail(code);
    previousIndex = indexes[0]!;
  }
  return ownIndexes[0]!;
}

function contextMethod(context: UnknownRecord, name: string): ((...args: unknown[]) => unknown) | null {
  const method = context[name];
  return typeof method === "function" ? method.bind(context) as (...args: unknown[]) => unknown : null;
}

function moduleInfo(
  idValue: unknown,
  infoValue: unknown,
  repoRoot: string,
): AstroObservedModule {
  const own = logicalId(idValue, repoRoot);
  const info = record(infoValue);
  if (info === null) fail("web.astro_build_module_info_invalid");
  const imported = sanitizeStringArray(
    info.importedIds ?? [],
    (value) => logicalId(value, repoRoot).id,
    "web.astro_build_module_imports_invalid",
  );
  const dynamic = sanitizeStringArray(
    info.dynamicallyImportedIds ?? [],
    (value) => logicalId(value, repoRoot).id,
    "web.astro_build_module_imports_invalid",
  );
  return {
    module_id: own.id,
    module_kind: own.kind,
    role: "module",
    is_entry: info.isEntry === true,
    imported_ids: imported,
    dynamic_imported_ids: dynamic,
  };
}

function outputDigest(value: unknown, code: string): string {
  if (typeof value === "string" || value instanceof Uint8Array) return sha256(value);
  fail(code);
}

function observedOutput(value: unknown, repoRoot: string, environment: AstroEnvironment): AstroObservedOutput {
  const output = record(value);
  if (output === null) fail("web.astro_build_output_contract_invalid");
  const fileName = sanitizeOutputFile(output.fileName);
  if (output.type === "asset") {
    return {
      file_name: fileName,
      kind: "asset",
      role: "asset",
      boundary: environment,
      digest: outputDigest(output.source, "web.astro_build_asset_source_invalid"),
      entry: false,
      module_ids: [],
      imported_outputs: [],
      referenced_assets: [],
    };
  }
  if (output.type !== "chunk") fail("web.astro_build_output_contract_invalid");
  const modules = record(output.modules);
  if (modules === null || Object.keys(modules).length > MAX_MODULES) fail("web.astro_build_chunk_modules_invalid");
  const moduleIds = Object.keys(modules).map((id) => logicalId(id, repoRoot).id).sort(compareUtf8);
  const metadata = record(output.viteMetadata);
  const referencedAssets = metadata === null
    ? []
    : [...setStrings(metadata.importedAssets), ...setStrings(metadata.importedCss)].sort(compareUtf8);
  return {
    file_name: fileName,
    kind: "chunk",
    role: environment === "browser" ? "client_chunk" : "server_chunk",
    boundary: environment,
    digest: outputDigest(output.code, "web.astro_build_chunk_code_invalid"),
    entry: output.isEntry === true,
    module_ids: [...new Set(moduleIds)],
    imported_outputs: sanitizeStringArray(
      [...(Array.isArray(output.imports) ? output.imports : []), ...(Array.isArray(output.dynamicImports) ? output.dynamicImports : [])],
      sanitizeOutputFile,
      "web.astro_build_chunk_imports_invalid",
    ),
    referenced_assets: [...new Set(referencedAssets)],
  };
}

function createViteObserverPlugin(
  state: MutableObserverState,
  expectedEnvironment?: AstroEnvironment,
): AstroVitePluginLike {
  let resolvedConfig: UnknownRecord | null = null;
  let names: string[] = [];
  let version: string | null = null;
  const upsert = (environment: AstroEnvironment, update: Partial<AstroObservedViteBuild>): void => {
    const previous = state.viteBuilds.get(environment);
    const next: AstroObservedViteBuild = {
      environment,
      vite_version: version ?? previous?.vite_version ?? "0.0.0",
      mode: previous?.mode ?? "production",
      base: previous?.base ?? "",
      out_dir: previous?.out_dir ?? "dist",
      plugin_count: previous?.plugin_count ?? 0,
      observer_plugin_index: previous?.observer_plugin_index ?? -1,
      modules: previous?.modules ?? [],
      outputs: previous?.outputs ?? [],
      failed: previous?.failed ?? false,
      ...update,
    };
    state.viteBuilds.set(environment, next);
  };
  return {
    name: ASTRO_BUILD_OBSERVER,
    apply: "build",
    enforce: "post",
    configResolved(config) {
      resolvedConfig = config;
      names = pluginNames(config);
      const observerIndex = validateExpectedChain(
        names,
        state.expectedVitePluginNames,
        ASTRO_BUILD_OBSERVER,
        "web.astro_build_plugin_chain_invalid",
      );
      const environment = viteEnvironment({}, config, expectedEnvironment);
      upsert(environment, {
        mode: viteMode(config.mode),
        base: viteBase(config.base),
        out_dir: viteOutDir(record(config.build)?.outDir, state.repoRoot),
        plugin_count: names.length,
        observer_plugin_index: observerIndex,
      });
    },
    buildStart() {
      const meta = record(this.meta);
      version = stableVersion(meta?.viteVersion, new Set([6, 7]), "web.astro_build_vite_version_unsupported");
      const environment = viteEnvironment(this, resolvedConfig, expectedEnvironment);
      upsert(environment, { vite_version: version });
    },
    generateBundle(_outputOptions, bundle) {
      const environment = viteEnvironment(this, resolvedConfig, expectedEnvironment);
      const idsMethod = contextMethod(this, "getModuleIds");
      const infoMethod = contextMethod(this, "getModuleInfo");
      if (idsMethod === null || infoMethod === null) fail("web.astro_build_module_graph_unavailable");
      const rawIds = [...idsMethod() as Iterable<unknown>];
      if (rawIds.length > MAX_MODULES) fail("web.astro_build_module_limit_exceeded");
      const mergedModules = new Map<string, AstroObservedModule>();
      for (const id of rawIds) {
        const item = moduleInfo(id, infoMethod(id), state.repoRoot);
        const previous = mergedModules.get(item.module_id);
        mergedModules.set(item.module_id, previous === undefined ? item : {
          ...item,
          is_entry: previous.is_entry || item.is_entry,
          imported_ids: [...new Set([...previous.imported_ids, ...item.imported_ids])].sort(compareUtf8),
          dynamic_imported_ids: [...new Set([...previous.dynamic_imported_ids, ...item.dynamic_imported_ids])].sort(compareUtf8),
        });
      }
      const modules = [...mergedModules.values()].sort((left, right) => compareUtf8(left.module_id, right.module_id));
      const outputValues = Object.values(bundle);
      if (outputValues.length > MAX_OUTPUTS) fail("web.astro_build_output_limit_exceeded");
      const outputs = outputValues.map((output) => observedOutput(output, state.repoRoot, environment))
        .sort((left, right) => compareUtf8(left.file_name, right.file_name));
      upsert(environment, { modules, outputs });
    },
    buildEnd(error) {
      if (error === undefined || error === null) return;
      upsert(viteEnvironment(this, resolvedConfig, expectedEnvironment), { failed: true });
    },
  };
}

function manifestEntryModules(value: unknown, repoRoot: string): AstroObservedEntryModule[] {
  const entries = record(value);
  if (entries === null || Object.keys(entries).length > MAX_MODULES) {
    fail("web.astro_build_ssr_manifest_invalid");
  }
  const result = new Map<string, AstroObservedEntryModule>();
  for (const [rawId, rawChunk] of Object.entries(entries)) {
    if (rawChunk === "") continue;
    const module = logicalId(rawId, repoRoot, true);
    const raw = boundedString(rawChunk);
    const chunk = sanitizeOutputFile(raw?.split(/[?#]/u, 1)[0]);
    const item: AstroObservedEntryModule = {
      module_id: module.id,
      module_kind: module.kind,
      chunk,
    };
    const previous = result.get(item.module_id);
    if (previous !== undefined && canonicalJson(previous as unknown as JsonValue)
      !== canonicalJson(item as unknown as JsonValue)) {
      fail("web.astro_build_ssr_manifest_invalid");
    }
    result.set(item.module_id, item);
  }
  return [...result.values()].sort((left, right) => compareUtf8(left.module_id, right.module_id));
}

function confinedDistArtifact(value: unknown, dirValue: unknown): string {
  if (!(value instanceof URL) || !(dirValue instanceof URL)
    || value.protocol !== "file:" || dirValue.protocol !== "file:") {
    fail("web.astro_build_assets_contract_invalid");
  }
  let candidate: string;
  let root: string;
  try {
    candidate = fileURLToPath(value);
    root = fileURLToPath(dirValue);
  } catch {
    fail("web.astro_build_assets_contract_invalid");
  }
  const relative = path.relative(path.resolve(root), path.resolve(candidate));
  const portable = canonicalRelativePath(relative);
  if (portable === null) fail("web.astro_build_output_path_unsafe");
  return portable;
}

function routeAssetRows(
  value: unknown,
  routes: readonly AstroObservedRoute[],
  outputDir: unknown,
): Array<{ route_digest: string; assets: string[] }> {
  if (!(outputDir instanceof URL) || outputDir.protocol !== "file:") {
    fail("web.astro_build_assets_contract_invalid");
  }
  if (value === undefined) return [];
  if (!(value instanceof Map) || value.size > MAX_ROUTES) fail("web.astro_build_assets_contract_invalid");
  const rows: Array<{ route_digest: string; assets: string[] }> = [];
  let assetCount = 0;
  for (const [routePatternValue, assets] of value.entries()) {
    const routePattern = canonicalPathname(routePatternValue);
    const routeDigest = routes.find((candidate) => candidate.route_pattern === routePattern)?.route_digest;
    if (routeDigest === undefined) fail("web.astro_build_assets_route_unknown");
    if (!Array.isArray(assets) || assets.length > MAX_OUTPUTS) fail("web.astro_build_assets_contract_invalid");
    assetCount += assets.length;
    if (assetCount > MAX_OUTPUTS) fail("web.astro_build_output_limit_exceeded");
    rows.push({
      route_digest: routeDigest,
      assets: [...new Set(assets.map((asset) => confinedDistArtifact(asset, outputDir)))].sort(compareUtf8),
    });
  }
  return rows.sort((left, right) => compareUtf8(left.route_digest, right.route_digest));
}

function pagePathnames(value: unknown): string[] {
  if (!Array.isArray(value) || value.length > MAX_ROUTES) fail("web.astro_build_pages_contract_invalid");
  return [...new Set(value.map((page) => {
    const candidate = record(page);
    const pathname = canonicalPathname(candidate?.pathname ?? candidate?.route ?? page);
    if (pathname === null) fail("web.astro_build_page_pathname_unsafe");
    return pathname;
  }))].sort(compareUtf8);
}

function componentLikeModule(moduleId: string): boolean {
  return /\.(?:astro|[cm]?[jt]sx?|vue|svelte)$/u.test(moduleId);
}

function finalizeViteBuild(
  build: AstroObservedViteBuild,
  routes: readonly AstroObservedRoute[],
  entryModules: readonly AstroObservedEntryModule[],
): AstroObservedViteBuild {
  const routeByComponent = new Map(routes.map((route) => [route.component_id, route]));
  const entryModuleIds = new Set(entryModules.map((entry) => entry.module_id));
  const entryChunks = new Set(entryModules.map((entry) => entry.chunk));
  const modules = build.modules.map((module) => {
    const route = routeByComponent.get(module.module_id);
    const role: AstroObservedModule["role"] = route?.type === "endpoint"
      ? "endpoint"
      : route !== undefined
        ? "route"
        : build.environment === "browser" && module.module_kind === "project"
          && entryModuleIds.has(module.module_id) && componentLikeModule(module.module_id)
          ? "island"
          : "module";
    return { ...module, role };
  });
  const roles = new Map(modules.map((module) => [module.module_id, module.role]));
  const outputs = build.outputs.map((output) => {
    if (output.kind === "asset") return { ...output, role: "asset" as const };
    const moduleRoles = new Set(output.module_ids.map((moduleId) => roles.get(moduleId)));
    const role: AstroObservedOutput["role"] = moduleRoles.has("endpoint")
      ? "endpoint_chunk"
      : build.environment === "browser" && (moduleRoles.has("island") || entryChunks.has(output.file_name))
        ? "hydration_chunk"
        : moduleRoles.has("route")
          ? "route_chunk"
          : build.environment === "browser"
            ? "client_chunk"
            : "server_chunk";
    return { ...output, role };
  });
  return { ...build, modules, outputs };
}

function finalObservation(state: MutableObserverState): AstroBuildObservation {
  if (state.config === null) fail("web.astro_build_config_unavailable");
  if (!state.hooks.routes || !state.hooks.config
    || !state.hooks.setup.has("browser") || !state.hooks.setup.has("server")
    || !state.hooks.ssr || !state.hooks.generated) {
    fail("web.astro_build_hook_missing");
  }
  for (const environment of ["browser", "server"] as const) {
    const build = state.viteBuilds.get(environment);
    if (build === undefined || build.failed) fail("web.astro_build_environment_observation_incomplete");
  }
  const routes = [...state.routes].sort((left, right) => compareUtf8(left.route_digest, right.route_digest));
  if (new Set(routes.map((route) => route.route_digest)).size !== routes.length) {
    fail("web.astro_build_route_manifest_invalid");
  }
  const routeAssets = [...state.routeAssets].sort((left, right) => compareUtf8(left.route_digest, right.route_digest));
  const viteBuilds = [...state.viteBuilds.values()]
    .map((build) => finalizeViteBuild(build, routes, state.ssr.entry_modules))
    .sort((left, right) => compareUtf8(left.environment, right.environment));
  const outputEntryCount = viteBuilds.reduce((count, build) => count + build.outputs.length, 0);
  const assetEntryCount = routeAssets.reduce((count, row) => count + row.assets.length, 0);
  const manifests: AstroObservedManifests = {
    contract_version: ASTRO_BUILD_MANIFEST_CONTRACT,
    route_manifest_digest: digestIdentity(routes as unknown as JsonValue),
    asset_manifest_digest: digestIdentity(routeAssets as unknown as JsonValue),
    island_manifest_digest: digestIdentity(state.ssr.entry_modules as unknown as JsonValue),
    vite_manifest_digest: digestIdentity(viteBuilds as unknown as JsonValue),
    route_entry_count: routes.length,
    asset_entry_count: assetEntryCount,
    island_entry_count: state.ssr.entry_modules.length,
    output_entry_count: outputEntryCount,
  };
  const observation: AstroBuildObservation = {
    schema_version: ASTRO_BUILD_OBSERVATION_SCHEMA,
    observer: ASTRO_BUILD_OBSERVER,
    observer_version: ASTRO_BUILD_OBSERVER_VERSION,
    capability: ASTRO_BUILD_OBSERVER_CAPABILITY,
    astro_version: state.capability.astro_version,
    config: state.config,
    manifests,
    routes,
    pages: state.pages,
    route_assets: routeAssets,
    vite_builds: viteBuilds,
    ssr: state.ssr,
    generated: state.generated,
  };
  validateAstroBuildObservation(observation);
  return observation;
}

export function createAstroBuildObserverIntegration(options: AstroBuildObserverOptions): AstroIntegrationLike {
  const capability = detectAstroObserverCapability(
    options.astroVersion,
    options.existingIntegrations ?? [],
    options.existingVitePlugins ?? [],
  );
  if (boundedString(options.repoRoot) === null || !path.isAbsolute(options.repoRoot)) {
    fail("web.astro_build_repo_root_invalid");
  }
  const root = path.resolve(options.repoRoot);
  const expectedIntegrationNames = validateNames(
    options.existingIntegrations ?? [], ASTRO_BUILD_OBSERVER, "web.astro_build_integration_chain_invalid",
  );
  const expectedVitePluginNames = validateNames(
    options.existingVitePlugins ?? [], ASTRO_BUILD_OBSERVER, "web.astro_build_plugin_chain_invalid",
  );
  const state: MutableObserverState = {
    repoRoot: root,
    capability,
    sink: options.sink,
    timeoutMs: timeoutMs(options.timeoutMs),
    dynamicConfigDetected: options.dynamicConfigDetected === true,
    expectedIntegrationNames,
    expectedVitePluginNames,
    config: null,
    routes: [],
    pages: [],
    routeAssets: [],
    viteBuilds: new Map(),
    ssr: { middleware_present: false, route_count: 0, endpoint_count: 0, entry_modules: [] },
    generated: { route_count: 0 },
    hooks: { routes: false, config: false, setup: new Set(), ssr: false, generated: false },
    wrote: false,
  };
  return {
    name: ASTRO_BUILD_OBSERVER,
    hooks: {
      "astro:routes:resolved": async (context) => boundedHook("web.astro_build_routes_hook_failed", state.timeoutMs, () => {
        if (!Array.isArray(context.routes) || context.routes.length > MAX_ROUTES) fail("web.astro_build_routes_contract_invalid");
        state.routes = context.routes.map((route) => sanitizeRoute(route, state.repoRoot));
        state.hooks.routes = true;
      }),
      "astro:config:done": async (context) => boundedHook("web.astro_build_config_hook_failed", state.timeoutMs, () => {
        const integrations = record(context.config)?.integrations;
        if (Array.isArray(integrations) && integrations.length <= MAX_PLUGIN_NAMES) {
          validateExpectedChain(
            integrations.map((value) => integrationName(value, "web.astro_build_integration_chain_invalid")),
            state.expectedIntegrationNames,
            ASTRO_BUILD_OBSERVER,
            "web.astro_build_integration_chain_invalid",
          );
        } else if (state.expectedIntegrationNames.length > 0 || Array.isArray(integrations)) {
          fail("web.astro_build_integration_chain_invalid");
        }
        state.config = normalizeConfig(context.config, capability, state.dynamicConfigDetected);
        state.hooks.config = true;
      }),
      "astro:build:setup": async (context) => boundedHook("web.astro_build_setup_hook_failed", state.timeoutMs, () => {
        if (typeof context.updateConfig !== "function") fail("web.astro_build_hook_unavailable");
        const environment: AstroEnvironment = context.target === "client"
          ? "browser"
          : context.target === "server"
            ? "server"
            : fail("web.astro_build_hook_unavailable");
        if (state.hooks.setup.has(environment)) fail("web.astro_build_setup_hook_duplicate");
        const plugin = createViteObserverPlugin(state, environment);
        (context.updateConfig as (value: unknown) => unknown)({ plugins: [plugin] });
        state.hooks.setup.add(environment);
      }),
      "astro:build:ssr": async (context) => boundedHook("web.astro_build_ssr_hook_failed", state.timeoutMs, () => {
        const manifest = record(context.manifest);
        const routes = manifest?.routes;
        if (!Array.isArray(routes) || routes.length > MAX_ROUTES) fail("web.astro_build_ssr_manifest_invalid");
        state.ssr = {
          middleware_present: context.middlewareEntryPoint !== undefined && context.middlewareEntryPoint !== null,
          route_count: routes.length,
          endpoint_count: state.routes.filter((route) => route.type === "endpoint" && route.prerender !== true).length,
          entry_modules: manifestEntryModules(manifest?.entryModules, state.repoRoot),
        };
        state.hooks.ssr = true;
      }),
      "astro:build:generated": async (context) => boundedHook("web.astro_build_generated_hook_failed", state.timeoutMs, () => {
        if (!(context.routeToHeaders instanceof Map) || context.routeToHeaders.size > MAX_ROUTES) {
          fail("web.astro_build_generated_manifest_invalid");
        }
        state.generated = { route_count: context.routeToHeaders.size };
        state.hooks.generated = true;
      }),
      "astro:build:done": async (context) => boundedHook("web.astro_build_done_hook_failed", state.timeoutMs, async () => {
        if (state.wrote) fail("web.astro_build_observation_already_written");
        state.pages = pagePathnames(context.pages ?? []);
        state.routeAssets = routeAssetRows(context.assets, state.routes, context.dir);
        const observation = finalObservation(state);
        await boundedHook("web.astro_build_observer_sink_failed", state.timeoutMs, () => state.sink.write(observation));
        state.wrote = true;
      }),
    },
  };
}

export function preflightAstroBuildObserver(options: AstroBuildObserverOptions): {
  integration: AstroIntegrationLike;
  capability: AstroObserverCapability;
} {
  const capability = detectAstroObserverCapability(
    options.astroVersion,
    options.existingIntegrations ?? [],
    options.existingVitePlugins ?? [],
  );
  return { integration: createAstroBuildObserverIntegration(options), capability };
}

export function astroBuildFailureDiagnostic(error: unknown, profileId: string): Diagnostic {
  const code = error instanceof AstroBuildObserverError && /^web\.astro_build_[a-z0-9_]+$/u.test(error.code)
    ? error.code
    : "web.astro_build_observer_failed";
  const properties: Record<string, JsonValue> = {
    framework: "astro",
    observer: ASTRO_BUILD_OBSERVER,
    observer_version: ASTRO_BUILD_OBSERVER_VERSION,
    capability: ASTRO_BUILD_OBSERVER_CAPABILITY,
    contract_version: FRAMEWORK_BUILD_GRAPH_CONTRACT_VERSION,
    observer_failure: true,
  };
  return {
    id: stableId("diagnostic", { code, profile_id: profileId, properties }),
    severity: "error",
    code,
    message: `${code}: Astro build observation was not promoted`,
    path: null,
    profile_id: profileId,
    properties,
  };
}

function validateProvenance(provenance: AstroBuildProvenance): void {
  try {
    validateFrameworkBuildProvenance(provenance);
  } catch {
    fail("web.astro_build_provenance_invalid");
  }
}

function buildEvidence(
  provenance: AstroBuildProvenance,
  logicalPath: string,
  artifactDigest: string,
): Evidence {
  return frameworkBuildEvidence(
    ASTRO_FRAMEWORK_BUILD_DESCRIPTOR,
    provenance,
    logicalPath,
    artifactDigest,
  );
}

function buildNode(
  kind: GraphNode["kind"],
  identity: Record<string, JsonValue>,
  displayName: string,
  properties: Record<string, JsonValue>,
  provenance: AstroBuildProvenance,
  logicalPath: string,
  artifactDigest: string,
): GraphNode {
  return frameworkBuildGeneratedNode(
    ASTRO_FRAMEWORK_BUILD_DESCRIPTOR,
    kind,
    identity,
    displayName,
    properties,
    provenance,
    logicalPath,
    artifactDigest,
  );
}

function observedCondition(environment: AstroEnvironment, extra: Array<{ key: string; value: string }> = []): Condition {
  return frameworkBuildCondition(environment, Object.fromEntries(extra.map(({ key, value }) => [key, value])));
}

function addObservedRelation(
  sites: DependencySite[],
  edges: GraphEdge[],
  source: string,
  target: string,
  kind: string,
  specifier: string,
  environment: AstroEnvironment,
  condition: Condition,
  evidence: Evidence,
  profileId: string,
): void {
  const { site, edge } = frameworkBuildRelation(
    ASTRO_FRAMEWORK_BUILD_DESCRIPTOR,
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

function graphDiagnostic(
  code: string,
  subject: string,
  profileId: string,
  evidence: Evidence,
  properties: Record<string, JsonValue>,
  severity: Diagnostic["severity"] = "warning",
): Diagnostic {
  return frameworkBuildDiagnostic(
    ASTRO_FRAMEWORK_BUILD_DESCRIPTOR,
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

function propertyPath(node: GraphNode): string | null {
  for (const key of ["source_path", "relative_path", "path"]) {
    const value = node.properties[key];
    if (typeof value === "string") return value;
  }
  return null;
}

function indexByPath(nodes: readonly GraphNode[]): Map<string, GraphNode[]> {
  const result = new Map<string, GraphNode[]>();
  for (const node of nodes) {
    const sourcePath = propertyPath(node);
    if (sourcePath === null) continue;
    const values = result.get(sourcePath) ?? [];
    values.push(node);
    result.set(sourcePath, values);
  }
  return result;
}

function indexAstroRoutes(nodes: readonly GraphNode[]): Map<string, GraphNode[]> {
  const result = new Map<string, GraphNode[]>();
  for (const node of nodes) {
    if (node.kind !== "route" || node.properties.framework !== "astro") continue;
    for (const value of [node.properties.route_pattern, node.properties.pattern]) {
      if (typeof value !== "string") continue;
      const values = result.get(value) ?? [];
      values.push(node);
      result.set(value, values);
    }
  }
  return result;
}

function preferredPathNode(nodes: readonly GraphNode[], environment: AstroEnvironment): GraphNode | null {
  const eligible = nodes.filter((node) => node.kind !== "route");
  const sameEnvironment = eligible.find((node) => node.properties.environment === environment);
  return sameEnvironment ?? eligible.find((node) => node.kind === "component") ?? eligible[0] ?? null;
}

function observedRouteIdentity(route: AstroObservedRoute): Record<string, JsonValue> {
  return {
    route_pattern: route.route_pattern,
    pathname: route.pathname,
    pattern_digest: route.pattern_digest,
    component_id: route.component_id,
    component_kind: route.component_kind,
    type: route.type,
    prerender: route.prerender,
    params: route.params,
    dynamic: route.dynamic,
    origin: route.origin,
    injected: route.injected,
  };
}

function validLogicalId(value: string): boolean {
  return canonicalRelativePath(value) === value
    || /^(?:virtual|external):[a-f0-9]{64}$/u.test(value);
}

function logicalIdKind(value: string): AstroObservedModule["module_kind"] | null {
  if (canonicalRelativePath(value) === value) return "project";
  if (/^virtual:[a-f0-9]{64}$/u.test(value)) return "virtual";
  if (/^external:[a-f0-9]{64}$/u.test(value)) return "external";
  return null;
}

function isCanonicalStringSet(values: readonly string[]): boolean {
  return canonicalJson([...new Set(values)].sort(compareUtf8) as unknown as JsonValue)
    === canonicalJson(values as unknown as JsonValue);
}

function routePatternParams(routePattern: string): AstroObservedRoute["params"] {
  return [...routePattern.matchAll(/\[(\.\.\.)?([A-Za-z_][A-Za-z0-9_-]*)\]/gu)]
    .map((match) => ({ name: match[2]!, spread: match[1] !== undefined }));
}

function validateAstroBuildObservationContract(observation: AstroBuildObservation): void {
  if (observation.schema_version !== ASTRO_BUILD_OBSERVATION_SCHEMA
    || observation.capability !== ASTRO_BUILD_OBSERVER_CAPABILITY
    || observation.observer !== ASTRO_BUILD_OBSERVER
    || observation.observer_version !== ASTRO_BUILD_OBSERVER_VERSION
    || observation.manifests?.contract_version !== ASTRO_BUILD_MANIFEST_CONTRACT
    || !Array.isArray(observation.routes)
    || !Array.isArray(observation.route_assets)
    || !Array.isArray(observation.vite_builds)
    || !Array.isArray(observation.pages)
    || observation.ssr === undefined
    || !Array.isArray(observation.ssr.entry_modules)
    || observation.generated === undefined) {
    fail("web.astro_build_observation_contract_invalid");
  }
  if (record(observation.config) === null
    || observation.routes.some((route) => record(route) === null)
    || observation.route_assets.some((row) => record(row) === null)
    || observation.vite_builds.some((build) => (
      record(build) === null || !Array.isArray(build.modules) || !Array.isArray(build.outputs)
    ))
    || observation.ssr.entry_modules.some((entry) => record(entry) === null)) {
    fail("web.astro_build_observation_contract_invalid");
  }
  if (!["static", "server"].includes(observation.config.output)
    || canonicalPathname(observation.config.base, true) !== observation.config.base
    || !["always", "never", "ignore"].includes(observation.config.trailing_slash)
    || typeof observation.config.adapter_present !== "boolean"
    || !Number.isSafeInteger(observation.config.integration_count)
    || observation.config.integration_count < 1
    || observation.config.integration_count > MAX_PLUGIN_NAMES
    || typeof observation.config.dynamic_config_detected !== "boolean"
    || observation.pages.some((page) => canonicalPathname(page) !== page)
    || !isCanonicalStringSet(observation.pages)) {
    fail("web.astro_build_observation_contract_invalid");
  }
  detectAstroObserverCapability(observation.astro_version);
  const manifests = observation.manifests;
  const outputCount = observation.vite_builds.reduce((count, build) => count + build.outputs.length, 0);
  const assetCount = observation.route_assets.reduce((count, row) => count + row.assets.length, 0);
  if (!/^[a-f0-9]{64}$/u.test(manifests.route_manifest_digest)
    || !/^[a-f0-9]{64}$/u.test(manifests.asset_manifest_digest)
    || !/^[a-f0-9]{64}$/u.test(manifests.island_manifest_digest)
    || !/^[a-f0-9]{64}$/u.test(manifests.vite_manifest_digest)
    || manifests.route_entry_count !== observation.routes.length
    || manifests.asset_entry_count !== assetCount
    || manifests.island_entry_count !== observation.ssr?.entry_modules?.length
    || manifests.output_entry_count !== outputCount
    || manifests.route_manifest_digest !== digestIdentity(observation.routes as unknown as JsonValue)
    || manifests.asset_manifest_digest !== digestIdentity(observation.route_assets as unknown as JsonValue)
    || manifests.island_manifest_digest !== digestIdentity(observation.ssr.entry_modules as unknown as JsonValue)
    || manifests.vite_manifest_digest !== digestIdentity(observation.vite_builds as unknown as JsonValue)) {
    fail("web.astro_build_observation_contract_invalid");
  }
  const routeDigests = new Set<string>();
  for (const route of observation.routes) {
    const params = route.params;
    if (route.route_digest !== digestIdentity(observedRouteIdentity(route))
      || !/^[a-f0-9]{64}$/u.test(route.route_digest)
      || !/^[a-f0-9]{64}$/u.test(route.pattern_digest)
      || canonicalPathname(route.route_pattern) !== route.route_pattern
      || (route.pathname !== null && canonicalPathname(route.pathname) !== route.pathname)
      || !validLogicalId(route.component_id)
      || !["project", "virtual", "external"].includes(route.component_kind)
      || logicalIdKind(route.component_id) !== route.component_kind
      || !["page", "endpoint", "redirect", "fallback", "unknown"].includes(route.type)
      || !Array.isArray(params)
      || params.length > MAX_PARAMS_PER_ROUTE
      || params.some((param) => !/^[A-Za-z_][A-Za-z0-9_-]*$/u.test(param.name)
        || typeof param.spread !== "boolean")
      || new Set(params.map((param) => param.name)).size !== params.length
      || canonicalJson(routePatternParams(route.route_pattern) as unknown as JsonValue)
        !== canonicalJson(params as unknown as JsonValue)
      || route.dynamic !== (params.length > 0 || route.pathname === null)
      || !["project", "internal", "external", "unknown"].includes(route.origin)
      || typeof route.injected !== "boolean"
      || (route.origin === "project" && route.injected)
      || ((route.origin === "internal" || route.origin === "external") && !route.injected)
      || routeDigests.has(route.route_digest)) {
      fail("web.astro_build_observation_contract_invalid");
    }
    routeDigests.add(route.route_digest);
  }
  if (canonicalJson([...observation.routes].sort((left, right) => compareUtf8(left.route_digest, right.route_digest)) as unknown as JsonValue)
    !== canonicalJson(observation.routes as unknown as JsonValue)) {
    fail("web.astro_build_observation_contract_invalid");
  }
  const assetRouteDigests = new Set<string>();
  for (const row of observation.route_assets) {
    if (!routeDigests.has(row.route_digest)
      || assetRouteDigests.has(row.route_digest)
      || !Array.isArray(row.assets)
      || row.assets.some((asset) => canonicalRelativePath(asset) !== asset)
      || !isCanonicalStringSet(row.assets)) {
      fail("web.astro_build_observation_contract_invalid");
    }
    assetRouteDigests.add(row.route_digest);
  }
  if (canonicalJson([...observation.route_assets].sort((left, right) => compareUtf8(left.route_digest, right.route_digest)) as unknown as JsonValue)
    !== canonicalJson(observation.route_assets as unknown as JsonValue)) {
    fail("web.astro_build_observation_contract_invalid");
  }
  const environments = new Set<AstroEnvironment>();
  for (const build of observation.vite_builds) {
    if (!["browser", "server"].includes(build.environment)
      || environments.has(build.environment)
      || build.failed
      || stableVersion(build.vite_version, new Set([6, 7]), "web.astro_build_observation_contract_invalid") !== build.vite_version
      || boundedString(build.mode) === null
      || canonicalPathname(build.base, true) !== build.base
      || canonicalRelativePath(build.out_dir) !== build.out_dir
      || !Number.isSafeInteger(build.plugin_count)
      || build.plugin_count < 1
      || build.plugin_count > MAX_PLUGIN_NAMES
      || !Number.isSafeInteger(build.observer_plugin_index)
      || build.observer_plugin_index < 0
      || build.observer_plugin_index >= build.plugin_count
      || !Array.isArray(build.modules)
      || build.modules.length > MAX_MODULES
      || !Array.isArray(build.outputs)
      || build.outputs.length > MAX_OUTPUTS) {
      fail("web.astro_build_observation_contract_invalid");
    }
    environments.add(build.environment);
    const moduleIds = new Set<string>();
    for (const module of build.modules) {
      if (!validLogicalId(module.module_id)
        || !["project", "virtual", "external"].includes(module.module_kind)
        || logicalIdKind(module.module_id) !== module.module_kind
        || !["route", "endpoint", "island", "module"].includes(module.role)
        || typeof module.is_entry !== "boolean"
        || !Array.isArray(module.imported_ids)
        || !Array.isArray(module.dynamic_imported_ids)
        || module.imported_ids.some((value) => !validLogicalId(value))
        || module.dynamic_imported_ids.some((value) => !validLogicalId(value))
        || !isCanonicalStringSet(module.imported_ids)
        || !isCanonicalStringSet(module.dynamic_imported_ids)
        || moduleIds.has(module.module_id)) {
        fail("web.astro_build_observation_contract_invalid");
      }
      moduleIds.add(module.module_id);
    }
    if (canonicalJson([...build.modules].sort((left, right) => compareUtf8(left.module_id, right.module_id)) as unknown as JsonValue)
      !== canonicalJson(build.modules as unknown as JsonValue)) {
      fail("web.astro_build_observation_contract_invalid");
    }
    const outputNames = new Set<string>();
    for (const output of build.outputs) {
      if (canonicalRelativePath(output.file_name) !== output.file_name
        || !["chunk", "asset"].includes(output.kind)
        || !["route_chunk", "endpoint_chunk", "hydration_chunk", "client_chunk", "server_chunk", "asset"].includes(output.role)
        || output.boundary !== build.environment
        || !/^[a-f0-9]{64}$/u.test(output.digest)
        || typeof output.entry !== "boolean"
        || !Array.isArray(output.module_ids)
        || !Array.isArray(output.imported_outputs)
        || !Array.isArray(output.referenced_assets)
        || output.module_ids.some((value) => !validLogicalId(value))
        || output.imported_outputs.some((value) => canonicalRelativePath(value) !== value)
        || output.referenced_assets.some((value) => canonicalRelativePath(value) !== value)
        || !isCanonicalStringSet(output.module_ids)
        || !isCanonicalStringSet(output.imported_outputs)
        || !isCanonicalStringSet(output.referenced_assets)
        || output.module_ids.some((value) => !moduleIds.has(value))
        || (output.kind === "asset"
          && (output.role !== "asset" || output.entry || output.module_ids.length > 0))
        || (output.kind === "chunk" && output.role === "asset")
        || outputNames.has(output.file_name)) {
        fail("web.astro_build_observation_contract_invalid");
      }
      outputNames.add(output.file_name);
    }
    for (const output of build.outputs) {
      if (output.imported_outputs.some((value) => !outputNames.has(value))) {
        fail("web.astro_build_observation_contract_invalid");
      }
    }
    if (canonicalJson([...build.outputs].sort((left, right) => compareUtf8(left.file_name, right.file_name)) as unknown as JsonValue)
      !== canonicalJson(build.outputs as unknown as JsonValue)) {
      fail("web.astro_build_observation_contract_invalid");
    }
    if (canonicalJson(finalizeViteBuild(build, observation.routes, observation.ssr.entry_modules) as unknown as JsonValue)
      !== canonicalJson(build as unknown as JsonValue)) {
      fail("web.astro_build_observation_contract_invalid");
    }
  }
  if (canonicalJson([...observation.vite_builds].sort((left, right) => compareUtf8(left.environment, right.environment)) as unknown as JsonValue)
    !== canonicalJson(observation.vite_builds as unknown as JsonValue)) {
    fail("web.astro_build_observation_contract_invalid");
  }
  if (environments.size !== 2 || !environments.has("browser") || !environments.has("server")
    || observation.generated === undefined
    || !Number.isSafeInteger(observation.generated.route_count)
    || observation.generated.route_count < 0
    || observation.generated.route_count > MAX_ROUTES
    || observation.ssr === undefined
    || typeof observation.ssr.middleware_present !== "boolean"
    || !Number.isSafeInteger(observation.ssr.route_count)
    || !Number.isSafeInteger(observation.ssr.endpoint_count)
    || observation.ssr.route_count < 0
    || observation.ssr.route_count > MAX_ROUTES
    || observation.ssr.endpoint_count < 0
    || observation.ssr.endpoint_count > MAX_ROUTES
    || observation.ssr.entry_modules.length > MAX_MODULES
    || observation.ssr.endpoint_count
      !== observation.routes.filter((route) => route.type === "endpoint" && route.prerender !== true).length) {
    fail("web.astro_build_observation_contract_invalid");
  }
  const browserOutputs = new Set(
    observation.vite_builds.find((build) => build.environment === "browser")?.outputs
      .map((output) => output.file_name) ?? [],
  );
  const entryIds = new Set<string>();
  for (const entry of observation.ssr.entry_modules) {
    if (!validLogicalId(entry.module_id)
      || !["project", "virtual", "external"].includes(entry.module_kind)
      || logicalIdKind(entry.module_id) !== entry.module_kind
      || canonicalRelativePath(entry.chunk) !== entry.chunk
      || !browserOutputs.has(entry.chunk)
      || entryIds.has(entry.module_id)) {
      fail("web.astro_build_observation_contract_invalid");
    }
    entryIds.add(entry.module_id);
  }
  if (canonicalJson([...observation.ssr.entry_modules].sort((left, right) => compareUtf8(left.module_id, right.module_id)) as unknown as JsonValue)
    !== canonicalJson(observation.ssr.entry_modules as unknown as JsonValue)) {
    fail("web.astro_build_observation_contract_invalid");
  }
  const browserBuild = observation.vite_builds.find((build) => build.environment === "browser")!;
  for (const entry of observation.ssr.entry_modules) {
    const output = browserBuild.outputs.find((candidate) => candidate.file_name === entry.chunk);
    if (output?.kind !== "chunk" || output.role !== "hydration_chunk") {
      fail("web.astro_build_observation_contract_invalid");
    }
  }
  const serverBuild = observation.vite_builds.find((build) => build.environment === "server")!;
  const emittedServerModules = new Set(serverBuild.outputs.flatMap((output) => output.module_ids));
  for (const route of observation.routes) {
    if ((route.type === "page" || route.type === "endpoint")
      && !emittedServerModules.has(route.component_id)) {
      fail("web.astro_build_observation_contract_invalid");
    }
  }
}

function validateAstroBuildObservation(observation: AstroBuildObservation): void {
  try {
    validateAstroBuildObservationContract(observation);
  } catch (error) {
    if (error instanceof AstroBuildObserverError) throw error;
    fail("web.astro_build_observation_contract_invalid");
  }
}

export function buildAstroObservedGraph(input: AstroBuildGraphInput): AstroBuildGraphDelta {
  const observation = input.observation;
  validateAstroBuildObservation(observation);
  validateProvenance(input.provenance);
  const observationDigest = digestIdentity(observation.manifests as unknown as JsonValue);
  const observationPath = `.astro/depgraph/${observationDigest}.json`;
  const observationEvidence = buildEvidence(input.provenance, observationPath, observationDigest);
  const nodes = new Map<string, GraphNode>();
  const sites: DependencySite[] = [];
  const edges: GraphEdge[] = [];
  const diagnostics: Diagnostic[] = [];
  const routeIndex = indexAstroRoutes(input.baseNodes);
  const pathIndex = indexByPath(input.baseNodes);
  const matchedRoutes = new Set<string>();
  const observedRoutes = new Map<string, GraphNode>();
  const observedRouteValues = new Map(observation.routes.map((route) => [route.route_digest, route]));
  const routesByComponent = new Map<string, AstroObservedRoute[]>();
  for (const route of observation.routes) {
    const values = routesByComponent.get(route.component_id) ?? [];
    values.push(route);
    routesByComponent.set(route.component_id, values);
  }
  const addNode = (node: GraphNode): void => {
    const existing = nodes.get(node.id);
    if (existing !== undefined && canonicalJson(existing as unknown as JsonValue) !== canonicalJson(node as unknown as JsonValue)) {
      fail("web.astro_build_node_conflict");
    }
    nodes.set(node.id, node);
  };

  for (const routeValue of observation.routes) {
    const routeKey = routeValue.route_pattern;
    const candidateMap = new Map<string, GraphNode>();
    for (const node of routeIndex.get(routeKey) ?? []) candidateMap.set(node.id, node);
    if (routeValue.pathname !== null) {
      for (const node of routeIndex.get(routeValue.pathname) ?? []) candidateMap.set(node.id, node);
    }
    for (const node of pathIndex.get(routeValue.component_id) ?? []) {
      if (node.kind === "route" && node.properties.framework === "astro") candidateMap.set(node.id, node);
    }
    const candidates = [...candidateMap.values()].sort((left, right) => compareUtf8(left.id, right.id));
    let route: GraphNode;
    if (candidates.length === 1) {
      route = candidates[0]!;
      matchedRoutes.add(route.id);
    } else {
      const identity: Record<string, JsonValue> = {
        framework: "astro",
        route_digest: routeValue.route_digest,
        route_pattern: routeKey,
        route_type: routeValue.type,
        profile_id: input.provenance.profile_id,
      };
      route = buildNode("route", identity, routeKey, {
        framework: "astro",
        route_pattern: identity.route_pattern!,
        route_type: routeValue.type,
        prerender: routeValue.prerender,
        dynamic: routeValue.dynamic,
        dynamic_params: routeValue.params,
        origin: routeValue.origin,
        injected: routeValue.injected,
        observed_only: true,
        profile_id: input.provenance.profile_id,
      }, input.provenance, observationPath, observationDigest);
      diagnostics.push(graphDiagnostic(
        candidates.length > 1
          ? "web.astro_build_route_conflict"
          : routeValue.injected
            ? "web.astro_build_injected_route_observed"
            : "web.astro_build_route_static_missing",
        routeKey,
        input.provenance.profile_id,
        observationEvidence,
        { candidate_count: candidates.length, observed_route_id: route.id, injected: routeValue.injected },
        candidates.length > 1 ? "warning" : "info",
      ));
    }
    addNode(route);
    observedRoutes.set(routeValue.route_digest, route);
    const component = preferredPathNode(pathIndex.get(routeValue.component_id) ?? [], "server");
    if (component !== null) {
      addNode(component);
      addObservedRelation(
        sites, edges, route.id, component.id, "renders", routeValue.component_id, "server",
        observedCondition("server", [
          { key: "astro.route", value: routeKey },
          { key: "astro.route_type", value: routeValue.type },
        ]),
        observationEvidence, input.provenance.profile_id,
      );
    }
  }

  for (const baseRoute of input.baseNodes) {
    if (baseRoute.kind !== "route" || baseRoute.properties.framework !== "astro" || matchedRoutes.has(baseRoute.id)) continue;
    const subject = typeof baseRoute.properties.route_pattern === "string" ? baseRoute.properties.route_pattern : baseRoute.id;
    diagnostics.push(graphDiagnostic(
      "web.astro_build_route_static_only",
      subject,
      input.provenance.profile_id,
      observationEvidence,
      { route_id: baseRoute.id },
      "info",
    ));
  }
  if (observation.config.dynamic_config_detected) {
    diagnostics.push(graphDiagnostic(
      "web.astro_build_dynamic_config_observed",
      "Astro configuration",
      input.provenance.profile_id,
      observationEvidence,
      { dynamic_config_detected: true },
    ));
  }

  const boundaryNodes = new Map<AstroEnvironment, GraphNode>();
  const outputNodesByEnvironment = new Map<string, GraphNode>();
  const boundaryNode = (environment: AstroEnvironment): GraphNode => {
    const previous = boundaryNodes.get(environment);
    if (previous !== undefined) return previous;
    const node = buildNode(
      "module",
      { framework: "astro", runtime_boundary: environment, profile_id: input.provenance.profile_id },
      `Astro ${environment} build boundary`,
      {
        framework: "astro",
        module_kind: "astro-build-runtime-boundary",
        runtime_boundary: environment,
        profile_id: input.provenance.profile_id,
      },
      input.provenance,
      observationPath,
      observationDigest,
    );
    addNode(node);
    boundaryNodes.set(environment, node);
    return node;
  };

  for (const build of observation.vite_builds) {
    const condition = observedCondition(build.environment, [
      { key: "astro.vite", value: build.vite_version },
      { key: "astro.boundary", value: build.environment },
    ]);
    const moduleNodes = new Map<string, GraphNode>();
    const outputNodes = new Map<string, GraphNode>();
    for (const module of build.modules) {
      let node = preferredPathNode(pathIndex.get(module.module_id) ?? [], build.environment);
      if (node === null) {
        node = buildNode("module", {
          framework: "astro",
          environment: build.environment,
          module_id: module.module_id,
          profile_id: input.provenance.profile_id,
        }, module.module_id, {
          framework: "astro",
          environment: build.environment,
          module_id: module.module_id,
          module_kind: module.module_kind,
          module_role: module.role,
          is_entry: module.is_entry,
          profile_id: input.provenance.profile_id,
        }, input.provenance, observationPath, observationDigest);
      }
      addNode(node);
      moduleNodes.set(module.module_id, node);
    }
    for (const output of build.outputs) {
      const outputEvidence = buildEvidence(input.provenance, output.file_name, output.digest);
      const node = buildNode("file", {
        framework: "astro",
        environment: build.environment,
        file_name: output.file_name,
        output_digest: output.digest,
        profile_id: input.provenance.profile_id,
      }, output.file_name, {
        framework: "astro",
        environment: build.environment,
        artifact_kind: output.kind,
        artifact_role: output.role,
        runtime_boundary: output.boundary,
        logical_path: output.file_name,
        artifact_digest: output.digest,
        entry: output.entry,
        profile_id: input.provenance.profile_id,
      }, input.provenance, output.file_name, output.digest);
      addNode(node);
      outputNodes.set(output.file_name, node);
      outputNodesByEnvironment.set(`${build.environment}\0${output.file_name}`, node);
      addObservedRelation(
        sites, edges, boundaryNode(build.environment).id, node.id, "emits", output.file_name, build.environment,
        observedCondition(build.environment, [
          { key: "astro.artifact_role", value: output.role },
          { key: "astro.boundary", value: output.boundary },
        ]),
        outputEvidence, input.provenance.profile_id,
      );
      for (const moduleId of output.module_ids) {
        const moduleNode = moduleNodes.get(moduleId);
        if (moduleNode !== undefined) addObservedRelation(
          sites, edges, moduleNode.id, node.id, "emits", output.file_name, build.environment,
          condition, outputEvidence, input.provenance.profile_id,
        );
        for (const routeValue of routesByComponent.get(moduleId) ?? []) {
          const route = observedRoutes.get(routeValue.route_digest);
          if (route === undefined) continue;
          addObservedRelation(
            sites, edges, route.id, node.id, "emits", output.file_name, build.environment,
            observedCondition(build.environment, [
              { key: "astro.artifact_role", value: output.role },
              { key: "astro.route", value: routeValue.route_pattern },
            ]),
            outputEvidence, input.provenance.profile_id,
          );
        }
      }
    }
    for (const module of build.modules) {
      const source = moduleNodes.get(module.module_id);
      if (source === undefined) continue;
      for (const targetId of module.imported_ids) {
        const target = moduleNodes.get(targetId);
        if (target !== undefined) addObservedRelation(
          sites, edges, source.id, target.id, "imports", targetId, build.environment,
          condition, observationEvidence, input.provenance.profile_id,
        );
      }
      for (const targetId of module.dynamic_imported_ids) {
        const target = moduleNodes.get(targetId);
        if (target !== undefined) addObservedRelation(
          sites, edges, source.id, target.id, "dynamic_imports", targetId, build.environment,
          condition, observationEvidence, input.provenance.profile_id,
        );
      }
    }
    for (const output of build.outputs) {
      const source = outputNodes.get(output.file_name);
      if (source === undefined) continue;
      for (const targetName of [...output.imported_outputs, ...output.referenced_assets]) {
        const target = outputNodes.get(targetName);
        if (target !== undefined) addObservedRelation(
          sites, edges, source.id, target.id, "loads", targetName, build.environment,
          condition, buildEvidence(input.provenance, targetName, target.properties.artifact_digest as string),
          input.provenance.profile_id,
        );
      }
    }
  }

  const serverModules = new Map(
    (observation.vite_builds.find((build) => build.environment === "server")?.modules ?? [])
      .map((module) => [module.module_id, module]),
  );
  let traversalSteps = 0;
  for (const routeValue of observation.routes) {
    const route = observedRoutes.get(routeValue.route_digest);
    if (route === undefined) continue;
    const visited = new Set<string>();
    const pending = [routeValue.component_id];
    while (pending.length > 0) {
      const moduleId = pending.pop()!;
      if (visited.has(moduleId)) continue;
      traversalSteps += 1;
      if (traversalSteps > MAX_GRAPH_TRAVERSAL_STEPS) {
        fail("web.astro_build_graph_traversal_limit_exceeded");
      }
      visited.add(moduleId);
      const module = serverModules.get(moduleId);
      if (module === undefined) continue;
      pending.push(...module.imported_ids, ...module.dynamic_imported_ids);
    }
    for (const entry of observation.ssr.entry_modules) {
      if (!visited.has(entry.module_id)) continue;
      const target = outputNodesByEnvironment.get(`browser\0${entry.chunk}`);
      if (target === undefined) fail("web.astro_build_graph_contract_invalid");
      addObservedRelation(
        sites, edges, route.id, target.id, "loads", entry.chunk, "browser",
        observedCondition("browser", [
          { key: "astro.artifact_role", value: "hydration_chunk" },
          { key: "astro.island", value: entry.module_id },
          { key: "astro.route", value: routeValue.route_pattern },
        ]),
        buildEvidence(input.provenance, entry.chunk, target.properties.artifact_digest as string),
        input.provenance.profile_id,
      );
    }
  }

  const allOutputs = new Map<string, GraphNode[]>();
  for (const node of nodes.values()) {
    const logicalPath = node.properties.logical_path;
    if (node.kind !== "file" || typeof logicalPath !== "string") continue;
    const values = allOutputs.get(logicalPath) ?? [];
    values.push(node);
    allOutputs.set(logicalPath, values);
  }
  for (const row of observation.route_assets) {
    const route = observedRoutes.get(row.route_digest);
    if (route === undefined) continue;
    const routeValue = observedRouteValues.get(row.route_digest);
    for (const asset of row.assets) {
      const candidates = allOutputs.get(asset) ?? [];
      const target = candidates.find((node) => node.properties.environment === "browser")
        ?? candidates.find((node) => node.properties.environment === "server");
      if (target === undefined) continue;
      const environment = target.properties.environment === "browser" ? "browser" : "server";
      addObservedRelation(
        sites, edges, route.id, target.id, "loads", asset, environment,
        observedCondition(environment, [
          { key: "astro.route_asset", value: row.route_digest },
          { key: "astro.artifact_role", value: target.properties.artifact_role as string },
          { key: "astro.route", value: routeValue?.route_pattern ?? row.route_digest },
        ]),
        buildEvidence(input.provenance, asset, target.properties.artifact_digest as string), input.provenance.profile_id,
      );
    }
  }

  const candidate = {
    astroVersion: observation.astro_version,
    viteVersions: [...new Set(observation.vite_builds.map((build) => build.vite_version))].sort(compareUtf8),
    nodes: [...nodes.values()].sort((left, right) => compareUtf8(left.id, right.id)),
    sites: uniqueById(sites, "web.astro_build_site_conflict"),
    edges: uniqueById(edges, "web.astro_build_edge_conflict"),
    diagnostics: uniqueById(diagnostics, "web.astro_build_diagnostic_conflict"),
  };
  let delta: AstroBuildGraphDelta;
  try {
    delta = {
      astroVersion: candidate.astroVersion,
      viteVersions: candidate.viteVersions,
      ...reconcileFrameworkBuildBaseRecords(
        candidate,
        ASTRO_FRAMEWORK_BUILD_DESCRIPTOR,
        input.provenance,
        input.baseNodes,
        input.baseEdges ?? [],
        input.baseDiagnosticIds,
      ),
    };
    validateFrameworkBuildDelta(
      delta,
      ASTRO_FRAMEWORK_BUILD_DESCRIPTOR,
      input.provenance,
      input.baseNodes,
    );
  } catch {
    fail("web.astro_build_graph_contract_invalid");
  }
  return delta;
}

export function astroBuildProtocolEvents(
  root: string,
  delta: AstroBuildGraphDelta,
  provenance: AstroBuildProvenance,
  sourceRevision: string,
): ProtocolEvent[] {
  return frameworkBuildProtocolEvents(
    root,
    delta,
    provenance,
    sourceRevision,
    ASTRO_FRAMEWORK_BUILD_DESCRIPTOR,
    {
      toolchain: `astro ${delta.astroVersion}`,
      command: "astro build",
      properties: {
        astro_version: delta.astroVersion,
        vite_versions: delta.viteVersions,
      },
    },
  );
}
