import { createHash } from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";
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

export const ASTRO_BUILD_OBSERVER = "astro-vite-build-observer" as const;
export const ASTRO_BUILD_OBSERVER_VERSION = "0.1.0" as const;
export const ASTRO_BUILD_OBSERVER_CAPABILITY = "astro-integration-v5-v7-vite-v6-v7-v1" as const;
export const ASTRO_BUILD_OBSERVATION_SCHEMA = "astro-build-observation-v1" as const;

const MAX_SAFE_STRING = 4_096;
const MAX_ROUTES = 20_000;
const MAX_MODULES = 100_000;
const MAX_IMPORTS_PER_MODULE = 20_000;
const MAX_OUTPUTS = 100_000;
const MAX_PLUGIN_NAMES = 20_000;
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
  pathname: string | null;
  pattern_digest: string;
  component_id: string;
  component_kind: "project" | "virtual" | "external";
  type: "page" | "endpoint" | "redirect" | "fallback" | "unknown";
  prerender: boolean | null;
  injected: boolean;
}

export interface AstroObservedModule {
  module_id: string;
  module_kind: "project" | "virtual" | "external";
  is_entry: boolean;
  imported_ids: string[];
  dynamic_imported_ids: string[];
}

export interface AstroObservedOutput {
  file_name: string;
  kind: "chunk" | "asset";
  digest: string;
  entry: boolean;
  module_ids: string[];
  imported_outputs: string[];
  referenced_assets: string[];
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
  routes: AstroObservedRoute[];
  pages: string[];
  route_assets: Array<{ route_digest: string; assets: string[] }>;
  vite_builds: AstroObservedViteBuild[];
  ssr: { middleware_present: boolean; route_count: number };
}

export interface AstroBuildGraphInput {
  observation: AstroBuildObservation;
  provenance: AstroBuildProvenance;
  baseNodes: readonly GraphNode[];
  baseEdges?: readonly GraphEdge[];
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

function sanitizeRoute(value: unknown, repoRoot: string): AstroObservedRoute {
  const route = record(value);
  if (route === null) fail("web.astro_build_route_contract_invalid");
  const pathname = route.pathname === undefined || route.pathname === null
    ? null
    : canonicalPathname(route.pathname);
  if (route.pathname !== undefined && route.pathname !== null && pathname === null) {
    fail("web.astro_build_route_pathname_unsafe");
  }
  const component = logicalId(route.component, repoRoot, true);
  const pattern = patternDigest(route.pattern);
  const origin = boundedString(route.origin);
  const injected = origin !== null && origin !== "project";
  const identity: Record<string, JsonValue> = {
    pathname,
    pattern_digest: pattern,
    component_id: component.id,
    component_kind: component.kind,
    type: routeType(route.type),
    prerender: typeof route.prerender === "boolean" ? route.prerender : null,
    injected,
  };
  return {
    route_digest: digestIdentity(identity),
    pathname,
    pattern_digest: pattern,
    component_id: component.id,
    component_kind: component.kind,
    type: routeType(route.type),
    prerender: typeof route.prerender === "boolean" ? route.prerender : null,
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
  ssr: { middleware_present: boolean; route_count: number };
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

function viteEnvironment(context: UnknownRecord, config: UnknownRecord | null): AstroEnvironment {
  const environment = boundedString(record(context.environment)?.name);
  if (environment === "client" || environment === "browser") return "browser";
  if (environment === "ssr" || environment === "server") return "server";
  return record(config?.build)?.ssr === true ? "server" : "browser";
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
    is_entry: info.isEntry === true,
    imported_ids: imported,
    dynamic_imported_ids: dynamic,
  };
}

function outputDigest(value: unknown, code: string): string {
  if (typeof value === "string" || value instanceof Uint8Array) return sha256(value);
  fail(code);
}

function observedOutput(value: unknown, repoRoot: string): AstroObservedOutput {
  const output = record(value);
  if (output === null) fail("web.astro_build_output_contract_invalid");
  const fileName = sanitizeOutputFile(output.fileName);
  if (output.type === "asset") {
    return {
      file_name: fileName,
      kind: "asset",
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

function createViteObserverPlugin(state: MutableObserverState): AstroVitePluginLike {
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
      const environment = viteEnvironment({}, config);
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
      const environment = viteEnvironment(this, resolvedConfig);
      upsert(environment, { vite_version: version });
    },
    generateBundle(_outputOptions, bundle) {
      const environment = viteEnvironment(this, resolvedConfig);
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
      const outputs = outputValues.map((output) => observedOutput(output, state.repoRoot))
        .sort((left, right) => compareUtf8(left.file_name, right.file_name));
      upsert(environment, { modules, outputs });
    },
    buildEnd(error) {
      if (error === undefined || error === null) return;
      upsert(viteEnvironment(this, resolvedConfig), { failed: true });
    },
  };
}

function routeAssetRows(
  value: unknown,
  routes: readonly AstroObservedRoute[],
  repoRoot: string,
): Array<{ route_digest: string; assets: string[] }> {
  if (value === undefined) return [];
  if (!(value instanceof Map) || value.size > MAX_ROUTES) fail("web.astro_build_assets_contract_invalid");
  const rows: Array<{ route_digest: string; assets: string[] }> = [];
  let assetCount = 0;
  for (const [route, assets] of value.entries()) {
    const routeRecord = record(route);
    const routePathname = canonicalPathname(routeRecord?.pathname ?? route);
    const routeDigest = boundedString(routeRecord?.route_digest)
      ?? (routeRecord !== null && routeRecord.component !== undefined && routeRecord.pattern !== undefined
        ? sanitizeRoute(routeRecord, repoRoot).route_digest
        : routes.find((candidate) => candidate.pathname === routePathname)?.route_digest);
    if (routeDigest === undefined) fail("web.astro_build_assets_route_unknown");
    if (!Array.isArray(assets) || assets.length > MAX_OUTPUTS) fail("web.astro_build_assets_contract_invalid");
    assetCount += assets.length;
    if (assetCount > MAX_OUTPUTS) fail("web.astro_build_output_limit_exceeded");
    rows.push({
      route_digest: routeDigest,
      assets: [...new Set(assets.map(sanitizeOutputFile))].sort(compareUtf8),
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

function finalObservation(state: MutableObserverState): AstroBuildObservation {
  if (state.config === null) fail("web.astro_build_config_unavailable");
  for (const environment of ["browser", "server"] as const) {
    const build = state.viteBuilds.get(environment);
    if (build === undefined || build.failed) fail("web.astro_build_environment_observation_incomplete");
  }
  return {
    schema_version: ASTRO_BUILD_OBSERVATION_SCHEMA,
    observer: ASTRO_BUILD_OBSERVER,
    observer_version: ASTRO_BUILD_OBSERVER_VERSION,
    capability: ASTRO_BUILD_OBSERVER_CAPABILITY,
    astro_version: state.capability.astro_version,
    config: state.config,
    routes: [...state.routes].sort((left, right) => compareUtf8(left.route_digest, right.route_digest)),
    pages: state.pages,
    route_assets: state.routeAssets,
    vite_builds: [...state.viteBuilds.values()].sort((left, right) => compareUtf8(left.environment, right.environment)),
    ssr: state.ssr,
  };
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
    ssr: { middleware_present: false, route_count: 0 },
    wrote: false,
  };
  const plugin = createViteObserverPlugin(state);
  return {
    name: ASTRO_BUILD_OBSERVER,
    hooks: {
      "astro:routes:resolved": async (context) => boundedHook("web.astro_build_routes_hook_failed", state.timeoutMs, () => {
        if (!Array.isArray(context.routes) || context.routes.length > MAX_ROUTES) fail("web.astro_build_routes_contract_invalid");
        state.routes = context.routes.map((route) => sanitizeRoute(route, state.repoRoot));
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
      }),
      "astro:build:setup": async (context) => boundedHook("web.astro_build_setup_hook_failed", state.timeoutMs, () => {
        if (typeof context.updateConfig !== "function") fail("web.astro_build_hook_unavailable");
        (context.updateConfig as (value: unknown) => unknown)({ plugins: [plugin] });
      }),
      "astro:build:ssr": async (context) => boundedHook("web.astro_build_ssr_hook_failed", state.timeoutMs, () => {
        const manifest = record(context.manifest);
        const routes = manifest?.routes;
        state.ssr = {
          middleware_present: context.middlewareEntryPoint !== undefined && context.middlewareEntryPoint !== null,
          route_count: Array.isArray(routes) ? routes.length : 0,
        };
      }),
      "astro:build:done": async (context) => boundedHook("web.astro_build_done_hook_failed", state.timeoutMs, async () => {
        if (state.wrote) fail("web.astro_build_observation_already_written");
        state.pages = pagePathnames(context.pages ?? []);
        state.routeAssets = routeAssetRows(context.assets, state.routes, state.repoRoot);
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
  for (const [field, value] of Object.entries(provenance)) {
    if (field === "build_run_id" || field === "profile_id") {
      if (boundedString(value) === null) fail("web.astro_build_provenance_invalid");
    } else if (!/^[a-f0-9]{64}$/u.test(value)) {
      fail("web.astro_build_provenance_invalid");
    }
  }
}

function buildEvidence(
  provenance: AstroBuildProvenance,
  logicalPath: string,
  artifactDigest: string,
): Evidence {
  return {
    kind: "build",
    extractor: ASTRO_BUILD_OBSERVER,
    extractor_version: ASTRO_BUILD_OBSERVER_VERSION,
    path: logicalPath,
    start_line: 1,
    start_column: 1,
    end_line: 1,
    end_column: 1,
    properties: {
      ...provenance,
      logical_artifact_path: logicalPath,
      artifact_digest: artifactDigest,
      capability: ASTRO_BUILD_OBSERVER_CAPABILITY,
    },
  };
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
  const id = stableId(kind, identity);
  return {
    id,
    kind,
    locator: `build://${ASTRO_BUILD_OBSERVER}/${encodeURIComponent(logicalPath)}#${id}`,
    display_name: displayName,
    properties: {
      ...properties,
      build_generated: true,
      build_identity: identity,
      build_provenance: {
        ...provenance,
        observer: ASTRO_BUILD_OBSERVER,
        observer_version: ASTRO_BUILD_OBSERVER_VERSION,
        logical_artifact_path: logicalPath,
        artifact_digest: artifactDigest,
      },
    },
  };
}

function observedCondition(environment: AstroEnvironment, extra: Array<{ key: string; value: string }> = []): Condition {
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
  environment: AstroEnvironment,
  condition: Condition,
  evidence: Evidence,
  profileId: string,
): void {
  const identity: Record<string, JsonValue> = {
    kind,
    source,
    specifier,
    profile_id: profileId,
    condition,
    resolution_status: "resolved",
    precision: "observed",
    observer: ASTRO_BUILD_OBSERVER,
    observer_version: ASTRO_BUILD_OBSERVER_VERSION,
    validated_output_digest: evidence.properties?.validated_output_digest ?? null,
    anchor: {
      path: evidence.path,
      start_line: evidence.start_line,
      start_column: evidence.start_column,
      end_line: evidence.end_line,
      end_column: evidence.end_column,
    },
  };
  const siteId = stableId("site", identity);
  sites.push({
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
  });
  edges.push({
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
  });
}

function graphDiagnostic(
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

export function buildAstroObservedGraph(input: AstroBuildGraphInput): AstroBuildGraphDelta {
  const observation = input.observation;
  if (observation.schema_version !== ASTRO_BUILD_OBSERVATION_SCHEMA
    || observation.capability !== ASTRO_BUILD_OBSERVER_CAPABILITY
    || observation.observer !== ASTRO_BUILD_OBSERVER
    || observation.observer_version !== ASTRO_BUILD_OBSERVER_VERSION) {
    fail("web.astro_build_observation_contract_invalid");
  }
  validateProvenance(input.provenance);
  const observationDigest = digestIdentity(observation as unknown as JsonValue);
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
  const addNode = (node: GraphNode): void => {
    const existing = nodes.get(node.id);
    if (existing !== undefined && canonicalJson(existing as unknown as JsonValue) !== canonicalJson(node as unknown as JsonValue)) {
      fail("web.astro_build_node_conflict");
    }
    nodes.set(node.id, node);
  };

  for (const routeValue of observation.routes) {
    const routeKey = routeValue.pathname;
    const candidateMap = new Map<string, GraphNode>();
    if (routeKey !== null) {
      for (const node of routeIndex.get(routeKey) ?? []) candidateMap.set(node.id, node);
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
        route_pattern: routeKey ?? `pattern:${routeValue.pattern_digest}`,
        route_type: routeValue.type,
        profile_id: input.provenance.profile_id,
      };
      route = buildNode("route", identity, routeKey ?? "observed Astro route", {
        framework: "astro",
        route_pattern: identity.route_pattern!,
        route_type: routeValue.type,
        prerender: routeValue.prerender,
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
        routeKey ?? routeValue.route_digest,
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
        observedCondition("server", [{ key: "astro.route", value: routeKey ?? routeValue.route_digest }]),
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

  for (const build of observation.vite_builds) {
    const condition = observedCondition(build.environment, [{ key: "astro.vite", value: build.vite_version }]);
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
        logical_path: output.file_name,
        artifact_digest: output.digest,
        entry: output.entry,
        profile_id: input.provenance.profile_id,
      }, input.provenance, output.file_name, output.digest);
      addNode(node);
      outputNodes.set(output.file_name, node);
      for (const moduleId of output.module_ids) {
        const moduleNode = moduleNodes.get(moduleId);
        if (moduleNode !== undefined) addObservedRelation(
          sites, edges, moduleNode.id, node.id, "emits", output.file_name, build.environment,
          condition, outputEvidence, input.provenance.profile_id,
        );
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

  const allOutputs = new Map<string, GraphNode>();
  for (const node of nodes.values()) {
    const logicalPath = node.properties.logical_path;
    if (node.kind === "file" && typeof logicalPath === "string") allOutputs.set(logicalPath, node);
  }
  for (const row of observation.route_assets) {
    const route = observedRoutes.get(row.route_digest);
    if (route === undefined) continue;
    for (const asset of row.assets) {
      const target = allOutputs.get(asset);
      if (target === undefined) continue;
      const environment = target.properties.environment === "browser" ? "browser" : "server";
      addObservedRelation(
        sites, edges, route.id, target.id, "emits", asset, environment,
        observedCondition(environment, [{ key: "astro.route_asset", value: row.route_digest }]),
        buildEvidence(input.provenance, asset, target.properties.artifact_digest as string), input.provenance.profile_id,
      );
    }
  }

  return {
    astroVersion: observation.astro_version,
    viteVersions: [...new Set(observation.vite_builds.map((build) => build.vite_version))].sort(compareUtf8),
    nodes: [...nodes.values()].sort((left, right) => compareUtf8(left.id, right.id)),
    sites: uniqueById(sites, "web.astro_build_site_conflict"),
    edges: uniqueById(edges, "web.astro_build_edge_conflict"),
    diagnostics: uniqueById(diagnostics, "web.astro_build_diagnostic_conflict"),
  };
}

export function astroBuildProtocolEvents(
  root: string,
  delta: AstroBuildGraphDelta,
  provenance: AstroBuildProvenance,
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
  const events: ProtocolEvent[] = [event("scan_started", { root, safe_mode: false, project_code_executed: true })];
  events.push(event("profile_declared", {
    profile: {
      id: provenance.profile_id,
      language: "typescript",
      toolchain: `astro ${delta.astroVersion}`,
      command: "astro build",
      target: "production",
      features: [ASTRO_BUILD_OBSERVER_CAPABILITY],
      environment: { mode: "production" },
      source_revision: sourceRevision,
      properties: {
        observer: ASTRO_BUILD_OBSERVER,
        observer_version: ASTRO_BUILD_OBSERVER_VERSION,
        astro_version: delta.astroVersion,
        vite_versions: delta.viteVersions,
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
