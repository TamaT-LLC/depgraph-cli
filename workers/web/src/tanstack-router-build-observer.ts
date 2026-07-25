import { createHash } from "node:crypto";
import { lstat, readFile, realpath } from "node:fs/promises";
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
  frameworkBuildUnresolvedTarget,
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

export const TANSTACK_ROUTER_BUILD_OBSERVER = "tanstack-router-vite-build-observer" as const;
export const TANSTACK_ROUTER_BUILD_OBSERVER_VERSION = "0.1.0" as const;
export const TANSTACK_ROUTER_BUILD_CAPABILITY = "tanstack-router-v1-vite-v6-v7-generated-route-v1" as const;
export const TANSTACK_ROUTER_BUILD_SCHEMA = "tanstack-router-build-observation-v1" as const;
export const TANSTACK_ROUTER_ROUTE_MANIFEST_CONTRACT = "tanstack-router-generated-manifest-v1" as const;
export const TANSTACK_ROUTER_FRAMEWORK_BUILD_DESCRIPTOR: FrameworkBuildDescriptor = Object.freeze({
  framework: "tanstack-router",
  observer: TANSTACK_ROUTER_BUILD_OBSERVER,
  observerVersion: TANSTACK_ROUTER_BUILD_OBSERVER_VERSION,
  capability: TANSTACK_ROUTER_BUILD_CAPABILITY,
});

const MAX_SAFE_STRING = 4_096;
const MAX_SOURCE_BYTES = 16 * 1024 * 1024;
const MAX_TRANSFORM_BYTES = 64 * 1024 * 1024;
const MAX_ROUTES = 100_000;
const MAX_MASKS = 100_000;
const MAX_MODULES = 100_000;
const MAX_IMPORTS = 20_000;
const MAX_OUTPUTS = 100_000;
const MAX_PLUGINS = 20_000;
const DEFAULT_TIMEOUT_MS = 10_000;
const MAX_TIMEOUT_MS = 60_000;
const ROUTER_GENERATOR_PLUGIN = "tanstack:router-generator";
const ROUTE_EXTENSIONS = [".ts", ".tsx", ".js", ".jsx", ".mts", ".mtsx", ".mjs", ".cts", ".ctsx", ".cjs"] as const;
const SHA256 = /^[a-f0-9]{64}$/u;

type UnknownRecord = Record<string, unknown>;
type Awaitable<T> = T | Promise<T>;
type RouteSourceKind = "file" | "virtual" | "code";
type ModuleKind = "project" | "virtual" | "external";

export interface TanStackRouterBuildProvenance {
  build_run_id: string;
  profile_id: string;
  command_plan_digest: string;
  toolchain_executable_digest: string;
  environment_key_set_digest: string;
  validated_output_digest: string;
}

export interface TanStackRouterObservationSink {
  write(observation: TanStackRouterBuildObservation): Awaitable<void>;
}

export interface TanStackRouterObserverOptions {
  routerVersion: string;
  repoRoot: string;
  sink: TanStackRouterObservationSink;
  generatedRouteTree?: string | null;
  routesDirectory?: string;
  basePath?: string;
  existingVitePlugins?: readonly unknown[];
  timeoutMs?: number;
}

export interface TanStackRouterCapability {
  capability: typeof TANSTACK_ROUTER_BUILD_CAPABILITY;
  router_version: string;
  generated_route_tree: string | null;
  routes_directory: string;
  base_path: string;
  existing_vite_plugin_count: number;
}

export interface TanStackRouterVitePluginLike {
  name: string;
  apply: "build";
  enforce: "post";
  configResolved(config: UnknownRecord): Awaitable<void>;
  buildStart(this: UnknownRecord): void;
  transform(this: UnknownRecord, code: string, id: string): null;
  generateBundle(this: UnknownRecord, outputOptions: unknown, bundle: UnknownRecord): void;
  buildEnd(this: UnknownRecord, error?: unknown): void;
  closeBundle(this: UnknownRecord): Awaitable<void>;
}

export interface TanStackRouterObservedConfig {
  mode: string;
  base: string;
  plugin_count: number;
  observer_plugin_index: number;
  generator_plugin_index: number | null;
}

export interface TanStackRouterObservedRoute {
  route_id: string;
  full_path: string;
  source_path: string;
  source_kind: RouteSourceKind;
  parent_route_id: string | null;
  lazy_source_path: string | null;
  has_loader: boolean;
  has_before_load: boolean;
}

export interface TanStackRouterObservedMask {
  source_path: string;
  from: string | null;
  to: string | null;
}

export interface TanStackRouterObservedModule {
  module_id: string;
  source_path: string | null;
  module_kind: ModuleKind;
  is_entry: boolean;
  imported_ids: string[];
  dynamic_imported_ids: string[];
}

export interface TanStackRouterObservedOutput {
  file_name: string;
  kind: "chunk" | "asset";
  digest: string;
  entry: boolean;
  module_ids: string[];
  imported_outputs: string[];
}

export interface TanStackRouterObservedBuild {
  vite_environment: "client";
  vite_version: string;
  config: TanStackRouterObservedConfig;
  modules: TanStackRouterObservedModule[];
  outputs: TanStackRouterObservedOutput[];
}

export interface TanStackRouterBuildObservation {
  schema_version: typeof TANSTACK_ROUTER_BUILD_SCHEMA;
  observer: typeof TANSTACK_ROUTER_BUILD_OBSERVER;
  observer_version: typeof TANSTACK_ROUTER_BUILD_OBSERVER_VERSION;
  capability: typeof TANSTACK_ROUTER_BUILD_CAPABILITY;
  manifest_contract: typeof TANSTACK_ROUTER_ROUTE_MANIFEST_CONTRACT;
  router_version: string;
  generated_route_tree_path: string | null;
  generated_route_tree_digest: string | null;
  route_manifest_digest: string;
  route_count: number;
  mask_count: number;
  routes: TanStackRouterObservedRoute[];
  masks: TanStackRouterObservedMask[];
  builds: TanStackRouterObservedBuild[];
}

export interface TanStackRouterBuildGraphInput {
  observation: TanStackRouterBuildObservation;
  provenance: TanStackRouterBuildProvenance;
  baseNodes: readonly GraphNode[];
  baseEdges?: readonly GraphEdge[];
  baseDiagnosticIds?: readonly string[];
}

export interface TanStackRouterBuildGraphDelta {
  routerVersion: string;
  viteVersions: string[];
  nodes: GraphNode[];
  sites: DependencySite[];
  edges: GraphEdge[];
  diagnostics: Diagnostic[];
}

export class TanStackRouterBuildObserverError extends Error {
  readonly code: string;

  constructor(code: string) {
    super(code);
    this.name = "TanStackRouterBuildObserverError";
    this.code = code;
  }
}

function fail(code: string): never {
  throw new TanStackRouterBuildObserverError(code);
}

function record(value: unknown): UnknownRecord | null {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as UnknownRecord
    : null;
}

function boundedString(value: unknown, max = MAX_SAFE_STRING): string | null {
  if (typeof value !== "string" || value.length === 0 || value.length > max
    || /[\u0000-\u001f\u007f]/u.test(value)) return null;
  return value;
}

function sha256(value: string | Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}

function stableVersion(value: unknown, allowedMajors: ReadonlySet<number>, code: string): string {
  const raw = boundedString(value, 128);
  const match = raw === null ? null : /^(\d+)\.(\d+)\.(\d+)$/u.exec(raw);
  if (match === null || !allowedMajors.has(Number(match[1]))) fail(code);
  return raw!;
}

function canonicalRelativePath(value: unknown): string | null {
  const raw = boundedString(value);
  const portable = raw?.replaceAll("\\", "/");
  if (portable === undefined || path.posix.isAbsolute(portable)
    || /^[a-z]:\//iu.test(portable) || portable.startsWith("//")) return null;
  const normalized = path.posix.normalize(portable).replace(/^\.\//u, "");
  if (normalized === "." || normalized === ".." || normalized.startsWith("../")
    || normalized.includes("/../") || normalized.split("/").some((segment) => segment === "")) return null;
  return normalized;
}

function configuredPath(value: unknown, fallback: string, nullable: boolean): string | null {
  if (value === null && nullable) return null;
  const result = canonicalRelativePath(value ?? fallback);
  if (result === null) fail("web.tanstack_router_build_path_invalid");
  return result;
}

function normalizeRoutePath(value: unknown): string | null {
  const raw = boundedString(value, 2_048);
  if (raw === null || !raw.startsWith("/") || raw.includes("\\") || raw.includes("?") || raw.includes("#")
    || raw.includes("//")) return null;
  const normalized = raw.length > 1 ? raw.replace(/\/$/u, "") : raw;
  return normalized === "" ? "/" : normalized;
}

function configuredBasePath(value: unknown): string {
  if (value === undefined || value === null || value === "" || value === "/") return "";
  const normalized = normalizeRoutePath(value);
  if (normalized === null || normalized === "/") fail("web.tanstack_router_build_base_path_invalid");
  return normalized;
}

function withBase(base: string, value: string): string {
  const normalized = normalizeRoutePath(value);
  if (normalized === null) fail("web.tanstack_router_build_route_path_invalid");
  if (base === "") return normalized;
  return normalized === "/" ? base : `${base}${normalized}`;
}

function outputPath(value: unknown): string {
  const result = canonicalRelativePath(value);
  if (result === null) fail("web.tanstack_router_build_output_path_unsafe");
  return result;
}

function pluginName(value: unknown, code: string): string {
  const name = boundedString(record(value)?.name);
  if (name === null) fail(code);
  return name;
}

function validatePluginNames(values: readonly unknown[]): string[] {
  if (values.length > MAX_PLUGINS) fail("web.tanstack_router_build_plugin_chain_invalid");
  const names = values.map((value) => pluginName(value, "web.tanstack_router_build_plugin_chain_invalid"));
  if (new Set(names).size !== names.length || names.includes(TANSTACK_ROUTER_BUILD_OBSERVER)) {
    fail("web.tanstack_router_build_plugin_chain_invalid");
  }
  return names;
}

function timeoutValue(value: number | undefined): number {
  const timeout = value ?? DEFAULT_TIMEOUT_MS;
  if (!Number.isSafeInteger(timeout) || timeout <= 0 || timeout > MAX_TIMEOUT_MS) {
    fail("web.tanstack_router_build_timeout_invalid");
  }
  return timeout;
}

async function bounded<T>(code: string, timeout: number, operation: () => Awaitable<T>): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      Promise.resolve().then(operation).catch((error: unknown) => {
        if (error instanceof TanStackRouterBuildObserverError) throw error;
        fail(code);
      }),
      new Promise<T>((_resolve, reject) => {
        timer = setTimeout(() => reject(new TanStackRouterBuildObserverError("web.tanstack_router_build_observer_timeout")), timeout);
        timer.unref?.();
      }),
    ]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

function normalizedHook<T>(code: string, operation: () => T): T {
  try {
    return operation();
  } catch (error) {
    if (error instanceof TanStackRouterBuildObserverError) throw error;
    fail(code);
  }
}

export function detectTanStackRouterBuildCapability(
  routerVersion: string,
  generatedRouteTree: string | null | undefined = undefined,
  routesDirectory: string | undefined = undefined,
  basePath: string | undefined = undefined,
  existingVitePlugins: readonly unknown[] = [],
): TanStackRouterCapability {
  const version = stableVersion(routerVersion, new Set([1]), "web.tanstack_router_build_version_unsupported");
  const tree = configuredPath(generatedRouteTree, "src/routeTree.gen.ts", true);
  const routes = configuredPath(routesDirectory, "src/routes", false)!;
  const base = configuredBasePath(basePath);
  const plugins = validatePluginNames(existingVitePlugins);
  if (tree !== null && !plugins.includes(ROUTER_GENERATOR_PLUGIN)) {
    fail("web.tanstack_router_build_generator_plugin_missing");
  }
  return {
    capability: TANSTACK_ROUTER_BUILD_CAPABILITY,
    router_version: version,
    generated_route_tree: tree,
    routes_directory: routes,
    base_path: base,
    existing_vite_plugin_count: plugins.length,
  };
}

interface QuotedValue {
  value: string;
  end: number;
}

function quotedAt(source: string, start: number): QuotedValue | null {
  const quote = source[start];
  if (quote !== "'" && quote !== "\"" && quote !== "`") return null;
  let value = "";
  for (let index = start + 1; index < source.length; index += 1) {
    const character = source[index]!;
    if (character === quote) return { value, end: index + 1 };
    if (character !== "\\") {
      value += character;
      continue;
    }
    const escaped = source[index + 1];
    if (escaped === undefined) return null;
    index += 1;
    if (escaped === "n") value += "\n";
    else if (escaped === "r") value += "\r";
    else if (escaped === "t") value += "\t";
    else if (escaped === "b") value += "\b";
    else if (escaped === "f") value += "\f";
    else if (escaped === "v") value += "\v";
    else if (escaped === "0") value += "\0";
    else if (escaped === "u") {
      const hex = source.slice(index + 1, index + 5);
      if (!/^[a-f0-9]{4}$/iu.test(hex)) return null;
      value += String.fromCodePoint(Number.parseInt(hex, 16));
      index += 4;
    } else value += escaped;
  }
  return null;
}

function skipTrivia(source: string, start: number): number {
  let index = start;
  while (index < source.length) {
    if (/\s/u.test(source[index]!)) {
      index += 1;
      continue;
    }
    if (source.startsWith("//", index)) {
      const newline = source.indexOf("\n", index + 2);
      index = newline < 0 ? source.length : newline + 1;
      continue;
    }
    if (source.startsWith("/*", index)) {
      const end = source.indexOf("*/", index + 2);
      index = end < 0 ? source.length : end + 2;
      continue;
    }
    break;
  }
  return index;
}

function matchingDelimiter(source: string, start: number, open = "{", close = "}"): number {
  if (source[start] !== open) return -1;
  let depth = 0;
  for (let index = start; index < source.length; index += 1) {
    const character = source[index]!;
    if (character === "'" || character === "\"" || character === "`") {
      const quoted = quotedAt(source, index);
      if (quoted === null) return -1;
      index = quoted.end - 1;
      continue;
    }
    if (source.startsWith("//", index)) {
      const newline = source.indexOf("\n", index + 2);
      index = newline < 0 ? source.length : newline;
      continue;
    }
    if (source.startsWith("/*", index)) {
      const end = source.indexOf("*/", index + 2);
      if (end < 0) return -1;
      index = end + 1;
      continue;
    }
    if (character === open) depth += 1;
    else if (character === close) {
      depth -= 1;
      if (depth === 0) return index;
    }
  }
  return -1;
}

function blockAfter(source: string, marker: string): string | null {
  const markerIndex = source.indexOf(marker);
  if (markerIndex < 0) return null;
  const start = source.indexOf("{", markerIndex + marker.length);
  if (start < 0) return null;
  const end = matchingDelimiter(source, start);
  return end < 0 ? null : source.slice(start + 1, end);
}

function quotedProperty(source: string, name: string): string | null {
  const expression = new RegExp(`(?:^|[,;\\n])\\s*${name}\\s*:\\s*`, "gu");
  const match = expression.exec(source);
  if (match === null) return null;
  const value = quotedAt(source, match.index + match[0].length);
  return value?.value ?? null;
}

function identifierProperty(source: string, name: string): string | null {
  const expression = new RegExp(`(?:^|[,;\\n])\\s*${name}\\s*:\\s*(?:typeof\\s+)?([A-Za-z_$][\\w$]*)`, "u");
  return expression.exec(source)?.[1] ?? null;
}

function interfaceEntries(source: string): Array<{ key: string; body: string }> {
  const body = blockAfter(source, "interface FileRoutesByPath");
  if (body === null) fail("web.tanstack_router_build_generated_manifest_invalid");
  const result: Array<{ key: string; body: string }> = [];
  let index = 0;
  while (index < body.length) {
    index = skipTrivia(body, index);
    const key = quotedAt(body, index);
    if (key === null) {
      index += 1;
      continue;
    }
    let cursor = skipTrivia(body, key.end);
    if (body[cursor] !== ":") {
      index = key.end;
      continue;
    }
    cursor = skipTrivia(body, cursor + 1);
    if (body[cursor] !== "{") {
      index = key.end;
      continue;
    }
    const end = matchingDelimiter(body, cursor);
    if (end < 0) fail("web.tanstack_router_build_generated_manifest_invalid");
    result.push({ key: key.value, body: body.slice(cursor + 1, end) });
    index = end + 1;
  }
  if (result.length === 0 || result.length > MAX_ROUTES) {
    fail("web.tanstack_router_build_generated_manifest_invalid");
  }
  return result;
}

interface RouteTemplate {
  routeId: string;
  fullPath: string;
  sourceBase: string;
  sourceKind: RouteSourceKind;
  parentRouteId: string | null;
  lazySourceBase: string | null;
  hasLoader: boolean;
  hasBeforeLoad: boolean;
}

function moduleBasePath(generatedPath: string, specifier: string): string {
  if (!specifier.startsWith(".")) fail("web.tanstack_router_build_generated_source_unsafe");
  const result = canonicalRelativePath(path.posix.join(path.posix.dirname(generatedPath), specifier));
  if (result === null) fail("web.tanstack_router_build_generated_source_unsafe");
  return result;
}

function parseGeneratedRouteTree(
  source: string,
  generatedPath: string,
  routesDirectory: string,
  basePath: string,
): RouteTemplate[] {
  if (source.length === 0 || source.length > MAX_SOURCE_BYTES) {
    fail("web.tanstack_router_build_generated_manifest_invalid");
  }
  const imports = new Map<string, string>();
  const importPattern = /\bimport\s*\{\s*Route\s+as\s+([A-Za-z_$][\w$]*)\s*\}\s*from\s*(["'`])/gu;
  for (const match of source.matchAll(importPattern)) {
    if (match.index === undefined) continue;
    const literal = quotedAt(source, match.index + match[0].length - 1);
    if (literal === null) fail("web.tanstack_router_build_generated_manifest_invalid");
    const sourceBase = moduleBasePath(generatedPath, literal.value);
    const previous = imports.get(match[1]!);
    if (previous !== undefined && previous !== sourceBase) fail("web.tanstack_router_build_generated_identity_conflict");
    imports.set(match[1]!, sourceBase);
  }
  const rootSource = imports.get("rootRouteImport");
  if (rootSource === undefined) fail("web.tanstack_router_build_generated_manifest_invalid");

  const variableByImport = new Map<string, string>();
  const parentByVariable = new Map<string, string>();
  const lazyByVariable = new Map<string, string>();
  const updatePattern = /\bconst\s+([A-Za-z_$][\w$]*)\s*=\s*([A-Za-z_$][\w$]*)\s*\.update\s*\(/gu;
  for (const match of source.matchAll(updatePattern)) {
    if (match.index === undefined) continue;
    const objectStart = source.indexOf("{", match.index + match[0].length);
    if (objectStart < 0) fail("web.tanstack_router_build_generated_manifest_invalid");
    const objectEnd = matchingDelimiter(source, objectStart);
    if (objectEnd < 0) fail("web.tanstack_router_build_generated_manifest_invalid");
    const body = source.slice(objectStart + 1, objectEnd);
    const parent = /getParentRoute\s*:\s*\(\s*\)\s*=>\s*([A-Za-z_$][\w$]*)/u.exec(body)?.[1];
    if (parent === undefined) fail("web.tanstack_router_build_generated_manifest_invalid");
    const variable = match[1]!;
    const importName = match[2]!;
    variableByImport.set(importName, variable);
    parentByVariable.set(variable, parent);
    const nextDeclaration = source.indexOf("\nconst ", objectEnd + 1);
    const tail = source.slice(objectEnd + 1, nextDeclaration < 0 ? Math.min(source.length, objectEnd + 4_096) : nextDeclaration);
    const lazyMatch = /\.lazy\s*\(\s*\(\s*\)\s*=>\s*import\s*\(\s*(["'`])/u.exec(tail);
    if (lazyMatch !== null) {
      const literal = quotedAt(tail, lazyMatch.index + lazyMatch[0].length - 1);
      if (literal === null) fail("web.tanstack_router_build_generated_manifest_invalid");
      lazyByVariable.set(variable, moduleBasePath(generatedPath, literal.value));
    }
  }

  const entryByImport = new Map<string, { routeId: string; fullPath: string; sourceBase: string; variable: string }>();
  for (const entry of interfaceEntries(source)) {
    const id = quotedProperty(entry.body, "id");
    const fullPath = quotedProperty(entry.body, "fullPath");
    const importName = identifierProperty(entry.body, "preLoaderRoute");
    if (id === null || fullPath === null || importName === null || id !== entry.key) {
      fail("web.tanstack_router_build_generated_manifest_invalid");
    }
    const sourceBase = imports.get(importName);
    const variable = variableByImport.get(importName);
    if (sourceBase === undefined || variable === undefined) fail("web.tanstack_router_build_generated_manifest_invalid");
    entryByImport.set(importName, {
      routeId: id,
      fullPath: withBase(basePath, fullPath),
      sourceBase,
      variable,
    });
  }
  const routeIdByVariable = new Map([...entryByImport.values()].map((entry) => [entry.variable, entry.routeId]));
  routeIdByVariable.set("rootRouteImport", "__root__");
  const routeDirectoryPrefix = routesDirectory.endsWith("/") ? routesDirectory : `${routesDirectory}/`;
  const sourceKind = (sourceBase: string): RouteSourceKind => (
    sourceBase === routesDirectory || sourceBase.startsWith(routeDirectoryPrefix) ? "file" : "virtual"
  );
  const routes: RouteTemplate[] = [{
    routeId: "__root__",
    fullPath: basePath === "" ? "/" : basePath,
    sourceBase: rootSource,
    sourceKind: sourceKind(rootSource),
    parentRouteId: null,
    lazySourceBase: null,
    hasLoader: false,
    hasBeforeLoad: false,
  }];
  for (const entry of [...entryByImport.values()].sort((left, right) => compareUtf8(left.routeId, right.routeId))) {
    const parentVariable = parentByVariable.get(entry.variable);
    const parentRouteId = parentVariable === undefined ? undefined : routeIdByVariable.get(parentVariable);
    if (parentRouteId === undefined || parentRouteId === entry.routeId) {
      fail("web.tanstack_router_build_generated_identity_conflict");
    }
    routes.push({
      routeId: entry.routeId,
      fullPath: entry.fullPath,
      sourceBase: entry.sourceBase,
      sourceKind: sourceKind(entry.sourceBase),
      parentRouteId,
      lazySourceBase: lazyByVariable.get(entry.variable) ?? null,
      hasLoader: false,
      hasBeforeLoad: false,
    });
  }
  return routes;
}

function objectAfterCall(source: string, start: number): string | null {
  const call = source[start - 1] === "(" ? start - 1 : source.indexOf("(", start);
  if (call < 0 || call - start > 2_048) return null;
  let open = call;
  for (let invocation = 0; invocation < 2; invocation += 1) {
    const close = matchingDelimiter(source, open, "(", ")");
    if (close < 0) return null;
    const argument = skipTrivia(source, open + 1);
    if (source[argument] === "{") {
      const end = matchingDelimiter(source, argument);
      return end < 0 || end > close ? null : source.slice(argument + 1, end);
    }
    const next = skipTrivia(source, close + 1);
    if (source[next] !== "(") return null;
    open = next;
  }
  return null;
}

function joinRoute(parent: string, child: string): string {
  const normalizedChild = child.startsWith("/") ? child : `/${child}`;
  return parent === "/" ? normalizeRoutePath(normalizedChild)! : normalizeRoutePath(`${parent}${normalizedChild}`)!;
}

function parseCodeRoutes(source: string, sourcePath: string, basePath: string): RouteTemplate[] {
  const declarations = new Map<string, {
    name: string;
    routeId: string;
    path: string | null;
    parent: string | null;
    root: boolean;
    hasLoader: boolean;
    hasBeforeLoad: boolean;
  }>();
  const expression = /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(createRootRoute(?:WithContext)?|createRoute)\b/gu;
  for (const match of source.matchAll(expression)) {
    if (match.index === undefined) continue;
    const body = objectAfterCall(source, match.index + match[0].length);
    const root = match[2]!.startsWith("createRootRoute");
    const routePath = body === null ? null : quotedProperty(`\n${body}`, "path") ?? quotedProperty(`\n${body}`, "id");
    const parent = body === null ? null : /getParentRoute\s*:\s*\(\s*\)\s*=>\s*([A-Za-z_$][\w$]*)/u.exec(body)?.[1] ?? null;
    declarations.set(match[1]!, {
      name: match[1]!,
      routeId: `${sourcePath}#${match[1]!}`,
      path: routePath,
      parent,
      root,
      hasLoader: body !== null && /(?:^|[,{\n])\s*loader\s*:/u.test(body),
      hasBeforeLoad: body !== null && /(?:^|[,{\n])\s*beforeLoad\s*:/u.test(body),
    });
  }
  const registered = new Set<string>();
  const registration = /\b([A-Za-z_$][\w$]*)\s*\.addChildren\s*\(\s*\[([^\]]*)\]/gu;
  for (const match of source.matchAll(registration)) {
    registered.add(match[1]!);
    for (const identifier of match[2]!.matchAll(/\b([A-Za-z_$][\w$]*)\b/gu)) {
      if (declarations.has(identifier[1]!)) registered.add(identifier[1]!);
    }
  }
  const roots = [...declarations.values()].filter((route) => route.root && registered.has(route.name));
  if (roots.length === 0) return [];
  if (roots.length > 1) fail("web.tanstack_router_build_code_route_identity_conflict");
  const fullPaths = new Map<string, string>([[roots[0]!.name, basePath === "" ? "/" : basePath]]);
  let progress = true;
  while (progress) {
    progress = false;
    for (const route of declarations.values()) {
      if (!registered.has(route.name) || route.root || route.path === null || route.parent === null
        || fullPaths.has(route.name)) continue;
      const parent = fullPaths.get(route.parent);
      if (parent === undefined) continue;
      const fullPath = joinRoute(parent, route.path);
      fullPaths.set(route.name, fullPath);
      progress = true;
    }
  }
  return [...declarations.values()]
    .filter((route) => registered.has(route.name) && fullPaths.has(route.name))
    .map((route) => ({
      routeId: route.routeId,
      fullPath: fullPaths.get(route.name)!,
      sourceBase: sourcePath.replace(/\.[^./]+$/u, ""),
      sourceKind: "code" as const,
      parentRouteId: route.parent === null ? null : declarations.get(route.parent)?.routeId ?? null,
      lazySourceBase: null,
      hasLoader: route.hasLoader,
      hasBeforeLoad: route.hasBeforeLoad,
    }))
    .sort((left, right) => compareUtf8(left.routeId, right.routeId));
}

function parseMasks(source: string, sourcePath: string, basePath: string): TanStackRouterObservedMask[] {
  const masks: TanStackRouterObservedMask[] = [];
  const expression = /\bcreateRouteMask\s*\(/gu;
  for (const match of source.matchAll(expression)) {
    if (match.index === undefined) continue;
    const body = objectAfterCall(source, match.index + match[0].length);
    if (body === null) continue;
    const rawFrom = quotedProperty(`\n${body}`, "from");
    const rawTo = quotedProperty(`\n${body}`, "to");
    const from = rawFrom === null ? null : withBase(basePath, rawFrom);
    const to = rawTo === null ? null : withBase(basePath, rawTo);
    masks.push({ source_path: sourcePath, from, to });
  }
  return masks;
}

function environmentName(context: UnknownRecord): string {
  const name = boundedString(record(context.environment)?.name, 128);
  if (name === null) fail("web.tanstack_router_build_environment_unavailable");
  return name;
}

function contextMethod(context: UnknownRecord, name: string): ((...args: unknown[]) => unknown) | null {
  const method = context[name];
  return typeof method === "function" ? method.bind(context) as (...args: unknown[]) => unknown : null;
}

interface LogicalModule {
  module_id: string;
  source_path: string | null;
  module_kind: ModuleKind;
}

function logicalModule(rawValue: unknown, repoRoot: string): LogicalModule {
  const raw = boundedString(rawValue);
  if (raw === null) fail("web.tanstack_router_build_module_id_unsafe");
  if (raw.startsWith("\0") || raw.startsWith("virtual:")) {
    return { module_id: `virtual:${sha256(raw)}`, source_path: null, module_kind: "virtual" };
  }
  const [rawPath, rawQuery = ""] = raw.split(/[?#]/u, 2);
  let absolute = rawPath!;
  if (absolute.startsWith("file://")) {
    try {
      absolute = fileURLToPath(absolute);
    } catch {
      fail("web.tanstack_router_build_module_id_unsafe");
    }
  }
  if (!path.isAbsolute(absolute)) {
    return { module_id: `external:${sha256(raw)}`, source_path: null, module_kind: "external" };
  }
  const relative = path.relative(path.resolve(repoRoot), path.resolve(absolute));
  const sourcePath = relative === "" || relative.startsWith("..") || path.isAbsolute(relative)
    ? null
    : canonicalRelativePath(relative);
  if (sourcePath === null) {
    return { module_id: `external:${sha256(raw)}`, source_path: null, module_kind: "external" };
  }
  const suffix = rawQuery === "" ? "" : `#query:${sha256(rawQuery)}`;
  return { module_id: `${sourcePath}${suffix}`, source_path: sourcePath, module_kind: "project" };
}

function stringArray(value: unknown, sanitizer: (value: unknown) => string, code: string): string[] {
  if (!Array.isArray(value) || value.length > MAX_IMPORTS) fail(code);
  return [...new Set(value.map(sanitizer))].sort(compareUtf8);
}

function observedModule(
  id: unknown,
  infoValue: unknown,
  repoRoot: string,
): TanStackRouterObservedModule {
  const logical = logicalModule(id, repoRoot);
  const info = record(infoValue);
  if (info === null) fail("web.tanstack_router_build_module_info_invalid");
  const toId = (value: unknown): string => logicalModule(value, repoRoot).module_id;
  return {
    ...logical,
    is_entry: info.isEntry === true,
    imported_ids: stringArray(info.importedIds ?? [], toId, "web.tanstack_router_build_module_imports_invalid"),
    dynamic_imported_ids: stringArray(
      info.dynamicallyImportedIds ?? [], toId, "web.tanstack_router_build_module_imports_invalid",
    ),
  };
}

function mergeModules(modules: readonly TanStackRouterObservedModule[]): TanStackRouterObservedModule[] {
  const result = new Map<string, TanStackRouterObservedModule>();
  for (const module of modules) {
    const previous = result.get(module.module_id);
    if (previous !== undefined && (previous.source_path !== module.source_path
      || previous.module_kind !== module.module_kind)) {
      fail("web.tanstack_router_build_module_identity_conflict");
    }
    result.set(module.module_id, previous === undefined ? module : {
      ...module,
      is_entry: previous.is_entry || module.is_entry,
      imported_ids: [...new Set([...previous.imported_ids, ...module.imported_ids])].sort(compareUtf8),
      dynamic_imported_ids: [...new Set([...previous.dynamic_imported_ids, ...module.dynamic_imported_ids])].sort(compareUtf8),
    });
  }
  return [...result.values()].sort((left, right) => compareUtf8(left.module_id, right.module_id));
}

function bytesDigest(value: unknown, code: string): string {
  if (typeof value === "string" || value instanceof Uint8Array) return sha256(value);
  fail(code);
}

function observedOutput(
  value: unknown,
  moduleById: ReadonlyMap<string, TanStackRouterObservedModule>,
  repoRoot: string,
): TanStackRouterObservedOutput {
  const output = record(value);
  if (output === null) fail("web.tanstack_router_build_output_contract_invalid");
  const fileName = outputPath(output.fileName);
  if (output.type === "asset") {
    return {
      file_name: fileName,
      kind: "asset",
      digest: bytesDigest(output.source, "web.tanstack_router_build_asset_source_invalid"),
      entry: false,
      module_ids: [],
      imported_outputs: [],
    };
  }
  if (output.type !== "chunk") fail("web.tanstack_router_build_output_contract_invalid");
  const rawModules = record(output.modules);
  if (rawModules === null || Object.keys(rawModules).length > MAX_MODULES) {
    fail("web.tanstack_router_build_chunk_modules_invalid");
  }
  const moduleIds = Object.keys(rawModules).map((id) => logicalModule(id, repoRoot).module_id).sort(compareUtf8);
  for (const id of moduleIds) {
    if (!moduleById.has(id)) fail("web.tanstack_router_build_chunk_module_missing");
  }
  return {
    file_name: fileName,
    kind: "chunk",
    digest: bytesDigest(output.code, "web.tanstack_router_build_chunk_code_invalid"),
    entry: output.isEntry === true,
    module_ids: [...new Set(moduleIds)],
    imported_outputs: stringArray(
      [...(Array.isArray(output.imports) ? output.imports : []), ...(Array.isArray(output.dynamicImports) ? output.dynamicImports : [])],
      outputPath,
      "web.tanstack_router_build_chunk_imports_invalid",
    ),
  };
}

function sourceStem(value: string): string {
  const extension = ROUTE_EXTENSIONS.find((candidate) => value.endsWith(candidate));
  return extension === undefined ? value : value.slice(0, -extension.length);
}

function resolveObservedSource(
  sourceBase: string,
  modules: readonly TanStackRouterObservedModule[],
  codeSource: boolean,
): string {
  if (codeSource) {
    const exact = modules.filter((module) => module.source_path !== null && sourceStem(module.source_path) === sourceBase);
    if (exact.length !== 1) fail("web.tanstack_router_build_source_mapping_invalid");
    return exact[0]!.source_path!;
  }
  const matches = modules.filter((module) => module.source_path !== null && sourceStem(module.source_path) === sourceBase);
  const paths = [...new Set(matches.map((module) => module.source_path!))];
  if (paths.length !== 1) fail("web.tanstack_router_build_source_mapping_invalid");
  return paths[0]!;
}

function maskKey(mask: TanStackRouterObservedMask): string {
  return canonicalJson(mask as unknown as JsonValue);
}

function routeManifestDigest(
  generatedPath: string | null,
  generatedDigest: string | null,
  routes: readonly TanStackRouterObservedRoute[],
  masks: readonly TanStackRouterObservedMask[],
): string {
  return sha256(canonicalJson({
    contract: TANSTACK_ROUTER_ROUTE_MANIFEST_CONTRACT,
    generated_route_tree_path: generatedPath,
    generated_route_tree_digest: generatedDigest,
    routes: [...routes],
    masks: [...masks],
  } as unknown as JsonValue));
}

interface MutableState {
  readonly capability: TanStackRouterCapability;
  readonly repoRoot: string;
  readonly sink: TanStackRouterObservationSink;
  readonly timeoutMs: number;
  readonly expectedPluginNames: string[];
  readonly routeTemplates: Map<string, RouteTemplate>;
  readonly moduleOptions: Map<string, { loader: boolean; beforeLoad: boolean }>;
  readonly masks: Map<string, TanStackRouterObservedMask>;
  generatedDigest: string | null;
  config: TanStackRouterObservedConfig | null;
  viteVersion: string | null;
  build: TanStackRouterObservedBuild | null;
  failed: boolean;
  completed: boolean;
  writing: boolean;
  wrote: boolean;
}

async function readGeneratedArtifact(state: MutableState): Promise<void> {
  const logicalPath = state.capability.generated_route_tree;
  if (logicalPath === null) return;
  const absolute = path.resolve(state.repoRoot, logicalPath);
  const metadata = await lstat(absolute).catch(() => null);
  if (metadata === null || metadata.isSymbolicLink() || !metadata.isFile()
    || metadata.size === 0 || metadata.size > MAX_SOURCE_BYTES) {
    fail("web.tanstack_router_build_generated_artifact_unavailable");
  }
  const [rootReal, fileReal] = await Promise.all([realpath(state.repoRoot), realpath(absolute)]);
  const relative = path.relative(rootReal, fileReal);
  if (relative === "" || relative.startsWith("..") || path.isAbsolute(relative)) {
    fail("web.tanstack_router_build_generated_artifact_unsafe");
  }
  const bytes = await readFile(fileReal);
  const source = bytes.toString("utf8");
  if (Buffer.from(source, "utf8").length !== bytes.length) {
    fail("web.tanstack_router_build_generated_artifact_invalid_utf8");
  }
  const routes = parseGeneratedRouteTree(
    source,
    logicalPath,
    state.capability.routes_directory,
    state.capability.base_path,
  );
  for (const route of routes) {
    const previous = state.routeTemplates.get(route.routeId);
    if (previous !== undefined && canonicalJson(previous as unknown as JsonValue) !== canonicalJson(route as unknown as JsonValue)) {
      fail("web.tanstack_router_build_generated_identity_conflict");
    }
    state.routeTemplates.set(route.routeId, route);
  }
  state.generatedDigest = sha256(bytes);
}

function validateFinalPluginChain(config: UnknownRecord, state: MutableState): TanStackRouterObservedConfig {
  const plugins = config.plugins;
  if (!Array.isArray(plugins) || plugins.length > MAX_PLUGINS) {
    fail("web.tanstack_router_build_plugin_chain_invalid");
  }
  const names = plugins.map((value) => pluginName(value, "web.tanstack_router_build_plugin_chain_invalid"));
  const ownIndexes = names.flatMap((name, index) => name === TANSTACK_ROUTER_BUILD_OBSERVER ? [index] : []);
  if (ownIndexes.length !== 1) fail("web.tanstack_router_build_plugin_chain_invalid");
  const observerIndex = ownIndexes[0]!;
  let previous = -1;
  for (const expected of state.expectedPluginNames) {
    const indexes = names.flatMap((name, index) => name === expected ? [index] : []);
    if (indexes.length !== 1 || indexes[0]! <= previous || indexes[0]! >= observerIndex) {
      fail("web.tanstack_router_build_plugin_chain_invalid");
    }
    previous = indexes[0]!;
  }
  const generatorIndexes = names.flatMap((name, index) => name === ROUTER_GENERATOR_PLUGIN ? [index] : []);
  if (state.capability.generated_route_tree !== null
    && (generatorIndexes.length !== 1 || generatorIndexes[0]! >= observerIndex)) {
    fail("web.tanstack_router_build_generator_plugin_missing");
  }
  const configRoot = boundedString(config.root);
  if (configRoot === null || path.resolve(configRoot) !== state.repoRoot) {
    fail("web.tanstack_router_build_config_root_invalid");
  }
  const mode = boundedString(config.mode) ?? "production";
  if (mode !== "production") fail("web.tanstack_router_build_mode_invalid");
  const rawBase = config.base;
  const base = rawBase === undefined || rawBase === "/"
    ? ""
    : configuredBasePath(rawBase);
  if (base !== state.capability.base_path) {
    fail("web.tanstack_router_build_base_path_mismatch");
  }
  return {
    mode,
    base,
    plugin_count: names.length,
    observer_plugin_index: observerIndex,
    generator_plugin_index: generatorIndexes[0] ?? null,
  };
}

function finalObservation(state: MutableState): TanStackRouterBuildObservation {
  if (!state.completed || state.failed || state.build === null || state.config === null || state.viteVersion === null) {
    fail("web.tanstack_router_build_observation_incomplete");
  }
  if (state.capability.generated_route_tree !== null
    && (state.generatedDigest === null || state.routeTemplates.size === 0)) {
    fail("web.tanstack_router_build_generated_artifact_missing");
  }
  const modules = state.build.modules;
  const routes = [...state.routeTemplates.values()].map((route): TanStackRouterObservedRoute => {
    const sourcePath = resolveObservedSource(route.sourceBase, modules, route.sourceKind === "code");
    const lazySourcePath = route.lazySourceBase === null
      ? null
      : resolveObservedSource(route.lazySourceBase, modules, false);
    const options = state.moduleOptions.get(sourcePath);
    return {
      route_id: route.routeId,
      full_path: route.fullPath,
      source_path: sourcePath,
      source_kind: route.sourceKind,
      parent_route_id: route.parentRouteId,
      lazy_source_path: lazySourcePath,
      has_loader: route.hasLoader || options?.loader === true,
      has_before_load: route.hasBeforeLoad || options?.beforeLoad === true,
    };
  }).sort((left, right) => compareUtf8(left.route_id, right.route_id));
  if (routes.length === 0 || routes.length > MAX_ROUTES
    || new Set(routes.map((route) => route.route_id)).size !== routes.length) {
    fail("web.tanstack_router_build_route_manifest_invalid");
  }
  const routeIds = new Set(routes.map((route) => route.route_id));
  for (const route of routes) {
    if (route.parent_route_id !== null && !routeIds.has(route.parent_route_id)) {
      fail("web.tanstack_router_build_parent_route_missing");
    }
  }
  const masks = [...state.masks.values()].sort((left, right) => compareUtf8(maskKey(left), maskKey(right)));
  if (masks.length > MAX_MASKS) fail("web.tanstack_router_build_mask_limit_exceeded");
  const manifestDigest = routeManifestDigest(
    state.capability.generated_route_tree,
    state.generatedDigest,
    routes,
    masks,
  );
  const observation: TanStackRouterBuildObservation = {
    schema_version: TANSTACK_ROUTER_BUILD_SCHEMA,
    observer: TANSTACK_ROUTER_BUILD_OBSERVER,
    observer_version: TANSTACK_ROUTER_BUILD_OBSERVER_VERSION,
    capability: TANSTACK_ROUTER_BUILD_CAPABILITY,
    manifest_contract: TANSTACK_ROUTER_ROUTE_MANIFEST_CONTRACT,
    router_version: state.capability.router_version,
    generated_route_tree_path: state.capability.generated_route_tree,
    generated_route_tree_digest: state.generatedDigest,
    route_manifest_digest: manifestDigest,
    route_count: routes.length,
    mask_count: masks.length,
    routes,
    masks,
    builds: [{ ...state.build, config: state.config, vite_version: state.viteVersion }],
  };
  validateTanStackRouterBuildObservation(observation);
  return observation;
}

async function maybeWrite(state: MutableState): Promise<void> {
  if (state.wrote || state.writing || !state.completed) return;
  state.writing = true;
  try {
    const observation = finalObservation(state);
    await bounded("web.tanstack_router_build_observer_sink_failed", state.timeoutMs, () => state.sink.write(observation));
    state.wrote = true;
  } finally {
    state.writing = false;
  }
}

export function createTanStackRouterBuildObserverPlugin(
  options: TanStackRouterObserverOptions,
): TanStackRouterVitePluginLike {
  if (boundedString(options.repoRoot) === null || !path.isAbsolute(options.repoRoot)) {
    fail("web.tanstack_router_build_repo_root_invalid");
  }
  const capability = detectTanStackRouterBuildCapability(
    options.routerVersion,
    options.generatedRouteTree,
    options.routesDirectory,
    options.basePath,
    options.existingVitePlugins ?? [],
  );
  const state: MutableState = {
    capability,
    repoRoot: path.resolve(options.repoRoot),
    sink: options.sink,
    timeoutMs: timeoutValue(options.timeoutMs),
    expectedPluginNames: validatePluginNames(options.existingVitePlugins ?? []),
    routeTemplates: new Map(),
    moduleOptions: new Map(),
    masks: new Map(),
    generatedDigest: null,
    config: null,
    viteVersion: null,
    build: null,
    failed: false,
    completed: false,
    writing: false,
    wrote: false,
  };
  return {
    name: TANSTACK_ROUTER_BUILD_OBSERVER,
    apply: "build",
    enforce: "post",
    async configResolved(config) {
      await bounded("web.tanstack_router_build_config_hook_failed", state.timeoutMs, async () => {
        state.config = validateFinalPluginChain(config, state);
        await readGeneratedArtifact(state);
      });
    },
    buildStart() {
      normalizedHook("web.tanstack_router_build_start_hook_failed", () => {
        if (environmentName(this) !== "client") return;
        state.viteVersion = stableVersion(
          record(this.meta)?.viteVersion,
          new Set([6, 7]),
          "web.tanstack_router_build_vite_version_unsupported",
        );
      });
    },
    transform(code, id) {
      return normalizedHook("web.tanstack_router_build_transform_hook_failed", () => {
        if (environmentName(this) !== "client") return null;
        if (typeof code !== "string" || code.length > MAX_TRANSFORM_BYTES || boundedString(id) === null) {
          fail("web.tanstack_router_build_transform_contract_invalid");
        }
        const module = logicalModule(id, state.repoRoot);
        if (module.source_path === null) return null;
        const options = state.moduleOptions.get(module.source_path) ?? { loader: false, beforeLoad: false };
        state.moduleOptions.set(module.source_path, {
          loader: options.loader || /(?:^|[,{\n])\s*loader\s*:/u.test(code),
          beforeLoad: options.beforeLoad || /(?:^|[,{\n])\s*beforeLoad\s*:/u.test(code),
        });
        for (const route of parseCodeRoutes(code, module.source_path, capability.base_path)) {
          const previous = state.routeTemplates.get(route.routeId);
          if (previous !== undefined
            && canonicalJson(previous as unknown as JsonValue) !== canonicalJson(route as unknown as JsonValue)) {
            fail("web.tanstack_router_build_code_route_identity_conflict");
          }
          state.routeTemplates.set(route.routeId, previous ?? route);
        }
        for (const mask of parseMasks(code, module.source_path, capability.base_path)) {
          state.masks.set(maskKey(mask), mask);
        }
        return null;
      });
    },
    generateBundle(_outputOptions, bundle) {
      normalizedHook("web.tanstack_router_build_bundle_hook_failed", () => {
        if (environmentName(this) !== "client") return;
        const idsMethod = contextMethod(this, "getModuleIds");
        const infoMethod = contextMethod(this, "getModuleInfo");
        if (idsMethod === null || infoMethod === null) fail("web.tanstack_router_build_module_graph_unavailable");
        const ids = [...idsMethod() as Iterable<unknown>];
        if (ids.length > MAX_MODULES) fail("web.tanstack_router_build_module_limit_exceeded");
        const modules = mergeModules(ids.map((id) => observedModule(id, infoMethod(id), state.repoRoot)));
        const moduleById = new Map(modules.map((module) => [module.module_id, module]));
        const rawOutputs = Object.values(bundle);
        if (rawOutputs.length > MAX_OUTPUTS) fail("web.tanstack_router_build_output_limit_exceeded");
        const outputs = rawOutputs.map((value) => observedOutput(value, moduleById, state.repoRoot))
          .sort((left, right) => compareUtf8(left.file_name, right.file_name));
        if (state.config === null || state.viteVersion === null) fail("web.tanstack_router_build_hook_order_invalid");
        state.build = {
          vite_environment: "client",
          vite_version: state.viteVersion,
          config: state.config,
          modules,
          outputs,
        };
      });
    },
    buildEnd(error) {
      normalizedHook("web.tanstack_router_build_end_hook_failed", () => {
        if (environmentName(this) === "client" && error !== undefined && error !== null) state.failed = true;
      });
    },
    async closeBundle() {
      await bounded("web.tanstack_router_build_close_hook_failed", state.timeoutMs, async () => {
        if (environmentName(this) !== "client") return;
        state.completed = true;
        await maybeWrite(state);
      });
    },
  };
}

export function preflightTanStackRouterBuildObserver(options: TanStackRouterObserverOptions): {
  plugin: TanStackRouterVitePluginLike;
  capability: TanStackRouterCapability;
} {
  return {
    capability: detectTanStackRouterBuildCapability(
      options.routerVersion,
      options.generatedRouteTree,
      options.routesDirectory,
      options.basePath,
      options.existingVitePlugins ?? [],
    ),
    plugin: createTanStackRouterBuildObserverPlugin(options),
  };
}

function validateCanonicalOrder<T>(values: readonly T[], key: (value: T) => string, code: string): void {
  const keys = values.map(key);
  const sorted = [...keys].sort(compareUtf8);
  if (new Set(keys).size !== keys.length || keys.some((value, index) => value !== sorted[index])) fail(code);
}

function validateModule(module: TanStackRouterObservedModule): void {
  if (boundedString(module.module_id) === null
    || !new Set<ModuleKind>(["project", "virtual", "external"]).has(module.module_kind)
    || (module.source_path !== null && canonicalRelativePath(module.source_path) !== module.source_path)) {
    fail("web.tanstack_router_build_observation_contract_invalid");
  }
  validateCanonicalOrder(module.imported_ids, String, "web.tanstack_router_build_observation_contract_invalid");
  validateCanonicalOrder(module.dynamic_imported_ids, String, "web.tanstack_router_build_observation_contract_invalid");
}

export function validateTanStackRouterBuildObservation(observation: TanStackRouterBuildObservation): void {
  if (observation.schema_version !== TANSTACK_ROUTER_BUILD_SCHEMA
    || observation.observer !== TANSTACK_ROUTER_BUILD_OBSERVER
    || observation.observer_version !== TANSTACK_ROUTER_BUILD_OBSERVER_VERSION
    || observation.capability !== TANSTACK_ROUTER_BUILD_CAPABILITY
    || observation.manifest_contract !== TANSTACK_ROUTER_ROUTE_MANIFEST_CONTRACT) {
    fail("web.tanstack_router_build_observation_contract_invalid");
  }
  stableVersion(observation.router_version, new Set([1]), "web.tanstack_router_build_version_unsupported");
  if ((observation.generated_route_tree_path === null) !== (observation.generated_route_tree_digest === null)
    || (observation.generated_route_tree_path !== null
      && canonicalRelativePath(observation.generated_route_tree_path) !== observation.generated_route_tree_path)
    || (observation.generated_route_tree_digest !== null && !SHA256.test(observation.generated_route_tree_digest))) {
    fail("web.tanstack_router_build_observation_contract_invalid");
  }
  if (observation.route_count !== observation.routes.length || observation.mask_count !== observation.masks.length
    || observation.routes.length === 0 || observation.routes.length > MAX_ROUTES
    || observation.masks.length > MAX_MASKS || !SHA256.test(observation.route_manifest_digest)) {
    fail("web.tanstack_router_build_observation_contract_invalid");
  }
  validateCanonicalOrder(observation.routes, (route) => route.route_id, "web.tanstack_router_build_observation_contract_invalid");
  const routeIds = new Set(observation.routes.map((route) => route.route_id));
  for (const route of observation.routes) {
    if (boundedString(route.route_id) === null || normalizeRoutePath(route.full_path) !== route.full_path
      || canonicalRelativePath(route.source_path) !== route.source_path
      || !new Set<RouteSourceKind>(["file", "virtual", "code"]).has(route.source_kind)
      || (route.parent_route_id !== null && (!routeIds.has(route.parent_route_id) || route.parent_route_id === route.route_id))
      || (route.lazy_source_path !== null && canonicalRelativePath(route.lazy_source_path) !== route.lazy_source_path)
      || typeof route.has_loader !== "boolean" || typeof route.has_before_load !== "boolean") {
      fail("web.tanstack_router_build_observation_contract_invalid");
    }
  }
  validateCanonicalOrder(observation.masks, maskKey, "web.tanstack_router_build_observation_contract_invalid");
  for (const mask of observation.masks) {
    if (canonicalRelativePath(mask.source_path) !== mask.source_path
      || (mask.from !== null && normalizeRoutePath(mask.from) !== mask.from)
      || (mask.to !== null && normalizeRoutePath(mask.to) !== mask.to)) {
      fail("web.tanstack_router_build_observation_contract_invalid");
    }
  }
  if (routeManifestDigest(
    observation.generated_route_tree_path,
    observation.generated_route_tree_digest,
    observation.routes,
    observation.masks,
  ) !== observation.route_manifest_digest || observation.builds.length !== 1) {
    fail("web.tanstack_router_build_observation_contract_invalid");
  }
  const build = observation.builds[0]!;
  stableVersion(build.vite_version, new Set([6, 7]), "web.tanstack_router_build_vite_version_unsupported");
  if (build.vite_environment !== "client" || build.config.mode !== "production"
    || build.config.observer_plugin_index >= build.config.plugin_count
    || (observation.generated_route_tree_path !== null && build.config.generator_plugin_index === null)) {
    fail("web.tanstack_router_build_observation_contract_invalid");
  }
  validateCanonicalOrder(build.modules, (module) => module.module_id, "web.tanstack_router_build_observation_contract_invalid");
  for (const module of build.modules) validateModule(module);
  const moduleIds = new Set(build.modules.map((module) => module.module_id));
  validateCanonicalOrder(build.outputs, (output) => output.file_name, "web.tanstack_router_build_observation_contract_invalid");
  const outputNames = new Set(build.outputs.map((output) => output.file_name));
  for (const output of build.outputs) {
    if (canonicalRelativePath(output.file_name) !== output.file_name || !SHA256.test(output.digest)
      || !new Set(["chunk", "asset"]).has(output.kind)
      || output.module_ids.some((id) => !moduleIds.has(id))
      || output.imported_outputs.some((name) => !outputNames.has(name))) {
      fail("web.tanstack_router_build_observation_contract_invalid");
    }
    validateCanonicalOrder(output.module_ids, String, "web.tanstack_router_build_observation_contract_invalid");
    validateCanonicalOrder(output.imported_outputs, String, "web.tanstack_router_build_observation_contract_invalid");
  }
}

export function tanStackRouterBuildFailureDiagnostic(error: unknown, profileId: string): Diagnostic {
  const code = error instanceof TanStackRouterBuildObserverError && /^web\.tanstack_router_build_[a-z0-9_]+$/u.test(error.code)
    ? error.code
    : "web.tanstack_router_build_observer_failed";
  const properties: Record<string, JsonValue> = {
    framework: "tanstack-router",
    observer: TANSTACK_ROUTER_BUILD_OBSERVER,
    observer_version: TANSTACK_ROUTER_BUILD_OBSERVER_VERSION,
    capability: TANSTACK_ROUTER_BUILD_CAPABILITY,
    contract_version: FRAMEWORK_BUILD_GRAPH_CONTRACT_VERSION,
    observer_failure: true,
  };
  return {
    id: stableId("diagnostic", { code, profile_id: profileId, properties }),
    severity: "error",
    code,
    message: `${code}: TanStack Router build observation was not promoted`,
    path: null,
    profile_id: profileId,
    properties,
  };
}

function buildEvidence(
  provenance: TanStackRouterBuildProvenance,
  logicalPath: string,
  artifactDigest: string,
  properties: Record<string, JsonValue> = {},
): Evidence {
  return frameworkBuildEvidence(
    TANSTACK_ROUTER_FRAMEWORK_BUILD_DESCRIPTOR,
    provenance,
    logicalPath,
    artifactDigest,
    properties,
  );
}

function buildNode(
  kind: GraphNode["kind"],
  identity: Record<string, JsonValue>,
  displayName: string,
  properties: Record<string, JsonValue>,
  provenance: TanStackRouterBuildProvenance,
  logicalPath: string,
  digest: string,
): GraphNode {
  return frameworkBuildGeneratedNode(
    TANSTACK_ROUTER_FRAMEWORK_BUILD_DESCRIPTOR,
    kind,
    identity,
    displayName,
    properties,
    provenance,
    logicalPath,
    digest,
  );
}

function addRelation(
  sites: DependencySite[],
  edges: GraphEdge[],
  source: string,
  target: string,
  kind: string,
  specifier: string,
  condition: Condition,
  evidence: Evidence,
  profileId: string,
): void {
  const relation = frameworkBuildRelation(
    TANSTACK_ROUTER_FRAMEWORK_BUILD_DESCRIPTOR,
    source,
    target,
    kind,
    specifier,
    "client",
    condition,
    evidence,
    profileId,
  );
  sites.push(relation.site);
  edges.push(relation.edge);
}

function sourcePath(node: GraphNode): string | null {
  const value = node.properties.source_path ?? node.properties.relative_path ?? node.properties.path;
  return typeof value === "string" ? value : null;
}

function nodesByPath(nodes: readonly GraphNode[]): Map<string, GraphNode[]> {
  const result = new Map<string, GraphNode[]>();
  for (const node of nodes) {
    const value = sourcePath(node);
    if (value === null) continue;
    const items = result.get(value) ?? [];
    items.push(node);
    result.set(value, items);
  }
  return result;
}

function graphDiagnostic(
  code: string,
  subject: string,
  profileId: string,
  evidence: Evidence,
  properties: Record<string, JsonValue>,
): Diagnostic {
  return frameworkBuildDiagnostic(
    TANSTACK_ROUTER_FRAMEWORK_BUILD_DESCRIPTOR,
    code,
    subject,
    profileId,
    evidence,
    properties,
  );
}

function uniqueById<T extends { id: string }>(values: readonly T[], code: string): T[] {
  try {
    return deduplicateFrameworkBuildRecords(values);
  } catch {
    fail(code);
  }
}

export function buildTanStackRouterObservedGraph(
  input: TanStackRouterBuildGraphInput,
): TanStackRouterBuildGraphDelta {
  validateTanStackRouterBuildObservation(input.observation);
  try {
    validateFrameworkBuildProvenance(input.provenance);
  } catch {
    fail("web.tanstack_router_build_provenance_invalid");
  }
  const observation = input.observation;
  const manifestPath = `.tanstack/depgraph/${observation.route_manifest_digest}.json`;
  const manifestEvidence = buildEvidence(input.provenance, manifestPath, observation.route_manifest_digest);
  const baseByPath = nodesByPath(input.baseNodes);
  const nodes = new Map<string, GraphNode>();
  const sites: DependencySite[] = [];
  const edges: GraphEdge[] = [];
  const diagnostics: Diagnostic[] = [];
  const addNode = (node: GraphNode): void => {
    const previous = nodes.get(node.id);
    if (previous !== undefined
      && canonicalJson(previous as unknown as JsonValue) !== canonicalJson(node as unknown as JsonValue)) {
      fail("web.tanstack_router_build_node_conflict");
    }
    nodes.set(node.id, previous ?? node);
  };
  const condition = (properties: Record<string, string> = {}): Condition => frameworkBuildCondition("client", properties);

  const build = observation.builds[0]!;
  const moduleNodes = new Map<string, GraphNode>();
  for (const module of build.modules) {
    const candidates = module.source_path === null ? [] : (baseByPath.get(module.source_path) ?? [])
      .filter((node) => node.kind === "file" || node.kind === "module");
    let node = candidates.length === 1 ? candidates[0]! : null;
    if (node === null) {
      node = buildNode("module", {
        framework: "tanstack-router",
        module_id: module.module_id,
        profile_id: input.provenance.profile_id,
      }, module.module_id, {
        framework: "tanstack-router",
        module_id: module.module_id,
        source_path: module.source_path,
        module_kind: module.module_kind,
        environment: "browser",
        profile_id: input.provenance.profile_id,
      }, input.provenance, manifestPath, observation.route_manifest_digest);
    }
    addNode(node);
    moduleNodes.set(module.module_id, node);
  }

  const modulesBySource = new Map<string, GraphNode[]>();
  for (const module of build.modules) {
    if (module.source_path === null) continue;
    const node = moduleNodes.get(module.module_id)!;
    const values = modulesBySource.get(module.source_path) ?? [];
    if (!values.some((candidate) => candidate.id === node.id)) values.push(node);
    modulesBySource.set(module.source_path, values);
  }

  const routeNodes = new Map<string, GraphNode>();
  const routesByPath = new Map<string, GraphNode[]>();
  for (const route of observation.routes) {
    const staticCandidates = input.baseNodes.filter((node) => node.kind === "route"
      && (node.properties.framework === "tanstack-router"
        || record(node.properties.canonical_identity)?.framework === "tanstack-router")
      && node.properties.route_pattern === route.full_path);
    const exact = staticCandidates.filter((node) => sourcePath(node) === route.source_path);
    let routeNode: GraphNode;
    if (exact.length === 1) routeNode = exact[0]!;
    else {
      routeNode = buildNode("route", {
        framework: "tanstack-router",
        route_id: route.route_id,
        route_pattern: route.full_path,
        source_path: route.source_path,
        source_kind: route.source_kind,
        profile_id: input.provenance.profile_id,
      }, `tanstack-router:${route.full_path}`, {
        framework: "tanstack-router",
        route_id: route.route_id,
        route_pattern: route.full_path,
        route_kind: `tanstack-build-${route.source_kind}-route`,
        source_path: route.source_path,
        source_kind: route.source_kind,
        lazy_source_path: route.lazy_source_path,
        has_loader: route.has_loader,
        has_before_load: route.has_before_load,
        environment: "browser",
        profile_id: input.provenance.profile_id,
      }, input.provenance, manifestPath, observation.route_manifest_digest);
      if (staticCandidates.length > 0 || exact.length > 1) {
        const unresolved = frameworkBuildUnresolvedTarget(
          TANSTACK_ROUTER_FRAMEWORK_BUILD_DESCRIPTOR,
          input.provenance,
          "observes_definition",
          routeNode.id,
          `${route.source_path}#${route.route_id}`,
          "client",
          condition({ "tanstack.router.route": route.full_path }),
          manifestEvidence,
          "framework_build_dynamic_target_unmatched",
        );
        addNode(unresolved.node);
        sites.push(unresolved.site);
        edges.push(unresolved.edge);
        diagnostics.push(graphDiagnostic(
          "web.tanstack_router_build_static_route_mismatch",
          route.route_id,
          input.provenance.profile_id,
          manifestEvidence,
          { candidate_count: staticCandidates.length, route_pattern: route.full_path, source_path: route.source_path },
        ));
      }
    }
    addNode(routeNode);
    routeNodes.set(route.route_id, routeNode);
    const paths = routesByPath.get(route.full_path) ?? [];
    paths.push(routeNode);
    routesByPath.set(route.full_path, paths);
    const sources = modulesBySource.get(route.source_path) ?? [];
    if (sources.length === 1) {
      addRelation(
        sites, edges, sources[0]!.id, routeNode.id, "route_entry", route.full_path,
        condition({ "tanstack.router.source_kind": route.source_kind }), manifestEvidence, input.provenance.profile_id,
      );
    } else {
      const unresolved = frameworkBuildUnresolvedTarget(
        TANSTACK_ROUTER_FRAMEWORK_BUILD_DESCRIPTOR,
        input.provenance,
        "route_entry",
        routeNode.id,
        route.source_path,
        "client",
        condition({ "tanstack.router.route": route.full_path }),
        manifestEvidence,
        "framework_build_dynamic_target_unmatched",
      );
      addNode(unresolved.node);
      sites.push(unresolved.site);
      edges.push(unresolved.edge);
    }
  }

  for (const route of observation.routes) {
    const source = routeNodes.get(route.route_id)!;
    if (route.parent_route_id !== null) {
      const parent = routeNodes.get(route.parent_route_id);
      if (parent === undefined) fail("web.tanstack_router_build_parent_route_missing");
      addRelation(
        sites, edges, source.id, parent.id, "parent_route", route.parent_route_id,
        condition({ "tanstack.router.parent": "generated" }), manifestEvidence, input.provenance.profile_id,
      );
    }
    const sourceModules = modulesBySource.get(route.source_path) ?? [];
    if (sourceModules.length === 1 && route.has_loader) addRelation(
      sites, edges, source.id, sourceModules[0]!.id, "loads", `${route.source_path}#loader`,
      condition({ "tanstack.router.handler": "loader" }), manifestEvidence, input.provenance.profile_id,
    );
    if (sourceModules.length === 1 && route.has_before_load) addRelation(
      sites, edges, source.id, sourceModules[0]!.id, "before_load", `${route.source_path}#beforeLoad`,
      condition({ "tanstack.router.handler": "beforeLoad" }), manifestEvidence, input.provenance.profile_id,
    );
    if (route.lazy_source_path !== null) {
      const lazy = modulesBySource.get(route.lazy_source_path) ?? [];
      if (lazy.length === 1) addRelation(
        sites, edges, source.id, lazy[0]!.id, "dynamic_imports", route.lazy_source_path,
        condition({ "tanstack.router.lazy": "generated" }), manifestEvidence, input.provenance.profile_id,
      );
      else {
        const unresolved = frameworkBuildUnresolvedTarget(
          TANSTACK_ROUTER_FRAMEWORK_BUILD_DESCRIPTOR,
          input.provenance,
          "dynamic_imports",
          source.id,
          route.lazy_source_path,
          "client",
          condition({ "tanstack.router.lazy": "generated" }),
          manifestEvidence,
          "framework_build_dynamic_target_unmatched",
        );
        addNode(unresolved.node);
        sites.push(unresolved.site);
        edges.push(unresolved.edge);
      }
    }
  }

  for (const mask of observation.masks) {
    const from = mask.from === null ? [] : routesByPath.get(mask.from) ?? [];
    const source = from.length === 1 ? from[0]! : (modulesBySource.get(mask.source_path) ?? [])[0];
    if (source === undefined) continue;
    const targets = mask.to === null ? [] : routesByPath.get(mask.to) ?? [];
    if (targets.length === 1) addRelation(
      sites, edges, source.id, targets[0]!.id, "masks_to", mask.to!,
      condition({ "tanstack.router.mask": "observed" }), manifestEvidence, input.provenance.profile_id,
    );
    else {
      const unresolved = frameworkBuildUnresolvedTarget(
        TANSTACK_ROUTER_FRAMEWORK_BUILD_DESCRIPTOR,
        input.provenance,
        "masks_to",
        source.id,
        mask.to ?? "<dynamic-mask-target>",
        "client",
        condition({ "tanstack.router.mask": "observed" }),
        manifestEvidence,
        "framework_build_dynamic_target_unmatched",
      );
      addNode(unresolved.node);
      sites.push(unresolved.site);
      edges.push(unresolved.edge);
      diagnostics.push(graphDiagnostic(
        "web.tanstack_router_build_mask_target_unmatched",
        mask.to ?? "<dynamic-mask-target>",
        input.provenance.profile_id,
        manifestEvidence,
        { from: mask.from, source_path: mask.source_path, target_count: targets.length },
      ));
    }
  }

  const outputNodes = new Map<string, GraphNode>();
  for (const output of build.outputs) {
    const evidence = buildEvidence(input.provenance, output.file_name, output.digest);
    const outputNode = buildNode("file", {
      framework: "tanstack-router",
      file_name: output.file_name,
      output_digest: output.digest,
      profile_id: input.provenance.profile_id,
    }, output.file_name, {
      framework: "tanstack-router",
      artifact_kind: output.kind,
      logical_path: output.file_name,
      artifact_digest: output.digest,
      environment: "browser",
      entry: output.entry,
      profile_id: input.provenance.profile_id,
    }, input.provenance, output.file_name, output.digest);
    addNode(outputNode);
    outputNodes.set(output.file_name, outputNode);
    for (const moduleId of output.module_ids) {
      const moduleNode = moduleNodes.get(moduleId);
      if (moduleNode !== undefined) addRelation(
        sites, edges, moduleNode.id, outputNode.id, "emits", output.file_name,
        condition(), evidence, input.provenance.profile_id,
      );
      const observedModuleValue = build.modules.find((module) => module.module_id === moduleId);
      if (observedModuleValue?.source_path === null || observedModuleValue?.source_path === undefined) continue;
      for (const route of observation.routes.filter((candidate) => (
        candidate.source_path === observedModuleValue.source_path
        || candidate.lazy_source_path === observedModuleValue.source_path
      ))) {
        addRelation(
          sites, edges, routeNodes.get(route.route_id)!.id, outputNode.id, "emits", output.file_name,
          condition({ "tanstack.router.route": route.full_path }), evidence, input.provenance.profile_id,
        );
      }
    }
  }
  for (const module of build.modules) {
    const source = moduleNodes.get(module.module_id)!;
    for (const [kind, targets] of [["imports", module.imported_ids], ["dynamic_imports", module.dynamic_imported_ids]] as const) {
      for (const targetId of targets) {
        const target = moduleNodes.get(targetId);
        if (target !== undefined) addRelation(
          sites, edges, source.id, target.id, kind, targetId,
          condition(), manifestEvidence, input.provenance.profile_id,
        );
      }
    }
  }
  for (const output of build.outputs) {
    const source = outputNodes.get(output.file_name)!;
    for (const targetName of output.imported_outputs) {
      const target = outputNodes.get(targetName);
      if (target !== undefined) addRelation(
        sites, edges, source.id, target.id, "loads", targetName,
        condition(), buildEvidence(input.provenance, targetName, target.properties.artifact_digest as string),
        input.provenance.profile_id,
      );
    }
  }

  const candidate = {
    routerVersion: observation.router_version,
    viteVersions: [build.vite_version],
    nodes: [...nodes.values()].sort((left, right) => compareUtf8(left.id, right.id)),
    sites: uniqueById(sites, "web.tanstack_router_build_site_conflict"),
    edges: uniqueById(edges, "web.tanstack_router_build_edge_conflict"),
    diagnostics: uniqueById(diagnostics, "web.tanstack_router_build_diagnostic_conflict"),
  };
  let delta: TanStackRouterBuildGraphDelta;
  try {
    delta = {
      routerVersion: candidate.routerVersion,
      viteVersions: candidate.viteVersions,
      ...reconcileFrameworkBuildBaseRecords(
        candidate,
        TANSTACK_ROUTER_FRAMEWORK_BUILD_DESCRIPTOR,
        input.provenance,
        input.baseNodes,
        input.baseEdges ?? [],
        input.baseDiagnosticIds,
      ),
    };
    validateFrameworkBuildDelta(
      delta,
      TANSTACK_ROUTER_FRAMEWORK_BUILD_DESCRIPTOR,
      input.provenance,
      input.baseNodes,
    );
  } catch {
    fail("web.tanstack_router_build_graph_contract_invalid");
  }
  return delta;
}

export function tanStackRouterBuildProtocolEvents(
  root: string,
  delta: TanStackRouterBuildGraphDelta,
  provenance: TanStackRouterBuildProvenance,
  sourceRevision: string,
): ProtocolEvent[] {
  return frameworkBuildProtocolEvents(
    root,
    delta,
    provenance,
    sourceRevision,
    TANSTACK_ROUTER_FRAMEWORK_BUILD_DESCRIPTOR,
    {
      toolchain: `@tanstack/react-router ${delta.routerVersion}`,
      command: "vite build",
      properties: {
        tanstack_router_version: delta.routerVersion,
        vite_versions: delta.viteVersions,
      },
    },
  );
}
