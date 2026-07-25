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

export const TANSTACK_START_BUILD_OBSERVER = "tanstack-start-vite-build-observer" as const;
export const TANSTACK_START_BUILD_OBSERVER_VERSION = "0.2.0" as const;
export const TANSTACK_START_BUILD_CAPABILITY = "tanstack-start-v1-vite-v7-production-rpc-manifest-v2" as const;
export const TANSTACK_START_BUILD_SCHEMA = "tanstack-start-build-observation-v2" as const;
export const TANSTACK_START_FRAMEWORK_BUILD_DESCRIPTOR: FrameworkBuildDescriptor = Object.freeze({
  framework: "tanstack-start",
  observer: TANSTACK_START_BUILD_OBSERVER,
  observerVersion: TANSTACK_START_BUILD_OBSERVER_VERSION,
  capability: TANSTACK_START_BUILD_CAPABILITY,
});

const MAX_SAFE_STRING = 4_096;
const MAX_RPC_ID = 512;
const MAX_MODULES = 100_000;
const MAX_IMPORTS = 20_000;
const MAX_OUTPUTS = 100_000;
const MAX_PLUGINS = 20_000;
const DEFAULT_TIMEOUT_MS = 10_000;
const MAX_TIMEOUT_MS = 60_000;
const PROVIDER_QUERY = "tss-serverfn-split";
const RESOLVER_MARKERS = ["server-fn-resolver", "server-fn-module-lookup"] as const;

type UnknownRecord = Record<string, unknown>;
type Awaitable<T> = T | Promise<T>;
export type TanStackBuildEnvironment = "client" | "ssr" | "server";
type ModuleKind = "project" | "virtual" | "external";

export interface TanStackStartBuildProvenance {
  build_run_id: string;
  profile_id: string;
  command_plan_digest: string;
  toolchain_executable_digest: string;
  environment_key_set_digest: string;
  validated_output_digest: string;
}

export interface TanStackStartObservationSink {
  write(observation: TanStackStartBuildObservation): Awaitable<void>;
}

export interface TanStackStartObserverOptions {
  startVersion: string;
  repoRoot: string;
  sink: TanStackStartObservationSink;
  providerEnvironmentName?: string;
  existingVitePlugins?: readonly unknown[];
  timeoutMs?: number;
}

export interface TanStackStartCapability {
  capability: typeof TANSTACK_START_BUILD_CAPABILITY;
  start_version: string;
  provider_environment_name: string;
  existing_vite_plugin_count: number;
}

export interface TanStackVitePluginLike {
  name: string;
  apply: "build";
  enforce: "post";
  configResolved(config: UnknownRecord): void;
  buildStart(this: UnknownRecord): void;
  transform(this: UnknownRecord, code: string, id: string): null;
  generateBundle(this: UnknownRecord, outputOptions: unknown, bundle: UnknownRecord): void;
  buildEnd(this: UnknownRecord, error?: unknown): void;
  closeBundle(this: UnknownRecord): Awaitable<void>;
}

export interface TanStackObservedConfig {
  mode: string;
  base: string;
  plugin_count: number;
  observer_plugin_index: number;
  tanstack_plugin_count: number;
}

export interface TanStackObservedModule {
  module_id: string;
  source_path: string | null;
  module_kind: ModuleKind;
  environment: TanStackBuildEnvironment;
  is_entry: boolean;
  imported_ids: string[];
  dynamic_imported_ids: string[];
}

export interface TanStackObservedOutput {
  file_name: string;
  kind: "chunk" | "asset";
  digest: string;
  environment: TanStackBuildEnvironment;
  entry: boolean;
  module_ids: string[];
  imported_outputs: string[];
}

export interface TanStackObservedBuild {
  vite_environment: string;
  vite_version: string;
  config: TanStackObservedConfig;
  modules: TanStackObservedModule[];
  outputs: TanStackObservedOutput[];
}

export interface TanStackObservedServerFunction {
  production_rpc_id: string;
  source_path: string;
  export_name: string;
  provider_module_id: string;
  collision_suffix: number | null;
  collision_suffix_status: "not-separately-observed";
  client_referenced: boolean;
  ssr_referenced: boolean;
}

export interface TanStackObservedStub {
  production_rpc_id: string;
  source_module_id: string;
  source_path: string | null;
  environment: "client" | "ssr";
}

export interface TanStackObservedRpcManifestEntry {
  production_rpc_id: string;
  handler_export_name: string;
  provider_module_id: string;
  client_referenced: boolean | null;
}

export interface TanStackObservedRpcManifest {
  resolver_module_id: string;
  resolver_environment: string;
  entry_count: number;
  entries_digest: string;
  entries: TanStackObservedRpcManifestEntry[];
}

export interface TanStackStartBuildObservation {
  schema_version: typeof TANSTACK_START_BUILD_SCHEMA;
  observer: typeof TANSTACK_START_BUILD_OBSERVER;
  observer_version: typeof TANSTACK_START_BUILD_OBSERVER_VERSION;
  capability: typeof TANSTACK_START_BUILD_CAPABILITY;
  start_version: string;
  provider_environment_name: string;
  resolver_virtual_module_observed: boolean;
  production_rpc_manifest: TanStackObservedRpcManifest;
  builds: TanStackObservedBuild[];
  server_functions: TanStackObservedServerFunction[];
  stubs: TanStackObservedStub[];
}

export interface TanStackStartBuildGraphInput {
  observation: TanStackStartBuildObservation;
  provenance: TanStackStartBuildProvenance;
  baseNodes: readonly GraphNode[];
  baseEdges?: readonly GraphEdge[];
  baseDiagnosticIds?: readonly string[];
}

export interface TanStackStartBuildGraphDelta {
  startVersion: string;
  viteVersions: string[];
  productionRpcManifestEntryCount: number;
  productionRpcManifestDigest: string;
  nodes: GraphNode[];
  sites: DependencySite[];
  edges: GraphEdge[];
  diagnostics: Diagnostic[];
}

export class TanStackStartBuildObserverError extends Error {
  readonly code: string;

  constructor(code: string) {
    super(code);
    this.name = "TanStackStartBuildObserverError";
    this.code = code;
  }
}

function fail(code: string): never {
  throw new TanStackStartBuildObserverError(code);
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

function boundedString(value: unknown, max = MAX_SAFE_STRING): string | null {
  if (typeof value !== "string" || value.length === 0 || value.length > max) return null;
  if ([...value].some((character) => character.charCodeAt(0) < 0x20 || character.charCodeAt(0) === 0x7f)) return null;
  return value;
}

function boundedModuleString(value: unknown): string | null {
  if (typeof value !== "string" || value.length === 0 || value.length > MAX_SAFE_STRING) return null;
  const checked = value.startsWith("\0") ? value.slice(1) : value;
  return boundedString(checked) === null ? null : value;
}

function stableVersion(value: unknown, allowedMajors: ReadonlySet<number>, code: string): string {
  const raw = boundedString(value);
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
  if (normalized === "." || normalized === ".." || normalized.startsWith("../") || normalized.includes("/../")) return null;
  return normalized;
}

function outputPath(value: unknown): string {
  const result = canonicalRelativePath(value);
  if (result === null) fail("web.tanstack_start_build_output_path_unsafe");
  return result;
}

function pluginName(value: unknown, code: string): string {
  const name = boundedString(record(value)?.name);
  if (name === null) fail(code);
  return name;
}

function validatePluginNames(values: readonly unknown[]): string[] {
  if (values.length > MAX_PLUGINS) fail("web.tanstack_start_build_plugin_chain_invalid");
  const names = values.map((value) => pluginName(value, "web.tanstack_start_build_plugin_chain_invalid"));
  if (new Set(names).size !== names.length || names.includes(TANSTACK_START_BUILD_OBSERVER)) {
    fail("web.tanstack_start_build_plugin_chain_invalid");
  }
  return names;
}

function providerEnvironmentName(value: string | undefined): string {
  const name = value ?? "ssr";
  if (boundedString(name, 128) === null || !/^[a-z][a-z0-9_-]*$/u.test(name) || name === "client") {
    fail("web.tanstack_start_build_provider_environment_invalid");
  }
  return name;
}

export function detectTanStackStartBuildCapability(
  startVersion: string,
  providerEnvironment: string | undefined = undefined,
  existingVitePlugins: readonly unknown[] = [],
): TanStackStartCapability {
  const version = stableVersion(startVersion, new Set([1]), "web.tanstack_start_build_version_unsupported");
  const provider = providerEnvironmentName(providerEnvironment);
  validatePluginNames(existingVitePlugins);
  return {
    capability: TANSTACK_START_BUILD_CAPABILITY,
    start_version: version,
    provider_environment_name: provider,
    existing_vite_plugin_count: existingVitePlugins.length,
  };
}

interface LogicalModule {
  module_id: string;
  source_path: string | null;
  module_kind: ModuleKind;
  environment: TanStackBuildEnvironment;
}

function moduleRole(raw: string, viteEnvironment: string, providerEnvironment: string): TanStackBuildEnvironment {
  if (raw.includes(PROVIDER_QUERY)) return "server";
  if (viteEnvironment === "client") return "client";
  return viteEnvironment === providerEnvironment && providerEnvironment !== "ssr" ? "server" : "ssr";
}

function logicalModule(rawValue: unknown, repoRoot: string, viteEnvironment: string, providerEnvironment: string): LogicalModule {
  const raw = boundedModuleString(rawValue);
  if (raw === null) fail("web.tanstack_start_build_module_id_unsafe");
  const role = moduleRole(raw, viteEnvironment, providerEnvironment);
  if (raw.startsWith("\0") || raw.startsWith("virtual:")) {
    return { module_id: `virtual:${sha256(raw)}`, source_path: null, module_kind: "virtual", environment: role };
  }
  const [rawPath, rawQuery = ""] = raw.split(/[?#]/u, 2);
  let absolute = rawPath!;
  if (absolute.startsWith("file://")) {
    try {
      absolute = fileURLToPath(absolute);
    } catch {
      fail("web.tanstack_start_build_module_id_unsafe");
    }
  }
  if (!path.isAbsolute(absolute)) {
    return { module_id: `external:${sha256(raw)}`, source_path: null, module_kind: "external", environment: role };
  }
  const relative = path.relative(path.resolve(repoRoot), path.resolve(absolute));
  const sourcePath = relative === "" || relative.startsWith("..") || path.isAbsolute(relative)
    ? null
    : canonicalRelativePath(relative);
  if (sourcePath === null) {
    return { module_id: `external:${sha256(raw)}`, source_path: null, module_kind: "external", environment: role };
  }
  const suffix = rawQuery === ""
    ? ""
    : rawQuery.includes(PROVIDER_QUERY)
      ? "#server-provider"
      : `#query:${sha256(rawQuery)}`;
  return { module_id: `${sourcePath}${suffix}`, source_path: sourcePath, module_kind: "project", environment: role };
}

function timeoutValue(value: number | undefined): number {
  const timeout = value ?? DEFAULT_TIMEOUT_MS;
  if (!Number.isSafeInteger(timeout) || timeout <= 0 || timeout > MAX_TIMEOUT_MS) {
    fail("web.tanstack_start_build_timeout_invalid");
  }
  return timeout;
}

async function bounded<T>(code: string, timeout: number, operation: () => Awaitable<T>): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      Promise.resolve().then(operation).catch((error: unknown) => {
        if (error instanceof TanStackStartBuildObserverError) throw error;
        fail(code);
      }),
      new Promise<T>((_resolve, reject) => {
        timer = setTimeout(() => reject(new TanStackStartBuildObserverError("web.tanstack_start_build_observer_timeout")), timeout);
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
    if (error instanceof TanStackStartBuildObserverError) throw error;
    fail(code);
  }
}

function environmentName(context: UnknownRecord): string {
  const name = boundedString(record(context.environment)?.name, 128);
  if (name === null) fail("web.tanstack_start_build_environment_unavailable");
  return name;
}

function contextMethod(context: UnknownRecord, name: string): ((...args: unknown[]) => unknown) | null {
  const method = context[name];
  return typeof method === "function" ? method.bind(context) as (...args: unknown[]) => unknown : null;
}

function stringArray(value: unknown, sanitizer: (value: unknown) => string, code: string): string[] {
  if (!Array.isArray(value) || value.length > MAX_IMPORTS) fail(code);
  return [...new Set(value.map(sanitizer))].sort(compareUtf8);
}

function jsString(raw: string): string {
  const quote = raw[0];
  if ((quote !== '"' && quote !== "'") || raw.at(-1) !== quote) {
    fail("web.tanstack_start_build_rpc_metadata_invalid");
  }
  if (quote === '"') {
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch {
      fail("web.tanstack_start_build_rpc_metadata_invalid");
    }
    const value = boundedString(parsed, MAX_RPC_ID);
    if (value === null) fail("web.tanstack_start_build_rpc_metadata_invalid");
    return value;
  }
  let value = "";
  for (let index = 1; index < raw.length - 1; index += 1) {
    const character = raw[index]!;
    if (character !== "\\") {
      value += character;
      continue;
    }
    const escaped = raw[++index];
    if (escaped === undefined) fail("web.tanstack_start_build_rpc_metadata_invalid");
    const simple = new Map([
      ["'", "'"], ['"', '"'], ["\\", "\\"], ["b", "\b"], ["f", "\f"],
      ["n", "\n"], ["r", "\r"], ["t", "\t"], ["v", "\v"], ["0", "\0"],
    ]).get(escaped);
    if (simple !== undefined) {
      value += simple;
      continue;
    }
    const width = escaped === "x" ? 2 : escaped === "u" ? 4 : 0;
    const digits = width === 0 ? "" : raw.slice(index + 1, index + 1 + width);
    if (width === 0 || !new RegExp(`^[a-f0-9]{${width}}$`, "iu").test(digits)) {
      fail("web.tanstack_start_build_rpc_metadata_invalid");
    }
    value += String.fromCharCode(Number.parseInt(digits, 16));
    index += width;
  }
  const bounded = boundedString(value, MAX_RPC_ID);
  if (bounded === null) fail("web.tanstack_start_build_rpc_metadata_invalid");
  return bounded;
}

const JS_STRING_PATTERN = `(?:"(?:\\\\.|[^"\\\\])*"|'(?:\\\\.|[^'\\\\])*')`;

function requiresRuntimeImport(
  code: string,
  symbol: "createClientRpc" | "createSsrRpc" | "createServerRpc",
  runtime: "client-rpc" | "ssr-rpc" | "server-rpc",
): void {
  const expression = new RegExp(
    `\\bimport\\s*\\{[^}]*\\b${symbol}\\b[^}]*\\}\\s*from\\s*["']@tanstack/(?:react|solid|vue)-start/${runtime}["']`,
    "u",
  );
  if (!expression.test(code)) fail("web.tanstack_start_build_rpc_runtime_import_missing");
}

function callStrings(code: string, functionName: "createClientRpc" | "createSsrRpc"): string[] {
  const expression = new RegExp(`\\b${functionName}\\s*\\(\\s*(${JS_STRING_PATTERN})`, "gu");
  const values: string[] = [];
  for (const match of code.matchAll(expression)) values.push(jsString(match[1]!));
  if (values.length > 0) {
    requiresRuntimeImport(code, functionName, functionName === "createClientRpc" ? "client-rpc" : "ssr-rpc");
  }
  return [...new Set(values)].sort(compareUtf8);
}

interface ProviderCall {
  id: string;
  name: string;
  filename: string;
}

function providerCalls(code: string): ProviderCall[] {
  const expression = new RegExp(
    `\\bcreateServerRpc\\s*\\(\\s*\\{\\s*(?:["']?id["']?)\\s*:\\s*(${JS_STRING_PATTERN})\\s*,\\s*(?:["']?name["']?)\\s*:\\s*(${JS_STRING_PATTERN})\\s*,\\s*(?:["']?filename["']?)\\s*:\\s*(${JS_STRING_PATTERN})`,
    "gu",
  );
  const calls = [...code.matchAll(expression)].map((match) => ({
    id: jsString(match[1]!),
    name: jsString(match[2]!),
    filename: jsString(match[3]!),
  }));
  if (calls.length > 0) requiresRuntimeImport(code, "createServerRpc", "server-rpc");
  return calls.sort((left, right) => compareUtf8(left.id, right.id));
}

function resolverManifestEntries(
  code: string,
  state: MutableState,
  viteEnvironment: string,
): TanStackObservedRpcManifestEntry[] {
  const expression = new RegExp(
    `(${JS_STRING_PATTERN})\\s*:\\s*\\{\\s*functionName\\s*:\\s*(${JS_STRING_PATTERN})\\s*,\\s*`
      + `importer\\s*:\\s*\\(\\s*\\)\\s*=>\\s*import\\(\\s*(${JS_STRING_PATTERN})\\s*\\)`
      + `(?:\\s*,\\s*isClientReferenced\\s*:\\s*(true|false))?\\s*\\}`,
    "gu",
  );
  const entries = [...code.matchAll(expression)].map((match) => ({
    production_rpc_id: jsString(match[1]!),
    handler_export_name: jsString(match[2]!),
    provider_module_id: logicalModule(
      jsString(match[3]!),
      state.repoRoot,
      viteEnvironment,
      state.capability.provider_environment_name,
    ).module_id,
    client_referenced: match[4] === undefined ? null : match[4] === "true",
  })).sort((left, right) => compareUtf8(left.production_rpc_id, right.production_rpc_id));
  const declaredEntryCount = [...code.matchAll(/\bfunctionName\s*:/gu)].length;
  if (!/\bconst\s+manifest\s*=\s*\{/u.test(code) || entries.length !== declaredEntryCount) {
    fail("web.tanstack_start_build_rpc_manifest_invalid");
  }
  const ids = entries.map((entry) => entry.production_rpc_id);
  if (new Set(ids).size !== ids.length) fail("web.tanstack_start_build_rpc_manifest_collision");
  return entries;
}

interface MutableState {
  readonly capability: TanStackStartCapability;
  readonly repoRoot: string;
  readonly sink: TanStackStartObservationSink;
  readonly timeoutMs: number;
  readonly expectedPluginNames: string[];
  readonly completedViteEnvironments: Set<string>;
  readonly failedViteEnvironments: Set<string>;
  readonly builds: Map<string, TanStackObservedBuild>;
  readonly serverFunctions: Map<string, TanStackObservedServerFunction>;
  readonly stubs: Map<string, TanStackObservedStub>;
  readonly resolverModules: Map<string, LogicalModule>;
  rpcManifest: TanStackObservedRpcManifest | null;
  resolverObserved: boolean;
  writing: boolean;
  wrote: boolean;
}

function validateFinalPluginChain(config: UnknownRecord, state: MutableState): TanStackObservedConfig {
  const plugins = config.plugins;
  if (!Array.isArray(plugins) || plugins.length > MAX_PLUGINS) {
    fail("web.tanstack_start_build_plugin_chain_invalid");
  }
  const names = plugins.map((value) => pluginName(value, "web.tanstack_start_build_plugin_chain_invalid"));
  const ownIndexes = names.flatMap((name, index) => name === TANSTACK_START_BUILD_OBSERVER ? [index] : []);
  if (ownIndexes.length !== 1) fail("web.tanstack_start_build_plugin_chain_invalid");
  const observerIndex = ownIndexes[0]!;
  let previous = -1;
  for (const expected of state.expectedPluginNames) {
    const indexes = names.flatMap((name, index) => name === expected ? [index] : []);
    if (indexes.length !== 1 || indexes[0]! <= previous || indexes[0]! >= observerIndex) {
      fail("web.tanstack_start_build_plugin_chain_invalid");
    }
    previous = indexes[0]!;
  }
  const tanstackIndexes = names.flatMap((name, index) => name === "tanstack-start-core:config" ? [index] : []);
  if (tanstackIndexes.length !== 1 || tanstackIndexes[0]! >= observerIndex) {
    fail("web.tanstack_start_build_internal_contract_unavailable");
  }
  const baseValue = config.base;
  const base = baseValue === undefined || baseValue === "/"
    ? ""
    : (() => {
      const value = boundedString(baseValue);
      if (value === null || !value.startsWith("/") || value.includes("\\") || value.includes("?") || value.includes("#")) {
        fail("web.tanstack_start_build_config_unsafe");
      }
      return value.length > 1 ? value.replace(/\/$/u, "") : "";
    })();
  const mode = boundedString(config.mode) ?? "production";
  if (mode !== "production") fail("web.tanstack_start_build_mode_unsupported");
  return {
    mode,
    base,
    plugin_count: names.length,
    observer_plugin_index: observerIndex,
    tanstack_plugin_count: names.filter((name) => name.startsWith("tanstack-start-core:")).length,
  };
}

function observedModule(
  id: unknown,
  infoValue: unknown,
  state: MutableState,
  viteEnvironment: string,
): TanStackObservedModule {
  const logical = logicalModule(id, state.repoRoot, viteEnvironment, state.capability.provider_environment_name);
  const info = record(infoValue);
  if (info === null) fail("web.tanstack_start_build_module_info_invalid");
  const toId = (value: unknown): string => logicalModule(
    value, state.repoRoot, viteEnvironment, state.capability.provider_environment_name,
  ).module_id;
  return {
    ...logical,
    is_entry: info.isEntry === true,
    imported_ids: stringArray(info.importedIds ?? [], toId, "web.tanstack_start_build_module_imports_invalid"),
    dynamic_imported_ids: stringArray(
      info.dynamicallyImportedIds ?? [], toId, "web.tanstack_start_build_module_imports_invalid",
    ),
  };
}

function mergeModules(modules: readonly TanStackObservedModule[]): TanStackObservedModule[] {
  const result = new Map<string, TanStackObservedModule>();
  for (const module of modules) {
    const previous = result.get(module.module_id);
    if (previous !== undefined && (previous.environment !== module.environment
      || previous.source_path !== module.source_path || previous.module_kind !== module.module_kind)) {
      fail("web.tanstack_start_build_module_identity_conflict");
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
  moduleById: ReadonlyMap<string, TanStackObservedModule>,
  state: MutableState,
  viteEnvironment: string,
): TanStackObservedOutput {
  const output = record(value);
  if (output === null) fail("web.tanstack_start_build_output_contract_invalid");
  const fileName = outputPath(output.fileName);
  if (output.type === "asset") {
    const environment: TanStackBuildEnvironment = viteEnvironment === "client"
      ? "client"
      : viteEnvironment === state.capability.provider_environment_name
          && state.capability.provider_environment_name !== "ssr"
        ? "server"
        : "ssr";
    return {
      file_name: fileName,
      kind: "asset",
      digest: bytesDigest(output.source, "web.tanstack_start_build_asset_source_invalid"),
      environment,
      entry: false,
      module_ids: [],
      imported_outputs: [],
    };
  }
  if (output.type !== "chunk") fail("web.tanstack_start_build_output_contract_invalid");
  const rawModules = record(output.modules);
  if (rawModules === null || Object.keys(rawModules).length > MAX_MODULES) {
    fail("web.tanstack_start_build_chunk_modules_invalid");
  }
  const moduleIds = Object.keys(rawModules).map((id) => logicalModule(
    id, state.repoRoot, viteEnvironment, state.capability.provider_environment_name,
  ).module_id).sort(compareUtf8);
  const roles = new Set(moduleIds.map((id) => moduleById.get(id)?.environment).filter((role): role is TanStackBuildEnvironment => role !== undefined));
  const environment: TanStackBuildEnvironment = roles.has("server")
    ? "server"
    : roles.has("client")
      ? "client"
      : "ssr";
  return {
    file_name: fileName,
    kind: "chunk",
    digest: bytesDigest(output.code, "web.tanstack_start_build_chunk_code_invalid"),
    environment,
    entry: output.isEntry === true,
    module_ids: [...new Set(moduleIds)],
    imported_outputs: stringArray(
      [...(Array.isArray(output.imports) ? output.imports : []), ...(Array.isArray(output.dynamicImports) ? output.dynamicImports : [])],
      outputPath,
      "web.tanstack_start_build_chunk_imports_invalid",
    ),
  };
}

function upsertServerFunction(state: MutableState, call: ProviderCall, module: LogicalModule): void {
  const sourcePath = canonicalRelativePath(call.filename);
  if (sourcePath === null || module.environment !== "server") {
    fail("web.tanstack_start_build_provider_metadata_invalid");
  }
  const value: TanStackObservedServerFunction = {
    production_rpc_id: call.id,
    source_path: sourcePath,
    export_name: call.name,
    provider_module_id: module.module_id,
    collision_suffix: null,
    collision_suffix_status: "not-separately-observed",
    client_referenced: false,
    ssr_referenced: false,
  };
  const previous = state.serverFunctions.get(call.id);
  if (previous !== undefined && (previous.source_path !== value.source_path
    || previous.export_name !== value.export_name || previous.provider_module_id !== value.provider_module_id)) {
    fail("web.tanstack_start_build_rpc_id_conflict");
  }
  state.serverFunctions.set(call.id, previous === undefined ? value : {
    ...value,
    client_referenced: previous.client_referenced,
    ssr_referenced: previous.ssr_referenced,
  });
}

function upsertStub(
  state: MutableState,
  rpcId: string,
  module: LogicalModule,
  environment: "client" | "ssr",
): void {
  const value: TanStackObservedStub = {
    production_rpc_id: rpcId,
    source_module_id: module.module_id,
    source_path: module.source_path,
    environment,
  };
  state.stubs.set(digestIdentity(value as unknown as JsonValue), value);
}

function updateReferences(state: MutableState): void {
  const client = new Set([...state.stubs.values()].filter((stub) => stub.environment === "client").map((stub) => stub.production_rpc_id));
  const ssr = new Set([...state.stubs.values()].filter((stub) => stub.environment === "ssr").map((stub) => stub.production_rpc_id));
  for (const [id, value] of state.serverFunctions) {
    state.serverFunctions.set(id, { ...value, client_referenced: client.has(id), ssr_referenced: ssr.has(id) });
  }
}

function requiredViteEnvironments(state: MutableState): Set<string> {
  return new Set(["client", "ssr", state.capability.provider_environment_name]);
}

function finalObservation(state: MutableState): TanStackStartBuildObservation {
  const required = requiredViteEnvironments(state);
  for (const environment of required) {
    if (!state.completedViteEnvironments.has(environment) || state.failedViteEnvironments.has(environment)
      || !state.builds.has(environment)) {
      fail("web.tanstack_start_build_environment_observation_incomplete");
    }
  }
  if (!state.resolverObserved) fail("web.tanstack_start_build_virtual_module_missing");
  const manifest = state.rpcManifest;
  if (manifest === null) fail("web.tanstack_start_build_rpc_manifest_missing");
  updateReferences(state);
  const functions = [...state.serverFunctions.values()].sort((left, right) => compareUtf8(left.production_rpc_id, right.production_rpc_id));
  const functionsById = new Map(functions.map((fn) => [fn.production_rpc_id, fn]));
  if (manifest.entries.length !== functions.length) fail("web.tanstack_start_build_rpc_manifest_provider_mismatch");
  for (const entry of manifest.entries) {
    const fn = functionsById.get(entry.production_rpc_id);
    if (fn === undefined || entry.handler_export_name !== `${fn.export_name}_createServerFn_handler`
      || entry.provider_module_id !== fn.provider_module_id
      || (entry.client_referenced !== null && entry.client_referenced !== fn.client_referenced)) {
      fail("web.tanstack_start_build_rpc_manifest_provider_mismatch");
    }
  }
  for (const stub of state.stubs.values()) {
    if (!functionsById.has(stub.production_rpc_id)) fail("web.tanstack_start_build_stub_target_missing");
  }
  return validateTanStackStartBuildObservation({
    schema_version: TANSTACK_START_BUILD_SCHEMA,
    observer: TANSTACK_START_BUILD_OBSERVER,
    observer_version: TANSTACK_START_BUILD_OBSERVER_VERSION,
    capability: TANSTACK_START_BUILD_CAPABILITY,
    start_version: state.capability.start_version,
    provider_environment_name: state.capability.provider_environment_name,
    resolver_virtual_module_observed: true,
    production_rpc_manifest: manifest,
    builds: [...state.builds.values()].sort((left, right) => compareUtf8(left.vite_environment, right.vite_environment)),
    server_functions: functions,
    stubs: [...state.stubs.values()].sort((left, right) => (
      compareUtf8(left.production_rpc_id, right.production_rpc_id)
      || compareUtf8(left.environment, right.environment)
      || compareUtf8(left.source_module_id, right.source_module_id)
    )),
  });
}

function strictRecord(value: unknown, keys: readonly string[], code: string): UnknownRecord {
  const result = record(value);
  if (result === null) fail(code);
  const actual = Object.keys(result).sort(compareUtf8);
  const expected = [...keys].sort(compareUtf8);
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) fail(code);
  return result;
}

function integer(value: unknown, minimum: number, maximum: number, code: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < minimum || (value as number) > maximum) fail(code);
  return value as number;
}

function booleanValue(value: unknown, code: string): boolean {
  if (typeof value !== "boolean") fail(code);
  return value;
}

function nullableBoolean(value: unknown, code: string): boolean | null {
  return value === null ? null : booleanValue(value, code);
}

function digest(value: unknown, code: string): string {
  const result = boundedString(value, 64);
  if (result === null || !/^[a-f0-9]{64}$/u.test(result)) fail(code);
  return result;
}

function canonicalStringList(
  value: unknown,
  sanitizer: (item: unknown) => string,
  maximum: number,
  code: string,
): string[] {
  if (!Array.isArray(value) || value.length > maximum) fail(code);
  const values = value.map(sanitizer);
  if (new Set(values).size !== values.length
    || values.some((item, index) => index > 0 && compareUtf8(values[index - 1]!, item) >= 0)) {
    fail(code);
  }
  return values;
}

function normalizedModuleId(value: unknown, code: string): string {
  const result = boundedString(value);
  if (result === null) fail(code);
  if (result.startsWith("virtual:") || result.startsWith("external:")) {
    if (!/^(?:virtual|external):[a-f0-9]{64}$/u.test(result)) fail(code);
    return result;
  }
  const [source, suffix] = result.split("#", 2);
  if (canonicalRelativePath(source) !== source) fail(code);
  if (suffix !== undefined && suffix !== "server-provider" && !/^query:[a-f0-9]{64}$/u.test(suffix)) fail(code);
  return result;
}

function moduleEnvironment(value: unknown, code: string): TanStackBuildEnvironment {
  if (value !== "client" && value !== "ssr" && value !== "server") fail(code);
  return value;
}

function validateObservedConfig(value: unknown): TanStackObservedConfig {
  const code = "web.tanstack_start_build_observation_config_invalid";
  const item = strictRecord(value, [
    "mode", "base", "plugin_count", "observer_plugin_index", "tanstack_plugin_count",
  ], code);
  const base = item.base === "" ? "" : boundedString(item.base);
  if (item.mode !== "production" || base === null || (base !== "" && (!base.startsWith("/")
    || base.endsWith("/") || base.includes("\\") || base.includes("?") || base.includes("#")))) fail(code);
  const pluginCount = integer(item.plugin_count, 1, MAX_PLUGINS, code);
  const observerIndex = integer(item.observer_plugin_index, 0, pluginCount - 1, code);
  return {
    mode: "production",
    base,
    plugin_count: pluginCount,
    observer_plugin_index: observerIndex,
    tanstack_plugin_count: integer(item.tanstack_plugin_count, 1, pluginCount, code),
  };
}

function validateObservedModule(value: unknown): TanStackObservedModule {
  const code = "web.tanstack_start_build_observation_module_invalid";
  const item = strictRecord(value, [
    "module_id", "source_path", "module_kind", "environment", "is_entry", "imported_ids", "dynamic_imported_ids",
  ], code);
  const moduleId = normalizedModuleId(item.module_id, code);
  if (item.module_kind !== "project" && item.module_kind !== "virtual" && item.module_kind !== "external") fail(code);
  const sourcePath = item.source_path === null ? null : canonicalRelativePath(item.source_path);
  if ((item.module_kind === "project") !== (sourcePath !== null)
    || (item.module_kind === "project" && !moduleId.startsWith(sourcePath!))
    || (item.module_kind === "virtual" && !moduleId.startsWith("virtual:"))
    || (item.module_kind === "external" && !moduleId.startsWith("external:"))) fail(code);
  return {
    module_id: moduleId,
    source_path: sourcePath,
    module_kind: item.module_kind,
    environment: moduleEnvironment(item.environment, code),
    is_entry: booleanValue(item.is_entry, code),
    imported_ids: canonicalStringList(item.imported_ids, (entry) => normalizedModuleId(entry, code), MAX_IMPORTS, code),
    dynamic_imported_ids: canonicalStringList(
      item.dynamic_imported_ids, (entry) => normalizedModuleId(entry, code), MAX_IMPORTS, code,
    ),
  };
}

function validateObservedOutput(value: unknown): TanStackObservedOutput {
  const code = "web.tanstack_start_build_observation_output_invalid";
  const item = strictRecord(value, [
    "file_name", "kind", "digest", "environment", "entry", "module_ids", "imported_outputs",
  ], code);
  if (item.kind !== "chunk" && item.kind !== "asset") fail(code);
  const moduleIds = canonicalStringList(
    item.module_ids, (entry) => normalizedModuleId(entry, code), MAX_MODULES, code,
  );
  if (item.kind === "asset" && moduleIds.length !== 0) fail(code);
  return {
    file_name: outputPath(item.file_name),
    kind: item.kind,
    digest: digest(item.digest, code),
    environment: moduleEnvironment(item.environment, code),
    entry: booleanValue(item.entry, code),
    module_ids: moduleIds,
    imported_outputs: canonicalStringList(item.imported_outputs, outputPath, MAX_OUTPUTS, code),
  };
}

function validateObservedBuild(value: unknown): TanStackObservedBuild {
  const code = "web.tanstack_start_build_observation_build_invalid";
  const item = strictRecord(value, ["vite_environment", "vite_version", "config", "modules", "outputs"], code);
  const viteEnvironment = boundedString(item.vite_environment, 128);
  if (viteEnvironment === null || !/^[a-z][a-z0-9_-]*$/u.test(viteEnvironment)) fail(code);
  if (!Array.isArray(item.modules) || item.modules.length > MAX_MODULES
    || !Array.isArray(item.outputs) || item.outputs.length > MAX_OUTPUTS) fail(code);
  const modules = item.modules.map(validateObservedModule);
  const outputs = item.outputs.map(validateObservedOutput);
  if (modules.some((entry, index) => index > 0 && compareUtf8(modules[index - 1]!.module_id, entry.module_id) >= 0)
    || outputs.some((entry, index) => index > 0 && compareUtf8(outputs[index - 1]!.file_name, entry.file_name) >= 0)) {
    fail(code);
  }
  const moduleIds = new Set(modules.map((entry) => entry.module_id));
  const outputNames = new Set(outputs.map((entry) => entry.file_name));
  for (const output of outputs) {
    if (output.module_ids.some((moduleId) => !moduleIds.has(moduleId))
      || output.imported_outputs.some((name) => !outputNames.has(name))) fail(code);
  }
  return {
    vite_environment: viteEnvironment,
    vite_version: stableVersion(item.vite_version, new Set([7]), "web.tanstack_start_build_vite_version_unsupported"),
    config: validateObservedConfig(item.config),
    modules,
    outputs,
  };
}

function validateObservedServerFunction(value: unknown): TanStackObservedServerFunction {
  const code = "web.tanstack_start_build_observation_server_function_invalid";
  const item = strictRecord(value, [
    "production_rpc_id", "source_path", "export_name", "provider_module_id", "collision_suffix",
    "collision_suffix_status",
    "client_referenced", "ssr_referenced",
  ], code);
  const productionRpcId = boundedString(item.production_rpc_id, MAX_RPC_ID);
  const source = canonicalRelativePath(item.source_path);
  const exportName = boundedString(item.export_name);
  if (productionRpcId === null || source === null || exportName === null) fail(code);
  if (item.collision_suffix !== null || item.collision_suffix_status !== "not-separately-observed") fail(code);
  return {
    production_rpc_id: productionRpcId,
    source_path: source,
    export_name: exportName,
    provider_module_id: normalizedModuleId(item.provider_module_id, code),
    collision_suffix: null,
    collision_suffix_status: "not-separately-observed",
    client_referenced: booleanValue(item.client_referenced, code),
    ssr_referenced: booleanValue(item.ssr_referenced, code),
  };
}

function validateObservedStub(value: unknown): TanStackObservedStub {
  const code = "web.tanstack_start_build_observation_stub_invalid";
  const item = strictRecord(value, [
    "production_rpc_id", "source_module_id", "source_path", "environment",
  ], code);
  const productionRpcId = boundedString(item.production_rpc_id, MAX_RPC_ID);
  if (productionRpcId === null || (item.environment !== "client" && item.environment !== "ssr")) fail(code);
  const sourcePath = item.source_path === null ? null : canonicalRelativePath(item.source_path);
  if (item.source_path !== null && sourcePath === null) fail(code);
  return {
    production_rpc_id: productionRpcId,
    source_module_id: normalizedModuleId(item.source_module_id, code),
    source_path: sourcePath,
    environment: item.environment,
  };
}

function validateRpcManifestEntry(value: unknown): TanStackObservedRpcManifestEntry {
  const code = "web.tanstack_start_build_rpc_manifest_invalid";
  const item = strictRecord(value, [
    "production_rpc_id", "handler_export_name", "provider_module_id", "client_referenced",
  ], code);
  const productionRpcId = boundedString(item.production_rpc_id, MAX_RPC_ID);
  const handlerExportName = boundedString(item.handler_export_name);
  if (productionRpcId === null || handlerExportName === null) fail(code);
  return {
    production_rpc_id: productionRpcId,
    handler_export_name: handlerExportName,
    provider_module_id: normalizedModuleId(item.provider_module_id, code),
    client_referenced: nullableBoolean(item.client_referenced, code),
  };
}

function validateRpcManifest(value: unknown): TanStackObservedRpcManifest {
  const code = "web.tanstack_start_build_rpc_manifest_invalid";
  const item = strictRecord(value, [
    "resolver_module_id", "resolver_environment", "entry_count", "entries_digest", "entries",
  ], code);
  if (!Array.isArray(item.entries) || item.entries.length > MAX_MODULES) fail(code);
  const entries = item.entries.map(validateRpcManifestEntry);
  if (entries.some((entry, index) => index > 0
    && compareUtf8(entries[index - 1]!.production_rpc_id, entry.production_rpc_id) >= 0)
    || integer(item.entry_count, 0, MAX_MODULES, code) !== entries.length
    || digest(item.entries_digest, code) !== digestIdentity(entries as unknown as JsonValue)) fail(code);
  const resolverModuleId = normalizedModuleId(item.resolver_module_id, code);
  const resolverEnvironment = boundedString(item.resolver_environment, 128);
  if (!resolverModuleId.startsWith("virtual:") || resolverEnvironment === null
    || !/^[a-z][a-z0-9_-]*$/u.test(resolverEnvironment)) fail(code);
  return {
    resolver_module_id: resolverModuleId,
    resolver_environment: resolverEnvironment,
    entry_count: entries.length,
    entries_digest: item.entries_digest as string,
    entries,
  };
}

export function validateTanStackStartBuildObservation(value: unknown): TanStackStartBuildObservation {
  const code = "web.tanstack_start_build_observation_contract_invalid";
  const item = strictRecord(value, [
    "schema_version", "observer", "observer_version", "capability", "start_version",
    "provider_environment_name", "resolver_virtual_module_observed", "production_rpc_manifest",
    "builds", "server_functions", "stubs",
  ], code);
  if (item.schema_version !== TANSTACK_START_BUILD_SCHEMA || item.observer !== TANSTACK_START_BUILD_OBSERVER
    || item.observer_version !== TANSTACK_START_BUILD_OBSERVER_VERSION
    || item.capability !== TANSTACK_START_BUILD_CAPABILITY
    || item.resolver_virtual_module_observed !== true) fail(code);
  const startVersion = stableVersion(item.start_version, new Set([1]), "web.tanstack_start_build_version_unsupported");
  const providerValue = boundedString(item.provider_environment_name, 128);
  if (providerValue === null) fail(code);
  const provider = providerEnvironmentName(providerValue);
  if (!Array.isArray(item.builds) || item.builds.length > 3
    || !Array.isArray(item.server_functions) || item.server_functions.length > MAX_MODULES
    || !Array.isArray(item.stubs) || item.stubs.length > MAX_MODULES) fail(code);
  const builds = item.builds.map(validateObservedBuild);
  const functions = item.server_functions.map(validateObservedServerFunction);
  const stubs = item.stubs.map(validateObservedStub);
  const manifest = validateRpcManifest(item.production_rpc_manifest);
  const expectedEnvironments = [...new Set(["client", "ssr", provider])].sort(compareUtf8);
  const actualEnvironments = builds.map((build) => build.vite_environment);
  if (actualEnvironments.length !== expectedEnvironments.length
    || actualEnvironments.some((environment, index) => environment !== expectedEnvironments[index])
    || manifest.resolver_environment !== provider
    || functions.some((entry, index) => index > 0
      && compareUtf8(functions[index - 1]!.production_rpc_id, entry.production_rpc_id) >= 0)
    || stubs.some((entry, index) => index > 0 && (
      compareUtf8(stubs[index - 1]!.production_rpc_id, entry.production_rpc_id)
      || compareUtf8(stubs[index - 1]!.environment, entry.environment)
      || compareUtf8(stubs[index - 1]!.source_module_id, entry.source_module_id)
    ) >= 0)) fail(code);
  const canonicalConfig = canonicalJson(builds[0]?.config as unknown as JsonValue);
  if (builds.some((build) => canonicalJson(build.config as unknown as JsonValue) !== canonicalConfig)) fail(code);
  const modulesByEnvironment = new Map(builds.map((build) => [
    build.vite_environment,
    new Map(build.modules.map((module) => [module.module_id, module])),
  ]));
  const providerModules = modulesByEnvironment.get(provider);
  const resolverModule = providerModules?.get(manifest.resolver_module_id);
  if (resolverModule?.module_kind !== "virtual") fail("web.tanstack_start_build_rpc_manifest_missing");
  const functionById = new Map(functions.map((fn) => [fn.production_rpc_id, fn]));
  if (functionById.size !== functions.length || manifest.entries.length !== functions.length) {
    fail("web.tanstack_start_build_rpc_manifest_provider_mismatch");
  }
  const manifestById = new Map(manifest.entries.map((entry) => [entry.production_rpc_id, entry]));
  for (const fn of functions) {
    const entry = manifestById.get(fn.production_rpc_id);
    const providerModule = providerModules?.get(fn.provider_module_id);
    if (entry === undefined || entry.handler_export_name !== `${fn.export_name}_createServerFn_handler`
      || entry.provider_module_id !== fn.provider_module_id || providerModule?.environment !== "server"
      || (entry.client_referenced !== null && entry.client_referenced !== fn.client_referenced)) {
      fail("web.tanstack_start_build_rpc_manifest_provider_mismatch");
    }
  }
  const clientIds = new Set<string>();
  const ssrIds = new Set<string>();
  for (const stub of stubs) {
    const module = modulesByEnvironment.get(stub.environment)?.get(stub.source_module_id);
    if ((module !== undefined && module.source_path !== stub.source_path)
      || (module === undefined && (stub.source_path === null
        || (stub.source_module_id !== stub.source_path && !stub.source_module_id.startsWith(`${stub.source_path}#`))))
      || !functionById.has(stub.production_rpc_id)) {
      fail("web.tanstack_start_build_stub_target_missing");
    }
    (stub.environment === "client" ? clientIds : ssrIds).add(stub.production_rpc_id);
  }
  for (const fn of functions) {
    if (fn.client_referenced !== clientIds.has(fn.production_rpc_id)
      || fn.ssr_referenced !== ssrIds.has(fn.production_rpc_id)) fail(code);
  }
  return {
    schema_version: TANSTACK_START_BUILD_SCHEMA,
    observer: TANSTACK_START_BUILD_OBSERVER,
    observer_version: TANSTACK_START_BUILD_OBSERVER_VERSION,
    capability: TANSTACK_START_BUILD_CAPABILITY,
    start_version: startVersion,
    provider_environment_name: provider,
    resolver_virtual_module_observed: true,
    production_rpc_manifest: manifest,
    builds,
    server_functions: functions,
    stubs,
  };
}

async function maybeWrite(state: MutableState): Promise<void> {
  if (state.wrote || state.writing) return;
  const required = requiredViteEnvironments(state);
  if ([...required].some((environment) => !state.completedViteEnvironments.has(environment))) return;
  state.writing = true;
  try {
    const observation = finalObservation(state);
    await bounded("web.tanstack_start_build_observer_sink_failed", state.timeoutMs, () => state.sink.write(observation));
    state.wrote = true;
  } finally {
    state.writing = false;
  }
}

export function createTanStackStartBuildObserverPlugin(options: TanStackStartObserverOptions): TanStackVitePluginLike {
  if (boundedString(options.repoRoot) === null || !path.isAbsolute(options.repoRoot)) {
    fail("web.tanstack_start_build_repo_root_invalid");
  }
  const capability = detectTanStackStartBuildCapability(
    options.startVersion,
    options.providerEnvironmentName,
    options.existingVitePlugins ?? [],
  );
  const state: MutableState = {
    capability,
    repoRoot: path.resolve(options.repoRoot),
    sink: options.sink,
    timeoutMs: timeoutValue(options.timeoutMs),
    expectedPluginNames: validatePluginNames(options.existingVitePlugins ?? []),
    completedViteEnvironments: new Set(),
    failedViteEnvironments: new Set(),
    builds: new Map(),
    serverFunctions: new Map(),
    stubs: new Map(),
    resolverModules: new Map(),
    rpcManifest: null,
    resolverObserved: false,
    writing: false,
    wrote: false,
  };
  const configs = new Map<string, TanStackObservedConfig>();
  const versions = new Map<string, string>();
  return {
    name: TANSTACK_START_BUILD_OBSERVER,
    apply: "build",
    enforce: "post",
    configResolved(config) {
      normalizedHook("web.tanstack_start_build_config_hook_failed", () => {
        const validated = validateFinalPluginChain(config, state);
        const environments = record(config.environments);
        const declared = environments === null ? [] : Object.keys(environments);
        for (const required of requiredViteEnvironments(state)) {
          if (declared.length > 0 && !declared.includes(required)) {
            fail("web.tanstack_start_build_environment_contract_invalid");
          }
        }
        configs.set("shared", validated);
      });
    },
    buildStart() {
      normalizedHook("web.tanstack_start_build_start_hook_failed", () => {
        const environment = environmentName(this);
        if (!requiredViteEnvironments(state).has(environment)) return;
        const version = stableVersion(record(this.meta)?.viteVersion, new Set([7]), "web.tanstack_start_build_vite_version_unsupported");
        versions.set(environment, version);
      });
    },
    transform(code, id) {
      return normalizedHook("web.tanstack_start_build_transform_hook_failed", () => {
        const environment = environmentName(this);
        if (!requiredViteEnvironments(state).has(environment)) return null;
        if (typeof code !== "string" || code.length > 64 * 1024 * 1024 || boundedModuleString(id) === null) {
          fail("web.tanstack_start_build_transform_contract_invalid");
        }
        const module = logicalModule(id, state.repoRoot, environment, capability.provider_environment_name);
        if (RESOLVER_MARKERS.some((marker) => id.includes(marker))) {
          if (module.module_kind !== "virtual") fail("web.tanstack_start_build_rpc_manifest_invalid");
          state.resolverObserved = true;
          const previous = state.resolverModules.get(environment);
          if (previous !== undefined && previous.module_id !== module.module_id) {
            fail("web.tanstack_start_build_resolver_module_conflict");
          }
          state.resolverModules.set(environment, module);
          if (environment === capability.provider_environment_name) {
            const entries = resolverManifestEntries(code, state, environment);
            const manifest: TanStackObservedRpcManifest = {
              resolver_module_id: module.module_id,
              resolver_environment: environment,
              entry_count: entries.length,
              entries_digest: digestIdentity(entries as unknown as JsonValue),
              entries,
            };
            if (state.rpcManifest !== null
              && canonicalJson(state.rpcManifest as unknown as JsonValue)
                !== canonicalJson(manifest as unknown as JsonValue)) {
              fail("web.tanstack_start_build_rpc_manifest_conflict");
            }
            state.rpcManifest = manifest;
          }
        }
        for (const rpcId of callStrings(code, "createClientRpc")) upsertStub(state, rpcId, module, "client");
        for (const rpcId of callStrings(code, "createSsrRpc")) upsertStub(state, rpcId, module, "ssr");
        for (const call of providerCalls(code)) upsertServerFunction(state, call, module);
        return null;
      });
    },
    generateBundle(_outputOptions, bundle) {
      normalizedHook("web.tanstack_start_build_bundle_hook_failed", () => {
        const environment = environmentName(this);
        if (!requiredViteEnvironments(state).has(environment)) return;
        const idsMethod = contextMethod(this, "getModuleIds");
        const infoMethod = contextMethod(this, "getModuleInfo");
        if (idsMethod === null || infoMethod === null) fail("web.tanstack_start_build_module_graph_unavailable");
        const ids = [...idsMethod() as Iterable<unknown>];
        if (ids.length > MAX_MODULES) fail("web.tanstack_start_build_module_limit_exceeded");
        const modules = mergeModules(ids.map((id) => observedModule(id, infoMethod(id), state, environment)));
        const moduleById = new Map(modules.map((module) => [module.module_id, module]));
        const rawOutputs = Object.values(bundle);
        if (rawOutputs.length > MAX_OUTPUTS) fail("web.tanstack_start_build_output_limit_exceeded");
        const outputs = rawOutputs.map((value) => observedOutput(value, moduleById, state, environment))
          .sort((left, right) => compareUtf8(left.file_name, right.file_name));
        const config = configs.get(environment) ?? configs.get("shared");
        const version = versions.get(environment);
        if (config === undefined || version === undefined) fail("web.tanstack_start_build_hook_order_invalid");
        state.builds.set(environment, { vite_environment: environment, vite_version: version, config, modules, outputs });
      });
    },
    buildEnd(error) {
      normalizedHook("web.tanstack_start_build_end_hook_failed", () => {
        if (error !== undefined && error !== null) state.failedViteEnvironments.add(environmentName(this));
      });
    },
    async closeBundle() {
      await bounded("web.tanstack_start_build_close_hook_failed", state.timeoutMs, async () => {
        const environment = environmentName(this);
        if (!requiredViteEnvironments(state).has(environment)) return;
        state.completedViteEnvironments.add(environment);
        await maybeWrite(state);
      });
    },
  };
}

export function preflightTanStackStartBuildObserver(options: TanStackStartObserverOptions): {
  plugin: TanStackVitePluginLike;
  capability: TanStackStartCapability;
} {
  return {
    capability: detectTanStackStartBuildCapability(
      options.startVersion, options.providerEnvironmentName, options.existingVitePlugins ?? [],
    ),
    plugin: createTanStackStartBuildObserverPlugin(options),
  };
}

export function tanStackStartBuildFailureDiagnostic(error: unknown, profileId: string): Diagnostic {
  const code = error instanceof TanStackStartBuildObserverError && /^web\.tanstack_start_build_[a-z0-9_]+$/u.test(error.code)
    ? error.code
    : "web.tanstack_start_build_observer_failed";
  const reason = code.includes("version_unsupported")
    ? "framework_build_version_unsupported"
    : code.includes("manifest") || code.includes("stub_target_missing") || code.includes("virtual_module_missing")
      ? "framework_build_manifest_missing"
      : code.includes("conflict") || code.includes("collision")
        ? "framework_build_generated_identity_conflict"
        : code.includes("hook") || code.includes("plugin_chain") || code.includes("environment_")
          ? "framework_build_hook_missing"
          : "framework_build_incomplete";
  const properties: Record<string, JsonValue> = {
    framework: "tanstack-start",
    observer: TANSTACK_START_BUILD_OBSERVER,
    observer_version: TANSTACK_START_BUILD_OBSERVER_VERSION,
    capability: TANSTACK_START_BUILD_CAPABILITY,
    contract_version: FRAMEWORK_BUILD_GRAPH_CONTRACT_VERSION,
    observer_failure: true,
    framework_build_completion_status: code.includes("version_unsupported") ? "unsupported" : "partial",
    framework_build_completion_reason: reason,
  };
  return {
    id: stableId("diagnostic", { code, profile_id: profileId, properties }),
    severity: "error",
    code,
    message: `${code}: TanStack Start build observation was not promoted`,
    path: null,
    profile_id: profileId,
    properties,
  };
}

function validateProvenance(provenance: TanStackStartBuildProvenance): void {
  try {
    validateFrameworkBuildProvenance(provenance);
  } catch {
    fail("web.tanstack_start_build_provenance_invalid");
  }
}

function buildEvidence(
  provenance: TanStackStartBuildProvenance,
  logicalPath: string,
  artifactDigest: string,
  properties: Record<string, JsonValue> = {},
): Evidence {
  return frameworkBuildEvidence(
    TANSTACK_START_FRAMEWORK_BUILD_DESCRIPTOR,
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
  provenance: TanStackStartBuildProvenance,
  logicalPath: string,
  digest: string,
): GraphNode {
  return frameworkBuildGeneratedNode(
    TANSTACK_START_FRAMEWORK_BUILD_DESCRIPTOR,
    kind,
    identity,
    displayName,
    properties,
    provenance,
    logicalPath,
    digest,
  );
}

function observedCondition(environment: TanStackBuildEnvironment, properties: Record<string, string> = {}): Condition {
  return frameworkBuildCondition(environment, properties);
}

function addObservedRelation(
  sites: DependencySite[],
  edges: GraphEdge[],
  source: string,
  target: string,
  kind: string,
  specifier: string,
  environment: TanStackBuildEnvironment,
  condition: Condition,
  evidence: Evidence,
  profileId: string,
): void {
  const { site, edge } = frameworkBuildRelation(
    TANSTACK_START_FRAMEWORK_BUILD_DESCRIPTOR,
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
    TANSTACK_START_FRAMEWORK_BUILD_DESCRIPTOR,
    code,
    subject,
    profileId,
    evidence,
    properties,
    severity,
  );
}

function uniqueById<T extends { id: string }>(values: readonly T[], code: string): T[] {
  try {
    return deduplicateFrameworkBuildRecords(values);
  } catch {
    fail(code);
  }
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

function serverFunctionCandidates(nodes: readonly GraphNode[], value: TanStackObservedServerFunction): GraphNode[] {
  return nodes.filter((node) => node.kind === "server_function"
    && node.properties.framework === "tanstack-start"
    && sourcePath(node) === value.source_path
    && node.display_name === value.export_name)
    .sort((left, right) => compareUtf8(left.id, right.id));
}

export function buildTanStackStartObservedGraph(
  input: TanStackStartBuildGraphInput,
): TanStackStartBuildGraphDelta {
  const observation = validateTanStackStartBuildObservation(input.observation);
  validateProvenance(input.provenance);
  const observationDigest = digestIdentity(observation as unknown as JsonValue);
  const observationPath = `.tanstack/depgraph/${observationDigest}.json`;
  const commonEvidence = buildEvidence(input.provenance, observationPath, observationDigest);
  const nodes = new Map<string, GraphNode>();
  const sites: DependencySite[] = [];
  const edges: GraphEdge[] = [];
  const diagnostics: Diagnostic[] = [];
  const baseById = new Map(input.baseNodes.map((node) => [node.id, node]));
  const baseByPath = nodesByPath(input.baseNodes);
  const outputIdsByBaseNode = new Map<string, Set<string>>();
  const observedFunctionByRpcId = new Map<string, GraphNode>();
  const safeFunctionByRpcId = new Map<string, GraphNode>();
  const observedFunctionBySafeId = new Map<string, GraphNode>();
  const manifestByRpcId = new Map(
    observation.production_rpc_manifest.entries.map((entry) => [entry.production_rpc_id, entry]),
  );
  const addNode = (node: GraphNode): void => {
    const previous = nodes.get(node.id);
    if (previous !== undefined
      && canonicalJson(previous as unknown as JsonValue) !== canonicalJson(node as unknown as JsonValue)) {
      fail("web.tanstack_start_build_node_conflict");
    }
    nodes.set(node.id, node);
  };

  const handlerTargets = new Map<string, GraphNode[]>();
  for (const edge of input.baseEdges ?? []) {
    if (edge.kind !== "handled_by") continue;
    const target = baseById.get(edge.target);
    if (target === undefined) continue;
    const values = handlerTargets.get(edge.source) ?? [];
    values.push(target);
    handlerTargets.set(edge.source, values);
  }

  for (const fn of observation.server_functions) {
    const manifestEntry = manifestByRpcId.get(fn.production_rpc_id);
    if (manifestEntry === undefined) fail("web.tanstack_start_build_rpc_manifest_provider_mismatch");
    const evidence = buildEvidence(input.provenance, observationPath, observationDigest, {
      production_rpc_id: fn.production_rpc_id,
      collision_suffix: fn.collision_suffix,
      collision_suffix_status: fn.collision_suffix_status,
      manifest_entries_digest: observation.production_rpc_manifest.entries_digest,
    });
    const identity: Record<string, JsonValue> = {
      framework: "tanstack-start",
      production_rpc_id: fn.production_rpc_id,
      provider_module_id: fn.provider_module_id,
      profile_id: input.provenance.profile_id,
    };
    const observed = buildNode("server_function", identity, fn.export_name, {
      framework: "tanstack-start",
      production_rpc_id: fn.production_rpc_id,
      production_rpc_id_status: "build-observed",
      collision_suffix: fn.collision_suffix,
      collision_suffix_status: fn.collision_suffix_status,
      source_path: fn.source_path,
      provider_module_id: fn.provider_module_id,
      manifest_handler_export_name: manifestEntry.handler_export_name,
      manifest_client_referenced: manifestEntry.client_referenced,
      client_referenced: fn.client_referenced,
      ssr_referenced: fn.ssr_referenced,
      profile_id: input.provenance.profile_id,
    }, input.provenance, observationPath, observationDigest);
    addNode(observed);
    observedFunctionByRpcId.set(fn.production_rpc_id, observed);
    const candidates = serverFunctionCandidates(input.baseNodes, fn);
    if (candidates.length === 1) {
      const safe = candidates[0]!;
      addNode(safe);
      safeFunctionByRpcId.set(fn.production_rpc_id, safe);
      observedFunctionBySafeId.set(safe.id, observed);
      addObservedRelation(
        sites, edges, observed.id, safe.id, "observes_definition", fn.export_name, "server",
        observedCondition("server", { "tanstack.start.rpc_id": fn.production_rpc_id }),
        evidence, input.provenance.profile_id,
      );
      for (const handler of handlerTargets.get(safe.id) ?? []) {
        addNode(handler);
        addObservedRelation(
          sites, edges, observed.id, handler.id, "handled_by", handler.display_name, "server",
          observedCondition("server", { "tanstack.start.rpc_id": fn.production_rpc_id }),
          evidence, input.provenance.profile_id,
        );
      }
    } else {
      const unresolved = frameworkBuildUnresolvedTarget(
        TANSTACK_START_FRAMEWORK_BUILD_DESCRIPTOR,
        input.provenance,
        "observes_definition",
        observed.id,
        `${fn.source_path}#${fn.export_name}`,
        "server",
        observedCondition("server", { "tanstack.start.rpc_id": fn.production_rpc_id }),
        evidence,
        "framework_build_dynamic_target_unmatched",
      );
      addNode(unresolved.node);
      sites.push(unresolved.site);
      edges.push(unresolved.edge);
      diagnostics.push(graphDiagnostic(
        candidates.length === 0
          ? "web.tanstack_start_build_server_function_static_missing"
          : "web.tanstack_start_build_server_function_conflict",
        `${fn.source_path}#${fn.export_name}`,
        input.provenance.profile_id,
        evidence,
        { candidate_count: candidates.length, production_rpc_id: fn.production_rpc_id },
      ));
    }
  }

  for (const stub of observation.stubs) {
    const target = observedFunctionByRpcId.get(stub.production_rpc_id);
    if (target === undefined) fail("web.tanstack_start_build_stub_target_missing");
    const evidence = buildEvidence(input.provenance, observationPath, observationDigest, {
      production_rpc_id: stub.production_rpc_id,
      stub_environment: stub.environment,
    });
    const stubNode = buildNode("symbol", {
      framework: "tanstack-start",
      stub_environment: stub.environment,
      source_module_id: stub.source_module_id,
      production_rpc_id: stub.production_rpc_id,
      profile_id: input.provenance.profile_id,
    }, `RPC stub ${stub.production_rpc_id}`, {
      framework: "tanstack-start",
      generated_symbol_kind: "tanstack-start-rpc-stub",
      environment: stub.environment === "client" ? "browser" : "ssr",
      source_module_id: stub.source_module_id,
      source_path: stub.source_path,
      production_rpc_id: stub.production_rpc_id,
      profile_id: input.provenance.profile_id,
    }, input.provenance, observationPath, observationDigest);
    addNode(stubNode);
    addObservedRelation(
      sites, edges, stubNode.id, target.id, "client_stub_for", stub.production_rpc_id, stub.environment,
      observedCondition(stub.environment, { "tanstack.start.rpc_id": stub.production_rpc_id }),
      evidence, input.provenance.profile_id,
    );
    const safe = safeFunctionByRpcId.get(stub.production_rpc_id);
    const definitionId = safe?.properties.typescript_definition_id;
    const definition = typeof definitionId === "string" ? baseById.get(definitionId) : undefined;
    if (definition !== undefined) {
      addNode(definition);
      addObservedRelation(
        sites, edges, definition.id, target.id, "client_stub_for", stub.production_rpc_id, stub.environment,
        observedCondition(stub.environment, { "tanstack.start.rpc_id": stub.production_rpc_id }),
        evidence, input.provenance.profile_id,
      );
    }
  }

  const providerModuleIds = new Set(observation.server_functions.map((fn) => fn.provider_module_id));
  const stubRoleByModule = new Map(observation.stubs.map((stub) => [
    `${stub.environment}\0${stub.source_module_id}`,
    stub.environment === "client" ? "client-rpc-stub" : "ssr-rpc-stub",
  ]));
  for (const build of observation.builds) {
    const moduleNodes = new Map<string, GraphNode>();
    const observedModulesById = new Map(build.modules.map((module) => [module.module_id, module]));
    const outputNodes = new Map<string, GraphNode>();
    for (const module of build.modules) {
      const generatedModuleRole = module.module_id === observation.production_rpc_manifest.resolver_module_id
          && build.vite_environment === observation.production_rpc_manifest.resolver_environment
        ? "server-function-resolver"
        : providerModuleIds.has(module.module_id)
          ? "server-function-provider"
          : stubRoleByModule.get(`${build.vite_environment}\0${module.module_id}`) ?? null;
      const matching = module.source_path === null ? [] : (baseByPath.get(module.source_path) ?? [])
        .filter((node) => node.kind !== "route" && node.kind !== "server_function" && node.kind !== "middleware");
      let node = generatedModuleRole === null
        ? matching.find((candidate) => candidate.properties.environment === (module.environment === "client" ? "browser" : module.environment))
          ?? matching.find((candidate) => candidate.kind === "component" || candidate.kind === "file")
          ?? null
        : null;
      if (node === null) {
        node = buildNode("module", {
          framework: "tanstack-start",
          module_id: module.module_id,
          environment: module.environment,
          profile_id: input.provenance.profile_id,
        }, module.module_id, {
          framework: "tanstack-start",
          module_id: module.module_id,
          source_path: module.source_path,
          module_kind: module.module_kind,
          tanstack_start_module_role: generatedModuleRole,
          environment: module.environment === "client" ? "browser" : module.environment,
          profile_id: input.provenance.profile_id,
        }, input.provenance, observationPath, observationDigest);
      }
      addNode(node);
      moduleNodes.set(module.module_id, node);
    }
    for (const output of build.outputs) {
      const evidence = buildEvidence(input.provenance, output.file_name, output.digest);
      const node = buildNode("file", {
        framework: "tanstack-start",
        file_name: output.file_name,
        output_digest: output.digest,
        environment: output.environment,
        profile_id: input.provenance.profile_id,
      }, output.file_name, {
        framework: "tanstack-start",
        artifact_kind: output.kind,
        logical_path: output.file_name,
        artifact_digest: output.digest,
        environment: output.environment === "client" ? "browser" : output.environment,
        entry: output.entry,
        profile_id: input.provenance.profile_id,
      }, input.provenance, output.file_name, output.digest);
      addNode(node);
      outputNodes.set(output.file_name, node);
      for (const moduleId of output.module_ids) {
        const module = moduleNodes.get(moduleId);
        if (module !== undefined) addObservedRelation(
          sites, edges, module.id, node.id, "emits", output.file_name, output.environment,
          observedCondition(output.environment), evidence, input.provenance.profile_id,
        );
        const observedModuleValue = observedModulesById.get(moduleId);
        if (observedModuleValue?.source_path === null || observedModuleValue?.source_path === undefined) continue;
        for (const base of baseByPath.get(observedModuleValue.source_path) ?? []) {
          if (!(["route", "middleware", "server_function"] as GraphNode["kind"][]).includes(base.kind)
            || base.properties.framework !== "tanstack-start") continue;
          addNode(base);
          addObservedRelation(
            sites, edges, base.id, node.id, "emits", output.file_name, output.environment,
            observedCondition(output.environment), evidence, input.provenance.profile_id,
          );
          const ids = outputIdsByBaseNode.get(base.id) ?? new Set<string>();
          ids.add(node.id);
          outputIdsByBaseNode.set(base.id, ids);
        }
      }
    }
    for (const module of build.modules) {
      const source = moduleNodes.get(module.module_id);
      if (source === undefined) continue;
      for (const [kind, targets] of [["imports", module.imported_ids], ["dynamic_imports", module.dynamic_imported_ids]] as const) {
        for (const targetId of targets) {
          const target = moduleNodes.get(targetId);
          if (target !== undefined) addObservedRelation(
            sites, edges, source.id, target.id, kind, targetId, module.environment,
            observedCondition(module.environment), commonEvidence, input.provenance.profile_id,
          );
        }
      }
    }
    for (const output of build.outputs) {
      const source = outputNodes.get(output.file_name);
      if (source === undefined) continue;
      for (const targetName of output.imported_outputs) {
        const target = outputNodes.get(targetName);
        const digest = target?.properties.artifact_digest;
        if (target !== undefined && typeof digest === "string") addObservedRelation(
          sites, edges, source.id, target.id, "loads", targetName, output.environment,
          observedCondition(output.environment), buildEvidence(input.provenance, targetName, digest), input.provenance.profile_id,
        );
      }
    }
  }

  const outputLoads = new Map<string, Set<string>>();
  for (const edge of edges) {
    if (edge.kind !== "loads") continue;
    const targets = outputLoads.get(edge.source) ?? new Set<string>();
    targets.add(edge.target);
    outputLoads.set(edge.source, targets);
  }
  const reachesOutput = (source: string, targets: ReadonlySet<string>): boolean => {
    const pending = [source];
    const seen = new Set<string>();
    while (pending.length > 0) {
      const current = pending.pop()!;
      if (targets.has(current)) return true;
      if (seen.has(current)) continue;
      seen.add(current);
      pending.push(...(outputLoads.get(current) ?? []));
    }
    return false;
  };
  for (const edge of input.baseEdges ?? []) {
    if (edge.kind !== "uses_middleware") continue;
    const sourceOutputs = outputIdsByBaseNode.get(edge.source);
    const targetOutputs = outputIdsByBaseNode.get(edge.target);
    if (sourceOutputs === undefined) continue;
    const shared = targetOutputs !== undefined && [...sourceOutputs].some((id) => reachesOutput(id, targetOutputs));
    if (!shared) {
      diagnostics.push(graphDiagnostic(
        "web.tanstack_start_build_middleware_artifact_drift",
        `${edge.source}->${edge.target}`,
        input.provenance.profile_id,
        commonEvidence,
        { source_id: edge.source, middleware_id: edge.target },
      ));
      continue;
    }
    const source = observedFunctionBySafeId.get(edge.source) ?? baseById.get(edge.source);
    const target = baseById.get(edge.target);
    if (source === undefined || target?.kind !== "middleware") continue;
    addNode(source);
    addNode(target);
    addObservedRelation(
      sites,
      edges,
      source.id,
      target.id,
      "uses_middleware",
      target.display_name,
      "server",
      observedCondition("server", { "tanstack.start.middleware_chain": "build-correlated" }),
      commonEvidence,
      input.provenance.profile_id,
    );
  }

  const candidate = {
    startVersion: observation.start_version,
    viteVersions: [...new Set(observation.builds.map((build) => build.vite_version))].sort(compareUtf8),
    productionRpcManifestEntryCount: observation.production_rpc_manifest.entry_count,
    productionRpcManifestDigest: observation.production_rpc_manifest.entries_digest,
    nodes: [...nodes.values()].sort((left, right) => compareUtf8(left.id, right.id)),
    sites: uniqueById(sites, "web.tanstack_start_build_site_conflict"),
    edges: uniqueById(edges, "web.tanstack_start_build_edge_conflict"),
    diagnostics: uniqueById(diagnostics, "web.tanstack_start_build_diagnostic_conflict"),
  };
  let delta: TanStackStartBuildGraphDelta;
  try {
    delta = {
      startVersion: candidate.startVersion,
      viteVersions: candidate.viteVersions,
      productionRpcManifestEntryCount: candidate.productionRpcManifestEntryCount,
      productionRpcManifestDigest: candidate.productionRpcManifestDigest,
      ...reconcileFrameworkBuildBaseRecords(
        candidate,
        TANSTACK_START_FRAMEWORK_BUILD_DESCRIPTOR,
        input.provenance,
        input.baseNodes,
        input.baseEdges ?? [],
        input.baseDiagnosticIds,
      ),
    };
    validateFrameworkBuildDelta(
      delta,
      TANSTACK_START_FRAMEWORK_BUILD_DESCRIPTOR,
      input.provenance,
      input.baseNodes,
    );
  } catch {
    fail("web.tanstack_start_build_graph_contract_invalid");
  }
  return delta;
}

export function tanStackStartBuildProtocolEvents(
  root: string,
  delta: TanStackStartBuildGraphDelta,
  provenance: TanStackStartBuildProvenance,
  sourceRevision: string,
): ProtocolEvent[] {
  return frameworkBuildProtocolEvents(
    root,
    delta,
    provenance,
    sourceRevision,
    TANSTACK_START_FRAMEWORK_BUILD_DESCRIPTOR,
    {
      toolchain: `@tanstack/react-start ${delta.startVersion}`,
      command: "vite build",
      properties: {
        tanstack_start_version: delta.startVersion,
        vite_versions: delta.viteVersions,
        production_rpc_manifest_observed: true,
        production_rpc_manifest_entry_count: delta.productionRpcManifestEntryCount,
        production_rpc_manifest_digest: delta.productionRpcManifestDigest,
      },
    },
  );
}
