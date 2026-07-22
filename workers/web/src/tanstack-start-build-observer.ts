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

export const TANSTACK_START_BUILD_OBSERVER = "tanstack-start-vite-build-observer" as const;
export const TANSTACK_START_BUILD_OBSERVER_VERSION = "0.1.0" as const;
export const TANSTACK_START_BUILD_CAPABILITY = "tanstack-start-v1-vite-v7-server-fn-resolver-v1" as const;
export const TANSTACK_START_BUILD_SCHEMA = "tanstack-start-build-observation-v1" as const;

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
  client_referenced: boolean;
  ssr_referenced: boolean;
}

export interface TanStackObservedStub {
  production_rpc_id: string;
  source_module_id: string;
  source_path: string | null;
  environment: "client" | "ssr";
}

export interface TanStackStartBuildObservation {
  schema_version: typeof TANSTACK_START_BUILD_SCHEMA;
  observer: typeof TANSTACK_START_BUILD_OBSERVER;
  observer_version: typeof TANSTACK_START_BUILD_OBSERVER_VERSION;
  capability: typeof TANSTACK_START_BUILD_CAPABILITY;
  start_version: string;
  provider_environment_name: string;
  resolver_virtual_module_observed: boolean;
  builds: TanStackObservedBuild[];
  server_functions: TanStackObservedServerFunction[];
  stubs: TanStackObservedStub[];
}

export interface TanStackStartBuildGraphInput {
  observation: TanStackStartBuildObservation;
  provenance: TanStackStartBuildProvenance;
  baseNodes: readonly GraphNode[];
  baseEdges?: readonly GraphEdge[];
}

export interface TanStackStartBuildGraphDelta {
  startVersion: string;
  viteVersions: string[];
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

function jsonString(raw: string): string {
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

const JSON_STRING_PATTERN = '"(?:\\\\.|[^"\\\\])*"';

function callStrings(code: string, functionName: "createClientRpc" | "createSsrRpc"): string[] {
  const expression = new RegExp(`\\b${functionName}\\s*\\(\\s*(${JSON_STRING_PATTERN})`, "gu");
  const values: string[] = [];
  for (const match of code.matchAll(expression)) values.push(jsonString(match[1]!));
  return [...new Set(values)].sort(compareUtf8);
}

interface ProviderCall {
  id: string;
  name: string;
  filename: string;
}

function providerCalls(code: string): ProviderCall[] {
  const expression = new RegExp(
    `\\bcreateServerRpc\\s*\\(\\s*\\{\\s*(?:["']?id["']?)\\s*:\\s*(${JSON_STRING_PATTERN})\\s*,\\s*(?:["']?name["']?)\\s*:\\s*(${JSON_STRING_PATTERN})\\s*,\\s*(?:["']?filename["']?)\\s*:\\s*(${JSON_STRING_PATTERN})`,
    "gu",
  );
  const calls = [...code.matchAll(expression)].map((match) => ({
    id: jsonString(match[1]!),
    name: jsonString(match[2]!),
    filename: jsonString(match[3]!),
  }));
  return calls.sort((left, right) => compareUtf8(left.id, right.id));
}

function collisionSuffix(id: string): number | null {
  const match = /_(\d+)$/u.exec(id);
  if (match === null) return null;
  const value = Number(match[1]);
  return Number.isSafeInteger(value) && value > 0 ? value : null;
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
  return {
    mode: boundedString(config.mode) ?? "production",
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
    collision_suffix: collisionSuffix(call.id),
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
  updateReferences(state);
  const functions = [...state.serverFunctions.values()].sort((left, right) => compareUtf8(left.production_rpc_id, right.production_rpc_id));
  for (const stub of state.stubs.values()) {
    if (!state.serverFunctions.has(stub.production_rpc_id)) fail("web.tanstack_start_build_stub_target_missing");
  }
  return {
    schema_version: TANSTACK_START_BUILD_SCHEMA,
    observer: TANSTACK_START_BUILD_OBSERVER,
    observer_version: TANSTACK_START_BUILD_OBSERVER_VERSION,
    capability: TANSTACK_START_BUILD_CAPABILITY,
    start_version: state.capability.start_version,
    provider_environment_name: state.capability.provider_environment_name,
    resolver_virtual_module_observed: true,
    builds: [...state.builds.values()].sort((left, right) => compareUtf8(left.vite_environment, right.vite_environment)),
    server_functions: functions,
    stubs: [...state.stubs.values()].sort((left, right) => (
      compareUtf8(left.production_rpc_id, right.production_rpc_id)
      || compareUtf8(left.environment, right.environment)
      || compareUtf8(left.source_module_id, right.source_module_id)
    )),
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
        if (RESOLVER_MARKERS.some((marker) => id.includes(marker))) state.resolverObserved = true;
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
  const properties: Record<string, JsonValue> = {
    framework: "tanstack-start",
    observer: TANSTACK_START_BUILD_OBSERVER,
    observer_version: TANSTACK_START_BUILD_OBSERVER_VERSION,
    observer_failure: true,
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
  for (const [field, value] of Object.entries(provenance)) {
    if (field === "build_run_id" || field === "profile_id") {
      if (boundedString(value) === null) fail("web.tanstack_start_build_provenance_invalid");
    } else if (!/^[a-f0-9]{64}$/u.test(value)) {
      fail("web.tanstack_start_build_provenance_invalid");
    }
  }
}

function buildEvidence(
  provenance: TanStackStartBuildProvenance,
  logicalPath: string,
  artifactDigest: string,
  properties: Record<string, JsonValue> = {},
): Evidence {
  return {
    kind: "build",
    extractor: TANSTACK_START_BUILD_OBSERVER,
    extractor_version: TANSTACK_START_BUILD_OBSERVER_VERSION,
    path: logicalPath,
    start_line: 1,
    start_column: 1,
    end_line: 1,
    end_column: 1,
    properties: {
      ...provenance,
      logical_artifact_path: logicalPath,
      artifact_digest: artifactDigest,
      capability: TANSTACK_START_BUILD_CAPABILITY,
      ...properties,
    },
  };
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
  const id = stableId(kind, identity);
  return {
    id,
    kind,
    locator: `build://${TANSTACK_START_BUILD_OBSERVER}/${encodeURIComponent(logicalPath)}#${id}`,
    display_name: displayName,
    properties: {
      ...properties,
      build_generated: true,
      build_identity: identity,
      build_provenance: {
        ...provenance,
        observer: TANSTACK_START_BUILD_OBSERVER,
        observer_version: TANSTACK_START_BUILD_OBSERVER_VERSION,
        logical_artifact_path: logicalPath,
        artifact_digest: digest,
      },
    },
  };
}

function observedCondition(environment: TanStackBuildEnvironment, properties: Record<string, string> = {}): Condition {
  return canonicalizeCondition({
    op: "all",
    conditions: [
      { op: "eq", key: "mode", value: "production" },
      { op: "eq", key: "environment", value: environment === "client" ? "browser" : environment },
      ...Object.entries(properties).map(([key, value]) => ({ op: "eq" as const, key, value })),
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
  environment: TanStackBuildEnvironment,
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
    observer: TANSTACK_START_BUILD_OBSERVER,
    observer_version: TANSTACK_START_BUILD_OBSERVER_VERSION,
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
    environment: environment === "client" ? "browser" : environment,
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

function uniqueById<T extends { id: string }>(values: readonly T[], code: string): T[] {
  const result = new Map<string, T>();
  for (const value of values) {
    const previous = result.get(value.id);
    if (previous !== undefined
      && canonicalJson(previous as unknown as JsonValue) !== canonicalJson(value as unknown as JsonValue)) fail(code);
    result.set(value.id, value);
  }
  return [...result.values()].sort((left, right) => compareUtf8(left.id, right.id));
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
  const observation = input.observation;
  if (observation.schema_version !== TANSTACK_START_BUILD_SCHEMA
    || observation.observer !== TANSTACK_START_BUILD_OBSERVER
    || observation.observer_version !== TANSTACK_START_BUILD_OBSERVER_VERSION
    || observation.capability !== TANSTACK_START_BUILD_CAPABILITY
    || !observation.resolver_virtual_module_observed) {
    fail("web.tanstack_start_build_observation_contract_invalid");
  }
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
    const evidence = buildEvidence(input.provenance, observationPath, observationDigest, {
      production_rpc_id: fn.production_rpc_id,
      collision_suffix: fn.collision_suffix,
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
      source_path: fn.source_path,
      provider_module_id: fn.provider_module_id,
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

  for (const build of observation.builds) {
    const moduleNodes = new Map<string, GraphNode>();
    const outputNodes = new Map<string, GraphNode>();
    for (const module of build.modules) {
      const matching = module.source_path === null ? [] : (baseByPath.get(module.source_path) ?? [])
        .filter((node) => node.kind !== "route" && node.kind !== "server_function" && node.kind !== "middleware");
      let node = matching.find((candidate) => candidate.properties.environment === (module.environment === "client" ? "browser" : module.environment))
        ?? matching.find((candidate) => candidate.kind === "component" || candidate.kind === "file")
        ?? null;
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
        const observedModuleValue = build.modules.find((item) => item.module_id === moduleId);
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
    if (!shared) diagnostics.push(graphDiagnostic(
      "web.tanstack_start_build_middleware_artifact_drift",
      `${edge.source}->${edge.target}`,
      input.provenance.profile_id,
      commonEvidence,
      { source_id: edge.source, middleware_id: edge.target },
    ));
  }

  return {
    startVersion: observation.start_version,
    viteVersions: [...new Set(observation.builds.map((build) => build.vite_version))].sort(compareUtf8),
    nodes: [...nodes.values()].sort((left, right) => compareUtf8(left.id, right.id)),
    sites: uniqueById(sites, "web.tanstack_start_build_site_conflict"),
    edges: uniqueById(edges, "web.tanstack_start_build_edge_conflict"),
    diagnostics: uniqueById(diagnostics, "web.tanstack_start_build_diagnostic_conflict"),
  };
}

export function tanStackStartBuildProtocolEvents(
  root: string,
  delta: TanStackStartBuildGraphDelta,
  provenance: TanStackStartBuildProvenance,
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
    ...common, event: kind, seq: ++seq, ...payload,
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
      toolchain: `@tanstack/react-start ${delta.startVersion}`,
      command: "vite build",
      target: "production",
      features: [TANSTACK_START_BUILD_CAPABILITY],
      environment: { mode: "production" },
      source_revision: sourceRevision,
      properties: {
        observer: TANSTACK_START_BUILD_OBSERVER,
        observer_version: TANSTACK_START_BUILD_OBSERVER_VERSION,
        tanstack_start_version: delta.startVersion,
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
