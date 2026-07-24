import { lstat, open, rename, unlink } from "node:fs/promises";
import path from "node:path";
import type { Writable } from "node:stream";

export const RUNTIME_COLLECTOR_CONTRACT_VERSION = "runtime-collector-v1" as const;
export const RUNTIME_TRACE_SCHEMA_VERSION = "1.0" as const;
export const RUNTIME_TRACE_MEDIA_TYPE =
  "application/vnd.tamat.depgraph.runtime-trace.v1+json" as const;

const MAX_TRACE_EVENTS = 100_000;
const MAX_TRACE_BYTES = 16 * 1024 * 1024;
const MAX_STRING_CHARS = 4_096;
const MAX_NAMES = 256;
const DEFAULT_BUFFER_EVENTS = 10_000;
const DEFAULT_BUFFER_BYTES = 8 * 1024 * 1024;
const DEFAULT_EVENTS_PER_SECOND = 10_000;
const DEFAULT_SHUTDOWN_TIMEOUT_MS = 5_000;
const DEFAULT_RETRY_ATTEMPTS = 2;
const DEFAULT_RETRY_INITIAL_BACKOFF_MS = 25;
const DEFAULT_RETRY_MAX_BACKOFF_MS = 1_000;

export type RuntimeCollectorState = "disabled" | "running" | "draining" | "stopped";
export type RuntimeCollectorTransport = "file" | "stdout" | "otlp";
export type RuntimeObservationKind = "module" | "call" | "route" | "rpc";

export type RuntimeLocatorInput =
  | { kind: "node"; nodeId: string }
  | { kind: "graph_locator"; locator: string; nodeKind?: string }
  | { kind: "repository_path"; path: string; nodeKind?: string }
  | { kind: "external"; namespace: string; name: string }
  | { kind: "unresolved"; reason: string };

export type RuntimeTargetInput =
  | RuntimeLocatorInput
  | { kind: "http_url"; url: string };

export interface RuntimeRedactionInput {
  environmentKeys?: readonly string[];
  headerNames?: readonly string[];
  secretNames?: readonly string[];
  redactedValueCount?: number;
}

export interface RuntimeObservation {
  kind: RuntimeObservationKind;
  source: RuntimeLocatorInput;
  target: RuntimeTargetInput;
  count?: number;
  durationNs?: number;
  redaction?: RuntimeRedactionInput;
}

export interface RuntimeCollectorProfile {
  language: string;
  target?: string;
  features?: readonly string[];
  parentProfileId?: string;
}

export interface RuntimeCollectorEnvironment {
  name: string;
  runtime?: string;
  region?: string;
  environmentKeys?: readonly string[];
}

export interface RuntimeCollectorSession {
  id: string;
  profile: RuntimeCollectorProfile;
  environment: RuntimeCollectorEnvironment;
  redaction?: RuntimeRedactionInput;
}

export interface RuntimeCollectorClock {
  utcNow(): Date;
  monotonicNow(): number;
}

export interface RuntimeCollectorSinkContext {
  readonly contractVersion: typeof RUNTIME_COLLECTOR_CONTRACT_VERSION;
  readonly mediaType: typeof RUNTIME_TRACE_MEDIA_TYPE;
  readonly sessionId: string;
  readonly prefixEnd: number;
  readonly signal: AbortSignal;
}

export interface RuntimeCollectorSink {
  readonly kind: RuntimeCollectorTransport;
  write(payload: Readonly<Uint8Array>, context: RuntimeCollectorSinkContext): Promise<void>;
}

export interface OtlpRuntimeLogRecord {
  readonly body: Readonly<Uint8Array>;
  readonly attributes: Readonly<{
    "depgraph.collector.contract_version": typeof RUNTIME_COLLECTOR_CONTRACT_VERSION;
    "depgraph.runtime.media_type": typeof RUNTIME_TRACE_MEDIA_TYPE;
    "depgraph.runtime.session_id": string;
    "depgraph.runtime.prefix_end": number;
  }>;
}

export interface RuntimeCollectorDiagnostic {
  readonly code:
    | "invalid_observation"
    | "rate_limited"
    | "buffer_full"
    | "not_running"
    | "sink_failure"
    | "shutdown_timeout";
  readonly count: number;
}

export interface RuntimeCollectorOptions {
  enabled?: boolean;
  repository: {
    identity: string;
    revision?: string;
  };
  session: RuntimeCollectorSession;
  sink: RuntimeCollectorSink;
  buffer?: {
    maxEvents?: number;
    maxBytes?: number;
  };
  limits?: {
    maxEventsPerSecond?: number;
    maxTraceEvents?: number;
    maxTraceBytes?: number;
    maxStringChars?: number;
  };
  retry?: {
    maxAttempts?: number;
    initialBackoffMs?: number;
    maxBackoffMs?: number;
  };
  shutdownTimeoutMs?: number;
  clock?: RuntimeCollectorClock;
  sleep?: (delayMs: number, signal: AbortSignal) => Promise<void>;
  onDiagnostic?: (diagnostic: RuntimeCollectorDiagnostic) => void;
}

export interface RuntimeCollectorDescriptor {
  readonly contract_version: typeof RUNTIME_COLLECTOR_CONTRACT_VERSION;
  readonly output_schema_version: typeof RUNTIME_TRACE_SCHEMA_VERSION;
  readonly lifecycle: {
    readonly disabled: "no_op";
    readonly record_failure: "non_throwing_drop";
    readonly shutdown: "bounded_best_effort";
  };
  readonly buffer: {
    readonly max_events: number;
    readonly max_bytes: number;
    readonly overflow: "drop_newest";
  };
  readonly flush: {
    readonly snapshot: "immutable_contiguous_prefix";
    readonly concurrency: "coalesce";
    readonly shutdown_timeout_ms: number;
  };
  readonly retry: {
    readonly max_attempts: number;
    readonly initial_backoff_ms: number;
    readonly max_backoff_ms: number;
    readonly payload: "byte_identical";
    readonly exhaustion: "report_and_drop";
  };
  readonly sequence: {
    readonly initial: 1;
    readonly assignment: "accepted_event";
    readonly ordering: "contiguous_acceptance_order";
  };
  readonly clock: {
    readonly wall_source: "system_utc" | "injected_utc";
    readonly duration_source: "monotonic";
    readonly timestamp_format: "rfc3339_utc";
    readonly wall_regression: "clamp_to_previous";
  };
  readonly transport: {
    readonly kind: RuntimeCollectorTransport;
    readonly canonical_payload: "depgraph-runtime-trace-v1";
    readonly media_type: typeof RUNTIME_TRACE_MEDIA_TYPE;
  };
  readonly redaction: {
    readonly stage: "before_buffer";
    readonly url_policy: "scheme_host_port_only";
    readonly environment_keys: readonly string[];
    readonly header_names: readonly string[];
    readonly secret_names: readonly string[];
  };
  readonly limits: {
    readonly max_events_per_second: number;
    readonly max_trace_events: number;
    readonly max_trace_bytes: number;
    readonly max_string_chars: number;
  };
}

export interface RuntimeCollectorStats {
  readonly state: RuntimeCollectorState;
  readonly acceptedEvents: number;
  readonly flushedPrefixes: number;
  readonly dropped: Readonly<Record<RuntimeCollectorDiagnostic["code"], number>>;
}

export interface RuntimeFlushResult {
  readonly status: "disabled" | "empty" | "flushed" | "failed" | "stopped";
  readonly prefixEnd: number;
  readonly attempts: number;
}

export interface RuntimeCollector {
  readonly descriptor: RuntimeCollectorDescriptor;
  readonly state: RuntimeCollectorState;
  record(observation: RuntimeObservation): boolean;
  recordModule(observation: Omit<RuntimeObservation, "kind">): boolean;
  recordCall(observation: Omit<RuntimeObservation, "kind">): boolean;
  recordRoute(observation: Omit<RuntimeObservation, "kind">): boolean;
  recordRpc(observation: Omit<RuntimeObservation, "kind">): boolean;
  snapshot(): string | null;
  flush(): Promise<RuntimeFlushResult>;
  shutdown(): Promise<RuntimeFlushResult>;
  stats(): RuntimeCollectorStats;
}

type CanonicalLocator =
  | { kind: "node"; node_id: string }
  | { kind: "graph_locator"; locator: string; node_kind?: string }
  | { kind: "repository_path"; path: string; node_kind?: string }
  | { kind: "external"; namespace: string; name: string }
  | { kind: "unresolved"; reason: string };

interface CanonicalRedaction {
  environment_keys: string[];
  header_names: string[];
  secret_names: string[];
  redacted_value_count: number;
}

interface CanonicalizedTarget {
  locator: CanonicalLocator;
  urlRedaction: RuntimeRedactionInput | undefined;
}

interface NormalizedConfiguration {
  maxEvents: number;
  maxBytes: number;
  maxEventsPerSecond: number;
  maxTraceEvents: number;
  maxTraceBytes: number;
  maxStringChars: number;
  maxRetryAttempts: number;
  initialBackoffMs: number;
  maxBackoffMs: number;
  shutdownTimeoutMs: number;
}

const dependencyKinds: Readonly<Record<RuntimeObservationKind, string>> = {
  module: "imports",
  call: "calls",
  route: "requests",
  rpc: "invokes",
};

const defaultClock: RuntimeCollectorClock = {
  utcNow: () => new Date(),
  monotonicNow: () => performance.now(),
};

const diagnosticCodes: readonly RuntimeCollectorDiagnostic["code"][] = [
  "invalid_observation",
  "rate_limited",
  "buffer_full",
  "not_running",
  "sink_failure",
  "shutdown_timeout",
];

function boundedInteger(
  value: number | undefined,
  fallback: number,
  minimum: number,
  maximum: number,
  field: string,
): number {
  const normalized = value ?? fallback;
  if (!Number.isSafeInteger(normalized) || normalized < minimum || normalized > maximum) {
    throw new Error(`runtime collector ${field} is outside its supported range`);
  }
  return normalized;
}

function normalizeConfiguration(options: RuntimeCollectorOptions): NormalizedConfiguration {
  const maxTraceEvents = boundedInteger(
    options.limits?.maxTraceEvents,
    MAX_TRACE_EVENTS,
    1,
    MAX_TRACE_EVENTS,
    "maxTraceEvents",
  );
  const maxTraceBytes = boundedInteger(
    options.limits?.maxTraceBytes,
    MAX_TRACE_BYTES,
    1_024,
    MAX_TRACE_BYTES,
    "maxTraceBytes",
  );
  const maxEvents = Math.min(
    boundedInteger(
      options.buffer?.maxEvents,
      DEFAULT_BUFFER_EVENTS,
      1,
      MAX_TRACE_EVENTS,
      "maxEvents",
    ),
    maxTraceEvents,
  );
  const maxBytes = Math.min(
    boundedInteger(
      options.buffer?.maxBytes,
      DEFAULT_BUFFER_BYTES,
      1_024,
      MAX_TRACE_BYTES,
      "maxBytes",
    ),
    maxTraceBytes,
  );
  const initialBackoffMs = boundedInteger(
    options.retry?.initialBackoffMs,
    DEFAULT_RETRY_INITIAL_BACKOFF_MS,
    1,
    60_000,
    "initialBackoffMs",
  );
  const maxBackoffMs = boundedInteger(
    options.retry?.maxBackoffMs,
    DEFAULT_RETRY_MAX_BACKOFF_MS,
    1,
    60_000,
    "maxBackoffMs",
  );
  return {
    maxEvents,
    maxBytes,
    maxEventsPerSecond: boundedInteger(
      options.limits?.maxEventsPerSecond,
      DEFAULT_EVENTS_PER_SECOND,
      1,
      MAX_TRACE_EVENTS,
      "maxEventsPerSecond",
    ),
    maxTraceEvents,
    maxTraceBytes,
    maxStringChars: boundedInteger(
      options.limits?.maxStringChars,
      MAX_STRING_CHARS,
      1,
      MAX_STRING_CHARS,
      "maxStringChars",
    ),
    maxRetryAttempts: boundedInteger(
      options.retry?.maxAttempts,
      DEFAULT_RETRY_ATTEMPTS,
      0,
      10,
      "maxAttempts",
    ),
    initialBackoffMs,
    maxBackoffMs,
    shutdownTimeoutMs: boundedInteger(
      options.shutdownTimeoutMs,
      DEFAULT_SHUTDOWN_TIMEOUT_MS,
      1,
      60_000,
      "shutdownTimeoutMs",
    ),
  };
}

function hasOnlyKeys(value: object, allowed: readonly string[]): boolean {
  const keys = Object.keys(value);
  return keys.length <= allowed.length && keys.every((key) => allowed.includes(key));
}

function hasBoundedCharacters(value: string, maximum: number): boolean {
  let count = 0;
  for (const _character of value) {
    count += 1;
    if (count > maximum) return false;
  }
  return count > 0;
}

function validateString(value: unknown, maximum: number): value is string {
  return (
    typeof value === "string"
    && hasBoundedCharacters(value, maximum)
    && !/[\u0000-\u001f\u007f]/u.test(value)
  );
}

function looksLikeSecret(value: string): boolean {
  const lower = value.toLowerCase();
  return (
    lower.startsWith("bearer ")
    || lower.startsWith("basic ")
    || lower.startsWith("ghp_")
    || lower.startsWith("github_pat_")
    || lower.startsWith("sk-")
    || lower.startsWith("xoxb-")
    || lower.startsWith("xoxp-")
    || lower.startsWith("xoxa-")
    || lower.startsWith("xoxr-")
    || value.startsWith("AKIA")
    || value.startsWith("AIza")
    || (value.startsWith("eyJ") && value.split(".").length === 3)
    || (lower.includes("-----begin ") && lower.includes("private key-----"))
    || ["token=", "secret=", "password=", "api_key=", "apikey="].some((marker) =>
      lower.includes(marker)
    )
  );
}

function looksLikeAbsolutePath(value: string): boolean {
  const lower = value.toLowerCase();
  return (
    value.startsWith("/")
    || value.startsWith("\\\\")
    || /^[A-Za-z]:/u.test(value)
    || lower.startsWith("file:///")
    || lower === "file://localhost"
    || lower.startsWith("file://localhost/")
    || (lower.startsWith("file:/") && !lower.startsWith("file://"))
  );
}

function validateOutputString(value: unknown, maximum: number): value is string {
  return (
    validateString(value, maximum)
    && !looksLikeSecret(value)
    && !looksLikeAbsolutePath(value)
  );
}

function validateIdentifier(value: unknown): value is string {
  return validateOutputString(value, 512)
    && /^[A-Za-z0-9_.:/-]+$/u.test(value);
}

function normalizeNames(values: readonly string[] | undefined): string[] {
  if (values === undefined) return [];
  if (!Array.isArray(values)) throw new Error("redaction names must be an array");
  if (values.length > MAX_NAMES) throw new Error("too many redaction names");
  const names = [...new Set(values)];
  if (
    names.some(
      (name) =>
        !validateOutputString(name, 512)
        || !/^[A-Za-z0-9_.:/-]+$/u.test(name)
        || /:\/\/|[@?#%=]/u.test(name),
    )
  ) {
    throw new Error("invalid redaction name");
  }
  return names.sort(compareUtf8);
}

function compareUtf8(left: string, right: string): number {
  return Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8"));
}

function normalizeRedaction(
  input: RuntimeRedactionInput | undefined,
  extra: RuntimeRedactionInput | undefined,
): CanonicalRedaction | undefined {
  if (input === undefined && extra === undefined) return undefined;
  for (const value of [input, extra]) {
    if (
      value !== undefined
      && (value === null
        || typeof value !== "object"
        || Array.isArray(value)
        || !hasOnlyKeys(value, [
          "environmentKeys",
          "headerNames",
          "secretNames",
          "redactedValueCount",
        ])
        || (value.redactedValueCount !== undefined
          && (!Number.isSafeInteger(value.redactedValueCount)
            || value.redactedValueCount < 0)))
    ) {
      throw new Error("invalid redaction object");
    }
  }
  const environmentKeys = normalizeNames([
    ...(input?.environmentKeys ?? []),
    ...(extra?.environmentKeys ?? []),
  ]);
  const headerNames = normalizeNames([
    ...(input?.headerNames ?? []),
    ...(extra?.headerNames ?? []),
  ]);
  const secretNames = normalizeNames([
    ...(input?.secretNames ?? []),
    ...(extra?.secretNames ?? []),
  ]);
  const countFor = (value: RuntimeRedactionInput | undefined): number =>
    Math.max(
      (value?.environmentKeys?.length ?? 0)
        + (value?.headerNames?.length ?? 0)
        + (value?.secretNames?.length ?? 0),
      value?.redactedValueCount ?? 0,
    );
  const redactedValueCount = countFor(input) + countFor(extra);
  if (!Number.isSafeInteger(redactedValueCount) || redactedValueCount < 0) {
    throw new Error("invalid redaction count");
  }
  return {
    environment_keys: environmentKeys,
    header_names: headerNames,
    secret_names: secretNames,
    redacted_value_count: redactedValueCount,
  };
}

function normalizeRepositoryPath(value: string, maximum: number): string {
  if (
    !validateOutputString(value, maximum)
    || value.startsWith("/")
    || value.includes("\\")
    || value.includes(":")
    || value.includes("//")
    || value.endsWith("/")
    || value.split("/").some((segment) => segment === "." || segment === ".." || segment === "")
  ) {
    throw new Error("invalid repository path");
  }
  return value;
}

function canonicalizeLocator(input: RuntimeLocatorInput, maximum: number): CanonicalLocator {
  if (input === null || typeof input !== "object" || Array.isArray(input)) {
    throw new Error("invalid locator");
  }
  switch (input.kind) {
    case "node":
      if (!hasOnlyKeys(input, ["kind", "nodeId"])) throw new Error("invalid node locator");
      if (!validateOutputString(input.nodeId, 512)) throw new Error("invalid node locator");
      return { kind: "node", node_id: input.nodeId };
    case "graph_locator": {
      if (!hasOnlyKeys(input, ["kind", "locator", "nodeKind"])) {
        throw new Error("invalid graph locator");
      }
      if (
        !validateOutputString(input.locator, maximum)
        || /\s|\\/u.test(input.locator)
        || /^https?:\/\//iu.test(input.locator)
      ) {
        throw new Error("invalid graph locator");
      }
      if (/^file:/iu.test(input.locator) && !input.locator.startsWith("file:")) {
        throw new Error("invalid graph locator");
      }
      if (input.locator.startsWith("file://")) {
        const repositoryPath = input.locator.slice("file://".length);
        if (repositoryPath.split("/", 1)[0]?.toLowerCase() === "localhost") {
          throw new Error("invalid graph locator");
        }
        normalizeRepositoryPath(repositoryPath, maximum);
      } else if (input.locator.startsWith("file:")) {
        normalizeRepositoryPath(input.locator.slice("file:".length), maximum);
      }
      if (input.nodeKind !== undefined && !validateIdentifier(input.nodeKind)) {
        throw new Error("invalid graph node kind");
      }
      return input.nodeKind === undefined
        ? { kind: "graph_locator", locator: input.locator }
        : { kind: "graph_locator", locator: input.locator, node_kind: input.nodeKind };
    }
    case "repository_path": {
      if (!hasOnlyKeys(input, ["kind", "path", "nodeKind"])) {
        throw new Error("invalid repository locator");
      }
      const repositoryPath = normalizeRepositoryPath(input.path, maximum);
      if (input.nodeKind !== undefined && !validateIdentifier(input.nodeKind)) {
        throw new Error("invalid repository node kind");
      }
      return input.nodeKind === undefined
        ? { kind: "repository_path", path: repositoryPath }
        : { kind: "repository_path", path: repositoryPath, node_kind: input.nodeKind };
    }
    case "external": {
      if (!hasOnlyKeys(input, ["kind", "namespace", "name"])) {
        throw new Error("invalid external locator");
      }
      if (
        !validateIdentifier(input.namespace)
        || !validateOutputString(input.name, maximum)
        || /^[A-Za-z][A-Za-z0-9+.-]*:\/\//u.test(input.name)
      ) {
        throw new Error("invalid external locator");
      }
      const namespace = input.namespace.toLowerCase();
      if (namespace === "http" || namespace === "https") {
        if (/[@/?#%]/u.test(input.name)) throw new Error("invalid external locator");
        const parsed = new URL(`${namespace}://${input.name}`);
        if (parsed.host.length === 0 || parsed.pathname !== "/" || parsed.search || parsed.hash) {
          throw new Error("invalid external locator");
        }
        return { kind: "external", namespace, name: parsed.host.toLowerCase() };
      }
      return { kind: "external", namespace: input.namespace, name: input.name };
    }
    case "unresolved":
      if (!hasOnlyKeys(input, ["kind", "reason"])) {
        throw new Error("invalid unresolved locator");
      }
      if (!validateIdentifier(input.reason)) throw new Error("invalid unresolved locator");
      return { kind: "unresolved", reason: input.reason };
    default:
      throw new Error("invalid locator kind");
  }
}

function canonicalizeHttpTarget(raw: string, maximum: number): CanonicalizedTarget {
  if (!validateString(raw, maximum)) throw new Error("invalid HTTP target");
  const parsed = new URL(raw);
  const namespace = parsed.protocol.slice(0, -1).toLowerCase();
  if (namespace !== "http" && namespace !== "https") throw new Error("invalid HTTP target");
  const name = parsed.host.toLowerCase();
  if (!validateOutputString(name, maximum) || /[@/?#%]/u.test(name)) {
    throw new Error("invalid HTTP target");
  }
  const hasCredentials = parsed.username.length > 0 || parsed.password.length > 0;
  const redactedValueCount =
    (hasCredentials ? 1 : 0)
    + (parsed.pathname !== "/" && parsed.pathname !== "" ? 1 : 0)
    + (parsed.search.length > 0 ? 1 : 0)
    + (parsed.hash.length > 0 ? 1 : 0);
  return {
    locator: { kind: "external", namespace, name },
    urlRedaction:
      redactedValueCount === 0
        ? undefined
        : {
            secretNames: hasCredentials ? ["url_credentials"] : [],
            redactedValueCount,
          },
  };
}

function canonicalizeTarget(input: RuntimeTargetInput, maximum: number): CanonicalizedTarget {
  if (input === null || typeof input !== "object" || Array.isArray(input)) {
    throw new Error("invalid target");
  }
  if (input.kind === "http_url") {
    if (!hasOnlyKeys(input, ["kind", "url"])) throw new Error("invalid HTTP target");
    return canonicalizeHttpTarget(input.url, maximum);
  }
  return { locator: canonicalizeLocator(input, maximum), urlRedaction: undefined };
}

function defaultSleep(delayMs: number, signal: AbortSignal): Promise<void> {
  if (signal.aborted) return Promise.reject(new Error("aborted"));
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      signal.removeEventListener("abort", abort);
      resolve();
    }, delayMs);
    const abort = () => {
      clearTimeout(timer);
      reject(new Error("aborted"));
    };
    signal.addEventListener("abort", abort, { once: true });
  });
}

function compactTracePrefix(repository: object, session: object): string {
  const metadata = JSON.stringify({
    schema_version: RUNTIME_TRACE_SCHEMA_VERSION,
    repository,
    session,
  });
  return `${metadata.slice(0, -1)},"events":[`;
}

function createDescriptor(
  options: RuntimeCollectorOptions,
  configuration: NormalizedConfiguration,
  sessionRedaction: CanonicalRedaction | undefined,
): RuntimeCollectorDescriptor {
  return {
    contract_version: RUNTIME_COLLECTOR_CONTRACT_VERSION,
    output_schema_version: RUNTIME_TRACE_SCHEMA_VERSION,
    lifecycle: {
      disabled: "no_op",
      record_failure: "non_throwing_drop",
      shutdown: "bounded_best_effort",
    },
    buffer: {
      max_events: configuration.maxEvents,
      max_bytes: configuration.maxBytes,
      overflow: "drop_newest",
    },
    flush: {
      snapshot: "immutable_contiguous_prefix",
      concurrency: "coalesce",
      shutdown_timeout_ms: configuration.shutdownTimeoutMs,
    },
    retry: {
      max_attempts: configuration.maxRetryAttempts,
      initial_backoff_ms: configuration.initialBackoffMs,
      max_backoff_ms: configuration.maxBackoffMs,
      payload: "byte_identical",
      exhaustion: "report_and_drop",
    },
    sequence: {
      initial: 1,
      assignment: "accepted_event",
      ordering: "contiguous_acceptance_order",
    },
    clock: {
      wall_source: options.clock === undefined ? "system_utc" : "injected_utc",
      duration_source: "monotonic",
      timestamp_format: "rfc3339_utc",
      wall_regression: "clamp_to_previous",
    },
    transport: {
      kind: options.sink.kind,
      canonical_payload: "depgraph-runtime-trace-v1",
      media_type: RUNTIME_TRACE_MEDIA_TYPE,
    },
    redaction: {
      stage: "before_buffer",
      url_policy: "scheme_host_port_only",
      environment_keys: sessionRedaction?.environment_keys ?? [],
      header_names: sessionRedaction?.header_names ?? [],
      secret_names: sessionRedaction?.secret_names ?? [],
    },
    limits: {
      max_events_per_second: configuration.maxEventsPerSecond,
      max_trace_events: configuration.maxTraceEvents,
      max_trace_bytes: configuration.maxTraceBytes,
      max_string_chars: configuration.maxStringChars,
    },
  };
}

function createDisabledCollector(options: RuntimeCollectorOptions): RuntimeCollector {
  // Disabled mode deliberately ignores operational configuration so a stale
  // rollout value cannot change application startup behavior.
  const configuration: NormalizedConfiguration = {
    maxEvents: DEFAULT_BUFFER_EVENTS,
    maxBytes: DEFAULT_BUFFER_BYTES,
    maxEventsPerSecond: DEFAULT_EVENTS_PER_SECOND,
    maxTraceEvents: MAX_TRACE_EVENTS,
    maxTraceBytes: MAX_TRACE_BYTES,
    maxStringChars: MAX_STRING_CHARS,
    maxRetryAttempts: DEFAULT_RETRY_ATTEMPTS,
    initialBackoffMs: DEFAULT_RETRY_INITIAL_BACKOFF_MS,
    maxBackoffMs: DEFAULT_RETRY_MAX_BACKOFF_MS,
    shutdownTimeoutMs: DEFAULT_SHUTDOWN_TIMEOUT_MS,
  };
  const descriptor = createDescriptor(options, configuration, undefined);
  const result: RuntimeFlushResult = { status: "disabled", prefixEnd: 0, attempts: 0 };
  return {
    descriptor,
    state: "disabled",
    record: () => false,
    recordModule: () => false,
    recordCall: () => false,
    recordRoute: () => false,
    recordRpc: () => false,
    snapshot: () => null,
    flush: async () => result,
    shutdown: async () => result,
    stats: () => ({
      state: "disabled",
      acceptedEvents: 0,
      flushedPrefixes: 0,
      dropped: Object.fromEntries(diagnosticCodes.map((code) => [code, 0])) as Record<
        RuntimeCollectorDiagnostic["code"],
        number
      >,
    }),
  };
}

export function createRuntimeCollector(options: RuntimeCollectorOptions): RuntimeCollector {
  if (options.enabled === false) return createDisabledCollector(options);

  const configuration = normalizeConfiguration(options);
  if (!["file", "stdout", "otlp"].includes(options.sink.kind)) {
    throw new Error("runtime collector sink kind is unsupported");
  }
  const clock = options.clock ?? defaultClock;
  const sleep = options.sleep ?? defaultSleep;
  const startedDate = clock.utcNow();
  const startedMs = startedDate.getTime();
  const initialMonotonic = clock.monotonicNow();
  if (!Number.isFinite(startedMs) || !Number.isFinite(initialMonotonic)) {
    throw new Error("runtime collector clock returned an invalid value");
  }
  if (
    !validateOutputString(options.repository.identity, 512)
    || (options.repository.revision !== undefined
      && !validateOutputString(options.repository.revision, 512))
    || !validateOutputString(options.session.id, 512)
    || !validateIdentifier(options.session.profile.language)
    || (options.session.profile.target !== undefined
      && !validateOutputString(options.session.profile.target, 512))
    || (options.session.profile.parentProfileId !== undefined
      && !validateOutputString(options.session.profile.parentProfileId, 512))
    || !validateOutputString(options.session.environment.name, 512)
    || (options.session.environment.runtime !== undefined
      && !validateOutputString(options.session.environment.runtime, 512))
    || (options.session.environment.region !== undefined
      && !validateOutputString(options.session.environment.region, 512))
  ) {
    throw new Error("runtime collector metadata is invalid");
  }

  const features = normalizeNames(options.session.profile.features);
  const environmentKeys = normalizeNames(options.session.environment.environmentKeys);
  const sessionRedaction = normalizeRedaction(options.session.redaction, undefined);
  const repository = {
    identity: options.repository.identity,
    ...(options.repository.revision === undefined ? {} : { revision: options.repository.revision }),
  };
  const session = {
    id: options.session.id,
    started_at: startedDate.toISOString(),
    collector_contract_version: RUNTIME_COLLECTOR_CONTRACT_VERSION,
    profile: {
      language: options.session.profile.language,
      ...(options.session.profile.target === undefined
        ? {}
        : { target: options.session.profile.target }),
      ...(features.length === 0 ? {} : { features }),
      ...(options.session.profile.parentProfileId === undefined
        ? {}
        : { parent_profile_id: options.session.profile.parentProfileId }),
    },
    environment: {
      name: options.session.environment.name,
      ...(options.session.environment.runtime === undefined
        ? {}
        : { runtime: options.session.environment.runtime }),
      ...(options.session.environment.region === undefined
        ? {}
        : { region: options.session.environment.region }),
      ...(environmentKeys.length === 0 ? {} : { environment_keys: environmentKeys }),
    },
    ...(sessionRedaction === undefined ? {} : { redaction: sessionRedaction }),
  };
  const descriptor = createDescriptor(options, configuration, sessionRedaction);
  const prefix = compactTracePrefix(repository, session);
  const suffix = "]}";
  const baseBytes = Buffer.byteLength(prefix, "utf8") + Buffer.byteLength(suffix, "utf8");
  if (baseBytes >= configuration.maxBytes) {
    throw new Error("runtime collector metadata exceeds its byte limit");
  }

  let state: RuntimeCollectorState = "running";
  let lastTimestampMs = startedMs;
  let lastTokenTime = initialMonotonic;
  let tokens = configuration.maxEventsPerSecond;
  let flushedPrefixes = 0;
  let activeFlush: Promise<RuntimeFlushResult> | null = null;
  let activeAbort: AbortController | null = null;
  let shutdownPromise: Promise<RuntimeFlushResult> | null = null;
  const events: string[] = [];
  let eventBytes = 0;
  const dropped = Object.fromEntries(diagnosticCodes.map((code) => [code, 0])) as Record<
    RuntimeCollectorDiagnostic["code"],
    number
  >;

  const report = (code: RuntimeCollectorDiagnostic["code"]) => {
    dropped[code] += 1;
    try {
      options.onDiagnostic?.({ code, count: dropped[code] });
    } catch {
      // Application callbacks are outside the collector trust boundary.
    }
  };

  const snapshot = (): string | null =>
    events.length === 0 ? null : `${prefix}${events.join(",")}${suffix}`;

  const admitRate = (): boolean => {
    const now = clock.monotonicNow();
    if (!Number.isFinite(now)) return false;
    const elapsed = Math.max(0, now - lastTokenTime);
    tokens = Math.min(
      configuration.maxEventsPerSecond,
      tokens + (elapsed * configuration.maxEventsPerSecond) / 1_000,
    );
    lastTokenTime = Math.max(lastTokenTime, now);
    if (tokens < 1) return false;
    tokens -= 1;
    return true;
  };

  const record = (observation: RuntimeObservation): boolean => {
    if (state !== "running") {
      report("not_running");
      return false;
    }
    try {
      if (
        observation === null
        || typeof observation !== "object"
        || Array.isArray(observation)
        || !hasOnlyKeys(observation, [
          "kind",
          "source",
          "target",
          "count",
          "durationNs",
          "redaction",
        ])
        || !Object.hasOwn(dependencyKinds, observation.kind)
      ) {
        throw new Error("invalid observation kind");
      }
      const source = canonicalizeLocator(observation.source, configuration.maxStringChars);
      const target = canonicalizeTarget(observation.target, configuration.maxStringChars);
      const count = observation.count ?? 1;
      if (!Number.isSafeInteger(count) || count < 1) throw new Error("invalid count");
      if (
        observation.durationNs !== undefined
        && (!Number.isSafeInteger(observation.durationNs) || observation.durationNs < 0)
      ) {
        throw new Error("invalid duration");
      }
      const redaction = normalizeRedaction(observation.redaction, target.urlRedaction);
      if (!admitRate()) {
        report("rate_limited");
        return false;
      }
      const wall = clock.utcNow().getTime();
      if (!Number.isFinite(wall)) throw new Error("invalid wall clock");
      const timestampMs = Math.max(lastTimestampMs, wall);
      const sequence = events.length + 1;
      const event = {
        sequence,
        timestamp: new Date(timestampMs).toISOString(),
        dependency_kind: dependencyKinds[observation.kind],
        source,
        target: target.locator,
        ...(count === 1 ? {} : { count }),
        ...(observation.durationNs === undefined ? {} : { duration_ns: observation.durationNs }),
        ...(redaction === undefined ? {} : { redaction }),
      };
      const serialized = JSON.stringify(event);
      const serializedBytes = Buffer.byteLength(serialized, "utf8");
      const candidateBytes =
        baseBytes + eventBytes + serializedBytes + (events.length === 0 ? 0 : events.length);
      if (
        events.length >= configuration.maxEvents
        || events.length >= configuration.maxTraceEvents
        || candidateBytes > configuration.maxBytes
        || candidateBytes > configuration.maxTraceBytes
      ) {
        report("buffer_full");
        return false;
      }
      events.push(serialized);
      eventBytes += serializedBytes;
      lastTimestampMs = timestampMs;
      return true;
    } catch {
      report("invalid_observation");
      return false;
    }
  };

  const deliver = async (
    payload: string,
    prefixEnd: number,
    controller: AbortController,
  ): Promise<RuntimeFlushResult> => {
    const context: RuntimeCollectorSinkContext = {
      contractVersion: RUNTIME_COLLECTOR_CONTRACT_VERSION,
      mediaType: RUNTIME_TRACE_MEDIA_TYPE,
      sessionId: options.session.id,
      prefixEnd,
      signal: controller.signal,
    };
    for (let attempt = 0; attempt <= configuration.maxRetryAttempts; attempt += 1) {
      if (controller.signal.aborted) {
        return { status: "failed", prefixEnd, attempts: attempt };
      }
      try {
        await options.sink.write(Buffer.from(payload, "utf8"), context);
        if (controller.signal.aborted) {
          return { status: "failed", prefixEnd, attempts: attempt + 1 };
        }
        flushedPrefixes += 1;
        return { status: "flushed", prefixEnd, attempts: attempt + 1 };
      } catch {
        if (attempt === configuration.maxRetryAttempts) {
          report("sink_failure");
          return { status: "failed", prefixEnd, attempts: attempt + 1 };
        }
      }
      const delay = Math.min(
        configuration.initialBackoffMs * 2 ** attempt,
        configuration.maxBackoffMs,
      );
      try {
        await sleep(delay, controller.signal);
      } catch {
        return { status: "failed", prefixEnd, attempts: attempt + 1 };
      }
    }
    return {
      status: "failed",
      prefixEnd,
      attempts: configuration.maxRetryAttempts + 1,
    };
  };

  const flush = (): Promise<RuntimeFlushResult> => {
    if (state === "stopped") {
      return Promise.resolve({ status: "stopped", prefixEnd: events.length, attempts: 0 });
    }
    if (activeFlush !== null) return activeFlush;
    const payload = snapshot();
    const prefixEnd = events.length;
    if (payload === null) {
      return Promise.resolve({ status: "empty", prefixEnd: 0, attempts: 0 });
    }
    const controller = new AbortController();
    activeAbort = controller;
    const pending = deliver(payload, prefixEnd, controller);
    activeFlush = pending;
    void pending.finally(() => {
      if (activeFlush === pending) activeFlush = null;
      if (activeAbort === controller) activeAbort = null;
    });
    return pending;
  };

  const shutdown = (): Promise<RuntimeFlushResult> => {
    if (shutdownPromise !== null) return shutdownPromise;
    if (state === "stopped") {
      return Promise.resolve({ status: "stopped", prefixEnd: events.length, attempts: 0 });
    }
    state = "draining";
    shutdownPromise = (async () => {
      const pending = flush();
      let timer: NodeJS.Timeout | undefined;
      const timeout = new Promise<RuntimeFlushResult>((resolve) => {
        timer = setTimeout(() => {
          report("shutdown_timeout");
          activeAbort?.abort();
          resolve({ status: "failed", prefixEnd: events.length, attempts: 0 });
        }, configuration.shutdownTimeoutMs);
      });
      const result = await Promise.race([pending, timeout]);
      if (timer !== undefined) clearTimeout(timer);
      state = "stopped";
      return result;
    })();
    return shutdownPromise;
  };

  const withKind =
    (kind: RuntimeObservationKind) =>
    (observation: Omit<RuntimeObservation, "kind">): boolean =>
      record({ ...observation, kind });

  return {
    descriptor,
    get state() {
      return state;
    },
    record,
    recordModule: withKind("module"),
    recordCall: withKind("call"),
    recordRoute: withKind("route"),
    recordRpc: withKind("rpc"),
    snapshot,
    flush,
    shutdown,
    stats: () => ({
      state,
      acceptedEvents: events.length,
      flushedPrefixes,
      dropped: { ...dropped },
    }),
  };
}

let temporaryFileOrdinal = 0;

export function createFileRuntimeCollectorSink(destination: string): RuntimeCollectorSink {
  if (!path.isAbsolute(destination)) {
    throw new Error("runtime collector file destination must be absolute");
  }
  return {
    kind: "file",
    async write(payload, context) {
      if (context.signal.aborted) throw new Error("runtime collector write aborted");
      try {
        const metadata = await lstat(destination);
        if (metadata.isSymbolicLink() || !metadata.isFile()) {
          throw new Error("runtime collector destination is not a regular file");
        }
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      }
      temporaryFileOrdinal += 1;
      const temporary = path.join(
        path.dirname(destination),
        `.${path.basename(destination)}.depgraph-${process.pid}-${temporaryFileOrdinal}.tmp`,
      );
      let handle;
      try {
        handle = await open(temporary, "wx", 0o600);
        await handle.writeFile(payload);
        await handle.sync();
        await handle.close();
        handle = undefined;
        if (context.signal.aborted) throw new Error("runtime collector write aborted");
        await rename(temporary, destination);
        if (context.signal.aborted) throw new Error("runtime collector write aborted");
      } finally {
        await handle?.close().catch(() => undefined);
        await unlink(temporary).catch(() => undefined);
      }
    },
  };
}

export function createStdoutRuntimeCollectorSink(
  stream: Writable = process.stdout,
): RuntimeCollectorSink {
  return {
    kind: "stdout",
    async write(payload, context) {
      if (context.signal.aborted) throw new Error("runtime collector write aborted");
      const line = Buffer.concat([Buffer.from(payload), Buffer.from("\n", "utf8")]);
      // Writable.write queues the complete line synchronously. Its callback is
      // not cancellable, so waiting for it could let a shutdown deadline pass
      // while an already-committed stdout write remains pending.
      stream.write(line);
    },
  };
}

export function createOtlpRuntimeCollectorSink(
  exportLogRecord: (record: OtlpRuntimeLogRecord, signal: AbortSignal) => Promise<void>,
): RuntimeCollectorSink {
  return {
    kind: "otlp",
    async write(payload, context) {
      if (context.signal.aborted) throw new Error("runtime collector write aborted");
      await exportLogRecord(
        {
          body: Buffer.from(payload),
          attributes: {
            "depgraph.collector.contract_version": context.contractVersion,
            "depgraph.runtime.media_type": context.mediaType,
            "depgraph.runtime.session_id": context.sessionId,
            "depgraph.runtime.prefix_end": context.prefixEnd,
          },
        },
        context.signal,
      );
      if (context.signal.aborted) throw new Error("runtime collector write aborted");
    },
  };
}
