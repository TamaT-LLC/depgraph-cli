import { createHash } from "node:crypto";
import { readFile, realpath, stat } from "node:fs/promises";
import path from "node:path";
import { normalizeRelative, WEB_SOURCE_EXTENSIONS } from "./fs";
import { compareUtf8 } from "./types";

/** Request contract negotiated by the core for bounded Web source batches. */
export const ANALYSIS_UNIT_CONTRACT_VERSION = "depgraph-analysis-unit-v2" as const;
export const ANALYSIS_SOURCE_BATCH_CAPABILITY = "analysis-source-batch-v1" as const;

export type AnalysisUnitStage = "syntax" | "semantic";

export interface AnalysisUnitRequest {
  contract_version: typeof ANALYSIS_UNIT_CONTRACT_VERSION;
  unit_id: string;
  adapter: "web";
  unit_root: string;
  source_paths: string[];
  stage: AnalysisUnitStage;
  context_paths: string[];
  chunk_id: string;
  chunk_index: number;
  chunk_count: number;
  /** Metadata owned by this chunk (manifests, configs, and lockfiles). */
  auxiliary_paths: string[];
  /** Digest of the complete compiler input closure, supplied by core. */
  context_fingerprint: string;
}

const MAX_REQUEST_BYTES = 4 * 1024 * 1024;
const MAX_PATH_CHARS = 4_096;
const MAX_ID_CHARS = 4_096;
// Core currently serializes this field as a bare lower-case SHA-256 digest;
// accept the prefixed spelling too so direct callers using the protocol's
// common fingerprint notation remain compatible.
const SHA256 = /^(?:[0-9a-f]{64}|sha256:[0-9a-f]{64})$/u;

// The core Web inventory also assigns Vue and Svelte source files to this
// adapter. They are retained as bounded, explicitly incomplete inputs here;
// the current parser can still account for their file coverage without
// pretending to extract TypeScript dependencies from them.
const ANALYSIS_UNIT_SOURCE_EXTENSIONS = new Set([
  ...WEB_SOURCE_EXTENSIONS,
  ".vue",
  ".svelte",
]);

const ANALYSIS_AUXILIARY_BASENAMES = new Set([
  "package.json",
  "pnpm-workspace.yaml",
  "pnpm-workspace.yml",
  "pnpm-lock.yaml",
  "yarn.lock",
  ".pnp.data.json",
  ".pnp.cjs",
  "bun.lock",
  "bun.lockb",
  "package-lock.json",
  "npm-shrinkwrap.json",
]);

function isAnalysisAuxiliaryPath(relativePath: string): boolean {
  const basename = path.basename(relativePath);
  return ANALYSIS_AUXILIARY_BASENAMES.has(basename)
    || /^(?:tsconfig|jsconfig)(?:\.[^.]+)*\.json$/u.test(basename)
    || /^(?:next|astro|vite|tanstack|router|webpack|rollup)\.config\.(?:js|jsx|ts|tsx|mjs|cjs)$/u.test(basename);
}

function isAncestorWorkspaceManifest(relativePath: string, unitRoot: string): boolean {
  const directory = path.posix.dirname(relativePath.replaceAll("\\", "/"));
  if (unitRoot === "." || path.posix.relative(directory, unitRoot).split("/").includes("..")) return false;
  const basename = path.basename(relativePath);
  return basename === "package.json" || basename === "pnpm-workspace.yaml" || basename === "pnpm-workspace.yml";
}

/** Profile identity is scoped to one source chunk and stage. */
export function analysisUnitProfileId(
  request: Pick<AnalysisUnitRequest, "unit_id" | "stage" | "chunk_id" | "chunk_index" | "chunk_count">,
  baseProfileId: string,
): string {
  const identity = JSON.stringify({
    base_profile: baseProfileId,
    contract_version: ANALYSIS_UNIT_CONTRACT_VERSION,
    stage: request.stage,
    unit_id: request.unit_id,
    chunk_id: request.chunk_id,
    chunk_index: request.chunk_index,
    chunk_count: request.chunk_count,
  });
  return `profile:sha256:${createHash("sha256").update(identity, "utf8").digest("hex")}`;
}

/** Structural graph identity is shared by all chunks in one unit/stage. */
export function analysisUnitLogicalProfileId(
  request: Pick<AnalysisUnitRequest, "unit_id" | "stage">,
  baseProfileId: string,
): string {
  const identity = JSON.stringify({
    base_profile: baseProfileId,
    contract_version: ANALYSIS_UNIT_CONTRACT_VERSION,
    stage: request.stage,
    unit_id: request.unit_id,
  });
  return `profile:sha256:${createHash("sha256").update(identity, "utf8").digest("hex")}`;
}

export function isCanonicalRepositoryPath(value: string, allowRoot = false): boolean {
  const portable = value.replaceAll("\\", "/");
  if (portable === ".") return allowRoot;
  return portable.length > 0
    && portable.length <= MAX_PATH_CHARS
    && !portable.includes("\0")
    && !portable.startsWith("/")
    && !/^[A-Za-z]:/u.test(portable)
    && !portable.split("/").some((part) => part === "" || part === "." || part === "..");
}

function isSortedUnique(values: readonly string[]): boolean {
  for (let index = 1; index < values.length; index += 1) {
    if (compareUtf8(values[index - 1]!, values[index]!) >= 0) return false;
  }
  return true;
}

function requestRecord(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("analysis unit request must be a JSON object");
  }
  return value as Record<string, unknown>;
}

function requiredString(record: Record<string, unknown>, key: string, max = MAX_ID_CHARS): string {
  const value = record[key];
  if (typeof value !== "string" || value.length === 0 || value.length > max || /[\u0000-\u001f\u007f]/u.test(value)) {
    throw new Error(`analysis unit request ${key} is empty or exceeds its limit`);
  }
  return value;
}

function pathList(record: Record<string, unknown>, key: string, allowEmpty = true): string[] {
  const value = record[key];
  if (!Array.isArray(value) || !value.every((item) => typeof item === "string")) {
    throw new Error(`analysis unit request ${key} must be an array of paths`);
  }
  const paths = value as string[];
  if (!allowEmpty && paths.length === 0) throw new Error(`analysis unit request ${key} must not be empty`);
  if (!isSortedUnique(paths)) throw new Error(`analysis unit request ${key} must be sorted and unique`);
  for (const item of paths) {
    if (!isCanonicalRepositoryPath(item)) throw new Error(`analysis unit request ${key} contains a non-canonical path`);
  }
  return [...paths];
}

interface ParsedAnalysisUnitIdentity {
  contract_version: typeof ANALYSIS_UNIT_CONTRACT_VERSION;
  unit_id: string;
  adapter: "web";
  unit_root: string;
  source_paths: string[];
  context_paths: string[];
  auxiliary_paths: string[];
}

function parseAnalysisUnitIdentity(record: Record<string, unknown>): ParsedAnalysisUnitIdentity {
  const contractVersion = requiredString(record, "contract_version", 128);
  if (contractVersion !== ANALYSIS_UNIT_CONTRACT_VERSION) {
    throw new Error(`analysis unit request contract version is unsupported: ${contractVersion}`);
  }
  const adapter = requiredString(record, "adapter", 32);
  if (adapter !== "web") throw new Error("analysis unit request adapter must be web");
  const unitId = requiredString(record, "unit_id");
  const unitRoot = requiredString(record, "unit_root", MAX_PATH_CHARS);
  if (!isCanonicalRepositoryPath(unitRoot, true)) throw new Error("analysis unit request unit_root is not canonical");
  return {
    contract_version: ANALYSIS_UNIT_CONTRACT_VERSION,
    unit_id: unitId,
    adapter: "web",
    unit_root: unitRoot,
    source_paths: pathList(record, "source_paths", true),
    context_paths: pathList(record, "context_paths", true),
    auxiliary_paths: pathList(record, "auxiliary_paths", true),
  };
}

function parseAnalysisUnitStage(record: Record<string, unknown>): AnalysisUnitStage {
  const stage = requiredString(record, "stage", 32);
  if (stage !== "syntax" && stage !== "semantic") throw new Error("analysis unit request stage must be syntax or semantic");
  return stage;
}

function isSafeNonNegativeInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

function requireAnalysisUnitChunkIndex(record: Record<string, unknown>): number {
  const value = record.chunk_index;
  if (!isSafeNonNegativeInteger(value)) {
    throw new Error("analysis unit request chunk_index must be a non-negative integer");
  }
  return value;
}

function requireAnalysisUnitChunkCount(record: Record<string, unknown>, chunkIndex: number): number {
  const value = record.chunk_count;
  if (!isSafeNonNegativeInteger(value) || value < 1 || chunkIndex >= value) {
    throw new Error("analysis unit request chunk_count is invalid");
  }
  return value;
}

function parseAnalysisUnitChunk(record: Record<string, unknown>): Pick<ParsedAnalysisUnitExecution, "chunk_index" | "chunk_count"> {
  const chunkIndex = requireAnalysisUnitChunkIndex(record);
  return { chunk_index: chunkIndex, chunk_count: requireAnalysisUnitChunkCount(record, chunkIndex) };
}

function parseAnalysisUnitContextFingerprint(record: Record<string, unknown>): string {
  const contextFingerprint = requiredString(record, "context_fingerprint", 128);
  if (!SHA256.test(contextFingerprint)) throw new Error("analysis unit request context_fingerprint is not sha256");
  return contextFingerprint;
}

interface ParsedAnalysisUnitExecution {
  stage: AnalysisUnitStage;
  chunk_id: string;
  chunk_index: number;
  chunk_count: number;
  context_fingerprint: string;
}

function parseAnalysisUnitExecution(record: Record<string, unknown>): ParsedAnalysisUnitExecution {
  const stage = parseAnalysisUnitStage(record);
  const chunkId = requiredString(record, "chunk_id");
  const chunk = parseAnalysisUnitChunk(record);
  return {
    stage,
    chunk_id: chunkId,
    ...chunk,
    context_fingerprint: parseAnalysisUnitContextFingerprint(record),
  };
}

function validateAnalysisUnitAuxiliaryPath(auxiliary: string, unitRoot: string): void {
  if (!isAnalysisAuxiliaryPath(auxiliary)) {
    throw new Error(`analysis unit auxiliary path ${auxiliary} is unsupported`);
  }
  if (!analysisUnitAuxiliaryPathWithinRoot(auxiliary, unitRoot)) {
    throw new Error(`analysis unit auxiliary path ${auxiliary} escapes unit_root ${unitRoot}`);
  }
}

function analysisUnitAuxiliaryPathWithinRoot(auxiliary: string, unitRoot: string): boolean {
  if (unitRoot === ".") return true;
  const unitPrefix = `${unitRoot}/`;
  return auxiliary.startsWith(unitPrefix) || isAncestorWorkspaceManifest(auxiliary, unitRoot);
}

function validateAnalysisUnitAuxiliaryPaths(identity: ParsedAnalysisUnitIdentity): void {
  for (const auxiliary of identity.auxiliary_paths) validateAnalysisUnitAuxiliaryPath(auxiliary, identity.unit_root);
}

function validateAnalysisUnitSourceMembership(source: string, contextPaths: ReadonlySet<string>): void {
  if (!contextPaths.has(source)) throw new Error(`analysis unit source path ${source} is missing from context_paths`);
}

function validateAnalysisUnitSourceExtension(source: string): void {
  if (!ANALYSIS_UNIT_SOURCE_EXTENSIONS.has(path.extname(source).toLowerCase())) {
    throw new Error(`analysis unit source path ${source} is not a supported Web source`);
  }
}

function validateAnalysisUnitSourceRoot(source: string, unitRoot: string): void {
  const withinUnit = unitRoot === "." || source === unitRoot || source.startsWith(`${unitRoot}/`);
  if (!withinUnit) throw new Error(`analysis unit source path ${source} escapes unit_root ${unitRoot}`);
}

function validateAnalysisUnitSourcePaths(identity: ParsedAnalysisUnitIdentity): void {
  const contextSet = new Set(identity.context_paths);
  for (const source of identity.source_paths) {
    validateAnalysisUnitSourceMembership(source, contextSet);
    validateAnalysisUnitSourceExtension(source);
    validateAnalysisUnitSourceRoot(source, identity.unit_root);
  }
}

function validateAnalysisUnitPathScopes(identity: ParsedAnalysisUnitIdentity): void {
  validateAnalysisUnitAuxiliaryPaths(identity);
  validateAnalysisUnitSourcePaths(identity);
}

/** Parse and validate the JSON shape before the request can influence a scan. */
export function parseAnalysisUnitRequest(value: unknown): AnalysisUnitRequest {
  const record = requestRecord(value);
  const identity = parseAnalysisUnitIdentity(record);
  const execution = parseAnalysisUnitExecution(record);
  validateAnalysisUnitPathScopes(identity);
  return {
    ...identity,
    ...execution,
  };
}

/** Read a bounded request file and reject trailing JSON or unknown fields. */
export async function readAnalysisUnitRequest(file: string): Promise<AnalysisUnitRequest> {
  const metadata = await stat(file);
  if (!metadata.isFile() || metadata.size > MAX_REQUEST_BYTES) {
    throw new Error("analysis unit request is not a regular file within its byte limit");
  }
  const source = await readFile(file, "utf8");
  const parsed = JSON.parse(source) as unknown;
  const record = requestRecord(parsed);
  const allowed = new Set([
    "contract_version", "unit_id", "adapter", "unit_root", "source_paths", "stage",
    "context_paths", "chunk_id", "chunk_index", "chunk_count", "auxiliary_paths", "context_fingerprint",
  ]);
  for (const key of Object.keys(record)) {
    if (!allowed.has(key)) throw new Error(`analysis unit request contains unknown field ${key}`);
  }
  return parseAnalysisUnitRequest(parsed);
}

/** Apply repository inventory and symlink confinement checks to a valid shape. */
export async function validateAnalysisUnitForRoot(
  root: string,
  allFiles: readonly string[],
  request: AnalysisUnitRequest,
): Promise<void> {
  const canonicalRoot = await realpath(root);
  const lexicalRoot = path.resolve(root);
  // Direct library callers may provide the same files through a symlinked
  // temp directory while the worker entrypoint already canonicalizes root.
  // Keep both spellings in the inventory witness; requested paths still pass
  // the canonical realpath confinement check below.
  const inventory = new Set(allFiles.flatMap((file) => [
    normalizeRelative(path.relative(lexicalRoot, path.resolve(file))),
    normalizeRelative(path.relative(canonicalRoot, path.resolve(file))),
  ]));
  const unitAbsolute = request.unit_root === "."
    ? canonicalRoot
    : path.resolve(canonicalRoot, ...request.unit_root.split("/"));
  const canonicalUnit = await realpath(unitAbsolute).catch(() => unitAbsolute);
  if (canonicalUnit !== canonicalRoot && !canonicalUnit.startsWith(`${canonicalRoot}${path.sep}`)) {
    throw new Error(`analysis unit unit_root ${request.unit_root} escapes repository root`);
  }
  for (const relative of [...request.context_paths, ...request.source_paths, ...request.auxiliary_paths]) {
    if (!inventory.has(relative)) throw new Error(`analysis unit path ${relative} is absent from the repository inventory`);
    const absolute = path.resolve(canonicalRoot, ...relative.split("/"));
    const canonical = await realpath(absolute).catch(() => absolute);
    if (canonical !== canonicalRoot && !canonical.startsWith(`${canonicalRoot}${path.sep}`)) {
      throw new Error(`analysis unit path ${relative} escapes repository root after symlink resolution`);
    }
  }
}
