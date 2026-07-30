import type { ChildProcess } from "node:child_process";
import { constants as fsConstants } from "node:fs";
import { access, readFile, readdir, realpath, stat } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";
import { API, type Diagnostic as CompilerDiagnostic } from "typescript/unstable/async";
import {
  SyntaxKind,
  type ExportDeclaration,
  type ImportDeclaration,
  type ImportEqualsDeclaration,
  type Node,
  type SourceFile,
} from "typescript/unstable/ast";
import type { FileSystem, FileSystemEntries } from "typescript/unstable/fs";
import { compareUtf8, type TypeScriptProjectSummary } from "./types";
import { NOOP_PROGRESS, type ProgressReporter } from "./progress";
import {
  extractTypeScriptRawDefinitionDelta,
  TYPESCRIPT_SEMANTIC_MAX_SOURCE_FILES,
  type TypeScriptRawDefinitionDelta,
} from "./typescript-semantic";
import {
  extractTypeScriptRawDependencyDelta,
  type TypeScriptCallValidationSpan,
  type TypeScriptModuleCallValidationSpan,
  type TypeScriptNonLiteralModuleValidationSpan,
  type TypeScriptRawDependencyDelta,
  type TypeScriptTypeUseValidationSpan,
} from "./typescript-dependencies";

export const TYPESCRIPT_COMPILER_VERSION = ts.version;
const TYPESCRIPT_RELEASE_GATE_VERIFIED = "release-gate-verified";
const TYPESCRIPT_RELEASE_GATE_PENDING = "release-gate-pending";
export const TYPESCRIPT_RELEASE_GATE = process.env.DEPGRAPH_TYPESCRIPT_RELEASE_GATE === TYPESCRIPT_RELEASE_GATE_VERIFIED
  ? TYPESCRIPT_RELEASE_GATE_VERIFIED
  : TYPESCRIPT_RELEASE_GATE_PENDING;
export const TYPESCRIPT_COMPILER_PROFILE_PROPERTIES = Object.freeze({
  bundled_typescript: "true",
  typescript_syntax_compiler: `native-${TYPESCRIPT_COMPILER_VERSION}`,
  typescript_compiler_source: "bundled",
  typescript_compiler_version: TYPESCRIPT_COMPILER_VERSION,
  typescript_compiler_selection: "bundled-only",
  typescript_compiler_fallback: "fail-closed",
  typescript_analysis_mode: "semantic-import-type-call-graph",
  typescript_project_local_policy: "metadata-only",
  typescript_project_local_loaded: "false",
  typescript_typechecker_status: "definition-import-type-call-graph-emitted",
  typescript_project_model_status: "ready",
  typescript_project_config: "worker-neutral-allowlist",
  typescript_module_resolution: "inventory-only",
  typescript_standard_library_source: "bundled",
  typescript_standard_library_integrity: TYPESCRIPT_RELEASE_GATE === TYPESCRIPT_RELEASE_GATE_VERIFIED
    ? "core-attested-whole-tree"
    : "build-produced-pending-core-attestation",
  typescript_release_gate: TYPESCRIPT_RELEASE_GATE,
  typescript_semantic_graph_emission: "definition-import-type-call-graph-v2",
  typescript_compiler_processes: "1",
  typescript_project_filesystem: "isolated-virtual",
} as const);
const COMPILER_TIMEOUT_MS = 30_000;
const MAX_SEMANTIC_DIAGNOSTICS = 256;
const MAX_DIAGNOSTIC_MESSAGE_CHARS = 2_048;
const MAX_STANDARD_LIBRARY_BYTES = 64 * 1024 * 1024;
const COMPILER_BASENAME = process.platform === "win32" ? "tsc.exe" : "tsc";
declare const __DEPGRAPH_PACKAGED_WORKER__: boolean;
const PACKAGED_WORKER = typeof __DEPGRAPH_PACKAGED_WORKER__ !== "undefined" && __DEPGRAPH_PACKAGED_WORKER__;
const VIRTUAL_ROOT = path.join(path.parse(process.execPath).root, "__depgraph_typescript_project__");
const VIRTUAL_CONFIG = path.join(VIRTUAL_ROOT, "tsconfig.json");
const NEUTRAL_CWD = path.parse(process.execPath).root;

export const TYPESCRIPT_SOURCE_EXTENSIONS = new Set([
  ".ts",
  ".tsx",
  ".mts",
  ".cts",
  ".js",
  ".jsx",
  ".mjs",
  ".cjs",
]);

export interface TypeScriptSyntaxDiagnostic {
  relativePath: string;
  code: number;
  message: string;
  startOffset: number;
  endOffset: number;
}

export interface TypeScriptSemanticDiagnostic {
  relativePath: string | null;
  code: number;
  message: string;
  startOffset: number;
  endOffset: number;
}

export interface TypeScriptStaticConfig {
  configFiles: number;
  paths: Readonly<Record<string, readonly string[]>>;
  /** User-declared safe path patterns; worker-internal package mappings excluded. */
  pathMappings?: number;
}

/**
 * A parser-confirmed source range whose dependency is erased from runtime
 * JavaScript. `import_type` also covers ImportType nodes attached to JSDoc,
 * which the trivia-skipping dependency tokenizer cannot otherwise observe.
 */
export interface TypeOnlyDependencyRange {
  startOffset: number;
  endOffset: number;
  syntax: "declaration" | "import_type";
}

export class TypeScriptProjectAnalysis extends Map<string, TypeScriptSyntaxDiagnostic[]> {
  readonly semanticSourceFiles = new Map<string, SourceFile>();
  readonly typeOnlyDependencyRanges = new Map<string, TypeOnlyDependencyRange[]>();
  readonly importTypeModuleSpans = new Map<string, Array<{ startOffset: number; endOffset: number }>>();
  readonly moduleCallSpans = new Map<string, TypeScriptModuleCallValidationSpan[]>();
  readonly nonLiteralModuleSpans = new Map<string, TypeScriptNonLiteralModuleValidationSpan[]>();
  readonly typeUseSpans = new Map<string, TypeScriptTypeUseValidationSpan[]>();
  readonly callSpans = new Map<string, TypeScriptCallValidationSpan[]>();
  readonly semanticDiagnostics: TypeScriptSemanticDiagnostic[] = [];
  definitionGraph: TypeScriptRawDefinitionDelta = {
    definitions: [],
    relations: [],
    issues: [],
    typeCheckerQueries: 0,
  };
  dependencyGraph: TypeScriptRawDependencyDelta = {
    sites: [],
    calls: [],
    moduleExports: [],
    issues: [],
    typeCheckerQueries: 0,
  };
  project: TypeScriptProjectSummary = {
    status: "ready",
    rootFiles: 0,
    programFiles: 0,
    staticConfigFiles: 0,
    pathMappings: 0,
    standardLibraryFiles: 0,
    typeCheckerQueries: 0,
    semanticDiagnostics: 0,
    emittedSemanticDiagnostics: 0,
    definitionGraphStatus: "ready",
    semanticNodes: 0,
    semanticRelations: 0,
    semanticSites: 0,
    semanticCallSites: 0,
    semanticIssues: 0,
  };
}

interface CompilerConnection {
  onError(listener: (error: Error) => void): { dispose(): void };
  onClose(listener: () => void): { dispose(): void };
}

interface CompilerClientInternals {
  client?: {
    process?: ChildProcess;
    connection?: CompilerConnection;
  };
}

class CompilerTimeoutError extends Error {}
class CompilerProtocolError extends Error {}

export type TypeScriptProjectFailureReason =
  | "compiler_unavailable"
  | "stdlib_unavailable"
  | "project_count_mismatch"
  | "root_file_mismatch"
  | "unexpected_program_input"
  | "typechecker_smoke_failed"
  | "compiler_timeout"
  | "compiler_protocol_failure";

export class TypeScriptProjectError extends Error {
  readonly reason: TypeScriptProjectFailureReason;

  constructor(reason: TypeScriptProjectFailureReason, message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "TypeScriptProjectError";
    this.reason = reason;
  }
}

function pathKey(value: string): string {
  const normalized = path.normalize(path.resolve(value));
  return process.platform === "win32" ? normalized.toLowerCase() : normalized;
}

export function isConfinedTypeScriptInputPath(value: string): boolean {
  const portable = value.replaceAll("\\", "/");
  return portable.length > 0
    && !path.posix.isAbsolute(portable)
    && !/^[A-Za-z]:/u.test(portable)
    && !portable.includes("\0")
    && !portable.split("/").some((part) => part === "" || part === "." || part === "..");
}

async function usableCompiler(candidate: string): Promise<string | null> {
  try {
    const resolved = await realpath(candidate);
    if (!(await stat(resolved)).isFile()) return null;
    if (process.platform !== "win32") await access(resolved, fsConstants.X_OK);
    return resolved;
  } catch {
    return null;
  }
}

/** Resolve only build-produced artifacts at fixed paths relative to this file. */
export async function resolveTypeScriptCompiler(): Promise<string> {
  const adjacent = fileURLToPath(new URL(`./typescript/lib/${COMPILER_BASENAME}`, import.meta.url));
  const bundled = await usableCompiler(adjacent);
  if (bundled !== null) return bundled;

  // The release bundle receives this compile-time marker from build.mjs. A
  // relocated or incomplete release must fail here: package resolution could
  // otherwise select node_modules owned by the repository being scanned.
  if (PACKAGED_WORKER) {
    throw new Error(`bundled TypeScript ${TYPESCRIPT_COMPILER_VERSION} compiler is missing next to packaged worker: ${adjacent}`);
  }

  // Source-mode tests and development run only after `pnpm build`; point them
  // explicitly at that verified build artifact. This path is independent of
  // cwd and the scan root and never walks ancestor node_modules directories.
  const developmentArtifact = fileURLToPath(new URL(`../dist/typescript/lib/${COMPILER_BASENAME}`, import.meta.url));
  const developmentCompiler = await usableCompiler(developmentArtifact);
  if (developmentCompiler !== null) return developmentCompiler;
  throw new Error(`bundled TypeScript ${TYPESCRIPT_COMPILER_VERSION} development compiler is unavailable; run pnpm build: ${developmentArtifact}`);
}

interface BundledStandardLibrary {
  files: Map<string, string>;
  root: string;
}

export interface TypeScriptAnalysisTestRuntime {
  compiler: string;
  standardLibraryRoot: string;
  timeoutMs: number;
}

export type TypeScriptLifecycleTestMode = "crash" | "protocol-error" | "timeout" | "strict-close";

export interface TypeScriptLifecycleTestResult {
  reason: TypeScriptProjectFailureReason;
  reaped: boolean;
  listenersDisposed: boolean;
}

/**
 * Load only the declaration files shipped beside the already selected native
 * compiler. Release scans reach this point after the core has verified the
 * component's whole-tree digest; source scans use the build-produced copy.
 */
async function loadBundledStandardLibrary(
  compiler: string,
  standardLibraryRoot = path.dirname(compiler),
): Promise<BundledStandardLibrary> {
  const root = await realpath(standardLibraryRoot);
  const entries = (await readdir(root, { withFileTypes: true }))
    .filter((entry) => /^lib(?:\.[a-z0-9_-]+)*\.d\.ts$/iu.test(entry.name))
    .sort((left, right) => compareUtf8(left.name, right.name));
  if (entries.length === 0) {
    throw new Error(`bundled TypeScript ${TYPESCRIPT_COMPILER_VERSION} standard library is missing beside ${compiler}`);
  }
  const files = new Map<string, string>();
  let totalBytes = 0;
  for (const entry of entries) {
    if (!entry.isFile() || entry.isSymbolicLink()) {
      throw new Error(`bundled TypeScript standard library entry is not a regular file: ${path.join(root, entry.name)}`);
    }
    const candidate = path.join(root, entry.name);
    const resolved = await realpath(candidate);
    if (pathKey(path.dirname(resolved)) !== pathKey(root)) {
      throw new Error(`bundled TypeScript standard library escaped its component root: ${candidate}`);
    }
    const metadata = await stat(resolved);
    if (!metadata.isFile()) throw new Error(`bundled TypeScript standard library entry is not a file: ${candidate}`);
    totalBytes += metadata.size;
    if (totalBytes > MAX_STANDARD_LIBRARY_BYTES) {
      throw new Error(`bundled TypeScript standard library exceeds ${MAX_STANDARD_LIBRARY_BYTES} bytes`);
    }
    files.set(resolved, await readFile(resolved, "utf8"));
  }
  for (const required of ["lib.esnext.full.d.ts", "lib.es5.d.ts"]) {
    if (![...files.keys()].some((file) => path.basename(file) === required)) {
      throw new Error(`bundled TypeScript standard library is incomplete: ${required} is missing`);
    }
  }
  return { files, root };
}

function addDirectory(
  directories: Map<string, { path: string; files: Set<string>; directories: Set<string> }>,
  directory: string,
): void {
  let current = path.resolve(directory);
  for (;;) {
    const key = pathKey(current);
    if (!directories.has(key)) directories.set(key, { path: current, files: new Set(), directories: new Set() });
    const parent = path.dirname(current);
    if (parent === current) break;
    const parentKey = pathKey(parent);
    if (!directories.has(parentKey)) directories.set(parentKey, { path: parent, files: new Set(), directories: new Set() });
    directories.get(parentKey)!.directories.add(path.basename(current));
    current = parent;
  }
}

function virtualFileSystem(files: ReadonlyMap<string, string>): FileSystem {
  const content = new Map<string, string>();
  const directories = new Map<string, { path: string; files: Set<string>; directories: Set<string> }>();
  for (const [file, source] of files) {
    const absolute = path.resolve(file);
    content.set(pathKey(absolute), source);
    const directory = path.dirname(absolute);
    addDirectory(directories, directory);
    directories.get(pathKey(directory))!.files.add(path.basename(absolute));
  }
  return {
    readFile: (fileName): string | null => content.get(pathKey(fileName)) ?? null,
    fileExists: (fileName): boolean => content.has(pathKey(fileName)),
    directoryExists: (directoryName): boolean => directories.has(pathKey(directoryName)),
    getAccessibleEntries: (directoryName): FileSystemEntries => {
      const entry = directories.get(pathKey(directoryName));
      return {
        files: entry ? [...entry.files].sort() : [],
        directories: entry ? [...entry.directories].sort() : [],
      };
    },
    // Returning a value for every request prevents fallback to the native
    // filesystem while retaining the compiler's normal lexical path rules.
    realpath: (fileName): string => path.normalize(path.resolve(fileName)),
  };
}

function neutralEnvironment(original: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  const find = (name: string): string | undefined => Object.entries(original)
    .find(([key]) => key.toLowerCase() === name.toLowerCase())?.[1];
  const systemRoot = find("SystemRoot") ?? find("WINDIR");
  const temp = process.platform === "win32" && systemRoot ? path.join(systemRoot, "Temp") : "/tmp";
  const result: NodeJS.ProcessEnv = {
    HOME: temp,
    USERPROFILE: temp,
    TMPDIR: temp,
    TEMP: temp,
    TMP: temp,
    PATH: "",
    LANG: "C",
    LC_ALL: "C",
    NO_COLOR: "1",
  };
  for (const key of ["SystemRoot", "WINDIR", "ComSpec"] as const) {
    const value = find(key);
    if (value !== undefined) result[key] = value;
  }
  return result;
}

function replaceProcessEnvironment(environment: NodeJS.ProcessEnv): void {
  for (const key of Object.keys(process.env)) delete process.env[key];
  for (const [key, value] of Object.entries(environment)) {
    if (value !== undefined) process.env[key] = value;
  }
}

async function withNeutralEnvironment<T>(operation: () => Promise<T>): Promise<T> {
  const original = { ...process.env };
  replaceProcessEnvironment(neutralEnvironment(original));
  try {
    return await operation();
  } finally {
    replaceProcessEnvironment(original);
  }
}

function flattenDiagnosticMessage(diagnostic: CompilerDiagnostic): string {
  const nested = diagnostic.messageChain?.map(flattenDiagnosticMessage).filter(Boolean) ?? [];
  return [diagnostic.text, ...nested].filter(Boolean).join(" ");
}

function boundedDiagnosticMessage(diagnostic: CompilerDiagnostic, redactions: readonly string[]): string {
  let message = flattenDiagnosticMessage(diagnostic).replace(/[\r\n\t]+/gu, " ");
  for (const value of redactions.filter(Boolean).sort((left, right) => right.length - left.length)) {
    message = message.replaceAll(value, "<trusted-typescript>");
    message = message.replaceAll(value.replaceAll("\\", "/"), "<trusted-typescript>");
  }
  if (message.length <= MAX_DIAGNOSTIC_MESSAGE_CHARS) return message;
  return `${message.slice(0, MAX_DIAGNOSTIC_MESSAGE_CHARS - 1)}…`;
}

function isEntirelyTypeOnlyImport(node: ImportDeclaration): boolean {
  const clause = node.importClause;
  if (clause === undefined) return false;
  if (clause.phaseModifier === SyntaxKind.TypeKeyword) return true;
  if (clause.name !== undefined || clause.namedBindings?.kind !== SyntaxKind.NamedImports) return false;
  return clause.namedBindings.elements.length > 0
    && clause.namedBindings.elements.every((element) => element.isTypeOnly);
}

function isEntirelyTypeOnlyExport(node: ExportDeclaration): boolean {
  if (node.isTypeOnly) return true;
  if (node.exportClause?.kind !== SyntaxKind.NamedExports) return false;
  return node.exportClause.elements.length > 0
    && node.exportClause.elements.every((element) => element.isTypeOnly);
}

function typeOnlyDependencyRanges(sourceFile: SourceFile): TypeOnlyDependencyRange[] {
  const ranges: TypeOnlyDependencyRange[] = [];
  const visited = new WeakSet<object>();
  const add = (node: Node, syntax: TypeOnlyDependencyRange["syntax"]): void => {
    ranges.push({
      startOffset: Math.max(0, node.pos),
      endOffset: Math.min(sourceFile.text.length, node.end),
      syntax,
    });
  };
  const visit = (node: Node): void => {
    if (visited.has(node)) return;
    visited.add(node);
    if (node.kind === SyntaxKind.ImportType) {
      add(node, "import_type");
    } else if (node.kind === SyntaxKind.ImportDeclaration && isEntirelyTypeOnlyImport(node as ImportDeclaration)) {
      add(node, "declaration");
    } else if (node.kind === SyntaxKind.ImportEqualsDeclaration && (node as ImportEqualsDeclaration).isTypeOnly) {
      add(node, "declaration");
    } else if (node.kind === SyntaxKind.ExportDeclaration && isEntirelyTypeOnlyExport(node as ExportDeclaration)) {
      add(node, "declaration");
    }
    // JSDoc is stored outside the normal child array on several declaration
    // nodes. Visit it explicitly; WeakSet de-duplicates compiler versions that
    // also expose the same nodes through forEachChild.
    for (const jsDoc of node.jsDoc ?? []) visit(jsDoc);
    node.forEachChild((child) => {
      visit(child);
      return undefined;
    });
  };
  visit(sourceFile);
  return ranges
    .filter((range) => range.endOffset > range.startOffset)
    .filter((range, index, all) => all.findIndex((candidate) => (
      candidate.startOffset === range.startOffset
      && candidate.endOffset === range.endOffset
      && candidate.syntax === range.syntax
    )) === index)
    .sort((left, right) => left.startOffset - right.startOffset || left.endOffset - right.endOffset || compareUtf8(left.syntax, right.syntax));
}

function compilerProcess(api: API): ChildProcess | undefined {
  return (api as unknown as CompilerClientInternals).client?.process;
}

async function waitForExit(child: ChildProcess, timeoutMs: number): Promise<boolean> {
  if (child.exitCode !== null || child.signalCode !== null) return true;
  return await new Promise<boolean>((resolve) => {
    const timer = setTimeout(() => {
      child.off("exit", exited);
      resolve(false);
    }, timeoutMs);
    timer.unref();
    const exited = (): void => {
      clearTimeout(timer);
      resolve(true);
    };
    child.once("exit", exited);
  });
}

async function closeCompiler(
  api: API,
  force: boolean,
  retainedChild: ChildProcess | undefined = compilerProcess(api),
): Promise<void> {
  const child = retainedChild;
  if (force) {
    child?.kill("SIGKILL");
    let closeTimer: NodeJS.Timeout | undefined;
    await Promise.race([
      api.close().catch(() => undefined),
      new Promise<void>((resolve) => {
        closeTimer = setTimeout(resolve, 1_000);
      }),
    ]);
    if (closeTimer) clearTimeout(closeTimer);
    if (child && !(await waitForExit(child, 1_000))) {
      child.kill("SIGKILL");
      if (!(await waitForExit(child, 1_000))) {
        throw new CompilerProtocolError("TypeScript native compiler could not be reaped after forced close");
      }
    }
    return;
  }

  let closeTimer: NodeJS.Timeout | undefined;
  const closeResult = await Promise.race([
    api.close().then(
      () => ({ status: "closed" as const }),
      () => ({ status: "failed" as const }),
    ),
    new Promise<{ status: "timeout" }>((resolve) => {
      closeTimer = setTimeout(() => resolve({ status: "timeout" }), 1_000);
    }),
  ]);
  if (closeTimer) clearTimeout(closeTimer);
  if (closeResult.status !== "closed") {
    child?.kill("SIGKILL");
    if (child) await waitForExit(child, 1_000);
    throw new CompilerProtocolError(`TypeScript native compiler close ${closeResult.status}`);
  }
  if (child && !(await waitForExit(child, 1_000))) {
    child.kill("SIGKILL");
    if (!(await waitForExit(child, 1_000))) {
      child.kill("SIGKILL");
      if (!(await waitForExit(child, 1_000))) {
        throw new CompilerProtocolError("TypeScript native compiler could not be reaped after strict close");
      }
    }
    throw new CompilerProtocolError("TypeScript native compiler did not exit after close");
  }
  if (child && (child.signalCode !== null || child.exitCode !== 0)) {
    throw new CompilerProtocolError("TypeScript native compiler exited unsuccessfully during close");
  }
}

function monitorCompilerLifecycle(api: API): { failure: Promise<never>; stop(): void } {
  const client = (api as unknown as CompilerClientInternals).client;
  let child: ChildProcess | undefined;
  let connection: CompilerConnection | undefined;
  let stopped = false;
  let rejectFailure: (error: CompilerProtocolError) => void = () => undefined;
  const disposables: Array<{ dispose(): void }> = [];
  const failure = new Promise<never>((_resolve, reject) => {
    rejectFailure = reject;
  });
  const childExited = (code: number | null, signal: NodeJS.Signals | null): void => {
    fail(`TypeScript native compiler exited during analysis (code=${code ?? "none"}, signal=${signal ?? "none"})`);
  };
  const childErrored = (): void => {
    fail("TypeScript native compiler process failed during analysis");
  };
  const cleanup = (): void => {
    clearInterval(poll);
    child?.off("exit", childExited);
    child?.off("error", childErrored);
    for (const disposable of disposables.splice(0)) disposable.dispose();
  };
  const fail = (message: string): void => {
    if (stopped) return;
    stopped = true;
    cleanup();
    rejectFailure(new CompilerProtocolError(message));
  };
  const attach = (): void => {
    if (stopped) return;
    if (!child && client?.process) {
      child = client.process;
      if (child.exitCode !== null || child.signalCode !== null) {
        childExited(child.exitCode, child.signalCode);
        return;
      }
      child.once("exit", childExited);
      child.once("error", childErrored);
    }
    if (!connection && client?.connection) {
      connection = client.connection;
      disposables.push(connection.onError(() => fail("TypeScript native compiler protocol failed during analysis")));
      disposables.push(connection.onClose(() => fail("TypeScript native compiler protocol closed during analysis")));
    }
    if (child && connection) clearInterval(poll);
  };
  const poll = setInterval(attach, 2);
  attach();
  return {
    failure,
    stop: () => {
      if (stopped) return;
      stopped = true;
      cleanup();
    },
  };
}

function withTimeout<T>(operation: Promise<T>, timeoutMs: number): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => reject(new CompilerTimeoutError(`TypeScript native project analysis timed out after ${timeoutMs}ms`)), timeoutMs);
    operation.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      (error: unknown) => {
        clearTimeout(timer);
        reject(error);
      },
    );
  });
}

async function runCompilerOperation<T>(api: API, operation: Promise<T>, timeoutMs: number): Promise<T> {
  const lifecycle = monitorCompilerLifecycle(api);
  let retainedChild: ChildProcess | undefined;
  try {
    const result = await withTimeout(Promise.race([operation, lifecycle.failure]), timeoutMs);
    lifecycle.stop();
    retainedChild = compilerProcess(api);
    await closeCompiler(api, false, retainedChild);
    return result;
  } catch (error) {
    lifecycle.stop();
    void operation.catch(() => undefined);
    retainedChild ??= compilerProcess(api);
    await closeCompiler(api, true, retainedChild);
    throw error;
  }
}

function semanticDiagnostic(
  diagnostic: CompilerDiagnostic,
  sources: ReadonlyMap<string, string>,
  virtualToRelative: ReadonlyMap<string, string>,
  allowedCompilerFiles: ReadonlySet<string>,
  trustedRoot: string,
): TypeScriptSemanticDiagnostic {
  if (!diagnostic.fileName) {
    return {
      relativePath: null,
      code: diagnostic.code,
      message: boundedDiagnosticMessage(diagnostic, [VIRTUAL_ROOT, trustedRoot]),
      startOffset: 0,
      endOffset: 0,
    };
  }
  const fileKey = pathKey(diagnostic.fileName);
  const relativePath = virtualToRelative.get(fileKey) ?? null;
  if (relativePath === null && !allowedCompilerFiles.has(fileKey)) {
    throw new Error(`TypeScript native semantic diagnostic escaped the isolated project: ${diagnostic.fileName}`);
  }
  const source = relativePath === null ? "" : sources.get(relativePath);
  if (source === undefined) throw new Error(`TypeScript semantic input disappeared for ${relativePath}`);
  const startOffset = Math.max(0, Math.min(source.length, diagnostic.pos));
  const endOffset = Math.max(startOffset, Math.min(source.length, diagnostic.end));
  return {
    relativePath,
    code: diagnostic.code,
    message: boundedDiagnosticMessage(diagnostic, [VIRTUAL_ROOT, trustedRoot]),
    startOffset,
    endOffset,
  };
}

/** Run one trusted native TypeScript Program and TypeChecker for one scan. */
async function analyzeTypeScriptProjectInner(
  sources: ReadonlyMap<string, string>,
  staticConfig: TypeScriptStaticConfig,
  testRuntime?: TypeScriptAnalysisTestRuntime,
  progress: ProgressReporter = NOOP_PROGRESS,
): Promise<TypeScriptProjectAnalysis> {
  progress.start("typescript_compiler_setup", { source_files: sources.size });
  // Validate the selected compiler even for repositories with no TS/JS
  // sources. The profile must not attest to a bundled, fail-closed compiler
  // that was never resolved.
  const compiler = testRuntime?.compiler ?? await resolveTypeScriptCompiler();
  let standardLibrary: BundledStandardLibrary;
  try {
    standardLibrary = await loadBundledStandardLibrary(
      compiler,
      testRuntime?.standardLibraryRoot,
    );
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    throw new Error(`bundled TypeScript standard library is unavailable: ${detail}`, { cause: error });
  }
  const result = new TypeScriptProjectAnalysis();

  const virtualFiles = new Map<string, string>();
  const virtualToRelative = new Map<string, string>();
  const configFiles: string[] = [];
  for (const [file, source] of standardLibrary.files) virtualFiles.set(file, source);
  for (const [relativePath, source] of [...sources].sort(([left], [right]) => compareUtf8(left, right))) {
    if (!isConfinedTypeScriptInputPath(relativePath) || !TYPESCRIPT_SOURCE_EXTENSIONS.has(path.extname(relativePath).toLowerCase())) {
      throw new Error(`refusing unsafe or unsupported TypeScript project input path: ${relativePath}`);
    }
    const portable = relativePath.replaceAll("\\", "/");
    const virtualPath = path.join(VIRTUAL_ROOT, ...portable.split("/"));
    virtualFiles.set(virtualPath, source);
    virtualToRelative.set(pathKey(virtualPath), portable);
    configFiles.push(portable);
    result.set(portable, []);
    result.typeOnlyDependencyRanges.set(portable, []);
    result.importTypeModuleSpans.set(portable, []);
    result.moduleCallSpans.set(portable, []);
    result.nonLiteralModuleSpans.set(portable, []);
    result.typeUseSpans.set(portable, []);
    result.callSpans.set(portable, []);
  }
  const internalRoot = path.join(VIRTUAL_ROOT, "__depgraph_empty_project__.d.ts");
  if (configFiles.length === 0) {
    virtualFiles.set(internalRoot, "declare const __depgraph_empty_project__: unique symbol;\n");
    configFiles.push(path.basename(internalRoot));
  }
  virtualFiles.set(VIRTUAL_CONFIG, `${JSON.stringify({
    compilerOptions: {
      allowJs: true,
      allowImportingTsExtensions: true,
      checkJs: false,
      jsx: "preserve",
      module: "preserve",
      moduleDetection: "force",
      moduleResolution: "bundler",
      noEmit: true,
      paths: Object.fromEntries(Object.entries(staticConfig.paths).map(([pattern, replacements]) => [
        pattern,
        replacements.map((replacement) => replacement.startsWith(".") ? replacement : `./${replacement}`),
      ])),
      plugins: [],
      skipLibCheck: true,
      target: "esnext",
      typeRoots: [],
      types: [],
      verbatimModuleSyntax: true,
    },
    files: configFiles,
  })}\n`);

  const api = new API({
    cwd: NEUTRAL_CWD,
    fs: virtualFileSystem(virtualFiles),
    tsserverPath: compiler,
  });
  progress.complete("typescript_compiler_setup", { source_files: sources.size });
  const operation = (async (): Promise<void> => {
    progress.start("typescript_project_open", { source_files: sources.size });
    const snapshot = await withNeutralEnvironment(() => api.updateSnapshot({ openProjects: [VIRTUAL_CONFIG] }));
    try {
      const projects = snapshot.getProjects();
      if (projects.length !== 1) throw new Error(`TypeScript native project analysis opened ${projects.length} projects instead of one neutral project`);
      const project = projects[0]!;
      progress.complete("typescript_project_open", { source_files: sources.size });
      progress.start("typescript_ast_transfer", { source_files: sources.size });
      const actualRoots = new Set(project.rootFiles.map(pathKey));
      const sourceFiles = new Map<string, SourceFile>();
      const dependencyValidationQueryBudget = { value: 0 };
      const definitionSourceLimitExceeded = virtualToRelative.size > TYPESCRIPT_SEMANTIC_MAX_SOURCE_FILES;
      if (definitionSourceLimitExceeded) {
        result.definitionGraph = {
          definitions: [],
          relations: [],
          issues: [{
            code: "typescript_semantic_source_limit_exceeded",
            message: `TypeScript semantic definition extraction received ${virtualToRelative.size} sources; limit=${TYPESCRIPT_SEMANTIC_MAX_SOURCE_FILES}`,
            relativePath: null,
            fatal: true,
          }],
          typeCheckerQueries: 0,
        };
      }
      for (const virtualPath of virtualToRelative.keys()) {
        if (!actualRoots.has(virtualPath)) throw new Error(`TypeScript native project analysis omitted ${virtualToRelative.get(virtualPath)}`);
        // Source count can be rejected before transferring remote ASTs. The
        // node-count guard necessarily runs after getSourceFile because the
        // async compiler API transfers each syntax tree as one remote object.
        if (definitionSourceLimitExceeded) continue;
        const relativePath = virtualToRelative.get(virtualPath)!;
        const sourceFile = await project.program.getSourceFile(virtualPath);
        if (sourceFile === undefined) throw new Error(`TypeScript native project analysis could not read AST for ${relativePath}`);
        const inventorySource = sources.get(relativePath);
        const sourceMismatches = [
          ...(inventorySource === undefined ? ["missing-inventory"] : []),
          ...(pathKey(String(sourceFile.path)).toLowerCase() !== virtualPath.toLowerCase() ? ["path"] : []),
          ...(pathKey(sourceFile.fileName) !== virtualPath ? ["fileName"] : []),
          ...(sourceFile.text !== inventorySource ? ["text"] : []),
        ];
        if (sourceMismatches.length > 0) {
          throw new Error(`TypeScript native project analysis returned an AST that disagrees with the confined inventory (${sourceMismatches.join(",")}) for ${relativePath}`);
        }
        sourceFiles.set(relativePath, sourceFile);
        result.semanticSourceFiles.set(relativePath, sourceFile);
        result.importTypeModuleSpans.set(relativePath, []);
        result.nonLiteralModuleSpans.set(relativePath, []);
        result.moduleCallSpans.set(relativePath, []);
        result.typeUseSpans.set(relativePath, []);
        result.callSpans.set(relativePath, []);
        // The definition slice needs every inventory AST. Import-type ranges
        // remain an independent lexical refinement and can avoid traversing a
        // second time when the source has no possible import token.
        if ((sources.get(relativePath) ?? "").includes("import")) {
          result.typeOnlyDependencyRanges.set(relativePath, typeOnlyDependencyRanges(sourceFile));
        }
      }
      const internalRootKey = pathKey(internalRoot);
      if (sources.size === 0 && !actualRoots.has(internalRootKey)) {
        throw new Error("TypeScript native project analysis omitted its worker-owned empty root");
      }
      const standardLibraryKeys = new Set([...standardLibrary.files.keys()].map(pathKey));
      const workerOwnedKeys = new Set([internalRootKey, pathKey(VIRTUAL_CONFIG)]);
      const allowedCompilerFiles = new Set([...standardLibraryKeys, ...workerOwnedKeys]);
      const programFiles = await project.program.getSourceFileNames();
      for (const file of programFiles) {
        const key = pathKey(file);
        if (!virtualToRelative.has(key) && !allowedCompilerFiles.has(key)) {
          throw new Error(`TypeScript native project analysis loaded a file outside its isolated VFS: ${file}`);
        }
      }
      const loadedStandardLibraryFiles = programFiles.filter((file) => standardLibraryKeys.has(pathKey(file)));
      if (!loadedStandardLibraryFiles.some((file) => path.basename(file) === "lib.esnext.full.d.ts")) {
        throw new Error(`TypeScript native project analysis did not load bundled lib.esnext.full.d.ts from ${standardLibrary.root}`);
      }
      progress.complete("typescript_ast_transfer", {
        program_files: programFiles.length,
        source_files: sources.size,
      });
      progress.start("typescript_syntax_diagnostics", { source_files: sources.size });
      const syntacticallyInvalidPaths = new Set<string>();
      for (const diagnostic of await project.program.getSyntacticDiagnostics()) {
        if (!diagnostic.fileName) throw new Error(`TypeScript native syntax diagnostic TS${diagnostic.code} has no source file`);
        const relativePath = virtualToRelative.get(pathKey(diagnostic.fileName));
        if (relativePath === undefined) throw new Error(`TypeScript native syntax diagnostic escaped the virtual input: ${diagnostic.fileName}`);
        const source = sources.get(relativePath);
        if (source === undefined) throw new Error(`TypeScript syntax input disappeared for ${relativePath}`);
        syntacticallyInvalidPaths.add(relativePath);
        const startOffset = Math.max(0, Math.min(source.length, diagnostic.pos));
        const endOffset = Math.max(startOffset, Math.min(source.length, diagnostic.end));
        result.get(relativePath)!.push({
          relativePath,
          code: diagnostic.code,
          message: boundedDiagnosticMessage(diagnostic, [VIRTUAL_ROOT, standardLibrary.root]),
          startOffset,
          endOffset,
        });
      }
      progress.complete("typescript_syntax_diagnostics", {
        invalid_files: syntacticallyInvalidPaths.size,
        source_files: sources.size,
      });
      for (const [relativePath, sourceFile] of [...sourceFiles.entries()]
        .sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0)) {
        result.importTypeModuleSpans.set(relativePath, []);
        result.nonLiteralModuleSpans.set(relativePath, []);
        result.moduleCallSpans.set(relativePath, []);
        result.typeUseSpans.set(relativePath, []);
        result.callSpans.set(relativePath, []);
      }
      const intrinsicString = await project.checker.getStringType();
      if (await project.checker.typeToString(intrinsicString) !== "string") {
        throw new Error("TypeScript native TypeChecker smoke query returned an unexpected intrinsic string type");
      }
      if (!definitionSourceLimitExceeded) {
        const semanticSources = [...sourceFiles.entries()]
          .sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0)
          .map(([relativePath, sourceFile]) => ({
            relativePath,
            compilerPath: sourceFile.fileName,
            expectedText: sources.get(relativePath)!,
            sourceFile,
            syntacticallyValid: !syntacticallyInvalidPaths.has(relativePath),
          }));
        progress.start("typescript_definition_graph", { source_files: semanticSources.length });
        result.definitionGraph = await extractTypeScriptRawDefinitionDelta(
          project.checker,
          semanticSources,
        );
        progress.complete("typescript_definition_graph", {
          definitions: result.definitionGraph.definitions.length,
          source_files: semanticSources.length,
        });
        if (!result.definitionGraph.issues.some((issue) => issue.fatal)) {
          progress.start("typescript_dependency_graph", { source_files: semanticSources.length });
          result.dependencyGraph = await extractTypeScriptRawDependencyDelta(
            project.checker,
            semanticSources,
            result.definitionGraph,
            result.definitionGraph.typeCheckerQueries,
            result,
          );
          progress.complete("typescript_dependency_graph", {
            dependency_sites: result.dependencyGraph.sites.length,
            source_files: semanticSources.length,
          });
        }
      }
      const typeCheckerQueries = 1
        + result.definitionGraph.typeCheckerQueries
        + result.dependencyGraph.typeCheckerQueries
        + dependencyValidationQueryBudget.value;
      progress.start("typescript_semantic_diagnostics", { source_files: sources.size });
      const diagnostics = [
        ...await project.program.getProgramDiagnostics(),
        ...await project.program.getGlobalDiagnostics(),
        ...await project.program.getSemanticDiagnostics(),
      ].map((diagnostic) => semanticDiagnostic(
        diagnostic,
        sources,
        virtualToRelative,
        allowedCompilerFiles,
        standardLibrary.root,
      ));
      progress.complete("typescript_semantic_diagnostics", {
        diagnostics: diagnostics.length,
        source_files: sources.size,
      });
      const uniqueDiagnostics = [...new Map(diagnostics.map((diagnostic) => [
        JSON.stringify(diagnostic),
        diagnostic,
      ])).values()].sort((left, right) => (
        compareUtf8(left.relativePath ?? "", right.relativePath ?? "")
        || left.startOffset - right.startOffset
        || left.code - right.code
        || compareUtf8(left.message, right.message)
      ));
      result.semanticDiagnostics.push(...uniqueDiagnostics.slice(0, MAX_SEMANTIC_DIAGNOSTICS));
      result.project = {
        status: "ready",
        rootFiles: sources.size,
        programFiles: programFiles.filter((file) => !workerOwnedKeys.has(pathKey(file))).length,
        staticConfigFiles: staticConfig.configFiles,
        pathMappings: staticConfig.pathMappings ?? Object.keys(staticConfig.paths).length,
        standardLibraryFiles: loadedStandardLibraryFiles.length,
        typeCheckerQueries,
        semanticDiagnostics: uniqueDiagnostics.length,
        emittedSemanticDiagnostics: result.semanticDiagnostics.length,
        definitionGraphStatus: [...result.definitionGraph.issues, ...result.dependencyGraph.issues].some((issue) => issue.fatal) ? "failed" : "ready",
        semanticNodes: result.definitionGraph.definitions.length,
        semanticRelations: result.definitionGraph.relations.length,
        semanticSites: result.dependencyGraph.sites.length + result.dependencyGraph.calls.length,
        semanticCallSites: result.dependencyGraph.calls.length,
        semanticIssues: result.definitionGraph.issues.length + result.dependencyGraph.issues.length,
      };
    } finally {
      await snapshot.dispose();
    }
  })();
  await runCompilerOperation(api, operation, testRuntime?.timeoutMs ?? COMPILER_TIMEOUT_MS);
  for (const diagnostics of result.values()) {
    diagnostics.sort((left, right) => left.startOffset - right.startOffset || left.code - right.code || compareUtf8(left.message, right.message));
  }
  return result;
}

function projectFailure(error: unknown): TypeScriptProjectError {
  if (error instanceof TypeScriptProjectError) return error;
  const detail = error instanceof Error ? error.message : String(error);
  let reason: TypeScriptProjectFailureReason;
  if (error instanceof CompilerTimeoutError || /timed out/iu.test(detail)) {
    reason = "compiler_timeout";
  } else if (error instanceof CompilerProtocolError) {
    reason = "compiler_protocol_failure";
  } else if (/compiler is missing next to packaged worker|development compiler is unavailable/iu.test(detail)) {
    reason = "compiler_unavailable";
  } else if (/standard library/iu.test(detail)) {
    reason = "stdlib_unavailable";
  } else if (/opened \d+ projects/iu.test(detail)) {
    reason = "project_count_mismatch";
  } else if (/omitted/iu.test(detail)) {
    reason = "root_file_mismatch";
  } else if (/outside its isolated VFS|escaped the isolated project/iu.test(detail)) {
    reason = "unexpected_program_input";
  } else if (/TypeChecker smoke query/iu.test(detail)) {
    reason = "typechecker_smoke_failed";
  } else {
    reason = "compiler_protocol_failure";
  }
  const message = reason === "compiler_unavailable" && PACKAGED_WORKER
    ? `bundled TypeScript ${TYPESCRIPT_COMPILER_VERSION} compiler is missing next to packaged worker (${reason})`
    : `bundled TypeScript ${TYPESCRIPT_COMPILER_VERSION} project model failed (${reason})`;
  return new TypeScriptProjectError(reason, message, { cause: error });
}

/** @internal Cross-platform process lifecycle seam; the worker entrypoint never calls this. */
export async function exerciseTypeScriptCompilerLifecycleForTest(
  mode: TypeScriptLifecycleTestMode,
): Promise<TypeScriptLifecycleTestResult> {
  const { spawn } = await import("node:child_process");
  const errorListeners = new Set<(error: Error) => void>();
  const closeListeners = new Set<() => void>();
  const connection: CompilerConnection = {
    onError: (listener) => {
      errorListeners.add(listener);
      return { dispose: () => { errorListeners.delete(listener); } };
    },
    onClose: (listener) => {
      closeListeners.add(listener);
      return { dispose: () => { closeListeners.delete(listener); } };
    },
  };
  const child = spawn(
    process.execPath,
    ["-e", mode === "crash" ? "process.exit(17)" : "setInterval(() => undefined, 1000)"],
    { stdio: "ignore", windowsHide: true },
  );
  const client: { process?: ChildProcess; connection: CompilerConnection } = { process: child, connection };
  const api = {
    client,
    close: async (): Promise<void> => {
      if (mode === "strict-close") delete client.process;
    },
  } as unknown as API;
  let protocolTimer: NodeJS.Timeout | undefined;
  let failure: unknown;
  try {
    if (mode === "protocol-error") {
      protocolTimer = setTimeout(() => {
        for (const listener of [...errorListeners]) listener(new Error("injected protocol failure"));
      }, 10);
    }
    await runCompilerOperation(
      api,
      mode === "strict-close" ? Promise.resolve() : new Promise<never>(() => undefined),
      mode === "timeout" ? 100 : 2_000,
    );
  } catch (error) {
    failure = error;
  } finally {
    if (protocolTimer) clearTimeout(protocolTimer);
    await closeCompiler(api, true, child);
  }
  if (failure === undefined) throw new Error(`TypeScript compiler lifecycle test ${mode} did not fail`);
  return {
    reason: projectFailure(failure).reason,
    reaped: child.exitCode !== null || child.signalCode !== null,
    listenersDisposed: errorListeners.size === 0 && closeListeners.size === 0,
  };
}

export async function analyzeTypeScriptProject(
  sources: ReadonlyMap<string, string>,
  staticConfig: TypeScriptStaticConfig = { configFiles: 0, paths: {} },
  progress: ProgressReporter = NOOP_PROGRESS,
): Promise<TypeScriptProjectAnalysis> {
  try {
    return await analyzeTypeScriptProjectInner(sources, staticConfig, undefined, progress);
  } catch (error) {
    throw projectFailure(error);
  }
}

/** @internal Test-only failure-injection seam; the worker entrypoint never calls this. */
export async function analyzeTypeScriptProjectWithRuntimeForTest(
  sources: ReadonlyMap<string, string>,
  runtime: TypeScriptAnalysisTestRuntime,
): Promise<TypeScriptProjectAnalysis> {
  try {
    return await analyzeTypeScriptProjectInner(sources, { configFiles: 0, paths: {} }, runtime);
  } catch (error) {
    throw projectFailure(error);
  }
}
