import type { ChildProcess } from "node:child_process";
import { constants as fsConstants } from "node:fs";
import { access, readFile, realpath, stat } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
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

const TYPESCRIPT_VERSION = "7.0.2";
const COMPILER_TIMEOUT_MS = 30_000;
const COMPILER_BASENAME = process.platform === "win32" ? "tsc.exe" : "tsc";
const VIRTUAL_ROOT = path.join(path.parse(process.execPath).root, "__depgraph_typescript_syntax__");
const VIRTUAL_CONFIG = path.join(VIRTUAL_ROOT, "tsconfig.json");
const NEUTRAL_CWD = path.parse(process.execPath).root;
const MAY_CONTAIN_IMPORT_TYPE = /\bimport(?:\s|\/\*[\s\S]*?\*\/|\/\/[^\r\n]*(?:\r?\n|$))*\(/u;

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

export class TypeScriptSyntaxDiagnostics extends Map<string, TypeScriptSyntaxDiagnostic[]> {
  readonly typeOnlyDependencyRanges = new Map<string, TypeOnlyDependencyRange[]>();
}

interface CompilerClientInternals {
  client?: { process?: ChildProcess };
}

class CompilerTimeoutError extends Error {}

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

function isWithin(parent: string, child: string): boolean {
  const relative = path.relative(parent, child);
  return relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative));
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

/**
 * Resolve only release-adjacent or worker-installation artifacts. In
 * particular, this never resolves a compiler relative to the scanned root or
 * the worker process cwd.
 */
export async function resolveTypeScriptCompiler(): Promise<string> {
  const adjacent = fileURLToPath(new URL(`./typescript/lib/${COMPILER_BASENAME}`, import.meta.url));
  const bundled = await usableCompiler(adjacent);
  if (bundled !== null) return bundled;

  let typescriptManifest: string;
  try {
    typescriptManifest = fileURLToPath(import.meta.resolve("typescript/package.json"));
  } catch (error) {
    throw new Error(`bundled TypeScript ${TYPESCRIPT_VERSION} package is unavailable: ${String(error)}`);
  }
  const typescriptRoot = await realpath(path.dirname(typescriptManifest));
  const platformPackageName = `typescript-${process.platform}-${process.arch}`;
  const platformRoot = path.resolve(typescriptRoot, "..", "@typescript", platformPackageName);
  const platformManifest = path.join(platformRoot, "package.json");
  let packageMetadata: { name?: unknown; version?: unknown };
  try {
    packageMetadata = JSON.parse(await readFile(platformManifest, "utf8")) as { name?: unknown; version?: unknown };
  } catch (error) {
    throw new Error(`bundled TypeScript native package @typescript/${platformPackageName} is unavailable: ${String(error)}`);
  }
  if (packageMetadata.name !== `@typescript/${platformPackageName}` || packageMetadata.version !== TYPESCRIPT_VERSION) {
    throw new Error(`bundled TypeScript native package identity mismatch: expected @typescript/${platformPackageName}@${TYPESCRIPT_VERSION}`);
  }
  const resolvedPlatformRoot = await realpath(platformRoot);
  const candidate = path.join(resolvedPlatformRoot, "lib", process.platform === "win32" ? "tsc.exe" : "tsc");
  const compiler = await usableCompiler(candidate);
  if (compiler === null || !isWithin(resolvedPlatformRoot, compiler)) {
    throw new Error(`bundled TypeScript native compiler is missing or escapes its package: ${candidate}`);
  }
  return compiler;
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
    .sort((left, right) => left.startOffset - right.startOffset || left.endOffset - right.endOffset || left.syntax.localeCompare(right.syntax));
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

async function closeCompiler(api: API, force: boolean): Promise<void> {
  const child = compilerProcess(api);
  if (force) child?.kill("SIGKILL");
  await Promise.race([
    api.close().catch(() => undefined),
    new Promise<void>((resolve) => {
      const timer = setTimeout(resolve, 1_000);
      timer.unref();
    }),
  ]);
  if (child && !(await waitForExit(child, 1_000))) child.kill("SIGKILL");
}

function withTimeout<T>(operation: Promise<T>, timeoutMs: number): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => reject(new CompilerTimeoutError(`TypeScript native syntax analysis timed out after ${timeoutMs}ms`)), timeoutMs);
    timer.unref();
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

/** Run exactly one trusted native TypeScript compiler process for one scan. */
export async function collectTypeScriptSyntacticDiagnostics(
  sources: ReadonlyMap<string, string>,
): Promise<TypeScriptSyntaxDiagnostics> {
  const result = new TypeScriptSyntaxDiagnostics();
  if (sources.size === 0) return result;

  const compiler = await resolveTypeScriptCompiler();
  const virtualFiles = new Map<string, string>();
  const virtualToRelative = new Map<string, string>();
  const configFiles: string[] = [];
  for (const [relativePath, source] of [...sources].sort(([left], [right]) => left.localeCompare(right))) {
    if (!isConfinedTypeScriptInputPath(relativePath) || !TYPESCRIPT_SOURCE_EXTENSIONS.has(path.extname(relativePath).toLowerCase())) {
      throw new Error(`refusing unsafe or unsupported TypeScript syntax input path: ${relativePath}`);
    }
    const portable = relativePath.replaceAll("\\", "/");
    const virtualPath = path.join(VIRTUAL_ROOT, ...portable.split("/"));
    virtualFiles.set(virtualPath, source);
    virtualToRelative.set(pathKey(virtualPath), portable);
    configFiles.push(portable);
    result.set(portable, []);
    result.typeOnlyDependencyRanges.set(portable, []);
  }
  virtualFiles.set(VIRTUAL_CONFIG, `${JSON.stringify({
    compilerOptions: {
      allowJs: true,
      checkJs: false,
      jsx: "preserve",
      module: "preserve",
      noCheck: true,
      noEmit: true,
      noLib: true,
      noResolve: true,
      plugins: [],
      skipLibCheck: true,
      target: "esnext",
      types: [],
    },
    files: configFiles,
  })}\n`);

  const api = new API({
    cwd: NEUTRAL_CWD,
    fs: virtualFileSystem(virtualFiles),
    tsserverPath: compiler,
  });
  const operation = (async (): Promise<void> => {
    const snapshot = await withNeutralEnvironment(() => api.updateSnapshot({ openProjects: [VIRTUAL_CONFIG] }));
    const projects = snapshot.getProjects();
    if (projects.length !== 1) throw new Error(`TypeScript native syntax analysis opened ${projects.length} projects instead of one neutral project`);
    const project = projects[0]!;
    const actualRoots = new Set(project.rootFiles.map(pathKey));
    for (const virtualPath of virtualToRelative.keys()) {
      if (!actualRoots.has(virtualPath)) throw new Error(`TypeScript native syntax analysis omitted ${virtualToRelative.get(virtualPath)}`);
      const relativePath = virtualToRelative.get(virtualPath)!;
      // Fetching a remote AST transfers and decodes the full syntax tree. The
      // lexical inventory already classifies import/export declarations, so
      // only request trees that may contain the parser-ambiguous `import(...)`
      // form (runtime CallExpression vs erased ImportType/JSDoc ImportType).
      if (!MAY_CONTAIN_IMPORT_TYPE.test(sources.get(relativePath) ?? "")) continue;
      const sourceFile = await project.program.getSourceFile(virtualPath);
      if (sourceFile === undefined) throw new Error(`TypeScript native syntax analysis could not read AST for ${relativePath}`);
      result.typeOnlyDependencyRanges.set(relativePath, typeOnlyDependencyRanges(sourceFile));
    }
    for (const diagnostic of await project.program.getSyntacticDiagnostics()) {
      if (!diagnostic.fileName) throw new Error(`TypeScript native syntax diagnostic TS${diagnostic.code} has no source file`);
      const relativePath = virtualToRelative.get(pathKey(diagnostic.fileName));
      if (relativePath === undefined) throw new Error(`TypeScript native syntax diagnostic escaped the virtual input: ${diagnostic.fileName}`);
      const source = sources.get(relativePath);
      if (source === undefined) throw new Error(`TypeScript syntax input disappeared for ${relativePath}`);
      const startOffset = Math.max(0, Math.min(source.length, diagnostic.pos));
      const endOffset = Math.max(startOffset, Math.min(source.length, diagnostic.end));
      result.get(relativePath)!.push({
        relativePath,
        code: diagnostic.code,
        message: flattenDiagnosticMessage(diagnostic),
        startOffset,
        endOffset,
      });
    }
  })();

  try {
    await withTimeout(operation, COMPILER_TIMEOUT_MS);
  } catch (error) {
    const timedOut = error instanceof CompilerTimeoutError;
    if (timedOut) void operation.catch(() => undefined);
    await closeCompiler(api, timedOut);
    throw error;
  }
  await closeCompiler(api, false);
  for (const diagnostics of result.values()) {
    diagnostics.sort((left, right) => left.startOffset - right.startOffset || left.code - right.code || left.message.localeCompare(right.message));
  }
  return result;
}
