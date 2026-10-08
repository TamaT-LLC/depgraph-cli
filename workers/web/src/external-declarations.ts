import { open, realpath, type FileHandle } from "node:fs/promises";
import path from "node:path";
import { extractDependencies, type ModuleResolver, type TypeScriptPathRequest } from "./imports";
import { normalizeRelative, resolveWithinRoot } from "./fs";
import { compareUtf8 } from "./types";

export const EXTERNAL_DECLARATION_LIMITS = Object.freeze({ files: 1_024, bytes: 16 * 1024 * 1024, fileBytes: 1024 * 1024, requests: 8_192 });

export interface ExternalDeclarationFile {
  text: string;
  locator: string;
}

export interface ExternalDeclarations {
  files: ReadonlyMap<string, ExternalDeclarationFile>;
  paths: Readonly<Record<string, readonly string[]>>;
  issues: readonly { path: string; reason: string }[];
  bytes: number;
}

type Entry = { file: string; packageRoot: string; locator: string };

function readableDeclarationSize(metadata: { isFile(): boolean; size: number }, maxBytes: number): boolean {
  return metadata.isFile() && metadata.size <= maxBytes;
}

async function readDeclarationBytes(handle: FileHandle, maxBytes: number): Promise<string | null> {
  const before = await handle.stat();
  if (!readableDeclarationSize(before, maxBytes)) return null;
  const buffer = Buffer.alloc(before.size + 1);
  const { bytesRead } = await handle.read(buffer, 0, buffer.length, 0);
  const after = await handle.stat();
  if (!consistentDeclarationRead(bytesRead, before, after)) return null;
  try { return new TextDecoder("utf-8", { fatal: true }).decode(buffer.subarray(0, bytesRead)); }
  catch { return null; }
}

function consistentDeclarationRead(bytesRead: number, before: { size: number; mtimeMs: number }, after: { size: number; mtimeMs: number }): boolean {
  return bytesRead === before.size && before.size === after.size && before.mtimeMs === after.mtimeMs;
}

async function readDeclaration(root: string, file: string, maxBytes: number): Promise<string | null> {
  const canonical = await resolveWithinRoot(root, file);
  if (canonical !== file) return null;
  const handle = await open(file, "r").catch(() => null);
  if (handle === null) return null;
  try { return await readDeclarationBytes(handle, maxBytes); }
  finally { await handle.close(); }
}

function declarationRequests(file: string, relative: string, text: string): string[] {
  const dependencies = extractDependencies(file, relative, text).dependencies
    .filter((dependency) => dependency.literal)
    .map((dependency) => dependency.specifier);
  for (const match of text.matchAll(/^\s*\/\/\/\s*<reference\s+(path|types)=["']([^"']+)["'][^>]*>/gmu)) {
    const target = match[2]!;
    dependencies.push(match[1] === "path" ? target.startsWith(".") ? target : `./${target}` : target);
  }
  return [...new Set(dependencies)].sort(compareUtf8);
}

/** Explicit module requests plus quoted JSDoc imports; ordinary string literals are not package probes. */
export function externalDeclarationRequests(root: string, sources: ReadonlyMap<string, string>): TypeScriptPathRequest[] {
  return [...sources].flatMap(([relative, text]) => {
    const sourceFile = path.join(root, relative);
    const specifiers = [...declarationRequests(sourceFile, relative, text), ...commentModuleRequests(text)];
    return [...new Set(specifiers)].map((specifier) => ({ sourceFile, specifier }));
  });
}

function commentModuleRequests(text: string): string[] {
  const inline = [...text.matchAll(/\bimport\s*\(\s*["']([^"']+)["']\s*\)/gu)].map((match) => match[1]!);
  const tags = [...text.matchAll(/@import[^\r\n]*?\bfrom\s*["']([^"']+)["']/gu)].map((match) => match[1]!);
  return [...inline, ...tags];
}

function bareProbeKey(specifier: string, sourceFile: string, parent?: Entry): string {
  // The lookup directory determines the repository owner; preserve an external parent's identity too.
  return JSON.stringify(["bare", parent?.locator ?? null, path.dirname(sourceFile), specifier]);
}

type Limits = { files: number; bytes: number; fileBytes: number; requests: number };

class DeclarationLoader {
  readonly files = new Map<string, ExternalDeclarationFile>();
  readonly paths = new Map<string, string[]>();
  readonly blocked = new Set<string>();
  readonly issues = new Map<string, { path: string; reason: string }>();
  readonly pending: Entry[] = [];
  readonly admitted = new Map<string, string>();
  readonly ambiguousFiles = new Set<string>();
  bytes = 0;
  requestCount = 0;
  readonly probes = new Map<string, Entry | null>();

  constructor(readonly root: string, readonly canonicalRoot: string, readonly resolver: ModuleResolver, readonly limits: Limits) {}

  issue(file: string, reason: string): void {
    const relative = normalizeRelative(path.relative(this.canonicalRoot, file));
    if (this.issues.size < 128) this.issues.set(`${relative}\0${reason}`, { path: relative, reason });
  }

  enqueue(entry: Entry): void {
    const prior = this.admitted.get(entry.file);
    if (prior !== undefined) { this.checkIdentity(entry, prior); return; }
    if (this.admitted.size >= this.limits.files) { this.issue(entry.file, "external_declaration_file_limit"); return; }
    this.admitted.set(entry.file, entry.locator);
    this.pending.push(entry);
  }

  checkIdentity(entry: Entry, prior: string): void {
    if (prior === entry.locator) return;
    this.issue(entry.file, "external_declaration_identity_ambiguous");
    this.ambiguousFiles.add(entry.file);
    this.files.delete(normalizeRelative(path.relative(this.canonicalRoot, entry.file)));
  }

  async request(specifier: string, sourceFile: string, parent?: Entry): Promise<void> {
    if (specifier.startsWith(".") && parent === undefined) return;
    if (specifier.startsWith(".")) await this.relativeRequest(specifier, sourceFile, parent);
    else await this.bareRequest(specifier, sourceFile, parent);
  }

  async relativeRequest(specifier: string, sourceFile: string, parent?: Entry): Promise<void> {
    if (parent === undefined) return;
    const key = JSON.stringify(["relative", parent.locator, parent.packageRoot, path.dirname(sourceFile), specifier]);
    const entry = await this.probe(key, sourceFile, async () => {
      const file = await this.resolver.relativeDeclaration(specifier, sourceFile, parent.packageRoot);
      return file === null ? null : { ...parent, file };
    });
    if (entry === undefined) return;
    if (entry === null) { this.issue(sourceFile, "external_declaration_reference_unavailable"); return; }
    this.enqueue(entry);
  }

  async bareRequest(specifier: string, sourceFile: string, parent?: Entry): Promise<void> {
    const key = bareProbeKey(specifier, sourceFile, parent);
    const entry = await this.probe(key, sourceFile, () => this.resolver.externalDeclaration(specifier, sourceFile));
    if (entry === undefined) return;
    if (entry === null) {
      this.block(specifier);
      if (parent !== undefined) this.issue(sourceFile, "external_declaration_dependency_unavailable");
      return;
    }
    this.admitMapping(specifier, sourceFile, entry);
  }

  async probe(key: string, sourceFile: string, resolve: () => Promise<Entry | null>): Promise<Entry | null | undefined> {
    if (this.probes.has(key)) return this.probes.get(key)!;
    if (this.requestCount >= this.limits.requests) { this.issue(sourceFile, "external_declaration_request_limit"); return undefined; }
    this.requestCount++;
    const entry = await resolve();
    this.probes.set(key, entry);
    return entry;
  }

  block(specifier: string): void {
    this.blocked.add(specifier);
    this.paths.delete(specifier);
  }

  conflictingMapping(specifier: string, relative: string): boolean {
    const prior = this.paths.get(specifier)?.[0];
    return this.blocked.has(specifier) || (prior !== undefined && prior !== relative);
  }

  admitMapping(specifier: string, sourceFile: string, entry: Entry): void {
    const relative = normalizeRelative(path.relative(this.canonicalRoot, entry.file));
    if (this.conflictingMapping(specifier, relative)) {
      this.block(specifier);
      this.issue(sourceFile, "external_declaration_resolution_ambiguous");
      return;
    }
    this.paths.set(specifier, [relative]);
    this.enqueue(entry);
  }

  async loadRequests(requests: readonly TypeScriptPathRequest[]): Promise<void> {
    const sorted = [...requests].sort((left, right) => compareUtf8(left.sourceFile, right.sourceFile) || compareUtf8(left.specifier, right.specifier));
    for (const item of sorted) await this.request(item.specifier, item.sourceFile);
  }

  async loadEntry(entry: Entry): Promise<void> {
    if (this.ambiguousFiles.has(entry.file)) return;
    const relative = normalizeRelative(path.relative(this.canonicalRoot, entry.file));
    const text = await readDeclaration(this.canonicalRoot, entry.file, Math.min(this.limits.fileBytes, this.limits.bytes - this.bytes));
    if (text === null) { this.issue(entry.file, "external_declaration_unreadable_or_byte_limit"); return; }
    this.bytes += Buffer.byteLength(text, "utf8");
    this.files.set(relative, { text, locator: entry.locator });
    for (const specifier of [...declarationRequests(entry.file, relative, text), ...commentModuleRequests(text)]) await this.request(specifier, path.join(this.root, relative), entry);
  }

  allIssues(): { path: string; reason: string }[] {
    const issues = [...this.issues.values(), ...this.resolver.externalDeclarationIssues()];
    return [...new Map(issues.map((issue) => [JSON.stringify(issue), issue])).values()];
  }

  async finish(): Promise<ExternalDeclarations> {
    while (this.pending.length > 0) await this.loadEntry(this.pending.shift()!);
    // Missing entries must not redirect the compiler to a partial file.
    for (const [specifier, targets] of this.paths) if (!this.files.has(targets[0]!)) this.paths.delete(specifier);
    return { files: this.files, paths: Object.fromEntries(this.paths), issues: this.allIssues(), bytes: this.bytes };
  }
}

/** Copy only bounded, resolved declaration bytes. The compiler never reads the repository. */
export async function loadExternalDeclarations(
  root: string,
  resolver: ModuleResolver,
  requests: readonly TypeScriptPathRequest[],
  limits: Limits = EXTERNAL_DECLARATION_LIMITS,
): Promise<ExternalDeclarations> {
  const loader = new DeclarationLoader(root, await realpath(root), resolver, limits);
  await loader.loadRequests(requests);
  return await loader.finish();
}
