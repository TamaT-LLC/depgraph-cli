import path from "node:path";
import { isWithinRoot, normalizeRelative, readUtf8 } from "./fs";
import { compareUtf8, type Evidence } from "./types";
import type { PackageRecord, Workspace } from "./workspace";

export interface RouteEntry {
  framework: "next" | "astro" | "tanstack-router" | "tanstack-start";
  pattern: string;
  absoluteFile: string;
  relativeFile: string;
  entryKind: string;
  generated: boolean;
  evidence: Evidence;
}

export interface RouteDrift {
  package: PackageRecord;
  missingFromGenerated: string[];
  onlyGenerated: string[];
}

export interface RouteDiscovery {
  entries: RouteEntry[];
  drifts: RouteDrift[];
  frameworks: string[];
  configDiagnostics: RouteConfigDiagnostic[];
}

export interface RouteConfigDiagnostic {
  severity: "info" | "warning" | "error";
  code: string;
  message: string;
  path: string;
}

interface StaticRouteConfig {
  nextBasePath: string;
  astroBasePath: string;
  tanstackBasePath: string;
  nextPageExtensions: Set<string> | null;
  astroPageRoots: string[];
  tanstackRouteRoots: string[];
  tanstackGeneratedFiles: string[];
  diagnostics: RouteConfigDiagnostic[];
}

const NEXT_APP_FILES = new Set([
  "page",
  "layout",
  "template",
  "loading",
  "error",
  "global-error",
  "not-found",
  "forbidden",
  "unauthorized",
  "global-not-found",
  "default",
  "route",
  "sitemap",
  "robots",
  "manifest",
  "icon",
  "apple-icon",
  "opengraph-image",
  "twitter-image",
  "proxy",
  "instrumentation",
]);
// Next's built-in page extensions are JavaScript and TypeScript only. MD/MDX
// become routes only when the project explicitly opts into those suffixes.
const NEXT_PAGE_EXTENSIONS = new Set([".js", ".jsx", ".ts", ".tsx"]);
const NEXT_ROOT_SPECIAL_FILES = new Set(["proxy", "middleware", "instrumentation", "instrumentation-client"]);
const ASTRO_PAGE_EXTENSIONS = new Set([".astro", ".md", ".mdx", ".html", ".js", ".ts"]);
const TANSTACK_EXTENSIONS = new Set([".js", ".jsx", ".ts", ".tsx"]);

function literalProperty(source: string, key: string): string | null {
  const expression = new RegExp(`\\b${key}\\s*:\\s*(["'\\x60])([^"'\\x60\\\\]*)\\1`, "u");
  const match = source.match(expression);
  if (!match) return null;
  if (match[1] === "`" && match[2]?.includes("${")) return null;
  return match[2] ?? null;
}

function literalStringArrayProperty(source: string, key: string): string[] | null {
  const body = source.match(new RegExp(`\\b${key}\\s*:\\s*\\[([^\\]]*)\\]`, "u"))?.[1];
  if (body === undefined) return null;
  const matches = [...body.matchAll(/(["'`])([^"'`\\]*)\1/gu)];
  if (matches.some((match) => match[1] === "`" && match[2]?.includes("${"))) return null;
  const values = matches.map((match) => match[2]!).filter(Boolean);
  const remainder = body.replace(/(["'`])([^"'`\\]*)\1/gu, "").replace(/[\s,]/gu, "");
  return remainder === "" ? values : null;
}

function hasProperty(source: string, key: string): boolean {
  return new RegExp(`\\b${key}\\s*:`, "u").test(source);
}

/**
 * Remove comments without changing quoted content. Configuration extraction is
 * intentionally lexical: this keeps commented examples from becoming active
 * settings while avoiding any import or evaluation of project code.
 */
function withoutComments(source: string): string {
  let result = "";
  let quote: "\"" | "'" | "`" | null = null;
  let escaped = false;
  for (let index = 0; index < source.length; index += 1) {
    const current = source[index]!;
    const next = source[index + 1];
    if (quote !== null) {
      result += current;
      if (escaped) escaped = false;
      else if (current === "\\") escaped = true;
      else if (current === quote) quote = null;
      continue;
    }
    if (current === "\"" || current === "'" || current === "`") {
      quote = current;
      result += current;
      continue;
    }
    if (current === "/" && next === "/") {
      result += "  ";
      index += 2;
      while (index < source.length && source[index] !== "\n" && source[index] !== "\r") {
        result += " ";
        index += 1;
      }
      index -= 1;
      continue;
    }
    if (current === "/" && next === "*") {
      result += "  ";
      index += 2;
      while (index < source.length && !(source[index] === "*" && source[index + 1] === "/")) {
        result += source[index] === "\n" || source[index] === "\r" ? source[index] : " ";
        index += 1;
      }
      if (index < source.length) {
        result += "  ";
        index += 1;
      }
      continue;
    }
    result += current;
  }
  return result;
}

function canonicalBasePath(value: string, property: string, relativeFile: string, diagnostics: RouteConfigDiagnostic[]): string {
  if (value.includes("..") || value.includes("?") || value.includes("#")) {
    diagnostics.push({ severity: "warning", code: "web.static_config_unresolved", message: `${property} is not a safe literal URL path`, path: relativeFile });
    return "";
  }
  const base = `/${value}`.replace(/\/{2,}/gu, "/").replace(/\/$/u, "");
  return base === "/" ? "" : base;
}

function withBasePath(basePath: string, pattern: string): string {
  if (!basePath) return pattern;
  return `${basePath}${pattern === "/" ? "" : pattern}` || "/";
}

function safeConfiguredPath(
  workspaceRoot: string,
  packageRoot: string,
  value: string,
  property: string,
  relativeFile: string,
  diagnostics: RouteConfigDiagnostic[],
): string | null {
  const resolved = path.resolve(packageRoot, value);
  if (!isWithinRoot(workspaceRoot, resolved)) {
    diagnostics.push({ severity: "warning", code: "web.static_config_unresolved", message: `${property} escapes the repository and was ignored`, path: relativeFile });
    return null;
  }
  return resolved;
}

async function staticRouteConfig(record: PackageRecord, allFiles: string[], workspaceRoot: string): Promise<StaticRouteConfig> {
  const diagnostics: RouteConfigDiagnostic[] = [];
  let nextBasePath = "";
  let astroBasePath = "";
  let tanstackBasePath = "";
  let nextPageExtensions: Set<string> | null = null;
  let astroPageRoots = [path.join(record.absolutePath, "src", "pages")];
  let tanstackRouteRoots = [path.join(record.absolutePath, "src", "routes"), path.join(record.absolutePath, "app", "routes")];
  let tanstackGeneratedFiles: string[] = [];
  const configs = allFiles.filter((file) => path.dirname(file) === record.absolutePath && /^(?:next|astro|vite|tanstack|router)\.config\.(?:js|jsx|ts|tsx|mjs|cjs)$/u.test(path.basename(file)));
  for (const file of configs.sort()) {
    const rawSource = await readUtf8(workspaceRoot, file);
    const relativeFile = normalizeRelative(path.relative(workspaceRoot, file));
    if (rawSource === null) {
      diagnostics.push({
        severity: "error",
        code: "web.config_read_failed",
        message: "Framework configuration could not be read within the repository boundary; defaults were not assumed complete",
        path: relativeFile,
      });
      continue;
    }
    const source = withoutComments(rawSource);
    const name = path.basename(file);
    for (const runtimeProperty of ["webpack", "integrations", "plugins", "adapter"]) {
      if (hasProperty(source, runtimeProperty)) {
        diagnostics.push({
          severity: "warning",
          code: "web.static_config_runtime_ignored",
          message: `${runtimeProperty} requires project code evaluation and was not interpreted in safe mode`,
          path: relativeFile,
        });
      }
    }
    if (name.startsWith("next.config.")) {
      const configuredBase = literalProperty(source, "basePath");
      if (configuredBase !== null) {
        nextBasePath = canonicalBasePath(configuredBase, "basePath", relativeFile, diagnostics);
        diagnostics.push({ severity: "info", code: "web.static_config_literal_applied", message: `Applied static Next.js basePath=${nextBasePath || "/"}`, path: relativeFile });
      } else if (hasProperty(source, "basePath")) diagnostics.push({ severity: "warning", code: "web.static_config_unresolved", message: "Next.js basePath is not a static string literal", path: relativeFile });
      const extensions = literalStringArrayProperty(source, "pageExtensions");
      if (extensions !== null) {
        nextPageExtensions = new Set(extensions.map((extension) => extension.startsWith(".") ? extension : `.${extension}`));
        diagnostics.push({ severity: "info", code: "web.static_config_literal_applied", message: `Applied static Next.js pageExtensions=${[...nextPageExtensions].sort().join(",")}`, path: relativeFile });
      } else if (hasProperty(source, "pageExtensions")) diagnostics.push({ severity: "warning", code: "web.static_config_unresolved", message: "Next.js pageExtensions is not a static string array", path: relativeFile });
    }
    if (name.startsWith("astro.config.")) {
      const configuredBase = literalProperty(source, "base");
      if (configuredBase !== null) {
        astroBasePath = canonicalBasePath(configuredBase, "base", relativeFile, diagnostics);
        diagnostics.push({ severity: "info", code: "web.static_config_literal_applied", message: `Applied static Astro base=${astroBasePath || "/"}`, path: relativeFile });
      } else if (hasProperty(source, "base")) diagnostics.push({ severity: "warning", code: "web.static_config_unresolved", message: "Astro base is not a static string literal", path: relativeFile });
      const srcDir = literalProperty(source, "srcDir");
      if (srcDir !== null) {
        const configured = safeConfiguredPath(workspaceRoot, record.absolutePath, srcDir, "srcDir", relativeFile, diagnostics);
        if (configured) {
          astroPageRoots = [path.join(configured, "pages")];
          diagnostics.push({ severity: "info", code: "web.static_config_literal_applied", message: `Applied static Astro srcDir=${srcDir}`, path: relativeFile });
        }
      } else if (hasProperty(source, "srcDir")) diagnostics.push({ severity: "warning", code: "web.static_config_unresolved", message: "Astro srcDir is not a static string literal", path: relativeFile });
    }
    if (/^(?:vite|tanstack|router)\.config\./u.test(name)) {
      const configuredBase = literalProperty(source, "basepath") ?? literalProperty(source, "basePath");
      if (configuredBase !== null) {
        tanstackBasePath = canonicalBasePath(configuredBase, "basepath", relativeFile, diagnostics);
        diagnostics.push({ severity: "info", code: "web.static_config_literal_applied", message: `Applied static TanStack basepath=${tanstackBasePath || "/"}`, path: relativeFile });
      } else if (hasProperty(source, "basepath") || hasProperty(source, "basePath")) diagnostics.push({ severity: "warning", code: "web.static_config_unresolved", message: "TanStack basepath is not a static string literal", path: relativeFile });
      const routesDirectory = literalProperty(source, "routesDirectory");
      if (routesDirectory !== null) {
        const configured = safeConfiguredPath(workspaceRoot, record.absolutePath, routesDirectory, "routesDirectory", relativeFile, diagnostics);
        if (configured) {
          tanstackRouteRoots = [configured];
          diagnostics.push({ severity: "info", code: "web.static_config_literal_applied", message: `Applied static TanStack routesDirectory=${routesDirectory}`, path: relativeFile });
        }
      } else if (hasProperty(source, "routesDirectory")) diagnostics.push({ severity: "warning", code: "web.static_config_unresolved", message: "TanStack routesDirectory is not a static string literal", path: relativeFile });
      const generatedRouteTree = literalProperty(source, "generatedRouteTree");
      if (generatedRouteTree !== null) {
        const configured = safeConfiguredPath(workspaceRoot, record.absolutePath, generatedRouteTree, "generatedRouteTree", relativeFile, diagnostics);
        if (configured) {
          tanstackGeneratedFiles = [configured];
          diagnostics.push({ severity: "info", code: "web.static_config_literal_applied", message: `Applied static TanStack generatedRouteTree=${generatedRouteTree}`, path: relativeFile });
        }
      } else if (hasProperty(source, "generatedRouteTree")) diagnostics.push({ severity: "warning", code: "web.static_config_unresolved", message: "TanStack generatedRouteTree is not a static string literal", path: relativeFile });
    }
  }
  if (tanstackGeneratedFiles.length === 0) {
    tanstackGeneratedFiles = allFiles.filter((candidate) => /^routeTree\.gen\.(?:ts|tsx|js|jsx)$/u.test(path.basename(candidate)) && isWithinRoot(record.absolutePath, candidate));
  }
  return { nextBasePath, astroBasePath, tanstackBasePath, nextPageExtensions, astroPageRoots, tanstackRouteRoots, tanstackGeneratedFiles, diagnostics };
}

function evidence(relativeFile: string, extractor: string, generated = false, detail?: string): Evidence {
  return {
    kind: generated ? "build" : "source",
    extractor,
    extractor_version: "0.1.0",
    path: relativeFile,
    start_line: 1,
    start_column: 1,
    end_line: 1,
    end_column: 1,
    ...(detail ? { detail } : {}),
  };
}

function normalizePattern(segments: string[]): string {
  const converted: string[] = [];
  for (const raw of segments.filter((segment) => segment !== "" && segment !== ".").flatMap((segment) => segment.split("/"))) {
    if (/^\([^/]+\)$/u.test(raw) || raw.startsWith("@")) continue;
    let segment = raw;
    if (segment.startsWith("(...)")) {
      converted.length = 0;
      segment = segment.slice("(...)".length);
    } else {
      let parentMoves = 0;
      while (segment.startsWith("(..)")) {
        parentMoves += 1;
        segment = segment.slice("(..)".length);
      }
      if (segment.startsWith("(.)")) segment = segment.slice("(.)".length);
      if (parentMoves > 0) converted.splice(Math.max(0, converted.length - parentMoves));
    }
    if (!segment) continue;
    converted.push(segment
      .replace(/\[\[\.\.\.([^\]]+)\]\]/gu, (_match, name: string) => `$${name}*?`)
      .replace(/\[\.\.\.([^\]]+)\]/gu, (_match, name: string) => `$${name}*`)
      .replace(/\[([^\]]+)\]/gu, (_match, name: string) => `$${name}`));
  }
  return converted.length === 0 ? "/" : `/${converted.join("/")}`.replace(/\/{2,}/gu, "/");
}

function relativeUnder(base: string, file: string): string[] | null {
  const relative = path.relative(base, file);
  if (relative.startsWith("..") || path.isAbsolute(relative)) return null;
  return normalizeRelative(relative).split("/");
}

function hasDependency(record: PackageRecord, names: string[]): boolean {
  return names.some((name) => record.dependencies.has(name));
}

function nextStaticMetadataRoute(filename: string): string | null {
  const lower = filename.toLowerCase();
  if (["favicon.ico", "robots.txt", "sitemap.xml", "manifest.json", "manifest.webmanifest"].includes(lower)) return lower;
  return /^(?:icon|apple-icon|opengraph-image|twitter-image)\d*\.(?:jpg|jpeg|png|svg|ico)$/u.test(lower) ? lower : null;
}

function nextCodeMetadataRoute(base: string): string {
  if (base === "robots") return "robots.txt";
  if (base === "sitemap") return "sitemap.xml";
  if (base === "manifest") return "manifest.webmanifest";
  return base;
}

function nextPageExtension(filename: string, configured: Set<string> | null): string | null {
  const extensions = [...(configured ?? NEXT_PAGE_EXTENSIONS)]
    .map((extension) => extension.startsWith(".") ? extension : `.${extension}`)
    // A compound suffix such as `.page.tsx` must win over `.tsx` when both are
    // configured, otherwise the route stem would incorrectly retain `.page`.
    .sort((left, right) => right.length - left.length || compareUtf8(left, right));
  return extensions.find((extension) => filename.length > extension.length && filename.endsWith(extension)) ?? null;
}

function discoverNext(record: PackageRecord, allFiles: string[], root: string, config: StaticRouteConfig): RouteEntry[] {
  if (!hasDependency(record, ["next"]) && !allFiles.some((file) => /^next\.config\./u.test(path.basename(file)) && path.dirname(file) === record.absolutePath)) return [];
  const entries: RouteEntry[] = [];
  for (const file of allFiles) {
    const directory = path.dirname(file);
    if (directory !== record.absolutePath && directory !== path.join(record.absolutePath, "src")) continue;
    const filename = path.basename(file);
    const extension = nextPageExtension(filename, config.nextPageExtensions);
    if (extension === null) continue;
    const base = filename.slice(0, -extension.length);
    if (!NEXT_ROOT_SPECIAL_FILES.has(base)) continue;
    const relativeFile = normalizeRelative(path.relative(root, file));
    entries.push({
      framework: "next",
      pattern: `/_next/special/${base}`,
      absoluteFile: file,
      relativeFile,
      entryKind: base,
      generated: false,
      evidence: evidence(relativeFile, "next-filesystem-routes", false, `convention=${base};scope=root-special;url_route=false`),
    });
  }
  for (const routerRoot of [path.join(record.absolutePath, "app"), path.join(record.absolutePath, "src", "app")]) {
    for (const file of allFiles) {
      const parts = relativeUnder(routerRoot, file);
      if (!parts || parts.length === 0) continue;
      // Next App Router private folders opt the whole subtree out of routing;
      // dropping only the private segment would incorrectly expose its page.
      if (parts.slice(0, -1).some((segment) => segment.startsWith("_"))) continue;
      const filename = parts.at(-1)!;
      const staticMetadata = nextStaticMetadataRoute(filename);
      const extension = nextPageExtension(filename, config.nextPageExtensions);
      const base = extension === null ? filename : filename.slice(0, -extension.length);
      if (!staticMetadata && (extension === null || !NEXT_APP_FILES.has(base))) continue;
      const routeSegments = parts.slice(0, -1);
      if (staticMetadata) routeSegments.push(staticMetadata);
      else if (["sitemap", "robots", "manifest", "icon", "apple-icon", "opengraph-image", "twitter-image"].includes(base)) {
        routeSegments.push(nextCodeMetadataRoute(base));
      }
      const relativeFile = normalizeRelative(path.relative(root, file));
      entries.push({
        framework: "next",
        pattern: withBasePath(config.nextBasePath, normalizePattern(routeSegments)),
        absoluteFile: file,
        relativeFile,
        entryKind: staticMetadata ? "static-metadata" : base,
        generated: false,
        evidence: evidence(relativeFile, "next-filesystem-routes", false, `convention=${staticMetadata ?? base};basePath=${config.nextBasePath || "/"}`),
      });
    }
  }
  for (const routerRoot of [path.join(record.absolutePath, "pages"), path.join(record.absolutePath, "src", "pages")]) {
    for (const file of allFiles) {
      const parts = relativeUnder(routerRoot, file);
      if (!parts || parts.length === 0) continue;
      const filename = parts.at(-1)!;
      const extension = nextPageExtension(filename, config.nextPageExtensions);
      if (extension === null) continue;
      const base = filename.slice(0, -extension.length);
      if (base.startsWith("_")) continue;
      const routeSegments = [...parts.slice(0, -1), base];
      if (base === "index") routeSegments.pop();
      const relativeFile = normalizeRelative(path.relative(root, file));
      entries.push({
        framework: "next",
        pattern: withBasePath(config.nextBasePath, normalizePattern(routeSegments)),
        absoluteFile: file,
        relativeFile,
        entryKind: routeSegments[0] === "api" ? "api-route" : "page",
        generated: false,
        evidence: evidence(relativeFile, "next-filesystem-routes", false, `router=pages;basePath=${config.nextBasePath || "/"}`),
      });
    }
  }
  return entries;
}

function discoverAstro(record: PackageRecord, allFiles: string[], root: string, config: StaticRouteConfig): RouteEntry[] {
  if (!hasDependency(record, ["astro"]) && !allFiles.some((file) => /^astro\.config\./u.test(path.basename(file)) && path.dirname(file) === record.absolutePath)) return [];
  const entries: RouteEntry[] = [];
  for (const pagesRoot of config.astroPageRoots) {
    for (const file of allFiles) {
      const parts = relativeUnder(pagesRoot, file);
      if (!parts || parts.length === 0) continue;
      const extension = path.extname(parts.at(-1)!);
      if (!ASTRO_PAGE_EXTENSIONS.has(extension)) continue;
      const base = path.basename(parts.at(-1)!, extension);
      if (base.startsWith("_")) continue;
      const routeSegments = [...parts.slice(0, -1), base];
      if (base === "index") routeSegments.pop();
      const relativeFile = normalizeRelative(path.relative(root, file));
      entries.push({
        framework: "astro",
        pattern: withBasePath(config.astroBasePath, normalizePattern(routeSegments)),
        absoluteFile: file,
        relativeFile,
        entryKind: extension === ".js" || extension === ".ts" ? "endpoint" : "page",
        generated: false,
        evidence: evidence(relativeFile, "astro-filesystem-routes", false, `${extension === ".astro" ? "frontmatter=astro-compiler-4.0.0;" : ""}base=${config.astroBasePath || "/"}`),
      });
    }
  }
  return entries;
}

function tanstackFilesystemPattern(parts: string[]): string {
  const filename = parts.at(-1)!;
  const extension = path.extname(filename);
  const stem = path.basename(filename, extension).replace(/\.lazy$/u, "").replace(/\.route$/u, "");
  const segments = [...parts.slice(0, -1), ...stem.split(".")]
    .filter((segment) => segment !== "__root" && segment !== "index" && !segment.startsWith("_") && segment !== "route")
    .map((segment) => segment.replace(/_$/u, ""));
  return normalizePattern(segments);
}

function literalGeneratedRoutes(source: string, relativeFile: string): Array<{ pattern: string; evidence: Evidence }> {
  const result: Array<{ pattern: string; evidence: Evidence }> = [];
  function add(startOffset: number, endOffset: number, pattern: string, detail: string): void {
    if (!pattern.startsWith("/")) return;
    const startLines = source.slice(0, startOffset).split(/\r?\n/u);
    const endLines = source.slice(0, endOffset).split(/\r?\n/u);
    result.push({
      pattern: pattern === "" ? "/" : pattern,
      evidence: {
        kind: "build",
        extractor: "tanstack-generated-route-tree",
        extractor_version: "0.1.0",
        path: relativeFile,
        start_line: startLines.length,
        start_column: (startLines.at(-1)?.length ?? 0) + 1,
        end_line: endLines.length,
        end_column: (endLines.at(-1)?.length ?? 0) + 1,
        detail,
      },
    });
  }
  const routeLiteral = /(?:createFileRoute|createLazyFileRoute)\s*\(\s*(["'`])([^"'`\\]*)\1/gu;
  for (const match of source.matchAll(routeLiteral)) {
    if (match.index === undefined || !match[2]) continue;
    const valueOffset = match[0].lastIndexOf(match[2]);
    add(match.index + valueOffset, match.index + valueOffset + match[2].length, match[2], "source_route_literal");
  }
  const fullPathLiteral = /\bfullPath\s*:\s*(["'`])([^"'`\\]*)\1/gu;
  for (const match of source.matchAll(fullPathLiteral)) {
    if (match.index === undefined || !match[2]) continue;
    const valueOffset = match[0].lastIndexOf(match[2]);
    add(match.index + valueOffset, match.index + valueOffset + match[2].length, match[2], "generated_full_path");
  }
  return result;
}

async function discoverTanStack(record: PackageRecord, allFiles: string[], root: string, config: StaticRouteConfig): Promise<{ entries: RouteEntry[]; drift: RouteDrift | null }> {
  const isStart = hasDependency(record, ["@tanstack/start", "@tanstack/react-start"]);
  if (!isStart && !hasDependency(record, ["@tanstack/react-router", "@tanstack/router-core"])) return { entries: [], drift: null };
  const framework: RouteEntry["framework"] = isStart ? "tanstack-start" : "tanstack-router";
  const entries: RouteEntry[] = [];
  const staticPatterns = new Set<string>();
  const generatedPatterns = new Set<string>();
  const routeRoots = config.tanstackRouteRoots;
  for (const file of allFiles) {
    if (!TANSTACK_EXTENSIONS.has(path.extname(file))) continue;
    if (path.basename(file) === "routeTree.gen.ts" || path.basename(file) === "routeTree.gen.tsx") continue;
    const rootMatch = routeRoots.map((routeRoot) => relativeUnder(routeRoot, file)).find((parts) => parts !== null);
    if (!rootMatch) continue;
    if (rootMatch.some((segment) => segment.startsWith("-"))) continue;
    const relativeFile = normalizeRelative(path.relative(root, file));
    const source = await readUtf8(root, file);
    const explicit = source === null ? [] : literalGeneratedRoutes(source, relativeFile).filter((item) => item.evidence.detail === "source_route_literal");
    const patterns = explicit.length > 0 ? explicit : [{ pattern: tanstackFilesystemPattern(rootMatch), evidence: evidence(relativeFile, "tanstack-filesystem-routes") }];
    for (const item of patterns) {
      const pattern = withBasePath(config.tanstackBasePath, item.pattern);
      staticPatterns.add(pattern);
      entries.push({
        framework,
        pattern,
        absoluteFile: file,
        relativeFile,
        entryKind: "file-route",
        generated: false,
        evidence: item.evidence.kind === "build" ? { ...item.evidence, kind: "source", extractor: "tanstack-file-route-literal" } : item.evidence,
      });
    }
  }
  for (const file of config.tanstackGeneratedFiles) {
    const relativeFile = normalizeRelative(path.relative(root, file));
    const source = await readUtf8(root, file);
    if (source === null) continue;
    for (const item of literalGeneratedRoutes(source, relativeFile).filter((value) => value.evidence.detail === "generated_full_path")) {
      const pattern = withBasePath(config.tanstackBasePath, item.pattern);
      generatedPatterns.add(pattern);
      entries.push({
        framework,
        pattern,
        absoluteFile: file,
        relativeFile,
        entryKind: "generated-route",
        generated: true,
        evidence: item.evidence,
      });
    }
  }
  const drift = generatedPatterns.size === 0 ? null : {
    package: record,
    missingFromGenerated: [...staticPatterns].filter((pattern) => !generatedPatterns.has(pattern)).sort(),
    onlyGenerated: [...generatedPatterns].filter((pattern) => !staticPatterns.has(pattern)).sort(),
  };
  return { entries, drift };
}

export async function discoverRoutes(workspace: Workspace, allFiles: string[]): Promise<RouteDiscovery> {
  const entries: RouteEntry[] = [];
  const drifts: RouteDrift[] = [];
  const frameworks = new Set<string>();
  const configDiagnostics: RouteConfigDiagnostic[] = [];
  for (const record of workspace.packages) {
    const config = await staticRouteConfig(record, allFiles, workspace.root);
    configDiagnostics.push(...config.diagnostics);
    const next = discoverNext(record, allFiles, workspace.root, config);
    const astro = discoverAstro(record, allFiles, workspace.root, config);
    const tanstack = await discoverTanStack(record, allFiles, workspace.root, config);
    if (next.length > 0) frameworks.add("next");
    if (astro.length > 0) frameworks.add("astro");
    for (const entry of tanstack.entries) frameworks.add(entry.framework);
    entries.push(...next, ...astro, ...tanstack.entries);
    if (tanstack.drift && (tanstack.drift.missingFromGenerated.length > 0 || tanstack.drift.onlyGenerated.length > 0)) drifts.push(tanstack.drift);
  }
  entries.sort((left, right) => compareUtf8(
    `${left.framework}\0${left.pattern}\0${left.relativeFile}`,
    `${right.framework}\0${right.pattern}\0${right.relativeFile}`,
  ));
  configDiagnostics.sort((left, right) => compareUtf8(
    `${left.path}\0${left.code}\0${left.message}`,
    `${right.path}\0${right.code}\0${right.message}`,
  ));
  return { entries, drifts, frameworks: [...frameworks].sort(), configDiagnostics };
}
