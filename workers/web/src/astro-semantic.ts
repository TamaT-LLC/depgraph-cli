import path from "node:path";
import { parse as parseAstro } from "@astrojs/compiler/sync";
import type {
  AttributeNode,
  ComponentNode as AstroComponentNode,
  FrontmatterNode,
  Node as AstroNode,
} from "@astrojs/compiler/types";
import { SyntaxKind } from "typescript/unstable/ast";
import {
  WEB_FRAMEWORK_SEMANTIC_CAPABILITY,
  WEB_FRAMEWORK_SEMANTIC_EXTRACTOR_VERSION,
  type FrameworkSemanticDelta,
} from "./framework-semantic";
import {
  scanTypeScriptSyntaxTokens,
  type RawDependency,
  type Resolution,
  type ResolvedTarget,
  type TypeScriptSyntaxToken,
} from "./imports";
import { stableId } from "./ids";
import type { RouteEntry } from "./routes";
import type { TypeScriptRawDefinitionDelta } from "./typescript-semantic";
import type { TypeScriptRawDependencyDelta } from "./typescript-dependencies";
import {
  canonicalizeCondition,
  compareUtf8,
  preferredWebEnvironment,
  PROFILE_ID,
  type Condition,
  type DependencySite,
  type Diagnostic,
  type Evidence,
  type GraphEdge,
  type GraphNode,
  type JsonValue,
  type Precision,
  type ResolutionStatus,
} from "./types";
import type { PackageRecord } from "./workspace";

const ASTRO_EXTRACTOR = "astro-static-adapter";
const ASTRO_COMPILER_VERSION = "4.0.0";
const ASTRO_HTTP_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "ALL"] as const;
const ASTRO_COMPONENT_EXTENSIONS = new Set([".astro", ".md", ".mdx", ".html"]);
const ASTRO_SCRIPT_EXTENSIONS = new Set([".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs"]);
const ASTRO_ASSET_EXTENSIONS = new Set([
  ".avif", ".bmp", ".css", ".gif", ".ico", ".jpeg", ".jpg", ".less", ".png",
  ".sass", ".scss", ".svg", ".tiff", ".ttf", ".webp", ".woff", ".woff2",
]);
const ASTRO_CONTENT_EXTENSIONS = new Set([".json", ".md", ".mdx", ".yaml", ".yml"]);

type Span = {
  start_line: number;
  start_column: number;
  end_line: number;
  end_column: number;
};

interface ImportBinding {
  localName: string;
  importedName: string;
  namespace: boolean;
}

interface ImportRecord {
  moduleSpecifier: string;
  span: Span;
  bindings: ImportBinding[];
}

interface ContentCall {
  kind: "getCollection" | "getEntry";
  collection: string | null;
  entry: string | null;
  span: Span;
}

interface ParsedFrontmatter {
  imports: ImportRecord[];
  bindings: Map<string, { binding: ImportBinding; record: ImportRecord }>;
  flows: Map<string, string[]>;
  contentCalls: ContentCall[];
}

interface AstroDirective {
  name: string;
  value: string;
  valueKind: AttributeNode["kind"];
}

interface ResolvedTag {
  status: ResolutionStatus;
  precision: Precision;
  targets: GraphNode[];
  reason: string | null;
  algorithm: string | null;
  properties: Record<string, JsonValue>;
}

export interface AstroSemanticInput {
  root: string;
  entries: readonly RouteEntry[];
  sources: ReadonlyMap<string, string>;
  inventoryFiles: readonly string[];
  definitions: TypeScriptRawDefinitionDelta;
  dependencies: TypeScriptRawDependencyDelta;
  definitionNode(key: string): GraphNode | null;
  fileNode(relativePath: string): GraphNode | null;
  owner(entry: RouteEntry): PackageRecord;
  ownerForPath(relativePath: string): PackageRecord;
  resolveImport(relativePath: string, dependency: RawDependency): Promise<Resolution>;
  targetNode(target: ResolvedTarget): GraphNode;
  unknownTarget(): GraphNode;
}

export interface AstroSemanticResult {
  delta: FrameworkSemanticDelta;
  diagnostics: Array<Omit<Diagnostic, "id">>;
}

function position(source: string, offset: number): { line: number; column: number } {
  const lines = source.slice(0, Math.max(0, Math.min(source.length, offset))).split(/\r?\n/u);
  return { line: lines.length, column: (lines.at(-1)?.length ?? 0) + 1 };
}

function spanFor(source: string, startOffset: number, endOffset: number): Span {
  const start = position(source, startOffset);
  const end = position(source, Math.max(startOffset, endOffset));
  return {
    start_line: start.line,
    start_column: start.column,
    end_line: end.line,
    end_column: end.column,
  };
}

function offsetForPosition(source: string, line: number, column: number): number {
  let offset = 0;
  for (let current = 1; current < line; current += 1) {
    const newline = source.indexOf("\n", offset);
    if (newline < 0) return source.length;
    offset = newline + 1;
  }
  return Math.min(source.length, offset + Math.max(0, column - 1));
}

function fileSpan(source: string): Span {
  return spanFor(source, 0, source.length);
}

function entrySpan(entry: RouteEntry): Span {
  return {
    start_line: entry.evidence.start_line,
    start_column: entry.evidence.start_column,
    end_line: entry.evidence.end_line,
    end_column: entry.evidence.end_column,
  };
}

function spanFromNode(node: GraphNode): Span | null {
  const raw = node.properties.source_span;
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) return null;
  const value = raw as Record<string, JsonValue>;
  if (!["start_line", "start_column", "end_line", "end_column"].every((field) => (
    Number.isSafeInteger(value[field]) && Number(value[field]) >= 1
  ))) return null;
  return {
    start_line: Number(value.start_line),
    start_column: Number(value.start_column),
    end_line: Number(value.end_line),
    end_column: Number(value.end_column),
  };
}

function tagSpan(source: string, node: AstroComponentNode): Span {
  const point = node.position?.start;
  const approximate = point ? offsetForPosition(source, point.line, point.column) : 0;
  const lineStart = source.lastIndexOf("\n", Math.max(0, approximate - 1)) + 1;
  const lineEndValue = source.indexOf("\n", approximate);
  const lineEnd = lineEndValue < 0 ? source.length : lineEndValue;
  const escaped = node.name.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
  const searchStart = Math.max(lineStart, approximate - 2);
  const match = new RegExp(`<\\s*(${escaped})(?=[\\s/>])`, "u").exec(source.slice(searchStart, lineEnd));
  if (match?.index !== undefined && match[1]) {
    const nameOffset = searchStart + match.index + match[0].indexOf(match[1]);
    return spanFor(source, nameOffset, nameOffset + match[1].length);
  }
  return spanFor(source, approximate, Math.min(source.length, approximate + node.name.length));
}

function diagnosticSpan(source: string, line: number, column: number, length: number): Span {
  const start = offsetForPosition(source, Math.max(1, line), Math.max(1, column));
  return spanFor(source, start, Math.min(source.length, start + Math.max(1, length)));
}

function evidence(
  relativePath: string,
  span: Span,
  occurrenceKind: string,
  properties: Record<string, JsonValue> = {},
): Evidence[] {
  const common = {
    extractor: ASTRO_EXTRACTOR,
    extractor_version: WEB_FRAMEWORK_SEMANTIC_EXTRACTOR_VERSION,
    path: relativePath,
    ...span,
  };
  const shared: Record<string, JsonValue> = {
    profile_id: PROFILE_ID,
    framework: "astro",
    occurrence_kind: occurrenceKind,
    parser_backend: "astro-compiler-ast",
    astro_compiler_version: ASTRO_COMPILER_VERSION,
    ...properties,
  };
  return [
    { kind: "semantic", ...common, properties: { ...shared, contract_version: WEB_FRAMEWORK_SEMANTIC_CAPABILITY } },
    { kind: "source", ...common, properties: shared },
  ];
}

function astroCondition(
  environment: string,
  directive: AstroDirective | null = null,
  properties: Record<string, string> = {},
): Condition {
  const conditions: Condition[] = [
    { op: "eq", key: "mode", value: "production" },
    { op: "eq", key: "environment", value: environment },
    { op: "eq", key: "astro.router", value: "filesystem" },
  ];
  if (directive) {
    conditions.push({ op: "eq", key: "astro.directive", value: directive.name });
    if (directive.value !== "") conditions.push({ op: "eq", key: "astro.directive.value", value: directive.value.slice(0, 512) });
  }
  for (const [key, value] of Object.entries(properties).sort(([left], [right]) => compareUtf8(left, right))) {
    conditions.push({ op: "eq", key, value });
  }
  return canonicalizeCondition({ op: "all", conditions });
}

function componentKindForFile(relativePath: string): string {
  switch (path.posix.extname(relativePath).toLowerCase()) {
    case ".md": return "astro-markdown-component";
    case ".mdx": return "astro-mdx-component";
    case ".html": return "astro-html-component";
    default: return "astro-component";
  }
}

function fileComponent(
  relativePath: string,
  owner: PackageRecord,
  environment: string,
  source: string | undefined,
): GraphNode {
  const componentKind = componentKindForFile(relativePath);
  const resolverIdentity = `astro:file:${relativePath}#default`;
  const canonicalIdentity: Record<string, JsonValue> = {
    framework: "astro",
    package_locator: owner.locator,
    component_kind: componentKind,
    environment,
    resolver_identity: resolverIdentity,
  };
  const id = stableId("component", canonicalIdentity);
  return {
    id,
    kind: "component",
    locator: `component://astro/${encodeURIComponent(owner.locator)}/${id}`,
    display_name: path.posix.basename(relativePath),
    properties: {
      framework: "astro",
      package_locator: owner.locator,
      component_kind: componentKind,
      environment,
      profile_id: PROFILE_ID,
      canonical_identity: canonicalIdentity,
      resolver_identity: resolverIdentity,
      source_path: relativePath,
      source_span: source === undefined ? {
        start_line: 1, start_column: 1, end_line: 1, end_column: 1,
      } : fileSpan(source),
    },
  };
}

function symbolComponent(symbol: GraphNode, environment: string): GraphNode | null {
  const resolverIdentity = symbol.properties.resolver_identity;
  const packageLocator = symbol.properties.package_locator;
  const sourcePath = symbol.properties.source_path;
  if (typeof resolverIdentity !== "string" || resolverIdentity === ""
    || typeof packageLocator !== "string" || packageLocator === ""
    || typeof sourcePath !== "string" || sourcePath === "") return null;
  const componentKind = "astro-imported-script-component";
  const canonicalIdentity: Record<string, JsonValue> = {
    framework: "astro",
    package_locator: packageLocator,
    component_kind: componentKind,
    environment,
    resolver_identity: resolverIdentity,
  };
  const id = stableId("component", canonicalIdentity);
  return {
    id,
    kind: "component",
    locator: `component://astro/${encodeURIComponent(packageLocator)}/${id}`,
    display_name: symbol.display_name,
    properties: {
      framework: "astro",
      package_locator: packageLocator,
      component_kind: componentKind,
      environment,
      profile_id: PROFILE_ID,
      canonical_identity: canonicalIdentity,
      resolver_identity: resolverIdentity,
      source_path: sourcePath,
      source_span: symbol.properties.source_span ?? null,
      typescript_definition_id: symbol.id,
    },
  };
}

function frameworkRoute(entry: RouteEntry, owner: PackageRecord): GraphNode {
  const environment = preferredWebEnvironment("server");
  const routeKind = `astro-${entry.entryKind}`;
  const canonicalIdentity: Record<string, JsonValue> = {
    framework: "astro",
    package_locator: owner.locator,
    route_kind: routeKind,
    environment,
    router_instance: `astro:${owner.locator}:filesystem`,
    route_pattern: entry.pattern,
  };
  const id = stableId("route", canonicalIdentity);
  return {
    id,
    kind: "route",
    locator: `route://astro/${encodeURIComponent(owner.locator)}${entry.pattern}#${encodeURIComponent(routeKind)}`,
    display_name: `astro:${entry.entryKind}:${entry.pattern}`,
    properties: {
      framework: "astro",
      package_locator: owner.locator,
      route_kind: routeKind,
      environment,
      profile_id: PROFILE_ID,
      canonical_identity: canonicalIdentity,
      router_instance: canonicalIdentity.router_instance!,
      route_pattern: entry.pattern,
      source_path: entry.relativeFile,
    },
  };
}

function exportProofKey(relativePath: string, exportPath: readonly string[]): string {
  return JSON.stringify([relativePath, exportPath]);
}

type SyntaxToken = TypeScriptSyntaxToken;

function isNameToken(token: SyntaxToken | undefined): token is SyntaxToken {
  return token?.kind === SyntaxKind.Identifier;
}

function isStringToken(token: SyntaxToken | undefined): token is SyntaxToken {
  return token?.kind === SyntaxKind.StringLiteral || token?.kind === SyntaxKind.NoSubstitutionTemplateLiteral;
}

function matchingToken(
  tokens: readonly SyntaxToken[],
  openIndex: number,
  opening: SyntaxKind,
  closing: SyntaxKind,
): number | null {
  let depth = 0;
  for (let index = openIndex; index < tokens.length; index += 1) {
    if (tokens[index]?.kind === opening) depth += 1;
    else if (tokens[index]?.kind === closing) {
      depth -= 1;
      if (depth === 0) return index;
    }
  }
  return null;
}

function trimParentheses(tokens: readonly SyntaxToken[]): readonly SyntaxToken[] {
  let result = tokens;
  while (result[0]?.kind === SyntaxKind.OpenParenToken) {
    const closing = matchingToken(result, 0, SyntaxKind.OpenParenToken, SyntaxKind.CloseParenToken);
    if (closing !== result.length - 1) break;
    result = result.slice(1, -1);
  }
  return result;
}

function topLevelToken(tokens: readonly SyntaxToken[], kinds: ReadonlySet<SyntaxKind>): number | null {
  let paren = 0;
  let bracket = 0;
  let brace = 0;
  for (let index = 0; index < tokens.length; index += 1) {
    const kind = tokens[index]!.kind;
    if (kind === SyntaxKind.OpenParenToken) paren += 1;
    else if (kind === SyntaxKind.CloseParenToken) paren -= 1;
    else if (kind === SyntaxKind.OpenBracketToken) bracket += 1;
    else if (kind === SyntaxKind.CloseBracketToken) bracket -= 1;
    else if (kind === SyntaxKind.OpenBraceToken) brace += 1;
    else if (kind === SyntaxKind.CloseBraceToken) brace -= 1;
    else if (paren === 0 && bracket === 0 && brace === 0 && kinds.has(kind)) return index;
  }
  return null;
}

function dottedName(tokensValue: readonly SyntaxToken[]): string | null {
  const tokens = trimParentheses(tokensValue);
  if (tokens.length === 0 || !isNameToken(tokens[0])) return null;
  const parts = [tokens[0].value || tokens[0].text];
  for (let index = 1; index < tokens.length; index += 2) {
    if (tokens[index]?.kind !== SyntaxKind.DotToken || !isNameToken(tokens[index + 1])) return null;
    parts.push(tokens[index + 1]!.value || tokens[index + 1]!.text);
  }
  return parts.join(".");
}

function flowReferences(tokensValue: readonly SyntaxToken[]): string[] | null {
  const tokens = trimParentheses(tokensValue);
  const question = topLevelToken(tokens, new Set([SyntaxKind.QuestionToken]));
  if (question !== null) {
    let nested = 0;
    let colon: number | null = null;
    for (let index = question + 1; index < tokens.length; index += 1) {
      if (tokens[index]?.kind === SyntaxKind.QuestionToken) nested += 1;
      else if (tokens[index]?.kind === SyntaxKind.ColonToken) {
        if (nested === 0) {
          colon = index;
          break;
        }
        nested -= 1;
      }
    }
    if (colon === null) return null;
    const left = flowReferences(tokens.slice(question + 1, colon));
    const right = flowReferences(tokens.slice(colon + 1));
    return left === null || right === null ? null : [...new Set([...left, ...right])].sort(compareUtf8);
  }
  const alternative = topLevelToken(tokens, new Set([SyntaxKind.BarBarToken, SyntaxKind.QuestionQuestionToken]));
  if (alternative !== null) {
    const left = flowReferences(tokens.slice(0, alternative));
    const right = flowReferences(tokens.slice(alternative + 1));
    return left === null || right === null ? null : [...new Set([...left, ...right])].sort(compareUtf8);
  }
  const direct = dottedName(tokens);
  return direct === null ? null : [direct];
}

const STATEMENT_START_TOKENS = new Set<SyntaxKind>([
  SyntaxKind.ConstKeyword,
  SyntaxKind.ExportKeyword,
  SyntaxKind.ImportKeyword,
  SyntaxKind.LetKeyword,
  SyntaxKind.VarKeyword,
]);

function statementEnd(tokens: readonly SyntaxToken[], start: number, source: string): number {
  let paren = 0;
  let bracket = 0;
  let brace = 0;
  for (let index = start; index < tokens.length; index += 1) {
    const kind = tokens[index]!.kind;
    if (index > start && paren === 0 && bracket === 0 && brace === 0
      && STATEMENT_START_TOKENS.has(kind)
      && /[\r\n]/u.test(source.slice(tokens[index - 1]!.end, tokens[index]!.start))) {
      return index - 1;
    }
    if (kind === SyntaxKind.OpenParenToken) paren += 1;
    else if (kind === SyntaxKind.CloseParenToken) paren -= 1;
    else if (kind === SyntaxKind.OpenBracketToken) bracket += 1;
    else if (kind === SyntaxKind.CloseBracketToken) bracket -= 1;
    else if (kind === SyntaxKind.OpenBraceToken) brace += 1;
    else if (kind === SyntaxKind.CloseBraceToken) brace -= 1;
    if (kind === SyntaxKind.SemicolonToken && paren === 0 && bracket === 0 && brace === 0) return index;
  }
  return tokens.length - 1;
}

function parseFrontmatter(source: string, frontmatter: FrontmatterNode | null): ParsedFrontmatter {
  const result: ParsedFrontmatter = {
    imports: [],
    bindings: new Map(),
    flows: new Map(),
    contentCalls: [],
  };
  if (!frontmatter) return result;
  const valueStart = source.indexOf(frontmatter.value, Math.max(0, frontmatter.position?.start.offset ?? 0));
  if (valueStart < 0) return result;
  const tokens = scanTypeScriptSyntaxTokens(frontmatter.value, true);
  for (let index = 0; index < tokens.length; index += 1) {
    const token = tokens[index]!;
    if (token.kind === SyntaxKind.ImportKeyword) {
      const end = statementEnd(tokens, index, frontmatter.value);
      const from = tokens.slice(index + 1, end + 1).findIndex((candidate) => candidate.kind === SyntaxKind.FromKeyword);
      const moduleIndex = from >= 0 ? index + 2 + from : index + 1;
      const moduleToken = tokens[moduleIndex];
      if (!isStringToken(moduleToken)) continue;
      const record: ImportRecord = {
        moduleSpecifier: moduleToken.value,
        span: spanFor(source, valueStart + token.start, valueStart + (tokens[end]?.end ?? moduleToken.end)),
        bindings: [],
      };
      const clauseEnd = from >= 0 ? index + 1 + from : index + 1;
      let cursor = index + 1;
      if (isNameToken(tokens[cursor])) {
        record.bindings.push({ localName: tokens[cursor]!.value, importedName: "default", namespace: false });
        cursor += tokens[cursor + 1]?.kind === SyntaxKind.CommaToken ? 2 : 1;
      }
      if (tokens[cursor]?.kind === SyntaxKind.OpenBraceToken) {
        cursor += 1;
        while (cursor < clauseEnd && tokens[cursor]?.kind !== SyntaxKind.CloseBraceToken) {
          if (tokens[cursor]?.kind === SyntaxKind.TypeKeyword) cursor += 1;
          const imported = tokens[cursor];
          if (!isNameToken(imported)) {
            cursor += 1;
            continue;
          }
          let local = imported;
          if (tokens[cursor + 1]?.kind === SyntaxKind.AsKeyword && isNameToken(tokens[cursor + 2])) {
            local = tokens[cursor + 2]!;
            cursor += 2;
          }
          record.bindings.push({
            localName: local.value,
            importedName: imported.value,
            namespace: false,
          });
          cursor += 1;
          if (tokens[cursor]?.kind === SyntaxKind.CommaToken) cursor += 1;
        }
      } else if (tokens[cursor]?.kind === SyntaxKind.AsteriskToken
        && tokens[cursor + 1]?.kind === SyntaxKind.AsKeyword
        && isNameToken(tokens[cursor + 2])) {
        record.bindings.push({ localName: tokens[cursor + 2]!.value, importedName: "*", namespace: true });
      }
      result.imports.push(record);
      for (const binding of record.bindings) result.bindings.set(binding.localName, { binding, record });
      index = end;
      continue;
    }
    if (token.kind !== SyntaxKind.ConstKeyword || !isNameToken(tokens[index + 1])
      || tokens[index + 2]?.kind !== SyntaxKind.EqualsToken) continue;
    const end = statementEnd(tokens, index, frontmatter.value);
    const references = flowReferences(tokens.slice(index + 3, tokens[end]?.kind === SyntaxKind.SemicolonToken ? end : end + 1));
    if (references !== null && references.length > 0) {
      result.flows.set(tokens[index + 1]!.value, references);
    }
  }

  const contentBinding = (expression: readonly SyntaxToken[]): "getCollection" | "getEntry" | null => {
    const name = dottedName(expression);
    if (name === null) return null;
    const [root, member] = name.split(".");
    if (!root) return null;
    const imported = result.bindings.get(root);
    if (!imported || imported.record.moduleSpecifier !== "astro:content") return null;
    const candidate = imported.binding.namespace ? member : imported.binding.importedName;
    return candidate === "getCollection" || candidate === "getEntry" ? candidate : null;
  };
  for (let index = 0; index < tokens.length; index += 1) {
    if (!isNameToken(tokens[index])) continue;
    let cursor = index + 1;
    while (tokens[cursor]?.kind === SyntaxKind.DotToken && isNameToken(tokens[cursor + 1])) cursor += 2;
    if (tokens[cursor]?.kind !== SyntaxKind.OpenParenToken) continue;
    const closing = matchingToken(tokens, cursor, SyntaxKind.OpenParenToken, SyntaxKind.CloseParenToken);
    if (closing === null) continue;
    const kind = contentBinding(tokens.slice(index, cursor));
    if (!kind) continue;
    const argumentTokens = tokens.slice(cursor + 1, closing);
    const comma = topLevelToken(argumentTokens, new Set([SyntaxKind.CommaToken]));
    const first = trimParentheses(argumentTokens.slice(0, comma ?? argumentTokens.length));
    const second = comma === null ? [] : trimParentheses(argumentTokens.slice(comma + 1));
    result.contentCalls.push({
      kind,
      collection: first.length === 1 && isStringToken(first[0]) ? first[0].value : null,
      entry: kind === "getEntry" && second.length === 1 && isStringToken(second[0]) ? second[0].value : null,
      span: spanFor(source, valueStart + tokens[index]!.start, valueStart + tokens[closing]!.end),
    });
    index = closing;
  }
  result.imports.sort((left, right) => (
    left.span.start_line - right.span.start_line
    || left.span.start_column - right.span.start_column
    || compareUtf8(left.moduleSpecifier, right.moduleSpecifier)
  ));
  result.contentCalls.sort((left, right) => (
    left.span.start_line - right.span.start_line
    || left.span.start_column - right.span.start_column
  ));
  return result;
}

function collectAstroComponents(node: AstroNode, result: AstroComponentNode[]): void {
  if (node.type === "component") result.push(node);
  if ("children" in node) for (const child of node.children) collectAstroComponents(child, result);
}

function directiveFor(node: AstroComponentNode): { directive: AstroDirective | null; multiple: boolean } {
  const directives = node.attributes.filter((attribute) => (
    attribute.name.startsWith("client:") || attribute.name === "server:defer"
  ));
  if (directives.length !== 1) return { directive: null, multiple: directives.length > 1 };
  const attribute = directives[0]!;
  return {
    directive: { name: attribute.name, value: attribute.value.slice(0, 512), valueKind: attribute.kind },
    multiple: false,
  };
}

function normalizedStatus(status: ResolutionStatus, count: number): ResolutionStatus {
  if (status === "resolved" && count > 1) return "candidates";
  return status;
}

export async function collectAstroSemanticDelta(input: AstroSemanticInput): Promise<AstroSemanticResult> {
  const nodes = new Map<string, GraphNode>();
  const sites = new Map<string, DependencySite>();
  const edges = new Map<string, GraphEdge>();
  const diagnostics: Array<Omit<Diagnostic, "id">> = [];
  const diagnosticKeys = new Set<string>();
  const definitions = new Map(input.definitions.definitions.map((definition) => [definition.key, definition]));
  const proofKeys = new Map(input.dependencies.moduleExports.map((proof) => [
    exportProofKey(proof.relativePath, proof.exportPath),
    proof.definitionKeys,
  ]));
  const exportedDefinitionKeys = (relativePath: string, exportName: string): string[] => (
    [...new Set(proofKeys.get(exportProofKey(relativePath, [exportName])) ?? [])]
      .filter((key) => definitions.get(key)?.graphKind === "symbol")
      .sort(compareUtf8)
  );
  const addDiagnostic = (diagnostic: Omit<Diagnostic, "id">): void => {
    const key = JSON.stringify([diagnostic.code, diagnostic.path, diagnostic.message]);
    if (!diagnosticKeys.has(key)) diagnostics.push(diagnostic);
    diagnosticKeys.add(key);
  };
  const addNode = (node: GraphNode): GraphNode => {
    const existing = nodes.get(node.id);
    if (existing && JSON.stringify(existing) !== JSON.stringify(node)) {
      throw new Error(`Astro semantic collector produced conflicting node ${node.id}`);
    }
    nodes.set(node.id, existing ?? node);
    return existing ?? node;
  };
  const addRelation = (
    source: GraphNode,
    targetsValue: readonly GraphNode[],
    kind: string,
    specifier: string,
    relativePath: string,
    span: Span,
    condition: Condition,
    environment: string,
    occurrenceKind: string,
    status: ResolutionStatus = "resolved",
    reason: string | null = null,
    algorithm: string | null = null,
    extraEvidence: Record<string, JsonValue> = {},
    precisionValue: Precision | null = null,
  ): void => {
    const targets = [...new Map(targetsValue.map((target) => [target.id, target])).values()]
      .sort((left, right) => compareUtf8(left.id, right.id));
    if (targets.length === 0) throw new Error(`Astro semantic relation ${kind} has no target`);
    const precision: Precision = precisionValue
      ?? (status === "candidates" ? "overapprox" : status === "unresolved" ? "heuristic" : "exact");
    const relationEvidence = evidence(relativePath, span, occurrenceKind, {
      ...extraEvidence,
      ...(algorithm ? { algorithm } : {}),
    });
    const canonicalCondition = canonicalizeCondition(condition);
    const siteId = stableId("site", {
      condition: canonicalCondition,
      kind,
      path: relativePath,
      profile_id: PROFILE_ID,
      source: source.id,
      span,
    });
    const site: DependencySite = {
      id: siteId,
      source: source.id,
      kind,
      specifier,
      resolution_status: status,
      target_ids: targets.map((target) => target.id),
      profile_id: PROFILE_ID,
      condition: canonicalCondition,
      precision,
      reason,
      evidence: relationEvidence,
    };
    const existingSite = sites.get(site.id);
    if (existingSite && JSON.stringify(existingSite) !== JSON.stringify(site)) {
      throw new Error(`Astro semantic collector produced conflicting site ${site.id}`);
    }
    sites.set(site.id, existingSite ?? site);
    for (const target of targets) {
      const edge: GraphEdge = {
        id: stableId("edge", { kind, site_id: site.id, target: target.id }),
        source: source.id,
        target: target.id,
        kind,
        site_id: site.id,
        phase: "semantic",
        environment,
        profile_id: PROFILE_ID,
        condition: canonicalCondition,
        resolution_status: status,
        precision,
        generated: false,
        evidence: relationEvidence,
      };
      const existingEdge = edges.get(edge.id);
      if (existingEdge && JSON.stringify(existingEdge) !== JSON.stringify(edge)) {
        throw new Error(`Astro semantic collector produced conflicting edge ${edge.id}`);
      }
      edges.set(edge.id, existingEdge ?? edge);
    }
  };

  const componentCache = new Map<string, GraphNode>();
  const componentForFile = (relativePath: string, environment: string): GraphNode => {
    const key = `file\0${relativePath}\0${environment}`;
    const existing = componentCache.get(key);
    if (existing) return existing;
    const component = addNode(fileComponent(
      relativePath,
      input.ownerForPath(relativePath),
      environment,
      input.sources.get(relativePath),
    ));
    componentCache.set(key, component);
    return component;
  };
  const componentForDefinition = (key: string, environment: string): GraphNode | null => {
    const cacheKey = `definition\0${key}\0${environment}`;
    const existing = componentCache.get(cacheKey);
    if (existing) return existing;
    const symbol = input.definitionNode(key);
    if (!symbol) return null;
    const component = symbolComponent(symbol, environment);
    if (!component) return null;
    const added = addNode(component);
    componentCache.set(cacheKey, added);
    return added;
  };

  for (const entry of input.entries.filter((candidate) => candidate.framework === "astro")) {
    const owner = input.owner(entry);
    const route = addNode(frameworkRoute(entry, owner));
    const extension = path.posix.extname(entry.relativeFile).toLowerCase();
    if (ASTRO_COMPONENT_EXTENSIONS.has(extension)) {
      const component = componentForFile(entry.relativeFile, preferredWebEnvironment("server"));
      const span = entrySpan(entry);
      addRelation(
        component, [route], "route_entry", entry.pattern, entry.relativeFile, span,
        astroCondition(preferredWebEnvironment("server")), preferredWebEnvironment("server"),
        "astro_route_entry", "resolved", null, null,
        { route_kind: entry.entryKind },
      );
      addRelation(
        route, [component], "renders", entry.pattern, entry.relativeFile, span,
        astroCondition(preferredWebEnvironment("server")), preferredWebEnvironment("server"),
        "astro_route_render", "resolved", null, null,
        { route_kind: entry.entryKind },
      );
      continue;
    }
    const handlers = ASTRO_HTTP_METHODS.flatMap((method) => (
      exportedDefinitionKeys(entry.relativeFile, method).map((key) => ({ method, key }))
    ));
    if (handlers.length > 0) {
      for (const { method, key } of handlers) {
        const symbol = input.definitionNode(key);
        if (!symbol) continue;
        const span = spanFromNode(symbol) ?? entrySpan(entry);
        const condition = astroCondition(preferredWebEnvironment("server"), null, { "astro.method": method });
        addRelation(
          symbol, [route], "route_entry", entry.pattern, entry.relativeFile, span,
          condition, preferredWebEnvironment("server"), "astro_endpoint_route_entry",
          "resolved", null, null, { http_method: method },
        );
        addRelation(
          route, [symbol], "handled_by", method, entry.relativeFile, span,
          condition, preferredWebEnvironment("server"), "astro_endpoint_handler",
          "resolved", null, null, { http_method: method },
        );
      }
    } else {
      const file = input.fileNode(entry.relativeFile);
      if (!file) throw new Error(`Astro route has no inventory file ${entry.relativeFile}`);
      addRelation(
        file, [route], "route_entry", entry.pattern, entry.relativeFile, entrySpan(entry),
        astroCondition(preferredWebEnvironment("server")), preferredWebEnvironment("server"),
        "astro_file_route_entry", "resolved", null, null,
        { route_kind: entry.entryKind },
      );
      if (entry.entryKind === "endpoint") {
        addRelation(
          route, [input.unknownTarget()], "handled_by", entry.relativeFile, entry.relativeFile, entrySpan(entry),
          astroCondition(preferredWebEnvironment("server")), preferredWebEnvironment("server"),
          "astro_endpoint_handler_unresolved", "unresolved", "astro_endpoint_export_unresolved",
        );
      }
    }
  }

  const resolutionCache = new Map<string, Promise<Resolution>>();
  const resolveRecord = (relativePath: string, record: ImportRecord): Promise<Resolution> => {
    const key = JSON.stringify([relativePath, record.moduleSpecifier]);
    const existing = resolutionCache.get(key);
    if (existing) return existing;
    const dependency: RawDependency = {
      kind: "import",
      edgeKind: "imports",
      specifier: record.moduleSpecifier,
      literal: true,
      typeOnly: false,
      evidence: {
        kind: "source",
        extractor: "astro-compiler-frontmatter",
        extractor_version: ASTRO_COMPILER_VERSION,
        path: relativePath,
        ...record.span,
      },
    };
    const pending = input.resolveImport(relativePath, dependency);
    resolutionCache.set(key, pending);
    return pending;
  };
  const targetRelativePath = (target: Extract<ResolvedTarget, { kind: "file" }>): string => {
    const relative = path.relative(input.root, target.absolutePath).replaceAll("\\", "/");
    return relative === ".." || relative.startsWith("../") || path.posix.isAbsolute(relative) ? "" : relative;
  };
  const componentTargets = async (
    relativePath: string,
    binding: ImportBinding,
    record: ImportRecord,
    importedName: string,
    environment: string,
  ): Promise<ResolvedTag> => {
    const resolution = await resolveRecord(relativePath, record);
    if (resolution.status === "external" && resolution.targets.length === 1) {
      return {
        status: "external",
        precision: resolution.precision === "heuristic" ? "heuristic" : "exact",
        targets: [input.targetNode(resolution.targets[0]!)],
        reason: resolution.reason,
        algorithm: null,
        properties: {
          module_specifier: record.moduleSpecifier,
          imported_name: importedName,
          local_name: binding.localName,
        },
      };
    }
    const targets: GraphNode[] = [];
    for (const target of resolution.targets) {
      if (target.kind !== "file") continue;
      const targetPath = targetRelativePath(target);
      if (targetPath === "") continue;
      const extension = path.posix.extname(targetPath).toLowerCase();
      if (ASTRO_COMPONENT_EXTENSIONS.has(extension)) {
        if (importedName === "default") targets.push(componentForFile(targetPath, environment));
        continue;
      }
      if (!ASTRO_SCRIPT_EXTENSIONS.has(extension)) continue;
      for (const key of exportedDefinitionKeys(targetPath, importedName)) {
        const component = componentForDefinition(key, environment);
        if (component) targets.push(component);
      }
    }
    const unique = [...new Map(targets.map((target) => [target.id, target])).values()]
      .sort((left, right) => compareUtf8(left.id, right.id));
    if (unique.length === 0) {
      return {
        status: "unresolved",
        precision: "heuristic",
        targets: [input.unknownTarget()],
        reason: resolution.reason ?? "astro_component_export_unresolved",
        algorithm: null,
        properties: {
          module_specifier: record.moduleSpecifier,
          imported_name: importedName,
          local_name: binding.localName,
        },
      };
    }
    const status = normalizedStatus(resolution.status, unique.length);
    if (status !== "resolved" && status !== "candidates") {
      return {
        status: "unresolved",
        precision: "heuristic",
        targets: [input.unknownTarget()],
        reason: "astro_component_target_set_not_closed",
        algorithm: null,
        properties: { module_specifier: record.moduleSpecifier, imported_name: importedName, local_name: binding.localName },
      };
    }
    return {
      status,
      precision: status === "candidates" ? "overapprox" : "exact",
      targets: unique,
      reason: status === "candidates" ? resolution.reason ?? "multiple_astro_component_targets" : null,
      algorithm: status === "candidates" ? "astro-static-import-targets-v1" : null,
      properties: {
        module_specifier: record.moduleSpecifier,
        imported_name: importedName,
        local_name: binding.localName,
      },
    };
  };

  const resolveReference = async (
    relativePath: string,
    parsed: ParsedFrontmatter,
    reference: string,
    environment: string,
  ): Promise<ResolvedTag | null> => {
    const [root, member] = reference.split(".");
    if (!root) return null;
    const imported = parsed.bindings.get(root);
    if (!imported) return null;
    if (imported.binding.namespace) {
      if (!member) return null;
      return await componentTargets(relativePath, imported.binding, imported.record, member, environment);
    }
    if (member) return null;
    return await componentTargets(
      relativePath,
      imported.binding,
      imported.record,
      imported.binding.importedName,
      environment,
    );
  };
  const resolveTag = async (
    relativePath: string,
    parsed: ParsedFrontmatter,
    name: string,
    environment: string,
  ): Promise<ResolvedTag> => {
    const direct = await resolveReference(relativePath, parsed, name, environment);
    if (direct) return direct;
    const references = parsed.flows.get(name);
    if (!references) {
      return {
        status: "unresolved", precision: "heuristic", targets: [input.unknownTarget()],
        reason: "astro_template_component_import_missing", algorithm: null,
        properties: { local_name: name },
      };
    }
    const resolved = await Promise.all(references.map(async (reference) => (
      await resolveReference(relativePath, parsed, reference, environment)
    )));
    if (resolved.some((target) => target === null || target.status !== "resolved")) {
      return {
        status: "unresolved", precision: "heuristic", targets: [input.unknownTarget()],
        reason: "astro_dynamic_component_flow_incomplete", algorithm: null,
        properties: { local_name: name, candidate_references: references },
      };
    }
    const targets = [...new Map(resolved.flatMap((target) => target!.targets).map((target) => [target.id, target])).values()]
      .sort((left, right) => compareUtf8(left.id, right.id));
    return {
      status: targets.length === 1 ? "resolved" : "candidates",
      precision: targets.length === 1 ? "exact" : "overapprox",
      targets,
      reason: targets.length === 1 ? null : "multiple_closed_frontmatter_component_targets",
      algorithm: targets.length === 1 ? null : "astro-closed-frontmatter-component-flow-v1",
      properties: { local_name: name, candidate_references: references },
    };
  };

  for (const [relativePath, source] of [...input.sources].sort(([left], [right]) => compareUtf8(left, right))) {
    const sourceComponent = componentForFile(relativePath, preferredWebEnvironment("server"));
    let parsedAstro: ReturnType<typeof parseAstro>;
    try {
      parsedAstro = parseAstro(source, { position: true });
    } catch (error) {
      const span = { start_line: 1, start_column: 1, end_line: 1, end_column: 1 };
      addRelation(
        sourceComponent, [input.unknownTarget()], "renders", "astro:template", relativePath, span,
        astroCondition(preferredWebEnvironment("server")), preferredWebEnvironment("server"),
        "astro_template_parse_unresolved", "unresolved", "astro_parser_failure", null,
        { parser_error: (error instanceof Error ? error.message : String(error)).slice(0, 512) },
      );
      addDiagnostic({
        severity: "warning", code: "web.astro_template_parse_failed",
        message: `Astro template graph could not be parsed: ${error instanceof Error ? error.message : String(error)}`.slice(0, 2_048),
        path: relativePath, profile_id: PROFILE_ID,
        evidence: [evidence(relativePath, span, "astro_template_parse_unresolved")[1]!],
        properties: { framework_semantic_issue: true },
      });
      continue;
    }
    const errors = parsedAstro.diagnostics.filter((diagnostic) => diagnostic.severity === 1);
    for (const diagnostic of parsedAstro.diagnostics) {
      const span = diagnosticSpan(source, diagnostic.location.line, diagnostic.location.column, diagnostic.location.length);
      addDiagnostic({
        severity: diagnostic.severity === 1 ? "warning" : "info",
        code: diagnostic.severity === 1 ? "web.astro_template_parse_failed" : "web.astro_template_parser_diagnostic",
        message: `Astro compiler ${diagnostic.code}: ${diagnostic.text}`.slice(0, 2_048),
        path: relativePath, profile_id: PROFILE_ID,
        evidence: [evidence(relativePath, span, "astro_template_parser_diagnostic", { diagnostic_code: diagnostic.code })[1]!],
        ...(diagnostic.severity === 1 ? { properties: { framework_semantic_issue: true } } : {}),
      });
      if (diagnostic.severity === 1) {
        addRelation(
          sourceComponent, [input.unknownTarget()], "renders", "astro:template", relativePath, span,
          astroCondition(preferredWebEnvironment("server")), preferredWebEnvironment("server"),
          "astro_template_parse_unresolved", "unresolved", `astro_parser_diagnostic_${diagnostic.code}`,
          null, { diagnostic_code: diagnostic.code },
        );
      }
    }
    const frontmatter = parsedAstro.ast.children.find((node): node is FrontmatterNode => node.type === "frontmatter") ?? null;
    const parsed = parseFrontmatter(source, frontmatter);
    const occurrences: AstroComponentNode[] = [];
    collectAstroComponents(parsedAstro.ast, occurrences);
    occurrences.sort((left, right) => {
      const leftSpan = tagSpan(source, left);
      const rightSpan = tagSpan(source, right);
      return leftSpan.start_line - rightSpan.start_line
        || leftSpan.start_column - rightSpan.start_column
        || compareUtf8(left.name, right.name);
    });
    for (const occurrence of occurrences) {
      const span = tagSpan(source, occurrence);
      const { directive, multiple } = directiveFor(occurrence);
      if (multiple) {
        addRelation(
          sourceComponent, [input.unknownTarget()], "renders", occurrence.name, relativePath, span,
          astroCondition(preferredWebEnvironment("server")), preferredWebEnvironment("server"),
          "astro_component_directive_unresolved", "unresolved", "multiple_astro_environment_directives",
          null, { tag_name: occurrence.name },
        );
        continue;
      }
      const isClient = directive?.name.startsWith("client:") === true;
      const clientOnly = directive?.name === "client:only";
      const renderEnvironment = clientOnly ? preferredWebEnvironment("browser") : preferredWebEnvironment("server");
      const rendered = await resolveTag(relativePath, parsed, occurrence.name, renderEnvironment);
      const occurrenceKind = rendered.status === "unresolved"
        ? "astro_component_render_unresolved"
        : rendered.status === "candidates" ? "astro_dynamic_component_render" : "astro_component_render";
      addRelation(
        sourceComponent, rendered.targets, "renders", occurrence.name, relativePath, span,
        astroCondition(renderEnvironment, directive), renderEnvironment, occurrenceKind,
        rendered.status, rendered.reason, rendered.algorithm,
        {
          tag_name: occurrence.name,
          ...(directive ? {
            directive: directive.name,
            directive_value: directive.value,
            directive_value_kind: directive.valueKind,
          } : {}),
          ...rendered.properties,
        },
        rendered.precision,
      );
      if (rendered.status === "unresolved") {
        addDiagnostic({
          severity: "warning", code: "web.astro_component_unresolved",
          message: `Astro template component ${occurrence.name} could not be resolved: ${rendered.reason ?? "unknown reason"}`,
          path: relativePath, profile_id: PROFILE_ID,
          evidence: [evidence(relativePath, span, occurrenceKind, { tag_name: occurrence.name })[1]!],
          properties: { framework_semantic_issue: true },
        });
      }
      if (rendered.status === "candidates" && isClient) {
        addDiagnostic({
          severity: "warning", code: "web.astro_hydration_candidates_unresolved",
          message: `Astro hydration for dynamic component ${occurrence.name} retained render candidates but was not promoted to exact hydration edges`,
          path: relativePath, profile_id: PROFILE_ID,
          evidence: [evidence(relativePath, span, occurrenceKind, { tag_name: occurrence.name })[1]!],
          properties: { framework_semantic_issue: true },
        });
      }
      if (isClient && (rendered.status === "resolved" || rendered.status === "external")) {
        const browser = await resolveTag(relativePath, parsed, occurrence.name, preferredWebEnvironment("browser"));
        if (browser.status === rendered.status && browser.targets.length === 1) {
          const condition = astroCondition(preferredWebEnvironment("browser"), directive);
          for (const kind of ["hydrates", "client_boundary"] as const) {
            addRelation(
              sourceComponent, browser.targets, kind, occurrence.name, relativePath, span,
              condition, preferredWebEnvironment("browser"), `astro_${kind}`,
              browser.status, browser.reason, null,
              {
                tag_name: occurrence.name,
                directive: directive!.name,
                directive_value: directive!.value,
                directive_value_kind: directive!.valueKind,
                ...browser.properties,
              },
              browser.precision,
            );
          }
        }
      } else if (directive?.name === "server:defer" && (rendered.status === "resolved" || rendered.status === "external")) {
        addRelation(
          sourceComponent, rendered.targets, "server_boundary", occurrence.name, relativePath, span,
          astroCondition(preferredWebEnvironment("server"), directive), preferredWebEnvironment("server"),
          "astro_server_defer_boundary", rendered.status, rendered.reason, null,
          {
            tag_name: occurrence.name,
            directive: directive.name,
            ...rendered.properties,
          },
          rendered.precision,
        );
      }
    }

    for (const record of parsed.imports) {
      const specifierExtension = path.posix.extname(record.moduleSpecifier.replace(/[?#].*$/u, "")).toLowerCase();
      if (!ASTRO_ASSET_EXTENSIONS.has(specifierExtension)) continue;
      const resolution = await resolveRecord(relativePath, record);
      const assetTargets = resolution.targets
        .filter((target): target is Extract<ResolvedTarget, { kind: "file" }> => target.kind === "file")
        .map((target) => input.targetNode(target))
        .filter((target) => target.kind === "file")
        .sort((left, right) => compareUtf8(left.id, right.id));
      const status = assetTargets.length === 0 ? "unresolved" : normalizedStatus(resolution.status, assetTargets.length);
      const targets = assetTargets.length === 0 ? [input.unknownTarget()] : assetTargets;
      const algorithm = status === "candidates" ? "astro-static-asset-import-targets-v1" : null;
      addRelation(
        sourceComponent, targets, "loads", record.moduleSpecifier, relativePath, record.span,
        astroCondition(preferredWebEnvironment("server"), null, { "astro.resource": "asset" }),
        preferredWebEnvironment("server"), status === "unresolved" ? "astro_asset_load_unresolved" : "astro_asset_load",
        status, status === "unresolved" ? resolution.reason ?? "astro_asset_target_not_found" : resolution.reason,
        algorithm, { module_specifier: record.moduleSpecifier, resource_kind: "asset" },
        status === "unresolved" ? "heuristic" : status === "candidates" ? "overapprox" : "exact",
      );
    }

    for (const call of parsed.contentCalls) {
      const owner = input.ownerForPath(relativePath);
      const ownerRoot = owner.relativePath === "." ? "" : owner.relativePath;
      const collection = call.collection;
      const entry = call.entry;
      const safeCollection = collection !== null && /^[A-Za-z0-9_-]+(?:\/[A-Za-z0-9_-]+)*$/u.test(collection);
      const safeEntry = entry === null || /^[A-Za-z0-9_.-]+(?:\/[A-Za-z0-9_.-]+)*$/u.test(entry);
      let targetPaths: string[] = [];
      if (safeCollection && safeEntry) {
        const prefix = path.posix.join(ownerRoot, "src/content", collection!);
        targetPaths = input.inventoryFiles.filter((candidate) => {
          if (!(candidate === prefix || candidate.startsWith(`${prefix}/`))) return false;
          const extension = path.posix.extname(candidate).toLowerCase();
          if (!ASTRO_CONTENT_EXTENSIONS.has(extension)) return false;
          if (call.kind === "getCollection") return true;
          const relativeEntry = candidate.slice(prefix.length + 1, -extension.length);
          return relativeEntry === entry;
        }).sort(compareUtf8);
      }
      const contentTargets = targetPaths.map((targetPath) => input.fileNode(targetPath)).filter((target): target is GraphNode => target !== null);
      const status: ResolutionStatus = contentTargets.length === 0 ? "unresolved" : contentTargets.length === 1 ? "resolved" : "candidates";
      const targets = contentTargets.length === 0 ? [input.unknownTarget()] : contentTargets;
      const specifier = collection === null
        ? `astro:content/${call.kind}/<computed>`
        : `astro:content/${collection}${entry === null ? "" : `/${entry}`}`;
      addRelation(
        sourceComponent, targets, "loads", specifier, relativePath, call.span,
        astroCondition(preferredWebEnvironment("server"), null, {
          "astro.resource": "content",
          ...(collection === null ? {} : { "astro.content.collection": collection }),
        }),
        preferredWebEnvironment("server"), status === "unresolved" ? "astro_content_load_unresolved" : "astro_content_load",
        status,
        status === "unresolved"
          ? collection === null || !safeCollection || !safeEntry ? "astro_content_specifier_non_literal_or_unsafe" : "astro_content_entry_not_found"
          : status === "candidates" ? "astro_content_collection_entries" : null,
        status === "candidates" ? "astro-static-content-collection-v1" : null,
        {
          content_api: call.kind,
          content_collection: collection ?? "computed",
          ...(entry === null ? {} : { content_entry: entry }),
        },
      );
    }

    if (errors.length > 0 && occurrences.length === 0) {
      addDiagnostic({
        severity: "warning", code: "web.astro_template_graph_incomplete",
        message: "Astro template parser errors prevented component occurrence collection",
        path: relativePath, profile_id: PROFILE_ID,
        properties: { framework_semantic_issue: true },
      });
    }
  }

  return {
    delta: {
      nodes: [...nodes.values()].sort((left, right) => compareUtf8(left.id, right.id)),
      sites: [...sites.values()].sort((left, right) => compareUtf8(left.id, right.id)),
      edges: [...edges.values()].sort((left, right) => compareUtf8(left.id, right.id)),
    },
    diagnostics: diagnostics.sort((left, right) => compareUtf8(
      `${left.path ?? ""}\0${left.code}\0${left.message}`,
      `${right.path ?? ""}\0${right.code}\0${right.message}`,
    )),
  };
}
