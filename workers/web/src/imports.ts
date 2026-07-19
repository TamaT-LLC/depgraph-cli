import path from "node:path";
import { builtinModules, isBuiltin } from "node:module";
import { lstat, stat } from "node:fs/promises";
import { parse as parseAstro } from "@astrojs/compiler/sync";
import { createScanner, LanguageVariant, SyntaxKind } from "typescript/unstable/ast";
import { isFile, isWithinRoot, normalizeRelative, readJson, readUtf8, resolveWithinRoot, WEB_SOURCE_EXTENSIONS } from "./fs";
import type { TypeOnlyDependencyRange, TypeScriptStaticConfig } from "./typescript-compiler";
import {
  canonicalizeCondition,
  compareUtf8,
  WEB_CONDITION,
  WEB_ENVIRONMENTS,
  type Condition,
  type Evidence,
  type Precision,
  type ResolutionStatus,
} from "./types";
import {
  selectPackageInstallCandidates,
  owningPackage,
  type LockInstance,
  type PackageRecord,
  type Workspace,
} from "./workspace";

export interface RawDependency {
  kind: string;
  edgeKind: "imports" | "reexports" | "lazy_imports" | "side_effect_imports" | "depends_on";
  specifier: string;
  literal: boolean;
  typeOnly: boolean;
  /** Enable TypeScript's `types`/`types@` conditions independently of syntax type-onlyness. */
  useTypesCondition?: boolean;
  resolutionMode?: "import" | "require";
  evidence: Evidence;
  precisionHint?: "heuristic";
}

export type ResolvedTarget =
  | { kind: "file"; absolutePath: string }
  | { kind: "workspace_package"; package: PackageRecord }
  | { kind: "external_package"; name: string; version: string; locator: string };

export interface Resolution {
  status: ResolutionStatus;
  precision: Precision;
  targets: ResolvedTarget[];
  reason: string | null;
  condition?: Condition;
  /** Per-target conditions, in the same order as targets. */
  targetConditions?: Condition[];
}

interface AliasRule {
  pattern: string;
  replacements: string[];
  virtualReplacements: string[];
  basePath: string;
}

export interface ResolverIssue {
  path: string;
  reason: string;
}

export interface TypeScriptPathRequest {
  sourceFile: string;
  specifier: string;
}

function portableRelativePath(value: string): string | null {
  const portable = value.replaceAll("\\", "/");
  if (
    portable.includes("\0")
    || path.posix.isAbsolute(portable)
    || /^[A-Za-z]:/u.test(portable)
  ) return null;
  return portable;
}

function resolvePortableRepositoryPath(baseRelative: string, value: string): string | null {
  const portable = portableRelativePath(value);
  if (portable === null) return null;
  const base = baseRelative === "." ? "" : baseRelative;
  const resolved = path.posix.normalize(path.posix.join(base, portable));
  if (resolved === ".." || resolved.startsWith("../") || path.posix.isAbsolute(resolved)) return null;
  return resolved === "" ? "." : resolved;
}

function astroTokenizerSource(source: string): string {
  if (!source.startsWith("---")) return source.replace(/[^\r\n]/gu, " ");
  const firstEnd = source.indexOf("\n");
  const closing = firstEnd < 0 ? -1 : source.indexOf("\n---", firstEnd);
  if (closing < 0) return source.replace(/[^\r\n]/gu, " ");
  const contentStart = firstEnd + 1;
  const contentEnd = closing;
  return `${source.slice(0, contentStart).replace(/[^\r\n]/gu, " ")}${source.slice(contentStart, contentEnd)}${source.slice(contentEnd).replace(/[^\r\n]/gu, " ")}`;
}

interface PreparedSource {
  input: string;
  extractor: string;
  extractorVersion: string;
  precisionHint?: "heuristic";
  fallbackReason?: string;
}

function maskOutside(source: string, start: number, end: number): string {
  return `${source.slice(0, start).replace(/[^\r\n]/gu, " ")}${source.slice(start, end)}${source.slice(end).replace(/[^\r\n]/gu, " ")}`;
}

function prepareSource(absoluteFile: string, source: string): PreparedSource {
  if (path.extname(absoluteFile).toLowerCase() !== ".astro") {
    return { input: source, extractor: "typescript-static", extractorVersion: "7.0.2" };
  }
  try {
    const parsed = parseAstro(source, { position: true });
    const errors = parsed.diagnostics.filter((diagnostic) => diagnostic.severity === 1);
    if (errors.length > 0) throw new Error(errors.map((diagnostic) => diagnostic.text).join("; "));
    const frontmatter = parsed.ast.children.find((node) => node.type === "frontmatter");
    if (!frontmatter || frontmatter.type !== "frontmatter") {
      return { input: source.replace(/[^\r\n]/gu, " "), extractor: "astro-compiler-frontmatter", extractorVersion: "4.0.0" };
    }
    const start = source.indexOf(frontmatter.value, frontmatter.position?.start.offset ?? 0);
    if (start < 0) throw new Error("compiler frontmatter span could not be mapped to source text");
    return {
      input: maskOutside(source, start, start + frontmatter.value.length),
      extractor: "astro-compiler-frontmatter",
      extractorVersion: "4.0.0",
    };
  } catch (error) {
    return {
      input: astroTokenizerSource(source),
      extractor: "astro-frontmatter-tokenizer",
      extractorVersion: "0.1.0",
      precisionHint: "heuristic",
      fallbackReason: error instanceof Error ? error.message : String(error),
    };
  }
}

export interface TypeScriptSyntaxToken {
  kind: SyntaxKind;
  text: string;
  value: string;
  start: number;
  end: number;
  unterminated: boolean;
  scannerError?: string;
}

type Token = TypeScriptSyntaxToken;

function lineAndColumn(source: string, offset: number): { line: number; column: number } {
  const prefix = source.slice(0, Math.max(0, offset));
  const lines = prefix.split(/\r?\n/u);
  return { line: lines.length, column: (lines.at(-1)?.length ?? 0) + 1 };
}

function span(
  source: string,
  startOffset: number,
  endOffset: number,
  relativePath: string,
  extractor = "typescript-static",
  extractorVersion = "7.0.2",
  detail?: string,
): Evidence {
  const start = lineAndColumn(source, startOffset);
  const end = lineAndColumn(source, endOffset);
  return {
    kind: "source",
    extractor,
    extractor_version: extractorVersion,
    path: relativePath,
    start_line: start.line,
    start_column: start.column,
    end_line: end.line,
    end_column: end.column,
    ...(detail ? { detail } : {}),
  };
}

const EXPRESSION_END_TOKENS = new Set<SyntaxKind>([
  SyntaxKind.NumericLiteral,
  SyntaxKind.BigIntLiteral,
  SyntaxKind.StringLiteral,
  SyntaxKind.RegularExpressionLiteral,
  SyntaxKind.NoSubstitutionTemplateLiteral,
  SyntaxKind.TemplateTail,
  SyntaxKind.Identifier,
  SyntaxKind.PrivateIdentifier,
  SyntaxKind.CloseParenToken,
  SyntaxKind.CloseBracketToken,
  SyntaxKind.CloseBraceToken,
  SyntaxKind.PlusPlusToken,
  SyntaxKind.MinusMinusToken,
  SyntaxKind.FalseKeyword,
  SyntaxKind.NullKeyword,
  SyntaxKind.SuperKeyword,
  SyntaxKind.ThisKeyword,
  SyntaxKind.TrueKeyword,
]);

function slashStartsRegularExpression(previous: Token | undefined): boolean {
  return previous === undefined || !EXPRESSION_END_TOKENS.has(previous.kind);
}

function nextCodePointOffset(source: string, offset: number): number {
  const codePoint = source.codePointAt(offset);
  return Math.min(source.length, offset + (codePoint !== undefined && codePoint > 0xffff ? 2 : 1));
}

function looksLikeJsxElementStart(source: string, offset: number): boolean {
  const match = source.slice(offset).match(/^<([$_\p{ID_Start}][$_\p{ID_Continue}.:-]*|>)/u);
  if (!match?.[1]) return false;
  if (match[1] === ">") return source.indexOf("</>", offset + 2) >= 0;
  const tagEnd = source.indexOf(">", offset + match[0].length);
  if (tagEnd < 0) return false;
  if (/\/\s*$/u.test(source.slice(offset, tagEnd))) return true;
  return source.indexOf(`</${match[1]}`, tagEnd + 1) >= 0;
}

function scanTokens(source: string, languageVariant: LanguageVariant): Token[] {
  const scanner = createScanner(true, languageVariant, source);
  const tokens: Token[] = [];
  let braceDepth = 0;
  const templateBases: number[] = [];
  let consumedOffset = 0;
  let jsxMode: "code" | "tag" | "text" = "code";
  let jsxDepth = 0;
  let jsxClosingTag = false;
  let jsxExpression: { returnMode: "tag" | "text"; depth: number } | null = null;
  const jsxCodeReturnDepths: number[] = [];
  for (;;) {
    const modeAtScan = jsxMode;
    let kind = modeAtScan === "text" ? scanner.scanJsxToken() as SyntaxKind : scanner.scan();
    if (kind === SyntaxKind.EndOfFile) break;
    if (
      modeAtScan === "code"
      && (kind === SyntaxKind.SlashToken || kind === SyntaxKind.SlashEqualsToken)
      && slashStartsRegularExpression(tokens.at(-1))
    ) {
      kind = scanner.reScanSlashToken();
    }
    if (kind === SyntaxKind.TemplateHead) templateBases.push(braceDepth);
    else if (kind === SyntaxKind.OpenBraceToken) braceDepth += 1;
    else if (kind === SyntaxKind.CloseBraceToken) {
      const templateBase = templateBases.at(-1);
      if (templateBase !== undefined && braceDepth === templateBase) {
        kind = scanner.reScanTemplateToken(false);
        if (kind === SyntaxKind.TemplateTail) templateBases.pop();
      } else if (braceDepth > 0) braceDepth -= 1;
    }
    const start = scanner.getTokenStart();
    const end = scanner.getTokenEnd();
    if (end <= start || end <= consumedOffset) {
      const recoveryStart = Math.max(consumedOffset, start, end);
      if (recoveryStart >= source.length) break;
      const recoveryEnd = nextCodePointOffset(source, recoveryStart);
      tokens.push({
        kind: SyntaxKind.Unknown,
        text: source.slice(recoveryStart, recoveryEnd),
        value: source.slice(recoveryStart, recoveryEnd),
        start: recoveryStart,
        end: recoveryEnd,
        unterminated: false,
        scannerError: `TypeScript scanner made no progress at offset ${recoveryStart}; skipped one code point`,
      });
      scanner.resetTokenState(recoveryEnd);
      consumedOffset = recoveryEnd;
      continue;
    }
    tokens.push({
      kind,
      text: scanner.getTokenText(),
      value: scanner.getTokenValue(),
      start,
      end,
      unterminated: scanner.isUnterminated(),
    });
    consumedOffset = end;

    if (languageVariant === LanguageVariant.JSX) {
      if (
        modeAtScan === "code"
        && kind === SyntaxKind.LessThanToken
        && looksLikeJsxElementStart(source, start)
      ) {
        if (jsxExpression !== null) jsxCodeReturnDepths.push(jsxDepth);
        jsxMode = "tag";
        jsxClosingTag = false;
      } else if (modeAtScan === "text") {
        if (kind === SyntaxKind.LessThanToken || kind === SyntaxKind.LessThanSlashToken) {
          jsxMode = "tag";
          jsxClosingTag = kind === SyntaxKind.LessThanSlashToken;
        } else if (kind === SyntaxKind.OpenBraceToken) {
          jsxExpression = { returnMode: "text", depth: 1 };
          jsxMode = "code";
        }
      } else if (modeAtScan === "tag") {
        if (kind === SyntaxKind.OpenBraceToken) {
          jsxExpression = { returnMode: "tag", depth: 1 };
          jsxMode = "code";
        } else if (kind === SyntaxKind.GreaterThanToken) {
          const selfClosing = tokens.at(-2)?.kind === SyntaxKind.SlashToken;
          if (jsxClosingTag) jsxDepth = Math.max(0, jsxDepth - 1);
          else if (!selfClosing) jsxDepth += 1;
          jsxClosingTag = false;
          const codeReturnDepth = jsxCodeReturnDepths.at(-1);
          if (codeReturnDepth !== undefined && jsxDepth === codeReturnDepth) {
            jsxCodeReturnDepths.pop();
            jsxMode = "code";
          } else {
            jsxMode = jsxDepth > 0 ? "text" : "code";
          }
        }
      } else if (modeAtScan === "code" && jsxExpression !== null) {
        if (kind === SyntaxKind.OpenBraceToken) jsxExpression.depth += 1;
        else if (kind === SyntaxKind.CloseBraceToken) {
          jsxExpression.depth -= 1;
          if (jsxExpression.depth === 0) {
            jsxMode = jsxExpression.returnMode;
            jsxExpression = null;
          }
        }
      }
    }
  }
  return tokens;
}

/** Shared context-aware tokenization for source attestation consumers. */
export function scanTypeScriptSyntaxTokens(source: string, jsx = false): TypeScriptSyntaxToken[] {
  return scanTokens(source, jsx ? LanguageVariant.JSX : LanguageVariant.Standard);
}

function quotedCommentValues(comment: string): string[] {
  const values: string[] = [];
  for (let index = 0; index < comment.length; index += 1) {
    const quote = comment[index];
    if (quote !== '"' && quote !== "'") continue;
    let end = index + 1;
    while (end < comment.length) {
      if (comment[end] === "\\") {
        end += 2;
        continue;
      }
      if (comment[end] === quote) break;
      if (comment[end] === "\n" || comment[end] === "\r") break;
      end += 1;
    }
    if (comment[end] !== quote) continue;
    const literal = comment.slice(index, end + 1);
    const scanner = createScanner(true, LanguageVariant.Standard, literal);
    if (scanner.scan() === SyntaxKind.StringLiteral) values.push(scanner.getTokenValue());
    index = end;
  }
  return values;
}

/**
 * Conservative pre-compiler request inventory for owner-scoped exact hints.
 * All code strings and quoted comment/JSDoc strings are retained so an
 * unresolved foreign type reference cannot be hidden by another owner's hint.
 */
export function extractPotentialTypeScriptModuleSpecifiers(absoluteFile: string, source: string): string[] {
  const languageVariant = [".tsx", ".jsx"].includes(path.extname(absoluteFile).toLowerCase())
    ? LanguageVariant.JSX
    : LanguageVariant.Standard;
  const scanner = createScanner(false, languageVariant, source);
  const specifiers = new Set<string>();
  for (;;) {
    const kind = scanner.scan() as SyntaxKind;
    if (kind === SyntaxKind.EndOfFile) break;
    if (kind === SyntaxKind.StringLiteral || kind === SyntaxKind.NoSubstitutionTemplateLiteral) {
      specifiers.add(scanner.getTokenValue());
    } else if (kind === SyntaxKind.SingleLineCommentTrivia || kind === SyntaxKind.MultiLineCommentTrivia) {
      for (const value of quotedCommentValues(scanner.getTokenText())) specifiers.add(value);
    }
  }
  return [...specifiers].sort(compareUtf8);
}

function isStringToken(token: Token | undefined): token is Token {
  return token?.kind === SyntaxKind.StringLiteral || token?.kind === SyntaxKind.NoSubstitutionTemplateLiteral;
}

function matchingParen(tokens: Token[], openIndex: number): number | null {
  let depth = 0;
  for (let index = openIndex; index < tokens.length; index += 1) {
    if (tokens[index]!.kind === SyntaxKind.OpenParenToken) depth += 1;
    else if (tokens[index]!.kind === SyntaxKind.CloseParenToken) {
      depth -= 1;
      if (depth === 0) return index;
    }
  }
  return null;
}

function isMemberName(tokens: Token[], index: number): boolean {
  const previous = tokens[index - 1]?.kind;
  return previous === SyntaxKind.DotToken || previous === SyntaxKind.QuestionDotToken;
}

function isMethodDeclaration(tokens: Token[], closeParen: number | null): boolean {
  return closeParen !== null && tokens[closeParen + 1]?.kind === SyntaxKind.OpenBraceToken;
}

function namedBindingsAreEntirelyTypeOnly(tokens: Token[], declarationIndex: number, fromIndex: number): boolean {
  const open = declarationIndex + 1;
  if (tokens[open]?.kind !== SyntaxKind.OpenBraceToken) return false;
  let segmentStart = open + 1;
  let sawSpecifier = false;
  const checkSegment = (end: number): boolean => {
    const segment = tokens.slice(segmentStart, end);
    if (segment.length === 0) return true;
    sawSpecifier = true;
    // `type` by itself (and the ambiguous `type as name`) imports a value
    // named "type". A genuine inline modifier is followed by the imported
    // name before an optional `as` alias.
    return segment.length >= 2
      && segment[0]?.kind === SyntaxKind.TypeKeyword
      && segment[1]?.kind !== SyntaxKind.AsKeyword;
  };
  for (let index = segmentStart; index < fromIndex; index += 1) {
    const kind = tokens[index]!.kind;
    if (kind === SyntaxKind.CommaToken) {
      if (!checkSegment(index)) return false;
      segmentStart = index + 1;
      continue;
    }
    if (kind === SyntaxKind.CloseBraceToken) {
      if (!checkSegment(index)) return false;
      return sawSpecifier && index + 1 === fromIndex;
    }
  }
  return false;
}

function containingTypeOnlyRange(
  ranges: readonly TypeOnlyDependencyRange[],
  offset: number,
  syntax?: TypeOnlyDependencyRange["syntax"],
): number {
  return ranges.findIndex((range) => (
    (syntax === undefined || range.syntax === syntax)
    && offset >= range.startOffset
    && offset < range.endOffset
  ));
}

/**
 * TypeScript 7 exposes its tokenizer independently from the native compiler.
 * Keep a small parser pass here so scanner recovery never turns malformed
 * source into a silently "complete" file. This pass validates the delimiter
 * structure used by import/export declarations and call expressions; scanner
 * diagnostics are added below as well.
 */
function typescriptParseDiagnostics(tokens: Token[], source: string, relativePath: string, prepared: PreparedSource): Array<{ message: string; evidence: Evidence }> {
  const diagnostics: Array<{ message: string; evidence: Evidence }> = [];
  const add = (message: string, token: Token): void => {
    diagnostics.push({
      message: `TypeScript parser: ${message}`,
      evidence: span(source, token.start, token.end, relativePath, prepared.extractor, prepared.extractorVersion),
    });
  };
  const stack: Token[] = [];
  const pairs = new Map<SyntaxKind, SyntaxKind>([
    [SyntaxKind.OpenParenToken, SyntaxKind.CloseParenToken],
    [SyntaxKind.OpenBracketToken, SyntaxKind.CloseBracketToken],
    [SyntaxKind.OpenBraceToken, SyntaxKind.CloseBraceToken],
  ]);
  const openingFor = new Map<SyntaxKind, SyntaxKind>([...pairs].map(([opening, closing]) => [closing, opening]));
  for (const token of tokens) {
    if (pairs.has(token.kind)) {
      stack.push(token);
      continue;
    }
    const expectedOpening = openingFor.get(token.kind);
    if (expectedOpening === undefined) continue;
    const opening = stack.at(-1);
    if (opening?.kind === expectedOpening) {
      stack.pop();
      continue;
    }
    add(`unexpected ${SyntaxKind[token.kind] ?? "closing token"}`, token);
  }
  for (const opening of stack) {
    const expected = pairs.get(opening.kind);
    add(`${SyntaxKind[expected ?? SyntaxKind.Unknown] ?? "closing token"} expected`, opening);
  }

  // The standalone TS 7 tokenizer intentionally does not expose parse
  // diagnostics. Validate the declaration forms that define dependency sites
  // so balanced-but-invalid input cannot be reported as syntax-complete.
  for (let index = 0; index < tokens.length; index += 1) {
    const token = tokens[index]!;
    if (token.kind === SyntaxKind.ImportKeyword) {
      const first = tokens[index + 1];
      if (
        first === undefined
        || first.kind === SyntaxKind.OpenParenToken
        || first.kind === SyntaxKind.DotToken
        || first.kind === SyntaxKind.StringLiteral
        || first.kind === SyntaxKind.NoSubstitutionTemplateLiteral
      ) continue;
      let cursor = index + (first.kind === SyntaxKind.TypeKeyword ? 2 : 1);
      const binding = tokens[cursor];
      if (binding === undefined) {
        add("import binding expected", token);
        continue;
      }
      // `import name = require("name")` is a complete import-equals form.
      if (
        binding.kind === SyntaxKind.Identifier
        && tokens[cursor + 1]?.kind === SyntaxKind.EqualsToken
        && (tokens[cursor + 2]?.kind === SyntaxKind.Identifier || tokens[cursor + 2]?.kind === SyntaxKind.RequireKeyword)
        && tokens[cursor + 2]?.value === "require"
      ) continue;
      let fromIndex = -1;
      let boundary = tokens.length;
      for (; cursor < tokens.length; cursor += 1) {
        const candidate = tokens[cursor]!;
        if (candidate.kind === SyntaxKind.FromKeyword) {
          fromIndex = cursor;
          break;
        }
        if (
          candidate.kind === SyntaxKind.SemicolonToken
          || (cursor > index + 1 && (candidate.kind === SyntaxKind.ImportKeyword || candidate.kind === SyntaxKind.ExportKeyword))
        ) {
          boundary = cursor;
          break;
        }
      }
      if (fromIndex < 0) {
        add("FromKeyword expected in import declaration", tokens[Math.min(boundary, tokens.length - 1)] ?? token);
      } else if (!isStringToken(tokens[fromIndex + 1])) {
        add("module string literal expected after FromKeyword", tokens[fromIndex + 1] ?? tokens[fromIndex]!);
      }
      continue;
    }
    if (token.kind === SyntaxKind.ConstKeyword || token.kind === SyntaxKind.LetKeyword || token.kind === SyntaxKind.VarKeyword) {
      const declaration = tokens[index + 1];
      if (token.kind === SyntaxKind.ConstKeyword && declaration?.kind === SyntaxKind.EnumKeyword) continue;
      const identifierLike = declaration !== undefined && /^[$_\p{ID_Start}][$_\p{ID_Continue}]*$/u.test(declaration.text);
      if (
        declaration === undefined
        || (!identifierLike && ![SyntaxKind.Identifier, SyntaxKind.OpenBraceToken, SyntaxKind.OpenBracketToken].includes(declaration.kind))
      ) {
        add("variable declaration name or binding pattern expected", declaration ?? token);
      }
    }
  }
  return diagnostics.filter((diagnostic, index, all) => all.findIndex((candidate) => (
    candidate.message === diagnostic.message
    && candidate.evidence.start_line === diagnostic.evidence.start_line
    && candidate.evidence.start_column === diagnostic.evidence.start_column
  )) === index);
}

export function extractDependencies(
  absoluteFile: string,
  relativePath: string,
  source: string,
  parserTypeOnlyRanges: readonly TypeOnlyDependencyRange[] = [],
): {
  dependencies: RawDependency[];
  parseErrors: Array<{ message: string; evidence: Evidence }>;
  fallbackReason?: string;
} {
  const prepared = prepareSource(absoluteFile, source);
  const input = prepared.input;
  const extension = path.extname(absoluteFile).toLowerCase();
  // Astro input is a masked script frontmatter even when the component body
  // contains JSX-like markup. Native TSX/JSX files must use the JSX lexical
  // variant so closing tags and JSX tokens are not reinterpreted as JS.
  const languageVariant = extension === ".tsx" || extension === ".jsx" ? LanguageVariant.JSX : LanguageVariant.Standard;
  const tokens = scanTokens(input, languageVariant);
  const dependencies: RawDependency[] = [];
  const matchedTypeOnlyRanges = new Set<number>();
  function add(
    startIndex: number,
    endIndex: number,
    expressionStart: number,
    expressionEnd: number,
    literal: string | null,
    kind: string,
    edgeKind: RawDependency["edgeKind"],
    typeOnly = false,
  ): void {
    dependencies.push({
      kind,
      edgeKind,
      specifier: literal ?? source.slice(expressionStart, expressionEnd).trim(),
      literal: literal !== null,
      typeOnly,
      evidence: span(source, startIndex, endIndex, relativePath, prepared.extractor, prepared.extractorVersion, typeOnly ? "type_only=true" : undefined),
      ...(prepared.precisionHint ? { precisionHint: prepared.precisionHint } : {}),
    });
  }
  for (let index = 0; index < tokens.length; index += 1) {
    const token = tokens[index]!;
    if (token.kind === SyntaxKind.ImportKeyword && tokens[index + 1]?.kind === SyntaxKind.DotToken) {
      // `import.meta` is a meta-property, not a declaration or dynamic import.
      // Do not let a later `from`-shaped token in the same statement turn it
      // into a synthetic dependency site.
      continue;
    }
    if (token.kind === SyntaxKind.ImportKeyword && tokens[index + 1]?.kind === SyntaxKind.OpenParenToken && !isMemberName(tokens, index)) {
      const close = matchingParen(tokens, index + 1);
      if (isMethodDeclaration(tokens, close)) {
        index = close!;
        continue;
      }
      const expressionTokens = close === null ? tokens.slice(index + 2) : tokens.slice(index + 2, close);
      // Import attributes/options are subsequent arguments. Resolution is
      // determined solely by the first argument, which remains literal for
      // `import("./data.json", { with: { type: "json" } })`.
      const first = expressionTokens[0];
      const literal = isStringToken(first)
        && (expressionTokens.length === 1 || expressionTokens[1]?.kind === SyntaxKind.CommaToken)
        ? first
        : null;
      const expressionStart = expressionTokens[0]?.start ?? tokens[index + 1]!.end;
      const expressionEnd = expressionTokens.at(-1)?.end ?? expressionStart;
      const end = close === null ? expressionEnd : tokens[close]!.end;
      const typeOnlyRange = containingTypeOnlyRange(parserTypeOnlyRanges, token.start, "import_type");
      const typeOnly = typeOnlyRange >= 0;
      if (typeOnly) matchedTypeOnlyRanges.add(typeOnlyRange);
      add(
        token.start,
        end,
        expressionStart,
        expressionEnd,
        literal?.value ?? null,
        typeOnly ? "type_import" : "dynamic_import",
        typeOnly ? "imports" : "lazy_imports",
        typeOnly,
      );
      if (close !== null) index = close;
      continue;
    }
    if (token.kind === SyntaxKind.ImportKeyword) {
      const first = tokens[index + 1];
      const parserRange = containingTypeOnlyRange(parserTypeOnlyRanges, token.start, "declaration");
      if (parserRange >= 0) matchedTypeOnlyRanges.add(parserRange);
      const sideEffect = isStringToken(first);
      let literalIndex = sideEffect ? index + 1 : -1;
      let requireIndex = -1;
      let fromIndex = -1;
      for (let cursor = index + 1; cursor < Math.min(tokens.length, index + 128); cursor += 1) {
        const candidate = tokens[cursor]!;
        if (candidate.kind === SyntaxKind.SemicolonToken || (cursor > index + 1 && (candidate.kind === SyntaxKind.ImportKeyword || candidate.kind === SyntaxKind.ExportKeyword))) break;
        if (candidate.value === "require" && tokens[cursor + 1]?.kind === SyntaxKind.OpenParenToken) requireIndex = cursor;
        if (candidate.kind === SyntaxKind.FromKeyword && isStringToken(tokens[cursor + 1])) {
          fromIndex = cursor;
          literalIndex = cursor + 1;
          break;
        }
      }
      const typeOnly = first?.kind === SyntaxKind.TypeKeyword
        || parserRange >= 0
        || (fromIndex >= 0 && namedBindingsAreEntirelyTypeOnly(tokens, index, fromIndex));
      if (requireIndex >= 0 && isStringToken(tokens[requireIndex + 2])) literalIndex = requireIndex + 2;
      const literal = tokens[literalIndex];
      if (literal && isStringToken(literal)) {
        const close = requireIndex >= 0 ? matchingParen(tokens, requireIndex + 1) : null;
        add(token.start, close === null ? literal.end : tokens[close]!.end, literal.start, literal.end, literal.value, requireIndex >= 0 ? typeOnly ? "type_import_equals" : "require" : typeOnly ? "type_import" : sideEffect ? "side_effect_import" : "import", sideEffect ? "side_effect_imports" : "imports", typeOnly);
        index = close ?? literalIndex;
      }
      continue;
    }
    if (token.kind === SyntaxKind.ExportKeyword) {
      const parserRange = containingTypeOnlyRange(parserTypeOnlyRanges, token.start, "declaration");
      if (parserRange >= 0) matchedTypeOnlyRanges.add(parserRange);
      let literalIndex = -1;
      let fromIndex = -1;
      for (let cursor = index + 1; cursor < Math.min(tokens.length, index + 128); cursor += 1) {
        const candidate = tokens[cursor]!;
        if (candidate.kind === SyntaxKind.SemicolonToken || (cursor > index + 1 && (candidate.kind === SyntaxKind.ImportKeyword || candidate.kind === SyntaxKind.ExportKeyword))) break;
        if (candidate.kind === SyntaxKind.FromKeyword && isStringToken(tokens[cursor + 1])) {
          fromIndex = cursor;
          literalIndex = cursor + 1;
          break;
        }
      }
      const typeOnly = tokens[index + 1]?.kind === SyntaxKind.TypeKeyword
        || parserRange >= 0
        || (fromIndex >= 0 && namedBindingsAreEntirelyTypeOnly(tokens, index, fromIndex));
      const literal = tokens[literalIndex];
      if (literal && isStringToken(literal)) {
        add(token.start, literal.end, literal.start, literal.end, literal.value, typeOnly ? "type_reexport" : "reexport", "reexports", typeOnly);
        index = literalIndex;
      }
      continue;
    }
    if (
      (token.kind === SyntaxKind.Identifier || token.kind === SyntaxKind.RequireKeyword)
      && token.value === "require"
      && tokens[index + 1]?.kind === SyntaxKind.OpenParenToken
      && !isMemberName(tokens, index)
    ) {
      const close = matchingParen(tokens, index + 1);
      if (isMethodDeclaration(tokens, close)) {
        index = close!;
        continue;
      }
      const expressionTokens = close === null ? tokens.slice(index + 2) : tokens.slice(index + 2, close);
      const only = expressionTokens.length === 1 && isStringToken(expressionTokens[0]) ? expressionTokens[0] : null;
      const expressionStart = expressionTokens[0]?.start ?? tokens[index + 1]!.end;
      const expressionEnd = expressionTokens.at(-1)?.end ?? expressionStart;
      add(token.start, close === null ? expressionEnd : tokens[close]!.end, expressionStart, expressionEnd, only?.value ?? null, "require", "imports");
      if (close !== null) index = close;
    }
  }

  // The normal tokenizer deliberately skips comments. Recover parser-confirmed
  // ImportType nodes stored in JSDoc without treating arbitrary prose or a
  // textual `import()` example as a dependency site.
  for (const [rangeIndex, range] of parserTypeOnlyRanges.entries()) {
    if (range.syntax !== "import_type" || matchedTypeOnlyRanges.has(rangeIndex)) continue;
    const boundedStart = Math.max(0, Math.min(source.length, range.startOffset));
    const boundedEnd = Math.max(boundedStart, Math.min(source.length, range.endOffset));
    const rangeSource = source.slice(boundedStart, boundedEnd);
    const importMatch = /\bimport\s*\(/u.exec(rangeSource);
    if (importMatch?.index === undefined) continue;
    const importStart = boundedStart + importMatch.index;
    const rangeTokens = scanTokens(source.slice(importStart, boundedEnd), LanguageVariant.Standard);
    const importIndex = rangeTokens.findIndex((candidate) => candidate.kind === SyntaxKind.ImportKeyword);
    if (importIndex < 0 || rangeTokens[importIndex + 1]?.kind !== SyntaxKind.OpenParenToken) continue;
    const close = matchingParen(rangeTokens, importIndex + 1);
    const expressionTokens = close === null ? rangeTokens.slice(importIndex + 2) : rangeTokens.slice(importIndex + 2, close);
    const first = expressionTokens[0];
    const literal = isStringToken(first)
      && (expressionTokens.length === 1 || expressionTokens[1]?.kind === SyntaxKind.CommaToken)
      ? first
      : null;
    const expressionStart = importStart + (expressionTokens[0]?.start ?? rangeTokens[importIndex + 1]!.end);
    const expressionEnd = importStart + (expressionTokens.at(-1)?.end ?? expressionTokens[0]?.start ?? rangeTokens[importIndex + 1]!.end);
    const dependencyEnd = importStart + (close === null ? expressionEnd - importStart : rangeTokens[close]!.end);
    add(
      importStart + rangeTokens[importIndex]!.start,
      dependencyEnd,
      expressionStart,
      expressionEnd,
      literal?.value ?? null,
      "type_import",
      "imports",
      true,
    );
  }
  dependencies.sort((left, right) => (
    left.evidence.start_line - right.evidence.start_line
    || left.evidence.start_column - right.evidence.start_column
    || compareUtf8(left.kind, right.kind)
    || compareUtf8(left.specifier, right.specifier)
  ));
  const parseErrors = typescriptParseDiagnostics(tokens, source, relativePath, prepared);
  for (const token of tokens.filter((candidate) => candidate.unterminated || candidate.scannerError !== undefined)) {
    parseErrors.push({
      message: token.scannerError ?? `Unterminated ${SyntaxKind[token.kind] ?? "token"}`,
      evidence: span(source, token.start, token.end, relativePath, prepared.extractor, prepared.extractorVersion),
    });
  }
  return {
    dependencies,
    parseErrors,
    ...(prepared.fallbackReason ? { fallbackReason: prepared.fallbackReason } : {}),
  };
}

export function parseStaticJsonc(source: string): Record<string, unknown> | null {
  const input = source.charCodeAt(0) === 0xfeff ? source.slice(1) : source;
  const scanner = createScanner(false, LanguageVariant.Standard, input);
  const tokens: Array<{ kind: SyntaxKind; start: number; end: number }> = [];
  for (;;) {
    const kind = scanner.scan() as SyntaxKind;
    if (kind === SyntaxKind.EndOfFile) break;
    if (scanner.isUnterminated()) return null;
    tokens.push({ kind, start: scanner.getTokenStart(), end: scanner.getTokenEnd() });
  }
  const trivia = new Set([
    SyntaxKind.WhitespaceTrivia,
    SyntaxKind.NewLineTrivia,
    SyntaxKind.SingleLineCommentTrivia,
    SyntaxKind.MultiLineCommentTrivia,
  ]);
  const comments = new Set([
    SyntaxKind.SingleLineCommentTrivia,
    SyntaxKind.MultiLineCommentTrivia,
  ]);
  const nextNonTrivia = new Array<SyntaxKind | undefined>(tokens.length);
  let followingKind: SyntaxKind | undefined;
  for (let index = tokens.length - 1; index >= 0; index -= 1) {
    const token = tokens[index]!;
    nextNonTrivia[index] = followingKind;
    if (!trivia.has(token.kind)) followingKind = token.kind;
  }
  const mask = (value: string): string => value.replace(/[^\r\n]/g, " ");
  let stripped = "";
  let cursor = 0;
  for (let index = 0; index < tokens.length; index += 1) {
    const token = tokens[index]!;
    stripped += input.slice(cursor, token.start);
    let remove = comments.has(token.kind);
    if (token.kind === SyntaxKind.CommaToken) {
      const next = nextNonTrivia[index];
      remove = next === SyntaxKind.CloseBraceToken || next === SyntaxKind.CloseBracketToken;
    }
    const text = input.slice(token.start, token.end);
    stripped += remove ? mask(text) : text;
    cursor = token.end;
  }
  stripped += input.slice(cursor);
  try {
    const parsed: unknown = JSON.parse(stripped);
    return parsed !== null && typeof parsed === "object" && !Array.isArray(parsed) ? parsed as Record<string, unknown> : null;
  } catch {
    return null;
  }
}

function packageNameOf(specifier: string): string {
  if (specifier.startsWith("@")) return specifier.split("/").slice(0, 2).join("/");
  return specifier.split("/")[0] ?? specifier;
}

function subpathOf(specifier: string, packageName: string): string {
  return specifier === packageName ? "." : `.${specifier.slice(packageName.length)}`;
}

interface ConditionalStringTarget {
  value: string;
  /** Package.json keys which selected this declaration, for diagnostics. */
  conditions: string[];
  /** Exact profile/conditional predicates under which this target is selected. */
  guards: Condition[];
}

interface PackageEntrySelection {
  targets: ConditionalStringTarget[];
  exportsDefined: boolean;
  matched: boolean;
  reason: string | null;
}

type ModuleResolutionKind = "import" | "require";

function moduleResolutionKind(dependencyKind: string): ModuleResolutionKind {
  return ["require", "require_call", "import_equals", "type_import_equals"].includes(dependencyKind)
    ? "require"
    : "import";
}

interface PackageMapEntry {
  value: unknown;
  capture?: string;
  invalid?: boolean;
}

type ConditionalSearchState = "target" | "missing" | "blocked" | "invalid" | "unsupported" | "exhausted";

interface ConditionalSearchResult {
  state: ConditionalSearchState;
  guards: Condition[];
  conditions: string[];
  value?: string;
}

interface ConditionalSearchOptions {
  environment: string;
  typeOnly: boolean;
  moduleKind: ModuleResolutionKind;
  targetKind: "exports" | "imports";
  patternCapture?: string;
  probe: (value: string) => boolean | Promise<boolean>;
  budget: { remaining: number };
}

interface SemanticVersion {
  major: number;
  minor: number;
  patch: number;
  prerelease: string[];
}

interface PartialSemanticVersion {
  version: SemanticVersion;
  majorWildcard: boolean;
  minorWildcard: boolean;
  patchWildcard: boolean;
}

type VersionComparatorOperator = "<" | "<=" | "=" | ">=" | ">";

interface VersionComparator {
  operator: VersionComparatorOperator;
  operand: SemanticVersion;
}

const TYPESCRIPT_VERSION: SemanticVersion = { major: 7, minor: 0, patch: 2, prerelease: [] };
const UINT32_MAX = 0xffff_ffff;
const UINT32_MODULUS = 0x1_0000_0000;
const VERSION_ZERO: SemanticVersion = { major: 0, minor: 0, patch: 0, prerelease: ["0"] };
const MAX_CONDITIONAL_TARGET_NODES = 512;
const MAX_CONDITIONAL_TARGET_DEPTH = 32;

function compareVersions(left: SemanticVersion, right: SemanticVersion): number {
  for (const key of ["major", "minor", "patch"] as const) {
    const difference = left[key] - right[key];
    if (difference !== 0) return difference;
  }
  if (left.prerelease.length === 0 || right.prerelease.length === 0) {
    return left.prerelease.length === right.prerelease.length ? 0 : left.prerelease.length === 0 ? 1 : -1;
  }
  for (let index = 0; index < Math.max(left.prerelease.length, right.prerelease.length); index += 1) {
    const leftPart = left.prerelease[index];
    const rightPart = right.prerelease[index];
    if (leftPart === undefined || rightPart === undefined) return leftPart === rightPart ? 0 : leftPart === undefined ? -1 : 1;
    if (leftPart === rightPart) continue;
    const leftNumeric = /^(?:0|[1-9]\d*)$/u.test(leftPart);
    const rightNumeric = /^(?:0|[1-9]\d*)$/u.test(rightPart);
    if (leftNumeric && rightNumeric) {
      return leftPart.length - rightPart.length || compareUtf8(leftPart, rightPart);
    }
    if (leftNumeric !== rightNumeric) return leftNumeric ? -1 : 1;
    return compareUtf8(leftPart, rightPart);
  }
  return 0;
}

function parsePartialVersion(value: string): PartialSemanticVersion | null {
  const match = value.match(/^([x*0]|[1-9]\d*)(?:\.([x*0]|[1-9]\d*)(?:\.([x*0]|[1-9]\d*)(?:-([a-z0-9-.]+))?(?:\+([a-z0-9-.]+))?)?)?$/iu);
  if (match === null) return null;
  const majorText = match[1]!;
  const minorText = match[2] ?? "*";
  const patchText = match[3] ?? "*";
  const majorWildcard = /^(?:x|\*)$/iu.test(majorText);
  const minorWildcard = /^(?:x|\*)$/iu.test(minorText);
  const patchWildcard = /^(?:x|\*)$/iu.test(patchText);
  let major = 0;
  let minor = 0;
  let patch = 0;
  if (!majorWildcard) {
    major = Number(majorText);
    if (!Number.isInteger(major) || major > UINT32_MAX) return null;
    if (!minorWildcard) {
      minor = Number(minorText);
      if (!Number.isInteger(minor) || minor > UINT32_MAX) return null;
      if (!patchWildcard) {
        patch = Number(patchText);
        if (!Number.isInteger(patch) || patch > UINT32_MAX) return null;
      }
    }
  }
  return {
    version: {
      major,
      minor,
      patch,
      prerelease: match[4] === undefined ? [] : match[4].split("."),
    },
    majorWildcard,
    minorWildcard,
    patchWildcard,
  };
}

function incrementMajor(version: SemanticVersion): SemanticVersion {
  return { major: (version.major + 1) % UINT32_MODULUS, minor: 0, patch: 0, prerelease: [] };
}

function incrementMinor(version: SemanticVersion): SemanticVersion {
  return { major: version.major, minor: (version.minor + 1) % UINT32_MODULUS, patch: 0, prerelease: [] };
}

function incrementPatch(version: SemanticVersion): SemanticVersion {
  return { major: version.major, minor: version.minor, patch: (version.patch + 1) % UINT32_MODULUS, prerelease: [] };
}

function cloneVersion(version: SemanticVersion, prerelease = version.prerelease): SemanticVersion {
  return { major: version.major, minor: version.minor, patch: version.patch, prerelease: [...prerelease] };
}

function parseComparator(operatorText: string, value: string): VersionComparator[] | null {
  const partial = parsePartialVersion(value);
  if (partial === null) return null;
  if (partial.majorWildcard) {
    return operatorText === "<" || operatorText === ">"
      ? [{ operator: "<", operand: VERSION_ZERO }]
      : [];
  }
  if (operatorText === "~") {
    return [
      { operator: ">=", operand: partial.version },
      { operator: "<", operand: partial.minorWildcard ? incrementMajor(partial.version) : incrementMinor(partial.version) },
    ];
  }
  if (operatorText === "^") {
    const upper = partial.version.major > 0 || partial.minorWildcard
      ? incrementMajor(partial.version)
      : partial.version.minor > 0 || partial.patchWildcard
        ? incrementMinor(partial.version)
        : incrementPatch(partial.version);
    return [
      { operator: ">=", operand: partial.version },
      { operator: "<", operand: upper },
    ];
  }
  if (operatorText === "<" || operatorText === ">=") {
    const operand = partial.minorWildcard || partial.patchWildcard
      ? cloneVersion(partial.version, ["0"])
      : partial.version;
    return [{ operator: operatorText, operand }];
  }
  if (operatorText === "<=" || operatorText === ">") {
    let operator: VersionComparatorOperator = operatorText;
    let operand = partial.version;
    if (partial.minorWildcard) {
      operator = operatorText === "<=" ? "<" : ">=";
      operand = cloneVersion(incrementMajor(partial.version), ["0"]);
    } else if (partial.patchWildcard) {
      operator = operatorText === "<=" ? "<" : ">=";
      operand = cloneVersion(incrementMinor(partial.version), ["0"]);
    }
    return [{ operator, operand }];
  }
  if (operatorText !== "" && operatorText !== "=") return null;
  if (partial.minorWildcard || partial.patchWildcard) {
    const lower = cloneVersion(partial.version, ["0"]);
    const upper = cloneVersion(
      partial.minorWildcard ? incrementMajor(partial.version) : incrementMinor(partial.version),
      ["0"],
    );
    return [
      { operator: ">=", operand: lower },
      { operator: "<", operand: upper },
    ];
  }
  return [{ operator: "=", operand: partial.version }];
}

function parseHyphenRange(lowerText: string, upperText: string): VersionComparator[] | null {
  const lower = parsePartialVersion(lowerText);
  const upper = parsePartialVersion(upperText);
  if (lower === null || upper === null) return null;
  const comparators: VersionComparator[] = [];
  if (!lower.majorWildcard) comparators.push({ operator: ">=", operand: lower.version });
  if (!upper.majorWildcard) {
    if (upper.minorWildcard) comparators.push({ operator: "<", operand: incrementMajor(upper.version) });
    else if (upper.patchWildcard) comparators.push({ operator: "<", operand: incrementMinor(upper.version) });
    else comparators.push({ operator: "<=", operand: upper.version });
  }
  return comparators;
}

function matchesComparator(comparator: VersionComparator): boolean {
  const comparison = compareVersions(TYPESCRIPT_VERSION, comparator.operand);
  if (comparator.operator === "<") return comparison < 0;
  if (comparator.operator === "<=") return comparison <= 0;
  if (comparator.operator === "=") return comparison === 0;
  if (comparator.operator === ">=") return comparison >= 0;
  return comparison > 0;
}

function trimTypeScriptVersionSpace(value: string): string {
  // TypeScript's Go implementation uses strings.TrimSpace at range
  // boundaries, while its regexp `\\s` is the smaller ASCII/RE2 set below.
  return value.replace(
    /^[\u0009-\u000d\u0020\u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]+|[\u0009-\u000d\u0020\u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]+$/gu,
    "",
  );
}

/** Mirrors the full range forms accepted by TypeScript's versioned `types@` keys. */
function matchesTypeScriptVersionRange(range: string): boolean | null {
  const alternatives: VersionComparator[][] = [];
  for (const rawAlternative of trimTypeScriptVersionSpace(range).split("||")) {
    const alternative = trimTypeScriptVersionSpace(rawAlternative);
    if (alternative === "") continue;
    const hyphen = alternative.match(/^([a-z0-9+.*-]+)[ \t\n\f\r]+-[ \t\n\f\r]+([a-z0-9+.*-]+)$/iu);
    if (hyphen) {
      const comparators = parseHyphenRange(hyphen[1]!, hyphen[2]!);
      if (comparators === null) return null;
      alternatives.push(comparators);
      continue;
    }
    const comparators: VersionComparator[] = [];
    for (const simple of alternative.split(/[ \t\n\f\r]+/u)) {
      const match = trimTypeScriptVersionSpace(simple).match(/^([~^<>=]|<=|>=)?[ \t\n\f\r]*([a-z0-9+.*-]+)$/iu);
      if (match === null) return null;
      const parsed = parseComparator(match[1] ?? "", match[2]!);
      if (parsed === null) return null;
      comparators.push(...parsed);
    }
    alternatives.push(comparators);
  }
  if (alternatives.length === 0) return true;
  return alternatives.some((alternative) => {
    for (const comparator of alternative) {
      if (!matchesComparator(comparator)) return false;
    }
    return true;
  });
}

function packageTargetIsSyntacticallyValid(value: string, targetKind: "exports" | "imports"): boolean {
  if (
    value.includes("\0")
    || value.includes("\\")
    || value.startsWith("/")
    || /^[A-Za-z]:/u.test(value)
    || /%(?:2f|5c)/iu.test(value)
  ) return false;
  if (value.startsWith("./")) {
    const rawSegments = value.slice(2).split("/");
    if (rawSegments.some((segment) => {
      const dotsDecoded = segment.replaceAll(/%2e/giu, ".");
      return segment === ""
        || dotsDecoded === "."
        || dotsDecoded === ".."
        || dotsDecoded.toLowerCase() === "node_modules";
    })) return false;
    const normalized = path.posix.normalize(value.slice(2));
    return normalized !== ".."
      && !normalized.startsWith("../")
      && !path.posix.isAbsolute(normalized)
      && !normalized.split("/").includes("node_modules");
  }
  return targetKind === "imports"
    && !value.startsWith("../")
    && value !== "."
    && value !== "..";
}

function customConditionKey(key: string): string {
  return `package.exports.condition:${key}`;
}

function isArrayIndexProperty(key: string): boolean {
  if (!/^(?:0|[1-9]\d*)$/u.test(key)) return false;
  const value = Number(key);
  return Number.isSafeInteger(value) && value >= 0 && value < 0xffff_ffff;
}

function selectorState(
  key: string,
  options: ConditionalSearchOptions,
): { state: boolean | "unknown" | "unsupported"; guard?: Condition } {
  if (key === "default") return { state: true };
  if (key === "import" || key === "require") return { state: key === options.moduleKind };
  if (key === "types") return { state: options.typeOnly };
  if (key.startsWith("types@")) {
    if (!options.typeOnly) return { state: false };
    const matches = matchesTypeScriptVersionRange(key.slice("types@".length));
    // TypeScript treats an unparseable versioned key as non-applicable and
    // continues evaluating later conditions (usually `types` or `default`).
    return { state: matches ?? false };
  }
  // Neutral Bundler resolution has no customConditions. Once `types` is
  // active, browser/node/mode and arbitrary package conditions must not
  // shadow a later `types` declaration.
  if (options.typeOnly) return { state: false };
  if (key === "browser") {
    return { state: options.environment === "browser", guard: { op: "eq", key: "environment", value: "browser" } };
  }
  if (key === "node" || key === "node-addons") {
    return { state: options.environment === "server", guard: { op: "eq", key: "environment", value: "server" } };
  }
  if (key === "production") return { state: true, guard: { op: "eq", key: "mode", value: "production" } };
  if (key === "development") return { state: false };
  return { state: "unknown" };
}

async function searchConditionalTarget(
  value: unknown,
  options: ConditionalSearchOptions,
  guards: Condition[] = [],
  conditions: string[] = [],
  depth = 0,
): Promise<ConditionalSearchResult[]> {
  options.budget.remaining -= 1;
  if (depth > MAX_CONDITIONAL_TARGET_DEPTH || options.budget.remaining < 0) {
    return [{ state: "exhausted", guards, conditions }];
  }
  if (value === null) return [{ state: "blocked", guards, conditions }];
  if (typeof value === "string") {
    const target = options.patternCapture === undefined ? value : value.replaceAll("*", options.patternCapture);
    if (!packageTargetIsSyntacticallyValid(target, options.targetKind)) {
      return [{ state: "invalid", guards, conditions }];
    }
    // Node treats a syntactically valid runtime string as terminal even when
    // its file is absent. TypeScript's type probe may advance array/object
    // fallbacks when the substitution cannot be loaded.
    if (!options.typeOnly || await options.probe(target)) {
      return [{ state: "target", value: target, guards, conditions }];
    }
    return [{ state: "missing", guards, conditions }];
  }
  if (Array.isArray(value)) {
    if (value.length === 0) {
      return [{ state: options.typeOnly ? "missing" : "blocked", guards, conditions }];
    }
    let pending: ConditionalSearchResult[] = [{ state: "missing", guards, conditions }];
    const terminal: ConditionalSearchResult[] = [];
    for (let index = 0; index < value.length && pending.length > 0; index += 1) {
      const nextPending: ConditionalSearchResult[] = [];
      for (const branch of pending) {
        const results = await searchConditionalTarget(
          value[index],
          options,
          branch.guards,
          [...branch.conditions, `fallback[${index}]`],
          depth + 1,
        );
        for (const result of results) {
          if (result.state === "missing" || result.state === "invalid") {
            nextPending.push({ ...result, conditions: branch.conditions });
          }
          else terminal.push(result);
        }
      }
      if (nextPending.length > 128) {
        return [...terminal, { state: "exhausted", guards, conditions }];
      }
      pending = nextPending;
    }
    return [...terminal, ...pending];
  }
  if (typeof value !== "object") return [{ state: "invalid", guards, conditions }];

  let pending: ConditionalSearchResult[] = [{ state: "missing", guards, conditions }];
  const terminal: ConditionalSearchResult[] = [];
  for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
    if (pending.length === 0) break;
    if (isArrayIndexProperty(key)) {
      return [...terminal, { state: "invalid", guards, conditions }];
    }
    const selector = selectorState(key, options);
    if (selector.state === false) continue;
    if (selector.state === "unsupported") {
      return [...terminal, { state: "unsupported", guards, conditions: [...conditions, key] }];
    }
    const nextPending: ConditionalSearchResult[] = [];
    for (const branch of pending) {
      if (selector.state === "unknown") {
        const positive: Condition = { op: "defined", key: customConditionKey(key) };
        const active = await searchConditionalTarget(
          child,
          options,
          [...branch.guards, positive],
          [...branch.conditions, key],
          depth + 1,
        );
        for (const result of active) {
          if (result.state === "missing" || (options.typeOnly && result.state === "invalid")) {
            nextPending.push({ ...result, conditions: branch.conditions });
          }
          else terminal.push(result);
        }
        nextPending.push({
          state: "missing",
          guards: [...branch.guards, { op: "not", condition: positive }],
          conditions: branch.conditions,
        });
        continue;
      }
      const active = await searchConditionalTarget(
        child,
        options,
        selector.guard === undefined ? branch.guards : [...branch.guards, selector.guard],
        [...branch.conditions, key],
        depth + 1,
      );
      for (const result of active) {
        if (result.state === "missing" || (options.typeOnly && result.state === "invalid")) {
          nextPending.push({ ...result, conditions: branch.conditions });
        }
        else terminal.push(result);
      }
    }
    if (nextPending.length > 128) {
      return [...terminal, { state: "exhausted", guards, conditions }];
    }
    pending = nextPending;
  }
  return [...terminal, ...pending];
}

function selectPackageMapEntry(
  map: Record<string, unknown>,
  request: string,
  keyPrefix: "./" | "#",
): PackageMapEntry | null {
  // Match the pinned TypeScript resolver: a request containing `*` (or ending
  // in `/`) is never eligible for the exact-key fast path. In particular, a
  // malformed multi-star pattern must not become valid merely because the
  // request text is identical to the manifest key.
  if (!request.includes("*") && !request.endsWith("/") && Object.hasOwn(map, request)) {
    return { value: map[request] };
  }
  const matches = Object.keys(map).flatMap((key, order) => {
    if (!key.startsWith(keyPrefix) || key.split("*").length !== 2) return [];
    const star = key.indexOf("*");
    const prefix = key.slice(0, star);
    const suffix = key.slice(star + 1);
    if (
      request.length < prefix.length + suffix.length
      || !request.startsWith(prefix)
      || !request.endsWith(suffix)
    ) return [];
    return [{ key, prefix, suffix, order, capture: request.slice(prefix.length, request.length - suffix.length) }];
  }).sort((left, right) => (
    right.prefix.length - left.prefix.length
    || right.suffix.length - left.suffix.length
    || left.order - right.order
  ));
  const selected = matches[0];
  if (selected === undefined) return null;
  const invalidCapture = selected.capture.includes("\0")
    || selected.capture.includes("\\")
    || /%(?:2f|5c)/iu.test(selected.capture)
    || selected.capture.split("/").some((segment) => {
      const dotsDecoded = segment.replaceAll(/%2e/giu, ".");
      return dotsDecoded === "."
        || dotsDecoded === ".."
        || dotsDecoded.toLowerCase() === "node_modules";
    });
  return invalidCapture
    ? { value: undefined, invalid: true }
    : { value: map[selected.key], capture: selected.capture };
}

function declaredPackageEntry(manifest: Record<string, unknown>, subpath: string): PackageMapEntry | null {
  const exportsValue = manifest.exports;
  if (subpath === "." && (typeof exportsValue === "string" || Array.isArray(exportsValue) || exportsValue === null)) {
    return { value: exportsValue };
  }
  if (exportsValue === null || typeof exportsValue !== "object" || Array.isArray(exportsValue)) return null;
  const exportMap = exportsValue as Record<string, unknown>;
  const keys = Object.keys(exportMap);
  const hasSubpaths = keys.some((key) => key.startsWith("."));
  if (hasSubpaths && keys.some((key) => !key.startsWith("."))) return { value: undefined, invalid: true };
  if (subpath === "." && !hasSubpaths) return { value: exportMap };
  return selectPackageMapEntry(exportMap, subpath, "./");
}

function packageExportsAreEnabled(manifest: Record<string, unknown>, effectiveTypes: boolean): boolean {
  if (!Object.hasOwn(manifest, "exports")) return false;
  const value = manifest.exports;
  // The pinned TypeScript resolver uses JavaScript truthiness for effective
  // type/self-name resolution. Runtime Node resolution uses a nullish check.
  return effectiveTypes ? Boolean(value) : value !== null && value !== undefined;
}

async function packageEntrySelection(
  manifest: Record<string, unknown>,
  subpath: string,
  typeOnly: boolean,
  moduleKind: ModuleResolutionKind,
  probe: (value: string) => boolean | Promise<boolean>,
): Promise<PackageEntrySelection> {
  const exportsDefined = packageExportsAreEnabled(manifest, typeOnly);
  if (exportsDefined) {
    const entry = declaredPackageEntry(manifest, subpath);
    if (entry === null) return { targets: [], exportsDefined: true, matched: false, reason: "package_subpath_not_exported" };
    if (entry.invalid === true) {
      return { targets: [], exportsDefined: true, matched: true, reason: "package_exports_configuration_invalid" };
    }
    const profiles = typeOnly
      ? [{ environment: "neutral", guards: [] as Condition[] }]
      : WEB_ENVIRONMENTS.map((environment) => ({
        environment,
        guards: [{ op: "eq", key: "environment", value: environment } as Condition],
      }));
    const outcomes = (await Promise.all(profiles.map(async ({ environment, guards }) => searchConditionalTarget(
      entry.value,
      {
        environment,
        typeOnly,
        moduleKind,
        targetKind: "exports",
        ...(entry.capture === undefined ? {} : { patternCapture: entry.capture }),
        probe,
        budget: { remaining: MAX_CONDITIONAL_TARGET_NODES },
      },
      guards,
    )))).flat();
    const targets = outcomes
      .filter((outcome): outcome is ConditionalSearchResult & { state: "target"; value: string } => (
        outcome.state === "target" && outcome.value !== undefined
      ))
      .map((outcome) => ({ value: outcome.value, conditions: outcome.conditions, guards: outcome.guards }));
    const states = new Set(outcomes.map((outcome) => outcome.state));
    if (states.has("exhausted")) {
      return { targets: [], exportsDefined: true, matched: true, reason: "package_condition_state_limit_exceeded" };
    }
    if (states.has("unsupported")) {
      return { targets: [], exportsDefined: true, matched: true, reason: "package_types_version_selector_unsupported" };
    }
    const incomplete = outcomes.some((outcome) => outcome.state !== "target");
    return {
      targets: incomplete ? [] : targets,
      exportsDefined: true,
      matched: true,
      reason: incomplete && targets.length > 0
        ? "package_export_target_partially_unavailable"
        : targets.length > 0
        ? null
        : states.has("blocked") ? "package_subpath_blocked"
          : states.has("invalid") ? "package_export_target_invalid"
            : "package_export_target_not_found",
    };
  }

  const legacy: Array<{ value: string; condition: string }> = [];
  if (subpath !== ".") legacy.push({ value: subpath.slice(2), condition: "default" });
  else {
    const fields = typeOnly ? ["typings", "types", "main"] : ["module", "main"];
    for (const field of fields) {
      const value = manifest[field];
      if (typeof value === "string") legacy.push({ value, condition: field });
    }
    legacy.push({ value: "index", condition: "default" });
  }
  for (const target of legacy) {
    if (await probe(target.value)) {
      return {
        targets: [{
          value: target.value,
          conditions: [target.condition],
          guards: [],
        }],
        exportsDefined: false,
        matched: true,
        reason: null,
      };
    }
  }
  return { targets: [], exportsDefined: false, matched: true, reason: "package_legacy_target_not_found" };
}

async function packageImportSelection(
  manifest: Record<string, unknown>,
  specifier: string,
  typeOnly: boolean,
  moduleKind: ModuleResolutionKind,
  probe: (value: string) => boolean | Promise<boolean>,
): Promise<PackageEntrySelection> {
  if (specifier === "#") {
    return { targets: [], exportsDefined: false, matched: false, reason: "package_import_specifier_invalid" };
  }
  const imports = manifest.imports;
  if (imports === null || typeof imports !== "object" || Array.isArray(imports)) {
    return { targets: [], exportsDefined: false, matched: false, reason: "package_import_not_defined" };
  }
  const entry = selectPackageMapEntry(imports as Record<string, unknown>, specifier, "#");
  if (entry === null) {
    return { targets: [], exportsDefined: false, matched: false, reason: "package_import_not_defined" };
  }
  if (entry.invalid === true) {
    return { targets: [], exportsDefined: false, matched: true, reason: "package_import_specifier_invalid" };
  }
  const profiles = typeOnly
    ? [{ environment: "neutral", guards: [] as Condition[] }]
    : WEB_ENVIRONMENTS.map((environment) => ({
      environment,
      guards: [{ op: "eq", key: "environment", value: environment } as Condition],
    }));
  const outcomes = (await Promise.all(profiles.map(async ({ environment, guards }) => searchConditionalTarget(
    entry.value,
    {
      environment,
      typeOnly,
      moduleKind,
      targetKind: "imports",
      ...(entry.capture === undefined ? {} : { patternCapture: entry.capture }),
      probe,
      budget: { remaining: MAX_CONDITIONAL_TARGET_NODES },
    },
    guards,
  )))).flat();
  const targets = outcomes
    .filter((outcome): outcome is ConditionalSearchResult & { state: "target"; value: string } => (
      outcome.state === "target" && outcome.value !== undefined
    ))
    .map((outcome) => ({ value: outcome.value, conditions: outcome.conditions, guards: outcome.guards }));
  const states = new Set(outcomes.map((outcome) => outcome.state));
  if (states.has("exhausted")) {
    return { targets: [], exportsDefined: false, matched: true, reason: "package_condition_state_limit_exceeded" };
  }
  if (states.has("unsupported")) {
    return { targets: [], exportsDefined: false, matched: true, reason: "package_types_version_selector_unsupported" };
  }
  const incomplete = outcomes.some((outcome) => outcome.state !== "target");
  return {
    targets: incomplete ? [] : targets,
    exportsDefined: false,
    matched: true,
    reason: incomplete && targets.length > 0
      ? "package_import_target_partially_unavailable"
      : targets.length > 0
      ? null
      : states.has("blocked") ? "package_import_blocked"
        : states.has("invalid") ? "package_import_target_invalid"
          : "package_import_target_not_found",
  };
}

function combineConditions(...conditions: Array<Condition | undefined>): Condition {
  return canonicalizeCondition({
    op: "all",
    conditions: conditions.filter((condition): condition is Condition => condition !== undefined),
  });
}

function conditionIsSatisfiable(condition: Condition): boolean {
  const atomKeys = new Set<string>();
  const collect = (current: Condition): void => {
    switch (current.op) {
      case "all":
      case "any":
        current.conditions.forEach(collect);
        return;
      case "not":
        collect(current.condition);
        return;
      case "defined":
      case "eq":
      case "in":
        if (current.key !== "environment" && current.key !== "mode") atomKeys.add(JSON.stringify(current));
    }
  };
  collect(condition);
  const atoms = [...atomKeys];
  // Condition manifests are already bounded. If a deliberately adversarial
  // manifest still creates too many independent atoms, retain the target
  // conservatively instead of claiming an impossible proof.
  if (atoms.length > 12) return true;
  const evaluate = (current: Condition, environment: string, assignment: ReadonlyMap<string, boolean>): boolean => {
    switch (current.op) {
      case "all": return current.conditions.every((child) => evaluate(child, environment, assignment));
      case "any": return current.conditions.some((child) => evaluate(child, environment, assignment));
      case "not": return !evaluate(current.condition, environment, assignment);
      case "defined": return assignment.get(JSON.stringify(current)) ?? false;
      case "eq":
        if (current.key === "environment") return current.value === environment;
        if (current.key === "mode") return current.value === "production";
        return assignment.get(JSON.stringify(current)) ?? false;
      case "in":
        if (current.key === "environment") return current.values.includes(environment);
        if (current.key === "mode") return current.values.includes("production");
        return assignment.get(JSON.stringify(current)) ?? false;
    }
  };
  for (const environment of WEB_ENVIRONMENTS) {
    for (let mask = 0; mask < 2 ** atoms.length; mask += 1) {
      const assignment = new Map(atoms.map((atom, index) => [atom, (mask & (1 << index)) !== 0]));
      if (evaluate(condition, environment, assignment)) return true;
    }
  }
  return false;
}

function resolvedTargetKey(target: ResolvedTarget): string {
  if (target.kind === "file") return `file\0${target.absolutePath}`;
  if (target.kind === "workspace_package") return `workspace\0${target.package.id}`;
  return `external\0${target.locator}`;
}

function conditionForTargets(targets: ConditionalStringTarget[]): Condition | undefined {
  const branches = targets
    .filter((target) => target.guards.length > 0)
    .map((target): Condition => canonicalizeCondition({
      op: "all",
      conditions: [WEB_CONDITION, ...target.guards],
    }));
  if (branches.length === 0) return undefined;
  return canonicalizeCondition({ op: "any", conditions: branches });
}

function typeScriptPathPatternMatches(pattern: string, specifier: string): boolean {
  const star = pattern.indexOf("*");
  if (star < 0) return pattern === specifier;
  const prefix = pattern.slice(0, star);
  const suffix = pattern.slice(star + 1);
  return specifier.length >= prefix.length + suffix.length
    && specifier.startsWith(prefix)
    && specifier.endsWith(suffix);
}

/** Whether two admitted single-wildcard TypeScript path patterns can match one request. */
function typeScriptPathPatternsOverlap(left: string, right: string): boolean {
  const leftStar = left.indexOf("*");
  const rightStar = right.indexOf("*");
  if (leftStar < 0) return typeScriptPathPatternMatches(right, left);
  if (rightStar < 0) return typeScriptPathPatternMatches(left, right);
  const leftPrefix = left.slice(0, leftStar);
  const rightPrefix = right.slice(0, rightStar);
  const leftSuffix = left.slice(leftStar + 1);
  const rightSuffix = right.slice(rightStar + 1);
  return (leftPrefix.startsWith(rightPrefix) || rightPrefix.startsWith(leftPrefix))
    && (leftSuffix.endsWith(rightSuffix) || rightSuffix.endsWith(leftSuffix));
}

const NODE_BUILTIN_SPECIFIERS = [...new Set(builtinModules.flatMap((specifier) => (
  specifier.startsWith("node:")
    ? [specifier, specifier.slice("node:".length)]
    : [specifier, `node:${specifier}`]
)))];

function typeScriptPathPatternCanMatchNodeBuiltin(pattern: string): boolean {
  return typeScriptPathPatternsOverlap(pattern, "node:*")
    || NODE_BUILTIN_SPECIFIERS.some((specifier) => typeScriptPathPatternMatches(pattern, specifier));
}

function fileBaseCandidates(
  base: string,
  includeDirectoryIndex = true,
  stripSpecifierSuffix = true,
  typeScriptLoadableOnly = false,
): string[] {
  const clean = stripSpecifierSuffix ? base.replace(/[?#].*$/u, "") : base;
  const extension = path.extname(clean).toLowerCase();
  const stem = extension === "" ? clean : clean.slice(0, -extension.length);
  let candidates: string[];
  if (extension === ".js") candidates = [`${stem}.ts`, `${stem}.tsx`, `${stem}.d.ts`, clean, `${stem}.jsx`];
  else if (extension === ".jsx") candidates = [`${stem}.tsx`, `${stem}.ts`, `${stem}.d.ts`, clean, `${stem}.js`];
  else if (extension === ".mjs") candidates = [`${stem}.mts`, `${stem}.d.mts`, clean];
  else if (extension === ".cjs") candidates = [`${stem}.cts`, `${stem}.d.cts`, clean];
  else if (extension !== "") {
    candidates = !typeScriptLoadableOnly || [".ts", ".tsx", ".mts", ".cts"].includes(extension)
      ? [clean]
      : [];
  }
  else {
    // TS extensionless lookup does not synthesize .mts/.cts: those are only
    // substitutions for explicit .mjs/.cjs specifiers.
    const extensions = typeScriptLoadableOnly
      ? [".ts", ".tsx", ".d.ts", ".js", ".jsx"]
      : [".ts", ".tsx", ".d.ts", ".js", ".jsx", ".json", ".astro"];
    candidates = [
      ...extensions.map((item) => `${clean}${item}`),
      ...(includeDirectoryIndex ? extensions.map((item) => path.join(clean, `index${item}`)) : []),
    ];
  }
  return [...new Set(candidates.map((item) => path.resolve(item)))];
}

interface ExternalPackageManifest {
  root: string;
  manifest: Record<string, unknown>;
  version: string | null;
}

interface PackageFileTargets {
  files: string[];
  targetDeclarations: ConditionalStringTarget[];
  condition?: Condition;
  conditionNames: string[];
  reason: string | null;
}

export class ModuleResolver {
  readonly #root: string;
  readonly #workspace: Workspace;
  readonly #fileSet: Set<string>;
  readonly #aliasRules = new Map<string, AliasRule[]>();
  readonly #staticConfigFiles = new Set<string>();
  readonly #projectPathMappings = new Map<string, string[]>();
  readonly #projectPathMappingOwners = new Map<string, string>();
  readonly #ambiguousProjectPathMappings = new Set<string>();
  readonly #ownerProjectPathMappings = new Map<string, Map<string, string[]>>();
  readonly #sourceOwnerIds: Set<string>;
  readonly #externalPackages = new Map<string, Promise<ExternalPackageManifest[]>>();
  readonly #externalPackageBoundaries = new Set<string>();
  readonly #directoryPackageEntries = new Map<string, string[]>();
  readonly issues: ResolverIssue[] = [];

  private constructor(workspace: Workspace, allFiles: string[]) {
    this.#root = workspace.root;
    this.#workspace = workspace;
    this.#fileSet = new Set(allFiles.map((file) => path.resolve(file)));
    this.#sourceOwnerIds = new Set(allFiles
      .filter((file) => WEB_SOURCE_EXTENSIONS.has(path.extname(file).toLowerCase()))
      .map((file) => owningPackage(workspace, path.resolve(file)).id));
  }

  static async create(workspace: Workspace, allFiles: string[]): Promise<ModuleResolver> {
    const resolver = new ModuleResolver(workspace, allFiles);
    await resolver.#loadDirectoryPackageEntries();
    for (const record of workspace.packages) {
      await resolver.#loadAliases(record);
      await resolver.#loadWorkspaceCompilerMappings(record);
    }
    return resolver;
  }

  async #loadDirectoryPackageEntries(): Promise<void> {
    const manifests = [...this.#fileSet]
      .filter((file) => path.basename(file) === "package.json")
      .sort(compareUtf8);
    for (const manifestPath of manifests) {
      const manifest = await readJson(this.#root, manifestPath);
      if (manifest === null) continue;
      const directory = path.dirname(manifestPath);
      const entries: string[] = [];
      for (const field of ["typings", "types", "main"] as const) {
        const value = manifest[field];
        if (typeof value !== "string") continue;
        const portable = portableRelativePath(value);
        if (portable === null) continue;
        const target = path.resolve(directory, portable);
        if (isWithinRoot(this.#root, target)) entries.push(target);
      }
      if (entries.length > 0) this.#directoryPackageEntries.set(directory, entries);
    }
  }

  #addProjectPathMapping(ownerId: string, pattern: string, normalized: string): void {
    if (this.#ambiguousProjectPathMappings.has(pattern)) return;
    const existingOwner = this.#projectPathMappingOwners.get(pattern);
    if (existingOwner !== undefined && existingOwner !== ownerId) {
      // A single neutral TypeScript Program cannot represent package-scoped
      // aliases with the same key. Omit the ambiguous global hint; the
      // owner-aware resolver and TypeChecker module-export proof correlate it.
      this.#projectPathMappings.delete(pattern);
      this.#ambiguousProjectPathMappings.add(pattern);
      return;
    }
    this.#projectPathMappingOwners.set(pattern, ownerId);
    const mappings = this.#projectPathMappings.get(pattern) ?? [];
    if (!mappings.includes(normalized)) mappings.push(normalized);
    this.#projectPathMappings.set(pattern, mappings);
  }

  #addOwnerProjectPathMapping(ownerId: string, pattern: string, normalized: string): void {
    const ownerMappings = this.#ownerProjectPathMappings.get(ownerId) ?? new Map<string, string[]>();
    const replacements = ownerMappings.get(pattern) ?? [];
    if (!replacements.includes(normalized)) replacements.push(normalized);
    ownerMappings.set(pattern, replacements);
    this.#ownerProjectPathMappings.set(ownerId, ownerMappings);
  }

  async #loadWorkspaceCompilerMappings(record: PackageRecord): Promise<void> {
    const add = (pattern: string, targetValue: string): void => {
      if (!targetValue.startsWith("./")) return;
      const packageBase = record.relativePath === "." ? "" : record.relativePath;
      const normalized = resolvePortableRepositoryPath(packageBase, targetValue);
      if (normalized === null) return;
      this.#addProjectPathMapping(record.id, pattern, normalized);
    };
    const exportsValue = record.manifest.exports;
    const subpaths = exportsValue !== null && typeof exportsValue === "object" && !Array.isArray(exportsValue)
      && Object.keys(exportsValue as Record<string, unknown>).some((key) => key.startsWith("."))
      ? Object.keys(exportsValue as Record<string, unknown>).filter((key) => (
        (key === "." || key.startsWith("./")) && key.split("*").length <= 2
      ))
      : ["."];
    for (const subpath of subpaths) {
      const probe = (target: string): boolean => (
        target.includes("*") || this.#resolveFileBase(path.resolve(record.absolutePath, target)).length > 0
      );
      const [importSelection, requireSelection] = await Promise.all([
        packageEntrySelection(record.manifest, subpath, true, "import", probe),
        packageEntrySelection(record.manifest, subpath, true, "require", probe),
      ]);
      const importTargets = importSelection.targets.map((target) => target.value);
      const requireTargets = requireSelection.targets.map((target) => target.value);
      // The neutral Program has one paths table for both resolver phases.
      // Publishing either phase alone can make import-equals prove the import
      // declaration while owner-aware refinement correctly selects require.
      if (
        importTargets.length !== requireTargets.length
        || importTargets.some((target, index) => target !== requireTargets[index])
      ) continue;
      const pattern = subpath === "." ? record.name : `${record.name}${subpath.slice(1)}`;
      for (const target of importTargets) {
        const normalized = target.startsWith("./") ? target : `./${target}`;
        add(pattern, normalized);
      }
    }
  }

  typeScriptStaticConfig(requests: readonly TypeScriptPathRequest[] = []): TypeScriptStaticConfig {
    const paths = new Map<string, string[]>();
    const sourceOwnerIds = [...this.#sourceOwnerIds].sort(compareUtf8);
    const ownerPatternSequences = sourceOwnerIds.map((ownerId) => (
      [...(this.#ownerProjectPathMappings.get(ownerId)?.keys() ?? [])]
    ));
    const firstPatternSequence = ownerPatternSequences[0] ?? [];
    const sharedPatternOrder = ownerPatternSequences.every((patterns) => (
      patterns.length === firstPatternSequence.length
      && patterns.every((pattern, index) => pattern === firstPatternSequence[index])
    ));
    const ownerPatterns = new Set(ownerPatternSequences.flat());
    const ownerPatternList = [...ownerPatterns];
    const firstOwnerMappings = this.#ownerProjectPathMappings.get(sourceOwnerIds[0] ?? "");
    if (sharedPatternOrder && firstOwnerMappings !== undefined) {
      for (const [pattern, replacements] of firstOwnerMappings) {
        if (typeScriptPathPatternCanMatchNodeBuiltin(pattern)) continue;
        if (sourceOwnerIds.every((ownerId) => {
          const candidate = this.#ownerProjectPathMappings.get(ownerId)?.get(pattern);
          return candidate !== undefined
            && candidate.length === replacements.length
            && candidate.every((value, index) => value === replacements[index]);
        })) paths.set(pattern, [...replacements]);
      }
    }
    for (const [pattern, replacements] of this.#projectPathMappings) {
      // Owner resolution applies tsconfig aliases before workspace packages,
      // while a combined TypeScript `paths` table chooses among every pattern.
      // Any intersecting workspace hint could therefore shadow or be shadowed
      // by an owner alias and make the neutral Program prove another target.
      if (
        typeScriptPathPatternCanMatchNodeBuiltin(pattern)
        || ownerPatternList.some((ownerPattern) => typeScriptPathPatternsOverlap(pattern, ownerPattern))
      ) continue;
      if (!paths.has(pattern)) paths.set(pattern, [...replacements]);
    }
    const requestsBySpecifier = new Map<string, Set<string>>();
    for (const request of requests) {
      const sourceFile = path.resolve(request.sourceFile);
      if (
        request.specifier === ""
        || request.specifier.includes("*")
        || request.specifier.startsWith(".")
        || request.specifier.startsWith("/")
        || request.specifier.startsWith("node:")
        || isBuiltin(request.specifier)
        || !this.#fileSet.has(sourceFile)
        || !isWithinRoot(this.#root, sourceFile)
      ) continue;
      const sources = requestsBySpecifier.get(request.specifier) ?? new Set<string>();
      sources.add(sourceFile);
      requestsBySpecifier.set(request.specifier, sources);
    }
    for (const [specifier, sourceFiles] of [...requestsBySpecifier].sort(([left], [right]) => compareUtf8(left, right))) {
      let sharedTarget: string | null = null;
      let safe = true;
      for (const sourceFile of sourceFiles) {
        const owner = owningPackage(this.#workspace, sourceFile);
        const aliasTargets = this.#resolveAlias(specifier, owner, false);
        if (aliasTargets === null || aliasTargets.length !== 1) {
          safe = false;
          break;
        }
        const target = normalizeRelative(path.relative(this.#root, aliasTargets[0]!));
        if (sharedTarget !== null && target !== sharedTarget) {
          safe = false;
          break;
        }
        sharedTarget = target;
      }
      // Exact, observed request hints cannot affect a different specifier.
      // Admit one only when every source occurrence's owner-aware alias proof
      // selects the same repository file; otherwise retain fail-closed paths.
      if (safe && sharedTarget !== null) paths.set(specifier, [sharedTarget]);
    }
    return {
      configFiles: this.#staticConfigFiles.size,
      pathMappings: new Set([...this.#aliasRules.values()].flatMap((rules) => rules.map((rule) => rule.pattern))).size,
      paths: Object.fromEntries(paths),
    };
  }

  async #loadAliases(record: PackageRecord): Promise<void> {
    for (const configName of ["tsconfig.json", "jsconfig.json"]) {
      const configPath = path.join(record.absolutePath, configName);
      if (!this.#fileSet.has(path.resolve(configPath))) continue;
      const chain = await this.#loadConfigChain(configPath, new Set());
      // `compilerOptions.paths` is one option: a child declaration replaces
      // the complete parent object. Its substitutions are relative to the
      // config which declared `paths` in the bundled TS 7 resolver; baseUrl is
      // deliberately not inherited/applied here.
      const declaration = [...chain].reverse().find(({ config }) => {
        const options = config.compilerOptions;
        return options !== null
          && typeof options === "object"
          && !Array.isArray(options)
          && Object.hasOwn(options as Record<string, unknown>, "paths");
      });
      const rules: AliasRule[] = [];
      if (declaration !== undefined) {
        const { config, configPath: sourcePath } = declaration;
        const typed = config.compilerOptions as Record<string, unknown>;
        const sourceDirectory = normalizeRelative(path.relative(this.#root, path.dirname(sourcePath)));
        const baseRelative = sourceDirectory === "" ? "." : sourceDirectory;
        const paths = typed.paths;
        if (paths !== null && typeof paths === "object" && !Array.isArray(paths)) {
          for (const [pattern, replacements] of Object.entries(paths)) {
            if (!Array.isArray(replacements) || !replacements.every((item) => typeof item === "string")) {
              this.issues.push({ path: normalizeRelative(path.relative(this.#root, sourcePath)), reason: `invalid path alias replacements for ${pattern}` });
              continue;
            }
            if (replacements.some((replacement) => replacement.split("*").length > 2)) {
              this.issues.push({
                path: normalizeRelative(path.relative(this.#root, sourcePath)),
                reason: `path alias replacement contains multiple wildcards: ${pattern}`,
              });
              continue;
            }
            const admitted = replacements
              .map((replacement) => ({
                replacement: portableRelativePath(replacement),
                virtual: resolvePortableRepositoryPath(baseRelative, replacement),
              }))
              .filter((entry): entry is { replacement: string; virtual: string } => (
                entry.replacement !== null && entry.virtual !== null
              ));
            if (admitted.length !== replacements.length) {
              this.issues.push({
                path: normalizeRelative(path.relative(this.#root, sourcePath)),
                reason: `path alias replacement escapes the repository: ${pattern}`,
              });
            }
            if (admitted.length > 0) {
              const normalizedPattern = pattern.replaceAll("\\", "/");
              if (normalizedPattern.split("*").length > 2) {
                this.issues.push({
                  path: normalizeRelative(path.relative(this.#root, sourcePath)),
                  reason: `path alias pattern contains multiple wildcards: ${pattern}`,
                });
                continue;
              }
              rules.push({
                pattern: normalizedPattern,
                replacements: admitted.map((entry) => entry.replacement),
                virtualReplacements: admitted.map((entry) => entry.virtual),
                basePath: path.join(this.#root, ...baseRelative.split("/")),
              });
            }
          }
        } else {
          this.issues.push({ path: normalizeRelative(path.relative(this.#root, sourcePath)), reason: "compilerOptions.paths is not a static object" });
        }
      }
      if (rules.length > 0) {
        this.#aliasRules.set(record.id, rules);
        for (const rule of rules) {
          for (const normalized of rule.virtualReplacements) {
            this.#addOwnerProjectPathMapping(record.id, rule.pattern, normalized);
          }
        }
      }
      break;
    }
  }

  async #loadConfigChain(configPath: string, seen: Set<string>): Promise<Array<{ configPath: string; config: Record<string, unknown> }>> {
    const absolute = path.resolve(configPath);
    const relative = normalizeRelative(path.relative(this.#root, absolute));
    if (!isWithinRoot(this.#root, absolute) || !this.#fileSet.has(absolute)) {
      this.issues.push({ path: relative, reason: "extended config is outside the repository, missing, or a symlink" });
      return [];
    }
    if (seen.has(absolute)) {
      this.issues.push({ path: relative, reason: "cyclic tsconfig/jsconfig extends chain" });
      return [];
    }
    seen.add(absolute);
    const source = await readUtf8(this.#root, absolute);
    const config = source === null ? null : parseStaticJsonc(source);
    if (config === null) {
      this.issues.push({ path: relative, reason: "config is not valid static JSONC" });
      return [];
    }
    this.#staticConfigFiles.add(relative);
    const parents: Array<{ configPath: string; config: Record<string, unknown> }> = [];
    const extended = typeof config.extends === "string"
      ? [config.extends]
      : Array.isArray(config.extends) ? config.extends.filter((item): item is string => typeof item === "string") : [];
    for (const parent of extended) {
      const portableParent = portableRelativePath(parent);
      if (portableParent === null) {
        this.issues.push({ path: relative, reason: `absolute config extends was not loaded in safe mode: ${parent}` });
        continue;
      }
      if (!portableParent.startsWith(".")) {
        this.issues.push({ path: relative, reason: `package-based config extends was not loaded in safe mode: ${parent}` });
        continue;
      }
      const configDirectory = normalizeRelative(path.relative(this.#root, path.dirname(absolute)));
      let parentRelative = resolvePortableRepositoryPath(configDirectory, portableParent);
      if (parentRelative === null) {
        this.issues.push({ path: relative, reason: `extended config escapes the repository: ${parent}` });
        continue;
      }
      if (path.posix.extname(parentRelative) === "") parentRelative += ".json";
      const parentPath = path.join(this.#root, ...parentRelative.split("/"));
      parents.push(...await this.#loadConfigChain(parentPath, new Set(seen)));
    }
    parents.push({ configPath: absolute, config });
    return parents;
  }

  #resolveFileBase(
    base: string,
    seen: ReadonlySet<string> = new Set(),
    depth = 0,
    stripSpecifierSuffix = true,
    typeScriptLoadableOnly = false,
  ): string[] {
    const absolute = path.resolve(base);
    if (depth > 16 || seen.has(absolute) || !isWithinRoot(this.#root, absolute)) return [];
    const nextSeen = new Set(seen);
    nextSeen.add(absolute);
    const direct = fileBaseCandidates(absolute, false, stripSpecifierSuffix, typeScriptLoadableOnly)
      .find((item) => isWithinRoot(this.#root, item) && this.#fileSet.has(item));
    if (direct !== undefined) return [direct];
    if (path.extname(absolute) !== "") return [];
    for (const entry of this.#directoryPackageEntries.get(absolute) ?? []) {
      const resolved = this.#resolveFileBase(
        entry,
        nextSeen,
        depth + 1,
        stripSpecifierSuffix,
        typeScriptLoadableOnly,
      );
      if (resolved.length > 0) return resolved;
    }
    const index = fileBaseCandidates(absolute, true, stripSpecifierSuffix, typeScriptLoadableOnly)
      .slice(fileBaseCandidates(absolute, false, stripSpecifierSuffix, typeScriptLoadableOnly).length)
      .find((item) => isWithinRoot(this.#root, item) && this.#fileSet.has(item));
    return index === undefined ? [] : [index];
  }

  #resolveAlias(specifier: string, owner: PackageRecord, stripSpecifierSuffix: boolean): string[] | null {
    const matches: Array<{ rule: AliasRule; capture: string; exact: boolean; prefixLength: number }> = [];
    for (const rule of this.#aliasRules.get(owner.id) ?? []) {
      const star = rule.pattern.indexOf("*");
      let capture = "";
      if (star < 0) {
        if (specifier !== rule.pattern) continue;
      } else {
        const prefix = rule.pattern.slice(0, star);
        const suffix = rule.pattern.slice(star + 1);
        if (
          specifier.length < prefix.length + suffix.length
          || !specifier.startsWith(prefix)
          || !specifier.endsWith(suffix)
        ) continue;
        capture = specifier.slice(prefix.length, specifier.length - suffix.length);
      }
      matches.push({ rule, capture, exact: star < 0, prefixLength: star < 0 ? rule.pattern.length : star });
    }
    let selected = matches.find((match) => match.exact);
    for (const match of matches) {
      if (match.exact) continue;
      if (selected === undefined || (!selected.exact && match.prefixLength > selected.prefixLength)) selected = match;
    }
    if (selected === undefined) return null;
    for (const replacement of selected.rule.replacements) {
      const resolved = this.#resolveFileBase(path.resolve(
        selected.rule.basePath,
        replacement.replace("*", selected.capture),
      ), new Set(), 0, stripSpecifierSuffix, !stripSpecifierSuffix);
      if (resolved.length === 0) continue;
      // `compilerOptions.paths` replacements are ordered fallbacks. Once a
      // replacement resolves, later entries are not alternative targets.
      return [...new Set(resolved)].sort(compareUtf8);
    }
    return [];
  }

  async #workspacePackageTargets(
    specifier: string,
    record: PackageRecord,
    typeOnly: boolean,
    moduleKind: ModuleResolutionKind,
  ): Promise<{
    targets: ResolvedTarget[];
    condition?: Condition;
    targetConditions?: Condition[];
    conditionNames: string[];
    reason: string | null;
  }> {
    const subpath = subpathOf(specifier, record.name);
    const selection = await packageEntrySelection(
      record.manifest,
      subpath,
      typeOnly,
      moduleKind,
      (target) => this.#resolveFileBase(
        path.resolve(record.absolutePath, target),
        new Set(),
        0,
        !typeOnly,
        typeOnly,
      ).length > 0,
    );
    const conditionsByFile = new Map<string, ConditionalStringTarget[]>();
    for (const target of selection.targets) {
      for (const file of this.#resolveFileBase(
        path.resolve(record.absolutePath, target.value),
        new Set(),
        0,
        !typeOnly,
        typeOnly,
      )) {
        if (!isWithinRoot(record.absolutePath, file)) continue;
        const conditions = conditionsByFile.get(file) ?? [];
        conditions.push(target);
        conditionsByFile.set(file, conditions);
      }
    }
    const files = [...conditionsByFile.keys()].sort(compareUtf8);
    const resolvedDeclarations = [...conditionsByFile.values()].flat();
    if (resolvedDeclarations.length < selection.targets.length) {
      return {
        targets: [],
        conditionNames: [],
        reason: resolvedDeclarations.length > 0
          ? "package_export_target_partially_unavailable"
          : selection.exportsDefined ? "package_export_target_not_found" : "package_legacy_target_not_found",
      };
    }
    const conditionNames = [...new Set(resolvedDeclarations.flatMap((target) => target.conditions))].sort(compareUtf8);
    const condition = conditionForTargets(resolvedDeclarations);
    return {
      targets: files.map((absolutePath) => ({ kind: "file", absolutePath })),
      targetConditions: files.map((file) => conditionForTargets(conditionsByFile.get(file) ?? []) ?? WEB_CONDITION),
      ...(condition ? { condition } : {}),
      conditionNames,
      reason: selection.reason ?? (files.length === 0
        ? selection.exportsDefined ? "package_export_target_not_found" : "package_legacy_target_not_found"
        : resolvedDeclarations.length < selection.targets.length ? "package_export_target_partially_unavailable" : null),
    };
  }

  async #resolveWorkspacePackages(
    specifier: string,
    workspaceMatches: PackageRecord[],
    typeOnly: boolean,
    moduleKind: ModuleResolutionKind,
  ): Promise<Resolution> {
    const resolved = await Promise.all(workspaceMatches.map((record) => (
      this.#workspacePackageTargets(specifier, record, typeOnly, moduleKind)
    )));
    const targets = resolved.flatMap((entry) => entry.targets);
    if (targets.length === 0) {
      const reasons = [...new Set(resolved.map((entry) => entry.reason).filter((reason): reason is string => reason !== null))].sort(compareUtf8);
      return {
        status: "unresolved",
        precision: "heuristic",
        targets: [],
        reason: reasons.join(",") || "workspace_package_target_not_found",
      };
    }
    const targetConditions = resolved.flatMap((entry) => entry.targetConditions ?? entry.targets.map(() => entry.condition ?? WEB_CONDITION));
    const conditions = resolved.map((entry) => entry.condition).filter((condition): condition is Condition => condition !== undefined);
    const conditionNames = [...new Set(resolved.flatMap((entry) => entry.conditionNames))].sort(compareUtf8);
    const targetReasons = [...new Set(resolved.map((entry) => entry.reason).filter((reason): reason is string => reason !== null))].sort(compareUtf8);
    return {
      status: targets.length === 1 && workspaceMatches.length === 1 ? "resolved" : "candidates",
      precision: targetReasons.length > 0 ? "heuristic" : targets.length === 1 && workspaceMatches.length === 1 ? "exact" : "overapprox",
      targets,
      targetConditions,
      reason: targetReasons.length > 0
        ? targetReasons.join(",")
        : conditionNames.length > 0
          ? `package_exports_conditions=${conditionNames.join(",")}`
          : targets.length === 1 ? null : "multiple_workspace_package_targets",
      ...(conditions.length > 0 ? { condition: canonicalizeCondition({ op: "any", conditions }) } : {}),
    };
  }

  #externalPackageLookup(
    owner: PackageRecord,
    packageName: string,
    lookupDirectory: string,
  ): { key: string; startDirectory: string } | null {
    const startDirectory = path.resolve(lookupDirectory);
    if (!isWithinRoot(this.#root, startDirectory)) return null;
    const relativeStart = normalizeRelative(path.relative(this.#root, startDirectory));
    return {
      key: JSON.stringify([owner.id, relativeStart, packageName]),
      startDirectory,
    };
  }

  async #loadExternalPackages(
    packageName: string,
    lookup: { key: string; startDirectory: string },
  ): Promise<ExternalPackageManifest[]> {
    const { key } = lookup;
    const existing = this.#externalPackages.get(key);
    if (existing) return existing;
    const loading = (async (): Promise<ExternalPackageManifest[]> => {
      const records: ExternalPackageManifest[] = [];
      let directory = lookup.startDirectory;
      for (;;) {
        if (!isWithinRoot(this.#root, directory)) break;
        const packageDirectory = path.join(directory, "node_modules", packageName);
        let lexicalBoundary = false;
        try {
          await lstat(packageDirectory);
          lexicalBoundary = true;
        } catch (error) {
          const code = (error as NodeJS.ErrnoException).code;
          if (code !== "ENOENT" && code !== "ENOTDIR") lexicalBoundary = true;
        }
        if (lexicalBoundary) this.#externalPackageBoundaries.add(key);
        const resolvedPackageDirectory = await resolveWithinRoot(this.#root, packageDirectory);
        const directoryExists = resolvedPackageDirectory !== null
          && await stat(resolvedPackageDirectory).then((entry) => entry.isDirectory(), () => false);
        if (directoryExists) {
          const manifestPath = path.join(resolvedPackageDirectory, "package.json");
          const resolvedManifest = await resolveWithinRoot(this.#root, manifestPath);
          const manifest = resolvedManifest === null ? {} : await readJson(this.#root, resolvedManifest);
          if (manifest !== null) {
            // A physical directory without a manifest version cannot be
            // correlated to an arbitrary lock entry. Keep the version
            // unknown so every selected lock instance remains a candidate.
            const version = typeof manifest.version === "string" ? manifest.version : null;
            records.push({ root: resolvedPackageDirectory, manifest, version });
          }
          // Bare package lookup is bound to the nearest package boundary. A
          // blocked/missing export there must never fall through to a second
          // installation of the same name higher in the ancestor chain.
          break;
        }
        if (lexicalBoundary) break;
        if (directory === this.#root) break;
        const parent = path.dirname(directory);
        if (parent === directory) break;
        directory = parent;
      }
      return records;
    })();
    this.#externalPackages.set(key, loading);
    return loading;
  }

  async #externalPackageFiles(
    record: ExternalPackageManifest,
    subpath: string,
    typeOnly: boolean,
    moduleKind: ModuleResolutionKind,
  ): Promise<PackageFileTargets> {
    const resolveTarget = async (
      target: string,
      seen: ReadonlySet<string> = new Set(),
      depth = 0,
    ): Promise<string | null> => {
      const base = path.resolve(record.root, target);
      if (depth > 16 || seen.has(base) || !isWithinRoot(record.root, base)) return null;
      const nextSeen = new Set(seen);
      nextSeen.add(base);
      for (const candidate of fileBaseCandidates(base, false, !typeOnly, typeOnly)) {
        if (!isWithinRoot(record.root, candidate)) continue;
        const resolved = await resolveWithinRoot(this.#root, candidate);
        if (resolved !== null && isWithinRoot(record.root, resolved) && await isFile(this.#root, resolved)) return resolved;
      }
      if (path.extname(base) !== "") return null;
      const manifestPath = await resolveWithinRoot(this.#root, path.join(base, "package.json"));
      if (manifestPath !== null && isWithinRoot(record.root, manifestPath)) {
        const manifest = await readJson(this.#root, manifestPath);
        if (manifest !== null) {
          for (const field of ["typings", "types", "main"] as const) {
            const value = manifest[field];
            if (typeof value !== "string" || portableRelativePath(value) === null) continue;
            const resolved = await resolveTarget(path.resolve(base, value), nextSeen, depth + 1);
            if (resolved !== null) return resolved;
          }
        }
      }
      const directCount = fileBaseCandidates(base, false, !typeOnly, typeOnly).length;
      for (const candidate of fileBaseCandidates(base, true, !typeOnly, typeOnly).slice(directCount)) {
        if (!isWithinRoot(record.root, candidate)) continue;
        const resolved = await resolveWithinRoot(this.#root, candidate);
        if (resolved !== null && isWithinRoot(record.root, resolved) && await isFile(this.#root, resolved)) return resolved;
      }
      return null;
    };
    const selection = await packageEntrySelection(
      record.manifest,
      subpath,
      typeOnly,
      moduleKind,
      async (target) => await resolveTarget(target) !== null,
    );
    if (selection.reason !== null && selection.targets.length === 0) {
      return { files: [], targetDeclarations: [], conditionNames: [], reason: selection.reason };
    }
    const files = new Set<string>();
    const resolvedDeclarations: ConditionalStringTarget[] = [];
    for (const target of selection.targets) {
      const resolved = await resolveTarget(target.value);
      if (resolved === null) continue;
      files.add(resolved);
      resolvedDeclarations.push(target);
    }
    if (resolvedDeclarations.length < selection.targets.length) {
      return {
        files: [],
        targetDeclarations: [],
        conditionNames: [],
        reason: resolvedDeclarations.length > 0
          ? "package_export_target_partially_unavailable"
          : selection.exportsDefined ? "package_export_target_not_found" : "package_legacy_target_not_found",
      };
    }
    const condition = conditionForTargets(resolvedDeclarations);
    return {
      files: [...files].sort(compareUtf8),
      targetDeclarations: resolvedDeclarations,
      ...(condition ? { condition } : {}),
      conditionNames: [...new Set(resolvedDeclarations.flatMap((target) => target.conditions))].sort(compareUtf8),
      reason: selection.reason ?? (files.size === 0
        ? selection.exportsDefined ? "package_export_target_not_found" : "package_legacy_target_not_found"
        : resolvedDeclarations.length < selection.targets.length ? "package_export_target_partially_unavailable" : null),
    };
  }

  async #resolveExternalPackage(
    specifier: string,
    packageName: string,
    owner: PackageRecord,
    lookupDirectory: string,
    selectedInstances: LockInstance[] | null = null,
    typeOnly = false,
    moduleKind: ModuleResolutionKind = "import",
  ): Promise<Resolution> {
    const lookup = this.#externalPackageLookup(owner, packageName, lookupDirectory);
    if (lookup === null) {
      return { status: "unresolved", precision: "heuristic", targets: [], reason: "external_package_lookup_outside_repository" };
    }
    const installed = await this.#loadExternalPackages(packageName, lookup);
    const subpath = subpathOf(specifier, packageName);
    const candidateInstances = selectedInstances ?? this.#workspace.lockInstances.get(packageName) ?? [];
    if (installed.length > 0) {
      const inspected = await Promise.all(installed.map(async (record) => ({
        record,
        files: await this.#externalPackageFiles(record, subpath, typeOnly, moduleKind),
      })));
      const relevant = inspected;
      const valid = relevant.filter((entry) => entry.files.files.length > 0);
      const byLocator = new Map<string, { target: ResolvedTarget; condition: Condition; reason: string | null; conditionNames: string[] }>();
      for (const entry of valid) {
        const locked = entry.record.version === null
          ? candidateInstances
          : candidateInstances.filter((instance) => instance.version === entry.record.version);
        const instances = locked.length > 0
          ? locked
          : entry.record.version !== null
            ? [{ version: entry.record.version, locator: `${this.#workspace.manager}:${packageName}@${entry.record.version}` }]
            : [{
              version: owner.dependencies.get(packageName)?.range ?? "unknown",
              locator: `${this.#workspace.manager}:${packageName}@${owner.dependencies.get(packageName)?.range ?? "unknown"}`,
            }];
        for (const instance of instances) {
          byLocator.set(instance.locator, {
            target: { kind: "external_package", name: packageName, version: instance.version, locator: instance.locator },
            condition: entry.files.condition ?? WEB_CONDITION,
            reason: entry.files.reason ?? (entry.record.version === null ? "external_package_version_unproven" : null),
            conditionNames: entry.files.conditionNames,
          });
        }
      }
      const resolutions = [...byLocator.values()].sort((left, right) => (
        compareUtf8(
          left.target.kind === "external_package" ? left.target.locator : "",
          right.target.kind === "external_package" ? right.target.locator : "",
        )
      ));
      const inspectedReasons = relevant
        .filter((entry) => entry.files.files.length === 0)
        .map((entry) => entry.files.reason)
        .filter((reason): reason is string => reason !== null);
      if (resolutions.length === 0) {
        const reasons = [...new Set(inspectedReasons)].sort(compareUtf8);
        return { status: "unresolved", precision: "heuristic", targets: [], reason: reasons.join(",") || "external_package_target_not_found" };
      }
      const conditionNames = [...new Set(resolutions.flatMap((entry) => entry.conditionNames))].sort(compareUtf8);
      const partialReasons = [...new Set([
        ...resolutions.map((entry) => entry.reason),
        ...inspectedReasons,
      ].filter((reason): reason is string => reason !== null))].sort(compareUtf8);
      const conditions = [...new Map(resolutions.map((entry) => [JSON.stringify(entry.condition), entry.condition])).values()];
      const hasMultipleCandidates = resolutions.length > 1;
      return {
        status: hasMultipleCandidates ? "candidates" : "external",
        precision: hasMultipleCandidates ? "overapprox" : partialReasons.length === 0 ? "exact" : "heuristic",
        targets: resolutions.map((entry) => entry.target),
        targetConditions: resolutions.map((entry) => entry.condition),
        reason: partialReasons.length > 0
          ? partialReasons.join(",")
          : conditionNames.length > 0 ? `package_exports_conditions=${conditionNames.join(",")}` : hasMultipleCandidates ? "multiple_installed_package_instances" : null,
        ...(conditions.length > 0 ? { condition: canonicalizeCondition({ op: "any", conditions }) } : {}),
      };
    }

    if (this.#externalPackageBoundaries.has(lookup.key)) {
      return {
        status: "unresolved",
        precision: "heuristic",
        targets: [],
        reason: "external_package_manifest_invalid",
      };
    }

    const declared = owner.dependencies.get(packageName)?.range ?? "unknown";
    const locked = candidateInstances;
    const instances = locked.length > 0
      ? locked
      : [{ version: declared, locator: `${this.#workspace.manager}:${packageName}@${declared}` }];
    return {
      status: instances.length === 1 ? "external" : "candidates",
      precision: instances.length === 1 ? "heuristic" : "overapprox",
      targets: instances.map((instance) => ({
        kind: "external_package" as const,
        name: packageName,
        version: instance.version,
        locator: instance.locator,
      })),
      reason: instances.length > 1
        ? "multiple_locked_package_instances"
        : subpath === "." ? "external_package_files_unavailable" : "external_package_exports_unavailable",
    };
  }

  async #resolvePackageImport(
    dependency: RawDependency,
    sourceFile: string,
    owner: PackageRecord,
    moduleKind: ModuleResolutionKind,
    seen: ReadonlySet<string>,
    depth: number,
    aliasMissed: boolean,
  ): Promise<Resolution> {
    const effectiveTypes = dependency.typeOnly || dependency.useTypesCondition === true;
    const prefixReasons = (...reasons: Array<string | null | undefined>): string => (
      [...new Set([
        ...(aliasMissed ? ["path_alias_target_not_found"] : []),
        ...reasons,
      ].filter((reason): reason is string => typeof reason === "string" && reason !== ""))].sort(compareUtf8).join(",")
      || "package_import_target_not_found"
    );
    const probe = async (target: string): Promise<boolean> => {
      if (target.startsWith("./")) {
        return this.#resolveFileBase(
          path.resolve(owner.absolutePath, target),
          new Set(),
          0,
          !effectiveTypes,
          effectiveTypes,
        ).length > 0;
      }
      const nested = await this.#resolve(
        { ...dependency, specifier: target },
        sourceFile,
        owner,
        seen,
        depth + 1,
        false,
        owner.absolutePath,
      );
      return nested.targets.length > 0;
    };
    const selection = await packageImportSelection(
      owner.manifest,
      dependency.specifier,
      effectiveTypes,
      moduleKind,
      probe,
    );
    const byTarget = new Map<string, { target: ResolvedTarget; conditions: Condition[]; precision: Precision }>();
    const nestedReasons: string[] = [];
    let nestedFailed = false;
    for (const declaration of selection.targets) {
      const declarationCondition = conditionForTargets([declaration]) ?? WEB_CONDITION;
      let nested: Resolution;
      if (declaration.value.startsWith("./")) {
        const files = this.#resolveFileBase(
          path.resolve(owner.absolutePath, declaration.value),
          new Set(),
          0,
          !effectiveTypes,
          effectiveTypes,
        );
        nested = files.length === 0
          ? { status: "unresolved", precision: "heuristic", targets: [], reason: "package_import_target_not_found" }
          : {
            status: "resolved",
            precision: "exact",
            targets: files.map((absolutePath) => ({ kind: "file" as const, absolutePath })),
            reason: null,
          };
      } else {
        nested = await this.#resolve(
          { ...dependency, specifier: declaration.value },
          sourceFile,
          owner,
          seen,
          depth + 1,
          false,
          owner.absolutePath,
        );
      }
      if (nested.reason !== null) nestedReasons.push(nested.reason);
      if (nested.targets.length === 0) nestedFailed = true;
      let compatibleTargets = 0;
      for (let index = 0; index < nested.targets.length; index += 1) {
        const target = nested.targets[index]!;
        const nestedCondition = nested.targetConditions?.[index] ?? nested.condition ?? WEB_CONDITION;
        const condition = combineConditions(declarationCondition, nestedCondition);
        if (!conditionIsSatisfiable(condition)) continue;
        compatibleTargets += 1;
        const key = resolvedTargetKey(target);
        const current = byTarget.get(key);
        if (current === undefined) {
          byTarget.set(key, { target, conditions: [condition], precision: nested.precision });
        } else {
          current.conditions.push(condition);
          if (nested.precision === "heuristic") current.precision = "heuristic";
          else if (nested.precision === "overapprox" && current.precision === "exact") current.precision = "overapprox";
        }
      }
      if (nested.targets.length > 0 && compatibleTargets === 0) nestedFailed = true;
    }
    const entries = [...byTarget.values()].sort((left, right) => (
      compareUtf8(resolvedTargetKey(left.target), resolvedTargetKey(right.target))
    ));
    if (entries.length === 0 || nestedFailed) {
      return {
        status: "unresolved",
        precision: "heuristic",
        targets: [],
        reason: prefixReasons(
          selection.reason,
          ...nestedReasons,
          nestedFailed && entries.length > 0 ? "package_import_target_partially_unavailable" : null,
        ),
      };
    }
    const targetConditions = entries.map((entry) => canonicalizeCondition({ op: "any", conditions: entry.conditions }));
    const condition = canonicalizeCondition({ op: "any", conditions: targetConditions });
    const conditionNames = [...new Set(selection.targets.flatMap((target) => target.conditions))].sort(compareUtf8);
    const hasHeuristic = entries.some((entry) => entry.precision === "heuristic");
    const reasons = [...new Set([
      ...(conditionNames.length > 0 ? [`package_import_conditions=${conditionNames.join(",")}`] : []),
      ...nestedReasons,
    ])].sort(compareUtf8);
    return {
      status: entries.length === 1 && entries[0]!.target.kind === "external_package" ? "external"
        : entries.length === 1 ? "resolved" : "candidates",
      precision: hasHeuristic ? "heuristic" : entries.length === 1 ? entries[0]!.precision : "overapprox",
      targets: entries.map((entry) => entry.target),
      targetConditions,
      condition,
      reason: reasons.length > 0 ? reasons.join(",") : entries.length === 1 ? null : "multiple_package_import_targets",
    };
  }

  async resolve(dependency: RawDependency, sourceFile: string, owner: PackageRecord): Promise<Resolution> {
    return await this.#resolve(
      dependency,
      sourceFile,
      owner,
      new Set(),
      0,
      false,
      path.dirname(path.resolve(sourceFile)),
    );
  }

  async #resolve(
    dependency: RawDependency,
    sourceFile: string,
    owner: PackageRecord,
    seen: ReadonlySet<string>,
    depth: number,
    skipAliases: boolean,
    bareLookupDirectory: string,
  ): Promise<Resolution> {
    if (!dependency.literal) {
      return { status: "unresolved", precision: "heuristic", targets: [], reason: "computed_specifier" };
    }
    const specifier = dependency.specifier;
    const moduleKind = dependency.resolutionMode ?? moduleResolutionKind(dependency.kind);
    const useTypesCondition = dependency.typeOnly || dependency.useTypesCondition === true;
    const normalizedLookupDirectory = normalizeRelative(path.relative(this.#root, path.resolve(bareLookupDirectory)));
    const cycleKey = `${owner.id}\0${specifier}\0${useTypesCondition ? "types" : "runtime"}\0${moduleKind}\0${normalizedLookupDirectory}`;
    if (depth > 24 || seen.has(cycleKey)) {
      return { status: "unresolved", precision: "heuristic", targets: [], reason: "package_import_cycle_or_depth_limit" };
    }
    const nextSeen = new Set(seen);
    nextSeen.add(cycleKey);
    if (specifier.startsWith(".") || specifier.startsWith("/")) {
      const base = specifier.startsWith("/")
        ? useTypesCondition ? path.resolve(specifier) : path.resolve(this.#root, `.${specifier}`)
        : path.resolve(path.dirname(sourceFile), specifier);
      // Runtime profiles intentionally support bundler resource suffixes.
      // Semantic/type promotion must mirror TS Bundler, which does not strip
      // an uncorroborated query/hash before probing the filesystem.
      const files = this.#resolveFileBase(
        base,
        new Set(),
        0,
        !useTypesCondition,
        useTypesCondition,
      );
      if (files.length === 0) return { status: "unresolved", precision: "heuristic", targets: [], reason: "relative_target_not_found" };
      return {
        status: "resolved",
        precision: "exact",
        targets: files.map((absolutePath) => ({ kind: "file", absolutePath })),
        reason: null,
      };
    }
    if (specifier.startsWith("node:") || isBuiltin(specifier)) {
      if (!isBuiltin(specifier)) {
        return {
          status: "unresolved",
          precision: "heuristic",
          targets: [],
          reason: "unknown_node_builtin",
        };
      }
      const locator = specifier.startsWith("node:") ? specifier : `node:${specifier}`;
      return {
        status: "external",
        precision: "exact",
        targets: [{ kind: "external_package", name: locator, version: "builtin", locator }],
        reason: null,
      };
    }
    const aliases = skipAliases ? null : this.#resolveAlias(specifier, owner, !useTypesCondition);
    const aliasMissed = aliases !== null && aliases.length === 0;
    if (aliases !== null && aliases.length > 0) {
      return {
        status: "resolved",
        precision: "exact",
        targets: aliases.map((absolutePath) => ({ kind: "file", absolutePath })),
        reason: null,
      };
    }
    const unresolvedReason = (...reasons: Array<string | null | undefined>): string => (
      [...new Set([
        ...(aliasMissed ? ["path_alias_target_not_found"] : []),
        ...reasons,
      ].filter((reason): reason is string => typeof reason === "string" && reason !== ""))].sort(compareUtf8).join(",")
      || "package_target_not_found"
    );
    if (specifier.startsWith("#")) {
      return await this.#resolvePackageImport(
        dependency,
        sourceFile,
        owner,
        moduleKind,
        nextSeen,
        depth,
        aliasMissed,
      );
    }
    const packageName = packageNameOf(specifier);
    const selfReferenceEnabled = owner.name === packageName
      && packageExportsAreEnabled(owner.manifest, useTypesCondition);
    if (selfReferenceEnabled) {
      const self = await this.#resolveWorkspacePackages(specifier, [owner], useTypesCondition, moduleKind);
      return self.targets.length > 0 ? self : { ...self, reason: unresolvedReason(self.reason) };
    }
    const selection = selectPackageInstallCandidates(
      this.#workspace,
      owner,
      packageName,
      owner.dependencies.get(packageName)?.range ?? null,
      owner.name === packageName
        ? new Set((this.#workspace.packageByName.get(packageName) ?? []).map((record) => record.id))
        : new Set(),
    );
    if (selection.workspacePackages.length === 0 && selection.externalInstances.length === 0) {
      return { status: "unresolved", precision: "heuristic", targets: [], reason: unresolvedReason(selection.reason) };
    }
    const resolutions: Resolution[] = [];
    if (selection.workspacePackages.length > 0) {
      resolutions.push(await this.#resolveWorkspacePackages(specifier, selection.workspacePackages, useTypesCondition, moduleKind));
    }
    if (selection.externalInstances.length > 0) {
      resolutions.push(await this.#resolveExternalPackage(
        specifier,
        packageName,
        owner,
        bareLookupDirectory,
        selection.externalInstances,
        useTypesCondition,
        moduleKind,
      ));
    }
    if (resolutions.length === 1) {
      const resolution = resolutions[0]!;
      if (resolution.targets.length === 0) {
        return { ...resolution, reason: unresolvedReason(resolution.reason, selection.reason) };
      }
      const inspectedExternalExact = selection.workspacePackages.length === 0
        && resolution.precision === "exact"
        && resolution.targets.every((target) => target.kind === "external_package");
      const precision = inspectedExternalExact
        ? "exact"
        : selection.precision === "overapprox" || resolution.precision === "overapprox"
        ? "overapprox"
        : selection.precision === "heuristic" || resolution.precision === "heuristic" ? "heuristic" : "exact";
      return {
        ...resolution,
        precision,
        reason: resolution.reason ?? (inspectedExternalExact ? null : selection.reason),
      };
    }

    const targets = resolutions.flatMap((resolution) => resolution.targets);
    const reasons = [...new Set([
      selection.reason,
      ...resolutions.map((resolution) => resolution.reason),
    ].filter((reason): reason is string => reason !== null))].sort(compareUtf8);
    if (targets.length === 0) {
      return { status: "unresolved", precision: "heuristic", targets: [], reason: unresolvedReason(...reasons) };
    }
    const targetConditions = resolutions.flatMap((resolution) => (
      resolution.targetConditions ?? resolution.targets.map(() => resolution.condition ?? WEB_CONDITION)
    ));
    const conditions = resolutions
      .filter((resolution) => resolution.targets.length > 0)
      .map((resolution) => resolution.condition ?? canonicalizeCondition({
        op: "any",
        conditions: resolution.targetConditions ?? resolution.targets.map(() => WEB_CONDITION),
      }));
    return {
      status: "candidates",
      precision: "overapprox",
      targets,
      targetConditions,
      reason: reasons.join(",") || "workspace_and_external_package_candidates",
      ...(conditions.length > 0 ? { condition: canonicalizeCondition({ op: "any", conditions }) } : {}),
    };
  }
}

export function relativeImportPath(root: string, file: string): string {
  return normalizeRelative(path.relative(root, file));
}
