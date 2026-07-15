import path from "node:path";
import { parse as parseAstro } from "@astrojs/compiler/sync";
import { createScanner, LanguageVariant, SyntaxKind } from "typescript/unstable/ast";
import { isFile, isWithinRoot, normalizeRelative, readJson, readUtf8, resolveWithinRoot } from "./fs";
import type { TypeOnlyDependencyRange } from "./typescript-compiler";
import { WEB_CONDITION, type Condition, type Evidence, type Precision, type ResolutionStatus } from "./types";
import {
  selectPackageInstallCandidates,
  type LockInstance,
  type PackageRecord,
  type Workspace,
} from "./workspace";

const SCRIPT_EXTENSIONS = [".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs", ".astro", ".json"];

export interface RawDependency {
  kind: string;
  edgeKind: "imports" | "reexports" | "lazy_imports" | "side_effect_imports" | "depends_on";
  specifier: string;
  literal: boolean;
  typeOnly: boolean;
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
  basePath: string;
}

export interface ResolverIssue {
  path: string;
  reason: string;
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

interface Token {
  kind: SyntaxKind;
  text: string;
  value: string;
  start: number;
  end: number;
  unterminated: boolean;
  scannerError?: string;
}

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
    || left.kind.localeCompare(right.kind)
    || left.specifier.localeCompare(right.specifier)
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

function parseJsonc(source: string): Record<string, unknown> | null {
  let stripped = "";
  let inString = false;
  let escaped = false;
  for (let index = 0; index < source.length; index += 1) {
    const character = source[index]!;
    const next = source[index + 1];
    if (inString) {
      stripped += character;
      if (escaped) escaped = false;
      else if (character === "\\") escaped = true;
      else if (character === '"') inString = false;
    } else if (character === '"') {
      inString = true;
      stripped += character;
    } else if (character === "/" && next === "/") {
      stripped += "  ";
      index += 1;
      while (index + 1 < source.length && source[index + 1] !== "\n") {
        stripped += " ";
        index += 1;
      }
    } else if (character === "/" && next === "*") {
      stripped += "  ";
      index += 1;
      while (index + 1 < source.length && !(source[index] === "*" && source[index + 1] === "/")) {
        stripped += source[index] === "\n" ? "\n" : " ";
        index += 1;
      }
      stripped += " ";
    } else stripped += character;
  }
  try {
    const parsed: unknown = JSON.parse(stripped.replace(/,\s*([}\]])/gu, "$1"));
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
  conditions: string[];
}

function staticConditionalTargets(value: unknown, conditions: string[] = [], patternCapture?: string): ConditionalStringTarget[] {
  if (typeof value === "string") return [{ value: patternCapture === undefined ? value : value.replaceAll("*", patternCapture), conditions }];
  if (Array.isArray(value)) {
    return value.flatMap((child, index) => staticConditionalTargets(child, [...conditions, `fallback[${index}]`], patternCapture));
  }
  if (value !== null && typeof value === "object") {
    return Object.entries(value).flatMap(([condition, child]) => staticConditionalTargets(child, [...conditions, condition], patternCapture));
  }
  return [];
}

interface PackageEntrySelection {
  targets: ConditionalStringTarget[];
  exportsDefined: boolean;
  matched: boolean;
  reason: string | null;
}

function packageEntrySelection(manifest: Record<string, unknown>, subpath: string): PackageEntrySelection {
  const exportsDefined = Object.hasOwn(manifest, "exports");
  if (exportsDefined) {
    const exportsValue = manifest.exports;
    let selected: unknown;
    let matched = false;
    let capture: string | undefined;
    if (subpath === "." && (typeof exportsValue === "string" || Array.isArray(exportsValue) || exportsValue === null)) {
      selected = exportsValue;
      matched = true;
    } else if (exportsValue !== null && typeof exportsValue === "object" && !Array.isArray(exportsValue)) {
      const exportMap = exportsValue as Record<string, unknown>;
      const keys = Object.keys(exportMap);
      if (subpath === "." && !keys.some((key) => key.startsWith("."))) {
        selected = exportMap;
        matched = true;
      } else if (Object.hasOwn(exportMap, subpath)) {
        selected = exportMap[subpath];
        matched = true;
      } else {
        const pattern = keys
          .filter((key) => key.startsWith("./") && key.includes("*"))
          .map((key) => {
            const star = key.indexOf("*");
            const prefix = key.slice(0, star);
            const suffix = key.slice(star + 1);
            return subpath.startsWith(prefix) && subpath.endsWith(suffix)
              ? { key, prefix, suffix, capture: subpath.slice(prefix.length, subpath.length - suffix.length) }
              : null;
          })
          .filter((entry): entry is { key: string; prefix: string; suffix: string; capture: string } => entry !== null)
          .sort((left, right) => right.prefix.length - left.prefix.length || right.suffix.length - left.suffix.length || left.key.localeCompare(right.key))[0];
        if (pattern) {
          selected = exportMap[pattern.key];
          capture = pattern.capture;
          matched = true;
        }
      }
    }
    if (!matched) return { targets: [], exportsDefined: true, matched: false, reason: "package_subpath_not_exported" };
    const targets = staticConditionalTargets(selected, [], capture);
    return {
      targets,
      exportsDefined: true,
      matched: true,
      reason: targets.length === 0 ? "package_subpath_blocked_or_non_static" : null,
    };
  }

  const targets: ConditionalStringTarget[] = [];
  if (subpath !== ".") targets.push({ value: subpath.slice(2), conditions: [] });
  else {
    for (const field of ["module", "main", "types", "typings"] as const) {
      const value = manifest[field];
      if (typeof value === "string") targets.push({ value, conditions: [field] });
    }
    targets.push({ value: "index", conditions: ["default"] });
  }
  return { targets, exportsDefined: false, matched: true, reason: null };
}

function exportCondition(key: string): Condition {
  if (key === "browser") return { op: "eq", key: "environment", value: "browser" };
  if (key === "node" || key === "node-addons") return { op: "eq", key: "environment", value: "server" };
  if (key === "development" || key === "production") return { op: "eq", key: "mode", value: key };
  return { op: "eq", key: "package.exports.condition", value: key };
}

function conditionForTargets(targets: ConditionalStringTarget[]): Condition | undefined {
  const branches = targets
    .filter((target) => target.conditions.length > 0)
    .map((target): Condition => target.conditions.length === 1
      ? exportCondition(target.conditions[0]!)
      : { op: "all", conditions: target.conditions.map(exportCondition) });
  if (branches.length === 0) return undefined;
  const unique = [...new Map(branches.map((branch) => [JSON.stringify(branch), branch])).values()];
  const conditional: Condition = unique.length === 1 ? unique[0]! : { op: "any", conditions: unique };
  return { op: "all", conditions: [WEB_CONDITION, conditional] };
}

function fileBaseCandidates(base: string): string[] {
  const clean = base.replace(/[?#].*$/u, "");
  const candidates: string[] = [];
  const extension = path.extname(clean);
  if (extension) {
    candidates.push(clean);
    const runtimeToSource: Record<string, string[]> = {
      ".js": [".ts", ".tsx"],
      ".jsx": [".tsx", ".ts"],
      ".mjs": [".mts"],
      ".cjs": [".cts"],
    };
    for (const replacement of runtimeToSource[extension] ?? []) candidates.push(`${clean.slice(0, -extension.length)}${replacement}`);
  } else {
    candidates.push(clean);
    candidates.push(...SCRIPT_EXTENSIONS.map((item) => `${clean}${item}`));
    candidates.push(...SCRIPT_EXTENSIONS.map((item) => path.join(clean, `index${item}`)));
  }
  return [...new Set(candidates.map((item) => path.resolve(item)))];
}

interface ExternalPackageManifest {
  root: string;
  manifest: Record<string, unknown>;
  version: string;
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
  readonly #externalPackages = new Map<string, Promise<ExternalPackageManifest[]>>();
  readonly issues: ResolverIssue[] = [];

  private constructor(workspace: Workspace, allFiles: string[]) {
    this.#root = workspace.root;
    this.#workspace = workspace;
    this.#fileSet = new Set(allFiles.map((file) => path.resolve(file)));
  }

  static async create(workspace: Workspace, allFiles: string[]): Promise<ModuleResolver> {
    const resolver = new ModuleResolver(workspace, allFiles);
    for (const record of workspace.packages) await resolver.#loadAliases(record);
    return resolver;
  }

  async #loadAliases(record: PackageRecord): Promise<void> {
    for (const configName of ["tsconfig.json", "jsconfig.json"]) {
      const configPath = path.join(record.absolutePath, configName);
      if (!this.#fileSet.has(path.resolve(configPath))) continue;
      const chain = await this.#loadConfigChain(configPath, new Set());
      const ruleMap = new Map<string, AliasRule>();
      for (const { config, configPath: sourcePath } of chain) {
        const options = config.compilerOptions;
        if (options === null || typeof options !== "object" || Array.isArray(options)) continue;
        const typed = options as Record<string, unknown>;
        const baseUrl = typeof typed.baseUrl === "string" ? typed.baseUrl : ".";
        const paths = typed.paths;
        if (paths === null || typeof paths !== "object" || Array.isArray(paths)) continue;
        for (const [pattern, replacements] of Object.entries(paths)) {
          if (!Array.isArray(replacements) || !replacements.every((item) => typeof item === "string")) {
            this.issues.push({ path: normalizeRelative(path.relative(this.#root, sourcePath)), reason: `invalid path alias replacements for ${pattern}` });
            continue;
          }
          if (replacements.length > 0) ruleMap.set(pattern, { pattern, replacements, basePath: path.resolve(path.dirname(sourcePath), baseUrl) });
        }
      }
      const rules = [...ruleMap.values()].sort((left, right) => left.pattern.localeCompare(right.pattern));
      if (rules.length > 0) this.#aliasRules.set(record.id, rules.sort((left, right) => left.pattern.localeCompare(right.pattern)));
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
    const config = source === null ? null : parseJsonc(source);
    if (config === null) {
      this.issues.push({ path: relative, reason: "config is not valid static JSONC" });
      return [];
    }
    const parents: Array<{ configPath: string; config: Record<string, unknown> }> = [];
    const extended = typeof config.extends === "string"
      ? [config.extends]
      : Array.isArray(config.extends) ? config.extends.filter((item): item is string => typeof item === "string") : [];
    for (const parent of extended) {
      if (!parent.startsWith(".") && !path.isAbsolute(parent)) {
        this.issues.push({ path: relative, reason: `package-based config extends was not loaded in safe mode: ${parent}` });
        continue;
      }
      let parentPath = path.resolve(path.dirname(absolute), parent);
      if (path.extname(parentPath) === "") parentPath += ".json";
      parents.push(...await this.#loadConfigChain(parentPath, new Set(seen)));
    }
    parents.push({ configPath: absolute, config });
    return parents;
  }

  #resolveFileBase(base: string): string[] {
    return fileBaseCandidates(base)
      .filter((item) => isWithinRoot(this.#root, item) && this.#fileSet.has(item))
      .sort();
  }

  #resolveAlias(specifier: string, owner: PackageRecord): string[] | null {
    const results: string[] = [];
    let matched = false;
    for (const rule of this.#aliasRules.get(owner.id) ?? []) {
      const star = rule.pattern.indexOf("*");
      let capture = "";
      if (star < 0) {
        if (specifier !== rule.pattern) continue;
      } else {
        const prefix = rule.pattern.slice(0, star);
        const suffix = rule.pattern.slice(star + 1);
        if (!specifier.startsWith(prefix) || !specifier.endsWith(suffix)) continue;
        capture = specifier.slice(prefix.length, specifier.length - suffix.length);
      }
      matched = true;
      for (const replacement of rule.replacements) {
        results.push(...this.#resolveFileBase(path.resolve(rule.basePath, replacement.replace("*", capture))));
      }
    }
    return matched ? [...new Set(results)].sort() : null;
  }

  #workspacePackageTargets(specifier: string, record: PackageRecord): {
    targets: ResolvedTarget[];
    condition?: Condition;
    targetConditions?: Condition[];
    conditionNames: string[];
    reason: string | null;
  } {
    const subpath = subpathOf(specifier, record.name);
    const selection = packageEntrySelection(record.manifest, subpath);
    const conditionsByFile = new Map<string, ConditionalStringTarget[]>();
    for (const target of selection.targets) {
      if (selection.exportsDefined && !target.value.startsWith("./")) continue;
      for (const file of this.#resolveFileBase(path.resolve(record.absolutePath, target.value))) {
        if (!isWithinRoot(record.absolutePath, file)) continue;
        const conditions = conditionsByFile.get(file) ?? [];
        conditions.push(target);
        conditionsByFile.set(file, conditions);
      }
    }
    const files = [...conditionsByFile.keys()].sort();
    const resolvedDeclarations = [...conditionsByFile.values()].flat();
    const conditionNames = [...new Set(resolvedDeclarations.flatMap((target) => target.conditions))].sort();
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

  #resolveWorkspacePackages(specifier: string, workspaceMatches: PackageRecord[]): Resolution {
    const resolved = workspaceMatches.map((record) => this.#workspacePackageTargets(specifier, record));
    const targets = resolved.flatMap((entry) => entry.targets);
    if (targets.length === 0) {
      const reasons = [...new Set(resolved.map((entry) => entry.reason).filter((reason): reason is string => reason !== null))].sort();
      return {
        status: "unresolved",
        precision: "heuristic",
        targets: [],
        reason: reasons.join(",") || "workspace_package_target_not_found",
      };
    }
    const targetConditions = resolved.flatMap((entry) => entry.targetConditions ?? entry.targets.map(() => entry.condition ?? WEB_CONDITION));
    const conditions = resolved.map((entry) => entry.condition).filter((condition): condition is Condition => condition !== undefined);
    const conditionNames = [...new Set(resolved.flatMap((entry) => entry.conditionNames))].sort();
    const targetReasons = [...new Set(resolved.map((entry) => entry.reason).filter((reason): reason is string => reason !== null))].sort();
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
      ...(conditions.length === 1 ? { condition: conditions[0] } : conditions.length > 1 ? { condition: { op: "any", conditions } } : {}),
    };
  }

  async #loadExternalPackages(owner: PackageRecord, packageName: string): Promise<ExternalPackageManifest[]> {
    const key = `${owner.id}\0${packageName}`;
    const existing = this.#externalPackages.get(key);
    if (existing) return existing;
    const loading = (async (): Promise<ExternalPackageManifest[]> => {
      const records: ExternalPackageManifest[] = [];
      const seen = new Set<string>();
      let directory = owner.absolutePath;
      for (;;) {
        if (!isWithinRoot(this.#root, directory)) break;
        const manifestPath = path.join(directory, "node_modules", packageName, "package.json");
        const resolvedManifest = await resolveWithinRoot(this.#root, manifestPath);
        if (resolvedManifest !== null) {
          const manifest = await readJson(this.#root, resolvedManifest);
          const packageRoot = path.dirname(resolvedManifest);
          if (manifest !== null && !seen.has(packageRoot)) {
            seen.add(packageRoot);
            const locked = this.#workspace.lockInstances.get(packageName) ?? [];
            const declared = owner.dependencies.get(packageName)?.range ?? "unknown";
            const version = typeof manifest.version === "string" ? manifest.version : locked[0]?.version ?? declared;
            records.push({ root: packageRoot, manifest, version });
          }
        }
        if (directory === this.#root) break;
        const parent = path.dirname(directory);
        if (parent === directory) break;
        directory = parent;
      }
      return records.sort((left, right) => `${left.version}\0${left.root}`.localeCompare(`${right.version}\0${right.root}`));
    })();
    this.#externalPackages.set(key, loading);
    return loading;
  }

  async #externalPackageFiles(record: ExternalPackageManifest, subpath: string): Promise<PackageFileTargets> {
    const selection = packageEntrySelection(record.manifest, subpath);
    if (selection.reason !== null && selection.targets.length === 0) {
      return { files: [], targetDeclarations: [], conditionNames: [], reason: selection.reason };
    }
    const files = new Set<string>();
    const resolvedDeclarations: ConditionalStringTarget[] = [];
    for (const target of selection.targets) {
      if (selection.exportsDefined && !target.value.startsWith("./")) continue;
      const base = path.resolve(record.root, target.value);
      if (!isWithinRoot(record.root, base)) continue;
      let resolvedTarget = false;
      const candidates = selection.exportsDefined && path.extname(base) !== "" ? [base] : fileBaseCandidates(base);
      for (const candidate of candidates) {
        if (!isWithinRoot(record.root, candidate)) continue;
        const resolved = await resolveWithinRoot(this.#root, candidate);
        if (resolved === null || !isWithinRoot(record.root, resolved) || !(await isFile(this.#root, resolved))) continue;
        files.add(resolved);
        resolvedTarget = true;
      }
      if (resolvedTarget) resolvedDeclarations.push(target);
    }
    const condition = conditionForTargets(resolvedDeclarations);
    return {
      files: [...files].sort(),
      targetDeclarations: resolvedDeclarations,
      ...(condition ? { condition } : {}),
      conditionNames: [...new Set(resolvedDeclarations.flatMap((target) => target.conditions))].sort(),
      reason: files.size === 0
        ? selection.exportsDefined ? "package_export_target_not_found" : "package_legacy_target_not_found"
        : resolvedDeclarations.length < selection.targets.length ? "package_export_target_partially_unavailable" : null,
    };
  }

  async #resolveExternalPackage(
    specifier: string,
    packageName: string,
    owner: PackageRecord,
    selectedInstances: LockInstance[] | null = null,
  ): Promise<Resolution> {
    const installed = await this.#loadExternalPackages(owner, packageName);
    const subpath = subpathOf(specifier, packageName);
    const candidateInstances = selectedInstances ?? this.#workspace.lockInstances.get(packageName) ?? [];
    if (installed.length > 0) {
      const inspected = await Promise.all(installed.map(async (record) => ({ record, files: await this.#externalPackageFiles(record, subpath) })));
      const rangeFallback = selectedInstances?.length === 1
        && !/^v?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/u.test(selectedInstances[0]!.version);
      const relevant = inspected.filter((entry) => (
        candidateInstances.some((instance) => instance.version === entry.record.version) || rangeFallback
      ));
      const valid = relevant.filter((entry) => entry.files.files.length > 0);
      const byLocator = new Map<string, { target: ResolvedTarget; condition: Condition; reason: string | null; conditionNames: string[] }>();
      let rangeFallbackCovered = false;
      for (const entry of valid) {
        const locked = candidateInstances.filter((instance) => instance.version === entry.record.version);
        const instances = locked.length > 0
          ? locked
          : [{ version: entry.record.version, locator: `${this.#workspace.manager}:${packageName}@${entry.record.version}` }];
        if (locked.length === 0 && rangeFallback) rangeFallbackCovered = true;
        for (const instance of instances) {
          byLocator.set(instance.locator, {
            target: { kind: "external_package", name: packageName, version: instance.version, locator: instance.locator },
            condition: entry.files.condition ?? WEB_CONDITION,
            reason: entry.files.reason,
            conditionNames: entry.files.conditionNames,
          });
        }
      }
      const inspectedVersions = new Set(relevant.map((entry) => entry.record.version));
      for (const instance of candidateInstances) {
        if (byLocator.has(instance.locator) || rangeFallbackCovered || inspectedVersions.has(instance.version)) continue;
        byLocator.set(instance.locator, {
          target: { kind: "external_package", name: packageName, version: instance.version, locator: instance.locator },
          condition: WEB_CONDITION,
          reason: subpath === "." ? "external_package_files_unavailable" : "external_package_exports_unavailable",
          conditionNames: [],
        });
      }
      const resolutions = [...byLocator.values()].sort((left, right) => (
        (left.target.kind === "external_package" ? left.target.locator : "").localeCompare(right.target.kind === "external_package" ? right.target.locator : "")
      ));
      const inspectedReasons = relevant
        .filter((entry) => entry.files.files.length === 0)
        .map((entry) => entry.files.reason)
        .filter((reason): reason is string => reason !== null);
      if (resolutions.length === 0) {
        const reasons = [...new Set(inspectedReasons)].sort();
        return { status: "unresolved", precision: "heuristic", targets: [], reason: reasons.join(",") || "external_package_target_not_found" };
      }
      const conditionNames = [...new Set(resolutions.flatMap((entry) => entry.conditionNames))].sort();
      const partialReasons = [...new Set([
        ...resolutions.map((entry) => entry.reason),
        ...inspectedReasons,
      ].filter((reason): reason is string => reason !== null))].sort();
      const conditions = [...new Map(resolutions.map((entry) => [JSON.stringify(entry.condition), entry.condition])).values()];
      const hasMultipleCandidates = candidateInstances.length > 1 || resolutions.length > 1;
      return {
        status: hasMultipleCandidates ? "candidates" : "external",
        precision: hasMultipleCandidates ? "overapprox" : partialReasons.length === 0 ? "exact" : "heuristic",
        targets: resolutions.map((entry) => entry.target),
        targetConditions: resolutions.map((entry) => entry.condition),
        reason: partialReasons.length > 0
          ? partialReasons.join(",")
          : conditionNames.length > 0 ? `package_exports_conditions=${conditionNames.join(",")}` : hasMultipleCandidates ? "multiple_installed_package_instances" : null,
        ...(conditions.length === 1 ? { condition: conditions[0] } : conditions.length > 1 ? { condition: { op: "any", conditions } } : {}),
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

  async resolve(dependency: RawDependency, sourceFile: string, owner: PackageRecord): Promise<Resolution> {
    if (!dependency.literal) {
      return { status: "unresolved", precision: "heuristic", targets: [], reason: "computed_specifier" };
    }
    const specifier = dependency.specifier;
    if (specifier.startsWith(".") || specifier.startsWith("/")) {
      const base = specifier.startsWith("/") ? path.resolve(this.#root, `.${specifier}`) : path.resolve(path.dirname(sourceFile), specifier);
      const files = this.#resolveFileBase(base);
      if (files.length === 0) return { status: "unresolved", precision: "heuristic", targets: [], reason: "relative_target_not_found" };
      return {
        status: files.length === 1 ? "resolved" : "candidates",
        precision: files.length === 1 ? "exact" : "overapprox",
        targets: files.map((absolutePath) => ({ kind: "file", absolutePath })),
        reason: files.length === 1 ? null : "multiple_relative_targets",
      };
    }
    const aliases = this.#resolveAlias(specifier, owner);
    if (aliases !== null) {
      if (aliases.length === 0) return { status: "unresolved", precision: "heuristic", targets: [], reason: "path_alias_target_not_found" };
      return {
        status: aliases.length === 1 ? "resolved" : "candidates",
        precision: aliases.length === 1 ? "exact" : "overapprox",
        targets: aliases.map((absolutePath) => ({ kind: "file", absolutePath })),
        reason: aliases.length === 1 ? null : "multiple_path_alias_targets",
      };
    }
    if (specifier.startsWith("#")) {
      const imports = owner.manifest.imports;
      const values = imports !== null && typeof imports === "object" && !Array.isArray(imports)
        ? staticConditionalTargets((imports as Record<string, unknown>)[specifier])
        : [];
      const conditionsByFile = new Map<string, ConditionalStringTarget[]>();
      for (const value of values) {
        for (const file of this.#resolveFileBase(path.resolve(owner.absolutePath, value.value))) {
          const conditions = conditionsByFile.get(file) ?? [];
          conditions.push(value);
          conditionsByFile.set(file, conditions);
        }
      }
      const files = [...conditionsByFile.keys()].sort();
      const condition = conditionForTargets(values);
      if (files.length === 0) return { status: "unresolved", precision: "heuristic", targets: [], reason: "package_import_target_not_found" };
      return {
        status: files.length === 1 ? "resolved" : "candidates",
        precision: files.length === 1 ? "exact" : "overapprox",
        targets: files.map((absolutePath) => ({ kind: "file", absolutePath })),
        targetConditions: files.map((file) => conditionForTargets(conditionsByFile.get(file) ?? []) ?? WEB_CONDITION),
        reason: values.some((value) => value.conditions.length > 0)
          ? `package_import_conditions=${[...new Set(values.flatMap((value) => value.conditions))].sort().join(",")}`
          : files.length === 1 ? null : "multiple_package_import_targets",
        ...(condition ? { condition } : {}),
      };
    }
    const packageName = packageNameOf(specifier);
    const selection = selectPackageInstallCandidates(this.#workspace, owner, packageName);
    if (selection.workspacePackages.length === 0 && selection.externalInstances.length === 0) {
      return { status: "unresolved", precision: "heuristic", targets: [], reason: selection.reason ?? "package_target_not_found" };
    }
    const resolutions: Resolution[] = [];
    if (selection.workspacePackages.length > 0) {
      resolutions.push(this.#resolveWorkspacePackages(specifier, selection.workspacePackages));
    }
    if (selection.externalInstances.length > 0) {
      resolutions.push(await this.#resolveExternalPackage(specifier, packageName, owner, selection.externalInstances));
    }
    if (resolutions.length === 1) {
      const resolution = resolutions[0]!;
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
    ].filter((reason): reason is string => reason !== null))].sort();
    if (targets.length === 0) {
      return { status: "unresolved", precision: "heuristic", targets: [], reason: reasons.join(",") || "package_target_not_found" };
    }
    const targetConditions = resolutions.flatMap((resolution) => (
      resolution.targetConditions ?? resolution.targets.map(() => resolution.condition ?? WEB_CONDITION)
    ));
    const conditions = resolutions
      .map((resolution) => resolution.condition)
      .filter((condition): condition is Condition => condition !== undefined);
    return {
      status: "candidates",
      precision: "overapprox",
      targets,
      targetConditions,
      reason: reasons.join(",") || "workspace_and_external_package_candidates",
      ...(conditions.length === 1 ? { condition: conditions[0] } : conditions.length > 1 ? { condition: { op: "any", conditions } } : {}),
    };
  }
}

export function relativeImportPath(root: string, file: string): string {
  return normalizeRelative(path.relative(root, file));
}
