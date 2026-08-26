import path from "node:path";
import {
  type Checker,
  SymbolFlags,
  type Symbol as CompilerSymbol,
} from "typescript/unstable/async";
import {
  type CallExpression,
  type Expression,
  type Identifier,
  type ImportAttributes,
  type ImportDeclaration,
  type ImportEqualsDeclaration,
  type NewExpression,
  type Node,
  type SourceFile,
  SyntaxKind,
  type TaggedTemplateExpression,
} from "typescript/unstable/ast";
import type {
  TypeScriptRawDefinitionEndpoint,
  TypeScriptSemanticIssue,
} from "./typescript-semantic";
import type { Condition } from "./types";

export const MAX_AST_NODES = 1_000_000;
export const MAX_AST_DEPTH = 512;
export const MAX_SITES = 250_000;
export const MAX_MODULE_EXPORT_BINDINGS = 250_000;
export const MAX_EXPORTS_PER_MODULE = 4_096;
export const MAX_SYMBOL_DECLARATIONS = 4_096;
const MAX_TYPECHECKER_QUERIES = 1_000_000;
export const MAX_SPECIFIER_CHARS = 2_048;
export const MAX_CONDITION_DEPTH = 64;
export const MAX_CONDITION_NODES = 65_536;
export const MAX_CONDITION_VALUES = 4_096;
export const MAX_EXPORT_PATH_DEPTH = 64;

export const TYPESCRIPT_CLOSED_LOCAL_CALL_FLOW_ALGORITHM = "typescript-closed-local-call-flow-v1";
export const TYPESCRIPT_CLOSED_LOCAL_FRESH_INSTANCE_FLOW_ALGORITHM = "typescript-closed-local-fresh-instance-flow-v1";

export type TypeScriptRawDependencySiteKind = "web_import" | "web_reexport" | "type_use";
export type TypeScriptRawDependencyEdgeKind = "imports" | "reexports" | "type_uses";
export type TypeScriptRawDependencyStatus = "resolved" | "candidates" | "external" | "unresolved";
export type TypeScriptRawDependencyPrecision = "exact" | "overapprox" | "heuristic";
export type TypeScriptResolutionMode = "import" | "require";
export type TypeScriptBindingKind = "default" | "named" | "namespace" | "import_equals";
export type TypeScriptRawCallKind = "function" | "method" | "constructor" | "tagged_template";
export type TypeScriptRawCallDispatch =
  | "direct"
  | "static"
  | "private"
  | "fresh_instance"
  | "super"
  | "external"
  | "dynamic"
  | "open";

export type TypeScriptRawDependencyTarget =
  | { kind: "definition"; key: string }
  | { kind: "file"; relativePath: string }
  | { kind: "external"; locator: string; displayName: string }
  | { kind: "unknown" };

export type TypeScriptRawCallSource = Extract<TypeScriptRawDefinitionEndpoint, { kind: "definition" }>
  | { kind: "module_initializer"; relativePath: string };

export interface TypeScriptRawDependencyEvidence {
  relativePath: string;
  startOffset: number;
  endOffset: number;
  detail: string;
  occurrenceKind: string;
  targetBasis: "canonical_definition" | "repository_module" | "external_boundary" | "unresolved";
}

export interface TypeScriptRawDependencySite {
  key: string;
  kind: TypeScriptRawDependencySiteKind;
  edgeKind: TypeScriptRawDependencyEdgeKind;
  source: TypeScriptRawDefinitionEndpoint;
  specifier: string;
  moduleSpecifier: string | null;
  importedName: string | null;
  /** Canonical module export path used only for scanner-side proof correlation. */
  exportPath: string[] | null;
  /** Explicit TypeScript `resolution-mode`, if the occurrence declared one. */
  resolutionMode: TypeScriptResolutionMode | null;
  /** Internal source-span proof for an explicit resolution-mode attribute. */
  resolutionModeProof: {
    keyStartOffset: number;
    keyEndOffset: number;
    valueStartOffset: number;
    valueEndOffset: number;
  } | null;
  /** Internal provenance marker; never emitted as public protocol evidence. */
  bindingKind: TypeScriptBindingKind | null;
  /**
   * Internal import-binding correlation proof. The declaration span identifies
   * the canonical import site while the reference span identifies the
   * left-most alias used by this occurrence. Import-equals uses this proof to
   * retain its implicit `require` phase. It is never public protocol evidence.
   */
  bindingOrigin: {
    siteKey: string;
    declarationStartOffset: number;
    declarationEndOffset: number;
    scopeStartOffset: number;
    scopeEndOffset: number;
    referenceStartOffset: number;
    referenceEndOffset: number;
  } | null;
  /** Lexical SourceFile/ModuleBlock scope for a direct import binding site. */
  bindingScope: { startOffset: number; endOffset: number } | null;
  typeOnly: boolean;
  status: TypeScriptRawDependencyStatus;
  precision: TypeScriptRawDependencyPrecision;
  reason: string | null;
  condition: Condition;
  targets: TypeScriptRawDependencyTarget[];
  /** Per-target conditions, aligned with the canonical target order. */
  targetConditions: Condition[];
  evidence: TypeScriptRawDependencyEvidence;
}

export interface TypeScriptRawCallSite {
  key: string;
  source: TypeScriptRawCallSource;
  specifier: string;
  callKind: TypeScriptRawCallKind;
  dispatch: TypeScriptRawCallDispatch;
  moduleSpecifier: string | null;
  status: TypeScriptRawDependencyStatus;
  precision: TypeScriptRawDependencyPrecision;
  reason: string | null;
  /** Required for closed candidate calls; never emitted for exact/fallback calls. */
  algorithm: string | null;
  condition: Condition;
  targets: TypeScriptRawDependencyTarget[];
  targetConditions: Condition[];
  evidence: TypeScriptRawDependencyEvidence;
}

export interface TypeScriptRawDependencyDelta {
  sites: TypeScriptRawDependencySite[];
  calls: TypeScriptRawCallSite[];
  moduleExports: TypeScriptRawModuleExport[];
  issues: TypeScriptSemanticIssue[];
  typeCheckerQueries: number;
}

/** Internal TypeChecker proof used only to constrain scanner-side module resolution. */
export interface TypeScriptRawModuleExport {
  relativePath: string;
  /** Empty only for the canonical root assigned by `export =`. */
  exportPath: string[];
  definitionKeys: string[];
}

export interface QueryCounter { value: number; prior: number }

export interface ResolutionModeDirective {
  mode: TypeScriptResolutionMode | null;
  error: string | null;
  proof?: NonNullable<TypeScriptRawDependencySite["resolutionModeProof"]>;
}

export const NO_RESOLUTION_MODE: ResolutionModeDirective = Object.freeze({ mode: null, error: null });

export class DependencyContractError extends Error {}

export function compareStrings(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

export function hasUnpairedSurrogate(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return true;
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) return true;
  }
  return false;
}

export function isCanonicalRelativePath(value: string): boolean {
  return value.length > 0
    && !hasUnpairedSurrogate(value)
    && !value.startsWith("/")
    && !/^[A-Za-z]:/u.test(value)
    && !value.includes("\\")
    && !value.includes("\0")
    && !value.split("/").some((part) => part === "" || part === "." || part === "..");
}

export function compilerPathKey(value: string): string {
  const normalized = path.normalize(path.resolve(value));
  return process.platform === "win32" ? normalized.toLowerCase() : normalized;
}

export function nodeStart(node: Node, sourceFile: SourceFile): number {
  const value = node.getStart(sourceFile);
  if (!Number.isSafeInteger(value) || value < 0 || value > sourceFile.text.length) {
    throw new DependencyContractError("dependency AST start offset is outside its confined source");
  }
  return value;
}

export function nodeEnd(node: Node, sourceFile: SourceFile): number {
  const value = node.getEnd();
  if (!Number.isSafeInteger(value) || value < 0 || value > sourceFile.text.length) {
    throw new DependencyContractError("dependency AST end offset is outside its confined source");
  }
  return value;
}

export function nodeSpan(
  node: Node,
  sourceFile: SourceFile,
  allowEmpty = false,
): { startOffset: number; endOffset: number } {
  const startOffset = nodeStart(node, sourceFile);
  const endOffset = nodeEnd(node, sourceFile);
  if (endOffset < startOffset || (!allowEmpty && endOffset === startOffset)) {
    throw new DependencyContractError("dependency AST span is empty or reversed");
  }
  return { startOffset, endOffset };
}

export function bindingScopeSpan(binding: Node): { startOffset: number; endOffset: number } {
  const sourceFile = binding.getSourceFile();
  let scope: Node = sourceFile;
  for (let current = binding.parent; current !== undefined; current = current.parent) {
    if (current.kind === SyntaxKind.SourceFile || current.kind === SyntaxKind.ModuleBlock) {
      scope = current;
      break;
    }
  }
  return scope.kind === SyntaxKind.SourceFile
    ? { startOffset: 0, endOffset: sourceFile.text.length }
    : nodeSpan(scope, sourceFile, true);
}

export function childTraversalKey(node: Node, sourceFile: SourceFile): string {
  const { startOffset, endOffset } = nodeSpan(node, sourceFile, true);
  return `${node.kind}\0${startOffset}\0${endOffset}`;
}

export function beginQuery(counter: QueryCounter): void {
  if (counter.prior + counter.value >= MAX_TYPECHECKER_QUERIES) {
    throw new DependencyContractError("TypeChecker scan-wide query limit exceeded");
  }
  counter.value += 1;
}

export async function querySymbol(
  checker: Checker,
  node: Node,
  counter: QueryCounter,
  purpose: string,
  allowReferencedAliasBinding = false,
): Promise<CompilerSymbol | undefined> {
  beginQuery(counter);
  const batch = await checker.getSymbolAtLocation([node]);
  if (!Array.isArray(batch) || batch.length !== 1) {
    throw new DependencyContractError(`${purpose} symbol batch cardinality mismatch`);
  }
  beginQuery(counter);
  const singleton = await checker.getSymbolAtLocation(node);
  if (batch[0]?.id !== singleton?.id) {
    throw new DependencyContractError(`${purpose} symbol response correlation mismatch`);
  }
  const symbol = batch[0];
  if (symbol !== undefined && node.kind === SyntaxKind.Identifier) {
    const requested = (node as Identifier).text;
    if (symbol.name !== requested) {
      throw new DependencyContractError(`${purpose} symbol name did not match its requested identifier`);
    }
    const bindingParent = new Set([
      SyntaxKind.ImportSpecifier,
      SyntaxKind.ImportClause,
      SyntaxKind.NamespaceImport,
      SyntaxKind.ImportEqualsDeclaration,
      SyntaxKind.ExportSpecifier,
      SyntaxKind.NamespaceExport,
    ]).has(node.parent.kind);
    if ((symbol.flags & SymbolFlags.Alias) !== 0 && bindingParent && !allowReferencedAliasBinding) {
      const source = node.getSourceFile();
      const { startOffset: start, endOffset: end } = nodeSpan(node, source);
      let declaredAtRequest = false;
      for (const declaration of symbol.declarations.slice(0, MAX_SYMBOL_DECLARATIONS)) {
        if (compilerPathKey(String(declaration.path)) !== compilerPathKey(String(source.path))) continue;
        beginQuery(counter);
        const resolved = await declaration.resolve();
        if (resolved === undefined) continue;
        const { startOffset: resolvedStart, endOffset: resolvedEnd } = nodeSpan(resolved, source);
        if (resolvedStart <= start && resolvedEnd >= end) declaredAtRequest = true;
      }
      if (!declaredAtRequest) {
        throw new DependencyContractError(`${purpose} alias symbol did not declare its requested binding`);
      }
    }
  }
  return symbol;
}

export function terminalIdentifier(node: Node): Identifier | null {
  if (node.kind === SyntaxKind.Identifier) return node as Identifier;
  if (node.kind === SyntaxKind.QualifiedName) {
    return (node as Node & { readonly right: Identifier }).right;
  }
  if (node.kind === SyntaxKind.PropertyAccessExpression) {
    return (node as Node & { readonly name: Identifier }).name;
  }
  return null;
}

function bindingNameMatches(node: Node | undefined, name: string): boolean {
  if (node === undefined) return false;
  if (node.kind === SyntaxKind.Identifier) return (node as Identifier).text === name;
  if (node.kind !== SyntaxKind.ObjectBindingPattern && node.kind !== SyntaxKind.ArrayBindingPattern) return false;
  let matched = false;
  node.forEachChild((child) => {
    if (bindingNameMatches(child, name)) matched = true;
    return undefined;
  });
  return matched;
}

function directScopeDeclarationMatches(node: Node, name: string, valueNamespaceOnly: boolean): boolean {
  if (node.kind === SyntaxKind.ImportDeclaration) {
    if (!valueNamespaceOnly) return false;
    const clause = (node as ImportDeclaration).importClause;
    if (clause === undefined || clause.phaseModifier === SyntaxKind.TypeKeyword) return false;
    if (clause.name?.text === name) return true;
    if (clause.namedBindings?.kind === SyntaxKind.NamespaceImport) {
      return clause.namedBindings.name.text === name;
    }
    return clause.namedBindings?.kind === SyntaxKind.NamedImports
      && clause.namedBindings.elements.some((element) => !element.isTypeOnly && element.name.text === name);
  }
  if (node.kind === SyntaxKind.ImportEqualsDeclaration) {
    const declaration = node as ImportEqualsDeclaration;
    return valueNamespaceOnly && !declaration.isTypeOnly && declaration.name.text === name;
  }
  if (node.kind === SyntaxKind.VariableStatement) {
    const declarations = (node as Node & {
      readonly declarationList: { readonly declarations: readonly { readonly name: Node }[] };
    }).declarationList.declarations;
    return declarations.some((declaration) => bindingNameMatches(declaration.name, name));
  }
  const declarations = valueNamespaceOnly ? new Set([
    SyntaxKind.FunctionDeclaration,
    SyntaxKind.ClassDeclaration,
    SyntaxKind.EnumDeclaration,
    SyntaxKind.ModuleDeclaration,
  ]) : new Set([
    SyntaxKind.FunctionDeclaration,
    SyntaxKind.ClassDeclaration,
    SyntaxKind.InterfaceDeclaration,
    SyntaxKind.TypeAliasDeclaration,
    SyntaxKind.EnumDeclaration,
    SyntaxKind.ModuleDeclaration,
  ]);
  if (declarations.has(node.kind)) {
    return bindingNameMatches((node as Node & { readonly name?: Node }).name, name);
  }
  return false;
}

export function isLexicallyShadowedBinding(node: Node, name: string, valueNamespaceOnly = false): boolean {
  let current: Node | undefined = node.parent;
  for (let depth = 0; current !== undefined && depth < MAX_AST_DEPTH; depth += 1, current = current.parent) {
    if (
      (current.kind === SyntaxKind.FunctionExpression || current.kind === SyntaxKind.ClassExpression)
      && bindingNameMatches((current as Node & { readonly name?: Node }).name, name)
    ) return true;
    const parameters = (current as Node & {
      readonly typeParameters?: readonly { readonly name: Identifier }[];
    }).typeParameters;
    if (!valueNamespaceOnly && parameters?.some((parameter) => parameter.name.text === name)) return true;
    const valueParameters = (current as Node & {
      readonly parameters?: readonly { readonly name: Node }[];
    }).parameters;
    if (valueParameters?.some((parameter) => bindingNameMatches(parameter.name, name))) return true;
    if (
      current.kind === SyntaxKind.Block
      || current.kind === SyntaxKind.ModuleBlock
      || current.kind === SyntaxKind.SourceFile
    ) {
      let matched = false;
      current.forEachChild((child) => {
        if (directScopeDeclarationMatches(child, name, valueNamespaceOnly)) matched = true;
        return undefined;
      });
      if (matched) return true;
    }
    if (current.kind === SyntaxKind.CatchClause) {
      const declaration = (current as Node & {
        readonly variableDeclaration?: { readonly name: Node };
      }).variableDeclaration;
      if (bindingNameMatches(declaration?.name, name)) return true;
    }
  }
  return false;
}

export async function isAmbientRequireSymbol(symbol: CompilerSymbol, counter: QueryCounter): Promise<boolean> {
  if ((symbol.flags & SymbolFlags.Alias) !== 0) return false;
  if (symbol.declarations.length === 0) return false;
  if (symbol.declarations.length > MAX_SYMBOL_DECLARATIONS) {
    throw new DependencyContractError("require callee declaration limit exceeded");
  }
  let sawDeclaration = false;
  for (const declaration of symbol.declarations) {
    beginQuery(counter);
    const resolved = await declaration.resolve();
    if (resolved === undefined) return false;
    sawDeclaration = true;
    const modifiers = (resolved as Node & { readonly modifiers?: readonly Node[] }).modifiers ?? [];
    if (
      !resolved.getSourceFile().isDeclarationFile
      && !modifiers.some((modifier) => modifier.kind === SyntaxKind.DeclareKeyword)
    ) return false;
  }
  return sawDeclaration;
}

export function stringLiteralText(node: Node | undefined): string | null {
  if (node?.kind !== SyntaxKind.StringLiteral && node?.kind !== SyntaxKind.NoSubstitutionTemplateLiteral) {
    return null;
  }
  return (node as Node & { readonly text: string }).text;
}

function importAttributeName(node: Node): string | null {
  if (node.kind !== SyntaxKind.Identifier && node.kind !== SyntaxKind.StringLiteral) return null;
  return (node as Node & { readonly text: string }).text;
}

/**
 * Read only the standardized static `resolution-mode` attribute. The native
 * parser may recover duplicate or non-literal attributes, so those shapes are
 * kept as explicit unresolved occurrences instead of silently defaulting to
 * ESM resolution.
 */
export function resolutionModeDirective(
  attributes: ImportAttributes | undefined,
  exclusivelyTypeOnly = false,
): ResolutionModeDirective {
  if (attributes === undefined) return NO_RESOLUTION_MODE;
  const matches = attributes.attributes.filter((attribute) => importAttributeName(attribute.name) === "resolution-mode");
  if (matches.length === 0) {
    return exclusivelyTypeOnly
      ? { mode: null, error: "resolution_mode_attribute_required" }
      : NO_RESOLUTION_MODE;
  }
  if (matches.length !== 1) return { mode: null, error: "duplicate_resolution_mode" };
  if (attributes.attributes.length !== 1) return { mode: null, error: "resolution_mode_requires_single_attribute" };
  const match = matches[0]!;
  const value = stringLiteralText(match.value);
  const sourceFile = match.getSourceFile();
  const keySpan = nodeSpan(match.name, sourceFile);
  const valueSpan = nodeSpan(match.value, sourceFile);
  return value === "import" || value === "require"
    ? {
      mode: value,
      error: null,
      proof: {
        keyStartOffset: keySpan.startOffset,
        keyEndOffset: keySpan.endOffset,
        valueStartOffset: valueSpan.startOffset,
        valueEndOffset: valueSpan.endOffset,
      },
    }
    : { mode: null, error: "invalid_resolution_mode" };
}

export function resolutionModeForOccurrence(
  directive: ResolutionModeDirective,
  typeOnly: boolean,
): ResolutionModeDirective {
  return directive.mode !== null && !typeOnly
    ? { mode: null, error: "resolution_mode_requires_type_only" }
    : directive;
}

export function siteKey(
  source: TypeScriptRawDefinitionEndpoint | TypeScriptRawCallSource,
  kind: TypeScriptRawDependencySiteKind | "call",
  relativePath: string,
  startOffset: number,
  endOffset: number,
): string {
  return `site:${JSON.stringify([source, kind, relativePath, startOffset, endOffset])}`;
}

export function targetSortKey(target: TypeScriptRawDependencyTarget): string {
  switch (target.kind) {
    case "definition": return `definition:${target.key}`;
    case "file": return `file:${target.relativePath}`;
    case "external": return `external:${target.locator}:${target.displayName}`;
    case "unknown": return "unknown";
  }
}

export function basisForTargets(
  targets: readonly TypeScriptRawDependencyTarget[],
): TypeScriptRawDependencyEvidence["targetBasis"] {
  if (targets.some((target) => target.kind === "definition")) return "canonical_definition";
  if (targets.some((target) => target.kind === "file")) return "repository_module";
  if (targets.some((target) => target.kind === "external")) return "external_boundary";
  return "unresolved";
}

export function transparentCallExpression(expression: Expression): Expression {
  let current = expression;
  for (let depth = 0; depth < MAX_AST_DEPTH; depth += 1) {
    if (![
      SyntaxKind.ParenthesizedExpression,
      SyntaxKind.NonNullExpression,
      SyntaxKind.AsExpression,
      SyntaxKind.TypeAssertionExpression,
      SyntaxKind.SatisfiesExpression,
    ].includes(current.kind)) return current;
    current = (current as Expression & { readonly expression: Expression }).expression;
  }
  throw new DependencyContractError("call callee wrapper depth limit exceeded");
}

export function callCallee(node: CallExpression | NewExpression | TaggedTemplateExpression): Expression {
  return node.kind === SyntaxKind.TaggedTemplateExpression
    ? (node as TaggedTemplateExpression).tag
    : (node as CallExpression | NewExpression).expression;
}

export function callOccurrenceKind(node: CallExpression | NewExpression | TaggedTemplateExpression): string {
  switch (node.kind) {
    case SyntaxKind.CallExpression: return "call_expression";
    case SyntaxKind.NewExpression: return "new_expression";
    case SyntaxKind.TaggedTemplateExpression: return "tagged_template";
    default: throw new DependencyContractError("unsupported call-like occurrence");
  }
}

export function callSpecifier(
  node: CallExpression | NewExpression | TaggedTemplateExpression,
  sourceFile: SourceFile,
): string {
  const text = callCallee(node).getText(sourceFile);
  return (text.length === 0 ? "<call>" : text).slice(0, MAX_SPECIFIER_CHARS);
}

export async function isModuleLoaderCall(
  node: CallExpression,
  checker: Checker,
  counter: QueryCounter,
): Promise<boolean> {
  if (node.expression.kind === SyntaxKind.ImportKeyword) return true;
  if (
    node.expression.kind !== SyntaxKind.Identifier
    || (node.expression as Identifier).text !== "require"
    || isLexicallyShadowedBinding(node.expression, "require", true)
  ) return false;
  const symbol = await querySymbol(checker, node.expression, counter, "call-graph require callee");
  return symbol === undefined || await isAmbientRequireSymbol(symbol, counter);
}
