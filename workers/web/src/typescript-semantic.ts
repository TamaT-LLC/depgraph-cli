import path from "node:path";
import {
  ModifierFlags,
  SymbolFlags,
  TypeFlags,
  type Checker,
  type Symbol as CompilerSymbol,
  type Type as CompilerType,
} from "typescript/unstable/async";
import {
  SyntaxKind,
  isTypeNode,
  type ClassDeclaration,
  type EnumDeclaration,
  type ExpressionWithTypeArguments,
  type FunctionDeclaration,
  type FunctionExpression,
  type InterfaceDeclaration,
  type MethodDeclaration,
  type MethodSignatureDeclaration,
  type ModuleDeclaration,
  type Node,
  type PropertyName,
  type SourceFile,
  type TypeAliasDeclaration,
  type TypeNode,
  type TypeParameterDeclaration,
  type VariableDeclaration,
} from "typescript/unstable/ast";

export const TYPESCRIPT_SEMANTIC_MAX_SOURCE_FILES = 50_000;
const MAX_AST_NODES = 1_000_000;
const MAX_DEFINITION_CANDIDATES = 100_000;
const MAX_RELATIONS = 250_000;
const MAX_TYPE_ARGUMENTS = 64;
const MAX_TYPE_ARGUMENT_DESCRIPTOR_CHARS = 2_048;
const MAX_DISPLAY_NAME_CHARS = 512;
const MAX_RESOLVER_IDENTITY_CHARS = 4_096;
const MAX_ISSUES = 1_000;
const MAX_AST_DEPTH = 512;
const MAX_TYPE_DESCRIPTOR_DEPTH = 64;
const MAX_TYPE_DESCRIPTOR_MEMBERS = 256;
const MAX_TYPE_DESCRIPTOR_NODES = MAX_TYPE_ARGUMENT_DESCRIPTOR_CHARS;
const MAX_SYMBOL_DECLARATIONS = 4_096;
const MAX_TYPECHECKER_QUERIES = 1_000_000;

export type TypeScriptSemanticLanguage = "typescript" | "javascript";
export type TypeScriptRawGraphKind = "symbol" | "type";
export type TypeScriptRawSymbolIdentityKind = "named" | "local" | "anonymous";
export type TypeScriptRawDefinitionRelationKind = "declares" | "extends" | "implements" | "instantiates";

export type TypeScriptRawTypeArgumentDescriptor =
  | { kind: "intrinsic"; name: string }
  | { kind: "literal"; valueKind: "string" | "number" | "boolean" | "bigint"; value: string }
  | { kind: "definition"; key: string }
  | { kind: "type_parameter"; owner: string; index: number; name: string }
  | {
    kind: "application";
    target: TypeScriptRawTypeArgumentDescriptor;
    typeArguments: TypeScriptRawTypeArgumentDescriptor[];
  }
  | { kind: "union" | "intersection"; members: TypeScriptRawTypeArgumentDescriptor[] };

const TYPE_SEMANTIC_KINDS: ReadonlySet<string> = new Set([
  "class",
  "enum",
  "generic_instance",
  "interface",
  "type_alias",
]);
const SYMBOL_SEMANTIC_IDENTITIES = new Map<string, TypeScriptRawSymbolIdentityKind>([
  ["anonymous_function", "anonymous"],
  ["constructor", "named"],
  ["function", "named"],
  ["function_variable", "named"],
  ["local_function", "local"],
  ["local_function_variable", "local"],
  ["method", "named"],
  ["variable", "named"],
]);
const RELATION_KINDS = new Set<TypeScriptRawDefinitionRelationKind>([
  "declares",
  "extends",
  "implements",
  "instantiates",
]);

/** A confined source file whose AST belongs to the active compiler snapshot. */
export interface TypeScriptSemanticSource {
  relativePath: string;
  /** Absolute, worker-owned VFS path requested from Program.getSourceFile. */
  compilerPath: string;
  /** Exact inventory bytes used to create the worker-owned VFS entry. */
  expectedText: string;
  sourceFile: SourceFile;
  syntacticallyValid: boolean;
}

/** A raw owner reference. Scanner-side code replaces these with graph node IDs. */
export type TypeScriptRawDefinitionEndpoint =
  | { kind: "file"; relativePath: string }
  | { kind: "definition"; key: string };

/**
 * A compiler-confirmed definition without a protocol ID or package locator.
 * `key` is stable only within this raw contract and never contains native
 * Symbol, Type, or NodeHandle identifiers.
 */
export interface TypeScriptRawDefinition {
  key: string;
  graphKind: TypeScriptRawGraphKind;
  semanticKind: string;
  language: TypeScriptSemanticLanguage;
  resolverIdentity: string | null;
  identityKind: TypeScriptRawSymbolIdentityKind | null;
  displayName: string;
  relativePath: string;
  startOffset: number;
  endOffset: number;
  owner: TypeScriptRawDefinitionEndpoint;
  /** Present only when module-scope syntax directly exports this definition. */
  exported?: true;
  genericOrigin?: string;
  typeArguments?: TypeScriptRawTypeArgumentDescriptor[];
}

export interface TypeScriptRawDefinitionEvidence {
  relativePath: string;
  startOffset: number;
  endOffset: number;
  detail: string;
}

export interface TypeScriptRawDefinitionRelation {
  kind: TypeScriptRawDefinitionRelationKind;
  source: TypeScriptRawDefinitionEndpoint;
  target: string;
  evidence: TypeScriptRawDefinitionEvidence;
}

export interface TypeScriptSemanticIssue {
  code: string;
  message: string;
  relativePath: string | null;
  fatal: boolean;
}

export interface TypeScriptRawDefinitionDelta {
  definitions: TypeScriptRawDefinition[];
  relations: TypeScriptRawDefinitionRelation[];
  issues: TypeScriptSemanticIssue[];
  /** Number of async TypeChecker/remote-object method invocations. */
  typeCheckerQueries: number;
}

interface Candidate {
  readonly index: number;
  readonly node: Node;
  readonly source: TypeScriptSemanticSource;
  readonly graphKind: TypeScriptRawGraphKind;
  readonly initialSemanticKind: string;
  readonly displayName: string;
  readonly nameNode: Node | null;
  readonly owner: Candidate | null;
  readonly lexicalPath: readonly string[];
  readonly moduleScoped: boolean;
  readonly exported: boolean;
  readonly startOffset: number;
  readonly endOffset: number;
  readonly depth: number;
  symbol: CompilerSymbol | null;
  type: CompilerType | null;
  resolverIdentity: string | null;
  identityKind: TypeScriptRawSymbolIdentityKind | null;
  semanticKind: string;
}

interface CandidateGroup {
  readonly ephemeralKey: string;
  readonly candidates: Candidate[];
  readonly primary: Candidate;
  readonly symbol: CompilerSymbol | null;
  readonly graphKind: TypeScriptRawGraphKind;
  readonly semanticKind: string;
  readonly identityKind: TypeScriptRawSymbolIdentityKind | null;
  readonly resolverIdentity: string | null;
  readonly key: string;
  skipped: boolean;
}

interface HeritageCandidate {
  readonly owner: Candidate;
  readonly node: ExpressionWithTypeArguments;
  readonly relationKind: "extends" | "implements";
  targetSymbol: CompilerSymbol | null;
}

interface TypeParameterCandidate {
  readonly owner: Candidate;
  readonly node: TypeParameterDeclaration;
  readonly index: number;
  symbol: CompilerSymbol | null;
}

interface Collection {
  readonly candidates: Candidate[];
  readonly heritage: HeritageCandidate[];
  readonly typeParameters: TypeParameterCandidate[];
  astNodes: number;
  limitIssue: TypeScriptSemanticIssue | null;
}

interface IssueCollector {
  issues: TypeScriptSemanticIssue[];
  truncated: boolean;
}

interface QueryCounter {
  value: number;
}

interface SymbolDefinitionIndex {
  readonly byId: ReadonlyMap<string, CandidateGroup>;
  readonly byDeclaration: ReadonlyMap<string, CandidateGroup>;
}

interface TypeDescriptorBudget {
  nodes: number;
}

class DeltaValidationError extends Error {}
class TypeCheckerContractError extends Error {
  readonly typeCheckerQueries: number;

  constructor(message: string, typeCheckerQueries: number) {
    super(message);
    this.typeCheckerQueries = typeCheckerQueries;
  }
}

function beginTypeCheckerQuery(counter: QueryCounter): void {
  if (counter.value >= MAX_TYPECHECKER_QUERIES) {
    throw new TypeCheckerContractError(
      `TypeChecker semantic query limit ${MAX_TYPECHECKER_QUERIES} exceeded`,
      counter.value,
    );
  }
  counter.value += 1;
}

function languageForPath(relativePath: string): TypeScriptSemanticLanguage {
  return /\.(?:js|jsx|mjs|cjs)$/iu.test(relativePath) ? "javascript" : "typescript";
}

function compareStrings(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function isCanonicalRelativePath(value: string): boolean {
  return value.length > 0
    && !hasUnpairedSurrogate(value)
    && !value.startsWith("/")
    && !/^[A-Za-z]:/u.test(value)
    && !value.includes("\\")
    && !value.includes("\0")
    && !value.split("/").some((part) => part === "" || part === "." || part === "..");
}

function hasUnpairedSurrogate(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return true;
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      return true;
    }
  }
  return false;
}

function wellFormedDiagnosticText(value: string): string {
  if (!hasUnpairedSurrogate(value)) return value;
  let result = "";
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (next >= 0xdc00 && next <= 0xdfff) {
        result += value[index]! + value[index + 1]!;
        index += 1;
      } else {
        result += "�";
      }
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      result += "�";
    } else {
      result += value[index]!;
    }
  }
  return result;
}

function compilerPathKey(value: string): string {
  const normalized = path.normalize(path.resolve(value));
  return process.platform === "win32" ? normalized.toLowerCase() : normalized;
}

function compilerInternalPathKey(value: string): string {
  return compilerPathKey(value).toLowerCase();
}

function sourceMatchesInventory(source: TypeScriptSemanticSource): boolean {
  try {
    const expectedPath = compilerPathKey(source.compilerPath);
    return path.isAbsolute(source.compilerPath)
      && compilerInternalPathKey(String(source.sourceFile.path)) === expectedPath.toLowerCase()
      && compilerPathKey(source.sourceFile.fileName) === expectedPath
      && source.sourceFile.text === source.expectedText;
  } catch {
    return false;
  }
}

function addIssue(
  collector: IssueCollector,
  issue: TypeScriptSemanticIssue,
): void {
  if (collector.issues.length < MAX_ISSUES) {
    collector.issues.push(issue);
    return;
  }
  collector.truncated = true;
  if (issue.fatal) {
    const replace = collector.issues.findLastIndex((existing) => !existing.fatal);
    if (replace >= 0) collector.issues[replace] = issue;
  }
}

function issue(
  code: string,
  message: string,
  relativePath: string | null,
  fatal = false,
): TypeScriptSemanticIssue {
  return {
    code,
    message: wellFormedDiagnosticText(message),
    relativePath: relativePath === null || !hasUnpairedSurrogate(relativePath) ? relativePath : null,
    fatal,
  };
}

function nodeStart(node: Node, sourceFile: SourceFile): number {
  return Math.max(0, Math.min(sourceFile.text.length, node.getStart(sourceFile)));
}

function nodeEnd(node: Node, sourceFile: SourceFile): number {
  return Math.max(0, Math.min(sourceFile.text.length, node.getEnd()));
}

function propertyName(node: PropertyName): string | null {
  switch (node.kind) {
    case SyntaxKind.Identifier:
    case SyntaxKind.PrivateIdentifier:
    case SyntaxKind.StringLiteral:
    case SyntaxKind.NoSubstitutionTemplateLiteral:
    case SyntaxKind.NumericLiteral:
    case SyntaxKind.BigIntLiteral:
      return (node as { readonly text: string }).text;
    case SyntaxKind.ComputedPropertyName:
      return null;
    default:
      return null;
  }
}

function moduleName(node: ModuleDeclaration): string | null {
  return propertyName(node.name);
}

function typeParametersOf(node: Node): readonly TypeParameterDeclaration[] {
  return (node as Node & { readonly typeParameters?: readonly TypeParameterDeclaration[] }).typeParameters ?? [];
}

function hasExportModifier(node: Node): boolean {
  const modifierFlags = (node as Node & { readonly modifierFlags?: ModifierFlags }).modifierFlags
    ?? ModifierFlags.None;
  return (modifierFlags & (ModifierFlags.Export | ModifierFlags.Default)) !== 0;
}

function isDirectModuleExport(
  node: Node,
  moduleScoped: boolean,
  lexicalPath: readonly string[],
): boolean {
  if (!moduleScoped) return false;
  if (lexicalPath.length > 0) return false;
  const declaration = node.kind === SyntaxKind.VariableDeclaration ? node.parent.parent : node;
  return hasExportModifier(declaration);
}

function declarationCandidate(
  node: Node,
  source: TypeScriptSemanticSource,
  owner: Candidate | null,
  lexicalPath: readonly string[],
  moduleScoped: boolean,
  index: number,
  issues: IssueCollector,
): Candidate | null {
  const sourceFile = source.sourceFile;
  const common = {
    index,
    node,
    source,
    owner,
    lexicalPath,
    moduleScoped,
    exported: isDirectModuleExport(node, moduleScoped, lexicalPath),
    startOffset: nodeStart(node, sourceFile),
    endOffset: nodeEnd(node, sourceFile),
    depth: owner === null ? 0 : owner.depth + 1,
    symbol: null,
    type: null,
    resolverIdentity: null,
    identityKind: null,
  } as const;

  switch (node.kind) {
    case SyntaxKind.ClassDeclaration: {
      const declaration = node as ClassDeclaration;
      const name = declaration.name?.text
        ?? ((declaration.modifierFlags & ModifierFlags.Default) !== 0 ? "default" : null);
      if (name === null) {
        addIssue(issues, issue(
          "typescript_semantic_anonymous_class_skipped",
          "An anonymous non-default class declaration has no canonical definition identity",
          source.relativePath,
        ));
        return null;
      }
      return {
        ...common,
        graphKind: "type",
        initialSemanticKind: "class",
        semanticKind: "class",
        displayName: name,
        nameNode: declaration.name ?? null,
      };
    }
    case SyntaxKind.InterfaceDeclaration: {
      const declaration = node as InterfaceDeclaration;
      return {
        ...common,
        graphKind: "type",
        initialSemanticKind: "interface",
        semanticKind: "interface",
        displayName: declaration.name.text,
        nameNode: declaration.name,
      };
    }
    case SyntaxKind.TypeAliasDeclaration: {
      const declaration = node as TypeAliasDeclaration;
      return {
        ...common,
        graphKind: "type",
        initialSemanticKind: "type_alias",
        semanticKind: "type_alias",
        displayName: declaration.name.text,
        nameNode: declaration.name,
      };
    }
    case SyntaxKind.EnumDeclaration: {
      const declaration = node as EnumDeclaration;
      return {
        ...common,
        graphKind: "type",
        initialSemanticKind: "enum",
        semanticKind: "enum",
        displayName: declaration.name.text,
        nameNode: declaration.name,
      };
    }
    case SyntaxKind.FunctionDeclaration: {
      const declaration = node as FunctionDeclaration;
      const displayName = declaration.name?.text
        ?? ((declaration.modifierFlags & ModifierFlags.Default) !== 0 ? "default" : "anonymous function");
      return {
        ...common,
        graphKind: "symbol",
        initialSemanticKind: "function",
        semanticKind: "function",
        displayName,
        nameNode: declaration.name ?? null,
      };
    }
    case SyntaxKind.MethodDeclaration: {
      const declaration = node as MethodDeclaration;
      const name = propertyName(declaration.name);
      if (name === null) {
        addIssue(issues, issue(
          "typescript_semantic_computed_member_skipped",
          "A computed method name could not be canonicalized without evaluating project code",
          source.relativePath,
        ));
        return null;
      }
      return {
        ...common,
        graphKind: "symbol",
        initialSemanticKind: "method",
        semanticKind: "method",
        displayName: name,
        nameNode: declaration.name,
      };
    }
    case SyntaxKind.MethodSignature: {
      const declaration = node as MethodSignatureDeclaration;
      const name = propertyName(declaration.name);
      if (name === null) {
        addIssue(issues, issue(
          "typescript_semantic_computed_member_skipped",
          "A computed method signature name could not be canonicalized without evaluating project code",
          source.relativePath,
        ));
        return null;
      }
      return {
        ...common,
        graphKind: "symbol",
        initialSemanticKind: "method",
        semanticKind: "method",
        displayName: name,
        nameNode: declaration.name,
      };
    }
    case SyntaxKind.Constructor:
      return {
        ...common,
        graphKind: "symbol",
        initialSemanticKind: "constructor",
        semanticKind: "constructor",
        displayName: "constructor",
        nameNode: null,
      };
    case SyntaxKind.VariableDeclaration: {
      const declaration = node as VariableDeclaration;
      if (declaration.name.kind !== SyntaxKind.Identifier) return null;
      const callable = declaration.initializer?.kind === SyntaxKind.ArrowFunction
        || declaration.initializer?.kind === SyntaxKind.FunctionExpression;
      // Ordinary variables are promoted only at module scope. This gives an
      // imported/re-exported value a canonical endpoint without turning every
      // block-local temporary into a graph node. Callable variables retain the
      // more specific function identity at either module or local scope.
      if (!callable && !moduleScoped) return null;
      return {
        ...common,
        graphKind: "symbol",
        initialSemanticKind: callable ? "function_variable" : "variable",
        semanticKind: callable ? "function_variable" : "variable",
        displayName: declaration.name.text,
        nameNode: declaration.name,
      };
    }
    case SyntaxKind.ArrowFunction:
      return {
        ...common,
        graphKind: "symbol",
        initialSemanticKind: "anonymous_function",
        semanticKind: "anonymous_function",
        displayName: "anonymous function",
        nameNode: null,
      };
    case SyntaxKind.FunctionExpression: {
      const expression = node as FunctionExpression;
      return {
        ...common,
        graphKind: "symbol",
        initialSemanticKind: expression.name === undefined ? "anonymous_function" : "local_function",
        semanticKind: expression.name === undefined ? "anonymous_function" : "local_function",
        displayName: expression.name?.text ?? "anonymous function",
        nameNode: expression.name ?? null,
      };
    }
    default:
      return null;
  }
}

function hasCanonicalMemberOwner(node: Node, owner: Candidate | null): owner is Candidate {
  if (owner?.graphKind !== "type") return false;
  if (owner.node === node.parent) return true;
  return node.kind === SyntaxKind.MethodSignature
    && owner.node.kind === SyntaxKind.TypeAliasDeclaration
    && (owner.node as TypeAliasDeclaration).type === node.parent;
}

function collectSources(
  sources: readonly TypeScriptSemanticSource[],
  issues: IssueCollector,
): Collection {
  const collection: Collection = {
    candidates: [],
    heritage: [],
    typeParameters: [],
    astNodes: 0,
    limitIssue: null,
  };
  if (sources.length > TYPESCRIPT_SEMANTIC_MAX_SOURCE_FILES) {
    collection.limitIssue = issue(
      "typescript_semantic_source_limit_exceeded",
      `TypeScript semantic definition extraction received ${sources.length} sources; limit=${TYPESCRIPT_SEMANTIC_MAX_SOURCE_FILES}`,
      null,
      true,
    );
    return collection;
  }

  const visit = (
    node: Node,
    source: TypeScriptSemanticSource,
    owner: Candidate | null,
    lexicalPath: readonly string[],
    moduleScoped: boolean,
    astDepth: number,
  ): void => {
    if (collection.limitIssue !== null) return;
    if (astDepth > MAX_AST_DEPTH) {
      collection.limitIssue = issue(
        "typescript_semantic_ast_depth_exceeded",
        `TypeScript semantic definition extraction exceeded AST depth ${MAX_AST_DEPTH}`,
        source.relativePath,
        true,
      );
      return;
    }
    collection.astNodes += 1;
    if (collection.astNodes > MAX_AST_NODES) {
      collection.limitIssue = issue(
        "typescript_semantic_ast_limit_exceeded",
        `TypeScript semantic definition extraction exceeded ${MAX_AST_NODES} AST nodes`,
        source.relativePath,
        true,
      );
      return;
    }

    // Members can only inherit a semantic owner when it represents their
    // actual syntax container. A direct type-literal body is also the public
    // member surface of its type alias. Other object/class/type literals do
    // not have definition candidates, so inheriting an outer type would
    // fabricate that outer type's member identity and can collide with a real
    // member.
    const candidateOwner = (
      node.kind === SyntaxKind.MethodDeclaration
      || node.kind === SyntaxKind.Constructor
      || node.kind === SyntaxKind.MethodSignature
    ) && !hasCanonicalMemberOwner(node, owner)
      ? null
      : owner;
    const candidate = declarationCandidate(
      node,
      source,
      candidateOwner,
      lexicalPath,
      moduleScoped,
      collection.candidates.length,
      issues,
    );
    let childOwner = owner;
    if (candidate !== null) {
      collection.candidates.push(candidate);
      if (candidate.initialSemanticKind !== "variable") childOwner = candidate;
      if (collection.candidates.length > MAX_DEFINITION_CANDIDATES) {
        collection.limitIssue = issue(
          "typescript_semantic_definition_limit_exceeded",
          `TypeScript semantic definition extraction exceeded ${MAX_DEFINITION_CANDIDATES} candidates`,
          source.relativePath,
          true,
        );
        return;
      }
      for (const [parameterIndex, parameter] of typeParametersOf(node).entries()) {
        collection.typeParameters.push({ owner: candidate, node: parameter, index: parameterIndex, symbol: null });
      }
      if (candidate.graphKind === "type") {
        const clauses = (node as ClassDeclaration | InterfaceDeclaration).heritageClauses ?? [];
        for (const clause of clauses) {
          const relationKind = clause.token === SyntaxKind.ImplementsKeyword ? "implements" : "extends";
          for (const heritageType of clause.types) {
            collection.heritage.push({ owner: candidate, node: heritageType, relationKind, targetSymbol: null });
          }
        }
      }
    }

    let childLexicalPath = lexicalPath;
    if (node.kind === SyntaxKind.ModuleDeclaration) {
      const name = moduleName(node as ModuleDeclaration);
      if (name !== null) childLexicalPath = [...lexicalPath, name];
    }
    const childModuleScoped = moduleScoped && (
      node.kind === SyntaxKind.SourceFile
      || node.kind === SyntaxKind.ModuleDeclaration
      || node.kind === SyntaxKind.ModuleBlock
      || node.kind === SyntaxKind.VariableStatement
      || node.kind === SyntaxKind.VariableDeclarationList
    );
    // A computed method that could not be represented must not leak nested
    // definitions with the containing class as a fabricated direct owner.
    if (candidate !== null || node.kind !== SyntaxKind.MethodDeclaration) {
      node.forEachChild((child) => {
        visit(child, source, childOwner, childLexicalPath, childModuleScoped, astDepth + 1);
        return undefined;
      });
    }
  };

  const seenPaths = new Set<string>();
  for (const source of [...sources].sort((left, right) => compareStrings(left.relativePath, right.relativePath))) {
    if (!isCanonicalRelativePath(source.relativePath)) {
      collection.limitIssue = issue(
        "typescript_semantic_unsafe_source_path",
        `TypeScript semantic source path is not canonical: ${source.relativePath}`,
        null,
        true,
      );
      break;
    }
    if (!seenPaths.add(source.relativePath)) {
      collection.limitIssue = issue(
        "typescript_semantic_duplicate_source_path",
        `TypeScript semantic source path was provided more than once: ${source.relativePath}`,
        source.relativePath,
        true,
      );
      break;
    }
    if (!sourceMatchesInventory(source)) {
      collection.limitIssue = issue(
        "typescript_semantic_source_identity_mismatch",
        "TypeScript semantic AST path or text did not match the confined source inventory",
        source.relativePath,
        true,
      );
      break;
    }
    if (!source.syntacticallyValid) {
      addIssue(issues, issue(
        "typescript_semantic_syntax_invalid",
        "Semantic definitions were not promoted from a source with syntactic diagnostics",
        source.relativePath,
      ));
      continue;
    }
    visit(source.sourceFile, source, null, [], true, 0);
    if (collection.limitIssue !== null) break;
  }
  return collection;
}

async function querySymbols(
  checker: Checker,
  nodes: readonly Node[],
  counter: QueryCounter,
  purpose: string,
): Promise<(CompilerSymbol | undefined)[]> {
  const result: (CompilerSymbol | undefined)[] = [];
  for (const node of nodes) {
    beginTypeCheckerQuery(counter);
    const batch = await checker.getSymbolAtLocation([node]);
    if (!Array.isArray(batch) || batch.length !== 1) {
      throw new TypeCheckerContractError(`${purpose} symbol batch cardinality mismatch`, counter.value);
    }
    beginTypeCheckerQuery(counter);
    const singleton = await checker.getSymbolAtLocation(node);
    if (batch[0]?.id !== singleton?.id) {
      throw new TypeCheckerContractError(`${purpose} symbol request correlation mismatch`, counter.value);
    }
    result.push(batch[0]);
  }
  return result;
}

async function queryTypes(
  checker: Checker,
  nodes: readonly Node[],
  counter: QueryCounter,
  purpose: string,
): Promise<(CompilerType | undefined)[]> {
  const result: (CompilerType | undefined)[] = [];
  for (const node of nodes) {
    beginTypeCheckerQuery(counter);
    const batch = await checker.getTypeAtLocation([node]);
    if (!Array.isArray(batch) || batch.length !== 1) {
      throw new TypeCheckerContractError(`${purpose} type batch cardinality mismatch`, counter.value);
    }
    beginTypeCheckerQuery(counter);
    const singleton = await checker.getTypeAtLocation(node);
    if (batch[0]?.id !== singleton?.id) {
      throw new TypeCheckerContractError(`${purpose} type request correlation mismatch`, counter.value);
    }
    result.push(batch[0]);
  }
  return result;
}

function candidateResolver(candidate: Candidate): string | null {
  if (candidate.graphKind === "type") {
    return candidate.owner === null && candidate.moduleScoped
      ? `definition:${JSON.stringify([
        "module",
        candidate.graphKind,
        candidate.source.relativePath,
        [...candidate.lexicalPath, candidate.displayName],
      ])}`
      : `definition:${JSON.stringify([
        "local",
        candidate.graphKind,
        candidate.source.relativePath,
        candidate.startOffset,
        candidate.endOffset,
      ])}`;
  }

  if (candidate.node.kind === SyntaxKind.MethodDeclaration) {
    if (!hasCanonicalMemberOwner(candidate.node, candidate.owner)) return null;
    const ownerResolver = candidateResolver(candidate.owner);
    if (ownerResolver === null) return null;
    const isStatic = ((candidate.node as MethodDeclaration).modifierFlags & ModifierFlags.Static) !== 0;
    return `definition:${JSON.stringify([
      "member",
      candidate.graphKind,
      ownerResolver,
      isStatic ? "static" : "instance",
      candidate.displayName,
    ])}`;
  }
  if (candidate.node.kind === SyntaxKind.MethodSignature) {
    if (!hasCanonicalMemberOwner(candidate.node, candidate.owner)) return null;
    const ownerResolver = candidateResolver(candidate.owner);
    if (ownerResolver === null) return null;
    const isStatic = ((candidate.node as MethodDeclaration).modifierFlags & ModifierFlags.Static) !== 0;
    return `definition:${JSON.stringify([
      "member",
      candidate.graphKind,
      ownerResolver,
      isStatic ? "static" : "instance",
      candidate.displayName,
    ])}`;
  }
  if (candidate.node.kind === SyntaxKind.Constructor) {
    if (!hasCanonicalMemberOwner(candidate.node, candidate.owner)) return null;
    const ownerResolver = candidateResolver(candidate.owner);
    return ownerResolver === null
      ? null
      : `definition:${JSON.stringify([
        "member",
        candidate.graphKind,
        ownerResolver,
        "constructor",
        candidate.displayName,
      ])}`;
  }
  if (candidate.node.kind === SyntaxKind.ArrowFunction) return null;
  if (candidate.node.kind === SyntaxKind.FunctionExpression) return null;
  if (candidate.owner !== null || !candidate.moduleScoped) return null;
  return `definition:${JSON.stringify([
    "module",
    candidate.graphKind,
    candidate.source.relativePath,
    [...candidate.lexicalPath, candidate.displayName],
  ])}`;
}

function candidateIdentityKind(candidate: Candidate): TypeScriptRawSymbolIdentityKind | null {
  if (candidate.graphKind === "type") return null;
  if (candidate.node.kind === SyntaxKind.ArrowFunction) return "anonymous";
  if (candidate.node.kind === SyntaxKind.FunctionExpression) {
    return (candidate.node as FunctionExpression).name === undefined || candidate.owner?.graphKind !== "symbol"
      ? "anonymous"
      : "local";
  }
  if (candidateResolver(candidate) !== null) return "named";
  return candidate.owner?.graphKind === "symbol" ? "local" : "anonymous";
}

function candidateSemanticKind(candidate: Candidate): string {
  const identityKind = candidateIdentityKind(candidate);
  if (identityKind === "anonymous") return "anonymous_function";
  if (candidate.initialSemanticKind === "function" && identityKind === "local") return "local_function";
  if (candidate.initialSemanticKind === "function_variable" && identityKind === "local") return "local_function_variable";
  return candidate.initialSemanticKind;
}

function rawDefinitionKey(
  graphKind: TypeScriptRawGraphKind,
  semanticKind: string,
  identityKind: TypeScriptRawSymbolIdentityKind | null,
  resolverIdentity: string | null,
  relativePath: string,
  startOffset: number,
  endOffset: number,
): string {
  const location = resolverIdentity === null ? [relativePath, startOffset, endOffset] : null;
  return `definition:${JSON.stringify([graphKind, semanticKind, identityKind, resolverIdentity, location])}`;
}

function candidateGroupKey(candidate: Candidate): string {
  if (candidate.symbol !== null) return `symbol:${candidate.symbol.id}:${candidate.graphKind}`;
  if (candidate.node.kind === SyntaxKind.Constructor && candidate.owner !== null) return `constructor:${candidate.owner.index}`;
  return `candidate:${candidate.index}`;
}

function ownedSymbol(
  symbol: CompilerSymbol,
  sourceByCompilerPath: ReadonlyMap<string, TypeScriptSemanticSource>,
): boolean {
  return symbol.declarations.length > 0
    && symbol.declarations.length <= MAX_SYMBOL_DECLARATIONS
    && symbol.declarations.every((declaration) => (
      sourceByCompilerPath.get(compilerInternalPathKey(String(declaration.path)))?.syntacticallyValid === true
    ));
}

function compilerDeclarationKey(declaration: CompilerSymbol["declarations"][number]): string {
  return `${String(declaration.path)}\0${declaration.index}`;
}

async function resolveMatchingDeclaration(
  symbol: CompilerSymbol,
  source: TypeScriptSemanticSource,
  kind: SyntaxKind,
  startOffset: number,
  endOffset: number,
  counter: QueryCounter,
): Promise<Node | null> {
  if (symbol.declarations.length === 0 || symbol.declarations.length > MAX_SYMBOL_DECLARATIONS) return null;
  const expectedPath = compilerInternalPathKey(source.compilerPath);
  for (const declaration of symbol.declarations) {
    if (declaration.kind !== kind || compilerInternalPathKey(String(declaration.path)) !== expectedPath) continue;
    beginTypeCheckerQuery(counter);
    const resolved = await declaration.resolve();
    if (resolved === undefined || resolved.kind !== kind) continue;
    const resolvedSource = resolved.getSourceFile();
    if (
      compilerInternalPathKey(String(resolvedSource.path)) === expectedPath
      && resolved.getStart(resolvedSource) === startOffset
      && resolved.getEnd() === endOffset
    ) return resolved;
  }
  return null;
}

async function symbolDeclaresCandidate(
  symbol: CompilerSymbol,
  candidate: Candidate,
  counter: QueryCounter,
): Promise<boolean> {
  return await resolveMatchingDeclaration(
    symbol,
    candidate.source,
    candidate.node.kind,
    candidate.startOffset,
    candidate.endOffset,
    counter,
  ) !== null;
}

async function symbolDeclaresTypeParameter(
  symbol: CompilerSymbol,
  parameter: TypeParameterCandidate,
  counter: QueryCounter,
): Promise<boolean> {
  if (symbol.name !== parameter.node.name.text) return false;
  const declaration = await resolveMatchingDeclaration(
    symbol,
    parameter.owner.source,
    SyntaxKind.TypeParameter,
    nodeStart(parameter.node, parameter.owner.source.sourceFile),
    nodeEnd(parameter.node, parameter.owner.source.sourceFile),
    counter,
  );
  if (declaration === null) return false;
  const parent = declaration.parent;
  if (
    parent.kind !== parameter.owner.node.kind
    || parent.getStart(parent.getSourceFile()) !== parameter.owner.startOffset
    || parent.getEnd() !== parameter.owner.endOffset
  ) return false;
  const parameters = typeParametersOf(parent);
  const indexed = parameters[parameter.index];
  return indexed !== undefined
    && indexed.getStart(indexed.getSourceFile()) === declaration.getStart(declaration.getSourceFile())
    && indexed.getEnd() === declaration.getEnd();
}

function symbolDefinitionIdKey(graphKind: TypeScriptRawGraphKind, symbolId: number): string {
  return `${graphKind}:${symbolId}`;
}

function symbolDefinitionDeclarationKey(
  graphKind: TypeScriptRawGraphKind,
  declaration: CompilerSymbol["declarations"][number],
): string {
  return `${graphKind}:${compilerDeclarationKey(declaration)}`;
}

function lookupSymbolDefinition(
  symbol: CompilerSymbol,
  definitions: SymbolDefinitionIndex,
  graphKind: TypeScriptRawGraphKind,
): CandidateGroup | undefined {
  const direct = definitions.byId.get(symbolDefinitionIdKey(graphKind, symbol.id));
  if (direct !== undefined) return direct;
  let match: CandidateGroup | undefined;
  for (const declaration of symbol.declarations) {
    const candidate = definitions.byDeclaration.get(symbolDefinitionDeclarationKey(graphKind, declaration));
    if (candidate === undefined) continue;
    if (match !== undefined && match.ephemeralKey !== candidate.ephemeralKey) return undefined;
    match = candidate;
  }
  return match;
}

function semanticKindForGroup(candidates: readonly Candidate[]): string | null {
  const kinds = new Set(candidates.map((candidate) => candidate.semanticKind));
  if (kinds.size === 1) return kinds.values().next().value ?? null;
  if (candidates[0]?.graphKind === "type" && kinds.has("class") && [...kinds].every((kind) => kind === "class" || kind === "interface")) {
    return "class";
  }
  return null;
}

function sortCandidates(left: Candidate, right: Candidate): number {
  return compareStrings(left.source.relativePath, right.source.relativePath)
    || left.startOffset - right.startOffset
    || left.endOffset - right.endOffset
    || left.index - right.index;
}

function createGroups(
  candidates: readonly Candidate[],
  sourceByCompilerPath: ReadonlyMap<string, TypeScriptSemanticSource>,
  issues: IssueCollector,
): { groups: CandidateGroup[]; candidateGroups: Map<number, CandidateGroup> } {
  const grouped = new Map<string, Candidate[]>();
  for (const candidate of candidates) {
    if (candidate.type === null || candidate.type.isErrorType()) {
      if (candidate.initialSemanticKind !== "variable") {
        addIssue(issues, issue(
          "typescript_semantic_error_type_skipped",
          `TypeChecker did not produce a usable type for ${candidate.displayName}`,
          candidate.source.relativePath,
        ));
      }
      continue;
    }
    if (candidate.symbol !== null && !ownedSymbol(candidate.symbol, sourceByCompilerPath)) {
      addIssue(issues, issue(
        "typescript_semantic_nonlocal_definition_skipped",
        `Definition ${candidate.displayName} is not owned exclusively by the confined source inventory`,
        candidate.source.relativePath,
      ));
      continue;
    }
    const key = candidateGroupKey(candidate);
    grouped.set(key, [...(grouped.get(key) ?? []), candidate]);
  }

  const groups: CandidateGroup[] = [];
  const candidateGroups = new Map<number, CandidateGroup>();
  for (const [ephemeralKey, membersValue] of grouped) {
    const members = [...membersValue].sort(sortCandidates);
    const primary = members[0]!;
    const graphKinds = new Set(members.map((candidate) => candidate.graphKind));
    const semanticKind = semanticKindForGroup(members);
    const resolvers = new Set(members.map((candidate) => candidate.resolverIdentity));
    const identityKinds = new Set(members.map((candidate) => candidate.identityKind));
    const languages = new Set(members.map((candidate) => languageForPath(candidate.source.relativePath)));
    const valid = graphKinds.size === 1
      && semanticKind !== null
      && resolvers.size === 1
      && identityKinds.size === 1
      && languages.size === 1
      && primary.displayName.length > 0
      && primary.displayName.length <= MAX_DISPLAY_NAME_CHARS
      && !hasUnpairedSurrogate(primary.displayName)
      && (primary.resolverIdentity === null || primary.resolverIdentity.length <= MAX_RESOLVER_IDENTITY_CHARS)
      && !(primary.graphKind === "symbol" && primary.identityKind === "named" && primary.resolverIdentity === null)
      && !(primary.graphKind === "symbol" && primary.identityKind !== "named" && primary.resolverIdentity !== null)
      && !(primary.graphKind === "symbol" && primary.identityKind === "local" && primary.owner?.graphKind !== "symbol")
      && !(primary.graphKind === "type" && primary.resolverIdentity === null);
    if (!valid) {
      addIssue(issues, issue(
        "typescript_semantic_merged_definition_skipped",
        `Merged definition ${primary.displayName} has incompatible kinds, owners, or canonical resolvers`,
        primary.source.relativePath,
      ));
      continue;
    }
    const group: CandidateGroup = {
      ephemeralKey,
      candidates: members,
      primary,
      symbol: primary.symbol,
      graphKind: primary.graphKind,
      semanticKind,
      identityKind: primary.identityKind,
      resolverIdentity: primary.resolverIdentity,
      key: rawDefinitionKey(
        primary.graphKind,
        semanticKind,
        primary.identityKind,
        primary.resolverIdentity,
        primary.source.relativePath,
        primary.startOffset,
        primary.endOffset,
      ),
      skipped: false,
    };
    groups.push(group);
    for (const candidate of members) candidateGroups.set(candidate.index, group);
  }
  return {
    groups: groups.sort((left, right) => left.primary.depth - right.primary.depth || compareStrings(left.key, right.key)),
    candidateGroups,
  };
}

function endpointForOwner(
  candidate: Candidate,
  candidateGroups: ReadonlyMap<number, CandidateGroup>,
): TypeScriptRawDefinitionEndpoint | null {
  if (candidate.owner === null) return { kind: "file", relativePath: candidate.source.relativePath };
  const group = candidateGroups.get(candidate.owner.index);
  if (group === undefined || group.skipped) return null;
  return { kind: "definition", key: group.key };
}

function evidence(candidate: Candidate, detail: string): TypeScriptRawDefinitionEvidence {
  return {
    relativePath: candidate.source.relativePath,
    startOffset: candidate.startOffset,
    endOffset: candidate.endOffset,
    detail,
  };
}

function heritageEvidence(heritage: HeritageCandidate, detail: string): TypeScriptRawDefinitionEvidence {
  return {
    relativePath: heritage.owner.source.relativePath,
    startOffset: nodeStart(heritage.node, heritage.owner.source.sourceFile),
    endOffset: nodeEnd(heritage.node, heritage.owner.source.sourceFile),
    detail,
  };
}

function terminalReferenceName(node: Node): string | null {
  if (node.kind === SyntaxKind.Identifier || node.kind === SyntaxKind.PrivateIdentifier) {
    return (node as Node & { readonly text: string }).text;
  }
  if (node.kind === SyntaxKind.PropertyAccessExpression) {
    return propertyName((node as Node & { readonly name: PropertyName }).name);
  }
  if (node.kind === SyntaxKind.ElementAccessExpression) {
    const argument = (node as Node & { readonly argumentExpression: Node }).argumentExpression;
    return argument.kind === SyntaxKind.StringLiteral || argument.kind === SyntaxKind.NumericLiteral
      ? (argument as Node & { readonly text: string }).text
      : null;
  }
  return null;
}

async function unwrapAlias(
  checker: Checker,
  symbol: CompilerSymbol,
  counter: QueryCounter,
): Promise<CompilerSymbol | null> {
  if ((symbol.flags & SymbolFlags.Alias) === 0) return symbol;
  beginTypeCheckerQuery(counter);
  const target = await checker.getAliasedSymbol(symbol);
  beginTypeCheckerQuery(counter);
  return await checker.isUnknownSymbol(target) ? null : target;
}

function intrinsicTypeDescriptor(type: CompilerType): TypeScriptRawTypeArgumentDescriptor | null {
  if (type.isLiteralType()) {
    const value = type.value;
    const valueKind = typeof value;
    if (valueKind !== "string" && valueKind !== "number" && valueKind !== "boolean" && valueKind !== "bigint") return null;
    if (typeof value === "string" && hasUnpairedSurrogate(value)) return null;
    const encoded = typeof value === "bigint"
      ? value.toString(10)
      : typeof value === "number" && Object.is(value, -0)
        ? "-0"
        : String(value);
    return { kind: "literal", valueKind, value: encoded };
  }
  if ((type.flags & TypeFlags.Any) !== 0) return { kind: "intrinsic", name: "any" };
  if ((type.flags & TypeFlags.Unknown) !== 0) return { kind: "intrinsic", name: "unknown" };
  if ((type.flags & TypeFlags.String) !== 0) return { kind: "intrinsic", name: "string" };
  if ((type.flags & TypeFlags.Number) !== 0) return { kind: "intrinsic", name: "number" };
  if ((type.flags & TypeFlags.Boolean) !== 0) return { kind: "intrinsic", name: "boolean" };
  if ((type.flags & TypeFlags.BigInt) !== 0) return { kind: "intrinsic", name: "bigint" };
  if ((type.flags & TypeFlags.ESSymbol) !== 0) return { kind: "intrinsic", name: "symbol" };
  if ((type.flags & TypeFlags.Void) !== 0) return { kind: "intrinsic", name: "void" };
  if ((type.flags & TypeFlags.Undefined) !== 0) return { kind: "intrinsic", name: "undefined" };
  if ((type.flags & TypeFlags.Null) !== 0) return { kind: "intrinsic", name: "null" };
  if ((type.flags & TypeFlags.Never) !== 0) return { kind: "intrinsic", name: "never" };
  return null;
}

function explicitTypeArguments(node: TypeNode): readonly TypeNode[] {
  return (node as TypeNode & { readonly typeArguments?: readonly TypeNode[] }).typeArguments ?? [];
}

function hasDescendantExplicitTypeArguments(node: TypeNode): boolean {
  const pending: { node: TypeNode; depth: number }[] = [{ node, depth: 0 }];
  let visited = 0;
  let found = false;
  while (pending.length > 0) {
    const current = pending.pop()!;
    visited += 1;
    if (visited > MAX_TYPE_DESCRIPTOR_NODES || current.depth >= MAX_TYPE_DESCRIPTOR_DEPTH) return true;
    current.node.forEachChild((child) => {
      if (found || !isTypeNode(child)) return undefined;
      if (explicitTypeArguments(child).length > 0) {
        found = true;
      } else {
        pending.push({ node: child, depth: current.depth + 1 });
      }
      return undefined;
    });
    if (found) return true;
  }
  return false;
}

function canonicalTypeMembers(
  kind: "union" | "intersection",
  members: readonly TypeScriptRawTypeArgumentDescriptor[],
): TypeScriptRawTypeArgumentDescriptor {
  const canonical = [...new Map(members.map((descriptor) => [JSON.stringify(descriptor), descriptor])).entries()]
    .sort(([left], [right]) => compareStrings(left, right))
    .map(([, descriptor]) => descriptor);
  return { kind, members: canonical };
}

async function namedTypeDescriptor(
  type: CompilerType,
  symbolDefinitions: SymbolDefinitionIndex,
  typeParameters: ReadonlyMap<number, TypeScriptRawTypeArgumentDescriptor>,
  counter: QueryCounter,
): Promise<TypeScriptRawTypeArgumentDescriptor | null> {
  beginTypeCheckerQuery(counter);
  const aliasSymbol = await type.getAliasSymbol();
  beginTypeCheckerQuery(counter);
  const directSymbol = await type.getSymbol();
  const symbol = aliasSymbol ?? directSymbol;
  if (symbol === undefined) return null;
  const parameter = typeParameters.get(symbol.id);
  if (parameter !== undefined) return parameter;
  const definition = lookupSymbolDefinition(symbol, symbolDefinitions, "type");
  if (definition !== undefined && definition.resolverIdentity !== null) {
    return { kind: "definition", key: definition.key };
  }
  return null;
}

async function typeDescriptor(
  type: CompilerType,
  syntaxNode: TypeNode | null,
  typesByNode: ReadonlyMap<TypeNode, CompilerType | undefined>,
  symbolDefinitions: SymbolDefinitionIndex,
  typeParameters: ReadonlyMap<number, TypeScriptRawTypeArgumentDescriptor>,
  counter: QueryCounter,
  budget: TypeDescriptorBudget,
  depth = 0,
  seen = new Set<number>(),
): Promise<TypeScriptRawTypeArgumentDescriptor | null> {
  budget.nodes += 1;
  if (
    budget.nodes > MAX_TYPE_DESCRIPTOR_NODES
    || type.isErrorType()
    || seen.has(type.id)
    || depth > MAX_TYPE_DESCRIPTOR_DEPTH
  ) return null;
  const intrinsic = intrinsicTypeDescriptor(type);
  if (intrinsic !== null) return intrinsic;
  const nextSeen = new Set(seen).add(type.id);
  if (syntaxNode !== null) {
    const syntaxArguments = explicitTypeArguments(syntaxNode);
    if (syntaxArguments.length > 0) {
      if (syntaxArguments.length > MAX_TYPE_ARGUMENTS) return null;
      const base = await namedTypeDescriptor(type, symbolDefinitions, typeParameters, counter);
      if (base === null) return null;
      const argumentsDescriptors: TypeScriptRawTypeArgumentDescriptor[] = [];
      for (const argument of syntaxArguments) {
        const argumentType = typesByNode.get(argument);
        if (argumentType === undefined) return null;
        const descriptor = await typeDescriptor(
          argumentType,
          argument,
          typesByNode,
          symbolDefinitions,
          typeParameters,
          counter,
          budget,
          depth + 1,
          nextSeen,
        );
        if (descriptor === null) return null;
        argumentsDescriptors.push(descriptor);
      }
      return { kind: "application", target: base, typeArguments: argumentsDescriptors };
    }
    if (syntaxNode.kind === SyntaxKind.TypeReference) {
      const named = await namedTypeDescriptor(type, symbolDefinitions, typeParameters, counter);
      if (named !== null) return named;
    }
    if (syntaxNode.kind === SyntaxKind.ParenthesizedType) {
      const children: TypeNode[] = [];
      syntaxNode.forEachChild((child) => {
        if (isTypeNode(child)) children.push(child);
        return undefined;
      });
      if (children.length !== 1) return null;
      const childType = typesByNode.get(children[0]!);
      return childType === undefined
        ? null
        : await typeDescriptor(
          childType,
          children[0]!,
          typesByNode,
          symbolDefinitions,
          typeParameters,
          counter,
          budget,
          depth + 1,
          nextSeen,
        );
    }
    if (syntaxNode.kind === SyntaxKind.UnionType || syntaxNode.kind === SyntaxKind.IntersectionType) {
      const syntaxMembers = (syntaxNode as TypeNode & { readonly types: readonly TypeNode[] }).types;
      if (syntaxMembers.length === 0 || syntaxMembers.length > MAX_TYPE_DESCRIPTOR_MEMBERS) return null;
      const descriptors: TypeScriptRawTypeArgumentDescriptor[] = [];
      for (const member of syntaxMembers) {
        const memberType = typesByNode.get(member);
        if (memberType === undefined) return null;
        const descriptor = await typeDescriptor(
          memberType,
          member,
          typesByNode,
          symbolDefinitions,
          typeParameters,
          counter,
          budget,
          depth + 1,
          nextSeen,
        );
        if (descriptor === null) return null;
        descriptors.push(descriptor);
      }
      return canonicalTypeMembers(syntaxNode.kind === SyntaxKind.UnionType ? "union" : "intersection", descriptors);
    }
    // A union/intersection's compiler members are normalized and may no longer
    // correspond one-to-one with its syntax children. Be conservative rather
    // than silently dropping a nested explicit generic application.
    if (hasDescendantExplicitTypeArguments(syntaxNode)) return null;
  }
  if (type.isUnionType() || type.isIntersectionType()) {
    beginTypeCheckerQuery(counter);
    const members = await type.getTypes();
    if (members === undefined || members.length > MAX_TYPE_DESCRIPTOR_MEMBERS) return null;
    const descriptors: TypeScriptRawTypeArgumentDescriptor[] = [];
    for (const member of members) {
      const descriptor = await typeDescriptor(
        member,
        null,
        typesByNode,
        symbolDefinitions,
        typeParameters,
        counter,
        budget,
        depth + 1,
        nextSeen,
      );
      if (descriptor === null) return null;
      descriptors.push(descriptor);
    }
    return canonicalTypeMembers(type.isUnionType() ? "union" : "intersection", descriptors);
  }
  return await namedTypeDescriptor(type, symbolDefinitions, typeParameters, counter);
}

function sortDefinitions(left: TypeScriptRawDefinition, right: TypeScriptRawDefinition): number {
  return compareStrings(left.key, right.key);
}

function endpointKey(endpoint: TypeScriptRawDefinitionEndpoint): string {
  return endpoint.kind === "file" ? `file:${endpoint.relativePath}` : `definition:${endpoint.key}`;
}

function sortRelations(left: TypeScriptRawDefinitionRelation, right: TypeScriptRawDefinitionRelation): number {
  return compareStrings(left.kind, right.kind)
    || compareStrings(endpointKey(left.source), endpointKey(right.source))
    || compareStrings(left.target, right.target)
    || compareStrings(left.evidence.relativePath, right.evidence.relativePath)
    || left.evidence.startOffset - right.evidence.startOffset
    || left.evidence.endOffset - right.evidence.endOffset
    || compareStrings(left.evidence.detail, right.evidence.detail);
}

function sortIssues(left: TypeScriptSemanticIssue, right: TypeScriptSemanticIssue): number {
  return compareStrings(left.relativePath ?? "", right.relativePath ?? "")
    || compareStrings(left.code, right.code)
    || compareStrings(left.message, right.message)
    || Number(left.fatal) - Number(right.fatal);
}

function deduplicateRelations(relations: readonly TypeScriptRawDefinitionRelation[]): TypeScriptRawDefinitionRelation[] {
  const result = new Map<string, TypeScriptRawDefinitionRelation>();
  for (const relation of relations) {
    const key = JSON.stringify(relation);
    result.set(key, relation);
  }
  return [...result.values()].sort(sortRelations);
}

function deduplicateIssues(collector: IssueCollector): TypeScriptSemanticIssue[] {
  const result = new Map<string, TypeScriptSemanticIssue>();
  for (const item of collector.issues) result.set(JSON.stringify(item), item);
  if (collector.truncated) {
    const truncation = issue(
      "typescript_semantic_issues_truncated",
      `TypeScript semantic issues were truncated at ${MAX_ISSUES}`,
      null,
    );
    if (result.size >= MAX_ISSUES) {
      const replace = [...result].findLast(([, existing]) => !existing.fatal);
      if (replace !== undefined) result.delete(replace[0]);
    }
    if (result.size < MAX_ISSUES) result.set(JSON.stringify(truncation), truncation);
  }
  return [...result.values()].sort(sortIssues);
}

/**
 * Validate the raw delta before scanner-side identity construction. This is
 * intentionally strict so an invalid endpoint or partial semantic relation
 * can never be merged piecemeal into the syntax graph.
 */
export function validateTypeScriptRawDefinitionDelta(
  delta: Pick<TypeScriptRawDefinitionDelta, "definitions" | "relations">,
  sources: readonly TypeScriptSemanticSource[],
): void {
  if (sources.length > TYPESCRIPT_SEMANTIC_MAX_SOURCE_FILES) throw new DeltaValidationError("raw delta source inventory exceeds its limit");
  if (delta.definitions.length > MAX_RELATIONS) throw new DeltaValidationError("raw definition delta exceeds its limit");
  if (delta.relations.length > MAX_RELATIONS) throw new DeltaValidationError("raw relation delta exceeds its limit");
  const sourceLengths = new Map<string, number>();
  const validSources = new Set<string>();
  for (const source of sources) {
    if (!isCanonicalRelativePath(source.relativePath)) throw new DeltaValidationError(`unsafe semantic source path ${source.relativePath}`);
    if (sourceLengths.has(source.relativePath)) throw new DeltaValidationError(`duplicate semantic source path ${source.relativePath}`);
    if (source.sourceFile.text !== source.expectedText) {
      throw new DeltaValidationError(`semantic source text disagrees with inventory for ${source.relativePath}`);
    }
    sourceLengths.set(source.relativePath, source.sourceFile.text.length);
    if (source.syntacticallyValid) validSources.add(source.relativePath);
  }
  const definitions = new Map<string, TypeScriptRawDefinition>();
  const resolverDefinitions = new Map<string, string>();
  let previousDefinition = "";
  for (const definition of delta.definitions) {
    if (previousDefinition !== "" && compareStrings(previousDefinition, definition.key) >= 0) {
      throw new DeltaValidationError("raw definitions are not in strict key order");
    }
    previousDefinition = definition.key;
    if (definitions.has(definition.key)) throw new DeltaValidationError(`duplicate raw definition ${definition.key}`);
    if (definition.graphKind !== "symbol" && definition.graphKind !== "type") {
      throw new DeltaValidationError(`raw definition ${definition.key} has an unsupported graph kind`);
    }
    if (definition.language !== "typescript" && definition.language !== "javascript") {
      throw new DeltaValidationError(`raw definition ${definition.key} has an unsupported language`);
    }
    if (definition.exported !== undefined && definition.exported !== true) {
      throw new DeltaValidationError(`raw definition ${definition.key} has invalid export evidence`);
    }
    if (definition.exported === true && definition.owner.kind !== "file") {
      throw new DeltaValidationError(`raw definition ${definition.key} exports a non-module definition`);
    }
    if (
      definition.displayName.length === 0
      || definition.displayName.length > MAX_DISPLAY_NAME_CHARS
      || hasUnpairedSurrogate(definition.displayName)
    ) {
      throw new DeltaValidationError(`raw definition ${definition.key} has an invalid display name`);
    }
    if (definition.resolverIdentity !== null && (
      definition.resolverIdentity.length === 0
      || definition.resolverIdentity.length > MAX_RESOLVER_IDENTITY_CHARS
    )) throw new DeltaValidationError(`raw definition ${definition.key} has an invalid resolver identity`);
    if (definition.resolverIdentity !== null) {
      const existingResolver = resolverDefinitions.get(definition.resolverIdentity);
      if (existingResolver !== undefined && existingResolver !== definition.key) {
        throw new DeltaValidationError(`raw definitions share canonical resolver ${definition.resolverIdentity}`);
      }
      resolverDefinitions.set(definition.resolverIdentity, definition.key);
    }
    if (!isCanonicalRelativePath(definition.relativePath)) throw new DeltaValidationError(`unsafe raw definition path ${definition.relativePath}`);
    const sourceLength = sourceLengths.get(definition.relativePath);
    if (sourceLength === undefined || !validSources.has(definition.relativePath)) {
      throw new DeltaValidationError(`raw definition references missing or invalid source ${definition.relativePath}`);
    }
    if (
      !Number.isSafeInteger(definition.startOffset)
      || !Number.isSafeInteger(definition.endOffset)
      || definition.startOffset < 0
      || definition.endOffset < definition.startOffset
      || definition.endOffset > sourceLength
    ) {
      throw new DeltaValidationError(`raw definition ${definition.key} has an invalid source range`);
    }
    if (definition.graphKind === "symbol") {
      const expectedIdentity = SYMBOL_SEMANTIC_IDENTITIES.get(definition.semanticKind);
      if (expectedIdentity === undefined || definition.identityKind !== expectedIdentity) {
        throw new DeltaValidationError(`symbol ${definition.key} has an unsupported semantic or identity kind`);
      }
      if ((definition.identityKind === "named") !== (definition.resolverIdentity !== null)) {
        throw new DeltaValidationError(`symbol ${definition.key} has an inconsistent resolver identity`);
      }
      if (definition.genericOrigin !== undefined || definition.typeArguments !== undefined) {
        throw new DeltaValidationError(`symbol ${definition.key} has generic type metadata`);
      }
    } else {
      if (!TYPE_SEMANTIC_KINDS.has(definition.semanticKind)) {
        throw new DeltaValidationError(`type ${definition.key} has an unsupported semantic kind`);
      }
      if (definition.identityKind !== null || definition.resolverIdentity === null) {
        throw new DeltaValidationError(`type ${definition.key} has an invalid identity shape`);
      }
      const isGenericInstance = definition.semanticKind === "generic_instance";
      if (isGenericInstance !== (definition.genericOrigin !== undefined && definition.typeArguments !== undefined)) {
        throw new DeltaValidationError(`generic definition ${definition.key} has incomplete origin metadata`);
      }
      if (definition.typeArguments !== undefined && (
        definition.typeArguments.length === 0
        || definition.typeArguments.length > MAX_TYPE_ARGUMENTS
      )) throw new DeltaValidationError(`generic definition ${definition.key} has invalid type arguments`);
    }
    const expectedKey = rawDefinitionKey(
      definition.graphKind,
      definition.semanticKind,
      definition.identityKind,
      definition.resolverIdentity,
      definition.relativePath,
      definition.startOffset,
      definition.endOffset,
    );
    if (definition.key !== expectedKey) {
      throw new DeltaValidationError(`raw definition ${definition.key} has a non-canonical key`);
    }
    definitions.set(definition.key, definition);
  }

  for (const definition of definitions.values()) {
    if (definition.genericOrigin !== undefined) continue;
    const resolver = definition.resolverIdentity;
    if (resolver === null) continue;
    if (!resolver.startsWith("definition:")) {
      throw new DeltaValidationError("raw definition resolver has an unsupported encoding");
    }
    let tuple: unknown;
    try {
      tuple = JSON.parse(resolver.slice("definition:".length)) as unknown;
    } catch {
      throw new DeltaValidationError("raw definition resolver is not canonical JSON");
    }
    if (!Array.isArray(tuple) || `definition:${JSON.stringify(tuple)}` !== resolver) {
      throw new DeltaValidationError("raw definition resolver is not canonical JSON");
    }
    const [scope, graphKind] = tuple;
    if (graphKind !== definition.graphKind) throw new DeltaValidationError("raw definition resolver has the wrong graph kind");
    if (scope === "module") {
      const segments = tuple[3];
      if (
        tuple.length !== 4
        || tuple[2] !== definition.relativePath
        || !Array.isArray(segments)
        || segments.length === 0
        || segments.length > MAX_AST_DEPTH + 1
        || segments.some((segment) => typeof segment !== "string" || segment.length > MAX_DISPLAY_NAME_CHARS)
        || segments.at(-1) !== definition.displayName
      ) throw new DeltaValidationError("raw module definition resolver is inconsistent");
    } else if (scope === "local") {
      if (
        tuple.length !== 5
        || definition.graphKind !== "type"
        || tuple[2] !== definition.relativePath
        || tuple[3] !== definition.startOffset
        || tuple[4] !== definition.endOffset
      ) throw new DeltaValidationError("raw local definition resolver is inconsistent");
    } else if (scope === "member") {
      const owner = definition.owner.kind === "definition" ? definitions.get(definition.owner.key) : undefined;
      const memberKind = tuple[3];
      if (
        tuple.length !== 5
        || definition.graphKind !== "symbol"
        || owner?.graphKind !== "type"
        || tuple[2] !== owner.resolverIdentity
        || (memberKind !== "static" && memberKind !== "instance" && memberKind !== "constructor")
        || tuple[4] !== definition.displayName
        || (definition.semanticKind === "constructor") !== (memberKind === "constructor")
      ) throw new DeltaValidationError("raw member definition resolver is inconsistent");
    } else {
      throw new DeltaValidationError("raw definition resolver has an unsupported scope");
    }
  }

  const intrinsicNames = new Set([
    "any", "unknown", "string", "number", "boolean", "bigint", "symbol",
    "void", "undefined", "null", "never",
  ]);
  const activeDescriptors = new Set<object>();
  const validateTypeArgument = (
    descriptor: TypeScriptRawTypeArgumentDescriptor,
    depth = 0,
    budget: TypeDescriptorBudget = { nodes: 0 },
  ): string => {
    budget.nodes += 1;
    if (
      budget.nodes > MAX_TYPE_DESCRIPTOR_NODES
      || depth > MAX_TYPE_DESCRIPTOR_DEPTH
      || descriptor === null
      || typeof descriptor !== "object"
      || Array.isArray(descriptor)
    ) {
      throw new DeltaValidationError("generic type argument has an invalid descriptor shape");
    }
    if (activeDescriptors.has(descriptor)) throw new DeltaValidationError("generic type argument descriptor is cyclic");
    activeDescriptors.add(descriptor);
    try {
      let canonical: string;
      switch (descriptor.kind) {
        case "intrinsic":
          if (!intrinsicNames.has(descriptor.name)) throw new DeltaValidationError("generic type argument has an unknown intrinsic");
          canonical = JSON.stringify({ kind: "intrinsic", name: descriptor.name });
          break;
        case "literal":
          if (
            !(["string", "number", "boolean", "bigint"] as const).includes(descriptor.valueKind)
            || (descriptor.valueKind === "string" && hasUnpairedSurrogate(descriptor.value))
            || (descriptor.valueKind === "boolean" && descriptor.value !== "true" && descriptor.value !== "false")
            || (descriptor.valueKind === "bigint" && !/^(?:0|-?[1-9]\d*)$/u.test(descriptor.value))
            || (descriptor.valueKind === "number" && (
              !Number.isFinite(Number(descriptor.value))
              || (descriptor.value !== "-0" && String(Number(descriptor.value)) !== descriptor.value)
            ))
          ) throw new DeltaValidationError("generic type argument has an invalid literal");
          canonical = JSON.stringify({ kind: "literal", valueKind: descriptor.valueKind, value: descriptor.value });
          break;
        case "definition": {
          const target = definitions.get(descriptor.key);
          if (target?.graphKind !== "type" || target.semanticKind === "generic_instance") {
            throw new DeltaValidationError("generic type argument references a missing concrete type definition");
          }
          canonical = JSON.stringify({ kind: "definition", key: descriptor.key });
          break;
        }
        case "type_parameter":
          if (
            !definitions.has(descriptor.owner)
            || !Number.isSafeInteger(descriptor.index)
            || descriptor.index < 0
            || descriptor.name.length === 0
            || descriptor.name.length > MAX_DISPLAY_NAME_CHARS
            || hasUnpairedSurrogate(descriptor.name)
          ) throw new DeltaValidationError("generic type argument has an invalid type parameter");
          canonical = JSON.stringify({
            kind: "type_parameter",
            owner: descriptor.owner,
            index: descriptor.index,
            name: descriptor.name,
          });
          break;
        case "application": {
          if (
            descriptor.target.kind !== "definition"
            && descriptor.target.kind !== "type_parameter"
          ) throw new DeltaValidationError("generic application has an invalid target");
          if (
            !Array.isArray(descriptor.typeArguments)
            || descriptor.typeArguments.length === 0
            || descriptor.typeArguments.length > MAX_TYPE_ARGUMENTS
          ) throw new DeltaValidationError("generic application has invalid arguments");
          const target = validateTypeArgument(descriptor.target, depth + 1, budget);
          const typeArguments = descriptor.typeArguments.map((argument) => validateTypeArgument(argument, depth + 1, budget));
          canonical = JSON.stringify({
            kind: "application",
            target: JSON.parse(target) as unknown,
            typeArguments: typeArguments.map((argument) => JSON.parse(argument) as unknown),
          });
          break;
        }
        case "union":
        case "intersection": {
          if (
            !Array.isArray(descriptor.members)
            || descriptor.members.length === 0
            || descriptor.members.length > MAX_TYPE_DESCRIPTOR_MEMBERS
          ) throw new DeltaValidationError(`generic ${descriptor.kind} has invalid members`);
          const members = descriptor.members.map((member) => validateTypeArgument(member, depth + 1, budget));
          for (let index = 1; index < members.length; index += 1) {
            if (compareStrings(members[index - 1]!, members[index]!) >= 0) {
              throw new DeltaValidationError(`generic ${descriptor.kind} members are not in strict canonical order`);
            }
          }
          canonical = JSON.stringify({
            kind: descriptor.kind,
            members: members.map((member) => JSON.parse(member) as unknown),
          });
          break;
        }
        default:
          throw new DeltaValidationError("generic type argument has an unsupported descriptor kind");
      }
      if (canonical.length > MAX_TYPE_ARGUMENT_DESCRIPTOR_CHARS || JSON.stringify(descriptor) !== canonical) {
        throw new DeltaValidationError("generic type argument descriptor is too large or non-canonical");
      }
      return canonical;
    } finally {
      activeDescriptors.delete(descriptor);
    }
  };

  for (const definition of definitions.values()) {
    if (definition.owner.kind === "file") {
      if (
        definition.owner.relativePath !== definition.relativePath
        || !validSources.has(definition.owner.relativePath)
      ) throw new DeltaValidationError(`definition ${definition.key} has an invalid file owner`);
    } else {
      const owner = definitions.get(definition.owner.key);
      if (owner === undefined) throw new DeltaValidationError(`definition ${definition.key} has a missing definition owner`);
      if (definition.identityKind === "local" && owner.graphKind !== "symbol") {
        throw new DeltaValidationError(`local definition ${definition.key} has a non-symbol owner`);
      }
    }
    if (definition.genericOrigin !== undefined) {
      const origin = definitions.get(definition.genericOrigin);
      if (origin?.graphKind !== "type" || origin.semanticKind === "generic_instance") {
        throw new DeltaValidationError(`generic definition ${definition.key} has a non-concrete type origin`);
      }
      if (
        definition.owner.kind !== "definition"
        || definition.owner.key !== origin.key
        || definition.language !== origin.language
        || definition.relativePath !== origin.relativePath
        || definition.startOffset !== origin.startOffset
        || definition.endOffset !== origin.endOffset
      ) throw new DeltaValidationError(`generic definition ${definition.key} is not anchored to its origin`);
      const typeArguments = definition.typeArguments!.map((argument) => validateTypeArgument(argument));
      const expectedResolver = `generic:${JSON.stringify([
        origin.key,
        typeArguments.map((argument) => JSON.parse(argument) as unknown),
      ])}`;
      if (definition.resolverIdentity !== expectedResolver) {
        throw new DeltaValidationError(`generic definition ${definition.key} has a non-canonical raw resolver`);
      }
    }
  }

  for (const definition of definitions.values()) {
    const seenOwners = new Set<string>();
    let current = definition;
    let depth = 0;
    for (;;) {
      if (!seenOwners.add(current.key)) throw new DeltaValidationError(`definition ownership cycle at ${current.key}`);
      if (current.owner.kind === "file") break;
      depth += 1;
      if (depth > MAX_AST_DEPTH) throw new DeltaValidationError(`definition ownership exceeds depth ${MAX_AST_DEPTH}`);
      current = definitions.get(current.owner.key)!;
    }
  }

  let previousRelation: TypeScriptRawDefinitionRelation | null = null;
  const declaredTargets = new Set<string>();
  const instantiatedTargets = new Set<string>();
  for (const relation of delta.relations) {
    if (!RELATION_KINDS.has(relation.kind)) throw new DeltaValidationError(`unsupported raw relation kind ${relation.kind}`);
    if (previousRelation !== null && sortRelations(previousRelation, relation) >= 0) {
      throw new DeltaValidationError("raw relations are not in strict canonical order");
    }
    previousRelation = relation;
    const target = definitions.get(relation.target);
    if (target === undefined) throw new DeltaValidationError(`relation references missing target ${relation.target}`);
    let sourceDefinition: TypeScriptRawDefinition | undefined;
    if (relation.source.kind === "file") {
      if (!validSources.has(relation.source.relativePath)) throw new DeltaValidationError("relation has a missing file source");
    } else {
      sourceDefinition = definitions.get(relation.source.key);
      if (sourceDefinition === undefined) throw new DeltaValidationError(`relation references missing source ${relation.source.key}`);
    }
    const evidenceLength = sourceLengths.get(relation.evidence.relativePath);
    if (
      evidenceLength === undefined
      || !validSources.has(relation.evidence.relativePath)
      || !Number.isSafeInteger(relation.evidence.startOffset)
      || !Number.isSafeInteger(relation.evidence.endOffset)
      || relation.evidence.startOffset < 0
      || relation.evidence.endOffset < relation.evidence.startOffset
      || relation.evidence.endOffset > evidenceLength
      || relation.evidence.detail.length === 0
    ) throw new DeltaValidationError("relation has invalid semantic evidence");
    const sourcePath = relation.source.kind === "file" ? relation.source.relativePath : sourceDefinition!.relativePath;
    if (relation.evidence.relativePath !== sourcePath) {
      throw new DeltaValidationError("relation evidence is not anchored to its source endpoint");
    }
    if (relation.kind === "declares") {
      if (target.semanticKind === "generic_instance" || endpointKey(relation.source) !== endpointKey(target.owner)) {
        throw new DeltaValidationError("declares relation does not match its definition owner");
      }
      declaredTargets.add(target.key);
    }
    if ((relation.kind === "extends" || relation.kind === "implements")
      && (sourceDefinition?.graphKind !== "type" || target.graphKind !== "type")) {
      throw new DeltaValidationError(`${relation.kind} relation must connect type definitions`);
    }
    if (relation.kind === "instantiates") {
      if (sourceDefinition?.graphKind !== "type" || target.semanticKind !== "generic_instance") {
        throw new DeltaValidationError("instantiates relation must connect a type to a generic instance");
      }
      instantiatedTargets.add(target.key);
    }
  }
  for (const definition of definitions.values()) {
    if (definition.semanticKind === "generic_instance") {
      if (!instantiatedTargets.has(definition.key)) throw new DeltaValidationError(`generic definition ${definition.key} is never instantiated`);
    } else if (!declaredTargets.has(definition.key)) {
      throw new DeltaValidationError(`raw definition ${definition.key} has no declares relation`);
    }
  }
}

/**
 * Extract a repository-owned TypeScript/JavaScript definition slice. The
 * returned DTO deliberately omits package locators and protocol IDs; scanner
 * code adds those only after this complete delta passes validation.
 */
async function extractTypeScriptRawDefinitionDeltaUnchecked(
  checker: Checker,
  sources: readonly TypeScriptSemanticSource[],
): Promise<TypeScriptRawDefinitionDelta> {
  const issueCollector: IssueCollector = { issues: [], truncated: false };
  const counter: QueryCounter = { value: 0 };
  const collection = collectSources(sources, issueCollector);
  if (collection.limitIssue !== null) {
    addIssue(issueCollector, collection.limitIssue);
    return { definitions: [], relations: [], issues: deduplicateIssues(issueCollector), typeCheckerQueries: counter.value };
  }

  const namedCandidates = collection.candidates.filter((candidate) => candidate.nameNode !== null);
  const symbols = await querySymbols(
    checker,
    namedCandidates.map((candidate) => candidate.nameNode!),
    counter,
    "definition",
  );
  for (const [index, candidate] of namedCandidates.entries()) {
    const symbol = symbols[index];
    candidate.symbol = symbol ?? null;
    if (symbol !== undefined && !await symbolDeclaresCandidate(symbol, candidate, counter)) {
      throw new TypeCheckerContractError("definition symbol did not declare the requested node", counter.value);
    }
  }

  const types = await queryTypes(
    checker,
    collection.candidates.map((candidate) => candidate.node),
    counter,
    "definition",
  );
  for (const [index, candidate] of collection.candidates.entries()) candidate.type = types[index] ?? null;

  for (const candidate of namedCandidates) {
    if (
      (
        candidate.initialSemanticKind === "function_variable"
        || candidate.initialSemanticKind === "variable"
        // getTypeAtLocation on a type-alias declaration can legitimately
        // expose the aliased target's symbol (not the declaration symbol),
        // especially through qualified or cyclic namespace aliases. The
        // separately correlated name-symbol query remains the ownership proof.
        || candidate.initialSemanticKind === "type_alias"
      )
      || candidate.symbol === null
      || candidate.type === null
      || candidate.type.isErrorType()
    ) continue;
    beginTypeCheckerQuery(counter);
    const aliasSymbol = await candidate.type.getAliasSymbol();
    beginTypeCheckerQuery(counter);
    const directSymbol = await candidate.type.getSymbol();
    const typeSymbol = aliasSymbol ?? directSymbol;
    if (typeSymbol !== undefined && typeSymbol.id !== candidate.symbol.id) {
      throw new TypeCheckerContractError(
        `definition type did not correlate with its requested ${candidate.semanticKind} symbol`,
        counter.value,
      );
    }
  }

  // Unnamed default declarations have no symbol at the declaration node. The
  // type's symbol is still compiler-owned and carries the declaration handles.
  for (const candidate of collection.candidates) {
    if (
      candidate.symbol === null
      && (candidate.node.kind === SyntaxKind.FunctionDeclaration || candidate.node.kind === SyntaxKind.ClassDeclaration)
      && candidate.displayName === "default"
      && candidate.type !== null
      && !candidate.type.isErrorType()
    ) {
      beginTypeCheckerQuery(counter);
      candidate.symbol = await candidate.type.getSymbol() ?? null;
    }
  }

  // ConstructorDeclaration is the only candidate for which getTypeAtLocation
  // is not a usable proof. Calling getSignatureFromDeclaration on arbitrary
  // nodes can panic the native compiler, so keep this exact SyntaxKind guard.
  for (const candidate of collection.candidates) {
    if (candidate.node.kind !== SyntaxKind.Constructor) continue;
    beginTypeCheckerQuery(counter);
    const signature = await checker.getSignatureFromDeclaration(candidate.node);
    if (signature === undefined) candidate.type = null;
    else if (candidate.owner?.type !== null && candidate.owner?.type !== undefined) candidate.type = candidate.owner.type;
  }

  for (const candidate of collection.candidates) {
    candidate.resolverIdentity = candidateResolver(candidate);
    candidate.identityKind = candidateIdentityKind(candidate);
    candidate.semanticKind = candidateSemanticKind(candidate);
    if (candidate.graphKind === "type" && candidate.symbol === null) {
      addIssue(issueCollector, issue(
        "typescript_semantic_definition_symbol_missing",
        `TypeChecker did not bind type declaration ${candidate.displayName}`,
        candidate.source.relativePath,
      ));
      candidate.type = null;
    } else if (
      candidate.graphKind === "symbol"
      && candidate.node.kind !== SyntaxKind.Constructor
      && candidate.node.kind !== SyntaxKind.ArrowFunction
      && candidate.node.kind !== SyntaxKind.FunctionExpression
      && candidate.symbol === null
    ) {
      addIssue(issueCollector, issue(
        "typescript_semantic_definition_symbol_missing",
        `TypeChecker did not bind symbol declaration ${candidate.displayName}`,
        candidate.source.relativePath,
      ));
      candidate.type = null;
    }
  }

  const sourceByCompilerPath = new Map<string, TypeScriptSemanticSource>();
  for (const source of sources) {
    sourceByCompilerPath.set(compilerInternalPathKey(String(source.sourceFile.path)), source);
    sourceByCompilerPath.set(compilerInternalPathKey(source.sourceFile.fileName), source);
  }
  const { groups, candidateGroups } = createGroups(collection.candidates, sourceByCompilerPath, issueCollector);

  const definitions: TypeScriptRawDefinition[] = [];
  const relations: TypeScriptRawDefinitionRelation[] = [];
  for (const group of groups) {
    const owner = endpointForOwner(group.primary, candidateGroups);
    if (owner === null) {
      group.skipped = true;
      addIssue(issueCollector, issue(
        "typescript_semantic_definition_owner_missing",
        `Definition ${group.primary.displayName} has no compiler-confirmed semantic owner`,
        group.primary.source.relativePath,
      ));
      continue;
    }
    const definition: TypeScriptRawDefinition = {
      key: group.key,
      graphKind: group.graphKind,
      semanticKind: group.semanticKind,
      language: languageForPath(group.primary.source.relativePath),
      resolverIdentity: group.resolverIdentity,
      identityKind: group.identityKind,
      displayName: group.primary.displayName,
      relativePath: group.primary.source.relativePath,
      startOffset: group.primary.startOffset,
      endOffset: group.primary.endOffset,
      owner,
      ...(group.candidates.some((candidate) => candidate.exported) ? { exported: true as const } : {}),
    };
    definitions.push(definition);
    for (const candidate of group.candidates) {
      relations.push({
        kind: "declares",
        source: owner,
        target: group.key,
        evidence: evidence(candidate, `TypeChecker ${group.semanticKind} definition`),
      });
    }
  }

  const emittedGroups = new Map(groups.filter((group) => !group.skipped).map((group) => [group.ephemeralKey, group]));
  const symbolDefinitionsById = new Map<string, CandidateGroup>();
  const symbolDefinitionsByDeclaration = new Map<string, CandidateGroup>();
  for (const group of emittedGroups.values()) {
    if (group.symbol === null) continue;
    symbolDefinitionsById.set(symbolDefinitionIdKey(group.graphKind, group.symbol.id), group);
    for (const declaration of group.symbol.declarations) {
      symbolDefinitionsByDeclaration.set(symbolDefinitionDeclarationKey(group.graphKind, declaration), group);
    }
  }
  const symbolDefinitions: SymbolDefinitionIndex = {
    byId: symbolDefinitionsById,
    byDeclaration: symbolDefinitionsByDeclaration,
  };

  const parameterSymbols = await querySymbols(
    checker,
    collection.typeParameters.map((parameter) => parameter.node.name),
    counter,
    "type parameter",
  );
  for (const [index, parameter] of collection.typeParameters.entries()) {
    const symbol = parameterSymbols[index];
    parameter.symbol = symbol ?? null;
    if (symbol !== undefined && !await symbolDeclaresTypeParameter(symbol, parameter, counter)) {
      throw new TypeCheckerContractError("type parameter symbol did not match its requested owner and index", counter.value);
    }
  }
  const typeParameterDescriptors = new Map<number, TypeScriptRawTypeArgumentDescriptor>();
  for (const parameter of collection.typeParameters) {
    if (parameter.symbol === null) continue;
    const ownerGroup = candidateGroups.get(parameter.owner.index);
    if (ownerGroup === undefined || ownerGroup.skipped) continue;
    if (typeParameterDescriptors.has(parameter.symbol.id)) {
      throw new TypeCheckerContractError("a TypeChecker type parameter symbol was reused for multiple declarations", counter.value);
    }
    typeParameterDescriptors.set(parameter.symbol.id, {
      kind: "type_parameter",
      owner: ownerGroup.key,
      index: parameter.index,
      name: parameter.node.name.text,
    });
  }

  const heritageSymbols = await querySymbols(
    checker,
    collection.heritage.map((heritage) => heritage.node.expression),
    counter,
    "heritage",
  );
  const heritageTargetTypes = await queryTypes(
    checker,
    collection.heritage.map((heritage) => heritage.node.expression),
    counter,
    "heritage",
  );
  for (const [index, heritage] of collection.heritage.entries()) {
    const symbol = heritageSymbols[index];
    const targetType = heritageTargetTypes[index];
    const expectedName = terminalReferenceName(heritage.node.expression);
    if (symbol !== undefined && expectedName !== null && symbol.name !== expectedName) {
      throw new TypeCheckerContractError("heritage symbol did not match the requested reference name", counter.value);
    }
    const symbolTarget = symbol === undefined ? null : await unwrapAlias(checker, symbol, counter);
    let typeSymbol: CompilerSymbol | undefined;
    if (targetType !== undefined && !targetType.isErrorType()) {
      beginTypeCheckerQuery(counter);
      typeSymbol = await targetType.getAliasSymbol();
      if (typeSymbol === undefined) {
        beginTypeCheckerQuery(counter);
        typeSymbol = await targetType.getSymbol();
      }
    }
    const typeTarget = typeSymbol === undefined ? null : await unwrapAlias(checker, typeSymbol, counter);
    if (symbolTarget !== null && typeTarget !== null && symbolTarget.id !== typeTarget.id) {
      throw new TypeCheckerContractError("heritage symbol and type responses did not correlate", counter.value);
    }
    heritage.targetSymbol = symbolTarget ?? typeTarget;
  }
  const allTypeArgumentNodes: TypeNode[] = [];
  const seenTypeArgumentNodes = new Set<TypeNode>();
  const collectTypeArgument = (root: TypeNode): boolean => {
    const pending: { node: TypeNode; depth: number }[] = [{ node: root, depth: 0 }];
    while (pending.length > 0) {
      const current = pending.pop()!;
      if (current.depth > MAX_TYPE_DESCRIPTOR_DEPTH) return false;
      if (seenTypeArgumentNodes.has(current.node)) continue;
      seenTypeArgumentNodes.add(current.node);
      allTypeArgumentNodes.push(current.node);
      if (allTypeArgumentNodes.length > MAX_RELATIONS) return false;
      current.node.forEachChild((child) => {
        if (isTypeNode(child)) pending.push({ node: child, depth: current.depth + 1 });
        return undefined;
      });
    }
    return true;
  };
  let typeArgumentInputValid = true;
  for (const heritage of collection.heritage) {
    for (const argument of heritage.node.typeArguments ?? []) {
      if (!collectTypeArgument(argument)) typeArgumentInputValid = false;
    }
  }
  if (!typeArgumentInputValid) {
    addIssue(issueCollector, issue(
      "typescript_semantic_type_argument_ast_limit_exceeded",
      "TypeScript semantic type-argument AST exceeded its depth or node limit",
      null,
      true,
    ));
    return { definitions: [], relations: [], issues: deduplicateIssues(issueCollector), typeCheckerQueries: counter.value };
  }
  const allTypeArguments = await queryTypes(checker, allTypeArgumentNodes, counter, "type argument");
  const typeArgumentsByNode = new Map<TypeNode, CompilerType | undefined>();
  for (const [index, node] of allTypeArgumentNodes.entries()) {
    typeArgumentsByNode.set(node, allTypeArguments[index]);
  }

  const definitionByKey = new Map(definitions.map((definition) => [definition.key, definition]));
  for (const heritage of collection.heritage) {
    const ownerGroup = candidateGroups.get(heritage.owner.index);
    if (ownerGroup === undefined || ownerGroup.skipped) continue;
    const targetSymbol = heritage.targetSymbol;
    const targetGroup = targetSymbol === null ? undefined : lookupSymbolDefinition(targetSymbol, symbolDefinitions, "type");
    if (targetGroup === undefined || targetGroup.graphKind !== "type" || targetGroup.skipped) {
      addIssue(issueCollector, issue(
        "typescript_semantic_heritage_target_skipped",
        `Heritage target ${heritage.node.getText(heritage.owner.source.sourceFile).slice(0, MAX_DISPLAY_NAME_CHARS)} is unresolved or outside the confined definition graph`,
        heritage.owner.source.relativePath,
      ));
      continue;
    }
    const source: TypeScriptRawDefinitionEndpoint = { kind: "definition", key: ownerGroup.key };
    const explicitArguments = heritage.node.typeArguments ?? [];
    if (explicitArguments.length === 0) {
      relations.push({
        kind: heritage.relationKind,
        source,
        target: targetGroup.key,
        evidence: heritageEvidence(heritage, `TypeChecker ${heritage.relationKind} relation`),
      });
      continue;
    }
    if (explicitArguments.length > MAX_TYPE_ARGUMENTS) {
      addIssue(issueCollector, issue(
        "typescript_semantic_type_argument_limit_exceeded",
        `Generic heritage has ${explicitArguments.length} explicit arguments; limit=${MAX_TYPE_ARGUMENTS}`,
        heritage.owner.source.relativePath,
      ));
      continue;
    }
    const descriptors: TypeScriptRawTypeArgumentDescriptor[] = [];
    let canonical = true;
    for (const typeNode of explicitArguments) {
      const type = typeArgumentsByNode.get(typeNode);
      if (type === undefined) {
        canonical = false;
        break;
      }
      const descriptor = await typeDescriptor(
        type,
        typeNode,
        typeArgumentsByNode,
        symbolDefinitions,
        typeParameterDescriptors,
        counter,
        { nodes: 0 },
      );
      if (descriptor === null || JSON.stringify(descriptor).length > MAX_TYPE_ARGUMENT_DESCRIPTOR_CHARS) {
        canonical = false;
        break;
      }
      descriptors.push(descriptor);
    }
    if (!canonical || descriptors.length !== explicitArguments.length || targetGroup.resolverIdentity === null) {
      addIssue(issueCollector, issue(
        "typescript_semantic_generic_identity_skipped",
        `Generic heritage ${heritage.node.getText(heritage.owner.source.sourceFile).slice(0, MAX_DISPLAY_NAME_CHARS)} has no complete canonical type-argument identity`,
        heritage.owner.source.relativePath,
      ));
      continue;
    }
    const resolverIdentity = `generic:${JSON.stringify([targetGroup.key, descriptors])}`;
    if (resolverIdentity.length > MAX_RESOLVER_IDENTITY_CHARS) {
      addIssue(issueCollector, issue(
        "typescript_semantic_generic_identity_too_large",
        `Generic heritage identity exceeds ${MAX_RESOLVER_IDENTITY_CHARS} characters`,
        heritage.owner.source.relativePath,
      ));
      continue;
    }
    const displayName = heritage.node.getText(heritage.owner.source.sourceFile);
    if (displayName.length > MAX_DISPLAY_NAME_CHARS) {
      addIssue(issueCollector, issue(
        "typescript_semantic_generic_display_name_too_large",
        `Generic heritage display name exceeds ${MAX_DISPLAY_NAME_CHARS} characters`,
        heritage.owner.source.relativePath,
      ));
      continue;
    }
    const key = rawDefinitionKey(
      "type",
      "generic_instance",
      null,
      resolverIdentity,
      targetGroup.primary.source.relativePath,
      targetGroup.primary.startOffset,
      targetGroup.primary.endOffset,
    );
    if (!definitionByKey.has(key)) {
      const instance: TypeScriptRawDefinition = {
        key,
        graphKind: "type",
        semanticKind: "generic_instance",
        language: languageForPath(targetGroup.primary.source.relativePath),
        resolverIdentity,
        identityKind: null,
        displayName,
        relativePath: targetGroup.primary.source.relativePath,
        startOffset: targetGroup.primary.startOffset,
        endOffset: targetGroup.primary.endOffset,
        owner: { kind: "definition", key: targetGroup.key },
        genericOrigin: targetGroup.key,
        typeArguments: descriptors,
      };
      definitionByKey.set(key, instance);
      definitions.push(instance);
    }
    relations.push({
      kind: "instantiates",
      source,
      target: key,
      evidence: heritageEvidence(heritage, "TypeChecker generic heritage instantiation"),
    });
    relations.push({
      kind: heritage.relationKind,
      source,
      target: key,
      evidence: heritageEvidence(heritage, `TypeChecker generic ${heritage.relationKind} relation`),
    });
  }

  if (relations.length > MAX_RELATIONS) {
    addIssue(issueCollector, issue(
      "typescript_semantic_relation_limit_exceeded",
      `TypeScript semantic definition extraction produced ${relations.length} relations; limit=${MAX_RELATIONS}`,
      null,
      true,
    ));
    return { definitions: [], relations: [], issues: deduplicateIssues(issueCollector), typeCheckerQueries: counter.value };
  }

  const sortedDefinitions = definitions.sort(sortDefinitions);
  const sortedRelations = deduplicateRelations(relations);
  try {
    validateTypeScriptRawDefinitionDelta(
      { definitions: sortedDefinitions, relations: sortedRelations },
      sources,
    );
  } catch (error) {
    addIssue(issueCollector, issue(
      "typescript_semantic_delta_invalid",
      `TypeScript semantic definition delta failed validation: ${error instanceof Error ? error.message : String(error)}`,
      null,
      true,
    ));
    return { definitions: [], relations: [], issues: deduplicateIssues(issueCollector), typeCheckerQueries: counter.value };
  }
  return {
    definitions: sortedDefinitions,
    relations: sortedRelations,
    issues: deduplicateIssues(issueCollector),
    typeCheckerQueries: counter.value,
  };
}

export async function extractTypeScriptRawDefinitionDelta(
  checker: Checker,
  sources: readonly TypeScriptSemanticSource[],
): Promise<TypeScriptRawDefinitionDelta> {
  try {
    return await extractTypeScriptRawDefinitionDeltaUnchecked(checker, sources);
  } catch (error) {
    if (!(error instanceof TypeCheckerContractError)) throw error;
    return {
      definitions: [],
      relations: [],
      issues: [issue(
        "typescript_semantic_typechecker_contract_violation",
        `TypeChecker semantic response failed correlation: ${error.message}`,
        null,
        true,
      )],
      typeCheckerQueries: error.typeCheckerQueries,
    };
  }
}
