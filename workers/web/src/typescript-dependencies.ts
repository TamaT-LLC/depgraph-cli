import { isBuiltin } from "node:module";
import {
  ModifierFlags,
  SignatureKind,
  SymbolFlags,
  TypeFlags,
  type Checker,
  type Signature,
  type Symbol as CompilerSymbol,
  type Type as CompilerType,
} from "typescript/unstable/async";
import {
  type CallExpression,
  createScanner,
  type Expression,
  LanguageVariant,
  type MethodDeclaration,
  type NewExpression,
  NodeFlags,
  SyntaxKind,
  type TaggedTemplateExpression,
  tokenIsIdentifierOrKeyword,
  type ExportAssignment,
  type ExportDeclaration,
  type ExportSpecifier,
  type Identifier,
  type ImportDeclaration,
  type ImportEqualsDeclaration,
  type ImportSpecifier,
  type ImportTypeNode,
  type JSDocImportTag,
  type Node,
  type SourceFile,
  type TypeReferenceNode,
  type TypeQueryNode,
  type VariableDeclaration,
} from "typescript/unstable/ast";
import type {
  TypeScriptRawDefinition,
  TypeScriptRawDefinitionDelta,
  TypeScriptRawDefinitionEndpoint,
  TypeScriptSemanticIssue,
  TypeScriptSemanticSource,
} from "./typescript-semantic";
import { scanTypeScriptSyntaxTokens } from "./imports";
import { aggregateConditions, canonicalizeCondition, WEB_CONDITION, type Condition } from "./types";
import {
  basisForTargets,
  beginQuery,
  bindingScopeSpan,
  callCallee,
  callOccurrenceKind,
  callSpecifier,
  childTraversalKey,
  compareStrings,
  compilerPathKey,
  DependencyContractError,
  hasUnpairedSurrogate,
  isAmbientRequireSymbol,
  isCanonicalRelativePath,
  isLexicallyShadowedBinding,
  isModuleLoaderCall,
  MAX_AST_DEPTH,
  MAX_AST_NODES,
  MAX_CONDITION_DEPTH,
  MAX_CONDITION_NODES,
  MAX_CONDITION_VALUES,
  MAX_EXPORT_PATH_DEPTH,
  MAX_EXPORTS_PER_MODULE,
  MAX_MODULE_EXPORT_BINDINGS,
  MAX_SITES,
  MAX_SPECIFIER_CHARS,
  MAX_SYMBOL_DECLARATIONS,
  nodeEnd,
  nodeSpan,
  nodeStart,
  NO_RESOLUTION_MODE,
  querySymbol,
  resolutionModeDirective,
  resolutionModeForOccurrence,
  siteKey,
  stringLiteralText,
  targetSortKey,
  terminalIdentifier,
  transparentCallExpression,
  TYPESCRIPT_CLOSED_LOCAL_CALL_FLOW_ALGORITHM,
  TYPESCRIPT_CLOSED_LOCAL_FRESH_INSTANCE_FLOW_ALGORITHM,
} from "./typescript-dependency-contract";
import type {
  QueryCounter,
  ResolutionModeDirective,
  TypeScriptBindingKind,
  TypeScriptRawCallDispatch,
  TypeScriptRawCallKind,
  TypeScriptRawCallSite,
  TypeScriptRawCallSource,
  TypeScriptRawDependencyDelta,
  TypeScriptRawDependencyEdgeKind,
  TypeScriptRawDependencyEvidence,
  TypeScriptRawDependencyPrecision,
  TypeScriptRawDependencySite,
  TypeScriptRawDependencySiteKind,
  TypeScriptRawDependencyStatus,
  TypeScriptRawDependencyTarget,
  TypeScriptRawModuleExport,
  TypeScriptResolutionMode,
} from "./typescript-dependency-contract";
import {
  moduleCallValidationOccurrence,
  sortModuleCallValidationSpans,
  validateTypeScriptRawDependencyDelta,
} from "./typescript-dependency-validation";
import type {
  TypeScriptCallValidationSpan,
  TypeScriptDependencyValidationSource,
  TypeScriptDependencyValidationTarget,
  TypeScriptModuleCallValidationSpan,
  TypeScriptNonLiteralModuleValidationSpan,
  TypeScriptTypeUseValidationSpan,
} from "./typescript-dependency-validation";

const MAX_CLOSED_CALL_FLOW_DEPTH = 64;

interface DefinitionIndex {
  definitions: ReadonlyMap<string, TypeScriptRawDefinition>;
  byDeclaration: ReadonlyMap<string, readonly string[]>;
  declarationLocationsByDefinition: ReadonlyMap<string, readonly string[]>;
  heritageBySource: ReadonlyMap<string, readonly {
    startOffset: number;
    endOffset: number;
    target: string;
  }[]>;
}

interface FreshReceiverProofState {
  identifierIndex: ReadonlyMap<string, readonly Identifier[]> | null;
  indexFailed: boolean;
  useProofs: Map<string, boolean>;
}

interface CollectionContext {
  source: TypeScriptSemanticSource;
  owner: TypeScriptRawDefinitionEndpoint;
  syntacticallyValid: boolean;
  externalBindings: BindingProvenanceMap;
  bindingProvenance: ReadonlyMap<string, BindingProvenance>;
  freshReceiverProof: FreshReceiverProofState;
}

type BindingKind = TypeScriptBindingKind;

interface BindingProvenance {
  moduleSpecifier: string;
  importedName: string;
  exportPath: string[];
  targets: TypeScriptRawDependencyTarget[];
  resolutionMode: TypeScriptResolutionMode | null;
  resolutionModeError: string | null;
  resolutionModeProof?: NonNullable<TypeScriptRawDependencySite["resolutionModeProof"]>;
  bindingKind?: BindingKind;
  typeOnly?: boolean;
  bindingOrigin?: {
    declarationStartOffset: number;
    declarationEndOffset: number;
    scopeStartOffset: number;
    scopeEndOffset: number;
  };
  bindingReference?: {
    startOffset: number;
    endOffset: number;
  };
}

interface StructuredBindingSpecifier {
  kind: "binding";
  moduleSpecifier: string;
  importedName: string;
  bindingKind: BindingKind;
}

class BindingProvenanceMap extends Map<number, BindingProvenance> {
  readonly #ambiguousSymbols = new Set<number>();

  override set(symbolId: number, provenance: BindingProvenance): this {
    if (!this.#ambiguousSymbols.has(symbolId)) super.set(symbolId, provenance);
    return this;
  }

  markAmbiguous(symbolId: number): void {
    super.delete(symbolId);
    this.#ambiguousSymbols.add(symbolId);
  }

  isAmbiguous(symbolId: number): boolean {
    return this.#ambiguousSymbols.has(symbolId);
  }
}

function declarationKey(relativePath: string, startOffset: number, endOffset: number): string {
  return JSON.stringify([relativePath, startOffset, endOffset]);
}

function bindingDeclarationOrigin(binding: Node): NonNullable<BindingProvenance["bindingOrigin"]> {
  const sourceFile = binding.getSourceFile();
  const { startOffset, endOffset } = nodeSpan(binding, sourceFile);
  const { startOffset: scopeStartOffset, endOffset: scopeEndOffset } = bindingScopeSpan(binding);
  return {
    declarationStartOffset: startOffset,
    declarationEndOffset: endOffset,
    scopeStartOffset,
    scopeEndOffset,
  };
}

function withBindingReference(
  provenance: BindingProvenance,
  reference: Node,
  sourceFile: SourceFile,
): BindingProvenance {
  if (provenance.bindingOrigin === undefined) {
    return provenance;
  }
  const { startOffset, endOffset } = nodeSpan(reference, sourceFile);
  return {
    ...provenance,
    bindingReference: { startOffset, endOffset },
  };
}

async function queryTypeSymbol(
  checker: Checker,
  node: Node,
  counter: QueryCounter,
  purpose: string,
): Promise<CompilerSymbol | undefined> {
  const type = await queryTypeAtLocation(checker, node, counter, purpose);
  if (type === undefined) return undefined;
  beginQuery(counter);
  const alias = await type.getAliasSymbol();
  if (alias !== undefined) return alias;
  beginQuery(counter);
  return await type.getSymbol();
}

async function queryTypeAtLocation(
  checker: Checker,
  node: Node,
  counter: QueryCounter,
  purpose: string,
): Promise<CompilerType | undefined> {
  beginQuery(counter);
  const batch = await checker.getTypeAtLocation([node]);
  if (!Array.isArray(batch) || batch.length !== 1) throw new DependencyContractError(`${purpose} type batch cardinality mismatch`);
  beginQuery(counter);
  const singleton = await checker.getTypeAtLocation(node);
  if (batch[0]?.id !== singleton?.id) throw new DependencyContractError(`${purpose} type response correlation mismatch`);
  const type: CompilerType | undefined = batch[0];
  return type === undefined || type.isErrorType() ? undefined : type;
}

async function queryTypeOfSymbol(
  checker: Checker,
  symbol: CompilerSymbol,
  counter: QueryCounter,
  purpose: string,
): Promise<CompilerType | undefined> {
  beginQuery(counter);
  const batch = await checker.getTypeOfSymbol([symbol]);
  if (!Array.isArray(batch) || batch.length !== 1) {
    throw new DependencyContractError(`${purpose} type batch cardinality mismatch`);
  }
  beginQuery(counter);
  const singleton = await checker.getTypeOfSymbol(symbol);
  if (batch[0]?.id !== singleton?.id) {
    throw new DependencyContractError(`${purpose} type response correlation mismatch`);
  }
  const type: CompilerType | undefined = batch[0];
  return type === undefined || type.isErrorType() ? undefined : type;
}

async function compilerTypeSymbol(
  type: CompilerType,
  counter: QueryCounter,
): Promise<CompilerSymbol | undefined> {
  beginQuery(counter);
  const alias = await type.getAliasSymbol();
  if (alias !== undefined) return alias;
  beginQuery(counter);
  return await type.getSymbol();
}

async function unwrapAlias(
  checker: Checker,
  symbol: CompilerSymbol,
  counter: QueryCounter,
): Promise<CompilerSymbol | null> {
  if ((symbol.flags & SymbolFlags.Alias) === 0) return symbol;
  beginQuery(counter);
  const target = await checker.getAliasedSymbol(symbol);
  beginQuery(counter);
  return await checker.isUnknownSymbol(target) ? null : target;
}

function leftmostIdentifier(node: Node): Identifier | null {
  if (node.kind === SyntaxKind.Identifier) return node as Identifier;
  if (node.kind === SyntaxKind.QualifiedName) {
    return leftmostIdentifier((node as Node & { readonly left: Node }).left);
  }
  if (node.kind === SyntaxKind.PropertyAccessExpression) {
    return leftmostIdentifier((node as Node & { readonly expression: Node }).expression);
  }
  return null;
}

function qualifiedIdentifierPath(node: Node): Identifier[] {
  if (node.kind === SyntaxKind.Identifier) return [node as Identifier];
  if (node.kind === SyntaxKind.QualifiedName) {
    return [
      ...qualifiedIdentifierPath((node as Node & { readonly left: Node }).left),
      (node as Node & { readonly right: Identifier }).right,
    ];
  }
  if (node.kind === SyntaxKind.PropertyAccessExpression) {
    return [
      ...qualifiedIdentifierPath((node as Node & { readonly expression: Node }).expression),
      (node as Node & { readonly name: Identifier }).name,
    ];
  }
  return [];
}

function packageName(specifier: string): string {
  const parts = specifier.split("/");
  return specifier.startsWith("@") ? parts.slice(0, 2).join("/") : parts[0] ?? specifier;
}

function externalTarget(specifier: string, symbolName?: string): TypeScriptRawDependencyTarget {
  const identity = specifier.startsWith("typescript:stdlib:")
    ? specifier
    : isBuiltin(specifier)
      ? specifier.startsWith("node:") ? specifier : `node:${specifier}`
      : `npm:${packageName(specifier)}`;
  return {
    kind: "external",
    locator: identity,
    displayName: symbolName === undefined ? identity : `${identity}#${symbolName}`,
  };
}

function isExternalModuleSpecifier(specifier: string): boolean {
  return specifier.length > 0 && !specifier.startsWith(".") && !specifier.startsWith("/");
}

function structuredBindingSpecifier(
  moduleSpecifier: string,
  importedName: string,
  bindingKind: BindingKind,
): StructuredBindingSpecifier {
  return { kind: "binding", moduleSpecifier, importedName, bindingKind };
}

function deduplicateTargets(targets: readonly TypeScriptRawDependencyTarget[]): TypeScriptRawDependencyTarget[] {
  return [...new Map(targets.map((target) => [targetSortKey(target), target])).entries()]
    .sort(([left], [right]) => compareStrings(left, right))
    .map(([, target]) => target);
}

function typeUseTargets(
  targets: readonly TypeScriptRawDependencyTarget[],
  index: DefinitionIndex,
): TypeScriptRawDependencyTarget[] {
  return targets.filter((target) => (
    target.kind === "external"
    || (target.kind === "definition" && index.definitions.get(target.key)?.graphKind === "type")
  ));
}

function definitionIndex(delta: TypeScriptRawDefinitionDelta): DefinitionIndex {
  const definitions = new Map(delta.definitions.map((definition) => [definition.key, definition]));
  const byDeclarationMutable = new Map<string, Set<string>>();
  const declarationLocationsByDefinitionMutable = new Map<string, Set<string>>();
  const heritageBySourceMutable = new Map<string, Array<{ startOffset: number; endOffset: number; target: string }>>();
  const add = (relativePath: string, startOffset: number, endOffset: number, key: string): void => {
    const location = declarationKey(relativePath, startOffset, endOffset);
    const keys = byDeclarationMutable.get(location) ?? new Set<string>();
    keys.add(key);
    byDeclarationMutable.set(location, keys);
    const locations = declarationLocationsByDefinitionMutable.get(key) ?? new Set<string>();
    locations.add(location);
    declarationLocationsByDefinitionMutable.set(key, locations);
  };
  for (const definition of delta.definitions) {
    if (definition.semanticKind !== "generic_instance") {
      add(definition.relativePath, definition.startOffset, definition.endOffset, definition.key);
    }
  }
  for (const relation of delta.relations) {
    if (relation.kind === "declares" && definitions.get(relation.target)?.semanticKind !== "generic_instance") {
      add(relation.evidence.relativePath, relation.evidence.startOffset, relation.evidence.endOffset, relation.target);
    } else if (relation.kind === "extends" || relation.kind === "implements") {
      const target = definitions.get(relation.target);
      const canonicalTarget = target?.semanticKind === "generic_instance" ? target.genericOrigin : target?.key;
      if (canonicalTarget !== undefined) {
        const entries = heritageBySourceMutable.get(relation.evidence.relativePath) ?? [];
        entries.push({
          startOffset: relation.evidence.startOffset,
          endOffset: relation.evidence.endOffset,
          target: canonicalTarget,
        });
        heritageBySourceMutable.set(relation.evidence.relativePath, entries);
      }
    }
  }
  return {
    definitions,
    byDeclaration: new Map([...byDeclarationMutable].map(([location, keys]) => [location, [...keys].sort(compareStrings)])),
    declarationLocationsByDefinition: new Map([...declarationLocationsByDefinitionMutable].map(([key, locations]) => [
      key,
      [...locations].sort(compareStrings),
    ])),
    heritageBySource: new Map([...heritageBySourceMutable].map(([relativePath, entries]) => [
      relativePath,
      entries.sort((left, right) => left.startOffset - right.startOffset
        || left.endOffset - right.endOffset
        || compareStrings(left.target, right.target)),
    ])),
  };
}

function compilerProvenHeritageTargets(
  index: DefinitionIndex,
  context: CollectionContext,
  node: Node,
): TypeScriptRawDependencyTarget[] {
  const { startOffset, endOffset } = nodeSpan(node, context.source.sourceFile);
  return deduplicateTargets((index.heritageBySource.get(context.source.relativePath) ?? [])
    .filter((entry) => entry.startOffset <= startOffset && entry.endOffset >= endOffset)
    .map((entry) => ({ kind: "definition" as const, key: entry.target })));
}

function ownerAtNode(
  index: DefinitionIndex,
  source: TypeScriptSemanticSource,
  node: Node,
): TypeScriptRawDefinitionEndpoint | null {
  if (node.kind === SyntaxKind.SourceFile) return null;
  const { startOffset, endOffset } = nodeSpan(node, source.sourceFile, true);
  if (startOffset === endOffset) return null;
  const keys = index.byDeclaration.get(declarationKey(
    source.relativePath,
    startOffset,
    endOffset,
  ));
  if (keys?.length !== 1) return null;
  return { kind: "definition", key: keys[0]! };
}

function sourcePathMap(sources: readonly TypeScriptSemanticSource[]): Map<string, TypeScriptSemanticSource> {
  const result = new Map<string, TypeScriptSemanticSource>();
  for (const source of sources) {
    for (const [label, candidate] of [
      ["compilerPath", source.compilerPath],
      ["sourceFile.path", String(source.sourceFile.path)],
      ["sourceFile.fileName", source.sourceFile.fileName],
    ] as const) {
      const key = compilerPathKey(candidate);
      const existing = result.get(key);
      if (existing !== undefined && existing.relativePath !== source.relativePath) {
        throw new DependencyContractError(
          `TypeScript dependency source paths collide after compiler normalization at ${label}: ${key} (${existing.relativePath}, ${source.relativePath})`,
        );
      }
      result.set(key, source);
    }
  }
  return result;
}

async function compilerSymbolTargets(
  symbol: CompilerSymbol,
  checker: Checker,
  counter: QueryCounter,
  index: DefinitionIndex,
  sourcesByPath: ReadonlyMap<string, TypeScriptSemanticSource>,
  preferType: boolean,
  allowCrossSourceDeclaration = false,
): Promise<{ targets: TypeScriptRawDependencyTarget[]; external: boolean; repositoryDeclarations: boolean }> {
  const unwrapped = await unwrapAlias(checker, symbol, counter);
  if (unwrapped === null) return { targets: [], external: false, repositoryDeclarations: false };
  if (unwrapped.declarations.length > MAX_SYMBOL_DECLARATIONS) throw new DependencyContractError("dependency symbol declaration limit exceeded");
  const definitions: TypeScriptRawDependencyTarget[] = [];
  const files: TypeScriptRawDependencyTarget[] = [];
  let external = false;
  let repositoryDeclarations = false;
  for (const declaration of unwrapped.declarations) {
    const declaredSource = sourcesByPath.get(compilerPathKey(String(declaration.path)));
    if (declaredSource === undefined) {
      external = true;
      continue;
    }
    repositoryDeclarations = true;
    beginQuery(counter);
    const resolved = await declaration.resolve();
    if (resolved === undefined) continue;
    const resolvedSource = resolved.getSourceFile();
    const source = sourcesByPath.get(compilerPathKey(String(resolvedSource.path)))
      ?? sourcesByPath.get(compilerPathKey(resolvedSource.fileName));
    if (source === undefined) {
      external = true;
      continue;
    }
    if (
      !allowCrossSourceDeclaration
      && compilerPathKey(source.compilerPath) !== compilerPathKey(declaredSource.compilerPath)
    ) {
      throw new DependencyContractError(
        `dependency declaration resolved to a mismatched source (${declaredSource.relativePath}, ${source.relativePath})`,
      );
    }
    if (resolved.kind === SyntaxKind.SourceFile) {
      files.push({ kind: "file", relativePath: source.relativePath });
      continue;
    }
    const { startOffset, endOffset } = nodeSpan(resolved, source.sourceFile);
    const keys = index.byDeclaration.get(declarationKey(source.relativePath, startOffset, endOffset)) ?? [];
    for (const key of keys) definitions.push({ kind: "definition", key });
  }
  const canonicalDefinitions = deduplicateTargets(definitions).filter((target): target is Extract<TypeScriptRawDependencyTarget, { kind: "definition" }> => target.kind === "definition");
  const preferred = canonicalDefinitions.filter((target) => index.definitions.get(target.key)?.graphKind === (preferType ? "type" : "symbol"));
  const alternate = canonicalDefinitions.filter((target) => index.definitions.get(target.key)?.graphKind === (preferType ? "symbol" : "type"));
  const selected = preferred.length > 0 ? preferred : alternate.length > 0 ? alternate : canonicalDefinitions;
  return { targets: selected.length > 0 ? selected : deduplicateTargets(files), external, repositoryDeclarations };
}

async function collectModuleExportProofs(
  checker: Checker,
  counter: QueryCounter,
  sources: readonly TypeScriptSemanticSource[],
  index: DefinitionIndex,
  sourcesByPath: ReadonlyMap<string, TypeScriptSemanticSource>,
  requestedExportPaths: readonly (readonly string[])[],
  requestedExportEqualsPaths: readonly (readonly string[])[],
): Promise<TypeScriptRawModuleExport[]> {
  const requested = [...new Map(requestedExportPaths.map((exportPath) => [
    JSON.stringify(exportPath),
    [...exportPath],
  ] as const)).values()].sort((left, right) => compareStrings(JSON.stringify(left), JSON.stringify(right)));
  if (requested.length === 0) return [];
  const requestedKeys = new Set(requested.map((exportPath) => JSON.stringify(exportPath)));
  const requestedPrefixKeys = new Set<string>();
  for (const exportPath of requested) {
    for (let length = 1; length < exportPath.length; length += 1) {
      requestedPrefixKeys.add(JSON.stringify(exportPath.slice(0, length)));
    }
  }
  const requestedExportEquals = [...new Map(requestedExportEqualsPaths.map((exportPath) => [
    JSON.stringify(exportPath),
    [...exportPath],
  ] as const)).values()];
  const requestedExportEqualsKeys = new Set(requestedExportEquals.map((exportPath) => JSON.stringify(exportPath)));
  const requestedExportEqualsPrefixKeys = new Set<string>();
  for (const exportPath of requestedExportEquals) {
    for (let length = 1; length < exportPath.length; length += 1) {
      requestedExportEqualsPrefixKeys.add(JSON.stringify(exportPath.slice(0, length)));
    }
  }
  const proofKeys = new Map<string, {
    relativePath: string;
    exportPath: string[];
    definitionKeys: Set<string>;
  }>();
  let traversedBindings = 0;
  const recordSymbolProof = async (
    source: TypeScriptSemanticSource,
    exportPath: string[],
    symbol: CompilerSymbol,
  ): Promise<void> => {
    const valueTargets = await compilerSymbolTargets(symbol, checker, counter, index, sourcesByPath, false, true);
    const typeTargets = await compilerSymbolTargets(symbol, checker, counter, index, sourcesByPath, true, true);
    const definitionKeys = [...new Set([...valueTargets.targets, ...typeTargets.targets]
      .filter((target): target is Extract<TypeScriptRawDependencyTarget, { kind: "definition" }> => target.kind === "definition")
      .map((target) => target.key)
      .filter((key) => index.definitions.get(key)?.semanticKind !== "generic_instance"))]
      .sort(compareStrings);
    if (definitionKeys.length > MAX_EXPORTS_PER_MODULE) {
      throw new DependencyContractError("module export target response exceeds its bounded cardinality");
    }
    if (definitionKeys.length === 0) return;
    const proofKey = JSON.stringify([source.relativePath, exportPath]);
    const proof = proofKeys.get(proofKey) ?? {
      relativePath: source.relativePath,
      exportPath,
      definitionKeys: new Set<string>(),
    };
    for (const key of definitionKeys) proof.definitionKeys.add(key);
    proofKeys.set(proofKey, proof);
  };
  const queryExports = async (moduleSymbol: CompilerSymbol): Promise<CompilerSymbol[]> => {
    beginQuery(counter);
    const first = await checker.getExportsOfModule(moduleSymbol);
    if (!Array.isArray(first) || first.length > MAX_EXPORTS_PER_MODULE) {
      throw new DependencyContractError("module export response exceeds its bounded cardinality");
    }
    beginQuery(counter);
    const second = await checker.getExportsOfModule(moduleSymbol);
    if (!Array.isArray(second) || second.length > MAX_EXPORTS_PER_MODULE) {
      throw new DependencyContractError("module export response exceeds its bounded cardinality");
    }
    const canonical = (symbols: readonly CompilerSymbol[]): CompilerSymbol[] => {
      const sorted = [...symbols].sort((left, right) => left.id - right.id || compareStrings(left.name, right.name));
      for (let indexValue = 1; indexValue < sorted.length; indexValue += 1) {
        if (sorted[indexValue - 1]!.id === sorted[indexValue]!.id && sorted[indexValue - 1]!.name === sorted[indexValue]!.name) {
          throw new DependencyContractError("module export response contains duplicate symbols");
        }
      }
      return sorted;
    };
    const firstCanonical = canonical(first);
    const secondCanonical = canonical(second);
    if (
      secondCanonical.length !== firstCanonical.length
      || firstCanonical.some((symbol, indexValue) => (
        symbol.id !== secondCanonical[indexValue]?.id || symbol.name !== secondCanonical[indexValue]?.name
      ))
    ) throw new DependencyContractError("module export response correlation mismatch");
    return firstCanonical;
  };
  const queryProperties = async (type: CompilerType): Promise<CompilerSymbol[]> => {
    beginQuery(counter);
    const first = await checker.getPropertiesOfType(type);
    if (!Array.isArray(first) || first.length > MAX_EXPORTS_PER_MODULE) {
      throw new DependencyContractError("export-equals property response exceeds its bounded cardinality");
    }
    beginQuery(counter);
    const second = await checker.getPropertiesOfType(type);
    if (!Array.isArray(second) || second.length > MAX_EXPORTS_PER_MODULE) {
      throw new DependencyContractError("export-equals property response exceeds its bounded cardinality");
    }
    const canonical = (symbols: readonly CompilerSymbol[]): CompilerSymbol[] => (
      [...symbols].sort((left, right) => left.id - right.id || compareStrings(left.name, right.name))
    );
    const firstCanonical = canonical(first);
    const secondCanonical = canonical(second);
    if (
      secondCanonical.length !== firstCanonical.length
      || firstCanonical.some((symbol, indexValue) => (
        symbol.id !== secondCanonical[indexValue]?.id || symbol.name !== secondCanonical[indexValue]?.name
      ))
    ) throw new DependencyContractError("export-equals property response correlation mismatch");
    for (let indexValue = 1; indexValue < firstCanonical.length; indexValue += 1) {
      if (
        firstCanonical[indexValue - 1]!.id === firstCanonical[indexValue]!.id
        && firstCanonical[indexValue - 1]!.name === firstCanonical[indexValue]!.name
      ) throw new DependencyContractError("export-equals property response contains duplicate symbols");
    }
    return firstCanonical;
  };
  const visitTypeProperties = async (
    source: TypeScriptSemanticSource,
    type: CompilerType,
    prefix: readonly string[],
  ): Promise<void> => {
    if (prefix.length >= MAX_EXPORT_PATH_DEPTH) {
      throw new DependencyContractError("export-equals property path depth limit exceeded");
    }
    const properties = await queryProperties(type);
    for (const property of properties) {
      traversedBindings += 1;
      if (traversedBindings > MAX_MODULE_EXPORT_BINDINGS) {
        throw new DependencyContractError("module export proof limit exceeded");
      }
      if (property.name.length > 512 || hasUnpairedSurrogate(property.name)) {
        throw new DependencyContractError("export-equals property name is invalid");
      }
      const exportPath = [...prefix, property.name];
      const exportPathKey = JSON.stringify(exportPath);
      const requestedLeaf = requestedExportEqualsKeys.has(exportPathKey);
      const requestedPrefix = requestedExportEqualsPrefixKeys.has(exportPathKey);
      if (!requestedLeaf && !requestedPrefix) continue;
      const propertyType = await queryTypeOfSymbol(checker, property, counter, "export-equals property");
      if (requestedLeaf) {
        await recordSymbolProof(source, exportPath, property);
        if (propertyType !== undefined) {
          const typeSymbol = await compilerTypeSymbol(propertyType, counter);
          if (typeSymbol !== undefined) await recordSymbolProof(source, exportPath, typeSymbol);
        }
      }
      if (requestedPrefix && propertyType !== undefined) {
        await visitTypeProperties(source, propertyType, exportPath);
      }
    }
  };
  const visitExports = async (
    source: TypeScriptSemanticSource,
    moduleSymbol: CompilerSymbol,
    prefix: readonly string[],
    leafKeys: ReadonlySet<string> = requestedKeys,
    prefixKeys: ReadonlySet<string> = requestedPrefixKeys,
  ): Promise<void> => {
    if (prefix.length >= MAX_EXPORT_PATH_DEPTH) throw new DependencyContractError("module export path depth limit exceeded");
    const exports = await queryExports(moduleSymbol);
    for (const exported of exports) {
      traversedBindings += 1;
      if (traversedBindings > MAX_MODULE_EXPORT_BINDINGS) {
        throw new DependencyContractError("module export proof limit exceeded");
      }
      if (
        exported.name.length > 512
        || hasUnpairedSurrogate(exported.name)
      ) throw new DependencyContractError("module export name is invalid");
      const exportPath = [...prefix, exported.name];
      const exportPathKey = JSON.stringify(exportPath);
      const requestedLeaf = leafKeys.has(exportPathKey);
      const requestedPrefix = prefixKeys.has(exportPathKey);
      if (!requestedLeaf && !requestedPrefix) continue;
      if (requestedLeaf) {
        await recordSymbolProof(source, exportPath, exported);
      }
      if (!requestedPrefix) continue;
      const unwrapped = await unwrapAlias(checker, exported, counter);
      if (unwrapped !== null && (unwrapped.flags & SymbolFlags.Module) !== 0) {
        // Cyclic namespace exports are finite when traversal is constrained by
        // an actual occurrence path. Do not reject a repeated module symbol;
        // the requested path length and MAX_EXPORT_PATH_DEPTH bound recursion.
        await visitExports(source, unwrapped, exportPath, leafKeys, prefixKeys);
      }
    }
  };
  for (const source of [...sources].sort((left, right) => compareStrings(left.relativePath, right.relativePath))) {
    if (!source.syntacticallyValid) continue;
    const moduleSymbol = await querySymbol(checker, source.sourceFile, counter, "source module");
    if (moduleSymbol === undefined) continue;
    await visitExports(source, moduleSymbol, []);
    const exportEqualsPaths: string[][] = [];
    if (requestedExportEqualsKeys.has(JSON.stringify([]))) exportEqualsPaths.push([]);
    if (requestedKeys.has(JSON.stringify(["default"]))) exportEqualsPaths.push(["default"]);
    const nestedExportEqualsRequested = requestedExportEquals.some((exportPath) => exportPath.length > 0);
    if (exportEqualsPaths.length > 0 || nestedExportEqualsRequested) {
      for (const statement of source.sourceFile.statements) {
        if (statement.kind !== SyntaxKind.ExportAssignment || !(statement as ExportAssignment).isExportEquals) continue;
        traversedBindings += 1;
        if (traversedBindings > MAX_MODULE_EXPORT_BINDINGS) {
          throw new DependencyContractError("module export proof limit exceeded");
        }
        const assignment = statement as ExportAssignment;
        const assignmentType = nestedExportEqualsRequested || exportEqualsPaths.length > 0
          ? await queryTypeAtLocation(checker, assignment.expression, counter, "export-equals target")
          : undefined;
        const symbol = await querySymbol(checker, assignment.expression, counter, "export-equals target");
        if (symbol !== undefined) {
          const target = await unwrapAlias(checker, symbol, counter);
          if (target === null) continue;
          for (const exportPath of exportEqualsPaths) await recordSymbolProof(source, exportPath, target);
          if (nestedExportEqualsRequested) {
            await visitExports(
              source,
              target,
              [],
              requestedExportEqualsKeys,
              requestedExportEqualsPrefixKeys,
            );
          }
        }
        if (assignmentType !== undefined) {
          const typeSymbol = await compilerTypeSymbol(assignmentType, counter);
          if (typeSymbol !== undefined) {
            for (const exportPath of exportEqualsPaths) await recordSymbolProof(source, exportPath, typeSymbol);
          }
          if (nestedExportEqualsRequested) await visitTypeProperties(source, assignmentType, []);
        }
      }
    }
  }
  return [...proofKeys.values()].map((proof) => ({
    relativePath: proof.relativePath,
    exportPath: proof.exportPath,
    definitionKeys: [...proof.definitionKeys].sort(compareStrings),
  })).sort((left, right) => compareStrings(left.relativePath, right.relativePath)
    || compareStrings(JSON.stringify(left.exportPath), JSON.stringify(right.exportPath)));
}

function createSite(
  context: CollectionContext,
  kind: TypeScriptRawDependencySiteKind,
  edgeKind: TypeScriptRawDependencyEdgeKind,
  occurrenceKind: string,
  anchor: Node,
  specifier: string | StructuredBindingSpecifier,
  targetsValue: readonly TypeScriptRawDependencyTarget[],
  reasonValue: string | null,
  detail: string,
  typeOnly = false,
  bindingMetadata?: Pick<BindingProvenance,
  | "moduleSpecifier"
  | "importedName"
  | "exportPath"
  | "resolutionMode"
  | "resolutionModeError"
  | "resolutionModeProof"
  | "bindingKind"
  | "bindingOrigin"
  | "bindingReference">,
  explicitResolutionMode: ResolutionModeDirective = NO_RESOLUTION_MODE,
): TypeScriptRawDependencySite {
  const { startOffset, endOffset } = nodeSpan(anchor, context.source.sourceFile);
  // Import and re-export sites belong to the source file in the public graph
  // contract even when their syntax is nested inside a semantic definition.
  // Named type uses retain the nearest definition owner so member/signature
  // dependencies remain attributable to their declaring symbol or type.
  const source: TypeScriptRawDefinitionEndpoint = kind === "type_use"
    ? context.owner
    : { kind: "file", relativePath: context.source.relativePath };
  const directive = bindingMetadata === undefined
    ? explicitResolutionMode
    : {
      mode: bindingMetadata.resolutionMode,
      error: bindingMetadata.resolutionModeError,
      ...(bindingMetadata.resolutionModeProof === undefined ? {} : { proof: bindingMetadata.resolutionModeProof }),
    };
  let targets = deduplicateTargets(targetsValue);
  let status: TypeScriptRawDependencyStatus;
  let precision: TypeScriptRawDependencyPrecision;
  let reason = reasonValue;
  if (!context.syntacticallyValid) {
    targets = [{ kind: "unknown" }];
    status = "unresolved";
    precision = "heuristic";
    reason = "syntax_invalid";
  } else if (directive.error !== null) {
    targets = [{ kind: "unknown" }];
    status = "unresolved";
    precision = "heuristic";
    reason = directive.error;
  } else if (targets.length === 0 || targets.some((target) => target.kind === "unknown")) {
    targets = [{ kind: "unknown" }];
    status = "unresolved";
    precision = "heuristic";
    reason ??= "typechecker_target_unresolved";
  } else if (targets.every((target) => target.kind === "external")) {
    status = "external";
    const canonicalExternal = targets.length === 1
      && targets[0]!.kind === "external"
      && (targets[0]!.locator.startsWith("typescript:stdlib:") || targets[0]!.locator.startsWith("node:"));
    precision = canonicalExternal ? "exact" : "heuristic";
    if (!canonicalExternal) reason ??= "external_package_instance_unavailable";
  } else if (targets.length > 1) {
    status = "candidates";
    precision = "overapprox";
    reason ??= "multiple_typechecker_targets";
  } else {
    status = "resolved";
    precision = "exact";
  }
  const targetBasis = basisForTargets(targets);
  let protocolSpecifier = typeof specifier === "string"
    ? specifier === "" && reasonValue === "missing_module_specifier" ? "<missing>" : specifier
    : kind === "type_use" ? specifier.importedName : specifier.moduleSpecifier;
  let moduleSpecifier: string | null = kind === "type_use" ? null : protocolSpecifier;
  let importedName: string | null = kind === "type_use" ? protocolSpecifier : null;
  let exportPath: string[] | null = null;
  if (typeof specifier !== "string") {
    moduleSpecifier = specifier.moduleSpecifier;
    importedName = specifier.importedName;
    exportPath = specifier.bindingKind === "namespace" || specifier.bindingKind === "import_equals"
      ? null
      : [specifier.importedName];
  }
  if (bindingMetadata !== undefined) {
    moduleSpecifier = bindingMetadata.moduleSpecifier;
    importedName = bindingMetadata.importedName;
    exportPath = occurrenceKind === "namespace_reexport" ? null : [...bindingMetadata.exportPath];
    if (kind === "type_use") protocolSpecifier = bindingMetadata.importedName;
  }
  const bindingOrigin = bindingMetadata?.bindingOrigin !== undefined
    && bindingMetadata.bindingReference !== undefined
    ? {
      siteKey: siteKey(
        { kind: "file", relativePath: context.source.relativePath },
        "web_import",
        context.source.relativePath,
        bindingMetadata.bindingOrigin.declarationStartOffset,
        bindingMetadata.bindingOrigin.declarationEndOffset,
      ),
      declarationStartOffset: bindingMetadata.bindingOrigin.declarationStartOffset,
      declarationEndOffset: bindingMetadata.bindingOrigin.declarationEndOffset,
      scopeStartOffset: bindingMetadata.bindingOrigin.scopeStartOffset,
      scopeEndOffset: bindingMetadata.bindingOrigin.scopeEndOffset,
      referenceStartOffset: bindingMetadata.bindingReference.startOffset,
      referenceEndOffset: bindingMetadata.bindingReference.endOffset,
    }
    : null;
  const bindingKind = bindingMetadata?.bindingKind
    ?? (typeof specifier === "string" ? null : specifier.bindingKind);
  const bindingScope = kind === "web_import"
    && ["default_import", "named_import", "namespace_import", "import_equals"].includes(occurrenceKind)
    ? bindingScopeSpan(anchor)
    : null;
  return {
    key: siteKey(source, kind, context.source.relativePath, startOffset, endOffset),
    kind,
    edgeKind,
    source,
    specifier: protocolSpecifier.slice(0, MAX_SPECIFIER_CHARS),
    moduleSpecifier,
    importedName,
    exportPath,
    resolutionMode: directive.mode,
    resolutionModeProof: directive.mode === null ? null : directive.proof ?? null,
    bindingKind,
    bindingOrigin,
    bindingScope,
    typeOnly,
    status,
    precision,
    reason,
    condition: WEB_CONDITION,
    targets,
    targetConditions: targets.map(() => WEB_CONDITION),
    evidence: {
      relativePath: context.source.relativePath,
      startOffset,
      endOffset,
      detail,
      occurrenceKind,
      targetBasis,
    },
  };
}

async function moduleTargets(
  checker: Checker,
  counter: QueryCounter,
  moduleNode: Node,
  moduleSpecifier: string,
  index: DefinitionIndex,
  sourcesByPath: ReadonlyMap<string, TypeScriptSemanticSource>,
): Promise<TypeScriptRawDependencyTarget[]> {
  if (moduleSpecifier.length === 0) return [];
  const symbol = await querySymbol(checker, moduleNode, counter, "module");
  if (symbol !== undefined) {
    const resolved = await compilerSymbolTargets(symbol, checker, counter, index, sourcesByPath, false);
    if (resolved.targets.length > 0) return resolved.targets;
    if (resolved.external) return [externalTarget(moduleSpecifier, symbol.name)];
  }
  return isExternalModuleSpecifier(moduleSpecifier) ? [externalTarget(moduleSpecifier)] : [];
}

async function bindingTargets(
  checker: Checker,
  counter: QueryCounter,
  binding: Node,
  moduleNode: Node,
  moduleSpecifier: string,
  index: DefinitionIndex,
  sourcesByPath: ReadonlyMap<string, TypeScriptSemanticSource>,
  preferType: boolean,
  externalBindings?: BindingProvenanceMap,
  imported = "default",
  directive: ResolutionModeDirective = NO_RESOLUTION_MODE,
  bindingKind: BindingKind = imported === "default" ? "default" : "named",
): Promise<TypeScriptRawDependencyTarget[]> {
  const symbol = await querySymbol(checker, binding, counter, "binding");
  let targets: TypeScriptRawDependencyTarget[] = [];
  if (symbol !== undefined) {
    const resolved = await compilerSymbolTargets(symbol, checker, counter, index, sourcesByPath, preferType);
    const canonical = resolved.targets.filter((target) => target.kind === "definition" || target.kind === "external");
    if (canonical.length > 0) targets = canonical;
    else if (resolved.external) targets = [externalTarget(moduleSpecifier, symbol.name)];
  }
  if (targets.length === 0) {
    const moduleBoundary = await moduleTargets(checker, counter, moduleNode, moduleSpecifier, index, sourcesByPath);
    if (moduleBoundary.every((target) => target.kind === "external")) targets = moduleBoundary;
  }
  if (symbol !== undefined) {
    externalBindings?.set(symbol.id, {
      moduleSpecifier,
      importedName: imported,
      exportPath: bindingKind === "namespace" || bindingKind === "import_equals" ? [] : [imported],
      targets,
      resolutionMode: directive.mode,
      resolutionModeError: directive.error,
      ...(directive.proof === undefined ? {} : { resolutionModeProof: directive.proof }),
      bindingKind,
      typeOnly: preferType,
      bindingOrigin: bindingDeclarationOrigin(binding),
    });
  }
  return targets;
}

async function recordNamespaceBinding(
  checker: Checker,
  counter: QueryCounter,
  binding: Node,
  bindings: BindingProvenanceMap,
  moduleSpecifier: string,
  targets: TypeScriptRawDependencyTarget[],
  directive: ResolutionModeDirective,
  typeOnly: boolean,
): Promise<void> {
  const symbol = await querySymbol(checker, binding, counter, "namespace binding");
  if (symbol === undefined) return;
  bindings.set(symbol.id, {
    moduleSpecifier,
    importedName: "*",
    exportPath: [],
    targets,
    resolutionMode: directive.mode,
    resolutionModeError: directive.error,
    ...(directive.proof === undefined ? {} : { resolutionModeProof: directive.proof }),
    bindingKind: "namespace",
    typeOnly,
    bindingOrigin: bindingDeclarationOrigin(binding),
  });
}

function importedName(specifier: ImportSpecifier): string {
  const source = specifier.propertyName ?? specifier.name;
  return (source as Node & { readonly text: string }).text;
}

function directImportBindingOrigins(scope: Node, localName: string): BindingProvenance[] {
  const origins: BindingProvenance[] = [];
  const add = (
    binding: Node,
    moduleSpecifier: string,
    importedNameValue: string,
    bindingKind: BindingKind,
    directive: ResolutionModeDirective,
    typeOnly: boolean,
  ): void => {
    origins.push({
      moduleSpecifier,
      importedName: importedNameValue,
      exportPath: bindingKind === "namespace" || bindingKind === "import_equals" ? [] : [importedNameValue],
      targets: isExternalModuleSpecifier(moduleSpecifier)
        ? [externalTarget(moduleSpecifier, importedNameValue)]
        : [],
      resolutionMode: directive.mode,
      resolutionModeError: directive.error,
      ...(directive.proof === undefined ? {} : { resolutionModeProof: directive.proof }),
      bindingKind,
      typeOnly,
      bindingOrigin: bindingDeclarationOrigin(binding),
    });
  };
  scope.forEachChild((child) => {
    if (child.kind === SyntaxKind.ImportDeclaration) {
      const declaration = child as ImportDeclaration;
      const moduleSpecifier = stringLiteralText(declaration.moduleSpecifier);
      const clause = declaration.importClause;
      if (moduleSpecifier === null || clause === undefined) return undefined;
      const clauseTypeOnly = clause.phaseModifier === SyntaxKind.TypeKeyword;
      const directive = resolutionModeForOccurrence(
        resolutionModeDirective(declaration.attributes, clauseTypeOnly),
        clauseTypeOnly,
      );
      if (clause.name?.text === localName) {
        add(clause.name, moduleSpecifier, "default", "default", directive, clauseTypeOnly);
      }
      if (clause.namedBindings?.kind === SyntaxKind.NamespaceImport) {
        if (clause.namedBindings.name.text === localName) {
          add(clause.namedBindings.name, moduleSpecifier, "*", "namespace", directive, clauseTypeOnly);
        }
      } else if (clause.namedBindings?.kind === SyntaxKind.NamedImports) {
        for (const element of clause.namedBindings.elements) {
          if (element.name.text === localName) {
            add(
              element.name,
              moduleSpecifier,
              importedName(element),
              "named",
              directive,
              clauseTypeOnly || element.isTypeOnly,
            );
          }
        }
      }
    } else if (child.kind === SyntaxKind.ImportEqualsDeclaration) {
      const declaration = child as ImportEqualsDeclaration;
      if (
        declaration.name.text === localName
        && declaration.moduleReference.kind === SyntaxKind.ExternalModuleReference
      ) {
        const expression = (declaration.moduleReference as Node & { readonly expression: Node }).expression;
        const moduleSpecifier = stringLiteralText(expression);
        if (moduleSpecifier !== null) {
          add(
            declaration.name,
            moduleSpecifier,
            "=",
            "import_equals",
            { mode: "require", error: null },
            declaration.isTypeOnly,
          );
        }
      }
    }
    return undefined;
  });
  return origins;
}

function nearestDirectImportBindingOrigins(node: Node, localName: string): BindingProvenance[] {
  let current: Node | undefined = node.parent;
  for (let depth = 0; current !== undefined && depth < MAX_AST_DEPTH; depth += 1, current = current.parent) {
    if (current.kind === SyntaxKind.SourceFile || current.kind === SyntaxKind.ModuleBlock) {
      return directImportBindingOrigins(current, localName);
    }
  }
  return [];
}

function isAmbiguousImportBindingAt(node: Node, localName: string): boolean {
  let current: Node | undefined = node.parent;
  for (let depth = 0; current !== undefined && depth < MAX_AST_DEPTH; depth += 1, current = current.parent) {
    if (current.kind !== SyntaxKind.SourceFile && current.kind !== SyntaxKind.ModuleBlock) continue;
    const origins = directImportBindingOrigins(current, localName);
    if (origins.length > 0) return origins.length > 1;
  }
  return false;
}

function sourceBindingProvenance(sourceFile: SourceFile): Map<string, BindingProvenance> {
  const candidates = new Map<string, BindingProvenance[]>();
  const add = (
    binding: Node,
    localName: string,
    moduleSpecifier: string,
    imported: string,
    directive: ResolutionModeDirective = NO_RESOLUTION_MODE,
    bindingKind: BindingKind = imported === "default" ? "default" : "named",
    typeOnly = false,
  ): void => {
    const targets = isExternalModuleSpecifier(moduleSpecifier)
      ? [externalTarget(moduleSpecifier, imported)]
      : [];
    candidates.set(localName, [
      ...(candidates.get(localName) ?? []),
      {
        moduleSpecifier,
        importedName: imported,
        exportPath: bindingKind === "namespace" || bindingKind === "import_equals" ? [] : [imported],
        targets,
        resolutionMode: directive.mode,
        resolutionModeError: directive.error,
        ...(directive.proof === undefined ? {} : { resolutionModeProof: directive.proof }),
        bindingKind,
        typeOnly,
        bindingOrigin: bindingDeclarationOrigin(binding),
      },
    ]);
  };
  const recordClause = (declaration: ImportDeclaration | JSDocImportTag): void => {
    const moduleSpecifier = stringLiteralText(declaration.moduleSpecifier);
    if (moduleSpecifier === null || declaration.importClause === undefined) return;
    const clause = declaration.importClause;
    const clauseTypeOnly = clause.phaseModifier === SyntaxKind.TypeKeyword || declaration.kind === SyntaxKind.JSDocImportTag;
    const directive = resolutionModeDirective(declaration.attributes, clauseTypeOnly);
    const clauseDirective = resolutionModeForOccurrence(directive, clauseTypeOnly);
    if (clause.name !== undefined) {
      add(clause.name, clause.name.text, moduleSpecifier, "default", clauseDirective, "default", clauseTypeOnly);
    }
    if (clause.namedBindings?.kind === SyntaxKind.NamespaceImport) {
      add(
        clause.namedBindings.name,
        clause.namedBindings.name.text,
        moduleSpecifier,
        "*",
        clauseDirective,
        "namespace",
        clauseTypeOnly,
      );
    } else if (clause.namedBindings?.kind === SyntaxKind.NamedImports) {
      for (const element of clause.namedBindings.elements) {
        add(
          element.name,
          element.name.text,
          moduleSpecifier,
          importedName(element),
          clauseDirective,
          "named",
          clauseTypeOnly || element.isTypeOnly,
        );
      }
    }
  };
  let visited = 0;
  const visitDetachedJSDoc = (node: Node, depth: number): void => {
    if (depth > MAX_AST_DEPTH || visited >= MAX_AST_NODES) return;
    visited += 1;
    if (node.kind === SyntaxKind.JSDocImportTag) recordClause(node as JSDocImportTag);
    node.forEachChild((child) => {
      visitDetachedJSDoc(child, depth + 1);
      return undefined;
    });
  };
  const visit = (node: Node, depth: number): void => {
    if (depth > MAX_AST_DEPTH || visited >= MAX_AST_NODES) return;
    visited += 1;
    if (node.kind === SyntaxKind.ImportDeclaration) {
      recordClause(node as ImportDeclaration);
    } else if (node.kind === SyntaxKind.ImportEqualsDeclaration) {
      const declaration = node as ImportEqualsDeclaration;
      if (declaration.moduleReference.kind !== SyntaxKind.ExternalModuleReference) return;
      const expression = (declaration.moduleReference as Node & { readonly expression: Node }).expression;
      const moduleSpecifier = stringLiteralText(expression);
      if (moduleSpecifier !== null) add(
        declaration.name,
        declaration.name.text,
        moduleSpecifier,
        "=",
        { mode: "require", error: null },
        "import_equals",
        declaration.isTypeOnly,
      );
    }
    const children = new Map<string, Node>();
    const addChild = (child: Node): void => {
      const key = childTraversalKey(child, sourceFile);
      if (!children.has(key)) children.set(key, child);
    };
    node.forEachChild((child) => {
      addChild(child);
      return undefined;
    });
    for (const child of children.values()) visit(child, depth + 1);
    // Detached JSDoc is scanned only for import tags. Ordinary JSDoc type
    // nodes already flow through the compiler's canonical `forEachChild`
    // traversal and must not be visited again under a file owner.
    for (const jsDoc of node.jsDoc ?? []) visitDetachedJSDoc(jsDoc, depth + 1);
  };
  visit(sourceFile, 0);
  return new Map([...candidates]
    .filter(([, entries]) => entries.length === 1)
    .map(([localName, entries]) => [localName, entries[0]!]));
}

async function prepopulateBindingSymbols(
  sourceFile: SourceFile,
  checker: Checker,
  counter: QueryCounter,
  bindings: BindingProvenanceMap,
): Promise<void> {
  const record = async (
    binding: Node,
    moduleSpecifier: string,
    imported: string,
    directive: ResolutionModeDirective,
    bindingKind: BindingKind,
    typeOnly: boolean,
  ): Promise<void> => {
    const symbol = await querySymbol(checker, binding, counter, "binding provenance prepass");
    if (symbol === undefined) return;
    const provenance: BindingProvenance = {
      moduleSpecifier,
      importedName: imported,
      exportPath: bindingKind === "namespace" || bindingKind === "import_equals" ? [] : [imported],
      targets: isExternalModuleSpecifier(moduleSpecifier)
        ? [externalTarget(moduleSpecifier, imported)]
        : [],
      resolutionMode: directive.mode,
      resolutionModeError: directive.error,
      ...(directive.proof === undefined ? {} : { resolutionModeProof: directive.proof }),
      bindingKind,
      typeOnly,
      bindingOrigin: bindingDeclarationOrigin(binding),
    };
    if (bindings.isAmbiguous(symbol.id)) return;
    const existing = bindings.get(symbol.id);
    if (existing !== undefined && JSON.stringify(existing) !== JSON.stringify(provenance)) {
      bindings.markAmbiguous(symbol.id);
      return;
    }
    bindings.set(symbol.id, provenance);
  };
  let visited = 0;
  const visit = async (node: Node, depth: number): Promise<void> => {
    if (depth > MAX_AST_DEPTH) throw new DependencyContractError("dependency AST depth limit exceeded");
    visited += 1;
    if (visited > MAX_AST_NODES) throw new DependencyContractError("dependency AST node limit exceeded");
    if (node.kind === SyntaxKind.ImportDeclaration) {
      const declaration = node as ImportDeclaration;
      const moduleSpecifier = stringLiteralText(declaration.moduleSpecifier);
      const clause = declaration.importClause;
      if (moduleSpecifier !== null && clause !== undefined) {
        const clauseTypeOnly = clause.phaseModifier === SyntaxKind.TypeKeyword;
        const directive = resolutionModeForOccurrence(
          resolutionModeDirective(declaration.attributes, clauseTypeOnly),
          clauseTypeOnly,
        );
        if (clause.name !== undefined) {
          await record(clause.name, moduleSpecifier, "default", directive, "default", clauseTypeOnly);
        }
        if (clause.namedBindings?.kind === SyntaxKind.NamespaceImport) {
          await record(
            clause.namedBindings.name,
            moduleSpecifier,
            "*",
            directive,
            "namespace",
            clauseTypeOnly,
          );
        } else if (clause.namedBindings?.kind === SyntaxKind.NamedImports) {
          for (const element of clause.namedBindings.elements) {
            const typeOnly = clauseTypeOnly || element.isTypeOnly;
            await record(
              element.name,
              moduleSpecifier,
              importedName(element),
              resolutionModeForOccurrence(directive, typeOnly),
              "named",
              typeOnly,
            );
          }
        }
      }
    } else if (node.kind === SyntaxKind.ImportEqualsDeclaration) {
      const declaration = node as ImportEqualsDeclaration;
      if (declaration.moduleReference.kind === SyntaxKind.ExternalModuleReference) {
        const expression = (declaration.moduleReference as Node & { readonly expression: Node }).expression;
        const moduleSpecifier = stringLiteralText(expression);
        if (moduleSpecifier !== null) {
          await record(
            declaration.name,
            moduleSpecifier,
            "=",
            { mode: "require", error: null },
            "import_equals",
            declaration.isTypeOnly,
          );
        }
      }
    }
    const children: Node[] = [];
    node.forEachChild((child) => {
      children.push(child);
      return undefined;
    });
    for (const child of children) await visit(child, depth + 1);
  };
  await visit(sourceFile, 0);
}

function exportedName(specifier: ExportSpecifier): string {
  const source = specifier.propertyName ?? specifier.name;
  return (source as Node & { readonly text: string }).text;
}

async function collectImportDeclaration(
  node: ImportDeclaration,
  context: CollectionContext,
  checker: Checker,
  counter: QueryCounter,
  index: DefinitionIndex,
  sourcesByPath: ReadonlyMap<string, TypeScriptSemanticSource>,
): Promise<TypeScriptRawDependencySite[]> {
  const clause = node.importClause;
  const clauseTypeOnly = clause?.phaseModifier === SyntaxKind.TypeKeyword;
  const directive = resolutionModeDirective(node.attributes, clauseTypeOnly);
  const declarationDirective = resolutionModeForOccurrence(directive, clauseTypeOnly);
  const moduleSpecifier = stringLiteralText(node.moduleSpecifier);
  if (moduleSpecifier === null) return [createSite(
    context, "web_import", "imports", "dynamic_import", node.moduleSpecifier,
    node.moduleSpecifier.getText(context.source.sourceFile), [], "non_literal_module_specifier",
    "TypeChecker import declaration with a non-literal module specifier", clauseTypeOnly,
    undefined, declarationDirective,
  )];
  if (clause === undefined) {
    return [createSite(context, "web_import", "imports", "side_effect_import", node.moduleSpecifier, moduleSpecifier,
      await moduleTargets(checker, counter, node.moduleSpecifier, moduleSpecifier, index, sourcesByPath), null,
      "TypeChecker side-effect import module occurrence", false, undefined,
      declarationDirective)];
  }
  const sites: TypeScriptRawDependencySite[] = [];
  if (clause.name !== undefined) {
    sites.push(createSite(context, "web_import", "imports", "default_import", clause.name,
      structuredBindingSpecifier(moduleSpecifier, "default", "default"),
      await bindingTargets(checker, counter, clause.name, node.moduleSpecifier, moduleSpecifier, index, sourcesByPath, clauseTypeOnly, context.externalBindings, "default", declarationDirective), null,
      "TypeChecker default import binding occurrence", clauseTypeOnly, undefined, declarationDirective));
  }
  const bindings = clause.namedBindings;
  if (bindings?.kind === SyntaxKind.NamespaceImport) {
    const targets = await moduleTargets(checker, counter, node.moduleSpecifier, moduleSpecifier, index, sourcesByPath);
    await recordNamespaceBinding(
      checker,
      counter,
      bindings.name,
      context.externalBindings,
      moduleSpecifier,
      targets,
      declarationDirective,
      clauseTypeOnly,
    );
    sites.push(createSite(context, "web_import", "imports", "namespace_import", bindings.name,
      structuredBindingSpecifier(moduleSpecifier, "*", "namespace"),
      targets, null,
      "TypeChecker namespace import binding occurrence", clauseTypeOnly, undefined, declarationDirective));
  } else if (bindings?.kind === SyntaxKind.NamedImports) {
    for (const element of bindings.elements) {
      const typeOnly = clauseTypeOnly || element.isTypeOnly;
      sites.push(createSite(context, "web_import", "imports", "named_import", element.name,
        structuredBindingSpecifier(moduleSpecifier, importedName(element), "named"),
        await bindingTargets(checker, counter, element.name, node.moduleSpecifier, moduleSpecifier, index, sourcesByPath, typeOnly, context.externalBindings, importedName(element), declarationDirective), null,
        "TypeChecker named import binding occurrence", typeOnly, undefined, declarationDirective));
    }
  }
  if (sites.length === 0 && bindings?.kind === SyntaxKind.NamedImports && bindings.elements.length === 0) {
    sites.push(createSite(
      context,
      "web_import",
      "imports",
      "empty_import",
      node.moduleSpecifier,
      moduleSpecifier,
      await moduleTargets(checker, counter, node.moduleSpecifier, moduleSpecifier, index, sourcesByPath),
      null,
      "TypeChecker empty import-clause module occurrence",
      clauseTypeOnly,
      undefined,
      declarationDirective,
    ));
  }
  return sites;
}

async function collectJSDocImportTag(
  node: JSDocImportTag,
  context: CollectionContext,
  checker: Checker,
  counter: QueryCounter,
  index: DefinitionIndex,
  sourcesByPath: ReadonlyMap<string, TypeScriptSemanticSource>,
): Promise<TypeScriptRawDependencySite[]> {
  const directive = resolutionModeForOccurrence(resolutionModeDirective(node.attributes, true), true);
  const moduleSpecifier = stringLiteralText(node.moduleSpecifier);
  if (moduleSpecifier === null) return [createSite(
    context, "web_import", "imports", "import_type", node.moduleSpecifier,
    node.moduleSpecifier.getText(context.source.sourceFile), [], "non_literal_module_specifier",
    "TypeChecker JSDoc import tag with a non-literal module specifier", true,
    undefined, directive,
  )];
  const clause = node.importClause;
  if (clause === undefined) {
    return [createSite(context, "web_import", "imports", "import_type", node.moduleSpecifier, moduleSpecifier,
      await moduleTargets(checker, counter, node.moduleSpecifier, moduleSpecifier, index, sourcesByPath), null,
      "TypeChecker JSDoc module import occurrence", true, undefined, directive)];
  }
  const sites: TypeScriptRawDependencySite[] = [];
  if (clause.name !== undefined) {
    sites.push(createSite(context, "web_import", "imports", "default_import", clause.name,
      structuredBindingSpecifier(moduleSpecifier, "default", "default"),
      await bindingTargets(checker, counter, clause.name, node.moduleSpecifier, moduleSpecifier, index, sourcesByPath, true, context.externalBindings, "default", directive), null,
      "TypeChecker JSDoc default import binding occurrence", true, undefined, directive));
  }
  const bindings = clause.namedBindings;
  if (bindings?.kind === SyntaxKind.NamespaceImport) {
    const targets = await moduleTargets(checker, counter, node.moduleSpecifier, moduleSpecifier, index, sourcesByPath);
    await recordNamespaceBinding(
      checker,
      counter,
      bindings.name,
      context.externalBindings,
      moduleSpecifier,
      targets,
      directive,
      true,
    );
    sites.push(createSite(context, "web_import", "imports", "namespace_import", bindings.name,
      structuredBindingSpecifier(moduleSpecifier, "*", "namespace"),
      targets, null,
      "TypeChecker JSDoc namespace import binding occurrence", true, undefined, directive));
  } else if (bindings?.kind === SyntaxKind.NamedImports) {
    for (const element of bindings.elements) {
      sites.push(createSite(context, "web_import", "imports", "named_import", element.name,
        structuredBindingSpecifier(moduleSpecifier, importedName(element), "named"),
        await bindingTargets(checker, counter, element.name, node.moduleSpecifier, moduleSpecifier, index, sourcesByPath, true, context.externalBindings, importedName(element), directive), null,
        "TypeChecker JSDoc named import binding occurrence", true, undefined, directive));
    }
  }
  if (sites.length === 0 && bindings?.kind === SyntaxKind.NamedImports && bindings.elements.length === 0) {
    sites.push(createSite(
      context,
      "web_import",
      "imports",
      "empty_import",
      node.moduleSpecifier,
      moduleSpecifier,
      await moduleTargets(checker, counter, node.moduleSpecifier, moduleSpecifier, index, sourcesByPath),
      null,
      "TypeChecker empty JSDoc import-clause module occurrence",
      true,
      undefined,
      directive,
    ));
  }
  return sites.length > 0
    ? sites
    : [createSite(context, "web_import", "imports", "import_type", node.moduleSpecifier, moduleSpecifier,
      await moduleTargets(checker, counter, node.moduleSpecifier, moduleSpecifier, index, sourcesByPath), "jsdoc_import_binding_missing",
      "TypeChecker JSDoc import tag without a supported binding", true, undefined, directive)];
}

async function collectExportDeclaration(
  node: ExportDeclaration,
  context: CollectionContext,
  checker: Checker,
  counter: QueryCounter,
  index: DefinitionIndex,
  sourcesByPath: ReadonlyMap<string, TypeScriptSemanticSource>,
): Promise<TypeScriptRawDependencySite[]> {
  if (node.moduleSpecifier === undefined) {
    if (node.exportClause?.kind !== SyntaxKind.NamedExports) return [];
    const sites: TypeScriptRawDependencySite[] = [];
    for (const element of node.exportClause.elements) {
      const localNode = element.propertyName ?? element.name;
      const localName = (localNode as Node & { readonly text: string }).text;
      beginQuery(counter);
      const targetSymbol = await checker.getExportSpecifierLocalTargetSymbol(element);
      const syntaxSymbol = await querySymbol(checker, localNode, counter, "local re-export binding", true);
      const ambiguousSyntaxBinding = isAmbiguousImportBindingAt(element, localName)
        || (syntaxSymbol !== undefined && context.externalBindings.isAmbiguous(syntaxSymbol.id));
      let syntaxTarget: CompilerSymbol | null | undefined;
      if (!ambiguousSyntaxBinding && syntaxSymbol !== undefined && targetSymbol !== undefined) {
        syntaxTarget = await unwrapAlias(checker, syntaxSymbol, counter);
        const localTarget = await unwrapAlias(checker, targetSymbol, counter);
        if (syntaxTarget !== null && localTarget !== null && syntaxTarget.id !== localTarget.id) {
          throw new DependencyContractError(
            `local re-export target did not correlate with its syntax binding (${localName})`,
          );
        }
      } else if (!ambiguousSyntaxBinding && syntaxSymbol !== undefined) {
        syntaxTarget = await unwrapAlias(checker, syntaxSymbol, counter);
      }
      const provenance = (syntaxSymbol === undefined ? undefined : context.externalBindings.get(syntaxSymbol.id))
        ?? (syntaxSymbol === undefined || syntaxTarget === null
          ? context.bindingProvenance.get(localName)
          : undefined);
      if (provenance === undefined) {
        if (ambiguousSyntaxBinding) {
          sites.push(createSite(
            context,
            "web_reexport",
            "reexports",
            "named_reexport",
            element.name,
            structuredBindingSpecifier("<ambiguous>", localName, "named"),
            [],
            "ambiguous_binding_provenance",
            "TypeChecker local re-export has multiple incompatible import origins",
            node.isTypeOnly || element.isTypeOnly,
          ));
        }
        continue;
      }
      const typeOnly = node.isTypeOnly || element.isTypeOnly || provenance.typeOnly === true;
      if (provenance.bindingKind === "namespace") {
        const referencedProvenance = withBindingReference(provenance, localNode, context.source.sourceFile);
        const resolved = targetSymbol === undefined
          ? null
          : await compilerSymbolTargets(targetSymbol, checker, counter, index, sourcesByPath, false);
        const targets = resolved?.targets.length
          ? resolved.targets
          : resolved?.external
            ? [externalTarget(provenance.moduleSpecifier, "*")]
            : provenance.targets;
        sites.push(createSite(
          context,
          "web_reexport",
          "reexports",
          "namespace_reexport",
          element.name,
          structuredBindingSpecifier(provenance.moduleSpecifier, "*", "namespace"),
          targets,
          null,
          "TypeChecker local namespace-alias re-export occurrence",
          typeOnly,
          referencedProvenance,
        ));
        continue;
      }
      const resolved = targetSymbol === undefined
        ? null
        : await compilerSymbolTargets(targetSymbol, checker, counter, index, sourcesByPath, typeOnly);
      const canonicalTargets = resolved?.targets.filter((target) => target.kind === "definition" || target.kind === "external") ?? [];
      const targets = canonicalTargets.length > 0
        ? canonicalTargets
        : provenance.targets;
      const referencedProvenance = withBindingReference(provenance, localNode, context.source.sourceFile);
      sites.push(createSite(
        context,
        "web_reexport",
        "reexports",
        "named_reexport",
        element.name,
        structuredBindingSpecifier(
          provenance.moduleSpecifier,
          provenance.importedName,
          provenance.bindingKind ?? "named",
        ),
        targets,
        null,
        "TypeChecker imported local-alias re-export occurrence",
        typeOnly,
        referencedProvenance.bindingKind === "import_equals"
          ? { ...referencedProvenance, resolutionMode: null, resolutionModeError: null }
          : referencedProvenance,
      ));
    }
    return sites;
  }
  const directive = resolutionModeDirective(node.attributes, node.isTypeOnly);
  const declarationDirective = resolutionModeForOccurrence(directive, node.isTypeOnly);
  const moduleSpecifier = stringLiteralText(node.moduleSpecifier);
  if (moduleSpecifier === null) return [createSite(
    context, "web_reexport", "reexports", "export_star", node.moduleSpecifier,
    node.moduleSpecifier.getText(context.source.sourceFile), [], "non_literal_module_specifier",
    "TypeChecker re-export declaration with a non-literal module specifier", node.isTypeOnly, undefined,
    declarationDirective,
  )];
  const clause = node.exportClause;
  if (clause === undefined) {
    return [createSite(context, "web_reexport", "reexports", "export_star", node.moduleSpecifier, moduleSpecifier,
      await moduleTargets(checker, counter, node.moduleSpecifier, moduleSpecifier, index, sourcesByPath), null,
      "TypeChecker export-star module occurrence", node.isTypeOnly, undefined,
      declarationDirective)];
  }
  if (clause.kind === SyntaxKind.NamespaceExport) {
    return [createSite(context, "web_reexport", "reexports", "namespace_reexport", clause.name,
      structuredBindingSpecifier(moduleSpecifier, "*", "namespace"),
      await moduleTargets(checker, counter, node.moduleSpecifier, moduleSpecifier, index, sourcesByPath), null,
      "TypeChecker namespace re-export occurrence", node.isTypeOnly, undefined,
      declarationDirective)];
  }
  const sites: TypeScriptRawDependencySite[] = [];
  for (const element of clause.elements) {
    const typeOnly = node.isTypeOnly || element.isTypeOnly;
    let targetSymbol: CompilerSymbol | undefined;
    beginQuery(counter);
    targetSymbol = await checker.getExportSpecifierLocalTargetSymbol(element);
    const syntaxSymbol = await querySymbol(checker, element.propertyName ?? element.name, counter, "export binding", true);
    if (targetSymbol !== undefined && syntaxSymbol !== undefined) {
      const syntaxTarget = await unwrapAlias(checker, syntaxSymbol, counter);
      const exportTarget = await unwrapAlias(checker, targetSymbol, counter);
      if (syntaxTarget !== null && exportTarget !== null && syntaxTarget.id !== exportTarget.id) {
        throw new DependencyContractError("export target symbol did not correlate with its syntax binding");
      }
    }
    let targets: TypeScriptRawDependencyTarget[] = [];
    if (targetSymbol !== undefined) {
      const resolved = await compilerSymbolTargets(targetSymbol, checker, counter, index, sourcesByPath, typeOnly);
      targets = resolved.targets.filter((target) => target.kind === "definition" || target.kind === "external");
      if (targets.length === 0 && resolved.external) targets = [externalTarget(moduleSpecifier, targetSymbol.name)];
    }
    if (targets.length === 0) {
      targets = await bindingTargets(checker, counter, element.name, node.moduleSpecifier, moduleSpecifier, index, sourcesByPath, typeOnly);
    }
    sites.push(createSite(context, "web_reexport", "reexports", "named_reexport", element.name,
      structuredBindingSpecifier(moduleSpecifier, exportedName(element), "named"), targets, null,
      "TypeChecker named re-export binding occurrence", typeOnly, undefined, declarationDirective));
  }
  if (sites.length === 0 && clause.kind === SyntaxKind.NamedExports && clause.elements.length === 0) {
    sites.push(createSite(
      context,
      "web_reexport",
      "reexports",
      "empty_reexport",
      node.moduleSpecifier,
      moduleSpecifier,
      await moduleTargets(checker, counter, node.moduleSpecifier, moduleSpecifier, index, sourcesByPath),
      null,
      "TypeChecker empty re-export-clause module occurrence",
      node.isTypeOnly,
      undefined,
      declarationDirective,
    ));
  }
  return sites;
}

async function collectImportEquals(
  node: ImportEqualsDeclaration,
  context: CollectionContext,
  checker: Checker,
  counter: QueryCounter,
  index: DefinitionIndex,
  sourcesByPath: ReadonlyMap<string, TypeScriptSemanticSource>,
): Promise<TypeScriptRawDependencySite[]> {
  if (node.moduleReference.kind !== SyntaxKind.ExternalModuleReference) return [];
  const expression = (node.moduleReference as Node & { readonly expression: Node }).expression;
  const moduleSpecifier = stringLiteralText(expression);
  if (moduleSpecifier === null) return [createSite(context, "web_import", "imports", "import_equals", expression,
    structuredBindingSpecifier(expression.getText(context.source.sourceFile), "=", "import_equals"), [],
    "non_literal_module_specifier", "TypeChecker import-equals occurrence", node.isTypeOnly)];
  const binding = await bindingTargets(
    checker, counter, node.name, expression, moduleSpecifier, index, sourcesByPath, node.isTypeOnly, context.externalBindings, "=",
    { mode: "require", error: null }, "import_equals",
  );
  return [createSite(context, "web_import", "imports", "import_equals", node.name,
    structuredBindingSpecifier(moduleSpecifier, "=", "import_equals"),
    binding.length > 0
      ? binding
      : await moduleTargets(checker, counter, expression, moduleSpecifier, index, sourcesByPath), null,
    "TypeChecker import-equals binding occurrence", node.isTypeOnly)];
}

async function collectCallImport(
  node: Node & { readonly expression: Node; readonly arguments: readonly Node[] },
  context: CollectionContext,
  checker: Checker,
  counter: QueryCounter,
  index: DefinitionIndex,
  sourcesByPath: ReadonlyMap<string, TypeScriptSemanticSource>,
): Promise<TypeScriptRawDependencySite[]> {
  const expressionText = node.expression.kind === SyntaxKind.Identifier
    ? (node.expression as Identifier).text
    : node.expression.kind === SyntaxKind.ImportKeyword ? "import" : null;
  if (expressionText !== "require" && expressionText !== "import") return [];
  if (expressionText === "require") {
    if (isLexicallyShadowedBinding(node.expression, "require", true)) return [];
    const callee = await querySymbol(checker, node.expression, counter, "require callee");
    // A canonical ambient CommonJS declaration is evidence for the runtime
    // loader, not a lexical shadow. Imported/local implementations remain
    // excluded, and mixed ambient/non-ambient declaration sets fail closed.
    if (callee !== undefined && !await isAmbientRequireSymbol(callee, counter)) return [];
  }
  const argument = node.arguments[0];
  if (argument === undefined) return [createSite(context, "web_import", "imports",
    expressionText === "require" ? "require_call" : "dynamic_import", node, "", [], "missing_module_specifier",
    `TypeChecker ${expressionText} call without a module argument`)];
  const moduleSpecifier = stringLiteralText(argument);
  if (moduleSpecifier === null) return [createSite(context, "web_import", "imports",
    expressionText === "require" ? "require_call" : "dynamic_import", argument,
    argument.getText(context.source.sourceFile), [], "computed_module_specifier",
    `TypeChecker ${expressionText} call with a computed module occurrence`)];
  return [createSite(context, "web_import", "imports",
    expressionText === "require" ? "require_call" : "dynamic_import", argument, moduleSpecifier,
    await moduleTargets(checker, counter, argument, moduleSpecifier, index, sourcesByPath), null,
    `TypeChecker ${expressionText} module occurrence`)];
}

function defaultCallKind(
  node: CallExpression | NewExpression | TaggedTemplateExpression,
): TypeScriptRawCallKind {
  return node.kind === SyntaxKind.NewExpression
    ? "constructor"
    : node.kind === SyntaxKind.TaggedTemplateExpression
      ? "tagged_template"
      : "function";
}

function callKindForDefinition(
  node: CallExpression | NewExpression | TaggedTemplateExpression,
  semanticKind: string,
): TypeScriptRawCallKind {
  if (node.kind === SyntaxKind.NewExpression || node.kind === SyntaxKind.TaggedTemplateExpression) {
    return defaultCallKind(node);
  }
  if (semanticKind === "method") return "method";
  if (semanticKind === "constructor") return "constructor";
  return "function";
}

async function queryResolvedSignature(
  checker: Checker,
  node: CallExpression | NewExpression | TaggedTemplateExpression,
  counter: QueryCounter,
): Promise<Signature | undefined> {
  beginQuery(counter);
  const first = await checker.getResolvedSignature(node);
  beginQuery(counter);
  const second = await checker.getResolvedSignature(node);
  if (first?.id !== second?.id) {
    throw new DependencyContractError("resolved signature response correlation mismatch");
  }
  return first;
}

async function resolvedSignatureDeclaration(
  signature: Signature,
  counter: QueryCounter,
  index: DefinitionIndex,
  sourcesByPath: ReadonlyMap<string, TypeScriptSemanticSource>,
): Promise<{
  declaration: Node | null;
  definitionKeys: string[];
  external: boolean;
}> {
  const handle = signature.declaration;
  if (handle === undefined) return { declaration: null, definitionKeys: [], external: false };
  const declaredSource = sourcesByPath.get(compilerPathKey(String(handle.path)));
  if (declaredSource === undefined) return { declaration: null, definitionKeys: [], external: true };
  beginQuery(counter);
  const declaration = await handle.resolve();
  if (declaration === undefined) return { declaration: null, definitionKeys: [], external: false };
  const sourceFile = declaration.getSourceFile();
  const source = sourcesByPath.get(compilerPathKey(String(sourceFile.path)))
    ?? sourcesByPath.get(compilerPathKey(sourceFile.fileName));
  if (source === undefined) return { declaration: null, definitionKeys: [], external: true };
  if (source.relativePath !== declaredSource.relativePath) {
    throw new DependencyContractError("resolved signature declaration source correlation mismatch");
  }
  const { startOffset, endOffset } = nodeSpan(declaration, source.sourceFile);
  const definitionKeys = (index.byDeclaration.get(declarationKey(
    source.relativePath,
    startOffset,
    endOffset,
  )) ?? []).filter((key) => index.definitions.get(key)?.graphKind === "symbol");
  return { declaration, definitionKeys: [...definitionKeys], external: false };
}

function callTargetNode(expression: Expression): Node {
  const callee = transparentCallExpression(expression);
  if (callee.kind === SyntaxKind.PropertyAccessExpression) {
    return (callee as Expression & { readonly name: Node }).name;
  }
  return callee;
}

function callRootIdentifier(expression: Expression): Identifier | null {
  const callee = transparentCallExpression(expression);
  if (callee.kind === SyntaxKind.Identifier) return callee as Identifier;
  if (callee.kind === SyntaxKind.PropertyAccessExpression) {
    return leftmostIdentifier(callee);
  }
  if (callee.kind === SyntaxKind.ElementAccessExpression) {
    return leftmostIdentifier((callee as Expression & { readonly expression: Node }).expression);
  }
  return null;
}

async function callBindingProvenance(
  expression: Expression,
  context: CollectionContext,
  checker: Checker,
  counter: QueryCounter,
): Promise<BindingProvenance | undefined> {
  const root = callRootIdentifier(expression);
  if (root === null || isLexicallyShadowedBinding(root, root.text)) return undefined;
  const symbol = await querySymbol(checker, root, counter, "call binding provenance");
  if (symbol !== undefined && context.externalBindings.isAmbiguous(symbol.id)) return undefined;
  return (symbol === undefined ? undefined : context.externalBindings.get(symbol.id))
    ?? context.bindingProvenance.get(root.text);
}

function directCallDispatch(
  node: CallExpression | NewExpression | TaggedTemplateExpression,
  declaration: Node,
): { callKind: TypeScriptRawCallKind; dispatch: TypeScriptRawCallDispatch; reason: string | null } {
  const callee = transparentCallExpression(callCallee(node));
  if (
    node.kind === SyntaxKind.CallExpression
    && (
      (node as CallExpression).questionDotToken !== undefined
      || (
        (callee.kind === SyntaxKind.PropertyAccessExpression || callee.kind === SyntaxKind.ElementAccessExpression)
        && (callee as Expression & { readonly questionDotToken?: Node }).questionDotToken !== undefined
      )
    )
  ) return { callKind: "function", dispatch: "dynamic", reason: "optional_call_dispatch" };

  if (declaration.kind === SyntaxKind.MethodSignature) {
    return { callKind: "method", dispatch: "open", reason: "interface_dispatch" };
  }
  if (declaration.kind === SyntaxKind.MethodDeclaration) {
    const method = declaration as MethodDeclaration;
    if ((method.modifierFlags & ModifierFlags.Static) !== 0) {
      return { callKind: "method", dispatch: "static", reason: null };
    }
    if ((method.modifierFlags & ModifierFlags.Private) !== 0 || method.name.kind === SyntaxKind.PrivateIdentifier) {
      return { callKind: "method", dispatch: "private", reason: null };
    }
    if (callee.kind === SyntaxKind.PropertyAccessExpression || callee.kind === SyntaxKind.ElementAccessExpression) {
      const receiver = transparentCallExpression((callee as Expression & { readonly expression: Expression }).expression);
      if (receiver.kind === SyntaxKind.NewExpression) {
        return { callKind: "method", dispatch: "fresh_instance", reason: null };
      }
      if (receiver.kind === SyntaxKind.SuperKeyword) {
        return { callKind: "method", dispatch: "super", reason: null };
      }
    }
    return { callKind: "method", dispatch: "open", reason: "open_method_dispatch" };
  }
  if (declaration.kind === SyntaxKind.Constructor) {
    const directConstructor = node.kind === SyntaxKind.NewExpression || callee.kind === SyntaxKind.SuperKeyword;
    return directConstructor
      ? { callKind: "constructor", dispatch: callee.kind === SyntaxKind.SuperKeyword ? "super" : "direct", reason: null }
      : { callKind: "constructor", dispatch: "dynamic", reason: "constructor_value_dispatch" };
  }
  const directlySpelledCallable = [
    SyntaxKind.Identifier,
    SyntaxKind.PropertyAccessExpression,
    SyntaxKind.ElementAccessExpression,
    SyntaxKind.FunctionExpression,
    SyntaxKind.ArrowFunction,
  ].includes(callee.kind);
  if (!directlySpelledCallable) {
    return {
      callKind: node.kind === SyntaxKind.TaggedTemplateExpression ? "tagged_template" : "function",
      dispatch: "dynamic",
      reason: "function_value_dispatch",
    };
  }
  return {
    callKind: node.kind === SyntaxKind.TaggedTemplateExpression ? "tagged_template" : "function",
    dispatch: "direct",
    reason: null,
  };
}

const CALLABLE_EXECUTION_SYNTAX_KINDS = new Set<SyntaxKind>([
  SyntaxKind.FunctionDeclaration,
  SyntaxKind.FunctionExpression,
  SyntaxKind.ArrowFunction,
  SyntaxKind.MethodDeclaration,
  SyntaxKind.Constructor,
  SyntaxKind.GetAccessor,
  SyntaxKind.SetAccessor,
]);

const CANONICAL_CALLER_SEMANTIC_KINDS = new Set([
  "function",
  "method",
  "constructor",
  "anonymous_function",
  "local_function",
]);

function callExecutionOwner(
  context: CollectionContext,
  index: DefinitionIndex,
  node: CallExpression | NewExpression | TaggedTemplateExpression,
): { source: TypeScriptRawCallSource; unavailable: boolean } {
  let branch: Node = node;
  let insideDecorator = false;
  for (let current = node.parent, depth = 0; current !== undefined && depth < MAX_AST_DEPTH; current = current.parent, depth += 1) {
    if (current.kind === SyntaxKind.Decorator) insideDecorator = true;
    if (current.kind === SyntaxKind.PropertyDeclaration) {
      const name = (current as Node & { readonly name?: Node }).name;
      if (name === branch) {
        // A computed field name belongs to the surrounding class-evaluation
        // scope. Its initializer, however, may run for each instance and has
        // no canonical caller until field-initializer scopes are represented.
        branch = current;
        continue;
      }
      return {
        source: { kind: "module_initializer", relativePath: context.source.relativePath },
        unavailable: true,
      };
    }
    if (current.kind === SyntaxKind.ClassStaticBlockDeclaration) {
      return {
        source: { kind: "module_initializer", relativePath: context.source.relativePath },
        unavailable: true,
      };
    }
    if (!CALLABLE_EXECUTION_SYNTAX_KINDS.has(current.kind)) {
      branch = current;
      continue;
    }
    const name = (current as Node & { readonly name?: Node }).name;
    if (name === branch) {
      // A computed callable name executes in the surrounding scope, not when
      // the callable body is invoked. Continue looking for that outer scope.
      branch = current;
      continue;
    }
    if (insideDecorator) {
      // Decorator expressions execute while the surrounding declaration is
      // evaluated. Until that execution scope is represented explicitly, do
      // not attribute them to the decorated member or constructor.
      return {
        source: { kind: "module_initializer", relativePath: context.source.relativePath },
        unavailable: true,
      };
    }
    const endpoint = ownerAtNode(index, context.source, current);
    const definition = endpoint?.kind === "definition" ? index.definitions.get(endpoint.key) : undefined;
    if (
      endpoint?.kind === "definition"
      && definition?.graphKind === "symbol"
      && CANONICAL_CALLER_SEMANTIC_KINDS.has(definition.semanticKind)
    ) return { source: endpoint, unavailable: false };
    return {
      source: { kind: "module_initializer", relativePath: context.source.relativePath },
      unavailable: true,
    };
  }
  if (insideDecorator) {
    return {
      source: { kind: "module_initializer", relativePath: context.source.relativePath },
      unavailable: true,
    };
  }
  const owner = context.owner.kind === "definition"
    ? index.definitions.get(context.owner.key)
    : undefined;
  const hasCanonicalCaller = owner?.graphKind === "symbol"
    && CANONICAL_CALLER_SEMANTIC_KINDS.has(owner.semanticKind);
  const moduleInitializerOwner = owner === undefined || (
    owner.graphKind === "symbol"
    && ["variable", "function_variable", "local_function_variable"].includes(owner.semanticKind)
  );
  return {
    source: context.owner.kind === "definition" && hasCanonicalCaller
      ? context.owner
      : { kind: "module_initializer", relativePath: context.source.relativePath },
    unavailable: context.owner.kind === "definition" && !hasCanonicalCaller && !moduleInitializerOwner,
  };
}

function createCallSite(
  context: CollectionContext,
  index: DefinitionIndex,
  node: CallExpression | NewExpression | TaggedTemplateExpression,
  callKind: TypeScriptRawCallKind,
  dispatch: TypeScriptRawCallDispatch,
  targetsValue: readonly TypeScriptRawDependencyTarget[],
  statusValue: TypeScriptRawDependencyStatus,
  precisionValue: TypeScriptRawDependencyPrecision,
  reasonValue: string | null,
  moduleSpecifier: string | null,
  algorithmValue: string | null = null,
): TypeScriptRawCallSite {
  const { startOffset, endOffset } = nodeSpan(node, context.source.sourceFile);
  const executionOwner = callExecutionOwner(context, index, node);
  const source = executionOwner.source;
  const callerDefinitionUnavailable = executionOwner.unavailable;
  let targets = deduplicateTargets(targetsValue);
  let status = statusValue;
  let precision = precisionValue;
  let reason = reasonValue;
  let algorithm = algorithmValue;
  let finalDispatch = dispatch;
  if (!context.syntacticallyValid) {
    targets = [{ kind: "unknown" }];
    status = "unresolved";
    precision = "heuristic";
    reason = "syntax_invalid";
    algorithm = null;
    finalDispatch = "dynamic";
  }
  if (context.syntacticallyValid && callerDefinitionUnavailable) {
    // Calls in execution scopes which do not yet have a canonical callable
    // definition (for example, instance field initializers) remain in the
    // ledger, but must not be attributed to the module initializer as exact.
    targets = [{ kind: "unknown" }];
    status = "unresolved";
    precision = "heuristic";
    reason = "caller_definition_unavailable";
    algorithm = null;
    finalDispatch = "dynamic";
  }
  if (
    (status === "candidates" && (
      targets.length === 0
      || targets.some((target) => target.kind !== "definition")
      || algorithm === null
    ))
    || (status !== "candidates" && targets.length !== 1)
  ) {
    targets = [{ kind: "unknown" }];
    status = "unresolved";
    precision = "heuristic";
    reason ??= "call_target_not_unique";
    algorithm = null;
    finalDispatch = "dynamic";
  }
  const condition = WEB_CONDITION;
  return {
    key: siteKey(source, "call", context.source.relativePath, startOffset, endOffset),
    source,
    specifier: callSpecifier(node, context.source.sourceFile),
    callKind,
    dispatch: finalDispatch,
    moduleSpecifier,
    status,
    precision,
    reason,
    algorithm,
    condition,
    targets,
    targetConditions: targets.map(() => condition),
    evidence: {
      relativePath: context.source.relativePath,
      startOffset,
      endOffset,
      detail: status === "resolved"
        ? "TypeChecker resolved-signature direct call occurrence"
        : status === "candidates"
          ? "TypeChecker closed local candidate call occurrence"
        : status === "external"
          ? "TypeChecker external call boundary occurrence"
          : "TypeChecker unresolved call occurrence",
      occurrenceKind: callOccurrenceKind(node),
      targetBasis: basisForTargets(targets),
    },
  };
}

const CALLABLE_TARGET_SEMANTIC_KINDS = new Set([
  "function",
  "local_function",
  "anonymous_function",
  "method",
  "constructor",
]);

interface ClosedLocalCallTargets {
  targets: TypeScriptRawDependencyTarget[];
}

type ClosedLocalCallableResolution =
  | { kind: "targets"; value: ClosedLocalCallTargets }
  | { kind: "blocked"; reason: "reassignable_function_declaration" }
  | null;

type LocalConstBinding =
  | { kind: "local"; declaration: VariableDeclaration; initializer: Expression }
  | { kind: "not_variable" }
  | { kind: "unsupported" };

function canonicalCallableTargets(
  targets: readonly TypeScriptRawDependencyTarget[],
  index: DefinitionIndex,
): TypeScriptRawDependencyTarget[] | null {
  const canonical = deduplicateTargets(targets);
  if (
    canonical.length === 0
    || canonical.some((target) => (
      target.kind !== "definition"
      || !CALLABLE_TARGET_SEMANTIC_KINDS.has(index.definitions.get(target.key)?.semanticKind ?? "")
    ))
  ) return null;
  return canonical;
}

function directDefinitionTargetsAtNode(
  index: DefinitionIndex,
  source: TypeScriptSemanticSource,
  node: Node,
): TypeScriptRawDependencyTarget[] | null {
  const { startOffset, endOffset } = nodeSpan(node, source.sourceFile);
  return canonicalCallableTargets(
    (index.byDeclaration.get(declarationKey(source.relativePath, startOffset, endOffset)) ?? [])
      .map((key) => ({ kind: "definition" as const, key })),
    index,
  );
}

function localConstBindingKey(
  declaration: VariableDeclaration,
  source: TypeScriptSemanticSource,
): string {
  const { startOffset, endOffset } = nodeSpan(declaration, source.sourceFile);
  return declarationKey(source.relativePath, startOffset, endOffset);
}

async function localConstBindingForIdentifier(
  identifier: Identifier,
  context: CollectionContext,
  checker: Checker,
  counter: QueryCounter,
  sourcesByPath: ReadonlyMap<string, TypeScriptSemanticSource>,
): Promise<LocalConstBinding> {
  const symbol = await querySymbol(checker, identifier, counter, "closed local call binding");
  if (symbol === undefined) return { kind: "not_variable" };
  const unwrapped = await unwrapAlias(checker, symbol, counter);
  if (unwrapped === null || unwrapped.declarations.length !== 1) return { kind: "unsupported" };
  const handle = unwrapped.declarations[0]!;
  const declaredSource = sourcesByPath.get(compilerPathKey(String(handle.path)));
  if (declaredSource === undefined) return { kind: "unsupported" };
  beginQuery(counter);
  const declaration = await handle.resolve();
  if (declaration === undefined) return { kind: "unsupported" };
  const sourceFile = declaration.getSourceFile();
  const source = sourcesByPath.get(compilerPathKey(String(sourceFile.path)))
    ?? sourcesByPath.get(compilerPathKey(sourceFile.fileName));
  if (
    source === undefined
    || source.relativePath !== declaredSource.relativePath
    || source.relativePath !== context.source.relativePath
  ) return declaration.kind === SyntaxKind.VariableDeclaration
    ? { kind: "unsupported" }
    : { kind: "not_variable" };
  if (declaration.kind !== SyntaxKind.VariableDeclaration) return { kind: "not_variable" };
  const variable = declaration as VariableDeclaration;
  const list = variable.parent;
  const isConst = list.kind === SyntaxKind.VariableDeclarationList
    && (((list as Node & { readonly flags: number }).flags & NodeFlags.Const) !== 0);
  if (
    !isConst
    || variable.name.kind !== SyntaxKind.Identifier
    || variable.initializer === undefined
  ) return { kind: "unsupported" };
  const declarationSpan = nodeSpan(variable, source.sourceFile);
  const referenceSpan = nodeSpan(identifier, context.source.sourceFile);
  if (declarationSpan.startOffset >= referenceSpan.startOffset) return { kind: "unsupported" };
  return { kind: "local", declaration: variable, initializer: variable.initializer };
}

async function directCallableTargetsForIdentifier(
  identifier: Identifier,
  checker: Checker,
  counter: QueryCounter,
  index: DefinitionIndex,
  sourcesByPath: ReadonlyMap<string, TypeScriptSemanticSource>,
): Promise<TypeScriptRawDependencyTarget[] | "reassignable_function_declaration" | null> {
  // A FunctionDeclaration is a mutable lexical binding. The checker can keep
  // pointing a value alias at its declaration even after a write, so never use
  // that declaration as a closed-flow leaf without a write proof.
  const leafSymbol = await querySymbol(checker, identifier, counter, "closed local call leaf");
  if (leafSymbol === undefined) return null;
  if ((leafSymbol.flags & SymbolFlags.Alias) === 0) {
    if (leafSymbol.declarations.length === 0 || leafSymbol.declarations.length > MAX_SYMBOL_DECLARATIONS) {
      return "reassignable_function_declaration";
    }
    for (const handle of leafSymbol.declarations) {
      beginQuery(counter);
      const declaration = await handle.resolve();
      if (declaration === undefined || declaration.kind === SyntaxKind.FunctionDeclaration) {
        return "reassignable_function_declaration";
      }
    }
  }
  const symbol = await querySymbol(checker, identifier, counter, "closed local call target");
  if (symbol === undefined) return null;
  const resolved = await compilerSymbolTargets(symbol, checker, counter, index, sourcesByPath, false);
  const targets = canonicalCallableTargets(resolved.targets, index);
  return targets?.length === 1 ? targets : null;
}

function mergeClosedLocalTargets(
  left: ClosedLocalCallTargets,
  right: ClosedLocalCallTargets,
): ClosedLocalCallTargets {
  return {
    targets: deduplicateTargets([...left.targets, ...right.targets]),
  };
}

async function closedLocalCallableTargets(
  expression: Expression,
  context: CollectionContext,
  checker: Checker,
  counter: QueryCounter,
  index: DefinitionIndex,
  sourcesByPath: ReadonlyMap<string, TypeScriptSemanticSource>,
  visiting: Set<string>,
  depth: number,
): Promise<ClosedLocalCallableResolution> {
  if (depth > MAX_CLOSED_CALL_FLOW_DEPTH) return null;
  const current = transparentCallExpression(expression);
  if (current.kind === SyntaxKind.ConditionalExpression) {
    const conditional = current as Expression & {
      readonly whenTrue: Expression;
      readonly whenFalse: Expression;
    };
    const whenTrue = await closedLocalCallableTargets(
      conditional.whenTrue, context, checker, counter, index, sourcesByPath, visiting, depth + 1,
    );
    const whenFalse = await closedLocalCallableTargets(
      conditional.whenFalse, context, checker, counter, index, sourcesByPath, visiting, depth + 1,
    );
    if (whenTrue?.kind === "blocked" || whenFalse?.kind === "blocked") {
      return { kind: "blocked", reason: "reassignable_function_declaration" };
    }
    if (whenTrue === null || whenFalse === null) return null;
    return { kind: "targets", value: mergeClosedLocalTargets(whenTrue.value, whenFalse.value) };
  }
  if (current.kind === SyntaxKind.ArrowFunction || current.kind === SyntaxKind.FunctionExpression) {
    const targets = directDefinitionTargetsAtNode(index, context.source, current);
    return targets?.length === 1 ? { kind: "targets", value: { targets } } : null;
  }
  if (current.kind !== SyntaxKind.Identifier) return null;
  const identifier = current as Identifier;
  const binding = await localConstBindingForIdentifier(identifier, context, checker, counter, sourcesByPath);
  if (binding.kind === "unsupported") return null;
  if (binding.kind === "not_variable") {
    const targets = await directCallableTargetsForIdentifier(identifier, checker, counter, index, sourcesByPath);
    if (targets === "reassignable_function_declaration") {
      return { kind: "blocked", reason: "reassignable_function_declaration" };
    }
    return targets === null ? null : { kind: "targets", value: { targets } };
  }
  const key = localConstBindingKey(binding.declaration, context.source);
  if (visiting.has(key)) return null;
  visiting.add(key);
  try {
    return await closedLocalCallableTargets(
      binding.initializer, context, checker, counter, index, sourcesByPath, visiting, depth + 1,
    );
  } finally {
    visiting.delete(key);
  }
}

async function closedLocalFunctionCallTargets(
  callee: Expression,
  context: CollectionContext,
  checker: Checker,
  counter: QueryCounter,
  index: DefinitionIndex,
  sourcesByPath: ReadonlyMap<string, TypeScriptSemanticSource>,
): Promise<ClosedLocalCallableResolution> {
  const current = transparentCallExpression(callee);
  if (current.kind !== SyntaxKind.Identifier) return null;
  const binding = await localConstBindingForIdentifier(
    current as Identifier,
    context,
    checker,
    counter,
    sourcesByPath,
  );
  if (binding.kind !== "local") return null;
  const result = await closedLocalCallableTargets(
    binding.initializer,
    context,
    checker,
    counter,
    index,
    sourcesByPath,
    new Set([localConstBindingKey(binding.declaration, context.source)]),
    0,
  );
  return result?.kind === "targets" && result.value.targets.length === 0 ? null : result;
}

async function queryPropertyOfType(
  checker: Checker,
  type: CompilerType,
  name: string,
  counter: QueryCounter,
): Promise<CompilerSymbol | undefined> {
  beginQuery(counter);
  const first = await checker.getPropertyOfType(type, name);
  beginQuery(counter);
  const second = await checker.getPropertyOfType(type, name);
  if (first?.id !== second?.id) {
    throw new DependencyContractError("closed fresh-instance property response correlation mismatch");
  }
  return first;
}

function hasDecoratorModifier(node: Node): boolean {
  return ((node as Node & { readonly modifiers?: readonly Node[] }).modifiers ?? [])
    .some((modifier) => modifier.kind === SyntaxKind.Decorator);
}

function hasConservativelySafeFreshInstanceClassShape(node: Node): boolean {
  if (node.kind !== SyntaxKind.ClassDeclaration || hasDecoratorModifier(node)) return false;
  const declaration = node as Node & {
    readonly heritageClauses?: readonly Node[];
    readonly members?: readonly Node[];
  };
  // Constructors, fields, accessors, inheritance, and decorators can replace
  // the method selected from the instance type before the observed call. A
  // class containing only undecorated own methods has no such construction-
  // time hook in the modeled source.
  if ((declaration.heritageClauses?.length ?? 0) !== 0) return false;
  return (declaration.members ?? []).every((member) => (
    member.kind === SyntaxKind.MethodDeclaration && !hasDecoratorModifier(member)
  ));
}

async function hasConservativelySafeFreshInstanceClass(
  constructorSymbol: CompilerSymbol,
  checker: Checker,
  counter: QueryCounter,
): Promise<boolean> {
  const unwrapped = await unwrapAlias(checker, constructorSymbol, counter);
  if (
    unwrapped === null
    || unwrapped.declarations.length !== 1
    || unwrapped.declarations.length > MAX_SYMBOL_DECLARATIONS
  ) return false;
  beginQuery(counter);
  const declaration = await unwrapped.declarations[0]!.resolve();
  return declaration !== undefined && hasConservativelySafeFreshInstanceClassShape(declaration);
}

function isSimpleConstBinding(declaration: VariableDeclaration): boolean {
  const list = declaration.parent;
  return list.kind === SyntaxKind.VariableDeclarationList
    && (((list as Node & { readonly flags: number }).flags & NodeFlags.Const) !== 0)
    && declaration.name.kind === SyntaxKind.Identifier
    && declaration.initializer !== undefined;
}

function isDirectClosedFreshInstanceCallUse(identifier: Identifier, methodName: string): boolean {
  const access = identifier.parent;
  if (access.kind !== SyntaxKind.PropertyAccessExpression) return false;
  const property = access as Expression & {
    readonly expression: Expression;
    readonly name: Node;
    readonly questionDotToken?: Node;
  };
  if (
    property.expression !== identifier
    || property.questionDotToken !== undefined
    || property.name.kind !== SyntaxKind.Identifier
    || (property.name as Identifier).text !== methodName
  ) return false;
  const invocation = access.parent;
  if (invocation.kind === SyntaxKind.CallExpression) {
    return (invocation as CallExpression).expression === access
      && (invocation as CallExpression).questionDotToken === undefined;
  }
  return invocation.kind === SyntaxKind.TaggedTemplateExpression
    && (invocation as TaggedTemplateExpression).tag === access;
}

function freshReceiverIdentifierIndex(
  sourceFile: SourceFile,
  state: FreshReceiverProofState,
): ReadonlyMap<string, readonly Identifier[]> | null {
  if (state.indexFailed) return null;
  if (state.identifierIndex !== null) return state.identifierIndex;
  const identifiers = new Map<string, Identifier[]>();
  let visited = 0;
  let failed = false;
  const visit = (node: Node, depth: number): void => {
    if (failed) return;
    if (depth > MAX_AST_DEPTH || visited >= MAX_AST_NODES) {
      failed = true;
      return;
    }
    visited += 1;
    if (node.kind === SyntaxKind.Identifier) {
      const identifier = node as Identifier;
      const entries = identifiers.get(identifier.text) ?? [];
      entries.push(identifier);
      identifiers.set(identifier.text, entries);
    }
    node.forEachChild((child) => {
      visit(child, depth + 1);
      return undefined;
    });
  };
  visit(sourceFile, 0);
  if (failed) {
    state.indexFailed = true;
    return null;
  }
  state.identifierIndex = identifiers;
  return identifiers;
}

function hasConservativelyClosedFreshReceiverUses(
  declaration: VariableDeclaration,
  methodName: string,
  sourceFile: SourceFile,
  state: FreshReceiverProofState,
): boolean {
  if (!isSimpleConstBinding(declaration)) return false;
  const name = declaration.name as Identifier;
  const { startOffset, endOffset } = nodeSpan(declaration, sourceFile);
  const proofKey = `${startOffset}:${endOffset}:${methodName}`;
  const cached = state.useProofs.get(proofKey);
  if (cached !== undefined) return cached;
  const identifiers = freshReceiverIdentifierIndex(sourceFile, state);
  if (identifiers === null) return false;
  let directCallCount = 0;
  for (const identifier of identifiers.get(name.text) ?? []) {
    if (identifier === name) continue;
    if (!isDirectClosedFreshInstanceCallUse(identifier, methodName)) {
      // Any alias, property read/write, argument/return, capture, or other
      // use could expose or replace the receiver's method. Do not infer a
      // candidate without a complete alias/effect proof.
      state.useProofs.set(proofKey, false);
      return false;
    }
    directCallCount += 1;
  }
  // One call avoids underapproximating a later invocation after the first
  // method body mutates its own receiver.
  const result = directCallCount === 1;
  state.useProofs.set(proofKey, result);
  return result;
}

async function closedFreshInstanceMethodTargets(
  expression: Expression,
  methodName: string,
  context: CollectionContext,
  checker: Checker,
  counter: QueryCounter,
  index: DefinitionIndex,
  sourcesByPath: ReadonlyMap<string, TypeScriptSemanticSource>,
  visiting: Set<string>,
  depth: number,
): Promise<ClosedLocalCallTargets | null> {
  if (depth > MAX_CLOSED_CALL_FLOW_DEPTH) return null;
  const current = transparentCallExpression(expression);
  if (current.kind === SyntaxKind.ConditionalExpression) {
    const conditional = current as Expression & {
      readonly whenTrue: Expression;
      readonly whenFalse: Expression;
    };
    const whenTrue = await closedFreshInstanceMethodTargets(
      conditional.whenTrue, methodName, context, checker, counter, index, sourcesByPath, visiting, depth + 1,
    );
    const whenFalse = await closedFreshInstanceMethodTargets(
      conditional.whenFalse, methodName, context, checker, counter, index, sourcesByPath, visiting, depth + 1,
    );
    return whenTrue === null || whenFalse === null ? null : mergeClosedLocalTargets(whenTrue, whenFalse);
  }
  if (current.kind === SyntaxKind.Identifier) {
    const binding = await localConstBindingForIdentifier(
      current as Identifier, context, checker, counter, sourcesByPath,
    );
    if (binding.kind !== "local") return null;
    if (!hasConservativelyClosedFreshReceiverUses(
      binding.declaration,
      methodName,
      context.source.sourceFile,
      context.freshReceiverProof,
    )) return null;
    const key = localConstBindingKey(binding.declaration, context.source);
    if (visiting.has(key)) return null;
    visiting.add(key);
    try {
      return await closedFreshInstanceMethodTargets(
        binding.initializer, methodName, context, checker, counter, index, sourcesByPath, visiting, depth + 1,
      );
    } finally {
      visiting.delete(key);
    }
  }
  if (current.kind !== SyntaxKind.NewExpression) return null;
  if (((current as NewExpression).arguments?.length ?? 0) !== 0) return null;
  const constructorExpression = transparentCallExpression(callCallee(current as NewExpression));
  if (constructorExpression.kind !== SyntaxKind.Identifier) return null;
  const constructorSymbol = await querySymbol(
    checker, constructorExpression, counter, "closed fresh-instance constructor",
  );
  if (constructorSymbol === undefined) return null;
  if (!await hasConservativelySafeFreshInstanceClass(constructorSymbol, checker, counter)) return null;
  const constructorTargets = (await compilerSymbolTargets(
    constructorSymbol, checker, counter, index, sourcesByPath, true,
  )).targets;
  if (
    constructorTargets.length !== 1
    || constructorTargets[0]?.kind !== "definition"
    || index.definitions.get(constructorTargets[0].key)?.semanticKind !== "class"
  ) return null;
  const instanceType = await queryTypeAtLocation(checker, current, counter, "closed fresh-instance receiver");
  if (instanceType === undefined) return null;
  const property = await queryPropertyOfType(checker, instanceType, methodName, counter);
  if (property === undefined) return null;
  const methodTargets = canonicalCallableTargets(
    (await compilerSymbolTargets(property, checker, counter, index, sourcesByPath, false)).targets,
    index,
  );
  if (methodTargets?.length !== 1 || methodTargets[0]?.kind !== "definition") return null;
  const method = index.definitions.get(methodTargets[0].key);
  if (
    method?.semanticKind !== "method"
    || method.owner.kind !== "definition"
    || method.owner.key !== constructorTargets[0]!.key
    || (index.declarationLocationsByDefinition.get(methodTargets[0].key)?.length ?? 0) !== 1
  ) return null;
  return { targets: methodTargets };
}

async function closedLocalFreshInstanceCallTargets(
  callee: Expression,
  context: CollectionContext,
  checker: Checker,
  counter: QueryCounter,
  index: DefinitionIndex,
  sourcesByPath: ReadonlyMap<string, TypeScriptSemanticSource>,
): Promise<ClosedLocalCallTargets | null> {
  const current = transparentCallExpression(callee);
  if (current.kind !== SyntaxKind.PropertyAccessExpression) return null;
  const access = current as Expression & {
    readonly expression: Expression;
    readonly name: Node;
    readonly questionDotToken?: Node;
  };
  if (access.questionDotToken !== undefined || access.name.kind !== SyntaxKind.Identifier) return null;
  const receiver = transparentCallExpression(access.expression);
  if (receiver.kind !== SyntaxKind.Identifier) return null;
  const binding = await localConstBindingForIdentifier(
    receiver as Identifier, context, checker, counter, sourcesByPath,
  );
  if (binding.kind !== "local") return null;
  if (!hasConservativelyClosedFreshReceiverUses(
    binding.declaration,
    (access.name as Identifier).text,
    context.source.sourceFile,
    context.freshReceiverProof,
  )) return null;
  return await closedFreshInstanceMethodTargets(
    binding.initializer,
    (access.name as Identifier).text,
    context,
    checker,
    counter,
    index,
    sourcesByPath,
    new Set([localConstBindingKey(binding.declaration, context.source)]),
    0,
  );
}

async function collectSemanticCall(
  node: CallExpression | NewExpression | TaggedTemplateExpression,
  context: CollectionContext,
  checker: Checker,
  counter: QueryCounter,
  index: DefinitionIndex,
  sourcesByPath: ReadonlyMap<string, TypeScriptSemanticSource>,
): Promise<TypeScriptRawCallSite[]> {
  if (node.kind === SyntaxKind.CallExpression) {
    const call = node as CallExpression;
    const lexicalModuleLoader = call.expression.kind === SyntaxKind.ImportKeyword
      || (
        call.expression.kind === SyntaxKind.Identifier
        && (call.expression as Identifier).text === "require"
        && !isLexicallyShadowedBinding(call.expression, "require", true)
      );
    if (
      (!context.syntacticallyValid && lexicalModuleLoader)
      || (context.syntacticallyValid && await isModuleLoaderCall(call, checker, counter))
    ) return [];
  }
  if (!context.syntacticallyValid) {
    return [createCallSite(
      context,
      index,
      node,
      defaultCallKind(node),
      "dynamic",
      [{ kind: "unknown" }],
      "unresolved",
      "heuristic",
      "syntax_invalid",
      null,
    )];
  }

  const callee = callCallee(node);
  // Candidate flows model invocations only. A NewExpression has a construct
  // signature and must stay on the exact/unresolved constructor path; in
  // particular, `new receiver.run()` is not a fresh-instance method call.
  if (node.kind !== SyntaxKind.NewExpression) {
    const closedFunctionTargets = await closedLocalFunctionCallTargets(
      callee,
      context,
      checker,
      counter,
      index,
      sourcesByPath,
    );
    if (closedFunctionTargets?.kind === "targets") {
      return [createCallSite(
        context,
        index,
        node,
        defaultCallKind(node),
        "dynamic",
        closedFunctionTargets.value.targets,
        "candidates",
        "overapprox",
        null,
        null,
        TYPESCRIPT_CLOSED_LOCAL_CALL_FLOW_ALGORITHM,
      )];
    }
    if (closedFunctionTargets?.kind === "blocked") {
      return [createCallSite(
        context,
        index,
        node,
        defaultCallKind(node),
        "dynamic",
        [{ kind: "unknown" }],
        "unresolved",
        "heuristic",
        closedFunctionTargets.reason,
        null,
      )];
    }
    const closedFreshInstanceTargets = await closedLocalFreshInstanceCallTargets(
      callee,
      context,
      checker,
      counter,
      index,
      sourcesByPath,
    );
    if (closedFreshInstanceTargets !== null) {
      return [createCallSite(
        context,
        index,
        node,
        node.kind === SyntaxKind.TaggedTemplateExpression ? "tagged_template" : "method",
        "fresh_instance",
        closedFreshInstanceTargets.targets,
        "candidates",
        "overapprox",
        null,
        null,
        TYPESCRIPT_CLOSED_LOCAL_FRESH_INSTANCE_FLOW_ALGORITHM,
      )];
    }
  }
  const provenance = await callBindingProvenance(callee, context, checker, counter);
  const externalFromBinding = provenance?.targets.find(
    (target): target is Extract<TypeScriptRawDependencyTarget, { kind: "external" }> => target.kind === "external",
  ) ?? (provenance !== undefined && isExternalModuleSpecifier(provenance.moduleSpecifier)
    ? externalTarget(provenance.moduleSpecifier, provenance.importedName)
    : undefined);
  const calleeType = await queryTypeAtLocation(checker, callee, counter, "call callee");
  if (calleeType !== undefined && (calleeType.flags & (TypeFlags.Union | TypeFlags.Intersection)) !== 0) {
    return [createCallSite(context, index, node, defaultCallKind(node), "dynamic",
      [{ kind: "unknown" }], "unresolved", "heuristic",
      (calleeType.flags & TypeFlags.Intersection) !== 0 ? "intersection_dispatch" : "union_dispatch", null)];
  }
  const signature = await queryResolvedSignature(checker, node, counter);
  if (signature === undefined) {
    if (externalFromBinding !== undefined) {
      return [createCallSite(context, index, node, defaultCallKind(node), "external", [externalFromBinding], "external", "heuristic",
        "external_package_instance_unavailable", provenance?.moduleSpecifier ?? null)];
    }
    return [createCallSite(context, index, node, defaultCallKind(node), "dynamic",
      [{ kind: "unknown" }], "unresolved", "heuristic", "resolved_signature_unavailable", null)];
  }

  const resolved = await resolvedSignatureDeclaration(signature, counter, index, sourcesByPath);
  if (resolved.external) {
    const target = externalFromBinding ?? externalTarget(`typescript:stdlib:${callSpecifier(node, context.source.sourceFile)}`);
    const canonical = target.kind === "external" && (
      target.locator.startsWith("typescript:stdlib:") || target.locator.startsWith("node:")
    );
    return [createCallSite(context, index, node, defaultCallKind(node), "external",
      [target], "external", canonical ? "exact" : "heuristic",
      canonical ? null : "external_package_instance_unavailable", provenance?.moduleSpecifier ?? null)];
  }
  if (resolved.declaration === null && externalFromBinding !== undefined) {
    return [createCallSite(context, index, node, defaultCallKind(node), "external", [externalFromBinding], "external", "heuristic",
      "external_package_instance_unavailable", provenance?.moduleSpecifier ?? null)];
  }
  const targetNode = callTargetNode(callee);
  const targetSymbol = await querySymbol(checker, targetNode, counter, "direct call target");
  const compilerTargetResolution = targetSymbol === undefined
    ? { targets: [] as TypeScriptRawDependencyTarget[], external: false, repositoryDeclarations: false }
    : await compilerSymbolTargets(targetSymbol, checker, counter, index, sourcesByPath, false);
  const rootIdentifier = callRootIdentifier(callee);
  const rootSymbol = rootIdentifier === null || rootIdentifier === targetNode
    ? targetSymbol
    : await querySymbol(checker, rootIdentifier, counter, "direct call root");
  const compilerRootResolution = rootSymbol === undefined || rootSymbol === targetSymbol
    ? compilerTargetResolution
    : await compilerSymbolTargets(rootSymbol, checker, counter, index, sourcesByPath, false);
  const compilerTargets = compilerTargetResolution.targets
    .filter((target): target is Extract<TypeScriptRawDependencyTarget, { kind: "definition" }> => target.kind === "definition")
    .map((target) => target.key);
  const compilerGlobalBoundary = resolved.declaration === null
    && rootIdentifier !== null
    && !isLexicallyShadowedBinding(rootIdentifier, rootIdentifier.text)
    && !compilerTargetResolution.repositoryDeclarations
    && !compilerRootResolution.repositoryDeclarations
    && calleeType !== undefined
    && !calleeType.isErrorType();
  if (
    resolved.declaration === null
    && (compilerTargetResolution.external || compilerRootResolution.external || compilerGlobalBoundary)
  ) {
    return [createCallSite(
      context,
      index,
      node,
      defaultCallKind(node),
      "external",
      [externalTarget(`typescript:stdlib:${callSpecifier(node, context.source.sourceFile)}`)],
      "external",
      "exact",
      null,
      null,
    )];
  }
  if (calleeType !== undefined) {
    beginQuery(counter);
    const firstSignatures = await checker.getSignaturesOfType(
      calleeType,
      node.kind === SyntaxKind.NewExpression ? SignatureKind.Construct : SignatureKind.Call,
    );
    beginQuery(counter);
    const secondSignatures = await checker.getSignaturesOfType(
      calleeType,
      node.kind === SyntaxKind.NewExpression ? SignatureKind.Construct : SignatureKind.Call,
    );
    if (
      !Array.isArray(firstSignatures)
      || !Array.isArray(secondSignatures)
      || firstSignatures.length > MAX_SYMBOL_DECLARATIONS
      || secondSignatures.length > MAX_SYMBOL_DECLARATIONS
    ) {
      throw new DependencyContractError("call signature response exceeds its bounded cardinality");
    }
    if (
      JSON.stringify(firstSignatures.map((candidate) => candidate.id))
      !== JSON.stringify(secondSignatures.map((candidate) => candidate.id))
    ) {
      throw new DependencyContractError("call signature response correlation mismatch");
    }
    if (firstSignatures.length > 1) {
      return [createCallSite(context, index, node, defaultCallKind(node), "dynamic",
        [{ kind: "unknown" }], "unresolved", "heuristic", "overload_dispatch", null)];
    }
  }
  if (resolved.declaration === null || resolved.definitionKeys.length !== 1) {
    return [createCallSite(context, index, node, defaultCallKind(node), "dynamic",
      [{ kind: "unknown" }], "unresolved", "heuristic",
      resolved.declaration === null ? "resolved_signature_declaration_missing" : "resolved_signature_not_canonical", null)];
  }

  const targetKey = resolved.definitionKeys[0]!;
  const definition = index.definitions.get(targetKey);
  if (definition === undefined || definition.graphKind !== "symbol") {
    return [createCallSite(context, index, node, defaultCallKind(node), "dynamic", [{ kind: "unknown" }], "unresolved", "heuristic",
      "resolved_signature_not_canonical", null)];
  }
  if ((index.declarationLocationsByDefinition.get(targetKey)?.length ?? 0) > 1) {
    return [createCallSite(context, index, node, callKindForDefinition(node, definition.semanticKind), "dynamic",
      [{ kind: "unknown" }], "unresolved", "heuristic", "overload_dispatch", null)];
  }
  if (definition.semanticKind === "function_variable" || definition.semanticKind === "local_function_variable" || definition.semanticKind === "variable") {
    return [createCallSite(context, index, node, defaultCallKind(node), "dynamic", [{ kind: "unknown" }], "unresolved", "heuristic",
      "function_value_dispatch", null)];
  }

  const transparent = transparentCallExpression(callee);
  const directExpressionDeclaration = [SyntaxKind.FunctionExpression, SyntaxKind.ArrowFunction].includes(transparent.kind);
  const superCall = transparent.kind === SyntaxKind.SuperKeyword;
  const constructorOwner = definition.semanticKind === "constructor" && definition.owner.kind === "definition"
    ? definition.owner.key
    : null;
  const compilerTargetMatches = compilerTargets.length === 1 && (
    compilerTargets[0] === targetKey
    || (
      node.kind === SyntaxKind.NewExpression
      && constructorOwner !== null
      && compilerTargets[0] === constructorOwner
    )
  );
  if (
    !directExpressionDeclaration
    && !superCall
    && !compilerTargetMatches
  ) {
    return [createCallSite(context, index, node, callKindForDefinition(node, definition.semanticKind), "dynamic", [{ kind: "unknown" }], "unresolved", "heuristic",
      "function_value_dispatch", null)];
  }

  if (
    resolved.declaration.kind === SyntaxKind.MethodDeclaration
    && ((resolved.declaration as MethodDeclaration).modifierFlags & ModifierFlags.Static) !== 0
    && (transparent.kind === SyntaxKind.PropertyAccessExpression || transparent.kind === SyntaxKind.ElementAccessExpression)
  ) {
    const receiver = transparentCallExpression(
      (transparent as Expression & { readonly expression: Expression }).expression,
    );
    if (receiver.kind !== SyntaxKind.SuperKeyword) {
      const receiverSymbol = await querySymbol(checker, receiver, counter, "static call receiver");
      const receiverTargets = receiverSymbol === undefined
        ? []
        : (await compilerSymbolTargets(receiverSymbol, checker, counter, index, sourcesByPath, true)).targets
          .filter((target): target is Extract<TypeScriptRawDependencyTarget, { kind: "definition" }> => target.kind === "definition")
          .map((target) => target.key);
      const ownerKey = definition.owner.kind === "definition" ? definition.owner.key : null;
      if (ownerKey === null || receiverTargets.length !== 1 || receiverTargets[0] !== ownerKey) {
        return [createCallSite(context, index, node, callKindForDefinition(node, definition.semanticKind), "dynamic", [{ kind: "unknown" }], "unresolved", "heuristic",
          "function_value_dispatch", null)];
      }
    }
  }
  if (
    resolved.declaration.kind === SyntaxKind.MethodDeclaration
    && ((resolved.declaration as MethodDeclaration).modifierFlags & (ModifierFlags.Static | ModifierFlags.Private)) === 0
    && (resolved.declaration as MethodDeclaration).name.kind !== SyntaxKind.PrivateIdentifier
    && (transparent.kind === SyntaxKind.PropertyAccessExpression || transparent.kind === SyntaxKind.ElementAccessExpression)
  ) {
    const receiver = transparentCallExpression(
      (transparent as Expression & { readonly expression: Expression }).expression,
    );
    if (receiver.kind === SyntaxKind.NewExpression) {
      const constructorExpression = callCallee(receiver as NewExpression);
      const constructorSymbol = await querySymbol(checker, callTargetNode(constructorExpression), counter, "fresh call receiver");
      const constructorTargets = constructorSymbol === undefined
        ? []
        : (await compilerSymbolTargets(constructorSymbol, checker, counter, index, sourcesByPath, true)).targets
          .filter((target): target is Extract<TypeScriptRawDependencyTarget, { kind: "definition" }> => target.kind === "definition")
          .map((target) => target.key);
      const ownerKey = definition.owner.kind === "definition" ? definition.owner.key : null;
      if (ownerKey === null || constructorTargets.length !== 1 || constructorTargets[0] !== ownerKey) {
        return [createCallSite(context, index, node, callKindForDefinition(node, definition.semanticKind), "dynamic", [{ kind: "unknown" }], "unresolved", "heuristic",
          "function_value_dispatch", null)];
      }
    }
  }

  const direct = directCallDispatch(node, resolved.declaration);
  // New/tagged syntax is part of the protocol contract even when the resolved
  // declaration is a function or method. Dispatch remains semantic, while the
  // occurrence determines these two call kinds.
  const directCallKind = node.kind === SyntaxKind.CallExpression
    ? direct.callKind
    : defaultCallKind(node);
  if (direct.reason !== null) {
    return [createCallSite(context, index, node, directCallKind, direct.dispatch, [{ kind: "unknown" }], "unresolved", "heuristic",
      direct.reason, null)];
  }
  return [createCallSite(context, index, node, directCallKind, direct.dispatch, [{ kind: "definition", key: targetKey }],
    "resolved", "exact", null, provenance?.moduleSpecifier ?? null)];
}

async function collectImportType(
  node: ImportTypeNode,
  context: CollectionContext,
  checker: Checker,
  counter: QueryCounter,
  index: DefinitionIndex,
  sourcesByPath: ReadonlyMap<string, TypeScriptSemanticSource>,
): Promise<TypeScriptRawDependencySite[]> {
  const directive = resolutionModeDirective(node.attributes, true);
  const literal = (node.argument as Node & { readonly literal?: Node }).literal;
  const moduleSpecifier = stringLiteralText(literal);
  const anchor = literal ?? node.argument;
  const sites = [createSite(context, "web_import", "imports", "import_type", anchor,
    moduleSpecifier ?? node.argument.getText(context.source.sourceFile),
    moduleSpecifier === null ? [] : await moduleTargets(checker, counter, anchor, moduleSpecifier, index, sourcesByPath),
    moduleSpecifier === null ? "non_literal_module_specifier" : null,
    "TypeChecker import-type module occurrence", true, undefined, directive)];
  if (node.qualifier !== undefined) {
    const terminal = terminalIdentifier(node.qualifier);
    if (terminal !== null) {
      const exportPath = qualifiedIdentifierPath(node.qualifier).map((identifier) => identifier.text);
      const symbol = await querySymbol(checker, terminal, counter, "import type qualifier");
      let targets: TypeScriptRawDependencyTarget[] = [];
      let nonTypeTarget = false;
      if (symbol !== undefined) {
        const resolved = await compilerSymbolTargets(symbol, checker, counter, index, sourcesByPath, true);
        targets = typeUseTargets(resolved.targets, index);
        nonTypeTarget = resolved.targets.some((target) => target.kind === "definition") && targets.length === 0;
        if (targets.length === 0 && resolved.external && moduleSpecifier !== null) targets = [externalTarget(moduleSpecifier, symbol.name)];
      }
      sites.push(createSite(context, "type_use", "type_uses", "type_reference", terminal,
        moduleSpecifier === null
          ? terminal.text
          : structuredBindingSpecifier(moduleSpecifier, terminal.text, "named"),
        targets, nonTypeTarget ? "value_symbol_is_not_a_type" : null,
        "TypeChecker import-type named reference occurrence", true,
        moduleSpecifier === null ? undefined : {
          moduleSpecifier,
          importedName: terminal.text,
          exportPath,
          resolutionMode: directive.mode,
          resolutionModeError: directive.error,
          ...(directive.proof === undefined ? {} : { resolutionModeProof: directive.proof }),
        }, directive));
    }
  }
  return sites;
}

async function collectTypeReference(
  typeName: Node,
  occurrenceKind: string,
  context: CollectionContext,
  checker: Checker,
  counter: QueryCounter,
  index: DefinitionIndex,
  sourcesByPath: ReadonlyMap<string, TypeScriptSemanticSource>,
): Promise<TypeScriptRawDependencySite[]> {
  const terminal = terminalIdentifier(typeName);
  if (terminal === null) return [];
  const symbol = await querySymbol(checker, terminal, counter, "type reference");
  // A type parameter denotes the current declaration's binder, not a graph
  // dependency target. Its constraint/default children are visited separately
  // and still produce the named type occurrences this slice promises.
  if (symbol !== undefined && (symbol.flags & SymbolFlags.TypeParameter) !== 0) return [];
  let targets: TypeScriptRawDependencyTarget[] = [];
  let nonTypeTarget = false;
  const importedAlias = symbol !== undefined && (symbol.flags & SymbolFlags.Alias) !== 0;
  const terminalBindingAmbiguous = isAmbiguousImportBindingAt(terminal, terminal.text)
    || (symbol !== undefined && context.externalBindings.isAmbiguous(symbol.id));
  const recordedBinding = symbol === undefined ? undefined : context.externalBindings.get(symbol.id);
  const identifierPath = qualifiedIdentifierPath(typeName);
  const root = leftmostIdentifier(typeName);
  const rootSymbol = root === null || root === terminal
    ? undefined
    : await querySymbol(checker, root, counter, "qualified type root");
  const rootBindingAmbiguous = root !== null && root !== terminal && (
    isAmbiguousImportBindingAt(root, root.text)
    || (rootSymbol !== undefined && context.externalBindings.isAmbiguous(rootSymbol.id))
  );
  const ambiguousBinding = terminalBindingAmbiguous || rootBindingAmbiguous;
  const namespaceBinding = root === null || root === terminal
    ? undefined
    : (rootSymbol === undefined ? undefined : context.externalBindings.get(rootSymbol.id))
      ?? context.bindingProvenance.get(root.text);
  const qualifiedBinding: BindingProvenance | undefined = namespaceBinding !== undefined
    && root !== null
    && !isLexicallyShadowedBinding(root, root.text)
    && rootSymbol !== undefined
    && (rootSymbol.flags & SymbolFlags.Alias) !== 0
    ? {
      moduleSpecifier: namespaceBinding.moduleSpecifier,
      importedName: terminal.text,
      exportPath: [
        ...namespaceBinding.exportPath,
        ...identifierPath.slice(1).map((identifier) => identifier.text),
      ],
      targets: isExternalModuleSpecifier(namespaceBinding.moduleSpecifier)
        ? [externalTarget(namespaceBinding.moduleSpecifier, terminal.text)]
        : [],
      resolutionMode: namespaceBinding.resolutionMode,
      resolutionModeError: namespaceBinding.resolutionModeError,
      ...(namespaceBinding.resolutionModeProof === undefined ? {} : {
        resolutionModeProof: namespaceBinding.resolutionModeProof,
      }),
      ...(namespaceBinding.bindingKind === undefined ? {} : { bindingKind: namespaceBinding.bindingKind }),
      ...(namespaceBinding.typeOnly === undefined ? {} : { typeOnly: namespaceBinding.typeOnly }),
      ...(namespaceBinding.bindingOrigin === undefined ? {} : { bindingOrigin: namespaceBinding.bindingOrigin }),
    }
    : undefined;
  // A terminal-name lookup is sound only for an unqualified reference. In
  // `T.Foo`, an unrelated imported `Foo` must not be attached by name alone;
  // qualified provenance requires the correlated namespace alias above.
  const syntaxBinding = root === terminal
    ? context.bindingProvenance.get(terminal.text)
    : undefined;
  let provenance: BindingProvenance | undefined = ambiguousBinding
    ? {
      moduleSpecifier: "<ambiguous>",
      importedName: terminal.text,
      exportPath: root === terminal
        ? [terminal.text]
        : identifierPath.slice(1).map((identifier) => identifier.text),
      targets: [],
      resolutionMode: null,
      resolutionModeError: null,
      bindingKind: "named",
      typeOnly: true,
    }
    : qualifiedBinding
    ?? (root === terminal ? recordedBinding : undefined)
    ?? ((symbol === undefined || importedAlias) ? syntaxBinding : undefined);
  if (symbol !== undefined && !ambiguousBinding) {
    const resolved = await compilerSymbolTargets(symbol, checker, counter, index, sourcesByPath, true);
    const rawTargets = resolved.targets.filter((target) => target.kind === "definition" || target.kind === "external");
    targets = typeUseTargets(rawTargets, index);
    if (rawTargets.some((target) => target.kind === "definition") && targets.length === 0) {
      nonTypeTarget = true;
    }
    if (targets.length === 0 && resolved.external) {
      targets = provenance?.targets.length ? provenance.targets : [externalTarget(`typescript:stdlib:${symbol.name}`, symbol.name)];
    }
  }
  if (targets.length === 0 && !ambiguousBinding && occurrenceKind === "heritage_type") {
    targets = compilerProvenHeritageTargets(index, context, terminal);
  }
  if (targets.length === 0 && !ambiguousBinding) {
    const typeSymbol = await queryTypeSymbol(checker, typeName, counter, "type reference");
    if (typeSymbol !== undefined && (typeSymbol.flags & SymbolFlags.TypeParameter) === 0) {
      const resolved = await compilerSymbolTargets(typeSymbol, checker, counter, index, sourcesByPath, true);
      const rawTargets = resolved.targets.filter((target) => target.kind === "definition" || target.kind === "external");
      targets = typeUseTargets(rawTargets, index);
      if (rawTargets.some((target) => target.kind === "definition") && targets.length === 0) {
        nonTypeTarget = true;
      }
      if (targets.length === 0 && resolved.external) {
        const typeBinding = context.externalBindings.get(typeSymbol.id) ?? provenance;
        targets = typeBinding?.targets.length ? typeBinding.targets : [externalTarget(`typescript:stdlib:${typeSymbol.name}`, typeSymbol.name)];
      }
    }
  }
  if (targets.length === 0 && provenance === undefined && syntaxBinding !== undefined) {
    provenance = syntaxBinding;
  }
  if (targets.length === 0 && provenance?.targets.length) {
    const provenTypes = typeUseTargets(provenance.targets, index);
    if (
      provenTypes.length === 0
      && provenance.targets.some((target) => target.kind === "definition")
    ) nonTypeTarget = true;
    targets = provenTypes;
  }
  if (provenance?.importedName === "") {
    // An empty ModuleExportName is valid, but the public type-use occurrence
    // is still named by its local identifier. Keep the remote name solely in
    // exportPath for module-proof correlation.
    provenance = { ...provenance, importedName: terminal.text };
  }
  const referencedProvenance = provenance === undefined || root === null
    ? provenance
    : withBindingReference(provenance, root, context.source.sourceFile);
  const publicProvenance = referencedProvenance?.bindingKind === "import_equals"
    ? { ...referencedProvenance, resolutionMode: null, resolutionModeError: null }
    : referencedProvenance;
  return [createSite(context, "type_use", "type_uses", occurrenceKind, terminal, terminal.text, targets,
    ambiguousBinding ? "ambiguous_binding_provenance" : nonTypeTarget ? "value_symbol_is_not_a_type" : null,
    "TypeChecker named type reference occurrence", true, publicProvenance)];
}

function collectInvalidOccurrences(node: Node, context: CollectionContext): TypeScriptRawDependencySite[] {
  const hasEvidenceSpan = (candidate: Node): boolean => (
    nodeEnd(candidate, context.source.sourceFile) > nodeStart(candidate, context.source.sourceFile)
  );
  const evidenceAnchor = (candidate: Node, fallback: Node): Node => (
    hasEvidenceSpan(candidate) ? candidate : fallback
  );
  const recoveredModuleSpecifier = (candidate: Node): string => {
    if (!hasEvidenceSpan(candidate)) return "<missing>";
    const literal = stringLiteralText(candidate);
    if (literal !== null) return literal;
    const text = candidate.getText(context.source.sourceFile);
    return text.length === 0 ? "<missing>" : text;
  };
  const startsWithFromToken = (source: string): boolean => (
    scanTypeScriptSyntaxTokens(source)[0]?.kind === SyntaxKind.FromKeyword
  );
  const unresolved = (
    kind: TypeScriptRawDependencySiteKind,
    edgeKind: TypeScriptRawDependencyEdgeKind,
    occurrenceKind: string,
    anchor: Node,
    specifier: string | StructuredBindingSpecifier,
    typeOnly = kind === "type_use",
  ): TypeScriptRawDependencySite => createSite(
    context,
    kind,
    edgeKind,
    occurrenceKind,
    anchor,
    specifier,
    [],
    "syntax_invalid",
    `Recovered ${occurrenceKind} occurrence from a syntactically invalid source`,
    typeOnly,
  );
  if (node.kind === SyntaxKind.ImportDeclaration) {
    const declaration = node as ImportDeclaration;
    const moduleNode = (declaration as ImportDeclaration & { readonly moduleSpecifier?: Node }).moduleSpecifier;
    const moduleSpecifier = moduleNode === undefined ? "<missing>" : recoveredModuleSpecifier(moduleNode);
    const moduleAnchor = moduleNode === undefined ? declaration : evidenceAnchor(moduleNode, declaration);
    const clause = declaration.importClause;
    if (clause === undefined) return [unresolved("web_import", "imports", "side_effect_import", moduleAnchor, moduleSpecifier)];
    const result: TypeScriptRawDependencySite[] = [];
    const clauseTypeOnly = clause.phaseModifier === SyntaxKind.TypeKeyword;
    if (clause.name !== undefined && hasEvidenceSpan(clause.name)) {
      result.push(unresolved("web_import", "imports", "default_import", clause.name,
        structuredBindingSpecifier(moduleSpecifier, "default", "default"), clauseTypeOnly));
    }
    if (
      clause.namedBindings?.kind === SyntaxKind.NamespaceImport
      && hasEvidenceSpan(clause.namedBindings.name)
    ) {
      result.push(unresolved("web_import", "imports", "namespace_import", clause.namedBindings.name, structuredBindingSpecifier(moduleSpecifier, "*", "namespace"), clauseTypeOnly));
    } else if (clause.namedBindings?.kind === SyntaxKind.NamedImports) {
      for (const element of clause.namedBindings.elements) {
        if (!hasEvidenceSpan(element.name)) continue;
        result.push(unresolved("web_import", "imports", "named_import", element.name, structuredBindingSpecifier(moduleSpecifier, importedName(element), "named"), clauseTypeOnly || element.isTypeOnly));
      }
    }
    if (result.length > 0) return result;
    return clause.namedBindings?.kind === SyntaxKind.NamedImports && clause.namedBindings.elements.length === 0
      ? [unresolved("web_import", "imports", "empty_import", moduleAnchor, moduleSpecifier, clauseTypeOnly)]
      : [unresolved("web_import", "imports", "side_effect_import", moduleAnchor, moduleSpecifier)];
  }
  if (node.kind === SyntaxKind.JSDocImportTag) {
    const declaration = node as JSDocImportTag;
    const moduleNode = (declaration as JSDocImportTag & { readonly moduleSpecifier?: Node }).moduleSpecifier;
    const moduleSpecifier = moduleNode === undefined ? "<missing>" : recoveredModuleSpecifier(moduleNode);
    const moduleAnchor = moduleNode === undefined ? declaration : evidenceAnchor(moduleNode, declaration);
    const clause = declaration.importClause;
    if (clause === undefined) {
      return [unresolved("web_import", "imports", "import_type", moduleAnchor, moduleSpecifier, true)];
    }
    const result: TypeScriptRawDependencySite[] = [];
    if (clause.name !== undefined && hasEvidenceSpan(clause.name)) {
      result.push(unresolved("web_import", "imports", "default_import", clause.name,
        structuredBindingSpecifier(moduleSpecifier, "default", "default"), true));
    }
    if (
      clause.namedBindings?.kind === SyntaxKind.NamespaceImport
      && hasEvidenceSpan(clause.namedBindings.name)
    ) {
      result.push(unresolved("web_import", "imports", "namespace_import", clause.namedBindings.name,
        structuredBindingSpecifier(moduleSpecifier, "*", "namespace"), true));
    } else if (clause.namedBindings?.kind === SyntaxKind.NamedImports) {
      for (const element of clause.namedBindings.elements) {
        if (!hasEvidenceSpan(element.name)) continue;
        result.push(unresolved("web_import", "imports", "named_import", element.name,
          structuredBindingSpecifier(moduleSpecifier, importedName(element), "named"), true));
      }
    }
    return result.length > 0
      ? result
      : [unresolved("web_import", "imports", "import_type", moduleAnchor, moduleSpecifier, true)];
  }
  if (node.kind === SyntaxKind.ExportDeclaration) {
    const declaration = node as ExportDeclaration;
    if (declaration.moduleSpecifier === undefined) {
      const clause = declaration.exportClause;
      const trailingSource = context.source.expectedText.slice(
        clause === undefined
          ? nodeStart(declaration, context.source.sourceFile)
          : nodeEnd(clause, context.source.sourceFile),
        nodeEnd(declaration, context.source.sourceFile),
      );
      const missingModuleForm = clause === undefined
        ? /^\s*export\s+(?:type\s+)?\*\s+from\b/u.test(trailingSource)
        : startsWithFromToken(trailingSource);
      if (missingModuleForm) {
        if (clause?.kind === SyntaxKind.NamespaceExport && hasEvidenceSpan(clause.name)) {
          return [unresolved(
            "web_reexport",
            "reexports",
            "namespace_reexport",
            clause.name,
            structuredBindingSpecifier("<missing>", "*", "namespace"),
            declaration.isTypeOnly,
          )];
        }
        if (clause?.kind !== SyntaxKind.NamedExports) {
          return [unresolved(
            "web_reexport",
            "reexports",
            "export_star",
            declaration,
            "<missing>",
            declaration.isTypeOnly,
          )];
        }
        const elements = clause.elements
          .filter((element) => hasEvidenceSpan(element.name))
          .map((element) => unresolved(
            "web_reexport",
            "reexports",
            "named_reexport",
            element.name,
            structuredBindingSpecifier("<missing>", exportedName(element), "named"),
            declaration.isTypeOnly || element.isTypeOnly,
          ));
        return elements.length > 0
          ? elements
          : [unresolved("web_reexport", "reexports", "empty_reexport", declaration, "<missing>", declaration.isTypeOnly)];
      }
      if (clause?.kind !== SyntaxKind.NamedExports) return [];
      const sites: TypeScriptRawDependencySite[] = [];
      for (const element of clause.elements) {
        if (!hasEvidenceSpan(element.name)) continue;
        const localNode = element.propertyName ?? element.name;
        if (!hasEvidenceSpan(localNode)) continue;
        const localName = (localNode as Node & { readonly text: string }).text;
        const origins = nearestDirectImportBindingOrigins(element, localName);
        if (origins.length === 0) continue;
        if (origins.length > 1) {
          sites.push(createSite(
            context,
            "web_reexport",
            "reexports",
            "named_reexport",
            element.name,
            structuredBindingSpecifier("<ambiguous>", localName, "named"),
            [],
            "syntax_invalid",
            "Recovered ambiguous local re-export from a syntactically invalid source",
            declaration.isTypeOnly || element.isTypeOnly,
          ));
          continue;
        }
        const provenance = origins[0]!;
        const typeOnly = declaration.isTypeOnly || element.isTypeOnly || provenance.typeOnly === true;
        if (provenance.bindingKind === "namespace") {
          const referencedProvenance = withBindingReference(provenance, localNode, context.source.sourceFile);
          sites.push(createSite(
            context,
            "web_reexport",
            "reexports",
            "namespace_reexport",
            element.name,
            structuredBindingSpecifier(provenance.moduleSpecifier, "*", "namespace"),
            [],
            "syntax_invalid",
            "Recovered local namespace-alias re-export from a syntactically invalid source",
            typeOnly,
            referencedProvenance,
          ));
          continue;
        }
      const referencedProvenance = withBindingReference(provenance, localNode, context.source.sourceFile);
      const publicProvenance = referencedProvenance.bindingKind === "import_equals"
        ? { ...referencedProvenance, resolutionMode: null, resolutionModeError: null }
        : referencedProvenance;
        sites.push(createSite(
          context,
          "web_reexport",
          "reexports",
          "named_reexport",
          element.name,
          structuredBindingSpecifier(
            provenance.moduleSpecifier,
            provenance.importedName,
            provenance.bindingKind ?? "named",
          ),
          [],
          "syntax_invalid",
          "Recovered imported local-alias re-export from a syntactically invalid source",
          typeOnly,
          publicProvenance,
        ));
      }
      return sites;
    }
    const moduleSpecifier = recoveredModuleSpecifier(declaration.moduleSpecifier);
    const moduleAnchor = evidenceAnchor(declaration.moduleSpecifier, declaration);
    if (declaration.exportClause?.kind === SyntaxKind.NamedExports) {
      const elements = declaration.exportClause.elements
        .filter((element) => hasEvidenceSpan(element.name))
        .map((element) => unresolved(
          "web_reexport", "reexports", "named_reexport", element.name,
          structuredBindingSpecifier(moduleSpecifier, exportedName(element), "named"), declaration.isTypeOnly || element.isTypeOnly,
        ));
      return elements.length > 0
        ? elements
        : [unresolved("web_reexport", "reexports", "empty_reexport", moduleAnchor, moduleSpecifier, declaration.isTypeOnly)];
    }
    const occurrenceKind = declaration.exportClause?.kind === SyntaxKind.NamespaceExport ? "namespace_reexport" : "export_star";
    const anchor = declaration.exportClause?.kind === SyntaxKind.NamespaceExport
      ? evidenceAnchor(declaration.exportClause.name, moduleAnchor)
      : moduleAnchor;
    const specifier = declaration.exportClause?.kind === SyntaxKind.NamespaceExport
      ? structuredBindingSpecifier(moduleSpecifier, "*", "namespace")
      : moduleSpecifier;
    return [unresolved("web_reexport", "reexports", occurrenceKind, anchor, specifier, declaration.isTypeOnly)];
  }
  if (node.kind === SyntaxKind.ImportEqualsDeclaration) {
    const declaration = node as ImportEqualsDeclaration;
    if (declaration.moduleReference.kind !== SyntaxKind.ExternalModuleReference) return [];
    const expression = (declaration.moduleReference as Node & { readonly expression?: Node }).expression;
    const moduleSpecifier = expression === undefined ? "<missing>" : recoveredModuleSpecifier(expression);
    const anchor = hasEvidenceSpan(declaration.name)
      ? declaration.name
      : expression === undefined ? declaration : evidenceAnchor(expression, declaration);
    return [unresolved("web_import", "imports", "import_equals", anchor,
      structuredBindingSpecifier(moduleSpecifier, "=", "import_equals"), declaration.isTypeOnly)];
  }
  if (node.kind === SyntaxKind.CallExpression) {
    const call = node as Node & { readonly expression: Node; readonly arguments: readonly Node[] };
    const expressionText = call.expression.kind === SyntaxKind.Identifier
      ? (call.expression as Identifier).text
      : call.expression.kind === SyntaxKind.ImportKeyword ? "import" : null;
    if (expressionText !== "require" && expressionText !== "import") return [];
    if (expressionText === "require" && isLexicallyShadowedBinding(call.expression, "require", true)) return [];
    const argument = call.arguments[0];
    if (argument === undefined) {
      return [unresolved(
        "web_import", "imports", expressionText === "require" ? "require_call" : "dynamic_import", call,
        "<missing>",
      )];
    }
    return [unresolved(
      "web_import", "imports", expressionText === "require" ? "require_call" : "dynamic_import",
      evidenceAnchor(argument, call),
      stringLiteralText(argument) ?? argument.getText(context.source.sourceFile),
    )];
  }
  if (node.kind === SyntaxKind.ImportType) {
    const importType = node as ImportTypeNode;
    const literal = (importType.argument as Node & { readonly literal?: Node }).literal;
    const anchor = literal ?? importType.argument;
    const moduleSpecifier = recoveredModuleSpecifier(anchor);
    const result = [unresolved(
      "web_import",
      "imports",
      "import_type",
      evidenceAnchor(anchor, importType),
      moduleSpecifier,
      true,
    )];
    const terminal = importType.qualifier === undefined ? null : terminalIdentifier(importType.qualifier);
    if (
      terminal !== null
      && nodeEnd(terminal, context.source.sourceFile) > nodeStart(terminal, context.source.sourceFile)
    ) result.push(unresolved("type_use", "type_uses", "type_reference", terminal, terminal.text));
    return result;
  }
  if (node.kind === SyntaxKind.TypeReference) {
    const terminal = terminalIdentifier((node as TypeReferenceNode).typeName);
    return terminal === null || nodeEnd(terminal, context.source.sourceFile) <= nodeStart(terminal, context.source.sourceFile)
      ? []
      : [unresolved("type_use", "type_uses", "type_reference", terminal, terminal.text)];
  }
  if (node.kind === SyntaxKind.TypeQuery) {
    const terminal = terminalIdentifier((node as TypeQueryNode).exprName);
    return terminal === null || nodeEnd(terminal, context.source.sourceFile) <= nodeStart(terminal, context.source.sourceFile)
      ? []
      : [unresolved("type_use", "type_uses", "type_reference", terminal, terminal.text)];
  }
  if (node.kind === SyntaxKind.ExpressionWithTypeArguments) {
    const terminal = terminalIdentifier((node as Node & { readonly expression: Node }).expression);
    return terminal === null || nodeEnd(terminal, context.source.sourceFile) <= nodeStart(terminal, context.source.sourceFile)
      ? []
      : [unresolved("type_use", "type_uses", "heritage_type", terminal, terminal.text)];
  }
  if (node.kind === SyntaxKind.JSDocNameReference) {
    const terminal = terminalIdentifier((node as Node & { readonly name: Node }).name);
    return terminal === null || nodeEnd(terminal, context.source.sourceFile) <= nodeStart(terminal, context.source.sourceFile)
      ? []
      : [unresolved("type_use", "type_uses", "jsdoc_type", terminal, terminal.text)];
  }
  return [];
}

function sortSites(left: TypeScriptRawDependencySite, right: TypeScriptRawDependencySite): number {
  return compareStrings(left.key, right.key)
    || compareStrings(left.specifier, right.specifier)
    || compareStrings(JSON.stringify(left.targets), JSON.stringify(right.targets));
}

function sortCallSites(left: TypeScriptRawCallSite, right: TypeScriptRawCallSite): number {
  return compareStrings(left.key, right.key)
    || compareStrings(left.specifier, right.specifier)
    || compareStrings(JSON.stringify(left.targets), JSON.stringify(right.targets));
}

function occurrenceIdentity(site: TypeScriptRawDependencySite): string {
  return JSON.stringify([
    site.kind,
    site.evidence.relativePath,
    site.evidence.startOffset,
    site.evidence.endOffset,
    site.evidence.occurrenceKind,
    site.specifier,
    site.moduleSpecifier,
    site.importedName,
    site.resolutionMode,
    site.typeOnly,
  ]);
}

function occurrencePayload(site: TypeScriptRawDependencySite): string {
  const { key: _key, source: _source, ...payload } = site;
  return JSON.stringify(payload);
}

export {
  basisForTargets,
  bindingScopeSpan,
  callOccurrenceKind,
  callSpecifier,
  childTraversalKey,
  compareStrings,
  DependencyContractError,
  hasUnpairedSurrogate,
  isAmbientRequireSymbol,
  isCanonicalRelativePath,
  isLexicallyShadowedBinding,
  isModuleLoaderCall,
  MAX_AST_DEPTH,
  MAX_AST_NODES,
  MAX_CONDITION_DEPTH,
  MAX_CONDITION_NODES,
  MAX_CONDITION_VALUES,
  MAX_EXPORT_PATH_DEPTH,
  MAX_EXPORTS_PER_MODULE,
  MAX_MODULE_EXPORT_BINDINGS,
  MAX_SITES,
  MAX_SPECIFIER_CHARS,
  nodeEnd,
  nodeSpan,
  nodeStart,
  querySymbol,
  resolutionModeDirective,
  resolutionModeForOccurrence,
  siteKey,
  stringLiteralText,
  targetSortKey,
  terminalIdentifier,
  TYPESCRIPT_CLOSED_LOCAL_CALL_FLOW_ALGORITHM,
  TYPESCRIPT_CLOSED_LOCAL_FRESH_INSTANCE_FLOW_ALGORITHM,
};
export type {
  QueryCounter,
  TypeScriptBindingKind,
  TypeScriptRawCallDispatch,
  TypeScriptRawCallKind,
  TypeScriptRawCallSite,
  TypeScriptRawCallSource,
  TypeScriptRawDependencyDelta,
  TypeScriptRawDependencyEdgeKind,
  TypeScriptRawDependencyEvidence,
  TypeScriptRawDependencyPrecision,
  TypeScriptRawDependencySite,
  TypeScriptRawDependencySiteKind,
  TypeScriptRawDependencyStatus,
  TypeScriptRawDependencyTarget,
  TypeScriptRawModuleExport,
  TypeScriptResolutionMode,
};

export {
  callValidationSpans,
  importTypeModuleValidationSpans,
  moduleCallValidationSpans,
  moduleCallValidationSpansFromSyntax,
  nonLiteralModuleValidationSpans,
  typeUseValidationSpans,
  validateTypeScriptRawDependencyDelta,
} from "./typescript-dependency-validation";
export type {
  TypeScriptCallValidationSpan,
  TypeScriptDependencyValidationSource,
  TypeScriptDependencyValidationTarget,
  TypeScriptModuleCallValidationSpan,
  TypeScriptNonLiteralModuleValidationSpan,
  TypeScriptTypeUseValidationSpan,
  TypeScriptValidationQueryBudget,
} from "./typescript-dependency-validation";

/**
 * Extract import, re-export, named type, and non-module-loader call
 * occurrences from the same confined Program/TypeChecker snapshot used by the
 * definition graph. The DTO carries no protocol IDs; scanner-side code adds
 * canonical graph IDs only after the entire semantic delta passes validation.
 */
export async function extractTypeScriptRawDependencyDelta(
  checker: Checker,
  sources: readonly TypeScriptSemanticSource[],
  definitions: TypeScriptRawDefinitionDelta,
  priorTypeCheckerQueries = 0,
  validationTarget?: TypeScriptDependencyValidationTarget,
): Promise<TypeScriptRawDependencyDelta> {
  const counter: QueryCounter = { value: 0, prior: priorTypeCheckerQueries };
  const sites: TypeScriptRawDependencySite[] = [];
  const calls: TypeScriptRawCallSite[] = [];
  const issues: TypeScriptSemanticIssue[] = [];
  const validationByPath = new Map(sources.map((source) => [source.relativePath, {
    visited: new Set<string>(),
    importTypeModules: new Map<string, { startOffset: number; endOffset: number }>(),
    moduleCalls: new Map<string, TypeScriptModuleCallValidationSpan>(),
    nonLiteralModules: new Map<string, TypeScriptNonLiteralModuleValidationSpan>(),
    typeUses: new Map<string, TypeScriptTypeUseValidationSpan>(),
    calls: new Map<string, TypeScriptCallValidationSpan>(),
  }]));
  let astNodes = 0;
  try {
    const index = definitionIndex(definitions);
    const sourcesByPath = sourcePathMap(sources);
    const consumeAstNode = (depth: number): void => {
      if (depth > MAX_AST_DEPTH) throw new DependencyContractError(`dependency AST depth ${MAX_AST_DEPTH} exceeded`);
      astNodes += 1;
      if (astNodes > MAX_AST_NODES) throw new DependencyContractError(`dependency AST node limit ${MAX_AST_NODES} exceeded`);
    };
    const collectValidation = async (node: Node, context: CollectionContext): Promise<void> => {
      const validation = validationByPath.get(context.source.relativePath);
      if (validation === undefined) {
        throw new DependencyContractError(`dependency validation source disappeared for ${context.source.relativePath}`);
      }
      const sourceFile = context.source.sourceFile;
      const validationKey = childTraversalKey(node, sourceFile);
      if (validation.visited.has(validationKey)) return;
      validation.visited.add(validationKey);
      const addNonLiteral = (
        moduleNode: Node,
        descriptor: Omit<TypeScriptNonLiteralModuleValidationSpan,
        | "startOffset"
        | "endOffset"
        | "moduleSpecifier"
        | "bindingScope"> & { bindingScopeAnchor?: Node },
      ): void => {
        if (stringLiteralText(moduleNode) !== null) return;
        const startOffset = nodeStart(moduleNode, sourceFile);
        const endOffset = nodeEnd(moduleNode, sourceFile);
        if (endOffset <= startOffset) return;
        const occurrence: TypeScriptNonLiteralModuleValidationSpan = {
          startOffset,
          endOffset,
          siteKind: descriptor.siteKind,
          occurrenceKind: descriptor.occurrenceKind,
          moduleSpecifier: moduleNode.getText(sourceFile),
          importedName: descriptor.importedName,
          bindingKind: descriptor.bindingKind,
          bindingScope: descriptor.bindingScopeAnchor === undefined
            ? null
            : bindingScopeSpan(descriptor.bindingScopeAnchor),
          typeOnly: descriptor.typeOnly,
          resolutionMode: descriptor.resolutionMode,
          resolutionModeProof: descriptor.resolutionModeProof,
          resolutionModeError: descriptor.resolutionModeError,
        };
        validation.nonLiteralModules.set(JSON.stringify(occurrence), occurrence);
      };
      const addTypeUse = async (
        typeName: Node | undefined,
        occurrenceKind: TypeScriptTypeUseValidationSpan["occurrenceKind"],
        inlineImportModule: Node | null = null,
      ): Promise<void> => {
        if (typeName === undefined) return;
        const terminal = terminalIdentifier(typeName);
        if (terminal === null) return;
        const startOffset = nodeStart(terminal, sourceFile);
        const endOffset = nodeEnd(terminal, sourceFile);
        const symbol = await querySymbol(
          checker,
          terminal,
          counter,
          `validation type reference ${terminal.text}@${startOffset}:${endOffset}`,
        );
        if (symbol !== undefined && (symbol.flags & SymbolFlags.TypeParameter) !== 0) return;
        if (endOffset <= startOffset) return;
        const inlineImportModuleSpan = inlineImportModule === null
          ? null
          : nodeSpan(inlineImportModule, sourceFile);
        const occurrence: TypeScriptTypeUseValidationSpan = {
          startOffset,
          endOffset,
          occurrenceKind,
          terminalName: terminal.text,
          inlineImportModuleStartOffset: inlineImportModuleSpan?.startOffset ?? null,
          inlineImportModuleEndOffset: inlineImportModuleSpan?.endOffset ?? null,
        };
        validation.typeUses.set(JSON.stringify(occurrence), occurrence);
      };

      if (context.syntacticallyValid) {
        let importTypeModule: Node | undefined;
        if (node.kind === SyntaxKind.ImportType) {
          const argument = (node as ImportTypeNode).argument as Node & { readonly literal?: Node };
          importTypeModule = argument.literal ?? argument;
        } else if (node.kind === SyntaxKind.JSDocImportTag) {
          importTypeModule = (node as JSDocImportTag).moduleSpecifier;
        }
        if (importTypeModule !== undefined) {
          const startOffset = nodeStart(importTypeModule, sourceFile);
          const endOffset = nodeEnd(importTypeModule, sourceFile);
          if (endOffset > startOffset) {
            validation.importTypeModules.set(`${startOffset}\0${endOffset}`, { startOffset, endOffset });
          }
        }

        if (node.kind === SyntaxKind.ImportDeclaration) {
          const declaration = node as ImportDeclaration;
          const typeOnly = declaration.importClause?.phaseModifier === SyntaxKind.TypeKeyword;
          const directive = resolutionModeForOccurrence(
            resolutionModeDirective(declaration.attributes, typeOnly),
            typeOnly,
          );
          addNonLiteral(declaration.moduleSpecifier, {
            siteKind: "web_import",
            occurrenceKind: "dynamic_import",
            importedName: null,
            bindingKind: null,
            typeOnly,
            resolutionMode: directive.mode,
            resolutionModeProof: directive.proof ?? null,
            resolutionModeError: directive.error,
          });
        } else if (node.kind === SyntaxKind.JSDocImportTag) {
          const declaration = node as JSDocImportTag;
          const directive = resolutionModeForOccurrence(
            resolutionModeDirective(declaration.attributes, true),
            true,
          );
          addNonLiteral(declaration.moduleSpecifier, {
            siteKind: "web_import",
            occurrenceKind: "import_type",
            importedName: null,
            bindingKind: null,
            typeOnly: true,
            resolutionMode: directive.mode,
            resolutionModeProof: directive.proof ?? null,
            resolutionModeError: directive.error,
          });
        } else if (node.kind === SyntaxKind.ExportDeclaration) {
          const declaration = node as ExportDeclaration;
          if (declaration.moduleSpecifier !== undefined) {
            const directive = resolutionModeForOccurrence(
              resolutionModeDirective(declaration.attributes, declaration.isTypeOnly),
              declaration.isTypeOnly,
            );
            addNonLiteral(declaration.moduleSpecifier, {
              siteKind: "web_reexport",
              occurrenceKind: "export_star",
              importedName: null,
              bindingKind: null,
              typeOnly: declaration.isTypeOnly,
              resolutionMode: directive.mode,
              resolutionModeProof: directive.proof ?? null,
              resolutionModeError: directive.error,
            });
          }
        } else if (node.kind === SyntaxKind.ImportEqualsDeclaration) {
          const declaration = node as ImportEqualsDeclaration;
          if (declaration.moduleReference.kind === SyntaxKind.ExternalModuleReference) {
            const expression = (declaration.moduleReference as Node & { readonly expression: Node }).expression;
            addNonLiteral(expression, {
              siteKind: "web_import",
              occurrenceKind: "import_equals",
              importedName: "=",
              bindingKind: "import_equals",
              bindingScopeAnchor: expression,
              typeOnly: declaration.isTypeOnly,
              resolutionMode: null,
              resolutionModeProof: null,
              resolutionModeError: null,
            });
          }
        }

        if (node.kind === SyntaxKind.TypeReference) {
          await addTypeUse((node as TypeReferenceNode).typeName, "type_reference");
        } else if (node.kind === SyntaxKind.TypeQuery) {
          await addTypeUse((node as TypeQueryNode).exprName, "type_reference");
        } else if (node.kind === SyntaxKind.ExpressionWithTypeArguments) {
          await addTypeUse((node as Node & { readonly expression: Node }).expression, "heritage_type");
        } else if (node.kind === SyntaxKind.JSDocNameReference) {
          await addTypeUse((node as Node & { readonly name: Node }).name, "jsdoc_type");
        } else if (node.kind === SyntaxKind.ImportType) {
          const importType = node as ImportTypeNode;
          const argument = importType.argument as Node & { readonly literal?: Node };
          await addTypeUse(importType.qualifier, "type_reference", argument.literal ?? argument);
        }
      }

      if (
        node.kind === SyntaxKind.CallExpression
        || node.kind === SyntaxKind.NewExpression
        || node.kind === SyntaxKind.TaggedTemplateExpression
      ) {
        const call = node as CallExpression | NewExpression | TaggedTemplateExpression;
        let moduleLoader = false;
        let isRequire = false;
        if (call.kind === SyntaxKind.CallExpression) {
          const callExpression = call as CallExpression;
          const isDynamicImport = callExpression.expression.kind === SyntaxKind.ImportKeyword;
          isRequire = callExpression.expression.kind === SyntaxKind.Identifier
            && (callExpression.expression as Identifier).text === "require"
            && !isLexicallyShadowedBinding(callExpression.expression, "require", true);
          if (context.syntacticallyValid && isRequire) {
            const symbol = await querySymbol(checker, callExpression.expression, counter, "validation require callee");
            if (symbol !== undefined && !await isAmbientRequireSymbol(symbol, counter)) isRequire = false;
          }
          moduleLoader = isDynamicImport || isRequire;
          if (context.syntacticallyValid && moduleLoader) {
            const occurrence = moduleCallValidationOccurrence(callExpression, sourceFile, isRequire);
            validation.moduleCalls.set(JSON.stringify(occurrence), occurrence);
          }
        }
        if (!moduleLoader) {
          const spanValue = nodeSpan(call, sourceFile);
          const occurrence: TypeScriptCallValidationSpan = {
            ...spanValue,
            occurrenceKind: callOccurrenceKind(call) as TypeScriptCallValidationSpan["occurrenceKind"],
            specifier: callSpecifier(call, sourceFile),
          };
          validation.calls.set(JSON.stringify(occurrence), occurrence);
        }
      }
    };
    const visitDetachedJSDoc = async (node: Node, context: CollectionContext, depth: number): Promise<void> => {
      consumeAstNode(depth);
      await collectValidation(node, context);
      if (node.kind === SyntaxKind.JSDocImportTag) {
        if (context.syntacticallyValid) {
          sites.push(...await collectJSDocImportTag(node as JSDocImportTag, context, checker, counter, index, sourcesByPath));
        } else {
          sites.push(...collectInvalidOccurrences(node, context));
        }
      }
      const children = new Map<string, Node>();
      node.forEachChild((child) => {
        const key = childTraversalKey(child, context.source.sourceFile);
        if (!children.has(key)) children.set(key, child);
        return undefined;
      });
      for (const child of children.values()) await visitDetachedJSDoc(child, context, depth + 1);
    };
    const visit = async (node: Node, context: CollectionContext, depth: number): Promise<void> => {
      consumeAstNode(depth);
      await collectValidation(node, context);
      const semanticOwner = context.syntacticallyValid ? ownerAtNode(index, context.source, node) : null;
      const childContext = semanticOwner === null ? context : { ...context, owner: semanticOwner };
      if (!childContext.syntacticallyValid) {
        sites.push(...collectInvalidOccurrences(node, childContext));
        if (
          node.kind === SyntaxKind.CallExpression
          || node.kind === SyntaxKind.NewExpression
          || node.kind === SyntaxKind.TaggedTemplateExpression
        ) calls.push(...await collectSemanticCall(
          node as CallExpression | NewExpression | TaggedTemplateExpression,
          childContext,
          checker,
          counter,
          index,
          sourcesByPath,
        ));
      } else if (node.kind === SyntaxKind.ImportDeclaration) {
        sites.push(...await collectImportDeclaration(node as ImportDeclaration, childContext, checker, counter, index, sourcesByPath));
      } else if (node.kind === SyntaxKind.JSDocImportTag) {
        sites.push(...await collectJSDocImportTag(node as JSDocImportTag, childContext, checker, counter, index, sourcesByPath));
      } else if (node.kind === SyntaxKind.ExportDeclaration) {
        sites.push(...await collectExportDeclaration(node as ExportDeclaration, childContext, checker, counter, index, sourcesByPath));
      } else if (node.kind === SyntaxKind.ImportEqualsDeclaration) {
        sites.push(...await collectImportEquals(node as ImportEqualsDeclaration, childContext, checker, counter, index, sourcesByPath));
      } else if (node.kind === SyntaxKind.CallExpression) {
        sites.push(...await collectCallImport(
          node as Node & { readonly expression: Node; readonly arguments: readonly Node[] },
          childContext, checker, counter, index, sourcesByPath,
        ));
        calls.push(...await collectSemanticCall(
          node as CallExpression,
          childContext,
          checker,
          counter,
          index,
          sourcesByPath,
        ));
      } else if (node.kind === SyntaxKind.NewExpression || node.kind === SyntaxKind.TaggedTemplateExpression) {
        calls.push(...await collectSemanticCall(
          node as NewExpression | TaggedTemplateExpression,
          childContext,
          checker,
          counter,
          index,
          sourcesByPath,
        ));
      } else if (node.kind === SyntaxKind.ImportType) {
        sites.push(...await collectImportType(node as ImportTypeNode, childContext, checker, counter, index, sourcesByPath));
      } else if (node.kind === SyntaxKind.TypeReference) {
        sites.push(...await collectTypeReference((node as TypeReferenceNode).typeName, "type_reference", childContext, checker, counter, index, sourcesByPath));
      } else if (node.kind === SyntaxKind.TypeQuery) {
        sites.push(...await collectTypeReference((node as TypeQueryNode).exprName, "type_reference", childContext, checker, counter, index, sourcesByPath));
      } else if (node.kind === SyntaxKind.ExpressionWithTypeArguments) {
        sites.push(...await collectTypeReference(
          (node as Node & { readonly expression: Node }).expression,
          "heritage_type", childContext, checker, counter, index, sourcesByPath,
        ));
      } else if (node.kind === SyntaxKind.JSDocNameReference) {
        sites.push(...await collectTypeReference(
          (node as Node & { readonly name: Node }).name,
          "jsdoc_type", childContext, checker, counter, index, sourcesByPath,
        ));
      }
      const children = new Map<string, Node>();
      const addChild = (child: Node): void => {
        const key = childTraversalKey(child, childContext.source.sourceFile);
        if (!children.has(key)) children.set(key, child);
      };
      node.forEachChild((child) => {
        addChild(child);
        return undefined;
      });
      for (const child of children.values()) await visit(child, childContext, depth + 1);
      // TypeScript omits newer tags such as `@import` from the canonical child
      // stream on some hosts. Traverse detached docs in a tag-only mode so
      // existing JSDoc type nodes are not duplicated under a different owner.
      for (const jsDoc of node.jsDoc ?? []) await visitDetachedJSDoc(jsDoc, childContext, depth + 1);
    };

    for (const source of [...sources].sort((left, right) => compareStrings(left.relativePath, right.relativePath))) {
      const externalBindings = new BindingProvenanceMap();
      if (source.syntacticallyValid) {
        await prepopulateBindingSymbols(source.sourceFile, checker, counter, externalBindings);
      }
      await visit(source.sourceFile, {
        source,
        owner: { kind: "file", relativePath: source.relativePath },
        syntacticallyValid: source.syntacticallyValid,
        externalBindings,
        bindingProvenance: source.syntacticallyValid
          ? sourceBindingProvenance(source.sourceFile)
          : new Map<string, BindingProvenance>(),
        freshReceiverProof: {
          identifierIndex: null,
          indexFailed: false,
          useProofs: new Map<string, boolean>(),
        },
      }, 0);
    }
    if (sites.length + calls.length > MAX_SITES) throw new DependencyContractError(`dependency site limit ${MAX_SITES} exceeded`);
    const occurrences = new Map<string, TypeScriptRawDependencySite>();
    for (const site of sites.sort(sortSites)) {
      const occurrence = occurrenceIdentity(site);
      const existing = occurrences.get(occurrence);
      if (existing === undefined) {
        occurrences.set(occurrence, site);
        continue;
      }
      if (occurrencePayload(existing) !== occurrencePayload(site)) {
        throw new DependencyContractError(`dependency occurrence payload collision ${occurrence}`);
      }
      if (existing.source.kind === "file" && site.source.kind === "definition") {
        occurrences.set(occurrence, site);
      } else if (
        existing.source.kind === "definition"
        && site.source.kind === "definition"
        && existing.source.key !== site.source.key
      ) {
        throw new DependencyContractError(`dependency occurrence owner collision ${occurrence}`);
      }
    }
    const unique = new Map<string, TypeScriptRawDependencySite>();
    for (const site of [...occurrences.values()].sort(sortSites)) {
      const existing = unique.get(site.key);
      if (existing !== undefined && JSON.stringify(existing) !== JSON.stringify(site)) {
        throw new DependencyContractError(`dependency site identity collision ${site.key}`);
      }
      unique.set(site.key, site);
    }
    const uniqueSites = [...unique.values()].sort(sortSites);
    const uniqueCallsByKey = new Map<string, TypeScriptRawCallSite>();
    for (const call of calls.sort(sortCallSites)) {
      const existing = uniqueCallsByKey.get(call.key);
      if (existing !== undefined && JSON.stringify(existing) !== JSON.stringify(call)) {
        throw new DependencyContractError(`call site identity collision ${call.key}`);
      }
      uniqueCallsByKey.set(call.key, existing ?? call);
    }
    const uniqueCalls = [...uniqueCallsByKey.values()].sort(sortCallSites);
    const moduleExports = await collectModuleExportProofs(
      checker,
      counter,
      sources,
      index,
      sourcesByPath,
      uniqueSites
        .filter((site) => (
          site.exportPath !== null
          && (
            site.exportPath.length > 0
            || (site.exportPath.length === 0 && site.importedName === "=")
          )
        ))
        .map((site) => site.exportPath!),
      uniqueSites
        .filter((site) => site.bindingKind === "import_equals" && site.exportPath !== null)
        .map((site) => site.exportPath!),
    );
    const validationSources: TypeScriptDependencyValidationSource[] = [...sources]
      .sort((left, right) => compareStrings(left.relativePath, right.relativePath))
      .map((source) => {
        const validation = validationByPath.get(source.relativePath);
        if (validation === undefined) {
          throw new DependencyContractError(`dependency validation source disappeared for ${source.relativePath}`);
        }
        const importTypeModuleSpans = [...validation.importTypeModules.values()].sort((left, right) => (
          left.startOffset - right.startOffset || left.endOffset - right.endOffset
        ));
        const moduleCallSpans = sortModuleCallValidationSpans(validation.moduleCalls);
        const nonLiteralModuleSpans = [...validation.nonLiteralModules.values()].sort((left, right) => (
          left.startOffset - right.startOffset
          || left.endOffset - right.endOffset
          || compareStrings(left.occurrenceKind, right.occurrenceKind)
        ));
        const typeUseSpans = [...validation.typeUses.values()].sort((left, right) => (
          left.startOffset - right.startOffset
          || left.endOffset - right.endOffset
          || compareStrings(left.occurrenceKind, right.occurrenceKind)
        ));
        const callSpans = [...validation.calls.values()].sort((left, right) => (
          left.startOffset - right.startOffset
          || left.endOffset - right.endOffset
          || compareStrings(left.occurrenceKind, right.occurrenceKind)
          || compareStrings(left.specifier, right.specifier)
        ));
        validationTarget?.importTypeModuleSpans.set(source.relativePath, importTypeModuleSpans);
        validationTarget?.moduleCallSpans.set(source.relativePath, moduleCallSpans);
        validationTarget?.nonLiteralModuleSpans.set(source.relativePath, nonLiteralModuleSpans);
        validationTarget?.typeUseSpans.set(source.relativePath, typeUseSpans);
        validationTarget?.callSpans.set(source.relativePath, callSpans);
        return {
          relativePath: source.relativePath,
          text: source.expectedText,
          syntacticallyValid: source.syntacticallyValid,
          importTypeModuleSpans,
          moduleCallSpans,
          nonLiteralModuleSpans,
          typeUseSpans,
          callSpans,
        };
      });
    const result = {
      sites: uniqueSites,
      calls: uniqueCalls,
      moduleExports,
      issues,
      typeCheckerQueries: counter.value,
    };
    validateTypeScriptRawDependencyDelta(
      result,
      definitions,
      validationSources,
    );
    return result;
  } catch (error) {
    return {
      sites: [],
      calls: [],
      moduleExports: [],
      issues: [{
        code: "typescript_semantic_dependency_contract_violation",
        message: error instanceof Error ? error.message : String(error),
        relativePath: null,
        fatal: true,
      }],
      typeCheckerQueries: counter.value,
    };
  }
}
