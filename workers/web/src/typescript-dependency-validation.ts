import {
  type Checker,
  SymbolFlags,
} from "typescript/unstable/async";
import {
  type CallExpression,
  createScanner,
  type ExportDeclaration,
  type Identifier,
  type ImportDeclaration,
  type ImportEqualsDeclaration,
  type ImportTypeNode,
  type JSDocImportTag,
  LanguageVariant,
  type NewExpression,
  type Node,
  type SourceFile,
  SyntaxKind,
  type TaggedTemplateExpression,
  tokenIsIdentifierOrKeyword,
  type TypeQueryNode,
  type TypeReferenceNode,
} from "typescript/unstable/ast";
import type { TypeScriptRawDefinitionDelta } from "./typescript-semantic";
import { scanTypeScriptSyntaxTokens } from "./imports";
import { aggregateConditions, canonicalizeCondition, type Condition } from "./types";
import {
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
} from "./typescript-dependency-contract";
import type {
  QueryCounter,
  TypeScriptBindingKind,
  TypeScriptRawDependencyDelta,
  TypeScriptRawDependencySite,
  TypeScriptRawDependencySiteKind,
  TypeScriptResolutionMode,
} from "./typescript-dependency-contract";

export interface TypeScriptDependencyValidationSource {
  relativePath: string;
  text: string;
  /** Parser-confirmed source validity from the caller-owned compiler snapshot. */
  syntacticallyValid: boolean;
  /** Module argument/specifier spans belonging to ImportType/JSDoc module-import nodes. */
  importTypeModuleSpans: readonly { startOffset: number; endOffset: number }[];
  /** Parser-confirmed, lexically unshadowed runtime module-call occurrences. */
  moduleCallSpans: readonly TypeScriptModuleCallValidationSpan[];
  /** Parser-confirmed grammar-late non-literal static/JSDoc module occurrences. */
  nonLiteralModuleSpans: readonly TypeScriptNonLiteralModuleValidationSpan[];
  /** Parser-confirmed named type-use terminal spans and occurrence kinds. */
  typeUseSpans: readonly TypeScriptTypeUseValidationSpan[];
  /** Parser/TypeChecker-confirmed non-module call-like occurrences. */
  callSpans: readonly TypeScriptCallValidationSpan[];
}

export interface TypeScriptDependencyValidationTarget {
  importTypeModuleSpans: Map<string, Array<{ startOffset: number; endOffset: number }>>;
  moduleCallSpans: Map<string, TypeScriptModuleCallValidationSpan[]>;
  nonLiteralModuleSpans: Map<string, TypeScriptNonLiteralModuleValidationSpan[]>;
  typeUseSpans: Map<string, TypeScriptTypeUseValidationSpan[]>;
  callSpans: Map<string, TypeScriptCallValidationSpan[]>;
}

export interface TypeScriptCallValidationSpan {
  startOffset: number;
  endOffset: number;
  occurrenceKind: "call_expression" | "new_expression" | "tagged_template";
  specifier: string;
}

export interface TypeScriptModuleCallValidationSpan {
  startOffset: number;
  endOffset: number;
  occurrenceKind: "require_call" | "dynamic_import";
  syntax: "literal" | "computed" | "missing";
  moduleSpecifier: string;
}

export interface TypeScriptTypeUseValidationSpan {
  startOffset: number;
  endOffset: number;
  occurrenceKind: "type_reference" | "heritage_type" | "jsdoc_type";
  /** Exact terminal identifier value attested by the parser-owned AST. */
  terminalName: string;
  /** Exact parent ImportType module span, or null for non-inline type uses. */
  inlineImportModuleStartOffset: number | null;
  inlineImportModuleEndOffset: number | null;
}

export interface TypeScriptNonLiteralModuleValidationSpan {
  startOffset: number;
  endOffset: number;
  siteKind: "web_import" | "web_reexport";
  occurrenceKind: "dynamic_import" | "import_type" | "export_star" | "import_equals";
  moduleSpecifier: string;
  importedName: "=" | null;
  bindingKind: "import_equals" | null;
  bindingScope: { startOffset: number; endOffset: number } | null;
  typeOnly: boolean;
  resolutionMode: TypeScriptResolutionMode | null;
  resolutionModeProof: TypeScriptRawDependencySite["resolutionModeProof"];
  resolutionModeError: string | null;
}

export function importTypeModuleValidationSpans(
  sourceFile: SourceFile,
): Array<{ startOffset: number; endOffset: number }> {
  const spans = new Map<string, { startOffset: number; endOffset: number }>();
  const visited = new Set<string>();
  let count = 0;
  const visit = (node: Node, depth: number): void => {
    if (depth > MAX_AST_DEPTH) throw new DependencyContractError("dependency validation AST depth limit exceeded");
    const key = childTraversalKey(node, sourceFile);
    if (visited.has(key)) return;
    visited.add(key);
    count += 1;
    if (count > MAX_AST_NODES) throw new DependencyContractError("dependency validation AST node limit exceeded");
    let moduleNode: Node | undefined;
    if (node.kind === SyntaxKind.ImportType) {
      const argument = (node as ImportTypeNode).argument as Node & { readonly literal?: Node };
      moduleNode = argument.literal ?? argument;
    } else if (node.kind === SyntaxKind.JSDocImportTag) {
      moduleNode = (node as JSDocImportTag).moduleSpecifier;
    }
    if (moduleNode !== undefined) {
      const startOffset = nodeStart(moduleNode, sourceFile);
      const endOffset = nodeEnd(moduleNode, sourceFile);
      if (endOffset > startOffset) {
        const spanValue = { startOffset, endOffset };
        spans.set(`${startOffset}\0${endOffset}`, spanValue);
      }
    }
    node.forEachChild((child) => {
      visit(child, depth + 1);
      return undefined;
    });
    for (const jsDoc of node.jsDoc ?? []) visit(jsDoc, depth + 1);
  };
  visit(sourceFile, 0);
  return [...spans.values()].sort((left, right) => (
    left.startOffset - right.startOffset || left.endOffset - right.endOffset
  ));
}

export function nonLiteralModuleValidationSpans(
  sourceFile: SourceFile,
): TypeScriptNonLiteralModuleValidationSpan[] {
  const spans = new Map<string, TypeScriptNonLiteralModuleValidationSpan>();
  const visited = new Set<string>();
  let count = 0;
  const add = (
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
    const spanValue = { startOffset, endOffset };
    const occurrence: TypeScriptNonLiteralModuleValidationSpan = {
      ...spanValue,
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
    spans.set(JSON.stringify(occurrence), occurrence);
  };
  const visit = (node: Node, depth: number): void => {
    if (depth > MAX_AST_DEPTH) throw new DependencyContractError("dependency validation AST depth limit exceeded");
    const key = childTraversalKey(node, sourceFile);
    if (visited.has(key)) return;
    visited.add(key);
    count += 1;
    if (count > MAX_AST_NODES) throw new DependencyContractError("dependency validation AST node limit exceeded");
    if (node.kind === SyntaxKind.ImportDeclaration) {
      const declaration = node as ImportDeclaration;
      const typeOnly = declaration.importClause?.phaseModifier === SyntaxKind.TypeKeyword;
      const directive = resolutionModeForOccurrence(
        resolutionModeDirective(declaration.attributes, typeOnly),
        typeOnly,
      );
      add(declaration.moduleSpecifier, {
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
      const directive = resolutionModeForOccurrence(resolutionModeDirective(declaration.attributes, true), true);
      add(declaration.moduleSpecifier, {
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
        add(declaration.moduleSpecifier, {
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
        add(expression, {
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
    node.forEachChild((child) => {
      visit(child, depth + 1);
      return undefined;
    });
    for (const jsDoc of node.jsDoc ?? []) visit(jsDoc, depth + 1);
  };
  visit(sourceFile, 0);
  return [...spans.values()].sort((left, right) => (
    left.startOffset - right.startOffset
    || left.endOffset - right.endOffset
    || compareStrings(left.occurrenceKind, right.occurrenceKind)
  ));
}

export function moduleCallValidationOccurrence(
  node: Node & { readonly expression: Node; readonly arguments: readonly Node[] },
  sourceFile: SourceFile,
  isRequire: boolean,
): TypeScriptModuleCallValidationSpan {
  const argument = node.arguments[0];
  const anchor = argument ?? node;
  const spanValue = nodeSpan(anchor, sourceFile);
  return {
    ...spanValue,
    occurrenceKind: isRequire ? "require_call" : "dynamic_import",
    syntax: argument === undefined
      ? "missing"
      : stringLiteralText(argument) === null ? "computed" : "literal",
    moduleSpecifier: argument === undefined
      ? "<missing>"
      : stringLiteralText(argument) ?? argument.getText(sourceFile),
  };
}

export function sortModuleCallValidationSpans(
  spans: ReadonlyMap<string, TypeScriptModuleCallValidationSpan>,
): TypeScriptModuleCallValidationSpan[] {
  return [...spans.values()].sort((left, right) => (
    left.startOffset - right.startOffset
    || left.endOffset - right.endOffset
    || compareStrings(left.occurrenceKind, right.occurrenceKind)
    || compareStrings(left.syntax, right.syntax)
  ));
}

export function moduleCallValidationSpansFromSyntax(sourceFile: SourceFile): TypeScriptModuleCallValidationSpan[] {
  const spans = new Map<string, TypeScriptModuleCallValidationSpan>();
  const visited = new Set<string>();
  let count = 0;
  const visit = (node: Node, depth: number): void => {
    if (depth > MAX_AST_DEPTH) throw new DependencyContractError("dependency validation AST depth limit exceeded");
    const key = childTraversalKey(node, sourceFile);
    if (visited.has(key)) return;
    visited.add(key);
    count += 1;
    if (count > MAX_AST_NODES) throw new DependencyContractError("dependency validation AST node limit exceeded");
    if (node.kind === SyntaxKind.CallExpression) {
      const call = node as Node & { readonly expression: Node; readonly arguments: readonly Node[] };
      const isDynamicImport = call.expression.kind === SyntaxKind.ImportKeyword;
      const isRequire = call.expression.kind === SyntaxKind.Identifier
        && (call.expression as Identifier).text === "require"
        && !isLexicallyShadowedBinding(call.expression, "require", true);
      if (isDynamicImport || isRequire) {
        const occurrence = moduleCallValidationOccurrence(call, sourceFile, isRequire);
        spans.set(JSON.stringify(occurrence), occurrence);
      }
    }
    node.forEachChild((child) => {
      visit(child, depth + 1);
      return undefined;
    });
  };
  visit(sourceFile, 0);
  return sortModuleCallValidationSpans(spans);
}

export interface TypeScriptValidationQueryBudget {
  value: number;
}

export async function moduleCallValidationSpans(
  checker: Checker,
  sourceFile: SourceFile,
  budget: TypeScriptValidationQueryBudget = { value: 0 },
): Promise<TypeScriptModuleCallValidationSpan[]> {
  const spans = new Map<string, TypeScriptModuleCallValidationSpan>();
  const visited = new Set<string>();
  const counter: QueryCounter = { value: budget.value, prior: 0 };
  let count = 0;
  const visit = async (node: Node, depth: number): Promise<void> => {
    if (depth > MAX_AST_DEPTH) throw new DependencyContractError("dependency validation AST depth limit exceeded");
    const key = childTraversalKey(node, sourceFile);
    if (visited.has(key)) return;
    visited.add(key);
    count += 1;
    if (count > MAX_AST_NODES) throw new DependencyContractError("dependency validation AST node limit exceeded");
    if (node.kind === SyntaxKind.CallExpression) {
      const call = node as Node & { readonly expression: Node; readonly arguments: readonly Node[] };
      const isDynamicImport = call.expression.kind === SyntaxKind.ImportKeyword;
      let isRequire = call.expression.kind === SyntaxKind.Identifier
        && (call.expression as Identifier).text === "require"
        && !isLexicallyShadowedBinding(call.expression, "require", true);
      if (isRequire) {
        const symbol = await querySymbol(checker, call.expression, counter, "validation require callee");
        if (symbol !== undefined && !await isAmbientRequireSymbol(symbol, counter)) isRequire = false;
      }
      if (isDynamicImport || isRequire) {
        const occurrence = moduleCallValidationOccurrence(call, sourceFile, isRequire);
        spans.set(JSON.stringify(occurrence), occurrence);
      }
    }
    const children = new Map<string, Node>();
    node.forEachChild((child) => {
      const key = childTraversalKey(child, sourceFile);
      if (!children.has(key)) children.set(key, child);
      return undefined;
    });
    for (const child of children.values()) await visit(child, depth + 1);
  };
  try {
    await visit(sourceFile, 0);
  } finally {
    budget.value = counter.value;
  }
  return sortModuleCallValidationSpans(spans);
}

export async function callValidationSpans(
  checker: Checker,
  sourceFile: SourceFile,
  budget: TypeScriptValidationQueryBudget = { value: 0 },
  syntacticallyValid = true,
): Promise<TypeScriptCallValidationSpan[]> {
  const spans = new Map<string, TypeScriptCallValidationSpan>();
  const visited = new Set<string>();
  const counter: QueryCounter = { value: budget.value, prior: 0 };
  let count = 0;
  const visit = async (node: Node, depth: number): Promise<void> => {
    if (depth > MAX_AST_DEPTH) throw new DependencyContractError("call validation AST depth limit exceeded");
    const key = childTraversalKey(node, sourceFile);
    if (visited.has(key)) return;
    visited.add(key);
    count += 1;
    if (count > MAX_AST_NODES) throw new DependencyContractError("call validation AST node limit exceeded");
    if (
      node.kind === SyntaxKind.CallExpression
      || node.kind === SyntaxKind.NewExpression
      || node.kind === SyntaxKind.TaggedTemplateExpression
    ) {
      const call = node as CallExpression | NewExpression | TaggedTemplateExpression;
      const callExpression = call.kind === SyntaxKind.CallExpression ? call as CallExpression : null;
      const lexicalModuleLoader = callExpression !== null && (
        callExpression.expression.kind === SyntaxKind.ImportKeyword
        || (
          callExpression.expression.kind === SyntaxKind.Identifier
          && (callExpression.expression as Identifier).text === "require"
          && !isLexicallyShadowedBinding(callExpression.expression, "require", true)
        )
      );
      const moduleLoader = callExpression !== null && (
        syntacticallyValid
          ? await isModuleLoaderCall(callExpression, checker, counter)
          : lexicalModuleLoader
      );
      if (!moduleLoader) {
        const spanValue = nodeSpan(call, sourceFile);
        const occurrence: TypeScriptCallValidationSpan = {
          ...spanValue,
          occurrenceKind: callOccurrenceKind(call) as TypeScriptCallValidationSpan["occurrenceKind"],
          specifier: callSpecifier(call, sourceFile),
        };
        spans.set(JSON.stringify(occurrence), occurrence);
      }
    }
    const children = new Map<string, Node>();
    node.forEachChild((child) => {
      const childKey = childTraversalKey(child, sourceFile);
      if (!children.has(childKey)) children.set(childKey, child);
      return undefined;
    });
    for (const child of children.values()) await visit(child, depth + 1);
  };
  try {
    await visit(sourceFile, 0);
  } finally {
    budget.value = counter.value;
  }
  return [...spans.values()].sort((left, right) => (
    left.startOffset - right.startOffset
    || left.endOffset - right.endOffset
    || compareStrings(left.occurrenceKind, right.occurrenceKind)
    || compareStrings(left.specifier, right.specifier)
  ));
}

async function typeUseValidationSpansWithCounter(
  checker: Checker,
  sourceFile: SourceFile,
  counter: QueryCounter,
): Promise<TypeScriptTypeUseValidationSpan[]> {
  const spans = new Map<string, TypeScriptTypeUseValidationSpan>();
  const visited = new Set<string>();
  let count = 0;
  const add = async (
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
    const spanValue = { startOffset, endOffset };
    const inlineImportModuleSpan = inlineImportModule === null
      ? null
      : nodeSpan(inlineImportModule, sourceFile);
    const occurrence = {
      ...spanValue,
      occurrenceKind,
      terminalName: terminal.text,
      inlineImportModuleStartOffset: inlineImportModuleSpan?.startOffset ?? null,
      inlineImportModuleEndOffset: inlineImportModuleSpan?.endOffset ?? null,
    };
    spans.set(JSON.stringify(occurrence), occurrence);
  };
  const visit = async (node: Node, depth: number): Promise<void> => {
    if (depth > MAX_AST_DEPTH) throw new DependencyContractError("dependency validation AST depth limit exceeded");
    const key = childTraversalKey(node, sourceFile);
    if (visited.has(key)) return;
    visited.add(key);
    count += 1;
    if (count > MAX_AST_NODES) throw new DependencyContractError("dependency validation AST node limit exceeded");
    if (node.kind === SyntaxKind.TypeReference) {
      await add((node as TypeReferenceNode).typeName, "type_reference");
    } else if (node.kind === SyntaxKind.TypeQuery) {
      await add((node as TypeQueryNode).exprName, "type_reference");
    } else if (node.kind === SyntaxKind.ExpressionWithTypeArguments) {
      await add((node as Node & { readonly expression: Node }).expression, "heritage_type");
    } else if (node.kind === SyntaxKind.JSDocNameReference) {
      await add((node as Node & { readonly name: Node }).name, "jsdoc_type");
    } else if (node.kind === SyntaxKind.ImportType) {
      const importType = node as ImportTypeNode;
      const argument = importType.argument as Node & { readonly literal?: Node };
      await add(importType.qualifier, "type_reference", argument.literal ?? argument);
    }
    const children = new Map<string, Node>();
    node.forEachChild((child) => {
      const key = childTraversalKey(child, sourceFile);
      if (!children.has(key)) children.set(key, child);
      return undefined;
    });
    for (const child of children.values()) await visit(child, depth + 1);
    for (const jsDoc of node.jsDoc ?? []) await visit(jsDoc, depth + 1);
  };
  await visit(sourceFile, 0);
  return [...spans.values()].sort((left, right) => (
    left.startOffset - right.startOffset
    || left.endOffset - right.endOffset
    || compareStrings(left.occurrenceKind, right.occurrenceKind)
  ));
}

export async function typeUseValidationSpans(
  checker: Checker,
  sourceFile: SourceFile,
  budget: TypeScriptValidationQueryBudget = { value: 0 },
): Promise<TypeScriptTypeUseValidationSpan[]> {
  const counter: QueryCounter = { value: budget.value, prior: 0 };
  try {
    return await typeUseValidationSpansWithCounter(checker, sourceFile, counter);
  } finally {
    budget.value = counter.value;
  }
}

function validateRawCondition(
  condition: Condition,
  depth = 0,
  counter: { value: number } = { value: 0 },
): void {
  if (depth > MAX_CONDITION_DEPTH) throw new DependencyContractError("raw dependency condition depth limit exceeded");
  counter.value += 1;
  if (counter.value > MAX_CONDITION_NODES) throw new DependencyContractError("raw dependency condition node limit exceeded");
  if (condition === null || typeof condition !== "object") throw new DependencyContractError("raw dependency condition is invalid");
  if (condition.op === "all" || condition.op === "any") {
    if (!Array.isArray(condition.conditions) || condition.conditions.length > MAX_CONDITION_NODES) {
      throw new DependencyContractError("raw dependency condition branch list is invalid");
    }
    for (const child of condition.conditions) validateRawCondition(child, depth + 1, counter);
    return;
  }
  if (condition.op === "not") {
    validateRawCondition(condition.condition, depth + 1, counter);
    return;
  }
  if (condition.op === "defined") {
    if (condition.key.length === 0 || condition.key.length > MAX_SPECIFIER_CHARS || hasUnpairedSurrogate(condition.key)) {
      throw new DependencyContractError("raw dependency condition key is invalid");
    }
    return;
  }
  if (condition.op === "eq" || condition.op === "in") {
    if (condition.key.length === 0 || condition.key.length > MAX_SPECIFIER_CHARS || hasUnpairedSurrogate(condition.key)) {
      throw new DependencyContractError("raw dependency condition key is invalid");
    }
    const values = condition.op === "eq" ? [condition.value] : condition.values;
    if (!Array.isArray(values) || values.length > MAX_CONDITION_VALUES || values.some((value) => (
      value !== null
      && typeof value !== "string"
      && typeof value !== "boolean"
      && !(typeof value === "number" && Number.isFinite(value))
    )) || values.some((value) => (
      (typeof value === "string" && hasUnpairedSurrogate(value))
      || (typeof value === "number" && Object.is(value, -0))
    ))) throw new DependencyContractError("raw dependency condition value is invalid");
    return;
  }
  throw new DependencyContractError("raw dependency condition operator is invalid");
}

function validateCanonicalRawCondition(condition: Condition): void {
  validateRawCondition(condition);
  if (JSON.stringify(condition) !== JSON.stringify(canonicalizeCondition(condition))) {
    throw new DependencyContractError("raw dependency condition is not canonical");
  }
}

function bindingReferenceCorrelates(
  site: TypeScriptRawDependencySite,
  originSite: TypeScriptRawDependencySite,
  sourceText: string,
  bindingOrigin: NonNullable<TypeScriptRawDependencySite["bindingOrigin"]>,
): boolean {
  const length = site.evidence.endOffset - bindingOrigin.referenceStartOffset;
  if (length <= 0) return false;
  const scanner = createScanner(
    true,
    LanguageVariant.Standard,
    sourceText,
    bindingOrigin.referenceStartOffset,
    length,
  );
  const first = scanner.scan() as SyntaxKind;
  if (
    !tokenIsIdentifierOrKeyword(first)
    || scanner.getTokenStart() !== bindingOrigin.referenceStartOffset
    || scanner.getTokenEnd() !== bindingOrigin.referenceEndOffset
  ) return false;
  const referenceName = scanner.getTokenValue();
  const originScanner = createScanner(
    true,
    LanguageVariant.Standard,
    sourceText,
    bindingOrigin.declarationStartOffset,
    bindingOrigin.declarationEndOffset - bindingOrigin.declarationStartOffset,
  );
  if (
    !tokenIsIdentifierOrKeyword(originScanner.scan() as SyntaxKind)
    || originScanner.getTokenStart() !== bindingOrigin.declarationStartOffset
    || originScanner.getTokenEnd() !== bindingOrigin.declarationEndOffset
    || originScanner.getTokenValue() !== referenceName
    || originScanner.scan() !== SyntaxKind.EndOfFile
  ) return false;
  if (site.kind === "type_use") {
    const path: string[] = [];
    let lastStart = scanner.getTokenStart();
    let lastEnd = scanner.getTokenEnd();
    for (;;) {
      const separator = scanner.scan() as SyntaxKind;
      if (separator === SyntaxKind.EndOfFile) break;
      if (separator !== SyntaxKind.DotToken) return false;
      const member = scanner.scan() as SyntaxKind;
      if (!tokenIsIdentifierOrKeyword(member)) return false;
      path.push(scanner.getTokenValue());
      lastStart = scanner.getTokenStart();
      lastEnd = scanner.getTokenEnd();
    }
    const exportPath = site.exportPath ?? [];
    const expectedPath = originSite.bindingKind === "default" || originSite.bindingKind === "named"
      ? originSite.importedName !== null && exportPath[0] === originSite.importedName
        ? exportPath.slice(1)
        : null
      : exportPath;
    return expectedPath !== null
      && lastStart === site.evidence.startOffset
      && lastEnd === site.evidence.endOffset
      && JSON.stringify(path) === JSON.stringify(expectedPath);
  }
  if (site.evidence.occurrenceKind !== "named_reexport" && site.evidence.occurrenceKind !== "namespace_reexport") {
    return false;
  }
  const separator = scanner.scan() as SyntaxKind;
  if (separator === SyntaxKind.EndOfFile) {
    return bindingOrigin.referenceStartOffset === site.evidence.startOffset
      && bindingOrigin.referenceEndOffset === site.evidence.endOffset;
  }
  if (separator !== SyntaxKind.AsKeyword) return false;
  const exported = scanner.scan() as SyntaxKind;
  if (!tokenIsIdentifierOrKeyword(exported) && exported !== SyntaxKind.StringLiteral) return false;
  return scanner.getTokenStart() === site.evidence.startOffset
    && scanner.getTokenEnd() === site.evidence.endOffset
    && scanner.scan() === SyntaxKind.EndOfFile;
}

function inlineImportReferenceCorrelates(
  site: TypeScriptRawDependencySite,
  originSite: TypeScriptRawDependencySite,
  sourceText: string,
): boolean {
  const length = site.evidence.endOffset - originSite.evidence.endOffset;
  if (length <= 0 || site.exportPath === null) return false;
  const scanner = createScanner(
    true,
    LanguageVariant.Standard,
    sourceText,
    originSite.evidence.endOffset,
    length,
  );
  let braces = 0;
  let brackets = 0;
  let parentheses = 0;
  let closedImport = false;
  for (;;) {
    const token = scanner.scan() as SyntaxKind;
    if (token === SyntaxKind.EndOfFile) return false;
    if (token === SyntaxKind.OpenBraceToken) braces += 1;
    else if (token === SyntaxKind.CloseBraceToken) {
      if (braces === 0) return false;
      braces -= 1;
    } else if (token === SyntaxKind.OpenBracketToken) brackets += 1;
    else if (token === SyntaxKind.CloseBracketToken) {
      if (brackets === 0) return false;
      brackets -= 1;
    } else if (token === SyntaxKind.OpenParenToken) parentheses += 1;
    else if (token === SyntaxKind.CloseParenToken) {
      if (braces === 0 && brackets === 0 && parentheses === 0) {
        closedImport = true;
        break;
      }
      if (parentheses === 0) return false;
      parentheses -= 1;
    }
  }
  if (!closedImport || braces !== 0 || brackets !== 0 || parentheses !== 0) return false;
  const path: string[] = [];
  let lastStart = -1;
  let lastEnd = -1;
  for (;;) {
    const separator = scanner.scan() as SyntaxKind;
    if (separator === SyntaxKind.EndOfFile) break;
    if (separator !== SyntaxKind.DotToken) return false;
    const member = scanner.scan() as SyntaxKind;
    if (!tokenIsIdentifierOrKeyword(member)) return false;
    path.push(scanner.getTokenValue());
    lastStart = scanner.getTokenStart();
    lastEnd = scanner.getTokenEnd();
  }
  return lastStart === site.evidence.startOffset
    && lastEnd === site.evidence.endOffset
    && JSON.stringify(path) === JSON.stringify(site.exportPath);
}

function identifierValueAt(sourceText: string, startOffset: number, endOffset: number): string | null {
  if (startOffset < 0 || endOffset <= startOffset || endOffset > sourceText.length) return null;
  const scanner = createScanner(true, LanguageVariant.Standard, sourceText, startOffset, endOffset - startOffset);
  if (
    !tokenIsIdentifierOrKeyword(scanner.scan() as SyntaxKind)
    || scanner.getTokenStart() !== startOffset
    || scanner.getTokenEnd() !== endOffset
  ) return null;
  const value = scanner.getTokenValue();
  return scanner.scan() === SyntaxKind.EndOfFile ? value : null;
}

function resolutionModeProofCorrelates(
  sourceText: string,
  mode: TypeScriptResolutionMode,
  proof: NonNullable<TypeScriptRawDependencySite["resolutionModeProof"]>,
): boolean {
  const tokenValue = (startOffset: number, endOffset: number): { kind: SyntaxKind; value: string } | null => {
    if (startOffset < 0 || endOffset <= startOffset || endOffset > sourceText.length) return null;
    const scanner = createScanner(true, LanguageVariant.Standard, sourceText, startOffset, endOffset - startOffset);
    const kind = scanner.scan() as SyntaxKind;
    const value = scanner.getTokenValue();
    return scanner.getTokenStart() === startOffset
      && scanner.getTokenEnd() === endOffset
      && scanner.scan() === SyntaxKind.EndOfFile
      ? { kind, value }
      : null;
  };
  const key = tokenValue(proof.keyStartOffset, proof.keyEndOffset);
  const value = tokenValue(proof.valueStartOffset, proof.valueEndOffset);
  return key !== null
    && value !== null
    && proof.keyEndOffset < proof.valueStartOffset
    && (key.kind === SyntaxKind.StringLiteral || tokenIsIdentifierOrKeyword(key.kind))
    && key.value === "resolution-mode"
    && value.kind === SyntaxKind.StringLiteral
    && value.value === mode;
}

interface DependencyValidationToken {
  kind: SyntaxKind;
  startOffset: number;
  endOffset: number;
  value: string;
  enclosingOpenBraceIndex: number | null;
  matchingIndex: number | null;
}

function dependencyValidationTokens(
  sourceText: string,
  startOffset = 0,
  endOffset = sourceText.length,
  jsDoc = false,
  jsx = false,
): DependencyValidationToken[] {
  const scannedTokens = scanTypeScriptSyntaxTokens(sourceText.slice(startOffset, endOffset), jsx);
  const tokens: DependencyValidationToken[] = [];
  const delimiterStack: Array<{ index: number; kind: SyntaxKind }> = [];
  const matchingOpen = new Map<SyntaxKind, SyntaxKind>([
    [SyntaxKind.CloseBraceToken, SyntaxKind.OpenBraceToken],
    [SyntaxKind.CloseBracketToken, SyntaxKind.OpenBracketToken],
    [SyntaxKind.CloseParenToken, SyntaxKind.OpenParenToken],
  ]);
  for (const scanned of scannedTokens) {
    const kind = scanned.kind;
    const tokenStart = startOffset + scanned.start;
    if (jsDoc && kind === SyntaxKind.AsteriskToken) {
      const lineStart = Math.max(
        sourceText.lastIndexOf("\n", tokenStart - 1),
        sourceText.lastIndexOf("\r", tokenStart - 1),
      ) + 1;
      if (/^\s*$/u.test(sourceText.slice(lineStart, tokenStart))) continue;
    }
    const expectedOpen = matchingOpen.get(kind);
    let matchingIndex: number | null = null;
    if (expectedOpen !== undefined && delimiterStack.at(-1)?.kind === expectedOpen) {
      matchingIndex = delimiterStack.pop()!.index;
    }
    const enclosingOpenBraceIndex = [...delimiterStack].reverse()
      .find((entry) => entry.kind === SyntaxKind.OpenBraceToken)?.index ?? null;
    tokens.push({
      kind,
      startOffset: tokenStart,
      endOffset: startOffset + scanned.end,
      value: scanned.value,
      enclosingOpenBraceIndex,
      matchingIndex,
    });
    const index = tokens.length - 1;
    if (matchingIndex !== null) tokens[matchingIndex]!.matchingIndex = index;
    if (
      kind === SyntaxKind.OpenBraceToken
      || kind === SyntaxKind.OpenBracketToken
      || kind === SyntaxKind.OpenParenToken
    ) delimiterStack.push({ index, kind });
  }
  return tokens;
}

interface SyntaxResolutionMode {
  mode: TypeScriptResolutionMode | null;
  proof: TypeScriptRawDependencySite["resolutionModeProof"];
  error: string | null;
}

const NO_SYNTAX_RESOLUTION_MODE: SyntaxResolutionMode = Object.freeze({ mode: null, proof: null, error: null });
const RESOLUTION_MODE_ERRORS: ReadonlySet<string> = new Set([
  "duplicate_resolution_mode",
  "invalid_resolution_mode",
  "invalid_resolution_mode_syntax",
  "resolution_mode_attribute_required",
  "resolution_mode_requires_single_attribute",
  "resolution_mode_requires_type_only",
]);

function resolutionModeError(reason: string | null): string | null {
  return reason !== null && RESOLUTION_MODE_ERRORS.has(reason) ? reason : null;
}

function topLevelTokenSegments(
  tokens: readonly DependencyValidationToken[],
  openIndex: number,
): DependencyValidationToken[][] | null {
  const closeIndex = tokens[openIndex]?.matchingIndex;
  if (tokens[openIndex]?.kind !== SyntaxKind.OpenBraceToken || closeIndex === null || closeIndex === undefined) {
    return null;
  }
  const segments: DependencyValidationToken[][] = [[]];
  let depth = 0;
  for (let indexValue = openIndex + 1; indexValue < closeIndex; indexValue += 1) {
    const token = tokens[indexValue]!;
    if (
      token.kind === SyntaxKind.OpenBraceToken
      || token.kind === SyntaxKind.OpenBracketToken
      || token.kind === SyntaxKind.OpenParenToken
    ) depth += 1;
    if (depth === 0 && token.kind === SyntaxKind.CommaToken) {
      segments.push([]);
      continue;
    }
    segments.at(-1)!.push(token);
    if (
      token.kind === SyntaxKind.CloseBraceToken
      || token.kind === SyntaxKind.CloseBracketToken
      || token.kind === SyntaxKind.CloseParenToken
    ) depth -= 1;
    if (depth < 0) return null;
  }
  if (depth !== 0) return null;
  return segments.filter((segment) => segment.length > 0);
}

function resolutionModeInAttributeObject(
  tokens: readonly DependencyValidationToken[],
  openIndex: number,
  typeOnly: boolean,
): SyntaxResolutionMode {
  const segments = topLevelTokenSegments(tokens, openIndex);
  if (segments === null) return NO_SYNTAX_RESOLUTION_MODE;
  const matches = segments.filter((segment) => segment[0]?.value === "resolution-mode");
  if (matches.length === 0) {
    return typeOnly
      ? { mode: null, proof: null, error: "resolution_mode_attribute_required" }
      : NO_SYNTAX_RESOLUTION_MODE;
  }
  if (matches.length !== 1) {
    return { mode: null, proof: null, error: "duplicate_resolution_mode" };
  }
  if (segments.length !== 1) {
    return { mode: null, proof: null, error: "resolution_mode_requires_single_attribute" };
  }
  const [key, colon, value] = matches[0]!;
  if (
    matches[0]!.length !== 3
    || key?.value !== "resolution-mode"
    || colon?.kind !== SyntaxKind.ColonToken
    || value?.kind !== SyntaxKind.StringLiteral
    || (value.value !== "import" && value.value !== "require")
  ) return { mode: null, proof: null, error: "invalid_resolution_mode" };
  if (!typeOnly) {
    return { mode: null, proof: null, error: "resolution_mode_requires_type_only" };
  }
  return {
    mode: value.value,
    error: null,
    proof: {
      keyStartOffset: key.startOffset,
      keyEndOffset: key.endOffset,
      valueStartOffset: value.startOffset,
      valueEndOffset: value.endOffset,
    },
  };
}

function staticResolutionMode(
  tokens: readonly DependencyValidationToken[],
  moduleIndex: number,
  typeOnly: boolean,
): SyntaxResolutionMode {
  const keyword = tokens[moduleIndex + 1];
  const open = tokens[moduleIndex + 2];
  if (
    keyword?.value !== "with"
    || open?.kind !== SyntaxKind.OpenBraceToken
  ) return NO_SYNTAX_RESOLUTION_MODE;
  return resolutionModeInAttributeObject(tokens, moduleIndex + 2, typeOnly);
}

function importTypeResolutionMode(
  tokens: readonly DependencyValidationToken[],
  moduleIndex: number,
): SyntaxResolutionMode {
  if (tokens[moduleIndex + 1]?.kind !== SyntaxKind.CommaToken) return NO_SYNTAX_RESOLUTION_MODE;
  const optionsOpenIndex = moduleIndex + 2;
  const options = topLevelTokenSegments(tokens, optionsOpenIndex);
  if (options?.length !== 1) return NO_SYNTAX_RESOLUTION_MODE;
  const [withKey, colon, attributesOpen] = options[0]!;
  if (
    options[0]!.length < 3
    || withKey?.value !== "with"
    || colon?.kind !== SyntaxKind.ColonToken
    || attributesOpen?.kind !== SyntaxKind.OpenBraceToken
  ) return NO_SYNTAX_RESOLUTION_MODE;
  const attributesOpenIndex = tokens.indexOf(attributesOpen);
  if (
    attributesOpenIndex < 0
    || attributesOpen.matchingIndex === null
    || options[0]!.at(-1) !== tokens[attributesOpen.matchingIndex]
  ) return NO_SYNTAX_RESOLUTION_MODE;
  return resolutionModeInAttributeObject(tokens, attributesOpenIndex, true);
}

function syntaxResolutionModeMatches(
  site: TypeScriptRawDependencySite,
  actual: SyntaxResolutionMode,
): boolean {
  return site.resolutionMode === actual.mode
    && JSON.stringify(site.resolutionModeProof) === JSON.stringify(actual.proof)
    && resolutionModeError(site.reason) === actual.error;
}

function bindingScopeCorrelates(
  site: TypeScriptRawDependencySite,
  tokens: readonly DependencyValidationToken[],
  declarationIndex: number | null,
  sourceLength: number,
): boolean {
  if (site.bindingScope === null) return false;
  if (declarationIndex === null) {
    return site.bindingScope.startOffset === 0 && site.bindingScope.endOffset === sourceLength;
  }
  const openIndex = tokens[declarationIndex]?.enclosingOpenBraceIndex;
  if (openIndex === null || openIndex === undefined) {
    return site.bindingScope.startOffset === 0 && site.bindingScope.endOffset === sourceLength;
  }
  const closeIndex = tokens[openIndex]?.matchingIndex;
  return closeIndex !== null
    && closeIndex !== undefined
    && site.bindingScope.startOffset === tokens[openIndex]!.startOffset
    && site.bindingScope.endOffset === tokens[closeIndex]!.endOffset;
}

function typeOnlyImportClause(
  tokens: readonly DependencyValidationToken[],
  importIndex: number,
): boolean {
  const marker = tokens[importIndex + 1];
  const following = tokens[importIndex + 2];
  return marker?.kind === SyntaxKind.TypeKeyword
    && following !== undefined
    && following.kind !== SyntaxKind.FromKeyword
    && following.kind !== SyntaxKind.CommaToken
    && following.kind !== SyntaxKind.EqualsToken;
}

function namedBindingSyntax(
  tokens: readonly DependencyValidationToken[],
  evidenceIndex: number,
  openIndex: number,
): { importedName: string; typeOnly: boolean } | null {
  const closeIndex = tokens[openIndex]?.matchingIndex;
  if (closeIndex === null || closeIndex === undefined || evidenceIndex <= openIndex || evidenceIndex >= closeIndex) {
    return null;
  }
  let segmentStart = openIndex + 1;
  for (let indexValue = openIndex + 1; indexValue < evidenceIndex; indexValue += 1) {
    if (tokens[indexValue]?.kind === SyntaxKind.CommaToken) segmentStart = indexValue + 1;
  }
  let segmentEnd = closeIndex;
  for (let indexValue = evidenceIndex + 1; indexValue < closeIndex; indexValue += 1) {
    if (tokens[indexValue]?.kind === SyntaxKind.CommaToken) {
      segmentEnd = indexValue;
      break;
    }
  }
  const segment = tokens.slice(segmentStart, segmentEnd);
  if (segment.length === 0) return null;
  const elementTypeOnly = segment[0]?.kind === SyntaxKind.TypeKeyword
    && segment[1] !== undefined
    && segment[1]!.kind !== SyntaxKind.AsKeyword;
  const importedIndex = elementTypeOnly ? 1 : 0;
  const imported = segment[importedIndex];
  if (imported === undefined || (
    imported.kind !== SyntaxKind.StringLiteral && !tokenIsIdentifierOrKeyword(imported.kind)
  )) return null;
  const asToken = segment[importedIndex + 1];
  const local = asToken?.kind === SyntaxKind.AsKeyword
    ? segment[importedIndex + 2]
    : imported;
  if (
    local === undefined
    || (local.kind !== SyntaxKind.StringLiteral && !tokenIsIdentifierOrKeyword(local.kind))
    || local.startOffset !== tokens[evidenceIndex]?.startOffset
    || local.endOffset !== tokens[evidenceIndex]?.endOffset
    || segment.length !== importedIndex + (asToken?.kind === SyntaxKind.AsKeyword ? 3 : 1)
  ) return null;
  return { importedName: imported.value, typeOnly: elementTypeOnly };
}

function jsDocImportTagTokens(
  site: TypeScriptRawDependencySite,
  sourceText: string,
): DependencyValidationToken[] | null {
  const commentStart = sourceText.lastIndexOf("/**", site.evidence.startOffset);
  const commentEnd = sourceText.indexOf("*/", site.evidence.endOffset);
  if (commentStart < 0 || commentEnd < site.evidence.endOffset) return null;
  const markers: Array<{ start: number; end: number }> = [];
  const matcher = /@import\b/gu;
  matcher.lastIndex = commentStart + 3;
  for (;;) {
    const match = matcher.exec(sourceText);
    if (match === null || match.index >= commentEnd) break;
    markers.push({ start: match.index, end: matcher.lastIndex });
  }
  const markerIndex = markers.findLastIndex((marker) => marker.end <= site.evidence.startOffset);
  if (markerIndex < 0) return null;
  const startOffset = markers[markerIndex]!.end;
  const endOffset = markers[markerIndex + 1]?.start ?? commentEnd;
  if (site.evidence.endOffset > endOffset) return null;
  return dependencyValidationTokens(sourceText, startOffset, endOffset, true);
}

function jsDocBindingSyntaxCorrelates(
  site: TypeScriptRawDependencySite,
  sourceText: string,
): boolean {
  const tokens = jsDocImportTagTokens(site, sourceText);
  if (tokens === null) return false;
  const evidenceIndex = tokens.findIndex((token) => (
    token.startOffset === site.evidence.startOffset && token.endOffset === site.evidence.endOffset
  ));
  if (evidenceIndex < 0) return false;
  const fromIndex = tokens.findIndex((token, indexValue) => (
    indexValue > evidenceIndex && token.kind === SyntaxKind.FromKeyword
  ));
  const moduleIndex = fromIndex < 0 ? -1 : fromIndex + 1;
  const moduleToken = tokens[moduleIndex];
  if (moduleToken?.kind !== SyntaxKind.StringLiteral || moduleToken.value !== site.moduleSpecifier) return false;
  const openIndex = tokens[evidenceIndex]?.enclosingOpenBraceIndex;
  const named = openIndex === null || openIndex === undefined
    ? null
    : namedBindingSyntax(tokens, evidenceIndex, openIndex);
  let occurrenceKind: string;
  let bindingKind: TypeScriptBindingKind;
  let importedNameValue: string;
  if (named !== null) {
    occurrenceKind = "named_import";
    bindingKind = "named";
    importedNameValue = named.importedName;
  } else if (
    tokens[evidenceIndex - 1]?.kind === SyntaxKind.AsKeyword
    && tokens[evidenceIndex - 2]?.kind === SyntaxKind.AsteriskToken
  ) {
    occurrenceKind = "namespace_import";
    bindingKind = "namespace";
    importedNameValue = "*";
  } else {
    occurrenceKind = "default_import";
    bindingKind = "default";
    importedNameValue = "default";
  }
  return site.evidence.occurrenceKind === occurrenceKind
    && site.bindingKind === bindingKind
    && site.importedName === importedNameValue
    && site.typeOnly
    && bindingScopeCorrelates(site, tokens, null, sourceText.length)
    && syntaxResolutionModeMatches(site, staticResolutionMode(tokens, moduleIndex, true));
}

function directBindingSyntaxCorrelates(
  site: TypeScriptRawDependencySite,
  sourceText: string,
  tokens: readonly DependencyValidationToken[],
): boolean {
  const evidenceIndex = tokens.findIndex((token) => (
    token.startOffset === site.evidence.startOffset && token.endOffset === site.evidence.endOffset
  ));
  if (evidenceIndex < 0) return jsDocBindingSyntaxCorrelates(site, sourceText);
  for (let importIndex = evidenceIndex - 1; importIndex >= 0; importIndex -= 1) {
    if (tokens[importIndex]?.kind !== SyntaxKind.ImportKeyword) continue;
    const clauseTypeOnly = typeOnlyImportClause(tokens, importIndex);
    if (tokens[evidenceIndex + 1]?.kind === SyntaxKind.EqualsToken) {
      const expectedBindingIndex = clauseTypeOnly ? importIndex + 2 : importIndex + 1;
      const moduleIndex = evidenceIndex + 4;
      if (
        expectedBindingIndex !== evidenceIndex
        || tokens[evidenceIndex + 2]?.value !== "require"
        || tokens[evidenceIndex + 3]?.kind !== SyntaxKind.OpenParenToken
        || tokens[moduleIndex]?.kind !== SyntaxKind.StringLiteral
        || tokens[moduleIndex]?.value !== site.moduleSpecifier
        || tokens[evidenceIndex + 3]?.matchingIndex !== moduleIndex + 1
        || site.evidence.occurrenceKind !== "import_equals"
        || site.bindingKind !== "import_equals"
        || site.importedName !== "="
        || site.typeOnly !== clauseTypeOnly
        || !syntaxResolutionModeMatches(site, NO_SYNTAX_RESOLUTION_MODE)
        || !bindingScopeCorrelates(site, tokens, importIndex, sourceText.length)
      ) continue;
      return true;
    }
    const statementScope = tokens[importIndex]?.enclosingOpenBraceIndex;
    const fromIndex = tokens.findIndex((token, indexValue) => (
      indexValue > evidenceIndex
      && token.kind === SyntaxKind.FromKeyword
      && token.enclosingOpenBraceIndex === statementScope
    ));
    const moduleIndex = fromIndex < 0 ? -1 : fromIndex + 1;
    if (tokens[moduleIndex]?.kind !== SyntaxKind.StringLiteral || tokens[moduleIndex]?.value !== site.moduleSpecifier) {
      continue;
    }
    const evidenceOpenIndex = tokens[evidenceIndex]?.enclosingOpenBraceIndex;
    const named = evidenceOpenIndex !== null
      && evidenceOpenIndex !== undefined
      && evidenceOpenIndex !== statementScope
      && (tokens[evidenceOpenIndex]?.startOffset ?? -1) > tokens[importIndex]!.startOffset
      ? namedBindingSyntax(tokens, evidenceIndex, evidenceOpenIndex)
      : null;
    let occurrenceKind: string;
    let bindingKind: TypeScriptBindingKind;
    let importedNameValue: string;
    let elementTypeOnly = false;
    if (named !== null) {
      occurrenceKind = "named_import";
      bindingKind = "named";
      importedNameValue = named.importedName;
      elementTypeOnly = named.typeOnly;
    } else if (
      tokens[evidenceIndex - 1]?.kind === SyntaxKind.AsKeyword
      && tokens[evidenceIndex - 2]?.kind === SyntaxKind.AsteriskToken
    ) {
      occurrenceKind = "namespace_import";
      bindingKind = "namespace";
      importedNameValue = "*";
    } else {
      const expectedDefaultIndex = clauseTypeOnly ? importIndex + 2 : importIndex + 1;
      if (expectedDefaultIndex !== evidenceIndex) continue;
      occurrenceKind = "default_import";
      bindingKind = "default";
      importedNameValue = "default";
    }
    const actualTypeOnly = clauseTypeOnly || elementTypeOnly;
    if (
      site.evidence.occurrenceKind !== occurrenceKind
      || site.bindingKind !== bindingKind
      || site.importedName !== importedNameValue
      || site.typeOnly !== actualTypeOnly
      || !syntaxResolutionModeMatches(site, staticResolutionMode(tokens, moduleIndex, clauseTypeOnly))
      || !bindingScopeCorrelates(site, tokens, importIndex, sourceText.length)
    ) continue;
    return true;
  }
  return false;
}

function reexportSyntaxCorrelates(
  site: TypeScriptRawDependencySite,
  sourceText: string,
  tokens: readonly DependencyValidationToken[],
  sitesByKey: ReadonlyMap<string, TypeScriptRawDependencySite>,
): boolean {
  const evidenceIndex = tokens.findIndex((token) => (
    token.startOffset === site.evidence.startOffset && token.endOffset === site.evidence.endOffset
  ));
  if (evidenceIndex < 0) return false;
  for (let exportIndex = evidenceIndex - 1; exportIndex >= 0; exportIndex -= 1) {
    if (tokens[exportIndex]?.kind !== SyntaxKind.ExportKeyword) continue;
    const statementScope = tokens[exportIndex]?.enclosingOpenBraceIndex;
    const declarationTypeOnly = tokens[exportIndex + 1]?.kind === SyntaxKind.TypeKeyword
      && (
        tokens[exportIndex + 2]?.kind === SyntaxKind.OpenBraceToken
        || tokens[exportIndex + 2]?.kind === SyntaxKind.AsteriskToken
      );
    const evidenceOpenIndex = tokens[evidenceIndex]?.enclosingOpenBraceIndex;
    const namedOpenIndex = evidenceOpenIndex !== null
      && evidenceOpenIndex !== undefined
      && evidenceOpenIndex !== statementScope
      && (tokens[evidenceOpenIndex]?.startOffset ?? -1) > tokens[exportIndex]!.startOffset
      ? evidenceOpenIndex
      : null;
    if (namedOpenIndex !== null) {
      const named = namedBindingSyntax(tokens, evidenceIndex, namedOpenIndex);
      if (named === null) continue;
      const closeIndex = tokens[namedOpenIndex]?.matchingIndex;
      if (closeIndex === null || closeIndex === undefined) continue;
      const fromIndex = tokens[closeIndex + 1]?.kind === SyntaxKind.FromKeyword ? closeIndex + 1 : -1;
      if (fromIndex < 0) {
        const origin = site.bindingOrigin === null ? undefined : sitesByKey.get(site.bindingOrigin.siteKey);
        return (site.evidence.occurrenceKind === "named_reexport"
            || site.evidence.occurrenceKind === "namespace_reexport")
          && origin !== undefined
          && site.typeOnly === (declarationTypeOnly || named.typeOnly || origin.typeOnly)
          && syntaxResolutionModeMatches(site, NO_SYNTAX_RESOLUTION_MODE);
      }
      const moduleIndex = fromIndex + 1;
      return tokens[moduleIndex]?.kind === SyntaxKind.StringLiteral
        && tokens[moduleIndex]?.value === site.moduleSpecifier
        && site.evidence.occurrenceKind === "named_reexport"
        && site.bindingKind === "named"
        && site.bindingOrigin === null
        && site.importedName === named.importedName
        && JSON.stringify(site.exportPath) === JSON.stringify([named.importedName])
        && site.typeOnly === (declarationTypeOnly || named.typeOnly)
        && syntaxResolutionModeMatches(site, staticResolutionMode(tokens, moduleIndex, declarationTypeOnly));
    }
    if (
      tokens[evidenceIndex - 1]?.kind !== SyntaxKind.AsKeyword
      || tokens[evidenceIndex - 2]?.kind !== SyntaxKind.AsteriskToken
    ) continue;
    const fromIndex = evidenceIndex + 1;
    const moduleIndex = fromIndex + 1;
    if (tokens[fromIndex]?.kind !== SyntaxKind.FromKeyword) continue;
    return tokens[moduleIndex]?.kind === SyntaxKind.StringLiteral
      && tokens[moduleIndex]?.value === site.moduleSpecifier
      && site.evidence.occurrenceKind === "namespace_reexport"
      && site.bindingKind === "namespace"
      && site.bindingOrigin === null
      && site.importedName === "*"
      && site.exportPath === null
      && site.typeOnly === declarationTypeOnly
      && syntaxResolutionModeMatches(site, staticResolutionMode(tokens, moduleIndex, declarationTypeOnly));
  }
  return false;
}

function jsDocModuleImportSyntaxCorrelates(
  site: TypeScriptRawDependencySite,
  sourceText: string,
): boolean {
  const tokens = jsDocImportTagTokens(site, sourceText);
  if (tokens === null) return false;
  const moduleIndex = tokens.findIndex((token) => (
    token.startOffset === site.evidence.startOffset
    && token.endOffset === site.evidence.endOffset
    && token.kind === SyntaxKind.StringLiteral
  ));
  if (moduleIndex < 0 || tokens[moduleIndex]?.value !== site.moduleSpecifier) return false;
  const fromIndex = moduleIndex - 1;
  const hasFromClause = tokens[fromIndex]?.kind === SyntaxKind.FromKeyword;
  const closeIndex = hasFromClause ? fromIndex - 1 : -1;
  const openIndex = closeIndex < 0 ? null : tokens[closeIndex]?.matchingIndex;
  const emptyNamedClause = openIndex !== null
    && openIndex !== undefined
    && tokens[openIndex]?.kind === SyntaxKind.OpenBraceToken
    && openIndex + 1 === closeIndex;
  const occurrenceCorrelates = hasFromClause
    ? emptyNamedClause && site.evidence.occurrenceKind === "empty_import"
    : site.evidence.occurrenceKind === "import_type";
  return occurrenceCorrelates
    && site.kind === "web_import"
    && site.bindingKind === null
    && site.importedName === null
    && site.exportPath === null
    && site.typeOnly
    && syntaxResolutionModeMatches(site, staticResolutionMode(tokens, moduleIndex, true));
}

function jsDocImportTypeSyntaxCorrelates(
  site: TypeScriptRawDependencySite,
  sourceText: string,
): boolean {
  const commentStart = sourceText.lastIndexOf("/**", site.evidence.startOffset);
  const commentEnd = sourceText.indexOf("*/", site.evidence.endOffset);
  if (commentStart < 0 || commentEnd < site.evidence.endOffset) return false;
  const importStart = sourceText.lastIndexOf("import", site.evidence.startOffset);
  if (importStart < commentStart) return false;
  const tokens = dependencyValidationTokens(sourceText, importStart, commentEnd, true);
  const moduleIndex = tokens.findIndex((token) => (
    token.startOffset === site.evidence.startOffset
    && token.endOffset === site.evidence.endOffset
    && token.kind === SyntaxKind.StringLiteral
  ));
  return moduleIndex >= 2
    && tokens[moduleIndex - 1]?.kind === SyntaxKind.OpenParenToken
    && tokens[moduleIndex - 2]?.kind === SyntaxKind.ImportKeyword
    && tokens[moduleIndex - 1]?.matchingIndex !== null
    && tokens[moduleIndex]?.value === site.moduleSpecifier
    && site.kind === "web_import"
    && site.evidence.occurrenceKind === "import_type"
    && site.bindingKind === null
    && site.bindingOrigin === null
    && site.bindingScope === null
    && site.importedName === null
    && site.exportPath === null
    && site.typeOnly
    && syntaxResolutionModeMatches(site, importTypeResolutionMode(tokens, moduleIndex));
}

function moduleLiteralSyntaxCorrelates(
  site: TypeScriptRawDependencySite,
  sourceText: string,
  tokens: readonly DependencyValidationToken[],
): boolean {
  const moduleIndex = tokens.findIndex((token) => (
    token.startOffset === site.evidence.startOffset
    && token.endOffset === site.evidence.endOffset
    && (
      token.kind === SyntaxKind.StringLiteral
      || token.kind === SyntaxKind.NoSubstitutionTemplateLiteral
    )
  ));
  if (moduleIndex < 0) {
    return jsDocModuleImportSyntaxCorrelates(site, sourceText)
      || jsDocImportTypeSyntaxCorrelates(site, sourceText);
  }
  const moduleToken = tokens[moduleIndex]!;
  if (
    moduleToken.value !== site.moduleSpecifier
    || site.bindingKind !== null
    || site.bindingOrigin !== null
    || site.bindingScope !== null
    || site.importedName !== null
    || site.exportPath !== null
  ) return false;
  if (tokens[moduleIndex - 1]?.kind === SyntaxKind.OpenParenToken) {
    const callee = tokens[moduleIndex - 2];
    const closeIndex = tokens[moduleIndex - 1]?.matchingIndex;
    if (closeIndex === null || closeIndex === undefined) return false;
    const calleeIndex = moduleIndex - 2;
    if (
      tokens[calleeIndex - 1]?.kind === SyntaxKind.DotToken
      || tokens[calleeIndex - 1]?.kind === SyntaxKind.QuestionDotToken
      || tokens[calleeIndex - 1]?.kind === SyntaxKind.FunctionKeyword
      || tokens[closeIndex + 1]?.kind === SyntaxKind.OpenBraceToken
    ) return false;
    if (
      (callee?.kind === SyntaxKind.Identifier || callee?.kind === SyntaxKind.RequireKeyword)
      && callee.value === "require"
    ) {
      return site.kind === "web_import"
        && site.evidence.occurrenceKind === "require_call"
        && !site.typeOnly
        && syntaxResolutionModeMatches(site, NO_SYNTAX_RESOLUTION_MODE);
    }
    if (callee?.kind !== SyntaxKind.ImportKeyword) return false;
    if (site.evidence.occurrenceKind === "dynamic_import") {
      return site.kind === "web_import"
        && !site.typeOnly
        && syntaxResolutionModeMatches(site, NO_SYNTAX_RESOLUTION_MODE);
    }
    return site.kind === "web_import"
      && site.evidence.occurrenceKind === "import_type"
      && site.typeOnly
      && syntaxResolutionModeMatches(site, importTypeResolutionMode(tokens, moduleIndex));
  }
  if (tokens[moduleIndex - 1]?.kind !== SyntaxKind.FromKeyword) {
    return tokens[moduleIndex - 1]?.kind === SyntaxKind.ImportKeyword
      && site.kind === "web_import"
      && site.evidence.occurrenceKind === "side_effect_import"
      && !site.typeOnly
      && syntaxResolutionModeMatches(site, staticResolutionMode(tokens, moduleIndex, false));
  }
  const fromIndex = moduleIndex - 1;
  const beforeFrom = tokens[fromIndex - 1];
  if (beforeFrom?.kind === SyntaxKind.CloseBraceToken) {
    const openIndex = beforeFrom.matchingIndex;
    if (openIndex === null || openIndex === undefined || openIndex + 1 !== fromIndex - 1) return false;
    let declarationIndex = openIndex - 1;
    let declarationTypeOnly = false;
    if (tokens[declarationIndex]?.kind === SyntaxKind.TypeKeyword) {
      declarationTypeOnly = true;
      declarationIndex -= 1;
    }
    const declarationKind = tokens[declarationIndex]?.kind;
    if (declarationKind === SyntaxKind.ImportKeyword) {
      return site.kind === "web_import"
        && site.evidence.occurrenceKind === "empty_import"
        && site.typeOnly === declarationTypeOnly
        && syntaxResolutionModeMatches(site, staticResolutionMode(tokens, moduleIndex, declarationTypeOnly));
    }
    return declarationKind === SyntaxKind.ExportKeyword
      && site.kind === "web_reexport"
      && site.evidence.occurrenceKind === "empty_reexport"
      && site.typeOnly === declarationTypeOnly
      && syntaxResolutionModeMatches(site, staticResolutionMode(tokens, moduleIndex, declarationTypeOnly));
  }
  if (beforeFrom?.kind === SyntaxKind.AsteriskToken) {
    let declarationIndex = fromIndex - 2;
    let declarationTypeOnly = false;
    if (tokens[declarationIndex]?.kind === SyntaxKind.TypeKeyword) {
      declarationTypeOnly = true;
      declarationIndex -= 1;
    }
    return tokens[declarationIndex]?.kind === SyntaxKind.ExportKeyword
      && site.kind === "web_reexport"
      && site.evidence.occurrenceKind === "export_star"
      && site.typeOnly === declarationTypeOnly
      && syntaxResolutionModeMatches(site, staticResolutionMode(tokens, moduleIndex, declarationTypeOnly));
  }
  return false;
}

function unresolvedCallModuleSyntaxCorrelates(
  site: TypeScriptRawDependencySite,
  sourceText: string,
  tokens: readonly DependencyValidationToken[],
): boolean {
  if (
    site.kind !== "web_import"
    || site.bindingKind !== null
    || site.bindingOrigin !== null
    || site.bindingScope !== null
    || site.importedName !== null
    || site.exportPath !== null
  ) return false;
  for (let calleeIndex = 0; calleeIndex + 1 < tokens.length; calleeIndex += 1) {
    const callee = tokens[calleeIndex]!;
    const isImport = callee.kind === SyntaxKind.ImportKeyword;
    const isRequire = (
      callee.kind === SyntaxKind.Identifier
      || callee.kind === SyntaxKind.RequireKeyword
    ) && callee.value === "require";
    if (
      (!isImport && !isRequire)
      || tokens[calleeIndex - 1]?.kind === SyntaxKind.DotToken
      || tokens[calleeIndex - 1]?.kind === SyntaxKind.QuestionDotToken
      || tokens[calleeIndex + 1]?.kind !== SyntaxKind.OpenParenToken
    ) continue;
    const openIndex = calleeIndex + 1;
    const closeIndex = tokens[openIndex]?.matchingIndex;
    if (closeIndex === null || closeIndex === undefined) continue;
    if (
      tokens[calleeIndex - 1]?.kind === SyntaxKind.FunctionKeyword
      || tokens[closeIndex + 1]?.kind === SyntaxKind.OpenBraceToken
    ) continue;
    const expectedOccurrence = isRequire
      ? "require_call"
      : site.typeOnly ? "import_type" : "dynamic_import";
    if (site.evidence.occurrenceKind !== expectedOccurrence) continue;
    if (site.reason === "missing_module_specifier") {
      if (
        openIndex + 1 !== closeIndex
        || site.evidence.startOffset !== callee.startOffset
        || site.evidence.endOffset !== tokens[closeIndex]!.endOffset
        || site.specifier !== "<missing>"
        || site.moduleSpecifier !== "<missing>"
        || site.typeOnly
        || !syntaxResolutionModeMatches(site, NO_SYNTAX_RESOLUTION_MODE)
      ) continue;
      return true;
    }
    const expectedReason = site.typeOnly
      ? "non_literal_module_specifier"
      : "computed_module_specifier";
    if (
      site.reason !== expectedReason
      && (!site.typeOnly || resolutionModeError(site.reason) === null)
    ) continue;
    if (openIndex + 1 >= closeIndex) continue;
    const argumentStartIndex = openIndex + 1;
    let argumentEndIndex = closeIndex - 1;
    for (let indexValue = argumentStartIndex; indexValue < closeIndex; indexValue += 1) {
      const token = tokens[indexValue]!;
      if (
        token.kind === SyntaxKind.OpenBraceToken
        || token.kind === SyntaxKind.OpenBracketToken
        || token.kind === SyntaxKind.OpenParenToken
      ) {
        const matchingIndex = token.matchingIndex;
        if (matchingIndex === null || matchingIndex === undefined || matchingIndex >= closeIndex) break;
        indexValue = matchingIndex;
        continue;
      }
      if (token.kind === SyntaxKind.CommaToken) {
        argumentEndIndex = indexValue - 1;
        break;
      }
    }
    const firstArgument = tokens[argumentStartIndex];
    const lastArgument = tokens[argumentEndIndex];
    if (
      firstArgument === undefined
      || lastArgument === undefined
      || site.evidence.startOffset !== firstArgument.startOffset
      || site.evidence.endOffset !== lastArgument.endOffset
    ) continue;
    if (
      argumentStartIndex === argumentEndIndex
      && (
        firstArgument.kind === SyntaxKind.StringLiteral
        || firstArgument.kind === SyntaxKind.NoSubstitutionTemplateLiteral
      )
    ) continue;
    const argumentText = sourceText.slice(firstArgument.startOffset, lastArgument.endOffset);
    if (site.specifier !== argumentText || site.moduleSpecifier !== argumentText) continue;
    if (isRequire || !site.typeOnly) {
      if (!syntaxResolutionModeMatches(site, NO_SYNTAX_RESOLUTION_MODE)) continue;
    } else if (!syntaxResolutionModeMatches(site, importTypeResolutionMode(tokens, argumentEndIndex))) {
      continue;
    }
    return true;
  }
  return false;
}

function ambiguousLocalReexportSyntaxCorrelates(
  site: TypeScriptRawDependencySite,
  tokens: readonly DependencyValidationToken[],
  directBindingsByName: ReadonlyMap<string, readonly TypeScriptRawDependencySite[]>,
): boolean {
  if (
    site.kind !== "web_reexport"
    || site.evidence.occurrenceKind !== "named_reexport"
    || site.moduleSpecifier !== "<ambiguous>"
    || site.bindingKind !== "named"
    || site.bindingOrigin !== null
    || site.bindingScope !== null
    || site.resolutionMode !== null
    || site.resolutionModeProof !== null
  ) return false;
  const evidenceIndex = tokens.findIndex((token) => (
    token.startOffset === site.evidence.startOffset && token.endOffset === site.evidence.endOffset
  ));
  if (evidenceIndex < 0) return false;
  const openIndex = tokens[evidenceIndex]?.enclosingOpenBraceIndex;
  if (openIndex === null || openIndex === undefined) return false;
  const closeIndex = tokens[openIndex]?.matchingIndex;
  if (closeIndex === null || closeIndex === undefined) return false;
  let exportIndex = openIndex - 1;
  let declarationTypeOnly = false;
  if (tokens[exportIndex]?.kind === SyntaxKind.TypeKeyword) {
    declarationTypeOnly = true;
    exportIndex -= 1;
  }
  if (
    tokens[exportIndex]?.kind !== SyntaxKind.ExportKeyword
    || tokens[closeIndex + 1]?.kind === SyntaxKind.FromKeyword
  ) return false;
  const named = namedBindingSyntax(tokens, evidenceIndex, openIndex);
  let segmentStart = openIndex + 1;
  for (let indexValue = openIndex + 1; indexValue < evidenceIndex; indexValue += 1) {
    if (tokens[indexValue]?.kind === SyntaxKind.CommaToken) segmentStart = indexValue + 1;
  }
  const referenceIndex = tokens[segmentStart]?.kind === SyntaxKind.TypeKeyword
    ? segmentStart + 1
    : segmentStart;
  const reference = tokens[referenceIndex];
  return named !== null
    && reference !== undefined
    && site.importedName === named.importedName
    && JSON.stringify(site.exportPath) === JSON.stringify([named.importedName])
    && site.typeOnly === (declarationTypeOnly || named.typeOnly)
    && hasIncompatibleVisibleBindingOrigins(
      site.evidence.relativePath,
      named.importedName,
      reference.startOffset,
      directBindingsByName,
    );
}

function ambiguousTypeUseSyntaxCorrelates(
  site: TypeScriptRawDependencySite,
  sourceText: string,
  tokens: readonly DependencyValidationToken[],
  directBindingsByName: ReadonlyMap<string, readonly TypeScriptRawDependencySite[]>,
): boolean {
  const identifier = identifierValueAt(sourceText, site.evidence.startOffset, site.evidence.endOffset);
  const evidenceIndex = tokens.findIndex((token) => (
    token.startOffset === site.evidence.startOffset && token.endOffset === site.evidence.endOffset
  ));
  let rootIndex = evidenceIndex;
  while (
    rootIndex >= 2
    && tokens[rootIndex - 1]?.kind === SyntaxKind.DotToken
    && tokenIsIdentifierOrKeyword(tokens[rootIndex - 2]!.kind)
  ) rootIndex -= 2;
  const root = tokens[rootIndex];
  const exportPath = rootIndex === evidenceIndex
    ? identifier === null ? [] : [identifier]
    : tokens
      .filter((_token, indexValue) => (
        indexValue >= rootIndex + 2
        && indexValue <= evidenceIndex
        && (indexValue - rootIndex) % 2 === 0
      ))
      .map((token) => token.value);
  return site.kind === "type_use"
    && identifier !== null
    && root !== undefined
    && tokenIsIdentifierOrKeyword(root.kind)
    && site.specifier === identifier
    && site.importedName === identifier
    && site.moduleSpecifier === "<ambiguous>"
    && site.bindingKind === "named"
    && JSON.stringify(site.exportPath) === JSON.stringify(exportPath)
    && site.bindingOrigin === null
    && site.bindingScope === null
    && site.resolutionMode === null
    && site.resolutionModeProof === null
    && site.typeOnly
    && hasIncompatibleVisibleBindingOrigins(
      site.evidence.relativePath,
      root.value,
      root.startOffset,
      directBindingsByName,
    );
}

function hasIncompatibleVisibleBindingOrigins(
  relativePath: string,
  localName: string,
  referenceOffset: number,
  directBindingsByName: ReadonlyMap<string, readonly TypeScriptRawDependencySite[]>,
): boolean {
  const visible = (directBindingsByName.get(JSON.stringify([relativePath, localName])) ?? [])
    .filter((candidate) => (
      candidate.bindingScope !== null
      && candidate.bindingScope.startOffset <= referenceOffset
      && candidate.bindingScope.endOffset >= referenceOffset
    ));
  const nearestScopeLength = visible.reduce((length, candidate) => (
    candidate.bindingScope === null
      ? length
      : Math.min(length, candidate.bindingScope.endOffset - candidate.bindingScope.startOffset)
  ), Number.POSITIVE_INFINITY);
  const nearest = visible.filter((candidate) => (
    candidate.bindingScope !== null
    && candidate.bindingScope.endOffset - candidate.bindingScope.startOffset === nearestScopeLength
  ));
  if (nearest.length < 2) return false;
  const provenOrigins = new Set(nearest.map((candidate) => JSON.stringify([
    candidate.moduleSpecifier,
    candidate.importedName,
    candidate.bindingKind,
    candidate.typeOnly,
    candidate.resolutionMode,
    candidate.resolutionModeProof,
  ])));
  return provenOrigins.size > 1;
}

function isValidationRecord(value: unknown): boolean {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

interface TypeScriptDependencyValidationContext {
  readonly sourceLengths: ReadonlyMap<string, number>;
  readonly sourceTexts: ReadonlyMap<string, string>;
  readonly sourceSyntaxValidity: ReadonlyMap<string, boolean>;
  readonly importTypeModuleSpans: ReadonlyMap<string, ReadonlySet<string>>;
  readonly moduleCallSpans: ReadonlyMap<string, ReadonlyMap<string, string>>;
  readonly nonLiteralModuleSpans: ReadonlyMap<
    string,
    ReadonlyMap<string, TypeScriptNonLiteralModuleValidationSpan>
  >;
  readonly typeUseSpans: ReadonlyMap<string, ReadonlyMap<string, TypeScriptTypeUseValidationSpan>>;
  readonly callSpans: ReadonlyMap<string, ReadonlyMap<string, TypeScriptCallValidationSpan>>;
}

function buildImportTypeModuleSpanIndex(
  source: Readonly<TypeScriptDependencyValidationSource>,
): ReadonlySet<string> {
  if (!Array.isArray(source.importTypeModuleSpans)) {
    throw new DependencyContractError("raw dependency import-type validation spans are missing");
  }
  const spans = new Set<string>();
  for (const spanValue of source.importTypeModuleSpans) {
    if (
      !isValidationRecord(spanValue)
      || !Number.isSafeInteger(spanValue.startOffset)
      || !Number.isSafeInteger(spanValue.endOffset)
      || spanValue.startOffset < 0
      || spanValue.endOffset <= spanValue.startOffset
      || spanValue.endOffset > source.text.length
    ) throw new DependencyContractError("raw dependency import-type validation span is invalid");
    const key = `${spanValue.startOffset}\0${spanValue.endOffset}`;
    if (spans.has(key)) throw new DependencyContractError("raw dependency import-type validation span is duplicated");
    spans.add(key);
  }
  return spans;
}

function buildModuleCallSpanIndex(
  source: Readonly<TypeScriptDependencyValidationSource>,
): ReadonlyMap<string, string> {
  if (!Array.isArray(source.moduleCallSpans)) {
    throw new DependencyContractError("raw dependency module-call validation spans are missing");
  }
  const calls = new Map<string, string>();
  for (const spanValue of source.moduleCallSpans) {
    if (
      !isValidationRecord(spanValue)
      || !Number.isSafeInteger(spanValue.startOffset)
      || !Number.isSafeInteger(spanValue.endOffset)
      || spanValue.startOffset < 0
      || spanValue.endOffset <= spanValue.startOffset
      || spanValue.endOffset > source.text.length
      || (spanValue.occurrenceKind !== "require_call" && spanValue.occurrenceKind !== "dynamic_import")
      || !["literal", "computed", "missing"].includes(spanValue.syntax)
      || typeof spanValue.moduleSpecifier !== "string"
      || spanValue.moduleSpecifier.length > MAX_SPECIFIER_CHARS
      || hasUnpairedSurrogate(spanValue.moduleSpecifier)
    ) throw new DependencyContractError("raw dependency module-call validation span is invalid");
    const key = `${spanValue.startOffset}\0${spanValue.endOffset}\0${spanValue.occurrenceKind}\0${spanValue.syntax}`;
    if (calls.has(key)) throw new DependencyContractError("raw dependency module-call validation span is duplicated");
    calls.set(key, spanValue.moduleSpecifier);
  }
  return calls;
}

function buildNonLiteralModuleSpanIndex(
  source: Readonly<TypeScriptDependencyValidationSource>,
): ReadonlyMap<string, TypeScriptNonLiteralModuleValidationSpan> {
  if (!Array.isArray(source.nonLiteralModuleSpans)) {
    throw new DependencyContractError("raw dependency non-literal module validation spans are missing");
  }
  const nonLiteralModules = new Map<string, TypeScriptNonLiteralModuleValidationSpan>();
  for (const spanValue of source.nonLiteralModuleSpans) {
    if (!isValidationRecord(spanValue)) {
      throw new DependencyContractError("raw dependency non-literal module validation span is invalid");
    }
    const bindingScope = spanValue.bindingScope;
    const proof = spanValue.resolutionModeProof;
    if (
      !Number.isSafeInteger(spanValue.startOffset)
      || !Number.isSafeInteger(spanValue.endOffset)
      || spanValue.startOffset < 0
      || spanValue.endOffset <= spanValue.startOffset
      || spanValue.endOffset > source.text.length
      || !["web_import", "web_reexport"].includes(spanValue.siteKind)
      || !["dynamic_import", "import_type", "export_star", "import_equals"].includes(spanValue.occurrenceKind)
      || typeof spanValue.moduleSpecifier !== "string"
      || spanValue.moduleSpecifier.length === 0
      || spanValue.moduleSpecifier.length > MAX_SPECIFIER_CHARS
      || hasUnpairedSurrogate(spanValue.moduleSpecifier)
      || source.text.slice(spanValue.startOffset, spanValue.endOffset) !== spanValue.moduleSpecifier
      || typeof spanValue.typeOnly !== "boolean"
      || (spanValue.resolutionMode !== null
        && spanValue.resolutionMode !== "import"
        && spanValue.resolutionMode !== "require")
      || (spanValue.resolutionModeError !== null
        && !RESOLUTION_MODE_ERRORS.has(spanValue.resolutionModeError))
      || (
        spanValue.occurrenceKind === "import_equals"
          ? spanValue.siteKind !== "web_import"
            || spanValue.importedName !== "="
            || spanValue.bindingKind !== "import_equals"
            || bindingScope === null
            || !Number.isSafeInteger(bindingScope.startOffset)
            || !Number.isSafeInteger(bindingScope.endOffset)
            || bindingScope.startOffset < 0
            || bindingScope.endOffset <= bindingScope.startOffset
            || bindingScope.endOffset > source.text.length
            || bindingScope.startOffset > spanValue.startOffset
            || bindingScope.endOffset < spanValue.endOffset
          : spanValue.importedName !== null
            || spanValue.bindingKind !== null
            || bindingScope !== null
      )
      || (spanValue.siteKind === "web_reexport" && spanValue.occurrenceKind !== "export_star")
      || (spanValue.siteKind === "web_import" && spanValue.occurrenceKind === "export_star")
      || (
        spanValue.resolutionMode === null
          ? proof !== null
          : proof === null
            || !resolutionModeProofCorrelates(source.text, spanValue.resolutionMode, proof)
      )
      || (spanValue.resolutionModeError !== null
        && (spanValue.resolutionMode !== null || proof !== null))
    ) throw new DependencyContractError("raw dependency non-literal module validation span is invalid");
    const key = `${spanValue.startOffset}\0${spanValue.endOffset}\0${spanValue.siteKind}\0${spanValue.occurrenceKind}`;
    if (nonLiteralModules.has(key)) {
      throw new DependencyContractError("raw dependency non-literal module validation span is duplicated");
    }
    nonLiteralModules.set(key, {
      ...spanValue,
      bindingScope: bindingScope === null ? null : { ...bindingScope },
      resolutionModeProof: proof === null ? null : { ...proof },
    });
  }
  return nonLiteralModules;
}

function buildTypeUseSpanIndex(
  source: Readonly<TypeScriptDependencyValidationSource>,
  importTypeModuleSpans: ReadonlySet<string>,
): ReadonlyMap<string, TypeScriptTypeUseValidationSpan> {
  if (!Array.isArray(source.typeUseSpans)) {
    throw new DependencyContractError("raw dependency type-use validation spans are missing");
  }
  const typeUses = new Map<string, TypeScriptTypeUseValidationSpan>();
  for (const spanValue of source.typeUseSpans) {
    if (
      !isValidationRecord(spanValue)
      || !Number.isSafeInteger(spanValue.startOffset)
      || !Number.isSafeInteger(spanValue.endOffset)
      || spanValue.startOffset < 0
      || spanValue.endOffset <= spanValue.startOffset
      || spanValue.endOffset > source.text.length
      || !["type_reference", "heritage_type", "jsdoc_type"].includes(spanValue.occurrenceKind)
      || typeof spanValue.terminalName !== "string"
      || spanValue.terminalName.length === 0
      || spanValue.terminalName.length > 512
      || hasUnpairedSurrogate(spanValue.terminalName)
      || identifierValueAt(source.text, spanValue.startOffset, spanValue.endOffset) !== spanValue.terminalName
      || !(
        (spanValue.inlineImportModuleStartOffset === null && spanValue.inlineImportModuleEndOffset === null)
        || (
          Number.isSafeInteger(spanValue.inlineImportModuleStartOffset)
          && Number.isSafeInteger(spanValue.inlineImportModuleEndOffset)
          && spanValue.inlineImportModuleStartOffset! >= 0
          && spanValue.inlineImportModuleEndOffset! > spanValue.inlineImportModuleStartOffset!
          && spanValue.inlineImportModuleEndOffset! <= source.text.length
          && importTypeModuleSpans.has(
            `${spanValue.inlineImportModuleStartOffset}\0${spanValue.inlineImportModuleEndOffset}`,
          )
        )
      )
    ) throw new DependencyContractError("raw dependency type-use validation span is invalid");
    const key = `${spanValue.startOffset}\0${spanValue.endOffset}\0${spanValue.occurrenceKind}`;
    if (typeUses.has(key)) throw new DependencyContractError("raw dependency type-use validation span is duplicated");
    typeUses.set(key, { ...spanValue });
  }
  return typeUses;
}

function buildCallSpanIndex(
  source: Readonly<TypeScriptDependencyValidationSource>,
): ReadonlyMap<string, TypeScriptCallValidationSpan> {
  if (!Array.isArray(source.callSpans)) {
    throw new DependencyContractError("raw dependency call validation spans are missing");
  }
  const sourceCalls = new Map<string, TypeScriptCallValidationSpan>();
  for (const spanValue of source.callSpans) {
    if (
      !isValidationRecord(spanValue)
      || !Number.isSafeInteger(spanValue.startOffset)
      || !Number.isSafeInteger(spanValue.endOffset)
      || spanValue.startOffset < 0
      || spanValue.endOffset <= spanValue.startOffset
      || spanValue.endOffset > source.text.length
      || !["call_expression", "new_expression", "tagged_template"].includes(spanValue.occurrenceKind)
      || typeof spanValue.specifier !== "string"
      || spanValue.specifier.length === 0
      || spanValue.specifier.length > MAX_SPECIFIER_CHARS
      || hasUnpairedSurrogate(spanValue.specifier)
    ) throw new DependencyContractError("raw dependency call validation span is invalid");
    const key = `${spanValue.startOffset}\0${spanValue.endOffset}\0${spanValue.occurrenceKind}`;
    if (sourceCalls.has(key)) throw new DependencyContractError("raw dependency call validation span is duplicated");
    sourceCalls.set(key, { ...spanValue });
  }
  return sourceCalls;
}

function buildTypeScriptDependencyValidationContext(
  sources: readonly TypeScriptDependencyValidationSource[],
): TypeScriptDependencyValidationContext {
  const sourceLengths = new Map<string, number>();
  const sourceTexts = new Map<string, string>();
  const sourceSyntaxValidity = new Map<string, boolean>();
  const importTypeModuleSpans = new Map<string, ReadonlySet<string>>();
  const moduleCallSpans = new Map<string, ReadonlyMap<string, string>>();
  const nonLiteralModuleSpans = new Map<string, ReadonlyMap<string, TypeScriptNonLiteralModuleValidationSpan>>();
  const typeUseSpans = new Map<string, ReadonlyMap<string, TypeScriptTypeUseValidationSpan>>();
  const callSpans = new Map<string, ReadonlyMap<string, TypeScriptCallValidationSpan>>();
  for (const source of sources) {
    if (!isValidationRecord(source)) {
      throw new DependencyContractError("raw dependency source is invalid");
    }
    if (typeof source.relativePath !== "string" || !isCanonicalRelativePath(source.relativePath)) {
      throw new DependencyContractError("raw dependency source path is not canonical");
    }
    if (sourceLengths.has(source.relativePath)) {
      throw new DependencyContractError("raw dependency source path is duplicated");
    }
    if (typeof source.text !== "string") {
      throw new DependencyContractError("raw dependency source text is invalid");
    }
    sourceLengths.set(source.relativePath, source.text.length);
    sourceTexts.set(source.relativePath, source.text);
    if (typeof source.syntacticallyValid !== "boolean") {
      throw new DependencyContractError("raw dependency source syntax validity is invalid");
    }
    sourceSyntaxValidity.set(source.relativePath, source.syntacticallyValid);
    const importTypeSpans = buildImportTypeModuleSpanIndex(source);
    importTypeModuleSpans.set(source.relativePath, importTypeSpans);
    moduleCallSpans.set(source.relativePath, buildModuleCallSpanIndex(source));
    nonLiteralModuleSpans.set(source.relativePath, buildNonLiteralModuleSpanIndex(source));
    typeUseSpans.set(source.relativePath, buildTypeUseSpanIndex(source, importTypeSpans));
    callSpans.set(source.relativePath, buildCallSpanIndex(source));
  }
  return Object.freeze({
    sourceLengths,
    sourceTexts,
    sourceSyntaxValidity,
    importTypeModuleSpans,
    moduleCallSpans,
    nonLiteralModuleSpans,
    typeUseSpans,
    callSpans,
  });
}

export function validateTypeScriptRawDependencyDelta(
  delta: TypeScriptRawDependencyDelta,
  definitionsDelta: Pick<TypeScriptRawDefinitionDelta, "definitions">,
  sources: readonly TypeScriptDependencyValidationSource[],
): void {
  if (!Array.isArray(delta.calls)) throw new DependencyContractError("raw dependency call ledger is missing");
  if (delta.sites.length + delta.calls.length > MAX_SITES) throw new DependencyContractError("raw dependency site limit exceeded");
  const {
    sourceLengths,
    sourceTexts,
    sourceSyntaxValidity,
    importTypeModuleSpans,
    moduleCallSpans,
    nonLiteralModuleSpans,
    typeUseSpans,
    callSpans,
  } = buildTypeScriptDependencyValidationContext(sources);
  const sitesByKey = new Map(delta.sites.map((site) => [site.key, site]));
  const definitions = new Map(definitionsDelta.definitions.map((definition) => [definition.key, definition]));
  const validationTokensBySource = new Map([...sourceTexts].map(([relativePath, sourceText]) => [
    relativePath,
    dependencyValidationTokens(sourceText, 0, sourceText.length, false, /\.(?:jsx|tsx)$/iu.test(relativePath)),
  ]));
  if (delta.moduleExports.length > MAX_MODULE_EXPORT_BINDINGS) {
    throw new DependencyContractError("raw module export proof limit exceeded");
  }
  let previousModuleExport: { relativePath: string; exportPathKey: string } | null = null;
  for (const proof of delta.moduleExports) {
    const exportPathKey = JSON.stringify(proof.exportPath);
    if (
      previousModuleExport !== null
      && (
        compareStrings(previousModuleExport.relativePath, proof.relativePath)
        || compareStrings(previousModuleExport.exportPathKey, exportPathKey)
      ) >= 0
    ) {
      throw new DependencyContractError("raw module export proofs are not strictly sorted");
    }
    previousModuleExport = { relativePath: proof.relativePath, exportPathKey };
    if (
      !sourceLengths.has(proof.relativePath)
      || !Array.isArray(proof.exportPath)
      || proof.exportPath.length > MAX_EXPORT_PATH_DEPTH
      || proof.exportPath.some((part) => part.length > 512 || hasUnpairedSurrogate(part))
      || proof.definitionKeys.length === 0
      || proof.definitionKeys.length > MAX_EXPORTS_PER_MODULE
    ) throw new DependencyContractError("raw module export proof is invalid");
    let previousDefinition = "";
    for (const key of proof.definitionKeys) {
      if (previousDefinition !== "" && compareStrings(previousDefinition, key) >= 0) {
        throw new DependencyContractError("raw module export targets are not strictly sorted");
      }
      previousDefinition = key;
      const definition = definitions.get(key);
      if (definition === undefined || definition.semanticKind === "generic_instance") {
        throw new DependencyContractError("raw module export target is not a canonical definition");
      }
    }
  }
  const moduleLevelOccurrences = new Set([
    "namespace_import", "side_effect_import", "empty_import", "import_equals", "require_call", "dynamic_import", "import_type",
    "namespace_reexport", "empty_reexport", "export_star",
  ]);
  const occurrencesByKind = new Map<TypeScriptRawDependencySiteKind, ReadonlySet<string>>([
    ["web_import", new Set([
      "default_import", "named_import", "namespace_import", "side_effect_import", "import_equals",
      "empty_import", "require_call", "dynamic_import", "import_type",
    ])],
    ["web_reexport", new Set(["named_reexport", "namespace_reexport", "empty_reexport", "export_star"])],
    ["type_use", new Set(["type_reference", "heritage_type", "jsdoc_type"])],
  ]);
  const namedBindingOccurrences = new Set(["default_import", "named_import", "named_reexport"]);
  const namespaceBindingOccurrences = new Set(["namespace_import", "namespace_reexport"]);
  const moduleOnlyOccurrences = new Set([
    "side_effect_import", "empty_import", "require_call", "dynamic_import", "import_type", "empty_reexport", "export_star",
  ]);
  const originOccurrences = new Map<TypeScriptBindingKind, ReadonlySet<string>>([
    ["default", new Set(["default_import"])],
    ["named", new Set(["named_import"])],
    ["namespace", new Set(["namespace_import"])],
    ["import_equals", new Set(["import_equals"])],
  ]);
  const inlineImportsByModule = new Map<string, TypeScriptRawDependencySite[]>();
  const inlineImportsByEvidence = new Map<string, TypeScriptRawDependencySite>();
  for (const site of delta.sites) {
    if (site.evidence.occurrenceKind !== "import_type" || site.moduleSpecifier === null) continue;
    const key = JSON.stringify([site.evidence.relativePath, site.moduleSpecifier]);
    inlineImportsByModule.set(key, [...(inlineImportsByModule.get(key) ?? []), site]);
  }
  for (const site of delta.sites) {
    if (site.kind !== "web_import" || site.evidence.occurrenceKind !== "import_type") continue;
    const key = `${site.evidence.relativePath}\0${site.evidence.startOffset}\0${site.evidence.endOffset}`;
    if (inlineImportsByEvidence.has(key)) {
      throw new DependencyContractError("raw inline import evidence is duplicated");
    }
    inlineImportsByEvidence.set(key, site);
  }
  for (const sites of inlineImportsByModule.values()) {
    sites.sort((left, right) => left.evidence.endOffset - right.evidence.endOffset);
  }
  const directBindingsByName = new Map<string, TypeScriptRawDependencySite[]>();
  for (const site of delta.sites) {
    if (!["default_import", "named_import", "namespace_import", "import_equals"].includes(site.evidence.occurrenceKind)) {
      continue;
    }
    const sourceText = sourceTexts.get(site.evidence.relativePath);
    const localName = sourceText === undefined
      ? null
      : identifierValueAt(sourceText, site.evidence.startOffset, site.evidence.endOffset);
    if (localName === null) continue;
    const key = JSON.stringify([site.evidence.relativePath, localName]);
    directBindingsByName.set(key, [...(directBindingsByName.get(key) ?? []), site]);
  }
  for (const site of delta.sites) {
    const attestationSourceLength = sourceLengths.get(site.evidence.relativePath);
    if (
      attestationSourceLength === undefined
      || !Number.isSafeInteger(site.evidence.startOffset)
      || !Number.isSafeInteger(site.evidence.endOffset)
      || site.evidence.startOffset < 0
      || site.evidence.endOffset <= site.evidence.startOffset
      || site.evidence.endOffset > attestationSourceLength
    ) throw new DependencyContractError("raw dependency evidence is invalid");
    if (
      site.resolutionMode !== null
      && site.resolutionMode !== "import"
      && site.resolutionMode !== "require"
    ) throw new DependencyContractError("raw dependency resolution mode is invalid");
    const safelyUnresolvedSyntax = site.status === "unresolved"
      && site.precision === "heuristic"
      && site.targets.length === 1
      && site.targets[0]?.kind === "unknown"
      && (
        site.reason === "syntax_invalid"
        || site.reason === "non_literal_module_specifier"
        || site.reason === "computed_module_specifier"
        || site.reason === "missing_module_specifier"
        || site.reason === "ambiguous_binding_provenance"
      );
    const parserValidity = sourceSyntaxValidity.get(site.evidence.relativePath);
    if (parserValidity === undefined) {
      throw new DependencyContractError("raw dependency evidence is invalid");
    }
    if (parserValidity === false) {
      if (!safelyUnresolvedSyntax || site.reason !== "syntax_invalid") {
        throw new DependencyContractError("raw dependency site contradicts parser-invalid source");
      }
      continue;
    }
    if (site.reason === "syntax_invalid") {
      throw new DependencyContractError("raw dependency site contradicts parser-valid source");
    }
    const sourceText = sourceTexts.get(site.evidence.relativePath);
    const tokens = validationTokensBySource.get(site.evidence.relativePath);
    if (sourceText === undefined || tokens === undefined) {
      throw new DependencyContractError("raw dependency source attestation context is missing");
    }
    const parserImportTypeSpans = importTypeModuleSpans.get(site.evidence.relativePath);
    if (parserImportTypeSpans === undefined) {
      throw new DependencyContractError("raw dependency import-type parser context is missing");
    }
    if (
      site.kind === "web_import"
      && (site.evidence.occurrenceKind === "import_type" || site.evidence.occurrenceKind === "dynamic_import")
    ) {
      const parserImportType = parserImportTypeSpans.has(`${site.evidence.startOffset}\0${site.evidence.endOffset}`);
      if (parserImportType !== (site.evidence.occurrenceKind === "import_type")) {
        throw new DependencyContractError("raw dependency import occurrence contradicts parser context");
      }
    }
    const parserNonLiteralModuleSpans = nonLiteralModuleSpans.get(site.evidence.relativePath);
    if (parserNonLiteralModuleSpans === undefined) {
      throw new DependencyContractError("raw dependency non-literal module parser context is missing");
    }
    const nonLiteralDescriptor = parserNonLiteralModuleSpans.get(
      `${site.evidence.startOffset}\0${site.evidence.endOffset}\0${site.kind}\0${site.evidence.occurrenceKind}`,
    );
    if (nonLiteralDescriptor !== undefined) {
      const expectedReason = nonLiteralDescriptor.resolutionModeError ?? "non_literal_module_specifier";
      if (
        site.reason === expectedReason
        && site.status === "unresolved"
        && site.precision === "heuristic"
        && site.targets.length === 1
        && site.targets[0]?.kind === "unknown"
        && site.evidence.targetBasis === "unresolved"
        && site.specifier === nonLiteralDescriptor.moduleSpecifier
        && site.moduleSpecifier === nonLiteralDescriptor.moduleSpecifier
        && site.importedName === nonLiteralDescriptor.importedName
        && site.exportPath === null
        && site.bindingKind === nonLiteralDescriptor.bindingKind
        && site.bindingOrigin === null
        && JSON.stringify(site.bindingScope) === JSON.stringify(nonLiteralDescriptor.bindingScope)
        && site.typeOnly === nonLiteralDescriptor.typeOnly
        && site.resolutionMode === nonLiteralDescriptor.resolutionMode
        && JSON.stringify(site.resolutionModeProof) === JSON.stringify(nonLiteralDescriptor.resolutionModeProof)
      ) continue;
    }
    const parserModuleCallSpans = moduleCallSpans.get(site.evidence.relativePath);
    if (parserModuleCallSpans === undefined) {
      throw new DependencyContractError("raw dependency module-call parser context is missing");
    }
    if (
      site.evidence.occurrenceKind === "require_call"
      || site.evidence.occurrenceKind === "dynamic_import"
    ) {
      const syntax = site.reason === "missing_module_specifier"
        ? "missing"
        : site.reason === "computed_module_specifier" ? "computed" : "literal";
      const key = `${site.evidence.startOffset}\0${site.evidence.endOffset}\0${site.evidence.occurrenceKind}\0${syntax}`;
      const expectedModuleSpecifier = parserModuleCallSpans.get(key);
      const syntaxReasonCorrelates = syntax === "computed"
        ? site.reason === "computed_module_specifier"
        : syntax === "missing"
          ? site.reason === "missing_module_specifier"
          : ![
            "computed_module_specifier",
            "missing_module_specifier",
            "non_literal_module_specifier",
            "ambiguous_binding_provenance",
            "syntax_invalid",
          ].includes(site.reason ?? "")
            && resolutionModeError(site.reason) === null;
      if (
        expectedModuleSpecifier === undefined
        || !syntaxReasonCorrelates
        || site.kind !== "web_import"
        || site.specifier !== expectedModuleSpecifier
        || site.moduleSpecifier !== expectedModuleSpecifier
        || site.importedName !== null
        || site.exportPath !== null
        || site.bindingKind !== null
        || site.bindingOrigin !== null
        || site.bindingScope !== null
        || site.typeOnly
        || site.resolutionMode !== null
        || site.resolutionModeProof !== null
      ) {
        throw new DependencyContractError("raw dependency module call contradicts parser context");
      }
      continue;
    }
    const parserTypeUseSpans = typeUseSpans.get(site.evidence.relativePath);
    if (parserTypeUseSpans === undefined) {
      throw new DependencyContractError("raw dependency type-use parser context is missing");
    }
    if (site.kind === "type_use") {
      const key = `${site.evidence.startOffset}\0${site.evidence.endOffset}\0${site.evidence.occurrenceKind}`;
      const descriptor = parserTypeUseSpans.get(key);
      if (
        descriptor === undefined
        || (site.bindingOrigin === null && site.importedName !== descriptor.terminalName)
      ) {
        throw new DependencyContractError(`raw dependency type-use occurrence contradicts parser context (${JSON.stringify([
          site.evidence.relativePath,
          site.evidence.startOffset,
          site.evidence.endOffset,
          site.evidence.occurrenceKind,
          site.specifier,
        ])})`);
      }
    }
    if (
      site.evidence.occurrenceKind === "import_type"
      && resolutionModeError(site.reason) !== null
      && unresolvedCallModuleSyntaxCorrelates(site, sourceText, tokens)
    ) continue;
    if (safelyUnresolvedSyntax) {
      const correlates = site.reason === "ambiguous_binding_provenance"
        ? site.kind === "web_reexport"
          ? ambiguousLocalReexportSyntaxCorrelates(site, tokens, directBindingsByName)
          : ambiguousTypeUseSyntaxCorrelates(site, sourceText, tokens, directBindingsByName)
        : unresolvedCallModuleSyntaxCorrelates(site, sourceText, tokens);
      if (!correlates) {
        throw new DependencyContractError("raw safely-unresolved dependency syntax does not correlate");
      }
      continue;
    }
    if (["default_import", "named_import", "namespace_import", "import_equals"].includes(site.evidence.occurrenceKind)) {
      if (!directBindingSyntaxCorrelates(site, sourceText, tokens)) {
        throw new DependencyContractError("raw dependency direct binding syntax does not correlate");
      }
      continue;
    }
    if (
      site.kind === "web_reexport"
      && ["named_reexport", "namespace_reexport"].includes(site.evidence.occurrenceKind)
    ) {
      if (!reexportSyntaxCorrelates(site, sourceText, tokens, sitesByKey)) {
        throw new DependencyContractError(`raw dependency re-export syntax does not correlate (${JSON.stringify([
          site.evidence.relativePath,
          site.evidence.startOffset,
          site.evidence.endOffset,
          site.evidence.occurrenceKind,
          site.moduleSpecifier,
          site.importedName,
          site.bindingKind,
          site.bindingOrigin,
        ])})`);
      }
      continue;
    }
    if (
      site.kind !== "type_use"
      && [
        "side_effect_import", "empty_import", "require_call", "dynamic_import", "import_type",
        "empty_reexport", "export_star",
      ].includes(site.evidence.occurrenceKind)
      && !moduleLiteralSyntaxCorrelates(site, sourceText, tokens)
    ) throw new DependencyContractError(`raw dependency module occurrence syntax does not correlate (${JSON.stringify([
      site.evidence.relativePath,
      site.evidence.startOffset,
      site.evidence.endOffset,
      site.evidence.occurrenceKind,
      site.moduleSpecifier,
      site.typeOnly,
      site.resolutionMode,
    ])})`);
  }
  let previousKey = "";
  for (const site of delta.sites) {
    if (!(site.kind === "web_import" || site.kind === "web_reexport" || site.kind === "type_use")) throw new DependencyContractError("raw dependency site kind is invalid");
    if (!(site.status === "resolved" || site.status === "candidates" || site.status === "external" || site.status === "unresolved")) throw new DependencyContractError("raw dependency status is invalid");
    if (!(site.precision === "exact" || site.precision === "overapprox" || site.precision === "heuristic")) throw new DependencyContractError("raw dependency precision is invalid");
    if (previousKey !== "" && compareStrings(previousKey, site.key) >= 0) throw new DependencyContractError("raw dependency sites are not strictly sorted");
    previousKey = site.key;
    const expectedEdge = site.kind === "web_import" ? "imports" : site.kind === "web_reexport" ? "reexports" : "type_uses";
    if (site.edgeKind !== expectedEdge) throw new DependencyContractError("raw dependency site/edge kind mapping is invalid");
    if (!occurrencesByKind.get(site.kind)?.has(site.evidence.occurrenceKind)) throw new DependencyContractError("raw dependency occurrence kind is invalid for its site kind");
    const preliminarySourceLength = sourceLengths.get(site.evidence.relativePath);
    if (
      preliminarySourceLength === undefined
      || !Number.isSafeInteger(site.evidence.startOffset)
      || !Number.isSafeInteger(site.evidence.endOffset)
      || site.evidence.startOffset < 0
      || site.evidence.endOffset <= site.evidence.startOffset
      || site.evidence.endOffset > preliminarySourceLength
    ) throw new DependencyContractError("raw dependency evidence is invalid");
    if (typeof site.typeOnly !== "boolean") throw new DependencyContractError("raw dependency type-only marker is invalid");
    if (
      site.resolutionMode !== null
      && site.resolutionMode !== "import"
      && site.resolutionMode !== "require"
    ) throw new DependencyContractError("raw dependency resolution mode is invalid");
    const resolutionModeProof = site.resolutionModeProof;
    const resolutionModeSource = sourceTexts.get(site.evidence.relativePath);
    if (site.resolutionMode === null) {
      if (resolutionModeProof !== null) {
        throw new DependencyContractError("raw dependency resolution mode proof contradicts its occurrence");
      }
    } else if (
      resolutionModeProof === null
      || typeof resolutionModeProof !== "object"
      || !Number.isSafeInteger(resolutionModeProof.keyStartOffset)
      || !Number.isSafeInteger(resolutionModeProof.keyEndOffset)
      || !Number.isSafeInteger(resolutionModeProof.valueStartOffset)
      || !Number.isSafeInteger(resolutionModeProof.valueEndOffset)
      || resolutionModeSource === undefined
      || !resolutionModeProofCorrelates(resolutionModeSource, site.resolutionMode, resolutionModeProof)
    ) throw new DependencyContractError("raw dependency resolution mode proof is invalid");
    if (site.resolutionMode !== null && (!site.typeOnly || site.moduleSpecifier === null)) {
      throw new DependencyContractError("raw dependency resolution mode contradicts its occurrence");
    }
    if (site.resolutionMode !== null && site.evidence.occurrenceKind === "import_equals") {
      throw new DependencyContractError("raw dependency import-equals occurrence cannot expose a resolution mode");
    }
    if (
      site.bindingKind !== null
      && !["default", "named", "namespace", "import_equals"].includes(site.bindingKind)
    ) throw new DependencyContractError("raw dependency binding kind is invalid");
    if (
      (site.evidence.occurrenceKind === "default_import" && site.bindingKind !== "default")
      || (site.evidence.occurrenceKind === "named_import" && site.bindingKind !== "named")
      || (namespaceBindingOccurrences.has(site.evidence.occurrenceKind) && site.bindingKind !== "namespace")
    ) throw new DependencyContractError("raw dependency occurrence binding kind is invalid");
    if (site.bindingKind === "import_equals" && site.resolutionMode !== null) {
      throw new DependencyContractError("raw dependency implicit import-equals mode became public");
    }
    if (
      site.bindingKind === "import_equals"
      && site.evidence.occurrenceKind !== "import_equals"
      && site.kind !== "type_use"
      && site.evidence.occurrenceKind !== "named_reexport"
    ) throw new DependencyContractError("raw dependency import-equals provenance shape is invalid");
    if (site.evidence.occurrenceKind === "import_equals" && site.bindingKind !== "import_equals") {
      throw new DependencyContractError("raw dependency import-equals provenance is missing");
    }
    const directBindingOccurrence = ["default_import", "named_import", "namespace_import", "import_equals"]
      .includes(site.evidence.occurrenceKind);
    const bindingScope = site.bindingScope;
    const bindingSourceLength = sourceLengths.get(site.evidence.relativePath);
    if (directBindingOccurrence) {
      if (
        bindingScope === null
        || typeof bindingScope !== "object"
        || !Number.isSafeInteger(bindingScope.startOffset)
        || !Number.isSafeInteger(bindingScope.endOffset)
        || bindingSourceLength === undefined
        || bindingScope.startOffset < 0
        || bindingScope.endOffset <= bindingScope.startOffset
        || bindingScope.endOffset > bindingSourceLength
        || bindingScope.startOffset > site.evidence.startOffset
        || bindingScope.endOffset < site.evidence.endOffset
      ) throw new DependencyContractError("raw dependency binding scope is invalid");
    } else if (bindingScope !== null) {
      throw new DependencyContractError("raw dependency binding scope contradicts its occurrence");
    }
    const bindingOrigin = site.bindingOrigin;
    if (bindingOrigin !== null && (
      typeof bindingOrigin !== "object"
      || typeof bindingOrigin.siteKey !== "string"
      || !Number.isSafeInteger(bindingOrigin.declarationStartOffset)
      || !Number.isSafeInteger(bindingOrigin.declarationEndOffset)
      || !Number.isSafeInteger(bindingOrigin.scopeStartOffset)
      || !Number.isSafeInteger(bindingOrigin.scopeEndOffset)
      || !Number.isSafeInteger(bindingOrigin.referenceStartOffset)
      || !Number.isSafeInteger(bindingOrigin.referenceEndOffset)
    )) throw new DependencyContractError("raw dependency binding origin is invalid");
    const sourceTextForBinding = sourceTexts.get(site.evidence.relativePath);
    const typeUseDescriptor = site.kind === "type_use"
      ? typeUseSpans.get(site.evidence.relativePath)?.get(
        `${site.evidence.startOffset}\0${site.evidence.endOffset}\0${site.evidence.occurrenceKind}`,
      )
      : undefined;
    const parserInlineImportOrigin = typeUseDescriptor?.inlineImportModuleStartOffset === null
      || typeUseDescriptor?.inlineImportModuleStartOffset === undefined
      || typeUseDescriptor.inlineImportModuleEndOffset === null
      ? undefined
      : inlineImportsByEvidence.get(
        `${site.evidence.relativePath}\0${typeUseDescriptor.inlineImportModuleStartOffset}\0${typeUseDescriptor.inlineImportModuleEndOffset}`,
      );
    if (
      typeUseDescriptor?.inlineImportModuleStartOffset !== null
      && typeUseDescriptor?.inlineImportModuleStartOffset !== undefined
      && parserInlineImportOrigin === undefined
    ) throw new DependencyContractError("raw dependency inline import parser origin is missing");
    const inlineImportOrigin = site.kind === "type_use"
      && site.moduleSpecifier !== null
      && bindingOrigin === null
      && sourceTextForBinding !== undefined
      ? [...(inlineImportsByModule.get(JSON.stringify([
        site.evidence.relativePath,
        site.moduleSpecifier,
      ])) ?? [])].reverse().find((origin) => (
        origin.evidence.endOffset <= site.evidence.startOffset
        && inlineImportReferenceCorrelates(site, origin, sourceTextForBinding)
      ))
      : undefined;
    if (parserInlineImportOrigin !== undefined && (
      bindingOrigin !== null
      || site.resolutionMode !== parserInlineImportOrigin.resolutionMode
      || JSON.stringify(site.resolutionModeProof) !== JSON.stringify(parserInlineImportOrigin.resolutionModeProof)
      || resolutionModeError(site.reason) !== resolutionModeError(parserInlineImportOrigin.reason)
      || (
        site.moduleSpecifier === null
          ? site.bindingKind !== null || site.exportPath !== null
          : site.moduleSpecifier !== parserInlineImportOrigin.moduleSpecifier
      )
    )) throw new DependencyContractError("raw dependency parser-confirmed inline import origin does not correlate");
    if (inlineImportOrigin !== undefined && (
      site.bindingKind !== "named"
      || site.resolutionMode !== inlineImportOrigin.resolutionMode
      || JSON.stringify(site.resolutionModeProof) !== JSON.stringify(inlineImportOrigin.resolutionModeProof)
      || resolutionModeError(site.reason) !== resolutionModeError(inlineImportOrigin.reason)
    )) throw new DependencyContractError("raw dependency inline import origin does not correlate");
    const importedTypeUseRequiresOrigin = site.kind === "type_use"
      && site.moduleSpecifier !== null
      && site.reason !== "ambiguous_binding_provenance"
      && site.reason !== "syntax_invalid"
      && inlineImportOrigin === undefined;
    if (importedTypeUseRequiresOrigin && bindingOrigin === null) {
      throw new DependencyContractError("raw dependency imported binding origin is missing");
    }
    if (
      site.kind === "type_use"
      && bindingOrigin === null
      && inlineImportOrigin === undefined
      && parserInlineImportOrigin === undefined
      && resolutionModeError(site.reason) !== null
    ) throw new DependencyContractError("raw dependency type-use resolution mode error has no syntax origin");
    if (bindingOrigin !== null) {
      const origin = sitesByKey.get(bindingOrigin.siteKey);
      const sourceText = sourceTexts.get(site.evidence.relativePath);
      const referenceName = sourceText === undefined
        ? null
        : identifierValueAt(
          sourceText,
          bindingOrigin.referenceStartOffset,
          bindingOrigin.referenceEndOffset,
        );
      const visibleOrigins = referenceName === null
        ? []
        : (directBindingsByName.get(JSON.stringify([site.evidence.relativePath, referenceName])) ?? [])
          .filter((candidate) => (
            candidate.bindingScope !== null
            && typeof candidate.bindingScope === "object"
            && candidate.bindingScope.startOffset <= bindingOrigin.referenceStartOffset
            && candidate.bindingScope.endOffset >= bindingOrigin.referenceEndOffset
          ));
      const nearestScopeLength = visibleOrigins.reduce((length, candidate) => (
        candidate.bindingScope === null
          ? length
          : Math.min(length, candidate.bindingScope.endOffset - candidate.bindingScope.startOffset)
      ), Number.POSITIVE_INFINITY);
      const nearestOrigins = visibleOrigins.filter((candidate) => (
        candidate.bindingScope !== null
        && candidate.bindingScope.endOffset - candidate.bindingScope.startOffset === nearestScopeLength
      ));
      if (
        origin === undefined
        || sourceText === undefined
        || referenceName === null
        || nearestOrigins.length !== 1
        || nearestOrigins[0]?.key !== origin.key
        || (
          site.kind !== "type_use"
          && site.evidence.occurrenceKind !== "named_reexport"
          && site.evidence.occurrenceKind !== "namespace_reexport"
        )
        || site.bindingKind === null
        || origin.bindingKind !== site.bindingKind
        || !originOccurrences.get(site.bindingKind)?.has(origin.evidence.occurrenceKind)
        || origin.evidence.relativePath !== site.evidence.relativePath
        || origin.moduleSpecifier !== site.moduleSpecifier
        || origin.evidence.startOffset !== bindingOrigin.declarationStartOffset
        || origin.evidence.endOffset !== bindingOrigin.declarationEndOffset
        || origin.bindingScope === null
        || origin.bindingScope.startOffset !== bindingOrigin.scopeStartOffset
        || origin.bindingScope.endOffset !== bindingOrigin.scopeEndOffset
        || bindingOrigin.declarationStartOffset < 0
        || bindingOrigin.declarationEndOffset <= bindingOrigin.declarationStartOffset
        || bindingOrigin.scopeStartOffset < 0
        || bindingOrigin.scopeEndOffset <= bindingOrigin.scopeStartOffset
        || bindingOrigin.scopeStartOffset > bindingOrigin.declarationStartOffset
        || bindingOrigin.scopeEndOffset < bindingOrigin.declarationEndOffset
        || bindingOrigin.referenceStartOffset < 0
        || bindingOrigin.referenceEndOffset <= bindingOrigin.referenceStartOffset
        || bindingOrigin.declarationEndOffset > sourceText.length
        || bindingOrigin.scopeEndOffset > sourceText.length
        || bindingOrigin.scopeStartOffset > bindingOrigin.referenceStartOffset
        || bindingOrigin.scopeEndOffset < bindingOrigin.referenceEndOffset
        || bindingOrigin.referenceEndOffset > sourceText.length
        || bindingOrigin.referenceStartOffset > site.evidence.startOffset
        || bindingOrigin.referenceEndOffset > site.evidence.endOffset
        || (site.kind === "web_reexport" && origin.typeOnly && !site.typeOnly)
        || site.resolutionMode !== origin.resolutionMode
        || JSON.stringify(site.resolutionModeProof) !== JSON.stringify(origin.resolutionModeProof)
        || resolutionModeError(site.reason) !== resolutionModeError(origin.reason)
        || !bindingReferenceCorrelates(site, origin, sourceText, bindingOrigin)
      ) throw new DependencyContractError(
        `raw dependency binding origin does not correlate (${JSON.stringify({
          site: [site.evidence.relativePath, site.evidence.startOffset, site.evidence.occurrenceKind, site.bindingKind, site.resolutionMode, site.exportPath],
          origin: origin === undefined ? null : [origin.evidence.startOffset, origin.evidence.occurrenceKind, origin.bindingKind, origin.resolutionMode, origin.importedName],
          bindingOrigin,
          referenceCorrelates: origin === undefined || sourceText === undefined
            ? false
            : bindingReferenceCorrelates(site, origin, sourceText, bindingOrigin),
        })})`,
      );
    } else if (site.bindingKind === "import_equals" && site.evidence.occurrenceKind !== "import_equals") {
      throw new DependencyContractError("raw dependency import-equals origin is missing");
    }
    if (
      ((site.kind === "type_use" || site.evidence.occurrenceKind === "import_type") && !site.typeOnly)
      || (["side_effect_import", "require_call", "dynamic_import"].includes(site.evidence.occurrenceKind) && site.typeOnly)
    ) throw new DependencyContractError("raw dependency type-only marker contradicts its occurrence");
    const exportPath = Array.isArray(site.exportPath) ? site.exportPath : null;
    const emptyBindingRoot = exportPath?.length === 0
      && site.moduleSpecifier !== null
      && (
        (site.importedName === "=" && site.resolutionMode === null && (
          site.kind === "type_use" || site.evidence.occurrenceKind === "named_reexport"
        ) && site.bindingKind === "import_equals")
        || (site.kind === "type_use" && site.importedName === "*" && site.bindingKind === "namespace")
      );
    const emptyModuleExportName = exportPath?.length === 1
      && exportPath[0] === ""
      && site.importedName === ""
      && namedBindingOccurrences.has(site.evidence.occurrenceKind);
    const emptyExportAliasTypeUse = exportPath?.length === 1
      && exportPath[0] === ""
      && site.kind === "type_use"
      && site.importedName !== null
      && site.importedName.length > 0;
    const emptyModuleSpecifier = site.moduleSpecifier === ""
      && site.kind !== "type_use"
      && site.specifier === "";
    if (
      (site.specifier.length === 0 && !emptyModuleSpecifier)
      || site.specifier.length > MAX_SPECIFIER_CHARS
      || hasUnpairedSurrogate(site.specifier)
    ) throw new DependencyContractError("raw dependency specifier is invalid");
    if (
      (site.moduleSpecifier !== null && (
        typeof site.moduleSpecifier !== "string"
        || site.moduleSpecifier.length > MAX_SPECIFIER_CHARS
        || hasUnpairedSurrogate(site.moduleSpecifier)
      ))
      || (site.importedName !== null && (
        typeof site.importedName !== "string"
        || (site.importedName.length === 0 && !emptyModuleExportName)
        || site.importedName.length > 512
        || hasUnpairedSurrogate(site.importedName)
      ))
    ) throw new DependencyContractError("raw dependency binding metadata is invalid");
    if (
      (site.kind === "type_use" && site.specifier !== site.importedName)
      || (site.kind !== "type_use" && site.specifier !== site.moduleSpecifier)
    ) throw new DependencyContractError("raw dependency protocol specifier disagrees with its occurrence metadata");
    if (site.exportPath !== null && (
      !Array.isArray(site.exportPath)
      || (site.exportPath.length === 0 && !emptyBindingRoot)
      || site.exportPath.length > MAX_EXPORT_PATH_DEPTH
      || site.exportPath.some((part) => (
        (part.length === 0 && !emptyModuleExportName && !emptyExportAliasTypeUse)
        || part.length > 512
        || hasUnpairedSurrogate(part)
      ))
      || (site.exportPath.length > 0
        && site.exportPath.at(-1) !== site.importedName
        && !emptyExportAliasTypeUse)
    )) throw new DependencyContractError("raw dependency export path is invalid");
    if (
      (site.kind !== "type_use" && site.moduleSpecifier === null)
      || (site.kind === "type_use" && site.importedName === null)
      || (namedBindingOccurrences.has(site.evidence.occurrenceKind) && site.importedName === null)
      || (namedBindingOccurrences.has(site.evidence.occurrenceKind) && site.exportPath === null)
      || (namespaceBindingOccurrences.has(site.evidence.occurrenceKind) && site.importedName !== "*")
      || (moduleOnlyOccurrences.has(site.evidence.occurrenceKind) && site.importedName !== null)
      || (moduleOnlyOccurrences.has(site.evidence.occurrenceKind) && site.exportPath !== null)
      || (site.evidence.occurrenceKind === "default_import" && site.importedName !== "default")
      || (site.evidence.occurrenceKind === "import_equals" && site.importedName !== "=")
      || (site.moduleSpecifier === null && site.exportPath !== null)
      || (site.kind === "type_use" && site.moduleSpecifier !== null && site.exportPath === null)
    ) throw new DependencyContractError("raw dependency occurrence metadata shape is invalid");
    const sourceLength = sourceLengths.get(site.evidence.relativePath);
    if (
      sourceLength === undefined
      || !Number.isSafeInteger(site.evidence.startOffset)
      || !Number.isSafeInteger(site.evidence.endOffset)
      || site.evidence.startOffset < 0
      || site.evidence.endOffset <= site.evidence.startOffset
      || site.evidence.endOffset > sourceLength
      || site.evidence.detail.length === 0
      || site.evidence.detail.length > MAX_SPECIFIER_CHARS
      || hasUnpairedSurrogate(site.evidence.detail)
    ) throw new DependencyContractError("raw dependency evidence is invalid");
    let sourcePath: string;
    if (site.kind !== "type_use" && site.source.kind !== "file") {
      throw new DependencyContractError("raw import or re-export source is not its evidence file");
    }
    if (site.source.kind === "file") {
      sourcePath = site.source.relativePath;
      if (!isCanonicalRelativePath(sourcePath)) throw new DependencyContractError("raw dependency file source path is not canonical");
      if (!sourceLengths.has(sourcePath)) throw new DependencyContractError("raw dependency file source is missing");
    } else if (site.source.kind === "definition") {
      const definition = definitions.get(site.source.key);
      if (definition === undefined) throw new DependencyContractError("raw dependency definition source is missing");
      sourcePath = definition.relativePath;
    } else {
      throw new DependencyContractError("raw dependency source kind is invalid");
    }
    if (sourcePath !== site.evidence.relativePath) throw new DependencyContractError("raw dependency source and evidence paths disagree");
    const expectedKey = siteKey(site.source, site.kind, site.evidence.relativePath, site.evidence.startOffset, site.evidence.endOffset);
    if (site.key !== expectedKey) throw new DependencyContractError("raw dependency site key is not canonical");
    if (site.targets.length === 0) throw new DependencyContractError("raw dependency site has no targets");
    if (!Array.isArray(site.targetConditions) || site.targetConditions.length !== site.targets.length) {
      throw new DependencyContractError("raw dependency target conditions do not align with targets");
    }
    validateCanonicalRawCondition(site.condition);
    for (const condition of site.targetConditions) validateCanonicalRawCondition(condition);
    if (JSON.stringify(site.condition) !== JSON.stringify(aggregateConditions(site.targetConditions))) {
      throw new DependencyContractError("raw dependency site condition is not the aggregate of its target conditions");
    }
    let previousTarget = "";
    for (const target of site.targets) {
      const targetKey = targetSortKey(target);
      if (previousTarget !== "" && compareStrings(previousTarget, targetKey) >= 0) throw new DependencyContractError("raw dependency targets are not strictly sorted");
      previousTarget = targetKey;
      if (target.kind === "definition") {
        const definition = definitions.get(target.key);
        if (definition === undefined) throw new DependencyContractError("raw dependency target definition is missing");
        if (site.kind === "type_use" && definition.graphKind !== "type") throw new DependencyContractError("raw type-use target is not a type");
      } else if (target.kind === "file") {
        if (!isCanonicalRelativePath(target.relativePath)) throw new DependencyContractError("raw dependency target file path is not canonical");
        if (!sourceLengths.has(target.relativePath)) throw new DependencyContractError("raw dependency target file is missing");
        if (!moduleLevelOccurrences.has(site.evidence.occurrenceKind)) throw new DependencyContractError("raw named binding target cannot fall back to a file");
      } else if (target.kind === "external") {
        if (
          target.locator.length === 0
          || target.locator.length > MAX_SPECIFIER_CHARS
          || target.displayName.length === 0
          || target.displayName.length > MAX_SPECIFIER_CHARS
          || hasUnpairedSurrogate(target.locator)
          || hasUnpairedSurrogate(target.displayName)
        ) throw new DependencyContractError("raw external target identity is invalid");
      } else if (target.kind !== "unknown") {
        throw new DependencyContractError("raw dependency target kind is invalid");
      }
    }
    const kinds = new Set(site.targets.map((target) => target.kind));
    if (kinds.size > 1) throw new DependencyContractError("raw dependency target kinds are incompatible");
    if (
      (site.status === "resolved" && (site.precision !== "exact" || site.targets.length !== 1 || kinds.has("external") || kinds.has("unknown")))
      || (site.status === "resolved" && site.reason !== null)
      || (site.status === "candidates" && (site.precision !== "overapprox" || kinds.has("external") || kinds.has("unknown")))
      || (site.status === "external" && (site.targets.length !== 1 || !kinds.has("external") || (site.precision !== "exact" && site.precision !== "heuristic")))
      || (site.status === "external" && site.precision === "exact" && site.reason !== null)
      || (site.status === "unresolved" && (site.precision !== "heuristic" || site.targets.length !== 1 || !kinds.has("unknown") || !site.reason))
      || (site.status === "external" && site.precision === "heuristic" && !site.reason)
    ) throw new DependencyContractError("raw dependency status/precision/target contract is invalid");
    if (site.reason !== null && (site.reason.length === 0 || site.reason.length > MAX_SPECIFIER_CHARS || hasUnpairedSurrogate(site.reason))) {
      throw new DependencyContractError("raw dependency reason is invalid");
    }
    const expectedBasis = basisForTargets(site.targets);
    if (site.evidence.targetBasis !== expectedBasis) throw new DependencyContractError("raw dependency target basis is invalid");
  }

  const seenCallSpans = new Set<string>();
  let previousCallKey = "";
  for (const call of delta.calls) {
    if (previousCallKey !== "" && compareStrings(previousCallKey, call.key) >= 0) {
      throw new DependencyContractError("raw call sites are not strictly sorted");
    }
    previousCallKey = call.key;
    const sourceLength = sourceLengths.get(call.evidence.relativePath);
    if (
      sourceLength === undefined
      || !Number.isSafeInteger(call.evidence.startOffset)
      || !Number.isSafeInteger(call.evidence.endOffset)
      || call.evidence.startOffset < 0
      || call.evidence.endOffset <= call.evidence.startOffset
      || call.evidence.endOffset > sourceLength
      || call.evidence.detail.length === 0
      || call.evidence.detail.length > MAX_SPECIFIER_CHARS
      || hasUnpairedSurrogate(call.evidence.detail)
      || !["call_expression", "new_expression", "tagged_template"].includes(call.evidence.occurrenceKind)
    ) throw new DependencyContractError("raw call evidence is invalid");
    const validationKey = `${call.evidence.startOffset}\0${call.evidence.endOffset}\0${call.evidence.occurrenceKind}`;
    const validationSpan = callSpans.get(call.evidence.relativePath)?.get(validationKey);
    if (validationSpan === undefined || validationSpan.specifier !== call.specifier) {
      throw new DependencyContractError("raw call site does not correlate with its parser occurrence");
    }
    const globalValidationKey = `${call.evidence.relativePath}\0${validationKey}`;
    if (!seenCallSpans.add(globalValidationKey)) {
      throw new DependencyContractError("raw call occurrence is duplicated");
    }
    if (
      call.specifier.length === 0
      || call.specifier.length > MAX_SPECIFIER_CHARS
      || hasUnpairedSurrogate(call.specifier)
      || !["function", "method", "constructor", "tagged_template"].includes(call.callKind)
      || !["direct", "static", "private", "fresh_instance", "super", "external", "dynamic", "open"].includes(call.dispatch)
      || (call.evidence.occurrenceKind === "new_expression" && call.callKind !== "constructor")
      || (call.evidence.occurrenceKind === "tagged_template" && call.callKind !== "tagged_template")
      || (call.moduleSpecifier !== null && (
        call.moduleSpecifier.length === 0
        || call.moduleSpecifier.length > MAX_SPECIFIER_CHARS
        || hasUnpairedSurrogate(call.moduleSpecifier)
      ))
    ) throw new DependencyContractError("raw call metadata is invalid");
    let sourcePath: string;
    if (call.source.kind === "definition") {
      const source = definitions.get(call.source.key);
      if (
        source === undefined
        || source.graphKind !== "symbol"
        || ![
          "function",
          "method",
          "constructor",
          "anonymous_function",
          "local_function",
        ].includes(source.semanticKind)
      ) {
        throw new DependencyContractError("raw call caller is not a canonical symbol definition");
      }
      sourcePath = source.relativePath;
    } else if (call.source.kind === "module_initializer") {
      sourcePath = call.source.relativePath;
      if (!isCanonicalRelativePath(sourcePath) || !sourceLengths.has(sourcePath)) {
        throw new DependencyContractError("raw call module initializer source is invalid");
      }
    } else {
      throw new DependencyContractError("raw call source kind is invalid");
    }
    if (sourcePath !== call.evidence.relativePath) {
      throw new DependencyContractError("raw call caller and evidence paths disagree");
    }
    const expectedKey = siteKey(call.source, "call", call.evidence.relativePath, call.evidence.startOffset, call.evidence.endOffset);
    if (call.key !== expectedKey) throw new DependencyContractError("raw call site key is not canonical");
    if (call.targets.length === 0 || call.targetConditions.length !== call.targets.length) {
      throw new DependencyContractError("raw call site has no target or unaligned target conditions");
    }
    validateCanonicalRawCondition(call.condition);
    for (const targetCondition of call.targetConditions) {
      validateCanonicalRawCondition(targetCondition);
      if (JSON.stringify(call.condition) !== JSON.stringify(targetCondition)) {
        throw new DependencyContractError("raw call site and target conditions disagree");
      }
    }
    for (const target of call.targets) {
      if (target.kind === "definition") {
        const definition = definitions.get(target.key);
        if (
          definition === undefined
          || definition.graphKind !== "symbol"
          || ![
            "function",
            "local_function",
            "anonymous_function",
            "method",
            "constructor",
          ].includes(definition.semanticKind)
        ) throw new DependencyContractError("raw call target is not a canonical callable symbol");
      } else if (target.kind === "external") {
        if (
          target.locator.length === 0
          || target.locator.length > MAX_SPECIFIER_CHARS
          || target.displayName.length === 0
          || target.displayName.length > MAX_SPECIFIER_CHARS
          || hasUnpairedSurrogate(target.locator)
          || hasUnpairedSurrogate(target.displayName)
        ) throw new DependencyContractError("raw call external target is invalid");
      } else if (target.kind !== "unknown") {
        throw new DependencyContractError("raw call target kind is invalid");
      }
    }
    const targetKinds = new Set(call.targets.map((target) => target.kind));
    const targetKeys = call.targets.map(targetSortKey);
    if (targetKeys.some((key, index) => index > 0 && targetKeys[index - 1]! >= key)) {
      throw new DependencyContractError("raw call targets are not unique and canonical-sorted");
    }
    if (
      (!["resolved", "candidates", "external", "unresolved"].includes(call.status)
        || !["exact", "overapprox", "heuristic"].includes(call.precision))
      || (call.status === "resolved" && (
        call.precision !== "exact"
        || call.reason !== null
        || call.algorithm !== null
        || call.targets.length !== 1
        || !targetKinds.has("definition")
        || !["direct", "static", "private", "fresh_instance", "super"].includes(call.dispatch)
      ))
      || (call.status === "candidates" && (
        call.precision !== "overapprox"
        || call.reason !== null
        || typeof call.algorithm !== "string"
        || call.algorithm.length === 0
        || call.algorithm.length > MAX_SPECIFIER_CHARS
        || hasUnpairedSurrogate(call.algorithm)
        || targetKinds.size !== 1
        || !targetKinds.has("definition")
        || !["dynamic", "fresh_instance"].includes(call.dispatch)
        || call.evidence.occurrenceKind === "new_expression"
        || (call.dispatch === "dynamic" && (
          call.algorithm !== TYPESCRIPT_CLOSED_LOCAL_CALL_FLOW_ALGORITHM
        ))
        || (call.dispatch === "fresh_instance" && (
          call.algorithm !== TYPESCRIPT_CLOSED_LOCAL_FRESH_INSTANCE_FLOW_ALGORITHM
          || !["method", "tagged_template"].includes(call.callKind)
          || !["call_expression", "tagged_template"].includes(call.evidence.occurrenceKind)
          || call.targets.some((target) => (
            target.kind !== "definition" || definitions.get(target.key)?.semanticKind !== "method"
          ))
        ))
      ))
      || (call.status === "external" && (
        call.algorithm !== null
        || call.targets.length !== 1
        || !targetKinds.has("external")
        || call.dispatch !== "external"
        || (call.precision !== "exact" && call.precision !== "heuristic")
        || (call.precision === "exact" ? call.reason !== null : !call.reason)
      ))
      || (call.status === "unresolved" && (
        call.algorithm !== null
        || call.targets.length !== 1
        || !targetKinds.has("unknown")
        || call.precision !== "heuristic"
        || !call.reason
        || !["dynamic", "open"].includes(call.dispatch)
      ))
    ) throw new DependencyContractError("raw call status/precision/target contract is invalid");
    if (call.reason !== null && (
      call.reason.length === 0
      || call.reason.length > MAX_SPECIFIER_CHARS
      || hasUnpairedSurrogate(call.reason)
    )) throw new DependencyContractError("raw call reason is invalid");
    if (call.evidence.targetBasis !== basisForTargets(call.targets)) {
      throw new DependencyContractError("raw call target basis is invalid");
    }
  }
  for (const [relativePath, spans] of callSpans) {
    for (const key of spans.keys()) {
      if (!seenCallSpans.has(`${relativePath}\0${key}`)) {
        throw new DependencyContractError("parser-confirmed call occurrence is missing from the raw ledger");
      }
    }
  }
}
