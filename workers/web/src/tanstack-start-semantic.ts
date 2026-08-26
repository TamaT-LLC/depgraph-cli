import path from "node:path";
import {
  SyntaxKind,
  isArrayLiteralExpression,
  isCallExpression,
  isIdentifier,
  isImportDeclaration,
  isNamedImports,
  isNoSubstitutionTemplateLiteral,
  isObjectLiteralExpression,
  isParenthesizedExpression,
  isPropertyAccessExpression,
  isPropertyAssignment,
  isShorthandPropertyAssignment,
  isStringLiteral,
  isVariableStatement,
  NodeFlags,
  type CallExpression,
  type Expression,
  type Node,
  type ObjectLiteralExpression,
  type SourceFile,
} from "typescript/unstable/ast";
import {
  WEB_FRAMEWORK_SEMANTIC_CAPABILITY,
  WEB_FRAMEWORK_SEMANTIC_EXTRACTOR_VERSION,
  emitFrameworkSemanticRelation,
  type FrameworkSemanticDelta,
} from "./framework-semantic";
import { stableId } from "./ids";
import type { RouteEntry } from "./routes";
import { collectTanStackRouterSemanticDelta } from "./tanstack-router-semantic";
import type { TypeScriptRawDefinition, TypeScriptRawDefinitionDelta } from "./typescript-semantic";
import type { TypeScriptRawDependencyDelta } from "./typescript-dependencies";
import {
  canonicalizeCondition,
  compareUtf8,
  preferredWebEnvironment,
  PROFILE_ID,
  type Condition,
  type Diagnostic,
  type Evidence,
  type GraphNode,
  type JsonValue,
  type ResolutionStatus,
} from "./types";
import type { PackageRecord } from "./workspace";

const FRAMEWORK = "tanstack-start" as const;
const EXTRACTOR = "tanstack-start-static-adapter";
const START_MODULES = new Set(["@tanstack/react-start", "@tanstack/start"]);
const ROUTER_MODULES = new Set(["@tanstack/react-router", "@tanstack/router-core"]);

type Span = {
  start_line: number;
  start_column: number;
  end_line: number;
  end_column: number;
};

interface ImportBinding {
  local: string;
  imported: string;
  moduleSpecifier: string;
  node: Node;
}

interface ChainStep {
  name: string;
  call: CallExpression;
  arguments: readonly Expression[];
}

interface ServerFunctionDeclaration {
  name: string;
  relativePath: string;
  declaration: Node;
  factoryCall: CallExpression;
  definition: TypeScriptRawDefinition | null;
  symbol: GraphNode | null;
  sourceSymbol: GraphNode | null;
  exported: boolean;
  method: string;
  handler: Expression | null;
  validator: Expression | null;
  middleware: Array<{ name: string; node: Node }>;
  node: GraphNode;
}

interface MiddlewareDeclaration {
  name: string;
  relativePath: string;
  declaration: Node;
  definition: TypeScriptRawDefinition | null;
  symbol: GraphNode | null;
  exported: boolean;
  scope: string;
  handler: Expression | null;
  node: GraphNode;
}

export interface TanStackStartSemanticInput {
  entries: readonly RouteEntry[];
  sources: ReadonlyMap<string, string>;
  sourceFiles: ReadonlyMap<string, SourceFile>;
  definitions: TypeScriptRawDefinitionDelta;
  dependencies: TypeScriptRawDependencyDelta;
  definitionNode(key: string): GraphNode | null;
  fileNode(relativePath: string): GraphNode | null;
  ownerForPath(relativePath: string): PackageRecord;
  unknownTarget(): GraphNode;
}

export interface TanStackStartSemanticResult {
  delta: FrameworkSemanticDelta;
  diagnostics: Array<Omit<Diagnostic, "id">>;
}

function position(source: string, offset: number): { line: number; column: number } {
  const lines = source.slice(0, Math.max(0, Math.min(source.length, offset))).split(/\r?\n/u);
  return { line: lines.length, column: (lines.at(-1)?.length ?? 0) + 1 };
}

function spanFor(source: string, node: Node): Span {
  const start = position(source, node.getStart());
  const end = position(source, node.getEnd());
  return { start_line: start.line, start_column: start.column, end_line: end.line, end_column: end.column };
}

function evidence(
  relativePath: string,
  span: Span,
  occurrenceKind: string,
  properties: Record<string, JsonValue> = {},
): Evidence[] {
  const common = {
    extractor: EXTRACTOR,
    extractor_version: WEB_FRAMEWORK_SEMANTIC_EXTRACTOR_VERSION,
    path: relativePath,
    ...span,
  };
  const shared: Record<string, JsonValue> = {
    profile_id: PROFILE_ID,
    framework: FRAMEWORK,
    occurrence_kind: occurrenceKind,
    ...properties,
  };
  return [
    { kind: "semantic", ...common, properties: { ...shared, contract_version: WEB_FRAMEWORK_SEMANTIC_CAPABILITY } },
    { kind: "source", ...common, properties: shared },
  ];
}

function visit(node: Node, action: (node: Node) => void): void {
  action(node);
  node.forEachChild((child) => visit(child, action));
}

function unwrap(expression: Expression): Expression {
  let current = expression;
  while (isParenthesizedExpression(current)) current = current.expression;
  return current;
}

function literal(expression: Expression | null | undefined): string | null {
  if (!expression) return null;
  const value = unwrap(expression);
  return isStringLiteral(value) || isNoSubstitutionTemplateLiteral(value) ? value.text : null;
}

function propertyName(node: Node): string | null {
  return isIdentifier(node) || isStringLiteral(node) || isNoSubstitutionTemplateLiteral(node) ? node.text : null;
}

function propertyExpression(object: ObjectLiteralExpression | null, name: string): Expression | null {
  if (!object) return null;
  for (const item of object.properties) {
    if (!isPropertyAssignment(item) && !isShorthandPropertyAssignment(item)) continue;
    if (propertyName(item.name) !== name) continue;
    if (isPropertyAssignment(item)) return item.initializer;
    if (isShorthandPropertyAssignment(item) && isIdentifier(item.name)) return item.name;
  }
  return null;
}

function importBindings(sourceFile: SourceFile, modules: ReadonlySet<string>): ImportBinding[] {
  const result: ImportBinding[] = [];
  for (const statement of sourceFile.statements) {
    if (!isImportDeclaration(statement) || !isStringLiteral(statement.moduleSpecifier)
      || !modules.has(statement.moduleSpecifier.text)) continue;
    const named = statement.importClause?.namedBindings;
    if (!named || !isNamedImports(named)) continue;
    for (const element of named.elements) result.push({
      local: element.name.text,
      imported: element.propertyName?.text ?? element.name.text,
      moduleSpecifier: statement.moduleSpecifier.text,
      node: element,
    });
  }
  return result;
}

function allImportBindings(sourceFile: SourceFile): ImportBinding[] {
  const result: ImportBinding[] = [];
  for (const statement of sourceFile.statements) {
    if (!isImportDeclaration(statement) || !isStringLiteral(statement.moduleSpecifier)) continue;
    const named = statement.importClause?.namedBindings;
    if (!named || !isNamedImports(named)) continue;
    for (const element of named.elements) result.push({
      local: element.name.text,
      imported: element.propertyName?.text ?? element.name.text,
      moduleSpecifier: statement.moduleSpecifier.text,
      node: element,
    });
  }
  return result;
}

function callChain(call: CallExpression, factoryBindings: ReadonlyMap<string, string>): {
  factory: string;
  factoryCall: CallExpression;
  steps: ChainStep[];
} | null {
  const steps: ChainStep[] = [];
  let current = call;
  while (isPropertyAccessExpression(current.expression)) {
    steps.unshift({ name: current.expression.name.text, call: current, arguments: current.arguments });
    const receiver = unwrap(current.expression.expression);
    if (!isCallExpression(receiver)) return null;
    current = receiver;
  }
  if (isCallExpression(current.expression)) {
    steps.push({ name: "configure", call: current, arguments: current.arguments });
    current = current.expression;
  }
  if (!isIdentifier(current.expression)) return null;
  const factory = factoryBindings.get(current.expression.text);
  return factory ? { factory, factoryCall: current, steps } : null;
}

function identifierText(expression: Expression | null): string | null {
  if (!expression) return null;
  const value = unwrap(expression);
  return isIdentifier(value) ? value.text : null;
}

function hasModifier(node: Node, kind: SyntaxKind): boolean {
  const modifiers = (node as Node & { readonly modifiers?: readonly Node[] }).modifiers;
  return modifiers?.some((modifier) => modifier.kind === kind) ?? false;
}

function condition(environment: "server" | "browser", properties: Record<string, string> = {}): Condition {
  return canonicalizeCondition({
    op: "all",
    conditions: [
      { op: "eq", key: "mode", value: "production" },
      { op: "eq", key: "environment", value: preferredWebEnvironment(environment) },
      ...Object.entries(properties).map(([key, value]) => ({ op: "eq" as const, key, value })),
    ],
  });
}

function serverFunctionNode(
  owner: PackageRecord,
  symbol: GraphNode | null,
  relativePath: string,
  name: string,
  method: string,
  handler: GraphNode | null,
  validator: GraphNode | null,
): GraphNode | null {
  const semanticResolver = symbol?.properties.resolver_identity;
  const resolverIdentity = typeof semanticResolver === "string" && semanticResolver.length > 0
    ? semanticResolver
    : `tanstack-start-static:${JSON.stringify([owner.locator, relativePath, name, "server-function"])}`;
  const environment = preferredWebEnvironment("server");
  const serverFunctionKind = "tanstack-start-server-function";
  const canonicalIdentity: Record<string, JsonValue> = {
    framework: FRAMEWORK,
    package_locator: owner.locator,
    server_function_kind: serverFunctionKind,
    environment,
    resolver_identity: resolverIdentity,
  };
  const id = stableId("server_function", canonicalIdentity);
  return {
    id,
    kind: "server_function",
    locator: `server-function://tanstack-start/${encodeURIComponent(owner.locator)}/${id}`,
    display_name: name,
    properties: {
      framework: FRAMEWORK,
      package_locator: owner.locator,
      server_function_kind: serverFunctionKind,
      environment,
      profile_id: PROFILE_ID,
      canonical_identity: canonicalIdentity,
      resolver_identity: resolverIdentity,
      source_path: relativePath,
      source_span: symbol?.properties.source_span ?? null,
      typescript_definition_id: symbol?.id ?? null,
      static_definition_identity: symbol === null,
      http_method: method,
      handler_definition_id: handler?.id ?? null,
      validator_definition_id: validator?.id ?? null,
      production_rpc_id: null,
      production_rpc_id_status: "build-unobserved",
      build_boundary_reason: "tanstack_start_internal_virtual_module_unobserved",
    },
  };
}

function middlewareNode(
  owner: PackageRecord,
  symbol: GraphNode | null,
  relativePath: string,
  name: string,
  scope: string,
  handler: GraphNode | null,
): GraphNode | null {
  const semanticResolver = symbol?.properties.resolver_identity;
  const resolverIdentity = typeof semanticResolver === "string" && semanticResolver.length > 0
    ? semanticResolver
    : `tanstack-start-static:${JSON.stringify([owner.locator, relativePath, name, "middleware", scope])}`;
  const environment = preferredWebEnvironment("server");
  const middlewareKind = `tanstack-start-${scope}-middleware`;
  const canonicalIdentity: Record<string, JsonValue> = {
    framework: FRAMEWORK,
    package_locator: owner.locator,
    middleware_kind: middlewareKind,
    environment,
    resolver_identity: resolverIdentity,
    scope,
  };
  const id = stableId("middleware", canonicalIdentity);
  return {
    id,
    kind: "middleware",
    locator: `middleware://tanstack-start/${encodeURIComponent(owner.locator)}/${id}`,
    display_name: name,
    properties: {
      framework: FRAMEWORK,
      package_locator: owner.locator,
      middleware_kind: middlewareKind,
      environment,
      profile_id: PROFILE_ID,
      canonical_identity: canonicalIdentity,
      resolver_identity: resolverIdentity,
      scope,
      source_path: relativePath,
      source_span: symbol?.properties.source_span ?? null,
      typescript_definition_id: symbol?.id ?? null,
      static_definition_identity: symbol === null,
      handler_definition_id: handler?.id ?? null,
    },
  };
}

function breakoutMiddlewareNode(owner: PackageRecord, relativePath: string, layout: string): GraphNode {
  const environment = preferredWebEnvironment("server");
  const scope = `route:${relativePath}`;
  const resolverIdentity = `${owner.locator}#${relativePath}#middleware-breakout:${layout}`;
  const middlewareKind = "tanstack-start-middleware-breakout";
  const canonicalIdentity: Record<string, JsonValue> = {
    framework: FRAMEWORK,
    package_locator: owner.locator,
    middleware_kind: middlewareKind,
    environment,
    resolver_identity: resolverIdentity,
    scope,
  };
  const id = stableId("middleware", canonicalIdentity);
  return {
    id,
    kind: "middleware",
    locator: `middleware://tanstack-start/${encodeURIComponent(owner.locator)}/${id}`,
    display_name: `middleware-breakout:${layout}`,
    properties: {
      framework: FRAMEWORK,
      package_locator: owner.locator,
      middleware_kind: middlewareKind,
      environment,
      profile_id: PROFILE_ID,
      canonical_identity: canonicalIdentity,
      resolver_identity: resolverIdentity,
      scope,
      source_path: relativePath,
      inherited_from: layout,
      middleware_inheritance: "break-out",
    },
  };
}

function resolveRelativeModule(
  fromPath: string,
  specifier: string,
  sources: ReadonlyMap<string, string>,
): string | null {
  if (!specifier.startsWith(".")) return null;
  const base = path.posix.normalize(path.posix.join(path.posix.dirname(fromPath), specifier));
  const candidates = [
    base,
    ...[".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs"].map((extension) => `${base}${extension}`),
    ...[".ts", ".tsx", ".js", ".jsx"].map((extension) => `${base}/index${extension}`),
  ];
  return candidates.find((candidate) => sources.has(candidate)) ?? null;
}

function targetsSupportedMajor(range: string): boolean {
  const versionPattern = "v?\\d+(?:\\.(?:\\d+|x|\\*)){0,2}(?:-[0-9A-Za-z.-]+)?";
  const parseAlternative = (value: string): Array<{ operator: string | null; version: string }> | null => {
    const normalized = value
      .replace(/^([~^=])\s+/u, "$1")
      .replace(/(>=|<=|>|<)\s+/gu, "$1")
      .trim();
    const simple = normalized.match(new RegExp(`^([~^=])?(${versionPattern})$`, "iu"));
    if (simple?.[2]) return [{ operator: simple[1] ?? null, version: simple[2] }];
    const hyphen = normalized.match(new RegExp(`^(${versionPattern})\\s+-\\s+(${versionPattern})$`, "iu"));
    if (hyphen?.[1] && hyphen[2]) return [
      { operator: null, version: hyphen[1] },
      { operator: null, version: hyphen[2] },
    ];
    const comparators = normalized.split(/[\s,]+/u).filter(Boolean).map((part) => (
      part.match(new RegExp(`^(>=|<=|>|<)(${versionPattern})$`, "iu"))
    ));
    if (comparators.length === 0 || comparators.some((token) => !token?.[1] || !token[2])) return null;
    return comparators.map((token) => ({ operator: token![1]!, version: token![2]! }));
  };
  const alternatives = range.trim().split("||").map((value) => value.trim()).filter(Boolean);
  if (alternatives.length === 0) return false;
  return alternatives.every((alternative) => {
    const tokens = parseAlternative(alternative);
    if (!tokens) return false;
    let includesVersionOne = false;
    for (const token of tokens) {
      const version = token.version.replace(/^v/iu, "");
      const major = Number(version.match(/^\d+/u)?.[0]);
      if (major === 1) {
        includesVersionOne = true;
        continue;
      }
      const exclusiveVersionTwoUpperBound = major === 2
        && token.operator === "<"
        && /^2(?:\.0){0,2}$/u.test(version);
      if (!exclusiveVersionTwoUpperBound) return false;
    }
    return includesVersionOne;
  });
}

function supportedVersion(owner: PackageRecord): boolean {
  const range = owner.dependencies.get("@tanstack/react-start")?.range
    ?? owner.dependencies.get("@tanstack/start")?.range;
  return typeof range === "string" && targetsSupportedMajor(range);
}

export function collectTanStackStartSemanticDelta(
  input: TanStackStartSemanticInput,
): TanStackStartSemanticResult {
  const routeResult = collectTanStackRouterSemanticDelta(input);
  const nodes = new Map(routeResult.delta.nodes.map((node) => [node.id, node]));
  const sites = new Map(routeResult.delta.sites.map((site) => [site.id, site]));
  const edges = new Map(routeResult.delta.edges.map((edge) => [edge.id, edge]));
  const diagnostics = [...routeResult.diagnostics];
  const addNode = (node: GraphNode): GraphNode => {
    const existing = nodes.get(node.id);
    if (existing && JSON.stringify(existing) !== JSON.stringify(node)) throw new Error(`TanStack Start collector produced conflicting node ${node.id}`);
    nodes.set(node.id, existing ?? node);
    return existing ?? node;
  };
  const addDiagnostic = (diagnostic: Omit<Diagnostic, "id">): void => {
    if (!diagnostics.some((item) => item.code === diagnostic.code && item.path === diagnostic.path && item.message === diagnostic.message)) diagnostics.push(diagnostic);
  };
  const addRelation = (
    source: GraphNode,
    targetsValue: readonly GraphNode[],
    kind: string,
    specifier: string,
    relativePath: string,
    span: Span,
    relationCondition: Condition,
    environment: "server" | "browser",
    occurrenceKind: string,
    status: ResolutionStatus = "resolved",
    reason: string | null = null,
    algorithm: string | null = null,
    properties: Record<string, JsonValue> = {},
  ): void => {
    const relationEvidence = evidence(relativePath, span, occurrenceKind, { ...properties, ...(algorithm ? { algorithm } : {}) });
    emitFrameworkSemanticRelation(
      { sites, edges },
      {
        source, targets: targetsValue, kind, specifier, relativePath, span,
        condition: relationCondition, environment: preferredWebEnvironment(environment),
        profileId: PROFILE_ID, resolutionStatus: status, precision: null, reason,
        evidence: relationEvidence, generated: false,
      },
      { conflictSubject: "TanStack Start collector", emptyTargetSubject: "TanStack Start relation" },
    );
  };

  const definitionsByPath = new Map<string, TypeScriptRawDefinition[]>();
  for (const definition of input.definitions.definitions) {
    if (definition.graphKind !== "symbol") continue;
    const values = definitionsByPath.get(definition.relativePath) ?? [];
    values.push(definition);
    definitionsByPath.set(definition.relativePath, values);
  }
  const definitionNamed = (relativePath: string, name: string): TypeScriptRawDefinition | null => (
    (definitionsByPath.get(relativePath) ?? [])
      .filter((definition) => definition.displayName === name)
      .sort((left, right) => (left.endOffset - left.startOffset) - (right.endOffset - right.startOffset) || compareUtf8(left.key, right.key))[0] ?? null
  );
  const containingDefinition = (relativePath: string, node: Node): TypeScriptRawDefinition | null => {
    const sourceFile = input.sourceFiles.get(relativePath);
    if (!sourceFile) return null;
    const start = node.getStart(sourceFile);
    const end = node.getEnd();
    return (definitionsByPath.get(relativePath) ?? [])
      .filter((definition) => definition.startOffset <= start && definition.endOffset >= end)
      .sort((left, right) => (left.endOffset - left.startOffset) - (right.endOffset - right.startOffset) || compareUtf8(left.key, right.key))[0] ?? null;
  };
  const moduleInitializerFor = (relativePath: string): GraphNode | null => {
    const definition = (definitionsByPath.get(relativePath) ?? []).find((candidate) => (
      candidate.semanticKind === "generated_module_initializer"
      || candidate.displayName.endsWith(" module initializer")
    ));
    return definition ? input.definitionNode(definition.key) : null;
  };

  const owners = new Map(input.entries.map((entry) => {
    const owner = input.ownerForPath(entry.relativeFile);
    return [owner.locator, owner];
  }));
  for (const owner of owners.values()) {
    if (supportedVersion(owner)) continue;
    addDiagnostic({
      severity: "warning",
      code: "web.tanstack_start_version_unsupported",
      message: `TanStack Start server-function semantics are unsupported for declared version ${owner.dependencies.get("@tanstack/react-start")?.range ?? owner.dependencies.get("@tanstack/start")?.range ?? "unknown"}`,
      path: owner.manifestPath,
      profile_id: PROFILE_ID,
      properties: { framework_semantic_issue: true },
    });
  }
  const supportedOwners = new Set([...owners.values()].filter(supportedVersion).map((owner) => owner.locator));

  const serverFunctions = new Map<string, ServerFunctionDeclaration>();
  const middleware = new Map<string, MiddlewareDeclaration>();
  const middlewareBySymbolName = new Map<string, MiddlewareDeclaration[]>();
  for (const [relativePath, sourceFile] of input.sourceFiles) {
    const owner = input.ownerForPath(relativePath);
    if (!supportedOwners.has(owner.locator)) continue;
    const bindings = new Map(importBindings(sourceFile, START_MODULES).map((binding) => [binding.local, binding.imported]));
    if (![...bindings.values()].some((value) => value === "createServerFn" || value === "createMiddleware")) continue;
    const source = input.sources.get(relativePath) ?? "";
    for (const statement of sourceFile.statements) {
      if (!isVariableStatement(statement)) continue;
      for (const declaration of statement.declarationList.declarations) {
        if (!isIdentifier(declaration.name) || !declaration.initializer || !isCallExpression(declaration.initializer)) continue;
        const chain = callChain(declaration.initializer, bindings);
        if (!chain || (chain.factory !== "createServerFn" && chain.factory !== "createMiddleware")) continue;
        if ((((statement.declarationList as Node & { readonly flags: number }).flags) & NodeFlags.Const) === 0) {
          addDiagnostic({
            severity: "warning",
            code: "web.tanstack_start_mutable_declaration_unsupported",
            message: `TanStack Start ${chain.factory} declaration ${declaration.name.text} is mutable and was not promoted to a canonical semantic node`,
            path: relativePath,
            profile_id: PROFILE_ID,
            evidence: evidence(relativePath, spanFor(source, declaration), "tanstack_start_mutable_declaration_unsupported"),
            properties: { framework_semantic_issue: true },
          });
          continue;
        }
        const definition = definitionNamed(relativePath, declaration.name.text);
        const symbol = definition ? input.definitionNode(definition.key) : null;
        const exported = hasModifier(statement, SyntaxKind.ExportKeyword);
        const factoryOptions = chain.factoryCall.arguments[0];
        const options = factoryOptions && isObjectLiteralExpression(factoryOptions) ? factoryOptions : null;
        if (chain.factory === "createMiddleware") {
          const serverStep = chain.steps.find((step) => step.name === "server");
          const handlerExpression = serverStep?.arguments[0] ?? null;
          const handlerName = identifierText(handlerExpression);
          const handlerDefinition = handlerName
            ? definitionNamed(relativePath, handlerName)
            : handlerExpression ? containingDefinition(relativePath, handlerExpression) : null;
          const handler = handlerDefinition ? input.definitionNode(handlerDefinition.key) : null;
          const scope = literal(propertyExpression(options, "type")) ?? "function";
          const semanticNode = middlewareNode(owner, symbol, relativePath, declaration.name.text, scope, handler);
          if (!semanticNode) continue;
          const item: MiddlewareDeclaration = {
            name: declaration.name.text,
            relativePath,
            declaration,
            definition,
            symbol,
            exported,
            scope,
            handler: handlerExpression,
            node: addNode(semanticNode),
          };
          middleware.set(`${relativePath}\0${item.name}`, item);
          const byName = middlewareBySymbolName.get(item.name) ?? [];
          byName.push(item);
          middlewareBySymbolName.set(item.name, byName);
          continue;
        }
        const handlerStep = chain.steps.find((step) => step.name === "handler");
        const validatorStep = chain.steps.find((step) => step.name === "validator" || step.name === "inputValidator");
        const middlewareStep = chain.steps.find((step) => step.name === "middleware");
        const handlerExpression = handlerStep?.arguments[0] ?? null;
        const validatorExpression = validatorStep?.arguments[0] ?? null;
        const handlerName = identifierText(handlerExpression);
        const validatorName = identifierText(validatorExpression);
        const handlerDefinition = handlerName
          ? definitionNamed(relativePath, handlerName)
          : handlerExpression ? containingDefinition(relativePath, handlerExpression) : null;
        const validatorDefinition = validatorName
          ? definitionNamed(relativePath, validatorName)
          : validatorExpression ? containingDefinition(relativePath, validatorExpression) : null;
        const handler = handlerDefinition ? input.definitionNode(handlerDefinition.key) : null;
        const validator = validatorDefinition ? input.definitionNode(validatorDefinition.key) : null;
        const method = (literal(propertyExpression(options, "method")) ?? "GET").toUpperCase();
        const semanticNode = serverFunctionNode(owner, symbol, relativePath, declaration.name.text, method, handler, validator);
        if (!semanticNode) continue;
        const middlewareReferences: ServerFunctionDeclaration["middleware"] = [];
        const middlewareArgument = middlewareStep?.arguments[0];
        if (middlewareArgument && isArrayLiteralExpression(middlewareArgument)) {
          for (const item of middlewareArgument.elements) if (isIdentifier(item)) middlewareReferences.push({ name: item.text, node: item });
        }
        const item: ServerFunctionDeclaration = {
          name: declaration.name.text,
          relativePath,
          declaration,
          factoryCall: chain.factoryCall,
          definition,
          symbol,
          sourceSymbol: symbol ?? moduleInitializerFor(relativePath),
          exported,
          method,
          handler: handlerExpression,
          validator: validatorExpression,
          middleware: middlewareReferences,
          node: addNode(semanticNode),
        };
        serverFunctions.set(`${relativePath}\0${item.name}`, item);
      }
    }
  }

  const exportedProofs = new Map(input.dependencies.moduleExports.map((proof) => [
    JSON.stringify([proof.relativePath, proof.exportPath]),
    new Set(proof.definitionKeys),
  ]));
  const serverFunctionForImport = (fromPath: string, binding: ImportBinding): ServerFunctionDeclaration | null => {
    const targetPath = resolveRelativeModule(fromPath, binding.moduleSpecifier, input.sources);
    if (!targetPath) return null;
    const candidate = serverFunctions.get(`${targetPath}\0${binding.imported}`);
    if (!candidate) return null;
    const proof = exportedProofs.get(JSON.stringify([targetPath, [binding.imported]]));
    return candidate.definition ? proof?.has(candidate.definition.key) ? candidate : null : candidate.exported ? candidate : null;
  };
  const middlewareForImport = (fromPath: string, binding: ImportBinding): MiddlewareDeclaration | null => {
    const targetPath = resolveRelativeModule(fromPath, binding.moduleSpecifier, input.sources);
    if (!targetPath) return null;
    const candidate = middleware.get(`${targetPath}\0${binding.imported}`);
    if (!candidate) return null;
    const proof = exportedProofs.get(JSON.stringify([targetPath, [binding.imported]]));
    return candidate.definition ? proof?.has(candidate.definition.key) ? candidate : null : candidate.exported ? candidate : null;
  };

  for (const serverFunction of serverFunctions.values()) {
    const source = input.sources.get(serverFunction.relativePath) ?? "";
    const importedMiddleware = new Map<string, MiddlewareDeclaration>();
    const sourceFile = input.sourceFiles.get(serverFunction.relativePath);
    if (sourceFile) for (const binding of allImportBindings(sourceFile)) {
      const target = middlewareForImport(serverFunction.relativePath, binding);
      if (target) importedMiddleware.set(binding.local, target);
    }
    if (serverFunction.handler) {
      const handlerName = identifierText(serverFunction.handler);
      const handlerDefinition = handlerName
        ? definitionNamed(serverFunction.relativePath, handlerName)
        : containingDefinition(serverFunction.relativePath, serverFunction.handler);
      const handler = handlerDefinition ? input.definitionNode(handlerDefinition.key) : null;
      addRelation(
        serverFunction.node,
        [handler ?? input.unknownTarget()],
        "handled_by",
        handler?.display_name ?? "<unresolved-handler>",
        serverFunction.relativePath,
        spanFor(source, serverFunction.handler),
        condition("server", { "tanstack.start.handler": "server-function" }),
        "server",
        "tanstack_start_server_handler",
        handler ? "resolved" : "unresolved",
        handler ? null : "tanstack_start_handler_definition_unresolved",
      );
    }
    for (const reference of serverFunction.middleware) {
      const target = middleware.get(`${serverFunction.relativePath}\0${reference.name}`)
        ?? middlewareBySymbolName.get(reference.name)?.find((item) => item.relativePath === serverFunction.relativePath)
        ?? importedMiddleware.get(reference.name);
      if (!target) {
        addDiagnostic({
          severity: "warning",
          code: "web.tanstack_start_middleware_unresolved",
          message: `TanStack Start handler middleware ${reference.name} could not be correlated to an immutable createMiddleware declaration`,
          path: serverFunction.relativePath,
          profile_id: PROFILE_ID,
          evidence: evidence(serverFunction.relativePath, spanFor(source, reference.node), "tanstack_start_handler_middleware_unresolved"),
          properties: { framework_semantic_issue: true },
        });
        continue;
      }
      addRelation(
        serverFunction.node,
        [target.node],
        "uses_middleware",
        reference.name,
        serverFunction.relativePath,
        spanFor(source, reference.node),
        condition("server", { "tanstack.start.middleware_scope": "handler" }),
        "server",
        "tanstack_start_handler_middleware",
      );
    }
    if (serverFunction.sourceSymbol) addRelation(
      serverFunction.sourceSymbol,
      [input.unknownTarget()],
      "client_stub_for",
      serverFunction.name,
      serverFunction.relativePath,
      spanFor(source, serverFunction.factoryCall),
      condition("browser", { "tanstack.start.rpc_id": "build-unobserved" }),
      "browser",
      "tanstack_start_build_stub_unobserved",
      "unresolved",
      "tanstack_start_internal_virtual_module_unobserved",
    );
    addDiagnostic({
      severity: "info",
      code: "web.tanstack_start_build_rpc_id_unobserved",
      message: `Production RPC ID and internal virtual client stub for ${serverFunction.name} require build evidence and were not guessed during safe scan`,
      path: serverFunction.relativePath,
      profile_id: PROFILE_ID,
      evidence: evidence(serverFunction.relativePath, spanFor(source, serverFunction.factoryCall), "tanstack_start_build_stub_unobserved"),
      properties: { framework_semantic_issue: true },
    });
  }

  const routeNodesByPath = new Map<string, GraphNode[]>();
  const componentsByDefinitionId = new Map<string, GraphNode>();
  for (const node of nodes.values()) {
    if (node.properties.framework !== FRAMEWORK) continue;
    const sourcePath = node.properties.source_path;
    if (typeof sourcePath === "string" && node.kind === "route") {
      const values = routeNodesByPath.get(sourcePath) ?? [];
      values.push(node);
      routeNodesByPath.set(sourcePath, values);
    }
    if (node.kind === "component" && typeof node.properties.typescript_definition_id === "string") {
      componentsByDefinitionId.set(node.properties.typescript_definition_id, node);
    }
  }

  for (const [relativePath, sourceFile] of input.sourceFiles) {
    const owner = input.ownerForPath(relativePath);
    if (!supportedOwners.has(owner.locator)) continue;
    const bindings = allImportBindings(sourceFile);
    const rpcBindings = new Map<string, ServerFunctionDeclaration>();
    const middlewareBindings = new Map<string, MiddlewareDeclaration>();
    for (const binding of bindings) {
      const serverFunction = serverFunctionForImport(relativePath, binding);
      if (serverFunction) rpcBindings.set(binding.local, serverFunction);
      const middlewareValue = middlewareForImport(relativePath, binding);
      if (middlewareValue) middlewareBindings.set(binding.local, middlewareValue);
    }
    for (const serverFunction of serverFunctions.values()) if (serverFunction.relativePath === relativePath) rpcBindings.set(serverFunction.name, serverFunction);
    for (const middlewareValue of middleware.values()) if (middlewareValue.relativePath === relativePath) middlewareBindings.set(middlewareValue.name, middlewareValue);
    const source = input.sources.get(relativePath) ?? "";

    visit(sourceFile, (node) => {
      if (!isCallExpression(node) || !isIdentifier(node.expression)) return;
      const target = rpcBindings.get(node.expression.text);
      if (!target) return;
      const definition = containingDefinition(relativePath, node);
      const symbol = definition ? input.definitionNode(definition.key) : null;
      const component = symbol ? componentsByDefinitionId.get(symbol.id) : null;
      const route = routeNodesByPath.get(relativePath)?.sort((left, right) => compareUtf8(left.id, right.id))[0] ?? null;
      const sourceNode = component ?? route ?? symbol;
      if (!sourceNode) return;
      addRelation(
        sourceNode,
        [target.node],
        "rpc_call",
        node.expression.text,
        relativePath,
        spanFor(source, node),
        condition("browser", { "tanstack.start.rpc": "client-call" }),
        "browser",
        "tanstack_start_client_rpc_call",
      );
    });

    const routerBindings = new Map(importBindings(sourceFile, ROUTER_MODULES).map((binding) => [binding.local, binding.imported]));
    for (const statement of sourceFile.statements) {
      if (!isVariableStatement(statement)) continue;
      for (const declaration of statement.declarationList.declarations) {
        if (!isIdentifier(declaration.name) || !declaration.initializer || !isCallExpression(declaration.initializer)) continue;
        const chain = callChain(declaration.initializer, routerBindings);
        if (!chain || !["createFileRoute", "createRootRoute", "createRootRouteWithContext"].includes(chain.factory)) continue;
        const optionsExpression = chain.factory === "createRootRoute"
          ? chain.factoryCall.arguments[0]
          : chain.steps.at(-1)?.arguments[0];
        const options = optionsExpression && isObjectLiteralExpression(optionsExpression) ? optionsExpression : null;
        const server = propertyExpression(options, "server");
        const serverOptions = server && isObjectLiteralExpression(server) ? server : null;
        const middlewareExpression = propertyExpression(serverOptions, "middleware");
        if (!middlewareExpression || !isArrayLiteralExpression(middlewareExpression)) continue;
        const route = routeNodesByPath.get(relativePath)?.sort((left, right) => compareUtf8(left.id, right.id))[0];
        if (!route) continue;
        for (const item of middlewareExpression.elements) {
          if (!isIdentifier(item)) continue;
          const target = middlewareBindings.get(item.text);
          if (!target) {
            addDiagnostic({
              severity: "warning",
              code: "web.tanstack_start_middleware_unresolved",
              message: `TanStack Start route middleware ${item.text} could not be correlated to an immutable createMiddleware declaration`,
              path: relativePath,
              profile_id: PROFILE_ID,
              evidence: evidence(relativePath, spanFor(source, item), "tanstack_start_route_middleware_unresolved"),
              properties: { framework_semantic_issue: true },
            });
            continue;
          }
          addRelation(
            route,
            [target.node],
            "uses_middleware",
            item.text,
            relativePath,
            spanFor(source, item),
            condition("server", { "tanstack.start.middleware_scope": "route-direct" }),
            "server",
            "tanstack_start_route_middleware",
          );
        }
      }
    }
  }

  const routeRecords = [...routeNodesByPath].flatMap(([relativePath, routeNodes]) => routeNodes.map((node) => ({ relativePath, node })));
  const directMiddlewareByPath = new Map<string, Array<{
    declaration: MiddlewareDeclaration;
    span: Span;
  }>>();
  for (const site of sites.values()) {
    if (site.kind !== "uses_middleware" || site.evidence[0]?.properties?.framework !== FRAMEWORK
      || site.evidence[0]?.properties?.occurrence_kind !== "tanstack_start_route_middleware") continue;
    const target = nodes.get(site.target_ids[0] ?? "");
    if (!target) continue;
    const declaration = [...middleware.values()].find((item) => item.node.id === target.id);
    if (!declaration) continue;
    const primary = site.evidence[0]!;
    const values = directMiddlewareByPath.get(site.evidence[0]!.path) ?? [];
    values.push({
      declaration,
      span: {
        start_line: primary.start_line!,
        start_column: primary.start_column!,
        end_line: primary.end_line!,
        end_column: primary.end_column!,
      },
    });
    directMiddlewareByPath.set(site.evidence[0]!.path, values);
  }
  const rootRoutes = routeRecords.filter((record) => record.node.properties.route_pattern === "/");
  for (const record of routeRecords) {
    const source = input.sources.get(record.relativePath) ?? "";
    const sourceFile = input.sourceFiles.get(record.relativePath);
    const anchor = sourceFile ?? null;
    if (!anchor) continue;
    const recordOwner = input.ownerForPath(record.relativePath).locator;
    const recordDirectory = path.posix.dirname(record.relativePath);
    for (const root of rootRoutes) {
      if (root.relativePath === record.relativePath || root.node.properties.package_locator !== record.node.properties.package_locator) continue;
      for (const inherited of directMiddlewareByPath.get(root.relativePath) ?? []) addRelation(
        record.node,
        [inherited.declaration.node],
        "uses_middleware",
        inherited.declaration.name,
        root.relativePath,
        inherited.span,
        condition("server", { "tanstack.start.middleware_scope": "route-inherited-root" }),
        "server",
        "tanstack_start_inherited_root_middleware",
      );
    }
    const basename = path.posix.basename(record.relativePath).replace(/\.[^.]+$/u, "");
    const breakout = basename.match(/^(_[^.]+_)\./u)?.[1] ?? null;
    if (breakout) {
      const layout = breakout.slice(0, -1);
      const owner = input.ownerForPath(record.relativePath);
      const boundary = addNode(breakoutMiddlewareNode(owner, record.relativePath, layout));
      addRelation(
        record.node,
        [boundary],
        "uses_middleware",
        layout,
        record.relativePath,
        spanFor(source, anchor),
        condition("server", { "tanstack.start.middleware_inheritance": "break-out" }),
        "server",
        "tanstack_start_middleware_breakout",
      );
      continue;
    }
    for (const [layoutPath, inheritedMiddleware] of directMiddlewareByPath) {
      if (input.ownerForPath(layoutPath).locator !== recordOwner
        || path.posix.dirname(layoutPath) !== recordDirectory) continue;
      const layoutStem = path.posix.basename(layoutPath).replace(/\.[^.]+$/u, "");
      if (!layoutStem.startsWith("_") || layoutStem.endsWith("_") || !basename.startsWith(`${layoutStem}.`)) continue;
      for (const inherited of inheritedMiddleware) addRelation(
        record.node,
        [inherited.declaration.node],
        "uses_middleware",
        inherited.declaration.name,
        layoutPath,
        inherited.span,
        condition("server", { "tanstack.start.middleware_scope": "route-inherited-pathless", "tanstack.start.pathless_layout": layoutStem }),
        "server",
        "tanstack_start_inherited_pathless_middleware",
      );
    }
  }

  diagnostics.sort((left, right) => compareUtf8(`${left.path ?? ""}\0${left.code}\0${left.message}`, `${right.path ?? ""}\0${right.code}\0${right.message}`));
  return {
    delta: {
      nodes: [...nodes.values()].sort((left, right) => compareUtf8(left.id, right.id)),
      sites: [...sites.values()].sort((left, right) => compareUtf8(left.id, right.id)),
      edges: [...edges.values()].sort((left, right) => compareUtf8(left.id, right.id)),
    },
    diagnostics,
  };
}
