import path from "node:path";
import {
  isArrayLiteralExpression,
  isArrowFunction,
  isCallExpression,
  isConditionalExpression,
  isFunctionExpression,
  isIdentifier,
  isImportDeclaration,
  isJsxAttribute,
  isJsxElement,
  isJsxExpression,
  isJsxOpeningElement,
  isJsxSelfClosingElement,
  isNamedImports,
  isNoSubstitutionTemplateLiteral,
  isObjectLiteralExpression,
  isParenthesizedExpression,
  isPropertyAccessExpression,
  isPropertyAssignment,
  isReturnStatement,
  isShorthandPropertyAssignment,
  isStringLiteral,
  isVariableDeclaration,
  isVariableStatement,
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
import type { TypeScriptRawDefinitionDelta } from "./typescript-semantic";
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
  type ResolutionStatus,
} from "./types";
import type { PackageRecord } from "./workspace";

type TanStackRouteFramework = "tanstack-router" | "tanstack-start";
const ROUTER_MODULES = new Set(["@tanstack/react-router", "@tanstack/router-core"]);
const FACTORIES = new Set([
  "createRootRoute", "createRootRouteWithContext", "createRoute",
  "createFileRoute", "createLazyFileRoute",
]);

type Span = {
  start_line: number;
  start_column: number;
  end_line: number;
  end_column: number;
};

interface RouteDeclaration {
  name: string;
  relativePath: string;
  sourceFile: SourceFile;
  node: Node;
  call: CallExpression;
  factory: string;
  kind: "root" | "code" | "file" | "lazy-file";
  literalPath: string | null;
  parentName: string | null;
  parentNode: Node | null;
  options: ObjectLiteralExpression | null;
}

interface Registration {
  parentName: string;
  childName: string | null;
  childCandidates: string[];
  relativePath: string;
  node: Node;
  status: "resolved" | "candidates" | "unresolved";
  reason: string | null;
}

interface SemanticRoute {
  node: GraphNode;
  relativePath: string;
  declaration: RouteDeclaration | null;
  entry: RouteEntry | null;
  pattern: string;
}

export interface TanStackRouterSemanticInput {
  entries: readonly RouteEntry[];
  sources: ReadonlyMap<string, string>;
  sourceFiles: ReadonlyMap<string, SourceFile>;
  definitions: TypeScriptRawDefinitionDelta;
  definitionNode(key: string): GraphNode | null;
  fileNode(relativePath: string): GraphNode | null;
  ownerForPath(relativePath: string): PackageRecord;
  unknownTarget(): GraphNode;
}

export interface TanStackRouterSemanticResult {
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
  return {
    start_line: start.line,
    start_column: start.column,
    end_line: end.line,
    end_column: end.column,
  };
}

function evidence(
  framework: TanStackRouteFramework,
  relativePath: string,
  span: Span,
  occurrenceKind: string,
  properties: Record<string, JsonValue> = {},
): Evidence[] {
  const common = {
    extractor: `${framework}-static-adapter`,
    extractor_version: WEB_FRAMEWORK_SEMANTIC_EXTRACTOR_VERSION,
    path: relativePath,
    ...span,
  };
  const shared: Record<string, JsonValue> = {
    profile_id: PROFILE_ID,
    framework,
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
  if (isIdentifier(node) || isStringLiteral(node) || isNoSubstitutionTemplateLiteral(node)) return node.text;
  return null;
}

function property(object: ObjectLiteralExpression | null, name: string): Node | null {
  if (!object) return null;
  for (const item of object.properties) {
    if (!isPropertyAssignment(item) && !isShorthandPropertyAssignment(item)) continue;
    if (propertyName(item.name) === name) return item;
  }
  return null;
}

function propertyExpression(object: ObjectLiteralExpression | null, name: string): Expression | null {
  const item = property(object, name);
  if (!item) return null;
  if (isPropertyAssignment(item)) return item.initializer;
  return isShorthandPropertyAssignment(item) && isIdentifier(item.name) ? item.name : null;
}

function returnedIdentifier(expression: Expression | null): { name: string; node: Node } | null {
  if (!expression) return null;
  const value = unwrap(expression);
  if (isIdentifier(value)) return { name: value.text, node: value };
  if (!isArrowFunction(value) && !isFunctionExpression(value)) return null;
  if (isIdentifier(value.body)) return { name: value.body.text, node: value.body };
  if (isParenthesizedExpression(value.body) && isIdentifier(unwrap(value.body))) {
    const identifier = unwrap(value.body);
    return isIdentifier(identifier) ? { name: identifier.text, node: identifier } : null;
  }
  if ("statements" in value.body) {
    for (const statement of value.body.statements) {
      if (isReturnStatement(statement) && statement.expression) {
        const returned = unwrap(statement.expression);
        if (isIdentifier(returned)) return { name: returned.text, node: returned };
      }
    }
  }
  return null;
}

function normalizeUrl(value: string): string {
  const normalized = `/${value}`.replace(/\/{2,}/gu, "/").replace(/\/$/u, "");
  return normalized === "" ? "/" : normalized;
}

function joinUrl(parent: string, child: string): string {
  if (child.startsWith("/")) return normalizeUrl(child);
  return normalizeUrl(`${parent}/${child}`);
}

function basePath(sources: ReadonlyMap<string, string>, packagePrefix: string): string {
  for (const [relativePath, source] of sources) {
    if (packagePrefix !== "." && relativePath !== packagePrefix && !relativePath.startsWith(`${packagePrefix}/`)) continue;
    const matched = [...source.matchAll(/\bbase[Pp]ath\s*:\s*(["'`])([^"'`\\]*)\1/gu)].at(-1)?.[2];
    if (matched !== undefined) return normalizeUrl(matched);
  }
  return "/";
}

function withBase(base: string, pattern: string): string {
  const normalized = normalizeUrl(pattern);
  if (base === "/") return normalized;
  return normalized === "/" ? base : normalizeUrl(`${base}/${normalized}`);
}

function importBindings(sourceFile: SourceFile): Map<string, string> {
  const bindings = new Map<string, string>();
  for (const statement of sourceFile.statements) {
    if (!isImportDeclaration(statement) || !isStringLiteral(statement.moduleSpecifier)
      || !ROUTER_MODULES.has(statement.moduleSpecifier.text)) continue;
    const named = statement.importClause?.namedBindings;
    if (!named || !isNamedImports(named)) continue;
    for (const element of named.elements) {
      bindings.set(element.name.text, element.propertyName?.text ?? element.name.text);
    }
  }
  return bindings;
}

function routeFactory(
  call: CallExpression,
  bindings: ReadonlyMap<string, string>,
): { factory: string; factoryCall: CallExpression; options: ObjectLiteralExpression | null; routePath: string | null } | null {
  if (isIdentifier(call.expression)) {
    const factory = bindings.get(call.expression.text);
    if (!factory || !FACTORIES.has(factory)) return null;
    const first = call.arguments[0];
    return {
      factory,
      factoryCall: call,
      options: first && isObjectLiteralExpression(first) ? first : null,
      routePath: factory === "createFileRoute" || factory === "createLazyFileRoute"
        ? literal(first)
        : null,
    };
  }
  if (!isCallExpression(call.expression)) return null;
  const inner = routeFactory(call.expression, bindings);
  if (!inner) return null;
  const first = call.arguments[0];
  return {
    ...inner,
    options: first && isObjectLiteralExpression(first) ? first : inner.options,
  };
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

function routeNode(
  framework: TanStackRouteFramework,
  owner: PackageRecord,
  pattern: string,
  routeKind: string,
  routerInstance: string,
  relativePath: string,
  properties: Record<string, JsonValue> = {},
): GraphNode {
  const environment = preferredWebEnvironment("server");
  const canonicalIdentity: Record<string, JsonValue> = {
    framework,
    package_locator: owner.locator,
    route_kind: routeKind,
    environment,
    router_instance: routerInstance,
    route_pattern: pattern,
  };
  const id = stableId("route", canonicalIdentity);
  return {
    id,
    kind: "route",
    locator: `route://${framework}/${encodeURIComponent(owner.locator)}${pattern}#${encodeURIComponent(routeKind)}`,
    display_name: `${framework}:${routeKind}:${pattern}`,
    properties: {
      framework,
      package_locator: owner.locator,
      route_kind: routeKind,
      environment,
      profile_id: PROFILE_ID,
      canonical_identity: canonicalIdentity,
      router_instance: routerInstance,
      route_pattern: pattern,
      source_path: relativePath,
      ...properties,
    },
  };
}

function componentNode(framework: TanStackRouteFramework, symbol: GraphNode, componentKind: string): GraphNode | null {
  const resolverIdentity = symbol.properties.resolver_identity;
  const packageLocator = symbol.properties.package_locator;
  const sourcePath = symbol.properties.source_path;
  if (typeof resolverIdentity !== "string" || typeof packageLocator !== "string" || typeof sourcePath !== "string") return null;
  const environment = preferredWebEnvironment("browser");
  const canonicalIdentity: Record<string, JsonValue> = {
    framework,
    package_locator: packageLocator,
    component_kind: componentKind,
    environment,
    resolver_identity: resolverIdentity,
  };
  const id = stableId("component", canonicalIdentity);
  return {
    id,
    kind: "component",
    locator: `component://${framework}/${encodeURIComponent(packageLocator)}/${id}`,
    display_name: symbol.display_name,
    properties: {
      framework,
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

export function collectTanStackRouterSemanticDelta(
  input: TanStackRouterSemanticInput,
): TanStackRouterSemanticResult {
  const nodes = new Map<string, GraphNode>();
  const sites = new Map<string, DependencySite>();
  const edges = new Map<string, GraphEdge>();
  const diagnostics: Array<Omit<Diagnostic, "id">> = [];
  const framework: TanStackRouteFramework = input.entries.some((entry) => entry.framework === "tanstack-start")
    ? "tanstack-start"
    : "tanstack-router";
  const packageScope = new Set(input.entries.map((entry) => input.ownerForPath(entry.relativeFile).locator));
  const inPackageScope = (relativePath: string): boolean => packageScope.has(input.ownerForPath(relativePath).locator);
  const semanticEvidence = (
    relativePath: string,
    span: Span,
    occurrenceKind: string,
    properties: Record<string, JsonValue> = {},
  ): Evidence[] => evidence(framework, relativePath, span, occurrenceKind, properties);
  const definitionsByPath = new Map<string, TypeScriptRawDefinitionDelta["definitions"]>();
  for (const definition of input.definitions.definitions) {
    if (definition.graphKind !== "symbol") continue;
    const current = definitionsByPath.get(definition.relativePath) ?? [];
    current.push(definition);
    definitionsByPath.set(definition.relativePath, current);
  }
  for (const values of definitionsByPath.values()) {
    values.sort((left, right) => left.startOffset - right.startOffset || left.endOffset - right.endOffset || compareUtf8(left.key, right.key));
  }
  const addNode = (node: GraphNode): GraphNode => {
    const existing = nodes.get(node.id);
    if (existing && JSON.stringify(existing) !== JSON.stringify(node)) {
      throw new Error(`TanStack Router semantic collector produced conflicting node ${node.id}`);
    }
    nodes.set(node.id, existing ?? node);
    return existing ?? node;
  };
  const addDiagnostic = (diagnostic: Omit<Diagnostic, "id">): void => {
    if (!diagnostics.some((item) => item.code === diagnostic.code && item.path === diagnostic.path && item.message === diagnostic.message)) {
      diagnostics.push(diagnostic);
    }
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
    const relationEvidence = semanticEvidence(relativePath, span, occurrenceKind, {
      ...properties,
      ...(algorithm ? { algorithm } : {}),
    });
    emitFrameworkSemanticRelation(
      { sites, edges },
      {
        source, targets: targetsValue, kind, specifier, relativePath, span,
        condition: relationCondition, environment: preferredWebEnvironment(environment),
        profileId: PROFILE_ID, resolutionStatus: status, precision: null, reason,
        evidence: relationEvidence, generated: properties.generated === true,
      },
      {
        conflictSubject: "TanStack Router semantic collector",
        emptyTargetSubject: "TanStack Router semantic relation",
      },
    );
  };

  const definitionFor = (relativePath: string, reference: Node): GraphNode | null => {
    const sourceFile = input.sourceFiles.get(relativePath);
    if (!sourceFile) return null;
    const start = reference.getStart(sourceFile);
    const end = reference.getEnd();
    const referenceName = isIdentifier(reference) ? reference.text : null;
    const definitions = definitionsByPath.get(relativePath) ?? [];
    const exactName = referenceName === null ? [] : definitions.filter((definition) => definition.displayName === referenceName);
    const containing = definitions.filter((definition) => definition.startOffset <= start && definition.endOffset >= end);
    const selected = [...exactName, ...containing]
      .sort((left, right) => (left.endOffset - left.startOffset) - (right.endOffset - right.startOffset) || compareUtf8(left.key, right.key))[0];
    return selected ? input.definitionNode(selected.key) : null;
  };

  const declarationKey = (relativePath: string, name: string): string => `${relativePath}\0${name}`;
  const declarations = new Map<string, RouteDeclaration>();
  const declarationNamed = (relativePath: string, name: string): RouteDeclaration | undefined => {
    const local = declarations.get(declarationKey(relativePath, name));
    if (local) return local;
    const matches = [...declarations.values()].filter((declaration) => declaration.name === name);
    return matches.length === 1 ? matches[0] : undefined;
  };
  const declarationNamesByPath = new Map<string, Set<string>>();
  const registrations: Registration[] = [];
  const maskCalls: Array<{ relativePath: string; call: CallExpression; options: ObjectLiteralExpression }> = [];
  const navigationCalls: Array<{ relativePath: string; node: Node; options: ObjectLiteralExpression; occurrence: string }> = [];

  for (const [relativePath, sourceFile] of input.sourceFiles) {
    if (!inPackageScope(relativePath)) continue;
    const bindings = importBindings(sourceFile);
    if (bindings.size === 0) continue;
    const localDeclarations = new Set<string>();
    const navigateBindings = new Set<string>();
    for (const statement of sourceFile.statements) {
      if (!isVariableStatement(statement)) continue;
      for (const declaration of statement.declarationList.declarations) {
        if (!isIdentifier(declaration.name) || !declaration.initializer) continue;
        if (isCallExpression(declaration.initializer) && isIdentifier(declaration.initializer.expression)
          && bindings.get(declaration.initializer.expression.text) === "useNavigate") {
          navigateBindings.add(declaration.name.text);
        }
        if (!isCallExpression(declaration.initializer)) continue;
        const identified = routeFactory(declaration.initializer, bindings);
        if (!identified) continue;
        const factory = identified.factory;
        const kind = factory === "createRootRoute" || factory === "createRootRouteWithContext" ? "root"
          : factory === "createFileRoute" ? "file"
            : factory === "createLazyFileRoute" ? "lazy-file"
              : "code";
        const parent = returnedIdentifier(propertyExpression(identified.options, "getParentRoute"));
        const routeDeclaration: RouteDeclaration = {
          name: declaration.name.text,
          relativePath,
          sourceFile,
          node: declaration,
          call: declaration.initializer,
          factory,
          kind,
          literalPath: identified.routePath ?? literal(propertyExpression(identified.options, "path"))
            ?? literal(propertyExpression(identified.options, "id")),
          parentName: parent?.name ?? null,
          parentNode: parent?.node ?? null,
          options: identified.options,
        };
        declarations.set(declarationKey(relativePath, routeDeclaration.name), routeDeclaration);
        localDeclarations.add(routeDeclaration.name);
      }
    }
    declarationNamesByPath.set(relativePath, localDeclarations);

    visit(sourceFile, (node) => {
      if (!isVariableDeclaration(node) || !isIdentifier(node.name) || !node.initializer
        || !isCallExpression(node.initializer) || !isIdentifier(node.initializer.expression)) return;
      if (bindings.get(node.initializer.expression.text) === "useNavigate") navigateBindings.add(node.name.text);
    });

    visit(sourceFile, (node) => {
      if (!isCallExpression(node)) return;
      if (isPropertyAccessExpression(node.expression) && node.expression.name.text === "addChildren"
        && isIdentifier(node.expression.expression)) {
        const parentName = node.expression.expression.text;
        const children = node.arguments[0];
        if (children && isArrayLiteralExpression(children)) {
          for (const child of children.elements) {
            if (isIdentifier(child)) {
              registrations.push({ parentName, childName: child.text, childCandidates: [], relativePath, node: child, status: "resolved", reason: null });
            } else if (isConditionalExpression(child)) {
              const candidates = [child.whenTrue, child.whenFalse].filter(isIdentifier).map((item) => item.text);
              if (candidates.length > 0) registrations.push({
                parentName,
                childName: null,
                childCandidates: [...new Set(candidates)].sort(compareUtf8),
                relativePath,
                node: child,
                status: "candidates",
                reason: "tanstack_conditional_child_registration",
              });
              else registrations.push({ parentName, childName: null, childCandidates: [], relativePath, node: child, status: "unresolved", reason: "tanstack_runtime_child_registration" });
            } else {
              registrations.push({ parentName, childName: null, childCandidates: [], relativePath, node: child, status: "unresolved", reason: "tanstack_runtime_child_registration" });
            }
          }
        } else {
          registrations.push({ parentName, childName: null, childCandidates: [], relativePath, node: children ?? node, status: "unresolved", reason: "tanstack_runtime_child_registration" });
        }
      }
      if (isIdentifier(node.expression) && bindings.get(node.expression.text) === "createRouteMask") {
        const options = node.arguments[0];
        if (options && isObjectLiteralExpression(options)) maskCalls.push({ relativePath, call: node, options });
      }
      const isNavigate = isIdentifier(node.expression) && navigateBindings.has(node.expression.text);
      const isRouterNavigate = isPropertyAccessExpression(node.expression) && node.expression.name.text === "navigate";
      if (isNavigate || isRouterNavigate) {
        const options = node.arguments[0];
        if (options && isObjectLiteralExpression(options)) navigationCalls.push({ relativePath, node, options, occurrence: "tanstack_navigation_call" });
      }
    });
  }

  const registered = new Map<string, "resolved" | "candidates">();
  for (const declaration of declarations.values()) if (declaration.kind === "root" || declaration.kind === "file" || declaration.kind === "lazy-file") {
    registered.set(declarationKey(declaration.relativePath, declaration.name), "resolved");
  }
  for (const registration of registrations) {
    if (registration.childName) {
      const child = declarationNamed(registration.relativePath, registration.childName);
      if (child) registered.set(declarationKey(child.relativePath, child.name), "resolved");
    }
    for (const candidate of registration.childCandidates) {
      const child = declarationNamed(registration.relativePath, candidate);
      if (child) registered.set(declarationKey(child.relativePath, child.name), "candidates");
    }
  }

  const baseByPackage = new Map<string, string>();
  const packageBaseFor = (relativePath: string): string => {
    const owner = input.ownerForPath(relativePath);
    const cached = baseByPackage.get(owner.locator);
    if (cached) return cached;
    const rootEntry = input.entries.find((entry) => (
      !entry.generated
      && input.ownerForPath(entry.relativeFile).locator === owner.locator
      && /^__root\.(?:[cm]?[jt]sx?)$/u.test(path.posix.basename(entry.relativeFile))
    ));
    const value = rootEntry?.pattern ?? basePath(input.sources, owner.relativePath);
    baseByPackage.set(owner.locator, value);
    return value;
  };
  const patternMemo = new Map<string, string>();
  const declarationPattern = (key: string, visiting = new Set<string>()): string | null => {
    const cached = patternMemo.get(key);
    if (cached) return cached;
    const declaration = declarations.get(key);
    if (!declaration || visiting.has(key)) return null;
    visiting.add(key);
    let pattern: string;
    if (declaration.kind === "root") pattern = packageBaseFor(declaration.relativePath);
    else if (declaration.kind === "file" || declaration.kind === "lazy-file") {
      if (declaration.literalPath === null) return null;
      pattern = withBase(packageBaseFor(declaration.relativePath), declaration.literalPath);
    } else {
      if (declaration.literalPath === null || declaration.parentName === null) return null;
      const parentDeclaration = declarationNamed(declaration.relativePath, declaration.parentName);
      if (!parentDeclaration) return null;
      const parent = declarationPattern(declarationKey(parentDeclaration.relativePath, parentDeclaration.name), visiting);
      if (parent === null) return null;
      pattern = joinUrl(parent, declaration.literalPath);
    }
    patternMemo.set(key, pattern);
    return pattern;
  };

  const declarationRoutes = new Map<string, SemanticRoute>();
  const routeForDeclaration = new Map<RouteDeclaration, SemanticRoute>();
  const semanticRoutes = new Map<string, SemanticRoute>();
  const routesByPattern = new Map<string, SemanticRoute[]>();
  const routesByPath = new Map<string, SemanticRoute[]>();
  const appendRoute = (route: SemanticRoute): void => {
    semanticRoutes.set(route.node.id, route);
    const byPattern = routesByPattern.get(route.pattern) ?? [];
    if (!byPattern.some((candidate) => candidate.node.id === route.node.id)) byPattern.push(route);
    routesByPattern.set(route.pattern, byPattern);
    const byPath = routesByPath.get(route.relativePath) ?? [];
    if (!byPath.some((candidate) => candidate.node.id === route.node.id)) byPath.push(route);
    routesByPath.set(route.relativePath, byPath);
  };

  const sourceEntries = input.entries.filter((entry) => !entry.generated);
  const generatedByPattern = new Map(input.entries.filter((entry) => entry.generated).map((entry) => [entry.pattern, entry]));
  for (const entry of sourceEntries) {
    const owner = input.ownerForPath(entry.relativeFile);
    const sourceFile = input.sourceFiles.get(entry.relativeFile);
    const localNames = declarationNamesByPath.get(entry.relativeFile) ?? new Set();
    const declaration = [...localNames].map((name) => declarations.get(declarationKey(entry.relativeFile, name))).find((candidate) => (
      candidate?.kind === "file" || candidate?.kind === "lazy-file" || candidate?.kind === "root"
    )) ?? null;
    const routeKind = declaration?.kind === "lazy-file" ? "tanstack-lazy-file-route"
      : declaration?.kind === "root" ? "tanstack-file-root-route"
        : "tanstack-file-route";
    const node = addNode(routeNode(
      framework,
      owner,
      entry.pattern,
      routeKind,
      `${framework}:${owner.locator}:file`,
      entry.relativeFile,
      { generated_tree_corroborated: generatedByPattern.has(entry.pattern) },
    ));
    const semantic = { node, relativePath: entry.relativeFile, declaration, entry, pattern: entry.pattern };
    appendRoute(semantic);
    if (declaration) routeForDeclaration.set(declaration, semantic);
    const file = input.fileNode(entry.relativeFile);
    if (file) addRelation(
      file,
      [node],
      "route_entry",
      entry.pattern,
      entry.relativeFile,
      declaration ? spanFor(input.sources.get(entry.relativeFile) ?? "", declaration.call) : {
        start_line: entry.evidence.start_line,
        start_column: entry.evidence.start_column,
        end_line: entry.evidence.end_line,
        end_column: entry.evidence.end_column,
      },
      condition("server", { "tanstack.route_source": "file" }),
      "server",
      "tanstack_file_route_entry",
      "resolved",
      null,
      null,
      { generated_tree_corroborated: generatedByPattern.has(entry.pattern) },
    );
  }

  for (const entry of input.entries.filter((candidate) => candidate.generated && !sourceEntries.some((source) => source.pattern === candidate.pattern))) {
    const owner = input.ownerForPath(entry.relativeFile);
    const node = addNode(routeNode(
      framework,
      owner,
      entry.pattern,
      "tanstack-generated-route",
      `${framework}:${owner.locator}:file`,
      entry.relativeFile,
      { generated_only: true },
    ));
    appendRoute({ node, relativePath: entry.relativeFile, declaration: null, entry, pattern: entry.pattern });
    const file = input.fileNode(entry.relativeFile);
    if (file) addRelation(
      file,
      [node],
      "route_entry",
      entry.pattern,
      entry.relativeFile,
      { start_line: entry.evidence.start_line, start_column: entry.evidence.start_column, end_line: entry.evidence.end_line, end_column: entry.evidence.end_column },
      condition("server", { "tanstack.route_source": "generated" }),
      "server",
      "tanstack_generated_route_entry",
      "resolved",
      null,
      null,
      { generated: true },
    );
  }

  const rootNameFor = (declaration: RouteDeclaration): string => {
    let current = declaration;
    const seen = new Set<string>();
    while (current.parentName && !seen.has(declarationKey(current.relativePath, current.name))) {
      seen.add(declarationKey(current.relativePath, current.name));
      const parent = declarationNamed(current.relativePath, current.parentName);
      if (!parent) break;
      current = parent;
    }
    return `${current.relativePath}:${current.name}`;
  };
  for (const [key] of registered) {
    if (declarationRoutes.has(key)) continue;
    const declaration = declarations.get(key);
    if (!declaration || declaration.kind === "file" || declaration.kind === "lazy-file") continue;
    if (routeForDeclaration.has(declaration)) continue;
    const pattern = declarationPattern(key);
    if (pattern === null) {
      addDiagnostic({
        severity: "warning",
        code: "web.tanstack_route_pattern_unresolved",
        message: `TanStack Router declaration ${declaration.name} has no statically closed parent/path identity`,
        path: declaration.relativePath,
        profile_id: PROFILE_ID,
        evidence: semanticEvidence(declaration.relativePath, spanFor(input.sources.get(declaration.relativePath) ?? "", declaration.node), "tanstack_route_pattern_unresolved"),
        properties: { framework_semantic_issue: true },
      });
      continue;
    }
    const owner = input.ownerForPath(declaration.relativePath);
    const node = addNode(routeNode(
      framework,
      owner,
      pattern,
      declaration.kind === "root" ? "tanstack-code-root-route" : "tanstack-code-route",
      `${framework}:${owner.locator}:code:${rootNameFor(declaration)}`,
      declaration.relativePath,
      { registration_status: registered.get(key)! },
    ));
    const semantic = { node, relativePath: declaration.relativePath, declaration, entry: null, pattern };
    declarationRoutes.set(key, semantic);
    routeForDeclaration.set(declaration, semantic);
    appendRoute(semantic);
    const file = input.fileNode(declaration.relativePath);
    if (file) addRelation(
      file,
      [node],
      "route_entry",
      pattern,
      declaration.relativePath,
      spanFor(input.sources.get(declaration.relativePath) ?? "", declaration.call),
      condition("server", { "tanstack.route_source": "code" }),
      "server",
      "tanstack_code_route_entry",
    );
  }

  for (const declaration of declarations.values()) {
    if (declaration.kind === "code" && !registered.has(declarationKey(declaration.relativePath, declaration.name))) addDiagnostic({
      severity: "info",
      code: "web.tanstack_route_declaration_unregistered",
      message: `TanStack Router declaration ${declaration.name} is not reachable from a statically closed addChildren registration and was not emitted as an actual route`,
      path: declaration.relativePath,
      profile_id: PROFILE_ID,
      evidence: semanticEvidence(declaration.relativePath, spanFor(input.sources.get(declaration.relativePath) ?? "", declaration.node), "tanstack_unregistered_declaration"),
      properties: { framework_semantic_issue: true },
    });
  }

  for (const registration of registrations) {
    const parentDeclaration = declarationNamed(registration.relativePath, registration.parentName);
    const parent = parentDeclaration
      ? declarationRoutes.get(declarationKey(parentDeclaration.relativePath, parentDeclaration.name))
      : undefined;
    const registrationSpan = spanFor(input.sources.get(registration.relativePath) ?? "", registration.node);
    if (!parent) continue;
    if (registration.status === "unresolved") {
      const unknown = input.unknownTarget();
      addRelation(
        parent.node,
        [unknown],
        "parent_route",
        "<runtime-children>",
        registration.relativePath,
        registrationSpan,
        condition("server", { "tanstack.parent_basis": "registered" }),
        "server",
        "tanstack_add_children_unresolved",
        "unresolved",
        registration.reason,
      );
      addDiagnostic({
        severity: "warning",
        code: "web.tanstack_route_registration_unresolved",
        message: "TanStack Router addChildren uses a loop or runtime-derived collection; registration was retained as unresolved",
        path: registration.relativePath,
        profile_id: PROFILE_ID,
        evidence: semanticEvidence(registration.relativePath, registrationSpan, "tanstack_add_children_unresolved"),
        properties: { framework_semantic_issue: true },
      });
      continue;
    }
    const childNames = registration.childName ? [registration.childName] : registration.childCandidates;
    for (const childName of childNames) {
      const childDeclaration = declarationNamed(registration.relativePath, childName);
      const child = childDeclaration
        ? declarationRoutes.get(declarationKey(childDeclaration.relativePath, childDeclaration.name))
        : undefined;
      if (!child) continue;
      const status: ResolutionStatus = registration.status;
      addRelation(
        child.node,
        [parent.node],
        "parent_route",
        parent.pattern,
        registration.relativePath,
        registrationSpan,
        condition("server", { "tanstack.parent_basis": "registered", "tanstack.registration": status }),
        "server",
        "tanstack_add_children_registration",
        status,
        registration.reason,
        status === "candidates" ? "finite-conditional-route-reference-set-v1" : null,
      );
      const declaration = child.declaration;
      if (declaration?.parentNode && declaration.parentName) addRelation(
        child.node,
        [parent.node],
        "parent_route",
        parent.pattern,
        declaration.relativePath,
        spanFor(input.sources.get(declaration.relativePath) ?? "", declaration.parentNode),
        condition("server", { "tanstack.parent_basis": "declared" }),
        "server",
        "tanstack_declared_parent",
      );
    }
  }

  // File routes are registered by the generated route tree. Emit their actual
  // hierarchy separately from the route declaration/entry evidence.
  for (const route of [...routesByPattern.values()].flat().filter((candidate) => candidate.entry && !candidate.entry.generated)) {
    if (route.pattern === packageBaseFor(route.relativePath)) continue;
    const segments = route.pattern.split("/").filter(Boolean);
    let parent: SemanticRoute | undefined;
    while (segments.length > 0 && !parent) {
      segments.pop();
      const candidatePattern = segments.length === 0 ? "/" : `/${segments.join("/")}`;
      parent = routesByPattern.get(candidatePattern)?.find((candidate) => candidate.entry && !candidate.entry.generated);
    }
    if (parent && route.entry) addRelation(
      route.node,
      [parent.node],
      "parent_route",
      parent.pattern,
      route.relativePath,
      { start_line: route.entry.evidence.start_line, start_column: route.entry.evidence.start_column, end_line: route.entry.evidence.end_line, end_column: route.entry.evidence.end_column },
      condition("server", { "tanstack.parent_basis": "generated-registration" }),
      "server",
      "tanstack_generated_parent_registration",
      "resolved",
      null,
      null,
      { generated_tree_corroborated: generatedByPattern.has(route.pattern) },
    );
  }

  const componentCache = new Map<string, GraphNode>();
  const componentFor = (relativePath: string, expression: Expression, kind: string): GraphNode | null => {
    const reference = isIdentifier(unwrap(expression)) ? unwrap(expression) : expression;
    const symbol = definitionFor(relativePath, reference);
    if (!symbol) return null;
    const cacheKey = `${symbol.id}\0${kind}`;
    const cached = componentCache.get(cacheKey);
    if (cached) return cached;
    const component = componentNode(framework, symbol, kind);
    if (!component) return null;
    componentCache.set(cacheKey, component);
    return addNode(component);
  };
  for (const route of semanticRoutes.values()) {
    const declaration = route.declaration;
    if (!declaration?.options) continue;
    const source = input.sources.get(declaration.relativePath) ?? "";
    const component = propertyExpression(declaration.options, "component");
    if (component) {
      const target = componentFor(declaration.relativePath, component, declaration.kind === "lazy-file" ? "tanstack-lazy-route-component" : "tanstack-route-component");
      if (target) addRelation(
        route.node,
        [target],
        "renders",
        target.display_name,
        declaration.relativePath,
        spanFor(source, component),
        condition("browser", { "tanstack.component": declaration.kind === "lazy-file" ? "lazy" : "eager" }),
        "browser",
        declaration.kind === "lazy-file" ? "tanstack_lazy_component" : "tanstack_route_component",
      );
    }
    for (const [optionName, edgeKind] of [["loader", "loads"], ["context", "loads"], ["beforeLoad", "before_load"]] as const) {
      const option = propertyExpression(declaration.options, optionName);
      if (!option) continue;
      const symbol = definitionFor(declaration.relativePath, isIdentifier(unwrap(option)) ? unwrap(option) : option);
      const target = symbol ?? input.fileNode(declaration.relativePath);
      if (!target || (edgeKind === "before_load" && target.kind !== "symbol" && target.kind !== "server_function")) continue;
      addRelation(
        route.node,
        [target],
        edgeKind,
        optionName,
        declaration.relativePath,
        spanFor(source, option),
        condition("server", { "tanstack.hook": optionName }),
        "server",
        `tanstack_${optionName.replace(/[A-Z]/gu, (value) => `_${value.toLowerCase()}`)}`,
      );
    }
  }

  // Static virtual route configuration is source-authoritative and does not
  // require executing Vite/TanStack configuration code.
  const addVirtualChildren = (
    relativePath: string,
    object: ObjectLiteralExpression,
    parent: SemanticRoute | null,
    routerInstance: string,
  ): void => {
    const source = input.sources.get(relativePath) ?? "";
    const owner = input.ownerForPath(relativePath);
    const configuredPath = literal(propertyExpression(object, "path"));
    const type = literal(propertyExpression(object, "type"));
    const pattern = parent === null ? packageBaseFor(relativePath) : configuredPath === null ? parent.pattern : joinUrl(parent.pattern, configuredPath);
    const virtual = addNode(routeNode(
      framework,
      owner,
      pattern,
      type === "root" || parent === null ? "tanstack-virtual-root-route" : "tanstack-virtual-route",
      routerInstance,
      relativePath,
      { virtual_config: true },
    ));
    const semantic: SemanticRoute = { node: virtual, relativePath, declaration: null, entry: null, pattern };
    appendRoute(semantic);
    const file = input.fileNode(relativePath);
    if (file) addRelation(
      file,
      [virtual],
      "route_entry",
      pattern,
      relativePath,
      spanFor(source, object),
      condition("server", { "tanstack.route_source": "virtual" }),
      "server",
      "tanstack_virtual_route_entry",
    );
    if (parent) addRelation(
      virtual,
      [parent.node],
      "parent_route",
      parent.pattern,
      relativePath,
      spanFor(source, object),
      condition("server", { "tanstack.parent_basis": "virtual-registration" }),
      "server",
      "tanstack_virtual_parent_registration",
    );
    const configuredFile = literal(propertyExpression(object, "file"));
    if (configuredFile) {
      const targetPath = path.posix.normalize(path.posix.join(path.posix.dirname(relativePath), configuredFile));
      const target = input.fileNode(targetPath);
      if (target) addRelation(
        virtual,
        [target],
        "loads",
        configuredFile,
        relativePath,
        spanFor(source, propertyExpression(object, "file") ?? object),
        condition("server", { "tanstack.hook": "virtual-file" }),
        "server",
        "tanstack_virtual_route_file",
      );
    }
    const children = propertyExpression(object, "children");
    if (children && isArrayLiteralExpression(children)) {
      for (const child of children.elements) if (isObjectLiteralExpression(child)) addVirtualChildren(relativePath, child, semantic, routerInstance);
    }
  };
  for (const [relativePath, sourceFile] of input.sourceFiles) {
    if (!inPackageScope(relativePath)) continue;
    visit(sourceFile, (node) => {
      if (!isPropertyAssignment(node) || propertyName(node.name) !== "virtualRouteConfig" || !isObjectLiteralExpression(node.initializer)) return;
      const owner = input.ownerForPath(relativePath);
      addVirtualChildren(relativePath, node.initializer, null, `${framework}:${owner.locator}:virtual`);
    });
  }

  const routeTarget = (value: string, relativePath: string): SemanticRoute | null => {
    const owner = input.ownerForPath(relativePath);
    const exact = routesByPattern.get(withBase(packageBaseFor(relativePath), value)) ?? routesByPattern.get(normalizeUrl(value));
    return exact?.filter((candidate) => candidate.node.properties.package_locator === owner.locator)
      .sort((left, right) => compareUtf8(left.node.id, right.node.id))[0] ?? null;
  };
  const navigationSource = (relativePath: string, node: Node): GraphNode | null => {
    const definition = definitionFor(relativePath, node);
    return definition ?? routesByPath.get(relativePath)?.sort((left, right) => compareUtf8(left.node.id, right.node.id))[0]?.node ?? null;
  };
  const addNavigation = (
    relativePath: string,
    sourceNode: Node,
    expression: Expression,
    kind: "navigates_to" | "masks_to",
    occurrence: string,
  ): void => {
    const source = navigationSource(relativePath, sourceNode);
    if (!source) return;
    const sourceText = input.sources.get(relativePath) ?? "";
    const value = unwrap(expression);
    const values = isConditionalExpression(value)
      ? [literal(value.whenTrue), literal(value.whenFalse)].filter((candidate): candidate is string => candidate !== null)
      : literal(value) === null ? [] : [literal(value)!];
    const targets = [...new Set(values)].map((value) => routeTarget(value, relativePath)).filter((target): target is SemanticRoute => target !== null).map((target) => target.node);
    if (targets.length === 0) addRelation(
      source,
      [input.unknownTarget()],
      kind,
      values[0] ?? "<dynamic-route>",
      relativePath,
      spanFor(sourceText, expression),
      condition("browser", { "tanstack.navigation": kind }),
      "browser",
      occurrence,
      "unresolved",
      values.length === 0 ? "tanstack_navigation_non_literal" : "tanstack_navigation_target_not_found",
    );
    else addRelation(
      source,
      targets,
      kind,
      values.join(" | "),
      relativePath,
      spanFor(sourceText, expression),
      condition("browser", { "tanstack.navigation": kind }),
      "browser",
      occurrence,
      targets.length > 1 ? "candidates" : "resolved",
      targets.length > 1 ? "tanstack_navigation_literal_union" : null,
      targets.length > 1 ? "finite-literal-route-set-v1" : null,
    );
  };
  for (const navigation of navigationCalls) {
    const to = propertyExpression(navigation.options, "to");
    if (to) addNavigation(navigation.relativePath, navigation.node, to, "navigates_to", navigation.occurrence);
    const mask = propertyExpression(navigation.options, "mask");
    if (mask && isObjectLiteralExpression(mask)) {
      const maskTo = propertyExpression(mask, "to");
      if (maskTo) addNavigation(navigation.relativePath, navigation.node, maskTo, "masks_to", "tanstack_navigation_mask");
    }
  }
  for (const mask of maskCalls) {
    const from = literal(propertyExpression(mask.options, "from"));
    const to = propertyExpression(mask.options, "to");
    const source = from ? routeTarget(from, mask.relativePath) : null;
    if (source && to) addNavigation(mask.relativePath, source.declaration?.node ?? mask.call, to, "masks_to", "tanstack_route_mask");
  }
  for (const [relativePath, sourceFile] of input.sourceFiles) {
    if (!inPackageScope(relativePath)) continue;
    const bindings = importBindings(sourceFile);
    const linkNames = new Set([...bindings].filter(([, imported]) => imported === "Link" || imported === "Navigate").map(([local]) => local));
    if (linkNames.size === 0) continue;
    visit(sourceFile, (node) => {
      const opening = isJsxSelfClosingElement(node) ? node : isJsxOpeningElement(node) ? node : isJsxElement(node) ? node.openingElement : null;
      if (!opening || !isIdentifier(opening.tagName) || !linkNames.has(opening.tagName.text)) return;
      for (const attribute of opening.attributes.properties) {
        if (!isJsxAttribute(attribute) || !isIdentifier(attribute.name)) continue;
        const kind = attribute.name.text === "to" ? "navigates_to" : attribute.name.text === "mask" ? "masks_to" : null;
        if (!kind || !attribute.initializer) continue;
        if (isStringLiteral(attribute.initializer)) addNavigation(relativePath, opening, attribute.initializer, kind, "tanstack_jsx_navigation");
        else if (isJsxExpression(attribute.initializer) && attribute.initializer.expression) {
          const expression = attribute.initializer.expression;
          if (kind === "masks_to" && isObjectLiteralExpression(expression)) {
            const to = propertyExpression(expression, "to");
            if (to) addNavigation(relativePath, opening, to, kind, "tanstack_jsx_mask");
          } else addNavigation(relativePath, opening, expression, kind, "tanstack_jsx_navigation");
        }
      }
    });
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
