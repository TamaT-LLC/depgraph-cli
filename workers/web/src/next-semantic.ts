import {
  SyntaxKind,
  isArrowFunction,
  isBlock,
  isCallExpression,
  isExpressionStatement,
  isExportAssignment,
  isFunctionExpression,
  isIdentifier,
  isImportDeclaration,
  isJsxOpeningElement,
  isJsxSelfClosingElement,
  isNamedImports,
  isNoSubstitutionTemplateLiteral,
  isParenthesizedExpression,
  isPropertyAccessExpression,
  isReturnStatement,
  isStringLiteral,
  isVariableStatement,
  type CallExpression,
  type JsxTagNameExpression,
  type Node,
  type SourceFile,
} from "typescript/unstable/ast";
import {
  WEB_FRAMEWORK_SEMANTIC_CAPABILITY,
  WEB_FRAMEWORK_SEMANTIC_EXTRACTOR_VERSION,
  type FrameworkSemanticDelta,
} from "./framework-semantic";
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

const NEXT_EXTRACTOR = "next-static-adapter";
const NEXT_HTTP_METHODS = ["GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"] as const;

type Span = {
  start_line: number;
  start_column: number;
  end_line: number;
  end_column: number;
};

interface SourceMetadata {
  sourceFile: SourceFile;
  directives: Array<{ value: string; span: Span }>;
  runtime: { value: string; span: Span; dynamic: boolean } | null;
}

interface RouteContext {
  entry: RouteEntry;
  owner: PackageRecord;
  routerKind: "app" | "pages" | "root";
  route: GraphNode;
  components: GraphNode[];
  metadata: SourceMetadata | null;
}

export interface NextSemanticInput {
  entries: readonly RouteEntry[];
  sources: ReadonlyMap<string, string>;
  sourceFiles: ReadonlyMap<string, SourceFile>;
  definitions: TypeScriptRawDefinitionDelta;
  dependencies: TypeScriptRawDependencyDelta;
  definitionNode(key: string): GraphNode | null;
  fileNode(relativePath: string): GraphNode | null;
  owner(entry: RouteEntry): PackageRecord;
  unknownTarget(): GraphNode;
}

export interface NextSemanticResult {
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

function sourceMetadata(sourceFile: SourceFile, source: string): SourceMetadata {
  const directives: SourceMetadata["directives"] = [];
  for (const statement of sourceFile.statements) {
    if (!isExpressionStatement(statement) || !isStringLiteral(statement.expression)) break;
    const value = statement.expression.text;
    if (value === "use client" || value === "use server" || value === "use cache" || value.startsWith("use cache:")) {
      directives.push({
        value,
        span: spanFor(source, statement.getStart(sourceFile), statement.getEnd()),
      });
    }
  }
  let runtime: SourceMetadata["runtime"] = null;
  for (const statement of sourceFile.statements) {
    if (!isVariableStatement(statement)
      || !statement.modifiers?.some((modifier) => modifier.kind === SyntaxKind.ExportKeyword)) continue;
    for (const declaration of statement.declarationList.declarations) {
      if (!isIdentifier(declaration.name) || declaration.name.text !== "runtime" || !declaration.initializer) continue;
      const literal = isStringLiteral(declaration.initializer) || isNoSubstitutionTemplateLiteral(declaration.initializer)
        ? declaration.initializer.text
        : null;
      runtime = {
        value: literal ?? "dynamic",
        span: spanFor(source, declaration.getStart(sourceFile), declaration.getEnd()),
        dynamic: literal === null,
      };
    }
  }
  return { sourceFile, directives, runtime };
}

function routerKind(entry: RouteEntry): RouteContext["routerKind"] {
  const portable = `/${entry.relativeFile.replaceAll("\\", "/")}`;
  if (portable.includes("/src/app/") || portable.includes("/app/")) return "app";
  if (portable.includes("/src/pages/") || portable.includes("/pages/")) return "pages";
  return "root";
}

function routeSyntax(entry: RouteEntry, kind: RouteContext["routerKind"]): {
  groups: string[];
  slots: string[];
  intercepts: string[];
} {
  const portable = `/${entry.relativeFile.replaceAll("\\", "/")}`;
  const marker = kind === "app" ? /\/(?:src\/)?app\//u : kind === "pages" ? /\/(?:src\/)?pages\//u : null;
  const relative = marker ? portable.split(marker)[1] ?? portable : portable;
  const segments = relative.split("/").slice(0, -1);
  return {
    groups: segments.filter((segment) => /^\([^./][^/]*\)$/u.test(segment)),
    slots: segments.filter((segment) => segment.startsWith("@")),
    intercepts: segments.filter((segment) => /^(?:\(\.\)|\(\.\.\)|\(\.\.\.\))/u.test(segment)),
  };
}

function componentEntryKind(entry: RouteEntry, kind: RouteContext["routerKind"], exportName = "default"): string {
  if (entry.entryKind === "route" || entry.entryKind === "api-route") {
    return `next-${kind}-route-handler-${exportName.toLowerCase()}`;
  }
  return `next-${kind}-${entry.entryKind}`;
}

function routeEntryKind(entry: RouteEntry, kind: RouteContext["routerKind"]): string {
  return `next-${kind}-${entry.entryKind}`;
}

function isComponentEntry(entry: RouteEntry): boolean {
  return [
    "page", "layout", "template", "loading", "error", "global-error",
    "not-found", "forbidden", "unauthorized", "global-not-found", "default",
    "route", "api-route",
  ].includes(entry.entryKind);
}

function cacheDirective(metadata: SourceMetadata | null): string | null {
  return metadata?.directives.find((directive) => directive.value === "use cache" || directive.value.startsWith("use cache:"))?.value ?? null;
}

function environmentFor(metadata: SourceMetadata | null): string {
  if (metadata?.directives.some((directive) => directive.value === "use client")) {
    return preferredWebEnvironment("browser");
  }
  if (metadata?.directives.some((directive) => directive.value === "use server" || directive.value === "use cache" || directive.value.startsWith("use cache:"))) {
    return preferredWebEnvironment("server");
  }
  return preferredWebEnvironment("server");
}

function nextCondition(
  environment: string,
  metadata: SourceMetadata | null,
  kind: RouteContext["routerKind"],
  httpMethod: typeof NEXT_HTTP_METHODS[number] | null = null,
): Condition {
  const conditions: Condition[] = [
    { op: "eq", key: "mode", value: "production" },
    { op: "eq", key: "environment", value: environment },
    { op: "eq", key: "next.router", value: kind },
  ];
  if (metadata?.runtime) conditions.push({ op: "eq", key: "next.runtime", value: metadata.runtime.value });
  const boundary = metadata?.directives.find((directive) => directive.value === "use client" || directive.value === "use server");
  if (boundary) conditions.push({ op: "eq", key: "next.boundary", value: boundary.value });
  const cache = cacheDirective(metadata);
  if (cache) conditions.push({ op: "eq", key: "next.cache", value: cache });
  if (httpMethod) conditions.push({ op: "eq", key: "next.method", value: httpMethod });
  return canonicalizeCondition({ op: "all", conditions });
}

function componentHttpMethod(component: GraphNode): typeof NEXT_HTTP_METHODS[number] | null {
  const componentKind = component.properties.component_kind;
  if (typeof componentKind !== "string") return null;
  return NEXT_HTTP_METHODS.find((method) => componentKind.endsWith(`-${method.toLowerCase()}`)) ?? null;
}

function evidence(
  relativePath: string,
  span: Span,
  occurrenceKind: string,
  properties: Record<string, JsonValue> = {},
): Evidence[] {
  const common = {
    extractor: NEXT_EXTRACTOR,
    extractor_version: WEB_FRAMEWORK_SEMANTIC_EXTRACTOR_VERSION,
    path: relativePath,
    ...span,
  };
  const sharedProperties: Record<string, JsonValue> = {
    profile_id: PROFILE_ID,
    framework: "next",
    occurrence_kind: occurrenceKind,
    ...properties,
  };
  return [
    {
      kind: "semantic",
      ...common,
      properties: {
        ...sharedProperties,
        contract_version: WEB_FRAMEWORK_SEMANTIC_CAPABILITY,
      },
    },
    {
      kind: "source",
      ...common,
      properties: sharedProperties,
    },
  ];
}

function spanFromNode(node: GraphNode): Span | null {
  const value = node.properties.source_span;
  if (value === null || typeof value !== "object" || Array.isArray(value)) return null;
  const result = value as Record<string, JsonValue>;
  const fields = ["start_line", "start_column", "end_line", "end_column"] as const;
  if (!fields.every((field) => Number.isSafeInteger(result[field]) && Number(result[field]) >= 1)) return null;
  return {
    start_line: Number(result.start_line),
    start_column: Number(result.start_column),
    end_line: Number(result.end_line),
    end_column: Number(result.end_column),
  };
}

function defaultEntrySpan(entry: RouteEntry): Span {
  return {
    start_line: entry.evidence.start_line,
    start_column: entry.evidence.start_column,
    end_line: entry.evidence.end_line,
    end_column: entry.evidence.end_column,
  };
}

function frameworkComponent(
  symbol: GraphNode,
  componentKind: string,
  metadata: SourceMetadata | null,
): GraphNode | null {
  const resolverIdentity = symbol.properties.resolver_identity;
  const packageLocator = symbol.properties.package_locator;
  const sourcePath = symbol.properties.source_path;
  if (typeof resolverIdentity !== "string" || resolverIdentity.length === 0
    || typeof packageLocator !== "string" || packageLocator.length === 0
    || typeof sourcePath !== "string" || sourcePath.length === 0) return null;
  const environment = environmentFor(metadata);
  const canonicalIdentity: Record<string, JsonValue> = {
    framework: "next",
    package_locator: packageLocator,
    component_kind: componentKind,
    environment,
    resolver_identity: resolverIdentity,
  };
  const id = stableId("component", canonicalIdentity);
  return {
    id,
    kind: "component",
    locator: `component://next/${encodeURIComponent(packageLocator)}/${id}`,
    display_name: symbol.display_name,
    properties: {
      framework: "next",
      package_locator: packageLocator,
      component_kind: componentKind,
      environment,
      profile_id: PROFILE_ID,
      canonical_identity: canonicalIdentity,
      resolver_identity: resolverIdentity,
      source_path: sourcePath,
      source_span: symbol.properties.source_span ?? null,
      directives: metadata?.directives.map((directive) => directive.value) ?? [],
      runtime: metadata?.runtime?.value ?? "default",
      runtime_dynamic: metadata?.runtime?.dynamic ?? false,
      ...(cacheDirective(metadata) ? { cache_directive: cacheDirective(metadata)! } : {}),
      typescript_definition_id: symbol.id,
    },
  };
}

function frameworkRoute(entry: RouteEntry, owner: PackageRecord, kind: RouteContext["routerKind"]): GraphNode {
  const environment = preferredWebEnvironment("server");
  const syntax = routeSyntax(entry, kind);
  const routeKind = routeEntryKind(entry, kind);
  const canonicalIdentity: Record<string, JsonValue> = {
    framework: "next",
    package_locator: owner.locator,
    route_kind: routeKind,
    environment,
    router_instance: `next:${owner.locator}:${kind}`,
    route_pattern: entry.pattern,
    ...(syntax.groups.length > 0 ? { route_groups: syntax.groups } : {}),
    ...(syntax.slots.length > 0 ? { parallel_slots: syntax.slots } : {}),
    ...(syntax.intercepts.length > 0 ? { intercepting_segments: syntax.intercepts } : {}),
  };
  const id = stableId("route", canonicalIdentity);
  return {
    id,
    kind: "route",
    locator: `route://next/${encodeURIComponent(owner.locator)}${entry.pattern}#${encodeURIComponent(routeKind)}`,
    display_name: `next:${kind}:${entry.entryKind}:${entry.pattern}`,
    properties: {
      framework: "next",
      package_locator: owner.locator,
      route_kind: routeKind,
      environment,
      profile_id: PROFILE_ID,
      canonical_identity: canonicalIdentity,
      router_instance: canonicalIdentity.router_instance!,
      route_pattern: entry.pattern,
      router_kind: kind,
      source_path: entry.relativeFile,
      route_groups: syntax.groups,
      parallel_slots: syntax.slots,
      intercepting_segments: syntax.intercepts,
    },
  };
}

function exportProofKey(relativePath: string, exportPath: readonly string[]): string {
  return JSON.stringify([relativePath, exportPath]);
}

function isPathAncestor(parentPath: string, childPath: string): boolean {
  const parent = parentPath.replaceAll("\\", "/").replace(/\/[^/]+$/u, "");
  const child = childPath.replaceAll("\\", "/").replace(/\/[^/]+$/u, "");
  return child === parent || child.startsWith(`${parent}/`);
}

function jsxTagRoot(node: JsxTagNameExpression): string | null {
  let current: Node = node;
  while (isPropertyAccessExpression(current)) current = current.expression;
  return isIdentifier(current) ? current.text : null;
}

function visit(node: Node, action: (node: Node) => void): void {
  action(node);
  node.forEachChild((child) => visit(child, action));
}

function directDynamicImport(loader: Node): CallExpression | null {
  if (!isArrowFunction(loader) && !isFunctionExpression(loader)) return null;
  let body: Node = loader.body;
  if (isBlock(body)) {
    const [statement] = body.statements;
    if (body.statements.length !== 1 || !statement || !isReturnStatement(statement)) return null;
    const returned = statement.expression;
    if (!returned) return null;
    body = returned;
  }
  while (isParenthesizedExpression(body)) body = body.expression;
  return isCallExpression(body) && body.expression.kind === SyntaxKind.ImportKeyword ? body : null;
}

function hasModifier(node: Node, kind: SyntaxKind): boolean {
  const modifiers = (node as Node & { readonly modifiers?: readonly Node[] }).modifiers;
  return modifiers?.some((modifier) => modifier.kind === kind) ?? false;
}

function syntaxExportDefinitionKeys(
  exportName: string,
  sourceFile: SourceFile | undefined,
  localDefinitions: readonly TypeScriptRawDefinitionDelta["definitions"][number][],
): string[] {
  if (!sourceFile) return [];
  const keys = new Set<string>();
  for (const statement of sourceFile.statements) {
    const start = statement.getStart(sourceFile);
    const end = statement.getEnd();
    if (exportName === "default") {
      if (hasModifier(statement, SyntaxKind.ExportKeyword) && hasModifier(statement, SyntaxKind.DefaultKeyword)) {
        for (const definition of localDefinitions) {
          if (definition.startOffset >= start && definition.endOffset <= end) keys.add(definition.key);
        }
      } else if (isExportAssignment(statement) && !statement.isExportEquals) {
        if (isIdentifier(statement.expression)) {
          const exportedName = statement.expression.text;
          for (const definition of localDefinitions.filter((definition) => definition.displayName === exportedName)) {
            keys.add(definition.key);
          }
        } else {
          for (const definition of localDefinitions) {
            if (definition.startOffset >= statement.expression.getStart(sourceFile)
              && definition.endOffset <= statement.expression.getEnd()) keys.add(definition.key);
          }
        }
      }
      continue;
    }
    if (!hasModifier(statement, SyntaxKind.ExportKeyword)) continue;
    for (const definition of localDefinitions) {
      if (definition.displayName === exportName
        && definition.startOffset >= start
        && definition.endOffset <= end) keys.add(definition.key);
    }
  }
  return [...keys].sort(compareUtf8);
}

export function collectNextSemanticDelta(input: NextSemanticInput): NextSemanticResult {
  const nodes = new Map<string, GraphNode>();
  const sites = new Map<string, DependencySite>();
  const edges = new Map<string, GraphEdge>();
  const diagnostics: Array<Omit<Diagnostic, "id">> = [];
  const definitions = new Map(input.definitions.definitions.map((definition) => [definition.key, definition]));
  const definitionsByPath = new Map<string, TypeScriptRawDefinitionDelta["definitions"]>();
  for (const definition of input.definitions.definitions) {
    if (definition.graphKind !== "symbol") continue;
    const local = definitionsByPath.get(definition.relativePath) ?? [];
    local.push(definition);
    definitionsByPath.set(definition.relativePath, local);
  }
  const dependencySitesByImport = new Map<string, TypeScriptRawDependencyDelta["sites"]>();
  const importKey = (relativePath: string, moduleSpecifier: string, importedName: string | null): string => (
    JSON.stringify([relativePath, moduleSpecifier, importedName])
  );
  for (const site of input.dependencies.sites) {
    if (site.moduleSpecifier === null) continue;
    const key = importKey(site.evidence.relativePath, site.moduleSpecifier, site.importedName);
    const correlated = dependencySitesByImport.get(key) ?? [];
    correlated.push(site);
    dependencySitesByImport.set(key, correlated);
  }
  const proofKeys = new Map(input.dependencies.moduleExports.map((proof) => [
    exportProofKey(proof.relativePath, proof.exportPath),
    proof.definitionKeys,
  ]));
  const exportedDefinitionKeys = (relativePath: string, exportName: string): string[] => {
    const proven = proofKeys.get(exportProofKey(relativePath, [exportName])) ?? [];
    return [...new Set([
      ...proven,
      ...syntaxExportDefinitionKeys(
        exportName,
        input.sourceFiles.get(relativePath),
        definitionsByPath.get(relativePath) ?? [],
      ),
    ].filter((key) => definitions.get(key)?.graphKind === "symbol"))].sort(compareUtf8);
  };
  const metadata = new Map<string, SourceMetadata>();
  const metadataFor = (relativePath: string): SourceMetadata | null => {
    const existing = metadata.get(relativePath);
    if (existing) return existing;
    const source = input.sources.get(relativePath);
    const sourceFile = input.sourceFiles.get(relativePath);
    if (source === undefined || sourceFile === undefined) return null;
    const value = sourceMetadata(sourceFile, source);
    metadata.set(relativePath, value);
    return value;
  };
  const diagnosticKeys = new Set<string>();
  const addDiagnostic = (diagnostic: Omit<Diagnostic, "id">): void => {
    const key = JSON.stringify([diagnostic.code, diagnostic.path, diagnostic.message]);
    if (!diagnosticKeys.has(key)) diagnostics.push(diagnostic);
    diagnosticKeys.add(key);
  };
  const addNode = (node: GraphNode): GraphNode => {
    const existing = nodes.get(node.id);
    if (existing && JSON.stringify(existing) !== JSON.stringify(node)) {
      throw new Error(`Next semantic collector produced conflicting node ${node.id}`);
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
  ): void => {
    const targets = [...targetsValue].sort((left, right) => compareUtf8(left.id, right.id));
    const precision: Precision = status === "candidates" ? "overapprox"
      : status === "unresolved" ? "heuristic"
        : "exact";
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
      throw new Error(`Next semantic collector produced conflicting site ${site.id}`);
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
        throw new Error(`Next semantic collector produced conflicting edge ${edge.id}`);
      }
      edges.set(edge.id, existingEdge ?? edge);
    }
  };
  const componentByKey = new Map<string, GraphNode>();
  const componentFor = (
    definitionKey: string,
    componentKind: string,
    sourceKind: RouteContext["routerKind"],
  ): GraphNode | null => {
    const cacheKey = `${definitionKey}\0${componentKind}\0${sourceKind}`;
    const existing = componentByKey.get(cacheKey);
    if (existing) return existing;
    const definition = definitions.get(definitionKey);
    const symbol = input.definitionNode(definitionKey);
    if (!definition || !symbol) return null;
    const component = frameworkComponent(
      symbol,
      componentKind,
      metadataFor(definition.relativePath),
    );
    if (!component) return null;
    componentByKey.set(cacheKey, component);
    return addNode(component);
  };

  const contexts: RouteContext[] = [];
  for (const entry of input.entries.filter((candidate) => candidate.framework === "next")) {
    const owner = input.owner(entry);
    const kind = routerKind(entry);
    const entryMetadata = metadataFor(entry.relativeFile);
    const route = addNode(frameworkRoute(entry, owner, kind));
    const exportNames = entry.entryKind === "route" || entry.entryKind === "api-route"
      ? NEXT_HTTP_METHODS
      : ["default"] as const;
    const components: GraphNode[] = [];
    for (const exportName of exportNames) {
      const keys = exportedDefinitionKeys(entry.relativeFile, exportName);
      for (const key of keys) {
        const component = componentFor(key, componentEntryKind(entry, kind, exportName), kind);
        if (component) {
          components.push(component);
        }
      }
    }
    const uniqueComponents = [...new Map(components.map((component) => [component.id, component])).values()]
      .sort((left, right) => compareUtf8(left.id, right.id));
    const file = input.fileNode(entry.relativeFile);
    if (!file) throw new Error(`Next semantic route has no inventory file ${entry.relativeFile}`);
    const routeHandler = entry.entryKind === "route" || entry.entryKind === "api-route";
    if (uniqueComponents.length === 1 || (routeHandler && uniqueComponents.length > 0)) {
      for (const component of uniqueComponents) {
        const componentSpan = spanFromNode(component) ?? defaultEntrySpan(entry);
        const componentCondition = nextCondition(
          component.properties.environment as string,
          entryMetadata,
          kind,
          routeHandler ? componentHttpMethod(component) : null,
        );
        addRelation(
          component,
          [route],
          "route_entry",
          entry.pattern,
          entry.relativeFile,
          componentSpan,
          componentCondition,
          component.properties.environment as string,
          "next_route_entry",
          "resolved",
          null,
          null,
          { route_kind: route.properties.route_kind as string },
        );
        addRelation(
          route,
          [component],
          "renders",
          component.display_name,
          entry.relativeFile,
          componentSpan,
          componentCondition,
          component.properties.environment as string,
          "next_route_render",
          "resolved",
          null,
          null,
          { route_kind: route.properties.route_kind as string },
        );
      }
    } else {
      const routeCondition = nextCondition(preferredWebEnvironment("server"), entryMetadata, kind);
      addRelation(
        file,
        [route],
        "route_entry",
        entry.pattern,
        entry.relativeFile,
        defaultEntrySpan(entry),
        routeCondition,
        preferredWebEnvironment("server"),
        "next_filesystem_route_entry",
        "resolved",
        null,
        null,
        { route_kind: route.properties.route_kind as string },
      );
      if (isComponentEntry(entry)) {
        addDiagnostic({
          severity: "warning",
          code: "web.next_component_export_unresolved",
          message: uniqueComponents.length > 1
            ? `Next route ${entry.relativeFile} has multiple TypeChecker component export targets; the filesystem route was retained without guessing one entry component`
            : `Next route ${entry.relativeFile} has no canonical TypeChecker component export target; the filesystem route was retained`,
          path: entry.relativeFile,
          profile_id: PROFILE_ID,
          evidence: [evidence(entry.relativeFile, defaultEntrySpan(entry), "next_component_export_unresolved")[1]!],
          properties: { framework_semantic_issue: true },
        });
        if (uniqueComponents.length > 1) {
          addRelation(
            route,
            uniqueComponents,
            "renders",
            entry.relativeFile,
            entry.relativeFile,
            defaultEntrySpan(entry),
            routeCondition,
            preferredWebEnvironment("server"),
            "next_route_render_candidates",
            "candidates",
            "multiple_typechecker_export_targets",
            "next-typechecker-module-export-v1",
          );
        }
      }
    }
    if (entryMetadata?.runtime?.dynamic) {
      addDiagnostic({
        severity: "warning",
        code: "web.next_dynamic_runtime_config",
        message: `Next runtime export in ${entry.relativeFile} is not a static string literal; the route condition records runtime=dynamic`,
        path: entry.relativeFile,
        profile_id: PROFILE_ID,
        evidence: [evidence(entry.relativeFile, entryMetadata.runtime.span, "next_dynamic_runtime_config")[1]!],
        properties: { framework_semantic_issue: true },
      });
    }
    const clientDirective = entryMetadata?.directives.find((directive) => directive.value === "use client");
    const serverDirective = entryMetadata?.directives.find((directive) => directive.value === "use server");
    if (clientDirective && serverDirective) {
      addDiagnostic({
        severity: "warning",
        code: "web.next_conflicting_boundary_directives",
        message: `Next module ${entry.relativeFile} contains both use client and use server directives; no boundary edge was inferred`,
        path: entry.relativeFile,
        profile_id: PROFILE_ID,
        evidence: [evidence(entry.relativeFile, clientDirective.span, "next_conflicting_boundary_directives")[1]!],
        properties: { framework_semantic_issue: true },
      });
    } else {
      for (const component of uniqueComponents) {
        const directive = clientDirective ?? serverDirective;
        if (!directive) continue;
        const boundaryKind = clientDirective ? "client_boundary" : "server_boundary";
        const componentEnvironment = component.properties.environment as string;
        addRelation(
          component,
          [component],
          boundaryKind,
          directive.value,
          entry.relativeFile,
          directive.span,
          nextCondition(componentEnvironment, entryMetadata, kind),
          componentEnvironment,
          `next_${boundaryKind}_directive`,
          "resolved",
          null,
          null,
          { directive: directive.value },
        );
      }
    }
    contexts.push({
      entry,
      owner,
      routerKind: kind,
      route,
      components: uniqueComponents,
      metadata: entryMetadata,
    });
  }

  const layouts = contexts.filter((context) => context.routerKind === "app" && context.entry.entryKind === "layout");
  for (const child of contexts.filter((context) => context.routerKind === "app" && context.entry.entryKind !== "layout")) {
    const candidates = layouts
      .filter((layout) => layout.owner.locator === child.owner.locator
        && layout.route.id !== child.route.id
        && isPathAncestor(layout.entry.relativeFile, child.entry.relativeFile))
      .sort((left, right) => right.entry.relativeFile.length - left.entry.relativeFile.length
        || compareUtf8(left.route.id, right.route.id));
    const deepestLength = candidates[0]?.entry.relativeFile.replace(/\/[^/]+$/u, "").length;
    const parents = deepestLength === undefined
      ? []
      : candidates.filter((candidate) => candidate.entry.relativeFile.replace(/\/[^/]+$/u, "").length === deepestLength);
    if (parents.length === 0) continue;
    const status: ResolutionStatus = parents.length === 1 ? "resolved" : "candidates";
    addRelation(
      child.route,
      parents.map((parent) => parent.route),
      "parent_route",
      parents.map((parent) => parent.entry.pattern).join(","),
      child.entry.relativeFile,
      defaultEntrySpan(child.entry),
      nextCondition(preferredWebEnvironment("server"), child.metadata, child.routerKind),
      preferredWebEnvironment("server"),
      "next_parent_layout",
      status,
      status === "candidates" ? "parallel_layout_candidates" : null,
      status === "candidates" ? "next-filesystem-layout-ancestry-v1" : null,
    );
  }

  const routeContextByPath = new Map(contexts.map((context) => [context.entry.relativeFile, context]));
  const componentForImportedDefinition = (key: string, sourceKind: RouteContext["routerKind"]): GraphNode | null => {
    const definition = definitions.get(key);
    if (!definition) return null;
    const routeContext = routeContextByPath.get(definition.relativePath);
    const entryKind = routeContext
      ? componentEntryKind(routeContext.entry, routeContext.routerKind)
      : "next-react-component";
    return componentFor(key, entryKind, routeContext?.routerKind ?? sourceKind);
  };
  for (const context of contexts.filter((candidate) => candidate.components.length === 1)) {
    const sourceComponent = context.components[0]!;
    const source = input.sources.get(context.entry.relativeFile);
    const sourceMeta = context.metadata;
    if (source === undefined || sourceMeta === null) continue;
    const jsxUses = new Map<string, Span[]>();
    visit(sourceMeta.sourceFile, (node) => {
      if (!isJsxOpeningElement(node) && !isJsxSelfClosingElement(node)) return;
      const name = jsxTagRoot(node.tagName);
      if (!name || /^[a-z]/u.test(name)) return;
      const spans = jsxUses.get(name) ?? [];
      spans.push(spanFor(source, node.tagName.getStart(sourceMeta.sourceFile), node.tagName.getEnd()));
      jsxUses.set(name, spans);
    });
    const dynamicNames = new Set<string>();
    for (const statement of sourceMeta.sourceFile.statements) {
      if (!isImportDeclaration(statement) || !isStringLiteral(statement.moduleSpecifier)) continue;
      const importedModule = statement.moduleSpecifier.text;
      const clause = statement.importClause;
      if (importedModule === "next/dynamic" && clause?.name) dynamicNames.add(clause.name.text);
      if (!clause) continue;
      const bindings: Array<{ local: string; imported: string; span: Span }> = [];
      if (clause.name) {
        bindings.push({
          local: clause.name.text,
          imported: "default",
          span: spanFor(source, clause.name.getStart(sourceMeta.sourceFile), clause.name.getEnd()),
        });
      }
      if (clause.namedBindings && isNamedImports(clause.namedBindings)) {
        for (const specifier of clause.namedBindings.elements) {
          bindings.push({
            local: specifier.name.text,
            imported: specifier.propertyName?.text ?? specifier.name.text,
            span: spanFor(source, specifier.name.getStart(sourceMeta.sourceFile), specifier.name.getEnd()),
          });
        }
      }
      for (const binding of bindings) {
        const uses = jsxUses.get(binding.local) ?? [];
        if (uses.length === 0) continue;
        const correlated = dependencySitesByImport.get(importKey(
          context.entry.relativeFile,
          importedModule,
          binding.imported,
        )) ?? [];
        const raw = correlated.find((site) => (
          site.evidence.startOffset === positionOffset(source, binding.span.start_line, binding.span.start_column)
        )) ?? correlated[0];
        const targets = raw?.targets
          .filter((target): target is Extract<typeof target, { kind: "definition" }> => target.kind === "definition")
          .map((target) => componentForImportedDefinition(target.key, context.routerKind))
          .filter((target): target is GraphNode => target !== null) ?? [];
        for (const useSpan of uses) {
          if (targets.length === 0) {
            if (importedModule.startsWith(".")) {
              const unknown = input.unknownTarget();
              addRelation(
                sourceComponent,
                [unknown],
                "renders",
                importedModule,
                context.entry.relativeFile,
                useSpan,
                nextCondition(sourceComponent.properties.environment as string, sourceMeta, context.routerKind),
                sourceComponent.properties.environment as string,
                "next_import_render_unresolved",
                "unresolved",
                raw?.reason ?? "typescript_component_target_unresolved",
                null,
                { typescript_site_key: raw?.key ?? "missing" },
              );
              addDiagnostic({
                severity: "warning",
                code: "web.next_component_import_unresolved",
                message: `JSX component import ${importedModule} in ${context.entry.relativeFile} has no canonical TypeChecker target`,
                path: context.entry.relativeFile,
                profile_id: PROFILE_ID,
                evidence: [evidence(context.entry.relativeFile, useSpan, "next_component_import_unresolved")[1]!],
                properties: { framework_semantic_issue: true },
              });
            }
            continue;
          }
          const uniqueTargets = [...new Map(targets.map((target) => [target.id, target])).values()]
            .sort((left, right) => compareUtf8(left.id, right.id));
          const status: ResolutionStatus = uniqueTargets.length === 1 ? "resolved" : "candidates";
          addRelation(
            sourceComponent,
            uniqueTargets,
            "renders",
            importedModule,
            context.entry.relativeFile,
            useSpan,
            nextCondition(sourceComponent.properties.environment as string, sourceMeta, context.routerKind),
            sourceComponent.properties.environment as string,
            "next_import_render",
            status,
            status === "candidates" ? "multiple_typechecker_component_targets" : null,
            status === "candidates" ? "next-typechecker-import-binding-v1" : null,
            { typescript_site_key: raw?.key ?? "missing" },
          );
          for (const target of uniqueTargets) {
            const targetPath = target.properties.source_path;
            if (typeof targetPath !== "string") continue;
            const targetMeta = metadataFor(targetPath);
            const client = targetMeta?.directives.find((directive) => directive.value === "use client");
            const server = targetMeta?.directives.find((directive) => directive.value === "use server");
            const sourceEnvironment = sourceComponent.properties.environment as string;
            if (client && sourceEnvironment !== preferredWebEnvironment("browser")) {
              addRelation(
                sourceComponent,
                [target],
                "client_boundary",
                importedModule,
                targetPath,
                client.span,
                nextCondition(target.properties.environment as string, targetMeta, context.routerKind),
                target.properties.environment as string,
                "next_client_boundary_import",
                "resolved",
                null,
                null,
                { directive: client.value, typescript_site_key: raw?.key ?? "missing" },
              );
            } else if (server && sourceEnvironment === preferredWebEnvironment("browser")) {
              addRelation(
                sourceComponent,
                [target],
                "server_boundary",
                importedModule,
                targetPath,
                server.span,
                nextCondition(target.properties.environment as string, targetMeta, context.routerKind),
                target.properties.environment as string,
                "next_server_boundary_import",
                "resolved",
                null,
                null,
                { directive: server.value, typescript_site_key: raw?.key ?? "missing" },
              );
            }
          }
        }
      }
    }
    visit(sourceMeta.sourceFile, (node) => {
      if (!isCallExpression(node) || !isIdentifier(node.expression) || !dynamicNames.has(node.expression.text)) return;
      const importCall = node.arguments[0] ? directDynamicImport(node.arguments[0]) : null;
      const anchor = spanFor(source, node.getStart(sourceMeta.sourceFile), node.getEnd());
      if (importCall === null) {
        const unknown = input.unknownTarget();
        addRelation(
          sourceComponent,
          [unknown],
          "renders",
          "next/dynamic",
          context.entry.relativeFile,
          anchor,
          nextCondition(sourceComponent.properties.environment as string, sourceMeta, context.routerKind),
          sourceComponent.properties.environment as string,
          "next_dynamic_render_unresolved",
          "unresolved",
          "next_dynamic_import_shape_unsupported",
        );
        addDiagnostic({
          severity: "warning",
          code: "web.next_dynamic_import_unresolved",
          message: `next/dynamic in ${context.entry.relativeFile} does not use the supported direct () => import("literal") loader shape`,
          path: context.entry.relativeFile,
          profile_id: PROFILE_ID,
          evidence: [evidence(context.entry.relativeFile, anchor, "next_dynamic_import_unresolved")[1]!],
          properties: { framework_semantic_issue: true },
        });
        return;
      }
      const argument = importCall.arguments[0];
      const moduleSpecifier = argument && (isStringLiteral(argument) || isNoSubstitutionTemplateLiteral(argument))
        ? argument.text
        : null;
      const raw = moduleSpecifier === null ? null : (
        dependencySitesByImport.get(importKey(context.entry.relativeFile, moduleSpecifier, null))
          ?.find((site) => site.evidence.occurrenceKind === "dynamic_import") ?? null
      );
      const definitionKeys: string[] = [];
      if (raw) {
        for (const target of raw.targets) {
          if (target.kind === "definition") definitionKeys.push(target.key);
          if (target.kind === "file") {
            definitionKeys.push(...exportedDefinitionKeys(target.relativePath, "default"));
          }
        }
      }
      const targets = [...new Map(definitionKeys
        .map((key) => componentForImportedDefinition(key, context.routerKind))
        .filter((target): target is GraphNode => target !== null)
        .map((target) => [target.id, target])).values()]
        .sort((left, right) => compareUtf8(left.id, right.id));
      if (moduleSpecifier === null || targets.length === 0) {
        const unknown = input.unknownTarget();
        addRelation(
          sourceComponent,
          [unknown],
          "renders",
          moduleSpecifier ?? "next/dynamic:<computed>",
          context.entry.relativeFile,
          anchor,
          nextCondition(sourceComponent.properties.environment as string, sourceMeta, context.routerKind),
          sourceComponent.properties.environment as string,
          "next_dynamic_render_unresolved",
          "unresolved",
          moduleSpecifier === null ? "next_dynamic_non_literal_import" : raw?.reason ?? "next_dynamic_default_export_unresolved",
          null,
          { typescript_site_key: raw?.key ?? "missing" },
        );
        addDiagnostic({
          severity: "warning",
          code: "web.next_dynamic_import_unresolved",
          message: moduleSpecifier === null
            ? `next/dynamic in ${context.entry.relativeFile} uses a computed import specifier`
            : `next/dynamic target ${moduleSpecifier} in ${context.entry.relativeFile} has no canonical default-export component`,
          path: context.entry.relativeFile,
          profile_id: PROFILE_ID,
          evidence: [evidence(context.entry.relativeFile, anchor, "next_dynamic_import_unresolved")[1]!],
          properties: { framework_semantic_issue: true },
        });
        return;
      }
      const status: ResolutionStatus = targets.length === 1 ? "resolved" : "candidates";
      addRelation(
        sourceComponent,
        targets,
        "renders",
        moduleSpecifier,
        context.entry.relativeFile,
        anchor,
        nextCondition(sourceComponent.properties.environment as string, sourceMeta, context.routerKind),
        sourceComponent.properties.environment as string,
        "next_dynamic_render",
        status,
        status === "candidates" ? "multiple_dynamic_default_export_targets" : null,
        status === "candidates" ? "next-typechecker-dynamic-import-v1" : null,
        { typescript_site_key: raw?.key ?? "missing" },
      );
    });
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

function positionOffset(source: string, line: number, column: number): number {
  const lines = source.split(/\r?\n/u);
  let offset = 0;
  for (let index = 0; index < line - 1; index += 1) offset += (lines[index]?.length ?? 0) + 1;
  return offset + column - 1;
}
