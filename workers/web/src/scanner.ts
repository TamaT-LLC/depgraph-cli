import path from "node:path";
import ts from "typescript";
import { normalizeRelative, readJson, readUtf8, WEB_SOURCE_EXTENSIONS, type FileInventoryIssue } from "./fs";
import { compareById, stableId } from "./ids";
import {
  extractDependencies,
  extractPotentialTypeScriptModuleSpecifiers,
  ModuleResolver,
  type RawDependency,
  type Resolution,
  type ResolvedTarget,
  type TypeScriptPathRequest,
} from "./imports";
import { discoverRoutes, type RouteEntry } from "./routes";
import { mergeTypeScriptDefinitionDelta, type TypeScriptDefinitionDelta } from "./semantic-delta";
import {
  analyzeTypeScriptProject,
  TYPESCRIPT_COMPILER_VERSION,
  TYPESCRIPT_SOURCE_EXTENSIONS,
  type TypeScriptProjectAnalysis,
} from "./typescript-compiler";
import type {
  TypeScriptRawDefinition,
  TypeScriptRawDefinitionDelta,
  TypeScriptRawDefinitionEndpoint,
  TypeScriptRawTypeArgumentDescriptor,
} from "./typescript-semantic";
import type {
  TypeScriptDependencyValidationSource,
  TypeScriptRawDependencyDelta,
  TypeScriptRawDependencySite,
  TypeScriptRawDependencyTarget,
} from "./typescript-dependencies";
import { validateTypeScriptRawDependencyDelta } from "./typescript-dependencies";
import {
  ADAPTER_VERSION,
  aggregateConditions,
  canonicalizeCondition,
  compareUtf8,
  PROFILE_CONFIG_ISSUE,
  PROFILE_ID,
  WEB_CONDITION,
  WEB_UNIVERSAL_ENVIRONMENT,
  preferredWebEnvironment,
  type Condition,
  type DependencySite,
  type Diagnostic,
  type Evidence,
  type FileCoverage,
  type GraphEdge,
  type GraphNode,
  type JsonValue,
  type ScanModel,
} from "./types";
import {
  discoverWorkspace,
  owningPackage,
  packageProperties,
  selectPackageInstallCandidates,
  type DependencySection,
  type PackageRecord,
  type Workspace,
} from "./workspace";

const PARSED_EXTENSIONS = new Set([".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs", ".astro"]);
const SOURCE_READ_CONCURRENCY = 64;
const MAX_SEMANTIC_OWNERSHIP_DEPTH = 512;
const MAX_SEMANTIC_TYPE_DESCRIPTOR_DEPTH = 64;
const MAX_SEMANTIC_TYPE_DESCRIPTOR_NODES = 2_048;
const MAX_SEMANTIC_RESOLVER_CHARS = 4_096;
const MAX_SEMANTIC_TYPE_DESCRIPTOR_CHARS = 2_048;
const MAX_TYPESCRIPT_REFINEMENT_TARGETS_PER_SITE = 4_096;

type SourceSpan = {
  start_line: number;
  start_column: number;
  end_line: number;
  end_column: number;
};

function rawDependencyTargetKey(target: TypeScriptRawDependencyTarget): string {
  switch (target.kind) {
    case "definition": return `definition:${target.key}`;
    case "file": return `file:${target.relativePath}`;
    case "external": return `external:${target.locator}:${target.displayName}`;
    case "unknown": return "unknown";
  }
}

function appendTargetCondition(map: Map<string, Condition[]>, key: string, condition: Condition): void {
  const values = map.get(key) ?? [];
  values.push(canonicalizeCondition(condition));
  map.set(key, values);
}

function sourceLineStarts(source: string): number[] {
  const starts = [0];
  for (let index = 0; index < source.length; index += 1) {
    if (source.charCodeAt(index) === 10) starts.push(index + 1);
  }
  return starts;
}

function sourcePosition(starts: readonly number[], offset: number): { line: number; column: number } {
  let low = 0;
  let high = starts.length;
  while (low + 1 < high) {
    const middle = low + Math.floor((high - low) / 2);
    if (starts[middle]! <= offset) low = middle;
    else high = middle;
  }
  return { line: low + 1, column: offset - starts[low]! + 1 };
}

function sourceSpan(starts: readonly number[], startOffset: number, endOffset: number): SourceSpan {
  const start = sourcePosition(starts, startOffset);
  const end = sourcePosition(starts, endOffset);
  return {
    start_line: start.line,
    start_column: start.column,
    end_line: end.line,
    end_column: end.column,
  };
}

class GraphBuilder {
  nodes = new Map<string, GraphNode>();
  readonly sites = new Map<string, DependencySite>();
  edges = new Map<string, GraphEdge>();
  readonly diagnostics = new Map<string, Diagnostic>();
  readonly files = new Map<string, FileCoverage>();
  readonly #fileNodesByPath = new Map<string, GraphNode>();
  readonly #workspace: Workspace;

  constructor(workspace: Workspace) {
    this.#workspace = workspace;
  }

  addNode(node: GraphNode): GraphNode {
    const existing = this.nodes.get(node.id);
    if (existing && JSON.stringify(existing) !== JSON.stringify(node)) {
      throw new Error(`conflicting node upsert for ${node.id}`);
    }
    this.nodes.set(node.id, existing ?? node);
    return existing ?? node;
  }

  addSite(site: DependencySite): void {
    const existing = this.sites.get(site.id);
    if (existing && JSON.stringify(existing) !== JSON.stringify(site)) throw new Error(`conflicting site upsert for ${site.id}`);
    this.sites.set(site.id, existing ?? site);
  }

  addEdge(edge: GraphEdge): void {
    const existing = this.edges.get(edge.id);
    if (!existing) {
      this.edges.set(edge.id, edge);
      return;
    }
    if (
      existing.source !== edge.source
      || existing.target !== edge.target
      || existing.kind !== edge.kind
      || existing.resolution_status !== edge.resolution_status
    ) throw new Error(`conflicting edge upsert for ${edge.id}`);
    const evidence = [...existing.evidence, ...edge.evidence]
      .filter((item, index, array) => array.findIndex((candidate) => JSON.stringify(candidate) === JSON.stringify(item)) === index)
      .sort((left, right) => compareUtf8(JSON.stringify(left), JSON.stringify(right)));
    this.edges.set(edge.id, { ...existing, evidence });
  }

  mergeTypeScriptSemanticGraph(
    rawDelta: Pick<TypeScriptRawDefinitionDelta, "definitions" | "relations">,
    dependencyDelta: TypeScriptRawDependencyDelta,
    sources: ReadonlyMap<string, string>,
  ): { nodes: number; relations: number; sites: number } {
    const definitions = new Map<string, TypeScriptRawDefinition>();
    const rawResolvers = new Map<string, string>();
    for (const definition of rawDelta.definitions) {
      if (definitions.has(definition.key)) throw new Error(`duplicate TypeScript semantic definition key ${definition.key}`);
      definitions.set(definition.key, definition);
      if (definition.resolverIdentity !== null) {
        const existing = rawResolvers.get(definition.resolverIdentity);
        if (existing !== undefined && existing !== definition.key) {
          throw new Error("duplicate TypeScript semantic canonical resolver");
        }
        rawResolvers.set(definition.resolverIdentity, definition.key);
      }
    }
    const materialized = new Map<string, GraphNode>();
    const materializedIds = new Map<string, string>();
    const visiting = new Set<string>();
    const lineStarts = new Map<string, number[]>();
    const startsFor = (relativePath: string): number[] => {
      const existing = lineStarts.get(relativePath);
      if (existing) return existing;
      const source = sources.get(relativePath);
      if (source === undefined) throw new Error(`TypeScript semantic definition references missing source ${relativePath}`);
      const starts = sourceLineStarts(source);
      lineStarts.set(relativePath, starts);
      return starts;
    };
    const existingFile = (relativePath: string): GraphNode => {
      const node = this.#fileNodesByPath.get(path.resolve(this.#workspace.root, relativePath));
      if (!node) throw new Error(`TypeScript semantic definition references unknown file ${relativePath}`);
      return node;
    };
    const identityPackage = (
      definition: TypeScriptRawDefinition,
      seen = new Set<string>(),
      depth = 0,
    ): PackageRecord => {
      if (depth > MAX_SEMANTIC_OWNERSHIP_DEPTH || !seen.add(definition.key)) {
        throw new Error("TypeScript generic origin cycle or depth limit exceeded");
      }
      if (definition.genericOrigin !== undefined) {
        const origin = definitions.get(definition.genericOrigin);
        if (!origin) throw new Error(`generic TypeScript definition ${definition.key} has no origin`);
        return identityPackage(origin, seen, depth + 1);
      }
      return owningPackage(this.#workspace, path.join(this.#workspace.root, definition.relativePath));
    };
    const canonicalResolver = (
      definition: TypeScriptRawDefinition,
      active = new Set<string>(),
      depth = 0,
    ): string => {
      if (depth > MAX_SEMANTIC_OWNERSHIP_DEPTH || active.has(definition.key)) {
        throw new Error("TypeScript canonical resolver cycle or depth limit exceeded");
      }
      active.add(definition.key);
      try {
        if (definition.resolverIdentity === null) throw new Error(`named TypeScript definition ${definition.key} has no resolver identity`);
        let resolver: string;
        if (definition.genericOrigin !== undefined) {
          const origin = definitions.get(definition.genericOrigin);
          if (!origin) throw new Error(`generic TypeScript definition ${definition.key} has no origin`);
          resolver = `generic:${JSON.stringify([
            canonicalResolver(origin, active, depth + 1),
            (definition.typeArguments ?? []).map((argument) => canonicalTypeArgument(argument, {
              nodes: 0,
              activeResolvers: active,
            })),
          ])}`;
        } else {
          const owner = identityPackage(definition);
          resolver = `definition:${JSON.stringify(["package", owner.locator, definition.resolverIdentity])}`;
        }
        if (resolver.length > MAX_SEMANTIC_RESOLVER_CHARS) {
          throw new Error("TypeScript canonical resolver exceeds its UTF-16 length limit");
        }
        return resolver;
      } finally {
        active.delete(definition.key);
      }
    };
    const canonicalDefinitionReference = (key: string, activeResolvers = new Set<string>()): string => {
      const definition = definitions.get(key);
      if (!definition) throw new Error(`TypeScript type argument references missing definition ${key}`);
      return definition.resolverIdentity === null
        ? `node:${materializeDefinition(key).id}`
        : canonicalResolver(definition, activeResolvers);
    };
    const canonicalTypeArgument = (
      descriptor: TypeScriptRawTypeArgumentDescriptor,
      budget: { nodes: number; activeResolvers: Set<string> },
      depth = 0,
    ): JsonValue => {
      budget.nodes += 1;
      if (
        depth > MAX_SEMANTIC_TYPE_DESCRIPTOR_DEPTH
        || budget.nodes > MAX_SEMANTIC_TYPE_DESCRIPTOR_NODES
      ) throw new Error("TypeScript semantic type descriptor depth or node limit exceeded");
      let result: JsonValue;
      switch (descriptor.kind) {
        case "intrinsic":
          result = { kind: "intrinsic", name: descriptor.name };
          break;
        case "literal":
          result = { kind: "literal", value_kind: descriptor.valueKind, value: descriptor.value };
          break;
        case "definition":
          result = {
            kind: "definition",
            resolver_identity: canonicalDefinitionReference(descriptor.key, budget.activeResolvers),
          };
          break;
        case "type_parameter":
          result = {
            kind: "type_parameter",
            owner: canonicalDefinitionReference(descriptor.owner, budget.activeResolvers),
            index: descriptor.index,
            name: descriptor.name,
          };
          break;
        case "application":
          result = {
            kind: "application",
            target: canonicalTypeArgument(descriptor.target, budget, depth + 1),
            type_arguments: descriptor.typeArguments.map((argument) => canonicalTypeArgument(argument, budget, depth + 1)),
          };
          break;
        case "union":
        case "intersection":
          result = {
            kind: descriptor.kind,
            members: descriptor.members
              .map((member) => canonicalTypeArgument(member, budget, depth + 1))
              .sort((left, right) => {
                const leftKey = JSON.stringify(left);
                const rightKey = JSON.stringify(right);
                return leftKey < rightKey ? -1 : leftKey > rightKey ? 1 : 0;
              }),
          };
          break;
      }
      if (JSON.stringify(result).length > MAX_SEMANTIC_TYPE_DESCRIPTOR_CHARS) {
        throw new Error("TypeScript canonical type descriptor exceeds its UTF-16 length limit");
      }
      return result;
    };
    const resolveEndpoint = (endpoint: TypeScriptRawDefinitionEndpoint, depth = 0): GraphNode => (
      endpoint.kind === "file" ? existingFile(endpoint.relativePath) : materializeDefinition(endpoint.key, depth + 1)
    );
    const materializeDefinition = (key: string, depth = 0): GraphNode => {
      if (depth > MAX_SEMANTIC_OWNERSHIP_DEPTH) {
        throw new Error("TypeScript semantic definition ownership depth limit exceeded");
      }
      const existing = materialized.get(key);
      if (existing) return existing;
      if (visiting.has(key)) throw new Error(`TypeScript semantic definition ownership cycle at ${key}`);
      const definition = definitions.get(key);
      if (!definition) throw new Error(`TypeScript semantic definition is missing ${key}`);
      visiting.add(key);
      try {
        const ownerPackage = identityPackage(definition);
        const span = sourceSpan(startsFor(definition.relativePath), definition.startOffset, definition.endOffset);
        let canonicalIdentity: Record<string, JsonValue>;
        let resolverIdentity: string | null = null;
        if (definition.graphKind === "type") {
          resolverIdentity = canonicalResolver(definition);
          canonicalIdentity = {
            language: definition.language,
            package_locator: ownerPackage.locator,
            type_kind: definition.semanticKind,
            resolver_identity: resolverIdentity,
          };
          if (definition.genericOrigin !== undefined) {
            const origin = definitions.get(definition.genericOrigin);
            if (!origin) throw new Error(`generic TypeScript definition ${key} has no origin`);
            canonicalIdentity.generic_origin = canonicalResolver(origin);
            canonicalIdentity.type_arguments = (definition.typeArguments ?? []).map((argument) => canonicalTypeArgument(argument, {
              nodes: 0,
              activeResolvers: new Set(),
            }));
          }
        } else if (definition.identityKind === "named") {
          resolverIdentity = canonicalResolver(definition);
          canonicalIdentity = {
            language: definition.language,
            package_locator: ownerPackage.locator,
            symbol_kind: definition.semanticKind,
            identity_kind: "named",
            resolver_identity: resolverIdentity,
          };
        } else if (definition.identityKind === "local" || definition.identityKind === "anonymous") {
          const origin = resolveEndpoint(definition.owner, depth);
          if (definition.identityKind === "local" && origin.kind !== "symbol") {
            throw new Error(`local TypeScript definition ${key} has a non-symbol enclosing owner`);
          }
          canonicalIdentity = {
            language: definition.language,
            package_locator: ownerPackage.locator,
            symbol_kind: definition.semanticKind,
            identity_kind: definition.identityKind,
            ...(definition.identityKind === "local" ? { enclosing_symbol: origin.id } : { generated_from: origin.id }),
            relative_path: definition.relativePath,
            span,
          };
        } else {
          throw new Error(`TypeScript symbol ${key} has an invalid identity kind`);
        }
        const id = stableId(definition.graphKind, canonicalIdentity);
        const file = existingFile(definition.relativePath);
        const node: GraphNode = {
          id,
          kind: definition.graphKind,
          locator: `${definition.language}-${definition.graphKind}:${id}`,
          display_name: definition.displayName,
          properties: {
            language: definition.language,
            package_locator: ownerPackage.locator,
            package_id: ownerPackage.id,
            [definition.graphKind === "symbol" ? "symbol_kind" : "type_kind"]: definition.semanticKind,
            canonical_identity: canonicalIdentity,
            profile_id: PROFILE_ID,
            source_path: definition.relativePath,
            source_span: span,
            generated: file.properties.generated === true,
            typescript_provenance: "typescript-native-typechecker",
            ...(resolverIdentity === null ? {} : { resolver_identity: resolverIdentity }),
            ...(definition.genericOrigin === undefined ? {} : {
              generic_origin: canonicalIdentity.generic_origin!,
              type_arguments: canonicalIdentity.type_arguments!,
            }),
          },
        };
        const existingKey = materializedIds.get(node.id);
        if (existingKey !== undefined && existingKey !== key) {
          throw new Error("TypeScript semantic definitions collided on a canonical node ID");
        }
        materializedIds.set(node.id, key);
        materialized.set(key, node);
        return node;
      } finally {
        visiting.delete(key);
      }
    };

    const nodes = rawDelta.definitions.map((definition) => materializeDefinition(definition.key));
    const edges = rawDelta.relations.map((relation): GraphEdge => {
      const source = resolveEndpoint(relation.source);
      const target = materializeDefinition(relation.target);
      const span = sourceSpan(
        startsFor(relation.evidence.relativePath),
        relation.evidence.startOffset,
        relation.evidence.endOffset,
      );
      const evidence: Evidence = {
        kind: "semantic",
        extractor: "typescript-native-typechecker",
        extractor_version: TYPESCRIPT_COMPILER_VERSION,
        path: relation.evidence.relativePath,
        ...span,
        detail: relation.evidence.detail,
        properties: {
          backend: "typescript-native-compiler",
          compiler_source: "bundled",
          compiler_version: TYPESCRIPT_COMPILER_VERSION,
          analysis_mode: "semantic-import-type-graph",
          profile_id: PROFILE_ID,
          project_code_executed: false,
          relation_kind: relation.kind,
        },
      };
      const id = stableId("edge", {
        condition: WEB_CONDITION,
        kind: relation.kind,
        profile_id: PROFILE_ID,
        source: source.id,
        target: target.id,
        path: evidence.path,
        span,
      });
      return {
        id,
        source: source.id,
        target: target.id,
        kind: relation.kind,
        site_id: null,
        phase: "semantic",
        environment: "any",
        profile_id: PROFILE_ID,
        condition: WEB_CONDITION,
        resolution_status: "resolved",
        precision: "exact",
        generated: existingFile(relation.evidence.relativePath).properties.generated === true,
        evidence: [evidence],
      };
    });
    const delta: TypeScriptDefinitionDelta = { nodes, edges };
    const merged = mergeTypeScriptDefinitionDelta(this.nodes, this.edges, delta, {
      profileId: PROFILE_ID,
      compilerVersion: TYPESCRIPT_COMPILER_VERSION,
    });
    const nextNodes = new Map(merged.nodes);
    const nextSites = new Map(this.sites);
    const nextEdges = new Map(merged.edges);
    const coverageDeltas = new Map<string, Record<"resolved" | "candidates" | "external" | "unresolved", number>>();
    const unknownTarget = (): GraphNode => ({
      id: stableId("unknown", {
        repository: this.#workspace.repositoryIdentity,
        profile: PROFILE_ID,
        language: "web",
        identity: "unresolved_dependency_target",
      }),
      kind: "unknown_target",
      locator: "unknown://web/unresolved-dependency",
      display_name: "Unresolved web dependency",
      properties: { language: "web", profile_id: PROFILE_ID },
    });
    const externalTarget = (target: Extract<TypeScriptRawDependencyTarget, { kind: "external" }>): GraphNode => {
      const canonicalIdentity = {
        language: "typescript",
        compiler_version: TYPESCRIPT_COMPILER_VERSION,
        locator: target.locator,
      };
      const id = stableId("external", canonicalIdentity);
      return {
        id,
        kind: "external_system",
        locator: `external://typescript/${encodeURIComponent(target.locator)}`,
        // Node identity is package/compiler boundary scoped, not binding
        // scoped. Keep display stable when several imported names share it.
        display_name: target.locator,
        properties: {
          language: "typescript",
          external: true,
          canonical_identity: canonicalIdentity,
          profile_id: PROFILE_ID,
          compiler_version: TYPESCRIPT_COMPILER_VERSION,
        },
      };
    };
    const insertNode = (node: GraphNode): GraphNode => {
      const existing = nextNodes.get(node.id);
      if (existing !== undefined && JSON.stringify(existing) !== JSON.stringify(node)) {
        throw new Error(`TypeScript dependency delta conflicts with node ${node.id}`);
      }
      nextNodes.set(node.id, existing ?? node);
      return existing ?? node;
    };
    const dependencyTarget = (target: TypeScriptRawDependencyTarget): GraphNode => {
      switch (target.kind) {
        case "definition": return materializeDefinition(target.key);
        case "file": return existingFile(target.relativePath);
        case "external": return insertNode(externalTarget(target));
        case "unknown": return insertNode(unknownTarget());
      }
    };
    const endpointPath = (endpoint: TypeScriptRawDefinitionEndpoint): string => (
      endpoint.kind === "file"
        ? endpoint.relativePath
        : definitions.get(endpoint.key)?.relativePath ?? (() => { throw new Error(`dependency source definition is missing ${endpoint.key}`); })()
    );
    const semanticSites: DependencySite[] = [];
    const semanticEdges: GraphEdge[] = [];
    let previousRawKey = "";
    for (const raw of dependencyDelta.sites) {
      if (previousRawKey !== "" && previousRawKey >= raw.key) throw new Error("TypeScript dependency sites are not in strict canonical order");
      previousRawKey = raw.key;
      const emptyModuleSpecifier = raw.moduleSpecifier === ""
        && raw.kind !== "type_use"
        && raw.specifier === "";
      if ((raw.specifier.length === 0 && !emptyModuleSpecifier) || raw.specifier.length > 2_048) {
        throw new Error("TypeScript dependency site has an invalid specifier");
      }
      if (typeof raw.typeOnly !== "boolean") throw new Error("TypeScript dependency site has an invalid type-only marker");
      if (raw.resolutionMode !== null && raw.resolutionMode !== "import" && raw.resolutionMode !== "require") {
        throw new Error("TypeScript dependency site has an invalid resolution mode");
      }
      if (raw.resolutionMode !== null && (!raw.typeOnly || raw.moduleSpecifier === null)) {
        throw new Error("TypeScript dependency site resolution mode contradicts its occurrence");
      }
      if (raw.resolutionMode !== null && raw.evidence.occurrenceKind === "import_equals") {
        throw new Error("TypeScript import-equals dependency site cannot expose a resolution mode");
      }
      const emptyModuleExportName = raw.importedName === ""
        && raw.exportPath?.length === 1
        && raw.exportPath[0] === ""
        && ["default_import", "named_import", "named_reexport"].includes(raw.evidence.occurrenceKind);
      if (
        (raw.moduleSpecifier !== null && raw.moduleSpecifier.length > 2_048)
        || (raw.importedName !== null && (
          (raw.importedName.length === 0 && !emptyModuleExportName)
          || raw.importedName.length > 512
        ))
      ) throw new Error("TypeScript dependency binding metadata is invalid");
      if (raw.targets.length === 0) throw new Error("TypeScript dependency site has no target");
      if (raw.targetConditions.length !== raw.targets.length) {
        throw new Error("TypeScript dependency target conditions do not align with targets");
      }
      if (
        JSON.stringify(raw.condition) !== JSON.stringify(canonicalizeCondition(raw.condition))
        || JSON.stringify(raw.condition) !== JSON.stringify(aggregateConditions(raw.targetConditions))
      ) throw new Error("TypeScript dependency site condition is not its canonical target-condition aggregate");
      const expectedEdgeKind = raw.kind === "web_import" ? "imports" : raw.kind === "web_reexport" ? "reexports" : "type_uses";
      if (raw.edgeKind !== expectedEdgeKind) throw new Error("TypeScript dependency site kind and edge kind disagree");
      const source = resolveEndpoint(raw.source);
      const sourcePath = endpointPath(raw.source);
      if (sourcePath !== raw.evidence.relativePath) throw new Error("TypeScript dependency evidence is not anchored to its source endpoint");
      const evidenceSource = sources.get(raw.evidence.relativePath);
      if (
        evidenceSource === undefined
        || !Number.isSafeInteger(raw.evidence.startOffset)
        || !Number.isSafeInteger(raw.evidence.endOffset)
        || raw.evidence.startOffset < 0
        || raw.evidence.endOffset <= raw.evidence.startOffset
        || raw.evidence.endOffset > evidenceSource.length
      ) throw new Error("TypeScript dependency evidence has an invalid source span");
      const concreteTargets = raw.targets.map((target, index) => ({
        node: dependencyTarget(target),
        condition: canonicalizeCondition(raw.targetConditions[index]!),
      })).sort((left, right) => compareById(left.node, right.node));
      for (let index = 1; index < concreteTargets.length; index += 1) {
        if (concreteTargets[index - 1]!.node.id === concreteTargets[index]!.node.id) throw new Error("TypeScript dependency site repeats a target");
      }
      const targetKinds = new Set(concreteTargets.map(({ node }) => node.kind));
      if (
        (raw.status === "resolved" && (raw.precision !== "exact" || concreteTargets.length !== 1 || targetKinds.has("external_system") || targetKinds.has("unknown_target")))
        || (raw.status === "candidates" && (raw.precision !== "overapprox" || concreteTargets.length < 1 || targetKinds.has("external_system") || targetKinds.has("unknown_target")))
        || (raw.status === "external" && (concreteTargets.length !== 1 || !targetKinds.has("external_system") || (raw.precision !== "exact" && raw.precision !== "heuristic")))
        || (raw.status === "unresolved" && (raw.precision !== "heuristic" || concreteTargets.length !== 1 || !targetKinds.has("unknown_target") || !raw.reason))
      ) throw new Error("TypeScript dependency site has an invalid status/precision/target combination");
      if (raw.kind === "type_use" && concreteTargets.some(({ node }) => node.kind !== "type" && node.kind !== "external_system" && node.kind !== "unknown_target")) {
        throw new Error("TypeScript type-use target is not a type or sentinel");
      }
      const span = sourceSpan(startsFor(raw.evidence.relativePath), raw.evidence.startOffset, raw.evidence.endOffset);
      const evidenceProperties = {
        backend: "typescript-native-compiler",
        compiler_source: "bundled",
        compiler_version: TYPESCRIPT_COMPILER_VERSION,
        analysis_mode: "semantic-import-type-graph",
        profile_id: PROFILE_ID,
        project_code_executed: false,
        occurrence_kind: raw.evidence.occurrenceKind,
        target_basis: raw.evidence.targetBasis,
        type_only: raw.typeOnly,
        ...(raw.resolutionMode === null ? {} : { resolution_mode: raw.resolutionMode }),
        ...(raw.moduleSpecifier === null ? {} : { module_specifier: raw.moduleSpecifier }),
        ...(raw.importedName === null ? {} : { imported_name: raw.importedName }),
      } as const;
      const primary: Evidence = {
        kind: "semantic",
        extractor: "typescript-native-typechecker",
        extractor_version: TYPESCRIPT_COMPILER_VERSION,
        path: raw.evidence.relativePath,
        ...span,
        detail: raw.evidence.detail,
        properties: evidenceProperties,
      };
      const supporting: Evidence = {
        kind: "source",
        extractor: "typescript-native-syntax",
        extractor_version: TYPESCRIPT_COMPILER_VERSION,
        path: raw.evidence.relativePath,
        ...span,
        detail: `syntax occurrence for ${raw.evidence.occurrenceKind}`,
        properties: { profile_id: PROFILE_ID, occurrence_kind: raw.evidence.occurrenceKind },
      };
      const siteId = stableId("site", {
        source: source.id,
        kind: raw.kind,
        profile_id: PROFILE_ID,
        condition: raw.condition,
        path: primary.path,
        span,
      });
      const site: DependencySite = {
        id: siteId,
        source: source.id,
        kind: raw.kind,
        specifier: raw.specifier,
        resolution_status: raw.status,
        target_ids: concreteTargets.map(({ node }) => node.id),
        profile_id: PROFILE_ID,
        condition: raw.condition,
        precision: raw.precision,
        reason: raw.reason,
        evidence: [primary, supporting],
      };
      const existingSite = nextSites.get(site.id);
      if (existingSite !== undefined && JSON.stringify(existingSite) !== JSON.stringify(site)) throw new Error(`TypeScript dependency delta conflicts with site ${site.id}`);
      nextSites.set(site.id, existingSite ?? site);
      semanticSites.push(site);
      for (const { node: target, condition } of concreteTargets) {
        const edge: GraphEdge = {
          id: stableId("edge", { site_id: siteId, kind: raw.edgeKind, target: target.id }),
          source: source.id,
          target: target.id,
          kind: raw.edgeKind,
          site_id: siteId,
          phase: "semantic",
          environment: "any",
          profile_id: PROFILE_ID,
          condition,
          resolution_status: raw.status,
          precision: raw.precision,
          generated: existingFile(raw.evidence.relativePath).properties.generated === true,
          evidence: [primary, supporting],
        };
        const existingEdge = nextEdges.get(edge.id);
        if (existingEdge !== undefined && JSON.stringify(existingEdge) !== JSON.stringify(edge)) throw new Error(`TypeScript dependency delta conflicts with edge ${edge.id}`);
        nextEdges.set(edge.id, existingEdge ?? edge);
        semanticEdges.push(edge);
      }
      const counts = coverageDeltas.get(raw.evidence.relativePath) ?? { resolved: 0, candidates: 0, external: 0, unresolved: 0 };
      counts[raw.status] += 1;
      coverageDeltas.set(raw.evidence.relativePath, counts);
    }
    const nextFiles = new Map([...this.files].map(([relativePath, coverage]) => [relativePath, { ...coverage }]));
    for (const [relativePath, counts] of coverageDeltas) {
      const coverage = nextFiles.get(relativePath);
      if (!coverage) throw new Error(`semantic coverage missing for ${relativePath}`);
      const total = counts.resolved + counts.candidates + counts.external + counts.unresolved;
      coverage.expected_sites += total;
      coverage.produced_sites += total;
      coverage.resolved += counts.resolved;
      coverage.candidates += counts.candidates;
      coverage.external += counts.external;
      coverage.unresolved += counts.unresolved;
    }
    // Swap all graph maps and coverage counters only after every node/site/edge
    // has passed validation. A late dependency failure therefore preserves the
    // complete pre-existing syntax graph and ledger.
    this.nodes = nextNodes;
    this.sites.clear();
    for (const [id, site] of nextSites) this.sites.set(id, site);
    this.edges = nextEdges;
    this.files.clear();
    for (const [relativePath, coverage] of nextFiles) this.files.set(relativePath, coverage);
    return { nodes: nodes.length, relations: edges.length + semanticEdges.length, sites: semanticSites.length };
  }

  addDiagnostic(diagnostic: Omit<Diagnostic, "id">): void {
    const id = stableId("diagnostic", {
      repository: this.#workspace.repositoryIdentity,
      code: diagnostic.code,
      message: diagnostic.message,
      path: diagnostic.path,
      profile: diagnostic.profile_id,
      evidence: (diagnostic.evidence ?? []).map((evidence) => ({
        kind: evidence.kind,
        extractor: evidence.extractor,
        extractor_version: evidence.extractor_version,
        path: evidence.path,
        start_line: evidence.start_line,
        start_column: evidence.start_column,
        end_line: evidence.end_line,
        end_column: evidence.end_column,
      })),
    });
    this.diagnostics.set(id, { id, ...diagnostic });
  }

  fileNode(absoluteFile: string, generated = false): GraphNode {
    const absolute = path.resolve(absoluteFile);
    const existing = this.#fileNodesByPath.get(absolute);
    if (existing) return existing;
    const relative = normalizeRelative(path.relative(this.#workspace.root, absolute));
    const owner = owningPackage(this.#workspace, absolute);
    const extension = path.extname(relative).toLowerCase();
    const id = stableId("file", {
      repository: this.#workspace.repositoryIdentity,
      workspace: owner.relativePath,
      package: owner.locator,
      path: relative,
      profile: PROFILE_ID,
      language: "web",
    });
    const node: GraphNode = {
      id,
      kind: "file",
      locator: `file://${relative}`,
      display_name: relative,
      properties: {
        path: relative,
        extension,
        language: extension === ".astro" ? "astro" : [".ts", ".tsx", ".mts", ".cts"].includes(extension) ? "typescript" : [".js", ".jsx", ".mjs", ".cjs"].includes(extension) ? "javascript" : "data",
        package_id: owner.id,
        generated,
      },
    };
    this.#fileNodesByPath.set(absolute, node);
    return this.addNode(node);
  }

  unknownNode(): GraphNode {
    return this.addNode({
      id: stableId("unknown", {
        repository: this.#workspace.repositoryIdentity,
        profile: PROFILE_ID,
        language: "web",
        identity: "unresolved_dependency_target",
      }),
      kind: "unknown_target",
      locator: "unknown://web/unresolved-dependency",
      display_name: "Unresolved web dependency",
      properties: { language: "web", profile_id: PROFILE_ID },
    });
  }

  targetNode(target: ResolvedTarget): GraphNode {
    if (target.kind === "file") return this.fileNode(target.absolutePath);
    if (target.kind === "workspace_package") return this.nodes.get(target.package.id) ?? this.addPackageNode(target.package);
    const id = stableId("package", {
      manager: this.#workspace.manager,
      locator: target.locator,
      profile: PROFILE_ID,
      language: "web",
    });
    return this.addNode({
      id,
      kind: "external_system",
      locator: `package://${target.locator}`,
      display_name: target.name,
      properties: {
        name: target.name,
        version: target.version,
        package_manager: this.#workspace.manager,
        locator: target.locator,
        workspace: false,
        external: true,
      },
    });
  }

  addPackageNode(record: PackageRecord): GraphNode {
    return this.addNode({
      id: record.id,
      kind: "package_instance",
      locator: `package://${record.locator}`,
      display_name: record.name,
      properties: packageProperties(record, this.#workspace.manager),
    });
  }

  routeNode(entry: RouteEntry, owner: PackageRecord): GraphNode {
    const environment = preferredWebEnvironment("server");
    const id = stableId("route", {
      repository: this.#workspace.repositoryIdentity,
      workspace: owner.relativePath,
      package: owner.locator,
      framework: entry.framework,
      router_instance: owner.id,
      pattern: entry.pattern,
      environment,
      profile: PROFILE_ID,
    });
    return this.addNode({
      id,
      kind: "route",
      locator: `route://${entry.framework}/${owner.name}${entry.pattern}`,
      display_name: `${entry.framework}:${entry.pattern}`,
      properties: {
        framework: entry.framework,
        pattern: entry.pattern,
        router_instance: owner.id,
        package_id: owner.id,
        environment,
      },
    });
  }

  structureEdge(source: GraphNode, target: GraphNode, kind: string, evidence: Evidence, generated = false): void {
    const id = stableId("edge", {
      repository: this.#workspace.repositoryIdentity,
      source: source.id,
      target: target.id,
      kind,
      profile: PROFILE_ID,
      site: null,
    });
    this.addEdge({
      id,
      source: source.id,
      target: target.id,
      kind,
      site_id: null,
      phase: "source",
      environment: WEB_UNIVERSAL_ENVIRONMENT,
      profile_id: PROFILE_ID,
      condition: WEB_CONDITION,
      resolution_status: "resolved",
      precision: "exact",
      generated,
      evidence: [evidence],
    });
  }

  dependency(
    source: GraphNode,
    raw: Pick<RawDependency, "kind" | "edgeKind" | "specifier" | "evidence">,
    resolution: Resolution,
    generated = false,
  ): void {
    const condition = resolution.condition ?? WEB_CONDITION;
    const targets = resolution.targets.map((target, index) => ({
      node: this.targetNode(target),
      condition: resolution.targetConditions?.[index] ?? condition,
    }));
    if (resolution.status === "unresolved") targets.push({ node: this.unknownNode(), condition });
    targets.sort((left, right) => compareById(left.node, right.node));
    const siteId = stableId("site", {
      repository: this.#workspace.repositoryIdentity,
      source: source.id,
      kind: raw.kind,
      specifier: raw.specifier,
      profile: PROFILE_ID,
      path: raw.evidence.path,
      start_line: raw.evidence.start_line,
      start_column: raw.evidence.start_column,
    });
    this.addSite({
      id: siteId,
      source: source.id,
      kind: raw.kind,
      specifier: raw.specifier,
      resolution_status: resolution.status,
      target_ids: targets.map((target) => target.node.id),
      profile_id: PROFILE_ID,
      condition,
      precision: resolution.precision,
      reason: resolution.reason,
      evidence: [raw.evidence],
    });
    for (const target of targets) {
      const edgeId = stableId("edge", {
        repository: this.#workspace.repositoryIdentity,
        source: source.id,
        target: target.node.id,
        kind: raw.edgeKind,
        profile: PROFILE_ID,
        site: siteId,
      });
      this.addEdge({
        id: edgeId,
        source: source.id,
        target: target.node.id,
        kind: raw.edgeKind,
        site_id: siteId,
        phase: "source",
        environment: raw.edgeKind === "imports" || raw.edgeKind === "reexports" ? WEB_UNIVERSAL_ENVIRONMENT : preferredWebEnvironment("browser"),
        profile_id: PROFILE_ID,
        condition: target.condition,
        resolution_status: resolution.status,
        precision: resolution.precision,
        generated,
        evidence: [raw.evidence],
      });
    }
  }

  ensureCoverage(fileNode: GraphNode, pathValue: string): FileCoverage {
    let coverage = this.files.get(pathValue);
    if (!coverage) {
      coverage = {
        file_id: fileNode.id,
        path: pathValue,
        expected_sites: 0,
        produced_sites: 0,
        skipped_sites: 0,
        resolved: 0,
        candidates: 0,
        external: 0,
        unresolved: 0,
        unsupported_syntax: 0,
      };
      this.files.set(pathValue, coverage);
    }
    return coverage;
  }

  countSite(pathValue: string, status: Resolution["status"]): void {
    const coverage = this.files.get(pathValue);
    if (!coverage) throw new Error(`coverage missing for ${pathValue}`);
    coverage.expected_sites += 1;
    coverage.produced_sites += 1;
    coverage[status] += 1;
  }
}

function sourceEvidence(pathValue: string, extractor: string, detail?: string): Evidence {
  return {
    kind: "source",
    extractor,
    extractor_version: ADAPTER_VERSION,
    path: pathValue,
    start_line: 1,
    start_column: 1,
    end_line: 1,
    end_column: 1,
    ...(detail ? { detail } : {}),
  };
}

function syntaxEvidence(source: string, pathValue: string, startOffset: number, endOffset: number): Evidence {
  const position = (offset: number): { line: number; column: number } => {
    const lines = source.slice(0, Math.max(0, offset)).split(/\r?\n/u);
    return { line: lines.length, column: (lines.at(-1)?.length ?? 0) + 1 };
  };
  const start = position(startOffset);
  const end = position(endOffset);
  return {
    kind: "source",
    extractor: "typescript-native-syntax",
    extractor_version: "7.0.2",
    path: pathValue,
    start_line: start.line,
    start_column: start.column,
    end_line: end.line,
    end_column: end.column,
  };
}

function semanticEvidence(source: string, pathValue: string, startOffset: number, endOffset: number): Evidence {
  const syntax = syntaxEvidence(source, pathValue, startOffset, endOffset);
  return {
    ...syntax,
    kind: "semantic",
    extractor: "typescript-native-typechecker",
  };
}

export function buildTypeScriptDependencyValidationSources(
  sources: ReadonlyMap<string, string>,
  analysis: TypeScriptProjectAnalysis,
): TypeScriptDependencyValidationSource[] {
  return [...sources]
    .sort(([left], [right]) => compareUtf8(left, right))
    .map(([relativePath, text]) => {
      const diagnostics = analysis.get(relativePath);
      const importTypeModuleSpans = analysis.importTypeModuleSpans.get(relativePath);
      const moduleCallSpans = analysis.moduleCallSpans.get(relativePath);
      const nonLiteralModuleSpans = analysis.nonLiteralModuleSpans.get(relativePath);
      const typeUseSpans = analysis.typeUseSpans.get(relativePath);
      if (
        diagnostics === undefined
        || importTypeModuleSpans === undefined
        || moduleCallSpans === undefined
        || nonLiteralModuleSpans === undefined
        || typeUseSpans === undefined
      ) {
        throw new Error(`TypeScript dependency validation context is missing for ${relativePath}`);
      }
      return {
        relativePath,
        text,
        syntacticallyValid: diagnostics.length === 0,
        importTypeModuleSpans: importTypeModuleSpans.map((spanValue) => ({ ...spanValue })),
        moduleCallSpans: moduleCallSpans.map((spanValue) => ({ ...spanValue })),
        nonLiteralModuleSpans: nonLiteralModuleSpans.map((spanValue) => ({
          ...spanValue,
          bindingScope: spanValue.bindingScope === null ? null : { ...spanValue.bindingScope },
          resolutionModeProof: spanValue.resolutionModeProof === null ? null : { ...spanValue.resolutionModeProof },
        })),
        typeUseSpans: typeUseSpans.map((spanValue) => ({ ...spanValue })),
      };
    });
}

async function refineTypeScriptDependencyDelta(
  delta: TypeScriptRawDependencyDelta,
  definitions: TypeScriptRawDefinitionDelta,
  resolver: ModuleResolver,
  workspace: Workspace,
  root: string,
  sources: ReadonlyMap<string, string>,
  validationSources: readonly TypeScriptDependencyValidationSource[],
): Promise<TypeScriptRawDependencyDelta> {
  const definitionByKey = new Map(definitions.definitions.map((definition) => [definition.key, definition]));
  const moduleExportProofs = new Map(delta.moduleExports.map((proof) => [
    JSON.stringify([proof.relativePath, proof.exportPath]),
    proof.definitionKeys,
  ]));
  const refined: TypeScriptRawDependencySite[] = [];
  for (const site of delta.sites) {
    const source = sources.get(site.evidence.relativePath);
    if (source === undefined || !site.evidence.occurrenceKind) {
      refined.push(site);
      continue;
    }
    const moduleSpecifier = site.moduleSpecifier ?? site.specifier;
    const imported = site.importedName;
    const importEqualsOrigin = site.bindingKind === "import_equals"
      && (
        site.evidence.occurrenceKind === "import_equals"
        || site.bindingOrigin !== null
      );
    // Public resolutionMode records only an explicit resolution-mode
    // attribute. Import-equals still requires the CommonJS resolver phase,
    // so retain that implicit syntax fact only inside refinement.
    const effectiveResolutionMode = importEqualsOrigin ? "require" : site.resolutionMode;
    if (
      site.reason === "syntax_invalid"
      || site.reason === "invalid_resolution_mode"
      || site.reason === "duplicate_resolution_mode"
      || site.reason === "invalid_resolution_mode_syntax"
      || site.reason === "resolution_mode_attribute_required"
      || site.reason === "resolution_mode_requires_single_attribute"
      || site.reason === "resolution_mode_requires_type_only"
      || site.reason === "ambiguous_binding_provenance"
      || site.reason === "missing_module_specifier"
    ) {
      refined.push(site);
      continue;
    }
    if (site.kind === "type_use" && site.moduleSpecifier === null) {
      refined.push(site);
      continue;
    }
    if (moduleSpecifier.length === 0 || site.reason === "computed_module_specifier" || site.reason === "non_literal_module_specifier") {
      refined.push(site);
      continue;
    }
    const absoluteSource = path.join(root, ...site.evidence.relativePath.split("/"));
    const owner = owningPackage(workspace, absoluteSource);
    const resolution = await resolver.resolve({
      kind: site.evidence.occurrenceKind,
      edgeKind: site.kind === "web_reexport" ? "reexports" : "imports",
      specifier: moduleSpecifier,
      literal: true,
      typeOnly: site.typeOnly,
      // TypeScript's semantic module resolver always enables `types` unless
      // noDtsResolution is set; occurrence type-only-ness remains separate.
      useTypesCondition: true,
      ...(effectiveResolutionMode === null ? {} : { resolutionMode: effectiveResolutionMode }),
      evidence: syntaxEvidence(source, site.evidence.relativePath, site.evidence.startOffset, site.evidence.endOffset),
    }, absoluteSource, owner);
    if (resolution.targetConditions !== undefined && resolution.targetConditions.length !== resolution.targets.length) {
      throw new Error("TypeScript module resolution target conditions do not align with targets");
    }
    const resolutionTargetConditions = resolution.targets.map((_, index) => canonicalizeCondition(
      resolution.targetConditions?.[index] ?? resolution.condition ?? site.condition,
    ));
    const resolutionCondition = resolutionTargetConditions.length === 0
      ? canonicalizeCondition(resolution.condition ?? site.condition)
      : aggregateConditions(resolutionTargetConditions);
    const unresolvedCondition = canonicalizeCondition(site.condition);
    const unresolvedSite = (reason: string): TypeScriptRawDependencySite => ({
      ...site,
      status: "unresolved",
      precision: "heuristic",
      reason,
      condition: unresolvedCondition,
      targets: [{ kind: "unknown" }],
      targetConditions: [unresolvedCondition],
      evidence: { ...site.evidence, targetBasis: "unresolved" },
    });
    if (resolution.status === "unresolved") {
      refined.push(unresolvedSite(resolution.reason ?? site.reason ?? "module_target_unresolved"));
      continue;
    }
    if (resolution.precision === "heuristic" && resolution.status !== "external") {
      // A concrete repository target for only part of the active profile is
      // not a complete candidate set. The semantic contract has no mixed
      // concrete+unknown target shape, so fail the whole occurrence closed
      // instead of re-promoting the surviving branch to resolved/exact.
      refined.push(unresolvedSite(resolution.reason ?? "repository_resolution_incomplete"));
      continue;
    }
    const fileTargetConditions = new Map<string, Condition[]>();
    const externalTargetMap = new Map<string, {
      target: Extract<TypeScriptRawDependencyTarget, { kind: "external" }>;
      conditions: Condition[];
    }>();
    let targetLimitExceeded = false;
    for (const [index, target] of resolution.targets.entries()) {
      const targetCondition = resolutionTargetConditions[index]!;
      if (target.kind === "file") {
        const relativePath = normalizeRelative(path.relative(root, target.absolutePath));
        if (!fileTargetConditions.has(relativePath) && fileTargetConditions.size >= MAX_TYPESCRIPT_REFINEMENT_TARGETS_PER_SITE) {
          targetLimitExceeded = true;
          break;
        }
        appendTargetCondition(fileTargetConditions, relativePath, targetCondition);
      } else if (target.kind === "external_package") {
        const locator = target.locator.startsWith("node:") ? target.locator : `package:${target.locator}`;
        if (!externalTargetMap.has(locator) && externalTargetMap.size >= MAX_TYPESCRIPT_REFINEMENT_TARGETS_PER_SITE) {
          targetLimitExceeded = true;
          break;
        }
        const existing = externalTargetMap.get(locator);
        if (existing === undefined) {
          externalTargetMap.set(locator, {
            target: { kind: "external", locator, displayName: target.locator },
            conditions: [targetCondition],
          });
        } else {
          existing.conditions.push(targetCondition);
        }
      }
    }
    if (targetLimitExceeded) {
      refined.push(unresolvedSite("typescript_refinement_target_limit_exceeded"));
      continue;
    }
    const fileTargets = [...fileTargetConditions.keys()].sort(compareUtf8);
    const externalTargets = [...externalTargetMap.values()]
      .sort((left, right) => compareUtf8(left.target.locator, right.target.locator));
    let conditionedTargets: Array<{ target: TypeScriptRawDependencyTarget; condition: Condition }>;
    let emptyTargetReason = "repository_binding_not_canonical";
    const moduleLevel = site.kind !== "type_use" && (
      imported === null
      || ["namespace_import", "side_effect_import", "empty_import", "import_equals", "namespace_reexport", "empty_reexport", "export_star", "require_call", "dynamic_import", "import_type"]
        .includes(site.evidence.occurrenceKind)
    );
    if (moduleLevel) {
      conditionedTargets = [
        ...fileTargets.map((relativePath) => ({
          target: { kind: "file" as const, relativePath },
          condition: aggregateConditions(fileTargetConditions.get(relativePath)!),
        })),
        ...externalTargets.map(({ target, conditions }) => ({
          target,
          condition: aggregateConditions(conditions),
        })),
      ];
    } else {
      const compilerGraphKind = site.targets
        .filter((target): target is Extract<TypeScriptRawDependencyTarget, { kind: "definition" }> => target.kind === "definition")
        .map((target) => definitionByKey.get(target.key)?.graphKind)
        .find((value): value is "symbol" | "type" => value !== undefined);
      const compilerDefinitions = [...new Map(site.targets
        .filter((target): target is Extract<TypeScriptRawDependencyTarget, { kind: "definition" }> => target.kind === "definition")
        .map((target) => [target.key, target])).values()];
      const canonicalImportEqualsRoot = site.exportPath?.length === 0
        && imported === "="
        && site.bindingKind === "import_equals"
        && site.bindingOrigin !== null
        && effectiveResolutionMode === "require"
        && (site.kind === "type_use" || site.evidence.occurrenceKind === "named_reexport");
      if (externalTargets.length > 0) {
        if (fileTargets.length > 0 || externalTargets.length > 1) {
          conditionedTargets = [];
          emptyTargetReason = "mixed_or_multiple_external_targets";
        } else {
          conditionedTargets = externalTargets.map(({ target, conditions }) => ({
            target,
            condition: aggregateConditions(conditions),
          }));
        }
      } else if (fileTargets.length > 0 && canonicalImportEqualsRoot) {
        const conditionsByDefinition = new Map<string, Condition[]>();
        let completeProof = true;
        const preferredGraphKind = site.kind === "type_use" || site.typeOnly ? "type" : "symbol";
        for (const relativePath of fileTargets) {
          const allKeys = moduleExportProofs.get(JSON.stringify([relativePath, []])) ?? [];
          const preferredKeys = allKeys.filter((key) => definitionByKey.get(key)?.graphKind === preferredGraphKind);
          const keys = preferredKeys.length > 0
            ? preferredKeys
            : site.kind === "type_use" ? [] : allKeys;
          if (keys.length === 0) completeProof = false;
          for (const key of keys) {
            for (const condition of fileTargetConditions.get(relativePath) ?? []) {
              appendTargetCondition(conditionsByDefinition, key, condition);
            }
          }
        }
        conditionedTargets = completeProof
          ? [...conditionsByDefinition].sort(([left], [right]) => compareUtf8(left, right)).map(([key, conditions]) => ({
            target: { kind: "definition" as const, key },
            condition: aggregateConditions(conditions),
          }))
          : [];
        if (!completeProof) emptyTargetReason = "import_equals_target_not_correlated";
      } else if (fileTargets.length > 0 && site.exportPath !== null && site.exportPath.length > 0) {
        const provenByFile: string[][] = [];
        const conditionsByDefinition = new Map<string, Condition[]>();
        let completeProof = true;
        const preferredGraphKind = compilerGraphKind ?? (site.kind === "type_use" || site.typeOnly ? "type" : "symbol");
        for (const relativePath of fileTargets) {
          const allKeys = moduleExportProofs.get(JSON.stringify([relativePath, site.exportPath])) ?? [];
          const preferredKeys = allKeys.filter((key) => definitionByKey.get(key)?.graphKind === preferredGraphKind);
          const keys = preferredKeys.length > 0
            ? preferredKeys
            : site.kind === "type_use" ? [] : allKeys;
          if (keys.length === 0) completeProof = false;
          provenByFile.push(keys);
          for (const key of keys) {
            for (const condition of fileTargetConditions.get(relativePath) ?? []) {
              appendTargetCondition(conditionsByDefinition, key, condition);
            }
          }
        }
        const provenKeys = [...new Set(provenByFile.flat())].sort(compareUtf8);
        if (completeProof) {
          conditionedTargets = provenKeys.map((key) => ({
            target: { kind: "definition" as const, key },
            condition: aggregateConditions(conditionsByDefinition.get(key)!),
          }));
        } else {
          conditionedTargets = [];
          emptyTargetReason = "module_export_not_proven";
        }
      } else {
        conditionedTargets = [];
        emptyTargetReason = site.exportPath === null || site.exportPath.length === 0
          ? "repository_binding_not_canonical"
          : "module_export_not_proven";
      }
    }
    conditionedTargets.sort((left, right) => compareUtf8(
      rawDependencyTargetKey(left.target),
      rawDependencyTargetKey(right.target),
    ));
    const targets = conditionedTargets.map(({ target }) => target);
    const targetConditions = conditionedTargets.map(({ condition }) => canonicalizeCondition(condition));
    const hasRepository = targets.some((target) => target.kind === "definition" || target.kind === "file");
    const hasExternal = targets.some((target) => target.kind === "external");
    if (targets.length === 0 || (hasRepository && hasExternal) || (hasExternal && targets.length !== 1)) {
      refined.push(unresolvedSite(targets.length === 0 ? emptyTargetReason : "mixed_or_multiple_external_targets"));
      continue;
    }
    const condition = aggregateConditions(targetConditions);
    const status = hasExternal ? "external" : targets.length > 1 ? "candidates" : "resolved";
    const precision = hasExternal
      ? resolution.precision === "exact" ? "exact" : "heuristic"
      : targets.length > 1 ? "overapprox" : "exact";
    refined.push({
      ...site,
      status,
      precision,
      reason: status === "resolved" || (status === "external" && precision === "exact")
        ? null
        : resolution.reason ?? site.reason,
      condition,
      targets,
      targetConditions,
      evidence: {
        ...site.evidence,
        targetBasis: hasExternal ? "external_boundary" : targets[0]?.kind === "definition" ? "canonical_definition" : "repository_module",
      },
    });
  }
  const result = { ...delta, sites: refined };
  validateTypeScriptRawDependencyDelta(
    result,
    definitions,
    validationSources,
  );
  return result;
}

function lineEvidence(source: string | null, pathValue: string, token: string, extractor: string, detail?: string, section?: string): Evidence {
  if (source === null) return sourceEvidence(pathValue, extractor, detail);
  const sectionIndex = section === undefined ? 0 : Math.max(0, source.indexOf(`"${section}"`));
  const index = source.indexOf(`"${token}"`, sectionIndex);
  const prefix = index < 0 ? "" : source.slice(0, index);
  const lines = prefix.split(/\r?\n/u);
  const line = lines.length;
  const column = (lines.at(-1)?.length ?? 0) + 1;
  return {
    kind: "source",
    extractor,
    extractor_version: ADAPTER_VERSION,
    path: pathValue,
    start_line: line,
    start_column: column,
    end_line: line,
    end_column: column + token.length + 2,
    ...(detail ? { detail } : {}),
  };
}

function packageDependencyResolution(workspace: Workspace, owner: PackageRecord, name: string, range: string): Resolution {
  const selection = selectPackageInstallCandidates(workspace, owner, name, range);
  const targets: ResolvedTarget[] = [
    ...selection.workspacePackages.map((record) => ({ kind: "workspace_package" as const, package: record })),
    ...selection.externalInstances.map((instance) => ({
      kind: "external_package" as const,
      name,
      version: instance.version,
      locator: instance.locator,
    })),
  ];
  if (targets.length === 0) {
    return { status: "unresolved", precision: "heuristic", targets: [], reason: selection.reason ?? "package_target_not_found" };
  }
  const hasWorkspace = selection.workspacePackages.length > 0;
  const hasExternal = selection.externalInstances.length > 0;
  return {
    status: targets.length > 1 || (hasWorkspace && hasExternal) ? "candidates" : hasWorkspace ? "resolved" : "external",
    precision: selection.precision,
    targets,
    reason: selection.reason,
  };
}

function packageDependencySiteKind(section: DependencySection): string {
  if (section === "peerDependencies") return "package_peer_dependency";
  if (section === "optionalDependencies") return "package_optional_dependency";
  return "package_dependency";
}

function coverageForPath(graph: GraphBuilder, root: string, pathValue: string): FileCoverage | null {
  const absolute = path.resolve(root, pathValue);
  const relative = path.relative(root, absolute);
  if (relative.startsWith("..") || path.isAbsolute(relative)) return null;
  const node = graph.fileNode(absolute);
  return graph.ensureCoverage(node, pathValue);
}

function recordSkippedInterpretation(graph: GraphBuilder, root: string, pathValue: string): void {
  const coverage = coverageForPath(graph, root, pathValue);
  if (coverage === null) return;
  coverage.expected_sites += 1;
  coverage.skipped_sites += 1;
  coverage.unsupported_syntax += 1;
}

function metadataFiles(allFiles: string[], root: string): string[] {
  return allFiles
    .filter((file) => {
      const name = path.basename(file);
      return name === "package.json"
        || /^(?:pnpm-workspace\.yaml|pnpm-lock\.yaml|yarn\.lock|bun\.lock|bun\.lockb|package-lock\.json|npm-shrinkwrap\.json|\.pnp\.data\.json|\.pnp\.cjs)$/u.test(name)
        || /^(?:tsconfig|jsconfig)(?:\.[^.]+)*\.json$/u.test(name)
        || /^(?:next|astro|vite|tanstack|router|webpack|rollup)\.config\.(?:js|jsx|ts|tsx|mjs|cjs)$/u.test(name);
    })
    .map((file) => normalizeRelative(path.relative(root, file)))
    .sort();
}

function configFiles(allFiles: string[], root: string): string[] {
  return allFiles
    .filter((file) => /^(?:next|astro|vite|tanstack|webpack|rollup)\.config\.(?:js|jsx|ts|tsx|mjs|cjs)$/u.test(path.basename(file)) || path.basename(file) === ".pnp.cjs")
    .map((file) => normalizeRelative(path.relative(root, file)))
    .sort();
}

async function localTypeScriptVersion(workspace: Workspace): Promise<Array<{ package: PackageRecord; version: string; source: string }>> {
  const result: Array<{ package: PackageRecord; version: string; source: string }> = [];
  for (const record of workspace.packages) {
    const manifest = await readJson(workspace.root, path.join(record.absolutePath, "node_modules", "typescript", "package.json"));
    if (typeof manifest?.version === "string") result.push({ package: record, version: manifest.version, source: "installed package manifest" });
    const declaration = record.dependencies.get("typescript");
    if (!declaration) continue;
    const locked = workspace.lockInstances.get("typescript") ?? [];
    if (locked.length > 0) {
      for (const version of [...new Set(locked.map((instance) => instance.version))]) {
        result.push({ package: record, version, source: workspace.lockfile ?? "lockfile" });
      }
    } else {
      result.push({ package: record, version: declaration.range, source: `${record.manifestPath} ${declaration.section}` });
    }
  }
  return result.filter((entry, index, entries) => entries.findIndex((candidate) => (
    candidate.package.id === entry.package.id && candidate.version === entry.version
  )) === index);
}

export async function scan(root: string, allFiles: string[], inventoryIssues: FileInventoryIssue[] = []): Promise<ScanModel> {
  const workspace = await discoverWorkspace(root, allFiles);
  const graph = new GraphBuilder(workspace);
  if (process.versions.node !== "24.18.0") {
    graph.addDiagnostic({
      severity: "warning",
      code: "web.best_effort_node_version",
      message: `Node.js ${process.versions.node} is outside the verified 24.18.0 baseline; static analysis continues on a best-effort basis`,
      path: null,
      profile_id: PROFILE_ID,
    });
  }
  if (ts.version !== "7.0.2") {
    graph.addDiagnostic({
      severity: "warning",
      code: "web.best_effort_typescript_version",
      message: `Bundled TypeScript ${ts.version} does not match the verified 7.0.2 baseline`,
      path: null,
      profile_id: PROFILE_ID,
    });
  }
  const packageBaselines = new Map([
    ["next", "16.2.10"],
    ["astro", "7.0.9"],
    ["@tanstack/react-router", "1.170.18"],
    ["@tanstack/react-start", "1.168.28"],
  ]);
  for (const [name, baseline] of packageBaselines) {
    const versions = [...new Set((workspace.lockInstances.get(name) ?? []).map((instance) => instance.version))];
    for (const version of versions.filter((candidate) => candidate !== baseline)) {
      graph.addDiagnostic({
        severity: "info",
        code: "web.best_effort_framework_version",
        message: `${name} ${version} is outside the verified ${baseline} baseline; framework extraction continues on a best-effort basis`,
        path: workspace.lockfile,
        profile_id: PROFILE_ID,
      });
    }
  }
  if (PROFILE_CONFIG_ISSUE) {
    graph.addDiagnostic({
      severity: "warning",
      code: "web.profile_config_defaulted",
      message: PROFILE_CONFIG_ISSUE,
      path: null,
      profile_id: PROFILE_ID,
    });
  }
  graph.addNode(workspace.workspaceNode);
  for (const metadataPath of metadataFiles(allFiles, root)) coverageForPath(graph, root, metadataPath);
  for (const issue of inventoryIssues) {
    // Protocol paths are themselves confinement-checked after resolving
    // symlinks. Keep an out-of-root link's lexical name in the diagnostic,
    // while using a non-existent in-root ledger path that remains valid input
    // for the core validator.
    const ledgerPath = issue.reason === "out_of_root_symlink"
      ? normalizeRelative(path.join("__depgraph_skipped__", issue.path))
      : issue.path;
    const node = graph.fileNode(path.join(root, ledgerPath));
    const coverage = graph.ensureCoverage(node, ledgerPath);
    coverage.expected_sites += 1;
    coverage.skipped_sites += 1;
    graph.dependency(
      node,
      {
        kind: "inventory_skipped_source",
        edgeKind: "imports",
        specifier: issue.path,
        evidence: sourceEvidence(ledgerPath, "filesystem-inventory", `skipped=${issue.reason}`),
      },
      { status: "unresolved", precision: "heuristic", targets: [], reason: issue.reason },
    );
    graph.addDiagnostic({
      severity: "warning",
      code: issue.reason === "out_of_root_symlink" ? "web.source_symlink_outside_root" : "web.source_inventory_skipped",
      message: `Skipped ${issue.path}: ${issue.detail}`,
      path: issue.reason === "out_of_root_symlink" ? null : issue.path,
      profile_id: PROFILE_ID,
    });
  }
  for (const issue of workspace.issues) {
    recordSkippedInterpretation(graph, root, issue.path);
    graph.addDiagnostic({
      severity: "error",
      code: issue.code,
      message: issue.reason,
      path: issue.path,
      profile_id: PROFILE_ID,
    });
  }
  for (const manifestPath of workspace.ignoredManifestPaths) {
    graph.addDiagnostic({
      severity: "info",
      code: "web.package_manifest_outside_workspace",
      message: `${manifestPath} is outside the declared workspace patterns and was not treated as a package`,
      path: manifestPath,
      profile_id: PROFILE_ID,
    });
  }
  for (const record of workspace.packages) {
    const packageNode = graph.addPackageNode(record);
    graph.structureEdge(workspace.workspaceNode, packageNode, "contains", sourceEvidence(record.manifestPath, "workspace-manifest"));
    const manifestNode = graph.fileNode(path.join(record.absolutePath, "package.json"));
    graph.ensureCoverage(manifestNode, record.manifestPath);
    graph.structureEdge(packageNode, manifestNode, "contains", sourceEvidence(record.manifestPath, "workspace-manifest"));
    const manifestSource = await readUtf8(root, path.join(record.absolutePath, "package.json"));
    for (const [name, dependency] of [...record.dependencies.entries()].sort(([left], [right]) => compareUtf8(left, right))) {
      if (dependency.section === "devDependencies") continue;
      const evidence = {
        ...lineEvidence(manifestSource, record.manifestPath, name, "package-manifest", `section=${dependency.section}`, dependency.section),
        properties: { dependency_section: dependency.section },
      };
      const resolution = packageDependencyResolution(workspace, record, name, dependency.range);
      graph.dependency(packageNode, { kind: packageDependencySiteKind(dependency.section), edgeKind: "depends_on", specifier: name, evidence }, resolution);
      graph.countSite(record.manifestPath, resolution.status);
    }
  }

  const routeDiscovery = await discoverRoutes(workspace, allFiles);
  for (const diagnostic of routeDiscovery.configDiagnostics) {
    if (diagnostic.code === "web.static_config_unresolved" || diagnostic.code === "web.config_read_failed") {
      recordSkippedInterpretation(graph, root, diagnostic.path);
    }
    graph.addDiagnostic({
      severity: diagnostic.severity,
      code: diagnostic.code,
      message: diagnostic.message,
      path: diagnostic.path,
      profile_id: PROFILE_ID,
    });
  }
  const routeEntriesByFile = new Map<string, RouteEntry[]>();
  for (const entry of routeDiscovery.entries) {
    const absolute = path.resolve(entry.absoluteFile);
    const entries = routeEntriesByFile.get(absolute) ?? [];
    entries.push(entry);
    routeEntriesByFile.set(absolute, entries);
  }
  const routeFiles = new Set(routeEntriesByFile.keys());
  const sourceFiles = allFiles
    .filter((file) => PARSED_EXTENSIONS.has(path.extname(file).toLowerCase()) || routeFiles.has(path.resolve(file)))
    .sort();
  // Parse repository-owned JSON/JSONC without executing it, retain only
  // repository-relative TypeScript 7 `paths` mappings, and feed the normalized
  // allowlist into the worker-owned compiler config. Deprecated `baseUrl` is
  // intentionally not applied.
  const resolver = await ModuleResolver.create(workspace, allFiles);
  // Read every TS/JS input once, then expose only those bytes through the
  // compiler's virtual filesystem. The native compiler never receives the
  // repository path, raw project config, node_modules, or package metadata.
  const sourceCache = new Map<string, string | null>();
  const compilerSources = new Map<string, string>();
  const compilerFiles = sourceFiles.filter((file) => TYPESCRIPT_SOURCE_EXTENSIONS.has(path.extname(file).toLowerCase()));
  // Each confined read performs a realpath check followed by the actual file
  // read. Bound the fan-out so large repositories do not serialize tens of
  // thousands of independent filesystem round trips or exhaust descriptors.
  for (let offset = 0; offset < compilerFiles.length; offset += SOURCE_READ_CONCURRENCY) {
    const batch = compilerFiles.slice(offset, offset + SOURCE_READ_CONCURRENCY);
    const sources = await Promise.all(batch.map(async (file) => await readUtf8(root, file)));
    for (let index = 0; index < batch.length; index += 1) {
      const file = batch[index]!;
      const source = sources[index] ?? null;
      sourceCache.set(path.resolve(file), source);
      if (source !== null) compilerSources.set(normalizeRelative(path.relative(root, file)), source);
    }
  }
  const precompilerExtractions = new Map<string, ReturnType<typeof extractDependencies>>();
  const typeScriptPathRequests: TypeScriptPathRequest[] = [];
  for (const [relative, source] of compilerSources) {
    const absolute = path.join(root, ...relative.split("/"));
    const extraction = extractDependencies(absolute, relative, source);
    precompilerExtractions.set(relative, extraction);
    for (const specifier of extractPotentialTypeScriptModuleSpecifiers(absolute, source)) {
      typeScriptPathRequests.push({ sourceFile: absolute, specifier });
    }
  }
  const nativeTypeScript = await analyzeTypeScriptProject(
    compilerSources,
    resolver.typeScriptStaticConfig(typeScriptPathRequests),
  );
  for (const issue of resolver.issues) {
    recordSkippedInterpretation(graph, root, issue.path);
    graph.addDiagnostic({
      severity: "warning",
      code: "web.static_config_unresolved",
      message: issue.reason,
      path: issue.path,
      profile_id: PROFILE_ID,
    });
  }
  for (const file of sourceFiles) {
    const relative = normalizeRelative(path.relative(root, file));
    const generated = /^routeTree\.gen\./u.test(path.basename(file));
    const node = graph.fileNode(file, generated);
    const owner = owningPackage(workspace, file);
    const ownerNode = graph.nodes.get(owner.id) ?? graph.addPackageNode(owner);
    graph.structureEdge(ownerNode, node, "contains", sourceEvidence(relative, "filesystem-inventory"), generated);
    const coverage = graph.ensureCoverage(node, relative);
    const extension = path.extname(file).toLowerCase();
    if (!PARSED_EXTENSIONS.has(extension)) {
      const routeEntries = routeEntriesByFile.get(path.resolve(file)) ?? [];
      // Static metadata assets contain no source-level module syntax. Other
      // configured route suffixes may contain arbitrary project-defined
      // languages, so retaining only the route edge would falsely claim a
      // syntax-complete dependency inventory.
      if (routeEntries.length > 0 && routeEntries.every((entry) => entry.entryKind === "static-metadata")) continue;
      const frameworks = [...new Set(routeEntries.map((entry) => entry.framework))].sort().join(",");
      const detail = `extension=${extension || "<none>"};frameworks=${frameworks || "unknown"}`;
      coverage.expected_sites += 1;
      coverage.skipped_sites += 1;
      coverage.unsupported_syntax += 1;
      graph.addDiagnostic({
        severity: "warning",
        code: "web.unsupported_syntax",
        message: `Dependency inventory for route source ${relative} was skipped because ${extension || "its extension"} is not supported (${frameworks || "unknown framework"})`,
        path: relative,
        profile_id: PROFILE_ID,
        evidence: [sourceEvidence(relative, "route-source-inventory", detail)],
      });
      continue;
    }
    const cachedSource = sourceCache.get(path.resolve(file));
    const source = cachedSource === undefined ? await readUtf8(root, file) : cachedSource;
    if (source === null) {
      coverage.expected_sites += 1;
      coverage.skipped_sites += 1;
      graph.dependency(
        node,
        {
          kind: "unreadable_source",
          edgeKind: "imports",
          specifier: relative,
          evidence: sourceEvidence(relative, "filesystem-inventory", "skipped=unreadable_source"),
        },
        { status: "unresolved", precision: "heuristic", targets: [], reason: "source_read_failed" },
        generated,
      );
      graph.addDiagnostic({
        severity: "error",
        code: "web.file_read_failed",
        message: `Could not read ${relative}`,
        path: relative,
        profile_id: PROFILE_ID,
      });
      continue;
    }
    const typeOnlyRanges = nativeTypeScript.typeOnlyDependencyRanges.get(relative) ?? [];
    const extraction = typeOnlyRanges.length === 0
      ? precompilerExtractions.get(relative) ?? extractDependencies(file, relative, source)
      : extractDependencies(file, relative, source, typeOnlyRanges);
    if (extraction.fallbackReason) {
      graph.addDiagnostic({
        severity: "warning",
        code: "web.astro_compiler_fallback",
        message: `Astro compiler could not provide a reliable frontmatter span; tokenizer fallback used: ${extraction.fallbackReason}`,
        path: relative,
        profile_id: PROFILE_ID,
        evidence: [sourceEvidence(relative, "astro-frontmatter-tokenizer", "precision=heuristic")],
      });
    }
    for (const error of extraction.parseErrors) {
      coverage.unsupported_syntax += 1;
      graph.addDiagnostic({
        severity: "warning",
        code: "web.unsupported_syntax",
        message: error.message,
        path: relative,
        profile_id: PROFILE_ID,
        evidence: [error.evidence],
      });
    }
    for (const diagnostic of nativeTypeScript.get(relative) ?? []) {
      coverage.unsupported_syntax += 1;
      graph.addDiagnostic({
        severity: "warning",
        code: "web.unsupported_syntax",
        message: `TypeScript native parser TS${diagnostic.code}: ${diagnostic.message}`,
        path: relative,
        profile_id: PROFILE_ID,
        evidence: [syntaxEvidence(source, relative, diagnostic.startOffset, diagnostic.endOffset)],
      });
    }
    for (const dependency of extraction.dependencies) {
      const resolved = await resolver.resolve(dependency, file, owner);
      const resolution = dependency.precisionHint && resolved.precision === "exact"
        ? { ...resolved, precision: "heuristic" as const, reason: resolved.reason ?? "astro_compiler_tokenizer_fallback" }
        : resolved;
      graph.dependency(node, dependency, resolution, generated);
      graph.countSite(relative, resolution.status);
    }
  }

  for (const issue of nativeTypeScript.definitionGraph.issues) {
    graph.addDiagnostic({
      severity: "warning",
      code: `web.${issue.code}`,
      message: issue.message.length <= 2_048 ? issue.message : `${issue.message.slice(0, 2_047)}…`,
      path: issue.relativePath,
      profile_id: PROFILE_ID,
      properties: { typescript_definition_issue: true },
      ...(issue.relativePath === null ? {} : {
        evidence: [sourceEvidence(
          issue.relativePath,
          "typescript-native-typechecker",
          `definition_graph_issue=${issue.code};fatal=${String(issue.fatal)}`,
        )],
      }),
    });
  }
  for (const issue of nativeTypeScript.dependencyGraph.issues) {
    graph.addDiagnostic({
      severity: "warning",
      code: `web.${issue.code}`,
      message: issue.message.length <= 2_048 ? issue.message : `${issue.message.slice(0, 2_047)}…`,
      path: issue.relativePath,
      profile_id: PROFILE_ID,
      properties: { typescript_dependency_issue: true },
      ...(issue.relativePath === null ? {} : {
        evidence: [sourceEvidence(
          issue.relativePath,
          "typescript-native-typechecker",
          `dependency_graph_issue=${issue.code};fatal=${String(issue.fatal)}`,
        )],
      }),
    });
  }
  if (nativeTypeScript.project.definitionGraphStatus === "ready") {
    try {
      nativeTypeScript.dependencyGraph = await refineTypeScriptDependencyDelta(
        nativeTypeScript.dependencyGraph,
        nativeTypeScript.definitionGraph,
        resolver,
        workspace,
        root,
        compilerSources,
        buildTypeScriptDependencyValidationSources(compilerSources, nativeTypeScript),
      );
      const counts = graph.mergeTypeScriptSemanticGraph(
        nativeTypeScript.definitionGraph,
        nativeTypeScript.dependencyGraph,
        compilerSources,
      );
      nativeTypeScript.project.semanticNodes = counts.nodes;
      nativeTypeScript.project.semanticRelations = counts.relations;
      nativeTypeScript.project.semanticSites = counts.sites;
    } catch (error) {
      nativeTypeScript.project.definitionGraphStatus = "failed";
      nativeTypeScript.project.semanticNodes = 0;
      nativeTypeScript.project.semanticRelations = 0;
      nativeTypeScript.project.semanticSites = 0;
      nativeTypeScript.project.semanticIssues += 1;
      graph.addDiagnostic({
        severity: "warning",
        code: "web.typescript_semantic_delta_discarded",
        message: `TypeScript semantic graph was discarded atomically after contract validation failed; syntax graph output was preserved: ${error instanceof Error ? error.message : String(error)}`.slice(0, 2_048),
        path: null,
        profile_id: PROFILE_ID,
        properties: { typescript_definition_issue: true },
      });
    }
  } else {
    nativeTypeScript.project.semanticNodes = 0;
    nativeTypeScript.project.semanticRelations = 0;
    nativeTypeScript.project.semanticSites = 0;
  }

  const routeNodesByGroup = new Map<string, Map<string, { node: GraphNode; evidence: Evidence }>>();
  for (const entry of routeDiscovery.entries) {
    const fileNode = graph.fileNode(entry.absoluteFile, entry.generated);
    const coverage = graph.ensureCoverage(fileNode, entry.relativeFile);
    const owner = owningPackage(workspace, entry.absoluteFile);
    const routeNode = graph.routeNode(entry, owner);
    const resolution: Resolution = {
      status: "resolved",
      precision: entry.generated ? "exact" : entry.framework === "astro" ? "heuristic" : "exact",
      targets: [{ kind: "workspace_package", package: owner }],
      reason: null,
    };
    const routeRaw = { kind: "route_entry", edgeKind: "reexports" as const, specifier: entry.pattern, evidence: entry.evidence };
    const siteId = stableId("site", {
      repository: workspace.repositoryIdentity,
      source: fileNode.id,
      kind: "route_entry",
      framework: entry.framework,
      pattern: entry.pattern,
      profile: PROFILE_ID,
      path: entry.relativeFile,
      entry_kind: entry.entryKind,
    });
    graph.addSite({
      id: siteId,
      source: fileNode.id,
      kind: "route_entry",
      specifier: entry.pattern,
      resolution_status: "resolved",
      target_ids: [routeNode.id],
      profile_id: PROFILE_ID,
      condition: WEB_CONDITION,
      precision: resolution.precision,
      reason: null,
      evidence: [routeRaw.evidence],
    });
    graph.addEdge({
      id: stableId("edge", { repository: workspace.repositoryIdentity, source: fileNode.id, target: routeNode.id, kind: "route_entry", profile: PROFILE_ID, site: siteId }),
      source: fileNode.id,
      target: routeNode.id,
      kind: "route_entry",
      site_id: siteId,
      phase: "source",
      environment: preferredWebEnvironment("server"),
      profile_id: PROFILE_ID,
      condition: WEB_CONDITION,
      resolution_status: "resolved",
      precision: resolution.precision,
      generated: entry.generated,
      evidence: [entry.evidence],
    });
    graph.countSite(entry.relativeFile, "resolved");
    const groupKey = `${owner.id}\0${entry.framework}`;
    const group = routeNodesByGroup.get(groupKey) ?? new Map();
    group.set(entry.pattern, { node: routeNode, evidence: entry.evidence });
    routeNodesByGroup.set(groupKey, group);
  }
  for (const group of routeNodesByGroup.values()) {
    for (const [patternValue, child] of group) {
      if (patternValue === "/") continue;
      const segments = patternValue.split("/").filter(Boolean);
      let parent: { node: GraphNode; evidence: Evidence } | undefined;
      while (segments.length > 0 && !parent) {
        segments.pop();
        parent = group.get(segments.length === 0 ? "/" : `/${segments.join("/")}`);
      }
      if (parent) graph.structureEdge(child.node, parent.node, "parent_route", child.evidence, child.evidence.kind === "build");
    }
  }

  for (const drift of routeDiscovery.drifts) {
    graph.addDiagnostic({
      severity: "warning",
      code: "web.tanstack_route_tree_drift",
      message: `Generated route tree drift in ${drift.package.name}; missing=[${drift.missingFromGenerated.join(", ")}], generated-only=[${drift.onlyGenerated.join(", ")}]`,
      path: drift.package.relativePath,
      profile_id: PROFILE_ID,
    });
  }
  for (const config of configFiles(allFiles, root)) {
    graph.addDiagnostic({
      severity: "info",
      code: "web.executable_config_not_executed",
      message: `Safe scan did not execute ${config}; only filesystem and literal source evidence was used`,
      path: config,
      profile_id: PROFILE_ID,
    });
  }
  for (const local of await localTypeScriptVersion(workspace)) {
    graph.addDiagnostic({
      severity: "info",
      code: "web.project_typescript_not_loaded",
      message: `Detected project-local TypeScript ${local.version} in ${local.package.name} from ${local.source}; safe scan used bundled TypeScript ${ts.version}`,
      path: local.package.manifestPath,
      profile_id: PROFILE_ID,
    });
  }
  for (const diagnostic of nativeTypeScript.semanticDiagnostics) {
    const source = diagnostic.relativePath === null ? null : compilerSources.get(diagnostic.relativePath) ?? null;
    graph.addDiagnostic({
      severity: "info",
      code: "web.typescript_semantic_scaffold_diagnostic",
      message: `TypeScript TypeChecker TS${diagnostic.code}: ${diagnostic.message}`,
      path: diagnostic.relativePath,
      profile_id: PROFILE_ID,
      ...(source === null || diagnostic.relativePath === null ? {} : {
        evidence: [semanticEvidence(
          source,
          diagnostic.relativePath,
          diagnostic.startOffset,
          diagnostic.endOffset,
        )],
      }),
    });
  }
  if (nativeTypeScript.project.semanticDiagnostics > nativeTypeScript.project.emittedSemanticDiagnostics) {
    graph.addDiagnostic({
      severity: "info",
      code: "web.typescript_semantic_scaffold_diagnostics_truncated",
      message: `TypeScript TypeChecker retained ${nativeTypeScript.project.emittedSemanticDiagnostics} of ${nativeTypeScript.project.semanticDiagnostics} deterministic diagnostics`,
      path: null,
      profile_id: PROFILE_ID,
    });
  }

  const files = [...graph.files.values()].sort((left, right) => compareUtf8(left.path, right.path));
  const sites = [...graph.sites.values()].sort(compareById);
  const counts = { resolved: 0, candidates: 0, external: 0, unresolved: 0 };
  for (const site of sites) counts[site.resolution_status] += 1;
  const unsupportedSyntax = files.reduce((sum, file) => sum + file.unsupported_syntax, 0);
  const skipped = files.reduce((sum, file) => sum + file.skipped_sites, 0);
  const reasons: string[] = [];
  if (counts.unresolved > 0) reasons.push("unresolved_dependency_sites");
  if (unsupportedSyntax > 0) reasons.push("unsupported_syntax");
  if (skipped > 0) reasons.push("skipped_sites");
  if (nativeTypeScript.project.definitionGraphStatus === "failed") reasons.push("typescript_definition_graph_failure");
  else if (nativeTypeScript.project.semanticIssues > 0) reasons.push("typescript_definition_graph_incomplete");
  return {
    nodes: [...graph.nodes.values()].sort(compareById),
    sites,
    edges: [...graph.edges.values()].sort(compareById),
    diagnostics: [...graph.diagnostics.values()].sort(compareById),
    files,
    coverage: {
      profiles: 1,
      files_discovered: files.length,
      files_analyzed: files.filter((file) => file.skipped_sites === 0).length,
      files_skipped: files.filter((file) => file.skipped_sites > 0).length,
      dependency_sites: sites.length,
      ...counts,
      unsupported_syntax: unsupportedSyntax,
      project_code_executed: false,
      completeness: unsupportedSyntax === 0 && skipped === 0 ? ["syntax-complete"] : [],
      reasons,
    },
    repositoryIdentity: workspace.repositoryIdentity,
    packageManager: workspace.manager,
    lockfile: workspace.lockfile,
    detectedFrameworks: routeDiscovery.frameworks,
    typeScriptProject: nativeTypeScript.project,
  };
}
