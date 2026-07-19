import path from "node:path";
import ts from "typescript";
import { normalizeRelative, readJson, readUtf8, WEB_SOURCE_EXTENSIONS, type FileInventoryIssue } from "./fs";
import { compareById, stableId } from "./ids";
import { extractDependencies, ModuleResolver, type RawDependency, type Resolution, type ResolvedTarget } from "./imports";
import { discoverRoutes, type RouteEntry } from "./routes";
import { analyzeTypeScriptProject, TYPESCRIPT_SOURCE_EXTENSIONS } from "./typescript-compiler";
import {
  ADAPTER_VERSION,
  PROFILE_CONFIG_ISSUE,
  PROFILE_ID,
  WEB_CONDITION,
  WEB_UNIVERSAL_ENVIRONMENT,
  preferredWebEnvironment,
  type DependencySite,
  type Diagnostic,
  type Evidence,
  type FileCoverage,
  type GraphEdge,
  type GraphNode,
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

class GraphBuilder {
  readonly nodes = new Map<string, GraphNode>();
  readonly sites = new Map<string, DependencySite>();
  readonly edges = new Map<string, GraphEdge>();
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
      .sort((left, right) => JSON.stringify(left).localeCompare(JSON.stringify(right)));
    this.edges.set(edge.id, { ...existing, evidence });
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
    for (const [name, dependency] of [...record.dependencies.entries()].sort(([left], [right]) => left.localeCompare(right))) {
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
  // repository-relative baseUrl/paths mappings, and feed the normalized
  // allowlist into the worker-owned compiler config.
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
  const nativeTypeScript = await analyzeTypeScriptProject(compilerSources, resolver.typeScriptStaticConfig());
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
    const extraction = extractDependencies(
      file,
      relative,
      source,
      nativeTypeScript.typeOnlyDependencyRanges.get(relative),
    );
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
      message: `TypeScript TypeChecker scaffold TS${diagnostic.code}: ${diagnostic.message}`,
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
      message: `TypeScript TypeChecker scaffold retained ${nativeTypeScript.project.emittedSemanticDiagnostics} of ${nativeTypeScript.project.semanticDiagnostics} deterministic diagnostics`,
      path: null,
      profile_id: PROFILE_ID,
    });
  }

  const files = [...graph.files.values()].sort((left, right) => left.path.localeCompare(right.path));
  const sites = [...graph.sites.values()].sort(compareById);
  const counts = { resolved: 0, candidates: 0, external: 0, unresolved: 0 };
  for (const site of sites) counts[site.resolution_status] += 1;
  const unsupportedSyntax = files.reduce((sum, file) => sum + file.unsupported_syntax, 0);
  const skipped = files.reduce((sum, file) => sum + file.skipped_sites, 0);
  const reasons: string[] = [];
  if (counts.unresolved > 0) reasons.push("unresolved_dependency_sites");
  if (unsupportedSyntax > 0) reasons.push("unsupported_syntax");
  if (skipped > 0) reasons.push("skipped_sites");
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
