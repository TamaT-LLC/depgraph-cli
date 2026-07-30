import { readFile, realpath, stat } from "node:fs/promises";
import path from "node:path";
import { inventoryFiles, readUtf8 } from "./fs";
import { stableId } from "./ids";
import {
  deltaEventsFor,
  IncrementalFallbackError,
  parseWorkerDeltaRequest,
  semanticNoopDeltaEventsFor,
} from "./incremental";
import {
  frameworkSemanticProfileProperties,
  WEB_FRAMEWORK_SEMANTIC_PROFILE_PROPERTIES,
  WEB_SEMANTIC_RELEASE_CAPABILITIES,
} from "./framework-semantic";
import { StderrProgressReporter } from "./progress";
import { scan } from "./scanner";
import {
  TYPESCRIPT_COMPILER_PROFILE_PROPERTIES,
  TYPESCRIPT_COMPILER_VERSION,
  TypeScriptProjectError,
} from "./typescript-compiler";
import {
  ADAPTER,
  ADAPTER_VERSION,
  PROFILE_ID,
  WEB_ENVIRONMENTS,
  PROTOCOL_VERSION,
  type CommonEvent,
  type ProtocolEvent,
  type ScanModel,
} from "./types";

interface Options {
  root: string;
  scanId: string;
  deltaRequest: string | null;
}

interface VersionOptions {
  version: true;
}

class UsageError extends Error {}

function typeScriptProfileProperties(
  project: ScanModel["typeScriptProject"] | null,
  failure: TypeScriptProjectError | null = null,
): Record<string, string> {
  if (project === null) {
    return {
      ...TYPESCRIPT_COMPILER_PROFILE_PROPERTIES,
      typescript_project_model_status: "failed",
      typescript_typechecker_status: "failed",
      typescript_definition_graph_status: "failed",
      typescript_project_model_failure_reason: failure?.reason ?? "compiler_protocol_failure",
      typescript_project_root_files: "0",
      typescript_program_files: "0",
      typescript_static_config_files: "0",
      typescript_path_mappings: "0",
      typescript_standard_library_files: "0",
      typescript_typechecker_queries: "0",
      typescript_semantic_diagnostics: "0",
      typescript_emitted_semantic_diagnostics: "0",
      typescript_semantic_node_count: "0",
      typescript_semantic_relation_count: "0",
      typescript_semantic_site_count: "0",
      typescript_semantic_call_site_count: "0",
      typescript_semantic_issue_count: "0",
    };
  }
  return {
    ...TYPESCRIPT_COMPILER_PROFILE_PROPERTIES,
    typescript_typechecker_status: project.definitionGraphStatus === "ready"
      ? "definition-import-type-call-graph-emitted"
      : "definition-import-type-call-graph-discarded",
    typescript_definition_graph_status: project.definitionGraphStatus,
    typescript_project_model_failure_reason: "none",
    typescript_project_root_files: String(project.rootFiles),
    typescript_program_files: String(project.programFiles),
    typescript_static_config_files: String(project.staticConfigFiles),
    typescript_path_mappings: String(project.pathMappings),
    typescript_standard_library_files: String(project.standardLibraryFiles),
    typescript_typechecker_queries: String(project.typeCheckerQueries),
    typescript_semantic_diagnostics: String(project.semanticDiagnostics),
    typescript_emitted_semantic_diagnostics: String(project.emittedSemanticDiagnostics),
    typescript_semantic_node_count: String(project.semanticNodes),
    typescript_semantic_relation_count: String(project.semanticRelations),
    typescript_semantic_site_count: String(project.semanticSites),
    typescript_semantic_call_site_count: String(project.semanticCallSites),
    typescript_semantic_issue_count: String(project.semanticIssues),
  };
}

function parseArgs(args: string[]): Options | VersionOptions {
  if (args.length === 1 && (args[0] === "--version" || args[0] === "-V")) return { version: true };
  let root: string | null = null;
  let scanId: string | null = null;
  let deltaRequest: string | null = null;
  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index];
    if (argument === "--root") {
      const value = args[index + 1];
      if (!value) throw new UsageError("--root requires a path");
      root = value;
      index += 1;
    } else if (argument === "--scan-id") {
      const value = args[index + 1];
      if (!value) throw new UsageError("--scan-id requires a non-empty identifier");
      scanId = value;
      index += 1;
    } else if (argument === "--delta-request") {
      const value = args[index + 1];
      if (!value) throw new UsageError("--delta-request requires a path");
      deltaRequest = path.resolve(value);
      index += 1;
    } else if (argument === "--help" || argument === "-h") {
      throw new UsageError(
        "usage: depgraph-web-worker --root <path> --scan-id <id> [--delta-request <path>]",
      );
    } else {
      throw new UsageError(`unknown argument: ${argument ?? ""}`);
    }
  }
  if (!root || !scanId) {
    throw new UsageError(
      "usage: depgraph-web-worker --root <path> --scan-id <id> [--delta-request <path>]",
    );
  }
  return { root: path.resolve(root), scanId, deltaRequest };
}

function eventsFor(model: ScanModel, root: string, scanId: string): ProtocolEvent[] {
  let seq = 0;
  const common = (event: string): CommonEvent => ({
    event,
    protocol_version: PROTOCOL_VERSION,
    scan_id: scanId,
    adapter: ADAPTER,
    adapter_version: ADAPTER_VERSION,
    seq: ++seq,
  });
  const events: ProtocolEvent[] = [];
  events.push({
    ...common("scan_started"),
    root,
    project_code_executed: false,
    safe_mode: true,
  });
  events.push({
    ...common("profile_declared"),
    profile: {
      id: PROFILE_ID,
      language: "web",
      toolchain: `typescript ${TYPESCRIPT_COMPILER_VERSION}`,
      command: "scan",
      target: `web:${WEB_ENVIRONMENTS.join(",")}`,
      features: model.detectedFrameworks,
      environment: { mode: "production", environments: WEB_ENVIRONMENTS },
      properties: {
        module_resolution: "static-safe",
        package_manager: model.packageManager,
        lockfile: model.lockfile ?? "",
        ...frameworkSemanticProfileProperties(model.frameworkSemantic),
        ...typeScriptProfileProperties(model.typeScriptProject),
        project_code_executed: "false",
      },
    },
  });
  for (const node of model.nodes) events.push({ ...common("node_upsert"), node });
  for (const site of model.sites) events.push({ ...common("dependency_site"), site });
  for (const edge of model.edges) events.push({ ...common("edge_upsert"), edge });
  for (const diagnostic of model.diagnostics) events.push({ ...common("diagnostic"), diagnostic });
  for (const file of model.files) {
    events.push({
      ...common("file_completed"),
      path: file.path,
      discovered_sites: file.expected_sites,
      emitted_sites: file.produced_sites,
      skipped_sites: file.skipped_sites,
      skipped: file.skipped_sites > 0,
      reason: file.skipped_sites > 0 ? "file_or_site_skipped" : null,
    });
  }
  events.push({ ...common("profile_completed"), profile_id: PROFILE_ID, coverage: model.coverage });
  events.push({ ...common("scan_completed"), coverage: model.coverage });
  return events;
}

function failureEventsFor(root: string, scanId: string, failure: TypeScriptProjectError): ProtocolEvent[] {
  let seq = 0;
  const common = (event: string): CommonEvent => ({
    event,
    protocol_version: PROTOCOL_VERSION,
    scan_id: scanId,
    adapter: ADAPTER,
    adapter_version: ADAPTER_VERSION,
    seq: ++seq,
  });
  const coverage = {
    profiles: 1,
    files_discovered: 0,
    files_analyzed: 0,
    files_skipped: 0,
    dependency_sites: 0,
    resolved: 0,
    candidates: 0,
    external: 0,
    unresolved: 0,
    unsupported_syntax: 0,
    project_code_executed: false,
    completeness: [],
    reasons: ["typescript_project_model_failure", failure.reason],
  };
  return [
    {
      ...common("scan_started"),
      root,
      project_code_executed: false,
      safe_mode: true,
    },
    {
      ...common("profile_declared"),
      profile: {
        id: PROFILE_ID,
        language: "web",
        toolchain: `typescript ${TYPESCRIPT_COMPILER_VERSION}`,
        command: "scan",
        target: `web:${WEB_ENVIRONMENTS.join(",")}`,
        features: [],
        environment: { mode: "production", environments: WEB_ENVIRONMENTS },
        properties: {
          module_resolution: "static-safe",
          package_manager: "unknown",
          lockfile: "",
          ...WEB_FRAMEWORK_SEMANTIC_PROFILE_PROPERTIES,
          ...typeScriptProfileProperties(null, failure),
          project_code_executed: "false",
        },
      },
    },
    {
      ...common("diagnostic"),
      diagnostic: {
        id: stableId("diagnostic", {
          profile: PROFILE_ID,
          code: "web.typescript_project_model_failed",
          reason: failure.reason,
        }),
        severity: "error",
        code: "web.typescript_project_model_failed",
        message: `Bundled TypeScript project model failed: ${failure.reason}`,
        path: null,
        profile_id: PROFILE_ID,
      },
    },
    { ...common("profile_completed"), profile_id: PROFILE_ID, coverage },
    { ...common("scan_completed"), coverage },
  ];
}

async function writeEvents(events: readonly unknown[]): Promise<void> {
  const write = async (chunk: string): Promise<void> => {
    if (process.stdout.write(chunk)) return;
    await new Promise<void>((resolve, reject) => {
      const cleanup = (): void => {
        process.stdout.off("drain", drained);
        process.stdout.off("error", failed);
      };
      const drained = (): void => {
        cleanup();
        resolve();
      };
      const failed = (error: Error): void => {
        cleanup();
        reject(error);
      };
      process.stdout.once("drain", drained);
      process.stdout.once("error", failed);
    });
  };
  const chunks: string[] = [];
  let chunkLength = 0;
  for (const event of events) {
    const line = `${JSON.stringify(event)}\n`;
    chunks.push(line);
    chunkLength += line.length;
    if (chunkLength >= 256 * 1024) {
      await write(chunks.join(""));
      chunks.length = 0;
      chunkLength = 0;
    }
  }
  if (chunks.length > 0) await write(chunks.join(""));
}

async function main(): Promise<void> {
  let options: Options | VersionOptions;
  try {
    options = parseArgs(process.argv.slice(2));
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 2;
    return;
  }
  if ("version" in options) {
    process.stdout.write(
      `depgraph-web-worker ${ADAPTER_VERSION} (protocol ${PROTOCOL_VERSION}; typescript ${TYPESCRIPT_COMPILER_VERSION}; capabilities ${WEB_SEMANTIC_RELEASE_CAPABILITIES.join(",")})\n`,
    );
    return;
  }
  let root: string | null = null;
  try {
    root = await realpath(options.root);
    if (!(await stat(root)).isDirectory()) throw new Error(`root is not a directory: ${root}`);
    const deltaRequest = options.deltaRequest === null
      ? null
      : parseWorkerDeltaRequest(
        JSON.parse(await readFile(options.deltaRequest, "utf8")) as unknown,
        options.scanId,
      );
    if (deltaRequest?.analysis_mode === "semantic_noop") {
      const changedPath = deltaRequest.changes[0]?.new_path;
      const source = changedPath === undefined
        ? null
        : await readUtf8(root, path.join(root, changedPath));
      if (source === null) {
        throw new IncrementalFallbackError("changed file could not be read safely");
      }
      await writeEvents(semanticNoopDeltaEventsFor(source, deltaRequest));
      process.stderr.write(
        "depgraph-web-worker: 1 file, semantic no-op delta mode, project code executed=false\n",
      );
      return;
    }
    const progress = new StderrProgressReporter();
    progress.start("filesystem_inventory");
    const inventory = await inventoryFiles(root);
    progress.complete("filesystem_inventory", {
      inventory_files: inventory.files.length,
      inventory_issues: inventory.issues.length,
    });
    const model = await scan(root, inventory.files, inventory.issues, progress);
    await writeEvents(deltaRequest === null
      ? eventsFor(model, root, options.scanId)
      : deltaEventsFor(model, deltaRequest));
    process.stderr.write(
      `depgraph-web-worker: ${model.coverage.files_analyzed} files, ${model.coverage.dependency_sites} sites, ${deltaRequest === null ? "full" : "delta"} mode, project code executed=false\n`,
    );
  } catch (error) {
    if (error instanceof IncrementalFallbackError) {
      process.stderr.write(`depgraph-web-worker: incremental fallback required: ${error.message}\n`);
      process.exitCode = 75;
    } else if (error instanceof TypeScriptProjectError && root !== null) {
      await writeEvents(failureEventsFor(root, options.scanId, error)).catch(() => undefined);
      process.stderr.write(`depgraph-web-worker: ${error.message}\n`);
    } else {
      process.stderr.write(`depgraph-web-worker: ${error instanceof Error ? error.stack ?? error.message : String(error)}\n`);
    }
    process.exitCode = 3;
  }
}

await main();
