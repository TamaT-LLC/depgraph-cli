import { realpath, stat } from "node:fs/promises";
import path from "node:path";
import ts from "typescript";
import { inventoryFiles } from "./fs";
import { scan } from "./scanner";
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
}

interface VersionOptions {
  version: true;
}

class UsageError extends Error {}

function parseArgs(args: string[]): Options | VersionOptions {
  if (args.length === 1 && (args[0] === "--version" || args[0] === "-V")) return { version: true };
  let root: string | null = null;
  let scanId: string | null = null;
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
    } else if (argument === "--help" || argument === "-h") {
      throw new UsageError("usage: depgraph-web-worker --root <path> --scan-id <id>");
    } else {
      throw new UsageError(`unknown argument: ${argument ?? ""}`);
    }
  }
  if (!root || !scanId) throw new UsageError("usage: depgraph-web-worker --root <path> --scan-id <id>");
  return { root: path.resolve(root), scanId };
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
      toolchain: `typescript ${ts.version}`,
      command: "scan",
      target: `web:${WEB_ENVIRONMENTS.join(",")}`,
      features: model.detectedFrameworks,
      environment: { mode: "production", environments: WEB_ENVIRONMENTS },
      properties: {
        module_resolution: "static-safe",
        package_manager: model.packageManager,
        lockfile: model.lockfile ?? "",
        bundled_typescript: "true",
        typescript_syntax_compiler: "native-7.0.2",
        typescript_compiler_processes: "1",
        typescript_project_filesystem: "isolated-virtual",
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

async function writeEvents(events: ProtocolEvent[]): Promise<void> {
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
    process.stdout.write(`depgraph-web-worker ${ADAPTER_VERSION} (protocol ${PROTOCOL_VERSION}; typescript ${ts.version})\n`);
    return;
  }
  try {
    const root = await realpath(options.root);
    if (!(await stat(root)).isDirectory()) throw new Error(`root is not a directory: ${root}`);
    const inventory = await inventoryFiles(root);
    const model = await scan(root, inventory.files, inventory.issues);
    await writeEvents(eventsFor(model, root, options.scanId));
    process.stderr.write(`depgraph-web-worker: ${model.coverage.files_analyzed} files, ${model.coverage.dependency_sites} sites, project code executed=false\n`);
  } catch (error) {
    process.stderr.write(`depgraph-web-worker: ${error instanceof Error ? error.stack ?? error.message : String(error)}\n`);
    process.exitCode = 3;
  }
}

await main();
