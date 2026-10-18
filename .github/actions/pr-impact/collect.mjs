// Collect depgraph impact for every file a pull request changed and write one
// aggregated report. Pure helpers are exported for tests; the CLI entry point
// at the bottom wires them to git, depgraph, and the environment.
//
// No shell is involved: git and depgraph run through execFile with argument
// arrays, and every value that reaches an argv slot is either validated or
// attached to its flag (`--profile=<value>`) so it cannot become an option.

import { execFile } from "node:child_process";
import { appendFileSync, readFileSync, writeFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

export const REPORT_SCHEMA_VERSION = "depgraph-pr-impact-report-v0";

const SCAN_EXIT_OK = 0;
const SCAN_EXIT_POLICY_VIOLATION = 1;
const SCAN_EXIT_WORKER_FAILURE = 3;
const IMPACT_EXIT_SELECTOR = 2;
const MESSAGE_LIMIT = 300;
const SKIPPED_PATH_LIMIT = 50;
const MAX_BUFFER_BYTES = 256 * 1024 * 1024;
const BASE_REF_PATTERN = /^[0-9A-Za-z._/~^@{}-]+$/;
const ATTEMPT_ID_PATTERN = /^[0-9A-Za-z][0-9A-Za-z._:-]*$/;
const KIND_ORDER = { route: 0, package_instance: 1 };

/** Parse `git diff --name-status -z` output. Rename and copy records carry two paths. */
export function parseNameStatusZ(raw) {
  const fields = raw.split("\0");
  if (fields.at(-1) === "") fields.pop();
  const entries = [];
  let index = 0;
  while (index < fields.length) {
    const status = fields[index++];
    const change = status.charAt(0);
    if (!/^[ACDMRTUX]$/.test(change)) {
      throw new Error(`malformed git diff status ${JSON.stringify(status)}`);
    }
    if (change === "R" || change === "C") {
      if (index + 2 > fields.length) throw new Error("malformed git diff rename record");
      const oldPath = fields[index++];
      const path = fields[index++];
      entries.push({ change, path, oldPath, similarity: Number.parseInt(status.slice(1), 10) });
      continue;
    }
    if (index + 1 > fields.length) throw new Error("malformed git diff record");
    entries.push({ change, path: fields[index++] });
  }
  return entries;
}

export function parseProfiles(raw) {
  return (raw ?? "")
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0);
}

export function buildImpactArgs({ store, path, selector, profiles = [], maxNodes, maxEdges, attemptId }) {
  const args = ["--store", store];
  if (attemptId) args.push(`--scan-id=attempt:${attemptId}`);
  args.push("impact", selector ?? `path:${path}`, "--json");
  for (const profile of profiles) args.push(`--profile=${profile}`);
  if (maxNodes !== undefined) args.push(`--max-nodes=${maxNodes}`);
  if (maxEdges !== undefined) args.push(`--max-edges=${maxEdges}`);
  return args;
}

function messageHead(text) {
  const line = String(text ?? "")
    .split(/\r?\n/)
    .map((part) => part.trim())
    .find((part) => part.length > 0);
  const head = (line ?? "").replace(/^error:\s*/i, "");
  return head.length > MESSAGE_LIMIT ? `${head.slice(0, MESSAGE_LIMIT - 1)}…` : head;
}

// `path:<p>` is not an exact lookup: when no file node has exactly that path,
// depgraph falls back to a suffix match and can resolve to (or list) other
// files with the same basename. A result only counts when its root is the
// changed file itself. Go and web workers spell file locators differently.
function rootIsPath(root, path) {
  if (!root || root.kind !== "file") return false;
  return root.display_name === path || root.locator === `file://${path}` || root.locator === `file:${path}`;
}

// Worker failures name binaries under the runner's temp directory; only the
// file name helps the reader, and the full path just eats the message budget.
function shortenAbsolutePaths(text) {
  return text.replace(/(?:\/[^\s/:;'"]+){2,}\/([^\s/:;'"]+)/g, "…/$1");
}

/** Turn one `depgraph impact` process result into ok / unmapped / error. */
export function classifyImpactResult({ exitCode, stdout, stderr }, { path } = {}) {
  if (exitCode === 0) {
    let envelope;
    try {
      envelope = JSON.parse(stdout);
    } catch {
      return { status: "error", exitCode, message: "impact output is not valid JSON" };
    }
    if (!envelope || typeof envelope !== "object" || !envelope.data || !Array.isArray(envelope.data.impacts)) {
      return { status: "error", exitCode, message: "impact JSON envelope is missing data.impacts" };
    }
    if (path !== undefined && !rootIsPath(envelope.data.root, path)) {
      const resolved = messageHead(envelope.data.root?.display_name ?? envelope.data.root?.id ?? "unknown");
      return { status: "unmapped", exitCode: 0, message: `path selector resolved to a different file (${resolved})` };
    }
    return { status: "ok", data: envelope.data };
  }
  const head = messageHead(stderr) || messageHead(stdout) || `exit ${exitCode}`;
  if (exitCode === IMPACT_EXIT_SELECTOR) {
    let message = head;
    if (/did not match any node/.test(head)) {
      message = "no graph node for this path";
    } else if (/is ambiguous/.test(head)) {
      const candidates = String(stderr ?? "").match(/\(file, id:/g)?.length ?? 0;
      message = `no graph node for this path (${candidates} other files share its suffix)`;
    }
    return { status: "unmapped", exitCode, message };
  }
  return { status: "error", exitCode, message: head };
}

/** From an ambiguous-selector error, the id of the candidate that is exactly `path`. */
export function ambiguousCandidateId(stderr, path) {
  const text = String(stderr ?? "");
  if (!/is ambiguous/.test(text)) return undefined;
  const pattern = /(file:\/\/|file:)([^\s()]+) \(file, id:([^\s(),]+)\)/g;
  for (const match of text.matchAll(pattern)) {
    if (match[2] === path && ATTEMPT_ID_PATTERN.test(match[3])) return match[3];
  }
  return undefined;
}

function isCloser(candidate, current) {
  if (candidate.depth !== current.depth) return candidate.depth < current.depth;
  return candidate.dependency_path.length < current.dependency_path.length;
}

function compareImpacted(left, right) {
  const leftKind = KIND_ORDER[left.kind] ?? 2;
  const rightKind = KIND_ORDER[right.kind] ?? 2;
  if (leftKind !== rightKind) return leftKind - rightKind;
  if (left.kind !== right.kind) return left.kind < right.kind ? -1 : 1;
  if (left.depth !== right.depth) return left.depth - right.depth;
  if (left.display_name !== right.display_name) return left.display_name < right.display_name ? -1 : 1;
  return left.id < right.id ? -1 : left.id > right.id ? 1 : 0;
}

/** Fold per-file impact results into the report written to report.json. */
export function aggregateReport({
  baseSha,
  mergeBase,
  headSha,
  pathPrefix = "",
  depgraphVersion,
  strict = false,
  scan,
  files,
  skipped = [],
}) {
  const impacted = new Map();
  const changedFiles = [];
  const diagnostics = [];
  let incomplete = scan.partial === true;

  for (const file of files) {
    const entry = { path: file.path, change: file.change };
    if (file.oldPath !== undefined) entry.old_path = file.oldPath;
    const { result } = file;
    entry.status = result.status;
    if (result.status === "ok") {
      const data = result.data;
      const own = data.impacts.filter((item) => item.depth > 0);
      entry.impacted_count = own.length;
      entry.complete = data.complete !== false;
      if (!entry.complete) incomplete = true;
      for (const diagnostic of data.diagnostics ?? []) {
        diagnostics.push({ path: file.path, code: diagnostic.code, message: diagnostic.message });
      }
      for (const item of own) {
        const candidate = {
          id: item.node.id,
          kind: item.node.kind,
          display_name: item.node.display_name,
          locator: item.node.locator,
          depth: item.depth,
          dependency_path: item.dependency_path ?? [],
        };
        const current = impacted.get(candidate.id);
        if (!current) {
          impacted.set(candidate.id, { ...candidate, reached_from: new Set([file.path]) });
          continue;
        }
        current.reached_from.add(file.path);
        if (isCloser(candidate, current)) {
          current.depth = candidate.depth;
          current.dependency_path = candidate.dependency_path;
        }
      }
    } else if (result.status === "unmapped" || result.status === "error") {
      entry.exit_code = result.exitCode;
      entry.message = result.message;
      if (result.status === "error") incomplete = true;
    }
    changedFiles.push(entry);
  }

  const impactedList = [...impacted.values()]
    .map((entry) => ({ ...entry, reached_from: [...entry.reached_from].sort() }))
    .sort(compareImpacted);
  const routes = impactedList.filter((entry) => entry.kind === "route").length;
  const packages = impactedList.filter((entry) => entry.kind === "package_instance").length;
  if (skipped.length > 0) incomplete = true;

  const scanReport = {
    exit_code: scan.exitCode,
    status: scanStatus(scan),
    strict,
  };
  if (scan.message) scanReport.message = scan.message;
  if (scanReport.status === "failed") incomplete = true;

  return {
    schema_version: REPORT_SCHEMA_VERSION,
    depgraph_version: depgraphVersion,
    base_sha: baseSha,
    merge_base: mergeBase,
    head_sha: headSha,
    path_prefix: pathPrefix,
    scan: scanReport,
    totals: {
      changed: files.length + skipped.length,
      routes,
      packages,
      others: impactedList.length - routes - packages,
      impacted: impactedList.length,
    },
    incomplete,
    changed_files: changedFiles,
    skipped: { count: skipped.length, paths: skipped.slice(0, SKIPPED_PATH_LIMIT) },
    diagnostics,
    impacted: impactedList,
  };
}

function scanStatus(scan) {
  if (scan.exitCode === SCAN_EXIT_OK) return "ok";
  if (scan.exitCode === SCAN_EXIT_POLICY_VIOLATION) return "policy_violation";
  if (scan.partial === true) return "partial";
  return "failed";
}

// `depgraph impact` reads the latest *completed* scan by default. A scan that
// ended partial (exit 3) or failed the strict policy (exit 1) is stored only as
// an attempt, so it has to be selected explicitly as `attempt:<id>`.
const ATTEMPT_STATUSES = new Map([
  [SCAN_EXIT_POLICY_VIOLATION, "policy_failed"],
  [SCAN_EXIT_WORKER_FAILURE, "partial"],
]);

function scanAttemptId(scanExitCode, scanOutput) {
  const expected = ATTEMPT_STATUSES.get(scanExitCode);
  if (!expected || !scanOutput || scanOutput.status !== expected) return undefined;
  const id = scanOutput.scan_id;
  return typeof id === "string" && ATTEMPT_ID_PATTERN.test(id) ? id : undefined;
}

function positiveInteger(name, value) {
  if (value === undefined || value === null || value === "") return undefined;
  const text = String(value).trim();
  if (!/^[1-9][0-9]{0,8}$/.test(text)) throw new Error(`${name} must be a positive integer`);
  return Number(text);
}

/** Run the whole collection against injectable git and depgraph runners. */
export async function collectReport({
  baseRef,
  headRef = "HEAD",
  store,
  profiles = [],
  maxFiles,
  maxNodes,
  maxEdges,
  scanExitCode,
  scanOutput,
  scanMessage,
  strict = false,
  depgraphVersion,
  runGit,
  runDepgraph,
}) {
  if (typeof baseRef !== "string" || !BASE_REF_PATTERN.test(baseRef) || baseRef.startsWith("-")) {
    throw new Error(`base ref is not a plain revision: ${JSON.stringify(baseRef)}`);
  }
  const fileLimit = positiveInteger("max-files", maxFiles) ?? 200;
  const nodeLimit = positiveInteger("max-nodes", maxNodes);
  const edgeLimit = positiveInteger("max-edges", maxEdges);

  const baseSha = (await runGit(["rev-parse", "--verify", "--quiet", `${baseRef}^{commit}`])).trim();
  const headSha = (await runGit(["rev-parse", "--verify", "--quiet", headRef])).trim();
  const mergeBase = (await runGit(["merge-base", baseSha, headSha])).trim();
  const pathPrefix = (await runGit(["rev-parse", "--show-prefix"])).trim();
  const diff = await runGit(["diff", "--name-status", "-z", "--find-renames", "--relative", mergeBase, headSha, "--"]);
  const entries = parseNameStatusZ(diff);

  const attemptId = scanAttemptId(scanExitCode, scanOutput);
  const message = scanMessage ?? (scanOutput && typeof scanOutput.error === "string" ? messageHead(shortenAbsolutePaths(scanOutput.error)) : undefined);
  const scan = { exitCode: scanExitCode, partial: attemptId !== undefined && scanExitCode === SCAN_EXIT_WORKER_FAILURE, message };
  const canQuery = scanExitCode === SCAN_EXIT_OK || scanExitCode === SCAN_EXIT_POLICY_VIOLATION || attemptId !== undefined;

  const files = [];
  const skipped = [];
  let queried = 0;
  for (const entry of entries) {
    if (entry.change === "D") {
      files.push({ ...entry, result: { status: "deleted" } });
      continue;
    }
    if (!canQuery) {
      files.push({ ...entry, result: { status: "not_analyzed" } });
      continue;
    }
    if (queried >= fileLimit) {
      skipped.push(entry.path);
      continue;
    }
    queried += 1;
    const options = { store, profiles, maxNodes: nodeLimit, maxEdges: edgeLimit, attemptId };
    let processResult = await runDepgraph(buildImpactArgs({ ...options, path: entry.path }));
    const candidate = processResult.exitCode === IMPACT_EXIT_SELECTOR ? ambiguousCandidateId(processResult.stderr, entry.path) : undefined;
    if (candidate) processResult = await runDepgraph(buildImpactArgs({ ...options, selector: `id:${candidate}` }));
    files.push({ ...entry, result: classifyImpactResult(processResult, { path: entry.path }) });
  }

  return aggregateReport({
    baseSha,
    mergeBase,
    headSha,
    pathPrefix,
    depgraphVersion,
    strict,
    scan,
    files,
    skipped,
  });
}

function execFileResult(command, args, options) {
  return new Promise((resolve) => {
    execFile(command, args, { maxBuffer: MAX_BUFFER_BYTES, encoding: "utf8", ...options }, (error, stdout, stderr) => {
      if (error && typeof error.code !== "number") {
        resolve({ exitCode: -1, stdout: stdout ?? "", stderr: `${error.message}\n${stderr ?? ""}` });
        return;
      }
      resolve({ exitCode: error ? error.code : 0, stdout, stderr });
    });
  });
}

function readScanOutput(path) {
  if (!path) return undefined;
  try {
    return JSON.parse(readFileSync(path, "utf8"));
  } catch {
    return undefined;
  }
}

async function main() {
  const env = process.env;
  const depgraph = env.DEPGRAPH_BIN;
  const reportPath = env.REPORT_PATH;
  if (!depgraph || !env.DEPGRAPH_STORE || !reportPath) {
    throw new Error("DEPGRAPH_BIN, DEPGRAPH_STORE, and REPORT_PATH are required");
  }
  const scanExitCode = Number.parseInt(env.SCAN_EXIT_CODE ?? "", 10);
  if (!Number.isInteger(scanExitCode)) throw new Error("SCAN_EXIT_CODE must be an integer");

  const runGit = async (args) => {
    const result = await execFileResult("git", args, {});
    if (result.exitCode !== 0) throw new Error(`git ${args[0]} failed: ${messageHead(result.stderr)}`);
    return result.stdout;
  };
  const runDepgraph = (args) => execFileResult(depgraph, args, {});

  const report = await collectReport({
    baseRef: env.BASE_REF,
    store: env.DEPGRAPH_STORE,
    profiles: parseProfiles(env.PROFILES),
    maxFiles: env.MAX_FILES,
    maxNodes: env.MAX_NODES,
    maxEdges: env.MAX_EDGES,
    scanExitCode,
    scanOutput: readScanOutput(env.SCAN_OUTPUT_PATH),
    strict: env.STRICT === "true",
    depgraphVersion: env.DEPGRAPH_VERSION ?? "unknown",
    runGit,
    runDepgraph,
  });
  writeFileSync(reportPath, `${JSON.stringify(report, null, 2)}\n`);
  if (env.GITHUB_OUTPUT) {
    appendFileSync(env.GITHUB_OUTPUT, `impacted-count=${report.totals.impacted}\nscan-status=${report.scan.status}\n`);
  }
  console.log(
    `depgraph pr-impact: ${report.totals.changed} changed file(s), ${report.totals.impacted} impacted node(s), scan ${report.scan.status}`,
  );
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  main().catch((error) => {
    console.error(`depgraph pr-impact collect: ${error.message}`);
    process.exit(1);
  });
}
