// Collect depgraph impact for every file a pull request changed and write one
// aggregated report. Pure helpers are exported for tests; the CLI entry point
// at the bottom wires them to git, depgraph, and the environment.
//
// Two impact modes produce the same report shape. `per-file` runs
// `depgraph impact path:<file>` once per changed file. `changed-set` runs
// `depgraph impact --changed <merge-base>` once (depgraph 0.7.0 and later) and
// splits its result back into per-file entries.
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
// depgraph exits 2 for every input or not-found error, not only selector
// misses: an out-of-range bound, a missing snapshot, or a bad git ref share it.
const IMPACT_EXIT_INPUT = 2;
// Only these first-line diagnostics (query.rs `choose_unique_bounded_cancellable`)
// mean the changed file has no graph node; any other exit 2 is a failure.
const SELECTOR_MISS_PATTERN = /^(?:graph query is invalid: )?selector ".*" did not match any node$/;
const SELECTOR_AMBIGUOUS_PATTERN = /^(?:graph query is invalid: )?selector ".*" is ambiguous;/;
// `MAX_INTERACTIVE_QUERY_TRAVERSAL` in depgraph-core; `ImpactRequest::try_new`
// rejects larger --max-nodes / --max-edges as "invalid service input".
const MAX_TRAVERSAL_LIMIT = 1_000_000;
const MESSAGE_LIMIT = 300;
const SKIPPED_PATH_LIMIT = 50;
const MAX_BUFFER_BYTES = 256 * 1024 * 1024;
const BASE_REF_PATTERN = /^[0-9A-Za-z._/~^@{}-]+$/;
const ATTEMPT_ID_PATTERN = /^[0-9A-Za-z][0-9A-Za-z._:-]*$/;
const KIND_ORDER = { route: 0, package_instance: 1 };
const OBJECT_ID_PATTERN = /^[0-9a-f]{40}(?:[0-9a-f]{24})?$/;

export const IMPACT_MODE_PER_FILE = "per-file";
export const IMPACT_MODE_CHANGED_SET = "changed-set";
const IMPACT_MODES = [IMPACT_MODE_PER_FILE, IMPACT_MODE_CHANGED_SET];
// `data.mode` of a selector-less `impact --changed` result (depgraph-core
// `CHANGED_SET_IMPACT_MODE`).
const CHANGED_SET_DATA_MODE = "changed_set";
// The changed-set result lists unmapped paths in `unmapped[]` and repeats each
// one as this diagnostic; the per-file status already says it.
const CHANGED_PATH_UNMAPPED_DIAGNOSTIC = "changed_path_unmapped";
// clap's usage line marks an optional positional as `[SELECTOR]` and a
// required one as `<SELECTOR>`; only a CLI with the optional form accepts
// `impact --changed <ref>` without a selector. The version number is not used:
// a build from main reports the last released version.
const OPTIONAL_SELECTOR_USAGE = /^Usage:.*\bimpact\b.*\[SELECTOR\]/m;
// What an older CLI prints when the selector is missing anyway.
const SELECTOR_REQUIRED_PATTERN = /required arguments were not provided[\s\S]*<SELECTOR>/;

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

/** Arguments of the single changed-set call; the ref is a validated object id. */
export function buildChangedSetImpactArgs({ store, changedRef, profiles = [], maxNodes, maxEdges }) {
  if (typeof changedRef !== "string" || !OBJECT_ID_PATTERN.test(changedRef)) {
    throw new Error(`changed-set ref is not an object id: ${JSON.stringify(changedRef)}`);
  }
  const args = ["--store", store, "impact", `--changed=${changedRef}`, "--json"];
  for (const profile of profiles) args.push(`--profile=${profile}`);
  if (maxNodes !== undefined) args.push(`--max-nodes=${maxNodes}`);
  if (maxEdges !== undefined) args.push(`--max-edges=${maxEdges}`);
  return args;
}

export function parseImpactMode(raw) {
  const mode = String(raw ?? "").trim() || IMPACT_MODE_PER_FILE;
  if (!IMPACT_MODES.includes(mode)) throw new Error(`impact-mode must be one of ${IMPACT_MODES.join(", ")}`);
  return mode;
}

/** Whether `depgraph impact --help` shows that the selector may be omitted. */
export function supportsChangedSetImpact({ exitCode, stdout }) {
  return exitCode === 0 && OPTIONAL_SELECTOR_USAGE.test(String(stdout ?? ""));
}

function firstLine(text) {
  const line = String(text ?? "")
    .split(/\r?\n/)
    .map((part) => part.trim())
    .find((part) => part.length > 0);
  return (line ?? "").replace(/^error:\s*/i, "");
}

function messageHead(text) {
  const head = firstLine(text);
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
  if (exitCode === IMPACT_EXIT_INPUT) {
    // Match the untruncated line: a long path would cut the head short.
    const line = firstLine(stderr);
    if (SELECTOR_MISS_PATTERN.test(line)) {
      return { status: "unmapped", exitCode, message: "no graph node for this path" };
    }
    if (SELECTOR_AMBIGUOUS_PATTERN.test(line)) {
      const candidates = String(stderr ?? "").match(/\(file, id:/g)?.length ?? 0;
      return { status: "unmapped", exitCode, message: `no graph node for this path (${candidates} other files share its suffix)` };
    }
  }
  return { status: "error", exitCode, message: head };
}

/** From an ambiguous-selector error, the id of the candidate that is exactly `path`. */
export function ambiguousCandidateId(stderr, path) {
  const text = String(stderr ?? "");
  if (!SELECTOR_AMBIGUOUS_PATTERN.test(firstLine(text))) return undefined;
  const pattern = /(file:\/\/|file:)([^\s()]+) \(file, id:([^\s(),]+)\)/g;
  for (const match of text.matchAll(pattern)) {
    if (match[2] === path && ATTEMPT_ID_PATTERN.test(match[3])) return match[3];
  }
  return undefined;
}

/** Turn the single changed-set `depgraph impact` process result into ok / error. */
export function classifyChangedSetResult({ exitCode, stdout, stderr }) {
  if (exitCode !== 0) {
    return { status: "error", exitCode, message: messageHead(stderr) || messageHead(stdout) || `exit ${exitCode}` };
  }
  let envelope;
  try {
    envelope = JSON.parse(stdout);
  } catch {
    return { status: "error", exitCode, message: "impact output is not valid JSON" };
  }
  const data = envelope?.data;
  if (
    !data ||
    typeof data !== "object" ||
    data.mode !== CHANGED_SET_DATA_MODE ||
    !Array.isArray(data.impacts) ||
    !Array.isArray(data.mappings) ||
    !Array.isArray(data.unmapped)
  ) {
    return { status: "error", exitCode, message: "impact JSON envelope is not a changed_set result" };
  }
  return { status: "ok", data };
}

/**
 * Split one changed-set result into the per-file results `aggregateReport`
 * folds, so both modes produce the same report.
 *
 * A file is `ok` when depgraph mapped it to at least one node, and `unmapped`
 * when its only mappings have none. Each impacted node (depth > 0) is credited
 * to every changed file in its `changed_paths`, with the depth and path depgraph
 * already reduced to the nearest change. Depth-0 nodes are the changed nodes
 * themselves and are left out, as `per-file` leaves out its root. A file the
 * result does not mention at all is an `error`: the two diffs disagree, and the
 * report must not claim that file has no impact.
 */
export function changedSetFiles(entries, data) {
  const mapped = new Map();
  for (const mapping of data.mappings) {
    const path = mapping?.change?.new_path ?? mapping?.change?.old_path;
    if (typeof path !== "string") continue;
    const nodes = Array.isArray(mapping.correlated_node_ids) ? mapping.correlated_node_ids.length : 0;
    mapped.set(path, (mapped.get(path) ?? 0) + nodes);
  }
  const impactsByPath = new Map();
  for (const item of data.impacts) {
    if (!(item.depth > 0)) continue;
    const impact = { node: item.node, depth: item.depth, changed_node_id: item.changed_node_id, dependency_path: item.dependency_path ?? [] };
    for (const path of item.changed_paths ?? []) {
      if (!impactsByPath.has(path)) impactsByPath.set(path, []);
      impactsByPath.get(path).push(impact);
    }
  }
  return entries.map((entry) => {
    if (entry.change === "D") return { ...entry, result: { status: "deleted" } };
    const nodes = mapped.get(entry.path);
    if (nodes === undefined) {
      return { ...entry, result: { status: "error", exitCode: 0, message: "changed-set impact did not report this path" } };
    }
    if (nodes === 0) return { ...entry, result: { status: "unmapped", exitCode: 0, message: "no graph node for this path" } };
    const impacts = impactsByPath.get(entry.path) ?? [];
    return { ...entry, result: { status: "ok", data: { complete: data.complete !== false, impacts, diagnostics: [] } } };
  });
}

function changedSetDiagnostics(data) {
  return (Array.isArray(data.diagnostics) ? data.diagnostics : [])
    .filter((diagnostic) => diagnostic?.code !== CHANGED_PATH_UNMAPPED_DIAGNOSTIC)
    .map((diagnostic) => ({ code: diagnostic.code, message: diagnostic.message }));
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
  diagnostics: reportDiagnostics = [],
  impactMode,
}) {
  const impacted = new Map();
  const changedFiles = [];
  const diagnostics = [...reportDiagnostics];
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
    } else if (result.status === "not_analyzed") {
      incomplete = true;
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

  const report = {
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
  if (impactMode) report.impact_mode = impactMode;
  return report;
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

function positiveInteger(name, value, maximum) {
  if (value === undefined || value === null || value === "") return undefined;
  const text = String(value).trim();
  if (!/^[1-9][0-9]{0,8}$/.test(text)) throw new Error(`${name} must be a positive integer`);
  const number = Number(text);
  if (maximum !== undefined && number > maximum) throw new Error(`${name} must be at most ${maximum}`);
  return number;
}

const HISTORY_HINT = "use actions/checkout with fetch-depth: 0, or fetch the base commit before this step";

// `rev-parse --quiet` and a history-less `merge-base` fail without stderr, so
// the bare git error says nothing; name the likely cause and keep git's details.
async function resolveHistory(runGit, args, what) {
  try {
    return (await runGit(args)).trim();
  } catch (error) {
    const details = [];
    if (error?.exitCode !== undefined) details.push(`exit code ${error.exitCode}`);
    const stderr = typeof error?.stderr === "string" ? messageHead(error.stderr) : "";
    if (stderr) details.push(stderr);
    const suffix = details.length > 0 ? ` (git ${args[0]}: ${details.join(", ")})` : "";
    throw new Error(`${what}; ${HISTORY_HINT}${suffix}`, { cause: error });
  }
}

/**
 * The impact mode this run can use. `changed-set` falls back to `per-file`
 * with a reason when depgraph cannot answer it: the scan is only readable as an
 * `attempt:` (a changed-set query needs the current completed snapshot), or the
 * CLI predates the selector-less `impact --changed`.
 */
async function resolveImpactMode(requested, { attemptId, runDepgraph }) {
  if (requested !== IMPACT_MODE_CHANGED_SET) return { requested, used: requested };
  if (attemptId !== undefined) {
    return {
      requested,
      used: IMPACT_MODE_PER_FILE,
      fallback_reason: "the scan is only readable as attempt:<scan_id>, which impact --changed does not accept",
    };
  }
  if (!supportsChangedSetImpact(await runDepgraph(["impact", "--help"]))) {
    return { requested, used: IMPACT_MODE_PER_FILE, fallback_reason: "this depgraph does not support impact --changed without a selector" };
  }
  return { requested, used: requested };
}

async function collectPerFile(entries, { canQuery, fileLimit, options, runDepgraph }) {
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
    let processResult = await runDepgraph(buildImpactArgs({ ...options, path: entry.path }));
    const candidate = processResult.exitCode === IMPACT_EXIT_INPUT ? ambiguousCandidateId(processResult.stderr, entry.path) : undefined;
    if (candidate) processResult = await runDepgraph(buildImpactArgs({ ...options, selector: `id:${candidate}` }));
    files.push({ ...entry, result: classifyImpactResult(processResult, { path: entry.path }) });
  }
  return { files, skipped, diagnostics: [] };
}

// One call covers every changed file, so max-files does not apply. A failed
// call (exit 2 for a HEAD mismatch, exit 3 for an exceeded bound) leaves every
// surviving file as an error rather than as having no impact.
async function collectChangedSet(entries, { mergeBase, options, runDepgraph }) {
  const processResult = await runDepgraph(buildChangedSetImpactArgs({ ...options, changedRef: mergeBase }));
  if (processResult.exitCode === IMPACT_EXIT_INPUT && SELECTOR_REQUIRED_PATTERN.test(String(processResult.stderr ?? ""))) {
    return { unsupported: true };
  }
  const result = classifyChangedSetResult(processResult);
  if (result.status !== "ok") {
    const files = entries.map((entry) => ({ ...entry, result: entry.change === "D" ? { status: "deleted" } : result }));
    return { files, skipped: [], diagnostics: [] };
  }
  return { files: changedSetFiles(entries, result.data), skipped: [], diagnostics: changedSetDiagnostics(result.data) };
}

/** Run the whole collection against injectable git and depgraph runners. */
export async function collectReport({
  baseRef,
  headRef = "HEAD",
  store,
  profiles = [],
  impactMode,
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
  onWarning = () => {},
}) {
  if (typeof baseRef !== "string" || !BASE_REF_PATTERN.test(baseRef) || baseRef.startsWith("-")) {
    throw new Error(`base ref is not a plain revision: ${JSON.stringify(baseRef)}`);
  }
  const requestedMode = parseImpactMode(impactMode);
  const fileLimit = positiveInteger("max-files", maxFiles) ?? 200;
  const nodeLimit = positiveInteger("max-nodes", maxNodes, MAX_TRAVERSAL_LIMIT);
  const edgeLimit = positiveInteger("max-edges", maxEdges, MAX_TRAVERSAL_LIMIT);

  const baseSha = await resolveHistory(runGit, ["rev-parse", "--verify", "--quiet", `${baseRef}^{commit}`], `cannot resolve base ref ${baseRef}`);
  const headSha = (await runGit(["rev-parse", "--verify", "--quiet", headRef])).trim();
  const mergeBase = await resolveHistory(runGit, ["merge-base", baseSha, headSha], `cannot find a merge-base between base ref ${baseRef} and ${headRef}`);
  const pathPrefix = (await runGit(["rev-parse", "--show-prefix"])).trim();
  const diff = await runGit(["diff", "--name-status", "-z", "--find-renames", "--relative", mergeBase, headSha, "--"]);
  const entries = parseNameStatusZ(diff);

  const attemptId = scanAttemptId(scanExitCode, scanOutput);
  const message = scanMessage ?? (scanOutput && typeof scanOutput.error === "string" ? messageHead(shortenAbsolutePaths(scanOutput.error)) : undefined);
  const scan = { exitCode: scanExitCode, partial: attemptId !== undefined && scanExitCode === SCAN_EXIT_WORKER_FAILURE, message };
  // A non-zero scan leaves only an attempt behind; without its id an impact
  // query cannot read what this scan produced, so it must not be issued.
  const canQuery = scanExitCode === SCAN_EXIT_OK || attemptId !== undefined;
  const options = { store, profiles, maxNodes: nodeLimit, maxEdges: edgeLimit, attemptId };

  const fallBack = (mode) => {
    onWarning(`impact-mode ${mode.requested} falls back to ${mode.used}: ${mode.fallback_reason}`);
    return mode;
  };
  let mode = canQuery ? await resolveImpactMode(requestedMode, { attemptId, runDepgraph }) : { requested: requestedMode, used: requestedMode };
  if (mode.fallback_reason) fallBack(mode);
  let collected;
  if (canQuery && mode.used === IMPACT_MODE_CHANGED_SET) {
    collected = await collectChangedSet(entries, { mergeBase, options, runDepgraph });
    if (collected.unsupported) {
      mode = fallBack({ requested: requestedMode, used: IMPACT_MODE_PER_FILE, fallback_reason: "this depgraph requires a selector for impact" });
      collected = undefined;
    }
  }
  collected ??= await collectPerFile(entries, { canQuery, fileLimit, options, runDepgraph });

  return aggregateReport({
    baseSha,
    mergeBase,
    headSha,
    pathPrefix,
    depgraphVersion,
    strict,
    scan,
    files: collected.files,
    skipped: collected.skipped,
    diagnostics: collected.diagnostics,
    impactMode: mode,
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
    if (result.exitCode === 0) return result.stdout;
    const error = new Error(`git ${args[0]} failed (exit code ${result.exitCode}): ${messageHead(result.stderr)}`);
    error.exitCode = result.exitCode;
    error.stderr = result.stderr;
    throw error;
  };
  const runDepgraph = (args) => execFileResult(depgraph, args, {});

  const report = await collectReport({
    baseRef: env.BASE_REF,
    store: env.DEPGRAPH_STORE,
    profiles: parseProfiles(env.PROFILES),
    impactMode: env.IMPACT_MODE,
    maxFiles: env.MAX_FILES,
    maxNodes: env.MAX_NODES,
    maxEdges: env.MAX_EDGES,
    scanExitCode,
    scanOutput: readScanOutput(env.SCAN_OUTPUT_PATH),
    strict: env.STRICT === "true",
    depgraphVersion: env.DEPGRAPH_VERSION ?? "unknown",
    runGit,
    runDepgraph,
    onWarning: (text) => console.log(`::warning::${text}`),
  });
  writeFileSync(reportPath, `${JSON.stringify(report, null, 2)}\n`);
  if (env.GITHUB_OUTPUT) {
    appendFileSync(env.GITHUB_OUTPUT, `impacted-count=${report.totals.impacted}\nscan-status=${report.scan.status}\n`);
  }
  console.log(
    `depgraph pr-impact: ${report.totals.changed} changed file(s), ${report.totals.impacted} impacted node(s), scan ${report.scan.status}, impact-mode ${report.impact_mode.used}`,
  );
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  main().catch((error) => {
    console.error(`depgraph pr-impact collect: ${error.message}`);
    process.exit(1);
  });
}
