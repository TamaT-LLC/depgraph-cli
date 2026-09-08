// Public synthetic fixture for the core + real Go/Web worker boundary.
// Run after `cargo xtask build`; no project code or package manager is run.
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { performance } from "node:perf_hooks";
import { DatabaseSync } from "node:sqlite";
import { setTimeout as delay } from "node:timers/promises";
import { assertWorkspaceQuery } from "./resumable-analysis-query-assertions.mjs";

const workspace = path.resolve(import.meta.dirname, "..");
const executableSuffix = process.platform === "win32" ? ".exe" : "";
const cli = path.resolve(process.env.DEPGRAPH_BIN ?? path.join(workspace, `target/debug/depgraph${executableSuffix}`));
const parent = mkdtempSync(path.join(tmpdir(), "depgraph-resumable-e2e-"));
const root = path.join(parent, "repository");
const includeWeb = process.env.DEPGRAPH_RESUMABLE_GO_ONLY !== "1";
const unicodeSourcePaths = [
  `frontend/packages/shared/src/${String.fromCodePoint(0xE000)}.ts`,
  `frontend/packages/shared/src/${String.fromCodePoint(0x10000)}.ts`,
];
const ambientDeclarationPath = "frontend/packages/shared/global.d.ts";
const environment = {
  ...process.env,
  GOTOOLCHAIN: "local", GOPROXY: "off", GOSUMDB: "off", GOWORK: "off",
  GOMODCACHE: path.join(parent, "empty-module-cache"),
  GOPATH: path.join(parent, "empty-gopath"),
  DEPGRAPH_GO_WORKER: process.env.DEPGRAPH_GO_WORKER ?? path.join(workspace, `workers/go/bin/depgraph-go-worker${executableSuffix}`),
  DEPGRAPH_WEB_WORKER: process.env.DEPGRAPH_WEB_WORKER ?? path.join(workspace, "workers/web/dist/worker.mjs"),
};
function write(relative, value) {
  const file = path.join(root, relative);
  mkdirSync(path.dirname(file), { recursive: true });
  writeFileSync(file, typeof value === "string" ? value : JSON.stringify(value));
}
function runProcess(store, args) {
  return spawnSync(cli, ["--store", store, ...args], {
    cwd: root, env: environment, encoding: "utf8", maxBuffer: 32 * 1024 * 1024,
  });
}
function run(store, args) {
  const result = runProcess(store, args);
  assert.equal(result.status, 0, `${args.join(" ")}: ${result.error ?? result.stderr}\n${result.stdout}`);
  return JSON.parse(result.stdout);
}
function scan(store) {
  const start = performance.now();
  const output = run(store, ["scan", root, "--json"]);
  assert.equal(output.status, "completed");
  assert.equal(output.coverage.project_code_executed, false);
  assert.ok(output.analysis.units.length > 4, "real source-batch schedule is required");
  assert.ok(output.analysis.units.every((unit) => unit.status === "completed"));
  return { output, duration_ms: Math.round(performance.now() - start) };
}
function stageSummary(outcome) {
  const stages = new Map();
  for (const unit of outcome.analysis.units) {
    const key = `${unit.adapter}:${unit.stage}`;
    const stage = stages.get(key) ?? { units: 0, completed: 0, reused: 0, worker_duration_ms: 0 };
    stage.units += 1;
    stage.completed += Number(unit.status === "completed");
    stage.reused += Number(unit.reused);
    stage.worker_duration_ms += unit.duration_ms;
    stages.set(key, stage);
  }
  return Object.fromEntries([...stages].sort(([left], [right]) => left.localeCompare(right)));
}
function graph(store, attemptId) {
  const exported = run(store, ["export", "--format", "json", ...(attemptId ? ["--scan-id", `attempt:${attemptId}`] : [])]);
  assert.ok(exported.nodes.length > 0 && exported.edges.length > 0);
  // CLI JSON export intentionally projects nodes and edges. Compare every
  // persisted graph payload as well, so profiles, sites, evidence, conditions,
  // diagnostics, and coverage cannot disappear behind that projection.
  const database = new DatabaseSync(store, { readOnly: true });
  try {
    const scanId = attemptId ?? database.prepare(`
      SELECT s.scan_id FROM completed_snapshots s
      JOIN current_completed_snapshot c ON c.snapshot_id = s.id
    `).get().scan_id;
    const payloads = (table, column) => database.prepare(
      `SELECT ${column} AS payload FROM ${table} WHERE scan_id = ? ORDER BY id`,
    ).all(scanId).map((row) => JSON.parse(row.payload));
    const profiles = payloads("profiles", "json");
    assert.ok(profiles.length > 0, "completed scan has no persisted profiles");
    return {
      exported,
      profiles,
      nodes: payloads("nodes", "raw_json"),
      edges: payloads("edges", "raw_json"),
      sites: payloads("sites", "raw_json"),
      diagnostics: payloads("diagnostics", "raw_json"),
      evidence: database.prepare(`SELECT owner_type, owner_id, ordinal, raw_json
        FROM evidence WHERE scan_id = ? ORDER BY owner_type, owner_id, ordinal`)
        .all(scanId).map(({ raw_json, ...owner }) => ({ ...owner, evidence: JSON.parse(raw_json) })),
      coverage: JSON.parse(database.prepare("SELECT json FROM coverage WHERE scan_id = ?").get(scanId).json),
      profile_coverage: database.prepare("SELECT profile_id, json FROM profile_coverage WHERE scan_id = ? ORDER BY profile_id")
        .all(scanId).map((row) => ({ profile_id: row.profile_id, coverage: JSON.parse(row.json) })),
      file_coverage: database.prepare(`SELECT path, discovered_sites, emitted_sites,
        skipped_sites, skipped, reason, adapter FROM file_coverage
        WHERE scan_id = ? ORDER BY path, adapter`).all(scanId),
    };
  } finally {
    database.close();
  }
}
function currentCompletedSnapshot(store) {
  const database = new DatabaseSync(store, { readOnly: true });
  try {
    return database.prepare(`SELECT s.id, s.scan_id FROM completed_snapshots s
      JOIN current_completed_snapshot c ON c.snapshot_id = s.id`).get();
  } finally {
    database.close();
  }
}
function configure(batch, parallel) {
  write(".depgraph.toml", `schema_version = 1\n[scan]\nmax_unit_source_files = ${batch}\nmax_concurrent_units = ${parallel}\n`);
}
function unitIdsFor(expected, adapter) {
  const ids = [...new Set(expected.profiles
    .filter((profile) => profile.language === adapter)
    .map((profile) => profile.properties.analysis_unit_id)
    .filter((id) => typeof id === "string"))];
  assert.ok(ids.length > 0, `${adapter} analysis unit identities are missing from the graph`);
  return ids;
}
function unitIdForRoot(expected, adapter, unitRoot) {
  const id = expected.profiles.find((profile) => (
    profile.language === adapter && profile.properties.analysis_unit_root === unitRoot
  ))?.properties.analysis_unit_id;
  assert.equal(typeof id, "string", `${adapter} unit ${unitRoot} is missing from the graph`);
  return id;
}
function makeWebWorkerWrapper(name, { pauseSemantic = false } = {}) {
  const worker = environment.DEPGRAPH_WEB_WORKER;
  const wrapper = path.join(parent, name);
  const interruptionSentinel = path.join(parent, `${name}.semantic-interrupted`);
  const pause = pauseSemantic ? `
if (request?.stage === 'semantic' && !existsSync(${JSON.stringify(interruptionSentinel)})) {
  writeFileSync(${JSON.stringify(interruptionSentinel)}, JSON.stringify({ pid: process.pid, unit_id: request.unit_id }));
  setInterval(() => {}, 1000);
  await new Promise(() => {});
}
` : "";
  writeFileSync(wrapper, `#!/usr/bin/env node
// Compatibility marker keeps this public wrapper byte-distinct from the real artifact.
import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
const args = process.argv.slice(2);
const index = args.indexOf('--analysis-unit');
const request = index < 0 ? null : JSON.parse(readFileSync(args[index + 1], 'utf8'));
${pause}
const result = spawnSync(process.execPath, [${JSON.stringify(worker)}, ...args], { stdio: 'inherit' });
if (result.error) {
  process.stderr.write(String(result.error));
  process.exit(1);
}
process.exit(result.status ?? 1);
`);
  chmodSync(wrapper, 0o700);
  if (pauseSemantic) rmSync(interruptionSentinel, { force: true });
  return { worker, wrapper, interruptionSentinel };
}
async function verifyWebSemanticInterruptionAndResume(expected) {
  if (!includeWeb || process.platform === "win32") return { skipped: "Web interruption fixture requires POSIX worker" };
  const webIds = unitIdsFor(expected, "web");
  const originalWorker = environment.DEPGRAPH_WEB_WORKER;
  const { wrapper, interruptionSentinel } = makeWebWorkerWrapper("web-worker-interruption.mjs", { pauseSemantic: true });
  const store = path.join(parent, "web-semantic-interruption.sqlite");
  configure(128, 1);
  scan(store);
  const completedBefore = currentCompletedSnapshot(store);
  assert.ok(completedBefore, "interruption fixture has no completed snapshot to preserve");
  assert.deepEqual(graph(store), expected, "interruption fixture baseline differs from the public graph");
  environment.DEPGRAPH_WEB_WORKER = wrapper;
  const child = spawn(cli, ["--store", store, "scan", root, "--json"], {
    cwd: root, env: environment, stdio: ["ignore", "pipe", "pipe"],
  });
  let stdout = "", stderr = "", ended = false;
  child.stdout.on("data", (data) => { stdout += data; });
  child.stderr.on("data", (data) => { stderr += data; });
  const completion = new Promise((resolve, reject) => {
    child.once("error", reject);
    child.once("close", (code, signal) => { ended = true; resolve({ code, signal }); });
  });
  try {
    const deadline = performance.now() + 60_000;
    while (!existsSync(interruptionSentinel) && !ended && performance.now() < deadline) await delay(25);
    assert.ok(existsSync(interruptionSentinel), `Web semantic stage did not stop: ${stderr}\n${stdout}`);
    child.kill("SIGINT");
    const stopped = await completion;
    assert.equal(stopped.signal, null, `CLI did not handle Web cancellation: ${stderr}\n${stdout}`);
    assert.equal(stopped.code, 3, `${stderr}\n${stdout}`);
    const interrupted = JSON.parse(stdout);
    assert.equal(interrupted.status, "cancelled");
    assert.equal(interrupted.completed_snapshot_id ?? null, null);
    const interruptedUnits = interrupted.analysis?.units ?? [];
    const interruptedWebUnits = interruptedUnits.filter((unit) => webIds.some((id) => unit.unit_id.startsWith(`${id}:`)));
    assert.ok(interruptedWebUnits.some((unit) => unit.stage === "syntax" && unit.status === "completed"), "Web syntax did not checkpoint before semantic interruption");
    assert.ok(interruptedWebUnits.some((unit) => unit.stage === "semantic" && (unit.status === "cancelled" || unit.status === "failed")), "Web semantic interruption was not recorded");
    const partial = run(store, ["export", "--scan-id", `attempt:${interrupted.scan_id}`, "--format", "json"]);
    assert.equal(partial.partial.analysis_complete, false);
    assert.ok(partial.nodes.length > 0, "semantic interruption discarded all validated partial graph data");
    assert.deepEqual(currentCompletedSnapshot(store), completedBefore, "partial attempt replaced the existing completed snapshot");
    assert.deepEqual(graph(store), expected, "partial attempt changed the default completed graph");
    const partialGraph = graph(store, interrupted.scan_id);
    const partialQueries = [
      ["deps", ["path:frontend/apps/web/src/index.ts", "--transitive", "--all"]],
      ["dependents", ["path:frontend/packages/shared/src/index.ts", "--transitive", "--all"]],
      ["why", ["path:frontend/apps/web/src/index.ts", "path:frontend/packages/shared/src/index.ts"]],
      ["impact", ["path:frontend/packages/shared/src/index.ts"]],
    ];
    for (const [command, args] of partialQueries) {
      const output = run(store, [command, ...args, "--scan-id", `attempt:${interrupted.scan_id}`, "--json"]);
      assert.ok(output.data, `${command} returned no partial graph result`);
      assert.equal(output.partial?.attempt_id, interrupted.scan_id, `${command} selected a different attempt`);
      assert.equal(output.partial?.analysis_complete, false, `${command} claimed complete analysis for the partial attempt`);
      assertWorkspaceQuery(command, output.data, partialGraph);
    }
    const health = run(store, ["health", "list", "--scan-id", `attempt:${interrupted.scan_id}`, "--kind", "unused-file", "--all", "--json"]);
    assert.ok((health.data?.findings ?? []).every((finding) => finding.confidence !== "confirmed"), "partial Web scan promoted an unused finding to confirmed");

    const resumed = scan(store);
    const resumedWebUnits = resumed.output.analysis.units.filter((unit) => webIds.some((id) => unit.unit_id.startsWith(`${id}:`)));
    assert.ok(resumedWebUnits.some((unit) => unit.stage === "syntax" && unit.reused), "resume did not reuse Web syntax checkpoint");
    assert.ok(resumedWebUnits.some((unit) => unit.stage === "semantic" && !unit.reused), "resume reused an incomplete Web semantic checkpoint");
    assert.deepEqual(graph(store), expected, "Web semantic interruption and resume changed the canonical graph");
    return {
      interrupted_status: interrupted.status,
      stopped_web_units: interruptedWebUnits.filter((unit) => unit.status === "cancelled" || unit.status === "failed").length,
      resumed_reused: resumed.output.analysis.units.filter((unit) => unit.reused).length,
      partial_unused_findings: health.data?.findings?.length ?? 0,
      partial_queries: partialQueries.map(([command]) => command),
      current_completed_preserved: true,
    };
  } finally {
    if (!ended) { child.kill("SIGINT"); await completion; }
    environment.DEPGRAPH_WEB_WORKER = originalWorker;
  }
}
function verifyWebConfigAndArtifactReexecution(expected) {
  if (!includeWeb) return { skipped: "Web reexecution fixture disabled" };
  const webIds = unitIdsFor(expected, "web");
  const goIds = unitIdsFor(expected, "go");
  const goRootId = unitIdForRoot(expected, "go", ".");
  const goSharedId = unitIdForRoot(expected, "go", "modules/shared");
  const goIndependentId = unitIdForRoot(expected, "go", "tools/independent");
  const appId = unitIdForRoot(expected, "web", "frontend/apps/web");
  const sharedId = unitIdForRoot(expected, "web", "frontend/packages/shared");
  const store = path.join(parent, "web-input-reexecution.sqlite");
  configure(128, 1);
  scan(store);
  assert.deepEqual(graph(store), expected, "input reexecution fixture baseline differs from the public graph");
  const configPath = path.join(root, "frontend/apps/web/tsconfig.json");
  const originalConfig = readFileSync(configPath, "utf8");
  const originalWorker = environment.DEPGRAPH_WEB_WORKER;
  let configRun;
  let artifactRun;
  try {
    const config = JSON.parse(originalConfig);
    config.compilerOptions = { ...config.compilerOptions, strict: true };
    writeFileSync(configPath, JSON.stringify(config));
    configRun = scan(store);
    assert.ok(unitRuns(configRun.output, appId).length > 0 && unitRuns(configRun.output, appId).every((unit) => !unit.reused), "Web app config edit reused stale Web analysis");
    assert.ok(unitRuns(configRun.output, sharedId).length > 0 && unitRuns(configRun.output, sharedId).every((unit) => unit.reused), "Web app config edit discarded an unrelated shared checkpoint");
    assert.ok(unitRuns(configRun.output, goRootId).length > 0 && unitRuns(configRun.output, goRootId).every((unit) => !unit.reused), "repository-wide Go config input was not re-executed");
    for (const id of [goSharedId, goIndependentId]) assert.ok(unitRuns(configRun.output, id).every((unit) => unit.reused), "Web config edit discarded an unrelated Go checkpoint");
    const configCleanStore = path.join(parent, "web-config-clean.sqlite");
    scan(configCleanStore);
    assert.deepEqual(graph(store), graph(configCleanStore), "Web config reexecution changed the graph compared with a clean scan");

    writeFileSync(configPath, originalConfig);
    const { wrapper } = makeWebWorkerWrapper("web-worker-compatibility-v2.mjs");
    environment.DEPGRAPH_WEB_WORKER = wrapper;
    artifactRun = scan(store);
    for (const id of webIds) assert.ok(unitRuns(artifactRun.output, id).length > 0 && unitRuns(artifactRun.output, id).every((unit) => !unit.reused), "Web worker artifact change reused stale Web analysis");
    for (const id of goIds) assert.ok(unitRuns(artifactRun.output, id).every((unit) => unit.reused), "Web worker artifact change discarded a valid Go checkpoint");
    assert.deepEqual(graph(store), expected, "compatible Web worker artifact changed the canonical graph");
    return {
      config_app_reused: configRun.output.analysis.units.filter((unit) => unit.reused && unit.unit_id.startsWith(`${appId}:`)).length,
      config_reused: configRun.output.analysis.units.filter((unit) => unit.reused).length,
      artifact_web_reused: artifactRun.output.analysis.units.filter((unit) => webIds.some((id) => unit.unit_id.startsWith(`${id}:`)) && unit.reused).length,
      artifact_reused: artifactRun.output.analysis.units.filter((unit) => unit.reused).length,
    };
  } finally {
    writeFileSync(configPath, originalConfig);
    environment.DEPGRAPH_WEB_WORKER = originalWorker;
  }
}
// Pause a real worker at the next expensive stage, outside the analyzed tree.
// The wrapper's bytes and CLI configuration stay identical across both runs.
// SIGINT exercises the same cancellation and child-reaping path as a user stop.
async function interruptAndResume(expected) {
  if (process.platform === "win32") return { skipped: "POSIX process signal fixture" };
  const worker = environment.DEPGRAPH_GO_WORKER;
  const gate = path.join(parent, "pause-semantic");
  const reached = path.join(parent, "semantic-started");
  const wrapper = path.join(parent, "go-worker-wrapper.mjs");
  writeFileSync(wrapper, `#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
const args = process.argv.slice(2);
const index = args.indexOf('--analysis-unit');
const request = index < 0 ? null : JSON.parse(readFileSync(args[index + 1], 'utf8'));
if (request?.stage === 'semantic' && existsSync(${JSON.stringify(gate)})) {
  writeFileSync(${JSON.stringify(reached)}, JSON.stringify({ pid: process.pid, unit_id: request.unit_id }));
  setInterval(() => {}, 1000);
  await new Promise(() => {});
} else {
  const result = spawnSync(${JSON.stringify(worker)}, args, { stdio: 'inherit' });
  process.exit(result.status ?? 1);
}
`);
  chmodSync(wrapper, 0o700);
  environment.DEPGRAPH_GO_WORKER = wrapper;
  const store = path.join(parent, "interrupted.sqlite");
  writeFileSync(gate, "pause");
  const child = spawn(cli, ["--store", store, "scan", root, "--json"], {
    cwd: root, env: environment, stdio: ["ignore", "pipe", "pipe"],
  });
  let stdout = "", stderr = "", ended = false;
  child.stdout.on("data", (data) => { stdout += data; });
  child.stderr.on("data", (data) => { stderr += data; });
  const completion = new Promise((resolve, reject) => {
    child.once("error", reject);
    child.once("close", (code, signal) => { ended = true; resolve({ code, signal }); });
  });
  try {
    const deadline = performance.now() + 60_000;
    while (!existsSync(reached) && !ended && performance.now() < deadline) await delay(25);
    assert.ok(existsSync(reached), `semantic stage did not start: ${stderr}\n${stdout}`);
    child.kill("SIGINT");
    const stopped = await completion;
    assert.equal(stopped.signal, null, "CLI did not handle cancellation");
    assert.equal(stopped.code, 3, `${stderr}\n${stdout}`);
    const partial = JSON.parse(stdout);
    assert.ok(partial.completed_snapshot_id == null);
    assert.notEqual(partial.status, "completed");
    assert.ok(partial.analysis.units.some((unit) => unit.stage === "syntax" && unit.status === "completed"));
    assert.ok(partial.analysis.units.some((unit) => unit.stage === "typed" && unit.status === "completed"), "no typed checkpoint survived the stop");
    assert.ok(partial.analysis.units.some((unit) => unit.status === "cancelled" || unit.status === "failed"));
    const readable = run(store, ["export", "--scan-id", `attempt:${partial.scan_id}`, "--format", "json"]);
    assert.equal(readable.partial.attempt_id, partial.scan_id);
    assert.equal(readable.partial.analysis_complete, false);
    assert.ok(readable.nodes.length > 0, "cancelled scan lost validated syntax results");
    assert.ok(readable.nodes.some((node) => node.kind === "symbol" || node.kind === "type"), "cancelled scan lost its completed typed graph");
    rmSync(gate);
    const resumed = scan(store);
    assert.ok(resumed.output.analysis.units.some((unit) => unit.stage === "syntax" && unit.reused));
    assert.ok(resumed.output.analysis.units.some((unit) => unit.stage === "typed" && unit.reused), "resumed CLI did not reuse its typed checkpoint");
    assert.deepEqual(graph(store), expected, "cancellation and resumed CLI changed the canonical graph");
    return { duration_ms: resumed.duration_ms, reused: resumed.output.analysis.units.filter((unit) => unit.reused).length };
  } finally {
    if (!ended) { child.kill("SIGINT"); await completion; }
    environment.DEPGRAPH_GO_WORKER = worker;
  }
}

function unitRuns(output, unitId) {
  return output.analysis.units.filter((unit) => unit.unit_id.startsWith(`${unitId}:`));
}

function verifySelectiveInvalidation(store, expected) {
  const goUnit = (unitRoot) => expected.profiles.find((profile) => profile.language === "go"
    && profile.properties.analysis_unit_root === unitRoot)?.properties.analysis_unit_id;
  const app = goUnit("."), shared = goUnit("modules/shared"), independent = goUnit("tools/independent");
  assert.ok(app && shared && independent, "Go unit identities are missing from the graph");
  write("tools/independent/value.go", "package independent\nfunc Value() int { return 2 }\n");
  const unrelated = scan(store);
  for (const id of [app, shared]) {
    const runs = unitRuns(unrelated.output, id);
    assert.ok(runs.length > 0 && runs.every((unit) => unit.reused), "unrelated module edit discarded a valid checkpoint");
  }
  assert.ok(unitRuns(unrelated.output, independent).every((unit) => !unit.reused));
  write("modules/shared/shared.go", 'package shared\nfunc Use() string {return "changed"}\n');
  const dependency = scan(store);
  for (const id of [app, shared]) {
    const runs = unitRuns(dependency.output, id);
    assert.ok(runs.length > 0 && runs.every((unit) => !unit.reused), "local replacement edit reused stale dependent analysis");
  }
  assert.ok(unitRuns(dependency.output, independent).every((unit) => unit.reused));
  // A clean store must agree with selective reuse, including evidence and IDs.
  const cleanStore = path.join(parent, "changed-clean.sqlite");
  scan(cleanStore);
  assert.deepEqual(graph(store), graph(cleanStore), "selective reuse changed the edited graph");
  let webDependencyReused;
  if (includeWeb) {
    const webUnits = ["frontend/apps/web", "frontend/packages/shared"].map((unitRoot) =>
      expected.profiles.find((profile) => profile.language === "web"
        && profile.properties.analysis_unit_root === unitRoot)?.properties.analysis_unit_id);
    assert.ok(webUnits.every(Boolean), "Web unit identities are missing from the graph");
    write("frontend/packages/shared/src/index.ts", 'export type Shared = {value:string};\nexport function shared(): Shared {return {value:"changed"};}\n');
    const webDependency = scan(store);
    for (const id of webUnits) {
      const runs = unitRuns(webDependency.output, id);
      assert.ok(runs.length > 0 && runs.every((unit) => !unit.reused), "workspace dependency edit reused stale Web analysis");
    }
    for (const id of [app, shared, independent]) {
      assert.ok(unitRuns(webDependency.output, id).every((unit) => unit.reused), "Web edit discarded a valid Go checkpoint");
    }
    const webCleanStore = path.join(parent, "web-changed-clean.sqlite");
    scan(webCleanStore);
    assert.deepEqual(graph(store), graph(webCleanStore), "Web selective reuse changed the edited graph");
    webDependencyReused = webDependency.output.analysis.units.filter((unit) => unit.reused).length;
  }
  return {
    unrelated_reused: unrelated.output.analysis.units.filter((unit) => unit.reused).length,
    dependency_reused: dependency.output.analysis.units.filter((unit) => unit.reused).length,
    ...(webDependencyReused === undefined ? {} : { web_dependency_reused: webDependencyReused }),
  };
}
try {
  mkdirSync(environment.GOMODCACHE, { recursive: true });
  mkdirSync(environment.GOPATH, { recursive: true });
  write("go.mod", "module example.test/app\n\ngo 1.26.1\n\nrequire example.test/shared v0.0.0\nreplace example.test/shared => ./modules/shared\n");
  write("main.go", 'package main\nimport "example.test/shared"\nfunc main(){ shared.Use() }\n');
  write("extra.go", "package main\nfunc extra(){}\n");
  write("modules/shared/go.mod", "module example.test/shared\n\ngo 1.26.1\n");
  write("modules/shared/shared.go", 'package shared\nfunc Use() string {return "ok"}\n');
  write("tools/independent/go.mod", "module example.test/independent\n\ngo 1.26.1\n");
  write("tools/independent/value.go", "package independent\nfunc Value() int { return 1 }\n");
  if (includeWeb) {
    write("frontend/pnpm-workspace.yaml", "packages: ['apps/*', 'packages/*'] # nested workspace\n");
    write("frontend/package.json", { name: "fixture-frontend", private: true });
    write("frontend/apps/web/package.json", {
      name: "fixture-web", version: "1.0.0", dependencies: { "@fixture/shared": "workspace:*" },
    });
    const compilerOptions = { target: "esnext", module: "preserve", moduleResolution: "bundler" };
    write("frontend/apps/web/tsconfig.json", { compilerOptions: { ...compilerOptions,
      baseUrl: ".", paths: { "@fixture/shared": ["../../packages/shared/src/index.ts"] },
    } });
    write("frontend/apps/web/src/index.ts", 'import { shared, sharedDate, type Shared } from "@fixture/shared";\nexport const value: Shared = shared();\nexport const ambientValue: string = sharedAmbientMessage();\nexport const appDate = new Date();\nexport const packageDate = sharedDate();\nexport { extra } from "./extra";\n');
    write("frontend/apps/web/src/extra.ts", 'import { value } from "./index";\nexport function extra() {return value;}\n');
    write("frontend/packages/shared/package.json", {
      name: "@fixture/shared", version: "1.0.0", exports: { types: "./src/index.ts", default: "./src/index.ts" },
    });
    write("frontend/packages/shared/tsconfig.json", { compilerOptions });
    write("frontend/packages/shared/src/index.ts", 'export type Shared = {value:string};\nexport function shared(): Shared {return {value:"ok"};}\nexport function sharedDate(): Date {return new Date();}\n');
    write(ambientDeclarationPath, "declare function sharedAmbientMessage(): string;\n");
    write(unicodeSourcePaths[0], 'export const unicodeBmp = "bmp";\n');
    write(unicodeSourcePaths[1], 'export const unicodeSupplementary = "supplementary";\n');
  }

  const baselineStore = path.join(parent, "baseline.sqlite");
  configure(128, 1);
  const baseline = scan(baselineStore);
  const expected = graph(baselineStore);
  const replacementImports = expected.sites.filter((site) => site.kind === "import"
    && site.specifier === "example.test/shared");
  assert.ok(replacementImports.length > 0, "Go local replacement import is missing");
  for (const site of replacementImports) {
    assert.equal(site.resolution_status, "resolved", "Go local replacement was classified as external");
    assert.ok(site.target_ids.length > 0 && site.target_ids.every((id) => {
      const node = expected.nodes.find((candidate) => candidate.id === id);
      return node && !["external_system", "unknown_target"].includes(node.kind);
    }), "Go local replacement lost its internal target");
  }
  if (includeWeb) {
    const sharedPackage = expected.nodes.find((node) => (
      node.kind === "package_instance" && node.display_name === "@fixture/shared"
        && node.properties.workspace === true
    ));
    assert.ok(sharedPackage, "inline pnpm workspace lost its internal package");
    const workspaceDependency = expected.sites.filter((site) => (
      site.kind === "package_dependency" && site.specifier === "@fixture/shared"
    ));
    assert.ok(workspaceDependency.length > 0, "inline pnpm workspace dependency is missing");
    for (const site of workspaceDependency) {
      assert.equal(site.resolution_status, "resolved", "inline pnpm workspace dependency was not resolved internally");
      assert.deepEqual(site.target_ids, [sharedPackage.id], "inline pnpm workspace dependency lost its internal target");
    }
    for (const relative of unicodeSourcePaths) {
      assert.ok(expected.nodes.some((node) => node.kind === "file" && node.properties.path === relative), `Unicode source ${relative} is missing from the baseline graph`);
    }
    const ambientDiagnostics = expected.diagnostics.filter((diagnostic) => (
      diagnostic.path === "frontend/apps/web/src/index.ts"
        && /TS2304|sharedAmbientMessage/u.test(diagnostic.message)
    ));
    assert.deepEqual(ambientDiagnostics, [], "shared package ambient declaration was not resolved in the Web compiler context");
    const ambientDeclaration = expected.nodes.find((node) => (
      node.kind === "symbol"
        && node.display_name === "sharedAmbientMessage"
        && node.properties.source_path === ambientDeclarationPath
    ));
    assert.ok(ambientDeclaration, "ambient declaration symbol is missing from the baseline graph");
    assert.ok(expected.nodes.some((node) => (
      node.kind === "symbol"
        && node.display_name === "ambientValue"
        && node.properties.source_path === "frontend/apps/web/src/index.ts"
    )), "ambient reference owner symbol is missing from the baseline graph");
    const dateExternal = expected.nodes.find((node) => (
      node.kind === "external_system"
        && node.properties.canonical_identity?.locator === "typescript:stdlib:Date"
    ));
    assert.ok(dateExternal, "shared TypeScript standard-library sentinel is missing from the baseline graph");
    const dateProfiles = dateExternal?.properties.profile_ids;
    assert.ok(Array.isArray(dateProfiles) && dateProfiles.length >= 2, "shared TypeScript sentinel did not retain all Web profile memberships");
    assert.equal(dateExternal?.properties.profile_id, dateProfiles?.[0], "shared TypeScript sentinel representative profile is not canonical");
    const ambientCallSite = expected.sites.find((site) => (
      site.kind === "call"
        && site.specifier === "sharedAmbientMessage"
        && site.resolution_status === "resolved"
        && site.target_ids.length === 1
        && site.target_ids[0] === ambientDeclaration.id
    ));
    assert.ok(ambientCallSite, "ambient reference has no resolved semantic target site");
    const ambientCallSource = expected.nodes.find((node) => node.id === ambientCallSite.source);
    assert.equal(ambientCallSource?.properties.source_path, "frontend/apps/web/src/index.ts", "ambient reference is not owned by the app source");
    assert.ok(expected.edges.some((edge) => (
      edge.kind === "calls"
        && edge.site_id === ambientCallSite.id
        && edge.target === ambientDeclaration.id
        && edge.resolution_status === "resolved"
    )), "ambient reference has no resolved semantic target edge");
  }
  const splitStore = path.join(parent, "split.sqlite");
  configure(1, 2);
  const split = scan(splitStore);
  assert.ok(split.output.analysis.units.length > baseline.output.analysis.units.length);
  assert.deepEqual(graph(splitStore), expected, "batch size and parallelism changed the canonical graph");
  const resumed = scan(splitStore);
  assert.ok(resumed.output.analysis.units.some((unit) => unit.reused), "warm scan reused no completed units");
  assert.deepEqual(graph(splitStore), expected, "restarted CLI changed the canonical graph");

  for (const [command, args] of includeWeb ? [
    ["deps", ["path:frontend/apps/web/src/index.ts", "--transitive", "--all"]],
    ["dependents", ["path:frontend/packages/shared/src/index.ts", "--transitive", "--all"]],
    ["why", ["path:frontend/apps/web/src/index.ts", "path:frontend/packages/shared/src/index.ts"]],
    ["impact", ["path:frontend/packages/shared/src/index.ts"]],
  ] : []) {
    const output = run(splitStore, [command, ...args, "--json"]);
    assert.ok(output.data, `${command} returned no graph result`);
    assertWorkspaceQuery(command, output.data, expected);
  }
  const interrupted = await interruptAndResume(expected);
  const web_interruption = await verifyWebSemanticInterruptionAndResume(expected);
  const web_reexecution = verifyWebConfigAndArtifactReexecution(expected);
  configure(1, 2);
  const invalidation = verifySelectiveInvalidation(splitStore, expected);
  // A missing dependency is a semantic limitation, even when every worker
  // completed. Preserve the limitation in normal snapshot health and reuse.
  if (includeWeb) {
    write("frontend/apps/web/src/unknown.ts", 'import "missing-external-package";\nexport const unusedUnknown = 1;\n');
    const unknownStore = path.join(parent, "unknown.sqlite");
    const unknown = scan(unknownStore).output;
    assert.equal(unknown.analysis_coverage.complete, true);
    assert.equal(unknown.analysis_coverage.unanalysed_units, 0);
    assert.ok(unknown.coverage.reasons.includes("analysis-unit-unknown-dependency"));
    assert.ok(!unknown.coverage.completeness.includes("semantic-complete"));
    const health = run(unknownStore, ["health", "--json"]).data;
    assert.equal(health.partial_ranges, false);
    assert.ok(Object.values(health.counts_by_confidence).some(count => count > 0), "unknown fixture must retain findings for review");
    assert.equal(health.counts_by_confidence.confirmed ?? 0, 0);
    const findingPage = run(unknownStore, ["health", "list", "--json"]);
    assert.equal(findingPage.complete, true);
    const findings = findingPage.items;
    assert.equal(run(unknownStore, ["health", "--json"]).data.collection_digest, health.collection_digest);
    const repeat = scan(unknownStore).output;
    assert.ok(repeat.analysis.units.some(unit => unit.stage === "syntax" && unit.reused));
    assert.ok(repeat.coverage.reasons.includes("analysis-unit-unknown-dependency"));
    const repeatHealth = run(unknownStore, ["health", "--json"]).data;
    assert.deepEqual(repeatHealth.counts_by_confidence, health.counts_by_confidence);
    const repeatPage = run(unknownStore, ["health", "list", "--json"]);
    assert.equal(repeatPage.complete, true);
    assert.deepEqual(repeatPage.items, findings);
    assert.equal(run(unknownStore, ["health", "--json"]).data.collection_digest, repeatHealth.collection_digest);
  }
  const report = {
    contract_version: "depgraph-resumable-e2e-v1",
    adapters: includeWeb ? ["go", "web"] : ["go"],
    baseline: { duration_ms: baseline.duration_ms, units: baseline.output.analysis.units.length },
    split: { duration_ms: split.duration_ms, units: split.output.analysis.units.length },
    resumed: { duration_ms: resumed.duration_ms, reused: resumed.output.analysis.units.filter((unit) => unit.reused).length },
    stages: { baseline: stageSummary(baseline.output), split: stageSummary(split.output), resumed: stageSummary(resumed.output) },
    interrupted, web_interruption, web_reexecution, invalidation,
    profiles: expected.profiles.length, nodes: expected.nodes.length, edges: expected.edges.length,
    evidence: expected.evidence.length,
  };
  if (process.env.DEPGRAPH_RESUMABLE_REPORT) {
    writeFileSync(process.env.DEPGRAPH_RESUMABLE_REPORT, `${JSON.stringify(report, null, 2)}\n`);
  }
  console.log(JSON.stringify(report));
} finally {
  if (process.env.DEPGRAPH_RESUMABLE_KEEP_FIXTURE) {
    console.error(`resumable fixture retained at ${parent}`);
  } else {
    rmSync(parent, { recursive: true, force: true });
  }
}
