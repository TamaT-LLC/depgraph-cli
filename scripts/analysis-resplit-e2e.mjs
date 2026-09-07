// Real Go worker regression for repeated memory-limit refinement and restart.
// Only the public fixture's wrapper allocates excess memory; project code is never run.
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { setTimeout as delay } from "node:timers/promises";

const workspace = path.resolve(import.meta.dirname, "..");
const cli = process.env.DEPGRAPH_BIN ?? path.join(workspace, "target/debug/depgraph");
const worker = process.env.DEPGRAPH_GO_WORKER ?? path.join(workspace, "workers/go/bin/depgraph-go-worker");
const parent = mkdtempSync(path.join(tmpdir(), "depgraph-resplit-e2e-"));
const root = path.join(parent, "repository");
mkdirSync(root);
const marker = path.join(parent, "paused");
const pause = path.join(parent, "pause-enabled");
const inject = path.join(parent, "inject-enabled");
const wrapper = path.join(parent, "worker.mjs");
const limit = 192 * 1024 * 1024;
const env = {
  ...process.env, DEPGRAPH_GO_WORKER: wrapper,
  GOTOOLCHAIN: "local", GOPROXY: "off", GOSUMDB: "off", GOWORK: "off",
  GOMODCACHE: path.join(parent, "module-cache"), GOPATH: path.join(parent, "gopath"),
};
writeFileSync(path.join(root, "go.mod"), "module example.test/refinement\n\ngo 1.26.1\n");
for (let i = 0; i < 5; i++) {
  writeFileSync(path.join(root, `f${i}.go`), `package refinement\nfunc F${i}(x int) int { return x + ${i}; }\n`);
}
writeFileSync(path.join(root, ".depgraph.toml"), `schema_version = 1
[scan]
max_concurrent_units = 1
max_worker_memory_bytes = ${limit}
max_protocol_bytes = 2097152
max_unit_source_files = 4
max_unit_source_bytes = 1000
`);
// Keep the wrapper bytes unchanged for the control, interruption and restart:
// the worker artifact digest must not invalidate the checkpoints being tested.
writeFileSync(wrapper, `#!/usr/bin/env node
import { existsSync, readFileSync, writeFileSync, writeSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
const args = process.argv.slice(2);
const at = args.indexOf('--analysis-unit');
if (at >= 0) {
  const request = JSON.parse(readFileSync(args[at + 1], 'utf8'));
  if (existsSync(${JSON.stringify(inject)}) && request.stage !== 'syntax' && (request.source_paths.length > 1 || readFileSync(${JSON.stringify(inject)}, 'utf8') === 'unsplittable')) {
    if (['output', 'unsplittable'].includes(readFileSync(${JSON.stringify(inject)}, 'utf8'))) {
      // Keep a real, valid prefix: recovery must not double-count graph or
      // file coverage already ingested before the output limit was reached.
      const result = spawnSync(${JSON.stringify(worker)}, args, { encoding: 'utf8', maxBuffer: 16 * 1024 * 1024, env: process.env });
      if (result.status !== 0) process.exit(result.status ?? 1);
      const lines = result.stdout.trimEnd().split('\\n');
      const end = lines.findIndex(line => JSON.parse(line).event === 'profile_completed');
      writeSync(1, lines.slice(0, end).join('\\n') + '\\n');
      writeSync(1, Buffer.alloc(3 * 1024 * 1024, 32));
      process.exit(0);
    }
    globalThis.excess = Buffer.alloc(384 * 1024 * 1024, 1);
    setInterval(() => { globalThis.excess[0] ^= 1; }, 100);
    await new Promise(() => {});
  }
  if (existsSync(${JSON.stringify(pause)}) && request.stage === 'typed' && request.source_paths.length === 1 && request.source_paths[0] === 'f0.go') {
    writeFileSync(${JSON.stringify(marker)}, JSON.stringify(request));
    setInterval(() => {}, 100);
    await new Promise(() => {});
  }
}
const result = spawnSync(${JSON.stringify(worker)}, args, { stdio: 'inherit', env: process.env });
process.exit(result.status ?? 1);
`);
chmodSync(wrapper, 0o700);
function scan(store, target = root) {
  const result = spawnSync(cli, ["--store", store, "scan", target, "--json"], { env, encoding: "utf8", maxBuffer: 16 * 1024 * 1024 });
  assert.equal(result.status, 0, `${result.stderr}\n${result.stdout}`);
  const output = JSON.parse(result.stdout);
  assert.equal(output.status, "completed");
  assert.equal(output.coverage.project_code_executed, false);
  return output;
}
function graph(store, scanId) {
  const db = new DatabaseSync(store, { readOnly: true });
  try {
    const result = {};
    for (const table of ["nodes", "edges", "sites"]) {
      result[table] = db.prepare(`SELECT raw_json FROM ${table} WHERE scan_id = ? ORDER BY id`).all(scanId).map(row => JSON.parse(row.raw_json));
    }
    result.evidence = db.prepare("SELECT owner_type, owner_id, ordinal, raw_json FROM evidence WHERE scan_id = ? ORDER BY owner_type, owner_id, ordinal").all(scanId);
    result.coverage = JSON.parse(db.prepare("SELECT json FROM coverage WHERE scan_id = ?").get(scanId).json);
    return result;
  } finally { db.close(); }
}
try {
  const controlStore = path.join(parent, "control.sqlite");
  const control = scan(controlStore);
  const expected = graph(controlStore, control.scan_id);
  assert.ok(expected.nodes.length && expected.edges.length && expected.sites.length);
  writeFileSync(inject, "enabled");
  writeFileSync(pause, "enabled");
  const store = path.join(parent, "restart.sqlite");
  const child = spawn(cli, ["--store", store, "scan", root, "--json"], { env, stdio: ["ignore", "pipe", "pipe"] });
  let stdout = "", stderr = "";
  child.stdout.on("data", data => { stdout += data; });
  child.stderr.on("data", data => { stderr += data; });
  const stopped = new Promise((resolve, reject) => { child.once("error", reject); child.once("close", code => resolve(code)); });
  try {
    const deadline = Date.now() + 120_000;
    while (!existsSync(marker) && child.exitCode === null && Date.now() < deadline) await delay(100);
    assert.ok(existsSync(marker), `replacement did not reach interruption point: ${stderr}\n${stdout}`);
  } finally {
    child.kill("SIGINT");
    await stopped;
  }
  const interrupted = JSON.parse(stdout);
  assert.equal(interrupted.status, "cancelled");
  assert.equal(interrupted.completed_snapshot_id ?? null, null);
  const kept = interrupted.analysis.units.filter(unit => unit.status === "completed");
  assert.ok(kept.some(unit => unit.stage === "typed"), "successful sibling was not persisted");
  assert.ok(interrupted.diagnostics.filter(d => d.code === "analysis-resplit" && d.message.includes("applied")).length >= 2);
  rmSync(pause);
  const resumed = scan(store);
  const active = resumed.analysis.units.filter(unit => unit.loader?.analysis_resplit !== "superseded");
  assert.ok(active.every(unit => unit.status === "completed"), "unexecuted replacements counted as complete");
  // Syntax and typed results are checkpointable immediately. A semantic
  // sibling that ran while typed units were failing has no complete typed
  // reference binding and must be replayed conservatively on restart.
  for (const sibling of kept.filter(unit => unit.stage !== "semantic")) {
    assert.ok(active.some(unit => unit.unit_id === sibling.unit_id && unit.reused), `sibling ${sibling.unit_id} was not reused`);
  }
  assert.ok(resumed.diagnostics.filter(d => d.code === "analysis-resplit" && d.message.includes("applied")).length >= 2);
  assert.ok(!resumed.diagnostics.some(d => d.code === "analysis-resplit" && d.message.includes("deferred")));
  assert.deepEqual(graph(store, resumed.scan_id), expected, "refinement/restart changed graph, evidence or coverage");
  const repeated = scan(store);
  assert.deepEqual(graph(store, repeated.scan_id), expected);
  const repeatedActive = repeated.analysis.units.filter(unit => unit.loader?.analysis_resplit !== "superseded");
  assert.ok(repeatedActive.filter(unit => unit.stage !== "semantic").every(unit => unit.reused));
  assert.ok(repeatedActive.some(unit => unit.stage === "semantic" && unit.reused));
  writeFileSync(inject, "output");
  const outputStore = path.join(parent, "output-limit.sqlite");
  const outputLimited = scan(outputStore);
  assert.ok(outputLimited.diagnostics.some(d => d.code === "analysis-resplit" && d.message.includes("output_limit") && d.message.includes("applied")));
  assert.deepEqual(graph(outputStore, outputLimited.scan_id), expected, "output-limit refinement changed graph, evidence or coverage");
  // If no finer batch is possible, retain the failed leaf's valid prefix as
  // partial evidence, without publishing a completed snapshot or confirmed unused findings.
  writeFileSync(inject, "unsplittable");
  const partialStore = path.join(parent, "unsplittable.sqlite");
  const partialRun = spawnSync(cli, ["--store", partialStore, "scan", root, "--json"], { env, encoding: "utf8", maxBuffer: 16 * 1024 * 1024 });
  assert.equal(partialRun.status, 3, partialRun.stderr);
  const partial = JSON.parse(partialRun.stdout);
  assert.equal(partial.status, "partial");
  assert.equal(partial.completed_snapshot_id ?? null, null);
  assert.ok(partial.diagnostics.some(d => d.code === "analysis-resplit" && d.message.includes("unsplittable")));
  const partialDb = new DatabaseSync(partialStore, { readOnly: true });
  try {
    const typedProfiles = partialDb.prepare("SELECT count(*) AS count FROM profiles WHERE scan_id = ? AND json_extract(json, '$.properties.analysis_stage') = 'typed'").get(partial.scan_id);
    assert.ok(typedProfiles.count > 0, "unsplittable typed prefix was discarded");
  } finally { partialDb.close(); }
  const partialHealth = spawnSync(cli, ["--store", partialStore, "health", "list", "--scan-id", `attempt:${partial.scan_id}`, "--kind", "unused-file", "--all", "--json"], { env, encoding: "utf8", maxBuffer: 16 * 1024 * 1024 });
  assert.equal(partialHealth.status, 0, partialHealth.stderr);
  assert.ok(JSON.parse(partialHealth.stdout).data.findings.every(finding => finding.confidence !== "confirmed"));
  rmSync(inject);
  // In-repository references must bind package semantic checkpoints on macOS
  // as well as Linux. A source edit must invalidate the dependent result.
  const references = path.join(parent, "references");
  for (const name of ["app", "lib"]) mkdirSync(path.join(references, name), { recursive: true });
  writeFileSync(path.join(references, "go.mod"), "module example.test/references\n\ngo 1.26.1\n");
  writeFileSync(path.join(references, "app", "app.go"), 'package app\nimport "example.test/references/lib"\nfunc Run() int { return lib.Value() }\n');
  const dependency = path.join(references, "lib", "lib.go");
  writeFileSync(dependency, "package lib\nfunc Value() int { return 1 }\n");
  writeFileSync(path.join(references, ".depgraph.toml"), "schema_version = 1\n[scan]\nmax_unit_source_files = 1\nmax_unit_source_bytes = 100\nmax_context_source_bytes = 1000\n");
  const referenceStore = path.join(parent, "references.sqlite");
  scan(referenceStore, references);
  const reused = scan(referenceStore, references);
  assert.equal(reused.analysis.units.filter(unit => unit.stage === "semantic").length, 2);
  assert.ok(reused.analysis.units.every(unit => unit.reused), "package semantic checkpoint was not reused");
  writeFileSync(dependency, "package lib\nfunc Value() int { return 2 }\n");
  const changed = scan(referenceStore, references);
  assert.ok(changed.analysis.units.filter(unit => unit.stage === "semantic").every(unit => !unit.reused), "dependency edit reused stale semantic results");
  const changedControl = path.join(parent, "references-control.sqlite");
  const fresh = scan(changedControl, references);
  assert.deepEqual(graph(referenceStore, changed.scan_id), graph(changedControl, fresh.scan_id));
  console.log(JSON.stringify({ passed: true, memory_limit: limit, retained_siblings: kept.length, active_units: active.length }));
} finally {
  if (process.env.DEPGRAPH_RESPLIT_KEEP_FIXTURE) console.error(`fixture: ${parent}`);
  else rmSync(parent, { recursive: true, force: true });
}
