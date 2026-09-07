// Public synthetic Go fixtures for the pre-split loader scope (#463).
//
// Two generated repositories drive the real Go worker through the shipped
// core at one reduced per-unit memory limit that is never raised:
//
//   * `fanout`: one module with 64 packages × 8 files, tests, and a main
//     package. The planner batches packages topologically; the worker loads
//     targets from source and references from export data.
//   * `bigpkg`: one module with a single 1,024-file package whose whole-module
//     typed and semantic units exceed the limit. The package path stages the
//     bodies and completes under the same limit.
//
// A control worker advertising only the module-loader capabilities plays the
// pre-#463 path: at the default memory limit it provides the canonical graph
// the package path must reproduce, at the reduced limit it fails.
//
// Run after `cargo xtask build`; no project code or package manager is run.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, closeSync, mkdirSync, mkdtempSync, openSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { performance } from "node:perf_hooks";
import { DatabaseSync } from "node:sqlite";

const workspace = path.resolve(import.meta.dirname, "..");
const executableSuffix = process.platform === "win32" ? ".exe" : "";
const cli = path.resolve(process.env.DEPGRAPH_BIN ?? path.join(workspace, `target/debug/depgraph${executableSuffix}`));
const parent = mkdtempSync(path.join(tmpdir(), "depgraph-go-loader-scope-e2e-"));
const MIB = 1024 * 1024;
// Reduced from the 2 GiB default; identical for the control and the package
// path of the same fixture. Chosen above the measured package-path peaks
// (hybrid self ~318 MiB for the 1,024-file package, batch-of-8 ~81 MiB)
// and below the measured whole-module peaks (~555 MiB / ~721 MiB). Never
// raised: the whole-module units of `bigpkg` still need several times this.
const REDUCED_WORKER_MEMORY_BYTES = 448 * MIB;
const BIG_PACKAGE_FILES = 1024;
const BIG_PACKAGE_TABLE = 512;
const FANOUT_PACKAGES = 64;
const FANOUT_FILES = 8;
const FANOUT_TABLE = 16;
// Bounds the fan-out packages into several package batches per stage. File
// count is required as well as bytes: unmeasured 0-byte granules would
// otherwise pack every package into one unit (the default 128-file budget
// exactly fit the previous 32×4 fixture and still OOM'd after a 1→2 re-split).
// The byte cap also stops the default 8 MiB budget from promoting the small
// module to one whole context.
const FANOUT_UNIT_SOURCE_BYTES = 64 * 1024;
const FANOUT_UNIT_SOURCE_FILES = 64;
const shippedWorker = process.env.DEPGRAPH_GO_WORKER
  ?? path.join(workspace, `workers/go/bin/depgraph-go-worker${executableSuffix}`);
const environment = {
  ...process.env,
  GOTOOLCHAIN: "local", GOPROXY: "off", GOSUMDB: "off", GOWORK: "off",
  GOMODCACHE: path.join(parent, "empty-module-cache"),
  GOPATH: path.join(parent, "empty-gopath"),
  DEPGRAPH_GO_WORKER: shippedWorker,
  DEPGRAPH_WEB_WORKER: process.env.DEPGRAPH_WEB_WORKER ?? path.join(workspace, "workers/web/dist/worker.mjs"),
};
// Loader policy the package path declares on its profiles; identities, graph
// payloads, evidence, and coverage must not depend on it.
const LOADER_POLICY_PROPERTIES = new Set([
  "analysis_loader_kind", "analysis_loader_mode", "analysis_scope", "go_packages_query",
  "go_call_graph_program_scope", "go_implements_scope", "go_loader_child_process_kind",
  "go_loader_child_process_target_compiled", "go_loader_dependency_snapshot_source",
  "go_loader_identity_key", "go_loader_program_scope", "go_loader_reference_fingerprint_definition",
  "go_loader_reference_source_policy", "go_reference_fingerprint_schema",
]);

const pad = (n) => String(n).padStart(4, "0");
// A literal table gives the type checker one expression and one constant per
// element while the graph sees only the declaration and its type use, so the
// fixture stresses typed memory without inflating the protocol stream.
function table(seed, size) {
  const rows = [];
  for (let i = 0; i < size; i += 16) {
    const row = [];
    for (let j = i; j < Math.min(i + 16, size); j++) row.push(String((seed * 7919 + j * 104729) % 1000003));
    rows.push(`\t\t${row.join(", ")},`);
  }
  return rows.join("\n");
}
function writer(root) {
  return (relative, value) => {
    const file = path.join(root, relative);
    mkdirSync(path.dirname(file), { recursive: true });
    writeFileSync(file, value);
  };
}
function writeBigPackageFixture(root) {
  const write = writer(root);
  write("go.mod", "module example.test/bigpkg\n\ngo 1.26.1\n");
  for (let i = 0; i < BIG_PACKAGE_FILES; i++) {
    const next = (i + 1) % BIG_PACKAGE_FILES;
    write(`big/file_${pad(i)}.go`, `package big

// Record${pad(i)} is a generated record.
type Record${pad(i)} struct {
	Key   string
	Value int
}

// Weight${pad(i)} folds the record's table.
func (r *Record${pad(i)}) Weight${pad(i)}() int {
	total := r.Value
	for _, v := range table${pad(i)}() {
		total += v
	}
	return total
}

// Step${pad(i)} chains into the next generated file.
func Step${pad(i)}(depth int) int {
	r := &Record${pad(i)}{Key: "k${pad(i)}", Value: depth}
	if depth <= 0 {
		return r.Weight${pad(i)}()
	}
	return r.Weight${pad(i)}() + Step${pad(next)}(depth-1)
}

func table${pad(i)}() []int {
	return []int{
${table(i, BIG_PACKAGE_TABLE)}
	}
}
`);
  }
}
function writeFanoutFixture(root) {
  const write = writer(root);
  write("go.mod", "module example.test/fanout\n\ngo 1.26.1\n");
  write("core/core.go", `package core

// Value is the shared record type.
type Value struct {
	N int
	S string
}

// Shape is implemented by every generated package's Unit.
type Shape interface {
	Area() int
}

// Make builds a Value.
func Make(n int) Value { return Value{N: n, S: "core"} }

// Sum adds values.
func Sum(values ...Value) int {
	total := 0
	for _, v := range values {
		total += v.N
	}
	return total
}

// Total adds the areas of shapes through the interface.
func Total(shapes ...Shape) int {
	total := 0
	for _, s := range shapes {
		total += s.Area()
	}
	return total
}
`);
  const names = [];
  for (let p = 1; p <= FANOUT_PACKAGES; p++) {
    const name = `pkg${String(p).padStart(2, "0")}`;
    names.push(name);
    // Every fourth package also imports its predecessor so the import graph
    // has depth and the batches carry prerequisite waves.
    const previous = p > 1 && p % 4 === 0 ? names[names.length - 2] : null;
    for (let f = 0; f < FANOUT_FILES; f++) {
      const importPrevious = previous && f === 0 ? `\t"example.test/fanout/${previous}"\n` : "";
      const usePrevious = previous && f === 0 ? `\ttotal += ${previous}.Run0(x)\n` : "";
      write(`${name}/f${f}.go`, `package ${name}

import (
	"example.test/fanout/core"
${importPrevious})

// Unit${f} implements core.Shape.
type Unit${f} struct{ Side int }

// Area returns the square area.
func (u Unit${f}) Area() int { return u.Side * u.Side }

// Run${f} exercises core.
func Run${f}(x int) int {
	total := 0
	for _, v := range weights${f}() {
		total += v
	}
${usePrevious}	total += core.Total(Unit${f}{Side: x})
	return core.Sum(core.Make(total), core.Make(x))
}

func weights${f}() []int {
	return []int{
${table(p * 100 + f, FANOUT_TABLE)}
	}
}
`);
    }
  }
  // Test variants: an in-package test and an external test package. Neither
  // imports the standard library: the module loader type-checks the `testing`
  // closure of the generated test mains from source either way, while the
  // package loader would compile that closure into the cold scan cache with a
  // toolchain child alone peaking near 290 MiB, above the reduced limit. The
  // standard-library export path is covered by the worker's loader tests.
  write("pkg01/f0_test.go", `package pkg01

// The in-package test variant reaches an unexported declaration.
func helper0() int { return len(weights0()) + Run0(1) }
`);
  write("pkg02/f0_test.go", `package pkg02_test

import (
	"example.test/fanout/core"
	"example.test/fanout/pkg02"
)

// The external test variant imports the package under test.
func helper0() int { return pkg02.Run0(1) + core.Sum(core.Make(0)) }
`);
  write("cmd/app/main.go", `package main

import (
${names.map((name) => `\t"example.test/fanout/${name}"`).join("\n")}
)

func main() {
	total := 0
${names.map((name) => `\ttotal += ${name}.Run0(total)`).join("\n")}
	_ = total
}
`);
}
function configure(root, options) {
  const merged = { max_concurrent_units: 1, ...options };
  const lines = ["schema_version = 1", "[scan]"];
  for (const [key, value] of Object.entries(merged)) lines.push(`${key} = ${value}`);
  writeFileSync(path.join(root, ".depgraph.toml"), `${lines.join("\n")}\n`);
  scanMemoryLimit = merged.max_worker_memory_bytes ?? (2 * 1024 * MIB);
}
// The real Go worker advertising only the module-loader capabilities, so the
// core plans and requests exactly as it did before the package loader.
function makeControlWorker() {
  const wrapper = path.join(parent, "go-worker-module-loader-control.mjs");
  writeFileSync(wrapper, `#!/usr/bin/env node
// Control: the real Go worker without the loader-scope and package-loader capabilities.
import { spawnSync } from 'node:child_process';
const args = process.argv.slice(2);
if (args.includes('--version')) {
  const result = spawnSync(${JSON.stringify(shippedWorker)}, args, { encoding: 'utf8' });
  const version = (result.stdout ?? '').replace(/capabilities [^)]*/u, 'capabilities analysis-source-batch-v1,analysis-unit-typed-v1');
  process.stdout.write(version);
  process.exit(result.status ?? 1);
}
const result = spawnSync(${JSON.stringify(shippedWorker)}, args, { stdio: 'inherit' });
if (result.error) {
  process.stderr.write(String(result.error));
  process.exit(1);
}
process.exit(result.status ?? 1);
`);
  chmodSync(wrapper, 0o700);
  return wrapper;
}
// Every scan's Go units join the per-unit table before any assertion runs, so
// a failed run still prints the evidence it was judged on. JSON is written to
// a file rather than buffered in the node process: a 1,024-file SSA graph can
// exceed tens of megabytes and would otherwise OOM the runner.
let scanMemoryLimit = 2 * 1024 * MIB;
function scan(name, root, store, worker) {
  console.error(`go-loader-scope-e2e: start ${name}`);
  const jsonPath = path.join(parent, `${name}.json`);
  const out = openSync(jsonPath, "w");
  const start = performance.now();
  const result = spawnSync(cli, ["--store", store, "scan", root, "--json"], {
    cwd: root,
    env: {
      ...environment,
      DEPGRAPH_GO_WORKER: worker,
      GOMEMLIMIT: String(scanMemoryLimit),
    },
    stdio: ["ignore", out, "inherit"],
  });
  closeSync(out);
  const stdout = readFileSync(jsonPath, "utf8");
  assert.ok(stdout, `${name}: scan produced no JSON: ${result.error ?? result.status}`);
  const output = JSON.parse(stdout);
  assert.equal(output.coverage.project_code_executed, false);
  const outcome = { name, output, exit_code: result.status, duration_ms: Math.round(performance.now() - start) };
  for (const unit of goUnits(outcome)) rows.push(unitRow(name, unit));
  console.error(`go-loader-scope-e2e: end ${name} status=${output.status} exit=${result.status} ms=${outcome.duration_ms} units=${goUnits(outcome).length}`);
  return outcome;
}
const number = (unit, key) => (unit.loader?.[key] === undefined ? null : Number(unit.loader[key]));
const mib = (bytes) => (bytes === null || bytes === undefined ? null : Math.round((bytes / MIB) * 10) / 10);
function unitRow(scenario, unit) {
  const loader = unit.loader ?? {};
  return {
    scenario,
    stage: unit.stage,
    status: unit.status,
    reused: unit.reused,
    duration_ms: unit.duration_ms,
    failure_reason: unit.failure_reason ?? null,
    resplit: loader.analysis_resplit ?? null,
    split_kind: loader.analysis_split_kind ?? null,
    loader_kind: loader.analysis_loader_kind ?? null,
    loader_scope: loader.analysis_loader_scope ?? null,
    target_packages: number(unit, "go_loader_target_packages"),
    syntax_packages: number(unit, "go_loader_syntax_packages"),
    loaded_packages: number(unit, "go_loader_loaded_packages"),
    target_files: number(unit, "go_loader_target_files"),
    body_files: number(unit, "go_loader_body_files"),
    declaration_only_files: number(unit, "go_loader_declaration_only_files"),
    reference_packages_export: number(unit, "go_loader_reference_packages_export"),
    reference_packages_source: number(unit, "go_loader_reference_packages_source"),
    core_peak_mib: mib(number(unit, "analysis_worker_peak_memory_bytes")),
    worker_peak_rss_mib: mib(number(unit, "go_loader_peak_rss_bytes")),
    child_max_rss_mib: mib(number(unit, "go_loader_child_max_rss_bytes")),
    build_cache_reused: loader.go_loader_build_cache_reused ?? null,
    reference_fingerprint: loader.go_reference_fingerprint ?? null,
  };
}
const TABLE_COLUMNS = [
  ["scenario", 24], ["stage", 8], ["status", 9], ["reused", 6], ["duration_ms", 8], ["failure_reason", 12],
  ["resplit", 11], ["split_kind", 13], ["loader_kind", 7], ["loader_scope", 7], ["target_packages", 3],
  ["syntax_packages", 3], ["loaded_packages", 6], ["target_files", 5], ["body_files", 4],
  ["declaration_only_files", 4], ["core_peak_mib", 9], ["worker_peak_rss_mib", 8], ["child_max_rss_mib", 8],
  ["build_cache_reused", 5],
];
const TABLE_HEADERS = {
  scenario: "scenario", stage: "stage", status: "status", reused: "reused", duration_ms: "ms", failure_reason: "failure",
  resplit: "resplit", split_kind: "split", loader_kind: "loader", loader_scope: "scope", target_packages: "tgt",
  syntax_packages: "syn", loaded_packages: "loaded", target_files: "files", body_files: "body",
  declaration_only_files: "decl", core_peak_mib: "peak MiB", worker_peak_rss_mib: "rss MiB", child_max_rss_mib: "child MiB",
  build_cache_reused: "cache",
};
function printUnitTable(rows) {
  const cell = (value, width) => String(value ?? "").slice(0, width).padEnd(width);
  const lines = [TABLE_COLUMNS.map(([key, width]) => cell(TABLE_HEADERS[key], width)).join(" ")];
  lines.push(TABLE_COLUMNS.map(([, width]) => "-".repeat(width)).join(" "));
  for (const row of rows) lines.push(TABLE_COLUMNS.map(([key, width]) => cell(row[key], width)).join(" "));
  console.error(lines.join("\n"));
}
// Every persisted graph payload of the current completed snapshot. Profiles
// are returned separately: their identities must match while the loader
// policy properties legitimately differ between the module and package paths.
function graph(store) {
  const database = new DatabaseSync(store, { readOnly: true });
  try {
    const scanId = database.prepare(`
      SELECT s.scan_id FROM completed_snapshots s
      JOIN current_completed_snapshot c ON c.snapshot_id = s.id
    `).get().scan_id;
    const payloads = (table, column) => database.prepare(
      `SELECT ${column} AS payload FROM ${table} WHERE scan_id = ? ORDER BY id`,
    ).all(scanId).map((row) => JSON.parse(row.payload));
    const profiles = payloads("profiles", "json");
    assert.ok(profiles.length > 0, "completed scan has no persisted profiles");
    return {
      profiles,
      payloads: {
        nodes: payloads("nodes", "raw_json"),
        edges: payloads("edges", "raw_json"),
        sites: payloads("sites", "raw_json"),
        // The package path records its re-split as an informational core
        // diagnostic; worker diagnostics must be identical.
        diagnostics: payloads("diagnostics", "raw_json").filter((diagnostic) => diagnostic.code !== "analysis-resplit"),
        evidence: database.prepare(`SELECT owner_type, owner_id, ordinal, raw_json
          FROM evidence WHERE scan_id = ? ORDER BY owner_type, owner_id, ordinal`)
          .all(scanId).map(({ raw_json, ...owner }) => ({ ...owner, evidence: JSON.parse(raw_json) })),
        coverage: JSON.parse(database.prepare("SELECT json FROM coverage WHERE scan_id = ?").get(scanId).json),
        profile_coverage: database.prepare("SELECT profile_id, json FROM profile_coverage WHERE scan_id = ? ORDER BY profile_id")
          .all(scanId).map((row) => ({ profile_id: row.profile_id, coverage: JSON.parse(row.json) })),
        file_coverage: database.prepare(`SELECT path, discovered_sites, emitted_sites,
          skipped_sites, skipped, reason, adapter FROM file_coverage
          WHERE scan_id = ? ORDER BY path, adapter`).all(scanId),
      },
    };
  } finally {
    database.close();
  }
}
function assertSameCanonicalGraph(actual, expected, label) {
  assert.ok(actual.payloads.nodes.length > 0 && actual.payloads.edges.length > 0 && actual.payloads.sites.length > 0, `${label}: empty graph`);
  for (const key of Object.keys(expected.payloads)) {
    assert.deepEqual(actual.payloads[key], expected.payloads[key], `${label}: ${key} differ from the module-loader control`);
  }
  const strip = (profile) => ({
    ...profile,
    properties: Object.fromEntries(Object.entries(profile.properties ?? {}).filter(([key]) => !LOADER_POLICY_PROPERTIES.has(key))),
  });
  assert.deepEqual(actual.profiles.map(strip), expected.profiles.map(strip), `${label}: profile identities or non-policy properties differ`);
  const policy = new Set();
  actual.profiles.forEach((profile, index) => {
    const control = expected.profiles[index].properties ?? {};
    for (const [key, value] of Object.entries(profile.properties ?? {})) {
      if (control[key] !== value) policy.add(key);
    }
  });
  return [...policy].sort();
}
function goUnits(outcome) {
  return outcome.output.analysis.units.filter((unit) => unit.adapter === "go");
}
// The control has no split binding, so the worker reports no loader scope
// and no loader metrics: the pre-#463 module path, byte for byte.
function assertModuleLoaderControl(outcome, label) {
  for (const unit of goUnits(outcome)) {
    const loader = unit.loader ?? {};
    assert.equal(loader.analysis_loader_scope, undefined, `${label}: control unit negotiated loader scope`);
    assert.equal(loader.analysis_split_kind, undefined, `${label}: control unit carries a split binding`);
    assert.ok(!Object.keys(loader).some((key) => key.startsWith("go_loader_")), `${label}: control unit reports loader metrics`);
    if (unit.stage !== "syntax" && unit.status === "completed") {
      assert.equal(loader.analysis_scope, "full_module", `${label}: control ${unit.stage} unit is not a full-module load`);
    }
  }
}
// Every package-bounded unit type-checks exactly its target packages from
// source, reports the memory it took, and stays under the reduced limit.
function assertPackageBoundedUnits(units, label) {
  assert.ok(units.length > 0, `${label}: no package-bounded units`);
  for (const unit of units) {
    const row = unitRow(label, unit);
    assert.equal(unit.status, "completed", `${label}: ${unit.stage} unit ${unit.failure_reason ?? unit.status}`);
    assert.equal(row.loader_kind, "package", `${label}: ${unit.stage} unit is not package-bound`);
    assert.equal(row.loader_scope, "applied", `${label}: ${unit.stage} unit widened its loader scope`);
    assert.equal(unit.loader.go_loader_syntax_equals_targets, "true", `${label}: syntax packages differ from targets`);
    assert.ok(row.target_packages > 0 && row.syntax_packages === row.target_packages, `${label}: syntax=${row.syntax_packages} targets=${row.target_packages}`);
    assert.ok(row.loaded_packages >= row.target_packages, `${label}: loaded=${row.loaded_packages} < targets`);
    assert.equal(row.reference_packages_source, 0, `${label}: a reference package fell back to source`);
    assert.equal(row.body_files + row.declaration_only_files, row.target_files, `${label}: body + declaration-only files != target files`);
    assert.ok(row.worker_peak_rss_mib > 0, `${label}: worker peak RSS missing`);
    assert.ok(row.child_max_rss_mib > 0, `${label}: child max RSS missing`);
    assert.ok(typeof unit.loader.go_reference_fingerprint === "string" && unit.loader.go_reference_fingerprint.includes("sha256:"), `${label}: reference fingerprint missing`);
    if (!unit.reused) {
      assert.ok(row.core_peak_mib > 0 && row.core_peak_mib * MIB <= REDUCED_WORKER_MEMORY_BYTES, `${label}: core-observed peak ${row.core_peak_mib} MiB is not under the limit`);
    }
  }
}
// Within one stage the bodies of the owned package files are type-checked
// exactly once across all batches.
function assertBodiesLoadedOnce(units, stage, expectedFiles, label) {
  const staged = units.filter((unit) => unit.stage === stage && unit.loader?.analysis_split_kind === "staged_bodies");
  assert.ok(staged.length > 1, `${label}: ${stage} stage was not staged into several body batches`);
  const bodies = staged.reduce((sum, unit) => sum + number(unit, "go_loader_body_files"), 0);
  assert.equal(bodies, expectedFiles, `${label}: ${stage} bodies loaded ${bodies} times for ${expectedFiles} files`);
  for (const unit of staged) {
    assert.equal(number(unit, "go_loader_target_files"), expectedFiles, `${label}: ${stage} batch does not see the whole package's declarations`);
    assert.ok(number(unit, "go_loader_body_files") < expectedFiles, `${label}: ${stage} batch loaded every body`);
  }
  return staged.length;
}
function stageSummary(outcome) {
  const stages = new Map();
  for (const unit of goUnits(outcome)) {
    const key = unit.stage;
    const stage = stages.get(key) ?? { units: 0, completed: 0, failed: 0, reused: 0, worker_duration_ms: 0, core_peak_mib_max: 0 };
    stage.units += 1;
    stage.completed += Number(unit.status === "completed");
    stage.failed += Number(unit.status === "failed");
    stage.reused += Number(unit.reused);
    stage.worker_duration_ms += unit.duration_ms;
    stage.core_peak_mib_max = Math.max(stage.core_peak_mib_max, mib(number(unit, "analysis_worker_peak_memory_bytes")) ?? 0);
    stages.set(key, stage);
  }
  return Object.fromEntries([...stages].sort(([left], [right]) => left.localeCompare(right)));
}

const rows = [];
const report = {
  contract_version: "depgraph-go-loader-scope-e2e-v1",
  reduced_worker_memory_bytes: REDUCED_WORKER_MEMORY_BYTES,
  fixtures: {
    fanout: {
      packages: FANOUT_PACKAGES, files_per_package: FANOUT_FILES,
      unit_source_bytes: FANOUT_UNIT_SOURCE_BYTES, unit_source_files: FANOUT_UNIT_SOURCE_FILES,
    },
    bigpkg: { files: BIG_PACKAGE_FILES, table: BIG_PACKAGE_TABLE },
  },
  scenarios: {},
};
function record(outcome, extra = {}) {
  const { name } = outcome;
  report.scenarios[name] = {
    status: outcome.output.status,
    exit_code: outcome.exit_code,
    duration_ms: outcome.duration_ms,
    units: goUnits(outcome).length,
    stages: stageSummary(outcome),
    ...extra,
  };
  return report.scenarios[name];
}
// The module-loader control twice: at the default memory limit it provides the
// canonical graph and the whole-module memory the package path must avoid; at
// the reduced limit it must fail its typed and semantic units and have no
// finer boundary to re-split to.
function controlScenarios(name, root, control) {
  configure(root, {});
  const baselineStore = path.join(parent, `${name}-control.sqlite`);
  const baseline = scan(`${name}-control`, root, baselineStore, control);
  assert.equal(baseline.output.status, "completed", JSON.stringify(baseline.output.diagnostics));
  assertModuleLoaderControl(baseline, `${name}-control`);
  const wholeModuleUnits = goUnits(baseline).filter((unit) => unit.stage !== "syntax");
  const wholeModulePeak = Math.max(...wholeModuleUnits.map((unit) => number(unit, "analysis_worker_peak_memory_bytes") ?? 0));
  assert.ok(wholeModulePeak > REDUCED_WORKER_MEMORY_BYTES, `${name}: whole-module ${mib(wholeModulePeak)} MiB does not exceed the reduced limit; the fixture is too small to separate the paths`);
  record(baseline, { whole_module_peak_bytes: wholeModulePeak });

  configure(root, { max_worker_memory_bytes: REDUCED_WORKER_MEMORY_BYTES });
  const limited = scan(`${name}-control-limited`, root, path.join(parent, `${name}-control-limited.sqlite`), control);
  assert.equal(limited.output.status, "partial", `${name}: module-loader control completed under the reduced limit`);
  assert.equal(limited.exit_code, 3);
  const failures = goUnits(limited).filter((unit) => unit.status === "failed");
  assert.deepEqual(failures.map((unit) => [unit.stage, unit.failure_reason]).sort(), [["semantic", "memory-limit"], ["typed", "memory-limit"]], `${name}: control did not fail its typed and semantic whole-module units at the limit`);
  assert.ok(limited.output.diagnostics.some((diagnostic) => diagnostic.code === "analysis-resplit" && diagnostic.message.includes("unsplittable")), `${name}: module-loader control re-split to a finer boundary`);
  record(limited, {
    failed_units: failures.map((unit) => ({ stage: unit.stage, failure_reason: unit.failure_reason, core_peak_bytes: number(unit, "analysis_worker_peak_memory_bytes") })),
  });
  return { expected: graph(baselineStore), wholeModulePeak };
}
let passed = false;
try {
  const control = makeControlWorker();
  const fanoutRoot = path.join(parent, "fanout");
  const bigRoot = path.join(parent, "bigpkg");
  writeFanoutFixture(fanoutRoot);
  writeBigPackageFixture(bigRoot);

  // --- fan-out: module-loader control ------------------------------------
  // Even the small module exceeds the reduced limit whole: the module loader
  // type-checks the `testing` closure of the test mains from source.
  const { expected: fanoutExpected, wholeModulePeak: fanoutWholePeak } = controlScenarios("fanout", fanoutRoot, control);

  // --- fan-out: shipped worker, packages batched under a byte budget ------
  configure(fanoutRoot, {
    max_worker_memory_bytes: REDUCED_WORKER_MEMORY_BYTES,
    max_unit_source_bytes: FANOUT_UNIT_SOURCE_BYTES,
    max_unit_source_files: FANOUT_UNIT_SOURCE_FILES,
  });
  const fanoutStore = path.join(parent, "fanout-package.sqlite");
  const fanoutPackage = scan("fanout-package", fanoutRoot, fanoutStore, shippedWorker);
  assert.equal(fanoutPackage.output.status, "completed", JSON.stringify(fanoutPackage.output.diagnostics));
  const fanoutBounded = goUnits(fanoutPackage).filter((unit) => unit.stage !== "syntax");
  assertPackageBoundedUnits(fanoutBounded, "fanout-package");
  const fanoutTypedBatches = fanoutBounded.filter((unit) => unit.stage === "typed");
  assert.ok(fanoutTypedBatches.length > 1, "fan-out typed stage was not batched by package");
  assert.ok(fanoutTypedBatches.some((unit) => number(unit, "go_loader_target_packages") > 1), "no typed batch groups several small packages");
  assert.ok(fanoutBounded.some((unit) => number(unit, "go_loader_reference_packages_export") > 0), "no package batch took a reference from export data");
  // The first batch of a scan populates the scan-scoped build cache; later
  // batches find the export data of their references already built. Up to
  // `max_concurrent_units` batches start cold together, so only the first is
  // required to be cold and only some later batch to be warm.
  assert.equal(fanoutBounded[0].loader.go_loader_build_cache_reused, "false", "the first fan-out batch found a populated scan cache");
  assert.ok(fanoutBounded.slice(1).some((unit) => unit.loader.go_loader_build_cache_reused === "true"), "no later fan-out batch reused the scan-scoped build cache");
  const fanoutPackagePeak = Math.max(...fanoutBounded.map((unit) => number(unit, "analysis_worker_peak_memory_bytes")));
  const fanoutPolicy = assertSameCanonicalGraph(graph(fanoutStore), fanoutExpected, "fanout-package");
  record(fanoutPackage, {
    canonical_graph_equal_to_control: true,
    profile_policy_properties: fanoutPolicy,
    typed_batches: fanoutTypedBatches.length,
    semantic_batches: fanoutBounded.filter((unit) => unit.stage === "semantic").length,
    package_peak_bytes: fanoutPackagePeak,
    whole_module_peak_bytes: fanoutWholePeak,
  });

  // --- fan-out: resume replays every typed and semantic batch -------------
  const fanoutResume = scan("fanout-resume", fanoutRoot, fanoutStore, shippedWorker);
  assert.equal(fanoutResume.output.status, "completed");
  for (const unit of goUnits(fanoutResume)) {
    assert.ok(unit.reused, `fanout-resume: ${unit.stage} unit ${unit.unit_id} re-ran`);
  }
  assertPackageBoundedUnits(goUnits(fanoutResume).filter((unit) => unit.stage !== "syntax"), "fanout-resume");
  assertSameCanonicalGraph(graph(fanoutStore), fanoutExpected, "fanout-resume");
  record(fanoutResume, { canonical_graph_equal_to_control: true });

  // --- big package: module-loader control ---------------------------------
  const { expected: bigExpected, wholeModulePeak } = controlScenarios("bigpkg", bigRoot, control);

  // --- big package: shipped worker completes under the same limit --------
  // The module fits the byte budget, so the planner promotes it to one whole
  // context; the memory failure re-splits it into staged package batches.
  configure(bigRoot, { max_worker_memory_bytes: REDUCED_WORKER_MEMORY_BYTES });
  const bigStore = path.join(parent, "bigpkg-package.sqlite");
  const bigPackage = scan("bigpkg-package", bigRoot, bigStore, shippedWorker);
  assert.equal(bigPackage.output.status, "completed", JSON.stringify(bigPackage.output.diagnostics));
  assert.equal(bigPackage.exit_code, 0);
  const bigUnits = goUnits(bigPackage);
  const superseded = bigUnits.filter((unit) => unit.loader?.analysis_resplit === "superseded");
  assert.deepEqual(superseded.map((unit) => [unit.stage, unit.status, unit.failure_reason]).sort(), [["semantic", "failed", "memory-limit"], ["typed", "failed", "memory-limit"]], "promoted whole-module units were not superseded by the memory re-split");
  const replacements = bigUnits.filter((unit) => unit.loader?.analysis_resplit === "replacement");
  assertPackageBoundedUnits(replacements, "bigpkg-package");
  const typedBatches = assertBodiesLoadedOnce(replacements, "typed", BIG_PACKAGE_FILES, "bigpkg-package");
  const semanticBatches = assertBodiesLoadedOnce(replacements, "semantic", BIG_PACKAGE_FILES, "bigpkg-package");
  for (const unit of replacements) {
    assert.equal(number(unit, "go_loader_target_packages"), 1);
    assert.equal(number(unit, "go_loader_loaded_packages"), 1, "the single package needs no reference package");
  }
  assert.ok(bigPackage.output.diagnostics.some((diagnostic) => diagnostic.code === "analysis-resplit" && diagnostic.message.includes("applied")), "no applied re-split diagnostic");
  const packagePeak = Math.max(...replacements.map((unit) => number(unit, "analysis_worker_peak_memory_bytes")));
  assert.ok(packagePeak < wholeModulePeak / 2, `package units peak at ${mib(packagePeak)} MiB against ${mib(wholeModulePeak)} MiB whole-module`);
  const bigPolicy = assertSameCanonicalGraph(graph(bigStore), bigExpected, "bigpkg-package");
  record(bigPackage, {
    canonical_graph_equal_to_control: true,
    profile_policy_properties: bigPolicy,
    typed_batches: typedBatches,
    semantic_batches: semanticBatches,
    package_peak_bytes: packagePeak,
    whole_module_peak_bytes: wholeModulePeak,
  });

  // --- big package: resume reuses every staged batch ----------------------
  // The static plan promotes the module again; the attempt fails at the same
  // limit and the re-split replays the checkpointed replacements.
  const bigResume = scan("bigpkg-resume", bigRoot, bigStore, shippedWorker);
  assert.equal(bigResume.output.status, "completed", JSON.stringify(bigResume.output.diagnostics));
  const resumedReplacements = goUnits(bigResume).filter((unit) => unit.loader?.analysis_resplit === "replacement");
  assert.equal(resumedReplacements.length, replacements.length);
  for (const unit of resumedReplacements) {
    assert.ok(unit.reused, `bigpkg-resume: ${unit.stage} batch re-ran`);
  }
  for (const unit of goUnits(bigResume).filter((unit) => unit.stage === "syntax")) {
    assert.ok(unit.reused, "bigpkg-resume: syntax batch re-ran");
  }
  assertPackageBoundedUnits(resumedReplacements, "bigpkg-resume");
  assertSameCanonicalGraph(graph(bigStore), bigExpected, "bigpkg-resume");
  record(bigResume, { canonical_graph_equal_to_control: true, reused_replacements: resumedReplacements.length });

  report.summary = `at ${mib(REDUCED_WORKER_MEMORY_BYTES)} MiB per unit the module-loader control fails `
    + `(${BIG_PACKAGE_FILES}-file package whole-module peak ${mib(wholeModulePeak)} MiB, fan-out ${mib(fanoutWholePeak)} MiB); `
    + `${typedBatches} typed + ${semanticBatches} semantic staged package batches peak at ${mib(packagePeak)} MiB and complete; `
    + `fan-out ${FANOUT_PACKAGES} packages in ${fanoutTypedBatches.length} typed batches peak at ${mib(fanoutPackagePeak)} MiB; `
    + "canonical graphs equal to the module-loader control";
  passed = true;
} catch (error) {
  report.failure = error instanceof Error ? error.message : String(error);
  throw error;
} finally {
  // The table and the report are written on every path so a failed CI run
  // keeps the per-unit evidence it was judged on.
  report.passed = passed;
  report.units = rows;
  printUnitTable(rows);
  if (report.summary) console.log(`go-loader-scope-e2e: ${report.summary}`);
  if (process.env.DEPGRAPH_GO_LOADER_SCOPE_REPORT) {
    writeFileSync(process.env.DEPGRAPH_GO_LOADER_SCOPE_REPORT, `${JSON.stringify(report, null, 2)}\n`);
  }
  console.log(JSON.stringify({ ...report, units: undefined }));
  if (process.env.DEPGRAPH_GO_LOADER_SCOPE_KEEP_FIXTURE) {
    console.error(`go loader scope fixture retained at ${parent}`);
  } else {
    rmSync(parent, { recursive: true, force: true });
  }
}
