import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  aggregateReport,
  ambiguousCandidateId,
  buildChangedSetImpactArgs,
  buildImpactArgs,
  changedSetFiles,
  classifyChangedSetResult,
  classifyImpactResult,
  collectReport,
  parseImpactMode,
  parseNameStatusZ,
  parseProfiles,
  supportsChangedSetImpact,
} from "../../.github/actions/pr-impact/collect.mjs";
import {
  COMMENT_MARKER,
  blobUrl,
  escapeMarkdown,
  renderComment,
} from "../../.github/actions/pr-impact/render.mjs";
import { isOwnComment, upsertComment } from "../../.github/actions/pr-impact/comment.mjs";

const HEAD_SHA = "0123456789abcdef0123456789abcdef01234567";
const REPOSITORY = "TamaT-LLC/depgraph-cli";

function node(id, kind, displayName, extra = {}) {
  return { id, kind, locator: `${kind}:${displayName}`, display_name: displayName, properties: {}, ...extra };
}

function step(kind, path, startLine, endLine = startLine) {
  return {
    edge: { id: `e-${path}-${startLine}`, source: "s", target: "t", kind },
    evidence: [
      { kind: "syntax", extractor: "test", path, start_line: startLine, start_column: 1, end_line: endLine, end_column: 2 },
    ],
  };
}

function impact(target, depth, path = [step("imports", "src/a.ts", 3)]) {
  return { node: target, depth, changed_node_id: "file-root", dependency_path: path };
}

function okResult(impacts, extra = {}) {
  return {
    status: "ok",
    data: { root: node("file-root", "file", "src/a.ts"), root_impacted: true, complete: true, impacts, diagnostics: [], ...extra },
  };
}

function reportFixture(overrides = {}) {
  return aggregateReport({
    baseSha: "b".repeat(40),
    mergeBase: "c".repeat(40),
    headSha: HEAD_SHA,
    pathPrefix: "",
    depgraphVersion: "0.6.4",
    strict: false,
    scan: { exitCode: 0 },
    files: [],
    skipped: [],
    ...overrides,
  });
}

// --- git diff -z parsing -------------------------------------------------

test("parseNameStatusZ reads modified, added, deleted, and renamed entries", () => {
  const raw = ["M", "src/a.ts", "A", "src/new file.ts", "D", "old.ts", "R087", "from.ts", "to.ts", "C100", "x.ts", "y.ts", ""].join("\0");
  assert.deepEqual(parseNameStatusZ(raw), [
    { change: "M", path: "src/a.ts" },
    { change: "A", path: "src/new file.ts" },
    { change: "D", path: "old.ts" },
    { change: "R", path: "to.ts", oldPath: "from.ts", similarity: 87 },
    { change: "C", path: "y.ts", oldPath: "x.ts", similarity: 100 },
  ]);
});

test("parseNameStatusZ keeps paths that contain newlines and tabs verbatim", () => {
  const raw = "M\0weird\nname\t.ts\0";
  assert.deepEqual(parseNameStatusZ(raw), [{ change: "M", path: "weird\nname\t.ts" }]);
});

test("parseNameStatusZ rejects a truncated rename record", () => {
  assert.throws(() => parseNameStatusZ("R100\0only-one.ts\0"), /malformed/);
});

test("parseNameStatusZ returns an empty list for an empty diff", () => {
  assert.deepEqual(parseNameStatusZ(""), []);
});

// --- argument building ---------------------------------------------------

test("buildImpactArgs keeps profiles in the attached form so values cannot become flags", () => {
  assert.deepEqual(buildImpactArgs({ store: "/s", selector: "id:file:sha256:1" }).slice(0, 4), ["--store", "/s", "impact", "id:file:sha256:1"]);
  assert.deepEqual(
    buildImpactArgs({ store: "/tmp/s", path: "src/a.ts", profiles: ["web", "--evil"], maxNodes: 10, maxEdges: 20 }),
    ["--store", "/tmp/s", "impact", "path:src/a.ts", "--json", "--profile=web", "--profile=--evil", "--max-nodes=10", "--max-edges=20"],
  );
  assert.deepEqual(buildImpactArgs({ store: "/s", path: "a.go", profiles: [] }), [
    "--store",
    "/s",
    "impact",
    "path:a.go",
    "--json",
  ]);
});

test("parseProfiles splits newline separated input and drops blanks", () => {
  assert.deepEqual(parseProfiles("web\n\n  go-default  \r\n"), ["web", "go-default"]);
  assert.deepEqual(parseProfiles(""), []);
  assert.deepEqual(parseProfiles(undefined), []);
});

// --- impact result classification ----------------------------------------

test("classifyImpactResult maps exit 0 envelopes to ok", () => {
  const envelope = { schema_version: "1.0", command: "impact", scan_id: "s1", data: { impacts: [] } };
  const result = classifyImpactResult({ exitCode: 0, stdout: JSON.stringify(envelope), stderr: "" });
  assert.equal(result.status, "ok");
  assert.deepEqual(result.data, { impacts: [] });
});

test("classifyImpactResult maps an ambiguous selector exit 2 to unmapped and counts the candidates", () => {
  const stderr =
    'error: graph query is invalid: selector "path:README.md" is ambiguous; select a candidate with id:<stable-id>. candidates: ' +
    "file://docs/README.md (file, id:file:sha256:bb), file://web/README.md (file, id:file:sha256:cc)\n";
  const result = classifyImpactResult({ exitCode: 2, stdout: "", stderr });
  assert.deepEqual(result, { status: "unmapped", exitCode: 2, message: "no graph node for this path (2 other files share its suffix)" });
});

test("classifyImpactResult maps exit 2 input errors that are not selector misses to error", () => {
  assert.deepEqual(classifyImpactResult({ exitCode: 2, stdout: "", stderr: "error: invalid service input\n" }), {
    status: "error",
    exitCode: 2,
    message: "invalid service input",
  });
  const noSnapshot = classifyImpactResult({ exitCode: 2, stdout: "", stderr: "error: no current completed snapshot\n" });
  assert.equal(noSnapshot.status, "error");
  assert.equal(noSnapshot.exitCode, 2);
  // A selector miss mentioned only below the first line must not reclassify the failure.
  const later = classifyImpactResult({ exitCode: 2, stdout: "", stderr: 'error: invalid service input\nselector "x" did not match any node\n' });
  assert.equal(later.status, "error");
});

test("collectReport marks the report incomplete when impact rejects its input with exit 2", async () => {
  const report = await collectReport({
    ...collectFixture(),
    runDepgraph: async () => ({ exitCode: 2, stdout: "", stderr: "error: invalid service input\n" }),
  });
  assert.equal(report.changed_files[0].status, "error");
  assert.equal(report.changed_files[0].exit_code, 2);
  assert.equal(report.incomplete, true);
  const body = renderComment(report, { repository: REPOSITORY });
  assert.doesNotMatch(body, /影響を受けるノードは見つかりませんでした/);
  assert.doesNotMatch(body, /影響は見つかりませんでした/);
  assert.match(body, /invalid service input/);
});

test("collectReport rejects max-nodes and max-edges above the depgraph traversal limit before running git", async () => {
  for (const [key, name] of [["maxNodes", "max-nodes"], ["maxEdges", "max-edges"]]) {
    let gitCalls = 0;
    await assert.rejects(
      collectReport({
        ...collectFixture(),
        [key]: "2000000",
        runGit: async () => {
          gitCalls += 1;
          return "";
        },
      }),
      new RegExp(`${name} must be at most 1000000`),
    );
    assert.equal(gitCalls, 0);
  }
  const report = await collectReport({ ...collectFixture(), maxNodes: "1000000", maxEdges: "1000000" });
  assert.equal(report.changed_files[0].status, "ok");
});

test("classifyImpactResult maps other failures and unparsable output to error", () => {
  assert.deepEqual(classifyImpactResult({ exitCode: 3, stdout: "", stderr: "limit exceeded" }), {
    status: "error",
    exitCode: 3,
    message: "limit exceeded",
  });
  const garbled = classifyImpactResult({ exitCode: 0, stdout: "not json", stderr: "" });
  assert.equal(garbled.status, "error");
  assert.match(garbled.message, /JSON/);
});

test("classifyImpactResult rejects a path selector that resolved to a different file", () => {
  const envelope = { data: { root: node("f", "file", "src/README.md", { locator: "file://src/README.md" }), impacts: [] } };
  const result = classifyImpactResult({ exitCode: 0, stdout: JSON.stringify(envelope), stderr: "" }, { path: "README.md" });
  assert.equal(result.status, "unmapped");
  assert.match(result.message, /src\/README\.md/);
  for (const root of [
    node("g", "file", "a/b.go", { locator: "file:a/b.go" }),
    node("w", "file", "a/b.go", { locator: "file://a/b.go" }),
  ]) {
    const ok = classifyImpactResult({ exitCode: 0, stdout: JSON.stringify({ data: { root, impacts: [] } }), stderr: "" }, { path: "a/b.go" });
    assert.equal(ok.status, "ok");
  }
});

test("classifyImpactResult shortens the no-match message", () => {
  const result = classifyImpactResult({
    exitCode: 2,
    stdout: "",
    stderr: 'error: graph query is invalid: selector "path:Cargo.toml" did not match any node\n',
  });
  assert.deepEqual(result, { status: "unmapped", exitCode: 2, message: "no graph node for this path" });
});

test("ambiguousCandidateId picks the candidate whose locator is exactly the changed path", () => {
  const stderr =
    'error: graph query is invalid: selector "path:README.md" is ambiguous; select a candidate with id:<stable-id>. candidates: ' +
    "file://workers/web/README.md (file, id:file:sha256:72), file://README.md (file, id:file:sha256:aa)";
  assert.equal(ambiguousCandidateId(stderr, "README.md"), "file:sha256:aa");
  assert.equal(ambiguousCandidateId(stderr, "docs/README.md"), undefined);
  assert.equal(ambiguousCandidateId("did not match", "README.md"), undefined);
});

test("collectReport retries an ambiguous path with the exact candidate id", async () => {
  const { runGit } = fakeGit(["M", "README.md", "M", "docs/x.md", ""].join("\0"));
  const depgraphCalls = [];
  const ambiguity = (path) =>
    `error: graph query is invalid: selector "path:${path}" is ambiguous; select a candidate with id:<stable-id>. candidates: ` +
    "file://a/README.md (file, id:file:sha256:11), file://README.md (file, id:file:sha256:22)";
  const report = await collectReport({
    baseRef: "main",
    store: "/s",
    profiles: [],
    maxFiles: 10,
    scanExitCode: 0,
    runGit,
    runDepgraph: async (args) => {
      depgraphCalls.push(args);
      const selector = args[3];
      if (selector === "id:file:sha256:22") {
        const root = node("file:sha256:22", "file", "README.md", { locator: "file://README.md" });
        return { exitCode: 0, stdout: JSON.stringify({ data: { root, complete: true, impacts: [], diagnostics: [] } }), stderr: "" };
      }
      return { exitCode: 2, stdout: "", stderr: ambiguity(selector.slice("path:".length)) };
    },
  });
  assert.deepEqual(
    depgraphCalls.map((args) => args[3]),
    ["path:README.md", "id:file:sha256:22", "path:docs/x.md"],
  );
  assert.equal(report.changed_files[0].status, "ok");
  assert.equal(report.changed_files[1].status, "unmapped");
  assert.equal(report.changed_files[1].message, "no graph node for this path (2 other files share its suffix)");
});

test("classifyImpactResult truncates long messages", () => {
  const result = classifyImpactResult({ exitCode: 3, stdout: "", stderr: "x".repeat(1000) });
  assert.ok(result.message.length <= 300);
});

// --- aggregation ---------------------------------------------------------

test("aggregateReport deduplicates nodes, keeps the minimum depth and its path, and records sources", () => {
  const route = node("route-1", "route", "/users");
  const pkg = node("pkg-1", "package_instance", "lodash@4");
  const shortPath = [step("imports", "src/b.ts", 9)];
  const longPath = [step("imports", "src/a.ts", 1), step("calls", "src/c.ts", 2), step("routes", "src/d.ts", 3)];
  const report = reportFixture({
    files: [
      { change: "M", path: "src/a.ts", result: okResult([impact(route, 3, longPath), impact(pkg, 1)]) },
      { change: "M", path: "src/b.ts", result: okResult([impact(route, 1, shortPath)]) },
    ],
  });
  assert.equal(report.impacted.length, 2);
  const routeEntry = report.impacted.find((entry) => entry.id === "route-1");
  assert.equal(routeEntry.depth, 1);
  assert.deepEqual(routeEntry.dependency_path, shortPath);
  assert.deepEqual(routeEntry.reached_from, ["src/a.ts", "src/b.ts"]);
  assert.equal(routeEntry.kind, "route");
  assert.equal(routeEntry.display_name, "/users");
  assert.equal(routeEntry.locator, "route:/users");
  assert.deepEqual(report.totals, { changed: 2, routes: 1, packages: 1, others: 0, impacted: 2 });
  assert.deepEqual(
    report.changed_files.map((file) => [file.path, file.status, file.impacted_count]),
    [
      ["src/a.ts", "ok", 2],
      ["src/b.ts", "ok", 1],
    ],
  );
});

test("aggregateReport breaks depth ties by the shorter dependency path", () => {
  const target = node("n", "symbol", "f");
  const report = reportFixture({
    files: [
      { change: "M", path: "a", result: okResult([impact(target, 2, [step("x", "a", 1), step("y", "a", 2)])]) },
      { change: "M", path: "b", result: okResult([impact(target, 2, [step("z", "b", 1)])]) },
    ],
  });
  assert.equal(report.impacted[0].dependency_path.length, 1);
});

test("aggregateReport records deleted, unmapped, error, and skipped files", () => {
  const report = reportFixture({
    files: [
      { change: "D", path: "gone.ts", result: { status: "deleted" } },
      { change: "M", path: "README.md", result: { status: "unmapped", exitCode: 2, message: "no node" } },
      { change: "M", path: "big.ts", result: { status: "error", exitCode: 3, message: "limit" } },
      { change: "R", path: "to.ts", oldPath: "from.ts", result: okResult([], { complete: false, diagnostics: [{ code: "incomplete", message: "cap" }] }) },
    ],
    skipped: ["s1.ts", "s2.ts"],
  });
  assert.deepEqual(
    report.changed_files.map((file) => [file.path, file.status]),
    [
      ["gone.ts", "deleted"],
      ["README.md", "unmapped"],
      ["big.ts", "error"],
      ["to.ts", "ok"],
    ],
  );
  assert.equal(report.changed_files[1].message, "no node");
  assert.equal(report.changed_files[2].exit_code, 3);
  assert.equal(report.changed_files[3].old_path, "from.ts");
  assert.equal(report.changed_files[3].complete, false);
  assert.deepEqual(report.diagnostics, [{ path: "to.ts", code: "incomplete", message: "cap" }]);
  assert.equal(report.incomplete, true);
  assert.deepEqual(report.skipped, { count: 2, paths: ["s1.ts", "s2.ts"] });
  assert.equal(report.totals.changed, 6);
});

test("aggregateReport orders impacted nodes by kind, depth, and display name", () => {
  const report = reportFixture({
    files: [
      {
        change: "M",
        path: "a",
        result: okResult([
          impact(node("s", "symbol", "zeta"), 1),
          impact(node("p", "package_instance", "pkg"), 1),
          impact(node("r2", "route", "/b"), 2),
          impact(node("r1", "route", "/a"), 2),
        ]),
      },
    ],
  });
  assert.deepEqual(
    report.impacted.map((entry) => entry.id),
    ["r1", "r2", "p", "s"],
  );
});

test("aggregateReport ignores depth-zero entries that only restate the changed root", () => {
  const report = reportFixture({
    files: [{ change: "M", path: "a", result: okResult([impact(node("file-root", "file", "src/a.ts"), 0)]) }],
  });
  assert.equal(report.impacted.length, 0);
});

test("aggregateReport records the scan state", () => {
  assert.equal(reportFixture({ scan: { exitCode: 0 } }).scan.status, "ok");
  assert.equal(reportFixture({ scan: { exitCode: 1 }, strict: true }).scan.status, "policy_violation");
  const failed = reportFixture({ scan: { exitCode: 3, message: "worker missing" } });
  assert.equal(failed.scan.status, "failed");
  assert.equal(failed.scan.message, "worker missing");
});

// --- collect orchestration -----------------------------------------------

function fakeGit(diff) {
  const calls = [];
  const runGit = async (args) => {
    calls.push(args);
    if (args[0] === "merge-base") return "c".repeat(40) + "\n";
    if (args[0] === "rev-parse" && args[1] === "--show-prefix") return "\n";
    if (args[0] === "rev-parse") return (args.at(-1) === "HEAD" ? HEAD_SHA : "b".repeat(40)) + "\n";
    if (args[0] === "diff") return diff;
    throw new Error(`unexpected git ${args.join(" ")}`);
  };
  return { runGit, calls };
}

function collectFixture() {
  const { runGit } = fakeGit(["M", "src/a.ts", ""].join("\0"));
  const envelope = { schema_version: "1.0", command: "impact", scan_id: "s", data: okResult([]).data };
  return {
    baseRef: "main",
    store: "/s",
    profiles: [],
    scanExitCode: 0,
    strict: false,
    depgraphVersion: "0.6.4",
    runGit,
    runDepgraph: async () => ({ exitCode: 0, stdout: JSON.stringify(envelope), stderr: "" }),
  };
}

test("collectReport impacts each surviving file, skips deletes, and caps the file count", async () => {
  const { runGit, calls: gitCalls } = fakeGit(["M", "a.ts", "D", "gone.ts", "M", "b.ts", "M", "c.ts", ""].join("\0"));
  const depgraphCalls = [];
  const runDepgraph = async (args) => {
    depgraphCalls.push(args);
    const envelope = { schema_version: "1.0", command: "impact", scan_id: "s", data: okResult([]).data };
    return { exitCode: 0, stdout: JSON.stringify(envelope), stderr: "" };
  };
  const report = await collectReport({
    baseRef: "main",
    store: "/s",
    profiles: [],
    maxFiles: 2,
    scanExitCode: 0,
    strict: false,
    depgraphVersion: "0.6.4",
    runGit,
    runDepgraph,
  });
  const diffCall = gitCalls.find((args) => args[0] === "diff");
  assert.ok(diffCall.includes("-z"));
  assert.ok(diffCall.includes("--find-renames"));
  assert.ok(diffCall.includes("c".repeat(40)));
  assert.deepEqual(
    depgraphCalls.map((args) => args[3]),
    ["path:a.ts", "path:b.ts"],
  );
  assert.deepEqual(report.skipped, { count: 1, paths: ["c.ts"] });
  assert.equal(report.changed_files.find((file) => file.path === "gone.ts").status, "deleted");
  assert.equal(report.merge_base, "c".repeat(40));
  assert.equal(report.head_sha, HEAD_SHA);
});

test("collectReport does not query impact when the scan failed", async () => {
  const { runGit } = fakeGit(["M", "a.ts", ""].join("\0"));
  let called = false;
  const report = await collectReport({
    baseRef: "main",
    store: "/s",
    profiles: [],
    maxFiles: 10,
    scanExitCode: 3,
    scanMessage: "worker failed",
    strict: false,
    depgraphVersion: "0.6.4",
    runGit,
    runDepgraph: async () => {
      called = true;
      return { exitCode: 0, stdout: "{}", stderr: "" };
    },
  });
  assert.equal(called, false);
  assert.equal(report.scan.status, "failed");
  assert.equal(report.changed_files[0].status, "not_analyzed");
});

test("collectReport inspects a partial scan attempt and marks the report incomplete", async () => {
  const { runGit } = fakeGit(["M", "a.ts", ""].join("\0"));
  const depgraphCalls = [];
  const report = await collectReport({
    baseRef: "main",
    store: "/s",
    profiles: [],
    maxFiles: 10,
    scanExitCode: 3,
    scanOutput: { scan_id: "4aea1ad6-316f-4863-94f5-14ee01e3763a", status: "partial", error: "rust worker exceeded its memory budget" },
    strict: false,
    depgraphVersion: "0.6.4",
    runGit,
    runDepgraph: async (args) => {
      depgraphCalls.push(args);
      const data = { ...okResult([]).data, root: node("file-root", "file", "a.ts") };
      const envelope = { schema_version: "1.0", command: "impact", scan_id: "s", partial: {}, data };
      return { exitCode: 0, stdout: JSON.stringify(envelope), stderr: "" };
    },
  });
  assert.deepEqual(depgraphCalls[0].slice(0, 4), [
    "--store",
    "/s",
    "--scan-id=attempt:4aea1ad6-316f-4863-94f5-14ee01e3763a",
    "impact",
  ]);
  assert.equal(report.scan.status, "partial");
  assert.match(report.scan.message, /memory budget/);
  assert.equal(report.incomplete, true);
  assert.equal(report.changed_files[0].status, "ok");
});

test("collectReport reads a strict policy_failed attempt because it is never stored as completed", async () => {
  const { runGit } = fakeGit(["M", "a.ts", ""].join("\0"));
  const depgraphCalls = [];
  const report = await collectReport({
    baseRef: "main",
    store: "/s",
    profiles: [],
    maxFiles: 10,
    scanExitCode: 1,
    scanOutput: { scan_id: "04f90e9e-be7f-47d7", status: "policy_failed", error: "strict policy failed: unresolved=1 (max 0)" },
    strict: true,
    runGit,
    runDepgraph: async (args) => {
      depgraphCalls.push(args);
      return { exitCode: 0, stdout: JSON.stringify({ data: okResult([]).data }), stderr: "" };
    },
  });
  assert.equal(depgraphCalls[0][2], "--scan-id=attempt:04f90e9e-be7f-47d7");
  assert.equal(report.scan.status, "policy_violation");
  assert.match(report.scan.message, /unresolved=1/);
  assert.equal(report.incomplete, false);
});

test("collectReport does not query a strict violation whose attempt id is missing", async () => {
  const { runGit } = fakeGit(["M", "a.ts", "D", "gone.ts", ""].join("\0"));
  let called = false;
  const report = await collectReport({
    baseRef: "main",
    store: "/s",
    profiles: [],
    maxFiles: 10,
    scanExitCode: 1,
    scanOutput: { status: "policy_failed", error: "strict policy failed: unresolved=1 (max 0)" },
    strict: true,
    runGit,
    runDepgraph: async () => {
      called = true;
      return { exitCode: 0, stdout: JSON.stringify({ data: okResult([]).data }), stderr: "" };
    },
  });
  assert.equal(called, false);
  assert.equal(report.scan.status, "policy_violation");
  assert.equal(report.changed_files.find((file) => file.path === "a.ts").status, "not_analyzed");
  assert.equal(report.changed_files.find((file) => file.path === "gone.ts").status, "deleted");
  assert.equal(report.incomplete, true);

  const body = renderComment(report, { repository: REPOSITORY });
  assert.match(body, /ポリシー違反/);
  assert.doesNotMatch(body, /影響を受けるノードは見つかりませんでした/);
  assert.match(body, /影響範囲は計算していません/);
  assert.match(body, /a\.ts — scan 結果を照会できないため未解析/);
});

test("collectReport shortens runner-absolute paths in the scan error", async () => {
  const { runGit } = fakeGit("");
  const report = await collectReport({
    baseRef: "main",
    store: "/s",
    profiles: [],
    maxFiles: 10,
    scanExitCode: 4,
    scanOutput: { status: "failed", error: "rust: /home/runner/work/_temp/depgraph-install.Ab/extract/libexec/depgraph-rust-worker exceeded its budget" },
    runGit,
    runDepgraph: async () => ({}),
  });
  assert.equal(report.scan.message, "rust: …/depgraph-rust-worker exceeded its budget");
});

test("collectReport ignores a partial scan whose attempt id is not a plain identifier", async () => {
  const { runGit } = fakeGit(["M", "a.ts", ""].join("\0"));
  let called = false;
  const report = await collectReport({
    baseRef: "main",
    store: "/s",
    profiles: [],
    maxFiles: 10,
    scanExitCode: 3,
    scanOutput: { scan_id: "--evil", status: "partial" },
    runGit,
    runDepgraph: async () => {
      called = true;
      return {};
    },
  });
  assert.equal(called, false);
  assert.equal(report.scan.status, "failed");
});

test("collectReport rejects option-like or malformed base refs before running git", async () => {
  const { runGit, calls } = fakeGit("");
  for (const baseRef of ["--output=/tmp/x", "", "main;rm", "a b"]) {
    await assert.rejects(
      collectReport({ baseRef, store: "/s", profiles: [], maxFiles: 1, scanExitCode: 0, runGit, runDepgraph: async () => ({}) }),
      /base ref/,
    );
  }
  assert.equal(calls.length, 0);
});

function failingGit(failOn, { exitCode = 1, stderr = "" } = {}) {
  const { runGit: base } = fakeGit("");
  return async (args) => {
    if (failOn(args)) {
      const error = new Error(`git ${args[0]} failed: ${stderr}`);
      error.exitCode = exitCode;
      error.stderr = stderr;
      throw error;
    }
    return base(args);
  };
}

const collectWith = (runGit) =>
  collectReport({ baseRef: "origin/main", store: "/s", profiles: [], maxFiles: 1, scanExitCode: 0, runGit, runDepgraph: async () => ({}) });

test("collectReport explains an unresolvable base ref and keeps the git error details", async () => {
  const runGit = failingGit((args) => args[0] === "rev-parse" && args.at(-1) === "origin/main^{commit}", { exitCode: 1 });
  await assert.rejects(collectWith(runGit), (error) => {
    assert.match(error.message, /base ref origin\/main/);
    assert.match(error.message, /fetch-depth: 0/);
    assert.match(error.message, /exit code 1/);
    assert.equal(error.cause.exitCode, 1);
    return true;
  });
});

test("collectReport explains a missing merge-base and keeps the git stderr", async () => {
  const runGit = failingGit((args) => args[0] === "merge-base", { exitCode: 128, stderr: "fatal: bad object" });
  await assert.rejects(collectWith(runGit), (error) => {
    assert.match(error.message, /merge-base/);
    assert.match(error.message, /fetch-depth: 0/);
    assert.match(error.message, /fatal: bad object/);
    assert.match(error.message, /exit code 128/);
    assert.equal(error.cause.stderr, "fatal: bad object");
    return true;
  });
});


// --- changed-set impact mode -----------------------------------------------

const MERGE_BASE = "c".repeat(40);
const NEW_HELP = "Show reverse dependency impact\n\nUsage: depgraph impact [OPTIONS] [SELECTOR]\n\nArguments:\n  [SELECTOR]  Graph node\n";
const OLD_HELP = "Show reverse dependency impact\n\nUsage: depgraph impact [OPTIONS] <SELECTOR>\n\nArguments:\n  <SELECTOR>  \n";
const OLD_SELECTOR_ERROR =
  "error: the following required arguments were not provided:\n  <SELECTOR>\n\nUsage: depgraph impact --changed <GIT_REF> <SELECTOR>\n";

function mapping(path, nodeIds, extra = {}) {
  return { change: { status: "modified", new_path: path, sources: ["committed"], ...extra }, old_node_ids: [], new_node_ids: nodeIds, correlated_node_ids: nodeIds };
}

function changedImpact(target, depth, changedPaths, path = [step("imports", "src/a.ts", 3)]) {
  return { node: target, depth, changed_node_id: "file-a", changed_paths: changedPaths, dependency_path: path };
}

function changedSetData(overrides = {}) {
  return {
    mode: "changed_set",
    complete: true,
    filters: {},
    changed_set: { requested_ref: MERGE_BASE, merge_base: MERGE_BASE, head: HEAD_SHA, repository_prefix: "", changes: [] },
    mappings: [],
    changed_nodes: [],
    unmapped: [],
    impacts: [],
    diagnostics: [],
    ...overrides,
  };
}

function changedSetEnvelope(data) {
  return { exitCode: 0, stdout: JSON.stringify({ schema_version: "1.0", command: "impact", scan_id: "s", data }), stderr: "" };
}

// The graph a.ts <- b.ts <- route, with c.ts unmapped and gone.ts deleted,
// answered both ways so the two modes can be compared.
const SCENARIO_DIFF = ["M", "src/a.ts", "M", "src/b.ts", "M", "docs/c.md", "D", "src/gone.ts", ""].join("\0");
const SCENARIO_ROUTE = node("route-orders", "route", "GET /orders");
const SCENARIO_PACKAGE = node("pkg-web", "package_instance", "apps/web");
const ROUTE_FROM_B = [step("routes", "src/route.ts", 2), step("imports", "src/b.ts", 1)];

function scenarioPerFile(args) {
  const selector = args[3];
  const root = (path) => node(`file-${path}`, "file", path);
  if (selector === "path:src/a.ts") {
    const data = {
      root: root("src/a.ts"),
      complete: true,
      diagnostics: [],
      impacts: [
        impact(root("src/a.ts"), 0, []),
        impact(node("file-src/b.ts", "file", "src/b.ts"), 1),
        impact(SCENARIO_ROUTE, 2, [...ROUTE_FROM_B, step("imports", "src/a.ts", 3)]),
        impact(SCENARIO_PACKAGE, 1, [step("contains", "apps/web/package.json", 1)]),
      ],
    };
    return { exitCode: 0, stdout: JSON.stringify({ data }), stderr: "" };
  }
  if (selector === "path:src/b.ts") {
    const data = { root: root("src/b.ts"), complete: true, diagnostics: [], impacts: [impact(root("src/b.ts"), 0, []), impact(SCENARIO_ROUTE, 1, ROUTE_FROM_B)] };
    return { exitCode: 0, stdout: JSON.stringify({ data }), stderr: "" };
  }
  return { exitCode: 2, stdout: "", stderr: `error: selector "${selector}" did not match any node\n` };
}

function scenarioChangedSet() {
  return changedSetData({
    mappings: [mapping("src/a.ts", ["file-src/a.ts"]), mapping("src/b.ts", ["file-src/b.ts"]), mapping("docs/c.md", []), mapping("src/gone.ts", [], { status: "deleted", new_path: undefined, old_path: "src/gone.ts" })],
    unmapped: [
      { status: "modified", new_path: "docs/c.md", reason: "not_in_snapshot" },
      { status: "deleted", old_path: "src/gone.ts", reason: "deleted" },
    ],
    impacts: [
      changedImpact(node("file-src/a.ts", "file", "src/a.ts"), 0, ["src/a.ts"], []),
      changedImpact(node("file-src/b.ts", "file", "src/b.ts"), 0, ["src/a.ts", "src/b.ts"], []),
      changedImpact(SCENARIO_ROUTE, 1, ["src/a.ts", "src/b.ts"], ROUTE_FROM_B),
      changedImpact(SCENARIO_PACKAGE, 1, ["src/a.ts"], [step("contains", "apps/web/package.json", 1)]),
    ],
    diagnostics: [
      { code: "changed_path_unmapped", message: "changed path docs/c.md was not present in the selected snapshot" },
      { code: "profile_skipped", message: "profile web was skipped" },
    ],
  });
}

function changedSetDepgraph({ help = NEW_HELP, answer } = {}) {
  const calls = [];
  const runDepgraph = async (args) => {
    calls.push(args);
    if (args[0] === "impact" && args[1] === "--help") return { exitCode: 0, stdout: help, stderr: "" };
    if (args.some((arg) => arg.startsWith("--changed="))) return answer ? answer(args) : changedSetEnvelope(scenarioChangedSet());
    return scenarioPerFile(args);
  };
  return { runDepgraph, calls };
}

function scenarioCollect(overrides = {}) {
  const { runGit } = fakeGit(SCENARIO_DIFF);
  return { baseRef: "main", store: "/s", profiles: [], scanExitCode: 0, strict: false, depgraphVersion: "0.7.0", runGit, ...overrides };
}

test("parseImpactMode defaults to per-file and rejects unknown modes", () => {
  assert.equal(parseImpactMode(undefined), "per-file");
  assert.equal(parseImpactMode(""), "per-file");
  assert.equal(parseImpactMode(" changed-set "), "changed-set");
  assert.throws(() => parseImpactMode("changed_set"), /impact-mode must be one of per-file, changed-set/);
});

test("buildChangedSetImpactArgs attaches the merge-base and options so no value becomes a flag", () => {
  assert.deepEqual(buildChangedSetImpactArgs({ store: "/s", changedRef: MERGE_BASE, profiles: ["web", "--evil"], maxNodes: 10, maxEdges: 20 }), [
    "--store",
    "/s",
    "impact",
    `--changed=${MERGE_BASE}`,
    "--json",
    "--profile=web",
    "--profile=--evil",
    "--max-nodes=10",
    "--max-edges=20",
  ]);
  assert.throws(() => buildChangedSetImpactArgs({ store: "/s", changedRef: "main" }), /not an object id/);
  assert.throws(() => buildChangedSetImpactArgs({ store: "/s", changedRef: "--output=x" }), /not an object id/);
});

test("supportsChangedSetImpact reads the optional selector from the usage line, not the version", () => {
  assert.equal(supportsChangedSetImpact({ exitCode: 0, stdout: NEW_HELP }), true);
  assert.equal(supportsChangedSetImpact({ exitCode: 0, stdout: OLD_HELP }), false);
  assert.equal(supportsChangedSetImpact({ exitCode: 2, stdout: NEW_HELP }), false);
  assert.equal(supportsChangedSetImpact({ exitCode: 0, stdout: "" }), false);
});

test("classifyChangedSetResult accepts only a changed_set envelope and keeps failures as errors", () => {
  assert.equal(classifyChangedSetResult(changedSetEnvelope(changedSetData())).status, "ok");
  assert.deepEqual(classifyChangedSetResult({ exitCode: 0, stdout: JSON.stringify({ data: okResult([]).data }), stderr: "" }), {
    status: "error",
    exitCode: 0,
    message: "impact JSON envelope is not a changed_set result",
  });
  assert.equal(classifyChangedSetResult({ exitCode: 0, stdout: "not json", stderr: "" }).message, "impact output is not valid JSON");
  assert.deepEqual(classifyChangedSetResult({ exitCode: 3, stdout: "", stderr: "error: service resource limit exceeded\n" }), {
    status: "error",
    exitCode: 3,
    message: "service resource limit exceeded",
  });
});

test("changedSetFiles credits each impacted node to every changed path that reaches it", () => {
  const entries = [
    { change: "M", path: "src/a.ts" },
    { change: "M", path: "src/b.ts" },
    { change: "M", path: "docs/c.md" },
    { change: "D", path: "src/gone.ts" },
    { change: "A", path: "src/unknown.ts" },
  ];
  const files = changedSetFiles(entries, scenarioChangedSet());
  const byPath = Object.fromEntries(files.map((file) => [file.path, file.result]));
  assert.equal(byPath["src/a.ts"].status, "ok");
  assert.deepEqual(
    byPath["src/a.ts"].data.impacts.map((item) => [item.node.id, item.depth]),
    [
      ["route-orders", 1],
      ["pkg-web", 1],
    ],
  );
  // b.ts is itself a changed node (depth 0), so it is not an impact of a.ts here.
  assert.deepEqual(
    byPath["src/b.ts"].data.impacts.map((item) => item.node.id),
    ["route-orders"],
  );
  assert.deepEqual(byPath["docs/c.md"], { status: "unmapped", exitCode: 0, message: "no graph node for this path" });
  assert.deepEqual(byPath["src/gone.ts"], { status: "deleted" });
  assert.deepEqual(byPath["src/unknown.ts"], { status: "error", exitCode: 0, message: "changed-set impact did not report this path" });
});

test("changedSetFiles matches a renamed file by its new path", () => {
  const data = changedSetData({
    mappings: [mapping("src/to.ts", ["file-to"], { status: "renamed", old_path: "src/from.ts" })],
    impacts: [changedImpact(SCENARIO_ROUTE, 2, ["src/to.ts"])],
  });
  const [file] = changedSetFiles([{ change: "R", path: "src/to.ts", oldPath: "src/from.ts", similarity: 90 }], data);
  assert.equal(file.result.status, "ok");
  assert.equal(file.oldPath, "src/from.ts");
  assert.deepEqual(file.result.data.impacts.map((item) => item.node.id), ["route-orders"]);
});

test("collectReport changed-set makes one impact call and reports what per-file reports", async () => {
  const perFile = changedSetDepgraph();
  const perFileReport = await collectReport({ ...scenarioCollect(), runDepgraph: perFile.runDepgraph });
  const changedSet = changedSetDepgraph();
  const warnings = [];
  const changedSetReport = await collectReport({
    ...scenarioCollect(),
    impactMode: "changed-set",
    runDepgraph: changedSet.runDepgraph,
    onWarning: (text) => warnings.push(text),
  });

  assert.deepEqual(warnings, []);
  assert.deepEqual(
    changedSet.calls.map((args) => args.slice(0, 4)),
    [
      ["impact", "--help"],
      ["--store", "/s", "impact", `--changed=${MERGE_BASE}`],
    ],
  );
  assert.deepEqual(changedSetReport.impact_mode, { requested: "changed-set", used: "changed-set" });
  assert.deepEqual(perFileReport.impact_mode, { requested: "per-file", used: "per-file" });
  assert.deepEqual(
    changedSetReport.changed_files.map((file) => [file.path, file.status, file.impacted_count]),
    [
      ["src/a.ts", "ok", 2],
      ["src/b.ts", "ok", 1],
      ["docs/c.md", "unmapped", undefined],
      ["src/gone.ts", "deleted", undefined],
    ],
  );
  assert.deepEqual(changedSetReport.totals, { changed: 4, routes: 1, packages: 1, others: 0, impacted: 2 });
  assert.equal(changedSetReport.incomplete, false);
  assert.deepEqual(changedSetReport.diagnostics, [{ code: "profile_skipped", message: "profile web was skipped" }]);

  // per-file also lists b.ts, a changed file, as impacted by a.ts; the
  // changed-set result treats it as a changed node. Everything else agrees.
  const withoutChangedFiles = perFileReport.impacted.filter((entry) => entry.id !== "file-src/b.ts");
  assert.deepEqual(changedSetReport.impacted, withoutChangedFiles);
  assert.deepEqual(changedSetReport.skipped, perFileReport.skipped);
});

test("collectReport changed-set ignores max-files because it makes a single call", async () => {
  const { runDepgraph, calls } = changedSetDepgraph();
  const report = await collectReport({ ...scenarioCollect(), impactMode: "changed-set", maxFiles: 1, runDepgraph });
  assert.equal(calls.length, 2);
  assert.deepEqual(report.skipped, { count: 0, paths: [] });
  assert.equal(report.changed_files.filter((file) => file.status === "ok").length, 2);
});

test("collectReport changed-set turns a failed call into errors for every surviving file", async () => {
  const { runDepgraph } = changedSetDepgraph({
    answer: () => ({ exitCode: 3, stdout: "", stderr: "error: service resource limit exceeded\n" }),
  });
  const report = await collectReport({ ...scenarioCollect(), impactMode: "changed-set", runDepgraph });
  assert.equal(report.incomplete, true);
  assert.deepEqual(
    report.changed_files.map((file) => [file.path, file.status, file.exit_code]),
    [
      ["src/a.ts", "error", 3],
      ["src/b.ts", "error", 3],
      ["docs/c.md", "error", 3],
      ["src/gone.ts", "deleted", undefined],
    ],
  );
  assert.equal(report.changed_files[0].message, "service resource limit exceeded");
  assert.deepEqual(report.impacted, []);
});

test("collectReport changed-set marks the report incomplete when the result is incomplete", async () => {
  const { runDepgraph } = changedSetDepgraph({ answer: () => changedSetEnvelope({ ...scenarioChangedSet(), complete: false }) });
  const report = await collectReport({ ...scenarioCollect(), impactMode: "changed-set", runDepgraph });
  assert.equal(report.incomplete, true);
  assert.equal(report.changed_files[0].complete, false);
});

test("collectReport changed-set falls back to per-file with a warning on a depgraph without it", async () => {
  const { runDepgraph, calls } = changedSetDepgraph({ help: OLD_HELP });
  const warnings = [];
  const report = await collectReport({ ...scenarioCollect(), impactMode: "changed-set", runDepgraph, onWarning: (text) => warnings.push(text) });
  assert.deepEqual(warnings, ["impact-mode changed-set falls back to per-file: this depgraph does not support impact --changed without a selector"]);
  assert.equal(calls.some((args) => args.some((arg) => arg.startsWith("--changed="))), false);
  assert.deepEqual(
    calls.slice(1).map((args) => args[3]),
    ["path:src/a.ts", "path:src/b.ts", "path:docs/c.md"],
  );
  assert.equal(report.impact_mode.used, "per-file");
  assert.match(report.impact_mode.fallback_reason, /does not support/);
  assert.equal(report.totals.impacted, 3);
});

test("collectReport changed-set falls back when the call itself says a selector is required", async () => {
  const { runDepgraph } = changedSetDepgraph({ answer: () => ({ exitCode: 2, stdout: "", stderr: OLD_SELECTOR_ERROR }) });
  const warnings = [];
  const report = await collectReport({ ...scenarioCollect(), impactMode: "changed-set", runDepgraph, onWarning: (text) => warnings.push(text) });
  assert.equal(warnings.length, 1);
  assert.equal(report.impact_mode.used, "per-file");
  assert.equal(report.changed_files[0].status, "ok");
});

test("collectReport changed-set reads a partial scan attempt per file because impact --changed needs the current snapshot", async () => {
  const { runDepgraph, calls } = changedSetDepgraph();
  const warnings = [];
  const report = await collectReport({
    ...scenarioCollect(),
    impactMode: "changed-set",
    scanExitCode: 3,
    scanOutput: { scan_id: "4aea1ad6-316f-4863-94f5-14ee01e3763a", status: "partial", error: "rust worker exceeded its memory budget" },
    runDepgraph,
    onWarning: (text) => warnings.push(text),
  });
  assert.equal(warnings.length, 1);
  assert.match(warnings[0], /attempt/);
  assert.equal(calls.some((args) => args[0] === "impact" && args[1] === "--help"), false);
  assert.equal(calls[0][2], "--scan-id=attempt:4aea1ad6-316f-4863-94f5-14ee01e3763a");
  assert.equal(report.impact_mode.used, "per-file");
  assert.equal(report.scan.status, "partial");
});

test("collectReport changed-set does not query impact when the scan failed", async () => {
  const { runDepgraph, calls } = changedSetDepgraph();
  const report = await collectReport({ ...scenarioCollect(), impactMode: "changed-set", scanExitCode: 3, scanMessage: "worker failed", runDepgraph });
  assert.deepEqual(calls, []);
  assert.equal(report.changed_files[0].status, "not_analyzed");
});

test("collectReport rejects an unknown impact mode before running git", async () => {
  const { runGit, calls } = fakeGit("");
  await assert.rejects(collectReport({ ...scenarioCollect(), runGit, impactMode: "fast", runDepgraph: async () => assert.fail() }), /impact-mode/);
  assert.deepEqual(calls, []);
});

test("the Validate inputs step rejects an unknown impact-mode", () => {
  const script = compositeStepScript(readFileSync(ACTION_YML, "utf8"), "paths");
  const runnerTemp = mkdtempSync(join(tmpdir(), "pr-impact-runner-"));
  try {
    const run = (mode) =>
      spawnSync("bash", ["-c", script], {
        encoding: "utf8",
        env: {
          PATH: process.env.PATH,
          RUNNER_TEMP: runnerTemp,
          GITHUB_OUTPUT: join(runnerTemp, "out"),
          INPUT_STRICT: "false",
          INPUT_POST_COMMENT: "false",
          INPUT_IMPACT_MODE: mode,
        },
      });
    assert.equal(run("changed-set").status, 0);
    const rejected = run("changed_set");
    assert.equal(rejected.status, 2);
    assert.match(rejected.stderr, /impact-mode must be per-file or changed-set/);
  } finally {
    rmSync(runnerTemp, { recursive: true, force: true });
  }
});

// --- rendering -----------------------------------------------------------

test("escapeMarkdown neutralizes table, HTML, code, link, and mention syntax", () => {
  const escaped = escapeMarkdown("a|b <script>&`x` [l](u) @team *s* _u_ ~t~ \\ \n2");
  for (const raw of ["|", "<", ">", "`", "[", "]", "@", "*", "_", "~", "\\", "\n"]) {
    assert.ok(!escaped.includes(raw), `still contains ${JSON.stringify(raw)}: ${escaped}`);
  }
  assert.ok(escaped.includes("&amp;"));
  assert.equal(escapeMarkdown("plain/path.ts"), "plain/path.ts");
});

test("escapeMarkdown keeps bare URLs from becoming GitHub autolinks", () => {
  const escaped = escapeMarkdown("see https://evil.example/x or HTTP://a.b and www.evil.example / WWW.Evil.example");
  // GFM autolinks scheme URLs only through a literal ":" and www links only through a literal "www.".
  assert.ok(!escaped.includes(":"), `still contains ":": ${escaped}`);
  assert.ok(!/www\./i.test(escaped), `still contains "www.": ${escaped}`);
  assert.match(escaped, /https&#58;\/\/evil\.example\/x/);
  assert.match(escaped, /www&#46;evil\.example/);
  assert.match(escaped, /WWW&#46;Evil\.example/);
  assert.equal(escapeMarkdown("a.b.c/d.ts"), "a.b.c/d.ts");
});

test("renderComment keeps URLs in display names from autolinking", () => {
  const report = reportFixture({
    files: [{ change: "M", path: "a", result: okResult([impact(node("r", "route", "https://evil.example/x www.evil.example"), 1)]) }],
  });
  const body = renderComment(report, { repository: REPOSITORY });
  assert.doesNotMatch(body, /https:\/\/evil\.example/i);
  assert.doesNotMatch(body, /www\.evil\.example/i);
  assert.match(body, /https&#58;\/\/evil\.example\/x/);
});

test("blobUrl builds a line-anchored link and encodes path segments", () => {
  assert.equal(
    blobUrl({ repository: REPOSITORY, headSha: HEAD_SHA, path: "src/a b#.ts", startLine: 3, endLine: 5 }),
    `https://github.com/${REPOSITORY}/blob/${HEAD_SHA}/src/a%20b%23.ts#L3-L5`,
  );
  assert.equal(
    blobUrl({ repository: REPOSITORY, headSha: HEAD_SHA, path: "a.ts", startLine: 3, endLine: 3 }),
    `https://github.com/${REPOSITORY}/blob/${HEAD_SHA}/a.ts#L3`,
  );
  assert.equal(blobUrl({ repository: "bad repo", headSha: HEAD_SHA, path: "a.ts", startLine: 1 }), null);
  assert.equal(blobUrl({ repository: REPOSITORY, headSha: "main", path: "a.ts", startLine: 1 }), null);
  assert.equal(blobUrl({ repository: REPOSITORY, headSha: HEAD_SHA, path: "../etc/passwd", startLine: 1 }), null);
});

test("renderComment starts with the marker and summarizes routes and packages", () => {
  const report = reportFixture({
    files: [
      {
        change: "M",
        path: "src/a.ts",
        result: okResult([
          impact(node("r", "route", "/users/:id"), 2, [step("imports", "src/a.ts", 3), step("route_handler", "app/users/page.tsx", 10, 12)]),
          impact(node("p", "package_instance", "web@1.0.0"), 1),
          impact(node("s", "symbol", "helper"), 1),
        ]),
      },
    ],
  });
  const body = renderComment(report, { repository: REPOSITORY });
  assert.ok(body.startsWith(COMMENT_MARKER));
  assert.match(body, /変更ファイル 1 件/);
  assert.match(body, /影響ルート 1 件/);
  assert.match(body, /影響パッケージ 1 件/);
  assert.match(body, /その他ノード 1 件/);
  assert.match(body, /\/users\/&#58;id/);
  assert.match(body, /<details>/);
  assert.match(
    body,
    /https:\/\/github\.com\/TamaT-LLC\/depgraph-cli\/blob\/0123456789abcdef0123456789abcdef01234567\/app\/users\/page\.tsx#L10-L12/,
  );
  assert.match(body, /route_handler/);
  assert.match(body, /depgraph 0\.6\.4/);
  assert.match(body, /実行していません/);
});

test("renderComment prefixes evidence links with the scan root inside the repository", () => {
  const report = reportFixture({
    pathPrefix: "packages/web/",
    files: [{ change: "M", path: "a.ts", result: okResult([impact(node("r", "route", "/"), 1, [step("x", "a.ts", 4)])]) }],
  });
  const body = renderComment(report, { repository: REPOSITORY });
  assert.ok(body.includes(`/blob/${HEAD_SHA}/packages/web/a.ts#L4`));
});

test("renderComment lists each evidence location of a step once", () => {
  const duplicated = step("renders", "app/page.tsx", 2, 4);
  duplicated.evidence.push({ ...duplicated.evidence[0], extractor: "other" });
  const report = reportFixture({
    files: [{ change: "M", path: "a", result: okResult([impact(node("r", "route", "/"), 1, [duplicated])]) }],
  });
  const body = renderComment(report, { repository: REPOSITORY });
  assert.equal(body.split("app/page.tsx#L2-L4").length - 1, 1);
});

test("renderComment escapes hostile display names", () => {
  const report = reportFixture({
    files: [{ change: "M", path: "a", result: okResult([impact(node("r", "route", "</details><img src=x>|@admin"), 1)]) }],
  });
  const body = renderComment(report, { repository: REPOSITORY });
  assert.ok(!body.includes("<img"));
  assert.ok(!body.includes("@admin"));
});

test("renderComment explains a zero-impact result", () => {
  const report = reportFixture({ files: [{ change: "M", path: "a", result: okResult([]) }] });
  const body = renderComment(report, { repository: REPOSITORY });
  assert.match(body, /影響を受けるノードは見つかりませんでした/);
});

test("renderComment does not claim zero impact when the change only deletes files", () => {
  const report = reportFixture({
    files: [
      { change: "D", path: "app/users/page.tsx", result: { status: "deleted" } },
      { change: "D", path: "gone.ts", result: { status: "deleted" } },
    ],
  });
  assert.equal(report.changed_files.filter((file) => file.status === "deleted").length, 2);
  const body = renderComment(report, { repository: REPOSITORY });
  assert.doesNotMatch(body, /影響を受けるノードは見つかりませんでした/);
  assert.match(body, /削除されたファイル 2 件の影響（消えたルートなど）は計算していません/);
});

test("renderComment notes uncomputed deletions next to the impacts of other files", () => {
  const report = reportFixture({
    files: [
      { change: "M", path: "src/a.ts", result: okResult([impact(node("r", "route", "/users"), 1)]) },
      { change: "D", path: "gone.ts", result: { status: "deleted" } },
    ],
  });
  const body = renderComment(report, { repository: REPOSITORY });
  assert.match(body, /影響ルート（1 件）/);
  assert.match(body, /削除されたファイル 1 件の影響（消えたルートなど）は計算していません/);
});

test("renderComment limits a zero-impact claim to the surviving files when some were deleted", () => {
  const report = reportFixture({
    files: [
      { change: "M", path: "src/a.ts", result: okResult([]) },
      { change: "D", path: "gone.ts", result: { status: "deleted" } },
    ],
  });
  const body = renderComment(report, { repository: REPOSITORY });
  assert.doesNotMatch(body, /^影響を受けるノードは見つかりませんでした/m);
  assert.match(body, /削除されたファイルを除く変更では、影響を受けるノードは見つかりませんでした/);
  assert.match(body, /削除されたファイル 1 件の影響（消えたルートなど）は計算していません/);
});

test("renderComment lists unmapped, error, deleted, and skipped files in a collapsed section", () => {
  const report = reportFixture({
    files: [
      { change: "D", path: "gone.ts", result: { status: "deleted" } },
      { change: "M", path: "README.md", result: { status: "unmapped", exitCode: 2, message: "no node" } },
      { change: "M", path: "big.ts", result: { status: "error", exitCode: 3, message: "limit" } },
    ],
    skipped: ["s.ts"],
  });
  const body = renderComment(report, { repository: REPOSITORY });
  assert.match(body, /README\.md/);
  assert.match(body, /big\.ts/);
  assert.match(body, /exit 3/);
  assert.match(body, /gone\.ts/);
  assert.match(body, /上限を超えたため 1 件/);
});

test("renderComment reports scan failure and strict policy violations", () => {
  const failed = renderComment(reportFixture({ scan: { exitCode: 3, message: "worker crashed" } }), { repository: REPOSITORY });
  assert.match(failed, /scan が失敗しました/);
  assert.match(failed, /worker crashed/);
  const violated = renderComment(reportFixture({ scan: { exitCode: 1 }, strict: true }), { repository: REPOSITORY });
  assert.match(violated, /ポリシー違反/);
});

test("renderComment stays under the size limit and notes the truncation", () => {
  const impacts = Array.from({ length: 3000 }, (_, index) =>
    impact(node(`r${index}`, "route", `/route/${index}/${"x".repeat(40)}`), 1, [step("imports", `src/file-${index}.ts`, index + 1)]),
  );
  const report = reportFixture({ files: [{ change: "M", path: "a", result: okResult(impacts) }] });
  const body = renderComment(report, { repository: REPOSITORY, maxLength: 60000 });
  assert.ok(body.length <= 60000, `length ${body.length}`);
  assert.ok(body.startsWith(COMMENT_MARKER));
  assert.match(body, /省略/);
  assert.equal((body.match(/<details>/g) ?? []).length, (body.match(/<\/details>/g) ?? []).length);
});

// --- comment upsert ------------------------------------------------------

function fakeFetch(pages) {
  const calls = [];
  const fetchImpl = async (url, init = {}) => {
    calls.push({ url, method: init.method ?? "GET", body: init.body, headers: init.headers });
    const method = init.method ?? "GET";
    if (method === "GET") {
      const page = Number(new URL(url).searchParams.get("page") ?? "1");
      const items = pages[page - 1] ?? [];
      const headers = new Headers();
      if (page < pages.length) {
        const next = new URL(url);
        next.searchParams.set("page", String(page + 1));
        headers.set("link", `<${next}>; rel="next", <${next}>; rel="last"`);
      }
      return new Response(JSON.stringify(items), { status: 200, headers });
    }
    return new Response(JSON.stringify({ id: 999, html_url: "https://github.com/x" }), { status: method === "POST" ? 201 : 200 });
  };
  return { fetchImpl, calls };
}

const botComment = (id, body) => ({ id, body, user: { login: "github-actions[bot]", type: "Bot" } });

test("upsertComment patches the existing marked bot comment found on a later page", async () => {
  const { fetchImpl, calls } = fakeFetch([
    [{ id: 1, body: COMMENT_MARKER, user: { login: "someone", type: "User" } }, botComment(2, "unrelated")],
    [botComment(3, `${COMMENT_MARKER}\nold`)],
  ]);
  const result = await upsertComment({ token: "t", repository: REPOSITORY, prNumber: "12", body: `${COMMENT_MARKER}\nnew`, fetch: fetchImpl });
  assert.equal(result.action, "updated");
  const patch = calls.find((call) => call.method === "PATCH");
  assert.match(patch.url, /\/repos\/TamaT-LLC\/depgraph-cli\/issues\/comments\/3$/);
  assert.equal(JSON.parse(patch.body).body, `${COMMENT_MARKER}\nnew`);
  assert.equal(calls.filter((call) => call.method === "GET").length, 2);
  assert.equal(patch.headers.authorization, "Bearer t");
});

test("upsertComment posts a new comment when no marked comment exists", async () => {
  const { fetchImpl, calls } = fakeFetch([[botComment(2, "unrelated")]]);
  const result = await upsertComment({ token: "t", repository: REPOSITORY, prNumber: 12, body: `${COMMENT_MARKER}\nnew`, fetch: fetchImpl });
  assert.equal(result.action, "created");
  const post = calls.find((call) => call.method === "POST");
  assert.match(post.url, /\/repos\/TamaT-LLC\/depgraph-cli\/issues\/12\/comments$/);
});

test("upsertComment accepts a configured author login", async () => {
  const { fetchImpl, calls } = fakeFetch([[{ id: 5, body: COMMENT_MARKER, user: { login: "my-app[bot]", type: "Bot" } }]]);
  const result = await upsertComment({
    token: "t",
    repository: REPOSITORY,
    prNumber: 1,
    body: COMMENT_MARKER,
    authorLogin: "my-app[bot]",
    fetch: fetchImpl,
  });
  assert.equal(result.action, "updated");
  assert.ok(calls.some((call) => call.method === "PATCH" && call.url.endsWith("/comments/5")));
});

test("upsertComment validates the pull request number and repository", async () => {
  const { fetchImpl, calls } = fakeFetch([[]]);
  for (const prNumber of ["0", "-1", "1;2", "abc", "", 1.5]) {
    await assert.rejects(upsertComment({ token: "t", repository: REPOSITORY, prNumber, body: "x", fetch: fetchImpl }), /pull request number/);
  }
  await assert.rejects(upsertComment({ token: "t", repository: "../x", prNumber: 1, body: "x", fetch: fetchImpl }), /repository/);
  assert.equal(calls.length, 0);
});

test("upsertComment refuses to follow pagination links to another origin", async () => {
  const fetchImpl = async () =>
    new Response("[]", { status: 200, headers: { link: '<https://evil.example/next?page=2>; rel="next"' } });
  await assert.rejects(
    upsertComment({ token: "t", repository: REPOSITORY, prNumber: 1, body: "x", fetch: fetchImpl }),
    /origin/,
  );
});

test("upsertComment surfaces API failures", async () => {
  const fetchImpl = async () => new Response('{"message":"Resource not accessible"}', { status: 403 });
  await assert.rejects(upsertComment({ token: "t", repository: REPOSITORY, prNumber: 1, body: "x", fetch: fetchImpl }), /403/);
});

test("isOwnComment requires the marker and the expected bot identity", () => {
  assert.equal(isOwnComment(botComment(1, COMMENT_MARKER)), true);
  assert.equal(isOwnComment(botComment(1, "no marker")), false);
  assert.equal(isOwnComment({ id: 1, body: COMMENT_MARKER, user: { login: "github-actions[bot]", type: "User" } }), false);
  assert.equal(isOwnComment({ id: 1, body: COMMENT_MARKER, user: { login: "mallory", type: "User" } }), false);
});

// --- per-call output directory ---------------------------------------------

const ACTION_YML = new URL("../../.github/actions/pr-impact/action.yml", import.meta.url);
const WORKFLOW_YML = new URL("../../.github/workflows/depgraph-pr-impact.yml", import.meta.url);
const STEP_RUN_INDENT = "        ";

// Pull the `run: |` block of the step with the given id out of the composite
// action, so the test exercises the shell the runner actually executes.
function compositeStepScript(actionText, stepId) {
  const lines = actionText.split("\n");
  const idIndex = lines.findIndex((line) => line.trim() === `id: ${stepId}`);
  assert.notEqual(idIndex, -1, `step ${stepId} not found`);
  const runIndex = lines.findIndex((line, index) => index > idIndex && line.trim() === "run: |");
  assert.notEqual(runIndex, -1, `step ${stepId} has no run block`);
  const body = [];
  for (const line of lines.slice(runIndex + 1)) {
    if (line !== "" && !line.startsWith(STEP_RUN_INDENT)) break;
    body.push(line.slice(STEP_RUN_INDENT.length));
  }
  return body.join("\n");
}

function readOutputs(text) {
  return Object.fromEntries(
    text
      .split("\n")
      .filter((line) => line.includes("="))
      .map((line) => [line.slice(0, line.indexOf("=")), line.slice(line.indexOf("=") + 1)]),
  );
}

test("each Action call in a job gets its own output directory", () => {
  const script = compositeStepScript(readFileSync(ACTION_YML, "utf8"), "paths");
  const runnerTemp = mkdtempSync(join(tmpdir(), "pr-impact-runner-"));
  try {
    const runOnce = (index) => {
      const outputFile = join(runnerTemp, `github-output-${index}`);
      writeFileSync(outputFile, "");
      execFileSync("bash", ["-c", script], {
        env: {
          PATH: process.env.PATH,
          RUNNER_TEMP: runnerTemp,
          GITHUB_OUTPUT: outputFile,
          INPUT_STRICT: "false",
          INPUT_POST_COMMENT: "false",
          INPUT_IMPACT_MODE: "per-file",
        },
      });
      return readOutputs(readFileSync(outputFile, "utf8"));
    };
    const first = runOnce(1);
    const second = runOnce(2);
    for (const outputs of [first, second]) {
      assert.ok(outputs["out-dir"].startsWith(join(runnerTemp, "depgraph-pr-impact.")));
      for (const key of ["store", "scan-path", "scan-stderr-path", "report-path", "comment-path"]) {
        assert.ok(outputs[key].startsWith(`${outputs["out-dir"]}/`), `${key} is outside out-dir`);
      }
    }
    assert.notEqual(first["out-dir"], second["out-dir"]);
    assert.notEqual(first["report-path"], second["report-path"]);
    assert.notEqual(first["comment-path"], second["comment-path"]);
  } finally {
    rmSync(runnerTemp, { recursive: true, force: true });
  }
});

test("the dry-run workflow uploads the paths the Action reports instead of a fixed directory", () => {
  const workflow = readFileSync(WORKFLOW_YML, "utf8");
  assert.match(workflow, /^\s+\$\{\{ steps\.impact\.outputs\.report-path \}\}$/m);
  assert.match(workflow, /^\s+\$\{\{ steps\.impact\.outputs\.comment-path \}\}$/m);
  assert.doesNotMatch(workflow, /depgraph-pr-impact\//);
});
