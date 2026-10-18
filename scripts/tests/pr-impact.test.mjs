import assert from "node:assert/strict";
import test from "node:test";

import {
  aggregateReport,
  ambiguousCandidateId,
  buildImpactArgs,
  classifyImpactResult,
  collectReport,
  parseNameStatusZ,
  parseProfiles,
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

test("classifyImpactResult maps exit 2 to unmapped and keeps the message head", () => {
  const result = classifyImpactResult({ exitCode: 2, stdout: "", stderr: "selector did not match\nmore detail" });
  assert.deepEqual(result, { status: "unmapped", exitCode: 2, message: "selector did not match" });
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

// --- rendering -----------------------------------------------------------

test("escapeMarkdown neutralizes table, HTML, code, link, and mention syntax", () => {
  const escaped = escapeMarkdown("a|b <script>&`x` [l](u) @team *s* _u_ ~t~ \\ \n2");
  for (const raw of ["|", "<", ">", "`", "[", "]", "@", "*", "_", "~", "\\", "\n"]) {
    assert.ok(!escaped.includes(raw), `still contains ${JSON.stringify(raw)}: ${escaped}`);
  }
  assert.ok(escaped.includes("&amp;"));
  assert.equal(escapeMarkdown("plain/path.ts"), "plain/path.ts");
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
  assert.match(body, /\/users\/:id/);
  assert.match(body, /<details>/);
  assert.ok(body.includes(`https://github.com/${REPOSITORY}/blob/${HEAD_SHA}/app/users/page.tsx#L10-L12`));
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
