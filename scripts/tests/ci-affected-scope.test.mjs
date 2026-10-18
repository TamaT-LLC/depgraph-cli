import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

const script = resolve("scripts/ci-affected-scope.sh");

// Every run gets its own GITHUB_OUTPUT so a test inside CI never appends to
// the real step output file of the job that runs it.
function scratch() {
  const root = mkdtempSync(join(tmpdir(), "depgraph-ci-scope-test-"));
  const output = join(root, "github-output");
  writeFileSync(output, "");
  return { root, output, cleanup: () => rmSync(root, { recursive: true, force: true }) };
}

function baseEnv(output, overrides = {}) {
  const env = { ...process.env, GITHUB_OUTPUT: output, ...overrides };
  for (const key of ["CI_EVENT_NAME", "CI_BASE_SHA", "CI_HEAD_SHA"]) {
    if (!(key in overrides)) delete env[key];
  }
  return env;
}

function classify(job, input) {
  const s = scratch();
  try {
    return spawnSync("bash", [script, "classify", job], {
      input,
      env: baseEnv(s.output),
      encoding: "utf8",
    });
  } finally {
    s.cleanup();
  }
}

// [paths, go expectation, web expectation]
const CLASSIFY_CASES = [
  [["docs/50_test/x.md"], false, false],
  [["README.md"], false, false],
  [[".github/ISSUE_TEMPLATE/bug_report.yml"], false, false],
  [["workers/web/src/worker.ts"], false, true],
  [["workers/go/internal/worker/scan.go"], true, true],
  [["crates/depgraph-core/src/lib.rs"], false, true],
  [["crates/depgraph-core/tests/fixtures/health/issue437-go.ndjson"], true, true],
  [["crates/depgraph-mcp/src/main.rs"], false, false],
  [["crates/depgraph-mcp-tools/src/lib.rs"], false, true],
  [["workers/rust/src/lib.rs"], false, false],
  [["npm/depgraph/package.json"], false, false],
  [["schemas/x.json"], false, true],
  [["third_party/rust-src/COPYRIGHT"], false, true],
  [["LICENSE-MIT"], false, true],
  [["Cargo.lock"], true, true],
  [["crates/depgraph-mcp/Cargo.toml"], true, true],
  [["rust-toolchain.toml"], true, true],
  [[".github/workflows/ci.yml"], true, true],
  [[".github/settings-desired-v1.json"], true, true],
  [["scripts/ci-affected-scope.sh"], true, true],
  [["xtask/src/main.rs"], true, true],
  [["newdir/file"], true, true],
  [["docs/a.md", "newdir/x"], true, true],
  [[], true, true],
  // git quotes non-ASCII paths; the quoted form must never look ignorable.
  [['"docs/\\346.md"'], true, true],
];

for (const [paths, goExpected, webExpected] of CLASSIFY_CASES) {
  for (const [job, expected] of [
    ["go", goExpected],
    ["web", webExpected],
  ]) {
    test(`classify ${job} ${JSON.stringify(paths)} -> ${expected}`, () => {
      const input = paths.length === 0 ? "" : `${paths.join("\n")}\n`;
      const result = classify(job, input);
      assert.equal(result.status, 0, result.stderr);
      assert.equal(result.stdout, `${expected}\n`);
    });
  }
}

test("classify reads a final path that has no trailing newline", () => {
  const result = classify("go", "docs/a.md\nnewdir/x");
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, "true\n");
});

test("invalid arguments exit 2", () => {
  const s = scratch();
  try {
    for (const args of [["classify", "rust"], ["decide", "go-macos"], ["run", "go"], ["classify"], []]) {
      const result = spawnSync("bash", [script, ...args], {
        input: "",
        env: baseEnv(s.output),
        encoding: "utf8",
      });
      assert.equal(result.status, 2, `${JSON.stringify(args)}: ${result.stderr}`);
      assert.match(result.stderr, /usage:/);
    }
  } finally {
    s.cleanup();
  }
});

function repository() {
  const s = scratch();
  const repo = join(s.root, "repo");
  mkdirSync(repo);
  const git = (...args) => {
    const result = spawnSync("git", args, { cwd: repo, encoding: "utf8" });
    assert.equal(result.status, 0, result.stderr);
    return result.stdout.trim();
  };
  git("init", "--quiet", "--initial-branch=main");
  git("config", "user.name", "fixture");
  git("config", "user.email", "fixture@example.invalid");
  git("config", "commit.gpgsign", "false");
  const write = (path, content) => {
    mkdirSync(dirname(join(repo, path)), { recursive: true });
    writeFileSync(join(repo, path), content);
  };
  write("workers/go/a.go", "package a\n");
  write("docs/index.md", "docs\n");
  git("add", ".");
  git("commit", "--quiet", "-m", "initial");
  const base = git("rev-parse", "HEAD");
  const decide = (job, env) => {
    writeFileSync(s.output, "");
    const result = spawnSync("bash", [script, "decide", job], {
      cwd: repo,
      env: baseEnv(s.output, env),
      encoding: "utf8",
    });
    assert.equal(result.status, 0, result.stderr);
    return readFileSync(s.output, "utf8");
  };
  return { ...s, repo, git, write, base, decide };
}

test("decide runs every job outside pull requests", () => {
  const r = repository();
  try {
    for (const event of ["push", "workflow_dispatch", "", "merge_group"]) {
      for (const job of ["go", "web"]) {
        assert.equal(r.decide(job, { CI_EVENT_NAME: event }), "run=true\n", `${event}/${job}`);
      }
    }
    assert.equal(r.decide("go", {}), "run=true\n");
  } finally {
    r.cleanup();
  }
});

test("decide runs when the pull request SHAs are missing, malformed, or unknown", () => {
  const r = repository();
  try {
    const missing = "0".repeat(40);
    for (const [base, head] of [
      ["", ""],
      [r.base, ""],
      ["", r.base],
      ["not-a-sha", r.base],
      [r.base.toUpperCase(), r.base],
      [`${r.base}0`, r.base],
      [`${r.base};true`, r.base],
      [missing, r.base],
      [r.base, missing],
    ]) {
      assert.equal(
        r.decide("go", { CI_EVENT_NAME: "pull_request", CI_BASE_SHA: base, CI_HEAD_SHA: head }),
        "run=true\n",
        `${base}..${head}`,
      );
    }
  } finally {
    r.cleanup();
  }
});

test("decide skips a documentation-only pull request", () => {
  const r = repository();
  try {
    r.write("docs/index.md", "changed docs\n");
    r.write("README.md", "readme\n");
    r.git("add", ".");
    r.git("commit", "--quiet", "-m", "docs");
    const head = r.git("rev-parse", "HEAD");
    const env = { CI_EVENT_NAME: "pull_request", CI_BASE_SHA: r.base, CI_HEAD_SHA: head };
    assert.equal(r.decide("go", env), "run=false\n");
    assert.equal(r.decide("web", env), "run=false\n");
  } finally {
    r.cleanup();
  }
});

test("decide sees the source side of a file moved into an ignored directory", () => {
  const r = repository();
  try {
    r.git("mv", "workers/go/a.go", "docs/a.go");
    r.git("commit", "--quiet", "-m", "move");
    const head = r.git("rev-parse", "HEAD");
    const env = { CI_EVENT_NAME: "pull_request", CI_BASE_SHA: r.base, CI_HEAD_SHA: head };
    assert.equal(r.decide("go", env), "run=true\n");
    assert.equal(r.decide("web", env), "run=true\n");
  } finally {
    r.cleanup();
  }
});

test("decide refuses to run without a step output file", () => {
  const r = repository();
  try {
    const env = { ...process.env, CI_EVENT_NAME: "push" };
    delete env.GITHUB_OUTPUT;
    const result = spawnSync("bash", [script, "decide", "go"], { cwd: r.repo, env, encoding: "utf8" });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /GITHUB_OUTPUT/);
  } finally {
    r.cleanup();
  }
});
