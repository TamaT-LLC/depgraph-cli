import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

const script = resolve("scripts/update-homebrew-tap.sh");
function fixture(current = "0.6.0") {
  const root = mkdtempSync(join(tmpdir(), "depgraph-tap-test-"));
  const bin = join(root, "bin");
  mkdirSync(bin);
  const repo = join(root, "repo");
  mkdirSync(repo);
  const git = (...args) => {
    const result = spawnSync("git", args, { cwd: repo, encoding: "utf8" });
    assert.equal(result.status, 0, result.stderr);
    return result.stdout.trim();
  };
  git("init", "--quiet", "--initial-branch=main");
  git("config", "user.name", "fixture");
  git("config", "user.email", "fixture@example.invalid");
  mkdirSync(join(repo, "Formula"));
  writeFileSync(join(repo, "Formula/depgraph.rb"), `  url "https://github.com/TamaT-LLC/depgraph-cli/releases/download/v${current}/archive.tar.gz"\nold\n`);
  writeFileSync(join(repo, "README.md"), "untouched\n");
  git("add", ".");
  git("commit", "--quiet", "-m", "initial");
  const remote = join(root, "remote.git");
  git("clone", "--quiet", "--bare", repo, remote);
  const config = join(root, "gitconfig");
  writeFileSync(config, `[url "file://${remote}"]\n  insteadOf = https://github.com/TamaT-LLC/homebrew-tap.git\n`);
  const formula = join(root, "depgraph.rb");
  writeFileSync(formula, '  url "https://github.com/TamaT-LLC/depgraph-cli/releases/download/v0.6.1/archive.tar.gz"\nnew\n');
  const log = join(root, "gh.log");
  writeFileSync(join(bin, "gh"), `#!/usr/bin/env node
const fs = require('node:fs');
const args = process.argv.slice(2);
fs.appendFileSync(process.env.FAKE_GH_LOG, JSON.stringify(args)+'\\n');
if (args[0] === 'api') console.log('12345');
else if (args[1] === 'list') console.log('');
else if (args[1] === 'create') console.log('https://github.com/TamaT-LLC/homebrew-tap/pull/123');
else process.exit(1);
`, { mode: 0o755 });
  const env = { ...process.env, PATH: `${bin}:${process.env.PATH}`, GIT_CONFIG_GLOBAL: config,
    GIT_CONFIG_NOSYSTEM: "1", FAKE_GH_LOG: log };
  delete env.GH_TOKEN;
  delete env.GITHUB_TOKEN;
  const run = (tag = "v0.6.1", dry = "true") => spawnSync("bash", [script, tag, formula, dry], { env, encoding: "utf8" });
  return { root, git, remote, repo, formula, log, run, cleanup: () => rmSync(root, { recursive: true, force: true }) };
}

test("dry run clones and compares without pushing or opening a PR", () => {
  const f = fixture();
  try {
    const result = f.run();
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /Dry run/);
    assert.equal(f.git("--git-dir", f.remote, "branch", "--list", "depgraph-v0.6.1"), "");
  } finally { f.cleanup(); }
});

test("update pushes exactly one formula change and creates a PR; rerun reuses the branch", () => {
  const f = fixture();
  try {
    let result = f.run("v0.6.1", "false");
    assert.equal(result.status, 0, result.stderr);
    assert.equal(f.git("--git-dir", f.remote, "diff", "--name-only", "main...depgraph-v0.6.1"), "Formula/depgraph.rb");
    assert.equal(f.git("--git-dir", f.remote, "show", "depgraph-v0.6.1:Formula/depgraph.rb"), 'url "https://github.com/TamaT-LLC/depgraph-cli/releases/download/v0.6.1/archive.tar.gz"\nnew');
    const head = f.git("--git-dir", f.remote, "rev-parse", "depgraph-v0.6.1");
    result = f.run("v0.6.1", "false");
    assert.equal(result.status, 0, result.stderr);
    assert.equal(f.git("--git-dir", f.remote, "rev-parse", "depgraph-v0.6.1"), head);
    const calls = readFileSync(f.log, "utf8");
    assert.match(calls, /--body-file/);
    assert.doesNotMatch(calls, /merge/);
  } finally { f.cleanup(); }
});

test("same version succeeds only when the formula matches exactly", () => {
  const f = fixture("0.6.1");
  try {
    assert.notEqual(f.run().status, 0);
    writeFileSync(f.formula, '  url "https://github.com/TamaT-LLC/depgraph-cli/releases/download/v0.6.1/archive.tar.gz"\nold\n');
    const result = f.run("v0.6.1", "false");
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /no PR needed/);
  } finally { f.cleanup(); }
});

test("rejects downgrade and malformed tag without modifying remote history", () => {
  const f = fixture("0.6.2");
  try {
    const head = f.git("--git-dir", f.remote, "rev-parse", "main");
    for (const tag of ["v0.6.1", "v00.6.1", "v0.6.1;touch evil", "v0.6.1-rc1"]) {
      assert.notEqual(f.run(tag, "false").status, 0);
    }
    assert.equal(f.git("--git-dir", f.remote, "rev-parse", "main"), head);
  } finally { f.cleanup(); }
});

test("an existing update branch with unrelated changes is rejected", () => {
  const f = fixture();
  try {
    f.git("switch", "--quiet", "-c", "depgraph-v0.6.1");
    writeFileSync(join(f.repo, "Formula/depgraph.rb"), readFileSync(f.formula));
    writeFileSync(join(f.repo, "README.md"), "unexpected\n");
    f.git("add", ".");
    f.git("commit", "--quiet", "-m", "unrelated change");
    f.git("push", "--quiet", f.remote, "HEAD:refs/heads/depgraph-v0.6.1");
    assert.notEqual(f.run("v0.6.1", "false").status, 0);
  } finally { f.cleanup(); }
});

test("privileged workflow binds only trusted source and verifies before token issuance", () => {
  const workflow = readFileSync(".github/workflows/homebrew-tap.yml", "utf8");
  assert.ok(workflow.indexOf("depgraph_release.py render") < workflow.indexOf("actions/create-github-app-token@"));
  assert.match(workflow, /ref: refs\/heads\/main/);
  assert.doesNotMatch(workflow, /ref: \$\{\{ github\.event\.workflow_run\.head_sha/);
  assert.match(workflow, /--release-run-id/);
  assert.match(workflow, /repositories: homebrew-tap/);
  assert.match(workflow, /github\.event\.workflow_run\.head_repository\.full_name == github\.repository/);
  assert.doesNotMatch(workflow, /pull_request_target|pull_request:/);
  assert.doesNotMatch(workflow, /persist-credentials: true|skip-token-revoke: true/);
});
