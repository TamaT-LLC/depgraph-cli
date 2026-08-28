import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  cpSync,
  existsSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  ANSWER_SCHEMA_VERSION,
  BASELINE_COMMIT_PLACEHOLDER,
  PENDING_RELEASE_SENTINEL,
  PENDING_SPEC_ERROR,
  REPORT_SCHEMA_VERSION,
  SPEC_SCHEMA_VERSION,
  SPEC_SCHEMA_VERSION_V2,
  UNUSED_HEALTH_PROBE_PATH,
  canonicalJson,
  efficiencyRatio,
  expectedPackagedProductVersion,
  expectedSampleIdentity,
  generationFrozenContract,
  hostCliVersionsMatch,
  lintSpec,
  lintSpecFile,
  localGitConfigAllowed,
  materializeDogfoodPrompt,
  mcpToolContractPassed,
  sanitizedAgentEnvironment,
  scoreAnswer,
  sentDogfoodPromptSha256,
  sourceDigests,
  traceMetrics,
  traceSafety,
  v2PinnedReleaseAssetNames,
  validateAnswer,
  validateSpec,
  verifyReport,
} from "../agent-dogfood.mjs";

const root = join(dirname(fileURLToPath(import.meta.url)), "../..");
const fixtureDir = join(root, "fixtures/agent-dogfood-v1");
const specPath = join(fixtureDir, "spec.json");
const spec = JSON.parse(readFileSync(specPath, "utf8"));
const v2FixtureDir = join(root, "fixtures/agent-dogfood-v2");
const v2SpecPath = join(v2FixtureDir, "spec.json");
const v2Spec = JSON.parse(readFileSync(v2SpecPath, "utf8"));
const v2Prompt = readFileSync(join(v2FixtureDir, "prompt.md"), "utf8");
const DUMMY_SHA256 = "ab".repeat(32);
const DUMMY_OID = "cd".repeat(20);
const SCRIPT = join(root, "scripts/agent-dogfood.mjs");

function goldenAnswer() {
  return {
    schema_version: ANSWER_SCHEMA_VERSION,
    claims: Object.fromEntries(spec.claims.map((claim) => [claim.id, {
      ...claim.expected,
      evidence: [{ path: "README.md", line: 1, source: "source" }],
      reason: "The fixed evidence supports the canonical value.",
    }])),
    failure: { code: "none", task: "", remediation: "" },
  };
}

test("Agent dogfood spec fixes identities, samples, budgets, and thresholds", () => {
  assert.equal(validateSpec(spec), spec);
  const drifted = structuredClone(spec);
  drifted.host.maximum_tool_calls += 1;
  assert.throws(() => validateSpec(drifted), /identity or host controls/);

  const selected = structuredClone(spec);
  selected.host.samples_per_arm = 1;
  assert.throws(() => validateSpec(selected), /identity or host controls/);

  const relaxed = structuredClone(spec);
  relaxed.thresholds.maximum_false_exact_claims = 1;
  assert.throws(() => validateSpec(relaxed), /thresholds drifted/);

  const extended = structuredClone(spec);
  extended.release.unreviewed = true;
  assert.throws(() => validateSpec(extended), /incomplete or incompatible/);

  const missingRequiredTool = structuredClone(spec);
  missingRequiredTool.host.mcp_required_tools.pop();
  assert.throws(() => validateSpec(missingRequiredTool), /identity or host controls/);

  const driftedSafetyBaseline = structuredClone(spec);
  driftedSafetyBaseline.safety_baseline.source_sha256 = "0".repeat(64);
  assert.throws(() => validateSpec(driftedSafetyBaseline), /identity or host controls/);
});

test("every successful MCP sample must exercise the fixed workflow tool set", () => {
  assert.equal(mcpToolContractPassed(spec, "baseline", []), true);
  assert.equal(mcpToolContractPassed(spec, "baseline", ["get_context"]), false);
  assert.equal(mcpToolContractPassed(spec, "mcp", []), false);
  assert.equal(
    mcpToolContractPassed(spec, "mcp", spec.host.mcp_required_tools),
    true,
  );
  assert.equal(
    mcpToolContractPassed(
      spec,
      "mcp",
      spec.host.mcp_required_tools.filter((tool) => tool !== "graph_path_get"),
    ),
    false,
  );
});

test("golden scoring is exact and candidate or unresolved promotion fails closed", () => {
  const answer = goldenAnswer();
  const score = scoreAnswer(spec, answer);
  assert.equal(score.accuracy_percent, 100);
  assert.equal(score.major_recall_percent, 100);
  assert.equal(score.false_exact_claims, 0);
  assert.equal(score.candidate_or_unresolved_as_exact, 0);

  const promoted = structuredClone(answer);
  promoted.claims.rust_candidate_import.classification = "exact";
  const promotedScore = scoreAnswer(spec, promoted);
  assert.equal(promotedScore.accuracy_percent, 91.67);
  assert.deepEqual(promotedScore.false_exact_claim_ids, ["rust_candidate_import"]);
  assert.deepEqual(
    promotedScore.candidate_or_unresolved_as_exact_ids,
    ["rust_candidate_import"],
  );

  const wrongExact = structuredClone(answer);
  wrongExact.claims.rust_path.value = "target=wrong";
  const wrongExactScore = scoreAnswer(spec, wrongExact);
  assert.deepEqual(wrongExactScore.false_exact_claim_ids, ["rust_path"]);
});

test("answers reject path leaks and noncanonical insufficient claims", () => {
  const leaked = goldenAnswer();
  leaked.claims.rust_path.evidence[0].path = "/private/repository/secret.rs";
  assert.throws(() => validateAnswer(spec, leaked), /leaks invalid evidence/);

  const guessed = goldenAnswer();
  guessed.claims.rust_path = {
    verdict: "insufficient",
    classification: "exact",
    value: spec.claims[0].expected.value,
    evidence: [],
    reason: "Not enough evidence.",
  };
  assert.throws(() => validateAnswer(spec, guessed), /claim rust_path is invalid/);

  const missingPathEvidence = goldenAnswer();
  missingPathEvidence.claims.rust_path.evidence = [];
  assert.throws(
    () => validateAnswer(spec, missingPathEvidence),
    /claim rust_path is invalid/,
  );

  const aggregateWithoutPath = goldenAnswer();
  aggregateWithoutPath.claims.snapshot_package_diff.evidence = [];
  aggregateWithoutPath.claims.snapshot_file_diff.evidence = [];
  aggregateWithoutPath.claims.package_cycles.evidence = [];
  aggregateWithoutPath.claims.candidate_coverage.evidence = [];
  assert.equal(validateAnswer(spec, aggregateWithoutPath), aggregateWithoutPath);
});

test("Codex JSONL metrics count completed tool bytes and effective host tokens", () => {
  const trace = [
    { type: "thread.started", thread_id: "thread" },
    {
      type: "item.started",
      item: { id: "one", type: "command_execution" },
    },
    {
      type: "item.completed",
      item: {
        id: "one",
        type: "command_execution",
        aggregated_output: "abc",
      },
    },
    {
      type: "item.started",
      item: { id: "two", type: "mcp_tool_call", tool: "get_context" },
    },
    {
      type: "item.completed",
      item: {
        id: "two",
        type: "mcp_tool_call",
        tool: "get_context",
        status: "completed",
        error: null,
        result: {
          content: "value",
          structured_content: {
            contract_version: "depgraph-mcp-tools-v1",
            repository_id: "repository",
            result: { value: "value" },
          },
        },
      },
    },
    {
      type: "turn.completed",
      usage: {
        input_tokens: 100,
        cached_input_tokens: 60,
        output_tokens: 20,
      },
    },
  ].map(JSON.stringify).join("\n");
  const metrics = traceMetrics(trace);
  assert.equal(metrics.tool_calls, 2);
  assert.equal(
    metrics.tool_result_bytes,
    3 + Buffer.byteLength(
      '{"content":"value","structured_content":{"contract_version":"depgraph-mcp-tools-v1","repository_id":"repository","result":{"value":"value"}}}',
    ),
  );
  assert.equal(metrics.total_tokens, 120);
  assert.equal(metrics.effective_tokens, 60);
  assert.deepEqual(metrics.mcp_tools, ["get_context"]);
  assert.deepEqual(metrics.mcp_tools_succeeded, ["get_context"]);

  const failed = traceMetrics([
    JSON.stringify({
      type: "item.started",
      item: {
        id: "failed",
        type: "mcp_tool_call",
        tool: "graph_path_get",
        status: "in_progress",
      },
    }),
    JSON.stringify({
      type: "item.completed",
      item: {
        id: "failed",
        type: "mcp_tool_call",
        tool: "graph_path_get",
        status: "failed",
        error: "unavailable",
      },
    }),
  ].join("\n"));
  assert.deepEqual(failed.mcp_tools, ["graph_path_get"]);
  assert.deepEqual(failed.mcp_tools_succeeded, []);
  assert.equal(mcpToolContractPassed(spec, "mcp", failed.mcp_tools_succeeded), false);
});

test("trace safety fails closed on project or compound shell commands", () => {
  const observation = (command) => traceSafety([
    JSON.stringify({
      type: "item.started",
      item: { id: "command", type: "command_execution", command },
    }),
    JSON.stringify({
      type: "item.completed",
      item: { id: "command", type: "command_execution", command },
    }),
  ].join("\n"));
  const safe = observation("/bin/zsh -lc 'git status --short'");
  assert.equal(safe.command_execution_count, 1);
  assert.equal(safe.project_code_execution_observed, false);
  assert.match(safe.commands_sha256, /^[0-9a-f]{64}$/u);
  assert.equal(
    observation("/bin/zsh -c \"sed -n '1,10p' README.md\"")
      .project_code_execution_observed,
    false,
  );
  assert.equal(
    observation("/bin/zsh -lc \"rg -n 'from a|from b' workers/web/src\"")
      .project_code_execution_observed,
    false,
  );
  assert.equal(
    observation(
      "/bin/zsh -lc \"rg -n '^import .*from ' workers/web/src --glob '*.ts'\"",
    ).project_code_execution_observed,
    false,
  );
  assert.equal(
    observation("/bin/zsh -lc 'cargo test'").project_code_execution_observed,
    true,
  );
  assert.equal(
    observation("/bin/zsh -lc 'git status && cargo test'")
      .project_code_execution_observed,
    true,
  );
  assert.equal(
    observation("/bin/zsh -lc 'git reset --hard HEAD'")
      .project_code_execution_observed,
    true,
  );
  assert.equal(
    observation("/bin/zsh -lc 'git diff --output=/tmp/diff.txt HEAD^ HEAD'")
      .project_code_execution_observed,
    true,
  );
  assert.equal(
    observation("/bin/zsh -lc 'git log --output /tmp/log.txt -1'")
      .project_code_execution_observed,
    true,
  );
  assert.equal(
    observation('/bin/zsh -lc "git show \'--output=/tmp/show.txt\' HEAD"')
      .project_code_execution_observed,
    true,
  );
  assert.equal(
    observation('/bin/zsh -lc "git diff --out\'\'put=/tmp/diff.txt HEAD^ HEAD"')
      .project_code_execution_observed,
    true,
  );
  assert.equal(
    observation("/bin/zsh -lc 'sed -i bak README.md'")
      .project_code_execution_observed,
    true,
  );
  assert.equal(
    observation("/bin/zsh -lc 'rg --pre ./project-script pattern .'")
      .project_code_execution_observed,
    true,
  );
  assert.equal(
    observation('/bin/zsh -lc "rg --pr\'\'e ./project-script pattern ."')
      .project_code_execution_observed,
    true,
  );
  assert.equal(
    observation('/bin/zsh -lc "rg --pr${DOGFOOD_UNSET}e ./project-script pattern ."')
      .project_code_execution_observed,
    true,
  );
  assert.equal(
    observation('/bin/zsh -lc "rg --pr{,}e ./project-script pattern ."')
      .project_code_execution_observed,
    true,
  );
  assert.equal(
    observation("/bin/zsh -lc 'rg pattern *(.e:project-script:)' ")
      .project_code_execution_observed,
    true,
  );
  assert.equal(
    observation('/bin/zsh -lc "rg \'--hostname-bin=./project-script\' pattern ."')
      .project_code_execution_observed,
    true,
  );
  assert.equal(
    observation("/bin/zsh -lc 'rg pattern . &'").project_code_execution_observed,
    true,
  );
  assert.equal(
    observation("/bin/zsh -lc 'rg pattern .|sed -n 1p'")
      .project_code_execution_observed,
    true,
  );
});

test("Agent runs discard external Git and ripgrep execution configuration", () => {
  const environment = sanitizedAgentEnvironment({
    PATH: "/trusted/bin",
    GIT_EXTERNAL_DIFF: "./project-script",
    GIT_CONFIG_COUNT: "1",
    GIT_CONFIG_KEY_0: "diff.external",
    GIT_CONFIG_VALUE_0: "./project-script",
    RIPGREP_CONFIG_PATH: "/tmp/host-ripgreprc",
    ZDOTDIR: "/tmp/host-zdotdir",
  }, "/tmp/fresh-dogfood-output");
  assert.equal(environment.PATH, "/trusted/bin");
  assert.equal(environment.GIT_EXTERNAL_DIFF, undefined);
  assert.equal(environment.GIT_CONFIG_COUNT, "3");
  assert.equal(environment.GIT_CONFIG_KEY_0, "core.fsmonitor");
  assert.equal(environment.GIT_CONFIG_VALUE_0, "false");
  assert.equal(environment.GIT_CONFIG_GLOBAL, "/dev/null");
  assert.equal(environment.GIT_CONFIG_NOSYSTEM, "1");
  assert.equal(environment.GIT_ATTR_NOSYSTEM, "1");
  assert.equal(environment.GIT_OPTIONAL_LOCKS, "0");
  assert.equal(environment.GIT_PAGER, "");
  assert.equal(environment.RIPGREP_CONFIG_PATH, "/dev/null");
  assert.equal(environment.ZDOTDIR, "/tmp/fresh-dogfood-output");
  assert.equal(localGitConfigAllowed([
    "core.repositoryformatversion",
    "remote.origin.url",
    "branch.benchmark.remote",
  ]), true);
  for (const key of [
    "core.fsmonitor",
    "diff.project.command",
    "diff.project.textconv",
    "include.path",
    "pager.diff",
  ]) assert.equal(localGitConfigAllowed([key]), false);
});

test("efficiency ratios make a zero baseline explicit", () => {
  assert.equal(efficiencyRatio(0, 0), 1);
  assert.equal(efficiencyRatio(1, 0), null);
  assert.equal(efficiencyRatio(3, 2), 1.5);
});

test("report schema is closed recursively", () => {
  const schema = JSON.parse(
    readFileSync(join(root, "schemas/agent-dogfood-report-v1.schema.json"), "utf8"),
  );
  assert.equal(schema.properties.schema_version.const, REPORT_SCHEMA_VERSION);
  const visit = (value) => {
    if (Array.isArray(value)) {
      for (const item of value) visit(item);
      return;
    }
    if (value === null || typeof value !== "object") return;
    if (value.type === "object") assert.equal(value.additionalProperties, false);
    for (const item of Object.values(value)) visit(item);
  };
  visit(schema);
});

test("checked-in six-sample report is the deterministic aggregate", async () => {
  const rawDir = join(fixtureDir, "evidence/v0.5.0-rc.7");
  const report = JSON.parse(readFileSync(join(rawDir, "report.json"), "utf8"));
  assert.equal(await verifyReport({ specPath, rawDir, report }), true);

  const forged = structuredClone(report);
  forged.aggregates.mcp.accuracy_percent_median -= 1;
  await assert.rejects(
    verifyReport({ specPath, rawDir, report: forged }),
    /deterministic aggregate/,
  );
});

test("raw evidence rejects extra entries and symlink substitution", async (context) => {
  const rawDir = join(fixtureDir, "evidence/v0.5.0-rc.7");
  const temporary = mkdtempSync(join(tmpdir(), "depgraph-agent-dogfood-"));
  context.after(() => rmSync(temporary, { recursive: true, force: true }));
  const copied = join(temporary, "evidence");
  cpSync(rawDir, copied, { recursive: true });
  const report = JSON.parse(readFileSync(join(copied, "report.json"), "utf8"));

  const extra = join(copied, "selected-sample.json");
  writeFileSync(extra, "{}\n");
  await assert.rejects(
    verifyReport({ specPath, rawDir: copied, report }),
    /unexpected entry/,
  );
  rmSync(extra);

  const forged = join(temporary, "forged");
  cpSync(rawDir, forged, { recursive: true });
  const safetyPath = join(forged, "baseline-1.safety.json");
  const safety = JSON.parse(readFileSync(safetyPath, "utf8"));
  safety.before.source_sha256 = "0".repeat(64);
  safety.after.source_sha256 = "0".repeat(64);
  writeFileSync(safetyPath, `${JSON.stringify(safety, null, 2)}\n`);
  const safetyBytes = readFileSync(safetyPath);
  const samplePath = join(forged, "baseline-1.sample.json");
  const sample = JSON.parse(readFileSync(samplePath, "utf8"));
  sample.artifacts.safety.bytes = safetyBytes.length;
  sample.artifacts.safety.sha256 = createHash("sha256")
    .update(safetyBytes)
    .digest("hex");
  writeFileSync(samplePath, `${JSON.stringify(sample, null, 2)}\n`);
  await assert.rejects(
    verifyReport({ specPath, rawDir: forged, report }),
    /predeclared baseline/,
  );

  const trace = join(copied, "baseline-1.trace.jsonl");
  rmSync(trace);
  symlinkSync(join(rawDir, "baseline-1.trace.jsonl"), trace);
  await assert.rejects(
    verifyReport({ specPath, rawDir: copied, report }),
    /unexpected entry/,
  );
});

function pinV2Spec(pending, expectedValues = {}) {
  const pinned = structuredClone(pending);
  pinned.release_status = "pinned";
  pinned.release.tag = "v9.9.9-rc.1";
  const names = v2PinnedReleaseAssetNames(
    pinned.release.tag,
    pinned.release.host_target,
  );
  pinned.release.archive.name = names.archive;
  pinned.release.compiler_pack_archive.name = names.compiler_pack_archive;
  pinned.release.compiler_pack_requirement.name = names.compiler_pack_requirement;
  pinned.release.mcp_smoke.name = names.mcp_smoke;
  pinned.release.candidate_commit = DUMMY_OID;
  pinned.release.candidate_tree = DUMMY_OID;
  pinned.release.archive.sha256 = DUMMY_SHA256;
  pinned.release.compiler_pack_archive.sha256 = DUMMY_SHA256;
  pinned.release.compiler_pack_requirement.sha256 = DUMMY_SHA256;
  pinned.release.mcp_smoke.sha256 = DUMMY_SHA256;
  pinned.release.mcp_smoke.read_catalog_sha256 = DUMMY_SHA256;
  pinned.repository.baseline_commit = DUMMY_OID;
  pinned.repository.baseline_tree = DUMMY_OID;
  pinned.repository.candidate_commit = DUMMY_OID;
  pinned.repository.candidate_tree = DUMMY_OID;
  pinned.snapshots.baseline.id = `snapshot:sha256:${DUMMY_SHA256}`;
  pinned.snapshots.baseline.source_revision = DUMMY_OID;
  pinned.snapshots.candidate.id = `snapshot:sha256:${DUMMY_SHA256}`;
  pinned.snapshots.candidate.source_revision = DUMMY_OID;
  pinned.safety_baseline = {
    source_sha256: DUMMY_SHA256,
    store_sha256: DUMMY_SHA256,
    journal_sha256: DUMMY_SHA256,
    daemon_state_sha256: DUMMY_SHA256,
    relevant_processes: 0,
  };
  pinned.host.cli_version = "codex-cli 0.146.0";
  pinned.host.model = "gpt-5.6-terra";
  pinned.host.reasoning_effort = "medium";
  const defaults = {
    health_unused_findings: `count=1;digest=collection:sha256:${DUMMY_SHA256}`,
    health_finding_detail:
      `id=finding:sha256:${DUMMY_SHA256};kind=unused-file;confidence=confirmed;blockers=churn-unavailable`,
    health_hotspots: "top=file:workers/web/src/worker.ts;score=2500;blockers=none",
    health_audit_base:
      `base_present=true;changed_oid=${DUMMY_OID};digest=collection:sha256:${DUMMY_SHA256}`,
  };
  for (const claim of pinned.claims) {
    claim.expected.value = expectedValues[claim.id]
      ?? defaults[claim.id]
      ?? `pinned-${claim.id}`;
  }
  return pinned;
}

function goldenV2Answer(pinned) {
  return {
    schema_version: ANSWER_SCHEMA_VERSION,
    claims: Object.fromEntries(pinned.claims.map((claim) => [claim.id, {
      ...claim.expected,
      evidence: claim.id === "health_finding_detail"
        ? [{ path: UNUSED_HEALTH_PROBE_PATH, line: 1, source: "mcp" }]
        : [{ path: "README.md", line: 1, source: "source" }],
      reason: "The fixed evidence supports the canonical value.",
    }])),
    failure: { code: "none", task: "", remediation: "" },
  };
}

function runDogfood(args) {
  try {
    return {
      code: 0,
      stdout: execFileSync(process.execPath, [SCRIPT, ...args], {
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
      }),
      stderr: "",
    };
  } catch (error) {
    return {
      code: typeof error.status === "number" ? error.status : 1,
      stdout: error.stdout ?? "",
      stderr: `${error.stderr ?? ""}${error.message}`,
    };
  }
}

function sourceFiles(dir, acc = []) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if ([
      ".git",
      "node_modules",
      "target",
      "dist",
      "evidence",
    ].includes(entry.name)) continue;
    const path = join(dir, entry.name);
    if (entry.isDirectory()) sourceFiles(path, acc);
    else if (/\.(?:ts|tsx|js|mjs|cjs|rs|go)$/u.test(entry.name)) acc.push(path);
  }
  return acc;
}

test("v1 generation table is canonical-frozen", () => {
  const frozen = generationFrozenContract(SPEC_SCHEMA_VERSION);
  assert.equal(
    canonicalJson(frozen),
    canonicalJson({
      schema_version: "agent-dogfood-spec-v1",
      requires_release_status: false,
      identity_includes_cli_version: false,
      claim_descriptors: [
        { id: "rust_path", category: "dependency_path", major: true, verdict: "supported", classification: "exact" },
        { id: "go_dependency", category: "dependency", major: true, verdict: "supported", classification: "exact" },
        { id: "web_dependency", category: "dependency", major: true, verdict: "supported", classification: "exact" },
        { id: "web_dependents", category: "dependents", major: true, verdict: "supported", classification: "exact" },
        { id: "rust_impact", category: "impact", major: true, verdict: "supported", classification: "exact" },
        { id: "rust_unresolved_type", category: "unresolved", major: false, verdict: "supported", classification: "unresolved" },
        { id: "rust_candidate_import", category: "candidate", major: false, verdict: "supported", classification: "candidate" },
        { id: "snapshot_package_diff", category: "snapshot_diff", major: false, verdict: "supported", classification: "exact" },
        { id: "snapshot_file_diff", category: "snapshot_diff", major: false, verdict: "supported", classification: "exact" },
        { id: "file_cycle", category: "cycle", major: false, verdict: "supported", classification: "exact" },
        { id: "package_cycles", category: "cycle", major: false, verdict: "supported", classification: "exact" },
        { id: "candidate_coverage", category: "snapshot", major: false, verdict: "supported", classification: "exact" },
      ],
      claim_ids: [
        "rust_path",
        "go_dependency",
        "web_dependency",
        "web_dependents",
        "rust_impact",
        "rust_unresolved_type",
        "rust_candidate_import",
        "snapshot_package_diff",
        "snapshot_file_diff",
        "file_cycle",
        "package_cycles",
        "candidate_coverage",
      ],
      major_count: 5,
      mcp_enabled_tools: [
        "agent_edges_list",
        "agent_nodes_list",
        "get_context",
        "graph_cycles_list",
        "graph_dependencies_list",
        "graph_dependents_list",
        "graph_impact_get",
        "graph_path_get",
        "snapshot_diff_get",
      ],
      mcp_required_tools: [
        "agent_nodes_list",
        "get_context",
        "graph_cycles_list",
        "graph_dependencies_list",
        "graph_dependents_list",
        "graph_impact_get",
        "graph_path_get",
        "snapshot_diff_get",
      ],
      thresholds: {
        minimum_mcp_accuracy_percent: 90,
        minimum_mcp_major_recall_percent: 100,
        maximum_false_exact_claims: 0,
        maximum_candidate_or_unresolved_as_exact: 0,
        minimum_setup_successes_per_arm: 3,
        require_mcp_accuracy_not_below_baseline: true,
        maximum_mcp_median_tool_calls: 28,
        maximum_mcp_median_tool_result_bytes: 327680,
        maximum_mcp_median_elapsed_ms: 240000,
        maximum_mcp_median_effective_tokens: 100000,
        require_mcp_tool_contract: true,
        require_read_only_safety: true,
        require_packaged_reconnect: true,
      },
      allowing_empty_supported_evidence: [
        "snapshot_package_diff",
        "snapshot_file_diff",
        "package_cycles",
        "candidate_coverage",
      ],
      maximum_tool_calls: 28,
      issue: 357,
      benchmark_id: "depgraph-v0.5.0-rc.7-agent-dogfood-v1",
      health_unused_kinds: null,
    }),
  );
});

test("pending-release contract accepts lint-spec only and rejects the four execution paths", () => {
  assert.equal(lintSpec(v2Spec), v2Spec);
  assert.equal(lintSpecFile(v2SpecPath).release_status, "pending");
  assert.throws(() => lintSpec(v2Spec, { pinned: true }), new RegExp(PENDING_SPEC_ERROR));
  assert.throws(() => validateSpec(v2Spec), new RegExp(PENDING_SPEC_ERROR));
  assert.throws(
    () => scoreAnswer(v2Spec, goldenV2Answer(pinV2Spec(v2Spec))),
    new RegExp(PENDING_SPEC_ERROR),
  );
  assert.throws(
    () => validateAnswer(v2Spec, goldenV2Answer(pinV2Spec(v2Spec))),
    new RegExp(PENDING_SPEC_ERROR),
  );

  const residual = structuredClone(v2Spec);
  residual.release.archive.sha256 = DUMMY_SHA256;
  assert.throws(() => lintSpec(residual), /missing PENDING-RELEASE sentinels/);

  const excess = structuredClone(v2Spec);
  excess.release.archive.name = PENDING_RELEASE_SENTINEL;
  assert.throws(() => lintSpec(excess), /PENDING-RELEASE outside the pin set/);

  const leftover = pinV2Spec(v2Spec);
  leftover.release.tag = PENDING_RELEASE_SENTINEL;
  assert.throws(() => validateSpec(leftover), /still contains PENDING-RELEASE/);

  const linted = runDogfood(["lint-spec", v2SpecPath]);
  assert.equal(linted.code, 0);
  assert.match(linted.stdout, /linted Agent dogfood spec/);
  const pinnedLint = runDogfood(["lint-spec", "--pinned", v2SpecPath]);
  assert.notEqual(pinnedLint.code, 0);
  assert.match(`${pinnedLint.stdout}${pinnedLint.stderr}`, new RegExp(PENDING_SPEC_ERROR));
  const verifyPending = runDogfood([
    "verify",
    v2SpecPath,
    join(v2FixtureDir, "missing-evidence"),
    join(v2FixtureDir, "missing-report.json"),
  ]);
  assert.notEqual(verifyPending.code, 0);
  assert.match(`${verifyPending.stdout}${verifyPending.stderr}`, new RegExp(PENDING_SPEC_ERROR));
});

test("v2 pinned-form spec validates 16 claims and scores health confidence asymmetrically", () => {
  const pinned = pinV2Spec(v2Spec);
  assert.equal(validateSpec(pinned), pinned);
  assert.equal(lintSpec(pinned, { pinned: true, prompt: v2Prompt }), pinned);
  assert.equal(pinned.claims.length, 16);
  assert.equal(pinned.claims.filter((claim) => claim.major).length, 7);

  const answer = goldenV2Answer(pinned);
  const score = scoreAnswer(pinned, answer);
  assert.equal(score.total_claims, 16);
  assert.equal(score.major_claims, 7);
  assert.equal(score.accuracy_percent, 100);
  assert.equal(score.major_recall_percent, 100);

  const aggregateWithoutPath = structuredClone(answer);
  aggregateWithoutPath.claims.health_unused_findings.evidence = [];
  aggregateWithoutPath.claims.health_hotspots.evidence = [];
  aggregateWithoutPath.claims.health_audit_base.evidence = [];
  assert.equal(validateAnswer(pinned, aggregateWithoutPath), aggregateWithoutPath);

  const missingDetailEvidence = structuredClone(answer);
  missingDetailEvidence.claims.health_finding_detail.evidence = [];
  assert.throws(
    () => validateAnswer(pinned, missingDetailEvidence),
    /claim health_finding_detail is invalid/,
  );

  const scoreLayerConfirmed = pinV2Spec(v2Spec, {
    health_finding_detail:
      `id=finding:sha256:${DUMMY_SHA256};kind=unused-file;confidence=confirmed;blockers=churn-unavailable,runtime-not-observed`,
  });
  const scoreLayerAnswer = goldenV2Answer(scoreLayerConfirmed);
  assert.equal(scoreAnswer(scoreLayerConfirmed, scoreLayerAnswer).accuracy_percent, 100);

  const hardBlocker = pinV2Spec(v2Spec, {
    health_finding_detail:
      `id=finding:sha256:${DUMMY_SHA256};kind=unused-file;confidence=indeterminate;blockers=public-surface`,
  });
  const promotedConfirmed = goldenV2Answer(hardBlocker);
  promotedConfirmed.claims.health_finding_detail.value =
    `id=finding:sha256:${DUMMY_SHA256};kind=unused-file;confidence=confirmed;blockers=public-surface`;
  const promotedConfirmedScore = scoreAnswer(hardBlocker, promotedConfirmed);
  assert.equal(promotedConfirmedScore.accuracy_percent, 93.75);
  assert.deepEqual(promotedConfirmedScore.missed_major_claim_ids, ["health_finding_detail"]);

  const promotedProbable = goldenV2Answer(hardBlocker);
  promotedProbable.claims.health_finding_detail.value =
    `id=finding:sha256:${DUMMY_SHA256};kind=unused-file;confidence=probable;blockers=public-surface`;
  const promotedProbableScore = scoreAnswer(hardBlocker, promotedProbable);
  assert.equal(promotedProbableScore.accuracy_percent, 93.75);
  assert.deepEqual(promotedProbableScore.missed_claim_ids, ["health_finding_detail"]);
});

test("v2 expected sample identity pins the exact host cli_version tuple", () => {
  const pinned = pinV2Spec(v2Spec);
  const identity = expectedSampleIdentity(pinned, {
    spec: "11".repeat(32),
    prompt: "22".repeat(32),
    answerSchema: "33".repeat(32),
    safetySchema: "44".repeat(32),
  }, "55".repeat(32));
  assert.equal(identity.cli_version, "codex-cli 0.146.0");
  assert.equal(identity.model, "gpt-5.6-terra");
  assert.equal(identity.reasoning_effort, "medium");
  assert.equal(identity.sandbox, "read-only");
  assert.equal(identity.approval_policy, "never");
  assert.deepEqual(identity.mcp_enabled_tools, pinned.host.mcp_enabled_tools);
  assert.deepEqual(identity.mcp_required_tools, pinned.host.mcp_required_tools);

  const v1Identity = expectedSampleIdentity(spec, {
    spec: "11".repeat(32),
    prompt: "22".repeat(32),
    answerSchema: "33".repeat(32),
    safetySchema: "44".repeat(32),
  }, "55".repeat(32));
  assert.equal(Object.hasOwn(v1Identity, "cli_version"), false);

  const drifted = structuredClone(identity);
  drifted.cli_version = "codex-cli 0.146.1";
  assert.notEqual(canonicalJson(drifted), canonicalJson(identity));
});

test("v2 host cli_version accepts the measured Codex --version string", () => {
  assert.equal(hostCliVersionsMatch("codex-cli 0.146.0", "0.146.0"), true);
  assert.equal(hostCliVersionsMatch("codex-cli 0.146.0", "codex-cli 0.146.0"), true);
  assert.equal(hostCliVersionsMatch("0.146.0", "0.146.0"), true);
  assert.equal(hostCliVersionsMatch("codex-cli 0.146.1", "0.146.0"), false);
  assert.equal(hostCliVersionsMatch("other-cli 0.146.0", "codex-cli 0.146.0"), false);

  const numericPin = pinV2Spec(v2Spec);
  numericPin.host.cli_version = "0.146.0";
  assert.equal(validateSpec(numericPin), numericPin);
  assert.equal(hostCliVersionsMatch("codex-cli 0.146.0", numericPin.host.cli_version), true);
});

function writeTempV2Corpus(spec, prompt = v2Prompt) {
  const dir = mkdtempSync(join(tmpdir(), "dogfood-v2-"));
  writeFileSync(join(dir, "spec.json"), `${JSON.stringify(spec, null, 2)}\n`);
  writeFileSync(join(dir, "prompt.md"), prompt);
  return dir;
}

test("v2 claim descriptors freeze category, major, verdict, and classification", () => {
  const movedMajor = pinV2Spec(v2Spec);
  const unused = movedMajor.claims.find((claim) => claim.id === "health_unused_findings");
  const hotspot = movedMajor.claims.find((claim) => claim.id === "health_hotspots");
  unused.major = false;
  hotspot.major = true;
  assert.throws(() => validateSpec(movedMajor), /task corpus drifted/);

  const category = pinV2Spec(v2Spec);
  category.claims.find((claim) => claim.id === "health_unused_findings").category = "cleanup";
  assert.throws(() => validateSpec(category), /task corpus drifted/);

  const classification = pinV2Spec(v2Spec);
  classification.claims.find((claim) => claim.id === "health_hotspots")
    .expected.classification = "candidate";
  assert.throws(() => validateSpec(classification), /task corpus drifted/);

  const verdict = pinV2Spec(v2Spec);
  const detail = verdict.claims.find((claim) => claim.id === "health_finding_detail");
  detail.expected.verdict = "insufficient";
  detail.expected.classification = "not_applicable";
  detail.expected.value = "unknown";
  assert.throws(() => validateSpec(verdict), /task corpus drifted/);
  assert.throws(
    () => lintSpec(verdict, { pinned: true, prompt: v2Prompt }),
    /task corpus drifted/,
  );
});

test("v2 pinned unused-file invariants are enforced on validate and verify", () => {
  const zero = pinV2Spec(v2Spec, {
    health_unused_findings: `count=0;digest=collection:sha256:${DUMMY_SHA256}`,
  });
  assert.throws(() => validateSpec(zero), /does not guarantee an unused-file finding/);
  assert.throws(
    () => lintSpec(zero, { prompt: v2Prompt }),
    /does not guarantee an unused-file finding/,
  );

  const zeroDir = writeTempV2Corpus(zero);
  try {
    const verified = runDogfood([
      "verify",
      join(zeroDir, "spec.json"),
      join(zeroDir, "raw"),
      join(zeroDir, "report.json"),
    ]);
    assert.notEqual(verified.code, 0);
    assert.match(
      `${verified.stdout}${verified.stderr}`,
      /does not guarantee an unused-file finding/,
    );
  } finally {
    rmSync(zeroDir, { recursive: true, force: true });
  }

  const wrongKindPrompt = v2Prompt.replaceAll('kinds:["unused-file"]', 'kinds:["unused-export"]');
  const pinned = pinV2Spec(v2Spec);
  assert.throws(
    () => lintSpec(pinned, { prompt: wrongKindPrompt }),
    /does not pin unused-file/,
  );
  const kindDir = writeTempV2Corpus(pinned, wrongKindPrompt);
  try {
    const verified = runDogfood([
      "verify",
      join(kindDir, "spec.json"),
      join(kindDir, "raw"),
      join(kindDir, "report.json"),
    ]);
    assert.notEqual(verified.code, 0);
    assert.match(`${verified.stdout}${verified.stderr}`, /does not pin unused-file/);
  } finally {
    rmSync(kindDir, { recursive: true, force: true });
  }

  const runDir = writeTempV2Corpus(pinned, wrongKindPrompt);
  try {
    writeFileSync(
      join(runDir, "answer.schema.json"),
      readFileSync(join(v2FixtureDir, "answer.schema.json")),
    );
    writeFileSync(
      join(runDir, "safety.schema.json"),
      readFileSync(join(v2FixtureDir, "safety.schema.json")),
    );
    const rawDir = join(runDir, "raw");
    const ran = runDogfood([
      "run",
      join(runDir, "spec.json"),
      rawDir,
      join(runDir, "report.json"),
    ]);
    assert.notEqual(ran.code, 0);
    assert.match(`${ran.stdout}${ran.stderr}`, /does not pin unused-file/);
    assert.equal(existsSync(rawDir), false);
  } finally {
    rmSync(runDir, { recursive: true, force: true });
  }
});

test("v2 prompt pins baseline commit for runner injection", () => {
  const pinned = pinV2Spec(v2Spec);
  assert.match(v2Prompt, new RegExp(BASELINE_COMMIT_PLACEHOLDER.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&")));
  const materialized = materializeDogfoodPrompt(pinned, v2Prompt);
  assert.match(materialized, new RegExp(pinned.repository.baseline_commit));
  assert.equal(materialized.includes(BASELINE_COMMIT_PLACEHOLDER), false);
  assert.throws(
    () => materializeDogfoodPrompt(pinned, v2Prompt.replaceAll(BASELINE_COMMIT_PLACEHOLDER, DUMMY_OID)),
    /must pin repository\.baseline_commit/,
  );
  assert.throws(
    () => lintSpec(pinned, { prompt: v2Prompt.replaceAll(BASELINE_COMMIT_PLACEHOLDER, DUMMY_OID) }),
    /must pin repository\.baseline_commit/,
  );
  assert.equal(lintSpecFile(v2SpecPath).release_status, "pending");
});

test("v2 prompt digest is the materialized bytes sent to the host", () => {
  const pinned = pinV2Spec(v2Spec);
  const sent = materializeDogfoodPrompt(pinned, v2Prompt);
  const sentDigest = createHash("sha256").update(sent).digest("hex");
  assert.notEqual(sent, v2Prompt);
  assert.equal(sentDogfoodPromptSha256(pinned, v2Prompt), sentDigest);
  assert.notEqual(
    sentDogfoodPromptSha256(pinned, v2Prompt),
    createHash("sha256").update(v2Prompt).digest("hex"),
  );

  const dir = writeTempV2Corpus(pinned);
  try {
    writeFileSync(
      join(dir, "answer.schema.json"),
      readFileSync(join(v2FixtureDir, "answer.schema.json")),
    );
    writeFileSync(
      join(dir, "safety.schema.json"),
      readFileSync(join(v2FixtureDir, "safety.schema.json")),
    );
    writeFileSync(join(dir, "spec.json"), `${JSON.stringify(pinned, null, 2)}\n`);
    const digests = sourceDigests(join(dir, "spec.json"), pinned);
    assert.equal(digests.sentPrompt, sent);
    assert.equal(digests.prompt, sentDigest);
    assert.equal(
      expectedSampleIdentity(pinned, digests, "55".repeat(32)).prompt_sha256,
      sentDigest,
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }

  const v1Digests = sourceDigests(specPath, spec);
  assert.equal(
    v1Digests.prompt,
    createHash("sha256").update(readFileSync(join(fixtureDir, "prompt.md"))).digest("hex"),
  );
});

test("v2 pinned release identity derives versioned assets and rejects drift", () => {
  const pinned = pinV2Spec(v2Spec);
  assert.equal(expectedPackagedProductVersion(spec), "0.5.0");
  assert.equal(expectedPackagedProductVersion(pinned), "9.9.9");
  assert.deepEqual(
    v2PinnedReleaseAssetNames(pinned.release.tag, pinned.release.host_target),
    {
      archive: "depgraph-9.9.9-aarch64-apple-darwin.tar.gz",
      compiler_pack_archive: "depgraph-compiler-pack-9.9.9-aarch64-apple-darwin.tar.gz",
      compiler_pack_requirement:
        "depgraph-compiler-pack-9.9.9-aarch64-apple-darwin.requirement.json",
      mcp_smoke: "depgraph-9.9.9-aarch64-apple-darwin.mcp-smoke.json",
    },
  );

  const badTag = pinV2Spec(v2Spec);
  badTag.release.tag = "v0.0.0-test";
  assert.throws(() => validateSpec(badTag), /canonical RC tag/);

  const stableTag = pinV2Spec(v2Spec);
  stableTag.release.tag = "v9.9.9";
  assert.throws(() => validateSpec(stableTag), /canonical RC tag/);

  const leadingZero = pinV2Spec(v2Spec);
  leadingZero.release.tag = "v9.9.9-rc.01";
  assert.throws(() => validateSpec(leadingZero), /canonical RC tag/);

  for (const tag of ["v01.2.3-rc.1", "v1.02.3-rc.1", "v1.2.03-rc.1"]) {
    const padded = pinV2Spec(v2Spec);
    padded.release.tag = tag;
    assert.throws(() => validateSpec(padded), /canonical RC tag/);
  }

  const leftoverPendingNames = pinV2Spec(v2Spec);
  leftoverPendingNames.release.archive.name = "depgraph-aarch64-apple-darwin.tar.gz";
  leftoverPendingNames.release.compiler_pack_archive.name =
    "depgraph-compiler-pack-aarch64-apple-darwin.tar.gz";
  leftoverPendingNames.release.compiler_pack_requirement.name =
    "depgraph-compiler-pack-aarch64-apple-darwin.requirement.json";
  leftoverPendingNames.release.mcp_smoke.name = "depgraph-aarch64-apple-darwin.mcp-smoke.json";
  assert.throws(() => validateSpec(leftoverPendingNames), /asset names do not match the RC tag/);

  const versionDrift = pinV2Spec(v2Spec);
  versionDrift.release.tag = "v8.8.8-rc.2";
  assert.throws(() => validateSpec(versionDrift), /asset names do not match the RC tag/);
  assert.equal(expectedPackagedProductVersion({
    schema_version: SPEC_SCHEMA_VERSION_V2,
    release: { tag: "v8.8.8-rc.2" },
  }), "8.8.8");
});

test("unused health probe exists and is never imported", () => {
  const probePath = join(root, UNUSED_HEALTH_PROBE_PATH);
  assert.equal(existsSync(probePath), true);
  assert.match(readFileSync(probePath, "utf8"), /Intentionally unreferenced/);
  const importPattern =
    /(?:from|import)\s+['"][^'"]*unused-health-probe[^'"]*['"]|import\(\s*['"][^'"]*unused-health-probe|require\(\s*['"][^'"]*unused-health-probe/;
  const imported = [];
  for (const file of [
    ...sourceFiles(join(root, "workers")),
    ...sourceFiles(join(root, "crates")),
    ...sourceFiles(join(root, "scripts")),
    ...sourceFiles(join(root, "xtask")),
  ]) {
    if (file === probePath) continue;
    if (file.endsWith("scripts/tests/agent-dogfood.test.mjs")) continue;
    const text = readFileSync(file, "utf8");
    if (importPattern.test(text)) imported.push(file);
  }
  assert.deepEqual(imported, []);
});
