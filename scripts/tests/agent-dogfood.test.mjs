import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  cpSync,
  mkdtempSync,
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
  REPORT_SCHEMA_VERSION,
  efficiencyRatio,
  mcpToolContractPassed,
  scoreAnswer,
  traceMetrics,
  traceSafety,
  validateAnswer,
  validateSpec,
  verifyReport,
} from "../agent-dogfood.mjs";

const root = join(dirname(fileURLToPath(import.meta.url)), "../..");
const fixtureDir = join(root, "fixtures/agent-dogfood-v1");
const specPath = join(fixtureDir, "spec.json");
const spec = JSON.parse(readFileSync(specPath, "utf8"));

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
    observation("/bin/zsh -lc 'rg pattern . &'").project_code_execution_observed,
    true,
  );
  assert.equal(
    observation("/bin/zsh -lc 'rg pattern .|sed -n 1p'")
      .project_code_execution_observed,
    true,
  );
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
