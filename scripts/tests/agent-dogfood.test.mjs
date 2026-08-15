import assert from "node:assert/strict";
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
  scoreAnswer,
  traceMetrics,
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
        result: { content: "value" },
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
  assert.equal(metrics.tool_result_bytes, 3 + Buffer.byteLength('{"content":"value"}'));
  assert.equal(metrics.total_tokens, 120);
  assert.equal(metrics.effective_tokens, 60);
  assert.deepEqual(metrics.mcp_tools, ["get_context"]);
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

  const trace = join(copied, "baseline-1.trace.jsonl");
  rmSync(trace);
  symlinkSync(join(rawDir, "baseline-1.trace.jsonl"), trace);
  await assert.rejects(
    verifyReport({ specPath, rawDir: copied, report }),
    /unexpected entry/,
  );
});
