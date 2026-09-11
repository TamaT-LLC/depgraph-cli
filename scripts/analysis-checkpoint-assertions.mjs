// Assertions for fresh, private stores owned by the real-worker E2E fixtures.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import path from "node:path";

export function checkpointedUnitIds(store) {
  const identity = createHash("sha256").update(path.basename(store)).digest("hex");
  const directory = path.join(path.dirname(store), ".depgraph", "analysis-checkpoints-v1", identity);
  const ids = new Set();
  for (const file of readdirSync(directory)) {
    if (!file.endsWith(".json") || file.startsWith("refinements-")) continue;
    const checkpoint = JSON.parse(readFileSync(path.join(directory, file), "utf8"));
    assert.equal(checkpoint.contract, "depgraph-analysis-checkpoint-v1");
    ids.add(checkpoint.key.unit_id);
  }
  return ids;
}

const activeUnits = (scan) => scan.analysis.units.filter((unit) => unit.loader?.analysis_resplit !== "superseded");
const owner = (unit) => unit.unit_id.split(`:${unit.stage}:`)[0];

// A typed refinement can leave already-completed semantic work without a
// complete reference binding. Such work must run once after types recover;
// every checkpoint that was valid at the prior boundary must still be reused.
export function assertValidCheckpointReuse(previous, resumed, checkpointed) {
  assert.equal(previous.analysis_coverage.complete, true);
  assert.equal(resumed.analysis_coverage.complete, true);
  const prior = activeUnits(previous);
  const next = new Map(activeUnits(resumed).map((unit) => [unit.unit_id, unit]));
  assert.deepEqual([...next.keys()].sort(), prior.map((unit) => unit.unit_id).sort(), "resume changed the refined execution units");
  const refinedTypedOwners = new Set(previous.analysis.units
    .filter((unit) => unit.stage === "typed" && unit.status === "failed" && unit.loader?.analysis_resplit === "superseded")
    .map(owner));
  let semanticReplays = 0;
  for (const unit of prior) {
    assert.equal(unit.status, "completed");
    const result = next.get(unit.unit_id);
    assert.equal(result.status, "completed");
    if (checkpointed.has(unit.unit_id)) {
      assert.ok(result.reused, `valid checkpoint ${unit.unit_id} re-ran`);
    } else {
      assert.equal(unit.stage, "semantic", `completed ${unit.stage} unit has no checkpoint`);
      assert.ok(refinedTypedOwners.has(owner(unit)), "semantic checkpoint was missing without typed refinement");
      assert.equal(result.reused, false, "unbound semantic work was reused");
      semanticReplays++;
    }
  }
  return semanticReplays;
}
