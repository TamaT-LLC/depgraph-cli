import assert from "node:assert/strict";

const appPath = "frontend/apps/web/src/index.ts";
const sharedPath = "frontend/packages/shared/src/index.ts";
const extraPath = "frontend/apps/web/src/extra.ts";

function evidenceRecord({ owner_type, owner_id, ordinal, evidence }) {
  return {
    owner_type, owner_id, ordinal,
    kind: evidence.kind,
    extractor: evidence.extractor,
    extractor_version: evidence.extractor_version,
    path: evidence.path,
    start_line: evidence.start_line ?? null,
    start_column: evidence.start_column ?? null,
    end_line: evidence.end_line ?? null,
    end_column: evidence.end_column ?? null,
    detail: evidence.detail ?? null,
    properties: evidence.properties ?? {},
  };
}

/** Assert graph direction and exact stored provenance at the public CLI boundary. */
export function assertWorkspaceQuery(command, data, expected) {
  const file = (relative) => {
    const node = expected.nodes.find((node) => node.kind === "file" && node.properties.path === relative);
    assert.ok(node, `fixture file ${relative} is missing`);
    return node;
  };
  const app = file(appPath);
  const shared = file(sharedPath);
  const extra = file(extraPath);
  const profileIds = new Set(expected.profiles.map((profile) => profile.id));
  const storedEdges = new Map(expected.edges.map((edge) => [edge.id, edge]));
  const direct = expected.edges.find((edge) => (
    edge.source === app.id && edge.target === shared.id
      && edge.kind === "imports" && edge.phase === "source"
  ));
  assert.ok(direct, "fixture has no direct app-to-shared import");
  const checkStep = (step) => {
    const stored = storedEdges.get(step.edge.id);
    assert.ok(stored, `${command} returned an edge outside the stored graph`);
    const { evidence: _evidence, ...payload } = stored;
    payload.site_id ??= null;
    assert.deepEqual(step.edge, payload, `${command} changed an edge, profile, or condition`);
    assert.ok(profileIds.has(step.edge.profile_id), `${command} returned an unknown profile`);
    const evidence = expected.evidence
      .filter((record) => record.owner_type === "edge" && record.owner_id === step.edge.id)
      .map(evidenceRecord);
    assert.deepEqual(step.evidence, evidence, `${command} changed edge evidence`);
  };
  const checkPath = (steps, from, to) => {
    let current = from;
    for (const step of steps) {
      checkStep(step);
      assert.equal(step.edge.source, current, `${command} returned a discontinuous dependency path`);
      current = step.edge.target;
    }
    assert.equal(current, to, `${command} returned a path in the wrong direction`);
  };

  if (command === "why") {
    assert.deepEqual(data.from, app);
    assert.deepEqual(data.to, shared);
    assert.equal(data.path_found, true);
    assert.equal(data.steps.length, 1);
    assert.equal(data.steps[0].edge.id, direct.id);
    checkPath(data.steps, app.id, shared.id);
    assert.equal(data.steps[0].evidence[0].path, appPath);
    assert.equal(data.steps[0].evidence[0].start_line, 1);
    return;
  }
  assert.deepEqual(data.root, command === "deps" ? app : shared);
  if (command === "impact") {
    assert.equal(data.complete, true);
    assert.deepEqual(data.changed_nodes, [shared]);
    for (const [node, depth] of [[app, 1], [extra, 2]]) {
      const impact = data.impacts.find((impact) => impact.node.id === node.id);
      assert.ok(impact, `impact omitted ${node.properties.path}`);
      assert.equal(impact.depth, depth);
      assert.equal(impact.changed_node_id, shared.id);
      assert.equal(impact.dependency_path.length, depth);
      checkPath(impact.dependency_path, node.id, shared.id);
    }
    return;
  }
  assert.ok(["deps", "dependents"].includes(command));
  assert.ok(data.edges.some((edge) => edge.id === direct.id));
  assert.ok(data.nodes.some((node) => node.id === (command === "deps" ? shared.id : app.id)));
  assert.ok(data.nodes.some((node) => node.id === extra.id), `${command} lost the cycle/transitive file`);
  assert.deepEqual(data.steps.map((step) => step.edge.id).sort(), data.edges.map((edge) => edge.id).sort());
  for (const step of data.steps) checkStep(step);
  const reachable = new Set([data.root.id]);
  for (let previous = -1; previous !== reachable.size;) {
    previous = reachable.size;
    for (const edge of data.edges) {
      const [from, to] = command === "deps" ? [edge.source, edge.target] : [edge.target, edge.source];
      if (reachable.has(from)) reachable.add(to);
    }
  }
  for (const node of data.nodes) {
    assert.ok(reachable.has(node.id), `${command} included an unreachable node`);
  }
}
