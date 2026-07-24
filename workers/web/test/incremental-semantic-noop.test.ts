import assert from "node:assert/strict";
import { test } from "node:test";
import {
  IncrementalFallbackError,
  parseWorkerDeltaRequest,
  semanticNoopDeltaEventsFor,
  type WorkerDeltaRequest,
} from "../src/incremental";
import { canonicalJson, contentHash, stableId } from "../src/ids";
import { analysisContentHash } from "../src/source-fingerprint";
import { ADAPTER, PROTOCOL_VERSION, type GraphNode, type JsonValue } from "../src/types";

const SOURCE_PATH = "src/index.ts";
const BASE_SOURCE = 'import { value } from "./value";\nconsole.log(value);\n';

function requestFor(source = BASE_SOURCE): WorkerDeltaRequest {
  const node: GraphNode = {
    id: stableId("file", { path: SOURCE_PATH }),
    kind: "file",
    locator: `file://${SOURCE_PATH}`,
    display_name: SOURCE_PATH,
    properties: {
      path: SOURCE_PATH,
      content_hash: contentHash(source),
      analysis_hash: analysisContentHash(source, SOURCE_PATH),
    },
  };
  const baseGraph = {
    profiles: ["web:production"],
    nodes: [node],
    sites: [],
    edges: [],
    evidence: [],
    coverage: [],
  };
  const digest = stableId("worker-graph", {
    schema: "worker-delta-v1",
    ...baseGraph,
  } as unknown as JsonValue).slice("worker-graph:sha256:".length);
  return {
    schema_version: "worker-delta-request-v1",
    protocol_version: PROTOCOL_VERSION,
    scan_id: "semantic-noop-test",
    adapter: ADAPTER,
    analysis_mode: "semantic_noop",
    base_snapshot_id: `snapshot:sha256:${"1".repeat(64)}`,
    base_graph_digest: digest,
    changes: [{ kind: "modified", new_path: SOURCE_PATH }],
    scope: {
      paths: [SOURCE_PATH],
      package_locators: [],
      profile_ids: ["web:production"],
      artifact_node_ids: [],
      adapters: [ADAPTER],
    },
    base_graph: baseGraph,
  };
}

test("semantic no-op delta updates only the changed file fingerprint", () => {
  const request = parseWorkerDeltaRequest(requestFor(), "semantic-noop-test");
  const nextSource = `${BASE_SOURCE}// benchmark revision 1\n`;
  const events = semanticNoopDeltaEventsFor(nextSource, request);

  assert.deepEqual(events.map((event) => event.event), [
    "delta_started",
    "delta_node_upsert",
    "delta_completed",
  ]);
  assert.equal(events[1]?.node !== null && typeof events[1]?.node === "object", true);
  const node = events[1]?.node as unknown as GraphNode;
  assert.equal(node.properties.content_hash, contentHash(nextSource));
  assert.equal(node.properties.analysis_hash, analysisContentHash(BASE_SOURCE, SOURCE_PATH));
  assert.equal(events[2]?.mutation_count, 1);
  assert.notEqual(events[2]?.result_graph_digest, request.base_graph_digest);
});

test("semantic dependency changes request a complete analysis fallback", () => {
  assert.throws(
    () => semanticNoopDeltaEventsFor(
      'import { value } from "./other";\nconsole.log(value);\n',
      requestFor(),
    ),
    IncrementalFallbackError,
  );
});

test("delta request parser defaults legacy requests and rejects unknown analysis modes", () => {
  const missing = JSON.parse(canonicalJson(requestFor() as unknown as JsonValue)) as Record<string, unknown>;
  delete missing.analysis_mode;
  assert.equal(
    parseWorkerDeltaRequest(missing, "semantic-noop-test").analysis_mode,
    "complete",
  );

  assert.throws(
    () => parseWorkerDeltaRequest(
      { ...requestFor(), analysis_mode: "future-mode" },
      "semantic-noop-test",
    ),
    /analysis mode is unsupported/u,
  );
});
