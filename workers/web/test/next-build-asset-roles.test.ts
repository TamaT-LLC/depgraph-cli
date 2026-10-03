import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import {
  buildNextObservedGraph,
  collectNextBuildObservation,
  type NextAdapterBuildContext,
  type NextBuildObservation,
} from "../src/next-build-observer";

const shared = ".next/server/middleware-build-manifest.js";
const unrelated = ".next/server/other-manifest.js";
const digest = (value: string): string => createHash("sha256").update(value).digest("hex");

function fixture() {
  const server = (id: string) => ({
    id, type: "APP_ROUTE", pathname: `/${id}`, sourcePage: `${id}/route`, runtime: "nodejs", config: {},
    filePath: `/repo/.next/server/app/${id}/route.js`, assets: { [shared]: `/repo/${shared}` },
  });
  const edgePath = "/repo/.next/server/edge/route.js";
  const serverOne = server("one");
  const serverTwo = server("two");
  const edge = {
    id: "edge", type: "APP_ROUTE", pathname: "/edge", sourcePage: "edge/route", runtime: "edge", config: {},
    filePath: edgePath,
    assets: { "server/middleware-build-manifest.js": `/repo/${shared}`, "server/other-manifest.js": `/repo/${unrelated}` },
    edgeRuntime: { modulePath: edgePath, entryKey: "middleware_app/edge/route", handlerExport: "handler" },
  };
  const appRoutes = [serverOne, serverTwo, edge];
  const context: NextAdapterBuildContext = {
    repoRoot: "/repo", projectDir: "/repo", distDir: "/repo/.next", nextVersion: "16.3.6", buildId: "build",
    config: { basePath: "" },
    routing: { beforeMiddleware: [], beforeFiles: [], afterFiles: [], dynamicRoutes: [], onMatch: [], fallback: [] },
    outputs: { pages: [], pagesApi: [], appPages: [], appRoutes, prerenders: [], staticFiles: [] },
  };
  return { context, appRoutes };
}

function graph(observation: NextBuildObservation) {
  return buildNextObservedGraph({ observation, baseNodes: [], provenance: {
    build_run_id: "run", profile_id: "profile", command_plan_digest: digest("plan"),
    toolchain_executable_digest: digest("node"), environment_key_set_digest: digest("environment"),
    validated_output_digest: digest("output"),
  } });
}

test("shared server/edge manifest bytes retain distinct role identities and all load relations", async () => {
  const item = fixture();
  const observed = await collectNextBuildObservation(item.context, () => digest("identical bytes"));
  const result = graph(observed);
  const sharedNodes = result.nodes.filter((node) => node.properties.logical_path === shared);
  assert.equal(sharedNodes.length, 2);
  assert.deepEqual(sharedNodes.map((node) => node.properties.asset_role).sort(), ["edge_asset", "traced_asset"]);
  const serverNode = sharedNodes.find((node) => node.properties.asset_role === "traced_asset")!;
  const edgeNode = sharedNodes.find((node) => node.properties.asset_role === "edge_asset")!;
  assert.notEqual(serverNode.id, edgeNode.id);
  assert.equal(serverNode.properties.artifact_digest, edgeNode.properties.artifact_digest);
  const serverLoads = result.edges.filter((edge) => edge.kind === "loads" && edge.target === serverNode.id);
  const edgeLoads = result.edges.filter((edge) => edge.kind === "loads" && edge.target === edgeNode.id);
  assert.equal(serverLoads.length, 2);
  assert.equal(edgeLoads.length, 1);
  assert.ok(serverLoads.every((edge) => edge.environment === "server"));
  assert.equal(edgeLoads[0]!.environment, "edge");
  assert.ok(JSON.stringify(serverLoads).includes("traced_asset"));
  assert.ok(JSON.stringify(edgeLoads).includes("edge_asset"));
  const unrelatedNodes = result.nodes.filter((node) => node.properties.logical_path === unrelated);
  assert.equal(unrelatedNodes.length, 1);
  assert.equal(unrelatedNodes[0]!.properties.asset_role, "edge_asset");
  assert.notEqual(unrelatedNodes[0]!.id, edgeNode.id);
  item.appRoutes.reverse();
  const reordered = await collectNextBuildObservation(item.context, () => digest("identical bytes"));
  assert.deepEqual(reordered, observed);
  assert.deepEqual(graph(reordered), result);
  assert.deepEqual(graph(observed), result);
});
