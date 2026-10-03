import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import { canonicalJson } from "../src/ids";
import { compareUtf8, type JsonValue } from "../src/types";
import {
  NextBuildObserverError,
  buildNextObservedGraph,
  collectNextBuildObservation,
  type NextAdapterBuildContext,
  type NextBuildObservation,
  type NextObservedOutput,
} from "../src/next-build-observer";

type RawOutput = Record<string, unknown>;
const digest = (value: unknown): string => createHash("sha256").update(canonicalJson(value as JsonValue)).digest("hex");
const readArtifact = (): string => digest("artifact contents");

function request(type = "APP_PAGE", id = "/items/[id]", pathname = id): RawOutput {
  return {
    type, id, pathname, sourcePage: "/items/[id]/page", runtime: "nodejs", config: {},
    filePath: "/repo/.next/server/app/items/[id]/page.js", assets: {},
  };
}

function prerender(id = "/items/[id]", parentOutputId = "/items/[id]", pathname = id): RawOutput {
  return { type: "PRERENDER", id, pathname, parentOutputId, groupId: 1, config: {} };
}

function fixture() {
  const outputs = {
    pages: [] as RawOutput[], pagesApi: [] as RawOutput[], appPages: [] as RawOutput[],
    appRoutes: [] as RawOutput[], prerenders: [] as RawOutput[], staticFiles: [] as RawOutput[],
  };
  const context: NextAdapterBuildContext = {
    repoRoot: "/repo", projectDir: "/repo", distDir: "/repo/.next", nextVersion: "16.3.6", buildId: "build",
    config: { basePath: "" },
    routing: { beforeMiddleware: [], beforeFiles: [], afterFiles: [], dynamicRoutes: [], onMatch: [], fallback: [] },
    outputs,
  };
  return { context, outputs };
}

function graph(observation: NextBuildObservation) {
  return buildNextObservedGraph({ observation, baseNodes: [], provenance: {
    build_run_id: "run", profile_id: "profile", command_plan_digest: digest("plan"),
    toolchain_executable_digest: digest("node"), environment_key_set_digest: digest("environment"),
    validated_output_digest: digest("output"),
  } });
}

async function rejectsCollection(context: NextAdapterBuildContext, code: string) {
  await assert.rejects(collectNextBuildObservation(context, readArtifact), (error: unknown) => (
    error instanceof NextBuildObserverError && error.code === code
  ));
}

function rehashOutput(output: NextObservedOutput): void {
  const fields = [
    "type", "pathname", "source_page", "canonical_route_pattern", "variant", "artifact_role", "boundary",
    "metadata_kind", "runtime", "logical_artifact_path", "artifact_digest", "parent_output_identity_digest",
    "prerender_group_id", "edge_runtime",
  ] as const;
  output.output_identity_digest = digest(Object.fromEntries(fields.map((field) => [field, output[field]])));
}

function rehashManifest(observation: NextBuildObservation): void {
  observation.outputs.sort((left, right) => compareUtf8(canonicalJson(left as unknown as JsonValue), canonicalJson(right as unknown as JsonValue)));
  observation.manifests.build_manifest_digest = digest(observation.outputs);
  observation.manifests.output_entry_count = observation.outputs.length;
}

test("request and prerender route/RSC IDs remain distinct and raw self-IDs resolve to the primary request", async () => {
  const item = fixture();
  item.outputs.appPages = [request(), request("APP_PAGE", "/items/[id].rsc")];
  item.outputs.prerenders = [prerender(), prerender("/items/[id].rsc"), prerender("/items/one")];
  const observed = await collectNextBuildObservation(item.context, readArtifact);
  assert.equal(observed.outputs.length, 5);
  const parent = observed.outputs.find((output) => output.type === "APP_PAGE" && output.variant === "route")!;
  const children = observed.outputs.filter((output) => output.type === "PRERENDER");
  assert.equal(children.length, 3);
  assert.ok(children.every((child) => child.parent_output_identity_digest === parent.output_identity_digest));
  assert.ok(children.every((child) => child.output_identity_digest !== parent.output_identity_digest));
  assert.ok(graph(observed).edges.some((edge) => edge.kind === "parent_route"));
  item.outputs.appPages.reverse();
  item.outputs.prerenders.reverse();
  assert.deepEqual(await collectNextBuildObservation(item.context, readArtifact), observed);
});

test("Next Edge SSR Pages route/data clones may share a raw ID while prerenders select only the route", async () => {
  const item = fixture();
  const edge = request("PAGES", "/products");
  edge.runtime = "edge";
  edge.edgeRuntime = { modulePath: edge.filePath, entryKey: "middleware_pages/products", handlerExport: "handler" };
  item.outputs.pages = [edge, { ...edge, pathname: "/_next/data/build/products.json" }];
  item.outputs.prerenders = [prerender("/products", "/products")];
  const observed = await collectNextBuildObservation(item.context, readArtifact);
  assert.equal(observed.outputs.length, 3);
  const parent = observed.outputs.find((output) => output.type === "PAGES" && output.variant === "route")!;
  assert.ok(observed.outputs.some((output) => output.type === "PAGES" && output.variant === "data"));
  assert.equal(observed.outputs.find((output) => output.type === "PRERENDER")!.parent_output_identity_digest, parent.output_identity_digest);
  assert.doesNotThrow(() => graph(observed));
  item.outputs.pages.reverse();
  assert.deepEqual(await collectNextBuildObservation(item.context, readArtifact), observed);
});

test("duplicate IDs within one type and semantic variant fail closed even with differing content", async (t) => {
  for (const mode of ["route", "data", "prerender", "static"] as const) {
    await t.test(mode, async () => {
      const item = fixture();
      if (mode === "route") item.outputs.appPages = [request(), request("APP_PAGE", "/items/[id]", "/different")];
      if (mode === "data") item.outputs.pages = [
        request("PAGES", "shared", "/_next/data/build/one.json"), request("PAGES", "shared", "/_next/data/build/two.json"),
      ];
      if (mode === "prerender") { item.outputs.appPages = [request()]; item.outputs.prerenders = [prerender(), prerender()]; }
      if (mode === "static") item.outputs.staticFiles = [
        { type: "STATIC_FILE", id: "static", pathname: "/one", filePath: "/repo/.next/one.txt" },
        { type: "STATIC_FILE", id: "static", pathname: "/two", filePath: "/repo/.next/two.txt" },
      ];
      await rejectsCollection(item.context, "web.next_build_manifest_invalid");
    });
  }
});

test("missing, wrong-kind, variant-only and cyclic prerender parent references fail closed", async (t) => {
  for (const mode of ["missing", "static", "middleware", "rsc", "data", "self", "cycle"] as const) {
    await t.test(mode, async () => {
      const item = fixture();
      item.outputs.prerenders = [prerender("child", "parent", "/child")];
      if (mode === "static") item.outputs.staticFiles = [{ type: "STATIC_FILE", id: "parent", pathname: "/static", filePath: "/repo/.next/static.txt" }];
      if (mode === "middleware") item.context.outputs.middleware = request("MIDDLEWARE", "parent", "/_middleware");
      if (mode === "rsc") item.outputs.appPages = [request("APP_PAGE", "parent", "/items.rsc")];
      if (mode === "data") item.outputs.pages = [request("PAGES", "parent", "/_next/data/build/items.json")];
      if (mode === "self") item.outputs.prerenders = [prerender("parent", "parent", "/parent")];
      if (mode === "cycle") item.outputs.prerenders.push(prerender("parent", "child", "/parent"));
      await rejectsCollection(item.context, "web.next_build_partial_build");
    });
  }
});

test("ambiguous request parents across types fail closed without choosing a collection order", async () => {
  const item = fixture();
  item.outputs.pages = [request("PAGES", "shared", "/pages-route")];
  item.outputs.appPages = [request("APP_PAGE", "shared", "/app-route")];
  item.outputs.prerenders = [prerender("child", "shared", "/child")];
  await rejectsCollection(item.context, "web.next_build_manifest_invalid");
});

test("non-prerender raw parent or group metadata is invalid", async (t) => {
  for (const field of ["parentOutputId", "groupId"]) {
    await t.test(field, async () => {
      const item = fixture();
      item.outputs.appPages = [{ ...request(), [field]: field === "groupId" ? 1 : "parent" }];
      await rejectsCollection(item.context, "web.next_build_manifest_invalid");
    });
  }
});

test("rehashed observations still reject prerender references to non-primary outputs", async (t) => {
  for (const mode of ["prerender", "static", "middleware", "rsc", "data"] as const) {
    await t.test(mode, async () => {
      const item = fixture();
      item.outputs.appPages = [request(), request("APP_PAGE", "rsc", "/items.rsc")];
      item.outputs.pages = [request("PAGES", "data", "/_next/data/build/items.json")];
      item.outputs.prerenders = [prerender(), prerender("second", "/items/[id]", "/second")];
      item.outputs.staticFiles = [{ type: "STATIC_FILE", id: "static", pathname: "/static", filePath: "/repo/.next/static.txt" }];
      item.context.outputs.middleware = request("MIDDLEWARE", "middleware", "/_middleware");
      const observed = await collectNextBuildObservation(item.context, readArtifact);
      const child = observed.outputs.find((output) => output.type === "PRERENDER" && output.pathname === "/second")!;
      const target = observed.outputs.find((output) => (
        mode === "prerender" ? output.type === "PRERENDER" && output !== child
          : mode === "static" ? output.type === "STATIC_FILE"
            : mode === "middleware" ? output.type === "MIDDLEWARE" : output.variant === mode
      ))!;
      child.parent_output_identity_digest = target.output_identity_digest;
      rehashOutput(child);
      rehashManifest(observed);
      assert.throws(() => graph(observed), (error: unknown) => (
        error instanceof NextBuildObserverError && error.code === "web.next_build_observation_contract_invalid"
      ));
    });
  }
});

test("rehashed non-prerender observations cannot retain only parent or only group metadata", async (t) => {
  for (const field of ["parent_output_identity_digest", "prerender_group_id"] as const) {
    await t.test(field, async () => {
      const item = fixture();
      item.outputs.appPages = [request()];
      const observed = await collectNextBuildObservation(item.context, readArtifact);
      const output = observed.outputs[0]!;
      if (field === "parent_output_identity_digest") output.parent_output_identity_digest = output.output_identity_digest;
      else output.prerender_group_id = 1;
      rehashOutput(output);
      rehashManifest(observed);
      assert.throws(() => graph(observed), (error: unknown) => (
        error instanceof NextBuildObserverError && error.code === "web.next_build_observation_contract_invalid"
      ));
    });
  }
});
