import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";
import { promisify } from "node:util";
import {
  NEXT_BUILD_OBSERVER,
  NEXT_BUILD_OBSERVER_CAPABILITY,
  NEXT_BUILD_OBSERVER_VERSION,
  NextBuildObserverError,
  buildNextObservedGraph,
  collectNextBuildObservation,
  composeNextBuildObserver,
  detectNextAdapterCapability,
  nextBuildProtocolEvents,
  nextBuildFailureDiagnostic,
  preflightNextBuildObserver,
  type NextAdapterBuildContext,
  type NextBuildObservation,
  type NextBuildProvenance,
} from "../src/next-build-observer";
import { stableId } from "../src/ids";
import { canonicalizeCondition, type GraphEdge, type GraphNode, type JsonValue } from "../src/types";

const digest = (character: string): string => character.repeat(64);
const execute = promisify(execFile);

function buildContext(overrides: Partial<NextAdapterBuildContext> = {}): NextAdapterBuildContext {
  return {
    nextVersion: "16.2.9",
    buildId: "private-build-id",
    projectDir: "/repo/apps/site",
    repoRoot: "/repo",
    distDir: "/repo/apps/site/.next",
    config: {
      output: "standalone",
      basePath: "/docs",
      trailingSlash: true,
      reactStrictMode: true,
      adapterPath: "/trusted/depgraph-next-adapter.mjs",
      env: { PRIVATE_TOKEN: "must-not-be-persisted" },
      webpack() { throw new Error("config function must not be inspected"); },
    },
    routing: {
      beforeMiddleware: [],
      beforeFiles: [{
        source: "/legacy", sourceRegex: "^/legacy$", destination: "/docs", status: 307,
        headers: { authorization: "must-not-be-persisted" },
      }],
      afterFiles: [],
      dynamicRoutes: [],
      onMatch: [],
      fallback: [],
      shouldNormalizeNextData: false,
      rsc: { header: "must-not-be-persisted" },
    },
    outputs: {
      pages: [],
      pagesApi: [],
      appPages: [{
        id: "private-output-id",
        type: "APP_PAGE",
        pathname: "/docs/products/[id]",
        sourcePage: "/products/[id]",
        filePath: "/repo/apps/site/.next/server/app/products/[id]/page.js",
        runtime: "nodejs",
        assets: {
          "apps/site/.next/server/chunks/shared.js": "/repo/apps/site/.next/server/chunks/shared.js",
        },
        wasmAssets: {},
        config: {
          maxDuration: 15,
          preferredRegion: ["iad1", "hnd1"],
          env: { API_SECRET: "must-not-be-persisted" },
        },
      }],
      appRoutes: [],
      prerenders: [],
      staticFiles: [],
    },
    ...overrides,
  };
}

async function observation(): Promise<NextBuildObservation> {
  return collectNextBuildObservation(buildContext(), (_absolutePath, logicalPath) => (
    logicalPath.endsWith("shared.js") ? digest("b") : digest("a")
  ));
}

const provenance: NextBuildProvenance = {
  build_run_id: "next-build-run-1",
  profile_id: "web:next:production",
  command_plan_digest: digest("c"),
  toolchain_executable_digest: digest("d"),
  environment_key_set_digest: digest("e"),
  validated_output_digest: digest("f"),
};

function baseRoute(idSuffix = "one", runtime: string = "nodejs"): GraphNode {
  const identity: Record<string, JsonValue> = {
    framework: "next",
    package_locator: "npm:workspace:site@1.0.0#apps/site",
    route_kind: "next-app-page",
    environment: "server",
    router_instance: "next:npm:workspace:site@1.0.0#apps/site:app",
    route_pattern: "/docs/products/[id]",
    discriminator: idSuffix,
  };
  const id = stableId("route", identity);
  return {
    id,
    kind: "route",
    locator: `route://next/${id}`,
    display_name: "/docs/products/[id]",
    properties: {
      framework: "next",
      route_pattern: "/docs/products/[id]",
      source_path: "apps/site/src/app/products/[id]/page.tsx",
      runtime,
      canonical_identity: identity,
    },
  };
}

function sourceRoute(): GraphNode {
  return {
    id: "route:source-next-products",
    kind: "route",
    locator: "route://next/site/docs/products/[id]",
    display_name: "next:/docs/products/[id]",
    properties: {
      framework: "next",
      pattern: "/docs/products/[id]",
      router_instance: "package:site",
      package_id: "package:site",
      environment: "server",
    },
  };
}

function pageComponent(): GraphNode {
  return {
    id: "component:next-products-page",
    kind: "component",
    locator: "component://next/products-page",
    display_name: "ProductsPage",
    properties: {
      framework: "next",
      component_kind: "next-app-page",
      source_path: "apps/site/src/app/products/[id]/page.tsx",
      environment: "server",
    },
  };
}

function renderEdge(route: GraphNode, component: GraphNode): GraphEdge {
  return {
    id: "edge:next-products-render",
    source: route.id,
    target: component.id,
    kind: "renders",
    site_id: "site:next-products-render",
    phase: "semantic",
    environment: "server",
    profile_id: "profile:safe",
    condition: canonicalizeCondition({ op: "all", conditions: [] }),
    resolution_status: "resolved",
    precision: "exact",
    generated: false,
    evidence: [],
  };
}

test("Next Adapter API capability is pinned to stable Next 16.2.x and later 16.x", () => {
  assert.deepEqual(detectNextAdapterCapability("16.2.0"), {
    capability: "next-adapter-api-16.2-v1",
    nextVersion: "16.2.0",
    existingAdapter: "absent",
  });
  assert.equal(detectNextAdapterCapability("16.9.3").capability, NEXT_BUILD_OBSERVER_CAPABILITY);
  for (const version of ["16.1.9", "16.2.0-canary.1", "17.0.0", "latest", "16.2"]) {
    assert.throws(
      () => detectNextAdapterCapability(version),
      (error: unknown) => error instanceof NextBuildObserverError
        && error.code === "web.next_build_version_unsupported",
      version,
    );
  }
});

test("preflight chains an existing adapter without replacement and preserves hook ordering", async () => {
  const calls: string[] = [];
  let captured: NextBuildObservation | null = null;
  const preflight = await preflightNextBuildObserver({
    nextVersion: "16.2.9",
    configuredAdapterPath: "existing-platform-adapter",
    observerAdapterPath: "depgraph-next-adapter",
    loadExistingAdapter: async (specifier) => {
      assert.equal(specifier, "existing-platform-adapter");
      calls.push("load");
      return {
        default: {
          name: "platform",
          modifyConfig(config: Record<string, unknown>) {
            calls.push("existing:modify");
            return { ...config, trailingSlash: true };
          },
          onBuildComplete() {
            calls.push("existing:complete");
          },
        },
      };
    },
    sink: {
      write(value) {
        calls.push("observer:write");
        captured = value;
      },
    },
    readArtifact: () => digest("a"),
  });
  assert.equal(preflight.capability.existingAdapter, "chainable");
  assert.equal(preflight.adapter.name, `${NEXT_BUILD_OBSERVER}+platform`);
  const context = buildContext();
  const modified = await preflight.adapter.modifyConfig!(context.config, {
    phase: "phase-production-build",
    nextVersion: "16.2.9",
  });
  assert.equal(modified.trailingSlash, true);
  await preflight.adapter.onBuildComplete!({ ...context, config: modified });
  assert.deepEqual(calls, ["load", "existing:modify", "existing:complete", "observer:write"]);
  assert.ok(captured !== null);
});

test("chain preflight fails closed before a caller can start the project build", async () => {
  let buildStarted = false;
  await assert.rejects(
    async () => {
      await preflightNextBuildObserver({
        nextVersion: "16.2.9",
        configuredAdapterPath: "existing-platform-adapter",
        observerAdapterPath: "depgraph-next-adapter",
        loadExistingAdapter: async () => ({ name: "invalid", onBuildComplete: "not-a-function" }),
        sink: { write() {} },
      });
      buildStarted = true;
    },
    (error: unknown) => error instanceof NextBuildObserverError
      && error.code === "web.next_build_existing_adapter_invalid",
  );
  assert.equal(buildStarted, false);

  await assert.rejects(
    preflightNextBuildObserver({
      nextVersion: "16.2.9",
      configuredAdapterPath: "existing-platform-adapter",
      observerAdapterPath: "depgraph-next-adapter",
      sink: { write() {} },
    }),
    (error: unknown) => error instanceof NextBuildObserverError
      && error.code === "web.next_build_existing_adapter_chain_unavailable",
  );

  await assert.rejects(
    preflightNextBuildObserver({
      nextVersion: "16.2.9",
      configuredAdapterPath: "hostile-platform-adapter",
      observerAdapterPath: "depgraph-next-adapter",
      loadExistingAdapter: async () => new Proxy({}, {
        get(_target, property) {
          if (property === "then") return undefined;
          throw new Error("PRIVATE_TOKEN=raw-secret");
        },
      }),
      sink: { write() {} },
    }),
    (error: unknown) => error instanceof NextBuildObserverError
      && error.code === "web.next_build_existing_adapter_invalid"
      && !error.message.includes("raw-secret"),
  );
});

test("adapter and observer crashes are normalized without preserving raw error text", async () => {
  const context = buildContext();
  const existingCrash = composeNextBuildObserver({
    name: "platform",
    onBuildComplete() { throw new Error("PRIVATE_TOKEN=raw-secret"); },
  }, { write() {} }, () => digest("a"));
  await assert.rejects(
    async () => existingCrash.onBuildComplete!(context),
    (error: unknown) => error instanceof NextBuildObserverError
      && error.message === "web.next_build_existing_adapter_complete_failed"
      && !error.message.includes("raw-secret"),
  );

  const sinkCrash = composeNextBuildObserver(null, {
    write() { throw new Error("SESSION_COOKIE=raw-secret"); },
  }, () => digest("a"));
  await assert.rejects(
    async () => sinkCrash.onBuildComplete!(context),
    (error: unknown) => error instanceof NextBuildObserverError
      && error.message === "web.next_build_observer_sink_failed"
      && !error.message.includes("raw-secret"),
  );

  const diagnostic = nextBuildFailureDiagnostic(
    new Error("SESSION_COOKIE=raw-secret"),
    provenance.profile_id,
  );
  assert.equal(diagnostic.code, "web.next_build_observer_failed");
  assert.equal(JSON.stringify(diagnostic).includes("raw-secret"), false);
  const unsupported = nextBuildFailureDiagnostic(
    new NextBuildObserverError("web.next_build_version_unsupported"),
    provenance.profile_id,
  );
  assert.equal(unsupported.code, "web.next_build_version_unsupported");
});

test("observer keeps only allowlisted final config, route, runtime, output, and asset metadata", async () => {
  const observed = await observation();
  assert.equal(observed.schema_version, "next-build-observation-v1");
  assert.equal(observed.next_version, "16.2.9");
  assert.equal(observed.config.output, "standalone");
  assert.equal(observed.config.environment_key_count, 1);
  assert.equal(observed.routing[0]?.phase, "beforeFiles");
  assert.deepEqual(observed.routing[0], {
    phase: "beforeFiles",
    source: "/legacy",
    source_regex_digest: "ef35ea91a1ad1227dafb8d0e04809cba01c3260b4e15d7487e8072a9dbf6b717",
    destination: "/docs",
    source_present: true,
    destination_present: true,
    status: 307,
    priority: false,
    header_count: 1,
    predicate_count: 0,
  });
  assert.equal(observed.outputs[0]?.runtime, "nodejs");
  assert.equal(observed.outputs[0]?.logical_artifact_path, "apps/site/.next/server/app/products/[id]/page.js");
  assert.equal(observed.outputs[0]?.assets[0]?.logical_path, "apps/site/.next/server/chunks/shared.js");
  assert.equal(observed.outputs[0]?.config.environment_key_count, 1);
  const encoded = JSON.stringify(observed);
  for (const forbidden of [
    "private-build-id", "private-output-id", "must-not-be-persisted", "PRIVATE_TOKEN",
    "API_SECRET", "authorization", "/repo/", "sourceRegex", "webpack",
  ]) {
    assert.equal(encoded.includes(forbidden), false, forbidden);
  }
});

test("prerenders without a fallback artifact use deterministic synthetic metadata", async () => {
  const context = buildContext();
  context.outputs.appPages = [];
  context.outputs.prerenders = [{
    id: "private-prerender-output-id",
    type: "PRERENDER",
    pathname: "/docs/prerendered",
    config: {},
  }];
  let artifactReads = 0;
  const observed = await collectNextBuildObservation(context, () => {
    artifactReads += 1;
    return digest("a");
  });

  assert.equal(artifactReads, 0);
  assert.equal(observed.outputs.length, 1);
  assert.match(observed.outputs[0]!.logical_artifact_path, /^\.next\/observed\/[a-f0-9]{64}\.metadata$/u);
  assert.match(observed.outputs[0]!.artifact_digest, /^[a-f0-9]{64}$/u);
  assert.equal(JSON.stringify(observed).includes("private-prerender-output-id"), false);
});

test("unsafe artifact paths and unsupported output contracts fail without a partial observation", async () => {
  const escaped = buildContext();
  (escaped.outputs.appPages as Array<Record<string, unknown>>)[0]!.filePath = "/outside/page.js";
  await assert.rejects(
    collectNextBuildObservation(escaped, () => digest("a")),
    (error: unknown) => error instanceof NextBuildObserverError
      && error.code === "web.next_build_artifact_path_unsafe",
  );

  const unsupported = buildContext({ nextVersion: "17.0.0" });
  await assert.rejects(
    collectNextBuildObservation(unsupported, () => digest("a")),
    (error: unknown) => error instanceof NextBuildObserverError
      && error.code === "web.next_build_version_unsupported",
  );

  const mismatchedAsset = buildContext();
  (mismatchedAsset.outputs.appPages as Array<Record<string, unknown>>)[0]!.assets = {
    "C:\\private\\secret.js": "/repo/apps/site/.next/server/chunks/shared.js",
  };
  await assert.rejects(
    collectNextBuildObservation(mismatchedAsset, () => digest("a")),
    (error: unknown) => error instanceof NextBuildObserverError
      && error.code === "web.next_build_artifact_path_unsafe",
  );
});

test("observed outputs correlate to canonical safe routes and become deterministic build evidence", async () => {
  const observed = await observation();
  const route = baseRoute();
  const first = buildNextObservedGraph({ observation: observed, provenance, baseNodes: [route] });
  const second = buildNextObservedGraph({ observation: observed, provenance, baseNodes: [route] });
  assert.deepEqual(first, second);
  assert.ok(first.nodes.some((node) => node.id === route.id));
  assert.ok(first.nodes.some((node) => node.kind === "file" && node.properties.artifact_kind === "APP_PAGE"));
  assert.ok(first.nodes.some((node) => node.kind === "file" && node.properties.artifact_kind === "asset"));
  assert.ok(first.edges.some((edge) => edge.source === route.id && edge.kind === "emits"));
  assert.ok(first.edges.some((edge) => edge.kind === "loads"));
  assert.ok(first.edges.some((edge) => edge.kind === "routes_in_phase"));
  assert.ok(first.edges.every((edge) => edge.phase === "build" && edge.precision === "observed"));
  assert.ok(first.sites.every((site) => site.precision === "observed"));
  assert.ok(first.sites.every((site) => site.evidence[0]?.kind === "build"));
  assert.ok(first.sites.every((site) => site.evidence[0]?.properties?.build_run_id === provenance.build_run_id));
  assert.equal(first.diagnostics.length, 0);

  const semanticPreferred = buildNextObservedGraph({
    observation: observed,
    provenance,
    baseNodes: [sourceRoute(), route, pageComponent()],
    baseEdges: [renderEdge(route, pageComponent())],
  });
  assert.ok(semanticPreferred.edges.some((edge) => edge.kind === "emits" && edge.source === route.id));
  assert.ok(semanticPreferred.edges.some((edge) => edge.kind === "emits" && edge.source === pageComponent().id));
  assert.equal(semanticPreferred.diagnostics.some((item) => item.code === "web.next_build_route_conflict"), false);

  const sourceFallback = buildNextObservedGraph({
    observation: observed,
    provenance,
    baseNodes: [sourceRoute()],
  });
  assert.ok(sourceFallback.edges.some((edge) => edge.kind === "emits" && edge.source === sourceRoute().id));
  assert.equal(sourceFallback.diagnostics.some((item) => item.code === "web.next_build_route_static_missing"), false);

  const sourcePageObservation = await observation();
  sourcePageObservation.outputs[0]!.pathname = "/docs/rendered-products/[id]";
  const sourcePageFallback = buildNextObservedGraph({
    observation: sourcePageObservation,
    provenance,
    baseNodes: [route],
  });
  assert.ok(sourcePageFallback.edges.some((edge) => edge.kind === "emits" && edge.source === route.id));
  assert.equal(sourcePageFallback.diagnostics.some((item) => item.code === "web.next_build_route_static_missing"), false);

  const events = nextBuildProtocolEvents("/repo", first, provenance, "revision-1");
  assert.equal(events[0]?.event, "scan_started");
  assert.equal(events.at(-1)?.event, "scan_completed");
  const declared = events.find((value) => value.event === "profile_declared") as Record<string, unknown>;
  assert.equal((declared.profile as Record<string, unknown>).toolchain, "next 16.2.9");
  assert.equal((events.at(-1) as Record<string, unknown>).coverage instanceof Object, true);
  assert.equal(JSON.stringify(events).includes("must-not-be-persisted"), false);
});

test("static ambiguity and runtime drift retain observed evidence with bounded diagnostics", async () => {
  const observed = await observation();
  const conflict = buildNextObservedGraph({
    observation: observed,
    provenance,
    baseNodes: [baseRoute("one"), baseRoute("two")],
  });
  assert.ok(conflict.diagnostics.some((item) => item.code === "web.next_build_route_conflict"));
  assert.ok(conflict.nodes.some((node) => node.kind === "route" && node.properties.observed_only === true));

  const drift = buildNextObservedGraph({
    observation: observed,
    provenance,
    baseNodes: [baseRoute("one", "edge")],
  });
  const runtime = drift.diagnostics.find((item) => item.code === "web.next_build_runtime_drift");
  assert.deepEqual(runtime?.properties, {
    capability: NEXT_BUILD_OBSERVER_CAPABILITY,
    contract_version: "framework-build-graph-v1",
    declared_runtime: "edge",
    framework: "next",
    observed_runtime: "nodejs",
    route_id: baseRoute("one", "edge").id,
  });
  assert.equal(JSON.stringify(drift).includes("private-build-id"), false);
});

test("same-source conditional routing entries remain distinct while exact duplicates deduplicate", async () => {
  const observed = await observation();
  const first = observed.routing[0]!;
  const second = {
    ...first,
    destination: "/docs/conditional",
    predicate_count: 1,
  };
  observed.routing = [first, second, { ...first }];

  const graph = buildNextObservedGraph({ observation: observed, provenance, baseNodes: [] });
  const routes = graph.nodes.filter((node) => (
    node.kind === "route" && node.properties.routing_phase === "beforeFiles"
  ));
  assert.equal(routes.length, 2);
  assert.equal(new Set(routes.map((node) => node.id)).size, 2);
  assert.deepEqual(
    routes.map((node) => node.properties.destination).sort(),
    ["/docs", "/docs/conditional"],
  );
  assert.equal(graph.edges.filter((edge) => edge.kind === "routes_in_phase").length, 2);
});

test("observer identity remains aligned across build evidence and adapter metadata", () => {
  assert.equal(NEXT_BUILD_OBSERVER, "next-adapter-observer");
  assert.equal(NEXT_BUILD_OBSERVER_VERSION, "0.1.0");
});

test("bundled Next adapter writes one confined sanitized observation artifact", async (context) => {
  const temporary = await mkdtemp(path.join(tmpdir(), "depgraph-next-observer-"));
  context.after(async () => rm(temporary, { recursive: true, force: true }));
  const repository = path.join(temporary, "repo");
  const outputRoot = path.join(temporary, "observer-output");
  const artifact = path.join(repository, ".next", "server", "app", "page.js");
  await mkdir(path.dirname(artifact), { recursive: true });
  await mkdir(outputRoot, { recursive: true });
  await writeFile(path.join(repository, "package.json"), "{\"private\":true}\n", "utf8");
  await writeFile(artifact, "export default 'PRIVATE_TOKEN is artifact content only';\n", "utf8");
  const adapterUrl = pathToFileURL(fileURLToPath(new URL("../dist/next-build-adapter.mjs", import.meta.url))).href;
  const script = `
    const adapter = (await import(${JSON.stringify(adapterUrl)})).default;
    const config = await adapter.modifyConfig({ basePath: "", env: { PRIVATE_TOKEN: "raw-secret" } }, {
      phase: "phase-production-build", nextVersion: "16.2.9"
    });
    await adapter.onBuildComplete({
      nextVersion: "16.2.9", buildId: "private-build-id",
      projectDir: ${JSON.stringify(repository)}, repoRoot: ${JSON.stringify(repository)},
      distDir: ${JSON.stringify(path.join(repository, ".next"))}, config,
      routing: {
        beforeMiddleware: [], beforeFiles: [], afterFiles: [], dynamicRoutes: [], onMatch: [], fallback: [],
        shouldNormalizeNextData: false, rsc: {}
      },
      outputs: {
        pages: [], pagesApi: [], appPages: [{
          id: "private-output-id", type: "APP_PAGE", pathname: "/", sourcePage: "/",
          runtime: "nodejs", filePath: ${JSON.stringify(artifact)}, assets: {}, wasmAssets: {}, config: {}
        }], appRoutes: [], prerenders: [], staticFiles: []
      }
    });
  `;
  await execute(process.execPath, ["--input-type=module", "--eval", script], {
    cwd: repository,
    env: {
      DEPGRAPH_OUTPUT_DIR: outputRoot,
      ...(process.platform === "win32" && process.env.SystemRoot ? { SystemRoot: process.env.SystemRoot } : {}),
    },
    timeout: 10_000,
  });
  const encoded = await readFile(path.join(outputRoot, "next-build-observation.json"), "utf8");
  const observed = JSON.parse(encoded) as NextBuildObservation;
  assert.equal(observed.observer, NEXT_BUILD_OBSERVER);
  assert.equal(observed.outputs[0]?.logical_artifact_path, ".next/server/app/page.js");
  assert.match(observed.outputs[0]?.artifact_digest ?? "", /^[a-f0-9]{64}$/u);
  for (const forbidden of ["raw-secret", "PRIVATE_TOKEN", "private-build-id", "private-output-id", temporary]) {
    assert.equal(encoded.includes(forbidden), false, forbidden);
  }
});
