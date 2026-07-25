import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { pathToFileURL } from "node:url";
import { stableId } from "../src/ids";
import {
  TANSTACK_START_BUILD_CAPABILITY,
  TANSTACK_START_BUILD_OBSERVER,
  TANSTACK_START_BUILD_OBSERVER_VERSION,
  TanStackStartBuildObserverError,
  buildTanStackStartObservedGraph,
  createTanStackStartBuildObserverPlugin,
  detectTanStackStartBuildCapability,
  tanStackStartBuildFailureDiagnostic,
  tanStackStartBuildProtocolEvents,
  validateTanStackStartBuildObservation,
  type TanStackStartBuildObservation,
  type TanStackStartBuildProvenance,
  type TanStackVitePluginLike,
} from "../src/tanstack-start-build-observer";
import type { Condition, GraphEdge, GraphNode } from "../src/types";

const DIGEST = "b".repeat(64);
const provenance: TanStackStartBuildProvenance = {
  build_run_id: "tanstack-build-run",
  profile_id: "tanstack-build-profile",
  command_plan_digest: DIGEST,
  toolchain_executable_digest: DIGEST,
  environment_key_set_digest: DIGEST,
  validated_output_digest: DIGEST,
};

function errorCode(operation: () => unknown): string {
  try {
    operation();
  } catch (error) {
    assert.ok(error instanceof TanStackStartBuildObserverError);
    return error.code;
  }
  assert.fail("expected TanStackStartBuildObserverError");
}

function context(environment: string, modules: Record<string, {
  importedIds?: string[];
  dynamicallyImportedIds?: string[];
  isEntry?: boolean;
}>) {
  return {
    environment: { name: environment },
    meta: { viteVersion: "7.0.6", rollupVersion: "4.0.0", watchMode: false },
    getModuleIds: () => Object.keys(modules).values(),
    getModuleInfo: (id: unknown) => modules[String(id)] ?? null,
  };
}

function configure(plugin: TanStackVitePluginLike, existing: unknown[] = []): void {
  plugin.configResolved({
    mode: "production",
    base: "/",
    environments: { client: {}, ssr: {} },
    plugins: [...existing, { name: "tanstack-start-core:config" }, plugin],
  });
}

async function observe(options: { collision?: boolean; sink?: (value: TanStackStartBuildObservation) => void } = {}): Promise<TanStackStartBuildObservation> {
  const observations: TanStackStartBuildObservation[] = [];
  const plugin = createTanStackStartBuildObserverPlugin({
    startVersion: "1.168.28",
    repoRoot: "/repo",
    sink: { write: (value) => { observations.push(value); options.sink?.(value); } },
  });
  configure(plugin);
  const clientModules = {
    "/repo/src/routes/index.tsx": { importedIds: ["/repo/src/server/account.ts"], isEntry: true },
    "/repo/src/server/account.ts": { importedIds: [] },
  };
  const client = context("client", clientModules);
  plugin.buildStart.call(client);
  plugin.transform.call(
    client,
    `import { createClientRpc } from "@tanstack/react-start/client-rpc"\nconst getAccount = createClientRpc("rpc${options.collision ? "_1" : ""}")\nconst secret = "CLIENT_SECRET"`,
    "/repo/src/server/account.ts",
  );
  plugin.generateBundle.call(client, {}, {
    "assets/client.js": {
      type: "chunk",
      fileName: "assets/client.js",
      code: "CLIENT_CHUNK_SECRET",
      isEntry: true,
      modules: { "/repo/src/routes/index.tsx": {}, "/repo/src/server/account.ts": {} },
      imports: [],
      dynamicImports: [],
    },
    "assets/style.css": { type: "asset", fileName: "assets/style.css", source: "ASSET_SECRET" },
  });
  await plugin.closeBundle.call(client);
  assert.equal(observations.length, 0);

  const providerId = "/repo/src/server/account.ts?tss-serverfn-split";
  const ssrModules = {
    "/repo/src/routes/index.tsx": { importedIds: [providerId, "/repo/src/server/middleware.ts"], isEntry: true },
    [providerId]: { importedIds: ["/repo/src/server/middleware.ts"] },
    "/repo/src/server/middleware.ts": { importedIds: [] },
    "\0virtual:tanstack-start-server-fn-resolver": { importedIds: [providerId], isEntry: true },
  };
  const ssr = context("ssr", ssrModules);
  plugin.buildStart.call(ssr);
  const rpcId = `rpc${options.collision ? "_1" : ""}`;
  plugin.transform.call(
    ssr,
    `import { createSsrRpc } from "@tanstack/react-start/ssr-rpc"\nconst getAccount = createSsrRpc("${rpcId}")`,
    "/repo/src/server/account.ts",
  );
  plugin.transform.call(
    ssr,
    `import { createServerRpc } from "@tanstack/react-start/server-rpc"\nconst extracted = createServerRpc({ id: "${rpcId}", name: "getAccount", filename: "src/server/account.ts" }, () => "PROVIDER_SECRET")`,
    providerId,
  );
  plugin.transform.call(
    ssr,
    `const manifest = { '${rpcId}': { functionName: 'getAccount_createServerFn_handler', importer: () => import('${providerId}') } }`,
    "\0virtual:tanstack-start-server-fn-resolver",
  );
  plugin.generateBundle.call(ssr, {}, {
    "server/entry.mjs": {
      type: "chunk",
      fileName: "server/entry.mjs",
      code: "SSR_CHUNK_SECRET",
      isEntry: true,
      modules: {
        "/repo/src/routes/index.tsx": {},
        [providerId]: {},
        "/repo/src/server/middleware.ts": {},
        "\0virtual:tanstack-start-server-fn-resolver": {},
      },
      imports: [],
      dynamicImports: [],
    },
    "server/manifest.json": {
      type: "asset",
      fileName: "server/manifest.json",
      source: "SSR_ASSET_SECRET",
    },
  });
  await plugin.closeBundle.call(ssr);
  assert.equal(observations.length, 1);
  return observations[0]!;
}

test("TanStack Start v1 and Vite 7 capability gates are stable and explicit", () => {
  for (const version of ["1.0.0", "1.168.28", "1.999.0"]) {
    assert.equal(detectTanStackStartBuildCapability(version).capability, TANSTACK_START_BUILD_CAPABILITY);
  }
  for (const version of ["0.99.0", "2.0.0", "1.2.3-beta.1", "latest"]) {
    assert.equal(errorCode(() => detectTanStackStartBuildCapability(version)), "web.tanstack_start_build_version_unsupported");
  }
  assert.equal(errorCode(() => detectTanStackStartBuildCapability("1.0.0", "client")),
    "web.tanstack_start_build_provider_environment_invalid");
});

test("observer requires the internal Start plugin, preserves existing order, and rejects conflicts", () => {
  const existing = { name: "existing-vite-plugin" };
  const plugin = createTanStackStartBuildObserverPlugin({
    startVersion: "1.168.28",
    repoRoot: "/repo",
    existingVitePlugins: [existing],
    sink: { write() {} },
  });
  configure(plugin, [existing]);
  assert.equal(errorCode(() => plugin.configResolved({ plugins: [plugin, existing, { name: "tanstack-start-core:config" }] })),
    "web.tanstack_start_build_plugin_chain_invalid");
  const absent = createTanStackStartBuildObserverPlugin({
    startVersion: "1.168.28", repoRoot: "/repo", sink: { write() {} },
  });
  assert.equal(errorCode(() => absent.configResolved({ plugins: [absent] })),
    "web.tanstack_start_build_internal_contract_unavailable");
  assert.equal(errorCode(() => detectTanStackStartBuildCapability("1.0.0", undefined, [{ name: "same" }, { name: "same" }])),
    "web.tanstack_start_build_plugin_chain_invalid");

  const collision = createTanStackStartBuildObserverPlugin({
    startVersion: "1.168.28", repoRoot: "/repo", sink: { write() {} },
  });
  configure(collision);
  const providerContext = context("ssr", {});
  collision.buildStart.call(providerContext);
  const runtime = 'import { createServerRpc } from "@tanstack/react-start/server-rpc";';
  collision.transform.call(
    providerContext,
    `${runtime} createServerRpc({ id: "rpc", name: "first", filename: "src/first.ts" }, () => {})`,
    "/repo/src/first.ts?tss-serverfn-split",
  );
  assert.equal(errorCode(() => collision.transform.call(
    providerContext,
    `${runtime} createServerRpc({ id: "rpc", name: "second", filename: "src/second.ts" }, () => {})`,
    "/repo/src/second.ts?tss-serverfn-split",
  )), "web.tanstack_start_build_rpc_id_conflict");
});

test("observer stores authoritative RPC IDs without guessing suffixes and separates client/SSR/server evidence", async () => {
  const observation = await observe({ collision: true });
  assert.equal(observation.resolver_virtual_module_observed, true);
  assert.deepEqual(observation.builds.map((build) => build.vite_environment), ["client", "ssr"]);
  assert.equal(observation.server_functions[0]?.production_rpc_id, "rpc_1");
  assert.equal(observation.server_functions[0]?.collision_suffix, null);
  assert.equal(observation.server_functions[0]?.collision_suffix_status, "not-separately-observed");
  assert.equal(observation.server_functions[0]?.client_referenced, true);
  assert.equal(observation.server_functions[0]?.ssr_referenced, true);
  assert.equal(observation.production_rpc_manifest.entry_count, 1);
  assert.equal(observation.production_rpc_manifest.entries[0]?.production_rpc_id, "rpc_1");
  assert.equal(observation.production_rpc_manifest.entries[0]?.handler_export_name, "getAccount_createServerFn_handler");
  assert.match(observation.production_rpc_manifest.entries_digest, /^[a-f0-9]{64}$/u);
  const environments = new Set(observation.builds.flatMap((build) => [
    ...build.modules.map((module) => module.environment),
    ...build.outputs.map((output) => output.environment),
  ]));
  assert.deepEqual([...environments].sort(), ["client", "server", "ssr"]);
  const serialized = JSON.stringify(observation);
  assert.equal(serialized.includes("tanstack-start-server-fn-resolver"), false);
  assert.equal(
    observation.builds.find((build) => build.vite_environment === "ssr")?.outputs
      .find((output) => output.file_name === "server/manifest.json")?.environment,
    "ssr",
  );
  for (const secret of [
    "CLIENT_SECRET", "CLIENT_CHUNK_SECRET", "ASSET_SECRET", "PROVIDER_SECRET", "SSR_CHUNK_SECRET", "SSR_ASSET_SECRET",
  ]) {
    assert.equal(serialized.includes(secret), false);
  }
  assert.equal(serialized.includes("/repo/"), false);
});

test("v2 observation rejects manifest/provider/stub drift and non-production configuration", async () => {
  const observation = await observe();
  assert.equal(observation.observer_version, TANSTACK_START_BUILD_OBSERVER_VERSION);
  assert.deepEqual(validateTanStackStartBuildObservation(observation), observation);
  const manifestDrift = structuredClone(observation);
  manifestDrift.production_rpc_manifest.entries[0]!.provider_module_id = "src/server/other.ts#server-provider";
  assert.equal(
    errorCode(() => validateTanStackStartBuildObservation(manifestDrift)),
    "web.tanstack_start_build_rpc_manifest_invalid",
  );
  const stubDrift = structuredClone(observation);
  stubDrift.stubs[0]!.production_rpc_id = "missing";
  assert.equal(
    errorCode(() => validateTanStackStartBuildObservation(stubDrift)),
    "web.tanstack_start_build_stub_target_missing",
  );
  const plugin = createTanStackStartBuildObserverPlugin({
    startVersion: "1.168.28", repoRoot: "/repo", sink: { write() {} },
  });
  assert.equal(errorCode(() => plugin.configResolved({
    mode: "development",
    plugins: [{ name: "tanstack-start-core:config" }, plugin],
  })), "web.tanstack_start_build_mode_unsupported");
});

test("unsupported Vite, failed builds, missing virtual modules, raw crashes, and timeout fail without partial output", async () => {
  const plugin = createTanStackStartBuildObserverPlugin({
    startVersion: "1.168.28", repoRoot: "/repo", timeoutMs: 10, sink: { write: () => new Promise(() => undefined) },
  });
  configure(plugin);
  assert.equal(errorCode(() => plugin.buildStart.call({ environment: { name: "client" }, meta: { viteVersion: "8.0.0" } })),
    "web.tanstack_start_build_vite_version_unsupported");
  assert.equal(errorCode(() => plugin.buildStart.call({ environment: { name: "client" }, meta: { viteVersion: "6.4.0" } })),
    "web.tanstack_start_build_vite_version_unsupported");
  const diagnostic = tanStackStartBuildFailureDiagnostic(new Error("RAW_CRASH_SECRET"), "profile");
  assert.equal(diagnostic.code, "web.tanstack_start_build_observer_failed");
  assert.equal(JSON.stringify(diagnostic).includes("RAW_CRASH_SECRET"), false);
  const unsupported = tanStackStartBuildFailureDiagnostic(
    new TanStackStartBuildObserverError("web.tanstack_start_build_version_unsupported"),
    "profile",
  );
  assert.equal(unsupported.properties?.framework_build_completion_status, "unsupported");
  assert.equal(unsupported.properties?.framework_build_completion_reason, "framework_build_version_unsupported");
  const missingManifest = tanStackStartBuildFailureDiagnostic(
    new TanStackStartBuildObserverError("web.tanstack_start_build_rpc_manifest_missing"),
    "profile",
  );
  assert.equal(missingManifest.properties?.framework_build_completion_reason, "framework_build_manifest_missing");

  const missing = createTanStackStartBuildObserverPlugin({
    startVersion: "1.168.28", repoRoot: "/repo", sink: { write() {} },
  });
  configure(missing);
  for (const environment of ["client", "ssr"]) {
    const current = context(environment, {});
    missing.buildStart.call(current);
    missing.generateBundle.call(current, {}, {});
    await (environment === "ssr"
      ? assert.rejects(async () => missing.closeBundle.call(current), { code: "web.tanstack_start_build_virtual_module_missing" })
      : missing.closeBundle.call(current));
  }

  const failed = createTanStackStartBuildObserverPlugin({
    startVersion: "1.168.28", repoRoot: "/repo", sink: { write() {} },
  });
  configure(failed);
  for (const environment of ["client", "ssr"]) {
    const current = context(environment, {});
    failed.buildStart.call(current);
    if (environment === "ssr") failed.transform.call(
      current, "const manifest = {}", "\0virtual:tanstack-start-server-fn-resolver",
    );
    failed.generateBundle.call(current, {}, {});
    if (environment === "ssr") failed.buildEnd.call(current, new Error("BUILD_SECRET"));
    await (environment === "ssr"
      ? assert.rejects(async () => failed.closeBundle.call(current), { code: "web.tanstack_start_build_environment_observation_incomplete" })
      : failed.closeBundle.call(current));
  }

  const timeout = createTanStackStartBuildObserverPlugin({
    startVersion: "1.168.28", repoRoot: "/repo", timeoutMs: 10, sink: { write: () => new Promise(() => undefined) },
  });
  configure(timeout);
  for (const environment of ["client", "ssr"]) {
    const current = context(environment, environment === "ssr"
      ? { "\0virtual:tanstack-start-server-fn-resolver": { isEntry: true } }
      : {});
    timeout.buildStart.call(current);
    if (environment === "ssr") timeout.transform.call(
      current, "const manifest = {}", "\0virtual:tanstack-start-server-fn-resolver",
    );
    timeout.generateBundle.call(current, {}, {});
    await (environment === "ssr"
      ? assert.rejects(async () => timeout.closeBundle.call(current), { code: "web.tanstack_start_build_observer_timeout" })
      : timeout.closeBundle.call(current));
  }
});

test("observed stubs correlate to safe server functions, handlers, routes, middleware, and artifacts", async () => {
  const observation = await observe();
  const definition: GraphNode = {
    id: "symbol:safe-definition",
    kind: "symbol",
    locator: "symbol://safe/getAccount",
    display_name: "getAccount",
    properties: { framework: "tanstack-start", source_path: "src/server/account.ts" },
  };
  const safeIdentity = { framework: "tanstack-start", resolver_identity: "safe:getAccount" };
  const serverFunction: GraphNode = {
    id: stableId("server_function", safeIdentity),
    kind: "server_function",
    locator: "server-function://safe/getAccount",
    display_name: "getAccount",
    properties: {
      ...safeIdentity,
      source_path: "src/server/account.ts",
      typescript_definition_id: definition.id,
    },
  };
  const handler: GraphNode = {
    id: "symbol:safe-handler",
    kind: "symbol",
    locator: "symbol://safe/handler",
    display_name: "handler",
    properties: { framework: "tanstack-start", source_path: "src/server/account.ts" },
  };
  const route: GraphNode = {
    id: "route:safe-index",
    kind: "route",
    locator: "route://safe/index",
    display_name: "/",
    properties: { framework: "tanstack-start", source_path: "src/routes/index.tsx" },
  };
  const middleware: GraphNode = {
    id: "middleware:safe-auth",
    kind: "middleware",
    locator: "middleware://safe/auth",
    display_name: "auth",
    properties: { framework: "tanstack-start", source_path: "src/server/middleware.ts" },
  };
  const condition: Condition = { op: "all", conditions: [] };
  const baseEdges: GraphEdge[] = [
    {
      id: "edge:handler", source: serverFunction.id, target: handler.id, kind: "handled_by", site_id: null,
      phase: "semantic", environment: "server", profile_id: provenance.profile_id, condition,
      resolution_status: "resolved", precision: "exact", generated: false, evidence: [],
    },
    {
      id: "edge:middleware", source: route.id, target: middleware.id, kind: "uses_middleware", site_id: null,
      phase: "semantic", environment: "server", profile_id: provenance.profile_id, condition,
      resolution_status: "resolved", precision: "exact", generated: false, evidence: [],
    },
    {
      id: "edge:function-middleware", source: serverFunction.id, target: middleware.id, kind: "uses_middleware", site_id: null,
      phase: "semantic", environment: "server", profile_id: provenance.profile_id, condition,
      resolution_status: "resolved", precision: "exact", generated: false, evidence: [],
    },
  ];
  const delta = buildTanStackStartObservedGraph({
    observation,
    provenance,
    baseNodes: [definition, serverFunction, handler, route, middleware],
    baseEdges,
  });
  const observed = delta.nodes.find((node) => node.kind === "server_function" && node.properties.production_rpc_id === "rpc");
  assert.ok(observed);
  assert.ok(delta.edges.some((edge) => edge.kind === "client_stub_for" && edge.target === observed.id && edge.environment === "browser"));
  assert.ok(delta.edges.some((edge) => edge.kind === "client_stub_for" && edge.target === observed.id && edge.environment === "ssr"));
  assert.ok(delta.edges.some((edge) => edge.kind === "handled_by" && edge.source === observed.id && edge.target === handler.id));
  assert.ok(delta.edges.some((edge) => edge.kind === "uses_middleware"
    && edge.source === observed.id && edge.target === middleware.id && edge.precision === "observed"));
  assert.ok(delta.edges.some((edge) => edge.kind === "emits" && edge.source === route.id));
  assert.ok(delta.edges.some((edge) => edge.kind === "emits" && edge.source === middleware.id));
  const generatedModuleRoles = new Set(delta.nodes
    .filter((node) => node.kind === "module")
    .map((node) => node.properties.tanstack_start_module_role));
  assert.ok(generatedModuleRoles.has("client-rpc-stub"));
  assert.ok(generatedModuleRoles.has("server-function-provider"));
  assert.ok(generatedModuleRoles.has("server-function-resolver"));
  assert.equal(delta.diagnostics.some((item) => item.code === "web.tanstack_start_build_middleware_artifact_drift"), false);
  const events = tanStackStartBuildProtocolEvents("/repo", delta, provenance, "revision");
  assert.equal(events[0]?.event, "scan_started");
  const profile = events.find((event) => event.event === "profile_declared")?.profile as
    | { properties: Record<string, unknown> }
    | undefined;
  assert.equal(profile?.properties.production_rpc_manifest_entry_count, 1);
  assert.equal(events.at(-1)?.event, "scan_completed");
});

test("missing safe server-function target stays unresolved instead of becoming exact", async () => {
  const observation = await observe();
  const delta = buildTanStackStartObservedGraph({ observation, provenance, baseNodes: [] });
  const site = delta.sites.find((item) => item.kind === "observes_definition");
  assert.equal(site?.resolution_status, "unresolved");
  assert.equal(site?.reason, "framework_build_dynamic_target_unmatched");
  assert.equal(delta.nodes.find((node) => node.id === site?.target_ids[0])?.kind, "unknown_target");
  assert.ok(delta.diagnostics.some((item) => item.code === "web.tanstack_start_build_server_function_static_missing"));
});

test("bundled observer writes one confined deterministic observation", async () => {
  const root = await mkdtemp(path.join(tmpdir(), "depgraph-tanstack-observer-"));
  const previousOutput = process.env.DEPGRAPH_OUTPUT_DIR;
  const previousVersion = process.env.DEPGRAPH_TANSTACK_START_VERSION;
  try {
    process.env.DEPGRAPH_OUTPUT_DIR = root;
    process.env.DEPGRAPH_TANSTACK_START_VERSION = "1.168.28";
    const entry = `${pathToFileURL(path.resolve("dist/tanstack-start-build-observer.mjs")).href}?test=${Date.now()}`;
    const module = await import(entry) as { default: (options: { repoRoot: string }) => TanStackVitePluginLike };
    const plugin = module.default({ repoRoot: "/repo" });
    configure(plugin);
    for (const environment of ["client", "ssr"]) {
      const current = context(environment, environment === "ssr"
        ? { "\0virtual:tanstack-start-server-fn-resolver": { isEntry: true } }
        : {});
      plugin.buildStart.call(current);
      if (environment === "ssr") plugin.transform.call(
        current, "const manifest = {}", "\0virtual:tanstack-start-server-fn-resolver",
      );
      plugin.generateBundle.call(current, {}, {});
      await plugin.closeBundle.call(current);
    }
    const artifact = await readFile(path.join(root, "tanstack-start-build-observation.json"), "utf8");
    assert.equal(JSON.parse(artifact).observer, TANSTACK_START_BUILD_OBSERVER);
  } finally {
    if (previousOutput === undefined) delete process.env.DEPGRAPH_OUTPUT_DIR;
    else process.env.DEPGRAPH_OUTPUT_DIR = previousOutput;
    if (previousVersion === undefined) delete process.env.DEPGRAPH_TANSTACK_START_VERSION;
    else process.env.DEPGRAPH_TANSTACK_START_VERSION = previousVersion;
    await rm(root, { recursive: true, force: true });
  }
});
