import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { pathToFileURL } from "node:url";
import {
  ASTRO_BUILD_MANIFEST_CONTRACT,
  ASTRO_BUILD_OBSERVER,
  ASTRO_BUILD_OBSERVER_CAPABILITY,
  ASTRO_BUILD_OBSERVER_VERSION,
  AstroBuildObserverError,
  astroBuildFailureDiagnostic,
  astroBuildProtocolEvents,
  buildAstroObservedGraph,
  createAstroBuildObserverIntegration,
  detectAstroObserverCapability,
  type AstroBuildObservation,
  type AstroBuildProvenance,
  type AstroVitePluginLike,
} from "../src/astro-build-observer";
import { stableId } from "../src/ids";
import type { GraphNode } from "../src/types";

const DIGEST = "a".repeat(64);
const provenance: AstroBuildProvenance = {
  build_run_id: "astro-build-run",
  profile_id: "astro-build-profile",
  command_plan_digest: DIGEST,
  toolchain_executable_digest: DIGEST,
  environment_key_set_digest: DIGEST,
  validated_output_digest: DIGEST,
};

const routeInput = {
  route: "/blog",
  pathname: "/blog",
  pattern: "/blog",
  patternRegex: /^\/blog$/,
  entrypoint: "src/pages/blog.astro",
  params: [],
  segments: [[{ content: "blog", dynamic: false, spread: false }]],
  type: "page",
  isPrerendered: true,
  origin: "project",
};

function observerErrorCode(operation: () => unknown): string {
  try {
    operation();
  } catch (error) {
    assert.ok(error instanceof AstroBuildObserverError);
    return error.code;
  }
  assert.fail("expected AstroBuildObserverError");
}

function viteContext(environment: "browser" | "server", modules: Record<string, {
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

async function completeObservation(options: {
  injected?: boolean;
  dynamic?: boolean;
  repoRoot?: string;
} = {}): Promise<AstroBuildObservation> {
  const observations: AstroBuildObservation[] = [];
  const repoRoot = options.repoRoot ?? "/repo";
  const existingIntegration = { name: "existing-integration" };
  const existingPlugin = { name: "existing-vite-plugin" };
  const integration = createAstroBuildObserverIntegration({
    astroVersion: "5.12.0",
    repoRoot,
    existingIntegrations: [existingIntegration],
    existingVitePlugins: [existingPlugin],
    dynamicConfigDetected: options.dynamic === true,
    sink: { write: (observation) => { observations.push(observation); } },
  });
  await integration.hooks["astro:config:done"]!({
    config: {
      output: "static",
      base: "/",
      trailingSlash: "ignore",
      adapter: null,
      integrations: [existingIntegration, integration],
      secret: "CONFIG_SECRET",
    },
  });
  const observedRoute = { ...routeInput, origin: options.injected ? "integration" : "project" };
  const dynamicRoute = {
    route: "/blog/[...slug]",
    pathname: undefined,
    pattern: "/blog/[...slug]",
    patternRegex: /^\/blog\/(.*?)\/?$/,
    entrypoint: "src/pages/blog/[...slug].astro",
    params: ["...slug"],
    segments: [
      [{ content: "blog", dynamic: false, spread: false }],
      [{ content: "slug", dynamic: true, spread: true }],
    ],
    type: "page",
    isPrerendered: false,
    origin: "project",
  };
  const endpointRoute = {
    route: "/api/[id]",
    pathname: undefined,
    pattern: "/api/[id]",
    patternRegex: /^\/api\/([^/]+?)\/?$/,
    entrypoint: "src/pages/api/[id].ts",
    params: ["id"],
    segments: [
      [{ content: "api", dynamic: false, spread: false }],
      [{ content: "id", dynamic: true, spread: false }],
    ],
    type: "endpoint",
    isPrerendered: false,
    origin: "project",
  };
  const resolvedRoutes: unknown[] = [observedRoute, dynamicRoute, endpointRoute];
  await integration.hooks["astro:routes:resolved"]!({ routes: resolvedRoutes });
  const plugins = new Map<"browser" | "server", AstroVitePluginLike>();
  for (const [target, environment] of [["client", "browser"], ["server", "server"]] as const) {
    let update: unknown = null;
    await integration.hooks["astro:build:setup"]!({
      target,
      updateConfig: (value: unknown) => { update = value; },
    });
    assert.deepEqual(Object.keys(update as object), ["plugins"]);
    const configured = (update as { plugins: AstroVitePluginLike[] }).plugins;
    assert.equal(configured.length, 1);
    plugins.set(environment, configured[0]!);
  }
  const browserPlugin = plugins.get("browser")!;
  const serverPlugin = plugins.get("server")!;

  const browser = viteContext("browser", {
    [`${repoRoot}/src/pages/blog.astro`]: { importedIds: [`${repoRoot}/src/lib/client.ts`], isEntry: true },
    [`${repoRoot}/src/lib/client.ts`]: { importedIds: [], dynamicallyImportedIds: [] },
    [`${repoRoot}/src/components/Counter.tsx`]: { importedIds: [`${repoRoot}/src/lib/client.ts`], isEntry: true },
  });
  browserPlugin.configResolved({
    mode: "production",
    base: "/",
    build: { ssr: false, outDir: `${repoRoot}/dist/client` },
    plugins: [existingPlugin, browserPlugin],
  });
  browserPlugin.buildStart.call(browser);
  browserPlugin.generateBundle.call(browser, {}, {
    "assets/main.js": {
      type: "chunk",
      fileName: "assets/main.js",
      code: "const TOKEN = 'SOURCE_SECRET'",
      isEntry: true,
      modules: { [`${repoRoot}/src/pages/blog.astro`]: {}, [`${repoRoot}/src/lib/client.ts`]: {} },
      imports: [],
      dynamicImports: [],
      viteMetadata: { importedAssets: new Set(), importedCss: new Set(["assets/main.css"]) },
    },
    "assets/main.css": { type: "asset", fileName: "assets/main.css", source: "/* ASSET_SECRET */" },
    "assets/counter.js": {
      type: "chunk",
      fileName: "assets/counter.js",
      code: "export const Counter = 1",
      isEntry: true,
      modules: { [`${repoRoot}/src/components/Counter.tsx`]: {} },
      imports: [],
      dynamicImports: [],
      viteMetadata: { importedAssets: new Set(), importedCss: new Set() },
    },
  });

  const server = viteContext("server", {
    [`${repoRoot}/src/pages/blog.astro`]: { importedIds: [`${repoRoot}/src/content/posts/a.md`], isEntry: true },
    [`${repoRoot}/src/content/posts/a.md`]: { importedIds: [] },
    [`${repoRoot}/src/pages/blog/[...slug].astro`]: {
      importedIds: [`${repoRoot}/src/components/Counter.tsx`],
      isEntry: true,
    },
    [`${repoRoot}/src/components/Counter.tsx`]: { importedIds: [] },
    [`${repoRoot}/src/pages/api/[id].ts`]: { importedIds: [], isEntry: true },
  });
  serverPlugin.configResolved({
    mode: "production",
    base: "/",
    build: { ssr: true, outDir: `${repoRoot}/dist/server` },
    plugins: [existingPlugin, serverPlugin],
  });
  serverPlugin.buildStart.call(server);
  serverPlugin.generateBundle.call(server, {}, {
    "server/entry.mjs": {
      type: "chunk",
      fileName: "server/entry.mjs",
      code: "export const password = 'SERVER_SECRET'",
      isEntry: true,
      modules: { [`${repoRoot}/src/pages/blog.astro`]: {}, [`${repoRoot}/src/content/posts/a.md`]: {} },
      imports: [],
      dynamicImports: [],
      viteMetadata: { importedAssets: new Set(), importedCss: new Set() },
    },
    "server/dynamic.mjs": {
      type: "chunk",
      fileName: "server/dynamic.mjs",
      code: "export const page = true",
      isEntry: true,
      modules: {
        [`${repoRoot}/src/pages/blog/[...slug].astro`]: {},
        [`${repoRoot}/src/components/Counter.tsx`]: {},
      },
      imports: [],
      dynamicImports: [],
      viteMetadata: { importedAssets: new Set(), importedCss: new Set() },
    },
    "server/endpoint.mjs": {
      type: "chunk",
      fileName: "server/endpoint.mjs",
      code: "export const GET = true",
      isEntry: true,
      modules: { [`${repoRoot}/src/pages/api/[id].ts`]: {} },
      imports: [],
      dynamicImports: [],
      viteMetadata: { importedAssets: new Set(), importedCss: new Set() },
    },
  });
  await integration.hooks["astro:build:ssr"]!({
    manifest: {
      routes: [{}, {}, {}],
      entryModules: { [`${repoRoot}/src/components/Counter.tsx`]: "assets/counter.js" },
      token: "MANIFEST_SECRET",
    },
    middlewareEntryPoint: "middleware.mjs",
  });
  await integration.hooks["astro:build:generated"]!({
    routeToHeaders: new Map([
      ["/blog", { route: observedRoute }],
      ["/generated/blog", { route: dynamicRoute }],
      ["/generated/api", { route: endpointRoute }],
    ]),
  });
  await integration.hooks["astro:build:done"]!({
    pages: [{ pathname: "/blog", secret: "PAGE_SECRET" }],
    dir: pathToFileURL(`${repoRoot}/dist/`),
    assets: new Map<string, URL[]>([
      ["/blog", [pathToFileURL(`${repoRoot}/dist/blog/index.html`)]],
    ]),
  });
  assert.equal(observations.length, 1);
  return observations[0]!;
}

test("Astro capability supports stable 5-7 and rejects unsupported or prerelease versions", () => {
  for (const version of ["5.0.0", "6.4.1", "7.0.9"]) {
    assert.equal(detectAstroObserverCapability(version).capability, ASTRO_BUILD_OBSERVER_CAPABILITY);
  }
  for (const version of ["4.16.0", "8.0.0", "7.0.0-beta.1", "latest"]) {
    assert.equal(observerErrorCode(() => detectAstroObserverCapability(version)), "web.astro_build_version_unsupported");
  }
});

test("integration and plugin chains fail closed on malformed, colliding, or reordered entries", async () => {
  assert.equal(observerErrorCode(() => detectAstroObserverCapability("5.0.0", [{ name: ASTRO_BUILD_OBSERVER }])),
    "web.astro_build_integration_chain_invalid");
  assert.equal(observerErrorCode(() => detectAstroObserverCapability("5.0.0", [], [{ name: "same" }, { name: "same" }])),
    "web.astro_build_plugin_chain_invalid");
  assert.equal(observerErrorCode(() => detectAstroObserverCapability("5.0.0", [{}])),
    "web.astro_build_integration_chain_invalid");
  const existingIntegration = { name: "existing-integration" };
  const existingPlugin = { name: "existing-plugin" };
  const integration = createAstroBuildObserverIntegration({
    astroVersion: "5.0.0",
    repoRoot: "/repo",
    existingIntegrations: [existingIntegration],
    existingVitePlugins: [existingPlugin],
    sink: { write() {} },
  });
  await assert.rejects(async () => integration.hooks["astro:config:done"]!({
    config: { integrations: [integration, existingIntegration] },
  }), { code: "web.astro_build_integration_chain_invalid" });
  let plugin: AstroVitePluginLike | null = null;
  await integration.hooks["astro:build:setup"]!({ target: "client", updateConfig: (value: unknown) => {
    plugin = (value as { plugins: AstroVitePluginLike[] }).plugins[0]!;
  } });
  assert.equal(observerErrorCode(() => plugin!.configResolved({
    mode: "production",
    build: { outDir: "/repo/dist" },
    plugins: [plugin!, existingPlugin],
  })), "web.astro_build_plugin_chain_invalid");
});

test("observer preserves chains and stores only sanitized client/SSR graph and asset evidence", async () => {
  const observation = await completeObservation();
  assert.equal(observation.config.integration_count, 2);
  assert.deepEqual(observation.vite_builds.map((build) => build.environment), ["browser", "server"]);
  assert.deepEqual(observation.vite_builds.map((build) => build.vite_version), ["7.0.6", "7.0.6"]);
  assert.equal(observation.ssr.route_count, 3);
  assert.equal(observation.ssr.endpoint_count, 1);
  assert.equal(observation.ssr.middleware_present, true);
  assert.equal(observation.generated.route_count, 3);
  assert.equal(observation.manifests.contract_version, ASTRO_BUILD_MANIFEST_CONTRACT);
  assert.equal(observation.manifests.route_entry_count, 3);
  assert.equal(observation.manifests.asset_entry_count, 1);
  assert.equal(observation.manifests.island_entry_count, 1);
  assert.equal(observation.manifests.output_entry_count, 6);
  assert.match(observation.manifests.route_manifest_digest, /^[a-f0-9]{64}$/u);
  assert.match(observation.manifests.asset_manifest_digest, /^[a-f0-9]{64}$/u);
  assert.match(observation.manifests.island_manifest_digest, /^[a-f0-9]{64}$/u);
  assert.match(observation.manifests.vite_manifest_digest, /^[a-f0-9]{64}$/u);
  assert.deepEqual(observation.ssr.entry_modules, [{
    module_id: "src/components/Counter.tsx",
    module_kind: "project",
    chunk: "assets/counter.js",
  }]);
  const dynamic = observation.routes.find((route) => route.route_pattern === "/blog/[...slug]");
  assert.deepEqual(dynamic?.params, [{ name: "slug", spread: true }]);
  assert.equal(dynamic?.dynamic, true);
  assert.equal(dynamic?.pathname, null);
  assert.ok(observation.vite_builds.some((build) => build.outputs.some((output) => (
    output.role === "hydration_chunk" && output.boundary === "browser"
  ))));
  assert.ok(observation.vite_builds.some((build) => build.outputs.some((output) => (
    output.role === "endpoint_chunk" && output.boundary === "server"
  ))));
  assert.equal(
    observation.route_assets[0]?.route_digest,
    observation.routes.find((route) => route.route_pattern === "/blog")?.route_digest,
  );
  const serialized = JSON.stringify(observation);
  for (const secret of ["CONFIG_SECRET", "SOURCE_SECRET", "ASSET_SECRET", "SERVER_SECRET", "MANIFEST_SECRET", "PAGE_SECRET"]) {
    assert.equal(serialized.includes(secret), false);
  }
  assert.equal(serialized.includes("/repo/"), false);
  assert.match(observation.vite_builds[0]!.outputs[0]!.digest, /^[a-f0-9]{64}$/u);
});

test("unsupported versions, missing hooks, partial builds, crashes, and timeouts use bounded fixed diagnostics", async () => {
  const integration = createAstroBuildObserverIntegration({
    astroVersion: "5.12.0",
    repoRoot: "/repo",
    timeoutMs: 10,
    sink: { write: () => new Promise(() => undefined) },
  });
  await assert.rejects(async () => integration.hooks["astro:build:setup"]!({}), { code: "web.astro_build_hook_unavailable" });
  await assert.rejects(async () => integration.hooks["astro:build:setup"]!({
    target: "client",
    updateConfig: () => { throw new Error("UPDATE_CONFIG_SECRET"); },
  }), (error: unknown) => error instanceof AstroBuildObserverError
    && error.code === "web.astro_build_setup_hook_failed"
    && !error.message.includes("UPDATE_CONFIG_SECRET"));
  const plugins = new Map<"browser" | "server", AstroVitePluginLike>();
  for (const [target, environment] of [["client", "browser"], ["server", "server"]] as const) {
    await integration.hooks["astro:build:setup"]!({ target, updateConfig: (value: unknown) => {
      plugins.set(environment, (value as { plugins: AstroVitePluginLike[] }).plugins[0]!);
    } });
  }
  const browserPlugin = plugins.get("browser")!;
  browserPlugin.configResolved({
    mode: "production", base: "/", build: { outDir: "/repo/dist" }, plugins: [browserPlugin],
  });
  assert.equal(observerErrorCode(() => browserPlugin.buildStart.call({ meta: { viteVersion: "8.0.0" } })),
    "web.astro_build_vite_version_unsupported");
  await integration.hooks["astro:config:done"]!({ config: {} });
  await integration.hooks["astro:routes:resolved"]!({ routes: [] });
  const observeEnvironment = (environment: "browser" | "server"): void => {
    const plugin = plugins.get(environment)!;
    plugin.configResolved({
      mode: "production",
      base: "/",
      build: { ssr: environment === "server", outDir: `/repo/dist/${environment}` },
      plugins: [plugin],
    });
    const context = viteContext(environment, {});
    plugin!.buildStart.call(context);
    plugin!.generateBundle.call(context, {}, {});
  };
  observeEnvironment("browser");
  await assert.rejects(async () => integration.hooks["astro:build:done"]!({
    pages: [], assets: new Map(), dir: new URL("file:///repo/dist/"),
  }), {
    code: "web.astro_build_hook_missing",
  });
  await integration.hooks["astro:build:ssr"]!({ manifest: { routes: [], entryModules: {} } });
  await integration.hooks["astro:build:generated"]!({ routeToHeaders: new Map() });
  await assert.rejects(async () => integration.hooks["astro:build:done"]!({
    pages: [], assets: new Map(), dir: new URL("file:///repo/dist/"),
  }), {
    code: "web.astro_build_environment_observation_incomplete",
  });
  observeEnvironment("server");
  await assert.rejects(async () => integration.hooks["astro:build:done"]!({
    pages: [], assets: new Map(), dir: new URL("file:///repo/dist/"),
  }), {
    code: "web.astro_build_observer_timeout",
  });
  const diagnostic = astroBuildFailureDiagnostic(new Error("raw secret"), "profile");
  assert.equal(diagnostic.code, "web.astro_build_observer_failed");
  assert.equal(JSON.stringify(diagnostic).includes("raw secret"), false);
});

test("observed routes, modules, content, chunks, and assets correlate with environment-specific build evidence", async () => {
  const observation = await completeObservation({ dynamic: true });
  const relocatedObservation = await completeObservation({ dynamic: true, repoRoot: "/checkout" });
  assert.deepEqual(relocatedObservation, observation);
  const routeIdentity = {
    framework: "astro",
    package_locator: "workspace:app",
    route_kind: "astro-page",
    environment: "server",
    router_instance: "astro:workspace:app:filesystem",
    route_pattern: "/blog",
  };
  const route: GraphNode = {
    id: stableId("route", routeIdentity),
    kind: "route",
    locator: "route://astro/app/blog",
    display_name: "astro:page:/blog",
    properties: { ...routeIdentity, canonical_identity: routeIdentity, source_path: "src/pages/blog.astro" },
  };
  const componentIdentity = { framework: "astro", source_path: "src/pages/blog.astro", environment: "server" };
  const component: GraphNode = {
    id: stableId("component", componentIdentity),
    kind: "component",
    locator: "component://astro/blog",
    display_name: "blog.astro",
    properties: { ...componentIdentity },
  };
  const contentIdentity = { framework: "astro", path: "src/content/posts/a.md" };
  const content: GraphNode = {
    id: stableId("file", contentIdentity),
    kind: "file",
    locator: "file://src/content/posts/a.md",
    display_name: "a.md",
    properties: { ...contentIdentity },
  };
  const staticOnlyIdentity = { framework: "astro", route_pattern: "/gone" };
  const staticOnly: GraphNode = {
    id: stableId("route", staticOnlyIdentity),
    kind: "route",
    locator: "route://astro/gone",
    display_name: "/gone",
    properties: { ...staticOnlyIdentity },
  };
  const delta = buildAstroObservedGraph({ observation, provenance, baseNodes: [route, component, content, staticOnly] });
  assert.ok(delta.nodes.some((node) => node.id === route.id));
  assert.ok(delta.nodes.some((node) => node.id === component.id));
  assert.ok(delta.nodes.some((node) => node.id === content.id));
  assert.ok(delta.edges.some((edge) => edge.kind === "renders" && edge.source === route.id && edge.target === component.id));
  assert.equal(delta.edges.some((edge) => edge.source === edge.target), false);
  assert.ok(delta.edges.some((edge) => edge.phase === "build" && edge.precision === "observed" && edge.environment === "browser"));
  assert.ok(delta.edges.some((edge) => edge.phase === "build" && edge.precision === "observed" && edge.environment === "server"));
  assert.ok(delta.edges.some((edge) => edge.kind === "loads" && edge.target !== ""));
  const dynamicRoute = delta.nodes.find((node) => (
    node.kind === "route" && node.properties.route_pattern === "/blog/[...slug]"
  ));
  const endpointRoute = delta.nodes.find((node) => (
    node.kind === "route" && node.properties.route_pattern === "/api/[id]"
  ));
  const hydrationChunk = delta.nodes.find((node) => node.properties.artifact_role === "hydration_chunk");
  const endpointChunk = delta.nodes.find((node) => node.properties.artifact_role === "endpoint_chunk");
  assert.equal(dynamicRoute?.properties.dynamic, true);
  assert.deepEqual(dynamicRoute?.properties.dynamic_params, [{ name: "slug", spread: true }]);
  assert.ok(hydrationChunk);
  assert.ok(endpointChunk);
  assert.ok(delta.edges.some((edge) => (
    edge.kind === "loads"
      && edge.source === dynamicRoute?.id
      && edge.target === hydrationChunk?.id
      && edge.environment === "browser"
  )));
  assert.ok(delta.edges.some((edge) => (
    edge.kind === "emits"
      && edge.source === endpointRoute?.id
      && edge.target === endpointChunk?.id
      && edge.environment === "server"
  )));
  assert.ok(delta.nodes.some((node) => (
    node.kind === "module" && node.properties.module_role === "island"
  )));
  assert.ok(delta.nodes.some((node) => (
    node.kind === "module" && node.properties.runtime_boundary === "server"
  )));
  assert.ok(delta.diagnostics.some((item) => item.code === "web.astro_build_route_static_only"));
  assert.ok(delta.diagnostics.some((item) => item.code === "web.astro_build_dynamic_config_observed"));
  const events = astroBuildProtocolEvents("/repo", delta, provenance, "revision");
  assert.equal(events[0]?.event, "scan_started");
  assert.equal(events.at(-1)?.event, "scan_completed");
  const repeated = buildAstroObservedGraph({
    observation: relocatedObservation,
    provenance: { ...provenance, build_run_id: "astro-build-run-repeat" },
    baseNodes: delta.nodes,
    baseEdges: delta.edges,
    baseDiagnosticIds: delta.diagnostics.map((diagnostic) => diagnostic.id),
  });
  assert.deepEqual(repeated.nodes, delta.nodes);
  assert.deepEqual(repeated.sites, []);
  assert.deepEqual(repeated.edges, []);
  assert.deepEqual(repeated.diagnostics, []);

  const tampered = structuredClone(observation);
  tampered.vite_builds[0]!.outputs[0]!.role = "server_chunk";
  assert.throws(
    () => buildAstroObservedGraph({ observation: tampered, provenance, baseNodes: [route, component, content] }),
    (error: unknown) => error instanceof AstroBuildObserverError
      && error.code === "web.astro_build_observation_contract_invalid",
  );
});

test("injected routes remain queryable when absent from the safe graph", async () => {
  const observation = await completeObservation({ injected: true });
  const delta = buildAstroObservedGraph({ observation, provenance, baseNodes: [] });
  assert.ok(delta.nodes.some((node) => node.kind === "route" && node.properties.injected === true));
  assert.ok(delta.diagnostics.some((item) => item.code === "web.astro_build_injected_route_observed"));
});

test("bundled Astro integration writes one confined observation artifact", async () => {
  const root = await mkdtemp(path.join(tmpdir(), "depgraph-astro-observer-"));
  const previousOutput = process.env.DEPGRAPH_OUTPUT_DIR;
  const previousVersion = process.env.DEPGRAPH_ASTRO_VERSION;
  try {
    process.env.DEPGRAPH_OUTPUT_DIR = root;
    process.env.DEPGRAPH_ASTRO_VERSION = "5.12.0";
    const entryUrl = `${pathToFileURL(path.resolve("dist/astro-build-integration.mjs")).href}?test=${Date.now()}`;
    const module = await import(entryUrl) as { default: (options: { repoRoot: string }) => ReturnType<typeof createAstroBuildObserverIntegration> };
    const integration = module.default({ repoRoot: "/repo" });
    await integration.hooks["astro:config:done"]!({ config: {} });
    await integration.hooks["astro:routes:resolved"]!({ routes: [] });
    for (const environment of ["browser", "server"] as const) {
      let plugin: AstroVitePluginLike | null = null;
      await integration.hooks["astro:build:setup"]!({
        target: environment === "browser" ? "client" : "server",
        updateConfig: (value: unknown) => {
          plugin = (value as { plugins: AstroVitePluginLike[] }).plugins[0]!;
        },
      });
      plugin!.configResolved({
        mode: "production",
        base: "/",
        build: { ssr: environment === "server", outDir: `/repo/dist/${environment}` },
        plugins: [plugin!],
      });
      const context = viteContext(environment, {});
      plugin!.buildStart.call(context);
      plugin!.generateBundle.call(context, {}, {});
    }
    await integration.hooks["astro:build:ssr"]!({ manifest: { routes: [], entryModules: {} } });
    await integration.hooks["astro:build:generated"]!({ routeToHeaders: new Map() });
    await integration.hooks["astro:build:done"]!({
      pages: [], assets: new Map(), dir: new URL("file:///repo/dist/"),
    });
    const artifact = await readFile(path.join(root, "astro-build-observation.json"), "utf8");
    assert.equal(JSON.parse(artifact).observer, ASTRO_BUILD_OBSERVER);
    assert.equal(JSON.parse(artifact).observer_version, ASTRO_BUILD_OBSERVER_VERSION);
    await assert.rejects(async () => integration.hooks["astro:build:done"]!({
      pages: [], assets: new Map(), dir: new URL("file:///repo/dist/"),
    }), {
      code: "web.astro_build_observation_already_written",
    });
  } finally {
    if (previousOutput === undefined) delete process.env.DEPGRAPH_OUTPUT_DIR;
    else process.env.DEPGRAPH_OUTPUT_DIR = previousOutput;
    if (previousVersion === undefined) delete process.env.DEPGRAPH_ASTRO_VERSION;
    else process.env.DEPGRAPH_ASTRO_VERSION = previousVersion;
    await rm(root, { recursive: true, force: true });
  }
});
