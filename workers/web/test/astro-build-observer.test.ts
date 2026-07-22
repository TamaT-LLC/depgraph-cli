import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { pathToFileURL } from "node:url";
import {
  ASTRO_BUILD_OBSERVER,
  ASTRO_BUILD_OBSERVER_CAPABILITY,
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
  pathname: "/blog",
  pattern: /^\/blog$/,
  component: "src/pages/blog.astro",
  type: "page",
  prerender: true,
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

async function completeObservation(options: { injected?: boolean; dynamic?: boolean } = {}): Promise<AstroBuildObservation> {
  const observations: AstroBuildObservation[] = [];
  const existingIntegration = { name: "existing-integration" };
  const existingPlugin = { name: "existing-vite-plugin" };
  const integration = createAstroBuildObserverIntegration({
    astroVersion: "5.12.0",
    repoRoot: "/repo",
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
  await integration.hooks["astro:routes:resolved"]!({ routes: [observedRoute] });
  let update: unknown = null;
  await integration.hooks["astro:build:setup"]!({ updateConfig: (value: unknown) => { update = value; } });
  assert.deepEqual(Object.keys(update as object), ["plugins"]);
  const plugins = (update as { plugins: AstroVitePluginLike[] }).plugins;
  assert.equal(plugins.length, 1);
  const plugin = plugins[0]!;

  const browser = viteContext("browser", {
    "/repo/src/pages/blog.astro": { importedIds: ["/repo/src/lib/client.ts"], isEntry: true },
    "/repo/src/lib/client.ts": { importedIds: [], dynamicallyImportedIds: [] },
  });
  plugin.configResolved({
    mode: "production",
    base: "/",
    build: { ssr: false, outDir: "/repo/dist/client" },
    plugins: [existingPlugin, plugin],
  });
  plugin.buildStart.call(browser);
  plugin.generateBundle.call(browser, {}, {
    "assets/main.js": {
      type: "chunk",
      fileName: "assets/main.js",
      code: "const TOKEN = 'SOURCE_SECRET'",
      isEntry: true,
      modules: { "/repo/src/pages/blog.astro": {}, "/repo/src/lib/client.ts": {} },
      imports: [],
      dynamicImports: [],
      viteMetadata: { importedAssets: new Set(), importedCss: new Set(["assets/main.css"]) },
    },
    "assets/main.css": { type: "asset", fileName: "assets/main.css", source: "/* ASSET_SECRET */" },
  });

  const server = viteContext("server", {
    "/repo/src/pages/blog.astro": { importedIds: ["/repo/src/content/posts/a.md"], isEntry: true },
    "/repo/src/content/posts/a.md": { importedIds: [] },
  });
  plugin.configResolved({
    mode: "production",
    base: "/",
    build: { ssr: true, outDir: "/repo/dist/server" },
    plugins: [existingPlugin, plugin],
  });
  plugin.buildStart.call(server);
  plugin.generateBundle.call(server, {}, {
    "server/entry.mjs": {
      type: "chunk",
      fileName: "server/entry.mjs",
      code: "export const password = 'SERVER_SECRET'",
      isEntry: true,
      modules: { "/repo/src/pages/blog.astro": {}, "/repo/src/content/posts/a.md": {} },
      imports: [],
      dynamicImports: [],
      viteMetadata: { importedAssets: new Set(), importedCss: new Set() },
    },
  });
  await integration.hooks["astro:build:ssr"]!({
    manifest: { routes: [{ secret: "MANIFEST_SECRET" }], token: "SECRET" },
    middlewareEntryPoint: "middleware.mjs",
  });
  await integration.hooks["astro:build:done"]!({
    pages: [{ pathname: "/blog", secret: "PAGE_SECRET" }],
    dir: new URL("file:///repo/dist/"),
    assets: new Map([[observedRoute, ["assets/main.js", "assets/main.css"]]]),
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
  await integration.hooks["astro:build:setup"]!({ updateConfig: (value: unknown) => {
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
  assert.equal(observation.ssr.route_count, 1);
  assert.equal(observation.ssr.middleware_present, true);
  assert.equal(observation.route_assets[0]?.route_digest, observation.routes[0]?.route_digest);
  const serialized = JSON.stringify(observation);
  for (const secret of ["CONFIG_SECRET", "SOURCE_SECRET", "ASSET_SECRET", "SERVER_SECRET", "MANIFEST_SECRET", "PAGE_SECRET"]) {
    assert.equal(serialized.includes(secret), false);
  }
  assert.equal(serialized.includes("/repo/"), false);
  assert.match(observation.vite_builds[0]!.outputs[0]!.digest, /^[a-f0-9]{64}$/u);
});

test("unsupported Vite versions, missing hooks, crashes, and timeouts use bounded fixed diagnostics", async () => {
  const integration = createAstroBuildObserverIntegration({
    astroVersion: "5.12.0",
    repoRoot: "/repo",
    timeoutMs: 10,
    sink: { write: () => new Promise(() => undefined) },
  });
  await assert.rejects(async () => integration.hooks["astro:build:setup"]!({}), { code: "web.astro_build_hook_unavailable" });
  await assert.rejects(async () => integration.hooks["astro:build:setup"]!({
    updateConfig: () => { throw new Error("UPDATE_CONFIG_SECRET"); },
  }), (error: unknown) => error instanceof AstroBuildObserverError
    && error.code === "web.astro_build_setup_hook_failed"
    && !error.message.includes("UPDATE_CONFIG_SECRET"));
  let plugin: AstroVitePluginLike | null = null;
  await integration.hooks["astro:build:setup"]!({ updateConfig: (value: unknown) => {
    plugin = (value as { plugins: AstroVitePluginLike[] }).plugins[0]!;
  } });
  plugin!.configResolved({ mode: "production", base: "/", build: { outDir: "/repo/dist" }, plugins: [plugin!] });
  assert.equal(observerErrorCode(() => plugin!.buildStart.call({ meta: { viteVersion: "8.0.0" } })),
    "web.astro_build_vite_version_unsupported");
  for (const environment of ["browser", "server"] as const) {
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
  await integration.hooks["astro:config:done"]!({ config: {} });
  await integration.hooks["astro:routes:resolved"]!({ routes: [] });
  await assert.rejects(async () => integration.hooks["astro:build:done"]!({ pages: [], assets: new Map() }), {
    code: "web.astro_build_observer_timeout",
  });
  const diagnostic = astroBuildFailureDiagnostic(new Error("raw secret"), "profile");
  assert.equal(diagnostic.code, "web.astro_build_observer_failed");
  assert.equal(JSON.stringify(diagnostic).includes("raw secret"), false);
});

test("observed routes, modules, content, chunks, and assets correlate with environment-specific build evidence", async () => {
  const observation = await completeObservation({ dynamic: true });
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
  assert.ok(delta.diagnostics.some((item) => item.code === "web.astro_build_route_static_only"));
  assert.ok(delta.diagnostics.some((item) => item.code === "web.astro_build_dynamic_config_observed"));
  const events = astroBuildProtocolEvents("/repo", delta, provenance, "revision");
  assert.equal(events[0]?.event, "scan_started");
  assert.equal(events.at(-1)?.event, "scan_completed");
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
    let plugin: AstroVitePluginLike | null = null;
    await integration.hooks["astro:build:setup"]!({ updateConfig: (value: unknown) => {
      plugin = (value as { plugins: AstroVitePluginLike[] }).plugins[0]!;
    } });
    for (const environment of ["browser", "server"] as const) {
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
    await integration.hooks["astro:build:done"]!({ pages: [], assets: new Map() });
    const artifact = await readFile(path.join(root, "astro-build-observation.json"), "utf8");
    assert.equal(JSON.parse(artifact).observer, ASTRO_BUILD_OBSERVER);
    await assert.rejects(async () => integration.hooks["astro:build:done"]!({ pages: [], assets: new Map() }), {
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
