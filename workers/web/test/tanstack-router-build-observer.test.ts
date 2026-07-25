import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { pathToFileURL } from "node:url";
import {
  TANSTACK_ROUTER_BUILD_CAPABILITY,
  TANSTACK_ROUTER_BUILD_OBSERVER,
  TanStackRouterBuildObserverError,
  buildTanStackRouterObservedGraph,
  createTanStackRouterBuildObserverPlugin,
  detectTanStackRouterBuildCapability,
  tanStackRouterBuildFailureDiagnostic,
  tanStackRouterBuildProtocolEvents,
  validateTanStackRouterBuildObservation,
  type TanStackRouterBuildObservation,
  type TanStackRouterBuildProvenance,
  type TanStackRouterVitePluginLike,
} from "../src/tanstack-router-build-observer";
import type { GraphNode } from "../src/types";

const DIGEST = "c".repeat(64);
const GENERATOR = { name: "tanstack:router-generator" };
const provenance: TanStackRouterBuildProvenance = {
  build_run_id: "tanstack-router-build-run",
  profile_id: "tanstack-router-build-profile",
  command_plan_digest: DIGEST,
  toolchain_executable_digest: DIGEST,
  environment_key_set_digest: DIGEST,
  validated_output_digest: DIGEST,
};

function errorCode(operation: () => unknown): string {
  try {
    operation();
  } catch (error) {
    assert.ok(error instanceof TanStackRouterBuildObserverError);
    return error.code;
  }
  assert.fail("expected TanStackRouterBuildObserverError");
}

function clientContext(modules: Record<string, {
  importedIds?: string[];
  dynamicallyImportedIds?: string[];
  isEntry?: boolean;
}>) {
  return {
    environment: { name: "client" },
    meta: { viteVersion: "7.2.2", rollupVersion: "4.53.3", watchMode: false },
    getModuleIds: () => Object.keys(modules).values(),
    getModuleInfo: (id: unknown) => modules[String(id)] ?? null,
  };
}

async function writeProject(root: string): Promise<Record<string, string>> {
  const source = (relative: string): string => path.join(root, relative);
  const files: Record<string, string> = {
    "src/routes/__root.tsx": `
      export const Route = createRootRoute({
        loader: () => ({ secret: "ROOT_SOURCE_SECRET" }),
        beforeLoad: () => ({ viewer: true }),
      })
    `,
    "src/routes/index.tsx": "export const Route = createFileRoute('/')({})",
    "src/routes/posts.$postId.tsx": `
      export const Route = createFileRoute('/posts/$postId')({
        loader: () => ({ post: true }),
        beforeLoad: () => ({ allowed: true }),
      })
      export const postMask = createRouteMask({
        from: '/posts/$postId',
        to: dynamicMaskTarget,
      })
    `,
    "src/routes/posts.lazy.tsx": "export const Route = createLazyFileRoute('/posts/$postId')({})",
    "src/virtual/report.tsx": "export const Route = createFileRoute('/report')({})",
    "src/code-routes.tsx": `
      const codeRoot = createRootRoute({})
      const admin = createRoute({
        getParentRoute: () => codeRoot,
        path: 'admin',
        loader: () => ({ admin: true }),
        beforeLoad: () => ({ authenticated: true }),
      })
      export const codeRouteTree = codeRoot.addChildren([admin])
    `,
  };
  const generated = `
    import { Route as rootRouteImport } from './routes/__root'
    import { Route as IndexRouteImport } from './routes/index'
    import { Route as PostsPostIdRouteImport } from './routes/posts.$postId'
    import { Route as ReportRouteImport } from './virtual/report'

    const IndexRoute = IndexRouteImport.update({
      id: '/',
      path: '/',
      getParentRoute: () => rootRouteImport,
    })
    const PostsPostIdRoute = PostsPostIdRouteImport.update({
      id: '/posts/$postId',
      path: '/posts/$postId',
      getParentRoute: () => rootRouteImport,
    }).lazy(() => import('./routes/posts.lazy').then((d) => d.Route))
    const ReportRoute = ReportRouteImport.update({
      id: '/report',
      path: '/report',
      getParentRoute: () => rootRouteImport,
    })

    declare module '@tanstack/react-router' {
      interface FileRoutesByPath {
        '/': {
          id: '/'
          path: '/'
          fullPath: '/'
          preLoaderRoute: typeof IndexRouteImport
          parentRoute: typeof rootRouteImport
        }
        '/posts/$postId': {
          id: '/posts/$postId'
          path: '/posts/$postId'
          fullPath: '/posts/$postId'
          preLoaderRoute: typeof PostsPostIdRouteImport
          parentRoute: typeof rootRouteImport
        }
        '/report': {
          id: '/report'
          path: '/report'
          fullPath: '/report'
          preLoaderRoute: typeof ReportRouteImport
          parentRoute: typeof rootRouteImport
        }
      }
    }
  `;
  files["src/routeTree.gen.ts"] = generated;
  for (const [relative, contents] of Object.entries(files)) {
    await mkdir(path.dirname(source(relative)), { recursive: true });
    await writeFile(source(relative), contents, "utf8");
  }
  return Object.fromEntries(Object.keys(files).map((relative) => [relative, source(relative)]));
}

async function observe(root: string, output?: (value: TanStackRouterBuildObservation) => void): Promise<TanStackRouterBuildObservation> {
  const files = await writeProject(root);
  const observations: TanStackRouterBuildObservation[] = [];
  const plugin = createTanStackRouterBuildObserverPlugin({
    routerVersion: "1.170.18",
    repoRoot: root,
    basePath: "/app",
    existingVitePlugins: [GENERATOR],
    sink: { write(value) { observations.push(value); output?.(value); } },
  });
  await plugin.configResolved({
    root,
    mode: "production",
    base: "/app",
    plugins: [GENERATOR, plugin],
  });
  const modules = {
    [files["src/routeTree.gen.ts"]!]: {
      importedIds: [
        files["src/routes/__root.tsx"]!,
        files["src/routes/index.tsx"]!,
        files["src/routes/posts.$postId.tsx"]!,
        files["src/virtual/report.tsx"]!,
      ],
      dynamicallyImportedIds: [files["src/routes/posts.lazy.tsx"]!],
      isEntry: true,
    },
    [files["src/routes/__root.tsx"]!]: { importedIds: [] },
    [files["src/routes/index.tsx"]!]: { importedIds: [] },
    [files["src/routes/posts.$postId.tsx"]!]: { importedIds: [] },
    [files["src/routes/posts.lazy.tsx"]!]: { importedIds: [] },
    [files["src/virtual/report.tsx"]!]: { importedIds: [] },
    [files["src/code-routes.tsx"]!]: { importedIds: [], isEntry: true },
  };
  const context = clientContext(modules);
  plugin.buildStart.call(context);
  for (const [relative, absolute] of Object.entries(files)) {
    plugin.transform.call(context, await readFile(absolute, "utf8"), absolute);
  }
  plugin.generateBundle.call(context, {}, {
    "assets/router.js": {
      type: "chunk",
      fileName: "assets/router.js",
      code: "OUTPUT_CHUNK_SECRET",
      isEntry: true,
      modules: Object.fromEntries(Object.keys(modules).map((id) => [id, {}])),
      imports: [],
      dynamicImports: [],
    },
  });
  await plugin.closeBundle.call(context);
  assert.equal(observations.length, 1);
  return observations[0]!;
}

test("TanStack Router v1 capability requires the generator for generated route trees", () => {
  assert.equal(
    detectTanStackRouterBuildCapability("1.170.18", undefined, undefined, undefined, [GENERATOR]).capability,
    TANSTACK_ROUTER_BUILD_CAPABILITY,
  );
  for (const version of ["0.99.0", "2.0.0", "1.2.3-beta.1", "latest"]) {
    assert.equal(
      errorCode(() => detectTanStackRouterBuildCapability(version, undefined, undefined, undefined, [GENERATOR])),
      "web.tanstack_router_build_version_unsupported",
    );
  }
  assert.equal(
    errorCode(() => detectTanStackRouterBuildCapability("1.170.18")),
    "web.tanstack_router_build_generator_plugin_missing",
  );
  assert.equal(
    detectTanStackRouterBuildCapability("1.170.18", null).generated_route_tree,
    null,
  );
});

test("observer rejects a Vite base that differs from the canonical route base", async () => {
  const plugin = createTanStackRouterBuildObserverPlugin({
    routerVersion: "1.170.18",
    repoRoot: "/repo",
    generatedRouteTree: null,
    basePath: "/router",
    sink: { write() {} },
  });
  await assert.rejects(
    async () => plugin.configResolved({
      root: "/repo",
      mode: "production",
      base: "/different",
      plugins: [plugin],
    }),
    { code: "web.tanstack_router_build_base_path_mismatch" },
  );
});

test("observer captures generated, virtual, lazy, code, handler, and dynamic-mask evidence without code", async () => {
  const root = await mkdtemp(path.join(tmpdir(), "depgraph-router-observer-"));
  try {
    const observation = await observe(root);
    assert.equal(observation.observer, TANSTACK_ROUTER_BUILD_OBSERVER);
    assert.equal(observation.route_count, 6);
    assert.ok(observation.routes.some((route) => route.source_kind === "virtual" && route.full_path === "/app/report"));
    assert.ok(observation.routes.some((route) => route.source_kind === "code" && route.full_path === "/app/admin"));
    const post = observation.routes.find((route) => route.full_path === "/app/posts/$postId");
    assert.equal(post?.lazy_source_path, "src/routes/posts.lazy.tsx");
    assert.equal(post?.has_loader, true);
    assert.equal(post?.has_before_load, true);
    assert.deepEqual(observation.masks, [{
      source_path: "src/routes/posts.$postId.tsx",
      from: "/app/posts/$postId",
      to: null,
    }]);
    const serialized = JSON.stringify(observation);
    assert.equal(serialized.includes(root), false);
    for (const secret of ["ROOT_SOURCE_SECRET", "OUTPUT_CHUNK_SECRET"]) {
      assert.equal(serialized.includes(secret), false);
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("equivalent checkouts produce byte-identical observations", async () => {
  const firstRoot = await mkdtemp(path.join(tmpdir(), "depgraph-router-first-"));
  const secondRoot = await mkdtemp(path.join(tmpdir(), "depgraph-router-second-"));
  try {
    const [first, second] = await Promise.all([observe(firstRoot), observe(secondRoot)]);
    assert.equal(JSON.stringify(first), JSON.stringify(second));
  } finally {
    await rm(firstRoot, { recursive: true, force: true });
    await rm(secondRoot, { recursive: true, force: true });
  }
});

test("observed graph reuses an exact static route and preserves unmatched targets as unresolved", async () => {
  const root = await mkdtemp(path.join(tmpdir(), "depgraph-router-graph-"));
  try {
    const observation = await observe(root);
    const staticPost: GraphNode = {
      id: "route:static-post",
      kind: "route",
      locator: "route://static/app/posts/$postId",
      display_name: "/app/posts/$postId",
      properties: {
        framework: "tanstack-router",
        route_pattern: "/app/posts/$postId",
        source_path: "src/routes/posts.$postId.tsx",
      },
    };
    const mismatchedReport: GraphNode = {
      id: "route:static-report-mismatch",
      kind: "route",
      locator: "route://static/app/report",
      display_name: "/app/report",
      properties: {
        framework: "tanstack-router",
        route_pattern: "/app/report",
        source_path: "src/routes/report.tsx",
      },
    };
    const delta = buildTanStackRouterObservedGraph({
      observation,
      provenance,
      baseNodes: [staticPost, mismatchedReport],
    });
    assert.equal(
      delta.nodes.filter((node) => node.kind === "route"
        && node.properties.route_pattern === "/app/posts/$postId").length,
      1,
    );
    assert.ok(delta.nodes.some((node) => node.id === staticPost.id));
    assert.ok(delta.edges.some((edge) => edge.kind === "dynamic_imports"));
    assert.ok(delta.edges.some((edge) => edge.kind === "loads"));
    assert.ok(delta.edges.some((edge) => edge.kind === "before_load"));
    assert.ok(delta.edges.some((edge) => edge.kind === "masks_to"
      && edge.resolution_status === "unresolved"));
    assert.ok(delta.edges.some((edge) => edge.kind === "observes_definition"
      && edge.resolution_status === "unresolved"));
    assert.ok(delta.nodes.some((node) => node.kind === "unknown_target"
      && node.properties.reason === "framework_build_dynamic_target_unmatched"));
    const events = tanStackRouterBuildProtocolEvents(root, delta, provenance, "revision");
    assert.equal(events[0]?.event, "scan_started");
    assert.equal(events.at(-1)?.event, "scan_completed");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("tampering, unsupported Vite, failed builds, raw crashes, and sink timeouts fail closed", async () => {
  const root = await mkdtemp(path.join(tmpdir(), "depgraph-router-failure-"));
  try {
    const observation = await observe(root);
    const tampered = structuredClone(observation);
    tampered.routes[0]!.full_path = "/tampered";
    assert.equal(
      errorCode(() => validateTanStackRouterBuildObservation(tampered)),
      "web.tanstack_router_build_observation_contract_invalid",
    );
    const diagnostic = tanStackRouterBuildFailureDiagnostic(new Error("RAW_CRASH_SECRET"), "profile");
    assert.equal(diagnostic.code, "web.tanstack_router_build_observer_failed");
    assert.equal(JSON.stringify(diagnostic).includes("RAW_CRASH_SECRET"), false);

    const plugin = createTanStackRouterBuildObserverPlugin({
      routerVersion: "1.170.18",
      repoRoot: root,
      generatedRouteTree: null,
      sink: { write() {} },
    });
    await plugin.configResolved({ root, mode: "production", base: "/", plugins: [plugin] });
    assert.equal(
      errorCode(() => plugin.buildStart.call({
        environment: { name: "client" },
        meta: { viteVersion: "8.0.0" },
      })),
      "web.tanstack_router_build_vite_version_unsupported",
    );

    const timedOut = createTanStackRouterBuildObserverPlugin({
      routerVersion: "1.170.18",
      repoRoot: root,
      generatedRouteTree: null,
      timeoutMs: 10,
      sink: { write: () => new Promise(() => undefined) },
    });
    await timedOut.configResolved({ root, mode: "production", base: "/", plugins: [timedOut] });
    const current = clientContext({
      [path.join(root, "src/code-routes.tsx")]: { importedIds: [], isEntry: true },
    });
    timedOut.buildStart.call(current);
    timedOut.transform.call(current, await readFile(path.join(root, "src/code-routes.tsx"), "utf8"), path.join(root, "src/code-routes.tsx"));
    timedOut.generateBundle.call(current, {}, {});
    await assert.rejects(
      async () => timedOut.closeBundle.call(current),
      { code: "web.tanstack_router_build_observer_timeout" },
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("bundled observer writes one confined observation", async () => {
  const root = await mkdtemp(path.join(tmpdir(), "depgraph-router-entry-"));
  const output = await mkdtemp(path.join(tmpdir(), "depgraph-router-output-"));
  const previousOutput = process.env.DEPGRAPH_OUTPUT_DIR;
  const previousVersion = process.env.DEPGRAPH_TANSTACK_ROUTER_VERSION;
  try {
    const files = await writeProject(root);
    process.env.DEPGRAPH_OUTPUT_DIR = output;
    process.env.DEPGRAPH_TANSTACK_ROUTER_VERSION = "1.170.18";
    const entry = `${pathToFileURL(path.resolve("dist/tanstack-router-build-observer.mjs")).href}?test=${Date.now()}`;
    const module = await import(entry) as {
      default: (options: {
        repoRoot: string;
        basePath: string;
        existingVitePlugins: unknown[];
      }) => TanStackRouterVitePluginLike;
    };
    const plugin = module.default({ repoRoot: root, basePath: "/app", existingVitePlugins: [GENERATOR] });
    await plugin.configResolved({ root, mode: "production", base: "/app", plugins: [GENERATOR, plugin] });
    const modules = Object.fromEntries(Object.values(files).map((id) => [id, { importedIds: [] }]));
    const current = clientContext(modules);
    plugin.buildStart.call(current);
    for (const [relative, absolute] of Object.entries(files)) {
      plugin.transform.call(current, await readFile(absolute, "utf8"), absolute);
    }
    plugin.generateBundle.call(current, {}, {
      "assets/router.js": {
        type: "chunk",
        fileName: "assets/router.js",
        code: "BUNDLED_SECRET",
        isEntry: true,
        modules: Object.fromEntries(Object.values(files).map((id) => [id, {}])),
        imports: [],
        dynamicImports: [],
      },
    });
    await plugin.closeBundle.call(current);
    const artifact = await readFile(path.join(output, "tanstack-router-build-observation.json"), "utf8");
    assert.equal(JSON.parse(artifact).observer, TANSTACK_ROUTER_BUILD_OBSERVER);
    assert.equal(artifact.includes("BUNDLED_SECRET"), false);
  } finally {
    if (previousOutput === undefined) delete process.env.DEPGRAPH_OUTPUT_DIR;
    else process.env.DEPGRAPH_OUTPUT_DIR = previousOutput;
    if (previousVersion === undefined) delete process.env.DEPGRAPH_TANSTACK_ROUTER_VERSION;
    else process.env.DEPGRAPH_TANSTACK_ROUTER_VERSION = previousVersion;
    await rm(root, { recursive: true, force: true });
    await rm(output, { recursive: true, force: true });
  }
});
