import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { chmod, cp, mkdir, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { test } from "node:test";

const execute = promisify(execFile);
const fixture = fileURLToPath(new URL("./fixtures/polyglot", import.meta.url));
const frameworkCompleteFixture = fileURLToPath(new URL("./fixtures/framework-complete", import.meta.url));
const managerFixtures = fileURLToPath(new URL("./fixtures/managers", import.meta.url));
const worker = fileURLToPath(new URL("../dist/worker.mjs", import.meta.url));

async function run(
  scanId: string,
  root = fixture,
  profileConfig?: Record<string, unknown>,
): Promise<{ events: Array<Record<string, any>>; stderr: string }> {
  const result = await execute(process.execPath, [worker, "--root", root, "--scan-id", scanId], {
    maxBuffer: 16 * 1024 * 1024,
    env: profileConfig ? { ...process.env, DEPGRAPH_PROFILE_CONFIG: JSON.stringify(profileConfig) } : process.env,
  });
  return {
    events: result.stdout.trim().split("\n").filter(Boolean).map((line) => JSON.parse(line) as Record<string, any>),
    stderr: result.stderr,
  };
}

test("worker emits deterministic protocol graph without executing project code", async () => {
  const markers = [
    new URL("./fixtures/polyglot/apps/next-app/NEXT_CONFIG_EXECUTED", import.meta.url),
    new URL("./fixtures/polyglot/apps/astro-app/ASTRO_CONFIG_EXECUTED", import.meta.url),
  ];
  await Promise.all(markers.map((marker) => rm(marker, { force: true })));
  const first = await run("scan-one");
  const second = await run("scan-two");

  assert.equal(first.events[0]?.event, "scan_started");
  assert.equal(first.events[0]?.project_code_executed, false);
  assert.equal(first.events.at(-1)?.event, "scan_completed");
  assert.ok(first.events.every((event, index) => event.protocol_version === "1.0" && event.adapter === "web" && event.seq === index + 1));
  assert.match(first.stderr, /project code executed=false/u);

  const profile = first.events.find((event) => event.event === "profile_declared")?.profile;
  assert.equal(profile?.toolchain, "typescript 7.0.2");
  assert.deepEqual(
    Object.fromEntries([
      "typescript_compiler_source",
      "typescript_compiler_version",
      "typescript_compiler_selection",
      "typescript_compiler_fallback",
      "typescript_analysis_mode",
      "typescript_project_local_policy",
      "typescript_project_local_loaded",
      "typescript_typechecker_status",
      "typescript_definition_graph_status",
      "typescript_project_model_status",
      "typescript_project_config",
      "typescript_module_resolution",
      "typescript_standard_library_source",
      "typescript_standard_library_integrity",
      "typescript_release_gate",
      "typescript_semantic_graph_emission",
      "web_framework_semantic_capability",
      "web_framework_semantic_status",
      "web_framework_semantic_extractor_version",
      "web_framework_completeness_capability",
      "web_framework_completeness_status",
      "project_code_executed",
    ].map((key) => [key, profile?.properties[key]])),
    {
      typescript_compiler_source: "bundled",
      typescript_compiler_version: "7.0.2",
      typescript_compiler_selection: "bundled-only",
      typescript_compiler_fallback: "fail-closed",
      typescript_analysis_mode: "semantic-import-type-call-graph",
      typescript_project_local_policy: "metadata-only",
      typescript_project_local_loaded: "false",
      typescript_typechecker_status: "definition-import-type-call-graph-emitted",
      typescript_definition_graph_status: "ready",
      typescript_project_model_status: "ready",
      typescript_project_config: "worker-neutral-allowlist",
      typescript_module_resolution: "inventory-only",
      typescript_standard_library_source: "bundled",
      typescript_standard_library_integrity: "build-produced-pending-core-attestation",
      typescript_release_gate: "release-gate-pending",
      typescript_semantic_graph_emission: "definition-import-type-call-graph-v2",
      web_framework_semantic_capability: "framework-semantic-graph-v1",
      web_framework_semantic_status: "emitted",
      web_framework_semantic_extractor_version: "0.1.0",
      web_framework_completeness_capability: "framework-semantic-completeness-v1",
      web_framework_completeness_status: "incomplete",
      project_code_executed: "false",
    },
  );
  assert.equal(profile?.properties.typescript_static_config_files, "2");
  assert.equal(profile?.properties.typescript_path_mappings, "3");

  const nodes = first.events.filter((event) => event.event === "node_upsert").map((event) => event.node);
  const sites = first.events.filter((event) => event.event === "dependency_site").map((event) => event.site);
  const edges = first.events.filter((event) => event.event === "edge_upsert").map((event) => event.edge);
  const diagnostics = first.events.filter((event) => event.event === "diagnostic").map((event) => event.diagnostic);
  assert.ok(diagnostics.filter((diagnostic) => (
    diagnostic.code === "web.typescript_semantic_scaffold_diagnostic"
    && /TS2307.*@shared\/index/u.test(diagnostic.message)
  )).every((diagnostic) => diagnostic.severity === "info"));
  const completedFiles = first.events.filter((event) => event.event === "file_completed");
  const completed = first.events.at(-1)?.coverage;
  assert.ok(nodes.some((node) => node.kind === "workspace"));
  assert.ok(nodes.some((node) => node.kind === "unknown_target"));
  assert.ok(nodes.some((node) => node.kind === "route" && node.locator.includes("next") && node.locator.endsWith("/shop/products/$id")));
  assert.ok(nodes.some((node) => node.kind === "route" && node.locator.includes("astro") && node.locator.endsWith("/docs/blog/$slug")));
  assert.ok(nodes.some((node) => node.kind === "route" && node.locator.includes("tanstack-router") && node.locator.endsWith("/router/posts/$postId")));
  assert.ok(nodes.some((node) => node.kind === "route" && node.locator.includes("tanstack-start") && node.locator.endsWith("/account/$accountId")));
  assert.ok(nodes.some((node) => node.kind === "route" && node.locator.endsWith("/shop/icon.png")));
  assert.ok(nodes.some((node) => node.kind === "route" && node.locator.endsWith("/shop/robots.txt")));
  assert.ok(nodes.some((node) => node.kind === "route" && node.locator.endsWith("/shop/photo/$slug*")));
  assert.ok(nodes.some((node) => node.kind === "route" && node.locator.endsWith("/shop/docs/$parts*?")));
  assert.deepEqual([...new Set(sites.map((site) => site.resolution_status))].sort(), ["candidates", "external", "resolved", "unresolved"]);
  assert.ok(sites.some((site) => site.kind === "type_import"));
  const sharedSemanticImport = sites.find((site) => (
    site.kind === "web_import"
    && site.specifier === "@shared/index"
    && site.evidence[0]?.kind === "semantic"
    && site.evidence[0]?.properties.occurrence_kind === "named_import"
  ));
  assert.equal(sharedSemanticImport?.resolution_status, "resolved");
  assert.equal(sharedSemanticImport?.precision, "exact");
  assert.equal(sharedSemanticImport?.target_ids.length, 1);
  const conditionalExport = sites.find((site) => site.specifier === "@fixture/shared" && site.kind === "import");
  assert.equal(conditionalExport?.resolution_status, "candidates");
  assert.match(conditionalExport?.reason ?? "", /package_exports_conditions=browser,node/u);
  assert.doesNotMatch(JSON.stringify(conditionalExport?.condition), /package\.exports\.condition/u);
  const conditionalEdges = edges.filter((edge) => edge.site_id === conditionalExport?.id);
  const nodeById = new Map(nodes.map((node) => [node.id, node]));
  for (const site of sites) {
    if (site.resolution_status === "resolved") assert.equal(site.target_ids.length, 1, site.id);
    if (site.resolution_status === "external") {
      assert.equal(site.target_ids.length, 1, site.id);
      assert.equal(nodeById.get(site.target_ids[0])?.kind, "external_system", site.id);
    }
    if (site.resolution_status === "candidates") assert.ok(site.target_ids.length >= 1, site.id);
    if (site.resolution_status === "unresolved") {
      assert.equal(site.target_ids.length, 1, site.id);
      assert.equal(nodeById.get(site.target_ids[0])?.kind, "unknown_target", site.id);
    }
    assert.ok(edges.filter((edge) => edge.site_id === site.id).every((edge) => (
      edge.resolution_status === site.resolution_status
    )), site.id);
  }
  const routeSites = sites.filter((site) => site.kind === "route_entry");
  const routeSource = (site: Record<string, any>) => nodeById.get(site.source)?.display_name;
  for (const special of ["forbidden.tsx", "unauthorized.tsx", "global-not-found.tsx"]) {
    assert.ok(routeSites.some((site) => site.specifier === "/shop" && routeSource(site)?.endsWith(`/src/app/${special}`)));
  }
  assert.ok(routeSites.some((site) => site.specifier === "/shop/manifest.json" && routeSource(site)?.endsWith("/src/app/manifest.json")));
  assert.ok(!routeSites.some((site) => routeSource(site)?.includes("/src/app/_components/")));
  assert.ok(!nodes.some((node) => node.kind === "route" && ["/-components", "/-private/page"].includes(node.properties.pattern)));
  const browserEdge = conditionalEdges.find((edge) => nodeById.get(edge.target)?.display_name?.endsWith("/src/browser.ts"));
  const serverEdge = conditionalEdges.find((edge) => nodeById.get(edge.target)?.display_name?.endsWith("/src/server.ts"));
  assert.match(JSON.stringify(browserEdge?.condition), /"key":"environment","value":"browser"/u);
  assert.match(JSON.stringify(serverEdge?.condition), /"key":"environment","value":"server"/u);
  assert.notDeepEqual(browserEdge?.condition, serverEdge?.condition);
  assert.ok(sites.some((site) => site.kind === "dynamic_import" && site.reason === "computed_specifier"));
  assert.ok(sites.every((site) => site.evidence.length > 0 && site.evidence[0].start_line > 0));
  assert.ok(sites.some((site) => site.evidence.some((item: any) => item.extractor === "astro-compiler-frontmatter" && item.extractor_version === "4.0.0")));
  assert.ok(diagnostics.some((diagnostic) => diagnostic.code === "web.executable_config_not_executed"));
  assert.ok(diagnostics.some((diagnostic) => diagnostic.code === "web.static_config_literal_applied"));
  assert.ok(diagnostics.some((diagnostic) => diagnostic.code === "web.static_config_runtime_ignored"));
  assert.ok(diagnostics.some((diagnostic) => diagnostic.code === "web.tanstack_route_tree_drift"));
  assert.equal(completed.project_code_executed, false);
  assert.ok(Number(profile?.properties.typescript_project_root_files) > 0);
  assert.ok(Number(profile?.properties.typescript_standard_library_files) > 0);
  assert.ok(Number(profile?.properties.typescript_typechecker_queries) > 1);
  const semanticNodes = nodes.filter((node) => node.kind === "symbol" || node.kind === "type");
  const semanticEdges = edges.filter((edge) => (
    edge.phase === "semantic"
    && edge.evidence[0]?.properties?.analysis_mode === "semantic-import-type-call-graph"
  ));
  const semanticSites = sites.filter((site) => (
    site.evidence[0]?.kind === "semantic"
    && site.evidence[0]?.properties?.analysis_mode === "semantic-import-type-call-graph"
  ));
  const semanticCallSites = semanticSites.filter((site) => site.kind === "call");
  const moduleInitializers = semanticNodes.filter((node) => (
    node.kind === "symbol" && node.properties.symbol_kind === "generated_module_initializer"
  ));
  const definitionEdges = semanticEdges.filter((edge) => edge.site_id === null);
  const dependencySemanticEdges = semanticEdges.filter((edge) => edge.site_id !== null);
  assert.equal(Number(profile?.properties.typescript_semantic_node_count), semanticNodes.length);
  assert.equal(Number(profile?.properties.typescript_semantic_relation_count), semanticEdges.length);
  assert.equal(Number(profile?.properties.typescript_semantic_site_count), semanticSites.length);
  assert.equal(Number(profile?.properties.typescript_semantic_call_site_count), semanticCallSites.length);
  assert.equal(profile?.properties.typescript_semantic_issue_count, "0");
  assert.ok(semanticNodes.some((node) => node.kind === "symbol" && node.properties.symbol_kind === "function"));
  assert.ok(semanticNodes.some((node) => node.kind === "symbol" && node.properties.symbol_kind === "variable"));
  assert.ok(semanticNodes.some((node) => node.kind === "type" && node.properties.type_kind === "class"));
  assert.ok(semanticNodes.some((node) => node.kind === "type" && node.properties.type_kind === "generic_instance"));
  assert.deepEqual([...new Set(definitionEdges.map((edge) => edge.kind))].sort(), ["declares", "extends", "implements", "instantiates"]);
  assert.deepEqual([...new Set(semanticSites.map((site) => site.kind))].sort(), ["call", "type_use", "web_import", "web_reexport"]);
  assert.deepEqual([...new Set(dependencySemanticEdges.map((edge) => edge.kind))].sort(), ["calls", "imports", "may_call", "reexports", "type_uses"]);
  assert.ok(moduleInitializers.length > 0);
  assert.ok(moduleInitializers.every((node) => (
    node.properties.generated === true
    && node.properties.canonical_identity?.identity_kind === "generated"
    && node.properties.canonical_identity?.generated_from === definitionEdges
      .find((edge) => edge.kind === "declares" && edge.target === node.id)?.source
  )));
  assert.deepEqual(
    [...new Set(semanticCallSites.map((site) => site.resolution_status))].sort(),
    ["candidates", "external", "resolved", "unresolved"],
  );
  assert.ok(semanticCallSites.every((site) => (
    site.target_ids.length >= 1
    && nodeById.get(site.source)?.kind === "symbol"
    && site.evidence[0]?.properties.analysis_mode === "semantic-import-type-call-graph"
    && typeof site.evidence[0]?.properties.call_kind === "string"
    && typeof site.evidence[0]?.properties.dispatch === "string"
    && (site.resolution_status !== "candidates" || (
      site.precision === "overapprox"
      && typeof site.evidence[0]?.properties.algorithm === "string"
    ))
  )));
  for (const site of semanticCallSites) {
    const targets = (site.target_ids as string[]).map((targetId: string) => nodeById.get(targetId));
    if (site.resolution_status === "candidates") {
      assert.ok(targets.every((target: { kind?: string } | undefined) => target?.kind === "symbol"));
    } else {
      assert.equal(targets[0]?.kind, site.resolution_status === "resolved"
        ? "symbol"
        : site.resolution_status === "external"
          ? "external_system"
          : "unknown_target");
    }
    const callEdges = dependencySemanticEdges.filter((edge) => edge.site_id === site.id);
    assert.equal(callEdges.length, site.target_ids.length);
    assert.ok(callEdges.every((edge) => (
      edge.kind === (site.resolution_status === "candidates" ? "may_call" : "calls")
      && JSON.stringify(edge.condition) === JSON.stringify(site.condition)
    )));
  }
  assert.ok(edges.some((edge) => edge.kind === "may_call"));
  assert.ok(definitionEdges.every((edge) => edge.resolution_status === "resolved" && edge.precision === "exact"));
  assert.ok(semanticEdges.every((edge) => edge.evidence[0]?.kind === "semantic" && edge.evidence[0]?.properties.profile_id === profile.id));
  assert.ok(semanticSites.every((site) => site.evidence[1]?.kind === "source"));

  const allFrameworkNodes = nodes.filter((node) => (
    node.properties.canonical_identity?.framework === "next"
    || node.properties.canonical_identity?.framework === "astro"
    || node.properties.canonical_identity?.framework === "tanstack-router"
    || node.properties.canonical_identity?.framework === "tanstack-start"
  ));
  const allFrameworkSites = sites.filter((site) => (
    site.evidence[0]?.properties?.contract_version === "framework-semantic-graph-v1"
  ));
  const allFrameworkEdges = edges.filter((edge) => (
    edge.evidence[0]?.properties?.contract_version === "framework-semantic-graph-v1"
  ));
  const frameworkNodes = allFrameworkNodes.filter((node) => (
    node.properties.framework === "next"
    && node.properties.canonical_identity?.framework === "next"
  ));
  const frameworkSites = allFrameworkSites.filter((site) => (
    site.evidence[0]?.properties?.contract_version === "framework-semantic-graph-v1"
    && site.evidence[0]?.properties?.framework === "next"
  ));
  const frameworkEdges = allFrameworkEdges.filter((edge) => (
    edge.evidence[0]?.properties?.contract_version === "framework-semantic-graph-v1"
    && edge.evidence[0]?.properties?.framework === "next"
  ));
  assert.equal(Number(profile?.properties.web_framework_semantic_node_count), allFrameworkNodes.length);
  assert.equal(Number(profile?.properties.web_framework_semantic_site_count), allFrameworkSites.length);
  assert.equal(Number(profile?.properties.web_framework_semantic_edge_count), allFrameworkEdges.length);
  assert.deepEqual(
    [...new Set(frameworkNodes.map((node) => node.kind))].sort(),
    ["component", "route"],
  );
  assert.deepEqual(
    [...new Set(frameworkEdges.map((edge) => edge.kind))].sort(),
    ["client_boundary", "parent_route", "renders", "route_entry", "server_boundary"],
  );
  const productRoute = frameworkNodes.find((node) => (
    node.kind === "route"
    && node.properties.canonical_identity?.router_instance?.endsWith(":app")
    && node.properties.canonical_identity?.route_pattern === "/shop/products/$id"
    && node.properties.canonical_identity?.route_kind === "next-app-page"
  ));
  const interceptedRoute = frameworkNodes.find((node) => (
    node.kind === "route"
    && node.properties.canonical_identity?.route_pattern === "/shop/photo/$slug*"
  ));
  assert.deepEqual(productRoute?.properties.route_groups, ["(shop)"]);
  assert.deepEqual(productRoute?.properties.canonical_identity?.route_groups, ["(shop)"]);
  assert.deepEqual(interceptedRoute?.properties.parallel_slots, ["@modal"]);
  assert.deepEqual(interceptedRoute?.properties.canonical_identity?.parallel_slots, ["@modal"]);
  assert.deepEqual(interceptedRoute?.properties.intercepting_segments, ["(.)photo"]);
  assert.deepEqual(interceptedRoute?.properties.canonical_identity?.intercepting_segments, ["(.)photo"]);

  const productComponent = frameworkNodes.find((node) => node.kind === "component" && node.display_name === "Product");
  const clientComponent = frameworkNodes.find((node) => node.kind === "component" && node.display_name === "ClientPanel");
  const lazyComponent = frameworkNodes.find((node) => node.kind === "component" && node.display_name === "LazyPanel");
  const getComponent = frameworkNodes.find((node) => node.kind === "component" && node.display_name === "GET");
  const sharedHandlerRoute = frameworkNodes.find((node) => (
    node.kind === "route"
    && node.properties.canonical_identity?.route_pattern === "/shop/api/shared"
  ));
  const sharedHandlerComponents = frameworkNodes.filter((node) => (
    node.kind === "component"
    && node.properties.source_path === "apps/next-app/src/app/api/shared/route.ts"
  ));
  assert.deepEqual(productComponent?.properties.directives, ["use cache"]);
  assert.equal(productComponent?.properties.runtime, "edge");
  assert.equal(clientComponent?.properties.environment, "browser");
  assert.deepEqual(clientComponent?.properties.directives, ["use client"]);
  assert.deepEqual(getComponent?.properties.directives, ["use server"]);
  assert.deepEqual(
    sharedHandlerComponents.map((node) => node.properties.component_kind).sort(),
    ["next-app-route-handler-get", "next-app-route-handler-post"],
  );
  assert.equal(new Set(sharedHandlerComponents.map((node) => JSON.stringify(node.properties.source_span))).size, 1);

  const frameworkEdge = (kind: string, sourceId: string | undefined, targetId: string | undefined) => frameworkEdges.find((edge) => (
    edge.kind === kind && edge.source === sourceId && edge.target === targetId
  ));
  const clientBoundary = frameworkEdge("client_boundary", productComponent?.id, clientComponent?.id);
  const serverBoundary = frameworkEdge("server_boundary", getComponent?.id, getComponent?.id);
  const literalDynamicRender = frameworkEdge("renders", productComponent?.id, lazyComponent?.id);
  const sharedHandlerIds = new Set(sharedHandlerComponents.map((node) => node.id));
  const sharedHandlerRenders = frameworkEdges.filter((edge) => (
    edge.kind === "renders"
    && edge.source === sharedHandlerRoute?.id
    && sharedHandlerIds.has(edge.target)
  ));
  const unresolvedDynamicRender = frameworkEdges.find((edge) => (
    edge.kind === "renders"
    && edge.source === productComponent?.id
    && edge.resolution_status === "unresolved"
  ));
  const unresolvedDynamicSites = frameworkSites.filter((site) => (
    site.kind === "renders"
    && site.source === productComponent?.id
    && site.resolution_status === "unresolved"
  ));
  assert.equal(clientBoundary?.precision, "exact");
  assert.match(JSON.stringify(clientBoundary?.condition), /"next\.boundary","value":"use client"/u);
  assert.equal(serverBoundary?.precision, "exact");
  assert.match(JSON.stringify(serverBoundary?.condition), /"next\.boundary","value":"use server"/u);
  assert.equal(literalDynamicRender?.resolution_status, "resolved");
  assert.equal(literalDynamicRender?.evidence[0]?.properties.occurrence_kind, "next_dynamic_render");
  assert.equal(sharedHandlerRenders.length, 2);
  assert.equal(new Set(sharedHandlerRenders.map((edge) => edge.site_id)).size, 2);
  assert.deepEqual(
    sharedHandlerRenders.map((edge) => (
      edge.condition.conditions?.find((condition: Record<string, any>) => condition.key === "next.method")?.value
    )).sort(),
    ["GET", "POST"],
  );
  assert.ok(sharedHandlerRenders.every((edge) => frameworkSites.some((site) => (
    site.id === edge.site_id
    && site.source === sharedHandlerRoute?.id
    && site.target_ids.length === 1
    && site.target_ids[0] === edge.target
  ))));
  assert.equal(unresolvedDynamicRender?.precision, "heuristic");
  assert.equal(nodeById.get(unresolvedDynamicRender?.target)?.kind, "unknown_target");
  assert.deepEqual(
    unresolvedDynamicSites.map((site) => site.reason).sort(),
    ["next_dynamic_import_shape_unsupported", "next_dynamic_non_literal_import"],
  );
  assert.match(JSON.stringify(frameworkEdge("renders", productRoute?.id, productComponent?.id)?.condition), /"next\.runtime","value":"edge"/u);
  assert.match(JSON.stringify(frameworkEdge("renders", productRoute?.id, productComponent?.id)?.condition), /"next\.cache","value":"use cache"/u);
  assert.ok(diagnostics.some((diagnostic) => (
    diagnostic.code === "web.next_dynamic_import_unresolved"
    && diagnostic.path === "apps/next-app/src/app/(shop)/products/[id]/page.tsx"
  )));
  assert.ok(diagnostics.some((diagnostic) => (
    diagnostic.code === "web.next_dynamic_import_unresolved"
    && /supported direct/u.test(diagnostic.message)
  )));

  const astroNodes = allFrameworkNodes.filter((node) => node.properties.canonical_identity?.framework === "astro");
  const astroSites = allFrameworkSites.filter((site) => site.evidence[0]?.properties?.framework === "astro");
  const astroEdges = allFrameworkEdges.filter((edge) => edge.evidence[0]?.properties?.framework === "astro");
  assert.deepEqual([...new Set(astroNodes.map((node) => node.kind))].sort(), ["component", "route"]);
  assert.deepEqual(
    [...new Set(astroEdges.map((edge) => edge.kind))].sort(),
    ["client_boundary", "handled_by", "hydrates", "loads", "renders", "route_entry", "server_boundary"],
  );
  const astroPage = astroNodes.find((node) => (
    node.kind === "component"
    && node.properties.source_path === "apps/astro-app/src/pages/blog/[slug].astro"
  ));
  const astroCard = astroNodes.find((node) => (
    node.kind === "component"
    && node.properties.source_path === "apps/astro-app/src/components/Card.astro"
  ));
  const astroAlternative = astroNodes.find((node) => (
    node.kind === "component"
    && node.properties.source_path === "apps/astro-app/src/components/Alternative.astro"
  ));
  const astroInteractiveServer = astroNodes.find((node) => (
    node.kind === "component"
    && node.display_name === "Interactive"
    && node.properties.environment === "server"
  ));
  const astroInteractiveBrowser = astroNodes.find((node) => (
    node.kind === "component"
    && node.display_name === "Interactive"
    && node.properties.environment === "browser"
  ));
  assert.equal(astroInteractiveServer?.properties.component_kind, "astro-imported-script-component");
  assert.equal(typeof astroInteractiveServer?.properties.typescript_definition_id, "string");
  const exactCardRender = astroEdges.find((edge) => (
    edge.kind === "renders"
    && edge.source === astroPage?.id
    && edge.target === astroCard?.id
    && edge.evidence[0]?.properties.occurrence_kind === "astro_component_render"
  ));
  assert.equal(exactCardRender?.resolution_status, "resolved");
  assert.equal(exactCardRender?.precision, "exact");
  assert.equal(exactCardRender?.evidence[0]?.properties.occurrence_kind, "astro_component_render");
  assert.equal(exactCardRender?.evidence[1]?.kind, "source");

  const hydrationSites = astroSites.filter((site) => site.kind === "hydrates");
  assert.deepEqual(
    hydrationSites.map((site) => site.evidence[0]?.properties.directive).sort(),
    ["client:load", "client:media", "client:only"],
  );
  assert.ok(hydrationSites.every((site) => (
    site.resolution_status === "resolved"
    && site.precision === "exact"
    && site.target_ids.length === 1
    && site.target_ids[0] === astroInteractiveBrowser?.id
    && /"environment","value":"browser"/u.test(JSON.stringify(site.condition))
    && /"astro\.directive","value":"client:/u.test(JSON.stringify(site.condition))
  )));
  assert.equal(astroEdges.filter((edge) => edge.kind === "client_boundary").length, 3);
  const deferredBoundary = astroEdges.find((edge) => edge.kind === "server_boundary" && edge.source === astroPage?.id);
  assert.equal(deferredBoundary?.resolution_status, "resolved");
  assert.match(JSON.stringify(deferredBoundary?.condition), /"astro\.directive","value":"server:defer"/u);

  const dynamicRender = astroSites.find((site) => site.kind === "renders" && site.specifier === "Dynamic");
  assert.equal(dynamicRender?.resolution_status, "candidates");
  assert.equal(dynamicRender?.precision, "overapprox");
  assert.equal(dynamicRender?.reason, "multiple_closed_frontmatter_component_targets");
  assert.equal(dynamicRender?.evidence[0]?.properties.algorithm, "astro-closed-frontmatter-component-flow-v1");
  assert.deepEqual(new Set(dynamicRender?.target_ids), new Set([astroCard?.id, astroAlternative?.id]));
  const missingRender = astroSites.find((site) => site.kind === "renders" && site.specifier === "Missing");
  assert.equal(missingRender?.resolution_status, "unresolved");
  assert.equal(nodeById.get(missingRender?.target_ids[0])?.kind, "unknown_target");
  assert.equal(missingRender?.reason, "relative_target_not_found");
  const brokenDirective = astroSites.find((site) => (
    site.kind === "renders" && site.reason === "multiple_astro_environment_directives"
  ));
  assert.equal(brokenDirective?.resolution_status, "unresolved");
  assert.equal(nodeById.get(brokenDirective?.target_ids[0])?.kind, "unknown_target");

  const assetLoad = astroSites.find((site) => site.kind === "loads" && site.specifier.endsWith("hero.svg"));
  assert.equal(assetLoad?.resolution_status, "resolved");
  assert.equal(nodeById.get(assetLoad?.target_ids[0])?.kind, "file");
  assert.equal(nodeById.get(assetLoad?.target_ids[0])?.properties.path, "apps/astro-app/src/assets/hero.svg");
  const collectionLoad = astroSites.find((site) => site.kind === "loads" && site.specifier === "astro:content/posts");
  const entryLoad = astroSites.find((site) => site.kind === "loads" && site.specifier === "astro:content/posts/one");
  assert.equal(collectionLoad?.resolution_status, "candidates");
  assert.equal(collectionLoad?.target_ids.length, 2);
  assert.equal(collectionLoad?.evidence[0]?.properties.algorithm, "astro-static-content-collection-v1");
  assert.equal(entryLoad?.resolution_status, "resolved");
  assert.equal(nodeById.get(entryLoad?.target_ids[0])?.properties.path, "apps/astro-app/src/content/posts/one.md");

  const endpointHandler = astroEdges.find((edge) => edge.kind === "handled_by");
  assert.equal(nodeById.get(endpointHandler?.target)?.kind, "symbol");
  assert.match(JSON.stringify(endpointHandler?.condition), /"astro\.method","value":"GET"/u);
  const cardFrontmatterImports = sites.filter((site) => (
    site.specifier === "../../components/Card.astro"
    && site.evidence.some((item: Record<string, any>) => item.extractor === "astro-compiler-frontmatter")
    && site.evidence[0]?.properties?.contract_version !== "framework-semantic-graph-v1"
  ));
  assert.equal(cardFrontmatterImports.length, 1);
  assert.ok(diagnostics.some((diagnostic) => (
    diagnostic.code === "web.unsupported_syntax"
    && diagnostic.path === "apps/astro-app/src/components/Broken.astro"
  )));
  assert.ok(diagnostics.some((diagnostic) => (
    diagnostic.code === "web.astro_component_unresolved"
    && diagnostic.path === "apps/astro-app/src/pages/blog/[slug].astro"
  )));

  const tanstackNodes = allFrameworkNodes.filter((node) => node.properties.canonical_identity?.framework === "tanstack-router");
  const tanstackSites = allFrameworkSites.filter((site) => site.evidence[0]?.properties?.framework === "tanstack-router");
  const tanstackEdges = allFrameworkEdges.filter((edge) => edge.evidence[0]?.properties?.framework === "tanstack-router");
  assert.deepEqual([...new Set(tanstackNodes.map((node) => node.kind))].sort(), ["component", "route"]);
  assert.deepEqual(
    [...new Set(tanstackEdges.map((edge) => edge.kind))].sort(),
    ["before_load", "loads", "masks_to", "navigates_to", "parent_route", "renders", "route_entry"],
  );
  const tanstackRoute = (pattern: string, routeKind: string) => tanstackNodes.find((node) => (
    node.kind === "route"
    && node.properties.route_pattern === pattern
    && node.properties.route_kind === routeKind
  ));
  const fileRoot = tanstackRoute("/router", "tanstack-file-root-route");
  const codeRoot = tanstackNodes.find((node) => (
    node.kind === "route"
    && node.properties.route_pattern === "/router"
    && node.properties.route_kind === "tanstack-code-root-route"
    && node.properties.source_path === "apps/router/src/code-routes.tsx"
  ));
  const codeChild = tanstackRoute("/router/code", "tanstack-code-route");
  const lazyPosts = tanstackRoute("/router/posts", "tanstack-lazy-file-route");
  const virtualRoute = tanstackRoute("/router/virtual", "tanstack-virtual-route");
  assert.ok(fileRoot && codeRoot && codeChild && lazyPosts && virtualRoute);
  assert.ok(!tanstackNodes.some((node) => node.kind === "route" && node.properties.route_pattern === "/router/orphan"));
  const codeParentSites = tanstackSites.filter((site) => (
    site.kind === "parent_route"
    && site.source === codeChild?.id
    && site.target_ids[0] === codeRoot?.id
  ));
  assert.deepEqual(
    codeParentSites.map((site) => site.evidence[0]?.properties.occurrence_kind).sort(),
    ["tanstack_add_children_registration", "tanstack_declared_parent"],
  );
  assert.ok(tanstackSites.some((site) => (
    site.kind === "parent_route"
    && site.resolution_status === "candidates"
    && site.evidence[0]?.properties.algorithm === "finite-conditional-route-reference-set-v1"
  )));
  assert.ok(tanstackSites.some((site) => (
    site.kind === "parent_route"
    && site.resolution_status === "unresolved"
    && site.reason === "tanstack_runtime_child_registration"
  )));
  assert.ok(tanstackEdges.some((edge) => edge.kind === "renders" && edge.source === lazyPosts?.id));
  assert.ok(tanstackSites.filter((site) => site.kind === "navigates_to" || site.kind === "masks_to")
    .every((site) => site.resolution_status === "resolved"));
  assert.ok(diagnostics.some((diagnostic) => (
    diagnostic.code === "web.tanstack_route_declaration_unregistered"
    && diagnostic.message.includes("orphanRoute")
  )));
  assert.ok(diagnostics.some((diagnostic) => (
    diagnostic.code === "web.tanstack_route_registration_unresolved"
    && diagnostic.path === "apps/router/src/dynamic-routes.tsx"
  )));
  const tanstackDrift = diagnostics.find((diagnostic) => diagnostic.code === "web.tanstack_route_tree_drift");
  assert.equal(tanstackDrift?.path, "apps/router/src/routes/posts.lazy.tsx");
  assert.ok(tanstackDrift?.evidence.some((item: Record<string, any>) => (
    item.kind === "source" && item.start_line > 1
  )));

  const startNodes = allFrameworkNodes.filter((node) => node.properties.canonical_identity?.framework === "tanstack-start");
  const startSites = allFrameworkSites.filter((site) => site.evidence[0]?.properties?.framework === "tanstack-start");
  const startEdges = allFrameworkEdges.filter((edge) => edge.evidence[0]?.properties?.framework === "tanstack-start");
  assert.deepEqual(
    [...new Set(startNodes.map((node) => node.kind))].sort(),
    ["component", "middleware", "route", "server_function"],
  );
  const getAccount = startNodes.find((node) => node.kind === "server_function" && node.display_name === "getAccount");
  const accountRoute = startNodes.find((node) => (
    node.kind === "route" && node.properties.route_pattern === "/account/$accountId"
  ));
  const publicRoute = startNodes.find((node) => node.kind === "route" && node.properties.route_pattern === "/public");
  const accountComponent = startNodes.find((node) => node.kind === "component" && node.display_name === "AccountPage");
  const authMiddleware = startNodes.find((node) => node.kind === "middleware" && node.display_name === "authMiddleware");
  const pathlessAuditMiddleware = startNodes.find((node) => node.kind === "middleware" && node.display_name === "pathlessAuditMiddleware");
  const auditMiddleware = startNodes.find((node) => node.kind === "middleware" && node.display_name === "auditMiddleware");
  const accountMiddleware = startNodes.find((node) => node.kind === "middleware" && node.display_name === "accountRouteMiddleware");
  const adminMiddleware = startNodes.find((node) => node.kind === "middleware" && node.display_name === "adminMiddleware");
  const rootMiddleware = startNodes.find((node) => node.kind === "middleware" && node.display_name === "rootMiddleware");
  const rootAuditMiddleware = startNodes.find((node) => node.kind === "middleware" && node.display_name === "rootAuditMiddleware");
  const breakoutMiddleware = startNodes.find((node) => node.kind === "middleware" && node.properties.middleware_inheritance === "break-out");
  assert.equal(getAccount?.properties.http_method, "GET");
  assert.equal(getAccount?.properties.production_rpc_id, null);
  assert.equal(getAccount?.properties.production_rpc_id_status, "build-unobserved");
  assert.equal(getAccount?.properties.build_boundary_reason, "tanstack_start_internal_virtual_module_unobserved");
  assert.equal(typeof getAccount?.properties.handler_definition_id, "string");
  assert.equal(typeof getAccount?.properties.validator_definition_id, "string");
  const handledBy = startEdges.find((edge) => edge.kind === "handled_by" && edge.source === getAccount?.id);
  assert.equal(nodeById.get(handledBy?.target)?.display_name, "accountHandler");
  assert.deepEqual(
    new Set(startEdges.filter((edge) => edge.kind === "rpc_call" && edge.target === getAccount?.id).map((edge) => edge.source)),
    new Set([accountRoute?.id, accountComponent?.id]),
  );
  const middlewareTargets = (sourceId: string | undefined) => new Set(startEdges
    .filter((edge) => edge.kind === "uses_middleware" && edge.source === sourceId)
    .map((edge) => edge.target));
  assert.deepEqual(middlewareTargets(getAccount?.id), new Set([authMiddleware?.id, auditMiddleware?.id]));
  assert.deepEqual(
    middlewareTargets(accountRoute?.id),
    new Set([
      accountMiddleware?.id,
      authMiddleware?.id,
      pathlessAuditMiddleware?.id,
      rootMiddleware?.id,
      rootAuditMiddleware?.id,
    ]),
  );
  assert.ok(!middlewareTargets(accountRoute?.id).has(adminMiddleware?.id));
  assert.deepEqual(
    middlewareTargets(publicRoute?.id),
    new Set([breakoutMiddleware?.id, rootMiddleware?.id, rootAuditMiddleware?.id]),
  );
  assert.ok(startSites.some((site) => (
    site.kind === "uses_middleware"
    && site.source === accountRoute?.id
    && site.evidence[0]?.properties.occurrence_kind === "tanstack_start_inherited_pathless_middleware"
    && JSON.stringify(site.condition).includes("_authenticated")
  )));
  assert.ok(startSites.some((site) => (
    site.kind === "uses_middleware"
    && site.source === publicRoute?.id
    && site.evidence[0]?.properties.occurrence_kind === "tanstack_start_middleware_breakout"
    && JSON.stringify(site.condition).includes("break-out")
  )));
  assert.ok(diagnostics.some((diagnostic) => (
    diagnostic.code === "web.tanstack_start_build_rpc_id_unobserved"
    && diagnostic.message.includes("were not guessed")
  )));
  assert.ok(!diagnostics.some((diagnostic) => diagnostic.code === "web.tanstack_start_semantic_delta_discarded"));
  assert.ok(!completed.completeness.includes("semantic-complete"));
  assert.ok(completed.reasons.includes("framework_semantic_incomplete"));
  assert.equal(profile?.properties.web_framework_completeness_status, "incomplete");
  const frameworkLedger = JSON.parse(profile?.properties.web_framework_completeness_ledger ?? "null");
  assert.deepEqual(frameworkLedger.map((entry: Record<string, any>) => entry.framework), [
    "astro", "next", "tanstack-router", "tanstack-start",
  ]);
  assert.equal(Number(profile?.properties.web_framework_completeness_issue_count), frameworkLedger
    .reduce((sum: number, entry: Record<string, any>) => sum + entry.reasons.length, 0));
  assert.ok(frameworkLedger.every((entry: Record<string, any>) => entry.status === "incomplete"));
  assert.ok(frameworkLedger.find((entry: Record<string, any>) => entry.framework === "next")
    ?.reasons.includes("unresolved:next_dynamic_non_literal_import"));
  assert.ok(frameworkLedger.find((entry: Record<string, any>) => entry.framework === "tanstack-start")
    ?.reasons.includes("diagnostic:web.tanstack_start_build_rpc_id_unobserved"));
  assert.equal(completed.dependency_sites, sites.length);
  assert.equal(completed.dependency_sites, completed.resolved + completed.candidates + completed.external + completed.unresolved);
  assert.ok(completedFiles.length > 0);
  assert.ok(completedFiles.every((file) => Object.hasOwn(file, "skipped_sites")));
  assert.ok(completedFiles.every((file) => file.discovered_sites === file.emitted_sites + file.skipped_sites));

  const normalize = (events: Array<Record<string, any>>) => events.map(({ scan_id: _scanId, ...event }) => {
    if (event.event === "scan_started") {
      const { root: _root, ...portable } = event;
      return portable;
    }
    return event;
  });
  assert.deepEqual(normalize(first.events), normalize(second.events));
  for (const marker of markers) await assert.rejects(import("node:fs/promises").then(({ stat }) => stat(marker)));
});

test("framework completeness ledger covers each framework and mixed profiles deterministically", async (context) => {
  const frameworkCapability = new Map([
    ["astro", "astro-component-render-hydration-v1"],
    ["next", "next-route-component-boundary-v1"],
    ["tanstack-router", "tanstack-router-typed-route-v1"],
    ["tanstack-start", "tanstack-start-rpc-middleware-v1"],
  ]);
  const verify = async (result: Awaited<ReturnType<typeof run>>, expectedFrameworks: string[]) => {
    const profile = result.events.find((event) => event.event === "profile_declared")?.profile;
    const completed = result.events.at(-1)?.coverage;
    const ledger = JSON.parse(profile?.properties.web_framework_completeness_ledger ?? "null");
    assert.deepEqual(profile?.features, expectedFrameworks);
    assert.equal(profile?.properties.web_framework_completeness_capability, "framework-semantic-completeness-v1");
    assert.equal(profile?.properties.web_framework_completeness_status, "complete");
    assert.equal(profile?.properties.web_framework_completeness_issue_count, "0");
    assert.deepEqual(ledger.map((entry: Record<string, any>) => entry.framework), expectedFrameworks);
    for (const entry of ledger) {
      assert.equal(entry.status, "complete");
      assert.deepEqual(entry.reasons, []);
      assert.deepEqual(entry.emitted_capabilities, entry.required_capabilities);
      assert.deepEqual(new Set(entry.required_capabilities), new Set([
        "framework-semantic-graph-v1",
        frameworkCapability.get(entry.framework),
        "typescript-definition-import-type-call-graph-v2",
      ]));
    }
    assert.ok(!completed.reasons.includes("framework_semantic_incomplete"));
    return { profile, completed };
  };

  for (const framework of ["astro", "next", "tanstack-router", "tanstack-start"]) {
    const parent = await mkdtemp(path.join(os.tmpdir(), `depgraph-web-${framework}-complete-`));
    context.after(async () => rm(parent, { recursive: true, force: true }));
    const root = path.join(parent, "fixture");
    await cp(frameworkCompleteFixture, root, { recursive: true });
    for (const other of ["astro", "next", "router", "start"]) {
      const selected = framework === "tanstack-router" ? "router"
        : framework === "tanstack-start" ? "start"
          : framework;
      if (other !== selected) await rm(path.join(root, "apps", other), { recursive: true, force: true });
    }
    if (framework === "astro" || framework === "next") {
      await rm(path.join(root, "packages"), { recursive: true, force: true });
    }
    const result = await run(`${framework}-complete`, root);
    const { completed } = await verify(result, [framework]);
    if (framework === "astro" || framework === "next") {
      assert.deepEqual(completed.completeness, ["syntax-complete", "semantic-complete"]);
    } else {
      assert.ok(!completed.completeness.includes("semantic-complete"));
      assert.ok(completed.reasons.includes("unresolved_dependency_sites"));
      assert.ok(result.events.some((event) => (
        event.event === "dependency_site"
        && event.site.resolution_status === "unresolved"
        && event.site.reason === "function_value_dispatch"
      )));
    }
  }

  const first = await run("framework-mixed-one", frameworkCompleteFixture);
  const second = await run("framework-mixed-two", frameworkCompleteFixture);
  await verify(first, ["astro", "next", "tanstack-router", "tanstack-start"]);
  const normalize = (events: Array<Record<string, any>>) => events.map(({ scan_id: _scanId, ...event }) => {
    if (event.event === "scan_started") {
      const { root: _root, ...portable } = event;
      return portable;
    }
    return event;
  });
  assert.deepEqual(normalize(first.events), normalize(second.events));
});

test("TanStack Start version ranges are classified without crossing the v1 boundary", async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "depgraph-web-start-version-"));
  context.after(async () => rm(root, { recursive: true, force: true }));
  await mkdir(path.join(root, "src", "routes"), { recursive: true });
  await Promise.all([
    writeFile(path.join(root, "src", "routes", "index.tsx"), [
      'import { createFileRoute } from "@tanstack/react-router";',
      'export const Route = createFileRoute("/")({});',
      "",
    ].join("\n")),
    writeFile(path.join(root, "src", "server.ts"), [
      'import { createServerFn } from "@tanstack/react-start";',
      'export const unsupported = createServerFn({ method: "GET" }).handler(() => null);',
      "",
    ].join("\n")),
  ]);
  const scanRange = async (range: string, index: number) => {
    await writeFile(path.join(root, "package.json"), JSON.stringify({
      name: "start-version-range",
      version: "1.0.0",
      dependencies: {
        "@tanstack/react-router": "1.170.18",
        "@tanstack/react-start": range,
      },
    }));
    return await run(`start-version-range-${index}`, root);
  };
  for (const [index, range] of [">=1.0.0", "1", "^1", "~1", "1.x", ">=1 <2"].entries()) {
    const result = await scanRange(range, index);
    const nodes = result.events.filter((event) => event.event === "node_upsert").map((event) => event.node);
    const diagnostics = result.events.filter((event) => event.event === "diagnostic").map((event) => event.diagnostic);
    assert.ok(nodes.some((node) => node.kind === "server_function" && node.properties.framework === "tanstack-start"), range);
    assert.ok(!diagnostics.some((diagnostic) => diagnostic.code === "web.tanstack_start_version_unsupported"), range);
  }
  for (const [index, range] of ["2.0.0", "1.0.0 - 2.0.0", "^1 || ^2"].entries()) {
    const result = await scanRange(range, index + 10);
    const profile = result.events.find((event) => event.event === "profile_declared")?.profile;
    const ledger = JSON.parse(profile?.properties.web_framework_completeness_ledger ?? "null");
    const nodes = result.events.filter((event) => event.event === "node_upsert").map((event) => event.node);
    const diagnostics = result.events.filter((event) => event.event === "diagnostic").map((event) => event.diagnostic);
    assert.ok(diagnostics.some((diagnostic) => (
      diagnostic.code === "web.tanstack_start_version_unsupported"
      && diagnostic.message.includes(range)
    )), range);
    assert.ok(!nodes.some((node) => node.kind === "server_function" && node.properties.framework === "tanstack-start"), range);
    assert.equal(profile?.properties.web_framework_completeness_status, "incomplete");
    assert.ok(ledger.find((entry: Record<string, any>) => entry.framework === "tanstack-start")
      ?.reasons.includes("diagnostic:web.tanstack_start_version_unsupported"), range);
  }
});

test("pure TypeScript semantic profiles allow candidate and external calls", async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "depgraph-web-semantic-complete-"));
  context.after(async () => rm(root, { recursive: true, force: true }));
  await Promise.all([
    writeFile(path.join(root, "package.json"), JSON.stringify({ name: "semantic-complete", version: "1.0.0", type: "module" })),
    writeFile(path.join(root, "index.ts"), [
      "const exact = (): void => {};",
      "const first = (): void => {};",
      "const second = (): void => {};",
      "exact();",
      "const selected = Math.random() > 0.5 ? first : second;",
      "selected();",
      "",
    ].join("\n")),
  ]);

  const result = await run("semantic-complete", root);
  const profile = result.events.find((event) => event.event === "profile_declared")?.profile;
  const completed = result.events.at(-1)?.coverage;
  const semanticCalls = result.events
    .filter((event) => event.site?.kind === "call" && event.site?.evidence[0]?.kind === "semantic")
    .map((event) => event.site);

  assert.deepEqual(profile?.features, []);
  assert.equal(profile?.properties.project_code_executed, "false");
  assert.equal(completed.project_code_executed, false);
  assert.equal(completed.unresolved, 0);
  assert.equal(completed.unsupported_syntax, 0);
  assert.deepEqual(completed.completeness, ["syntax-complete", "semantic-complete"]);
  assert.equal(profile?.properties.web_framework_completeness_status, "not-detected");
  assert.equal(profile?.properties.web_framework_completeness_issue_count, "0");
  assert.equal(profile?.properties.web_framework_completeness_ledger, "[]");
  assert.ok(!completed.reasons.includes("framework_semantic_incomplete"));
  assert.ok(!completed.reasons.includes("typescript_semantic_diagnostics_present"));
  assert.ok(!completed.reasons.includes("typescript_emitted_semantic_diagnostics_present"));
  assert.ok(semanticCalls.some((site) => site.resolution_status === "candidates"));
  assert.ok(semanticCalls.some((site) => site.resolution_status === "external"));
});

test("Next JSX import correlation preserves CRLF offsets", async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "depgraph-web-next-crlf-"));
  context.after(async () => rm(root, { recursive: true, force: true }));
  const app = path.join(root, "app");
  await mkdir(app, { recursive: true });
  const pageSource = [
    'import { Widget as FirstWidget } from "./Widget";',
    'import { Widget as SecondWidget } from "./Widget";',
    "export default function Page(): unknown {",
    "  return <SecondWidget />;",
    "}",
    "",
  ].join("\r\n");
  await Promise.all([
    writeFile(path.join(root, "package.json"), JSON.stringify({
      name: "next-crlf",
      version: "1.0.0",
      type: "module",
      dependencies: { next: "16.2.10" },
    })),
    writeFile(path.join(app, "page.tsx"), pageSource),
    writeFile(path.join(app, "Widget.tsx"), "export function Widget(): unknown { return null; }\r\n"),
  ]);

  const result = await run("next-crlf", root);
  const profile = result.events.find((event) => event.event === "profile_declared")?.profile;
  const nodes = result.events.filter((event) => event.event === "node_upsert").map((event) => event.node);
  const edges = result.events.filter((event) => event.event === "edge_upsert").map((event) => event.edge);
  const page = nodes.find((node) => node.kind === "component" && node.display_name === "Page");
  const widget = nodes.find((node) => node.kind === "component" && node.display_name === "Widget");
  const render = edges.find((edge) => (
    edge.kind === "renders"
    && edge.source === page?.id
    && edge.target === widget?.id
    && edge.evidence[0]?.properties.occurrence_kind === "next_import_render"
  ));
  const rawSiteKey = render?.evidence[0]?.properties.typescript_site_key;

  assert.equal(profile?.properties.web_framework_semantic_status, "emitted");
  assert.equal(typeof rawSiteKey, "string");
  const rawSiteIdentity = JSON.parse(rawSiteKey.slice("site:".length)) as unknown[];
  assert.equal(rawSiteIdentity[2], "app/page.tsx");
  assert.equal(rawSiteIdentity[3], pageSource.indexOf("SecondWidget"));
});

test("stable IDs and events are independent of checkout directory", async (context) => {
  const temp = await mkdtemp(path.join(os.tmpdir(), "depgraph-web-checkouts-"));
  context.after(async () => rm(temp, { recursive: true, force: true }));
  const firstRoot = path.join(temp, "first");
  const secondRoot = path.join(temp, "second");
  await cp(fixture, firstRoot, { recursive: true });
  await cp(fixture, secondRoot, { recursive: true });
  const first = await run("checkout-one", firstRoot);
  const second = await run("checkout-two", secondRoot);
  const normalize = (events: Array<Record<string, any>>) => events.map(({ scan_id: _scanId, ...event }) => {
    if (event.event === "scan_started") {
      const { root: _root, ...portable } = event;
      return portable;
    }
    return event;
  });
  assert.deepEqual(normalize(first.events), normalize(second.events));
});

test("fallback repository identity never depends on the checkout directory name", async (context) => {
  const temp = await mkdtemp(path.join(os.tmpdir(), "depgraph-web-fallback-identity-"));
  context.after(async () => rm(temp, { recursive: true, force: true }));
  const cases: Array<{ name: string; files: Record<string, string> }> = [
    {
      name: "unnamed-root",
      files: {
        "package.json": JSON.stringify({ private: true, type: "module" }),
        "index.ts": "export const value = true;\n",
      },
    },
    {
      name: "malformed-root",
      files: {
        "package.json": "{ this is not valid JSON\n",
        "src/dep.ts": "export const dep = true;\n",
        "src/index.ts": 'import "./dep.js";\n',
      },
    },
    {
      name: "nested-only",
      files: {
        "packages/child/package.json": JSON.stringify({ name: "nested-child", version: "1.0.0" }),
        "packages/child/index.ts": "export const child = true;\n",
      },
    },
  ];
  const normalize = (events: Array<Record<string, any>>) => events.map(({ scan_id: _scanId, ...event }) => {
    if (event.event === "scan_started") {
      const { root: _root, ...portable } = event;
      return portable;
    }
    return event;
  });

  for (const fixtureCase of cases) {
    const firstRoot = path.join(temp, `first-checkout-${fixtureCase.name}`);
    const secondRoot = path.join(temp, `different-name-${fixtureCase.name}`);
    for (const root of [firstRoot, secondRoot]) {
      for (const [relative, source] of Object.entries(fixtureCase.files)) {
        const file = path.join(root, relative);
        await mkdir(path.dirname(file), { recursive: true });
        await writeFile(file, source);
      }
    }
    const first = await run(`fallback-first-${fixtureCase.name}`, firstRoot);
    const second = await run(`fallback-second-${fixtureCase.name}`, secondRoot);
    assert.deepEqual(normalize(first.events), normalize(second.events), fixtureCase.name);
  }
});

test("web environments are canonicalized into profile identity and every condition", async () => {
  const selection = { web_environments: ["worker", "browser", " SERVER ", "browser"] };
  const reordered = { web_environments: ["server", "browser", "worker"] };
  const first = await run("profile-one", fixture, selection);
  const second = await run("profile-two", fixture, reordered);
  const firstProfile = first.events.find((event) => event.event === "profile_declared")?.profile;
  const secondProfile = second.events.find((event) => event.event === "profile_declared")?.profile;
  assert.deepEqual(firstProfile.environment.environments, ["browser", "server", "worker"]);
  assert.equal(firstProfile.id, secondProfile.id);
  for (const event of first.events.filter((candidate) => candidate.site || candidate.edge)) {
    const record = event.site ?? event.edge;
    const serialized = JSON.stringify(record.condition);
    if (record.evidence[0]?.properties?.contract_version === "framework-semantic-graph-v1") {
      assert.match(serialized, /"key":"environment","value":"(?:browser|server|worker)"/u);
    } else {
      assert.match(serialized, /"values":\["browser","server","worker"\]/u);
    }
  }
});

test("npm, pnpm, Yarn, Bun, and Yarn PnP locks are read without running package code", async () => {
  const cases = [
    { manager: "npm", root: fixture },
    { manager: "pnpm", root: `${managerFixtures}/pnpm` },
    { manager: "yarn", root: `${managerFixtures}/yarn` },
    { manager: "yarn", root: `${managerFixtures}/yarn-modern` },
    { manager: "bun", root: `${managerFixtures}/bun` },
    { manager: "yarn", root: `${managerFixtures}/pnp`, pnp: true },
  ];
  const pnpMarker = new URL("./fixtures/managers/pnp/PNP_EXECUTED", import.meta.url);
  await rm(pnpMarker, { force: true });
  for (const [index, fixtureCase] of cases.entries()) {
    const result = await run(`manager-${index}`, fixtureCase.root);
    const profile = result.events.find((event) => event.event === "profile_declared")?.profile;
    const nodes = result.events.filter((event) => event.node).map((event) => event.node);
    const lodash = nodes.find((node) => node.kind === "external_system" && node.display_name === "lodash");
    assert.equal(profile.properties.package_manager, fixtureCase.manager);
    assert.equal(lodash?.properties.version, "4.17.21");
    if (fixtureCase.pnp) assert.equal(lodash?.properties.locator, "yarn:lodash@4.17.21");
    assert.ok(!result.events.some((event) => event.diagnostic?.code === "web.lockfile_invalid"), fixtureCase.root);
  }
  await assert.rejects(import("node:fs/promises").then(({ stat }) => stat(pnpMarker)));
});

test("Yarn classic and Berry lock scalars preserve quoted and unquoted versions", async () => {
  const classic = await run("yarn-classic-lock", `${managerFixtures}/yarn`);
  const modern = await run("yarn-modern-lock", `${managerFixtures}/yarn-modern`);
  const versions = (result: Awaited<ReturnType<typeof run>>) => new Map(result.events
    .filter((event) => event.node?.kind === "external_system")
    .map((event) => [event.node.display_name, event.node.properties.version]));
  assert.equal(versions(classic).get("lodash"), "4.17.21");
  assert.equal(versions(modern).get("lodash"), "4.17.21");
  assert.equal(versions(modern).get("modern-quoted"), "1.2.3");
});

test("workspace package selection respects explicit local references and incompatible external locks", async (context) => {
  const parent = await mkdtemp(path.join(os.tmpdir(), "depgraph-web-workspace-selection-"));
  context.after(async () => rm(parent, { recursive: true, force: true }));
  const managers = ["npm", "pnpm", "yarn"] as const;
  for (const manager of managers) {
    const root = path.join(parent, manager);
    await Promise.all([
      mkdir(path.join(root, "packages", "app", "src"), { recursive: true }),
      mkdir(path.join(root, "packages", "shared", "src"), { recursive: true }),
    ]);
    const packageManager = manager === "npm" ? "npm@11.0.0" : manager === "pnpm" ? "pnpm@10.33.0" : "yarn@4.0.0";
    const lock: readonly [string, string] = manager === "npm"
      ? ["package-lock.json", JSON.stringify({
        name: `${manager}-workspace-selection`,
        lockfileVersion: 3,
        packages: {
          "": { name: `${manager}-workspace-selection` },
          "node_modules/shared": { version: "2.0.0" },
        },
      })]
      : manager === "pnpm"
        ? ["pnpm-lock.yaml", "lockfileVersion: '9.0'\npackages:\n  shared@2.0.0:\n    resolution: {integrity: sha512-fixture}\n"]
        : ["yarn.lock", 'shared@2.0.0:\n  version "2.0.0"\n  resolved "https://registry.example/shared-2.0.0.tgz"\n'];
    await Promise.all([
      writeFile(path.join(root, "package.json"), JSON.stringify({
        name: `${manager}-workspace-selection`,
        private: true,
        packageManager,
        workspaces: ["packages/*"],
      })),
      writeFile(path.join(root, "packages", "app", "package.json"), JSON.stringify({
        name: "app",
        version: "1.0.0",
        dependencies: { shared: "2.0.0" },
      })),
      writeFile(path.join(root, "packages", "app", "src", "index.ts"), 'import "shared";\n'),
      writeFile(path.join(root, "packages", "shared", "package.json"), JSON.stringify({
        name: "shared",
        version: "1.0.0",
        exports: "./src/index.ts",
      })),
      writeFile(path.join(root, "packages", "shared", "src", "index.ts"), "export const local = true;\n"),
      writeFile(path.join(root, lock[0]), lock[1]),
    ]);

    const incompatible = await run(`${manager}-incompatible-workspace`, root);
    const incompatibleNodes = new Map(incompatible.events.filter((event) => event.node).map((event) => [event.node.id, event.node]));
    const incompatiblePackageSite = incompatible.events.find((event) => (
      event.site?.kind === "package_dependency" && event.site?.specifier === "shared"
    ))?.site;
    const incompatibleImportSite = incompatible.events.find((event) => (
      event.site?.kind === "side_effect_import" && event.site?.specifier === "shared"
    ))?.site;
    assert.equal(incompatiblePackageSite?.resolution_status, "external", manager);
    assert.equal(incompatibleImportSite?.resolution_status, "external", manager);
    for (const site of [incompatiblePackageSite, incompatibleImportSite]) {
      const target = incompatibleNodes.get(site?.target_ids[0]);
      assert.equal(target?.kind, "external_system", manager);
      assert.equal(target?.properties.version, "2.0.0", manager);
    }

    await writeFile(path.join(root, "packages", "app", "package.json"), JSON.stringify({
      name: "app",
      version: "1.0.0",
      dependencies: { shared: "1.0.0" },
    }));
    const ordinary = await run(`${manager}-ordinary-workspace-range`, root);
    const ordinaryNodes = new Map(ordinary.events.filter((event) => event.node).map((event) => [event.node.id, event.node]));
    for (const site of ordinary.events
      .filter((event) => event.site?.specifier === "shared" && ["package_dependency", "side_effect_import"].includes(event.site.kind))
      .map((event) => event.site)) {
      assert.equal(site.resolution_status, "candidates", `${manager}:${site.kind}`);
      assert.match(site.reason ?? "", /workspace_and_external_package_candidates/u, `${manager}:${site.kind}`);
      assert.deepEqual(
        [...new Set(site.target_ids.map((id: string) => ordinaryNodes.get(id)?.kind))].sort(),
        ["external_system", site.kind === "package_dependency" ? "package_instance" : "file"].sort(),
        `${manager}:${site.kind}`,
      );
    }

    await writeFile(path.join(root, "packages", "app", "package.json"), JSON.stringify({
      name: "app",
      version: "1.0.0",
    }));
    const undeclared = await run(`${manager}-undeclared-workspace-import`, root);
    const undeclaredNodes = new Map(undeclared.events.filter((event) => event.node).map((event) => [event.node.id, event.node]));
    const undeclaredImport = undeclared.events.find((event) => (
      event.site?.kind === "side_effect_import" && event.site?.specifier === "shared"
    ))?.site;
    assert.equal(undeclaredImport?.resolution_status, "candidates", manager);
    assert.notEqual(undeclaredImport?.precision, "exact", manager);
    assert.deepEqual(
      [...new Set(undeclaredImport?.target_ids.map((id: string) => undeclaredNodes.get(id)?.kind))].sort(),
      ["external_system", "file"],
      manager,
    );

    await writeFile(path.join(root, "packages", "app", "package.json"), JSON.stringify({
      name: "app",
      version: "1.0.0",
      dependencies: { shared: "workspace:*" },
    }));
    const explicit = await run(`${manager}-explicit-workspace`, root);
    const explicitNodes = new Map(explicit.events.filter((event) => event.node).map((event) => [event.node.id, event.node]));
    const explicitPackageSite = explicit.events.find((event) => (
      event.site?.kind === "package_dependency" && event.site?.specifier === "shared"
    ))?.site;
    const explicitImportSite = explicit.events.find((event) => (
      event.site?.kind === "side_effect_import" && event.site?.specifier === "shared"
    ))?.site;
    assert.equal(explicitPackageSite?.resolution_status, "resolved", manager);
    assert.equal(explicitImportSite?.resolution_status, "resolved", manager);
    assert.equal(explicitNodes.get(explicitPackageSite?.target_ids[0])?.kind, "package_instance", manager);
    assert.equal(explicitNodes.get(explicitPackageSite?.target_ids[0])?.properties.version, "1.0.0", manager);
    assert.equal(explicitNodes.get(explicitImportSite?.target_ids[0])?.display_name, "packages/shared/src/index.ts", manager);
  }
});

test("external owner resolution overrides neutral workspace compiler definitions", async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "depgraph-web-external-over-workspace-"));
  context.after(async () => rm(root, { recursive: true, force: true }));
  await Promise.all([
    mkdir(path.join(root, "packages", "app", "src"), { recursive: true }),
    mkdir(path.join(root, "packages", "shared", "src"), { recursive: true }),
  ]);
  await Promise.all([
    writeFile(path.join(root, "package.json"), JSON.stringify({
      name: "external-over-workspace",
      private: true,
      packageManager: "npm@11.0.0",
      workspaces: ["packages/*"],
    })),
    writeFile(path.join(root, "package-lock.json"), JSON.stringify({
      name: "external-over-workspace",
      lockfileVersion: 3,
      packages: {
        "": { name: "external-over-workspace" },
        "node_modules/shared": { version: "2.0.0" },
      },
    })),
    writeFile(path.join(root, "packages", "app", "package.json"), JSON.stringify({
      name: "external-over-workspace-app",
      version: "1.0.0",
      dependencies: { shared: "2.0.0" },
    })),
    writeFile(path.join(root, "packages", "app", "src", "index.ts"), [
      'import type { ExternalType } from "shared";',
      "export interface UsesExternal { readonly value: ExternalType }",
      "",
    ].join("\n")),
    writeFile(path.join(root, "packages", "shared", "package.json"), JSON.stringify({
      name: "shared",
      version: "1.0.0",
      exports: "./src/index.ts",
    })),
    writeFile(
      path.join(root, "packages", "shared", "src", "index.ts"),
      "export interface ExternalType { readonly source: 'local-workspace' }\n",
    ),
  ]);

  const result = await run("external-over-workspace", root);
  const nodes = new Map(result.events.filter((event) => event.node).map((event) => [event.node.id, event.node]));
  const sites = result.events
    .filter((event) => event.site?.evidence[0]?.kind === "semantic")
    .map((event) => event.site);
  const namedImport = sites.find((site) => (
    site.kind === "web_import"
    && site.specifier === "shared"
    && site.evidence[0]?.properties.imported_name === "ExternalType"
  ));
  const typeUse = sites.find((site) => (
    site.kind === "type_use"
    && site.specifier === "ExternalType"
    && site.evidence[0]?.properties.module_specifier === "shared"
  ));
  for (const site of [namedImport, typeUse]) {
    assert.equal(site?.resolution_status, "external");
    assert.ok(site?.precision === "exact" || site?.precision === "heuristic");
    if (site?.precision === "exact") assert.equal(site.reason, null);
    else assert.ok(site?.reason);
    assert.equal(site?.target_ids.length, 1);
    const target = nodes.get(site?.target_ids[0]);
    assert.equal(target?.kind, "external_system");
    assert.match(JSON.stringify(target), /2\.0\.0/u);
    assert.notEqual(target?.properties.source_path, "packages/shared/src/index.ts");
  }
});

test("missing explicit workspace, file, link, and portal targets remain unresolved", async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "depgraph-web-missing-explicit-local-"));
  context.after(async () => rm(root, { recursive: true, force: true }));
  const dependencies = {
    "missing-workspace": "workspace:*",
    "missing-file": "file:./packages/missing-file",
    "missing-link": "link:./packages/missing-link",
    "missing-portal": "portal:./packages/missing-portal",
  };
  await Promise.all([
    writeFile(path.join(root, "package.json"), JSON.stringify({ name: "missing-explicit-local", dependencies })),
    writeFile(path.join(root, "index.ts"), Object.keys(dependencies).map((name) => `import ${JSON.stringify(name)};`).join("\n")),
  ]);

  const result = await run("missing-explicit-local", root);
  for (const name of Object.keys(dependencies)) {
    const sites = result.events
      .filter((event) => event.site?.specifier === name)
      .map((event) => event.site);
    assert.deepEqual(sites.map((site) => site.kind).sort(), ["package_dependency", "side_effect_import", "web_import"]);
    assert.ok(sites.every((site) => site.resolution_status === "unresolved"), name);
    assert.ok(sites.every((site) => site.reason === "explicit_local_package_target_not_found"), name);
    assert.ok(sites.every((site) => site.target_ids.length === 1), name);
  }
});

test("Yarn manager-native resolution identity preserves same-version install instances", async (context) => {
  const parent = await mkdtemp(path.join(os.tmpdir(), "depgraph-web-yarn-instance-identity-"));
  context.after(async () => rm(parent, { recursive: true, force: true }));
  const locks = new Map([
    ["berry", '__metadata:\n  version: 8\n"twin@npm:^1.0.0":\n  version: 1.0.0\n  resolution: "twin@virtual:first#npm:1.0.0"\n"twin@npm:~1.0.0":\n  version: 1.0.0\n  resolution: "twin@virtual:second#npm:1.0.0"\n'],
    ["classic", 'twin@^1.0.0:\n  version "1.0.0"\n  resolved "https://one.example/twin-1.0.0.tgz"\ntwin@~1.0.0:\n  version "1.0.0"\n  resolved "https://two.example/twin-1.0.0.tgz"\n'],
    ["descriptor", 'twin@^1.0.0:\n  version "1.0.0"\ntwin@~1.0.0:\n  version "1.0.0"\n'],
  ]);
  for (const [variant, lock] of locks) {
    const root = path.join(parent, variant);
    await mkdir(root);
    await Promise.all([
      writeFile(path.join(root, "package.json"), JSON.stringify({
        name: `yarn-${variant}`,
        packageManager: "yarn@4.0.0",
        dependencies: { twin: "^1.0.0" },
      })),
      writeFile(path.join(root, "yarn.lock"), lock),
    ]);
    const result = await run(`yarn-${variant}-identity`, root);
    const nodes = new Map(result.events.filter((event) => event.node).map((event) => [event.node.id, event.node]));
    const site = result.events.find((event) => event.site?.kind === "package_dependency" && event.site?.specifier === "twin")?.site;
    assert.equal(site?.resolution_status, "candidates", variant);
    assert.equal(site?.reason, "multiple_locked_package_instances", variant);
    assert.equal(site?.target_ids.length, 2, variant);
    const targets = site.target_ids.map((id: string) => nodes.get(id));
    assert.equal(new Set(targets.map((node: any) => node.id)).size, 2, variant);
    assert.equal(new Set(targets.map((node: any) => node.properties.locator)).size, 2, variant);
    assert.ok(targets.every((node: any) => node.properties.version === "1.0.0"), variant);
    assert.ok(targets.every((node: any) => node.properties.locator.includes(`#${variant === "berry" ? "resolution" : variant === "classic" ? "resolved" : "descriptor"}:`)), variant);
  }
});

test("Yarn fallback locators are independent of descriptor order and checkout path", async (context) => {
  const parent = await mkdtemp(path.join(os.tmpdir(), "depgraph-web-yarn-portable-locator-"));
  context.after(async () => rm(parent, { recursive: true, force: true }));
  const roots = [path.join(parent, "first"), path.join(parent, "second")];
  for (const [index, root] of roots.entries()) {
    await mkdir(root);
    const descriptors = index === 0
      ? '"twin@~1.0.0", "twin@^1.0.0"'
      : '"twin@^1.0.0", "twin@~1.0.0"';
    await Promise.all([
      writeFile(path.join(root, "package.json"), JSON.stringify({
        name: "portable-yarn-locator",
        packageManager: "yarn@4.0.0",
        dependencies: { twin: "^1.0.0" },
      })),
      writeFile(path.join(root, "yarn.lock"), `${descriptors}:\n  version: 1.0.0\n`),
    ]);
  }
  const descriptorResults = await Promise.all(roots.map((root, index) => run(`yarn-descriptor-${index}`, root)));
  const twinNode = (result: Awaited<ReturnType<typeof run>>): Record<string, any> | undefined => result.events.find((event) => (
    event.node?.kind === "external_system" && event.node?.display_name === "twin"
  ))?.node;
  assert.equal(twinNode(descriptorResults[0]!)?.properties.locator, twinNode(descriptorResults[1]!)?.properties.locator);
  assert.equal(twinNode(descriptorResults[0]!)?.id, twinNode(descriptorResults[1]!)?.id);

  for (const root of roots) {
    await writeFile(path.join(root, "yarn.lock"), `twin@^1.0.0:\n  version: 1.0.0\n  resolution: "twin@portal:${root}/packages/twin"\n`);
  }
  const absoluteResults = await Promise.all(roots.map((root, index) => run(`yarn-absolute-${index}`, root)));
  const first = twinNode(absoluteResults[0]!);
  const second = twinNode(absoluteResults[1]!);
  assert.equal(first?.properties.locator, second?.properties.locator);
  assert.equal(first?.id, second?.id);
  assert.ok(!first?.properties.locator.includes(parent));
});

test("pnpm peer contexts remain separate lock instances and graph nodes", async () => {
  const result = await run("pnpm-peer-contexts", `${managerFixtures}/pnpm-peer`);
  const nodes = new Map(result.events.filter((event) => event.node).map((event) => [event.node.id, event.node]));
  const site = result.events
    .filter((event) => event.site?.kind === "package_dependency")
    .map((event) => event.site)
    .find((candidate) => candidate.specifier === "peerful");
  assert.equal(site?.resolution_status, "candidates");
  assert.equal(site?.reason, "multiple_locked_package_instances");
  assert.equal(site?.target_ids.length, 2);
  const targets = site?.target_ids.map((id: string) => nodes.get(id));
  assert.deepEqual(targets?.map((node: any) => node.properties.version), ["1.0.0", "1.0.0"]);
  assert.deepEqual(targets?.map((node: any) => node.properties.locator).sort(), [
    "pnpm:peerful@1.0.0(peer@1.0.0)",
    "pnpm:peerful@1.0.0(peer@2.0.0)",
  ]);
  assert.notEqual(site?.target_ids[0], site?.target_ids[1]);
});

test("pnpm workspace negations retain declaration order", async () => {
  const result = await run("pnpm-negated-workspace", `${managerFixtures}/pnpm-negated`);
  const packageNames = result.events
    .filter((event) => event.node?.kind === "package_instance")
    .map((event) => event.node.properties.name);
  assert.ok(packageNames.includes("workspace-included"));
  assert.ok(!packageNames.includes("workspace-excluded"));
});

test("multiple locked package instances remain explicit candidates", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "depgraph-web-multi-lock-"));
  try {
    await writeFile(path.join(root, "package.json"), JSON.stringify({
      name: "multi-lock",
      private: true,
      dependencies: { shared: "^1 || ^2" },
    }));
    await writeFile(path.join(root, "package-lock.json"), JSON.stringify({
      name: "multi-lock",
      lockfileVersion: 3,
      packages: {
        "": { name: "multi-lock" },
        "node_modules/left/node_modules/shared": { version: "1.2.3" },
        "node_modules/right/node_modules/shared": { version: "2.3.4" },
      },
    }));
    const result = await run("multi-lock", root);
    const site = result.events
      .filter((event) => event.event === "dependency_site")
      .map((event) => event.site)
      .find((candidate) => candidate.specifier === "shared");
    const nodes = new Map(result.events
      .filter((event) => event.event === "node_upsert")
      .map((event) => [event.node.id, event.node]));
    assert.equal(site?.resolution_status, "candidates");
    assert.equal(site?.reason, "multiple_locked_package_instances");
    assert.deepEqual(
      site?.target_ids.map((id: string) => nodes.get(id)?.properties.version).sort(),
      ["1.2.3", "2.3.4"],
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("dynamic import attributes resolve a literal first argument only", async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "depgraph-web-import-options-"));
  context.after(async () => rm(root, { recursive: true, force: true }));
  await Promise.all([
    writeFile(path.join(root, "package.json"), JSON.stringify({ name: "import-options", version: "1.0.0" })),
    writeFile(path.join(root, "data.json"), JSON.stringify({ value: true })),
    writeFile(path.join(root, "source.ts"), `
const literal = import("./data.json", { with: { type: "json" } });
const name = "./data.json";
const computed = import(name, { with: { type: "json" } });
`),
  ]);
  const result = await run("import-options", root);
  const sites = result.events.filter((event) => event.site?.kind === "dynamic_import").map((event) => event.site);
  const literal = sites.find((site) => site.specifier === "./data.json");
  const computed = sites.find((site) => site.specifier.startsWith("name,"));
  assert.equal(literal?.resolution_status, "resolved");
  assert.equal(computed?.resolution_status, "unresolved");
  assert.equal(computed?.reason, "computed_specifier");
});

test("production package graph excludes devDependencies and preserves included dependency kinds", async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "depgraph-web-worker-dependency-kind-"));
  context.after(async () => rm(root, { recursive: true, force: true }));
  await Promise.all([
    writeFile(path.join(root, "package.json"), JSON.stringify({
      name: "dependency-kind-fixture",
      version: "1.0.0",
      dependencies: { optional: "0.1.0", runtime: "1.0.0" },
      devDependencies: { "dev-only": "2.0.0" },
      peerDependencies: { peer: "3.0.0" },
      optionalDependencies: { optional: "4.0.0" },
    })),
    writeFile(path.join(root, "index.ts"), "export const value = true;\n"),
  ]);

  const result = await run("dependency-kinds", root);
  const packageSites = result.events
    .filter((event) => event.site?.source && event.site?.kind.startsWith("package_"))
    .map((event) => event.site);
  assert.deepEqual(packageSites.map((site) => [site.specifier, site.kind]).sort(), [
    ["optional", "package_optional_dependency"],
    ["peer", "package_peer_dependency"],
    ["runtime", "package_dependency"],
  ]);
  assert.ok(packageSites.every((site) => site.evidence[0]?.properties?.dependency_section));
  assert.ok(!result.events.some((event) => event.site?.specifier === "dev-only" || event.node?.display_name === "dev-only"));
});

test("invalid package and TypeScript config files produce incomplete coverage diagnostics", async (context) => {
  const invalidManifestRoot = await mkdtemp(path.join(os.tmpdir(), "depgraph-web-worker-invalid-manifest-"));
  const invalidConfigRoot = await mkdtemp(path.join(os.tmpdir(), "depgraph-web-worker-invalid-config-"));
  context.after(async () => Promise.all([
    rm(invalidManifestRoot, { recursive: true, force: true }),
    rm(invalidConfigRoot, { recursive: true, force: true }),
  ]));
  await Promise.all([
    writeFile(path.join(invalidManifestRoot, "package.json"), "{ invalid json"),
    writeFile(path.join(invalidManifestRoot, "index.ts"), "export const value = true;\n"),
    writeFile(path.join(invalidConfigRoot, "package.json"), JSON.stringify({ name: "invalid-config", version: "1.0.0" })),
    writeFile(path.join(invalidConfigRoot, "tsconfig.json"), "{ invalid jsonc"),
    writeFile(path.join(invalidConfigRoot, "index.ts"), "export const value = true;\n"),
  ]);

  const invalidManifest = await run("invalid-manifest", invalidManifestRoot);
  assert.ok(invalidManifest.events.some((event) => event.diagnostic?.code === "web.package_manifest_invalid"));
  assert.ok(invalidManifest.events.at(-1)?.coverage.unsupported_syntax > 0);
  assert.deepEqual(invalidManifest.events.at(-1)?.coverage.completeness, []);
  assert.ok(invalidManifest.events.at(-1)?.coverage.reasons.includes("unsupported_syntax"));

  const invalidConfig = await run("invalid-config", invalidConfigRoot);
  assert.ok(invalidConfig.events.some((event) => event.diagnostic?.code === "web.static_config_unresolved" && event.diagnostic?.path === "tsconfig.json"));
  assert.ok(invalidConfig.events.at(-1)?.coverage.unsupported_syntax > 0);
  assert.deepEqual(invalidConfig.events.at(-1)?.coverage.completeness, []);
});

test("recognized Web metadata files are represented in the per-file ledger", async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "depgraph-web-metadata-ledger-"));
  context.after(async () => rm(root, { recursive: true, force: true }));
  await mkdir(path.join(root, "examples", "nested"), { recursive: true });
  await Promise.all([
    writeFile(path.join(root, "package.json"), JSON.stringify({
      name: "metadata-ledger",
      packageManager: "pnpm@10.33.0",
      dependencies: { next: "16.2.10" },
    })),
    writeFile(path.join(root, "pnpm-lock.yaml"), "lockfileVersion: '9.0'\nimporters:\n  .: {}\n"),
    writeFile(path.join(root, "pnpm-workspace.yaml"), "packages: []\n"),
    writeFile(path.join(root, "tsconfig.json"), JSON.stringify({ extends: "./tsconfig.base.json", compilerOptions: { module: "esnext" } })),
    writeFile(path.join(root, "tsconfig.base.json"), JSON.stringify({ compilerOptions: { target: "esnext" } })),
    writeFile(path.join(root, "next.config.mjs"), "export default { basePath: '/docs' };\n"),
    writeFile(path.join(root, "index.ts"), "export const value = true;\n"),
    writeFile(path.join(root, "examples", "nested", "package.json"), JSON.stringify({ name: "not-a-workspace", version: "1.0.0" })),
  ]);

  const result = await run("metadata-ledger", root);
  const ledgers = new Map(result.events
    .filter((event) => event.event === "file_completed")
    .map((event) => [event.path, event]));
  for (const metadataPath of [
    "package.json",
    "pnpm-lock.yaml",
    "pnpm-workspace.yaml",
    "tsconfig.json",
    "tsconfig.base.json",
    "next.config.mjs",
    "examples/nested/package.json",
  ]) {
    assert.ok(ledgers.has(metadataPath), metadataPath);
    assert.equal(ledgers.get(metadataPath)?.skipped, false, metadataPath);
    assert.equal(ledgers.get(metadataPath)?.discovered_sites, ledgers.get(metadataPath)?.emitted_sites, metadataPath);
  }
  assert.ok(result.events.some((event) => (
    event.diagnostic?.code === "web.package_manifest_outside_workspace"
    && event.diagnostic?.path === "examples/nested/package.json"
  )));
  assert.ok(!result.events.some((event) => event.node?.kind === "package_instance" && event.node?.properties.name === "not-a-workspace"));
  assert.equal(result.events.at(-1)?.coverage.files_skipped, 0);
  assert.equal(result.events.at(-1)?.coverage.unsupported_syntax, 0);
});

test("malformed lock metadata is explicit skipped coverage", async (context) => {
  const parent = await mkdtemp(path.join(os.tmpdir(), "depgraph-web-malformed-locks-"));
  context.after(async () => rm(parent, { recursive: true, force: true }));
  const cases: Array<{ name: string; manager: string; lockfile: string; source: string }> = [
    { name: "npm", manager: "npm@11.0.0", lockfile: "package-lock.json", source: "{ not json" },
    { name: "pnp", manager: "yarn@4.0.0", lockfile: ".pnp.data.json", source: "{ not json" },
    { name: "pnpm", manager: "pnpm@10.33.0", lockfile: "pnpm-lock.yaml", source: "not a pnpm lock\n" },
    { name: "yarn", manager: "yarn@4.0.0", lockfile: "yarn.lock", source: "not a yarn lock\n" },
  ];
  for (const fixtureCase of cases) {
    const root = path.join(parent, fixtureCase.name);
    await mkdir(root);
    await Promise.all([
      writeFile(path.join(root, "package.json"), JSON.stringify({ name: `malformed-${fixtureCase.name}`, packageManager: fixtureCase.manager })),
      writeFile(path.join(root, fixtureCase.lockfile), fixtureCase.source),
    ]);
    const result = await run(`malformed-${fixtureCase.name}`, root);
    const ledger = result.events.find((event) => event.event === "file_completed" && event.path === fixtureCase.lockfile);
    assert.equal(ledger?.skipped, true, fixtureCase.name);
    assert.equal(ledger?.skipped_sites, 1, fixtureCase.name);
    assert.equal(ledger?.discovered_sites, ledger?.emitted_sites + ledger?.skipped_sites, fixtureCase.name);
    assert.ok(result.events.some((event) => (
      event.diagnostic?.code === "web.lockfile_invalid" && event.diagnostic?.path === fixtureCase.lockfile
    )), fixtureCase.name);
    assert.ok(result.events.at(-1)?.coverage.unsupported_syntax > 0, fixtureCase.name);
    assert.deepEqual(result.events.at(-1)?.coverage.completeness, [], fixtureCase.name);
  }
});

test("multiple package-manager lockfiles do not receive an implicit exact priority", async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "depgraph-web-ambiguous-manager-"));
  context.after(async () => rm(root, { recursive: true, force: true }));
  await Promise.all([
    writeFile(path.join(root, "package.json"), JSON.stringify({
      name: "ambiguous-manager",
      packageManager: "unknown-manager@1.0.0",
      dependencies: { shared: "1.0.0" },
    })),
    writeFile(path.join(root, "package-lock.json"), JSON.stringify({
      name: "ambiguous-manager",
      lockfileVersion: 3,
      packages: { "node_modules/shared": { version: "1.0.0" } },
    })),
    writeFile(path.join(root, "yarn.lock"), 'shared@1.0.0:\n  version "2.0.0"\n'),
  ]);

  const result = await run("ambiguous-manager", root);
  assert.equal(result.events.find((event) => event.event === "profile_declared")?.profile.properties.package_manager, "ambiguous");
  const diagnostics = result.events.filter((event) => event.diagnostic?.code === "web.package_manager_ambiguous");
  assert.deepEqual(diagnostics.map((event) => event.diagnostic.path).sort(), ["package-lock.json", "yarn.lock"]);
  for (const lockfile of ["package-lock.json", "yarn.lock"]) {
    const ledger = result.events.find((event) => event.event === "file_completed" && event.path === lockfile);
    assert.equal(ledger?.skipped, true, lockfile);
  }
  const site = result.events.find((event) => event.site?.kind === "package_dependency" && event.site?.specifier === "shared")?.site;
  assert.equal(site?.resolution_status, "external");
  assert.equal(site?.precision, "heuristic");
  assert.match(site?.reason ?? "", /version_from_manifest_range/u);
  assert.deepEqual(result.events.at(-1)?.coverage.completeness, []);
});

test("malformed TypeScript source increments unsupported syntax coverage", async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "depgraph-web-worker-broken-source-"));
  context.after(async () => rm(root, { recursive: true, force: true }));
  await Promise.all([
    writeFile(path.join(root, "package.json"), JSON.stringify({ name: "broken-source", version: "1.0.0" })),
    writeFile(path.join(root, "broken.ts"), "import {"),
  ]);

  const result = await run("broken-source", root);
  assert.ok(result.events.some((event) => event.diagnostic?.code === "web.unsupported_syntax" && event.diagnostic?.path === "broken.ts"));
  const semanticIssue = result.events.find((event) => (
    event.diagnostic?.code === "web.typescript_semantic_syntax_invalid"
  ))?.diagnostic;
  assert.equal(semanticIssue?.properties?.typescript_definition_issue, true);
  const profile = result.events.find((event) => event.event === "profile_declared")?.profile;
  assert.equal(profile?.properties.typescript_definition_graph_status, "ready");
  assert.equal(profile?.properties.typescript_semantic_node_count, "0");
  assert.equal(profile?.properties.typescript_semantic_relation_count, "1");
  assert.equal(profile?.properties.typescript_semantic_site_count, "1");
  assert.equal(profile?.properties.typescript_semantic_call_site_count, "0");
  assert.equal(profile?.properties.typescript_semantic_issue_count, "1");
  const recovered = result.events.find((event) => (
    event.site?.evidence[0]?.kind === "semantic"
    && event.site?.evidence[0]?.properties.occurrence_kind === "empty_import"
  ))?.site;
  assert.equal(recovered?.resolution_status, "unresolved");
  assert.equal(recovered?.reason, "syntax_invalid");
  assert.equal(recovered?.target_ids.length, 1);
  assert.equal(result.events.find((event) => event.node?.id === recovered?.target_ids[0])?.node.kind, "unknown_target");
  assert.ok(result.events.at(-1)?.coverage.unsupported_syntax > 0);
  assert.deepEqual(result.events.at(-1)?.coverage.completeness, []);
  assert.ok(result.events.at(-1)?.coverage.reasons.includes("unsupported_syntax"));
  assert.ok(result.events.at(-1)?.coverage.reasons.includes("typescript_definition_graph_incomplete"));
});

test("balanced malformed TypeScript cannot report syntax-complete coverage", async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "depgraph-web-worker-balanced-broken-"));
  context.after(async () => rm(root, { recursive: true, force: true }));
  await Promise.all([
    writeFile(path.join(root, "package.json"), JSON.stringify({ name: "balanced-broken", version: "1.0.0" })),
    writeFile(path.join(root, "broken.ts"), 'import { x } "./missing"; const = 1'),
  ]);

  const result = await run("balanced-broken", root);
  const diagnostics = result.events.filter((event) => event.diagnostic).map((event) => event.diagnostic);
  assert.ok(diagnostics.some((diagnostic) => diagnostic.code === "web.unsupported_syntax" && /FromKeyword expected/u.test(diagnostic.message)));
  assert.ok(diagnostics.some((diagnostic) => diagnostic.code === "web.unsupported_syntax" && /variable declaration name/u.test(diagnostic.message)));
  assert.ok(result.events.at(-1)?.coverage.unsupported_syntax >= 2);
  assert.deepEqual(result.events.at(-1)?.coverage.completeness, []);
});

test("native TypeScript 7 parser covers every TS and JS extension without loading project config code", async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "depgraph-web-worker-native-syntax-"));
  context.after(async () => rm(root, { recursive: true, force: true }));
  const marker = path.join(root, "PROJECT_PLUGIN_EXECUTED");
  const invalid = new Map([
    ["invalid.ts", "let x: = 1"],
    ["invalid.tsx", "interface X { foo: }"],
    ["invalid.mts", 'import {x as} from "./x"'],
    ["invalid.cts", "type X = ;"],
    ["invalid.js", "const x = ;"],
    ["invalid.jsx", "function f(,) {}"],
    ["invalid.mjs", "const x = ;"],
    ["invalid.cjs", "const x = ;"],
  ]);
  await Promise.all([
    writeFile(path.join(root, "package.json"), JSON.stringify({ name: "native-syntax", version: "1.0.0" })),
    writeFile(path.join(root, "tsconfig.json"), JSON.stringify({
      extends: "dangerous-config-package",
      compilerOptions: { plugins: [{ name: "./dangerous-plugin.cjs" }] },
    })),
    writeFile(
      path.join(root, "dangerous-plugin.cjs"),
      `require("node:fs").writeFileSync(${JSON.stringify(marker)}, "executed");\n`,
    ),
    writeFile(path.join(root, "semantic-only.ts"), "const value: string = 1; missingName();\n"),
    ...[...invalid].map(([file, source]) => writeFile(path.join(root, file), source)),
  ]);

  const result = await run("native-syntax", root);
  const diagnostics = result.events
    .filter((event) => event.diagnostic?.code === "web.unsupported_syntax" && event.diagnostic?.message.startsWith("TypeScript native parser"))
    .map((event) => event.diagnostic);
  assert.deepEqual(
    [...new Set(diagnostics.map((diagnostic) => diagnostic.path))].sort(),
    [...invalid.keys()].sort(),
  );
  assert.ok(diagnostics.every((diagnostic) => diagnostic.evidence?.[0]?.extractor === "typescript-native-syntax"));
  assert.ok(!diagnostics.some((diagnostic) => diagnostic.path === "semantic-only.ts"));
  assert.ok(result.events.at(-1)?.coverage.unsupported_syntax >= invalid.size);
  assert.deepEqual(result.events.at(-1)?.coverage.completeness, []);
  assert.ok(result.events.some((event) => (
    event.diagnostic?.code === "web.static_config_unresolved"
    && /package-based config extends was not loaded/u.test(event.diagnostic.message)
  )));
  await assert.rejects(import("node:fs/promises").then(({ stat }) => stat(marker)));
});

test("TypeChecker definition graph resolves inventory modules and bundled stdlib without reading project packages", async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "depgraph-web-worker-typechecker-scaffold-"));
  context.after(async () => rm(root, { recursive: true, force: true }));
  const packageRoot = path.join(root, "node_modules", "ambient-secret");
  const marker = path.join(root, "PROJECT_PACKAGE_EXECUTED");
  await mkdir(packageRoot, { recursive: true });
  await Promise.all([
    writeFile(path.join(root, "package.json"), JSON.stringify({
      name: "typechecker-scaffold",
      version: "1.0.0",
      dependencies: { "ambient-secret": "1.0.0" },
    })),
    writeFile(path.join(root, "tsconfig.json"), `{
      // Only paths are admitted into the worker-owned config; baseUrl is ignored.
      "compilerOptions": {
        "baseUrl": ".",
        "paths": { "@models/*": ["*"] },
        "plugins": [{ "name": "ambient-secret" }]
      }
    }`),
    writeFile(path.join(root, "model.ts"), [
      "export interface User { name: string }",
      "export const users: Array<User> = [];",
      "",
    ].join("\n")),
    writeFile(path.join(root, "main.ts"), [
      'import { users } from "@models/model";',
      'import { secret } from "ambient-secret";',
      'export const first: Promise<string> = Promise.resolve(users[0]?.name ?? secret);',
      "const firstMismatch: string = 1;",
      "const secondMismatch: string = 1;",
      "",
    ].join("\n")),
    writeFile(path.join(packageRoot, "package.json"), JSON.stringify({
      name: "ambient-secret",
      version: "1.0.0",
      types: "index.d.ts",
      main: "index.cjs",
    })),
    writeFile(path.join(packageRoot, "index.d.ts"), "export declare const secret: string;\n"),
    writeFile(
      path.join(packageRoot, "index.cjs"),
      `require("node:fs").writeFileSync(${JSON.stringify(marker)}, "executed");\n`,
    ),
  ]);

  const result = await run("typechecker-scaffold", root);
  const profile = result.events.find((event) => event.event === "profile_declared")?.profile;
  const semanticDiagnostics = result.events
    .filter((event) => event.diagnostic?.code === "web.typescript_semantic_scaffold_diagnostic")
    .map((event) => event.diagnostic);
  const semanticNodes = result.events
    .filter((event) => event.node?.kind === "symbol" || event.node?.kind === "type")
    .map((event) => event.node);
  const semanticEdges = result.events
    .filter((event) => event.edge?.phase === "semantic")
    .map((event) => event.edge);
  assert.equal(profile?.properties.typescript_project_model_status, "ready");
  assert.equal(profile?.properties.typescript_typechecker_status, "definition-import-type-call-graph-emitted");
  assert.equal(profile?.properties.typescript_definition_graph_status, "ready");
  assert.equal(profile?.properties.typescript_semantic_graph_emission, "definition-import-type-call-graph-v2");
  assert.equal(profile?.properties.typescript_project_root_files, "2");
  assert.ok(Number(profile?.properties.typescript_typechecker_queries) > 1);
  assert.equal(profile?.properties.typescript_static_config_files, "1");
  assert.equal(profile?.properties.typescript_path_mappings, "1");
  assert.ok(Number(profile?.properties.typescript_standard_library_files) > 0);
  assert.equal(
    semanticDiagnostics.filter((diagnostic) => diagnostic.path === "main.ts" && /TS2322/u.test(diagnostic.message)).length,
    2,
  );
  assert.equal(Number(profile?.properties.typescript_emitted_semantic_diagnostics), semanticDiagnostics.length);
  assert.ok(semanticDiagnostics.some((diagnostic) => diagnostic.path === "main.ts" && /TS2307.*ambient-secret/u.test(diagnostic.message)));
  assert.ok(!semanticDiagnostics.some((diagnostic) => /TS2307.*@models\/model/u.test(diagnostic.message)));
  assert.ok(!semanticDiagnostics.some((diagnostic) => /Cannot find global type|Promise only refers to a type/u.test(diagnostic.message)));
  assert.ok(semanticDiagnostics.every((diagnostic) => (
    diagnostic.path === null || diagnostic.evidence?.[0]?.extractor === "typescript-native-typechecker"
  )));
  assert.ok(semanticNodes.some((node) => node.kind === "type" && node.display_name === "User"));
  assert.ok(semanticEdges.some((edge) => edge.kind === "declares"));
  assert.equal(Number(profile?.properties.typescript_semantic_node_count), semanticNodes.length);
  assert.equal(Number(profile?.properties.typescript_semantic_relation_count), semanticEdges.length);
  assert.equal(profile?.properties.typescript_semantic_issue_count, "0");
  assert.ok(semanticEdges.filter((edge) => edge.site_id === null).every((edge) => edge.precision === "exact"));
  assert.ok(!result.events.at(-1)?.coverage.completeness.includes("semantic-complete"));
  assert.ok(result.events.at(-1)?.coverage.reasons.includes("typescript_semantic_diagnostics_present"));
  assert.ok(result.events.at(-1)?.coverage.reasons.includes("typescript_emitted_semantic_diagnostics_present"));
  await assert.rejects(import("node:fs/promises").then(({ stat }) => stat(marker)));
});

test("generic type arguments use the referenced workspace package identity", async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "depgraph-web-worker-generic-package-identity-"));
  context.after(async () => rm(root, { recursive: true, force: true }));
  const baseRoot = path.join(root, "packages", "base");
  const argumentRoot = path.join(root, "packages", "argument");
  const appRoot = path.join(root, "packages", "app");
  await Promise.all([
    mkdir(path.join(baseRoot, "src"), { recursive: true }),
    mkdir(path.join(argumentRoot, "src"), { recursive: true }),
    mkdir(path.join(appRoot, "src"), { recursive: true }),
  ]);
  await Promise.all([
    writeFile(path.join(root, "package.json"), JSON.stringify({
      name: "generic-package-workspace",
      private: true,
      version: "1.0.0",
      workspaces: ["packages/*"],
    })),
    writeFile(path.join(baseRoot, "package.json"), JSON.stringify({ name: "generic-base", version: "1.0.0" })),
    writeFile(path.join(argumentRoot, "package.json"), JSON.stringify({ name: "generic-argument", version: "1.0.0" })),
    writeFile(path.join(appRoot, "package.json"), JSON.stringify({ name: "generic-app", version: "1.0.0" })),
    writeFile(path.join(baseRoot, "src", "base.ts"), "export class Base<T> {}\n"),
    writeFile(path.join(argumentRoot, "src", "argument.ts"), "export class Argument {}\n"),
    writeFile(path.join(appRoot, "src", "app.ts"), [
      "import { Base } from '../../base/src/base';",
      "import { Argument } from '../../argument/src/argument';",
      "export class App extends Base<Argument> {}",
      "",
    ].join("\n")),
  ]);

  const semanticTypes = (events: Array<Record<string, any>>): Array<Record<string, any>> => events
    .filter((event) => event.node?.kind === "type")
    .map((event) => event.node);
  const first = await run("generic-package-identity-v1", root);
  const firstTypes = semanticTypes(first.events);
  const firstArgument = firstTypes.find((node) => node.display_name === "Argument");
  const firstInstance = firstTypes.find((node) => node.properties.type_kind === "generic_instance");
  assert.ok(firstArgument);
  assert.ok(firstInstance);
  assert.equal(
    firstInstance.properties.canonical_identity.type_arguments[0].resolver_identity,
    firstArgument.properties.resolver_identity,
  );
  assert.match(firstArgument.properties.resolver_identity, /generic-argument@1\.0\.0/u);

  await writeFile(path.join(argumentRoot, "package.json"), JSON.stringify({ name: "generic-argument", version: "2.0.0" }));
  const second = await run("generic-package-identity-v2", root);
  const secondTypes = semanticTypes(second.events);
  const secondArgument = secondTypes.find((node) => node.display_name === "Argument");
  const secondInstance = secondTypes.find((node) => node.properties.type_kind === "generic_instance");
  assert.ok(secondArgument);
  assert.ok(secondInstance);
  assert.match(secondArgument.properties.resolver_identity, /generic-argument@2\.0\.0/u);
  assert.notEqual(secondArgument.id, firstArgument.id);
  assert.notEqual(secondInstance.id, firstInstance.id);
});

test("TypeScript path mappings normalize Windows separators before repository confinement", async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "depgraph-web-worker-portable-paths-"));
  context.after(async () => rm(root, { recursive: true, force: true }));
  await Promise.all([
    writeFile(path.join(root, "package.json"), JSON.stringify({ name: "portable-paths", version: "1.0.0" })),
    writeFile(path.join(root, "tsconfig.json"), JSON.stringify({
      compilerOptions: {
        baseUrl: ".",
        paths: { "@outside/*": ["..\\outside\\*"] },
      },
    })),
    writeFile(path.join(root, "index.ts"), 'import value from "@outside/value";\nexport default value;\n'),
  ]);

  const result = await run("portable-paths", root);
  const profile = result.events.find((event) => event.event === "profile_declared")?.profile;
  assert.equal(profile?.properties.typescript_path_mappings, "0");
  assert.ok(result.events.some((event) => (
    event.diagnostic?.code === "web.static_config_unresolved"
    && event.diagnostic?.path === "tsconfig.json"
    && /path alias replacement escapes the repository/u.test(event.diagnostic.message)
  )));
});

test("external package exports reject private and missing subpaths", async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "depgraph-web-worker-external-exports-"));
  context.after(async () => rm(root, { recursive: true, force: true }));
  const packageRoot = path.join(root, "node_modules", "published-package");
  await mkdir(path.join(packageRoot, "dist"), { recursive: true });
  await Promise.all([
    writeFile(path.join(root, "package.json"), JSON.stringify({
      name: "external-exports",
      version: "1.0.0",
      dependencies: { "published-package": "1.2.3" },
    })),
    writeFile(path.join(root, "index.ts"), [
      'import "published-package/public";',
      'import "published-package/private";',
      'import "published-package/missing";',
    ].join("\n")),
    writeFile(path.join(packageRoot, "package.json"), JSON.stringify({
      name: "published-package",
      version: "1.2.3",
      exports: {
        ".": "./dist/index.js",
        "./public": "./dist/public.js",
        "./missing": "./dist/does-not-exist.js",
      },
    })),
    writeFile(path.join(packageRoot, "dist", "index.js"), "export const root = true;\n"),
    writeFile(path.join(packageRoot, "dist", "public.js"), "export const value = true;\n"),
    writeFile(path.join(packageRoot, "private.js"), "export const secret = true;\n"),
  ]);

  const result = await run("external-exports", root);
  const sites = result.events.filter((event) => event.site?.kind === "side_effect_import").map((event) => event.site);
  const publicSite = sites.find((site) => site.specifier === "published-package/public");
  const privateSite = sites.find((site) => site.specifier === "published-package/private");
  const missingSite = sites.find((site) => site.specifier === "published-package/missing");
  assert.equal(publicSite?.resolution_status, "external");
  assert.equal(publicSite?.precision, "exact");
  assert.equal(privateSite?.resolution_status, "unresolved");
  assert.match(privateSite?.reason ?? "", /package_subpath_not_exported/u);
  assert.equal(missingSite?.resolution_status, "unresolved");
  assert.match(missingSite?.reason ?? "", /package_export_target_not_found/u);
});

test("external subpath resolution is bound to the nearest installed package", async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "depgraph-web-external-lock-candidates-"));
  context.after(async () => rm(root, { recursive: true, force: true }));
  const packageRoot = path.join(root, "node_modules", "multi-export");
  await mkdir(path.join(packageRoot, "dist"), { recursive: true });
  await Promise.all([
    writeFile(path.join(root, "package.json"), JSON.stringify({
      name: "external-lock-candidates",
      dependencies: { "multi-export": "^1.0.0 || ^2.0.0" },
    })),
    writeFile(path.join(root, "package-lock.json"), JSON.stringify({
      name: "external-lock-candidates",
      lockfileVersion: 3,
      packages: {
        "": { name: "external-lock-candidates" },
        "node_modules/multi-export": { version: "1.0.0" },
        "node_modules/nested/node_modules/multi-export": { version: "2.0.0" },
      },
    })),
    writeFile(path.join(root, "index.ts"), 'import "multi-export/public";\nimport "multi-export/private";\n'),
    writeFile(path.join(packageRoot, "package.json"), JSON.stringify({
      name: "multi-export",
      version: "1.0.0",
      exports: { "./public": "./dist/public.js" },
    })),
    writeFile(path.join(packageRoot, "dist", "public.js"), "export const value = true;\n"),
  ]);

  const result = await run("external-lock-candidates", root);
  const nodes = new Map(result.events.filter((event) => event.node).map((event) => [event.node.id, event.node]));
  const sites = result.events.filter((event) => event.site?.kind === "side_effect_import").map((event) => event.site);
  const publicSite = sites.find((site) => site.specifier === "multi-export/public");
  const privateSite = sites.find((site) => site.specifier === "multi-export/private");
  assert.equal(publicSite?.resolution_status, "external");
  assert.deepEqual(publicSite?.target_ids.map((id: string) => nodes.get(id)?.properties.version), ["1.0.0"]);
  assert.equal(privateSite?.resolution_status, "unresolved");
  assert.match(privateSite?.reason ?? "", /package_subpath_not_exported/u);
});

test("workspace package exports do not fall back to private files", async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "depgraph-web-worker-workspace-exports-"));
  context.after(async () => rm(root, { recursive: true, force: true }));
  const shared = path.join(root, "packages", "shared");
  await mkdir(path.join(shared, "src"), { recursive: true });
  await Promise.all([
    writeFile(path.join(root, "package.json"), JSON.stringify({
      name: "workspace-exports",
      workspaces: ["packages/*"],
      dependencies: { "shared-package": "workspace:*" },
    })),
    writeFile(path.join(root, "index.ts"), 'import "shared-package/public";\nimport "shared-package/private";\n'),
    writeFile(path.join(shared, "package.json"), JSON.stringify({
      name: "shared-package",
      version: "1.0.0",
      exports: { "./public": "./src/public.ts" },
    })),
    writeFile(path.join(shared, "src", "public.ts"), "export const value = true;\n"),
    writeFile(path.join(shared, "private.ts"), "export const secret = true;\n"),
  ]);

  const result = await run("workspace-exports", root);
  const sites = result.events.filter((event) => event.site?.kind === "side_effect_import").map((event) => event.site);
  assert.equal(sites.find((site) => site.specifier === "shared-package/public")?.resolution_status, "resolved");
  const privateSite = sites.find((site) => site.specifier === "shared-package/private");
  assert.equal(privateSite?.resolution_status, "unresolved");
  assert.match(privateSite?.reason ?? "", /package_subpath_not_exported/u);
});

test("semantic Node builtins are exact for known prefixed and bare module names only", async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "depgraph-web-worker-node-builtins-"));
  context.after(async () => rm(root, { recursive: true, force: true }));
  await mkdir(path.join(root, "src"), { recursive: true });
  await Promise.all([
    writeFile(path.join(root, "package.json"), JSON.stringify({ name: "node-builtins", version: "1.0.0" })),
    writeFile(path.join(root, "tsconfig.json"), JSON.stringify({
      compilerOptions: { paths: { "node:*": ["src/*"] } },
    })),
    writeFile(path.join(root, "src", "fs.ts"), "export const readFile = 'shadowed';\n"),
    writeFile(path.join(root, "src", "not-a-real-builtin.ts"), "export const nonexistent = 'shadowed';\n"),
    writeFile(path.join(root, "index.ts"), [
      'import { readFile } from "node:fs";',
      'import { join } from "path";',
      'import { readFile as readFilePromise } from "fs/promises";',
      'import { nonexistent } from "node:not-a-real-builtin";',
      'const bareFs = require("fs");',
      "void readFile;",
      "void join;",
      "void readFilePromise;",
      "void bareFs;",
      "void nonexistent;",
      "",
    ].join("\n")),
  ]);

  const result = await run("node-builtins", root);
  const nodes = new Map(result.events.filter((event) => event.node).map((event) => [event.node.id, event.node]));
  const semanticImports = result.events
    .filter((event) => event.site?.kind === "web_import" && event.site.evidence[0]?.kind === "semantic")
    .map((event) => event.site);
  const known = semanticImports.find((site) => site.specifier === "node:fs");
  assert.equal(known?.resolution_status, "external");
  assert.equal(known?.precision, "exact");
  assert.equal(known?.reason, null);
  assert.equal(known?.evidence[0]?.properties.occurrence_kind, "named_import");
  assert.equal(known?.evidence[0]?.properties.imported_name, "readFile");
  const knownTarget = nodes.get(known?.target_ids[0]);
  assert.equal(knownTarget?.kind, "external_system");
  assert.equal(knownTarget?.locator, "external://typescript/node%3Afs");
  assert.deepEqual(knownTarget?.properties.canonical_identity, {
    language: "typescript",
    compiler_version: "7.0.2",
    locator: "node:fs",
  });

  const bareImport = semanticImports.find((site) => site.specifier === "path");
  assert.equal(bareImport?.resolution_status, "external");
  assert.equal(bareImport?.precision, "exact");
  assert.equal(bareImport?.reason, null);
  assert.equal(bareImport?.evidence[0]?.properties.occurrence_kind, "named_import");
  assert.equal(nodes.get(bareImport?.target_ids[0])?.locator, "external://typescript/node%3Apath");

  const bareRequire = semanticImports.find((site) => (
    site.specifier === "fs" && site.evidence[0]?.properties.occurrence_kind === "require_call"
  ));
  assert.equal(bareRequire?.resolution_status, "external");
  assert.equal(bareRequire?.precision, "exact");
  assert.equal(bareRequire?.reason, null);
  assert.equal(nodes.get(bareRequire?.target_ids[0])?.locator, "external://typescript/node%3Afs");
  assert.equal(bareRequire?.target_ids[0], known?.target_ids[0]);

  const bareSubpath = semanticImports.find((site) => site.specifier === "fs/promises");
  assert.equal(bareSubpath?.resolution_status, "external");
  assert.equal(bareSubpath?.precision, "exact");
  assert.equal(bareSubpath?.reason, null);
  assert.equal(nodes.get(bareSubpath?.target_ids[0])?.locator, "external://typescript/node%3Afs%2Fpromises");

  const unknown = semanticImports.find((site) => site.specifier === "node:not-a-real-builtin");
  assert.equal(unknown?.resolution_status, "unresolved");
  assert.equal(unknown?.precision, "heuristic");
  assert.equal(unknown?.reason, "unknown_node_builtin");
  assert.equal(nodes.get(unknown?.target_ids[0])?.kind, "unknown_target");
  assert.notEqual(nodes.get(known?.target_ids[0])?.properties.path, "src/fs.ts");
  assert.notEqual(nodes.get(unknown?.target_ids[0])?.properties.path, "src/not-a-real-builtin.ts");
});

test("semantic package resolution uses TypeScript's neutral Bundler conditions", async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "depgraph-web-worker-phase-exports-"));
  context.after(async () => rm(root, { recursive: true, force: true }));
  const packageRoot = path.join(root, "packages", "phase-package");
  await mkdir(path.join(packageRoot, "src"), { recursive: true });
  await Promise.all([
    writeFile(path.join(root, "package.json"), JSON.stringify({
      name: "phase-exports",
      workspaces: ["packages/*"],
      dependencies: { "phase-package": "workspace:*" },
    })),
    writeFile(path.join(root, "index.ts"), [
      'import type { Branch as BranchType } from "phase-package";',
      'import { Branch as RuntimeBranch } from "phase-package";',
      'import { RuntimeBranch as ImportBranch } from "phase-package/runtime";',
      'const requiredBranch = require("phase-package/runtime");',
      "export interface UsesBranch { readonly branch: BranchType }",
      "export const runtimeBranch = new RuntimeBranch();",
      "export const importBranch = new ImportBranch();",
      "void requiredBranch;",
      "",
    ].join("\n")),
    writeFile(path.join(packageRoot, "package.json"), JSON.stringify({
      name: "phase-package",
      version: "1.0.0",
      exports: {
        ".": {
          types: "./src/types.d.ts",
          browser: "./src/browser.ts",
          node: "./src/node.ts",
          import: "./src/import.ts",
          require: "./src/require.ts",
          default: "./src/default.ts",
        },
        "./runtime": {
          browser: "./src/browser-runtime.ts",
          node: "./src/node-runtime.ts",
          import: "./src/import.ts",
          require: "./src/require.ts",
          default: "./src/default.ts",
        },
      },
    })),
    writeFile(path.join(packageRoot, "src", "types.d.ts"), "export declare class Branch { readonly declared: true }\n"),
    writeFile(path.join(packageRoot, "src", "browser.ts"), "export class Branch { browser = true; }\n"),
    writeFile(path.join(packageRoot, "src", "node.ts"), "export class Branch { node = true; }\n"),
    writeFile(path.join(packageRoot, "src", "browser-runtime.ts"), "export class RuntimeBranch { browser = true; }\n"),
    writeFile(path.join(packageRoot, "src", "node-runtime.ts"), "export class RuntimeBranch { node = true; }\n"),
    writeFile(path.join(packageRoot, "src", "import.ts"), "export class RuntimeBranch { imported = true; }\n"),
    writeFile(path.join(packageRoot, "src", "require.ts"), "export const requiredBranch = 'require';\n"),
    writeFile(path.join(packageRoot, "src", "default.ts"), "export class RuntimeBranch { fallback = true; }\n"),
  ]);

  const result = await run("phase-exports", root);
  const nodes = new Map(result.events.filter((event) => event.node).map((event) => [event.node.id, event.node]));
  const sites = result.events
    .filter((event) => event.site?.kind === "web_import" && event.site.evidence[0]?.kind === "semantic")
    .map((event) => event.site)
    .filter((site) => site.specifier === "phase-package" || site.specifier === "phase-package/runtime");
  const edges = result.events.filter((event) => event.edge?.phase === "semantic").map((event) => event.edge);
  const typeImport = sites.find((site) => (
    site.evidence[0]?.properties.occurrence_kind === "named_import"
    && site.evidence[0]?.properties.imported_name === "Branch"
    && site.evidence[0]?.properties.type_only === true
  ));
  const runtimeImport = sites.find((site) => (
    site.specifier === "phase-package"
    && site.evidence[0]?.properties.occurrence_kind === "named_import"
    && site.evidence[0]?.properties.imported_name === "Branch"
    && site.evidence[0]?.properties.type_only === false
  ));
  const importBranch = sites.find((site) => (
    site.specifier === "phase-package/runtime"
    && site.evidence[0]?.properties.occurrence_kind === "named_import"
    && site.evidence[0]?.properties.imported_name === "RuntimeBranch"
    && site.evidence[0]?.properties.type_only === false
  ));
  const requireImport = sites.find((site) => (
    site.specifier === "phase-package/runtime"
    && site.evidence[0]?.properties.occurrence_kind === "require_call"
  ));
  const targetPath = (targetId: string): string => (
    nodes.get(targetId)?.properties.source_path ?? nodes.get(targetId)?.display_name
  );
  const neutralCondition = {
    op: "all",
    conditions: [
      { op: "eq", key: "mode", value: "production" },
      { op: "in", key: "environment", values: ["browser", "server"] },
    ],
  };
  for (const site of [typeImport, runtimeImport, importBranch, requireImport]) {
    assert.equal(site?.resolution_status, "resolved");
    assert.equal(site?.precision, "exact");
    assert.equal(site?.target_ids.length, 1);
    const linked = edges.filter((edge) => edge.site_id === site?.id);
    assert.equal(linked.length, 1);
    assert.deepEqual(linked[0]?.condition, site?.condition);
    assert.deepEqual(site?.condition, neutralCondition);
    assert.doesNotMatch(JSON.stringify(site?.condition), /package\.exports\.condition/u);
  }
  assert.equal(targetPath(typeImport?.target_ids[0]), "packages/phase-package/src/types.d.ts");
  assert.equal(targetPath(runtimeImport?.target_ids[0]), "packages/phase-package/src/types.d.ts");
  assert.equal(targetPath(importBranch?.target_ids[0]), "packages/phase-package/src/import.ts");
  assert.equal(targetPath(requireImport?.target_ids[0]), "packages/phase-package/src/require.ts");
});

test("overlapping TypeScript paths preserve declaration-order ties within the owning workspace", async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "depgraph-web-worker-owned-paths-"));
  context.after(async () => rm(root, { recursive: true, force: true }));
  const packages = ["a", "b"];
  await Promise.all(packages.flatMap((owner) => [
    mkdir(path.join(root, "packages", owner, "src", "special"), { recursive: true }),
    mkdir(path.join(root, "packages", owner, "src", "general"), { recursive: true }),
  ]));
  await Promise.all([
    writeFile(path.join(root, "package.json"), JSON.stringify({
      name: "owned-paths",
      workspaces: ["packages/*"],
    })),
    ...packages.flatMap((owner) => [
      writeFile(path.join(root, "packages", owner, "package.json"), JSON.stringify({
        name: `owned-paths-${owner}`,
        version: "1.0.0",
      })),
      writeFile(path.join(root, "packages", owner, "tsconfig.json"), JSON.stringify({
        compilerOptions: {
          baseUrl: ".",
          paths: {
            "@owned/*ä": ["src/general/*"],
            "@owned/*zä": ["src/special/*"],
          },
        },
      })),
      writeFile(
        path.join(root, "packages", owner, "src", "special", "z.ts"),
        `export interface Selected { readonly owner: '${owner}-special' }\n`,
      ),
      writeFile(
        path.join(root, "packages", owner, "src", "general", "zz.ts"),
        `export interface Selected { readonly owner: '${owner}-general' }\n`,
      ),
    ]),
    writeFile(path.join(root, "packages", "b", "src", "index.ts"), [
      'import type { Selected } from "@owned/zzä";',
      "export interface UsesSelected { readonly selected: Selected }",
      "",
    ].join("\n")),
  ]);

  const result = await run("owned-paths", root);
  const nodes = new Map(result.events.filter((event) => event.node).map((event) => [event.node.id, event.node]));
  const sites = result.events.filter((event) => event.site?.evidence[0]?.kind === "semantic").map((event) => event.site);
  const ownedImport = sites.find((site) => (
    site.kind === "web_import"
    && site.specifier === "@owned/zzä"
    && site.evidence[0]?.properties.occurrence_kind === "named_import"
  ));
  const ownedTypeUse = sites.find((site) => (
    site.kind === "type_use"
    && site.specifier === "Selected"
    && site.evidence[0]?.properties.module_specifier === "@owned/zzä"
  ));
  for (const site of [ownedImport, ownedTypeUse]) {
    assert.equal(site?.resolution_status, "resolved");
    assert.equal(site?.precision, "exact");
    assert.equal(site?.target_ids.length, 1);
    assert.equal(nodes.get(site?.target_ids[0])?.properties.source_path, "packages/b/src/general/zz.ts");
  }
});

test("neutral TypeScript paths fail closed when owners reverse equal-prefix pattern order", async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "depgraph-web-worker-neutral-path-order-"));
  context.after(async () => rm(root, { recursive: true, force: true }));
  await Promise.all([
    mkdir(path.join(root, "packages", "a", "src"), { recursive: true }),
    mkdir(path.join(root, "packages", "a", "shared"), { recursive: true }),
    mkdir(path.join(root, "packages", "b", "src"), { recursive: true }),
  ]);
  await Promise.all([
    writeFile(path.join(root, "package.json"), JSON.stringify({
      name: "neutral-path-order",
      workspaces: ["packages/*"],
    })),
    writeFile(path.join(root, "packages", "a", "package.json"), JSON.stringify({
      name: "neutral-path-order-a",
      version: "1.0.0",
    })),
    writeFile(path.join(root, "packages", "a", "tsconfig.json"), JSON.stringify({
      compilerOptions: {
        paths: {
          "@/*suffix": ["shared/*"],
          "@/*": ["shared/*"],
        },
      },
    })),
    writeFile(path.join(root, "packages", "a", "src", "index.ts"), [
      'import Alias = require("@/valuesuffix");',
      "export type UsesAlias = Alias;",
      "",
    ].join("\n")),
    writeFile(path.join(root, "packages", "a", "shared", "value.ts"), [
      "class Specific { readonly selected = 'specific' }",
      "export = Specific;",
      "",
    ].join("\n")),
    writeFile(path.join(root, "packages", "a", "shared", "valuesuffix.ts"), [
      "class Broad { readonly selected = 'broad' }",
      "export = Broad;",
      "",
    ].join("\n")),
    writeFile(path.join(root, "packages", "b", "package.json"), JSON.stringify({
      name: "neutral-path-order-b",
      version: "1.0.0",
    })),
    writeFile(path.join(root, "packages", "b", "tsconfig.json"), JSON.stringify({
      compilerOptions: {
        paths: {
          "@/*": ["../a/shared/*"],
          "@/*suffix": ["../a/shared/*"],
        },
      },
    })),
    writeFile(path.join(root, "packages", "b", "src", "index.ts"), [
      'import Alias = require("@/valuesuffix");',
      "export type UsesAlias = Alias;",
      "",
    ].join("\n")),
  ]);

  const result = await run("neutral-path-order", root);
  const nodes = new Map(result.events.filter((event) => event.node).map((event) => [event.node.id, event.node]));
  const sites = result.events
    .filter((event) => event.site?.evidence[0]?.kind === "semantic")
    .map((event) => event.site);
  const expectedTargets = new Map([
    ["packages/a/src/index.ts", "packages/a/shared/value.ts"],
    ["packages/b/src/index.ts", "packages/a/shared/valuesuffix.ts"],
  ]);
  for (const [sourcePath, expectedTarget] of expectedTargets) {
    const moduleImport = sites.find((site) => (
      site.kind === "web_import"
      && site.specifier === "@/valuesuffix"
      && site.evidence[0]?.path === sourcePath
      && site.evidence[0]?.properties.occurrence_kind === "import_equals"
    ));
    assert.equal(moduleImport?.resolution_status, "resolved");
    assert.equal(moduleImport?.precision, "exact");
    assert.equal(moduleImport?.target_ids.length, 1);
    assert.equal(nodes.get(moduleImport?.target_ids[0])?.properties.path, expectedTarget);

    const rootTypeUse = sites.find((site) => (
      site.kind === "type_use"
      && site.specifier === "="
      && site.evidence[0]?.path === sourcePath
      && site.evidence[0]?.properties.module_specifier === "@/valuesuffix"
    ));
    assert.equal(rootTypeUse?.resolution_status, "resolved");
    assert.equal(rootTypeUse?.precision, "exact");
    assert.equal(rootTypeUse?.reason, null);
    assert.equal(nodes.get(rootTypeUse?.target_ids[0])?.kind, "type");
    assert.equal(nodes.get(rootTypeUse?.target_ids[0])?.properties.source_path, expectedTarget);
  }
  const unresolvedCompilerPaths = result.events
    .filter((event) => (
      event.diagnostic?.code === "web.typescript_semantic_scaffold_diagnostic"
      && /TS2307.*@\/valuesuffix/u.test(event.diagnostic.message)
    ))
    .map((event) => event.diagnostic.path)
    .sort();
  assert.deepEqual(unresolvedCompilerPaths, ["packages/a/src/index.ts", "packages/b/src/index.ts"]);
});

test("workspace hints overlapping owner aliases stay out of the neutral import-equals program", async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "depgraph-web-worker-path-workspace-overlap-"));
  context.after(async () => rm(root, { recursive: true, force: true }));
  await Promise.all([
    mkdir(path.join(root, "packages", "a", "src"), { recursive: true }),
    mkdir(path.join(root, "packages", "a", "local"), { recursive: true }),
    mkdir(path.join(root, "packages", "b", "src"), { recursive: true }),
    mkdir(path.join(root, "packages", "shared"), { recursive: true }),
  ]);
  await Promise.all([
    writeFile(path.join(root, "package.json"), JSON.stringify({
      name: "path-workspace-overlap",
      workspaces: ["packages/*"],
    })),
    writeFile(path.join(root, "packages", "a", "package.json"), JSON.stringify({
      name: "path-workspace-overlap-a",
      version: "1.0.0",
      dependencies: { shared: "workspace:*" },
    })),
    writeFile(path.join(root, "packages", "a", "tsconfig.json"), JSON.stringify({
      compilerOptions: { paths: { "*": ["./local/*"] } },
    })),
    writeFile(path.join(root, "packages", "a", "src", "index.ts"), [
      'import Shared = require("shared");',
      "export type UsesShared = Shared;",
      "",
    ].join("\n")),
    writeFile(path.join(root, "packages", "a", "local", "shared.ts"), [
      "class LocalShared { readonly owner = 'local' }",
      "export = LocalShared;",
      "",
    ].join("\n")),
    writeFile(path.join(root, "packages", "b", "package.json"), JSON.stringify({
      name: "path-workspace-overlap-b",
      version: "1.0.0",
      dependencies: { shared: "workspace:*" },
    })),
    writeFile(path.join(root, "packages", "b", "src", "index.ts"), [
      'import Shared = require("shared");',
      "export type UsesShared = Shared;",
      "",
    ].join("\n")),
    writeFile(path.join(root, "packages", "shared", "package.json"), JSON.stringify({
      name: "shared",
      version: "1.0.0",
      exports: "./index.ts",
    })),
    writeFile(path.join(root, "packages", "shared", "index.ts"), [
      "class WorkspaceShared { readonly owner = 'workspace' }",
      "export = WorkspaceShared;",
      "",
    ].join("\n")),
  ]);

  const result = await run("path-workspace-overlap", root);
  const nodes = new Map(result.events.filter((event) => event.node).map((event) => [event.node.id, event.node]));
  const sites = result.events
    .filter((event) => event.site?.evidence[0]?.kind === "semantic")
    .map((event) => event.site);
  const expectedTargets = new Map([
    ["packages/a/src/index.ts", "packages/a/local/shared.ts"],
    ["packages/b/src/index.ts", "packages/shared/index.ts"],
  ]);
  for (const [sourcePath, expectedTarget] of expectedTargets) {
    const moduleImport = sites.find((site) => (
      site.kind === "web_import"
      && site.specifier === "shared"
      && site.evidence[0]?.path === sourcePath
      && site.evidence[0]?.properties.occurrence_kind === "import_equals"
    ));
    assert.equal(moduleImport?.resolution_status, "resolved");
    assert.equal(moduleImport?.precision, "exact");
    assert.equal(nodes.get(moduleImport?.target_ids[0])?.properties.path, expectedTarget);
    const rootTypeUse = sites.find((site) => (
      site.kind === "type_use"
      && site.specifier === "="
      && site.evidence[0]?.path === sourcePath
      && site.evidence[0]?.properties.module_specifier === "shared"
    ));
    assert.equal(rootTypeUse?.resolution_status, "resolved");
    assert.equal(rootTypeUse?.precision, "exact");
    assert.equal(rootTypeUse?.reason, null);
    assert.equal(nodes.get(rootTypeUse?.target_ids[0])?.kind, "type");
    assert.equal(nodes.get(rootTypeUse?.target_ids[0])?.properties.source_path, expectedTarget);
  }
  const unresolvedCompilerPaths = result.events
    .filter((event) => (
      event.diagnostic?.code === "web.typescript_semantic_scaffold_diagnostic"
      && /TS2307.*shared/u.test(event.diagnostic.message)
    ))
    .map((event) => event.diagnostic.path)
    .sort();
  assert.deepEqual(unresolvedCompilerPaths, ["packages/a/src/index.ts", "packages/b/src/index.ts"]);
});

test("phase-specific workspace type exports stay out of the neutral import-equals program", async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "depgraph-web-worker-workspace-phase-hint-"));
  context.after(async () => rm(root, { recursive: true, force: true }));
  await Promise.all([
    mkdir(path.join(root, "packages", "consumer", "src"), { recursive: true }),
    mkdir(path.join(root, "packages", "phase-split"), { recursive: true }),
  ]);
  await Promise.all([
    writeFile(path.join(root, "package.json"), JSON.stringify({
      name: "workspace-phase-hint",
      workspaces: ["packages/*"],
    })),
    writeFile(path.join(root, "packages", "consumer", "package.json"), JSON.stringify({
      name: "workspace-phase-consumer",
      version: "1.0.0",
      dependencies: { "phase-split": "workspace:*" },
    })),
    writeFile(path.join(root, "packages", "consumer", "src", "index.ts"), [
      'import Phase = require("phase-split");',
      "export type UsesPhase = Phase;",
      "export type UsesMember = Phase.Member;",
      "",
    ].join("\n")),
    writeFile(path.join(root, "packages", "phase-split", "package.json"), JSON.stringify({
      name: "phase-split",
      version: "1.0.0",
      exports: {
        import: { types: "./import.ts", default: "./import.ts" },
        require: { types: "./require.ts", default: "./require.ts" },
      },
    })),
    writeFile(path.join(root, "packages", "phase-split", "import.ts"), [
      "class ImportPhase { readonly phase = 'import' }",
      "namespace ImportPhase { export interface Member { readonly phase: 'import' } }",
      "export = ImportPhase;",
      "",
    ].join("\n")),
    writeFile(path.join(root, "packages", "phase-split", "require.ts"), [
      "class RequirePhase { readonly phase = 'require' }",
      "namespace RequirePhase { export interface Member { readonly phase: 'require' } }",
      "export = RequirePhase;",
      "",
    ].join("\n")),
  ]);

  const result = await run("workspace-phase-hint", root);
  const nodes = new Map(result.events.filter((event) => event.node).map((event) => [event.node.id, event.node]));
  const sites = result.events
    .filter((event) => event.site?.evidence[0]?.kind === "semantic")
    .map((event) => event.site);
  const moduleImport = sites.find((site) => (
    site.kind === "web_import"
    && site.specifier === "phase-split"
    && site.evidence[0]?.properties.occurrence_kind === "import_equals"
  ));
  assert.equal(moduleImport?.resolution_status, "resolved");
  assert.equal(moduleImport?.precision, "exact");
  assert.equal(nodes.get(moduleImport?.target_ids[0])?.properties.path, "packages/phase-split/require.ts");
  const rootTypeUse = sites.find((site) => (
    site.kind === "type_use"
    && site.specifier === "="
    && site.evidence[0]?.properties.module_specifier === "phase-split"
  ));
  assert.equal(rootTypeUse?.resolution_status, "resolved");
  assert.equal(rootTypeUse?.precision, "exact");
  assert.equal(rootTypeUse?.reason, null);
  assert.equal(nodes.get(rootTypeUse?.target_ids[0])?.kind, "type");
  assert.equal(nodes.get(rootTypeUse?.target_ids[0])?.properties.source_path, "packages/phase-split/require.ts");
  const qualifiedTypeUse = sites.find((site) => (
    site.kind === "type_use"
    && site.specifier === "Member"
    && site.evidence[0]?.properties.module_specifier === "phase-split"
  ));
  assert.equal(qualifiedTypeUse?.resolution_status, "resolved");
  assert.equal(qualifiedTypeUse?.precision, "exact");
  assert.equal(qualifiedTypeUse?.reason, null);
  assert.ok(!Object.hasOwn(qualifiedTypeUse?.evidence[0]?.properties ?? {}, "resolution_mode"));
  assert.equal(nodes.get(qualifiedTypeUse?.target_ids[0])?.kind, "type");
  assert.equal(nodes.get(qualifiedTypeUse?.target_ids[0])?.display_name, "Member");
  assert.equal(nodes.get(qualifiedTypeUse?.target_ids[0])?.properties.source_path, "packages/phase-split/require.ts");
  assert.ok(result.events.some((event) => (
    event.diagnostic?.code === "web.typescript_semantic_scaffold_diagnostic"
    && event.diagnostic.path === "packages/consumer/src/index.ts"
    && /TS2307.*phase-split/u.test(event.diagnostic.message)
  )));
});

test("export-equals object properties and forwarding aliases retain exact qualified type proof", async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "depgraph-web-worker-export-equals-properties-"));
  context.after(async () => rm(root, { recursive: true, force: true }));
  await mkdir(path.join(root, "src"), { recursive: true });
  await Promise.all([
    writeFile(path.join(root, "package.json"), JSON.stringify({
      name: "export-equals-properties",
      version: "1.0.0",
    })),
    writeFile(path.join(root, "src", "api.ts"), [
      "class PropertyMember { readonly value = 1 }",
      "const API = { PropertyMember };",
      "export = API;",
      "",
    ].join("\n")),
    writeFile(path.join(root, "src", "bridge.ts"), [
      'import API = require("./api");',
      "export = API;",
      "",
    ].join("\n")),
    writeFile(path.join(root, "src", "factory.ts"), [
      "class FactoryMember { readonly value = 2 }",
      "function makeAPI() { return { FactoryMember }; }",
      "export = makeAPI();",
      "",
    ].join("\n")),
    writeFile(path.join(root, "src", "wrapped.ts"), [
      "class Wrapped { readonly value = 3 }",
      "export = (Wrapped);",
      "",
    ].join("\n")),
    writeFile(path.join(root, "src", "consumer.ts"), [
      'import Direct = require("./api");',
      'import Forwarded = require("./bridge");',
      'import Factory = require("./factory");',
      'import Wrapped = require("./wrapped");',
      "export type DirectUse = typeof Direct.PropertyMember;",
      "export type ForwardedUse = typeof Forwarded.PropertyMember;",
      "export type FactoryUse = typeof Factory.FactoryMember;",
      "export type WrappedUse = Wrapped;",
      "",
    ].join("\n")),
  ]);

  const result = await run("export-equals-properties", root);
  const nodes = new Map(result.events.filter((event) => event.node).map((event) => [event.node.id, event.node]));
  const propertyUses = result.events
    .filter((event) => (
      event.site?.kind === "type_use"
      && event.site.specifier === "PropertyMember"
      && event.site.evidence[0]?.path === "src/consumer.ts"
    ))
    .map((event) => event.site);
  assert.equal(propertyUses.length, 2, JSON.stringify(propertyUses));
  for (const site of propertyUses) {
    assert.equal(site.resolution_status, "resolved");
    assert.equal(site.precision, "exact");
    assert.equal(site.reason, null);
    assert.equal(site.target_ids.length, 1);
    assert.equal(nodes.get(site.target_ids[0])?.kind, "type");
    assert.equal(nodes.get(site.target_ids[0])?.display_name, "PropertyMember");
    assert.equal(nodes.get(site.target_ids[0])?.properties.source_path, "src/api.ts");
    assert.ok(!Object.hasOwn(site.evidence[0]?.properties ?? {}, "resolution_mode"));
    assert.ok(!Object.hasOwn(site.evidence[0]?.properties ?? {}, "binding_origin"));
  }
  const factoryUse = result.events.find((event) => (
    event.site?.kind === "type_use"
    && event.site.specifier === "FactoryMember"
    && event.site.evidence[0]?.path === "src/consumer.ts"
  ))?.site;
  assert.equal(factoryUse?.resolution_status, "resolved");
  assert.equal(factoryUse?.precision, "exact");
  assert.equal(factoryUse?.reason, null);
  assert.equal(factoryUse?.target_ids.length, 1);
  assert.equal(nodes.get(factoryUse?.target_ids[0])?.kind, "type");
  assert.equal(nodes.get(factoryUse?.target_ids[0])?.display_name, "FactoryMember");
  assert.equal(nodes.get(factoryUse?.target_ids[0])?.properties.source_path, "src/factory.ts");
  const wrappedUse = result.events.find((event) => (
    event.site?.kind === "type_use"
    && event.site.specifier === "="
    && event.site.evidence[0]?.properties.module_specifier === "./wrapped"
  ))?.site;
  assert.equal(wrappedUse?.resolution_status, "resolved");
  assert.equal(wrappedUse?.precision, "exact");
  assert.equal(wrappedUse?.reason, null);
  assert.equal(wrappedUse?.target_ids.length, 1);
  assert.equal(nodes.get(wrappedUse?.target_ids[0])?.kind, "type");
  assert.equal(nodes.get(wrappedUse?.target_ids[0])?.display_name, "Wrapped");
  assert.equal(nodes.get(wrappedUse?.target_ids[0])?.properties.source_path, "src/wrapped.ts");
});

test("foreign-owner JSDoc requests prevent owner alias exact hints", async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "depgraph-web-worker-foreign-jsdoc-alias-"));
  context.after(async () => rm(root, { recursive: true, force: true }));
  await Promise.all([
    mkdir(path.join(root, "packages", "a", "src"), { recursive: true }),
    mkdir(path.join(root, "packages", "b", "src"), { recursive: true }),
  ]);
  await Promise.all([
    writeFile(path.join(root, "package.json"), JSON.stringify({
      name: "foreign-jsdoc-alias",
      private: true,
      packageManager: "npm@11.0.0",
      workspaces: ["packages/*"],
    })),
    writeFile(path.join(root, "package-lock.json"), JSON.stringify({
      name: "foreign-jsdoc-alias",
      lockfileVersion: 3,
      packages: {
        "": { name: "foreign-jsdoc-alias" },
        "node_modules/@private/value": { version: "1.0.0" },
      },
    })),
    writeFile(path.join(root, "packages", "a", "package.json"), JSON.stringify({
      name: "foreign-jsdoc-alias-a",
      version: "1.0.0",
    })),
    writeFile(path.join(root, "packages", "a", "tsconfig.json"), JSON.stringify({
      compilerOptions: { paths: { "@private/*": ["src/*"] } },
    })),
    writeFile(path.join(root, "packages", "a", "src", "index.ts"), [
      'import type { Value } from "@private/value";',
      "export type LocalUse = Value;",
      "",
    ].join("\n")),
    writeFile(
      path.join(root, "packages", "a", "src", "value.ts"),
      "export interface Value { readonly owner: 'a' }\n",
    ),
    writeFile(path.join(root, "packages", "b", "package.json"), JSON.stringify({
      name: "foreign-jsdoc-alias-b",
      version: "1.0.0",
      dependencies: { "@private/value": "1.0.0" },
    })),
    writeFile(path.join(root, "packages", "b", "src", "index.js"), [
      "// @ts-check",
      '/** @type {import("@private/value").Value} */',
      "export const foreign = {};",
      "",
    ].join("\n")),
  ]);

  const result = await run("foreign-jsdoc-alias", root);
  const unresolvedCompilerPaths = result.events
    .filter((event) => (
      event.diagnostic?.code === "web.typescript_semantic_scaffold_diagnostic"
      && /TS2307.*@private\/value/u.test(event.diagnostic.message)
    ))
    .map((event) => event.diagnostic.path)
    .sort();
  assert.deepEqual(unresolvedCompilerPaths, ["packages/a/src/index.ts", "packages/b/src/index.js"]);
  const nodes = new Map(result.events.filter((event) => event.node).map((event) => [event.node.id, event.node]));
  const foreignTypeUse = result.events
    .filter((event) => event.site?.kind === "type_use" && event.site.evidence[0]?.kind === "semantic")
    .map((event) => event.site)
    .find((site) => (
      site.evidence[0]?.path === "packages/b/src/index.js"
      && site.evidence[0]?.properties.module_specifier === "@private/value"
  ));
  assert.equal(foreignTypeUse?.resolution_status, "external");
  assert.ok(foreignTypeUse?.precision === "exact" || foreignTypeUse?.precision === "heuristic");
  assert.equal(nodes.get(foreignTypeUse?.target_ids[0])?.kind, "external_system");
  assert.match(JSON.stringify(nodes.get(foreignTypeUse?.target_ids[0])), /1\.0\.0/u);
  assert.notEqual(nodes.get(foreignTypeUse?.target_ids[0])?.properties.source_path, "packages/a/src/value.ts");
});

test("a package-scoped TypeScript path cannot resolve imports from a different workspace", async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "depgraph-web-worker-path-isolation-"));
  context.after(async () => rm(root, { recursive: true, force: true }));
  await Promise.all([
    mkdir(path.join(root, "packages", "a", "src"), { recursive: true }),
    mkdir(path.join(root, "packages", "b", "src"), { recursive: true }),
  ]);
  await Promise.all([
    writeFile(path.join(root, "package.json"), JSON.stringify({
      name: "worker-path-isolation",
      workspaces: ["packages/*"],
    })),
    writeFile(path.join(root, "packages", "a", "package.json"), JSON.stringify({
      name: "worker-path-isolation-a",
      version: "1.0.0",
    })),
    writeFile(path.join(root, "packages", "a", "tsconfig.json"), JSON.stringify({
      compilerOptions: { paths: { "@private/*": ["src/*"] } },
    })),
    writeFile(
      path.join(root, "packages", "a", "src", "private.ts"),
      "export interface PrivateType { readonly owner: 'a' }\n",
    ),
    writeFile(path.join(root, "packages", "b", "package.json"), JSON.stringify({
      name: "worker-path-isolation-b",
      version: "1.0.0",
      dependencies: { "@private/private": "1.0.0" },
    })),
    writeFile(path.join(root, "packages", "b", "src", "index.ts"), [
      'import type { PrivateType } from "@private/private";',
      "export interface UsesPrivate { readonly value: PrivateType }",
      "",
    ].join("\n")),
  ]);

  const result = await run("path-isolation", root);
  const nodes = new Map(result.events.filter((event) => event.node).map((event) => [event.node.id, event.node]));
  const sites = result.events
    .filter((event) => event.site?.evidence[0]?.kind === "semantic")
    .map((event) => event.site);
  const foreignSites = sites.filter((site) => (
    site.specifier === "@private/private"
    || site.evidence[0]?.properties.module_specifier === "@private/private"
  ));
  assert.ok(foreignSites.some((site) => (
    site.kind === "web_import"
    && site.evidence[0]?.properties.occurrence_kind === "named_import"
  )));
  for (const site of foreignSites) {
    assert.equal(site.resolution_status, "external");
    assert.equal(site.target_ids.length, 1);
    assert.equal(nodes.get(site.target_ids[0])?.kind, "external_system");
    assert.notEqual(nodes.get(site.target_ids[0])?.properties.source_path, "packages/a/src/private.ts");
  }
});

test("quoted star and equals exports and binding-scheme modules survive semantic refinement", async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "depgraph-web-worker-quoted-bindings-"));
  context.after(async () => rm(root, { recursive: true, force: true }));
  await Promise.all([
    writeFile(path.join(root, "package.json"), JSON.stringify({
      name: "quoted-bindings",
      version: "1.0.0",
    })),
    writeFile(path.join(root, "dep.ts"), [
      "interface StarType { readonly star: true }",
      "interface EqualsType { readonly equals: true }",
      'export { StarType as "*", EqualsType as "=" };',
      "",
    ].join("\n")),
    writeFile(path.join(root, "index.ts"), [
      'import type { "*" as LocalStar, "=" as LocalEquals } from "./dep";',
      'export type { "*" as ForwardStar, "=" as ForwardEquals } from "./dep";',
      'import \'binding:["pkg","X"]\';',
      "export interface UsesQuoted { readonly star: LocalStar; readonly equals: LocalEquals }",
      "",
    ].join("\n")),
  ]);

  const result = await run("quoted-bindings", root);
  const profile = result.events.find((event) => event.event === "profile_declared")?.profile;
  assert.equal(profile?.properties.typescript_definition_graph_status, "ready");
  assert.ok(!result.events.some((event) => event.diagnostic?.code === "web.typescript_semantic_delta_discarded"));
  const sites = result.events
    .filter((event) => event.site?.evidence[0]?.kind === "semantic")
    .map((event) => event.site);
  for (const remoteName of ["*", "="]) {
    const quotedImport = sites.find((site) => (
      site.kind === "web_import"
      && site.evidence[0]?.properties.occurrence_kind === "named_import"
      && site.evidence[0]?.properties.imported_name === remoteName
    ));
    assert.equal(quotedImport?.resolution_status, "resolved");
    assert.equal(quotedImport?.precision, "exact");
    const quotedReexport = sites.find((site) => (
      site.kind === "web_reexport"
      && site.evidence[0]?.properties.occurrence_kind === "named_reexport"
      && site.evidence[0]?.properties.imported_name === remoteName
    ));
    assert.equal(quotedReexport?.resolution_status, "resolved");
    assert.equal(quotedReexport?.precision, "exact");
    const quotedUse = sites.find((site) => (
      site.kind === "type_use"
      && site.evidence[0]?.properties.imported_name === remoteName
    ));
    assert.equal(quotedUse?.resolution_status, "resolved");
    assert.equal(quotedUse?.precision, "exact");
    assert.ok(!Object.hasOwn(quotedUse?.evidence[0]?.properties ?? {}, "resolution_mode"));
  }
  const bindingScheme = sites.find((site) => (
    site.kind === "web_import"
    && site.specifier === 'binding:["pkg","X"]'
    && site.evidence[0]?.properties.occurrence_kind === "side_effect_import"
  ));
  assert.equal(bindingScheme?.evidence[0]?.properties.module_specifier, 'binding:["pkg","X"]');
  assert.equal(bindingScheme?.resolution_status, "external");
});

test("qualified namespace and import-type references resolve the same canonical nested type", async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "depgraph-web-worker-qualified-types-"));
  context.after(async () => rm(root, { recursive: true, force: true }));
  await Promise.all([
    writeFile(path.join(root, "package.json"), JSON.stringify({ name: "qualified-types", version: "1.0.0" })),
    writeFile(path.join(root, "models.ts"), [
      "export namespace Nested {",
      "  export interface User { readonly id: string }",
      "}",
      "",
    ].join("\n")),
    writeFile(path.join(root, "index.ts"), [
      'import type * as Models from "./models";',
      "export interface NamespaceUse { readonly user: Models.Nested.User }",
      "export interface ImportTypeUse { readonly user: import('./models').Nested.User }",
      "",
    ].join("\n")),
  ]);

  const result = await run("qualified-types", root);
  const nodes = new Map(result.events.filter((event) => event.node).map((event) => [event.node.id, event.node]));
  const userSites = result.events
    .filter((event) => (
      event.site?.kind === "type_use"
      && event.site.evidence[0]?.kind === "semantic"
      && event.site.specifier === "User"
      && event.site.evidence[0]?.properties.module_specifier === "./models"
      && event.site.evidence[0]?.properties.imported_name === "User"
    ))
    .map((event) => event.site)
    .sort((left, right) => left.evidence[0].start_line - right.evidence[0].start_line);
  assert.equal(userSites.length, 2);
  assert.deepEqual(userSites.map((site) => site.evidence[0].start_line), [2, 3]);
  assert.ok(userSites.every((site) => (
    site.resolution_status === "resolved"
    && site.precision === "exact"
    && site.reason === null
    && site.target_ids.length === 1
  )));
  assert.equal(userSites[0]?.target_ids[0], userSites[1]?.target_ids[0]);
  const userType = nodes.get(userSites[0]?.target_ids[0]);
  assert.equal(userType?.kind, "type");
  assert.equal(userType?.display_name, "User");
  assert.equal(userType?.properties.source_path, "models.ts");
});

test("TypeScript paths replacements retain declaration-order fallback semantics", async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "depgraph-web-worker-path-order-"));
  context.after(async () => rm(root, { recursive: true, force: true }));
  await mkdir(path.join(root, "src"), { recursive: true });
  await Promise.all([
    writeFile(path.join(root, "package.json"), JSON.stringify({ name: "path-order", version: "1.0.0" })),
    writeFile(path.join(root, "tsconfig.json"), JSON.stringify({
      compilerOptions: {
        baseUrl: ".",
        paths: { "@pick": ["src/z-first.ts", "src/a-second.ts"] },
      },
    })),
    writeFile(path.join(root, "index.ts"), [
      'import type { Picked } from "@pick";',
      "export interface UsesPicked { readonly value: Picked }",
      "",
    ].join("\n")),
    writeFile(path.join(root, "src", "z-first.ts"), "export interface Picked { readonly selected: 'first' }\n"),
    writeFile(path.join(root, "src", "a-second.ts"), "export interface Picked { readonly selected: 'second' }\n"),
  ]);

  const result = await run("path-order", root);
  const nodes = new Map(result.events.filter((event) => event.node).map((event) => [event.node.id, event.node]));
  const site = result.events
    .filter((event) => event.site?.kind === "web_import" && event.site.evidence[0]?.kind === "semantic")
    .map((event) => event.site)
    .find((candidate) => candidate.specifier === "@pick");
  assert.equal(site?.resolution_status, "resolved");
  assert.equal(site?.precision, "exact");
  assert.equal(nodes.get(site?.target_ids[0])?.properties.source_path, "src/z-first.ts");
});

test("Next intercepting routes move to parent/root and root special files become sites", async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "depgraph-web-worker-next-routes-"));
  context.after(async () => rm(root, { recursive: true, force: true }));
  const files = [
    "src/app/feed/@modal/(..)photo/page.tsx",
    "src/app/a/b/@modal/(..)(..)deep/page.tsx",
    "src/app/a/b/@modal/(...)root/page.tsx",
    "src/app/default-mdx/page.mdx",
    "src/proxy.ts",
    "instrumentation.ts",
  ];
  await Promise.all(files.map((file) => mkdir(path.dirname(path.join(root, file)), { recursive: true })));
  await Promise.all([
    writeFile(path.join(root, "package.json"), JSON.stringify({ name: "next-routes", dependencies: { next: "16.2.10" } })),
    ...files.map((file) => writeFile(path.join(root, file), "export const value = true;\n")),
  ]);

  const result = await run("next-routes", root);
  const nodes = result.events.filter((event) => event.node).map((event) => event.node);
  const routePatterns = nodes.filter((node) => node.kind === "route").map((node) => node.properties.pattern);
  assert.ok(routePatterns.includes("/photo"));
  assert.ok(routePatterns.includes("/deep"));
  assert.ok(routePatterns.includes("/root"));
  assert.ok(!routePatterns.includes("/default-mdx"));
  assert.ok(!routePatterns.includes("/feed/photo"));
  const nodeById = new Map(nodes.map((node) => [node.id, node]));
  const routeSites = result.events.filter((event) => event.site?.kind === "route_entry").map((event) => event.site);
  assert.ok(routeSites.some((site) => site.specifier === "/_next/special/proxy" && nodeById.get(site.source)?.display_name === "src/proxy.ts"));
  assert.ok(routeSites.some((site) => site.specifier === "/_next/special/instrumentation" && nodeById.get(site.source)?.display_name === "instrumentation.ts"));
});

test("Next compound pageExtensions remove the full suffix in App and Pages routes", async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "depgraph-web-worker-next-page-extensions-"));
  context.after(async () => rm(root, { recursive: true, force: true }));
  const files = [
    "pages/about.page.tsx",
    "pages/plain.custom",
    "pages/ignored.tsx",
    "app/dashboard/page.page.tsx",
    "app/settings/page.custom",
    "app/ignored/page.tsx",
    "src/middleware.page.tsx",
    "proxy.custom",
    "instrumentation.ts",
  ];
  await Promise.all(files.map((file) => mkdir(path.dirname(path.join(root, file)), { recursive: true })));
  await Promise.all([
    writeFile(path.join(root, "package.json"), JSON.stringify({ name: "next-page-extensions", dependencies: { next: "16.2.10" } })),
    writeFile(path.join(root, "next.config.mjs"), "export default { pageExtensions: ['page.tsx', 'custom'] };\n"),
    ...files.map((file) => writeFile(path.join(root, file), "export default function Page() { return null; }\n")),
  ]);

  const result = await run("next-page-extensions", root);
  const patterns = result.events
    .filter((event) => event.node?.kind === "route")
    .map((event) => event.node.properties.pattern);
  const message = patterns.join(", ");
  for (const expected of ["/about", "/plain", "/dashboard", "/settings"]) assert.ok(patterns.includes(expected), message);
  assert.ok(!patterns.includes("/about.page"), message);
  assert.ok(!patterns.includes("/ignored"), message);
  assert.ok(patterns.includes("/_next/special/middleware"), message);
  assert.ok(patterns.includes("/_next/special/proxy"), message);
  assert.ok(!patterns.includes("/_next/special/instrumentation"), message);
  const unsupportedPaths = ["app/settings/page.custom", "pages/plain.custom", "proxy.custom"];
  for (const unsupportedPath of unsupportedPaths) {
    const ledger = result.events.find((event) => event.event === "file_completed" && event.path === unsupportedPath);
    assert.equal(ledger?.skipped, true, unsupportedPath);
    assert.equal(ledger?.skipped_sites, 1, unsupportedPath);
    assert.equal(ledger?.discovered_sites, ledger?.emitted_sites + ledger?.skipped_sites, unsupportedPath);
    assert.ok(result.events.some((event) => (
      event.diagnostic?.code === "web.unsupported_syntax" && event.diagnostic?.path === unsupportedPath
    )), unsupportedPath);
  }
  assert.equal(result.events.at(-1)?.coverage.files_skipped, unsupportedPaths.length);
  assert.equal(result.events.at(-1)?.coverage.unsupported_syntax, unsupportedPaths.length);
  assert.deepEqual(result.events.at(-1)?.coverage.completeness, []);
  assert.ok(!result.events.some((event) => event.site?.kind === "unsupported_route_source"));
});

test("Astro Markdown and MDX routes report unsupported dependency inventory without parsing their bodies", async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "depgraph-web-worker-astro-markdown-"));
  context.after(async () => rm(root, { recursive: true, force: true }));
  await mkdir(path.join(root, "src", "pages"), { recursive: true });
  await Promise.all([
    writeFile(path.join(root, "package.json"), JSON.stringify({ name: "astro-markdown", dependencies: { astro: "7.0.9" } })),
    writeFile(path.join(root, "src", "pages", "guide.md"), '---\ntitle: Guide\nexample: import "frontmatter-is-yaml"\n---\n# Guide\n'),
    writeFile(path.join(root, "src", "pages", "docs.mdx"), '---\ntitle: Docs\n---\nimport "mdx-body-only";\n# Docs\n'),
  ]);

  const result = await run("astro-markdown", root);
  const routePatterns = result.events
    .filter((event) => event.node?.kind === "route")
    .map((event) => event.node.properties.pattern);
  assert.ok(routePatterns.includes("/guide"));
  assert.ok(routePatterns.includes("/docs"));
  assert.ok(!result.events.some((event) => ["frontmatter-is-yaml", "mdx-body-only"].includes(event.site?.specifier)));
  for (const unsupportedPath of ["src/pages/docs.mdx", "src/pages/guide.md"]) {
    const ledger = result.events.find((event) => event.event === "file_completed" && event.path === unsupportedPath);
    assert.equal(ledger?.skipped, true, unsupportedPath);
    assert.equal(ledger?.skipped_sites, 1, unsupportedPath);
    assert.equal(ledger?.discovered_sites, ledger?.emitted_sites + ledger?.skipped_sites, unsupportedPath);
    assert.ok(result.events.some((event) => (
      event.diagnostic?.code === "web.unsupported_syntax" && event.diagnostic?.path === unsupportedPath
    )), unsupportedPath);
  }
  assert.equal(result.events.at(-1)?.coverage.files_skipped, 2);
  assert.equal(result.events.at(-1)?.coverage.unsupported_syntax, 2);
  assert.deepEqual(result.events.at(-1)?.coverage.completeness, []);
});

test("out-of-root source symlinks are explicit skipped coverage", async (context) => {
  const parent = await mkdtemp(path.join(os.tmpdir(), "depgraph-web-worker-source-symlink-"));
  context.after(async () => rm(parent, { recursive: true, force: true }));
  const root = path.join(parent, "repo");
  const outside = path.join(parent, "outside.ts");
  const outsideDirectory = path.join(parent, "outside-directory");
  await Promise.all([mkdir(root), mkdir(outsideDirectory)]);
  await Promise.all([
    writeFile(path.join(root, "package.json"), JSON.stringify({ name: "source-symlink", version: "1.0.0" })),
    writeFile(outside, 'import "outside-secret";\n'),
    writeFile(path.join(outsideDirectory, "secret.ts"), 'import "directory-secret";\n'),
  ]);
  try {
    await Promise.all([
      symlink(outside, path.join(root, "linked.ts")),
      symlink(path.join(parent, "missing.ts"), path.join(root, "broken.ts")),
      symlink(outsideDirectory, path.join(root, "linked-directory"), "dir"),
    ]);
  } catch (error) {
    context.skip(`symlink unavailable: ${String(error)}`);
    return;
  }

  const result = await run("source-symlink", root);
  const diagnostic = result.events.find((event) => event.diagnostic?.code === "web.source_symlink_outside_root")?.diagnostic;
  assert.match(diagnostic?.message ?? "", /linked\.ts/u);
  assert.equal(diagnostic?.path, null);
  const ledger = result.events.find((event) => event.event === "file_completed" && event.path === "__depgraph_skipped__/linked.ts");
  assert.equal(ledger?.skipped, true);
  assert.equal(ledger?.skipped_sites, 1);
  assert.ok(result.events.some((event) => event.diagnostic?.code === "web.source_symlink_outside_root" && /linked-directory/u.test(event.diagnostic?.message ?? "")));
  assert.equal(result.events.find((event) => event.event === "file_completed" && event.path === "__depgraph_skipped__/linked-directory")?.skipped_sites, 1);
  assert.ok(result.events.some((event) => event.diagnostic?.code === "web.source_inventory_skipped" && /broken\.ts/u.test(event.diagnostic?.message ?? "")));
  assert.equal(result.events.find((event) => event.event === "file_completed" && event.path === "broken.ts")?.skipped_sites, 1);
  assert.ok(result.events.at(-1)?.coverage.files_skipped >= 1);
  assert.deepEqual(result.events.at(-1)?.coverage.completeness, []);
  assert.ok(!result.events.some((event) => event.site?.specifier === "outside-secret"));
  assert.ok(!result.events.some((event) => event.site?.specifier === "directory-secret"));
});

test("bun.lockb and project TypeScript/framework versions are reported statically", async (context) => {
  const parent = await mkdtemp(path.join(os.tmpdir(), "depgraph-web-worker-version-sources-"));
  context.after(async () => rm(parent, { recursive: true, force: true }));
  const bunRoot = path.join(parent, "bun");
  const lockRoot = path.join(parent, "lock");
  await Promise.all([mkdir(bunRoot), mkdir(lockRoot)]);
  await Promise.all([
    writeFile(path.join(bunRoot, "package.json"), JSON.stringify({
      name: "bun-binary-lock",
      packageManager: "bun@1.3.0",
      devDependencies: { typescript: "^7.1.0" },
    })),
    writeFile(path.join(bunRoot, "bun.lockb"), Buffer.from([0, 1, 2, 3])),
    writeFile(path.join(bunRoot, "index.ts"), "export const value = true;\n"),
    writeFile(path.join(lockRoot, "package.json"), JSON.stringify({
      name: "locked-versions",
      devDependencies: { typescript: "^7.1.0" },
      dependencies: { "@tanstack/react-start": "1.2.3" },
    })),
    writeFile(path.join(lockRoot, "package-lock.json"), JSON.stringify({
      name: "locked-versions",
      lockfileVersion: 3,
      packages: {
        "": { name: "locked-versions" },
        "node_modules/typescript": { version: "7.1.4" },
        "node_modules/@tanstack/react-start": { version: "1.2.3" },
      },
    })),
    writeFile(path.join(lockRoot, "index.ts"), "export const value = true;\n"),
  ]);

  const bun = await run("bun-lockb", bunRoot);
  assert.ok(bun.events.some((event) => event.diagnostic?.code === "web.lockfile_unsupported" && event.diagnostic?.path === "bun.lockb"));
  assert.ok(bun.events.some((event) => event.diagnostic?.code === "web.project_typescript_not_loaded" && event.diagnostic?.message.includes("^7.1.0")));
  assert.ok(bun.events.at(-1)?.coverage.unsupported_syntax > 0);
  assert.deepEqual(bun.events.at(-1)?.coverage.completeness, []);

  const locked = await run("locked-versions", lockRoot);
  assert.ok(locked.events.some((event) => event.diagnostic?.code === "web.project_typescript_not_loaded" && event.diagnostic?.message.includes("7.1.4")));
  assert.ok(locked.events.some((event) => event.diagnostic?.code === "web.best_effort_framework_version" && event.diagnostic?.message.includes("@tanstack/react-start 1.2.3")));
});

test("unsupported project-local TypeScript is metadata only and its module is never executed", async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "depgraph-web-worker-malicious-typescript-"));
  context.after(async () => rm(root, { recursive: true, force: true }));
  const localTypeScript = path.join(root, "node_modules", "typescript");
  const marker = path.join(root, "PROJECT_TYPESCRIPT_EXECUTED");
  await mkdir(localTypeScript, { recursive: true });
  await Promise.all([
    writeFile(path.join(root, "package.json"), JSON.stringify({
      name: "malicious-typescript-fixture",
      version: "1.0.0",
      devDependencies: { typescript: "99.0.0-evil" },
    })),
    writeFile(path.join(root, "index.ts"), "export const safe = true;\n"),
    writeFile(path.join(localTypeScript, "package.json"), JSON.stringify({
      name: "typescript",
      version: "99.0.0-evil",
      main: "index.cjs",
    })),
    writeFile(
      path.join(localTypeScript, "index.cjs"),
      `require("node:fs").writeFileSync(${JSON.stringify(marker)}, "executed"); module.exports = { version: "99.0.0-evil" };\n`,
    ),
  ]);

  const result = await run("malicious-project-typescript", root);
  const profile = result.events.find((event) => event.event === "profile_declared")?.profile;
  const diagnostics = result.events.filter((event) => event.event === "diagnostic").map((event) => event.diagnostic);
  const localDiagnostic = diagnostics.find((diagnostic) => diagnostic.code === "web.project_typescript_not_loaded");

  assert.match(localDiagnostic?.message ?? "", /project-local TypeScript 99\.0\.0-evil/u);
  assert.match(localDiagnostic?.message ?? "", /installed package manifest/u);
  assert.equal(localDiagnostic?.path, "package.json");
  assert.equal(profile?.properties.typescript_compiler_source, "bundled");
  assert.equal(profile?.properties.typescript_compiler_version, "7.0.2");
  assert.equal(profile?.properties.typescript_project_local_policy, "metadata-only");
  assert.equal(profile?.properties.typescript_project_local_loaded, "false");
  assert.equal(profile?.properties.project_code_executed, "false");
  assert.equal(result.events[0]?.project_code_executed, false);
  await assert.rejects(import("node:fs/promises").then(({ stat }) => stat(marker)));
});

test("relocated packaged worker fails closed when its adjacent TypeScript compiler is missing", async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "depgraph-web-worker-missing-compiler-"));
  context.after(async () => rm(root, { recursive: true, force: true }));
  // node_modules is excluded from source inventory, so this also proves that
  // an empty TS/JS source set still validates the compiler before declaring a
  // bundled, fail-closed profile.
  const relocatedWorker = path.join(root, "node_modules", ".bin", "worker.mjs");
  const marker = path.join(root, "PROJECT_TYPESCRIPT_EXECUTED");
  const platformPackageName = `typescript-${process.platform}-${process.arch}`;
  const projectPlatformRoot = path.join(root, "node_modules", "@typescript", platformPackageName);
  const fakeCompiler = path.join(projectPlatformRoot, "lib", process.platform === "win32" ? "tsc.exe" : "tsc");
  await Promise.all([
    mkdir(path.dirname(relocatedWorker), { recursive: true }),
    mkdir(path.join(path.dirname(relocatedWorker), "astro"), { recursive: true }),
    mkdir(path.dirname(fakeCompiler), { recursive: true }),
    mkdir(path.join(root, "node_modules", "typescript"), { recursive: true }),
  ]);
  await Promise.all([
    cp(worker, relocatedWorker),
    cp(
      fileURLToPath(new URL("../dist/astro/astro.wasm", import.meta.url)),
      path.join(path.dirname(relocatedWorker), "astro", "astro.wasm"),
    ),
    writeFile(path.join(root, "package.json"), JSON.stringify({ name: "missing-compiler-fixture", version: "1.0.0" })),
    writeFile(path.join(root, "node_modules", "typescript", "package.json"), JSON.stringify({
      name: "typescript",
      version: "7.0.2",
    })),
    writeFile(path.join(projectPlatformRoot, "package.json"), JSON.stringify({
      name: `@typescript/${platformPackageName}`,
      version: "7.0.2",
    })),
    writeFile(
      fakeCompiler,
      process.platform === "win32"
        ? "this is intentionally not a real executable\n"
        : `#!${process.execPath}\nrequire("node:fs").writeFileSync(${JSON.stringify(marker)}, "executed");\n`,
    ),
  ]);
  if (process.platform !== "win32") await chmod(fakeCompiler, 0o755);

  await assert.rejects(
    execute(process.execPath, [relocatedWorker, "--root", root, "--scan-id", "missing-adjacent-compiler"]),
    (error: unknown) => {
      const stderr = typeof error === "object" && error !== null && "stderr" in error
        ? String(error.stderr)
        : String(error);
      const stdout = typeof error === "object" && error !== null && "stdout" in error
        ? String(error.stdout)
        : "";
      const events = stdout.trim().split("\n").filter(Boolean).map((line) => JSON.parse(line) as Record<string, any>);
      const profile = events.find((event) => event.event === "profile_declared")?.profile;
      assert.match(stderr, /bundled TypeScript 7\.0\.2 compiler is missing next to packaged worker/u);
      assert.doesNotMatch(stderr, /node_modules[\\/]@typescript/u);
      assert.equal(profile?.properties.typescript_project_model_status, "failed");
      assert.equal(profile?.properties.typescript_typechecker_status, "failed");
      assert.equal(profile?.properties.typescript_definition_graph_status, "failed");
      assert.equal(profile?.properties.typescript_semantic_node_count, "0");
      assert.equal(profile?.properties.typescript_semantic_relation_count, "0");
      assert.equal(profile?.properties.typescript_semantic_site_count, "0");
      assert.equal(profile?.properties.typescript_semantic_call_site_count, "0");
      assert.equal(profile?.properties.typescript_semantic_issue_count, "0");
      assert.equal(profile?.properties.typescript_project_model_failure_reason, "compiler_unavailable");
      assert.ok(events.some((event) => (
        event.diagnostic?.code === "web.typescript_project_model_failed"
        && event.diagnostic?.message === "Bundled TypeScript project model failed: compiler_unavailable"
      )));
      assert.deepEqual(events.at(-1)?.coverage.completeness, []);
      assert.ok(events.at(-1)?.coverage.reasons.includes("typescript_project_model_failure"));
      return true;
    },
  );
  await assert.rejects(import("node:fs/promises").then(({ stat }) => stat(marker)));
});

test("dynamic framework config is diagnosed without evaluating project code", async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "depgraph-web-worker-dynamic-config-"));
  context.after(async () => rm(root, { recursive: true, force: true }));
  const marker = path.join(root, "DYNAMIC_CONFIG_EXECUTED");
  await Promise.all([
    writeFile(path.join(root, "package.json"), JSON.stringify({ name: "dynamic-config-fixture", version: "1.0.0" })),
    writeFile(path.join(root, "index.ts"), "export const safe = true;\n"),
    writeFile(path.join(root, "next.config.mjs"), `
      import { writeFileSync } from "node:fs";
      writeFileSync(${JSON.stringify(marker)}, "executed");
      const dynamicBasePath = process.env.BASE_PATH;
      export default {
        basePath: dynamicBasePath,
        webpack: (config) => config,
      };
    `),
  ]);

  const result = await run("dynamic-config", root);
  const diagnostics = result.events.filter((event) => event.event === "diagnostic").map((event) => event.diagnostic);
  assert.ok(diagnostics.some((diagnostic) => (
    diagnostic.code === "web.executable_config_not_executed" && diagnostic.path === "next.config.mjs"
  )));
  assert.ok(diagnostics.some((diagnostic) => (
    diagnostic.code === "web.static_config_unresolved"
      && diagnostic.path === "next.config.mjs"
      && /basePath is not a static string literal/u.test(diagnostic.message)
  )));
  assert.ok(diagnostics.some((diagnostic) => (
    diagnostic.code === "web.static_config_runtime_ignored"
      && diagnostic.path === "next.config.mjs"
      && /webpack requires project code evaluation/u.test(diagnostic.message)
  )));
  assert.equal(result.events[0]?.project_code_executed, false);
  assert.equal(result.events.find((event) => event.event === "profile_declared")?.profile.properties.project_code_executed, "false");
  await assert.rejects(import("node:fs/promises").then(({ stat }) => stat(marker)));
});

test("workspace metadata and generated routes cannot be read through out-of-root symlinks", async (context) => {
  const parent = await mkdtemp(path.join(os.tmpdir(), "depgraph-web-worker-confinement-"));
  context.after(async () => rm(parent, { recursive: true, force: true }));
  const root = path.join(parent, "repo");
  const outside = path.join(parent, "outside");
  const outsideGit = path.join(outside, "git");
  const outsideTypeScript = path.join(outside, "typescript");
  await Promise.all([
    mkdir(path.join(root, "node_modules"), { recursive: true }),
    mkdir(outsideGit, { recursive: true }),
    mkdir(outsideTypeScript, { recursive: true }),
  ]);
  await Promise.all([
    writeFile(path.join(root, "package.json"), JSON.stringify({
      name: "confinement-fixture",
      version: "1.0.0",
      dependencies: { "@tanstack/react-router": "1.170.18" },
    })),
    writeFile(path.join(root, "vite.config.ts"), "export default { generatedRouteTree: './routeTree.gen.ts' };\n"),
    writeFile(path.join(root, "index.ts"), "export const safe = true;\n"),
    writeFile(path.join(outside, "routeTree.gen.ts"), "export const routes = [{ fullPath: '/outside-secret' }];\n"),
    writeFile(path.join(outsideGit, "config"), "[remote \"origin\"]\n  url = https://secret.example/outside.git\n"),
    writeFile(path.join(outsideTypeScript, "package.json"), JSON.stringify({ name: "typescript", version: "99.99.99-outside-secret" })),
  ]);
  try {
    await Promise.all([
      symlink(path.join(outside, "routeTree.gen.ts"), path.join(root, "routeTree.gen.ts")),
      symlink(outsideGit, path.join(root, ".git"), "dir"),
      symlink(outsideTypeScript, path.join(root, "node_modules", "typescript"), "dir"),
    ]);
  } catch (error) {
    context.skip(`symlink unavailable: ${String(error)}`);
    return;
  }

  const withExternalGitLink = await run("confinement-one", root);
  await rm(path.join(root, ".git"), { force: true });
  const withoutGit = await run("confinement-two", root);
  const serialized = JSON.stringify(withExternalGitLink.events);
  assert.doesNotMatch(serialized, /outside-secret|99\.99\.99/u);
  assert.ok(!withExternalGitLink.events.some((event) => event.node?.kind === "route" && event.node?.locator.endsWith("/outside-secret")));
  assert.ok(!withExternalGitLink.events.some((event) => event.diagnostic?.code === "web.project_typescript_not_loaded"));

  const normalize = (events: Array<Record<string, any>>) => events.map(({ scan_id: _scanId, ...event }) => event);
  assert.deepEqual(normalize(withExternalGitLink.events), normalize(withoutGit.events));
});

test("worker reports usage errors on stderr without protocol output", async () => {
  await assert.rejects(
    execute(process.execPath, [worker, "--scan-id", "missing-root"]),
    (error: any) => error.code === 2 && error.stdout === "" && /usage/u.test(error.stderr),
  );
});

test("worker exposes the release and protocol handshake", async () => {
  const result = await execute(process.execPath, [worker, "--version"]);
  assert.equal(
    result.stdout,
    "depgraph-web-worker 0.1.0 (protocol 1.0; typescript 7.0.2; capabilities astro-component-render-hydration-v1,framework-semantic-completeness-v1,framework-semantic-graph-v1,next-route-component-boundary-v1,tanstack-router-typed-route-v1,tanstack-start-rpc-middleware-v1,typescript-definition-import-type-call-graph-v2)\n",
  );
  assert.equal(result.stderr, "");
});
