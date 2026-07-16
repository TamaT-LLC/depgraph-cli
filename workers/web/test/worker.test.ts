import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { cp, mkdir, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { test } from "node:test";

const execute = promisify(execFile);
const fixture = fileURLToPath(new URL("./fixtures/polyglot", import.meta.url));
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
  assert.equal(first.events.at(-1)?.event, "scan_completed");
  assert.ok(first.events.every((event, index) => event.protocol_version === "1.0" && event.adapter === "web" && event.seq === index + 1));
  assert.match(first.stderr, /project code executed=false/u);

  const nodes = first.events.filter((event) => event.event === "node_upsert").map((event) => event.node);
  const sites = first.events.filter((event) => event.event === "dependency_site").map((event) => event.site);
  const edges = first.events.filter((event) => event.event === "edge_upsert").map((event) => event.edge);
  const diagnostics = first.events.filter((event) => event.event === "diagnostic").map((event) => event.diagnostic);
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
  assert.ok(sites.some((site) => site.specifier === "@shared/index" && site.resolution_status === "resolved"));
  const conditionalExport = sites.find((site) => site.specifier === "@fixture/shared" && site.kind === "import");
  assert.equal(conditionalExport?.resolution_status, "candidates");
  assert.match(conditionalExport?.reason ?? "", /package_exports_conditions=browser,default,node/u);
  assert.match(JSON.stringify(conditionalExport?.condition), /package\.exports\.condition/u);
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
    assert.match(JSON.stringify(event.site?.condition ?? event.edge?.condition), /"values":\["browser","server","worker"\]/u);
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
    assert.deepEqual(sites.map((site) => site.kind).sort(), ["package_dependency", "side_effect_import"]);
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
  assert.ok(result.events.at(-1)?.coverage.unsupported_syntax > 0);
  assert.deepEqual(result.events.at(-1)?.coverage.completeness, []);
  assert.ok(result.events.at(-1)?.coverage.reasons.includes("unsupported_syntax"));
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

test("native TypeScript 7 parser covers every TS and JS extension without loading project config", async (context) => {
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
  await assert.rejects(import("node:fs/promises").then(({ stat }) => stat(marker)));
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

test("external subpath resolution retains lock candidates whose files are unavailable", async (context) => {
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
  assert.equal(publicSite?.resolution_status, "candidates");
  assert.deepEqual(publicSite?.target_ids.map((id: string) => nodes.get(id)?.properties.version).sort(), ["1.0.0", "2.0.0"]);
  assert.match(publicSite?.reason ?? "", /external_package_exports_unavailable/u);
  assert.equal(privateSite?.resolution_status, "candidates");
  assert.deepEqual(privateSite?.target_ids.map((id: string) => nodes.get(id)?.properties.version), ["2.0.0"]);
  assert.match(privateSite?.reason ?? "", /package_subpath_not_exported/u);
  assert.match(privateSite?.reason ?? "", /external_package_exports_unavailable/u);
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
  assert.equal(result.stdout, "depgraph-web-worker 0.1.0 (protocol 1.0; typescript 7.0.2)\n");
  assert.equal(result.stderr, "");
});
