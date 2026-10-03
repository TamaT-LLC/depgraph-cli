import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import fs, { mkdir, mkdtemp, rm, symlink, truncate, writeFile } from "node:fs/promises";
import { syncBuiltinESMExports } from "node:module";
import { tmpdir } from "node:os";
import path from "node:path";
import test, { type TestContext } from "node:test";
import { promisify } from "node:util";
import {
  NextBuildObserverError,
  buildNextObservedGraph,
  collectNextBuildObservation,
  type NextAdapterBuildContext,
} from "../src/next-build-observer";

const packagePath = "node_modules/.pnpm/pkg@1/node_modules/pkg";
const hash = (text: string): string => createHash("sha256").update(text).digest("hex");

async function fixture(t: TestContext) {
  const root = await mkdtemp(path.join(tmpdir(), "depgraph-next-links-"));
  t.after(async () => rm(root, { recursive: true, force: true }));
  const target = path.join(root, packagePath);
  const main = path.join(root, ".next/server/app/page.js");
  const link = path.join(root, "node_modules/pkg");
  await mkdir(target, { recursive: true });
  await mkdir(path.dirname(main), { recursive: true });
  await writeFile(main, "route entry");
  await writeFile(path.join(target, "index.js"), "package content");
  await symlink(".pnpm/pkg@1/node_modules/pkg", link, "dir");
  const output = {
    id: "page", type: "APP_PAGE", pathname: "/", sourcePage: "/", filePath: main,
    runtime: "nodejs", config: {},
    assets: {
      "node_modules/pkg": link,
      [`${packagePath}/index.js`]: path.join(target, "index.js"),
    } as Record<string, string>,
    wasmAssets: {} as Record<string, string>,
  };
  const context: NextAdapterBuildContext = {
    repoRoot: root, projectDir: root, distDir: path.join(root, ".next"),
    nextVersion: "16.3.6", buildId: "build", config: { basePath: "" },
    routing: {
      beforeMiddleware: [], beforeFiles: [], afterFiles: [], dynamicRoutes: [], onMatch: [], fallback: [],
    },
    outputs: { pages: [], pagesApi: [], appPages: [output], appRoutes: [], prerenders: [], staticFiles: [] },
  };
  return { root, target, main, link, output, context };
}

async function rejectsUnsafe(context: NextAdapterBuildContext) {
  await assert.rejects(collectNextBuildObservation(context), (error: unknown) => (
    error instanceof NextBuildObserverError
      && ["web.next_build_artifact_unsafe", "web.next_build_artifact_read_failed"].includes(error.code)
  ));
}

test("pnpm trace links retain topology and independent file content with checkout-stable identities", async (t) => {
  const first = await fixture(t);
  const relocated = await fixture(t);
  await rm(relocated.link);
  await symlink(relocated.target, relocated.link, "dir");
  const observed = await collectNextBuildObservation(first.context);
  assert.deepEqual(await collectNextBuildObservation(relocated.context), observed);
  const assets = observed.outputs[0]!.assets;
  assert.equal(assets.length, 2);
  assert.equal(assets.find((asset) => asset.logical_path.endsWith("/index.js"))?.digest, hash("package content"));
  const linkDigest = assets.find((asset) => asset.logical_path === "node_modules/pkg")!.digest;
  assert.match(linkDigest, /^[a-f0-9]{64}$/u);
  assert.notEqual(linkDigest, hash("package content"));
  assert.equal(JSON.stringify(observed).includes(first.root), false);
  const graph = buildNextObservedGraph({ observation: observed, baseNodes: [], provenance: {
    build_run_id: "run", profile_id: "profile", command_plan_digest: hash("plan"),
    toolchain_executable_digest: hash("node"), environment_key_set_digest: hash("environment"),
    validated_output_digest: hash("output"),
  } });
  assert.ok(graph.nodes.some((node) => node.properties.logical_path === "node_modules/pkg"));

  const otherTarget = path.join(first.root, "node_modules/.pnpm/pkg@2/node_modules/pkg");
  await mkdir(otherTarget, { recursive: true });
  await writeFile(path.join(otherTarget, "index.js"), "package content");
  await rm(first.link);
  await symlink(".pnpm/pkg@2/node_modules/pkg", first.link, "dir");
  const changed = await collectNextBuildObservation(first.context);
  assert.notEqual(changed.outputs[0]!.assets.find((asset) => asset.logical_path === "node_modules/pkg")!.digest, linkDigest);
  assert.notEqual(changed.manifests.build_manifest_digest, observed.manifests.build_manifest_digest);
});

test("workspace dependency links preserve distinct source and dependency logical paths", async (t) => {
  const item = await fixture(t);
  const source = path.join(item.root, "packages/workspace");
  await mkdir(source, { recursive: true });
  await writeFile(path.join(source, "index.js"), "workspace source");
  await rm(item.link);
  await symlink("../packages/workspace", item.link, "dir");
  item.output.assets["packages/workspace/index.js"] = path.join(source, "index.js");
  const observed = await collectNextBuildObservation(item.context);
  assert.deepEqual(observed.outputs[0]!.assets.map((asset) => asset.logical_path).sort(), [
    `${packagePath}/index.js`, "node_modules/pkg", "packages/workspace/index.js",
  ].sort());
});

test("main, fallback, wasm, edge and non-dependency assets keep strict regular-file handling", async (t) => {
  for (const mode of ["main", "main-file", "fallback", "wasm", "edge", "generated", "directory", "file-link"] as const) {
    await t.test(mode, async (child) => {
      const item = await fixture(child);
      if (mode === "main") item.output.filePath = item.link;
      if (mode === "main-file") {
        await rm(item.main);
        await symlink(path.join(item.target, "index.js"), item.main);
      }
      if (mode === "fallback") {
        item.context.outputs.prerenders = [{
          id: "prerender", type: "PRERENDER", pathname: "/static", config: {},
          parentOutputId: "page", groupId: 0, fallback: { filePath: item.link },
        }];
      }
      if (mode === "wasm") item.output.wasmAssets = { "node_modules/pkg": item.link };
      if (mode === "edge") item.output.runtime = "edge";
      if (mode === "generated") {
        const generated = path.join(item.root, ".next/generated-link");
        await symlink(item.target, generated, "dir");
        item.output.assets = { ".next/generated-link": generated };
      }
      if (mode === "directory") item.output.assets = { [packagePath]: item.target };
      if (mode === "file-link") {
        await rm(item.link);
        await symlink(path.join(item.target, "index.js"), item.link);
      }
      await rejectsUnsafe(item.context);
    });
  }
});

test("trace links reject escaping, dangling, ancestor and cyclic targets", async (t) => {
  for (const mode of ["outside", "dangling", "root", "ancestor", "cycle"] as const) {
    await t.test(mode, async (child) => {
      const item = await fixture(child);
      await rm(item.link);
      const targets = {
        outside: tmpdir(), dangling: "missing-package", root: "..", ancestor: ".", cycle: "pkg",
      };
      await symlink(targets[mode], item.link, "dir");
      await rejectsUnsafe(item.context);
    });
  }
});

test("trace links reject control targets and aliases without reading their contents", async (t) => {
  for (const relative of [".git", ".depgraph", "target", ".next", "packages/app/.git", "packages/app/.depgraph"]) {
    await t.test(relative, async (child) => {
      const item = await fixture(child);
      const forbidden = path.join(item.root, relative);
      await mkdir(forbidden, { recursive: true });
      await rm(item.link);
      await symlink(forbidden, item.link, "dir");
      await rejectsUnsafe(item.context);
      // A benign direct target must not conceal a forbidden canonical target.
      const alias = path.join(item.root, "node_modules/alias");
      await symlink(forbidden, alias, "dir");
      await rm(item.link);
      await symlink("alias", item.link, "dir");
      await rejectsUnsafe(item.context);
    });
  }
});

test("nested scoped pnpm directory links are observed without recursively hashing packages", async (t) => {
  const item = await fixture(t);
  const scopedTarget = path.join(item.root, "node_modules/.pnpm/@swc+helpers@0.5.23/node_modules/@swc/helpers");
  const scopedLogical = "node_modules/.pnpm/next@16.3.6/node_modules/@swc/helpers";
  const scopedLink = path.join(item.root, scopedLogical);
  await mkdir(scopedTarget, { recursive: true });
  await mkdir(path.dirname(scopedLink), { recursive: true });
  await symlink(path.relative(path.dirname(scopedLink), scopedTarget), scopedLink, "dir");
  const untraced = path.join(scopedTarget, "untraced-large-file");
  await writeFile(untraced, "");
  await truncate(untraced, 64 * 1024 * 1024 + 1);
  item.output.assets[scopedLogical] = scopedLink;
  const observed = await collectNextBuildObservation(item.context);
  assert.equal(observed.outputs[0]!.assets.length, 3);
  assert.ok(observed.outputs[0]!.assets.some((asset) => asset.logical_path === scopedLogical));
});

test("Next-generated package aliases below .next/node_modules retain traced dependency topology", async (t) => {
  const item = await fixture(t);
  const packageLogical = "node_modules/.pnpm/@fixture+renderer@1.0.0/node_modules/@fixture/renderer";
  const packageTarget = path.join(item.root, packageLogical);
  const aliasLogical = ".next/node_modules/@fixture/renderer-0123456789abcdef";
  const alias = path.join(item.root, aliasLogical);
  await mkdir(packageTarget, { recursive: true });
  await mkdir(path.dirname(alias), { recursive: true });
  await writeFile(path.join(packageTarget, "index.js"), "renderer content");
  await symlink(path.relative(path.dirname(alias), packageTarget), alias, "dir");
  item.output.assets = {
    [aliasLogical]: alias,
    [`${packageLogical}/index.js`]: path.join(packageTarget, "index.js"),
  };
  const observed = await collectNextBuildObservation(item.context);
  assert.equal(observed.outputs[0]!.assets.length, 2);
  assert.ok(observed.outputs[0]!.assets.some((asset) => asset.logical_path === aliasLogical));
  assert.equal(observed.outputs[0]!.assets.find((asset) => asset.logical_path.endsWith("/index.js"))?.digest, hash("renderer content"));
  item.output.wasmAssets = { [aliasLogical]: alias };
  await rejectsUnsafe(item.context);
});

test("trace link locations reject nested control directories including canonical-parent aliases", async (t) => {
  for (const control of [".git", ".depgraph"]) {
    await t.test(control, async (child) => {
      const item = await fixture(child);
      const parent = path.join(item.root, "packages/app", control, "node_modules");
      const controlled = path.join(parent, "pkg");
      await mkdir(parent, { recursive: true });
      await symlink(item.target, controlled, "dir");
      const controlledLogical = `packages/app/${control}/node_modules/pkg`;
      item.output.assets = { [controlledLogical]: controlled };
      await rejectsUnsafe(item.context);
      const alias = path.join(item.root, "node_modules/control-alias");
      await symlink(path.dirname(parent), alias, "dir");
      item.output.assets = { "node_modules/control-alias/node_modules/pkg": path.join(alias, "node_modules/pkg") };
      await rejectsUnsafe(item.context);
    });
  }
});

test("trace links reject special targets without opening them", async (t) => {
  if (process.platform === "win32") { t.skip("FIFO fixture requires POSIX"); return; }
  const item = await fixture(t);
  const fifo = path.join(item.root, "node_modules/pipe");
  await promisify(execFile)("mkfifo", [fifo]);
  await rm(item.link);
  await symlink("pipe", item.link);
  await rejectsUnsafe(item.context);
});

test("link metadata, link text and target identity changes fail closed", async (t) => {
  for (const mode of ["link-identity", "target-identity", "link-text"] as const) {
    await t.test(mode, async (child) => {
      const item = await fixture(child);
      const targetPath = mode === "target-identity" ? item.target : item.link;
      let calls = 0;
      const originalLstat = fs.lstat;
      const originalReadlink = fs.readlink;
      const mocked = mode === "link-text"
        ? child.mock.method(fs, "readlink", async (...args: Parameters<typeof fs.readlink>) => {
          const result = await originalReadlink(...args);
          return ++calls === 2 ? "changed-target" : result;
        })
        : child.mock.method(fs, "lstat", async (...args: Parameters<typeof fs.lstat>) => {
          const result = await originalLstat(...args);
          if (args[0] === targetPath && ++calls === 2) result.ino = typeof result.ino === "bigint" ? result.ino + 1n : result.ino + 1;
          return result;
        });
      syncBuiltinESMExports();
      try {
        await rejectsUnsafe(item.context);
      } finally {
        mocked.mock.restore();
        syncBuiltinESMExports();
      }
    });
  }
});

test("trace links retain identity and asset bounds, and regular artifacts retain byte bounds", async (t) => {
  await t.test("link identity", async (child) => {
    const item = await fixture(child);
    const original = fs.readlink;
    const mocked = child.mock.method(fs, "readlink", async () => "x".repeat(4097));
    syncBuiltinESMExports();
    try { await rejectsUnsafe(item.context); } finally {
      mocked.mock.restore();
      syncBuiltinESMExports();
    }
    assert.equal(fs.readlink, original);
  });
  await t.test("asset count", async (child) => {
    const item = await fixture(child);
    item.output.assets = Object.fromEntries(Array.from({ length: 2001 }, (_, index) => [`node_modules/pkg/${index}`, item.link]));
    await assert.rejects(collectNextBuildObservation(item.context), (error: unknown) => (
      error instanceof NextBuildObserverError && error.code === "web.next_build_asset_contract_invalid"
    ));
  });
  await t.test("artifact bytes", async (child) => {
    const item = await fixture(child);
    await truncate(item.main, 64 * 1024 * 1024 + 1);
    await rejectsUnsafe(item.context);
  });
});
