import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test, { type TestContext } from "node:test";
import {
  NextBuildObserverError,
  collectNextBuildObservation,
  type NextAdapterBuildContext,
} from "../src/next-build-observer";

async function edgeFixture(t: TestContext, distRelative = ".next") {
  const root = await mkdtemp(path.join(tmpdir(), "depgraph-next-edge-"));
  t.after(async () => rm(root, { recursive: true, force: true }));
  const distDir = path.join(root, distRelative);
  const main = path.join(distDir, "server/app/edge/route.js");
  const manifest = path.join(distDir, "server/middleware-build-manifest.js");
  await mkdir(path.dirname(main), { recursive: true });
  await writeFile(main, "edge entry");
  await writeFile(manifest, "manifest contents");
  const output = {
    id: "edge", type: "APP_ROUTE", pathname: "/edge", sourcePage: "/edge/route", filePath: main,
    runtime: "edge", config: {},
    edgeRuntime: { modulePath: main, entryKey: "middleware_app/edge/route", handlerExport: "handler" },
    assets: { "server/middleware-build-manifest.js": manifest } as Record<string, string>,
    wasmAssets: {} as Record<string, string>,
  };
  const context: NextAdapterBuildContext = {
    repoRoot: root, projectDir: root, distDir, nextVersion: "16.3.6", buildId: "build", config: { basePath: "" },
    routing: { beforeMiddleware: [], beforeFiles: [], afterFiles: [], dynamicRoutes: [], onMatch: [], fallback: [] },
    outputs: { pages: [], pagesApi: [], appPages: [], appRoutes: [output], prerenders: [], staticFiles: [] },
  };
  return { root, distDir, main, manifest, output, context };
}

async function rejectsHint(context: NextAdapterBuildContext) {
  await assert.rejects(collectNextBuildObservation(context), (error: unknown) => (
    error instanceof NextBuildObserverError && error.code === "web.next_build_artifact_path_unsafe"
  ));
}

test("Edge page.files accept exact dist-relative hints and emit repository-relative artifact paths", async (t) => {
  for (const distRelative of [".next", "custom-output", "apps/site/custom-output"]) {
    await t.test(distRelative, async (child) => {
      const item = await edgeFixture(child, distRelative);
      const observed = await collectNextBuildObservation(item.context);
      const assets = observed.outputs[0]!.assets;
      assert.equal(assets.length, 1);
      assert.equal(assets[0]!.logical_path, `${distRelative}/server/middleware-build-manifest.js`);
      assert.equal(assets[0]!.role, "edge_asset");
      assert.equal(assets[0]!.boundary, "edge");
      item.output.assets = { [`${distRelative}/server/middleware-build-manifest.js`]: item.manifest };
      assert.deepEqual(await collectNextBuildObservation(item.context), observed);
      const relocated = await edgeFixture(child, distRelative);
      assert.deepEqual(await collectNextBuildObservation(relocated.context), observed);
    });
  }
});

test("Edge dist-relative hints reject traversal, absolute paths and mismatched prefixes", async (t) => {
  for (const hint of [
    "../.next/server/middleware-build-manifest.js", "server/../server/middleware-build-manifest.js",
    "./server/middleware-build-manifest.js", "server\\middleware-build-manifest.js",
    "/server/middleware-build-manifest.js", "other/server/middleware-build-manifest.js",
    "server/middleware-build-manifest.js?token=private", "server/middleware-build-manifest.js#fragment",
  ]) {
    await t.test(hint, async (child) => {
      const item = await edgeFixture(child);
      item.output.assets = { [hint]: item.manifest };
      await rejectsHint(item.context);
    });
  }
});

test("Edge aliases must identify an exact contained artifact below a contained distDir", async (t) => {
  for (const mode of ["outside-artifact", "outside-dist", "root-dist", "different-artifact", "sibling-prefix"] as const) {
    await t.test(mode, async (child) => {
      const item = await edgeFixture(child);
      if (mode === "outside-artifact") item.output.assets = { "server/middleware-build-manifest.js": path.join(tmpdir(), "manifest.js") };
      if (mode === "outside-dist") item.context.distDir = tmpdir();
      if (mode === "root-dist") item.context.distDir = item.root;
      if (mode === "different-artifact") item.output.assets = { "server/other.js": item.manifest };
      if (mode === "sibling-prefix") item.output.assets = { "server/middleware-build-manifest.js": path.join(item.root, ".next-extra/server/middleware-build-manifest.js") };
      await rejectsHint(item.context);
    });
  }
});

test("dist-relative aliases are not admitted for nodejs, static or wasm artifacts", async (t) => {
  for (const mode of ["nodejs", "static", "wasm"] as const) {
    await t.test(mode, async (child) => {
      const item = await edgeFixture(child);
      if (mode === "nodejs") item.output.runtime = "nodejs";
      if (mode === "static") {
        item.context.outputs.appRoutes = [];
        item.context.outputs.staticFiles = [{ ...item.output, runtime: "static", type: "STATIC_FILE" }];
      }
      if (mode === "wasm") {
        item.output.assets = {};
        item.output.wasmAssets = { "server/middleware-build-manifest.js": item.manifest };
      }
      await rejectsHint(item.context);
    });
  }
});

test("Edge alias normalization retains strict regular-file and canonical-confinement checks", async (t) => {
  for (const mode of ["file-link", "directory-link", "escaped-parent"] as const) {
    await t.test(mode, async (child) => {
      const item = await edgeFixture(child);
      await rm(item.manifest);
      if (mode === "file-link") await symlink(item.main, item.manifest);
      if (mode === "directory-link") await symlink(path.dirname(item.main), item.manifest, "dir");
      if (mode === "escaped-parent") {
        const outside = await mkdtemp(path.join(tmpdir(), "depgraph-next-edge-outside-"));
        child.after(async () => rm(outside, { recursive: true, force: true }));
        await writeFile(path.join(outside, "manifest.js"), "outside contents");
        const escapedParent = path.join(item.distDir, "external");
        await symlink(outside, escapedParent, "dir");
        item.output.assets = { "external/manifest.js": path.join(escapedParent, "manifest.js") };
      }
      await assert.rejects(collectNextBuildObservation(item.context), (error: unknown) => (
        error instanceof NextBuildObserverError && error.code === "web.next_build_artifact_unsafe"
      ));
    });
  }
});
