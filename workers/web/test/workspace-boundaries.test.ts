import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { discoverWorkspace } from "../src/workspace";

for (const declaration of ["package.json", "pnpm-workspace.yaml"] as const) {
  test(`nested ${declaration} recursive globs stay within their workspace root`, async (context) => {
    const root = await mkdtemp(path.join(os.tmpdir(), "depgraph-workspace-boundary-"));
    context.after(async () => rm(root, { recursive: true, force: true }));
    const manifests: Record<string, Record<string, unknown>> = {
      "package.json": { name: "repository" },
      "apps/package.json": { name: "unclaimed-ancestor" },
      "apps/frontend/package.json": { name: "frontend" },
      "apps/frontend/packages/shared/package.json": { name: "shared" },
      "apps/frontend-extra/package.json": { name: "unclaimed-sibling" },
      "tools/package.json": { name: "unclaimed-tools" },
      "apps/independent/package.json": { name: "independent", workspaces: ["packages/*"] },
      "apps/independent/packages/own/package.json": { name: "own" },
    };
    if (declaration === "package.json") manifests["apps/frontend/package.json"]!.workspaces = ["**"];
    const files = await Promise.all(Object.entries(manifests).map(async ([relative, manifest]) => {
      const file = path.join(root, relative);
      await mkdir(path.dirname(file), { recursive: true });
      await writeFile(file, JSON.stringify(manifest));
      return file;
    }));
    if (declaration === "pnpm-workspace.yaml") {
      const file = path.join(root, "apps/frontend/pnpm-workspace.yaml");
      await writeFile(file, 'packages:\n  - "**"\n');
      files.push(file);
    }

    const workspace = await discoverWorkspace(root, files);
    assert.deepEqual(workspace.packages.map((record) => record.relativePath), [
      ".",
      "apps",
      "apps/frontend",
      "apps/frontend-extra",
      "apps/frontend/packages/shared",
      "apps/independent",
      "apps/independent/packages/own",
      "tools",
    ]);
    assert.deepEqual(workspace.packages
      .filter((record) => record.relativePath === "apps/frontend-extra" || record.relativePath === "apps" || record.relativePath === "tools")
      .map((record) => [record.relativePath, record.workspaceRoot]), [
      ["apps", "apps"],
      ["apps/frontend-extra", "apps/frontend-extra"],
      ["tools", "tools"],
    ]);
    assert.deepEqual(workspace.standaloneManifestPaths, [
      "apps/frontend-extra/package.json",
      "apps/package.json",
      "tools/package.json",
    ]);
    assert.deepEqual(workspace.ignoredManifestPaths, []);
  });
}
