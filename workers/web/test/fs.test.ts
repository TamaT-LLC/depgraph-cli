import assert from "node:assert/strict";
import { mkdir, mkdtemp, realpath, rm, symlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";

import {
  inventoryFilesFromManifest,
  readJson,
  readUtf8,
  resolveWithinRoot,
} from "../src/fs";

test("direct reads reject symlinks whose real target is outside the canonical scan root", async (context) => {
  const parent = await mkdtemp(path.join(os.tmpdir(), "depgraph-web-confinement-"));
  context.after(async () => rm(parent, { recursive: true, force: true }));
  const root = path.join(parent, "repo");
  const outside = path.join(parent, "outside");
  await Promise.all([mkdir(root), mkdir(outside)]);
  await writeFile(path.join(root, "inside.json"), JSON.stringify({ scope: "inside" }));
  await writeFile(path.join(outside, "secret.json"), JSON.stringify({ scope: "outside-secret" }));
  try {
    await symlink(path.join(outside, "secret.json"), path.join(root, "linked.json"));
  } catch (error) {
    context.skip(`symlink unavailable: ${String(error)}`);
    return;
  }

  assert.deepEqual(await readJson(root, path.join(root, "inside.json")), { scope: "inside" });
  assert.equal(await resolveWithinRoot(root, path.join(root, "linked.json")), null);
  assert.equal(await readUtf8(root, path.join(root, "linked.json")), null);
  assert.equal(await readJson(root, path.join(root, "linked.json")), null);
});

test("core repository inventory confines Web source enumeration", async (context) => {
  const parent = await mkdtemp(path.join(os.tmpdir(), "depgraph-web-inventory-"));
  context.after(async () => rm(parent, { recursive: true, force: true }));
  const root = path.join(parent, "repo");
  await Promise.all([
    mkdir(path.join(root, "src"), { recursive: true }),
    mkdir(path.join(root, ".branches", "feature", ".next"), { recursive: true }),
  ]);
  await Promise.all([
    writeFile(path.join(root, "package.json"), JSON.stringify({ name: "inventory" })),
    writeFile(path.join(root, "src", "app.ts"), "export const app = true;\n"),
    writeFile(path.join(root, ".branches", "feature", ".next", "generated.ts"), "ignored\n"),
  ]);
  const inventoryFile = path.join(parent, "inventory.json");
  await writeFile(inventoryFile, JSON.stringify({
    contract_version: "depgraph-repository-file-inventory-v1",
    paths: ["package.json", "src/app.ts"],
  }));

  const inventory = await inventoryFilesFromManifest(root, inventoryFile);
  const canonicalRoot = await realpath(root);
  assert.deepEqual(
    inventory.files.map((file) => path.relative(canonicalRoot, file).replaceAll("\\", "/")),
    ["package.json", "src/app.ts"],
  );
  assert.deepEqual(inventory.issues, []);
});
