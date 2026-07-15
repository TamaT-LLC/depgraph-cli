import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";

import { readJson, readUtf8, resolveWithinRoot } from "../src/fs";

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
