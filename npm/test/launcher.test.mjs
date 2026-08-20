import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { chmod, mkdir, mkdtemp, readFile, realpath, symlink, unlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { selectPlatform, verifyPackageCommand } from "../depgraph/lib/launcher.js";

const version = JSON.parse(
  await readFile(new URL("../depgraph/package.json", import.meta.url), "utf8"),
).version;

function digest(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

async function fixture() {
  const root = await mkdtemp(path.join(os.tmpdir(), "depgraph-npm-launcher-"));
  const descriptor = selectPlatform({ platform: "linux", arch: "x64", glibcVersionRuntime: "2.39" });
  const binary = Buffer.from("#!/bin/sh\nexit 0\n");
  await mkdir(path.join(root, "bin"), { recursive: true });
  await writeFile(path.join(root, "bin", "depgraph"), binary);
  await chmod(path.join(root, "bin", "depgraph"), 0o755);
  await writeFile(path.join(root, "package.json"), `${JSON.stringify({ name: descriptor.packageName, version })}\n`);
  await writeFile(path.join(root, "release-manifest.json"), `${JSON.stringify({
    release_version: version,
    target: descriptor.target,
    core: { path: "bin/depgraph", sha256: digest(binary) },
  })}\n`);
  return { root, descriptor };
}

test("selectPlatform maps every supported npm target", () => {
  assert.equal(
    selectPlatform({ platform: "darwin", arch: "arm64" }).packageName,
    "@tamat-llc/depgraph-darwin-arm64",
  );
  assert.equal(selectPlatform({ platform: "darwin", arch: "x64" }).target, "x86_64-apple-darwin");
  assert.equal(
    selectPlatform({ platform: "linux", arch: "arm64", glibcVersionRuntime: "2.39" }).packageName,
    "@tamat-llc/depgraph-linux-arm64-gnu",
  );
  assert.equal(selectPlatform({ platform: "win32", arch: "x64" }).executableSuffix, ".exe");
});

test("selectPlatform rejects unsupported architectures and musl", () => {
  assert.throws(() => selectPlatform({ platform: "freebsd", arch: "x64" }), /unsupported platform/u);
  assert.throws(
    () => selectPlatform({ platform: "linux", arch: "x64", glibcVersionRuntime: null }),
    /requires glibc/u,
  );
});

test("verifyPackageCommand accepts only the manifest-attested executable", async () => {
  const { root, descriptor } = await fixture();
  assert.equal(
    await verifyPackageCommand({ packageRoot: root, descriptor, command: "depgraph", expectedVersion: version }),
    await realpath(path.join(root, "bin", "depgraph")),
  );
});

test("verifyPackageCommand rejects tampered bytes and target drift", async () => {
  const { root, descriptor } = await fixture();
  await writeFile(path.join(root, "bin", "depgraph"), "#!/bin/sh\nexit 1\n");
  await chmod(path.join(root, "bin", "depgraph"), 0o755);
  await assert.rejects(
    verifyPackageCommand({ packageRoot: root, descriptor, command: "depgraph", expectedVersion: version }),
    /does not match the release manifest/u,
  );

  const second = await fixture();
  const manifestPath = path.join(second.root, "release-manifest.json");
  const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
  manifest.target = "aarch64-unknown-linux-gnu";
  await writeFile(manifestPath, `${JSON.stringify(manifest)}\n`);
  await assert.rejects(
    verifyPackageCommand({
      packageRoot: second.root,
      descriptor: second.descriptor,
      command: "depgraph",
      expectedVersion: version,
    }),
    /identity does not match/u,
  );
});

test("verifyPackageCommand rejects a symlinked executable", { skip: process.platform === "win32" }, async () => {
  const { root, descriptor } = await fixture();
  const real = path.join(root, "bin", "depgraph-real");
  await writeFile(real, "#!/bin/sh\nexit 0\n");
  await chmod(real, 0o755);
  await writeFile(
    path.join(root, "release-manifest.json"),
    `${JSON.stringify({
      release_version: version,
      target: descriptor.target,
      core: { path: "bin/depgraph", sha256: digest(await readFile(real)) },
    })}\n`,
  );
  await unlink(path.join(root, "bin", "depgraph"));
  await symlink("depgraph-real", path.join(root, "bin", "depgraph"));
  await assert.rejects(
    verifyPackageCommand({ packageRoot: root, descriptor, command: "depgraph", expectedVersion: version }),
    /regular non-symlink/u,
  );
});
