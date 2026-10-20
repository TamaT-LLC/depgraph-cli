import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { chmod, mkdir, mkdtemp, readFile, realpath, symlink, unlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  missingPlatformPackageMessage,
  npxInstallFor,
  satisfiesMinimumVersion,
  selectPlatform,
  verifyPackageCommand,
} from "../depgraph/lib/launcher.js";

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
  assert.throws(
    () => selectPlatform({ platform: "darwin", arch: "x64" }),
    /unsupported platform/u,
  );
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

const rootPackage = { name: "@tamat-llc/depgraph", version: "0.7.0", engines: { node: ">=24.0.0" } };
const npxLauncher = "/Users/me/.npm/_npx/54494822b90eadc5/node_modules/@tamat-llc/depgraph/lib/launcher.js";
const globalLauncher = "/usr/local/lib/node_modules/@tamat-llc/depgraph/lib/launcher.js";

test("satisfiesMinimumVersion compares only ranges it understands", () => {
  assert.equal(satisfiesMinimumVersion(">=24.0.0", "v22.23.2"), false);
  assert.equal(satisfiesMinimumVersion(">=24.0.0", "v23.99.99"), false);
  assert.equal(satisfiesMinimumVersion(">=24.0.0", "v24.0.0"), true);
  assert.equal(satisfiesMinimumVersion(">=24.0.0", "24.22.0"), true);
  assert.equal(satisfiesMinimumVersion(">=24.1.0", "v24.0.9"), false);
  assert.equal(satisfiesMinimumVersion("^24", "v22.0.0"), null);
  assert.equal(satisfiesMinimumVersion(undefined, "v22.0.0"), null);
});

test("npxInstallFor finds the npx install directory and its cache key", () => {
  assert.deepEqual(npxInstallFor(npxLauncher), {
    directory: "/Users/me/.npm/_npx/54494822b90eadc5",
    key: "54494822b90eadc5",
  });
  assert.deepEqual(
    npxInstallFor(
      "C:\\Users\\me\\AppData\\Local\\npm-cache\\_npx\\0123456789abcdef\\node_modules\\@tamat-llc\\depgraph\\lib\\launcher.js",
    ),
    { directory: "C:\\Users\\me\\AppData\\Local\\npm-cache\\_npx\\0123456789abcdef", key: "0123456789abcdef" },
  );
  assert.equal(npxInstallFor(globalLauncher), null);
});

test("a missing platform package under an old Node.js names the engines mismatch first", () => {
  const message = missingPlatformPackageMessage({
    packageName: "@tamat-llc/depgraph-darwin-arm64",
    rootPackage,
    nodeVersion: "v22.23.2",
    launcherPath: npxLauncher,
  });
  assert.equal(
    message.split("\n")[0],
    "Node.js v22.23.2 does not satisfy @tamat-llc/depgraph@0.7.0's requirement node >=24.0.0.",
  );
  assert.match(message, /skips the optional platform package @tamat-llc\/depgraph-darwin-arm64/u);
  assert.match(message, /switch to Node\.js 24 or newer/u);
  assert.match(message, /npm cache npx rm 54494822b90eadc5/u);
  assert.match(message, /or delete \/Users\/me\/\.npm\/_npx\/54494822b90eadc5/u);
  assert.doesNotMatch(message, /without omitting optional dependencies/u);
});

test("a missing platform package under a supported Node.js lists the reuse and omit causes", () => {
  const viaNpx = missingPlatformPackageMessage({
    packageName: "@tamat-llc/depgraph-darwin-arm64",
    rootPackage,
    nodeVersion: "v24.22.0",
    launcherPath: npxLauncher,
  });
  assert.match(
    viaNpx,
    /^required optional package @tamat-llc\/depgraph-darwin-arm64 is missing, although Node\.js v24\.22\.0 satisfies node >=24\.0\.0\./u,
  );
  assert.match(viaNpx, /install ran under an older Node\.js/u);
  assert.match(viaNpx, /--omit=optional/u);
  assert.match(viaNpx, /npm cache npx rm 54494822b90eadc5/u);

  const global = missingPlatformPackageMessage({
    packageName: "@tamat-llc/depgraph-linux-x64-gnu",
    rootPackage,
    nodeVersion: "v24.22.0",
    launcherPath: globalLauncher,
  });
  assert.match(global, /npm install -g --include=optional @tamat-llc\/depgraph@0\.7\.0/u);
  assert.doesNotMatch(global, /npm cache npx/u);
});
