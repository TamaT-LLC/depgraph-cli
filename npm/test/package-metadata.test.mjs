import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  ROOT_PACKAGE_NAME,
  TARGETS,
  createPlatformManifest,
  createRootManifest,
} from "../scripts/build-packages.mjs";
import {
  BOOTSTRAP_PACKAGE_NAMES,
  BOOTSTRAP_TAG,
  BOOTSTRAP_VERSION,
  createBootstrapManifest,
} from "../scripts/build-bootstrap-packages.mjs";

const template = JSON.parse(await readFile(new URL("../depgraph-cli/package.json", import.meta.url), "utf8"));

test("the source CLI package is private until release packaging", () => {
  assert.equal(template.name, ROOT_PACKAGE_NAME);
  assert.equal(template.private, true);
  assert.equal(template.license, "MIT OR Apache-2.0");
  assert.equal(template.repository.url, "git+https://github.com/TamaT-LLC/depgraph-cli.git");
  assert.deepEqual(template.bin, {
    depgraph: "bin/depgraph.js",
    "depgraph-cli": "bin/depgraph.js",
    "depgraph-mcp": "bin/depgraph-mcp.js",
  });
  assert.equal(template.scripts, undefined);
});

test("release packaging adds exact optional platform dependencies and removes private", () => {
  const manifest = createRootManifest(template, template.version);
  assert.equal(manifest.private, undefined);
  assert.deepEqual(
    manifest.optionalDependencies,
    Object.fromEntries(TARGETS.map((target) => [target.packageName, template.version])),
  );
  assert.equal(Object.keys(manifest.optionalDependencies).length, 5);
});

test("platform package constraints cover the five native release targets exactly", () => {
  assert.equal(new Set(TARGETS.map((target) => target.target)).size, 5);
  assert.equal(new Set(TARGETS.map((target) => target.packageName)).size, 5);
  for (const target of TARGETS) {
    const manifest = createPlatformManifest(target, template.version);
    assert.equal(manifest.name, target.packageName);
    assert.equal(manifest.version, template.version);
    assert.deepEqual(manifest.os, [target.os]);
    assert.deepEqual(manifest.cpu, [target.cpu]);
    assert.equal(manifest.scripts, undefined);
    assert.equal(manifest.dependencies, undefined);
    assert.equal(manifest.publishConfig.provenance, true);
    if (target.os === "linux") assert.deepEqual(manifest.libc, ["glibc"]);
    else assert.equal(manifest.libc, undefined);
  }
});

test("release packaging rejects source-version drift", () => {
  assert.throws(() => createRootManifest(template, "9.9.9"), /not synchronized/u);
});

test("bootstrap packages are inert, non-latest name reservations", () => {
  assert.deepEqual(BOOTSTRAP_PACKAGE_NAMES, [
    ...TARGETS.map((target) => target.packageName),
    ROOT_PACKAGE_NAME,
  ]);
  assert.equal(new Set(BOOTSTRAP_PACKAGE_NAMES).size, 6);
  for (const name of BOOTSTRAP_PACKAGE_NAMES) {
    const manifest = createBootstrapManifest(name);
    assert.equal(manifest.name, name);
    assert.equal(manifest.version, BOOTSTRAP_VERSION);
    assert.deepEqual(manifest.publishConfig, { access: "public", tag: BOOTSTRAP_TAG });
    assert.deepEqual(manifest.files, ["README.md", "LICENSE-APACHE", "LICENSE-MIT"]);
    assert.equal(manifest.license, "MIT OR Apache-2.0");
    assert.equal(manifest.repository.url, "git+https://github.com/TamaT-LLC/depgraph-cli.git");
    for (const forbidden of [
      "private",
      "bin",
      "scripts",
      "dependencies",
      "optionalDependencies",
      "peerDependencies",
      "devDependencies",
    ]) {
      assert.equal(manifest[forbidden], undefined);
    }
  }
});

test("bootstrap manifest rejects a name outside the closed package set", () => {
  assert.throws(() => createBootstrapManifest("depgraph-cli-unknown"), /unknown bootstrap package/u);
});
