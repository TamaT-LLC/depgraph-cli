import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import {
  ASTRO_BUILD_OBSERVATION_SCHEMA,
  ASTRO_BUILD_OBSERVER_CAPABILITY,
  ASTRO_BUILD_OBSERVER_VERSION,
} from "../src/astro-build-observer";
import {
  NEXT_BUILD_OBSERVATION_SCHEMA,
  NEXT_BUILD_OBSERVER_CAPABILITY,
  NEXT_BUILD_OBSERVER_VERSION,
} from "../src/next-build-observer";
import {
  TANSTACK_ROUTER_BUILD_CAPABILITY,
  TANSTACK_ROUTER_BUILD_OBSERVER_VERSION,
  TANSTACK_ROUTER_BUILD_SCHEMA,
} from "../src/tanstack-router-build-observer";
import {
  TANSTACK_START_BUILD_CAPABILITY,
  TANSTACK_START_BUILD_OBSERVER_VERSION,
  TANSTACK_START_BUILD_SCHEMA,
} from "../src/tanstack-start-build-observer";

interface ArtifactInventory {
  name: string;
  version: string;
  license: string;
  path: string;
  sha256: string;
  roles: string[];
  bundled_packages: string[];
  framework?: string;
  capability?: string;
  observation_schema?: string;
}

test("release inventory pins every dynamic framework observer and converter as dependency-free artifacts", async () => {
  const inventory = JSON.parse(
    await readFile(path.resolve("dist/runtime-packages.json"), "utf8"),
  ) as { schema_version: number; artifacts: ArtifactInventory[] };
  assert.equal(inventory.schema_version, 1);
  assert.equal(inventory.artifacts.length, 6);
  const expected = [
    {
      framework: "astro",
      name: "depgraph-astro-build-observer",
      version: ASTRO_BUILD_OBSERVER_VERSION,
      capability: ASTRO_BUILD_OBSERVER_CAPABILITY,
      observation_schema: ASTRO_BUILD_OBSERVATION_SCHEMA,
      path: "astro-build-integration.mjs",
    },
    {
      framework: "next",
      name: "depgraph-next-build-observer",
      version: NEXT_BUILD_OBSERVER_VERSION,
      capability: NEXT_BUILD_OBSERVER_CAPABILITY,
      observation_schema: NEXT_BUILD_OBSERVATION_SCHEMA,
      path: "next-build-adapter.mjs",
    },
    {
      framework: "tanstack-router",
      name: "depgraph-tanstack-router-build-observer",
      version: TANSTACK_ROUTER_BUILD_OBSERVER_VERSION,
      capability: TANSTACK_ROUTER_BUILD_CAPABILITY,
      observation_schema: TANSTACK_ROUTER_BUILD_SCHEMA,
      path: "tanstack-router-build-observer.mjs",
    },
    {
      framework: "tanstack-start",
      name: "depgraph-tanstack-start-build-observer",
      version: TANSTACK_START_BUILD_OBSERVER_VERSION,
      capability: TANSTACK_START_BUILD_CAPABILITY,
      observation_schema: TANSTACK_START_BUILD_SCHEMA,
      path: "tanstack-start-build-observer.mjs",
    },
  ];
  for (const required of expected) {
    const artifact = inventory.artifacts.find((candidate) => candidate.framework === required.framework);
    assert.deepEqual(artifact, {
      ...required,
      license: "MIT OR Apache-2.0",
      sha256: artifact?.sha256,
      roles: ["framework-build-observer"],
      bundled_packages: [],
    });
  }
  const converter = inventory.artifacts.find(
    (artifact) => artifact.name === "depgraph-web-build-evidence",
  );
  assert.deepEqual(converter, {
    name: "depgraph-web-build-evidence",
    version: "dynamic-framework-evidence-release-gate-v1",
    license: "MIT OR Apache-2.0",
    path: "depgraph-web-build-evidence.mjs",
    sha256: converter?.sha256,
    roles: ["framework-build-converter"],
    bundled_packages: [],
  });
  for (const artifact of inventory.artifacts) {
    const bytes = await readFile(path.resolve("dist", artifact.path));
    assert.match(artifact.sha256, /^[a-f0-9]{64}$/u);
    assert.equal(createHash("sha256").update(bytes).digest("hex"), artifact.sha256);
    assert.deepEqual(artifact.bundled_packages, []);
  }
});
