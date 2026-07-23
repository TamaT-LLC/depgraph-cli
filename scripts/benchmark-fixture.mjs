#!/usr/bin/env node

import { createHash } from "node:crypto";
import {
  closeSync,
  mkdirSync,
  openSync,
  readFileSync,
  statSync,
  writeSync,
  writeFileSync,
} from "node:fs";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

export const FIXTURE_SCHEMA_VERSION = "depgraph-benchmark-fixture-v1";

function sourceName(index) {
  return `f${String(index).padStart(5, "0")}.ts`;
}

function sourceContents(index, fileCount) {
  const current = String(index).padStart(5, "0");
  const importLine =
    index + 1 < fileCount
      ? `import "./${sourceName(index + 1).replace(/\.ts$/, ".js")}";\n`
      : "";
  return `${importLine}export const value${current} = ${index};\n`;
}

function manifestShape(fileCount) {
  const changedIndex = Math.floor(fileCount / 2);
  return {
    schema_version: FIXTURE_SCHEMA_VERSION,
    source_file_count: fileCount,
    expected_dependency_sites: fileCount - 1,
    changed_file: `src/${sourceName(changedIndex)}`,
    changed_file_index: changedIndex,
    impact_file: `src/${sourceName(1)}`,
    impact_expected_dependent_file: `src/${sourceName(0)}`,
  };
}

function updateFingerprint(hash, relativePath, contents) {
  hash.update(relativePath);
  hash.update("\0");
  hash.update(contents);
  hash.update("\0");
}

export function generateFixture(root, fileCount) {
  if (!Number.isSafeInteger(fileCount) || fileCount < 2 || fileCount > 100_000) {
    throw new Error("benchmark fixture file count must be between 2 and 100000");
  }
  root = resolve(root);
  mkdirSync(root);
  mkdirSync(join(root, "src"));

  const packageJson = `${JSON.stringify(
    {
      name: "depgraph-benchmark",
      version: "1.0.0",
      private: true,
      type: "module",
    },
    null,
    2,
  )}\n`;
  writeFileSync(join(root, "package.json"), packageJson);

  const hash = createHash("sha256");
  updateFingerprint(hash, "package.json", packageJson);
  for (let index = 0; index < fileCount; index += 1) {
    const relativePath = `src/${sourceName(index)}`;
    const contents = sourceContents(index, fileCount);
    writeFileSync(join(root, relativePath), contents);
    updateFingerprint(hash, relativePath, contents);
  }

  const manifest = {
    ...manifestShape(fileCount),
    sha256: hash.digest("hex"),
  };
  writeFileSync(
    join(root, "depgraph-benchmark-fixture-v1.json"),
    `${JSON.stringify(manifest, null, 2)}\n`,
  );
  return manifest;
}

function readManifest(root) {
  const path = join(resolve(root), "depgraph-benchmark-fixture-v1.json");
  const manifest = JSON.parse(readFileSync(path, "utf8"));
  if (
    !Number.isSafeInteger(manifest.source_file_count) ||
    manifest.source_file_count < 2 ||
    manifest.source_file_count > 100_000
  ) {
    throw new Error(`invalid benchmark fixture source count at ${path}`);
  }
  const expected = manifestShape(manifest.source_file_count);
  if (
    Object.keys(manifest).length !== Object.keys(expected).length + 1 ||
    Object.entries(expected).some(([key, value]) => manifest[key] !== value) ||
    typeof manifest.sha256 !== "string" ||
    !/^[0-9a-f]{64}$/.test(manifest.sha256)
  ) {
    throw new Error(`invalid benchmark fixture manifest at ${path}`);
  }
  return manifest;
}

export function mutateFixture(root, revision) {
  if (!Number.isSafeInteger(revision) || revision < 0) {
    throw new Error("benchmark fixture revision must be a non-negative integer");
  }
  root = resolve(root);
  const manifest = readManifest(root);
  const path = join(root, manifest.changed_file);
  const file = openSync(path, "r+");
  try {
    const revisionLine = `// benchmark revision ${revision}\n`;
    const written = writeSync(file, revisionLine, statSync(path).size, "utf8");
    if (written !== Buffer.byteLength(revisionLine)) {
      throw new Error(`short write while mutating benchmark fixture at ${path}`);
    }
  } finally {
    closeSync(file);
  }
  return manifest.changed_file;
}

export function restoreFixture(root) {
  root = resolve(root);
  const manifest = readManifest(root);
  writeFileSync(
    join(root, manifest.changed_file),
    sourceContents(manifest.changed_file_index, manifest.source_file_count),
  );
  return manifest.changed_file;
}

export function fixtureFingerprint(root) {
  root = resolve(root);
  const manifest = readManifest(root);
  const hash = createHash("sha256");
  const packageJson = readFileSync(join(root, "package.json"));
  updateFingerprint(hash, "package.json", packageJson);
  for (let index = 0; index < manifest.source_file_count; index += 1) {
    const relativePath = `src/${sourceName(index)}`;
    updateFingerprint(hash, relativePath, readFileSync(join(root, relativePath)));
  }
  return hash.digest("hex");
}

function usage() {
  throw new Error(
    "usage: benchmark-fixture.mjs generate ROOT FILE_COUNT | mutate ROOT REVISION | restore ROOT | fingerprint ROOT",
  );
}

function main(argv) {
  const [command, root, value, ...extra] = argv;
  if (!command || !root || extra.length > 0) usage();
  switch (command) {
    case "generate":
      if (value === undefined) usage();
      process.stdout.write(
        `${JSON.stringify(generateFixture(root, Number(value)))}\n`,
      );
      break;
    case "mutate":
      if (value === undefined) usage();
      process.stdout.write(`${mutateFixture(root, Number(value))}\n`);
      break;
    case "restore":
      if (value !== undefined) usage();
      process.stdout.write(`${restoreFixture(root)}\n`);
      break;
    case "fingerprint":
      if (value !== undefined) usage();
      process.stdout.write(`${fixtureFingerprint(root)}\n`);
      break;
    default:
      usage();
  }
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(resolve(process.argv[1])).href
) {
  try {
    main(process.argv.slice(2));
  } catch (error) {
    process.stderr.write(`${error.stack ?? error}\n`);
    process.exitCode = 1;
  }
}
