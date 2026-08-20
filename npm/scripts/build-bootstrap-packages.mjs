#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import {
  cp,
  lstat,
  mkdir,
  mkdtemp,
  readdir,
  rename,
  rm,
  writeFile,
} from "node:fs/promises";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { ROOT_PACKAGE_NAME, TARGETS } from "./build-packages.mjs";

export const BOOTSTRAP_VERSION = "0.0.0-bootstrap.0";
export const BOOTSTRAP_TAG = "bootstrap";
export const BOOTSTRAP_PACKAGE_NAMES = Object.freeze([
  ...TARGETS.map((target) => target.packageName),
  ROOT_PACKAGE_NAME,
]);

const REPOSITORY_ROOT = fileURLToPath(new URL("../../", import.meta.url));
const REPOSITORY = Object.freeze({
  type: "git",
  url: "git+https://github.com/TamaT-LLC/depgraph-cli.git",
});
const LICENSE = "MIT OR Apache-2.0";
const INVENTORY_SCHEMA = "depgraph-npm-bootstrap-set-v1";

function parseArguments(argv) {
  if (argv.length !== 2 || argv[0] !== "--output" || !argv[1] || argv[1].startsWith("--")) {
    throw new Error("usage: build-bootstrap-packages.mjs --output <directory>");
  }
  return { output: argv[1] };
}

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: options.cwd,
    encoding: "utf8",
    maxBuffer: 4 * 1024 * 1024,
    stdio: options.capture ? ["ignore", "pipe", "pipe"] : "inherit",
  });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error(`${command} ${args.join(" ")} failed${result.stderr ? `: ${result.stderr.trim()}` : ""}`);
  }
  return result.stdout ?? "";
}

async function sha256(file) {
  const hash = createHash("sha256");
  await new Promise((resolve, reject) => {
    const input = createReadStream(file);
    input.on("data", (chunk) => hash.update(chunk));
    input.on("error", reject);
    input.on("end", resolve);
  });
  return hash.digest("hex");
}

export function createBootstrapManifest(name) {
  if (!BOOTSTRAP_PACKAGE_NAMES.includes(name)) {
    throw new Error(`unknown bootstrap package name: ${name}`);
  }
  return {
    name,
    version: BOOTSTRAP_VERSION,
    description: "Inert bootstrap placeholder for the official depgraph npm distribution",
    files: ["README.md", "LICENSE-APACHE", "LICENSE-MIT"],
    license: LICENSE,
    repository: REPOSITORY,
    homepage: "https://github.com/TamaT-LLC/depgraph-cli#readme",
    bugs: { url: "https://github.com/TamaT-LLC/depgraph-cli/issues" },
    publishConfig: { access: "public", tag: BOOTSTRAP_TAG },
  };
}

function bootstrapReadme(name) {
  return `# ${name}\n\n` +
    "This inert package reserves an official npm name for the depgraph distribution.\n" +
    "It contains no executable, dependency, or lifecycle script and is not a supported release.\n" +
    "Install a stable version of [`@tamat-llc/depgraph`](https://www.npmjs.com/package/@tamat-llc/depgraph) instead.\n";
}

async function packPackage({ name, stagingRoot, output }) {
  const staging = path.join(stagingRoot, name);
  await mkdir(staging, { recursive: true });
  await writeFile(
    path.join(staging, "package.json"),
    `${JSON.stringify(createBootstrapManifest(name), null, 2)}\n`,
  );
  await writeFile(path.join(staging, "README.md"), bootstrapReadme(name));
  await cp(path.join(REPOSITORY_ROOT, "LICENSE-APACHE"), path.join(staging, "LICENSE-APACHE"));
  await cp(path.join(REPOSITORY_ROOT, "LICENSE-MIT"), path.join(staging, "LICENSE-MIT"));

  const stdout = run(
    "npm",
    ["pack", "--json", "--ignore-scripts", "--pack-destination", output, staging],
    { capture: true },
  );
  const parsed = JSON.parse(stdout);
  if (!Array.isArray(parsed) || parsed.length !== 1) {
    throw new Error(`npm pack returned no result for ${name}`);
  }
  const result = parsed[0];
  if (
    result.name !== name ||
    result.version !== BOOTSTRAP_VERSION ||
    typeof result.filename !== "string" ||
    typeof result.integrity !== "string" ||
    typeof result.shasum !== "string" ||
    !Array.isArray(result.files)
  ) {
    throw new Error(`npm pack returned invalid metadata for ${name}`);
  }
  const expectedFiles = new Set(["package.json", "README.md", "LICENSE-APACHE", "LICENSE-MIT"]);
  const actualFiles = new Set(result.files.map((file) => file.path));
  if (
    expectedFiles.size !== actualFiles.size ||
    [...expectedFiles].some((file) => !actualFiles.has(file))
  ) {
    throw new Error(`${name} bootstrap tarball contains an unexpected file closure`);
  }
  const tarball = path.join(output, result.filename);
  return {
    name,
    version: BOOTSTRAP_VERSION,
    tag: BOOTSTRAP_TAG,
    tarball: result.filename,
    sha256: await sha256(tarball),
    integrity: result.integrity,
    shasum: result.shasum,
    size: result.size,
    unpacked_size: result.unpackedSize,
    file_count: result.entryCount,
  };
}

export async function buildBootstrapPackages({ output }) {
  const outputPath = path.resolve(output);
  try {
    await lstat(outputPath);
    throw new Error(`npm bootstrap output already exists: ${outputPath}`);
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }

  const parent = path.dirname(outputPath);
  await mkdir(parent, { recursive: true });
  const temporary = await mkdtemp(path.join(parent, ".depgraph-npm-bootstrap-"));
  const finalOutput = path.join(temporary, "package-set");
  const stagingRoot = path.join(temporary, "staging");
  await mkdir(finalOutput);
  try {
    const packages = [];
    for (const name of BOOTSTRAP_PACKAGE_NAMES) {
      packages.push(await packPackage({ name, stagingRoot, output: finalOutput }));
    }
    const inventory = {
      schema_version: INVENTORY_SCHEMA,
      repository: "TamaT-LLC/depgraph-cli",
      version: BOOTSTRAP_VERSION,
      npm_tag: BOOTSTRAP_TAG,
      packages,
    };
    await writeFile(
      path.join(finalOutput, "npm-bootstrap-set.json"),
      `${JSON.stringify(inventory, null, 2)}\n`,
    );
    const expectedFiles = new Set([
      "npm-bootstrap-set.json",
      ...packages.map((entry) => entry.tarball),
    ]);
    const actualFiles = new Set(await readdir(finalOutput));
    if (
      expectedFiles.size !== actualFiles.size ||
      [...expectedFiles].some((file) => !actualFiles.has(file))
    ) {
      throw new Error("npm bootstrap output contains an unexpected file closure");
    }
    await rename(finalOutput, outputPath);
    return inventory;
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
}

const invokedAsScript = process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url;
if (invokedAsScript) {
  try {
    const options = parseArguments(process.argv.slice(2));
    const inventory = await buildBootstrapPackages(options);
    process.stdout.write(`built ${inventory.packages.length} inert npm bootstrap packages\n`);
  } catch (error) {
    process.stderr.write(`npm bootstrap package build failed: ${error.message}\n`);
    process.exitCode = 1;
  }
}
