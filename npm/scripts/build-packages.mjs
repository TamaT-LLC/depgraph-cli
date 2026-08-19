#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import {
  cp,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  realpath,
  rename,
  rm,
  writeFile,
} from "node:fs/promises";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

export const ROOT_PACKAGE_NAME = "depgraph-cli";
export const PACKAGE_SET_SCHEMA = "depgraph-npm-package-set-v1";
export const TARGETS = Object.freeze([
  Object.freeze({
    target: "aarch64-apple-darwin",
    extension: "tar.gz",
    packageName: "depgraph-cli-darwin-arm64",
    os: "darwin",
    cpu: "arm64",
  }),
  Object.freeze({
    target: "x86_64-apple-darwin",
    extension: "tar.gz",
    packageName: "depgraph-cli-darwin-x64",
    os: "darwin",
    cpu: "x64",
  }),
  Object.freeze({
    target: "aarch64-unknown-linux-gnu",
    extension: "tar.gz",
    packageName: "depgraph-cli-linux-arm64-gnu",
    os: "linux",
    cpu: "arm64",
    libc: "glibc",
  }),
  Object.freeze({
    target: "x86_64-unknown-linux-gnu",
    extension: "tar.gz",
    packageName: "depgraph-cli-linux-x64-gnu",
    os: "linux",
    cpu: "x64",
    libc: "glibc",
  }),
  Object.freeze({
    target: "x86_64-pc-windows-msvc",
    extension: "zip",
    packageName: "depgraph-cli-win32-x64",
    os: "win32",
    cpu: "x64",
  }),
]);

const REPOSITORY = Object.freeze({
  type: "git",
  url: "git+https://github.com/TamaT-LLC/depgraph-cli.git",
});
const LICENSE = "MIT OR Apache-2.0";
const VERSION_PATTERN = /^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$/u;
const SHA256_PATTERN = /^[0-9a-f]{64}$/u;
const REPOSITORY_ROOT = fileURLToPath(new URL("../../", import.meta.url));
const ROOT_TEMPLATE = path.join(REPOSITORY_ROOT, "npm", "depgraph-cli");

function parseArguments(argv) {
  const values = new Map();
  for (let index = 0; index < argv.length; index += 2) {
    const key = argv[index];
    const value = argv[index + 1];
    if (!key?.startsWith("--") || !value || value.startsWith("--") || values.has(key)) {
      throw new Error("usage: build-packages.mjs --release-assets <directory> --output <directory>");
    }
    values.set(key, value);
  }
  if (values.size !== 2 || !values.has("--release-assets") || !values.has("--output")) {
    throw new Error("usage: build-packages.mjs --release-assets <directory> --output <directory>");
  }
  return {
    releaseAssets: values.get("--release-assets"),
    output: values.get("--output"),
  };
}

async function readJson(file, label) {
  try {
    return JSON.parse(await readFile(file, "utf8"));
  } catch (error) {
    throw new Error(`${label} is not valid JSON: ${file}`, { cause: error });
  }
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

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: options.cwd,
    encoding: "utf8",
    maxBuffer: 16 * 1024 * 1024,
    stdio: options.capture ? ["ignore", "pipe", "pipe"] : "inherit",
  });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error(`${command} ${args.join(" ")} failed${result.stderr ? `: ${result.stderr.trim()}` : ""}`);
  }
  return result.stdout ?? "";
}

async function assertRegularDirectory(directory, label) {
  const metadata = await lstat(directory);
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
    throw new Error(`${label} must be a regular non-symlink directory`);
  }
}

async function rejectSymlinks(root) {
  for (const entry of await readdir(root, { withFileTypes: true })) {
    const file = path.join(root, entry.name);
    const metadata = await lstat(file);
    if (metadata.isSymbolicLink()) throw new Error(`release package contains a symlink: ${file}`);
    if (metadata.isDirectory()) await rejectSymlinks(file);
    else if (!metadata.isFile()) throw new Error(`release package contains a special file: ${file}`);
  }
}

export function createPlatformManifest(target, version) {
  const manifest = {
    name: target.packageName,
    version,
    description: `Native depgraph binaries for ${target.target}`,
    os: [target.os],
    cpu: [target.cpu],
    engines: { node: ">=24.0.0" },
    files: [
      "bin",
      "libexec",
      "schemas",
      "queries",
      "fixtures",
      "release-manifest.json",
      "sbom.spdx.json",
      "THIRD_PARTY_LICENSES.txt",
      "LICENSE-APACHE",
      "LICENSE-MIT",
      "README.md",
    ],
    license: LICENSE,
    repository: REPOSITORY,
    homepage: "https://github.com/TamaT-LLC/depgraph-cli#readme",
    bugs: { url: "https://github.com/TamaT-LLC/depgraph-cli/issues" },
    publishConfig: { access: "public", provenance: true },
  };
  if (target.libc) manifest.libc = [target.libc];
  return manifest;
}

export function createRootManifest(template, version) {
  if (template.name !== ROOT_PACKAGE_NAME || template.version !== version || template.private !== true) {
    throw new Error("private npm CLI template identity is not synchronized with the release version");
  }
  const manifest = structuredClone(template);
  delete manifest.private;
  manifest.optionalDependencies = Object.fromEntries(
    TARGETS.map((target) => [target.packageName, version]),
  );
  return manifest;
}

function platformReadme(target) {
  return `# ${target.packageName}\n\n` +
    `Native depgraph release package for \`${target.target}\`. This package is selected by ` +
    "[`depgraph-cli`](https://www.npmjs.com/package/depgraph-cli) through an exact-version " +
    "optional dependency. Install `depgraph-cli` instead of depending on this package directly.\n\n" +
    "The package preserves the verified GitHub Release layout, release manifest, project licenses, " +
    "third-party notices, and SPDX SBOM.\n";
}

function validateReleaseManifest(manifest, target, version) {
  const suffix = target.os === "win32" ? ".exe" : "";
  if (
    manifest.release_version !== version ||
    manifest.target !== target.target ||
    manifest.license_expression !== LICENSE ||
    manifest.core?.path !== `bin/depgraph${suffix}` ||
    manifest.mcp_server?.path !== `bin/depgraph-mcp${suffix}` ||
    !SHA256_PATTERN.test(manifest.core?.sha256 ?? "") ||
    !SHA256_PATTERN.test(manifest.mcp_server?.sha256 ?? "")
  ) {
    throw new Error(`release manifest is incompatible with ${target.packageName}@${version}`);
  }
}

async function extractArchive(archive, target, destination) {
  await mkdir(destination, { recursive: true });
  if (target.extension === "zip") run("unzip", ["-q", archive, "-d", destination]);
  else run("tar", ["-xzf", archive, "-C", destination]);
}

function validatePackResult(result, expectedName, version, role) {
  if (
    result.name !== expectedName ||
    result.version !== version ||
    typeof result.filename !== "string" ||
    typeof result.integrity !== "string" ||
    typeof result.shasum !== "string" ||
    !Array.isArray(result.files)
  ) {
    throw new Error(`npm pack returned an invalid result for ${expectedName}`);
  }
  const files = new Set(result.files.map((file) => file.path));
  for (const required of ["package.json", "README.md", "LICENSE-APACHE", "LICENSE-MIT"]) {
    if (!files.has(required)) throw new Error(`${expectedName} tarball is missing ${required}`);
  }
  if (role === "root") {
    for (const required of ["bin/depgraph.js", "bin/depgraph-mcp.js", "lib/launcher.js"]) {
      if (!files.has(required)) throw new Error(`${expectedName} tarball is missing ${required}`);
    }
  } else {
    for (const required of ["release-manifest.json", "sbom.spdx.json", "THIRD_PARTY_LICENSES.txt"]) {
      if (!files.has(required)) throw new Error(`${expectedName} tarball is missing ${required}`);
    }
  }
  if ([...files].some((file) => /^(?:src|test|tests|fixtures\/test)(?:\/|$)/u.test(file))) {
    throw new Error(`${expectedName} tarball includes development-only source or tests`);
  }
}

async function pack(staging, output, expectedName, version, role) {
  const stdout = run(
    "npm",
    ["pack", "--json", "--ignore-scripts", "--pack-destination", output, staging],
    { capture: true },
  );
  const parsed = JSON.parse(stdout);
  if (!Array.isArray(parsed) || parsed.length !== 1) throw new Error(`npm pack returned no result for ${expectedName}`);
  const result = parsed[0];
  validatePackResult(result, expectedName, version, role);
  const tarball = path.join(output, result.filename);
  return {
    name: expectedName,
    version,
    role,
    tarball: result.filename,
    sha256: await sha256(tarball),
    integrity: result.integrity,
    shasum: result.shasum,
    size: result.size,
    unpacked_size: result.unpackedSize,
    file_count: result.entryCount,
  };
}

async function preparePlatformPackage({ target, version, releaseAssets, verificationTarget, stagingRoot, output }) {
  const archiveName = `depgraph-${version}-${target.target}.${target.extension}`;
  const archive = path.join(releaseAssets, archiveName);
  const checksum = path.join(releaseAssets, `${archiveName}.sha256`);
  const archiveDigest = await sha256(archive);
  if (archiveDigest !== verificationTarget.archive_sha256) {
    throw new Error(`${archiveName} differs from release-verification.json`);
  }
  if (await readFile(checksum, "utf8") !== `${archiveDigest}  ${archiveName}\n`) {
    throw new Error(`${archiveName}.sha256 does not attest the release archive`);
  }

  const extraction = path.join(stagingRoot, "extracted", target.packageName);
  await extractArchive(archive, target, extraction);
  const expectedRootName = `depgraph-${version}-${target.target}`;
  const entries = await readdir(extraction);
  if (entries.length !== 1 || entries[0] !== expectedRootName) {
    throw new Error(`${archiveName} has an unexpected extraction root`);
  }
  const releaseRoot = path.join(extraction, expectedRootName);
  await assertRegularDirectory(releaseRoot, "extracted release root");
  await rejectSymlinks(releaseRoot);
  const releaseManifest = await readJson(path.join(releaseRoot, "release-manifest.json"), "release manifest");
  validateReleaseManifest(releaseManifest, target, version);

  const staging = path.join(stagingRoot, "packages", target.packageName);
  await cp(releaseRoot, staging, { recursive: true, force: false, errorOnExist: true });
  await writeFile(path.join(staging, "package.json"), `${JSON.stringify(createPlatformManifest(target, version), null, 2)}\n`);
  await writeFile(path.join(staging, "README.md"), platformReadme(target));
  const packageRecord = await pack(staging, output, target.packageName, version, "platform");
  return {
    ...packageRecord,
    target: target.target,
    source_archive: archiveName,
    source_archive_sha256: archiveDigest,
    release_manifest_sha256: verificationTarget.release_manifest_sha256,
  };
}

async function prepareRootPackage({ version, stagingRoot, output }) {
  const staging = path.join(stagingRoot, "packages", ROOT_PACKAGE_NAME);
  await cp(ROOT_TEMPLATE, staging, { recursive: true, force: false, errorOnExist: true });
  await cp(path.join(REPOSITORY_ROOT, "LICENSE-APACHE"), path.join(staging, "LICENSE-APACHE"));
  await cp(path.join(REPOSITORY_ROOT, "LICENSE-MIT"), path.join(staging, "LICENSE-MIT"));
  const template = await readJson(path.join(staging, "package.json"), "private npm CLI template");
  await writeFile(path.join(staging, "package.json"), `${JSON.stringify(createRootManifest(template, version), null, 2)}\n`);
  return pack(staging, output, ROOT_PACKAGE_NAME, version, "root");
}

export async function buildPackages({ releaseAssets, output }) {
  const canonicalAssets = await realpath(releaseAssets);
  await assertRegularDirectory(canonicalAssets, "release asset directory");
  const outputPath = path.resolve(output);
  try {
    await lstat(outputPath);
    throw new Error(`npm package output already exists: ${outputPath}`);
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
  if (outputPath.startsWith(`${canonicalAssets}${path.sep}`)) {
    throw new Error("npm package output must be outside the verified release asset directory");
  }

  const verificationPath = path.join(canonicalAssets, "release-verification.json");
  const verification = await readJson(verificationPath, "release verification");
  const version = verification.release_version;
  if (
    verification.schema_version !== 9 ||
    !VERSION_PATTERN.test(version ?? "") ||
    verification.tag !== `v${version}` ||
    verification.license_expression !== LICENSE ||
    !Array.isArray(verification.targets) ||
    verification.targets.length !== TARGETS.length
  ) {
    throw new Error("release-verification.json is not a stable five-target release closure");
  }
  const verificationTargets = new Map(verification.targets.map((target) => [target.target, target]));
  if (verificationTargets.size !== TARGETS.length || TARGETS.some((target) => !verificationTargets.has(target.target))) {
    throw new Error("release-verification.json has an unknown, missing, or duplicate target");
  }

  const parent = path.dirname(outputPath);
  await mkdir(parent, { recursive: true });
  const temporary = await mkdtemp(path.join(parent, ".depgraph-npm-"));
  const finalOutput = path.join(temporary, "package-set");
  const stagingRoot = path.join(temporary, "staging");
  await mkdir(finalOutput);
  try {
    const packages = [];
    for (const target of TARGETS) {
      packages.push(await preparePlatformPackage({
        target,
        version,
        releaseAssets: canonicalAssets,
        verificationTarget: verificationTargets.get(target.target),
        stagingRoot,
        output: finalOutput,
      }));
    }
    packages.push(await prepareRootPackage({ version, stagingRoot, output: finalOutput }));
    const inventory = {
      schema_version: PACKAGE_SET_SCHEMA,
      release_version: version,
      release_tag: verification.tag,
      repository: "TamaT-LLC/depgraph-cli",
      npm_tag: "latest",
      release_verification_sha256: await sha256(verificationPath),
      packages,
    };
    await writeFile(path.join(finalOutput, "npm-package-set.json"), `${JSON.stringify(inventory, null, 2)}\n`);
    const expectedFiles = new Set(["npm-package-set.json", ...packages.map((entry) => entry.tarball)]);
    const actualFiles = new Set(await readdir(finalOutput));
    if (expectedFiles.size !== actualFiles.size || [...expectedFiles].some((file) => !actualFiles.has(file))) {
      throw new Error("npm package output contains an unexpected file closure");
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
    const inventory = await buildPackages(options);
    process.stdout.write(`built ${inventory.packages.length} npm packages for ${inventory.release_tag}\n`);
  } catch (error) {
    process.stderr.write(`npm package build failed: ${error.message}\n`);
    process.exitCode = 1;
  }
}
