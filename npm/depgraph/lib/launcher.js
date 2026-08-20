import { createReadStream } from "node:fs";
import { lstat, readFile, realpath } from "node:fs/promises";
import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import path from "node:path";
import { spawn } from "node:child_process";

const require = createRequire(import.meta.url);
const MAX_METADATA_BYTES = 2 * 1024 * 1024;
const SHA256_PATTERN = /^[0-9a-f]{64}$/u;

const PLATFORM_PACKAGES = Object.freeze({
  "darwin:arm64": Object.freeze({
    packageName: "@tamat-llc/depgraph-darwin-arm64",
    target: "aarch64-apple-darwin",
    executableSuffix: "",
  }),
  "darwin:x64": Object.freeze({
    packageName: "@tamat-llc/depgraph-darwin-x64",
    target: "x86_64-apple-darwin",
    executableSuffix: "",
  }),
  "linux:arm64": Object.freeze({
    packageName: "@tamat-llc/depgraph-linux-arm64-gnu",
    target: "aarch64-unknown-linux-gnu",
    executableSuffix: "",
  }),
  "linux:x64": Object.freeze({
    packageName: "@tamat-llc/depgraph-linux-x64-gnu",
    target: "x86_64-unknown-linux-gnu",
    executableSuffix: "",
  }),
  "win32:x64": Object.freeze({
    packageName: "@tamat-llc/depgraph-win32-x64",
    target: "x86_64-pc-windows-msvc",
    executableSuffix: ".exe",
  }),
});

function runtimeGlibcVersion() {
  if (process.platform !== "linux") return null;
  const report = process.report?.getReport?.();
  return report?.header?.glibcVersionRuntime ?? null;
}

export function selectPlatform({
  platform = process.platform,
  arch = process.arch,
  glibcVersionRuntime = runtimeGlibcVersion(),
} = {}) {
  const descriptor = PLATFORM_PACKAGES[`${platform}:${arch}`];
  if (!descriptor) {
    throw new Error(`unsupported platform: ${platform}/${arch}`);
  }
  if (platform === "linux" && !glibcVersionRuntime) {
    throw new Error("unsupported Linux libc: depgraph currently requires glibc");
  }
  return descriptor;
}

async function readRegularJson(file, label) {
  const metadata = await lstat(file);
  if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size === 0 || metadata.size > MAX_METADATA_BYTES) {
    throw new Error(`${label} must be a bounded regular file`);
  }
  try {
    return JSON.parse(await readFile(file, "utf8"));
  } catch (error) {
    throw new Error(`${label} is not valid JSON`, { cause: error });
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

function expectedArtifact(command, suffix) {
  if (command === "depgraph") {
    return { field: "core", path: `bin/depgraph${suffix}` };
  }
  if (command === "depgraph-mcp") {
    return { field: "mcp_server", path: `bin/depgraph-mcp${suffix}` };
  }
  throw new Error(`unsupported depgraph command: ${command}`);
}

export async function verifyPackageCommand({
  packageRoot,
  descriptor,
  command,
  expectedVersion,
}) {
  const canonicalRoot = await realpath(packageRoot);
  const packageJsonPath = path.join(canonicalRoot, "package.json");
  const packageJson = await readRegularJson(packageJsonPath, "platform package metadata");
  if (packageJson.name !== descriptor.packageName || packageJson.version !== expectedVersion) {
    throw new Error("platform package identity does not match the CLI package");
  }

  const manifestPath = path.join(canonicalRoot, "release-manifest.json");
  const manifest = await readRegularJson(manifestPath, "release manifest");
  if (manifest.release_version !== expectedVersion || manifest.target !== descriptor.target) {
    throw new Error("release manifest identity does not match the selected platform package");
  }

  const expected = expectedArtifact(command, descriptor.executableSuffix);
  const artifact = manifest[expected.field];
  if (artifact?.path !== expected.path || !SHA256_PATTERN.test(artifact?.sha256 ?? "")) {
    throw new Error(`release manifest does not attest ${expected.path}`);
  }

  const candidate = path.join(canonicalRoot, ...expected.path.split("/"));
  const metadata = await lstat(candidate);
  if (!metadata.isFile() || metadata.isSymbolicLink()) {
    throw new Error(`${expected.path} must be a regular non-symlink file`);
  }
  const canonicalCandidate = await realpath(candidate);
  if (!canonicalCandidate.startsWith(`${canonicalRoot}${path.sep}`)) {
    throw new Error(`${expected.path} escapes the platform package`);
  }
  if (process.platform !== "win32" && (metadata.mode & 0o111) === 0) {
    throw new Error(`${expected.path} is not executable`);
  }
  if (await sha256(canonicalCandidate) !== artifact.sha256) {
    throw new Error(`${expected.path} does not match the release manifest`);
  }
  return canonicalCandidate;
}

async function installedCommand(command) {
  const descriptor = selectPlatform();
  let platformPackageJson;
  try {
    platformPackageJson = require.resolve(`${descriptor.packageName}/package.json`);
  } catch (error) {
    throw new Error(
      `required optional package ${descriptor.packageName} is missing; reinstall @tamat-llc/depgraph without omitting optional dependencies`,
      { cause: error },
    );
  }

  const rootPackage = await readRegularJson(new URL("../package.json", import.meta.url), "CLI package metadata");
  return verifyPackageCommand({
    packageRoot: path.dirname(await realpath(platformPackageJson)),
    descriptor,
    command,
    expectedVersion: rootPackage.version,
  });
}

function exitCodeForSignal(signal) {
  return { SIGHUP: 129, SIGINT: 130, SIGTERM: 143 }[signal] ?? 1;
}

export async function launch(command, args = process.argv.slice(2)) {
  try {
    const executable = await installedCommand(command);
    const child = spawn(executable, args, {
      cwd: process.cwd(),
      env: process.env,
      stdio: "inherit",
      windowsHide: false,
    });
    const forwardedSignals = ["SIGHUP", "SIGINT", "SIGTERM"];
    const handlers = new Map(
      forwardedSignals.map((signal) => [signal, () => {
        if (!child.killed) child.kill(signal);
      }]),
    );
    for (const [signal, handler] of handlers) process.on(signal, handler);

    const result = await new Promise((resolve, reject) => {
      child.once("error", reject);
      child.once("exit", (code, signal) => resolve({ code, signal }));
    });
    for (const [signal, handler] of handlers) process.off(signal, handler);
    process.exitCode = result.code ?? exitCodeForSignal(result.signal);
  } catch (error) {
    process.stderr.write(`depgraph npm launcher: ${error.message}\n`);
    process.exitCode = 1;
  }
}
