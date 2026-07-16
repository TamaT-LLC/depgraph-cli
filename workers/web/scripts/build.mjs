import { execFile } from "node:child_process";
import { chmod, copyFile, cp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { build } from "esbuild";

const execute = promisify(execFile);

await rm(new URL("../dist", import.meta.url), { recursive: true, force: true });
await mkdir(new URL("../dist", import.meta.url), { recursive: true });

const bundle = await build({
  entryPoints: [fileURLToPath(new URL("../src/worker.ts", import.meta.url))],
  outfile: fileURLToPath(new URL("../dist/worker.mjs", import.meta.url)),
  bundle: true,
  platform: "node",
  format: "esm",
  target: "node24",
  metafile: true,
  define: {
    // Source-mode tests may use dist/typescript explicitly, but a packaged
    // worker must require its own release-adjacent compiler and fail closed.
    __DEPGRAPH_PACKAGED_WORKER__: "true",
  },
  // The release ships a single self-contained worker file. An external map
  // would leave a dangling sourceMappingURL unless it were also part of the
  // checksum-verified runtime manifest.
  sourcemap: false,
  legalComments: "external",
  banner: {
    js: "#!/usr/bin/env node\nimport { createRequire as __depgraphCreateRequire } from 'node:module';\nconst require = __depgraphCreateRequire(import.meta.url);",
  },
  plugins: [{
    name: "astro-compiler-wasm-location",
    setup(context) {
      context.onLoad({ filter: /@astrojs[+\\/]compiler.*[\\/]dist[\\/]node[\\/]sync\.js$/ }, async ({ path }) => ({
        contents: (await readFile(path, "utf8")).replaceAll("../astro.wasm", "./astro.wasm"),
        loader: "js",
      }));
    },
  }],
});

const astroManifest = fileURLToPath(import.meta.resolve("@astrojs/compiler/package.json"));
const astroMetadata = JSON.parse(await readFile(astroManifest, "utf8"));
if (astroMetadata.name !== "@astrojs/compiler" || astroMetadata.version !== "4.0.0") {
  throw new Error(`expected @astrojs/compiler@4.0.0, received ${astroMetadata.name ?? "unknown"}@${astroMetadata.version ?? "unknown"}`);
}
await copyFile(
  fileURLToPath(import.meta.resolve("@astrojs/compiler/astro.wasm")),
  new URL("../dist/astro.wasm", import.meta.url),
);

// TypeScript 7 ships its parser/typechecker as a platform package. Resolve it
// strictly from this worker's pinned TypeScript installation; never from a
// repository being scanned or the build cwd.
const typescriptManifest = fileURLToPath(import.meta.resolve("typescript/package.json"));
const typescriptMetadata = JSON.parse(await readFile(typescriptManifest, "utf8"));
if (typescriptMetadata.name !== "typescript" || typescriptMetadata.version !== "7.0.2") {
  throw new Error(`expected typescript@7.0.2, received ${typescriptMetadata.name ?? "unknown"}@${typescriptMetadata.version ?? "unknown"}`);
}
const platformPackageName = `typescript-${process.platform}-${process.arch}`;
const platformRoot = path.resolve(path.dirname(typescriptManifest), "..", "@typescript", platformPackageName);
const platformMetadata = JSON.parse(await readFile(path.join(platformRoot, "package.json"), "utf8"));
if (platformMetadata.name !== `@typescript/${platformPackageName}` || platformMetadata.version !== "7.0.2") {
  throw new Error(`expected @typescript/${platformPackageName}@7.0.2, received ${platformMetadata.name ?? "unknown"}@${platformMetadata.version ?? "unknown"}`);
}
const compilerName = process.platform === "win32" ? "tsc.exe" : "tsc";
const compilerOutput = fileURLToPath(new URL(`../dist/typescript/lib/${compilerName}`, import.meta.url));
await cp(path.join(platformRoot, "lib"), path.dirname(compilerOutput), { recursive: true, force: true });
if (process.platform !== "win32") await chmod(compilerOutput, 0o755);
const version = await execute(compilerOutput, ["--version"], { encoding: "utf8", timeout: 10_000 });
if (version.stdout.trim() !== "Version 7.0.2" || version.stderr !== "") {
  throw new Error(`copied TypeScript compiler failed its version gate: stdout=${JSON.stringify(version.stdout)}, stderr=${JSON.stringify(version.stderr)}`);
}

function bundledPackageName(input) {
  const normalized = input.replaceAll("\\", "/");
  const marker = "/node_modules/";
  const markerIndex = normalized.lastIndexOf(marker);
  const relative = markerIndex >= 0
    ? normalized.slice(markerIndex + marker.length)
    : normalized.startsWith("node_modules/")
      ? normalized.slice("node_modules/".length)
      : null;
  if (relative === null) return null;
  const segments = relative.split("/");
  return segments[0]?.startsWith("@") ? `${segments[0]}/${segments[1] ?? ""}` : segments[0];
}

const bundledPackages = [...new Set(
  Object.keys(bundle.metafile.inputs)
    .map(bundledPackageName)
    .filter((name) => name !== null),
)].sort();
const declaredBundledPackages = [astroMetadata.name, typescriptMetadata.name].sort();
if (JSON.stringify(bundledPackages) !== JSON.stringify(declaredBundledPackages)) {
  throw new Error(`runtime package inventory does not match bundle inputs: bundle=${JSON.stringify(bundledPackages)}, declared=${JSON.stringify(declaredBundledPackages)}`);
}

const packageEntry = (metadata, roles) => ({
  name: metadata.name,
  version: metadata.version,
  license: typeof metadata.license === "string" ? metadata.license : "license metadata unavailable",
  roles,
});
const runtimePackages = [
  packageEntry(astroMetadata, ["bundle", "runtime-artifact"]),
  packageEntry(typescriptMetadata, ["bundle"]),
  packageEntry(platformMetadata, ["runtime-component"]),
].sort((left, right) => left.name.localeCompare(right.name) || left.version.localeCompare(right.version));
await writeFile(
  new URL("../dist/runtime-packages.json", import.meta.url),
  `${JSON.stringify({ schema_version: 1, packages: runtimePackages }, null, 2)}\n`,
  "utf8",
);
