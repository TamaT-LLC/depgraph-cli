import { createRequire } from "node:module";
import { writeFile } from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";
import {
  NEXT_BUILD_OBSERVER,
  NextBuildObserverError,
  composeNextBuildObserver,
  type NextAdapterLike,
} from "./next-build-observer";

const outputRoot = process.env.DEPGRAPH_OUTPUT_DIR;
if (outputRoot === undefined || !path.isAbsolute(outputRoot)) {
  throw new NextBuildObserverError("web.next_build_output_root_invalid");
}

async function loadExistingAdapter(): Promise<NextAdapterLike | null> {
  const specifier = process.env.DEPGRAPH_NEXT_EXISTING_ADAPTER;
  if (specifier === undefined || specifier.length === 0) return null;
  let resolved: string;
  try {
    const require = createRequire(path.join(process.cwd(), "package.json"));
    resolved = require.resolve(specifier);
  } catch {
    throw new NextBuildObserverError("web.next_build_existing_adapter_load_failed");
  }
  try {
    const loaded: unknown = await import(pathToFileURL(resolved).href);
    const candidate = loaded !== null && typeof loaded === "object" && "default" in loaded
      ? (loaded as { default: unknown }).default
      : loaded;
    return candidate as NextAdapterLike;
  } catch {
    throw new NextBuildObserverError("web.next_build_existing_adapter_load_failed");
  }
}

const observationPath = path.join(outputRoot, "next-build-observation.json");
const adapter = composeNextBuildObserver(await loadExistingAdapter(), {
  async write(observation) {
    const encoded = `${JSON.stringify(observation)}\n`;
    await writeFile(observationPath, encoded, { encoding: "utf8", flag: "wx", mode: 0o600 });
  },
});

if (!adapter.name.startsWith(NEXT_BUILD_OBSERVER)) {
  throw new NextBuildObserverError("web.next_build_adapter_identity_invalid");
}

export default adapter;
