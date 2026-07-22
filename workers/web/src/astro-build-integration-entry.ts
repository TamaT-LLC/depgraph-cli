import { writeFile } from "node:fs/promises";
import path from "node:path";
import {
  ASTRO_BUILD_OBSERVER,
  AstroBuildObserverError,
  createAstroBuildObserverIntegration,
  type AstroBuildObserverOptions,
} from "./astro-build-observer";

export interface BundledAstroBuildObserverOptions {
  astroVersion?: string;
  repoRoot?: string;
  dynamicConfigDetected?: boolean;
  existingIntegrations?: AstroBuildObserverOptions["existingIntegrations"];
  existingVitePlugins?: AstroBuildObserverOptions["existingVitePlugins"];
  timeoutMs?: number;
}

export default function depgraphAstroBuildObserver(
  options: BundledAstroBuildObserverOptions = {},
) {
  const outputRoot = process.env.DEPGRAPH_OUTPUT_DIR;
  if (outputRoot === undefined || !path.isAbsolute(outputRoot)) {
    throw new AstroBuildObserverError("web.astro_build_output_root_invalid");
  }
  const astroVersion = options.astroVersion ?? process.env.DEPGRAPH_ASTRO_VERSION;
  if (astroVersion === undefined) {
    throw new AstroBuildObserverError("web.astro_build_version_unavailable");
  }
  const observationPath = path.join(outputRoot, "astro-build-observation.json");
  const integration = createAstroBuildObserverIntegration({
    astroVersion,
    repoRoot: options.repoRoot ?? process.cwd(),
    ...(options.existingIntegrations === undefined ? {} : { existingIntegrations: options.existingIntegrations }),
    ...(options.existingVitePlugins === undefined ? {} : { existingVitePlugins: options.existingVitePlugins }),
    ...(options.dynamicConfigDetected === undefined ? {} : { dynamicConfigDetected: options.dynamicConfigDetected }),
    ...(options.timeoutMs === undefined ? {} : { timeoutMs: options.timeoutMs }),
    sink: {
      async write(observation) {
        await writeFile(observationPath, `${JSON.stringify(observation)}\n`, {
          encoding: "utf8",
          flag: "wx",
          mode: 0o600,
        });
      },
    },
  });
  if (integration.name !== ASTRO_BUILD_OBSERVER) {
    throw new AstroBuildObserverError("web.astro_build_integration_identity_invalid");
  }
  return integration;
}
