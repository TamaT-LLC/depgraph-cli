import { writeFile } from "node:fs/promises";
import path from "node:path";
import {
  TANSTACK_START_BUILD_OBSERVER,
  TanStackStartBuildObserverError,
  createTanStackStartBuildObserverPlugin,
  type TanStackStartObserverOptions,
} from "./tanstack-start-build-observer";

export interface BundledTanStackStartObserverOptions {
  startVersion?: string;
  repoRoot?: string;
  providerEnvironmentName?: string;
  existingVitePlugins?: TanStackStartObserverOptions["existingVitePlugins"];
  timeoutMs?: number;
}

export default function depgraphTanStackStartBuildObserver(
  options: BundledTanStackStartObserverOptions = {},
) {
  const outputRoot = process.env.DEPGRAPH_OUTPUT_DIR;
  if (outputRoot === undefined || !path.isAbsolute(outputRoot)) {
    throw new TanStackStartBuildObserverError("web.tanstack_start_build_output_root_invalid");
  }
  const startVersion = options.startVersion ?? process.env.DEPGRAPH_TANSTACK_START_VERSION;
  if (startVersion === undefined) {
    throw new TanStackStartBuildObserverError("web.tanstack_start_build_version_unavailable");
  }
  const observationPath = path.join(outputRoot, "tanstack-start-build-observation.json");
  const plugin = createTanStackStartBuildObserverPlugin({
    startVersion,
    repoRoot: options.repoRoot ?? process.cwd(),
    ...(options.providerEnvironmentName === undefined ? {} : { providerEnvironmentName: options.providerEnvironmentName }),
    ...(options.existingVitePlugins === undefined ? {} : { existingVitePlugins: options.existingVitePlugins }),
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
  if (plugin.name !== TANSTACK_START_BUILD_OBSERVER) {
    throw new TanStackStartBuildObserverError("web.tanstack_start_build_plugin_identity_invalid");
  }
  return plugin;
}
