import { writeFile } from "node:fs/promises";
import path from "node:path";
import {
  TANSTACK_ROUTER_BUILD_OBSERVER,
  TanStackRouterBuildObserverError,
  createTanStackRouterBuildObserverPlugin,
  type TanStackRouterObserverOptions,
} from "./tanstack-router-build-observer";

export interface BundledTanStackRouterObserverOptions {
  routerVersion?: string;
  repoRoot?: string;
  generatedRouteTree?: string | null;
  routesDirectory?: string;
  basePath?: string;
  existingVitePlugins?: TanStackRouterObserverOptions["existingVitePlugins"];
  timeoutMs?: number;
}

export default function depgraphTanStackRouterBuildObserver(
  options: BundledTanStackRouterObserverOptions = {},
) {
  const outputRoot = process.env.DEPGRAPH_OUTPUT_DIR;
  if (outputRoot === undefined || !path.isAbsolute(outputRoot)) {
    throw new TanStackRouterBuildObserverError("web.tanstack_router_build_output_root_invalid");
  }
  const routerVersion = options.routerVersion ?? process.env.DEPGRAPH_TANSTACK_ROUTER_VERSION;
  if (routerVersion === undefined) {
    throw new TanStackRouterBuildObserverError("web.tanstack_router_build_version_unavailable");
  }
  const observationPath = path.join(outputRoot, "tanstack-router-build-observation.json");
  const plugin = createTanStackRouterBuildObserverPlugin({
    routerVersion,
    repoRoot: options.repoRoot ?? process.cwd(),
    ...(options.generatedRouteTree === undefined ? {} : { generatedRouteTree: options.generatedRouteTree }),
    ...(options.routesDirectory === undefined ? {} : { routesDirectory: options.routesDirectory }),
    ...(options.basePath === undefined ? {} : { basePath: options.basePath }),
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
  if (plugin.name !== TANSTACK_ROUTER_BUILD_OBSERVER) {
    throw new TanStackRouterBuildObserverError("web.tanstack_router_build_plugin_identity_invalid");
  }
  return plugin;
}
