import { createRootRoute, createRoute } from "@tanstack/react-router";

const dynamicRoot = createRootRoute();
const alphaRoute = createRoute({ getParentRoute: () => dynamicRoot, path: "alpha" });
const betaRoute = createRoute({ getParentRoute: () => dynamicRoot, path: "beta" });
declare const chooseAlpha: boolean;
declare const runtimeRoutes: Array<typeof alphaRoute>;

dynamicRoot.addChildren([chooseAlpha ? alphaRoute : betaRoute]);
dynamicRoot.addChildren(runtimeRoutes.map((route) => route));
