import { createRootRoute, createRoute } from "@tanstack/react-router";

export function CodeRootComponent() {
  return null;
}

export function CodeChildComponent() {
  return null;
}

export const codeLoader = () => ({ code: true });
export const codeBeforeLoad = () => ({ code: "allowed" });

const rootRoute = createRootRoute({ component: CodeRootComponent });
const codeChild = createRoute({
  getParentRoute: () => rootRoute,
  path: "code",
  component: CodeChildComponent,
  loader: codeLoader,
  beforeLoad: codeBeforeLoad,
});

// This declaration deliberately never participates in addChildren and must not
// become an actual route node.
const orphanRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "orphan",
  component: CodeChildComponent,
});

export const routeTree = rootRoute.addChildren([codeChild]);
export const retainedForTypeChecking = orphanRoute;
