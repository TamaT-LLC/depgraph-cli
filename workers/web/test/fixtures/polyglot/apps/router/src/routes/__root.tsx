import { createRootRoute } from "@tanstack/react-router";

export function RootComponent() {
  return null;
}

export const rootLoader = () => ({ viewer: "fixture" });
export const rootBeforeLoad = () => ({ role: "reader" });

export const Route = createRootRoute({
  component: RootComponent,
  loader: rootLoader,
  beforeLoad: rootBeforeLoad,
  context: rootLoader,
});
