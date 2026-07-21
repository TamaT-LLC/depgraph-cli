import { createRootRouteWithContext } from "@tanstack/react-router";
import { rootAuditMiddleware, rootMiddleware } from "../server/middleware";

export function StartHome() {
  return null;
}

export const Route = createRootRouteWithContext<{ requestId: string }>()({
  component: StartHome,
  server: { middleware: [rootMiddleware, rootAuditMiddleware] },
});
