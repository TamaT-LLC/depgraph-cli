import { createFileRoute } from "@tanstack/react-router";
import { authMiddleware, pathlessAuditMiddleware } from "../server/middleware";

export const Route = createFileRoute("/_authenticated")({
  server: { middleware: [authMiddleware, pathlessAuditMiddleware] },
});
