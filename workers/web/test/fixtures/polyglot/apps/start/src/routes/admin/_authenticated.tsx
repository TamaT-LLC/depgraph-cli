import { createFileRoute } from "@tanstack/react-router";
import { adminMiddleware } from "../../server/middleware";

export const Route = createFileRoute("/admin")({
  server: { middleware: [adminMiddleware] },
});
