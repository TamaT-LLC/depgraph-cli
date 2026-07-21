import { createFileRoute } from "@tanstack/react-router";
import { rootMiddleware } from "../server/middleware";

export function StartHome() {
  return null;
}

export const Route = createFileRoute("/")({
  component: StartHome,
  server: { middleware: [rootMiddleware] },
});
