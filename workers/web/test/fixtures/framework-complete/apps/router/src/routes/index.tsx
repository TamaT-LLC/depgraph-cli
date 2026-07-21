import { createFileRoute } from "@tanstack/react-router";

export function RouterHome(): null {
  return null;
}

export const Route = createFileRoute("/")({ component: RouterHome });
