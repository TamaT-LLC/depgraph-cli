import { createFileRoute } from "@tanstack/react-router";

export function PublicPage() {
  return null;
}

export const Route = createFileRoute("/public")({ component: PublicPage });
