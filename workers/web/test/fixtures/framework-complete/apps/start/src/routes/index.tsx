import { createFileRoute } from "@tanstack/react-router";

export function StartHome(): null {
  return null;
}

export const Route = createFileRoute("/")({ component: StartHome });
