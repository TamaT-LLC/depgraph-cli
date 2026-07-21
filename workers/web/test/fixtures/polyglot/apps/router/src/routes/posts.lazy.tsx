import { createLazyFileRoute } from "@tanstack/react-router";

export function PostsLazyComponent() {
  return null;
}

export const Route = createLazyFileRoute("/posts")({
  component: PostsLazyComponent,
});
