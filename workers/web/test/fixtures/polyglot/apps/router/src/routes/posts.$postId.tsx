import { createFileRoute, createRouteMask, Link, useNavigate } from "@tanstack/react-router";

export function PostComponent() {
  const navigate = useNavigate();
  navigate({ to: "/posts/$postId", mask: { to: "/posts" } });
  return <Link to="/posts/$postId" mask={{ to: "/posts" }}>post</Link>;
}

export const postLoader = () => ({ id: "fixture" });
export const postBeforeLoad = () => ({ allowed: true });

export const postMask = createRouteMask({
  from: "/posts/$postId",
  to: "/posts",
});

export const Route = createFileRoute("/posts/$postId")({
  component: PostComponent,
  loader: postLoader,
  beforeLoad: postBeforeLoad,
});
