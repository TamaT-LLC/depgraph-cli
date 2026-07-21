import { createMiddleware } from "@tanstack/react-start";

export const rootMiddleware = createMiddleware({ type: "request" }).server(async ({ next }) => next());
export const authMiddleware = createMiddleware({ type: "function" }).server(async ({ next }) => next());
export const auditMiddleware = createMiddleware({ type: "function" }).server(async ({ next }) => next());
export const accountRouteMiddleware = createMiddleware({ type: "request" }).server(async ({ next }) => next());
export const adminMiddleware = createMiddleware({ type: "request" }).server(async ({ next }) => next());
