import { createServerFn } from "@tanstack/react-start";
import { auditMiddleware, authMiddleware } from "./middleware";

export const validateAccount = (input: { accountId: string }) => input;

export async function accountHandler({ data }: { data: { accountId: string } }) {
  return { accountId: data.accountId, name: "fixture" };
}

export const getAccount = createServerFn({ method: "GET" })
  .validator(validateAccount)
  .middleware([authMiddleware, auditMiddleware])
  .handler(accountHandler);
