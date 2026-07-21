import { createFileRoute } from "@tanstack/react-router";
import { getAccount } from "../server/account";
import { accountRouteMiddleware } from "../server/middleware";

export function AccountPage() {
  void getAccount({ data: { accountId: "fixture" } });
  return null;
}

export const Route = createFileRoute("/account/$accountId")({
  component: AccountPage,
  loader: () => getAccount({ data: { accountId: "fixture" } }),
  server: { middleware: [accountRouteMiddleware] },
});
