#!/usr/bin/env node
// Copy this file to a repository-relative path named by
// package.json depgraph.build.entrypoint. depgraph launches it as
// `node <entrypoint>` with no extra arguments and sets DEPGRAPH_OBSERVER
// (and NEXT_ADAPTER_PATH to the same path for Next).
//
// Next.js 16.2+ loads that adapter automatically from NEXT_ADAPTER_PATH.
// Do not call modifyConfig / onBuildComplete here; Next invokes those hooks
// during `next build`. This script only starts the real build and inherits
// its exit code.
import { spawn } from "node:child_process";
import path from "node:path";

const observerPath = process.env.DEPGRAPH_OBSERVER;
if (!observerPath || observerPath !== process.env.NEXT_ADAPTER_PATH) {
  console.error("DEPGRAPH_OBSERVER and NEXT_ADAPTER_PATH must be set and equal");
  process.exit(1);
}

const nextCli = path.join("node_modules", "next", "dist", "bin", "next");
const child = spawn(process.execPath, [nextCli, "build"], {
  stdio: "inherit",
  env: process.env,
});
child.on("error", (error) => {
  console.error(error);
  process.exit(1);
});
child.on("exit", (code, signal) => {
  if (signal) {
    process.kill(process.pid, signal);
    return;
  }
  process.exit(code ?? 1);
});
