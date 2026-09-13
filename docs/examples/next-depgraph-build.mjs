#!/usr/bin/env node
// Copy this file to a repository-relative path named by
// package.json depgraph.build.entrypoint. depgraph launches it as
// `node <entrypoint>` with no extra arguments.
import { spawn } from "node:child_process";
import path from "node:path";

const nextCli = path.join("node_modules", "next", "dist", "bin", "next");
const child = spawn(process.execPath, [nextCli, "build"], {
  stdio: "inherit",
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
