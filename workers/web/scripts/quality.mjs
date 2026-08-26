import { spawn } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const qualityRoot = path.resolve(process.env.DEPGRAPH_WEB_QUALITY_ROOT ?? packageRoot);
const fallowConfig = path.resolve(
  process.env.DEPGRAPH_WEB_FALLOW_CONFIG ?? path.join(qualityRoot, ".fallowrc.jsonc"),
);
const baselineDirectory = path.resolve(
  process.env.DEPGRAPH_WEB_FALLOW_BASELINES ?? path.join(qualityRoot, "fallow-baselines"),
);
const biomeBin = path.join(
  path.dirname(fileURLToPath(import.meta.resolve("@biomejs/biome/package.json"))),
  "bin",
  "biome",
);
const fallowBin = fileURLToPath(import.meta.resolve("fallow/bin/fallow"));

const gates = [
  {
    name: "Biome lint",
    executable: biomeBin,
    args: ["lint", ".", "--diagnostic-level=error"],
  },
  {
    name: "Fallow import graph",
    executable: fallowBin,
    captureJson: "import-graph",
    args: [
      "dead-code",
      "--root", qualityRoot,
      "--config", fallowConfig,
      "--production",
      "--summary",
      "--format", "json",
      "--quiet",
    ],
  },
  {
    name: "Fallow duplication regression",
    executable: fallowBin,
    args: [
      "dupes",
      "--root", qualityRoot,
      "--config", fallowConfig,
      "--production",
      "--baseline", path.join(baselineDirectory, "dupes.json"),
      // A baseline-filtered report has 0% duplication. This smallest
      // practical positive ceiling therefore rejects every new clone group.
      "--threshold", "0.000001",
      "--format", "compact",
      "--quiet",
    ],
  },
  {
    name: "Fallow complexity regression",
    executable: fallowBin,
    args: [
      "health",
      "--root", qualityRoot,
      "--config", fallowConfig,
      "--production",
      "--complexity",
      "--baseline", path.join(baselineDirectory, "health.json"),
      "--baseline-mode", "identity",
      "--fail-on-issues",
      "--format", "compact",
      "--quiet",
    ],
  },
];

function parseJson(value) {
  try {
    return JSON.parse(value);
  } catch {
    return null;
  }
}

function renderCapturedFallback(captured) {
  if (captured.length > 0) process.stderr.write(captured);
}

function renderImportSummary(report) {
  const { entry_points: entryPoints, summary } = report;
  process.stdout.write(
    `[quality] import graph: ${entryPoints.total} entries, `
    + `${summary.unused_files} unused files, `
    + `${summary.unresolved_imports} unresolved imports, `
    + `${summary.circular_dependencies} cycles\n`,
  );
}

function renderUnresolvedImports(report) {
  for (const issue of report.unresolved_imports) {
    process.stderr.write(`${issue.path}:${issue.line} unresolved ${issue.specifier}\n`);
  }
}

function renderCircularDependencies(report) {
  for (const cycle of report.circular_dependencies) {
    process.stderr.write(`circular dependency: ${JSON.stringify(cycle)}\n`);
  }
}

function importGraphFailed(summary) {
  return [summary.unused_files, summary.unresolved_imports, summary.circular_dependencies]
    .some((count) => count > 0);
}

function renderImportGraph(captured) {
  const report = parseJson(captured);
  if (report === null) {
    renderCapturedFallback(captured);
    return true;
  }
  if (report.error === true) {
    process.stderr.write(`${report.message ?? captured}\n`);
    return true;
  }
  renderImportSummary(report);
  renderUnresolvedImports(report);
  renderCircularDependencies(report);
  return importGraphFailed(report.summary);
}

function renderCapturedReport(gate, captured) {
  return gate.captureJson === "import-graph" && renderImportGraph(captured);
}

function effectiveStatus(code, reportFailed) {
  if (reportFailed && code === 0) return 1;
  if (code === null) return 1;
  return code;
}

function runGate(gate) {
  return new Promise((resolve, reject) => {
    process.stdout.write(`\n[quality] ${gate.name}\n`);
    let captured = "";
    const child = spawn(process.execPath, [gate.executable, ...gate.args], {
      cwd: qualityRoot,
      env: process.env,
      stdio: ["inherit", gate.captureJson ? "pipe" : "inherit", "inherit"],
    });
    child.stdout?.setEncoding("utf8");
    child.stdout?.on("data", (chunk) => {
      captured += chunk;
    });
    child.once("error", reject);
    child.once("exit", (code, signal) => {
      if (signal !== null) {
        reject(new Error(`${gate.name} terminated by ${signal}`));
        return;
      }
      const reportFailed = renderCapturedReport(gate, captured);
      resolve(effectiveStatus(code, reportFailed));
    });
  });
}

for (const gate of gates) {
  const status = await runGate(gate);
  if (status !== 0) {
    process.stderr.write(`[quality] ${gate.name} failed with exit code ${status}\n`);
    process.exitCode = status;
    break;
  }
}
