import assert from "node:assert/strict";
import { readFile, readdir } from "node:fs/promises";
import path from "node:path";
import { test } from "node:test";
import { scanTypeScriptSyntaxTokens } from "../src/imports";

const SOURCE_DIRECTORY = new URL("../src/", import.meta.url);
const EXTRACTION_MODULE = "typescript-dependencies.ts";
const VALIDATION_MODULE = "typescript-dependency-validation.ts";
const CONTRACT_MODULE = "typescript-dependency-contract.ts";

function staticRelativeSpecifiers(source: string): string[] {
  const tokens = scanTypeScriptSyntaxTokens(source);
  const specifiers = new Set<string>();
  for (let index = 0; index < tokens.length; index += 1) {
    const keyword = tokens[index]?.text;
    if (keyword !== "import" && keyword !== "export") continue;
    if (tokens[index + 1]?.text === "(") continue;
    if (tokens[index + 1]?.text === "type") continue;
    const direct = tokens[index + 1];
    if (keyword === "import" && (direct?.text.startsWith("\"") || direct?.text.startsWith("'"))) {
      if (direct.value.startsWith(".")) specifiers.add(direct.value);
      continue;
    }
    for (let cursor = index + 1; cursor < tokens.length && tokens[cursor]?.text !== ";"; cursor += 1) {
      const token = tokens[cursor];
      if (token?.value.startsWith(".") && (
        tokens[cursor - 1]?.text === "from"
        || tokens[cursor - 1]?.text === "("
          && tokens[cursor - 2]?.text === "require"
      )) {
        specifiers.add(token.value);
        break;
      }
    }
  }
  return [...specifiers].sort();
}

function resolvedSourceModule(
  importer: string,
  specifier: string,
  sourceModules: ReadonlySet<string>,
): string | null {
  const base = path.posix.normalize(path.posix.join(path.posix.dirname(importer), specifier));
  for (const candidate of [base, `${base}.ts`, path.posix.join(base, "index.ts")]) {
    if (sourceModules.has(candidate)) return candidate;
  }
  return null;
}

function cycleFrom(
  graph: ReadonlyMap<string, ReadonlySet<string>>,
  start: string,
): string[] | null {
  const explored = new Set<string>();
  const visit = (current: string, pathToCurrent: readonly string[]): string[] | null => {
    if (explored.has(current)) return null;
    const pathSet = new Set(pathToCurrent);
    for (const dependency of graph.get(current) ?? []) {
      if (dependency === start) return [...pathToCurrent, current, start];
      if (pathSet.has(dependency)) continue;
      const cycle = visit(dependency, [...pathToCurrent, current]);
      if (cycle !== null) return cycle;
    }
    explored.add(current);
    return null;
  };
  return visit(start, []);
}

test("TypeScript dependency extraction and validation imports stay acyclic", async () => {
  const sourceModules = new Set(
    (await readdir(SOURCE_DIRECTORY, { recursive: true }))
      .filter((entry) => entry.endsWith(".ts"))
      .map((entry) => entry.split(path.sep).join(path.posix.sep))
      .sort(),
  );
  const graph = new Map<string, Set<string>>();
  for (const module of sourceModules) {
    const source = await readFile(new URL(module, SOURCE_DIRECTORY), "utf8");
    const dependencies = new Set<string>();
    for (const specifier of staticRelativeSpecifiers(source)) {
      const resolved = resolvedSourceModule(module, specifier, sourceModules);
      if (resolved !== null) dependencies.add(resolved);
    }
    graph.set(module, dependencies);
  }

  const extractionImports = graph.get(EXTRACTION_MODULE);
  const validationImports = graph.get(VALIDATION_MODULE);
  assert.ok(extractionImports?.has(CONTRACT_MODULE), "extraction must use the neutral dependency contract");
  assert.ok(validationImports?.has(CONTRACT_MODULE), "validation must use the neutral dependency contract");
  assert.equal(
    extractionImports?.has(VALIDATION_MODULE) && validationImports?.has(EXTRACTION_MODULE),
    false,
    "extraction and validation must not import each other",
  );
  for (const module of [EXTRACTION_MODULE, VALIDATION_MODULE]) {
    const cycle = cycleFrom(graph, module);
    assert.equal(cycle, null, `production import cycle: ${cycle?.join(" -> ")}`);
  }
});
