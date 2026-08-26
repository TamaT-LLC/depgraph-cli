import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const execute = promisify(execFile);
const qualityScript = fileURLToPath(new URL("../scripts/quality.mjs", import.meta.url));
const fallowBin = fileURLToPath(import.meta.resolve("fallow/bin/fallow"));

interface CommandResult {
  code: number;
  stdout: string;
  stderr: string;
}

async function command(
  args: readonly string[],
  options: { cwd: string; env?: NodeJS.ProcessEnv },
): Promise<CommandResult> {
  try {
    const result = await execute(process.execPath, [...args], {
      cwd: options.cwd,
      env: options.env,
      encoding: "utf8",
      maxBuffer: 8 * 1024 * 1024,
    });
    return { code: 0, stdout: result.stdout, stderr: result.stderr };
  } catch (error) {
    const failure = error as Error & { code?: number; stdout?: string; stderr?: string };
    return {
      code: typeof failure.code === "number" ? failure.code : 1,
      stdout: failure.stdout ?? "",
      stderr: failure.stderr ?? failure.message,
    };
  }
}

async function createQualityFixture(): Promise<{
  root: string;
  config: string;
  baselines: string;
  runQuality: () => Promise<CommandResult>;
}> {
  const root = await mkdtemp(path.join(tmpdir(), "depgraph-web-quality-"));
  const source = path.join(root, "src");
  const baselines = path.join(root, "fallow-baselines");
  await mkdir(source);
  await mkdir(baselines);
  await mkdir(path.join(root, "node_modules"));
  await writeFile(path.join(root, "package.json"), `${JSON.stringify({ type: "module" }, null, 2)}\n`);
  await writeFile(path.join(source, "index.ts"), "export const baselineValue = 1;\n");
  await writeFile(
    path.join(root, "biome.json"),
    `${JSON.stringify(
      {
        files: { includes: ["src/**/*.ts"] },
        formatter: { enabled: false },
        linter: { enabled: true, rules: { preset: "recommended" } },
      },
      null,
      2,
    )}\n`,
  );
  const config = path.join(root, ".fallowrc.json");
  await writeFile(
    config,
    `${JSON.stringify(
      {
        entry: ["src/index.ts"],
        rules: {
          "unused-files": "off",
          "unused-exports": "off",
          "unused-types": "off",
          "unused-dependencies": "off",
          "unused-dev-dependencies": "off",
          "unlisted-dependencies": "off",
          "duplicate-exports": "off",
          "unresolved-imports": "error",
          "circular-dependencies": "error",
        },
        duplicates: {
          minTokens: 20,
          minLines: 4,
        },
        health: {
          maxCyclomatic: 3,
          maxCognitive: 3,
          maxCrap: 0,
          maxUnitSize: 200,
        },
      },
      null,
      2,
    )}\n`,
  );

  for (const [analysis, baseline, extra] of [
    ["dupes", "dupes.json", []],
    ["health", "health.json", ["--complexity", "--baseline-mode", "identity"]],
  ] as const) {
    const result = await command(
      [
        fallowBin,
        analysis,
        "--root",
        root,
        "--config",
        config,
        "--production",
        ...extra,
        "--save-baseline",
        path.join(baselines, baseline),
        "--format",
        "json",
        "--quiet",
      ],
      { cwd: root },
    );
    assert.equal(result.code, 0, result.stderr || result.stdout);
  }

  return {
    root,
    config,
    baselines,
    runQuality: () =>
      command([qualityScript], {
        cwd: root,
        env: {
          ...process.env,
          DEPGRAPH_WEB_QUALITY_ROOT: root,
          DEPGRAPH_WEB_FALLOW_CONFIG: config,
          DEPGRAPH_WEB_FALLOW_BASELINES: baselines,
        },
      }),
  };
}

test("quality rejects formatting drift in the checked scope", async () => {
  const fixture = await createQualityFixture();
  try {
    await writeFile(
      path.join(fixture.root, "biome.json"),
      `${JSON.stringify(
        {
          files: { includes: ["src/**/*.ts"] },
          formatter: { enabled: true },
          linter: { enabled: true, rules: { preset: "recommended" } },
        },
        null,
        2,
      )}\n`,
    );
    await writeFile(path.join(fixture.root, "src/index.ts"), "export const baselineValue={ value:1 };\n");
    const result = await fixture.runQuality();
    assert.equal(result.code, 1, result.stdout + result.stderr);
    assert.match(result.stdout + result.stderr, /Biome lint and format failed/u);
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("quality rejects a new unresolved import", async () => {
  const fixture = await createQualityFixture();
  try {
    await writeFile(
      path.join(fixture.root, "src/index.ts"),
      'import { missing } from "./missing";\nexport const baselineValue = missing;\n',
    );
    const result = await fixture.runQuality();
    assert.equal(result.code, 1, result.stdout + result.stderr);
    assert.match(result.stdout + result.stderr, /Fallow import graph failed/u);
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("quality rejects a new circular dependency", async () => {
  const fixture = await createQualityFixture();
  try {
    await writeFile(
      path.join(fixture.root, "src/index.ts"),
      'import { fromA } from "./a";\nexport const baselineValue = fromA();\n',
    );
    await writeFile(
      path.join(fixture.root, "src/a.ts"),
      'import { fromB } from "./b";\nexport function fromA(): number { return fromB() + 1; }\n',
    );
    await writeFile(
      path.join(fixture.root, "src/b.ts"),
      'import { fromA } from "./a";\nexport function fromB(): number { return fromA() + 1; }\n',
    );
    const result = await fixture.runQuality();
    assert.equal(result.code, 1, result.stdout + result.stderr);
    assert.match(result.stdout + result.stderr, /Fallow import graph failed/u);
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("quality rejects duplication beyond the saved baseline", async () => {
  const fixture = await createQualityFixture();
  const duplicate = `export function normalize(value: number): number {
  const doubled = value * 2;
  const shifted = doubled + 3;
  const clamped = Math.max(0, shifted);
  return clamped;
}
`;
  try {
    await writeFile(
      path.join(fixture.root, "src/index.ts"),
      'import { normalize as left } from "./left";\nimport { normalize as right } from "./right";\nexport const baselineValue = left(1) + right(2);\n',
    );
    await writeFile(path.join(fixture.root, "src/left.ts"), duplicate);
    await writeFile(path.join(fixture.root, "src/right.ts"), duplicate);
    const result = await fixture.runQuality();
    assert.equal(result.code, 1, result.stdout + result.stderr);
    assert.match(result.stdout + result.stderr, /Fallow duplication regression failed/u);
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("quality rejects complexity beyond the saved baseline", async () => {
  const fixture = await createQualityFixture();
  try {
    await writeFile(
      path.join(fixture.root, "src/index.ts"),
      `export function decide(first: boolean, second: boolean, third: boolean, fourth: boolean): number {
  let result = 0;
  if (first) result += 1;
  if (second) result += 2;
  if (third) result += 3;
  if (fourth) result += 4;
  return result;
}
`,
    );
    const result = await fixture.runQuality();
    assert.equal(result.code, 1, result.stdout + result.stderr);
    assert.match(result.stdout + result.stderr, /Fallow complexity regression failed/u);
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});
