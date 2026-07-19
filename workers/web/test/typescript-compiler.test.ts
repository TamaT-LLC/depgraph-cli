import assert from "node:assert/strict";
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import {
  analyzeTypeScriptProject,
  analyzeTypeScriptProjectWithRuntimeForTest,
  exerciseTypeScriptCompilerLifecycleForTest,
  isConfinedTypeScriptInputPath,
  TYPESCRIPT_COMPILER_PROFILE_PROPERTIES,
  TypeScriptProjectError,
  type TypeScriptAnalysisTestRuntime,
} from "../src/typescript-compiler";

async function fakeCompilerRuntime(
  context: { after(callback: () => Promise<void>): void },
  body: string,
  timeoutMs: number,
): Promise<{ runtime: TypeScriptAnalysisTestRuntime; marker: string }> {
  const root = await mkdtemp(path.join(os.tmpdir(), "depgraph-typescript-failure-"));
  context.after(async () => rm(root, { recursive: true, force: true }));
  const compilerRoot = path.join(root, "lib");
  const compiler = path.join(compilerRoot, "tsc");
  const marker = path.join(root, "compiler.pid");
  await mkdir(compilerRoot, { recursive: true });
  await Promise.all([
    writeFile(path.join(compilerRoot, "lib.es5.d.ts"), "interface String {}\n"),
    writeFile(path.join(compilerRoot, "lib.esnext.full.d.ts"), "/// <reference no-default-lib=\"true\"/>\n"),
    writeFile(compiler, `#!${process.execPath}\nrequire("node:fs").writeFileSync(${JSON.stringify(marker)}, String(process.pid));\n${body}\n`),
  ]);
  await chmod(compiler, 0o755);
  return {
    runtime: { compiler, standardLibraryRoot: compilerRoot, timeoutMs },
    marker,
  };
}

async function assertCompilerReaped(marker: string): Promise<void> {
  const pid = Number(await readFile(marker, "utf8"));
  assert.ok(Number.isSafeInteger(pid) && pid > 0);
  await new Promise((resolve) => setTimeout(resolve, 25));
  assert.throws(
    () => process.kill(pid, 0),
    (error: unknown) => (
      error instanceof Error
      && "code" in error
      && error.code === "ESRCH"
    ),
  );
}

test("TypeScript virtual filesystem rejects POSIX, drive, UNC, and traversal paths", () => {
  for (const unsafe of [
    "/absolute.ts",
    "../escape.ts",
    "nested/../../escape.ts",
    "C:\\secret.ts",
    "C:/secret.ts",
    "C:drive-relative.ts",
    "\\\\server\\share\\secret.ts",
    "//server/share/secret.ts",
    "nested/./file.ts",
    "nested//file.ts",
    "nul\0file.ts",
  ]) {
    assert.equal(isConfinedTypeScriptInputPath(unsafe), false, unsafe);
  }
  assert.equal(isConfinedTypeScriptInputPath("packages/app/src/index.ts"), true);
});

test("TypeChecker smoke remains valid for empty and declaration-free projects", async () => {
  const cases = [
    new Map<string, string>(),
    new Map([["comment-only.ts", "// intentionally no declarations\n"]]),
    new Map([["module.ts", "export {};\n"]]),
  ];
  for (const sources of cases) {
    const analysis = await analyzeTypeScriptProject(sources);
    assert.equal(analysis.project.status, "ready");
    assert.equal(analysis.project.rootFiles, sources.size);
    // Declaration-free projects need only the intrinsic TypeChecker smoke
    // query; export-proof reads are demand-driven by dependency occurrences.
    assert.equal(analysis.project.typeCheckerQueries, 1);
    assert.ok(analysis.project.standardLibraryFiles > 0);
    assert.equal(analysis.project.emittedSemanticDiagnostics, analysis.semanticDiagnostics.length);
  }
});

test("project analysis carries the cumulative exact-call capability and call validation ledger", async () => {
  const analysis = await analyzeTypeScriptProject(new Map([
    ["valid.ts", [
      "export function direct(): void {}",
      "direct();",
      "class Constructed {}",
      "new Constructed();",
      "function tag(strings: TemplateStringsArray): string { return strings[0] ?? \"\"; }",
      "tag`value`;",
      "const require = (value: string): string => value;",
      "require(\"./shadowed\");",
      "void import(\"./module\");",
      "",
    ].join("\n")],
    ["broken.ts", "export function broken(): void { broken( }\n"],
  ]));

  assert.equal(TYPESCRIPT_COMPILER_PROFILE_PROPERTIES.typescript_analysis_mode, "semantic-import-type-call-graph");
  assert.equal(TYPESCRIPT_COMPILER_PROFILE_PROPERTIES.typescript_typechecker_status, "definition-import-type-call-graph-emitted");
  assert.equal(TYPESCRIPT_COMPILER_PROFILE_PROPERTIES.typescript_semantic_graph_emission, "definition-import-type-call-graph-v1");
  assert.deepEqual(
    analysis.callSpans.get("valid.ts")?.map(({ occurrenceKind, specifier }) => ({ occurrenceKind, specifier })),
    [
      { occurrenceKind: "call_expression", specifier: "direct" },
      { occurrenceKind: "new_expression", specifier: "Constructed" },
      { occurrenceKind: "tagged_template", specifier: "tag" },
      { occurrenceKind: "call_expression", specifier: "require" },
    ],
  );
  assert.deepEqual(
    analysis.callSpans.get("broken.ts")?.map(({ occurrenceKind, specifier }) => ({ occurrenceKind, specifier })),
    [{ occurrenceKind: "call_expression", specifier: "broken" }],
  );
  assert.ok((analysis.get("broken.ts")?.length ?? 0) > 0);
  assert.equal(analysis.project.semanticCallSites, analysis.dependencyGraph.calls.length);
  assert.equal(
    analysis.project.semanticSites,
    analysis.dependencyGraph.sites.length + analysis.dependencyGraph.calls.length,
  );
});

test("import-type candidate detection stays bounded on repeated comments", { timeout: 3_000 }, async () => {
  const source = `import ${"/*x*/".repeat(1_000)}x;\n`;
  const analysis = await analyzeTypeScriptProject(new Map([["comments.ts", source]]));
  assert.equal(analysis.project.status, "ready");
  assert.ok((analysis.get("comments.ts")?.length ?? 0) > 0);
});

test("missing standard library I/O is classified as stdlib_unavailable", async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "depgraph-typescript-missing-stdlib-"));
  context.after(async () => rm(root, { recursive: true, force: true }));
  await assert.rejects(
    analyzeTypeScriptProjectWithRuntimeForTest(
      new Map([[
        "index.ts",
        "export const value = true;\n",
      ]]),
      {
        compiler: process.execPath,
        standardLibraryRoot: path.join(root, "missing"),
        timeoutMs: 1_000,
      },
    ),
    (error: unknown) => (
      error instanceof TypeScriptProjectError
      && error.reason === "stdlib_unavailable"
    ),
  );
});

test("cross-platform compiler lifecycle failures are classified and reap the child", async () => {
  for (const [mode, reason] of [
    ["crash", "compiler_protocol_failure"],
    ["protocol-error", "compiler_protocol_failure"],
    ["timeout", "compiler_timeout"],
    ["strict-close", "compiler_protocol_failure"],
  ] as const) {
    const started = Date.now();
    const result = await exerciseTypeScriptCompilerLifecycleForTest(mode);
    assert.equal(result.reason, reason, mode);
    assert.equal(result.reaped, true, mode);
    assert.equal(result.listenersDisposed, true, mode);
    assert.ok(Date.now() - started < 3_000, `${mode} was not detected promptly`);
  }
});

test("native compiler crash and malformed IPC fail promptly and reap the child", {
  skip: process.platform === "win32",
}, async (context) => {
  for (const fixture of [
    { name: "crash", body: "process.exit(17);" },
    {
      name: "malformed",
      body: 'process.stdout.write("Content-Length: nope\\r\\n\\r\\n"); setInterval(() => undefined, 1_000);',
    },
  ]) {
    const { runtime, marker } = await fakeCompilerRuntime(context, fixture.body, 5_000);
    const started = Date.now();
    await assert.rejects(
      analyzeTypeScriptProjectWithRuntimeForTest(new Map([["index.ts", "export const value = 1;\n"]]), runtime),
      (error: unknown) => (
        error instanceof TypeScriptProjectError
        && error.reason === "compiler_protocol_failure"
      ),
      fixture.name,
    );
    assert.ok(Date.now() - started < 3_000, `${fixture.name} was not detected promptly`);
    await assertCompilerReaped(marker);
  }
});

test("native compiler internal timeout fails closed and reaps the child", {
  skip: process.platform === "win32",
}, async (context) => {
  const { runtime, marker } = await fakeCompilerRuntime(
    context,
    "setInterval(() => undefined, 1_000);",
    500,
  );
  await assert.rejects(
    analyzeTypeScriptProjectWithRuntimeForTest(new Map([["index.ts", "export const value = 1;\n"]]), runtime),
    (error: unknown) => (
      error instanceof TypeScriptProjectError
      && error.reason === "compiler_timeout"
    ),
  );
  await assertCompilerReaped(marker);
});
