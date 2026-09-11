import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { promisify } from "node:util";
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

test("definition source limits exclude retained context ASTs", async () => {
  const sources = new Map([
    ["entry.ts", "export const value = 1;\n"],
    ["context.ts", "export const context = 2;\n"],
    ["other-context.ts", "export const other = 3;\n"],
  ]);
  const runtime = { maxDefinitionSourceFiles: 1 };
  const analysis = await analyzeTypeScriptProjectWithRuntimeForTest(sources, runtime, {
    astPaths: new Set(sources.keys()),
    definitionPaths: new Set(["entry.ts", "missing.ts"]),
    sourcePaths: new Set(["entry.ts"]),
  });
  assert.equal(analysis.astRetainedSourceFiles, 3);
  assert.equal(analysis.definitionGraph.issues.some((issue) => issue.fatal), false);
  assert.ok(analysis.definitionGraph.definitions.length > 0);
  assert.ok(analysis.definitionGraph.definitions.every((definition) => definition.relativePath === "entry.ts"));
  assert.deepEqual([...analysis.semanticSourceFiles.keys()], ["entry.ts"]);

  const oversized = await analyzeTypeScriptProjectWithRuntimeForTest(sources, runtime, {
    astPaths: new Set(sources.keys()),
    definitionPaths: new Set(["entry.ts", "context.ts"]),
  });
  const issue = oversized.definitionGraph.issues.find((entry) => entry.code === "typescript_semantic_source_limit_exceeded");
  assert.equal(issue?.fatal, true);
  assert.match(issue!.message, /received 2 sources; limit=1/u);
  assert.equal(oversized.astRetainedSourceFiles, 0);
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
  assert.equal(TYPESCRIPT_COMPILER_PROFILE_PROPERTIES.typescript_semantic_graph_emission, "definition-import-type-call-graph-v2");
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
    1_500,
  );
  await assert.rejects(
    analyzeTypeScriptProjectWithRuntimeForTest(new Map([["index.ts", "export const value = 1;\n"]]), runtime),
    (error: unknown) => (
      error instanceof TypeScriptProjectError
      && error.reason === "compiler_timeout"
      && error.exitCode === 124
    ),
  );
  await assertCompilerReaped(marker);
});

test("compiler timeout stops queued filesystem replies before terminating IPC", {
  skip: process.platform === "win32",
}, async (context) => {
  const { runtime, marker } = await fakeCompilerRuntime(context, `
    const path = require("node:path");
    let input = Buffer.alloc(0);
    let id = 0;
    function send(message) {
      const json = JSON.stringify(message);
      process.stdout.write("Content-Length: " + Buffer.byteLength(json) + "\\r\\n\\r\\n" + json);
    }
    process.stdin.on("data", (chunk) => {
      input = Buffer.concat([input, chunk]);
      for (;;) {
        const boundary = input.indexOf("\\r\\n\\r\\n");
        if (boundary < 0) return;
        const length = Number(/Content-Length: (\\d+)/i.exec(input.subarray(0, boundary).toString())[1]);
        if (input.length < boundary + 4 + length) return;
        const message = JSON.parse(input.subarray(boundary + 4, boundary + 4 + length).toString());
        input = input.subarray(boundary + 4 + length);
        if (message.method === "initialize") {
          send({ jsonrpc: "2.0", id: message.id, result: {
            useCaseSensitiveFileNames: true, currentDirectory: path.parse(process.execPath).root
          } });
        } else if (message.method === "updateSnapshot") {
          const config = message.params.openProjects[0];
          send({ jsonrpc: "2.0", id: message.id, result: { snapshot: "active-snapshot", projects: [{
            id: "project", configFileName: config, compilerOptions: {},
            rootFiles: [path.join(path.dirname(config), "index.ts")]
          }] } });
          pump();
        }
      }
    });
    function pump() {
      const frames = Array.from({ length: 128 }, () => {
        const message = JSON.stringify({ jsonrpc: "2.0", id: ++id, method: "readFile", params: ["/missing.ts"] });
        return "Content-Length: " + Buffer.byteLength(message) + "\\r\\n\\r\\n" + message;
      }).join("");
      process.stdout.write(frames, () => setImmediate(pump));
    }
  `, 1_500);
  const payload = "x".repeat(256 * 1024);
  const program = `
    import { analyzeTypeScriptProjectWithRuntimeForTest, TypeScriptProjectError }
      from ${JSON.stringify(new URL("../src/typescript-compiler.ts", import.meta.url).href)};
    import { exitWorkerAfterFlushing }
      from ${JSON.stringify(new URL("../src/worker-exit.ts", import.meta.url).href)};
    try {
      await analyzeTypeScriptProjectWithRuntimeForTest(new Map([["index.ts", "export const value = 1;\\n"]]), ${JSON.stringify(runtime)});
      throw new Error("compiler timeout was not detected");
    } catch (error) {
      if (!(error instanceof TypeScriptProjectError) || error.reason !== "compiler_timeout") throw error;
      process.stdout.write(JSON.stringify({ reason: error.reason, payload: "x".repeat(256 * 1024) }) + "\\n");
      process.stderr.write("compiler timeout classified\\n");
      await exitWorkerAfterFlushing(error.exitCode);
    }
  `;
  await assert.rejects(promisify(execFile)(process.execPath, [
    "--import", import.meta.resolve("tsx"), "--input-type=module", "--eval", program,
  ], { timeout: 10_000, maxBuffer: 1024 * 1024 }), (error: unknown) => {
    const failure = error as { code?: number; stdout?: string; stderr?: string };
    assert.equal(failure.code, 124);
    assert.deepEqual(JSON.parse(failure.stdout ?? ""), { reason: "compiler_timeout", payload });
    assert.equal(failure.stderr, "compiler timeout classified\n");
    return true;
  });
  await assertCompilerReaped(marker);
});
