import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import {
  API,
  type Checker,
  type Symbol as CompilerSymbol,
  type Type as CompilerType,
} from "typescript/unstable/async";
import { SyntaxKind, type Node } from "typescript/unstable/ast";
import type { FileSystem, FileSystemEntries } from "typescript/unstable/fs";
import { buildTypeScriptDependencyValidationSources, scan } from "../src/scanner";
import { analyzeTypeScriptProject, resolveTypeScriptCompiler } from "../src/typescript-compiler";
import {
  extractTypeScriptRawDefinitionDelta,
  TYPESCRIPT_SEMANTIC_MAX_SOURCE_FILES,
  type TypeScriptRawDefinitionDelta,
  type TypeScriptRawTypeArgumentDescriptor,
  type TypeScriptSemanticSource,
  validateTypeScriptRawDefinitionDelta,
} from "../src/typescript-semantic";
import {
  callValidationSpans,
  extractTypeScriptRawDependencyDelta,
  importTypeModuleValidationSpans,
  moduleCallValidationSpans,
  nonLiteralModuleValidationSpans,
  typeUseValidationSpans,
  validateTypeScriptRawDependencyDelta,
  type TypeScriptDependencyValidationSource,
  type TypeScriptRawDependencyDelta,
} from "../src/typescript-dependencies";

function pathKey(value: string): string {
  const normalized = path.normalize(path.resolve(value));
  return process.platform === "win32" ? normalized.toLowerCase() : normalized;
}

function testFileSystem(files: ReadonlyMap<string, string>): FileSystem {
  const content = new Map<string, string>();
  const directories = new Map<string, { path: string; files: Set<string>; directories: Set<string> }>();
  const ensureDirectory = (directory: string): void => {
    let current = path.resolve(directory);
    for (;;) {
      const key = pathKey(current);
      if (!directories.has(key)) directories.set(key, { path: current, files: new Set(), directories: new Set() });
      const parent = path.dirname(current);
      if (parent === current) break;
      const parentKey = pathKey(parent);
      if (!directories.has(parentKey)) directories.set(parentKey, { path: parent, files: new Set(), directories: new Set() });
      directories.get(parentKey)!.directories.add(path.basename(current));
      current = parent;
    }
  };
  for (const [file, source] of files) {
    const absolute = path.resolve(file);
    content.set(pathKey(absolute), source);
    const directory = path.dirname(absolute);
    ensureDirectory(directory);
    directories.get(pathKey(directory))!.files.add(path.basename(absolute));
  }
  return {
    readFile: (fileName): string | null => content.get(pathKey(fileName)) ?? null,
    fileExists: (fileName): boolean => content.has(pathKey(fileName)),
    directoryExists: (directoryName): boolean => directories.has(pathKey(directoryName)),
    getAccessibleEntries: (directoryName): FileSystemEntries => {
      const directory = directories.get(pathKey(directoryName));
      return {
        files: directory ? [...directory.files].sort() : [],
        directories: directory ? [...directory.directories].sort() : [],
      };
    },
    realpath: (fileName): string => path.normalize(path.resolve(fileName)),
  };
}

async function extractFixture(
  sources: Readonly<Record<string, string>>,
  virtualRootName: string,
  options: {
    transformChecker?: (checker: Checker) => Checker;
    transformSources?: (sources: TypeScriptSemanticSource[]) => TypeScriptSemanticSource[];
  } = {},
): Promise<TypeScriptRawDefinitionDelta> {
  const compiler = await resolveTypeScriptCompiler();
  const virtualRoot = path.join(path.parse(process.execPath).root, virtualRootName);
  const config = path.join(virtualRoot, "tsconfig.json");
  const virtualFiles = new Map<string, string>();
  for (const [relativePath, source] of Object.entries(sources)) {
    virtualFiles.set(path.join(virtualRoot, ...relativePath.split("/")), source);
  }
  virtualFiles.set(config, `${JSON.stringify({
    compilerOptions: {
      allowJs: true,
      checkJs: false,
      jsx: "preserve",
      module: "preserve",
      moduleDetection: "force",
      moduleResolution: "bundler",
      noEmit: true,
      noLib: true,
      target: "esnext",
    },
    files: Object.keys(sources).sort(),
  })}\n`);
  const api = new API({
    cwd: path.parse(process.execPath).root,
    fs: testFileSystem(virtualFiles),
    tsserverPath: compiler,
  });
  const snapshot = await api.updateSnapshot({ openProjects: [config] });
  try {
    const project = snapshot.getProjects()[0];
    assert.ok(project);
    const inputs: TypeScriptSemanticSource[] = [];
    for (const relativePath of Object.keys(sources).sort()) {
      const virtualPath = path.join(virtualRoot, ...relativePath.split("/"));
      const sourceFile = await project.program.getSourceFile(virtualPath);
      assert.ok(sourceFile);
      const diagnostics = await project.program.getSyntacticDiagnostics(virtualPath);
      inputs.push({
        relativePath,
        compilerPath: virtualPath,
        expectedText: sources[relativePath]!,
        sourceFile,
        syntacticallyValid: diagnostics.length === 0,
      });
    }
    return await extractTypeScriptRawDefinitionDelta(
      options.transformChecker?.(project.checker) ?? project.checker,
      options.transformSources?.(inputs) ?? inputs,
    );
  } finally {
    await snapshot.dispose();
    await api.close();
  }
}

async function extractDependencyFixture(
  sources: Readonly<Record<string, string>>,
  virtualRootName: string,
  transformDependencyChecker?: (checker: Checker) => Checker,
  transformDependencySources?: (sources: TypeScriptSemanticSource[]) => TypeScriptSemanticSource[],
): Promise<{
  definitions: TypeScriptRawDefinitionDelta;
  dependencies: TypeScriptRawDependencyDelta;
  dependencyValidationSources: TypeScriptDependencyValidationSource[];
}> {
  const compiler = await resolveTypeScriptCompiler();
  const virtualRoot = path.join(path.parse(process.execPath).root, virtualRootName);
  const config = path.join(virtualRoot, "tsconfig.json");
  const virtualFiles = new Map<string, string>();
  for (const [relativePath, source] of Object.entries(sources)) {
    virtualFiles.set(path.join(virtualRoot, ...relativePath.split("/")), source);
  }
  virtualFiles.set(config, `${JSON.stringify({
    compilerOptions: {
      allowJs: true,
      checkJs: false,
      jsx: "preserve",
      module: "preserve",
      moduleDetection: "force",
      noEmit: true,
      noLib: true,
      target: "esnext",
    },
    files: Object.keys(sources).sort(),
  })}\n`);
  const api = new API({
    cwd: path.parse(process.execPath).root,
    fs: testFileSystem(virtualFiles),
    tsserverPath: compiler,
  });
  const snapshot = await api.updateSnapshot({ openProjects: [config] });
  try {
    const project = snapshot.getProjects()[0];
    assert.ok(project);
    const inputs: TypeScriptSemanticSource[] = [];
    for (const relativePath of Object.keys(sources).sort()) {
      const virtualPath = path.join(virtualRoot, ...relativePath.split("/"));
      const sourceFile = await project.program.getSourceFile(virtualPath);
      assert.ok(sourceFile);
      const diagnostics = await project.program.getSyntacticDiagnostics(virtualPath);
      inputs.push({
        relativePath,
        compilerPath: virtualPath,
        expectedText: sources[relativePath]!,
        sourceFile,
        syntacticallyValid: diagnostics.length === 0,
      });
    }
    const dependencyInputs = transformDependencySources?.(inputs) ?? inputs;
    const definitions = await extractTypeScriptRawDefinitionDelta(project.checker, inputs);
    const dependencies = await extractTypeScriptRawDependencyDelta(
      transformDependencyChecker?.(project.checker) ?? project.checker,
      dependencyInputs,
      definitions,
      definitions.typeCheckerQueries,
    );
    const dependencyValidationQueryBudget = { value: 0 };
    const dependencyValidationSources: TypeScriptDependencyValidationSource[] = [];
    for (const source of dependencyInputs) {
      dependencyValidationSources.push({
        relativePath: source.relativePath,
        text: source.expectedText,
        syntacticallyValid: source.syntacticallyValid,
        importTypeModuleSpans: source.syntacticallyValid
          ? importTypeModuleValidationSpans(source.sourceFile)
          : [],
        moduleCallSpans: source.syntacticallyValid
          ? await moduleCallValidationSpans(
            project.checker,
            source.sourceFile,
            dependencyValidationQueryBudget,
          )
          : [],
        nonLiteralModuleSpans: source.syntacticallyValid
          ? nonLiteralModuleValidationSpans(source.sourceFile)
          : [],
        typeUseSpans: source.syntacticallyValid
          ? await typeUseValidationSpans(
            project.checker,
            source.sourceFile,
            dependencyValidationQueryBudget,
          )
          : [],
        callSpans: await callValidationSpans(
          project.checker,
          source.sourceFile,
          dependencyValidationQueryBudget,
          source.syntacticallyValid,
        ),
      });
    }
    return { definitions, dependencies, dependencyValidationSources };
  } finally {
    await snapshot.dispose();
    await api.close();
  }
}

function validationSources(sources: Readonly<Record<string, string>>): TypeScriptSemanticSource[] {
  return Object.entries(sources).map(([relativePath, source]) => ({
    relativePath,
    compilerPath: path.resolve("/__depgraph_validation__", relativePath),
    expectedText: source,
    sourceFile: { text: source } as TypeScriptSemanticSource["sourceFile"],
    syntacticallyValid: true,
  }));
}

function transformCheckerBatches(
  checker: Checker,
  transforms: {
    symbols?: (nodes: readonly Node[], values: (CompilerSymbol | undefined)[]) => (CompilerSymbol | undefined)[];
    types?: (nodes: readonly Node[], values: (CompilerType | undefined)[]) => (CompilerType | undefined)[];
  },
): Checker {
  const querySymbol = checker.getSymbolAtLocation.bind(checker);
  const queryType = checker.getTypeAtLocation.bind(checker);
  return new Proxy(checker, {
    get(target, property, receiver): unknown {
      if (property === "getSymbolAtLocation") {
        return async (input: Node | readonly Node[]): Promise<CompilerSymbol | undefined | (CompilerSymbol | undefined)[]> => {
          if (Array.isArray(input)) {
            const nodes = input as readonly Node[];
            const values = await querySymbol(nodes);
            return transforms.symbols?.(nodes, values) ?? values;
          }
          return await querySymbol(input as Node);
        };
      }
      if (property === "getTypeAtLocation") {
        return async (input: Node | readonly Node[]): Promise<CompilerType | undefined | (CompilerType | undefined)[]> => {
          if (Array.isArray(input)) {
            const nodes = input as readonly Node[];
            const values = await queryType(nodes);
            return transforms.types?.(nodes, values) ?? values;
          }
          return await queryType(input as Node);
        };
      }
      const value = Reflect.get(target, property, receiver) as unknown;
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
}

function reverseAlternatingModuleExportResponses(checker: Checker): Checker {
  const queryExports = checker.getExportsOfModule.bind(checker);
  let calls = 0;
  return new Proxy(checker, {
    get(target, property, receiver): unknown {
      if (property === "getExportsOfModule") {
        return async (symbol: CompilerSymbol): Promise<CompilerSymbol[]> => {
          const values = await queryExports(symbol);
          calls += 1;
          return calls % 2 === 0 ? [...values].reverse() : [...values];
        };
      }
      const value = Reflect.get(target, property, receiver) as unknown;
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
}

const definitionFixture = `
class Parent<T> {}
interface Contract<T> {}
class Service<T> extends Parent<T> implements Contract<T> {
  constructor(readonly value: T) {}
  run(input: T): T {
    const local = (next: T) => next;
    return local(input);
  }
}
type ServiceContract<T> = Contract<T>;
enum State { Ready, Stopped }
function top<T>(input: T): T {
  function nested(value: T): T { return value; }
  return nested(input);
}
const exported = <T,>(input: T): T => input;
`;

function literalValidationDelta(
  descriptor: TypeScriptRawTypeArgumentDescriptor,
): Pick<TypeScriptRawDefinitionDelta, "definitions" | "relations"> {
  const relativePath = "src/literal.ts";
  const originResolver = `definition:${JSON.stringify(["module", "type", relativePath, ["Base"]])}`;
  const originKey = `definition:${JSON.stringify(["type", "class", null, originResolver, null])}`;
  const instanceResolver = `generic:${JSON.stringify([originKey, [descriptor]])}`;
  const instanceKey = `definition:${JSON.stringify(["type", "generic_instance", null, instanceResolver, null])}`;
  const origin = {
    key: originKey,
    graphKind: "type" as const,
    semanticKind: "class",
    language: "typescript" as const,
    resolverIdentity: originResolver,
    identityKind: null,
    displayName: "Base",
    relativePath,
    startOffset: 0,
    endOffset: 16,
    owner: { kind: "file" as const, relativePath },
  };
  const instance = {
    ...origin,
    key: instanceKey,
    semanticKind: "generic_instance",
    resolverIdentity: instanceResolver,
    displayName: "Base<literal>",
    owner: { kind: "definition" as const, key: originKey },
    genericOrigin: originKey,
    typeArguments: [descriptor],
  };
  const evidence = { relativePath, startOffset: 0, endOffset: 16, detail: "TypeChecker fixture" };
  return {
    definitions: [origin, instance].sort((left, right) => left.key < right.key ? -1 : left.key > right.key ? 1 : 0),
    relations: [
      { kind: "declares", source: { kind: "file", relativePath }, target: originKey, evidence },
      { kind: "instantiates", source: { kind: "definition", key: originKey }, target: instanceKey, evidence },
    ],
  };
}

test("extracts compiler-confirmed definitions and definition relations", async () => {
  const delta = await extractFixture({ "src/index.ts": definitionFixture }, "__depgraph_ts_semantic_graph__");
  assert.equal(delta.issues.some((item) => item.fatal), false, JSON.stringify(delta.issues));
  assert.ok(delta.typeCheckerQueries > 0);
  const kinds = new Set(delta.definitions.map((definition) => `${definition.graphKind}:${definition.semanticKind}`));
  for (const expected of [
    "type:class",
    "type:interface",
    "type:type_alias",
    "type:enum",
    "type:generic_instance",
    "symbol:constructor",
    "symbol:method",
    "symbol:function",
    "symbol:local_function",
    "symbol:function_variable",
    "symbol:local_function_variable",
    "symbol:anonymous_function",
  ]) assert.ok(kinds.has(expected), expected);

  const relationKinds = new Set(delta.relations.map((relation) => relation.kind));
  assert.deepEqual(relationKinds, new Set(["declares", "extends", "implements", "instantiates"]));
  const instances = delta.definitions.filter((definition) => definition.semanticKind === "generic_instance");
  assert.equal(instances.length, 2);
  assert.ok(instances.every((definition) => (
    definition.genericOrigin !== undefined
    && definition.typeArguments?.length === 1
    && definition.typeArguments[0]?.kind === "type_parameter"
  )));
  assert.ok(delta.definitions.every((definition) => !definition.key.includes("__depgraph_ts_semantic_graph__")));
  assert.ok(delta.definitions.every((definition) => !definition.resolverIdentity?.includes("__depgraph_ts_semantic_graph__")));
});

test("raw definition delta is deterministic across checkout-equivalent virtual roots", async () => {
  const first = await extractFixture({ "src/index.ts": definitionFixture }, "__depgraph_ts_semantic_repeat_a__");
  const second = await extractFixture({ "src/index.ts": definitionFixture }, "__depgraph_ts_semantic_repeat_b__");
  assert.deepEqual(first, second);
});

test("syntactically invalid sources and unresolved heritage do not fabricate definitions", async () => {
  const invalid = await extractFixture(
    { "src/broken.ts": "class Broken extends Missing { method( { }\n" },
    "__depgraph_ts_semantic_invalid__",
  );
  assert.deepEqual(invalid.definitions, []);
  assert.deepEqual(invalid.relations, []);
  assert.ok(invalid.issues.some((item) => item.code === "typescript_semantic_syntax_invalid"));

  const unresolved = await extractFixture(
    { "src/unresolved.ts": "class Local extends Missing {}\n" },
    "__depgraph_ts_semantic_unresolved__",
  );
  assert.deepEqual(unresolved.definitions.map((definition) => definition.displayName), ["Local"]);
  assert.equal(unresolved.relations.some((relation) => relation.kind === "extends"), false);
  assert.ok(unresolved.issues.some((item) => item.code === "typescript_semantic_heritage_target_skipped"));
});

test("constructor signature query stays on its strict SyntaxKind path", async () => {
  const delta = await extractFixture(
    { "src/constructor.ts": "class Constructed { constructor(value: string) {} }\n" },
    "__depgraph_ts_semantic_constructor__",
  );
  assert.equal(delta.issues.some((item) => item.fatal), false, JSON.stringify(delta.issues));
  assert.ok(delta.definitions.some((definition) => definition.semanticKind === "constructor"));
});

test("JavaScript and JSX definitions retain their source language", async () => {
  const delta = await extractFixture(
    {
      "src/module.js": "export function fromJavaScript(value) { return value; }\nexport class JavaScriptClass {}\n",
      "src/view.jsx": "export function View() { return <main />; }\n",
    },
    "__depgraph_ts_semantic_javascript__",
  );
  assert.equal(delta.issues.some((item) => item.fatal), false, JSON.stringify(delta.issues));
  assert.deepEqual(
    Object.fromEntries(delta.definitions
      .filter((definition) => ["fromJavaScript", "JavaScriptClass", "View"].includes(definition.displayName))
      .map((definition) => [definition.displayName, definition.language])),
    { fromJavaScript: "javascript", JavaScriptClass: "javascript", View: "javascript" },
  );
});

test("block-scoped definitions cannot collide or create local symbols with file/type owners", async () => {
  const delta = await extractFixture(
    {
      "src/blocks.ts": `
{ class Local {} }
{ class Local {} }
class Holder {
  field = function namedInField() {};
  static { function namedInStaticBlock() {} }
}
(function namedAtFileScope() {})();
`,
    },
    "__depgraph_ts_semantic_block_scope__",
  );
  assert.equal(delta.issues.some((item) => item.fatal), false, JSON.stringify(delta.issues));
  const locals = delta.definitions.filter((definition) => definition.displayName === "Local");
  assert.equal(locals.length, 2);
  assert.equal(new Set(locals.map((definition) => definition.key)).size, 2);
  const definitions = new Map(delta.definitions.map((definition) => [definition.key, definition]));
  const holder = delta.definitions.find((definition) => definition.displayName === "Holder");
  assert.ok(holder);
  for (const displayName of ["namedInField", "namedInStaticBlock", "namedAtFileScope"]) {
    const definition = delta.definitions.find((item) => item.displayName === displayName);
    assert.ok(definition, displayName);
    assert.equal(definition.semanticKind, "anonymous_function");
    assert.equal(definition.identityKind, "anonymous");
    assert.ok(definition.endOffset > definition.startOffset);
    assert.deepEqual(
      definition.owner,
      displayName === "namedAtFileScope"
        ? { kind: "file", relativePath: "src/blocks.ts" }
        : { kind: "definition", key: holder.key },
    );
  }
  for (const definition of delta.definitions.filter((item) => item.identityKind === "local")) {
    assert.equal(definition.owner.kind, "definition");
    assert.equal(definitions.get((definition.owner as { kind: "definition"; key: string }).key)?.graphKind, "symbol");
  }
});

test("nested and delimiter-bearing generic arguments produce distinct canonical instances", async () => {
  const delta = await extractFixture(
    {
      "src/generics.ts": `
class Base<T> {}
interface Box<T> { value: T }
interface Marker { marker: true }
class Pair<A, B> {}
class StringBox extends Base<Box<string>> {}
class NumberBox extends Base<Box<number>> {}
class UnionBox extends Base<Box<string> | Box<number>> {}
class IntersectionBox extends Base<Box<string> & Marker> {}
class CommaLeft extends Pair<"a,b", "c"> {}
class CommaRight extends Pair<"a", "b,c"> {}
`,
    },
    "__depgraph_ts_semantic_nested_generics__",
  );
  assert.equal(delta.issues.some((item) => item.fatal), false, JSON.stringify(delta.issues));
  const base = delta.definitions.find((definition) => definition.displayName === "Base");
  const pair = delta.definitions.find((definition) => definition.displayName === "Pair");
  assert.ok(base);
  assert.ok(pair);
  const baseInstances = delta.definitions.filter((definition) => definition.genericOrigin === base.key);
  const pairInstances = delta.definitions.filter((definition) => definition.genericOrigin === pair.key);
  assert.equal(baseInstances.length, 4, JSON.stringify(delta.issues));
  assert.equal(pairInstances.length, 2, JSON.stringify(delta.issues));
  assert.equal(new Set(baseInstances.map((definition) => definition.resolverIdentity)).size, 4);
  assert.equal(new Set(pairInstances.map((definition) => definition.resolverIdentity)).size, 2);
  assert.ok(baseInstances.some((definition) => definition.typeArguments?.[0]?.kind === "application"));
  assert.ok(baseInstances.some((definition) => definition.typeArguments?.[0]?.kind === "union"));
  assert.ok(baseInstances.some((definition) => definition.typeArguments?.[0]?.kind === "intersection"));
});

test("structured resolvers separate namespace paths, quoted members, and escaped member names", async () => {
  const delta = await extractFixture(
    {
      "src/resolvers.ts": `
export class C {
  static "D.foo"() {}
  static 'quote"\\\\name'() {}
}
export namespace C {
  export class D { static foo() {} }
}
`,
    },
    "__depgraph_ts_semantic_structured_resolvers__",
  );
  assert.equal(delta.issues.some((item) => item.fatal), false, JSON.stringify(delta.issues));
  const methods = delta.definitions.filter((definition) => definition.semanticKind === "method");
  assert.deepEqual(new Set(methods.map((definition) => definition.displayName)), new Set(["D.foo", "quote\"\\name", "foo"]));
  assert.equal(new Set(methods.map((definition) => definition.resolverIdentity)).size, methods.length);
  assert.ok(methods.every((definition) => definition.resolverIdentity?.startsWith("definition:[\"member\"") === true));
});

test("type and value declarations sharing one compiler Symbol remain separate graph definitions", async () => {
  const delta = await extractFixture(
    {
      "src/merged.ts": `
export interface Foo { value: string }
export function Foo(): Foo { return { value: "ok" }; }
`,
    },
    "__depgraph_ts_semantic_type_value_symbol__",
  );
  assert.equal(delta.issues.some((item) => item.fatal), false, JSON.stringify(delta.issues));
  const foo = delta.definitions.filter((definition) => definition.displayName === "Foo");
  assert.deepEqual(new Set(foo.map((definition) => `${definition.graphKind}:${definition.semanticKind}`)), new Set([
    "type:interface",
    "symbol:function",
  ]));
  assert.equal(new Set(foo.map((definition) => definition.resolverIdentity)).size, 2);
});

test("TypeChecker batch cardinality failures atomically discard semantic definitions", async () => {
  let corrupted = false;
  const delta = await extractFixture(
    { "src/batch.ts": "export class Alpha {}\nexport class Beta {}\n" },
    "__depgraph_ts_semantic_batch_cardinality__",
    {
      transformChecker: (checker) => transformCheckerBatches(checker, {
        symbols: (_nodes, values) => {
          if (corrupted) return values;
          corrupted = true;
          return [];
        },
      }),
    },
  );
  assert.deepEqual(delta.definitions, []);
  assert.deepEqual(delta.relations, []);
  assert.ok(delta.issues.some((item) => item.code === "typescript_semantic_typechecker_contract_violation" && item.fatal));
});

test("TypeChecker batch order spoofing is rejected by request correlation", async () => {
  let firstSymbol: CompilerSymbol | undefined;
  const delta = await extractFixture(
    { "src/order.ts": "export class Alpha {}\nexport class Beta {}\n" },
    "__depgraph_ts_semantic_batch_order__",
    {
      transformChecker: (checker) => transformCheckerBatches(checker, {
        symbols: (_nodes, values) => {
          if (firstSymbol === undefined) {
            firstSymbol = values[0];
            return values;
          }
          return [firstSymbol];
        },
      }),
    },
  );
  assert.deepEqual(delta.definitions, []);
  assert.deepEqual(delta.relations, []);
  assert.ok(delta.issues.some((item) => item.code === "typescript_semantic_typechecker_contract_violation" && item.fatal));
});

test("TypeChecker type-parameter symbols must correlate to their owner and index", async () => {
  let firstParameter: CompilerSymbol | undefined;
  const delta = await extractFixture(
    {
      "src/parameters.ts": `
class Base<T> {}
class Alpha<U> extends Base<U> {}
class Beta<V> extends Base<V> {}
`,
    },
    "__depgraph_ts_semantic_parameter_correlation__",
    {
      transformChecker: (checker) => transformCheckerBatches(checker, {
        symbols: (nodes, values) => {
          if (nodes[0]?.parent.kind !== SyntaxKind.TypeParameter) return values;
          if (firstParameter === undefined) {
            firstParameter = values[0];
            return values;
          }
          return [firstParameter];
        },
      }),
    },
  );
  assert.deepEqual(delta.definitions, []);
  assert.deepEqual(delta.relations, []);
  assert.ok(delta.issues.some((item) => item.code === "typescript_semantic_typechecker_contract_violation" && item.fatal));
});

test("TypeChecker type-argument response spoofing atomically discards generic identities", async () => {
  let firstPrimitive: CompilerType | undefined;
  const delta = await extractFixture(
    {
      "src/type-order.ts": `
class Pair<Left, Right> {}
class Child extends Pair<string, number> {}
`,
    },
    "__depgraph_ts_semantic_type_argument_order__",
    {
      transformChecker: (checker) => transformCheckerBatches(checker, {
        types: (nodes, values) => {
          const kind = nodes[0]?.kind;
          if (kind !== SyntaxKind.StringKeyword && kind !== SyntaxKind.NumberKeyword) return values;
          if (firstPrimitive === undefined) {
            firstPrimitive = values[0];
            return values;
          }
          return [firstPrimitive];
        },
      }),
    },
  );
  assert.deepEqual(delta.definitions, []);
  assert.deepEqual(delta.relations, []);
  assert.ok(delta.issues.some((item) => item.code === "typescript_semantic_typechecker_contract_violation" && item.fatal));
});

test("semantic AST path and bytes must match the confined inventory", async () => {
  const delta = await extractFixture(
    { "src/source.ts": "export class Inventory {}\n" },
    "__depgraph_ts_semantic_source_identity__",
    {
      transformSources: (sources) => sources.map((source) => ({
        ...source,
        expectedText: "export class Spoofed {}\n",
      })),
    },
  );
  assert.deepEqual(delta.definitions, []);
  assert.deepEqual(delta.relations, []);
  assert.ok(delta.issues.some((item) => item.code === "typescript_semantic_source_identity_mismatch" && item.fatal));
});

test("semantic AST traversal rejects excessive depth before querying TypeChecker", async () => {
  const compilerPath = path.resolve("/__depgraph_depth__", "src/deep.ts");
  let child: Node | undefined;
  for (let depth = 0; depth < 514; depth += 1) {
    const next = child;
    child = {
      kind: SyntaxKind.EmptyStatement,
      getStart: () => 0,
      getEnd: () => 0,
      forEachChild: (visitor: (node: Node) => unknown): unknown => next === undefined ? undefined : visitor(next),
    } as Node;
  }
  const nested = child!;
  const sourceFile = {
    kind: SyntaxKind.SourceFile,
    path: compilerPath,
    fileName: compilerPath,
    text: "",
    getStart: () => 0,
    getEnd: () => 0,
    forEachChild: (visitor: (node: Node) => unknown): unknown => visitor(nested),
  } as TypeScriptSemanticSource["sourceFile"];
  const delta = await extractTypeScriptRawDefinitionDelta({} as Checker, [{
    relativePath: "src/deep.ts",
    compilerPath,
    expectedText: "",
    sourceFile,
    syntacticallyValid: true,
  }]);
  assert.deepEqual(delta.definitions, []);
  assert.deepEqual(delta.relations, []);
  assert.ok(delta.issues.some((item) => item.code === "typescript_semantic_ast_depth_exceeded" && item.fatal));
  assert.equal(delta.typeCheckerQueries, 0);
});

test("fatal semantic issues survive a full nonfatal issue buffer and truncation", async () => {
  const compilerPath = path.resolve("/__depgraph_issue_cap__", "src/capped.ts");
  const emptyNode = (kind: SyntaxKind): Node => ({
    kind,
    getStart: () => 0,
    getEnd: () => 0,
    forEachChild: () => undefined,
  }) as unknown as Node;
  const noisyMethods = Array.from({ length: 1_000 }, () => ({
    ...emptyNode(SyntaxKind.MethodDeclaration),
    name: emptyNode(SyntaxKind.ComputedPropertyName),
    modifierFlags: 0,
  }) as Node);
  let child: Node | undefined;
  for (let depth = 0; depth < 514; depth += 1) {
    const next = child;
    child = {
      ...emptyNode(SyntaxKind.EmptyStatement),
      forEachChild: (visitor: (node: Node) => unknown): unknown => next === undefined ? undefined : visitor(next),
    } as Node;
  }
  const nested = child!;
  const sourceFile = {
    ...emptyNode(SyntaxKind.SourceFile),
    path: compilerPath,
    fileName: compilerPath,
    text: "",
    forEachChild: (visitor: (node: Node) => unknown): unknown => {
      for (const method of noisyMethods) visitor(method);
      return visitor(nested);
    },
  } as TypeScriptSemanticSource["sourceFile"];
  const delta = await extractTypeScriptRawDefinitionDelta({} as Checker, [{
    relativePath: "src/capped.ts",
    compilerPath,
    expectedText: "",
    sourceFile,
    syntacticallyValid: true,
  }]);
  assert.deepEqual(delta.definitions, []);
  assert.deepEqual(delta.relations, []);
  assert.ok(delta.issues.some((item) => item.code === "typescript_semantic_ast_depth_exceeded" && item.fatal));
  assert.ok(delta.issues.some((item) => item.code === "typescript_semantic_issues_truncated"));
  assert.equal(delta.issues.some((item) => item.fatal) ? "failed" : "ready", "failed");
  assert.ok(delta.issues.length <= 1_000);
});

test("shared cross-language generic instances are anchored to their origin", async () => {
  const sources = {
    "src/base.js": "/** @template T */\nexport class Base {}\n",
    "src/alpha.ts": "import { Base } from './base.js';\nexport class Alpha extends Base<string> {}\n",
    "src/beta.ts": "import { Base } from './base.js';\nexport class Beta extends Base<string> {}\n",
  };
  const delta = await extractFixture(sources, "__depgraph_ts_semantic_shared_cross_language__");
  assert.equal(delta.issues.some((item) => item.fatal), false, JSON.stringify(delta.issues));
  const origin = delta.definitions.find((definition) => definition.displayName === "Base");
  assert.ok(origin);
  const instances = delta.definitions.filter((definition) => definition.genericOrigin === origin.key);
  assert.equal(instances.length, 1);
  const instance = instances[0]!;
  assert.deepEqual(instance.owner, { kind: "definition", key: origin.key });
  assert.equal(instance.language, "javascript");
  assert.equal(instance.relativePath, origin.relativePath);
  assert.equal(instance.startOffset, origin.startOffset);
  assert.equal(instance.endOffset, origin.endOffset);
  assert.equal(delta.relations.filter((relation) => (
    relation.kind === "instantiates" && relation.target === instance.key
  )).length, 2);
});

test("definition ordering uses locale-independent code-unit order", async () => {
  const delta = await extractFixture(
    {
      "z.ts": "export class Same {}\n",
      "ä.ts": "export class Same {}\n",
    },
    "__depgraph_ts_semantic_locale_order__",
  );
  assert.equal(delta.issues.some((item) => item.fatal), false, JSON.stringify(delta.issues));
  assert.deepEqual(
    delta.definitions.filter((definition) => definition.displayName === "Same").map((definition) => definition.relativePath),
    ["z.ts", "ä.ts"],
  );
  assert.deepEqual(
    delta.definitions.map((definition) => definition.key),
    [...delta.definitions.map((definition) => definition.key)].sort((left, right) => left < right ? -1 : left > right ? 1 : 0),
  );
});

test("raw validator rejects unsorted and duplicate relations", async () => {
  const sources = { "src/index.ts": definitionFixture };
  const delta = await extractFixture(sources, "__depgraph_ts_semantic_relation_validation__");
  assert.ok(delta.relations.length > 2);
  assert.throws(() => validateTypeScriptRawDefinitionDelta(
    { definitions: delta.definitions, relations: [...delta.relations].reverse() },
    validationSources(sources),
  ), /strict canonical order/u);
  assert.throws(() => validateTypeScriptRawDefinitionDelta(
    { definitions: delta.definitions, relations: [delta.relations[0]!, delta.relations[0]!, ...delta.relations.slice(1)] },
    validationSources(sources),
  ), /strict canonical order/u);
  assert.throws(() => validateTypeScriptRawDefinitionDelta(
    { definitions: delta.definitions, relations: [...delta.relations, delta.relations[0]!] },
    validationSources(sources),
  ), /strict canonical order/u);
});

test("raw validator rejects incomplete generic instance metadata", async () => {
  const sources = {
    "src/generic.ts": "class Base<T> {}\nclass Child extends Base<string> {}\n",
  };
  const delta = await extractFixture(sources, "__depgraph_ts_semantic_incomplete_generic__");
  const generic = delta.definitions.find((definition) => definition.semanticKind === "generic_instance");
  assert.ok(generic);
  const definitions = delta.definitions.map((definition) => {
    if (definition.key !== generic.key) return definition;
    const { genericOrigin: _genericOrigin, typeArguments: _typeArguments, ...incomplete } = definition;
    return incomplete;
  });
  assert.throws(() => validateTypeScriptRawDefinitionDelta(
    { definitions, relations: delta.relations },
    validationSources(sources),
  ), /incomplete origin metadata/u);
});

test("raw validator accepts canonical negative zero and rejects non-finite or non-canonical numeric literals", () => {
  const sources = validationSources({ "src/literal.ts": "class Base<T> {}" });
  assert.doesNotThrow(() => validateTypeScriptRawDefinitionDelta(
    literalValidationDelta({ kind: "literal", valueKind: "number", value: "-0" }),
    sources,
  ));
  for (const descriptor of [
    { kind: "literal", valueKind: "number", value: "NaN" },
    { kind: "literal", valueKind: "number", value: "Infinity" },
    { kind: "literal", valueKind: "bigint", value: "01" },
    { kind: "literal", valueKind: "bigint", value: "-0" },
    { kind: "literal", valueKind: "string", value: "x\ud800" },
  ] as const) {
    assert.throws(
      () => validateTypeScriptRawDefinitionDelta(literalValidationDelta(descriptor), sources),
      /invalid literal/u,
    );
  }
});

test("raw validator rejects two definitions sharing one canonical resolver", () => {
  const sources = validationSources({ "src/literal.ts": "class Base<T> {}" });
  const delta = literalValidationDelta({ kind: "literal", valueKind: "number", value: "0" });
  const origin = delta.definitions.find((definition) => definition.semanticKind === "class")!;
  const duplicate = {
    ...origin,
    key: `definition:${JSON.stringify(["type", "interface", null, origin.resolverIdentity, null])}`,
    semanticKind: "interface",
  };
  assert.throws(() => validateTypeScriptRawDefinitionDelta(
    {
      definitions: [...delta.definitions, duplicate].sort((left, right) => left.key < right.key ? -1 : left.key > right.key ? 1 : 0),
      relations: delta.relations,
    },
    sources,
  ), /share canonical resolver/u);
});

test("raw source-count limit is exported for compiler preflight", () => {
  const sourceFile = { text: "" } as TypeScriptSemanticSource["sourceFile"];
  const oversized = Array.from(
    { length: TYPESCRIPT_SEMANTIC_MAX_SOURCE_FILES + 1 },
    (_, index): TypeScriptSemanticSource => ({
      relativePath: `src/generated-${index}.ts`,
      compilerPath: path.resolve("/__depgraph_oversized__", `src/generated-${index}.ts`),
      expectedText: "",
      sourceFile,
      syntacticallyValid: true,
    }),
  );
  assert.throws(() => validateTypeScriptRawDefinitionDelta(
    { definitions: [], relations: [] },
    oversized,
  ), /source inventory exceeds its limit/u);
});

test("dependency collector covers TS, JS, JSX, ESM, CJS, re-exports, and named type uses deterministically", async () => {
  const sources = {
    "src/cjs.ts": "const legacy = { value: 1 };\nexport = legacy;\n",
    "src/defs.ts": `
export interface Constraint { readonly id: string }
export interface SharedCollection<T> { readonly value: T }
export function named(): void {}
export const runtime = 1;
export default function defaultExport(): void {}
`,
    "src/doc.js": `
/** @type {import("./defs").SharedCollection<string>} */
export const documented = { value: "js" };
`,
    "src/external-order.ts": `
interface BeforeImports {
  readonly client: QueryClient;
  readonly widget: PackageNS.Widget;
}
import type { QueryClient } from "@tanstack/react-query";
import type * as PackageNS from "@scope/package";
`,
    "src/main.ts": `
import defaultBinding, { named as renamed, runtime, type Constraint as Bound, type SharedCollection } from "./defs";
import * as namespaceBinding from "./defs";
import "./side";
import legacy = require("./cjs");
export { named as forwarded } from "./defs";
export type { SharedCollection as PublicCollection } from "./defs";
export * as namespaceExport from "./defs";
export * from "./side";
const required = require("./side");
void import("./side");
class Derived<T extends Bound> implements SharedCollection<T> { value!: T }
interface Contract<T extends Bound> {
  field: SharedCollection<T>;
  call(value: SharedCollection<T>): Bound;
}
interface ImportedHolder { imported: import("./defs").SharedCollection<string> }
void defaultBinding;
void renamed;
void runtime;
void namespaceBinding;
void legacy;
void required;
`,
    "src/missing.ts": `
import { map } from "lodash";
import { absent } from "./does-not-exist";
import type { QueryClient } from "@tanstack/react-query";
interface UnknownHolder { readonly missing: MissingType }
interface PackageUse { readonly client: QueryClient }
void map;
void absent;
`,
    "src/side.ts": "export const side = true;\n",
    "src/shadow.ts": `
function require(value: string): string { return value }
export const localCall = require("./not-a-cjs-dependency");
`,
    "src/imported-require.ts": `
import require from "other-require";
export const importedCall = require("./not-a-cjs-dependency-either");
`,
    "src/namespace-shadow.ts": `
import type * as PackageNS from "@scope/package";
import type { Foo } from "@other/package";
function shadowed<PackageNS>(value: PackageNS.Foo): void { void value }
function valueShadow(PackageNS: unknown): void { type Local = PackageNS.Foo; void (0 as unknown as Local) }
type GenericShadow<T> = T.Foo;
`,
    "src/view.jsx": `
/** @type {import("./defs").SharedCollection<string>} */
const props = { value: "jsx" };
export const View = () => <section>{props.value}</section>;
`,
  };
  const first = await extractDependencyFixture(sources, "__depgraph_ts_dependency_complete_a__");
  const second = await extractDependencyFixture(sources, "__depgraph_ts_dependency_complete_z__");

  assert.deepEqual(first.dependencies, second.dependencies);
  assert.deepEqual(first.dependencies.issues, []);
  assert.doesNotThrow(() => validateTypeScriptRawDependencyDelta(
    first.dependencies,
    first.definitions,
    first.dependencyValidationSources,
  ));
  const sites = first.dependencies.sites;
  assert.ok(sites.length > 20);
  assert.deepEqual(
    [...new Set(sites.map((site) => site.kind))].sort(),
    ["type_use", "web_import", "web_reexport"],
  );
  assert.deepEqual(
    [...new Set(sites.map((site) => site.edgeKind))].sort(),
    ["imports", "reexports", "type_uses"],
  );
  const occurrences = new Set(sites.map((site) => site.evidence.occurrenceKind));
  for (const occurrence of [
    "default_import",
    "named_import",
    "namespace_import",
    "side_effect_import",
    "import_equals",
    "require_call",
    "dynamic_import",
    "named_reexport",
    "namespace_reexport",
    "export_star",
    "import_type",
    "type_reference",
    "heritage_type",
  ]) assert.ok(occurrences.has(occurrence), occurrence);
  assert.ok(sites.some((site) => site.evidence.relativePath === "src/doc.js"));
  assert.ok(sites.some((site) => site.evidence.relativePath === "src/view.jsx"));
  assert.ok(sites.every((site) => !site.specifier.startsWith("binding:")));
  assert.ok(sites.filter((site) => site.kind !== "type_use").every((site) => (
    site.source.kind === "file" && site.source.relativePath === site.evidence.relativePath
  )));
  assert.ok(sites.some((site) => site.typeOnly && site.importedName === "SharedCollection"));
  assert.ok(sites.some((site) => !site.typeOnly && site.importedName === "named"));
  assert.ok(!sites.some((site) => site.evidence.relativePath === "src/shadow.ts" && site.evidence.occurrenceKind === "require_call"));
  assert.ok(!sites.some((site) => site.evidence.relativePath === "src/imported-require.ts" && site.evidence.occurrenceKind === "require_call"));

  const definitions = new Map(first.definitions.definitions.map((definition) => [definition.key, definition]));
  const genericUses = sites.filter((site) => (
    site.kind === "type_use"
    && site.importedName === "SharedCollection"
    && site.evidence.relativePath === "src/main.ts"
  ));
  assert.ok(genericUses.length >= 4);
  for (const site of genericUses) {
    assert.equal(site.status, "resolved", JSON.stringify({
      site,
      issues: first.definitions.issues,
      relations: first.definitions.relations.filter((relation) => (
        relation.evidence.relativePath === site.evidence.relativePath
        && (relation.kind === "extends" || relation.kind === "implements")
      )),
    }));
    assert.equal(site.precision, "exact");
    assert.equal(site.targets.length, 1);
    const target = site.targets[0];
    assert.equal(target?.kind, "definition");
    assert.equal(target?.kind === "definition" ? definitions.get(target.key)?.semanticKind : null, "interface");
    assert.equal(target?.kind === "definition" ? definitions.get(target.key)?.displayName : null, "SharedCollection");
  }

  const external = sites.find((site) => site.moduleSpecifier === "lodash" && site.importedName === "map");
  assert.equal(external?.status, "external");
  assert.equal(external?.targets[0]?.kind, "external");
  const unresolved = sites.find((site) => site.moduleSpecifier === "./does-not-exist" && site.importedName === "absent");
  assert.equal(unresolved?.status, "unresolved");
  assert.equal(unresolved?.targets[0]?.kind, "unknown");
  const packageTypeUse = sites.find((site) => (
    site.kind === "type_use"
    && site.importedName === "QueryClient"
    && site.evidence.relativePath === "src/missing.ts"
  ));
  assert.equal(packageTypeUse?.status, "external");
  assert.equal(packageTypeUse?.targets[0]?.kind, "external");
  assert.equal(
    packageTypeUse?.targets[0]?.kind === "external" ? packageTypeUse.targets[0].locator : null,
    "npm:@tanstack/react-query",
  );
  const beforeImport = sites.find((site) => (
    site.kind === "type_use"
    && site.importedName === "QueryClient"
    && site.evidence.relativePath === "src/external-order.ts"
  ));
  assert.equal(beforeImport?.moduleSpecifier, "@tanstack/react-query");
  assert.equal(beforeImport?.status, "external");
  assert.equal(beforeImport?.targets[0]?.kind === "external" ? beforeImport.targets[0].locator : null, "npm:@tanstack/react-query");
  const qualifiedExternal = sites.find((site) => (
    site.kind === "type_use"
    && site.importedName === "Widget"
    && site.evidence.relativePath === "src/external-order.ts"
  ));
  assert.equal(qualifiedExternal?.moduleSpecifier, "@scope/package");
  assert.equal(qualifiedExternal?.status, "external");
  assert.equal(qualifiedExternal?.targets[0]?.kind === "external" ? qualifiedExternal.targets[0].locator : null, "npm:@scope/package");
  const shadowedNamespaces = sites.filter((site) => (
    site.kind === "type_use"
    && site.importedName === "Foo"
    && site.evidence.relativePath === "src/namespace-shadow.ts"
  ));
  assert.equal(shadowedNamespaces.length, 3, JSON.stringify(shadowedNamespaces));
  assert.ok(shadowedNamespaces.every((site) => (
    site.moduleSpecifier === null
    && site.status === "unresolved"
    && site.targets[0]?.kind === "unknown"
  )), JSON.stringify(shadowedNamespaces));
});

test("exact direct-call ledger distinguishes closed dispatch from dynamic and external calls", async () => {
  const sources = {
    "src/defs.ts": `
export function direct(): void {}
export function tag(parts: TemplateStringsArray): void { void parts }
export class Box {
  constructor() {}
  static create(): void {}
  static staticTag(parts: TemplateStringsArray): void { void parts }
  #hidden(): void {}
  open(): void {}
  openTag(parts: TemplateStringsArray): void { void parts }
  invokePrivate(): void { this.#hidden() }
  invokeOpen(): void { this.open() }
}
export class DerivedBox extends Box { constructor() { super() } }
`,
    "src/main.ts": `
import { direct as alias, tag, Box } from "./defs";
import { externalFn, ExternalClass } from "@fixture/external";
alias();
new Box();
Box.create();
new Box().open();
Box.staticTag\`value\`;
new Box().openTag\`value\`;
const box = new Box();
box.openTag\`value\`;
tag\`value\`;
const functionValue = alias;
functionValue();
const ConstructorValue = Box;
new ConstructorValue();
const StaticValue = Box;
StaticValue.create();
StaticValue.staticTag\`value\`;
new ConstructorValue().open();
new ConstructorValue().openTag\`value\`;
interface Contract { run(): void }
declare const contract: Contract;
contract.run();
declare const optionalCall: (() => void) | undefined;
optionalCall?.();
declare const unionCall: (() => void) | ((value: string) => void);
unionCall();
declare const intersectionCall: (() => void) & { readonly marker: true };
intersectionCall();
function overloaded(value: string): void;
function overloaded(value: number): void;
function overloaded(value: string | number): void { void value }
overloaded("value");
externalFn();
new ExternalClass();
`,
    "src/legacy.js": `
export function Legacy() {}
new Legacy();
`,
  };
  const first = await extractDependencyFixture(sources, "__depgraph_ts_call_complete_a__");
  const second = await extractDependencyFixture(sources, "__depgraph_ts_call_complete_z__");
  assert.deepEqual(first.dependencies, second.dependencies);
  assert.deepEqual(first.dependencies.issues, []);
  assert.doesNotThrow(() => validateTypeScriptRawDependencyDelta(
    first.dependencies,
    first.definitions,
    first.dependencyValidationSources,
  ));

  const calls = first.dependencies.calls;
  const definitions = new Map(first.definitions.definitions.map((definition) => [definition.key, definition]));
  const bySpecifier = (specifier: string) => calls.filter((call) => call.specifier === specifier);
  const targetKind = (call: (typeof calls)[number]): string | null => {
    const target = call.targets[0];
    return target?.kind === "definition" ? definitions.get(target.key)?.semanticKind ?? null : target?.kind ?? null;
  };
  const assertResolved = (
    specifier: string,
    dispatch: (typeof calls)[number]["dispatch"],
    semanticKind: string,
  ): void => {
    const call = bySpecifier(specifier).find((candidate) => candidate.dispatch === dispatch);
    assert.ok(call, `${specifier}/${dispatch}`);
    assert.equal(call.status, "resolved");
    assert.equal(call.precision, "exact");
    assert.equal(call.reason, null);
    assert.equal(targetKind(call), semanticKind);
  };
  assertResolved("alias", "direct", "function");
  assertResolved("Box", "direct", "constructor");
  assertResolved("Box.create", "static", "method");
  assertResolved("new Box().open", "fresh_instance", "method");
  assertResolved("Box.staticTag", "static", "method");
  assertResolved("new Box().openTag", "fresh_instance", "method");
  assertResolved("tag", "direct", "function");
  assertResolved("Legacy", "direct", "function");
  assertResolved("this.#hidden", "private", "method");
  assertResolved("super", "super", "constructor");

  for (const [specifier, reason] of [
    ["functionValue", "function_value_dispatch"],
    ["ConstructorValue", "function_value_dispatch"],
    ["StaticValue.create", "function_value_dispatch"],
    ["StaticValue.staticTag", "function_value_dispatch"],
    ["new ConstructorValue().open", "function_value_dispatch"],
    ["new ConstructorValue().openTag", "function_value_dispatch"],
    ["contract.run", "interface_dispatch"],
    ["optionalCall", "union_dispatch"],
    ["unionCall", "union_dispatch"],
    ["intersectionCall", "intersection_dispatch"],
    ["overloaded", "overload_dispatch"],
    ["this.open", "open_method_dispatch"],
    ["box.openTag", "open_method_dispatch"],
  ] as const) {
    const call = bySpecifier(specifier)[0];
    assert.ok(call, specifier);
    assert.equal(call.status, "unresolved", specifier);
    assert.equal(call.precision, "heuristic", specifier);
    assert.equal(call.targets[0]?.kind, "unknown", specifier);
    assert.equal(call.reason, reason, specifier);
  }
  assert.equal(bySpecifier("Box.staticTag")[0]?.callKind, "tagged_template");
  assert.equal(bySpecifier("new Box().openTag")[0]?.callKind, "tagged_template");
  assert.equal(bySpecifier("box.openTag")[0]?.callKind, "tagged_template");
  assert.equal(bySpecifier("StaticValue.staticTag")[0]?.callKind, "tagged_template");
  assert.equal(bySpecifier("new ConstructorValue().openTag")[0]?.callKind, "tagged_template");
  assert.equal(bySpecifier("Legacy")[0]?.callKind, "constructor");
  const externalFunction = bySpecifier("externalFn")[0];
  assert.equal(externalFunction?.status, "external");
  assert.equal(externalFunction?.precision, "heuristic");
  assert.equal(externalFunction?.dispatch, "external");
  const externalConstructor = bySpecifier("ExternalClass")[0];
  assert.equal(externalConstructor?.callKind, "constructor");
  assert.equal(externalConstructor?.status, "external");
  assert.equal(externalConstructor?.dispatch, "external");
  assert.ok(calls.every((call) => call.status !== ("candidates" as typeof call.status)));
  assert.ok(calls.filter((call) => call.evidence.relativePath === "src/main.ts").every((call) => (
    call.source.kind === "module_initializer"
  )));
  assert.ok(bySpecifier("this.#hidden").every((call) => call.source.kind === "definition"));
});

test("call ledger fails closed when a class field has no canonical callable owner", async () => {
  const fixture = await extractDependencyFixture({
    "src/main.ts": `
export function target(): number { return 1 }
export class FieldOwner {
  readonly value = target();
  static readonly staticValue = target();
}
const topLevelValue = target();
void topLevelValue;
`,
  }, "__depgraph_ts_call_field_owner__");
  assert.deepEqual(fixture.dependencies.issues, []);
  assert.doesNotThrow(() => validateTypeScriptRawDependencyDelta(
    fixture.dependencies,
    fixture.definitions,
    fixture.dependencyValidationSources,
  ));
  const targetCalls = fixture.dependencies.calls.filter((call) => call.specifier === "target");
  assert.equal(targetCalls.length, 3, JSON.stringify(targetCalls));
  const unresolved = targetCalls.filter((call) => call.reason === "caller_definition_unavailable");
  assert.equal(unresolved.length, 2, JSON.stringify(targetCalls));
  assert.ok(unresolved.every((call) => (
    call.status === "unresolved"
    && call.precision === "heuristic"
    && call.dispatch === "dynamic"
    && call.targets[0]?.kind === "unknown"
  )), JSON.stringify(unresolved));
  const topLevel = targetCalls.find((call) => call.status === "resolved");
  assert.ok(topLevel, JSON.stringify(targetCalls));
  assert.equal(topLevel.precision, "exact");
  assert.equal(topLevel.dispatch, "direct");
  assert.equal(topLevel.source.kind, "module_initializer");
});

test("call ledger does not attribute decorators or unrepresented callable bodies to an outer caller", async () => {
  const fixture = await extractDependencyFixture({
    "src/main.ts": `
export function target(): string { return "" }
function decorate(value: unknown): unknown { return value }
class Decorated {
  @decorate(target())
  method(@decorate(target()) value = target()): void { target(); void value }
}
const object = {
  [target()](): string { return target() },
  get value(): string { return target() },
  set value(value: string) { target(); void value },
  regular(): string { return target() },
};
void object;
`,
  }, "__depgraph_ts_call_execution_owner__");
  assert.doesNotThrow(() => validateTypeScriptRawDependencyDelta(
    fixture.dependencies,
    fixture.definitions,
    fixture.dependencyValidationSources,
  ));
  const definitions = new Map(fixture.definitions.definitions.map((definition) => [definition.key, definition]));
  const calls = fixture.dependencies.calls.filter((call) => call.specifier === "target");
  const unresolved = calls.filter((call) => call.reason === "caller_definition_unavailable");
  assert.equal(unresolved.length, 5, JSON.stringify(calls));
  assert.ok(unresolved.every((call) => (
    call.status === "unresolved"
    && call.dispatch === "dynamic"
    && call.source.kind === "module_initializer"
  )), JSON.stringify(unresolved));
  const methodCalls = calls.filter((call) => (
    call.status === "resolved"
    && call.source.kind === "definition"
    && definitions.get(call.source.key)?.displayName === "method"
  ));
  assert.equal(methodCalls.length, 2, JSON.stringify(calls));
  const moduleCalls = calls.filter((call) => call.status === "resolved" && call.source.kind === "module_initializer");
  assert.equal(moduleCalls.length, 1, JSON.stringify(calls));
  const regularCall = calls.find((call) => (
    call.status === "resolved"
    && call.source.kind === "definition"
    && definitions.get(call.source.key)?.displayName === "regular"
  ));
  assert.ok(regularCall, JSON.stringify(calls));
});

test("call ledger fails closed for class-expression fields and static blocks", async () => {
  const fixture = await extractDependencyFixture({
    "src/main.ts": `
function target(): string { return "" }
const ExpressionOwner = class {
  readonly field = target();
  static readonly staticField = target();
  static { target() }
  method(): string { return target() }
  readonly nested = (): string => target();
};
void ExpressionOwner;
`,
  }, "__depgraph_ts_call_class_expression_owner__");
  assert.doesNotThrow(() => validateTypeScriptRawDependencyDelta(
    fixture.dependencies,
    fixture.definitions,
    fixture.dependencyValidationSources,
  ));
  const definitions = new Map(fixture.definitions.definitions.map((definition) => [definition.key, definition]));
  const calls = fixture.dependencies.calls.filter((call) => call.specifier === "target");
  assert.equal(calls.length, 5, JSON.stringify(calls));
  const unresolved = calls.filter((call) => call.reason === "caller_definition_unavailable");
  assert.equal(unresolved.length, 3, JSON.stringify(calls));
  assert.ok(unresolved.every((call) => call.status === "unresolved" && call.dispatch === "dynamic"));
  const resolved = calls.filter((call) => call.status === "resolved" && call.source.kind === "definition");
  assert.equal(resolved.length, 2, JSON.stringify(calls));
  assert.ok(resolved.every((call) => (
    call.source.kind === "definition"
    && ["anonymous_function", "method"].includes(definitions.get(call.source.key)?.semanticKind ?? "")
  )), JSON.stringify(calls));
});

test("nested object and class-expression callables do not inherit a containing class member identity", async () => {
  const objectFixture = await extractDependencyFixture({
    "src/main.ts": `
function target(): void {}
class Host {
  nestedMethod(): void { target() }
  holder = { nestedMethod(): void { target() } };
}
void Host;
`,
  }, "__depgraph_ts_nested_object_callable_owner__");
  assert.ok(!objectFixture.definitions.issues.some((issue) => issue.fatal), JSON.stringify(objectFixture.definitions.issues));
  assert.ok(!objectFixture.dependencies.issues.some((issue) => issue.fatal), JSON.stringify(objectFixture.dependencies.issues));
  assert.doesNotThrow(() => validateTypeScriptRawDependencyDelta(
    objectFixture.dependencies,
    objectFixture.definitions,
    objectFixture.dependencyValidationSources,
  ));
  const objectDefinitions = new Map(objectFixture.definitions.definitions.map((definition) => [definition.key, definition]));
  const objectCalls = objectFixture.dependencies.calls.filter((call) => call.specifier === "target");
  assert.equal(objectCalls.length, 2, JSON.stringify(objectCalls));
  assert.ok(objectCalls.every((call) => call.status === "resolved" && call.source.kind === "definition"));
  assert.equal(new Set(objectCalls.map((call) => call.source.kind === "definition" ? call.source.key : "")).size, 2);
  assert.deepEqual(new Set(objectCalls.map((call) => (
    call.source.kind === "definition" ? objectDefinitions.get(call.source.key)?.semanticKind : null
  ))), new Set(["method", "anonymous_function"]));

  const classFixture = await extractDependencyFixture({
    "src/main.ts": `
function target(): void {}
class Host {
  constructor() {}
  holder = class { constructor() { target() } };
}
void Host;
`,
  }, "__depgraph_ts_nested_class_callable_owner__");
  assert.ok(!classFixture.definitions.issues.some((issue) => issue.fatal), JSON.stringify(classFixture.definitions.issues));
  assert.ok(!classFixture.dependencies.issues.some((issue) => issue.fatal), JSON.stringify(classFixture.dependencies.issues));
  const host = classFixture.definitions.definitions.find((definition) => (
    definition.graphKind === "type" && definition.semanticKind === "class" && definition.displayName === "Host"
  ));
  assert.ok(host);
  const outerConstructor = classFixture.definitions.definitions.find((definition) => (
    definition.semanticKind === "constructor"
    && definition.owner.kind === "definition"
    && definition.owner.key === host.key
  ));
  assert.ok(outerConstructor);
  const innerCall = classFixture.dependencies.calls.find((call) => call.specifier === "target");
  assert.ok(innerCall, JSON.stringify(classFixture.dependencies.calls));
  assert.equal(innerCall.status, "unresolved");
  assert.equal(innerCall.reason, "caller_definition_unavailable");
  assert.equal(innerCall.dispatch, "dynamic");
  assert.notEqual(innerCall.source.kind === "definition" ? innerCall.source.key : null, outerConstructor.key);
});

test("nested type-literal method signatures do not inherit a containing type identity", async () => {
  const sources = {
    "src/main.ts": `
class Host {
  nestedMethod(): void {}
  holder!: { nestedMethod(): void };
}
interface Contract { direct(): void }
type Alias = { directAlias(): void };
void Host;
`,
  };
  const delta = await extractFixture(sources, "__depgraph_ts_nested_type_literal_method_owner__");
  assert.ok(!delta.issues.some((issue) => issue.fatal), JSON.stringify(delta.issues));
  assert.doesNotThrow(() => validateTypeScriptRawDefinitionDelta(
    delta,
    validationSources(sources),
  ));
  const host = delta.definitions.find((definition) => definition.displayName === "Host");
  const contract = delta.definitions.find((definition) => definition.displayName === "Contract");
  const alias = delta.definitions.find((definition) => definition.displayName === "Alias");
  assert.ok(host);
  assert.ok(contract);
  assert.ok(alias);
  const methods = delta.definitions.filter((definition) => definition.semanticKind === "method");
  assert.ok(methods.some((definition) => (
    definition.displayName === "nestedMethod"
    && definition.owner.kind === "definition"
    && definition.owner.key === host.key
  )), JSON.stringify(methods));
  assert.ok(methods.some((definition) => (
    definition.displayName === "direct"
    && definition.owner.kind === "definition"
    && definition.owner.key === contract.key
  )), JSON.stringify(methods));
  assert.ok(methods.some((definition) => (
    definition.displayName === "directAlias"
    && definition.owner.kind === "definition"
    && definition.owner.key === alias.key
  )), JSON.stringify(methods));
  const nestedSignature = delta.definitions.find((definition) => (
    definition.displayName === "nestedMethod"
    && definition.owner.kind === "file"
  ));
  assert.ok(nestedSignature, JSON.stringify(delta.definitions));
  assert.equal(nestedSignature.semanticKind, "anonymous_function");
  assert.equal(nestedSignature.identityKind, "anonymous");
  assert.equal(nestedSignature.resolverIdentity, null);
});

test("raw call validator rejects singleton candidates and coordinated call mutations", async () => {
  const fixture = await extractDependencyFixture({
    "src/main.ts": "export function target(): void {}\nexport const holder = 1;\ntarget();\n",
  }, "__depgraph_ts_call_validation__");
  assert.equal(fixture.dependencies.calls.length, 1);
  const reject = (mutate: (delta: TypeScriptRawDependencyDelta) => void, pattern: RegExp): void => {
    const delta = structuredClone(fixture.dependencies);
    mutate(delta);
    assert.throws(() => validateTypeScriptRawDependencyDelta(
      delta,
      fixture.definitions,
      fixture.dependencyValidationSources,
    ), pattern);
  };
  reject((delta) => {
    const call = delta.calls[0]! as unknown as Record<string, unknown>;
    call.status = "candidates";
    call.precision = "overapprox";
  }, /call status\/precision\/target contract/u);
  reject((delta) => {
    delta.calls[0]!.dispatch = "open";
  }, /call status\/precision\/target contract/u);
  reject((delta) => {
    (delta.calls[0]! as unknown as { source: unknown }).source = { kind: "file", relativePath: "src/main.ts" };
  }, /call source kind/u);
  reject((delta) => {
    const variable = fixture.definitions.definitions.find((definition) => definition.semanticKind === "variable");
    assert.ok(variable);
    const call = delta.calls[0]!;
    call.source = { kind: "definition", key: variable.key };
    call.key = `site:${JSON.stringify([
      call.source,
      "call",
      call.evidence.relativePath,
      call.evidence.startOffset,
      call.evidence.endOffset,
    ])}`;
  }, /caller is not a canonical symbol definition/u);
  reject((delta) => {
    delta.calls[0]!.targetConditions[0] = { op: "eq", key: "mode", value: "test" };
  }, /call site and target conditions disagree/u);
  reject((delta) => {
    delta.calls = [];
  }, /call occurrence is missing/u);
});

test("import-equals and export-equals retain canonical type proof without resolving a bare namespace type", async () => {
  const sources = {
    "src/cjs.ts": [
      "class Foo { readonly value = 1 }",
      "namespace Foo { export interface Member { readonly nested: true } }",
      "export = Foo;",
      "",
    ].join("\n"),
    "src/bridge.ts": 'import Foo = require("./cjs");\nexport = Foo;\n',
    "src/property-api.ts": [
      "class PropertyMember { readonly value = 1 }",
      "const API = { PropertyMember };",
      "export = API;",
      "",
    ].join("\n"),
    "src/escaped-consumer.ts": [
      'import \\u0045scaped = require("./cjs");',
      "type EscapedUse = Escaped.Member;",
      'export { Escaped as "quoted-origin" };',
      "",
    ].join("\n"),
    "src/ns.ts": "export interface Member { readonly value: string }\n",
    "src/es-default.ts": "export default class Ordinary { readonly value = 1 }\n",
    "src/consumer.ts": [
      'import EqualsFoo = require("./cjs");',
      'import Bridge = require("./bridge");',
      'import PropertyAPI = require("./property-api");',
      'import DefaultFoo from "./cjs";',
      'import * as NS from "./ns";',
      "type EqualsUse = EqualsFoo;",
      "type QualifiedEqualsUse = EqualsFoo.Member;",
      "type BridgeUse = Bridge.Member;",
      "type PropertyUse = typeof PropertyAPI.PropertyMember;",
      "type DefaultUse = DefaultFoo;",
      "type BareNamespaceUse = NS;",
      "type QualifiedNamespaceUse = NS.Member;",
      "",
    ].join("\n"),
  };
  const { definitions, dependencies, dependencyValidationSources } = await extractDependencyFixture(
    sources,
    "__depgraph_ts_dependency_import_equals_root__",
  );
  assert.deepEqual(dependencies.issues, []);
  assert.doesNotThrow(() => validateTypeScriptRawDependencyDelta(
    dependencies,
    definitions,
    dependencyValidationSources,
  ));
  const definitionsByKey = new Map(definitions.definitions.map((definition) => [definition.key, definition]));
  const typeUse = (importedName: string, exportPath: readonly string[], moduleSpecifier?: string) => dependencies.sites.find((site) => (
    site.kind === "type_use"
    && site.importedName === importedName
    && JSON.stringify(site.exportPath) === JSON.stringify(exportPath)
    && (moduleSpecifier === undefined || site.moduleSpecifier === moduleSpecifier)
  ));
  const equalsUse = typeUse("=", []);
  assert.equal(equalsUse?.moduleSpecifier, "./cjs");
  assert.equal(equalsUse?.resolutionMode, null);
  assert.equal(equalsUse?.bindingKind, "import_equals");
  assert.equal(equalsUse?.status, "resolved");
  const equalsTarget = equalsUse?.targets[0];
  assert.equal(equalsTarget?.kind, "definition");
  assert.equal(
    equalsTarget?.kind === "definition" ? definitionsByKey.get(equalsTarget.key)?.displayName : null,
    "Foo",
  );
  assert.equal(
    equalsTarget?.kind === "definition" ? definitionsByKey.get(equalsTarget.key)?.graphKind : null,
    "type",
  );
  const rootProof = dependencies.moduleExports.find((proof) => (
    proof.relativePath === "src/cjs.ts"
    && JSON.stringify(proof.exportPath) === JSON.stringify([])
  ));
  assert.ok(rootProof?.definitionKeys.some((key) => (
    definitionsByKey.get(key)?.displayName === "Foo"
    && definitionsByKey.get(key)?.graphKind === "type"
  )), JSON.stringify(dependencies.moduleExports));
  assert.ok(!dependencies.moduleExports.some((proof) => (
    proof.relativePath === "src/es-default.ts"
    && proof.exportPath.length === 0
  )), JSON.stringify(dependencies.moduleExports));
  const qualifiedEquals = typeUse("Member", ["Member"], "./cjs");
  assert.equal(qualifiedEquals?.resolutionMode, null);
  assert.equal(qualifiedEquals?.bindingKind, "import_equals");
  assert.equal(qualifiedEquals?.status, "resolved");
  const memberProof = dependencies.moduleExports.find((proof) => (
    proof.relativePath === "src/cjs.ts"
    && JSON.stringify(proof.exportPath) === JSON.stringify(["Member"])
  ));
  assert.ok(memberProof?.definitionKeys.some((key) => (
    definitionsByKey.get(key)?.displayName === "Member"
    && definitionsByKey.get(key)?.graphKind === "type"
  )), JSON.stringify(dependencies.moduleExports));
  const bridgeUse = typeUse("Member", ["Member"], "./bridge");
  assert.equal(bridgeUse?.status, "resolved");
  assert.ok(dependencies.moduleExports.some((proof) => (
    proof.relativePath === "src/bridge.ts"
    && JSON.stringify(proof.exportPath) === JSON.stringify(["Member"])
    && proof.definitionKeys.some((key) => definitionsByKey.get(key)?.displayName === "Member")
  )), JSON.stringify(dependencies.moduleExports));
  const propertyUse = typeUse("PropertyMember", ["PropertyMember"], "./property-api");
  assert.equal(propertyUse?.status, "resolved");
  assert.ok(dependencies.moduleExports.some((proof) => (
    proof.relativePath === "src/property-api.ts"
    && JSON.stringify(proof.exportPath) === JSON.stringify(["PropertyMember"])
    && proof.definitionKeys.some((key) => definitionsByKey.get(key)?.displayName === "PropertyMember")
  )), JSON.stringify(dependencies.moduleExports));
  const escapedUse = dependencies.sites.find((site) => (
    site.kind === "type_use"
    && site.evidence.relativePath === "src/escaped-consumer.ts"
    && site.importedName === "Member"
  ));
  assert.equal(escapedUse?.status, "resolved");
  assert.ok(escapedUse?.bindingOrigin);
  const quotedOrigin = dependencies.sites.find((site) => (
    site.evidence.relativePath === "src/escaped-consumer.ts"
    && site.evidence.occurrenceKind === "named_reexport"
    && site.bindingKind === "import_equals"
  ));
  assert.ok(quotedOrigin?.bindingOrigin);

  const defaultUse = typeUse("default", ["default"]);
  assert.equal(defaultUse?.status, "resolved");
  const defaultTarget = defaultUse?.targets[0];
  assert.equal(defaultTarget?.kind, "definition");
  assert.equal(
    defaultTarget?.kind === "definition" ? definitionsByKey.get(defaultTarget.key)?.displayName : null,
    "Foo",
  );
  const defaultProof = dependencies.moduleExports.find((proof) => (
    proof.relativePath === "src/cjs.ts"
    && JSON.stringify(proof.exportPath) === JSON.stringify(["default"])
  ));
  assert.ok(defaultProof?.definitionKeys.some((key) => (
    definitionsByKey.get(key)?.displayName === "Foo"
    && definitionsByKey.get(key)?.graphKind === "type"
  )), JSON.stringify(dependencies.moduleExports));

  const bareNamespace = typeUse("*", []);
  assert.equal(bareNamespace?.moduleSpecifier, "./ns");
  assert.equal(bareNamespace?.status, "unresolved");
  assert.equal(bareNamespace?.targets[0]?.kind, "unknown");
  const qualifiedNamespace = typeUse("Member", ["Member"], "./ns");
  assert.equal(qualifiedNamespace?.moduleSpecifier, "./ns");
  assert.equal(qualifiedNamespace?.status, "resolved");
  const memberTarget = qualifiedNamespace?.targets[0];
  assert.equal(memberTarget?.kind, "definition");
  assert.equal(
    memberTarget?.kind === "definition" ? definitionsByKey.get(memberTarget.key)?.displayName : null,
    "Member",
  );
});

test("empty import and re-export clauses are preserved while ambient require shadows stay lexical", async () => {
  const sources = {
    "globals.d.ts": "export {};\ndeclare global { function require(id: string): unknown }\n",
    "src/dep.ts": "export interface Dep { readonly value: string }\n",
    "src/types.ts": "export interface require { readonly typeOnly: true }\n",
    "src/loader.ts": "export function loader(id: string): string { return id }\n",
    "src/consumer.ts": [
      'import {} from "./dep";',
      'import type {} from "./dep";',
      'export {} from "./dep";',
      'export type {} from "./dep";',
      "type require = string;",
      'export const loaded = require("./dep");',
      'export const typeAliasLoaded = require("./type-alias-not-a-shadow");',
      "export function generic<require>(): unknown {",
      '  return require("./type-parameter-not-a-shadow");',
      "}",
      "",
    ].join("\n"),
    "src/type-import.ts": [
      'import type { require } from "./types";',
      'export const loaded = require("./type-import-not-a-shadow");',
      "",
    ].join("\n"),
    "src/type-specifier-import.ts": [
      'import { type require } from "./types";',
      'export const loaded = require("./type-specifier-not-a-shadow");',
      "",
    ].join("\n"),
    "src/value-import-shadow.ts": [
      'import { loader as require } from "./loader";',
      'export const loaded = require("./value-import-shadow-must-not-collect");',
      "",
    ].join("\n"),
    "src/local-ambient-function.ts": [
      "declare function require(id: string): unknown;",
      'export const loaded = require("./dep");',
      "",
    ].join("\n"),
    "src/local-ambient-const.ts": [
      "declare const require: (id: string) => unknown;",
      'export const loaded = require("./dep");',
      "",
    ].join("\n"),
  };
  const { definitions, dependencies, dependencyValidationSources } = await extractDependencyFixture(
    sources,
    "__depgraph_ts_dependency_empty_clauses_ambient_require__",
  );
  assert.deepEqual(dependencies.issues, []);
  assert.doesNotThrow(() => validateTypeScriptRawDependencyDelta(
    dependencies,
    definitions,
    dependencyValidationSources,
  ));
  const emptyImports = dependencies.sites.filter((site) => (
    site.evidence.relativePath === "src/consumer.ts"
    && site.evidence.occurrenceKind === "empty_import"
  ));
  assert.equal(emptyImports.length, 2, JSON.stringify(dependencies.sites));
  assert.deepEqual(emptyImports.map((site) => site.typeOnly).sort(), [false, true]);
  assert.ok(emptyImports.every((site) => (
    site.kind === "web_import"
    && site.moduleSpecifier === "./dep"
    && site.importedName === null
    && site.exportPath === null
  )));
  const emptyReexports = dependencies.sites.filter((site) => (
    site.evidence.relativePath === "src/consumer.ts"
    && site.evidence.occurrenceKind === "empty_reexport"
  ));
  assert.equal(emptyReexports.length, 2, JSON.stringify(dependencies.sites));
  assert.deepEqual(emptyReexports.map((site) => site.typeOnly).sort(), [false, true]);
  assert.ok(emptyReexports.every((site) => (
    site.kind === "web_reexport"
    && site.moduleSpecifier === "./dep"
    && site.importedName === null
    && site.exportPath === null
  )));
  assert.ok(dependencies.sites.some((site) => (
    site.evidence.relativePath === "src/consumer.ts"
    && site.evidence.occurrenceKind === "require_call"
    && site.moduleSpecifier === "./dep"
  )), JSON.stringify(dependencies.sites));
  for (const moduleSpecifier of [
    "./type-alias-not-a-shadow",
    "./type-parameter-not-a-shadow",
    "./type-import-not-a-shadow",
    "./type-specifier-not-a-shadow",
  ]) {
    assert.ok(dependencies.sites.some((site) => (
      site.evidence.occurrenceKind === "require_call"
      && site.moduleSpecifier === moduleSpecifier
    )), moduleSpecifier);
  }
  assert.ok(!dependencies.sites.some((site) => (
    site.evidence.occurrenceKind === "require_call"
    && site.moduleSpecifier === "./value-import-shadow-must-not-collect"
  )));
  for (const relativePath of ["src/local-ambient-function.ts", "src/local-ambient-const.ts"]) {
    assert.ok(!dependencies.sites.some((site) => (
      site.evidence.relativePath === relativePath
      && site.evidence.occurrenceKind === "require_call"
    )), relativePath);
  }
});

test("alias re-exports, empty export names, scoped namespaces, and type queries remain deterministic", async () => {
  const sources = {
    "src/cjs.ts": [
      "class EqualsThing { readonly value = 1 }",
      "export = EqualsThing;",
      "",
    ].join("\n"),
    "src/origin.ts": [
      "export interface Foo { readonly value: string }",
      "export const value = 1;",
      "export default class DefaultThing {}",
      "export namespace Space { export interface Member { readonly id: string } }",
      "",
    ].join("\n"),
    "src/mid.ts": [
      'import { type Foo as LocalFoo, value as LocalValue } from "./origin";',
      'import DefaultThing from "./origin";',
      'import * as LocalNS from "./origin";',
      'import EqualsThing = require("./cjs");',
      "export { LocalFoo as Foo };",
      "export { LocalValue as value };",
      "export { DefaultThing as Default };",
      "export { LocalNS as NS };",
      "export { EqualsThing as Equals };",
      "",
    ].join("\n"),
    "src/top.ts": 'export { Foo as Renamed } from "./mid";\n',
    "src/missing-mid.ts": [
      'import { Missing } from "./does-not-exist";',
      "export { Missing };",
      "",
    ].join("\n"),
    "src/ordinary-local.ts": [
      "namespace Hidden {",
      '  import Plain = require("./cjs");',
      "  export type Alias = Plain;",
      "}",
      "class Plain {}",
      "export { Plain };",
      "",
    ].join("\n"),
    "src/empty-name.ts": [
      "interface EmptyType { readonly empty: true }",
      "interface StarType { readonly star: true }",
      "interface EqualsType { readonly equals: true }",
      'export { EmptyType as "" };',
      'export { StarType as "*" };',
      'export { EqualsType as "=" };',
      "export interface Other { readonly other: true }",
      "",
    ].join("\n"),
    "src/consumer.ts": [
      'import type { Renamed } from "./top";',
      'import type { "" as LocalEmpty, "*" as LocalStar, "=" as LocalEquals, Other } from "./empty-name";',
      'import { value } from "./origin";',
      "interface Uses {",
      "  readonly renamed: Renamed;",
      "  readonly empty: LocalEmpty;",
      "  readonly star: LocalStar;",
      "  readonly equals: LocalEquals;",
      "  readonly other: Other;",
      "  readonly query: typeof value;",
      "  readonly invalid: value;",
      "}",
      "",
    ].join("\n"),
    "src/scopes.ts": [
      "namespace A {",
      "  export type UsesFoo = Package.Foo;",
      '  import Package = require("pkg-a");',
      "}",
      "namespace B {",
      "  export type UsesBar = Package.Bar;",
      '  import Package = require("pkg-b");',
      "}",
      "",
    ].join("\n"),
    "src/binding-scheme.ts": "import 'binding:[\"pkg\",\"X\"]';\n",
    "src/forward.ts": 'export type { "*" as ForwardStar, "=" as ForwardEquals } from "./empty-name";\n',
  };
  const first = await extractDependencyFixture(
    sources,
    "__depgraph_ts_dependency_alias_proofs_a__",
    reverseAlternatingModuleExportResponses,
  );
  const second = await extractDependencyFixture(
    sources,
    "__depgraph_ts_dependency_alias_proofs_z__",
    reverseAlternatingModuleExportResponses,
  );
  assert.deepEqual(first.dependencies, second.dependencies);
  assert.deepEqual(first.dependencies.issues, []);
  assert.doesNotThrow(() => validateTypeScriptRawDependencyDelta(
    first.dependencies,
    first.definitions,
    first.dependencyValidationSources,
  ));
  const { dependencies, definitions } = first;
  const definitionsByKey = new Map(definitions.definitions.map((definition) => [definition.key, definition]));
  const localAlias = dependencies.sites.find((site) => (
    site.evidence.relativePath === "src/mid.ts"
    && site.evidence.occurrenceKind === "named_reexport"
    && site.moduleSpecifier === "./origin"
    && site.importedName === "Foo"
  ));
  assert.equal(localAlias?.typeOnly, true);
  assert.deepEqual(localAlias?.exportPath, ["Foo"]);
  assert.equal(localAlias?.status, "resolved");
  for (const importedName of ["value", "default"]) {
    assert.ok(dependencies.sites.some((site) => (
      site.evidence.relativePath === "src/mid.ts"
      && site.evidence.occurrenceKind === "named_reexport"
      && site.moduleSpecifier === "./origin"
      && site.importedName === importedName
      && site.status === "resolved"
    )), importedName);
  }
  assert.ok(dependencies.sites.some((site) => (
    site.evidence.relativePath === "src/mid.ts"
    && site.evidence.occurrenceKind === "namespace_reexport"
    && site.moduleSpecifier === "./origin"
    && site.importedName === "*"
  )), JSON.stringify(dependencies.sites));
  const equalsReexport = dependencies.sites.find((site) => (
    site.evidence.relativePath === "src/mid.ts"
    && site.evidence.occurrenceKind === "named_reexport"
    && site.moduleSpecifier === "./cjs"
    && site.importedName === "="
  ));
  assert.equal(equalsReexport?.typeOnly, false);
  assert.equal(equalsReexport?.resolutionMode, null);
  assert.deepEqual(equalsReexport?.exportPath, []);
  assert.equal(equalsReexport?.status, "resolved");
  const missingReexport = dependencies.sites.find((site) => (
    site.evidence.relativePath === "src/missing-mid.ts"
    && site.evidence.occurrenceKind === "named_reexport"
    && site.moduleSpecifier === "./does-not-exist"
    && site.importedName === "Missing"
  ));
  assert.equal(missingReexport?.status, "unresolved");
  assert.equal(missingReexport?.targets[0]?.kind, "unknown");
  assert.ok(!dependencies.sites.some((site) => (
    site.evidence.relativePath === "src/ordinary-local.ts"
    && site.kind === "web_reexport"
  )), JSON.stringify(dependencies.sites));

  const renamedUse = dependencies.sites.find((site) => (
    site.kind === "type_use"
    && site.evidence.relativePath === "src/consumer.ts"
    && site.importedName === "Renamed"
  ));
  assert.equal(renamedUse?.status, "resolved");
  const renamedTarget = renamedUse?.targets[0];
  assert.equal(renamedTarget?.kind, "definition");
  assert.equal(
    renamedTarget?.kind === "definition" ? definitionsByKey.get(renamedTarget.key)?.displayName : null,
    "Foo",
  );
  const renamedProof = dependencies.moduleExports.find((proof) => (
    proof.relativePath === "src/top.ts"
    && JSON.stringify(proof.exportPath) === JSON.stringify(["Renamed"])
  ));
  assert.ok(renamedProof?.definitionKeys.some((key) => definitionsByKey.get(key)?.displayName === "Foo"));

  const emptyImport = dependencies.sites.find((site) => (
    site.evidence.relativePath === "src/consumer.ts"
    && site.evidence.occurrenceKind === "named_import"
    && site.importedName === ""
  ));
  assert.deepEqual(emptyImport?.exportPath, [""]);
  const emptyUse = dependencies.sites.find((site) => (
    site.kind === "type_use"
    && site.evidence.relativePath === "src/consumer.ts"
    && site.importedName === "LocalEmpty"
  ));
  assert.deepEqual(emptyUse?.exportPath, [""]);
  assert.equal(emptyUse?.status, "resolved");
  const emptyTarget = emptyUse?.targets[0];
  assert.equal(emptyTarget?.kind, "definition");
  assert.equal(
    emptyTarget?.kind === "definition" ? definitionsByKey.get(emptyTarget.key)?.displayName : null,
    "EmptyType",
  );
  assert.ok(dependencies.moduleExports.some((proof) => (
    proof.relativePath === "src/empty-name.ts"
    && JSON.stringify(proof.exportPath) === JSON.stringify([""])
  )), JSON.stringify(dependencies.moduleExports));
  for (const remoteName of ["*", "="]) {
    const quotedImport = dependencies.sites.find((site) => (
      site.evidence.relativePath === "src/consumer.ts"
      && site.evidence.occurrenceKind === "named_import"
      && site.importedName === remoteName
    ));
    assert.deepEqual(quotedImport?.exportPath, [remoteName]);
    assert.equal(quotedImport?.status, "resolved");
    const quotedUse = dependencies.sites.find((site) => (
      site.kind === "type_use"
      && site.evidence.relativePath === "src/consumer.ts"
      && site.importedName === remoteName
    ));
    assert.deepEqual(quotedUse?.exportPath, [remoteName]);
    assert.equal(quotedUse?.status, "resolved");
    const quotedReexport = dependencies.sites.find((site) => (
      site.evidence.relativePath === "src/forward.ts"
      && site.evidence.occurrenceKind === "named_reexport"
      && site.importedName === remoteName
    ));
    assert.deepEqual(quotedReexport?.exportPath, [remoteName]);
    assert.equal(quotedReexport?.status, "resolved");
    assert.ok(dependencies.moduleExports.some((proof) => (
      proof.relativePath === "src/empty-name.ts"
      && JSON.stringify(proof.exportPath) === JSON.stringify([remoteName])
    )), remoteName);
  }
  const bindingScheme = dependencies.sites.find((site) => (
    site.evidence.relativePath === "src/binding-scheme.ts"
    && site.evidence.occurrenceKind === "side_effect_import"
  ));
  assert.equal(bindingScheme?.specifier, 'binding:["pkg","X"]');
  assert.equal(bindingScheme?.moduleSpecifier, 'binding:["pkg","X"]');
  assert.equal(bindingScheme?.importedName, null);
  assert.equal(bindingScheme?.status, "external");
  assert.equal(dependencies.sites.find((site) => (
    site.kind === "type_use"
    && site.evidence.relativePath === "src/consumer.ts"
    && site.importedName === "Other"
  ))?.status, "resolved");

  const valueTypeUses = dependencies.sites.filter((site) => (
    site.kind === "type_use"
    && site.evidence.relativePath === "src/consumer.ts"
    && site.importedName === "value"
  ));
  assert.equal(valueTypeUses.length, 2, JSON.stringify(dependencies.sites));
  assert.ok(valueTypeUses.every((site) => (
    site.status === "unresolved"
    && ["value_symbol_is_not_a_type", "typechecker_target_unresolved"].includes(site.reason ?? "")
    && site.targets[0]?.kind === "unknown"
  )), JSON.stringify(valueTypeUses));

  for (const [importedName, moduleSpecifier] of [["Foo", "pkg-a"], ["Bar", "pkg-b"]] as const) {
    const use = dependencies.sites.find((site) => (
      site.kind === "type_use"
      && site.evidence.relativePath === "src/scopes.ts"
      && site.importedName === importedName
    ));
    assert.equal(use?.moduleSpecifier, moduleSpecifier);
    assert.equal(use?.status, "external");
    assert.equal(use?.targets[0]?.kind === "external" ? use.targets[0].locator : null, `npm:${moduleSpecifier}`);
  }
});

test("duplicate local alias origins remain ambiguous regardless of import order", async () => {
  const fixture = (reverse: boolean): Readonly<Record<string, string>> => {
    const imports = [
      'import { Foo as X } from "./a";',
      'import { Bar as X } from "./b";',
      'import * as NS from "./a";',
      'import * as NS from "./b";',
    ];
    if (reverse) imports.reverse();
    return {
      "src/a.ts": "export interface Foo { readonly foo: true }\n",
      "src/b.ts": "export interface Bar { readonly bar: true }\n",
      "src/mid.ts": [
        ...imports,
        "export { X };",
        "type UsesNamespace = NS.Foo;",
        "const valueReference = NS;",
        "",
      ].join("\n"),
    };
  };
  const forward = await extractDependencyFixture(
    fixture(false),
    "__depgraph_ts_dependency_ambiguous_alias_forward__",
  );
  const reversed = await extractDependencyFixture(
    fixture(true),
    "__depgraph_ts_dependency_ambiguous_alias_reversed__",
  );
  assert.deepEqual(forward.dependencies.issues, []);
  assert.deepEqual(reversed.dependencies.issues, []);
  const ambiguousReexport = (delta: TypeScriptRawDependencyDelta) => delta.sites.find((site) => (
    site.evidence.relativePath === "src/mid.ts"
    && site.evidence.occurrenceKind === "named_reexport"
  ));
  const forwardSite = ambiguousReexport(forward.dependencies);
  const reversedSite = ambiguousReexport(reversed.dependencies);
  assert.ok(forwardSite, JSON.stringify(forward.dependencies.sites));
  assert.ok(reversedSite, JSON.stringify(reversed.dependencies.sites));
  assert.deepEqual(forwardSite, reversedSite);
  assert.equal(forwardSite?.moduleSpecifier, "<ambiguous>");
  assert.equal(forwardSite?.importedName, "X");
  assert.deepEqual(forwardSite?.exportPath, ["X"]);
  assert.equal(forwardSite?.status, "unresolved");
  assert.equal(forwardSite?.reason, "ambiguous_binding_provenance");
  assert.equal(forwardSite?.targets[0]?.kind, "unknown");
  const ambiguousQualifiedType = forward.dependencies.sites.find((site) => (
    site.kind === "type_use"
    && site.evidence.relativePath === "src/mid.ts"
    && site.importedName === "Foo"
  ));
  assert.equal(ambiguousQualifiedType?.status, "unresolved");
  assert.equal(ambiguousQualifiedType?.reason, "ambiguous_binding_provenance");
  assert.equal(ambiguousQualifiedType?.targets[0]?.kind, "unknown");
  assert.equal(ambiguousQualifiedType?.moduleSpecifier, "<ambiguous>");
  assert.equal(ambiguousQualifiedType?.bindingKind, "named");
  assert.deepEqual(ambiguousQualifiedType?.exportPath, ["Foo"]);
  for (const mutate of [
    (site: TypeScriptRawDependencyDelta["sites"][number]) => { site.moduleSpecifier = null; },
    (site: TypeScriptRawDependencyDelta["sites"][number]) => { site.bindingKind = null; },
    (site: TypeScriptRawDependencyDelta["sites"][number]) => { site.exportPath = null; },
    (site: TypeScriptRawDependencyDelta["sites"][number]) => {
      site.bindingScope = { startOffset: 0, endOffset: fixture(false)["src/mid.ts"]!.length };
    },
  ]) {
    const delta = structuredClone(forward.dependencies);
    const site = delta.sites.find((candidate) => candidate.key === ambiguousQualifiedType?.key);
    assert.ok(site);
    mutate(site);
    assert.throws(() => validateTypeScriptRawDependencyDelta(
      delta,
      forward.definitions,
      forward.dependencyValidationSources,
    ), /safely-unresolved dependency syntax does not correlate/u);
  }
  {
    const delta = structuredClone(forward.dependencies);
    const site = delta.sites.find((candidate) => candidate.key === ambiguousQualifiedType?.key);
    assert.ok(site);
    site.evidence.occurrenceKind = "heritage_type";
    assert.throws(() => validateTypeScriptRawDependencyDelta(
      delta,
      forward.definitions,
      forward.dependencyValidationSources,
    ), /type-use occurrence contradicts parser context/u);
  }
  {
    const delta = structuredClone(forward.dependencies);
    const site = delta.sites.find((candidate) => candidate.key === ambiguousQualifiedType?.key);
    assert.ok(site);
    const source = fixture(false)["src/mid.ts"]!;
    const valueStart = source.indexOf("NS", source.indexOf("valueReference"));
    site.evidence.startOffset = valueStart;
    site.evidence.endOffset = valueStart + "NS".length;
    site.specifier = "NS";
    site.importedName = "NS";
    site.exportPath = ["NS"];
    assert.throws(() => validateTypeScriptRawDependencyDelta(
      delta,
      forward.definitions,
      forward.dependencyValidationSources,
    ), /type-use occurrence contradicts parser context/u);
  }
});

test("empty module literals remain distinct from computed and missing module specifiers", async () => {
  const sources = {
    "globals.d.ts": "export {};\ndeclare global { function require(id?: string): unknown }\n",
    "src/empty.ts": [
      'import "";',
      'import { Missing } from "";',
      'export { Missing as Again } from "";',
      'void import("");',
      'const required = require("");',
      'void import(`./template-lazy`);',
      'const templateRequired = require(`template-package`);',
      'const optionalRequired = require?.(`optional-package`);',
      'const genericRequired = require<string>(`generic-package`);',
      'const name = "";',
      "void require(name);",
      "void require();",
      "type Use = Missing;",
      "void required;",
      "void templateRequired;",
      "void optionalRequired;",
      "void genericRequired;",
      "",
    ].join("\n"),
  };
  const { definitions, dependencies, dependencyValidationSources } = await extractDependencyFixture(
    sources,
    "__depgraph_ts_dependency_empty_module_literal__",
  );
  assert.deepEqual(dependencies.issues, []);
  assert.doesNotThrow(() => validateTypeScriptRawDependencyDelta(
    dependencies,
    definitions,
    dependencyValidationSources,
  ));
  const emptyLiteralSites = dependencies.sites.filter((site) => (
    site.evidence.relativePath === "src/empty.ts"
    && site.moduleSpecifier === ""
  ));
  assert.deepEqual(
    [...new Set(emptyLiteralSites
      .filter((site) => site.kind !== "type_use")
      .map((site) => site.evidence.occurrenceKind))].sort(),
    ["dynamic_import", "named_import", "named_reexport", "require_call", "side_effect_import"],
  );
  assert.ok(emptyLiteralSites.filter((site) => site.kind !== "type_use").every((site) => (
    site.specifier === ""
    && site.status === "unresolved"
    && site.targets[0]?.kind === "unknown"
  )), JSON.stringify(emptyLiteralSites));
  assert.ok(dependencies.sites.some((site) => (
    site.evidence.occurrenceKind === "dynamic_import" && site.moduleSpecifier === "./template-lazy"
  )), JSON.stringify(dependencies.sites));
  assert.ok(dependencies.sites.some((site) => (
    site.evidence.occurrenceKind === "require_call" && site.moduleSpecifier === "template-package"
  )), JSON.stringify(dependencies.sites));
  assert.ok(dependencies.sites.some((site) => (
    site.evidence.occurrenceKind === "require_call" && site.moduleSpecifier === "optional-package"
  )), JSON.stringify(dependencies.sites));
  assert.ok(dependencies.sites.some((site) => (
    site.evidence.occurrenceKind === "require_call" && site.moduleSpecifier === "generic-package"
  )), JSON.stringify(dependencies.sites));
  const missingTypeUse = emptyLiteralSites.find((site) => (
    site.kind === "type_use" && site.importedName === "Missing"
  ));
  assert.equal(missingTypeUse?.specifier, "Missing");
  assert.deepEqual(missingTypeUse?.exportPath, ["Missing"]);
  assert.equal(missingTypeUse?.status, "unresolved");
  assert.equal(missingTypeUse?.targets[0]?.kind, "unknown");

  const computed = dependencies.sites.find((site) => (
    site.evidence.relativePath === "src/empty.ts"
    && site.evidence.occurrenceKind === "require_call"
    && site.reason === "computed_module_specifier"
  ));
  assert.equal(computed?.specifier, "name");
  assert.equal(computed?.moduleSpecifier, "name");
  const missing = dependencies.sites.find((site) => (
    site.evidence.relativePath === "src/empty.ts"
    && site.evidence.occurrenceKind === "require_call"
    && site.reason === "missing_module_specifier"
  ));
  assert.equal(missing?.specifier, "<missing>");
  assert.equal(missing?.moduleSpecifier, "<missing>");
});

test("scanner refinement keeps missing and ambiguous bindings unresolved", async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "depgraph-missing-require-"));
  context.after(async () => await rm(root, { recursive: true, force: true }));
  const sourceDirectory = path.join(root, "src");
  const packageFile = path.join(root, "package.json");
  const configFile = path.join(root, "tsconfig.json");
  const sourceFile = path.join(sourceDirectory, "index.ts");
  const firstOrigin = path.join(sourceDirectory, "a.ts");
  const secondOrigin = path.join(sourceDirectory, "b.ts");
  const ambiguousFile = path.join(sourceDirectory, "mid.ts");
  await mkdir(sourceDirectory, { recursive: true });
  await writeFile(packageFile, '{"name":"missing-require-fixture","version":"1.0.0","type":"module"}\n');
  await writeFile(configFile, '{"compilerOptions":{"module":"preserve","moduleResolution":"bundler","target":"esnext"},"files":["src/a.ts","src/b.ts","src/index.ts","src/mid.ts"]}\n');
  await writeFile(sourceFile, "require();\n");
  await writeFile(firstOrigin, "export interface Foo { readonly foo: true }\n");
  await writeFile(secondOrigin, "export interface Bar { readonly bar: true }\n");
  await writeFile(ambiguousFile, [
    'import { Foo as X } from "./a";',
    'import { Bar as X } from "./b";',
    "export { X };",
    "",
  ].join("\n"));
  const model = await scan(root, [
    packageFile,
    configFile,
    sourceFile,
    firstOrigin,
    secondOrigin,
    ambiguousFile,
  ]);
  const missingRequire = model.sites.find((site) => site.evidence.some((evidence) => (
    evidence.properties?.occurrence_kind === "require_call"
  )));
  assert.equal(missingRequire?.specifier, "<missing>");
  assert.equal(missingRequire?.resolution_status, "unresolved");
  assert.equal(missingRequire?.reason, "missing_module_specifier");
  assert.ok(missingRequire?.target_ids.every((id) => (
    model.nodes.find((node) => node.id === id)?.kind === "unknown_target"
  )));
  const ambiguousReexport = model.sites.find((site) => site.evidence.some((evidence) => (
    evidence.path === "src/mid.ts"
    && evidence.properties?.occurrence_kind === "named_reexport"
  )));
  assert.equal(ambiguousReexport?.specifier, "<ambiguous>");
  assert.equal(ambiguousReexport?.resolution_status, "unresolved");
  assert.equal(ambiguousReexport?.reason, "ambiguous_binding_provenance");
  assert.ok(ambiguousReexport?.target_ids.every((id) => (
    model.nodes.find((node) => node.id === id)?.kind === "unknown_target"
  )));
});

test("module export proofs follow finite requested paths through cyclic namespaces", async () => {
  const sources = {
    "src/a.ts": [
      'export * as b from "./b";',
      "export interface A { readonly value: string }",
      "",
    ].join("\n"),
    "src/b.ts": 'export * as a from "./a";\n',
    "src/consumer.ts": [
      'import type * as root from "./a";',
      "export type Cyclic = root.b.a.A;",
      "",
    ].join("\n"),
  };
  const { definitions, dependencies, dependencyValidationSources } = await extractDependencyFixture(
    sources,
    "__depgraph_ts_dependency_cyclic_namespace__",
  );
  assert.deepEqual(dependencies.issues, []);
  const definition = definitions.definitions.find((candidate) => (
    candidate.relativePath === "src/a.ts"
    && candidate.displayName === "A"
    && candidate.graphKind === "type"
  ));
  assert.ok(definition, JSON.stringify({ definitions: definitions.definitions, issues: definitions.issues }, null, 2));
  const proof = dependencies.moduleExports.find((candidate) => (
    candidate.relativePath === "src/a.ts"
    && JSON.stringify(candidate.exportPath) === JSON.stringify(["b", "a", "A"])
  ));
  assert.deepEqual(proof?.definitionKeys, [definition.key]);
  const typeUse = dependencies.sites.find((site) => (
    site.kind === "type_use"
    && site.evidence.relativePath === "src/consumer.ts"
    && JSON.stringify(site.exportPath) === JSON.stringify(["b", "a", "A"])
  ));
  assert.equal(typeUse?.resolutionMode, null);
  assert.equal(typeUse?.targets[0]?.kind, "definition");
});

test("dependency collector preserves explicit resolution-mode on imports and their type uses", async () => {
  const sources = {
    "src/modes.ts": [
      'import type { Required } from "mode-package" with { "resolution-mode": "require" };',
      'import type { Invalid } from "invalid-mode-package" with { "resolution-mode": "other" };',
      'export type Imported = import("mode-package", { with: { "resolution-mode": "require" } }).Required;',
      "export interface UsesRequired { readonly value: Required }",
      "export interface UsesInvalid { readonly value: Invalid }",
      "",
    ].join("\n"),
    "src/declaration-modes.ts": [
      'import { type ElementOnly } from "element-mode-package" with { "resolution-mode": "require" };',
      'import type { Multiple } from "multiple-mode-package" with { "resolution-mode": "require", type: "json" };',
      'export { type ExportOnly } from "export-mode-package" with { "resolution-mode": "require" };',
      "export interface UsesElementOnly { readonly value: ElementOnly }",
      "export interface UsesMultiple { readonly value: Multiple }",
      "",
    ].join("\n"),
    "src/legacy-mode.ts": [
      'import type { Legacy } from "legacy-mode-package" assert { "resolution-mode": "require" };',
      "export interface UsesLegacy { readonly value: Legacy }",
      "",
    ].join("\n"),
    "src/invalid-attribute-modes.ts": [
      'const request = "wrong-key-import-type-package";',
      'import type { WrongKey } from "wrong-key-mode-package" with { type: "json" };',
      'import type { EmptyMode } from "empty-mode-package" with {};',
      'import runtimeJson from "runtime-json-package" with { type: "json" };',
      'export type WrongKeyImportType = import("wrong-key-import-type-package", { with: { type: "json" } }).Value;',
      'export type EmptyImportType = import("empty-import-type-package", { with: {} }).Value;',
      'export type ComputedWrongKey = import(request, { with: { type: "json" } }).Value;',
      'export type ComputedInvalid = import(request, { with: { "resolution-mode": "other" } }).Value;',
      "export interface UsesWrongKey { readonly value: WrongKey }",
      "export interface UsesEmptyMode { readonly value: EmptyMode }",
      "export const runtimeValue = runtimeJson;",
      "",
    ].join("\n"),
    "src/jsdoc-mode.js": [
      '/** @import { JSDocMode } from "jsdoc-mode-package" with { "resolution-mode": "require" } */',
      "/** @typedef {{ value: JSDocMode }} UsesJSDocMode */",
      "export {};",
      "",
    ].join("\n"),
    "src/jsdoc-invalid-modes.js": [
      '/** @import { WrongJSDocMode } from "wrong-key-jsdoc-mode-package" with { type: "json" } */',
      '/** @import { EmptyJSDocMode } from "empty-jsdoc-mode-package" with {} */',
      "/** @typedef {{ wrong: WrongJSDocMode, empty: EmptyJSDocMode }} InvalidJSDocModes */",
      "export {};",
      "",
    ].join("\n"),
  };
  const { definitions, dependencies, dependencyValidationSources } = await extractDependencyFixture(
    sources,
    "__depgraph_ts_dependency_resolution_mode__",
  );
  assert.deepEqual(dependencies.issues, []);
  assert.doesNotThrow(() => validateTypeScriptRawDependencyDelta(
    dependencies,
    definitions,
    dependencyValidationSources,
  ));
  const modeSites = dependencies.sites.filter((site) => (
    site.moduleSpecifier === "mode-package"
    && (site.importedName === "Required" || site.evidence.occurrenceKind === "import_type")
  ));
  assert.ok(modeSites.length >= 4, JSON.stringify(dependencies.sites));
  assert.ok(modeSites.every((site) => site.typeOnly && site.resolutionMode === "require"), JSON.stringify(modeSites));
  const invalidSites = dependencies.sites.filter((site) => site.moduleSpecifier === "invalid-mode-package");
  assert.ok(invalidSites.length >= 2, JSON.stringify(dependencies.sites));
  assert.ok(invalidSites.every((site) => (
    site.resolutionMode === null
    && site.status === "unresolved"
    && site.reason === "invalid_resolution_mode"
    && site.targets[0]?.kind === "unknown"
  )), JSON.stringify(invalidSites));
  for (const moduleSpecifier of ["element-mode-package", "export-mode-package"]) {
    const sites = dependencies.sites.filter((site) => site.moduleSpecifier === moduleSpecifier);
    assert.ok(sites.length >= 1, JSON.stringify(dependencies.sites));
    assert.ok(sites.every((site) => (
      site.resolutionMode === null
      && site.status === "unresolved"
      && site.reason === "resolution_mode_requires_type_only"
      && site.targets[0]?.kind === "unknown"
    )), JSON.stringify(sites));
  }
  const multipleSites = dependencies.sites.filter((site) => site.moduleSpecifier === "multiple-mode-package");
  assert.ok(multipleSites.length >= 2, JSON.stringify(dependencies.sites));
  assert.ok(multipleSites.every((site) => (
    site.resolutionMode === null
    && site.status === "unresolved"
    && site.reason === "resolution_mode_requires_single_attribute"
    && site.targets[0]?.kind === "unknown"
  )), JSON.stringify(multipleSites));
  const legacySites = dependencies.sites.filter((site) => site.moduleSpecifier === "legacy-mode-package");
  assert.ok(legacySites.length >= 1, JSON.stringify(dependencies.sites));
  assert.ok(legacySites.every((site) => (
    site.resolutionMode === null
    && site.status === "unresolved"
    && site.reason === "syntax_invalid"
    && site.targets[0]?.kind === "unknown"
  )), JSON.stringify(legacySites));
  const jsdocSites = dependencies.sites.filter((site) => site.moduleSpecifier === "jsdoc-mode-package");
  assert.ok(jsdocSites.length >= 2, JSON.stringify(dependencies.sites));
  assert.ok(jsdocSites.every((site) => site.typeOnly && site.resolutionMode === "require"), JSON.stringify(jsdocSites));
  for (const moduleSpecifier of [
    "wrong-key-mode-package",
    "empty-mode-package",
    "wrong-key-import-type-package",
    "empty-import-type-package",
    "wrong-key-jsdoc-mode-package",
    "empty-jsdoc-mode-package",
  ]) {
    const sites = dependencies.sites.filter((site) => site.moduleSpecifier === moduleSpecifier);
    assert.ok(sites.length >= 1, `${moduleSpecifier}: ${JSON.stringify(dependencies.sites)}`);
    assert.ok(sites.every((site) => (
      site.resolutionMode === null
      && site.status === "unresolved"
      && site.reason === "resolution_mode_attribute_required"
      && site.targets[0]?.kind === "unknown"
    )), JSON.stringify(sites));
  }
  const computedModeSites = dependencies.sites.filter((site) => (
    site.evidence.relativePath === "src/invalid-attribute-modes.ts"
    && site.evidence.occurrenceKind === "import_type"
    && site.moduleSpecifier === "request"
  ));
  assert.equal(computedModeSites.length, 2, JSON.stringify(dependencies.sites));
  assert.deepEqual(
    computedModeSites.map((site) => site.reason).sort(),
    ["invalid_resolution_mode", "resolution_mode_attribute_required"],
  );
  const runtimeAttributeSites = dependencies.sites.filter((site) => site.moduleSpecifier === "runtime-json-package");
  assert.ok(runtimeAttributeSites.length >= 1, JSON.stringify(dependencies.sites));
  assert.ok(runtimeAttributeSites.every((site) => (
    !site.typeOnly
    && site.resolutionMode === null
    && site.reason !== "resolution_mode_attribute_required"
  )), JSON.stringify(runtimeAttributeSites));
});

test("scanner validation context carries parser validity and exact import-type spans", async () => {
  const sources = new Map<string, string>([
    ["src/a.ts", "export interface A { readonly value: string }\n"],
    ["src/valid.ts", [
      'import "./a";',
      'export type Inline = import("./a").A;',
      'void import("./a");',
      "",
    ].join("\n")],
    ["src/shadow.ts", [
      'void import("./a");',
      'const named = function require(value: string): string { return require("./a"); };',
      'const NamedClass = class require { static load(): unknown { return require("./a"); } };',
      "void named;",
      "void NamedClass;",
      "",
    ].join("\n")],
    ["src/generics.ts", [
      "export type Box<T> = { [K in keyof T]: T[K] };",
      "export function outer<T>(): void {",
      "  { class T { readonly value!: string } type Uses = T; void (0 as unknown as Uses); }",
      "}",
      'export function inline<A>(): void { type X = import("./a").A; void (0 as unknown as X); }',
      "",
    ].join("\n")],
    ["src/broken.ts", "type Broken = ;\n"],
  ]);
  const analysis = await analyzeTypeScriptProject(sources);
  const inventory = buildTypeScriptDependencyValidationSources(sources, analysis);
  const valid = inventory.find((source) => source.relativePath === "src/valid.ts");
  const broken = inventory.find((source) => source.relativePath === "src/broken.ts");
  assert.equal(valid?.syntacticallyValid, true);
  assert.equal(broken?.syntacticallyValid, false);
  const validText = sources.get("src/valid.ts")!;
  const importTypeStart = validText.indexOf('"./a"', validText.indexOf("import("));
  assert.deepEqual(valid?.importTypeModuleSpans, [{
    startOffset: importTypeStart,
    endOffset: importTypeStart + '"./a"'.length,
  }]);
  const shadow = inventory.find((source) => source.relativePath === "src/shadow.ts");
  assert.deepEqual(shadow?.moduleCallSpans.map((spanValue) => spanValue.occurrenceKind), ["dynamic_import"]);
  const generics = inventory.find((source) => source.relativePath === "src/generics.ts");
  const genericsText = sources.get("src/generics.ts")!;
  const mappedK = genericsText.indexOf("K]", genericsText.indexOf("T[K]"));
  const shadowedLocalT = genericsText.indexOf("T;", genericsText.indexOf("type Uses"));
  const importTypeQualifierA = genericsText.indexOf(".A;", genericsText.indexOf('import("./a")')) + 1;
  assert.equal(generics?.typeUseSpans.some((spanValue) => (
    spanValue.startOffset === mappedK && spanValue.terminalName === "K"
  )), false);
  assert.equal(generics?.typeUseSpans.some((spanValue) => (
    spanValue.startOffset === shadowedLocalT && spanValue.terminalName === "T"
  )), true);
  assert.equal(generics?.typeUseSpans.some((spanValue) => (
    spanValue.startOffset === importTypeQualifierA && spanValue.terminalName === "A"
  )), true);
  assert.doesNotThrow(() => validateTypeScriptRawDependencyDelta(
    analysis.dependencyGraph,
    analysis.definitionGraph,
    inventory,
  ));
  const validateMutation = (
    select: (delta: TypeScriptRawDependencyDelta) => number,
    mutate: (site: TypeScriptRawDependencyDelta["sites"][number]) => void,
    expected: RegExp,
  ): void => {
    const delta = structuredClone(analysis.dependencyGraph);
    const index = select(delta);
    assert.notEqual(index, -1);
    mutate(delta.sites[index]!);
    assert.throws(() => validateTypeScriptRawDependencyDelta(
      delta,
      analysis.definitionGraph,
      inventory,
    ), expected);
  };
  validateMutation(
    (delta) => delta.sites.findIndex((site) => site.evidence.occurrenceKind === "dynamic_import"),
    (site) => {
      site.evidence.occurrenceKind = "import_type";
      site.typeOnly = true;
    },
    /import occurrence contradicts parser context/u,
  );
  validateMutation(
    (delta) => delta.sites.findIndex((site) => site.evidence.occurrenceKind === "side_effect_import"),
    (site) => {
      site.evidence.targetBasis = "unresolved";
      site.status = "unresolved";
      site.precision = "heuristic";
      site.reason = "syntax_invalid";
      site.targets = [{ kind: "unknown" }];
      site.targetConditions = [structuredClone(site.condition)];
    },
    /contradicts parser-valid source/u,
  );
  validateMutation(
    (delta) => delta.sites.findIndex((site) => (
      site.evidence.relativePath === "src/shadow.ts"
      && site.evidence.occurrenceKind === "dynamic_import"
    )),
    (site) => {
      const source = sources.get("src/shadow.ts")!;
      const namedFunctionStart = source.indexOf("function require");
      const literalStart = source.indexOf('"./a"', namedFunctionStart);
      site.evidence.occurrenceKind = "require_call";
      site.evidence.startOffset = literalStart;
      site.evidence.endOffset = literalStart + '"./a"'.length;
    },
    /module call contradicts parser context/u,
  );
});

test("dependency source attestation handles ASI, contextual type bindings, and independent JSDoc import tags", async () => {
  const sources = {
    "src/asi.ts": [
      'import type { A } from "asi-a"',
      'import type { B } from "asi-b" with { "resolution-mode": "require" };',
      "export interface UsesASI { readonly a: A; readonly b: B }",
      "",
    ].join("\n"),
    "src/contextual-default.ts": [
      'import type from "runtime-default";',
      "export type UsesContextualDefault = typeof type;",
      "",
    ].join("\n"),
    "src/contextual-equals.ts": [
      'import type = require("runtime-equals");',
      "export type UsesContextualEquals = typeof type;",
      "",
    ].join("\n"),
    "src/after-template.ts": [
      'const name = "value";',
      "const key = `prefix-${name}`;",
      'const braces = /\\{(?:[^}]*)\\}/u;',
      'import type { A } from "after-template";',
      "export type UsesAfterTemplate = A;",
      "void key;",
      "void braces;",
      "",
    ].join("\n"),
    "src/after-jsx.tsx": [
      "const view = <section>{`value-${1}`}</section>;",
      'void import("after-jsx");',
      "export { view };",
      "",
    ].join("\n"),
    "src/jsdoc-tags.js": [
      "/**",
      ' * @import { A } from "jsdoc-a"',
      ' * @import { B } from "jsdoc-b"',
      " */",
      "/** @typedef {{ a: A, b: B }} UsesJSDocImports */",
      "export {};",
      "",
    ].join("\n"),
    "src/jsdoc-escaped.js": [
      '/** @import { B as \\u0043 } from "pkg\\u002dname" with { "resolution-mode": "require" } */',
      "/** @typedef {{ c: C }} UsesEscapedJSDocImport */",
      "export {};",
      "",
    ].join("\n"),
  };
  const { definitions, dependencies, dependencyValidationSources } = await extractDependencyFixture(
    sources,
    "__depgraph_ts_dependency_source_attestation__",
  );

  assert.deepEqual(dependencies.issues, []);
  assert.doesNotThrow(() => validateTypeScriptRawDependencyDelta(
    dependencies,
    definitions,
    dependencyValidationSources,
  ));
  const asiA = dependencies.sites.filter((site) => site.moduleSpecifier === "asi-a");
  const asiB = dependencies.sites.filter((site) => site.moduleSpecifier === "asi-b");
  assert.ok(asiA.length >= 2 && asiA.every((site) => site.resolutionMode === null), JSON.stringify(asiA));
  assert.ok(asiB.length >= 2 && asiB.every((site) => site.resolutionMode === "require"), JSON.stringify(asiB));
  const contextualDefault = dependencies.sites.find((site) => (
    site.evidence.relativePath === "src/contextual-default.ts"
    && site.evidence.occurrenceKind === "default_import"
  ));
  const contextualEquals = dependencies.sites.find((site) => (
    site.evidence.relativePath === "src/contextual-equals.ts"
    && site.evidence.occurrenceKind === "import_equals"
  ));
  assert.equal(contextualDefault?.typeOnly, false);
  assert.equal(contextualEquals?.typeOnly, false);
  assert.ok(dependencies.sites.some((site) => site.moduleSpecifier === "after-template"));
  assert.ok(dependencies.sites.some((site) => (
    site.moduleSpecifier === "after-jsx" && site.evidence.occurrenceKind === "dynamic_import"
  )));
  const escapedJSDoc = dependencies.sites.filter((site) => site.moduleSpecifier === "pkg-name");
  assert.ok(escapedJSDoc.length >= 2, JSON.stringify(dependencies.sites));
  assert.ok(escapedJSDoc.every((site) => site.resolutionMode === "require"), JSON.stringify(escapedJSDoc));
});

test("grammar-late non-literal static, import-equals, re-export, and JSDoc modules remain explicit", async () => {
  const sources = {
    "src/static-import.ts": [
      "declare const request: string;",
      "import Default from request;",
      "void (0 as unknown as Default);",
      "",
    ].join("\n"),
    "src/import-equals.ts": [
      "declare const request: string;",
      "import type API = require(request);",
      "type Uses = API.Value;",
      "",
    ].join("\n"),
    "src/static-export.ts": [
      "declare const request: string;",
      "export * from request;",
      "",
    ].join("\n"),
    "src/jsdoc.js": [
      'const request = "./missing";',
      "/** @import * as API from request */",
      "export {};",
      "",
    ].join("\n"),
  };
  const { definitions, dependencies, dependencyValidationSources } = await extractDependencyFixture(
    sources,
    "__depgraph_ts_dependency_non_literal_static_modules__",
  );
  assert.deepEqual(dependencies.issues, []);
  assert.doesNotThrow(() => validateTypeScriptRawDependencyDelta(
    dependencies,
    definitions,
    dependencyValidationSources,
  ));
  const expected = new Map([
    ["src/static-import.ts", "dynamic_import"],
    ["src/import-equals.ts", "import_equals"],
    ["src/static-export.ts", "export_star"],
    ["src/jsdoc.js", "import_type"],
  ]);
  for (const [relativePath, occurrenceKind] of expected) {
    const site = dependencies.sites.find((candidate) => (
      candidate.evidence.relativePath === relativePath
      && candidate.evidence.occurrenceKind === occurrenceKind
    ));
    assert.equal(site?.status, "unresolved", `${relativePath}: ${JSON.stringify(dependencies.sites)}`);
    assert.equal(site?.precision, "heuristic", relativePath);
    assert.equal(site?.reason, "non_literal_module_specifier", relativePath);
    assert.equal(site?.targets[0]?.kind, "unknown", relativePath);
  }
  const importEquals = dependencies.sites.find((site) => (
    site.evidence.relativePath === "src/import-equals.ts"
    && site.evidence.occurrenceKind === "import_equals"
  ));
  assert.equal(importEquals?.typeOnly, true);
  assert.equal(importEquals?.bindingKind, "import_equals");
  assert.equal(importEquals?.importedName, "=");
});

test("dependency collector recovers safe unresolved sites from broken source without TypeChecker queries", async () => {
  const sources = {
    "src/defs.ts": [
      "export interface SharedCollection { readonly value: string }",
      "export interface X { readonly value: string }",
      "export const ImportedValue = 1;",
      "",
    ].join("\n"),
    "src/types.ts": "export interface require { readonly typeOnly: true }\n",
    "src/broken.ts": [
      'import type { SharedCollection } from "./defs";',
      'import { ImportedValue } from "./defs";',
      'import "";',
      'export {} from "";',
      "export { SharedCollection };",
      'const literal = require("");',
      'const name = "";',
      "type require = string;",
      "void require(name);",
      "void require();",
      "function typeGeneric<require>(): unknown {",
      '  return require("./invalid-type-parameter-not-a-shadow");',
      "}",
      "function localScope(): void {",
      "  const require = (id: string): string => id;",
      "  function nested(): string { return require(\"./not-a-dependency\"); }",
      "  void nested();",
      "}",
      "type Query = typeof ImportedValue;",
      "type Broken = SharedCollection<;",
      "void literal;",
      "",
    ].join("\n"),
    "src/missing-import.ts": "import { Foo } from ;\n",
    "src/missing-export.ts": "export { Foo } from ;\n",
    "src/missing-import-binding.ts": 'import { Foo as } from "./defs";\n',
    "src/missing-export-binding.ts": 'export { Foo as } from "./defs";\n',
    "src/broken-type-import.ts": [
      'import type { require } from "./types";',
      'const loaded = require("./invalid-type-import-not-a-shadow");',
      "type Broken = require<;",
      "void loaded;",
      "",
    ].join("\n"),
    "src/broken-value-import.ts": [
      'import { ImportedValue as require } from "./defs";',
      'const loaded = require("./invalid-value-import-shadow");',
      "type Broken = ImportedValue<;",
      "void loaded;",
      "",
    ].join("\n"),
    "src/broken-contextual-from.ts": [
      'import { X as from } from "./defs";',
      "export { from };",
      "type Broken = X<;",
      "",
    ].join("\n"),
  };
  const { dependencies } = await extractDependencyFixture(
    sources,
    "__depgraph_ts_dependency_broken__",
    (checker) => new Proxy(checker, {
      get(target, property, receiver): unknown {
        if (property === "getSymbolAtLocation") {
          const query = checker.getSymbolAtLocation.bind(checker);
          return async (input: Node | readonly Node[]): Promise<CompilerSymbol | undefined | (CompilerSymbol | undefined)[]> => {
            const nodes = Array.isArray(input) ? input : [input as Node];
            if (nodes.some((node) => /(?:broken(?:-type-import|-value-import|-contextual-from)?|missing-(?:import|export)(?:-binding)?)\.ts$/u.test(
              String(node.getSourceFile().fileName),
            ))) {
              throw new Error("invalid source queried the TypeChecker");
            }
            return Array.isArray(input)
              ? await query(input as readonly Node[])
              : await query(input as Node);
          };
        }
        const value = Reflect.get(target, property, receiver) as unknown;
        return typeof value === "function" ? value.bind(target) : value;
      },
    }),
  );
  assert.deepEqual(dependencies.issues, []);
  assert.ok(dependencies.sites.some((site) => site.kind === "web_import"));
  assert.ok(dependencies.sites.some((site) => site.kind === "type_use"));
  assert.ok(dependencies.sites.some((site) => (
    site.evidence.relativePath === "src/broken.ts"
    && site.evidence.occurrenceKind === "named_reexport"
    && site.moduleSpecifier === "./defs"
    && site.importedName === "SharedCollection"
  )), JSON.stringify(dependencies.sites));
  assert.ok(dependencies.sites.some((site) => (
    site.kind === "type_use"
    && site.evidence.relativePath === "src/broken.ts"
    && site.importedName === "ImportedValue"
  )), JSON.stringify(dependencies.sites));
  const emptyLiteralOccurrences = dependencies.sites.filter((site) => (
    site.evidence.relativePath === "src/broken.ts"
    && site.kind !== "type_use"
    && site.moduleSpecifier === ""
  ));
  assert.deepEqual(
    [...new Set(emptyLiteralOccurrences.map((site) => site.evidence.occurrenceKind))].sort(),
    ["empty_reexport", "require_call", "side_effect_import"],
  );
  assert.ok(emptyLiteralOccurrences.every((site) => site.specifier === ""));
  assert.ok(dependencies.sites.some((site) => (
    site.evidence.relativePath === "src/broken.ts"
    && site.evidence.occurrenceKind === "require_call"
    && site.specifier === "name"
  )));
  assert.ok(dependencies.sites.some((site) => (
    site.evidence.relativePath === "src/broken.ts"
    && site.evidence.occurrenceKind === "require_call"
    && site.specifier === "<missing>"
  )));
  assert.ok(!dependencies.sites.some((site) => site.moduleSpecifier === "./not-a-dependency"));
  for (const moduleSpecifier of [
    "./invalid-type-parameter-not-a-shadow",
    "./invalid-type-import-not-a-shadow",
  ]) {
    assert.ok(dependencies.sites.some((site) => (
      site.evidence.occurrenceKind === "require_call"
      && site.moduleSpecifier === moduleSpecifier
    )), moduleSpecifier);
  }
  assert.ok(!dependencies.sites.some((site) => site.moduleSpecifier === "./invalid-value-import-shadow"));
  const missingImport = dependencies.sites.find((site) => (
    site.evidence.relativePath === "src/missing-import.ts"
    && site.evidence.occurrenceKind === "named_import"
    && site.importedName === "Foo"
  ));
  assert.equal(missingImport?.moduleSpecifier, "<missing>");
  assert.equal(missingImport?.status, "unresolved");
  const missingExport = dependencies.sites.find((site) => (
    site.evidence.relativePath === "src/missing-export.ts"
    && site.evidence.occurrenceKind === "named_reexport"
    && site.importedName === "Foo"
  ));
  assert.equal(missingExport?.moduleSpecifier, "<missing>");
  assert.equal(missingExport?.status, "unresolved");
  for (const relativePath of ["src/missing-import-binding.ts", "src/missing-export-binding.ts"]) {
    const recoveredModule = dependencies.sites.find((site) => (
      site.evidence.relativePath === relativePath
      && site.moduleSpecifier === "./defs"
    ));
    assert.equal(recoveredModule?.status, "unresolved", JSON.stringify(dependencies.sites));
  }
  const contextualFromExport = dependencies.sites.find((site) => (
    site.evidence.relativePath === "src/broken-contextual-from.ts"
    && site.evidence.occurrenceKind === "named_reexport"
    && site.importedName === "X"
  ));
  assert.equal(contextualFromExport?.moduleSpecifier, "./defs");
  assert.equal(contextualFromExport?.status, "unresolved");
  assert.ok(dependencies.sites.every((site) => (
    site.status === "unresolved"
    && site.precision === "heuristic"
    && site.reason === "syntax_invalid"
    && site.targets.length === 1
    && site.targets[0]?.kind === "unknown"
  )));
  assert.ok(dependencies.calls.length > 0);
  assert.ok(dependencies.calls.every((call) => (
    call.status === "unresolved"
    && call.precision === "heuristic"
    && call.reason === "syntax_invalid"
    && call.dispatch === "dynamic"
    && call.targets.length === 1
    && call.targets[0]?.kind === "unknown"
    && call.source.kind === "module_initializer"
  )));
});

test("broken local re-export recovery keeps import aliases scoped to their nearest namespace", async () => {
  const sources = {
    "src/scoped.ts": [
      "namespace Left {",
      '  import X = require("a");',
      "  export { X };",
      "}",
      "namespace Right {",
      '  import X = require("b");',
      "  export { X };",
      "}",
      "type Broken = ;",
      "",
    ].join("\n"),
  };
  const first = await extractDependencyFixture(
    sources,
    "__depgraph_ts_dependency_broken_scoped_alias_a__",
  );
  const second = await extractDependencyFixture(
    sources,
    "__depgraph_ts_dependency_broken_scoped_alias_z__",
  );

  assert.deepEqual(first.dependencies, second.dependencies);
  assert.deepEqual(first.dependencies.issues, []);
  assert.doesNotThrow(() => validateTypeScriptRawDependencyDelta(
    first.dependencies,
    first.definitions,
    first.dependencyValidationSources,
  ));
  const recovered = first.dependencies.sites.filter((site) => (
    site.evidence.relativePath === "src/scoped.ts"
    && site.evidence.occurrenceKind === "named_reexport"
    && site.importedName === "="
  ));
  assert.deepEqual(recovered.map((site) => site.moduleSpecifier).sort(), ["a", "b"]);
  assert.ok(recovered.every((site) => (
    site.status === "unresolved"
    && site.precision === "heuristic"
    && site.reason === "syntax_invalid"
    && site.targets.length === 1
    && site.targets[0]?.kind === "unknown"
  )), JSON.stringify(recovered));
});

test("raw dependency validator rejects ordering, identity, binding, status, span, path, and target mutations", async () => {
  const sources = {
    "src/a.ts": "export interface A { readonly value: string }\n",
    "src/b.ts": [
      'import type { A } from "./a";',
      'import type C = require("./a");',
      "export interface B { readonly item: A }",
      "export type UsesCInB = C;",
      "",
    ].join("\n"),
    "src/c.ts": 'import type C = require("./a");\nexport type UsesC = C;\n',
    "src/equals.ts": 'export { A as "=", A as "*" } from "./a";\n',
    "src/uses-equals.ts": [
      'import type { "=" as Equal, "*" as Star } from "./equals";',
      "export type UsesEqual = Equal;",
      "export type UsesStar = Star;",
      "",
    ].join("\n"),
  };
  const { definitions, dependencies, dependencyValidationSources } = await extractDependencyFixture(
    sources,
    "__depgraph_ts_dependency_validation__",
  );
  const inventory = dependencyValidationSources;
  assert.ok(dependencies.sites.length > 1);
  assert.ok(definitions.definitions.length > 0, JSON.stringify(definitions.issues));

  const validate = (mutate: (delta: TypeScriptRawDependencyDelta) => void, expected: RegExp): void => {
    const delta = structuredClone(dependencies);
    mutate(delta);
    assert.throws(() => validateTypeScriptRawDependencyDelta(delta, definitions, inventory), expected);
  };
  validate((delta) => delta.sites.reverse(), /strictly sorted/u);
  validate((delta) => delta.sites.splice(1, 0, structuredClone(delta.sites[0]!)), /strictly sorted/u);
  validate((delta) => { (delta.sites[0] as { status: string }).status = "ready"; }, /status is invalid/u);
  validate((delta) => { delete (delta.sites[0] as { typeOnly?: boolean }).typeOnly; }, /type-only marker is invalid/u);
  validate((delta) => { delta.sites[0]!.evidence.endOffset = delta.sites[0]!.evidence.startOffset; }, /evidence is invalid/u);
  validate((delta) => { delta.sites[0]!.evidence.relativePath = "../escape.ts"; }, /evidence is invalid/u);
  validate((delta) => { delta.sites[0]!.targetConditions.pop(); }, /target conditions do not align/u);
  validate((delta) => {
    delta.sites[0]!.condition = { op: "eq", key: "environment", value: "spoofed" };
  }, /not the aggregate/u);
  validate((delta) => {
    delta.sites[0]!.condition = { op: "all", conditions: [delta.sites[0]!.condition] };
  }, /condition is not canonical/u);
  validate((delta) => {
    const invalid = { op: "eq" as const, key: "environment", value: -0 };
    delta.sites[0]!.condition = invalid;
    delta.sites[0]!.targetConditions = delta.sites[0]!.targets.map(() => invalid);
  }, /condition value is invalid/u);

  const importIndex = dependencies.sites.findIndex((site) => site.kind === "web_import");
  assert.notEqual(importIndex, -1);
  const definition = definitions.definitions[0]!;
  validate((delta) => {
    delta.sites[importIndex]!.source = { kind: "definition", key: definition.key };
  }, /source is not its evidence file/u);
  const namedImportIndex = dependencies.sites.findIndex((site) => site.evidence.occurrenceKind === "named_import");
  assert.notEqual(namedImportIndex, -1);
  validate((delta) => { delta.sites[namedImportIndex]!.exportPath = null; }, /occurrence metadata shape is invalid/u);
  validate((delta) => {
    (delta.sites[namedImportIndex] as unknown as { resolutionMode: string }).resolutionMode = "node";
  }, /resolution mode is invalid/u);
  validate((delta) => {
    delta.sites[namedImportIndex]!.resolutionMode = "require";
  }, /direct binding syntax does not correlate|resolution mode proof is invalid/u);
  validate((delta) => {
    delta.sites[namedImportIndex]!.bindingKind = "import_equals";
  }, /direct binding syntax does not correlate|occurrence binding kind is invalid/u);
  validate((delta) => {
    delta.sites[namedImportIndex]!.resolutionMode = "require";
    delta.sites[namedImportIndex]!.typeOnly = false;
  }, /direct binding syntax does not correlate|resolution mode contradicts its occurrence/u);
  const importEqualsIndex = dependencies.sites.findIndex((site) => site.evidence.occurrenceKind === "import_equals");
  assert.notEqual(importEqualsIndex, -1);
  validate((delta) => {
    delta.sites[importEqualsIndex]!.resolutionMode = "require";
  }, /direct binding syntax does not correlate|import-equals occurrence cannot expose/u);
  const namedTypeUseIndex = dependencies.sites.findIndex((site) => (
    site.kind === "type_use"
    && site.bindingKind === "named"
    && site.importedName === "A"
  ));
  assert.notEqual(namedTypeUseIndex, -1);
  validate((delta) => {
    delta.sites[namedTypeUseIndex]!.bindingKind = "import_equals";
  }, /binding origin does not correlate|import-equals origin is missing/u);
  validate((delta) => {
    delta.sites[namedTypeUseIndex]!.resolutionMode = "require";
  }, /resolution mode proof is invalid/u);
  validate((delta) => {
    const namedUse = delta.sites[namedTypeUseIndex]!;
    const unrelatedOrigin = delta.sites.find((site) => (
      site.evidence.occurrenceKind === "import_equals"
      && site.evidence.relativePath === namedUse.evidence.relativePath
      && site.moduleSpecifier === namedUse.moduleSpecifier
    ));
    assert.ok(unrelatedOrigin);
    namedUse.bindingKind = "import_equals";
    namedUse.bindingOrigin = {
      siteKey: unrelatedOrigin.key,
      declarationStartOffset: unrelatedOrigin.evidence.startOffset,
      declarationEndOffset: unrelatedOrigin.evidence.endOffset,
      scopeStartOffset: 0,
      scopeEndOffset: sources[namedUse.evidence.relativePath as keyof typeof sources].length,
      referenceStartOffset: unrelatedOrigin.evidence.startOffset,
      referenceEndOffset: unrelatedOrigin.evidence.endOffset,
    };
  }, /origin does not correlate/u);
  const importEqualsTypeUseIndex = dependencies.sites.findIndex((site) => (
    site.kind === "type_use"
    && site.bindingKind === "import_equals"
  ));
  assert.notEqual(importEqualsTypeUseIndex, -1);
  validate((delta) => {
    delta.sites[importEqualsTypeUseIndex]!.bindingKind = "named";
  }, /binding origin does not correlate/u);
  validate((delta) => {
    delta.sites[importEqualsTypeUseIndex]!.bindingKind = "named";
    delta.sites[importEqualsTypeUseIndex]!.bindingOrigin = null;
  }, /type-use occurrence contradicts parser context|imported binding origin is missing/u);
  validate((delta) => {
    delta.sites[importEqualsTypeUseIndex]!.bindingOrigin!.siteKey = "site:spoofed";
  }, /origin does not correlate/u);
  const quotedEqualsUseIndex = dependencies.sites.findIndex((site) => (
    site.kind === "type_use"
    && site.bindingKind === "named"
    && site.importedName === "="
  ));
  assert.notEqual(quotedEqualsUseIndex, -1);
  validate((delta) => {
    delta.sites[quotedEqualsUseIndex]!.exportPath = [];
  }, /binding origin does not correlate|export path is invalid/u);
  const quotedStarUseIndex = dependencies.sites.findIndex((site) => (
    site.kind === "type_use"
    && site.bindingKind === "named"
    && site.importedName === "*"
  ));
  assert.notEqual(quotedStarUseIndex, -1);
  validate((delta) => {
    delta.sites[quotedStarUseIndex]!.exportPath = [];
  }, /binding origin does not correlate|export path is invalid/u);

  const targetIndex = dependencies.sites.findIndex((site) => site.targets.some((target) => target.kind === "definition"));
  assert.notEqual(targetIndex, -1);
  validate((delta) => {
    delta.sites[targetIndex]!.targets = [{ kind: "definition", key: "definition:missing" }];
  }, /target definition is missing/u);
  const typeUseIndex = dependencies.sites.findIndex((site) => site.kind === "type_use");
  assert.notEqual(typeUseIndex, -1);
  validate((delta) => { delta.sites[typeUseIndex]!.typeOnly = false; }, /contradicts its occurrence/u);
  validate((delta) => { delta.sites[typeUseIndex]!.exportPath = []; }, /binding origin does not correlate|export path is invalid/u);
});

test("raw dependency source attestation rejects coordinated phase, re-export, module, and scope mutations", async () => {
  const sources = {
    "src/a.ts": "export interface A { readonly value: string }\n",
    "src/other.ts": "export interface Other { readonly value: number }\n",
    "src/consumer.ts": [
      'import "./a";',
      'const metadata = { "resolution-mode": "require" };',
      'export type { A } from "./a";',
      'export type Inline = import("./a").A;',
      'void import("./other");',
      'const request = "./other";',
      "void import(request);",
      "type ComputedInline = import(request).A;",
      "const holder = { require(value: string): string { return value; } };",
      "holder?.require(request);",
      "const loader = {",
      "  require(value: string): string { return value; },",
      "  import(value: string): string { return value; },",
      "};",
      'loader.require("./a");',
      'loader.import("./a");',
      '"require"("./a");',
      "function require(request: string): string { return request; }",
      'import { A as LocalA } from "./a";',
      "export { LocalA as LocalAlias };",
      "export type LocalUse = LocalA;",
      "interface LocalTypeA { readonly a: string }",
      "interface LocalTypeB { readonly b: number }",
      "export type LocalTypeUse = LocalTypeA;",
      "",
    ].join("\n"),
    "src/scoped.ts": [
      "namespace Left {",
      '  import API = require("./a");',
      "  export type Uses = API.A;",
      "}",
      "namespace Right {",
      '  import API = require("./other");',
      "}",
      "",
    ].join("\n"),
  };
  const { definitions, dependencies, dependencyValidationSources } = await extractDependencyFixture(
    sources,
    "__depgraph_ts_dependency_source_mutations__",
  );
  const inventory = dependencyValidationSources;
  assert.deepEqual(dependencies.issues, []);
  assert.doesNotThrow(() => validateTypeScriptRawDependencyDelta(dependencies, definitions, inventory));
  const validate = (mutate: (delta: TypeScriptRawDependencyDelta) => void, expected: RegExp): void => {
    const delta = structuredClone(dependencies);
    mutate(delta);
    assert.throws(() => validateTypeScriptRawDependencyDelta(delta, definitions, inventory), expected);
  };
  const forceUnresolvedReason = (
    site: TypeScriptRawDependencyDelta["sites"][number],
    reason: string,
  ): void => {
    site.evidence.targetBasis = "unresolved";
    site.status = "unresolved";
    site.precision = "heuristic";
    site.reason = reason;
    site.targets = [{ kind: "unknown" }];
    site.targetConditions = [structuredClone(site.condition)];
  };

  const sideEffectIndex = dependencies.sites.findIndex((site) => site.evidence.occurrenceKind === "side_effect_import");
  assert.notEqual(sideEffectIndex, -1);
  validate((delta) => {
    delta.sites[sideEffectIndex]!.evidence.occurrenceKind = "require_call";
  }, /module call contradicts parser context/u);
  validate((delta) => {
    const site = delta.sites[sideEffectIndex]!;
    site.evidence.occurrenceKind = "require_call";
    site.evidence.targetBasis = "unresolved";
    site.status = "unresolved";
    site.precision = "heuristic";
    site.reason = "computed_module_specifier";
    site.targets = [{ kind: "unknown" }];
    site.targetConditions = [structuredClone(site.condition)];
  }, /module call contradicts parser context/u);
  for (const reason of [
    "duplicate_resolution_mode",
    "invalid_resolution_mode",
    "invalid_resolution_mode_syntax",
    "resolution_mode_attribute_required",
    "resolution_mode_requires_single_attribute",
    "resolution_mode_requires_type_only",
  ]) {
    validate((delta) => {
      forceUnresolvedReason(delta.sites[sideEffectIndex]!, reason);
    }, /module occurrence syntax does not correlate/u);
  }

  const directReexportIndex = dependencies.sites.findIndex((site) => (
    site.kind === "web_reexport"
    && site.bindingOrigin === null
    && site.evidence.occurrenceKind === "named_reexport"
  ));
  assert.notEqual(directReexportIndex, -1);
  validate((delta) => {
    delta.sites[directReexportIndex]!.importedName = "Other";
    delta.sites[directReexportIndex]!.exportPath = ["Other"];
  }, /re-export syntax does not correlate/u);
  const metadata = sources["src/consumer.ts"];
  const keyStartOffset = metadata.indexOf('"resolution-mode"');
  const valueStartOffset = metadata.indexOf('"require"');
  validate((delta) => {
    const site = delta.sites[directReexportIndex]!;
    site.resolutionMode = "require";
    site.resolutionModeProof = {
      keyStartOffset,
      keyEndOffset: keyStartOffset + '"resolution-mode"'.length,
      valueStartOffset,
      valueEndOffset: valueStartOffset + '"require"'.length,
    };
  }, /re-export syntax does not correlate/u);

  const importTypeIndex = dependencies.sites.findIndex((site) => site.evidence.occurrenceKind === "import_type");
  assert.notEqual(importTypeIndex, -1);
  validate((delta) => {
    delta.sites[importTypeIndex]!.specifier = "./other";
    delta.sites[importTypeIndex]!.moduleSpecifier = "./other";
    for (const site of delta.sites) {
      if (site.kind === "type_use" && site.bindingOrigin === null && site.moduleSpecifier === "./a") {
        site.moduleSpecifier = "./other";
      }
    }
  }, /module occurrence syntax does not correlate/u);
  validate((delta) => {
    delta.sites[importTypeIndex]!.evidence.occurrenceKind = "dynamic_import";
    delta.sites[importTypeIndex]!.typeOnly = false;
  }, /import occurrence contradicts parser context/u);
  const dynamicImportIndex = dependencies.sites.findIndex((site) => (
    site.evidence.occurrenceKind === "dynamic_import" && site.moduleSpecifier === "./other"
  ));
  assert.notEqual(dynamicImportIndex, -1);
  validate((delta) => {
    delta.sites[dynamicImportIndex]!.evidence.occurrenceKind = "import_type";
    delta.sites[dynamicImportIndex]!.typeOnly = true;
  }, /import occurrence contradicts parser context/u);
  validate((delta) => {
    const site = delta.sites[dynamicImportIndex]!;
    site.evidence.targetBasis = "unresolved";
    site.specifier = '"./other"';
    site.moduleSpecifier = '"./other"';
    site.status = "unresolved";
    site.precision = "heuristic";
    site.reason = "computed_module_specifier";
    site.targets = [{ kind: "unknown" }];
    site.targetConditions = [structuredClone(site.condition)];
  }, /module call contradicts parser context/u);
  validate((delta) => {
    delta.sites[dynamicImportIndex]!.reason = "non_literal_module_specifier";
  }, /module call contradicts parser context/u);
  validate((delta) => {
    delta.sites[dynamicImportIndex]!.reason = "ambiguous_binding_provenance";
  }, /module call contradicts parser context/u);
  for (const reason of [
    "duplicate_resolution_mode",
    "invalid_resolution_mode",
    "invalid_resolution_mode_syntax",
    "resolution_mode_attribute_required",
    "resolution_mode_requires_single_attribute",
    "resolution_mode_requires_type_only",
  ]) {
    validate((delta) => {
      forceUnresolvedReason(delta.sites[dynamicImportIndex]!, reason);
    }, /module call contradicts parser context/u);
  }

  const computedDynamicIndex = dependencies.sites.findIndex((site) => (
    site.evidence.occurrenceKind === "dynamic_import" && site.reason === "computed_module_specifier"
  ));
  const nonLiteralImportTypeIndex = dependencies.sites.findIndex((site) => (
    site.evidence.occurrenceKind === "import_type" && site.reason === "non_literal_module_specifier"
  ));
  assert.notEqual(computedDynamicIndex, -1);
  assert.notEqual(nonLiteralImportTypeIndex, -1);
  validate((delta) => {
    delta.sites[computedDynamicIndex]!.reason = "non_literal_module_specifier";
  }, /module call contradicts parser context/u);
  validate((delta) => {
    delta.sites[nonLiteralImportTypeIndex]!.reason = "computed_module_specifier";
  }, /safely-unresolved dependency syntax does not correlate/u);
  validate((delta) => {
    const site = delta.sites[computedDynamicIndex]!;
    const optionalCallStart = sources["src/consumer.ts"].indexOf("holder?.require(request)");
    const optionalArgumentStart = sources["src/consumer.ts"].indexOf("request", optionalCallStart);
    site.evidence.occurrenceKind = "require_call";
    site.evidence.startOffset = optionalArgumentStart;
    site.evidence.endOffset = optionalArgumentStart + "request".length;
  }, /module call contradicts parser context/u);
  validate((delta) => {
    const site = delta.sites[computedDynamicIndex]!;
    const declarationStart = sources["src/consumer.ts"].indexOf("function require(request");
    const parameterStart = sources["src/consumer.ts"].indexOf("request", declarationStart);
    site.evidence.occurrenceKind = "require_call";
    site.evidence.startOffset = parameterStart;
    site.evidence.endOffset = parameterStart + "request".length;
  }, /module call contradicts parser context/u);

  const validateFabricatedLiteralCall = (callee: string, occurrenceKind: "require_call" | "dynamic_import"): void => {
    validate((delta) => {
      const site = delta.sites[dynamicImportIndex]!;
      const callStart = sources["src/consumer.ts"].indexOf(`${callee}("./a")`);
      const literalStart = sources["src/consumer.ts"].indexOf('"./a"', callStart);
      assert.notEqual(callStart, -1);
      assert.notEqual(literalStart, -1);
      site.evidence.occurrenceKind = occurrenceKind;
      site.evidence.startOffset = literalStart;
      site.evidence.endOffset = literalStart + '"./a"'.length;
      site.specifier = "./a";
      site.moduleSpecifier = "./a";
    }, /module call contradicts parser context/u);
  };
  validateFabricatedLiteralCall("loader.require", "require_call");
  validateFabricatedLiteralCall("loader.import", "dynamic_import");
  validateFabricatedLiteralCall('"require"', "require_call");

  const localReexportIndex = dependencies.sites.findIndex((site) => (
    site.kind === "web_reexport" && site.bindingOrigin !== null
  ));
  assert.notEqual(localReexportIndex, -1);
  validate((delta) => {
    delta.sites[localReexportIndex]!.bindingOrigin = null;
  }, /re-export syntax does not correlate/u);
  assert.equal(dependencies.sites[localReexportIndex]!.typeOnly, false);
  validate((delta) => {
    delta.sites[localReexportIndex]!.typeOnly = true;
  }, /re-export syntax does not correlate/u);
  validate((delta) => {
    const site = delta.sites[localReexportIndex]!;
    site.evidence.targetBasis = "unresolved";
    site.specifier = "<ambiguous>";
    site.moduleSpecifier = "<ambiguous>";
    site.importedName = "LocalA";
    site.exportPath = ["LocalA"];
    site.bindingOrigin = null;
    site.status = "unresolved";
    site.precision = "heuristic";
    site.reason = "ambiguous_binding_provenance";
    site.targets = [{ kind: "unknown" }];
    site.targetConditions = [structuredClone(site.condition)];
  }, /safely-unresolved dependency syntax does not correlate/u);

  const localTypeUseIndex = dependencies.sites.findIndex((site) => (
    site.kind === "type_use"
    && site.evidence.relativePath === "src/consumer.ts"
    && sources["src/consumer.ts"].slice(site.evidence.startOffset, site.evidence.endOffset) === "LocalA"
  ));
  assert.notEqual(localTypeUseIndex, -1);
  validate((delta) => {
    forceUnresolvedReason(delta.sites[localTypeUseIndex]!, "invalid_resolution_mode");
  }, /binding origin does not correlate/u);
  validate((delta) => {
    const site = delta.sites[localTypeUseIndex]!;
    site.evidence.targetBasis = "unresolved";
    site.specifier = "LocalA";
    site.moduleSpecifier = null;
    site.importedName = "LocalA";
    site.exportPath = null;
    site.bindingKind = null;
    site.bindingOrigin = null;
    site.resolutionMode = null;
    site.resolutionModeProof = null;
    site.status = "unresolved";
    site.precision = "heuristic";
    site.reason = "ambiguous_binding_provenance";
    site.targets = [{ kind: "unknown" }];
    site.targetConditions = [structuredClone(site.condition)];
  }, /safely-unresolved dependency syntax does not correlate/u);

  const localNamedTypeUseIndex = dependencies.sites.findIndex((site) => (
    site.kind === "type_use"
    && site.bindingOrigin === null
    && site.evidence.relativePath === "src/consumer.ts"
    && sources["src/consumer.ts"].slice(site.evidence.startOffset, site.evidence.endOffset) === "LocalTypeA"
  ));
  const localTypeB = definitions.definitions.find((definition) => definition.displayName === "LocalTypeB");
  assert.notEqual(localNamedTypeUseIndex, -1);
  assert.ok(localTypeB);
  validate((delta) => {
    const site = delta.sites[localNamedTypeUseIndex]!;
    site.specifier = "LocalTypeB";
    site.importedName = "LocalTypeB";
    site.targets = [{ kind: "definition", key: localTypeB.key }];
    site.targetConditions = [structuredClone(site.condition)];
  }, /type-use occurrence contradicts parser context/u);

  const scopedImportIndex = dependencies.sites.findIndex((site) => (
    site.evidence.relativePath === "src/scoped.ts"
    && site.evidence.occurrenceKind === "import_equals"
    && site.moduleSpecifier === "./a"
  ));
  assert.notEqual(scopedImportIndex, -1);
  validate((delta) => {
    delta.sites[scopedImportIndex]!.bindingScope = {
      startOffset: 0,
      endOffset: sources["src/scoped.ts"].length,
    };
  }, /direct binding syntax does not correlate/u);

  validate((delta) => {
    delta.sites[directReexportIndex]!.reason = "syntax_invalid";
  }, /contradicts parser-valid source|status\/precision\/target contract is invalid/u);
});

test("dependency extraction atomically discards partial sites on TypeChecker batch or correlation spoof", async () => {
  const sources = {
    "src/a.ts": "export interface A { readonly value: string }\nexport function target(): void {}\n",
    "src/b.ts": 'import type { A } from "./a";\nimport { target } from "./a";\ninterface B { readonly item: A }\ntarget();\n',
  };
  const cases: Array<{ name: string; transform: (checker: Checker) => Checker; message: RegExp }> = [
    {
      name: "cardinality",
      transform: (checker) => transformCheckerBatches(checker, {
        symbols: (_nodes, values) => [...values, undefined],
      }),
      message: /batch cardinality mismatch/u,
    },
    {
      name: "correlation",
      transform: (checker) => transformCheckerBatches(checker, {
        symbols: (_nodes, values) => values.map((value) => value === undefined
          ? undefined
          : new Proxy(value, {
            get(target, property, receiver): unknown {
              if (property === "id") return target.id + 1;
              return Reflect.get(target, property, receiver) as unknown;
            },
          })),
      }),
      message: /response correlation mismatch/u,
    },
  ];
  for (const fixtureCase of cases) {
    const { dependencies } = await extractDependencyFixture(
      sources,
      `__depgraph_ts_dependency_spoof_${fixtureCase.name}__`,
      fixtureCase.transform,
    );
    assert.deepEqual(dependencies.sites, [], fixtureCase.name);
    assert.deepEqual(dependencies.calls, [], fixtureCase.name);
    assert.equal(dependencies.issues.length, 1, fixtureCase.name);
    assert.equal(dependencies.issues[0]?.fatal, true, fixtureCase.name);
    assert.match(dependencies.issues[0]?.message ?? "", fixtureCase.message, fixtureCase.name);
  }
});

test("JSDoc import tags emit canonical type-only import sites and preserve binding provenance", async () => {
  const { definitions, dependencies } = await extractDependencyFixture({
    "src/a.js": "export class A {}\n",
    "src/use.js": [
      "/**",
      " * @import {",
      " *   A",
      ' * } from "./a"',
      " */",
      "/**",
      " * @import {",
      " * } from \"./a\"",
      " */",
      "/** @type {A} */",
      "export const value = null;",
      "",
    ].join("\n"),
  }, "__depgraph_ts_dependency_jsdoc_import__");
  assert.deepEqual(dependencies.issues, []);
  const importSite = dependencies.sites.find((site) => (
    site.kind === "web_import"
    && site.evidence.occurrenceKind === "named_import"
    && site.importedName === "A"
  ));
  assert.equal(importSite?.specifier, "./a");
  assert.equal(importSite?.moduleSpecifier, "./a");
  assert.equal(importSite?.typeOnly, true);
  assert.equal(importSite?.status, "resolved");
  assert.equal(importSite?.precision, "exact");
  assert.equal(importSite?.targets[0]?.kind, "definition");
  const emptyImport = dependencies.sites.find((site) => (
    site.kind === "web_import"
    && site.evidence.occurrenceKind === "empty_import"
    && site.moduleSpecifier === "./a"
  ));
  assert.equal(emptyImport?.typeOnly, true);
  assert.equal(emptyImport?.status, "resolved");
  assert.equal(emptyImport?.precision, "exact");
  assert.equal(emptyImport?.targets[0]?.kind, "file");
  const typeUse = dependencies.sites.find((site) => (
    site.kind === "type_use" && site.importedName === "A"
  ));
  assert.equal(dependencies.sites.filter((site) => (
    site.kind === "type_use" && site.importedName === "A"
  )).length, 1, JSON.stringify(dependencies.sites));
  assert.equal(typeUse?.moduleSpecifier, "./a");
  assert.equal(typeUse?.typeOnly, true);
  assert.equal(typeUse?.source.kind, "definition");
  assert.equal(typeUse?.status, "resolved");
  assert.equal(typeUse?.precision, "exact");
  const typeTarget = typeUse?.targets[0];
  assert.equal(typeTarget?.kind, "definition");
  assert.equal(
    typeTarget?.kind === "definition"
      ? definitions.definitions.find((definition) => definition.key === typeTarget.key)?.graphKind
      : null,
    "type",
  );
});

test("value symbols used as types fail one site closed without discarding other dependency sites", async () => {
  const sources = {
    "src/defs.ts": `
export const ValueOnly = 1;
export interface RealType { readonly value: string }
`,
    "src/use.ts": `
import { ValueOnly, type RealType } from "./defs";
interface Uses {
  readonly invalid: ValueOnly;
  readonly valid: RealType;
  readonly query: typeof import("./defs").ValueOnly;
}
`,
  };
  const { definitions, dependencies } = await extractDependencyFixture(
    sources,
    "__depgraph_ts_dependency_value_type__",
  );
  assert.deepEqual(dependencies.issues, []);
  const valueUses = dependencies.sites.filter((site) => (
    site.kind === "type_use" && site.importedName === "ValueOnly"
  ));
  assert.ok(valueUses.length >= 2);
  assert.ok(valueUses.every((site) => (
    site.status === "unresolved"
    && ["value_symbol_is_not_a_type", "typechecker_target_unresolved"].includes(site.reason ?? "")
    && site.targets[0]?.kind === "unknown"
  )), JSON.stringify(valueUses));
  const realUse = dependencies.sites.find((site) => (
    site.kind === "type_use" && site.importedName === "RealType"
  ));
  assert.equal(realUse?.status, "resolved");
  const realTarget = realUse?.targets[0];
  assert.equal(realTarget?.kind, "definition");
  assert.equal(
    realTarget?.kind === "definition"
      ? definitions.definitions.find((definition) => definition.key === realTarget.key)?.semanticKind
      : null,
    "interface",
  );
});

test("case-distinct compiler paths remain distinct and setup failures are contained as fatal empty deltas", async () => {
  const sources = {
    "src/A.ts": "export interface Upper { readonly upper: string }\n",
    "src/a.ts": "export interface Lower { readonly lower: string }\n",
    "src/use.ts": `
import type { Upper } from "./A";
import type { Lower } from "./a";
interface Uses { readonly upper: Upper; readonly lower: Lower }
`,
  };
  const first = await extractDependencyFixture(sources, "__depgraph_ts_dependency_case_distinct__");
  if (process.platform === "win32" || process.platform === "darwin") {
    assert.deepEqual(first.dependencies.sites, []);
    assert.match(first.dependencies.issues[0]?.message ?? "", /source paths collide/u);
  } else {
    assert.deepEqual(first.dependencies.issues, []);
    const definitions = new Map(first.definitions.definitions.map((definition) => [definition.key, definition]));
    const targetPaths = first.dependencies.sites
      .filter((site) => site.kind === "type_use" && ["Upper", "Lower"].includes(site.importedName ?? ""))
      .flatMap((site) => site.targets)
      .filter((target): target is Extract<typeof target, { kind: "definition" }> => target.kind === "definition")
      .map((target) => definitions.get(target.key)?.relativePath)
      .sort();
    assert.deepEqual(targetPaths, ["src/A.ts", "src/a.ts"]);
  }

  const collided = await extractDependencyFixture(
    sources,
    "__depgraph_ts_dependency_path_collision__",
    undefined,
    (inputs) => inputs.map((input, index) => index === 1
      ? { ...input, compilerPath: inputs[0]!.compilerPath }
      : input),
  );
  assert.deepEqual(collided.dependencies.sites, []);
  assert.equal(collided.dependencies.issues.length, 1);
  assert.equal(collided.dependencies.issues[0]?.fatal, true);
  assert.match(collided.dependencies.issues[0]?.message ?? "", /source paths collide/u);
});

test("spoofed compiler declaration spans fail atomically instead of being clamped", async () => {
  const sources = {
    "src/a.ts": "export const value = 1;\n",
    "src/b.ts": 'import { value } from "./a";\nvoid value;\n',
  };
  const corruptDeclarationSpans = (checker: Checker): Checker => {
    const query = checker.getSymbolAtLocation.bind(checker);
    const queryAlias = checker.getAliasedSymbol.bind(checker);
    const queryUnknown = checker.isUnknownSymbol.bind(checker);
    const wrapped = new Map<number, CompilerSymbol>();
    const originals = new Map<CompilerSymbol, CompilerSymbol>();
    const wrapSymbol = (symbol: CompilerSymbol | undefined): CompilerSymbol | undefined => {
      if (symbol === undefined) return undefined;
      const cached = wrapped.get(symbol.id);
      if (cached !== undefined) return cached;
      const proxy = new Proxy(symbol, {
        get(target, property, receiver): unknown {
          if (property === "declarations") {
            return target.declarations.map((declaration) => new Proxy(declaration, {
              get(declarationTarget, declarationProperty, declarationReceiver): unknown {
                if (declarationProperty === "resolve") {
                  return async (): Promise<Node | undefined> => {
                    const resolved = await declarationTarget.resolve();
                    if (resolved === undefined) return undefined;
                    return new Proxy(resolved, {
                      get(nodeTarget, nodeProperty, nodeReceiver): unknown {
                        if (nodeProperty === "getStart") return (): number => Number.MAX_SAFE_INTEGER;
                        return Reflect.get(nodeTarget, nodeProperty, nodeReceiver) as unknown;
                      },
                    });
                  };
                }
                return Reflect.get(declarationTarget, declarationProperty, declarationReceiver) as unknown;
              },
            }));
          }
          return Reflect.get(target, property, receiver) as unknown;
        },
      });
      wrapped.set(symbol.id, proxy);
      originals.set(proxy, symbol);
      return proxy;
    };
    return new Proxy(checker, {
      get(target, property, receiver): unknown {
        if (property === "getSymbolAtLocation") {
          return async (input: Node | readonly Node[]): Promise<CompilerSymbol | undefined | (CompilerSymbol | undefined)[]> => {
            const result = Array.isArray(input)
              ? await query(input as readonly Node[])
              : await query(input as Node);
            return Array.isArray(result) ? result.map(wrapSymbol) : wrapSymbol(result);
          };
        }
        if (property === "getAliasedSymbol") {
          return async (symbol: CompilerSymbol): Promise<CompilerSymbol> => (
            wrapSymbol(await queryAlias(originals.get(symbol) ?? symbol))!
          );
        }
        if (property === "isUnknownSymbol") {
          return async (symbol: CompilerSymbol): Promise<boolean> => (
            await queryUnknown(originals.get(symbol) ?? symbol)
          );
        }
        const value = Reflect.get(target, property, receiver) as unknown;
        return typeof value === "function" ? value.bind(target) : value;
      },
    });
  };
  const { dependencies } = await extractDependencyFixture(
    sources,
    "__depgraph_ts_dependency_bad_span__",
    corruptDeclarationSpans,
  );
  assert.deepEqual(dependencies.sites, []);
  assert.equal(dependencies.issues.length, 1);
  assert.equal(dependencies.issues[0]?.fatal, true);
  assert.match(dependencies.issues[0]?.message ?? "", /offset is outside its confined source/u);
});
