import assert from "node:assert/strict";
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
import { resolveTypeScriptCompiler } from "../src/typescript-compiler";
import {
  extractTypeScriptRawDefinitionDelta,
  TYPESCRIPT_SEMANTIC_MAX_SOURCE_FILES,
  type TypeScriptRawDefinitionDelta,
  type TypeScriptRawTypeArgumentDescriptor,
  type TypeScriptSemanticSource,
  validateTypeScriptRawDefinitionDelta,
} from "../src/typescript-semantic";

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
