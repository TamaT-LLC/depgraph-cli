import assert from "node:assert/strict";
import { test } from "node:test";
import { canonicalJson, stableId } from "../src/ids";

test("canonical JSON recursively sorts object keys and preserves array order", () => {
  assert.equal(canonicalJson({ z: 1, a: { y: 2, b: 3 }, list: [2, 1] }), '{"a":{"b":3,"y":2},"list":[2,1],"z":1}');
  assert.equal(
    stableId("file", { path: "src/a.ts", package: "pkg" }),
    stableId("file", { package: "pkg", path: "src/a.ts" }),
  );
  assert.match(stableId("file", { path: "src/a.ts" }), /^file:sha256:[0-9a-f]{64}$/u);
});
