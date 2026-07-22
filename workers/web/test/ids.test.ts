import assert from "node:assert/strict";
import { test } from "node:test";
import { canonicalJson, contentHash, stableId } from "../src/ids";

test("canonical JSON recursively sorts object keys and preserves array order", () => {
  assert.equal(canonicalJson({ z: 1, a: { y: 2, b: 3 }, list: [2, 1] }), '{"a":{"b":3,"y":2},"list":[2,1],"z":1}');
  assert.equal(
    stableId("file", { path: "src/a.ts", package: "pkg" }),
    stableId("file", { package: "pkg", path: "src/a.ts" }),
  );
  assert.match(stableId("file", { path: "src/a.ts" }), /^file:sha256:[0-9a-f]{64}$/u);
  assert.equal(
    canonicalJson({ ["\u{10000}"]: 2, ["\uE000"]: 1 }),
    '{"\uE000":1,"\u{10000}":2}',
  );
});

test("content hashes use raw UTF-8 bytes and an explicit algorithm prefix", () => {
  assert.equal(contentHash("abc"), "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
});
