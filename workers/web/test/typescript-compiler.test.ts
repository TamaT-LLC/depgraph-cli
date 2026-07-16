import assert from "node:assert/strict";
import { test } from "node:test";
import { isConfinedTypeScriptInputPath } from "../src/typescript-compiler";

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
