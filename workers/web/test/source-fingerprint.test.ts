import assert from "node:assert/strict";
import { test } from "node:test";

import { analysisContentHash } from "../src/source-fingerprint";

test("analysis fingerprint ignores harmless trailing trivia", () => {
  const baseline = 'import "./dep.js";\nexport const value = 1;\n';
  const edited = `${baseline}// benchmark revision 7\n\n`;

  assert.equal(
    analysisContentHash(edited, "src/value.ts"),
    analysisContentHash(baseline, "src/value.ts"),
  );
});

test("analysis fingerprint retains evidence positions, graph-affecting tokens, and comments", () => {
  const baseline = 'import "./before.js";\nexport const value = 1;\n';
  assert.notEqual(
    analysisContentHash(`\n${baseline}`, "src/value.ts"),
    analysisContentHash(baseline, "src/value.ts"),
  );
  assert.notEqual(
    analysisContentHash(
      'import "./after.js";\nexport const value = 1;\n',
      "src/value.ts",
    ),
    analysisContentHash(baseline, "src/value.ts"),
  );
  assert.notEqual(
    analysisContentHash(
      "/** @type {string} */\nexport const value = 1;\n",
      "src/value.js",
    ),
    analysisContentHash(
      "/** @type {number} */\nexport const value = 1;\n",
      "src/value.js",
    ),
  );
  assert.notEqual(
    analysisContentHash(
      '/// <reference path="./types-a.d.ts" />\nexport {};\n',
      "src/value.ts",
    ),
    analysisContentHash(
      '/// <reference path="./types-b.d.ts" />\nexport {};\n',
      "src/value.ts",
    ),
  );
  assert.notEqual(
    analysisContentHash(
      `${baseline}// possible module "./candidate-a.js"\n`,
      "src/value.ts",
    ),
    analysisContentHash(
      `${baseline}// possible module "./candidate-b.js"\n`,
      "src/value.ts",
    ),
  );
});

test("analysis fingerprint tokenizes JSX with the JSX language variant", () => {
  assert.notEqual(
    analysisContentHash("export const View = () => <Before />;\n", "src/view.tsx"),
    analysisContentHash("export const View = () => <After />;\n", "src/view.tsx"),
  );
});
