import { createHash } from "node:crypto";
import path from "node:path";
import {
  SyntaxKind,
  type SyntaxKind as SyntaxKindValue,
} from "typescript/unstable/ast";
import { scanTypeScriptSyntaxTokensWithTrivia } from "./imports";

const SIGNIFICANT_COMMENT = /(?:^\/\/\/|@[a-z][\w-]*|["'])/iu;

function appendToken(
  hash: ReturnType<typeof createHash>,
  kind: SyntaxKindValue,
  text: string,
  startOffset: number,
  line: number,
  column: number,
): void {
  hash.update(String(kind), "utf8");
  hash.update("\0", "utf8");
  hash.update(String(startOffset), "utf8");
  hash.update("\0", "utf8");
  hash.update(String(line), "utf8");
  hash.update("\0", "utf8");
  hash.update(String(column), "utf8");
  hash.update("\0", "utf8");
  hash.update(String(Buffer.byteLength(text)), "utf8");
  hash.update("\0", "utf8");
  hash.update(text, "utf8");
  hash.update("\0", "utf8");
}

function sourceLineStarts(source: string): number[] {
  const starts = [0];
  for (let index = 0; index < source.length; index += 1) {
    if (source.charCodeAt(index) === 10) starts.push(index + 1);
  }
  return starts;
}

function sourcePosition(
  starts: readonly number[],
  offset: number,
): { line: number; column: number } {
  let low = 0;
  let high = starts.length;
  while (low + 1 < high) {
    const middle = low + Math.floor((high - low) / 2);
    if (starts[middle]! <= offset) low = middle;
    else high = middle;
  }
  return { line: low + 1, column: offset - starts[low]! + 1 };
}

/**
 * Hashes only source input that can affect the dependency graph.
 *
 * Ordinary trivia is excluded only when it leaves every significant token at
 * the same byte-independent UTF-16 offset and line/column. This keeps stored
 * evidence spans valid while allowing harmless trailing comments. Triple-slash
 * directives, tag-bearing comments, and quoted comment strings remain inputs
 * because worker collectors can interpret them.
 */
export function analysisContentHash(source: string, filePath: string): string {
  const extension = path.extname(filePath).toLowerCase();
  const tokens = scanTypeScriptSyntaxTokensWithTrivia(
    source,
    extension === ".tsx" || extension === ".jsx",
  );
  const hash = createHash("sha256");
  const lineStarts = sourceLineStarts(source);
  for (const token of tokens) {
    const kind = token.kind;
    if (
      kind === SyntaxKind.WhitespaceTrivia
      || kind === SyntaxKind.NewLineTrivia
    ) {
      continue;
    }
    if (
      kind === SyntaxKind.SingleLineCommentTrivia
      || kind === SyntaxKind.MultiLineCommentTrivia
    ) {
      const text = token.text;
      if (SIGNIFICANT_COMMENT.test(text)) {
        const startOffset = token.start;
        const position = sourcePosition(lineStarts, startOffset);
        appendToken(hash, kind, text, startOffset, position.line, position.column);
      }
      continue;
    }
    const startOffset = token.start;
    const position = sourcePosition(lineStarts, startOffset);
    appendToken(
      hash,
      kind,
      token.text,
      startOffset,
      position.line,
      position.column,
    );
  }
  return `sha256:${hash.digest("hex")}`;
}
