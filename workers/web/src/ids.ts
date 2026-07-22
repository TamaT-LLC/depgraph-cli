import { createHash } from "node:crypto";
import { compareUtf8, type JsonValue } from "./types";

function canonicalize(value: JsonValue): JsonValue {
  if (Array.isArray(value)) {
    return value.map(canonicalize);
  }
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value)
        .sort(([left], [right]) => compareUtf8(left, right))
        .map(([key, child]) => [key, canonicalize(child)]),
    );
  }
  return value;
}

export function canonicalJson(value: JsonValue): string {
  return JSON.stringify(canonicalize(value));
}

export function stableId(namespace: string, identity: JsonValue): string {
  const digest = createHash("sha256").update(canonicalJson(identity), "utf8").digest("hex");
  return `${namespace}:sha256:${digest}`;
}

export function contentHash(contents: string | Uint8Array): string {
  return `sha256:${createHash("sha256").update(contents).digest("hex")}`;
}

export function compareById<T extends { id: string }>(left: T, right: T): number {
  return compareUtf8(left.id, right.id);
}
