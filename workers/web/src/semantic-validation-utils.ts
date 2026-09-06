import type { JsonValue } from "./types";

export function objectValue(value: JsonValue | undefined, field: string): Record<string, JsonValue> {
  if (value === null || value === undefined || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${field} must be an object`);
  }
  return value;
}

export function stringValue(value: JsonValue | undefined, field: string): string {
  if (typeof value !== "string" || value.length === 0) throw new Error(`${field} must be a non-empty string`);
  return value;
}
