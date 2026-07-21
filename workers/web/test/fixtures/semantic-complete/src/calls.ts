export type Message = "first" | "second";

export const first = (): Message => "first";

export const second = (): Message => "second";

const candidate = Math.random() >= 0.5 ? first : second;

export function choose(): Message {
  return candidate();
}

export function normalized(): string {
  return " fixture ".trim();
}
