export interface SharedEntity {
  id: string;
}

export class SharedCollection<T> {
  constructor(readonly value: T) {}

  current(): T {
    return this.value;
  }
}

export class SharedStringCollection extends SharedCollection<string> implements SharedEntity {
  id = "shared";
}

export type SharedResult<T> = { value: T };

export enum SharedState {
  Ready,
  Done,
}

export function buildShared(value: string): SharedResult<string> {
  const normalize = (input: string): string => input.trim();
  return { value: normalize(value) };
}

export const mapShared = <T>(value: T): SharedResult<T> => ({ value });
