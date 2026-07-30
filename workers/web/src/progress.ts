import { performance } from "node:perf_hooks";

export type ProgressDetail = Readonly<Record<string, string | number | boolean>>;

export interface ProgressReporter {
  start(phase: string, detail?: ProgressDetail): void;
  checkpoint(phase: string, detail?: ProgressDetail): void;
  complete(phase: string, detail?: ProgressDetail): void;
}

export const NOOP_PROGRESS: ProgressReporter = Object.freeze({
  start: () => undefined,
  checkpoint: () => undefined,
  complete: () => undefined,
});

function detailFields(detail: ProgressDetail): string {
  return Object.entries(detail)
    .sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0)
    .map(([key, value]) => `${key}=${String(value).replaceAll(/\s+/gu, "_")}`)
    .join(" ");
}

export class StderrProgressReporter implements ProgressReporter {
  readonly #startedAt = new Map<string, number>();

  start(phase: string, detail: ProgressDetail = {}): void {
    this.#startedAt.set(phase, performance.now());
    this.#write(phase, "started", detail);
  }

  checkpoint(phase: string, detail: ProgressDetail = {}): void {
    this.#write(phase, "progress", detail);
  }

  complete(phase: string, detail: ProgressDetail = {}): void {
    const startedAt = this.#startedAt.get(phase);
    this.#startedAt.delete(phase);
    this.#write(phase, "completed", {
      ...detail,
      ...(startedAt === undefined ? {} : { duration_ms: Math.round(performance.now() - startedAt) }),
    });
  }

  #write(phase: string, status: "started" | "progress" | "completed", detail: ProgressDetail): void {
    const fields = detailFields(detail);
    process.stderr.write(
      `depgraph-progress phase=${phase} status=${status}${fields.length === 0 ? "" : ` ${fields}`}\n`,
    );
  }
}
