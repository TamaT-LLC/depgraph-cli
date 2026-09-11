import type { Writable } from "node:stream";

function flushOutput(stream: Writable): Promise<void> {
  return new Promise((resolve) => {
    const finished = (): void => {
      resolve();
    };
    stream.once("error", finished);
    stream.write("", finished);
  });
}

/** Fatal compiler failures have already reaped their child process. */
export async function exitWorkerAfterFlushing(code: number): Promise<never> {
  process.exitCode = code;
  await Promise.all([flushOutput(process.stdout), flushOutput(process.stderr)]);
  // A disposed upstream JSON-RPC reader can retain its partial-frame timer.
  // This worker has no more work after a fatal error; terminate only after
  // its protocol result and stderr have reached their write callbacks.
  process.exit(code);
}
