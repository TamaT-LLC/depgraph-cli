import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { PassThrough } from "node:stream";
import test from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";

import {
  RUNTIME_COLLECTOR_CONTRACT_VERSION,
  RUNTIME_TRACE_MEDIA_TYPE,
  createFileRuntimeCollectorSink,
  createOtlpRuntimeCollectorSink,
  createRuntimeCollector,
  createStdoutRuntimeCollectorSink,
  type RuntimeCollectorClock,
  type RuntimeCollectorOptions,
  type RuntimeCollectorSession,
  type RuntimeCollectorSink,
  type RuntimeObservation,
} from "../src/runtime-collector.js";

interface CollectorFixture {
  framework: string;
  repository: RuntimeCollectorOptions["repository"];
  session: RuntimeCollectorSession;
  observations: RuntimeObservation[];
}

class StepClock implements RuntimeCollectorClock {
  private wallMs: number;
  monotonicMs = 0;

  constructor(start: string) {
    this.wallMs = Date.parse(start);
  }

  utcNow(): Date {
    const result = new Date(this.wallMs);
    this.wallMs += 1_000;
    return result;
  }

  monotonicNow(): number {
    return this.monotonicMs;
  }
}

async function readFixture(name: string): Promise<CollectorFixture> {
  const source = await readFile(
    new URL(`fixtures/runtime-collector/${name}.json`, import.meta.url),
    "utf8",
  );
  return JSON.parse(source) as CollectorFixture;
}

function memorySink(
  kind: RuntimeCollectorSink["kind"] = "otlp",
): RuntimeCollectorSink & { payloads: Buffer[] } {
  const payloads: Buffer[] = [];
  return {
    kind,
    payloads,
    async write(payload) {
      payloads.push(Buffer.from(payload));
    },
  };
}

function createFixtureCollector(
  fixture: CollectorFixture,
  sink: RuntimeCollectorSink,
  clock = new StepClock("2026-07-24T00:00:00Z"),
) {
  return createRuntimeCollector({
    repository: fixture.repository,
    session: fixture.session,
    sink,
    clock,
    retry: {
      maxAttempts: 0,
    },
  });
}

const basicObservation = (pathName: string): RuntimeObservation => ({
  kind: "module",
  source: { kind: "repository_path", path: pathName, nodeKind: "file" },
  target: { kind: "external", namespace: "npm", name: "fixture-package" },
});

test("Next.js, Astro, and TanStack observations produce redacted trace v1 metadata", async () => {
  for (const name of ["next", "astro", "tanstack"]) {
    const fixture = await readFixture(name);
    const sink = memorySink();
    const collector = createFixtureCollector(fixture, sink);
    for (const observation of fixture.observations) {
      assert.equal(collector.record(observation), true);
    }
    const result = await collector.flush();
    assert.equal(result.status, "flushed");
    assert.equal(result.prefixEnd, fixture.observations.length);
    assert.equal(sink.payloads.length, 1);

    const serialized = sink.payloads[0]!.toString("utf8");
    const trace = JSON.parse(serialized) as {
      schema_version: string;
      session: {
        collector_contract_version: string;
        profile: { features?: string[] };
        environment: { name: string; runtime?: string; region?: string };
      };
      events: Array<{
        sequence: number;
        target: { kind: string; name?: string };
      }>;
    };
    assert.equal(trace.schema_version, "1.0");
    assert.equal(
      trace.session.collector_contract_version,
      RUNTIME_COLLECTOR_CONTRACT_VERSION,
    );
    assert.equal(trace.session.environment.name, fixture.session.environment.name);
    assert.equal(trace.session.environment.runtime, fixture.session.environment.runtime);
    assert.equal(trace.session.environment.region, fixture.session.environment.region);
    assert.deepEqual(
      trace.session.profile.features,
      [...(fixture.session.profile.features ?? [])].sort(),
    );
    assert.deepEqual(
      trace.events.map((event) => event.sequence),
      fixture.observations.map((_, index) => index + 1),
    );
    assert(!serialized.includes("not-a-secret"));
    assert(!serialized.includes("fixture-password"));
    assert(!serialized.includes("/private"));
    assert(!serialized.includes("customer=42"));
    assert(!serialized.includes("tenant=private"));
    assert(!serialized.includes("fixture-user"));
  }

  const fixture = await readFixture("next");
  const sink = memorySink();
  const collector = createFixtureCollector(fixture, sink);
  fixture.observations.forEach((observation) => assert(collector.record(observation)));
  await collector.flush();
  const expected = JSON.parse(
    await readFile(
      new URL("fixtures/runtime-collector/next.expected.json", import.meta.url),
      "utf8",
    ),
  ) as unknown;
  assert.deepEqual(JSON.parse(sink.payloads[0]!.toString("utf8")), expected);
});

test("disabled collector is a no-op without clock, sink, timer, or diagnostic effects", async () => {
  let clockCalls = 0;
  let sinkCalls = 0;
  let diagnosticCalls = 0;
  const collector = createRuntimeCollector({
    enabled: false,
    repository: { identity: "workspace://disabled" },
    session: {
      id: "disabled-session",
      profile: { language: "typescript" },
      environment: { name: "test" },
    },
    sink: {
      kind: "stdout",
      async write() {
        sinkCalls += 1;
      },
    },
    clock: {
      utcNow() {
        clockCalls += 1;
        return new Date();
      },
      monotonicNow() {
        clockCalls += 1;
        return 0;
      },
    },
    onDiagnostic() {
      diagnosticCalls += 1;
    },
    buffer: {
      maxEvents: 0,
      maxBytes: 1,
    },
    retry: {
      maxAttempts: 99,
    },
  });

  assert.equal(collector.state, "disabled");
  assert.equal(collector.record(basicObservation("src/disabled.ts")), false);
  assert.equal(collector.snapshot(), null);
  assert.deepEqual(await collector.flush(), {
    status: "disabled",
    prefixEnd: 0,
    attempts: 0,
  });
  assert.deepEqual(await collector.shutdown(), {
    status: "disabled",
    prefixEnd: 0,
    attempts: 0,
  });
  assert.equal(clockCalls, 0);
  assert.equal(sinkCalls, 0);
  assert.equal(diagnosticCalls, 0);
});

test("collector descriptor is the exact runtime-collector-v1 behavior contract", async () => {
  const expected = JSON.parse(
    await readFile(
      new URL(
        "../../../crates/depgraph-core/tests/fixtures/runtime-collector-v1.contract.json",
        import.meta.url,
      ),
      "utf8",
    ),
  ) as unknown;
  const collector = createRuntimeCollector({
    repository: { identity: "workspace://descriptor" },
    session: {
      id: "descriptor-session",
      profile: { language: "typescript" },
      environment: { name: "test" },
      redaction: {
        environmentKeys: ["DATABASE_URL", "API_TOKEN"],
        headerNames: ["cookie", "authorization"],
        secretNames: ["api_token"],
      },
    },
    sink: memorySink("file"),
    buffer: {
      maxEvents: 4_096,
      maxBytes: 1_048_576,
    },
    retry: {
      maxAttempts: 3,
      initialBackoffMs: 100,
      maxBackoffMs: 5_000,
    },
    shutdownTimeoutMs: 5_000,
  });
  assert.deepEqual(collector.descriptor, expected);
});

test("bundled collector exposes the dependency-free reference API", async () => {
  const artifact = pathToFileURL(
    fileURLToPath(new URL("../dist/depgraph-runtime-collector.mjs", import.meta.url)),
  ).href;
  const bundled = (await import(artifact)) as Record<string, unknown>;
  assert.deepEqual(Object.keys(bundled).sort(), [
    "RUNTIME_COLLECTOR_CONTRACT_VERSION",
    "RUNTIME_TRACE_MEDIA_TYPE",
    "RUNTIME_TRACE_SCHEMA_VERSION",
    "createFileRuntimeCollectorSink",
    "createOtlpRuntimeCollectorSink",
    "createRuntimeCollector",
    "createStdoutRuntimeCollectorSink",
  ]);
});

test("buffer admission is drop-newest and flush snapshots an immutable contiguous prefix", async () => {
  const fixture = await readFixture("next");
  const payloads: Buffer[] = [];
  let releaseFirst: (() => void) | undefined;
  const firstGate = new Promise<void>((resolve) => {
    releaseFirst = resolve;
  });
  const sink: RuntimeCollectorSink = {
    kind: "otlp",
    async write(payload) {
      payloads.push(Buffer.from(payload));
      if (payloads.length === 1) await firstGate;
    },
  };
  const collector = createRuntimeCollector({
    repository: fixture.repository,
    session: fixture.session,
    sink,
    clock: new StepClock("2026-07-24T00:00:00Z"),
    buffer: { maxEvents: 3 },
    retry: { maxAttempts: 0 },
  });

  assert(collector.record(basicObservation("src/one.ts")));
  assert(collector.record(basicObservation("src/two.ts")));
  const first = collector.flush();
  const coalesced = collector.flush();
  assert.equal(first, coalesced);
  assert(collector.record(basicObservation("src/three.ts")));
  assert.equal(collector.record(basicObservation("src/four.ts")), false);
  releaseFirst?.();
  assert.equal((await first).status, "flushed");
  assert.equal((JSON.parse(payloads[0]!.toString("utf8")) as { events: unknown[] }).events.length, 2);

  assert.equal((await collector.flush()).status, "flushed");
  const latest = JSON.parse(payloads[1]!.toString("utf8")) as {
    events: Array<{ sequence: number }>;
  };
  assert.deepEqual(
    latest.events.map((event) => event.sequence),
    [1, 2, 3],
  );
  assert.equal(collector.stats().dropped.buffer_full, 1);
});

test("retry payloads are byte-identical and rate-limited drops do not consume sequence", async () => {
  const fixture = await readFixture("next");
  const retryPayloads: Buffer[] = [];
  let attempts = 0;
  const retryCollector = createRuntimeCollector({
    repository: fixture.repository,
    session: fixture.session,
    sink: {
      kind: "otlp",
      async write(payload) {
        retryPayloads.push(Buffer.from(payload));
        attempts += 1;
        if (attempts < 3) throw new Error("fixture sink failure");
      },
    },
    clock: new StepClock("2026-07-24T00:00:00Z"),
    retry: {
      maxAttempts: 2,
      initialBackoffMs: 1,
      maxBackoffMs: 1,
    },
    sleep: async () => undefined,
  });
  assert(retryCollector.record(basicObservation("src/retry.ts")));
  assert.deepEqual(await retryCollector.flush(), {
    status: "flushed",
    prefixEnd: 1,
    attempts: 3,
  });
  assert.equal(retryPayloads.length, 3);
  assert(retryPayloads.every((payload) => payload.equals(retryPayloads[0]!)));

  const rateClock = new StepClock("2026-07-24T00:00:00Z");
  const rateCollector = createRuntimeCollector({
    repository: fixture.repository,
    session: fixture.session,
    sink: memorySink(),
    clock: rateClock,
    limits: { maxEventsPerSecond: 1 },
  });
  assert(rateCollector.record(basicObservation("src/rate-one.ts")));
  assert.equal(rateCollector.record(basicObservation("src/rate-drop.ts")), false);
  rateClock.monotonicMs = 1_000;
  assert(rateCollector.record(basicObservation("src/rate-two.ts")));
  const trace = JSON.parse(rateCollector.snapshot()!) as {
    events: Array<{ sequence: number; source: { path: string } }>;
  };
  assert.deepEqual(
    trace.events.map((event) => [event.sequence, event.source.path]),
    [
      [1, "src/rate-one.ts"],
      [2, "src/rate-two.ts"],
    ],
  );
  assert.equal(rateCollector.stats().dropped.rate_limited, 1);
});

test("invalid or secret-shaped observations fail closed without consuming sequence or echoing input", async () => {
  const fixture = await readFixture("next");
  const diagnostics: Array<{ code: string; count: number }> = [];
  const collector = createRuntimeCollector({
    repository: fixture.repository,
    session: fixture.session,
    sink: memorySink(),
    clock: new StepClock("2026-07-24T00:00:00Z"),
    onDiagnostic: (diagnostic) => diagnostics.push({ ...diagnostic }),
  });
  assert.equal(
    collector.record({
      kind: "rpc",
      source: { kind: "node", nodeId: "sk-fixture-secret" },
      target: { kind: "external", namespace: "https", name: "api.example.test/private" },
    }),
    false,
  );
  assert.equal(
    collector.record({
      kind: "module",
      source: {
        kind: "repository_path",
        path: "src/token=opaque-value.ts",
        nodeKind: "file",
      },
      target: { kind: "external", namespace: "npm", name: "fixture" },
    }),
    false,
  );
  assert.equal(
    collector.record({
      ...basicObservation("src/unknown-field.ts"),
      rawHeaders: { authorization: "Bearer fixture-value" },
    } as unknown as RuntimeObservation),
    false,
  );
  assert(collector.record(basicObservation("src/accepted.ts")));
  const trace = collector.snapshot()!;
  assert(!trace.includes("sk-fixture-secret"));
  assert(!trace.includes("opaque-value"));
  assert(!trace.includes("fixture-value"));
  assert.deepEqual(
    (JSON.parse(trace) as { events: Array<{ sequence: number }> }).events.map(
      (event) => event.sequence,
    ),
    [1],
  );
  assert.deepEqual(diagnostics, [
    { code: "invalid_observation", count: 1 },
    { code: "invalid_observation", count: 2 },
    { code: "invalid_observation", count: 3 },
  ]);
});

test("shutdown is bounded, idempotent, and never throws sink failures into the app", async () => {
  const fixture = await readFixture("next");
  const collector = createRuntimeCollector({
    repository: fixture.repository,
    session: fixture.session,
    sink: {
      kind: "otlp",
      async write() {
        await new Promise<void>(() => undefined);
      },
    },
    clock: new StepClock("2026-07-24T00:00:00Z"),
    shutdownTimeoutMs: 10,
  });
  assert(collector.record(basicObservation("src/shutdown.ts")));
  const first = collector.shutdown();
  const second = collector.shutdown();
  assert.equal(first, second);
  const result = await first;
  assert.equal(result.status, "failed");
  assert.equal(collector.state, "stopped");
  assert.equal(collector.record(basicObservation("src/late.ts")), false);
  assert.equal(collector.stats().dropped.shutdown_timeout, 1);
  assert.equal((await collector.shutdown()).status, "failed");
});

test("file, stdout, and OTLP sinks carry the same canonical trace bytes", async () => {
  const fixture = await readFixture("astro");
  const directory = await mkdtemp(path.join(tmpdir(), "depgraph-runtime-collector-"));
  try {
    const destination = path.join(directory, "trace.json");
    const fileCollector = createFixtureCollector(
      fixture,
      createFileRuntimeCollectorSink(destination),
    );
    fixture.observations.forEach((observation) => assert(fileCollector.record(observation)));
    assert.equal((await fileCollector.flush()).status, "flushed");
    const filePayload = await readFile(destination);

    const output = new PassThrough();
    const chunks: Buffer[] = [];
    output.on("data", (chunk: Buffer) => chunks.push(Buffer.from(chunk)));
    const stdoutCollector = createFixtureCollector(
      fixture,
      createStdoutRuntimeCollectorSink(output),
    );
    fixture.observations.forEach((observation) => assert(stdoutCollector.record(observation)));
    assert.equal((await stdoutCollector.flush()).status, "flushed");
    const stdoutPayload = Buffer.concat(chunks).subarray(0, -1);

    let otlpBody: Buffer | undefined;
    let otlpAttributes: Record<string, unknown> | undefined;
    const otlpCollector = createFixtureCollector(
      fixture,
      createOtlpRuntimeCollectorSink(async (record) => {
        otlpBody = Buffer.from(record.body);
        otlpAttributes = { ...record.attributes };
      }),
    );
    fixture.observations.forEach((observation) => assert(otlpCollector.record(observation)));
    assert.equal((await otlpCollector.flush()).status, "flushed");

    assert(filePayload.equals(stdoutPayload));
    assert(filePayload.equals(otlpBody!));
    assert.deepEqual(otlpAttributes, {
      "depgraph.collector.contract_version": RUNTIME_COLLECTOR_CONTRACT_VERSION,
      "depgraph.runtime.media_type": RUNTIME_TRACE_MEDIA_TYPE,
      "depgraph.runtime.session_id": fixture.session.id,
      "depgraph.runtime.prefix_end": fixture.observations.length,
    });
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
