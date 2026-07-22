import process from "node:process";
import {
  buildNextObservedGraph,
  nextBuildProtocolEvents,
  type NextBuildGraphInput,
  type NextBuildObservation,
  type NextBuildProvenance,
} from "./next-build-observer";
import {
  astroBuildProtocolEvents,
  buildAstroObservedGraph,
  type AstroBuildGraphInput,
  type AstroBuildObservation,
  type AstroBuildProvenance,
} from "./astro-build-observer";
import {
  buildTanStackStartObservedGraph,
  tanStackStartBuildProtocolEvents,
  type TanStackStartBuildGraphInput,
  type TanStackStartBuildObservation,
  type TanStackStartBuildProvenance,
} from "./tanstack-start-build-observer";
import type { GraphEdge, GraphNode, JsonValue, ProtocolEvent } from "./types";

const MAX_INPUT_BYTES = 64 * 1024 * 1024;

interface BuildProfileContract {
  parent_profile_id: string;
  effective_input_id: string;
  environment: Record<string, JsonValue>;
}

interface BuildEvidenceInput {
  adapter: "next" | "astro" | "tanstack-start";
  root: string;
  source_revision: string;
  observation: unknown;
  provenance: NextBuildProvenance | AstroBuildProvenance | TanStackStartBuildProvenance;
  base_nodes: GraphNode[];
  base_edges: GraphEdge[];
  profile: BuildProfileContract;
}

function record(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error("invalid-record");
  return value as Record<string, unknown>;
}

function boundedString(value: unknown): string {
  if (typeof value !== "string" || value.length === 0 || value.length > 4096 || /[\u0000-\u001f\u007f]/u.test(value)) {
    throw new Error("invalid-string");
  }
  return value;
}

function parseInput(value: unknown): BuildEvidenceInput {
  const input = record(value);
  if (!(["next", "astro", "tanstack-start"] as const).includes(input.adapter as never)) {
    throw new Error("invalid-adapter");
  }
  const baseNodes = input.base_nodes;
  const baseEdges = input.base_edges;
  if (!Array.isArray(baseNodes) || !Array.isArray(baseEdges)) throw new Error("invalid-base-graph");
  const profile = record(input.profile);
  const environment = record(profile.environment) as Record<string, JsonValue>;
  return {
    adapter: input.adapter as BuildEvidenceInput["adapter"],
    root: boundedString(input.root),
    source_revision: boundedString(input.source_revision),
    observation: record(input.observation),
    provenance: record(input.provenance) as unknown as BuildEvidenceInput["provenance"],
    base_nodes: baseNodes as GraphNode[],
    base_edges: baseEdges as GraphEdge[],
    profile: {
      parent_profile_id: boundedString(profile.parent_profile_id),
      effective_input_id: boundedString(profile.effective_input_id),
      environment,
    },
  };
}

function applyProfileContract(events: ProtocolEvent[], input: BuildEvidenceInput): ProtocolEvent[] {
  const declaration = events.find((event) => event.event === "profile_declared");
  const profile = declaration === undefined ? null : record(declaration.profile);
  if (profile === null) throw new Error("profile-missing");
  profile.environment = { ...input.profile.environment, phase: "build" };
  profile.properties = {
    ...record(profile.properties),
    profile_contract: "phase-parent-effective-v1",
    profile_phase: "build",
    parent_profile_id: input.profile.parent_profile_id,
    effective_input_id: input.profile.effective_input_id,
  };
  return events;
}

function convert(input: BuildEvidenceInput): ProtocolEvent[] {
  const common = {
    provenance: input.provenance,
    baseNodes: input.base_nodes,
    baseEdges: input.base_edges,
  };
  let events: ProtocolEvent[];
  switch (input.adapter) {
    case "next": {
      const graphInput = { ...common, observation: input.observation as NextBuildObservation } as NextBuildGraphInput;
      events = nextBuildProtocolEvents(
        input.root,
        buildNextObservedGraph(graphInput),
        input.provenance as NextBuildProvenance,
        input.source_revision,
      );
      break;
    }
    case "astro": {
      const graphInput = { ...common, observation: input.observation as AstroBuildObservation } as AstroBuildGraphInput;
      events = astroBuildProtocolEvents(
        input.root,
        buildAstroObservedGraph(graphInput),
        input.provenance as AstroBuildProvenance,
        input.source_revision,
      );
      break;
    }
    case "tanstack-start": {
      const graphInput = { ...common, observation: input.observation as TanStackStartBuildObservation } as TanStackStartBuildGraphInput;
      events = tanStackStartBuildProtocolEvents(
        input.root,
        buildTanStackStartObservedGraph(graphInput),
        input.provenance as TanStackStartBuildProvenance,
        input.source_revision,
      );
      break;
    }
  }
  return applyProfileContract(events, input);
}

async function main(): Promise<void> {
  const chunks: Buffer[] = [];
  let length = 0;
  for await (const chunk of process.stdin) {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    length += bytes.length;
    if (length > MAX_INPUT_BYTES) throw new Error("input-limit");
    chunks.push(bytes);
  }
  const input = parseInput(JSON.parse(Buffer.concat(chunks).toString("utf8")));
  const encoded = convert(input).map((event) => JSON.stringify(event)).join("\n");
  process.stdout.write(`${encoded}\n`);
}

main().catch(() => {
  process.stderr.write("web.build_evidence_conversion_failed\n");
  process.exitCode = 1;
});
