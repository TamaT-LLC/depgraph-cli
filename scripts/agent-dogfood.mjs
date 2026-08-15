#!/usr/bin/env node

import { execFileSync, spawn } from "node:child_process";
import { createHash } from "node:crypto";
import {
  createReadStream,
  createWriteStream,
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  readlinkSync,
  realpathSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { once } from "node:events";
import { basename, dirname, isAbsolute, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

export const SPEC_SCHEMA_VERSION = "agent-dogfood-spec-v1";
export const ANSWER_SCHEMA_VERSION = "agent-dogfood-answer-v1";
export const SAMPLE_SCHEMA_VERSION = "agent-dogfood-sample-v1";
export const SAFETY_SCHEMA_VERSION = "agent-dogfood-safety-v1";
export const ENVIRONMENT_SCHEMA_VERSION = "agent-dogfood-environment-v1";
export const REPORT_SCHEMA_VERSION = "agent-dogfood-report-v1";

const ARM_NAMES = Object.freeze(["baseline", "mcp"]);
const FAILURE_CODES = Object.freeze([
  "setup_blocker",
  "tool_or_schema_missing",
  "agent_misuse",
  "excessive_context",
  "host_failure",
]);
const CLAIM_CLASSIFICATIONS = new Set([
  "exact",
  "candidate",
  "unresolved",
  "external",
  "heuristic",
  "not_applicable",
]);
const CLAIM_VERDICTS = new Set(["supported", "refuted", "insufficient"]);
const EVIDENCE_SOURCES = new Set(["mcp", "source", "git"]);
const CLAIM_IDS_ALLOWING_EMPTY_SUPPORTED_EVIDENCE = new Set([
  "snapshot_package_diff",
  "snapshot_file_diff",
  "package_cycles",
  "candidate_coverage",
]);
const TOOL_ITEM_TYPES = new Set(["command_execution", "mcp_tool_call"]);
const PRIVILEGED_MCP_TOOLS = new Set([
  "daemon_start_submit",
  "daemon_stop",
  "export_file",
  "repository_init",
  "resolve_build_submit",
  "runtime_trace_import_submit",
  "scan_submit",
  "snapshot_name_create",
]);
const DOGFOOD_MCP_TOOLS = Object.freeze([
  "agent_edges_list",
  "agent_nodes_list",
  "get_context",
  "graph_cycles_list",
  "graph_dependencies_list",
  "graph_dependents_list",
  "graph_impact_get",
  "graph_path_get",
  "snapshot_diff_get",
]);
const DOGFOOD_REQUIRED_MCP_TOOLS = Object.freeze([
  "agent_nodes_list",
  "get_context",
  "graph_cycles_list",
  "graph_dependencies_list",
  "graph_dependents_list",
  "graph_impact_get",
  "graph_path_get",
  "snapshot_diff_get",
]);
const DOGFOOD_SAFETY_BASELINE = Object.freeze({
  source_sha256: "ee7c2d70bff926657b091834fa5bc3a69a04f3d3573b116e1d8e3f194d9a9515",
  store_sha256: "9b03498b33abed475f7950aa865fb9d8c755f0cb0015dc923495b60792739f20",
  journal_sha256: "15df9ae7a75ab8383c84066c9d5e326ba7ef18f1c60655026d3a89be2b7564b9",
  daemon_state_sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  relevant_processes: 0,
});
const SHELL_COMMAND = /^\/bin\/zsh -(?:l)?c (["'])([\s\S]*)\1$/u;
const APPROVED_GIT_COMMAND = /^git (?:diff|log|ls-files|rev-parse|show|status)(?:\s|$)/u;
const UNSAFE_GIT_OPTIONS = new Set(["--ext-diff", "--output", "--textconv"]);
const UNSAFE_RG_OPTIONS = new Set(["--hostname-bin", "--pre", "--pre-glob"]);
const APPROVED_SED_PRINT = /^sed -n (["'])?\d+(?:,\d+)?p\1 [A-Za-z0-9_./*-]+$/u;
const DOGFOOD_CLAIM_IDS = Object.freeze([
  "rust_path",
  "go_dependency",
  "web_dependency",
  "web_dependents",
  "rust_impact",
  "rust_unresolved_type",
  "rust_candidate_import",
  "snapshot_package_diff",
  "snapshot_file_diff",
  "file_cycle",
  "package_cycles",
  "candidate_coverage",
]);
const DOGFOOD_THRESHOLDS = Object.freeze({
  minimum_mcp_accuracy_percent: 90,
  minimum_mcp_major_recall_percent: 100,
  maximum_false_exact_claims: 0,
  maximum_candidate_or_unresolved_as_exact: 0,
  minimum_setup_successes_per_arm: 3,
  require_mcp_accuracy_not_below_baseline: true,
  maximum_mcp_median_tool_calls: 28,
  maximum_mcp_median_tool_result_bytes: 327_680,
  maximum_mcp_median_elapsed_ms: 240_000,
  maximum_mcp_median_effective_tokens: 100_000,
  require_mcp_tool_contract: true,
  require_read_only_safety: true,
  require_packaged_reconnect: true,
});

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function exactKeys(value, keys) {
  return isRecord(value)
    && JSON.stringify(Object.keys(value).sort())
      === JSON.stringify([...keys].sort());
}

function jsonFile(path) {
  return JSON.parse(readFileSync(path, "utf8"));
}

function sortedValue(value) {
  if (Array.isArray(value)) return value.map(sortedValue);
  if (!isRecord(value)) return value;
  return Object.fromEntries(
    Object.keys(value).sort().map((key) => [key, sortedValue(value[key])]),
  );
}

function canonicalJson(value) {
  return JSON.stringify(sortedValue(value));
}

function prettyJson(value) {
  return `${JSON.stringify(sortedValue(value), null, 2)}\n`;
}

function sha256Bytes(value) {
  return createHash("sha256").update(value).digest("hex");
}

async function sha256File(path) {
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(path)) hash.update(chunk);
  return hash.digest("hex");
}

async function fileArtifact(path) {
  return {
    path: basename(path),
    sha256: await sha256File(path),
    bytes: statSync(path).size,
  };
}

function writeJson(path, value) {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, prettyJson(value), { flag: "wx" });
}

function assertDigest(value, label) {
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/u.test(value)) {
    throw new Error(`${label} is not a lowercase SHA-256 digest`);
  }
}

function assertPositiveInteger(value, label) {
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new Error(`${label} must be a positive integer`);
  }
}

function validRelativePath(path) {
  return typeof path === "string"
    && path.length > 0
    && path.length <= 512
    && !isAbsolute(path)
    && !/^[A-Za-z]:/u.test(path)
    && !path.includes("\\")
    && !path.split("/").includes("..")
    && !/[\u0000-\u001f\u007f]/u.test(path);
}

export function validateSpec(spec) {
  if (
    !isRecord(spec)
    || !exactKeys(spec, [
      "schema_version",
      "benchmark_id",
      "issue",
      "release",
      "repository",
      "snapshots",
      "safety_baseline",
      "host",
      "thresholds",
      "claims",
    ])
    || spec.schema_version !== SPEC_SCHEMA_VERSION
    || spec.benchmark_id !== "depgraph-v0.5.0-rc.7-agent-dogfood-v1"
    || spec.issue !== 357
    || !exactKeys(spec.release, [
      "repository",
      "tag",
      "candidate_commit",
      "candidate_tree",
      "host_target",
      "archive",
      "compiler_pack_archive",
      "compiler_pack_requirement",
      "mcp_smoke",
    ])
    || !exactKeys(spec.release.archive, ["name", "sha256"])
    || !exactKeys(spec.release.compiler_pack_archive, ["name", "sha256"])
    || !exactKeys(spec.release.compiler_pack_requirement, ["name", "sha256"])
    || !exactKeys(spec.release.mcp_smoke, [
      "name",
      "sha256",
      "schema_version",
      "read_catalog_sha256",
    ])
    || !exactKeys(spec.repository, [
      "baseline_commit",
      "baseline_tree",
      "candidate_commit",
      "candidate_tree",
    ])
    || !exactKeys(spec.snapshots, ["baseline", "candidate"])
    || !exactKeys(spec.snapshots.baseline, ["name", "id", "source_revision"])
    || !exactKeys(spec.snapshots.candidate, ["name", "id", "source_revision"])
    || !exactKeys(spec.safety_baseline, [
      "source_sha256",
      "store_sha256",
      "journal_sha256",
      "daemon_state_sha256",
      "relevant_processes",
    ])
    || !exactKeys(spec.host, [
      "program",
      "minimum_cli_version",
      "model",
      "reasoning_effort",
      "sandbox",
      "approval_policy",
      "ignore_user_config",
      "ignore_rules",
      "ephemeral",
      "samples_per_arm",
      "maximum_tool_calls",
      "mcp_enabled_tools",
      "mcp_required_tools",
      "timeout_ms",
    ])
    || !isRecord(spec.thresholds)
    || !Array.isArray(spec.claims)
    || spec.claims.length !== 12
  ) {
    throw new Error("Agent dogfood spec is incomplete or incompatible");
  }
  validateSafetySnapshot(spec.safety_baseline);
  for (const [label, value] of [
    ["release archive", spec.release.archive?.sha256],
    ["compiler-pack archive", spec.release.compiler_pack_archive?.sha256],
    ["compiler-pack requirement", spec.release.compiler_pack_requirement?.sha256],
    ["MCP smoke", spec.release.mcp_smoke?.sha256],
    ["MCP read catalog", spec.release.mcp_smoke?.read_catalog_sha256],
  ]) assertDigest(value, label);
  for (const [label, value] of [
    ["baseline commit", spec.repository.baseline_commit],
    ["baseline tree", spec.repository.baseline_tree],
    ["candidate commit", spec.repository.candidate_commit],
    ["candidate tree", spec.repository.candidate_tree],
  ]) {
    if (typeof value !== "string" || !/^[0-9a-f]{40}$/u.test(value)) {
      throw new Error(`${label} is not a full Git object ID`);
    }
  }
  if (
    spec.release.repository !== "TamaT-LLC/depgraph-cli"
    || spec.release.tag !== "v0.5.0-rc.7"
    || spec.release.host_target !== "aarch64-apple-darwin"
    || spec.release.archive.name !== "depgraph-0.5.0-aarch64-apple-darwin.tar.gz"
    || spec.release.compiler_pack_archive.name
      !== "depgraph-compiler-pack-0.5.0-aarch64-apple-darwin.tar.gz"
    || spec.release.compiler_pack_requirement.name
      !== "depgraph-compiler-pack-0.5.0-aarch64-apple-darwin.requirement.json"
    || spec.release.mcp_smoke.name
      !== "depgraph-0.5.0-aarch64-apple-darwin.mcp-smoke.json"
    || spec.release.mcp_smoke.schema_version !== "mcp-package-smoke-v1"
    || spec.release.candidate_commit !== spec.repository.candidate_commit
    || spec.release.candidate_tree !== spec.repository.candidate_tree
    || spec.snapshots.baseline?.source_revision !== spec.repository.baseline_commit
    || spec.snapshots.candidate?.source_revision !== spec.repository.candidate_commit
    || spec.snapshots.baseline.name !== "agent-tools-baseline"
    || spec.snapshots.candidate.name !== "rc7-candidate"
    || canonicalJson(spec.safety_baseline) !== canonicalJson(DOGFOOD_SAFETY_BASELINE)
    || typeof spec.snapshots.baseline.id !== "string"
    || typeof spec.snapshots.candidate.id !== "string"
    || !/^snapshot:sha256:[0-9a-f]{64}$/u.test(spec.snapshots.baseline.id)
    || !/^snapshot:sha256:[0-9a-f]{64}$/u.test(spec.snapshots.candidate.id)
    || spec.host.program !== "codex"
    || spec.host.minimum_cli_version !== "0.146.0"
    || spec.host.model !== "gpt-5.6-terra"
    || spec.host.reasoning_effort !== "medium"
    || spec.host.samples_per_arm !== 3
    || spec.host.maximum_tool_calls !== 28
    || canonicalJson(spec.host.mcp_enabled_tools) !== canonicalJson(DOGFOOD_MCP_TOOLS)
    || canonicalJson(spec.host.mcp_required_tools)
      !== canonicalJson(DOGFOOD_REQUIRED_MCP_TOOLS)
    || spec.host.mcp_required_tools.some(
      (tool) => !spec.host.mcp_enabled_tools.includes(tool),
    )
    || spec.host.timeout_ms !== 300_000
    || spec.host.sandbox !== "read-only"
    || spec.host.approval_policy !== "never"
    || spec.host.ignore_user_config !== true
    || spec.host.ignore_rules !== true
    || spec.host.ephemeral !== true
  ) {
    throw new Error("Agent dogfood identity or host controls drifted");
  }
  const thresholdKeys = [
    "minimum_mcp_accuracy_percent",
    "minimum_mcp_major_recall_percent",
    "maximum_false_exact_claims",
    "maximum_candidate_or_unresolved_as_exact",
    "minimum_setup_successes_per_arm",
    "require_mcp_accuracy_not_below_baseline",
    "maximum_mcp_median_tool_calls",
    "maximum_mcp_median_tool_result_bytes",
    "maximum_mcp_median_elapsed_ms",
    "maximum_mcp_median_effective_tokens",
    "require_mcp_tool_contract",
    "require_read_only_safety",
    "require_packaged_reconnect",
  ];
  if (!exactKeys(spec.thresholds, thresholdKeys)) {
    throw new Error("Agent dogfood thresholds are not the closed v1 set");
  }
  if (canonicalJson(spec.thresholds) !== canonicalJson(DOGFOOD_THRESHOLDS)) {
    throw new Error("Agent dogfood thresholds drifted after predeclaration");
  }
  const ids = new Set();
  for (const claim of spec.claims) {
    if (
      !exactKeys(claim, ["id", "category", "major", "expected"])
      || typeof claim.id !== "string"
      || !/^[a-z][a-z0-9_]*$/u.test(claim.id)
      || ids.has(claim.id)
      || typeof claim.category !== "string"
      || typeof claim.major !== "boolean"
      || !exactKeys(claim.expected, ["verdict", "classification", "value"])
      || !CLAIM_VERDICTS.has(claim.expected.verdict)
      || !CLAIM_CLASSIFICATIONS.has(claim.expected.classification)
      || typeof claim.expected.value !== "string"
      || claim.expected.value.length === 0
    ) {
      throw new Error("Agent dogfood golden claims are not closed and unique");
    }
    ids.add(claim.id);
  }
  if (
    canonicalJson([...ids]) !== canonicalJson(DOGFOOD_CLAIM_IDS)
    || spec.claims.filter((claim) => claim.major).length !== 5
  ) throw new Error("Agent dogfood task corpus drifted");
  return spec;
}

function validateFailure(failure) {
  if (
    !exactKeys(failure, ["code", "task", "remediation"])
    || !["none", ...FAILURE_CODES].includes(failure.code)
    || typeof failure.task !== "string"
    || failure.task.length > 128
    || typeof failure.remediation !== "string"
    || failure.remediation.length > 500
    || (failure.code === "none"
      && (failure.task.length !== 0 || failure.remediation.length !== 0))
    || (failure.code !== "none"
      && (failure.task.length === 0 || failure.remediation.length === 0))
  ) {
    throw new Error("Agent dogfood answer has an invalid typed failure");
  }
}

function validateSampleFailure(failure) {
  if (failure === null) return;
  validateFailure(failure);
  if (failure.code === "none") {
    throw new Error("Agent dogfood sample failure cannot use the success code");
  }
}

export function validateAnswer(spec, answer) {
  validateSpec(spec);
  if (
    !exactKeys(answer, ["schema_version", "claims", "failure"])
    || answer.schema_version !== ANSWER_SCHEMA_VERSION
    || !isRecord(answer.claims)
    || JSON.stringify(Object.keys(answer.claims).sort())
      !== JSON.stringify(spec.claims.map((claim) => claim.id).sort())
  ) {
    throw new Error("Agent dogfood answer shape is invalid");
  }
  for (const claim of spec.claims) {
    const result = answer.claims[claim.id];
    if (
      !exactKeys(result, [
        "verdict",
        "classification",
        "value",
        "evidence",
        "reason",
      ])
      || !CLAIM_VERDICTS.has(result.verdict)
      || !CLAIM_CLASSIFICATIONS.has(result.classification)
      || typeof result.value !== "string"
      || result.value.length < 1
      || result.value.length > 2048
      || !Array.isArray(result.evidence)
      || result.evidence.length > 3
      || typeof result.reason !== "string"
      || result.reason.length < 1
      || result.reason.length > 500
      || (result.verdict === "insufficient"
        && (result.classification !== "not_applicable" || result.value !== "unknown"))
      || (result.verdict !== "insufficient"
        && !CLAIM_IDS_ALLOWING_EMPTY_SUPPORTED_EVIDENCE.has(claim.id)
        && result.evidence.length === 0)
    ) {
      throw new Error(`Agent dogfood claim ${claim.id} is invalid`);
    }
    for (const evidence of result.evidence) {
      if (
        !exactKeys(evidence, ["path", "line", "source"])
        || !validRelativePath(evidence.path)
        || (evidence.line !== null
          && (!Number.isSafeInteger(evidence.line) || evidence.line < 1))
        || !EVIDENCE_SOURCES.has(evidence.source)
      ) {
        throw new Error(`Agent dogfood claim ${claim.id} leaks invalid evidence`);
      }
    }
  }
  validateFailure(answer.failure);
  return answer;
}

function percent(numerator, denominator) {
  return Number(((numerator * 100) / denominator).toFixed(2));
}

export function scoreAnswer(spec, answer) {
  validateAnswer(spec, answer);
  const missedClaimIds = [];
  const missedMajorClaimIds = [];
  const falseExactClaimIds = [];
  const candidateOrUnresolvedAsExactIds = [];
  let correctClaims = 0;
  let correctMajorClaims = 0;
  const majorClaims = spec.claims.filter((claim) => claim.major);
  for (const claim of spec.claims) {
    const actual = answer.claims[claim.id];
    const expected = claim.expected;
    const correct = actual.verdict === expected.verdict
      && actual.classification === expected.classification
      && actual.value === expected.value;
    if (correct) {
      correctClaims += 1;
      if (claim.major) correctMajorClaims += 1;
    } else {
      missedClaimIds.push(claim.id);
      if (claim.major) missedMajorClaimIds.push(claim.id);
    }
    if (actual.classification === "exact" && !correct) {
      falseExactClaimIds.push(claim.id);
    }
    if (
      actual.classification === "exact"
      && ["candidate", "unresolved"].includes(expected.classification)
    ) {
      candidateOrUnresolvedAsExactIds.push(claim.id);
    }
  }
  return {
    total_claims: spec.claims.length,
    correct_claims: correctClaims,
    accuracy_percent: percent(correctClaims, spec.claims.length),
    major_claims: majorClaims.length,
    correct_major_claims: correctMajorClaims,
    major_recall_percent: percent(correctMajorClaims, majorClaims.length),
    false_exact_claims: falseExactClaimIds.length,
    candidate_or_unresolved_as_exact: candidateOrUnresolvedAsExactIds.length,
    missed_claim_ids: missedClaimIds,
    missed_major_claim_ids: missedMajorClaimIds,
    false_exact_claim_ids: falseExactClaimIds,
    candidate_or_unresolved_as_exact_ids: candidateOrUnresolvedAsExactIds,
  };
}

function median(values) {
  const ordered = [...values].sort((left, right) => left - right);
  return ordered[Math.floor(ordered.length / 2)];
}

export function efficiencyRatio(numerator, denominator) {
  if (denominator === 0) return numerator === 0 ? 1 : null;
  return Number((numerator / denominator).toFixed(4));
}

function stringBytes(value) {
  if (typeof value === "string") return Buffer.byteLength(value);
  if (value === undefined) return 0;
  return Buffer.byteLength(JSON.stringify(value));
}

export function traceMetrics(text) {
  const toolIds = new Set();
  let anonymousTools = 0;
  let toolResultBytes = 0;
  let inputTokens = null;
  let cachedInputTokens = null;
  let outputTokens = null;
  let finalMessage = null;
  const mcpTools = new Set();
  const mcpToolsSucceeded = new Set();
  const startedMcpTools = new Map();
  for (const [lineIndex, line] of text.split(/\r?\n/u).entries()) {
    if (line.length === 0) continue;
    let event;
    try {
      event = JSON.parse(line);
    } catch {
      throw new Error(`Codex JSONL trace line ${lineIndex + 1} is invalid`);
    }
    const item = event.item;
    if (isRecord(item) && TOOL_ITEM_TYPES.has(item.type)) {
      if (typeof item.id === "string") toolIds.add(item.id);
      else if (event.type === "item.started") anonymousTools += 1;
      if (item.type === "mcp_tool_call" && typeof item.tool === "string") {
        mcpTools.add(item.tool);
        if (event.type === "item.started" && typeof item.id === "string") {
          const previous = startedMcpTools.get(item.id);
          if (previous !== undefined && previous !== item.tool) {
            throw new Error(`Codex MCP call ${item.id} changed tools within its trace`);
          }
          startedMcpTools.set(item.id, item.tool);
        }
        if (
          event.type === "item.completed"
          && typeof item.id === "string"
          && startedMcpTools.get(item.id) === item.tool
          && item.status === "completed"
          && item.error == null
          && isRecord(item.result)
          && isRecord(item.result.structured_content)
          && item.result.structured_content.contract_version
            === "depgraph-mcp-tools-v1"
          && item.result.structured_content.repository_id === "repository"
          && isRecord(item.result.structured_content.result)
          && item.result.isError !== true
          && item.result.is_error !== true
        ) mcpToolsSucceeded.add(item.tool);
      }
      if (event.type === "item.completed") {
        toolResultBytes += stringBytes(
          item.aggregated_output ?? item.output ?? item.result ?? item.error,
        );
      }
    }
    if (
      event.type === "item.completed"
      && item?.type === "agent_message"
      && typeof item.text === "string"
    ) finalMessage = item.text;
    const usage = event.usage ?? event.turn?.usage;
    if (isRecord(usage)) {
      if (Number.isSafeInteger(usage.input_tokens)) inputTokens = usage.input_tokens;
      if (Number.isSafeInteger(usage.cached_input_tokens)) {
        cachedInputTokens = usage.cached_input_tokens;
      }
      if (Number.isSafeInteger(usage.output_tokens)) outputTokens = usage.output_tokens;
    }
  }
  return {
    tool_calls: toolIds.size + anonymousTools,
    tool_result_bytes: toolResultBytes,
    input_tokens: inputTokens,
    cached_input_tokens: cachedInputTokens,
    output_tokens: outputTokens,
    total_tokens: inputTokens === null || outputTokens === null
      ? null
      : inputTokens + outputTokens,
    effective_tokens: inputTokens === null
      || cachedInputTokens === null
      || outputTokens === null
      ? null
      : inputTokens - cachedInputTokens + outputTokens,
    final_message: finalMessage,
    mcp_tools: [...mcpTools].sort(),
    mcp_tools_succeeded: [...mcpToolsSucceeded].sort(),
  };
}

function codeUnitCompare(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function shellWords(payload) {
  const words = [];
  let word = "";
  let wordStarted = false;
  let quote = null;
  for (let index = 0; index < payload.length; index += 1) {
    const character = payload[index];
    if (quote === "'") {
      if (character === "'") quote = null;
      else word += character;
      continue;
    }
    if (character === "\\") {
      if (index + 1 >= payload.length) return null;
      wordStarted = true;
      word += payload[index + 1];
      index += 1;
      continue;
    }
    if (character === '"') {
      quote = quote === '"' ? null : '"';
      wordStarted = true;
      continue;
    }
    if (quote === null && character === "'") {
      quote = "'";
      wordStarted = true;
      continue;
    }
    if (quote === null && /\s/u.test(character)) {
      if (wordStarted) words.push(word);
      word = "";
      wordStarted = false;
      continue;
    }
    wordStarted = true;
    word += character;
  }
  if (quote !== null) return null;
  if (wordStarted) words.push(word);
  return words;
}

function hasUnsafeOption(payload, argumentOffset, unsafeOptions) {
  const words = shellWords(payload);
  if (words === null) return true;
  return words.slice(argumentOffset).some((word) => [...unsafeOptions].some(
    (option) => word === option || word.startsWith(`${option}=`),
  ));
}

function approvedReadOnlyCommand(command) {
  if (typeof command !== "string") return false;
  const match = command.match(SHELL_COMMAND);
  if (match === null || hasUnsafeShellSyntax(match[2])) return false;
  const payload = match[2];
  if (APPROVED_GIT_COMMAND.test(payload)) {
    return !hasUnsafeOption(payload, 2, UNSAFE_GIT_OPTIONS);
  }
  if (/^rg(?:\s|$)/u.test(payload)) {
    return !hasUnsafeOption(payload, 1, UNSAFE_RG_OPTIONS);
  }
  return APPROVED_SED_PRINT.test(payload);
}

function hasUnsafeShellSyntax(payload) {
  let quote = null;
  for (let index = 0; index < payload.length; index += 1) {
    const character = payload[index];
    if (quote === "'") {
      if (character === "'") quote = null;
      continue;
    }
    if (character === "\\") {
      index += 1;
      continue;
    }
    if (character === '"') {
      quote = quote === '"' ? null : '"';
      continue;
    }
    if (quote === null && character === "'") {
      quote = "'";
      continue;
    }
    if (
      (quote === null && ";&|<>\r\n".includes(character))
      || ((quote === null || quote === '"') && character === "`")
      || ((quote === null || quote === '"') && character === "$")
    ) return true;
  }
  return quote !== null;
}

export function traceSafety(text) {
  const commands = new Map();
  let malformedCommandObserved = false;
  let malformedCommandCount = 0;
  let anonymous = 0;
  for (const [lineIndex, line] of text.split(/\r?\n/u).entries()) {
    if (line.length === 0) continue;
    let event;
    try {
      event = JSON.parse(line);
    } catch {
      throw new Error(`Codex JSONL trace line ${lineIndex + 1} is invalid`);
    }
    const item = event.item;
    if (!isRecord(item) || item.type !== "command_execution") continue;
    const id = typeof item.id === "string" ? item.id : `anonymous-${anonymous++}`;
    if (typeof item.command !== "string" || item.command.length === 0) {
      malformedCommandObserved = true;
      malformedCommandCount += 1;
      continue;
    }
    const previous = commands.get(id);
    if (previous !== undefined && previous !== item.command) {
      throw new Error(`Codex command ${id} changed within its trace`);
    }
    commands.set(id, item.command);
  }
  const orderedCommands = [...commands.entries()]
    .sort(([left], [right]) => codeUnitCompare(left, right))
    .map(([id, command]) => ({ id, command }));
  return {
    command_execution_count: orderedCommands.length + malformedCommandCount,
    commands_sha256: sha256Bytes(Buffer.from(canonicalJson(orderedCommands))),
    project_code_execution_observed: malformedCommandObserved
      || orderedCommands.some(({ command }) => !approvedReadOnlyCommand(command)),
  };
}

export function mcpToolContractPassed(spec, arm, tools) {
  if (!Array.isArray(tools)) return false;
  if (arm === "baseline") return tools.length === 0;
  if (arm !== "mcp" || !Array.isArray(spec?.host?.mcp_required_tools)) return false;
  return spec.host.mcp_required_tools.every((tool) => tools.includes(tool));
}

function confinedArtifact(rawDir, artifact) {
  if (
    !exactKeys(artifact, ["path", "sha256", "bytes"])
    || typeof artifact.path !== "string"
    || basename(artifact.path) !== artifact.path
    || !Number.isSafeInteger(artifact.bytes)
    || artifact.bytes < 0
  ) throw new Error("Agent dogfood artifact metadata is invalid");
  assertDigest(artifact.sha256, "Agent dogfood artifact");
  const canonicalRawDir = realpathSync(rawDir);
  const path = resolve(canonicalRawDir, artifact.path);
  if (dirname(path) !== canonicalRawDir || !existsSync(path)) {
    throw new Error("Agent dogfood artifact escapes its raw directory");
  }
  const metadata = lstatSync(path);
  if (!metadata.isFile() || metadata.isSymbolicLink() || dirname(realpathSync(path)) !== canonicalRawDir) {
    throw new Error("Agent dogfood artifact is not a confined regular file");
  }
  return path;
}

function validateRawDirectory(rawDir, spec) {
  const metadata = lstatSync(rawDir);
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
    throw new Error("Agent dogfood raw path is not a regular directory");
  }
  const required = new Set(["environment.json"]);
  for (const arm of ARM_NAMES) {
    for (let ordinal = 1; ordinal <= spec.host.samples_per_arm; ordinal += 1) {
      const sampleId = `${arm}-${ordinal}`;
      for (const suffix of [
        "answer.json",
        "last-message.txt",
        "safety.json",
        "sample.json",
        "trace.jsonl",
      ]) {
        required.add(`${sampleId}.${suffix}`);
      }
    }
  }
  const allowed = new Set([...required, "report.json"]);
  const entries = readdirSync(rawDir, { withFileTypes: true });
  for (const entry of entries) {
    if (!allowed.has(entry.name) || !entry.isFile() || entry.isSymbolicLink()) {
      throw new Error(`Agent dogfood raw directory has an unexpected entry: ${entry.name}`);
    }
  }
  const observed = new Set(entries.map((entry) => entry.name));
  for (const name of required) {
    if (!observed.has(name)) {
      throw new Error(`Agent dogfood raw directory is missing ${name}`);
    }
  }
}

async function validateArtifact(rawDir, artifact) {
  const path = confinedArtifact(rawDir, artifact);
  if (statSync(path).size !== artifact.bytes || await sha256File(path) !== artifact.sha256) {
    throw new Error(`Agent dogfood artifact digest drifted: ${artifact.path}`);
  }
  return path;
}

function validateSafetySnapshot(snapshot) {
  if (
    !exactKeys(snapshot, [
      "source_sha256",
      "store_sha256",
      "journal_sha256",
      "daemon_state_sha256",
      "relevant_processes",
    ])
    || !Number.isSafeInteger(snapshot.relevant_processes)
    || snapshot.relevant_processes < 0
  ) throw new Error("Agent dogfood safety snapshot is invalid");
  for (const [label, digest] of [
    ["source", snapshot.source_sha256],
    ["Store", snapshot.store_sha256],
    ["journal", snapshot.journal_sha256],
    ["daemon state", snapshot.daemon_state_sha256],
  ]) assertDigest(digest, `Agent dogfood safety ${label}`);
}

function matchesSafetyBaseline(snapshot, baseline) {
  return canonicalJson(snapshot) === canonicalJson(baseline);
}

function validateSafetyEvidence(evidence, sampleId, traceObservation, baseline) {
  if (
    !exactKeys(evidence, ["schema_version", "sample_id", "before", "after", "trace"])
    || evidence.schema_version !== SAFETY_SCHEMA_VERSION
    || evidence.sample_id !== sampleId
    || !exactKeys(evidence.trace, [
      "command_execution_count",
      "commands_sha256",
      "project_code_execution_observed",
    ])
    || !Number.isSafeInteger(evidence.trace.command_execution_count)
    || evidence.trace.command_execution_count < 0
    || typeof evidence.trace.project_code_execution_observed !== "boolean"
  ) throw new Error("Agent dogfood safety evidence is invalid");
  assertDigest(evidence.trace.commands_sha256, "Agent dogfood safety command trace");
  validateSafetySnapshot(evidence.before);
  validateSafetySnapshot(evidence.after);
  if (canonicalJson(evidence.trace) !== canonicalJson(traceObservation)) {
    throw new Error("Agent dogfood safety trace observation drifted");
  }
  if (
    !matchesSafetyBaseline(evidence.before, baseline)
    || !matchesSafetyBaseline(evidence.after, baseline)
  ) throw new Error("Agent dogfood safety evidence drifted from its predeclared baseline");
  return evidence;
}

function derivedSafety(evidence, mcpTools) {
  return {
    source_unchanged:
      evidence.before.source_sha256 === evidence.after.source_sha256,
    store_unchanged:
      evidence.before.store_sha256 === evidence.after.store_sha256,
    journal_unchanged:
      evidence.before.journal_sha256 === evidence.after.journal_sha256,
    daemon_state_unchanged:
      evidence.before.daemon_state_sha256 === evidence.after.daemon_state_sha256,
    no_lingering_depgraph_process: evidence.before.relevant_processes === 0
      && evidence.after.relevant_processes === 0,
    project_code_executed: evidence.trace.project_code_execution_observed,
    privileged_tools_observed:
      mcpTools.filter((tool) => PRIVILEGED_MCP_TOOLS.has(tool)),
  };
}

function expectedSampleIdentity(spec, digests, environmentSha256) {
  return {
    benchmark_id: spec.benchmark_id,
    spec_sha256: digests.spec,
    prompt_sha256: digests.prompt,
    answer_schema_sha256: digests.answerSchema,
    safety_schema_sha256: digests.safetySchema,
    environment_sha256: environmentSha256,
    repository_commit: spec.repository.candidate_commit,
    repository_tree: spec.repository.candidate_tree,
    model: spec.host.model,
    reasoning_effort: spec.host.reasoning_effort,
    sandbox: spec.host.sandbox,
    approval_policy: spec.host.approval_policy,
    maximum_tool_calls: spec.host.maximum_tool_calls,
    timeout_ms: spec.host.timeout_ms,
    mcp_enabled_tools: spec.host.mcp_enabled_tools,
    mcp_required_tools: spec.host.mcp_required_tools,
  };
}

function typedFailure(code, task, remediation) {
  return { code, task, remediation };
}

async function validateSample(spec, rawDir, sample, expectedIdentity) {
  const expectedSampleId = `${sample?.arm}-${sample?.ordinal}`;
  if (
    !exactKeys(sample, [
      "schema_version",
      "sample_id",
      "arm",
      "ordinal",
      "started_at",
      "finished_at",
      "identity",
      "artifacts",
      "runtime",
      "score",
      "failure",
      "safety",
    ])
    || sample.schema_version !== SAMPLE_SCHEMA_VERSION
    || !ARM_NAMES.includes(sample.arm)
    || !Number.isSafeInteger(sample.ordinal)
    || sample.ordinal < 1
    || sample.ordinal > spec.host.samples_per_arm
    || sample.sample_id !== expectedSampleId
    || !Number.isFinite(Date.parse(sample.started_at))
    || !Number.isFinite(Date.parse(sample.finished_at))
    || Date.parse(sample.finished_at) < Date.parse(sample.started_at)
    || canonicalJson(sample.identity) !== canonicalJson(expectedIdentity)
    || !exactKeys(sample.artifacts, ["trace", "host_output", "answer", "safety"])
    || sample.artifacts.trace?.path !== `${expectedSampleId}.trace.jsonl`
    || sample.artifacts.host_output?.path !== `${expectedSampleId}.last-message.txt`
    || sample.artifacts.answer?.path !== `${expectedSampleId}.answer.json`
    || sample.artifacts.safety?.path !== `${expectedSampleId}.safety.json`
  ) throw new Error("Agent dogfood sample envelope is invalid");
  const tracePath = await validateArtifact(rawDir, sample.artifacts.trace);
  const hostOutputPath = await validateArtifact(rawDir, sample.artifacts.host_output);
  const answerPath = await validateArtifact(rawDir, sample.artifacts.answer);
  const safetyPath = await validateArtifact(rawDir, sample.artifacts.safety);
  const traceText = readFileSync(tracePath, "utf8");
  const metrics = traceMetrics(traceText);
  const traceObservation = traceSafety(traceText);
  for (const key of [
    "tool_calls",
    "tool_result_bytes",
    "input_tokens",
    "cached_input_tokens",
    "output_tokens",
    "total_tokens",
    "effective_tokens",
  ]) {
    if (sample.runtime[key] !== metrics[key]) {
      throw new Error(`Agent dogfood sample trace metric drifted: ${key}`);
    }
  }
  const optionalNonnegativeInteger = (value) => value === null
    || (Number.isSafeInteger(value) && value >= 0);
  const integerRuntimeKeys = [
    "elapsed_ms",
    "tool_calls",
    "tool_result_bytes",
    "stderr_bytes",
  ];
  const tokenRuntimeKeys = [
    "input_tokens",
    "cached_input_tokens",
    "output_tokens",
    "total_tokens",
    "effective_tokens",
  ];
  if (
    !exactKeys(sample.runtime, [
      "exit_code",
      "timed_out",
      "tool_budget_exhausted",
      "elapsed_ms",
      "tool_calls",
      "tool_result_bytes",
      "input_tokens",
      "cached_input_tokens",
      "output_tokens",
      "total_tokens",
      "effective_tokens",
      "stderr_bytes",
      "stderr_sha256",
      "host_output_valid",
      "mcp_tools",
      "mcp_tools_succeeded",
    ])
    || (sample.runtime.exit_code !== null
      && !Number.isSafeInteger(sample.runtime.exit_code))
    || typeof sample.runtime.timed_out !== "boolean"
    || typeof sample.runtime.tool_budget_exhausted !== "boolean"
    || typeof sample.runtime.host_output_valid !== "boolean"
    || integerRuntimeKeys.some(
      (key) => !Number.isSafeInteger(sample.runtime[key]) || sample.runtime[key] < 0,
    )
    || tokenRuntimeKeys.some((key) => !optionalNonnegativeInteger(sample.runtime[key]))
    || (sample.runtime.cached_input_tokens !== null
      && (sample.runtime.input_tokens === null
        || sample.runtime.cached_input_tokens > sample.runtime.input_tokens))
    || (sample.runtime.total_tokens !== null
      && (sample.runtime.input_tokens === null
        || sample.runtime.output_tokens === null
        || sample.runtime.total_tokens
          !== sample.runtime.input_tokens + sample.runtime.output_tokens))
    || (sample.runtime.effective_tokens !== null
      && (sample.runtime.input_tokens === null
        || sample.runtime.cached_input_tokens === null
        || sample.runtime.output_tokens === null
        || sample.runtime.effective_tokens
          !== sample.runtime.input_tokens
            - sample.runtime.cached_input_tokens
            + sample.runtime.output_tokens))
    || (sample.runtime.tool_calls > spec.host.maximum_tool_calls
      && (!sample.runtime.tool_budget_exhausted
        || sample.runtime.tool_calls > spec.host.maximum_tool_calls + 1))
    || !Array.isArray(sample.runtime.mcp_tools)
    || sample.runtime.mcp_tools.some((tool) => typeof tool !== "string")
    || !Array.isArray(sample.runtime.mcp_tools_succeeded)
    || sample.runtime.mcp_tools_succeeded.some((tool) => typeof tool !== "string")
    || canonicalJson(sample.runtime.mcp_tools)
      !== canonicalJson([...new Set(sample.runtime.mcp_tools)].sort())
    || canonicalJson(sample.runtime.mcp_tools_succeeded)
      !== canonicalJson([...new Set(sample.runtime.mcp_tools_succeeded)].sort())
    || sample.runtime.mcp_tools_succeeded.some(
      (tool) => !sample.runtime.mcp_tools.includes(tool),
    )
    || (sample.arm === "baseline" && sample.runtime.mcp_tools.length !== 0)
    || (sample.arm === "baseline" && sample.runtime.mcp_tools_succeeded.length !== 0)
    || (sample.arm === "mcp"
      && sample.runtime.mcp_tools.some(
        (tool) => !spec.host.mcp_enabled_tools.includes(tool),
      ))
    || canonicalJson(sample.runtime.mcp_tools) !== canonicalJson(metrics.mcp_tools)
    || canonicalJson(sample.runtime.mcp_tools_succeeded)
      !== canonicalJson(metrics.mcp_tools_succeeded)
  ) throw new Error("Agent dogfood sample runtime is invalid");
  assertDigest(sample.runtime.stderr_sha256, "Agent dogfood stderr");
  validateSampleFailure(sample.failure);
  if (
    sample.failure === null
    && !mcpToolContractPassed(spec, sample.arm, sample.runtime.mcp_tools_succeeded)
  ) throw new Error("Agent dogfood successful sample did not satisfy its tool contract");
  if (
    sample.failure === null
    && (sample.runtime.exit_code !== 0
      || sample.runtime.timed_out
      || sample.runtime.tool_budget_exhausted
      || !sample.runtime.host_output_valid)
  ) throw new Error("Agent dogfood successful sample has a failed runtime");
  const answer = jsonFile(answerPath);
  validateAnswer(spec, answer);
  let rawAnswer = null;
  try {
    rawAnswer = JSON.parse(readFileSync(hostOutputPath, "utf8"));
    validateAnswer(spec, rawAnswer);
  } catch {
    rawAnswer = null;
  }
  if (
    sample.runtime.host_output_valid !== (rawAnswer !== null)
    || (rawAnswer !== null && canonicalJson(rawAnswer) !== canonicalJson(answer))
    || (rawAnswer === null
      && !["host_failure", "excessive_context"].includes(sample.failure?.code))
  ) throw new Error("Agent dogfood raw host output does not match its normalized answer");
  const score = scoreAnswer(spec, answer);
  if (canonicalJson(score) !== canonicalJson(sample.score)) {
    throw new Error("Agent dogfood sample score is not canonical");
  }
  const safetyEvidence = validateSafetyEvidence(
    jsonFile(safetyPath),
    expectedSampleId,
    traceObservation,
    spec.safety_baseline,
  );
  if (
    canonicalJson(sample.safety)
      !== canonicalJson(derivedSafety(safetyEvidence, sample.runtime.mcp_tools))
  ) throw new Error("Agent dogfood sample safety result is not derived from raw evidence");
  return { sample, answer };
}

function aggregateArm(samples) {
  const totals = (key) => samples.map((sample) => sample.runtime[key]);
  const scores = (key) => samples.map((sample) => sample.score[key]);
  const totalTokenSamples = totals("total_tokens");
  const effectiveTokenSamples = totals("effective_tokens");
  const tokensAvailable = effectiveTokenSamples.every(
    (value) => Number.isSafeInteger(value),
  );
  const failureCounts = Object.fromEntries(FAILURE_CODES.map((code) => [code, 0]));
  for (const sample of samples) {
    if (sample.failure !== null) failureCounts[sample.failure.code] += 1;
  }
  return {
    samples: samples.length,
    setup_successes: samples.filter((sample) => sample.failure === null).length,
    accuracy_percent_samples: scores("accuracy_percent"),
    accuracy_percent_median: median(scores("accuracy_percent")),
    major_recall_percent_samples: scores("major_recall_percent"),
    major_recall_percent_median: median(scores("major_recall_percent")),
    false_exact_claims: scores("false_exact_claims").reduce((sum, value) => sum + value, 0),
    candidate_or_unresolved_as_exact: scores("candidate_or_unresolved_as_exact")
      .reduce((sum, value) => sum + value, 0),
    tool_calls_samples: totals("tool_calls"),
    tool_calls_median: median(totals("tool_calls")),
    tool_result_bytes_samples: totals("tool_result_bytes"),
    tool_result_bytes_median: median(totals("tool_result_bytes")),
    elapsed_ms_samples: totals("elapsed_ms"),
    elapsed_ms_median: median(totals("elapsed_ms")),
    tokens_available: tokensAvailable,
    total_tokens_samples: totalTokenSamples.every(Number.isSafeInteger)
      ? totalTokenSamples
      : null,
    total_tokens_median: totalTokenSamples.every(Number.isSafeInteger)
      ? median(totalTokenSamples)
      : null,
    effective_tokens_samples: tokensAvailable ? effectiveTokenSamples : null,
    effective_tokens_median: tokensAvailable ? median(effectiveTokenSamples) : null,
    typed_failures: failureCounts,
  };
}

function safetyPassed(sample) {
  return sample.safety.source_unchanged
    && sample.safety.store_unchanged
    && sample.safety.journal_unchanged
    && sample.safety.daemon_state_unchanged
    && sample.safety.no_lingering_depgraph_process
    && sample.safety.project_code_executed === false
    && sample.safety.privileged_tools_observed.length === 0;
}

function gateCheck(name, passed, actual, threshold) {
  return { name, passed, actual: String(actual), threshold: String(threshold) };
}

function evaluateGate(spec, samples, environment, aggregates) {
  const { baseline, mcp } = aggregates;
  const thresholds = spec.thresholds;
  const mcpSamples = samples.filter((sample) => sample.arm === "mcp");
  const mcpToolContractPasses = mcpSamples.filter((sample) =>
    mcpToolContractPassed(spec, sample.arm, sample.runtime.mcp_tools_succeeded)
  ).length;
  const toolCallRatio = efficiencyRatio(
    mcp.tool_calls_median,
    baseline.tool_calls_median,
  );
  const toolBytesRatio = efficiencyRatio(
    mcp.tool_result_bytes_median,
    baseline.tool_result_bytes_median,
  );
  const elapsedRatio = efficiencyRatio(
    mcp.elapsed_ms_median,
    baseline.elapsed_ms_median,
  );
  const tokensComparable = baseline.tokens_available && mcp.tokens_available;
  const tokenRatio = tokensComparable
    ? efficiencyRatio(mcp.effective_tokens_median, baseline.effective_tokens_median)
    : null;
  const reconnect = environment.packaged_security.safe_scan_recovered_after_eof
    && environment.packaged_security.safe_scan_terminal_status === "completed"
    && environment.packaged_security.safe_scan_project_code_executed === false
    && environment.packaged_security.operation_cancel_denied_code === "CAPABILITY_DENIED"
    && environment.packaged_security.stdin_eof_clean_exit
    && environment.packaged_security.stdout_json_rpc_only;
  const checks = [
    gateCheck(
      "mcp_accuracy_each_sample",
      mcp.accuracy_percent_samples.every(
        (value) => value >= thresholds.minimum_mcp_accuracy_percent,
      ),
      Math.min(...mcp.accuracy_percent_samples),
      `>=${thresholds.minimum_mcp_accuracy_percent}`,
    ),
    gateCheck(
      "mcp_major_recall_each_sample",
      mcp.major_recall_percent_samples.every(
        (value) => value >= thresholds.minimum_mcp_major_recall_percent,
      ),
      Math.min(...mcp.major_recall_percent_samples),
      `>=${thresholds.minimum_mcp_major_recall_percent}`,
    ),
    gateCheck(
      "mcp_false_exact_claims",
      mcp.false_exact_claims <= thresholds.maximum_false_exact_claims,
      mcp.false_exact_claims,
      `<=${thresholds.maximum_false_exact_claims}`,
    ),
    gateCheck(
      "mcp_candidate_or_unresolved_as_exact",
      mcp.candidate_or_unresolved_as_exact
        <= thresholds.maximum_candidate_or_unresolved_as_exact,
      mcp.candidate_or_unresolved_as_exact,
      `<=${thresholds.maximum_candidate_or_unresolved_as_exact}`,
    ),
    gateCheck(
      "baseline_setup_successes",
      baseline.setup_successes >= thresholds.minimum_setup_successes_per_arm,
      baseline.setup_successes,
      `>=${thresholds.minimum_setup_successes_per_arm}`,
    ),
    gateCheck(
      "mcp_setup_successes",
      mcp.setup_successes >= thresholds.minimum_setup_successes_per_arm,
      mcp.setup_successes,
      `>=${thresholds.minimum_setup_successes_per_arm}`,
    ),
    gateCheck(
      "mcp_required_tools_each_sample",
      !thresholds.require_mcp_tool_contract
        || mcpToolContractPasses === mcpSamples.length,
      `${mcpToolContractPasses}/${mcpSamples.length}`,
      `${mcpSamples.length}/${mcpSamples.length}`,
    ),
    gateCheck(
      "mcp_accuracy_not_below_baseline",
      !thresholds.require_mcp_accuracy_not_below_baseline
        || mcp.accuracy_percent_median >= baseline.accuracy_percent_median,
      `${mcp.accuracy_percent_median}/${baseline.accuracy_percent_median}`,
      ">=1",
    ),
    gateCheck(
      "mcp_median_tool_calls",
      mcp.tool_calls_median <= thresholds.maximum_mcp_median_tool_calls,
      mcp.tool_calls_median,
      `<=${thresholds.maximum_mcp_median_tool_calls}`,
    ),
    gateCheck(
      "mcp_median_tool_result_bytes",
      mcp.tool_result_bytes_median <= thresholds.maximum_mcp_median_tool_result_bytes,
      mcp.tool_result_bytes_median,
      `<=${thresholds.maximum_mcp_median_tool_result_bytes}`,
    ),
    gateCheck(
      "mcp_median_elapsed_ms",
      mcp.elapsed_ms_median <= thresholds.maximum_mcp_median_elapsed_ms,
      mcp.elapsed_ms_median,
      `<=${thresholds.maximum_mcp_median_elapsed_ms}`,
    ),
    gateCheck(
      "mcp_median_effective_tokens",
      tokensComparable
        ? mcp.effective_tokens_median <= thresholds.maximum_mcp_median_effective_tokens
        : mcp.tool_result_bytes_median <= thresholds.maximum_mcp_median_tool_result_bytes,
      tokensComparable
        ? mcp.effective_tokens_median
        : `unavailable;tool_result_bytes_proxy=${mcp.tool_result_bytes_median}`,
      tokensComparable
        ? `<=${thresholds.maximum_mcp_median_effective_tokens}`
        : `proxy<=${thresholds.maximum_mcp_median_tool_result_bytes}`,
    ),
    gateCheck(
      "read_only_safety",
      !thresholds.require_read_only_safety || samples.every(safetyPassed),
      samples.filter(safetyPassed).length,
      `${samples.length}/${samples.length}`,
    ),
    gateCheck(
      "packaged_disconnect_reconnect",
      !thresholds.require_packaged_reconnect || reconnect,
      reconnect,
      true,
    ),
  ];
  return {
    checks,
    passed: checks.every((check) => check.passed),
    efficiency_ratios: {
      tool_calls: toolCallRatio,
      tool_result_bytes: toolBytesRatio,
      elapsed_ms: elapsedRatio,
      total_tokens: tokenRatio,
      token_metric: tokensComparable
        ? "host_effective_usage"
        : "tool_result_bytes_proxy",
    },
  };
}

function validateEnvironment(spec, environment) {
  if (
    !exactKeys(environment, [
      "schema_version",
      "benchmark_id",
      "captured_at",
      "host",
      "release",
      "snapshots",
      "packaged_security",
    ])
    || environment.schema_version !== ENVIRONMENT_SCHEMA_VERSION
    || environment.benchmark_id !== spec.benchmark_id
    || !Number.isFinite(Date.parse(environment.captured_at))
    || !exactKeys(environment.host, [
      "program",
      "cli_version",
      "platform",
      "architecture",
    ])
    || !exactKeys(environment.release, [
      "tag",
      "target",
      "archive_sha256",
      "compiler_pack_archive_sha256",
      "compiler_pack_requirement_sha256",
      "manifest_sha256",
      "depgraph_sha256",
      "mcp_binary_sha256",
      "mcp_smoke_sha256",
    ])
    || !exactKeys(environment.snapshots, [
      "baseline_id",
      "baseline_revision",
      "candidate_id",
      "candidate_revision",
    ])
    || !exactKeys(environment.packaged_security, [
      "schema_version",
      "read_catalog_sha256",
      "safe_scan_recovered_after_eof",
      "safe_scan_terminal_status",
      "safe_scan_project_code_executed",
      "operation_cancel_denied_code",
      "stdin_eof_clean_exit",
      "stdout_json_rpc_only",
    ])
    || environment.host.program !== spec.host.program
    || typeof environment.host.cli_version !== "string"
    || !semverAtLeast(environment.host.cli_version, spec.host.minimum_cli_version)
    || environment.host.platform !== "darwin"
    || environment.host.architecture !== "arm64"
    || environment.release.archive_sha256 !== spec.release.archive.sha256
    || environment.release.compiler_pack_archive_sha256
      !== spec.release.compiler_pack_archive.sha256
    || environment.release.compiler_pack_requirement_sha256
      !== spec.release.compiler_pack_requirement.sha256
    || environment.release.mcp_smoke_sha256 !== spec.release.mcp_smoke.sha256
    || environment.release.tag !== spec.release.tag
    || environment.release.target !== spec.release.host_target
    || environment.snapshots.baseline_id !== spec.snapshots.baseline.id
    || environment.snapshots.candidate_id !== spec.snapshots.candidate.id
    || environment.snapshots.baseline_revision !== spec.repository.baseline_commit
    || environment.snapshots.candidate_revision !== spec.repository.candidate_commit
    || environment.packaged_security.schema_version
      !== spec.release.mcp_smoke.schema_version
    || environment.packaged_security.read_catalog_sha256
      !== spec.release.mcp_smoke.read_catalog_sha256
    || environment.packaged_security.safe_scan_recovered_after_eof !== true
    || environment.packaged_security.safe_scan_terminal_status !== "completed"
    || environment.packaged_security.safe_scan_project_code_executed !== false
    || environment.packaged_security.operation_cancel_denied_code !== "CAPABILITY_DENIED"
    || environment.packaged_security.stdin_eof_clean_exit !== true
    || environment.packaged_security.stdout_json_rpc_only !== true
  ) throw new Error("Agent dogfood environment provenance is invalid");
  for (const [label, digest] of [
    ["release archive", environment.release.archive_sha256],
    ["compiler-pack archive", environment.release.compiler_pack_archive_sha256],
    ["compiler-pack requirement", environment.release.compiler_pack_requirement_sha256],
    ["manifest", environment.release.manifest_sha256],
    ["depgraph", environment.release.depgraph_sha256],
    ["MCP binary", environment.release.mcp_binary_sha256],
    ["MCP smoke", environment.release.mcp_smoke_sha256],
  ]) assertDigest(digest, label);
  return environment;
}

function sourceDigests(specPath) {
  const fixtureDir = dirname(resolve(specPath));
  const promptPath = join(fixtureDir, "prompt.md");
  const answerSchemaPath = join(fixtureDir, "answer.schema.json");
  const safetySchemaPath = join(fixtureDir, "safety.schema.json");
  return {
    fixtureDir,
    promptPath,
    answerSchemaPath,
    safetySchemaPath,
    spec: sha256Bytes(readFileSync(specPath)),
    prompt: sha256Bytes(readFileSync(promptPath)),
    answerSchema: sha256Bytes(readFileSync(answerSchemaPath)),
    safetySchema: sha256Bytes(readFileSync(safetySchemaPath)),
  };
}

export async function aggregateSamples({ specPath, rawDir }) {
  specPath = resolve(specPath);
  rawDir = resolve(rawDir);
  const spec = validateSpec(jsonFile(specPath));
  validateRawDirectory(rawDir, spec);
  const digests = sourceDigests(specPath);
  const environmentPath = join(rawDir, "environment.json");
  const environment = validateEnvironment(spec, jsonFile(environmentPath));
  const environmentSha256 = await sha256File(environmentPath);
  const identity = expectedSampleIdentity(spec, digests, environmentSha256);
  const samples = [];
  const sampleArtifacts = [];
  for (const arm of ARM_NAMES) {
    for (let ordinal = 1; ordinal <= spec.host.samples_per_arm; ordinal += 1) {
      const path = join(rawDir, `${arm}-${ordinal}.sample.json`);
      const sample = jsonFile(path);
      await validateSample(spec, rawDir, sample, identity);
      samples.push(sample);
      sampleArtifacts.push({
        sample_id: sample.sample_id,
        sample: await fileArtifact(path),
        answer: sample.artifacts.answer,
        host_output: sample.artifacts.host_output,
        safety: sample.artifacts.safety,
        trace: sample.artifacts.trace,
      });
    }
  }
  const aggregates = Object.fromEntries(
    ARM_NAMES.map((arm) => [
      arm,
      aggregateArm(samples.filter((sample) => sample.arm === arm)),
    ]),
  );
  const report = {
    schema_version: REPORT_SCHEMA_VERSION,
    benchmark_id: spec.benchmark_id,
    generated_at: samples.map((sample) => sample.finished_at).sort().at(-1),
    issue: spec.issue,
    inputs: {
      spec_sha256: digests.spec,
      prompt_sha256: digests.prompt,
      answer_schema_sha256: digests.answerSchema,
      safety_schema_sha256: digests.safetySchema,
      environment: await fileArtifact(environmentPath),
    },
    release: environment.release,
    repository: spec.repository,
    snapshots: environment.snapshots,
    safety_baseline: spec.safety_baseline,
    host: {
      ...environment.host,
      model: spec.host.model,
      reasoning_effort: spec.host.reasoning_effort,
      sandbox: spec.host.sandbox,
      approval_policy: spec.host.approval_policy,
      samples_per_arm: spec.host.samples_per_arm,
      maximum_tool_calls: spec.host.maximum_tool_calls,
      mcp_enabled_tools: spec.host.mcp_enabled_tools,
      mcp_required_tools: spec.host.mcp_required_tools,
      timeout_ms: spec.host.timeout_ms,
    },
    thresholds: spec.thresholds,
    samples: sampleArtifacts,
    aggregates,
    typed_failures: Object.fromEntries(
      FAILURE_CODES.map((code) => [
        code,
        samples.filter((sample) => sample.failure?.code === code).length,
      ]),
    ),
    security: environment.packaged_security,
    gate: evaluateGate(spec, samples, environment, aggregates),
  };
  if (!report.gate.passed) {
    const failed = report.gate.checks.filter((check) => !check.passed)
      .map((check) => check.name).join(", ");
    throw Object.assign(new Error(`Agent dogfood gate failed: ${failed}`), { report });
  }
  return report;
}

export async function verifyReport({ specPath, rawDir, report }) {
  const expected = await aggregateSamples({ specPath, rawDir });
  if (canonicalJson(report) !== canonicalJson(expected)) {
    throw new Error("Agent dogfood report is not the deterministic aggregate");
  }
  return true;
}

function commandOutput(program, args, options = {}) {
  return execFileSync(program, args, {
    encoding: "utf8",
    maxBuffer: 32 * 1024 * 1024,
    ...options,
  }).trim();
}

function semverTuple(value) {
  const match = value.match(/(\d+)\.(\d+)\.(\d+)/u);
  if (!match) throw new Error(`cannot parse semantic version from ${value}`);
  return match.slice(1).map(Number);
}

function semverAtLeast(actual, minimum) {
  const left = semverTuple(actual);
  const right = semverTuple(minimum);
  for (let index = 0; index < left.length; index += 1) {
    if (left[index] !== right[index]) return left[index] > right[index];
  }
  return true;
}

function canonicalExisting(path, kind, expectedKind) {
  if (!path || !isAbsolute(path) || !existsSync(path)) {
    throw new Error(`${kind} path must be an existing absolute path`);
  }
  const canonical = realpathSync(path);
  const metadata = lstatSync(canonical);
  if (
    (expectedKind === "file" && !metadata.isFile())
    || (expectedKind === "directory" && !metadata.isDirectory())
  ) throw new Error(`${kind} path must resolve to a ${expectedKind}`);
  return canonical;
}

function requiredRuntime() {
  return {
    repository: canonicalExisting(
      process.env.DEPGRAPH_AGENT_DOGFOOD_REPOSITORY,
      "repository",
      "directory",
    ),
    releaseArchive: canonicalExisting(
      process.env.DEPGRAPH_AGENT_DOGFOOD_RELEASE_ARCHIVE,
      "release archive",
      "file",
    ),
    packageRoot: canonicalExisting(
      process.env.DEPGRAPH_AGENT_DOGFOOD_PACKAGE_ROOT,
      "package root",
      "directory",
    ),
    compilerPackArchive: canonicalExisting(
      process.env.DEPGRAPH_AGENT_DOGFOOD_COMPILER_PACK_ARCHIVE,
      "compiler-pack archive",
      "file",
    ),
    compilerPackRequirement: canonicalExisting(
      process.env.DEPGRAPH_AGENT_DOGFOOD_COMPILER_PACK_REQUIREMENT,
      "compiler-pack requirement",
      "file",
    ),
    store: canonicalExisting(
      process.env.DEPGRAPH_AGENT_DOGFOOD_STORE,
      "store",
      "file",
    ),
    mcpSmoke: canonicalExisting(
      process.env.DEPGRAPH_AGENT_DOGFOOD_MCP_SMOKE,
      "MCP smoke",
      "file",
    ),
  };
}

async function fingerprintTree(root, excluded = new Set()) {
  const hash = createHash("sha256");
  async function visit(directory, prefix) {
    const entries = readdirSync(directory, { withFileTypes: true })
      .filter((entry) => !excluded.has(entry.name))
      .sort((left, right) => left.name.localeCompare(right.name));
    for (const entry of entries) {
      const path = join(directory, entry.name);
      const name = prefix ? `${prefix}/${entry.name}` : entry.name;
      const metadata = lstatSync(path);
      if (entry.isDirectory()) {
        hash.update(`d\0${name}\0${metadata.mode & 0o777}\0`);
        await visit(path, name);
      } else if (entry.isSymbolicLink()) {
        hash.update(`l\0${name}\0${readlinkSync(path)}\0`);
      } else if (entry.isFile()) {
        hash.update(`f\0${name}\0${metadata.mode & 0o777}\0${metadata.size}\0`);
        for await (const chunk of createReadStream(path)) hash.update(chunk);
        hash.update("\0");
      } else {
        hash.update(`o\0${name}\0${metadata.mode}\0`);
      }
    }
  }
  await visit(root, "");
  return hash.digest("hex");
}

async function fingerprintFileSet(paths) {
  const hash = createHash("sha256");
  for (const path of paths) {
    hash.update(`${basename(path)}\0`);
    if (!existsSync(path)) {
      hash.update("absent\0");
      continue;
    }
    const metadata = lstatSync(path);
    hash.update(`${metadata.mode & 0o777}\0${metadata.size}\0`);
    for await (const chunk of createReadStream(path)) hash.update(chunk);
    hash.update("\0");
  }
  return hash.digest("hex");
}

function storePaths(store) {
  return [store, `${store}-wal`, `${store}-shm`, `${store}.writer-lock`];
}

function journalPaths(store) {
  const journal = `${store}.operations.sqlite`;
  return [journal, `${journal}-wal`, `${journal}-shm`, `${journal}.purge-lock`];
}

async function daemonStateFingerprint(store) {
  const directory = dirname(store);
  const storeName = basename(store);
  const paths = readdirSync(directory)
    .filter((name) => !name.startsWith(storeName))
    .sort()
    .map((name) => join(directory, name));
  return fingerprintFileSet(paths);
}

function relevantProcesses(packageRoot, repository) {
  if (process.platform === "win32") return [];
  const output = commandOutput("ps", ["-axo", "command="]);
  return output.split(/\r?\n/u).filter((line) =>
    (line.includes("depgraph-mcp")
      || line.includes("depgraph-operation-runner")
      || line.includes("depgraph daemon"))
    && (line.includes(packageRoot) || line.includes(repository))
  );
}

async function safetySnapshot(runtime) {
  return {
    source_sha256: await fingerprintTree(runtime.repository, new Set([".git"])),
    store_sha256: await fingerprintFileSet(storePaths(runtime.store)),
    journal_sha256: await fingerprintFileSet(journalPaths(runtime.store)),
    daemon_state_sha256: await daemonStateFingerprint(runtime.store),
    relevant_processes: relevantProcesses(runtime.packageRoot, runtime.repository).length,
  };
}

function snapshotShow(depgraph, store, name, cwd) {
  return JSON.parse(commandOutput(
    depgraph,
    ["snapshot", "show", name, "--store", store, "--json"],
    { cwd },
  )).data;
}

async function preflight(spec, runtime) {
  if (await sha256File(runtime.releaseArchive) !== spec.release.archive.sha256) {
    throw new Error("public release archive digest mismatch");
  }
  if (
    await sha256File(runtime.compilerPackArchive)
      !== spec.release.compiler_pack_archive.sha256
  ) throw new Error("public compiler-pack archive digest mismatch");
  if (
    await sha256File(runtime.compilerPackRequirement)
      !== spec.release.compiler_pack_requirement.sha256
  ) throw new Error("public compiler-pack requirement digest mismatch");
  if (await sha256File(runtime.mcpSmoke) !== spec.release.mcp_smoke.sha256) {
    throw new Error("public MCP smoke digest mismatch");
  }
  const candidateCommit = commandOutput("git", ["rev-parse", "HEAD"], {
    cwd: runtime.repository,
  });
  const candidateTree = commandOutput("git", ["rev-parse", "HEAD^{tree}"], {
    cwd: runtime.repository,
  });
  const baselineTree = commandOutput(
    "git",
    ["rev-parse", `${spec.repository.baseline_commit}^{tree}`],
    { cwd: runtime.repository },
  );
  if (
    candidateCommit !== spec.repository.candidate_commit
    || candidateTree !== spec.repository.candidate_tree
    || baselineTree !== spec.repository.baseline_tree
  ) throw new Error("dogfood repository is not the fixed candidate checkout");
  const repositoryStatus = commandOutput(
    "git",
    ["status", "--porcelain=v1", "--untracked-files=all"],
    { cwd: runtime.repository },
  );
  if (repositoryStatus.length !== 0) {
    throw new Error("dogfood repository must be a clean fixed candidate checkout");
  }
  const archiveRoot = spec.release.archive.name.replace(/\.tar\.gz$/u, "");
  if (basename(runtime.packageRoot) !== archiveRoot) {
    throw new Error("extracted release package root has the wrong identity");
  }
  const manifestPath = join(runtime.packageRoot, "release-manifest.json");
  const depgraph = join(runtime.packageRoot, "bin", "depgraph");
  const mcp = join(runtime.packageRoot, "bin", "depgraph-mcp");
  for (const path of [manifestPath, depgraph, mcp]) {
    if (!existsSync(path) || !lstatSync(path).isFile()) {
      throw new Error("extracted release package is incomplete");
    }
  }
  let archiveManifest;
  try {
    archiveManifest = execFileSync(
      "tar",
      ["-xOf", runtime.releaseArchive, `${archiveRoot}/release-manifest.json`],
      { maxBuffer: 4 * 1024 * 1024 },
    );
  } catch {
    throw new Error("cannot read the release manifest from the public archive");
  }
  if (!archiveManifest.equals(readFileSync(manifestPath))) {
    throw new Error("extracted release manifest is not from the fixed public archive");
  }
  const manifest = jsonFile(manifestPath);
  if (
    manifest.target !== spec.release.host_target
    || manifest.core?.path !== "bin/depgraph"
    || manifest.mcp_server?.path !== "bin/depgraph-mcp"
    || manifest.mcp_server?.version !== "0.5.0"
    || manifest.mcp_server?.sdk_name !== "rmcp"
    || manifest.mcp_server?.sdk_version !== "3.1.0"
    || manifest.mcp_server?.protocol_revision !== "2026-07-28"
    || manifest.mcp_server?.tool_contract_version !== "depgraph-mcp-tools-v1"
    || manifest.mcp_server?.operation_contract_version !== "depgraph-operation-v1"
    || await sha256File(mcp) !== manifest.mcp_server.sha256
    || await sha256File(depgraph) !== manifest.core?.sha256
  ) throw new Error("extracted release manifest identity mismatch");
  const baseline = snapshotShow(
    depgraph,
    runtime.store,
    spec.snapshots.baseline.name,
    runtime.repository,
  );
  const candidate = snapshotShow(
    depgraph,
    runtime.store,
    spec.snapshots.candidate.name,
    runtime.repository,
  );
  if (
    baseline.id !== spec.snapshots.baseline.id
    || candidate.id !== spec.snapshots.candidate.id
    || baseline.source_revision !== spec.repository.baseline_commit
    || candidate.source_revision !== spec.repository.candidate_commit
    || baseline.status !== "completed"
    || candidate.status !== "completed"
    || baseline.coverage.project_code_executed !== false
    || candidate.coverage.project_code_executed !== false
  ) throw new Error("fixed dogfood snapshots are missing or incompatible");
  const smoke = jsonFile(runtime.mcpSmoke);
  if (
    smoke.schema_version !== spec.release.mcp_smoke.schema_version
    || smoke.target !== spec.release.host_target
    || smoke.archive_sha256 !== spec.release.archive.sha256
    || smoke.profile_catalog_sha256?.read
      !== spec.release.mcp_smoke.read_catalog_sha256
  ) throw new Error("public packaged MCP smoke identity mismatch");
  const codexVersion = commandOutput(spec.host.program, ["--version"]);
  if (!semverAtLeast(codexVersion, spec.host.minimum_cli_version)) {
    throw new Error("Codex CLI does not meet the fixed dogfood host version");
  }
  if (process.platform !== "darwin" || process.arch !== "arm64") {
    throw new Error("Agent dogfood host does not match aarch64-apple-darwin");
  }
  return {
    depgraph,
    mcp,
    environment: {
      schema_version: ENVIRONMENT_SCHEMA_VERSION,
      benchmark_id: spec.benchmark_id,
      captured_at: new Date().toISOString(),
      host: {
        program: spec.host.program,
        cli_version: codexVersion,
        platform: process.platform,
        architecture: process.arch,
      },
      release: {
        tag: spec.release.tag,
        target: spec.release.host_target,
        archive_sha256: spec.release.archive.sha256,
        compiler_pack_archive_sha256: spec.release.compiler_pack_archive.sha256,
        compiler_pack_requirement_sha256:
          spec.release.compiler_pack_requirement.sha256,
        manifest_sha256: await sha256File(manifestPath),
        depgraph_sha256: await sha256File(depgraph),
        mcp_binary_sha256: await sha256File(mcp),
        mcp_smoke_sha256: spec.release.mcp_smoke.sha256,
      },
      snapshots: {
        baseline_id: baseline.id,
        baseline_revision: baseline.source_revision,
        candidate_id: candidate.id,
        candidate_revision: candidate.source_revision,
      },
      packaged_security: {
        schema_version: smoke.schema_version,
        read_catalog_sha256: smoke.profile_catalog_sha256.read,
        safe_scan_recovered_after_eof: smoke.safe_scan_recovered_after_eof,
        safe_scan_terminal_status: smoke.safe_scan_terminal_status,
        safe_scan_project_code_executed: smoke.safe_scan_project_code_executed,
        operation_cancel_denied_code: smoke.operation_cancel_denied_code,
        stdin_eof_clean_exit: smoke.stdin_eof_clean_exit,
        stdout_json_rpc_only: smoke.stdout_json_rpc_only,
      },
    },
  };
}

function terminateProcessGroup(child, signal = "SIGTERM") {
  if (!child.pid) return;
  try {
    if (process.platform === "win32") child.kill(signal);
    else process.kill(-child.pid, signal);
  } catch {
    try {
      child.kill(signal);
    } catch {
      // The process may already have exited between the group and direct kill.
    }
  }
}

async function runCodex({ spec, runtime, preflightResult, prompt, answerSchema, arm, ordinal, rawDir }) {
  const sampleId = `${arm}-${ordinal}`;
  const tracePath = join(rawDir, `${sampleId}.trace.jsonl`);
  const hostOutputPath = join(rawDir, `${sampleId}.last-message.txt`);
  const answerPath = join(rawDir, `${sampleId}.answer.json`);
  const safetyPath = join(rawDir, `${sampleId}.safety.json`);
  const traceStream = createWriteStream(tracePath, { flags: "wx" });
  const traceClosed = once(traceStream, "close");
  const args = [
    "exec",
    "--json",
    "--ephemeral",
    "--ignore-user-config",
    "--ignore-rules",
    "--output-schema",
    answerSchema,
    "--output-last-message",
    hostOutputPath,
    "--sandbox",
    spec.host.sandbox,
    "--model",
    spec.host.model,
    "--config",
    `model_reasoning_effort=${JSON.stringify(spec.host.reasoning_effort)}`,
    "--config",
    `approval_policy=${JSON.stringify(spec.host.approval_policy)}`,
    "--cd",
    runtime.repository,
  ];
  if (arm === "mcp") {
    const mcpArgs = [
      "--root", runtime.repository,
      "--store", runtime.store,
      "--capability", "read",
      "--compiler-pack-requirement", runtime.compilerPackRequirement,
      "--log-level", "warn",
    ];
    args.push(
      "--config",
      `mcp_servers.depgraph.command=${JSON.stringify(preflightResult.mcp)}`,
      "--config",
      `mcp_servers.depgraph.args=${JSON.stringify(mcpArgs)}`,
      "--config",
      `mcp_servers.depgraph.enabled_tools=${JSON.stringify(spec.host.mcp_enabled_tools)}`,
      "--config",
      "mcp_servers.depgraph.default_tools_approval_mode=\"approve\"",
    );
  }
  args.push("-");
  const before = await safetySnapshot(runtime);
  if (!matchesSafetyBaseline(before, spec.safety_baseline)) {
    throw new Error("Agent dogfood runtime drifted from the predeclared safety baseline");
  }
  const startedAt = new Date();
  const startNs = process.hrtime.bigint();
  const child = spawn(spec.host.program, args, {
    cwd: runtime.repository,
    detached: process.platform !== "win32",
    stdio: ["pipe", "pipe", "pipe"],
    env: process.env,
  });
  let stderrBytes = 0;
  const stderrHash = createHash("sha256");
  let timedOut = false;
  let toolBudgetExhausted = false;
  let interruptedSignal = null;
  let forceKillTimer = null;
  let liveBuffer = "";
  const liveToolIds = new Set();
  const stopChild = () => {
    terminateProcessGroup(child);
    if (forceKillTimer === null) {
      forceKillTimer = setTimeout(() => {
        terminateProcessGroup(child, "SIGKILL");
      }, 5_000);
      forceKillTimer.unref();
    }
  };
  const interrupt = (signal) => {
    interruptedSignal ??= signal;
    stopChild();
  };
  const onSigint = () => interrupt("SIGINT");
  const onSigterm = () => interrupt("SIGTERM");
  process.once("SIGINT", onSigint);
  process.once("SIGTERM", onSigterm);
  child.stdout.pipe(traceStream);
  child.stdout.on("data", (chunk) => {
    liveBuffer += chunk.toString("utf8");
    const lines = liveBuffer.split(/\r?\n/u);
    liveBuffer = lines.pop() ?? "";
    for (const line of lines) {
      if (line.length === 0) continue;
      try {
        const event = JSON.parse(line);
        const item = event.item;
        if (
          event.type === "item.started"
          && TOOL_ITEM_TYPES.has(item?.type)
          && typeof item.id === "string"
        ) liveToolIds.add(item.id);
      } catch {
        continue;
      }
      if (liveToolIds.size > spec.host.maximum_tool_calls && !toolBudgetExhausted) {
        toolBudgetExhausted = true;
        stopChild();
      }
    }
  });
  child.stderr.on("data", (chunk) => {
    stderrBytes += chunk.length;
    stderrHash.update(chunk);
  });
  child.stdin.end(prompt);
  const timer = setTimeout(() => {
    timedOut = true;
    stopChild();
  }, spec.host.timeout_ms);
  let exitCode;
  try {
    [exitCode] = await once(child, "close");
  } finally {
    clearTimeout(timer);
    if (forceKillTimer !== null) clearTimeout(forceKillTimer);
    process.off("SIGINT", onSigint);
    process.off("SIGTERM", onSigterm);
  }
  await traceClosed;
  const elapsedMs = Number((process.hrtime.bigint() - startNs) / 1_000_000n);
  await new Promise((finish) => setTimeout(finish, 250));
  const finishedAt = new Date();
  const after = await safetySnapshot(runtime);
  if (interruptedSignal !== null) {
    if (after.relevant_processes !== 0) {
      throw new Error(`${interruptedSignal} cleanup left a benchmark process running`);
    }
    throw new Error(`Agent dogfood run interrupted by ${interruptedSignal}`);
  }
  const traceText = readFileSync(tracePath, "utf8");
  const metrics = traceMetrics(traceText);
  const traceObservation = traceSafety(traceText);
  let answer;
  let failure = null;
  let hostOutputValid = false;
  try {
    answer = jsonFile(hostOutputPath);
    validateAnswer(spec, answer);
    hostOutputValid = true;
    if (answer.failure.code !== "none") failure = answer.failure;
  } catch {
    answer = {
      schema_version: ANSWER_SCHEMA_VERSION,
      claims: Object.fromEntries(spec.claims.map((claim) => [claim.id, {
        verdict: "insufficient",
        classification: "not_applicable",
        value: "unknown",
        evidence: [],
        reason: "The host did not produce a valid structured answer.",
      }])),
      failure: typedFailure(
        timedOut ? "excessive_context" : "host_failure",
        sampleId,
        timedOut ? "Reduce the bounded task context." : "Inspect the retained raw trace.",
      ),
    };
    failure = answer.failure;
  }
  if (!existsSync(hostOutputPath)) writeFileSync(hostOutputPath, "", { flag: "wx" });
  writeFileSync(answerPath, prettyJson(answer), { flag: "wx" });
  if (timedOut) {
    failure = typedFailure(
      "excessive_context",
      sampleId,
      "Reduce the bounded task context before rerunning all samples.",
    );
  } else if (
    toolBudgetExhausted || metrics.tool_calls > spec.host.maximum_tool_calls
  ) {
    failure = typedFailure(
      "excessive_context",
      sampleId,
      "Reduce tool usage below the predeclared budget.",
    );
  } else if (exitCode !== 0 && failure === null) {
    failure = typedFailure(
      "host_failure",
      sampleId,
      "Inspect the retained raw trace and rerun all samples without selection.",
    );
  }
  const safetyEvidence = {
    schema_version: SAFETY_SCHEMA_VERSION,
    sample_id: sampleId,
    before,
    after,
    trace: traceObservation,
  };
  writeJson(safetyPath, safetyEvidence);
  const safety = derivedSafety(safetyEvidence, metrics.mcp_tools);
  if (
    failure === null
    && !mcpToolContractPassed(spec, arm, metrics.mcp_tools_succeeded)
  ) {
    failure = typedFailure(
      "agent_misuse",
      sampleId,
      "Use every predeclared MCP workflow tool, then rerun all samples.",
    );
  }
  if (
    failure === null
    && !safetyPassed({ safety })
  ) {
    failure = typedFailure(
      "agent_misuse",
      sampleId,
      "Discard the run, restore the fixed fixture, and investigate the side effect.",
    );
  }
  const sample = {
    schema_version: SAMPLE_SCHEMA_VERSION,
    sample_id: sampleId,
    arm,
    ordinal,
    started_at: startedAt.toISOString(),
    finished_at: finishedAt.toISOString(),
    identity: null,
    artifacts: {
      trace: await fileArtifact(tracePath),
      host_output: await fileArtifact(hostOutputPath),
      answer: await fileArtifact(answerPath),
      safety: await fileArtifact(safetyPath),
    },
    runtime: {
      exit_code: exitCode,
      timed_out: timedOut,
      tool_budget_exhausted: toolBudgetExhausted
        || metrics.tool_calls > spec.host.maximum_tool_calls,
      elapsed_ms: elapsedMs,
      tool_calls: metrics.tool_calls,
      tool_result_bytes: metrics.tool_result_bytes,
      input_tokens: metrics.input_tokens,
      cached_input_tokens: metrics.cached_input_tokens,
      output_tokens: metrics.output_tokens,
      total_tokens: metrics.total_tokens,
      effective_tokens: metrics.effective_tokens,
      stderr_bytes: stderrBytes,
      stderr_sha256: stderrHash.digest("hex"),
      host_output_valid: hostOutputValid,
      mcp_tools: metrics.mcp_tools,
      mcp_tools_succeeded: metrics.mcp_tools_succeeded,
    },
    score: scoreAnswer(spec, answer),
    failure,
    safety,
  };
  return sample;
}

export async function runBenchmark({ specPath, rawDir, output }) {
  specPath = resolve(specPath);
  rawDir = resolve(rawDir);
  output = resolve(output);
  if (existsSync(rawDir)) throw new Error("raw output directory already exists");
  mkdirSync(rawDir, { recursive: true });
  const spec = validateSpec(jsonFile(specPath));
  const digests = sourceDigests(specPath);
  const runtime = requiredRuntime();
  const ready = await preflight(spec, runtime);
  const environmentPath = join(rawDir, "environment.json");
  writeJson(environmentPath, ready.environment);
  const environmentSha256 = await sha256File(environmentPath);
  const identity = expectedSampleIdentity(spec, digests, environmentSha256);
  const prompt = readFileSync(digests.promptPath, "utf8");
  for (const arm of ARM_NAMES) {
    for (let ordinal = 1; ordinal <= spec.host.samples_per_arm; ordinal += 1) {
      const sample = await runCodex({
        spec,
        runtime,
        preflightResult: ready,
        prompt,
        answerSchema: digests.answerSchemaPath,
        arm,
        ordinal,
        rawDir,
      });
      sample.identity = identity;
      writeJson(join(rawDir, `${sample.sample_id}.sample.json`), sample);
      if (!safetyPassed(sample)) {
        throw new Error(`read-only safety failed in ${sample.sample_id}`);
      }
    }
  }
  let report;
  try {
    report = await aggregateSamples({ specPath, rawDir });
  } catch (error) {
    if (error.report) writeFileSync(output, prettyJson(error.report));
    throw error;
  }
  writeFileSync(output, prettyJson(report), { flag: "wx" });
  return report;
}

async function main(argv) {
  const [command, ...rest] = argv;
  if (command === "run" && rest.length === 3) {
    const report = await runBenchmark({
      specPath: rest[0],
      rawDir: rest[1],
      output: rest[2],
    });
    process.stdout.write(`Agent dogfood gate: ${report.gate.passed ? "PASS" : "FAIL"}\n`);
    return;
  }
  if (command === "aggregate" && rest.length === 3) {
    const report = await aggregateSamples({ specPath: rest[0], rawDir: rest[1] });
    writeFileSync(resolve(rest[2]), prettyJson(report));
    process.stdout.write(`Agent dogfood report: ${resolve(rest[2])}\n`);
    return;
  }
  if (command === "verify" && rest.length === 3) {
    await verifyReport({
      specPath: rest[0],
      rawDir: rest[1],
      report: jsonFile(resolve(rest[2])),
    });
    process.stdout.write(`verified Agent dogfood report: ${resolve(rest[2])}\n`);
    return;
  }
  throw new Error(
    "usage: agent-dogfood.mjs run|aggregate|verify <spec> <raw-dir> <report>",
  );
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main(process.argv.slice(2)).catch((error) => {
    process.stderr.write(`${error.stack ?? error}\n`);
    process.exitCode = 1;
  });
}
