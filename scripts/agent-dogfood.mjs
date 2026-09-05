#!/usr/bin/env node

import { execFileSync, spawn } from "node:child_process";
import { createHash } from "node:crypto";
import {
  createReadStream,
  createWriteStream,
  existsSync,
  lstatSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  readlinkSync,
  realpathSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { once } from "node:events";
import { tmpdir } from "node:os";
import { basename, dirname, isAbsolute, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

export const SPEC_SCHEMA_VERSION = "agent-dogfood-spec-v1";
export const SPEC_SCHEMA_VERSION_V2 = "agent-dogfood-spec-v2";
export const ANSWER_SCHEMA_VERSION = "agent-dogfood-answer-v1";
export const SAMPLE_SCHEMA_VERSION = "agent-dogfood-sample-v1";
export const SAFETY_SCHEMA_VERSION = "agent-dogfood-safety-v1";
export const ENVIRONMENT_SCHEMA_VERSION = "agent-dogfood-environment-v1";
export const REPORT_SCHEMA_VERSION = "agent-dogfood-report-v1";
export const REPORT_SCHEMA_VERSION_V2 = "agent-dogfood-report-v2";
export const PENDING_RELEASE_SENTINEL = "PENDING-RELEASE";
export const UNUSED_HEALTH_PROBE_PATH =
  "workers/web/src/dogfood/unused-health-probe.ts";
export const PENDING_SPEC_ERROR =
  "Agent dogfood spec is pending release pinning and cannot be executed or verified";
export const BASELINE_COMMIT_PLACEHOLDER = "{{repository.baseline_commit}}";
export const V2_SPARSE_PATHS = Object.freeze([
  "/Cargo.lock",
  "/Cargo.toml",
  "/crates/depgraph-cli/Cargo.toml",
  "/crates/depgraph-cli/src/main.rs",
  "/crates/depgraph-mcp-tools/Cargo.toml",
  "/crates/depgraph-mcp-tools/src/catalog.rs",
  "/crates/depgraph-mcp-tools/src/host_config.rs",
  "/crates/depgraph-mcp-tools/src/lib.rs",
  "/crates/depgraph-mcp/Cargo.toml",
  "/crates/depgraph-mcp/src/main.rs",
  "/workers/go/cmd/depgraph-go-worker/main.go",
  "/workers/go/go.mod",
  "/workers/go/internal/worker/scan.go",
  "/workers/web/package.json",
  "/workers/web/src/dogfood/unused-health-probe.ts",
  "/workers/web/src/imports.ts",
  "/workers/web/src/scanner.ts",
  "/workers/web/src/typescript-compiler.ts",
  "/workers/web/src/typescript-dependencies.ts",
  "/workers/web/src/typescript-dependency-validation.ts",
  "/workers/web/src/worker.ts",
]);
const V2_RC_TAG = /^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)-rc\.([1-9]\d*)$/u;

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
const DOGFOOD_HEALTH_MCP_TOOLS = Object.freeze([
  "health_audit_get",
  "health_finding_get",
  "health_findings_list",
  "health_hotspots_list",
  "health_summary_get",
]);
const DOGFOOD_HEALTH_REQUIRED_MCP_TOOLS = Object.freeze([
  "health_audit_get",
  "health_finding_get",
  "health_findings_list",
  "health_hotspots_list",
]);
const DOGFOOD_SAFETY_BASELINE = Object.freeze({
  source_sha256: "ee7c2d70bff926657b091834fa5bc3a69a04f3d3573b116e1d8e3f194d9a9515",
  store_sha256: "9b03498b33abed475f7950aa865fb9d8c755f0cb0015dc923495b60792739f20",
  journal_sha256: "15df9ae7a75ab8383c84066c9d5e326ba7ef18f1c60655026d3a89be2b7564b9",
  daemon_state_sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  relevant_processes: 0,
});
const APPROVED_GIT_COMMAND = /^git (?:diff|log|ls-files|rev-parse|show|status)(?:\s|$)/u;
const UNSAFE_GIT_OPTIONS = new Set(["--ext-diff", "--output", "--textconv"]);
const UNSAFE_RG_OPTIONS = new Set(["--hostname-bin", "--pre", "--pre-glob"]);
const APPROVED_LOCAL_GIT_CONFIG = Object.freeze([
  /^core\.(?:bare|filemode|ignorecase|logallrefupdates|precomposeunicode|repositoryformatversion)$/u,
  /^remote\.[A-Za-z0-9._/-]+\.(?:fetch|url)$/u,
  /^branch\..+\.(?:merge|remote)$/u,
  /^submodule\.active$/u,
]);
const APPROVED_SPARSE_LOCAL_GIT_CONFIG = Object.freeze([
  ...APPROVED_LOCAL_GIT_CONFIG,
  /^extensions\.worktreeconfig$/u,
]);
const V2_WORKTREE_GIT_CONFIG_KEYS = Object.freeze([
  "core.sparsecheckout",
  "core.sparsecheckoutcone",
]);
const APPROVED_SED_PRINT = /^sed -n (["'])?\d+(?:,\d+)?p\1 [A-Za-z0-9_./*-]+$/u;
function freezeClaimDescriptors(descriptors) {
  return Object.freeze(descriptors.map((descriptor) => Object.freeze({ ...descriptor })));
}

const DOGFOOD_CLAIM_DESCRIPTORS = freezeClaimDescriptors([
  { id: "rust_path", category: "dependency_path", major: true, verdict: "supported", classification: "exact" },
  { id: "go_dependency", category: "dependency", major: true, verdict: "supported", classification: "exact" },
  { id: "web_dependency", category: "dependency", major: true, verdict: "supported", classification: "exact" },
  { id: "web_dependents", category: "dependents", major: true, verdict: "supported", classification: "exact" },
  { id: "rust_impact", category: "impact", major: true, verdict: "supported", classification: "exact" },
  { id: "rust_unresolved_type", category: "unresolved", major: false, verdict: "supported", classification: "unresolved" },
  { id: "rust_candidate_import", category: "candidate", major: false, verdict: "supported", classification: "candidate" },
  { id: "snapshot_package_diff", category: "snapshot_diff", major: false, verdict: "supported", classification: "exact" },
  { id: "snapshot_file_diff", category: "snapshot_diff", major: false, verdict: "supported", classification: "exact" },
  { id: "file_cycle", category: "cycle", major: false, verdict: "supported", classification: "exact" },
  { id: "package_cycles", category: "cycle", major: false, verdict: "supported", classification: "exact" },
  { id: "candidate_coverage", category: "snapshot", major: false, verdict: "supported", classification: "exact" },
]);
const DOGFOOD_HEALTH_CLAIM_DESCRIPTORS = freezeClaimDescriptors([
  { id: "health_unused_findings", category: "health_finding", major: true, verdict: "supported", classification: "exact" },
  { id: "health_finding_detail", category: "health_finding", major: true, verdict: "supported", classification: "exact" },
  { id: "health_hotspots", category: "health_hotspot", major: false, verdict: "supported", classification: "exact" },
  { id: "health_audit_base", category: "health_audit", major: false, verdict: "supported", classification: "exact" },
]);
const V2_CLAIM_DESCRIPTORS = Object.freeze([
  ...DOGFOOD_CLAIM_DESCRIPTORS,
  ...DOGFOOD_HEALTH_CLAIM_DESCRIPTORS,
]);
const DOGFOOD_CLAIM_IDS = Object.freeze(
  DOGFOOD_CLAIM_DESCRIPTORS.map((descriptor) => descriptor.id),
);
const DOGFOOD_HEALTH_CLAIM_IDS = Object.freeze(
  DOGFOOD_HEALTH_CLAIM_DESCRIPTORS.map((descriptor) => descriptor.id),
);
const CLAIM_IDS_ALLOWING_EMPTY_SUPPORTED_EVIDENCE = Object.freeze([
  "snapshot_package_diff",
  "snapshot_file_diff",
  "package_cycles",
  "candidate_coverage",
]);
const V2_CLAIM_IDS_ALLOWING_EMPTY_SUPPORTED_EVIDENCE = Object.freeze([
  ...CLAIM_IDS_ALLOWING_EMPTY_SUPPORTED_EVIDENCE,
  "health_unused_findings",
  "health_hotspots",
  "health_audit_base",
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
const DOGFOOD_THRESHOLDS_V2 = Object.freeze({
  ...DOGFOOD_THRESHOLDS,
  maximum_mcp_median_tool_calls: 32,
});
const V2_PENDING_RELEASE_NAMES = Object.freeze({
  archive: "depgraph-aarch64-apple-darwin.tar.gz",
  compiler_pack_archive: "depgraph-compiler-pack-aarch64-apple-darwin.tar.gz",
  compiler_pack_requirement:
    "depgraph-compiler-pack-aarch64-apple-darwin.requirement.json",
  mcp_smoke: "depgraph-aarch64-apple-darwin.mcp-smoke.json",
});
const PENDING_RELEASE_FIELD_PATHS = Object.freeze([
  "release.tag",
  "release.candidate_commit",
  "release.candidate_tree",
  "release.archive.sha256",
  "release.compiler_pack_archive.sha256",
  "release.compiler_pack_requirement.sha256",
  "release.mcp_smoke.sha256",
  "release.mcp_smoke.read_catalog_sha256",
  "snapshots.baseline.id",
  "snapshots.baseline.source_revision",
  "snapshots.candidate.id",
  "snapshots.candidate.source_revision",
  "safety_baseline.source_sha256",
  "safety_baseline.store_sha256",
  "safety_baseline.journal_sha256",
  "safety_baseline.daemon_state_sha256",
  "safety_baseline.relevant_processes",
  "repository.baseline_commit",
  "repository.baseline_tree",
  "repository.candidate_commit",
  "repository.candidate_tree",
  "host.cli_version",
  "host.model",
  "host.reasoning_effort",
]);
const THRESHOLD_KEYS = Object.freeze([
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
]);
const SPEC_KEYS_V1 = Object.freeze([
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
]);
const SPEC_KEYS_V2 = Object.freeze([...SPEC_KEYS_V1, "release_status"]);
const HOST_KEYS_V1 = Object.freeze([
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
]);
const HOST_KEYS_V2 = Object.freeze([
  "program",
  "cli_version",
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
]);

export const DOGFOOD_GENERATIONS = Object.freeze({
  [SPEC_SCHEMA_VERSION]: Object.freeze({
    schema_version: SPEC_SCHEMA_VERSION,
    report_schema_version: REPORT_SCHEMA_VERSION,
    requires_release_status: false,
    identity_includes_cli_version: false,
    sparse_paths: null,
    claim_descriptors: DOGFOOD_CLAIM_DESCRIPTORS,
    claim_ids: DOGFOOD_CLAIM_IDS,
    major_count: 5,
    mcp_enabled_tools: DOGFOOD_MCP_TOOLS,
    mcp_required_tools: DOGFOOD_REQUIRED_MCP_TOOLS,
    thresholds: DOGFOOD_THRESHOLDS,
    allowing_empty_supported_evidence: CLAIM_IDS_ALLOWING_EMPTY_SUPPORTED_EVIDENCE,
    maximum_tool_calls: 28,
    issue: 357,
    benchmark_id: "depgraph-v0.5.0-rc.7-agent-dogfood-v1",
    health_unused_kinds: null,
  }),
  [SPEC_SCHEMA_VERSION_V2]: Object.freeze({
    schema_version: SPEC_SCHEMA_VERSION_V2,
    report_schema_version: REPORT_SCHEMA_VERSION_V2,
    requires_release_status: true,
    identity_includes_cli_version: true,
    sparse_paths: V2_SPARSE_PATHS,
    claim_descriptors: V2_CLAIM_DESCRIPTORS,
    claim_ids: Object.freeze([...DOGFOOD_CLAIM_IDS, ...DOGFOOD_HEALTH_CLAIM_IDS]),
    major_count: 7,
    mcp_enabled_tools: Object.freeze([
      ...DOGFOOD_MCP_TOOLS,
      "agent_node_get",
      ...DOGFOOD_HEALTH_MCP_TOOLS,
    ]),
    mcp_required_tools: Object.freeze([
      ...DOGFOOD_REQUIRED_MCP_TOOLS,
      "agent_node_get",
      ...DOGFOOD_HEALTH_REQUIRED_MCP_TOOLS,
    ]),
    thresholds: DOGFOOD_THRESHOLDS_V2,
    allowing_empty_supported_evidence: V2_CLAIM_IDS_ALLOWING_EMPTY_SUPPORTED_EVIDENCE,
    maximum_tool_calls: 32,
    issue: 436,
    benchmark_id: "depgraph-agent-dogfood-v2",
    health_unused_kinds: Object.freeze(["unused-file"]),
  }),
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

export function canonicalJson(value) {
  return JSON.stringify(sortedValue(value));
}

export function generationFrozenContract(schemaVersion) {
  const generation = DOGFOOD_GENERATIONS[schemaVersion];
  if (!generation) {
    throw new Error(`unknown Agent dogfood generation ${schemaVersion}`);
  }
  return {
    schema_version: generation.schema_version,
    report_schema_version: generation.report_schema_version,
    requires_release_status: generation.requires_release_status,
    identity_includes_cli_version: generation.identity_includes_cli_version,
    sparse_paths: generation.sparse_paths === null
      ? null
      : [...generation.sparse_paths],
    claim_descriptors: generation.claim_descriptors.map((descriptor) => ({ ...descriptor })),
    claim_ids: [...generation.claim_ids],
    major_count: generation.major_count,
    mcp_enabled_tools: [...generation.mcp_enabled_tools],
    mcp_required_tools: [...generation.mcp_required_tools],
    thresholds: { ...generation.thresholds },
    allowing_empty_supported_evidence: [...generation.allowing_empty_supported_evidence],
    maximum_tool_calls: generation.maximum_tool_calls,
    issue: generation.issue,
    benchmark_id: generation.benchmark_id,
    health_unused_kinds: generation.health_unused_kinds === null
      ? null
      : [...generation.health_unused_kinds],
  };
}

function generationOf(spec) {
  if (!isRecord(spec) || typeof spec.schema_version !== "string") {
    throw new Error("Agent dogfood spec is incomplete or incompatible");
  }
  const generation = DOGFOOD_GENERATIONS[spec.schema_version];
  if (!generation) {
    throw new Error("Agent dogfood spec is incomplete or incompatible");
  }
  return generation;
}

function visitLeaves(value, path, visit) {
  if (Array.isArray(value)) {
    value.forEach((item, index) => visitLeaves(item, `${path}.${index}`, visit));
    return;
  }
  if (isRecord(value)) {
    for (const [key, child] of Object.entries(value)) {
      visitLeaves(child, path ? `${path}.${key}` : key, visit);
    }
    return;
  }
  visit(path, value);
}

function isPendingSentinelPath(path) {
  return PENDING_RELEASE_FIELD_PATHS.includes(path)
    || /^claims\.\d+\.expected\.value$/u.test(path);
}

function collectPendingSentinelViolations(spec) {
  const missing = [];
  const excess = [];
  visitLeaves(spec, "", (path, value) => {
    if (isPendingSentinelPath(path)) {
      if (value !== PENDING_RELEASE_SENTINEL) missing.push(path);
      return;
    }
    if (value === PENDING_RELEASE_SENTINEL) excess.push(path);
  });
  return { missing, excess };
}

function collectPinnedSentinelResidues(spec) {
  const residues = [];
  visitLeaves(spec, "", (path, value) => {
    if (value === PENDING_RELEASE_SENTINEL) residues.push(path);
  });
  return residues;
}

function emptyEvidenceClaimIds(spec) {
  return generationOf(spec).allowing_empty_supported_evidence;
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

function validNormalizedRelativePath(path) {
  return validRelativePath(path)
    && path.split("/").every((segment) => segment.length > 0 && segment !== ".");
}

export function validateSpec(spec) {
  if (!isRecord(spec)) {
    throw new Error("Agent dogfood spec is incomplete or incompatible");
  }
  if (spec.schema_version === SPEC_SCHEMA_VERSION) {
    return validatePinnedSpecV1(spec);
  }
  if (spec.schema_version === SPEC_SCHEMA_VERSION_V2) {
    if (spec.release_status !== "pinned") {
      throw new Error(PENDING_SPEC_ERROR);
    }
    return validatePinnedSpecV2(spec);
  }
  throw new Error("Agent dogfood spec is incomplete or incompatible");
}

function validatePinnedSpecV1(spec) {
  if (
    !isRecord(spec)
    || !exactKeys(spec, SPEC_KEYS_V1)
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
    || !exactKeys(spec.host, HOST_KEYS_V1)
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
  assertClaimDescriptors(spec, generationOf(spec));
  return spec;
}

function validateReleaseShape(release) {
  return exactKeys(release, [
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
    && exactKeys(release.archive, ["name", "sha256"])
    && exactKeys(release.compiler_pack_archive, ["name", "sha256"])
    && exactKeys(release.compiler_pack_requirement, ["name", "sha256"])
    && exactKeys(release.mcp_smoke, [
      "name",
      "sha256",
      "schema_version",
      "read_catalog_sha256",
    ]);
}

function observedClaimDescriptors(spec) {
  return spec.claims.map((claim) => ({
    id: claim.id,
    category: claim.category,
    major: claim.major,
    verdict: claim.expected.verdict,
    classification: claim.expected.classification,
  }));
}

function assertClaimDescriptors(spec, generation) {
  if (canonicalJson(observedClaimDescriptors(spec))
    !== canonicalJson(generation.claim_descriptors)) {
    throw new Error("Agent dogfood task corpus drifted");
  }
}

function validateClaimDefinitions(spec, generation, { allowSentinelValues }) {
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
      || (!allowSentinelValues && claim.expected.value === PENDING_RELEASE_SENTINEL)
    ) {
      throw new Error("Agent dogfood golden claims are not closed and unique");
    }
    ids.add(claim.id);
  }
  assertClaimDescriptors(spec, generation);
}

function validateV2SharedIdentity(spec, generation) {
  if (
    spec.schema_version !== SPEC_SCHEMA_VERSION_V2
    || spec.benchmark_id !== generation.benchmark_id
    || spec.issue !== generation.issue
    || canonicalJson(spec.repository.sparse_paths)
      !== canonicalJson(generation.sparse_paths)
    || spec.release.repository !== "TamaT-LLC/depgraph-cli"
    || spec.release.host_target !== "aarch64-apple-darwin"
    || spec.release.mcp_smoke.schema_version !== "mcp-package-smoke-v3"
    || spec.snapshots.baseline.name !== "agent-tools-baseline"
    || spec.snapshots.candidate.name !== "rc-candidate"
    || spec.host.program !== "codex"
    || spec.host.samples_per_arm !== 3
    || spec.host.maximum_tool_calls !== generation.maximum_tool_calls
    || canonicalJson(spec.host.mcp_enabled_tools)
      !== canonicalJson(generation.mcp_enabled_tools)
    || canonicalJson(spec.host.mcp_required_tools)
      !== canonicalJson(generation.mcp_required_tools)
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
  if (!exactKeys(spec.thresholds, THRESHOLD_KEYS)) {
    throw new Error("Agent dogfood thresholds are not the closed v2 set");
  }
  if (canonicalJson(spec.thresholds) !== canonicalJson(generation.thresholds)) {
    throw new Error("Agent dogfood thresholds drifted after predeclaration");
  }
}

function validateV2PendingReleaseNames(spec) {
  if (
    spec.release.archive.name !== V2_PENDING_RELEASE_NAMES.archive
    || spec.release.compiler_pack_archive.name
      !== V2_PENDING_RELEASE_NAMES.compiler_pack_archive
    || spec.release.compiler_pack_requirement.name
      !== V2_PENDING_RELEASE_NAMES.compiler_pack_requirement
    || spec.release.mcp_smoke.name !== V2_PENDING_RELEASE_NAMES.mcp_smoke
  ) {
    throw new Error("Agent dogfood identity or host controls drifted");
  }
}

export function productVersionFromRcTag(tag) {
  const match = typeof tag === "string" ? V2_RC_TAG.exec(tag) : null;
  if (!match) {
    throw new Error("Agent dogfood v2 release tag is not a canonical RC tag");
  }
  return `${match[1]}.${match[2]}.${match[3]}`;
}

export function v2PinnedReleaseAssetNames(tag, hostTarget) {
  const version = productVersionFromRcTag(tag);
  if (typeof hostTarget !== "string" || hostTarget.length === 0) {
    throw new Error("Agent dogfood v2 host target is not pinned");
  }
  return {
    archive: `depgraph-${version}-${hostTarget}.tar.gz`,
    compiler_pack_archive: `depgraph-compiler-pack-${version}-${hostTarget}.tar.gz`,
    compiler_pack_requirement: `depgraph-compiler-pack-${version}-${hostTarget}.requirement.json`,
    mcp_smoke: `depgraph-${version}-${hostTarget}.mcp-smoke.json`,
  };
}

export function expectedPackagedProductVersion(spec) {
  if (spec.schema_version === SPEC_SCHEMA_VERSION) return "0.5.0";
  if (spec.schema_version === SPEC_SCHEMA_VERSION_V2) {
    return productVersionFromRcTag(spec.release.tag);
  }
  throw new Error("Agent dogfood spec is incomplete or incompatible");
}

function validateV2PinnedReleaseNames(spec) {
  const expected = v2PinnedReleaseAssetNames(spec.release.tag, spec.release.host_target);
  if (
    spec.release.archive.name !== expected.archive
    || spec.release.compiler_pack_archive.name !== expected.compiler_pack_archive
    || spec.release.compiler_pack_requirement.name !== expected.compiler_pack_requirement
    || spec.release.mcp_smoke.name !== expected.mcp_smoke
  ) {
    throw new Error("Agent dogfood v2 release asset names do not match the RC tag");
  }
}

function validateV2Shape(spec, generation) {
  if (
    !isRecord(spec)
    || !exactKeys(spec, SPEC_KEYS_V2)
    || !["pending", "pinned"].includes(spec.release_status)
    || !validateReleaseShape(spec.release)
    || !exactKeys(spec.repository, [
      "baseline_commit",
      "baseline_tree",
      "candidate_commit",
      "candidate_tree",
      "sparse_paths",
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
    || !exactKeys(spec.host, HOST_KEYS_V2)
    || !isRecord(spec.thresholds)
    || !Array.isArray(spec.claims)
    || spec.claims.length !== generation.claim_ids.length
  ) {
    throw new Error("Agent dogfood spec is incomplete or incompatible");
  }
}

function validatePendingSpecV2(spec) {
  const generation = generationOf(spec);
  validateV2Shape(spec, generation);
  if (spec.release_status !== "pending") {
    throw new Error(PENDING_SPEC_ERROR);
  }
  const { missing, excess } = collectPendingSentinelViolations(spec);
  if (missing.length > 0) {
    throw new Error(
      `Agent dogfood pending spec is missing PENDING-RELEASE sentinels: ${missing.join(", ")}`,
    );
  }
  if (excess.length > 0) {
    throw new Error(
      `Agent dogfood pending spec has PENDING-RELEASE outside the pin set: ${excess.join(", ")}`,
    );
  }
  validateV2SharedIdentity(spec, generation);
  validateV2PendingReleaseNames(spec);
  validateClaimDefinitions(spec, generation, { allowSentinelValues: true });
  return spec;
}

function validatePinnedSpecV2(spec) {
  const generation = generationOf(spec);
  validateV2Shape(spec, generation);
  if (spec.release_status !== "pinned") {
    throw new Error(PENDING_SPEC_ERROR);
  }
  const residues = collectPinnedSentinelResidues(spec);
  if (residues.length > 0) {
    throw new Error(
      `Agent dogfood pinned spec still contains PENDING-RELEASE sentinels: ${residues.join(", ")}`,
    );
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
    spec.release.candidate_commit !== spec.repository.candidate_commit
    || spec.release.candidate_tree !== spec.repository.candidate_tree
    || spec.snapshots.baseline?.source_revision !== spec.repository.baseline_commit
    || spec.snapshots.candidate?.source_revision !== spec.repository.candidate_commit
    || typeof spec.host.cli_version !== "string"
    || spec.host.cli_version.length === 0
    || typeof spec.host.model !== "string"
    || spec.host.model.length === 0
    || typeof spec.host.reasoning_effort !== "string"
    || spec.host.reasoning_effort.length === 0
    || typeof spec.snapshots.baseline.id !== "string"
    || typeof spec.snapshots.candidate.id !== "string"
    || !/^snapshot:sha256:[0-9a-f]{64}$/u.test(spec.snapshots.baseline.id)
    || !/^snapshot:sha256:[0-9a-f]{64}$/u.test(spec.snapshots.candidate.id)
  ) {
    throw new Error("Agent dogfood identity or host controls drifted");
  }
  semverTuple(spec.host.cli_version);
  productVersionFromRcTag(spec.release.tag);
  validateV2SharedIdentity(spec, generation);
  validateV2PinnedReleaseNames(spec);
  validateClaimDefinitions(spec, generation, { allowSentinelValues: false });
  validateUnusedFileSpecInvariants(spec);
  return spec;
}

function unusedFindingsCount(value) {
  const match = /^(?:count=(\d+);digest=collection:sha256:[0-9a-f]{64})$/u.exec(value);
  return match ? Number(match[1]) : null;
}

function validateUnusedFileSpecInvariants(spec) {
  const generation = generationOf(spec);
  if (generation.health_unused_kinds === null) return;
  const unused = spec.claims.find((claim) => claim.id === "health_unused_findings");
  const detail = spec.claims.find((claim) => claim.id === "health_finding_detail");
  const count = unusedFindingsCount(unused?.expected?.value);
  if (count === null || count < 1) {
    throw new Error("Agent dogfood pinned spec does not guarantee an unused-file finding");
  }
  if (detail?.expected?.verdict !== "supported") {
    throw new Error("Agent dogfood pinned spec does not require a supported unused finding");
  }
}

export function materializeDogfoodPrompt(spec, prompt) {
  if (!isRecord(spec) || spec.schema_version !== SPEC_SCHEMA_VERSION_V2) return prompt;
  if (typeof prompt !== "string" || !prompt.includes(BASELINE_COMMIT_PLACEHOLDER)) {
    throw new Error("Agent dogfood v2 prompt must pin repository.baseline_commit");
  }
  return prompt.replaceAll(BASELINE_COMMIT_PLACEHOLDER, spec.repository.baseline_commit);
}

export function validateV2PromptContracts(spec, prompt) {
  if (generationOf(spec).health_unused_kinds === null) return;
  if (typeof prompt !== "string" || !/kinds:\s*\[\s*"unused-file"\s*\]/u.test(prompt)) {
    throw new Error("Agent dogfood pinned spec does not pin unused-file for health claims");
  }
  const materialized = materializeDogfoodPrompt(spec, prompt);
  if (
    spec.release_status === "pinned"
    && (
      spec.repository.baseline_commit === PENDING_RELEASE_SENTINEL
      || !materialized.includes(spec.repository.baseline_commit)
    )
  ) {
    throw new Error("Agent dogfood materialized prompt does not match the pinned baseline commit");
  }
}

function validateCorpusPrompt(spec, prompt) {
  if (spec.schema_version !== SPEC_SCHEMA_VERSION_V2) return;
  validateV2PromptContracts(spec, prompt);
}

export function lintSpec(spec, options = {}) {
  const pinned = options.pinned === true;
  if (!isRecord(spec)) {
    throw new Error("Agent dogfood spec is incomplete or incompatible");
  }
  if (spec.schema_version === SPEC_SCHEMA_VERSION) {
    validatePinnedSpecV1(spec);
    return spec;
  }
  if (spec.schema_version !== SPEC_SCHEMA_VERSION_V2) {
    throw new Error("Agent dogfood spec is incomplete or incompatible");
  }
  if (pinned) {
    if (spec.release_status !== "pinned") {
      throw new Error(PENDING_SPEC_ERROR);
    }
    validatePinnedSpecV2(spec);
    validateV2PromptContracts(spec, options.prompt);
    return spec;
  }
  if (spec.release_status === "pending") {
    validatePendingSpecV2(spec);
    if (typeof options.prompt === "string") validateV2PromptContracts(spec, options.prompt);
    return spec;
  }
  if (spec.release_status === "pinned") {
    validatePinnedSpecV2(spec);
    if (typeof options.prompt === "string") validateV2PromptContracts(spec, options.prompt);
    return spec;
  }
  throw new Error("Agent dogfood spec is incomplete or incompatible");
}

export function lintSpecFile(specPath, options = {}) {
  const resolved = resolve(specPath);
  const promptPath = join(dirname(resolved), "prompt.md");
  return lintSpec(jsonFile(resolved), {
    ...options,
    prompt: existsSync(promptPath) ? readFileSync(promptPath, "utf8") : "",
  });
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
        && !emptyEvidenceClaimIds(spec).includes(claim.id)
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

const V2_MCP_TRACE_CALL_COUNT = 24;
const V2_MCP_CONTRACT_VERSION = "depgraph-mcp-tools-v1";
const V2_MCP_REPOSITORY_ID = "repository";
const V2_MCP_MAX_TRAVERSAL = 1_000_000;
const V2_MCP_CATALOG_LOCATOR =
  "rust-module:depgraph-mcp-tools:lib:depgraph_mcp_tools::catalog";
const V2_MCP_HEALTH_HOTSPOTS_DIGEST =
  "collection:sha256:2596815d4f478507c71ccd7643090abdcd34e79f1ca0c63ae39a6bf2a6a8b8f4";

function parseTraceEvents(text) {
  if (typeof text !== "string") {
    throw new Error("Agent dogfood trace is not text");
  }
  const events = [];
  for (const [lineIndex, line] of text.split(/\r?\n/u).entries()) {
    if (line.length === 0) continue;
    try {
      events.push(JSON.parse(line));
    } catch {
      throw new Error(`Codex JSONL trace line ${lineIndex + 1} is invalid`);
    }
  }
  return events;
}

function v2McpTraceFailure(message) {
  throw new Error(`Agent dogfood v2 MCP trace ${message}`);
}

function v2McpRequire(condition, message) {
  if (!condition) v2McpTraceFailure(message);
}

function v2McpClaimFields(spec, claimId) {
  const claim = spec.claims?.find((candidate) => candidate.id === claimId);
  v2McpRequire(
    isRecord(claim)
      && isRecord(claim.expected)
      && claim.expected.verdict === "supported"
      && typeof claim.expected.value === "string",
    `claim ${claimId} is not a supported pinned value`,
  );
  const fields = {};
  for (const part of claim.expected.value.split(";")) {
    const separator = part.indexOf("=");
    v2McpRequire(separator > 0, `claim ${claimId} has an invalid expected value`);
    const key = part.slice(0, separator);
    v2McpRequire(!Object.hasOwn(fields, key), `claim ${claimId} repeats ${key}`);
    fields[key] = part.slice(separator + 1);
  }
  return fields;
}

function v2McpRepositoryRelativePath(value) {
  return typeof value === "string"
    && value.length > 0
    && !value.startsWith("/")
    && !value.includes("\\")
    && !value.includes("://")
    && !value.split("/").some((segment) => segment === ""
      || segment === "."
      || segment === "..");
}

function v2McpNodePath(result, callNumber) {
  const repositoryPath = result.repository_path;
  const displayName = result.display_name;
  const path = typeof repositoryPath === "string" ? repositoryPath : displayName;
  v2McpRequire(
    result.kind === "file"
      && v2McpRepositoryRelativePath(path)
      && (repositoryPath === undefined
        || (v2McpRepositoryRelativePath(repositoryPath)
          && (displayName === undefined || displayName === repositoryPath))),
    `call ${callNumber} file node has no repository-relative path`,
  );
  return path;
}

function v2McpExpectedCyclePaths(spec) {
  const fields = v2McpClaimFields(spec, "file_cycle");
  const paths = fields.cycle?.split("->").map((locator) => locator.replace(/^file:\/\//u, ""));
  v2McpRequire(
    Array.isArray(paths)
      && paths.length === 5
      && paths.every((path) => v2McpRepositoryRelativePath(path))
      && paths[0] === paths[paths.length - 1],
    "file_cycle claim does not contain a closed repository-relative path",
  );
  return paths.slice(0, -1);
}

function v2McpCommonArgs(snapshot) {
  return {
    contract_version: V2_MCP_CONTRACT_VERSION,
    repository_id: V2_MCP_REPOSITORY_ID,
    snapshot,
  };
}

function resolveV2McpArgs(args) {
  if (typeof args === "function") return args();
  return Object.fromEntries(
    Object.entries(args).map(([key, value]) => [
      key,
      typeof value === "function" ? value() : value,
    ]),
  );
}

function v2McpItems(result, callNumber) {
  v2McpRequire(
    isRecord(result) && Array.isArray(result.items),
    `call ${callNumber} did not return an items array`,
  );
  return result.items;
}

function v2McpEdges(result, callNumber) {
  v2McpRequire(
    isRecord(result?.edges) && Array.isArray(result.edges.items),
    `call ${callNumber} did not return an edges.items array`,
  );
  return result.edges.items;
}

function v2McpOne(items, predicate, callNumber, description) {
  const matches = items.filter(predicate);
  v2McpRequire(
    matches.length === 1,
    `call ${callNumber} did not return exactly one ${description}`,
  );
  return matches[0];
}

function v2McpHasItem(items, id, callNumber) {
  v2McpRequire(
    items.some((item) => isRecord(item) && item.id === id),
    `call ${callNumber} did not return chained node ${id}`,
  );
}

function v2McpPage(result, callNumber, expected = {}) {
  v2McpRequire(
    isRecord(result)
      && Array.isArray(result.items)
      && Number.isSafeInteger(result.returned_items)
      && result.returned_items >= 0
      && Number.isSafeInteger(result.total_items)
      && result.total_items >= result.returned_items
      && typeof result.complete === "boolean"
      && result.returned_items === result.items.length,
    `call ${callNumber} has an invalid result page`,
  );
  for (const [key, value] of Object.entries(expected)) {
    v2McpRequire(result[key] === value, `call ${callNumber} result ${key} is invalid`);
  }
  return result.items;
}

function v2McpNestedPage(result, key, callNumber, expected = {}) {
  v2McpRequire(isRecord(result?.[key]), `call ${callNumber} has no ${key} page`);
  return v2McpPage(result[key], callNumber, expected);
}

function v2McpRoot(result, callNumber, repositoryPath) {
  const root = result?.root;
  v2McpRequire(
    isRecord(root)
      && /^file:sha256:[0-9a-f]{64}$/u.test(root.id ?? "")
      && root.kind === "file"
      && root.locator === `id:${root.id}`
      && root.display_name === repositoryPath
      && (root.repository_path === undefined || root.repository_path === repositoryPath),
    `call ${callNumber} root does not identify ${repositoryPath}`,
  );
  return root;
}

function v2McpEvidenceAt(edge, repositoryPath, line) {
  return isRecord(edge)
    && /^edge:sha256:[0-9a-f]{64}$/u.test(edge.id ?? "")
    && /^[a-z_]+:sha256:[0-9a-f]{64}$/u.test(edge.source_id ?? "")
    && /^[a-z_]+:sha256:[0-9a-f]{64}$/u.test(edge.target_id ?? "")
    && typeof edge.kind === "string"
    && edge.kind.length > 0
    && typeof edge.phase === "string"
    && edge.phase.length > 0
    && typeof edge.resolution_status === "string"
    && typeof edge.precision === "string"
    && /^profile:sha256:[0-9a-f]{64}$/u.test(edge.profile_id ?? "")
    && (edge.kind === "contains"
      ? edge.site_id === undefined
      : /^site:sha256:[0-9a-f]{64}$/u.test(edge.site_id ?? ""))
    && typeof edge.condition === "string"
    && edge.condition.length > 0
    && Array.isArray(edge.evidence)
    && edge.evidence.length > 0
    && edge.evidence.every((evidence) =>
      isRecord(evidence)
      && evidence.kind === "source"
      && typeof evidence.extractor === "string"
      && evidence.extractor.length > 0
      && typeof evidence.extractor_version === "string"
      && evidence.extractor_version.length > 0
      && isRecord(evidence.span)
      && v2McpRepositoryRelativePath(evidence.span.path)
      && Number.isSafeInteger(evidence.span.start?.line)
      && evidence.span.start.line > 0
      && Number.isSafeInteger(evidence.span.start?.column)
      && evidence.span.start.column > 0
      && Number.isSafeInteger(evidence.span.end?.line)
      && evidence.span.end.line >= evidence.span.start.line
      && Number.isSafeInteger(evidence.span.end?.column)
      && evidence.span.end.column > 0)
    && edge.evidence.some((evidence) =>
      evidence.span.path === repositoryPath
      && evidence.span.start?.line === line
      && evidence.span.end?.line === line);
}

function v2McpExpectedList(value, separator, claimId) {
  const entries = value?.split(separator);
  v2McpRequire(
    Array.isArray(entries) && entries.length > 0 && entries.every((entry) => entry.length > 0),
    `claim ${claimId} has an invalid list value`,
  );
  return entries;
}

function v2McpExpectedImpactItems(spec) {
  return v2McpExpectedList(
    v2McpClaimFields(spec, "rust_impact").items,
    ",",
    "rust_impact",
  ).map((entry) => {
    const separator = entry.lastIndexOf("@");
    v2McpRequire(separator > 0, "rust_impact has an invalid item value");
    const locator = entry.slice(0, separator);
    const depth = Number(entry.slice(separator + 1));
    v2McpRequire(Number.isSafeInteger(depth) && depth >= 0, "rust_impact has an invalid depth");
    return { locator, depth };
  });
}

function v2McpExpectedBlockerKinds(value, claimId) {
  if (value === "none") return [];
  return v2McpExpectedList(value, ",", claimId);
}

function validateV2McpClaimResults(spec, results, state) {
  const claim = (id) => v2McpClaimFields(spec, id);
  const candidateName = spec.snapshots.candidate.name;
  const baselineId = spec.snapshots.baseline.id;
  const candidateId = spec.snapshots.candidate.id;
  const asInteger = (value, callNumber, field) => {
    v2McpRequire(
      Number.isSafeInteger(value) && value >= 0,
      `call ${callNumber} result ${field} is not a non-negative integer`,
    );
    return value;
  };
  const pathFor = (locator, callNumber) => {
    v2McpRequire(
      typeof locator === "string" && locator.startsWith("file://"),
      `call ${callNumber} claim locator is not a file locator`,
    );
    const path = locator.slice("file://".length);
    v2McpRequire(
      v2McpRepositoryRelativePath(path),
      `call ${callNumber} claim locator is not repository-relative`,
    );
    return path;
  };
  const expectedPath = (value, callNumber) => pathFor(value, callNumber);
  const claimInteger = (fields, key, claimId) => {
    const value = Number(fields[key]);
    v2McpRequire(
      Number.isSafeInteger(value) && value >= 0,
      `claim ${claimId} has an invalid integer ${key}`,
    );
    return value;
  };
  const first = results[0];
  const rustPath = claim("rust_path");
  const catalogItems = v2McpPage(first, 1, {
    returned_items: 1,
    total_items: 1,
    complete: true,
  });
  v2McpRequire(
    catalogItems.length === 1
      && catalogItems[0].id === state.catalog?.id
      && /^module:sha256:[0-9a-f]{64}$/u.test(catalogItems[0].id ?? "")
      && catalogItems[0].kind === "module"
      && catalogItems[0].locator === rustPath.target
      && catalogItems[0].display_name === "catalog"
      && rustPath.target === V2_MCP_CATALOG_LOCATOR,
    "call 1 catalog result does not support rust_path",
  );

  const pathResult = results[1];
  const rustPathSteps = v2McpExpectedList(rustPath.steps, ",", "rust_path");
  const expectedPathSteps = claimInteger({ steps: rustPathSteps[0] }, "steps", "rust_path");
  v2McpRequire(
    pathResult.path_found === true
      && Array.isArray(pathResult.steps)
      && pathResult.steps.length === expectedPathSteps
      && asInteger(pathResult.traversed_edges, 2, "traversed_edges") >= expectedPathSteps
      && /^file:sha256:[0-9a-f]{64}$/u.test(pathResult.from?.id ?? "")
      && pathResult.from?.kind === "file"
      && pathResult.from?.locator === `id:${pathResult.from?.id}`
      && pathResult.from?.display_name === "crates/depgraph-mcp-tools/src/lib.rs"
      && pathResult.to?.id === state.catalog?.id
      && pathResult.to?.kind === "module"
      && pathResult.to?.locator === rustPath.target
      && pathResult.to?.display_name === "catalog"
      && pathResult.to?.repository_path === "crates/depgraph-mcp-tools/src/lib.rs"
      && v2McpRepositoryRelativePath(pathResult.from?.display_name),
    "call 2 path result does not support rust_path",
  );
  const pathStep = pathResult.steps[0];
  v2McpRequire(
    isRecord(pathStep)
      && pathStep.source?.kind === "file"
      && pathStep.source?.id === pathResult.from?.id
      && pathStep.source?.locator === `id:${pathStep.source?.id}`
      && pathStep.source?.display_name === "crates/depgraph-mcp-tools/src/lib.rs"
      && pathStep.edge?.source_id === pathStep.source?.id
      && pathStep.edge?.target_id === state.catalog?.id
      && pathStep.edge?.kind === rustPath.kind
      && pathStep.edge?.resolution_status === "resolved"
      && pathStep.edge?.precision === "exact"
      && v2McpEvidenceAt(
        pathStep.edge,
        "crates/depgraph-mcp-tools/src/lib.rs",
        15,
      )
      && pathStep.target?.id === state.catalog?.id
      && pathStep.target?.kind === "module"
      && pathStep.target?.locator === rustPath.target
      && pathStep.target?.display_name === "catalog"
      && pathStep.target?.repository_path === "crates/depgraph-mcp-tools/src/lib.rs",
    "call 2 path step does not support rust_path",
  );

  const goDependency = claim("go_dependency");
  const goResult = results[2];
  const goRoot = v2McpRoot(
    goResult,
    3,
    "workers/go/cmd/depgraph-go-worker/main.go",
  );
  const goEdges = v2McpNestedPage(goResult, "edges", 3, {
    returned_items: 6,
    total_items: 6,
    complete: true,
  });
  v2McpRequire(
    goResult.direction === "outgoing"
      && goResult.transitive === false
      && goResult.traversal_complete === true
      && asInteger(goResult.traversed_edges, 3, "traversed_edges") === 6,
    "call 3 graph result does not support go_dependency",
  );
  const goEdge = v2McpOne(
    goEdges,
    (entry) => isRecord(entry) && entry.target_id === state.goModuleId,
    3,
    "Go dependency edge",
  );
  const goLine = Number(goDependency.line);
  v2McpRequire(
    goEdge.kind === goDependency.kind
      && goEdge.resolution_status === "resolved"
      && goEdge.precision === "exact"
      && goEdge.source_id === goRoot.id
      && v2McpEvidenceAt(
        goEdge,
        "workers/go/cmd/depgraph-go-worker/main.go",
        goLine,
      ),
    "call 3 selected edge does not support go_dependency",
  );
  const goNodeItems = v2McpPage(results[3], 4, {
    returned_items: 1,
    total_items: 1,
    complete: true,
  });
  v2McpRequire(
    goNodeItems.length === 1
      && goNodeItems[0].id === state.goModuleId
      && goNodeItems[0].kind === "module"
      && goNodeItems[0].locator === goDependency.target
      && goNodeItems[0].display_name === goDependency.target.replace(/^go-package:/u, ""),
    "call 4 node result does not support go_dependency",
  );

  const webDependency = claim("web_dependency");
  const webResult = results[4];
  const webRoot = v2McpRoot(webResult, 5, "workers/web/src/worker.ts");
  const webEdges = v2McpNestedPage(webResult, "edges", 5, {
    returned_items: 10,
    total_items: 10,
    complete: true,
  });
  v2McpRequire(
    webResult.direction === "outgoing"
      && webResult.transitive === false
      && webResult.traversal_complete === true
      && asInteger(webResult.traversed_edges, 5, "traversed_edges") === 10,
    "call 5 graph result does not support web_dependency",
  );
  const scannerPath = expectedPath(webDependency.target, 5);
  const scannerRoot = v2McpRoot(
    results[5],
    6,
    "workers/web/src/scanner.ts",
  );
  const scannerEdges = v2McpNestedPage(results[5], "edges", 6, {
    returned_items: 2,
    total_items: 2,
    complete: true,
  });
  const scannerEdge = v2McpOne(
    webEdges,
    (entry) => isRecord(entry)
      && entry.target_id === scannerRoot.id
      && entry.kind === "imports"
      && v2McpEvidenceAt(entry, "workers/web/src/worker.ts", Number(webDependency.line)),
    5,
    "scanner dependency edge",
  );
  v2McpRequire(
    scannerEdge.resolution_status === "resolved"
      && scannerEdge.precision === "exact"
      && scannerEdge.condition === webDependency.condition
      && scannerPath === "workers/web/src/scanner.ts"
      && scannerEdge.source_id === webRoot.id,
    "call 5 selected edge does not support web_dependency",
  );
  v2McpRequire(
    results[5].direction === "incoming"
      && results[5].transitive === false
      && results[5].traversal_complete === true
      && asInteger(results[5].traversed_edges, 6, "traversed_edges") === 2,
    "call 6 graph result does not support web_dependents",
  );
  const webDependents = claim("web_dependents");
  const expectedSources = v2McpExpectedList(webDependents.sources, ",", "web_dependents");
  const packageSourceLocator = expectedSources.find((source) => source.startsWith("id:package:"));
  const workerSourceLocator = expectedSources.find((source) => source.startsWith("file://"));
  v2McpRequire(
    expectedSources.length === Number(webDependents.count)
      && packageSourceLocator !== undefined
      && workerSourceLocator !== undefined,
    "web_dependents claim has an invalid source set",
  );
  const packageSourceId = packageSourceLocator.slice("id:".length);
  const incomingPackage = v2McpOne(
    scannerEdges,
    (entry) => isRecord(entry)
      && entry.source_id === packageSourceId
      && entry.target_id === scannerRoot.id
      && entry.kind === "contains",
    6,
    "package dependent edge",
  );
  const incomingWorker = v2McpOne(
    scannerEdges,
    (entry) => isRecord(entry)
      && entry.source_id === webRoot.id
      && entry.target_id === scannerRoot.id
      && entry.kind === "imports",
    6,
    "worker dependent edge",
  );
  v2McpRequire(
    incomingPackage.resolution_status === "resolved"
      && incomingPackage.precision === "exact"
      && v2McpEvidenceAt(incomingPackage, "workers/web/src/scanner.ts", 1)
      && incomingWorker.resolution_status === "resolved"
      && incomingWorker.precision === "exact"
      && incomingWorker.condition === webDependency.condition
      && v2McpEvidenceAt(incomingWorker, "workers/web/src/worker.ts", 17),
    "call 6 incoming edges do not support web_dependents",
  );
  const actualSources = [workerSourceLocator, packageSourceLocator].sort();
  v2McpRequire(
    canonicalJson(actualSources) === canonicalJson(expectedSources),
    "call 6 source locators do not support web_dependents",
  );

  const rustImpact = claim("rust_impact");
  const impactResult = results[6];
  v2McpRoot(impactResult, 7, "crates/depgraph-mcp-tools/src/catalog.rs");
  const impactItems = v2McpNestedPage(impactResult, "impacts", 7, {
    returned_items: 4,
    total_items: 4,
    complete: true,
  });
  v2McpRequire(impactResult.root_impacted === true, "call 7 root impact is not established");
  const expectedImpacts = v2McpExpectedImpactItems(spec);
  const actualImpacts = impactItems.map((item) => {
    v2McpRequire(
      isRecord(item)
        && isRecord(item.node)
        && Number.isSafeInteger(item.depth)
        && item.depth >= 0
        && item.depth <= 2
        && Array.isArray(item.dependency_path)
        && item.dependency_path.length === item.depth
        && item.changed_node_id === impactResult.root.id,
      "call 7 impact item is incomplete",
    );
    v2McpRequire(
      typeof item.node.id === "string"
        && typeof item.node.kind === "string"
        && typeof item.node.locator === "string"
        && typeof item.node.display_name === "string",
      "call 7 impact node is incomplete",
    );
    for (const step of item.dependency_path) {
      v2McpRequire(
        isRecord(step)
          && isRecord(step.source)
          && isRecord(step.edge)
          && isRecord(step.target)
          && typeof step.edge.kind === "string"
          && step.source.id === step.edge.source_id
          && step.target.id === step.edge.target_id,
        "call 7 impact path is incomplete",
      );
    }
    v2McpRequire(
      item.dependency_path.length === 0
        ? item.node.id === impactResult.root.id
        : item.dependency_path[0].source.id === item.node.id
          && item.dependency_path.at(-1).target.id === impactResult.root.id
          && item.dependency_path.slice(1).every(
            (step, index) =>
              item.dependency_path[index].target.id === step.source.id,
          ),
      "call 7 impact path is not a connected node-to-root witness",
    );
    const locator = item.node.kind === "file"
      ? `file:${item.node.display_name}`
      : item.node.locator;
    v2McpRequire(
      (item.node.kind !== "file" || v2McpRepositoryRelativePath(item.node.display_name))
        && (item.node.kind !== "file"
          || item.node.locator === `id:${item.node.id}`),
      "call 7 impact file node is not repository-relative",
    );
    return { locator, depth: item.depth };
  }).filter((item) => item.depth > 0)
    .sort((left, right) => codeUnitCompare(left.locator, right.locator));
  const rootImpactItems = impactItems.filter((item) => item?.depth === 0);
  v2McpRequire(
    rootImpactItems.length === 1
      && rootImpactItems[0].node?.id === impactResult.root?.id
      && rootImpactItems[0].node?.kind === "file"
      && rootImpactItems[0].node?.display_name
        === "crates/depgraph-mcp-tools/src/catalog.rs"
      && canonicalJson(actualImpacts) === canonicalJson(expectedImpacts)
      && rustImpact.complete === "true",
    "call 7 impact result does not support rust_impact",
  );

  const unresolvedType = claim("rust_unresolved_type");
  const unresolvedResult = results[7];
  const unresolvedRoot = v2McpRoot(
    unresolvedResult,
    8,
    "crates/depgraph-mcp-tools/src/host_config.rs",
  );
  const unresolvedEdges = v2McpNestedPage(unresolvedResult, "edges", 8, {
    returned_items: 10,
    total_items: 66,
    complete: false,
  });
  v2McpRequire(
    unresolvedResult.direction === "outgoing"
      && unresolvedResult.transitive === false
      && unresolvedResult.traversal_complete === true
      && asInteger(unresolvedResult.traversed_edges, 8, "traversed_edges") === 66
      && typeof unresolvedResult.edges.next_cursor === "string"
      && unresolvedResult.edges.next_cursor.length > 0,
    "call 8 graph result does not support rust_unresolved_type",
  );
  const unresolvedLine = claimInteger(unresolvedType, "line", "rust_unresolved_type");
  const unresolvedEdge = v2McpOne(
    unresolvedEdges,
    (entry) => isRecord(entry)
      && entry.target_id === state.selfUnknownId
      && entry.kind === "type_uses",
    8,
    "Self unresolved type edge",
  );
  v2McpRequire(
    unresolvedEdge.source_id === unresolvedRoot.id
      && unresolvedEdge.resolution_status === unresolvedType.status
      && unresolvedEdge.precision === unresolvedType.precision
      && v2McpEvidenceAt(
        unresolvedEdge,
        "crates/depgraph-mcp-tools/src/host_config.rs",
        unresolvedLine,
      ),
    "call 8 selected edge does not support rust_unresolved_type",
  );
  const unresolvedNodeItems = v2McpPage(results[8], 9, {
    returned_items: 1,
    total_items: 1,
    complete: true,
  });
  v2McpRequire(
    unresolvedNodeItems.length === 1
      && unresolvedNodeItems[0].id === state.selfUnknownId
      && unresolvedNodeItems[0].kind === "unknown_target"
      && unresolvedNodeItems[0].locator === unresolvedType.target
      && unresolvedNodeItems[0].display_name === "Self",
    "call 9 node result does not support rust_unresolved_type",
  );

  const candidateImport = claim("rust_candidate_import");
  const candidateImportResult = results[9];
  const candidateImportRoot = v2McpRoot(
    candidateImportResult,
    10,
    "crates/depgraph-cli/src/main.rs",
  );
  const candidateImportEdges = v2McpNestedPage(candidateImportResult, "edges", 10, {
    returned_items: 10,
    total_items: 1213,
    complete: false,
  });
  v2McpRequire(
    candidateImportResult.direction === "outgoing"
      && candidateImportResult.transitive === false
      && candidateImportResult.traversal_complete === true
      && asInteger(candidateImportResult.traversed_edges, 10, "traversed_edges") === 1213
      && typeof candidateImportResult.edges.next_cursor === "string"
      && candidateImportResult.edges.next_cursor.length > 0,
    "call 10 graph result does not support rust_candidate_import",
  );
  const candidateImportLine = claimInteger(candidateImport, "line", "rust_candidate_import");
  const candidateImportEdge = v2McpOne(
    candidateImportEdges,
    (entry) => isRecord(entry)
      && entry.target_id === state.cliModuleId
      && entry.kind === "imports",
    10,
    "candidate Rust import edge",
  );
  v2McpRequire(
    candidateImportEdge.source_id === candidateImportRoot.id
      && candidateImportEdge.resolution_status === candidateImport.status
      && candidateImportEdge.precision === candidateImport.precision
      && candidateImportEdge.condition === "defined(rust.cfg.test)"
      && v2McpEvidenceAt(
        candidateImportEdge,
        "crates/depgraph-cli/src/main.rs",
        candidateImportLine,
      ),
    "call 10 selected edge does not support rust_candidate_import",
  );
  const candidateImportNodeItems = v2McpPage(results[10], 11, {
    returned_items: 1,
    total_items: 1,
    complete: true,
  });
  v2McpRequire(
    candidateImportNodeItems.length === 1
      && candidateImportNodeItems[0].id === state.cliModuleId
      && candidateImportNodeItems[0].kind === "module"
      && candidateImportNodeItems[0].locator === candidateImport.target
      && candidateImportNodeItems[0].display_name === "depgraph-cli",
    "call 11 node result does not support rust_candidate_import",
  );

  const validateDiff = (result, callNumber, claimId) => {
    const fields = claim(claimId);
    v2McpRequire(
      isRecord(result)
        && result.schema_version === "depgraph-snapshot-diff-service-v1"
        && result.from_snapshot_id === baselineId
        && result.to_snapshot_id === candidateId
        && Number.isSafeInteger(result.total_changes)
        && result.total_changes >= 0
        && typeof result.empty === "boolean"
        && Array.isArray(result.changes)
        && result.changes.length === result.total_changes
        && typeof result.collection_digest === "string"
        && result.collection_digest === fields.digest,
      `call ${callNumber} diff result is incomplete`,
    );
    const expectedTotal = fields.total === undefined ? 0 : claimInteger(fields, "total", claimId);
    const expectedEmpty = fields.empty === undefined ? expectedTotal === 0 : fields.empty === "true";
    v2McpRequire(
      result.total_changes === expectedTotal && result.empty === expectedEmpty,
      `call ${callNumber} diff result does not support ${claimId}`,
    );
  };
  validateDiff(results[11], 12, "snapshot_package_diff");
  validateDiff(results[12], 13, "snapshot_file_diff");

  const fileCycle = claim("file_cycle");
  const cycleResult = results[13];
  const cycleItems = v2McpPage(cycleResult, 14, {
    returned_items: 1,
    total_items: 1,
    complete: true,
  });
  const cycle = cycleItems[0];
  const expectedCyclePaths = v2McpExpectedCyclePaths(spec);
  const expectedCycleCount = claimInteger(fileCycle, "count", "file_cycle");
  v2McpRequire(
    expectedCycleCount === 1
      && isRecord(cycle)
      && cycle.level === "file"
      && Array.isArray(cycle.node_ids)
      && cycle.node_ids.length === expectedCyclePaths.length + 1
      && cycle.node_ids[0] === cycle.node_ids[cycle.node_ids.length - 1]
      && canonicalJson(cycle.node_ids) === canonicalJson([
        ...state.cycleNodeIds,
        state.cycleNodeIds?.[0],
      ]),
    "call 14 cycle result does not support file_cycle",
  );
  v2McpRequire(
    Array.isArray(state.cycleNodePaths)
      && state.cycleNodePaths.length === expectedCyclePaths.length
      && state.cycleNodePaths.every(v2McpRepositoryRelativePath)
      && new Set(state.cycleNodePaths).size === expectedCyclePaths.length,
    "calls 15-18 did not resolve four distinct cycle paths",
  );
  const cycleStart = state.cycleNodePaths.indexOf(expectedCyclePaths[0]);
  v2McpRequire(cycleStart >= 0, "calls 15-18 did not resolve the file_cycle start path");
  const observedCyclePaths = expectedCyclePaths.map((_, offset) =>
    state.cycleNodePaths[(cycleStart + offset) % state.cycleNodePaths.length]);
  v2McpRequire(
    canonicalJson(observedCyclePaths) === canonicalJson(expectedCyclePaths),
    "calls 15-18 file paths do not support file_cycle order",
  );
  for (let offset = 0; offset < expectedCyclePaths.length; offset += 1) {
    const node = results[14 + offset];
    const path = state.cycleNodePaths[offset];
    v2McpRequire(
      isRecord(node)
        && node.id === state.cycleNodeIds[offset]
        && node.kind === "file"
        && node.locator === `id:${node.id}`
        && v2McpNodePath(node, 15 + offset) === path,
      `call ${15 + offset} node result does not support file_cycle`,
    );
  }

  const packageCycles = claim("package_cycles");
  const packageCycleItems = v2McpPage(results[18], 19, {
    returned_items: 0,
    total_items: 0,
    complete: true,
  });
  v2McpRequire(
    claimInteger(packageCycles, "count", "package_cycles") === 0
      && packageCycleItems.length === 0,
    "call 19 package cycle result does not support package_cycles",
  );

  const coverageClaim = claim("candidate_coverage");
  const contextResult = results[19];
  const contextDetails = contextResult.snapshot?.details;
  const coverage = contextDetails?.coverage;
  v2McpRequire(
    contextResult.repository_id === V2_MCP_REPOSITORY_ID
      && Array.isArray(contextResult.enabled_capabilities)
      && canonicalJson(contextResult.enabled_capabilities) === canonicalJson(["read"])
      && contextResult.snapshot?.available === true
      && isRecord(contextDetails)
      && contextDetails.snapshot_id === candidateId
      && Array.isArray(contextDetails.names)
      && canonicalJson(contextDetails.names) === canonicalJson([candidateName])
      && contextDetails.status === "completed"
      && contextDetails.source_kind === "scan"
      && contextDetails.parent_snapshot_id === baselineId
      && contextDetails.source_revision === spec.repository.candidate_commit
      && Array.isArray(contextDetails.profile_ids)
      && isRecord(coverage),
    "call 20 context does not report candidate coverage",
  );
  const coverageValues = {
    files: "files_analyzed",
    sites: "dependency_sites",
    resolved: "resolved",
    candidates: "candidates",
    external: "external",
    unresolved: "unresolved",
    unsupported: "unsupported_syntax",
  };
  v2McpRequire(
    asInteger(coverage.profiles, 20, "coverage.profiles") === 3,
    "call 20 coverage.profiles is invalid",
  );
  for (const [claimKey, resultKey] of Object.entries(coverageValues)) {
    v2McpRequire(
      asInteger(coverage[resultKey], 20, `coverage.${resultKey}`)
        === claimInteger(coverageClaim, claimKey, "candidate_coverage"),
      `call 20 coverage.${resultKey} does not support candidate_coverage`,
    );
  }
  v2McpRequire(
    asInteger(coverage.files_discovered, 20, "coverage.files_discovered")
      === claimInteger(coverageClaim, "files", "candidate_coverage")
      && asInteger(coverage.files_skipped, 20, "coverage.files_skipped") === 0
      && coverage.project_code_executed === (coverageClaim.project_code_executed === "true")
      && Array.isArray(coverage.completeness)
      && Array.isArray(coverage.reasons)
      && coverage.reasons.length > 0
      && contextDetails.profile_ids.length === coverage.profiles,
    "call 20 coverage metadata does not support candidate_coverage",
  );

  const unusedFindings = claim("health_unused_findings");
  const unusedResult = results[20];
  const unusedItems = v2McpNestedPage(unusedResult, "findings", 21, {
    returned_items: 7,
    total_items: 7,
    complete: true,
  });
  const unusedCount = claimInteger(unusedFindings, "count", "health_unused_findings");
  v2McpRequire(
    unusedResult.collection_digest === unusedFindings.digest
      && unusedItems.length === unusedCount
      && new Set(unusedItems.map((item) => item?.id)).size === unusedItems.length,
    "call 21 health findings result does not support health_unused_findings",
  );
  for (const item of unusedItems) {
    v2McpRequire(
      isRecord(item)
        && /^finding:sha256:[0-9a-f]{64}$/u.test(item.id ?? "")
        && item.kind === "unused-file"
        && item.severity === "warning"
        && item.confidence === "indeterminate"
        && /^file:sha256:[0-9a-f]{64}$/u.test(item.subject_id ?? "")
        && item.subject_kind === "file"
        && typeof item.reason === "string"
        && item.reason.length > 0
        && Array.isArray(item.blockers)
        && item.blockers.some((blocker) => blocker?.kind === "incomplete-coverage")
        && Array.isArray(item.evidence)
        && Array.isArray(item.remediations)
        && Array.isArray(item.suppressions)
        && typeof item.analyzer_version === "string"
        && /^sha256:[0-9a-f]{64}$/u.test(item.fingerprint ?? ""),
      "call 21 health finding is incomplete",
    );
  }
  v2McpRequire(
    unusedItems[0]?.id === state.findingId
      && unusedItems[0]?.location?.path === "workers/web/src/worker.ts"
      && unusedItems[0]?.subject_id === webRoot.id,
    "call 21 first finding is not chained to the candidate worker",
  );

  const findingDetail = claim("health_finding_detail");
  const detailResult = results[21];
  const detailFinding = detailResult.finding;
  const expectedDetailBlockers = v2McpExpectedBlockerKinds(
    findingDetail.blockers,
    "health_finding_detail",
  );
  v2McpRequire(
    detailResult.input_scope === "snapshot-scoped"
      && isRecord(detailFinding)
      && detailFinding.id === findingDetail.id
      && detailFinding.id === state.findingId
      && detailFinding.kind === findingDetail.kind
      && detailFinding.kind === "unused-file"
      && detailFinding.severity === "warning"
      && detailFinding.confidence === findingDetail.confidence
      && detailFinding.subject_kind === "file"
      && detailFinding.subject_id === webRoot.id
      && detailFinding.location?.path === "workers/web/src/worker.ts"
      && typeof detailFinding.reason === "string"
      && detailFinding.reason.length > 0
      && Array.isArray(detailFinding.blockers)
      && canonicalJson(detailFinding.blockers.map((blocker) => blocker?.kind).sort())
        === canonicalJson([...expectedDetailBlockers].sort())
      && Array.isArray(detailFinding.evidence)
      && Array.isArray(detailFinding.remediations)
      && Array.isArray(detailFinding.suppressions)
      && typeof detailFinding.analyzer_version === "string"
      && /^sha256:[0-9a-f]{64}$/u.test(detailFinding.fingerprint ?? ""),
    "call 22 finding result does not support health_finding_detail",
  );

  const hotspotsClaim = claim("health_hotspots");
  const hotspotsResult = results[22];
  const hotspotItems = v2McpNestedPage(hotspotsResult, "findings", 23, {
    returned_items: 10,
    total_items: 136,
    complete: false,
  });
  v2McpRequire(
    hotspotsResult.collection_digest === V2_MCP_HEALTH_HOTSPOTS_DIGEST
      && typeof hotspotsResult.findings.next_cursor === "string"
      && hotspotsResult.findings.next_cursor.length > 0,
    "call 23 hotspots page is incomplete",
  );
  const expectedHotspotBlockers = v2McpExpectedBlockerKinds(
    hotspotsClaim.blockers,
    "health_hotspots",
  );
  const expectedHotspotScore = claimInteger(hotspotsClaim, "score", "health_hotspots");
  for (let index = 0; index < hotspotItems.length; index += 1) {
    const item = hotspotItems[index];
    const scores = item?.hotspot_scores;
    v2McpRequire(
      isRecord(item)
        && /^finding:sha256:[0-9a-f]{64}$/u.test(item.id ?? "")
        && item.kind === "hotspot"
        && item.severity === "info"
        && item.confidence === "probable"
        && typeof item.subject_id === "string"
        && typeof item.subject_kind === "string"
        && v2McpRepositoryRelativePath(item.location?.path)
        && typeof item.reason === "string"
        && item.reason.length > 0
        && isRecord(scores)
        && Number.isSafeInteger(scores.total)
        && scores.total >= 0
        && ["fan_in", "fan_out", "reverse_impact", "git_churn", "runtime"].every((layer) => {
          const score = scores[layer];
          return isRecord(score)
            && Number.isSafeInteger(score.raw)
            && Number.isSafeInteger(score.normalized_basis_points)
            && Number.isSafeInteger(score.weight_basis_points)
            && typeof score.available === "boolean";
        })
        && Array.isArray(item.blockers)
        && item.blockers.length > 0
        && item.blockers.every((blocker) =>
          isRecord(blocker)
            && typeof blocker.kind === "string"
            && typeof blocker.detail === "string")
        && Array.isArray(item.evidence)
        && Array.isArray(item.remediations)
        && Array.isArray(item.suppressions)
        && typeof item.analyzer_version === "string"
        && /^sha256:[0-9a-f]{64}$/u.test(item.fingerprint ?? "")
        && (index === 0 || hotspotItems[index - 1].hotspot_scores.total >= scores.total),
      "call 23 hotspot finding is incomplete",
    );
  }
  v2McpRequire(
    hotspotItems[0]?.subject_id === hotspotsClaim.top
      && hotspotItems[0]?.hotspot_scores?.total === expectedHotspotScore
      && canonicalJson(hotspotItems[0]?.blockers?.map((blocker) => blocker.kind).sort())
        === canonicalJson([...expectedHotspotBlockers].sort()),
    "call 23 top hotspot does not support health_hotspots",
  );

  const auditClaim = claim("health_audit_base");
  const auditResult = results[23];
  const auditFindings = v2McpNestedPage(auditResult, "findings", 24, {
    returned_items: 0,
    total_items: 0,
    complete: true,
  });
  v2McpRequire(
    auditResult.after_snapshot_id === candidateId
      && auditResult.before_snapshot_id === baselineId
      && auditResult.changed_oid === auditClaim.changed_oid
      && auditResult.collection_digest === auditClaim.digest
      && auditFindings.length === 0,
    "call 24 audit result does not support health_audit_base",
  );
}

function v2McpPlan(spec, state) {
  const candidateName = spec.snapshots.candidate.name;
  const baselineName = spec.snapshots.baseline.name;
  const candidateSnapshotId = spec.snapshots.candidate.id;
  const common = () => v2McpCommonArgs(candidateName);
  const fixed = (tool, args, observe = null) => ({ tool, args, observe });
  const listDependencies = (selector, transitive = false) => fixed(
    "graph_dependencies_list",
    {
      ...common(),
      selector,
      transitive,
      limit: 10,
      max_traversal: V2_MCP_MAX_TRAVERSAL,
    },
  );
  return [
    fixed(
      "agent_nodes_list",
      {
        ...common(),
        query: "catalog",
        match_mode: "exact",
        limit: 10,
      },
      (result) => {
        const item = v2McpOne(
          v2McpItems(result, 1),
          (entry) => isRecord(entry)
            && entry.kind === "module"
            && entry.locator === V2_MCP_CATALOG_LOCATOR
            && typeof entry.id === "string",
          1,
          "catalog module",
        );
        state.catalog = item;
      },
    ),
    fixed(
      "graph_path_get",
      {
        ...common(),
        from: "path:crates/depgraph-mcp-tools/src/lib.rs",
        to: V2_MCP_CATALOG_LOCATOR,
        max_traversal: V2_MCP_MAX_TRAVERSAL,
      },
      (result) => {
        v2McpRequire(
          result.path_found === true
            && isRecord(result.to)
            && result.to.locator === V2_MCP_CATALOG_LOCATOR
            && result.to.id === state.catalog?.id,
          "call 2 path result is not chained to call 1",
        );
      },
    ),
    fixed(
      "graph_dependencies_list",
      {
        ...common(),
        selector: "path:workers/go/cmd/depgraph-go-worker/main.go",
        transitive: false,
        limit: 10,
        max_traversal: V2_MCP_MAX_TRAVERSAL,
      },
      (result) => {
        const edge = v2McpOne(
          v2McpEdges(result, 3),
          (entry) => isRecord(entry)
            && entry.kind === "imports"
            && /^module:sha256:[0-9a-f]{64}$/u.test(entry.target_id ?? ""),
          3,
          "internal Go module edge",
        );
        state.goModuleId = edge.target_id;
      },
    ),
    fixed(
      "agent_nodes_list",
      {
        ...common(),
        query: () => state.goModuleId,
        match_mode: "exact",
        limit: 10,
      },
      (result) => v2McpHasItem(v2McpItems(result, 4), state.goModuleId, 4),
    ),
    listDependencies("path:workers/web/src/worker.ts"),
    fixed(
      "graph_dependents_list",
      {
        ...common(),
        selector: "path:workers/web/src/scanner.ts",
        transitive: false,
        limit: 10,
        max_traversal: V2_MCP_MAX_TRAVERSAL,
      },
    ),
    fixed(
      "graph_impact_get",
      {
        ...common(),
        selector: "path:crates/depgraph-mcp-tools/src/catalog.rs",
        depth: 2,
        limit: 10,
        max_nodes: V2_MCP_MAX_TRAVERSAL,
        max_edges: V2_MCP_MAX_TRAVERSAL,
      },
    ),
    fixed(
      "graph_dependencies_list",
      {
        ...common(),
        selector: "path:crates/depgraph-mcp-tools/src/host_config.rs",
        transitive: false,
        limit: 10,
        max_traversal: V2_MCP_MAX_TRAVERSAL,
      },
      (result) => {
        const edge = v2McpOne(
          v2McpEdges(result, 8),
          (entry) => isRecord(entry)
            && entry.kind === "type_uses"
            && /^unknown_target:sha256:[0-9a-f]{64}$/u.test(entry.target_id ?? ""),
          8,
          "Self unresolved type edge",
        );
        state.selfUnknownId = edge.target_id;
      },
    ),
    fixed(
      "agent_nodes_list",
      {
        ...common(),
        query: () => state.selfUnknownId,
        match_mode: "exact",
        limit: 10,
      },
      (result) => v2McpHasItem(v2McpItems(result, 9), state.selfUnknownId, 9),
    ),
    fixed(
      "graph_dependencies_list",
      {
        ...common(),
        selector: "path:crates/depgraph-cli/src/main.rs",
        transitive: false,
        limit: 10,
        max_traversal: V2_MCP_MAX_TRAVERSAL,
      },
      (result) => {
        const edge = v2McpOne(
          v2McpEdges(result, 10),
          (entry) => isRecord(entry)
            && entry.kind === "imports"
            && /^module:sha256:[0-9a-f]{64}$/u.test(entry.target_id ?? ""),
          10,
          "internal CLI module edge",
        );
        state.cliModuleId = edge.target_id;
      },
    ),
    fixed(
      "agent_nodes_list",
      {
        ...common(),
        query: () => state.cliModuleId,
        match_mode: "exact",
        limit: 10,
      },
      (result) => v2McpHasItem(v2McpItems(result, 11), state.cliModuleId, 11),
    ),
    fixed(
      "snapshot_diff_get",
      {
        contract_version: V2_MCP_CONTRACT_VERSION,
        repository_id: V2_MCP_REPOSITORY_ID,
        from: baselineName,
        to: candidateName,
        kinds: ["package"],
      },
    ),
    fixed(
      "snapshot_diff_get",
      {
        contract_version: V2_MCP_CONTRACT_VERSION,
        repository_id: V2_MCP_REPOSITORY_ID,
        from: baselineName,
        to: candidateName,
        kinds: ["file"],
      },
    ),
    fixed(
      "graph_cycles_list",
      {
        ...common(),
        level: "file",
        limit: 10,
        max_traversal: V2_MCP_MAX_TRAVERSAL,
      },
      (result) => {
        const cycle = v2McpOne(
          v2McpItems(result, 14),
          (entry) => isRecord(entry) && entry.level === "file"
            && Array.isArray(entry.node_ids),
          14,
          "file cycle",
        );
        const nodeIds = cycle.node_ids;
        v2McpRequire(
          nodeIds.length === 5
            && nodeIds[0] === nodeIds[nodeIds.length - 1]
            && nodeIds.slice(0, -1).every(
              (nodeId) => /^file:sha256:[0-9a-f]{64}$/u.test(nodeId),
            )
            && new Set(nodeIds.slice(0, -1)).size === 4,
          "call 14 file cycle does not contain the four closed node IDs",
        );
        state.cycleNodeIds = nodeIds.slice(0, -1);
      },
    ),
    ...[0, 1, 2, 3].map((offset) => fixed(
      "agent_node_get",
      {
        ...common(),
        node_id: () => state.cycleNodeIds?.[offset],
      },
      (result, observedState, callNumber) => {
        v2McpRequire(
          result.id === observedState.cycleNodeIds?.[offset]
            && result.kind === "file",
          `call ${callNumber} node result is not chained to call 14`,
        );
        const path = v2McpNodePath(result, callNumber);
        observedState.cycleNodePaths ??= [];
        observedState.cycleNodePaths[offset] = path;
      },
    )),
    fixed(
      "graph_cycles_list",
      {
        ...common(),
        level: "package",
        limit: 10,
        max_traversal: V2_MCP_MAX_TRAVERSAL,
      },
    ),
    fixed(
      "get_context",
      {
        contract_version: V2_MCP_CONTRACT_VERSION,
        repository_id: V2_MCP_REPOSITORY_ID,
      },
      (result) => {
        v2McpRequire(
          result.repository_id === V2_MCP_REPOSITORY_ID
            && result.snapshot?.available === true
            && result.snapshot.details?.snapshot_id === candidateSnapshotId
            && result.snapshot.details?.status === "completed"
            && result.snapshot.details?.source_revision === spec.repository.candidate_commit,
          "call 20 context does not report the candidate snapshot",
        );
      },
    ),
    fixed(
      "health_findings_list",
      {
        ...common(),
        kinds: ["unused-file"],
        limit: 10,
      },
      (result) => {
        const findings = result.findings?.items;
        const findingIds = Array.isArray(findings)
          ? findings.map((finding) => finding?.id)
          : [];
        v2McpRequire(
          Array.isArray(findings) && findings.length > 0
            && typeof findings[0]?.id === "string"
            && /^finding:sha256:[0-9a-f]{64}$/u.test(findings[0].id),
          "call 21 did not return a finding ID",
        );
        v2McpRequire(
          findingIds.every((findingId) =>
            /^finding:sha256:[0-9a-f]{64}$/u.test(findingId ?? ""))
            && findings[0].id === [...findingIds].sort()[0],
          "call 21 findings are not ordered by their minimum ID",
        );
        state.findingId = findings[0].id;
      },
    ),
    fixed(
      "health_finding_get",
      {
        ...common(),
        finding_id: () => state.findingId,
      },
      (result) => {
        v2McpRequire(
          result.finding?.id === state.findingId,
          "call 22 finding result is not chained to call 21",
        );
      },
    ),
    fixed(
      "health_hotspots_list",
      {
        ...common(),
        limit: 10,
        weight_fan_in: 2500,
        weight_fan_out: 1500,
        weight_reverse_impact: 2500,
        weight_git_churn: 2000,
        weight_runtime: 1500,
        churn_commit_limit: 512,
      },
    ),
    fixed(
      "health_audit_get",
      {
        ...common(),
        base_snapshot: baselineName,
        changed: spec.repository.baseline_commit,
        limit: 10,
      },
    ),
  ].map((descriptor, index) => ({ ...descriptor, callNumber: index + 1 }));
}

export function validateV2McpTrace(spec, text) {
  if (generationOf(spec).schema_version !== SPEC_SCHEMA_VERSION_V2) {
    throw new Error("Agent dogfood v2 MCP trace validator received a non-v2 spec");
  }
  const events = parseTraceEvents(text);
  const mcpItems = events.filter((event) => event?.item?.type === "mcp_tool_call");
  const started = mcpItems.filter((event) => event.type === "item.started");
  const completed = mcpItems.filter((event) => event.type === "item.completed");
  v2McpRequire(
    mcpItems.length === V2_MCP_TRACE_CALL_COUNT * 2
      && started.length === V2_MCP_TRACE_CALL_COUNT
      && completed.length === V2_MCP_TRACE_CALL_COUNT,
    `expected ${V2_MCP_TRACE_CALL_COUNT} started/completed MCP calls`,
  );
  for (let index = 0; index < V2_MCP_TRACE_CALL_COUNT; index += 1) {
    const startedEvent = mcpItems[index * 2];
    const completedEvent = mcpItems[index * 2 + 1];
    v2McpRequire(
      startedEvent.type === "item.started"
        && completedEvent.type === "item.completed"
        && typeof startedEvent.item?.id === "string"
        && startedEvent.item.id === completedEvent.item?.id,
      `call ${index + 1} completion is out of started order or not serial`,
    );
  }

  const byId = (items, kind) => {
    const result = new Map();
    for (const event of items) {
      const item = event.item;
      v2McpRequire(
        typeof item.id === "string" && item.id.length > 0,
        `${kind} MCP call has no ID`,
      );
      v2McpRequire(!result.has(item.id), `${kind} MCP call IDs are not unique`);
      result.set(item.id, event);
    }
    return result;
  };
  const startedById = byId(started, "started");
  const completedById = byId(completed, "completed");
  v2McpRequire(
    startedById.size === completedById.size
      && [...startedById.keys()].every((id) => completedById.has(id)),
    "started/completed MCP call IDs do not match",
  );

  const state = {};
  const results = [];
  const plan = v2McpPlan(spec, state);
  v2McpRequire(
    plan.length === V2_MCP_TRACE_CALL_COUNT,
    "fixed MCP call plan has the wrong length",
  );
  for (let index = 0; index < plan.length; index += 1) {
    const expected = plan[index];
    const startItem = started[index].item;
    const completedItem = completed[index].item;
    const callLabel = `call ${expected.callNumber}`;
    v2McpRequire(
      startItem.id === completedItem.id,
      `${callLabel} completion is out of started order`,
    );
    v2McpRequire(
      startItem.server === "depgraph"
        && completedItem.server === "depgraph",
      `${callLabel} does not use the depgraph MCP server`,
    );
    v2McpRequire(
      startItem.tool === expected.tool
        && completedItem.tool === expected.tool,
      `${callLabel} tool/order does not match the fixed plan`,
    );
    v2McpRequire(
      startItem.status === "in_progress"
        && startItem.error === null
        && startItem.result === null,
      `${callLabel} started item is not an in-progress MCP call`,
    );
    v2McpRequire(
      completedItem.status === "completed"
        && completedItem.error === null,
      `${callLabel} completed item is not successful`,
    );
    v2McpRequire(
      canonicalJson(startItem.arguments) === canonicalJson(completedItem.arguments),
      `${callLabel} started/completed arguments differ`,
    );
    v2McpRequire(
      startedById.get(startItem.id) === started[index]
        && completedById.get(completedItem.id) === completed[index],
      `${callLabel} started/completed ID correspondence is invalid`,
    );
    const result = completedItem.result;
    const structured = result?.structured_content;
    v2McpRequire(
      isRecord(startItem.arguments)
        && isRecord(result)
        && exactKeys(result, ["content", "structured_content"])
        && result.isError !== true
        && result.is_error !== true
        && Array.isArray(result.content)
        && result.content.length === 1
        && exactKeys(result.content[0], ["type", "text"])
        && result.content[0].type === "text"
        && typeof result.content[0].text === "string"
        && exactKeys(structured, [
          "contract_version",
          "repository_id",
          "snapshot_id",
          "result",
        ])
        && structured.contract_version === V2_MCP_CONTRACT_VERSION
        && structured.repository_id === V2_MCP_REPOSITORY_ID
        && structured.snapshot_id === spec.snapshots.candidate.id
        && isRecord(structured.result),
      `${callLabel} structured_content is not a successful candidate result`,
    );
    let textEnvelope;
    try {
      textEnvelope = JSON.parse(result.content[0].text);
    } catch {
      v2McpTraceFailure(`${callLabel} text content is not JSON`);
    }
    v2McpRequire(
      canonicalJson(textEnvelope) === canonicalJson(structured),
      `${callLabel} text and structured content differ`,
    );
    const expectedArgs = resolveV2McpArgs(expected.args);
    v2McpRequire(
      canonicalJson(startItem.arguments) === canonicalJson(expectedArgs),
      `${callLabel} arguments do not match the fixed plan`,
    );
    results.push(structured.result);
    expected.observe?.(structured.result, state, expected.callNumber);
  }
  validateV2McpClaimResults(spec, results, state);
  return true;
}

export function validateV2Trace(spec, arm, text) {
  if (generationOf(spec).schema_version !== SPEC_SCHEMA_VERSION_V2) return true;
  const events = parseTraceEvents(text);
  if (arm === "baseline") {
    v2McpRequire(
      !events.some((event) => event?.item?.type === "mcp_tool_call"),
      "baseline trace contains MCP calls",
    );
    return true;
  }
  if (arm !== "mcp") v2McpTraceFailure(`has an unknown arm: ${arm}`);
  return validateV2McpTrace(spec, text);
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

function shellCommandPayload(command) {
  const words = shellWords(command);
  if (
    words === null
    || words.length !== 3
    || !["/bin/bash", "/bin/zsh"].includes(words[0])
    || !["-c", "-lc"].includes(words[1])
  ) return null;
  return words[2];
}

function approvedReadOnlyCommand(command) {
  if (typeof command !== "string") return false;
  const payload = shellCommandPayload(command);
  if (payload === null || hasUnsafeShellSyntax(payload)) return false;
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
      (quote === null && ";&|<>\r\n(){}[]*?~#!^".includes(character))
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

export function expectedSampleIdentity(spec, digests, environmentSha256) {
  const identity = {
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
  if (generationOf(spec).identity_includes_cli_version) {
    identity.cli_version = spec.host.cli_version;
  }
  return identity;
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
  validateV2Trace(spec, sample.arm, traceText);
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
    || (generationOf(spec).identity_includes_cli_version
      ? !hostCliVersionsMatch(environment.host.cli_version, spec.host.cli_version)
      : !semverAtLeast(environment.host.cli_version, spec.host.minimum_cli_version))
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

export function sentDogfoodPrompt(spec, promptText) {
  if (!isRecord(spec) || spec.schema_version !== SPEC_SCHEMA_VERSION_V2) {
    return promptText;
  }
  return materializeDogfoodPrompt(spec, promptText);
}

export function sentDogfoodPromptSha256(spec, promptText) {
  return sha256Bytes(sentDogfoodPrompt(spec, promptText));
}

export function sourceDigests(specPath, spec) {
  const fixtureDir = dirname(resolve(specPath));
  const promptPath = join(fixtureDir, "prompt.md");
  const answerSchemaPath = join(fixtureDir, "answer.schema.json");
  const safetySchemaPath = join(fixtureDir, "safety.schema.json");
  const promptBytes = readFileSync(promptPath);
  const promptText = promptBytes.toString("utf8");
  const sentPrompt = sentDogfoodPrompt(spec, promptText);
  return {
    fixtureDir,
    promptPath,
    answerSchemaPath,
    safetySchemaPath,
    sentPrompt,
    spec: sha256Bytes(readFileSync(specPath)),
    prompt: spec.schema_version === SPEC_SCHEMA_VERSION_V2
      ? sha256Bytes(sentPrompt)
      : sha256Bytes(promptBytes),
    answerSchema: sha256Bytes(readFileSync(answerSchemaPath)),
    safetySchema: sha256Bytes(readFileSync(safetySchemaPath)),
  };
}

export async function aggregateSamples({ specPath, rawDir }) {
  specPath = resolve(specPath);
  rawDir = resolve(rawDir);
  const spec = validateSpec(jsonFile(specPath));
  const generation = generationOf(spec);
  const digests = sourceDigests(specPath, spec);
  validateCorpusPrompt(spec, readFileSync(digests.promptPath, "utf8"));
  validateRawDirectory(rawDir, spec);
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
    schema_version: generation.report_schema_version,
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

export function validateSparseCheckoutPaths(actual, expected = V2_SPARSE_PATHS) {
  if (
    !Array.isArray(actual)
    || canonicalJson(actual) !== canonicalJson(expected)
  ) {
    throw new Error(
      "dogfood repository sparse-checkout paths do not exactly match the pinned v2 paths",
    );
  }
  return true;
}

export function readSparseCheckoutPaths(repository, environment = process.env) {
  try {
    const output = execFileSync(
      "git",
      ["sparse-checkout", "list"],
      {
        cwd: repository,
        encoding: "utf8",
        env: environment,
        maxBuffer: 4 * 1024 * 1024,
      },
    );
    return output.split(/\r?\n/u).filter((path) => path.length > 0);
  } catch {
    throw new Error(
      "dogfood v2 repository is not a sparse checkout (git sparse-checkout list failed)",
    );
  }
}

function validateRepositorySparseCheckout(spec, repository, environment) {
  const expected = generationOf(spec).sparse_paths;
  if (expected === null) return;
  validateSparseCheckoutPaths(readSparseCheckoutPaths(repository, environment), expected);
}

export function validateSparseCheckoutMaterialization(
  repository,
  expected = V2_SPARSE_PATHS,
  environment = process.env,
) {
  const selected = new Set(expected.map((path) => path.slice(1)));
  const entries = execFileSync(
    "git",
    ["ls-files", "-t", "-z"],
    {
      cwd: repository,
      encoding: "utf8",
      env: environment,
      maxBuffer: 32 * 1024 * 1024,
    },
  ).split("\0").filter(Boolean);
  const observedSelected = new Set();
  for (const entry of entries) {
    const match = /^([A-Z]) (.+)$/u.exec(entry);
    if (match === null) {
      throw new Error("dogfood v2 repository has an invalid sparse index entry");
    }
    const [, tag, path] = match;
    const materialized = existsSync(join(repository, path));
    if (selected.has(path)) {
      if (tag !== "H" || !materialized) {
        throw new Error("dogfood v2 repository is missing a selected sparse path");
      }
      observedSelected.add(path);
    } else if (tag !== "S" || materialized) {
      throw new Error("dogfood v2 repository materialized a path outside the sparse set");
    }
  }
  if (canonicalJson([...observedSelected].sort()) !== canonicalJson([...selected].sort())) {
    throw new Error("dogfood v2 repository sparse selection is incomplete");
  }
  return true;
}

export function sanitizedAgentEnvironment(sourceEnvironment, zDotDir) {
  const environment = {};
  for (const [key, value] of Object.entries(sourceEnvironment)) {
    if (
      value === undefined
      || key.startsWith("GIT_")
      || key === "RIPGREP_CONFIG_PATH"
      || key === "ZDOTDIR"
    ) continue;
    environment[key] = value;
  }
  return {
    ...environment,
    GIT_ATTR_NOSYSTEM: "1",
    GIT_CONFIG_COUNT: "3",
    GIT_CONFIG_GLOBAL: "/dev/null",
    GIT_CONFIG_KEY_0: "core.fsmonitor",
    GIT_CONFIG_KEY_1: "core.hooksPath",
    GIT_CONFIG_KEY_2: "core.attributesFile",
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_CONFIG_SYSTEM: "/dev/null",
    GIT_CONFIG_VALUE_0: "false",
    GIT_CONFIG_VALUE_1: "/dev/null",
    GIT_CONFIG_VALUE_2: "/dev/null",
    GIT_OPTIONAL_LOCKS: "0",
    GIT_PAGER: "",
    GIT_TERMINAL_PROMPT: "0",
    RIPGREP_CONFIG_PATH: "/dev/null",
    ZDOTDIR: zDotDir,
  };
}

export function localGitConfigAllowed(keys, options = {}) {
  const approved = options.allowSparseCheckout
    ? APPROVED_SPARSE_LOCAL_GIT_CONFIG
    : APPROVED_LOCAL_GIT_CONFIG;
  return Array.isArray(keys) && keys.every((key) =>
    typeof key === "string"
    && approved.some((pattern) => pattern.test(key))
  );
}

export function validateLocalGitConfiguration(repository, environment, options = {}) {
  const keys = execFileSync(
    "git",
    ["config", "--local", "--includes", "--name-only", "--null", "--list"],
    {
      cwd: repository,
      encoding: "utf8",
      env: environment,
      maxBuffer: 4 * 1024 * 1024,
    },
  ).split("\0").filter(Boolean);
  if (!localGitConfigAllowed(keys, options)) {
    throw new Error("dogfood repository has unsafe local Git config");
  }
  if (!options.allowSparseCheckout) return;

  const worktreeKeys = execFileSync(
    "git",
    ["config", "--worktree", "--includes", "--name-only", "--null", "--list"],
    {
      cwd: repository,
      encoding: "utf8",
      env: environment,
      maxBuffer: 4 * 1024 * 1024,
    },
  ).split("\0").filter(Boolean);
  const configValues = (scope, key) => execFileSync(
    "git",
    ["config", scope, "--null", "--get-all", key],
    {
      cwd: repository,
      encoding: "utf8",
      env: environment,
      maxBuffer: 4 * 1024 * 1024,
    },
  ).split("\0").filter(Boolean);
  if (
    canonicalJson([...worktreeKeys].sort()) !== canonicalJson(V2_WORKTREE_GIT_CONFIG_KEYS)
    || canonicalJson(configValues("--local", "extensions.worktreeConfig"))
      !== canonicalJson(["true"])
    || canonicalJson(configValues("--worktree", "core.sparseCheckout"))
      !== canonicalJson(["true"])
    || canonicalJson(configValues("--worktree", "core.sparseCheckoutCone"))
      !== canonicalJson(["false"])
  ) {
    throw new Error("dogfood v2 repository has unsafe worktree Git config");
  }
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

export function hostCliVersionsMatch(actual, expected) {
  if (typeof actual !== "string" || typeof expected !== "string") return false;
  if (actual === expected) return true;
  let actualTuple;
  let expectedTuple;
  try {
    actualTuple = semverTuple(actual).join(".");
    expectedTuple = semverTuple(expected).join(".");
  } catch {
    return false;
  }
  if (actualTuple !== expectedTuple) return false;
  return actual.trim() === actualTuple || expected.trim() === expectedTuple;
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

function archiveMemberNames(archive, expectedRoot) {
  let names;
  let verbose;
  try {
    names = execFileSync("tar", ["-tzf", archive], {
      encoding: "utf8",
      maxBuffer: 64 * 1024 * 1024,
    }).trimEnd().split(/\r?\n/u);
    verbose = execFileSync("tar", ["-tvzf", archive], {
      encoding: "utf8",
      maxBuffer: 64 * 1024 * 1024,
    }).trimEnd().split(/\r?\n/u);
  } catch {
    throw new Error("cannot inspect the fixed public archive");
  }
  if (names.length === 0 || names.length !== verbose.length) {
    throw new Error("public archive inventory is incomplete");
  }
  const observed = new Set();
  for (let index = 0; index < names.length; index += 1) {
    const name = names[index].replace(/\/$/u, "");
    const segments = name.split("/");
    if (
      (verbose[index][0] !== "-" && verbose[index][0] !== "d")
      || name !== expectedRoot && !name.startsWith(`${expectedRoot}/`)
      || segments.some((segment) => segment === "" || segment === "." || segment === "..")
      || name.includes("\\")
      || /[\u0000-\u001f\u007f]/u.test(name)
      || observed.has(name)
    ) {
      throw new Error("public archive has an unsafe or duplicate member");
    }
    observed.add(name);
  }
  if (!observed.has(expectedRoot)) {
    throw new Error("public archive is missing its fixed root directory");
  }
  return observed;
}

function assertRegularTree(root) {
  const visit = (directory) => {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      const path = join(directory, entry.name);
      const metadata = lstatSync(path);
      if (entry.isDirectory() && !metadata.isSymbolicLink()) visit(path);
      else if (!entry.isFile() || metadata.isSymbolicLink()) {
        throw new Error("extracted public archive contains a non-regular entry");
      }
    }
  };
  visit(root);
}

export async function verifyExtractedArchiveClosure(archive, packageRoot, archiveRoot) {
  archiveMemberNames(archive, archiveRoot);
  assertRegularTree(packageRoot);
  const temporary = mkdtempSync(join(tmpdir(), "depgraph-dogfood-archive-"));
  try {
    execFileSync("tar", ["-xzf", archive, "-C", temporary], {
      maxBuffer: 4 * 1024 * 1024,
    });
    const extracted = join(temporary, archiveRoot);
    if (!existsSync(extracted) || !lstatSync(extracted).isDirectory()) {
      throw new Error("public archive did not extract to its fixed root");
    }
    assertRegularTree(extracted);
    if (await fingerprintTree(packageRoot) !== await fingerprintTree(extracted)) {
      throw new Error("extracted package does not exactly match the fixed public archive");
    }
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
  return true;
}

export async function verifyCompilerPackClosure(spec, runtime) {
  const requirement = jsonFile(runtime.compilerPackRequirement);
  const compilerRootName = spec.release.compiler_pack_archive.name.replace(/\.tar\.gz$/u, "");
  const expectedChecksumReference =
    `release-checksums:v${expectedPackagedProductVersion(spec)}/compiler-pack-${spec.release.host_target}`;
  if (
    !exactKeys(requirement, [
      "root",
      "expected_manifest_sha256",
      "release_checksum_reference",
      "host",
      "target",
    ])
    || requirement.root !== compilerRootName
    || requirement.release_checksum_reference !== expectedChecksumReference
    || requirement.host !== spec.release.host_target
    || requirement.target !== spec.release.host_target
  ) throw new Error("compiler-pack requirement identity mismatch");
  assertDigest(requirement.expected_manifest_sha256, "compiler-pack manifest");
  const requirementParent = realpathSync(dirname(runtime.compilerPackRequirement));
  const compilerRoot = canonicalExisting(
    join(requirementParent, compilerRootName),
    "compiler-pack root",
    "directory",
  );
  if (dirname(compilerRoot) !== requirementParent) {
    throw new Error("compiler-pack root escapes its requirement directory");
  }
  const members = archiveMemberNames(runtime.compilerPackArchive, compilerRootName);
  await verifyExtractedArchiveClosure(
    runtime.compilerPackArchive,
    compilerRoot,
    compilerRootName,
  );
  const manifestPath = join(compilerRoot, "compiler-pack-manifest.json");
  if (
    !existsSync(manifestPath)
    || await sha256File(manifestPath) !== requirement.expected_manifest_sha256
  ) throw new Error("compiler-pack manifest does not match its public requirement");
  let archiveManifest;
  try {
    archiveManifest = execFileSync(
      "tar",
      ["-xOf", runtime.compilerPackArchive, `${compilerRootName}/compiler-pack-manifest.json`],
      { maxBuffer: 16 * 1024 * 1024 },
    );
  } catch {
    throw new Error("cannot read the compiler-pack manifest from the public archive");
  }
  if (!archiveManifest.equals(readFileSync(manifestPath))) {
    throw new Error("extracted compiler-pack manifest is not from the fixed public archive");
  }
  const manifest = jsonFile(manifestPath);
  if (
    manifest.schema_version !== "depgraph-compiler-pack-manifest-v1"
    || manifest.host !== spec.release.host_target
    || manifest.target !== spec.release.host_target
    || manifest.release_checksum_reference !== expectedChecksumReference
    || !Array.isArray(manifest.directories)
    || !Array.isArray(manifest.files)
    || manifest.directories.length > 100_000
    || manifest.files.length < 1
    || manifest.files.length > 250_000
  ) throw new Error("compiler-pack manifest identity mismatch");

  const directorySet = new Set();
  const expectedMembers = new Set([
    compilerRootName,
    `${compilerRootName}/compiler-pack-manifest.json`,
  ]);
  let previousDirectory = null;
  for (const directory of manifest.directories) {
    if (
      !validNormalizedRelativePath(directory)
      || directory === "compiler-pack-manifest.json"
      || directorySet.has(directory)
      || previousDirectory !== null && previousDirectory >= directory
    ) throw new Error("compiler-pack manifest contains an invalid directory closure");
    previousDirectory = directory;
    directorySet.add(directory);
    expectedMembers.add(`${compilerRootName}/${directory}`);
    const path = join(compilerRoot, directory);
    let metadata;
    try {
      metadata = lstatSync(path);
    } catch {
      throw new Error("compiler-pack is missing a manifest directory");
    }
    if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
      throw new Error("compiler-pack manifest directory is not a real directory");
    }
  }

  const parentPaths = (path) => {
    const segments = path.split("/");
    return Array.from({ length: segments.length - 1 }, (_, index) =>
      segments.slice(0, index + 1).join("/"));
  };
  const requireParents = (path) => {
    for (const parent of parentPaths(path)) {
      if (!directorySet.has(parent)) {
        throw new Error("compiler-pack manifest is missing a parent directory");
      }
    }
  };
  for (const directory of manifest.directories) requireParents(directory);

  const seenFiles = new Set();
  let previousFilePath = null;
  for (const file of manifest.files) {
    if (
      !isRecord(file)
      || typeof file.path !== "string"
      || !validNormalizedRelativePath(file.path)
      || file.path === "compiler-pack-manifest.json"
      || directorySet.has(file.path)
      || seenFiles.has(file.path)
      || previousFilePath !== null && previousFilePath >= file.path
      || !Number.isSafeInteger(file.size)
      || file.size < 0
      || typeof file.executable !== "boolean"
    ) throw new Error("compiler-pack manifest contains an invalid file entry");
    assertDigest(file.sha256, "compiler-pack file");
    previousFilePath = file.path;
    seenFiles.add(file.path);
    requireParents(file.path);
    expectedMembers.add(`${compilerRootName}/${file.path}`);
    const path = join(compilerRoot, file.path);
    if (!existsSync(path)) {
      throw new Error("compiler-pack is missing a manifest file");
    }
    const metadata = lstatSync(path);
    if (
      !metadata.isFile()
      || metadata.isSymbolicLink()
      || metadata.size !== file.size
      || (metadata.mode & 0o111) !== (file.executable ? 0o111 : 0)
      || await sha256File(path) !== file.sha256
    ) throw new Error("compiler-pack file does not match its manifest");
  }
  if (canonicalJson([...members].sort()) !== canonicalJson([...expectedMembers].sort())) {
    throw new Error("compiler-pack archive inventory does not match its manifest");
  }
  return compilerRoot;
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

export async function daemonStateFingerprint(store) {
  const directory = dirname(store);
  const excluded = new Set([
    ...storePaths(store).map((path) => basename(path)),
    ...journalPaths(store).map((path) => basename(path)),
  ]);
  const paths = readdirSync(directory)
    .filter((name) => !excluded.has(name))
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

function validateRepositoryCheckout(spec, repository, environment) {
  const generation = generationOf(spec);
  validateLocalGitConfiguration(repository, environment, {
    allowSparseCheckout: generation.sparse_paths !== null,
  });
  validateRepositorySparseCheckout(spec, repository, environment);
  if (generation.sparse_paths !== null) {
    if (commandOutput("git", ["rev-parse", "--is-shallow-repository"], {
      cwd: repository,
      env: environment,
    }) !== "false") {
      throw new Error("dogfood v2 repository must retain full Git history");
    }
    const alternates = resolve(repository, commandOutput(
      "git",
      ["rev-parse", "--git-path", "objects/info/alternates"],
      { cwd: repository, env: environment },
    ));
    if (existsSync(alternates)) {
      throw new Error("dogfood v2 repository must not use alternate object stores");
    }
    try {
      execFileSync(
        "git",
        [
          "merge-base",
          "--is-ancestor",
          spec.repository.baseline_commit,
          spec.repository.candidate_commit,
        ],
        {
          cwd: repository,
          env: environment,
          stdio: "pipe",
          maxBuffer: 4 * 1024 * 1024,
        },
      );
    } catch {
      throw new Error("dogfood v2 repository does not retain the baseline ancestry");
    }
    validateSparseCheckoutMaterialization(
      repository,
      generation.sparse_paths,
      environment,
    );
  }
  const candidateCommit = commandOutput("git", ["rev-parse", "HEAD"], {
    cwd: repository,
    env: environment,
  });
  const candidateTree = commandOutput("git", ["rev-parse", "HEAD^{tree}"], {
    cwd: repository,
    env: environment,
  });
  const baselineTree = commandOutput(
    "git",
    ["rev-parse", `${spec.repository.baseline_commit}^{tree}`],
    { cwd: repository, env: environment },
  );
  if (
    candidateCommit !== spec.repository.candidate_commit
    || candidateTree !== spec.repository.candidate_tree
    || baselineTree !== spec.repository.baseline_tree
  ) throw new Error("dogfood repository is not the fixed candidate checkout");
  const repositoryStatus = commandOutput(
    "git",
    ["status", "--porcelain=v1", "--untracked-files=all"],
    { cwd: repository, env: environment },
  );
  if (repositoryStatus.length !== 0) {
    throw new Error("dogfood repository must be a clean fixed candidate checkout");
  }
}

async function preflight(spec, runtime, agentEnvironment) {
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
  validateRepositoryCheckout(spec, runtime.repository, agentEnvironment);
  const archiveRoot = spec.release.archive.name.replace(/\.tar\.gz$/u, "");
  if (basename(runtime.packageRoot) !== archiveRoot) {
    throw new Error("extracted release package root has the wrong identity");
  }
  await verifyExtractedArchiveClosure(
    runtime.releaseArchive,
    runtime.packageRoot,
    archiveRoot,
  );
  await verifyCompilerPackClosure(spec, runtime);
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
    || manifest.mcp_server?.version !== expectedPackagedProductVersion(spec)
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
  const codexVersion = commandOutput(spec.host.program, ["--version"], {
    env: agentEnvironment,
  });
  if (generationOf(spec).identity_includes_cli_version) {
    if (!hostCliVersionsMatch(codexVersion, spec.host.cli_version)) {
      throw new Error("Codex CLI does not match the pinned dogfood host version");
    }
  } else if (!semverAtLeast(codexVersion, spec.host.minimum_cli_version)) {
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

async function runCodex({
  spec,
  runtime,
  preflightResult,
  prompt,
  answerSchema,
  arm,
  ordinal,
  rawDir,
  agentEnvironment,
}) {
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
      "mcp_servers.depgraph.enabled=true",
      "--config",
      "mcp_servers.depgraph.required=true",
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
    env: agentEnvironment,
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
  validateRepositoryCheckout(spec, runtime.repository, agentEnvironment);
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
  const spec = validateSpec(jsonFile(specPath));
  if (existsSync(rawDir)) throw new Error("raw output directory already exists");
  const digests = sourceDigests(specPath, spec);
  validateCorpusPrompt(spec, readFileSync(digests.promptPath, "utf8"));
  mkdirSync(rawDir, { recursive: true });
  const prompt = digests.sentPrompt;
  const runtime = requiredRuntime();
  const agentEnvironment = sanitizedAgentEnvironment(process.env, rawDir);
  const ready = await preflight(spec, runtime, agentEnvironment);
  const environmentPath = join(rawDir, "environment.json");
  writeJson(environmentPath, ready.environment);
  const environmentSha256 = await sha256File(environmentPath);
  const identity = expectedSampleIdentity(spec, digests, environmentSha256);
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
        agentEnvironment,
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
  if (command === "lint-spec") {
    const pinned = rest.includes("--pinned");
    const args = rest.filter((argument) => argument !== "--pinned");
    if (args.length !== 1) {
      throw new Error("usage: agent-dogfood.mjs lint-spec [--pinned] <spec>");
    }
    lintSpecFile(args[0], { pinned });
    process.stdout.write(`linted Agent dogfood spec: ${resolve(args[0])}\n`);
    return;
  }
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
    const specPath = resolve(rest[0]);
    const spec = validateSpec(jsonFile(specPath));
    validateCorpusPrompt(spec, readFileSync(join(dirname(specPath), "prompt.md"), "utf8"));
    const report = await aggregateSamples({ specPath, rawDir: rest[1] });
    writeFileSync(resolve(rest[2]), prettyJson(report));
    process.stdout.write(`Agent dogfood report: ${resolve(rest[2])}\n`);
    return;
  }
  if (command === "verify" && rest.length === 3) {
    const specPath = resolve(rest[0]);
    const spec = validateSpec(jsonFile(specPath));
    validateCorpusPrompt(spec, readFileSync(join(dirname(specPath), "prompt.md"), "utf8"));
    await verifyReport({
      specPath,
      rawDir: rest[1],
      report: jsonFile(resolve(rest[2])),
    });
    process.stdout.write(`verified Agent dogfood report: ${resolve(rest[2])}\n`);
    return;
  }
  throw new Error(
    "usage: agent-dogfood.mjs lint-spec [--pinned] <spec> | run|aggregate|verify <spec> <raw-dir> <report>",
  );
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main(process.argv.slice(2)).catch((error) => {
    process.stderr.write(`${error.stack ?? error}\n`);
    process.exitCode = 1;
  });
}
