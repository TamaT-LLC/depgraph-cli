/**
 * Intentionally unreferenced Agent dogfood v2 unused-file probe.
 *
 * Candidate snapshots must contain at least one unused-file finding so
 * `health_findings_list` → `health_finding_get` can be exercised. Do not
 * import this module from production, test, or tool code.
 *
 * See docs/50_test/agent-dogfood-benchmark.md (v2 corpus).
 */
export const UNUSED_HEALTH_PROBE_MARKER: string =
  "depgraph-agent-dogfood-v2-unused-health-probe";
