use std::{collections::BTreeMap, path::Path};

use anyhow::{Context, Result};
use depgraph_core::{
    BaselineFindingRecord, BaselineTransition, Confidence, FindingKind, HealthFinding,
    HealthGateConfig, QueryCountGroup, QueryCountSummary, Severity, classify_baseline_transition,
    evaluate_health_gate, read_bounded_repository_file,
};
use serde::Serialize;

const MAX_HEALTH_BASELINE_BYTES: usize = 16 * 1024 * 1024;

pub const HEALTH_LONG_HELP: &str = "\
Explainable code-health findings for one pinned snapshot.

Confidence:
  confirmed      unused across every applicable analyzed profile, all of those
                 profiles are semantic-complete, and no hard blocker remains
  probable       unused so far with no hard blocker, but applicable profiles
                 are syntax-complete rather than semantic-complete
  indeterminate  a blocker prevents confirmed unused (public surface, entry
                 point, dynamic loading, candidate, unresolved, generated
                 artifact, profile-not-analyzed, manifest-drift, or similar)

This summary and list cover snapshot-scoped kinds only: unused-file,
unused-export, unused-type, unused-dependency, test-only-dependency, and
manifest-mismatch. They do not include audit or hotspot findings.

Read blockers before deleting or unexporting anything. Source is never
changed automatically.";

pub const CLEANUP_LONG_HELP: &str = "\
List snapshot-scoped unused-code or unused-dependency findings.

Same domain result as `depgraph health list`. Use --kind to restrict kinds.
Read confidence and blockers before acting. Source is never changed.

`--baseline` applies the transition gate (new / changed / regressed /
resolved / reappeared). Default violations are new, regressed, and
reappeared at severity warning+ and confidence probable+.";

pub const AUDIT_LONG_HELP: &str = "\
Audit changed code against a before/after snapshot pair.

`--changed` is the comparison base for merge-base(GIT_REF, HEAD)..HEAD.
Both refs are resolved at request start; changed_oid identifies that HEAD.
Without a comparable base snapshot, blast radius remains evaluable while
new-cycle / new-boundary / public-api checks return indeterminate placeholders
with blocker missing-base-snapshot.";

pub const HOTSPOTS_LONG_HELP: &str = "\
Rank graph hotspots using integer basis-point scores (0..=10000).

Layers: fan-in, fan-out, reverse impact, Git churn, runtime observation.
A missing layer contributes 0 and does not renormalize weights.";

#[derive(Serialize)]
pub struct CliHealthSummaryView<'a> {
    pub snapshot_id: &'a str,
    pub scan_id: &'a str,
    pub collection_digest: &'a str,
    pub counts_by_kind: &'a BTreeMap<String, u64>,
    pub counts_by_confidence: &'a BTreeMap<String, u64>,
    pub coverage: &'a depgraph_core::service::HealthCoverageOverview,
}

#[derive(Serialize)]
pub struct CliHealthFindingsView<'a> {
    pub snapshot_id: &'a str,
    pub scan_id: &'a str,
    pub collection_digest: &'a str,
    pub findings: &'a [HealthFinding],
}

#[derive(Serialize)]
pub struct CliHealthAuditView<'a> {
    pub after_snapshot_id: &'a str,
    pub before_snapshot_id: Option<&'a str>,
    pub changed_oid: &'a str,
    pub collection_digest: &'a str,
    pub findings: &'a [HealthFinding],
}

pub fn parse_snapshot_kinds(values: &[String]) -> Result<Vec<FindingKind>> {
    values
        .iter()
        .map(|value| {
            FindingKind::parse(value)
                .filter(|kind| kind.is_snapshot_scoped())
                .with_context(|| format!("unsupported snapshot-scoped health kind: {value}"))
        })
        .collect()
}

pub fn parse_severities(values: &[String]) -> Result<Vec<Severity>> {
    values
        .iter()
        .map(|value| {
            Severity::parse(value).with_context(|| format!("unsupported severity: {value}"))
        })
        .collect()
}

pub fn parse_confidences(values: &[String]) -> Result<Vec<Confidence>> {
    values
        .iter()
        .map(|value| {
            Confidence::parse(value).with_context(|| format!("unsupported confidence: {value}"))
        })
        .collect()
}

pub fn print_health_summary_human(summary: &depgraph_core::service::HealthSummaryResult) {
    println!("health collection: {}", summary.collection_digest());
    println!("scan: {}", summary.scan_id());
    println!(
        "coverage: skipped={} unresolved={} candidates={}",
        summary.coverage().files_skipped,
        summary.coverage().unresolved,
        summary.coverage().candidates
    );
    if summary.counts_by_kind().is_empty() {
        println!("findings: none");
    }
    for (kind, count) in summary.counts_by_kind() {
        println!("kind {kind}: {count}");
    }
    for (confidence, count) in summary.counts_by_confidence() {
        println!("confidence {confidence}: {count}");
    }
    println!(
        "summary excludes audit and hotspot findings; confirmed requires semantic-complete profiles and no hard blockers"
    );
}

pub fn print_findings_human(findings: &[HealthFinding]) {
    if findings.is_empty() {
        println!("no health findings");
    }
    for finding in findings {
        let location = finding
            .location
            .as_ref()
            .map(|location| location.path.as_str())
            .unwrap_or("-");
        println!(
            "{} {} {} {} at {} ({})",
            finding.kind.as_str(),
            finding.confidence.as_str(),
            finding.severity.as_str(),
            finding.subject_id,
            location,
            finding.id
        );
        println!("  {}", finding.reason);
        for blocker in &finding.blockers {
            println!("  blocker {}: {}", blocker.kind.as_str(), blocker.detail);
        }
    }
}

pub fn findings_page_summary(findings: &[HealthFinding]) -> depgraph_core::InteractiveQuerySummary {
    let mut by_kind = BTreeMap::<String, u64>::new();
    let mut by_confidence = BTreeMap::<String, u64>::new();
    for finding in findings {
        *by_kind.entry(finding.kind.as_str().to_owned()).or_insert(0) += 1;
        *by_confidence
            .entry(finding.confidence.as_str().to_owned())
            .or_insert(0) += 1;
    }
    depgraph_core::InteractiveQuerySummary {
        total_items: findings.len() as u64,
        by_status: count_summary(&by_confidence),
        by_phase: QueryCountSummary {
            groups: Vec::new(),
            omitted_groups: 0,
            omitted_items: 0,
        },
        by_profile: QueryCountSummary {
            groups: Vec::new(),
            omitted_groups: 0,
            omitted_items: 0,
        },
        by_kind: count_summary(&by_kind),
        by_reason: QueryCountSummary {
            groups: Vec::new(),
            omitted_groups: 0,
            omitted_items: 0,
        },
    }
}

fn count_summary(counts: &BTreeMap<String, u64>) -> QueryCountSummary {
    QueryCountSummary {
        groups: counts
            .iter()
            .map(|(key, count)| QueryCountGroup {
                key: key.clone(),
                count: *count,
            })
            .collect(),
        omitted_groups: 0,
        omitted_items: 0,
    }
}

pub fn evaluate_baseline_gate(
    baseline_path: Option<&Path>,
    findings: &[HealthFinding],
    min_severity: Option<&str>,
    min_confidence: Option<&str>,
    json_output: bool,
) -> Result<bool> {
    let Some(path) = baseline_path else {
        return Ok(false);
    };
    let mut config = HealthGateConfig::default();
    if let Some(severity) = min_severity {
        config.min_severity = Severity::parse(severity)
            .with_context(|| format!("unsupported severity: {severity}"))?;
    }
    if let Some(confidence) = min_confidence {
        config.min_confidence = Confidence::parse(confidence)
            .with_context(|| format!("unsupported confidence: {confidence}"))?;
    }
    let records = load_baseline(path)?;
    let mut current = findings
        .iter()
        .map(|finding| (finding.id.as_str(), finding))
        .collect::<BTreeMap<_, _>>();
    let mut violation = false;
    let print_transition = |id: &str, transition: BaselineTransition, is_violation: bool| {
        if json_output {
            eprintln!(
                "baseline {id}: {} violation={is_violation}",
                transition.as_str()
            );
        } else {
            println!(
                "baseline {id}: {} violation={is_violation}",
                transition.as_str()
            );
        }
    };
    for record in &records {
        let finding = current.remove(record.id.as_str());
        if let Some(transition) = classify_baseline_transition(Some(record), finding) {
            let decision = evaluate_health_gate(&config, transition, finding);
            print_transition(&record.id, decision.transition, decision.violation);
            violation |= decision.violation;
        }
    }
    for finding in current.values() {
        let transition =
            classify_baseline_transition(None, Some(finding)).unwrap_or(BaselineTransition::New);
        let decision = evaluate_health_gate(&config, transition, Some(finding));
        print_transition(&finding.id, decision.transition, decision.violation);
        violation |= decision.violation;
    }
    Ok(violation)
}

fn load_baseline(path: &Path) -> Result<Vec<BaselineFindingRecord>> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let file_name = path.file_name().context("baseline path must name a file")?;
    let bytes =
        read_bounded_repository_file(parent, Path::new(file_name), MAX_HEALTH_BASELINE_BYTES)
            .with_context(|| format!("failed to read baseline {}", path.display()))?;
    let value: serde_json::Value = serde_json::from_slice(&bytes)?;
    let items = value.get("findings").cloned().unwrap_or(value);
    serde_json::from_value(items)
        .context("baseline file must be a finding array or {{findings: [...]}}")
}
