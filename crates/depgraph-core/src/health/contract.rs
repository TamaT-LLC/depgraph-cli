use std::collections::{BTreeMap, BTreeSet};

use depgraph_protocol::{canonical_json, stable_id_from_value};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::hotspot::HotspotFindingScores;

pub const HEALTH_FINDING_CONTRACT_VERSION: &str = "depgraph-health-finding-v1";
pub const HEALTH_ANALYZER_VERSION: &str = "1.0.2";
pub const BASIS_POINTS_MAX: u32 = 10_000;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FindingKind {
    UnusedFile,
    UnusedExport,
    UnusedType,
    UnusedDependency,
    TestOnlyDependency,
    ManifestMismatch,
    NewCycle,
    NewBoundaryViolation,
    PublicApiChange,
    WideBlastRadius,
    Hotspot,
}

impl FindingKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnusedFile => "unused-file",
            Self::UnusedExport => "unused-export",
            Self::UnusedType => "unused-type",
            Self::UnusedDependency => "unused-dependency",
            Self::TestOnlyDependency => "test-only-dependency",
            Self::ManifestMismatch => "manifest-mismatch",
            Self::NewCycle => "new-cycle",
            Self::NewBoundaryViolation => "new-boundary-violation",
            Self::PublicApiChange => "public-api-change",
            Self::WideBlastRadius => "wide-blast-radius",
            Self::Hotspot => "hotspot",
        }
    }

    #[must_use]
    pub const fn is_snapshot_scoped(self) -> bool {
        matches!(
            self,
            Self::UnusedFile
                | Self::UnusedExport
                | Self::UnusedType
                | Self::UnusedDependency
                | Self::TestOnlyDependency
                | Self::ManifestMismatch
        )
    }

    #[must_use]
    pub const fn default_severity(self) -> Severity {
        match self {
            Self::NewCycle | Self::NewBoundaryViolation | Self::ManifestMismatch => Severity::Error,
            Self::UnusedFile
            | Self::UnusedExport
            | Self::UnusedType
            | Self::UnusedDependency
            | Self::TestOnlyDependency
            | Self::PublicApiChange
            | Self::WideBlastRadius => Severity::Warning,
            Self::Hotspot => Severity::Info,
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "unused-file" => Self::UnusedFile,
            "unused-export" => Self::UnusedExport,
            "unused-type" => Self::UnusedType,
            "unused-dependency" => Self::UnusedDependency,
            "test-only-dependency" => Self::TestOnlyDependency,
            "manifest-mismatch" => Self::ManifestMismatch,
            "new-cycle" => Self::NewCycle,
            "new-boundary-violation" => Self::NewBoundaryViolation,
            "public-api-change" => Self::PublicApiChange,
            "wide-blast-radius" => Self::WideBlastRadius,
            "hotspot" => Self::Hotspot,
            _ => return None,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Warning,
    Error,
}

impl Severity {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Error => "error",
        }
    }

    #[must_use]
    pub const fn rank(self) -> u8 {
        match self {
            Self::Info => 0,
            Self::Warning => 1,
            Self::Error => 2,
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "info" => Self::Info,
            "warning" => Self::Warning,
            "error" => Self::Error,
            _ => return None,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Indeterminate,
    Probable,
    Confirmed,
}

impl Confidence {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Indeterminate => "indeterminate",
            Self::Probable => "probable",
            Self::Confirmed => "confirmed",
        }
    }

    #[must_use]
    pub const fn rank(self) -> u8 {
        match self {
            Self::Indeterminate => 0,
            Self::Probable => 1,
            Self::Confirmed => 2,
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "indeterminate" => Self::Indeterminate,
            "probable" => Self::Probable,
            "confirmed" => Self::Confirmed,
            _ => return None,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BlockerKind {
    PublicSurface,
    EntryPoint,
    DynamicLoading,
    Candidate,
    Unresolved,
    HeuristicPrecision,
    OverapproxPrecision,
    CoverageOmission,
    GeneratedArtifact,
    ProfileNotAnalyzed,
    IncompleteCoverage,
    ManifestDrift,
    InsufficientSurfaceEvidence,
    MissingBaseSnapshot,
    BaseSnapshotMismatch,
    WorktreeDirty,
    ChurnUnavailable,
    RuntimeNotObserved,
    IncomparableProfileMatrix,
    IncomparableCoverage,
    IncomparablePolicy,
    IncomparableContract,
    InputScopedLookup,
}

impl BlockerKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PublicSurface => "public-surface",
            Self::EntryPoint => "entry-point",
            Self::DynamicLoading => "dynamic-loading",
            Self::Candidate => "candidate",
            Self::Unresolved => "unresolved",
            Self::HeuristicPrecision => "heuristic-precision",
            Self::OverapproxPrecision => "overapprox-precision",
            Self::CoverageOmission => "coverage-omission",
            Self::GeneratedArtifact => "generated-artifact",
            Self::ProfileNotAnalyzed => "profile-not-analyzed",
            Self::IncompleteCoverage => "incomplete-coverage",
            Self::ManifestDrift => "manifest-drift",
            Self::InsufficientSurfaceEvidence => "insufficient-surface-evidence",
            Self::MissingBaseSnapshot => "missing-base-snapshot",
            Self::BaseSnapshotMismatch => "base-snapshot-mismatch",
            Self::WorktreeDirty => "worktree-dirty",
            Self::ChurnUnavailable => "churn-unavailable",
            Self::RuntimeNotObserved => "runtime-not-observed",
            Self::IncomparableProfileMatrix => "incomparable-profile-matrix",
            Self::IncomparableCoverage => "incomparable-coverage",
            Self::IncomparablePolicy => "incomparable-policy",
            Self::IncomparableContract => "incomparable-contract",
            Self::InputScopedLookup => "input-scoped-lookup",
        }
    }

    #[must_use]
    pub const fn blocks_confirmed(self) -> bool {
        !matches!(self, Self::ChurnUnavailable | Self::RuntimeNotObserved)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BaselineTransition {
    New,
    Changed,
    Regressed,
    Resolved,
    Reappeared,
}

impl BaselineTransition {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::New => "new",
            Self::Changed => "changed",
            Self::Regressed => "regressed",
            Self::Resolved => "resolved",
            Self::Reappeared => "reappeared",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceLocation {
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_line: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_column: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_line: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_column: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FindingBlocker {
    pub kind: BlockerKind,
    pub detail: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FindingEvidenceRef {
    pub owner_type: String,
    pub owner_id: String,
    pub kind: String,
    pub path: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Remediation {
    pub kind: String,
    pub detail: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FindingSuppression {
    pub id: String,
    pub finding_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ticket: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HealthFinding {
    pub id: String,
    pub kind: FindingKind,
    pub severity: Severity,
    pub confidence: Confidence,
    pub subject_id: String,
    pub subject_kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<SourceLocation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile_scope: Option<String>,
    pub reason: String,
    /// Structured explainability data for hotspot findings.
    ///
    /// This is intentionally optional so non-hotspot findings retain the
    /// compact contract while hotspot consumers can avoid parsing `reason`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hotspot_scores: Option<HotspotFindingScores>,
    pub blockers: Vec<FindingBlocker>,
    pub evidence: Vec<FindingEvidenceRef>,
    pub remediations: Vec<Remediation>,
    pub suppressions: Vec<FindingSuppression>,
    pub analyzer_version: String,
    pub fingerprint: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HealthFindingDetail {
    pub finding: HealthFinding,
    pub input_scope: FindingKindScope,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FindingKindScope {
    SnapshotScoped,
    InputScoped,
}

impl FindingKindScope {
    #[must_use]
    pub const fn for_kind(kind: FindingKind) -> Self {
        if kind.is_snapshot_scoped() {
            Self::SnapshotScoped
        } else {
            Self::InputScoped
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FindingIdentity {
    pub kind: FindingKind,
    pub subject_id: String,
    pub profile_scope: Option<String>,
    pub witness_key: Value,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CollectionIdentity {
    pub snapshot_ids: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manifest_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub changed_oid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub changed_set_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub churn_start_oid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub churn_commit_limit: Option<u32>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub churn_path_filter: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hotspot_weights: Option<BTreeMap<String, u32>>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BaselineFindingRecord {
    pub id: String,
    pub fingerprint: String,
    pub severity: Severity,
    pub confidence: Confidence,
    #[serde(default)]
    pub resolved: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HealthGateConfig {
    pub min_severity: Severity,
    pub min_confidence: Confidence,
    pub violate_on: BTreeSet<BaselineTransition>,
}

impl Default for HealthGateConfig {
    fn default() -> Self {
        Self {
            min_severity: Severity::Warning,
            min_confidence: Confidence::Probable,
            violate_on: BTreeSet::from([
                BaselineTransition::New,
                BaselineTransition::Regressed,
                BaselineTransition::Reappeared,
            ]),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HealthGateDecision {
    pub transition: BaselineTransition,
    pub violation: bool,
}

#[must_use]
pub fn finding_id(identity: &FindingIdentity) -> String {
    let payload = json!({
        "contract": HEALTH_FINDING_CONTRACT_VERSION,
        "kind": identity.kind.as_str(),
        "profile_scope": identity.profile_scope,
        "subject_id": identity.subject_id,
        "witness": identity.witness_key,
    });
    stable_id_from_value("finding", &payload)
}

#[must_use]
pub fn finding_fingerprint(finding: &HealthFinding) -> String {
    let payload = fingerprint_payload(finding);
    format!("sha256:{}", hex_digest(&canonical_json(&payload)))
}

#[must_use]
pub fn collection_digest(identity: &CollectionIdentity, finding_ids: &[String]) -> String {
    let mut ids = finding_ids.to_vec();
    ids.sort();
    ids.dedup();
    let payload = json!({
        "contract": HEALTH_FINDING_CONTRACT_VERSION,
        "finding_ids": ids,
        "input": identity,
    });
    format!(
        "collection:sha256:{}",
        hex_digest(&canonical_json(&payload))
    )
}

#[must_use]
pub fn actionable_rank(severity: Severity, confidence: Confidence) -> u16 {
    u16::from(severity.rank()) * 8 + u16::from(confidence.rank())
}

#[must_use]
pub fn apply_confidence_guards(
    has_usage: bool,
    profiles_complete: bool,
    blockers: &[FindingBlocker],
) -> Confidence {
    if has_usage {
        return Confidence::Indeterminate;
    }
    if blockers
        .iter()
        .any(|blocker| blocker.kind.blocks_confirmed())
    {
        return Confidence::Indeterminate;
    }
    if profiles_complete {
        Confidence::Confirmed
    } else {
        Confidence::Probable
    }
}

#[must_use]
pub fn classify_baseline_transition(
    baseline: Option<&BaselineFindingRecord>,
    current: Option<&HealthFinding>,
) -> Option<BaselineTransition> {
    match (baseline, current) {
        (None, Some(_)) => Some(BaselineTransition::New),
        (Some(previous), None) if !previous.resolved => Some(BaselineTransition::Resolved),
        (Some(previous), Some(_)) if previous.resolved => Some(BaselineTransition::Reappeared),
        (Some(previous), Some(current)) => {
            if actionable_rank(current.severity, current.confidence)
                > actionable_rank(previous.severity, previous.confidence)
            {
                Some(BaselineTransition::Regressed)
            } else if previous.fingerprint == current.fingerprint
                && previous.severity == current.severity
                && previous.confidence == current.confidence
            {
                None
            } else {
                Some(BaselineTransition::Changed)
            }
        }
        (Some(_), None) | (None, None) => None,
    }
}

#[must_use]
pub fn evaluate_health_gate(
    config: &HealthGateConfig,
    transition: BaselineTransition,
    current: Option<&HealthFinding>,
) -> HealthGateDecision {
    let meets_threshold = current.is_some_and(|finding| {
        finding.severity.rank() >= config.min_severity.rank()
            && finding.confidence.rank() >= config.min_confidence.rank()
    });
    let violation = config.violate_on.contains(&transition)
        && (transition == BaselineTransition::Resolved || meets_threshold);
    HealthGateDecision {
        transition,
        violation,
    }
}

/// Rank-normalize integer samples into `0..=10_000` basis points.
///
/// Equal values receive the same rank. When every sample is equal, every
/// result is `0`.
#[must_use]
pub fn rank_normalize_basis_points(values: &[u64]) -> Vec<u32> {
    if values.is_empty() {
        return Vec::new();
    }
    let mut unique = values.to_vec();
    unique.sort_unstable();
    unique.dedup();
    let max_rank = unique.len().saturating_sub(1);
    values
        .iter()
        .map(|value| {
            let rank = unique
                .binary_search(value)
                .unwrap_or_else(|index| index.saturating_sub(1));
            if max_rank == 0 {
                0
            } else {
                u32::try_from(
                    rank.saturating_mul(usize::try_from(BASIS_POINTS_MAX).unwrap_or(0)) / max_rank,
                )
                .unwrap_or(BASIS_POINTS_MAX)
                .min(BASIS_POINTS_MAX)
            }
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
pub fn finish_finding(
    identity: FindingIdentity,
    subject_kind: impl Into<String>,
    location: Option<SourceLocation>,
    reason: impl Into<String>,
    blockers: Vec<FindingBlocker>,
    evidence: Vec<FindingEvidenceRef>,
    remediations: Vec<Remediation>,
    suppressions: Vec<FindingSuppression>,
    has_usage: bool,
    profiles_complete: bool,
) -> HealthFinding {
    let kind = identity.kind;
    let profile_scope = identity.profile_scope.clone();
    let subject_id = identity.subject_id.clone();
    let id = finding_id(&identity);
    let confidence = apply_confidence_guards(has_usage, profiles_complete, &blockers);
    let mut finding = HealthFinding {
        id,
        kind,
        severity: kind.default_severity(),
        confidence,
        subject_id,
        subject_kind: subject_kind.into(),
        location,
        profile_scope,
        reason: reason.into(),
        hotspot_scores: None,
        blockers,
        evidence,
        remediations,
        suppressions,
        analyzer_version: HEALTH_ANALYZER_VERSION.to_owned(),
        fingerprint: String::new(),
    };
    finding.fingerprint = finding_fingerprint(&finding);
    finding
}

fn fingerprint_payload(finding: &HealthFinding) -> Value {
    let mut payload = json!({
        "analyzer_version": finding.analyzer_version,
        "blockers": finding.blockers,
        "confidence": finding.confidence,
        "contract": HEALTH_FINDING_CONTRACT_VERSION,
        "evidence": finding.evidence,
        "id": finding.id,
        "kind": finding.kind,
        "location": finding.location,
        "profile_scope": finding.profile_scope,
        "remediations": finding.remediations,
        "severity": finding.severity,
        "subject_id": finding.subject_id,
        "subject_kind": finding.subject_kind,
        "suppressions": finding.suppressions,
    });
    if let Some(scores) = &finding.hotspot_scores {
        payload["hotspot_scores"] = serde_json::to_value(scores)
            .expect("hotspot score contract is always JSON serializable");
    }
    payload
}

fn hex_digest(bytes: &str) -> String {
    use sha2::{Digest as _, Sha256};
    hex::encode(Sha256::digest(bytes.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_identity() -> FindingIdentity {
        FindingIdentity {
            kind: FindingKind::UnusedFile,
            subject_id: "file:src/unused.rs".to_owned(),
            profile_scope: None,
            witness_key: json!({"path": "src/unused.rs"}),
        }
    }

    fn sample_finding(reason: &str, analyzer_version: &str) -> HealthFinding {
        let identity = sample_identity();
        let mut finding = finish_finding(
            identity,
            "file",
            Some(SourceLocation {
                path: "src/unused.rs".to_owned(),
                start_line: Some(1),
                start_column: Some(1),
                end_line: Some(1),
                end_column: Some(1),
            }),
            reason,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            false,
            true,
        );
        finding.analyzer_version = analyzer_version.to_owned();
        finding.fingerprint = finding_fingerprint(&finding);
        finding
    }

    #[test]
    fn issue_423_finding_id_is_deterministic_and_fingerprint_ignores_reason() {
        let first = finding_id(&sample_identity());
        let mut restated = sample_identity();
        restated.witness_key = json!({"path": "src/unused.rs"});
        assert_eq!(first, finding_id(&restated));
        assert!(first.starts_with("finding:sha256:"));

        let left = sample_finding(
            "unused because no incoming imports",
            HEALTH_ANALYZER_VERSION,
        );
        let right = sample_finding(
            "wording changed after analyzer update",
            HEALTH_ANALYZER_VERSION,
        );
        assert_eq!(left.id, right.id);
        assert_eq!(left.fingerprint, right.fingerprint);

        let changed_analyzer = sample_finding("wording changed after analyzer update", "1.0.1");
        assert_ne!(left.fingerprint, changed_analyzer.fingerprint);
    }

    #[test]
    fn issue_440_path_dependent_finding_ids_change_on_witness_or_subject_rename() {
        let old = FindingIdentity {
            kind: FindingKind::UnusedFile,
            subject_id: "file:src/old.rs".to_owned(),
            profile_scope: None,
            witness_key: json!({"path": "src/old.rs"}),
        };
        let mut witness_renamed = old.clone();
        witness_renamed.witness_key = json!({"path": "src/new.rs"});
        assert_ne!(finding_id(&old), finding_id(&witness_renamed));

        let mut subject_renamed = old;
        subject_renamed.subject_id = "file:src/new.rs".to_owned();
        assert_ne!(finding_id(&witness_renamed), finding_id(&subject_renamed));
    }

    #[test]
    fn issue_423_fingerprint_excludes_self_referential_fields() {
        let finding = sample_finding("unused file", HEALTH_ANALYZER_VERSION);
        let payload = fingerprint_payload(&finding);
        let object = payload.as_object().expect("object");
        assert!(!object.contains_key("fingerprint"));
        assert!(!object.contains_key("collection_digest"));
        assert!(!object.contains_key("transition"));
        assert!(!object.contains_key("reason"));
        assert_eq!(finding.fingerprint, finding_fingerprint(&finding));
    }

    #[test]
    fn issue_440_structured_hotspot_scores_are_included_in_fingerprint() {
        let mut finding = sample_finding("hotspot wording", HEALTH_ANALYZER_VERSION);
        finding.hotspot_scores = Some(crate::health::HotspotFindingScores {
            fan_in: crate::health::HotspotLayerScore {
                raw: 1,
                normalized_basis_points: 2_000,
                weight_basis_points: 2_500,
                available: true,
            },
            fan_out: crate::health::HotspotLayerScore {
                raw: 2,
                normalized_basis_points: 3_000,
                weight_basis_points: 1_500,
                available: true,
            },
            reverse_impact: crate::health::HotspotLayerScore {
                raw: 3,
                normalized_basis_points: 4_000,
                weight_basis_points: 2_500,
                available: true,
            },
            git_churn: crate::health::HotspotLayerScore {
                raw: 0,
                normalized_basis_points: 0,
                weight_basis_points: 2_000,
                available: false,
            },
            runtime: crate::health::HotspotLayerScore {
                raw: 0,
                normalized_basis_points: 0,
                weight_basis_points: 1_500,
                available: false,
            },
            total: 3_000,
        });
        finding.fingerprint = finding_fingerprint(&finding);
        let original = finding.fingerprint.clone();
        finding.reason = "another rendering of the same score".to_owned();
        assert_eq!(finding_fingerprint(&finding), original);
        finding
            .hotspot_scores
            .as_mut()
            .expect("scores")
            .fan_in
            .normalized_basis_points = 2_001;
        assert_ne!(finding_fingerprint(&finding), original);
    }

    #[test]
    fn issue_423_canonical_bytes_are_key_order_independent() {
        let identity = CollectionIdentity {
            snapshot_ids: vec!["snapshot:b".to_owned(), "snapshot:a".to_owned()],
            manifest_digest: Some("sha256:aa".to_owned()),
            changed_oid: None,
            changed_set_digest: None,
            churn_start_oid: None,
            churn_commit_limit: None,
            churn_path_filter: Vec::new(),
            hotspot_weights: None,
        };
        let first = collection_digest(&identity, &["finding:2".to_owned(), "finding:1".to_owned()]);
        let second =
            collection_digest(&identity, &["finding:1".to_owned(), "finding:2".to_owned()]);
        assert_eq!(first, second);
        assert!(first.starts_with("collection:sha256:"));
    }

    #[test]
    fn issue_423_confidence_guards_refuse_confirmed_when_blockers_or_usage_exist() {
        let blocker = FindingBlocker {
            kind: BlockerKind::PublicSurface,
            detail: "exported API".to_owned(),
        };
        assert_eq!(
            apply_confidence_guards(false, true, std::slice::from_ref(&blocker)),
            Confidence::Indeterminate
        );
        assert_eq!(
            apply_confidence_guards(true, true, &[]),
            Confidence::Indeterminate
        );
        assert_eq!(
            apply_confidence_guards(false, false, &[]),
            Confidence::Probable
        );
        assert_eq!(
            apply_confidence_guards(false, true, &[]),
            Confidence::Confirmed
        );
        assert_eq!(
            apply_confidence_guards(
                false,
                true,
                &[FindingBlocker {
                    kind: BlockerKind::ChurnUnavailable,
                    detail: "git missing".to_owned(),
                }]
            ),
            Confidence::Confirmed
        );
    }

    #[test]
    fn issue_423_baseline_classifies_indeterminate_to_confirmed_as_regressed() {
        let mut current = sample_finding("unused file", HEALTH_ANALYZER_VERSION);
        current.confidence = Confidence::Confirmed;
        current.fingerprint = finding_fingerprint(&current);
        let baseline = BaselineFindingRecord {
            id: current.id.clone(),
            // Never let an inconsistent/stale fingerprint hide an explicit
            // actionability increase recorded by the baseline fields.
            fingerprint: current.fingerprint.clone(),
            severity: Severity::Warning,
            confidence: Confidence::Indeterminate,
            resolved: false,
        };
        assert_eq!(
            classify_baseline_transition(Some(&baseline), Some(&current)),
            Some(BaselineTransition::Regressed)
        );
        let decision = evaluate_health_gate(
            &HealthGateConfig::default(),
            BaselineTransition::Regressed,
            Some(&current),
        );
        assert!(decision.violation);
    }

    #[test]
    fn issue_423_baseline_new_changed_resolved_and_reappeared() {
        let current = sample_finding("unused file", HEALTH_ANALYZER_VERSION);
        assert_eq!(
            classify_baseline_transition(None, Some(&current)),
            Some(BaselineTransition::New)
        );
        let unchanged = BaselineFindingRecord {
            id: current.id.clone(),
            fingerprint: current.fingerprint.clone(),
            severity: current.severity,
            confidence: current.confidence,
            resolved: false,
        };
        assert_eq!(
            classify_baseline_transition(Some(&unchanged), Some(&current)),
            None
        );
        let quieter = BaselineFindingRecord {
            id: current.id.clone(),
            fingerprint: "sha256:other".to_owned(),
            severity: Severity::Error,
            confidence: Confidence::Confirmed,
            resolved: false,
        };
        assert_eq!(
            classify_baseline_transition(Some(&quieter), Some(&current)),
            Some(BaselineTransition::Changed)
        );
        assert_eq!(
            classify_baseline_transition(Some(&unchanged), None),
            Some(BaselineTransition::Resolved)
        );
        let resolved = BaselineFindingRecord {
            resolved: true,
            ..unchanged
        };
        assert_eq!(
            classify_baseline_transition(Some(&resolved), Some(&current)),
            Some(BaselineTransition::Reappeared)
        );
    }

    #[test]
    fn issue_423_rank_normalization_is_integer_and_ties_share_a_rank() {
        assert_eq!(rank_normalize_basis_points(&[2, 2, 2]), vec![0, 0, 0]);
        assert_eq!(
            rank_normalize_basis_points(&[1, 10, 1, 20]),
            vec![0, 5_000, 0, 10_000]
        );
        assert_eq!(rank_normalize_basis_points(&[]), Vec::<u32>::new());
    }
}
