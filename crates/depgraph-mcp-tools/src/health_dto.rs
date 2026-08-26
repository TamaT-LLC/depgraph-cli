use depgraph_core::service::{
    MAX_HEALTH_BLOCKERS_PER_FINDING, MAX_HEALTH_EVIDENCE_PER_FINDING,
    MAX_HEALTH_REMEDIATIONS_PER_FINDING, MAX_HEALTH_SUPPRESSIONS_PER_FINDING,
};
use depgraph_core::{
    BlockerKind, Confidence, FindingKind, FindingKindScope, HealthFinding, HealthFindingDetail,
    Severity,
};
use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize, de::Error as _};

use crate::{
    AgentId, AgentLabel, AgentPolicyText, AgentToken, ContractBuildError, Page,
    RepositoryRelativePath, SnapshotId,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AgentFindingKind {
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

impl AgentFindingKind {
    fn from_core(kind: FindingKind) -> Self {
        match kind {
            FindingKind::UnusedFile => Self::UnusedFile,
            FindingKind::UnusedExport => Self::UnusedExport,
            FindingKind::UnusedType => Self::UnusedType,
            FindingKind::UnusedDependency => Self::UnusedDependency,
            FindingKind::TestOnlyDependency => Self::TestOnlyDependency,
            FindingKind::ManifestMismatch => Self::ManifestMismatch,
            FindingKind::NewCycle => Self::NewCycle,
            FindingKind::NewBoundaryViolation => Self::NewBoundaryViolation,
            FindingKind::PublicApiChange => Self::PublicApiChange,
            FindingKind::WideBlastRadius => Self::WideBlastRadius,
            FindingKind::Hotspot => Self::Hotspot,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentHealthSeverity {
    Info,
    Warning,
    Error,
}

impl AgentHealthSeverity {
    fn from_core(severity: Severity) -> Self {
        match severity {
            Severity::Info => Self::Info,
            Severity::Warning => Self::Warning,
            Severity::Error => Self::Error,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentHealthConfidence {
    Indeterminate,
    Probable,
    Confirmed,
}

impl AgentHealthConfidence {
    fn from_core(confidence: Confidence) -> Self {
        match confidence {
            Confidence::Indeterminate => Self::Indeterminate,
            Confidence::Probable => Self::Probable,
            Confidence::Confirmed => Self::Confirmed,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AgentHealthBlockerKind {
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

impl AgentHealthBlockerKind {
    fn from_core(kind: BlockerKind) -> Self {
        match kind {
            BlockerKind::PublicSurface => Self::PublicSurface,
            BlockerKind::EntryPoint => Self::EntryPoint,
            BlockerKind::DynamicLoading => Self::DynamicLoading,
            BlockerKind::Candidate => Self::Candidate,
            BlockerKind::Unresolved => Self::Unresolved,
            BlockerKind::HeuristicPrecision => Self::HeuristicPrecision,
            BlockerKind::OverapproxPrecision => Self::OverapproxPrecision,
            BlockerKind::CoverageOmission => Self::CoverageOmission,
            BlockerKind::GeneratedArtifact => Self::GeneratedArtifact,
            BlockerKind::ProfileNotAnalyzed => Self::ProfileNotAnalyzed,
            BlockerKind::IncompleteCoverage => Self::IncompleteCoverage,
            BlockerKind::ManifestDrift => Self::ManifestDrift,
            BlockerKind::InsufficientSurfaceEvidence => Self::InsufficientSurfaceEvidence,
            BlockerKind::MissingBaseSnapshot => Self::MissingBaseSnapshot,
            BlockerKind::BaseSnapshotMismatch => Self::BaseSnapshotMismatch,
            BlockerKind::WorktreeDirty => Self::WorktreeDirty,
            BlockerKind::ChurnUnavailable => Self::ChurnUnavailable,
            BlockerKind::RuntimeNotObserved => Self::RuntimeNotObserved,
            BlockerKind::IncomparableProfileMatrix => Self::IncomparableProfileMatrix,
            BlockerKind::IncomparableCoverage => Self::IncomparableCoverage,
            BlockerKind::IncomparablePolicy => Self::IncomparablePolicy,
            BlockerKind::IncomparableContract => Self::IncomparableContract,
            BlockerKind::InputScopedLookup => Self::InputScopedLookup,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AgentFindingKindScope {
    SnapshotScoped,
    InputScoped,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentHealthSourceLocation {
    path: RepositoryRelativePath,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    start_line: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    start_column: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    end_line: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    end_column: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentHealthBlocker {
    kind: AgentHealthBlockerKind,
    detail: AgentPolicyText,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentHealthEvidenceRef {
    owner_type: AgentToken,
    owner_id: AgentLabel,
    kind: AgentLabel,
    path: AgentLabel,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentHealthRemediation {
    kind: AgentToken,
    detail: AgentPolicyText,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentHealthSuppression {
    id: AgentId,
    finding_id: AgentId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ticket: Option<AgentLabel>,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentHealthFinding {
    id: AgentId,
    kind: AgentFindingKind,
    severity: AgentHealthSeverity,
    confidence: AgentHealthConfidence,
    subject_id: AgentLabel,
    subject_kind: AgentLabel,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    location: Option<AgentHealthSourceLocation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    profile_scope: Option<AgentId>,
    reason: AgentPolicyText,
    #[schemars(length(max = 32))]
    blockers: Vec<AgentHealthBlocker>,
    #[schemars(length(max = 64))]
    evidence: Vec<AgentHealthEvidenceRef>,
    #[schemars(length(max = 8))]
    remediations: Vec<AgentHealthRemediation>,
    #[schemars(length(max = 8))]
    suppressions: Vec<AgentHealthSuppression>,
    analyzer_version: AgentLabel,
    fingerprint: AgentId,
}

impl AgentHealthFinding {
    pub fn try_from_core(source: &HealthFinding) -> Result<Self, ContractBuildError> {
        if source.blockers.len() > MAX_HEALTH_BLOCKERS_PER_FINDING
            || source.evidence.len() > MAX_HEALTH_EVIDENCE_PER_FINDING
            || source.remediations.len() > MAX_HEALTH_REMEDIATIONS_PER_FINDING
            || source.suppressions.len() > MAX_HEALTH_SUPPRESSIONS_PER_FINDING
        {
            return Err(ContractBuildError::AgentDtoValue);
        }
        let location = source
            .location
            .as_ref()
            .map(|location| {
                Ok(AgentHealthSourceLocation {
                    path: RepositoryRelativePath::parse(&location.path)
                        .map_err(|_| ContractBuildError::AgentDtoValue)?,
                    start_line: location.start_line,
                    start_column: location.start_column,
                    end_line: location.end_line,
                    end_column: location.end_column,
                })
            })
            .transpose()?;
        Ok(Self {
            id: parse_id(&source.id)?,
            kind: AgentFindingKind::from_core(source.kind),
            severity: AgentHealthSeverity::from_core(source.severity),
            confidence: AgentHealthConfidence::from_core(source.confidence),
            subject_id: parse_label(&source.subject_id)?,
            subject_kind: parse_label(&source.subject_kind)?,
            location,
            profile_scope: source.profile_scope.as_deref().map(parse_id).transpose()?,
            reason: parse_text(&source.reason)?,
            blockers: source
                .blockers
                .iter()
                .map(|blocker| {
                    Ok(AgentHealthBlocker {
                        kind: AgentHealthBlockerKind::from_core(blocker.kind),
                        detail: parse_text(&blocker.detail)?,
                    })
                })
                .collect::<Result<_, _>>()?,
            evidence: source
                .evidence
                .iter()
                .map(|evidence| {
                    Ok(AgentHealthEvidenceRef {
                        owner_type: parse_token(&evidence.owner_type)?,
                        owner_id: parse_label(&evidence.owner_id)?,
                        kind: parse_label(&evidence.kind)?,
                        path: parse_label(&evidence.path)?,
                    })
                })
                .collect::<Result<_, _>>()?,
            remediations: source
                .remediations
                .iter()
                .map(|remediation| {
                    Ok(AgentHealthRemediation {
                        kind: parse_token(&remediation.kind)?,
                        detail: parse_text(&remediation.detail)?,
                    })
                })
                .collect::<Result<_, _>>()?,
            suppressions: source
                .suppressions
                .iter()
                .map(|suppression| {
                    Ok(AgentHealthSuppression {
                        id: parse_id(&suppression.id)?,
                        finding_id: parse_id(&suppression.finding_id)?,
                        ticket: suppression.ticket.as_deref().map(parse_label).transpose()?,
                    })
                })
                .collect::<Result<_, _>>()?,
            analyzer_version: parse_label(&source.analyzer_version)?,
            fingerprint: parse_id(&source.fingerprint)?,
        })
    }

    #[must_use]
    pub const fn id(&self) -> &AgentId {
        &self.id
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentHealthFindingWire {
    id: AgentId,
    kind: AgentFindingKind,
    severity: AgentHealthSeverity,
    confidence: AgentHealthConfidence,
    subject_id: AgentLabel,
    subject_kind: AgentLabel,
    #[serde(default)]
    location: Option<AgentHealthSourceLocation>,
    #[serde(default)]
    profile_scope: Option<AgentId>,
    reason: AgentPolicyText,
    blockers: Vec<AgentHealthBlocker>,
    evidence: Vec<AgentHealthEvidenceRef>,
    remediations: Vec<AgentHealthRemediation>,
    suppressions: Vec<AgentHealthSuppression>,
    analyzer_version: AgentLabel,
    fingerprint: AgentId,
}

impl<'de> Deserialize<'de> for AgentHealthFinding {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = AgentHealthFindingWire::deserialize(deserializer)?;
        if wire.blockers.len() > MAX_HEALTH_BLOCKERS_PER_FINDING
            || wire.evidence.len() > MAX_HEALTH_EVIDENCE_PER_FINDING
            || wire.remediations.len() > MAX_HEALTH_REMEDIATIONS_PER_FINDING
            || wire.suppressions.len() > MAX_HEALTH_SUPPRESSIONS_PER_FINDING
        {
            return Err(D::Error::custom(ContractBuildError::AgentDtoValue));
        }
        Ok(Self {
            id: wire.id,
            kind: wire.kind,
            severity: wire.severity,
            confidence: wire.confidence,
            subject_id: wire.subject_id,
            subject_kind: wire.subject_kind,
            location: wire.location,
            profile_scope: wire.profile_scope,
            reason: wire.reason,
            blockers: wire.blockers,
            evidence: wire.evidence,
            remediations: wire.remediations,
            suppressions: wire.suppressions,
            analyzer_version: wire.analyzer_version,
            fingerprint: wire.fingerprint,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentHealthNamedCount {
    name: AgentToken,
    count: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentHealthCoverage {
    completeness: Vec<AgentToken>,
    files_skipped: u64,
    unresolved: u64,
    candidates: u64,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentHealthSummary {
    collection_digest: AgentId,
    counts_by_kind: Vec<AgentHealthNamedCount>,
    counts_by_confidence: Vec<AgentHealthNamedCount>,
    coverage: AgentHealthCoverage,
}

impl AgentHealthSummary {
    pub fn try_new(
        collection_digest: &str,
        counts_by_kind: impl IntoIterator<Item = (String, u64)>,
        counts_by_confidence: impl IntoIterator<Item = (String, u64)>,
        completeness: &[String],
        files_skipped: u64,
        unresolved: u64,
        candidates: u64,
    ) -> Result<Self, ContractBuildError> {
        Ok(Self {
            collection_digest: parse_id(collection_digest)?,
            counts_by_kind: named_counts(counts_by_kind)?,
            counts_by_confidence: named_counts(counts_by_confidence)?,
            coverage: AgentHealthCoverage {
                completeness: completeness
                    .iter()
                    .map(|value| parse_token(value))
                    .collect::<Result<_, _>>()?,
                files_skipped,
                unresolved,
                candidates,
            },
        })
    }

    #[must_use]
    pub const fn collection_digest(&self) -> &AgentId {
        &self.collection_digest
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentHealthSummaryWire {
    collection_digest: AgentId,
    counts_by_kind: Vec<AgentHealthNamedCount>,
    counts_by_confidence: Vec<AgentHealthNamedCount>,
    coverage: AgentHealthCoverage,
}

impl<'de> Deserialize<'de> for AgentHealthSummary {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = AgentHealthSummaryWire::deserialize(deserializer)?;
        Ok(Self {
            collection_digest: wire.collection_digest,
            counts_by_kind: wire.counts_by_kind,
            counts_by_confidence: wire.counts_by_confidence,
            coverage: wire.coverage,
        })
    }
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentHealthFindingDetail {
    finding: AgentHealthFinding,
    input_scope: AgentFindingKindScope,
}

impl AgentHealthFindingDetail {
    pub fn try_from_core(source: &HealthFindingDetail) -> Result<Self, ContractBuildError> {
        Ok(Self {
            finding: AgentHealthFinding::try_from_core(&source.finding)?,
            input_scope: match source.input_scope {
                FindingKindScope::SnapshotScoped => AgentFindingKindScope::SnapshotScoped,
                FindingKindScope::InputScoped => AgentFindingKindScope::InputScoped,
            },
        })
    }

    #[must_use]
    pub const fn finding(&self) -> &AgentHealthFinding {
        &self.finding
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentHealthFindingDetailWire {
    finding: AgentHealthFinding,
    input_scope: AgentFindingKindScope,
}

impl<'de> Deserialize<'de> for AgentHealthFindingDetail {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = AgentHealthFindingDetailWire::deserialize(deserializer)?;
        Ok(Self {
            finding: wire.finding,
            input_scope: wire.input_scope,
        })
    }
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentHealthFindingsPage {
    collection_digest: AgentId,
    findings: Page<AgentHealthFinding>,
}

impl AgentHealthFindingsPage {
    pub fn try_new(
        collection_digest: &str,
        findings: Page<AgentHealthFinding>,
    ) -> Result<Self, ContractBuildError> {
        Ok(Self {
            collection_digest: parse_id(collection_digest)?,
            findings,
        })
    }

    #[must_use]
    pub const fn collection_digest(&self) -> &AgentId {
        &self.collection_digest
    }

    #[must_use]
    pub const fn findings(&self) -> &Page<AgentHealthFinding> {
        &self.findings
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentHealthFindingsPageWire {
    collection_digest: AgentId,
    findings: Page<AgentHealthFinding>,
}

impl<'de> Deserialize<'de> for AgentHealthFindingsPage {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = AgentHealthFindingsPageWire::deserialize(deserializer)?;
        Ok(Self {
            collection_digest: wire.collection_digest,
            findings: wire.findings,
        })
    }
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentHealthAudit {
    after_snapshot_id: SnapshotId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    before_snapshot_id: Option<SnapshotId>,
    changed_oid: AgentId,
    collection_digest: AgentId,
    findings: Page<AgentHealthFinding>,
}

impl AgentHealthAudit {
    pub fn try_new(
        after_snapshot_id: &str,
        before_snapshot_id: Option<&str>,
        changed_oid: &str,
        collection_digest: &str,
        findings: Page<AgentHealthFinding>,
    ) -> Result<Self, ContractBuildError> {
        Ok(Self {
            after_snapshot_id: SnapshotId::parse(after_snapshot_id)
                .map_err(|_| ContractBuildError::AgentDtoValue)?,
            before_snapshot_id: before_snapshot_id
                .map(SnapshotId::parse)
                .transpose()
                .map_err(|_| ContractBuildError::AgentDtoValue)?,
            changed_oid: parse_id(changed_oid)?,
            collection_digest: parse_id(collection_digest)?,
            findings,
        })
    }

    #[must_use]
    pub const fn collection_digest(&self) -> &AgentId {
        &self.collection_digest
    }

    #[must_use]
    pub const fn findings(&self) -> &Page<AgentHealthFinding> {
        &self.findings
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentHealthAuditWire {
    after_snapshot_id: SnapshotId,
    #[serde(default)]
    before_snapshot_id: Option<SnapshotId>,
    changed_oid: AgentId,
    collection_digest: AgentId,
    findings: Page<AgentHealthFinding>,
}

impl<'de> Deserialize<'de> for AgentHealthAudit {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = AgentHealthAuditWire::deserialize(deserializer)?;
        Ok(Self {
            after_snapshot_id: wire.after_snapshot_id,
            before_snapshot_id: wire.before_snapshot_id,
            changed_oid: wire.changed_oid,
            collection_digest: wire.collection_digest,
            findings: wire.findings,
        })
    }
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentHealthHotspots {
    collection_digest: AgentId,
    findings: Page<AgentHealthFinding>,
}

impl AgentHealthHotspots {
    pub fn try_new(
        collection_digest: &str,
        findings: Page<AgentHealthFinding>,
    ) -> Result<Self, ContractBuildError> {
        Ok(Self {
            collection_digest: parse_id(collection_digest)?,
            findings,
        })
    }

    #[must_use]
    pub const fn collection_digest(&self) -> &AgentId {
        &self.collection_digest
    }

    #[must_use]
    pub const fn findings(&self) -> &Page<AgentHealthFinding> {
        &self.findings
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentHealthHotspotsWire {
    collection_digest: AgentId,
    findings: Page<AgentHealthFinding>,
}

impl<'de> Deserialize<'de> for AgentHealthHotspots {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = AgentHealthHotspotsWire::deserialize(deserializer)?;
        Ok(Self {
            collection_digest: wire.collection_digest,
            findings: wire.findings,
        })
    }
}

fn named_counts(
    values: impl IntoIterator<Item = (String, u64)>,
) -> Result<Vec<AgentHealthNamedCount>, ContractBuildError> {
    values
        .into_iter()
        .map(|(name, count)| {
            Ok(AgentHealthNamedCount {
                name: parse_token(&name)?,
                count,
            })
        })
        .collect()
}

fn parse_id(value: &str) -> Result<AgentId, ContractBuildError> {
    AgentId::parse(value).map_err(|_| ContractBuildError::AgentDtoValue)
}

fn parse_token(value: &str) -> Result<AgentToken, ContractBuildError> {
    AgentToken::parse(value).map_err(|_| ContractBuildError::AgentDtoValue)
}

fn parse_label(value: &str) -> Result<AgentLabel, ContractBuildError> {
    AgentLabel::parse(value).map_err(|_| ContractBuildError::AgentDtoValue)
}

fn parse_text(value: &str) -> Result<AgentPolicyText, ContractBuildError> {
    AgentPolicyText::parse(value).map_err(|_| ContractBuildError::AgentDtoValue)
}

#[cfg(test)]
mod tests {
    use depgraph_core::{FindingSuppression, SourceLocation};
    use serde_json::json;

    use super::*;

    fn finding_with_suppressions(suppressions: Vec<FindingSuppression>) -> HealthFinding {
        HealthFinding {
            id: "finding:sample".to_owned(),
            kind: FindingKind::UnusedFile,
            severity: Severity::Warning,
            confidence: Confidence::Probable,
            subject_id: "file:src/unused.rs".to_owned(),
            subject_kind: "file".to_owned(),
            location: None,
            profile_scope: None,
            reason: "No reachable usage was observed.".to_owned(),
            blockers: Vec::new(),
            evidence: Vec::new(),
            remediations: Vec::new(),
            suppressions,
            analyzer_version: "1.0.0".to_owned(),
            fingerprint: "sha256:sample".to_owned(),
        }
    }

    #[test]
    fn issue_423_health_finding_preserves_suppressions_in_the_agent_contract() {
        let finding = finding_with_suppressions(vec![FindingSuppression {
            id: "suppression:sample".to_owned(),
            finding_id: "finding:sample".to_owned(),
            ticket: Some("PROJ-ARC-004".to_owned()),
        }]);

        let agent = AgentHealthFinding::try_from_core(&finding).expect("valid health finding");
        assert_eq!(
            serde_json::to_value(agent).expect("serialize agent health finding")["suppressions"],
            json!([{
                "id": "suppression:sample",
                "finding_id": "finding:sample",
                "ticket": "PROJ-ARC-004"
            }])
        );
    }

    #[test]
    fn issue_423_health_finding_rejects_excess_suppressions() {
        let suppressions = (0..=MAX_HEALTH_SUPPRESSIONS_PER_FINDING)
            .map(|index| FindingSuppression {
                id: format!("suppression:{index}"),
                finding_id: "finding:sample".to_owned(),
                ticket: None,
            })
            .collect();

        assert_eq!(
            AgentHealthFinding::try_from_core(&finding_with_suppressions(suppressions)),
            Err(ContractBuildError::AgentDtoValue)
        );
    }

    #[test]
    fn issue_423_health_finding_rejects_non_repository_source_locations() {
        let mut finding = finding_with_suppressions(Vec::new());
        finding.location = Some(SourceLocation {
            path: "/private/secret.rs".to_owned(),
            start_line: Some(1),
            start_column: None,
            end_line: None,
            end_column: None,
        });
        assert_eq!(
            AgentHealthFinding::try_from_core(&finding),
            Err(ContractBuildError::AgentDtoValue)
        );
    }
}
