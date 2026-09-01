use std::borrow::Cow;

use depgraph_core::health::{BASIS_POINTS_MAX, hotspot_weighted_total};
use depgraph_core::service::{
    MAX_HEALTH_BLOCKERS_PER_FINDING, MAX_HEALTH_EVIDENCE_PER_FINDING,
    MAX_HEALTH_REMEDIATIONS_PER_FINDING, MAX_HEALTH_SUPPRESSIONS_PER_FINDING,
};
use depgraph_core::{
    BlockerKind, Confidence, FindingKind, FindingKindScope, HealthFinding, HealthFindingDetail,
    HotspotFindingScores, HotspotLayerScore, Severity,
};
use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
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

/// One machine-readable hotspot layer contribution.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentHealthHotspotLayerScore {
    raw: u64,
    normalized_basis_points: u32,
    weight_basis_points: u32,
    available: bool,
}

impl JsonSchema for AgentHealthHotspotLayerScore {
    fn schema_name() -> Cow<'static, str> {
        "AgentHealthHotspotLayerScore".into()
    }

    fn schema_id() -> Cow<'static, str> {
        concat!(module_path!(), "::AgentHealthHotspotLayerScore").into()
    }

    fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
        // JSON Schema can express the unavailable-layer zero invariant exactly.
        // The derived weighted-total invariant is documented on the enclosing
        // score object and enforced by its authoritative Serde projection.
        json_schema!({
            "description": "One machine-readable hotspot layer contribution.",
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "raw": {"type": "integer", "format": "uint64", "minimum": 0},
                "normalized_basis_points": {"type": "integer", "format": "uint32", "minimum": 0, "maximum": BASIS_POINTS_MAX},
                "weight_basis_points": {"type": "integer", "format": "uint32", "minimum": 0, "maximum": BASIS_POINTS_MAX},
                "available": {"type": "boolean"}
            },
            "required": ["raw", "normalized_basis_points", "weight_basis_points", "available"],
            "allOf": [{
                "if": {
                    "properties": {"available": {"const": false}},
                    "required": ["available"]
                },
                "then": {
                    "properties": {
                        "raw": {"const": 0},
                        "normalized_basis_points": {"const": 0}
                    }
                }
            }]
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentHealthHotspotLayerScoreWire {
    raw: u64,
    normalized_basis_points: u32,
    weight_basis_points: u32,
    available: bool,
}

impl<'de> Deserialize<'de> for AgentHealthHotspotLayerScore {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = AgentHealthHotspotLayerScoreWire::deserialize(deserializer)?;
        if wire.normalized_basis_points > BASIS_POINTS_MAX
            || wire.weight_basis_points > BASIS_POINTS_MAX
            || (!wire.available && (wire.raw != 0 || wire.normalized_basis_points != 0))
        {
            return Err(D::Error::custom(ContractBuildError::AgentDtoValue));
        }
        Ok(Self {
            raw: wire.raw,
            normalized_basis_points: wire.normalized_basis_points,
            weight_basis_points: wire.weight_basis_points,
            available: wire.available,
        })
    }
}

impl AgentHealthHotspotLayerScore {
    fn try_from_core(source: &HotspotLayerScore) -> Result<Self, ContractBuildError> {
        if source.normalized_basis_points > BASIS_POINTS_MAX
            || source.weight_basis_points > BASIS_POINTS_MAX
            || (!source.available && (source.raw != 0 || source.normalized_basis_points != 0))
        {
            return Err(ContractBuildError::AgentDtoValue);
        }
        Ok(Self {
            raw: source.raw,
            normalized_basis_points: source.normalized_basis_points,
            weight_basis_points: source.weight_basis_points,
            available: source.available,
        })
    }

    #[must_use]
    pub const fn raw(&self) -> u64 {
        self.raw
    }

    #[must_use]
    pub const fn normalized_basis_points(&self) -> u32 {
        self.normalized_basis_points
    }

    #[must_use]
    pub const fn weight_basis_points(&self) -> u32 {
        self.weight_basis_points
    }

    #[must_use]
    pub const fn available(&self) -> bool {
        self.available
    }
}

/// Closed MCP projection of all five hotspot score layers.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentHealthHotspotScores {
    fan_in: AgentHealthHotspotLayerScore,
    fan_out: AgentHealthHotspotLayerScore,
    reverse_impact: AgentHealthHotspotLayerScore,
    git_churn: AgentHealthHotspotLayerScore,
    runtime: AgentHealthHotspotLayerScore,
    total: u32,
}

impl JsonSchema for AgentHealthHotspotScores {
    fn schema_name() -> Cow<'static, str> {
        "AgentHealthHotspotScores".into()
    }

    fn schema_id() -> Cow<'static, str> {
        concat!(module_path!(), "::AgentHealthHotspotScores").into()
    }

    fn json_schema(generator: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "description": "Closed MCP projection of all five hotspot score layers.",
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "fan_in": generator.subschema_for::<AgentHealthHotspotLayerScore>(),
                "fan_out": generator.subschema_for::<AgentHealthHotspotLayerScore>(),
                "reverse_impact": generator.subschema_for::<AgentHealthHotspotLayerScore>(),
                "git_churn": generator.subschema_for::<AgentHealthHotspotLayerScore>(),
                "runtime": generator.subschema_for::<AgentHealthHotspotLayerScore>(),
                "total": {"type": "integer", "format": "uint32", "minimum": 0, "maximum": BASIS_POINTS_MAX}
            },
            "required": ["fan_in", "fan_out", "reverse_impact", "git_churn", "runtime", "total"],
            // Draft 2020-12 has no arithmetic keyword for cross-property sums.
            // Keep the exact rule machine-readable for schema consumers while
            // AgentHealthHotspotScores' custom deserializer remains authoritative.
            "x-depgraph-weight-sum-max": BASIS_POINTS_MAX,
            "x-depgraph-derived-total": "sum(floor(normalized_basis_points * weight_basis_points / 10000))"
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentHealthHotspotScoresWire {
    fan_in: AgentHealthHotspotLayerScore,
    fan_out: AgentHealthHotspotLayerScore,
    reverse_impact: AgentHealthHotspotLayerScore,
    git_churn: AgentHealthHotspotLayerScore,
    runtime: AgentHealthHotspotLayerScore,
    total: u32,
}

impl<'de> Deserialize<'de> for AgentHealthHotspotScores {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = AgentHealthHotspotScoresWire::deserialize(deserializer)?;
        if wire.total > BASIS_POINTS_MAX
            || weight_sum(&wire) > BASIS_POINTS_MAX
            || wire.total
                != hotspot_weighted_total([
                    (
                        wire.fan_in.normalized_basis_points(),
                        wire.fan_in.weight_basis_points(),
                    ),
                    (
                        wire.fan_out.normalized_basis_points(),
                        wire.fan_out.weight_basis_points(),
                    ),
                    (
                        wire.reverse_impact.normalized_basis_points(),
                        wire.reverse_impact.weight_basis_points(),
                    ),
                    (
                        wire.git_churn.normalized_basis_points(),
                        wire.git_churn.weight_basis_points(),
                    ),
                    (
                        wire.runtime.normalized_basis_points(),
                        wire.runtime.weight_basis_points(),
                    ),
                ])
        {
            return Err(D::Error::custom(ContractBuildError::AgentDtoValue));
        }
        Ok(Self {
            fan_in: wire.fan_in,
            fan_out: wire.fan_out,
            reverse_impact: wire.reverse_impact,
            git_churn: wire.git_churn,
            runtime: wire.runtime,
            total: wire.total,
        })
    }
}

impl AgentHealthHotspotScores {
    pub fn try_from_core(source: &HotspotFindingScores) -> Result<Self, ContractBuildError> {
        if source.total > BASIS_POINTS_MAX
            || source
                .fan_in
                .weight_basis_points
                .saturating_add(source.fan_out.weight_basis_points)
                .saturating_add(source.reverse_impact.weight_basis_points)
                .saturating_add(source.git_churn.weight_basis_points)
                .saturating_add(source.runtime.weight_basis_points)
                > BASIS_POINTS_MAX
            || source.total != core_weighted_total(source)
        {
            return Err(ContractBuildError::AgentDtoValue);
        }
        Ok(Self {
            fan_in: AgentHealthHotspotLayerScore::try_from_core(&source.fan_in)?,
            fan_out: AgentHealthHotspotLayerScore::try_from_core(&source.fan_out)?,
            reverse_impact: AgentHealthHotspotLayerScore::try_from_core(&source.reverse_impact)?,
            git_churn: AgentHealthHotspotLayerScore::try_from_core(&source.git_churn)?,
            runtime: AgentHealthHotspotLayerScore::try_from_core(&source.runtime)?,
            total: source.total,
        })
    }

    #[must_use]
    pub const fn fan_in(&self) -> &AgentHealthHotspotLayerScore {
        &self.fan_in
    }

    #[must_use]
    pub const fn fan_out(&self) -> &AgentHealthHotspotLayerScore {
        &self.fan_out
    }

    #[must_use]
    pub const fn reverse_impact(&self) -> &AgentHealthHotspotLayerScore {
        &self.reverse_impact
    }

    #[must_use]
    pub const fn git_churn(&self) -> &AgentHealthHotspotLayerScore {
        &self.git_churn
    }

    #[must_use]
    pub const fn runtime(&self) -> &AgentHealthHotspotLayerScore {
        &self.runtime
    }

    #[must_use]
    pub const fn total(&self) -> u32 {
        self.total
    }
}

fn weight_sum(scores: &AgentHealthHotspotScoresWire) -> u32 {
    scores
        .fan_in
        .weight_basis_points()
        .saturating_add(scores.fan_out.weight_basis_points())
        .saturating_add(scores.reverse_impact.weight_basis_points())
        .saturating_add(scores.git_churn.weight_basis_points())
        .saturating_add(scores.runtime.weight_basis_points())
}

fn core_weighted_total(scores: &HotspotFindingScores) -> u32 {
    hotspot_weighted_total([
        (
            scores.fan_in.normalized_basis_points,
            scores.fan_in.weight_basis_points,
        ),
        (
            scores.fan_out.normalized_basis_points,
            scores.fan_out.weight_basis_points,
        ),
        (
            scores.reverse_impact.normalized_basis_points,
            scores.reverse_impact.weight_basis_points,
        ),
        (
            scores.git_churn.normalized_basis_points,
            scores.git_churn.weight_basis_points,
        ),
        (
            scores.runtime.normalized_basis_points,
            scores.runtime.weight_basis_points,
        ),
    ])
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    hotspot_scores: Option<AgentHealthHotspotScores>,
    blockers: Vec<AgentHealthBlocker>,
    evidence: Vec<AgentHealthEvidenceRef>,
    remediations: Vec<AgentHealthRemediation>,
    suppressions: Vec<AgentHealthSuppression>,
    analyzer_version: AgentLabel,
    fingerprint: AgentId,
}

impl JsonSchema for AgentHealthFinding {
    fn schema_name() -> Cow<'static, str> {
        "AgentHealthFinding".into()
    }

    fn schema_id() -> Cow<'static, str> {
        concat!(module_path!(), "::AgentHealthFinding").into()
    }

    fn json_schema(generator: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "id": generator.subschema_for::<AgentId>(),
                "kind": generator.subschema_for::<AgentFindingKind>(),
                "severity": generator.subschema_for::<AgentHealthSeverity>(),
                "confidence": generator.subschema_for::<AgentHealthConfidence>(),
                "subject_id": generator.subschema_for::<AgentLabel>(),
                "subject_kind": generator.subschema_for::<AgentLabel>(),
                "location": generator.subschema_for::<Option<AgentHealthSourceLocation>>(),
                "profile_scope": generator.subschema_for::<Option<AgentId>>(),
                "reason": generator.subschema_for::<AgentPolicyText>(),
                "hotspot_scores": generator.subschema_for::<Option<AgentHealthHotspotScores>>(),
                "blockers": {
                    "type": "array",
                    "maxItems": 32,
                    "items": generator.subschema_for::<AgentHealthBlocker>()
                },
                "evidence": {
                    "type": "array",
                    "maxItems": 64,
                    "items": generator.subschema_for::<AgentHealthEvidenceRef>()
                },
                "remediations": {
                    "type": "array",
                    "maxItems": 8,
                    "items": generator.subschema_for::<AgentHealthRemediation>()
                },
                "suppressions": {
                    "type": "array",
                    "maxItems": 8,
                    "items": generator.subschema_for::<AgentHealthSuppression>()
                },
                "analyzer_version": generator.subschema_for::<AgentLabel>(),
                "fingerprint": generator.subschema_for::<AgentId>()
            },
            "required": [
                "id", "kind", "severity", "confidence", "subject_id", "subject_kind",
                "reason", "blockers", "evidence", "remediations", "suppressions",
                "analyzer_version", "fingerprint"
            ],
            "allOf": [{
                "if": {
                    "properties": {"kind": {"const": "hotspot"}},
                    "required": ["kind"]
                },
                "then": {
                    "required": ["hotspot_scores"],
                    "properties": {
                        "confidence": {"enum": ["indeterminate", "probable"]},
                        "hotspot_scores": generator.subschema_for::<AgentHealthHotspotScores>()
                    }
                },
                "else": {
                    "properties": {
                        "hotspot_scores": {"type": "null"}
                    }
                }
            }]
        })
    }
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
        let kind = AgentFindingKind::from_core(source.kind);
        let confidence = AgentHealthConfidence::from_core(source.confidence);
        let hotspot_scores = source
            .hotspot_scores
            .as_ref()
            .map(AgentHealthHotspotScores::try_from_core)
            .transpose()?;
        validate_hotspot_finding(kind, confidence, hotspot_scores.as_ref())?;
        if kind == AgentFindingKind::Hotspot && hotspot_scores.is_none() {
            return Err(ContractBuildError::AgentDtoValue);
        }
        Ok(Self {
            id: parse_id(&source.id)?,
            kind,
            severity: AgentHealthSeverity::from_core(source.severity),
            confidence,
            subject_id: parse_label(&source.subject_id)?,
            subject_kind: parse_label(&source.subject_kind)?,
            location,
            profile_scope: source.profile_scope.as_deref().map(parse_id).transpose()?,
            reason: parse_text(&source.reason)?,
            hotspot_scores,
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
    // Records emitted before Issue #440 did not carry structured scores (and
    // could still report `confirmed`). Keep that legacy shape readable on the
    // wire; new output projection uses `AgentHealthFinding::try_from_core`,
    // which requires scores for hotspots and never emits `confirmed`.
    #[serde(default)]
    hotspot_scores: Option<AgentHealthHotspotScores>,
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
        validate_hotspot_finding(wire.kind, wire.confidence, wire.hotspot_scores.as_ref())
            .map_err(D::Error::custom)?;
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
            hotspot_scores: wire.hotspot_scores,
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

fn validate_hotspot_finding(
    kind: AgentFindingKind,
    confidence: AgentHealthConfidence,
    hotspot_scores: Option<&AgentHealthHotspotScores>,
) -> Result<(), ContractBuildError> {
    if kind != AgentFindingKind::Hotspot && hotspot_scores.is_some() {
        return Err(ContractBuildError::AgentDtoValue);
    }
    // `confirmed` was emitted by the pre-Issue #440 hotspot wire format, which
    // had no structured score object. Keep that legacy input readable, but do
    // not accept the combination on a current structured hotspot record.
    if kind == AgentFindingKind::Hotspot
        && confidence == AgentHealthConfidence::Confirmed
        && hotspot_scores.is_some()
    {
        return Err(ContractBuildError::AgentDtoValue);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use depgraph_core::{
        FindingSuppression, HotspotFindingScores, HotspotLayerScore, SourceLocation,
    };
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
            hotspot_scores: None,
            blockers: Vec::new(),
            evidence: Vec::new(),
            remediations: Vec::new(),
            suppressions,
            analyzer_version: "1.0.0".to_owned(),
            fingerprint: "sha256:sample".to_owned(),
        }
    }

    fn hotspot_scores() -> HotspotFindingScores {
        HotspotFindingScores {
            fan_in: HotspotLayerScore {
                raw: 2,
                normalized_basis_points: 10_000,
                weight_basis_points: 2_500,
                available: true,
            },
            fan_out: HotspotLayerScore {
                raw: 1,
                normalized_basis_points: 5_000,
                weight_basis_points: 1_500,
                available: true,
            },
            reverse_impact: HotspotLayerScore {
                raw: 3,
                normalized_basis_points: 10_000,
                weight_basis_points: 2_500,
                available: true,
            },
            git_churn: HotspotLayerScore {
                raw: 0,
                normalized_basis_points: 0,
                weight_basis_points: 2_000,
                available: false,
            },
            runtime: HotspotLayerScore {
                raw: 0,
                normalized_basis_points: 0,
                weight_basis_points: 1_500,
                available: false,
            },
            total: 5_750,
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

    #[test]
    fn issue_440_health_finding_new_output_is_closed_but_legacy_wire_scores_are_optional() {
        let mut finding = finding_with_suppressions(Vec::new());
        finding.kind = FindingKind::Hotspot;
        finding.hotspot_scores = Some(hotspot_scores());
        let agent = AgentHealthFinding::try_from_core(&finding).expect("valid hotspot finding");
        let encoded = serde_json::to_value(&agent).expect("serialize hotspot finding");
        assert_eq!(
            encoded["hotspot_scores"]["fan_in"],
            json!({
                "raw": 2,
                "normalized_basis_points": 10_000,
                "weight_basis_points": 2_500,
                "available": true
            })
        );
        assert_eq!(encoded["hotspot_scores"]["total"], 5_750);
        assert_eq!(encoded["hotspot_scores"]["git_churn"]["available"], false);

        let round_trip: AgentHealthFinding =
            serde_json::from_value(encoded.clone()).expect("deserialize hotspot finding");
        assert_eq!(round_trip.id().as_str(), "finding:sample");
        assert!(
            serde_json::to_value(round_trip)
                .expect("re-serialize hotspot finding")
                .get("hotspot_scores")
                .is_some()
        );

        let mut legacy_wire = encoded.clone();
        legacy_wire
            .as_object_mut()
            .expect("finding object")
            .remove("hotspot_scores");
        assert!(
            serde_json::from_value::<AgentHealthFinding>(legacy_wire).is_ok(),
            "pre-Issue #440 wire findings may omit the additive scores field"
        );

        let mut legacy_null = encoded.clone();
        legacy_null["hotspot_scores"] = serde_json::Value::Null;
        assert!(
            serde_json::from_value::<AgentHealthFinding>(legacy_null).is_ok(),
            "pre-Issue #440 wire findings may carry a null additive scores field"
        );

        let mut legacy_confirmed = encoded.clone();
        legacy_confirmed["confidence"] = json!("confirmed");
        legacy_confirmed
            .as_object_mut()
            .expect("finding object")
            .remove("hotspot_scores");
        assert!(
            serde_json::from_value::<AgentHealthFinding>(legacy_confirmed).is_ok(),
            "legacy hotspot wire findings may retain their pre-Issue #440 confirmed confidence"
        );

        let mut legacy_confirmed_null = encoded.clone();
        legacy_confirmed_null["confidence"] = json!("confirmed");
        legacy_confirmed_null["hotspot_scores"] = serde_json::Value::Null;
        assert!(
            serde_json::from_value::<AgentHealthFinding>(legacy_confirmed_null).is_ok(),
            "legacy hotspot wire findings may retain confirmed confidence with null scores"
        );

        let mut current_confirmed =
            serde_json::to_value(&agent).expect("serialize hotspot finding");
        current_confirmed["confidence"] = json!("confirmed");
        assert!(
            serde_json::from_value::<AgentHealthFinding>(current_confirmed).is_err(),
            "current structured hotspot wire findings must not claim confirmed confidence"
        );

        let mut invalid = encoded;
        invalid["hotspot_scores"]["runtime"]["raw"] = json!(1);
        assert!(serde_json::from_value::<AgentHealthFinding>(invalid).is_err());

        let mut invalid = serde_json::to_value(&agent).expect("serialize hotspot finding");
        invalid["hotspot_scores"]["fan_in"]["weight_basis_points"] = json!(10_000);
        assert!(serde_json::from_value::<AgentHealthFinding>(invalid).is_err());

        let mut invalid = serde_json::to_value(&agent).expect("serialize hotspot finding");
        invalid["hotspot_scores"]["fan_in"]["unknown"] = json!(true);
        assert!(serde_json::from_value::<AgentHealthFinding>(invalid).is_err());

        let mut invalid = serde_json::to_value(&agent).expect("serialize hotspot finding");
        invalid["hotspot_scores"]["total"] = json!(5_751);
        assert!(serde_json::from_value::<AgentHealthFinding>(invalid).is_err());

        let mut invalid = serde_json::to_value(&agent).expect("serialize hotspot finding");
        invalid["kind"] = json!("unused-file");
        assert!(serde_json::from_value::<AgentHealthFinding>(invalid).is_err());

        let mut invalid = finding_with_suppressions(Vec::new());
        invalid.hotspot_scores = Some(hotspot_scores());
        assert_eq!(
            AgentHealthFinding::try_from_core(&invalid),
            Err(ContractBuildError::AgentDtoValue)
        );

        let mut invalid = finding_with_suppressions(Vec::new());
        invalid.kind = FindingKind::Hotspot;
        assert_eq!(
            AgentHealthFinding::try_from_core(&invalid),
            Err(ContractBuildError::AgentDtoValue)
        );

        let mut invalid = finding_with_suppressions(Vec::new());
        invalid.kind = FindingKind::Hotspot;
        invalid.confidence = Confidence::Confirmed;
        invalid.hotspot_scores = Some(hotspot_scores());
        assert_eq!(
            AgentHealthFinding::try_from_core(&invalid),
            Err(ContractBuildError::AgentDtoValue)
        );

        let mut invalid = finding_with_suppressions(Vec::new());
        invalid.kind = FindingKind::Hotspot;
        let mut scores = hotspot_scores();
        scores.total = 5_751;
        invalid.hotspot_scores = Some(scores);
        assert_eq!(
            AgentHealthFinding::try_from_core(&invalid),
            Err(ContractBuildError::AgentDtoValue)
        );
    }
}
