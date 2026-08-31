pub mod audit;
mod budget;
pub mod contract;
pub mod dependency;
pub mod hotspot;
pub mod surface;
pub mod unused;

pub use audit::{
    AuditAnalysisOptions, AuditComparability, DEFAULT_WIDE_BLAST_RADIUS_MIN_ADDITIONAL_NODES,
    HealthAuditInputIdentity, analyze_changed_code, analyze_changed_code_cancellable,
    analyze_changed_code_with_boundary_ids_cancellable, canonical_cycle_rotation,
};
pub use budget::HealthAnalysisError;
pub use contract::{
    BASIS_POINTS_MAX, BaselineFindingRecord, BaselineTransition, BlockerKind, CollectionIdentity,
    Confidence, FindingBlocker, FindingEvidenceRef, FindingIdentity, FindingKind, FindingKindScope,
    FindingSuppression, HEALTH_ANALYZER_VERSION, HEALTH_FINDING_CONTRACT_VERSION, HealthFinding,
    HealthFindingDetail, HealthGateConfig, HealthGateDecision, Remediation, Severity,
    SourceLocation, actionable_rank, apply_confidence_guards, classify_baseline_transition,
    collection_digest, evaluate_health_gate, finding_fingerprint, finding_id, finish_finding,
    rank_normalize_basis_points,
};
pub use dependency::{ManifestIdentity, analyze_dependencies, analyze_dependencies_cancellable};
pub use hotspot::{
    DEFAULT_HOTSPOT_WEIGHTS, HotspotAnalysisError, HotspotFindingScores, HotspotLayer,
    HotspotLayerAvailability, HotspotLayerScore, HotspotLayerScores, HotspotScores, HotspotWeights,
    hotspot_weighted_total, score_hotspots, score_hotspots_cancellable,
};
pub use surface::{SurfaceClassification, SurfaceRole, classify_surface};
pub use unused::{analyze_unused, analyze_unused_cancellable};

/// Return the canonical policy identity bound to a production scan.
///
/// Health audit comparison must use this persisted value rather than reading
/// the repository configuration again later.  The policy implementation owns
/// normalization of set-like rules, suppressions, selectors, and conditions;
/// this helper only applies the stable namespace used by the store contract.
pub fn health_policy_config_digest(policy: &crate::policy::PolicyConfig) -> anyhow::Result<String> {
    let identity = policy.normalized_identity()?;
    Ok(depgraph_protocol::stable_id_from_value(
        "policy-config",
        &identity,
    ))
}
