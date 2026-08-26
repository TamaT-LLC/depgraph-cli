pub mod audit;
mod budget;
pub mod contract;
pub mod dependency;
pub mod hotspot;
pub mod surface;
pub mod unused;

pub use audit::{
    AuditComparability, HealthAuditInputIdentity, analyze_changed_code,
    analyze_changed_code_cancellable, canonical_cycle_rotation,
};
pub use budget::HealthAnalysisError;
pub use contract::{
    BaselineFindingRecord, BaselineTransition, BlockerKind, CollectionIdentity, Confidence,
    FindingBlocker, FindingEvidenceRef, FindingIdentity, FindingKind, FindingKindScope,
    FindingSuppression, HEALTH_ANALYZER_VERSION, HEALTH_FINDING_CONTRACT_VERSION, HealthFinding,
    HealthFindingDetail, HealthGateConfig, HealthGateDecision, Remediation, Severity,
    SourceLocation, actionable_rank, apply_confidence_guards, classify_baseline_transition,
    collection_digest, evaluate_health_gate, finding_fingerprint, finding_id, finish_finding,
    rank_normalize_basis_points,
};
pub use dependency::{ManifestIdentity, analyze_dependencies, analyze_dependencies_cancellable};
pub use hotspot::{
    DEFAULT_HOTSPOT_WEIGHTS, HotspotAnalysisError, HotspotLayer, HotspotLayerAvailability,
    HotspotLayerScores, HotspotWeights, score_hotspots, score_hotspots_cancellable,
};
pub use surface::{SurfaceClassification, SurfaceRole, classify_surface};
pub use unused::{analyze_unused, analyze_unused_cancellable};
