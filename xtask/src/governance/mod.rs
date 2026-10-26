//! Public OSS release governance checks used by `cargo xtask`.
//!
//! These modules evaluate public-readiness bundles, history and provenance
//! audits, migration rehearsals and GitHub settings snapshots. They used to
//! live in `depgraph-core`, but only xtask consumes them. The history,
//! provenance and migration-rehearsal evaluators have no xtask command yet;
//! they were moved unchanged together with their tests, so unused items are
//! allowed here instead of being deleted.

#![allow(dead_code, unused_imports)]

pub mod github_settings;
pub mod public_history_audit;
pub mod public_migration_rehearsal;
pub mod public_provenance_audit;
pub mod public_readiness;

pub use github_settings::{
    GITHUB_SETTINGS_DESIRED_SCHEMA_VERSION, GITHUB_SETTINGS_EVALUATION_SCHEMA_VERSION,
    GITHUB_SETTINGS_REPOSITORY, GITHUB_SETTINGS_VERIFIER_MODE, GITHUB_SETTINGS_VERIFIER_NAME,
    GITHUB_SETTINGS_VERIFIER_VERSION, GitHubRedactedPrincipal, GitHubRedactedSurface,
    GitHubRequiredCheck, GitHubRuleset, GitHubRulesetEnforcement, GitHubRulesetTarget,
    GitHubSecuritySettings, GitHubSettingsApiSnapshot, GitHubSettingsCollectionStatus,
    GitHubSettingsDrift, GitHubSettingsDriftReason, GitHubSettingsEvaluation, GitHubSettingsState,
    canonical_github_settings_digest, evaluate_github_settings, github_settings_verifier_identity,
    parse_github_settings_desired,
};
pub use public_history_audit::{
    FinalizedPublicHistoryAudit, MAX_PUBLIC_AUDIT_REFS, MAX_PUBLIC_AUDIT_SOURCE_BYTES,
    MAX_PUBLIC_AUDIT_SOURCES, MAX_PUBLIC_AUDIT_TOTAL_BYTES, PUBLIC_AUDIT_SOURCE_KINDS,
    PUBLIC_HISTORY_AUDIT_FINAL_SCHEMA_VERSION, PUBLIC_HISTORY_AUDIT_SCHEMA_VERSION,
    PUBLIC_SECRET_SCANNER_NAME, PUBLIC_SECRET_SCANNER_VERSION, PublicAuditCredentialAction,
    PublicAuditFinding, PublicAuditFindingState, PublicAuditPurgeAction, PublicAuditRefInput,
    PublicAuditRemediationAttestation, PublicAuditSourceInput, PublicAuditSourceKind,
    PublicHistoryAuditInput, PublicHistoryAuditReport, audit_public_history,
    finalize_public_history_audit, public_audit_remediation_attestation_digest,
    public_secret_scanner_identity,
};
pub use public_migration_rehearsal::{
    AnonymousPublicSurfaceSmoke, PUBLIC_MIGRATION_CHECKPOINT_VERIFIER_NAME,
    PUBLIC_MIGRATION_CHECKPOINT_VERIFIER_VERSION, PUBLIC_MIGRATION_PHASES,
    PUBLIC_MIGRATION_PRODUCTION_REPOSITORY, PUBLIC_MIGRATION_REHEARSAL_INPUT_SCHEMA_VERSION,
    PUBLIC_MIGRATION_REHEARSAL_MODE, PUBLIC_MIGRATION_REHEARSAL_REPORT_SCHEMA_VERSION,
    PublicMigrationCheckpointEvidence, PublicMigrationCleanup, PublicMigrationContainment,
    PublicMigrationEvidence, PublicMigrationEvidenceKind, PublicMigrationNoGoReason,
    PublicMigrationPhase, PublicMigrationRehearsalInput, PublicMigrationRehearsalReport,
    PublicMigrationStep, PublicMigrationStepOutcome, PublicMigrationWriteDisposition,
    canonical_public_migration_rehearsal_digest, evaluate_public_migration_rehearsal,
    public_migration_checkpoint_evidence_digest, public_migration_checkpoint_verifier_identity,
};
pub use public_provenance_audit::{
    MAX_PUBLIC_PROVENANCE_ASSETS, MAX_PUBLIC_PROVENANCE_DEPENDENCIES, PUBLIC_LICENSE_POLICY_NAME,
    PUBLIC_LICENSE_POLICY_VERSION, PUBLIC_PROVENANCE_EVALUATION_SCHEMA_VERSION,
    PUBLIC_PROVENANCE_REVIEW_SCHEMA_VERSION, PUBLIC_RELEASE_TARGETS,
    PUBLIC_VULNERABILITY_SCANNER_NAME, PUBLIC_VULNERABILITY_SCANNER_VERSION, PublicAssetAuditInput,
    PublicAssetEvidence, PublicAssetKind, PublicDependencyAuditInput, PublicDependencyEcosystem,
    PublicDependencyEvidence, PublicLicensePolicyState, PublicProvenanceAuditInput,
    PublicProvenanceEvaluation, PublicProvenanceExpectedState, PublicProvenanceFinding,
    PublicProvenanceFindingReason, PublicProvenanceRejectionReason, PublicProvenanceReviewPackage,
    PublicProvenanceState, PublicTargetAuditInput, PublicTargetEvidence,
    PublicVulnerabilitySeverity, build_public_provenance_review_package,
    evaluate_public_provenance_review, public_license_policy_identity,
    public_vulnerability_scanner_identity,
};
pub use public_readiness::{
    PUBLIC_READINESS_EVIDENCE_SCHEMA_VERSION, PUBLIC_READINESS_FINAL_APPROVAL_ROLES,
    PUBLIC_READINESS_GATE_IDS, PUBLIC_READINESS_REPOSITORY, PUBLIC_READINESS_ROLES,
    PUBLIC_READINESS_SCHEMA_VERSION, PUBLIC_READINESS_VERIFIER_MODE, PublicReadinessApproval,
    PublicReadinessBundle, PublicReadinessDecision, PublicReadinessEvaluation,
    PublicReadinessEvidence, PublicReadinessEvidenceManifest, PublicReadinessExpectedState,
    PublicReadinessFindingSummary, PublicReadinessGate, PublicReadinessRecord,
    PublicReadinessRejectionReason, PublicReadinessToolIdentity, canonical_public_readiness_digest,
    evaluate_public_readiness, public_readiness_approval_statement_digest,
    public_readiness_evidence_digest, public_readiness_evidence_input_digest,
};
