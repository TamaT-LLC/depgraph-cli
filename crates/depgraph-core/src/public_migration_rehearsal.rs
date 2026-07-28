use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

use crate::{PublicReadinessDecision, canonical_public_readiness_digest};

pub const PUBLIC_MIGRATION_REHEARSAL_INPUT_SCHEMA_VERSION: &str =
    "public-migration-rehearsal-input-v1";
pub const PUBLIC_MIGRATION_REHEARSAL_REPORT_SCHEMA_VERSION: &str =
    "public-migration-rehearsal-report-v1";
pub const PUBLIC_MIGRATION_REHEARSAL_MODE: &str = "temporary-repository-no-production-actuator";
pub const PUBLIC_MIGRATION_PRODUCTION_REPOSITORY: &str = "TamaT-LLC/depgraph-cli";

pub const PUBLIC_MIGRATION_PHASES: [PublicMigrationPhase; 10] = [
    PublicMigrationPhase::VerifyTemporaryTarget,
    PublicMigrationPhase::CaptureBackupAndSettings,
    PublicMigrationPhase::FreezeWrites,
    PublicMigrationPhase::ChangeVisibility,
    PublicMigrationPhase::RestoreRulesets,
    PublicMigrationPhase::EnableSecurity,
    PublicMigrationPhase::VerifyDesiredSettings,
    PublicMigrationPhase::RunAnonymousSmoke,
    PublicMigrationPhase::ReopenWrites,
    PublicMigrationPhase::CleanupTemporaryRepository,
];

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicMigrationPhase {
    VerifyTemporaryTarget,
    CaptureBackupAndSettings,
    FreezeWrites,
    ChangeVisibility,
    RestoreRulesets,
    EnableSecurity,
    VerifyDesiredSettings,
    RunAnonymousSmoke,
    ReopenWrites,
    CleanupTemporaryRepository,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicMigrationStepOutcome {
    Pass,
    Fail,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublicMigrationStep {
    pub phase: PublicMigrationPhase,
    pub outcome: PublicMigrationStepOutcome,
    pub evidence_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AnonymousPublicSurfaceSmoke {
    pub clone: bool,
    pub source_archive: bool,
    pub readme_and_docs: bool,
    pub community_links: bool,
    pub issue_templates: bool,
    pub actions: bool,
    pub release: bool,
    pub package_download: bool,
    pub evidence_digest: String,
}

impl AnonymousPublicSurfaceSmoke {
    fn all_pass(&self) -> bool {
        self.clone
            && self.source_archive
            && self.readme_and_docs
            && self.community_links
            && self.issue_templates
            && self.actions
            && self.release
            && self.package_download
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublicMigrationTargetAttestation {
    pub production_repository_digest: String,
    pub temporary_repository_digest: String,
    pub production_plan_features_digest: String,
    pub temporary_plan_features_digest: String,
    pub producer_identity: String,
    pub approver_identity: String,
    pub attestation_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublicMigrationRehearsalInput {
    pub schema_version: String,
    pub production_repository: String,
    pub temporary_repository: String,
    pub target_attestation: PublicMigrationTargetAttestation,
    pub production_plan_features_digest: String,
    pub temporary_plan_features_digest: String,
    pub production_visibility_unchanged: bool,
    pub steps: Vec<PublicMigrationStep>,
    pub anonymous_smoke: AnonymousPublicSurfaceSmoke,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicMigrationNoGoReason {
    ActivityAfterNoGo,
    AnonymousSmokeFailed,
    CleanupIncomplete,
    PlanFeaturesMismatch,
    ProductionTargetRejected,
    ProductionVisibilityChanged,
    StepFailed,
    StepMissing,
    StepOutOfOrder,
    TemporaryRepositoryUnattested,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicMigrationWriteDisposition {
    Frozen,
    Reopened,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicMigrationContainment {
    Contained,
    Released,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicMigrationCleanup {
    Completed,
    Required,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublicMigrationEvidence {
    pub phase: PublicMigrationPhase,
    pub evidence_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublicMigrationRehearsalReport {
    pub schema_version: String,
    pub harness_mode: String,
    pub temporary_repository_digest: String,
    pub plan_features_digest: String,
    pub phase_log: Vec<PublicMigrationPhase>,
    pub evidence: Vec<PublicMigrationEvidence>,
    pub anonymous_smoke_digest: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub no_go_phase: Option<PublicMigrationPhase>,
    pub no_go_reasons: Vec<PublicMigrationNoGoReason>,
    pub writes: PublicMigrationWriteDisposition,
    pub containment: PublicMigrationContainment,
    pub cleanup: PublicMigrationCleanup,
    pub production_visibility_unchanged: bool,
    pub decision: PublicReadinessDecision,
}

pub fn evaluate_public_migration_rehearsal(
    input: &PublicMigrationRehearsalInput,
) -> Result<PublicMigrationRehearsalReport> {
    validate_input_contract(input)?;

    let mut reasons = Vec::new();
    let mut no_go_phase = None;
    let mut stopped = false;
    if input.production_repository != PUBLIC_MIGRATION_PRODUCTION_REPOSITORY
        || input
            .temporary_repository
            .eq_ignore_ascii_case(&input.production_repository)
    {
        reject_at(
            &mut reasons,
            &mut no_go_phase,
            &mut stopped,
            PublicMigrationPhase::VerifyTemporaryTarget,
            PublicMigrationNoGoReason::ProductionTargetRejected,
        );
    }
    if !target_attestation_matches(input)? {
        reject_at(
            &mut reasons,
            &mut no_go_phase,
            &mut stopped,
            PublicMigrationPhase::VerifyTemporaryTarget,
            PublicMigrationNoGoReason::TemporaryRepositoryUnattested,
        );
    }
    if input.production_plan_features_digest != input.temporary_plan_features_digest {
        reject_at(
            &mut reasons,
            &mut no_go_phase,
            &mut stopped,
            PublicMigrationPhase::VerifyTemporaryTarget,
            PublicMigrationNoGoReason::PlanFeaturesMismatch,
        );
    }
    if !input.production_visibility_unchanged {
        reject_at(
            &mut reasons,
            &mut no_go_phase,
            &mut stopped,
            PublicMigrationPhase::ChangeVisibility,
            PublicMigrationNoGoReason::ProductionVisibilityChanged,
        );
    }

    let mut next_phase = 0;
    let mut writes_reopened = false;
    let mut cleanup_completed = false;
    let mut containment_cleanup_seen = false;
    for step in &input.steps {
        if stopped {
            if step.phase == PublicMigrationPhase::CleanupTemporaryRepository
                && step.outcome == PublicMigrationStepOutcome::Pass
                && !containment_cleanup_seen
            {
                cleanup_completed = true;
                containment_cleanup_seen = true;
            } else {
                reasons.push(PublicMigrationNoGoReason::ActivityAfterNoGo);
            }
            continue;
        }

        let Some(expected_phase) = PUBLIC_MIGRATION_PHASES.get(next_phase).copied() else {
            reject_at(
                &mut reasons,
                &mut no_go_phase,
                &mut stopped,
                PublicMigrationPhase::CleanupTemporaryRepository,
                PublicMigrationNoGoReason::StepOutOfOrder,
            );
            continue;
        };
        if step.phase != expected_phase {
            reject_at(
                &mut reasons,
                &mut no_go_phase,
                &mut stopped,
                expected_phase,
                PublicMigrationNoGoReason::StepOutOfOrder,
            );
            continue;
        }
        if step.outcome == PublicMigrationStepOutcome::Fail {
            reject_at(
                &mut reasons,
                &mut no_go_phase,
                &mut stopped,
                step.phase,
                PublicMigrationNoGoReason::StepFailed,
            );
            continue;
        }
        if step.phase == PublicMigrationPhase::RunAnonymousSmoke
            && !input.anonymous_smoke.all_pass()
        {
            reject_at(
                &mut reasons,
                &mut no_go_phase,
                &mut stopped,
                step.phase,
                PublicMigrationNoGoReason::AnonymousSmokeFailed,
            );
            continue;
        }
        if step.phase == PublicMigrationPhase::ReopenWrites {
            writes_reopened = true;
        }
        if step.phase == PublicMigrationPhase::CleanupTemporaryRepository {
            cleanup_completed = true;
        }
        next_phase += 1;
    }

    if !stopped && next_phase != PUBLIC_MIGRATION_PHASES.len() {
        reject_at(
            &mut reasons,
            &mut no_go_phase,
            &mut stopped,
            PUBLIC_MIGRATION_PHASES[next_phase],
            PublicMigrationNoGoReason::StepMissing,
        );
    }
    if !cleanup_completed {
        reasons.push(PublicMigrationNoGoReason::CleanupIncomplete);
    }
    reasons.sort();
    reasons.dedup();

    let decision = if reasons.is_empty() {
        PublicReadinessDecision::Allow
    } else {
        PublicReadinessDecision::Reject
    };
    let allow = decision == PublicReadinessDecision::Allow;
    Ok(PublicMigrationRehearsalReport {
        schema_version: PUBLIC_MIGRATION_REHEARSAL_REPORT_SCHEMA_VERSION.into(),
        harness_mode: PUBLIC_MIGRATION_REHEARSAL_MODE.into(),
        temporary_repository_digest: canonical_public_readiness_digest(
            &input.temporary_repository,
        )?,
        plan_features_digest: input.temporary_plan_features_digest.clone(),
        phase_log: input.steps.iter().map(|step| step.phase).collect(),
        evidence: input
            .steps
            .iter()
            .map(|step| PublicMigrationEvidence {
                phase: step.phase,
                evidence_digest: step.evidence_digest.clone(),
            })
            .collect(),
        anonymous_smoke_digest: input.anonymous_smoke.evidence_digest.clone(),
        no_go_phase,
        no_go_reasons: reasons,
        writes: if allow && writes_reopened {
            PublicMigrationWriteDisposition::Reopened
        } else {
            PublicMigrationWriteDisposition::Frozen
        },
        containment: if allow {
            PublicMigrationContainment::Released
        } else {
            PublicMigrationContainment::Contained
        },
        cleanup: if cleanup_completed {
            PublicMigrationCleanup::Completed
        } else {
            PublicMigrationCleanup::Required
        },
        production_visibility_unchanged: input.production_visibility_unchanged,
        decision,
    })
}

pub fn canonical_public_migration_rehearsal_digest(
    report: &PublicMigrationRehearsalReport,
) -> Result<String> {
    canonical_public_readiness_digest(report)
}

pub fn public_migration_target_attestation_digest(
    attestation: &PublicMigrationTargetAttestation,
) -> Result<String> {
    let mut value = serde_json::to_value(attestation)?;
    value["attestation_digest"] = serde_json::Value::String(String::new());
    canonical_public_readiness_digest(&value)
}

fn validate_input_contract(input: &PublicMigrationRehearsalInput) -> Result<()> {
    if input.schema_version != PUBLIC_MIGRATION_REHEARSAL_INPUT_SCHEMA_VERSION
        || !valid_repository_identifier(&input.production_repository)
        || !valid_repository_identifier(&input.temporary_repository)
        || input.steps.len() > 32
        || !is_digest(&input.production_plan_features_digest)
        || !is_digest(&input.temporary_plan_features_digest)
        || !is_digest(&input.anonymous_smoke.evidence_digest)
        || input
            .steps
            .iter()
            .any(|step| !is_digest(&step.evidence_digest))
    {
        bail!("public migration rehearsal input is malformed or exceeds a bound");
    }
    Ok(())
}

fn target_attestation_matches(input: &PublicMigrationRehearsalInput) -> Result<bool> {
    let attestation = &input.target_attestation;
    Ok(is_digest(&attestation.production_repository_digest)
        && is_digest(&attestation.temporary_repository_digest)
        && is_digest(&attestation.production_plan_features_digest)
        && is_digest(&attestation.temporary_plan_features_digest)
        && is_digest(&attestation.attestation_digest)
        && valid_team_identity(&attestation.producer_identity)
        && valid_team_identity(&attestation.approver_identity)
        && attestation.producer_identity != attestation.approver_identity
        && attestation.production_repository_digest
            == canonical_public_readiness_digest(&input.production_repository)?
        && attestation.temporary_repository_digest
            == canonical_public_readiness_digest(&input.temporary_repository)?
        && attestation.production_plan_features_digest == input.production_plan_features_digest
        && attestation.temporary_plan_features_digest == input.temporary_plan_features_digest
        && public_migration_target_attestation_digest(attestation)?
            == attestation.attestation_digest)
}

fn reject_at(
    reasons: &mut Vec<PublicMigrationNoGoReason>,
    no_go_phase: &mut Option<PublicMigrationPhase>,
    stopped: &mut bool,
    phase: PublicMigrationPhase,
    reason: PublicMigrationNoGoReason,
) {
    if no_go_phase.is_none() {
        *no_go_phase = Some(phase);
    }
    reasons.push(reason);
    *stopped = true;
}

fn valid_repository_identifier(value: &str) -> bool {
    let Some((owner, repository)) = value.split_once('/') else {
        return false;
    };
    !repository.contains('/') && valid_token(owner) && valid_token(repository)
}

fn valid_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn valid_team_identity(value: &str) -> bool {
    value.strip_prefix("team:").is_some_and(valid_token)
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(label: &str) -> String {
        use sha2::{Digest as _, Sha256};
        hex::encode(Sha256::digest(label.as_bytes()))
    }

    fn successful_input() -> PublicMigrationRehearsalInput {
        let plan_digest = digest("github-plan-and-features");
        let production_repository = PUBLIC_MIGRATION_PRODUCTION_REPOSITORY.to_string();
        let temporary_repository = "TamaT-LLC/depgraph-public-rehearsal-20260726".to_string();
        let mut target_attestation = PublicMigrationTargetAttestation {
            production_repository_digest: canonical_public_readiness_digest(&production_repository)
                .unwrap(),
            temporary_repository_digest: canonical_public_readiness_digest(&temporary_repository)
                .unwrap(),
            production_plan_features_digest: plan_digest.clone(),
            temporary_plan_features_digest: plan_digest.clone(),
            producer_identity: "team:repository-administrators".into(),
            approver_identity: "team:security-reviewers".into(),
            attestation_digest: String::new(),
        };
        target_attestation.attestation_digest =
            public_migration_target_attestation_digest(&target_attestation).unwrap();
        PublicMigrationRehearsalInput {
            schema_version: PUBLIC_MIGRATION_REHEARSAL_INPUT_SCHEMA_VERSION.into(),
            production_repository,
            temporary_repository,
            target_attestation,
            production_plan_features_digest: plan_digest.clone(),
            temporary_plan_features_digest: plan_digest,
            production_visibility_unchanged: true,
            steps: PUBLIC_MIGRATION_PHASES
                .iter()
                .map(|phase| PublicMigrationStep {
                    phase: *phase,
                    outcome: PublicMigrationStepOutcome::Pass,
                    evidence_digest: digest(&format!("{phase:?}")),
                })
                .collect(),
            anonymous_smoke: AnonymousPublicSurfaceSmoke {
                clone: true,
                source_archive: true,
                readme_and_docs: true,
                community_links: true,
                issue_templates: true,
                actions: true,
                release: true,
                package_download: true,
                evidence_digest: digest("anonymous-smoke"),
            },
        }
    }

    #[test]
    fn successful_rehearsal_is_deterministic_and_reopens_only_after_all_verification() {
        let input = successful_input();
        let first = evaluate_public_migration_rehearsal(&input).unwrap();
        let second = evaluate_public_migration_rehearsal(&input).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.decision, PublicReadinessDecision::Allow);
        assert_eq!(first.phase_log, PUBLIC_MIGRATION_PHASES);
        assert_eq!(first.writes, PublicMigrationWriteDisposition::Reopened);
        assert_eq!(first.containment, PublicMigrationContainment::Released);
        assert_eq!(first.cleanup, PublicMigrationCleanup::Completed);
        assert_eq!(
            canonical_public_migration_rehearsal_digest(&first).unwrap(),
            canonical_public_migration_rehearsal_digest(&second).unwrap()
        );
    }

    #[test]
    fn settings_failure_keeps_writes_frozen_and_allows_only_containment_cleanup() {
        let mut input = successful_input();
        input.steps = input
            .steps
            .into_iter()
            .take(7)
            .map(|mut step| {
                if step.phase == PublicMigrationPhase::VerifyDesiredSettings {
                    step.outcome = PublicMigrationStepOutcome::Fail;
                }
                step
            })
            .chain(std::iter::once(PublicMigrationStep {
                phase: PublicMigrationPhase::CleanupTemporaryRepository,
                outcome: PublicMigrationStepOutcome::Pass,
                evidence_digest: digest("containment-cleanup"),
            }))
            .collect();
        let report = evaluate_public_migration_rehearsal(&input).unwrap();
        assert_eq!(report.decision, PublicReadinessDecision::Reject);
        assert_eq!(
            report.no_go_phase,
            Some(PublicMigrationPhase::VerifyDesiredSettings)
        );
        assert_eq!(report.writes, PublicMigrationWriteDisposition::Frozen);
        assert_eq!(report.containment, PublicMigrationContainment::Contained);
        assert_eq!(report.cleanup, PublicMigrationCleanup::Completed);
        assert!(
            report
                .no_go_reasons
                .contains(&PublicMigrationNoGoReason::StepFailed)
        );
        assert!(
            !report
                .no_go_reasons
                .contains(&PublicMigrationNoGoReason::ActivityAfterNoGo)
        );
    }

    #[test]
    fn anonymous_surface_failure_is_a_deterministic_no_go_before_write_reopen() {
        let mut input = successful_input();
        input.anonymous_smoke.package_download = false;
        let report = evaluate_public_migration_rehearsal(&input).unwrap();
        assert_eq!(report.decision, PublicReadinessDecision::Reject);
        assert_eq!(
            report.no_go_phase,
            Some(PublicMigrationPhase::RunAnonymousSmoke)
        );
        assert_eq!(report.writes, PublicMigrationWriteDisposition::Frozen);
        assert!(
            report
                .no_go_reasons
                .contains(&PublicMigrationNoGoReason::AnonymousSmokeFailed)
        );
        assert!(
            report
                .no_go_reasons
                .contains(&PublicMigrationNoGoReason::ActivityAfterNoGo)
        );
    }

    #[test]
    fn production_target_and_visibility_mutation_fail_closed() {
        let mut input = successful_input();
        input.temporary_repository = "tamat-llc/DEPGRAPH-CLI".into();
        input.production_visibility_unchanged = false;
        let report = evaluate_public_migration_rehearsal(&input).unwrap();
        assert_eq!(report.decision, PublicReadinessDecision::Reject);
        assert_eq!(report.writes, PublicMigrationWriteDisposition::Frozen);
        assert!(
            report
                .no_go_reasons
                .contains(&PublicMigrationNoGoReason::ProductionTargetRejected)
        );
        assert!(
            report
                .no_go_reasons
                .contains(&PublicMigrationNoGoReason::ProductionVisibilityChanged)
        );

        let mut invalid = successful_input();
        invalid.temporary_repository = "TamaT-LLC/depgraph:rehearsal".into();
        assert!(evaluate_public_migration_rehearsal(&invalid).is_err());
    }

    #[test]
    fn target_attestation_is_identity_bound_and_requires_independent_approval() {
        let mut arbitrary = successful_input();
        arbitrary.target_attestation.attestation_digest = digest("unrelated-attestation");
        let report = evaluate_public_migration_rehearsal(&arbitrary).unwrap();
        assert_eq!(report.decision, PublicReadinessDecision::Reject);
        assert!(
            report
                .no_go_reasons
                .contains(&PublicMigrationNoGoReason::TemporaryRepositoryUnattested)
        );

        let mut reused = successful_input();
        reused.temporary_repository = "TamaT-LLC/another-public-rehearsal".into();
        let report = evaluate_public_migration_rehearsal(&reused).unwrap();
        assert_eq!(report.decision, PublicReadinessDecision::Reject);
        assert!(
            report
                .no_go_reasons
                .contains(&PublicMigrationNoGoReason::TemporaryRepositoryUnattested)
        );

        let mut self_approved = successful_input();
        self_approved.target_attestation.approver_identity =
            self_approved.target_attestation.producer_identity.clone();
        self_approved.target_attestation.attestation_digest =
            public_migration_target_attestation_digest(&self_approved.target_attestation).unwrap();
        let report = evaluate_public_migration_rehearsal(&self_approved).unwrap();
        assert_eq!(report.decision, PublicReadinessDecision::Reject);
        assert!(
            report
                .no_go_reasons
                .contains(&PublicMigrationNoGoReason::TemporaryRepositoryUnattested)
        );
    }

    #[test]
    fn out_of_order_or_duplicate_activity_stops_at_one_deterministic_no_go() {
        let mut input = successful_input();
        input.steps.swap(1, 2);
        input.steps.push(PublicMigrationStep {
            phase: PublicMigrationPhase::CleanupTemporaryRepository,
            outcome: PublicMigrationStepOutcome::Pass,
            evidence_digest: digest("duplicate-cleanup"),
        });
        let report = evaluate_public_migration_rehearsal(&input).unwrap();
        assert_eq!(
            report.no_go_phase,
            Some(PublicMigrationPhase::CaptureBackupAndSettings)
        );
        assert!(
            report
                .no_go_reasons
                .contains(&PublicMigrationNoGoReason::StepOutOfOrder)
        );
        assert!(
            report
                .no_go_reasons
                .contains(&PublicMigrationNoGoReason::ActivityAfterNoGo)
        );
        assert_eq!(report.writes, PublicMigrationWriteDisposition::Frozen);
    }

    #[test]
    fn report_preserves_only_redacted_evidence_and_rejects_unknown_secret_fields() {
        let input = successful_input();
        let report = evaluate_public_migration_rehearsal(&input).unwrap();
        let rendered = serde_json::to_string(&report).unwrap();
        assert!(!rendered.contains(&input.temporary_repository));
        assert!(!rendered.contains("token"));
        assert_eq!(report.evidence.len(), PUBLIC_MIGRATION_PHASES.len());

        let mut value = serde_json::to_value(input).unwrap();
        let schema: serde_json::Value = serde_json::from_slice(include_bytes!(
            "../../../schemas/public-migration-rehearsal-input-v1.schema.json"
        ))
        .unwrap();
        assert!(jsonschema::validator_for(&schema).unwrap().is_valid(&value));
        value["access_token"] = serde_json::json!("must-never-exist");
        assert!(!jsonschema::validator_for(&schema).unwrap().is_valid(&value));
        assert!(serde_json::from_value::<PublicMigrationRehearsalInput>(value).is_err());
    }
}
