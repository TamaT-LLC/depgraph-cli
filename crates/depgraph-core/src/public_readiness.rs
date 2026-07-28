use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, anyhow};
use chrono::DateTime;
use depgraph_protocol::canonical_json;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const PUBLIC_READINESS_SCHEMA_VERSION: &str = "public-readiness-v1";
pub const PUBLIC_READINESS_EVIDENCE_SCHEMA_VERSION: &str = "public-readiness-evidence-v1";
pub const PUBLIC_READINESS_REPOSITORY: &str = "TamaT-LLC/depgraph-cli";
pub const PUBLIC_READINESS_VERIFIER_MODE: &str = "evidence-only-no-visibility-actuator";

pub const PUBLIC_READINESS_GATE_IDS: [&str; 9] = [
    "candidate-and-surface",
    "governance-and-community",
    "history-and-secrets",
    "incident-readiness",
    "legal-and-provenance",
    "migration-dry-run",
    "release-and-support",
    "repository-controls",
    "security-and-disclosure",
];

pub const PUBLIC_READINESS_ROLES: [&str; 7] = [
    "independent-code-reviewer",
    "legal-provenance-reviewer",
    "release-maintainer",
    "repository-administrator",
    "security-maintainer",
    "support-triage-maintainer",
    "tamat-llc-organization-owner",
];

pub const PUBLIC_READINESS_FINAL_APPROVAL_ROLES: [&str; 4] = [
    "legal-provenance-reviewer",
    "release-maintainer",
    "security-maintainer",
    "tamat-llc-organization-owner",
];

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicReadinessDecision {
    Allow,
    Reject,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublicReadinessGate {
    pub id: String,
    pub decision: PublicReadinessDecision,
    pub evidence_digest: String,
    pub producer_role: String,
    pub producer_identity: String,
    pub approver_role: String,
    pub approver_identity: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublicReadinessApproval {
    pub role: String,
    pub identity: String,
    pub approved_at: String,
    pub statement_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublicReadinessRecord {
    pub schema_version: String,
    pub repository: String,
    pub candidate_commit: String,
    pub audited_refs_digest: String,
    pub github_settings_digest: String,
    pub governance_tree_digest: String,
    pub release_gate_digest: String,
    pub evidence_manifest_digest: String,
    pub gates: Vec<PublicReadinessGate>,
    pub decision: PublicReadinessDecision,
    pub decided_at: String,
    pub accountable_role: String,
    pub approvals: Vec<PublicReadinessApproval>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublicReadinessToolIdentity {
    pub name: String,
    pub version: String,
    pub acquisition_digest: String,
    pub configuration_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublicReadinessFindingSummary {
    pub resolved: u32,
    pub unresolved: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublicReadinessEvidence {
    pub gate_id: String,
    pub evidence_digest: String,
    pub input_digest: String,
    pub started_at: String,
    pub ended_at: String,
    pub producer_role: String,
    pub producer_identity: String,
    pub approver_role: String,
    pub approver_identity: String,
    pub tool: PublicReadinessToolIdentity,
    pub findings: PublicReadinessFindingSummary,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublicReadinessEvidenceManifest {
    pub schema_version: String,
    pub repository: String,
    pub candidate_commit: String,
    pub audited_refs_digest: String,
    pub github_settings_digest: String,
    pub governance_tree_digest: String,
    pub release_gate_digest: String,
    pub generated_at: String,
    pub evidence: Vec<PublicReadinessEvidence>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublicReadinessBundle {
    pub record: PublicReadinessRecord,
    pub evidence_manifest: PublicReadinessEvidenceManifest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicReadinessExpectedState {
    pub repository: String,
    pub candidate_commit: String,
    pub audited_refs_digest: String,
    pub github_settings_digest: String,
    pub governance_tree_digest: String,
    pub release_gate_digest: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicReadinessRejectionReason {
    ApprovalStatementMismatch,
    CandidateStateStale,
    EvidenceDigestMismatch,
    EvidenceManifestTampered,
    EvidenceMismatch,
    GateNotAllowed,
    InvalidEvidenceManifestContract,
    InvalidOrSelfApproval,
    InvalidRecordContract,
    MissingFinalApproval,
    MissingOrOutOfOrderGate,
    RecordDeclaresReject,
    SensitiveValueRejected,
    UnresolvedFinding,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublicReadinessEvaluation {
    pub schema_version: String,
    pub verifier_mode: String,
    pub decision: PublicReadinessDecision,
    pub record_digest: String,
    pub evidence_manifest_digest: String,
    pub reasons: Vec<PublicReadinessRejectionReason>,
}

pub fn canonical_public_readiness_digest<T: Serialize>(value: &T) -> Result<String> {
    let value = serde_json::to_value(value)?;
    Ok(hex::encode(Sha256::digest(
        canonical_json(&value).as_bytes(),
    )))
}

pub fn public_readiness_approval_statement_digest(
    record: &PublicReadinessRecord,
    role: &str,
    identity: &str,
) -> String {
    let statement = format!(
        "public-readiness-approval-v1\nrepository={}\ncandidate_commit={}\naudited_refs_digest={}\ngithub_settings_digest={}\ngovernance_tree_digest={}\nrelease_gate_digest={}\nevidence_manifest_digest={}\nrole={role}\nidentity={identity}\n",
        record.repository,
        record.candidate_commit,
        record.audited_refs_digest,
        record.github_settings_digest,
        record.governance_tree_digest,
        record.release_gate_digest,
        record.evidence_manifest_digest,
    );
    hex::encode(Sha256::digest(statement.as_bytes()))
}

pub fn public_readiness_evidence_input_digest(
    manifest: &PublicReadinessEvidenceManifest,
) -> String {
    let input = format!(
        "public-readiness-evidence-input-v1\nrepository={}\ncandidate_commit={}\naudited_refs_digest={}\ngithub_settings_digest={}\ngovernance_tree_digest={}\nrelease_gate_digest={}\n",
        manifest.repository,
        manifest.candidate_commit,
        manifest.audited_refs_digest,
        manifest.github_settings_digest,
        manifest.governance_tree_digest,
        manifest.release_gate_digest,
    );
    hex::encode(Sha256::digest(input.as_bytes()))
}

pub fn public_readiness_evidence_digest(evidence: &PublicReadinessEvidence) -> Result<String> {
    let mut value = serde_json::to_value(evidence)?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| anyhow!("serialized public readiness evidence is not an object"))?;
    object
        .remove("evidence_digest")
        .ok_or_else(|| anyhow!("serialized public readiness evidence has no digest field"))?;
    Ok(hex::encode(Sha256::digest(
        canonical_json(&value).as_bytes(),
    )))
}

pub fn evaluate_public_readiness(
    bundle: &PublicReadinessBundle,
    expected: &PublicReadinessExpectedState,
) -> Result<PublicReadinessEvaluation> {
    let record = &bundle.record;
    let manifest = &bundle.evidence_manifest;
    let record_digest = canonical_public_readiness_digest(record)?;
    let evidence_manifest_digest = canonical_public_readiness_digest(manifest)?;
    let mut reasons = BTreeSet::new();

    validate_record_shape(record, &mut reasons);
    validate_manifest_shape(manifest, &mut reasons);

    if record.repository != expected.repository
        || manifest.repository != expected.repository
        || record.candidate_commit != expected.candidate_commit
        || manifest.candidate_commit != expected.candidate_commit
        || record.audited_refs_digest != expected.audited_refs_digest
        || manifest.audited_refs_digest != expected.audited_refs_digest
        || record.github_settings_digest != expected.github_settings_digest
        || manifest.github_settings_digest != expected.github_settings_digest
        || record.governance_tree_digest != expected.governance_tree_digest
        || manifest.governance_tree_digest != expected.governance_tree_digest
        || record.release_gate_digest != expected.release_gate_digest
        || manifest.release_gate_digest != expected.release_gate_digest
    {
        reasons.insert(PublicReadinessRejectionReason::CandidateStateStale);
    }
    if record.evidence_manifest_digest != evidence_manifest_digest {
        reasons.insert(PublicReadinessRejectionReason::EvidenceManifestTampered);
    }
    if record.decision != PublicReadinessDecision::Allow {
        reasons.insert(PublicReadinessRejectionReason::RecordDeclaresReject);
    }

    let manifest_by_gate = manifest
        .evidence
        .iter()
        .map(|evidence| (evidence.gate_id.as_str(), evidence))
        .collect::<BTreeMap<_, _>>();
    for gate in &record.gates {
        if gate.decision != PublicReadinessDecision::Allow {
            reasons.insert(PublicReadinessRejectionReason::GateNotAllowed);
        }
        let Some(evidence) = manifest_by_gate.get(gate.id.as_str()) else {
            reasons.insert(PublicReadinessRejectionReason::EvidenceMismatch);
            continue;
        };
        if gate.evidence_digest != evidence.evidence_digest
            || gate.producer_role != evidence.producer_role
            || gate.producer_identity != evidence.producer_identity
            || gate.approver_role != evidence.approver_role
            || gate.approver_identity != evidence.approver_identity
        {
            reasons.insert(PublicReadinessRejectionReason::EvidenceMismatch);
        }
        if public_readiness_evidence_digest(evidence)? != evidence.evidence_digest {
            reasons.insert(PublicReadinessRejectionReason::EvidenceDigestMismatch);
        }
        if evidence.findings.unresolved != 0 {
            reasons.insert(PublicReadinessRejectionReason::UnresolvedFinding);
        }
    }

    validate_final_approvals(record, manifest, &mut reasons);

    let reasons = reasons.into_iter().collect::<Vec<_>>();
    Ok(PublicReadinessEvaluation {
        schema_version: PUBLIC_READINESS_SCHEMA_VERSION.into(),
        verifier_mode: PUBLIC_READINESS_VERIFIER_MODE.into(),
        decision: if reasons.is_empty() {
            PublicReadinessDecision::Allow
        } else {
            PublicReadinessDecision::Reject
        },
        record_digest,
        evidence_manifest_digest,
        reasons,
    })
}

fn validate_record_shape(
    record: &PublicReadinessRecord,
    reasons: &mut BTreeSet<PublicReadinessRejectionReason>,
) {
    if record.schema_version != PUBLIC_READINESS_SCHEMA_VERSION
        || record.repository != PUBLIC_READINESS_REPOSITORY
        || !is_lower_hex(&record.candidate_commit, 40)
        || !is_digest(&record.audited_refs_digest)
        || !is_digest(&record.github_settings_digest)
        || !is_digest(&record.governance_tree_digest)
        || !is_digest(&record.release_gate_digest)
        || !is_digest(&record.evidence_manifest_digest)
        || parse_time(&record.decided_at).is_none()
        || record.accountable_role != "tamat-llc-organization-owner"
    {
        reasons.insert(PublicReadinessRejectionReason::InvalidRecordContract);
    }
    let gate_ids = record
        .gates
        .iter()
        .map(|gate| gate.id.as_str())
        .collect::<Vec<_>>();
    if gate_ids != PUBLIC_READINESS_GATE_IDS {
        reasons.insert(PublicReadinessRejectionReason::MissingOrOutOfOrderGate);
    }
    for gate in &record.gates {
        if !PUBLIC_READINESS_GATE_IDS.contains(&gate.id.as_str())
            || !is_digest(&gate.evidence_digest)
            || !valid_role(&gate.producer_role)
            || !valid_team_identity(&gate.producer_identity)
            || !valid_role(&gate.approver_role)
            || !valid_team_identity(&gate.approver_identity)
            || gate.producer_role == gate.approver_role
            || gate.producer_identity == gate.approver_identity
        {
            reasons.insert(PublicReadinessRejectionReason::InvalidRecordContract);
        }
        if contains_sensitive_shape(&gate.producer_identity)
            || contains_sensitive_shape(&gate.approver_identity)
        {
            reasons.insert(PublicReadinessRejectionReason::SensitiveValueRejected);
        }
    }
}

fn validate_manifest_shape(
    manifest: &PublicReadinessEvidenceManifest,
    reasons: &mut BTreeSet<PublicReadinessRejectionReason>,
) {
    let generated_at = parse_time(&manifest.generated_at);
    let expected_input_digest = public_readiness_evidence_input_digest(manifest);
    if manifest.schema_version != PUBLIC_READINESS_EVIDENCE_SCHEMA_VERSION
        || manifest.repository != PUBLIC_READINESS_REPOSITORY
        || !is_lower_hex(&manifest.candidate_commit, 40)
        || !is_digest(&manifest.audited_refs_digest)
        || !is_digest(&manifest.github_settings_digest)
        || !is_digest(&manifest.governance_tree_digest)
        || !is_digest(&manifest.release_gate_digest)
        || generated_at.is_none()
    {
        reasons.insert(PublicReadinessRejectionReason::InvalidEvidenceManifestContract);
    }
    let gate_ids = manifest
        .evidence
        .iter()
        .map(|evidence| evidence.gate_id.as_str())
        .collect::<Vec<_>>();
    if gate_ids != PUBLIC_READINESS_GATE_IDS {
        reasons.insert(PublicReadinessRejectionReason::MissingOrOutOfOrderGate);
    }
    for evidence in &manifest.evidence {
        let started_at = parse_time(&evidence.started_at);
        let ended_at = parse_time(&evidence.ended_at);
        if !PUBLIC_READINESS_GATE_IDS.contains(&evidence.gate_id.as_str())
            || !is_digest(&evidence.evidence_digest)
            || evidence.input_digest != expected_input_digest
            || !valid_role(&evidence.producer_role)
            || !valid_team_identity(&evidence.producer_identity)
            || !valid_role(&evidence.approver_role)
            || !valid_team_identity(&evidence.approver_identity)
            || evidence.producer_role == evidence.approver_role
            || evidence.producer_identity == evidence.approver_identity
            || !valid_token(&evidence.tool.name, 64)
            || !valid_token(&evidence.tool.version, 64)
            || !is_digest(&evidence.tool.acquisition_digest)
            || !is_digest(&evidence.tool.configuration_digest)
            || started_at.is_none()
            || ended_at.is_none()
            || started_at > ended_at
            || ended_at > generated_at
        {
            reasons.insert(PublicReadinessRejectionReason::InvalidEvidenceManifestContract);
        }
        if contains_sensitive_shape(&evidence.producer_identity)
            || contains_sensitive_shape(&evidence.approver_identity)
        {
            reasons.insert(PublicReadinessRejectionReason::SensitiveValueRejected);
        }
    }
}

fn validate_final_approvals(
    record: &PublicReadinessRecord,
    manifest: &PublicReadinessEvidenceManifest,
    reasons: &mut BTreeSet<PublicReadinessRejectionReason>,
) {
    let approval_roles = record
        .approvals
        .iter()
        .map(|approval| approval.role.as_str())
        .collect::<Vec<_>>();
    if approval_roles != PUBLIC_READINESS_FINAL_APPROVAL_ROLES {
        reasons.insert(PublicReadinessRejectionReason::MissingFinalApproval);
    }
    let decided_at = parse_time(&record.decided_at);
    let generated_at = parse_time(&manifest.generated_at);
    let producer_identities = manifest
        .evidence
        .iter()
        .map(|evidence| evidence.producer_identity.as_str())
        .collect::<BTreeSet<_>>();
    let approver_identities = manifest
        .evidence
        .iter()
        .map(|evidence| evidence.approver_identity.as_str())
        .collect::<BTreeSet<_>>();
    if !producer_identities.is_disjoint(&approver_identities) {
        reasons.insert(PublicReadinessRejectionReason::InvalidOrSelfApproval);
    }
    let mut final_approval_identities = BTreeSet::new();
    for approval in &record.approvals {
        let approved_at = parse_time(&approval.approved_at);
        if !PUBLIC_READINESS_FINAL_APPROVAL_ROLES.contains(&approval.role.as_str())
            || !valid_team_identity(&approval.identity)
            || !is_digest(&approval.statement_digest)
            || approved_at.is_none()
            || approved_at < generated_at
            || approved_at > decided_at
        {
            reasons.insert(PublicReadinessRejectionReason::InvalidOrSelfApproval);
        }
        if !final_approval_identities.insert(approval.identity.as_str())
            || producer_identities.contains(approval.identity.as_str())
            || approver_identities.contains(approval.identity.as_str())
        {
            reasons.insert(PublicReadinessRejectionReason::InvalidOrSelfApproval);
        }
        if approval.statement_digest
            != public_readiness_approval_statement_digest(
                record,
                &approval.role,
                &approval.identity,
            )
        {
            reasons.insert(PublicReadinessRejectionReason::ApprovalStatementMismatch);
        }
        if contains_sensitive_shape(&approval.identity) {
            reasons.insert(PublicReadinessRejectionReason::SensitiveValueRejected);
        }
    }
}

fn is_digest(value: &str) -> bool {
    is_lower_hex(value, 64)
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_role(value: &str) -> bool {
    PUBLIC_READINESS_ROLES.contains(&value)
}

fn valid_team_identity(value: &str) -> bool {
    value
        .strip_prefix("team:")
        .is_some_and(|slug| valid_token(slug, 64))
}

fn valid_token(value: &str, max_len: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'+'))
}

fn contains_sensitive_shape(value: &str) -> bool {
    value.contains('@')
        || value.contains('\\')
        || value.starts_with('/')
        || value.contains("://")
        || value.to_ascii_lowercase().contains("secret")
        || value.to_ascii_lowercase().contains("token")
}

fn parse_time(value: &str) -> Option<DateTime<chrono::FixedOffset>> {
    value
        .ends_with('Z')
        .then(|| DateTime::parse_from_rfc3339(value).ok())
        .flatten()
        .filter(|timestamp| timestamp.offset().local_minus_utc() == 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const HASH_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const HASH_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const HASH_C: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    const HASH_D: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
    const HASH_E: &str = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
    const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";

    fn fixture() -> (PublicReadinessBundle, PublicReadinessExpectedState) {
        let mut manifest = PublicReadinessEvidenceManifest {
            schema_version: PUBLIC_READINESS_EVIDENCE_SCHEMA_VERSION.into(),
            repository: PUBLIC_READINESS_REPOSITORY.into(),
            candidate_commit: COMMIT.into(),
            audited_refs_digest: HASH_A.into(),
            github_settings_digest: HASH_B.into(),
            governance_tree_digest: HASH_C.into(),
            release_gate_digest: HASH_D.into(),
            generated_at: "2026-07-26T00:02:00Z".into(),
            evidence: Vec::new(),
        };
        let input_digest = public_readiness_evidence_input_digest(&manifest);
        manifest.evidence = PUBLIC_READINESS_GATE_IDS
            .iter()
            .enumerate()
            .map(|(index, gate_id)| {
                let mut evidence = PublicReadinessEvidence {
                    gate_id: (*gate_id).into(),
                    evidence_digest: String::new(),
                    input_digest: input_digest.clone(),
                    started_at: "2026-07-26T00:00:00Z".into(),
                    ended_at: format!("2026-07-26T00:01:{index:02}Z"),
                    producer_role: "repository-administrator".into(),
                    producer_identity: "team:readiness-producers".into(),
                    approver_role: "independent-code-reviewer".into(),
                    approver_identity: "team:readiness-gate-reviewers".into(),
                    tool: PublicReadinessToolIdentity {
                        name: "readiness-auditor".into(),
                        version: "1.0.0".into(),
                        acquisition_digest: HASH_B.into(),
                        configuration_digest: HASH_C.into(),
                    },
                    findings: PublicReadinessFindingSummary {
                        resolved: 0,
                        unresolved: 0,
                    },
                };
                evidence.evidence_digest = public_readiness_evidence_digest(&evidence).unwrap();
                evidence
            })
            .collect::<Vec<_>>();
        let evidence_manifest_digest = canonical_public_readiness_digest(&manifest).unwrap();
        let gates = manifest
            .evidence
            .iter()
            .map(|evidence| PublicReadinessGate {
                id: evidence.gate_id.clone(),
                decision: PublicReadinessDecision::Allow,
                evidence_digest: evidence.evidence_digest.clone(),
                producer_role: evidence.producer_role.clone(),
                producer_identity: evidence.producer_identity.clone(),
                approver_role: evidence.approver_role.clone(),
                approver_identity: evidence.approver_identity.clone(),
            })
            .collect();
        let mut record = PublicReadinessRecord {
            schema_version: PUBLIC_READINESS_SCHEMA_VERSION.into(),
            repository: PUBLIC_READINESS_REPOSITORY.into(),
            candidate_commit: COMMIT.into(),
            audited_refs_digest: HASH_A.into(),
            github_settings_digest: HASH_B.into(),
            governance_tree_digest: HASH_C.into(),
            release_gate_digest: HASH_D.into(),
            evidence_manifest_digest,
            gates,
            decision: PublicReadinessDecision::Allow,
            decided_at: "2026-07-26T00:04:00Z".into(),
            accountable_role: "tamat-llc-organization-owner".into(),
            approvals: PUBLIC_READINESS_FINAL_APPROVAL_ROLES
                .iter()
                .map(|role| PublicReadinessApproval {
                    role: (*role).into(),
                    identity: format!("team:{role}s"),
                    approved_at: "2026-07-26T00:03:00Z".into(),
                    statement_digest: String::new(),
                })
                .collect(),
        };
        let statement_digests = record
            .approvals
            .iter()
            .map(|approval| {
                public_readiness_approval_statement_digest(
                    &record,
                    &approval.role,
                    &approval.identity,
                )
            })
            .collect::<Vec<_>>();
        for (approval, statement_digest) in record.approvals.iter_mut().zip(statement_digests) {
            approval.statement_digest = statement_digest;
        }
        let expected = PublicReadinessExpectedState {
            repository: PUBLIC_READINESS_REPOSITORY.into(),
            candidate_commit: COMMIT.into(),
            audited_refs_digest: HASH_A.into(),
            github_settings_digest: HASH_B.into(),
            governance_tree_digest: HASH_C.into(),
            release_gate_digest: HASH_D.into(),
        };
        (
            PublicReadinessBundle {
                record,
                evidence_manifest: manifest,
            },
            expected,
        )
    }

    #[test]
    fn exact_candidate_evidence_and_independent_approvals_are_required_for_allow() {
        let (bundle, expected) = fixture();
        let evaluation = evaluate_public_readiness(&bundle, &expected).unwrap();
        assert_eq!(evaluation.decision, PublicReadinessDecision::Allow);
        assert!(evaluation.reasons.is_empty());
        assert_eq!(
            evaluation.verifier_mode,
            "evidence-only-no-visibility-actuator"
        );
    }

    #[test]
    fn canonical_digest_and_schema_round_trip_are_stable() {
        let (bundle, _) = fixture();
        let value = serde_json::to_value(&bundle).unwrap();
        let reversed = json!({
            "evidence_manifest": value["evidence_manifest"].clone(),
            "record": value["record"].clone(),
        });
        assert_eq!(
            canonical_public_readiness_digest(&bundle).unwrap(),
            hex::encode(Sha256::digest(canonical_json(&reversed).as_bytes()))
        );
        let round_trip: PublicReadinessBundle = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(round_trip, bundle);

        let schema: serde_json::Value = serde_json::from_slice(include_bytes!(
            "../../../schemas/public-readiness-v1.schema.json"
        ))
        .unwrap();
        let validator = jsonschema::validator_for(&schema).unwrap();
        assert!(validator.is_valid(&value));
        let mut unknown = value;
        unknown["record"]["unknown"] = json!(true);
        assert!(!validator.is_valid(&unknown));
        assert!(serde_json::from_value::<PublicReadinessBundle>(unknown).is_err());
    }

    #[test]
    fn missing_unknown_stale_self_approved_and_tampered_inputs_reject() {
        let (bundle, expected) = fixture();
        let mut cases = Vec::new();

        let mut missing_gate = bundle.clone();
        missing_gate.record.gates.pop();
        cases.push(missing_gate);

        let mut tampered = bundle.clone();
        tampered.evidence_manifest.evidence[0].findings.unresolved = 1;
        cases.push(tampered);

        let mut self_approved = bundle.clone();
        self_approved.evidence_manifest.evidence[0].approver_identity =
            self_approved.evidence_manifest.evidence[0]
                .producer_identity
                .clone();
        self_approved.record.gates[0].approver_identity =
            self_approved.record.gates[0].producer_identity.clone();
        cases.push(self_approved);

        let mut personal_contact = bundle.clone();
        personal_contact.record.approvals[0].identity = "person@example.invalid".into();
        cases.push(personal_contact);

        let mut non_canonical_timestamp = bundle.clone();
        non_canonical_timestamp.record.decided_at = "2026-07-26T09:04:00+09:00".into();
        cases.push(non_canonical_timestamp);

        for case in cases {
            assert_eq!(
                evaluate_public_readiness(&case, &expected)
                    .unwrap()
                    .decision,
                PublicReadinessDecision::Reject
            );
        }

        let mut stale = expected;
        stale.github_settings_digest = HASH_E.into();
        let evaluation = evaluate_public_readiness(&bundle, &stale).unwrap();
        assert_eq!(evaluation.decision, PublicReadinessDecision::Reject);
        assert!(
            evaluation
                .reasons
                .contains(&PublicReadinessRejectionReason::CandidateStateStale)
        );
    }

    #[test]
    fn evidence_digest_is_recomputed_from_canonical_evidence() {
        let (mut bundle, expected) = fixture();
        bundle.evidence_manifest.evidence[0].evidence_digest = HASH_E.into();
        bundle.record.gates[0].evidence_digest = HASH_E.into();
        refresh_record_integrity(&mut bundle);

        let evaluation = evaluate_public_readiness(&bundle, &expected).unwrap();
        assert_eq!(evaluation.decision, PublicReadinessDecision::Reject);
        assert!(
            evaluation
                .reasons
                .contains(&PublicReadinessRejectionReason::EvidenceDigestMismatch)
        );
        assert!(
            !evaluation
                .reasons
                .contains(&PublicReadinessRejectionReason::EvidenceManifestTampered)
        );
        assert!(
            !evaluation
                .reasons
                .contains(&PublicReadinessRejectionReason::EvidenceMismatch)
        );
    }

    #[test]
    fn authenticated_identities_cannot_cross_approval_boundaries() {
        let (bundle, expected) = fixture();

        let mut producer_as_approver = bundle.clone();
        producer_as_approver.evidence_manifest.evidence[0].approver_identity =
            producer_as_approver.evidence_manifest.evidence[0]
                .producer_identity
                .clone();
        refresh_evidence_and_record_integrity(&mut producer_as_approver, 0);

        let mut producer_as_final_approver = bundle.clone();
        producer_as_final_approver.record.approvals[0].identity =
            producer_as_final_approver.evidence_manifest.evidence[0]
                .producer_identity
                .clone();
        refresh_approval_statement_digests(&mut producer_as_final_approver.record);

        let mut duplicate_final_approver = bundle;
        duplicate_final_approver.record.approvals[1].identity =
            duplicate_final_approver.record.approvals[0]
                .identity
                .clone();
        refresh_approval_statement_digests(&mut duplicate_final_approver.record);

        for case in [
            producer_as_approver,
            producer_as_final_approver,
            duplicate_final_approver,
        ] {
            let evaluation = evaluate_public_readiness(&case, &expected).unwrap();
            assert_eq!(evaluation.decision, PublicReadinessDecision::Reject);
            assert!(
                evaluation
                    .reasons
                    .contains(&PublicReadinessRejectionReason::InvalidOrSelfApproval)
            );
        }
    }

    fn refresh_evidence_and_record_integrity(bundle: &mut PublicReadinessBundle, index: usize) {
        let evidence = &mut bundle.evidence_manifest.evidence[index];
        evidence.evidence_digest = public_readiness_evidence_digest(evidence).unwrap();
        let gate = &mut bundle.record.gates[index];
        gate.evidence_digest.clone_from(&evidence.evidence_digest);
        gate.producer_role.clone_from(&evidence.producer_role);
        gate.producer_identity
            .clone_from(&evidence.producer_identity);
        gate.approver_role.clone_from(&evidence.approver_role);
        gate.approver_identity
            .clone_from(&evidence.approver_identity);
        refresh_record_integrity(bundle);
    }

    fn refresh_record_integrity(bundle: &mut PublicReadinessBundle) {
        bundle.record.evidence_manifest_digest =
            canonical_public_readiness_digest(&bundle.evidence_manifest).unwrap();
        refresh_approval_statement_digests(&mut bundle.record);
    }

    fn refresh_approval_statement_digests(record: &mut PublicReadinessRecord) {
        let statement_digests = record
            .approvals
            .iter()
            .map(|approval| {
                public_readiness_approval_statement_digest(
                    record,
                    &approval.role,
                    &approval.identity,
                )
            })
            .collect::<Vec<_>>();
        for (approval, statement_digest) in record.approvals.iter_mut().zip(statement_digests) {
            approval.statement_digest = statement_digest;
        }
    }
}
