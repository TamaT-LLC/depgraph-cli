use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, bail};
use depgraph_protocol::canonical_json;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::{
    PublicReadinessFindingSummary, PublicReadinessToolIdentity, canonical_public_readiness_digest,
};

pub const PUBLIC_HISTORY_AUDIT_SCHEMA_VERSION: &str = "public-history-audit-v1";
pub const PUBLIC_HISTORY_AUDIT_FINAL_SCHEMA_VERSION: &str = "public-history-audit-final-v1";
pub const PUBLIC_SECRET_SCANNER_NAME: &str = "depgraph-public-secret-scanner";
pub const PUBLIC_SECRET_SCANNER_VERSION: &str = "1.0.0";
pub const MAX_PUBLIC_AUDIT_REFS: usize = 4_096;
pub const MAX_PUBLIC_AUDIT_SOURCES: usize = 20_000;
pub const MAX_PUBLIC_AUDIT_SOURCE_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_PUBLIC_AUDIT_TOTAL_BYTES: usize = 128 * 1024 * 1024;

const PATTERN_IDS: [&str; 6] = [
    "aws-access-key-v1",
    "generic-credential-assignment-v1",
    "github-token-v1",
    "internal-host-v1",
    "pem-private-key-v1",
    "personal-email-v1",
];

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicAuditSourceKind {
    ActionsArtifact,
    ActionsCache,
    ActionsLog,
    CommitMessage,
    Discussion,
    GitBlob,
    Issue,
    LfsObject,
    PullRequest,
    Release,
    SubmodulePointer,
    TagMessage,
    Wiki,
}

pub const PUBLIC_AUDIT_SOURCE_KINDS: [PublicAuditSourceKind; 13] = [
    PublicAuditSourceKind::ActionsArtifact,
    PublicAuditSourceKind::ActionsCache,
    PublicAuditSourceKind::ActionsLog,
    PublicAuditSourceKind::CommitMessage,
    PublicAuditSourceKind::Discussion,
    PublicAuditSourceKind::GitBlob,
    PublicAuditSourceKind::Issue,
    PublicAuditSourceKind::LfsObject,
    PublicAuditSourceKind::PullRequest,
    PublicAuditSourceKind::Release,
    PublicAuditSourceKind::SubmodulePointer,
    PublicAuditSourceKind::TagMessage,
    PublicAuditSourceKind::Wiki,
];

#[derive(Clone)]
pub struct PublicAuditRefInput {
    pub name: String,
    pub object_id: String,
}

#[derive(Clone)]
pub struct PublicAuditSourceInput {
    pub kind: PublicAuditSourceKind,
    pub portable_locator: String,
    pub content: Vec<u8>,
}

#[derive(Clone)]
pub struct PublicHistoryAuditInput {
    pub refs: Vec<PublicAuditRefInput>,
    pub sources: Vec<PublicAuditSourceInput>,
    pub collection_complete: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicAuditFindingState {
    Resolved,
    Unresolved,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicAuditCredentialAction {
    NotCredential,
    Revoked,
    Rotated,
    Unattested,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicAuditPurgeAction {
    NotRequired,
    Purged,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublicAuditFinding {
    pub id: String,
    pub source_kind: PublicAuditSourceKind,
    pub source_locator_digest: String,
    pub content_digest: String,
    pub pattern_id: String,
    pub credential: bool,
    pub state: PublicAuditFindingState,
    pub credential_action: PublicAuditCredentialAction,
    pub purge_action: PublicAuditPurgeAction,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation_attestation_digest: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublicHistoryAuditReport {
    pub schema_version: String,
    pub scanner: PublicReadinessToolIdentity,
    pub audited_refs_digest: String,
    pub object_closure_digest: String,
    pub collaboration_surface_digest: String,
    pub source_counts: BTreeMap<PublicAuditSourceKind, u64>,
    pub collection_complete: bool,
    pub findings: Vec<PublicAuditFinding>,
    pub unresolved_findings: u64,
    pub unrotated_credentials: u64,
    pub evidence_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublicAuditRemediationAttestation {
    pub finding_id: String,
    pub credential_action: PublicAuditCredentialAction,
    pub purge_action: PublicAuditPurgeAction,
    pub attestation_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FinalizedPublicHistoryAudit {
    pub schema_version: String,
    pub scanner: PublicReadinessToolIdentity,
    pub initial_audited_refs_digest: String,
    pub fresh_mirror_refs_digest: String,
    pub fresh_mirror_object_closure_digest: String,
    pub fresh_mirror_evidence_digest: String,
    pub history_rewritten: bool,
    pub collection_complete: bool,
    pub findings: Vec<PublicAuditFinding>,
    pub unresolved_findings: u64,
    pub unrotated_credentials: u64,
    pub readiness_findings: PublicReadinessFindingSummary,
    pub evidence_digest: String,
}

pub fn public_secret_scanner_identity() -> PublicReadinessToolIdentity {
    let acquisition_digest = digest_bytes(
        b"depgraph-public-secret-scanner-v1\nimplementation=compiled-rust\nnetwork=disabled\n",
    );
    let configuration_digest = digest_bytes(
        format!("public-secret-pattern-set-v1\n{}\n", PATTERN_IDS.join("\n")).as_bytes(),
    );
    PublicReadinessToolIdentity {
        name: PUBLIC_SECRET_SCANNER_NAME.into(),
        version: PUBLIC_SECRET_SCANNER_VERSION.into(),
        acquisition_digest,
        configuration_digest,
    }
}

pub fn audit_public_history(input: &PublicHistoryAuditInput) -> Result<PublicHistoryAuditReport> {
    validate_input(input)?;
    let scanner = public_secret_scanner_identity();
    let audited_refs_digest = refs_digest(&input.refs)?;
    let mut source_counts = PUBLIC_AUDIT_SOURCE_KINDS
        .into_iter()
        .map(|kind| (kind, 0_u64))
        .collect::<BTreeMap<_, _>>();
    let mut object_inventory = Vec::new();
    let mut collaboration_inventory = Vec::new();
    let mut findings = Vec::new();

    for source in &input.sources {
        *source_counts
            .get_mut(&source.kind)
            .context("source kind inventory is incomplete")? += 1;
        let locator_digest = digest_bytes(source.portable_locator.as_bytes());
        let content_digest = digest_bytes(&source.content);
        let inventory = json!({
            "kind": source.kind,
            "locator_digest": locator_digest,
            "content_digest": content_digest,
            "bytes": source.content.len(),
        });
        if is_collaboration_source(source.kind) {
            collaboration_inventory.push(inventory);
        } else {
            object_inventory.push(inventory);
        }
        for (pattern_id, credential) in scan_patterns(&source.content) {
            let id = digest_bytes(
                canonical_json(&json!({
                    "contract": PUBLIC_HISTORY_AUDIT_SCHEMA_VERSION,
                    "source_kind": source.kind,
                    "source_locator_digest": locator_digest,
                    "content_digest": content_digest,
                    "pattern_id": pattern_id,
                }))
                .as_bytes(),
            );
            findings.push(PublicAuditFinding {
                id,
                source_kind: source.kind,
                source_locator_digest: locator_digest.clone(),
                content_digest: content_digest.clone(),
                pattern_id: pattern_id.into(),
                credential,
                state: PublicAuditFindingState::Unresolved,
                credential_action: if credential {
                    PublicAuditCredentialAction::Unattested
                } else {
                    PublicAuditCredentialAction::NotCredential
                },
                purge_action: PublicAuditPurgeAction::NotRequired,
                remediation_attestation_digest: None,
            });
        }
    }
    findings.sort_by(|left, right| left.id.cmp(&right.id));
    findings.dedup_by(|left, right| left.id == right.id);
    object_inventory.sort_by_key(canonical_json);
    collaboration_inventory.sort_by_key(canonical_json);

    let mut report = PublicHistoryAuditReport {
        schema_version: PUBLIC_HISTORY_AUDIT_SCHEMA_VERSION.into(),
        scanner,
        audited_refs_digest,
        object_closure_digest: digest_json(&object_inventory)?,
        collaboration_surface_digest: digest_json(&collaboration_inventory)?,
        source_counts,
        collection_complete: input.collection_complete,
        unresolved_findings: findings.len() as u64 + u64::from(!input.collection_complete),
        unrotated_credentials: findings.iter().filter(|finding| finding.credential).count() as u64,
        findings,
        evidence_digest: String::new(),
    };
    report.evidence_digest = report_digest(&report)?;
    Ok(report)
}

pub fn finalize_public_history_audit(
    initial: &PublicHistoryAuditReport,
    fresh_mirror: &PublicHistoryAuditReport,
    attestations: &[PublicAuditRemediationAttestation],
) -> Result<FinalizedPublicHistoryAudit> {
    validate_report(initial)?;
    validate_report(fresh_mirror)?;
    let attestation_by_finding = attestations
        .iter()
        .map(|attestation| (attestation.finding_id.as_str(), attestation))
        .collect::<BTreeMap<_, _>>();
    if attestation_by_finding.len() != attestations.len()
        || attestations
            .iter()
            .any(|attestation| !is_digest(&attestation.attestation_digest))
    {
        bail!("public audit remediation attestations are duplicate or malformed");
    }
    let fresh_finding_ids = fresh_mirror
        .findings
        .iter()
        .map(|finding| finding.id.as_str())
        .collect::<BTreeSet<_>>();
    let mut findings = initial.findings.clone();
    for finding in &mut findings {
        let attestation = attestation_by_finding.get(finding.id.as_str());
        if let Some(attestation) = attestation {
            finding.credential_action = attestation.credential_action;
            finding.purge_action = attestation.purge_action;
            finding.remediation_attestation_digest = Some(attestation.attestation_digest.clone());
        }
        let credential_closed = if finding.credential {
            matches!(
                finding.credential_action,
                PublicAuditCredentialAction::Rotated | PublicAuditCredentialAction::Revoked
            )
        } else {
            finding.credential_action == PublicAuditCredentialAction::NotCredential
        };
        let purge_closed = finding.purge_action == PublicAuditPurgeAction::Purged;
        finding.state = if credential_closed
            && purge_closed
            && !fresh_finding_ids.contains(finding.id.as_str())
        {
            PublicAuditFindingState::Resolved
        } else {
            PublicAuditFindingState::Unresolved
        };
    }
    if attestations.iter().any(|attestation| {
        !findings
            .iter()
            .any(|finding| finding.id == attestation.finding_id)
    }) {
        bail!("public audit remediation attests an unknown finding");
    }
    let initial_finding_ids = findings
        .iter()
        .map(|finding| finding.id.as_str())
        .collect::<BTreeSet<_>>();
    let fresh_only_unresolved = fresh_mirror
        .findings
        .iter()
        .filter(|finding| !initial_finding_ids.contains(finding.id.as_str()))
        .count() as u64;
    let unresolved_findings = findings
        .iter()
        .filter(|finding| finding.state == PublicAuditFindingState::Unresolved)
        .count() as u64
        + fresh_only_unresolved
        + u64::from(!initial.collection_complete || !fresh_mirror.collection_complete);
    let unrotated_credentials = findings
        .iter()
        .filter(|finding| {
            finding.credential
                && !matches!(
                    finding.credential_action,
                    PublicAuditCredentialAction::Rotated | PublicAuditCredentialAction::Revoked
                )
        })
        .count() as u64
        + fresh_mirror
            .findings
            .iter()
            .filter(|finding| {
                finding.credential && !initial_finding_ids.contains(finding.id.as_str())
            })
            .count() as u64;
    let collection_complete = initial.collection_complete && fresh_mirror.collection_complete;
    let resolved = findings
        .iter()
        .filter(|finding| finding.state == PublicAuditFindingState::Resolved)
        .count() as u32;
    let mut finalized = FinalizedPublicHistoryAudit {
        schema_version: PUBLIC_HISTORY_AUDIT_FINAL_SCHEMA_VERSION.into(),
        scanner: initial.scanner.clone(),
        initial_audited_refs_digest: initial.audited_refs_digest.clone(),
        fresh_mirror_refs_digest: fresh_mirror.audited_refs_digest.clone(),
        fresh_mirror_object_closure_digest: fresh_mirror.object_closure_digest.clone(),
        fresh_mirror_evidence_digest: fresh_mirror.evidence_digest.clone(),
        history_rewritten: initial.audited_refs_digest != fresh_mirror.audited_refs_digest,
        collection_complete,
        findings,
        unresolved_findings,
        unrotated_credentials,
        readiness_findings: PublicReadinessFindingSummary {
            resolved,
            unresolved: unresolved_findings.try_into().unwrap_or(u32::MAX),
        },
        evidence_digest: String::new(),
    };
    finalized.evidence_digest = finalized_digest(&finalized)?;
    Ok(finalized)
}

fn validate_input(input: &PublicHistoryAuditInput) -> Result<()> {
    if input.refs.is_empty() || input.refs.len() > MAX_PUBLIC_AUDIT_REFS {
        bail!("public audit ref inventory is empty or exceeds its bound");
    }
    let mut prior_ref = None;
    for reference in &input.refs {
        if !valid_ref_name(&reference.name)
            || !is_object_id(&reference.object_id)
            || prior_ref.is_some_and(|prior| prior >= reference.name.as_str())
        {
            bail!("public audit refs must be canonical, unique, and portable");
        }
        prior_ref = Some(reference.name.as_str());
    }
    if input.sources.len() > MAX_PUBLIC_AUDIT_SOURCES {
        bail!("public audit source inventory exceeds its bound");
    }
    let mut total_bytes = 0_usize;
    let mut prior_source = None;
    for source in &input.sources {
        if source.content.len() > MAX_PUBLIC_AUDIT_SOURCE_BYTES
            || !valid_portable_locator(&source.portable_locator)
        {
            bail!("public audit source is oversized or has an unsafe locator");
        }
        total_bytes = total_bytes
            .checked_add(source.content.len())
            .context("public audit byte count overflow")?;
        let key = (source.kind, source.portable_locator.as_str());
        if prior_source.is_some_and(|prior| prior >= key) {
            bail!("public audit sources must be canonical and unique");
        }
        prior_source = Some(key);
    }
    if total_bytes > MAX_PUBLIC_AUDIT_TOTAL_BYTES {
        bail!("public audit total source bytes exceed the bound");
    }
    Ok(())
}

fn validate_report(report: &PublicHistoryAuditReport) -> Result<()> {
    let expected_unresolved = report
        .findings
        .iter()
        .filter(|finding| finding.state == PublicAuditFindingState::Unresolved)
        .count() as u64
        + u64::from(!report.collection_complete);
    let expected_unrotated = report
        .findings
        .iter()
        .filter(|finding| {
            finding.credential
                && !matches!(
                    finding.credential_action,
                    PublicAuditCredentialAction::Rotated | PublicAuditCredentialAction::Revoked
                )
        })
        .count() as u64;
    if report.schema_version != PUBLIC_HISTORY_AUDIT_SCHEMA_VERSION
        || report.scanner != public_secret_scanner_identity()
        || !is_digest(&report.audited_refs_digest)
        || !is_digest(&report.object_closure_digest)
        || !is_digest(&report.collaboration_surface_digest)
        || !is_digest(&report.evidence_digest)
        || report.evidence_digest != report_digest(report)?
        || report.unresolved_findings != expected_unresolved
        || report.unrotated_credentials != expected_unrotated
        || report
            .findings
            .windows(2)
            .any(|pair| pair[0].id >= pair[1].id)
        || report.findings.iter().any(|finding| {
            !is_digest(&finding.id)
                || !is_digest(&finding.source_locator_digest)
                || !is_digest(&finding.content_digest)
                || !PATTERN_IDS.contains(&finding.pattern_id.as_str())
        })
    {
        bail!("public history audit report is malformed or tampered");
    }
    Ok(())
}

fn refs_digest(refs: &[PublicAuditRefInput]) -> Result<String> {
    let values = refs
        .iter()
        .map(|reference| {
            json!({
                "name": reference.name,
                "object_id": reference.object_id,
            })
        })
        .collect::<Vec<_>>();
    digest_json(&values)
}

fn report_digest(report: &PublicHistoryAuditReport) -> Result<String> {
    let mut value = serde_json::to_value(report)?;
    value["evidence_digest"] = json!("");
    Ok(digest_bytes(canonical_json(&value).as_bytes()))
}

fn finalized_digest(report: &FinalizedPublicHistoryAudit) -> Result<String> {
    let mut value = serde_json::to_value(report)?;
    value["evidence_digest"] = json!("");
    Ok(digest_bytes(canonical_json(&value).as_bytes()))
}

fn digest_json<T: Serialize>(value: &T) -> Result<String> {
    canonical_public_readiness_digest(value)
}

fn digest_bytes(value: &[u8]) -> String {
    hex::encode(Sha256::digest(value))
}

fn is_object_id(value: &str) -> bool {
    matches!(value.len(), 40 | 64)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_ref_name(value: &str) -> bool {
    [
        "refs/heads/",
        "refs/notes/",
        "refs/pull/",
        "refs/remotes/",
        "refs/tags/",
    ]
    .iter()
    .any(|prefix| value.starts_with(prefix))
        && valid_portable_locator(value)
}

fn valid_portable_locator(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 1_024
        && !value.starts_with('/')
        && !value.starts_with('\\')
        && !value.contains('\\')
        && !value.contains('\0')
        && !value.contains("://")
        && !value
            .split('/')
            .any(|component| component.is_empty() || component == "." || component == "..")
        && !(value.len() >= 2 && value.as_bytes()[1] == b':')
}

fn is_collaboration_source(kind: PublicAuditSourceKind) -> bool {
    matches!(
        kind,
        PublicAuditSourceKind::ActionsArtifact
            | PublicAuditSourceKind::ActionsCache
            | PublicAuditSourceKind::ActionsLog
            | PublicAuditSourceKind::Discussion
            | PublicAuditSourceKind::Issue
            | PublicAuditSourceKind::PullRequest
            | PublicAuditSourceKind::Release
            | PublicAuditSourceKind::Wiki
    )
}

fn scan_patterns(content: &[u8]) -> Vec<(&'static str, bool)> {
    let text = String::from_utf8_lossy(content);
    let lower = text.to_ascii_lowercase();
    let mut findings = BTreeSet::new();
    if text.contains("-----BEGIN PRIVATE KEY-----")
        || text.contains("-----BEGIN RSA PRIVATE KEY-----")
    {
        findings.insert(("pem-private-key-v1", true));
    }
    if contains_prefixed_token(&text, &["ghp_", "gho_", "ghu_", "ghs_", "ghr_"], 20) {
        findings.insert(("github-token-v1", true));
    }
    if contains_aws_access_key(&text) {
        findings.insert(("aws-access-key-v1", true));
    }
    if contains_credential_assignment(&lower) {
        findings.insert(("generic-credential-assignment-v1", true));
    }
    if lower.contains(".internal") {
        findings.insert(("internal-host-v1", false));
    }
    if contains_personal_email(&text) {
        findings.insert(("personal-email-v1", false));
    }
    findings.into_iter().collect()
}

fn contains_prefixed_token(text: &str, prefixes: &[&str], minimum_suffix: usize) -> bool {
    prefixes.iter().any(|prefix| {
        text.match_indices(prefix).any(|(index, _)| {
            text[index + prefix.len()..]
                .bytes()
                .take_while(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
                .count()
                >= minimum_suffix
        })
    })
}

fn contains_aws_access_key(text: &str) -> bool {
    text.match_indices("AKIA").any(|(index, _)| {
        text[index + 4..]
            .bytes()
            .take(16)
            .filter(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
            .count()
            == 16
    })
}

fn contains_credential_assignment(lower: &str) -> bool {
    ["password", "passwd", "secret", "token", "api_key", "apikey"]
        .iter()
        .any(|key| {
            ["=", ":"].iter().any(|separator| {
                let needle = format!("{key}{separator}");
                lower.match_indices(&needle).any(|(index, _)| {
                    let value = lower[index + needle.len()..]
                        .trim_start_matches(|character: char| {
                            character.is_ascii_whitespace() || matches!(character, '"' | '\'' | '`')
                        })
                        .split(|character: char| {
                            character.is_ascii_whitespace()
                                || matches!(character, '"' | '\'' | '`' | ',' | ';')
                        })
                        .next()
                        .unwrap_or_default();
                    value.len() >= 8
                        && !matches!(
                            value,
                            "redacted" | "not-required" | "unavailable" | "placeholder"
                        )
                })
            })
        })
}

fn contains_personal_email(text: &str) -> bool {
    text.split(|character: char| {
        character.is_ascii_whitespace()
            || matches!(character, '<' | '>' | '(' | ')' | '"' | '\'' | ',' | ';')
    })
    .any(|candidate| {
        let Some((local, domain)) = candidate.split_once('@') else {
            return false;
        };
        !local.is_empty()
            && domain.contains('.')
            && !domain.ends_with(".invalid")
            && !domain.ends_with("users.noreply.github.com")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const COMMIT_A: &str = "0123456789abcdef0123456789abcdef01234567";
    const COMMIT_B: &str = "89abcdef0123456789abcdef0123456789abcdef";
    const ATTESTATION: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn source(kind: PublicAuditSourceKind, locator: &str, content: &str) -> PublicAuditSourceInput {
        PublicAuditSourceInput {
            kind,
            portable_locator: locator.into(),
            content: content.as_bytes().to_vec(),
        }
    }

    fn refs(object_id: &str) -> Vec<PublicAuditRefInput> {
        vec![
            PublicAuditRefInput {
                name: "refs/heads/main".into(),
                object_id: object_id.into(),
            },
            PublicAuditRefInput {
                name: "refs/notes/security-audit".into(),
                object_id: object_id.into(),
            },
            PublicAuditRefInput {
                name: "refs/pull/1/head".into(),
                object_id: object_id.into(),
            },
            PublicAuditRefInput {
                name: "refs/tags/v0.4.0".into(),
                object_id: object_id.into(),
            },
        ]
    }

    #[test]
    fn seeded_git_lfs_and_actions_secrets_are_redacted_and_bounded() {
        let input = PublicHistoryAuditInput {
            refs: refs(COMMIT_A),
            sources: vec![
                source(
                    PublicAuditSourceKind::ActionsArtifact,
                    "actions/artifact-1",
                    "password=super-sensitive-value",
                ),
                source(
                    PublicAuditSourceKind::GitBlob,
                    "objects/blob-a",
                    "token=ghp_abcdefghijklmnopqrstuvwxyz123456",
                ),
                source(
                    PublicAuditSourceKind::LfsObject,
                    "lfs/sha256-a",
                    "AKIAABCDEFGHIJKLMNOP",
                ),
                source(
                    PublicAuditSourceKind::SubmodulePointer,
                    "submodules/vendor",
                    COMMIT_A,
                ),
            ],
            collection_complete: true,
        };
        let report = audit_public_history(&input).unwrap();
        assert_eq!(report.findings.len(), 4);
        assert_eq!(report.unrotated_credentials, 4);
        assert_eq!(report.source_counts[&PublicAuditSourceKind::LfsObject], 1);
        assert_eq!(
            report.source_counts[&PublicAuditSourceKind::ActionsArtifact],
            1
        );
        let serialized = serde_json::to_string(&report).unwrap();
        for secret in [
            "ghp_abcdefghijklmnopqrstuvwxyz123456",
            "AKIAABCDEFGHIJKLMNOP",
            "super-sensitive-value",
            "objects/blob-a",
        ] {
            assert!(!serialized.contains(secret));
        }
    }

    #[test]
    fn history_rewrite_rotation_purge_and_fresh_mirror_close_findings() {
        let initial = audit_public_history(&PublicHistoryAuditInput {
            refs: refs(COMMIT_A),
            sources: vec![source(
                PublicAuditSourceKind::GitBlob,
                "objects/old-blob",
                "token=ghp_abcdefghijklmnopqrstuvwxyz123456",
            )],
            collection_complete: true,
        })
        .unwrap();
        let fresh = audit_public_history(&PublicHistoryAuditInput {
            refs: refs(COMMIT_B),
            sources: vec![source(
                PublicAuditSourceKind::GitBlob,
                "objects/clean-blob",
                "token=redacted",
            )],
            collection_complete: true,
        })
        .unwrap();
        let attestations = initial
            .findings
            .iter()
            .map(|finding| PublicAuditRemediationAttestation {
                finding_id: finding.id.clone(),
                credential_action: PublicAuditCredentialAction::Rotated,
                purge_action: PublicAuditPurgeAction::Purged,
                attestation_digest: ATTESTATION.into(),
            })
            .collect::<Vec<_>>();
        let finalized = finalize_public_history_audit(&initial, &fresh, &attestations).unwrap();
        assert!(finalized.history_rewritten);
        assert_eq!(finalized.unresolved_findings, 0);
        assert_eq!(finalized.unrotated_credentials, 0);
        assert_eq!(finalized.readiness_findings.unresolved, 0);
        assert!(
            finalized
                .findings
                .iter()
                .all(|finding| finding.state == PublicAuditFindingState::Resolved)
        );
    }

    #[test]
    fn missing_rotation_reachable_secret_and_unsafe_locator_fail_closed() {
        let initial = audit_public_history(&PublicHistoryAuditInput {
            refs: refs(COMMIT_A),
            sources: vec![source(
                PublicAuditSourceKind::ActionsLog,
                "actions/run-1/log",
                "secret=still-reachable-value",
            )],
            collection_complete: true,
        })
        .unwrap();
        let finalized = finalize_public_history_audit(&initial, &initial, &[]).unwrap();
        assert!(finalized.unresolved_findings > 0);
        assert!(finalized.unrotated_credentials > 0);
        assert!(finalized.readiness_findings.unresolved > 0);

        let unsafe_input = PublicHistoryAuditInput {
            refs: refs(COMMIT_A),
            sources: vec![source(
                PublicAuditSourceKind::ActionsArtifact,
                "/Users/operator/private.zip",
                "clean",
            )],
            collection_complete: true,
        };
        assert!(audit_public_history(&unsafe_input).is_err());
    }
}
