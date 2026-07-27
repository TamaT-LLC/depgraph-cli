use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, bail};
use depgraph_protocol::canonical_json;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::{
    PublicReadinessDecision, PublicReadinessFindingSummary, PublicReadinessToolIdentity,
    canonical_public_readiness_digest,
};

pub const PUBLIC_PROVENANCE_REVIEW_SCHEMA_VERSION: &str = "public-provenance-review-v1";
pub const PUBLIC_PROVENANCE_EVALUATION_SCHEMA_VERSION: &str = "public-provenance-evaluation-v1";
pub const PUBLIC_LICENSE_POLICY_NAME: &str = "depgraph-public-license-policy";
pub const PUBLIC_LICENSE_POLICY_VERSION: &str = "1.0.0";
pub const PUBLIC_VULNERABILITY_SCANNER_NAME: &str = "depgraph-public-vulnerability-scanner";
pub const PUBLIC_VULNERABILITY_SCANNER_VERSION: &str = "1.0.0";
pub const MAX_PUBLIC_PROVENANCE_ASSETS: usize = 100_000;
pub const MAX_PUBLIC_PROVENANCE_DEPENDENCIES: usize = 100_000;

pub const PUBLIC_RELEASE_TARGETS: [&str; 5] = [
    "x86_64-unknown-linux-gnu",
    "aarch64-unknown-linux-gnu",
    "x86_64-apple-darwin",
    "aarch64-apple-darwin",
    "x86_64-pc-windows-msvc",
];

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicAssetKind {
    ProjectSource,
    GeneratedSource,
    VendorSource,
    Binary,
    Font,
    Image,
    Fixture,
    Document,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicDependencyEcosystem {
    Rust,
    Go,
    Web,
    BundledRuntime,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicProvenanceState {
    Authorized,
    Unresolved,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicLicensePolicyState {
    Allowed,
    Forbidden,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicVulnerabilitySeverity {
    Clean,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Clone)]
pub struct PublicAssetAuditInput {
    pub kind: PublicAssetKind,
    pub portable_locator: String,
    pub present: bool,
    pub content_digest: Option<String>,
    pub provenance: PublicProvenanceState,
    pub license_expression: String,
    pub license_policy: PublicLicensePolicyState,
    pub notice_required: bool,
    pub notice_digest: Option<String>,
}

#[derive(Clone)]
pub struct PublicDependencyAuditInput {
    pub ecosystem: PublicDependencyEcosystem,
    pub target: String,
    pub package_url: String,
    pub component_digest: String,
    pub provenance: PublicProvenanceState,
    pub license_expression: String,
    pub license_policy: PublicLicensePolicyState,
    pub notice_required: bool,
    pub notice_digest: Option<String>,
    pub maximum_vulnerability: PublicVulnerabilitySeverity,
}

#[derive(Clone)]
pub struct PublicTargetAuditInput {
    pub target: String,
    pub archive_digest: String,
    pub sbom_digest: String,
    pub license_report_digest: String,
}

#[derive(Clone)]
pub struct PublicProvenanceAuditInput {
    pub candidate_commit: String,
    pub release_artifacts_digest: String,
    pub archive_checksums_digest: String,
    pub package_manifest_digest: String,
    pub third_party_licenses_digest: String,
    pub assets: Vec<PublicAssetAuditInput>,
    pub dependencies: Vec<PublicDependencyAuditInput>,
    pub targets: Vec<PublicTargetAuditInput>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublicAssetEvidence {
    pub id: String,
    pub kind: PublicAssetKind,
    pub locator_digest: String,
    pub license_expression_digest: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_digest: Option<String>,
    pub present: bool,
    pub provenance: PublicProvenanceState,
    pub license_policy: PublicLicensePolicyState,
    pub notice_required: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notice_digest: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublicDependencyEvidence {
    pub id: String,
    pub ecosystem: PublicDependencyEcosystem,
    pub target: String,
    pub package_url_digest: String,
    pub component_digest: String,
    pub license_expression_digest: String,
    pub provenance: PublicProvenanceState,
    pub license_policy: PublicLicensePolicyState,
    pub notice_required: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notice_digest: Option<String>,
    pub maximum_vulnerability: PublicVulnerabilitySeverity,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublicTargetEvidence {
    pub target: String,
    pub archive_digest: String,
    pub sbom_digest: String,
    pub license_report_digest: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicProvenanceFindingReason {
    CriticalVulnerability,
    ForbiddenLicense,
    HighVulnerability,
    MissingAsset,
    MissingNotice,
    UnknownLicense,
    UnresolvedProvenance,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublicProvenanceFinding {
    pub id: String,
    pub subject_digest: String,
    pub reason: PublicProvenanceFindingReason,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublicProvenanceReviewPackage {
    pub schema_version: String,
    pub candidate_commit: String,
    pub release_artifacts_digest: String,
    pub archive_checksums_digest: String,
    pub package_manifest_digest: String,
    pub third_party_licenses_digest: String,
    pub license_policy_tool: PublicReadinessToolIdentity,
    pub vulnerability_scanner: PublicReadinessToolIdentity,
    pub assets: Vec<PublicAssetEvidence>,
    pub dependencies: Vec<PublicDependencyEvidence>,
    pub targets: Vec<PublicTargetEvidence>,
    pub asset_inventory_digest: String,
    pub dependency_inventory_digest: String,
    pub target_inventory_digest: String,
    pub findings: Vec<PublicProvenanceFinding>,
    pub finding_summary: PublicReadinessFindingSummary,
    pub decision: PublicReadinessDecision,
    pub evidence_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicProvenanceExpectedState {
    pub candidate_commit: String,
    pub release_artifacts_digest: String,
    pub archive_checksums_digest: String,
    pub package_manifest_digest: String,
    pub third_party_licenses_digest: String,
    pub target_sbom_digests: BTreeMap<String, String>,
    pub target_license_report_digests: BTreeMap<String, String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicProvenanceRejectionReason {
    ArtifactClosureStale,
    CandidateStateStale,
    InvalidReviewPackage,
    LicenseReportStale,
    ReviewPackageTampered,
    SbomStale,
    UnresolvedFinding,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublicProvenanceEvaluation {
    pub schema_version: String,
    pub decision: PublicReadinessDecision,
    pub review_package_digest: String,
    pub reasons: Vec<PublicProvenanceRejectionReason>,
}

pub fn public_license_policy_identity() -> PublicReadinessToolIdentity {
    PublicReadinessToolIdentity {
        name: PUBLIC_LICENSE_POLICY_NAME.into(),
        version: PUBLIC_LICENSE_POLICY_VERSION.into(),
        acquisition_digest: digest_bytes(
            b"depgraph-public-license-policy-v1\nimplementation=compiled-rust\nnetwork=disabled\n",
        ),
        configuration_digest: digest_bytes(
            b"depgraph-public-license-policy-v1\nunknown=reject\nforbidden=reject\nmissing-notice=reject\n",
        ),
    }
}

pub fn public_vulnerability_scanner_identity() -> PublicReadinessToolIdentity {
    PublicReadinessToolIdentity {
        name: PUBLIC_VULNERABILITY_SCANNER_NAME.into(),
        version: PUBLIC_VULNERABILITY_SCANNER_VERSION.into(),
        acquisition_digest: digest_bytes(
            b"depgraph-public-vulnerability-scanner-v1\nimplementation=compiled-rust\nnetwork=disabled\n",
        ),
        configuration_digest: digest_bytes(
            b"depgraph-public-vulnerability-policy-v1\ncritical=reject\nhigh=reject\nmedium=allow-with-record\nlow=allow-with-record\n",
        ),
    }
}

pub fn build_public_provenance_review_package(
    input: &PublicProvenanceAuditInput,
) -> Result<PublicProvenanceReviewPackage> {
    validate_input(input)?;
    let mut assets = input
        .assets
        .iter()
        .map(asset_evidence)
        .collect::<Result<Vec<_>>>()?;
    assets.sort_by(|left, right| left.id.cmp(&right.id));
    let mut dependencies = input
        .dependencies
        .iter()
        .map(dependency_evidence)
        .collect::<Result<Vec<_>>>()?;
    dependencies.sort_by(|left, right| left.id.cmp(&right.id));
    let targets = input
        .targets
        .iter()
        .map(|target| PublicTargetEvidence {
            target: target.target.clone(),
            archive_digest: target.archive_digest.clone(),
            sbom_digest: target.sbom_digest.clone(),
            license_report_digest: target.license_report_digest.clone(),
        })
        .collect::<Vec<_>>();
    let findings = expected_findings(&assets, &dependencies);
    let unresolved = findings.len().try_into().unwrap_or(u32::MAX);
    let mut package = PublicProvenanceReviewPackage {
        schema_version: PUBLIC_PROVENANCE_REVIEW_SCHEMA_VERSION.into(),
        candidate_commit: input.candidate_commit.clone(),
        release_artifacts_digest: input.release_artifacts_digest.clone(),
        archive_checksums_digest: input.archive_checksums_digest.clone(),
        package_manifest_digest: input.package_manifest_digest.clone(),
        third_party_licenses_digest: input.third_party_licenses_digest.clone(),
        license_policy_tool: public_license_policy_identity(),
        vulnerability_scanner: public_vulnerability_scanner_identity(),
        asset_inventory_digest: canonical_public_readiness_digest(&assets)?,
        dependency_inventory_digest: canonical_public_readiness_digest(&dependencies)?,
        target_inventory_digest: canonical_public_readiness_digest(&targets)?,
        assets,
        dependencies,
        targets,
        finding_summary: PublicReadinessFindingSummary {
            resolved: 0,
            unresolved,
        },
        decision: if findings.is_empty() {
            PublicReadinessDecision::Allow
        } else {
            PublicReadinessDecision::Reject
        },
        findings,
        evidence_digest: String::new(),
    };
    package.evidence_digest = package_digest(&package)?;
    Ok(package)
}

pub fn evaluate_public_provenance_review(
    package: &PublicProvenanceReviewPackage,
    expected: &PublicProvenanceExpectedState,
) -> Result<PublicProvenanceEvaluation> {
    let review_package_digest = canonical_public_readiness_digest(package)?;
    let mut reasons = BTreeSet::new();
    if validate_package(package).is_err() {
        reasons.insert(PublicProvenanceRejectionReason::InvalidReviewPackage);
    }
    if package.evidence_digest != package_digest(package)? {
        reasons.insert(PublicProvenanceRejectionReason::ReviewPackageTampered);
    }
    if package.candidate_commit != expected.candidate_commit {
        reasons.insert(PublicProvenanceRejectionReason::CandidateStateStale);
    }
    if package.release_artifacts_digest != expected.release_artifacts_digest
        || package.archive_checksums_digest != expected.archive_checksums_digest
        || package.package_manifest_digest != expected.package_manifest_digest
        || package.third_party_licenses_digest != expected.third_party_licenses_digest
    {
        reasons.insert(PublicProvenanceRejectionReason::ArtifactClosureStale);
    }
    let target_by_name = package
        .targets
        .iter()
        .map(|target| (target.target.as_str(), target))
        .collect::<BTreeMap<_, _>>();
    if expected.target_sbom_digests.len() != PUBLIC_RELEASE_TARGETS.len()
        || PUBLIC_RELEASE_TARGETS.iter().any(|target| {
            target_by_name
                .get(target)
                .zip(expected.target_sbom_digests.get(*target))
                .is_none_or(|(actual, expected)| actual.sbom_digest != *expected)
        })
    {
        reasons.insert(PublicProvenanceRejectionReason::SbomStale);
    }
    if expected.target_license_report_digests.len() != PUBLIC_RELEASE_TARGETS.len()
        || PUBLIC_RELEASE_TARGETS.iter().any(|target| {
            target_by_name
                .get(target)
                .zip(expected.target_license_report_digests.get(*target))
                .is_none_or(|(actual, expected)| actual.license_report_digest != *expected)
        })
    {
        reasons.insert(PublicProvenanceRejectionReason::LicenseReportStale);
    }
    if package.decision != PublicReadinessDecision::Allow
        || package.finding_summary.unresolved != 0
        || !package.findings.is_empty()
    {
        reasons.insert(PublicProvenanceRejectionReason::UnresolvedFinding);
    }
    let reasons = reasons.into_iter().collect::<Vec<_>>();
    Ok(PublicProvenanceEvaluation {
        schema_version: PUBLIC_PROVENANCE_EVALUATION_SCHEMA_VERSION.into(),
        decision: if reasons.is_empty() {
            PublicReadinessDecision::Allow
        } else {
            PublicReadinessDecision::Reject
        },
        review_package_digest,
        reasons,
    })
}

fn validate_input(input: &PublicProvenanceAuditInput) -> Result<()> {
    if !is_lower_hex(&input.candidate_commit, 40)
        || !is_digest(&input.release_artifacts_digest)
        || !is_digest(&input.archive_checksums_digest)
        || !is_digest(&input.package_manifest_digest)
        || !is_digest(&input.third_party_licenses_digest)
    {
        bail!("public provenance candidate or artifact closure is malformed");
    }
    if input.assets.is_empty() || input.assets.len() > MAX_PUBLIC_PROVENANCE_ASSETS {
        bail!("public provenance asset inventory is empty or exceeds its bound");
    }
    if input.dependencies.is_empty()
        || input.dependencies.len() > MAX_PUBLIC_PROVENANCE_DEPENDENCIES
    {
        bail!("public provenance dependency inventory is empty or exceeds its bound");
    }
    let mut prior_asset = None;
    for asset in &input.assets {
        let key = (asset.kind, asset.portable_locator.as_str());
        if prior_asset.is_some_and(|prior| prior >= key)
            || !valid_portable_locator(&asset.portable_locator)
            || !valid_license_expression(&asset.license_expression)
            || (asset.present != asset.content_digest.is_some())
            || asset
                .content_digest
                .as_deref()
                .is_some_and(|digest| !is_digest(digest))
            || asset
                .notice_digest
                .as_deref()
                .is_some_and(|digest| !is_digest(digest))
        {
            bail!("public provenance asset inventory is malformed or noncanonical");
        }
        prior_asset = Some(key);
    }
    let mut prior_dependency = None;
    for dependency in &input.dependencies {
        let key = (
            dependency.ecosystem,
            dependency.target.as_str(),
            dependency.package_url.as_str(),
        );
        if prior_dependency.is_some_and(|prior| prior >= key)
            || (dependency.target != "all"
                && !PUBLIC_RELEASE_TARGETS.contains(&dependency.target.as_str()))
            || !valid_package_url(&dependency.package_url)
            || !is_digest(&dependency.component_digest)
            || !valid_license_expression(&dependency.license_expression)
            || dependency
                .notice_digest
                .as_deref()
                .is_some_and(|digest| !is_digest(digest))
        {
            bail!("public provenance dependency inventory is malformed or noncanonical");
        }
        prior_dependency = Some(key);
    }
    if input
        .targets
        .iter()
        .map(|target| target.target.as_str())
        .ne(PUBLIC_RELEASE_TARGETS)
        || input.targets.iter().any(|target| {
            !is_digest(&target.archive_digest)
                || !is_digest(&target.sbom_digest)
                || !is_digest(&target.license_report_digest)
        })
    {
        bail!("public provenance target inventory must cover the exact five release targets");
    }
    Ok(())
}

fn validate_package(package: &PublicProvenanceReviewPackage) -> Result<()> {
    if package.assets.is_empty()
        || package.assets.len() > MAX_PUBLIC_PROVENANCE_ASSETS
        || package.dependencies.is_empty()
        || package.dependencies.len() > MAX_PUBLIC_PROVENANCE_DEPENDENCIES
    {
        bail!("public provenance review package inventory is empty or exceeds its bound");
    }
    let expected = expected_findings(&package.assets, &package.dependencies);
    if package.schema_version != PUBLIC_PROVENANCE_REVIEW_SCHEMA_VERSION
        || !is_lower_hex(&package.candidate_commit, 40)
        || !is_digest(&package.release_artifacts_digest)
        || !is_digest(&package.archive_checksums_digest)
        || !is_digest(&package.package_manifest_digest)
        || !is_digest(&package.third_party_licenses_digest)
        || package.license_policy_tool != public_license_policy_identity()
        || package.vulnerability_scanner != public_vulnerability_scanner_identity()
        || package.asset_inventory_digest != canonical_public_readiness_digest(&package.assets)?
        || package.dependency_inventory_digest
            != canonical_public_readiness_digest(&package.dependencies)?
        || package.target_inventory_digest != canonical_public_readiness_digest(&package.targets)?
        || package.findings != expected
        || package.finding_summary.resolved != 0
        || package.finding_summary.unresolved as usize != package.findings.len()
        || package.decision
            != if package.findings.is_empty() {
                PublicReadinessDecision::Allow
            } else {
                PublicReadinessDecision::Reject
            }
        || package
            .assets
            .windows(2)
            .any(|pair| pair[0].id >= pair[1].id)
        || package
            .dependencies
            .windows(2)
            .any(|pair| pair[0].id >= pair[1].id)
        || package
            .targets
            .iter()
            .map(|target| target.target.as_str())
            .ne(PUBLIC_RELEASE_TARGETS)
        || package.assets.iter().any(invalid_asset_evidence)
        || package.dependencies.iter().any(invalid_dependency_evidence)
        || package.targets.iter().any(|target| {
            !is_digest(&target.archive_digest)
                || !is_digest(&target.sbom_digest)
                || !is_digest(&target.license_report_digest)
        })
    {
        bail!("public provenance review package is malformed or tampered");
    }
    Ok(())
}

fn asset_evidence(input: &PublicAssetAuditInput) -> Result<PublicAssetEvidence> {
    let locator_digest = digest_bytes(input.portable_locator.as_bytes());
    let license_expression_digest = digest_bytes(input.license_expression.as_bytes());
    let id = canonical_public_readiness_digest(&json!({
        "contract": PUBLIC_PROVENANCE_REVIEW_SCHEMA_VERSION,
        "kind": input.kind,
        "locator_digest": locator_digest,
        "content_digest": input.content_digest,
        "license_expression_digest": license_expression_digest,
    }))?;
    Ok(PublicAssetEvidence {
        id,
        kind: input.kind,
        locator_digest,
        license_expression_digest,
        content_digest: input.content_digest.clone(),
        present: input.present,
        provenance: input.provenance,
        license_policy: input.license_policy,
        notice_required: input.notice_required,
        notice_digest: input.notice_digest.clone(),
    })
}

fn dependency_evidence(input: &PublicDependencyAuditInput) -> Result<PublicDependencyEvidence> {
    let package_url_digest = digest_bytes(input.package_url.as_bytes());
    let license_expression_digest = digest_bytes(input.license_expression.as_bytes());
    let id = canonical_public_readiness_digest(&json!({
        "contract": PUBLIC_PROVENANCE_REVIEW_SCHEMA_VERSION,
        "ecosystem": input.ecosystem,
        "target": input.target,
        "package_url_digest": package_url_digest,
        "component_digest": input.component_digest,
        "license_expression_digest": license_expression_digest,
    }))?;
    Ok(PublicDependencyEvidence {
        id,
        ecosystem: input.ecosystem,
        target: input.target.clone(),
        package_url_digest,
        component_digest: input.component_digest.clone(),
        license_expression_digest,
        provenance: input.provenance,
        license_policy: input.license_policy,
        notice_required: input.notice_required,
        notice_digest: input.notice_digest.clone(),
        maximum_vulnerability: input.maximum_vulnerability,
    })
}

fn expected_findings(
    assets: &[PublicAssetEvidence],
    dependencies: &[PublicDependencyEvidence],
) -> Vec<PublicProvenanceFinding> {
    let mut findings = Vec::new();
    for asset in assets {
        if !asset.present {
            add_finding(
                &mut findings,
                &asset.id,
                PublicProvenanceFindingReason::MissingAsset,
            );
        }
        add_policy_findings(
            &mut findings,
            &asset.id,
            asset.provenance,
            asset.license_policy,
            asset.notice_required,
            asset.notice_digest.as_deref(),
            PublicVulnerabilitySeverity::Clean,
        );
    }
    for dependency in dependencies {
        add_policy_findings(
            &mut findings,
            &dependency.id,
            dependency.provenance,
            dependency.license_policy,
            dependency.notice_required,
            dependency.notice_digest.as_deref(),
            dependency.maximum_vulnerability,
        );
    }
    findings.sort_by(|left, right| left.id.cmp(&right.id));
    findings
}

fn add_policy_findings(
    findings: &mut Vec<PublicProvenanceFinding>,
    subject_digest: &str,
    provenance: PublicProvenanceState,
    license_policy: PublicLicensePolicyState,
    notice_required: bool,
    notice_digest: Option<&str>,
    severity: PublicVulnerabilitySeverity,
) {
    if provenance == PublicProvenanceState::Unresolved {
        add_finding(
            findings,
            subject_digest,
            PublicProvenanceFindingReason::UnresolvedProvenance,
        );
    }
    match license_policy {
        PublicLicensePolicyState::Allowed => {}
        PublicLicensePolicyState::Forbidden => add_finding(
            findings,
            subject_digest,
            PublicProvenanceFindingReason::ForbiddenLicense,
        ),
        PublicLicensePolicyState::Unknown => add_finding(
            findings,
            subject_digest,
            PublicProvenanceFindingReason::UnknownLicense,
        ),
    }
    if notice_required && notice_digest.is_none() {
        add_finding(
            findings,
            subject_digest,
            PublicProvenanceFindingReason::MissingNotice,
        );
    }
    match severity {
        PublicVulnerabilitySeverity::Critical => add_finding(
            findings,
            subject_digest,
            PublicProvenanceFindingReason::CriticalVulnerability,
        ),
        PublicVulnerabilitySeverity::High => add_finding(
            findings,
            subject_digest,
            PublicProvenanceFindingReason::HighVulnerability,
        ),
        PublicVulnerabilitySeverity::Clean
        | PublicVulnerabilitySeverity::Low
        | PublicVulnerabilitySeverity::Medium => {}
    }
}

fn add_finding(
    findings: &mut Vec<PublicProvenanceFinding>,
    subject_digest: &str,
    reason: PublicProvenanceFindingReason,
) {
    findings.push(PublicProvenanceFinding {
        id: digest_bytes(
            canonical_json(&json!({
                "contract": PUBLIC_PROVENANCE_REVIEW_SCHEMA_VERSION,
                "subject_digest": subject_digest,
                "reason": reason,
            }))
            .as_bytes(),
        ),
        subject_digest: subject_digest.into(),
        reason,
    });
}

fn invalid_asset_evidence(asset: &PublicAssetEvidence) -> bool {
    !is_digest(&asset.id)
        || !is_digest(&asset.locator_digest)
        || !is_digest(&asset.license_expression_digest)
        || asset.id
            != canonical_public_readiness_digest(&json!({
                "contract": PUBLIC_PROVENANCE_REVIEW_SCHEMA_VERSION,
                "kind": asset.kind,
                "locator_digest": asset.locator_digest,
                "content_digest": asset.content_digest,
                "license_expression_digest": asset.license_expression_digest,
            }))
            .unwrap_or_default()
        || (asset.present != asset.content_digest.is_some())
        || asset
            .content_digest
            .as_deref()
            .is_some_and(|digest| !is_digest(digest))
        || asset
            .notice_digest
            .as_deref()
            .is_some_and(|digest| !is_digest(digest))
}

fn invalid_dependency_evidence(dependency: &PublicDependencyEvidence) -> bool {
    !is_digest(&dependency.id)
        || !is_digest(&dependency.package_url_digest)
        || !is_digest(&dependency.component_digest)
        || !is_digest(&dependency.license_expression_digest)
        || dependency.id
            != canonical_public_readiness_digest(&json!({
                "contract": PUBLIC_PROVENANCE_REVIEW_SCHEMA_VERSION,
                "ecosystem": dependency.ecosystem,
                "target": dependency.target,
                "package_url_digest": dependency.package_url_digest,
                "component_digest": dependency.component_digest,
                "license_expression_digest": dependency.license_expression_digest,
            }))
            .unwrap_or_default()
        || (dependency.target != "all"
            && !PUBLIC_RELEASE_TARGETS.contains(&dependency.target.as_str()))
        || dependency
            .notice_digest
            .as_deref()
            .is_some_and(|digest| !is_digest(digest))
}

fn package_digest(package: &PublicProvenanceReviewPackage) -> Result<String> {
    let mut value = serde_json::to_value(package)?;
    value["evidence_digest"] = json!("");
    canonical_public_readiness_digest(&value)
}

fn digest_bytes(value: &[u8]) -> String {
    hex::encode(Sha256::digest(value))
}

fn is_digest(value: &str) -> bool {
    is_lower_hex(value, 64)
}

fn is_lower_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
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

fn valid_package_url(value: &str) -> bool {
    value.starts_with("pkg:")
        && value.len() <= 1_024
        && !value.bytes().any(|byte| byte.is_ascii_whitespace())
}

fn valid_license_expression(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b' ' | b'-' | b'.' | b'+' | b'(' | b')' | b'/')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";
    const HASH_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const HASH_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const HASH_C: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    const HASH_D: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
    const HASH_E: &str = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";

    fn fixture() -> (PublicProvenanceAuditInput, PublicProvenanceExpectedState) {
        let targets = PUBLIC_RELEASE_TARGETS
            .iter()
            .enumerate()
            .map(|(index, target)| PublicTargetAuditInput {
                target: (*target).into(),
                archive_digest: format!("{:064x}", index + 1),
                sbom_digest: format!("{:064x}", index + 11),
                license_report_digest: format!("{:064x}", index + 21),
            })
            .collect::<Vec<_>>();
        let input = PublicProvenanceAuditInput {
            candidate_commit: COMMIT.into(),
            release_artifacts_digest: HASH_A.into(),
            archive_checksums_digest: HASH_B.into(),
            package_manifest_digest: HASH_C.into(),
            third_party_licenses_digest: HASH_D.into(),
            assets: vec![
                PublicAssetAuditInput {
                    kind: PublicAssetKind::ProjectSource,
                    portable_locator: "crates/depgraph-core/src/lib.rs".into(),
                    present: true,
                    content_digest: Some(HASH_A.into()),
                    provenance: PublicProvenanceState::Authorized,
                    license_expression: "MIT OR Apache-2.0".into(),
                    license_policy: PublicLicensePolicyState::Allowed,
                    notice_required: false,
                    notice_digest: None,
                },
                PublicAssetAuditInput {
                    kind: PublicAssetKind::VendorSource,
                    portable_locator: "workers/web/vendor/runtime.js".into(),
                    present: true,
                    content_digest: Some(HASH_B.into()),
                    provenance: PublicProvenanceState::Authorized,
                    license_expression: "MIT".into(),
                    license_policy: PublicLicensePolicyState::Allowed,
                    notice_required: true,
                    notice_digest: Some(HASH_E.into()),
                },
            ],
            dependencies: vec![
                PublicDependencyAuditInput {
                    ecosystem: PublicDependencyEcosystem::Rust,
                    target: "all".into(),
                    package_url: "pkg:cargo/anyhow@1.0.102".into(),
                    component_digest: HASH_C.into(),
                    provenance: PublicProvenanceState::Authorized,
                    license_expression: "MIT OR Apache-2.0".into(),
                    license_policy: PublicLicensePolicyState::Allowed,
                    notice_required: false,
                    notice_digest: None,
                    maximum_vulnerability: PublicVulnerabilitySeverity::Clean,
                },
                PublicDependencyAuditInput {
                    ecosystem: PublicDependencyEcosystem::Web,
                    target: "all".into(),
                    package_url: "pkg:npm/typescript@7.0.2".into(),
                    component_digest: HASH_D.into(),
                    provenance: PublicProvenanceState::Authorized,
                    license_expression: "Apache-2.0".into(),
                    license_policy: PublicLicensePolicyState::Allowed,
                    notice_required: true,
                    notice_digest: Some(HASH_E.into()),
                    maximum_vulnerability: PublicVulnerabilitySeverity::Medium,
                },
            ],
            targets,
        };
        let expected = PublicProvenanceExpectedState {
            candidate_commit: COMMIT.into(),
            release_artifacts_digest: HASH_A.into(),
            archive_checksums_digest: HASH_B.into(),
            package_manifest_digest: HASH_C.into(),
            third_party_licenses_digest: HASH_D.into(),
            target_sbom_digests: input
                .targets
                .iter()
                .map(|target| (target.target.clone(), target.sbom_digest.clone()))
                .collect(),
            target_license_report_digests: input
                .targets
                .iter()
                .map(|target| (target.target.clone(), target.license_report_digest.clone()))
                .collect(),
        };
        (input, expected)
    }

    #[test]
    fn exact_candidate_five_target_review_package_is_checkout_independent() {
        let (input, expected) = fixture();
        let package_a = build_public_provenance_review_package(&input).unwrap();
        let package_b = build_public_provenance_review_package(&input.clone()).unwrap();
        assert_eq!(package_a, package_b);
        assert_eq!(package_a.targets.len(), 5);
        assert_eq!(
            evaluate_public_provenance_review(&package_a, &expected)
                .unwrap()
                .decision,
            PublicReadinessDecision::Allow
        );
    }

    #[test]
    fn stale_sbom_and_license_report_are_rejected() {
        let (input, mut expected) = fixture();
        let package = build_public_provenance_review_package(&input).unwrap();
        expected
            .target_sbom_digests
            .insert(PUBLIC_RELEASE_TARGETS[0].into(), HASH_E.into());
        expected
            .target_license_report_digests
            .insert(PUBLIC_RELEASE_TARGETS[1].into(), HASH_A.into());
        let evaluation = evaluate_public_provenance_review(&package, &expected).unwrap();
        assert_eq!(evaluation.decision, PublicReadinessDecision::Reject);
        assert!(
            evaluation
                .reasons
                .contains(&PublicProvenanceRejectionReason::SbomStale)
        );
        assert!(
            evaluation
                .reasons
                .contains(&PublicProvenanceRejectionReason::LicenseReportStale)
        );
    }

    #[test]
    fn missing_asset_license_drift_notice_and_high_vulnerability_block_allow() {
        let (mut input, expected) = fixture();
        input.assets[0].present = false;
        input.assets[0].content_digest = None;
        input.assets[1].notice_digest = None;
        input.dependencies[0].license_policy = PublicLicensePolicyState::Forbidden;
        input.dependencies[1].maximum_vulnerability = PublicVulnerabilitySeverity::High;
        let package = build_public_provenance_review_package(&input).unwrap();
        let reasons = package
            .findings
            .iter()
            .map(|finding| finding.reason)
            .collect::<BTreeSet<_>>();
        assert!(reasons.contains(&PublicProvenanceFindingReason::MissingAsset));
        assert!(reasons.contains(&PublicProvenanceFindingReason::MissingNotice));
        assert!(reasons.contains(&PublicProvenanceFindingReason::ForbiddenLicense));
        assert!(reasons.contains(&PublicProvenanceFindingReason::HighVulnerability));
        assert_eq!(
            evaluate_public_provenance_review(&package, &expected)
                .unwrap()
                .decision,
            PublicReadinessDecision::Reject
        );
    }

    #[test]
    fn malformed_target_inventory_and_absolute_asset_path_fail_closed() {
        let (mut input, _) = fixture();
        input.targets.pop();
        assert!(build_public_provenance_review_package(&input).is_err());
        let (mut input, _) = fixture();
        input.assets[0].portable_locator = "/private/checkout/src/lib.rs".into();
        assert!(build_public_provenance_review_package(&input).is_err());
    }

    #[test]
    fn evaluator_rejects_a_rehashed_empty_inventory() {
        let (input, expected) = fixture();
        let mut package = build_public_provenance_review_package(&input).unwrap();
        package.assets.clear();
        package.dependencies.clear();
        package.asset_inventory_digest =
            canonical_public_readiness_digest(&package.assets).unwrap();
        package.dependency_inventory_digest =
            canonical_public_readiness_digest(&package.dependencies).unwrap();
        package.findings.clear();
        package.finding_summary = PublicReadinessFindingSummary {
            resolved: 0,
            unresolved: 0,
        };
        package.decision = PublicReadinessDecision::Allow;
        package.evidence_digest = package_digest(&package).unwrap();

        let evaluation = evaluate_public_provenance_review(&package, &expected).unwrap();
        assert_eq!(evaluation.decision, PublicReadinessDecision::Reject);
        assert!(
            evaluation
                .reasons
                .contains(&PublicProvenanceRejectionReason::InvalidReviewPackage)
        );
    }
}
