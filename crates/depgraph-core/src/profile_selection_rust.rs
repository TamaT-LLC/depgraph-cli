use std::collections::BTreeMap;

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

use crate::{
    CanonicalProfileAxes, ProfileAxis, ProfileCandidateCoverage, ProfileCandidateDiscoveryResult,
    ProfileCandidateEvidence, ProfileCandidateKind, ProfileCandidateRecord, ProfileExclusionReason,
    ProfileLanguage, ProfilePolicyExclusion, ProfileSelectionProfile, RustProfileAxes,
    RustProfileMode, bound_profile_candidate_discovery, canonical_profile_id, profile_candidate_id,
    profile_exclusion_id,
};

pub const RUST_PROFILE_PLANNING_VERSION: &str = "rust-profile-planning-v1";

const MAX_RUST_TARGET_DECLARATIONS: usize = 4_096;
const MAX_RUST_FEATURE_DECLARATIONS: usize = 65_536;
const MAX_RUST_REJECTED_DECLARATIONS: usize = 4_096;
const MAX_RUST_FEATURE_CLOSURE: usize = 4_096;
const MAX_RUST_POLICY_EXCLUSIONS: usize = 512;
const MAX_AXIS_VALUE_CHARS: usize = 256;
const MAX_PACKAGE_LOCATOR_CHARS: usize = 512;
const MAX_EVIDENCE_ITEMS: usize = 65_536;
const MAX_EVIDENCE_PATH_CHARS: usize = 4_096;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RustProfileAvailability {
    Available,
    Unavailable,
    Unsupported,
}

impl RustProfileAvailability {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Available => "available",
            Self::Unavailable => "unavailable",
            Self::Unsupported => "unsupported",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RustStaticProfileEvidence {
    pub estimated_coverage: ProfileCandidateCoverage,
    pub evidence: Vec<ProfileCandidateEvidence>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RustTargetDeclaration {
    pub target: String,
    pub repository_default: bool,
    pub availability: RustProfileAvailability,
    pub static_evidence: RustStaticProfileEvidence,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RustProfileAlternativeDeclaration {
    pub availability: RustProfileAvailability,
    pub static_evidence: RustStaticProfileEvidence,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RustRootFeatureDeclaration {
    pub package_locator: String,
    pub root_feature: String,
    pub feature_closure: Vec<String>,
    pub availability: RustProfileAvailability,
    pub static_evidence: RustStaticProfileEvidence,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RustAutomaticBoundaryKind {
    AllFeatures,
    CartesianCombination,
    BuildProfile,
    RuntimeProfile,
    DynamicConfiguration,
    MalformedDeclaration,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RustRejectedProfileDeclaration {
    pub kind: RustAutomaticBoundaryKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub axis: Option<ProfileAxis>,
    pub axis_values: Vec<String>,
    pub evidence: Vec<ProfileCandidateEvidence>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RustProfilePlanningInput {
    pub planning_version: String,
    pub host_target: String,
    pub host_availability: RustProfileAvailability,
    pub baseline: RustStaticProfileEvidence,
    pub targets: Vec<RustTargetDeclaration>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub test_mode: Option<RustProfileAlternativeDeclaration>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub no_default_features: Option<RustProfileAlternativeDeclaration>,
    pub root_features: Vec<RustRootFeatureDeclaration>,
    pub rejected: Vec<RustRejectedProfileDeclaration>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RustProfileCandidateGenerationResult {
    pub bounded: ProfileCandidateDiscoveryResult,
    pub policy_excluded: Vec<ProfilePolicyExclusion>,
    pub policy_exclusion_overflow_count: u32,
    pub complete: bool,
    pub baseline_profile_id: String,
}

pub fn generate_rust_profile_candidates(
    mut input: RustProfilePlanningInput,
) -> Result<RustProfileCandidateGenerationResult> {
    if input.planning_version != RUST_PROFILE_PLANNING_VERSION {
        bail!(
            "unsupported Rust profile planning version; expected {RUST_PROFILE_PLANNING_VERSION}"
        );
    }
    if input.targets.len() > MAX_RUST_TARGET_DECLARATIONS
        || input.root_features.len() > MAX_RUST_FEATURE_DECLARATIONS
        || input.rejected.len() > MAX_RUST_REJECTED_DECLARATIONS
    {
        bail!("Rust profile planning input exceeds a closed declaration limit");
    }
    validate_portable_axis_value("Rust host target", &input.host_target)?;
    canonicalize_static_evidence(&mut input.baseline)?;

    let targets = canonical_targets(input.targets)?;
    let default_targets = targets
        .values()
        .filter(|target| target.repository_default)
        .collect::<Vec<_>>();
    let (baseline_target, baseline_availability) = if default_targets.len() == 1 {
        (
            default_targets[0].target.clone(),
            default_targets[0].availability,
        )
    } else {
        (input.host_target.clone(), input.host_availability)
    };

    let mut baseline_evidence = input.baseline;
    for target in targets
        .values()
        .filter(|target| target.target == baseline_target)
    {
        merge_static_evidence(&mut baseline_evidence, target.static_evidence.clone());
    }
    canonicalize_static_evidence(&mut baseline_evidence)?;

    let baseline_axes = RustProfileAxes {
        target: baseline_target.clone(),
        mode: RustProfileMode::Check,
        default_features: true,
        features: Vec::new(),
    };
    let baseline_profile = profile(baseline_axes.clone());
    let baseline_profile_id = baseline_profile.id.clone();
    let baseline_candidate = candidate(
        &baseline_profile,
        &baseline_profile_id,
        ProfileCandidateKind::Baseline,
        None,
        Vec::new(),
        baseline_evidence.clone(),
    );

    let mut profiles = vec![baseline_profile.clone()];
    let mut candidates = vec![baseline_candidate];
    let mut exclusions = Vec::new();
    if baseline_availability != RustProfileAvailability::Available {
        exclusions.push(availability_exclusion(
            Some(ProfileAxis::Target),
            vec![baseline_target.clone()],
            baseline_availability,
            baseline_evidence.evidence.clone(),
        ));
    }

    for target in targets.into_values() {
        if target.target == baseline_target {
            continue;
        }
        let axis_values = vec![target.target.clone()];
        if target.availability != RustProfileAvailability::Available {
            exclusions.push(availability_exclusion(
                Some(ProfileAxis::Target),
                axis_values,
                target.availability,
                target.static_evidence.evidence,
            ));
            continue;
        }
        let alternative = profile(RustProfileAxes {
            target: target.target.clone(),
            ..baseline_axes.clone()
        });
        candidates.push(candidate(
            &alternative,
            &baseline_profile_id,
            ProfileCandidateKind::Alternative,
            Some(ProfileAxis::Target),
            vec![target.target],
            target.static_evidence,
        ));
        profiles.push(alternative);
    }

    if let Some(mut test_mode) = input.test_mode {
        canonicalize_static_evidence(&mut test_mode.static_evidence)?;
        let axis_values = vec![RustProfileMode::Test.as_str().to_owned()];
        if test_mode.availability == RustProfileAvailability::Available {
            let alternative = profile(RustProfileAxes {
                mode: RustProfileMode::Test,
                ..baseline_axes.clone()
            });
            candidates.push(candidate(
                &alternative,
                &baseline_profile_id,
                ProfileCandidateKind::Alternative,
                Some(ProfileAxis::Mode),
                axis_values,
                test_mode.static_evidence,
            ));
            profiles.push(alternative);
        } else {
            exclusions.push(availability_exclusion(
                Some(ProfileAxis::Mode),
                axis_values,
                test_mode.availability,
                test_mode.static_evidence.evidence,
            ));
        }
    }

    if let Some(mut no_default) = input.no_default_features {
        canonicalize_static_evidence(&mut no_default.static_evidence)?;
        let axes = RustProfileAxes {
            default_features: false,
            ..baseline_axes.clone()
        };
        let axis_values = rust_feature_axis_values(&axes);
        if no_default.availability == RustProfileAvailability::Available {
            let alternative = profile(axes);
            candidates.push(candidate(
                &alternative,
                &baseline_profile_id,
                ProfileCandidateKind::Alternative,
                Some(ProfileAxis::FeatureOrTag),
                axis_values,
                no_default.static_evidence,
            ));
            profiles.push(alternative);
        } else {
            exclusions.push(availability_exclusion(
                Some(ProfileAxis::FeatureOrTag),
                axis_values,
                no_default.availability,
                no_default.static_evidence.evidence,
            ));
        }
    }

    let mut root_features = input.root_features;
    for feature in &mut root_features {
        validate_package_locator(&feature.package_locator)?;
        validate_portable_axis_value("Rust root feature", &feature.root_feature)?;
        if feature.root_feature == "default" {
            bail!("Rust root feature alternatives cannot repeat the default feature closure");
        }
        if feature.feature_closure.len() > MAX_RUST_FEATURE_CLOSURE {
            bail!("Rust feature closure exceeds its closed item limit");
        }
        for value in &feature.feature_closure {
            validate_portable_axis_value("Rust feature closure value", value)?;
        }
        feature
            .feature_closure
            .sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
        feature.feature_closure.dedup();
        if !feature.feature_closure.contains(&feature.root_feature) {
            bail!("Rust feature closure must contain its declared root feature");
        }
        if feature
            .feature_closure
            .iter()
            .any(|value| value == "default")
        {
            bail!("Rust root feature closure must not synthesize the default feature");
        }
        canonicalize_static_evidence(&mut feature.static_evidence)?;
    }
    root_features.sort_by(|left, right| {
        left.package_locator
            .as_bytes()
            .cmp(right.package_locator.as_bytes())
            .then(
                left.root_feature
                    .as_bytes()
                    .cmp(right.root_feature.as_bytes()),
            )
            .then(left.feature_closure.cmp(&right.feature_closure))
    });

    for feature in root_features {
        let axes = RustProfileAxes {
            features: feature.feature_closure,
            ..baseline_axes.clone()
        };
        let axis_values = rust_feature_axis_values(&axes);
        if feature.availability != RustProfileAvailability::Available {
            exclusions.push(availability_exclusion(
                Some(ProfileAxis::FeatureOrTag),
                axis_values,
                feature.availability,
                feature.static_evidence.evidence,
            ));
            continue;
        }
        let alternative = profile(axes);
        candidates.push(candidate(
            &alternative,
            &baseline_profile_id,
            ProfileCandidateKind::Alternative,
            Some(ProfileAxis::FeatureOrTag),
            axis_values,
            feature.static_evidence,
        ));
        profiles.push(alternative);
    }

    for mut rejected in input.rejected {
        canonicalize_evidence(&mut rejected.evidence)?;
        for value in &rejected.axis_values {
            validate_axis_value("Rust rejected axis value", value)?;
        }
        rejected
            .axis_values
            .sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
        rejected.axis_values.dedup();
        let (reason, expected_axis) = rejection_reason(rejected.kind);
        if expected_axis.is_some() && rejected.axis != expected_axis {
            bail!("Rust rejected automatic boundary uses an incompatible axis");
        }
        exclusions.push(exclusion(
            rejected.axis,
            rejected.axis_values,
            reason,
            rejected.evidence,
        ));
    }

    exclusions.sort_by(|left, right| left.id.as_bytes().cmp(right.id.as_bytes()));
    exclusions.dedup_by(|left, right| left.id == right.id);
    let policy_exclusion_overflow_count =
        u32::try_from(exclusions.len().saturating_sub(MAX_RUST_POLICY_EXCLUSIONS))?;
    exclusions.truncate(MAX_RUST_POLICY_EXCLUSIONS);
    let bounded =
        bound_profile_candidate_discovery(profiles, candidates, &[ProfileLanguage::Rust])?;
    let complete = bounded.complete && policy_exclusion_overflow_count == 0;
    Ok(RustProfileCandidateGenerationResult {
        bounded,
        policy_excluded: exclusions,
        policy_exclusion_overflow_count,
        complete,
        baseline_profile_id,
    })
}

fn canonical_targets(
    mut targets: Vec<RustTargetDeclaration>,
) -> Result<BTreeMap<String, RustTargetDeclaration>> {
    targets.sort_by(|left, right| left.target.as_bytes().cmp(right.target.as_bytes()));
    let mut canonical = BTreeMap::<String, RustTargetDeclaration>::new();
    for mut target in targets {
        validate_portable_axis_value("Rust declared target", &target.target)?;
        canonicalize_static_evidence(&mut target.static_evidence)?;
        if let Some(previous) = canonical.get_mut(&target.target) {
            if previous.availability != target.availability {
                bail!("one Rust target cannot have conflicting availability");
            }
            previous.repository_default |= target.repository_default;
            merge_static_evidence(&mut previous.static_evidence, target.static_evidence);
            canonicalize_static_evidence(&mut previous.static_evidence)?;
        } else {
            canonical.insert(target.target.clone(), target);
        }
    }
    Ok(canonical)
}

fn profile(axes: RustProfileAxes) -> ProfileSelectionProfile {
    let axes = CanonicalProfileAxes::Rust(axes);
    ProfileSelectionProfile {
        id: canonical_profile_id(&axes),
        axes,
    }
}

fn candidate(
    profile: &ProfileSelectionProfile,
    baseline_profile_id: &str,
    kind: ProfileCandidateKind,
    changed_axis: Option<ProfileAxis>,
    axis_values: Vec<String>,
    static_evidence: RustStaticProfileEvidence,
) -> ProfileCandidateRecord {
    let mut candidate = ProfileCandidateRecord {
        id: String::new(),
        profile_id: profile.id.clone(),
        baseline_profile_id: baseline_profile_id.to_owned(),
        kind,
        changed_axis,
        axis_values,
        estimated_coverage: static_evidence.estimated_coverage,
        evidence: static_evidence.evidence,
    };
    candidate.id = profile_candidate_id(&candidate);
    candidate
}

fn rust_feature_axis_values(axes: &RustProfileAxes) -> Vec<String> {
    let mut values = vec![format!("default_features={}", axes.default_features)];
    values.extend(
        axes.features
            .iter()
            .map(|feature| format!("feature={feature}")),
    );
    values
}

fn availability_exclusion(
    axis: Option<ProfileAxis>,
    mut axis_values: Vec<String>,
    availability: RustProfileAvailability,
    evidence: Vec<ProfileCandidateEvidence>,
) -> ProfilePolicyExclusion {
    axis_values.push(format!("availability={}", availability.as_str()));
    axis_values.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    axis_values.dedup();
    exclusion(
        axis,
        axis_values,
        ProfileExclusionReason::DefaultProfileUnsupportedAxis,
        evidence,
    )
}

fn rejection_reason(
    kind: RustAutomaticBoundaryKind,
) -> (ProfileExclusionReason, Option<ProfileAxis>) {
    match kind {
        RustAutomaticBoundaryKind::AllFeatures => (
            ProfileExclusionReason::DefaultProfileCombinationRequiresExplicitSelection,
            Some(ProfileAxis::FeatureOrTag),
        ),
        RustAutomaticBoundaryKind::CartesianCombination => (
            ProfileExclusionReason::DefaultProfileCombinationRequiresExplicitSelection,
            None,
        ),
        RustAutomaticBoundaryKind::BuildProfile => (
            ProfileExclusionReason::DefaultProfileBuildRequiresConsent,
            None,
        ),
        RustAutomaticBoundaryKind::RuntimeProfile => (
            ProfileExclusionReason::DefaultProfileRuntimeRequiresTrace,
            None,
        ),
        RustAutomaticBoundaryKind::DynamicConfiguration => (
            ProfileExclusionReason::DefaultProfileDynamicConfigurationNotExecuted,
            None,
        ),
        RustAutomaticBoundaryKind::MalformedDeclaration => (
            ProfileExclusionReason::DefaultProfileMalformedDeclaration,
            None,
        ),
    }
}

fn exclusion(
    axis: Option<ProfileAxis>,
    axis_values: Vec<String>,
    reason: ProfileExclusionReason,
    evidence: Vec<ProfileCandidateEvidence>,
) -> ProfilePolicyExclusion {
    let affects_completeness = matches!(
        reason,
        ProfileExclusionReason::DefaultProfileDynamicConfigurationNotExecuted
            | ProfileExclusionReason::DefaultProfileUnsupportedAxis
            | ProfileExclusionReason::DefaultProfileMalformedDeclaration
    );
    let mut exclusion = ProfilePolicyExclusion {
        id: String::new(),
        language: ProfileLanguage::Rust,
        axis,
        axis_values,
        reason,
        affects_completeness,
        evidence,
    };
    exclusion.id = profile_exclusion_id(&exclusion);
    exclusion
}

fn canonicalize_static_evidence(evidence: &mut RustStaticProfileEvidence) -> Result<()> {
    evidence
        .estimated_coverage
        .file_ids
        .sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    evidence.estimated_coverage.file_ids.dedup();
    for id in &evidence.estimated_coverage.file_ids {
        validate_stable_id("Rust profile file coverage ID", id, "file")?;
    }
    evidence
        .estimated_coverage
        .dependency_site_ids
        .sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    evidence.estimated_coverage.dependency_site_ids.dedup();
    for id in &evidence.estimated_coverage.dependency_site_ids {
        validate_stable_id("Rust profile dependency-site coverage ID", id, "site")?;
    }
    canonicalize_evidence(&mut evidence.evidence)
}

fn canonicalize_evidence(evidence: &mut Vec<ProfileCandidateEvidence>) -> Result<()> {
    if evidence.is_empty() || evidence.len() > MAX_EVIDENCE_ITEMS {
        bail!("Rust profile evidence must be non-empty and within its closed item limit");
    }
    evidence.sort_by(|left, right| {
        left.path
            .as_bytes()
            .cmp(right.path.as_bytes())
            .then(left.start_line.cmp(&right.start_line))
            .then(left.end_line.cmp(&right.end_line))
            .then(evidence_kind(left).cmp(evidence_kind(right)))
    });
    evidence.dedup();
    for item in evidence {
        validate_repository_path(&item.path)?;
        if item.start_line == 0 || item.end_line < item.start_line {
            bail!("Rust profile evidence line range is invalid");
        }
    }
    Ok(())
}

fn evidence_kind(evidence: &ProfileCandidateEvidence) -> &'static str {
    use crate::ProfileCandidateEvidenceKind::{Config, HostContext, Manifest, Source};
    match evidence.kind {
        Config => "config",
        Manifest => "manifest",
        Source => "source",
        HostContext => "host_context",
    }
}

fn merge_static_evidence(
    target: &mut RustStaticProfileEvidence,
    source: RustStaticProfileEvidence,
) {
    target
        .estimated_coverage
        .file_ids
        .extend(source.estimated_coverage.file_ids);
    target
        .estimated_coverage
        .dependency_site_ids
        .extend(source.estimated_coverage.dependency_site_ids);
    target.evidence.extend(source.evidence);
}

fn validate_portable_axis_value(name: &str, value: &str) -> Result<()> {
    validate_axis_value(name, value)?;
    if value.contains('/') || value.contains('\\') || value.contains(':') {
        bail!("{name} must be a portable non-path value");
    }
    Ok(())
}

fn validate_axis_value(name: &str, value: &str) -> Result<()> {
    if value.is_empty()
        || value.chars().count() > MAX_AXIS_VALUE_CHARS
        || value.trim() != value
        || value.chars().any(char::is_control)
        || value.chars().any(char::is_whitespace)
    {
        bail!("{name} must be non-empty, bounded, trimmed, and free of whitespace or controls");
    }
    Ok(())
}

fn validate_package_locator(value: &str) -> Result<()> {
    if value.is_empty()
        || value.chars().count() > MAX_PACKAGE_LOCATOR_CHARS
        || value.trim() != value
        || value.starts_with('/')
        || value.starts_with('\\')
        || value.contains('\\')
        || value.contains(':')
        || value.chars().any(char::is_control)
        || value
            .split('/')
            .any(|component| component.is_empty() || matches!(component, "." | ".."))
    {
        bail!("Rust package locator must be a bounded portable canonical locator");
    }
    Ok(())
}

fn validate_repository_path(path: &str) -> Result<()> {
    if path.is_empty()
        || path.chars().count() > MAX_EVIDENCE_PATH_CHARS
        || path.trim() != path
        || path.starts_with('/')
        || path.starts_with('\\')
        || path.contains('\\')
        || path.contains(':')
        || path.chars().any(char::is_control)
        || path
            .split('/')
            .any(|component| component.is_empty() || matches!(component, "." | ".."))
    {
        bail!("Rust profile evidence path must be a confined repository-relative path");
    }
    Ok(())
}

fn validate_stable_id(name: &str, value: &str, namespace: &str) -> Result<()> {
    let prefix = format!("{namespace}:sha256:");
    if !value.strip_prefix(&prefix).is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    }) {
        bail!("{name} must be {namespace}:sha256:<64 lowercase hex>");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use anyhow::Context;
    use depgraph_protocol::stable_id_from_value;
    use serde_json::json;

    use crate::{ProfileCandidateEvidenceKind, ProfileExclusionReason};

    use super::*;

    fn coverage(name: &str) -> RustStaticProfileEvidence {
        RustStaticProfileEvidence {
            estimated_coverage: ProfileCandidateCoverage {
                file_ids: vec![stable_id_from_value("file", &json!(name))],
                dependency_site_ids: vec![stable_id_from_value("site", &json!(name))],
            },
            evidence: vec![ProfileCandidateEvidence {
                kind: ProfileCandidateEvidenceKind::Manifest,
                path: format!("crates/{name}/Cargo.toml"),
                start_line: 1,
                end_line: 4,
            }],
        }
    }

    fn input() -> RustProfilePlanningInput {
        RustProfilePlanningInput {
            planning_version: RUST_PROFILE_PLANNING_VERSION.to_owned(),
            host_target: "aarch64-apple-darwin".to_owned(),
            host_availability: RustProfileAvailability::Available,
            baseline: coverage("baseline"),
            targets: Vec::new(),
            test_mode: None,
            no_default_features: None,
            root_features: Vec::new(),
            rejected: Vec::new(),
        }
    }

    fn target(
        name: &str,
        repository_default: bool,
        availability: RustProfileAvailability,
    ) -> RustTargetDeclaration {
        RustTargetDeclaration {
            target: name.to_owned(),
            repository_default,
            availability,
            static_evidence: coverage(name),
        }
    }

    fn feature(name: &str, closure: &[&str]) -> RustRootFeatureDeclaration {
        RustRootFeatureDeclaration {
            package_locator: format!("crates/{name}"),
            root_feature: name.to_owned(),
            feature_closure: closure.iter().map(|value| (*value).to_owned()).collect(),
            availability: RustProfileAvailability::Available,
            static_evidence: coverage(name),
        }
    }

    fn rust_axes(profile: &ProfileSelectionProfile) -> &RustProfileAxes {
        let CanonicalProfileAxes::Rust(axes) = &profile.axes else {
            panic!("Rust generator returned a non-Rust profile");
        };
        axes
    }

    #[test]
    fn mandatory_baseline_uses_one_default_or_the_attested_host() -> Result<()> {
        let host = generate_rust_profile_candidates(input())?;
        let baseline = host
            .bounded
            .profiles
            .iter()
            .find(|profile| profile.id == host.baseline_profile_id)
            .context("host baseline")?;
        assert_eq!(rust_axes(baseline).target, "aarch64-apple-darwin");

        let mut one_default = input();
        one_default.targets.push(target(
            "x86_64-unknown-linux-gnu",
            true,
            RustProfileAvailability::Available,
        ));
        let one_default = generate_rust_profile_candidates(one_default)?;
        let baseline = one_default
            .bounded
            .profiles
            .iter()
            .find(|profile| profile.id == one_default.baseline_profile_id)
            .context("repository default baseline")?;
        assert_eq!(rust_axes(baseline).target, "x86_64-unknown-linux-gnu");

        let mut multiple = input();
        multiple.targets = vec![
            target(
                "x86_64-unknown-linux-gnu",
                true,
                RustProfileAvailability::Available,
            ),
            target("wasm32-wasip1", true, RustProfileAvailability::Available),
        ];
        let multiple = generate_rust_profile_candidates(multiple)?;
        let baseline = multiple
            .bounded
            .profiles
            .iter()
            .find(|profile| profile.id == multiple.baseline_profile_id)
            .context("multiple-default host baseline")?;
        assert_eq!(rust_axes(baseline).target, "aarch64-apple-darwin");
        assert_eq!(multiple.bounded.candidates.len(), 3);
        Ok(())
    }

    #[test]
    fn target_mode_and_feature_fixtures_never_form_a_cartesian_product() -> Result<()> {
        let mut fixture = input();
        fixture.targets = vec![
            target(
                "x86_64-unknown-linux-gnu",
                true,
                RustProfileAvailability::Available,
            ),
            target("wasm32-wasip1", true, RustProfileAvailability::Available),
        ];
        fixture.test_mode = Some(RustProfileAlternativeDeclaration {
            availability: RustProfileAvailability::Available,
            static_evidence: coverage("tests"),
        });
        fixture.no_default_features = Some(RustProfileAlternativeDeclaration {
            availability: RustProfileAvailability::Available,
            static_evidence: coverage("no-default"),
        });
        fixture.root_features = vec![
            feature("alpha", &["shared", "alpha"]),
            feature("beta", &["beta", "shared"]),
        ];
        let generated = generate_rust_profile_candidates(fixture)?;
        assert_eq!(generated.bounded.candidates.len(), 7);
        let baseline = generated
            .bounded
            .profiles
            .iter()
            .find(|profile| profile.id == generated.baseline_profile_id)
            .context("baseline")?;
        let baseline = rust_axes(baseline);
        for profile in &generated.bounded.profiles {
            let axes = rust_axes(profile);
            let changed = usize::from(axes.target != baseline.target)
                + usize::from(axes.mode != baseline.mode)
                + usize::from(
                    axes.default_features != baseline.default_features
                        || axes.features != baseline.features,
                );
            assert!(changed <= 1);
        }
        assert!(!generated.bounded.profiles.iter().any(|profile| {
            let axes = rust_axes(profile);
            axes.features.contains(&"alpha".to_owned())
                && axes.features.contains(&"beta".to_owned())
        }));
        Ok(())
    }

    #[test]
    fn unsupported_baseline_and_forbidden_automatic_profiles_are_ledgered() -> Result<()> {
        let mut fixture = input();
        fixture.host_availability = RustProfileAvailability::Unavailable;
        fixture.rejected = vec![
            RustRejectedProfileDeclaration {
                kind: RustAutomaticBoundaryKind::AllFeatures,
                axis: Some(ProfileAxis::FeatureOrTag),
                axis_values: vec!["all_features=true".to_owned()],
                evidence: coverage("all-features").evidence,
            },
            RustRejectedProfileDeclaration {
                kind: RustAutomaticBoundaryKind::BuildProfile,
                axis: None,
                axis_values: vec!["phase=build".to_owned()],
                evidence: coverage("build").evidence,
            },
            RustRejectedProfileDeclaration {
                kind: RustAutomaticBoundaryKind::RuntimeProfile,
                axis: None,
                axis_values: vec!["phase=runtime".to_owned()],
                evidence: coverage("runtime").evidence,
            },
            RustRejectedProfileDeclaration {
                kind: RustAutomaticBoundaryKind::CartesianCombination,
                axis: None,
                axis_values: vec!["target+feature".to_owned()],
                evidence: coverage("combination").evidence,
            },
        ];
        let generated = generate_rust_profile_candidates(fixture)?;
        assert_eq!(generated.bounded.candidates.len(), 1);
        assert_eq!(generated.policy_excluded.len(), 5);
        assert!(generated.policy_excluded.iter().any(|entry| {
            entry.reason == ProfileExclusionReason::DefaultProfileUnsupportedAxis
                && entry.affects_completeness
        }));
        assert!(generated.policy_excluded.iter().any(|entry| {
            entry.reason == ProfileExclusionReason::DefaultProfileBuildRequiresConsent
                && !entry.affects_completeness
        }));
        assert!(generated.policy_excluded.iter().any(|entry| {
            entry.reason == ProfileExclusionReason::DefaultProfileRuntimeRequiresTrace
                && !entry.affects_completeness
        }));
        Ok(())
    }

    #[test]
    fn declaration_and_evidence_order_do_not_change_candidate_bytes() -> Result<()> {
        let mut first = input();
        first.targets = vec![
            target("wasm32-wasip1", false, RustProfileAvailability::Available),
            target(
                "x86_64-unknown-linux-gnu",
                false,
                RustProfileAvailability::Available,
            ),
        ];
        first.root_features = vec![
            feature("beta", &["shared", "beta"]),
            feature("alpha", &["shared", "alpha"]),
        ];
        let duplicate = first.root_features[0].static_evidence.evidence[0].clone();
        first.root_features[0]
            .static_evidence
            .evidence
            .push(duplicate);
        let mut reordered = first.clone();
        reordered.targets.reverse();
        reordered.root_features.reverse();
        for feature in &mut reordered.root_features {
            feature.feature_closure.reverse();
            feature.static_evidence.evidence.reverse();
        }
        assert_eq!(
            generate_rust_profile_candidates(first)?,
            generate_rust_profile_candidates(reordered)?
        );
        Ok(())
    }

    #[test]
    fn policy_exclusion_overflow_is_bounded_canonical_and_keeps_the_baseline() -> Result<()> {
        let mut fixture = input();
        fixture.rejected = (0..=MAX_RUST_POLICY_EXCLUSIONS)
            .map(|index| RustRejectedProfileDeclaration {
                kind: RustAutomaticBoundaryKind::MalformedDeclaration,
                axis: None,
                axis_values: vec![format!("declaration={index:04}")],
                evidence: coverage(&format!("rejected-{index:04}")).evidence,
            })
            .collect();
        let mut reordered = fixture.clone();
        reordered.rejected.reverse();

        let generated = generate_rust_profile_candidates(fixture)?;
        assert_eq!(generated.bounded.candidates.len(), 1);
        assert_eq!(generated.policy_excluded.len(), MAX_RUST_POLICY_EXCLUSIONS);
        assert_eq!(generated.policy_exclusion_overflow_count, 1);
        assert!(!generated.complete);
        assert_eq!(generated, generate_rust_profile_candidates(reordered)?);
        Ok(())
    }

    #[test]
    fn unsafe_paths_and_conflicting_target_availability_fail_closed() {
        let mut unsafe_input = input();
        unsafe_input.baseline.evidence[0].path = "/tmp/checkout/Cargo.toml".to_owned();
        assert!(
            generate_rust_profile_candidates(unsafe_input)
                .unwrap_err()
                .to_string()
                .contains("repository-relative")
        );

        let mut conflict = input();
        conflict.targets = vec![
            target("wasm32-wasip1", false, RustProfileAvailability::Available),
            target("wasm32-wasip1", false, RustProfileAvailability::Unsupported),
        ];
        assert!(
            generate_rust_profile_candidates(conflict)
                .unwrap_err()
                .to_string()
                .contains("conflicting availability")
        );
    }
}
