use std::collections::BTreeMap;

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

use crate::{
    CanonicalProfileAxes, GoCallGraph, GoProfileAxes, ProfileAxis, ProfileCandidateCoverage,
    ProfileCandidateDiscoveryResult, ProfileCandidateEvidence, ProfileCandidateEvidenceKind,
    ProfileCandidateKind, ProfileCandidateRecord, ProfileExclusionReason, ProfileLanguage,
    ProfilePolicyExclusion, ProfileSelectionProfile, bound_profile_candidate_discovery,
    canonical_profile_id, profile_candidate_id, profile_exclusion_id,
};

pub const GO_PROFILE_PLANNING_VERSION: &str = "go-profile-planning-v1";

const MAX_GO_PLATFORM_DECLARATIONS: usize = 8_192;
const MAX_GO_TAG_DECLARATIONS: usize = 65_536;
const MAX_GO_REJECTED_DECLARATIONS: usize = 4_096;
const MAX_GO_POLICY_EXCLUSIONS: usize = 512;
const MAX_AXIS_VALUE_CHARS: usize = 256;
const MAX_EVIDENCE_ITEMS: usize = 65_536;
const MAX_EVIDENCE_PATH_CHARS: usize = 4_096;

const GOOS_VALUES: &[&str] = &[
    "aix",
    "android",
    "darwin",
    "dragonfly",
    "freebsd",
    "illumos",
    "ios",
    "js",
    "linux",
    "netbsd",
    "openbsd",
    "plan9",
    "solaris",
    "wasip1",
    "windows",
    "zos",
];
const GOARCH_VALUES: &[&str] = &[
    "386", "amd64", "arm", "arm64", "loong64", "mips", "mips64", "mips64le", "mipsle", "ppc64",
    "ppc64le", "riscv64", "s390x", "sparc64", "wasm",
];
const RESERVED_BUILD_TAGS: &[&str] = &["cgo", "gc", "gccgo", "unix"];

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GoProfileAvailability {
    Available,
    Unavailable,
    Unsupported,
}

impl GoProfileAvailability {
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
pub struct GoStaticProfileEvidence {
    pub estimated_coverage: ProfileCandidateCoverage,
    pub evidence: Vec<ProfileCandidateEvidence>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GoPlatformEvidenceKind {
    FileName,
    BuildConstraint,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GoTargetDeclaration {
    pub goos: String,
    pub goarch: String,
    pub evidence_kind: GoPlatformEvidenceKind,
    #[serde(default)]
    pub constraint_goos: Vec<String>,
    #[serde(default)]
    pub constraint_goarch: Vec<String>,
    pub availability: GoProfileAvailability,
    pub static_evidence: GoStaticProfileEvidence,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GoTagDeclaration {
    pub tag: String,
    pub availability: GoProfileAvailability,
    pub static_evidence: GoStaticProfileEvidence,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GoAutomaticBoundaryKind {
    Cgo,
    Vta,
    CrossCompiler,
    ArbitraryUserTag,
    BuildProfile,
    RuntimeProfile,
    DynamicConfiguration,
    MalformedDeclaration,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GoRejectedProfileDeclaration {
    pub kind: GoAutomaticBoundaryKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub axis: Option<ProfileAxis>,
    pub axis_values: Vec<String>,
    pub evidence: Vec<ProfileCandidateEvidence>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GoProfilePlanningInput {
    pub planning_version: String,
    pub host_goos: String,
    pub host_goarch: String,
    pub host_availability: GoProfileAvailability,
    pub dependency_snapshot_id: String,
    pub baseline: GoStaticProfileEvidence,
    pub targets: Vec<GoTargetDeclaration>,
    pub tags: Vec<GoTagDeclaration>,
    pub rejected: Vec<GoRejectedProfileDeclaration>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GoProfileCandidateGenerationResult {
    pub bounded: ProfileCandidateDiscoveryResult,
    pub policy_excluded: Vec<ProfilePolicyExclusion>,
    pub policy_exclusion_overflow_count: u32,
    pub complete: bool,
    pub baseline_profile_id: String,
}

pub fn generate_go_profile_candidates(
    mut input: GoProfilePlanningInput,
) -> Result<GoProfileCandidateGenerationResult> {
    if input.planning_version != GO_PROFILE_PLANNING_VERSION {
        bail!("unsupported Go profile planning version; expected {GO_PROFILE_PLANNING_VERSION}");
    }
    if input.targets.len() > MAX_GO_PLATFORM_DECLARATIONS
        || input.tags.len() > MAX_GO_TAG_DECLARATIONS
        || input.rejected.len() > MAX_GO_REJECTED_DECLARATIONS
    {
        bail!("Go profile planning input exceeds a closed declaration limit");
    }
    validate_known_goos(&input.host_goos)?;
    validate_known_goarch(&input.host_goarch)?;
    validate_stable_id(
        "Go dependency snapshot id",
        &input.dependency_snapshot_id,
        "go-dependency-snapshot",
    )?;
    canonicalize_static_evidence(&mut input.baseline)?;

    let targets = canonical_targets(input.targets, &input.host_goos, &input.host_goarch)?;
    let baseline_axes = GoProfileAxes {
        goos: input.host_goos.clone(),
        goarch: input.host_goarch.clone(),
        tags: Vec::new(),
        cgo_enabled: false,
        call_graph: GoCallGraph::RtaCha,
        dependency_snapshot_id: input.dependency_snapshot_id,
    };
    let baseline_profile = profile(baseline_axes.clone());
    let baseline_profile_id = baseline_profile.id.clone();
    let mut baseline_evidence = input.baseline;
    if let Some(host) = targets.get(&(input.host_goos, input.host_goarch)) {
        merge_static_evidence(&mut baseline_evidence, host.static_evidence.clone());
        canonicalize_static_evidence(&mut baseline_evidence)?;
    }
    let baseline_candidate = candidate(
        &baseline_profile,
        &baseline_profile_id,
        ProfileCandidateKind::Baseline,
        None,
        Vec::new(),
        baseline_evidence.clone(),
    );

    let mut profiles = vec![baseline_profile];
    let mut candidates = vec![baseline_candidate];
    let mut exclusions = Vec::new();
    if input.host_availability != GoProfileAvailability::Available {
        exclusions.push(availability_exclusion(
            Some(ProfileAxis::Target),
            vec![format!("{}/{}", baseline_axes.goos, baseline_axes.goarch)],
            input.host_availability,
            baseline_evidence.evidence,
        ));
    }

    for ((goos, goarch), target) in targets {
        if goos == baseline_axes.goos && goarch == baseline_axes.goarch {
            continue;
        }
        let axis_values = vec![format!("{goos}/{goarch}")];
        if target.availability != GoProfileAvailability::Available {
            exclusions.push(availability_exclusion(
                Some(ProfileAxis::Target),
                axis_values,
                target.availability,
                target.static_evidence.evidence,
            ));
            continue;
        }
        let alternative = profile(GoProfileAxes {
            goos,
            goarch,
            ..baseline_axes.clone()
        });
        candidates.push(candidate(
            &alternative,
            &baseline_profile_id,
            ProfileCandidateKind::Alternative,
            Some(ProfileAxis::Target),
            axis_values,
            target.static_evidence,
        ));
        profiles.push(alternative);
    }

    let tags = canonical_tags(input.tags)?;
    for (tag, declaration) in tags {
        let axis_values = vec![format!("tag={tag}")];
        if reserved_go_tag(&tag) {
            exclusions.push(exclusion(
                Some(ProfileAxis::FeatureOrTag),
                axis_values,
                ProfileExclusionReason::DefaultProfileUnsupportedAxis,
                declaration.static_evidence.evidence,
            ));
            continue;
        }
        if declaration.availability != GoProfileAvailability::Available {
            exclusions.push(availability_exclusion(
                Some(ProfileAxis::FeatureOrTag),
                axis_values,
                declaration.availability,
                declaration.static_evidence.evidence,
            ));
            continue;
        }
        let alternative = profile(GoProfileAxes {
            tags: vec![tag],
            ..baseline_axes.clone()
        });
        candidates.push(candidate(
            &alternative,
            &baseline_profile_id,
            ProfileCandidateKind::Alternative,
            Some(ProfileAxis::FeatureOrTag),
            axis_values,
            declaration.static_evidence,
        ));
        profiles.push(alternative);
    }

    for mut rejected in input.rejected {
        canonicalize_evidence(&mut rejected.evidence)?;
        for value in &rejected.axis_values {
            validate_axis_value("Go rejected axis value", value)?;
        }
        rejected
            .axis_values
            .sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
        rejected.axis_values.dedup();
        exclusions.push(exclusion(
            rejected.axis,
            rejected.axis_values,
            rejection_reason(rejected.kind),
            rejected.evidence,
        ));
    }

    exclusions.sort_by(|left, right| left.id.as_bytes().cmp(right.id.as_bytes()));
    exclusions.dedup_by(|left, right| left.id == right.id);
    let policy_exclusion_overflow_count =
        u32::try_from(exclusions.len().saturating_sub(MAX_GO_POLICY_EXCLUSIONS))?;
    exclusions.truncate(MAX_GO_POLICY_EXCLUSIONS);
    let bounded = bound_profile_candidate_discovery(profiles, candidates, &[ProfileLanguage::Go])?;
    let complete = bounded.complete && policy_exclusion_overflow_count == 0;
    Ok(GoProfileCandidateGenerationResult {
        bounded,
        policy_excluded: exclusions,
        policy_exclusion_overflow_count,
        complete,
        baseline_profile_id,
    })
}

fn canonical_targets(
    mut targets: Vec<GoTargetDeclaration>,
    host_goos: &str,
    host_goarch: &str,
) -> Result<BTreeMap<(String, String), GoTargetDeclaration>> {
    targets.sort_by(|left, right| {
        (left.goos.as_bytes(), left.goarch.as_bytes())
            .cmp(&(right.goos.as_bytes(), right.goarch.as_bytes()))
    });
    let mut canonical = BTreeMap::<(String, String), GoTargetDeclaration>::new();
    for mut target in targets {
        validate_known_goos(&target.goos)?;
        validate_known_goarch(&target.goarch)?;
        canonicalize_constraint_platforms(&mut target)?;
        canonicalize_static_evidence(&mut target.static_evidence)?;
        validate_platform_evidence(&target, host_goos, host_goarch)?;
        let key = (target.goos.clone(), target.goarch.clone());
        if let Some(previous) = canonical.get_mut(&key) {
            if previous.availability != target.availability {
                bail!("one Go platform cannot have conflicting availability");
            }
            merge_static_evidence(&mut previous.static_evidence, target.static_evidence);
            canonicalize_static_evidence(&mut previous.static_evidence)?;
        } else {
            canonical.insert(key, target);
        }
    }
    Ok(canonical)
}

fn canonical_tags(mut tags: Vec<GoTagDeclaration>) -> Result<BTreeMap<String, GoTagDeclaration>> {
    tags.sort_by(|left, right| left.tag.as_bytes().cmp(right.tag.as_bytes()));
    let mut canonical = BTreeMap::<String, GoTagDeclaration>::new();
    for mut tag in tags {
        validate_axis_value("Go user build tag", &tag.tag)?;
        canonicalize_static_evidence(&mut tag.static_evidence)?;
        if !tag
            .static_evidence
            .evidence
            .iter()
            .any(|item| item.kind == ProfileCandidateEvidenceKind::Source)
        {
            bail!("Go user tag requires parsed source build-constraint evidence");
        }
        if let Some(previous) = canonical.get_mut(&tag.tag) {
            if previous.availability != tag.availability {
                bail!("one Go tag cannot have conflicting availability");
            }
            merge_static_evidence(&mut previous.static_evidence, tag.static_evidence);
            canonicalize_static_evidence(&mut previous.static_evidence)?;
        } else {
            canonical.insert(tag.tag.clone(), tag);
        }
    }
    Ok(canonical)
}

fn validate_platform_evidence(
    target: &GoTargetDeclaration,
    host_goos: &str,
    host_goarch: &str,
) -> Result<()> {
    let source_evidence = target
        .static_evidence
        .evidence
        .iter()
        .filter(|item| item.kind == ProfileCandidateEvidenceKind::Source)
        .collect::<Vec<_>>();
    if source_evidence.is_empty() {
        bail!("Go platform candidate requires static source evidence");
    }
    if target.evidence_kind == GoPlatformEvidenceKind::FileName
        && !source_evidence.iter().any(|item| {
            filename_evidences_platform(
                &item.path,
                &target.goos,
                &target.goarch,
                host_goos,
                host_goarch,
            )
        })
    {
        bail!("Go filename platform evidence does not match its GOOS/GOARCH pair");
    }
    if target.evidence_kind == GoPlatformEvidenceKind::BuildConstraint
        && (!target
            .constraint_goos
            .iter()
            .any(|value| value == &target.goos)
            || !target
                .constraint_goarch
                .iter()
                .any(|value| value == &target.goarch))
    {
        bail!("Go build-constraint evidence does not match its GOOS/GOARCH pair");
    }
    Ok(())
}

fn canonicalize_constraint_platforms(target: &mut GoTargetDeclaration) -> Result<()> {
    target.constraint_goos.sort();
    target.constraint_goos.dedup();
    target.constraint_goarch.sort();
    target.constraint_goarch.dedup();
    if target.constraint_goos.len() > GOOS_VALUES.len()
        || target.constraint_goarch.len() > GOARCH_VALUES.len()
    {
        bail!("Go build-constraint platform evidence exceeds its closed vocabulary");
    }
    for goos in &target.constraint_goos {
        validate_known_goos(goos)?;
    }
    for goarch in &target.constraint_goarch {
        validate_known_goarch(goarch)?;
    }
    if target.evidence_kind == GoPlatformEvidenceKind::FileName
        && (!target.constraint_goos.is_empty() || !target.constraint_goarch.is_empty())
    {
        bail!("Go filename evidence cannot claim parsed build-constraint platforms");
    }
    Ok(())
}

fn filename_evidences_platform(
    path: &str,
    goos: &str,
    goarch: &str,
    host_goos: &str,
    host_goarch: &str,
) -> bool {
    let Some(file_name) = path.rsplit('/').next() else {
        return false;
    };
    let Some(stem) = file_name.strip_suffix(".go") else {
        return false;
    };
    stem.ends_with(&format!("_{goos}_{goarch}"))
        || (goarch == host_goarch && stem.ends_with(&format!("_{goos}")))
        || (goos == host_goos && stem.ends_with(&format!("_{goarch}")))
}

fn profile(axes: GoProfileAxes) -> ProfileSelectionProfile {
    let axes = CanonicalProfileAxes::Go(axes);
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
    static_evidence: GoStaticProfileEvidence,
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

fn reserved_go_tag(tag: &str) -> bool {
    GOOS_VALUES.contains(&tag)
        || GOARCH_VALUES.contains(&tag)
        || RESERVED_BUILD_TAGS.contains(&tag)
        || tag.strip_prefix("go1.").is_some_and(|version| {
            !version.is_empty() && version.bytes().all(|byte| byte.is_ascii_digit())
        })
}

fn availability_exclusion(
    axis: Option<ProfileAxis>,
    mut axis_values: Vec<String>,
    availability: GoProfileAvailability,
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

const fn rejection_reason(kind: GoAutomaticBoundaryKind) -> ProfileExclusionReason {
    match kind {
        GoAutomaticBoundaryKind::Cgo
        | GoAutomaticBoundaryKind::Vta
        | GoAutomaticBoundaryKind::CrossCompiler
        | GoAutomaticBoundaryKind::ArbitraryUserTag => {
            ProfileExclusionReason::DefaultProfileUnsupportedAxis
        }
        GoAutomaticBoundaryKind::BuildProfile => {
            ProfileExclusionReason::DefaultProfileBuildRequiresConsent
        }
        GoAutomaticBoundaryKind::RuntimeProfile => {
            ProfileExclusionReason::DefaultProfileRuntimeRequiresTrace
        }
        GoAutomaticBoundaryKind::DynamicConfiguration => {
            ProfileExclusionReason::DefaultProfileDynamicConfigurationNotExecuted
        }
        GoAutomaticBoundaryKind::MalformedDeclaration => {
            ProfileExclusionReason::DefaultProfileMalformedDeclaration
        }
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
        language: ProfileLanguage::Go,
        axis,
        axis_values,
        reason,
        affects_completeness,
        evidence,
    };
    exclusion.id = profile_exclusion_id(&exclusion);
    exclusion
}

fn canonicalize_static_evidence(evidence: &mut GoStaticProfileEvidence) -> Result<()> {
    evidence
        .estimated_coverage
        .file_ids
        .sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    evidence.estimated_coverage.file_ids.dedup();
    for id in &evidence.estimated_coverage.file_ids {
        validate_stable_id("Go profile file coverage ID", id, "file")?;
    }
    evidence
        .estimated_coverage
        .dependency_site_ids
        .sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    evidence.estimated_coverage.dependency_site_ids.dedup();
    for id in &evidence.estimated_coverage.dependency_site_ids {
        validate_stable_id("Go profile dependency-site coverage ID", id, "site")?;
    }
    canonicalize_evidence(&mut evidence.evidence)
}

fn canonicalize_evidence(evidence: &mut Vec<ProfileCandidateEvidence>) -> Result<()> {
    if evidence.is_empty() || evidence.len() > MAX_EVIDENCE_ITEMS {
        bail!("Go profile evidence must be non-empty and within its closed item limit");
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
            bail!("Go profile evidence line range is invalid");
        }
    }
    Ok(())
}

fn evidence_kind(evidence: &ProfileCandidateEvidence) -> &'static str {
    use ProfileCandidateEvidenceKind::{Config, HostContext, Manifest, Source};
    match evidence.kind {
        Config => "config",
        Manifest => "manifest",
        Source => "source",
        HostContext => "host_context",
    }
}

fn merge_static_evidence(target: &mut GoStaticProfileEvidence, source: GoStaticProfileEvidence) {
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

fn validate_known_goos(value: &str) -> Result<()> {
    validate_axis_value("Go GOOS", value)?;
    if !GOOS_VALUES.contains(&value) {
        bail!("Go GOOS is not in the closed portable platform vocabulary");
    }
    Ok(())
}

fn validate_known_goarch(value: &str) -> Result<()> {
    validate_axis_value("Go GOARCH", value)?;
    if !GOARCH_VALUES.contains(&value) {
        bail!("Go GOARCH is not in the closed portable platform vocabulary");
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
        bail!("Go profile evidence path must be a confined repository-relative path");
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

    use super::*;

    fn evidence(name: &str, path: &str) -> GoStaticProfileEvidence {
        GoStaticProfileEvidence {
            estimated_coverage: ProfileCandidateCoverage {
                file_ids: vec![stable_id_from_value("file", &json!(name))],
                dependency_site_ids: vec![stable_id_from_value("site", &json!(name))],
            },
            evidence: vec![ProfileCandidateEvidence {
                kind: ProfileCandidateEvidenceKind::Source,
                path: path.to_owned(),
                start_line: 1,
                end_line: 2,
            }],
        }
    }

    fn input(snapshot_byte: char) -> GoProfilePlanningInput {
        GoProfilePlanningInput {
            planning_version: GO_PROFILE_PLANNING_VERSION.to_owned(),
            host_goos: "darwin".to_owned(),
            host_goarch: "arm64".to_owned(),
            host_availability: GoProfileAvailability::Available,
            dependency_snapshot_id: format!(
                "go-dependency-snapshot:sha256:{}",
                snapshot_byte.to_string().repeat(64)
            ),
            baseline: evidence("baseline", "go.mod"),
            targets: Vec::new(),
            tags: Vec::new(),
            rejected: Vec::new(),
        }
    }

    fn target(
        goos: &str,
        goarch: &str,
        kind: GoPlatformEvidenceKind,
        path: &str,
    ) -> GoTargetDeclaration {
        GoTargetDeclaration {
            goos: goos.to_owned(),
            goarch: goarch.to_owned(),
            evidence_kind: kind,
            constraint_goos: if kind == GoPlatformEvidenceKind::BuildConstraint {
                vec![goos.to_owned()]
            } else {
                Vec::new()
            },
            constraint_goarch: if kind == GoPlatformEvidenceKind::BuildConstraint {
                vec![goarch.to_owned()]
            } else {
                Vec::new()
            },
            availability: GoProfileAvailability::Available,
            static_evidence: evidence(&format!("{goos}-{goarch}"), path),
        }
    }

    fn tag(name: &str) -> GoTagDeclaration {
        GoTagDeclaration {
            tag: name.to_owned(),
            availability: GoProfileAvailability::Available,
            static_evidence: evidence(name, &format!("internal/{name}.go")),
        }
    }

    fn go_axes(profile: &ProfileSelectionProfile) -> &GoProfileAxes {
        let CanonicalProfileAxes::Go(axes) = &profile.axes else {
            panic!("Go generator returned a non-Go profile");
        };
        axes
    }

    #[test]
    fn mandatory_host_baseline_is_safe_and_snapshot_bound() -> Result<()> {
        let first = generate_go_profile_candidates(input('a'))?;
        let second = generate_go_profile_candidates(input('b'))?;
        let baseline = first
            .bounded
            .profiles
            .iter()
            .find(|profile| profile.id == first.baseline_profile_id)
            .context("Go baseline")?;
        let axes = go_axes(baseline);
        assert_eq!(
            (axes.goos.as_str(), axes.goarch.as_str()),
            ("darwin", "arm64")
        );
        assert!(axes.tags.is_empty());
        assert!(!axes.cgo_enabled);
        assert_eq!(axes.call_graph, GoCallGraph::RtaCha);
        assert_ne!(first.baseline_profile_id, second.baseline_profile_id);
        Ok(())
    }

    #[test]
    fn filename_constraint_and_tag_candidates_change_only_one_axis() -> Result<()> {
        let mut fixture = input('a');
        fixture.targets = vec![
            target(
                "linux",
                "arm64",
                GoPlatformEvidenceKind::FileName,
                "pkg/service_linux.go",
            ),
            target(
                "windows",
                "amd64",
                GoPlatformEvidenceKind::BuildConstraint,
                "pkg/service.go",
            ),
        ];
        fixture.tags = vec![tag("enterprise"), tag("integration")];
        let generated = generate_go_profile_candidates(fixture)?;
        assert_eq!(generated.bounded.candidates.len(), 5);
        let baseline = generated
            .bounded
            .profiles
            .iter()
            .find(|profile| profile.id == generated.baseline_profile_id)
            .context("Go baseline")?;
        let baseline = go_axes(baseline);
        for profile in &generated.bounded.profiles {
            let axes = go_axes(profile);
            let changed = usize::from(axes.goos != baseline.goos || axes.goarch != baseline.goarch)
                + usize::from(axes.tags != baseline.tags);
            assert!(changed <= 1);
            assert!(!axes.cgo_enabled);
            assert_eq!(axes.call_graph, GoCallGraph::RtaCha);
            assert_eq!(axes.dependency_snapshot_id, baseline.dependency_snapshot_id);
        }
        assert!(!generated.bounded.profiles.iter().any(|profile| {
            let axes = go_axes(profile);
            !axes.tags.is_empty() && axes.goos != baseline.goos
        }));
        Ok(())
    }

    #[test]
    fn reserved_tags_cgo_vta_and_cross_compiler_never_become_candidates() -> Result<()> {
        let mut fixture = input('a');
        fixture.tags = vec![tag("linux"), tag("go1.26"), tag("enterprise")];
        fixture.rejected = vec![
            GoRejectedProfileDeclaration {
                kind: GoAutomaticBoundaryKind::Cgo,
                axis: None,
                axis_values: vec!["cgo_enabled=true".to_owned()],
                evidence: evidence("cgo", "pkg/cgo.go").evidence,
            },
            GoRejectedProfileDeclaration {
                kind: GoAutomaticBoundaryKind::Vta,
                axis: None,
                axis_values: vec!["call_graph=vta".to_owned()],
                evidence: evidence("vta", "go.mod").evidence,
            },
            GoRejectedProfileDeclaration {
                kind: GoAutomaticBoundaryKind::CrossCompiler,
                axis: Some(ProfileAxis::Target),
                axis_values: vec!["cross_compiler=true".to_owned()],
                evidence: evidence("cross", "go.mod").evidence,
            },
        ];
        let generated = generate_go_profile_candidates(fixture)?;
        assert_eq!(generated.bounded.candidates.len(), 2);
        assert_eq!(generated.policy_excluded.len(), 5);
        assert!(generated.policy_excluded.iter().all(|entry| {
            entry.reason == ProfileExclusionReason::DefaultProfileUnsupportedAxis
        }));
        Ok(())
    }

    #[test]
    fn input_order_host_and_snapshot_identity_are_deterministic_and_explicit() -> Result<()> {
        let mut first = input('a');
        first.targets = vec![
            target(
                "windows",
                "amd64",
                GoPlatformEvidenceKind::BuildConstraint,
                "pkg/windows.go",
            ),
            target(
                "linux",
                "arm64",
                GoPlatformEvidenceKind::FileName,
                "pkg/service_linux.go",
            ),
        ];
        first.tags = vec![tag("integration"), tag("enterprise")];
        let mut reordered = first.clone();
        reordered.targets.reverse();
        reordered.tags.reverse();
        assert_eq!(
            generate_go_profile_candidates(first.clone())?,
            generate_go_profile_candidates(reordered)?
        );

        let mut different_host = first.clone();
        different_host.host_goos = "linux".to_owned();
        let mut different_snapshot = first;
        different_snapshot.dependency_snapshot_id =
            format!("go-dependency-snapshot:sha256:{}", "b".repeat(64));
        let original = generate_go_profile_candidates(input('a'))?;
        assert_ne!(
            original.baseline_profile_id,
            generate_go_profile_candidates(different_host)?.baseline_profile_id
        );
        assert_ne!(
            original.baseline_profile_id,
            generate_go_profile_candidates(different_snapshot)?.baseline_profile_id
        );
        Ok(())
    }

    #[test]
    fn invalid_filename_arbitrary_platform_and_unsafe_evidence_fail_closed() {
        let mut invalid_file = input('a');
        invalid_file.targets.push(target(
            "linux",
            "arm64",
            GoPlatformEvidenceKind::FileName,
            "pkg/service.go",
        ));
        assert!(
            generate_go_profile_candidates(invalid_file)
                .unwrap_err()
                .to_string()
                .contains("does not match")
        );

        let mut invalid_platform = input('a');
        invalid_platform.host_goos = "madeup".to_owned();
        assert!(
            generate_go_profile_candidates(invalid_platform)
                .unwrap_err()
                .to_string()
                .contains("platform vocabulary")
        );

        let mut unsafe_input = input('a');
        unsafe_input.baseline.evidence[0].path = "/tmp/checkout/go.mod".to_owned();
        assert!(
            generate_go_profile_candidates(unsafe_input)
                .unwrap_err()
                .to_string()
                .contains("repository-relative")
        );
    }

    #[test]
    fn build_constraint_platform_attestation_must_match_the_declared_target() {
        let mut missing = input('a');
        let mut declaration = target(
            "windows",
            "amd64",
            GoPlatformEvidenceKind::BuildConstraint,
            "pkg/service.go",
        );
        declaration.constraint_goos.clear();
        declaration.constraint_goarch.clear();
        missing.targets.push(declaration);
        assert!(
            generate_go_profile_candidates(missing)
                .unwrap_err()
                .to_string()
                .contains("does not match")
        );

        let mut wrong = input('a');
        let mut declaration = target(
            "windows",
            "amd64",
            GoPlatformEvidenceKind::BuildConstraint,
            "pkg/service.go",
        );
        declaration.constraint_goos = vec!["linux".to_owned()];
        declaration.constraint_goarch = vec!["arm64".to_owned()];
        wrong.targets.push(declaration);
        assert!(
            generate_go_profile_candidates(wrong)
                .unwrap_err()
                .to_string()
                .contains("does not match")
        );
    }

    #[test]
    fn policy_exclusion_overflow_is_bounded_canonical_and_keeps_the_baseline() -> Result<()> {
        let mut fixture = input('a');
        fixture.rejected = (0..=MAX_GO_POLICY_EXCLUSIONS)
            .map(|index| GoRejectedProfileDeclaration {
                kind: GoAutomaticBoundaryKind::BuildProfile,
                axis: None,
                axis_values: vec![format!("profile={index:04}")],
                evidence: evidence(
                    &format!("rejected-{index:04}"),
                    &format!("config/profile-{index:04}.json"),
                )
                .evidence,
            })
            .collect();
        let mut reordered = fixture.clone();
        reordered.rejected.reverse();
        let first = generate_go_profile_candidates(fixture)?;
        let second = generate_go_profile_candidates(reordered)?;
        assert_eq!(first, second);
        assert_eq!(first.policy_excluded.len(), MAX_GO_POLICY_EXCLUSIONS);
        assert_eq!(first.policy_exclusion_overflow_count, 1);
        assert!(!first.complete);
        assert!(
            first
                .bounded
                .profiles
                .iter()
                .any(|profile| { profile.id == first.baseline_profile_id })
        );
        Ok(())
    }
}
