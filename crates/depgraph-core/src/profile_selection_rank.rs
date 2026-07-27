use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet},
};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::{
    CandidateDiscoveryReason, DEFAULT_PROFILE_SELECTION_CONTRACT_VERSION,
    DefaultProfileSelectionPlan, ProfileAxis, ProfileCandidateDiscoveryResult,
    ProfileCandidateKind, ProfileCandidateRecord, ProfileDiscoveryLedger, ProfileExclusionReason,
    ProfileLanguage, ProfileOmissionReason, ProfileOmittedLedger, ProfilePolicyExclusion,
    ProfileRankEvidence, ProfileSelectedLedger, ProfileSelectedReason, ProfileSelectionInput,
    ProfileSelectionMode, ProfileSelectionProfile, ProfileSelectionSummary, RepositorySizeClass,
    bound_profile_candidate_discovery, canonical_profile_selection_plan_id,
    profile_selection_input_digest, validate_profile_selection_plan,
};

#[derive(Clone, Debug)]
pub struct AutomaticProfileSelectionRequest {
    pub input: ProfileSelectionInput,
    pub discoveries: Vec<ProfileCandidateDiscoveryResult>,
    pub policy_excluded: Vec<ProfilePolicyExclusion>,
    pub tracked_candidate_ids: Vec<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileMatrixIncompleteReason {
    DefaultProfileBudgetExhausted,
    DefaultProfileCandidateLimitExceeded,
    DefaultProfileDynamicConfigurationNotExecuted,
    DefaultProfileUnsupportedAxis,
    DefaultProfileMalformedDeclaration,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileSelectionDoctorStatus {
    pub eligible_profile_count: u32,
    pub selected_profile_count: u32,
    pub omitted_profile_count: u32,
    pub effective_profile_cap: u32,
    pub default_profile_matrix_complete: bool,
    pub reasons: Vec<ProfileMatrixIncompleteReason>,
    pub remediation: Vec<String>,
    pub strict_exit_code: u8,
}

pub fn plan_automatic_profile_selection(
    request: AutomaticProfileSelectionRequest,
) -> Result<DefaultProfileSelectionPlan> {
    if request.input.selection_file_digest.is_some() {
        bail!("automatic profile selection cannot use an explicit selection-file digest");
    }
    let (profiles, candidates, discovery) =
        merge_candidate_discoveries(&request.input, request.discoveries)?;
    let profile_by_id = profiles
        .iter()
        .map(|profile| (profile.id.as_str(), profile))
        .collect::<BTreeMap<_, _>>();
    let candidate_by_id = candidates
        .iter()
        .map(|candidate| (candidate.id.as_str(), candidate))
        .collect::<BTreeMap<_, _>>();

    let mut tracked_candidate_ids = request.tracked_candidate_ids;
    tracked_candidate_ids.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    if tracked_candidate_ids
        .windows(2)
        .any(|pair| pair[0] == pair[1])
    {
        bail!("tracked profile candidate IDs must be unique");
    }
    for candidate_id in &tracked_candidate_ids {
        let candidate = candidate_by_id
            .get(candidate_id.as_str())
            .copied()
            .ok_or_else(|| anyhow::anyhow!("tracked profile candidate ID is unknown"))?;
        if candidate.kind != ProfileCandidateKind::Alternative {
            bail!("mandatory language baselines cannot be tracked optional candidates");
        }
    }
    let tracked_candidate_ids = tracked_candidate_ids.into_iter().collect::<BTreeSet<_>>();

    let mut baselines = candidates
        .iter()
        .filter(|candidate| candidate.kind == ProfileCandidateKind::Baseline)
        .collect::<Vec<_>>();
    baselines.sort_by(|left, right| {
        let left_language = profile_by_id[left.profile_id.as_str()].axes.language();
        let right_language = profile_by_id[right.profile_id.as_str()].axes.language();
        language_priority(left_language)
            .cmp(&language_priority(right_language))
            .then(left.profile_id.as_bytes().cmp(right.profile_id.as_bytes()))
    });
    if u32::try_from(baselines.len())? > request.input.limits.effective_profile_cap {
        bail!("effective profile cap cannot reserve every mandatory language baseline");
    }

    let mut selected_sequence = Vec::<ProfileSelectedLedger>::new();
    let mut covered_files = BTreeSet::<String>::new();
    let mut covered_sites = BTreeSet::<String>::new();
    for candidate in baselines {
        let selection_rank = u32::try_from(selected_sequence.len())?;
        extend_coverage(candidate, &mut covered_files, &mut covered_sites);
        selected_sequence.push(ProfileSelectedLedger {
            candidate_id: candidate.id.clone(),
            profile_id: candidate.profile_id.clone(),
            selection_rank,
            reason: ProfileSelectedReason::MandatoryLanguageBaseline,
            rank: None,
        });
    }

    let mut remaining = candidates
        .iter()
        .filter(|candidate| candidate.kind == ProfileCandidateKind::Alternative)
        .map(|candidate| (candidate.id.as_str(), candidate))
        .collect::<BTreeMap<_, _>>();
    while u32::try_from(selected_sequence.len())? < request.input.limits.effective_profile_cap
        && !remaining.is_empty()
    {
        let next = remaining
            .values()
            .map(|candidate| {
                let profile = profile_by_id[candidate.profile_id.as_str()];
                let rank = rank_candidate(
                    candidate,
                    profile.axes.language(),
                    tracked_candidate_ids.contains(&candidate.id),
                    &covered_files,
                    &covered_sites,
                );
                (*candidate, rank)
            })
            .min_by(
                |(left_candidate, left_rank), (right_candidate, right_rank)| {
                    compare_rank(left_candidate, left_rank, right_candidate, right_rank)
                },
            )
            .context("automatic profile candidate ranking")?;
        remaining.remove(next.0.id.as_str());
        extend_coverage(next.0, &mut covered_files, &mut covered_sites);
        let selection_rank = u32::try_from(selected_sequence.len())?;
        selected_sequence.push(ProfileSelectedLedger {
            candidate_id: next.0.id.clone(),
            profile_id: next.0.profile_id.clone(),
            selection_rank,
            reason: if tracked_candidate_ids.contains(&next.0.id) {
                ProfileSelectedReason::TrackedProfileConfiguration
            } else {
                ProfileSelectedReason::AutomaticCoverageRanked
            },
            rank: Some(next.1),
        });
    }

    let mut omitted = remaining
        .into_values()
        .map(|candidate| {
            let language = profile_by_id[candidate.profile_id.as_str()].axes.language();
            ProfileOmittedLedger {
                candidate_id: candidate.id.clone(),
                profile_id: candidate.profile_id.clone(),
                reason: ProfileOmissionReason::DefaultProfileBudgetExhausted,
                rank: rank_candidate(
                    candidate,
                    language,
                    tracked_candidate_ids.contains(&candidate.id),
                    &covered_files,
                    &covered_sites,
                ),
            }
        })
        .collect::<Vec<_>>();
    omitted.sort_by(|left, right| left.profile_id.as_bytes().cmp(right.profile_id.as_bytes()));
    selected_sequence
        .sort_by(|left, right| left.profile_id.as_bytes().cmp(right.profile_id.as_bytes()));

    let mut policy_excluded = request.policy_excluded;
    policy_excluded.sort_by(|left, right| left.id.as_bytes().cmp(right.id.as_bytes()));
    if policy_excluded
        .windows(2)
        .any(|pair| pair[0].id == pair[1].id)
    {
        bail!("automatic profile policy exclusions must be unique");
    }
    let eligible_profile_count = u32::try_from(candidates.len())?;
    let selected_profile_count = u32::try_from(selected_sequence.len())?;
    let omitted_profile_count = u32::try_from(omitted.len())?;
    let policy_excluded_count = u32::try_from(policy_excluded.len())?;
    let candidate_discovery_complete = discovery.iter().all(|entry| entry.complete);
    let selection_complete = omitted.is_empty()
        && candidate_discovery_complete
        && !policy_excluded
            .iter()
            .any(|entry| entry.affects_completeness);
    let mut plan = DefaultProfileSelectionPlan {
        contract_version: DEFAULT_PROFILE_SELECTION_CONTRACT_VERSION.to_owned(),
        selection_mode: ProfileSelectionMode::Automatic,
        input_digest: profile_selection_input_digest(&request.input),
        input: request.input,
        profiles,
        candidates,
        selected: selected_sequence,
        omitted,
        policy_excluded,
        discovery,
        summary: ProfileSelectionSummary {
            eligible_profile_count,
            selected_profile_count,
            omitted_profile_count,
            policy_excluded_count,
            candidate_discovery_complete,
            selection_complete,
        },
        plan_id: String::new(),
    };
    plan.plan_id = canonical_profile_selection_plan_id(&plan);
    validate_profile_selection_plan(&plan)?;
    Ok(plan)
}

pub fn profile_selection_doctor_status(
    plan: &DefaultProfileSelectionPlan,
    strict: bool,
) -> Result<ProfileSelectionDoctorStatus> {
    validate_profile_selection_plan(plan)?;
    let reasons = profile_matrix_incomplete_reasons(plan);
    let default_profile_matrix_complete = reasons.is_empty();
    let mut remediation = Vec::new();
    if !plan.omitted.is_empty() {
        remediation.push("--profile-budget".to_owned());
    }
    if !default_profile_matrix_complete {
        remediation.push("--profiles-file".to_owned());
    }
    Ok(ProfileSelectionDoctorStatus {
        eligible_profile_count: plan.summary.eligible_profile_count,
        selected_profile_count: plan.summary.selected_profile_count,
        omitted_profile_count: plan.summary.omitted_profile_count,
        effective_profile_cap: plan.input.limits.effective_profile_cap,
        default_profile_matrix_complete,
        reasons: reasons.into_iter().collect(),
        remediation,
        strict_exit_code: u8::from(strict && !default_profile_matrix_complete),
    })
}

pub fn profile_selection_human_summary(plan: &DefaultProfileSelectionPlan) -> Result<String> {
    validate_profile_selection_plan(plan)?;
    let mut summary = if plan.summary.omitted_profile_count == 0 {
        format!(
            "profiles: {} selected / {} eligible; default matrix {}",
            plan.summary.selected_profile_count,
            plan.summary.eligible_profile_count,
            if plan.summary.selection_complete {
                "complete"
            } else {
                "incomplete"
            }
        )
    } else {
        format!(
            "profiles: {} selected / {} eligible; {} omitted by {}-repository budget {}",
            plan.summary.selected_profile_count,
            plan.summary.eligible_profile_count,
            plan.summary.omitted_profile_count,
            size_class_name(plan.input.repository.size_class),
            plan.input.limits.effective_profile_cap
        )
    };
    let additional_reasons = profile_matrix_incomplete_reasons(plan)
        .into_iter()
        .filter(|reason| {
            plan.summary.omitted_profile_count == 0
                || *reason != ProfileMatrixIncompleteReason::DefaultProfileBudgetExhausted
        })
        .map(incomplete_reason_human_label)
        .collect::<Vec<_>>();
    if !additional_reasons.is_empty() {
        summary.push_str(if plan.summary.omitted_profile_count == 0 {
            "; incomplete reasons: "
        } else {
            "; additional incomplete reasons: "
        });
        summary.push_str(&additional_reasons.join(", "));
    }
    Ok(summary)
}

fn profile_matrix_incomplete_reasons(
    plan: &DefaultProfileSelectionPlan,
) -> BTreeSet<ProfileMatrixIncompleteReason> {
    let mut reasons = BTreeSet::new();
    if !plan.omitted.is_empty() {
        reasons.insert(ProfileMatrixIncompleteReason::DefaultProfileBudgetExhausted);
    }
    if plan.discovery.iter().any(|entry| !entry.complete) {
        reasons.insert(ProfileMatrixIncompleteReason::DefaultProfileCandidateLimitExceeded);
    }
    for exclusion in &plan.policy_excluded {
        if let Some(reason) = incomplete_exclusion_reason(exclusion.reason) {
            reasons.insert(reason);
        }
    }
    reasons
}

fn merge_candidate_discoveries(
    input: &ProfileSelectionInput,
    discoveries: Vec<ProfileCandidateDiscoveryResult>,
) -> Result<(
    Vec<ProfileSelectionProfile>,
    Vec<ProfileCandidateRecord>,
    Vec<ProfileDiscoveryLedger>,
)> {
    let mut profiles = Vec::new();
    let mut candidates = Vec::new();
    let mut prior_overflow = input
        .language_families
        .iter()
        .map(|language| (*language, 0_u32))
        .collect::<BTreeMap<_, _>>();
    let mut seen_languages = BTreeSet::new();
    for result in discoveries {
        if result.complete != result.discovery.iter().all(|entry| entry.complete) {
            bail!("candidate discovery aggregate completeness is inconsistent");
        }
        for entry in &result.discovery {
            if !input.language_families.contains(&entry.language)
                || !seen_languages.insert(entry.language)
                || entry.complete != (entry.overflow_candidate_count == 0)
                || entry.reason
                    != (entry.overflow_candidate_count > 0)
                        .then_some(CandidateDiscoveryReason::DefaultProfileCandidateLimitExceeded)
            {
                bail!("candidate discovery input ledger is inconsistent or duplicated");
            }
            let actual = result
                .candidates
                .iter()
                .filter(|candidate| {
                    candidate.kind == ProfileCandidateKind::Alternative
                        && result
                            .profiles
                            .iter()
                            .find(|profile| profile.id == candidate.profile_id)
                            .is_some_and(|profile| profile.axes.language() == entry.language)
                })
                .count();
            if entry.discovered_candidate_count != u32::try_from(actual)? {
                bail!("candidate discovery input count does not match retained candidates");
            }
            prior_overflow.insert(entry.language, entry.overflow_candidate_count);
        }
        profiles.extend(result.profiles);
        candidates.extend(result.candidates);
    }
    if seen_languages.len() != input.language_families.len()
        || input
            .language_families
            .iter()
            .any(|language| !seen_languages.contains(language))
    {
        bail!("automatic profile selection requires one discovery result per language family");
    }

    let bounded =
        bound_profile_candidate_discovery(profiles, candidates, &input.language_families)?;
    let mut discovery = bounded.discovery;
    for entry in &mut discovery {
        entry.overflow_candidate_count = entry
            .overflow_candidate_count
            .checked_add(prior_overflow[&entry.language])
            .context("candidate discovery overflow count exceeds u32")?;
        entry.complete = entry.overflow_candidate_count == 0;
        entry.reason = (!entry.complete)
            .then_some(CandidateDiscoveryReason::DefaultProfileCandidateLimitExceeded);
    }
    Ok((bounded.profiles, bounded.candidates, discovery))
}

fn rank_candidate(
    candidate: &ProfileCandidateRecord,
    language: ProfileLanguage,
    tracked: bool,
    covered_files: &BTreeSet<String>,
    covered_sites: &BTreeSet<String>,
) -> ProfileRankEvidence {
    let changed_axis = candidate
        .changed_axis
        .expect("only alternatives are ranked");
    ProfileRankEvidence {
        declaration_tier: if tracked {
            0
        } else {
            match changed_axis {
                ProfileAxis::Target | ProfileAxis::Environment => 1,
                ProfileAxis::Mode => 2,
                ProfileAxis::FeatureOrTag => 3,
            }
        },
        new_dependency_occurrences: candidate
            .estimated_coverage
            .dependency_site_ids
            .iter()
            .filter(|id| !covered_sites.contains(*id))
            .count() as u64,
        new_files: candidate
            .estimated_coverage
            .file_ids
            .iter()
            .filter(|id| !covered_files.contains(*id))
            .count() as u64,
        dimension_priority: axis_priority(changed_axis),
        language_priority: language_priority(language),
    }
}

fn compare_rank(
    left_candidate: &ProfileCandidateRecord,
    left: &ProfileRankEvidence,
    right_candidate: &ProfileCandidateRecord,
    right: &ProfileRankEvidence,
) -> Ordering {
    left.declaration_tier
        .cmp(&right.declaration_tier)
        .then(
            right
                .new_dependency_occurrences
                .cmp(&left.new_dependency_occurrences),
        )
        .then(right.new_files.cmp(&left.new_files))
        .then(left.dimension_priority.cmp(&right.dimension_priority))
        .then(left.language_priority.cmp(&right.language_priority))
        .then(
            left_candidate
                .profile_id
                .as_bytes()
                .cmp(right_candidate.profile_id.as_bytes()),
        )
}

fn extend_coverage(
    candidate: &ProfileCandidateRecord,
    files: &mut BTreeSet<String>,
    sites: &mut BTreeSet<String>,
) {
    files.extend(candidate.estimated_coverage.file_ids.iter().cloned());
    sites.extend(
        candidate
            .estimated_coverage
            .dependency_site_ids
            .iter()
            .cloned(),
    );
}

const fn incomplete_exclusion_reason(
    reason: ProfileExclusionReason,
) -> Option<ProfileMatrixIncompleteReason> {
    match reason {
        ProfileExclusionReason::DefaultProfileDynamicConfigurationNotExecuted => {
            Some(ProfileMatrixIncompleteReason::DefaultProfileDynamicConfigurationNotExecuted)
        }
        ProfileExclusionReason::DefaultProfileUnsupportedAxis => {
            Some(ProfileMatrixIncompleteReason::DefaultProfileUnsupportedAxis)
        }
        ProfileExclusionReason::DefaultProfileMalformedDeclaration => {
            Some(ProfileMatrixIncompleteReason::DefaultProfileMalformedDeclaration)
        }
        ProfileExclusionReason::DefaultProfileCombinationRequiresExplicitSelection
        | ProfileExclusionReason::DefaultProfileBuildRequiresConsent
        | ProfileExclusionReason::DefaultProfileRuntimeRequiresTrace => None,
    }
}

const fn incomplete_reason_human_label(reason: ProfileMatrixIncompleteReason) -> &'static str {
    match reason {
        ProfileMatrixIncompleteReason::DefaultProfileBudgetExhausted => "profile budget exhausted",
        ProfileMatrixIncompleteReason::DefaultProfileCandidateLimitExceeded => {
            "candidate discovery limit exceeded"
        }
        ProfileMatrixIncompleteReason::DefaultProfileDynamicConfigurationNotExecuted => {
            "dynamic configuration not executed"
        }
        ProfileMatrixIncompleteReason::DefaultProfileUnsupportedAxis => "unsupported profile axis",
        ProfileMatrixIncompleteReason::DefaultProfileMalformedDeclaration => {
            "malformed profile declaration"
        }
    }
}

const fn axis_priority(axis: ProfileAxis) -> u8 {
    match axis {
        ProfileAxis::Target => 0,
        ProfileAxis::Environment => 1,
        ProfileAxis::Mode => 2,
        ProfileAxis::FeatureOrTag => 3,
    }
}

const fn language_priority(language: ProfileLanguage) -> u8 {
    match language {
        ProfileLanguage::Rust => 0,
        ProfileLanguage::Go => 1,
        ProfileLanguage::Web => 2,
    }
}

const fn size_class_name(size_class: RepositorySizeClass) -> &'static str {
    match size_class {
        RepositorySizeClass::Tiny => "tiny",
        RepositorySizeClass::Small => "small",
        RepositorySizeClass::Medium => "medium",
        RepositorySizeClass::Large => "large",
    }
}

#[cfg(test)]
mod tests {
    use depgraph_protocol::stable_id_from_value;

    use crate::{
        CanonicalProfileAxes, DEFAULT_PROFILE_SELECTION_LIMIT_VERSION, GoCallGraph, GoProfileAxes,
        MAX_AUTOMATIC_PROFILE_CANDIDATES, MAX_AUTOMATIC_PROFILE_CANDIDATES_PER_LANGUAGE,
        MAX_SELECTED_ROOT_PROFILES, ProfileCandidateCoverage, ProfileCandidateEvidence,
        ProfileCandidateEvidenceKind, ProfileHostContext, ProfileSelectionLimits,
        ProfileSelectionRepository, RustHostContext, RustProfileAxes, RustProfileMode,
        WebEnvironment, WebProfileAxes, WebProfileMode, canonical_profile_id,
        canonical_profile_selection_json, profile_candidate_id, profile_exclusion_id,
    };

    use super::*;

    fn stable_id(namespace: &str, value: impl Serialize) -> String {
        stable_id_from_value(namespace, &serde_json::to_value(value).unwrap())
    }

    fn input(cap: u32) -> ProfileSelectionInput {
        ProfileSelectionInput {
            contract_version: DEFAULT_PROFILE_SELECTION_CONTRACT_VERSION.to_owned(),
            inventory_digest: format!("sha256:{}", "a".repeat(64)),
            compatibility_ids: vec!["depgraph-protocol:1.0".to_owned()],
            language_families: vec![
                ProfileLanguage::Go,
                ProfileLanguage::Rust,
                ProfileLanguage::Web,
            ],
            inventory_language_families: vec![
                ProfileLanguage::Go,
                ProfileLanguage::Rust,
                ProfileLanguage::Web,
            ],
            host_contexts: vec![
                ProfileHostContext::Go(crate::GoHostContext {
                    goos: "darwin".to_owned(),
                    goarch: "arm64".to_owned(),
                }),
                ProfileHostContext::Rust(RustHostContext {
                    target: "aarch64-apple-darwin".to_owned(),
                }),
            ],
            configuration_digest: None,
            selection_file_digest: None,
            supported_axes: vec![
                crate::ProfileAxisCapability {
                    language: ProfileLanguage::Go,
                    axis: ProfileAxis::Target,
                },
                crate::ProfileAxisCapability {
                    language: ProfileLanguage::Rust,
                    axis: ProfileAxis::Target,
                },
                crate::ProfileAxisCapability {
                    language: ProfileLanguage::Web,
                    axis: ProfileAxis::Mode,
                },
            ],
            repository: ProfileSelectionRepository {
                size_class: RepositorySizeClass::Large,
                relevant_source_files: 50_001,
                build_units: 500,
            },
            limits: ProfileSelectionLimits {
                limit_version: DEFAULT_PROFILE_SELECTION_LIMIT_VERSION.to_owned(),
                effective_profile_cap: cap,
                hard_profile_cap: MAX_SELECTED_ROOT_PROFILES,
                per_language_candidate_cap: MAX_AUTOMATIC_PROFILE_CANDIDATES_PER_LANGUAGE,
                total_candidate_cap: MAX_AUTOMATIC_PROFILE_CANDIDATES,
            },
        }
    }

    fn rust_axes(target: &str) -> CanonicalProfileAxes {
        CanonicalProfileAxes::Rust(RustProfileAxes {
            target: target.to_owned(),
            mode: RustProfileMode::Check,
            default_features: true,
            features: Vec::new(),
        })
    }

    fn rust_mode_axes(mode: RustProfileMode) -> CanonicalProfileAxes {
        CanonicalProfileAxes::Rust(RustProfileAxes {
            target: "host".to_owned(),
            mode,
            default_features: true,
            features: Vec::new(),
        })
    }

    fn go_axes(goos: &str) -> CanonicalProfileAxes {
        CanonicalProfileAxes::Go(GoProfileAxes {
            goos: goos.to_owned(),
            goarch: "arm64".to_owned(),
            tags: Vec::new(),
            cgo_enabled: false,
            call_graph: GoCallGraph::RtaCha,
            dependency_snapshot_id: stable_id("go-dependency-snapshot", "snapshot"),
        })
    }

    fn web_axes(mode: WebProfileMode) -> CanonicalProfileAxes {
        CanonicalProfileAxes::Web(WebProfileAxes {
            mode,
            environments: vec![WebEnvironment::Browser, WebEnvironment::Server],
            bundled_typescript_compatibility_id: stable_id(
                "web-typescript-compatibility",
                "typescript",
            ),
            package_snapshot_id: stable_id("web-package-snapshot", "packages"),
            framework_capability_ids: vec![stable_id("web-framework-capability", "framework")],
        })
    }

    fn family(
        baseline_axes: CanonicalProfileAxes,
        alternatives: Vec<(CanonicalProfileAxes, ProfileAxis, &[&str], &[&str])>,
    ) -> ProfileCandidateDiscoveryResult {
        let baseline = profile(baseline_axes);
        let baseline_id = baseline.id.clone();
        let mut profiles = vec![baseline.clone()];
        let mut candidates = vec![candidate(
            &baseline,
            &baseline_id,
            ProfileCandidateKind::Baseline,
            None,
            &[],
            &["baseline"],
            &["baseline"],
        )];
        for (axes, changed_axis, files, sites) in alternatives {
            let profile = profile(axes);
            let axis_values = match (&profile.axes, changed_axis) {
                (CanonicalProfileAxes::Rust(axes), ProfileAxis::Target) => {
                    vec![axes.target.clone()]
                }
                (CanonicalProfileAxes::Rust(axes), ProfileAxis::Mode) => {
                    vec![axes.mode.as_str().to_owned()]
                }
                (CanonicalProfileAxes::Go(axes), ProfileAxis::Target) => {
                    vec![format!("{}/{}", axes.goos, axes.goarch)]
                }
                (CanonicalProfileAxes::Web(axes), ProfileAxis::Mode) => vec![
                    match axes.mode {
                        WebProfileMode::Production => "production",
                        WebProfileMode::Development => "development",
                        WebProfileMode::Test => "test",
                    }
                    .to_owned(),
                ],
                _ => unreachable!(),
            };
            candidates.push(candidate(
                &profile,
                &baseline_id,
                ProfileCandidateKind::Alternative,
                Some(changed_axis),
                &axis_values.iter().map(String::as_str).collect::<Vec<_>>(),
                files,
                sites,
            ));
            profiles.push(profile);
        }
        let language = baseline.axes.language();
        bound_profile_candidate_discovery(profiles, candidates, &[language]).unwrap()
    }

    fn profile(axes: CanonicalProfileAxes) -> ProfileSelectionProfile {
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
        axis_values: &[&str],
        files: &[&str],
        sites: &[&str],
    ) -> ProfileCandidateRecord {
        let mut candidate = ProfileCandidateRecord {
            id: String::new(),
            profile_id: profile.id.clone(),
            baseline_profile_id: baseline_profile_id.to_owned(),
            kind,
            changed_axis,
            axis_values: axis_values
                .iter()
                .map(|value| (*value).to_owned())
                .collect(),
            estimated_coverage: ProfileCandidateCoverage {
                file_ids: files.iter().map(|value| stable_id("file", value)).collect(),
                dependency_site_ids: sites.iter().map(|value| stable_id("site", value)).collect(),
            },
            evidence: vec![ProfileCandidateEvidence {
                kind: ProfileCandidateEvidenceKind::Source,
                path: format!("src/{}.rs", profile.id.replace(':', "-")),
                start_line: 1,
                end_line: 1,
            }],
        };
        candidate.id = profile_candidate_id(&candidate);
        candidate
    }

    fn polyglot_discoveries() -> Vec<ProfileCandidateDiscoveryResult> {
        vec![
            family(
                rust_axes("host"),
                vec![
                    (
                        rust_axes("linux"),
                        ProfileAxis::Target,
                        &["rust-linux"],
                        &["shared", "rust-linux"],
                    ),
                    (
                        rust_axes("wasm"),
                        ProfileAxis::Target,
                        &["rust-wasm"],
                        &["rust-wasm"],
                    ),
                    (
                        rust_mode_axes(RustProfileMode::Test),
                        ProfileAxis::Mode,
                        &["rust-test"],
                        &["rust-test"],
                    ),
                ],
            ),
            family(
                go_axes("darwin"),
                vec![(
                    go_axes("linux"),
                    ProfileAxis::Target,
                    &["go-linux"],
                    &["shared", "go-linux"],
                )],
            ),
            family(
                web_axes(WebProfileMode::Production),
                vec![(
                    web_axes(WebProfileMode::Test),
                    ProfileAxis::Mode,
                    &["web-test"],
                    &["web-test"],
                )],
            ),
        ]
    }

    #[test]
    fn every_polyglot_baseline_is_selected_before_optional_candidates() -> Result<()> {
        let plan = plan_automatic_profile_selection(AutomaticProfileSelectionRequest {
            input: input(4),
            discoveries: polyglot_discoveries(),
            policy_excluded: Vec::new(),
            tracked_candidate_ids: Vec::new(),
        })?;
        let candidates = plan
            .candidates
            .iter()
            .map(|candidate| (candidate.id.as_str(), candidate))
            .collect::<BTreeMap<_, _>>();
        let baseline_ranks = plan
            .selected
            .iter()
            .filter(|selected| {
                candidates[selected.candidate_id.as_str()].kind == ProfileCandidateKind::Baseline
            })
            .map(|selected| selected.selection_rank)
            .collect::<Vec<_>>();
        let optional_rank = plan
            .selected
            .iter()
            .find(|selected| {
                candidates[selected.candidate_id.as_str()].kind == ProfileCandidateKind::Alternative
            })
            .context("selected optional profile")?
            .selection_rank;
        assert_eq!(baseline_ranks.len(), 3);
        assert!(baseline_ranks.iter().all(|rank| *rank < optional_rank));
        assert_eq!(plan.summary.omitted_profile_count, 4);
        Ok(())
    }

    #[test]
    fn reordered_candidates_have_byte_identical_selected_and_omitted_ledgers() -> Result<()> {
        let first = plan_automatic_profile_selection(AutomaticProfileSelectionRequest {
            input: input(4),
            discoveries: polyglot_discoveries(),
            policy_excluded: Vec::new(),
            tracked_candidate_ids: Vec::new(),
        })?;
        let mut reordered = polyglot_discoveries();
        reordered.reverse();
        for discovery in &mut reordered {
            discovery.profiles.reverse();
            discovery.candidates.reverse();
            discovery.discovery.reverse();
        }
        let second = plan_automatic_profile_selection(AutomaticProfileSelectionRequest {
            input: input(4),
            discoveries: reordered,
            policy_excluded: Vec::new(),
            tracked_candidate_ids: Vec::new(),
        })?;
        assert_eq!(first.selected, second.selected);
        assert_eq!(first.omitted, second.omitted);
        assert_eq!(
            canonical_profile_selection_json(&first),
            canonical_profile_selection_json(&second)
        );
        Ok(())
    }

    #[test]
    fn budget_omission_and_discovery_overflow_have_distinct_operational_reasons() -> Result<()> {
        let mut discoveries = polyglot_discoveries();
        discoveries[0].discovery[0].overflow_candidate_count = 2;
        discoveries[0].discovery[0].complete = false;
        discoveries[0].discovery[0].reason =
            Some(CandidateDiscoveryReason::DefaultProfileCandidateLimitExceeded);
        discoveries[0].complete = false;
        let mut exclusion = ProfilePolicyExclusion {
            id: String::new(),
            language: ProfileLanguage::Web,
            axis: Some(ProfileAxis::Environment),
            axis_values: vec!["worker".to_owned()],
            reason: ProfileExclusionReason::DefaultProfileDynamicConfigurationNotExecuted,
            affects_completeness: true,
            evidence: vec![ProfileCandidateEvidence {
                kind: ProfileCandidateEvidenceKind::Source,
                path: "src/worker.ts".to_owned(),
                start_line: 1,
                end_line: 1,
            }],
        };
        exclusion.id = profile_exclusion_id(&exclusion);
        let plan = plan_automatic_profile_selection(AutomaticProfileSelectionRequest {
            input: input(3),
            discoveries,
            policy_excluded: vec![exclusion],
            tracked_candidate_ids: Vec::new(),
        })?;
        let status = profile_selection_doctor_status(&plan, true)?;
        assert_eq!(
            status.reasons,
            vec![
                ProfileMatrixIncompleteReason::DefaultProfileBudgetExhausted,
                ProfileMatrixIncompleteReason::DefaultProfileCandidateLimitExceeded,
                ProfileMatrixIncompleteReason::DefaultProfileDynamicConfigurationNotExecuted,
            ]
        );
        assert_eq!(status.strict_exit_code, 1);
        assert!(status.remediation.contains(&"--profile-budget".to_owned()));
        assert!(status.remediation.contains(&"--profiles-file".to_owned()));
        assert_eq!(
            profile_selection_human_summary(&plan)?,
            "profiles: 3 selected / 8 eligible; 5 omitted by large-repository budget 3; additional incomplete reasons: candidate discovery limit exceeded, dynamic configuration not executed"
        );
        Ok(())
    }

    #[test]
    fn strict_non_strict_size_class_and_human_summary_are_explicit() -> Result<()> {
        let plan = plan_automatic_profile_selection(AutomaticProfileSelectionRequest {
            input: input(4),
            discoveries: polyglot_discoveries(),
            policy_excluded: Vec::new(),
            tracked_candidate_ids: Vec::new(),
        })?;
        assert_eq!(
            profile_selection_doctor_status(&plan, false)?.strict_exit_code,
            0
        );
        assert_eq!(
            profile_selection_doctor_status(&plan, true)?.strict_exit_code,
            1
        );
        assert_eq!(
            profile_selection_human_summary(&plan)?,
            "profiles: 4 selected / 8 eligible; 4 omitted by large-repository budget 4"
        );
        Ok(())
    }

    #[test]
    fn tracked_declaration_tier_precedes_coverage_ranking() -> Result<()> {
        let discoveries = polyglot_discoveries();
        let tracked_id = discoveries[2]
            .candidates
            .iter()
            .find(|candidate| candidate.kind == ProfileCandidateKind::Alternative)
            .context("tracked candidate")?
            .id
            .clone();
        let plan = plan_automatic_profile_selection(AutomaticProfileSelectionRequest {
            input: input(4),
            discoveries,
            policy_excluded: Vec::new(),
            tracked_candidate_ids: vec![tracked_id.clone()],
        })?;
        let selected = plan
            .selected
            .iter()
            .find(|selected| selected.candidate_id == tracked_id)
            .context("tracked selection")?;
        assert_eq!(selected.selection_rank, 3);
        assert_eq!(
            selected.reason,
            ProfileSelectedReason::TrackedProfileConfiguration
        );
        assert_eq!(
            selected
                .rank
                .as_ref()
                .context("tracked rank")?
                .declaration_tier,
            0
        );
        Ok(())
    }

    #[test]
    fn greedy_gain_is_recomputed_and_dimension_language_ties_are_closed() -> Result<()> {
        let plan = plan_automatic_profile_selection(AutomaticProfileSelectionRequest {
            input: input(7),
            discoveries: polyglot_discoveries(),
            policy_excluded: Vec::new(),
            tracked_candidate_ids: Vec::new(),
        })?;
        let mut ranked = plan
            .selected
            .iter()
            .filter_map(|selected| {
                selected
                    .rank
                    .as_ref()
                    .map(|rank| (selected.selection_rank, selected.profile_id.as_str(), rank))
            })
            .collect::<Vec<_>>();
        ranked.sort_by_key(|entry| entry.0);
        assert_eq!(ranked.len(), 4);
        assert_eq!(
            (
                ranked[0].2.declaration_tier,
                ranked[0].2.new_dependency_occurrences,
                ranked[0].2.dimension_priority,
                ranked[0].2.language_priority,
            ),
            (1, 2, 0, 0)
        );
        assert_eq!(
            (
                ranked[1].2.new_dependency_occurrences,
                ranked[1].2.dimension_priority,
                ranked[1].2.language_priority,
            ),
            (1, 0, 0)
        );
        assert_eq!(
            (
                ranked[2].2.new_dependency_occurrences,
                ranked[2].2.dimension_priority,
                ranked[2].2.language_priority,
            ),
            (1, 0, 1)
        );
        assert_eq!(
            (
                ranked[3].2.declaration_tier,
                ranked[3].2.dimension_priority,
                ranked[3].2.language_priority,
            ),
            (2, 2, 0)
        );
        Ok(())
    }

    #[test]
    fn complete_plan_has_green_doctor_and_strict_status() -> Result<()> {
        let plan = plan_automatic_profile_selection(AutomaticProfileSelectionRequest {
            input: input(8),
            discoveries: polyglot_discoveries(),
            policy_excluded: Vec::new(),
            tracked_candidate_ids: Vec::new(),
        })?;
        let status = profile_selection_doctor_status(&plan, true)?;
        assert!(status.default_profile_matrix_complete);
        assert!(status.reasons.is_empty());
        assert_eq!(status.strict_exit_code, 0);
        assert_eq!(
            profile_selection_human_summary(&plan)?,
            "profiles: 8 selected / 8 eligible; default matrix complete"
        );
        Ok(())
    }
}
