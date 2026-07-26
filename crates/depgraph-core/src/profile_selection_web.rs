use std::collections::BTreeMap;

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

use crate::{
    CanonicalProfileAxes, ProfileAxis, ProfileCandidateCoverage, ProfileCandidateDiscoveryResult,
    ProfileCandidateEvidence, ProfileCandidateEvidenceKind, ProfileCandidateKind,
    ProfileCandidateRecord, ProfileExclusionReason, ProfileLanguage, ProfilePolicyExclusion,
    ProfileSelectionProfile, WebEnvironment, WebProfileAxes, WebProfileMode,
    bound_profile_candidate_discovery, canonical_profile_id, profile_candidate_id,
    profile_exclusion_id,
};

pub const WEB_PROFILE_PLANNING_VERSION: &str = "web-profile-planning-v1";

const MAX_WEB_ENVIRONMENT_DECLARATIONS: usize = 8_192;
const MAX_WEB_MODE_DECLARATIONS: usize = 4_096;
const MAX_WEB_REJECTED_DECLARATIONS: usize = 4_096;
const MAX_WEB_FRAMEWORK_CAPABILITIES: usize = 64;
const MAX_WEB_EXPORT_CONDITIONS: usize = 256;
const MAX_WEB_POLICY_EXCLUSIONS: usize = 512;
const MAX_AXIS_VALUE_CHARS: usize = 256;
const MAX_EVIDENCE_ITEMS: usize = 65_536;
const MAX_EVIDENCE_PATH_CHARS: usize = 4_096;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WebProfileAvailability {
    Available,
    Unavailable,
    Unsupported,
}

impl WebProfileAvailability {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Available => "available",
            Self::Unavailable => "unavailable",
            Self::Unsupported => "unsupported",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WebFramework {
    Next,
    Astro,
    Tanstack,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WebDeclarationSource {
    PackageExports,
    FrameworkMetadata,
    ManifestScript,
    SourceRole,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WebStaticProfileEvidence {
    pub estimated_coverage: ProfileCandidateCoverage,
    pub evidence: Vec<ProfileCandidateEvidence>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WebEnvironmentDeclaration {
    pub environment: WebEnvironment,
    pub source: WebDeclarationSource,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub framework: Option<WebFramework>,
    pub ordered_conditions: Vec<String>,
    pub availability: WebProfileAvailability,
    pub static_evidence: WebStaticProfileEvidence,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WebModeDeclaration {
    pub mode: WebProfileMode,
    pub source: WebDeclarationSource,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub framework: Option<WebFramework>,
    pub availability: WebProfileAvailability,
    pub static_evidence: WebStaticProfileEvidence,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WebAutomaticBoundaryKind {
    BuildProfile,
    RuntimeProfile,
    DynamicConfiguration,
    ProjectCode,
    InsufficientEvidence,
    CartesianCombination,
    MalformedDeclaration,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WebRejectedProfileDeclaration {
    pub kind: WebAutomaticBoundaryKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub axis: Option<ProfileAxis>,
    pub axis_values: Vec<String>,
    pub evidence: Vec<ProfileCandidateEvidence>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WebProfilePlanningInput {
    pub planning_version: String,
    pub bundled_typescript_compatibility_id: String,
    pub package_snapshot_id: String,
    pub framework_capability_ids: Vec<String>,
    pub baseline: WebStaticProfileEvidence,
    pub environments: Vec<WebEnvironmentDeclaration>,
    pub modes: Vec<WebModeDeclaration>,
    pub rejected: Vec<WebRejectedProfileDeclaration>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WebProfileCandidateGenerationResult {
    pub bounded: ProfileCandidateDiscoveryResult,
    pub policy_excluded: Vec<ProfilePolicyExclusion>,
    pub baseline_profile_id: String,
}

pub fn generate_web_profile_candidates(
    mut input: WebProfilePlanningInput,
) -> Result<WebProfileCandidateGenerationResult> {
    if input.planning_version != WEB_PROFILE_PLANNING_VERSION {
        bail!("unsupported Web profile planning version; expected {WEB_PROFILE_PLANNING_VERSION}");
    }
    if input.environments.len() > MAX_WEB_ENVIRONMENT_DECLARATIONS
        || input.modes.len() > MAX_WEB_MODE_DECLARATIONS
        || input.rejected.len() > MAX_WEB_REJECTED_DECLARATIONS
        || input.framework_capability_ids.len() > MAX_WEB_FRAMEWORK_CAPABILITIES
    {
        bail!("Web profile planning input exceeds a closed declaration limit");
    }
    validate_stable_id(
        "Web bundled TypeScript compatibility id",
        &input.bundled_typescript_compatibility_id,
        "web-typescript-compatibility",
    )?;
    validate_stable_id(
        "Web package snapshot id",
        &input.package_snapshot_id,
        "web-package-snapshot",
    )?;
    canonicalize_framework_capabilities(&mut input.framework_capability_ids)?;
    canonicalize_static_evidence(&mut input.baseline)?;

    let baseline_axes = WebProfileAxes {
        mode: WebProfileMode::Production,
        environments: vec![WebEnvironment::Browser, WebEnvironment::Server],
        bundled_typescript_compatibility_id: input.bundled_typescript_compatibility_id,
        package_snapshot_id: input.package_snapshot_id,
        framework_capability_ids: input.framework_capability_ids,
    };
    let baseline_profile = profile(baseline_axes.clone());
    let baseline_profile_id = baseline_profile.id.clone();
    let baseline_candidate = candidate(
        &baseline_profile,
        &baseline_profile_id,
        ProfileCandidateKind::Baseline,
        None,
        Vec::new(),
        input.baseline,
    );

    let environments = canonical_environments(input.environments)?;
    let modes = canonical_modes(input.modes)?;
    let mut profiles = vec![baseline_profile];
    let mut candidates = vec![baseline_candidate];
    let mut exclusions = Vec::new();

    for (environment, declaration) in environments {
        let mut candidate_environments = baseline_axes.environments.clone();
        candidate_environments.push(environment);
        canonicalize_environments(&mut candidate_environments);
        let axis_values = candidate_environments
            .iter()
            .map(|value| environment_name(*value).to_owned())
            .collect::<Vec<_>>();
        if declaration.availability != WebProfileAvailability::Available {
            exclusions.push(availability_exclusion(
                Some(ProfileAxis::Environment),
                axis_values,
                declaration.availability,
                declaration.static_evidence.evidence,
            ));
            continue;
        }
        let alternative = profile(WebProfileAxes {
            environments: candidate_environments,
            ..baseline_axes.clone()
        });
        candidates.push(candidate(
            &alternative,
            &baseline_profile_id,
            ProfileCandidateKind::Alternative,
            Some(ProfileAxis::Environment),
            axis_values,
            declaration.static_evidence,
        ));
        profiles.push(alternative);
    }

    for (mode, declaration) in modes {
        let axis_values = vec![mode_name(mode).to_owned()];
        if declaration.availability != WebProfileAvailability::Available {
            exclusions.push(availability_exclusion(
                Some(ProfileAxis::Mode),
                axis_values,
                declaration.availability,
                declaration.static_evidence.evidence,
            ));
            continue;
        }
        let alternative = profile(WebProfileAxes {
            mode,
            ..baseline_axes.clone()
        });
        candidates.push(candidate(
            &alternative,
            &baseline_profile_id,
            ProfileCandidateKind::Alternative,
            Some(ProfileAxis::Mode),
            axis_values,
            declaration.static_evidence,
        ));
        profiles.push(alternative);
    }

    for mut rejected in input.rejected {
        canonicalize_evidence(&mut rejected.evidence)?;
        for value in &rejected.axis_values {
            validate_axis_value("Web rejected axis value", value)?;
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
    if exclusions.len() > MAX_WEB_POLICY_EXCLUSIONS {
        bail!("Web profile planning exceeds the closed policy-exclusion limit");
    }
    let bounded = bound_profile_candidate_discovery(profiles, candidates, &[ProfileLanguage::Web])?;
    Ok(WebProfileCandidateGenerationResult {
        bounded,
        policy_excluded: exclusions,
        baseline_profile_id,
    })
}

fn canonical_environments(
    mut declarations: Vec<WebEnvironmentDeclaration>,
) -> Result<BTreeMap<WebEnvironment, WebEnvironmentDeclaration>> {
    declarations.sort_by(|left, right| {
        environment_name(left.environment)
            .as_bytes()
            .cmp(environment_name(right.environment).as_bytes())
            .then(declaration_source_name(left.source).cmp(declaration_source_name(right.source)))
            .then(
                framework_name(left.framework)
                    .as_bytes()
                    .cmp(framework_name(right.framework).as_bytes()),
            )
            .then(left.ordered_conditions.cmp(&right.ordered_conditions))
    });
    let mut canonical = BTreeMap::<WebEnvironment, WebEnvironmentDeclaration>::new();
    for mut declaration in declarations {
        if !matches!(
            declaration.environment,
            WebEnvironment::Edge | WebEnvironment::Worker
        ) {
            bail!("automatic Web environment candidates are limited to edge or worker");
        }
        canonicalize_static_evidence(&mut declaration.static_evidence)?;
        validate_declaration_source(
            declaration.source,
            declaration.framework,
            &declaration.ordered_conditions,
            &declaration.static_evidence.evidence,
            Some(declaration.environment),
        )?;
        if let Some(previous) = canonical.get_mut(&declaration.environment) {
            if previous.availability != declaration.availability {
                bail!("one Web environment cannot have conflicting availability");
            }
            merge_static_evidence(&mut previous.static_evidence, declaration.static_evidence);
            canonicalize_static_evidence(&mut previous.static_evidence)?;
        } else {
            canonical.insert(declaration.environment, declaration);
        }
    }
    Ok(canonical)
}

fn canonical_modes(
    mut declarations: Vec<WebModeDeclaration>,
) -> Result<BTreeMap<WebProfileMode, WebModeDeclaration>> {
    declarations.sort_by(|left, right| {
        mode_name(left.mode)
            .as_bytes()
            .cmp(mode_name(right.mode).as_bytes())
            .then(declaration_source_name(left.source).cmp(declaration_source_name(right.source)))
            .then(
                framework_name(left.framework)
                    .as_bytes()
                    .cmp(framework_name(right.framework).as_bytes()),
            )
    });
    let mut canonical = BTreeMap::<WebProfileMode, WebModeDeclaration>::new();
    for mut declaration in declarations {
        if !matches!(
            declaration.mode,
            WebProfileMode::Development | WebProfileMode::Test
        ) {
            bail!("automatic Web mode candidates are limited to development or test");
        }
        canonicalize_static_evidence(&mut declaration.static_evidence)?;
        validate_declaration_source(
            declaration.source,
            declaration.framework,
            &[],
            &declaration.static_evidence.evidence,
            None,
        )?;
        if declaration.source == WebDeclarationSource::PackageExports {
            bail!("package exports cannot prove a Web development or test mode");
        }
        if let Some(previous) = canonical.get_mut(&declaration.mode) {
            if previous.availability != declaration.availability {
                bail!("one Web mode cannot have conflicting availability");
            }
            merge_static_evidence(&mut previous.static_evidence, declaration.static_evidence);
            canonicalize_static_evidence(&mut previous.static_evidence)?;
        } else {
            canonical.insert(declaration.mode, declaration);
        }
    }
    Ok(canonical)
}

fn validate_declaration_source(
    source: WebDeclarationSource,
    framework: Option<WebFramework>,
    ordered_conditions: &[String],
    evidence: &[ProfileCandidateEvidence],
    environment: Option<WebEnvironment>,
) -> Result<()> {
    match source {
        WebDeclarationSource::PackageExports => {
            if framework.is_some()
                || ordered_conditions.is_empty()
                || ordered_conditions.len() > MAX_WEB_EXPORT_CONDITIONS
            {
                bail!(
                    "Web package-export evidence requires bounded ordered conditions and no framework"
                );
            }
            let mut seen = BTreeMap::new();
            for condition in ordered_conditions {
                validate_axis_value("Web package export condition", condition)?;
                if seen.insert(condition, ()).is_some() {
                    bail!("Web package export conditions must be unique in declaration order");
                }
            }
            let environment = environment
                .ok_or_else(|| anyhow::anyhow!("package exports require an environment"))?;
            if !ordered_conditions
                .iter()
                .any(|condition| export_condition_matches(environment, condition))
            {
                bail!("Web package export conditions do not prove the declared environment");
            }
            if !evidence.iter().any(|item| {
                item.kind == ProfileCandidateEvidenceKind::Manifest
                    && item.path.ends_with("package.json")
            }) {
                bail!("Web package exports require package.json manifest evidence");
            }
        }
        WebDeclarationSource::FrameworkMetadata => {
            if framework.is_none() || !ordered_conditions.is_empty() {
                bail!("Web framework metadata requires a recognized framework and no conditions");
            }
            if !evidence.iter().any(|item| {
                matches!(
                    item.kind,
                    ProfileCandidateEvidenceKind::Config
                        | ProfileCandidateEvidenceKind::Manifest
                        | ProfileCandidateEvidenceKind::Source
                )
            }) {
                bail!(
                    "Web framework metadata requires static config, manifest, or source evidence"
                );
            }
        }
        WebDeclarationSource::ManifestScript => {
            if framework.is_some() || !ordered_conditions.is_empty() {
                bail!("Web manifest script evidence cannot carry framework or export conditions");
            }
            if !evidence.iter().any(|item| {
                item.kind == ProfileCandidateEvidenceKind::Manifest
                    && item.path.ends_with("package.json")
            }) {
                bail!("Web manifest script requires package.json evidence");
            }
        }
        WebDeclarationSource::SourceRole => {
            if !ordered_conditions.is_empty()
                || !evidence
                    .iter()
                    .any(|item| item.kind == ProfileCandidateEvidenceKind::Source)
            {
                bail!("Web source-role declaration requires static source evidence");
            }
        }
    }
    Ok(())
}

fn export_condition_matches(environment: WebEnvironment, condition: &str) -> bool {
    match environment {
        WebEnvironment::Edge => matches!(condition, "edge" | "edge-light" | "workerd"),
        WebEnvironment::Worker => {
            matches!(
                condition,
                "worker" | "workers" | "workerd" | "serviceworker"
            )
        }
        WebEnvironment::Browser | WebEnvironment::Server => false,
    }
}

fn canonicalize_framework_capabilities(capabilities: &mut Vec<String>) -> Result<()> {
    capabilities.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    capabilities.dedup();
    for capability in capabilities {
        validate_stable_id(
            "Web framework capability id",
            capability,
            "web-framework-capability",
        )?;
    }
    Ok(())
}

fn profile(mut axes: WebProfileAxes) -> ProfileSelectionProfile {
    canonicalize_environments(&mut axes.environments);
    axes.framework_capability_ids
        .sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    axes.framework_capability_ids.dedup();
    let axes = CanonicalProfileAxes::Web(axes);
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
    static_evidence: WebStaticProfileEvidence,
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

fn canonicalize_environments(environments: &mut Vec<WebEnvironment>) {
    environments.sort_by(|left, right| {
        environment_name(*left)
            .as_bytes()
            .cmp(environment_name(*right).as_bytes())
    });
    environments.dedup();
}

fn availability_exclusion(
    axis: Option<ProfileAxis>,
    mut axis_values: Vec<String>,
    availability: WebProfileAvailability,
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

const fn rejection_reason(kind: WebAutomaticBoundaryKind) -> ProfileExclusionReason {
    match kind {
        WebAutomaticBoundaryKind::BuildProfile | WebAutomaticBoundaryKind::ProjectCode => {
            ProfileExclusionReason::DefaultProfileBuildRequiresConsent
        }
        WebAutomaticBoundaryKind::RuntimeProfile => {
            ProfileExclusionReason::DefaultProfileRuntimeRequiresTrace
        }
        WebAutomaticBoundaryKind::DynamicConfiguration => {
            ProfileExclusionReason::DefaultProfileDynamicConfigurationNotExecuted
        }
        WebAutomaticBoundaryKind::InsufficientEvidence => {
            ProfileExclusionReason::DefaultProfileUnsupportedAxis
        }
        WebAutomaticBoundaryKind::CartesianCombination => {
            ProfileExclusionReason::DefaultProfileCombinationRequiresExplicitSelection
        }
        WebAutomaticBoundaryKind::MalformedDeclaration => {
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
        language: ProfileLanguage::Web,
        axis,
        axis_values,
        reason,
        affects_completeness,
        evidence,
    };
    exclusion.id = profile_exclusion_id(&exclusion);
    exclusion
}

fn canonicalize_static_evidence(evidence: &mut WebStaticProfileEvidence) -> Result<()> {
    evidence
        .estimated_coverage
        .file_ids
        .sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    evidence.estimated_coverage.file_ids.dedup();
    for id in &evidence.estimated_coverage.file_ids {
        validate_stable_id("Web profile file coverage ID", id, "file")?;
    }
    evidence
        .estimated_coverage
        .dependency_site_ids
        .sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    evidence.estimated_coverage.dependency_site_ids.dedup();
    for id in &evidence.estimated_coverage.dependency_site_ids {
        validate_stable_id("Web profile dependency-site coverage ID", id, "site")?;
    }
    canonicalize_evidence(&mut evidence.evidence)
}

fn canonicalize_evidence(evidence: &mut Vec<ProfileCandidateEvidence>) -> Result<()> {
    if evidence.is_empty() || evidence.len() > MAX_EVIDENCE_ITEMS {
        bail!("Web profile evidence must be non-empty and within its closed item limit");
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
            bail!("Web profile evidence line range is invalid");
        }
    }
    Ok(())
}

fn merge_static_evidence(target: &mut WebStaticProfileEvidence, source: WebStaticProfileEvidence) {
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

fn evidence_kind(evidence: &ProfileCandidateEvidence) -> &'static str {
    use ProfileCandidateEvidenceKind::{Config, HostContext, Manifest, Source};
    match evidence.kind {
        Config => "config",
        Manifest => "manifest",
        Source => "source",
        HostContext => "host_context",
    }
}

const fn environment_name(environment: WebEnvironment) -> &'static str {
    match environment {
        WebEnvironment::Browser => "browser",
        WebEnvironment::Server => "server",
        WebEnvironment::Edge => "edge",
        WebEnvironment::Worker => "worker",
    }
}

const fn mode_name(mode: WebProfileMode) -> &'static str {
    match mode {
        WebProfileMode::Production => "production",
        WebProfileMode::Development => "development",
        WebProfileMode::Test => "test",
    }
}

const fn declaration_source_name(source: WebDeclarationSource) -> &'static str {
    match source {
        WebDeclarationSource::PackageExports => "package_exports",
        WebDeclarationSource::FrameworkMetadata => "framework_metadata",
        WebDeclarationSource::ManifestScript => "manifest_script",
        WebDeclarationSource::SourceRole => "source_role",
    }
}

const fn framework_name(framework: Option<WebFramework>) -> &'static str {
    match framework {
        None => "",
        Some(WebFramework::Next) => "next",
        Some(WebFramework::Astro) => "astro",
        Some(WebFramework::Tanstack) => "tanstack",
    }
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
        bail!("Web profile evidence path must be a confined repository-relative path");
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

    fn stable_id(namespace: &str, name: &str) -> String {
        stable_id_from_value(namespace, &json!(name))
    }

    fn evidence(
        name: &str,
        kind: ProfileCandidateEvidenceKind,
        path: &str,
        line: u32,
    ) -> WebStaticProfileEvidence {
        WebStaticProfileEvidence {
            estimated_coverage: ProfileCandidateCoverage {
                file_ids: vec![stable_id("file", name)],
                dependency_site_ids: vec![stable_id("site", name)],
            },
            evidence: vec![ProfileCandidateEvidence {
                kind,
                path: path.to_owned(),
                start_line: line,
                end_line: line,
            }],
        }
    }

    fn input() -> WebProfilePlanningInput {
        WebProfilePlanningInput {
            planning_version: WEB_PROFILE_PLANNING_VERSION.to_owned(),
            bundled_typescript_compatibility_id: stable_id(
                "web-typescript-compatibility",
                "typescript-7.0.2",
            ),
            package_snapshot_id: stable_id("web-package-snapshot", "pnpm-lock"),
            framework_capability_ids: vec![
                stable_id("web-framework-capability", "tanstack-start-v1"),
                stable_id("web-framework-capability", "next-16"),
                stable_id("web-framework-capability", "astro-5"),
            ],
            baseline: evidence(
                "baseline",
                ProfileCandidateEvidenceKind::HostContext,
                ".depgraph/web-toolchain.json",
                1,
            ),
            environments: Vec::new(),
            modes: Vec::new(),
            rejected: Vec::new(),
        }
    }

    fn environment(
        environment: WebEnvironment,
        framework: Option<WebFramework>,
        path: &str,
        line: u32,
    ) -> WebEnvironmentDeclaration {
        WebEnvironmentDeclaration {
            environment,
            source: WebDeclarationSource::FrameworkMetadata,
            framework,
            ordered_conditions: Vec::new(),
            availability: WebProfileAvailability::Available,
            static_evidence: evidence(path, ProfileCandidateEvidenceKind::Source, path, line),
        }
    }

    fn web_axes(profile: &ProfileSelectionProfile) -> &WebProfileAxes {
        let CanonicalProfileAxes::Web(axes) = &profile.axes else {
            panic!("Web generator returned a non-Web profile");
        };
        axes
    }

    #[test]
    fn mandatory_baseline_is_production_browser_server_and_bundled_toolchain_bound() -> Result<()> {
        let generated = generate_web_profile_candidates(input())?;
        let baseline = generated
            .bounded
            .profiles
            .iter()
            .find(|profile| profile.id == generated.baseline_profile_id)
            .context("Web baseline")?;
        let axes = web_axes(baseline);
        assert_eq!(axes.mode, WebProfileMode::Production);
        assert_eq!(
            axes.environments,
            vec![WebEnvironment::Browser, WebEnvironment::Server]
        );
        assert!(
            axes.bundled_typescript_compatibility_id
                .starts_with("web-typescript-compatibility:sha256:")
        );
        assert_eq!(axes.framework_capability_ids.len(), 3);
        Ok(())
    }

    #[test]
    fn next_astro_and_tanstack_evidence_merge_without_framework_profiles() -> Result<()> {
        let mut fixture = input();
        fixture.environments = vec![
            environment(
                WebEnvironment::Edge,
                Some(WebFramework::Next),
                "apps/next/app/page.tsx",
                2,
            ),
            environment(
                WebEnvironment::Worker,
                Some(WebFramework::Astro),
                "apps/astro/src/middleware.ts",
                4,
            ),
            environment(
                WebEnvironment::Worker,
                Some(WebFramework::Tanstack),
                "apps/start/src/server.ts",
                6,
            ),
        ];
        let generated = generate_web_profile_candidates(fixture)?;
        assert_eq!(generated.bounded.candidates.len(), 3);
        assert_eq!(generated.bounded.profiles.len(), 3);
        let baseline = generated
            .bounded
            .profiles
            .iter()
            .find(|profile| profile.id == generated.baseline_profile_id)
            .context("Web baseline")?;
        for profile in &generated.bounded.profiles {
            let axes = web_axes(profile);
            assert_eq!(axes.mode, WebProfileMode::Production);
            assert_eq!(
                axes.framework_capability_ids,
                web_axes(baseline).framework_capability_ids
            );
        }
        let worker = generated
            .bounded
            .candidates
            .iter()
            .find(|candidate| {
                candidate.changed_axis == Some(ProfileAxis::Environment)
                    && candidate.axis_values.contains(&"worker".to_owned())
            })
            .context("worker candidate")?;
        assert_eq!(worker.evidence.len(), 2);
        assert!(worker.evidence[0].path.contains("astro"));
        assert!(worker.evidence[1].path.contains("start"));
        Ok(())
    }

    #[test]
    fn ordered_exports_and_dev_test_candidates_are_single_axis() -> Result<()> {
        let mut fixture = input();
        fixture.environments.push(WebEnvironmentDeclaration {
            environment: WebEnvironment::Edge,
            source: WebDeclarationSource::PackageExports,
            framework: None,
            ordered_conditions: vec![
                "types".to_owned(),
                "edge-light".to_owned(),
                "default".to_owned(),
            ],
            availability: WebProfileAvailability::Available,
            static_evidence: evidence(
                "exports",
                ProfileCandidateEvidenceKind::Manifest,
                "packages/runtime/package.json",
                12,
            ),
        });
        fixture.modes = vec![
            WebModeDeclaration {
                mode: WebProfileMode::Development,
                source: WebDeclarationSource::ManifestScript,
                framework: None,
                availability: WebProfileAvailability::Available,
                static_evidence: evidence(
                    "dev",
                    ProfileCandidateEvidenceKind::Manifest,
                    "package.json",
                    8,
                ),
            },
            WebModeDeclaration {
                mode: WebProfileMode::Test,
                source: WebDeclarationSource::SourceRole,
                framework: None,
                availability: WebProfileAvailability::Available,
                static_evidence: evidence(
                    "test",
                    ProfileCandidateEvidenceKind::Source,
                    "test/app.test.ts",
                    1,
                ),
            },
        ];
        let generated = generate_web_profile_candidates(fixture)?;
        assert_eq!(generated.bounded.candidates.len(), 4);
        let baseline = generated
            .bounded
            .profiles
            .iter()
            .find(|profile| profile.id == generated.baseline_profile_id)
            .context("Web baseline")?;
        for profile in &generated.bounded.profiles {
            let axes = web_axes(profile);
            let changed = usize::from(axes.mode != web_axes(baseline).mode)
                + usize::from(axes.environments != web_axes(baseline).environments);
            assert!(changed <= 1);
        }
        Ok(())
    }

    #[test]
    fn build_runtime_dynamic_and_project_code_boundaries_are_ledgered() -> Result<()> {
        let mut fixture = input();
        fixture.rejected = vec![
            (WebAutomaticBoundaryKind::BuildProfile, "build"),
            (WebAutomaticBoundaryKind::RuntimeProfile, "runtime"),
            (WebAutomaticBoundaryKind::DynamicConfiguration, "dynamic"),
            (WebAutomaticBoundaryKind::ProjectCode, "project-code"),
        ]
        .into_iter()
        .map(|(kind, name)| WebRejectedProfileDeclaration {
            kind,
            axis: None,
            axis_values: vec![name.to_owned()],
            evidence: evidence(
                name,
                ProfileCandidateEvidenceKind::Config,
                "next.config.mjs",
                1,
            )
            .evidence,
        })
        .collect();
        let generated = generate_web_profile_candidates(fixture)?;
        assert_eq!(generated.bounded.candidates.len(), 1);
        assert_eq!(generated.policy_excluded.len(), 4);
        assert!(generated.policy_excluded.iter().any(|entry| {
            entry.reason == ProfileExclusionReason::DefaultProfileBuildRequiresConsent
        }));
        assert!(generated.policy_excluded.iter().any(|entry| {
            entry.reason == ProfileExclusionReason::DefaultProfileRuntimeRequiresTrace
        }));
        assert!(generated.policy_excluded.iter().any(|entry| {
            entry.reason == ProfileExclusionReason::DefaultProfileDynamicConfigurationNotExecuted
        }));
        Ok(())
    }

    #[test]
    fn polyglot_checkout_and_declaration_order_are_deterministic() -> Result<()> {
        let mut first = input();
        first.environments = vec![
            environment(
                WebEnvironment::Worker,
                Some(WebFramework::Tanstack),
                "web/start/src/server.ts",
                3,
            ),
            environment(
                WebEnvironment::Edge,
                Some(WebFramework::Next),
                "web/next/app/page.tsx",
                2,
            ),
            environment(
                WebEnvironment::Worker,
                Some(WebFramework::Astro),
                "web/astro/src/middleware.ts",
                4,
            ),
        ];
        first.baseline.evidence.push(ProfileCandidateEvidence {
            kind: ProfileCandidateEvidenceKind::Manifest,
            path: "web/package.json".to_owned(),
            start_line: 1,
            end_line: 10,
        });
        let mut reordered = first.clone();
        reordered.environments.reverse();
        reordered.framework_capability_ids.reverse();
        reordered.baseline.evidence.reverse();
        assert_eq!(
            generate_web_profile_candidates(first)?,
            generate_web_profile_candidates(reordered)?
        );
        Ok(())
    }

    #[test]
    fn dynamic_or_unproven_environment_metadata_fails_closed() {
        let mut package_exports = input();
        package_exports
            .environments
            .push(WebEnvironmentDeclaration {
                environment: WebEnvironment::Edge,
                source: WebDeclarationSource::PackageExports,
                framework: None,
                ordered_conditions: vec!["browser".to_owned(), "default".to_owned()],
                availability: WebProfileAvailability::Available,
                static_evidence: evidence(
                    "exports",
                    ProfileCandidateEvidenceKind::Manifest,
                    "package.json",
                    1,
                ),
            });
        assert!(
            generate_web_profile_candidates(package_exports)
                .unwrap_err()
                .to_string()
                .contains("do not prove")
        );

        let mut dynamic = input();
        dynamic.environments.push(WebEnvironmentDeclaration {
            environment: WebEnvironment::Worker,
            source: WebDeclarationSource::FrameworkMetadata,
            framework: None,
            ordered_conditions: Vec::new(),
            availability: WebProfileAvailability::Available,
            static_evidence: evidence(
                "dynamic",
                ProfileCandidateEvidenceKind::Config,
                "astro.config.mjs",
                1,
            ),
        });
        assert!(
            generate_web_profile_candidates(dynamic)
                .unwrap_err()
                .to_string()
                .contains("recognized framework")
        );
    }
}
