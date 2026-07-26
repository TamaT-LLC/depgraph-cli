use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, bail};
use depgraph_protocol::{canonical_json, stable_id_from_value};
use serde::{Deserialize, Serialize};
use serde_json::json;

pub const DEFAULT_PROFILE_SELECTION_CONTRACT_VERSION: &str = "default-profile-selection-v1";
pub const DEFAULT_PROFILE_SELECTION_LIMIT_VERSION: &str = "default-profile-selection-limits-v1";
pub const DEFAULT_PROFILE_SELECTION_SCHEMA_PATH: &str =
    "schemas/depgraph-default-profile-selection-v1.schema.json";
pub const DEFAULT_PROFILE_SELECTION_SCHEMA: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../schemas/depgraph-default-profile-selection-v1.schema.json"
));
pub const MAX_SELECTED_ROOT_PROFILES: u32 = 32;
pub const MAX_AUTOMATIC_PROFILE_CANDIDATES_PER_LANGUAGE: u32 = 256;
pub const MAX_AUTOMATIC_PROFILE_CANDIDATES: u32 = 512;

const MAX_IDENTITY_CHARS: usize = 512;
const MAX_AXIS_VALUE_CHARS: usize = 256;
const MAX_EVIDENCE_PATH_CHARS: usize = 4_096;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileLanguage {
    Rust,
    Go,
    Web,
}

impl ProfileLanguage {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Rust => "rust",
            Self::Go => "go",
            Self::Web => "web",
        }
    }

    const fn priority(self) -> u8 {
        match self {
            Self::Rust => 0,
            Self::Go => 1,
            Self::Web => 2,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileAxis {
    Target,
    Environment,
    Mode,
    FeatureOrTag,
}

impl ProfileAxis {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Target => "target",
            Self::Environment => "environment",
            Self::Mode => "mode",
            Self::FeatureOrTag => "feature_or_tag",
        }
    }

    const fn priority(self) -> u8 {
        match self {
            Self::Target => 0,
            Self::Environment => 1,
            Self::Mode => 2,
            Self::FeatureOrTag => 3,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileSelectionMode {
    Automatic,
    Explicit,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RepositorySizeClass {
    Tiny,
    Small,
    Medium,
    Large,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileSelectionRepository {
    pub size_class: RepositorySizeClass,
    pub relevant_source_files: u64,
    pub build_units: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileSelectionLimits {
    pub limit_version: String,
    pub effective_profile_cap: u32,
    pub hard_profile_cap: u32,
    pub per_language_candidate_cap: u32,
    pub total_candidate_cap: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileAxisCapability {
    pub language: ProfileLanguage,
    pub axis: ProfileAxis,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "language", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProfileHostContext {
    Rust(RustHostContext),
    Go(GoHostContext),
}

impl ProfileHostContext {
    const fn language(&self) -> ProfileLanguage {
        match self {
            Self::Rust(_) => ProfileLanguage::Rust,
            Self::Go(_) => ProfileLanguage::Go,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RustHostContext {
    pub target: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GoHostContext {
    pub goos: String,
    pub goarch: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileSelectionInput {
    pub contract_version: String,
    pub inventory_digest: String,
    pub compatibility_ids: Vec<String>,
    pub language_families: Vec<ProfileLanguage>,
    pub host_contexts: Vec<ProfileHostContext>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub configuration_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selection_file_digest: Option<String>,
    pub supported_axes: Vec<ProfileAxisCapability>,
    pub repository: ProfileSelectionRepository,
    pub limits: ProfileSelectionLimits,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RustProfileMode {
    Check,
    Test,
}

impl RustProfileMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Check => "check",
            Self::Test => "test",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum GoCallGraph {
    RtaCha,
    Vta,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WebEnvironment {
    Browser,
    Server,
    Edge,
    Worker,
}

impl WebEnvironment {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Browser => "browser",
            Self::Server => "server",
            Self::Edge => "edge",
            Self::Worker => "worker",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WebProfileMode {
    Production,
    Development,
    Test,
}

impl WebProfileMode {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Production => "production",
            Self::Development => "development",
            Self::Test => "test",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RustProfileAxes {
    pub target: String,
    pub mode: RustProfileMode,
    pub default_features: bool,
    pub features: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GoProfileAxes {
    pub goos: String,
    pub goarch: String,
    pub tags: Vec<String>,
    pub cgo_enabled: bool,
    pub call_graph: GoCallGraph,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WebProfileAxes {
    pub mode: WebProfileMode,
    pub environments: Vec<WebEnvironment>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "language", rename_all = "snake_case", deny_unknown_fields)]
pub enum CanonicalProfileAxes {
    Rust(RustProfileAxes),
    Go(GoProfileAxes),
    Web(WebProfileAxes),
}

impl CanonicalProfileAxes {
    pub const fn language(&self) -> ProfileLanguage {
        match self {
            Self::Rust(_) => ProfileLanguage::Rust,
            Self::Go(_) => ProfileLanguage::Go,
            Self::Web(_) => ProfileLanguage::Web,
        }
    }

    fn normalized(&self) -> Self {
        let mut normalized = self.clone();
        match &mut normalized {
            Self::Rust(axes) => {
                axes.features
                    .sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
                axes.features.dedup();
            }
            Self::Go(axes) => {
                axes.tags
                    .sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
                axes.tags.dedup();
            }
            Self::Web(axes) => {
                axes.environments
                    .sort_by(|left, right| left.as_str().as_bytes().cmp(right.as_str().as_bytes()));
                axes.environments.dedup();
            }
        }
        normalized
    }

    fn axis_values(&self, axis: ProfileAxis) -> Result<Vec<String>> {
        let values = match (self, axis) {
            (Self::Rust(axes), ProfileAxis::Target) => vec![axes.target.clone()],
            (Self::Rust(axes), ProfileAxis::Mode) => vec![axes.mode.as_str().to_owned()],
            (Self::Rust(axes), ProfileAxis::FeatureOrTag) => {
                let mut values = vec![format!("default_features={}", axes.default_features)];
                values.extend(
                    axes.features
                        .iter()
                        .map(|feature| format!("feature={feature}")),
                );
                values
            }
            (Self::Go(axes), ProfileAxis::Target) => {
                vec![format!("{}/{}", axes.goos, axes.goarch)]
            }
            (Self::Go(axes), ProfileAxis::FeatureOrTag) => {
                axes.tags.iter().map(|tag| format!("tag={tag}")).collect()
            }
            (Self::Web(axes), ProfileAxis::Environment) => axes
                .environments
                .iter()
                .map(|environment| environment.as_str().to_owned())
                .collect(),
            (Self::Web(axes), ProfileAxis::Mode) => vec![axes.mode.as_str().to_owned()],
            _ => bail!(
                "axis {} is not supported for {} profiles",
                axis.as_str(),
                self.language().as_str()
            ),
        };
        Ok(values)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileSelectionProfile {
    pub id: String,
    pub axes: CanonicalProfileAxes,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileCandidateKind {
    Baseline,
    Alternative,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileCandidateEvidenceKind {
    Config,
    Manifest,
    Source,
    HostContext,
}

impl ProfileCandidateEvidenceKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Config => "config",
            Self::Manifest => "manifest",
            Self::Source => "source",
            Self::HostContext => "host_context",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileCandidateEvidence {
    pub kind: ProfileCandidateEvidenceKind,
    pub path: String,
    pub start_line: u32,
    pub end_line: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileCandidateCoverage {
    pub file_ids: Vec<String>,
    pub dependency_site_ids: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileCandidateRecord {
    pub id: String,
    pub profile_id: String,
    pub baseline_profile_id: String,
    pub kind: ProfileCandidateKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub changed_axis: Option<ProfileAxis>,
    pub axis_values: Vec<String>,
    pub estimated_coverage: ProfileCandidateCoverage,
    pub evidence: Vec<ProfileCandidateEvidence>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileRankEvidence {
    pub declaration_tier: u8,
    pub new_dependency_occurrences: u64,
    pub new_files: u64,
    pub dimension_priority: u8,
    pub language_priority: u8,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileSelectedReason {
    MandatoryLanguageBaseline,
    TrackedProfileConfiguration,
    AutomaticCoverageRanked,
    ExplicitProfileRequested,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileSelectedLedger {
    pub candidate_id: String,
    pub profile_id: String,
    pub selection_rank: u32,
    pub reason: ProfileSelectedReason,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rank: Option<ProfileRankEvidence>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileOmissionReason {
    DefaultProfileBudgetExhausted,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileOmittedLedger {
    pub candidate_id: String,
    pub profile_id: String,
    pub reason: ProfileOmissionReason,
    pub rank: ProfileRankEvidence,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileExclusionReason {
    DefaultProfileCombinationRequiresExplicitSelection,
    DefaultProfileDynamicConfigurationNotExecuted,
    DefaultProfileUnsupportedAxis,
    DefaultProfileBuildRequiresConsent,
    DefaultProfileRuntimeRequiresTrace,
    DefaultProfileMalformedDeclaration,
}

impl ProfileExclusionReason {
    const fn affects_completeness(self) -> bool {
        matches!(
            self,
            Self::DefaultProfileDynamicConfigurationNotExecuted
                | Self::DefaultProfileUnsupportedAxis
                | Self::DefaultProfileMalformedDeclaration
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProfilePolicyExclusion {
    pub id: String,
    pub language: ProfileLanguage,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub axis: Option<ProfileAxis>,
    pub axis_values: Vec<String>,
    pub reason: ProfileExclusionReason,
    pub affects_completeness: bool,
    pub evidence: Vec<ProfileCandidateEvidence>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateDiscoveryReason {
    DefaultProfileCandidateLimitExceeded,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileDiscoveryLedger {
    pub language: ProfileLanguage,
    pub discovered_candidate_count: u32,
    pub overflow_candidate_count: u32,
    pub complete: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<CandidateDiscoveryReason>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileSelectionSummary {
    pub eligible_profile_count: u32,
    pub selected_profile_count: u32,
    pub omitted_profile_count: u32,
    pub policy_excluded_count: u32,
    pub candidate_discovery_complete: bool,
    pub selection_complete: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DefaultProfileSelectionPlan {
    pub contract_version: String,
    pub selection_mode: ProfileSelectionMode,
    pub input: ProfileSelectionInput,
    pub input_digest: String,
    pub profiles: Vec<ProfileSelectionProfile>,
    pub candidates: Vec<ProfileCandidateRecord>,
    pub selected: Vec<ProfileSelectedLedger>,
    pub omitted: Vec<ProfileOmittedLedger>,
    pub policy_excluded: Vec<ProfilePolicyExclusion>,
    pub discovery: Vec<ProfileDiscoveryLedger>,
    pub summary: ProfileSelectionSummary,
    pub plan_id: String,
}

#[must_use]
pub fn canonical_profile_id(axes: &CanonicalProfileAxes) -> String {
    stable_id_from_value(
        "profile",
        &json!({
            "contract_version": DEFAULT_PROFILE_SELECTION_CONTRACT_VERSION,
            "axes": axes.normalized(),
        }),
    )
}

#[must_use]
pub fn profile_candidate_id(candidate: &ProfileCandidateRecord) -> String {
    stable_id_from_value(
        "profile-candidate",
        &json!({
            "contract_version": DEFAULT_PROFILE_SELECTION_CONTRACT_VERSION,
            "profile_id": candidate.profile_id,
            "baseline_profile_id": candidate.baseline_profile_id,
            "kind": candidate.kind,
            "changed_axis": candidate.changed_axis,
            "axis_values": candidate.axis_values,
        }),
    )
}

#[must_use]
pub fn profile_exclusion_id(exclusion: &ProfilePolicyExclusion) -> String {
    stable_id_from_value(
        "profile-exclusion",
        &json!({
            "contract_version": DEFAULT_PROFILE_SELECTION_CONTRACT_VERSION,
            "language": exclusion.language,
            "axis": exclusion.axis,
            "axis_values": exclusion.axis_values,
            "reason": exclusion.reason,
            "evidence": exclusion.evidence,
        }),
    )
}

#[must_use]
pub fn profile_selection_input_digest(input: &ProfileSelectionInput) -> String {
    stable_id_from_value(
        "profile-selection-input",
        &serde_json::to_value(input).expect("profile selection input serialization cannot fail"),
    )
}

#[must_use]
pub fn canonical_profile_selection_plan_id(plan: &DefaultProfileSelectionPlan) -> String {
    let mut value =
        serde_json::to_value(plan).expect("profile selection plan serialization cannot fail");
    value
        .as_object_mut()
        .expect("profile selection plan serializes as an object")
        .remove("plan_id");
    stable_id_from_value("profile-selection-plan", &value)
}

#[must_use]
pub fn canonical_profile_selection_json(plan: &DefaultProfileSelectionPlan) -> String {
    canonical_json(
        &serde_json::to_value(plan).expect("profile selection plan serialization cannot fail"),
    )
}

pub fn validate_profile_selection_plan(plan: &DefaultProfileSelectionPlan) -> Result<()> {
    plan.validate()
}

impl DefaultProfileSelectionPlan {
    pub fn validate(&self) -> Result<()> {
        if self.contract_version != DEFAULT_PROFILE_SELECTION_CONTRACT_VERSION
            || self.input.contract_version != DEFAULT_PROFILE_SELECTION_CONTRACT_VERSION
        {
            bail!(
                "unsupported profile selection contract_version; expected {DEFAULT_PROFILE_SELECTION_CONTRACT_VERSION}"
            );
        }
        validate_input(&self.input)?;
        if self.input_digest != profile_selection_input_digest(&self.input) {
            bail!("profile selection input_digest does not match the canonical input");
        }
        match self.selection_mode {
            ProfileSelectionMode::Automatic if self.input.selection_file_digest.is_some() => {
                bail!("automatic profile selection cannot carry a selection_file_digest");
            }
            ProfileSelectionMode::Explicit if self.input.selection_file_digest.is_none() => {
                bail!("explicit profile selection requires a selection_file_digest");
            }
            _ => {}
        }

        validate_sorted_by("profiles", &self.profiles, |profile| profile.id.clone())?;
        validate_sorted_by("candidates", &self.candidates, |candidate| {
            candidate.profile_id.clone()
        })?;
        validate_sorted_by("selected", &self.selected, |entry| entry.profile_id.clone())?;
        validate_sorted_by("omitted", &self.omitted, |entry| entry.profile_id.clone())?;
        validate_sorted_by("policy_excluded", &self.policy_excluded, |entry| {
            entry.id.clone()
        })?;
        validate_sorted_by("discovery", &self.discovery, |entry| {
            entry.language.as_str().to_owned()
        })?;

        let mut profiles = BTreeMap::new();
        for profile in &self.profiles {
            validate_profile(profile)?;
            if profiles.insert(profile.id.as_str(), profile).is_some() {
                bail!("profiles must not contain duplicate IDs");
            }
        }

        let mut candidates = BTreeMap::new();
        for candidate in &self.candidates {
            validate_candidate(candidate)?;
            if !profiles.contains_key(candidate.profile_id.as_str()) {
                bail!("candidate profile_id must reference profiles");
            }
            if candidates
                .insert(candidate.id.as_str(), candidate)
                .is_some()
            {
                bail!("candidates must not contain duplicate IDs");
            }
        }
        if profiles.len() != candidates.len()
            || profiles.keys().any(|profile_id| {
                !self
                    .candidates
                    .iter()
                    .any(|item| item.profile_id.as_str() == *profile_id)
            })
        {
            bail!("profiles and candidates must have a one-to-one identity mapping");
        }

        for candidate in &self.candidates {
            validate_candidate_relationship(
                self.selection_mode,
                candidate,
                &candidates,
                &profiles,
            )?;
        }

        let mut ledger_candidates = BTreeSet::new();
        let mut selection_ranks = BTreeSet::new();
        for selected in &self.selected {
            let candidate = candidate_for_ledger(
                "selected",
                &selected.candidate_id,
                &selected.profile_id,
                &candidates,
            )?;
            if !ledger_candidates.insert(selected.candidate_id.as_str()) {
                bail!("selected and omitted ledgers must reference every candidate exactly once");
            }
            if !selection_ranks.insert(selected.selection_rank) {
                bail!("selected selection_rank values must be unique");
            }
            let language = profiles[candidate.profile_id.as_str()].axes.language();
            validate_selected_entry(self.selection_mode, selected, candidate, language)?;
        }
        let expected_ranks = 0..u32::try_from(self.selected.len())?;
        if selection_ranks.into_iter().ne(expected_ranks) {
            bail!("selected selection_rank values must be contiguous from zero");
        }

        for omitted in &self.omitted {
            let candidate = candidate_for_ledger(
                "omitted",
                &omitted.candidate_id,
                &omitted.profile_id,
                &candidates,
            )?;
            if !ledger_candidates.insert(omitted.candidate_id.as_str()) {
                bail!("selected and omitted ledgers must reference every candidate exactly once");
            }
            if self.selection_mode == ProfileSelectionMode::Explicit {
                bail!("explicit profile selection cannot omit a requested profile");
            }
            let language = profiles[candidate.profile_id.as_str()].axes.language();
            validate_rank(&omitted.rank, candidate, language)?;
        }
        if ledger_candidates.len() != candidates.len() {
            bail!("selected and omitted ledgers must cover every eligible candidate");
        }

        validate_baselines(self, &candidates, &profiles)?;
        validate_exclusions(&self.policy_excluded, &self.input.language_families)?;
        validate_discovery(self)?;
        validate_summary(self)?;

        if self.plan_id != canonical_profile_selection_plan_id(self) {
            bail!("profile selection plan_id does not match the canonical plan");
        }
        Ok(())
    }
}

fn validate_input(input: &ProfileSelectionInput) -> Result<()> {
    validate_digest("inventory_digest", &input.inventory_digest)?;
    if let Some(digest) = &input.configuration_digest {
        validate_digest("configuration_digest", digest)?;
    }
    if let Some(digest) = &input.selection_file_digest {
        validate_digest("selection_file_digest", digest)?;
    }
    validate_sorted_unique_strings("compatibility_ids", &input.compatibility_ids, false)?;
    for identity in &input.compatibility_ids {
        validate_bounded_text("compatibility identity", identity, MAX_IDENTITY_CHARS)?;
    }
    validate_sorted_by("language_families", &input.language_families, |language| {
        language.as_str().to_owned()
    })?;
    validate_unique(
        "language_families",
        input
            .language_families
            .iter()
            .map(|language| language.as_str()),
    )?;
    validate_sorted_by("host_contexts", &input.host_contexts, |context| {
        context.language().as_str().to_owned()
    })?;
    validate_unique(
        "host_contexts",
        input
            .host_contexts
            .iter()
            .map(|context| context.language().as_str()),
    )?;
    for context in &input.host_contexts {
        if !input.language_families.contains(&context.language()) {
            bail!("host_context language must be present in language_families");
        }
        match context {
            ProfileHostContext::Rust(context) => {
                validate_axis_value("Rust host target", &context.target)?;
            }
            ProfileHostContext::Go(context) => {
                validate_axis_value("Go host GOOS", &context.goos)?;
                validate_axis_value("Go host GOARCH", &context.goarch)?;
            }
        }
    }
    for language in &input.language_families {
        if matches!(language, ProfileLanguage::Rust | ProfileLanguage::Go)
            && !input
                .host_contexts
                .iter()
                .any(|context| context.language() == *language)
        {
            bail!("detected Rust and Go families require an attested host context");
        }
    }

    validate_sorted_by("supported_axes", &input.supported_axes, |capability| {
        (
            capability.language.as_str().to_owned(),
            capability.axis.as_str().to_owned(),
        )
    })?;
    validate_unique(
        "supported_axes",
        input
            .supported_axes
            .iter()
            .map(|capability| (capability.language, capability.axis)),
    )?;
    for capability in &input.supported_axes {
        if !input.language_families.contains(&capability.language)
            || !axis_is_supported(capability.language, capability.axis)
        {
            bail!("supported_axes contains an unavailable language or axis");
        }
    }

    if input.limits.limit_version != DEFAULT_PROFILE_SELECTION_LIMIT_VERSION
        || input.limits.hard_profile_cap != MAX_SELECTED_ROOT_PROFILES
        || input.limits.per_language_candidate_cap != MAX_AUTOMATIC_PROFILE_CANDIDATES_PER_LANGUAGE
        || input.limits.total_candidate_cap != MAX_AUTOMATIC_PROFILE_CANDIDATES
        || input.limits.effective_profile_cap == 0
        || input.limits.effective_profile_cap > input.limits.hard_profile_cap
    {
        bail!("profile selection limits do not match the closed v1 limits");
    }
    Ok(())
}

fn validate_profile(profile: &ProfileSelectionProfile) -> Result<()> {
    validate_stable_id("profile id", &profile.id, "profile")?;
    match &profile.axes {
        CanonicalProfileAxes::Rust(axes) => {
            validate_axis_value("Rust target", &axes.target)?;
            validate_sorted_unique_strings("Rust features", &axes.features, true)?;
            for feature in &axes.features {
                validate_axis_value("Rust feature", feature)?;
            }
        }
        CanonicalProfileAxes::Go(axes) => {
            validate_axis_value("Go GOOS", &axes.goos)?;
            validate_axis_value("Go GOARCH", &axes.goarch)?;
            validate_sorted_unique_strings("Go tags", &axes.tags, true)?;
            for tag in &axes.tags {
                validate_axis_value("Go tag", tag)?;
            }
        }
        CanonicalProfileAxes::Web(axes) => {
            if axes.environments.is_empty() {
                bail!("Web environments must not be empty");
            }
            validate_sorted_by("Web environments", &axes.environments, |environment| {
                environment.as_str().to_owned()
            })?;
            validate_unique(
                "Web environments",
                axes.environments
                    .iter()
                    .map(|environment| environment.as_str()),
            )?;
        }
    }
    if profile.id != canonical_profile_id(&profile.axes) {
        bail!("profile id does not match the canonical language axes");
    }
    Ok(())
}

fn validate_candidate(candidate: &ProfileCandidateRecord) -> Result<()> {
    validate_stable_id("candidate id", &candidate.id, "profile-candidate")?;
    validate_stable_id("candidate profile_id", &candidate.profile_id, "profile")?;
    validate_stable_id(
        "candidate baseline_profile_id",
        &candidate.baseline_profile_id,
        "profile",
    )?;
    validate_sorted_unique_strings("candidate axis_values", &candidate.axis_values, true)?;
    for value in &candidate.axis_values {
        validate_axis_value("candidate axis value", value)?;
    }
    validate_sorted_unique_stable_ids(
        "candidate coverage file_ids",
        &candidate.estimated_coverage.file_ids,
        "file",
    )?;
    validate_sorted_unique_stable_ids(
        "candidate coverage dependency_site_ids",
        &candidate.estimated_coverage.dependency_site_ids,
        "site",
    )?;
    if candidate.evidence.is_empty() {
        bail!("candidate evidence must not be empty");
    }
    validate_evidence(&candidate.evidence)?;
    if candidate.id != profile_candidate_id(candidate) {
        bail!("candidate id does not match its canonical identity");
    }
    Ok(())
}

fn validate_candidate_relationship<'a>(
    selection_mode: ProfileSelectionMode,
    candidate: &ProfileCandidateRecord,
    candidates: &BTreeMap<&'a str, &'a ProfileCandidateRecord>,
    profiles: &BTreeMap<&'a str, &'a ProfileSelectionProfile>,
) -> Result<()> {
    let profile = profiles[candidate.profile_id.as_str()];
    match candidate.kind {
        ProfileCandidateKind::Baseline => {
            if candidate.profile_id != candidate.baseline_profile_id
                || candidate.changed_axis.is_some()
                || !candidate.axis_values.is_empty()
            {
                bail!("baseline candidate must self-reference and have no changed axis");
            }
        }
        ProfileCandidateKind::Alternative => {
            let baseline = candidates
                .values()
                .find(|item| item.profile_id == candidate.baseline_profile_id)
                .copied()
                .ok_or_else(|| anyhow::anyhow!("alternative baseline_profile_id is unknown"))?;
            if baseline.kind != ProfileCandidateKind::Baseline {
                bail!("alternative baseline_profile_id must reference a baseline candidate");
            }
            let baseline_profile = profiles[baseline.profile_id.as_str()];
            if selection_mode == ProfileSelectionMode::Explicit {
                if baseline_profile.axes.language() != profile.axes.language() {
                    bail!("candidate and baseline profiles must use the same language");
                }
                if candidate.changed_axis.is_some() || !candidate.axis_values.is_empty() {
                    bail!("explicit alternative must not carry automatic changed-axis metadata");
                }
                return Ok(());
            }
            let changed_axis = candidate
                .changed_axis
                .ok_or_else(|| anyhow::anyhow!("alternative candidate requires changed_axis"))?;
            let changed = changed_axes(&baseline_profile.axes, &profile.axes)?;
            if changed != [changed_axis] {
                bail!("automatic alternative must differ from its baseline in exactly one axis");
            }
            if candidate.axis_values != profile.axes.axis_values(changed_axis)? {
                bail!("candidate axis_values do not match the changed profile axis");
            }
        }
    }
    Ok(())
}

fn changed_axes(
    baseline: &CanonicalProfileAxes,
    alternative: &CanonicalProfileAxes,
) -> Result<Vec<ProfileAxis>> {
    let mut changed = Vec::new();
    match (baseline, alternative) {
        (CanonicalProfileAxes::Rust(left), CanonicalProfileAxes::Rust(right)) => {
            if left.target != right.target {
                changed.push(ProfileAxis::Target);
            }
            if left.mode != right.mode {
                changed.push(ProfileAxis::Mode);
            }
            if left.default_features != right.default_features || left.features != right.features {
                changed.push(ProfileAxis::FeatureOrTag);
            }
        }
        (CanonicalProfileAxes::Go(left), CanonicalProfileAxes::Go(right)) => {
            if left.goos != right.goos || left.goarch != right.goarch {
                changed.push(ProfileAxis::Target);
            }
            if left.tags != right.tags {
                changed.push(ProfileAxis::FeatureOrTag);
            }
            if left.cgo_enabled != right.cgo_enabled || left.call_graph != right.call_graph {
                bail!("cgo and call-graph changes are not automatic profile alternatives");
            }
        }
        (CanonicalProfileAxes::Web(left), CanonicalProfileAxes::Web(right)) => {
            if left.mode != right.mode {
                changed.push(ProfileAxis::Mode);
            }
            if left.environments != right.environments {
                changed.push(ProfileAxis::Environment);
            }
        }
        _ => bail!("candidate and baseline profiles must use the same language"),
    }
    Ok(changed)
}

fn candidate_for_ledger<'a>(
    name: &str,
    candidate_id: &str,
    profile_id: &str,
    candidates: &BTreeMap<&'a str, &'a ProfileCandidateRecord>,
) -> Result<&'a ProfileCandidateRecord> {
    let candidate = candidates
        .get(candidate_id)
        .copied()
        .ok_or_else(|| anyhow::anyhow!("{name} candidate_id is unknown"))?;
    if candidate.profile_id != profile_id {
        bail!("{name} profile_id does not match its candidate");
    }
    Ok(candidate)
}

fn validate_selected_entry(
    mode: ProfileSelectionMode,
    selected: &ProfileSelectedLedger,
    candidate: &ProfileCandidateRecord,
    language: ProfileLanguage,
) -> Result<()> {
    match (mode, candidate.kind, selected.reason, &selected.rank) {
        (
            ProfileSelectionMode::Automatic,
            ProfileCandidateKind::Baseline,
            ProfileSelectedReason::MandatoryLanguageBaseline,
            None,
        )
        | (
            ProfileSelectionMode::Explicit,
            _,
            ProfileSelectedReason::ExplicitProfileRequested,
            None,
        ) => Ok(()),
        (
            ProfileSelectionMode::Automatic,
            ProfileCandidateKind::Alternative,
            ProfileSelectedReason::TrackedProfileConfiguration
            | ProfileSelectedReason::AutomaticCoverageRanked,
            Some(rank),
        ) => validate_rank(rank, candidate, language),
        _ => bail!("selected reason and rank do not match selection mode or candidate kind"),
    }
}

fn validate_rank(
    rank: &ProfileRankEvidence,
    candidate: &ProfileCandidateRecord,
    language: ProfileLanguage,
) -> Result<()> {
    let changed_axis = candidate
        .changed_axis
        .ok_or_else(|| anyhow::anyhow!("only alternative candidates have rank evidence"))?;
    if rank.declaration_tier > 3
        || rank.dimension_priority != changed_axis.priority()
        || rank.language_priority != language.priority()
        || rank.new_files > u64::try_from(candidate.estimated_coverage.file_ids.len())?
        || rank.new_dependency_occurrences
            > u64::try_from(candidate.estimated_coverage.dependency_site_ids.len())?
    {
        bail!("candidate rank evidence is outside the closed coverage and priority bounds");
    }
    Ok(())
}

fn validate_baselines(
    plan: &DefaultProfileSelectionPlan,
    candidates: &BTreeMap<&str, &ProfileCandidateRecord>,
    profiles: &BTreeMap<&str, &ProfileSelectionProfile>,
) -> Result<()> {
    if plan.profiles.iter().any(|profile| {
        !plan
            .input
            .language_families
            .contains(&profile.axes.language())
    }) {
        bail!("profile language must be present in the canonical planning input");
    }
    if plan.selection_mode != ProfileSelectionMode::Automatic {
        return Ok(());
    }
    for language in &plan.input.language_families {
        let baselines = candidates
            .values()
            .filter(|candidate| {
                candidate.kind == ProfileCandidateKind::Baseline
                    && profiles[candidate.profile_id.as_str()].axes.language() == *language
            })
            .collect::<Vec<_>>();
        if baselines.len() != 1
            || !plan
                .selected
                .iter()
                .any(|entry| entry.candidate_id == baselines[0].id)
        {
            bail!("automatic selection requires one selected baseline per language family");
        }
    }
    let baseline_ranks = plan
        .selected
        .iter()
        .filter_map(|entry| {
            (candidates[entry.candidate_id.as_str()].kind == ProfileCandidateKind::Baseline)
                .then_some(entry.selection_rank)
        })
        .collect::<Vec<_>>();
    let optional_ranks = plan
        .selected
        .iter()
        .filter_map(|entry| {
            (candidates[entry.candidate_id.as_str()].kind == ProfileCandidateKind::Alternative)
                .then_some(entry.selection_rank)
        })
        .collect::<Vec<_>>();
    if baseline_ranks
        .iter()
        .any(|baseline| optional_ranks.iter().any(|optional| baseline >= optional))
    {
        bail!("mandatory baselines must be selected before alternatives");
    }
    Ok(())
}

fn validate_exclusions(
    exclusions: &[ProfilePolicyExclusion],
    languages: &[ProfileLanguage],
) -> Result<()> {
    let mut ids = BTreeSet::new();
    for exclusion in exclusions {
        validate_stable_id("profile exclusion id", &exclusion.id, "profile-exclusion")?;
        if !languages.contains(&exclusion.language) {
            bail!("profile exclusion language is not present in the input");
        }
        validate_sorted_unique_strings(
            "profile exclusion axis_values",
            &exclusion.axis_values,
            true,
        )?;
        validate_evidence(&exclusion.evidence)?;
        if exclusion.affects_completeness != exclusion.reason.affects_completeness() {
            bail!("profile exclusion completeness flag does not match its fixed reason");
        }
        if exclusion.id != profile_exclusion_id(exclusion) || !ids.insert(exclusion.id.as_str()) {
            bail!("profile exclusion identity is invalid or duplicated");
        }
    }
    Ok(())
}

fn validate_discovery(plan: &DefaultProfileSelectionPlan) -> Result<()> {
    if plan.selection_mode == ProfileSelectionMode::Explicit {
        if !plan.discovery.is_empty() {
            bail!("explicit profile selection cannot carry automatic discovery ledger entries");
        }
        return Ok(());
    }
    if plan.discovery.len() != plan.input.language_families.len()
        || plan.input.language_families.iter().any(|language| {
            !plan
                .discovery
                .iter()
                .any(|entry| entry.language == *language)
        })
    {
        bail!("automatic discovery must contain one entry per language family");
    }
    let mut discovered_total = 0_u32;
    for entry in &plan.discovery {
        let alternatives = plan
            .candidates
            .iter()
            .filter(|candidate| {
                candidate.kind == ProfileCandidateKind::Alternative
                    && plan
                        .profiles
                        .iter()
                        .find(|profile| profile.id == candidate.profile_id)
                        .is_some_and(|profile| profile.axes.language() == entry.language)
            })
            .count();
        if entry.discovered_candidate_count != u32::try_from(alternatives)?
            || entry.discovered_candidate_count > plan.input.limits.per_language_candidate_cap
            || entry.complete != (entry.overflow_candidate_count == 0)
            || entry.reason.is_some() != (entry.overflow_candidate_count > 0)
        {
            bail!("candidate discovery ledger counts, completeness, or reason are inconsistent");
        }
        discovered_total = discovered_total
            .checked_add(entry.discovered_candidate_count)
            .ok_or_else(|| anyhow::anyhow!("candidate discovery count overflow"))?;
    }
    if discovered_total > plan.input.limits.total_candidate_cap {
        bail!("candidate discovery exceeds the total candidate cap");
    }
    Ok(())
}

fn validate_summary(plan: &DefaultProfileSelectionPlan) -> Result<()> {
    let summary = &plan.summary;
    let eligible = u32::try_from(plan.candidates.len())?;
    let selected = u32::try_from(plan.selected.len())?;
    let omitted = u32::try_from(plan.omitted.len())?;
    let excluded = u32::try_from(plan.policy_excluded.len())?;
    let discovery_complete = plan.discovery.iter().all(|entry| entry.complete);
    let selection_complete = omitted == 0
        && discovery_complete
        && !plan
            .policy_excluded
            .iter()
            .any(|entry| entry.affects_completeness);
    if summary.eligible_profile_count != eligible
        || summary.selected_profile_count != selected
        || summary.omitted_profile_count != omitted
        || summary.policy_excluded_count != excluded
        || summary.candidate_discovery_complete != discovery_complete
        || summary.selection_complete != selection_complete
        || selected.saturating_add(omitted) != eligible
        || selected > plan.input.limits.effective_profile_cap
        || selected > MAX_SELECTED_ROOT_PROFILES
    {
        bail!("profile selection summary violates ledger coverage conservation");
    }
    Ok(())
}

fn validate_evidence(evidence: &[ProfileCandidateEvidence]) -> Result<()> {
    validate_sorted_by("candidate evidence", evidence, |entry| {
        (
            entry.path.clone(),
            entry.start_line,
            entry.end_line,
            entry.kind.as_str().to_owned(),
        )
    })?;
    validate_unique(
        "candidate evidence",
        evidence.iter().map(|entry| {
            (
                entry.path.as_str(),
                entry.start_line,
                entry.end_line,
                entry.kind,
            )
        }),
    )?;
    for entry in evidence {
        validate_repository_path(&entry.path)?;
        if entry.start_line == 0 || entry.end_line < entry.start_line {
            bail!("candidate evidence line range is invalid");
        }
    }
    Ok(())
}

fn axis_is_supported(language: ProfileLanguage, axis: ProfileAxis) -> bool {
    matches!(
        (language, axis),
        (
            ProfileLanguage::Rust,
            ProfileAxis::Target | ProfileAxis::Mode | ProfileAxis::FeatureOrTag
        ) | (
            ProfileLanguage::Go,
            ProfileAxis::Target | ProfileAxis::FeatureOrTag
        ) | (
            ProfileLanguage::Web,
            ProfileAxis::Environment | ProfileAxis::Mode
        )
    )
}

fn validate_axis_value(name: &str, value: &str) -> Result<()> {
    validate_bounded_text(name, value, MAX_AXIS_VALUE_CHARS)?;
    if value.chars().any(char::is_whitespace) {
        bail!("{name} must not contain whitespace");
    }
    Ok(())
}

fn validate_bounded_text(name: &str, value: &str, maximum: usize) -> Result<()> {
    if value.is_empty()
        || value.chars().count() > maximum
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        bail!("{name} must be non-empty, bounded, trimmed, and free of control characters");
    }
    Ok(())
}

fn validate_repository_path(path: &str) -> Result<()> {
    validate_bounded_text("candidate evidence path", path, MAX_EVIDENCE_PATH_CHARS)?;
    if path.starts_with('/')
        || path.starts_with('\\')
        || path.contains('\\')
        || path.contains(':')
        || path
            .split('/')
            .any(|component| component.is_empty() || matches!(component, "." | ".."))
    {
        bail!("candidate evidence path must be a confined repository-relative path");
    }
    Ok(())
}

fn validate_digest(name: &str, value: &str) -> Result<()> {
    if !value.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    }) {
        bail!("{name} must be sha256:<64 lowercase hex>");
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

fn validate_sorted_unique_stable_ids(name: &str, values: &[String], namespace: &str) -> Result<()> {
    validate_sorted_unique_strings(name, values, true)?;
    for value in values {
        validate_stable_id(name, value, namespace)?;
    }
    Ok(())
}

fn validate_sorted_unique_strings(name: &str, values: &[String], allow_empty: bool) -> Result<()> {
    if !allow_empty && values.is_empty() {
        bail!("{name} must not be empty");
    }
    validate_sorted_by(name, values, Clone::clone)?;
    validate_unique(name, values.iter().map(String::as_str))
}

fn validate_sorted_by<T, K, F>(name: &str, values: &[T], key: F) -> Result<()>
where
    F: Fn(&T) -> K,
    K: Ord,
{
    if values.windows(2).any(|pair| key(&pair[0]) >= key(&pair[1])) {
        bail!("{name} must be strictly sorted in canonical UTF-8 order");
    }
    Ok(())
}

fn validate_unique<T, I>(name: &str, values: I) -> Result<()>
where
    T: Ord,
    I: IntoIterator<Item = T>,
{
    let mut seen = BTreeSet::new();
    if values.into_iter().any(|value| !seen.insert(value)) {
        bail!("{name} must not contain duplicates");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use anyhow::{Context, Result, anyhow};
    use serde_json::{Value, json};

    use super::*;

    const GOLDEN: &str = include_str!("../tests/fixtures/default-profile-selection-v1.golden.json");
    const INVALID_CORPUS: &str =
        include_str!("../tests/fixtures/default-profile-selection-v1.invalid.json");

    #[test]
    fn golden_plan_is_accepted_by_rust_and_json_schema() -> Result<()> {
        let value: Value = serde_json::from_str(GOLDEN)?;
        let plan: DefaultProfileSelectionPlan = serde_json::from_value(value.clone())?;
        plan.validate()?;
        let schema: Value = serde_json::from_str(DEFAULT_PROFILE_SELECTION_SCHEMA)?;
        jsonschema::validator_for(&schema)?
            .validate(&value)
            .map_err(|error| anyhow!("{error}"))?;
        assert_eq!(
            canonical_profile_selection_json(&plan),
            canonical_json(&value)
        );
        Ok(())
    }

    #[test]
    fn canonical_profile_identity_normalizes_set_order_but_validation_rejects_it() -> Result<()> {
        let mut first = CanonicalProfileAxes::Rust(RustProfileAxes {
            target: "aarch64-apple-darwin".to_owned(),
            mode: RustProfileMode::Check,
            default_features: true,
            features: vec!["serde".to_owned(), "cli".to_owned()],
        });
        let second = CanonicalProfileAxes::Rust(RustProfileAxes {
            target: "aarch64-apple-darwin".to_owned(),
            mode: RustProfileMode::Check,
            default_features: true,
            features: vec!["cli".to_owned(), "serde".to_owned()],
        });
        assert_eq!(canonical_profile_id(&first), canonical_profile_id(&second));
        let id = canonical_profile_id(&first);
        let profile = ProfileSelectionProfile {
            id,
            axes: first.clone(),
        };
        assert!(validate_profile(&profile).is_err());
        if let CanonicalProfileAxes::Rust(axes) = &mut first {
            axes.features.sort();
        }
        validate_profile(&ProfileSelectionProfile {
            id: canonical_profile_id(&first),
            axes: first,
        })
    }

    #[test]
    fn invalid_corpus_never_passes_both_closed_contract_validators() -> Result<()> {
        let golden: Value = serde_json::from_str(GOLDEN)?;
        let schema: Value = serde_json::from_str(DEFAULT_PROFILE_SELECTION_SCHEMA)?;
        let schema = jsonschema::validator_for(&schema)?;
        let corpus: Vec<Value> = serde_json::from_str(INVALID_CORPUS)?;
        for case in corpus {
            let name = case["name"].as_str().context("invalid case name")?;
            let mut value = golden.clone();
            apply_mutation(&mut value, &case)
                .with_context(|| format!("applying invalid mutation {name}"))?;
            let rust_valid = serde_json::from_value::<DefaultProfileSelectionPlan>(value.clone())
                .is_ok_and(|plan| plan.validate().is_ok());
            let schema_valid = schema.is_valid(&value);
            assert!(
                !(rust_valid && schema_valid),
                "invalid corpus case {name} passed both validators"
            );
        }
        Ok(())
    }

    fn apply_mutation(value: &mut Value, case: &Value) -> Result<()> {
        let operation = case["operation"].as_str().context("mutation operation")?;
        let pointer = case["pointer"].as_str().context("mutation pointer")?;
        match operation {
            "set" => {
                if pointer == "/unknown_contract_field" {
                    value
                        .as_object_mut()
                        .context("plan object")?
                        .insert("unknown_contract_field".to_owned(), case["value"].clone());
                } else {
                    *value
                        .pointer_mut(pointer)
                        .with_context(|| format!("missing pointer {pointer}"))? =
                        case["value"].clone();
                }
            }
            "duplicate" => {
                let array = value
                    .pointer_mut(pointer)
                    .and_then(Value::as_array_mut)
                    .with_context(|| format!("missing array {pointer}"))?;
                let first = array.first().context("duplicate source")?.clone();
                array.push(first);
            }
            "swap" => {
                let array = value
                    .pointer_mut(pointer)
                    .and_then(Value::as_array_mut)
                    .with_context(|| format!("missing array {pointer}"))?;
                if array.len() < 2 {
                    bail!("swap requires two values");
                }
                array.swap(0, 1);
            }
            other => bail!("unknown mutation operation {other}"),
        }
        Ok(())
    }

    #[test]
    fn alternative_validator_rejects_cartesian_and_unsafe_go_axis_changes() -> Result<()> {
        let rust_baseline = CanonicalProfileAxes::Rust(RustProfileAxes {
            target: "aarch64-apple-darwin".to_owned(),
            mode: RustProfileMode::Check,
            default_features: true,
            features: Vec::new(),
        });
        let rust_cartesian = CanonicalProfileAxes::Rust(RustProfileAxes {
            target: "aarch64-apple-darwin".to_owned(),
            mode: RustProfileMode::Test,
            default_features: true,
            features: vec!["serde".to_owned()],
        });
        assert_eq!(
            changed_axes(&rust_baseline, &rust_cartesian)?,
            [ProfileAxis::Mode, ProfileAxis::FeatureOrTag]
        );

        let baseline = CanonicalProfileAxes::Go(GoProfileAxes {
            goos: "darwin".to_owned(),
            goarch: "arm64".to_owned(),
            tags: Vec::new(),
            cgo_enabled: false,
            call_graph: GoCallGraph::RtaCha,
        });
        let mut changed = baseline.clone();
        let CanonicalProfileAxes::Go(axes) = &mut changed else {
            unreachable!();
        };
        axes.cgo_enabled = true;
        assert!(
            changed_axes(&baseline, &changed)
                .unwrap_err()
                .to_string()
                .contains("cgo and call-graph")
        );
        Ok(())
    }

    #[test]
    fn explicit_alternative_accepts_multi_axis_profile_without_automatic_metadata() -> Result<()> {
        let baseline_profile = ProfileSelectionProfile {
            id: "profile:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_owned(),
            axes: CanonicalProfileAxes::Rust(RustProfileAxes {
                target: "aarch64-apple-darwin".to_owned(),
                mode: RustProfileMode::Check,
                default_features: true,
                features: Vec::new(),
            }),
        };
        let alternative_profile = ProfileSelectionProfile {
            id: "profile:sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                .to_owned(),
            axes: CanonicalProfileAxes::Rust(RustProfileAxes {
                target: "x86_64-unknown-linux-gnu".to_owned(),
                mode: RustProfileMode::Test,
                default_features: false,
                features: vec!["serde".to_owned()],
            }),
        };
        let baseline = ProfileCandidateRecord {
            id: "profile-candidate:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_owned(),
            profile_id: baseline_profile.id.clone(),
            baseline_profile_id: baseline_profile.id.clone(),
            kind: ProfileCandidateKind::Baseline,
            changed_axis: None,
            axis_values: Vec::new(),
            estimated_coverage: ProfileCandidateCoverage {
                file_ids: Vec::new(),
                dependency_site_ids: Vec::new(),
            },
            evidence: vec![ProfileCandidateEvidence {
                kind: ProfileCandidateEvidenceKind::Manifest,
                path: "Cargo.toml".to_owned(),
                start_line: 1,
                end_line: 1,
            }],
        };
        let alternative = ProfileCandidateRecord {
            id: "profile-candidate:sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                .to_owned(),
            profile_id: alternative_profile.id.clone(),
            baseline_profile_id: baseline_profile.id.clone(),
            kind: ProfileCandidateKind::Alternative,
            changed_axis: None,
            axis_values: Vec::new(),
            estimated_coverage: ProfileCandidateCoverage {
                file_ids: Vec::new(),
                dependency_site_ids: Vec::new(),
            },
            evidence: vec![ProfileCandidateEvidence {
                kind: ProfileCandidateEvidenceKind::Manifest,
                path: "Cargo.toml".to_owned(),
                start_line: 1,
                end_line: 1,
            }],
        };
        let candidates = BTreeMap::from([
            (baseline.id.as_str(), &baseline),
            (alternative.id.as_str(), &alternative),
        ]);
        let profiles = BTreeMap::from([
            (baseline_profile.id.as_str(), &baseline_profile),
            (alternative_profile.id.as_str(), &alternative_profile),
        ]);

        validate_candidate_relationship(
            ProfileSelectionMode::Explicit,
            &alternative,
            &candidates,
            &profiles,
        )?;
        assert!(
            validate_candidate_relationship(
                ProfileSelectionMode::Automatic,
                &alternative,
                &candidates,
                &profiles,
            )
            .unwrap_err()
            .to_string()
            .contains("requires changed_axis")
        );
        Ok(())
    }

    #[test]
    fn reason_vocabulary_and_contract_versions_are_fixed() {
        assert_eq!(
            serde_json::to_value(ProfileOmissionReason::DefaultProfileBudgetExhausted).unwrap(),
            json!("default_profile_budget_exhausted")
        );
        assert_eq!(
            serde_json::to_value(CandidateDiscoveryReason::DefaultProfileCandidateLimitExceeded)
                .unwrap(),
            json!("default_profile_candidate_limit_exceeded")
        );
        assert_eq!(
            DEFAULT_PROFILE_SELECTION_CONTRACT_VERSION,
            "default-profile-selection-v1"
        );
    }

    #[test]
    fn empty_repository_has_a_complete_zero_profile_plan() -> Result<()> {
        let value: Value = serde_json::from_str(GOLDEN)?;
        let mut plan: DefaultProfileSelectionPlan = serde_json::from_value(value)?;
        plan.input.language_families.clear();
        plan.input.host_contexts.clear();
        plan.input.supported_axes.clear();
        plan.input.repository.relevant_source_files = 0;
        plan.input.repository.build_units = 0;
        plan.profiles.clear();
        plan.candidates.clear();
        plan.selected.clear();
        plan.discovery.clear();
        plan.summary.eligible_profile_count = 0;
        plan.summary.selected_profile_count = 0;
        plan.input_digest = profile_selection_input_digest(&plan.input);
        plan.plan_id = canonical_profile_selection_plan_id(&plan);
        plan.validate()
    }
}
