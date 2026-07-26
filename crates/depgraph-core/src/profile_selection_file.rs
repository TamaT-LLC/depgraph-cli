use std::{collections::BTreeSet, path::Path};

use anyhow::{Context, Result, bail};
use depgraph_protocol::canonical_json;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{
    CanonicalProfileAxes, DEFAULT_PROFILE_SELECTION_CONTRACT_VERSION, DefaultProfileSelectionPlan,
    GoCallGraph, MAX_SELECTED_ROOT_PROFILES, ProfileCandidateCoverage, ProfileCandidateEvidence,
    ProfileCandidateEvidenceKind, ProfileCandidateKind, ProfileCandidateRecord, ProfileLanguage,
    ProfileSelectedLedger, ProfileSelectedReason, ProfileSelectionInput, ProfileSelectionMode,
    ProfileSelectionProfile, ProfileSelectionSummary, RustProfileMode, WebEnvironment,
    WebProfileMode, canonical_profile_id, canonical_profile_selection_plan_id,
    profile_candidate_id, profile_selection_input_digest, read_bounded_query_file,
    validate_profile_selection_plan,
};

pub const EXPLICIT_PROFILE_SELECTION_FILE_SCHEMA_PATH: &str =
    "schemas/depgraph-profiles-file-v1.schema.json";
pub const EXPLICIT_PROFILE_SELECTION_FILE_SCHEMA: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../schemas/depgraph-profiles-file-v1.schema.json"
));

const EXPLICIT_PROFILE_EVIDENCE_PATH: &str = ".depgraph/profiles-file.json";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExplicitProfileSelectionFile {
    pub contract_version: String,
    pub profiles: Vec<CanonicalProfileAxes>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedExplicitProfileSelection {
    pub profiles: Vec<ProfileSelectionProfile>,
    pub content_digest: String,
}

pub fn read_explicit_profile_selection_file(
    repository_root: &Path,
    path: &Path,
) -> Result<ValidatedExplicitProfileSelection> {
    let raw = read_bounded_query_file(repository_root, path)
        .map_err(|error| anyhow::anyhow!("unsafe explicit profiles file: {error}"))?;
    parse_explicit_profile_selection_file(&raw)
}

pub fn parse_explicit_profile_selection_file(
    raw: &str,
) -> Result<ValidatedExplicitProfileSelection> {
    let value: Value =
        serde_json::from_str(raw).context("explicit profiles file is not valid JSON")?;
    reject_secret_shape(&value)?;
    let file: ExplicitProfileSelectionFile = serde_json::from_value(value)
        .context("explicit profiles file does not match its strict contract")?;
    if file.contract_version != DEFAULT_PROFILE_SELECTION_CONTRACT_VERSION {
        bail!(
            "unsupported explicit profiles contract_version; expected {DEFAULT_PROFILE_SELECTION_CONTRACT_VERSION}"
        );
    }
    if file.profiles.is_empty()
        || file.profiles.len() > usize::try_from(MAX_SELECTED_ROOT_PROFILES)?
    {
        bail!("explicit profiles file must contain 1..={MAX_SELECTED_ROOT_PROFILES} profiles");
    }

    let mut profiles = Vec::with_capacity(file.profiles.len());
    for axes in file.profiles {
        validate_canonical_axes_order(&axes)?;
        profiles.push(ProfileSelectionProfile {
            id: canonical_profile_id(&axes),
            axes,
        });
    }
    profiles.sort_by(|left, right| left.id.as_bytes().cmp(right.id.as_bytes()));
    if profiles.windows(2).any(|pair| pair[0].id == pair[1].id) {
        bail!("explicit profiles file must not contain duplicate canonical profiles");
    }
    let canonical_file = ExplicitProfileSelectionFile {
        contract_version: DEFAULT_PROFILE_SELECTION_CONTRACT_VERSION.to_owned(),
        profiles: profiles
            .iter()
            .map(|profile| profile.axes.clone())
            .collect(),
    };
    let bytes = canonical_json(&serde_json::to_value(canonical_file)?);
    Ok(ValidatedExplicitProfileSelection {
        profiles,
        content_digest: format!("sha256:{}", hex::encode(Sha256::digest(bytes.as_bytes()))),
    })
}

pub fn plan_explicit_profile_selection(
    mut input: ProfileSelectionInput,
    explicit: ValidatedExplicitProfileSelection,
) -> Result<DefaultProfileSelectionPlan> {
    if explicit.profiles.is_empty()
        || explicit.profiles.len() > usize::try_from(MAX_SELECTED_ROOT_PROFILES)?
    {
        bail!("explicit profile selection is outside the hard profile cap");
    }
    if explicit
        .profiles
        .iter()
        .any(|profile| !input.language_families.contains(&profile.axes.language()))
    {
        bail!("explicit profile selection contains an undetected language family");
    }
    input.selection_file_digest = Some(explicit.content_digest);
    input.limits.effective_profile_cap = input.limits.hard_profile_cap;

    let mut candidates = explicit
        .profiles
        .iter()
        .map(explicit_candidate)
        .collect::<Vec<_>>();
    candidates.sort_by(|left, right| left.profile_id.as_bytes().cmp(right.profile_id.as_bytes()));
    let selected = candidates
        .iter()
        .enumerate()
        .map(|(rank, candidate)| {
            Ok(ProfileSelectedLedger {
                candidate_id: candidate.id.clone(),
                profile_id: candidate.profile_id.clone(),
                selection_rank: u32::try_from(rank)?,
                reason: ProfileSelectedReason::ExplicitProfileRequested,
                rank: None,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let selected_profile_count = u32::try_from(selected.len())?;
    let mut plan = DefaultProfileSelectionPlan {
        contract_version: DEFAULT_PROFILE_SELECTION_CONTRACT_VERSION.to_owned(),
        selection_mode: ProfileSelectionMode::Explicit,
        input_digest: profile_selection_input_digest(&input),
        input,
        profiles: explicit.profiles,
        candidates,
        selected,
        omitted: Vec::new(),
        policy_excluded: Vec::new(),
        discovery: Vec::new(),
        summary: ProfileSelectionSummary {
            eligible_profile_count: selected_profile_count,
            selected_profile_count,
            omitted_profile_count: 0,
            policy_excluded_count: 0,
            candidate_discovery_complete: true,
            selection_complete: true,
        },
        plan_id: String::new(),
    };
    plan.plan_id = canonical_profile_selection_plan_id(&plan);
    validate_profile_selection_plan(&plan)?;
    Ok(plan)
}

pub fn validate_explicit_profile_selection_capabilities(
    automatic: &DefaultProfileSelectionPlan,
    explicit: &ValidatedExplicitProfileSelection,
) -> Result<()> {
    validate_profile_selection_plan(automatic)?;
    if automatic.selection_mode != ProfileSelectionMode::Automatic {
        bail!("explicit profile capabilities require an automatic repository plan");
    }
    let mut capabilities = ExplicitProfileCapabilities::default();
    for profile in &automatic.profiles {
        capabilities.add_axes(&profile.axes);
    }
    for exclusion in &automatic.policy_excluded {
        if exclusion.evidence.iter().all(|evidence| {
            evidence.kind == ProfileCandidateEvidenceKind::Config
                && evidence.path == crate::config::CONFIG_FILE
        }) {
            capabilities.add_config_exclusion(exclusion);
        }
    }
    for profile in &explicit.profiles {
        capabilities.validate_axes(&profile.axes)?;
    }
    Ok(())
}

#[derive(Default)]
struct ExplicitProfileCapabilities {
    rust_targets: BTreeSet<String>,
    rust_modes: BTreeSet<&'static str>,
    rust_default_features: BTreeSet<bool>,
    rust_features: BTreeSet<String>,
    go_platforms: BTreeSet<(String, String)>,
    go_tags: BTreeSet<String>,
    go_call_graphs: BTreeSet<&'static str>,
    go_dependency_snapshots: BTreeSet<String>,
    web_modes: BTreeSet<&'static str>,
    web_environments: BTreeSet<WebEnvironment>,
    web_typescript_compatibility_ids: BTreeSet<String>,
    web_package_snapshots: BTreeSet<String>,
    web_framework_capabilities: BTreeSet<String>,
}

impl ExplicitProfileCapabilities {
    fn add_axes(&mut self, axes: &CanonicalProfileAxes) {
        match axes {
            CanonicalProfileAxes::Rust(axes) => {
                self.rust_targets.insert(axes.target.clone());
                self.rust_modes.insert(rust_mode_name(axes.mode));
                self.rust_default_features.insert(axes.default_features);
                self.rust_features.extend(axes.features.iter().cloned());
            }
            CanonicalProfileAxes::Go(axes) => {
                self.go_platforms
                    .insert((axes.goos.clone(), axes.goarch.clone()));
                self.go_tags.extend(axes.tags.iter().cloned());
                self.go_call_graphs
                    .insert(go_call_graph_name(axes.call_graph));
                self.go_dependency_snapshots
                    .insert(axes.dependency_snapshot_id.clone());
            }
            CanonicalProfileAxes::Web(axes) => {
                self.web_modes.insert(web_mode_name(axes.mode));
                self.web_environments
                    .extend(axes.environments.iter().copied());
                self.web_typescript_compatibility_ids
                    .insert(axes.bundled_typescript_compatibility_id.clone());
                self.web_package_snapshots
                    .insert(axes.package_snapshot_id.clone());
                self.web_framework_capabilities
                    .extend(axes.framework_capability_ids.iter().cloned());
            }
        }
    }

    fn add_config_exclusion(&mut self, exclusion: &crate::ProfilePolicyExclusion) {
        for value in &exclusion.axis_values {
            match (exclusion.language, exclusion.axis) {
                (ProfileLanguage::Rust, Some(crate::ProfileAxis::Target)) => {
                    self.rust_targets.insert(value.clone());
                }
                (ProfileLanguage::Rust, Some(crate::ProfileAxis::Mode)) => {
                    if value == "test" {
                        self.rust_modes.insert("test");
                    }
                }
                (ProfileLanguage::Rust, Some(crate::ProfileAxis::FeatureOrTag)) => {
                    if let Some(feature) = value.strip_prefix("feature=") {
                        self.rust_features.insert(feature.to_owned());
                    }
                }
                (ProfileLanguage::Go, Some(crate::ProfileAxis::FeatureOrTag)) => {
                    if let Some(tag) = value.strip_prefix("tag=") {
                        self.go_tags.insert(tag.to_owned());
                    }
                }
                (ProfileLanguage::Go, None) if value == "call_graph=vta" => {
                    self.go_call_graphs.insert("vta");
                }
                (ProfileLanguage::Web, Some(crate::ProfileAxis::Environment)) => {
                    if let Some(environment) = parse_web_environment(value) {
                        self.web_environments.insert(environment);
                    }
                }
                _ => {}
            }
        }
    }

    fn validate_axes(&self, axes: &CanonicalProfileAxes) -> Result<()> {
        match axes {
            CanonicalProfileAxes::Rust(axes) => {
                if !self.rust_targets.contains(&axes.target) {
                    bail!("explicit profiles file contains an unavailable Rust target");
                }
                if !self.rust_modes.contains(rust_mode_name(axes.mode)) {
                    bail!("explicit profiles file contains an unavailable Rust mode");
                }
                if !self.rust_default_features.contains(&axes.default_features)
                    || axes
                        .features
                        .iter()
                        .any(|feature| !self.rust_features.contains(feature))
                {
                    bail!("explicit profiles file contains an unavailable Rust feature set");
                }
            }
            CanonicalProfileAxes::Go(axes) => {
                if !self
                    .go_platforms
                    .contains(&(axes.goos.clone(), axes.goarch.clone()))
                {
                    bail!("explicit profiles file contains an unavailable Go target");
                }
                if axes.tags.iter().any(|tag| !self.go_tags.contains(tag))
                    || !self
                        .go_call_graphs
                        .contains(go_call_graph_name(axes.call_graph))
                    || !self
                        .go_dependency_snapshots
                        .contains(&axes.dependency_snapshot_id)
                {
                    bail!("explicit profiles file contains an unavailable Go capability");
                }
            }
            CanonicalProfileAxes::Web(axes) => {
                if !self.web_modes.contains(web_mode_name(axes.mode))
                    || axes
                        .environments
                        .iter()
                        .any(|environment| !self.web_environments.contains(environment))
                    || !self
                        .web_typescript_compatibility_ids
                        .contains(&axes.bundled_typescript_compatibility_id)
                    || !self
                        .web_package_snapshots
                        .contains(&axes.package_snapshot_id)
                    || axes
                        .framework_capability_ids
                        .iter()
                        .any(|capability| !self.web_framework_capabilities.contains(capability))
                {
                    bail!("explicit profiles file contains an unavailable Web capability");
                }
            }
        }
        Ok(())
    }
}

fn explicit_candidate(profile: &ProfileSelectionProfile) -> ProfileCandidateRecord {
    let mut candidate = ProfileCandidateRecord {
        id: String::new(),
        profile_id: profile.id.clone(),
        baseline_profile_id: profile.id.clone(),
        kind: ProfileCandidateKind::Baseline,
        changed_axis: None,
        axis_values: Vec::new(),
        estimated_coverage: ProfileCandidateCoverage {
            file_ids: Vec::new(),
            dependency_site_ids: Vec::new(),
        },
        evidence: vec![ProfileCandidateEvidence {
            kind: ProfileCandidateEvidenceKind::Config,
            path: EXPLICIT_PROFILE_EVIDENCE_PATH.to_owned(),
            start_line: 1,
            end_line: 1,
        }],
    };
    candidate.id = profile_candidate_id(&candidate);
    candidate
}

fn validate_canonical_axes_order(axes: &CanonicalProfileAxes) -> Result<()> {
    match axes {
        CanonicalProfileAxes::Rust(axes) => {
            validate_sorted_unique("Rust explicit features", &axes.features)?;
        }
        CanonicalProfileAxes::Go(axes) => {
            validate_sorted_unique("Go explicit tags", &axes.tags)?;
        }
        CanonicalProfileAxes::Web(axes) => {
            let names = axes
                .environments
                .iter()
                .map(|environment| environment_name(*environment).to_owned())
                .collect::<Vec<_>>();
            validate_sorted_unique("Web explicit environments", &names)?;
            validate_sorted_unique(
                "Web explicit framework capabilities",
                &axes.framework_capability_ids,
            )?;
        }
    }
    Ok(())
}

fn validate_sorted_unique(name: &str, values: &[String]) -> Result<()> {
    if values
        .windows(2)
        .any(|pair| pair[0].as_bytes() >= pair[1].as_bytes())
    {
        bail!("{name} must be strictly sorted in canonical UTF-8 order");
    }
    Ok(())
}

fn reject_secret_shape(value: &Value) -> Result<()> {
    match value {
        Value::Object(object) => {
            for (key, value) in object {
                if secret_field_name(key) {
                    bail!("explicit profiles file contains a forbidden secret-bearing field");
                }
                reject_secret_shape(value)?;
            }
        }
        Value::Array(values) => {
            for value in values {
                reject_secret_shape(value)?;
            }
        }
        Value::String(value) if secret_like_value(value) => {
            bail!("explicit profiles file contains a secret-like value");
        }
        _ => {}
    }
    Ok(())
}

fn secret_field_name(name: &str) -> bool {
    let normalized = name.to_ascii_lowercase();
    [
        "token",
        "secret",
        "password",
        "authorization",
        "api_key",
        "apikey",
    ]
    .into_iter()
    .any(|part| {
        normalized == part
            || normalized
                .split(|character: char| !character.is_ascii_alphanumeric())
                .any(|segment| segment == part)
    })
}

fn secret_like_value(value: &str) -> bool {
    let lowercase = value.to_ascii_lowercase();
    lowercase.starts_with("bearer ")
        || lowercase.starts_with("ghp_")
        || lowercase.starts_with("github_pat_")
        || lowercase.starts_with("sk-")
        || ["token=", "secret=", "password=", "api_key=", "apikey="]
            .iter()
            .any(|marker| lowercase.contains(marker))
}

const fn environment_name(environment: WebEnvironment) -> &'static str {
    match environment {
        WebEnvironment::Browser => "browser",
        WebEnvironment::Server => "server",
        WebEnvironment::Edge => "edge",
        WebEnvironment::Worker => "worker",
    }
}

const fn rust_mode_name(mode: RustProfileMode) -> &'static str {
    match mode {
        RustProfileMode::Check => "check",
        RustProfileMode::Test => "test",
    }
}

const fn go_call_graph_name(call_graph: GoCallGraph) -> &'static str {
    match call_graph {
        GoCallGraph::RtaCha => "rta-cha",
        GoCallGraph::Vta => "vta",
    }
}

const fn web_mode_name(mode: WebProfileMode) -> &'static str {
    match mode {
        WebProfileMode::Production => "production",
        WebProfileMode::Development => "development",
        WebProfileMode::Test => "test",
    }
}

fn parse_web_environment(value: &str) -> Option<WebEnvironment> {
    match value {
        "browser" => Some(WebEnvironment::Browser),
        "server" => Some(WebEnvironment::Server),
        "edge" => Some(WebEnvironment::Edge),
        "worker" => Some(WebEnvironment::Worker),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use depgraph_protocol::stable_id_from_value;
    use serde_json::json;

    use crate::{
        DEFAULT_PROFILE_SELECTION_LIMIT_VERSION, GoCallGraph, GoHostContext, GoProfileAxes,
        MAX_AUTOMATIC_PROFILE_CANDIDATES, MAX_AUTOMATIC_PROFILE_CANDIDATES_PER_LANGUAGE,
        ProfileAxis, ProfileAxisCapability, ProfileHostContext, ProfileLanguage,
        ProfileSelectionLimits, ProfileSelectionRepository, RepositorySizeClass, RustHostContext,
        RustProfileAxes, RustProfileMode, WebProfileAxes, WebProfileMode,
    };

    use super::*;

    fn stable_id(namespace: &str, name: &str) -> String {
        stable_id_from_value(namespace, &json!(name))
    }

    fn rust() -> CanonicalProfileAxes {
        CanonicalProfileAxes::Rust(RustProfileAxes {
            target: "aarch64-apple-darwin".to_owned(),
            mode: RustProfileMode::Check,
            default_features: true,
            features: Vec::new(),
        })
    }

    fn go() -> CanonicalProfileAxes {
        CanonicalProfileAxes::Go(GoProfileAxes {
            goos: "darwin".to_owned(),
            goarch: "arm64".to_owned(),
            tags: Vec::new(),
            cgo_enabled: false,
            call_graph: GoCallGraph::RtaCha,
            dependency_snapshot_id: stable_id("go-dependency-snapshot", "go"),
        })
    }

    fn web() -> CanonicalProfileAxes {
        CanonicalProfileAxes::Web(WebProfileAxes {
            mode: WebProfileMode::Production,
            environments: vec![WebEnvironment::Browser, WebEnvironment::Server],
            bundled_typescript_compatibility_id: stable_id("web-typescript-compatibility", "ts"),
            package_snapshot_id: stable_id("web-package-snapshot", "packages"),
            framework_capability_ids: Vec::new(),
        })
    }

    fn input() -> ProfileSelectionInput {
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
                ProfileHostContext::Go(GoHostContext {
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
                ProfileAxisCapability {
                    language: ProfileLanguage::Go,
                    axis: ProfileAxis::Target,
                },
                ProfileAxisCapability {
                    language: ProfileLanguage::Rust,
                    axis: ProfileAxis::Target,
                },
                ProfileAxisCapability {
                    language: ProfileLanguage::Web,
                    axis: ProfileAxis::Environment,
                },
            ],
            repository: ProfileSelectionRepository {
                size_class: RepositorySizeClass::Large,
                relevant_source_files: 100_000,
                build_units: 1_000,
            },
            limits: ProfileSelectionLimits {
                limit_version: DEFAULT_PROFILE_SELECTION_LIMIT_VERSION.to_owned(),
                effective_profile_cap: 4,
                hard_profile_cap: MAX_SELECTED_ROOT_PROFILES,
                per_language_candidate_cap: MAX_AUTOMATIC_PROFILE_CANDIDATES_PER_LANGUAGE,
                total_candidate_cap: MAX_AUTOMATIC_PROFILE_CANDIDATES,
            },
        }
    }

    #[test]
    fn explicit_profiles_are_canonical_checkout_independent_and_never_auto_filled() -> Result<()> {
        let first = ExplicitProfileSelectionFile {
            contract_version: DEFAULT_PROFILE_SELECTION_CONTRACT_VERSION.to_owned(),
            profiles: vec![web(), rust(), go()],
        };
        let mut reordered = first.clone();
        reordered.profiles.reverse();
        let first = parse_explicit_profile_selection_file(&serde_json::to_string(&first)?)?;
        let second = parse_explicit_profile_selection_file(&serde_json::to_string(&reordered)?)?;
        assert_eq!(first, second);
        let plan = plan_explicit_profile_selection(input(), first)?;
        assert_eq!(plan.selection_mode, ProfileSelectionMode::Explicit);
        assert_eq!(plan.profiles.len(), 3);
        assert!(plan.omitted.is_empty());
        assert!(plan.discovery.is_empty());
        assert!(plan.policy_excluded.is_empty());
        assert!(
            plan.selected
                .iter()
                .all(|entry| entry.reason == ProfileSelectedReason::ExplicitProfileRequested)
        );
        Ok(())
    }

    #[test]
    fn one_invalid_or_duplicate_profile_rejects_the_whole_file() -> Result<()> {
        let duplicate = ExplicitProfileSelectionFile {
            contract_version: DEFAULT_PROFILE_SELECTION_CONTRACT_VERSION.to_owned(),
            profiles: vec![rust(), rust()],
        };
        assert!(
            parse_explicit_profile_selection_file(&serde_json::to_string(&duplicate)?)
                .unwrap_err()
                .to_string()
                .contains("duplicate")
        );

        let mut unsorted = web();
        let CanonicalProfileAxes::Web(axes) = &mut unsorted else {
            unreachable!()
        };
        axes.environments.reverse();
        let invalid = ExplicitProfileSelectionFile {
            contract_version: DEFAULT_PROFILE_SELECTION_CONTRACT_VERSION.to_owned(),
            profiles: vec![rust(), unsorted],
        };
        assert!(
            parse_explicit_profile_selection_file(&serde_json::to_string(&invalid)?)
                .unwrap_err()
                .to_string()
                .contains("strictly sorted")
        );
        Ok(())
    }

    #[test]
    fn unknown_secret_and_oversized_sets_fail_without_echoing_values() -> Result<()> {
        let secret = "fixture-super-secret";
        let raw = format!(
            r#"{{"contract_version":"default-profile-selection-v1","profiles":[],"api_token":"{secret}"}}"#
        );
        let error = parse_explicit_profile_selection_file(&raw)
            .unwrap_err()
            .to_string();
        assert!(error.contains("secret"));
        assert!(!error.contains(secret));

        let oversized = ExplicitProfileSelectionFile {
            contract_version: DEFAULT_PROFILE_SELECTION_CONTRACT_VERSION.to_owned(),
            profiles: (0..=MAX_SELECTED_ROOT_PROFILES)
                .map(|index| {
                    CanonicalProfileAxes::Rust(RustProfileAxes {
                        target: format!("target-{index}"),
                        mode: RustProfileMode::Check,
                        default_features: true,
                        features: Vec::new(),
                    })
                })
                .collect(),
        };
        assert!(
            parse_explicit_profile_selection_file(&serde_json::to_string(&oversized)?)
                .unwrap_err()
                .to_string()
                .contains("1..=32")
        );
        Ok(())
    }

    #[test]
    fn explicit_file_schema_accepts_contract_and_rejects_unknown_fields() -> Result<()> {
        let schema: Value = serde_json::from_str(EXPLICIT_PROFILE_SELECTION_FILE_SCHEMA)?;
        let validator = jsonschema::validator_for(&schema)?;
        let valid = serde_json::to_value(ExplicitProfileSelectionFile {
            contract_version: DEFAULT_PROFILE_SELECTION_CONTRACT_VERSION.to_owned(),
            profiles: vec![rust(), go(), web()],
        })?;
        assert!(validator.is_valid(&valid));
        let mut unknown = valid;
        unknown["unknown"] = json!(true);
        assert!(!validator.is_valid(&unknown));
        Ok(())
    }
}
