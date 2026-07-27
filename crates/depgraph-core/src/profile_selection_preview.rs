use std::{collections::BTreeMap, path::Path};

use anyhow::{Context, Result, bail};
use depgraph_protocol::stable_id_from_value;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use walkdir::{DirEntry, WalkDir};

use crate::bounded_query::read_bounded_repository_file;
use crate::profile_selection_web::{
    WEB_PROFILE_PLANNING_VERSION, WebAutomaticBoundaryKind, WebProfileCandidateGenerationResult,
    WebProfilePlanningInput, WebRejectedProfileDeclaration, WebStaticProfileEvidence,
    generate_web_profile_candidates,
};
use crate::{
    AutomaticProfileSelectionRequest, Config, DEFAULT_PROFILE_SELECTION_CONTRACT_VERSION,
    DefaultProfileSelectionPlan, GoAutomaticBoundaryKind, GoHostContext, GoProfileAvailability,
    GoProfilePlanningInput, GoRejectedProfileDeclaration, GoStaticProfileEvidence,
    MAX_SELECTED_ROOT_PROFILES, ProfileAxis, ProfileAxisCapability, ProfileCandidateCoverage,
    ProfileCandidateDiscoveryResult, ProfileCandidateEvidence, ProfileCandidateEvidenceKind,
    ProfileHostContext, ProfileLanguage, ProfilePlanningBuildUnit, ProfilePlanningBuildUnitKind,
    ProfilePlanningFile, ProfilePlanningFileKind, ProfilePlanningInventory, ProfilePolicyExclusion,
    ProfileSelectionInputContext, RustAutomaticBoundaryKind, RustHostContext,
    RustProfileAlternativeDeclaration, RustProfileAvailability, RustProfilePlanningInput,
    RustRejectedProfileDeclaration, RustRootFeatureDeclaration, RustStaticProfileEvidence,
    RustTargetDeclaration, build_profile_selection_input, canonical_profile_planning_inventory,
    generate_go_profile_candidates, plan_automatic_profile_selection,
    profile_planning_build_unit_id, profile_selection_inventory_digest,
};

const MAX_PREVIEW_FILE_BYTES: usize = 16 * 1024 * 1024;
const MAX_PREVIEW_TOTAL_BYTES: usize = 512 * 1024 * 1024;
const MAX_PREVIEW_FILES: usize = 1_000_000;
const MAX_PREVIEW_ENTRIES: usize = 1_000_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LegacyProfileMigrationStatus {
    DefaultEquivalent,
    NormalizedCandidates,
    ExplicitSelectionRequired,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LegacyProfileConfigMigration {
    pub source_schema_version: u32,
    pub status: LegacyProfileMigrationStatus,
    pub normalized_axes: Vec<String>,
    pub explicit_only_axes: Vec<String>,
    pub diagnostics: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryProfilePlanPreview {
    pub plan: DefaultProfileSelectionPlan,
    pub config_migration: LegacyProfileConfigMigration,
}

pub fn migrate_legacy_profile_config(config: &Config) -> LegacyProfileConfigMigration {
    let defaults = crate::config::ProfileConfig::default();
    let mut normalized_axes = Vec::new();
    let mut explicit_only_axes = Vec::new();
    let mut diagnostics = Vec::new();
    if config.profiles.rust_targets != defaults.rust_targets {
        normalized_axes.push("rust.target".to_owned());
    }
    if config.profiles.rust_features != defaults.rust_features {
        normalized_axes.push("rust.feature_or_tag".to_owned());
    }
    match config.profiles.rust_mode.as_str() {
        "test" => normalized_axes.push("rust.mode".to_owned()),
        "build" => {
            explicit_only_axes.push("rust.build".to_owned());
            diagnostics.push(
                "schema-v1 profiles.rust_mode=build requires explicit project-code consent"
                    .to_owned(),
            );
        }
        _ => {}
    }
    if !config.profiles.go_tags.is_empty() {
        explicit_only_axes.push("go.feature_or_tag".to_owned());
        diagnostics.push(
            "schema-v1 Go tags require parsed source evidence or an explicit profiles file"
                .to_owned(),
        );
    }
    if config.profiles.go_call_graph == "vta" {
        explicit_only_axes.push("go.call_graph".to_owned());
        diagnostics
            .push("schema-v1 Go VTA is not an automatic safe-profile alternative".to_owned());
    }
    let mut web_environments = config.profiles.web_environments.clone();
    web_environments.sort();
    web_environments.dedup();
    if web_environments != vec!["browser".to_owned(), "server".to_owned()] {
        explicit_only_axes.push("web.environment".to_owned());
        diagnostics.push(
            "schema-v1 Web environment changes require static evidence or an explicit profiles file"
                .to_owned(),
        );
    }
    normalized_axes.sort();
    normalized_axes.dedup();
    explicit_only_axes.sort();
    explicit_only_axes.dedup();
    diagnostics.sort();
    let status = if !explicit_only_axes.is_empty() {
        LegacyProfileMigrationStatus::ExplicitSelectionRequired
    } else if !normalized_axes.is_empty() {
        LegacyProfileMigrationStatus::NormalizedCandidates
    } else {
        LegacyProfileMigrationStatus::DefaultEquivalent
    };
    LegacyProfileConfigMigration {
        source_schema_version: config.schema_version,
        status,
        normalized_axes,
        explicit_only_axes,
        diagnostics,
    }
}

pub fn plan_repository_profiles(
    root: &Path,
    config: &Config,
    profile_budget: Option<u32>,
) -> Result<RepositoryProfilePlanPreview> {
    let inventory = build_repository_profile_planning_inventory(root)?;
    let evidence = family_evidence(&inventory);
    let mut language_families = evidence.keys().copied().collect::<Vec<_>>();
    language_families
        .sort_by(|left, right| left.as_str().as_bytes().cmp(right.as_str().as_bytes()));
    let mut host_contexts = Vec::new();
    if language_families.contains(&ProfileLanguage::Rust) {
        host_contexts.push(ProfileHostContext::Rust(RustHostContext {
            target: rust_host_target()?.to_owned(),
        }));
    }
    if language_families.contains(&ProfileLanguage::Go) {
        let (goos, goarch) = go_host_platform()?;
        host_contexts.push(ProfileHostContext::Go(GoHostContext {
            goos: goos.to_owned(),
            goarch: goarch.to_owned(),
        }));
    }
    let mut supported_axes = Vec::new();
    for language in &language_families {
        let axes: &[ProfileAxis] = match language {
            ProfileLanguage::Rust => &[
                ProfileAxis::Target,
                ProfileAxis::Mode,
                ProfileAxis::FeatureOrTag,
            ],
            ProfileLanguage::Go => &[ProfileAxis::Target, ProfileAxis::FeatureOrTag],
            ProfileLanguage::Web => &[ProfileAxis::Environment, ProfileAxis::Mode],
        };
        supported_axes.extend(axes.iter().map(|axis| ProfileAxisCapability {
            language: *language,
            axis: *axis,
        }));
    }
    let configuration_digest = profile_config_digest(&config.profiles)?;
    let release_contract = crate::profile_selection_release_compatibility_contract();
    let mut input = build_profile_selection_input(
        &inventory,
        ProfileSelectionInputContext {
            compatibility_ids: vec![
                format!("depgraph-core:{}", env!("CARGO_PKG_VERSION")),
                DEFAULT_PROFILE_SELECTION_CONTRACT_VERSION.to_owned(),
                release_contract.limit_version,
                release_contract.inventory_version,
                release_contract.rust_planning_version,
                release_contract.go_planning_version,
                release_contract.web_planning_version,
                release_contract.automatic_schema_sha256,
                release_contract.explicit_schema_sha256,
            ],
            language_families: language_families.clone(),
            host_contexts,
            configuration_digest: Some(configuration_digest),
            selection_file_digest: None,
            supported_axes,
        },
    )?;
    if let Some(profile_budget) = profile_budget {
        let baseline_count = u32::try_from(language_families.len())?;
        if !(1..=MAX_SELECTED_ROOT_PROFILES).contains(&profile_budget)
            || profile_budget < baseline_count
        {
            bail!(
                "profile-budget must be 1..={MAX_SELECTED_ROOT_PROFILES} and reserve every detected language baseline"
            );
        }
        input.limits.effective_profile_cap = profile_budget;
    }

    let migration = migrate_legacy_profile_config(config);
    let mut discoveries = Vec::<ProfileCandidateDiscoveryResult>::new();
    let mut policy_excluded = Vec::<ProfilePolicyExclusion>::new();
    let mut tracked_candidate_ids = Vec::new();
    if let Some(path) = evidence.get(&ProfileLanguage::Rust) {
        let generated = generate_rust_preview(config, path)?;
        tracked_candidate_ids.extend(
            generated
                .bounded
                .candidates
                .iter()
                .filter(|candidate| candidate.kind == crate::ProfileCandidateKind::Alternative)
                .map(|candidate| candidate.id.clone()),
        );
        policy_excluded.extend(generated.policy_excluded);
        discoveries.push(generated.bounded);
    }
    if let Some(path) = evidence.get(&ProfileLanguage::Go) {
        let generated = generate_go_preview(config, path, &input.inventory_digest)?;
        policy_excluded.extend(generated.policy_excluded);
        discoveries.push(generated.bounded);
    }
    if let Some(path) = evidence.get(&ProfileLanguage::Web) {
        let generated = generate_web_preview(config, path, &inventory)?;
        policy_excluded.extend(generated.policy_excluded);
        discoveries.push(generated.bounded);
    }
    let plan = plan_automatic_profile_selection(AutomaticProfileSelectionRequest {
        input,
        discoveries,
        policy_excluded,
        tracked_candidate_ids,
    })?;
    Ok(RepositoryProfilePlanPreview {
        plan,
        config_migration: migration,
    })
}

pub fn build_repository_profile_planning_inventory(
    root: &Path,
) -> Result<ProfilePlanningInventory> {
    let canonical_root = root
        .canonicalize()
        .context("profile planning repository root is unavailable")?;
    if !canonical_root.is_dir() {
        bail!("profile planning root must be a directory");
    }
    let mut files = Vec::new();
    let mut build_units = Vec::new();
    let mut total_bytes = 0_usize;
    let mut entry_count = 0_usize;
    for entry in WalkDir::new(&canonical_root)
        .follow_links(false)
        .into_iter()
        .filter_entry(include_entry)
    {
        let entry = entry.context("failed to inspect repository profile inventory")?;
        record_preview_entry(&mut entry_count)?;
        if !entry.file_type().is_file() {
            continue;
        }
        let relative = entry
            .path()
            .strip_prefix(&canonical_root)
            .context("profile inventory path escaped its root")?;
        let path = relative
            .to_str()
            .context("profile inventory path is not UTF-8")?
            .replace('\\', "/");
        let Some((kind, language)) = planning_file_kind(&path) else {
            continue;
        };
        if files.len() >= MAX_PREVIEW_FILES {
            bail!("profile preview exceeds its closed file-count limit");
        }
        let bytes =
            read_bounded_repository_file(&canonical_root, entry.path(), MAX_PREVIEW_FILE_BYTES)
                .map_err(|error| {
                    anyhow::anyhow!("failed to read bounded profile inventory file: {error}")
                })?;
        total_bytes = total_bytes
            .checked_add(bytes.len())
            .context("profile preview byte count overflow")?;
        if total_bytes > MAX_PREVIEW_TOTAL_BYTES {
            bail!("profile preview exceeds its closed total byte limit");
        }
        files.push(ProfilePlanningFile {
            path: path.clone(),
            kind,
            content_digest: format!("sha256:{}", hex::encode(Sha256::digest(&bytes))),
        });
        if let Some(unit_kind) = build_unit_kind(&path, language) {
            build_units.push(ProfilePlanningBuildUnit {
                id: profile_planning_build_unit_id(language, unit_kind, &path, &path),
                language,
                kind: unit_kind,
                name: path.clone(),
                evidence_path: path,
            });
        }
    }
    canonical_profile_planning_inventory(&ProfilePlanningInventory {
        inventory_version: crate::PROFILE_SELECTION_INVENTORY_VERSION.to_owned(),
        files,
        build_units,
    })
}

fn record_preview_entry(entry_count: &mut usize) -> Result<()> {
    *entry_count = entry_count
        .checked_add(1)
        .context("profile preview entry count overflow")?;
    if *entry_count > MAX_PREVIEW_ENTRIES {
        bail!("profile preview exceeds its closed entry-count limit");
    }
    Ok(())
}

fn generate_rust_preview(
    config: &Config,
    evidence_path: &str,
) -> Result<crate::RustProfileCandidateGenerationResult> {
    let baseline = rust_evidence("rust-baseline", evidence_path);
    let config_evidence = rust_evidence("rust-config", crate::config::CONFIG_FILE);
    let targets = config
        .profiles
        .rust_targets
        .iter()
        .map(|target| RustTargetDeclaration {
            target: target.clone(),
            repository_default: false,
            availability: RustProfileAvailability::Available,
            static_evidence: config_evidence.clone(),
        })
        .collect();
    let test_mode =
        (config.profiles.rust_mode == "test").then_some(RustProfileAlternativeDeclaration {
            availability: RustProfileAvailability::Available,
            static_evidence: config_evidence.clone(),
        });
    let root_features = config
        .profiles
        .rust_features
        .iter()
        .map(|feature| RustRootFeatureDeclaration {
            package_locator: "workspace".to_owned(),
            root_feature: feature.clone(),
            feature_closure: vec![feature.clone()],
            availability: RustProfileAvailability::Available,
            static_evidence: config_evidence.clone(),
        })
        .collect();
    let rejected = (config.profiles.rust_mode == "build")
        .then_some(RustRejectedProfileDeclaration {
            kind: RustAutomaticBoundaryKind::BuildProfile,
            axis: Some(ProfileAxis::Mode),
            axis_values: vec!["build".to_owned()],
            evidence: config_evidence.evidence.clone(),
        })
        .into_iter()
        .collect();
    crate::generate_rust_profile_candidates(RustProfilePlanningInput {
        planning_version: crate::RUST_PROFILE_PLANNING_VERSION.to_owned(),
        host_target: rust_host_target()?.to_owned(),
        host_availability: RustProfileAvailability::Available,
        baseline,
        targets,
        test_mode,
        no_default_features: None,
        root_features,
        rejected,
    })
}

fn generate_go_preview(
    config: &Config,
    evidence_path: &str,
    inventory_digest: &str,
) -> Result<crate::GoProfileCandidateGenerationResult> {
    let (goos, goarch) = go_host_platform()?;
    let config_evidence = go_evidence("go-config", crate::config::CONFIG_FILE);
    let mut rejected = config
        .profiles
        .go_tags
        .iter()
        .map(|tag| GoRejectedProfileDeclaration {
            kind: GoAutomaticBoundaryKind::ArbitraryUserTag,
            axis: Some(ProfileAxis::FeatureOrTag),
            axis_values: vec![format!("tag={tag}")],
            evidence: config_evidence.evidence.clone(),
        })
        .collect::<Vec<_>>();
    if config.profiles.go_call_graph == "vta" {
        rejected.push(GoRejectedProfileDeclaration {
            kind: GoAutomaticBoundaryKind::Vta,
            axis: None,
            axis_values: vec!["call_graph=vta".to_owned()],
            evidence: config_evidence.evidence.clone(),
        });
    }
    generate_go_profile_candidates(GoProfilePlanningInput {
        planning_version: crate::GO_PROFILE_PLANNING_VERSION.to_owned(),
        host_goos: goos.to_owned(),
        host_goarch: goarch.to_owned(),
        host_availability: GoProfileAvailability::Available,
        dependency_snapshot_id: stable_id_from_value(
            "go-dependency-snapshot",
            &json!(inventory_digest),
        ),
        baseline: go_evidence("go-baseline", evidence_path),
        targets: Vec::new(),
        tags: Vec::new(),
        rejected,
    })
}

fn generate_web_preview(
    config: &Config,
    evidence_path: &str,
    inventory: &ProfilePlanningInventory,
) -> Result<WebProfileCandidateGenerationResult> {
    let config_evidence = web_evidence("web-config", crate::config::CONFIG_FILE);
    let mut rejected = Vec::new();
    let mut environments = config.profiles.web_environments.clone();
    environments.sort();
    environments.dedup();
    if environments != vec!["browser".to_owned(), "server".to_owned()] {
        rejected.push(WebRejectedProfileDeclaration {
            kind: WebAutomaticBoundaryKind::InsufficientEvidence,
            axis: Some(ProfileAxis::Environment),
            axis_values: environments,
            evidence: config_evidence.evidence,
        });
    }
    let mut framework_capability_ids = inventory
        .build_units
        .iter()
        .filter(|unit| unit.kind == ProfilePlanningBuildUnitKind::FrameworkEnvironmentRoot)
        .map(|unit| stable_id_from_value("web-framework-capability", &json!(unit.id)))
        .collect::<Vec<_>>();
    framework_capability_ids.sort();
    framework_capability_ids.dedup();
    if framework_capability_ids.len() > 64 {
        bail!("web preview exceeds its closed framework-capability limit");
    }
    let package_snapshot_id = profile_selection_inventory_digest(inventory)?;
    generate_web_profile_candidates(WebProfilePlanningInput {
        planning_version: WEB_PROFILE_PLANNING_VERSION.to_owned(),
        bundled_typescript_compatibility_id: stable_id_from_value(
            "web-typescript-compatibility",
            &json!("typescript-7.0.2"),
        ),
        package_snapshot_id: stable_id_from_value(
            "web-package-snapshot",
            &json!(package_snapshot_id),
        ),
        framework_capability_ids,
        baseline: web_evidence("web-baseline", evidence_path),
        environments: Vec::new(),
        modes: Vec::new(),
        rejected,
    })
}

fn family_evidence(inventory: &ProfilePlanningInventory) -> BTreeMap<ProfileLanguage, String> {
    let mut evidence = BTreeMap::new();
    for file in &inventory.files {
        let language = match file.kind {
            ProfilePlanningFileKind::RustSource => Some(ProfileLanguage::Rust),
            ProfilePlanningFileKind::GoSource => Some(ProfileLanguage::Go),
            ProfilePlanningFileKind::WebSource | ProfilePlanningFileKind::FrameworkSource => {
                Some(ProfileLanguage::Web)
            }
            ProfilePlanningFileKind::SchemaSource | ProfilePlanningFileKind::GeneratedSource => {
                None
            }
        };
        if let Some(language) = language {
            evidence
                .entry(language)
                .or_insert_with(|| file.path.clone());
        }
    }
    evidence
}

fn rust_evidence(name: &str, path: &str) -> RustStaticProfileEvidence {
    RustStaticProfileEvidence {
        estimated_coverage: coverage(name),
        evidence: vec![evidence(path)],
    }
}

fn go_evidence(name: &str, path: &str) -> GoStaticProfileEvidence {
    GoStaticProfileEvidence {
        estimated_coverage: coverage(name),
        evidence: vec![evidence(path)],
    }
}

fn web_evidence(name: &str, path: &str) -> WebStaticProfileEvidence {
    WebStaticProfileEvidence {
        estimated_coverage: coverage(name),
        evidence: vec![evidence(path)],
    }
}

fn coverage(name: &str) -> ProfileCandidateCoverage {
    ProfileCandidateCoverage {
        file_ids: vec![stable_id_from_value("file", &json!(name))],
        dependency_site_ids: Vec::new(),
    }
}

fn evidence(path: &str) -> ProfileCandidateEvidence {
    ProfileCandidateEvidence {
        kind: if manifest_path(path) {
            ProfileCandidateEvidenceKind::Manifest
        } else if path == crate::config::CONFIG_FILE {
            ProfileCandidateEvidenceKind::Config
        } else {
            ProfileCandidateEvidenceKind::Source
        },
        path: path.to_owned(),
        start_line: 1,
        end_line: 1,
    }
}

fn include_entry(entry: &DirEntry) -> bool {
    if entry.depth() == 0 {
        return true;
    }
    if !entry.file_type().is_dir() {
        return true;
    }
    !matches!(
        entry.file_name().to_str(),
        Some(".git" | ".depgraph" | "target" | "node_modules")
    )
}

fn planning_file_kind(path: &str) -> Option<(ProfilePlanningFileKind, ProfileLanguage)> {
    if path.ends_with(".rs") || path.ends_with("Cargo.toml") {
        return Some((ProfilePlanningFileKind::RustSource, ProfileLanguage::Rust));
    }
    if path.ends_with(".go") || path.ends_with("go.mod") {
        return Some((ProfilePlanningFileKind::GoSource, ProfileLanguage::Go));
    }
    if framework_path(path) {
        return Some((
            ProfilePlanningFileKind::FrameworkSource,
            ProfileLanguage::Web,
        ));
    }
    if path.ends_with("package.json")
        || [
            ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".astro", ".vue", ".svelte",
        ]
        .iter()
        .any(|extension| path.ends_with(extension))
    {
        return Some((ProfilePlanningFileKind::WebSource, ProfileLanguage::Web));
    }
    None
}

fn build_unit_kind(path: &str, language: ProfileLanguage) -> Option<ProfilePlanningBuildUnitKind> {
    match language {
        ProfileLanguage::Rust if path.ends_with("Cargo.toml") => {
            Some(ProfilePlanningBuildUnitKind::RustPackageTarget)
        }
        ProfileLanguage::Go if path.ends_with("go.mod") => {
            Some(ProfilePlanningBuildUnitKind::GoPackageVariant)
        }
        ProfileLanguage::Web if path.ends_with("package.json") => {
            Some(ProfilePlanningBuildUnitKind::WebWorkspacePackage)
        }
        ProfileLanguage::Web if framework_path(path) => {
            Some(ProfilePlanningBuildUnitKind::FrameworkEnvironmentRoot)
        }
        _ => None,
    }
}

fn framework_path(path: &str) -> bool {
    path.rsplit('/').next().is_some_and(|name| {
        name.starts_with("next.config.")
            || name.starts_with("astro.config.")
            || name.starts_with("vite.config.")
            || name == "app.config.ts"
            || name == "app.config.js"
    })
}

fn manifest_path(path: &str) -> bool {
    path.ends_with("Cargo.toml") || path.ends_with("go.mod") || path.ends_with("package.json")
}

fn profile_config_digest(config: &crate::config::ProfileConfig) -> Result<String> {
    let bytes = toml::to_string(config).context("failed to canonicalize profile configuration")?;
    Ok(format!(
        "sha256:{}",
        hex::encode(Sha256::digest(bytes.as_bytes()))
    ))
}

fn rust_host_target() -> Result<&'static str> {
    match (std::env::consts::ARCH, std::env::consts::OS) {
        ("aarch64", "macos") => Ok("aarch64-apple-darwin"),
        ("x86_64", "macos") => Ok("x86_64-apple-darwin"),
        ("aarch64", "linux") => Ok("aarch64-unknown-linux-gnu"),
        ("x86_64", "linux") => Ok("x86_64-unknown-linux-gnu"),
        ("x86_64", "windows") => Ok("x86_64-pc-windows-msvc"),
        _ => bail!("current host is outside the closed profile-planning target vocabulary"),
    }
}

fn go_host_platform() -> Result<(&'static str, &'static str)> {
    let goos = match std::env::consts::OS {
        "macos" => "darwin",
        "linux" => "linux",
        "windows" => "windows",
        _ => bail!("current host is outside the closed Go profile-planning OS vocabulary"),
    };
    let goarch = match std::env::consts::ARCH {
        "aarch64" => "arm64",
        "x86_64" => "amd64",
        _ => {
            bail!("current host is outside the closed Go profile-planning architecture vocabulary")
        }
    };
    Ok((goos, goarch))
}

#[cfg(test)]
mod tests {
    use std::fs;

    use crate::{
        ProfileCandidateKind, ProfileExclusionReason, ProfileSelectedReason,
        canonical_profile_selection_json,
    };

    use super::*;

    fn fixture(root: &Path) -> Result<()> {
        fs::create_dir_all(root.join("src"))?;
        fs::create_dir_all(root.join("web"))?;
        fs::write(
            root.join("Cargo.toml"),
            "[package]\nname='fixture'\nversion='0.1.0'\n",
        )?;
        fs::write(root.join("src/lib.rs"), "pub fn fixture() {}\n")?;
        fs::write(
            root.join("go.mod"),
            "module example.test/fixture\n\ngo 1.26\n",
        )?;
        fs::write(root.join("main.go"), "package main\n")?;
        fs::write(root.join("web/package.json"), "{\"name\":\"fixture\"}\n")?;
        fs::write(root.join("web/app.ts"), "export const fixture = true;\n")?;
        Ok(())
    }

    #[test]
    fn polyglot_preview_selects_every_baseline_before_tracked_candidates() -> Result<()> {
        let root = tempfile::tempdir()?;
        fixture(root.path())?;
        let mut config = Config::default();
        config.profiles.rust_targets = vec!["wasm32-wasip1".to_owned()];
        let preview = plan_repository_profiles(root.path(), &config, Some(4))?;
        assert_eq!(preview.plan.input.language_families.len(), 3);
        assert_eq!(preview.plan.selected.len(), 4);
        assert_eq!(
            preview.config_migration.status,
            LegacyProfileMigrationStatus::NormalizedCandidates
        );
        let candidates = preview
            .plan
            .candidates
            .iter()
            .map(|candidate| (candidate.id.as_str(), candidate))
            .collect::<BTreeMap<_, _>>();
        let tracked = preview
            .plan
            .selected
            .iter()
            .find(|selected| selected.reason == ProfileSelectedReason::TrackedProfileConfiguration)
            .context("tracked Rust target")?;
        assert_eq!(tracked.selection_rank, 3);
        assert_eq!(
            candidates[tracked.candidate_id.as_str()].kind,
            ProfileCandidateKind::Alternative
        );
        Ok(())
    }

    #[test]
    fn preview_is_checkout_independent_and_ignores_build_directories() -> Result<()> {
        let first = tempfile::tempdir()?;
        let second = tempfile::tempdir()?;
        fixture(first.path())?;
        fixture(second.path())?;
        fs::create_dir_all(first.path().join("target"))?;
        fs::write(first.path().join("target/ignored.rs"), "secret drift")?;
        let first = plan_repository_profiles(first.path(), &Config::default(), None)?;
        let second = plan_repository_profiles(second.path(), &Config::default(), None)?;
        assert_eq!(
            canonical_profile_selection_json(&first.plan),
            canonical_profile_selection_json(&second.plan)
        );
        Ok(())
    }

    #[test]
    fn budget_conflict_and_legacy_explicit_boundaries_fail_or_remain_visible() -> Result<()> {
        let root = tempfile::tempdir()?;
        fixture(root.path())?;
        assert!(
            plan_repository_profiles(root.path(), &Config::default(), Some(2))
                .unwrap_err()
                .to_string()
                .contains("reserve every")
        );

        let mut config = Config::default();
        config.profiles.rust_mode = "build".to_owned();
        config.profiles.go_call_graph = "vta".to_owned();
        let preview = plan_repository_profiles(root.path(), &config, None)?;
        assert_eq!(
            preview.config_migration.status,
            LegacyProfileMigrationStatus::ExplicitSelectionRequired
        );
        assert!(preview.plan.policy_excluded.iter().any(
            |entry| entry.reason == ProfileExclusionReason::DefaultProfileBuildRequiresConsent
        ));
        assert!(
            preview
                .plan
                .policy_excluded
                .iter()
                .any(|entry| entry.reason == ProfileExclusionReason::DefaultProfileUnsupportedAxis)
        );
        Ok(())
    }

    #[test]
    fn entry_limit_counts_every_walked_entry_before_file_classification() -> Result<()> {
        let mut entry_count = MAX_PREVIEW_ENTRIES - 1;
        record_preview_entry(&mut entry_count)?;
        assert_eq!(entry_count, MAX_PREVIEW_ENTRIES);
        assert!(
            record_preview_entry(&mut entry_count)
                .unwrap_err()
                .to_string()
                .contains("entry-count")
        );
        Ok(())
    }

    #[test]
    fn only_profile_configuration_changes_the_profile_planning_identity() -> Result<()> {
        let root = tempfile::tempdir()?;
        fixture(root.path())?;
        let baseline = plan_repository_profiles(root.path(), &Config::default(), None)?;

        fs::write(root.path().join("src/lib.rs"), "pub fn changed() {}\n")?;
        fs::write(
            root.path().join("web/app.ts"),
            "export const changed = true;\n",
        )?;
        let source_only = plan_repository_profiles(root.path(), &Config::default(), None)?;
        assert_eq!(baseline.plan.plan_id, source_only.plan.plan_id);

        fs::write(
            root.path().join("web/package.json"),
            "{\"name\":\"changed\"}\n",
        )?;
        let manifest = plan_repository_profiles(root.path(), &Config::default(), None)?;
        assert_ne!(baseline.plan.plan_id, manifest.plan.plan_id);

        let mut scan_only = Config::default();
        scan_only.scan.max_stderr_bytes += 1;
        let scan_only = plan_repository_profiles(root.path(), &scan_only, None)?;
        assert_eq!(manifest.plan.plan_id, scan_only.plan.plan_id);

        let mut profile = Config::default();
        profile.profiles.rust_targets = vec!["wasm32-wasip1".to_owned()];
        let profile = plan_repository_profiles(root.path(), &profile, None)?;
        assert_ne!(manifest.plan.plan_id, profile.plan.plan_id);
        Ok(())
    }
}
