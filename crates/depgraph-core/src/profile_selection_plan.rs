use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, bail};
use depgraph_protocol::{canonical_json, stable_id_from_value};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::{
    CandidateDiscoveryReason, DEFAULT_PROFILE_SELECTION_CONTRACT_VERSION,
    DEFAULT_PROFILE_SELECTION_LIMIT_VERSION, GoHostContext, MAX_AUTOMATIC_PROFILE_CANDIDATES,
    MAX_AUTOMATIC_PROFILE_CANDIDATES_PER_LANGUAGE, MAX_SELECTED_ROOT_PROFILES, ProfileAxis,
    ProfileAxisCapability, ProfileCandidateEvidence, ProfileCandidateKind, ProfileCandidateRecord,
    ProfileDiscoveryLedger, ProfileHostContext, ProfileLanguage, ProfileSelectionInput,
    ProfileSelectionLimits, ProfileSelectionProfile, ProfileSelectionRepository,
    RepositorySizeClass, canonical_profile_id, profile_candidate_id,
};

pub const PROFILE_SELECTION_INVENTORY_VERSION: &str = "default-profile-inventory-v1";

pub const TINY_SOURCE_FILE_THRESHOLD: u64 = 1_000;
pub const TINY_BUILD_UNIT_THRESHOLD: u64 = 25;
pub const SMALL_SOURCE_FILE_THRESHOLD: u64 = 10_000;
pub const SMALL_BUILD_UNIT_THRESHOLD: u64 = 100;
pub const MEDIUM_SOURCE_FILE_THRESHOLD: u64 = 50_000;
pub const MEDIUM_BUILD_UNIT_THRESHOLD: u64 = 500;
pub const LARGE_SOURCE_FILE_THRESHOLD: u64 = u64::MAX;
pub const LARGE_BUILD_UNIT_THRESHOLD: u64 = u64::MAX;

pub const DEFAULT_TINY_PROFILE_CAP: u32 = 16;
pub const DEFAULT_SMALL_PROFILE_CAP: u32 = 10;
pub const DEFAULT_MEDIUM_PROFILE_CAP: u32 = 6;
pub const DEFAULT_LARGE_PROFILE_CAP: u32 = 4;

const MAX_INVENTORY_FILES: usize = 1_000_000;
const MAX_INVENTORY_BUILD_UNITS: usize = 100_000;
const MAX_INVENTORY_PATH_CHARS: usize = 4_096;
const MAX_BUILD_UNIT_NAME_CHARS: usize = 512;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfilePlanningFileKind {
    RustSource,
    GoSource,
    WebSource,
    SchemaSource,
    GeneratedSource,
    FrameworkSource,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProfilePlanningFile {
    pub path: String,
    pub kind: ProfilePlanningFileKind,
    pub content_digest: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfilePlanningBuildUnitKind {
    RustPackageTarget,
    GoPackageVariant,
    WebWorkspacePackage,
    FrameworkEnvironmentRoot,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProfilePlanningBuildUnit {
    pub id: String,
    pub language: ProfileLanguage,
    pub kind: ProfilePlanningBuildUnitKind,
    pub name: String,
    pub evidence_path: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProfilePlanningInventory {
    pub inventory_version: String,
    pub files: Vec<ProfilePlanningFile>,
    pub build_units: Vec<ProfilePlanningBuildUnit>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileSelectionInputContext {
    pub compatibility_ids: Vec<String>,
    pub language_families: Vec<ProfileLanguage>,
    pub host_contexts: Vec<ProfileHostContext>,
    pub configuration_digest: Option<String>,
    pub selection_file_digest: Option<String>,
    pub supported_axes: Vec<ProfileAxisCapability>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProfileCandidateDiscoveryResult {
    pub profiles: Vec<ProfileSelectionProfile>,
    pub candidates: Vec<ProfileCandidateRecord>,
    pub discovery: Vec<ProfileDiscoveryLedger>,
    pub complete: bool,
}

#[must_use]
pub fn profile_planning_build_unit_id(
    language: ProfileLanguage,
    kind: ProfilePlanningBuildUnitKind,
    name: &str,
    evidence_path: &str,
) -> String {
    stable_id_from_value(
        "profile-build-unit",
        &json!({
            "inventory_version": PROFILE_SELECTION_INVENTORY_VERSION,
            "language": language,
            "kind": kind,
            "name": name,
            "evidence_path": evidence_path,
        }),
    )
}

pub fn canonical_profile_planning_inventory(
    inventory: &ProfilePlanningInventory,
) -> Result<ProfilePlanningInventory> {
    if inventory.inventory_version != PROFILE_SELECTION_INVENTORY_VERSION {
        bail!(
            "unsupported profile planning inventory version; expected {PROFILE_SELECTION_INVENTORY_VERSION}"
        );
    }
    if inventory.files.len() > MAX_INVENTORY_FILES
        || inventory.build_units.len() > MAX_INVENTORY_BUILD_UNITS
    {
        bail!("profile planning inventory exceeds its closed file or build-unit limit");
    }

    let mut files = inventory.files.clone();
    files.sort_by(|left, right| {
        left.path
            .as_bytes()
            .cmp(right.path.as_bytes())
            .then(left.kind.cmp(&right.kind))
            .then(left.content_digest.cmp(&right.content_digest))
    });
    let mut canonical_files: Vec<ProfilePlanningFile> = Vec::with_capacity(files.len());
    for file in files {
        validate_repository_path("planning file path", &file.path)?;
        validate_sha256("planning file content_digest", &file.content_digest)?;
        if let Some(previous) = canonical_files.last()
            && previous.path == file.path
        {
            if previous != &file {
                bail!("one planning file path cannot have conflicting canonical records");
            }
            continue;
        }
        canonical_files.push(file);
    }

    let mut build_units = inventory.build_units.clone();
    build_units.sort_by(|left, right| left.id.as_bytes().cmp(right.id.as_bytes()));
    let mut canonical_build_units: Vec<ProfilePlanningBuildUnit> =
        Vec::with_capacity(build_units.len());
    for unit in build_units {
        validate_portable_build_unit_name(&unit.name)?;
        validate_repository_path("planning build-unit evidence_path", &unit.evidence_path)?;
        if !matches!(
            (unit.language, unit.kind),
            (
                ProfileLanguage::Rust,
                ProfilePlanningBuildUnitKind::RustPackageTarget
            ) | (
                ProfileLanguage::Go,
                ProfilePlanningBuildUnitKind::GoPackageVariant
            ) | (
                ProfileLanguage::Web,
                ProfilePlanningBuildUnitKind::WebWorkspacePackage
                    | ProfilePlanningBuildUnitKind::FrameworkEnvironmentRoot
            )
        ) {
            bail!("planning build-unit kind does not match its language");
        }
        let expected = profile_planning_build_unit_id(
            unit.language,
            unit.kind,
            &unit.name,
            &unit.evidence_path,
        );
        if unit.id != expected {
            bail!("planning build-unit id does not match its canonical identity");
        }
        if let Some(previous) = canonical_build_units.last()
            && previous.id == unit.id
        {
            if previous != &unit {
                bail!("one planning build-unit id cannot have conflicting records");
            }
            continue;
        }
        canonical_build_units.push(unit);
    }

    Ok(ProfilePlanningInventory {
        inventory_version: PROFILE_SELECTION_INVENTORY_VERSION.to_owned(),
        files: canonical_files,
        build_units: canonical_build_units,
    })
}

pub fn profile_selection_inventory_digest(inventory: &ProfilePlanningInventory) -> Result<String> {
    let canonical = canonical_profile_planning_inventory(inventory)?;
    let payload = canonical_json(&serde_json::to_value(canonical)?);
    Ok(format!(
        "sha256:{}",
        hex::encode(Sha256::digest(payload.as_bytes()))
    ))
}

pub fn classify_profile_selection_repository(
    inventory: &ProfilePlanningInventory,
) -> Result<ProfileSelectionRepository> {
    let canonical = canonical_profile_planning_inventory(inventory)?;
    let relevant_source_files = u64::try_from(canonical.files.len())?;
    let build_units = u64::try_from(canonical.build_units.len())?;
    let size_class = classify_repository_size(relevant_source_files, build_units);
    Ok(ProfileSelectionRepository {
        size_class,
        relevant_source_files,
        build_units,
    })
}

#[must_use]
pub fn default_profile_selection_limits(size_class: RepositorySizeClass) -> ProfileSelectionLimits {
    let effective_profile_cap = match size_class {
        RepositorySizeClass::Tiny => DEFAULT_TINY_PROFILE_CAP,
        RepositorySizeClass::Small => DEFAULT_SMALL_PROFILE_CAP,
        RepositorySizeClass::Medium => DEFAULT_MEDIUM_PROFILE_CAP,
        RepositorySizeClass::Large => DEFAULT_LARGE_PROFILE_CAP,
    };
    ProfileSelectionLimits {
        limit_version: DEFAULT_PROFILE_SELECTION_LIMIT_VERSION.to_owned(),
        effective_profile_cap,
        hard_profile_cap: MAX_SELECTED_ROOT_PROFILES,
        per_language_candidate_cap: MAX_AUTOMATIC_PROFILE_CANDIDATES_PER_LANGUAGE,
        total_candidate_cap: MAX_AUTOMATIC_PROFILE_CANDIDATES,
    }
}

pub fn build_profile_selection_input(
    inventory: &ProfilePlanningInventory,
    mut context: ProfileSelectionInputContext,
) -> Result<ProfileSelectionInput> {
    let canonical_inventory = canonical_profile_planning_inventory(inventory)?;
    context
        .compatibility_ids
        .sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    context.compatibility_ids.dedup();
    if context.compatibility_ids.is_empty() {
        bail!("profile selection compatibility_ids must not be empty");
    }
    for identity in &context.compatibility_ids {
        validate_bounded_text("profile compatibility identity", identity, 512)?;
        if identity.contains('/') || identity.contains('\\') {
            bail!("profile compatibility identity must not contain a filesystem path");
        }
    }

    context
        .language_families
        .sort_by(|left, right| left.as_str().as_bytes().cmp(right.as_str().as_bytes()));
    context.language_families.dedup();
    let detected_language_families = detected_language_families(&canonical_inventory);
    if context.language_families != detected_language_families {
        bail!(
            "profile selection language_families must exactly match the canonical safe inventory"
        );
    }
    context.host_contexts.sort_by(|left, right| {
        host_language(left)
            .as_str()
            .as_bytes()
            .cmp(host_language(right).as_str().as_bytes())
    });
    if context
        .host_contexts
        .windows(2)
        .any(|pair| host_language(&pair[0]) == host_language(&pair[1]))
    {
        bail!("profile selection host_contexts must contain one context per language");
    }
    for host in &context.host_contexts {
        if !context.language_families.contains(&host_language(host)) {
            bail!("profile selection host context language was not detected");
        }
        match host {
            ProfileHostContext::Rust(host) => {
                validate_portable_axis_value("Rust host target", &host.target)?;
            }
            ProfileHostContext::Go(GoHostContext { goos, goarch }) => {
                validate_portable_axis_value("Go host GOOS", goos)?;
                validate_portable_axis_value("Go host GOARCH", goarch)?;
            }
        }
    }
    for language in &context.language_families {
        if matches!(language, ProfileLanguage::Rust | ProfileLanguage::Go)
            && !context
                .host_contexts
                .iter()
                .any(|host| host_language(host) == *language)
        {
            bail!("detected Rust and Go families require an attested host context");
        }
    }

    context.supported_axes.sort_by(|left, right| {
        (left.language.as_str(), left.axis.as_str())
            .cmp(&(right.language.as_str(), right.axis.as_str()))
    });
    context
        .supported_axes
        .dedup_by(|left, right| left.language == right.language && left.axis == right.axis);
    for capability in &context.supported_axes {
        if !context.language_families.contains(&capability.language)
            || !axis_is_supported(capability.language, capability.axis)
        {
            bail!("profile selection supported_axes contains an unavailable axis");
        }
    }
    if let Some(digest) = &context.configuration_digest {
        validate_sha256("profile configuration digest", digest)?;
    }
    if let Some(digest) = &context.selection_file_digest {
        validate_sha256("profile selection-file digest", digest)?;
    }

    let repository = classify_profile_selection_repository(&canonical_inventory)?;
    let limits = default_profile_selection_limits(repository.size_class);
    Ok(ProfileSelectionInput {
        contract_version: DEFAULT_PROFILE_SELECTION_CONTRACT_VERSION.to_owned(),
        inventory_digest: profile_selection_inventory_digest(&canonical_inventory)?,
        compatibility_ids: context.compatibility_ids,
        language_families: context.language_families,
        host_contexts: context.host_contexts,
        configuration_digest: context.configuration_digest,
        selection_file_digest: context.selection_file_digest,
        supported_axes: context.supported_axes,
        repository,
        limits,
    })
}

fn detected_language_families(inventory: &ProfilePlanningInventory) -> Vec<ProfileLanguage> {
    let mut languages = inventory
        .build_units
        .iter()
        .map(|unit| unit.language)
        .chain(inventory.files.iter().filter_map(|file| match file.kind {
            ProfilePlanningFileKind::RustSource => Some(ProfileLanguage::Rust),
            ProfilePlanningFileKind::GoSource => Some(ProfileLanguage::Go),
            ProfilePlanningFileKind::WebSource | ProfilePlanningFileKind::FrameworkSource => {
                Some(ProfileLanguage::Web)
            }
            ProfilePlanningFileKind::SchemaSource | ProfilePlanningFileKind::GeneratedSource => {
                None
            }
        }))
        .collect::<Vec<_>>();
    languages.sort_by(|left, right| left.as_str().as_bytes().cmp(right.as_str().as_bytes()));
    languages.dedup();
    languages
}

pub fn bound_profile_candidate_discovery(
    profiles: Vec<ProfileSelectionProfile>,
    candidates: Vec<ProfileCandidateRecord>,
    language_families: &[ProfileLanguage],
) -> Result<ProfileCandidateDiscoveryResult> {
    let mut languages = language_families.to_vec();
    languages.sort_by(|left, right| left.as_str().as_bytes().cmp(right.as_str().as_bytes()));
    languages.dedup();
    if languages.len() != language_families.len() {
        bail!("candidate discovery language_families must be canonical and unique");
    }

    let profiles = canonical_profiles(profiles)?;
    let profile_by_id = profiles
        .iter()
        .map(|profile| (profile.id.as_str(), profile))
        .collect::<BTreeMap<_, _>>();
    let candidates = canonical_candidates(candidates, &profile_by_id)?;
    if profiles.len() != candidates.len()
        || profiles.iter().any(|profile| {
            !candidates
                .iter()
                .any(|candidate| candidate.profile_id == profile.id)
        })
    {
        bail!("bounded candidate discovery requires one candidate per profile");
    }

    let mut retained = Vec::with_capacity(candidates.len());
    let mut discovered = languages
        .iter()
        .map(|language| (*language, 0_u32))
        .collect::<BTreeMap<_, _>>();
    let mut overflow = languages
        .iter()
        .map(|language| (*language, 0_u32))
        .collect::<BTreeMap<_, _>>();
    let mut retained_alternatives = 0_u32;

    for candidate in candidates {
        let profile = profile_by_id[candidate.profile_id.as_str()];
        let language = profile.axes.language();
        if !languages.contains(&language) {
            bail!("candidate language is not present in language_families");
        }
        if candidate.kind == ProfileCandidateKind::Baseline {
            retained.push(candidate);
            continue;
        }
        let language_count = discovered
            .get_mut(&language)
            .context("candidate discovery language")?;
        if *language_count < MAX_AUTOMATIC_PROFILE_CANDIDATES_PER_LANGUAGE
            && retained_alternatives < MAX_AUTOMATIC_PROFILE_CANDIDATES
        {
            *language_count += 1;
            retained_alternatives += 1;
            retained.push(candidate);
        } else {
            let count = overflow
                .get_mut(&language)
                .context("candidate overflow language")?;
            *count = count
                .checked_add(1)
                .context("candidate overflow count exceeds u32")?;
        }
    }

    let retained_profile_ids = retained
        .iter()
        .map(|candidate| candidate.profile_id.as_str())
        .collect::<BTreeSet<_>>();
    let profiles = profiles
        .into_iter()
        .filter(|profile| retained_profile_ids.contains(profile.id.as_str()))
        .collect::<Vec<_>>();
    let discovery = languages
        .into_iter()
        .map(|language| {
            let overflow_candidate_count = overflow[&language];
            ProfileDiscoveryLedger {
                language,
                discovered_candidate_count: discovered[&language],
                overflow_candidate_count,
                complete: overflow_candidate_count == 0,
                reason: (overflow_candidate_count > 0)
                    .then_some(CandidateDiscoveryReason::DefaultProfileCandidateLimitExceeded),
            }
        })
        .collect::<Vec<_>>();
    let complete = discovery.iter().all(|entry| entry.complete);
    Ok(ProfileCandidateDiscoveryResult {
        profiles,
        candidates: retained,
        discovery,
        complete,
    })
}

const fn classify_repository_size(
    relevant_source_files: u64,
    build_units: u64,
) -> RepositorySizeClass {
    if relevant_source_files <= TINY_SOURCE_FILE_THRESHOLD
        && build_units <= TINY_BUILD_UNIT_THRESHOLD
    {
        RepositorySizeClass::Tiny
    } else if relevant_source_files <= SMALL_SOURCE_FILE_THRESHOLD
        && build_units <= SMALL_BUILD_UNIT_THRESHOLD
    {
        RepositorySizeClass::Small
    } else if relevant_source_files <= MEDIUM_SOURCE_FILE_THRESHOLD
        && build_units <= MEDIUM_BUILD_UNIT_THRESHOLD
    {
        RepositorySizeClass::Medium
    } else {
        RepositorySizeClass::Large
    }
}

fn canonical_profiles(
    mut profiles: Vec<ProfileSelectionProfile>,
) -> Result<Vec<ProfileSelectionProfile>> {
    profiles.sort_by(|left, right| left.id.as_bytes().cmp(right.id.as_bytes()));
    let mut canonical: Vec<ProfileSelectionProfile> = Vec::with_capacity(profiles.len());
    for profile in profiles {
        if profile.id != canonical_profile_id(&profile.axes) {
            bail!("candidate discovery profile id is not canonical");
        }
        if let Some(previous) = canonical.last()
            && previous.id == profile.id
        {
            if previous != &profile {
                bail!("duplicate profile id has conflicting axes");
            }
            continue;
        }
        canonical.push(profile);
    }
    Ok(canonical)
}

fn canonical_candidates(
    mut candidates: Vec<ProfileCandidateRecord>,
    profiles: &BTreeMap<&str, &ProfileSelectionProfile>,
) -> Result<Vec<ProfileCandidateRecord>> {
    candidates.sort_by(|left, right| left.profile_id.as_bytes().cmp(right.profile_id.as_bytes()));
    let mut canonical: Vec<ProfileCandidateRecord> = Vec::with_capacity(candidates.len());
    for mut candidate in candidates {
        if !profiles.contains_key(candidate.profile_id.as_str())
            || candidate.id != profile_candidate_id(&candidate)
        {
            bail!("candidate discovery candidate or profile identity is invalid");
        }
        canonicalize_candidate_evidence(&mut candidate);
        if let Some(previous) = canonical.last_mut()
            && previous.profile_id == candidate.profile_id
        {
            if previous.id != candidate.id
                || previous.baseline_profile_id != candidate.baseline_profile_id
                || previous.kind != candidate.kind
                || previous.changed_axis != candidate.changed_axis
                || previous.axis_values != candidate.axis_values
            {
                bail!("duplicate candidate profile has conflicting canonical identity");
            }
            previous
                .estimated_coverage
                .file_ids
                .extend(candidate.estimated_coverage.file_ids);
            previous
                .estimated_coverage
                .dependency_site_ids
                .extend(candidate.estimated_coverage.dependency_site_ids);
            previous.evidence.extend(candidate.evidence);
            canonicalize_candidate_evidence(previous);
            continue;
        }
        canonical.push(candidate);
    }
    Ok(canonical)
}

fn canonicalize_candidate_evidence(candidate: &mut ProfileCandidateRecord) {
    candidate
        .estimated_coverage
        .file_ids
        .sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    candidate.estimated_coverage.file_ids.dedup();
    candidate
        .estimated_coverage
        .dependency_site_ids
        .sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    candidate.estimated_coverage.dependency_site_ids.dedup();
    candidate.evidence.sort_by_key(evidence_key);
    candidate.evidence.dedup();
}

fn evidence_key(evidence: &ProfileCandidateEvidence) -> (String, u32, u32, String) {
    (
        evidence.path.clone(),
        evidence.start_line,
        evidence.end_line,
        serde_json::to_value(evidence.kind)
            .expect("evidence kind serialization cannot fail")
            .as_str()
            .expect("evidence kind serializes as a string")
            .to_owned(),
    )
}

const fn host_language(host: &ProfileHostContext) -> ProfileLanguage {
    match host {
        ProfileHostContext::Rust(_) => ProfileLanguage::Rust,
        ProfileHostContext::Go(_) => ProfileLanguage::Go,
    }
}

const fn axis_is_supported(language: ProfileLanguage, axis: ProfileAxis) -> bool {
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

fn validate_repository_path(name: &str, path: &str) -> Result<()> {
    validate_bounded_text(name, path, MAX_INVENTORY_PATH_CHARS)?;
    if path.starts_with('/')
        || path.starts_with('\\')
        || path.contains('\\')
        || path.contains(':')
        || path
            .split('/')
            .any(|component| component.is_empty() || matches!(component, "." | ".."))
    {
        bail!("{name} must be a confined repository-relative path");
    }
    Ok(())
}

fn validate_portable_build_unit_name(name: &str) -> Result<()> {
    validate_bounded_text("planning build-unit name", name, MAX_BUILD_UNIT_NAME_CHARS)?;
    if name.starts_with('/')
        || name.starts_with('\\')
        || name.contains('\\')
        || name.contains(':')
        || name
            .split('/')
            .any(|component| component.is_empty() || matches!(component, "." | ".."))
    {
        bail!("planning build-unit name must be a portable canonical locator");
    }
    Ok(())
}

fn validate_portable_axis_value(name: &str, value: &str) -> Result<()> {
    validate_bounded_text(name, value, 256)?;
    if value.contains('/') || value.contains('\\') || value.chars().any(char::is_whitespace) {
        bail!("{name} must not contain a filesystem path or whitespace");
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

fn validate_sha256(name: &str, value: &str) -> Result<()> {
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

#[cfg(test)]
mod tests {
    use depgraph_protocol::stable_id_from_value;

    use crate::{
        CanonicalProfileAxes, GoCallGraph, GoProfileAxes, ProfileCandidateCoverage,
        ProfileCandidateEvidenceKind, RustHostContext, RustProfileAxes, RustProfileMode,
        WebEnvironment, WebProfileAxes, WebProfileMode, profile_selection_input_digest,
    };

    use super::*;

    fn digest(byte: char) -> String {
        format!("sha256:{}", byte.to_string().repeat(64))
    }

    fn file(path: &str, kind: ProfilePlanningFileKind, byte: char) -> ProfilePlanningFile {
        ProfilePlanningFile {
            path: path.to_owned(),
            kind,
            content_digest: digest(byte),
        }
    }

    fn unit(
        language: ProfileLanguage,
        kind: ProfilePlanningBuildUnitKind,
        name: &str,
        path: &str,
    ) -> ProfilePlanningBuildUnit {
        ProfilePlanningBuildUnit {
            id: profile_planning_build_unit_id(language, kind, name, path),
            language,
            kind,
            name: name.to_owned(),
            evidence_path: path.to_owned(),
        }
    }

    fn inventory(files: u64, units: u64) -> ProfilePlanningInventory {
        ProfilePlanningInventory {
            inventory_version: PROFILE_SELECTION_INVENTORY_VERSION.to_owned(),
            files: (0..files)
                .map(|index| {
                    file(
                        &format!("src/f{index:06}.rs"),
                        ProfilePlanningFileKind::RustSource,
                        'a',
                    )
                })
                .collect(),
            build_units: (0..units)
                .map(|index| {
                    unit(
                        ProfileLanguage::Rust,
                        ProfilePlanningBuildUnitKind::RustPackageTarget,
                        &format!("crate-{index:04}"),
                        &format!("crates/c{index:04}/Cargo.toml"),
                    )
                })
                .collect(),
        }
    }

    #[test]
    fn repository_size_requires_both_thresholds_and_caps_are_exact() -> Result<()> {
        let cases = [
            (1_000, 25, RepositorySizeClass::Tiny, 16),
            (1_001, 25, RepositorySizeClass::Small, 10),
            (1_000, 26, RepositorySizeClass::Small, 10),
            (10_000, 100, RepositorySizeClass::Small, 10),
            (10_001, 100, RepositorySizeClass::Medium, 6),
            (10_000, 101, RepositorySizeClass::Medium, 6),
            (50_000, 500, RepositorySizeClass::Medium, 6),
            (50_001, 500, RepositorySizeClass::Large, 4),
            (50_000, 501, RepositorySizeClass::Large, 4),
        ];
        for (files, units, expected_class, expected_cap) in cases {
            let repository = classify_profile_selection_repository(&inventory(files, units))?;
            assert_eq!(repository.size_class, expected_class);
            assert_eq!(
                default_profile_selection_limits(expected_class).effective_profile_cap,
                expected_cap
            );
        }
        Ok(())
    }

    #[test]
    fn inventory_digest_is_order_and_checkout_independent_but_content_bound() -> Result<()> {
        let mut first = ProfilePlanningInventory {
            inventory_version: PROFILE_SELECTION_INVENTORY_VERSION.to_owned(),
            files: vec![
                file("src/lib.rs", ProfilePlanningFileKind::RustSource, '1'),
                file("web/app.ts", ProfilePlanningFileKind::WebSource, '2'),
            ],
            build_units: vec![
                unit(
                    ProfileLanguage::Web,
                    ProfilePlanningBuildUnitKind::WebWorkspacePackage,
                    "web",
                    "web/package.json",
                ),
                unit(
                    ProfileLanguage::Rust,
                    ProfilePlanningBuildUnitKind::RustPackageTarget,
                    "core/lib",
                    "Cargo.toml",
                ),
            ],
        };
        let mut reordered = first.clone();
        reordered.files.reverse();
        reordered.build_units.reverse();
        reordered.files.push(reordered.files[0].clone());
        assert_eq!(
            profile_selection_inventory_digest(&first)?,
            profile_selection_inventory_digest(&reordered)?
        );
        assert_eq!(
            classify_profile_selection_repository(&first)?,
            classify_profile_selection_repository(&reordered)?
        );

        first.files[0].content_digest = digest('3');
        assert_ne!(
            profile_selection_inventory_digest(&first)?,
            profile_selection_inventory_digest(&reordered)?
        );

        let mut absolute = reordered;
        absolute.files[0].path = "/tmp/checkout/src/lib.rs".to_owned();
        assert!(
            profile_selection_inventory_digest(&absolute)
                .unwrap_err()
                .to_string()
                .contains("repository-relative")
        );

        let mut absolute_unit = inventory(1, 1);
        absolute_unit.build_units[0].name = "/tmp/checkout/crate".to_owned();
        absolute_unit.build_units[0].id = profile_planning_build_unit_id(
            absolute_unit.build_units[0].language,
            absolute_unit.build_units[0].kind,
            &absolute_unit.build_units[0].name,
            &absolute_unit.build_units[0].evidence_path,
        );
        assert!(
            profile_selection_inventory_digest(&absolute_unit)
                .unwrap_err()
                .to_string()
                .contains("portable canonical locator")
        );
        Ok(())
    }

    #[test]
    fn input_builder_canonicalizes_order_and_binds_every_portable_context() -> Result<()> {
        let mut inventory = inventory(2, 1);
        inventory.files.push(file(
            "packages/web/src/index.ts",
            ProfilePlanningFileKind::WebSource,
            'b',
        ));
        inventory.build_units.push(unit(
            ProfileLanguage::Web,
            ProfilePlanningBuildUnitKind::WebWorkspacePackage,
            "web",
            "packages/web/package.json",
        ));
        let context = ProfileSelectionInputContext {
            compatibility_ids: vec![
                "rust-toolchain:1.93.1".to_owned(),
                "depgraph-protocol:1.0".to_owned(),
            ],
            language_families: vec![ProfileLanguage::Web, ProfileLanguage::Rust],
            host_contexts: vec![ProfileHostContext::Rust(RustHostContext {
                target: "aarch64-apple-darwin".to_owned(),
            })],
            configuration_digest: Some(digest('4')),
            selection_file_digest: None,
            supported_axes: vec![
                ProfileAxisCapability {
                    language: ProfileLanguage::Rust,
                    axis: ProfileAxis::Target,
                },
                ProfileAxisCapability {
                    language: ProfileLanguage::Web,
                    axis: ProfileAxis::Environment,
                },
            ],
        };
        let mut reordered = context.clone();
        reordered.compatibility_ids.reverse();
        reordered.language_families.reverse();
        reordered.supported_axes.reverse();
        let first = build_profile_selection_input(&inventory, context)?;
        let second = build_profile_selection_input(&inventory, reordered)?;
        assert_eq!(first, second);
        assert_eq!(
            profile_selection_input_digest(&first),
            profile_selection_input_digest(&second)
        );

        let mut drifted = first.clone();
        drifted.compatibility_ids[0] = "depgraph-protocol:1.1".to_owned();
        assert_ne!(
            profile_selection_input_digest(&first),
            profile_selection_input_digest(&drifted)
        );

        let unsafe_context = ProfileSelectionInputContext {
            compatibility_ids: vec!["tool:/tmp/checkout/bin".to_owned()],
            language_families: Vec::new(),
            host_contexts: Vec::new(),
            configuration_digest: None,
            selection_file_digest: None,
            supported_axes: Vec::new(),
        };
        assert!(
            build_profile_selection_input(&inventory, unsafe_context)
                .unwrap_err()
                .to_string()
                .contains("filesystem path")
        );
        Ok(())
    }

    #[test]
    fn input_builder_rejects_missing_or_fabricated_language_families() {
        let mut mixed_inventory = inventory(1, 1);
        mixed_inventory.build_units.push(unit(
            ProfileLanguage::Go,
            ProfilePlanningBuildUnitKind::GoPackageVariant,
            "go-worker",
            "workers/go/go.mod",
        ));
        let context = ProfileSelectionInputContext {
            compatibility_ids: vec!["depgraph-protocol:1.0".to_owned()],
            language_families: vec![ProfileLanguage::Rust],
            host_contexts: vec![ProfileHostContext::Rust(RustHostContext {
                target: "aarch64-apple-darwin".to_owned(),
            })],
            configuration_digest: None,
            selection_file_digest: None,
            supported_axes: Vec::new(),
        };
        assert!(
            build_profile_selection_input(&mixed_inventory, context.clone())
                .unwrap_err()
                .to_string()
                .contains("exactly match")
        );

        let rust_only = inventory(1, 1);
        let mut fabricated = context;
        fabricated.language_families.push(ProfileLanguage::Web);
        assert!(
            build_profile_selection_input(&rust_only, fabricated)
                .unwrap_err()
                .to_string()
                .contains("exactly match")
        );
    }

    #[test]
    fn per_language_overflow_is_canonical_bounded_and_never_complete() -> Result<()> {
        let (mut profiles, mut candidates) = rust_candidates(258);
        let first = bound_profile_candidate_discovery(
            profiles.clone(),
            candidates.clone(),
            &[ProfileLanguage::Rust],
        )?;
        profiles.reverse();
        candidates.reverse();
        let second =
            bound_profile_candidate_discovery(profiles, candidates, &[ProfileLanguage::Rust])?;
        assert_eq!(first, second);
        assert_eq!(first.profiles.len(), 257);
        assert_eq!(first.candidates.len(), 257);
        assert_eq!(first.discovery[0].discovered_candidate_count, 256);
        assert_eq!(first.discovery[0].overflow_candidate_count, 2);
        assert_eq!(
            first.discovery[0].reason,
            Some(CandidateDiscoveryReason::DefaultProfileCandidateLimitExceeded)
        );
        assert!(!first.complete);
        Ok(())
    }

    #[test]
    fn total_candidate_overflow_is_ledgered_after_per_language_admission() -> Result<()> {
        let (mut profiles, mut candidates) = rust_candidates(256);
        let (go_profiles, go_candidates) = go_candidates(256);
        profiles.extend(go_profiles);
        candidates.extend(go_candidates);
        let (web_profiles, web_candidates) = web_candidates(1);
        profiles.extend(web_profiles);
        candidates.extend(web_candidates);
        let result = bound_profile_candidate_discovery(
            profiles,
            candidates,
            &[
                ProfileLanguage::Go,
                ProfileLanguage::Rust,
                ProfileLanguage::Web,
            ],
        )?;
        assert_eq!(
            result
                .candidates
                .iter()
                .filter(|candidate| candidate.kind == ProfileCandidateKind::Alternative)
                .count(),
            512
        );
        assert_eq!(
            result
                .discovery
                .iter()
                .map(|entry| entry.overflow_candidate_count)
                .sum::<u32>(),
            1
        );
        assert!(!result.complete);
        Ok(())
    }

    fn rust_candidates(
        alternatives: u32,
    ) -> (Vec<ProfileSelectionProfile>, Vec<ProfileCandidateRecord>) {
        let baseline_axes = CanonicalProfileAxes::Rust(RustProfileAxes {
            target: "host".to_owned(),
            mode: RustProfileMode::Check,
            default_features: true,
            features: Vec::new(),
        });
        candidate_family(
            baseline_axes,
            alternatives,
            |index| {
                CanonicalProfileAxes::Rust(RustProfileAxes {
                    target: format!("target-{index:04}"),
                    mode: RustProfileMode::Check,
                    default_features: true,
                    features: Vec::new(),
                })
            },
            ProfileAxis::Target,
        )
    }

    fn go_candidates(
        alternatives: u32,
    ) -> (Vec<ProfileSelectionProfile>, Vec<ProfileCandidateRecord>) {
        let baseline_axes = CanonicalProfileAxes::Go(GoProfileAxes {
            goos: "darwin".to_owned(),
            goarch: "arm64".to_owned(),
            tags: Vec::new(),
            cgo_enabled: false,
            call_graph: GoCallGraph::RtaCha,
        });
        candidate_family(
            baseline_axes,
            alternatives,
            |index| {
                CanonicalProfileAxes::Go(GoProfileAxes {
                    goos: "linux".to_owned(),
                    goarch: format!("arch{index:04}"),
                    tags: Vec::new(),
                    cgo_enabled: false,
                    call_graph: GoCallGraph::RtaCha,
                })
            },
            ProfileAxis::Target,
        )
    }

    fn web_candidates(
        alternatives: u32,
    ) -> (Vec<ProfileSelectionProfile>, Vec<ProfileCandidateRecord>) {
        let baseline_axes = CanonicalProfileAxes::Web(WebProfileAxes {
            mode: WebProfileMode::Production,
            environments: vec![WebEnvironment::Browser, WebEnvironment::Server],
        });
        candidate_family(
            baseline_axes,
            alternatives,
            |index| {
                CanonicalProfileAxes::Web(WebProfileAxes {
                    mode: if index % 2 == 0 {
                        WebProfileMode::Development
                    } else {
                        WebProfileMode::Test
                    },
                    environments: vec![WebEnvironment::Browser, WebEnvironment::Server],
                })
            },
            ProfileAxis::Mode,
        )
    }

    fn candidate_family<F>(
        baseline_axes: CanonicalProfileAxes,
        alternatives: u32,
        axes: F,
        changed_axis: ProfileAxis,
    ) -> (Vec<ProfileSelectionProfile>, Vec<ProfileCandidateRecord>)
    where
        F: Fn(u32) -> CanonicalProfileAxes,
    {
        let baseline_profile = ProfileSelectionProfile {
            id: canonical_profile_id(&baseline_axes),
            axes: baseline_axes,
        };
        let baseline_candidate = candidate(
            &baseline_profile,
            &baseline_profile.id,
            ProfileCandidateKind::Baseline,
            None,
            Vec::new(),
            0,
        );
        let mut profiles = vec![baseline_profile.clone()];
        let mut candidates = vec![baseline_candidate];
        for index in 0..alternatives {
            let profile_axes = axes(index);
            let profile = ProfileSelectionProfile {
                id: canonical_profile_id(&profile_axes),
                axes: profile_axes,
            };
            let axis_values = match (&profile.axes, changed_axis) {
                (CanonicalProfileAxes::Rust(axes), ProfileAxis::Target) => {
                    vec![axes.target.clone()]
                }
                (CanonicalProfileAxes::Go(axes), ProfileAxis::Target) => {
                    vec![format!("{}/{}", axes.goos, axes.goarch)]
                }
                (CanonicalProfileAxes::Web(axes), ProfileAxis::Mode) => {
                    vec![
                        serde_json::to_value(axes.mode)
                            .unwrap()
                            .as_str()
                            .unwrap()
                            .to_owned(),
                    ]
                }
                _ => unreachable!(),
            };
            candidates.push(candidate(
                &profile,
                &baseline_profile.id,
                ProfileCandidateKind::Alternative,
                Some(changed_axis),
                axis_values,
                index + 1,
            ));
            profiles.push(profile);
        }
        (profiles, candidates)
    }

    fn candidate(
        profile: &ProfileSelectionProfile,
        baseline_profile_id: &str,
        kind: ProfileCandidateKind,
        changed_axis: Option<ProfileAxis>,
        axis_values: Vec<String>,
        index: u32,
    ) -> ProfileCandidateRecord {
        let mut candidate = ProfileCandidateRecord {
            id: String::new(),
            profile_id: profile.id.clone(),
            baseline_profile_id: baseline_profile_id.to_owned(),
            kind,
            changed_axis,
            axis_values,
            estimated_coverage: ProfileCandidateCoverage {
                file_ids: vec![stable_id_from_value("file", &json!({"index": index}))],
                dependency_site_ids: Vec::new(),
            },
            evidence: vec![ProfileCandidateEvidence {
                kind: ProfileCandidateEvidenceKind::Source,
                path: format!("src/profile-{index:04}.rs"),
                start_line: 1,
                end_line: 1,
            }],
        };
        candidate.id = profile_candidate_id(&candidate);
        candidate
    }
}
