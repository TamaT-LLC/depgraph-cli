//! Static discovery and planning for resumable repository analysis.
//!
//! This module is deliberately limited to reading the repository inventory
//! and manifest files.  It does not run package managers, compilers, build
//! scripts, or project code.  The resulting plan is the hand-off between
//! discovery and the execution/checkpoint layers.

use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fs::{self, File},
    io::{BufReader, Read},
    path::{Component, Path},
};

use anyhow::{Context, Result, bail};
use depgraph_protocol::{canonical_json, stable_id_from_value};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::{config::Config, repository_inventory::build_repository_file_inventory};

pub const ANALYSIS_PLAN_CONTRACT_VERSION: &str = "depgraph-analysis-plan-v1";
pub const ANALYSIS_UNIT_WORKER_CONTRACT_VERSION: &str = "depgraph-analysis-unit-v1";
pub const REPOSITORY_ROOT: &str = ".";

const MAX_PLAN_UNITS: usize = 100_000;
const MAX_PLAN_EDGES: usize = 500_000;
const MAX_PLAN_PATH_CHARS: usize = 4_096;
const MAX_PLAN_STRING_CHARS: usize = 4_096;
const MAX_MANIFEST_BYTES: usize = 16 * 1024 * 1024;
const MAX_IMPORTS_PER_FILE: usize = 4_096;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisAdapter {
    Rust,
    Go,
    Web,
}

impl AnalysisAdapter {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Rust => "rust",
            Self::Go => "go",
            Self::Web => "web",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisUnitRole {
    Executable,
    Context,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisUnitKind {
    RepositoryAdapter,
    RustWorkspace,
    RustPackage,
    GoWorkspace,
    GoModule,
    GoPackage,
    WebWorkspace,
    WebProject,
}

impl AnalysisUnitKind {
    const fn scope(self) -> AnalysisScope {
        match self {
            Self::RepositoryAdapter => AnalysisScope::Repository,
            Self::RustWorkspace | Self::GoWorkspace | Self::WebWorkspace => {
                AnalysisScope::Workspace
            }
            Self::RustPackage | Self::GoPackage => AnalysisScope::Package,
            Self::GoModule => AnalysisScope::Module,
            Self::WebProject => AnalysisScope::Project,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisScope {
    Repository,
    Workspace,
    Module,
    Project,
    Package,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisDependencyKind {
    WorkspaceMember,
    LocalPath,
    ManifestDependency,
    SourceImport,
    Context,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisDependencyResolution {
    Resolved,
    External,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AnalysisDependencyReference {
    pub target_unit_id: Option<String>,
    pub specifier: String,
    pub kind: AnalysisDependencyKind,
    pub resolution: AnalysisDependencyResolution,
    pub evidence_path: Option<String>,
}

impl AnalysisDependencyReference {
    fn sort_key(
        &self,
    ) -> (
        &str,
        &str,
        AnalysisDependencyKind,
        AnalysisDependencyResolution,
    ) {
        (
            self.target_unit_id.as_deref().unwrap_or(""),
            self.specifier.as_str(),
            self.kind,
            self.resolution,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AnalysisProfileScope {
    pub definition_ids: Vec<String>,
    pub scoped_ids: Vec<String>,
    pub fingerprint: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AnalysisInputFingerprints {
    pub source_fingerprint: String,
    pub manifest_fingerprint: String,
    pub config_fingerprint: String,
    pub profile_fingerprint: String,
    pub analyzer_fingerprint: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AnalysisPlanInput {
    pub profile_ids: Vec<String>,
    pub analyzer_fingerprint: String,
}

impl AnalysisPlanInput {
    pub fn new<I, P, A>(profile_ids: I, analyzer_fingerprint: A) -> Self
    where
        I: IntoIterator<Item = P>,
        P: Into<String>,
        A: Into<String>,
    {
        Self {
            profile_ids: profile_ids.into_iter().map(Into::into).collect(),
            analyzer_fingerprint: analyzer_fingerprint.into(),
        }
    }

    fn canonicalized(&self) -> Result<Self> {
        let mut profile_ids = self.profile_ids.clone();
        for profile_id in &profile_ids {
            validate_bounded_string("analysis profile id", profile_id, MAX_PLAN_STRING_CHARS)?;
        }
        profile_ids.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
        profile_ids.dedup();
        validate_bounded_string(
            "analysis analyzer fingerprint",
            &self.analyzer_fingerprint,
            MAX_PLAN_STRING_CHARS,
        )?;
        Ok(Self {
            profile_ids,
            analyzer_fingerprint: self.analyzer_fingerprint.clone(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AnalysisUnit {
    pub id: String,
    pub adapter: AnalysisAdapter,
    pub role: AnalysisUnitRole,
    pub kind: AnalysisUnitKind,
    pub locator: String,
    pub unit_root: String,
    pub manifest_paths: Vec<String>,
    pub source_paths: Vec<String>,
    pub config_paths: Vec<String>,
    pub profile_scope: AnalysisProfileScope,
    pub source_fingerprint: String,
    pub manifest_fingerprint: String,
    pub config_fingerprint: String,
    pub profile_fingerprint: String,
    pub analyzer_fingerprint: String,
    pub dependency_fingerprint: String,
    pub input_fingerprint: String,
    pub dependency_ids: Vec<String>,
    pub dependent_ids: Vec<String>,
    pub dependency_references: Vec<AnalysisDependencyReference>,
    pub unknown_dependencies: bool,
}

impl AnalysisUnit {
    pub fn is_executable(&self) -> bool {
        self.role == AnalysisUnitRole::Executable
    }

    pub fn source_scope(&self) -> AnalysisScope {
        self.kind.scope()
    }

    pub fn unit_id(&self) -> &str {
        &self.id
    }

    pub fn input_digest(&self) -> &str {
        &self.input_fingerprint
    }

    pub fn dependencies(&self) -> &[String] {
        &self.dependency_ids
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AnalysisDependencyGroup {
    pub id: String,
    pub unit_ids: Vec<String>,
    pub outgoing_group_ids: Vec<String>,
    pub cyclic: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisPlanLimitation {
    StaticDiscoveryOnly,
    PackageManagersNotExecuted,
    ProjectCodeNotExecuted,
    DynamicDependenciesMayBeUnknown,
    RustUsesWholeAdapterFallback,
    ProfilesReplicatedPerUnitUntilWorkerNegotiation,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AnalysisPlan {
    pub contract_version: String,
    pub repository_root: String,
    pub repository_identity: String,
    pub inventory_digest: String,
    pub fingerprints: AnalysisInputFingerprints,
    pub input_fingerprint: String,
    pub plan_id: String,
    pub input_digest: String,
    pub units: Vec<AnalysisUnit>,
    pub dependency_groups: Vec<AnalysisDependencyGroup>,
    pub limitations: Vec<AnalysisPlanLimitation>,
}

impl AnalysisPlan {
    pub fn canonicalize(&self) -> Result<Self> {
        canonicalize_plan(self.clone())
    }

    pub fn digest(&self) -> Result<String> {
        let canonical = self.canonicalize()?;
        Ok(sha256_digest(canonical_json(&serde_json::to_value(
            canonical,
        )?)))
    }

    pub fn executable_units(&self) -> Vec<&AnalysisUnit> {
        self.units
            .iter()
            .filter(|unit| unit.is_executable())
            .collect()
    }

    pub fn unit(&self, id: &str) -> Option<&AnalysisUnit> {
        self.units.iter().find(|unit| unit.id == id)
    }

    pub fn input_digest(&self) -> &str {
        &self.input_digest
    }

    pub fn plan_id(&self) -> &str {
        &self.plan_id
    }

    pub fn invalidation_from(&self, previous: &AnalysisPlan) -> Result<AnalysisInvalidationPlan> {
        let current = self.canonicalize()?;
        let previous = previous.canonicalize()?;
        if current.contract_version != previous.contract_version {
            bail!("cannot compare analysis plans from different contracts");
        }
        if current.repository_identity != previous.repository_identity {
            bail!("cannot compare analysis plans from different repository identities");
        }

        let current_by_id = current
            .units
            .iter()
            .map(|unit| (unit.id.as_str(), unit))
            .collect::<BTreeMap<_, _>>();
        let previous_by_id = previous
            .units
            .iter()
            .map(|unit| (unit.id.as_str(), unit))
            .collect::<BTreeMap<_, _>>();
        let mut reasons = BTreeMap::<String, BTreeSet<AnalysisInvalidationReason>>::new();
        let mut seeds = BTreeSet::new();

        for unit in &current.units {
            let Some(old) = previous_by_id.get(unit.id.as_str()) else {
                reasons
                    .entry(unit.id.clone())
                    .or_default()
                    .insert(AnalysisInvalidationReason::Added);
                seeds.insert(unit.id.clone());
                continue;
            };
            let mut direct = BTreeSet::new();
            if unit.source_fingerprint != old.source_fingerprint {
                direct.insert(AnalysisInvalidationReason::SourceChanged);
            }
            if unit.manifest_fingerprint != old.manifest_fingerprint {
                direct.insert(AnalysisInvalidationReason::ManifestChanged);
            }
            if unit.config_fingerprint != old.config_fingerprint {
                direct.insert(AnalysisInvalidationReason::ConfigChanged);
            }
            if unit.profile_fingerprint != old.profile_fingerprint {
                direct.insert(AnalysisInvalidationReason::ProfileChanged);
            }
            if unit.analyzer_fingerprint != old.analyzer_fingerprint {
                direct.insert(AnalysisInvalidationReason::AnalyzerChanged);
            }
            if unit.dependency_references != old.dependency_references
                || unit.dependency_ids != old.dependency_ids
            {
                direct.insert(AnalysisInvalidationReason::DependencyChanged);
            }
            if unit.unknown_dependencies || old.unknown_dependencies {
                direct.insert(AnalysisInvalidationReason::UnknownDependency);
            }
            if !direct.is_empty() {
                reasons.entry(unit.id.clone()).or_default().extend(direct);
                seeds.insert(unit.id.clone());
            }
        }

        let removed_ids = previous_by_id
            .keys()
            .filter(|id| !current_by_id.contains_key(**id))
            .map(|id| (*id).to_owned())
            .collect::<BTreeSet<_>>();
        seeds.extend(removed_ids.iter().cloned());

        let mut changed_adapters = current
            .units
            .iter()
            .filter(|unit| seeds.contains(&unit.id))
            .map(|unit| unit.adapter)
            .collect::<BTreeSet<_>>();
        changed_adapters.extend(
            previous
                .units
                .iter()
                .filter(|unit| seeds.contains(&unit.id))
                .map(|unit| unit.adapter),
        );
        for unit in &current.units {
            if unit.unknown_dependencies && changed_adapters.contains(&unit.adapter) {
                reasons
                    .entry(unit.id.clone())
                    .or_default()
                    .insert(AnalysisInvalidationReason::UnknownDependency);
                seeds.insert(unit.id.clone());
            }
        }

        let mut current_dependents = BTreeMap::<String, Vec<String>>::new();
        for unit in &current.units {
            for dependency_id in &unit.dependency_ids {
                current_dependents
                    .entry(dependency_id.clone())
                    .or_default()
                    .push(unit.id.clone());
            }
        }
        for dependents in current_dependents.values_mut() {
            dependents.sort();
            dependents.dedup();
        }

        let mut queue = VecDeque::from_iter(seeds.iter().cloned());
        let mut visited = seeds;
        while let Some(changed_id) = queue.pop_front() {
            for dependent_id in current_dependents.get(&changed_id).into_iter().flatten() {
                let entry = reasons.entry(dependent_id.clone()).or_default();
                if entry.insert(AnalysisInvalidationReason::DependencyChanged)
                    && visited.insert(dependent_id.clone())
                {
                    queue.push_back(dependent_id.clone());
                }
            }
        }
        for removed in &removed_ids {
            for old_unit in &previous.units {
                if old_unit.dependency_ids.iter().any(|id| id == removed)
                    && let Some(current_unit) = current_by_id.get(old_unit.id.as_str())
                {
                    let entry = reasons.entry(current_unit.id.clone()).or_default();
                    if entry.insert(AnalysisInvalidationReason::DependencyChanged)
                        && visited.insert(current_unit.id.clone())
                    {
                        queue.push_back(current_unit.id.clone());
                    }
                }
            }
        }
        while let Some(changed_id) = queue.pop_front() {
            for dependent_id in current_dependents.get(&changed_id).into_iter().flatten() {
                let entry = reasons.entry(dependent_id.clone()).or_default();
                if entry.insert(AnalysisInvalidationReason::DependencyChanged)
                    && visited.insert(dependent_id.clone())
                {
                    queue.push_back(dependent_id.clone());
                }
            }
        }

        let entries = reasons
            .into_iter()
            .map(|(unit_id, reasons)| AnalysisInvalidationEntry {
                unit_id,
                reasons: reasons.into_iter().collect(),
            })
            .collect::<Vec<_>>();
        Ok(AnalysisInvalidationPlan {
            contract_version: ANALYSIS_PLAN_CONTRACT_VERSION.to_owned(),
            previous_plan_digest: previous.digest()?,
            current_plan_digest: current.digest()?,
            invalidated_unit_ids: entries.iter().map(|entry| entry.unit_id.clone()).collect(),
            removed_unit_ids: removed_ids.into_iter().collect(),
            entries,
        })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisInvalidationReason {
    Added,
    Removed,
    SourceChanged,
    ManifestChanged,
    ConfigChanged,
    ProfileChanged,
    AnalyzerChanged,
    DependencyChanged,
    UnknownDependency,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AnalysisInvalidationEntry {
    pub unit_id: String,
    pub reasons: Vec<AnalysisInvalidationReason>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AnalysisInvalidationPlan {
    pub contract_version: String,
    pub previous_plan_digest: String,
    pub current_plan_digest: String,
    pub invalidated_unit_ids: Vec<String>,
    pub removed_unit_ids: Vec<String>,
    pub entries: Vec<AnalysisInvalidationEntry>,
}

/// Discover a plan rooted at root.
///
/// The invocation path and Store path are deliberately absent from the plan.
/// The existing repository inventory excludes generated state such as the
/// depgraph state directory, and a Store/checkpoint write must never invalidate
/// source analysis. The config and input are the complete non-filesystem inputs.
pub fn discover_analysis_plan(
    root: &Path,
    config: &Config,
    input: &AnalysisPlanInput,
) -> Result<AnalysisPlan> {
    discover_analysis_plan_with_exclusions(root, config, input, &BTreeSet::new())
}

fn discover_analysis_plan_with_exclusions(
    root: &Path,
    config: &Config,
    input: &AnalysisPlanInput,
    excluded_paths: &BTreeSet<String>,
) -> Result<AnalysisPlan> {
    let canonical_root = root
        .canonicalize()
        .context("analysis plan repository root is unavailable")?;
    if !canonical_root.is_dir() {
        bail!("analysis plan repository root must be a directory");
    }
    let input = input.canonicalized()?;
    let inventory = build_repository_file_inventory(&canonical_root)?;
    let mut files = BTreeMap::<String, FileKind>::new();
    for path in inventory.paths {
        if excluded_paths.contains(&path) {
            continue;
        }
        let kind = classify_file(&path);
        if kind != FileKind::Other {
            files.insert(path, kind);
        }
    }
    let mut digests = BTreeMap::new();
    for path in files.keys() {
        digests.insert(path.clone(), hash_repository_file(&canonical_root, path)?);
    }

    let manifest_paths = files
        .iter()
        .filter(|(_, kind)| kind.is_manifest())
        .map(|(path, _)| path.clone())
        .collect::<Vec<_>>();
    let parsed = parse_manifests(&canonical_root, &manifest_paths)?;
    let mut units = build_drafts(&files, &parsed)
        .into_iter()
        .map(UnitDraft::into_unit)
        .collect::<Vec<_>>();
    if units.len() > MAX_PLAN_UNITS {
        bail!("analysis plan exceeds its closed unit limit");
    }
    attach_active_go_workspace_manifests(&mut units, &parsed);
    let active_go_workspace_member_ids = active_go_workspace_member_ids(&units, &parsed);

    let manifest_to_package_id = units
        .iter()
        .filter(|unit| unit.kind == AnalysisUnitKind::RustPackage)
        .flat_map(|unit| {
            unit.manifest_paths
                .iter()
                .map(|path| (path.clone(), unit.id.clone()))
        })
        .collect::<BTreeMap<_, _>>();
    let manifest_to_go_module_id = units
        .iter()
        .filter(|unit| unit.kind == AnalysisUnitKind::GoModule)
        .flat_map(|unit| {
            unit.manifest_paths
                .iter()
                .filter(|path| path.ends_with("go.mod"))
                .map(|path| (path.clone(), unit.id.clone()))
        })
        .collect::<BTreeMap<_, _>>();
    let go_replacements_by_module = go_replacements_by_module(&parsed, &manifest_to_go_module_id);
    let web_name_to_project_ids = web_name_index(&units);
    let package_root_index = package_root_index(&units);

    let mut references = units
        .iter()
        .map(|unit| (unit.id.clone(), Vec::new()))
        .collect::<BTreeMap<String, Vec<AnalysisDependencyReference>>>();
    for manifest in &parsed {
        let Some(owner_id) = find_manifest_owner(manifest, &units) else {
            continue;
        };
        let go_resolution = GoResolutionContext {
            replacements: go_replacements_by_module
                .get(&owner_id)
                .map(Vec::as_slice)
                .unwrap_or_default(),
            active_workspace_member_ids: active_go_workspace_member_ids.as_ref(),
        };
        for raw in &manifest.dependencies {
            references
                .entry(owner_id.clone())
                .or_default()
                .push(resolve_manifest_dependency(
                    raw,
                    manifest,
                    &units,
                    &manifest_to_package_id,
                    &manifest_to_go_module_id,
                    &web_name_to_project_ids,
                    &go_resolution,
                ));
        }
        for member in &manifest.workspace_members {
            let Some(workspace_owner_id) = find_workspace_owner(manifest, &units) else {
                continue;
            };
            references
                .entry(workspace_owner_id)
                .or_default()
                .push(resolve_workspace_member(
                    member,
                    manifest,
                    &units,
                    &manifest_to_package_id,
                    &manifest_to_go_module_id,
                ));
        }
    }
    add_context_edges(&units, &mut references);
    add_static_source_imports(
        &canonical_root,
        &files,
        &mut units,
        &package_root_index,
        &mut references,
        &go_replacements_by_module,
        active_go_workspace_member_ids.as_ref(),
    )?;
    if parsed.iter().any(|manifest| {
        manifest.adapter == AnalysisAdapter::Go
            && manifest.workspace
            && manifest.path == "go.work"
            && go_workspace_has_nonportable_paths(manifest)
    }) {
        add_unknown_go_workspace_dependencies(&units, &mut references);
    }

    let source_paths = files
        .iter()
        .filter(|(_, kind)| kind.is_source())
        .map(|(path, _)| path.clone())
        .collect::<Vec<_>>();
    let config_paths = files
        .iter()
        .filter(|(_, kind)| kind.is_config())
        .map(|(path, _)| path.clone())
        .collect::<Vec<_>>();
    let (fingerprints, input_fingerprint) = global_fingerprints(
        &files,
        &digests,
        config,
        &input,
        &source_paths,
        &manifest_paths,
        &config_paths,
    )?;
    finalize_units(
        &mut units,
        references,
        &files,
        &digests,
        &input,
        &fingerprints,
    )?;
    let dependency_groups = dependency_groups(&units)?;
    let mut limitations = BTreeSet::from([
        AnalysisPlanLimitation::StaticDiscoveryOnly,
        AnalysisPlanLimitation::PackageManagersNotExecuted,
        AnalysisPlanLimitation::ProjectCodeNotExecuted,
        AnalysisPlanLimitation::DynamicDependenciesMayBeUnknown,
        AnalysisPlanLimitation::ProfilesReplicatedPerUnitUntilWorkerNegotiation,
    ]);
    if units
        .iter()
        .any(|unit| unit.adapter == AnalysisAdapter::Rust && unit.is_executable())
    {
        limitations.insert(AnalysisPlanLimitation::RustUsesWholeAdapterFallback);
    }
    let inventory_digest = inventory_digest(&files);
    let repository_identity = repository_identity(&canonical_root);
    let plan = AnalysisPlan {
        contract_version: ANALYSIS_PLAN_CONTRACT_VERSION.to_owned(),
        repository_root: REPOSITORY_ROOT.to_owned(),
        repository_identity,
        inventory_digest,
        fingerprints,
        input_fingerprint,
        plan_id: String::new(),
        input_digest: String::new(),
        units,
        dependency_groups,
        limitations: limitations.into_iter().collect(),
    };
    let mut plan = plan;
    plan.input_digest = plan.input_fingerprint.clone();
    plan.units.sort_by(|left, right| left.id.cmp(&right.id));
    plan.dependency_groups
        .sort_by(|left, right| left.id.cmp(&right.id));
    plan.limitations.sort();
    plan.plan_id = plan_id(&plan);
    plan.canonicalize()
}

/// Compatibility convenience for the scheduler. The store path is accepted
/// as an invocation binding but intentionally excluded from planning input.
pub fn plan_analysis_units(
    root: &Path,
    config: &Config,
    store_path: Option<&Path>,
) -> Result<AnalysisPlan> {
    let canonical_root = root
        .canonicalize()
        .context("analysis plan repository root is unavailable")?;
    if !canonical_root.is_dir() {
        bail!("analysis plan repository root must be a directory");
    }
    let excluded_paths = store_exclusion_paths(&canonical_root, store_path);
    discover_analysis_plan_with_exclusions(
        root,
        config,
        &AnalysisPlanInput::new(std::iter::empty::<String>(), "depgraph-analysis-plan-v1"),
        &excluded_paths,
    )
}

fn store_exclusion_paths(root: &Path, store_path: Option<&Path>) -> BTreeSet<String> {
    let Some(store_path) = store_path else {
        return BTreeSet::new();
    };
    let candidate = if store_path.is_absolute() {
        store_path.to_path_buf()
    } else {
        root.join(store_path)
    };
    let mut relative_paths = BTreeSet::new();
    for candidate in [
        candidate.clone(),
        fs::canonicalize(&candidate).unwrap_or(candidate),
    ] {
        if let Some(relative) = lexical_repository_path(root, &candidate) {
            relative_paths.insert(relative);
        }
    }
    let mut excluded = BTreeSet::new();
    for relative in relative_paths {
        excluded.insert(relative.clone());
        excluded.insert(format!("{relative}-wal"));
        excluded.insert(format!("{relative}-shm"));
    }
    excluded
}

fn lexical_repository_path(root: &Path, candidate: &Path) -> Option<String> {
    let relative = candidate.strip_prefix(root).ok()?;
    let mut components = Vec::new();
    for component in relative.components() {
        match component {
            Component::Normal(value) => components.push(value.to_str()?.to_owned()),
            Component::CurDir => {}
            Component::ParentDir => {
                components.pop()?;
            }
            Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    if components.is_empty() {
        Some(REPOSITORY_ROOT.to_owned())
    } else {
        Some(components.join("/"))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FileKind {
    Other,
    RustSource,
    GoSource,
    WebSource,
    CargoManifest,
    GoManifest,
    GoWorkspace,
    WebManifest,
    Config,
}

impl FileKind {
    const fn is_source(self) -> bool {
        matches!(self, Self::RustSource | Self::GoSource | Self::WebSource)
    }

    const fn is_manifest(self) -> bool {
        matches!(
            self,
            Self::CargoManifest | Self::GoManifest | Self::GoWorkspace | Self::WebManifest
        )
    }

    const fn is_config(self) -> bool {
        matches!(self, Self::Config)
    }

    const fn adapter(self) -> Option<AnalysisAdapter> {
        match self {
            Self::RustSource | Self::CargoManifest => Some(AnalysisAdapter::Rust),
            Self::GoSource | Self::GoManifest | Self::GoWorkspace => Some(AnalysisAdapter::Go),
            Self::WebSource | Self::WebManifest => Some(AnalysisAdapter::Web),
            Self::Other | Self::Config => None,
        }
    }
}

fn classify_file(path: &str) -> FileKind {
    let name = path.rsplit('/').next().unwrap_or(path);
    match name {
        "Cargo.toml" => FileKind::CargoManifest,
        "go.mod" => FileKind::GoManifest,
        "go.work" => FileKind::GoWorkspace,
        "package.json" => FileKind::WebManifest,
        ".depgraph.toml"
        | ".npmrc"
        | ".pnpmfile.cjs"
        | ".pnpmfile.js"
        | ".pnp.cjs"
        | ".pnp.data.json"
        | ".yarnrc"
        | ".yarnrc.yml"
        | ".yarnrc.yaml"
        | "go.sum"
        | "go.work.sum"
        | "Cargo.lock"
        | "pnpm-lock.yaml"
        | "pnpm-workspace.yaml"
        | "pnpm-workspace.yml"
        | "package-lock.json"
        | "npm-shrinkwrap.json"
        | "yarn.lock"
        | "bun.lock"
        | "bun.lockb"
        | "tsconfig.json"
        | "jsconfig.json"
        | "lerna.json"
        | "nx.json"
        | "project.json"
        | "rush.json"
        | "turbo.json"
        | "workspace.json" => FileKind::Config,
        _ if name.starts_with("tsconfig.") || name.starts_with("jsconfig.") => FileKind::Config,
        _ if name.starts_with("next.config.")
            || name.starts_with("astro.config.")
            || name.starts_with("vite.config.")
            || name.starts_with("tanstack.config.")
            || name.starts_with("router.config.")
            || name.starts_with("webpack.config.")
            || name.starts_with("rollup.config.")
            || name.starts_with("svelte.config.")
            || name.starts_with("nuxt.config.")
            || name.starts_with("remix.config.")
            || name.starts_with("postcss.config.")
            || name.starts_with("tailwind.config.")
            || name.starts_with("babel.config.")
            || name.starts_with(".babelrc")
            || name == "app.config.ts"
            || name == "app.config.js" =>
        {
            FileKind::Config
        }
        _ if path.ends_with(".json")
            || path.ends_with(".jsonc")
            || path.ends_with(".yaml")
            || path.ends_with(".yml")
            || path.ends_with(".css")
            || path.ends_with(".scss")
            || path.ends_with(".sass")
            || path.ends_with(".less")
            || path.ends_with(".styl") =>
        {
            FileKind::Config
        }
        _ if path.ends_with(".rs") => FileKind::RustSource,
        _ if path.ends_with(".go") => FileKind::GoSource,
        _ if [
            ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".mts", ".cts", ".astro", ".vue",
            ".svelte", ".md", ".mdx", ".html",
        ]
        .iter()
        .any(|suffix| path.ends_with(suffix)) =>
        {
            FileKind::WebSource
        }
        _ => FileKind::Other,
    }
}

#[derive(Clone, Debug)]
struct RawDependency {
    specifier: String,
    version: Option<String>,
    kind: AnalysisDependencyKind,
    local_path: Option<String>,
    evidence_path: String,
    external_hint: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct GoReplacement {
    old_module: String,
    old_version: Option<String>,
    new_module: Option<String>,
    new_version: Option<String>,
    local_path: Option<String>,
    evidence_path: String,
}

type GoReplacementSortKey<'a> = (
    &'a str,
    Option<&'a str>,
    Option<&'a str>,
    Option<&'a str>,
    Option<&'a str>,
    &'a str,
);

struct GoResolutionContext<'a> {
    replacements: &'a [GoReplacement],
    active_workspace_member_ids: Option<&'a BTreeSet<String>>,
}

struct GoImportResolutionContext<'a> {
    replacements: &'a [GoReplacement],
    active_workspace_member_ids: Option<&'a BTreeSet<String>>,
    source_unit_id: &'a str,
}

#[derive(Clone, Debug)]
struct ParsedManifest {
    path: String,
    adapter: AnalysisAdapter,
    locator: String,
    dependencies: Vec<RawDependency>,
    go_replacements: Vec<GoReplacement>,
    workspace_members: Vec<String>,
    workspace: bool,
}

#[derive(Clone, Debug)]
struct UnitDraft {
    adapter: AnalysisAdapter,
    role: AnalysisUnitRole,
    kind: AnalysisUnitKind,
    locator: String,
    unit_root: String,
    manifest_paths: Vec<String>,
}

impl UnitDraft {
    fn into_unit(self) -> AnalysisUnit {
        let id = analysis_unit_id(self.adapter, self.kind, &self.unit_root, &self.locator);
        AnalysisUnit {
            id,
            adapter: self.adapter,
            role: self.role,
            kind: self.kind,
            locator: self.locator,
            unit_root: self.unit_root,
            manifest_paths: self.manifest_paths,
            source_paths: Vec::new(),
            config_paths: Vec::new(),
            profile_scope: AnalysisProfileScope {
                definition_ids: Vec::new(),
                scoped_ids: Vec::new(),
                fingerprint: sha256_digest("uninitialized-profile-scope"),
            },
            source_fingerprint: sha256_digest("uninitialized-source-fingerprint"),
            manifest_fingerprint: sha256_digest("uninitialized-manifest-fingerprint"),
            config_fingerprint: sha256_digest("uninitialized-config-fingerprint"),
            profile_fingerprint: sha256_digest("uninitialized-profile-fingerprint"),
            analyzer_fingerprint: sha256_digest("uninitialized-analyzer-fingerprint"),
            dependency_fingerprint: sha256_digest("uninitialized-dependency-fingerprint"),
            input_fingerprint: sha256_digest("uninitialized-input-fingerprint"),
            dependency_ids: Vec::new(),
            dependent_ids: Vec::new(),
            dependency_references: Vec::new(),
            unknown_dependencies: false,
        }
    }
}

fn build_drafts(files: &BTreeMap<String, FileKind>, parsed: &[ParsedManifest]) -> Vec<UnitDraft> {
    let mut drafts = BTreeMap::<String, UnitDraft>::new();
    let has_adapter = |adapter| files.values().any(|kind| kind.adapter() == Some(adapter));
    let mut add = |draft: UnitDraft| {
        let key = format!(
            "{}|{:?}|{}|{}",
            draft.adapter.as_str(),
            draft.kind,
            draft.unit_root,
            draft.locator
        );
        drafts.entry(key).or_insert(draft);
    };

    if has_adapter(AnalysisAdapter::Rust) {
        add(UnitDraft {
            adapter: AnalysisAdapter::Rust,
            role: AnalysisUnitRole::Executable,
            kind: AnalysisUnitKind::RepositoryAdapter,
            locator: "repository".to_owned(),
            unit_root: REPOSITORY_ROOT.to_owned(),
            manifest_paths: parsed
                .iter()
                .filter(|manifest| manifest.adapter == AnalysisAdapter::Rust)
                .map(|manifest| manifest.path.clone())
                .collect(),
        });
    }
    if has_adapter(AnalysisAdapter::Go)
        && !parsed.iter().any(|manifest| {
            manifest.adapter == AnalysisAdapter::Go && manifest.path.ends_with("go.mod")
        })
    {
        add(UnitDraft {
            adapter: AnalysisAdapter::Go,
            role: AnalysisUnitRole::Executable,
            kind: AnalysisUnitKind::RepositoryAdapter,
            locator: "repository".to_owned(),
            unit_root: REPOSITORY_ROOT.to_owned(),
            manifest_paths: Vec::new(),
        });
    }
    if has_adapter(AnalysisAdapter::Web)
        && !parsed.iter().any(|manifest| {
            manifest.adapter == AnalysisAdapter::Web && manifest.path.ends_with("package.json")
        })
    {
        add(UnitDraft {
            adapter: AnalysisAdapter::Web,
            role: AnalysisUnitRole::Executable,
            kind: AnalysisUnitKind::RepositoryAdapter,
            locator: "repository".to_owned(),
            unit_root: REPOSITORY_ROOT.to_owned(),
            manifest_paths: Vec::new(),
        });
    }

    for manifest in parsed {
        let root = manifest
            .path
            .rsplit_once('/')
            .map(|(parent, _)| parent.to_owned())
            .unwrap_or_else(|| REPOSITORY_ROOT.to_owned());
        match (
            manifest.adapter,
            manifest.path.rsplit('/').next().unwrap_or_default(),
        ) {
            (AnalysisAdapter::Rust, "Cargo.toml") => {
                if manifest.workspace {
                    add(UnitDraft {
                        adapter: AnalysisAdapter::Rust,
                        role: AnalysisUnitRole::Context,
                        kind: AnalysisUnitKind::RustWorkspace,
                        locator: if manifest.locator.is_empty() {
                            manifest.path.clone()
                        } else {
                            manifest.locator.clone()
                        },
                        unit_root: root.clone(),
                        manifest_paths: vec![manifest.path.clone()],
                    });
                }
                if !manifest.locator.is_empty() {
                    add(UnitDraft {
                        adapter: AnalysisAdapter::Rust,
                        role: AnalysisUnitRole::Context,
                        kind: AnalysisUnitKind::RustPackage,
                        locator: manifest.locator.clone(),
                        unit_root: root,
                        manifest_paths: vec![manifest.path.clone()],
                    });
                }
            }
            (AnalysisAdapter::Go, "go.mod") => add(UnitDraft {
                adapter: AnalysisAdapter::Go,
                role: AnalysisUnitRole::Executable,
                kind: AnalysisUnitKind::GoModule,
                locator: if manifest.locator.is_empty() {
                    manifest.path.clone()
                } else {
                    manifest.locator.clone()
                },
                unit_root: root,
                manifest_paths: vec![manifest.path.clone()],
            }),
            (AnalysisAdapter::Go, "go.work") => add(UnitDraft {
                adapter: AnalysisAdapter::Go,
                role: AnalysisUnitRole::Context,
                kind: AnalysisUnitKind::GoWorkspace,
                locator: manifest.path.clone(),
                unit_root: root,
                manifest_paths: vec![manifest.path.clone()],
            }),
            (AnalysisAdapter::Web, "package.json") => {
                if manifest.workspace {
                    add(UnitDraft {
                        adapter: AnalysisAdapter::Web,
                        role: AnalysisUnitRole::Context,
                        kind: AnalysisUnitKind::WebWorkspace,
                        locator: if manifest.locator.is_empty() {
                            manifest.path.clone()
                        } else {
                            manifest.locator.clone()
                        },
                        unit_root: root.clone(),
                        manifest_paths: vec![manifest.path.clone()],
                    });
                    if workspace_has_direct_web_sources(files, parsed, &manifest.path, &root) {
                        add(UnitDraft {
                            adapter: AnalysisAdapter::Web,
                            role: AnalysisUnitRole::Executable,
                            kind: AnalysisUnitKind::WebProject,
                            locator: if manifest.locator.is_empty() {
                                manifest.path.clone()
                            } else {
                                manifest.locator.clone()
                            },
                            unit_root: root,
                            manifest_paths: vec![manifest.path.clone()],
                        });
                    }
                } else {
                    add(UnitDraft {
                        adapter: AnalysisAdapter::Web,
                        role: AnalysisUnitRole::Executable,
                        kind: AnalysisUnitKind::WebProject,
                        locator: if manifest.locator.is_empty() {
                            manifest.path.clone()
                        } else {
                            manifest.locator.clone()
                        },
                        unit_root: root,
                        manifest_paths: vec![manifest.path.clone()],
                    });
                }
            }
            _ => {}
        }
    }

    // Go module units stay executable while package records preserve the
    // package context for dependency resolution and future capability use.
    let go_dirs = files
        .iter()
        .filter(|(_, kind)| **kind == FileKind::GoSource)
        .map(|(path, _)| {
            path.rsplit_once('/')
                .map(|(parent, _)| parent.to_owned())
                .unwrap_or_else(|| REPOSITORY_ROOT.to_owned())
        })
        .collect::<BTreeSet<_>>();
    for directory in go_dirs {
        add(UnitDraft {
            adapter: AnalysisAdapter::Go,
            role: AnalysisUnitRole::Context,
            kind: AnalysisUnitKind::GoPackage,
            locator: directory.clone(),
            unit_root: directory,
            manifest_paths: Vec::new(),
        });
    }
    drafts.into_values().collect()
}

/// Attach the active root workspace manifest to each module it governs.
///
/// `go` reads the active `go.work` while compiling a member, so that file is
/// part of the member's manifest input even when the module's own `go.mod`
/// is unchanged.  Keeping the path on the executable unit also makes a
/// workspace edit invalidate direct members through `manifest_fingerprint`;
/// dependency closure then carries that change to their dependents.  Nested
/// `go.work` files intentionally remain context-only records.
fn attach_active_go_workspace_manifests(units: &mut [AnalysisUnit], parsed: &[ParsedManifest]) {
    let Some(workspace) = parsed.iter().find(|manifest| {
        manifest.adapter == AnalysisAdapter::Go && manifest.workspace && manifest.path == "go.work"
    }) else {
        return;
    };
    let workspace_paths_are_uncertain = go_workspace_has_nonportable_paths(workspace);
    for unit in units.iter_mut().filter(|unit| {
        unit.adapter == AnalysisAdapter::Go && unit.kind == AnalysisUnitKind::GoModule
    }) {
        let Some(module_manifest) = unit
            .manifest_paths
            .iter()
            .find(|path| path.ends_with("go.mod"))
        else {
            continue;
        };
        if (workspace_paths_are_uncertain
            || go_workspace_contains_module(workspace, module_manifest))
            && !unit.manifest_paths.contains(&workspace.path)
        {
            unit.manifest_paths.push(workspace.path.clone());
        }
    }
}

fn active_go_workspace_member_ids(
    units: &[AnalysisUnit],
    parsed: &[ParsedManifest],
) -> Option<BTreeSet<String>> {
    let workspace = parsed.iter().find(|manifest| {
        manifest.adapter == AnalysisAdapter::Go && manifest.workspace && manifest.path == "go.work"
    })?;
    Some(
        units
            .iter()
            .filter(|unit| {
                unit.adapter == AnalysisAdapter::Go && unit.kind == AnalysisUnitKind::GoModule
            })
            .filter_map(|unit| {
                let module_manifest = unit
                    .manifest_paths
                    .iter()
                    .find(|path| path.ends_with("go.mod"))?;
                go_workspace_contains_module(workspace, module_manifest).then(|| unit.id.clone())
            })
            .collect(),
    )
}

fn go_workspace_has_nonportable_paths(workspace: &ParsedManifest) -> bool {
    workspace
        .workspace_members
        .iter()
        .any(|member| is_nonportable_go_path(member))
        || workspace.go_replacements.iter().any(|replacement| {
            replacement
                .local_path
                .as_deref()
                .is_some_and(is_nonportable_go_path)
        })
}

fn is_nonportable_go_path(path: &str) -> bool {
    path.starts_with('/') || path.contains('\\') || path.as_bytes().get(1) == Some(&b':')
}

fn add_unknown_go_workspace_dependencies(
    units: &[AnalysisUnit],
    references: &mut BTreeMap<String, Vec<AnalysisDependencyReference>>,
) {
    for unit in units.iter().filter(|unit| {
        unit.adapter == AnalysisAdapter::Go && unit.kind == AnalysisUnitKind::GoModule
    }) {
        references
            .entry(unit.id.clone())
            .or_default()
            .push(AnalysisDependencyReference {
                target_unit_id: None,
                specifier: "go.work:nonportable-path".to_owned(),
                kind: AnalysisDependencyKind::Context,
                resolution: AnalysisDependencyResolution::Unknown,
                evidence_path: Some("go.work".to_owned()),
            });
    }
}

fn workspace_has_direct_web_sources(
    files: &BTreeMap<String, FileKind>,
    parsed: &[ParsedManifest],
    manifest_path: &str,
    workspace_root: &str,
) -> bool {
    let child_roots = parsed
        .iter()
        .filter(|manifest| {
            manifest.adapter == AnalysisAdapter::Web
                && manifest.path.ends_with("package.json")
                && manifest.path != manifest_path
        })
        .filter_map(|manifest| {
            let root = manifest
                .path
                .rsplit_once('/')
                .map(|(parent, _)| parent)
                .unwrap_or(REPOSITORY_ROOT);
            is_within(root, workspace_root).then_some(root.to_owned())
        })
        .collect::<Vec<_>>();
    files.iter().any(|(path, kind)| {
        kind.adapter() == Some(AnalysisAdapter::Web)
            && kind.is_source()
            && is_within(path, workspace_root)
            && !child_roots.iter().any(|child| is_within(path, child))
    })
}

fn parse_manifests(root: &Path, paths: &[String]) -> Result<Vec<ParsedManifest>> {
    let mut parsed = Vec::new();
    for path in paths {
        let bytes = read_bounded(root, path, MAX_MANIFEST_BYTES)?;
        let text = String::from_utf8(bytes)
            .with_context(|| format!("analysis manifest {path} is not UTF-8"))?;
        let manifest = match classify_file(path) {
            FileKind::CargoManifest => parse_cargo_manifest(path, &text)?,
            FileKind::GoManifest => parse_go_mod_manifest(path, &text)?,
            FileKind::GoWorkspace => parse_go_work_manifest(path, &text)?,
            FileKind::WebManifest => parse_web_manifest(path, &text)?,
            _ => continue,
        };
        parsed.push(manifest);
    }
    parsed.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(parsed)
}

fn parse_cargo_manifest(path: &str, text: &str) -> Result<ParsedManifest> {
    let value: toml::Value =
        toml::from_str(text).with_context(|| format!("failed to parse Cargo manifest {path}"))?;
    let package_name = value
        .get("package")
        .and_then(|package| package.get("name"))
        .and_then(toml::Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let workspace = value.get("workspace").is_some();
    let mut dependencies = Vec::new();
    for section in ["dependencies", "dev-dependencies", "build-dependencies"] {
        if let Some(table) = value.get(section).and_then(toml::Value::as_table) {
            for (name, spec) in table {
                let local_path = spec
                    .as_table()
                    .and_then(|table| table.get("path"))
                    .and_then(toml::Value::as_str)
                    .map(str::to_owned);
                let external_hint = local_path.is_none();
                dependencies.push(RawDependency {
                    specifier: name.clone(),
                    version: None,
                    kind: local_path
                        .as_ref()
                        .map(|_| AnalysisDependencyKind::LocalPath)
                        .unwrap_or(AnalysisDependencyKind::ManifestDependency),
                    local_path,
                    evidence_path: path.to_owned(),
                    external_hint,
                });
            }
        }
    }
    let workspace_members = value
        .get("workspace")
        .and_then(|workspace| workspace.get("members"))
        .and_then(toml::Value::as_array)
        .map(|members| {
            members
                .iter()
                .filter_map(toml::Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    Ok(ParsedManifest {
        path: path.to_owned(),
        adapter: AnalysisAdapter::Rust,
        locator: package_name,
        dependencies,
        go_replacements: Vec::new(),
        workspace_members,
        workspace,
    })
}

fn parse_go_mod_manifest(path: &str, text: &str) -> Result<ParsedManifest> {
    let mut locator = String::new();
    let mut dependencies = Vec::new();
    let mut go_replacements = Vec::new();
    let mut block = None::<&str>;
    for raw_line in text.lines() {
        let line = raw_line
            .split_once("//")
            .map_or(raw_line, |(line, _)| line)
            .trim();
        if line.is_empty() {
            continue;
        }
        if line == "require (" || line == "replace (" {
            block = Some(if line.starts_with("require") {
                "require"
            } else {
                "replace"
            });
            continue;
        }
        if line == ")" {
            block = None;
            continue;
        }
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if let Some(kind) = block {
            match kind {
                "require" if !fields.is_empty() => {
                    dependencies.push(RawDependency {
                        specifier: fields[0].to_owned(),
                        version: fields.get(1).map(|value| (*value).to_owned()),
                        kind: AnalysisDependencyKind::ManifestDependency,
                        local_path: None,
                        evidence_path: path.to_owned(),
                        external_hint: true,
                    });
                }
                "replace" => add_go_replacement(path, &fields, &mut go_replacements),
                _ => {}
            }
            continue;
        }
        match fields.first().copied() {
            Some("module") if fields.len() >= 2 => locator = fields[1].to_owned(),
            Some("require") if fields.len() >= 2 => dependencies.push(RawDependency {
                specifier: fields[1].to_owned(),
                version: fields.get(2).map(|value| (*value).to_owned()),
                kind: AnalysisDependencyKind::ManifestDependency,
                local_path: None,
                evidence_path: path.to_owned(),
                external_hint: true,
            }),
            Some("replace") => add_go_replacement(path, &fields[1..], &mut go_replacements),
            _ => {}
        }
    }
    Ok(ParsedManifest {
        path: path.to_owned(),
        adapter: AnalysisAdapter::Go,
        locator,
        dependencies,
        go_replacements,
        workspace_members: Vec::new(),
        workspace: false,
    })
}

fn add_go_replacement(path: &str, fields: &[&str], replacements: &mut Vec<GoReplacement>) {
    let Some(separator) = fields.iter().position(|field| *field == "=>") else {
        return;
    };
    let Some(old) = fields.first().copied() else {
        return;
    };
    let Some(replacement) = fields.get(separator + 1).copied() else {
        return;
    };
    let replacement_fields = fields.len().saturating_sub(separator + 1);
    if old.is_empty()
        || replacement.is_empty()
        || !(1..=2).contains(&separator)
        || !(1..=2).contains(&replacement_fields)
    {
        return;
    }
    let old_version = (separator == 2).then(|| fields[1].to_owned());
    let replacement_version = (replacement_fields == 2).then(|| fields[separator + 2].to_owned());
    let (new_module, local_path) = if is_local_specifier(replacement) {
        if replacement_fields != 1 {
            return;
        }
        (None, Some(replacement.to_owned()))
    } else {
        (Some(replacement.to_owned()), None)
    };
    replacements.push(GoReplacement {
        old_module: old.to_owned(),
        old_version,
        new_module,
        new_version: replacement_version,
        local_path,
        evidence_path: path.to_owned(),
    });
}

fn parse_go_work_manifest(path: &str, text: &str) -> Result<ParsedManifest> {
    let mut members = Vec::new();
    let mut go_replacements = Vec::new();
    let mut block = None::<&str>;
    for raw_line in text.lines() {
        let line = raw_line
            .split_once("//")
            .map_or(raw_line, |(line, _)| line)
            .trim();
        if line == "use (" || line == "replace (" {
            block = Some(if line.starts_with("use") {
                "use"
            } else {
                "replace"
            });
            continue;
        }
        if line == ")" {
            block = None;
            continue;
        }
        if let Some(kind) = block {
            match kind {
                "use" => {
                    if let Some(value) = line.split_whitespace().next()
                        && !value.is_empty()
                    {
                        members.push(value.to_owned());
                    }
                }
                "replace" => {
                    let fields = line.split_whitespace().collect::<Vec<_>>();
                    add_go_replacement(path, &fields, &mut go_replacements);
                }
                _ => {}
            }
        } else if let Some(value) = line.strip_prefix("use ") {
            let value = value.trim();
            if !value.is_empty() {
                members.push(value.to_owned());
            }
        } else if let Some(value) = line.strip_prefix("replace ") {
            let fields = value.split_whitespace().collect::<Vec<_>>();
            add_go_replacement(path, &fields, &mut go_replacements);
        }
    }
    Ok(ParsedManifest {
        path: path.to_owned(),
        adapter: AnalysisAdapter::Go,
        locator: path.to_owned(),
        dependencies: Vec::new(),
        go_replacements,
        workspace_members: members,
        workspace: true,
    })
}

fn parse_web_manifest(path: &str, text: &str) -> Result<ParsedManifest> {
    let value: Value = serde_json::from_str(text)
        .with_context(|| format!("failed to parse Web manifest {path}"))?;
    let locator = value
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let workspace_members = match value.get("workspaces") {
        Some(Value::Array(values)) => values
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect(),
        Some(Value::Object(object)) => object
            .get("packages")
            .and_then(Value::as_array)
            .map(|values| {
                values
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default(),
        _ => Vec::new(),
    };
    let workspace = !workspace_members.is_empty();
    let mut dependencies = Vec::new();
    for section in [
        "dependencies",
        "devDependencies",
        "peerDependencies",
        "optionalDependencies",
    ] {
        if let Some(object) = value.get(section).and_then(Value::as_object) {
            for (name, spec) in object {
                let Some(specifier) = spec.as_str() else {
                    continue;
                };
                let local_path = specifier
                    .strip_prefix("file:")
                    .or_else(|| specifier.strip_prefix("link:"))
                    .map(str::to_owned);
                dependencies.push(RawDependency {
                    specifier: name.clone(),
                    version: None,
                    kind: local_path
                        .as_ref()
                        .map(|_| AnalysisDependencyKind::LocalPath)
                        .unwrap_or(AnalysisDependencyKind::ManifestDependency),
                    local_path,
                    evidence_path: path.to_owned(),
                    external_hint: !specifier.starts_with("workspace:")
                        && !specifier.starts_with("file:")
                        && !specifier.starts_with("link:"),
                });
            }
        }
    }
    Ok(ParsedManifest {
        path: path.to_owned(),
        adapter: AnalysisAdapter::Web,
        locator,
        dependencies,
        go_replacements: Vec::new(),
        workspace_members,
        workspace,
    })
}

fn find_manifest_owner(manifest: &ParsedManifest, units: &[AnalysisUnit]) -> Option<String> {
    units
        .iter()
        .filter(|unit| unit.adapter == manifest.adapter)
        .filter(|unit| unit.manifest_paths.contains(&manifest.path))
        .filter(|unit| {
            if manifest.adapter == AnalysisAdapter::Go && manifest.path == "go.work" {
                return unit.kind == AnalysisUnitKind::GoWorkspace;
            }
            matches!(
                unit.kind,
                AnalysisUnitKind::RustPackage
                    | AnalysisUnitKind::RustWorkspace
                    | AnalysisUnitKind::GoModule
                    | AnalysisUnitKind::GoWorkspace
                    | AnalysisUnitKind::WebProject
                    | AnalysisUnitKind::WebWorkspace
            )
        })
        .min_by_key(|unit| (manifest_owner_rank(unit.kind), unit.id.as_str()))
        .map(|unit| unit.id.clone())
}

fn find_workspace_owner(manifest: &ParsedManifest, units: &[AnalysisUnit]) -> Option<String> {
    units
        .iter()
        .filter(|unit| unit.adapter == manifest.adapter)
        .filter(|unit| unit.manifest_paths.contains(&manifest.path))
        .filter(|unit| {
            matches!(
                unit.kind,
                AnalysisUnitKind::RustWorkspace
                    | AnalysisUnitKind::GoWorkspace
                    | AnalysisUnitKind::WebWorkspace
            )
        })
        .min_by_key(|unit| unit.id.as_str())
        .map(|unit| unit.id.clone())
}

/// Return the replacements that are effective for each Go module. A module
/// listed by the active repository-root go.work uses that workspace's
/// replacements; its own go.mod replacements are only a fallback when no
/// matching workspace directive governs the module. Conflicting directives at
/// the same version precedence remain in the returned set and resolve as
/// unknown rather than being selected by iteration order.
fn go_replacements_by_module(
    parsed: &[ParsedManifest],
    manifest_to_go_module_id: &BTreeMap<String, String>,
) -> BTreeMap<String, Vec<GoReplacement>> {
    let workspaces = parsed
        .iter()
        .filter(|manifest| {
            manifest.adapter == AnalysisAdapter::Go
                && manifest.workspace
                // The worker activates only the repository-root go.work.
                // Nested files remain context records and must not silently
                // alter module resolution for a root scan.
                && manifest.path == "go.work"
        })
        .collect::<Vec<_>>();
    let mut replacements_by_module = BTreeMap::new();
    for manifest in parsed.iter().filter(|manifest| {
        manifest.adapter == AnalysisAdapter::Go && manifest.path.ends_with("go.mod")
    }) {
        let Some(module_id) = manifest_to_go_module_id.get(&manifest.path) else {
            continue;
        };
        let matching_workspaces = workspaces
            .iter()
            .filter(|workspace| go_workspace_contains_module(workspace, &manifest.path))
            .collect::<Vec<_>>();
        let workspace_replacements = matching_workspaces
            .into_iter()
            .flat_map(|workspace| workspace.go_replacements.iter())
            .collect::<Vec<_>>();
        let mut replacements = Vec::new();
        for dependency in &manifest.dependencies {
            if workspace_replacements
                .iter()
                .any(|replacement| go_replacement_matches(replacement, dependency))
            {
                replacements.extend(
                    workspace_replacements
                        .iter()
                        .filter(|replacement| go_replacement_matches(replacement, dependency))
                        .map(|replacement| (*replacement).clone()),
                );
            } else {
                replacements.extend(
                    manifest
                        .go_replacements
                        .iter()
                        .filter(|replacement| go_replacement_matches(replacement, dependency))
                        .cloned(),
                );
            }
        }
        replacements.sort_by(|left, right| {
            go_replacement_sort_key(left).cmp(&go_replacement_sort_key(right))
        });
        replacements.dedup();
        replacements_by_module.insert(module_id.clone(), replacements);
    }
    replacements_by_module
}

fn go_replacement_matches(replacement: &GoReplacement, dependency: &RawDependency) -> bool {
    replacement.old_module == dependency.specifier
        && (replacement.old_version.is_none() || replacement.old_version == dependency.version)
}

fn go_replacement_sort_key(replacement: &GoReplacement) -> GoReplacementSortKey<'_> {
    (
        &replacement.old_module,
        replacement.old_version.as_deref(),
        replacement.new_module.as_deref(),
        replacement.new_version.as_deref(),
        replacement.local_path.as_deref(),
        &replacement.evidence_path,
    )
}

fn go_workspace_contains_module(workspace: &ParsedManifest, module_manifest: &str) -> bool {
    let module_dir = module_manifest
        .rsplit_once('/')
        .map(|(parent, _)| parent)
        .unwrap_or(REPOSITORY_ROOT);
    let workspace_dir = workspace
        .path
        .rsplit_once('/')
        .map(|(parent, _)| parent)
        .unwrap_or(REPOSITORY_ROOT);
    workspace
        .workspace_members
        .iter()
        .filter_map(|member| join_relative(workspace_dir, member))
        .any(|member| member == module_dir)
}

fn manifest_owner_rank(kind: AnalysisUnitKind) -> u8 {
    match kind {
        AnalysisUnitKind::RustPackage
        | AnalysisUnitKind::GoModule
        | AnalysisUnitKind::WebProject => 0,
        AnalysisUnitKind::RustWorkspace
        | AnalysisUnitKind::GoWorkspace
        | AnalysisUnitKind::WebWorkspace => 1,
        AnalysisUnitKind::RepositoryAdapter | AnalysisUnitKind::GoPackage => 2,
    }
}

fn resolve_manifest_dependency(
    raw: &RawDependency,
    manifest: &ParsedManifest,
    units: &[AnalysisUnit],
    manifest_to_package_id: &BTreeMap<String, String>,
    manifest_to_go_module_id: &BTreeMap<String, String>,
    web_name_to_project_ids: &BTreeMap<String, Vec<String>>,
    go_resolution: &GoResolutionContext<'_>,
) -> AnalysisDependencyReference {
    let mut target = None;
    let mut resolution = if raw.external_hint {
        AnalysisDependencyResolution::External
    } else {
        AnalysisDependencyResolution::Unknown
    };
    let mut kind = raw.kind;
    if manifest.adapter == AnalysisAdapter::Go {
        match select_go_replacement(go_resolution.replacements, raw) {
            Some(Err(())) => {
                return AnalysisDependencyReference {
                    target_unit_id: None,
                    specifier: raw.specifier.clone(),
                    kind: raw.kind,
                    resolution: AnalysisDependencyResolution::Unknown,
                    evidence_path: Some(raw.evidence_path.clone()),
                };
            }
            Some(Ok(replacement)) => {
                let (target, resolution) =
                    resolve_go_replacement_target(replacement, manifest_to_go_module_id);
                kind = replacement
                    .local_path
                    .as_ref()
                    .map(|_| AnalysisDependencyKind::LocalPath)
                    .unwrap_or(raw.kind);
                return AnalysisDependencyReference {
                    target_unit_id: target,
                    specifier: raw.specifier.clone(),
                    kind,
                    resolution,
                    evidence_path: Some(replacement.evidence_path.clone()),
                };
            }
            None => {}
        }
    }
    if let Some(local_path) = raw.local_path.as_deref()
        && let Some(manifest_path) =
            relative_manifest_path(manifest.adapter, &manifest.path, local_path)
    {
        target = match manifest.adapter {
            AnalysisAdapter::Rust => manifest_to_package_id.get(&manifest_path).cloned(),
            AnalysisAdapter::Go => manifest_to_go_module_id.get(&manifest_path).cloned(),
            AnalysisAdapter::Web => units
                .iter()
                .find(|unit| {
                    unit.adapter == AnalysisAdapter::Web
                        && unit.kind == AnalysisUnitKind::WebProject
                        && unit
                            .manifest_paths
                            .iter()
                            .any(|path| path == &manifest_path)
                })
                .map(|unit| unit.id.clone()),
        };
        resolution = if target.is_some() {
            AnalysisDependencyResolution::Resolved
        } else {
            AnalysisDependencyResolution::Unknown
        };
    } else if manifest.adapter == AnalysisAdapter::Web {
        if let Some(ids) = web_name_to_project_ids.get(&raw.specifier) {
            if ids.len() == 1 {
                target = ids.first().cloned();
                resolution = AnalysisDependencyResolution::Resolved;
            } else {
                resolution = AnalysisDependencyResolution::Unknown;
            }
        } else if raw.specifier.starts_with(".") || raw.specifier.starts_with("/") {
            resolution = AnalysisDependencyResolution::Unknown;
        }
    } else if manifest.adapter == AnalysisAdapter::Go {
        let source_id = manifest_to_go_module_id.get(&manifest.path);
        let matches = units
            .iter()
            .filter(|unit| {
                unit.adapter == AnalysisAdapter::Go
                    && unit.kind == AnalysisUnitKind::GoModule
                    && unit.locator == raw.specifier
            })
            .filter(|target| {
                go_resolution
                    .active_workspace_member_ids
                    .is_none_or(|member_ids| {
                        source_id.is_some_and(|source_id| {
                            source_id == &target.id
                                || (member_ids.contains(source_id)
                                    && member_ids.contains(&target.id))
                        })
                    })
            })
            .collect::<Vec<_>>();
        if matches.len() == 1 {
            target = Some(matches[0].id.clone());
            resolution = AnalysisDependencyResolution::Resolved;
        } else if matches.len() > 1 {
            resolution = AnalysisDependencyResolution::Unknown;
        }
    }
    AnalysisDependencyReference {
        target_unit_id: target,
        specifier: raw.specifier.clone(),
        kind,
        resolution,
        evidence_path: Some(raw.evidence_path.clone()),
    }
}

/// Go gives a versioned replacement precedence over a wildcard replacement.
/// At either precedence level, duplicate directives are ambiguous and must
/// remain unknown rather than being resolved by source order.
fn select_go_replacement<'a>(
    replacements: &'a [GoReplacement],
    dependency: &RawDependency,
) -> Option<Result<&'a GoReplacement, ()>> {
    let exact = replacements
        .iter()
        .filter(|replacement| {
            replacement.old_module == dependency.specifier
                && replacement.old_version.is_some()
                && replacement.old_version == dependency.version
        })
        .collect::<Vec<_>>();
    if exact.len() > 1 {
        return Some(Err(()));
    }
    if let Some(replacement) = exact.first() {
        return Some(Ok(replacement));
    }
    let wildcard = replacements
        .iter()
        .filter(|replacement| {
            replacement.old_module == dependency.specifier && replacement.old_version.is_none()
        })
        .collect::<Vec<_>>();
    if wildcard.len() > 1 {
        Some(Err(()))
    } else {
        wildcard.first().copied().map(Ok)
    }
}

fn resolve_go_replacement_target(
    replacement: &GoReplacement,
    manifest_to_go_module_id: &BTreeMap<String, String>,
) -> (Option<String>, AnalysisDependencyResolution) {
    if let Some(local_path) = replacement.local_path.as_deref() {
        if is_nonportable_go_path(local_path) {
            return (None, AnalysisDependencyResolution::Unknown);
        }
        let Some(manifest_path) =
            relative_manifest_path(AnalysisAdapter::Go, &replacement.evidence_path, local_path)
        else {
            return (None, AnalysisDependencyResolution::Unknown);
        };
        let Some(target) = manifest_to_go_module_id.get(&manifest_path).cloned() else {
            return (None, AnalysisDependencyResolution::Unknown);
        };
        return (Some(target), AnalysisDependencyResolution::Resolved);
    }
    if replacement.new_module.is_some() {
        // A module-path replacement remains a remote module from the core
        // planner's point of view. The worker only treats local replacement
        // paths as repository-local targets; a matching module name in this
        // checkout must not be mistaken for the selected remote version.
        return (None, AnalysisDependencyResolution::External);
    }
    (None, AnalysisDependencyResolution::Unknown)
}

fn resolve_workspace_member(
    member: &str,
    manifest: &ParsedManifest,
    units: &[AnalysisUnit],
    manifest_to_package_id: &BTreeMap<String, String>,
    manifest_to_go_module_id: &BTreeMap<String, String>,
) -> AnalysisDependencyReference {
    let target_paths = units
        .iter()
        .filter_map(|unit| {
            let manifest_path = unit.manifest_paths.first()?;
            let relative = relative_path_from_manifest(&manifest.path, manifest_path)?;
            glob_matches(member, &relative).then_some(manifest_path.clone())
        })
        .collect::<Vec<_>>();
    let target = match manifest.adapter {
        AnalysisAdapter::Rust => target_paths
            .iter()
            .find_map(|path| manifest_to_package_id.get(path).cloned()),
        AnalysisAdapter::Go => target_paths
            .iter()
            .find_map(|path| manifest_to_go_module_id.get(path).cloned()),
        AnalysisAdapter::Web => target_paths
            .iter()
            .find_map(|path| {
                units.iter().find(|unit| {
                    unit.kind == AnalysisUnitKind::WebProject
                        && unit
                            .manifest_paths
                            .iter()
                            .any(|candidate| candidate == path)
                })
            })
            .map(|unit| unit.id.clone()),
    };
    AnalysisDependencyReference {
        target_unit_id: target.clone(),
        specifier: member.to_owned(),
        kind: AnalysisDependencyKind::WorkspaceMember,
        resolution: if target.is_some() {
            AnalysisDependencyResolution::Resolved
        } else {
            AnalysisDependencyResolution::Unknown
        },
        evidence_path: Some(manifest.path.clone()),
    }
}

fn add_context_edges(
    units: &[AnalysisUnit],
    references: &mut BTreeMap<String, Vec<AnalysisDependencyReference>>,
) {
    for executable in units.iter().filter(|unit| unit.is_executable()) {
        for context in units.iter().filter(|unit| {
            unit.adapter == executable.adapter
                && unit.role == AnalysisUnitRole::Context
                && (is_within(&unit.unit_root, &executable.unit_root)
                    || is_within(&executable.unit_root, &unit.unit_root))
        }) {
            references.entry(executable.id.clone()).or_default().push(
                AnalysisDependencyReference {
                    target_unit_id: Some(context.id.clone()),
                    specifier: context.locator.clone(),
                    kind: AnalysisDependencyKind::Context,
                    resolution: AnalysisDependencyResolution::Resolved,
                    evidence_path: context.manifest_paths.first().cloned(),
                },
            );
        }
    }
}

fn web_name_index(units: &[AnalysisUnit]) -> BTreeMap<String, Vec<String>> {
    let mut index = BTreeMap::<String, Vec<String>>::new();
    for unit in units
        .iter()
        .filter(|unit| unit.kind == AnalysisUnitKind::WebProject)
    {
        if !unit.locator.is_empty() {
            index
                .entry(unit.locator.clone())
                .or_default()
                .push(unit.id.clone());
        }
    }
    for ids in index.values_mut() {
        ids.sort();
        ids.dedup();
    }
    index
}

fn package_root_index(units: &[AnalysisUnit]) -> BTreeMap<(AnalysisAdapter, String), String> {
    units
        .iter()
        .filter(|unit| {
            matches!(
                unit.kind,
                AnalysisUnitKind::GoPackage | AnalysisUnitKind::WebProject
            )
        })
        .map(|unit| ((unit.adapter, unit.unit_root.clone()), unit.id.clone()))
        .collect()
}

fn add_static_source_imports(
    root: &Path,
    files: &BTreeMap<String, FileKind>,
    units: &mut [AnalysisUnit],
    package_root_index: &BTreeMap<(AnalysisAdapter, String), String>,
    references: &mut BTreeMap<String, Vec<AnalysisDependencyReference>>,
    go_replacements_by_module: &BTreeMap<String, Vec<GoReplacement>>,
    active_go_workspace_member_ids: Option<&BTreeSet<String>>,
) -> Result<()> {
    for (path, kind) in files {
        if !kind.is_source() {
            continue;
        }
        let Some(adapter) = kind.adapter() else {
            continue;
        };
        let imports = match adapter {
            AnalysisAdapter::Go => extract_go_imports(root, path)?,
            AnalysisAdapter::Web => extract_web_imports(root, path)?,
            AnalysisAdapter::Rust => Vec::new(),
        };
        if imports.is_empty() {
            continue;
        }
        let Some(owner) = most_specific_executable(path, adapter, units) else {
            continue;
        };
        let owner_id = owner.id.clone();
        let go_resolution = GoImportResolutionContext {
            replacements: (adapter == AnalysisAdapter::Go)
                .then(|| go_replacements_by_module.get(&owner_id))
                .flatten()
                .map(Vec::as_slice)
                .unwrap_or_default(),
            active_workspace_member_ids: active_go_workspace_member_ids,
            source_unit_id: &owner_id,
        };
        for specifier in imports {
            let (target, resolution) = resolve_source_import(
                adapter,
                path,
                &specifier,
                units,
                package_root_index,
                &go_resolution,
            );
            references
                .entry(owner_id.clone())
                .or_default()
                .push(AnalysisDependencyReference {
                    target_unit_id: target,
                    specifier,
                    kind: AnalysisDependencyKind::SourceImport,
                    resolution,
                    evidence_path: Some(path.clone()),
                });
        }
    }
    Ok(())
}

fn most_specific_executable<'a>(
    path: &str,
    adapter: AnalysisAdapter,
    units: &'a [AnalysisUnit],
) -> Option<&'a AnalysisUnit> {
    let mut owner = None;
    let mut ambiguous = false;
    for candidate in units.iter().filter(|unit| {
        unit.is_executable() && unit.adapter == adapter && is_within(path, &unit.unit_root)
    }) {
        match owner {
            None => owner = Some(candidate),
            Some(current) if candidate.unit_root.len() > current.unit_root.len() => {
                owner = Some(candidate);
                ambiguous = false;
            }
            Some(current) if candidate.unit_root.len() == current.unit_root.len() => {
                if candidate.unit_root != current.unit_root {
                    // Two executable units can claim the same path only when
                    // their source scopes are ambiguous. Leave the path
                    // unowned so an executor cannot silently duplicate it.
                    ambiguous = true;
                } else if candidate.id < current.id {
                    owner = Some(candidate);
                }
            }
            Some(_) => {}
        }
    }
    (!ambiguous).then_some(owner).flatten()
}

fn extract_go_imports(root: &Path, path: &str) -> Result<Vec<String>> {
    let text = String::from_utf8_lossy(&read_bounded(root, path, MAX_MANIFEST_BYTES)?).into_owned();
    let mut imports = Vec::new();
    let mut block = false;
    for line in text.lines() {
        let line = line.split_once("//").map_or(line, |(line, _)| line).trim();
        if line.starts_with("import (") {
            block = true;
            continue;
        }
        if block && line == ")" {
            block = false;
            continue;
        }
        let value = if block {
            quoted_value(line)
        } else {
            line.strip_prefix("import ").and_then(quoted_value)
        };
        if let Some(value) = value
            && !value.starts_with(".")
            && imports.len() < MAX_IMPORTS_PER_FILE
        {
            imports.push(value);
        }
    }
    imports.sort();
    imports.dedup();
    Ok(imports)
}

fn extract_web_imports(root: &Path, path: &str) -> Result<Vec<String>> {
    let text = String::from_utf8_lossy(&read_bounded(root, path, MAX_MANIFEST_BYTES)?).into_owned();
    let mut imports = Vec::new();
    for line in text.lines() {
        for marker in ["from", "import", "require(", "dynamic("] {
            let mut rest = line;
            while let Some(index) = rest.find(marker) {
                rest = &rest[index + marker.len()..];
                let Some(value) = quoted_value(rest) else {
                    break;
                };
                if (value.starts_with(".") || value.starts_with("/"))
                    && imports.len() < MAX_IMPORTS_PER_FILE
                {
                    imports.push(value);
                }
                let Some(end) = rest.find(['"', '\'']) else {
                    break;
                };
                let quote = rest.as_bytes()[end] as char;
                let tail = &rest[end + 1..];
                let Some(close) = tail.find(quote) else {
                    break;
                };
                rest = &tail[close + 1..];
            }
        }
    }
    imports.sort();
    imports.dedup();
    Ok(imports)
}

fn quoted_value(value: &str) -> Option<String> {
    let first = value.find(['"', '\''])?;
    let quote = value.as_bytes()[first] as char;
    let value = &value[first + 1..];
    let end = value.find(quote)?;
    Some(value[..end].to_owned())
}

fn resolve_source_import(
    adapter: AnalysisAdapter,
    source_path: &str,
    specifier: &str,
    units: &[AnalysisUnit],
    package_root_index: &BTreeMap<(AnalysisAdapter, String), String>,
    go_resolution: &GoImportResolutionContext<'_>,
) -> (Option<String>, AnalysisDependencyResolution) {
    if adapter == AnalysisAdapter::Go {
        match select_go_replacement_for_import(go_resolution.replacements, specifier) {
            Some(Err(())) => return (None, AnalysisDependencyResolution::Unknown),
            Some(Ok(replacement)) => {
                let suffix = specifier
                    .strip_prefix(&replacement.old_module)
                    .unwrap_or_default()
                    .trim_start_matches('/');
                let (target, resolution) = resolve_go_replacement_target_for_import(
                    replacement,
                    units,
                    package_root_index,
                    suffix,
                );
                return (target, resolution);
            }
            None => {}
        }
        let modules = units
            .iter()
            .filter(|unit| unit.adapter == adapter && unit.kind == AnalysisUnitKind::GoModule)
            .filter(|target| {
                go_resolution
                    .active_workspace_member_ids
                    .is_none_or(|member_ids| {
                        target.id == go_resolution.source_unit_id
                            || (member_ids.contains(go_resolution.source_unit_id)
                                && member_ids.contains(&target.id))
                    })
            })
            .filter(|unit| {
                specifier == unit.locator || specifier.starts_with(&(unit.locator.clone() + "/"))
            })
            .collect::<Vec<_>>();
        if modules.len() > 1 {
            return (None, AnalysisDependencyResolution::Unknown);
        }
        if let Some(module) = modules.first() {
            let suffix = specifier
                .strip_prefix(&module.locator)
                .unwrap_or_default()
                .trim_start_matches('/');
            let package_root = if suffix.is_empty() {
                module.unit_root.clone()
            } else {
                join_relative(&module.unit_root, suffix).unwrap_or_else(|| module.unit_root.clone())
            };
            if let Some(id) = package_root_index.get(&(adapter, package_root)).cloned() {
                return (Some(id), AnalysisDependencyResolution::Resolved);
            }
            return (None, AnalysisDependencyResolution::Unknown);
        }
        return (None, AnalysisDependencyResolution::External);
    }
    if specifier.starts_with(".") || specifier.starts_with("/") {
        let base = source_path
            .rsplit_once('/')
            .map(|(parent, _)| parent)
            .unwrap_or("");
        let Some(root) = join_relative(base, specifier) else {
            return (None, AnalysisDependencyResolution::Unknown);
        };
        let matches = units
            .iter()
            .filter(|unit| {
                unit.adapter == adapter
                    && unit.kind == AnalysisUnitKind::WebProject
                    && is_within(&root, &unit.unit_root)
            })
            .collect::<Vec<_>>();
        let longest = matches.iter().map(|unit| unit.unit_root.len()).max();
        let matches = matches
            .into_iter()
            .filter(|unit| Some(unit.unit_root.len()) == longest)
            .collect::<Vec<_>>();
        if matches.len() == 1 {
            return (
                Some(matches[0].id.clone()),
                AnalysisDependencyResolution::Resolved,
            );
        }
        if matches.len() > 1 {
            return (None, AnalysisDependencyResolution::Unknown);
        }
        return (None, AnalysisDependencyResolution::Unknown);
    }
    (None, AnalysisDependencyResolution::External)
}

fn select_go_replacement_for_import<'a>(
    replacements: &'a [GoReplacement],
    specifier: &str,
) -> Option<Result<&'a GoReplacement, ()>> {
    let longest = replacements
        .iter()
        .filter(|replacement| {
            specifier == replacement.old_module
                || specifier.starts_with(&(replacement.old_module.clone() + "/"))
        })
        .map(|replacement| replacement.old_module.len())
        .max()?;
    let candidates = replacements
        .iter()
        .filter(|replacement| {
            replacement.old_module.len() == longest
                && (specifier == replacement.old_module
                    || specifier.starts_with(&(replacement.old_module.clone() + "/")))
        })
        .collect::<Vec<_>>();
    let versioned = candidates
        .iter()
        .filter(|replacement| replacement.old_version.is_some())
        .copied()
        .collect::<Vec<_>>();
    if versioned.len() > 1 {
        return Some(Err(()));
    }
    if let Some(replacement) = versioned.first() {
        return Some(Ok(replacement));
    }
    if candidates.len() > 1 {
        Some(Err(()))
    } else {
        candidates.first().copied().map(Ok)
    }
}

fn resolve_go_replacement_target_for_import(
    replacement: &GoReplacement,
    units: &[AnalysisUnit],
    package_root_index: &BTreeMap<(AnalysisAdapter, String), String>,
    suffix: &str,
) -> (Option<String>, AnalysisDependencyResolution) {
    let target_module = if let Some(local_path) = replacement.local_path.as_deref() {
        if is_nonportable_go_path(local_path) {
            return (None, AnalysisDependencyResolution::Unknown);
        }
        let Some(manifest_path) =
            relative_manifest_path(AnalysisAdapter::Go, &replacement.evidence_path, local_path)
        else {
            return (None, AnalysisDependencyResolution::Unknown);
        };
        units
            .iter()
            .filter(|unit| {
                unit.adapter == AnalysisAdapter::Go
                    && unit.kind == AnalysisUnitKind::GoModule
                    && unit
                        .manifest_paths
                        .iter()
                        .any(|path| path == &manifest_path)
            })
            .collect::<Vec<_>>()
    } else if replacement.new_module.is_some() {
        return (None, AnalysisDependencyResolution::External);
    } else {
        return (None, AnalysisDependencyResolution::Unknown);
    };
    if target_module.len() != 1 {
        return (None, AnalysisDependencyResolution::Unknown);
    }
    let module = target_module[0];
    let package_root = if suffix.is_empty() {
        module.unit_root.clone()
    } else {
        let Some(root) = join_relative(&module.unit_root, suffix) else {
            return (None, AnalysisDependencyResolution::Unknown);
        };
        root
    };
    package_root_index
        .get(&(AnalysisAdapter::Go, package_root))
        .cloned()
        .map(|id| (Some(id), AnalysisDependencyResolution::Resolved))
        .unwrap_or((None, AnalysisDependencyResolution::Unknown))
}

fn finalize_units(
    units: &mut [AnalysisUnit],
    mut references: BTreeMap<String, Vec<AnalysisDependencyReference>>,
    files: &BTreeMap<String, FileKind>,
    digests: &BTreeMap<String, String>,
    input: &AnalysisPlanInput,
    global: &AnalysisInputFingerprints,
) -> Result<()> {
    let all_config_paths = files
        .iter()
        .filter(|(_, kind)| kind.is_config())
        .map(|(path, _)| path.clone())
        .collect::<Vec<_>>();
    let source_owners = files
        .iter()
        .filter_map(|(path, kind)| {
            if !kind.is_source() {
                return None;
            }
            let adapter = kind.adapter()?;
            Some((
                path.clone(),
                most_specific_executable(path, adapter, units).map(|unit| unit.id.clone()),
            ))
        })
        .collect::<BTreeMap<_, _>>();
    for unit in units.iter_mut() {
        if unit.is_executable() {
            unit.source_paths = source_owners
                .iter()
                .filter_map(|(path, owner)| {
                    (owner.as_deref() == Some(unit.id.as_str())).then_some(path.clone())
                })
                .collect();
        }
        unit.manifest_paths.sort();
        unit.manifest_paths.dedup();
        unit.source_paths.sort();
        unit.source_paths.dedup();
        unit.config_paths = if unit.is_executable() {
            all_config_paths
                .iter()
                .filter(|path| {
                    // Root-level workspace metadata governs nested units. A
                    // unit also owns configuration below its source root.
                    *path == ".depgraph.toml"
                        || !path.contains('/')
                        || is_within(path, &unit.unit_root)
                })
                .cloned()
                .collect()
        } else {
            Vec::new()
        };
        unit.profile_scope = profile_scope(unit, &input.profile_ids)?;
        unit.source_fingerprint = fingerprint_paths(digests, &unit.source_paths);
        unit.manifest_fingerprint = fingerprint_paths(digests, &unit.manifest_paths);
        unit.config_fingerprint = fingerprint_paths(digests, &unit.config_paths);
        unit.profile_fingerprint = unit.profile_scope.fingerprint.clone();
        unit.analyzer_fingerprint = global.analyzer_fingerprint.clone();
        let mut refs = references.remove(&unit.id).unwrap_or_default();
        refs.sort_by(|left, right| left.sort_key().cmp(&right.sort_key()));
        refs.dedup();
        unit.unknown_dependencies = refs
            .iter()
            .any(|reference| reference.resolution == AnalysisDependencyResolution::Unknown);
        unit.dependency_references = refs;
        unit.dependency_ids = unit
            .dependency_references
            .iter()
            .filter_map(|reference| {
                (reference.resolution == AnalysisDependencyResolution::Resolved)
                    .then(|| reference.target_unit_id.clone())
                    .flatten()
            })
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
    }

    let adapter_fingerprints = adapter_fingerprints(units);
    let by_id = units
        .iter()
        .map(|unit| (unit.id.clone(), unit.clone()))
        .collect::<BTreeMap<_, _>>();
    for unit in units.iter_mut() {
        let mut dependency_payload = json!({
            "unit_id": unit.id,
            "references": unit.dependency_references,
        });
        let mut closure = BTreeSet::new();
        let mut queue = VecDeque::from_iter(unit.dependency_ids.iter().cloned());
        while let Some(target_id) = queue.pop_front() {
            if !closure.insert(target_id.clone()) {
                continue;
            }
            if let Some(target) = by_id.get(&target_id) {
                queue.extend(target.dependency_ids.iter().cloned());
            }
        }
        let closure_signatures = closure
            .iter()
            .filter_map(|target_id| by_id.get(target_id))
            .map(|target| {
                json!({
                    "id": target.id,
                    "source": target.source_fingerprint,
                    "manifest": target.manifest_fingerprint,
                    "config": target.config_fingerprint,
                    "profile": target.profile_fingerprint,
                    "analyzer": target.analyzer_fingerprint,
                    "references": target.dependency_references,
                    "unknown": target.unknown_dependencies,
                })
            })
            .collect::<Vec<_>>();
        dependency_payload["transitive_dependencies"] = Value::Array(closure_signatures);
        if unit.unknown_dependencies {
            dependency_payload["adapter_fingerprint"] = json!(adapter_fingerprints[&unit.adapter]);
        }
        unit.dependency_fingerprint = sha256_digest(canonical_json(&dependency_payload));
        unit.input_fingerprint = sha256_digest(canonical_json(&json!({
            "contract_version": ANALYSIS_PLAN_CONTRACT_VERSION,
            "source_fingerprint": unit.source_fingerprint,
            "manifest_fingerprint": unit.manifest_fingerprint,
            "config_fingerprint": unit.config_fingerprint,
            "profile_fingerprint": unit.profile_fingerprint,
            "analyzer_fingerprint": unit.analyzer_fingerprint,
            "dependency_fingerprint": unit.dependency_fingerprint,
        })));
    }
    let dependencies_by_id = units
        .iter()
        .map(|unit| (unit.id.clone(), unit.dependency_ids.clone()))
        .collect::<BTreeMap<_, _>>();
    for unit in units.iter_mut() {
        unit.dependent_ids = dependencies_by_id
            .iter()
            .filter(|(_, dependencies)| dependencies.iter().any(|id| id == &unit.id))
            .map(|(id, _)| id.clone())
            .collect();
    }
    Ok(())
}

fn profile_scope(unit: &AnalysisUnit, definition_ids: &[String]) -> Result<AnalysisProfileScope> {
    let mut definition_ids = definition_ids.to_vec();
    definition_ids.sort();
    definition_ids.dedup();
    let mut scoped_ids = definition_ids
        .iter()
        .map(|definition_id| {
            stable_id_from_value(
                "analysis-profile-scope",
                &json!({
                    "adapter": unit.adapter.as_str(),
                    "unit_id": unit.id,
                    "definition_id": definition_id,
                }),
            )
        })
        .collect::<Vec<_>>();
    scoped_ids.sort();
    scoped_ids.dedup();
    let fingerprint = sha256_digest(canonical_json(&json!({
        "definition_ids": definition_ids,
        "scoped_ids": scoped_ids,
    })));
    Ok(AnalysisProfileScope {
        definition_ids,
        scoped_ids,
        fingerprint,
    })
}

fn adapter_fingerprints(units: &[AnalysisUnit]) -> BTreeMap<AnalysisAdapter, String> {
    let mut records = BTreeMap::<AnalysisAdapter, Vec<Value>>::new();
    for unit in units {
        records.entry(unit.adapter).or_default().push(json!({
            "id": unit.id,
            "source": unit.source_fingerprint,
            "manifest": unit.manifest_fingerprint,
            "config": unit.config_fingerprint,
            "profile": unit.profile_fingerprint,
            "analyzer": unit.analyzer_fingerprint,
        }));
    }
    records
        .into_iter()
        .map(|(adapter, mut values)| {
            values.sort_by_key(canonical_json);
            (
                adapter,
                sha256_digest(canonical_json(&Value::Array(values))),
            )
        })
        .collect()
}

fn dependency_groups(units: &[AnalysisUnit]) -> Result<Vec<AnalysisDependencyGroup>> {
    let adjacency = units
        .iter()
        .map(|unit| (unit.id.clone(), unit.dependency_ids.clone()))
        .collect::<BTreeMap<_, _>>();
    if adjacency.values().map(Vec::len).sum::<usize>() > MAX_PLAN_EDGES {
        bail!("analysis plan exceeds its closed dependency edge limit");
    }

    let mut reverse = BTreeMap::<String, Vec<String>>::new();
    for (from, targets) in &adjacency {
        for target in targets {
            reverse
                .entry(target.clone())
                .or_default()
                .push(from.clone());
        }
    }
    for values in reverse.values_mut() {
        values.sort();
    }

    let mut visited = BTreeSet::new();
    let mut order = Vec::new();
    for id in adjacency.keys() {
        dfs_order(id, &adjacency, &mut visited, &mut order);
    }
    visited.clear();
    let mut components = Vec::new();
    for id in order.into_iter().rev() {
        if visited.contains(&id) {
            continue;
        }
        let mut component = Vec::new();
        dfs_component(&id, &reverse, &mut visited, &mut component);
        component.sort();
        components.push(component);
    }

    let group_for_unit = components
        .iter()
        .enumerate()
        .flat_map(|(index, component)| component.iter().map(move |id| (id.clone(), index)))
        .collect::<BTreeMap<_, _>>();
    let cyclic_components = components
        .iter()
        .map(|component| {
            component.len() > 1
                || component
                    .first()
                    .is_some_and(|id| adjacency[id].iter().any(|target| target == id))
        })
        .collect::<Vec<_>>();
    let mut groups = Vec::<AnalysisDependencyGroup>::new();
    for (component_index, component) in components.iter().enumerate() {
        let cyclic = cyclic_components[component_index];
        let id = stable_id_from_value(
            "analysis-dependency-group",
            &json!({"unit_ids": component, "cyclic": cyclic}),
        );
        let mut outgoing = BTreeSet::new();
        for unit_id in component {
            for target in &adjacency[unit_id] {
                if group_for_unit[target] != group_for_unit[unit_id] {
                    outgoing.insert(group_for_unit[target]);
                }
            }
        }
        let mut outgoing_group_ids = outgoing
            .into_iter()
            .map(|index| {
                stable_id_from_value(
                    "analysis-dependency-group",
                    &json!({
                        "unit_ids": components[index],
                        "cyclic": cyclic_components[index]
                    }),
                )
            })
            .collect::<Vec<_>>();
        outgoing_group_ids.sort();
        groups.push(AnalysisDependencyGroup {
            id,
            unit_ids: component.clone(),
            outgoing_group_ids,
            cyclic,
        });
    }
    groups.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(groups)
}

fn dfs_order(
    id: &str,
    adjacency: &BTreeMap<String, Vec<String>>,
    visited: &mut BTreeSet<String>,
    order: &mut Vec<String>,
) {
    let mut stack = vec![(id.to_owned(), false)];
    while let Some((current, exiting)) = stack.pop() {
        if exiting {
            order.push(current);
            continue;
        }
        if !visited.insert(current.clone()) {
            continue;
        }
        stack.push((current.clone(), true));
        if let Some(targets) = adjacency.get(&current) {
            for target in targets.iter().rev() {
                stack.push((target.clone(), false));
            }
        }
    }
}

fn dfs_component(
    id: &str,
    reverse: &BTreeMap<String, Vec<String>>,
    visited: &mut BTreeSet<String>,
    component: &mut Vec<String>,
) {
    let mut stack = vec![id.to_owned()];
    while let Some(current) = stack.pop() {
        if !visited.insert(current.clone()) {
            continue;
        }
        component.push(current.clone());
        if let Some(sources) = reverse.get(&current) {
            for source in sources.iter().rev() {
                stack.push(source.clone());
            }
        }
    }
}

fn canonicalize_plan(mut plan: AnalysisPlan) -> Result<AnalysisPlan> {
    if plan.contract_version != ANALYSIS_PLAN_CONTRACT_VERSION {
        bail!("unsupported analysis plan contract version");
    }
    if plan.repository_root != REPOSITORY_ROOT {
        bail!("analysis plan repository_root must be .");
    }
    validate_id(
        "analysis plan repository_identity",
        &plan.repository_identity,
        "analysis-repository",
    )?;
    validate_sha256("analysis plan inventory_digest", &plan.inventory_digest)?;
    validate_sha256("analysis plan input_fingerprint", &plan.input_fingerprint)?;
    validate_id("analysis plan plan_id", &plan.plan_id, "analysis-plan")?;
    validate_sha256("analysis plan input_digest", &plan.input_digest)?;
    if plan.input_digest != plan.input_fingerprint {
        bail!("analysis plan input_digest must equal input_fingerprint");
    }
    for fingerprint in [
        &plan.fingerprints.source_fingerprint,
        &plan.fingerprints.manifest_fingerprint,
        &plan.fingerprints.config_fingerprint,
        &plan.fingerprints.profile_fingerprint,
        &plan.fingerprints.analyzer_fingerprint,
    ] {
        validate_sha256("analysis plan fingerprint", fingerprint)?;
    }
    if plan.units.len() > MAX_PLAN_UNITS {
        bail!("analysis plan exceeds its closed unit limit");
    }
    plan.units.sort_by(|left, right| left.id.cmp(&right.id));
    let mut ids = BTreeSet::new();
    for unit in &mut plan.units {
        validate_analysis_unit(unit)?;
        if !ids.insert(unit.id.clone()) {
            bail!("analysis plan contains duplicate unit id");
        }
        unit.manifest_paths.sort();
        unit.manifest_paths.dedup();
        unit.source_paths.sort();
        unit.source_paths.dedup();
        unit.config_paths.sort();
        unit.config_paths.dedup();
        unit.dependency_ids.sort();
        unit.dependency_ids.dedup();
        unit.dependent_ids.sort();
        unit.dependent_ids.dedup();
        unit.dependency_references
            .sort_by(|left, right| left.sort_key().cmp(&right.sort_key()));
        unit.dependency_references.dedup();
        unit.profile_scope.definition_ids.sort();
        unit.profile_scope.definition_ids.dedup();
        unit.profile_scope.scoped_ids.sort();
        unit.profile_scope.scoped_ids.dedup();
        validate_profile_scope(unit)?;
    }
    for unit in &plan.units {
        for dependency_id in &unit.dependency_ids {
            if !ids.contains(dependency_id) {
                bail!(
                    "analysis unit {} references an unknown dependency {}",
                    unit.id,
                    dependency_id
                );
            }
        }
        for dependent_id in &unit.dependent_ids {
            if !ids.contains(dependent_id) {
                bail!(
                    "analysis unit {} references an unknown dependent {}",
                    unit.id,
                    dependent_id
                );
            }
        }
        for reference in &unit.dependency_references {
            match reference.resolution {
                AnalysisDependencyResolution::Resolved => {
                    let Some(target_id) = reference.target_unit_id.as_ref() else {
                        bail!("resolved dependency reference on {} has no target", unit.id);
                    };
                    if !ids.contains(target_id) {
                        bail!(
                            "analysis unit {} references an unknown target {}",
                            unit.id,
                            target_id
                        );
                    }
                }
                AnalysisDependencyResolution::External | AnalysisDependencyResolution::Unknown => {
                    if reference.target_unit_id.is_some() {
                        bail!(
                            "non-resolved dependency reference on {} has a target",
                            unit.id
                        );
                    }
                }
            }
        }
    }
    let mut expected_dependents = BTreeMap::<String, BTreeSet<String>>::new();
    for unit in &plan.units {
        for dependency_id in &unit.dependency_ids {
            expected_dependents
                .entry(dependency_id.clone())
                .or_default()
                .insert(unit.id.clone());
        }
    }
    for unit in &plan.units {
        let expected = expected_dependents
            .get(&unit.id)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .collect::<Vec<_>>();
        if unit.dependent_ids != expected {
            bail!("analysis unit {} has inconsistent dependent_ids", unit.id);
        }
    }
    plan.dependency_groups
        .sort_by(|left, right| left.id.cmp(&right.id));
    let mut group_ids = BTreeSet::new();
    let mut unit_groups = BTreeMap::<String, String>::new();
    for group in &mut plan.dependency_groups {
        validate_id(
            "analysis dependency group id",
            &group.id,
            "analysis-dependency-group",
        )?;
        group.unit_ids.sort();
        group.unit_ids.dedup();
        group.outgoing_group_ids.sort();
        group.outgoing_group_ids.dedup();
        let expected_id = stable_id_from_value(
            "analysis-dependency-group",
            &json!({"unit_ids": group.unit_ids, "cyclic": group.cyclic}),
        );
        if group.id != expected_id {
            bail!("analysis dependency group id does not match its contents");
        }
        if !group_ids.insert(group.id.clone()) {
            bail!("analysis plan contains duplicate dependency group id");
        }
        for unit_id in &group.unit_ids {
            if !ids.contains(unit_id) {
                bail!("analysis dependency group references an unknown unit");
            }
            if unit_groups
                .insert(unit_id.clone(), group.id.clone())
                .is_some()
            {
                bail!("analysis plan assigns a unit to multiple dependency groups");
            }
        }
    }
    if unit_groups.len() != plan.units.len() {
        bail!("analysis plan dependency groups do not cover every unit");
    }
    for group in &plan.dependency_groups {
        for outgoing_id in &group.outgoing_group_ids {
            if !group_ids.contains(outgoing_id) {
                bail!("analysis dependency group references an unknown outgoing group");
            }
        }
    }
    plan.limitations.sort();
    plan.limitations.dedup();
    let expected_plan_id = plan_id(&plan);
    if plan.plan_id != expected_plan_id {
        bail!("analysis plan plan_id does not match its canonical contents");
    }
    Ok(plan)
}

fn plan_id(plan: &AnalysisPlan) -> String {
    stable_id_from_value(
        "analysis-plan",
        &json!({
            "contract_version": plan.contract_version,
            "repository_identity": plan.repository_identity,
            "inventory_digest": plan.inventory_digest,
            "fingerprints": plan.fingerprints,
            "input_fingerprint": plan.input_fingerprint,
            "units": plan.units,
            "dependency_groups": plan.dependency_groups,
            "limitations": plan.limitations,
        }),
    )
}

fn validate_analysis_unit(unit: &AnalysisUnit) -> Result<()> {
    validate_id("analysis unit id", &unit.id, "analysis-unit")?;
    validate_bounded_string(
        "analysis unit locator",
        &unit.locator,
        MAX_PLAN_STRING_CHARS,
    )?;
    validate_repository_path("analysis unit root", &unit.unit_root)?;
    let expected_role = match unit.kind {
        AnalysisUnitKind::RepositoryAdapter
        | AnalysisUnitKind::GoModule
        | AnalysisUnitKind::WebProject => AnalysisUnitRole::Executable,
        AnalysisUnitKind::RustWorkspace
        | AnalysisUnitKind::RustPackage
        | AnalysisUnitKind::GoWorkspace
        | AnalysisUnitKind::GoPackage
        | AnalysisUnitKind::WebWorkspace => AnalysisUnitRole::Context,
    };
    if unit.role != expected_role {
        bail!("analysis unit role does not match its kind");
    }
    let expected_adapter = match unit.kind {
        AnalysisUnitKind::RepositoryAdapter => None,
        AnalysisUnitKind::RustWorkspace | AnalysisUnitKind::RustPackage => {
            Some(AnalysisAdapter::Rust)
        }
        AnalysisUnitKind::GoWorkspace
        | AnalysisUnitKind::GoModule
        | AnalysisUnitKind::GoPackage => Some(AnalysisAdapter::Go),
        AnalysisUnitKind::WebWorkspace | AnalysisUnitKind::WebProject => Some(AnalysisAdapter::Web),
    };
    if expected_adapter.is_some_and(|adapter| unit.adapter != adapter) {
        bail!("analysis unit adapter does not match its kind");
    }
    if unit.id != analysis_unit_id(unit.adapter, unit.kind, &unit.unit_root, &unit.locator) {
        bail!("analysis unit id does not match its canonical identity");
    }
    for path in unit
        .manifest_paths
        .iter()
        .chain(&unit.source_paths)
        .chain(&unit.config_paths)
    {
        validate_repository_path("analysis unit path", path)?;
    }
    for fingerprint in [
        &unit.source_fingerprint,
        &unit.manifest_fingerprint,
        &unit.config_fingerprint,
        &unit.profile_fingerprint,
        &unit.analyzer_fingerprint,
        &unit.dependency_fingerprint,
        &unit.input_fingerprint,
        &unit.profile_scope.fingerprint,
    ] {
        validate_sha256("analysis unit fingerprint", fingerprint)?;
    }
    Ok(())
}

fn validate_profile_scope(unit: &AnalysisUnit) -> Result<()> {
    let expected = profile_scope(unit, &unit.profile_scope.definition_ids)?;
    if expected.scoped_ids != unit.profile_scope.scoped_ids
        || expected.fingerprint != unit.profile_scope.fingerprint
    {
        bail!("analysis unit profile scope is inconsistent");
    }
    Ok(())
}

fn analysis_unit_id(
    adapter: AnalysisAdapter,
    kind: AnalysisUnitKind,
    unit_root: &str,
    locator: &str,
) -> String {
    stable_id_from_value(
        "analysis-unit",
        &json!({
            "contract_version": ANALYSIS_PLAN_CONTRACT_VERSION,
            "adapter": adapter,
            "kind": kind,
            "unit_root": unit_root,
            "locator": locator,
        }),
    )
}

pub fn canonical_analysis_unit_id(
    adapter: AnalysisAdapter,
    kind: AnalysisUnitKind,
    unit_root: &str,
    locator: &str,
) -> Result<String> {
    validate_repository_path("analysis unit root", unit_root)?;
    validate_bounded_string("analysis unit locator", locator, MAX_PLAN_STRING_CHARS)?;
    Ok(analysis_unit_id(adapter, kind, unit_root, locator))
}

fn global_fingerprints(
    files: &BTreeMap<String, FileKind>,
    digests: &BTreeMap<String, String>,
    config: &Config,
    input: &AnalysisPlanInput,
    source_paths: &[String],
    manifest_paths: &[String],
    config_paths: &[String],
) -> Result<(AnalysisInputFingerprints, String)> {
    let source_fingerprint = fingerprint_paths(digests, source_paths);
    let manifest_fingerprint = fingerprint_paths(digests, manifest_paths);
    let config_file_fingerprint = fingerprint_paths(digests, config_paths);
    let config_fingerprint = sha256_digest(canonical_json(&json!({
        "config": serde_json::to_value(config)?,
        "repository_config_files": config_file_fingerprint,
    })));
    let profile_fingerprint = sha256_digest(canonical_json(&json!({
        "profile_definition_ids": input.profile_ids,
    })));
    let analyzer_fingerprint = canonical_analyzer_fingerprint(&input.analyzer_fingerprint);
    let fingerprints = AnalysisInputFingerprints {
        source_fingerprint,
        manifest_fingerprint,
        config_fingerprint,
        profile_fingerprint,
        analyzer_fingerprint,
    };
    let input_fingerprint = sha256_digest(canonical_json(&json!({
        "contract_version": ANALYSIS_PLAN_CONTRACT_VERSION,
        "inventory": inventory_digest(files),
        "fingerprints": fingerprints,
    })));
    Ok((fingerprints, input_fingerprint))
}

fn inventory_digest(files: &BTreeMap<String, FileKind>) -> String {
    let records = files
        .iter()
        .map(|(path, kind)| json!({"path": path, "kind": kind_name(*kind)}))
        .collect::<Vec<_>>();
    sha256_digest(canonical_json(&json!({
        "contract_version": ANALYSIS_PLAN_CONTRACT_VERSION,
        "files": records,
    })))
}

fn repository_identity(root: &Path) -> String {
    let remote = fs::read_to_string(root.join(".git/config"))
        .ok()
        .and_then(|text| {
            let mut in_origin = false;
            for line in text.lines() {
                let line = line.trim();
                if line.starts_with('[') {
                    in_origin = line == "[remote \"origin\"]";
                } else if in_origin && let Some(value) = line.strip_prefix("url = ") {
                    return Some(value.trim().to_owned());
                }
            }
            None
        });
    stable_id_from_value(
        "analysis-repository",
        &json!({
            "contract_version": ANALYSIS_PLAN_CONTRACT_VERSION,
            "remote_origin": remote.unwrap_or_else(|| "unbound-repository".to_owned()),
        }),
    )
}

fn kind_name(kind: FileKind) -> &'static str {
    match kind {
        FileKind::Other => "other",
        FileKind::RustSource => "rust_source",
        FileKind::GoSource => "go_source",
        FileKind::WebSource => "web_source",
        FileKind::CargoManifest => "cargo_manifest",
        FileKind::GoManifest => "go_manifest",
        FileKind::GoWorkspace => "go_workspace",
        FileKind::WebManifest => "web_manifest",
        FileKind::Config => "config",
    }
}

fn fingerprint_paths(digests: &BTreeMap<String, String>, paths: &[String]) -> String {
    let records = paths
        .iter()
        .map(|path| json!({"path": path, "digest": digests.get(path)}))
        .collect::<Vec<_>>();
    sha256_digest(canonical_json(&Value::Array(records)))
}

fn hash_repository_file(root: &Path, relative: &str) -> Result<String> {
    let absolute = root.join(relative);
    let metadata = fs::symlink_metadata(&absolute)
        .with_context(|| format!("failed to inspect analysis input {relative}"))?;
    if metadata.file_type().is_symlink() {
        let target = fs::read_link(&absolute)
            .with_context(|| format!("failed to inspect analysis symlink {relative}"))?;
        let target = if target.is_absolute() {
            "external-symlink".to_owned()
        } else {
            target.to_string_lossy().replace('\\', "/")
        };
        return Ok(sha256_digest(format!("symlink:{target}")));
    }
    if !metadata.is_file() {
        return Ok(sha256_digest("non-file"));
    }
    let file = File::open(&absolute)
        .with_context(|| format!("failed to read analysis input {relative}"))?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = reader
            .read(&mut buffer)
            .with_context(|| format!("failed to hash analysis input {relative}"))?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(format!("sha256:{}", hex::encode(hasher.finalize())))
}

fn read_bounded(root: &Path, relative: &str, limit: usize) -> Result<Vec<u8>> {
    let absolute = root.join(relative);
    let metadata = fs::symlink_metadata(&absolute)
        .with_context(|| format!("failed to inspect analysis input {relative}"))?;
    if metadata.file_type().is_symlink() {
        bail!("analysis input {relative} must not be a symlink");
    }
    if !metadata.is_file() {
        bail!("analysis input {relative} must be a regular file");
    }
    let file = File::open(&absolute)
        .with_context(|| format!("failed to read analysis input {relative}"))?;
    let mut bytes = Vec::new();
    file.take((limit as u64) + 1).read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        bail!("analysis input {relative} exceeds its closed manifest limit");
    }
    Ok(bytes)
}

fn sha256_digest(value: impl AsRef<[u8]>) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(value.as_ref())))
}

fn canonical_analyzer_fingerprint(value: &str) -> String {
    if value.starts_with("sha256:")
        && value.len() == 71
        && value[7..].bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        value.to_owned()
    } else {
        sha256_digest(canonical_json(&json!({"analyzer": value})))
    }
}

fn validate_id(field: &str, value: &str, prefix: &str) -> Result<()> {
    validate_bounded_string(field, value, MAX_PLAN_STRING_CHARS)?;
    if !value.starts_with(&format!("{prefix}:sha256:"))
        || value.len() != prefix.len() + 8 + 64
        || !value[prefix.len() + 8..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        bail!("{field} is not a canonical {prefix} ID");
    }
    Ok(())
}

fn validate_sha256(field: &str, value: &str) -> Result<()> {
    if value.len() != 71
        || !value.starts_with("sha256:")
        || !value[7..].bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        bail!("{field} is not a canonical sha256 fingerprint");
    }
    Ok(())
}

fn validate_bounded_string(field: &str, value: &str, max_chars: usize) -> Result<()> {
    if value.is_empty() || value.chars().count() > max_chars || value.chars().any(char::is_control)
    {
        bail!("{field} is empty, too long, or contains control characters");
    }
    Ok(())
}

fn validate_repository_path(field: &str, path: &str) -> Result<()> {
    if path == REPOSITORY_ROOT {
        return Ok(());
    }
    if path.is_empty()
        || path.len() > MAX_PLAN_PATH_CHARS
        || path.contains('\\')
        || path.contains('\0')
    {
        bail!("{field} is not a canonical repository-relative path");
    }
    let value = Path::new(path);
    if value.is_absolute()
        || value.components().any(|component| {
            !matches!(component, Component::Normal(_))
                || component.as_os_str().to_str().is_none_or(str::is_empty)
        })
    {
        bail!("{field} is not a canonical repository-relative path");
    }
    Ok(())
}

fn relative_manifest_path(
    adapter: AnalysisAdapter,
    manifest_path: &str,
    local_path: &str,
) -> Option<String> {
    let base = manifest_path
        .rsplit_once('/')
        .map(|(parent, _)| parent)
        .unwrap_or("");
    let file_name = match adapter {
        AnalysisAdapter::Rust => "Cargo.toml",
        AnalysisAdapter::Go => "go.mod",
        AnalysisAdapter::Web => "package.json",
    };
    join_relative(base, &format!("{local_path}/{file_name}"))
}

fn relative_path_from_manifest(manifest_path: &str, target_path: &str) -> Option<String> {
    let base = manifest_path
        .rsplit_once('/')
        .map(|(parent, _)| parent)
        .unwrap_or("");
    let target_dir = target_path
        .rsplit_once('/')
        .map(|(parent, _)| parent)
        .unwrap_or("");
    let target_dir = if target_dir.is_empty() {
        REPOSITORY_ROOT
    } else {
        target_dir
    };
    if target_dir == base || (base.is_empty() && target_dir == REPOSITORY_ROOT) {
        return Some(REPOSITORY_ROOT.to_owned());
    }
    if base.is_empty() {
        return Some(target_dir.to_owned());
    }
    target_dir
        .strip_prefix(&(base.to_owned() + "/"))
        .map(str::to_owned)
}

fn join_relative(base: &str, candidate: &str) -> Option<String> {
    if candidate.starts_with('/') || candidate.contains('\\') || candidate.contains('\0') {
        return None;
    }
    let mut components = Vec::<String>::new();
    if base != REPOSITORY_ROOT && !base.is_empty() {
        components.extend(base.split('/').map(str::to_owned));
    }
    for component in candidate.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                components.pop()?;
            }
            value => components.push(value.to_owned()),
        }
    }
    if components.is_empty() {
        Some(REPOSITORY_ROOT.to_owned())
    } else {
        Some(components.join("/"))
    }
}

fn is_local_specifier(value: &str) -> bool {
    value == "."
        || value == ".."
        || value.starts_with("./")
        || value.starts_with("../")
        || value.starts_with('/')
        || value.contains('\\')
        || value.as_bytes().get(1) == Some(&b':')
}

fn is_within(path: &str, root: &str) -> bool {
    root == REPOSITORY_ROOT || path == root || path.starts_with(&(root.to_owned() + "/"))
}

fn glob_matches(pattern: &str, value: &str) -> bool {
    let pattern = pattern.trim_matches('/').trim_start_matches("./");
    let value = value.trim_matches('/');
    glob_segments(pattern.split('/').collect(), value.split('/').collect())
}

fn glob_segments(pattern: Vec<&str>, value: Vec<&str>) -> bool {
    if pattern.is_empty() {
        return value.is_empty();
    }
    if pattern[0] == "**" {
        return glob_segments(pattern[1..].to_vec(), value.clone())
            || (!value.is_empty() && glob_segments(pattern, value[1..].to_vec()));
    }
    if value.is_empty() || !segment_matches(pattern[0], value[0]) {
        return false;
    }
    glob_segments(pattern[1..].to_vec(), value[1..].to_vec())
}

fn segment_matches(pattern: &str, value: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    let mut remaining = value;
    for part in pattern.split('*').filter(|part| !part.is_empty()) {
        let Some(index) = remaining.find(part) else {
            return false;
        };
        remaining = &remaining[index + part.len()..];
    }
    pattern.ends_with('*') || remaining.is_empty()
}

#[cfg(test)]
mod tests {
    use std::{fs, path::Path};

    use super::*;

    const ANALYSIS_PLAN_SCHEMA: &str =
        include_str!("../../../schemas/depgraph-analysis-plan-v1.schema.json");

    fn input() -> AnalysisPlanInput {
        AnalysisPlanInput::new(["profile:web:source"], "web-worker@unit-test")
    }

    fn polyglot_fixture(root: &Path) -> Result<()> {
        fs::create_dir_all(root.join("apps/web/src"))?;
        fs::create_dir_all(root.join("packages/shared"))?;
        fs::create_dir_all(root.join("services/a"))?;
        fs::create_dir_all(root.join("services/b"))?;
        fs::write(
            root.join("Cargo.toml"),
            "[workspace]\nmembers = [\"packages/shared\"]\n",
        )?;
        fs::write(
            root.join("packages/shared/Cargo.toml"),
            "[package]\nname = \"shared\"\nversion = \"0.1.0\"\n",
        )?;
        fs::write(root.join("packages/shared/lib.rs"), "pub fn shared() {}\n")?;
        fs::write(
            root.join("go.work"),
            "go 1.23\n\nuse (\n ./services/a\n ./services/b\n)\n",
        )?;
        fs::write(
            root.join("services/a/go.mod"),
            "module example.test/a\n\ngo 1.23\n\nrequire example.test/b v1.0.0\n",
        )?;
        fs::write(
            root.join("services/b/go.mod"),
            "module example.test/b\n\ngo 1.23\n\nrequire example.test/a v1.0.0\n",
        )?;
        fs::write(root.join("services/a/a.go"), "package a\n")?;
        fs::write(root.join("services/b/b.go"), "package b\n")?;
        fs::write(
            root.join("package.json"),
            r#"{"name":"root-web","workspaces":["apps/*"]}"#,
        )?;
        fs::write(
            root.join("apps/web/package.json"),
            r#"{"name":"web-app","dependencies":{"shared-web":"workspace:*"}}"#,
        )?;
        fs::write(
            root.join("apps/web/src/index.ts"),
            "export const app = true;\n",
        )?;
        Ok(())
    }

    #[test]
    fn plan_discovers_nested_units_and_never_runs_package_managers() -> Result<()> {
        let root = tempfile::tempdir()?;
        polyglot_fixture(root.path())?;
        fs::create_dir_all(root.path().join(".depgraph/checkpoints"))?;
        fs::write(
            root.path().join(".depgraph/checkpoints/result.json"),
            "state must not enter inventory\n",
        )?;

        let plan = discover_analysis_plan(root.path(), &Config::default(), &input())?;
        assert_eq!(plan.repository_root, REPOSITORY_ROOT);
        assert!(plan.units.iter().any(|unit| {
            unit.adapter == AnalysisAdapter::Go && unit.kind == AnalysisUnitKind::GoModule
        }));
        assert!(plan.units.iter().any(|unit| {
            unit.adapter == AnalysisAdapter::Web && unit.kind == AnalysisUnitKind::WebProject
        }));
        assert!(plan.units.iter().any(|unit| {
            unit.adapter == AnalysisAdapter::Rust && unit.kind == AnalysisUnitKind::RustPackage
        }));
        assert!(
            !plan
                .units
                .iter()
                .flat_map(|unit| unit.source_paths.iter())
                .any(|path| path.starts_with(".depgraph/"))
        );
        assert!(
            plan.limitations
                .contains(&AnalysisPlanLimitation::PackageManagersNotExecuted)
        );
        assert!(
            plan.units
                .iter()
                .all(|unit| !unit.id.contains(root.path().to_string_lossy().as_ref()))
        );
        Ok(())
    }

    #[test]
    fn serialized_plan_satisfies_the_closed_schema() -> Result<()> {
        let root = tempfile::tempdir()?;
        polyglot_fixture(root.path())?;
        let plan = discover_analysis_plan(root.path(), &Config::default(), &input())?;
        let schema: Value = serde_json::from_str(ANALYSIS_PLAN_SCHEMA)?;
        let validator = jsonschema::validator_for(&schema)?;
        let value = serde_json::to_value(plan)?;
        assert!(validator.is_valid(&value));
        Ok(())
    }

    #[test]
    fn discovery_is_checkout_path_independent_and_repeatable() -> Result<()> {
        let first = tempfile::tempdir()?;
        polyglot_fixture(first.path())?;
        let second = tempfile::tempdir()?;
        polyglot_fixture(second.path())?;
        let first_plan = discover_analysis_plan(first.path(), &Config::default(), &input())?;
        let second_plan = discover_analysis_plan(second.path(), &Config::default(), &input())?;
        assert_eq!(
            first_plan.repository_identity,
            second_plan.repository_identity
        );
        assert_eq!(first_plan.plan_id, second_plan.plan_id);
        assert_eq!(first_plan.digest()?, second_plan.digest()?);
        assert_eq!(
            first_plan
                .units
                .iter()
                .map(|unit| unit.id.clone())
                .collect::<Vec<_>>(),
            second_plan
                .units
                .iter()
                .map(|unit| unit.id.clone())
                .collect::<Vec<_>>()
        );
        Ok(())
    }

    #[test]
    fn multiple_profiles_have_canonical_scoped_ids() -> Result<()> {
        let root = tempfile::tempdir()?;
        polyglot_fixture(root.path())?;
        let plan = discover_analysis_plan(
            root.path(),
            &Config::default(),
            &AnalysisPlanInput::new(["profile:z", "profile:a", "profile:z"], "worker"),
        )?;
        for unit in &plan.units {
            let scoped = unit.profile_scope.scoped_ids.clone();
            let mut sorted = scoped.clone();
            sorted.sort();
            sorted.dedup();
            assert_eq!(scoped, sorted);
            assert_eq!(
                unit.profile_scope.definition_ids,
                ["profile:a", "profile:z"]
            );
        }
        assert_eq!(plan, plan.canonicalize()?);
        Ok(())
    }

    #[test]
    fn workspace_edges_and_go_cycle_are_retained_in_the_common_graph() -> Result<()> {
        let root = tempfile::tempdir()?;
        polyglot_fixture(root.path())?;
        let plan = discover_analysis_plan(root.path(), &Config::default(), &input())?;
        assert!(
            plan.units
                .iter()
                .flat_map(|unit| unit.dependency_references.iter())
                .any(
                    |reference| reference.kind == AnalysisDependencyKind::WorkspaceMember
                        && reference.resolution == AnalysisDependencyResolution::Resolved
                )
        );
        assert!(plan.dependency_groups.iter().any(|group| group.cyclic));
        Ok(())
    }

    #[test]
    fn go_work_replacements_override_member_replacements_and_preserve_cycles() -> Result<()> {
        let root = tempfile::tempdir()?;
        for directory in ["app", "workspace-target", "local", "independent"] {
            fs::create_dir_all(root.path().join(directory))?;
        }
        fs::write(
            root.path().join("go.work"),
            "go 1.26\n\nuse (\n ./app\n ./workspace-target\n)\n\nreplace (\n example.com/old v1.0.0 => ./workspace-target\n)\nreplace example.com/old => ./local\nreplace example.com/wild => ./workspace-target\n",
        )?;
        fs::write(
            root.path().join("app/go.mod"),
            "module example.com/app\n\ngo 1.26\n\nrequire (\n example.com/old v1.0.0\n example.com/wild v1.0.0\n)\n\nreplace (\n example.com/old => ../local\n example.com/wild => ../local\n)\n",
        )?;
        fs::write(
            root.path().join("workspace-target/go.mod"),
            "module example.com/workspace-target\n\ngo 1.26\n\nrequire example.com/app v1.0.0\n",
        )?;
        fs::write(
            root.path().join("local/go.mod"),
            "module example.com/local\n\ngo 1.26\n",
        )?;
        fs::write(
            root.path().join("independent/go.mod"),
            "module example.com/independent\n\ngo 1.26\n\nrequire (\n example.com/old v1.0.0\n example.com/app v1.0.0\n)\n\nreplace example.com/old => ../local\n",
        )?;
        fs::write(
            root.path().join("app/app.go"),
            "package app\n\nimport (\n _ \"example.com/old\"\n _ \"example.com/wild\"\n)\n",
        )?;
        fs::write(
            root.path().join("workspace-target/target.go"),
            "package target\n",
        )?;
        fs::write(root.path().join("local/local.go"), "package local\n")?;
        fs::create_dir_all(root.path().join("independent/subpkg"))?;
        fs::write(
            root.path().join("independent/independent.go"),
            "package independent\nimport _ \"example.com/independent/subpkg\"\n",
        )?;
        fs::write(
            root.path().join("independent/subpkg/helper.go"),
            "package subpkg\n",
        )?;

        let before = discover_analysis_plan(root.path(), &Config::default(), &input())?;
        let app = before
            .units
            .iter()
            .find(|unit| unit.locator == "example.com/app")
            .expect("app module");
        let workspace_target = before
            .units
            .iter()
            .find(|unit| unit.locator == "example.com/workspace-target")
            .expect("workspace replacement target");
        let local = before
            .units
            .iter()
            .find(|unit| unit.locator == "example.com/local")
            .expect("module-local replacement target");
        let independent = before
            .units
            .iter()
            .find(|unit| unit.locator == "example.com/independent")
            .expect("independent module");
        let replacement_refs = app
            .dependency_references
            .iter()
            .filter(|reference| reference.kind == AnalysisDependencyKind::LocalPath)
            .collect::<Vec<_>>();
        assert!(replacement_refs.iter().any(|reference| {
            reference.target_unit_id.as_deref() == Some(workspace_target.id.as_str())
                && reference.evidence_path.as_deref() == Some("go.work")
        }));
        assert!(
            !replacement_refs.iter().any(|reference| {
                reference.target_unit_id.as_deref() == Some(local.id.as_str())
            })
        );
        assert!(independent.dependency_references.iter().any(|reference| {
            reference.target_unit_id.as_deref() == Some(local.id.as_str())
                && reference.evidence_path.as_deref() == Some("independent/go.mod")
        }));
        assert!(independent.dependency_references.iter().any(|reference| {
            reference.specifier == "example.com/app"
                && reference.resolution == AnalysisDependencyResolution::External
        }));
        assert!(independent.dependency_references.iter().any(|reference| {
            reference.specifier == "example.com/independent/subpkg"
                && reference.resolution == AnalysisDependencyResolution::Resolved
        }));
        assert!(before.dependency_groups.iter().any(|group| {
            group.cyclic
                && group.unit_ids.contains(&app.id)
                && group.unit_ids.contains(&workspace_target.id)
        }));
        Ok(())
    }

    #[test]
    fn absolute_go_workspace_paths_are_kept_conservative() -> Result<()> {
        for path in ["/repo/app", "C:/repo/app", r"C:\repo\app"] {
            let workspace = parse_go_work_manifest("go.work", &format!("use {path}\n"))?;
            assert!(go_workspace_has_nonportable_paths(&workspace), "{path}");
        }
        let root = tempfile::tempdir()?;
        for directory in ["app", "replacement"] {
            fs::create_dir_all(root.path().join(directory))?;
        }
        let app_path = root.path().join("app");
        let replacement_path = root.path().join("replacement");
        let app_path = app_path.to_string_lossy().replace('\\', "/");
        let replacement_path = replacement_path.to_string_lossy().replace('\\', "/");
        fs::write(
            root.path().join("go.work"),
            format!(
                "go 1.26\nuse (\n {app_path}\n {replacement_path}\n)\nreplace example.com/old => {replacement_path}\n"
            ),
        )?;
        fs::write(
            root.path().join("app/go.mod"),
            "module example.com/app\n\ngo 1.26\nrequire example.com/old v1.0.0\n",
        )?;
        fs::write(
            root.path().join("replacement/go.mod"),
            "module example.com/replacement\n\ngo 1.26\n",
        )?;
        fs::write(root.path().join("app/app.go"), "package app\n")?;
        fs::write(
            root.path().join("replacement/replacement.go"),
            "package replacement\n",
        )?;

        let plan = discover_analysis_plan(root.path(), &Config::default(), &input())?;
        let app = plan
            .units
            .iter()
            .find(|unit| unit.locator == "example.com/app")
            .expect("app module");
        assert!(app.unknown_dependencies);
        assert!(app.dependency_references.iter().any(|reference| {
            reference.specifier == "go.work:nonportable-path"
                && reference.resolution == AnalysisDependencyResolution::Unknown
                && reference.evidence_path.as_deref() == Some("go.work")
        }));
        Ok(())
    }

    #[test]
    fn go_work_edit_invalidates_members_and_their_dependents() -> Result<()> {
        let root = tempfile::tempdir()?;
        for directory in ["app", "selected", "replacement-two"] {
            fs::create_dir_all(root.path().join(directory))?;
        }
        fs::write(
            root.path().join("go.work"),
            "go 1.26\nuse (\n ./app\n ./selected\n)\nreplace example.com/old => ./selected\n",
        )?;
        fs::write(
            root.path().join("app/go.mod"),
            "module example.com/app\n\ngo 1.26\nrequire example.com/old v1.0.0\n",
        )?;
        fs::write(
            root.path().join("selected/go.mod"),
            "module example.com/selected\n\ngo 1.26\nrequire example.com/app v1.0.0\n",
        )?;
        fs::write(
            root.path().join("replacement-two/go.mod"),
            "module example.com/replacement-two\n\ngo 1.26\nrequire example.com/app v1.0.0\n",
        )?;
        fs::write(root.path().join("app/app.go"), "package app\n")?;
        fs::write(
            root.path().join("selected/selected.go"),
            "package selected\n",
        )?;
        fs::write(
            root.path().join("replacement-two/replacement.go"),
            "package replacementtwo\n",
        )?;

        let before = discover_analysis_plan(root.path(), &Config::default(), &input())?;
        let app_id = before
            .units
            .iter()
            .find(|unit| unit.locator == "example.com/app")
            .expect("app module")
            .id
            .clone();
        let before_app = before.unit(&app_id).expect("app module before edit");
        assert!(
            before_app
                .manifest_paths
                .iter()
                .any(|path| path == "go.work")
        );
        let before_app_manifest_fingerprint = before_app.manifest_fingerprint.clone();
        let target_id = before
            .units
            .iter()
            .find(|unit| unit.locator == "example.com/selected")
            .expect("target module")
            .id
            .clone();
        let before_target_dependency_fingerprint = before
            .unit(&target_id)
            .expect("target module before edit")
            .dependency_fingerprint
            .clone();
        let target_two_id = before
            .units
            .iter()
            .find(|unit| unit.locator == "example.com/replacement-two")
            .expect("second target module")
            .id
            .clone();
        fs::write(
            root.path().join("go.work"),
            "go 1.26\nuse (\n ./app\n ./replacement-two\n)\nreplace example.com/old => ./replacement-two\n",
        )?;
        let after = discover_analysis_plan(root.path(), &Config::default(), &input())?;
        let after_app = after.unit(&app_id).expect("app module after edit");
        assert!(
            after_app
                .manifest_paths
                .iter()
                .any(|path| path == "go.work")
        );
        assert_ne!(
            after_app.manifest_fingerprint,
            before_app_manifest_fingerprint
        );
        assert_ne!(
            after
                .unit(&target_id)
                .expect("target module after edit")
                .dependency_fingerprint,
            before_target_dependency_fingerprint
        );
        let invalidation = after.invalidation_from(&before)?;
        let app_entry = invalidation
            .entries
            .iter()
            .find(|entry| entry.unit_id == app_id)
            .expect("changed app entry");
        assert!(
            app_entry
                .reasons
                .contains(&AnalysisInvalidationReason::ManifestChanged)
        );
        assert!(
            app_entry
                .reasons
                .contains(&AnalysisInvalidationReason::DependencyChanged)
        );
        let target_entry = invalidation
            .entries
            .iter()
            .find(|entry| entry.unit_id == target_id)
            .expect("dependent target entry");
        assert!(
            target_entry
                .reasons
                .contains(&AnalysisInvalidationReason::DependencyChanged)
        );
        let target_two_entry = invalidation
            .entries
            .iter()
            .find(|entry| entry.unit_id == target_two_id)
            .expect("dependent target entry");
        assert!(
            target_two_entry
                .reasons
                .contains(&AnalysisInvalidationReason::DependencyChanged)
        );
        Ok(())
    }

    #[test]
    fn source_and_unknown_dependency_changes_produce_explainable_invalidation() -> Result<()> {
        let root = tempfile::tempdir()?;
        polyglot_fixture(root.path())?;
        let before = discover_analysis_plan(root.path(), &Config::default(), &input())?;
        fs::write(
            root.path().join("services/a/a.go"),
            "package a\n\nimport \"unknown.example/dep\"\n",
        )?;
        let after = discover_analysis_plan(root.path(), &Config::default(), &input())?;
        let invalidation = after.invalidation_from(&before)?;
        assert!(!invalidation.invalidated_unit_ids.is_empty());
        assert!(
            invalidation
                .entries
                .iter()
                .flat_map(|entry| entry.reasons.iter())
                .any(|reason| *reason == AnalysisInvalidationReason::SourceChanged)
        );
        assert!(
            invalidation
                .entries
                .iter()
                .flat_map(|entry| entry.reasons.iter())
                .any(|reason| *reason == AnalysisInvalidationReason::UnknownDependency)
        );
        Ok(())
    }

    #[test]
    fn plan_analysis_units_ignores_store_path() -> Result<()> {
        let root = tempfile::tempdir()?;
        polyglot_fixture(root.path())?;
        let store = root.path().join("outside-state/custom.json");
        fs::create_dir_all(store.parent().expect("store parent"))?;
        fs::write(&store, "store state v1")?;
        fs::write(format!("{}-wal", store.display()), "wal v1")?;
        fs::write(format!("{}-shm", store.display()), "shm v1")?;
        let first = plan_analysis_units(root.path(), &Config::default(), Some(&store))?;
        fs::write(&store, "store state v2")?;
        fs::write(format!("{}-wal", store.display()), "wal v2")?;
        fs::write(format!("{}-shm", store.display()), "shm v2")?;
        let second = plan_analysis_units(root.path(), &Config::default(), Some(&store))?;
        assert_eq!(first.input_digest, second.input_digest);
        assert_eq!(first.plan_id, second.plan_id);
        let sqlite_store = root.path().join("outside-state/custom.sqlite");
        let exclusions = store_exclusion_paths(root.path(), Some(&sqlite_store));
        assert!(exclusions.contains("outside-state/custom.sqlite"));
        assert!(exclusions.contains("outside-state/custom.sqlite-wal"));
        assert!(exclusions.contains("outside-state/custom.sqlite-shm"));
        Ok(())
    }

    #[test]
    fn malformed_input_fails_closed() {
        assert!(validate_repository_path("unit root", "../escape").is_err());
        assert!(
            AnalysisPlanInput::new(["profile"], "")
                .canonicalized()
                .is_err()
        );
    }
}
