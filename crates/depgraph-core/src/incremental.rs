use std::collections::{BTreeMap, BTreeSet, VecDeque};

use anyhow::{Result, bail};
use depgraph_store::{GraphSnapshot, IncrementalReplacementScope, NodeRecord, ProfileRecord};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const INCREMENTAL_PLAN_SCHEMA_VERSION: &str = "incremental-plan-v2";
const MAX_CHANGES: usize = 100_000;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum IncrementalChangeKind {
    Added,
    Modified,
    Deleted,
    Renamed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct IncrementalFileChange {
    pub kind: IncrementalChangeKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub old_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_path: Option<String>,
}

impl IncrementalFileChange {
    pub fn added(path: impl Into<String>) -> Self {
        Self {
            kind: IncrementalChangeKind::Added,
            old_path: None,
            new_path: Some(path.into()),
        }
    }

    pub fn modified(path: impl Into<String>) -> Self {
        Self {
            kind: IncrementalChangeKind::Modified,
            old_path: None,
            new_path: Some(path.into()),
        }
    }

    pub fn deleted(path: impl Into<String>) -> Self {
        Self {
            kind: IncrementalChangeKind::Deleted,
            old_path: Some(path.into()),
            new_path: None,
        }
    }

    pub fn renamed(old_path: impl Into<String>, new_path: impl Into<String>) -> Self {
        Self {
            kind: IncrementalChangeKind::Renamed,
            old_path: Some(old_path.into()),
            new_path: Some(new_path.into()),
        }
    }

    fn normalized(&self) -> Result<Self> {
        let old_path = self.old_path.as_deref().map(normalize_path).transpose()?;
        let new_path = self.new_path.as_deref().map(normalize_path).transpose()?;
        let valid = match self.kind {
            IncrementalChangeKind::Added | IncrementalChangeKind::Modified => {
                old_path.is_none() && new_path.is_some()
            }
            IncrementalChangeKind::Deleted => old_path.is_some() && new_path.is_none(),
            IncrementalChangeKind::Renamed => {
                old_path.is_some() && new_path.is_some() && old_path != new_path
            }
        };
        if !valid {
            bail!("incremental file change does not match its change kind");
        }
        Ok(Self {
            kind: self.kind,
            old_path,
            new_path,
        })
    }

    fn paths(&self) -> impl Iterator<Item = &str> {
        self.old_path
            .iter()
            .chain(&self.new_path)
            .map(String::as_str)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IncrementalInvalidationMode {
    ScopedReplacement,
    WorkspaceReplan,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum IncrementalInvalidationReason {
    SourceChanged,
    ManifestChanged,
    LockfileChanged,
    ConfigChanged,
    GeneratedInputChanged,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IncrementalInvalidationPlan {
    pub schema_version: String,
    pub base_snapshot_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_profile_plan_id: Option<String>,
    pub mode: IncrementalInvalidationMode,
    pub changes: Vec<IncrementalFileChange>,
    pub reasons: Vec<IncrementalInvalidationReason>,
    pub affected_package_locators: Vec<String>,
    pub affected_profile_ids: Vec<String>,
    pub affected_generated_artifact_ids: Vec<String>,
    pub replacement_scope: IncrementalReplacementScope,
}

#[derive(Debug, Clone)]
struct PackageInfo {
    node_id: String,
    locator: String,
    aliases: BTreeSet<String>,
    directory: String,
    ecosystem: String,
}

#[derive(Default)]
struct PackageIndex {
    packages: Vec<PackageInfo>,
    by_node: BTreeMap<String, String>,
    by_alias: BTreeMap<String, String>,
}

impl PackageIndex {
    fn new(snapshot: &GraphSnapshot) -> Self {
        let mut packages = snapshot
            .nodes
            .iter()
            .filter(|node| node.kind == "package_instance")
            .map(package_info)
            .collect::<Vec<_>>();
        packages.sort_by(|left, right| left.locator.cmp(&right.locator));
        let mut index = Self {
            packages,
            ..Self::default()
        };
        for package in &index.packages {
            index
                .by_node
                .insert(package.node_id.clone(), package.locator.clone());
            for alias in &package.aliases {
                index
                    .by_alias
                    .entry(alias.clone())
                    .or_insert_with(|| package.locator.clone());
            }
        }
        index
    }

    fn for_path(&self, path: &str) -> Option<&str> {
        self.packages
            .iter()
            .filter(|package| path_is_within(path, &package.directory))
            .max_by_key(|package| package.directory.len())
            .map(|package| package.locator.as_str())
    }

    fn for_node(&self, node: &NodeRecord) -> Option<&str> {
        if let Some(locator) = self.by_node.get(&node.id) {
            return Some(locator);
        }
        for key in ["package_locator", "package_id", "module_path"] {
            if let Some(value) = node.properties.get(key).and_then(Value::as_str)
                && let Some(locator) = self.by_alias.get(value)
            {
                return Some(locator);
            }
        }
        node_paths(node).find_map(|path| self.for_path(path))
    }

    fn ecosystem(&self, locator: &str) -> Option<&str> {
        self.packages
            .iter()
            .find(|package| package.locator == locator)
            .map(|package| package.ecosystem.as_str())
    }

    fn aliases(&self, locators: &BTreeSet<String>) -> BTreeSet<String> {
        self.packages
            .iter()
            .filter(|package| locators.contains(&package.locator))
            .flat_map(|package| package.aliases.iter().cloned())
            .collect()
    }

    fn for_ecosystem(&self, ecosystem: &str) -> BTreeSet<String> {
        self.packages
            .iter()
            .filter(|package| package.ecosystem == ecosystem)
            .map(|package| package.locator.clone())
            .collect()
    }

    fn all(&self) -> BTreeSet<String> {
        self.packages
            .iter()
            .map(|package| package.locator.clone())
            .collect()
    }
}

pub fn plan_incremental_invalidation(
    base_snapshot_id: &str,
    snapshot: &GraphSnapshot,
    changes: &[IncrementalFileChange],
) -> Result<IncrementalInvalidationPlan> {
    validate_identity("base snapshot ID", base_snapshot_id)?;
    if changes.is_empty() || changes.len() > MAX_CHANGES {
        bail!("incremental plan requires between 1 and {MAX_CHANGES} file changes");
    }
    let mut changes = changes
        .iter()
        .map(IncrementalFileChange::normalized)
        .collect::<Result<Vec<_>>>()?;
    changes.sort();
    changes.dedup();

    let packages = PackageIndex::new(snapshot);
    let base_profile_plan_id = snapshot_profile_plan_id(snapshot)?;
    let nodes = snapshot
        .nodes
        .iter()
        .map(|node| (node.id.as_str(), node))
        .collect::<BTreeMap<_, _>>();
    let sites = snapshot
        .sites
        .iter()
        .map(|site| (site.id.as_str(), site))
        .collect::<BTreeMap<_, _>>();
    let edges = snapshot
        .edges
        .iter()
        .map(|edge| (edge.id.as_str(), edge))
        .collect::<BTreeMap<_, _>>();

    let changed_paths = changes
        .iter()
        .flat_map(IncrementalFileChange::paths)
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    let mut affected_packages = BTreeSet::new();
    let mut reasons = BTreeSet::new();
    let mut replan = false;

    for path in &changed_paths {
        if let Some(locator) = packages.for_path(path) {
            affected_packages.insert(locator.to_owned());
        }
        match classify_control_path(path) {
            ControlPath::Source => {
                reasons.insert(IncrementalInvalidationReason::SourceChanged);
            }
            ControlPath::Manifest(ecosystem) => {
                reasons.insert(IncrementalInvalidationReason::ManifestChanged);
                replan = true;
                if packages.for_path(path).is_none() {
                    affected_packages.extend(packages.for_ecosystem(ecosystem));
                }
            }
            ControlPath::Lockfile(ecosystem) => {
                reasons.insert(IncrementalInvalidationReason::LockfileChanged);
                replan = true;
                affected_packages.extend(packages.for_ecosystem(ecosystem));
            }
            ControlPath::Config(ecosystem) => {
                reasons.insert(IncrementalInvalidationReason::ConfigChanged);
                replan = true;
                affected_packages.extend(
                    ecosystem.map_or_else(|| packages.all(), |value| packages.for_ecosystem(value)),
                );
            }
        }
    }

    for node in &snapshot.nodes {
        if node_paths(node).any(|path| changed_paths.contains(path))
            && let Some(locator) = packages.for_node(node)
        {
            affected_packages.insert(locator.to_owned());
        }
    }
    for evidence in &snapshot.evidence {
        if !changed_paths.contains(&evidence.path) {
            continue;
        }
        for node_id in evidence_owner_nodes(
            evidence.owner_type.as_str(),
            &evidence.owner_id,
            &sites,
            &edges,
        ) {
            if let Some(node) = nodes.get(node_id.as_str())
                && let Some(locator) = packages.for_node(node)
            {
                affected_packages.insert(locator.to_owned());
            }
        }
    }

    propagate_reverse_dependencies(snapshot, &packages, &nodes, &mut affected_packages);
    let affected_profiles = affected_profiles(snapshot, &packages, &affected_packages);
    let generated_nodes = generated_node_ids(snapshot);
    let affected_artifacts = affected_generated_artifacts(
        snapshot,
        &packages,
        &nodes,
        &sites,
        &edges,
        &changed_paths,
        &affected_packages,
        &affected_profiles,
        &generated_nodes,
    );
    if !affected_artifacts.is_empty() {
        reasons.insert(IncrementalInvalidationReason::GeneratedInputChanged);
    }

    let mut replacement_paths = changed_paths;
    collect_replacement_paths(
        snapshot,
        &packages,
        &affected_packages,
        &affected_artifacts,
        &mut replacement_paths,
    );
    let adapters = affected_profiles
        .iter()
        .filter_map(|profile_id| {
            snapshot
                .profiles
                .iter()
                .find(|profile| &profile.id == profile_id)
        })
        .map(|profile| adapter_for_language(&profile.language).to_owned())
        .collect::<BTreeSet<_>>();
    let replanned_profiles = if replan {
        affected_profiles.clone()
    } else {
        BTreeSet::new()
    };
    let replacement_scope = IncrementalReplacementScope::new(
        replacement_paths,
        packages.aliases(&affected_packages),
        affected_profiles.iter().cloned(),
        replanned_profiles,
        affected_artifacts.iter().cloned(),
        adapters,
    )?;

    Ok(IncrementalInvalidationPlan {
        schema_version: INCREMENTAL_PLAN_SCHEMA_VERSION.to_owned(),
        base_snapshot_id: base_snapshot_id.to_owned(),
        base_profile_plan_id,
        mode: if replan {
            IncrementalInvalidationMode::WorkspaceReplan
        } else {
            IncrementalInvalidationMode::ScopedReplacement
        },
        changes,
        reasons: reasons.into_iter().collect(),
        affected_package_locators: affected_packages.into_iter().collect(),
        affected_profile_ids: affected_profiles.into_iter().collect(),
        affected_generated_artifact_ids: affected_artifacts.into_iter().collect(),
        replacement_scope,
    })
}

pub fn snapshot_profile_plan_id(snapshot: &GraphSnapshot) -> Result<Option<String>> {
    profile_plan_id_from_properties(snapshot.profiles.iter().map(|profile| &profile.properties))
}

pub(crate) fn profile_records_profile_plan_id(
    profiles: &[ProfileRecord],
) -> Result<Option<String>> {
    profile_plan_id_from_properties(profiles.iter().map(|profile| &profile.properties))
}

fn profile_plan_id_from_properties<'a>(
    properties: impl IntoIterator<Item = &'a Value>,
) -> Result<Option<String>> {
    let mut ids = BTreeSet::new();
    let mut missing = false;
    for properties in properties {
        match properties
            .get("profile_selection_plan_id")
            .and_then(Value::as_str)
        {
            Some(id)
                if id
                    .strip_prefix("profile-selection-plan:sha256:")
                    .is_some_and(|digest| {
                        digest.len() == 64
                            && digest
                                .bytes()
                                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                    }) =>
            {
                ids.insert(id.to_owned());
            }
            Some(_) => bail!("snapshot profile selection plan ID is malformed"),
            None => missing = true,
        }
    }
    if ids.len() > 1 || (missing && !ids.is_empty()) {
        bail!("snapshot profiles do not share one profile selection plan ID");
    }
    Ok(ids.into_iter().next())
}

fn package_info(node: &NodeRecord) -> PackageInfo {
    let manifest = node.properties.get("manifest_path").and_then(Value::as_str);
    let directory = manifest
        .and_then(|path| path.rsplit_once('/').map(|(directory, _)| directory))
        .or_else(|| {
            node.properties
                .get("workspace_path")
                .or_else(|| node.properties.get("relative_dir"))
                .and_then(Value::as_str)
        })
        .filter(|directory| *directory != ".")
        .unwrap_or_default()
        .to_owned();
    let ecosystem = node
        .properties
        .get("ecosystem")
        .and_then(Value::as_str)
        .map(normalize_ecosystem)
        .or_else(|| manifest.and_then(manifest_ecosystem))
        .or_else(|| {
            node.properties
                .get("package_manager")
                .and_then(Value::as_str)
                .map(|_| "web")
        })
        .unwrap_or("unknown")
        .to_owned();
    let mut aliases = BTreeSet::from([node.locator.clone(), node.id.clone()]);
    for key in ["locator", "module_path"] {
        if let Some(value) = node.properties.get(key).and_then(Value::as_str) {
            aliases.insert(value.to_owned());
        }
    }
    PackageInfo {
        node_id: node.id.clone(),
        locator: node.locator.clone(),
        aliases,
        directory,
        ecosystem,
    }
}

fn normalize_ecosystem(value: &str) -> &str {
    match value {
        "cargo" | "rust" => "rust",
        "go" | "gomod" => "go",
        "npm" | "pnpm" | "yarn" | "bun" | "web" => "web",
        other => other,
    }
}

fn manifest_ecosystem(path: &str) -> Option<&'static str> {
    match path.rsplit('/').next().unwrap_or(path) {
        "Cargo.toml" => Some("rust"),
        "go.mod" => Some("go"),
        "package.json" => Some("web"),
        _ => None,
    }
}

enum ControlPath {
    Source,
    Manifest(&'static str),
    Lockfile(&'static str),
    Config(Option<&'static str>),
}

fn classify_control_path(path: &str) -> ControlPath {
    let name = path.rsplit('/').next().unwrap_or(path);
    if let Some(ecosystem) = manifest_ecosystem(path) {
        return ControlPath::Manifest(ecosystem);
    }
    if matches!(path, ".cargo/config" | ".cargo/config.toml")
        || path.ends_with("/.cargo/config")
        || path.ends_with("/.cargo/config.toml")
    {
        return ControlPath::Config(Some("rust"));
    }
    match name {
        "Cargo.lock" => ControlPath::Lockfile("rust"),
        "go.sum" | "go.work" | "go.work.sum" => ControlPath::Lockfile("go"),
        "package-lock.json"
        | "npm-shrinkwrap.json"
        | "pnpm-lock.yaml"
        | "yarn.lock"
        | "bun.lock"
        | "bun.lockb" => ControlPath::Lockfile("web"),
        ".depgraph.toml" => ControlPath::Config(None),
        "rust-toolchain" | "rust-toolchain.toml" => ControlPath::Config(Some("rust")),
        _ if name == "tsconfig.json"
            || name == "jsconfig.json"
            || name.starts_with("tsconfig.")
            || name.starts_with("next.config.")
            || name.starts_with("astro.config.")
            || name.starts_with("vite.config.")
            || name.starts_with("svelte.config.") =>
        {
            ControlPath::Config(Some("web"))
        }
        _ => ControlPath::Source,
    }
}

fn propagate_reverse_dependencies(
    snapshot: &GraphSnapshot,
    packages: &PackageIndex,
    nodes: &BTreeMap<&str, &NodeRecord>,
    affected: &mut BTreeSet<String>,
) {
    let mut reverse = BTreeMap::<String, BTreeSet<String>>::new();
    for edge in &snapshot.edges {
        let Some(source) = nodes
            .get(edge.source.as_str())
            .and_then(|node| packages.for_node(node))
        else {
            continue;
        };
        let Some(target) = nodes
            .get(edge.target.as_str())
            .and_then(|node| packages.for_node(node))
        else {
            continue;
        };
        if source != target {
            reverse
                .entry(target.to_owned())
                .or_default()
                .insert(source.to_owned());
        }
    }
    let mut queue = affected.iter().cloned().collect::<VecDeque<_>>();
    while let Some(package) = queue.pop_front() {
        for dependent in reverse.get(&package).into_iter().flatten() {
            if affected.insert(dependent.clone()) {
                queue.push_back(dependent.clone());
            }
        }
    }
}

fn affected_profiles(
    snapshot: &GraphSnapshot,
    packages: &PackageIndex,
    affected: &BTreeSet<String>,
) -> BTreeSet<String> {
    snapshot
        .profiles
        .iter()
        .filter(|profile| {
            let associations = ["package_locator", "package_id"]
                .into_iter()
                .filter_map(|key| profile.properties.get(key).and_then(Value::as_str))
                .filter_map(|alias| packages.by_alias.get(alias))
                .collect::<Vec<_>>();
            if associations.is_empty() {
                affected.iter().any(|locator| {
                    packages
                        .ecosystem(locator)
                        .is_some_and(|ecosystem| language_matches(&profile.language, ecosystem))
                })
            } else {
                associations
                    .into_iter()
                    .any(|locator| affected.contains(locator))
            }
        })
        .map(|profile| profile.id.clone())
        .collect()
}

fn generated_node_ids(snapshot: &GraphSnapshot) -> BTreeSet<String> {
    let mut generated = snapshot
        .nodes
        .iter()
        .filter(|node| {
            matches!(
                node.kind.as_str(),
                "route" | "generated_artifact" | "generated_module_initializer"
            ) || node
                .properties
                .get("generated")
                .and_then(Value::as_bool)
                .unwrap_or(false)
                || node
                    .properties
                    .get("build_generated")
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
        })
        .map(|node| node.id.clone())
        .collect::<BTreeSet<_>>();
    for edge in &snapshot.edges {
        if edge.generated {
            generated.insert(edge.target.clone());
        }
    }
    generated
}

#[allow(clippy::too_many_arguments)]
fn affected_generated_artifacts(
    snapshot: &GraphSnapshot,
    packages: &PackageIndex,
    nodes: &BTreeMap<&str, &NodeRecord>,
    sites: &BTreeMap<&str, &depgraph_store::SiteRecord>,
    edges: &BTreeMap<&str, &depgraph_store::EdgeRecord>,
    changed_paths: &BTreeSet<String>,
    affected_packages: &BTreeSet<String>,
    affected_profiles: &BTreeSet<String>,
    generated: &BTreeSet<String>,
) -> BTreeSet<String> {
    let mut affected = generated
        .iter()
        .filter(|id| {
            nodes.get(id.as_str()).is_some_and(|node| {
                let ownership_matches = packages.for_node(node).map_or_else(
                    || {
                        node.properties
                            .get("profile_id")
                            .and_then(Value::as_str)
                            .is_some_and(|profile| affected_profiles.contains(profile))
                    },
                    |package| affected_packages.contains(package),
                );
                ownership_matches || node_paths(node).any(|path| changed_paths.contains(path))
            })
        })
        .cloned()
        .collect::<BTreeSet<_>>();
    for evidence in &snapshot.evidence {
        if changed_paths.contains(&evidence.path) {
            affected.extend(
                evidence_owner_nodes(&evidence.owner_type, &evidence.owner_id, sites, edges)
                    .into_iter()
                    .filter(|id| generated.contains(id)),
            );
        }
    }
    affected
}

fn collect_replacement_paths(
    snapshot: &GraphSnapshot,
    packages: &PackageIndex,
    affected_packages: &BTreeSet<String>,
    affected_artifacts: &BTreeSet<String>,
    paths: &mut BTreeSet<String>,
) {
    let affected_nodes = snapshot
        .nodes
        .iter()
        .filter(|node| {
            affected_artifacts.contains(&node.id)
                || packages
                    .for_node(node)
                    .is_some_and(|package| affected_packages.contains(package))
        })
        .map(|node| node.id.as_str())
        .collect::<BTreeSet<_>>();
    for node in &snapshot.nodes {
        if affected_nodes.contains(node.id.as_str()) {
            for path in node_paths(node) {
                insert_graph_path(paths, path);
            }
        }
    }
    let affected_sites = snapshot
        .sites
        .iter()
        .filter(|site| affected_nodes.contains(site.source.as_str()))
        .map(|site| site.id.as_str())
        .collect::<BTreeSet<_>>();
    let affected_edges = snapshot
        .edges
        .iter()
        .filter(|edge| {
            affected_nodes.contains(edge.source.as_str())
                || affected_nodes.contains(edge.target.as_str())
                || edge
                    .site_id
                    .as_deref()
                    .is_some_and(|site| affected_sites.contains(site))
        })
        .map(|edge| edge.id.as_str())
        .collect::<BTreeSet<_>>();
    for evidence in &snapshot.evidence {
        let owned = match evidence.owner_type.as_str() {
            "node" => affected_nodes.contains(evidence.owner_id.as_str()),
            "site" => affected_sites.contains(evidence.owner_id.as_str()),
            "edge" => affected_edges.contains(evidence.owner_id.as_str()),
            _ => false,
        };
        if owned {
            insert_graph_path(paths, &evidence.path);
        }
    }
    for coverage in &snapshot.file_coverage {
        if packages
            .for_path(&coverage.path)
            .is_some_and(|package| affected_packages.contains(package))
        {
            insert_graph_path(paths, &coverage.path);
        }
    }
}

fn evidence_owner_nodes(
    owner_type: &str,
    owner_id: &str,
    sites: &BTreeMap<&str, &depgraph_store::SiteRecord>,
    edges: &BTreeMap<&str, &depgraph_store::EdgeRecord>,
) -> Vec<String> {
    match owner_type {
        "node" => vec![owner_id.to_owned()],
        "site" => sites
            .get(owner_id)
            .map(|site| vec![site.source.clone()])
            .unwrap_or_default(),
        "edge" => edges
            .get(owner_id)
            .map(|edge| vec![edge.source.clone(), edge.target.clone()])
            .unwrap_or_default(),
        _ => Vec::new(),
    }
}

fn node_paths(node: &NodeRecord) -> impl Iterator<Item = &str> {
    const KEYS: &[&str] = &[
        "path",
        "source_path",
        "manifest_path",
        "relative_path",
        "logical_path",
    ];
    KEYS.iter()
        .filter_map(|key| node.properties.get(*key).and_then(Value::as_str))
        .chain((node.kind == "file").then_some(node.display_name.as_str()))
}

fn language_matches(language: &str, ecosystem: &str) -> bool {
    match ecosystem {
        "rust" => language == "rust",
        "go" => language == "go",
        "web" => matches!(language, "web" | "typescript" | "javascript"),
        other => language == other,
    }
}

fn adapter_for_language(language: &str) -> &str {
    match language {
        "rust" => "rust",
        "go" => "go",
        "web" | "typescript" | "javascript" => "web",
        other => other,
    }
}

fn path_is_within(path: &str, directory: &str) -> bool {
    directory.is_empty()
        || path == directory
        || path
            .strip_prefix(directory)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

fn insert_graph_path(paths: &mut BTreeSet<String>, path: &str) {
    if let Ok(path) = normalize_path(path) {
        paths.insert(path);
    }
}

fn normalize_path(path: &str) -> Result<String> {
    let path = path.replace('\\', "/");
    if path.is_empty()
        || path.starts_with('/')
        || path.ends_with('/')
        || path.len() > 4_096
        || path.contains(':')
        || path.chars().any(char::is_control)
        || path
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        bail!("incremental path must be a canonical repository-relative path");
    }
    Ok(path)
}

fn validate_identity(name: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() || value.len() > 2_048 || value.chars().any(char::is_control) {
        bail!("incremental {name} must be a bounded printable value");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use depgraph_store::{
        CoverageRecord, EdgeRecord, EvidenceRecord, ProfileMatrixRecord, ProfileRecord, ScanRecord,
    };
    use serde_json::json;

    fn package(id: &str, locator: &str, manifest: &str, ecosystem: &str) -> NodeRecord {
        NodeRecord {
            id: id.to_owned(),
            kind: "package_instance".to_owned(),
            locator: locator.to_owned(),
            display_name: id.to_owned(),
            properties: json!({"manifest_path":manifest,"ecosystem":ecosystem}),
        }
    }

    fn file(id: &str, path: &str, package: &str) -> NodeRecord {
        NodeRecord {
            id: id.to_owned(),
            kind: "file".to_owned(),
            locator: format!("file:{path}"),
            display_name: path.to_owned(),
            properties: json!({"path":path,"package_locator":package}),
        }
    }

    fn profile(id: &str, language: &str, package: &str) -> ProfileRecord {
        ProfileRecord {
            id: id.to_owned(),
            language: language.to_owned(),
            toolchain: None,
            command: None,
            target: None,
            features: Vec::new(),
            environment: json!({}),
            source_revision: None,
            properties: json!({"package_locator":package}),
            coverage: None,
        }
    }

    fn edge(id: &str, source: &str, target: &str, profile_id: &str, generated: bool) -> EdgeRecord {
        EdgeRecord {
            id: id.to_owned(),
            site_id: None,
            source: source.to_owned(),
            target: target.to_owned(),
            kind: "depends_on".to_owned(),
            phase: "semantic".to_owned(),
            environment: "any".to_owned(),
            profile_id: profile_id.to_owned(),
            resolution_status: "resolved".to_owned(),
            precision: "exact".to_owned(),
            condition: json!({"op":"all","conditions":[]}),
            generated,
        }
    }

    fn snapshot() -> GraphSnapshot {
        let generated = NodeRecord {
            id: "generated:b".to_owned(),
            kind: "generated_artifact".to_owned(),
            locator: "generated:b".to_owned(),
            display_name: "generated b".to_owned(),
            properties: json!({"generated":true,"package_locator":"cargo:b@1#b","profile_id":"rust:b"}),
        };
        GraphSnapshot {
            scan: ScanRecord {
                id: "scan".to_owned(),
                root: "/fixture".to_owned(),
                status: "completed".to_owned(),
                strict: false,
                started_at: "2026-07-23T00:00:00.000Z".to_owned(),
                completed_at: Some("2026-07-23T00:00:01.000Z".to_owned()),
                project_code_executed: false,
                error: None,
            parent_snapshot_id: None,
            source_revision: None,
            health_policy_config_digest: None,
            health_analyzer_version: None,
            health_finding_contract_version: None,
        },
            profiles: vec![
                profile("rust:a", "rust", "cargo:a@1#a"),
                profile("rust:b", "rust", "cargo:b@1#b"),
                profile("rust:d", "rust", "cargo:d@1#d"),
                profile("web:c", "web", "web:c"),
            ],
            nodes: vec![
                package("package:a", "cargo:a@1#a", "a/Cargo.toml", "cargo"),
                package("package:b", "cargo:b@1#b", "b/Cargo.toml", "cargo"),
                package("package:c", "package://web:c", "c/package.json", "web"),
                package("package:d", "cargo:d@1#d", "d/Cargo.toml", "cargo"),
                file("file:a", "a/src/lib.rs", "cargo:a@1#a"),
                file("file:b", "b/src/lib.rs", "cargo:b@1#b"),
                file("file:c", "c/src/index.ts", "web:c"),
                file("file:d", "d/src/lib.rs", "cargo:d@1#d"),
                generated,
            ],
            sites: Vec::new(),
            edges: vec![
                edge(
                    "package-dependency",
                    "package:b",
                    "package:a",
                    "rust:b",
                    false,
                ),
                edge("generated-edge", "file:a", "generated:b", "rust:b", true),
            ],
            evidence: vec![EvidenceRecord {
                owner_type: "edge".to_owned(),
                owner_id: "generated-edge".to_owned(),
                ordinal: 0,
                kind: "source".to_owned(),
                extractor: "fixture".to_owned(),
                extractor_version: "1.0.0".to_owned(),
                path: "a/src/lib.rs".to_owned(),
                start_line: 1,
                start_column: 1,
                end_line: 1,
                end_column: 2,
                detail: None,
                properties: json!({}),
            }],
            diagnostics: Vec::new(),
            file_coverage: Vec::new(),
            adapter_logs: Vec::new(),
            coverage: CoverageRecord::default(),
            profile_matrix: ProfileMatrixRecord::default(),
        }
    }

    #[test]
    fn source_change_invalidates_only_owning_package_dependents_and_generated_artifacts() {
        let plan = plan_incremental_invalidation(
            "snapshot:base",
            &snapshot(),
            &[IncrementalFileChange::modified("a/src/lib.rs")],
        )
        .unwrap();
        assert_eq!(plan.mode, IncrementalInvalidationMode::ScopedReplacement);
        assert_eq!(
            plan.affected_package_locators,
            ["cargo:a@1#a", "cargo:b@1#b"]
        );
        assert_eq!(plan.affected_profile_ids, ["rust:a", "rust:b"]);
        assert_eq!(plan.affected_generated_artifact_ids, ["generated:b"]);
        assert!(plan.replacement_scope.replanned_profile_ids.is_empty());
        assert!(!plan.affected_profile_ids.contains(&"web:c".to_owned()));
        assert!(!plan.affected_profile_ids.contains(&"rust:d".to_owned()));
        assert!(
            !plan
                .replacement_scope
                .paths
                .contains(&"c/src/index.ts".to_owned())
        );
    }

    #[test]
    fn lockfile_and_global_config_replan_the_required_profiles() {
        let cargo = plan_incremental_invalidation(
            "snapshot:base",
            &snapshot(),
            &[IncrementalFileChange::modified("Cargo.lock")],
        )
        .unwrap();
        assert_eq!(cargo.mode, IncrementalInvalidationMode::WorkspaceReplan);
        assert_eq!(cargo.affected_profile_ids, ["rust:a", "rust:b", "rust:d"]);
        assert_eq!(
            cargo.replacement_scope.replanned_profile_ids,
            ["rust:a", "rust:b", "rust:d"]
        );

        let global = plan_incremental_invalidation(
            "snapshot:base",
            &snapshot(),
            &[IncrementalFileChange::modified(".depgraph.toml")],
        )
        .unwrap();
        assert_eq!(
            global.affected_profile_ids,
            ["rust:a", "rust:b", "rust:d", "web:c"]
        );
        assert_eq!(
            global.replacement_scope.replanned_profile_ids,
            global.affected_profile_ids
        );
    }

    #[test]
    fn profile_plan_binding_is_shared_or_the_incremental_plan_fails_closed() {
        let plan_id = format!("profile-selection-plan:sha256:{}", "a".repeat(64));
        let mut bound = snapshot();
        for profile in &mut bound.profiles {
            profile.properties["profile_selection_plan_id"] = json!(plan_id);
        }
        assert_eq!(
            snapshot_profile_plan_id(&bound).unwrap().as_deref(),
            Some(plan_id.as_str())
        );
        let plan = plan_incremental_invalidation(
            "snapshot:base",
            &bound,
            &[IncrementalFileChange::modified("a/src/lib.rs")],
        )
        .unwrap();
        assert_eq!(plan.base_profile_plan_id.as_deref(), Some(plan_id.as_str()));

        bound.profiles[0].properties["profile_selection_plan_id"] =
            json!(format!("profile-selection-plan:sha256:{}", "b".repeat(64)));
        assert!(snapshot_profile_plan_id(&bound).is_err());
        assert!(
            plan_incremental_invalidation(
                "snapshot:base",
                &bound,
                &[IncrementalFileChange::modified("a/src/lib.rs")],
            )
            .is_err()
        );
    }

    #[test]
    fn rename_is_canonical_and_retains_both_ownership_paths() {
        let plan = plan_incremental_invalidation(
            "snapshot:base",
            &snapshot(),
            &[
                IncrementalFileChange::renamed("a/src/lib.rs", "a/src/main.rs"),
                IncrementalFileChange::renamed("a/src/lib.rs", "a/src/main.rs"),
            ],
        )
        .unwrap();
        assert_eq!(plan.changes.len(), 1);
        assert!(
            plan.replacement_scope
                .paths
                .contains(&"a/src/lib.rs".to_owned())
        );
        assert!(
            plan.replacement_scope
                .paths
                .contains(&"a/src/main.rs".to_owned())
        );
    }
}
