//! Conservative, repository-local witness for Go semantic dependencies.
//!
//! A worker can discover the exact package files it loaded, but that happens
//! after a scan has started. The cache needs an input identity before it can
//! decide whether a completed semantic result is reusable. This module
//! records stable inputs that make an offline Go load eligible for reuse:
//! module requirements and replacements, workspace membership/replacements,
//! checksum files, and vendor manifests. A missing or ambiguous input makes
//! the witness unavailable, which deliberately disables semantic reuse.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Component, Path, PathBuf},
};

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::repository_inventory::build_repository_file_inventory;

pub(crate) const GO_DEPENDENCY_WITNESS_SCHEMA: &str = "depgraph-go-dependency-witness-v1";
const MAX_MANIFEST_BYTES: u64 = 8 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct GoDependencyWitness {
    status: String,
    fingerprint: String,
    reasons: Vec<String>,
}

impl GoDependencyWitness {
    pub(crate) fn status(&self) -> &str {
        &self.status
    }

    pub(crate) fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    /// not-applicable is cacheable because there is no external Go
    /// dependency input. complete is cacheable only after every declared
    /// dependency has a bounded offline witness.
    pub(crate) fn is_cacheable(&self) -> bool {
        matches!(self.status(), "complete" | "not-applicable")
    }

    #[allow(dead_code)]
    pub(crate) fn reasons(&self) -> &[String] {
        &self.reasons
    }
}

#[derive(Clone, Debug)]
struct Requirement {
    module: String,
    version: String,
}

#[derive(Clone, Debug)]
struct Replacement {
    old_module: String,
    old_version: Option<String>,
    new: ReplacementTarget,
}

#[derive(Clone, Debug)]
enum ReplacementTarget {
    Local(String),
    Remote {
        module: String,
        version: Option<String>,
    },
}

#[derive(Clone, Debug)]
struct ModuleManifest {
    path: String,
    module: Option<String>,
    requirements: Vec<Requirement>,
    replacements: Vec<Replacement>,
}

#[derive(Clone, Debug)]
struct WorkspaceManifest {
    path: String,
    uses: Vec<String>,
    replacements: Vec<Replacement>,
}

#[derive(Clone, Debug, Serialize)]
struct WitnessInput {
    path: String,
    digest: String,
}

#[derive(Clone, Debug, Serialize)]
struct WitnessRequirement {
    owner: String,
    module: String,
    version: String,
    resolution: String,
}

#[derive(Clone, Debug, Serialize)]
struct WitnessReplacement {
    owner: String,
    old_module: String,
    old_version: String,
    target: String,
}

#[derive(Clone, Debug, Serialize)]
struct WitnessPayload {
    schema: &'static str,
    status: String,
    inputs: Vec<WitnessInput>,
    requirements: Vec<WitnessRequirement>,
    replacements: Vec<WitnessReplacement>,
    reasons: Vec<String>,
}

/// Computes a deterministic witness from paths selected by the repository
/// inventory. An empty path list asks this function to discover the inventory
/// again; cache-hit validation uses that mode to observe newly created files.
pub(crate) fn compute_go_dependency_witness(
    root: &Path,
    inventory_paths: &[String],
) -> GoDependencyWitness {
    let canonical_root = match root.canonicalize() {
        Ok(path) if path.is_dir() => path,
        _ => return unavailable(vec!["repository-root-unavailable"]),
    };
    let paths = if inventory_paths.is_empty() {
        match build_repository_file_inventory(&canonical_root) {
            Ok(inventory) => inventory.paths,
            Err(_) => return unavailable(vec!["repository-inventory-unavailable"]),
        }
    } else {
        inventory_paths.to_owned()
    };
    let mut source = SourceReader::new(&canonical_root, paths);
    source.run()
}

/// Recomputes the witness used by cache-hit validation. Keeping this as a
/// separate name prevents callers from accidentally comparing a cache key
/// against a worker post-load snapshot.
pub(crate) fn recompute_go_dependency_witness(root: &Path) -> GoDependencyWitness {
    compute_go_dependency_witness(root, &[])
}

fn unavailable(reasons: Vec<&'static str>) -> GoDependencyWitness {
    let reasons = reasons.into_iter().map(str::to_owned).collect::<Vec<_>>();
    make_witness("unavailable", Vec::new(), Vec::new(), Vec::new(), reasons)
}

struct SourceReader<'a> {
    root: &'a Path,
    paths: Vec<String>,
    inputs: Vec<WitnessInput>,
    manifests: Vec<ModuleManifest>,
    workspace: Option<WorkspaceManifest>,
    checksums: BTreeSet<String>,
    vendored: BTreeMap<String, BTreeSet<String>>,
    vendor_source_witnesses: BTreeSet<(String, String)>,
    reasons: BTreeSet<String>,
}

impl<'a> SourceReader<'a> {
    fn new(root: &'a Path, mut paths: Vec<String>) -> Self {
        paths.sort();
        paths.dedup();
        Self {
            root,
            paths,
            inputs: Vec::new(),
            manifests: Vec::new(),
            workspace: None,
            checksums: BTreeSet::new(),
            vendored: BTreeMap::new(),
            vendor_source_witnesses: BTreeSet::new(),
            reasons: BTreeSet::new(),
        }
    }

    fn run(&mut self) -> GoDependencyWitness {
        let paths = self.paths.clone();
        for relative in paths {
            if !valid_relative_path(&relative) {
                self.reasons.insert("invalid-relative-path".to_owned());
                continue;
            }
            if relative == "go.work" {
                if let Some(contents) = self.read_input(&relative) {
                    let (workspace, malformed) = parse_go_work(&relative, &contents);
                    if malformed {
                        self.reasons.insert("workspace-manifest-invalid".to_owned());
                    }
                    self.workspace = Some(workspace);
                }
                continue;
            }
            if relative.ends_with("/go.mod") || relative == "go.mod" {
                if let Some(contents) = self.read_input(&relative) {
                    let (manifest, malformed) = parse_go_mod(&relative, &contents);
                    if malformed {
                        self.reasons.insert("module-manifest-invalid".to_owned());
                    }
                    self.manifests.push(manifest);
                }
                continue;
            }
            if relative.ends_with("/go.sum") || relative == "go.sum" {
                if let Some(contents) = self.read_input(&relative) {
                    self.parse_checksums(&contents);
                }
                continue;
            }
            if (relative == "vendor/modules.txt" || relative.ends_with("/vendor/modules.txt"))
                && let Some(contents) = self.read_input(&relative)
            {
                self.parse_vendor(&relative, &contents);
            }
        }
        // go.work.sum belongs to the root workspace. A nested module's
        // go.work.sum is not a root workspace input.
        if self.workspace.is_some()
            && let Some(contents) = self.read_input("go.work.sum")
        {
            self.parse_checksums(&contents);
        }
        self.validate_workspace_members();
        self.collect_vendor_source_witnesses();
        self.finish()
    }

    fn validate_workspace_members(&mut self) {
        let Some(workspace) = self.workspace.clone() else {
            return;
        };
        for use_path in workspace.uses {
            let Some(directory) = resolve_local_path(self.root, &workspace.path, &use_path) else {
                self.reasons
                    .insert("workspace-member-unavailable".to_owned());
                continue;
            };
            let relative = relative_path(self.root, &directory);
            let manifest_path = member_path(&relative);
            if !self
                .manifests
                .iter()
                .any(|manifest| manifest.path == manifest_path)
            {
                // A scoped witness must include every active workspace member
                // manifest. Otherwise a workspace replacement can be mistaken
                // for an ordinary remote requirement.
                self.reasons
                    .insert("workspace-member-manifest-unavailable".to_owned());
            }
        }
    }

    fn collect_vendor_source_witnesses(&mut self) {
        let vendored = self.vendored.clone();
        for (owner, modules) in vendored {
            for module_version in modules {
                let Some((module, _version)) = module_version.split_once('@') else {
                    self.reasons.insert("vendor-module-invalid".to_owned());
                    continue;
                };
                let prefix = vendor_source_prefix(&owner, module);
                let source_paths = self
                    .paths
                    .iter()
                    .filter(|path| {
                        path.starts_with(&prefix)
                            && path.ends_with(".go")
                            && valid_relative_path(path)
                    })
                    .cloned()
                    .collect::<Vec<_>>();
                if source_paths.is_empty() {
                    self.reasons.insert("vendor-source-unavailable".to_owned());
                    continue;
                }
                let mut available = true;
                for path in source_paths {
                    if self.read_input(&path).is_none() {
                        available = false;
                    }
                }
                if available {
                    self.vendor_source_witnesses
                        .insert((owner.clone(), module_version));
                } else {
                    self.reasons.insert("vendor-source-unavailable".to_owned());
                }
            }
        }
    }

    fn read_input(&mut self, relative: &str) -> Option<String> {
        let path = self.root.join(relative);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return None,
            Err(_) => {
                self.reasons
                    .insert("dependency-input-unreadable".to_owned());
                return None;
            }
        };
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            self.reasons
                .insert("dependency-input-not-regular".to_owned());
            return None;
        }
        if metadata.len() > MAX_MANIFEST_BYTES {
            self.reasons
                .insert("dependency-input-size-limit".to_owned());
            return None;
        }
        let bytes = match fs::read(&path) {
            Ok(bytes) if bytes.len() as u64 <= MAX_MANIFEST_BYTES => bytes,
            Ok(_) => {
                self.reasons
                    .insert("dependency-input-size-limit".to_owned());
                return None;
            }
            Err(_) => {
                self.reasons
                    .insert("dependency-input-unreadable".to_owned());
                return None;
            }
        };
        let text = match String::from_utf8(bytes.clone()) {
            Ok(text) => text,
            Err(_) => {
                self.reasons.insert("dependency-input-not-utf8".to_owned());
                return None;
            }
        };
        self.inputs.push(WitnessInput {
            path: relative.to_owned(),
            digest: digest_bytes(&bytes),
        });
        Some(text)
    }

    fn parse_checksums(&mut self, contents: &str) {
        for line in contents.lines() {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            if fields.len() == 3 && fields[2].starts_with("h1:") {
                let version = fields[1].trim_end_matches("/go.mod");
                self.checksums.insert(format!("{}@{}", fields[0], version));
            }
        }
    }

    fn parse_vendor(&mut self, relative: &str, contents: &str) {
        let owner = relative
            .strip_suffix("/vendor/modules.txt")
            .unwrap_or("")
            .to_owned();
        for line in contents.lines() {
            let line = line.trim();
            if line.starts_with("##") {
                continue;
            }
            let Some(rest) = line.strip_prefix('#') else {
                continue;
            };
            let fields = rest.split_whitespace().collect::<Vec<_>>();
            if fields.len() >= 2 {
                self.vendored
                    .entry(owner.clone())
                    .or_default()
                    .insert(format!("{}@{}", fields[0], fields[1]));
            }
        }
    }

    fn finish(&mut self) -> GoDependencyWitness {
        self.manifests
            .sort_by(|left, right| left.path.cmp(&right.path));
        self.inputs
            .sort_by(|left, right| left.path.cmp(&right.path));
        let has_manifest = !self.manifests.is_empty();
        let mut requirements = Vec::new();
        let mut replacements = Vec::new();
        let mut has_dependency = false;
        let member_paths = self.workspace_members();
        self.validate_replacement_ambiguity(&member_paths);

        let manifests = self.manifests.clone();
        for manifest in &manifests {
            let owner = manifest.path.clone();
            for requirement in &manifest.requirements {
                has_dependency = true;
                let replacement = effective_replacement(
                    manifest,
                    requirement,
                    self.workspace.as_ref(),
                    &member_paths,
                )
                .unwrap_or_else(|()| {
                    self.reasons.insert("replacement-ambiguous".to_owned());
                    None
                });
                let resolution = self.resolve_requirement(
                    manifest,
                    requirement,
                    replacement
                        .as_ref()
                        .map(|(replacement, owner)| (replacement, owner.as_str())),
                    &member_paths,
                );
                requirements.push(WitnessRequirement {
                    owner: owner.clone(),
                    module: requirement.module.clone(),
                    version: requirement.version.clone(),
                    resolution,
                });
            }
            for replacement in &manifest.replacements {
                has_dependency = true;
                replacements.push(self.witness_replacement(&manifest.path, replacement));
            }
        }
        if let Some(workspace) = self.workspace.clone() {
            for replacement in &workspace.replacements {
                has_dependency = true;
                replacements.push(self.witness_replacement(&workspace.path, replacement));
            }
        }
        if !self.checksums.is_empty() || !self.vendored.is_empty() {
            has_dependency = true;
        }
        if !has_manifest && self.workspace.is_none() {
            let status = if self.reasons.is_empty() {
                "not-applicable"
            } else {
                "unavailable"
            };
            return make_witness(
                status,
                self.inputs.clone(),
                requirements,
                replacements,
                self.reasons.iter().cloned().collect(),
            );
        }
        if self.workspace.as_ref().is_some_and(|workspace| {
            workspace
                .uses
                .iter()
                .any(|use_path| resolve_local_path(self.root, &workspace.path, use_path).is_none())
        }) {
            self.reasons
                .insert("workspace-member-unavailable".to_owned());
        }
        if self
            .manifests
            .iter()
            .any(|manifest| manifest.module.is_none())
        {
            self.reasons.insert("module-path-unavailable".to_owned());
        }
        if has_dependency && requirements.is_empty() {
            self.reasons
                .insert("dependency-resolution-unavailable".to_owned());
        }
        let status = if !self.reasons.is_empty() {
            "unavailable"
        } else if has_dependency {
            "complete"
        } else {
            "not-applicable"
        };
        make_witness(
            status,
            self.inputs.clone(),
            requirements,
            replacements,
            self.reasons.iter().cloned().collect(),
        )
    }

    fn validate_replacement_ambiguity(&mut self, member_paths: &BTreeMap<String, String>) {
        let manifests = self.manifests.clone();
        for manifest in &manifests {
            for requirement in &manifest.requirements {
                let workspace_matches = self
                    .workspace
                    .as_ref()
                    .filter(|_| member_paths.contains_key(&manifest.path))
                    .map(|workspace| matching_replacements(&workspace.replacements, requirement))
                    .unwrap_or_default();
                let module_matches = matching_replacements(&manifest.replacements, requirement);
                if replacement_set_is_ambiguous(&workspace_matches)
                    || (workspace_matches.is_empty()
                        && replacement_set_is_ambiguous(&module_matches))
                {
                    self.reasons.insert("replacement-ambiguous".to_owned());
                }
            }
        }
    }

    fn workspace_members(&self) -> BTreeMap<String, String> {
        let Some(workspace) = &self.workspace else {
            return BTreeMap::new();
        };
        let mut members = BTreeMap::new();
        for use_path in &workspace.uses {
            let Some(directory) = resolve_local_path(self.root, &workspace.path, use_path) else {
                continue;
            };
            let relative = relative_path(self.root, &directory);
            let manifest_path = member_path(&relative);
            if self
                .manifests
                .iter()
                .any(|manifest| manifest.path == manifest_path)
            {
                members.insert(manifest_path, relative);
            }
        }
        members
    }

    fn resolve_requirement(
        &mut self,
        manifest: &ModuleManifest,
        requirement: &Requirement,
        replacement: Option<(&Replacement, &str)>,
        member_paths: &BTreeMap<String, String>,
    ) -> String {
        if let Some((replacement, replacement_owner)) = replacement {
            match &replacement.new {
                ReplacementTarget::Local(path) => {
                    let Some(directory) = resolve_local_path(self.root, replacement_owner, path)
                    else {
                        self.reasons
                            .insert("local-replacement-outside-root".to_owned());
                        return "unavailable".to_owned();
                    };
                    let target = member_path(&relative_path(self.root, &directory));
                    if !self
                        .manifests
                        .iter()
                        .any(|candidate| candidate.path == target)
                    {
                        self.reasons
                            .insert("local-replacement-manifest-missing".to_owned());
                        return "unavailable".to_owned();
                    }
                    return format!("repo:{}", relative_path(self.root, &directory));
                }
                ReplacementTarget::Remote { module, version } => {
                    let Some(version) = version else {
                        self.reasons
                            .insert("remote-replacement-version-missing".to_owned());
                        return "unavailable".to_owned();
                    };
                    if !self.has_offline_module(module, version, manifest, member_paths) {
                        self.reasons
                            .insert("dependency-checksum-missing".to_owned());
                        return "unavailable".to_owned();
                    }
                    return format!("{module}@{version}");
                }
            }
        }
        if member_paths.contains_key(&manifest.path)
            && member_paths.keys().any(|path| {
                self.manifests
                    .iter()
                    .find(|candidate| &candidate.path == path)
                    .and_then(|candidate| candidate.module.as_deref())
                    == Some(requirement.module.as_str())
            })
        {
            return format!("workspace:{}", requirement.module);
        }
        if !self.has_offline_module(
            &requirement.module,
            &requirement.version,
            manifest,
            member_paths,
        ) {
            self.reasons
                .insert("dependency-checksum-missing".to_owned());
            return "unavailable".to_owned();
        }
        format!("{}@{}", requirement.module, requirement.version)
    }

    fn has_offline_module(
        &self,
        module: &str,
        version: &str,
        owner: &ModuleManifest,
        member_paths: &BTreeMap<String, String>,
    ) -> bool {
        if member_paths.contains_key(&owner.path)
            && member_paths.keys().any(|path| {
                self.manifests
                    .iter()
                    .find(|candidate| &candidate.path == path)
                    .and_then(|candidate| candidate.module.as_deref())
                    == Some(module)
            })
        {
            return true;
        }
        let key = format!("{module}@{version}");
        // A go.sum h1 line authenticates a module version, but it does not
        // prove that the exact module-cache bytes used by the prior scan are
        // still present. Only an inventory-visible vendor manifest is a
        // complete local source witness here. Runtime snapshots may extend
        // this set once their source files are persisted by the executor.
        self.vendored.iter().any(|(path, values)| {
            manifest_directory(&owner.path) == path
                && values.contains(&key)
                && self
                    .vendor_source_witnesses
                    .contains(&(path.clone(), key.clone()))
        })
    }

    fn witness_replacement(
        &mut self,
        owner_path: &str,
        replacement: &Replacement,
    ) -> WitnessReplacement {
        let target = match &replacement.new {
            ReplacementTarget::Local(path) => {
                let Some(directory) = resolve_local_path(self.root, owner_path, path) else {
                    self.reasons
                        .insert("local-replacement-outside-root".to_owned());
                    return WitnessReplacement {
                        owner: owner_path.to_owned(),
                        old_module: replacement.old_module.clone(),
                        old_version: replacement.old_version.clone().unwrap_or_default(),
                        target: "unavailable".to_owned(),
                    };
                };
                let relative = relative_path(self.root, &directory);
                if relative.is_empty() {
                    "repo:.".to_owned()
                } else {
                    format!("repo:{relative}")
                }
            }
            ReplacementTarget::Remote { module, version } => version
                .as_ref()
                .map(|version| format!("{module}@{version}"))
                .unwrap_or_else(|| {
                    self.reasons
                        .insert("remote-replacement-version-missing".to_owned());
                    "unavailable".to_owned()
                }),
        };
        WitnessReplacement {
            owner: owner_path.to_owned(),
            old_module: replacement.old_module.clone(),
            old_version: replacement.old_version.clone().unwrap_or_default(),
            target,
        }
    }
}

fn member_path(relative: &str) -> String {
    if relative.is_empty() {
        "go.mod".to_owned()
    } else {
        format!("{relative}/go.mod")
    }
}

fn manifest_directory(path: &str) -> &str {
    path.rsplit_once('/').map_or("", |(directory, _)| directory)
}

fn vendor_source_prefix(owner: &str, module: &str) -> String {
    let vendor_root = if owner.is_empty() {
        "vendor".to_owned()
    } else {
        format!("{}/vendor", owner)
    };
    format!("{}/{}/", vendor_root, escape_vendor_module_path(module))
}

// Go escapes uppercase module path elements in vendor directories with a
// leading ! followed by the lowercase letter. Requiring an exact escaped
// module prefix avoids treating an unrelated vendored package as proof for a
// declared dependency.
fn escape_vendor_module_path(module: &str) -> String {
    module
        .chars()
        .map(|character| {
            if character.is_ascii_uppercase() {
                format!("!{}", character.to_ascii_lowercase())
            } else {
                character.to_string()
            }
        })
        .collect()
}

fn effective_replacement(
    manifest: &ModuleManifest,
    requirement: &Requirement,
    workspace: Option<&WorkspaceManifest>,
    members: &BTreeMap<String, String>,
) -> Result<Option<(Replacement, String)>, ()> {
    let workspace_match = workspace
        .filter(|_| members.contains_key(&manifest.path))
        .map(|workspace| select_replacement(&workspace.replacements, requirement))
        .transpose()?
        .flatten()
        .cloned()
        .map(|replacement| (replacement, "go.work".to_owned()));
    if workspace_match.is_some() {
        return Ok(workspace_match);
    }
    Ok(select_replacement(&manifest.replacements, requirement)?
        .cloned()
        .map(|replacement| (replacement, manifest.path.clone())))
}

fn select_replacement<'a>(
    replacements: &'a [Replacement],
    requirement: &Requirement,
) -> Result<Option<&'a Replacement>, ()> {
    let exact = replacements
        .iter()
        .filter(|replacement| {
            replacement.old_module == requirement.module
                && replacement.old_version.as_deref() == Some(requirement.version.as_str())
        })
        .collect::<Vec<_>>();
    if exact.len() > 1 {
        return Err(());
    }
    if let Some(replacement) = exact.into_iter().next() {
        return Ok(Some(replacement));
    }
    let wildcard = replacements
        .iter()
        .filter(|replacement| {
            replacement.old_module == requirement.module && replacement.old_version.is_none()
        })
        .collect::<Vec<_>>();
    if wildcard.len() > 1 {
        return Err(());
    }
    Ok(wildcard.into_iter().next())
}

fn matching_replacements<'a>(
    replacements: &'a [Replacement],
    requirement: &Requirement,
) -> Vec<&'a Replacement> {
    replacements
        .iter()
        .filter(|replacement| {
            replacement.old_module == requirement.module
                && replacement
                    .old_version
                    .as_deref()
                    .is_none_or(|version| version == requirement.version)
        })
        .collect()
}

fn replacement_set_is_ambiguous(replacements: &[&Replacement]) -> bool {
    let exact = replacements
        .iter()
        .filter(|replacement| replacement.old_version.is_some())
        .count();
    let wildcard = replacements
        .iter()
        .filter(|replacement| replacement.old_version.is_none())
        .count();
    exact > 1 || (exact == 0 && wildcard > 1)
}

fn parse_go_mod(path: &str, text: &str) -> (ModuleManifest, bool) {
    let mut module = None;
    let mut requirements = Vec::new();
    let mut replacements = Vec::new();
    let mut malformed = false;
    let lines = text.lines().collect::<Vec<_>>();
    let mut index = 0;
    while index < lines.len() {
        let line = directive_line(lines[index]);
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.len() == 2 && fields[1] == "(" && fields[0] == "require" {
            let (entries, next, bad) = parse_require_block(&lines, index + 1);
            requirements.extend(entries);
            index = next;
            malformed |= bad;
        } else if fields.len() == 2 && fields[1] == "(" && fields[0] == "replace" {
            let (entries, next, bad) = parse_replace_block(&lines, index + 1);
            replacements.extend(entries);
            index = next;
            malformed |= bad;
        } else if fields.first() == Some(&"module") {
            module = fields.get(1).map(|value| (*value).to_owned());
        } else if fields.first() == Some(&"require") {
            if let Some(requirement) = parse_requirement(&fields[1..].join(" ")) {
                requirements.push(requirement);
            } else {
                malformed = true;
            }
        } else if fields.first() == Some(&"replace") {
            if let Some(replacement) = parse_replacement(&fields[1..].join(" ")) {
                replacements.push(replacement);
            } else {
                malformed = true;
            }
        }
        index += 1;
    }
    (
        ModuleManifest {
            path: path.to_owned(),
            module,
            requirements,
            replacements,
        },
        malformed,
    )
}

fn parse_go_work(path: &str, text: &str) -> (WorkspaceManifest, bool) {
    let mut uses = Vec::new();
    let mut replacements = Vec::new();
    let mut malformed = false;
    let lines = text.lines().collect::<Vec<_>>();
    let mut index = 0;
    while index < lines.len() {
        let line = directive_line(lines[index]);
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.len() == 2 && fields[1] == "(" && fields[0] == "use" {
            let (entries, next, bad) = parse_use_block(&lines, index + 1);
            uses.extend(entries);
            index = next;
            malformed |= bad;
        } else if fields.len() == 2 && fields[1] == "(" && fields[0] == "replace" {
            let (entries, next, bad) = parse_replace_block(&lines, index + 1);
            replacements.extend(entries);
            index = next;
            malformed |= bad;
        } else if fields.first() == Some(&"use") {
            if let Some(value) = parse_atom(&fields[1..].join(" ")) {
                uses.push(value);
            } else {
                malformed = true;
            }
        } else if fields.first() == Some(&"replace") {
            if let Some(replacement) = parse_replacement(&fields[1..].join(" ")) {
                replacements.push(replacement);
            } else {
                malformed = true;
            }
        }
        index += 1;
    }
    (
        WorkspaceManifest {
            path: path.to_owned(),
            uses,
            replacements,
        },
        malformed,
    )
}

fn parse_require_block(lines: &[&str], mut index: usize) -> (Vec<Requirement>, usize, bool) {
    let mut values = Vec::new();
    let mut malformed = false;
    while index < lines.len() {
        let line = directive_line(lines[index]);
        if line == ")" {
            return (values, index, malformed);
        }
        if !line.is_empty() {
            if let Some(requirement) = parse_requirement(&line) {
                values.push(requirement);
            } else {
                malformed = true;
            }
        }
        index += 1;
    }
    (values, index, true)
}

fn parse_use_block(lines: &[&str], mut index: usize) -> (Vec<String>, usize, bool) {
    let mut values = Vec::new();
    let mut malformed = false;
    while index < lines.len() {
        let line = directive_line(lines[index]);
        if line == ")" {
            return (values, index, malformed);
        }
        if !line.is_empty() {
            if let Some(value) = parse_atom(&line) {
                values.push(value);
            } else {
                malformed = true;
            }
        }
        index += 1;
    }
    (values, index, true)
}

fn parse_replace_block(lines: &[&str], mut index: usize) -> (Vec<Replacement>, usize, bool) {
    let mut values = Vec::new();
    let mut malformed = false;
    while index < lines.len() {
        let line = directive_line(lines[index]);
        if line == ")" {
            return (values, index, malformed);
        }
        if !line.is_empty() {
            if let Some(replacement) = parse_replacement(&line) {
                values.push(replacement);
            } else {
                malformed = true;
            }
        }
        index += 1;
    }
    (values, index, true)
}

fn parse_requirement(value: &str) -> Option<Requirement> {
    let fields = value.split_whitespace().collect::<Vec<_>>();
    (fields.len() >= 2).then(|| Requirement {
        module: fields[0].to_owned(),
        version: fields[1].to_owned(),
    })
}

fn parse_replacement(value: &str) -> Option<Replacement> {
    let (old, new) = value.split_once("=>")?;
    let old = old.split_whitespace().collect::<Vec<_>>();
    if old.is_empty() || old.len() > 2 {
        return None;
    }
    let new = new.split_whitespace().collect::<Vec<_>>();
    if new.is_empty() || new.len() > 2 {
        return None;
    }
    let target = if new[0].starts_with('.') || new[0].starts_with('/') || new[0].contains('\\') {
        (new.len() == 1).then(|| ReplacementTarget::Local(new[0].to_owned()))?
    } else {
        ReplacementTarget::Remote {
            module: new[0].to_owned(),
            version: (new.len() == 2).then(|| new[1].to_owned()),
        }
    };
    Some(Replacement {
        old_module: old[0].to_owned(),
        old_version: (old.len() == 2).then(|| old[1].to_owned()),
        new: target,
    })
}

fn directive_line(line: &str) -> String {
    let line = line.split_once("//").map_or(line, |(line, _)| line);
    line.trim().trim_matches('"').to_owned()
}

fn parse_atom(value: &str) -> Option<String> {
    let value = directive_line(value);
    let atom = value.split_whitespace().next()?.trim_matches('"');
    (!atom.is_empty()).then(|| atom.to_owned())
}

fn resolve_local_path(root: &Path, owner_path: &str, value: &str) -> Option<PathBuf> {
    let owner = if owner_path == "go.work" {
        root.to_path_buf()
    } else {
        root.join(owner_path).parent()?.to_path_buf()
    };
    let candidate = if Path::new(value).is_absolute() {
        PathBuf::from(value)
    } else {
        owner.join(value)
    };
    let metadata = fs::symlink_metadata(&candidate).ok()?;
    if metadata.file_type().is_symlink() {
        return None;
    }
    let canonical = candidate.canonicalize().ok()?;
    canonical.starts_with(root).then_some(canonical)
}

fn relative_path(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .components()
        .filter_map(|component| match component {
            Component::Normal(value) => value.to_str(),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("/")
}

fn valid_relative_path(path: &str) -> bool {
    !path.is_empty()
        && !path.contains('\\')
        && !path.chars().any(char::is_control)
        && Path::new(path)
            .components()
            .all(|component| matches!(component, Component::Normal(value) if !value.is_empty()))
}

fn digest_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"go-dependency-witness-input-v1\0");
    hasher.update(bytes);
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

fn make_witness(
    status: &str,
    mut inputs: Vec<WitnessInput>,
    mut requirements: Vec<WitnessRequirement>,
    mut replacements: Vec<WitnessReplacement>,
    mut reasons: Vec<String>,
) -> GoDependencyWitness {
    inputs.sort_by(|left, right| left.path.cmp(&right.path));
    requirements.sort_by(|left, right| {
        (&left.owner, &left.module, &left.version, &left.resolution).cmp(&(
            &right.owner,
            &right.module,
            &right.version,
            &right.resolution,
        ))
    });
    replacements.sort_by(|left, right| {
        (
            &left.owner,
            &left.old_module,
            &left.old_version,
            &left.target,
        )
            .cmp(&(
                &right.owner,
                &right.old_module,
                &right.old_version,
                &right.target,
            ))
    });
    reasons.sort();
    reasons.dedup();
    let payload = WitnessPayload {
        schema: GO_DEPENDENCY_WITNESS_SCHEMA,
        status: status.to_owned(),
        inputs,
        requirements,
        replacements,
        reasons: reasons.clone(),
    };
    let bytes = serde_json::to_vec(&payload).expect("witness payload is serializable");
    let mut hasher = Sha256::new();
    hasher.update(GO_DEPENDENCY_WITNESS_SCHEMA.as_bytes());
    hasher.update(b"\0");
    hasher.update(bytes);
    GoDependencyWitness {
        status: status.to_owned(),
        fingerprint: format!("sha256:{}", hex::encode(hasher.finalize())),
        reasons,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn witness(root: &Path) -> GoDependencyWitness {
        compute_go_dependency_witness(root, &[])
    }

    #[test]
    fn module_without_external_requirements_is_not_applicable() {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("go.mod"), "module example.test/app\n").unwrap();
        let result = witness(root.path());
        assert_eq!(result.status(), "not-applicable");
        assert!(result.is_cacheable());
    }

    #[test]
    fn malformed_scoped_inventory_cannot_be_cacheable_without_a_module() {
        let root = tempfile::tempdir().unwrap();
        let result = compute_go_dependency_witness(root.path(), &["../outside.go".to_owned()]);
        assert_eq!(result.status(), "unavailable");
        assert!(!result.is_cacheable());
        assert!(
            result
                .reasons()
                .iter()
                .any(|reason| reason == "invalid-relative-path")
        );
    }

    #[test]
    fn requirement_needs_checksum_or_vendor_witness() {
        let root = tempfile::tempdir().unwrap();
        fs::write(
            root.path().join("go.mod"),
            "module example.test/app\n\nrequire example.test/dep v1.2.3\n",
        )
        .unwrap();
        let result = witness(root.path());
        assert_eq!(result.status(), "unavailable");
        assert!(
            result
                .reasons()
                .iter()
                .any(|reason| reason == "dependency-checksum-missing")
        );
        fs::write(
            root.path().join("go.sum"),
            "example.test/dep v1.2.3 h1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=\n",
        )
        .unwrap();
        let result = witness(root.path());
        assert_eq!(result.status(), "unavailable");
        fs::create_dir_all(root.path().join("vendor")).unwrap();
        fs::write(
            root.path().join("vendor/modules.txt"),
            "# example.test/dep v1.2.3\n## explicit\nexample.test/dep\n",
        )
        .unwrap();
        fs::create_dir_all(root.path().join("vendor/example.test/dep")).unwrap();
        fs::write(
            root.path().join("vendor/example.test/dep/dep.go"),
            "package dep\n\nfunc Value() int { return 1 }\n",
        )
        .unwrap();
        let result = witness(root.path());
        assert_eq!(result.status(), "complete");
        assert!(result.is_cacheable());
    }

    #[test]
    fn scoped_workspace_witness_requires_every_active_member_manifest() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("app")).unwrap();
        fs::create_dir(root.path().join("shared")).unwrap();
        fs::write(
            root.path().join("go.work"),
            "go 1.23\nuse (\n ./app\n ./shared\n)\n",
        )
        .unwrap();
        fs::write(
            root.path().join("app/go.mod"),
            "module example.test/app\n\ngo 1.23\nrequire example.test/shared v0.0.0\n",
        )
        .unwrap();
        fs::write(
            root.path().join("shared/go.mod"),
            "module example.test/shared\n\ngo 1.23\n",
        )
        .unwrap();

        let incomplete = compute_go_dependency_witness(
            root.path(),
            &["go.work".to_owned(), "app/go.mod".to_owned()],
        );
        assert_eq!(incomplete.status(), "unavailable");
        assert!(
            incomplete
                .reasons()
                .iter()
                .any(|reason| reason == "workspace-member-manifest-unavailable")
        );

        let complete = compute_go_dependency_witness(
            root.path(),
            &[
                "app/go.mod".to_owned(),
                "go.work".to_owned(),
                "shared/go.mod".to_owned(),
            ],
        );
        assert_eq!(complete.status(), "complete");
        assert!(complete.is_cacheable());
    }

    #[test]
    fn vendor_source_content_is_part_of_the_witness() {
        let root = tempfile::tempdir().unwrap();
        fs::write(
            root.path().join("go.mod"),
            "module example.test/app\n\nrequire example.test/dep v1.2.3\n",
        )
        .unwrap();
        fs::create_dir_all(root.path().join("vendor/example.test/dep")).unwrap();
        fs::write(
            root.path().join("vendor/modules.txt"),
            "# example.test/dep v1.2.3\n## explicit\nexample.test/dep\n",
        )
        .unwrap();
        fs::write(
            root.path().join("vendor/example.test/dep/dep.go"),
            "package dep\n\nconst Value = 1\n",
        )
        .unwrap();
        let first = witness(root.path());
        assert_eq!(first.status(), "complete");
        fs::write(
            root.path().join("vendor/example.test/dep/dep.go"),
            "package dep\n\nconst Value = 2\n",
        )
        .unwrap();
        let second = witness(root.path());
        assert_eq!(second.status(), "complete");
        assert_ne!(first.fingerprint(), second.fingerprint());
    }

    #[test]
    fn parent_vendor_source_does_not_prove_nested_module_dependency() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("nested")).unwrap();
        fs::create_dir_all(root.path().join("vendor/example.test/dep")).unwrap();
        fs::write(
            root.path().join("go.mod"),
            "module example.test/root\n\nrequire example.test/dep v1.2.3\n",
        )
        .unwrap();
        fs::write(
            root.path().join("nested/go.mod"),
            "module example.test/nested\n\nrequire example.test/dep v1.2.3\n",
        )
        .unwrap();
        fs::write(
            root.path().join("vendor/modules.txt"),
            "# example.test/dep v1.2.3\n## explicit\nexample.test/dep\n",
        )
        .unwrap();
        fs::write(
            root.path().join("vendor/example.test/dep/dep.go"),
            "package dep\n\nconst Value = 1\n",
        )
        .unwrap();
        let result = compute_go_dependency_witness(
            root.path(),
            &[
                "go.mod".to_owned(),
                "nested/go.mod".to_owned(),
                "vendor/modules.txt".to_owned(),
                "vendor/example.test/dep/dep.go".to_owned(),
            ],
        );
        assert_eq!(result.status(), "unavailable");
        assert!(
            result
                .reasons()
                .iter()
                .any(|reason| reason == "dependency-checksum-missing")
        );
    }

    #[test]
    fn local_replacement_is_confined_and_checksum_free() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("dep")).unwrap();
        fs::write(
            root.path().join("go.mod"),
            "module example.test/app\n\nrequire example.test/dep v1.0.0\n\nreplace example.test/dep => ./dep\n",
        )
        .unwrap();
        fs::write(root.path().join("dep/go.mod"), "module example.test/dep\n").unwrap();
        let result = witness(root.path());
        assert_eq!(result.status(), "complete");
        fs::write(
            root.path().join("go.mod"),
            "module example.test/app\n\nrequire example.test/dep v1.0.0\n\nreplace example.test/dep => ../dep\n",
        )
        .unwrap();
        let result = witness(root.path());
        assert_eq!(result.status(), "unavailable");
        assert!(
            result
                .reasons()
                .iter()
                .any(|reason| reason == "local-replacement-outside-root")
        );
    }

    #[test]
    fn go_manifest_directives_accept_tab_separated_forms() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("dep")).unwrap();
        fs::write(
            root.path().join("go.mod"),
            "module\texample.test/app\n\ngo 1.26\nrequire\texample.test/dep v1.0.0\nreplace\texample.test/dep => ./dep\n",
        )
        .unwrap();
        fs::write(root.path().join("dep/go.mod"), "module example.test/dep\n").unwrap();
        assert_eq!(witness(root.path()).status(), "complete");

        fs::write(
            root.path().join("go.work"),
            "go 1.26\nuse\t(\n\t.\n\t./dep\n)\n",
        )
        .unwrap();
        assert_eq!(witness(root.path()).status(), "complete");

        fs::write(
            root.path().join("go.mod"),
            "module\texample.test/app\n\ngo 1.26\nrequire\t(\n\texample.test/dep v1.0.0\n)\nreplace\t(\n\texample.test/dep => ./dep\n)\n",
        )
        .unwrap();
        assert_eq!(witness(root.path()).status(), "complete");
    }

    #[test]
    fn workspace_name_collision_does_not_prove_non_member_requirement() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("member")).unwrap();
        fs::create_dir(root.path().join("consumer")).unwrap();
        fs::write(root.path().join("go.work"), "go 1.26\nuse ./member\n").unwrap();
        fs::write(
            root.path().join("member/go.mod"),
            "module example.test/same\n\ngo 1.26\n",
        )
        .unwrap();
        fs::write(
            root.path().join("consumer/go.mod"),
            "module example.test/consumer\n\ngo 1.26\nrequire example.test/same v1.0.0\n",
        )
        .unwrap();
        let result = witness(root.path());
        assert_eq!(result.status(), "unavailable");
        assert!(
            result
                .reasons()
                .iter()
                .any(|reason| reason == "dependency-checksum-missing")
        );
    }

    #[test]
    fn workspace_replacement_overrides_module_replacement() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("app")).unwrap();
        fs::create_dir(root.path().join("dep")).unwrap();
        fs::write(
            root.path().join("go.work"),
            "go 1.23\nuse ./app\nreplace example.test/dep => ./dep\n",
        )
        .unwrap();
        fs::write(
            root.path().join("app/go.mod"),
            "module example.test/app\n\nrequire example.test/dep v1.0.0\n\nreplace example.test/dep => example.test/remote v1.0.0\n",
        )
        .unwrap();
        fs::write(root.path().join("dep/go.mod"), "module example.test/dep\n").unwrap();
        let result = witness(root.path());
        assert_eq!(result.status(), "complete");
    }

    #[test]
    fn duplicate_replacements_are_unavailable_but_exact_beats_wildcard() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("dep")).unwrap();
        fs::write(
            root.path().join("go.mod"),
            "module example.test/app\n\ngo 1.23\nrequire example.test/dep v1.0.0\nreplace example.test/dep => ./dep\nreplace example.test/dep v1.0.0 => ./dep\n",
        )
        .unwrap();
        fs::write(
            root.path().join("dep/go.mod"),
            "module example.test/dep\n\ngo 1.23\n",
        )
        .unwrap();
        let result = witness(root.path());
        assert_eq!(result.status(), "complete");

        fs::write(
            root.path().join("go.mod"),
            "module example.test/app\n\ngo 1.23\nrequire example.test/dep v1.0.0\nreplace example.test/dep => ./dep\nreplace example.test/dep => ./dep\n",
        )
        .unwrap();
        let result = witness(root.path());
        assert_eq!(result.status(), "unavailable");
        assert!(
            result
                .reasons()
                .iter()
                .any(|reason| reason == "replacement-ambiguous")
        );
    }

    #[test]
    fn changing_checksum_changes_witness() {
        let root = tempfile::tempdir().unwrap();
        fs::write(
            root.path().join("go.mod"),
            "module example.test/app\n\nrequire example.test/dep v1.0.0\n",
        )
        .unwrap();
        fs::write(
            root.path().join("go.sum"),
            "example.test/dep v1.0.0 h1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=\n",
        )
        .unwrap();
        let first = witness(root.path());
        fs::write(
            root.path().join("go.sum"),
            "example.test/dep v1.0.0 h1:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb=\n",
        )
        .unwrap();
        let second = witness(root.path());
        assert_eq!(first.status(), "unavailable");
        assert_eq!(second.status(), "unavailable");
        assert_ne!(first.fingerprint(), second.fingerprint());
    }
}
