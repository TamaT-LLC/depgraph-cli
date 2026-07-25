//! Confined multi-file project input for the pinned rust-analyzer backend.
//!
//! The builder in this module has no repository loader. Its only source input
//! is the UTF-8 inventory already admitted by the scanner, and every path
//! exposed to rust-analyzer is virtual. Cargo discovery, project configuration,
//! build scripts, and procedural macro binaries remain outside this boundary.
//! The only non-repository source is a separately attested bundled sysroot
//! inventory supplied by core.

use crate::{
    RUST_TOOLCHAIN_BASELINE,
    hir_sysroot::AttestedSysroot,
    manifest::{Dependency, DependencyKind, Package, Target, expanded_named_features},
};
use proc_macro2::TokenStream;
use ra_ap_hir::{CfgOptions, ChangeWithProcMacros, Symbol};
use ra_ap_ide_db::{
    RootDatabase,
    base_db::{
        Crate as BaseCrate, CrateDisplayName, CrateGraphBuilder, CrateName, CrateOrigin,
        CrateWorkspaceData, DependencyBuilder, Env, FileId, FileSet, LangCrateOrigin, SourceRoot,
        VfsPath,
    },
    span::Edition,
};
use ra_ap_vfs::AbsPathBuf;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    path::{Component, Path},
};
use syn::{Attribute, Expr, ExprLit, Lit, Meta, Token, punctuated::Punctuated, visit::Visit as _};
use triomphe::Arc;

/// Source text read once through the scanner's confined inventory path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct InventorySource {
    pub rel_path: String,
    pub package_index: Option<usize>,
    pub text: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum HirProjectMode {
    Check,
    Build,
    Test,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct HirProjectProfile {
    pub target_triple: String,
    pub mode: HirProjectMode,
    pub requested_features: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct ProjectModelSnapshot {
    pub target_triple: String,
    pub mode: HirProjectMode,
    pub files: Vec<VfsFileSnapshot>,
    pub crates: Vec<CrateSnapshot>,
    pub sysroot_crates: Vec<SysrootCrateSnapshot>,
    pub externals: Vec<ExternalCrateSnapshot>,
    pub issues: Vec<ProjectModelIssue>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct SysrootCrateSnapshot {
    pub name: String,
    pub key: String,
    pub root_path: String,
    pub root_file_id: u32,
    pub dependencies: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct VfsFileSnapshot {
    pub file_id: u32,
    pub path: String,
    pub bytes: usize,
    pub sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct CrateSnapshot {
    pub key: String,
    pub package: String,
    pub target_name: String,
    pub target_kind: String,
    pub root_path: String,
    pub root_file_id: u32,
    pub edition: String,
    pub feature_resolver: u8,
    pub cfg: Vec<String>,
    pub dependencies: Vec<CrateDependencySnapshot>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub(crate) struct CrateDependencySnapshot {
    pub name: String,
    pub crate_key: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ExternalCrateKind {
    Registry,
    Git,
    OutsideOrUnmodeledPath,
    Sysroot,
    BuildDependency,
    ProcMacro,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub(crate) struct ExternalCrateSnapshot {
    pub from_crate: String,
    pub name: String,
    pub kind: ExternalCrateKind,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub(crate) struct ProjectModelIssue {
    pub code: String,
    pub path: Option<String>,
    pub reason: String,
}

/// The semantic definition pass consumes the database together with the
/// canonical audit snapshot and stable crate-instance mapping.
pub(crate) struct SafeProjectModel {
    database: RootDatabase,
    snapshot: ProjectModelSnapshot,
    crate_instances: BTreeMap<String, BaseCrate>,
    sysroot_crate_instances: BTreeMap<String, BaseCrate>,
}

impl SafeProjectModel {
    pub(crate) fn database(&self) -> &RootDatabase {
        &self.database
    }

    pub(crate) fn snapshot(&self) -> &ProjectModelSnapshot {
        &self.snapshot
    }

    /// Stable crate keys paired with the exact rust-analyzer crate instances
    /// created by this model. Root files are not unique in test mode, where a
    /// normal crate and its cfg(test) harness intentionally share one file.
    pub(crate) fn crate_instances(&self) -> &BTreeMap<String, BaseCrate> {
        &self.crate_instances
    }

    pub(crate) fn sysroot_crate_instances(&self) -> &BTreeMap<String, BaseCrate> {
        &self.sysroot_crate_instances
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProjectModelErrorKind {
    UnsupportedInput,
    Incomplete,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ProjectModelError {
    pub kind: ProjectModelErrorKind,
    pub path: Option<String>,
    pub reason: String,
}

impl ProjectModelError {
    fn unsupported(path: Option<&str>, reason: impl Into<String>) -> Self {
        Self {
            kind: ProjectModelErrorKind::UnsupportedInput,
            path: path.map(str::to_owned),
            reason: reason.into(),
        }
    }

    fn incomplete(path: Option<&str>, reason: impl Into<String>) -> Self {
        Self {
            kind: ProjectModelErrorKind::Incomplete,
            path: path.map(str::to_owned),
            reason: reason.into(),
        }
    }
}

impl fmt::Display for ProjectModelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.reason)
    }
}

impl std::error::Error for ProjectModelError {}

#[derive(Clone, Debug)]
struct TargetCfg {
    flags: BTreeSet<String>,
    values: BTreeMap<String, BTreeSet<String>>,
}

impl TargetCfg {
    fn ra_options(&self, features: &BTreeSet<String>, test: bool) -> CfgOptions {
        let mut options = CfgOptions::default();
        for flag in &self.flags {
            options.insert_atom(Symbol::intern(flag));
        }
        if test {
            options.insert_atom(Symbol::intern("test"));
        }
        for (key, values) in &self.values {
            for value in values {
                options.insert_key_value(Symbol::intern(key), Symbol::intern(value));
            }
        }
        for feature in features {
            options.insert_key_value(Symbol::intern("feature"), Symbol::intern(feature));
        }
        options
    }

    fn snapshot(&self, features: &BTreeSet<String>, test: bool) -> Vec<String> {
        let mut result = vec!["true".to_owned()];
        result.extend(self.flags.iter().cloned());
        if test {
            result.push("test".into());
        }
        for (key, values) in &self.values {
            for value in values {
                result.push(format!(r#"{key}="{value}""#));
            }
        }
        for feature in features {
            result.push(format!(r#"feature="{feature}""#));
        }
        result.sort();
        result.dedup();
        result
    }

    fn has_flag(&self, flag: &str, test: bool) -> std::result::Result<bool, String> {
        match flag {
            "true" => Ok(true),
            "false" => Ok(false),
            "test" => Ok(test),
            "unix" | "windows" | "debug_assertions" => Ok(self.flags.contains(flag)),
            // These compiler-controlled cfg flags are known to be absent from
            // the safe check/build/test profiles represented here.
            "doc" | "doctest" | "miri" | "proc_macro" | "sanitize" => Ok(false),
            _ => Err(format!(
                "custom cfg flag {flag} is unavailable without build-script output"
            )),
        }
    }

    fn has_value(
        &self,
        key: &str,
        value: &str,
        features: &BTreeSet<String>,
    ) -> std::result::Result<bool, String> {
        if key == "feature" {
            return Ok(features.contains(value));
        }
        if !matches!(
            key,
            "target_arch"
                | "target_vendor"
                | "target_os"
                | "target_env"
                | "target_family"
                | "target_pointer_width"
                | "target_endian"
                | "target_abi"
                | "target_has_atomic"
                | "target_feature"
                | "panic"
        ) {
            return Err(format!(
                "cfg key {key} is unavailable without compiler or build-script output"
            ));
        }
        Ok(self
            .values
            .get(key)
            .is_some_and(|values| values.contains(value)))
    }
}

#[derive(Clone, Debug)]
struct PendingCrate {
    package_index: usize,
    key: String,
    target: Target,
    root_file_id: FileId,
    root_file_raw: u32,
    edition: Edition,
    cfg: CfgOptions,
    cfg_snapshot: Vec<String>,
    test: bool,
    dev_dependencies: bool,
    sysroot_dependencies: BTreeSet<String>,
}

type BuiltVfs = (
    FileSet,
    FileSet,
    Vec<(FileId, String)>,
    Vec<VfsFileSnapshot>,
    BTreeMap<String, FileId>,
    BTreeMap<String, FileId>,
);

/// Builds an atomic, inventory-only rust-analyzer database.
///
/// Failure returns no partial database. rust-analyzer's required proc-macro
/// cwd field receives a fixed inert absolute sentinel; no proc macro is
/// registered and the sentinel is never inspected.
#[cfg(test)]
pub(crate) fn build_safe_project_model(
    packages: &[Package],
    inventory: &[InventorySource],
    profile: &HirProjectProfile,
    neutral_cwd: &Path,
) -> std::result::Result<SafeProjectModel, ProjectModelError> {
    build_safe_project_model_with_sysroot(packages, inventory, None, profile, neutral_cwd)
}

pub(crate) fn build_safe_project_model_with_sysroot(
    packages: &[Package],
    inventory: &[InventorySource],
    sysroot: Option<&AttestedSysroot>,
    profile: &HirProjectProfile,
    _neutral_cwd: &Path,
) -> std::result::Result<SafeProjectModel, ProjectModelError> {
    let target_cfg = supported_target_cfg(&profile.target_triple)?;
    let proc_macro_cwd = inert_proc_macro_cwd();
    if packages.is_empty() {
        return Err(ProjectModelError::incomplete(
            None,
            "confined Cargo metadata contains no packages",
        ));
    }
    let cargo_profile = if profile.mode == HirProjectMode::Test {
        "test"
    } else {
        "dev"
    };
    if let Some(package) = packages.iter().find(|package| {
        package.workspace_member && package.cfg_profile_overrides.contains(cargo_profile)
    }) {
        return Err(ProjectModelError::unsupported(
            Some(&package.manifest_path),
            format!("Cargo profile {cargo_profile} overrides cfg-affecting compiler settings"),
        ));
    }

    let forbidden_roots: BTreeSet<_> = packages
        .iter()
        .flat_map(|package| package.targets.iter())
        .filter(|target| target.kind == "custom-build" || target.proc_macro)
        .map(|target| target.src_path.clone())
        .collect();
    let proc_macro_packages: BTreeSet<_> = packages
        .iter()
        .enumerate()
        .filter(|(_, package)| {
            package.targets.iter().any(|target| target.proc_macro)
                && !package
                    .targets
                    .iter()
                    .any(|target| supported_target_kind(&target.kind) && !target.proc_macro)
        })
        .map(|(index, _)| index)
        .collect();
    let (package_features, active_packages) = resolve_package_features(
        packages,
        &profile.requested_features,
        profile,
        &target_cfg,
        &proc_macro_packages,
    )?;
    let excluded_packages: BTreeSet<_> = (0..packages.len())
        .filter(|index| proc_macro_packages.contains(index) || !active_packages.contains(index))
        .collect();
    let (
        file_set,
        sysroot_file_set,
        file_text,
        file_snapshots,
        files_by_path,
        sysroot_files_by_path,
    ) = build_vfs(
        inventory,
        sysroot,
        packages.len(),
        &forbidden_roots,
        &excluded_packages,
    )?;
    let mut issues = Vec::new();
    let mut externals = Vec::new();
    let mut pending = Vec::new();
    for (package_index, package) in packages.iter().enumerate() {
        if excluded_packages.contains(&package_index) {
            continue;
        }
        let features = &package_features[package_index];
        for target in sorted_targets(package) {
            if !package.workspace_member && target.kind != "lib" {
                continue;
            }
            if target.kind == "custom-build" {
                issues.push(ProjectModelIssue {
                    code: "BUILD_SCRIPT_NOT_EXECUTED".into(),
                    path: Some(target.src_path.clone()),
                    reason: "custom build target was not loaded by the safe project model".into(),
                });
                continue;
            }
            if target.proc_macro {
                issues.push(ProjectModelIssue {
                    code: "PROC_MACRO_NOT_EXECUTED".into(),
                    path: Some(target.src_path.clone()),
                    reason: "procedural macro target was not loaded by the safe project model"
                        .into(),
                });
                continue;
            }
            if !supported_target_kind(&target.kind) {
                return Err(ProjectModelError::unsupported(
                    Some(&target.src_path),
                    format!(
                        "Cargo target kind {} is not supported by the safe project model",
                        target.kind
                    ),
                ));
            }
            if !target_selected_for_profile(package, target, profile) {
                continue;
            }
            if target
                .required_features
                .iter()
                .any(|required| !features.contains(required))
            {
                continue;
            }
            let edition = target.edition.parse::<Edition>().map_err(|_| {
                ProjectModelError::unsupported(
                    Some(&target.src_path),
                    format!("Rust edition {} is not supported", target.edition),
                )
            })?;
            let root_file_id = files_by_path
                .get(&target.src_path)
                .copied()
                .ok_or_else(|| {
                    ProjectModelError::incomplete(
                        Some(&target.src_path),
                        "Cargo target crate root is missing from the admitted source inventory",
                    )
                })?;
            let test = profile.mode == HirProjectMode::Test
                && target.test
                && matches!(target.kind.as_str(), "example" | "test" | "bench");
            let dev_dependencies = profile.mode == HirProjectMode::Test
                && package.workspace_member
                && matches!(target.kind.as_str(), "example" | "test" | "bench");
            let key = crate_key(package, target);
            let sysroot_dependencies = crate_sysroot_dependencies(
                inventory,
                package_index,
                &target.src_path,
                &target_cfg,
                features,
                test,
            )?;
            pending.push(PendingCrate {
                package_index,
                key: key.clone(),
                target: target.clone(),
                root_file_id,
                root_file_raw: files_by_path
                    .iter()
                    .find_map(|(path, id)| (*id == root_file_id).then_some(path))
                    .and_then(|path| file_snapshots.iter().find(|file| &file.path == path))
                    .map(|file| file.file_id)
                    .expect("file snapshot and map are built together"),
                edition,
                cfg: target_cfg.ra_options(features, test),
                cfg_snapshot: target_cfg.snapshot(features, test),
                test,
                dev_dependencies,
                sysroot_dependencies,
            });
            if profile.mode == HirProjectMode::Test
                && package.workspace_member
                && matches!(target.kind.as_str(), "lib" | "bin")
                && target.test
            {
                let sysroot_dependencies = crate_sysroot_dependencies(
                    inventory,
                    package_index,
                    &target.src_path,
                    &target_cfg,
                    features,
                    true,
                )?;
                pending.push(PendingCrate {
                    package_index,
                    key: format!("{key}#unit-test"),
                    target: target.clone(),
                    root_file_id,
                    root_file_raw: files_by_path
                        .iter()
                        .find_map(|(path, id)| (*id == root_file_id).then_some(path))
                        .and_then(|path| file_snapshots.iter().find(|file| &file.path == path))
                        .map(|file| file.file_id)
                        .expect("file snapshot and map are built together"),
                    edition,
                    cfg: target_cfg.ra_options(features, true),
                    cfg_snapshot: target_cfg.snapshot(features, true),
                    test: true,
                    dev_dependencies: true,
                    sysroot_dependencies,
                });
            }
        }
    }
    if pending.is_empty() {
        return Err(ProjectModelError::incomplete(
            None,
            "confined Cargo metadata contains no supported crate targets",
        ));
    }
    pending.sort_by(|left, right| left.key.cmp(&right.key));
    let mut test_contexts: BTreeMap<usize, BTreeSet<bool>> = BTreeMap::new();
    for krate in &pending {
        test_contexts
            .entry(krate.package_index)
            .or_default()
            .insert(krate.test);
    }
    validate_inventory_cfg(
        inventory,
        &forbidden_roots,
        &excluded_packages,
        &package_features,
        &test_contexts,
        &target_cfg,
    )?;

    let mut graph = CrateGraphBuilder::default();
    let workspace_data = Arc::new(CrateWorkspaceData {
        target: Err("safe project model does not load a target layout".into()),
        toolchain: Some(
            ra_ap_ide_db::base_db::Version::parse(RUST_TOOLCHAIN_BASELINE)
                .expect("verified Rust baseline is valid semver"),
        ),
    });
    let mut sysroot_builder_ids = BTreeMap::new();
    let mut sysroot_crates = Vec::new();
    if sysroot.is_some() {
        let empty_features = BTreeSet::new();
        let cfg = target_cfg.ra_options(&empty_features, false);
        for (name, origin, dependencies) in [
            ("core", LangCrateOrigin::Core, Vec::<String>::new()),
            ("alloc", LangCrateOrigin::Alloc, vec!["core".into()]),
            (
                "std",
                LangCrateOrigin::Std,
                vec!["alloc".into(), "core".into()],
            ),
        ] {
            let root_path = format!("library/{name}/src/lib.rs");
            let root_file_id = sysroot_files_by_path
                .get(&root_path)
                .copied()
                .ok_or_else(|| {
                    ProjectModelError::incomplete(
                        Some(&root_path),
                        "attested sysroot crate root is missing from its inventory",
                    )
                })?;
            let snapshot_path = format!("rust-sysroot/{root_path}");
            let root_file_raw = file_snapshots
                .iter()
                .find(|file| file.path == snapshot_path)
                .map(|file| file.file_id)
                .expect("sysroot file snapshot and map are built together");
            let builder_id = graph.add_crate_root(
                root_file_id,
                Edition::Edition2024,
                Some(CrateDisplayName::from_canonical_name(name)),
                Some(RUST_TOOLCHAIN_BASELINE.into()),
                cfg.clone(),
                Some(cfg.clone()),
                Env::default(),
                CrateOrigin::Lang(origin),
                Vec::new(),
                false,
                proc_macro_cwd.clone(),
                workspace_data.clone(),
            );
            let key = format!("rust-sysroot#{name}");
            sysroot_builder_ids.insert(name.to_owned(), builder_id);
            sysroot_crates.push(SysrootCrateSnapshot {
                name: name.into(),
                key,
                root_path: snapshot_path,
                root_file_id: root_file_raw,
                dependencies,
            });
        }
        for (from_name, dependency_name) in [("alloc", "core"), ("std", "alloc"), ("std", "core")] {
            graph
                .add_dep(
                    sysroot_builder_ids[from_name],
                    DependencyBuilder::new(
                        CrateName::normalize_dashes(dependency_name),
                        sysroot_builder_ids[dependency_name],
                    ),
                )
                .map_err(|_| {
                    ProjectModelError::incomplete(
                        None,
                        "attested sysroot crate dependency graph contains a cycle",
                    )
                })?;
        }
    }
    let mut builder_ids = BTreeMap::new();
    for krate in &pending {
        let package = &packages[krate.package_index];
        let builder_id = graph.add_crate_root(
            krate.root_file_id,
            krate.edition,
            Some(CrateDisplayName::from_canonical_name(&krate.target.name)),
            Some(package.version.clone()),
            krate.cfg.clone(),
            Some(krate.cfg.clone()),
            Env::default(),
            CrateOrigin::Local {
                repo: None,
                name: Some(Symbol::intern(&package.name)),
            },
            Vec::new(),
            false,
            proc_macro_cwd.clone(),
            workspace_data.clone(),
        );
        builder_ids.insert(krate.key.clone(), builder_id);
    }

    let packages_by_dir: BTreeMap<_, _> = packages
        .iter()
        .enumerate()
        .map(|(index, package)| (package.dir.clone(), index))
        .collect();
    let lib_crates = linkable_library_crates(&pending);
    let mut dependencies_by_crate: BTreeMap<String, BTreeSet<CrateDependencySnapshot>> =
        BTreeMap::new();
    for krate in &pending {
        let package = &packages[krate.package_index];
        let mut dependencies = BTreeSet::new();

        if krate.target.kind != "lib"
            && let Some(lib_key) = lib_crates.get(&krate.package_index)
        {
            dependencies.insert(CrateDependencySnapshot {
                name: package
                    .targets
                    .iter()
                    .find(|target| crate_key(package, target) == *lib_key)
                    .map(|target| target.name.replace('-', "_"))
                    .unwrap_or_else(|| package.name.replace('-', "_")),
                crate_key: lib_key.clone(),
            });
        }

        for dependency in sorted_dependencies(package) {
            if dependency.kind == DependencyKind::Build {
                externals.push(ExternalCrateSnapshot {
                    from_crate: krate.key.clone(),
                    name: dependency.alias.clone(),
                    kind: ExternalCrateKind::BuildDependency,
                });
                continue;
            }
            if dependency.kind == DependencyKind::Development
                && (!package.workspace_member || !krate.dev_dependencies)
            {
                continue;
            }
            let active_features = &package_features[krate.package_index];
            if dependency.optional
                && !optional_dependency_enabled(package, dependency, active_features)
            {
                continue;
            }
            match dependency_applies(dependency, &profile.target_triple, &target_cfg) {
                Ok(true) => {}
                Ok(false) => continue,
                Err(reason) => {
                    return Err(ProjectModelError::unsupported(
                        Some(&package.manifest_path),
                        reason,
                    ));
                }
            }
            let Some(path) = dependency.path.as_ref() else {
                externals.push(ExternalCrateSnapshot {
                    from_crate: krate.key.clone(),
                    name: dependency.alias.clone(),
                    kind: if dependency
                        .source
                        .as_deref()
                        .is_some_and(|source| source.starts_with("git+"))
                    {
                        ExternalCrateKind::Git
                    } else {
                        ExternalCrateKind::Registry
                    },
                });
                continue;
            };
            let Some(dependency_package) = packages_by_dir.get(path).copied() else {
                externals.push(ExternalCrateSnapshot {
                    from_crate: krate.key.clone(),
                    name: dependency.alias.clone(),
                    kind: ExternalCrateKind::OutsideOrUnmodeledPath,
                });
                continue;
            };
            let Some(dependency_key) = lib_crates.get(&dependency_package) else {
                if packages[dependency_package]
                    .targets
                    .iter()
                    .any(|target| target.proc_macro)
                {
                    externals.push(ExternalCrateSnapshot {
                        from_crate: krate.key.clone(),
                        name: dependency.alias.clone(),
                        kind: ExternalCrateKind::ProcMacro,
                    });
                    continue;
                }
                return Err(ProjectModelError::incomplete(
                    Some(&package.manifest_path),
                    format!(
                        "local path dependency {} has no supported library crate",
                        dependency.alias
                    ),
                ));
            };
            dependencies.insert(CrateDependencySnapshot {
                name: dependency.alias.replace('-', "_"),
                crate_key: dependency_key.clone(),
            });
        }
        dependencies_by_crate.insert(krate.key.clone(), dependencies);
        if sysroot.is_none() {
            for name in &krate.sysroot_dependencies {
                externals.push(ExternalCrateSnapshot {
                    from_crate: krate.key.clone(),
                    name: name.clone(),
                    kind: ExternalCrateKind::Sysroot,
                });
            }
        }
    }

    for krate in &pending {
        let from = builder_ids[&krate.key];
        for dependency in &dependencies_by_crate[&krate.key] {
            let to = builder_ids[&dependency.crate_key];
            graph
                .add_dep(
                    from,
                    DependencyBuilder::new(CrateName::normalize_dashes(&dependency.name), to),
                )
                .map_err(|_| {
                    ProjectModelError::incomplete(
                        Some(&krate.target.src_path),
                        "local crate dependency graph contains a cycle",
                    )
                })?;
        }
        for name in &krate.sysroot_dependencies {
            if let Some(to) = sysroot_builder_ids.get(name) {
                graph
                    .add_dep(
                        from,
                        DependencyBuilder::new(CrateName::normalize_dashes(name), *to),
                    )
                    .map_err(|_| {
                        ProjectModelError::incomplete(
                            Some(&krate.target.src_path),
                            "local-to-sysroot crate dependency graph contains a cycle",
                        )
                    })?;
            }
        }
    }

    externals.sort();
    externals.dedup();
    if !externals.is_empty() {
        issues.push(ProjectModelIssue {
            code: "RUST_HIR_EXTERNAL_DEFINITION_UNAVAILABLE".into(),
            path: None,
            reason: if sysroot.is_some() {
                "external dependency definitions were not loaded".into()
            } else {
                "external crate definitions and sysroot source were not loaded".into()
            },
        });
    }
    if sysroot.is_none() {
        issues.push(ProjectModelIssue {
            code: "RUST_HIR_SYSROOT_UNAVAILABLE".into(),
            path: None,
            reason: "no core-attested bundled Rust sysroot was available".into(),
        });
    }
    issues.sort();
    issues.dedup();

    let crate_snapshots = pending
        .iter()
        .map(|krate| {
            let package = &packages[krate.package_index];
            let mut dependencies: Vec<_> =
                dependencies_by_crate[&krate.key].iter().cloned().collect();
            if sysroot.is_some() {
                dependencies.extend(krate.sysroot_dependencies.iter().map(|name| {
                    CrateDependencySnapshot {
                        name: name.clone(),
                        crate_key: format!("rust-sysroot#{name}"),
                    }
                }));
                dependencies.sort();
            }
            CrateSnapshot {
                key: krate.key.clone(),
                package: package.name.clone(),
                target_name: krate.target.name.clone(),
                target_kind: krate.target.kind.clone(),
                root_path: krate.target.src_path.clone(),
                root_file_id: krate.root_file_raw,
                edition: krate.target.edition.clone(),
                feature_resolver: package.feature_resolver,
                cfg: krate.cfg_snapshot.clone(),
                dependencies,
            }
        })
        .collect();

    let snapshot = ProjectModelSnapshot {
        target_triple: profile.target_triple.clone(),
        mode: profile.mode,
        files: file_snapshots,
        crates: crate_snapshots,
        sysroot_crates,
        externals,
        issues,
    };
    let mut change = ChangeWithProcMacros::default();
    change.set_roots(vec![
        SourceRoot::new_local(file_set),
        SourceRoot::new_library(sysroot_file_set),
    ]);
    for (file_id, text) in file_text {
        change.change_file(file_id, Some(text));
    }
    change.set_crate_graph(graph);
    let mut database = RootDatabase::default();
    debug_assert!(change.proc_macros.is_none());
    let crate_id_map = change
        .source_change
        .apply(&mut database)
        .expect("safe project model always installs a crate graph");
    let crate_instances = builder_ids
        .into_iter()
        .map(|(key, builder_id)| {
            let krate = crate_id_map
                .get(&builder_id)
                .copied()
                .expect("every safe crate builder ID is installed");
            (key, krate)
        })
        .collect();
    let sysroot_crate_instances = sysroot_builder_ids
        .into_iter()
        .map(|(key, builder_id)| {
            let krate = crate_id_map
                .get(&builder_id)
                .copied()
                .expect("every sysroot crate builder ID is installed");
            (key, krate)
        })
        .collect();
    Ok(SafeProjectModel {
        database,
        snapshot,
        crate_instances,
        sysroot_crate_instances,
    })
}

fn crate_sysroot_dependencies(
    inventory: &[InventorySource],
    package_index: usize,
    root_path: &str,
    target_cfg: &TargetCfg,
    features: &BTreeSet<String>,
    test: bool,
) -> std::result::Result<BTreeSet<String>, ProjectModelError> {
    let source = inventory
        .iter()
        .find(|source| source.package_index == Some(package_index) && source.rel_path == root_path)
        .ok_or_else(|| {
            ProjectModelError::incomplete(
                Some(root_path),
                "Cargo target crate root is missing from the admitted source inventory",
            )
        })?;
    let syntax = syn::parse_file(&source.text).map_err(|_| {
        ProjectModelError::incomplete(
            Some(root_path),
            "Rust crate root attributes could not be safely inventoried",
        )
    })?;
    let mut no_std = false;
    let mut no_core = false;
    for attribute in &syntax.attrs {
        apply_sysroot_crate_attribute(
            &attribute.meta,
            target_cfg,
            features,
            test,
            &mut no_std,
            &mut no_core,
        )
        .map_err(|reason| ProjectModelError::unsupported(Some(root_path), reason))?;
    }
    if no_core {
        return Err(ProjectModelError::unsupported(
            Some(root_path),
            "no_core crates are not supported by the attested sysroot dependency model",
        ));
    }

    let mut dependencies = BTreeSet::from(["core".to_owned()]);
    if !no_std {
        dependencies.insert("std".into());
    }
    for item in &syntax.items {
        let syn::Item::ExternCrate(extern_crate) = item else {
            continue;
        };
        let name = extern_crate.ident.to_string();
        if matches!(name.as_str(), "alloc" | "core" | "std")
            && cfg_attributes_are_active(&extern_crate.attrs, target_cfg, features, test)
                .map_err(|reason| ProjectModelError::unsupported(Some(root_path), reason))?
        {
            dependencies.insert(name);
        }
    }
    Ok(dependencies)
}

fn apply_sysroot_crate_attribute(
    meta: &Meta,
    target_cfg: &TargetCfg,
    features: &BTreeSet<String>,
    test: bool,
    no_std: &mut bool,
    no_core: &mut bool,
) -> std::result::Result<(), String> {
    if meta.path().is_ident("no_core") {
        *no_core = true;
        return Ok(());
    }
    if meta.path().is_ident("no_std") {
        *no_std = true;
        return Ok(());
    }
    let Meta::List(list) = meta else {
        return Ok(());
    };
    if !list.path.is_ident("cfg_attr") {
        return Ok(());
    }
    let nested = list
        .parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)
        .map_err(|_| "crate-level cfg_attr predicate is malformed".to_owned())?;
    if nested.len() < 2 {
        return Err("crate-level cfg_attr requires a predicate and attribute".into());
    }
    if evaluate_cfg_meta(
        nested.first().expect("length checked"),
        target_cfg,
        features,
        test,
    )? {
        for nested_attribute in nested.iter().skip(1) {
            apply_sysroot_crate_attribute(
                nested_attribute,
                target_cfg,
                features,
                test,
                no_std,
                no_core,
            )?;
        }
    }
    Ok(())
}

fn cfg_attributes_are_active(
    attributes: &[Attribute],
    target_cfg: &TargetCfg,
    features: &BTreeSet<String>,
    test: bool,
) -> std::result::Result<bool, String> {
    for attribute in attributes {
        if !cfg_meta_is_active(&attribute.meta, target_cfg, features, test)? {
            return Ok(false);
        }
    }
    Ok(true)
}

fn cfg_meta_is_active(
    meta: &Meta,
    target_cfg: &TargetCfg,
    features: &BTreeSet<String>,
    test: bool,
) -> std::result::Result<bool, String> {
    let Meta::List(list) = meta else {
        return Ok(true);
    };
    if list.path.is_ident("cfg") {
        let predicate = list
            .parse_args::<Meta>()
            .map_err(|_| "extern crate cfg predicate is malformed".to_owned())?;
        return evaluate_cfg_meta(&predicate, target_cfg, features, test);
    }
    if !list.path.is_ident("cfg_attr") {
        return Ok(true);
    }
    let nested = list
        .parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)
        .map_err(|_| "extern crate cfg_attr predicate is malformed".to_owned())?;
    if nested.len() < 2 {
        return Err("extern crate cfg_attr requires a predicate and attribute".into());
    }
    if !evaluate_cfg_meta(
        nested.first().expect("length checked"),
        target_cfg,
        features,
        test,
    )? {
        return Ok(true);
    }
    for nested_attribute in nested.iter().skip(1) {
        if !cfg_meta_is_active(nested_attribute, target_cfg, features, test)? {
            return Ok(false);
        }
    }
    Ok(true)
}

fn inert_proc_macro_cwd() -> Arc<AbsPathBuf> {
    let path = if cfg!(windows) {
        "C:/__depgraph_inert_proc_macro__"
    } else {
        "/__depgraph_inert_proc_macro__"
    };
    Arc::new(AbsPathBuf::try_from(path).expect("fixed proc-macro sentinel path is absolute"))
}

fn build_vfs(
    inventory: &[InventorySource],
    sysroot: Option<&AttestedSysroot>,
    package_count: usize,
    forbidden_roots: &BTreeSet<String>,
    excluded_packages: &BTreeSet<usize>,
) -> std::result::Result<BuiltVfs, ProjectModelError> {
    let mut admitted = BTreeMap::new();
    for source in inventory {
        validate_inventory_path(&source.rel_path)?;
        let Some(package_index) = source.package_index else {
            continue;
        };
        if package_index >= package_count {
            return Err(ProjectModelError::incomplete(
                Some(&source.rel_path),
                "source inventory refers to an unknown Cargo package",
            ));
        }
        if excluded_packages.contains(&package_index) {
            continue;
        }
        if forbidden_roots.contains(&source.rel_path) {
            continue;
        }
        if admitted
            .insert(source.rel_path.clone(), source.text.clone())
            .is_some()
        {
            return Err(ProjectModelError::incomplete(
                Some(&source.rel_path),
                "source inventory contains a duplicate path",
            ));
        }
    }
    let mut file_set = FileSet::default();
    let sysroot_file_count = sysroot.map_or(0, |sysroot| sysroot.files.len());
    let mut file_text = Vec::with_capacity(admitted.len() + sysroot_file_count);
    let mut snapshots = Vec::with_capacity(admitted.len() + sysroot_file_count);
    let mut files_by_path = BTreeMap::new();
    for (index, (path, text)) in admitted.into_iter().enumerate() {
        let raw = u32::try_from(index).map_err(|_| {
            ProjectModelError::incomplete(None, "source inventory contains too many files")
        })?;
        let file_id = FileId::from_raw(raw);
        file_set.insert(
            file_id,
            VfsPath::new_virtual_path(format!("/inventory/{path}")),
        );
        snapshots.push(VfsFileSnapshot {
            file_id: raw,
            path: path.clone(),
            bytes: text.len(),
            sha256: Sha256::digest(text.as_bytes())
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect(),
        });
        files_by_path.insert(path, file_id);
        file_text.push((file_id, text));
    }
    let mut sysroot_file_set = FileSet::default();
    let mut sysroot_files_by_path = BTreeMap::new();
    if let Some(sysroot) = sysroot {
        let offset = u32::try_from(snapshots.len()).map_err(|_| {
            ProjectModelError::incomplete(None, "source inventory contains too many files")
        })?;
        for (index, source) in sysroot.files.iter().enumerate() {
            validate_inventory_path(&source.rel_path)?;
            let index = u32::try_from(index).map_err(|_| {
                ProjectModelError::incomplete(None, "sysroot inventory contains too many files")
            })?;
            let raw = offset.checked_add(index).ok_or_else(|| {
                ProjectModelError::incomplete(None, "combined source inventory is too large")
            })?;
            let file_id = FileId::from_raw(raw);
            sysroot_file_set.insert(
                file_id,
                VfsPath::new_virtual_path(format!("/rust-sysroot/{}", source.rel_path)),
            );
            snapshots.push(VfsFileSnapshot {
                file_id: raw,
                path: format!("rust-sysroot/{}", source.rel_path),
                bytes: source.text.len(),
                sha256: Sha256::digest(source.text.as_bytes())
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect(),
            });
            if sysroot_files_by_path
                .insert(source.rel_path.clone(), file_id)
                .is_some()
            {
                return Err(ProjectModelError::incomplete(
                    Some(&source.rel_path),
                    "sysroot inventory contains a duplicate path",
                ));
            }
            file_text.push((file_id, source.text.clone()));
        }
    }
    Ok((
        file_set,
        sysroot_file_set,
        file_text,
        snapshots,
        files_by_path,
        sysroot_files_by_path,
    ))
}

fn validate_inventory_path(path: &str) -> std::result::Result<(), ProjectModelError> {
    if path.is_empty() || path.contains('\\') || Path::new(path).is_absolute() {
        return Err(ProjectModelError::incomplete(
            Some(path),
            "source inventory path is not a canonical relative path",
        ));
    }
    if Path::new(path)
        .components()
        .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(ProjectModelError::incomplete(
            Some(path),
            "source inventory path is not a canonical relative path",
        ));
    }
    Ok(())
}

fn sorted_targets(package: &Package) -> Vec<&Target> {
    let mut targets: Vec<_> = package.targets.iter().collect();
    targets.sort_by(|left, right| {
        (&left.kind, &left.name, &left.src_path).cmp(&(&right.kind, &right.name, &right.src_path))
    });
    targets
}

fn sorted_dependencies(package: &Package) -> Vec<&Dependency> {
    let mut dependencies: Vec<_> = package.dependencies.iter().collect();
    dependencies.sort_by(|left, right| {
        (
            left.kind.as_str(),
            left.target.as_deref(),
            left.alias.as_str(),
            left.package.as_str(),
        )
            .cmp(&(
                right.kind.as_str(),
                right.target.as_deref(),
                right.alias.as_str(),
                right.package.as_str(),
            ))
    });
    dependencies
}

fn supported_target_kind(kind: &str) -> bool {
    matches!(kind, "lib" | "bin" | "example" | "test" | "bench")
}

fn target_selected_for_profile(
    package: &Package,
    target: &Target,
    profile: &HirProjectProfile,
) -> bool {
    if !package.workspace_member && target.kind != "lib" {
        return false;
    }
    match profile.mode {
        HirProjectMode::Check | HirProjectMode::Build => {
            !matches!(target.kind.as_str(), "example" | "test" | "bench")
        }
        HirProjectMode::Test => !matches!(target.kind.as_str(), "test" | "bench") || target.test,
    }
}

fn target_required_features_are_enabled(target: &Target, features: &BTreeSet<String>) -> bool {
    target
        .required_features
        .iter()
        .all(|required| features.contains(required))
}

fn workspace_package_has_selected_target(
    package: &Package,
    features: &BTreeSet<String>,
    profile: &HirProjectProfile,
) -> bool {
    package.workspace_member
        && package.targets.iter().any(|target| {
            target.kind != "custom-build"
                && !target.proc_macro
                && target_selected_for_profile(package, target, profile)
                && target_required_features_are_enabled(target, features)
        })
}

fn workspace_package_uses_dev_dependencies(
    package: &Package,
    features: &BTreeSet<String>,
    profile: &HirProjectProfile,
) -> bool {
    profile.mode == HirProjectMode::Test
        && package.workspace_member
        && package.targets.iter().any(|target| {
            target.kind != "custom-build"
                && !target.proc_macro
                && target_selected_for_profile(package, target, profile)
                && target_required_features_are_enabled(target, features)
                && (matches!(target.kind.as_str(), "example" | "test" | "bench")
                    || (matches!(target.kind.as_str(), "lib" | "bin") && target.test))
        })
}

fn crate_key(package: &Package, target: &Target) -> String {
    format!(
        "{}#{}:{}:{}",
        package.manifest_path, target.kind, target.name, target.src_path
    )
}

fn linkable_library_crates(pending: &[PendingCrate]) -> BTreeMap<usize, String> {
    pending
        .iter()
        .filter(|krate| krate.target.kind == "lib" && !krate.test)
        .map(|krate| (krate.package_index, krate.key.clone()))
        .collect()
}

fn resolve_package_features(
    packages: &[Package],
    requested: &[String],
    profile: &HirProjectProfile,
    target_cfg: &TargetCfg,
    proc_macro_packages: &BTreeSet<usize>,
) -> std::result::Result<(Vec<BTreeSet<String>>, BTreeSet<usize>), ProjectModelError> {
    let seed_features: Vec<_> = packages
        .iter()
        .enumerate()
        .map(|(index, package)| {
            let selected = package.workspace_member && !proc_macro_packages.contains(&index);
            let requested = if selected {
                requested_for_package(package, requested)
            } else {
                Vec::new()
            };
            let mut features = expanded_named_features(package, &requested, selected);
            let declared = declared_features(package);
            features.retain(|feature| declared.contains(feature));
            features
        })
        .collect();
    let selected_workspace_packages: BTreeSet<_> = packages
        .iter()
        .enumerate()
        .filter(|(index, package)| {
            !proc_macro_packages.contains(index)
                && workspace_package_has_selected_target(package, &seed_features[*index], profile)
        })
        .map(|(index, _)| index)
        .collect();
    for feature in requested {
        let feature = feature.trim();
        if feature.is_empty() {
            continue;
        }
        let admitted = match feature.split_once('/') {
            Some((owner, feature)) => packages.iter().enumerate().any(|(index, package)| {
                selected_workspace_packages.contains(&index)
                    && package.name == owner
                    && declared_features(package).contains(feature)
            }),
            None => packages.iter().enumerate().any(|(index, package)| {
                selected_workspace_packages.contains(&index)
                    && declared_features(package).contains(feature)
            }),
        };
        if !admitted {
            return Err(ProjectModelError::unsupported(
                None,
                format!(
                    "requested Cargo feature {feature} is not declared by a selected workspace crate"
                ),
            ));
        }
    }
    let mut resolved: Vec<_> = packages
        .iter()
        .enumerate()
        .map(|(index, package)| {
            // Cargo selects every workspace member for this scan profile, but
            // root-confined non-member path packages are dependency units.
            // Their defaults and requested features must come only from an
            // active incoming dependency edge.
            let selected = selected_workspace_packages.contains(&index);
            let requested = if selected {
                requested_for_package(package, requested)
            } else {
                Vec::new()
            };
            let mut features = expanded_named_features(package, &requested, selected);
            let declared = declared_features(package);
            features.retain(|feature| declared.contains(feature));
            features
        })
        .collect();
    let mut active_packages = selected_workspace_packages;
    let packages_by_dir: BTreeMap<_, _> = packages
        .iter()
        .enumerate()
        .map(|(index, package)| (package.dir.clone(), index))
        .collect();
    loop {
        let before_features = resolved.clone();
        let before_active = active_packages.clone();
        let source_packages: Vec<_> = active_packages.iter().copied().collect();
        for package_index in source_packages {
            let package = &packages[package_index];
            for dependency in &package.dependencies {
                let Some(path) = dependency.path.as_ref() else {
                    continue;
                };
                let Some(dependency_index) = packages_by_dir.get(path).copied() else {
                    continue;
                };
                if dependency.kind == DependencyKind::Development && !package.workspace_member {
                    continue;
                }
                if proc_macro_packages.contains(&dependency_index) {
                    continue;
                }
                if dependency.optional
                    && !optional_dependency_enabled(package, dependency, &resolved[package_index])
                {
                    continue;
                }
                let applies = if dependency.kind == DependencyKind::Build {
                    false
                } else {
                    dependency_applies(dependency, &profile.target_triple, target_cfg).map_err(
                        |reason| {
                            ProjectModelError::unsupported(Some(&package.manifest_path), reason)
                        },
                    )?
                };
                let runtime_edge = match dependency.kind {
                    DependencyKind::Normal => applies,
                    DependencyKind::Development => {
                        workspace_package_uses_dev_dependencies(
                            package,
                            &resolved[package_index],
                            profile,
                        ) && applies
                    }
                    DependencyKind::Build => false,
                };
                if runtime_edge {
                    active_packages.insert(dependency_index);
                }

                // Resolver 1 unifies target/build/dev features only when the
                // dependency package is also an active target unit. Resolver
                // 2/3 isolate build and inactive target/dev feature sets.
                if !active_packages.contains(&dependency_index) {
                    continue;
                }
                let feature_edge = match dependency.kind {
                    DependencyKind::Build => package.feature_resolver == 1,
                    DependencyKind::Development if !package.workspace_member => false,
                    DependencyKind::Development => {
                        package.feature_resolver == 1
                            || workspace_package_uses_dev_dependencies(
                                package,
                                &resolved[package_index],
                                profile,
                            )
                    }
                    DependencyKind::Normal => package.feature_resolver == 1 || applies,
                };
                if !feature_edge {
                    continue;
                }
                let mut features = dependency.features.clone();
                features.extend(forwarded_dependency_features(
                    package,
                    dependency,
                    &resolved[package_index],
                ));
                let declared = declared_features(&packages[dependency_index]);
                if let Some(feature) = features.iter().find(|feature| !declared.contains(*feature))
                {
                    return Err(ProjectModelError::incomplete(
                        Some(&package.manifest_path),
                        format!(
                            "local dependency {} requests undeclared feature {feature}",
                            dependency.alias
                        ),
                    ));
                }
                let mut expanded = expanded_named_features(
                    &packages[dependency_index],
                    &features,
                    dependency.uses_default_features,
                );
                expanded.retain(|feature| declared.contains(feature));
                resolved[dependency_index].extend(expanded);
            }
        }
        if resolved == before_features && active_packages == before_active {
            break;
        }
    }
    Ok((resolved, active_packages))
}

fn declared_features(package: &Package) -> BTreeSet<String> {
    let mut declared: BTreeSet<_> = package.features.keys().cloned().collect();
    let explicitly_named_dependencies: BTreeSet<_> = package
        .features
        .values()
        .flatten()
        .filter_map(|member| member.strip_prefix("dep:"))
        .map(str::to_owned)
        .collect();
    for dependency in package
        .dependencies
        .iter()
        .filter(|dependency| dependency.optional)
    {
        if !explicitly_named_dependencies.contains(&dependency.alias) {
            declared.insert(dependency.alias.clone());
        }
    }
    declared
}

fn requested_for_package(package: &Package, requested: &[String]) -> Vec<String> {
    requested
        .iter()
        .filter_map(|feature| match feature.split_once('/') {
            Some((owner, feature)) if owner == package.name => Some(feature.to_owned()),
            Some(_) => None,
            None => Some(feature.clone()),
        })
        .collect()
}

fn validate_inventory_cfg(
    inventory: &[InventorySource],
    forbidden_roots: &BTreeSet<String>,
    excluded_packages: &BTreeSet<usize>,
    package_features: &[BTreeSet<String>],
    test_contexts: &BTreeMap<usize, BTreeSet<bool>>,
    target_cfg: &TargetCfg,
) -> std::result::Result<(), ProjectModelError> {
    for source in inventory {
        let Some(package_index) = source.package_index else {
            continue;
        };
        if forbidden_roots.contains(&source.rel_path) || excluded_packages.contains(&package_index)
        {
            continue;
        }
        let Some(contexts) = test_contexts.get(&package_index) else {
            continue;
        };
        let syntax = syn::parse_file(&source.text).map_err(|_| {
            ProjectModelError::incomplete(
                Some(&source.rel_path),
                "Rust source cfg could not be safely inventoried",
            )
        })?;
        for test in contexts {
            let mut validator = CfgAttributeValidator {
                target_cfg,
                features: &package_features[package_index],
                test: *test,
                error: None,
            };
            validator.visit_file(&syntax);
            if let Some(reason) = validator.error {
                return Err(ProjectModelError::unsupported(
                    Some(&source.rel_path),
                    reason,
                ));
            }
        }
    }
    Ok(())
}

struct CfgAttributeValidator<'a> {
    target_cfg: &'a TargetCfg,
    features: &'a BTreeSet<String>,
    test: bool,
    error: Option<String>,
}

impl CfgAttributeValidator<'_> {
    fn validate_attribute(&mut self, attribute: &Attribute) -> std::result::Result<(), String> {
        if attribute.path().is_ident("cfg") {
            let tokens = attribute
                .meta
                .require_list()
                .map_err(|_| "source cfg attribute is malformed".to_owned())?
                .tokens
                .clone();
            self.validate_cfg_tokens("cfg", tokens)?;
        } else if attribute.path().is_ident("cfg_attr") {
            let tokens = attribute
                .meta
                .require_list()
                .map_err(|_| "source cfg_attr attribute is malformed".to_owned())?
                .tokens
                .clone();
            self.validate_cfg_tokens("cfg_attr", tokens)?;
        }
        Ok(())
    }

    fn validate_cfg_tokens(
        &mut self,
        name: &str,
        tokens: TokenStream,
    ) -> std::result::Result<(), String> {
        if name == "cfg" {
            let meta = syn::parse2::<Meta>(tokens)
                .map_err(|_| "source cfg predicate is malformed".to_owned())?;
            evaluate_cfg_meta(&meta, self.target_cfg, self.features, self.test)?;
            return Ok(());
        }
        let nested =
            syn::parse::Parser::parse2(Punctuated::<Meta, Token![,]>::parse_terminated, tokens)
                .map_err(|_| "source cfg_attr predicate is malformed".to_owned())?;
        if nested.len() < 2 {
            return Err("source cfg_attr attribute requires a predicate and attribute".into());
        }
        let predicate = nested.first().expect("length checked");
        if evaluate_cfg_meta(predicate, self.target_cfg, self.features, self.test)? {
            for nested_attribute in nested.iter().skip(1) {
                self.validate_nested_meta(nested_attribute)?;
            }
        }
        Ok(())
    }

    fn validate_nested_meta(&mut self, meta: &Meta) -> std::result::Result<(), String> {
        let Meta::List(list) = meta else {
            return Ok(());
        };
        if list.path.is_ident("cfg") {
            let predicate = list
                .parse_args::<Meta>()
                .map_err(|_| "nested source cfg attribute is malformed".to_owned())?;
            evaluate_cfg_meta(&predicate, self.target_cfg, self.features, self.test)?;
        } else if list.path.is_ident("cfg_attr") {
            let nested = list
                .parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)
                .map_err(|_| "nested source cfg_attr attribute is malformed".to_owned())?;
            if nested.len() < 2 {
                return Err(
                    "nested source cfg_attr attribute requires a predicate and attribute".into(),
                );
            }
            let predicate = nested.first().expect("length checked");
            if evaluate_cfg_meta(predicate, self.target_cfg, self.features, self.test)? {
                for nested_attribute in nested.iter().skip(1) {
                    self.validate_nested_meta(nested_attribute)?;
                }
            }
        }
        Ok(())
    }
}

impl syn::visit::Visit<'_> for CfgAttributeValidator<'_> {
    fn visit_attribute(&mut self, attribute: &Attribute) {
        if self.error.is_none()
            && let Err(error) = self.validate_attribute(attribute)
        {
            self.error = Some(error);
        }
        if self.error.is_none() {
            syn::visit::visit_attribute(self, attribute);
        }
    }

    fn visit_macro(&mut self, mac: &syn::Macro) {
        if self.error.is_none()
            && mac.path.is_ident("cfg")
            && let Err(error) = self.validate_cfg_tokens("cfg", mac.tokens.clone())
        {
            self.error = Some(error);
        }
        if self.error.is_none() {
            syn::visit::visit_macro(self, mac);
        }
    }
}

fn optional_dependency_enabled(
    package: &Package,
    dependency: &Dependency,
    active_features: &BTreeSet<String>,
) -> bool {
    if !dependency.optional {
        return true;
    }
    let explicit = format!("dep:{}", dependency.alias);
    let strong_prefix = format!("{}/", dependency.alias);
    let explicit_dependency_feature = package
        .features
        .values()
        .flatten()
        .any(|member| member == &explicit);
    if !explicit_dependency_feature && active_features.contains(&dependency.alias) {
        return true;
    }
    package.features.iter().any(|(feature, members)| {
        active_features.contains(feature)
            && members.iter().any(|member| {
                member == &explicit
                    || (member.starts_with(&strong_prefix)
                        && !member.starts_with(&format!("{}?/", dependency.alias)))
            })
    })
}

fn forwarded_dependency_features(
    package: &Package,
    dependency: &Dependency,
    active_features: &BTreeSet<String>,
) -> BTreeSet<String> {
    let strong_prefix = format!("{}/", dependency.alias);
    let weak_prefix = format!("{}?/", dependency.alias);
    let dependency_active = optional_dependency_enabled(package, dependency, active_features);
    package
        .features
        .iter()
        .filter(|(feature, _)| active_features.contains(*feature))
        .flat_map(|(_, members)| members)
        .filter_map(|member| {
            member
                .strip_prefix(&strong_prefix)
                .or_else(|| {
                    dependency_active
                        .then(|| member.strip_prefix(&weak_prefix))
                        .flatten()
                })
                .map(str::to_owned)
        })
        .collect()
}

fn dependency_applies(
    dependency: &Dependency,
    target_triple: &str,
    target_cfg: &TargetCfg,
) -> std::result::Result<bool, String> {
    let Some(target) = dependency.target.as_deref() else {
        return Ok(true);
    };
    if !target.starts_with("cfg(") {
        return Ok(target == target_triple);
    }
    let inner = target
        .strip_prefix("cfg(")
        .and_then(|target| target.strip_suffix(')'))
        .ok_or_else(|| format!("target predicate {target} is malformed"))?;
    let meta = syn::parse_str::<Meta>(inner)
        .map_err(|_| format!("target predicate {target} is malformed"))?;
    validate_cargo_target_predicate(&meta)?;
    evaluate_cfg_meta(&meta, target_cfg, &BTreeSet::new(), false)
}

fn validate_cargo_target_predicate(meta: &Meta) -> std::result::Result<(), String> {
    match meta {
        Meta::Path(path) => {
            let key = path
                .get_ident()
                .map(ToString::to_string)
                .ok_or_else(|| "qualified Cargo target cfg paths are not supported".to_owned())?;
            if matches!(key.as_str(), "unix" | "windows" | "true" | "false") {
                Ok(())
            } else {
                Err(format!(
                    "Cargo target dependency predicate cfg({key}) is not a target-only cfg"
                ))
            }
        }
        Meta::NameValue(name_value) => {
            let key = name_value
                .path
                .get_ident()
                .map(ToString::to_string)
                .ok_or_else(|| "qualified Cargo target cfg keys are not supported".to_owned())?;
            if key.starts_with("target_") || key == "panic" {
                Ok(())
            } else {
                Err(format!(
                    "Cargo target dependency cfg key {key} is not target-only"
                ))
            }
        }
        Meta::List(list) => {
            let operator = list
                .path
                .get_ident()
                .map(ToString::to_string)
                .ok_or_else(|| {
                    "qualified Cargo target cfg operators are not supported".to_owned()
                })?;
            if !matches!(operator.as_str(), "all" | "any" | "not") {
                return Err(format!(
                    "Cargo target cfg operator {operator} is not supported"
                ));
            }
            let nested = list
                .parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)
                .map_err(|_| format!("Cargo target cfg operator {operator} is malformed"))?;
            if operator == "not" && nested.len() != 1 {
                return Err("Cargo target cfg not() requires exactly one argument".into());
            }
            for meta in &nested {
                validate_cargo_target_predicate(meta)?;
            }
            Ok(())
        }
    }
}

fn evaluate_cfg_meta(
    meta: &Meta,
    target_cfg: &TargetCfg,
    features: &BTreeSet<String>,
    test: bool,
) -> std::result::Result<bool, String> {
    match meta {
        Meta::Path(path) => {
            let key = path
                .get_ident()
                .map(ToString::to_string)
                .ok_or_else(|| "qualified cfg paths are not supported".to_owned())?;
            target_cfg.has_flag(&key, test)
        }
        Meta::NameValue(name_value) => {
            let key = name_value
                .path
                .get_ident()
                .map(ToString::to_string)
                .ok_or_else(|| "qualified cfg keys are not supported".to_owned())?;
            let Expr::Lit(ExprLit {
                lit: Lit::Str(value),
                ..
            }) = &name_value.value
            else {
                return Err("cfg values must be string literals".into());
            };
            target_cfg.has_value(&key, &value.value(), features)
        }
        Meta::List(list) => {
            let operator = list
                .path
                .get_ident()
                .map(ToString::to_string)
                .ok_or_else(|| "qualified cfg operators are not supported".to_owned())?;
            let nested = list
                .parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)
                .map_err(|_| format!("cfg operator {operator} has malformed arguments"))?;
            match operator.as_str() {
                "all" => {
                    for meta in &nested {
                        if !evaluate_cfg_meta(meta, target_cfg, features, test)? {
                            return Ok(false);
                        }
                    }
                    Ok(true)
                }
                "any" => {
                    for meta in &nested {
                        if evaluate_cfg_meta(meta, target_cfg, features, test)? {
                            return Ok(true);
                        }
                    }
                    Ok(false)
                }
                "not" if nested.len() == 1 => {
                    Ok(!evaluate_cfg_meta(&nested[0], target_cfg, features, test)?)
                }
                "not" => Err("cfg not() requires exactly one argument".into()),
                _ => Err(format!("cfg operator {operator} is not supported")),
            }
        }
    }
}

fn supported_target_cfg(target: &str) -> std::result::Result<TargetCfg, ProjectModelError> {
    let (arch, vendor, os, env, family, pointer_width, target_features, atomic_128) = match target {
        "x86_64-unknown-linux-gnu" => (
            "x86_64",
            "unknown",
            "linux",
            "gnu",
            "unix",
            "64",
            &["fxsr", "sse", "sse2"][..],
            false,
        ),
        "aarch64-unknown-linux-gnu" => (
            "aarch64",
            "unknown",
            "linux",
            "gnu",
            "unix",
            "64",
            &["neon"][..],
            true,
        ),
        "x86_64-apple-darwin" => (
            "x86_64",
            "apple",
            "macos",
            "",
            "unix",
            "64",
            &[
                "cmpxchg16b",
                "fxsr",
                "sse",
                "sse2",
                "sse3",
                "sse4.1",
                "ssse3",
            ][..],
            true,
        ),
        "aarch64-apple-darwin" => (
            "aarch64",
            "apple",
            "macos",
            "",
            "unix",
            "64",
            &[
                "aes", "crc", "dit", "dotprod", "dpb", "dpb2", "fcma", "fhm", "flagm", "fp16",
                "frintts", "jsconv", "lor", "lse", "neon", "paca", "pacg", "pan", "pmuv3", "ras",
                "rcpc", "rcpc2", "rdm", "sb", "sha2", "sha3", "ssbs", "vh",
            ][..],
            true,
        ),
        "x86_64-pc-windows-msvc" => (
            "x86_64",
            "pc",
            "windows",
            "msvc",
            "windows",
            "64",
            &["cmpxchg16b", "fxsr", "sse", "sse2", "sse3"][..],
            true,
        ),
        _ => {
            return Err(ProjectModelError::unsupported(
                None,
                "effective Rust target is outside the verified safe project-model matrix",
            ));
        }
    };
    let mut flags = BTreeSet::from([family.to_owned(), "debug_assertions".to_owned()]);
    if family == "unix" {
        flags.insert("unix".into());
    } else if family == "windows" {
        flags.insert("windows".into());
    }
    let mut atomic_values = BTreeSet::from([
        "8".into(),
        "16".into(),
        "32".into(),
        "64".into(),
        "ptr".into(),
    ]);
    if atomic_128 {
        atomic_values.insert("128".into());
    }
    let values = BTreeMap::from([
        ("target_arch".into(), BTreeSet::from([arch.into()])),
        ("target_vendor".into(), BTreeSet::from([vendor.into()])),
        ("target_os".into(), BTreeSet::from([os.into()])),
        ("target_env".into(), BTreeSet::from([env.into()])),
        ("target_family".into(), BTreeSet::from([family.into()])),
        (
            "target_pointer_width".into(),
            BTreeSet::from([pointer_width.into()]),
        ),
        ("target_endian".into(), BTreeSet::from(["little".into()])),
        ("target_abi".into(), BTreeSet::from([String::new()])),
        ("target_has_atomic".into(), atomic_values),
        (
            "target_feature".into(),
            target_features
                .iter()
                .map(|feature| (*feature).into())
                .collect(),
        ),
        ("panic".into(), BTreeSet::from(["unwind".into()])),
    ]);
    Ok(TargetCfg { flags, values })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hir_sysroot::SysrootSource;
    use depgraph_protocol::Condition;
    use std::path::PathBuf;

    fn target(name: &str, kind: &str, path: &str) -> Target {
        Target {
            name: name.into(),
            kind: kind.into(),
            src_path: path.into(),
            edition: String::new(),
            required_features: Vec::new(),
            test: matches!(kind, "lib" | "bin" | "test"),
            proc_macro: false,
        }
    }

    fn dependency(
        alias: &str,
        path: Option<&str>,
        kind: DependencyKind,
        target: Option<&str>,
    ) -> Dependency {
        Dependency {
            alias: alias.into(),
            package: alias.into(),
            version: Some("1.0.0".into()),
            path: path.map(PathBuf::from),
            optional: false,
            features: Vec::new(),
            uses_default_features: true,
            kind,
            condition: Condition::default(),
            target: target.map(str::to_owned),
            source: path
                .is_none()
                .then(|| "registry+https://example.invalid/index".into()),
            locked: true,
        }
    }

    fn package(name: &str, edition: &str, dir: &str, mut targets: Vec<Target>) -> Package {
        for target in &mut targets {
            if target.edition.is_empty() {
                target.edition = edition.into();
            }
        }
        Package {
            name: name.into(),
            version: "0.1.0".into(),
            edition: edition.into(),
            feature_resolver: 2,
            manifest_path: format!("{dir}/Cargo.toml"),
            dir: PathBuf::from(dir),
            rel_dir: dir.into(),
            features: BTreeMap::new(),
            dependencies: Vec::new(),
            targets,
            build_script: None,
            proc_macro: false,
            cfg_profile_overrides: BTreeSet::new(),
            workspace_member: true,
            from_metadata: true,
        }
    }

    fn source(package_index: Option<usize>, path: &str, text: &str) -> InventorySource {
        InventorySource {
            rel_path: path.into(),
            package_index,
            text: text.into(),
        }
    }

    fn fixture() -> (Vec<Package>, Vec<InventorySource>) {
        let mut app = package(
            "app",
            "2018",
            "app",
            vec![
                target("app_lib", "lib", "app/src/lib.rs"),
                target("app_bin", "bin", "app/src/main.rs"),
                target("app_test", "test", "app/tests/api.rs"),
                target("build-script-app", "custom-build", "app/build.rs"),
                Target {
                    name: "macros".into(),
                    kind: "lib".into(),
                    src_path: "app/src/macros.rs".into(),
                    edition: "2018".into(),
                    required_features: Vec::new(),
                    test: true,
                    proc_macro: true,
                },
            ],
        );
        app.build_script = Some("app/build.rs".into());
        app.features = BTreeMap::from([
            ("default".into(), vec!["base".into()]),
            ("base".into(), Vec::new()),
            (
                "fancy".into(),
                vec!["dep:dep_alias".into(), "dep_alias/serde".into()],
            ),
        ]);
        let mut local = dependency(
            "dep_alias",
            Some("dep"),
            DependencyKind::Normal,
            Some("cfg(unix)"),
        );
        local.package = "dep".into();
        local.optional = true;
        local.features = vec!["explicit".into()];
        local.uses_default_features = false;
        let mut git = dependency("git_dep", None, DependencyKind::Normal, None);
        git.source = Some("git+https://example.invalid/repo".into());
        let mut windows_local = dependency(
            "windows_local",
            Some("dep"),
            DependencyKind::Normal,
            Some("cfg(windows)"),
        );
        windows_local.features = vec!["windows_feature".into()];
        let mut build_dependency =
            dependency("build_dep", Some("dep"), DependencyKind::Build, None);
        build_dependency.features = vec!["build_feature".into()];
        app.dependencies = vec![
            local,
            dependency("registry_dep", None, DependencyKind::Normal, None),
            git,
            dependency("dev_dep", Some("dep"), DependencyKind::Development, None),
            build_dependency,
            windows_local,
            dependency(
                "outside_path",
                Some("../outside"),
                DependencyKind::Normal,
                None,
            ),
            dependency(
                "windows_only",
                None,
                DependencyKind::Normal,
                Some("cfg(windows)"),
            ),
        ];

        let mut dep = package(
            "dep",
            "2024",
            "dep",
            vec![target("dep_lib", "lib", "dep/src/lib.rs")],
        );
        dep.features = BTreeMap::from([
            ("default".into(), vec!["dep_default".into()]),
            ("dep_default".into(), Vec::new()),
            ("explicit".into(), Vec::new()),
            ("serde".into(), Vec::new()),
            ("fancy".into(), Vec::new()),
            ("windows_feature".into(), Vec::new()),
            ("build_feature".into(), Vec::new()),
        ]);

        let inventory = vec![
            source(
                Some(0),
                "app/src/lib.rs",
                "#[cfg(feature = \"fancy\")] pub fn enabled() -> dep_alias::Thing { dep_alias::Thing }\n",
            ),
            source(Some(0), "app/src/main.rs", "fn main() {}\n"),
            source(Some(0), "app/tests/api.rs", "#[test] fn api() {}\n"),
            source(
                Some(0),
                "app/build.rs",
                "fn main() { panic!(\"must not execute\") }\n",
            ),
            source(
                Some(0),
                "app/src/macros.rs",
                "compile_error!(\"must not load proc macro target\");\n",
            ),
            source(Some(1), "dep/src/lib.rs", "pub struct Thing;\n"),
            source(
                None,
                "fake-sysroot/library/std/src/lib.rs",
                "compile_error!(\"must not load sysroot\");\n",
            ),
        ];
        (vec![app, dep], inventory)
    }

    fn attested_sysroot_fixture() -> AttestedSysroot {
        AttestedSysroot {
            files: ["alloc", "core", "std"]
                .into_iter()
                .map(|name| SysrootSource {
                    rel_path: format!("library/{name}/src/lib.rs"),
                    text: format!("pub struct {name};\n"),
                })
                .collect(),
        }
    }

    #[test]
    fn builds_confined_vfs_crate_graph_and_crate_scoped_cfg() {
        let (packages, inventory) = fixture();
        let neutral = tempfile::tempdir().unwrap();
        let marker = neutral.path().join("executed");
        std::fs::write(
            neutral.path().join("rust-project.json"),
            r#"{"sysroot":"fake-sysroot"}"#,
        )
        .unwrap();
        std::fs::create_dir(neutral.path().join(".cargo")).unwrap();
        std::fs::write(
            neutral.path().join(".cargo/config.toml"),
            format!(
                "[build]\nrustc-wrapper = {:?}\n",
                neutral.path().join("must-not-run")
            ),
        )
        .unwrap();
        std::fs::write(
            neutral.path().join("build.rs"),
            format!("fn main() {{ std::fs::write({marker:?}, b\"executed\").unwrap(); }}"),
        )
        .unwrap();
        let profile = HirProjectProfile {
            target_triple: "x86_64-unknown-linux-gnu".into(),
            mode: HirProjectMode::Test,
            requested_features: vec!["app/fancy".into()],
        };

        let model = build_safe_project_model(&packages, &inventory, &profile, neutral.path())
            .expect("safe project model");
        let snapshot = model.snapshot();

        assert!(!marker.exists());
        assert_eq!(snapshot.target_triple, "x86_64-unknown-linux-gnu");
        assert_eq!(snapshot.crates.len(), 7);
        assert_eq!(ra_ap_hir::Crate::all(model.database()).len(), 7);
        assert!(snapshot.files.iter().all(|file| file.path != "app/build.rs"
            && file.path != "app/src/macros.rs"
            && !file.path.starts_with("fake-sysroot/")));
        assert_eq!(
            snapshot
                .files
                .iter()
                .map(|file| file.path.as_str())
                .collect::<Vec<_>>(),
            [
                "app/src/lib.rs",
                "app/src/main.rs",
                "app/tests/api.rs",
                "dep/src/lib.rs"
            ]
        );

        let app_lib = snapshot
            .crates
            .iter()
            .find(|krate| krate.target_name == "app_lib" && !krate.cfg.contains(&"test".into()))
            .unwrap();
        assert_eq!(app_lib.edition, "2018");
        assert!(app_lib.cfg.contains(&r#"feature="fancy""#.into()));
        assert!(app_lib.cfg.contains(&r#"target_os="linux""#.into()));
        assert!(app_lib.cfg.contains(&r#"target_feature="sse2""#.into()));
        assert!(!app_lib.cfg.contains(&r#"target_has_atomic="128""#.into()));
        assert!(app_lib.cfg.contains(&"unix".into()));
        assert!(!app_lib.cfg.contains(&"test".into()));
        assert!(
            app_lib
                .dependencies
                .iter()
                .any(|dependency| dependency.name == "dep_alias")
        );
        assert!(
            !app_lib
                .dependencies
                .iter()
                .any(|dependency| dependency.name == "dev_dep")
        );
        let app_lib_test = snapshot
            .crates
            .iter()
            .find(|krate| krate.target_name == "app_lib" && krate.cfg.contains(&"test".into()))
            .unwrap();
        assert!(
            app_lib_test
                .dependencies
                .iter()
                .any(|dependency| dependency.name == "dev_dep")
        );
        let app_test = snapshot
            .crates
            .iter()
            .find(|krate| krate.target_name == "app_test")
            .unwrap();
        assert!(app_test.cfg.contains(&"test".into()));
        assert!(
            app_test
                .dependencies
                .iter()
                .any(|dependency| dependency.name == "dev_dep")
        );
        let dep = snapshot
            .crates
            .iter()
            .find(|krate| krate.target_name == "dep_lib")
            .unwrap();
        assert_eq!(dep.edition, "2024");
        assert!(dep.cfg.contains(&r#"feature="explicit""#.into()));
        assert!(dep.cfg.contains(&r#"feature="serde""#.into()));
        assert!(!dep.cfg.contains(&r#"feature="fancy""#.into()));
        assert!(!dep.cfg.contains(&r#"feature="windows_feature""#.into()));
        assert!(!dep.cfg.contains(&r#"feature="build_feature""#.into()));
        assert!(snapshot.externals.iter().any(|external| {
            external.name == "registry_dep" && external.kind == ExternalCrateKind::Registry
        }));
        assert!(snapshot.externals.iter().any(|external| {
            external.name == "git_dep" && external.kind == ExternalCrateKind::Git
        }));
        assert!(snapshot.externals.iter().any(|external| {
            external.name == "std" && external.kind == ExternalCrateKind::Sysroot
        }));
        assert!(snapshot.externals.iter().any(|external| {
            external.name == "core" && external.kind == ExternalCrateKind::Sysroot
        }));
        assert!(!snapshot.externals.iter().any(|external| {
            external.name == "alloc" && external.kind == ExternalCrateKind::Sysroot
        }));
        assert!(snapshot.externals.iter().any(|external| {
            external.name == "outside_path"
                && external.kind == ExternalCrateKind::OutsideOrUnmodeledPath
        }));
        assert!(
            !snapshot
                .externals
                .iter()
                .any(|external| { external.name == "windows_only" })
        );
        assert!(
            snapshot
                .issues
                .iter()
                .any(|issue| { issue.code == "RUST_HIR_EXTERNAL_DEFINITION_UNAVAILABLE" })
        );
        assert!(
            snapshot
                .issues
                .iter()
                .any(|issue| issue.code == "BUILD_SCRIPT_NOT_EXECUTED")
        );
        assert!(
            snapshot
                .issues
                .iter()
                .any(|issue| issue.code == "PROC_MACRO_NOT_EXECUTED")
        );
    }

    #[test]
    fn maps_attested_sysroot_into_a_separate_library_vfs_and_crate_graph() {
        let (packages, inventory) = fixture();
        let sysroot = attested_sysroot_fixture();
        let neutral = tempfile::tempdir().unwrap();
        let profile = HirProjectProfile {
            target_triple: "x86_64-unknown-linux-gnu".into(),
            mode: HirProjectMode::Test,
            requested_features: vec!["app/fancy".into()],
        };

        let model = build_safe_project_model_with_sysroot(
            &packages,
            &inventory,
            Some(&sysroot),
            &profile,
            neutral.path(),
        )
        .expect("safe project model with attested sysroot");
        let snapshot = model.snapshot();

        assert_eq!(snapshot.crates.len(), 7);
        assert_eq!(snapshot.sysroot_crates.len(), 3);
        assert_eq!(model.sysroot_crate_instances().len(), 3);
        assert_eq!(ra_ap_hir::Crate::all(model.database()).len(), 10);
        assert_eq!(
            snapshot
                .sysroot_crates
                .iter()
                .map(|krate| krate.name.as_str())
                .collect::<Vec<_>>(),
            ["core", "alloc", "std"]
        );
        assert_eq!(
            snapshot.sysroot_crates[0].dependencies,
            Vec::<String>::new()
        );
        assert_eq!(snapshot.sysroot_crates[1].dependencies, ["core"]);
        assert_eq!(snapshot.sysroot_crates[2].dependencies, ["alloc", "core"]);
        for krate in &snapshot.sysroot_crates {
            assert!(
                snapshot.files.iter().any(|file| {
                    file.file_id == krate.root_file_id && file.path == krate.root_path
                }),
                "sysroot crate {} has no canonical VFS root mapping",
                krate.name
            );
        }
        assert!(snapshot.crates.iter().all(|krate| {
            ["core", "std"].iter().all(|name| {
                krate.dependencies.iter().any(|dependency| {
                    dependency.name == *name
                        && dependency.crate_key == format!("rust-sysroot#{name}")
                })
            })
        }));
        assert!(snapshot.crates.iter().all(|krate| {
            !krate
                .dependencies
                .iter()
                .any(|dependency| dependency.name == "alloc")
        }));
        assert!(!snapshot.externals.iter().any(|external| {
            external.kind == ExternalCrateKind::Sysroot
                && matches!(external.name.as_str(), "alloc" | "core" | "std")
        }));
        assert!(
            !snapshot
                .issues
                .iter()
                .any(|issue| { issue.code == "RUST_HIR_SYSROOT_UNAVAILABLE" })
        );
    }

    #[test]
    fn crate_root_attributes_control_attested_sysroot_dependencies() {
        let (packages, mut inventory) = fixture();
        inventory
            .iter_mut()
            .find(|source| source.rel_path == "app/src/lib.rs")
            .unwrap()
            .text = "#![cfg_attr(unix, no_std)]\nextern crate alloc;\npub fn enabled() {}\n".into();
        let model = build_safe_project_model_with_sysroot(
            &packages,
            &inventory,
            Some(&attested_sysroot_fixture()),
            &HirProjectProfile {
                target_triple: "x86_64-unknown-linux-gnu".into(),
                mode: HirProjectMode::Check,
                requested_features: Vec::new(),
            },
            Path::new(""),
        )
        .expect("active no_std cfg_attr must produce a confined crate graph");
        let app = model
            .snapshot()
            .crates
            .iter()
            .find(|krate| krate.target_name == "app_lib")
            .expect("app library crate");
        assert_eq!(
            app.dependencies
                .iter()
                .filter(|dependency| dependency.crate_key.starts_with("rust-sysroot#"))
                .map(|dependency| dependency.name.as_str())
                .collect::<Vec<_>>(),
            ["alloc", "core"]
        );

        inventory
            .iter_mut()
            .find(|source| source.rel_path == "app/src/lib.rs")
            .unwrap()
            .text = "#![no_core]\npub fn enabled() {}\n".into();
        let error = build_safe_project_model_with_sysroot(
            &packages,
            &inventory,
            Some(&attested_sysroot_fixture()),
            &HirProjectProfile {
                target_triple: "x86_64-unknown-linux-gnu".into(),
                mode: HirProjectMode::Check,
                requested_features: Vec::new(),
            },
            Path::new(""),
        )
        .err()
        .expect("no_core must fail closed instead of receiving fabricated sysroot edges");
        assert_eq!(error.kind, ProjectModelErrorKind::UnsupportedInput);
        assert!(error.reason.contains("no_core"));
    }

    #[test]
    fn target_specific_feature_propagation_follows_the_selected_cfg() {
        let (packages, inventory) = fixture();
        let neutral = tempfile::tempdir().unwrap();
        let model = build_safe_project_model(
            &packages,
            &inventory,
            &HirProjectProfile {
                target_triple: "x86_64-pc-windows-msvc".into(),
                mode: HirProjectMode::Build,
                requested_features: vec!["app/fancy".into()],
            },
            neutral.path(),
        )
        .unwrap();
        let dependency = model
            .snapshot()
            .crates
            .iter()
            .find(|krate| krate.target_name == "dep_lib")
            .unwrap();

        assert!(
            dependency
                .cfg
                .contains(&r#"feature="windows_feature""#.into())
        );
        assert!(!dependency.cfg.contains(&r#"feature="explicit""#.into()));
        assert!(!dependency.cfg.contains(&r#"feature="serde""#.into()));
        assert!(
            !dependency
                .cfg
                .contains(&r#"feature="build_feature""#.into())
        );
    }

    #[test]
    fn dependency_closure_starts_only_from_targets_selected_by_the_mode() {
        let mut active = package(
            "active",
            "2021",
            "active",
            vec![target("active", "lib", "active/src/lib.rs")],
        );
        active.targets[0].test = false;
        active.dependencies.push(dependency(
            "dep",
            Some("dep"),
            DependencyKind::Development,
            None,
        ));
        let mut inactive = package(
            "inactive",
            "2021",
            "inactive",
            vec![target("inactive_test", "test", "inactive/tests/only.rs")],
        );
        inactive.targets[0].test = false;
        inactive
            .dependencies
            .push(dependency("dep", Some("dep"), DependencyKind::Normal, None));
        let mut dep = package(
            "dep",
            "2021",
            "dep",
            vec![target("dep", "lib", "dep/src/lib.rs")],
        );
        dep.workspace_member = false;
        let packages = vec![active, inactive, dep];
        let inventory = vec![
            source(Some(0), "active/src/lib.rs", "pub fn active() {}\n"),
            source(Some(1), "inactive/tests/only.rs", "#[test] fn only() {}\n"),
            source(Some(2), "dep/src/lib.rs", "pub fn dep() {}\n"),
        ];
        let neutral = tempfile::tempdir().unwrap();

        for mode in [HirProjectMode::Check, HirProjectMode::Test] {
            let model = build_safe_project_model(
                &packages,
                &inventory,
                &HirProjectProfile {
                    target_triple: "x86_64-unknown-linux-gnu".into(),
                    mode,
                    requested_features: Vec::new(),
                },
                neutral.path(),
            )
            .expect("selected target closure");
            assert_eq!(
                model
                    .snapshot()
                    .crates
                    .iter()
                    .map(|krate| krate.package.as_str())
                    .collect::<Vec<_>>(),
                ["active"],
                "mode {mode:?} retained an orphan dependency crate"
            );
            assert_eq!(
                model
                    .snapshot()
                    .files
                    .iter()
                    .map(|file| file.path.as_str())
                    .collect::<Vec<_>>(),
                ["active/src/lib.rs"]
            );
        }
    }

    #[test]
    fn target_metadata_controls_edition_feature_gating_and_test_harnesses() {
        let mut app = package(
            "app",
            "2018",
            "app",
            vec![
                target("app_lib", "lib", "app/src/lib.rs"),
                target("tool", "bin", "app/src/tool.rs"),
                target("disabled_test", "test", "app/tests/disabled.rs"),
                target("plain_example", "example", "app/examples/plain.rs"),
                target("tested_example", "example", "app/examples/tested.rs"),
            ],
        );
        app.features.insert("tooling".into(), Vec::new());
        app.targets
            .iter_mut()
            .find(|target| target.name == "tool")
            .unwrap()
            .edition = "2024".into();
        app.targets
            .iter_mut()
            .find(|target| target.name == "tool")
            .unwrap()
            .required_features = vec!["tooling".into()];
        app.targets
            .iter_mut()
            .find(|target| target.name == "disabled_test")
            .unwrap()
            .test = false;
        app.targets
            .iter_mut()
            .find(|target| target.name == "tested_example")
            .unwrap()
            .test = true;
        let inventory = vec![
            source(Some(0), "app/src/lib.rs", "pub fn lib() {}\n"),
            source(Some(0), "app/src/tool.rs", "fn main() {}\n"),
            source(
                Some(0),
                "app/tests/disabled.rs",
                "#[test] fn disabled() {}\n",
            ),
            source(Some(0), "app/examples/plain.rs", "fn main() {}\n"),
            source(
                Some(0),
                "app/examples/tested.rs",
                "#[test] fn tested() {}\n",
            ),
        ];
        let neutral = tempfile::tempdir().unwrap();

        let without_feature = build_safe_project_model(
            std::slice::from_ref(&app),
            &inventory,
            &HirProjectProfile {
                target_triple: "x86_64-unknown-linux-gnu".into(),
                mode: HirProjectMode::Test,
                requested_features: Vec::new(),
            },
            neutral.path(),
        )
        .expect("ungated targets remain available");
        assert!(
            !without_feature
                .snapshot()
                .crates
                .iter()
                .any(|krate| krate.target_name == "tool")
        );
        assert!(
            !without_feature
                .snapshot()
                .crates
                .iter()
                .any(|krate| krate.target_name == "disabled_test")
        );
        let plain_example = without_feature
            .snapshot()
            .crates
            .iter()
            .find(|krate| krate.target_name == "plain_example")
            .unwrap();
        assert!(!plain_example.cfg.contains(&"test".into()));
        let tested_example = without_feature
            .snapshot()
            .crates
            .iter()
            .find(|krate| krate.target_name == "tested_example")
            .unwrap();
        assert!(tested_example.cfg.contains(&"test".into()));
        assert_eq!(
            without_feature
                .snapshot()
                .crates
                .iter()
                .filter(|krate| krate.target_name == "app_lib")
                .count(),
            2
        );

        let with_feature = build_safe_project_model(
            &[app],
            &inventory,
            &HirProjectProfile {
                target_triple: "x86_64-unknown-linux-gnu".into(),
                mode: HirProjectMode::Test,
                requested_features: vec!["app/tooling".into()],
            },
            neutral.path(),
        )
        .expect("required target feature is enabled");
        let tool = with_feature
            .snapshot()
            .crates
            .iter()
            .find(|krate| krate.target_name == "tool" && !krate.cfg.contains(&"test".into()))
            .unwrap();
        assert_eq!(tool.edition, "2024");
    }

    #[test]
    fn resolver_one_unifies_inactive_target_and_build_dependency_features() {
        let (mut packages, inventory) = fixture();
        for package in &mut packages {
            package.feature_resolver = 1;
        }
        let neutral = tempfile::tempdir().unwrap();
        let model = build_safe_project_model(
            &packages,
            &inventory,
            &HirProjectProfile {
                target_triple: "x86_64-unknown-linux-gnu".into(),
                mode: HirProjectMode::Build,
                requested_features: vec!["app/fancy".into()],
            },
            neutral.path(),
        )
        .unwrap();
        let dependency = model
            .snapshot()
            .crates
            .iter()
            .find(|krate| krate.target_name == "dep_lib")
            .unwrap();

        assert!(
            dependency
                .cfg
                .contains(&r#"feature="windows_feature""#.into())
        );
        assert!(
            dependency
                .cfg
                .contains(&r#"feature="build_feature""#.into())
        );
    }

    #[test]
    fn nonmember_path_dependency_defaults_follow_the_incoming_edge() {
        let (mut packages, inventory) = fixture();
        packages[1].from_metadata = false;
        packages[1].workspace_member = false;
        packages[0]
            .dependencies
            .iter_mut()
            .find(|dependency| dependency.alias == "dev_dep")
            .unwrap()
            .uses_default_features = false;
        packages[0].features.insert("dev_leak".into(), Vec::new());
        let mut ignored_dev_dependency =
            dependency("app_dev", Some("app"), DependencyKind::Development, None);
        ignored_dev_dependency.features = vec!["dev_leak".into()];
        ignored_dev_dependency.uses_default_features = false;
        packages[1].dependencies.push(ignored_dev_dependency);
        let neutral = tempfile::tempdir().unwrap();
        let profile = HirProjectProfile {
            target_triple: "x86_64-unknown-linux-gnu".into(),
            mode: HirProjectMode::Test,
            requested_features: vec!["app/fancy".into()],
        };

        let without_defaults =
            build_safe_project_model(&packages, &inventory, &profile, neutral.path()).unwrap();
        let dependency = without_defaults
            .snapshot()
            .crates
            .iter()
            .find(|krate| krate.target_name == "dep_lib")
            .unwrap();
        assert!(!dependency.cfg.contains(&r#"feature="default""#.into()));
        assert!(!dependency.cfg.contains(&r#"feature="dep_default""#.into()));
        let app = without_defaults
            .snapshot()
            .crates
            .iter()
            .find(|krate| krate.target_name == "app_lib")
            .unwrap();
        assert!(!app.cfg.contains(&r#"feature="dev_leak""#.into()));

        packages[0]
            .dependencies
            .iter_mut()
            .find(|dependency| dependency.alias == "dep_alias")
            .unwrap()
            .uses_default_features = true;
        let with_defaults =
            build_safe_project_model(&packages, &inventory, &profile, neutral.path()).unwrap();
        let dependency = with_defaults
            .snapshot()
            .crates
            .iter()
            .find(|krate| krate.target_name == "dep_lib")
            .unwrap();
        assert!(dependency.cfg.contains(&r#"feature="default""#.into()));
        assert!(dependency.cfg.contains(&r#"feature="dep_default""#.into()));
    }

    #[test]
    fn inactive_nonmember_path_packages_are_not_loaded() {
        let (mut packages, mut inventory) = fixture();
        let mut inactive = package(
            "inactive",
            "2024",
            "inactive",
            vec![target("inactive_lib", "lib", "inactive/src/lib.rs")],
        );
        inactive.workspace_member = false;
        inactive.from_metadata = false;
        packages.push(inactive);
        inventory.push(source(
            Some(2),
            "inactive/src/lib.rs",
            "#[cfg(project_generated)] compile_error!(\"must not load inactive package\");\n",
        ));

        let mut optional = dependency(
            "inactive_optional",
            Some("inactive"),
            DependencyKind::Normal,
            None,
        );
        optional.optional = true;
        let build = dependency(
            "inactive_build",
            Some("inactive"),
            DependencyKind::Build,
            None,
        );
        let target_only = dependency(
            "inactive_windows",
            Some("inactive"),
            DependencyKind::Normal,
            Some("cfg(windows)"),
        );
        packages[0]
            .dependencies
            .extend([optional, build, target_only]);

        let neutral = tempfile::tempdir().unwrap();
        let model = build_safe_project_model(
            &packages,
            &inventory,
            &HirProjectProfile {
                target_triple: "x86_64-unknown-linux-gnu".into(),
                mode: HirProjectMode::Build,
                requested_features: vec!["app/fancy".into()],
            },
            neutral.path(),
        )
        .unwrap();

        assert!(
            model
                .snapshot()
                .files
                .iter()
                .all(|file| !file.path.starts_with("inactive/"))
        );
        assert!(
            model
                .snapshot()
                .crates
                .iter()
                .all(|krate| krate.package != "inactive")
        );
        assert!(model.snapshot().externals.iter().any(|external| {
            external.name == "inactive_build" && external.kind == ExternalCrateKind::BuildDependency
        }));
    }

    #[test]
    fn canonical_snapshot_is_independent_of_inventory_order_and_neutral_path() {
        let (packages, inventory) = fixture();
        let first_neutral = tempfile::tempdir().unwrap();
        let second_neutral = tempfile::tempdir().unwrap();
        let first = build_safe_project_model(
            &packages,
            &inventory,
            &HirProjectProfile {
                target_triple: "aarch64-apple-darwin".into(),
                mode: HirProjectMode::Test,
                requested_features: vec!["app/fancy".into()],
            },
            first_neutral.path(),
        )
        .unwrap();
        let mut reversed = inventory;
        reversed.reverse();
        let second = build_safe_project_model(
            &packages,
            &reversed,
            &HirProjectProfile {
                target_triple: "aarch64-apple-darwin".into(),
                mode: HirProjectMode::Test,
                requested_features: vec!["app/fancy".into()],
            },
            second_neutral.path(),
        )
        .unwrap();

        assert_eq!(first.snapshot(), second.snapshot());
        let first_proc_macro_cwds: BTreeSet<_> = ra_ap_hir::Crate::all(first.database())
            .into_iter()
            .map(|krate| {
                krate
                    .base()
                    .data(first.database())
                    .proc_macro_cwd
                    .as_str()
                    .to_owned()
            })
            .collect();
        let second_proc_macro_cwds: BTreeSet<_> = ra_ap_hir::Crate::all(second.database())
            .into_iter()
            .map(|krate| {
                krate
                    .base()
                    .data(second.database())
                    .proc_macro_cwd
                    .as_str()
                    .to_owned()
            })
            .collect();
        assert_eq!(first_proc_macro_cwds, second_proc_macro_cwds);
        assert_eq!(
            first_proc_macro_cwds,
            BTreeSet::from([if cfg!(windows) {
                "C:/__depgraph_inert_proc_macro__".to_owned()
            } else {
                "/__depgraph_inert_proc_macro__".to_owned()
            }])
        );
        assert!(first.snapshot().crates.iter().any(|krate| {
            krate.target_name == "app_test" && krate.cfg.contains(&"test".into())
        }));
        assert!(first.snapshot().crates.iter().any(|krate| {
            krate.target_name == "dep_lib" && !krate.cfg.contains(&"test".into())
        }));
        assert!(first.snapshot().crates.iter().all(|krate| {
            krate.cfg.contains(&r#"target_feature="neon""#.into())
                && krate.cfg.contains(&r#"target_has_atomic="128""#.into())
        }));
        let serialized = serde_json::to_string(first.snapshot()).unwrap();
        assert!(!serialized.contains(first_neutral.path().to_string_lossy().as_ref()));
        assert!(!serialized.contains(second_neutral.path().to_string_lossy().as_ref()));
    }

    #[test]
    fn rejects_unsupported_or_incomplete_input_atomically() {
        let (packages, inventory) = fixture();
        let neutral = tempfile::tempdir().unwrap();
        let unsupported = build_safe_project_model(
            &packages,
            &inventory,
            &HirProjectProfile {
                target_triple: "custom-target.json".into(),
                mode: HirProjectMode::Build,
                requested_features: Vec::new(),
            },
            neutral.path(),
        )
        .err()
        .unwrap();
        assert_eq!(unsupported.kind, ProjectModelErrorKind::UnsupportedInput);
        let unsupported_with_sysroot = build_safe_project_model_with_sysroot(
            &packages,
            &inventory,
            Some(&attested_sysroot_fixture()),
            &HirProjectProfile {
                target_triple: "custom-target.json".into(),
                mode: HirProjectMode::Build,
                requested_features: Vec::new(),
            },
            neutral.path(),
        )
        .err()
        .unwrap();
        assert_eq!(
            unsupported_with_sysroot.kind,
            ProjectModelErrorKind::UnsupportedInput
        );

        let mut profile_override_packages = packages.clone();
        profile_override_packages[0]
            .cfg_profile_overrides
            .insert("dev".into());
        let profile_override = build_safe_project_model(
            &profile_override_packages,
            &inventory,
            &HirProjectProfile {
                target_triple: "x86_64-unknown-linux-gnu".into(),
                mode: HirProjectMode::Build,
                requested_features: Vec::new(),
            },
            neutral.path(),
        )
        .err()
        .unwrap();
        assert_eq!(
            profile_override.kind,
            ProjectModelErrorKind::UnsupportedInput
        );
        assert!(profile_override.reason.contains("profile dev"));

        let mut inactive_cfg = inventory.clone();
        inactive_cfg
            .iter_mut()
            .find(|source| source.rel_path == "app/src/lib.rs")
            .unwrap()
            .text
            .push_str(
                "#[cfg_attr(windows, cfg(project_generated))] fn portable() {}\n\
                 #[cfg(all(windows, project_generated))] fn also_portable() {}\n",
            );
        build_safe_project_model(
            &packages,
            &inactive_cfg,
            &HirProjectProfile {
                target_triple: "x86_64-unknown-linux-gnu".into(),
                mode: HirProjectMode::Check,
                requested_features: Vec::new(),
            },
            neutral.path(),
        )
        .expect("inactive cfg branches must not require unavailable custom cfg values");

        let mut mixed_test_cfg = inventory.clone();
        mixed_test_cfg
            .iter_mut()
            .find(|source| source.rel_path == "app/src/lib.rs")
            .unwrap()
            .text
            .push_str("#[cfg_attr(not(test), cfg(non_test_generated))] fn mixed() {}\n");
        let mixed_test_cfg = build_safe_project_model(
            &packages,
            &mixed_test_cfg,
            &HirProjectProfile {
                target_triple: "x86_64-unknown-linux-gnu".into(),
                mode: HirProjectMode::Test,
                requested_features: Vec::new(),
            },
            neutral.path(),
        )
        .err()
        .unwrap();
        assert_eq!(mixed_test_cfg.kind, ProjectModelErrorKind::UnsupportedInput);
        assert!(mixed_test_cfg.reason.contains("non_test_generated"));

        for malformed in [
            "#[cfg_attr(unix)] fn malformed() {}\n",
            "#[cfg_attr(unix, cfg_attr(unix))] fn malformed() {}\n",
        ] {
            let mut malformed_cfg_attr = inventory.clone();
            malformed_cfg_attr
                .iter_mut()
                .find(|source| source.rel_path == "app/src/lib.rs")
                .unwrap()
                .text
                .push_str(malformed);
            let error = build_safe_project_model(
                &packages,
                &malformed_cfg_attr,
                &HirProjectProfile {
                    target_triple: "x86_64-unknown-linux-gnu".into(),
                    mode: HirProjectMode::Check,
                    requested_features: Vec::new(),
                },
                neutral.path(),
            )
            .err()
            .unwrap();
            assert_eq!(error.kind, ProjectModelErrorKind::UnsupportedInput);
            assert!(error.reason.contains("requires a predicate and attribute"));
        }

        let mut custom_cfg = inventory.clone();
        custom_cfg
            .iter_mut()
            .find(|source| source.rel_path == "app/src/lib.rs")
            .unwrap()
            .text
            .push_str("#[cfg(project_generated)] fn generated() {}\n");
        let unsupported_cfg = build_safe_project_model(
            &packages,
            &custom_cfg,
            &HirProjectProfile {
                target_triple: "x86_64-unknown-linux-gnu".into(),
                mode: HirProjectMode::Check,
                requested_features: Vec::new(),
            },
            neutral.path(),
        )
        .err()
        .unwrap();
        assert_eq!(
            unsupported_cfg.kind,
            ProjectModelErrorKind::UnsupportedInput
        );
        assert!(unsupported_cfg.reason.contains("project_generated"));

        let mut macro_cfg = inventory.clone();
        macro_cfg
            .iter_mut()
            .find(|source| source.rel_path == "app/src/lib.rs")
            .unwrap()
            .text
            .push_str("const _: bool = cfg!(expression_generated);\n");
        let unsupported_macro_cfg = build_safe_project_model(
            &packages,
            &macro_cfg,
            &HirProjectProfile {
                target_triple: "x86_64-unknown-linux-gnu".into(),
                mode: HirProjectMode::Check,
                requested_features: Vec::new(),
            },
            neutral.path(),
        )
        .err()
        .unwrap();
        assert_eq!(
            unsupported_macro_cfg.kind,
            ProjectModelErrorKind::UnsupportedInput
        );
        assert!(
            unsupported_macro_cfg
                .reason
                .contains("expression_generated")
        );

        let mut missing_root = inventory.clone();
        missing_root.retain(|source| source.rel_path != "app/src/lib.rs");
        let incomplete = build_safe_project_model(
            &packages,
            &missing_root,
            &HirProjectProfile {
                target_triple: "x86_64-pc-windows-msvc".into(),
                mode: HirProjectMode::Check,
                requested_features: Vec::new(),
            },
            neutral.path(),
        )
        .err()
        .unwrap();
        assert_eq!(incomplete.kind, ProjectModelErrorKind::Incomplete);

        let mut duplicate = inventory;
        duplicate.push(duplicate[0].clone());
        let duplicate = build_safe_project_model(
            &packages,
            &duplicate,
            &HirProjectProfile {
                target_triple: "x86_64-unknown-linux-gnu".into(),
                mode: HirProjectMode::Check,
                requested_features: Vec::new(),
            },
            neutral.path(),
        )
        .err()
        .unwrap();
        assert_eq!(duplicate.kind, ProjectModelErrorKind::Incomplete);
        assert!(duplicate.reason.contains("duplicate"));
    }
}
