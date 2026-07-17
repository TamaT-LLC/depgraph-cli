use crate::{
    cargo_mirror::CargoInputMirror,
    manifest::{
        Dependency, DependencyKind, ManifestDocument, Package, Target, dependency_condition,
        normalize_feature_map, normalize_path, package_feature_resolver, parse_packages,
        slash_path, workspace_cfg_profile_overrides_at, workspace_feature_resolver_at,
    },
};
use anyhow::{Context, Result, bail};
use serde::Deserialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsStr,
    fs,
    path::{Path, PathBuf},
    process::Command,
};
use tempfile::{Builder as TempDirBuilder, TempDir};

#[derive(Clone, Debug, Default)]
pub(crate) struct LockIndex {
    versions_by_name: BTreeMap<String, BTreeSet<String>>,
    owner_dependencies: BTreeMap<(String, String, String), String>,
    source: Option<Vec<u8>>,
    pub path: Option<String>,
    pub failure: Option<LockFailure>,
}

#[derive(Clone, Debug)]
pub(crate) struct LockFailure {
    pub path: String,
    pub code: &'static str,
    pub reason: String,
}

impl LockIndex {
    pub fn read(root: &Path, workspace_root: &Path) -> Self {
        let path = workspace_root.join("Cargo.lock");
        let lexical_path = path
            .strip_prefix(root)
            .ok()
            .map(slash_path)
            .unwrap_or_else(|| "__depgraph_skipped__/Cargo.lock".into());
        let metadata = match std::fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Self::default(),
            Err(_) => {
                return Self::failed(
                    lexical_path,
                    "RUST_LOCKFILE_READ",
                    "Cargo.lock could not be inspected in safe mode",
                );
            }
        };
        if metadata.file_type().is_symlink() {
            let confined = path
                .canonicalize()
                .is_ok_and(|target| target.starts_with(root) && target.is_file());
            let ledger_path = if confined {
                lexical_path
            } else {
                format!(
                    "__depgraph_skipped__/{}",
                    lexical_path.trim_start_matches('/')
                )
            };
            return Self::failed(
                ledger_path,
                "RUST_LOCKFILE_PATH_CONFINEMENT",
                "Cargo.lock is a symbolic link and was not followed in safe mode",
            );
        }
        if !metadata.is_file() {
            return Self::failed(
                lexical_path,
                "RUST_LOCKFILE_READ",
                "Cargo.lock is not a regular file",
            );
        }
        let Ok(canonical_path) = path.canonicalize() else {
            return Self::failed(
                lexical_path,
                "RUST_LOCKFILE_READ",
                "Cargo.lock could not be canonicalized in safe mode",
            );
        };
        if !canonical_path.starts_with(root) || !canonical_path.is_file() {
            return Self::failed(
                format!(
                    "__depgraph_skipped__/{}",
                    lexical_path.trim_start_matches('/')
                ),
                "RUST_LOCKFILE_PATH_CONFINEMENT",
                "Cargo.lock does not resolve to a regular file within the scan root",
            );
        }
        let Ok(source) = std::fs::read(&canonical_path) else {
            return Self::failed(
                lexical_path,
                "RUST_LOCKFILE_READ",
                "Cargo.lock could not be read in safe mode",
            );
        };
        let Ok(source_text) = std::str::from_utf8(&source) else {
            return Self::failed(
                lexical_path,
                "RUST_LOCKFILE_PARSE",
                "Cargo.lock is not valid UTF-8 TOML",
            );
        };
        let Ok(value) = toml::from_str::<toml::Value>(source_text) else {
            return Self::failed(
                lexical_path,
                "RUST_LOCKFILE_PARSE",
                "Cargo.lock is not valid TOML",
            );
        };
        if contains_local_file_url(&value) {
            return Self::failed(
                lexical_path,
                "RUST_LOCKFILE_PATH_CONFINEMENT",
                "Cargo.lock contains a local file URL source that is not admitted",
            );
        }
        let mut index = Self {
            source: Some(source),
            path: Some(lexical_path),
            ..Self::default()
        };
        let Some(packages) = value.get("package").and_then(toml::Value::as_array) else {
            return index;
        };
        for package in packages.iter().filter_map(toml::Value::as_table) {
            let (Some(name), Some(version)) = (
                package.get("name").and_then(toml::Value::as_str),
                package.get("version").and_then(toml::Value::as_str),
            ) else {
                continue;
            };
            let source = package.get("source").and_then(toml::Value::as_str);
            if source.is_some() {
                index
                    .versions_by_name
                    .entry(name.into())
                    .or_default()
                    .insert(version.into());
            }
        }
        for package in packages.iter().filter_map(toml::Value::as_table) {
            let (Some(owner), Some(owner_version)) = (
                package.get("name").and_then(toml::Value::as_str),
                package.get("version").and_then(toml::Value::as_str),
            ) else {
                continue;
            };
            let Some(dependencies) = package.get("dependencies").and_then(toml::Value::as_array)
            else {
                continue;
            };
            for dependency in dependencies.iter().filter_map(toml::Value::as_str) {
                let mut parts = dependency.split_whitespace();
                let Some(name) = parts.next() else {
                    continue;
                };
                let explicit_version = parts.next().filter(|part| {
                    part.chars()
                        .next()
                        .is_some_and(|character| character.is_ascii_digit())
                });
                let version = explicit_version.map(str::to_owned).or_else(|| {
                    index
                        .versions_by_name
                        .get(name)
                        .filter(|versions| versions.len() == 1)
                        .and_then(|versions| versions.first().cloned())
                });
                if let Some(version) = version {
                    index
                        .owner_dependencies
                        .insert((owner.into(), owner_version.into(), name.into()), version);
                }
            }
        }
        index
    }

    fn failed(path: String, code: &'static str, reason: &str) -> Self {
        Self {
            failure: Some(LockFailure {
                path,
                code,
                reason: reason.into(),
            }),
            ..Self::default()
        }
    }

    pub fn resolve(&self, owner: &str, owner_version: &str, dependency: &str) -> Option<&str> {
        self.owner_dependencies
            .get(&(
                owner.to_owned(),
                owner_version.to_owned(),
                dependency.to_owned(),
            ))
            .map(String::as_str)
            .or_else(|| {
                self.versions_by_name
                    .get(dependency)
                    .filter(|versions| versions.len() == 1)
                    .and_then(|versions| versions.first().map(String::as_str))
            })
    }

    pub(crate) fn source(&self) -> Option<&[u8]> {
        self.source.as_deref()
    }
}

fn contains_local_file_url(value: &toml::Value) -> bool {
    match value {
        toml::Value::String(value) => value.to_ascii_lowercase().contains("file:"),
        toml::Value::Array(values) => values.iter().any(contains_local_file_url),
        toml::Value::Table(values) => values.values().any(contains_local_file_url),
        _ => false,
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct CargoMetadata {
    packages: Vec<MetadataPackage>,
    workspace_members: Vec<String>,
    workspace_root: PathBuf,
}

#[derive(Debug, Deserialize)]
struct MetadataPackage {
    id: String,
    name: String,
    version: String,
    edition: String,
    manifest_path: PathBuf,
    #[serde(default)]
    features: BTreeMap<String, Vec<String>>,
    dependencies: Vec<MetadataDependency>,
    targets: Vec<MetadataTarget>,
}

#[derive(Debug, Deserialize)]
struct MetadataDependency {
    name: String,
    source: Option<String>,
    req: String,
    kind: Option<String>,
    rename: Option<String>,
    optional: bool,
    #[serde(default)]
    features: Vec<String>,
    #[serde(default = "default_true")]
    uses_default_features: bool,
    target: Option<String>,
    path: Option<PathBuf>,
}

const fn default_true() -> bool {
    true
}

#[derive(Debug, Deserialize)]
struct MetadataTarget {
    name: String,
    kind: Vec<String>,
    crate_types: Vec<String>,
    src_path: PathBuf,
    #[serde(default)]
    edition: Option<String>,
    #[serde(default, rename = "required-features")]
    required_features: Vec<String>,
    #[serde(default)]
    test: Option<bool>,
}

fn canonical_target_kind(kind: &[String], crate_types: &[String]) -> String {
    if kind.iter().any(|kind| kind == "custom-build") {
        "custom-build".into()
    } else if kind
        .iter()
        .chain(crate_types)
        .any(|kind| matches!(kind.as_str(), "lib" | "rlib" | "dylib"))
    {
        "lib".into()
    } else {
        kind.first().cloned().unwrap_or_else(|| "unknown".into())
    }
}

impl CargoMetadata {
    pub fn workspace_root(&self) -> &Path {
        &self.workspace_root
    }

    fn remap_paths_with(mut self, mut remap: impl FnMut(&Path) -> Result<PathBuf>) -> Result<Self> {
        self.workspace_root = remap(&self.workspace_root)
            .context("remap cargo metadata workspace root to inventory")?;
        for package in &mut self.packages {
            package.manifest_path = remap(&package.manifest_path)
                .context("remap cargo metadata manifest to inventory")?;
            for dependency in &mut package.dependencies {
                if let Some(path) = &dependency.path {
                    dependency.path = Some(
                        remap(path).context("remap cargo metadata path dependency to inventory")?,
                    );
                }
            }
            for target in &mut package.targets {
                target.src_path =
                    remap(&target.src_path).context("remap cargo metadata target to inventory")?;
            }
        }
        Ok(self)
    }

    fn remap_from_mirror(mut self, mirror: &CargoInputMirror) -> Result<Self> {
        let mut stable_ids = BTreeMap::new();
        for package in &self.packages {
            for dependency in &package.dependencies {
                validate_dependency_source(dependency.source.as_deref(), mirror.project_root())?;
            }
            stable_ids.insert(
                package.id.clone(),
                mirror
                    .stable_manifest_id(&package.manifest_path)
                    .context("map cargo package identity to inventory")?,
            );
        }
        for package in &mut self.packages {
            package.id = stable_ids
                .get(&package.id)
                .cloned()
                .context("cargo package identity is not admitted")?;
        }
        for member in &mut self.workspace_members {
            *member = stable_ids
                .get(member)
                .cloned()
                .context("cargo workspace member identity is not admitted")?;
        }
        self.remap_paths_with(|path| mirror.remap_path(path).map_err(anyhow::Error::from))
    }

    pub fn into_packages(
        self,
        root: &Path,
        lock: &LockIndex,
        documents: &[ManifestDocument],
    ) -> Result<(Vec<Package>, Vec<ManifestDocument>)> {
        let workspace_resolver = workspace_feature_resolver_at(documents, &self.workspace_root);
        let cfg_profile_overrides =
            workspace_cfg_profile_overrides_at(documents, &self.workspace_root);
        let members: BTreeSet<_> = self.workspace_members.into_iter().collect();
        let documents_by_path: BTreeMap<_, _> = documents
            .iter()
            .map(|document| (normalize_path(&document.abs_path), document.clone()))
            .collect();
        let mut active_documents = Vec::new();
        if let Some(workspace_document) =
            documents_by_path.get(&normalize_path(&self.workspace_root.join("Cargo.toml")))
        {
            active_documents.push(workspace_document.clone());
        }
        let mut packages = Vec::new();
        for package in self
            .packages
            .into_iter()
            .filter(|package| members.contains(&package.id))
        {
            let manifest_path = normalize_path(&package.manifest_path);
            if !manifest_path.starts_with(root) {
                bail!(
                    "cargo metadata workspace member {} is outside the scan root",
                    package.name
                );
            }
            let Some(document) = documents_by_path.get(&manifest_path) else {
                bail!(
                    "cargo metadata member {} has no readable manifest",
                    package.name
                );
            };
            if !active_documents
                .iter()
                .any(|active| active.rel_path == document.rel_path)
            {
                active_documents.push(document.clone());
            }
            let mut targets = Vec::new();
            let package_edition = package.edition.clone();
            for target in package.targets {
                let src_path = normalize_path(&target.src_path);
                if !src_path.starts_with(root) {
                    bail!(
                        "cargo metadata target for {} is outside the inventory",
                        package.name
                    );
                }
                let proc_macro = target.kind.iter().any(|kind| kind == "proc-macro")
                    || target.crate_types.iter().any(|kind| kind == "proc-macro");
                let kind = canonical_target_kind(&target.kind, &target.crate_types);
                let mut required_features = if kind == "lib" {
                    Vec::new()
                } else {
                    target.required_features
                };
                required_features.sort();
                required_features.dedup();
                let test = target
                    .test
                    .unwrap_or(matches!(kind.as_str(), "lib" | "bin" | "test"));
                targets.push(Target {
                    name: target.name,
                    kind,
                    src_path: slash_path(src_path.strip_prefix(root).expect("path checked")),
                    edition: target.edition.unwrap_or_else(|| package_edition.clone()),
                    required_features,
                    test,
                    proc_macro,
                });
            }
            targets.sort_by(|left, right| {
                (&left.kind, &left.name, &left.src_path).cmp(&(
                    &right.kind,
                    &right.name,
                    &right.src_path,
                ))
            });
            let build_script = targets
                .iter()
                .find(|target| target.kind == "custom-build")
                .map(|target| target.src_path.clone());
            let proc_macro = targets.iter().any(|target| target.proc_macro);
            let features = normalize_feature_map(package.features);
            let dependencies = package
                .dependencies
                .into_iter()
                .map(|dependency| -> Result<Dependency> {
                    let kind = match dependency.kind.as_deref() {
                        Some("dev") => DependencyKind::Development,
                        Some("build") => DependencyKind::Build,
                        _ => DependencyKind::Normal,
                    };
                    let alias = dependency.rename.unwrap_or_else(|| dependency.name.clone());
                    let locked_version =
                        lock.resolve(&package.name, &package.version, &dependency.name);
                    let path = dependency.path.map(|path| normalize_path(&path));
                    if path.as_ref().is_some_and(|path| !path.starts_with(root)) {
                        bail!(
                            "cargo metadata path dependency for {} is outside the inventory",
                            package.name
                        );
                    }
                    let mut dependency_features = dependency.features;
                    dependency_features.sort();
                    dependency_features.dedup();
                    Ok(Dependency {
                        alias: alias.clone(),
                        package: dependency.name,
                        version: Some(locked_version.map(str::to_owned).unwrap_or(dependency.req)),
                        path,
                        optional: dependency.optional,
                        features: dependency_features,
                        uses_default_features: dependency.uses_default_features,
                        kind,
                        condition: dependency_condition(
                            kind,
                            dependency.target.as_deref(),
                            dependency.optional,
                            &alias,
                            &features,
                        ),
                        target: dependency.target,
                        source: dependency.source,
                        locked: locked_version.is_some(),
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            packages.push(Package {
                name: package.name,
                version: package.version,
                feature_resolver: package_feature_resolver(
                    document,
                    &package.edition,
                    workspace_resolver,
                ),
                edition: package.edition,
                manifest_path: document.rel_path.clone(),
                dir: document.dir.clone(),
                rel_dir: document.rel_dir.clone(),
                features,
                dependencies,
                targets,
                build_script,
                proc_macro,
                cfg_profile_overrides: cfg_profile_overrides.clone(),
                workspace_member: true,
                from_metadata: true,
            });
        }
        // `cargo metadata --no-deps` omits path packages that are not workspace
        // members. Complete only the transitive, root-confined path closure
        // from manifests that passed the same admitted inventory preflight.
        let static_packages = parse_packages(documents);
        let static_by_dir: BTreeMap<_, _> = static_packages
            .into_iter()
            .map(|package| (normalize_path(&package.dir), package))
            .collect();
        loop {
            let included_dirs: BTreeSet<_> = packages
                .iter()
                .map(|package| normalize_path(&package.dir))
                .collect();
            let required_paths: BTreeSet<_> = packages
                .iter()
                .flat_map(|package| package.dependencies.iter())
                .filter_map(|dependency| dependency.path.as_ref())
                .map(|path| normalize_path(path))
                .filter(|path| !included_dirs.contains(path))
                .collect();
            if required_paths.is_empty() {
                break;
            }
            let mut added = false;
            for path in required_paths {
                let mut package = static_by_dir.get(&path).cloned().ok_or_else(|| {
                    anyhow::anyhow!(
                        "admitted path dependency has no readable confined package manifest"
                    )
                })?;
                if !path.starts_with(root) {
                    bail!("admitted path dependency is outside the scan root");
                }
                package.from_metadata = false;
                package.workspace_member = false;
                if let Some(workspace_resolver) = workspace_resolver {
                    package.feature_resolver = workspace_resolver;
                }
                if let Some(document) = documents
                    .iter()
                    .find(|document| document.rel_path == package.manifest_path)
                    && !active_documents
                        .iter()
                        .any(|active| active.rel_path == document.rel_path)
                {
                    active_documents.push(document.clone());
                }
                packages.push(package);
                added = true;
            }
            if !added {
                break;
            }
        }
        apply_lock_versions(&mut packages, lock);
        packages.sort_by(|left, right| left.rel_dir.cmp(&right.rel_dir));
        active_documents.sort_by(|left, right| left.rel_path.cmp(&right.rel_path));
        active_documents.dedup_by(|left, right| left.rel_path == right.rel_path);
        Ok((packages, active_documents))
    }
}

fn validate_dependency_source(source: Option<&str>, mirror_root: &Path) -> Result<()> {
    let Some(source) = source else {
        return Ok(());
    };
    if source.to_ascii_lowercase().contains("file:")
        || source.contains(mirror_root.to_string_lossy().as_ref())
    {
        bail!("cargo metadata dependency source is not confined");
    }
    Ok(())
}

pub(crate) fn run_cargo_metadata(
    root: &Path,
    manifest_path: &Path,
    documents: &[ManifestDocument],
) -> Result<(CargoMetadata, LockIndex)> {
    let workspace_directory = CargoInputMirror::workspace_directory(root, manifest_path, documents)
        .context("resolve confined Cargo workspace inventory")?;
    let lock = LockIndex::read(root, &workspace_directory);
    if lock.failure.is_some() {
        bail!("Cargo.lock failed safe metadata preflight");
    }
    // The mirror is materialized before tool resolution or process launch, so
    // rejected path-bearing input cannot reach `cargo metadata`.
    let mirror = CargoInputMirror::materialize(root, manifest_path, documents, lock.source())
        .context("preflight and materialize confined Cargo input")?;
    let cargo = resolve_safe_tool("cargo", root)?;
    let cargo_cwd = neutral_cargo_working_directory(mirror.neutral_root())?;
    let mut command = Command::new(cargo);
    command
        .arg("metadata")
        .arg("--format-version")
        .arg("1")
        .arg("--no-deps")
        .arg("--frozen")
        .arg("--offline")
        .arg("--manifest-path")
        .arg(mirror.manifest_path())
        // Cargo and rustup discover configuration by walking upward from cwd.
        // Start at a checked filesystem anchor so neither project nor
        // temporary-directory ancestors can contribute configuration.
        .current_dir(cargo_cwd);
    configure_cargo_safety_environment(&mut command);
    let safe_path = sanitized_path(root)?;
    command.env("PATH", safe_path);
    configure_path_environment(&mut command, root, mirror.neutral_root())?;
    for key in ["LANG", "LC_ALL"] {
        if let Some(value) = std::env::var_os(key) {
            command.env(key, value);
        }
    }
    #[cfg(windows)]
    if let Some(system_root) = std::env::var_os("SystemRoot")
        .as_deref()
        .and_then(|value| safe_external_directory(root, value))
    {
        command.env("SystemRoot", system_root);
    }
    let output = command.output().context("start cargo metadata")?;
    if !output.status.success() {
        bail!("cargo metadata exited unsuccessfully");
    }
    let metadata: CargoMetadata =
        serde_json::from_slice(&output.stdout).context("decode cargo metadata JSON DTO")?;
    Ok((metadata.remap_from_mirror(&mirror)?, lock))
}

fn neutral_cargo_working_directory(neutral: &Path) -> Result<PathBuf> {
    let anchor = neutral
        .ancestors()
        .last()
        .filter(|path| path.is_absolute() && path.is_dir())
        .context("neutral Cargo filesystem anchor is unavailable")?
        .to_path_buf();
    for candidate in [
        anchor.join(".cargo"),
        anchor.join("rust-toolchain"),
        anchor.join("rust-toolchain.toml"),
    ] {
        match fs::symlink_metadata(&candidate) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => bail!("neutral Cargo filesystem anchor could not be inspected"),
            Ok(_) => bail!("neutral Cargo filesystem anchor contains toolchain configuration"),
        }
    }
    Ok(anchor)
}

fn configure_cargo_safety_environment(command: &mut Command) {
    command
        .env_clear()
        .env("CARGO_NET_OFFLINE", "true")
        .env("CARGO_TERM_COLOR", "never")
        // The resolved `cargo` can be a rustup proxy. Cargo's offline flag does
        // not prevent rustup from downloading an absent active toolchain.
        .env("RUSTUP_AUTO_INSTALL", "0")
        .env("RUSTC", "rustc")
        .env("RUSTC_WRAPPER", "")
        .env("RUSTC_WORKSPACE_WRAPPER", "");
}

pub(crate) fn neutral_environment(root: &Path) -> Result<TempDir> {
    let mut candidates = vec![std::env::temp_dir()];
    #[cfg(unix)]
    candidates.extend([PathBuf::from("/tmp"), PathBuf::from("/var/tmp")]);
    #[cfg(windows)]
    if let Some(system_root) = std::env::var_os("SystemRoot") {
        candidates.push(PathBuf::from(system_root).join("Temp"));
    }

    let mut seen = BTreeSet::new();
    for candidate in candidates {
        let Ok(candidate) = candidate.canonicalize() else {
            continue;
        };
        if !candidate.is_dir() || candidate.starts_with(root) || !seen.insert(candidate.clone()) {
            continue;
        }
        if let Ok(directory) = TempDirBuilder::new()
            .prefix("depgraph-cargo-")
            .tempdir_in(candidate)
        {
            return Ok(directory);
        }
    }
    bail!("no writable neutral temporary directory exists outside the scan root")
}

fn configure_path_environment(command: &mut Command, root: &Path, neutral: &Path) -> Result<()> {
    let fallbacks = [
        ("HOME", "home"),
        ("USERPROFILE", "home"),
        ("TMPDIR", "tmp"),
        ("TEMP", "tmp"),
        ("TMP", "tmp"),
        ("CARGO_HOME", "cargo-home"),
    ];
    for (key, fallback_name) in fallbacks {
        let fallback = neutral.join(fallback_name);
        fs::create_dir_all(&fallback)
            .with_context(|| format!("create neutral {fallback_name} directory"))?;
        command.env(key, fallback);
    }
    // A resolved Cargo executable may be a rustup proxy. Keep only the
    // installed, root-external rustup toolchain store; Cargo configuration and
    // every writable directory remain worker-owned and fresh.
    let rustup_home = std::env::var_os("RUSTUP_HOME")
        .as_deref()
        .and_then(|value| safe_external_directory(root, value))
        .or_else(|| {
            ["HOME", "USERPROFILE"].into_iter().find_map(|key| {
                std::env::var_os(key)
                    .map(PathBuf::from)
                    .map(|home| home.join(".rustup"))
                    .filter(|path| path.is_dir())
                    .and_then(|path| safe_external_directory(root, path.as_os_str()))
            })
        })
        .unwrap_or_else(|| neutral.join("rustup-home"));
    fs::create_dir_all(&rustup_home).context("create neutral Rustup home")?;
    command.env("RUSTUP_HOME", rustup_home);
    let target = neutral.join("cargo-target");
    fs::create_dir_all(&target).context("create neutral Cargo target directory")?;
    command.env("CARGO_TARGET_DIR", target);
    Ok(())
}

pub(crate) fn safe_external_directory(root: &Path, value: &OsStr) -> Option<PathBuf> {
    let path = Path::new(value);
    if !path.is_absolute() {
        return None;
    }
    let canonical = path.canonicalize().ok()?;
    (canonical.is_dir() && !canonical.starts_with(root)).then_some(canonical)
}

pub(crate) fn sanitized_path(root: &Path) -> Result<std::ffi::OsString> {
    let raw = std::env::var_os("PATH").context("PATH is unavailable")?;
    sanitized_path_from(root, &raw)
}

fn sanitized_path_from(root: &Path, raw: &OsStr) -> Result<std::ffi::OsString> {
    let mut paths = Vec::new();
    for path in std::env::split_paths(raw) {
        if !path.is_absolute() {
            continue;
        }
        let Ok(path) = path.canonicalize() else {
            continue;
        };
        if path.is_dir() && !path.starts_with(root) && !paths.contains(&path) {
            paths.push(path);
        }
    }
    if paths.is_empty() {
        bail!("PATH has no safe absolute directories outside the scan root");
    }
    std::env::join_paths(paths).context("construct sanitized PATH")
}

pub(crate) fn resolve_safe_tool(name: &str, root: &Path) -> Result<PathBuf> {
    let path = sanitized_path(root)?;
    resolve_safe_tool_on_path(name, root, &path)
}

fn resolve_safe_tool_on_path(name: &str, root: &Path, path: &OsStr) -> Result<PathBuf> {
    for directory in std::env::split_paths(&path) {
        #[cfg(windows)]
        let candidate = directory.join(format!("{name}.exe"));
        #[cfg(not(windows))]
        let candidate = directory.join(name);
        let Ok(target) = candidate.canonicalize() else {
            continue;
        };
        if target.is_file() && !target.starts_with(root) {
            return Ok(candidate);
        }
    }
    bail!("{name} is unavailable on the sanitized PATH")
}

pub(crate) fn apply_lock_versions(packages: &mut [Package], lock: &LockIndex) {
    for package in packages {
        for dependency in &mut package.dependencies {
            if let Some(version) =
                lock.resolve(&package.name, &package.version, &dependency.package)
            {
                dependency.version = Some(version.into());
                dependency.locked = true;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CargoMetadata, LockIndex, MetadataDependency, canonical_target_kind,
        configure_cargo_safety_environment, configure_path_environment,
        neutral_cargo_working_directory, neutral_environment, safe_external_directory,
        validate_dependency_source,
    };

    #[test]
    fn metadata_canonicalizes_only_rust_linkable_library_crate_types() {
        let strings = |values: &[&str]| {
            values
                .iter()
                .map(|value| (*value).into())
                .collect::<Vec<_>>()
        };

        assert_eq!(canonical_target_kind(&strings(&["rlib"]), &[]), "lib");
        assert_eq!(
            canonical_target_kind(&strings(&["cdylib"]), &strings(&["cdylib", "rlib"])),
            "lib"
        );
        assert_eq!(
            canonical_target_kind(&strings(&["cdylib"]), &strings(&["cdylib"])),
            "cdylib"
        );
        assert_eq!(
            canonical_target_kind(&strings(&["staticlib"]), &strings(&["staticlib"])),
            "staticlib"
        );
    }
    #[cfg(unix)]
    use super::{resolve_safe_tool_on_path, sanitized_path_from};
    use crate::manifest::{ManifestDocument, parse_packages};
    use depgraph_protocol::Condition;
    use serde_json::{Value, json};
    use std::{
        collections::BTreeMap,
        ffi::OsStr,
        path::{Path, PathBuf},
        process::Command,
    };

    #[test]
    fn cargo_metadata_disables_rustup_auto_install() {
        let mut command = Command::new("cargo");
        configure_cargo_safety_environment(&mut command);

        let auto_install = command
            .get_envs()
            .find(|(key, _)| *key == OsStr::new("RUSTUP_AUTO_INSTALL"))
            .and_then(|(_, value)| value);
        assert_eq!(auto_install, Some(OsStr::new("0")));
    }

    #[test]
    fn metadata_dependency_defaults_to_cargo_default_features() {
        let dependency: MetadataDependency = serde_json::from_value(json!({
            "name": "serde",
            "source": null,
            "req": "1",
            "kind": null,
            "rename": null,
            "optional": false,
            "target": null,
            "path": null
        }))
        .expect("valid metadata dependency");

        assert!(dependency.features.is_empty());
        assert!(dependency.uses_default_features);
    }

    #[test]
    fn metadata_environment_rejects_relative_and_repository_directories() {
        let temp = tempfile::tempdir().expect("temporary parent");
        let root = temp.path().join("repository");
        let outside = temp.path().join("outside");
        std::fs::create_dir_all(&root).expect("repository directory");
        std::fs::create_dir_all(&outside).expect("outside directory");
        let root = root.canonicalize().expect("canonical repository");
        let outside = outside.canonicalize().expect("canonical outside");

        assert!(safe_external_directory(&root, Path::new("relative").as_os_str()).is_none());
        assert!(safe_external_directory(&root, root.as_os_str()).is_none());
        assert_eq!(
            safe_external_directory(&root, outside.as_os_str()),
            Some(outside)
        );
        let neutral = neutral_environment(&root).expect("neutral environment");
        assert!(!neutral.path().starts_with(&root));
    }

    #[test]
    fn cargo_configuration_and_writable_paths_are_always_worker_owned() {
        let temp = tempfile::tempdir().expect("temporary parent");
        let root = temp.path().join("repository");
        let neutral = temp.path().join("neutral");
        std::fs::create_dir_all(&root).expect("repository directory");
        std::fs::create_dir_all(&neutral).expect("neutral directory");
        let root = root.canonicalize().expect("canonical repository");
        let neutral = neutral.canonicalize().expect("canonical neutral");
        let mut command = Command::new("cargo");

        configure_path_environment(&mut command, &root, &neutral)
            .expect("neutral Cargo environment");

        let environment = command
            .get_envs()
            .filter_map(|(key, value)| Some((key.to_owned(), value?.to_owned())))
            .collect::<BTreeMap<_, _>>();
        for (key, directory) in [
            ("HOME", "home"),
            ("USERPROFILE", "home"),
            ("TMPDIR", "tmp"),
            ("TEMP", "tmp"),
            ("TMP", "tmp"),
            ("CARGO_HOME", "cargo-home"),
            ("CARGO_TARGET_DIR", "cargo-target"),
        ] {
            assert_eq!(
                environment.get(OsStr::new(key)),
                Some(&neutral.join(directory).into_os_string())
            );
        }
    }

    #[test]
    fn cargo_cwd_does_not_inherit_temporary_directory_configuration() {
        let temp = tempfile::tempdir().expect("temporary parent");
        let neutral = temp.path().join("nested/neutral");
        std::fs::create_dir_all(temp.path().join(".cargo")).expect("ancestor Cargo directory");
        std::fs::create_dir_all(&neutral).expect("neutral directory");
        std::fs::write(
            temp.path().join(".cargo/config.toml"),
            "[build]\nrustc-wrapper = '/must/not/run'\n",
        )
        .expect("ancestor Cargo config");

        let cwd = neutral_cargo_working_directory(&neutral).expect("checked Cargo cwd");

        assert!(cwd.is_absolute());
        assert!(!cwd.starts_with(temp.path()));
        assert_eq!(cwd.parent(), None);
    }

    #[test]
    fn lockfile_local_file_sources_fail_closed_before_cargo() {
        let temp = tempfile::tempdir().expect("temporary workspace");
        let root = temp.path().canonicalize().expect("canonical workspace");
        std::fs::write(
            root.join("Cargo.lock"),
            r#"version = 4

[[package]]
name = "local-source"
version = "1.0.0"
source = "git+file:///outside/repository#deadbeef"
"#,
        )
        .expect("test lockfile");

        let lock = LockIndex::read(&root, &root);

        let failure = lock.failure.expect("local file source must fail closed");
        assert_eq!(failure.code, "RUST_LOCKFILE_PATH_CONFINEMENT");
        assert_eq!(failure.path, "Cargo.lock");
        assert!(!failure.reason.contains("/outside"));
    }

    #[cfg(unix)]
    #[test]
    fn metadata_environment_rejects_a_symlink_into_the_repository() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().expect("temporary parent");
        let root = temp.path().join("repository");
        let link = temp.path().join("repository-link");
        std::fs::create_dir_all(&root).expect("repository directory");
        let root = root.canonicalize().expect("canonical repository");
        symlink(&root, &link).expect("repository symlink");

        assert!(safe_external_directory(&root, link.as_os_str()).is_none());
    }

    #[cfg(unix)]
    #[test]
    fn tool_resolution_excludes_repository_and_relative_path_entries() {
        let temp = tempfile::tempdir().expect("temporary parent");
        let root = temp.path().join("repository");
        let repository_bin = root.join("bin");
        let external_bin = temp.path().join("external-bin");
        std::fs::create_dir_all(&repository_bin).expect("repository bin");
        std::fs::create_dir_all(&external_bin).expect("external bin");
        std::fs::write(repository_bin.join("rustc"), b"project tool").expect("project tool");
        std::fs::write(external_bin.join("rustc"), b"external tool").expect("external tool");
        let root = root.canonicalize().expect("canonical repository");
        let external_bin = external_bin.canonicalize().expect("canonical external bin");
        let raw = std::env::join_paths([
            Path::new("relative-bin"),
            repository_bin.as_path(),
            external_bin.as_path(),
        ])
        .expect("test PATH");

        let sanitized = sanitized_path_from(&root, &raw).expect("sanitized PATH");
        let entries = std::env::split_paths(&sanitized).collect::<Vec<_>>();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0], external_bin);
        assert_eq!(
            resolve_safe_tool_on_path("rustc", &root, &sanitized)
                .expect("external rustc")
                .canonicalize()
                .expect("canonical rustc"),
            external_bin.join("rustc").canonicalize().unwrap()
        );
    }

    #[test]
    fn metadata_paths_are_remapped_before_the_dto_leaves_the_boundary() {
        let mirror = Path::new("/neutral/mirror");
        let original = Path::new("/inventory");
        let package_id = "path+file:///neutral/mirror/member#0.1.0";
        let metadata: CargoMetadata = serde_json::from_value(json!({
            "packages": [{
                "id": package_id,
                "name": "member",
                "version": "0.1.0",
                "edition": "2024",
                "manifest_path": mirror.join("member/Cargo.toml"),
                "features": {},
                "dependencies": [{
                    "name": "local",
                    "source": null,
                    "req": "*",
                    "kind": null,
                    "rename": null,
                    "optional": false,
                    "target": null,
                    "path": mirror.join("local")
                }],
                "targets": [{
                    "name": "member",
                    "kind": ["lib"],
                    "crate_types": ["lib"],
                    "src_path": mirror.join("member/src/lib.rs")
                }]
            }],
            "workspace_members": [package_id],
            "workspace_root": mirror
        }))
        .expect("valid metadata DTO");
        let mappings = BTreeMap::from([
            (mirror.to_path_buf(), original.to_path_buf()),
            (
                mirror.join("member/Cargo.toml"),
                original.join("member/Cargo.toml"),
            ),
            (mirror.join("local"), original.join("local")),
            (
                mirror.join("member/src/lib.rs"),
                original.join("member/src/lib.rs"),
            ),
        ]);

        let remapped = metadata
            .remap_paths_with(|path| {
                mappings
                    .get(path)
                    .cloned()
                    .ok_or_else(|| anyhow::anyhow!("unknown mirror path"))
            })
            .expect("every returned path is admitted");

        assert_eq!(remapped.workspace_root, original);
        assert_eq!(
            remapped.packages[0].manifest_path,
            original.join("member/Cargo.toml")
        );
        assert_eq!(
            remapped.packages[0].dependencies[0].path,
            Some(original.join("local"))
        );
        assert_eq!(
            remapped.packages[0].targets[0].src_path,
            original.join("member/src/lib.rs")
        );
        let serialized = serde_json::to_string(&json!({
            "workspace_root": &remapped.workspace_root,
            "manifest": &remapped.packages[0].manifest_path,
            "dependency": &remapped.packages[0].dependencies[0].path,
            "target": &remapped.packages[0].targets[0].src_path,
        }))
        .unwrap();
        assert!(!serialized.contains("/neutral/mirror"));
    }

    #[test]
    fn metadata_completes_the_admitted_nonmember_path_dependency_closure() {
        let temp = tempfile::tempdir().expect("workspace");
        let root = temp.path().canonicalize().expect("canonical workspace");
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::create_dir_all(root.join("shared/src")).unwrap();
        std::fs::write(root.join("src/lib.rs"), "pub fn app() {}\n").unwrap();
        std::fs::write(root.join("shared/src/lib.rs"), "pub fn shared() {}\n").unwrap();
        std::fs::write(root.join("shared/src/main.rs"), "fn main() {}\n").unwrap();
        let root_manifest = r#"
            [package]
            name = "member"
            version = "0.1.0"
            edition = "2018"
            resolver = "2"

            [workspace]
            exclude = ["shared"]

            [dependencies]
            shared = { path = "shared", default-features = false }
        "#;
        let shared_manifest = r#"
            [package]
            name = "shared"
            version = "0.2.0"
            edition = "2024"
            autolib = false
            autobins = false

            [[bin]]
            name = "shared-tool"
            path = "src/main.rs"

            [features]
            default = []
        "#;
        std::fs::write(root.join("Cargo.toml"), root_manifest).unwrap();
        std::fs::write(root.join("shared/Cargo.toml"), shared_manifest).unwrap();
        let documents = vec![
            ManifestDocument {
                abs_path: root.join("Cargo.toml"),
                rel_path: "Cargo.toml".into(),
                dir: root.clone(),
                rel_dir: ".".into(),
                value: toml::from_str(root_manifest).unwrap(),
            },
            ManifestDocument {
                abs_path: root.join("shared/Cargo.toml"),
                rel_path: "shared/Cargo.toml".into(),
                dir: root.join("shared"),
                rel_dir: "shared".into(),
                value: toml::from_str(shared_manifest).unwrap(),
            },
        ];
        let metadata: CargoMetadata = serde_json::from_value(json!({
            "packages": [{
                "id": "member-id",
                "name": "member",
                "version": "0.1.0",
                "edition": "2018",
                "manifest_path": root.join("Cargo.toml"),
                "features": {},
                "dependencies": [{
                    "name": "shared",
                    "source": null,
                    "req": "*",
                    "kind": null,
                    "rename": "shared_alias",
                    "optional": false,
                    "features": [],
                    "uses_default_features": false,
                    "target": null,
                    "path": root.join("shared")
                }],
                "targets": [{
                    "name": "member",
                    "kind": ["lib"],
                    "crate_types": ["lib"],
                    "src_path": root.join("src/lib.rs")
                }]
            }],
            "workspace_members": ["member-id"],
            "workspace_root": root
        }))
        .unwrap();

        let (packages, active_documents) = metadata
            .into_packages(&root, &LockIndex::default(), &documents)
            .expect("confined path closure");

        assert_eq!(
            packages
                .iter()
                .map(|package| package.name.as_str())
                .collect::<Vec<_>>(),
            ["member", "shared"]
        );
        assert!(packages[0].from_metadata);
        assert!(!packages[1].from_metadata);
        assert_eq!(packages[0].feature_resolver, 2);
        assert_eq!(packages[1].feature_resolver, 2);
        assert_eq!(packages[1].targets.len(), 1);
        assert_eq!(packages[1].targets[0].kind, "bin");
        assert_eq!(packages[1].targets[0].name, "shared-tool");
        assert!(
            active_documents
                .iter()
                .any(|document| document.rel_path == "shared/Cargo.toml")
        );
    }

    #[test]
    fn metadata_conversion_matches_standalone_manifest_resolver_selection() {
        let temp = tempfile::tempdir().expect("workspace");
        let root = temp.path().canonicalize().expect("canonical workspace");
        let manifest_path = root.join("Cargo.toml");
        let source_path = root.join("src/lib.rs");
        let package_id = "path+file:///workspace#app@1.0.0";
        let cases = [
            ("2015", None, 1),
            ("2018", None, 1),
            ("2021", None, 2),
            ("2024", None, 3),
            ("2024", Some(1), 1),
            ("2015", Some(2), 2),
            ("2015", Some(3), 3),
        ];

        for (edition, explicit, expected) in cases {
            let resolver = explicit
                .map(|resolver| format!("resolver = '{resolver}'\n"))
                .unwrap_or_default();
            let manifest = format!(
                "[package]\nname = 'app'\nversion = '1.0.0'\nedition = '{edition}'\n{resolver}"
            );
            let documents = [ManifestDocument {
                abs_path: manifest_path.clone(),
                rel_path: "Cargo.toml".into(),
                dir: root.clone(),
                rel_dir: ".".into(),
                value: toml::from_str(&manifest).expect("valid manifest"),
            }];
            let metadata: CargoMetadata = serde_json::from_value(json!({
                "packages": [{
                    "id": package_id,
                    "name": "app",
                    "version": "1.0.0",
                    "edition": edition,
                    "manifest_path": manifest_path,
                    "features": {},
                    "dependencies": [],
                    "targets": [{
                        "name": "app",
                        "kind": ["bin"],
                        "crate_types": ["bin"],
                        "src_path": source_path,
                        "edition": "2018",
                        "required-features": ["z", "a", "z"],
                        "test": false
                    }]
                }],
                "workspace_members": [package_id],
                "workspace_root": root
            }))
            .expect("valid metadata DTO");
            let fallback_resolver = parse_packages(&documents)[0].feature_resolver;

            let (packages, _) = metadata
                .into_packages(&root, &LockIndex::default(), &documents)
                .expect("metadata conversion succeeds");

            assert_eq!(fallback_resolver, expected);
            assert_eq!(packages[0].feature_resolver, fallback_resolver);
            assert_eq!(packages[0].targets[0].edition, "2018");
            assert_eq!(packages[0].targets[0].required_features, ["a", "z"]);
            assert!(!packages[0].targets[0].test);
        }
    }

    #[test]
    fn metadata_ignores_an_unrelated_nested_workspace_resolver() {
        let temp = tempfile::tempdir().expect("workspace");
        let root = temp.path().canonicalize().expect("canonical workspace");
        let manifest_path = root.join("Cargo.toml");
        let source_path = root.join("src/lib.rs");
        let package_id = "path+file:///workspace#app@1.0.0";
        let documents = [
            ManifestDocument {
                abs_path: manifest_path.clone(),
                rel_path: "Cargo.toml".into(),
                dir: root.clone(),
                rel_dir: ".".into(),
                value: toml::from_str(
                    "[package]\nname = 'app'\nversion = '1.0.0'\nedition = '2018'\nresolver = '2'\n\n[dependencies]\nshared = { path = 'shared' }\n",
                )
                .expect("valid root manifest"),
            },
            ManifestDocument {
                abs_path: root.join("shared/Cargo.toml"),
                rel_path: "shared/Cargo.toml".into(),
                dir: root.join("shared"),
                rel_dir: "shared".into(),
                value: toml::from_str(
                    "[package]\nname = 'shared'\nversion = '1.0.0'\nedition = '2024'\nresolver = '3'\n",
                )
                .expect("valid path dependency manifest"),
            },
            ManifestDocument {
                abs_path: root.join("vendor/Cargo.toml"),
                rel_path: "vendor/Cargo.toml".into(),
                dir: root.join("vendor"),
                rel_dir: "vendor".into(),
                value: toml::from_str("[workspace]\nmembers = []\nresolver = '3'\n")
                    .expect("valid nested workspace manifest"),
            },
        ];
        let metadata: CargoMetadata = serde_json::from_value(json!({
            "packages": [{
                "id": package_id,
                "name": "app",
                "version": "1.0.0",
                "edition": "2018",
                "manifest_path": manifest_path,
                "features": {},
                "dependencies": [{
                    "name": "shared",
                    "source": null,
                    "req": "*",
                    "kind": null,
                    "rename": null,
                    "optional": false,
                    "features": [],
                    "uses_default_features": true,
                    "target": null,
                    "path": root.join("shared")
                }],
                "targets": [{
                    "name": "app",
                    "kind": ["lib"],
                    "crate_types": ["lib"],
                    "src_path": source_path
                }]
            }],
            "workspace_members": [package_id],
            "workspace_root": root
        }))
        .expect("valid metadata DTO");

        let (packages, _) = metadata
            .into_packages(&root, &LockIndex::default(), &documents)
            .expect("metadata conversion succeeds");

        assert_eq!(
            packages
                .iter()
                .map(|package| (package.name.as_str(), package.feature_resolver))
                .collect::<Vec<_>>(),
            [("app", 2), ("shared", 2)]
        );
    }

    #[test]
    fn metadata_uses_its_reported_workspace_for_resolver_and_cfg_profile() {
        let temp = tempfile::tempdir().expect("workspace");
        let root = temp.path().canonicalize().expect("canonical workspace");
        let owner = root.join("owner");
        let manifest_path = root.join("Cargo.toml");
        let source_path = root.join("src/lib.rs");
        let package_id = "path+file:///workspace#app@1.0.0";
        let documents = [
            ManifestDocument {
                abs_path: manifest_path.clone(),
                rel_path: "Cargo.toml".into(),
                dir: root.clone(),
                rel_dir: ".".into(),
                value: toml::from_str(
                    "[package]\nname='app'\nversion='1.0.0'\nedition='2018'\nresolver='1'\nworkspace='owner'\n",
                )
                .unwrap(),
            },
            ManifestDocument {
                abs_path: owner.join("Cargo.toml"),
                rel_path: "owner/Cargo.toml".into(),
                dir: owner.clone(),
                rel_dir: "owner".into(),
                value: toml::from_str(
                    "[workspace]\nmembers=['..']\nresolver='3'\n\n[profile.dev]\npanic='abort'\n",
                )
                .unwrap(),
            },
        ];
        let metadata: CargoMetadata = serde_json::from_value(json!({
            "packages": [{
                "id": package_id,
                "name": "app",
                "version": "1.0.0",
                "edition": "2018",
                "manifest_path": manifest_path,
                "features": {},
                "dependencies": [],
                "targets": [{
                    "name": "app",
                    "kind": ["lib"],
                    "crate_types": ["lib"],
                    "src_path": source_path
                }]
            }],
            "workspace_members": [package_id],
            "workspace_root": owner
        }))
        .unwrap();

        let (packages, _) = metadata
            .into_packages(&root, &LockIndex::default(), &documents)
            .expect("metadata conversion succeeds");

        assert_eq!(packages[0].feature_resolver, 3);
        assert_eq!(packages[0].cfg_profile_overrides, ["dev".to_owned()].into());
    }

    #[test]
    fn metadata_rejects_a_path_that_is_not_in_the_mirror_inventory() {
        let package_id = "path+file:///neutral/mirror/member#0.1.0";
        let metadata: CargoMetadata = serde_json::from_value(json!({
            "packages": [{
                "id": package_id,
                "name": "member",
                "version": "0.1.0",
                "edition": "2024",
                "manifest_path": "/neutral/mirror/member/Cargo.toml",
                "features": {},
                "dependencies": [],
                "targets": [{
                    "name": "member",
                    "kind": ["lib"],
                    "crate_types": ["lib"],
                    "src_path": "/outside/secret.rs"
                }]
            }],
            "workspace_members": [package_id],
            "workspace_root": "/neutral/mirror"
        }))
        .expect("valid metadata DTO");
        let mappings = BTreeMap::from([
            (
                PathBuf::from("/neutral/mirror"),
                PathBuf::from("/inventory"),
            ),
            (
                PathBuf::from("/neutral/mirror/member/Cargo.toml"),
                PathBuf::from("/inventory/member/Cargo.toml"),
            ),
        ]);

        assert!(
            metadata
                .remap_paths_with(|path| {
                    mappings
                        .get(path)
                        .cloned()
                        .ok_or_else(|| anyhow::anyhow!("unknown mirror path"))
                })
                .is_err()
        );
    }

    #[test]
    fn metadata_dependency_sources_cannot_name_local_or_mirror_files() {
        let mirror = Path::new("/neutral/mirror");
        assert!(validate_dependency_source(None, mirror).is_ok());
        assert!(
            validate_dependency_source(
                Some("registry+https://github.com/rust-lang/crates.io-index"),
                mirror,
            )
            .is_ok()
        );
        assert!(
            validate_dependency_source(Some("path+file:///neutral/mirror/local"), mirror).is_err()
        );
        assert!(
            validate_dependency_source(Some("registry+/neutral/mirror/index"), mirror).is_err()
        );
    }

    #[test]
    fn metadata_features_drive_optional_dependency_conditions() {
        let temp = tempfile::tempdir().expect("temporary workspace");
        let root = temp.path().canonicalize().expect("canonical workspace");
        let manifest_path = root.join("Cargo.toml");
        let source_path = root.join("src/lib.rs");
        let package_id = "path+file:///workspace#app@1.0.0";
        let metadata: CargoMetadata = serde_json::from_value(json!({
            "packages": [{
                "id": package_id,
                "name": "app",
                "version": "1.0.0",
                "edition": "2024",
                "manifest_path": manifest_path,
                "features": {
                    "default": ["json"],
                    "json": ["dep:serde", "dep:serde"]
                },
                "dependencies": [{
                    "name": "serde",
                    "source": "registry+https://github.com/rust-lang/crates.io-index",
                    "req": "^1",
                    "kind": null,
                    "rename": null,
                    "optional": true,
                    "features": ["derive", "alloc", "derive"],
                    "uses_default_features": false,
                    "target": null,
                    "path": null
                }],
                "targets": [{
                    "name": "app",
                    "kind": ["lib"],
                    "crate_types": ["lib"],
                    "src_path": source_path
                }]
            }],
            "workspace_members": [package_id],
            "workspace_root": root
        }))
        .expect("valid metadata DTO");
        let documents = [ManifestDocument {
            abs_path: manifest_path,
            rel_path: "Cargo.toml".into(),
            dir: root.clone(),
            rel_dir: ".".into(),
            value: toml::from_str(
                r#"
                    [package]
                    name = "app"
                    version = "1.0.0"
                "#,
            )
            .expect("valid manifest"),
        }];

        let (packages, _) = metadata
            .into_packages(&root, &LockIndex::default(), &documents)
            .expect("metadata conversion succeeds");
        assert_eq!(packages[0].features["json"], ["dep:serde"]);
        assert!(packages[0].dependencies[0].optional);
        assert_eq!(packages[0].dependencies[0].features, ["alloc", "derive"]);
        assert!(!packages[0].dependencies[0].uses_default_features);
        assert_eq!(
            packages[0].dependencies[0].condition,
            Condition::Eq {
                key: "rust.feature".into(),
                value: Value::String("json".into()),
            }
        );
    }
}
