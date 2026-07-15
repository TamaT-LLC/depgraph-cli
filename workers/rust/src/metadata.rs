use crate::manifest::{
    Dependency, DependencyKind, ManifestDocument, Package, Target, dependency_condition,
    normalize_feature_map, normalize_path, slash_path,
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
        let Ok(source) = std::fs::read_to_string(&canonical_path) else {
            return Self::failed(
                lexical_path,
                "RUST_LOCKFILE_READ",
                "Cargo.lock could not be read in safe mode",
            );
        };
        let Ok(value) = toml::from_str::<toml::Value>(&source) else {
            return Self::failed(
                lexical_path,
                "RUST_LOCKFILE_PARSE",
                "Cargo.lock is not valid TOML",
            );
        };
        let mut index = Self {
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
            if package
                .get("source")
                .and_then(toml::Value::as_str)
                .is_some()
            {
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
    target: Option<String>,
    path: Option<PathBuf>,
}

#[derive(Debug, Deserialize)]
struct MetadataTarget {
    name: String,
    kind: Vec<String>,
    crate_types: Vec<String>,
    src_path: PathBuf,
}

impl CargoMetadata {
    pub fn workspace_root(&self) -> &Path {
        &self.workspace_root
    }

    pub fn into_packages(
        self,
        root: &Path,
        lock: &LockIndex,
        documents: &[ManifestDocument],
    ) -> Result<(Vec<Package>, Vec<ManifestDocument>)> {
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
            for target in package.targets {
                let src_path = normalize_path(&target.src_path);
                if !src_path.starts_with(root) {
                    continue;
                }
                let kind = target
                    .kind
                    .iter()
                    .find(|kind| kind.as_str() == "custom-build")
                    .or_else(|| target.kind.first())
                    .cloned()
                    .unwrap_or_else(|| "unknown".into());
                let proc_macro = target.kind.iter().any(|kind| kind == "proc-macro")
                    || target.crate_types.iter().any(|kind| kind == "proc-macro");
                targets.push(Target {
                    name: target.name,
                    kind,
                    src_path: slash_path(src_path.strip_prefix(root).expect("path checked")),
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
                .map(|dependency| {
                    let kind = match dependency.kind.as_deref() {
                        Some("dev") => DependencyKind::Development,
                        Some("build") => DependencyKind::Build,
                        _ => DependencyKind::Normal,
                    };
                    let alias = dependency.rename.unwrap_or_else(|| dependency.name.clone());
                    let locked_version =
                        lock.resolve(&package.name, &package.version, &dependency.name);
                    Dependency {
                        alias: alias.clone(),
                        package: dependency.name,
                        version: Some(locked_version.map(str::to_owned).unwrap_or(dependency.req)),
                        path: dependency.path.map(|path| normalize_path(&path)),
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
                    }
                })
                .collect();
            packages.push(Package {
                name: package.name,
                version: package.version,
                edition: package.edition,
                manifest_path: document.rel_path.clone(),
                dir: document.dir.clone(),
                rel_dir: document.rel_dir.clone(),
                features,
                dependencies,
                targets,
                build_script,
                proc_macro,
                from_metadata: true,
            });
        }
        packages.sort_by(|left, right| left.rel_dir.cmp(&right.rel_dir));
        active_documents.sort_by(|left, right| left.rel_path.cmp(&right.rel_path));
        active_documents.dedup_by(|left, right| left.rel_path == right.rel_path);
        Ok((packages, active_documents))
    }
}

pub(crate) fn run_cargo_metadata(root: &Path, manifest_path: &Path) -> Result<CargoMetadata> {
    let cargo = resolve_safe_tool("cargo", root)?;
    let neutral = neutral_environment(root)?;
    let mut command = Command::new(cargo);
    command
        .arg("metadata")
        .arg("--format-version")
        .arg("1")
        .arg("--no-deps")
        .arg("--frozen")
        .arg("--offline")
        .arg("--manifest-path")
        .arg(manifest_path)
        // Cargo and rustup discover .cargo/config.toml and rust-toolchain.toml
        // by walking upward from cwd. The manifest path is absolute, so use a
        // neutral cwd and never expose project configuration to the toolchain.
        .current_dir(neutral.path())
        .env_clear()
        .env("CARGO_NET_OFFLINE", "true")
        .env("CARGO_TERM_COLOR", "never")
        .env("RUSTC", "rustc")
        .env("RUSTC_WRAPPER", "")
        .env("RUSTC_WORKSPACE_WRAPPER", "");
    let safe_path = sanitized_path(root)?;
    command.env("PATH", safe_path);
    configure_path_environment(&mut command, root, neutral.path())?;
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
    serde_json::from_slice(&output.stdout).context("decode cargo metadata JSON DTO")
}

fn neutral_environment(root: &Path) -> Result<TempDir> {
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
        ("RUSTUP_HOME", "rustup-home"),
    ];
    for (key, fallback_name) in fallbacks {
        let fallback = neutral.join(fallback_name);
        fs::create_dir_all(&fallback)
            .with_context(|| format!("create neutral {fallback_name} directory"))?;
        let value = std::env::var_os(key)
            .as_deref()
            .and_then(|value| safe_external_directory(root, value))
            .unwrap_or(fallback);
        command.env(key, value);
    }
    let target = neutral.join("cargo-target");
    fs::create_dir_all(&target).context("create neutral Cargo target directory")?;
    command.env("CARGO_TARGET_DIR", target);
    Ok(())
}

fn safe_external_directory(root: &Path, value: &OsStr) -> Option<PathBuf> {
    let path = Path::new(value);
    if !path.is_absolute() {
        return None;
    }
    let canonical = path.canonicalize().ok()?;
    (canonical.is_dir() && !canonical.starts_with(root)).then_some(canonical)
}

fn sanitized_path(root: &Path) -> Result<std::ffi::OsString> {
    let raw = std::env::var_os("PATH").context("PATH is unavailable")?;
    let mut paths = Vec::new();
    for path in std::env::split_paths(&raw) {
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

fn resolve_safe_tool(name: &str, root: &Path) -> Result<PathBuf> {
    let path = sanitized_path(root)?;
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
    use super::{CargoMetadata, LockIndex, neutral_environment, safe_external_directory};
    use crate::manifest::ManifestDocument;
    use depgraph_protocol::Condition;
    use serde_json::{Value, json};
    use std::path::Path;

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
        assert_eq!(
            packages[0].dependencies[0].condition,
            Condition::Eq {
                key: "rust.feature".into(),
                value: Value::String("json".into()),
            }
        );
    }
}
