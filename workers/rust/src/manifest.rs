use depgraph_protocol::Condition;
use serde_json::Value as JsonValue;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Component, Path, PathBuf},
};
use toml::Value;

#[derive(Clone, Debug)]
pub(crate) struct ManifestDocument {
    pub abs_path: PathBuf,
    pub rel_path: String,
    pub dir: PathBuf,
    pub rel_dir: String,
    pub value: Value,
}

#[derive(Clone, Debug)]
pub(crate) struct Package {
    pub name: String,
    pub version: String,
    pub edition: String,
    pub manifest_path: String,
    pub dir: PathBuf,
    pub rel_dir: String,
    pub features: BTreeMap<String, Vec<String>>,
    pub dependencies: Vec<Dependency>,
    pub targets: Vec<Target>,
    pub build_script: Option<String>,
    pub proc_macro: bool,
    pub from_metadata: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DependencyKind {
    Normal,
    Development,
    Build,
}

impl DependencyKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::Development => "dev",
            Self::Build => "build",
        }
    }

    pub fn edge_kind(self) -> &'static str {
        if self == Self::Build {
            "build_depends_on"
        } else {
            "depends_on"
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Dependency {
    pub alias: String,
    pub package: String,
    pub version: Option<String>,
    pub path: Option<PathBuf>,
    pub kind: DependencyKind,
    pub condition: Condition,
    pub target: Option<String>,
    pub source: Option<String>,
    pub locked: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct Target {
    pub name: String,
    pub kind: String,
    pub src_path: String,
    pub proc_macro: bool,
}

#[derive(Clone, Debug)]
struct WorkspaceDependency {
    value: Value,
    dir: PathBuf,
}

pub(crate) fn parse_packages(documents: &[ManifestDocument]) -> Vec<Package> {
    let workspace_dependencies = workspace_dependencies(documents);
    let workspace_package = workspace_package_values(documents);
    documents
        .iter()
        .filter_map(|document| parse_package(document, &workspace_dependencies, &workspace_package))
        .collect()
}

/// Selects the manifests that Cargo's static workspace fallback would own.
/// An explicit `members` list is authoritative, while `exclude` is applied to
/// both direct paths and wildcard members. The workspace manifest itself is
/// retained as evidence even when it is virtual.
pub(crate) fn select_static_documents(documents: &[ManifestDocument]) -> Vec<ManifestDocument> {
    let Some(workspace_document) = documents
        .iter()
        .find(|document| document.rel_path == "Cargo.toml")
        .or_else(|| {
            documents
                .iter()
                .find(|document| document.value.get("workspace").is_some())
        })
    else {
        return documents.to_vec();
    };
    let Some(workspace) = workspace_document
        .value
        .get("workspace")
        .and_then(Value::as_table)
    else {
        return documents.to_vec();
    };
    let members: Vec<_> = workspace
        .get("members")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(normalize_pattern)
        .collect();
    let excludes: Vec<_> = workspace
        .get("exclude")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(normalize_pattern)
        .collect();
    let base = Path::new(&workspace_document.rel_dir);
    let mut selected_paths = BTreeSet::new();
    for document in documents {
        if document.rel_path == workspace_document.rel_path {
            selected_paths.insert(document.rel_path.clone());
            continue;
        }
        let candidate = Path::new(&document.rel_dir)
            .strip_prefix(base)
            .map(slash_path)
            .unwrap_or_else(|_| document.rel_dir.clone());
        let included = members.is_empty()
            || members
                .iter()
                .any(|pattern| wildcard_match(pattern, &candidate));
        let excluded = excludes
            .iter()
            .any(|pattern| wildcard_match(pattern, &candidate));
        if included && !excluded {
            selected_paths.insert(document.rel_path.clone());
        }
    }
    // Cargo automatically promotes in-workspace path dependencies to members,
    // even if an explicit member glob did not name them. Follow that closure
    // statically while continuing to honor `exclude`.
    loop {
        let mut added = false;
        let selected_documents: Vec<_> = documents
            .iter()
            .filter(|document| selected_paths.contains(&document.rel_path))
            .collect();
        for document in selected_documents {
            for (dependency_base, dependency_path) in
                manifest_dependency_paths(document, workspace_document)
            {
                let dependency_dir = normalize_path(&dependency_base.join(dependency_path));
                let Some(dependency_document) = documents
                    .iter()
                    .find(|candidate| normalize_path(&candidate.dir) == dependency_dir)
                else {
                    continue;
                };
                let candidate = Path::new(&dependency_document.rel_dir)
                    .strip_prefix(base)
                    .map(slash_path)
                    .unwrap_or_else(|_| dependency_document.rel_dir.clone());
                let excluded = excludes
                    .iter()
                    .any(|pattern| wildcard_match(pattern, &candidate));
                if !excluded && selected_paths.insert(dependency_document.rel_path.clone()) {
                    added = true;
                }
            }
        }
        if !added {
            break;
        }
    }
    let mut selected: Vec<_> = documents
        .iter()
        .filter(|document| selected_paths.contains(&document.rel_path))
        .cloned()
        .collect();
    selected.sort_by(|left, right| left.rel_path.cmp(&right.rel_path));
    selected
}

fn manifest_dependency_paths<'a>(
    document: &'a ManifestDocument,
    workspace_document: &'a ManifestDocument,
) -> Vec<(&'a Path, &'a str)> {
    let mut paths = Vec::new();
    collect_dependency_paths(
        &document.value,
        &document.dir,
        workspace_document,
        &mut paths,
    );
    if let Some(targets) = document.value.get("target").and_then(Value::as_table) {
        for target in targets.values() {
            collect_dependency_paths(target, &document.dir, workspace_document, &mut paths);
        }
    }
    paths
}

fn collect_dependency_paths<'a>(
    parent: &'a Value,
    base: &'a Path,
    workspace_document: &'a ManifestDocument,
    output: &mut Vec<(&'a Path, &'a str)>,
) {
    for key in ["dependencies", "dev-dependencies", "build-dependencies"] {
        let Some(dependencies) = parent.get(key).and_then(Value::as_table) else {
            continue;
        };
        for (alias, dependency) in dependencies {
            let Some(table) = dependency.as_table() else {
                continue;
            };
            if let Some(path) = table.get("path").and_then(Value::as_str) {
                output.push((base, path));
                continue;
            }
            if table.get("workspace").and_then(Value::as_bool) == Some(true)
                && let Some(path) = workspace_document
                    .value
                    .get("workspace")
                    .and_then(Value::as_table)
                    .and_then(|workspace| workspace.get("dependencies"))
                    .and_then(Value::as_table)
                    .and_then(|dependencies| dependencies.get(alias))
                    .and_then(Value::as_table)
                    .and_then(|dependency| dependency.get("path"))
                    .and_then(Value::as_str)
            {
                output.push((&workspace_document.dir, path));
            }
        }
    }
}

fn normalize_pattern(pattern: &str) -> String {
    pattern
        .trim_start_matches("./")
        .trim_end_matches('/')
        .replace('\\', "/")
}

fn wildcard_match(pattern: &str, candidate: &str) -> bool {
    fn matches(
        pattern: &[u8],
        candidate: &[u8],
        cache: &mut BTreeMap<(usize, usize), bool>,
    ) -> bool {
        let key = (pattern.len(), candidate.len());
        if let Some(result) = cache.get(&key) {
            return *result;
        }
        let result = match pattern {
            [] => candidate.is_empty(),
            [b'*', b'*', rest @ ..] => {
                matches(rest, candidate, cache)
                    || (!candidate.is_empty() && matches(pattern, &candidate[1..], cache))
            }
            [b'*', rest @ ..] => {
                matches(rest, candidate, cache)
                    || (!candidate.is_empty()
                        && candidate[0] != b'/'
                        && matches(pattern, &candidate[1..], cache))
            }
            [b'?', rest @ ..] => {
                !candidate.is_empty()
                    && candidate[0] != b'/'
                    && matches(rest, &candidate[1..], cache)
            }
            [literal, rest @ ..] => {
                candidate.first() == Some(literal) && matches(rest, &candidate[1..], cache)
            }
        };
        cache.insert(key, result);
        result
    }
    matches(
        pattern.as_bytes(),
        candidate.as_bytes(),
        &mut BTreeMap::new(),
    )
}

fn parse_package(
    document: &ManifestDocument,
    workspace_dependencies: &BTreeMap<String, Vec<WorkspaceDependency>>,
    workspace_package: &BTreeMap<String, Value>,
) -> Option<Package> {
    let package_table = document.value.get("package")?.as_table()?;
    let name = package_table.get("name")?.as_str()?.to_owned();
    let version = inherited_string(package_table.get("version"), "version", workspace_package)
        .unwrap_or_else(|| "0.0.0".into());
    let edition = inherited_string(package_table.get("edition"), "edition", workspace_package)
        .unwrap_or_else(|| "2015".into());
    let features = manifest_features(document);

    let mut dependencies = Vec::new();
    parse_dependency_table(
        document,
        &document.value,
        "dependencies",
        DependencyKind::Normal,
        None,
        workspace_dependencies,
        &features,
        &mut dependencies,
    );
    parse_dependency_table(
        document,
        &document.value,
        "dev-dependencies",
        DependencyKind::Development,
        None,
        workspace_dependencies,
        &features,
        &mut dependencies,
    );
    parse_dependency_table(
        document,
        &document.value,
        "build-dependencies",
        DependencyKind::Build,
        None,
        workspace_dependencies,
        &features,
        &mut dependencies,
    );
    if let Some(targets) = document.value.get("target").and_then(Value::as_table) {
        for (target, table) in targets {
            parse_dependency_table(
                document,
                table,
                "dependencies",
                DependencyKind::Normal,
                Some(target),
                workspace_dependencies,
                &features,
                &mut dependencies,
            );
            parse_dependency_table(
                document,
                table,
                "dev-dependencies",
                DependencyKind::Development,
                Some(target),
                workspace_dependencies,
                &features,
                &mut dependencies,
            );
            parse_dependency_table(
                document,
                table,
                "build-dependencies",
                DependencyKind::Build,
                Some(target),
                workspace_dependencies,
                &features,
                &mut dependencies,
            );
        }
    }
    dependencies.sort_by(|left, right| {
        (
            left.kind.as_str(),
            left.target.as_deref(),
            left.alias.as_str(),
        )
            .cmp(&(
                right.kind.as_str(),
                right.target.as_deref(),
                right.alias.as_str(),
            ))
    });

    let build_script = match package_table.get("build") {
        Some(Value::Boolean(false)) => None,
        Some(Value::String(path)) => Some(relative_to_root(document, path)),
        _ if document.dir.join("build.rs").is_file() => {
            Some(relative_to_root(document, "build.rs"))
        }
        _ => None,
    };
    let mut targets = parse_targets(document, &name);
    if let Some(path) = &build_script {
        targets.push(Target {
            name: format!("build-script-{name}"),
            kind: "custom-build".into(),
            src_path: path.clone(),
            proc_macro: false,
        });
    }
    targets.sort_by(|left, right| {
        (&left.kind, &left.name, &left.src_path).cmp(&(&right.kind, &right.name, &right.src_path))
    });
    targets.dedup_by(|left, right| {
        left.kind == right.kind && left.name == right.name && left.src_path == right.src_path
    });
    let proc_macro = targets.iter().any(|target| target.proc_macro);

    Some(Package {
        name,
        version,
        edition,
        manifest_path: document.rel_path.clone(),
        dir: document.dir.clone(),
        rel_dir: document.rel_dir.clone(),
        features,
        dependencies,
        targets,
        build_script,
        proc_macro,
        from_metadata: false,
    })
}

fn inherited_string(
    value: Option<&Value>,
    key: &str,
    workspace_package: &BTreeMap<String, Value>,
) -> Option<String> {
    match value {
        Some(Value::String(value)) => Some(value.clone()),
        Some(Value::Table(table))
            if table.get("workspace").and_then(Value::as_bool) == Some(true) =>
        {
            workspace_package
                .get(key)
                .and_then(Value::as_str)
                .map(str::to_owned)
        }
        _ => None,
    }
}

fn parse_targets(document: &ManifestDocument, package_name: &str) -> Vec<Target> {
    let mut targets = Vec::new();
    let lib_table = document.value.get("lib").and_then(Value::as_table);
    if lib_table.is_some() || document.dir.join("src/lib.rs").is_file() {
        let name = lib_table
            .and_then(|table| table.get("name"))
            .and_then(Value::as_str)
            .unwrap_or(package_name)
            .replace('-', "_");
        let path = lib_table
            .and_then(|table| table.get("path"))
            .and_then(Value::as_str)
            .unwrap_or("src/lib.rs");
        let proc_macro = lib_table
            .and_then(|table| table.get("proc-macro"))
            .and_then(Value::as_bool)
            .unwrap_or(false)
            || lib_table
                .and_then(|table| table.get("crate-type"))
                .and_then(Value::as_array)
                .is_some_and(|types| types.iter().any(|kind| kind.as_str() == Some("proc-macro")));
        targets.push(Target {
            name,
            kind: "lib".into(),
            src_path: relative_to_root(document, path),
            proc_macro,
        });
    }
    if document.dir.join("src/main.rs").is_file() {
        targets.push(Target {
            name: package_name.into(),
            kind: "bin".into(),
            src_path: relative_to_root(document, "src/main.rs"),
            proc_macro: false,
        });
    }
    parse_target_array(document, package_name, "bin", "src/bin", &mut targets);
    parse_target_array(document, package_name, "example", "examples", &mut targets);
    parse_target_array(document, package_name, "test", "tests", &mut targets);
    parse_target_array(document, package_name, "bench", "benches", &mut targets);

    discover_implicit_targets(document, "bin", "src/bin", &mut targets);
    discover_implicit_targets(document, "example", "examples", &mut targets);
    discover_implicit_targets(document, "test", "tests", &mut targets);
    discover_implicit_targets(document, "bench", "benches", &mut targets);
    targets
}

fn parse_target_array(
    document: &ManifestDocument,
    package_name: &str,
    key: &str,
    default_dir: &str,
    targets: &mut Vec<Target>,
) {
    let Some(entries) = document.value.get(key).and_then(Value::as_array) else {
        return;
    };
    for entry in entries.iter().filter_map(Value::as_table) {
        let name = entry
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or(package_name);
        let default_path = format!("{default_dir}/{name}.rs");
        let path = entry
            .get("path")
            .and_then(Value::as_str)
            .unwrap_or(&default_path);
        targets.push(Target {
            name: name.into(),
            kind: key.into(),
            src_path: relative_to_root(document, path),
            proc_macro: false,
        });
    }
}

fn discover_implicit_targets(
    document: &ManifestDocument,
    kind: &str,
    relative_dir: &str,
    targets: &mut Vec<Target>,
) {
    let dir = document.dir.join(relative_dir);
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let (Some(extension), Some(stem)) = (path.extension(), path.file_stem()) else {
            continue;
        };
        if extension != "rs" {
            continue;
        }
        targets.push(Target {
            name: stem.to_string_lossy().into_owned(),
            kind: kind.into(),
            src_path: relative_to_root(
                document,
                &format!("{relative_dir}/{}", entry.file_name().to_string_lossy()),
            ),
            proc_macro: false,
        });
    }
}

#[allow(clippy::too_many_arguments)]
fn parse_dependency_table(
    document: &ManifestDocument,
    parent: &impl TableLike,
    key: &str,
    kind: DependencyKind,
    target: Option<&str>,
    workspace_dependencies: &BTreeMap<String, Vec<WorkspaceDependency>>,
    features: &BTreeMap<String, Vec<String>>,
    dependencies: &mut Vec<Dependency>,
) {
    let Some(table) = parent.get_value(key).and_then(Value::as_table) else {
        return;
    };
    for (alias, original) in table {
        let (value, base_dir) = if original
            .as_table()
            .and_then(|table| table.get("workspace"))
            .and_then(Value::as_bool)
            == Some(true)
        {
            workspace_dependencies
                .get(alias)
                .and_then(|candidates| {
                    candidates
                        .iter()
                        .filter(|candidate| document.dir.starts_with(&candidate.dir))
                        .max_by_key(|candidate| candidate.dir.components().count())
                })
                .map(|dependency| (&dependency.value, dependency.dir.as_path()))
                .unwrap_or((original, document.dir.as_path()))
        } else {
            (original, document.dir.as_path())
        };
        let (package, version, path, optional) = dependency_fields(alias, value, base_dir);
        let condition = dependency_condition(kind, target, optional, alias, features);
        dependencies.push(Dependency {
            alias: alias.clone(),
            package,
            version,
            path,
            kind,
            condition,
            target: target.map(str::to_owned),
            source: None,
            locked: false,
        });
    }
}

trait TableLike {
    fn get_value(&self, key: &str) -> Option<&Value>;
}

impl TableLike for Value {
    fn get_value(&self, key: &str) -> Option<&Value> {
        self.get(key)
    }
}

impl TableLike for toml::map::Map<String, Value> {
    fn get_value(&self, key: &str) -> Option<&Value> {
        self.get(key)
    }
}

fn dependency_fields(
    alias: &str,
    value: &Value,
    base_dir: &Path,
) -> (String, Option<String>, Option<PathBuf>, bool) {
    match value {
        Value::String(version) => (alias.into(), Some(version.clone()), None, false),
        Value::Table(table) => {
            let package = table
                .get("package")
                .and_then(Value::as_str)
                .unwrap_or(alias)
                .to_owned();
            let version = table
                .get("version")
                .and_then(Value::as_str)
                .map(str::to_owned);
            let path = table
                .get("path")
                .and_then(Value::as_str)
                .map(|path| normalize_path(&base_dir.join(path)));
            let optional = table
                .get("optional")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            (package, version, path, optional)
        }
        _ => (alias.into(), None, None, false),
    }
}

pub(crate) fn dependency_condition(
    kind: DependencyKind,
    target: Option<&str>,
    optional: bool,
    alias: &str,
    features: &BTreeMap<String, Vec<String>>,
) -> Condition {
    let mut conditions = Vec::new();
    if kind != DependencyKind::Normal {
        conditions.push(Condition::Eq {
            key: "cargo.dependency_kind".into(),
            value: JsonValue::String(kind.as_str().into()),
        });
    }
    if let Some(target) = target {
        conditions.push(parse_target_condition(target));
    }
    if optional {
        let activators = optional_dependency_activators(features, alias);
        conditions.push(
            Condition::Any {
                conditions: activators
                    .into_iter()
                    .map(|feature| Condition::Eq {
                        key: "rust.feature".into(),
                        value: JsonValue::String(feature),
                    })
                    .collect(),
            }
            .canonicalize(),
        );
    }
    Condition::All { conditions }.canonicalize()
}

fn manifest_features(document: &ManifestDocument) -> BTreeMap<String, Vec<String>> {
    let Some(table) = document.value.get("features").and_then(Value::as_table) else {
        return BTreeMap::new();
    };
    normalize_feature_map(table.iter().map(|(name, value)| {
        let members = value
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect();
        (name.clone(), members)
    }))
}

pub(crate) fn normalize_feature_map(
    features: impl IntoIterator<Item = (String, Vec<String>)>,
) -> BTreeMap<String, Vec<String>> {
    features
        .into_iter()
        .map(|(name, mut members)| {
            members.sort();
            members.dedup();
            (name, members)
        })
        .collect()
}

/// Expands the workspace's local named Cargo features for a deterministic
/// static profile. Dependency feature references are not local cfg features,
/// but explicitly requested references are retained verbatim so the profile
/// still reproduces the user's selection.
pub(crate) fn expanded_features(packages: &[Package], requested: &[String]) -> BTreeSet<String> {
    let mut expanded = BTreeSet::from(["default".to_owned()]);
    let mut pending = Vec::new();
    for feature in std::iter::once("default").chain(requested.iter().map(String::as_str)) {
        let feature = feature.trim();
        if feature.is_empty() {
            continue;
        }
        if (expanded.insert(feature.to_owned()) || feature == "default")
            && is_local_feature_reference(feature)
        {
            pending.push(feature.to_owned());
        }
    }
    let mut visited = BTreeSet::new();
    while let Some(feature) = pending.pop() {
        if !visited.insert(feature.clone()) {
            continue;
        }
        for member in packages
            .iter()
            .filter_map(|package| package.features.get(&feature))
            .flatten()
        {
            if is_local_feature_reference(member) && expanded.insert(member.clone()) {
                pending.push(member.clone());
            }
        }
    }
    expanded
}

fn is_local_feature_reference(feature: &str) -> bool {
    !feature.starts_with("dep:") && !feature.contains('/')
}

fn optional_dependency_activators(
    features: &BTreeMap<String, Vec<String>>,
    alias: &str,
) -> BTreeSet<String> {
    let explicit_dependency = format!("dep:{alias}");
    let dependency_feature_prefix = format!("{alias}/");
    let weak_dependency_feature_prefix = format!("{alias}?/");
    let mut activators = BTreeSet::new();
    let mut has_explicit_dependency_reference = false;
    for (feature, members) in features {
        for member in members {
            if member == &explicit_dependency {
                has_explicit_dependency_reference = true;
                activators.insert(feature.clone());
            } else if member.starts_with(&dependency_feature_prefix) {
                // A strong dependency feature reference activates an optional
                // dependency. Keep both its named parent and the raw reference
                // so a direct user request can reproduce the activation.
                activators.insert(feature.clone());
                activators.insert(member.clone());
            } else if member.starts_with(&weak_dependency_feature_prefix) {
                // `dep?/feature` only forwards a feature after the dependency
                // has already been enabled and is therefore not an activator.
            }
        }
    }
    if !has_explicit_dependency_reference {
        // Cargo supplies an implicit same-name feature unless `dep:alias` is
        // used by an explicit feature declaration.
        activators.insert(alias.to_owned());
    }
    activators
}

pub(crate) fn parse_target_condition(target: &str) -> Condition {
    if let Some(inner) = target
        .strip_prefix("cfg(")
        .and_then(|value| value.strip_suffix(')'))
        && let Ok(meta) = syn::parse_str::<syn::Meta>(inner)
    {
        return crate::source::condition_from_meta(&meta).canonicalize();
    }
    Condition::Eq {
        key: "rust.target".into(),
        value: JsonValue::String(target.into()),
    }
}

fn workspace_dependencies(
    documents: &[ManifestDocument],
) -> BTreeMap<String, Vec<WorkspaceDependency>> {
    let mut dependencies: BTreeMap<String, Vec<WorkspaceDependency>> = BTreeMap::new();
    for document in documents {
        let Some(table) = document
            .value
            .get("workspace")
            .and_then(Value::as_table)
            .and_then(|workspace| workspace.get("dependencies"))
            .and_then(Value::as_table)
        else {
            continue;
        };
        for (alias, value) in table {
            dependencies
                .entry(alias.clone())
                .or_default()
                .push(WorkspaceDependency {
                    value: value.clone(),
                    dir: document.dir.clone(),
                });
        }
    }
    dependencies
}

fn workspace_package_values(documents: &[ManifestDocument]) -> BTreeMap<String, Value> {
    documents
        .iter()
        .filter_map(|document| {
            document
                .value
                .get("workspace")
                .and_then(Value::as_table)
                .and_then(|workspace| workspace.get("package"))
                .and_then(Value::as_table)
        })
        .flat_map(|table| {
            table
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
        })
        .collect()
}

fn relative_to_root(document: &ManifestDocument, path: &str) -> String {
    let raw = Path::new(path);
    let bytes = path.as_bytes();
    let portable_absolute = raw.is_absolute()
        || path.starts_with("//")
        || path.starts_with(r"\\")
        || (bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':');
    if portable_absolute {
        return "__depgraph_skipped__/cargo-path".into();
    }
    let relative = if document.rel_dir == "." {
        PathBuf::from(raw)
    } else {
        Path::new(&document.rel_dir).join(raw)
    };
    let relative = normalize_path(&relative);
    if relative.components().any(|component| {
        matches!(
            component,
            Component::ParentDir | Component::Prefix(_) | Component::RootDir
        )
    }) {
        "__depgraph_skipped__/cargo-path".into()
    } else {
        slash_path(&relative)
    }
}

pub(crate) fn normalize_path(path: &Path) -> PathBuf {
    let mut prefix = None;
    let mut absolute = false;
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            Component::Prefix(value) => prefix = Some(value.as_os_str().to_owned()),
            Component::RootDir => absolute = true,
            Component::CurDir => {}
            Component::ParentDir => {
                if parts.last().is_some_and(|part| part != "..") {
                    parts.pop();
                } else if !absolute {
                    parts.push("..".into());
                }
            }
            Component::Normal(value) => parts.push(value.to_owned()),
        }
    }
    let mut result = PathBuf::new();
    if let Some(prefix) = prefix {
        result.push(prefix);
    }
    if absolute {
        result.push(Path::new(std::path::MAIN_SEPARATOR_STR));
    }
    for part in parts {
        result.push(part);
    }
    result
}

pub(crate) fn slash_path(path: &Path) -> String {
    let path = path.to_string_lossy().replace('\\', "/");
    if path.is_empty() { ".".into() } else { path }
}

pub(crate) fn workspace_identity(packages: &[Package], documents: &[ManifestDocument]) -> String {
    let mut identities: BTreeSet<_> = packages
        .iter()
        .map(|package| format!("{}@{}#{}", package.name, package.version, package.rel_dir))
        .collect();
    identities.extend(
        documents
            .iter()
            .filter(|document| document.value.get("workspace").is_some())
            .map(|document| format!("workspace#{}", document.rel_path)),
    );
    format!(
        "cargo-workspace:{}",
        identities.into_iter().collect::<Vec<_>>().join("|")
    )
}

#[cfg(test)]
mod tests {
    use super::{
        ManifestDocument, expanded_features, parse_packages, relative_to_root, wildcard_match,
    };
    use depgraph_protocol::Condition;
    use serde_json::Value as JsonValue;
    use std::{collections::BTreeSet, path::PathBuf};

    fn document(source: &str) -> ManifestDocument {
        ManifestDocument {
            abs_path: PathBuf::from("/workspace/Cargo.toml"),
            rel_path: "Cargo.toml".into(),
            dir: PathBuf::from("/workspace"),
            rel_dir: ".".into(),
            value: toml::from_str(source).expect("valid test manifest"),
        }
    }

    fn feature(name: &str) -> Condition {
        Condition::Eq {
            key: "rust.feature".into(),
            value: JsonValue::String(name.into()),
        }
    }

    #[test]
    fn cargo_member_wildcards_do_not_cross_directories_without_double_star() {
        assert!(wildcard_match("crates/*", "crates/member"));
        assert!(!wildcard_match("crates/*", "crates/group/member"));
        assert!(wildcard_match("crates/**", "crates/group/member"));
    }

    #[test]
    fn static_target_paths_reject_portable_absolute_and_drive_relative_forms() {
        let document = document("[package]\nname='app'\nversion='1.0.0'\n");
        for path in [
            "/outside/lib.rs",
            "//server/share/lib.rs",
            r"\\server\share\lib.rs",
            "C:/outside/lib.rs",
            r"C:\outside\lib.rs",
            "C:drive-relative.rs",
            "../outside/lib.rs",
        ] {
            assert_eq!(
                relative_to_root(&document, path),
                "__depgraph_skipped__/cargo-path",
                "unsafe path was retained: {path}"
            );
        }
    }

    #[test]
    fn expands_named_features_without_treating_dependency_features_as_local() {
        let packages = parse_packages(&[document(
            r#"
                [package]
                name = "app"
                version = "1.0.0"

                [features]
                default = ["full"]
                full = ["json", "image"]
                json = ["dep:serde"]
                image = ["png/fast"]
            "#,
        )]);

        assert_eq!(
            expanded_features(
                &packages,
                &[
                    " extra ".into(),
                    "png/direct".into(),
                    "weak?/trace".into(),
                    "".into(),
                ],
            ),
            BTreeSet::from([
                "default".into(),
                "extra".into(),
                "full".into(),
                "image".into(),
                "json".into(),
                "png/direct".into(),
                "weak?/trace".into(),
            ])
        );
    }

    #[test]
    fn optional_dependencies_use_named_and_strong_feature_activators() {
        let packages = parse_packages(&[document(
            r#"
                [package]
                name = "app"
                version = "1.0.0"

                [dependencies]
                serde = { version = "1", optional = true }
                png = { version = "1", optional = true }
                weak = { version = "1", optional = true }

                [features]
                json = ["dep:serde"]
                alternate-json = ["dep:serde"]
                image = ["png/fast"]
                observe = ["weak?/trace"]
            "#,
        )]);
        let package = &packages[0];
        let dependency = |alias: &str| {
            package
                .dependencies
                .iter()
                .find(|dependency| dependency.alias == alias)
                .expect("dependency exists")
        };

        assert_eq!(
            dependency("serde").condition,
            Condition::Any {
                conditions: vec![feature("alternate-json"), feature("json")],
            }
            .canonicalize()
        );
        assert_eq!(
            dependency("png").condition,
            Condition::Any {
                conditions: vec![feature("image"), feature("png"), feature("png/fast")],
            }
            .canonicalize()
        );
        assert_eq!(dependency("weak").condition, feature("weak"));
    }
}
