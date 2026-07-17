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
    pub feature_resolver: u8,
    pub manifest_path: String,
    pub dir: PathBuf,
    pub rel_dir: String,
    pub features: BTreeMap<String, Vec<String>>,
    pub dependencies: Vec<Dependency>,
    pub targets: Vec<Target>,
    pub build_script: Option<String>,
    pub proc_macro: bool,
    pub cfg_profile_overrides: BTreeSet<String>,
    pub workspace_member: bool,
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
    pub optional: bool,
    pub features: Vec<String>,
    pub uses_default_features: bool,
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
    pub edition: String,
    pub required_features: Vec<String>,
    pub test: bool,
    pub proc_macro: bool,
}

#[derive(Clone, Debug)]
struct WorkspaceDependency {
    value: Value,
    dir: PathBuf,
}

pub(crate) fn parse_packages(documents: &[ManifestDocument]) -> Vec<Package> {
    let workspace_dependencies = workspace_dependencies(documents);
    let workspace_resolver = workspace_feature_resolver(documents);
    let cfg_profile_overrides = workspace_cfg_profile_overrides(documents);
    documents
        .iter()
        .filter_map(|document| {
            let workspace_document = workspace_document_for_package(document, documents);
            let workspace_package = workspace_package_values(workspace_document);
            parse_package(
                document,
                &workspace_dependencies,
                workspace_document.map(|workspace| workspace.dir.as_path()),
                &workspace_package,
                workspace_resolver,
                &cfg_profile_overrides,
            )
        })
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
    workspace_dir: Option<&Path>,
    workspace_package: &BTreeMap<String, Value>,
    workspace_resolver: Option<u8>,
    cfg_profile_overrides: &BTreeSet<String>,
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
        workspace_dir,
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
        workspace_dir,
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
        workspace_dir,
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
                workspace_dir,
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
                workspace_dir,
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
                workspace_dir,
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
    let mut targets = parse_targets(document, &name, &edition);
    for target in &mut targets {
        if target.edition.is_empty() {
            target.edition = edition.clone();
        }
    }
    if let Some(path) = &build_script {
        targets.push(Target {
            name: format!("build-script-{name}"),
            kind: "custom-build".into(),
            src_path: path.clone(),
            edition: edition.clone(),
            required_features: Vec::new(),
            test: false,
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
        feature_resolver: package_feature_resolver(document, &edition, workspace_resolver),
        edition,
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
        from_metadata: false,
    })
}

pub(crate) fn workspace_feature_resolver(documents: &[ManifestDocument]) -> Option<u8> {
    let entry = match documents
        .iter()
        .find(|document| document.rel_path == "Cargo.toml")
    {
        Some(root)
            if root.value.get("workspace").is_some() || root.value.get("package").is_some() =>
        {
            Some(root)
        }
        Some(_) => None,
        None => documents
            .iter()
            .find(|document| document.value.get("workspace").is_some()),
    }?;
    let workspace = workspace_document_for_package(entry, documents).unwrap_or(entry);
    workspace_document_resolver(workspace)
}

pub(crate) fn workspace_feature_resolver_at(
    documents: &[ManifestDocument],
    workspace_root: &Path,
) -> Option<u8> {
    documents
        .iter()
        .find(|document| normalize_path(&document.dir) == normalize_path(workspace_root))
        .and_then(workspace_document_resolver)
}

fn workspace_document_resolver(workspace: &ManifestDocument) -> Option<u8> {
    if let Some(resolver) = workspace
        .value
        .get("workspace")
        .and_then(Value::as_table)
        .and_then(|workspace| workspace.get("resolver"))
        .and_then(parse_feature_resolver)
    {
        return Some(resolver);
    }
    let package = workspace.value.get("package").and_then(Value::as_table);
    if let Some(resolver) = package
        .and_then(|package| package.get("resolver"))
        .and_then(parse_feature_resolver)
    {
        return Some(resolver);
    }
    let edition = package
        .and_then(|package| package.get("edition"))
        .and_then(|edition| match edition {
            Value::String(edition) => Some(edition.as_str()),
            Value::Table(inherited)
                if inherited.get("workspace").and_then(Value::as_bool) == Some(true) =>
            {
                workspace
                    .value
                    .get("workspace")
                    .and_then(Value::as_table)
                    .and_then(|workspace| workspace.get("package"))
                    .and_then(Value::as_table)
                    .and_then(|package| package.get("edition"))
                    .and_then(Value::as_str)
            }
            _ => None,
        });
    Some(edition.map_or(1, edition_feature_resolver))
}

pub(crate) fn package_feature_resolver(
    document: &ManifestDocument,
    edition: &str,
    workspace_resolver: Option<u8>,
) -> u8 {
    workspace_resolver
        .or_else(|| {
            document
                .value
                .get("package")
                .and_then(Value::as_table)
                .and_then(|package| package.get("resolver"))
                .and_then(parse_feature_resolver)
        })
        .unwrap_or_else(|| edition_feature_resolver(edition))
}

fn parse_feature_resolver(value: &Value) -> Option<u8> {
    value
        .as_str()
        .and_then(|resolver| resolver.parse::<u8>().ok())
        .filter(|resolver| matches!(resolver, 1..=3))
}

pub(crate) fn edition_feature_resolver(edition: &str) -> u8 {
    match edition {
        "2024" => 3,
        "2021" => 2,
        _ => 1,
    }
}

pub(crate) fn workspace_cfg_profile_overrides(documents: &[ManifestDocument]) -> BTreeSet<String> {
    let entry = match documents
        .iter()
        .find(|document| document.rel_path == "Cargo.toml")
    {
        Some(root)
            if root.value.get("workspace").is_some() || root.value.get("package").is_some() =>
        {
            Some(root)
        }
        Some(_) => None,
        None => documents
            .iter()
            .find(|document| document.value.get("workspace").is_some()),
    };
    let workspace =
        entry.and_then(|entry| workspace_document_for_package(entry, documents).or(Some(entry)));
    workspace_cfg_profile_overrides_for_document(workspace)
}

pub(crate) fn workspace_cfg_profile_overrides_at(
    documents: &[ManifestDocument],
    workspace_root: &Path,
) -> BTreeSet<String> {
    let workspace = documents
        .iter()
        .find(|document| normalize_path(&document.dir) == normalize_path(workspace_root));
    workspace_cfg_profile_overrides_for_document(workspace)
}

fn workspace_cfg_profile_overrides_for_document(
    workspace: Option<&ManifestDocument>,
) -> BTreeSet<String> {
    let Some(profile) = workspace
        .and_then(|document| document.value.get("profile"))
        .and_then(Value::as_table)
    else {
        return BTreeSet::new();
    };
    ["dev", "test"]
        .into_iter()
        .filter(|mode| profile.get(*mode).is_some_and(has_cfg_profile_override))
        .map(str::to_owned)
        .collect()
}

fn has_cfg_profile_override(value: &Value) -> bool {
    value.as_table().is_some_and(|table| {
        table.iter().any(|(key, value)| {
            matches!(
                key.as_str(),
                "debug-assertions"
                    | "debug_assertions"
                    | "panic"
                    | "overflow-checks"
                    | "overflow_checks"
            ) || has_cfg_profile_override(value)
        })
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

fn parse_targets(document: &ManifestDocument, package_name: &str, edition: &str) -> Vec<Target> {
    let mut targets = Vec::new();
    let package = document.value.get("package").and_then(Value::as_table);
    let has_manual_target = ["lib", "bin", "example", "test", "bench"]
        .iter()
        .any(|key| document.value.get(*key).is_some());
    let auto_enabled = |flag: &str| {
        package
            .and_then(|package| package.get(flag))
            .and_then(Value::as_bool)
            .unwrap_or(!(edition == "2015" && has_manual_target))
    };
    let lib_table = document.value.get("lib").and_then(Value::as_table);
    if lib_table.is_some() || (auto_enabled("autolib") && document.dir.join("src/lib.rs").is_file())
    {
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
        let crate_types: Vec<_> = lib_table
            .and_then(|table| table.get("crate-type"))
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect();
        let kind = if proc_macro
            || crate_types.is_empty()
            || crate_types
                .iter()
                .any(|kind| matches!(*kind, "lib" | "rlib" | "dylib"))
        {
            "lib".to_owned()
        } else {
            crate_types[0].to_owned()
        };
        targets.push(Target {
            name,
            kind,
            src_path: relative_to_root(document, path),
            edition: lib_table
                .and_then(|table| table.get("edition"))
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            // Cargo does not apply `required-features` to library targets.
            required_features: Vec::new(),
            test: lib_table
                .and_then(|table| table.get("test"))
                .and_then(Value::as_bool)
                .unwrap_or(true),
            proc_macro,
        });
    }
    if auto_enabled("autobins") && document.dir.join("src/main.rs").is_file() {
        targets.push(Target {
            name: package_name.into(),
            kind: "bin".into(),
            src_path: relative_to_root(document, "src/main.rs"),
            edition: String::new(),
            required_features: Vec::new(),
            test: true,
            proc_macro: false,
        });
    }
    parse_target_array(document, package_name, "bin", "src/bin", &mut targets);
    parse_target_array(document, package_name, "example", "examples", &mut targets);
    parse_target_array(document, package_name, "test", "tests", &mut targets);
    parse_target_array(document, package_name, "bench", "benches", &mut targets);

    if auto_enabled("autobins") {
        discover_implicit_targets(document, "bin", "src/bin", &mut targets);
    }
    if auto_enabled("autoexamples") {
        discover_implicit_targets(document, "example", "examples", &mut targets);
    }
    if auto_enabled("autotests") {
        discover_implicit_targets(document, "test", "tests", &mut targets);
    }
    if auto_enabled("autobenches") {
        discover_implicit_targets(document, "bench", "benches", &mut targets);
    }
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
            edition: entry
                .get("edition")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            required_features: target_required_features(Some(entry)),
            test: entry
                .get("test")
                .and_then(Value::as_bool)
                .unwrap_or(matches!(key, "bin" | "test")),
            proc_macro: false,
        });
    }
}

fn target_required_features(table: Option<&toml::map::Map<String, Value>>) -> Vec<String> {
    let mut features = table
        .and_then(|table| {
            table
                .get("required-features")
                .or_else(|| table.get("required_features"))
        })
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect::<Vec<_>>();
    features.sort();
    features.dedup();
    features
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
            edition: String::new(),
            required_features: Vec::new(),
            test: matches!(kind, "bin" | "test"),
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
    workspace_dir: Option<&Path>,
    features: &BTreeMap<String, Vec<String>>,
    dependencies: &mut Vec<Dependency>,
) {
    let Some(table) = parent.get_value(key).and_then(Value::as_table) else {
        return;
    };
    for (alias, original) in table {
        let inherited = if original
            .as_table()
            .and_then(|table| table.get("workspace"))
            .and_then(Value::as_bool)
            == Some(true)
        {
            workspace_dir
                .and_then(|workspace_dir| {
                    workspace_dependencies.get(alias).and_then(|candidates| {
                        candidates
                            .iter()
                            .find(|candidate| candidate.dir == workspace_dir)
                    })
                })
                .map(|dependency| (&dependency.value, dependency.dir.as_path()))
        } else {
            None
        };
        let (value, base_dir) = inherited.unwrap_or((original, document.dir.as_path()));
        let (package, version, path, mut optional) = dependency_fields(alias, value, base_dir);
        let (mut dependency_features, mut uses_default_features) =
            dependency_feature_options(value);
        if inherited.is_some() {
            // Cargo permits a workspace dependency's features to be extended
            // at the member declaration. `optional` is not inherited, so an
            // explicit member value is authoritative.
            let (member_features, member_uses_default_features) =
                dependency_feature_options(original);
            dependency_features.extend(member_features);
            dependency_features.sort();
            dependency_features.dedup();
            uses_default_features &= member_uses_default_features;
            optional = original
                .as_table()
                .and_then(|table| table.get("optional"))
                .and_then(Value::as_bool)
                .unwrap_or(false);
        }
        let condition = dependency_condition(kind, target, optional, alias, features);
        dependencies.push(Dependency {
            alias: alias.clone(),
            package,
            version,
            path,
            optional,
            features: dependency_features,
            uses_default_features,
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

fn dependency_feature_options(value: &Value) -> (Vec<String>, bool) {
    let Some(table) = value.as_table() else {
        return (Vec::new(), true);
    };
    let mut features = table
        .get("features")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect::<Vec<_>>();
    features.sort();
    features.dedup();
    let uses_default_features = table
        .get("default-features")
        .or_else(|| table.get("default_features"))
        .and_then(Value::as_bool)
        .unwrap_or(true);
    (features, uses_default_features)
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

/// Expands one package's local named Cargo features. Dependency feature
/// references are not local cfg features, but explicitly requested references
/// are retained verbatim so the profile still reproduces the user's selection.
pub(crate) fn expanded_named_features(
    package: &Package,
    requested: &[String],
    uses_default_features: bool,
) -> BTreeSet<String> {
    let mut expanded = BTreeSet::new();
    let mut pending = Vec::new();
    for feature in uses_default_features
        .then_some("default")
        .into_iter()
        .chain(requested.iter().map(String::as_str))
    {
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
        for member in package.features.get(&feature).into_iter().flatten() {
            if is_local_feature_reference(member) && expanded.insert(member.clone()) {
                pending.push(member.clone());
            }
        }
    }
    expanded
}

/// Unions package-local feature expansions for the workspace-level profile
/// display. Keeping expansion package-scoped prevents identically named
/// features in different crates from affecting one another's cfg options.
pub(crate) fn expanded_features(packages: &[Package], requested: &[String]) -> BTreeSet<String> {
    let mut expanded = BTreeSet::new();
    for package in packages {
        expanded.extend(expanded_named_features(package, requested, true));
    }
    if packages.is_empty() {
        expanded.insert("default".to_owned());
        expanded.extend(
            requested
                .iter()
                .map(|feature| feature.trim())
                .filter(|feature| !feature.is_empty())
                .map(str::to_owned),
        );
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

fn workspace_document_for_package<'a>(
    package_document: &ManifestDocument,
    documents: &'a [ManifestDocument],
) -> Option<&'a ManifestDocument> {
    if let Some(raw) = package_document
        .value
        .get("package")
        .and_then(Value::as_table)
        .and_then(|package| package.get("workspace"))
    {
        let raw = raw.as_str()?;
        let target = if Path::new(raw).is_absolute() {
            normalize_path(Path::new(raw))
        } else {
            normalize_path(&package_document.dir.join(raw))
        };
        return documents.iter().find(|workspace_document| {
            normalize_path(&workspace_document.dir) == target
                && workspace_document.value.get("workspace").is_some()
        });
    }
    if package_document.value.get("workspace").is_some() {
        return documents
            .iter()
            .find(|document| document.rel_path == package_document.rel_path);
    }
    documents
        .iter()
        .filter(|workspace_document| {
            workspace_document.value.get("workspace").is_some()
                && package_document.dir.starts_with(&workspace_document.dir)
        })
        .max_by_key(|workspace_document| workspace_document.dir.components().count())
}

fn workspace_package_values(
    workspace_document: Option<&ManifestDocument>,
) -> BTreeMap<String, Value> {
    workspace_document
        .and_then(|workspace_document| {
            workspace_document
                .value
                .get("workspace")
                .and_then(Value::as_table)
                .and_then(|workspace| workspace.get("package"))
                .and_then(Value::as_table)
        })
        .map(|package| {
            package
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect()
        })
        .unwrap_or_default()
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
        ManifestDocument, expanded_features, expanded_named_features, parse_packages,
        relative_to_root, wildcard_match, workspace_feature_resolver,
    };
    use depgraph_protocol::Condition;
    use serde_json::Value as JsonValue;
    use std::{collections::BTreeSet, path::PathBuf};

    fn document(source: &str) -> ManifestDocument {
        document_at(".", source)
    }

    fn document_at(rel_dir: &str, source: &str) -> ManifestDocument {
        let dir = if rel_dir == "." {
            PathBuf::from("/workspace")
        } else {
            PathBuf::from("/workspace").join(rel_dir)
        };
        ManifestDocument {
            abs_path: dir.join("Cargo.toml"),
            rel_path: if rel_dir == "." {
                "Cargo.toml".into()
            } else {
                format!("{rel_dir}/Cargo.toml")
            },
            dir,
            rel_dir: rel_dir.into(),
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
    fn standalone_editions_select_their_default_feature_resolver() {
        for (edition, resolver) in [("2015", 1), ("2018", 1), ("2021", 2), ("2024", 3)] {
            let source =
                format!("[package]\nname = 'app'\nversion = '1.0.0'\nedition = '{edition}'\n");

            let packages = parse_packages(&[document(&source)]);

            assert_eq!(packages[0].feature_resolver, resolver, "edition {edition}");
        }
    }

    #[test]
    fn static_targets_preserve_required_features_and_cargo_test_defaults() {
        let packages = parse_packages(&[document(
            r#"
                [package]
                name = "app"
                version = "1.0.0"
                edition = "2021"

                [[bin]]
                name = "tool"
                path = "src/tool.rs"
                required-features = ["z", "a", "z"]
                test = false

                [[example]]
                name = "demo"
                path = "examples/demo.rs"
                test = true

                [[bench]]
                name = "perf"
                path = "benches/perf.rs"
            "#,
        )]);

        let targets = &packages[0].targets;
        let tool = targets.iter().find(|target| target.name == "tool").unwrap();
        assert_eq!(tool.edition, "2021");
        assert_eq!(tool.required_features, ["a", "z"]);
        assert!(!tool.test);
        assert!(
            targets
                .iter()
                .find(|target| target.name == "demo")
                .unwrap()
                .test
        );
        assert!(
            !targets
                .iter()
                .find(|target| target.name == "perf")
                .unwrap()
                .test
        );
    }

    #[test]
    fn standalone_explicit_package_resolver_overrides_the_edition_default() {
        for (resolver, edition) in [(1, "2024"), (2, "2015"), (3, "2015")] {
            let source = format!(
                "[package]\nname = 'app'\nversion = '1.0.0'\nedition = '{edition}'\nresolver = '{resolver}'\n"
            );

            let packages = parse_packages(&[document(&source)]);

            assert_eq!(packages[0].feature_resolver, resolver);
        }
    }

    #[test]
    fn nested_workspace_does_not_override_a_scan_root_standalone_package() {
        let documents = [
            document(
                "[package]\nname = 'app'\nversion = '1.0.0'\nedition = '2024'\nresolver = '1'\n",
            ),
            document_at("vendor", "[workspace]\nmembers = []\nresolver = '3'\n"),
        ];

        assert_eq!(workspace_feature_resolver(&documents), Some(1));
        assert_eq!(parse_packages(&documents)[0].feature_resolver, 1);
    }

    #[test]
    fn inherited_workspace_package_values_use_the_closest_ancestor() {
        let documents = [
            document(
                "[workspace]\nmembers = ['member']\n\n[workspace.package]\nversion = '1.0.0'\nedition = '2021'\n",
            ),
            document_at(
                "member",
                "[package]\nname = 'member'\nversion.workspace = true\nedition.workspace = true\n",
            ),
            document_at(
                "nested",
                "[workspace]\nmembers = ['child']\n\n[workspace.package]\nversion = '2.0.0'\nedition = '2024'\n",
            ),
            document_at(
                "nested/child",
                "[package]\nname = 'nested-child'\nversion.workspace = true\nedition.workspace = true\n",
            ),
        ];

        let packages = parse_packages(&documents);
        let member = packages
            .iter()
            .find(|package| package.name == "member")
            .unwrap();
        assert_eq!(member.version, "1.0.0");
        assert_eq!(member.edition, "2021");
        let nested = packages
            .iter()
            .find(|package| package.name == "nested-child")
            .unwrap();
        assert_eq!(nested.version, "2.0.0");
        assert_eq!(nested.edition, "2024");
    }

    #[test]
    fn explicit_package_workspace_owns_inherited_package_and_dependency_values() {
        let documents = [
            document(
                "[workspace]\nresolver='2'\n\n[workspace.package]\nversion='1.0.0'\nedition='2018'\n\n[workspace.dependencies]\nshared='1.0.0'\n",
            ),
            document_at(
                "member",
                "[package]\nname='member'\nworkspace='../owner'\nversion.workspace=true\nedition.workspace=true\n\n[dependencies]\nshared.workspace=true\n",
            ),
            document_at(
                "owner",
                "[workspace]\nresolver='3'\n\n[workspace.package]\nversion='2.0.0'\nedition='2024'\n\n[workspace.dependencies]\nshared={ version='2.0.0', path='../shared' }\n",
            ),
            document_at(
                "shared",
                "[package]\nname='shared'\nversion='2.0.0'\nedition='2021'\n",
            ),
        ];

        let packages = parse_packages(&documents);
        let member = packages
            .iter()
            .find(|package| package.name == "member")
            .unwrap();
        assert_eq!(member.version, "2.0.0");
        assert_eq!(member.edition, "2024");
        assert_eq!(member.feature_resolver, 2);
        assert_eq!(member.dependencies[0].version.as_deref(), Some("2.0.0"));
        assert_eq!(
            member.dependencies[0].path,
            Some(PathBuf::from("/workspace/shared"))
        );
    }

    #[test]
    fn static_target_discovery_honors_auto_flags_and_edition_2015_defaults() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().canonicalize().unwrap();
        std::fs::create_dir_all(dir.join("src/bin")).unwrap();
        std::fs::write(dir.join("src/lib.rs"), "pub fn stale() {}\n").unwrap();
        std::fs::write(dir.join("src/main.rs"), "fn main() {}\n").unwrap();
        std::fs::write(dir.join("src/bin/auto.rs"), "fn main() {}\n").unwrap();
        let make_document = |source: &str| ManifestDocument {
            abs_path: dir.join("Cargo.toml"),
            rel_path: "Cargo.toml".into(),
            dir: dir.clone(),
            rel_dir: ".".into(),
            value: toml::from_str(source).unwrap(),
        };

        let disabled = parse_packages(&[make_document(
            "[package]\nname='app'\nversion='1.0.0'\nedition='2021'\nautolib=false\nautobins=false\n\n[[bin]]\nname='manual'\npath='src/main.rs'\n",
        )]);
        assert_eq!(disabled[0].targets.len(), 1);
        assert_eq!(disabled[0].targets[0].name, "manual");

        let legacy = parse_packages(&[make_document(
            "[package]\nname='legacy'\nversion='1.0.0'\nedition='2015'\n\n[[bin]]\nname='manual'\npath='src/main.rs'\n",
        )]);
        assert_eq!(legacy[0].targets.len(), 1);
        assert_eq!(legacy[0].targets[0].name, "manual");

        let explicit_lib = parse_packages(&[make_document(
            "[package]\nname='explicit'\nversion='1.0.0'\nedition='2021'\nautolib=false\n\n[lib]\npath='src/lib.rs'\n",
        )]);
        assert!(
            explicit_lib[0]
                .targets
                .iter()
                .any(|target| target.kind == "lib")
        );

        let rlib = parse_packages(&[make_document(
            "[package]\nname='rlib'\nversion='1.0.0'\n\n[lib]\npath='src/lib.rs'\ncrate-type=['rlib']\n",
        )]);
        assert_eq!(rlib[0].targets[0].kind, "lib");
        let cdylib = parse_packages(&[make_document(
            "[package]\nname='cdylib'\nversion='1.0.0'\n\n[lib]\npath='src/lib.rs'\ncrate-type=['cdylib']\n",
        )]);
        assert_eq!(cdylib[0].targets[0].kind, "cdylib");
    }

    #[test]
    fn workspace_root_package_resolver_controls_every_member() {
        for (resolver, edition) in [(1, "2024"), (2, "2015"), (3, "2015")] {
            let root = document(&format!(
                "[package]\nname = 'root'\nversion = '1.0.0'\nedition = '{edition}'\nresolver = '{resolver}'\n\n[workspace]\nmembers = ['member']\n"
            ));
            let member = document_at(
                "member",
                "[package]\nname = 'member'\nversion = '1.0.0'\nedition = '2024'\n",
            );
            let documents = [root, member];

            assert_eq!(workspace_feature_resolver(&documents), Some(resolver));
            assert!(
                parse_packages(&documents)
                    .iter()
                    .all(|package| package.feature_resolver == resolver)
            );
        }
    }

    #[test]
    fn workspace_root_edition_selects_the_workspace_default_resolver() {
        for (edition, resolver) in [("2015", 1), ("2018", 1), ("2021", 2), ("2024", 3)] {
            let documents = [document(&format!(
                "[package]\nname = 'root'\nversion = '1.0.0'\nedition = '{edition}'\n\n[workspace]\n"
            ))];

            assert_eq!(
                workspace_feature_resolver(&documents),
                Some(resolver),
                "edition {edition}"
            );
            assert_eq!(parse_packages(&documents)[0].feature_resolver, resolver);
        }
    }

    #[test]
    fn virtual_workspace_defaults_to_resolver_one_and_honors_explicit_versions() {
        let member = || {
            document_at(
                "member",
                "[package]\nname = 'member'\nversion = '1.0.0'\nedition = '2024'\n",
            )
        };
        let default_documents = [document("[workspace]\nmembers = ['member']\n"), member()];
        assert_eq!(workspace_feature_resolver(&default_documents), Some(1));
        assert_eq!(parse_packages(&default_documents)[0].feature_resolver, 1);

        for resolver in 1..=3 {
            let documents = [
                document(&format!(
                    "[workspace]\nmembers = ['member']\nresolver = '{resolver}'\n"
                )),
                member(),
            ];

            assert_eq!(workspace_feature_resolver(&documents), Some(resolver));
            assert_eq!(parse_packages(&documents)[0].feature_resolver, resolver);
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
    fn expands_named_features_within_one_package_only() {
        let packages = parse_packages(&[
            document(
                r#"
                    [package]
                    name = "app"
                    version = "1.0.0"

                    [features]
                    shared = ["app-only"]
                    app-only = []
                "#,
            ),
            document(
                r#"
                    [package]
                    name = "dep"
                    version = "1.0.0"

                    [features]
                    default = ["implicit"]
                    implicit = []
                    shared = ["dep-only"]
                    dep-only = []
                "#,
            ),
        ]);
        let dependency = packages
            .iter()
            .find(|package| package.name == "dep")
            .expect("dependency package");

        assert_eq!(
            expanded_named_features(dependency, &["shared".into()], false),
            BTreeSet::from(["dep-only".into(), "shared".into()])
        );
    }

    #[test]
    fn static_dependencies_retain_sorted_feature_options() {
        let packages = parse_packages(&[document(
            r#"
                [package]
                name = "app"
                version = "1.0.0"

                [dependencies]
                modern = { version = "1", optional = true, features = ["derive", "alloc", "derive"], default-features = false }
                legacy = { version = "1", features = ["z", "a", "z"], default_features = false }
                plain = "1"
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

        assert!(dependency("modern").optional);
        assert_eq!(dependency("modern").features, ["alloc", "derive"]);
        assert!(!dependency("modern").uses_default_features);
        assert_eq!(dependency("legacy").features, ["a", "z"]);
        assert!(!dependency("legacy").uses_default_features);
        assert!(!dependency("plain").optional);
        assert!(dependency("plain").features.is_empty());
        assert!(dependency("plain").uses_default_features);
    }

    #[test]
    fn workspace_dependency_features_are_extended_by_the_member() {
        let root = ManifestDocument {
            abs_path: PathBuf::from("/workspace/Cargo.toml"),
            rel_path: "Cargo.toml".into(),
            dir: PathBuf::from("/workspace"),
            rel_dir: ".".into(),
            value: toml::from_str(
                r#"
                    [workspace]
                    members = ["member"]

                    [workspace.dependencies]
                    shared = { version = "1", features = ["z", "base"], default-features = false }
                "#,
            )
            .expect("valid workspace manifest"),
        };
        let member = ManifestDocument {
            abs_path: PathBuf::from("/workspace/member/Cargo.toml"),
            rel_path: "member/Cargo.toml".into(),
            dir: PathBuf::from("/workspace/member"),
            rel_dir: "member".into(),
            value: toml::from_str(
                r#"
                    [package]
                    name = "member"
                    version = "1.0.0"

                    [dependencies]
                    shared = { workspace = true, optional = true, features = ["member", "base"] }
                "#,
            )
            .expect("valid member manifest"),
        };

        let packages = parse_packages(&[root, member]);
        let dependency = &packages[0].dependencies[0];
        assert!(dependency.optional);
        assert_eq!(dependency.features, ["base", "member", "z"]);
        assert!(!dependency.uses_default_features);
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
