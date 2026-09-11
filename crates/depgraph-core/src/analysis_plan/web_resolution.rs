//! Repository-confined TypeScript configuration and locked package witnesses.

use super::{
    AnalysisAdapter, AnalysisDependencyResolution, AnalysisUnit, FileKind, MAX_MANIFEST_BYTES,
    WebResolutionContext, is_within, join_relative, manifest_directory, most_specific_executable,
    read_bounded, web_import_package_name,
};
use anyhow::Result;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

#[derive(Clone, Default)]
struct Paths {
    base_url: Option<String>,
    origin: String,
    patterns: BTreeMap<String, Vec<String>>,
    patterns_defined: bool,
    sources: BTreeSet<String>,
}

pub(super) struct WebInputs {
    configs: BTreeMap<String, Paths>,
    locked: BTreeMap<String, BTreeSet<String>>,
}

impl WebInputs {
    pub(super) fn discover(
        root: &Path,
        files: &BTreeMap<String, FileKind>,
        units: &[AnalysisUnit],
        web: &WebResolutionContext<'_>,
    ) -> Result<Self> {
        let mut configs = BTreeMap::new();
        let mut cache = BTreeMap::new();
        let mut locked = BTreeMap::new();
        for path in files.keys() {
            let name = path.rsplit('/').next().unwrap_or(path);
            if matches!(name, "tsconfig.json" | "jsconfig.json")
                && let Some(config) = load_paths(
                    root,
                    path,
                    files,
                    units,
                    web,
                    &mut cache,
                    &mut BTreeSet::new(),
                )?
            {
                configs.insert(path.clone(), config);
            }
            if name == "pnpm-lock.yaml" || name == "pnpm-lock.yml" {
                let bytes = read_bounded(root, path, MAX_MANIFEST_BYTES)?;
                locked.insert(
                    manifest_directory(path).to_owned(),
                    pnpm_packages(&String::from_utf8_lossy(&bytes)),
                );
            } else if matches!(name, "package-lock.json" | "npm-shrinkwrap.json") {
                let bytes = read_bounded(root, path, MAX_MANIFEST_BYTES)?;
                if let Ok(value) = serde_json::from_slice::<Value>(&bytes) {
                    let packages = value["packages"]
                        .as_object()
                        .into_iter()
                        .flatten()
                        .filter_map(|(location, metadata)| {
                            if metadata["link"] == true
                                || metadata["resolved"].as_str().is_some_and(local_version)
                            {
                                return None;
                            }
                            let (_, package) = location.rsplit_once("node_modules/")?;
                            (!package.is_empty()).then(|| package.to_owned())
                        })
                        .collect();
                    locked.insert(manifest_directory(path).to_owned(), packages);
                }
            }
        }
        Ok(Self { configs, locked })
    }

    fn config(&self, source: &str) -> Option<&Paths> {
        self.configs
            .iter()
            .filter(|(path, _)| is_within(source, manifest_directory(path)))
            .max_by_key(|(path, _)| {
                (
                    manifest_directory(path).len(),
                    path.ends_with("tsconfig.json"),
                )
            })
            .map(|(_, config)| config)
    }

    pub(super) fn config_sources(&self, source: &str) -> impl Iterator<Item = &String> {
        self.config(source)
            .into_iter()
            .flat_map(|config| &config.sources)
    }

    pub(super) fn external(&self, owner: &str, package: &str) -> bool {
        let types = if let Some(scoped) = package.strip_prefix('@') {
            format!("@types/{}", scoped.replace('/', "__"))
        } else {
            format!("@types/{package}")
        };
        self.locked
            .iter()
            .filter(|(directory, _)| is_within(owner, directory))
            .max_by_key(|(directory, _)| directory.len())
            .is_some_and(|(_, packages)| packages.contains(package) || packages.contains(&types))
    }

    pub(super) fn resolve_alias(
        &self,
        source: &str,
        specifier: &str,
        files: &BTreeMap<String, FileKind>,
        units: &[AnalysisUnit],
    ) -> Option<(Option<String>, AnalysisDependencyResolution)> {
        let config = self.config(source)?;
        let mut matches = config
            .patterns
            .iter()
            .filter_map(|(pattern, targets)| {
                if pattern == specifier {
                    return Some((usize::MAX, "", targets));
                }
                let (prefix, suffix) = pattern.split_once('*')?;
                if suffix.contains('*') {
                    return None;
                }
                let matched = specifier.strip_prefix(prefix)?.strip_suffix(suffix)?;
                Some((prefix.len(), matched, targets))
            })
            .collect::<Vec<_>>();
        matches.sort_by_key(|(length, _, _)| std::cmp::Reverse(*length));
        let base = config.base_url.as_deref().unwrap_or(&config.origin);
        if let Some((length, wildcard, targets)) = matches.first() {
            if matches.get(1).is_some_and(|(other, _, _)| other == length) {
                return Some((None, AnalysisDependencyResolution::Unknown));
            }
            for target in *targets {
                let target = target.replace('*', wildcard);
                if let Some(path) = join_relative(base, &target)
                    && let Some(owner) = source_owner(&path, files, units)
                {
                    return Some((Some(owner), AnalysisDependencyResolution::Resolved));
                }
            }
            return Some((None, AnalysisDependencyResolution::Unknown));
        }
        if let Some(base) = &config.base_url
            && let Some(path) = join_relative(base, specifier)
            && let Some(owner) = source_owner(&path, files, units)
        {
            return Some((Some(owner), AnalysisDependencyResolution::Resolved));
        }
        None
    }
}

fn source_owner(
    path: &str,
    files: &BTreeMap<String, FileKind>,
    units: &[AnalysisUnit],
) -> Option<String> {
    let mut candidates = vec![path.to_owned()];
    for (extension, typescript) in [
        (".js", ".ts"),
        (".jsx", ".tsx"),
        (".mjs", ".mts"),
        (".cjs", ".cts"),
    ] {
        if let Some(base) = path.strip_suffix(extension) {
            candidates.push(format!("{base}{typescript}"));
        }
    }
    for suffix in [
        ".ts",
        ".tsx",
        ".d.ts",
        ".mts",
        ".cts",
        ".js",
        ".jsx",
        ".mjs",
        ".cjs",
        ".json",
        "/index.ts",
        "/index.tsx",
        "/index.d.ts",
        "/index.js",
        "/index.jsx",
    ] {
        candidates.push(format!("{path}{suffix}"));
    }
    candidates.into_iter().find_map(|path| {
        files
            .contains_key(&path)
            .then(|| {
                most_specific_executable(&path, AnalysisAdapter::Web, units)
                    .map(|unit| unit.id.clone())
            })
            .flatten()
    })
}

fn load_paths(
    root: &Path,
    path: &str,
    files: &BTreeMap<String, FileKind>,
    units: &[AnalysisUnit],
    web: &WebResolutionContext<'_>,
    cache: &mut BTreeMap<String, Option<Paths>>,
    visiting: &mut BTreeSet<String>,
) -> Result<Option<Paths>> {
    if let Some(cached) = cache.get(path) {
        return Ok(cached.clone());
    }
    if visiting.len() >= 32 || !visiting.insert(path.to_owned()) {
        return Ok(None);
    }
    let result = load_paths_inner(root, path, files, units, web, cache, visiting)?;
    visiting.remove(path);
    cache.insert(path.to_owned(), result.clone());
    Ok(result)
}

fn load_paths_inner(
    root: &Path,
    path: &str,
    files: &BTreeMap<String, FileKind>,
    units: &[AnalysisUnit],
    web: &WebResolutionContext<'_>,
    cache: &mut BTreeMap<String, Option<Paths>>,
    visiting: &mut BTreeSet<String>,
) -> Result<Option<Paths>> {
    let bytes = read_bounded(root, path, MAX_MANIFEST_BYTES)?;
    let Some(value) = jsonc(&bytes) else {
        return Ok(None);
    };
    let directory = manifest_directory(path);
    let mut config = Paths {
        origin: directory.to_owned(),
        ..Paths::default()
    };
    let parents = value["extends"]
        .as_str()
        .map(|parent| vec![parent])
        .unwrap_or_else(|| {
            value["extends"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .collect()
        });
    for parent in parents {
        let candidate = if parent.starts_with('.') {
            join_relative(directory, parent)
        } else {
            let owner = most_specific_executable(path, AnalysisAdapter::Web, units);
            let package = web_import_package_name(parent);
            let ids = owner
                .and_then(|owner| web.scopes.get(&owner.id))
                .and_then(|scope| web.name_index.get(&(scope.clone(), package.to_owned())));
            ids.filter(|ids| ids.len() == 1)
                .and_then(|ids| units.iter().find(|unit| unit.id == ids[0]))
                .and_then(|unit| {
                    let suffix = parent.strip_prefix(package)?.trim_start_matches('/');
                    join_relative(
                        &unit.unit_root,
                        if suffix.is_empty() {
                            "tsconfig.json"
                        } else {
                            suffix
                        },
                    )
                })
        };
        let Some(candidate) = candidate else {
            return Ok(None);
        };
        let Some(parent_path) = [
            candidate.clone(),
            format!("{candidate}.json"),
            format!("{candidate}/tsconfig.json"),
        ]
        .into_iter()
        .find(|path| files.contains_key(path)) else {
            return Ok(None);
        };
        let Some(parent_config) =
            load_paths(root, &parent_path, files, units, web, cache, visiting)?
        else {
            return Ok(None);
        };
        config.sources.extend(parent_config.sources);
        if parent_config.base_url.is_some() {
            config.base_url = parent_config.base_url;
        }
        if parent_config.patterns_defined {
            config.patterns_defined = true;
            config.patterns = parent_config.patterns;
            config.origin = parent_config.origin;
        }
    }
    config.sources.insert(path.to_owned());
    if let Some(base) = value["compilerOptions"]["baseUrl"].as_str() {
        let Some(base) = join_relative(directory, base) else {
            return Ok(None);
        };
        config.base_url = Some(base);
    }
    if let Some(patterns) = value["compilerOptions"]["paths"].as_object() {
        config.patterns_defined = true;
        config.patterns = patterns
            .iter()
            .map(|(pattern, values)| {
                (
                    pattern.clone(),
                    values
                        .as_array()
                        .into_iter()
                        .flatten()
                        .filter_map(Value::as_str)
                        .map(str::to_owned)
                        .collect(),
                )
            })
            .collect();
        config.origin = directory.to_owned();
    }
    Ok(Some(config))
}

fn local_version(version: &str) -> bool {
    ["file:", "link:", "workspace:", "./", "../"]
        .iter()
        .any(|prefix| version.starts_with(prefix))
}

fn pnpm_packages(text: &str) -> BTreeSet<String> {
    let mut in_packages = false;
    let mut packages = BTreeSet::new();
    for line in text.lines() {
        if !line.starts_with(' ') && !line.trim().is_empty() && !line.starts_with('#') {
            in_packages = line.trim() == "packages:" || line.trim() == "snapshots:";
            continue;
        }
        if !in_packages || !line.starts_with("  ") || line.starts_with("   ") {
            continue;
        }
        let Some(key) = yaml_key(line.trim()) else {
            continue;
        };
        let key = key.trim_start_matches('/');
        let search = usize::from(key.starts_with('@'));
        let Some(separator) = key[search..].find('@').map(|at| at + search) else {
            continue;
        };
        let (name, version) = (&key[..separator], &key[separator + 1..]);
        if !name.is_empty() && !local_version(version) {
            packages.insert(name.to_owned());
        }
    }
    packages
}

fn yaml_key(line: &str) -> Option<&str> {
    if line.starts_with(['\'', '"']) {
        let quote = line.as_bytes()[0] as char;
        let end = line[1..].find(quote)? + 1;
        return line[end + 1..].starts_with(':').then_some(&line[1..end]);
    }
    line.match_indices(':').find_map(|(at, _)| {
        line.as_bytes()
            .get(at + 1)
            .is_none_or(u8::is_ascii_whitespace)
            .then_some(&line[..at])
    })
}

fn jsonc(bytes: &[u8]) -> Option<Value> {
    let mut clean = bytes.to_vec();
    let mut at = 0;
    let mut quoted = false;
    while at < clean.len() {
        if quoted {
            if clean[at] == b'\\' {
                at += 2;
                continue;
            }
            if clean[at] == b'"' {
                quoted = false;
            }
        } else if clean[at] == b'"' {
            quoted = true;
        } else if clean.get(at..at + 2) == Some(b"//") {
            while at < clean.len() && clean[at] != b'\n' {
                clean[at] = b' ';
                at += 1;
            }
            continue;
        } else if clean.get(at..at + 2) == Some(b"/*") {
            clean[at] = b' ';
            clean[at + 1] = b' ';
            at += 2;
            while at + 1 < clean.len() && &clean[at..at + 2] != b"*/" {
                clean[at] = b' ';
                at += 1;
            }
            if at + 1 >= clean.len() {
                return None;
            }
            clean[at] = b' ';
            clean[at + 1] = b' ';
            at += 2;
            continue;
        }
        at += 1;
    }
    quoted = false;
    at = 0;
    while at < clean.len() {
        if quoted {
            if clean[at] == b'\\' {
                at += 2;
                continue;
            }
            if clean[at] == b'"' {
                quoted = false;
            }
        } else if clean[at] == b'"' {
            quoted = true;
        } else if clean[at] == b','
            && clean[at + 1..]
                .iter()
                .find(|byte| !byte.is_ascii_whitespace())
                .is_some_and(|byte| matches!(byte, b'}' | b']'))
        {
            clean[at] = b' ';
        }
        at += 1;
    }
    serde_json::from_slice(&clean).ok()
}
