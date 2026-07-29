use std::{
    collections::{BTreeSet, VecDeque},
    fs,
    path::{Component, Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use walkdir::WalkDir;

pub const COMPILER_PRECISE_UNIT_GRAPH_ADAPTER: &str = "rust-compiler-unit-graph";
pub const COMPILER_PRECISE_UNIT_GRAPH_ADAPTER_VERSION: &str = "1.0.0";
pub const COMPILER_PRECISE_UNIT_GRAPH_SCHEMA_VERSION: &str = "depgraph-rust-cargo-unit-graph-v1";
pub const COMPILER_PRECISE_UNIT_GRAPH_SCHEMA_PATH: &str =
    "schemas/depgraph-rust-cargo-unit-graph-v1.schema.json";
pub const COMPILER_PRECISE_UNIT_GRAPH_SCHEMA: &str =
    include_str!("../../../schemas/depgraph-rust-cargo-unit-graph-v1.schema.json");
pub const NEUTRAL_CARGO_CONFIG_SCHEMA_VERSION: &str = "depgraph-neutral-cargo-config-v1";

const MAX_CONFIG_FILES: usize = 256;
const MAX_CONFIG_BYTES: u64 = 1024 * 1024;
const MAX_UNIT_GRAPH_BYTES: usize = 16 * 1024 * 1024;
const MAX_UNITS: usize = 100_000;
const MAX_DEPENDENCIES: usize = 1_000_000;
const MAX_LIST_ITEMS: usize = 1_024;
const MAX_STRING_BYTES: usize = 4_096;

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct NeutralCargoConfig {
    pub schema_version: String,
    pub digest: String,
    pub rendered: String,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct RustCargoUnitGraph {
    pub schema_version: String,
    pub digest: String,
    pub units: Vec<RustCargoUnit>,
    pub roots: Vec<String>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct RustCargoUnit {
    pub unit_id: String,
    pub package_id: String,
    pub target: RustCargoTarget,
    pub profile: RustCargoProfile,
    pub platform: Option<String>,
    pub mode: String,
    pub features: Vec<String>,
    pub is_std: bool,
    pub dependencies: Vec<RustCargoDependency>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RustCargoTarget {
    pub kind: Vec<String>,
    pub crate_types: Vec<String>,
    pub name: String,
    pub src_path: String,
    pub edition: String,
    pub doc: bool,
    pub doctest: bool,
    pub test: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RustCargoProfile {
    pub name: String,
    pub opt_level: String,
    pub lto: String,
    pub codegen_units: Option<u64>,
    pub debuginfo: Option<u64>,
    pub split_debuginfo: Option<String>,
    pub debug_assertions: bool,
    pub overflow_checks: bool,
    pub rpath: bool,
    pub incremental: bool,
    pub panic: String,
    pub strip: RustCargoStrip,
    pub codegen_backend: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RustCargoStrip {
    Deferred(String),
    Resolved(String),
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct RustCargoDependency {
    pub unit_id: String,
    pub extern_crate_name: String,
    pub public: bool,
    pub noprelude: bool,
    pub nounused: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawUnitGraph {
    version: u64,
    units: Vec<RawUnit>,
    roots: Vec<usize>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawUnit {
    pkg_id: String,
    target: RustCargoTarget,
    profile: RustCargoProfile,
    platform: Option<String>,
    mode: String,
    features: Vec<String>,
    #[serde(default)]
    is_std: bool,
    dependencies: Vec<RawDependency>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDependency {
    index: usize,
    extern_crate_name: String,
    #[serde(default)]
    public: bool,
    #[serde(default)]
    noprelude: bool,
    #[serde(default)]
    nounused: bool,
}

#[derive(Serialize)]
struct UnitIdentity<'a> {
    package_id: &'a str,
    target: &'a RustCargoTarget,
    profile: &'a RustCargoProfile,
    platform: &'a Option<String>,
    mode: &'a str,
    features: &'a [String],
    is_std: bool,
}

pub fn project_neutral_cargo_config(root: &Path) -> Result<NeutralCargoConfig> {
    let root = root
        .canonicalize()
        .context("compiler-precise source root is unavailable")?;
    if !root.is_dir() {
        bail!("compiler-precise source root is not a directory");
    }
    let mut configs = Vec::new();
    for entry in WalkDir::new(&root)
        .follow_links(false)
        .into_iter()
        .filter_entry(admit_config_inventory_entry)
    {
        let entry = entry?;
        let relative = entry.path().strip_prefix(&root)?;
        if relative.as_os_str().is_empty() {
            continue;
        }
        if entry.file_type().is_symlink() {
            bail!(
                "security policy violation: compiler-precise configuration inventory contains a symlink"
            );
        }
        if is_cargo_config_path(relative) {
            let metadata = fs::symlink_metadata(entry.path())?;
            if !metadata.is_file() || metadata.len() > MAX_CONFIG_BYTES {
                bail!(
                    "security policy violation: compiler-precise Cargo configuration must be a bounded regular file"
                );
            }
            configs.push((relative.to_path_buf(), entry.path().to_path_buf()));
            if configs.len() > MAX_CONFIG_FILES {
                bail!(
                    "security policy violation: compiler-precise Cargo configuration inventory exceeds its file limit"
                );
            }
        }
    }
    configs.sort_by(|left, right| left.0.cmp(&right.0));
    if configs.windows(2).any(|window| {
        window[0].0.parent() == window[1].0.parent()
            && window[0].0.file_name() != window[1].0.file_name()
    }) {
        bail!(
            "security policy violation: compiler-precise Cargo configuration contains both legacy and TOML config files"
        );
    }

    let mut root_projection = toml::Table::new();
    for (relative, path) in configs {
        let bytes = fs::read(&path)?;
        let text = std::str::from_utf8(&bytes)
            .context("compiler-precise Cargo configuration is not UTF-8")?;
        let value: toml::Value =
            toml::from_str(text).context("compiler-precise Cargo configuration is invalid TOML")?;
        let table = value
            .as_table()
            .context("compiler-precise Cargo configuration must be a TOML table")?;
        let projection = validate_and_project_config(table)?;
        if is_root_cargo_config(&relative) {
            merge_root_projection(&mut root_projection, projection)?;
        }
    }

    let mut neutral = toml::Table::new();
    if let Some(build) = root_projection.remove("build") {
        neutral.insert("build".to_owned(), build);
    }
    if let Some(target) = root_projection.remove("target") {
        neutral.insert("target".to_owned(), target);
    }
    neutral.insert(
        "net".to_owned(),
        toml::Value::Table(toml::Table::from_iter([(
            "offline".to_owned(),
            toml::Value::Boolean(true),
        )])),
    );
    neutral.insert(
        "term".to_owned(),
        toml::Value::Table(toml::Table::from_iter([(
            "color".to_owned(),
            toml::Value::String("never".to_owned()),
        )])),
    );
    let rendered =
        toml::to_string(&toml::Value::Table(neutral)).context("render neutral Cargo config")?;
    let digest = digest_bytes(rendered.as_bytes());
    Ok(NeutralCargoConfig {
        schema_version: NEUTRAL_CARGO_CONFIG_SCHEMA_VERSION.to_owned(),
        digest,
        rendered,
    })
}

pub fn install_neutral_cargo_config(workspace: &Path, config: &NeutralCargoConfig) -> Result<()> {
    if config.schema_version != NEUTRAL_CARGO_CONFIG_SCHEMA_VERSION
        || config.digest != digest_bytes(config.rendered.as_bytes())
    {
        bail!("security policy violation: neutral Cargo configuration identity is invalid");
    }
    let mut existing = Vec::new();
    for entry in WalkDir::new(workspace).follow_links(false) {
        let entry = entry?;
        let relative = entry.path().strip_prefix(workspace)?;
        if is_cargo_config_path(relative) {
            existing.push(entry.path().to_path_buf());
        }
    }
    existing.sort();
    for path in existing {
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            bail!("security policy violation: staged Cargo configuration is not regular");
        }
        fs::remove_file(path)?;
    }
    let cargo_directory = workspace.join(".cargo");
    fs::create_dir_all(&cargo_directory)?;
    fs::write(cargo_directory.join("config.toml"), &config.rendered)?;
    Ok(())
}

pub fn validate_cargo_unit_graph(bytes: &[u8], workspace: &Path) -> Result<RustCargoUnitGraph> {
    if bytes.is_empty() || bytes.len() > MAX_UNIT_GRAPH_BYTES {
        bail!("Cargo unit graph output is empty or exceeds its byte limit");
    }
    let workspace = workspace
        .canonicalize()
        .context("staged compiler-precise workspace is unavailable")?;
    let raw: RawUnitGraph =
        serde_json::from_slice(bytes).context("Cargo unit graph is invalid JSON")?;
    if raw.version != 1 {
        bail!("unsupported Cargo unit graph version {}", raw.version);
    }
    if raw.units.is_empty() || raw.units.len() > MAX_UNITS {
        bail!("Cargo unit graph unit count is outside the supported bounds");
    }
    if raw.roots.is_empty() || raw.roots.len() > raw.units.len() {
        bail!("Cargo unit graph root count is outside the supported bounds");
    }
    let dependency_count = raw
        .units
        .iter()
        .try_fold(0_usize, |count, unit| {
            count.checked_add(unit.dependencies.len())
        })
        .context("Cargo unit graph dependency count overflowed")?;
    if dependency_count > MAX_DEPENDENCIES {
        bail!("Cargo unit graph dependency count exceeds its limit");
    }
    validate_indices_and_reachability(&raw)?;

    let mut normalized = Vec::with_capacity(raw.units.len());
    let mut identity_set = BTreeSet::new();
    for unit in &raw.units {
        let package_id = normalize_package_id(&unit.pkg_id, &workspace)?;
        let mut target = unit.target.clone();
        validate_string_list("Cargo target kind", &mut target.kind)?;
        validate_string_list("Cargo crate type", &mut target.crate_types)?;
        validate_text("Cargo target name", &target.name)?;
        validate_text("Cargo target edition", &target.edition)?;
        target.src_path = normalize_source_path(&target.src_path, &workspace)?;
        validate_profile(&unit.profile)?;
        if let Some(platform) = &unit.platform {
            validate_identity("Cargo unit platform", platform)?;
        }
        if !matches!(
            unit.mode.as_str(),
            "test" | "build" | "check" | "doc" | "doctest" | "run-custom-build"
        ) {
            bail!("Cargo unit graph contains an unsupported unit mode");
        }
        let mut features = unit.features.clone();
        validate_string_list("Cargo unit feature", &mut features)?;
        let identity = UnitIdentity {
            package_id: &package_id,
            target: &target,
            profile: &unit.profile,
            platform: &unit.platform,
            mode: &unit.mode,
            features: &features,
            is_std: unit.is_std,
        };
        let unit_id = format!("cargo-unit:{}", digest_json(&identity)?);
        if !identity_set.insert(unit_id.clone()) {
            bail!("Cargo unit graph contains duplicate canonical units");
        }
        normalized.push((unit_id, package_id, target, unit.profile.clone(), features));
    }

    let index_to_id = normalized
        .iter()
        .map(|unit| unit.0.clone())
        .collect::<Vec<_>>();
    let mut units = raw
        .units
        .iter()
        .enumerate()
        .map(|(index, raw_unit)| {
            let normalized_unit = &normalized[index];
            let mut dependencies = raw_unit
                .dependencies
                .iter()
                .map(|dependency| {
                    validate_text(
                        "Cargo dependency extern crate name",
                        &dependency.extern_crate_name,
                    )?;
                    Ok(RustCargoDependency {
                        unit_id: index_to_id[dependency.index].clone(),
                        extern_crate_name: dependency.extern_crate_name.clone(),
                        public: dependency.public,
                        noprelude: dependency.noprelude,
                        nounused: dependency.nounused,
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            dependencies.sort();
            if !dependencies.windows(2).all(|window| window[0] != window[1]) {
                bail!("Cargo unit graph contains duplicate dependencies");
            }
            Ok(RustCargoUnit {
                unit_id: normalized_unit.0.clone(),
                package_id: normalized_unit.1.clone(),
                target: normalized_unit.2.clone(),
                profile: normalized_unit.3.clone(),
                platform: raw_unit.platform.clone(),
                mode: raw_unit.mode.clone(),
                features: normalized_unit.4.clone(),
                is_std: raw_unit.is_std,
                dependencies,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    units.sort_by(|left, right| left.unit_id.cmp(&right.unit_id));

    let mut roots = raw
        .roots
        .iter()
        .map(|index| index_to_id[*index].clone())
        .collect::<Vec<_>>();
    roots.sort();
    if !roots.windows(2).all(|window| window[0] != window[1]) {
        bail!("Cargo unit graph contains duplicate roots");
    }
    let digest = digest_json(&(&units, &roots))?;
    Ok(RustCargoUnitGraph {
        schema_version: COMPILER_PRECISE_UNIT_GRAPH_SCHEMA_VERSION.to_owned(),
        digest,
        units,
        roots,
    })
}

fn validate_and_project_config(table: &toml::Table) -> Result<toml::Table> {
    let mut projected = toml::Table::new();
    for (key, value) in table {
        match key.as_str() {
            "build" => {
                let build = value
                    .as_table()
                    .context("compiler-precise Cargo build configuration must be a table")?;
                let mut output = toml::Table::new();
                for (key, value) in build {
                    match key.as_str() {
                        "target" => {
                            let target = value.as_str().context(
                                "compiler-precise Cargo build.target must be a target triple",
                            )?;
                            validate_identity("Cargo build target", target)?;
                            if target.ends_with(".json")
                                || target.contains('/')
                                || target.contains('\\')
                            {
                                reject_config_key("build.target")?;
                            }
                            output.insert(key.clone(), value.clone());
                        }
                        "rustflags" => {
                            validate_rustflags(value, "build.rustflags")?;
                            output.insert(key.clone(), value.clone());
                        }
                        "rustc"
                        | "rustc-wrapper"
                        | "rustc-workspace-wrapper"
                        | "rustdoc"
                        | "rustdocflags"
                        | "target-dir"
                        | "build-dir"
                        | "dep-info-basedir" => reject_config_key(&format!("build.{key}"))?,
                        _ => reject_config_key(&format!("build.{key}"))?,
                    }
                }
                if !output.is_empty() {
                    projected.insert("build".to_owned(), toml::Value::Table(output));
                }
            }
            "target" => {
                let targets = value
                    .as_table()
                    .context("compiler-precise Cargo target configuration must be a table")?;
                let mut output_targets = toml::Table::new();
                for (target, value) in targets {
                    validate_identity("Cargo configuration target", target)?;
                    if target.ends_with(".json") || target.contains('/') || target.contains('\\') {
                        reject_config_key(&format!("target.{target}"))?;
                    }
                    let settings = value.as_table().with_context(|| {
                        format!("compiler-precise Cargo target.{target} must be a table")
                    })?;
                    let mut output_settings = toml::Table::new();
                    for (key, value) in settings {
                        match key.as_str() {
                            "rustflags" => {
                                validate_rustflags(value, &format!("target.{target}.rustflags"))?;
                                output_settings.insert(key.clone(), value.clone());
                            }
                            "runner" | "linker" => {
                                reject_config_key(&format!("target.{target}.{key}"))?
                            }
                            _ => reject_config_key(&format!("target.{target}.{key}"))?,
                        }
                    }
                    if !output_settings.is_empty() {
                        output_targets.insert(target.clone(), toml::Value::Table(output_settings));
                    }
                }
                if !output_targets.is_empty() {
                    projected.insert("target".to_owned(), toml::Value::Table(output_targets));
                }
            }
            "net" => {
                let net = value
                    .as_table()
                    .context("compiler-precise Cargo net configuration must be a table")?;
                for key in net.keys() {
                    if key != "offline" {
                        reject_config_key(&format!("net.{key}"))?;
                    }
                }
            }
            "term" => {
                let term = value
                    .as_table()
                    .context("compiler-precise Cargo term configuration must be a table")?;
                for key in term.keys() {
                    if key != "color" {
                        reject_config_key(&format!("term.{key}"))?;
                    }
                }
            }
            "alias"
            | "credential-alias"
            | "env"
            | "registries"
            | "registry"
            | "unstable"
            | "doc"
            | "http"
            | "future-incompat-report"
            | "cache"
            | "install"
            | "patch"
            | "paths"
            | "profile"
            | "resolver"
            | "source" => reject_config_key(key)?,
            _ => reject_config_key(key)?,
        }
    }
    Ok(projected)
}

fn validate_rustflags(value: &toml::Value, key: &str) -> Result<()> {
    let flags = match value {
        toml::Value::Array(values) => values
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .with_context(|| format!("compiler-precise Cargo {key} must contain strings"))
            })
            .collect::<Result<Vec<_>>>()?,
        toml::Value::String(_) => {
            return reject_config_key(key);
        }
        _ => bail!("compiler-precise Cargo {key} must be an array"),
    };
    if flags.len() > MAX_LIST_ITEMS {
        bail!("compiler-precise Cargo {key} exceeds its item limit");
    }
    let mut index = 0;
    while index < flags.len() {
        let flag = flags[index];
        validate_text("Cargo rustflag", flag)?;
        let consumes_value = matches!(flag, "--cfg" | "--check-cfg" | "-A" | "-W" | "-D" | "-F");
        let admitted = flag.starts_with("--cfg=")
            || flag.starts_with("--check-cfg=")
            || flag.starts_with("-A")
            || flag.starts_with("-W")
            || flag.starts_with("-D")
            || flag.starts_with("-F")
            || consumes_value;
        if !admitted
            || flag.contains('@')
            || flag.contains("linker")
            || flag.contains("link-arg")
            || flag.contains("plugin")
            || flag.contains("codegen-backend")
            || flag.contains("--extern")
            || flag.starts_with("-L")
            || flag.starts_with("-Z")
        {
            return reject_config_key(key);
        }
        if consumes_value {
            index += 1;
            let value = flags.get(index).with_context(|| {
                format!("compiler-precise Cargo {key} has a missing flag value")
            })?;
            validate_text("Cargo rustflag value", value)?;
            if value.contains('@') || value.contains('/') || value.contains('\\') {
                return reject_config_key(key);
            }
        }
        index += 1;
    }
    Ok(())
}

fn reject_config_key<T>(key: &str) -> Result<T> {
    let bounded = key.chars().take(160).collect::<String>();
    bail!(
        "security policy violation: compiler-precise Cargo configuration key `{bounded}` can influence execution and is not allowlisted"
    )
}

fn merge_root_projection(target: &mut toml::Table, source: toml::Table) -> Result<()> {
    for (section, value) in source {
        if target.insert(section.clone(), value).is_some() {
            bail!(
                "security policy violation: compiler-precise Cargo configuration has ambiguous legacy and TOML projections for `{section}`"
            );
        }
    }
    Ok(())
}

fn is_cargo_config_path(path: &Path) -> bool {
    let mut components = path.components().rev();
    let Some(Component::Normal(file)) = components.next() else {
        return false;
    };
    let Some(Component::Normal(directory)) = components.next() else {
        return false;
    };
    directory == ".cargo" && matches!(file.to_str(), Some("config" | "config.toml"))
}

fn admit_config_inventory_entry(entry: &walkdir::DirEntry) -> bool {
    if entry.depth() == 0 || !entry.file_type().is_dir() {
        return true;
    }
    if entry.depth() != 1 {
        return true;
    }
    !matches!(
        entry.file_name().to_str(),
        Some(".git" | ".depgraph" | "target" | ".next")
    )
}

fn is_root_cargo_config(path: &Path) -> bool {
    matches!(
        path.components().collect::<Vec<_>>().as_slice(),
        [Component::Normal(directory), Component::Normal(file)]
            if *directory == ".cargo" && matches!(file.to_str(), Some("config" | "config.toml"))
    )
}

fn validate_indices_and_reachability(raw: &RawUnitGraph) -> Result<()> {
    for root in &raw.roots {
        if *root >= raw.units.len() {
            bail!("Cargo unit graph root index is out of bounds");
        }
    }
    let mut seen = BTreeSet::new();
    let mut queue = VecDeque::from(raw.roots.clone());
    while let Some(index) = queue.pop_front() {
        if !seen.insert(index) {
            continue;
        }
        for dependency in &raw.units[index].dependencies {
            if dependency.index >= raw.units.len() {
                bail!("Cargo unit graph dependency index is out of bounds");
            }
            queue.push_back(dependency.index);
        }
    }
    if seen.len() != raw.units.len() {
        bail!("Cargo unit graph contains units unreachable from its roots");
    }
    Ok(())
}

fn normalize_package_id(value: &str, workspace: &Path) -> Result<String> {
    validate_text("Cargo package ID", value)?;
    let Some(path_source) = value.strip_prefix("path+file://") else {
        if value.contains("file://") {
            bail!("Cargo package ID contains an unsupported file source");
        }
        return Ok(value.to_owned());
    };
    let (encoded_path, fragment) = path_source
        .rsplit_once('#')
        .context("Cargo path package ID has no version fragment")?;
    validate_text("Cargo package version fragment", fragment)?;
    let decoded = percent_decode(encoded_path)?;
    #[cfg(windows)]
    let decoded = decoded.strip_prefix('/').unwrap_or(&decoded);
    let path = PathBuf::from(decoded)
        .canonicalize()
        .context("Cargo path package source is unavailable")?;
    let logical = confined_logical_path(&path, workspace, true)?;
    Ok(format!("path+repo://{logical}#{fragment}"))
}

fn normalize_source_path(value: &str, workspace: &Path) -> Result<String> {
    validate_text("Cargo target source path", value)?;
    let path = PathBuf::from(value);
    if !path.is_absolute() {
        bail!("Cargo target source path is not absolute");
    }
    let path = path
        .canonicalize()
        .context("Cargo target source path is unavailable")?;
    let logical = confined_logical_path(&path, workspace, false)?;
    Ok(format!("repo://{logical}"))
}

fn confined_logical_path(path: &Path, workspace: &Path, allow_root: bool) -> Result<String> {
    if !path.starts_with(workspace) {
        bail!("security policy violation: Cargo unit graph source escapes the staged workspace");
    }
    let relative = path.strip_prefix(workspace)?;
    if relative.as_os_str().is_empty() {
        if allow_root {
            return Ok(".".to_owned());
        }
        bail!("Cargo target source path identifies the workspace directory");
    }
    for component in relative.components() {
        if !matches!(component, Component::Normal(_)) {
            bail!("Cargo unit graph source path is not canonical");
        }
    }
    Ok(relative.to_string_lossy().replace('\\', "/"))
}

fn percent_decode(value: &str) -> Result<String> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let hex = bytes
                .get(index + 1..index + 3)
                .context("Cargo package file URL has an invalid escape")?;
            let encoded =
                std::str::from_utf8(hex).context("Cargo package file URL escape is invalid")?;
            decoded.push(
                u8::from_str_radix(encoded, 16)
                    .context("Cargo package file URL escape is invalid")?,
            );
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(decoded).context("Cargo package file URL is not UTF-8")
}

fn validate_profile(profile: &RustCargoProfile) -> Result<()> {
    for (label, value) in [
        ("Cargo profile name", profile.name.as_str()),
        ("Cargo optimization level", profile.opt_level.as_str()),
        ("Cargo LTO setting", profile.lto.as_str()),
        ("Cargo panic strategy", profile.panic.as_str()),
    ] {
        validate_text(label, value)?;
    }
    if !matches!(profile.panic.as_str(), "unwind" | "abort") {
        bail!("Cargo unit graph contains an unsupported panic strategy");
    }
    if let Some(value) = &profile.split_debuginfo {
        validate_text("Cargo split debuginfo setting", value)?;
    }
    if let Some(value) = &profile.codegen_backend {
        validate_text("Cargo codegen backend", value)?;
    }
    let strip = match &profile.strip {
        RustCargoStrip::Deferred(value) | RustCargoStrip::Resolved(value) => value,
    };
    validate_text("Cargo strip setting", strip)?;
    Ok(())
}

fn validate_string_list(label: &str, values: &mut [String]) -> Result<()> {
    if values.len() > MAX_LIST_ITEMS {
        bail!("{label} list exceeds its item limit");
    }
    for value in values.iter() {
        validate_text(label, value)?;
    }
    values.sort();
    if !values.windows(2).all(|window| window[0] != window[1]) {
        bail!("{label} list contains duplicates");
    }
    Ok(())
}

fn validate_identity(label: &str, value: &str) -> Result<()> {
    validate_text(label, value)?;
    if !value
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.'))
    {
        bail!("{label} contains unsupported characters");
    }
    Ok(())
}

fn validate_text(label: &str, value: &str) -> Result<()> {
    if value.is_empty() || value.len() > MAX_STRING_BYTES || value.chars().any(char::is_control) {
        bail!("{label} is empty, oversized, or contains control characters");
    }
    Ok(())
}

fn digest_json(value: &impl Serialize) -> Result<String> {
    Ok(digest_bytes(&serde_json::to_vec(value)?))
}

fn digest_bytes(bytes: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(bytes);
    hex::encode(digest.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile() -> RustCargoProfile {
        RustCargoProfile {
            name: "dev".to_owned(),
            opt_level: "0".to_owned(),
            lto: "false".to_owned(),
            codegen_units: None,
            debuginfo: Some(2),
            split_debuginfo: None,
            debug_assertions: true,
            overflow_checks: true,
            rpath: false,
            incremental: false,
            panic: "unwind".to_owned(),
            strip: RustCargoStrip::Deferred("None".to_owned()),
            codegen_backend: None,
        }
    }

    fn graph_json(workspace: &Path) -> serde_json::Value {
        let package = format!(
            "path+file://{}#0.1.0",
            workspace.to_string_lossy().replace(' ', "%20")
        );
        serde_json::json!({
            "version": 1,
            "units": [{
                "pkg_id": package,
                "target": {
                    "kind": ["lib"],
                    "crate_types": ["lib"],
                    "name": "fixture",
                    "src_path": workspace.join("src/lib.rs"),
                    "edition": "2024",
                    "doc": true,
                    "doctest": true,
                    "test": true
                },
                "profile": profile(),
                "platform": null,
                "mode": "build",
                "features": [],
                "dependencies": []
            }],
            "roots": [0]
        })
    }

    #[test]
    fn neutral_config_rejects_execution_injection_and_is_deterministic() -> Result<()> {
        let first = tempfile::tempdir()?;
        let second = tempfile::tempdir()?;
        for root in [first.path(), second.path()] {
            fs::create_dir_all(root.join(".cargo"))?;
            fs::write(
                root.join(".cargo/config.toml"),
                "[build]\ntarget = \"x86_64-unknown-linux-gnu\"\nrustflags = [\"--cfg\", \"depgraph_fixture\"]\n",
            )?;
        }
        let first_config = project_neutral_cargo_config(first.path())?;
        let second_config = project_neutral_cargo_config(second.path())?;
        assert_eq!(first_config, second_config);
        assert!(first_config.rendered.contains("offline = true"));

        fs::write(
            first.path().join(".cargo/config.toml"),
            "[target.x86_64-unknown-linux-gnu]\nlinker = \"/tmp/armed\"\n",
        )?;
        let error = project_neutral_cargo_config(first.path()).unwrap_err();
        let message = error.to_string();
        assert!(message.contains("target.x86_64-unknown-linux-gnu.linker"));
        assert!(!message.contains("/tmp/armed"));
        Ok(())
    }

    #[test]
    fn neutral_config_rejects_all_executable_selectors_with_bounded_reasons() -> Result<()> {
        let cases = [
            ("[build]\nrustc = \"armed-value\"\n", "build.rustc"),
            (
                "[build]\nrustc-wrapper = \"armed-value\"\n",
                "build.rustc-wrapper",
            ),
            (
                "[build]\nrustc-workspace-wrapper = \"armed-value\"\n",
                "build.rustc-workspace-wrapper",
            ),
            (
                "[target.x86_64-unknown-linux-gnu]\nrunner = \"armed-value\"\n",
                "target.x86_64-unknown-linux-gnu.runner",
            ),
            (
                "[target.x86_64-unknown-linux-gnu]\nlinker = \"armed-value\"\n",
                "target.x86_64-unknown-linux-gnu.linker",
            ),
            ("[alias]\nbuild = \"armed-value\"\n", "alias"),
            (
                "[credential-alias]\narmed = [\"armed-value\"]\n",
                "credential-alias",
            ),
            ("[env]\nRUSTC = \"armed-value\"\n", "env"),
            (
                "[registries.private]\ncredential-provider = \"armed-value\"\n",
                "registries",
            ),
            (
                "[build]\nrustflags = [\"-Clinker=armed-value\"]\n",
                "build.rustflags",
            ),
            (
                "[build]\nrustflags = [\"-Clink-arg=@armed-value\"]\n",
                "build.rustflags",
            ),
        ];
        for (config, reason) in cases {
            let root = tempfile::tempdir()?;
            fs::create_dir(root.path().join(".cargo"))?;
            fs::write(root.path().join(".cargo/config.toml"), config)?;
            let error = project_neutral_cargo_config(root.path()).unwrap_err();
            let message = error.to_string();
            assert!(message.contains(reason), "{message}");
            assert!(!message.contains("armed-value"), "{message}");
            assert!(message.len() < 512, "{message}");
        }
        Ok(())
    }

    #[test]
    fn unit_graph_is_canonical_and_rejects_version_drift_and_escape() -> Result<()> {
        let first = tempfile::tempdir()?;
        let second = tempfile::tempdir()?;
        for root in [first.path(), second.path()] {
            fs::create_dir(root.join("src"))?;
            fs::write(root.join("src/lib.rs"), "pub fn fixture() {}")?;
        }
        let first_graph = validate_cargo_unit_graph(
            &serde_json::to_vec(&graph_json(first.path()))?,
            first.path(),
        )?;
        let second_graph = validate_cargo_unit_graph(
            &serde_json::to_vec(&graph_json(second.path()))?,
            second.path(),
        )?;
        assert_eq!(first_graph, second_graph);
        let schema: serde_json::Value = serde_json::from_str(COMPILER_PRECISE_UNIT_GRAPH_SCHEMA)?;
        let validator = jsonschema::validator_for(&schema)?;
        assert!(validator.is_valid(&serde_json::to_value(&first_graph)?));
        assert!(
            !serde_json::to_string(&first_graph)?
                .contains(&first.path().to_string_lossy().to_string())
        );

        let mut version_drift = graph_json(first.path());
        version_drift["version"] = serde_json::json!(2);
        assert!(
            validate_cargo_unit_graph(&serde_json::to_vec(&version_drift)?, first.path()).is_err()
        );

        let outside = tempfile::NamedTempFile::new()?;
        let mut escaped = graph_json(first.path());
        escaped["units"][0]["target"]["src_path"] =
            serde_json::json!(outside.path().to_string_lossy());
        let error =
            validate_cargo_unit_graph(&serde_json::to_vec(&escaped)?, first.path()).unwrap_err();
        assert!(error.to_string().contains("escapes the staged workspace"));
        Ok(())
    }

    #[test]
    fn unit_graph_rejects_malformed_indices_and_unreachable_units() -> Result<()> {
        let workspace = tempfile::tempdir()?;
        fs::create_dir(workspace.path().join("src"))?;
        fs::write(workspace.path().join("src/lib.rs"), "pub fn fixture() {}")?;
        let mut graph = graph_json(workspace.path());
        graph["units"][0]["dependencies"] = serde_json::json!([{
            "index": 1,
            "extern_crate_name": "missing",
            "public": false,
            "noprelude": false,
            "nounused": false
        }]);
        assert!(validate_cargo_unit_graph(&serde_json::to_vec(&graph)?, workspace.path()).is_err());

        let mut unreachable = graph_json(workspace.path());
        let duplicate = unreachable["units"][0].clone();
        unreachable["units"].as_array_mut().unwrap().push(duplicate);
        assert!(
            validate_cargo_unit_graph(&serde_json::to_vec(&unreachable)?, workspace.path())
                .is_err()
        );
        Ok(())
    }
}
