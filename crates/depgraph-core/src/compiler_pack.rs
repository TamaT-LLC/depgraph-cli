use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Component, Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use walkdir::WalkDir;

pub const COMPILER_PRECISE_CONTRACT_VERSION: &str = "compiler-precise-rust-v1";
pub const COMPILER_PACK_MANIFEST_SCHEMA_VERSION: &str = "depgraph-compiler-pack-manifest-v1";
pub const COMPILER_PACK_MANIFEST_PATH: &str = "compiler-pack-manifest.json";
pub const COMPILER_PACK_SBOM_PATH: &str = "compiler-pack.spdx.json";
pub const COMPILER_PACK_LICENSE_INVENTORY_PATH: &str = "compiler-pack-licenses.json";
pub const COMPILER_PACK_PROVENANCE_PATH: &str = "compiler-pack-provenance.json";
pub const COMPILER_PACK_MANIFEST_SCHEMA_PATH: &str =
    "schemas/depgraph-compiler-pack-v1.schema.json";
pub const COMPILER_PACK_MANIFEST_SCHEMA: &str =
    include_str!("../../../schemas/depgraph-compiler-pack-v1.schema.json");
pub const COMPILER_PACK_TOOLCHAIN_CHANNEL: &str = "nightly-2026-07-17";
pub const COMPILER_PACK_RUST_RELEASE: &str = "1.99.0-nightly";
pub const COMPILER_PACK_RUSTC_COMMIT: &str = "3d50c25bc66853bf0ad205529d0f305a1d841b5e";
pub const COMPILER_PACK_CHANNEL_MANIFEST: &str = "2026-07-17/channel-rust-nightly.toml";
pub const COMPILER_PACK_CHANNEL_MANIFEST_SHA256: &str =
    "e8598e1b6ab58a60209ba3ac8e5dd3a0f799719829dede0306b4daf1769b52c9";
pub const COMPILER_PACK_WRAPPER_PROTOCOL_VERSION: &str = "depgraph-rust-compiler-precise-v1";
pub const COMPILER_PACK_RELEASE_CONTRACT_VERSION: &str = "compiler-pack-five-target-release-v1";
pub const COMPILER_PACK_DISTRIBUTION: &str = "separate-target-specific-first-party-archive";
pub const COMPILER_PACK_FALLBACK_POLICY: &str = "unsupported-no-fallback";
pub const COMPILER_PACK_SUPPORTED_TARGETS: &[&str] = &[
    "x86_64-unknown-linux-gnu",
    "aarch64-unknown-linux-gnu",
    "x86_64-apple-darwin",
    "aarch64-apple-darwin",
    "x86_64-pc-windows-msvc",
];

pub fn compiler_pack_host_target() -> Option<&'static str> {
    match (std::env::consts::ARCH, std::env::consts::OS) {
        ("x86_64", "linux") if cfg!(target_env = "gnu") => Some("x86_64-unknown-linux-gnu"),
        ("aarch64", "linux") if cfg!(target_env = "gnu") => Some("aarch64-unknown-linux-gnu"),
        ("x86_64", "macos") => Some("x86_64-apple-darwin"),
        ("aarch64", "macos") => Some("aarch64-apple-darwin"),
        ("x86_64", "windows") if cfg!(target_env = "msvc") => Some("x86_64-pc-windows-msvc"),
        _ => None,
    }
}

const COMPILER_PACK_LICENSE_SCHEMA_VERSION: &str = "compiler-pack-license-inventory-v1";
const COMPILER_PACK_PROVENANCE_SCHEMA_VERSION: &str = "compiler-pack-provenance-v1";
const COMPILER_PACK_LICENSE_EXPRESSION: &str = "MIT OR Apache-2.0";
const COMPILER_PACK_LICENSE_PATHS: &[&str] = &["licenses/LICENSE-APACHE", "licenses/LICENSE-MIT"];
const MAX_COMPILER_PACK_FILES: usize = 250_000;
const MAX_COMPILER_PACK_DIRECTORIES: usize = 100_000;
const MAX_COMPILER_PACK_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const REQUIRED_COMPONENTS: &[&str] = &[
    "cargo",
    "llvm-tools",
    "rust-src",
    "rust-std",
    "rustc",
    "rustc-dev",
];

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CompilerPackRequirement {
    pub root: PathBuf,
    pub expected_manifest_sha256: String,
    pub release_checksum_reference: String,
    pub host: String,
    pub target: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompilerPackBuildSpec {
    pub host: String,
    pub target: String,
    pub release_checksum_reference: String,
    pub cargo_path: String,
    pub rustc_path: String,
    pub wrapper_path: String,
    pub query_path: String,
    pub wrapper_protocol_schema_path: String,
    pub components: Vec<CompilerPackBuildComponent>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompilerPackBuildComponent {
    pub name: String,
    pub archive_sha256: String,
    pub source: String,
    pub files: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CompilerPackManifest {
    pub schema_version: String,
    pub contract_version: String,
    pub toolchain: CompilerPackToolchain,
    pub host: String,
    pub target: String,
    pub cargo: CompilerPackArtifact,
    pub rustc: CompilerPackArtifact,
    pub wrapper: CompilerPackArtifact,
    pub query: CompilerPackArtifact,
    pub wrapper_protocol: CompilerPackProtocol,
    pub components: Vec<CompilerPackComponent>,
    pub sbom: CompilerPackArtifact,
    pub license_inventory: CompilerPackArtifact,
    pub source_provenance: CompilerPackArtifact,
    pub release_checksum_reference: String,
    pub closed_tree_sha256: String,
    pub directories: Vec<String>,
    pub files: Vec<CompilerPackFile>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CompilerPackToolchain {
    pub channel: String,
    pub rust_release: String,
    pub cargo_release: String,
    pub rustc_commit: String,
    pub channel_manifest: String,
    pub channel_manifest_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CompilerPackArtifact {
    pub path: String,
    pub sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CompilerPackProtocol {
    pub contract_version: String,
    pub schema: CompilerPackArtifact,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CompilerPackComponent {
    pub name: String,
    pub source: String,
    pub archive_sha256: String,
    pub tree_sha256: String,
    pub file_count: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CompilerPackFile {
    pub path: String,
    pub owner: String,
    pub sha256: String,
    pub size: u64,
    pub executable: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct CompilerPackAttestation {
    pub contract_version: String,
    pub host: String,
    pub target: String,
    pub manifest_sha256: String,
    pub closed_tree_sha256: String,
    pub cargo_sha256: String,
    pub rustc_sha256: String,
    pub wrapper_sha256: String,
    pub query_sha256: String,
}

#[derive(Clone, Debug)]
pub struct VerifiedCompilerPack {
    pub attestation: CompilerPackAttestation,
    pub root: PathBuf,
    pub cargo_path: PathBuf,
    pub rustc_path: PathBuf,
    pub wrapper_path: PathBuf,
    pub query_path: PathBuf,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct CompilerPackLicenseInventory {
    schema_version: String,
    entries: Vec<CompilerPackLicenseEntry>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct CompilerPackLicenseEntry {
    name: String,
    license_expression: String,
    license_files: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct CompilerPackProvenance {
    schema_version: String,
    channel: String,
    rust_release: String,
    cargo_release: String,
    rustc_commit: String,
    channel_manifest: String,
    channel_manifest_sha256: String,
    components: Vec<CompilerPackProvenanceComponent>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct CompilerPackProvenanceComponent {
    name: String,
    source: String,
    archive_sha256: String,
}

pub fn read_compiler_pack_build_spec(path: &Path) -> Result<CompilerPackBuildSpec> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("compiler pack build spec {} is unavailable", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > 1024 * 1024 {
        bail!("compiler pack build spec must be a regular file no larger than 1 MiB");
    }
    serde_json::from_slice(&fs::read(path)?).context("compiler pack build spec is invalid")
}

pub fn read_compiler_pack_requirement(path: &Path) -> Result<CompilerPackRequirement> {
    let metadata = fs::symlink_metadata(path).with_context(|| {
        format!(
            "compiler pack requirement {} is unavailable",
            path.display()
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > 1024 * 1024 {
        bail!("compiler pack requirement must be a regular file no larger than 1 MiB");
    }
    let mut requirement: CompilerPackRequirement =
        serde_json::from_slice(&fs::read(path)?).context("compiler pack requirement is invalid")?;
    if requirement.root.is_relative() {
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        requirement.root = parent.join(&requirement.root);
    }
    Ok(requirement)
}

pub fn build_compiler_pack(
    source_root: &Path,
    output_root: &Path,
    spec: &CompilerPackBuildSpec,
) -> Result<VerifiedCompilerPack> {
    validate_build_spec(spec)?;
    validate_new_output_root(output_root)?;
    let source_metadata =
        fs::symlink_metadata(source_root).context("compiler pack source root is unavailable")?;
    if source_metadata.file_type().is_symlink() || !source_metadata.is_dir() {
        bail!("compiler pack source root must be a real directory");
    }

    fs::create_dir_all(output_root)?;
    copy_source_tree(source_root, output_root)?;
    validate_required_payload(output_root, spec)?;

    let license_inventory = build_license_inventory();
    write_canonical_json(
        &output_root.join(COMPILER_PACK_LICENSE_INVENTORY_PATH),
        &license_inventory,
    )?;
    let provenance = build_provenance(spec);
    write_canonical_json(
        &output_root.join(COMPILER_PACK_PROVENANCE_PATH),
        &provenance,
    )?;
    let sbom = build_spdx_sbom(spec);
    write_canonical_json(&output_root.join(COMPILER_PACK_SBOM_PATH), &sbom)?;

    let component_owners = component_file_owners(spec)?;
    let (directories, mut files) = collect_pack_tree(output_root, &component_owners, spec)?;
    files.sort_by(|left, right| left.path.cmp(&right.path));
    let components = build_component_records(spec, &files)?;
    let closed_tree_sha256 = closed_tree_digest(&directories, &files);
    let file_by_path = files
        .iter()
        .map(|file| (file.path.as_str(), file))
        .collect::<BTreeMap<_, _>>();
    let artifact = |path: &str| -> Result<CompilerPackArtifact> {
        let file = file_by_path
            .get(path)
            .with_context(|| format!("compiler pack artifact {path} is not in the closed tree"))?;
        Ok(CompilerPackArtifact {
            path: path.to_owned(),
            sha256: file.sha256.clone(),
        })
    };
    let manifest = CompilerPackManifest {
        schema_version: COMPILER_PACK_MANIFEST_SCHEMA_VERSION.to_owned(),
        contract_version: COMPILER_PRECISE_CONTRACT_VERSION.to_owned(),
        toolchain: pinned_toolchain(),
        host: spec.host.clone(),
        target: spec.target.clone(),
        cargo: artifact(&spec.cargo_path)?,
        rustc: artifact(&spec.rustc_path)?,
        wrapper: artifact(&spec.wrapper_path)?,
        query: artifact(&spec.query_path)?,
        wrapper_protocol: CompilerPackProtocol {
            contract_version: COMPILER_PACK_WRAPPER_PROTOCOL_VERSION.to_owned(),
            schema: artifact(&spec.wrapper_protocol_schema_path)?,
        },
        components,
        sbom: artifact(COMPILER_PACK_SBOM_PATH)?,
        license_inventory: artifact(COMPILER_PACK_LICENSE_INVENTORY_PATH)?,
        source_provenance: artifact(COMPILER_PACK_PROVENANCE_PATH)?,
        release_checksum_reference: spec.release_checksum_reference.clone(),
        closed_tree_sha256,
        directories,
        files,
    };
    let manifest_path = output_root.join(COMPILER_PACK_MANIFEST_PATH);
    write_canonical_json(&manifest_path, &manifest)?;
    let manifest_sha256 = digest_file(&manifest_path)?;
    verify_compiler_pack(&CompilerPackRequirement {
        root: output_root.to_path_buf(),
        expected_manifest_sha256: manifest_sha256,
        release_checksum_reference: spec.release_checksum_reference.clone(),
        host: spec.host.clone(),
        target: spec.target.clone(),
    })
}

pub fn verify_compiler_pack(requirement: &CompilerPackRequirement) -> Result<VerifiedCompilerPack> {
    validate_sha256(
        "expected compiler pack manifest",
        &requirement.expected_manifest_sha256,
    )?;
    validate_identity("compiler pack host", &requirement.host)?;
    validate_identity("compiler pack target", &requirement.target)?;
    validate_checksum_reference(&requirement.release_checksum_reference)?;
    let root_metadata = fs::symlink_metadata(&requirement.root)
        .context("exact compiler pack is missing; install the target-specific first-party pack")?;
    if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
        bail!("compiler pack root must be a real directory");
    }
    let root = requirement
        .root
        .canonicalize()
        .context("compiler pack root is unavailable")?;
    let manifest_path = root.join(COMPILER_PACK_MANIFEST_PATH);
    let manifest_metadata =
        fs::symlink_metadata(&manifest_path).context("compiler pack manifest is missing")?;
    if manifest_metadata.file_type().is_symlink()
        || !manifest_metadata.is_file()
        || manifest_metadata.len() > 16 * 1024 * 1024
    {
        bail!("compiler pack manifest must be a bounded regular file");
    }
    let manifest_sha256 = digest_file(&manifest_path)?;
    if manifest_sha256 != requirement.expected_manifest_sha256 {
        bail!("compiler pack manifest does not match its release checksum reference");
    }
    let manifest: CompilerPackManifest = serde_json::from_slice(&fs::read(&manifest_path)?)
        .context("compiler pack manifest is invalid")?;
    validate_manifest_identity(&manifest, requirement)?;
    validate_manifest_order(&manifest)?;
    let (actual_directories, actual_files) = collect_verified_tree(&root, &manifest)?;
    if actual_directories != manifest.directories {
        bail!("compiler pack directory closure does not match the manifest");
    }
    if actual_files != manifest.files {
        bail!("compiler pack file closure does not match the manifest");
    }
    if closed_tree_digest(&manifest.directories, &manifest.files) != manifest.closed_tree_sha256 {
        bail!("compiler pack closed-tree digest does not match the manifest");
    }
    validate_components(&manifest)?;
    validate_manifest_artifacts(&manifest)?;
    validate_file_ownership(&manifest)?;
    validate_license_inventory(&root, &manifest)?;
    validate_provenance(&root, &manifest)?;
    validate_spdx_sbom(&root, &manifest)?;

    let cargo_path = resolve_artifact_path(&root, &manifest.cargo, true)?;
    let rustc_path = resolve_artifact_path(&root, &manifest.rustc, true)?;
    let wrapper_path = resolve_artifact_path(&root, &manifest.wrapper, true)?;
    let query_path = resolve_artifact_path(&root, &manifest.query, true)?;
    Ok(VerifiedCompilerPack {
        attestation: CompilerPackAttestation {
            contract_version: manifest.contract_version,
            host: manifest.host,
            target: manifest.target,
            manifest_sha256,
            closed_tree_sha256: manifest.closed_tree_sha256,
            cargo_sha256: manifest.cargo.sha256,
            rustc_sha256: manifest.rustc.sha256,
            wrapper_sha256: manifest.wrapper.sha256,
            query_sha256: manifest.query.sha256,
        },
        root,
        cargo_path,
        rustc_path,
        wrapper_path,
        query_path,
    })
}

fn validate_build_spec(spec: &CompilerPackBuildSpec) -> Result<()> {
    validate_identity("compiler pack host", &spec.host)?;
    validate_identity("compiler pack target", &spec.target)?;
    validate_checksum_reference(&spec.release_checksum_reference)?;
    for path in [
        &spec.cargo_path,
        &spec.rustc_path,
        &spec.wrapper_path,
        &spec.query_path,
        &spec.wrapper_protocol_schema_path,
    ] {
        validate_pack_path(path)?;
    }
    let components = spec
        .components
        .iter()
        .map(|component| component.name.as_str())
        .collect::<Vec<_>>();
    if components != REQUIRED_COMPONENTS {
        bail!("compiler pack build components must be sorted and contain the exact required set");
    }
    let mut all_files = BTreeSet::new();
    for component in &spec.components {
        validate_sha256(
            &format!("{} component archive", component.name),
            &component.archive_sha256,
        )?;
        if !component
            .source
            .starts_with("https://static.rust-lang.org/dist/2026-07-17/")
            || component.source.len() > 1024
            || component.source.chars().any(char::is_control)
        {
            bail!(
                "compiler pack component {} has an invalid pinned source",
                component.name
            );
        }
        if component.files.is_empty()
            || !component
                .files
                .windows(2)
                .all(|window| window[0] < window[1])
        {
            bail!(
                "compiler pack component {} files must be non-empty, sorted, and unique",
                component.name
            );
        }
        for path in &component.files {
            validate_pack_path(path)?;
            if !path.starts_with("toolchain/") {
                bail!(
                    "compiler pack component {} file {path} is outside toolchain/",
                    component.name
                );
            }
            if !all_files.insert(path) {
                bail!("compiler pack component file {path} has more than one owner");
            }
        }
    }
    if !all_files.contains(&spec.cargo_path) || !all_files.contains(&spec.rustc_path) {
        bail!("compiler pack cargo and rustc must belong to exact component inventories");
    }
    if all_files.contains(&spec.wrapper_path)
        || all_files.contains(&spec.query_path)
        || all_files.contains(&spec.wrapper_protocol_schema_path)
    {
        bail!(
            "compiler pack wrapper, query child, and protocol schema must not be component-owned"
        );
    }
    Ok(())
}

fn validate_new_output_root(output_root: &Path) -> Result<()> {
    match fs::symlink_metadata(output_root) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            bail!("compiler pack output must be a real directory")
        }
        Ok(_) => {
            if fs::read_dir(output_root)?.next().is_some() {
                bail!("compiler pack output directory must be empty");
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

fn copy_source_tree(source_root: &Path, output_root: &Path) -> Result<()> {
    let generated = [
        COMPILER_PACK_MANIFEST_PATH,
        COMPILER_PACK_SBOM_PATH,
        COMPILER_PACK_LICENSE_INVENTORY_PATH,
        COMPILER_PACK_PROVENANCE_PATH,
    ];
    for entry in WalkDir::new(source_root).follow_links(false).min_depth(1) {
        let entry = entry?;
        let relative = relative_pack_path(source_root, entry.path())?;
        validate_pack_path(&relative)?;
        if generated.contains(&relative.as_str()) {
            bail!("compiler pack source contains generated artifact {relative}");
        }
        if entry.file_type().is_symlink() {
            bail!("compiler pack source contains symlink {relative}");
        }
        let destination = output_root.join(Path::new(&relative));
        if entry.file_type().is_dir() {
            fs::create_dir_all(&destination)?;
        } else if entry.file_type().is_file() {
            if let Some(parent) = destination.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::copy(entry.path(), &destination)?;
            fs::set_permissions(&destination, entry.metadata()?.permissions())?;
        } else {
            bail!("compiler pack source contains non-regular entry {relative}");
        }
    }
    Ok(())
}

fn validate_required_payload(root: &Path, spec: &CompilerPackBuildSpec) -> Result<()> {
    for path in COMPILER_PACK_LICENSE_PATHS {
        require_regular_file(root, path, false)?;
    }
    require_regular_file(root, &spec.cargo_path, true)?;
    require_regular_file(root, &spec.rustc_path, true)?;
    require_regular_file(root, &spec.wrapper_path, true)?;
    require_regular_file(root, &spec.query_path, true)?;
    require_regular_file(root, &spec.wrapper_protocol_schema_path, false)?;
    for component in &spec.components {
        for path in &component.files {
            require_regular_file(root, path, false)?;
        }
    }
    Ok(())
}

fn require_regular_file(root: &Path, relative: &str, executable: bool) -> Result<()> {
    let path = root.join(Path::new(relative));
    let metadata = fs::symlink_metadata(&path)
        .with_context(|| format!("compiler pack required file {relative} is missing"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("compiler pack required file {relative} is not regular");
    }
    if executable && !is_executable(&metadata, relative) {
        bail!("compiler pack executable {relative} is not executable");
    }
    Ok(())
}

fn build_license_inventory() -> CompilerPackLicenseInventory {
    let names = REQUIRED_COMPONENTS
        .iter()
        .map(|name| format!("component:{name}"))
        .chain([
            "depgraph-compiler-wrapper".to_owned(),
            "depgraph-compiler-query".to_owned(),
            "depgraph-compiler-protocol".to_owned(),
        ])
        .collect::<Vec<_>>();
    CompilerPackLicenseInventory {
        schema_version: COMPILER_PACK_LICENSE_SCHEMA_VERSION.to_owned(),
        entries: names
            .into_iter()
            .map(|name| CompilerPackLicenseEntry {
                name,
                license_expression: COMPILER_PACK_LICENSE_EXPRESSION.to_owned(),
                license_files: COMPILER_PACK_LICENSE_PATHS
                    .iter()
                    .map(|path| (*path).to_owned())
                    .collect(),
            })
            .collect(),
    }
}

fn build_provenance(spec: &CompilerPackBuildSpec) -> CompilerPackProvenance {
    CompilerPackProvenance {
        schema_version: COMPILER_PACK_PROVENANCE_SCHEMA_VERSION.to_owned(),
        channel: COMPILER_PACK_TOOLCHAIN_CHANNEL.to_owned(),
        rust_release: COMPILER_PACK_RUST_RELEASE.to_owned(),
        cargo_release: COMPILER_PACK_RUST_RELEASE.to_owned(),
        rustc_commit: COMPILER_PACK_RUSTC_COMMIT.to_owned(),
        channel_manifest: COMPILER_PACK_CHANNEL_MANIFEST.to_owned(),
        channel_manifest_sha256: COMPILER_PACK_CHANNEL_MANIFEST_SHA256.to_owned(),
        components: spec
            .components
            .iter()
            .map(|component| CompilerPackProvenanceComponent {
                name: component.name.clone(),
                source: component.source.clone(),
                archive_sha256: component.archive_sha256.clone(),
            })
            .collect(),
    }
}

fn build_spdx_sbom(spec: &CompilerPackBuildSpec) -> Value {
    let mut packages = spec
        .components
        .iter()
        .map(|component| {
            json!({
                "SPDXID": format!("SPDXRef-Component-{}", component.name),
                "name": component.name,
                "versionInfo": COMPILER_PACK_RUST_RELEASE,
                "downloadLocation": component.source,
                "filesAnalyzed": false,
                "licenseDeclared": COMPILER_PACK_LICENSE_EXPRESSION,
                "checksums": [{
                    "algorithm": "SHA256",
                    "checksumValue": component.archive_sha256
                }]
            })
        })
        .collect::<Vec<_>>();
    packages.extend([
        json!({
            "SPDXID": "SPDXRef-Depgraph-Compiler-Wrapper",
            "name": "depgraph-compiler-wrapper",
            "versionInfo": env!("CARGO_PKG_VERSION"),
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": false,
            "licenseDeclared": COMPILER_PACK_LICENSE_EXPRESSION
        }),
        json!({
            "SPDXID": "SPDXRef-Depgraph-Compiler-Query",
            "name": "depgraph-compiler-query",
            "versionInfo": env!("CARGO_PKG_VERSION"),
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": false,
            "licenseDeclared": COMPILER_PACK_LICENSE_EXPRESSION
        }),
        json!({
            "SPDXID": "SPDXRef-Depgraph-Compiler-Protocol",
            "name": "depgraph-compiler-protocol",
            "versionInfo": COMPILER_PACK_WRAPPER_PROTOCOL_VERSION,
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": false,
            "licenseDeclared": COMPILER_PACK_LICENSE_EXPRESSION
        }),
    ]);
    json!({
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": format!("depgraph-compiler-pack-{}-{}", spec.host, spec.target),
        "documentNamespace": format!(
            "https://tamat.dev/depgraph/compiler-pack/{}/{}",
            spec.host, spec.target
        ),
        "creationInfo": {
            "created": "2026-07-17T00:00:00Z",
            "creators": ["Tool: depgraph-compiler-pack-builder-v1"]
        },
        "packages": packages
    })
}

fn component_file_owners(spec: &CompilerPackBuildSpec) -> Result<BTreeMap<String, String>> {
    let mut owners = BTreeMap::new();
    for component in &spec.components {
        for path in &component.files {
            if owners
                .insert(path.clone(), component.name.clone())
                .is_some()
            {
                bail!("compiler pack component file {path} has multiple owners");
            }
        }
    }
    Ok(owners)
}

fn collect_pack_tree(
    root: &Path,
    component_owners: &BTreeMap<String, String>,
    spec: &CompilerPackBuildSpec,
) -> Result<(Vec<String>, Vec<CompilerPackFile>)> {
    let mut directories = Vec::new();
    let mut files = Vec::new();
    let mut total_bytes = 0_u64;
    for entry in WalkDir::new(root).follow_links(false).min_depth(1) {
        let entry = entry?;
        let relative = relative_pack_path(root, entry.path())?;
        validate_pack_path(&relative)?;
        if entry.file_type().is_symlink() {
            bail!("compiler pack contains symlink {relative}");
        }
        if entry.file_type().is_dir() {
            directories.push(relative);
            continue;
        }
        if !entry.file_type().is_file() {
            bail!("compiler pack contains non-regular entry {relative}");
        }
        if relative == COMPILER_PACK_MANIFEST_PATH {
            continue;
        }
        let metadata = entry.metadata()?;
        total_bytes = total_bytes
            .checked_add(metadata.len())
            .context("compiler pack byte count overflowed")?;
        let owner = pack_file_owner(&relative, component_owners, spec)?;
        files.push(CompilerPackFile {
            path: relative.clone(),
            owner,
            sha256: digest_file(entry.path())?,
            size: metadata.len(),
            executable: is_executable(&metadata, &relative),
        });
    }
    directories.sort();
    if directories.len() > MAX_COMPILER_PACK_DIRECTORIES
        || files.len() > MAX_COMPILER_PACK_FILES
        || total_bytes > MAX_COMPILER_PACK_BYTES
    {
        bail!("compiler pack tree exceeds its count or byte limit");
    }
    Ok((directories, files))
}

fn pack_file_owner(
    path: &str,
    component_owners: &BTreeMap<String, String>,
    spec: &CompilerPackBuildSpec,
) -> Result<String> {
    if let Some(owner) = component_owners.get(path) {
        return Ok(owner.clone());
    }
    if path.starts_with("toolchain/") {
        bail!("compiler pack toolchain file {path} has no component owner");
    }
    if path == spec.wrapper_path {
        return Ok("depgraph-wrapper".to_owned());
    }
    if path == spec.query_path {
        return Ok("depgraph-query".to_owned());
    }
    if path == spec.wrapper_protocol_schema_path {
        return Ok("depgraph-protocol".to_owned());
    }
    if COMPILER_PACK_LICENSE_PATHS.contains(&path) {
        return Ok("depgraph-legal".to_owned());
    }
    if matches!(
        path,
        COMPILER_PACK_SBOM_PATH
            | COMPILER_PACK_LICENSE_INVENTORY_PATH
            | COMPILER_PACK_PROVENANCE_PATH
    ) {
        return Ok("depgraph-metadata".to_owned());
    }
    bail!("compiler pack contains undeclared file {path}")
}

fn build_component_records(
    spec: &CompilerPackBuildSpec,
    files: &[CompilerPackFile],
) -> Result<Vec<CompilerPackComponent>> {
    spec.components
        .iter()
        .map(|component| {
            let owned = files
                .iter()
                .filter(|file| file.owner == component.name)
                .collect::<Vec<_>>();
            if owned.len() != component.files.len() {
                bail!(
                    "compiler pack component {} file closure is incomplete",
                    component.name
                );
            }
            Ok(CompilerPackComponent {
                name: component.name.clone(),
                source: component.source.clone(),
                archive_sha256: component.archive_sha256.clone(),
                tree_sha256: component_tree_digest(&component.name, &owned),
                file_count: owned.len(),
            })
        })
        .collect()
}

fn validate_manifest_identity(
    manifest: &CompilerPackManifest,
    requirement: &CompilerPackRequirement,
) -> Result<()> {
    if manifest.schema_version != COMPILER_PACK_MANIFEST_SCHEMA_VERSION
        || manifest.contract_version != COMPILER_PRECISE_CONTRACT_VERSION
        || manifest.toolchain != pinned_toolchain()
    {
        bail!("compiler pack compatibility identity is unsupported");
    }
    if manifest.host != requirement.host || manifest.target != requirement.target {
        bail!(
            "compiler pack host/target mismatch: expected {}/{}, found {}/{}",
            requirement.host,
            requirement.target,
            manifest.host,
            manifest.target
        );
    }
    validate_checksum_reference(&manifest.release_checksum_reference)?;
    if manifest.release_checksum_reference != requirement.release_checksum_reference {
        bail!("compiler pack release checksum reference does not match the requested release");
    }
    if manifest.wrapper_protocol.contract_version != COMPILER_PACK_WRAPPER_PROTOCOL_VERSION {
        bail!("compiler pack wrapper protocol is unsupported");
    }
    Ok(())
}

fn validate_manifest_order(manifest: &CompilerPackManifest) -> Result<()> {
    if manifest.directories.len() > MAX_COMPILER_PACK_DIRECTORIES
        || manifest.files.len() > MAX_COMPILER_PACK_FILES
        || !manifest
            .directories
            .windows(2)
            .all(|window| window[0] < window[1])
        || !manifest
            .files
            .windows(2)
            .all(|window| window[0].path < window[1].path)
    {
        bail!("compiler pack manifest closure is not bounded, sorted, and unique");
    }
    for directory in &manifest.directories {
        validate_pack_path(directory)?;
    }
    let mut total_bytes = 0_u64;
    for file in &manifest.files {
        validate_pack_path(&file.path)?;
        validate_identity("compiler pack file owner", &file.owner)?;
        validate_sha256("compiler pack file", &file.sha256)?;
        total_bytes = total_bytes
            .checked_add(file.size)
            .context("compiler pack byte count overflowed")?;
    }
    if total_bytes > MAX_COMPILER_PACK_BYTES {
        bail!("compiler pack manifest exceeds its byte limit");
    }
    Ok(())
}

fn collect_verified_tree(
    root: &Path,
    manifest: &CompilerPackManifest,
) -> Result<(Vec<String>, Vec<CompilerPackFile>)> {
    let expected = manifest
        .files
        .iter()
        .map(|file| (file.path.as_str(), file))
        .collect::<BTreeMap<_, _>>();
    let mut directories = Vec::new();
    let mut files = Vec::new();
    for entry in WalkDir::new(root).follow_links(false).min_depth(1) {
        let entry = entry?;
        let relative = relative_pack_path(root, entry.path())?;
        validate_pack_path(&relative)?;
        if entry.file_type().is_symlink() {
            bail!("compiler pack contains symlink {relative}");
        }
        if entry.file_type().is_dir() {
            directories.push(relative);
            continue;
        }
        if !entry.file_type().is_file() {
            bail!("compiler pack contains non-regular entry {relative}");
        }
        if relative == COMPILER_PACK_MANIFEST_PATH {
            continue;
        }
        let declared = expected
            .get(relative.as_str())
            .with_context(|| format!("compiler pack contains additional file {relative}"))?;
        let metadata = entry.metadata()?;
        files.push(CompilerPackFile {
            path: relative.clone(),
            owner: declared.owner.clone(),
            sha256: digest_file(entry.path())?,
            size: metadata.len(),
            executable: is_executable(&metadata, &relative),
        });
    }
    directories.sort();
    files.sort_by(|left, right| left.path.cmp(&right.path));
    Ok((directories, files))
}

fn validate_components(manifest: &CompilerPackManifest) -> Result<()> {
    let names = manifest
        .components
        .iter()
        .map(|component| component.name.as_str())
        .collect::<Vec<_>>();
    if names != REQUIRED_COMPONENTS {
        bail!("compiler pack does not contain the exact required component set");
    }
    for component in &manifest.components {
        validate_sha256(
            &format!("{} component archive", component.name),
            &component.archive_sha256,
        )?;
        validate_sha256(
            &format!("{} component tree", component.name),
            &component.tree_sha256,
        )?;
        if !component
            .source
            .starts_with("https://static.rust-lang.org/dist/2026-07-17/")
        {
            bail!(
                "compiler pack component {} source is not pinned",
                component.name
            );
        }
        let owned = manifest
            .files
            .iter()
            .filter(|file| file.owner == component.name)
            .collect::<Vec<_>>();
        if owned.len() != component.file_count
            || owned.is_empty()
            || component_tree_digest(&component.name, &owned) != component.tree_sha256
        {
            bail!(
                "compiler pack component {} tree closure does not match",
                component.name
            );
        }
    }
    Ok(())
}

fn validate_manifest_artifacts(manifest: &CompilerPackManifest) -> Result<()> {
    let by_path = manifest
        .files
        .iter()
        .map(|file| (file.path.as_str(), file))
        .collect::<BTreeMap<_, _>>();
    for (name, artifact, executable, owner) in [
        ("cargo", &manifest.cargo, true, "cargo"),
        ("rustc", &manifest.rustc, true, "rustc"),
        ("wrapper", &manifest.wrapper, true, "depgraph-wrapper"),
        ("query child", &manifest.query, true, "depgraph-query"),
        (
            "wrapper protocol schema",
            &manifest.wrapper_protocol.schema,
            false,
            "depgraph-protocol",
        ),
        ("SPDX SBOM", &manifest.sbom, false, "depgraph-metadata"),
        (
            "license inventory",
            &manifest.license_inventory,
            false,
            "depgraph-metadata",
        ),
        (
            "source provenance",
            &manifest.source_provenance,
            false,
            "depgraph-metadata",
        ),
    ] {
        validate_pack_path(&artifact.path)?;
        validate_sha256(name, &artifact.sha256)?;
        let file = by_path
            .get(artifact.path.as_str())
            .with_context(|| format!("compiler pack {name} is absent from the closed tree"))?;
        if file.sha256 != artifact.sha256 || file.owner != owner || executable && !file.executable {
            bail!("compiler pack {name} does not match its closed-tree entry");
        }
    }
    Ok(())
}

fn validate_file_ownership(manifest: &CompilerPackManifest) -> Result<()> {
    let component_names = REQUIRED_COMPONENTS.iter().copied().collect::<BTreeSet<_>>();
    for file in &manifest.files {
        if component_names.contains(file.owner.as_str()) {
            if !file.path.starts_with("toolchain/") {
                bail!(
                    "compiler pack component-owned file {} is outside toolchain/",
                    file.path
                );
            }
            continue;
        }
        let valid = match file.owner.as_str() {
            "depgraph-wrapper" => file.path == manifest.wrapper.path,
            "depgraph-query" => file.path == manifest.query.path,
            "depgraph-protocol" => file.path == manifest.wrapper_protocol.schema.path,
            "depgraph-legal" => COMPILER_PACK_LICENSE_PATHS.contains(&file.path.as_str()),
            "depgraph-metadata" => matches!(
                file.path.as_str(),
                COMPILER_PACK_SBOM_PATH
                    | COMPILER_PACK_LICENSE_INVENTORY_PATH
                    | COMPILER_PACK_PROVENANCE_PATH
            ),
            _ => false,
        };
        if !valid {
            bail!(
                "compiler pack file {} has an undeclared owner or role",
                file.path
            );
        }
    }
    Ok(())
}

fn validate_license_inventory(root: &Path, manifest: &CompilerPackManifest) -> Result<()> {
    let inventory: CompilerPackLicenseInventory =
        read_artifact_json(root, &manifest.license_inventory, "license inventory")?;
    if inventory != build_license_inventory() {
        bail!("compiler pack license inventory is incomplete or incompatible");
    }
    let files = manifest
        .files
        .iter()
        .map(|file| (file.path.as_str(), file))
        .collect::<BTreeMap<_, _>>();
    for path in COMPILER_PACK_LICENSE_PATHS {
        if files.get(path).map(|file| file.owner.as_str()) != Some("depgraph-legal") {
            bail!("compiler pack legal file {path} is not closed by the manifest");
        }
    }
    Ok(())
}

fn validate_provenance(root: &Path, manifest: &CompilerPackManifest) -> Result<()> {
    let provenance: CompilerPackProvenance =
        read_artifact_json(root, &manifest.source_provenance, "source provenance")?;
    if provenance.schema_version != COMPILER_PACK_PROVENANCE_SCHEMA_VERSION
        || provenance.channel != COMPILER_PACK_TOOLCHAIN_CHANNEL
        || provenance.rust_release != COMPILER_PACK_RUST_RELEASE
        || provenance.cargo_release != COMPILER_PACK_RUST_RELEASE
        || provenance.rustc_commit != COMPILER_PACK_RUSTC_COMMIT
        || provenance.channel_manifest != COMPILER_PACK_CHANNEL_MANIFEST
        || provenance.channel_manifest_sha256 != COMPILER_PACK_CHANNEL_MANIFEST_SHA256
    {
        bail!("compiler pack source provenance has an incompatible toolchain identity");
    }
    let expected = manifest
        .components
        .iter()
        .map(|component| CompilerPackProvenanceComponent {
            name: component.name.clone(),
            source: component.source.clone(),
            archive_sha256: component.archive_sha256.clone(),
        })
        .collect::<Vec<_>>();
    if provenance.components != expected {
        bail!("compiler pack source provenance does not close every component archive");
    }
    Ok(())
}

fn validate_spdx_sbom(root: &Path, manifest: &CompilerPackManifest) -> Result<()> {
    let sbom: Value = read_artifact_json(root, &manifest.sbom, "SPDX SBOM")?;
    if sbom["spdxVersion"] != "SPDX-2.3"
        || sbom["dataLicense"] != "CC0-1.0"
        || sbom["SPDXID"] != "SPDXRef-DOCUMENT"
    {
        bail!("compiler pack SPDX SBOM identity is incompatible");
    }
    let packages = sbom["packages"]
        .as_array()
        .context("compiler pack SPDX SBOM has no packages")?;
    let expected_names = REQUIRED_COMPONENTS
        .iter()
        .map(|name| (*name).to_owned())
        .chain([
            "depgraph-compiler-wrapper".to_owned(),
            "depgraph-compiler-query".to_owned(),
            "depgraph-compiler-protocol".to_owned(),
        ])
        .collect::<BTreeSet<_>>();
    let actual_names = packages
        .iter()
        .map(|package| {
            let name = package["name"]
                .as_str()
                .context("compiler pack SPDX package has no name")?;
            if package["licenseDeclared"] != COMPILER_PACK_LICENSE_EXPRESSION
                || package["filesAnalyzed"] != false
            {
                bail!("compiler pack SPDX package {name} has an incompatible legal record");
            }
            Ok(name.to_owned())
        })
        .collect::<Result<BTreeSet<_>>>()?;
    if actual_names != expected_names || packages.len() != expected_names.len() {
        bail!("compiler pack SPDX SBOM package closure is incomplete");
    }
    for component in &manifest.components {
        let package = packages
            .iter()
            .find(|package| package["name"] == component.name)
            .context("compiler pack SPDX SBOM is missing a component")?;
        if package["versionInfo"] != COMPILER_PACK_RUST_RELEASE
            || package["downloadLocation"] != component.source
            || package["checksums"][0]["algorithm"] != "SHA256"
            || package["checksums"][0]["checksumValue"] != component.archive_sha256
        {
            bail!(
                "compiler pack SPDX component {} does not match provenance",
                component.name
            );
        }
    }
    Ok(())
}

fn read_artifact_json<T: for<'de> Deserialize<'de>>(
    root: &Path,
    artifact: &CompilerPackArtifact,
    name: &str,
) -> Result<T> {
    let path = resolve_artifact_path(root, artifact, false)?;
    serde_json::from_slice(&fs::read(path)?)
        .with_context(|| format!("compiler pack {name} is invalid"))
}

fn resolve_artifact_path(
    root: &Path,
    artifact: &CompilerPackArtifact,
    executable: bool,
) -> Result<PathBuf> {
    validate_pack_path(&artifact.path)?;
    let path = root.join(Path::new(&artifact.path));
    let metadata = fs::symlink_metadata(&path)
        .with_context(|| format!("compiler pack artifact {} is missing", artifact.path))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || executable && !is_executable(&metadata, &artifact.path)
        || digest_file(&path)? != artifact.sha256
    {
        bail!(
            "compiler pack artifact {} failed attestation",
            artifact.path
        );
    }
    let canonical = path.canonicalize()?;
    if !canonical.starts_with(root) {
        bail!("compiler pack artifact {} escapes the pack", artifact.path);
    }
    Ok(canonical)
}

fn pinned_toolchain() -> CompilerPackToolchain {
    CompilerPackToolchain {
        channel: COMPILER_PACK_TOOLCHAIN_CHANNEL.to_owned(),
        rust_release: COMPILER_PACK_RUST_RELEASE.to_owned(),
        cargo_release: COMPILER_PACK_RUST_RELEASE.to_owned(),
        rustc_commit: COMPILER_PACK_RUSTC_COMMIT.to_owned(),
        channel_manifest: COMPILER_PACK_CHANNEL_MANIFEST.to_owned(),
        channel_manifest_sha256: COMPILER_PACK_CHANNEL_MANIFEST_SHA256.to_owned(),
    }
}

fn component_tree_digest(name: &str, files: &[&CompilerPackFile]) -> String {
    let mut digest = Sha256::new();
    digest.update(b"depgraph-compiler-component-tree-v1\0");
    digest.update((name.len() as u64).to_be_bytes());
    digest.update(name.as_bytes());
    for file in files {
        digest_file_record(&mut digest, file);
    }
    hex::encode(digest.finalize())
}

fn closed_tree_digest(directories: &[String], files: &[CompilerPackFile]) -> String {
    let mut digest = Sha256::new();
    digest.update(b"depgraph-compiler-pack-tree-v1\0");
    for directory in directories {
        digest.update([b'd']);
        digest.update((directory.len() as u64).to_be_bytes());
        digest.update(directory.as_bytes());
    }
    for file in files {
        digest.update([b'f']);
        digest_file_record(&mut digest, file);
    }
    hex::encode(digest.finalize())
}

fn digest_file_record(digest: &mut Sha256, file: &CompilerPackFile) {
    for value in [&file.path, &file.owner, &file.sha256] {
        digest.update((value.len() as u64).to_be_bytes());
        digest.update(value.as_bytes());
    }
    digest.update(file.size.to_be_bytes());
    digest.update([u8::from(file.executable)]);
}

fn write_canonical_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    fs::write(path, bytes)?;
    Ok(())
}

fn validate_pack_path(path: &str) -> Result<()> {
    if path.is_empty()
        || path.len() > 1024
        || path.contains('\\')
        || path.chars().any(char::is_control)
        || Path::new(path).is_absolute()
        || Path::new(path)
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        bail!("compiler pack path {path:?} is not a normalized relative path");
    }
    Ok(())
}

fn validate_identity(name: &str, value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 256
        || value
            .chars()
            .any(|character| !(character.is_ascii_alphanumeric() || "._+-:".contains(character)))
    {
        bail!("{name} is invalid");
    }
    Ok(())
}

fn validate_checksum_reference(value: &str) -> Result<()> {
    if value.trim().is_empty()
        || value.len() > 512
        || value.chars().any(char::is_control)
        || !value.starts_with("release-checksums:")
    {
        bail!("compiler pack release checksum reference is invalid");
    }
    Ok(())
}

fn validate_sha256(name: &str, value: &str) -> Result<()> {
    if value.len() != 64
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
    {
        bail!("{name} must be a lowercase SHA-256 digest");
    }
    Ok(())
}

fn relative_pack_path(root: &Path, path: &Path) -> Result<String> {
    Ok(path
        .strip_prefix(root)?
        .to_string_lossy()
        .replace('\\', "/"))
}

fn digest_file(path: &Path) -> Result<String> {
    Ok(hex::encode(Sha256::digest(fs::read(path).with_context(
        || format!("failed to read {}", path.display()),
    )?)))
}

#[cfg(unix)]
fn is_executable(metadata: &fs::Metadata, _path: &str) -> bool {
    use std::os::unix::fs::PermissionsExt as _;
    metadata.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn is_executable(_metadata: &fs::Metadata, path: &str) -> bool {
    path.to_ascii_lowercase().ends_with(".exe")
        || path.to_ascii_lowercase().ends_with(".cmd")
        || path.to_ascii_lowercase().ends_with(".bat")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn release_host_target_is_in_the_published_matrix() {
        let target = compiler_pack_host_target().expect("CI uses a supported release host");
        assert!(COMPILER_PACK_SUPPORTED_TARGETS.contains(&target));
    }

    fn fixture_spec() -> CompilerPackBuildSpec {
        let component = |name: &str, files: Vec<String>| CompilerPackBuildComponent {
            name: name.to_owned(),
            archive_sha256: hex::encode(Sha256::digest(format!("archive:{name}"))),
            source: format!(
                "https://static.rust-lang.org/dist/2026-07-17/{name}-nightly-fixture.tar.xz"
            ),
            files,
        };
        CompilerPackBuildSpec {
            host: "x86_64-unknown-linux-gnu".to_owned(),
            target: "x86_64-unknown-linux-gnu".to_owned(),
            release_checksum_reference:
                "release-checksums:v0.5.0/compiler-pack-x86_64-unknown-linux-gnu".to_owned(),
            cargo_path: "toolchain/cargo/bin/cargo".to_owned(),
            rustc_path: "toolchain/rustc/bin/rustc".to_owned(),
            wrapper_path: "bin/depgraph-rustc-wrapper".to_owned(),
            query_path: "bin/depgraph-rustc-query".to_owned(),
            wrapper_protocol_schema_path: "schemas/depgraph-rust-compiler-precise-v1.schema.json"
                .to_owned(),
            components: vec![
                component("cargo", vec!["toolchain/cargo/bin/cargo".to_owned()]),
                component(
                    "llvm-tools",
                    vec!["toolchain/llvm-tools/bin/llvm-config".to_owned()],
                ),
                component(
                    "rust-src",
                    vec!["toolchain/rust-src/library/core/src/lib.rs".to_owned()],
                ),
                component(
                    "rust-std",
                    vec!["toolchain/rust-std/lib/libstd.rlib".to_owned()],
                ),
                component("rustc", vec!["toolchain/rustc/bin/rustc".to_owned()]),
                component(
                    "rustc-dev",
                    vec!["toolchain/rustc-dev/lib/librustc_driver.rlib".to_owned()],
                ),
            ],
        }
    }

    fn create_fixture_source(root: &Path, spec: &CompilerPackBuildSpec) -> Result<()> {
        for component in &spec.components {
            for path in &component.files {
                let path = root.join(path);
                fs::create_dir_all(path.parent().context("fixture file has no parent")?)?;
                fs::write(&path, format!("fixture:{}:{path:?}", component.name))?;
            }
        }
        for path in [
            &spec.wrapper_path,
            &spec.query_path,
            &spec.wrapper_protocol_schema_path,
            COMPILER_PACK_LICENSE_PATHS[0],
            COMPILER_PACK_LICENSE_PATHS[1],
        ] {
            let path = root.join(path);
            fs::create_dir_all(path.parent().context("fixture file has no parent")?)?;
            fs::write(&path, b"fixture")?;
        }
        for path in [
            &spec.cargo_path,
            &spec.rustc_path,
            &spec.wrapper_path,
            &spec.query_path,
        ] {
            make_executable(&root.join(path))?;
        }
        Ok(())
    }

    #[cfg(unix)]
    fn make_executable(path: &Path) -> Result<()> {
        use std::os::unix::fs::PermissionsExt as _;
        let mut permissions = fs::metadata(path)?.permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(path, permissions)?;
        Ok(())
    }

    #[cfg(not(unix))]
    fn make_executable(_path: &Path) -> Result<()> {
        Ok(())
    }

    fn built_fixture() -> Result<(tempfile::TempDir, CompilerPackRequirement)> {
        let temp = tempfile::tempdir()?;
        let source = temp.path().join("source");
        let pack = temp.path().join("pack");
        fs::create_dir(&source)?;
        let spec = fixture_spec();
        create_fixture_source(&source, &spec)?;
        let verified = build_compiler_pack(&source, &pack, &spec)?;
        let requirement = CompilerPackRequirement {
            root: pack,
            expected_manifest_sha256: verified.attestation.manifest_sha256,
            release_checksum_reference: spec.release_checksum_reference,
            host: spec.host,
            target: spec.target,
        };
        Ok((temp, requirement))
    }

    #[test]
    fn compiler_pack_digest_is_checkout_independent_and_schema_valid() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let source = temp.path().join("source");
        fs::create_dir(&source)?;
        let spec = fixture_spec();
        create_fixture_source(&source, &spec)?;
        let first = build_compiler_pack(&source, &temp.path().join("first"), &spec)?;
        let second = build_compiler_pack(&source, &temp.path().join("second"), &spec)?;
        assert_eq!(
            first.attestation.manifest_sha256,
            second.attestation.manifest_sha256
        );
        assert_eq!(
            first.attestation.closed_tree_sha256,
            second.attestation.closed_tree_sha256
        );
        let schema: Value = serde_json::from_str(COMPILER_PACK_MANIFEST_SCHEMA)?;
        let validator = jsonschema::validator_for(&schema)?;
        let manifest: Value =
            serde_json::from_slice(&fs::read(first.root.join(COMPILER_PACK_MANIFEST_PATH))?)?;
        assert!(validator.is_valid(&manifest));
        Ok(())
    }

    #[test]
    fn compiler_pack_rejects_missing_additional_modified_and_host_mismatch() -> Result<()> {
        let (_temp, requirement) = built_fixture()?;
        fs::remove_file(requirement.root.join(COMPILER_PACK_SBOM_PATH))?;
        assert!(verify_compiler_pack(&requirement).is_err());

        let (_temp, requirement) = built_fixture()?;
        fs::write(requirement.root.join("additional"), b"unsafe")?;
        assert!(verify_compiler_pack(&requirement).is_err());

        let (_temp, requirement) = built_fixture()?;
        fs::write(
            requirement.root.join(COMPILER_PACK_PROVENANCE_PATH),
            b"changed",
        )?;
        assert!(verify_compiler_pack(&requirement).is_err());

        let (_temp, requirement) = built_fixture()?;
        fs::write(requirement.root.join("licenses/LICENSE-MIT"), b"changed")?;
        assert!(verify_compiler_pack(&requirement).is_err());

        let (_temp, mut requirement) = built_fixture()?;
        requirement.host = "aarch64-unknown-linux-gnu".to_owned();
        assert!(verify_compiler_pack(&requirement).is_err());

        let (_temp, mut requirement) = built_fixture()?;
        requirement.release_checksum_reference =
            "release-checksums:v0.4.1/compiler-pack-x86_64-unknown-linux-gnu".to_owned();
        assert!(verify_compiler_pack(&requirement).is_err());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn compiler_pack_rejects_symlink_and_non_regular_entries() -> Result<()> {
        use std::os::unix::{fs::symlink, net::UnixListener};

        let (_temp, requirement) = built_fixture()?;
        symlink(
            requirement.root.join(COMPILER_PACK_SBOM_PATH),
            requirement.root.join("unsafe-link"),
        )?;
        assert!(verify_compiler_pack(&requirement).is_err());

        let (_temp, requirement) = built_fixture()?;
        let _socket = UnixListener::bind(requirement.root.join("unsafe-socket"))?;
        assert!(verify_compiler_pack(&requirement).is_err());
        Ok(())
    }
}
