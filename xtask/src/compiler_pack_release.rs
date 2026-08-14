use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsStr,
    fs, io,
    path::{Path, PathBuf},
    process::Command,
    time::Instant,
};

use anyhow::{Context, Result, bail};
use depgraph_core::{
    COMPILER_PACK_CHANNEL_MANIFEST_SHA256, COMPILER_PACK_MANIFEST_PATH,
    COMPILER_PACK_SUPPORTED_TARGETS, COMPILER_PACK_TOOLCHAIN_CHANNEL, CompilerPackAttestation,
    CompilerPackBuildComponent, CompilerPackBuildSpec, CompilerPackManifest,
    CompilerPackRequirement, CompilerPreciseReleaseCompatibilityHealth, build_compiler_pack,
    compiler_precise_release_compatibility_contract, verify_compiler_pack,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

use super::{
    PROJECT_LICENSES, VERSION, archive_entries, cargo_target_dir, create_tar_archive,
    create_zip_archive, executable_name_for_target, host_target, run, sha256_file,
    verify_release_tag,
};

pub(crate) const COMPILER_PACK_SMOKE_SCHEMA_VERSION: &str = "compiler-pack-target-smoke-v1";
pub(crate) const COMPILER_PACK_VERIFICATION_SCHEMA_VERSION: &str =
    "compiler-pack-five-target-verification-v1";
const COMPONENT_HANDSHAKE_SCHEMA_VERSION: &str = "depgraph-compiler-component-handshake-v1";
const MAX_ARCHIVE_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const MAX_UNPACKED_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const MAX_PACK_FILES: usize = 250_000;
const MAX_PACK_DIRECTORIES: usize = 100_000;
const MAX_LINUX_MACOS_SEMANTIC_MILLIS: u64 = 10 * 60 * 1_000;
const MAX_WINDOWS_SEMANTIC_MILLIS: u64 = 15 * 60 * 1_000;

const COMPONENTS: &[ComponentDefinition] = &[
    ComponentDefinition {
        name: "cargo",
        package: "cargo",
        manifest_prefix: "manifest-cargo-",
        target_independent: false,
    },
    ComponentDefinition {
        name: "llvm-tools",
        package: "llvm-tools-preview",
        manifest_prefix: "manifest-llvm-tools-preview-",
        target_independent: false,
    },
    ComponentDefinition {
        name: "rust-src",
        package: "rust-src",
        manifest_prefix: "manifest-rust-src",
        target_independent: true,
    },
    ComponentDefinition {
        name: "rust-std",
        package: "rust-std",
        manifest_prefix: "manifest-rust-std-",
        target_independent: false,
    },
    ComponentDefinition {
        name: "rustc",
        package: "rustc",
        manifest_prefix: "manifest-rustc-",
        target_independent: false,
    },
    ComponentDefinition {
        name: "rustc-dev",
        package: "rustc-dev",
        manifest_prefix: "manifest-rustc-dev-",
        target_independent: false,
    },
];

struct ComponentDefinition {
    name: &'static str,
    package: &'static str,
    manifest_prefix: &'static str,
    target_independent: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct ComponentHandshake {
    pub(crate) schema_version: String,
    pub(crate) component: String,
    pub(crate) version: String,
    pub(crate) compiler_contract_version: String,
    pub(crate) wrapper_protocol_version: String,
    pub(crate) mir_schema_version: String,
    pub(crate) rustc_commit: String,
    pub(crate) query_capabilities: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct CompilerPackSemanticReport {
    pub(crate) checkout_a_export_sha256: String,
    pub(crate) checkout_b_export_sha256: String,
    pub(crate) cross_checkout_semantic_sha256: String,
    pub(crate) canonical_graph_sha256: String,
    pub(crate) node_kinds: BTreeMap<String, u64>,
    pub(crate) edge_kinds: BTreeMap<String, u64>,
    pub(crate) typed_mir_body_count: u64,
    pub(crate) compiler_instance_count: u64,
    pub(crate) compiler_call_count: u64,
    pub(crate) mir_constant_count: u64,
    pub(crate) query_capabilities: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct CompilerPackResourceReport {
    pub(crate) archive_bytes: u64,
    pub(crate) unpacked_bytes: u64,
    pub(crate) file_count: usize,
    pub(crate) semantic_elapsed_millis: u64,
    pub(crate) admitted: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct CompilerPackRollbackReport {
    pub(crate) tamper_rejected: bool,
    pub(crate) missing_pack_rejected: bool,
    pub(crate) unsupported_target_rejected: bool,
    pub(crate) no_fallback_observed: bool,
    pub(crate) completed_graph_preserved: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct CompilerPackTargetSmokeReport {
    pub(crate) schema_version: String,
    pub(crate) release_version: String,
    pub(crate) target: String,
    pub(crate) archive_sha256: String,
    pub(crate) compatibility: CompilerPreciseReleaseCompatibilityHealth,
    pub(crate) handshakes: BTreeMap<String, ComponentHandshake>,
    pub(crate) semantic: CompilerPackSemanticReport,
    pub(crate) resources: CompilerPackResourceReport,
    pub(crate) rollback: CompilerPackRollbackReport,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct CompilerPackTargetVerification {
    pub(crate) target: String,
    pub(crate) archive: String,
    pub(crate) archive_sha256: String,
    pub(crate) requirement_sha256: String,
    pub(crate) attestation: CompilerPackAttestation,
    pub(crate) component_tree_sha256: BTreeMap<String, String>,
    pub(crate) smoke_sha256: String,
    pub(crate) handshakes: BTreeMap<String, ComponentHandshake>,
    pub(crate) semantic: CompilerPackSemanticReport,
    pub(crate) resources: CompilerPackResourceReport,
    pub(crate) rollback: CompilerPackRollbackReport,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct CompilerPackVerificationReport {
    pub(crate) schema_version: String,
    pub(crate) release_version: String,
    pub(crate) compatibility: CompilerPreciseReleaseCompatibilityHealth,
    pub(crate) targets: Vec<CompilerPackTargetVerification>,
}

struct SemanticRun {
    report: CompilerPackSemanticReport,
    rollback: CompilerPackRollbackReport,
    elapsed_millis: u64,
}

pub(crate) fn package(
    channel_manifest_path: &Path,
    output_directory: &Path,
    requested_target: Option<&str>,
) -> Result<()> {
    verify_release_tag()?;
    let host = host_target()?;
    let target = requested_target
        .map(str::to_owned)
        .or_else(|| std::env::var("DEPGRAPH_TARGET").ok())
        .unwrap_or_else(|| host.clone());
    if target != host {
        bail!("compiler pack target {target} does not match native host {host}");
    }
    if !COMPILER_PACK_SUPPORTED_TARGETS.contains(&target.as_str()) {
        bail!(
            "compiler pack target {target} is unsupported; supported targets: {}",
            COMPILER_PACK_SUPPORTED_TARGETS.join(", ")
        );
    }
    validate_channel_manifest(channel_manifest_path)?;
    let channel: toml::Value = toml::from_str(&fs::read_to_string(channel_manifest_path)?)
        .context("pinned Rust channel manifest is invalid")?;

    build_release_binaries()?;
    let sysroot = pinned_sysroot()?;
    let name = format!("depgraph-compiler-pack-{VERSION}-{target}");
    fs::create_dir_all(output_directory)?;
    let staging = output_directory.join(&name);
    clear_exact_directory(&staging, output_directory)?;

    let verified = {
        let source = TempDir::new()?;
        let spec = stage_pack_source(source.path(), &sysroot, &channel, &host, &target)?;
        build_compiler_pack(source.path(), &staging, &spec)?
    };
    let handshakes = verify_component_handshakes(&verified)?;
    let extension = archive_extension(&target)?;
    let archive = output_directory.join(format!("{name}.{extension}"));
    let entries = archive_entries(&staging, &name)?;
    if extension == "zip" {
        create_zip_archive(&archive, &entries)?;
    } else {
        create_tar_archive(&archive, &entries)?;
    }
    let archive_sha256 = sha256_file(&archive)?;
    let archive_name = archive
        .file_name()
        .context("compiler pack archive has no file name")?
        .to_string_lossy();
    fs::write(
        output_directory.join(format!("{archive_name}.sha256")),
        format!("{archive_sha256}  {archive_name}\n"),
    )?;

    let requirement = CompilerPackRequirement {
        root: PathBuf::from(&name),
        expected_manifest_sha256: verified.attestation.manifest_sha256.clone(),
        release_checksum_reference: checksum_reference(&target),
        host: host.clone(),
        target: target.clone(),
    };
    let requirement_path = output_directory.join(format!("{name}.requirement.json"));
    write_pretty_json(&requirement_path, &requirement)?;

    let semantic_start = Instant::now();
    let extracted = TempDir::new()?;
    extract_compiler_pack_archive(&archive, extracted.path())?;
    let extracted_root = extracted.path().join(&name);
    let extracted_requirement = CompilerPackRequirement {
        root: extracted_root.clone(),
        ..requirement.clone()
    };
    let extracted_verified = verify_compiler_pack(&extracted_requirement)?;
    let extracted_handshakes = verify_component_handshakes(&extracted_verified)?;
    if handshakes != extracted_handshakes {
        bail!("compiler pack component handshakes changed after archive extraction");
    }
    let semantic =
        run_semantic_fixture(&extracted_verified, &extracted_requirement, semantic_start)?;
    let manifest: CompilerPackManifest =
        serde_json::from_slice(&fs::read(extracted_root.join(COMPILER_PACK_MANIFEST_PATH))?)?;
    let unpacked_bytes = manifest.files.iter().map(|file| file.size).sum();
    let semantic_millis_budget = semantic_millis_budget(&target)?;
    let resources = CompilerPackResourceReport {
        archive_bytes: fs::metadata(&archive)?.len(),
        unpacked_bytes,
        file_count: manifest.files.len(),
        semantic_elapsed_millis: semantic.elapsed_millis,
        admitted: fs::metadata(&archive)?.len() <= MAX_ARCHIVE_BYTES
            && unpacked_bytes <= MAX_UNPACKED_BYTES
            && manifest.files.len() <= MAX_PACK_FILES
            && semantic.elapsed_millis <= semantic_millis_budget,
    };
    if !resources.admitted {
        bail!(
            "compiler pack resource budget was exceeded for {target}: archive_bytes={} (max {MAX_ARCHIVE_BYTES}), unpacked_bytes={} (max {MAX_UNPACKED_BYTES}), file_count={} (max {MAX_PACK_FILES}), semantic_elapsed_millis={} (max {semantic_millis_budget})",
            resources.archive_bytes,
            resources.unpacked_bytes,
            resources.file_count,
            resources.semantic_elapsed_millis,
        );
    }
    let smoke = CompilerPackTargetSmokeReport {
        schema_version: COMPILER_PACK_SMOKE_SCHEMA_VERSION.to_owned(),
        release_version: VERSION.to_owned(),
        target: target.clone(),
        archive_sha256,
        compatibility: compiler_precise_release_compatibility_contract(),
        handshakes,
        semantic: semantic.report,
        resources,
        rollback: semantic.rollback,
    };
    validate_smoke(&smoke, &target, &smoke.archive_sha256)?;
    write_pretty_json(&output_directory.join(format!("{name}.smoke.json")), &smoke)?;
    fs::remove_dir_all(&staging).with_context(|| {
        format!(
            "failed to remove compiler pack staging {}",
            staging.display()
        )
    })?;
    println!("packaged compiler pack {target}: {}", archive.display());
    Ok(())
}

pub(crate) fn verify_assets(
    directory: &Path,
    requested_targets: &[String],
) -> Result<CompilerPackVerificationReport> {
    if !directory.is_dir()
        || fs::symlink_metadata(directory).is_ok_and(|metadata| metadata.file_type().is_symlink())
    {
        bail!(
            "compiler pack asset directory is missing or symlinked: {}",
            directory.display()
        );
    }
    let selected = selected_targets(requested_targets)?;
    let expected = selected
        .iter()
        .flat_map(|target| {
            let name = format!("depgraph-compiler-pack-{VERSION}-{target}");
            let archive = format!(
                "{name}.{}",
                archive_extension(target).expect("known target")
            );
            [
                archive.clone(),
                format!("{archive}.sha256"),
                format!("{name}.requirement.json"),
                format!("{name}.smoke.json"),
            ]
        })
        .collect::<BTreeSet<_>>();
    let actual = fs::read_dir(directory)?
        .map(|entry| {
            let entry = entry?;
            if !entry.file_type()?.is_file() {
                bail!(
                    "compiler pack asset directory contains non-file entry {}",
                    entry.path().display()
                );
            }
            Ok(entry.file_name().to_string_lossy().into_owned())
        })
        .collect::<Result<BTreeSet<_>>>()?;
    let mut permitted = expected.clone();
    permitted.insert("compiler-pack-verification.json".to_owned());
    if !expected.is_subset(&actual) || !actual.is_subset(&permitted) {
        bail!(
            "compiler pack asset set differs from its target contract: expected {expected:?}, found {actual:?}"
        );
    }

    let compatibility = compiler_precise_release_compatibility_contract();
    let mut targets = Vec::new();
    for target in &selected {
        let name = format!("depgraph-compiler-pack-{VERSION}-{target}");
        let archive_name = format!("{name}.{}", archive_extension(target)?);
        let archive = directory.join(&archive_name);
        let archive_sha256 =
            verify_checksum_sidecar(&archive, &directory.join(format!("{archive_name}.sha256")))?;
        let requirement_path = directory.join(format!("{name}.requirement.json"));
        let requirement_bytes = fs::read(&requirement_path)?;
        let published_requirement: CompilerPackRequirement =
            serde_json::from_slice(&requirement_bytes)
                .context("compiler pack requirement has an invalid schema")?;
        if published_requirement.root != Path::new(&name)
            || published_requirement.host != *target
            || published_requirement.target != *target
            || published_requirement.release_checksum_reference != checksum_reference(target)
        {
            bail!("compiler pack requirement is incompatible for {target}");
        }
        let smoke_path = directory.join(format!("{name}.smoke.json"));
        let smoke_bytes = fs::read(&smoke_path)?;
        let smoke: CompilerPackTargetSmokeReport = serde_json::from_slice(&smoke_bytes)
            .context("compiler pack smoke report has an invalid schema")?;
        validate_smoke(&smoke, target, &archive_sha256)?;

        let extracted = TempDir::new()?;
        extract_compiler_pack_archive(&archive, extracted.path())?;
        let top_level = fs::read_dir(extracted.path())?
            .map(|entry| Ok(entry?.file_name().to_string_lossy().into_owned()))
            .collect::<Result<BTreeSet<_>>>()?;
        if top_level != BTreeSet::from([name.clone()]) {
            bail!("compiler pack archive {archive_name} has an invalid top-level closure");
        }
        let requirement = CompilerPackRequirement {
            root: extracted.path().join(&name),
            ..published_requirement
        };
        let verified = verify_compiler_pack(&requirement)?;
        let manifest: CompilerPackManifest = serde_json::from_slice(&fs::read(
            requirement.root.join(COMPILER_PACK_MANIFEST_PATH),
        )?)?;
        if manifest.toolchain.channel != compatibility.toolchain_channel
            || manifest.toolchain.rust_release != compatibility.rust_release
            || manifest.toolchain.rustc_commit != compatibility.rustc_commit
            || manifest.toolchain.channel_manifest != compatibility.channel_manifest
            || manifest.toolchain.channel_manifest_sha256 != compatibility.channel_manifest_sha256
            || manifest.schema_version != compatibility.manifest_schema_version
            || manifest.contract_version != compatibility.compiler_contract_version
            || manifest.wrapper_protocol.contract_version != compatibility.wrapper_protocol_version
        {
            bail!("compiler pack compatibility identity drifted for {target}");
        }
        targets.push(CompilerPackTargetVerification {
            target: target.clone(),
            archive: archive_name,
            archive_sha256,
            requirement_sha256: digest_bytes(&requirement_bytes),
            attestation: verified.attestation,
            component_tree_sha256: manifest
                .components
                .iter()
                .map(|component| (component.name.clone(), component.tree_sha256.clone()))
                .collect(),
            smoke_sha256: digest_bytes(&smoke_bytes),
            handshakes: smoke.handshakes,
            semantic: smoke.semantic,
            resources: smoke.resources,
            rollback: smoke.rollback,
        });
    }
    validate_aggregate_targets(&targets, &selected)?;
    let report = CompilerPackVerificationReport {
        schema_version: COMPILER_PACK_VERIFICATION_SCHEMA_VERSION.to_owned(),
        release_version: VERSION.to_owned(),
        compatibility,
        targets,
    };
    write_pretty_json(&directory.join("compiler-pack-verification.json"), &report)?;
    println!(
        "verified {} compiler pack targets in {}",
        selected.len(),
        directory.display()
    );
    Ok(report)
}

pub(crate) fn validate_verification_report(report: &CompilerPackVerificationReport) -> Result<()> {
    let targets = COMPILER_PACK_SUPPORTED_TARGETS
        .iter()
        .map(|target| (*target).to_owned())
        .collect::<Vec<_>>();
    if report.schema_version != COMPILER_PACK_VERIFICATION_SCHEMA_VERSION
        || report.release_version != VERSION
        || report.compatibility != compiler_precise_release_compatibility_contract()
    {
        bail!("compiler pack aggregate report has an incompatible contract");
    }
    validate_aggregate_targets(&report.targets, &targets)
}

fn validate_aggregate_targets(
    targets: &[CompilerPackTargetVerification],
    expected_targets: &[String],
) -> Result<()> {
    if targets.len() != expected_targets.len()
        || targets
            .iter()
            .map(|target| target.target.as_str())
            .ne(expected_targets.iter().map(String::as_str))
    {
        bail!("compiler pack aggregate target matrix is incomplete or out of order");
    }
    let compatibility = compiler_precise_release_compatibility_contract();
    let expected_handshakes = ["wrapper", "query"].into_iter().collect::<BTreeSet<_>>();
    for target in targets {
        if !COMPILER_PACK_SUPPORTED_TARGETS.contains(&target.target.as_str())
            || !lowercase_sha256(&target.archive_sha256)
            || !lowercase_sha256(&target.requirement_sha256)
            || !lowercase_sha256(&target.smoke_sha256)
            || target
                .handshakes
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>()
                != expected_handshakes
            || !target.resources.admitted
            || !target.rollback.tamper_rejected
            || !target.rollback.missing_pack_rejected
            || !target.rollback.unsupported_target_rejected
            || !target.rollback.no_fallback_observed
            || !target.rollback.completed_graph_preserved
            || !lowercase_sha256(&target.semantic.checkout_a_export_sha256)
            || !lowercase_sha256(&target.semantic.checkout_b_export_sha256)
            || !lowercase_sha256(&target.semantic.cross_checkout_semantic_sha256)
            || !lowercase_sha256(&target.semantic.canonical_graph_sha256)
            || target.semantic.typed_mir_body_count == 0
            || target.semantic.compiler_instance_count == 0
            || target.semantic.compiler_call_count == 0
            || target.semantic.mir_constant_count == 0
            || target.semantic.query_capabilities != compatibility.query_capabilities
        {
            bail!(
                "compiler pack target evidence is incomplete for {}",
                target.target
            );
        }
        for (component, handshake) in &target.handshakes {
            validate_handshake(handshake, component, &compatibility)?;
        }
    }
    if targets.len() > 1
        && targets
            .iter()
            .map(|target| {
                (
                    target.semantic.canonical_graph_sha256.as_str(),
                    &target.semantic.node_kinds,
                    &target.semantic.edge_kinds,
                    target.semantic.typed_mir_body_count,
                    target.semantic.compiler_instance_count,
                    target.semantic.compiler_call_count,
                    target.semantic.mir_constant_count,
                    &target.semantic.query_capabilities,
                )
            })
            .collect::<BTreeSet<_>>()
            .len()
            != 1
    {
        bail!("compiler pack targets do not produce the same canonical semantic graph");
    }
    Ok(())
}

fn validate_smoke(
    smoke: &CompilerPackTargetSmokeReport,
    target: &str,
    archive_sha256: &str,
) -> Result<()> {
    let semantic_millis_budget = semantic_millis_budget(target)?;
    if smoke.schema_version != COMPILER_PACK_SMOKE_SCHEMA_VERSION
        || smoke.release_version != VERSION
        || smoke.target != target
        || smoke.archive_sha256 != archive_sha256
        || smoke.compatibility != compiler_precise_release_compatibility_contract()
        || !lowercase_sha256(&smoke.archive_sha256)
        || !smoke.resources.admitted
        || smoke.resources.archive_bytes > MAX_ARCHIVE_BYTES
        || smoke.resources.unpacked_bytes > MAX_UNPACKED_BYTES
        || smoke.resources.file_count > MAX_PACK_FILES
        || smoke.resources.semantic_elapsed_millis > semantic_millis_budget
    {
        bail!("compiler pack smoke report is incompatible for {target}");
    }
    let verification = CompilerPackTargetVerification {
        target: target.to_owned(),
        archive: String::new(),
        archive_sha256: smoke.archive_sha256.clone(),
        requirement_sha256: "0".repeat(64),
        attestation: CompilerPackAttestation {
            contract_version: smoke.compatibility.compiler_contract_version.clone(),
            host: target.to_owned(),
            target: target.to_owned(),
            manifest_sha256: "0".repeat(64),
            closed_tree_sha256: "0".repeat(64),
            cargo_sha256: "0".repeat(64),
            rustc_sha256: "0".repeat(64),
            wrapper_sha256: "0".repeat(64),
            query_sha256: "0".repeat(64),
        },
        component_tree_sha256: BTreeMap::new(),
        smoke_sha256: "0".repeat(64),
        handshakes: smoke.handshakes.clone(),
        semantic: smoke.semantic.clone(),
        resources: smoke.resources.clone(),
        rollback: smoke.rollback.clone(),
    };
    validate_aggregate_targets(&[verification], &[target.to_owned()])
}

fn semantic_millis_budget(target: &str) -> Result<u64> {
    if target == "x86_64-pc-windows-msvc" {
        return Ok(MAX_WINDOWS_SEMANTIC_MILLIS);
    }
    if COMPILER_PACK_SUPPORTED_TARGETS.contains(&target) {
        return Ok(MAX_LINUX_MACOS_SEMANTIC_MILLIS);
    }
    bail!("compiler pack semantic budget target {target} is unsupported")
}

fn validate_handshake(
    handshake: &ComponentHandshake,
    expected_component: &str,
    compatibility: &CompilerPreciseReleaseCompatibilityHealth,
) -> Result<()> {
    if handshake.schema_version != COMPONENT_HANDSHAKE_SCHEMA_VERSION
        || handshake.component != expected_component
        || handshake.version != VERSION
        || handshake.compiler_contract_version != compatibility.compiler_contract_version
        || handshake.wrapper_protocol_version != compatibility.wrapper_protocol_version
        || handshake.mir_schema_version != compatibility.mir_schema_version
        || handshake.rustc_commit != compatibility.rustc_commit
        || handshake.query_capabilities != compatibility.query_capabilities
    {
        bail!("compiler pack {expected_component} handshake is incompatible");
    }
    Ok(())
}

fn validate_channel_manifest(path: &Path) -> Result<()> {
    let metadata =
        fs::symlink_metadata(path).context("pinned Rust channel manifest is unavailable")?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > 16 * 1024 * 1024
        || sha256_file(path)? != COMPILER_PACK_CHANNEL_MANIFEST_SHA256
    {
        bail!(
            "pinned Rust channel manifest must be the exact {} digest",
            COMPILER_PACK_CHANNEL_MANIFEST_SHA256
        );
    }
    Ok(())
}

fn build_release_binaries() -> Result<()> {
    run(Command::new("rustup").args([
        "run",
        COMPILER_PACK_TOOLCHAIN_CHANNEL,
        "cargo",
        "build",
        "--release",
        "--locked",
        "-p",
        "depgraph-rustc-wrapper",
    ]))?;
    run(Command::new("rustup").args([
        "run",
        COMPILER_PACK_TOOLCHAIN_CHANNEL,
        "cargo",
        "build",
        "--manifest-path",
        "crates/depgraph-rustc-query/Cargo.toml",
        "--target-dir",
        "target/compiler-query",
        "--release",
        "--locked",
    ]))?;
    run(Command::new("cargo").args([
        "build",
        "--release",
        "--locked",
        "-p",
        "depgraph-cli",
        "-p",
        "depgraph-rust-worker",
    ]))
}

fn pinned_sysroot() -> Result<PathBuf> {
    let output = Command::new("rustup")
        .args([
            "run",
            COMPILER_PACK_TOOLCHAIN_CHANNEL,
            "rustc",
            "--print",
            "sysroot",
        ])
        .output()?;
    if !output.status.success() {
        bail!("pinned compiler sysroot probe failed");
    }
    let sysroot = PathBuf::from(String::from_utf8(output.stdout)?.trim())
        .canonicalize()
        .context("pinned compiler sysroot is unavailable")?;
    if !sysroot.is_dir() {
        bail!("pinned compiler sysroot is not a directory");
    }
    Ok(sysroot)
}

fn stage_pack_source(
    source: &Path,
    sysroot: &Path,
    channel: &toml::Value,
    host: &str,
    target: &str,
) -> Result<CompilerPackBuildSpec> {
    let mut components = Vec::new();
    let mut owned = BTreeSet::new();
    for definition in COMPONENTS {
        let manifest_name = if definition.target_independent {
            definition.manifest_prefix.to_owned()
        } else {
            format!("{}{host}", definition.manifest_prefix)
        };
        let inventory_path = sysroot.join("lib/rustlib").join(&manifest_name);
        let relative_files = rustup_component_inventory(&inventory_path)?;
        let mut files = Vec::new();
        for relative in relative_files {
            let pack_path = format!("toolchain/{relative}");
            if !owned.insert(pack_path.clone()) {
                bail!("pinned Rust components overlap at {pack_path}");
            }
            copy_regular_file(
                &sysroot.join(&relative),
                &source.join(Path::new(&pack_path)),
            )?;
            files.push(pack_path);
        }
        let archive_target = if definition.target_independent {
            "*"
        } else {
            target
        };
        let (archive_source, archive_sha256) =
            channel_component(channel, definition.package, archive_target)?;
        components.push(CompilerPackBuildComponent {
            name: definition.name.to_owned(),
            archive_sha256,
            source: archive_source,
            files,
        });
    }
    for (name, bytes) in PROJECT_LICENSES {
        let destination = source.join("licenses").join(name);
        fs::create_dir_all(destination.parent().unwrap())?;
        fs::write(destination, bytes)?;
    }
    let wrapper_name = executable_name_for_target("depgraph-rustc-wrapper", target);
    let query_name = executable_name_for_target("depgraph-rustc-query", target);
    copy_regular_file(
        &cargo_target_dir().join("release").join(&wrapper_name),
        &source.join("bin").join(&wrapper_name),
    )?;
    copy_regular_file(
        &Path::new("target/compiler-query/release").join(&query_name),
        &source.join("bin").join(&query_name),
    )?;
    copy_regular_file(
        Path::new("schemas/depgraph-rust-compiler-precise-v1.schema.json"),
        &source.join("schemas/depgraph-rust-compiler-precise-v1.schema.json"),
    )?;
    Ok(CompilerPackBuildSpec {
        host: host.to_owned(),
        target: target.to_owned(),
        release_checksum_reference: checksum_reference(target),
        cargo_path: format!(
            "toolchain/bin/{}",
            executable_name_for_target("cargo", target)
        ),
        rustc_path: format!(
            "toolchain/bin/{}",
            executable_name_for_target("rustc", target)
        ),
        wrapper_path: format!("bin/{wrapper_name}"),
        query_path: format!("bin/{query_name}"),
        wrapper_protocol_schema_path: "schemas/depgraph-rust-compiler-precise-v1.schema.json"
            .to_owned(),
        components,
    })
}

fn rustup_component_inventory(path: &Path) -> Result<Vec<String>> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("rustup component manifest {} is missing", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > 16 * 1024 * 1024
    {
        bail!("rustup component manifest {} is invalid", path.display());
    }
    let mut files = fs::read_to_string(path)?
        .lines()
        .filter_map(|line| line.strip_prefix("file:").map(str::to_owned))
        .collect::<Vec<_>>();
    files.sort();
    files.dedup();
    if files.is_empty()
        || files.iter().any(|path| {
            Path::new(path).is_absolute()
                || path.contains('\\')
                || path
                    .split('/')
                    .any(|component| component.is_empty() || component == "." || component == "..")
        })
    {
        bail!(
            "rustup component manifest {} has unsafe paths",
            path.display()
        );
    }
    Ok(files)
}

fn channel_component(
    channel: &toml::Value,
    package: &str,
    target: &str,
) -> Result<(String, String)> {
    let entry = channel
        .get("pkg")
        .and_then(|value| value.get(package))
        .and_then(|value| value.get("target"))
        .and_then(|value| value.get(target))
        .with_context(|| format!("channel manifest omits {package}/{target}"))?;
    if entry.get("available").and_then(toml::Value::as_bool) != Some(true) {
        bail!("channel manifest marks {package}/{target} unavailable");
    }
    let source = entry
        .get("xz_url")
        .and_then(toml::Value::as_str)
        .context("channel component xz_url is missing")?
        .to_owned();
    let digest = entry
        .get("xz_hash")
        .and_then(toml::Value::as_str)
        .context("channel component xz_hash is missing")?
        .to_owned();
    if !source.starts_with("https://static.rust-lang.org/dist/2026-07-17/")
        || !lowercase_sha256(&digest)
    {
        bail!("channel component {package}/{target} is not pinned");
    }
    Ok((source, digest))
}

fn verify_component_handshakes(
    pack: &depgraph_core::VerifiedCompilerPack,
) -> Result<BTreeMap<String, ComponentHandshake>> {
    let compatibility = compiler_precise_release_compatibility_contract();
    let mut handshakes = BTreeMap::new();
    for (component, executable) in [("wrapper", &pack.wrapper_path), ("query", &pack.query_path)] {
        let mut command = Command::new(executable);
        command.arg("--depgraph-handshake");
        let library_paths = [
            pack.root.join("toolchain/lib"),
            pack.root
                .join("toolchain/lib/rustlib")
                .join(&pack.attestation.host)
                .join("lib"),
        ];
        let joined = std::env::join_paths(&library_paths)?;
        command
            .env("LD_LIBRARY_PATH", &joined)
            .env("DYLD_LIBRARY_PATH", &joined);
        if cfg!(windows) {
            let mut paths = library_paths.to_vec();
            paths.push(pack.root.join("toolchain/bin"));
            command.env("PATH", std::env::join_paths(paths)?);
        }
        let output = command
            .output()
            .with_context(|| format!("failed to execute compiler pack {component} handshake"))?;
        if !output.status.success() || !output.stderr.is_empty() {
            bail!(
                "compiler pack {component} handshake failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        let handshake: ComponentHandshake = serde_json::from_slice(&output.stdout)
            .with_context(|| format!("compiler pack {component} handshake is invalid"))?;
        validate_handshake(&handshake, component, &compatibility)?;
        handshakes.insert(component.to_owned(), handshake);
    }
    Ok(handshakes)
}

fn run_semantic_fixture(
    pack: &depgraph_core::VerifiedCompilerPack,
    requirement: &CompilerPackRequirement,
    started: Instant,
) -> Result<SemanticRun> {
    let temp = TempDir::new()?;
    let repository = temp.path().join("repository");
    seed_semantic_repository(&repository)?;
    let checkout_a = temp.path().join("checkout-a");
    let checkout_b = temp.path().join("checkout-b");
    git(
        &repository,
        [
            "clone",
            "--local",
            "--no-hardlinks",
            ".",
            checkout_a.to_str().unwrap(),
        ],
    )?;
    git(
        &repository,
        [
            "clone",
            "--local",
            "--no-hardlinks",
            ".",
            checkout_b.to_str().unwrap(),
        ],
    )?;
    let requirement_path = temp.path().join("compiler-pack-requirement.json");
    write_pretty_json(&requirement_path, requirement)?;
    let cli = cargo_target_dir()
        .join("release")
        .join(executable_name_for_target("depgraph", &host_target()?));
    let first = run_compiler_precise_checkout(
        &cli,
        &checkout_a,
        &temp.path().join("checkout-a.db"),
        &requirement_path,
        &temp.path().join("checkout-a-export.json"),
    )?;
    verify_compiler_precise_warm_cache(
        &cli,
        &checkout_a,
        &temp.path().join("checkout-a.db"),
        &requirement_path,
        &first.1,
        &temp.path().join("checkout-a-warm-export.json"),
    )?;
    let second = run_compiler_precise_checkout(
        &cli,
        &checkout_b,
        &temp.path().join("checkout-b.db"),
        &requirement_path,
        &temp.path().join("checkout-b-export.json"),
    )?;
    let mut semantic = semantic_report(&first.1, &first.0)?;
    let second_semantic = semantic_report(&second.1, &second.0)?;
    if semantic.cross_checkout_semantic_sha256 != second_semantic.cross_checkout_semantic_sha256 {
        bail!("compiler pack semantic graph is not stable across equivalent checkouts");
    }
    semantic.checkout_b_export_sha256 = digest_bytes(&second.0);
    run_out_dir_build_script_fixture(&cli, requirement, temp.path())?;
    run_empty_build_script_fixture(&cli, requirement, temp.path())?;
    verify_failing_build_script_fixture(&cli, requirement, temp.path())?;
    let before = first.0.clone();
    let store = temp.path().join("checkout-a.db");
    let export_after = temp.path().join("rollback-export.json");

    let missing_requirement = CompilerPackRequirement {
        root: temp.path().join("missing-pack"),
        ..requirement.clone()
    };
    let missing_path = temp.path().join("missing-requirement.json");
    write_pretty_json(&missing_path, &missing_requirement)?;
    let missing = failed_resolve(&cli, &checkout_a, &store, &missing_path)?;

    let unsupported_requirement = CompilerPackRequirement {
        target: "unsupported-unknown-target".to_owned(),
        ..requirement.clone()
    };
    let unsupported_path = temp.path().join("unsupported-requirement.json");
    write_pretty_json(&unsupported_path, &unsupported_requirement)?;
    let unsupported = failed_resolve(&cli, &checkout_a, &store, &unsupported_path)?;

    let mut query = fs::read(&pack.query_path)?;
    if query.is_empty() {
        bail!("compiler query is empty");
    }
    query[0] ^= 0xff;
    fs::write(&pack.query_path, query)?;
    let tamper = failed_resolve(&cli, &checkout_a, &store, &requirement_path)?;
    export_graph(&cli, &store, &export_after)?;
    let after = fs::read(&export_after)?;
    let no_fallback = [&missing, &unsupported, &tamper]
        .iter()
        .all(|output| output.contains("unsupported") && output.contains("fallback"));
    Ok(SemanticRun {
        report: semantic,
        rollback: CompilerPackRollbackReport {
            tamper_rejected: !tamper.is_empty(),
            missing_pack_rejected: !missing.is_empty(),
            unsupported_target_rejected: !unsupported.is_empty(),
            no_fallback_observed: no_fallback,
            completed_graph_preserved: before == after,
        },
        elapsed_millis: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
    })
}

fn seed_semantic_repository(root: &Path) -> Result<()> {
    fs::create_dir_all(root.join("src"))?;
    fs::write(
        root.join("Cargo.toml"),
        "[package]\nname='compiler-pack-release-fixture'\nversion='0.1.0'\nedition='2024'\n",
    )?;
    fs::write(
        root.join("Cargo.lock"),
        "version = 4\n\n[[package]]\nname = \"compiler-pack-release-fixture\"\nversion = \"0.1.0\"\n",
    )?;
    fs::write(
        root.join("src/lib.rs"),
        r#"pub static PROMOTED: &[u64] = &[3, 5, 8];

pub trait Evaluate {
    fn evaluate(&self, value: u64) -> u64;
}

pub struct Doubler;

impl Evaluate for Doubler {
    fn evaluate(&self, value: u64) -> u64 {
        value * 2
    }
}

pub fn generic_call<T: Evaluate>(value: &T, input: u64) -> u64 {
    value.evaluate(input) + PROMOTED[0]
}

pub fn release_entry(input: u64) -> u64 {
    generic_call(&Doubler, input)
}
"#,
    )?;
    git(root, ["init", "--initial-branch=main"])?;
    git(root, ["config", "user.name", "depgraph release gate"])?;
    git(
        root,
        ["config", "user.email", "release-gate@example.invalid"],
    )?;
    git(root, ["add", "."])?;
    let mut commit = Command::new("git");
    commit
        .arg("-C")
        .arg(root)
        .args(["commit", "-m", "compiler pack release fixture"])
        .env("GIT_AUTHOR_DATE", "2026-07-17T00:00:00Z")
        .env("GIT_COMMITTER_DATE", "2026-07-17T00:00:00Z");
    run(&mut commit)
}

fn run_out_dir_build_script_fixture(
    cli: &Path,
    requirement: &CompilerPackRequirement,
    temporary_root: &Path,
) -> Result<()> {
    let checkout = temporary_root.join("out-dir-build-script");
    seed_build_script_fixture(
        &checkout,
        r#"fn main() {
    let output = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
    std::fs::write(output.join("generated.rs"), "pub const GENERATED_BIAS: u64 = 13;\n")
        .unwrap();
}
"#,
        r#"include!(concat!(env!("OUT_DIR"), "/generated.rs"));

pub fn generated_fixture(input: u64) -> u64 {
    input + GENERATED_BIAS
}
"#,
    )?;
    let requirement_path = temporary_root.join("out-dir-build-script-requirement.json");
    write_pretty_json(&requirement_path, requirement)?;
    let store = temporary_root.join("out-dir-build-script.db");
    let (_, export) = run_compiler_precise_checkout(
        cli,
        &checkout,
        &store,
        &requirement_path,
        &temporary_root.join("out-dir-build-script-export.json"),
    )?;
    verify_build_script_units(&export)?;
    let warm = verify_compiler_precise_warm_cache(
        cli,
        &checkout,
        &store,
        &requirement_path,
        &export,
        &temporary_root.join("out-dir-build-script-warm-export.json"),
    )?;
    verify_build_script_units(&warm)?;
    verify_query_surfaces(cli, &store, &warm)
}

fn run_empty_build_script_fixture(
    cli: &Path,
    requirement: &CompilerPackRequirement,
    temporary_root: &Path,
) -> Result<()> {
    let checkout = temporary_root.join("empty-build-script");
    seed_build_script_fixture(&checkout, "fn main() {}\n", "pub fn empty_fixture() {}\n")?;
    let requirement_path = temporary_root.join("empty-build-script-requirement.json");
    write_pretty_json(&requirement_path, requirement)?;
    let (_, export) = run_compiler_precise_checkout(
        cli,
        &checkout,
        &temporary_root.join("empty-build-script.db"),
        &requirement_path,
        &temporary_root.join("empty-build-script-export.json"),
    )?;
    verify_build_script_units(&export)
}

fn verify_failing_build_script_fixture(
    cli: &Path,
    requirement: &CompilerPackRequirement,
    temporary_root: &Path,
) -> Result<()> {
    let checkout = temporary_root.join("failing-build-script");
    seed_build_script_fixture(
        &checkout,
        r#"fn main() {
    eprintln!("DEPGRAPH_BUILD_SCRIPT_SECRET_MUST_NOT_ESCAPE");
    std::process::exit(23);
}
"#,
        "pub fn failing_fixture() {}\n",
    )?;
    let requirement_path = temporary_root.join("failing-build-script-requirement.json");
    write_pretty_json(&requirement_path, requirement)?;
    let store = temporary_root.join("failing-build-script.db");
    run_cli(
        cli,
        [
            OsStr::new("--store"),
            store.as_os_str(),
            OsStr::new("scan"),
            checkout.as_os_str(),
            OsStr::new("--no-cache"),
        ],
    )?;
    let before_path = temporary_root.join("failing-build-script-before.json");
    export_graph(cli, &store, &before_path)?;
    let before = fs::read(&before_path)?;
    let failure = failed_resolve(cli, &checkout, &store, &requirement_path)?;
    if !failure.contains("rust-compiler-build-script-failed")
        || !failure.contains("kind=custom-build, mode=run-custom-build")
        || failure.contains("DEPGRAPH_BUILD_SCRIPT_SECRET_MUST_NOT_ESCAPE")
    {
        bail!("compiler-precise build-script failure diagnostic is not actionable and redacted");
    }
    let after_path = temporary_root.join("failing-build-script-after.json");
    export_graph(cli, &store, &after_path)?;
    if before != fs::read(after_path)? {
        bail!("failed compiler-precise build script promoted a partial graph");
    }
    Ok(())
}

fn seed_build_script_fixture(root: &Path, build_script: &str, library: &str) -> Result<()> {
    fs::create_dir_all(root.join("src"))?;
    fs::write(
        root.join("Cargo.toml"),
        "[package]\nname='compiler-build-script-fixture'\nversion='0.1.0'\nedition='2024'\nbuild='build.rs'\n",
    )?;
    fs::write(
        root.join("Cargo.lock"),
        "version = 4\n\n[[package]]\nname = \"compiler-build-script-fixture\"\nversion = \"0.1.0\"\n",
    )?;
    fs::write(root.join("build.rs"), build_script)?;
    fs::write(root.join("src/lib.rs"), library)?;
    Ok(())
}

fn run_compiler_precise_checkout(
    cli: &Path,
    checkout: &Path,
    store: &Path,
    requirement: &Path,
    export: &Path,
) -> Result<(Vec<u8>, Value)> {
    run_cli(
        cli,
        [
            OsStr::new("--store"),
            store.as_os_str(),
            OsStr::new("scan"),
            checkout.as_os_str(),
            OsStr::new("--no-cache"),
        ],
    )?;
    let cold = run_compiler_precise_resolve(cli, checkout, store, requirement)?;
    if !cold.contains("project code executed: true")
        || !cold.contains("build cache lookup: miss (not-found)")
        || !cold.contains("build cache: stored")
    {
        bail!("compiler-precise cold run did not store a validated cache entry: {cold}");
    }
    export_graph(cli, store, export)?;
    let bytes = fs::read(export)?;
    let value = serde_json::from_slice(&bytes)?;
    Ok((bytes, value))
}

fn verify_compiler_precise_warm_cache(
    cli: &Path,
    checkout: &Path,
    store: &Path,
    requirement: &Path,
    cold_export: &Value,
    warm_export_path: &Path,
) -> Result<Value> {
    let warm = run_compiler_precise_resolve(cli, checkout, store, requirement)?;
    if !warm.contains("project code executed: false")
        || !warm.contains("build cache lookup: hit (validated)")
        || !warm.contains("build cache: hit")
    {
        bail!("compiler-precise warm run did not reuse validated evidence: {warm}");
    }
    export_graph(cli, store, warm_export_path)?;
    let warm_export: Value = serde_json::from_slice(&fs::read(warm_export_path)?)?;
    let mut normalized_cold = cold_export.clone();
    let mut normalized_warm = warm_export.clone();
    remove_execution_provenance(&mut normalized_cold);
    remove_execution_provenance(&mut normalized_warm);
    if normalized_cold != normalized_warm {
        bail!("compiler-precise cold and warm exports differ outside execution provenance");
    }
    Ok(warm_export)
}

fn run_compiler_precise_resolve(
    cli: &Path,
    checkout: &Path,
    store: &Path,
    requirement: &Path,
) -> Result<String> {
    let output = Command::new(cli)
        .args([
            OsStr::new("--store"),
            store.as_os_str(),
            OsStr::new("resolve"),
            OsStr::new("--build"),
            checkout.as_os_str(),
            OsStr::new("--allow-project-code"),
            OsStr::new("--rust-compiler-precise"),
            OsStr::new("--compiler-pack-requirement"),
            requirement.as_os_str(),
        ])
        .env("CARGO_NET_OFFLINE", "true")
        .output()?;
    let rendered = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    if !output.status.success() {
        bail!(
            "{} compiler-precise resolve failed: {rendered}",
            cli.display()
        );
    }
    Ok(rendered)
}

fn remove_execution_provenance(value: &mut Value) {
    match value {
        Value::Object(object) => {
            for key in [
                "build_run_id",
                "run_id",
                "source_attempt_id",
                "build_attempt_id",
                "created_at",
                "started_at",
                "finished_at",
                "duration_millis",
            ] {
                object.remove(key);
            }
            for child in object.values_mut() {
                remove_execution_provenance(child);
            }
        }
        Value::Array(values) => {
            for child in values {
                remove_execution_provenance(child);
            }
        }
        _ => {}
    }
}

fn verify_build_script_units(export: &Value) -> Result<()> {
    let nodes = export["graph"]["nodes"]
        .as_array()
        .context("compiler pack export graph nodes are unavailable")?;
    let find_unit = |mode: &str| {
        nodes.iter().find(|node| {
            node["kind"] == "rust_compiler_unit"
                && node["properties"]["mode"] == mode
                && node["properties"]["cargo_target"]["kind"]
                    .as_array()
                    .is_some_and(|kinds| kinds.iter().any(|kind| kind == "custom-build"))
        })
    };
    let compiler = find_unit("build")
        .context("compiler pack export omits the build-script compiler Cargo unit")?;
    find_unit("run-custom-build")
        .context("compiler pack export omits the build-script execution Cargo unit")?;
    let mir_digest = compiler["properties"]["mir_unit_digest"]
        .as_str()
        .context("build-script compiler Cargo unit omits typed MIR evidence")?;
    if mir_digest.len() != 64 || !mir_digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("build-script compiler Cargo unit has an invalid typed MIR digest");
    }
    if !nodes
        .iter()
        .any(|node| node["kind"] == "rust_compiler_instance")
    {
        bail!("compiler pack export omits compiler instances for the build-script fixture");
    }
    let edges = export["graph"]["edges"]
        .as_array()
        .context("compiler pack export graph edges are unavailable")?;
    if !edges.iter().any(|edge| edge["kind"] == "calls") {
        bail!("compiler pack export omits compiler call evidence for the build-script fixture");
    }
    Ok(())
}

fn verify_query_surfaces(cli: &Path, store: &Path, export: &Value) -> Result<()> {
    let nodes = export["graph"]["nodes"]
        .as_array()
        .context("compiler pack export graph nodes are unavailable")?;
    let root = nodes
        .iter()
        .find(|node| node["kind"] == "rust_compiler_unit" && node["properties"]["is_root"] == true)
        .and_then(|node| node["id"].as_str())
        .context("compiler pack export omits a root Cargo unit")?;
    let build_script = nodes
        .iter()
        .find(|node| {
            node["kind"] == "rust_compiler_unit"
                && node["properties"]["mode"] == "build"
                && node["properties"]["cargo_target"]["kind"]
                    .as_array()
                    .is_some_and(|kinds| kinds.iter().any(|kind| kind == "custom-build"))
        })
        .and_then(|node| node["id"].as_str())
        .context("compiler pack export omits the build-script compiler unit")?;
    for arguments in [
        vec![
            OsStr::new("--store"),
            store.as_os_str(),
            OsStr::new("doctor"),
            OsStr::new("--details"),
        ],
        vec![
            OsStr::new("--store"),
            store.as_os_str(),
            OsStr::new("deps"),
            OsStr::new(root),
            OsStr::new("--json"),
            OsStr::new("--all"),
        ],
        vec![
            OsStr::new("--store"),
            store.as_os_str(),
            OsStr::new("why"),
            OsStr::new(root),
            OsStr::new(build_script),
            OsStr::new("--json"),
        ],
    ] {
        run_cli(cli, arguments)?;
    }
    Ok(())
}

fn failed_resolve(cli: &Path, checkout: &Path, store: &Path, requirement: &Path) -> Result<String> {
    let output = Command::new(cli)
        .args([
            OsStr::new("--store"),
            store.as_os_str(),
            OsStr::new("resolve"),
            OsStr::new("--build"),
            checkout.as_os_str(),
            OsStr::new("--allow-project-code"),
            OsStr::new("--rust-compiler-precise"),
            OsStr::new("--compiler-pack-requirement"),
            requirement.as_os_str(),
        ])
        .env("CARGO_NET_OFFLINE", "true")
        .output()?;
    if output.status.success() {
        bail!("compiler-precise failure fixture unexpectedly succeeded");
    }
    Ok(format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    ))
}

fn export_graph(cli: &Path, store: &Path, export: &Path) -> Result<()> {
    let repository_root = export
        .parent()
        .context("compiler-pack export path has no repository root")?;
    let output_argument = export
        .strip_prefix(repository_root)
        .context("compiler-pack export path is outside the repository root")?;
    let mut command = command_in_directory(cli, repository_root)?;
    let output = command
        .args([
            OsStr::new("--store"),
            store.as_os_str(),
            OsStr::new("export"),
            OsStr::new("--format"),
            OsStr::new("json"),
            OsStr::new("--output"),
            output_argument.as_os_str(),
        ])
        .env("CARGO_NET_OFFLINE", "true")
        .output()?;
    if !output.status.success() {
        bail!(
            "{} failed: {}{}",
            cli.display(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

fn command_in_directory(executable: &Path, directory: &Path) -> Result<Command> {
    // `cargo_target_dir()` is normally relative to the xtask launch directory.
    // Resolve it before changing cwd so repository-relative output arguments do
    // not also make the executable path repository-relative.
    let executable = executable.canonicalize().with_context(|| {
        format!(
            "failed to resolve executable {} before changing directory to {}",
            executable.display(),
            directory.display()
        )
    })?;
    let mut command = Command::new(executable);
    command.current_dir(directory);
    Ok(command)
}

fn run_cli<'a>(cli: &Path, arguments: impl IntoIterator<Item = &'a OsStr>) -> Result<()> {
    let output = Command::new(cli)
        .args(arguments)
        .env("CARGO_NET_OFFLINE", "true")
        .output()?;
    if !output.status.success() {
        bail!(
            "{} failed: {}{}",
            cli.display(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

fn semantic_report(export: &Value, bytes: &[u8]) -> Result<CompilerPackSemanticReport> {
    let graph = export
        .get("graph")
        .context("compiler pack export omits graph")?;
    let profile = graph["profiles"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|profile| {
            profile["properties"]["compiler_precise_contract"]
                == compiler_precise_release_compatibility_contract().compiler_contract_version
        })
        .context("compiler pack export omits compiler-precise profile")?;
    let count = |name: &str| {
        profile["properties"][name]
            .as_u64()
            .with_context(|| format!("compiler-precise profile omits {name}"))
    };
    let query_capabilities = profile["properties"]["query_capabilities"]
        .as_array()
        .context("compiler-precise profile omits query capabilities")?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .context("compiler-precise query capability is not text")
        })
        .collect::<Result<Vec<_>>>()?;
    let node_kinds = counted_strings(&graph["nodes"], "kind")?;
    let edge_kinds = counted_strings(&graph["edges"], "kind")?;
    let mir_constant_count = graph["nodes"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|node| node["kind"] == "rust_mir_body")
        .filter_map(|node| node["properties"]["constant_count"].as_u64())
        .sum();
    let canonical_shape = json!({
        "node_kinds": node_kinds,
        "edge_kinds": edge_kinds,
        "typed_mir_body_count": count("typed_mir_body_count")?,
        "compiler_instance_count": count("compiler_instance_count")?,
        "compiler_call_count": count("compiler_call_count")?,
        "mir_constant_count": mir_constant_count,
        "query_capabilities": query_capabilities,
    });
    let cross_checkout_semantic = canonical_checkout_semantic_graph(graph)?;
    Ok(CompilerPackSemanticReport {
        checkout_a_export_sha256: digest_bytes(bytes),
        checkout_b_export_sha256: digest_bytes(bytes),
        cross_checkout_semantic_sha256: digest_bytes(&serde_json::to_vec(
            &cross_checkout_semantic,
        )?),
        canonical_graph_sha256: digest_bytes(&serde_json::to_vec(&canonical_shape)?),
        node_kinds,
        edge_kinds,
        typed_mir_body_count: count("typed_mir_body_count")?,
        compiler_instance_count: count("compiler_instance_count")?,
        compiler_call_count: count("compiler_call_count")?,
        mir_constant_count,
        query_capabilities,
    })
}

fn canonical_checkout_semantic_graph(graph: &Value) -> Result<Value> {
    let mut profiles = graph["profiles"]
        .as_array()
        .context("compiler pack graph profiles are not an array")?
        .clone();
    for profile in &mut profiles {
        let properties = profile["properties"]
            .as_object_mut()
            .context("compiler pack profile properties are not an object")?;
        properties.remove("invocation_ledger_digest");
        properties.remove("mir_ledger_digest");
    }
    profiles.sort_by(|left, right| left["id"].as_str().cmp(&right["id"].as_str()));

    let mut nodes = graph["nodes"]
        .as_array()
        .context("compiler pack graph nodes are not an array")?
        .clone();
    for node in &mut nodes {
        let object = node
            .as_object_mut()
            .context("compiler pack graph node is not an object")?;
        object.remove("locator");
        let properties = object
            .get_mut("properties")
            .and_then(Value::as_object_mut)
            .context("compiler pack graph node properties are not an object")?;
        properties.remove("build_provenance");
        properties.remove("mir_unit_digest");
    }
    nodes.sort_by(|left, right| left["id"].as_str().cmp(&right["id"].as_str()));

    let mut edges = graph["edges"]
        .as_array()
        .context("compiler pack graph edges are not an array")?
        .clone();
    for edge in &mut edges {
        let object = edge
            .as_object_mut()
            .context("compiler pack graph edge is not an object")?;
        object.remove("id");
        object.remove("site_id");
    }
    edges.sort_by_key(Value::to_string);
    Ok(json!({
        "profiles": profiles,
        "nodes": nodes,
        "edges": edges,
    }))
}

fn counted_strings(array: &Value, field: &str) -> Result<BTreeMap<String, u64>> {
    let mut counts = BTreeMap::new();
    for item in array
        .as_array()
        .context("graph collection is not an array")?
    {
        let value = item[field]
            .as_str()
            .with_context(|| format!("graph item omits {field}"))?;
        *counts.entry(value.to_owned()).or_default() += 1;
    }
    Ok(counts)
}

fn selected_targets(requested: &[String]) -> Result<Vec<String>> {
    let unique = requested.iter().collect::<BTreeSet<_>>();
    if unique.len() != requested.len()
        || unique
            .iter()
            .any(|target| !COMPILER_PACK_SUPPORTED_TARGETS.contains(&target.as_str()))
    {
        bail!("compiler pack verification requested an unknown or duplicate target");
    }
    Ok(COMPILER_PACK_SUPPORTED_TARGETS
        .iter()
        .filter(|target| requested.is_empty() || unique.contains(&target.to_string()))
        .map(|target| (*target).to_owned())
        .collect())
}

fn archive_extension(target: &str) -> Result<&'static str> {
    if !COMPILER_PACK_SUPPORTED_TARGETS.contains(&target) {
        bail!("unsupported compiler pack target {target}");
    }
    Ok(if target.ends_with("-windows-msvc") {
        "zip"
    } else {
        "tar.gz"
    })
}

fn checksum_reference(target: &str) -> String {
    format!("release-checksums:v{VERSION}/compiler-pack-{target}")
}

fn copy_regular_file(source: &Path, destination: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(source)
        .with_context(|| format!("compiler pack input {} is missing", source.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("compiler pack input {} is not regular", source.display());
    }
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::copy(source, destination)?;
    fs::set_permissions(destination, metadata.permissions())?;
    Ok(())
}

fn extract_compiler_pack_archive(archive: &Path, destination: &Path) -> Result<()> {
    let archive_metadata = fs::symlink_metadata(archive)
        .with_context(|| format!("compiler pack archive {} is missing", archive.display()))?;
    if archive_metadata.file_type().is_symlink()
        || !archive_metadata.is_file()
        || archive_metadata.len() > MAX_ARCHIVE_BYTES
    {
        bail!("compiler pack archive is not a bounded regular file");
    }
    let destination_metadata = fs::symlink_metadata(destination).with_context(|| {
        format!(
            "compiler pack extraction root {} is missing",
            destination.display()
        )
    })?;
    if destination_metadata.file_type().is_symlink()
        || !destination_metadata.is_dir()
        || fs::read_dir(destination)?.next().is_some()
    {
        bail!("compiler pack extraction root must be an empty real directory");
    }
    if archive
        .extension()
        .is_some_and(|extension| extension == "zip")
    {
        extract_bounded_zip(archive, destination)
    } else {
        extract_bounded_tar_gz(archive, destination)
    }
}

fn extract_bounded_tar_gz(archive: &Path, destination: &Path) -> Result<()> {
    let input = fs::File::open(archive)?;
    let decoder = flate2::read::GzDecoder::new(input);
    let mut tar = tar::Archive::new(decoder);
    let mut seen = BTreeSet::new();
    let mut directories = BTreeSet::new();
    let mut file_count = 0_usize;
    let mut directory_count = 0_usize;
    let mut unpacked_bytes = 0_u64;
    for entry in tar.entries()? {
        let mut entry = entry?;
        let relative = bounded_archive_path(entry.path()?.as_ref())?;
        if !seen.insert(relative.clone()) {
            bail!("compiler pack archive contains a duplicate path");
        }
        require_explicit_archive_parent(&relative, &directories)?;
        let entry_type = entry.header().entry_type();
        let size = entry.header().size()?;
        if entry_type.is_dir() {
            directory_count = directory_count
                .checked_add(1)
                .context("compiler pack directory count overflowed")?;
            if size != 0 {
                bail!("compiler pack archive directory has a payload");
            }
        } else if entry_type.is_file() {
            file_count = file_count
                .checked_add(1)
                .context("compiler pack file count overflowed")?;
            unpacked_bytes = unpacked_bytes
                .checked_add(size)
                .context("compiler pack unpacked byte count overflowed")?;
        } else {
            bail!("compiler pack archive contains a non-regular entry");
        }
        enforce_extraction_bounds(file_count, directory_count, unpacked_bytes)?;
        if !entry.unpack_in(destination)? {
            bail!("compiler pack archive entry escapes its extraction root");
        }
        if entry_type.is_dir() {
            directories.insert(relative);
        }
    }
    Ok(())
}

fn extract_bounded_zip(archive: &Path, destination: &Path) -> Result<()> {
    let input = fs::File::open(archive)?;
    let mut zip = zip::ZipArchive::new(input)?;
    if zip.len() > MAX_PACK_FILES.saturating_add(MAX_PACK_DIRECTORIES) {
        bail!("compiler pack archive entry count exceeds its bound");
    }
    let mut seen = BTreeSet::new();
    let mut directories = BTreeSet::new();
    let mut file_count = 0_usize;
    let mut directory_count = 0_usize;
    let mut unpacked_bytes = 0_u64;
    for index in 0..zip.len() {
        let mut entry = zip.by_index(index)?;
        let enclosed = entry
            .enclosed_name()
            .context("compiler pack zip entry has an unsafe path")?;
        let relative = bounded_archive_path(&enclosed)?;
        if entry.name().contains('\\') || !seen.insert(relative.clone()) {
            bail!("compiler pack archive contains an unsafe or duplicate path");
        }
        require_explicit_archive_parent(&relative, &directories)?;
        let unix_file_type = entry.unix_mode().map(|mode| mode & 0o170000);
        if unix_file_type.is_some_and(|file_type| {
            file_type != 0 && file_type != 0o040000 && file_type != 0o100000
        }) {
            bail!("compiler pack archive contains a non-regular entry");
        }
        let output = destination.join(&relative);
        if entry.is_dir() {
            directory_count = directory_count
                .checked_add(1)
                .context("compiler pack directory count overflowed")?;
            if entry.size() != 0 {
                bail!("compiler pack archive directory has a payload");
            }
            enforce_extraction_bounds(file_count, directory_count, unpacked_bytes)?;
            fs::create_dir(&output)?;
            set_zip_permissions(&output, entry.unix_mode())?;
            directories.insert(relative);
            continue;
        }
        if !entry.is_file() {
            bail!("compiler pack archive contains a non-regular entry");
        }
        file_count = file_count
            .checked_add(1)
            .context("compiler pack file count overflowed")?;
        unpacked_bytes = unpacked_bytes
            .checked_add(entry.size())
            .context("compiler pack unpacked byte count overflowed")?;
        enforce_extraction_bounds(file_count, directory_count, unpacked_bytes)?;
        let parent = output
            .parent()
            .context("compiler pack archive entry has no parent")?;
        if !parent.is_dir() {
            bail!("compiler pack archive omits a parent directory entry");
        }
        let mut output_file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&output)?;
        let copied = io::copy(&mut entry, &mut output_file)?;
        if copied != entry.size() {
            bail!("compiler pack archive entry size changed during extraction");
        }
        set_zip_permissions(&output, entry.unix_mode())?;
    }
    Ok(())
}

fn require_explicit_archive_parent(path: &Path, directories: &BTreeSet<PathBuf>) -> Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
        && !directories.contains(parent)
    {
        bail!("compiler pack archive omits an explicit parent directory entry");
    }
    Ok(())
}

fn bounded_archive_path(path: &Path) -> Result<PathBuf> {
    let mut relative = PathBuf::new();
    for component in path.components() {
        let std::path::Component::Normal(component) = component else {
            bail!("compiler pack archive contains an unsafe path");
        };
        let component = component
            .to_str()
            .context("compiler pack archive path is not UTF-8")?;
        if component.is_empty() || component.contains(['/', '\\']) {
            bail!("compiler pack archive contains an unsafe path");
        }
        relative.push(component);
    }
    if relative.as_os_str().is_empty() {
        bail!("compiler pack archive contains an empty path");
    }
    Ok(relative)
}

fn enforce_extraction_bounds(
    file_count: usize,
    directory_count: usize,
    unpacked_bytes: u64,
) -> Result<()> {
    if file_count > MAX_PACK_FILES
        || directory_count > MAX_PACK_DIRECTORIES
        || unpacked_bytes > MAX_UNPACKED_BYTES
    {
        bail!("compiler pack archive exceeds its extraction resource bounds");
    }
    Ok(())
}

#[cfg(unix)]
fn set_zip_permissions(path: &Path, mode: Option<u32>) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    let mode = mode.context("compiler pack zip entry omits Unix permissions")? & 0o777;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_zip_permissions(_path: &Path, _mode: Option<u32>) -> Result<()> {
    Ok(())
}

fn clear_exact_directory(path: &Path, parent: &Path) -> Result<()> {
    if path.parent() != Some(parent)
        || !path
            .file_name()
            .and_then(OsStr::to_str)
            .is_some_and(|name| name.starts_with("depgraph-compiler-pack-"))
    {
        bail!("refusing to clear an invalid compiler pack staging directory");
    }
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            bail!("compiler pack staging path is not a real directory")
        }
        Ok(_) => fs::remove_dir_all(path)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

fn verify_checksum_sidecar(archive: &Path, checksum: &Path) -> Result<String> {
    let digest = sha256_file(archive)?;
    let name = archive
        .file_name()
        .context("compiler pack archive has no file name")?
        .to_string_lossy();
    if fs::read_to_string(checksum)? != format!("{digest}  {name}\n") {
        bail!("compiler pack checksum sidecar does not attest {name}");
    }
    Ok(digest)
}

fn write_pretty_json(path: &Path, value: &impl Serialize) -> Result<()> {
    fs::write(path, format!("{}\n", serde_json::to_string_pretty(value)?))?;
    Ok(())
}

fn digest_bytes(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn lowercase_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn git<I, S>(root: &Path, arguments: I) -> Result<()>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let mut command = Command::new("git");
    command.arg("-C").arg(root).args(arguments);
    run(&mut command)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn handshake(component: &str) -> ComponentHandshake {
        let compatibility = compiler_precise_release_compatibility_contract();
        ComponentHandshake {
            schema_version: COMPONENT_HANDSHAKE_SCHEMA_VERSION.to_owned(),
            component: component.to_owned(),
            version: VERSION.to_owned(),
            compiler_contract_version: compatibility.compiler_contract_version,
            wrapper_protocol_version: compatibility.wrapper_protocol_version,
            mir_schema_version: compatibility.mir_schema_version,
            rustc_commit: compatibility.rustc_commit,
            query_capabilities: compatibility.query_capabilities,
        }
    }

    fn target(target: &str) -> CompilerPackTargetVerification {
        CompilerPackTargetVerification {
            target: target.to_owned(),
            archive: format!("depgraph-compiler-pack-{VERSION}-{target}.tar.gz"),
            archive_sha256: "a".repeat(64),
            requirement_sha256: "b".repeat(64),
            attestation: CompilerPackAttestation {
                contract_version: "compiler-precise-rust-v1".to_owned(),
                host: target.to_owned(),
                target: target.to_owned(),
                manifest_sha256: "c".repeat(64),
                closed_tree_sha256: "d".repeat(64),
                cargo_sha256: "e".repeat(64),
                rustc_sha256: "f".repeat(64),
                wrapper_sha256: "1".repeat(64),
                query_sha256: "2".repeat(64),
            },
            component_tree_sha256: BTreeMap::new(),
            smoke_sha256: "3".repeat(64),
            handshakes: BTreeMap::from([
                ("query".to_owned(), handshake("query")),
                ("wrapper".to_owned(), handshake("wrapper")),
            ]),
            semantic: CompilerPackSemanticReport {
                checkout_a_export_sha256: "4".repeat(64),
                checkout_b_export_sha256: "4".repeat(64),
                cross_checkout_semantic_sha256: "6".repeat(64),
                canonical_graph_sha256: "5".repeat(64),
                node_kinds: BTreeMap::from([("rust_mir_body".to_owned(), 2)]),
                edge_kinds: BTreeMap::from([("calls".to_owned(), 1)]),
                typed_mir_body_count: 2,
                compiler_instance_count: 3,
                compiler_call_count: 1,
                mir_constant_count: 1,
                query_capabilities: vec![
                    "monomorphized_call_graph".to_owned(),
                    "typed_mir".to_owned(),
                ],
            },
            resources: CompilerPackResourceReport {
                archive_bytes: 1,
                unpacked_bytes: 2,
                file_count: 3,
                semantic_elapsed_millis: 4,
                admitted: true,
            },
            rollback: CompilerPackRollbackReport {
                tamper_rejected: true,
                missing_pack_rejected: true,
                unsupported_target_rejected: true,
                no_fallback_observed: true,
                completed_graph_preserved: true,
            },
        }
    }

    #[test]
    fn aggregate_requires_exact_five_target_semantic_and_rollback_closure() {
        let expected = COMPILER_PACK_SUPPORTED_TARGETS
            .iter()
            .map(|target| (*target).to_owned())
            .collect::<Vec<_>>();
        let targets = expected
            .iter()
            .map(|target_name| target(target_name))
            .collect::<Vec<_>>();
        validate_aggregate_targets(&targets, &expected).unwrap();

        let mut missing = targets.clone();
        missing.pop();
        assert!(validate_aggregate_targets(&missing, &expected).is_err());

        let mut drift = targets.clone();
        drift[0].semantic.canonical_graph_sha256 = "9".repeat(64);
        assert!(validate_aggregate_targets(&drift, &expected).is_err());

        let mut rollback = targets;
        rollback[0].rollback.tamper_rejected = false;
        assert!(validate_aggregate_targets(&rollback, &expected).is_err());
    }

    #[test]
    fn cross_checkout_canonicalization_ignores_only_run_provenance() -> Result<()> {
        let graph = json!({
            "profiles": [{
                "id": "compiler",
                "properties": {
                    "invocation_ledger_digest": "first",
                    "mir_ledger_digest": "first",
                    "query_capabilities": ["typed_mir"]
                }
            }],
            "nodes": [{
                "id": "node-a",
                "kind": "rust_mir_body",
                "locator": "build://first",
                "properties": {
                    "build_provenance": {"build_run_id": "first"},
                    "mir_unit_digest": "first",
                    "definition": {"name": "stable"}
                }
            }, {
                "id": "node-b",
                "kind": "rust_compiler_instance",
                "locator": "build://first",
                "properties": {
                    "build_provenance": {"build_run_id": "first"},
                    "definition": {"name": "callee"}
                }
            }],
            "edges": [{
                "id": "edge-first",
                "site_id": "site-first",
                "source": "node-a",
                "target": "node-b",
                "kind": "calls"
            }]
        });
        let mut equivalent = graph.clone();
        equivalent["profiles"][0]["properties"]["invocation_ledger_digest"] = json!("second");
        equivalent["profiles"][0]["properties"]["mir_ledger_digest"] = json!("second");
        equivalent["nodes"][0]["locator"] = json!("build://second");
        equivalent["nodes"][0]["properties"]["build_provenance"] =
            json!({"build_run_id": "second"});
        equivalent["nodes"][0]["properties"]["mir_unit_digest"] = json!("second");
        equivalent["edges"][0]["id"] = json!("edge-second");
        equivalent["edges"][0]["site_id"] = json!("site-second");
        assert_eq!(
            canonical_checkout_semantic_graph(&graph)?,
            canonical_checkout_semantic_graph(&equivalent)?
        );

        equivalent["edges"][0]["target"] = json!("node-c");
        assert_ne!(
            canonical_checkout_semantic_graph(&graph)?,
            canonical_checkout_semantic_graph(&equivalent)?
        );
        Ok(())
    }

    #[test]
    fn selected_target_matrix_and_archive_formats_are_closed() {
        assert_eq!(
            selected_targets(&[]).unwrap(),
            COMPILER_PACK_SUPPORTED_TARGETS
        );
        assert_eq!(archive_extension("x86_64-pc-windows-msvc").unwrap(), "zip");
        assert_eq!(archive_extension("aarch64-apple-darwin").unwrap(), "tar.gz");
        assert!(selected_targets(&["unknown-target".to_owned()]).is_err());
    }

    #[test]
    fn semantic_resource_budget_is_target_specific_and_closed() {
        for target in COMPILER_PACK_SUPPORTED_TARGETS {
            let expected = if target == &"x86_64-pc-windows-msvc" {
                MAX_WINDOWS_SEMANTIC_MILLIS
            } else {
                MAX_LINUX_MACOS_SEMANTIC_MILLIS
            };
            assert_eq!(semantic_millis_budget(target).unwrap(), expected);
        }
        assert!(semantic_millis_budget("unsupported-unknown-target").is_err());
    }

    #[test]
    fn bounded_archive_paths_reject_escape_and_cross_platform_separators() {
        assert_eq!(
            bounded_archive_path(Path::new("root/bin/tool")).unwrap(),
            PathBuf::from("root/bin/tool")
        );
        for unsafe_path in ["../escape", "/absolute", "root\\escape", "C:\\absolute"] {
            assert!(bounded_archive_path(Path::new(unsafe_path)).is_err());
        }
    }

    #[test]
    fn compiler_pack_extraction_rejects_oversized_archive_before_reading() -> Result<()> {
        let temp = TempDir::new()?;
        let archive = temp.path().join("oversized.tar.gz");
        fs::File::create(&archive)?.set_len(MAX_ARCHIVE_BYTES + 1)?;
        let destination = temp.path().join("destination");
        fs::create_dir(&destination)?;

        assert!(extract_compiler_pack_archive(&archive, &destination).is_err());
        assert!(fs::read_dir(&destination)?.next().is_none());
        Ok(())
    }

    #[test]
    fn bounded_extraction_accepts_release_tar_and_zip_formats() -> Result<()> {
        let temp = TempDir::new()?;
        let source = temp.path().join("source");
        fs::create_dir(&source)?;
        fs::write(source.join("payload.txt"), "bounded compiler pack\n")?;
        let entries = archive_entries(&source, "compiler-pack")?;

        let tar_archive = temp.path().join("compiler-pack.tar.gz");
        create_tar_archive(&tar_archive, &entries)?;
        let tar_destination = temp.path().join("tar-destination");
        fs::create_dir(&tar_destination)?;
        extract_compiler_pack_archive(&tar_archive, &tar_destination)?;
        assert_eq!(
            fs::read_to_string(tar_destination.join("compiler-pack/payload.txt"))?,
            "bounded compiler pack\n"
        );

        let zip_archive = temp.path().join("compiler-pack.zip");
        create_zip_archive(&zip_archive, &entries)?;
        let zip_destination = temp.path().join("zip-destination");
        fs::create_dir(&zip_destination)?;
        extract_compiler_pack_archive(&zip_archive, &zip_destination)?;
        assert_eq!(
            fs::read_to_string(zip_destination.join("compiler-pack/payload.txt"))?,
            "bounded compiler pack\n"
        );
        Ok(())
    }

    #[test]
    fn bounded_tar_rejects_implicit_parent_directories_before_extraction() -> Result<()> {
        let temp = TempDir::new()?;
        let archive = temp.path().join("implicit-parent.tar.gz");
        let output = fs::File::create(&archive)?;
        let encoder = flate2::GzBuilder::new()
            .mtime(0)
            .write(output, flate2::Compression::best());
        let mut builder = tar::Builder::new(encoder);
        let payload = b"must not be extracted\n";
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Regular);
        header.set_mode(0o644);
        header.set_size(payload.len() as u64);
        header.set_cksum();
        builder.append_data(
            &mut header,
            "compiler-pack/implicit/payload.txt",
            &payload[..],
        )?;
        let encoder = builder.into_inner()?;
        encoder.finish()?;

        let destination = temp.path().join("destination");
        fs::create_dir(&destination)?;
        assert!(extract_compiler_pack_archive(&archive, &destination).is_err());
        assert!(fs::read_dir(&destination)?.next().is_none());
        Ok(())
    }

    #[test]
    fn extraction_resource_bounds_are_inclusive_and_independent() {
        enforce_extraction_bounds(MAX_PACK_FILES, MAX_PACK_DIRECTORIES, MAX_UNPACKED_BYTES)
            .unwrap();
        assert!(
            enforce_extraction_bounds(MAX_PACK_FILES + 1, MAX_PACK_DIRECTORIES, MAX_UNPACKED_BYTES)
                .is_err()
        );
        assert!(
            enforce_extraction_bounds(MAX_PACK_FILES, MAX_PACK_DIRECTORIES + 1, MAX_UNPACKED_BYTES)
                .is_err()
        );
        assert!(
            enforce_extraction_bounds(MAX_PACK_FILES, MAX_PACK_DIRECTORIES, MAX_UNPACKED_BYTES + 1)
                .is_err()
        );
    }

    #[test]
    fn repository_scoped_command_resolves_relative_executable_before_chdir() -> Result<()> {
        let current = std::env::current_dir()?;
        let launch = TempDir::new_in(&current)?;
        let executable = launch.path().join("depgraph-fixture");
        fs::write(&executable, b"fixture")?;
        let relative = executable
            .strip_prefix(&current)
            .context("fixture executable is outside the launch directory")?;
        let repository = TempDir::new()?;

        let command = command_in_directory(relative, repository.path())?;

        assert_eq!(command.get_program(), executable.canonicalize()?);
        assert_eq!(command.get_current_dir(), Some(repository.path()));
        Ok(())
    }
}
