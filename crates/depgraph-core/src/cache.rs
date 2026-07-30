use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use depgraph_store::{CacheKey, CacheLayer};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::{
    build::BuildAudit,
    config::Config,
    repository_inventory::build_repository_file_inventory,
    worker::{AdapterKind, WorkerSpec, resolve_safe_executable, sanitized_path},
};

const CACHE_MAX_FILES: usize = 100_000;
const CACHE_MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;
const CACHE_MAX_TOTAL_BYTES: u64 = 512 * 1024 * 1024;
const RUST_TOOLCHAIN_BASELINE: &str = "1.93.1";
const RUSTC_BASELINE_COMMIT: &str = "01f6ddf7588f42ae2d7eb0a2f21d44e8e96674cf";
const CARGO_BASELINE_COMMIT: &str = "083ac5135f967fd9dc906ab057a2315861c7a80d";

#[derive(Debug, Clone)]
pub(crate) struct ScanCachePlan {
    pub syntax: CacheKey,
    pub semantic: Option<CacheKey>,
    pub semantic_reject_reason: Option<&'static str>,
    pub(crate) symlink_proofs: Vec<SymlinkProof>,
}

#[derive(Debug, Clone)]
pub(crate) enum ScanCachePreparation {
    Ready(ScanCachePlan),
    Rejected(CacheRejection),
}

#[derive(Debug, Clone, Eq, PartialEq, thiserror::Error)]
#[error("{reason}")]
pub(crate) struct CacheRejection {
    pub reason: &'static str,
    pub path: Option<String>,
}

impl CacheRejection {
    fn new(reason: &'static str) -> Self {
        Self { reason, path: None }
    }

    fn at_path(reason: &'static str, path: &str) -> Self {
        Self {
            reason,
            path: Some(path.to_owned()),
        }
    }
}

impl ScanCachePlan {
    pub(crate) fn has_symlink_proofs(&self) -> bool {
        !self.symlink_proofs.is_empty()
    }
}

#[derive(Debug)]
struct InventoryFile {
    relative: String,
    path: PathBuf,
    length: u64,
    manifest: bool,
    generated: bool,
    symlink: Option<SymlinkObservation>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct SymlinkObservation {
    link_target: String,
    cache_identity: String,
    canonical_target: PathBuf,
    length: u64,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct SymlinkProof {
    relative: String,
    observation: SymlinkObservation,
    content_digest: String,
}

#[derive(Debug)]
struct InventoryFingerprints {
    all: String,
    manifests: String,
    generated: String,
    go_dependency_rescan_required: bool,
    symlink_proofs: Vec<SymlinkProof>,
}

pub(crate) fn prepare_scan_cache(
    root: &Path,
    config: &Config,
    workers: &[(AdapterKind, WorkerSpec)],
    store_path: Option<&Path>,
    profile_plan_id: &str,
) -> ScanCachePreparation {
    let inventory = match fingerprint_inventory(root, store_path) {
        Ok(value) => value,
        Err(rejection) => return ScanCachePreparation::Rejected(rejection),
    };
    let adapter = match fingerprint_adapters(workers) {
        Ok(value) => value,
        Err(()) => {
            return ScanCachePreparation::Rejected(CacheRejection::new(
                "adapter-fingerprint-unavailable",
            ));
        }
    };
    let scan_contract = digest_serialized("scan-contract-v1", &config.scan);

    let syntax = CacheKey::new(
        CacheLayer::Syntax,
        BTreeMap::from([
            ("adapter_protocol".to_owned(), adapter.clone()),
            ("file_content".to_owned(), inventory.all.clone()),
            ("scan_contract".to_owned(), scan_contract),
        ]),
    );
    if inventory.go_dependency_rescan_required {
        return ScanCachePreparation::Ready(ScanCachePlan {
            syntax,
            semantic: None,
            semantic_reject_reason: Some("dependency-fingerprint-requires-rescan"),
            symlink_proofs: inventory.symlink_proofs,
        });
    }
    let toolchain = match fingerprint_toolchains(root, workers) {
        Ok(value) => value,
        Err(()) => {
            return ScanCachePreparation::Ready(ScanCachePlan {
                syntax,
                semantic: None,
                semantic_reject_reason: Some("toolchain-fingerprint-unavailable"),
                symlink_proofs: inventory.symlink_proofs,
            });
        }
    };
    let semantic = CacheKey::new(
        CacheLayer::Semantic,
        BTreeMap::from([
            ("adapter_protocol".to_owned(), adapter),
            ("config".to_owned(), digest_serialized("config-v1", config)),
            (
                "dependency_snapshot".to_owned(),
                inventory.manifests.clone(),
            ),
            ("generated_artifact".to_owned(), inventory.generated),
            ("manifest_lock_config".to_owned(), inventory.manifests),
            (
                "profile".to_owned(),
                digest_serialized("profile-v1", &config.profiles),
            ),
            ("profile_plan".to_owned(), profile_plan_id.to_owned()),
            ("syntax_key".to_owned(), syntax.key.clone()),
            ("toolchain_framework".to_owned(), toolchain),
        ]),
    );
    ScanCachePreparation::Ready(ScanCachePlan {
        syntax,
        semantic: Some(semantic),
        semantic_reject_reason: None,
        symlink_proofs: inventory.symlink_proofs,
    })
}

pub(crate) fn validate_scan_cache_hit_inputs(
    root: &Path,
    plan: &ScanCachePlan,
) -> Result<(), CacheRejection> {
    for proof in &plan.symlink_proofs {
        validate_symlink_proof(root, proof)?;
    }
    Ok(())
}

pub fn build_cache_key(audit: &BuildAudit) -> Option<CacheKey> {
    let artifact = audit.validated_output_digest.as_ref()?;
    Some(CacheKey::new(
        CacheLayer::Build,
        BTreeMap::from([
            ("adapter".to_owned(), audit.adapter.clone()),
            ("adapter_version".to_owned(), audit.adapter_version.clone()),
            ("artifact_fingerprint".to_owned(), artifact.clone()),
            ("command_plan".to_owned(), audit.command_plan_digest.clone()),
            (
                "environment_keys".to_owned(),
                audit.environment_key_set_digest.clone(),
            ),
            ("profile".to_owned(), audit.profile_id.clone()),
            ("protocol".to_owned(), audit.schema_version.clone()),
            ("source".to_owned(), audit.source_root_digest.clone()),
            (
                "toolchain_executable".to_owned(),
                audit.toolchain_executable_digest.clone(),
            ),
            (
                "toolchain_version".to_owned(),
                digest_bytes(
                    "build-toolchain-version-v1",
                    audit
                        .toolchain_version
                        .as_deref()
                        .unwrap_or("unknown")
                        .as_bytes(),
                ),
            ),
        ]),
    ))
}

fn fingerprint_inventory(
    root: &Path,
    store_path: Option<&Path>,
) -> Result<InventoryFingerprints, CacheRejection> {
    let root = root
        .canonicalize()
        .map_err(|_| CacheRejection::new("inventory-unavailable"))?;
    let store_path = store_path.and_then(|path| path.canonicalize().ok());
    let mut files = Vec::new();
    let mut total = 0_u64;
    let inventory = build_repository_file_inventory(&root)
        .map_err(|_| CacheRejection::new("inventory-unavailable"))?;
    for relative in inventory.paths {
        let path = root.join(&relative);
        if is_store_artifact(&path, store_path.as_deref()) {
            continue;
        }
        if relative.is_empty()
            || relative.starts_with('/')
            || relative.split('/').any(|component| component == "..")
            || relative.chars().any(char::is_control)
        {
            return Err(CacheRejection::new("invalid-relative-path"));
        }
        let metadata = fs::symlink_metadata(&path)
            .map_err(|_| CacheRejection::at_path("inventory-unavailable", &relative))?;
        let (content_path, length, symlink) = if metadata.file_type().is_symlink() {
            let observation = observe_confined_symlink(&root, &path, &relative)?;
            (
                observation.canonical_target.clone(),
                observation.length,
                Some(observation),
            )
        } else if metadata.is_file() {
            (path.clone(), metadata.len(), None)
        } else {
            return Err(CacheRejection::at_path(
                "unsupported-filesystem-entry",
                &relative,
            ));
        };
        if length > CACHE_MAX_FILE_BYTES {
            return Err(CacheRejection::at_path("file-size-limit", &relative));
        }
        total = total
            .checked_add(length)
            .ok_or_else(|| CacheRejection::at_path("inventory-size-limit", &relative))?;
        if total > CACHE_MAX_TOTAL_BYTES {
            return Err(CacheRejection::at_path("inventory-size-limit", &relative));
        }
        if files.len() >= CACHE_MAX_FILES {
            return Err(CacheRejection::at_path("inventory-file-limit", &relative));
        }
        files.push(InventoryFile {
            manifest: is_manifest_lock_or_config(&relative),
            generated: is_generated_artifact(&relative),
            relative,
            path: content_path,
            length,
            symlink,
        });
    }
    files.sort_by(|left, right| left.relative.cmp(&right.relative));

    let mut all = Sha256::new();
    all.update(b"depgraph-cache-inventory-v1\0");
    let mut manifests = Sha256::new();
    manifests.update(b"depgraph-cache-manifests-v1\0");
    let mut generated = Sha256::new();
    generated.update(b"depgraph-cache-generated-v1\0");
    let mut go_dependency_rescan_required = false;
    let mut symlink_proofs = Vec::new();
    for file in files {
        let bytes = fs::read(&file.path)
            .map_err(|_| CacheRejection::at_path("inventory-read-failed", &file.relative))?;
        if bytes.len() as u64 != file.length {
            return Err(CacheRejection::at_path(
                "input-changed-during-fingerprint",
                &file.relative,
            ));
        }
        if file.relative.rsplit('/').next() != Some(".depgraph.toml") {
            update_inventory_entry_digest(&mut all, &file, &bytes);
        }
        if file.manifest {
            update_inventory_entry_digest(&mut manifests, &file, &bytes);
        }
        if file.generated {
            update_inventory_entry_digest(&mut generated, &file, &bytes);
        }
        if file.relative.ends_with("go.mod") && go_mod_requires_dependencies(&bytes) {
            go_dependency_rescan_required = true;
        }
        let observed = fs::metadata(&file.path)
            .map_err(|_| CacheRejection::at_path("inventory-read-failed", &file.relative))?;
        if observed.len() != file.length {
            return Err(CacheRejection::at_path(
                "input-changed-during-fingerprint",
                &file.relative,
            ));
        }
        if let Some(expected) = &file.symlink {
            let link_path = root.join(&file.relative);
            let observed = observe_confined_symlink(&root, &link_path, &file.relative)?;
            if &observed != expected {
                return Err(CacheRejection::at_path(
                    "symlink-input-changed-during-fingerprint",
                    &file.relative,
                ));
            }
            symlink_proofs.push(SymlinkProof {
                relative: file.relative,
                observation: observed,
                content_digest: digest_bytes("symlink-target-content-v1", &bytes),
            });
        }
    }
    Ok(InventoryFingerprints {
        all: finish_digest(all),
        manifests: finish_digest(manifests),
        generated: finish_digest(generated),
        go_dependency_rescan_required,
        symlink_proofs,
    })
}

fn observe_confined_symlink(
    root: &Path,
    link_path: &Path,
    relative: &str,
) -> Result<SymlinkObservation, CacheRejection> {
    let metadata = fs::symlink_metadata(link_path)
        .map_err(|_| CacheRejection::at_path("symlink-input-unavailable", relative))?;
    if !metadata.file_type().is_symlink() {
        return Err(CacheRejection::at_path("symlink-input-changed", relative));
    }
    let target = fs::read_link(link_path)
        .map_err(|_| CacheRejection::at_path("symlink-target-unavailable", relative))?;
    let link_target = target
        .to_str()
        .ok_or_else(|| CacheRejection::at_path("symlink-target-not-utf8", relative))?
        .to_owned();
    let unresolved = if target.is_absolute() {
        target
    } else {
        link_path.parent().unwrap_or(root).join(target)
    };
    let canonical_target = unresolved.canonicalize().map_err(|error| {
        CacheRejection::at_path(symlink_resolution_error_reason(&error), relative)
    })?;
    if !canonical_target.starts_with(root) {
        return Err(CacheRejection::at_path(
            "symlink-target-outside-root",
            relative,
        ));
    }
    let target_metadata = fs::metadata(&canonical_target)
        .map_err(|_| CacheRejection::at_path("symlink-target-unavailable", relative))?;
    if !target_metadata.is_file() {
        return Err(CacheRejection::at_path("symlink-target-not-file", relative));
    }
    let cache_identity = if Path::new(&link_target).is_absolute() {
        let relative_target = canonical_target
            .strip_prefix(root)
            .expect("confined symlink target must be beneath its root")
            .to_str()
            .ok_or_else(|| CacheRejection::at_path("symlink-target-not-utf8", relative))?
            .replace('\\', "/");
        format!("root:/{relative_target}")
    } else {
        format!("relative:{link_target}")
    };
    Ok(SymlinkObservation {
        link_target,
        cache_identity,
        canonical_target,
        length: target_metadata.len(),
    })
}

fn symlink_resolution_error_reason(error: &std::io::Error) -> &'static str {
    if error.kind() == std::io::ErrorKind::NotFound {
        "dangling-symlink"
    } else if is_symlink_loop_error(error) {
        "symlink-loop"
    } else {
        "symlink-target-unavailable"
    }
}

fn is_symlink_loop_error(error: &std::io::Error) -> bool {
    #[cfg(unix)]
    {
        error.raw_os_error() == Some(libc::ELOOP)
    }
    #[cfg(windows)]
    {
        error.raw_os_error()
            == Some(windows_sys::Win32::Foundation::ERROR_CANT_RESOLVE_FILENAME as i32)
    }
    #[cfg(not(any(unix, windows)))]
    {
        false
    }
}

fn validate_symlink_proof(root: &Path, proof: &SymlinkProof) -> Result<(), CacheRejection> {
    let root = root
        .canonicalize()
        .map_err(|_| CacheRejection::new("inventory-unavailable"))?;
    let link_path = root.join(&proof.relative);
    let before = observe_confined_symlink(&root, &link_path, &proof.relative)?;
    if before != proof.observation {
        return Err(CacheRejection::at_path(
            "symlink-input-changed-before-cache-hit-promotion",
            &proof.relative,
        ));
    }
    let bytes = fs::read(&before.canonical_target)
        .map_err(|_| CacheRejection::at_path("symlink-target-unavailable", &proof.relative))?;
    if bytes.len() as u64 != before.length
        || digest_bytes("symlink-target-content-v1", &bytes) != proof.content_digest
    {
        return Err(CacheRejection::at_path(
            "symlink-input-changed-before-cache-hit-promotion",
            &proof.relative,
        ));
    }
    let after = observe_confined_symlink(&root, &link_path, &proof.relative)?;
    if after != before {
        return Err(CacheRejection::at_path(
            "symlink-input-changed-before-cache-hit-promotion",
            &proof.relative,
        ));
    }
    Ok(())
}

fn fingerprint_adapters(workers: &[(AdapterKind, WorkerSpec)]) -> Result<String, ()> {
    let mut hasher = Sha256::new();
    hasher.update(b"depgraph-cache-adapters-v1\0");
    hasher.update(env!("CARGO_PKG_VERSION").as_bytes());
    hasher.update(b"\0protocol:1.0\0graph:1.0\0");
    for (adapter, spec) in workers {
        hasher.update(adapter.name().as_bytes());
        hasher.update(b"\0");
        let artifact = spec.artifact_path.canonicalize().map_err(|_| ())?;
        let bytes = fs::read(artifact).map_err(|_| ())?;
        hasher.update(Sha256::digest(bytes));
        hasher.update(b"\0");
        hasher.update(
            spec.expected_version
                .as_deref()
                .unwrap_or("development")
                .as_bytes(),
        );
        hasher.update(b"\0");
        hasher.update(
            spec.runtime_requirement
                .as_deref()
                .unwrap_or("native")
                .as_bytes(),
        );
        hasher.update(b"\0");
        hasher.update([u8::from(spec.release_attested)]);
    }
    Ok(finish_digest(hasher))
}

fn fingerprint_toolchains(
    root: &Path,
    workers: &[(AdapterKind, WorkerSpec)],
) -> Result<String, ()> {
    let mut identities = BTreeMap::new();
    for (adapter, _) in workers {
        match adapter {
            AdapterKind::Rust => {
                let (selection, rustc, cargo) = verified_rust_toolchain_identities(root)?;
                identities.insert("rust-toolchain-selection", selection);
                identities.insert("rustc", rustc);
                identities.insert("cargo", cargo);
            }
            AdapterKind::Go => {
                identities.insert("go", tool_identity(root, "go", &["version"])?);
            }
            AdapterKind::Web => {
                identities.insert("node", tool_identity(root, "node", &["--version"])?);
            }
        }
    }
    Ok(digest_serialized("toolchain-framework-v1", &identities))
}

fn tool_identity(root: &Path, name: &str, arguments: &[&str]) -> Result<String, ()> {
    let program = resolve_safe_executable(name, root).map_err(|_| ())?;
    tool_identity_at(root, name, &program, arguments).map(|(identity, _)| identity)
}

fn tool_identity_at(
    root: &Path,
    name: &str,
    program: &Path,
    arguments: &[&str],
) -> Result<(String, Vec<u8>), ()> {
    let artifact = program.canonicalize().map_err(|_| ())?;
    let artifact_bytes = fs::read(&artifact).map_err(|_| ())?;
    let artifact_digest = Sha256::digest(&artifact_bytes);
    let mut command = Command::new(program);
    command.args(arguments).env_clear();
    copy_safe_tool_environment(&mut command, root)?;
    let output = command.output().map_err(|_| ())?;
    if !output.status.success()
        || output.stdout.len() > 64 * 1024
        || output.stderr.len() > 64 * 1024
    {
        return Err(());
    }
    if fs::read(&artifact).map_err(|_| ())? != artifact_bytes {
        return Err(());
    }
    let mut hasher = Sha256::new();
    hasher.update(b"depgraph-cache-tool-v1\0");
    hasher.update(name.as_bytes());
    hasher.update(b"\0");
    hasher.update(artifact_digest);
    hasher.update(b"\0");
    hasher.update(&output.stdout);
    hasher.update(b"\0");
    hasher.update(&output.stderr);
    Ok((finish_digest(hasher), output.stdout))
}

fn verified_rust_toolchain_identities(root: &Path) -> Result<(String, String, String), ()> {
    if let Ok((rustc, cargo)) = rustup_baseline_pair(root)
        && let Ok((rustc_identity, rustc_output)) =
            tool_identity_at(root, "rustc", &rustc, &["--version", "--verbose"])
        && let Ok((cargo_identity, cargo_output)) =
            tool_identity_at(root, "cargo", &cargo, &["--version", "--verbose"])
        && verified_rust_version(&rustc_output, RUSTC_BASELINE_COMMIT)
        && verified_rust_version(&cargo_output, CARGO_BASELINE_COMMIT)
        && version_field(&rustc_output, "host") == version_field(&cargo_output, "host")
        && rustup_pair_matches_attested_host(root, &rustc, &rustc_output)
    {
        return Ok((
            "installed-verified-baseline".to_owned(),
            rustc_identity,
            cargo_identity,
        ));
    }

    let rustc = resolve_safe_executable("rustc", root).map_err(|_| ())?;
    let cargo = resolve_safe_executable("cargo", root).map_err(|_| ())?;
    let (rustc_identity, rustc_output) =
        tool_identity_at(root, "rustc", &rustc, &["--version", "--verbose"])?;
    let (cargo_identity, cargo_output) =
        tool_identity_at(root, "cargo", &cargo, &["--version", "--verbose"])?;
    if !verified_rust_version(&rustc_output, RUSTC_BASELINE_COMMIT)
        || !verified_rust_version(&cargo_output, CARGO_BASELINE_COMMIT)
        || version_field(&rustc_output, "host") != version_field(&cargo_output, "host")
    {
        return Err(());
    }
    Ok(("host-default".to_owned(), rustc_identity, cargo_identity))
}

fn rustup_pair_matches_attested_host(root: &Path, rustc: &Path, output: &[u8]) -> bool {
    let Some(rustup_home) = safe_rustup_home(root) else {
        return false;
    };
    let Some(host) = version_field(output, "host") else {
        return false;
    };
    rustup_toolchain_root(rustc, &rustup_home)
        .ok()
        .and_then(|path| path.file_name().map(ToOwned::to_owned))
        .is_some_and(|name| name.to_string_lossy() == format!("{RUST_TOOLCHAIN_BASELINE}-{host}"))
}

fn rustup_baseline_pair(root: &Path) -> Result<(PathBuf, PathBuf), ()> {
    let rustup = resolve_safe_executable("rustup", root).map_err(|_| ())?;
    let rustup_home = safe_rustup_home(root).ok_or(())?;
    let rustc = rustup_which(root, &rustup, &rustup_home, "rustc")?;
    let cargo = rustup_which(root, &rustup, &rustup_home, "cargo")?;
    if rustup_toolchain_root(&rustc, &rustup_home)? != rustup_toolchain_root(&cargo, &rustup_home)?
    {
        return Err(());
    }
    Ok((rustc, cargo))
}

fn safe_rustup_home(root: &Path) -> Option<PathBuf> {
    std::env::var_os("RUSTUP_HOME")
        .as_deref()
        .and_then(|value| safe_external_directory_for_cache(root, value))
        .or_else(|| {
            ["HOME", "USERPROFILE"].into_iter().find_map(|key| {
                std::env::var_os(key)
                    .map(PathBuf::from)
                    .map(|home| home.join(".rustup"))
                    .filter(|path| path.is_dir())
                    .and_then(|path| safe_external_directory_for_cache(root, path.as_os_str()))
            })
        })
}

fn safe_external_directory_for_cache(root: &Path, value: &std::ffi::OsStr) -> Option<PathBuf> {
    let path = Path::new(value);
    if !path.is_absolute() {
        return None;
    }
    let canonical = path.canonicalize().ok()?;
    (canonical.is_dir() && !canonical.starts_with(root)).then_some(canonical)
}

fn rustup_which(root: &Path, rustup: &Path, rustup_home: &Path, tool: &str) -> Result<PathBuf, ()> {
    let mut command = Command::new(rustup);
    command
        .args(["which", "--toolchain", RUST_TOOLCHAIN_BASELINE, tool])
        .env_clear();
    copy_safe_tool_environment(&mut command, root)?;
    command
        .env("RUSTUP_AUTO_INSTALL", "0")
        .env("RUSTUP_HOME", rustup_home);
    let output = command.output().map_err(|_| ())?;
    if !output.status.success()
        || output.stdout.len() > 64 * 1024
        || output.stderr.len() > 64 * 1024
    {
        return Err(());
    }
    let stdout = std::str::from_utf8(&output.stdout).map_err(|_| ())?;
    let mut lines = stdout
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty());
    let path = PathBuf::from(lines.next().ok_or(())?);
    if lines.next().is_some() || !path.is_absolute() {
        return Err(());
    }
    let metadata = fs::symlink_metadata(&path).map_err(|_| ())?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(());
    }
    let path = path.canonicalize().map_err(|_| ())?;
    rustup_toolchain_root(&path, rustup_home)?;
    Ok(path)
}

fn rustup_toolchain_root(tool: &Path, rustup_home: &Path) -> Result<PathBuf, ()> {
    let toolchains = rustup_home
        .join("toolchains")
        .canonicalize()
        .map_err(|_| ())?;
    let relative = tool.strip_prefix(&toolchains).map_err(|_| ())?;
    let mut components = relative.components();
    let toolchain = components.next().ok_or(())?;
    let bin = components.next().ok_or(())?;
    let executable = components.next().ok_or(())?;
    if components.next().is_some() || bin.as_os_str() != "bin" || executable.as_os_str().is_empty()
    {
        return Err(());
    }
    Ok(toolchains.join(toolchain.as_os_str()))
}

fn verified_rust_version(output: &[u8], expected_commit: &str) -> bool {
    version_field(output, "release") == Some(RUST_TOOLCHAIN_BASELINE)
        && version_field(output, "commit-hash") == Some(expected_commit)
        && version_field(output, "host").is_some_and(|host| !host.is_empty())
}

fn version_field<'a>(output: &'a [u8], key: &str) -> Option<&'a str> {
    std::str::from_utf8(output).ok()?.lines().find_map(|line| {
        let (candidate, value) = line.split_once(':')?;
        (candidate.trim() == key).then(|| value.trim())
    })
}

fn copy_safe_tool_environment(command: &mut Command, root: &Path) -> Result<(), ()> {
    command.env("PATH", sanitized_path(root).map_err(|_| ())?);
    for key in [
        "HOME",
        "USERPROFILE",
        "TMPDIR",
        "TEMP",
        "TMP",
        "SystemRoot",
        "CARGO_HOME",
        "RUSTUP_HOME",
        "GOROOT",
        "GOPATH",
        "GOMODCACHE",
    ] {
        if let Some(value) = std::env::var_os(key) {
            let path = PathBuf::from(&value);
            let safe = path.is_absolute()
                && path
                    .canonicalize()
                    .is_ok_and(|canonical| !canonical.starts_with(root));
            if safe {
                command.env(key, value);
            }
        }
    }
    for key in ["LANG", "LC_ALL"] {
        if let Some(value) = std::env::var_os(key) {
            command.env(key, value);
        }
    }
    Ok(())
}

fn is_store_artifact(path: &Path, store_path: Option<&Path>) -> bool {
    let Some(store_path) = store_path else {
        return false;
    };
    if path == store_path {
        return true;
    }
    let Some(store_name) = store_path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    path.parent() == store_path.parent()
        && path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| {
                name == format!("{store_name}-wal") || name == format!("{store_name}-shm")
            })
}

fn is_manifest_lock_or_config(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path);
    matches!(
        name,
        "Cargo.toml"
            | "Cargo.lock"
            | "go.mod"
            | "go.sum"
            | "go.work"
            | "go.work.sum"
            | "package.json"
            | "package-lock.json"
            | "pnpm-lock.yaml"
            | "yarn.lock"
            | ".depgraph.toml"
    ) || name.starts_with("tsconfig")
        || name.starts_with("next.config.")
        || name.starts_with("astro.config.")
        || name.starts_with("vite.config.")
}

fn is_generated_artifact(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower
        .split('/')
        .any(|component| matches!(component, "generated" | "gen" | "codegen" | "artifacts"))
        || lower.contains(".generated.")
        || lower.ends_with(".g.rs")
        || lower.ends_with("routetree.gen.ts")
}

fn go_mod_requires_dependencies(bytes: &[u8]) -> bool {
    std::str::from_utf8(bytes).is_ok_and(|text| {
        text.lines().any(|line| {
            let line = line.trim_start();
            line == "require (" || line.starts_with("require\t") || line.starts_with("require ")
        })
    })
}

fn update_inventory_entry_digest(hasher: &mut Sha256, file: &InventoryFile, bytes: &[u8]) {
    let Some(symlink) = &file.symlink else {
        update_entry_digest(hasher, &file.relative, bytes);
        return;
    };
    hasher.update(b"symlink\0");
    hasher.update((file.relative.len() as u64).to_be_bytes());
    hasher.update(file.relative.as_bytes());
    hasher.update((symlink.cache_identity.len() as u64).to_be_bytes());
    hasher.update(symlink.cache_identity.as_bytes());
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

fn update_entry_digest(hasher: &mut Sha256, path: &str, bytes: &[u8]) {
    hasher.update((path.len() as u64).to_be_bytes());
    hasher.update(path.as_bytes());
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

fn digest_serialized(domain: &str, value: &impl Serialize) -> String {
    let bytes = serde_json::to_vec(value).expect("cache identity inputs must serialize");
    digest_bytes(domain, &bytes)
}

fn digest_bytes(domain: &str, bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain.as_bytes());
    hasher.update(b"\0");
    hasher.update(bytes);
    finish_digest(hasher)
}

fn finish_digest(hasher: Sha256) -> String {
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn semantic_cache_fingerprints_the_effective_verified_rust_pair() {
        let root = tempfile::tempdir().unwrap();
        let (selection, rustc, cargo) =
            verified_rust_toolchain_identities(root.path()).expect("verified Rust baseline");
        assert!(matches!(
            selection.as_str(),
            "installed-verified-baseline" | "host-default"
        ));
        assert!(rustc.starts_with("sha256:"));
        assert!(cargo.starts_with("sha256:"));
        assert_ne!(rustc, cargo);
    }

    #[cfg(unix)]
    #[test]
    fn repository_internal_symlink_is_fingerprinted_and_revalidated() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("CLAUDE.md"), "first\n").unwrap();
        symlink("CLAUDE.md", root.path().join("WARP.md")).unwrap();
        let profile_plan_id = format!("profile-selection-plan:sha256:{}", "1".repeat(64));
        let ScanCachePreparation::Ready(first) =
            prepare_scan_cache(root.path(), &Config::default(), &[], None, &profile_plan_id)
        else {
            panic!("root-confined symlink must remain cacheable");
        };
        assert_eq!(first.symlink_proofs.len(), 1);
        validate_scan_cache_hit_inputs(root.path(), &first).unwrap();

        fs::remove_file(root.path().join("WARP.md")).unwrap();
        symlink("./CLAUDE.md", root.path().join("WARP.md")).unwrap();
        let relinked_rejection = validate_scan_cache_hit_inputs(root.path(), &first).unwrap_err();
        assert_eq!(
            relinked_rejection,
            CacheRejection::at_path(
                "symlink-input-changed-before-cache-hit-promotion",
                "WARP.md"
            )
        );
        let ScanCachePreparation::Ready(relinked) =
            prepare_scan_cache(root.path(), &Config::default(), &[], None, &profile_plan_id)
        else {
            panic!("relinked root-confined symlink must remain cacheable");
        };
        assert_ne!(first.syntax.key, relinked.syntax.key);

        fs::write(root.path().join("CLAUDE.md"), "other\n").unwrap();
        let rejection = validate_scan_cache_hit_inputs(root.path(), &relinked).unwrap_err();
        assert_eq!(
            rejection,
            CacheRejection::at_path(
                "symlink-input-changed-before-cache-hit-promotion",
                "WARP.md"
            )
        );
        let ScanCachePreparation::Ready(changed) =
            prepare_scan_cache(root.path(), &Config::default(), &[], None, &profile_plan_id)
        else {
            panic!("changed root-confined symlink must remain cacheable");
        };
        assert_ne!(relinked.syntax.key, changed.syntax.key);
        assert_ne!(
            relinked.semantic.unwrap().key,
            changed.semantic.unwrap().key
        );
    }

    #[cfg(unix)]
    #[test]
    fn absolute_internal_symlink_identity_is_checkout_independent() {
        use std::os::unix::fs::symlink;

        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        for root in [&first, &second] {
            fs::write(root.path().join("CLAUDE.md"), "fixture\n").unwrap();
            symlink(root.path().join("CLAUDE.md"), root.path().join("WARP.md")).unwrap();
        }
        let profile_plan_id = format!("profile-selection-plan:sha256:{}", "1".repeat(64));
        let ScanCachePreparation::Ready(first_plan) = prepare_scan_cache(
            first.path(),
            &Config::default(),
            &[],
            None,
            &profile_plan_id,
        ) else {
            panic!("first absolute internal symlink must remain cacheable");
        };
        let ScanCachePreparation::Ready(second_plan) = prepare_scan_cache(
            second.path(),
            &Config::default(),
            &[],
            None,
            &profile_plan_id,
        ) else {
            panic!("second absolute internal symlink must remain cacheable");
        };
        assert_eq!(first_plan.syntax.key, second_plan.syntax.key);
        assert_eq!(
            first_plan.semantic.unwrap().key,
            second_plan.semantic.unwrap().key
        );
    }

    #[cfg(unix)]
    #[test]
    fn unsafe_symlink_shapes_fail_closed_with_repository_relative_paths() {
        use std::os::unix::fs::symlink;

        let profile_plan_id = format!("profile-selection-plan:sha256:{}", "1".repeat(64));
        let outside_root = tempfile::tempdir().unwrap();
        let outside_target = outside_root.path().join("outside.md");
        fs::write(&outside_target, "outside\n").unwrap();

        let root_out = tempfile::tempdir().unwrap();
        symlink(&outside_target, root_out.path().join("WARP.md")).unwrap();
        let ScanCachePreparation::Rejected(root_out_rejection) = prepare_scan_cache(
            root_out.path(),
            &Config::default(),
            &[],
            None,
            &profile_plan_id,
        ) else {
            panic!("root-out symlink must reject caching");
        };
        assert_eq!(
            root_out_rejection,
            CacheRejection::at_path("symlink-target-outside-root", "WARP.md")
        );

        let dangling = tempfile::tempdir().unwrap();
        symlink("missing.md", dangling.path().join("WARP.md")).unwrap();
        let ScanCachePreparation::Rejected(dangling_rejection) = prepare_scan_cache(
            dangling.path(),
            &Config::default(),
            &[],
            None,
            &profile_plan_id,
        ) else {
            panic!("dangling symlink must reject caching");
        };
        assert_eq!(
            dangling_rejection,
            CacheRejection::at_path("dangling-symlink", "WARP.md")
        );

        let looped = tempfile::tempdir().unwrap();
        symlink("second.md", looped.path().join("first.md")).unwrap();
        symlink("first.md", looped.path().join("second.md")).unwrap();
        let ScanCachePreparation::Rejected(loop_rejection) = prepare_scan_cache(
            looped.path(),
            &Config::default(),
            &[],
            None,
            &profile_plan_id,
        ) else {
            panic!("symlink loop must reject caching");
        };
        assert_eq!(
            loop_rejection,
            CacheRejection::at_path("symlink-loop", "first.md")
        );
    }

    #[test]
    fn inventory_identity_is_checkout_independent_and_content_sensitive() {
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        for root in [first.path(), second.path()] {
            fs::create_dir(root.join("src")).unwrap();
            fs::write(root.join("src/lib.rs"), "pub fn answer() -> u8 { 42 }\n").unwrap();
            fs::write(root.join("Cargo.toml"), "[package]\nname='fixture'\n").unwrap();
        }
        let first_fingerprint = fingerprint_inventory(first.path(), None).unwrap();
        let second_fingerprint = fingerprint_inventory(second.path(), None).unwrap();
        assert_eq!(first_fingerprint.all, second_fingerprint.all);
        assert_eq!(first_fingerprint.manifests, second_fingerprint.manifests);

        fs::write(
            second.path().join("src/lib.rs"),
            "pub fn answer() -> u8 { 43 }\n",
        )
        .unwrap();
        let changed = fingerprint_inventory(second.path(), None).unwrap();
        assert_ne!(first_fingerprint.all, changed.all);
        assert_eq!(first_fingerprint.manifests, changed.manifests);
    }

    #[test]
    fn inventory_identity_ignores_internal_compiler_pack_state() {
        let checkout = tempfile::tempdir().unwrap();
        fs::create_dir(checkout.path().join("src")).unwrap();
        fs::write(checkout.path().join("src/lib.rs"), "pub fn fixture() {}\n").unwrap();
        let before = fingerprint_inventory(checkout.path(), None).unwrap();

        let pack = checkout.path().join(".depgraph/compiler-pack");
        fs::create_dir_all(&pack).unwrap();
        fs::write(
            pack.join("manifest.json"),
            r#"{"schema_version":"hostile-safe-scan-canary"}"#,
        )
        .unwrap();
        fs::write(pack.join("cargo"), b"armed project-local executable").unwrap();
        let after = fingerprint_inventory(checkout.path(), None).unwrap();

        assert_eq!(before.all, after.all);
        assert_eq!(before.manifests, after.manifests);
        assert_eq!(before.generated, after.generated);
    }

    #[test]
    fn inventory_identity_ignores_gitignored_worktrees_and_next_outputs() {
        let checkout = tempfile::tempdir().unwrap();
        fs::create_dir_all(checkout.path().join("src")).unwrap();
        fs::create_dir_all(checkout.path().join(".branches/feature/.next/dev/build")).unwrap();
        fs::write(checkout.path().join(".gitignore"), ".branches/\n.next/\n").unwrap();
        fs::write(
            checkout.path().join("src/app.ts"),
            "export const value = 1;\n",
        )
        .unwrap();
        fs::write(
            checkout
                .path()
                .join(".branches/feature/.next/dev/build/postcss.js"),
            "generated one\n",
        )
        .unwrap();
        let before = fingerprint_inventory(checkout.path(), None).unwrap();

        fs::write(
            checkout
                .path()
                .join(".branches/feature/.next/dev/build/postcss.js"),
            "generated two\n",
        )
        .unwrap();
        let after = fingerprint_inventory(checkout.path(), None).unwrap();
        assert_eq!(before.all, after.all);
        assert_eq!(before.manifests, after.manifests);
        assert_eq!(before.generated, after.generated);
    }

    #[test]
    fn inventory_tracks_output_named_directories_and_scan_roots() {
        let checkout = tempfile::tempdir().unwrap();
        fs::create_dir(checkout.path().join("build")).unwrap();
        let source = checkout.path().join("build/main.go");
        fs::write(&source, "package build\n\nconst value = 1\n").unwrap();
        let before = fingerprint_inventory(checkout.path(), None).unwrap();
        fs::write(&source, "package build\n\nconst value = 2\n").unwrap();
        let after = fingerprint_inventory(checkout.path(), None).unwrap();
        assert_ne!(before.all, after.all);

        let parent = tempfile::tempdir().unwrap();
        let named_root = parent.path().join("target");
        fs::create_dir(&named_root).unwrap();
        let root_source = named_root.join("lib.rs");
        fs::write(&root_source, "pub const VALUE: u8 = 1;\n").unwrap();
        let before = fingerprint_inventory(&named_root, None).unwrap();
        fs::write(&root_source, "pub const VALUE: u8 = 2;\n").unwrap();
        let after = fingerprint_inventory(&named_root, None).unwrap();
        assert_ne!(before.all, after.all);
    }

    #[test]
    fn syntax_key_excludes_profile_while_semantic_key_includes_it() {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("README.md"), "fixture").unwrap();
        fs::write(root.path().join(".depgraph.toml"), "schema_version = 1\n").unwrap();
        let mut first = Config::default();
        let mut second = Config::default();
        let ScanCachePreparation::Ready(first_plan) = prepare_scan_cache(
            root.path(),
            &first,
            &[],
            None,
            &format!("profile-selection-plan:sha256:{}", "1".repeat(64)),
        ) else {
            panic!("first cache plan must be available");
        };
        second.profiles.rust_features.push("serde".to_owned());
        fs::write(
            root.path().join(".depgraph.toml"),
            "schema_version = 1\n[profiles]\nrust_features = ['serde']\n",
        )
        .unwrap();
        let ScanCachePreparation::Ready(second_plan) = prepare_scan_cache(
            root.path(),
            &second,
            &[],
            None,
            &format!("profile-selection-plan:sha256:{}", "2".repeat(64)),
        ) else {
            panic!("second cache plan must be available");
        };
        assert_eq!(first_plan.syntax.key, second_plan.syntax.key);
        assert_ne!(
            first_plan.semantic.as_ref().unwrap().key,
            second_plan.semantic.as_ref().unwrap().key
        );

        first.scan.max_stderr_bytes += 1;
        let ScanCachePreparation::Ready(scan_changed) = prepare_scan_cache(
            root.path(),
            &first,
            &[],
            None,
            &format!("profile-selection-plan:sha256:{}", "1".repeat(64)),
        ) else {
            panic!("changed scan cache plan must be available");
        };
        assert_ne!(first_plan.syntax.key, scan_changed.syntax.key);
    }

    #[test]
    fn go_dependency_snapshot_fails_closed_to_a_rescan() {
        let root = tempfile::tempdir().unwrap();
        fs::write(
            root.path().join("go.mod"),
            "module example.test/app\n\nrequire example.test/dep v1.0.0\n",
        )
        .unwrap();
        let ScanCachePreparation::Ready(plan) = prepare_scan_cache(
            root.path(),
            &Config::default(),
            &[],
            None,
            &format!("profile-selection-plan:sha256:{}", "1".repeat(64)),
        ) else {
            panic!("syntax cache must remain available");
        };
        assert!(plan.semantic.is_none());
        assert_eq!(
            plan.semantic_reject_reason,
            Some("dependency-fingerprint-requires-rescan")
        );
    }

    #[test]
    fn profile_plan_identity_invalidates_only_the_semantic_cache_layer() {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("lib.rs"), "pub fn fixture() {}\n").unwrap();
        let first_id = format!("profile-selection-plan:sha256:{}", "1".repeat(64));
        let second_id = format!("profile-selection-plan:sha256:{}", "2".repeat(64));
        let ScanCachePreparation::Ready(first) =
            prepare_scan_cache(root.path(), &Config::default(), &[], None, &first_id)
        else {
            panic!("first cache plan must be available");
        };
        let ScanCachePreparation::Ready(second) =
            prepare_scan_cache(root.path(), &Config::default(), &[], None, &second_id)
        else {
            panic!("second cache plan must be available");
        };
        assert_eq!(first.syntax, second.syntax);
        assert_ne!(first.semantic, second.semantic);
        assert_eq!(
            first
                .semantic
                .as_ref()
                .unwrap()
                .dimensions
                .get("profile_plan"),
            Some(&first_id)
        );
    }
}
