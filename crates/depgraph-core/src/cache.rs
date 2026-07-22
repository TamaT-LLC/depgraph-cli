use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use depgraph_store::{CacheKey, CacheLayer};
use serde::Serialize;
use sha2::{Digest, Sha256};
use walkdir::{DirEntry, WalkDir};

use crate::{
    build::BuildAudit,
    config::Config,
    worker::{AdapterKind, WorkerSpec, resolve_safe_executable, sanitized_path},
};

const CACHE_MAX_FILES: usize = 100_000;
const CACHE_MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;
const CACHE_MAX_TOTAL_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Debug, Clone)]
pub(crate) struct ScanCachePlan {
    pub syntax: CacheKey,
    pub semantic: Option<CacheKey>,
    pub semantic_reject_reason: Option<&'static str>,
}

#[derive(Debug, Clone)]
pub(crate) enum ScanCachePreparation {
    Ready(ScanCachePlan),
    Rejected(&'static str),
}

#[derive(Debug)]
struct InventoryFile {
    relative: String,
    path: PathBuf,
    length: u64,
    manifest: bool,
    generated: bool,
}

#[derive(Debug)]
struct InventoryFingerprints {
    all: String,
    manifests: String,
    generated: String,
    go_dependency_rescan_required: bool,
}

pub(crate) fn prepare_scan_cache(
    root: &Path,
    config: &Config,
    workers: &[(AdapterKind, WorkerSpec)],
    store_path: Option<&Path>,
) -> ScanCachePreparation {
    let inventory = match fingerprint_inventory(root, store_path) {
        Ok(value) => value,
        Err(reason) => return ScanCachePreparation::Rejected(reason),
    };
    let adapter = match fingerprint_adapters(workers) {
        Ok(value) => value,
        Err(()) => return ScanCachePreparation::Rejected("adapter-fingerprint-unavailable"),
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
        });
    }
    let toolchain = match fingerprint_toolchains(root, workers) {
        Ok(value) => value,
        Err(()) => {
            return ScanCachePreparation::Ready(ScanCachePlan {
                syntax,
                semantic: None,
                semantic_reject_reason: Some("toolchain-fingerprint-unavailable"),
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
            ("syntax_key".to_owned(), syntax.key.clone()),
            ("toolchain_framework".to_owned(), toolchain),
        ]),
    );
    ScanCachePreparation::Ready(ScanCachePlan {
        syntax,
        semantic: Some(semantic),
        semantic_reject_reason: None,
    })
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
) -> Result<InventoryFingerprints, &'static str> {
    let store_path = store_path.and_then(|path| path.canonicalize().ok());
    let mut files = Vec::new();
    let mut total = 0_u64;
    for entry in WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_entry(is_cache_scannable_entry)
    {
        let entry = entry.map_err(|_| "inventory-unavailable")?;
        if entry.file_type().is_dir() {
            continue;
        }
        if entry.file_type().is_symlink() {
            return Err("symlink-input");
        }
        if !entry.file_type().is_file() {
            return Err("unsupported-filesystem-entry");
        }
        if is_store_artifact(entry.path(), store_path.as_deref()) {
            continue;
        }
        let relative = entry
            .path()
            .strip_prefix(root)
            .map_err(|_| "invalid-relative-path")?
            .to_str()
            .ok_or("non-utf8-path")?
            .replace('\\', "/");
        if relative.is_empty()
            || relative.starts_with('/')
            || relative.split('/').any(|component| component == "..")
            || relative.chars().any(char::is_control)
        {
            return Err("invalid-relative-path");
        }
        let metadata = entry.metadata().map_err(|_| "inventory-unavailable")?;
        if metadata.len() > CACHE_MAX_FILE_BYTES {
            return Err("file-size-limit");
        }
        total = total
            .checked_add(metadata.len())
            .ok_or("inventory-size-limit")?;
        if total > CACHE_MAX_TOTAL_BYTES {
            return Err("inventory-size-limit");
        }
        if files.len() >= CACHE_MAX_FILES {
            return Err("inventory-file-limit");
        }
        files.push(InventoryFile {
            manifest: is_manifest_lock_or_config(&relative),
            generated: is_generated_artifact(&relative),
            relative,
            path: entry.path().to_path_buf(),
            length: metadata.len(),
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
    for file in files {
        let bytes = fs::read(&file.path).map_err(|_| "inventory-read-failed")?;
        if bytes.len() as u64 != file.length {
            return Err("input-changed-during-fingerprint");
        }
        if file.relative.rsplit('/').next() != Some(".depgraph.toml") {
            update_entry_digest(&mut all, &file.relative, &bytes);
        }
        if file.manifest {
            update_entry_digest(&mut manifests, &file.relative, &bytes);
        }
        if file.generated {
            update_entry_digest(&mut generated, &file.relative, &bytes);
        }
        if file.relative.ends_with("go.mod") && go_mod_requires_dependencies(&bytes) {
            go_dependency_rescan_required = true;
        }
        let observed = fs::metadata(&file.path).map_err(|_| "inventory-read-failed")?;
        if observed.len() != file.length {
            return Err("input-changed-during-fingerprint");
        }
    }
    Ok(InventoryFingerprints {
        all: finish_digest(all),
        manifests: finish_digest(manifests),
        generated: finish_digest(generated),
        go_dependency_rescan_required,
    })
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
                identities.insert(
                    "cargo",
                    tool_identity(root, "cargo", &["--version", "--verbose"])?,
                );
                identities.insert(
                    "rustc",
                    tool_identity(root, "rustc", &["--version", "--verbose"])?,
                );
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
    let artifact = program.canonicalize().map_err(|_| ())?;
    let artifact_digest = Sha256::digest(fs::read(artifact).map_err(|_| ())?);
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
    let mut hasher = Sha256::new();
    hasher.update(b"depgraph-cache-tool-v1\0");
    hasher.update(name.as_bytes());
    hasher.update(b"\0");
    hasher.update(artifact_digest);
    hasher.update(b"\0");
    hasher.update(&output.stdout);
    hasher.update(b"\0");
    hasher.update(&output.stderr);
    Ok(finish_digest(hasher))
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

fn is_cache_scannable_entry(entry: &DirEntry) -> bool {
    if entry.depth() == 0 || !entry.file_type().is_dir() {
        return true;
    }
    !matches!(
        entry.file_name().to_string_lossy().as_ref(),
        ".git" | ".hg" | ".svn"
    )
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
        let ScanCachePreparation::Ready(first_plan) =
            prepare_scan_cache(root.path(), &first, &[], None)
        else {
            panic!("first cache plan must be available");
        };
        second.profiles.rust_features.push("serde".to_owned());
        fs::write(
            root.path().join(".depgraph.toml"),
            "schema_version = 1\n[profiles]\nrust_features = ['serde']\n",
        )
        .unwrap();
        let ScanCachePreparation::Ready(second_plan) =
            prepare_scan_cache(root.path(), &second, &[], None)
        else {
            panic!("second cache plan must be available");
        };
        assert_eq!(first_plan.syntax.key, second_plan.syntax.key);
        assert_ne!(
            first_plan.semantic.as_ref().unwrap().key,
            second_plan.semantic.as_ref().unwrap().key
        );

        first.scan.max_stderr_bytes += 1;
        let ScanCachePreparation::Ready(scan_changed) =
            prepare_scan_cache(root.path(), &first, &[], None)
        else {
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
        let ScanCachePreparation::Ready(plan) =
            prepare_scan_cache(root.path(), &Config::default(), &[], None)
        else {
            panic!("syntax cache must remain available");
        };
        assert!(plan.semantic.is_none());
        assert_eq!(
            plan.semantic_reject_reason,
            Some("dependency-fingerprint-requires-rescan")
        );
    }
}
