//! Attested, inventory-only Rust standard-library source input.
//!
//! The core process verifies the complete packaged data tree before launching
//! the worker. This module accepts only that verified release hand-off and
//! converts the pinned `core`, `alloc`, and `std` source trees into bounded,
//! stable virtual-file inputs. It never consults rustup, `RUST_SRC_PATH`, the
//! scan root, or a system/project sysroot.

use crate::{
    RUST_SYSROOT_COMPONENT_VERSION, RUST_SYSROOT_CONTRACT_VERSION, RUST_SYSROOT_LICENSE_EXPRESSION,
    RUST_SYSROOT_SOURCE_LAYOUT, RUST_TOOLCHAIN_BASELINE, RUSTC_BASELINE_COMMIT,
};
use serde::Deserialize;
use std::{
    ffi::OsStr,
    fs,
    path::{Component, Path, PathBuf},
};
use walkdir::WalkDir;

pub(crate) const RUST_SYSROOT_ROOT_ENV: &str = "DEPGRAPH_RUST_SYSROOT_ROOT";

const MAX_SYSROOT_FILES: usize = 4_096;
const MAX_SYSROOT_BYTES: usize = 64 * 1024 * 1024;
const MAX_SOURCE_IDENTITY_BYTES: u64 = 64 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SysrootSource {
    pub rel_path: String,
    pub text: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AttestedSysroot {
    pub files: Vec<SysrootSource>,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct SourceIdentity {
    contract_version: String,
    toolchain_version: String,
    toolchain_commit: String,
    component_version: String,
    source_layout: String,
    acquisition: String,
    normalized_root: String,
    license_expression: String,
}

pub(crate) fn load_attested_sysroot(
    release_verified: bool,
    configured_root: Option<&OsStr>,
) -> Result<AttestedSysroot, String> {
    if !release_verified {
        return Err("the Rust sysroot was not handed off by a verified release".into());
    }
    let configured_root = configured_root
        .ok_or_else(|| "the verified release omitted its Rust sysroot root".to_owned())?;
    let declared_root = PathBuf::from(configured_root);
    let declared_metadata = fs::symlink_metadata(&declared_root)
        .map_err(|_| "the attested Rust sysroot root is missing".to_owned())?;
    if declared_metadata.file_type().is_symlink() || !declared_metadata.is_dir() {
        return Err("the attested Rust sysroot root is not a non-symlink directory".into());
    }
    let component_root = declared_root
        .canonicalize()
        .map_err(|_| "the attested Rust sysroot root cannot be canonicalized".to_owned())?;
    verify_source_identity(&component_root)?;
    let library_root = component_root.join("library");
    let library_metadata = fs::symlink_metadata(&library_root)
        .map_err(|_| "the attested Rust sysroot library root is missing".to_owned())?;
    if library_metadata.file_type().is_symlink() || !library_metadata.is_dir() {
        return Err("the attested Rust sysroot library root is not a non-symlink directory".into());
    }

    let mut files = Vec::new();
    let mut total_bytes = 0usize;
    for crate_name in ["core", "alloc", "std"] {
        let crate_root = library_root.join(crate_name);
        let crate_metadata = fs::symlink_metadata(&crate_root)
            .map_err(|_| format!("the attested Rust sysroot is missing the {crate_name} crate"))?;
        if crate_metadata.file_type().is_symlink() || !crate_metadata.is_dir() {
            return Err(format!(
                "the attested Rust sysroot {crate_name} crate is not a non-symlink directory"
            ));
        }
        for entry in WalkDir::new(&crate_root)
            .follow_links(false)
            .sort_by_file_name()
        {
            let entry = entry.map_err(|_| {
                format!("the attested Rust sysroot {crate_name} inventory is unreadable")
            })?;
            let file_type = entry.file_type();
            if file_type.is_symlink() {
                return Err(format!(
                    "the attested Rust sysroot contains a symlink under library/{crate_name}"
                ));
            }
            if file_type.is_dir() {
                continue;
            }
            if !file_type.is_file() {
                return Err(format!(
                    "the attested Rust sysroot contains an unsupported entry under library/{crate_name}"
                ));
            }
            if entry.path().extension() != Some(OsStr::new("rs")) {
                continue;
            }
            let relative = entry.path().strip_prefix(&component_root).map_err(|_| {
                "the attested Rust sysroot entry escaped its component root".to_owned()
            })?;
            let rel_path = canonical_relative_path(relative)?;
            let bytes = fs::read(entry.path()).map_err(|_| {
                format!("the attested Rust sysroot source {rel_path} is unreadable")
            })?;
            total_bytes = total_bytes.checked_add(bytes.len()).ok_or_else(|| {
                "the attested Rust sysroot source inventory is too large".to_owned()
            })?;
            if total_bytes > MAX_SYSROOT_BYTES {
                return Err(
                    "the attested Rust sysroot source inventory exceeds its byte limit".into(),
                );
            }
            let text = String::from_utf8(bytes)
                .map_err(|_| format!("the attested Rust sysroot source {rel_path} is not UTF-8"))?;
            files.push(SysrootSource { rel_path, text });
            if files.len() > MAX_SYSROOT_FILES {
                return Err("the attested Rust sysroot source inventory has too many files".into());
            }
        }
    }
    files.sort_by(|left, right| left.rel_path.cmp(&right.rel_path));
    for required in [
        "library/core/src/lib.rs",
        "library/alloc/src/lib.rs",
        "library/std/src/lib.rs",
    ] {
        if !files.iter().any(|source| source.rel_path == required) {
            return Err(format!(
                "the attested Rust sysroot inventory is missing {required}"
            ));
        }
    }
    Ok(AttestedSysroot { files })
}

fn verify_source_identity(component_root: &Path) -> Result<(), String> {
    let path = component_root.join("SOURCE.json");
    let metadata = fs::symlink_metadata(&path)
        .map_err(|_| "the attested Rust sysroot SOURCE.json is missing".to_owned())?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > MAX_SOURCE_IDENTITY_BYTES
    {
        return Err(
            "the attested Rust sysroot SOURCE.json is not a bounded non-symlink file".into(),
        );
    }
    let identity: SourceIdentity = serde_json::from_slice(
        &fs::read(&path)
            .map_err(|_| "the attested Rust sysroot SOURCE.json is unreadable".to_owned())?,
    )
    .map_err(|_| "the attested Rust sysroot SOURCE.json is invalid".to_owned())?;
    let expected = SourceIdentity {
        contract_version: RUST_SYSROOT_CONTRACT_VERSION.into(),
        toolchain_version: RUST_TOOLCHAIN_BASELINE.into(),
        toolchain_commit: RUSTC_BASELINE_COMMIT.into(),
        component_version: RUST_SYSROOT_COMPONENT_VERSION.into(),
        source_layout: RUST_SYSROOT_SOURCE_LAYOUT.into(),
        acquisition: "rustup-component:rust-src".into(),
        normalized_root: "library".into(),
        license_expression: RUST_SYSROOT_LICENSE_EXPRESSION.into(),
    };
    if identity != expected {
        return Err(
            "the attested Rust sysroot SOURCE.json does not match the pinned compatibility unit"
                .into(),
        );
    }
    Ok(())
}

fn canonical_relative_path(path: &Path) -> Result<String, String> {
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err("the attested Rust sysroot contains a non-canonical path".into());
    }
    let parts = path
        .components()
        .map(|component| match component {
            Component::Normal(part) => part
                .to_str()
                .map(str::to_owned)
                .ok_or_else(|| "the attested Rust sysroot path is not UTF-8".to_owned()),
            _ => unreachable!("validated normal component"),
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(parts.join("/"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_identity(root: &Path) {
        fs::write(
            root.join("SOURCE.json"),
            serde_json::to_vec(&serde_json::json!({
                "contract_version": RUST_SYSROOT_CONTRACT_VERSION,
                "toolchain_version": RUST_TOOLCHAIN_BASELINE,
                "toolchain_commit": RUSTC_BASELINE_COMMIT,
                "component_version": RUST_SYSROOT_COMPONENT_VERSION,
                "source_layout": RUST_SYSROOT_SOURCE_LAYOUT,
                "acquisition": "rustup-component:rust-src",
                "normalized_root": "library",
                "license_expression": RUST_SYSROOT_LICENSE_EXPRESSION,
            }))
            .unwrap(),
        )
        .unwrap();
    }

    fn fixture() -> tempfile::TempDir {
        let temp = tempfile::tempdir().unwrap();
        write_identity(temp.path());
        for crate_name in ["core", "alloc", "std"] {
            let source = temp.path().join("library").join(crate_name).join("src");
            fs::create_dir_all(&source).unwrap();
            fs::write(
                source.join("lib.rs"),
                format!("pub mod {crate_name}_fixture;\n"),
            )
            .unwrap();
        }
        temp
    }

    #[test]
    fn accepts_only_the_verified_pinned_inventory() {
        let temp = fixture();
        let inventory =
            load_attested_sysroot(true, Some(temp.path().as_os_str())).expect("attested sysroot");
        assert_eq!(inventory.files.len(), 3);
        assert_eq!(inventory.files[0].rel_path, "library/alloc/src/lib.rs");
        assert!(load_attested_sysroot(false, Some(temp.path().as_os_str())).is_err());
    }

    #[test]
    fn rejects_identity_drift_and_missing_crates() {
        let temp = fixture();
        fs::write(temp.path().join("SOURCE.json"), b"{}").unwrap();
        assert!(load_attested_sysroot(true, Some(temp.path().as_os_str())).is_err());

        let temp = fixture();
        fs::remove_file(temp.path().join("library/std/src/lib.rs")).unwrap();
        assert!(load_attested_sysroot(true, Some(temp.path().as_os_str())).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinks_inside_the_inventory() {
        use std::os::unix::fs::symlink;

        let temp = fixture();
        symlink(
            temp.path().join("library/core/src/lib.rs"),
            temp.path().join("library/core/src/alias.rs"),
        )
        .unwrap();
        assert!(load_attested_sysroot(true, Some(temp.path().as_os_str())).is_err());

        let temp = fixture();
        let replacement = tempfile::tempdir().unwrap();
        fs::rename(
            temp.path().join("library"),
            replacement.path().join("library"),
        )
        .unwrap();
        symlink(
            replacement.path().join("library"),
            temp.path().join("library"),
        )
        .unwrap();
        assert!(load_attested_sysroot(true, Some(temp.path().as_os_str())).is_err());
    }
}
