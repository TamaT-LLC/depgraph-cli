use std::{
    collections::BTreeSet,
    fs,
    path::{Component, Path},
    process::Command,
};

use anyhow::{Context, Result, bail};
use ignore::{DirEntry, WalkBuilder};
use serde::{Deserialize, Serialize};

use crate::worker::resolve_safe_executable;

pub(crate) const REPOSITORY_INVENTORY_CONTRACT_VERSION: &str =
    "depgraph-repository-file-inventory-v1";
const MAX_REPOSITORY_INVENTORY_BYTES: usize = 64 * 1024 * 1024;
const MAX_REPOSITORY_INVENTORY_FILES: usize = 1_000_000;

const GENERATED_DIRECTORIES: &[&str] = &[
    ".cache",
    ".depgraph",
    ".git",
    ".hg",
    ".next",
    ".output",
    ".svn",
    ".turbo",
    ".astro",
    "node_modules",
    "target",
];

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RepositoryFileInventory {
    pub contract_version: String,
    pub paths: Vec<String>,
}

pub(crate) fn build_repository_file_inventory(root: &Path) -> Result<RepositoryFileInventory> {
    let root = root
        .canonicalize()
        .context("repository inventory root is unavailable")?;
    if !root.is_dir() {
        bail!("repository inventory root must be a directory");
    }
    let paths = git_inventory(&root)?.unwrap_or(fallback_inventory(&root)?);
    Ok(RepositoryFileInventory {
        contract_version: REPOSITORY_INVENTORY_CONTRACT_VERSION.to_owned(),
        paths,
    })
}

fn git_inventory(root: &Path) -> Result<Option<Vec<String>>> {
    let Ok(git) = resolve_safe_executable("git", root) else {
        return Ok(None);
    };
    let top_level = Command::new(&git)
        .arg("-C")
        .arg(root)
        .args(["rev-parse", "--show-toplevel"])
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .output()
        .context("failed to identify repository inventory Git root")?;
    if !top_level.status.success() {
        return Ok(None);
    }
    let top_level = std::str::from_utf8(&top_level.stdout)
        .context("repository inventory Git root is not UTF-8")?
        .trim();
    let top_level = Path::new(top_level)
        .canonicalize()
        .context("failed to canonicalize repository inventory Git root")?;
    if top_level != root {
        return Ok(None);
    }

    let output = Command::new(git)
        .arg("-C")
        .arg(root)
        .args([
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
        ])
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .output()
        .context("failed to enumerate repository files with Git")?;
    if !output.status.success() {
        return Ok(None);
    }
    if output.stdout.len() > MAX_REPOSITORY_INVENTORY_BYTES {
        bail!("repository inventory exceeds its closed byte limit");
    }
    let mut paths = BTreeSet::new();
    for raw in output
        .stdout
        .split(|byte| *byte == 0)
        .filter(|raw| !raw.is_empty())
    {
        let relative =
            std::str::from_utf8(raw).context("repository inventory path is not UTF-8")?;
        if excluded_relative_path(relative)? {
            continue;
        }
        let absolute = root.join(relative);
        match fs::symlink_metadata(&absolute) {
            Ok(metadata) if metadata.is_file() || metadata.file_type().is_symlink() => {
                paths.insert(relative.replace('\\', "/"));
            }
            Ok(_) => {
                // A nested repository or worktree is represented by its
                // directory entry. Never cross that repository boundary.
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                // The index may retain a deleted tracked path.
            }
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("failed to inspect repository file {relative}"));
            }
        }
        if paths.len() > MAX_REPOSITORY_INVENTORY_FILES {
            bail!("repository inventory exceeds its closed file-count limit");
        }
    }
    Ok(Some(paths.into_iter().collect()))
}

fn fallback_inventory(root: &Path) -> Result<Vec<String>> {
    let mut builder = WalkBuilder::new(root);
    builder
        .follow_links(false)
        .hidden(false)
        .parents(false)
        .git_ignore(true)
        .git_global(false)
        .git_exclude(true)
        .require_git(false)
        .filter_entry({
            let root = root.to_path_buf();
            move |entry| include_fallback_entry(&root, entry)
        });
    let mut paths = BTreeSet::new();
    let mut entry_count = 0_usize;
    let mut total_bytes = 0_usize;
    for entry in builder.build() {
        let entry = entry.context("failed to inspect repository file inventory")?;
        entry_count = entry_count
            .checked_add(1)
            .context("repository inventory entry count overflow")?;
        if entry_count > MAX_REPOSITORY_INVENTORY_FILES {
            bail!("repository inventory exceeds its closed entry-count limit");
        }
        if entry.path() == root {
            continue;
        }
        let Some(file_type) = entry.file_type() else {
            continue;
        };
        if !file_type.is_file() && !file_type.is_symlink() {
            continue;
        }
        let relative = entry
            .path()
            .strip_prefix(root)
            .context("repository inventory path escaped its root")?;
        let relative = relative
            .to_str()
            .context("repository inventory path is not UTF-8")?
            .replace('\\', "/");
        if excluded_relative_path(&relative)? {
            continue;
        }
        total_bytes = total_bytes
            .checked_add(relative.len() + 1)
            .context("repository inventory byte count overflow")?;
        if total_bytes > MAX_REPOSITORY_INVENTORY_BYTES {
            bail!("repository inventory exceeds its closed byte limit");
        }
        paths.insert(relative);
        if paths.len() > MAX_REPOSITORY_INVENTORY_FILES {
            bail!("repository inventory exceeds its closed file-count limit");
        }
    }
    Ok(paths.into_iter().collect())
}

fn include_fallback_entry(root: &Path, entry: &DirEntry) -> bool {
    if entry.path() == root {
        return true;
    }
    let Some(file_type) = entry.file_type() else {
        return false;
    };
    if !file_type.is_dir() {
        return true;
    }
    let Some(name) = entry.file_name().to_str() else {
        return false;
    };
    if GENERATED_DIRECTORIES.contains(&name) {
        return false;
    }
    // A .git directory or file marks a nested repository/worktree boundary.
    fs::symlink_metadata(entry.path().join(".git")).is_err()
}

fn excluded_relative_path(relative: &str) -> Result<bool> {
    if relative.is_empty() || relative.contains('\\') || relative.chars().any(char::is_control) {
        bail!("repository inventory path is not a canonical slash-separated relative path");
    }
    let path = Path::new(relative);
    if path.is_absolute()
        || path.components().any(|component| {
            !matches!(component, Component::Normal(_))
                || component
                    .as_os_str()
                    .to_str()
                    .is_none_or(|name| name.is_empty())
        })
    {
        bail!("repository inventory path is not a canonical relative path");
    }
    Ok(path.components().any(|component| {
        let Component::Normal(name) = component else {
            return true;
        };
        name.to_str()
            .is_none_or(|name| GENERATED_DIRECTORIES.contains(&name))
    }))
}

pub(crate) fn write_repository_inventory_file(root: &Path) -> Result<tempfile::NamedTempFile> {
    use std::io::Write as _;

    let inventory = build_repository_file_inventory(root)?;
    let mut file = tempfile::Builder::new()
        .prefix("depgraph-repository-inventory-")
        .tempfile()
        .context("failed to create repository inventory file")?;
    serde_json::to_writer(file.as_file_mut(), &inventory)
        .context("failed to serialize repository inventory")?;
    file.as_file_mut()
        .flush()
        .context("failed to flush repository inventory")?;
    Ok(file)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    #[test]
    fn fallback_inventory_honors_nested_ignores_and_repository_boundaries() -> Result<()> {
        let root = tempfile::tempdir()?;
        fs::create_dir_all(root.path().join("src/generated"))?;
        fs::create_dir_all(root.path().join("nested/repository/.git"))?;
        fs::write(root.path().join(".gitignore"), "ignored.ts\n")?;
        fs::write(root.path().join("src/.gitignore"), "generated/\n")?;
        fs::write(root.path().join("kept.ts"), "export {};\n")?;
        fs::write(root.path().join("ignored.ts"), "ignored\n")?;
        fs::write(root.path().join("src/generated/ignored.ts"), "ignored\n")?;
        fs::write(
            root.path().join("nested/repository/hidden.go"),
            "package hidden\n",
        )?;

        let inventory = fallback_inventory(root.path())?;
        assert!(inventory.contains(&".gitignore".to_owned()));
        assert!(inventory.contains(&"kept.ts".to_owned()));
        assert!(!inventory.iter().any(|path| path.contains("ignored.ts")));
        assert!(
            !inventory
                .iter()
                .any(|path| path.contains("nested/repository"))
        );
        Ok(())
    }

    #[test]
    fn generated_directories_are_excluded_even_without_ignore_rules() -> Result<()> {
        let root = tempfile::tempdir()?;
        fs::create_dir_all(root.path().join(".next/dev/build"))?;
        fs::create_dir_all(root.path().join("src"))?;
        fs::write(
            root.path().join(".next/dev/build/postcss.js"),
            "generated\n",
        )?;
        fs::write(root.path().join("src/app.ts"), "export {};\n")?;

        let inventory = fallback_inventory(root.path())?;
        assert_eq!(inventory, vec!["src/app.ts"]);
        Ok(())
    }
}
