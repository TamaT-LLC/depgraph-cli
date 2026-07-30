use std::{
    collections::BTreeSet,
    fs,
    path::{Component, Path},
};

use anyhow::{Context, Result, bail};
use serde::Deserialize;

const REPOSITORY_INVENTORY_CONTRACT_VERSION: &str = "depgraph-repository-file-inventory-v1";
const MAX_REPOSITORY_INVENTORY_BYTES: u64 = 64 * 1024 * 1024;
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

#[derive(Clone, Debug)]
pub(crate) struct RepositoryInventory {
    paths: BTreeSet<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RepositoryInventoryDocument {
    contract_version: String,
    paths: Vec<String>,
}

impl RepositoryInventory {
    pub(crate) fn read(file: &Path) -> Result<Self> {
        let metadata = fs::metadata(file).context("read repository inventory metadata")?;
        if !metadata.is_file() || metadata.len() > MAX_REPOSITORY_INVENTORY_BYTES {
            bail!("repository inventory file exceeds its closed byte limit");
        }
        let document: RepositoryInventoryDocument =
            serde_json::from_slice(&fs::read(file).context("read repository inventory")?)
                .context("decode repository inventory")?;
        if document.contract_version != REPOSITORY_INVENTORY_CONTRACT_VERSION {
            bail!("repository inventory contract version is unsupported");
        }
        if document.paths.len() > MAX_REPOSITORY_INVENTORY_FILES {
            bail!("repository inventory exceeds its closed file-count limit");
        }
        let mut paths = BTreeSet::new();
        for relative in document.paths {
            validate_relative_path(&relative)?;
            if !paths.insert(relative) {
                bail!("repository inventory contains a duplicate path");
            }
        }
        Ok(Self { paths })
    }

    pub(crate) fn paths(&self) -> impl Iterator<Item = &str> {
        self.paths.iter().map(String::as_str)
    }
}

fn validate_relative_path(relative: &str) -> Result<()> {
    if relative.is_empty() || relative.contains('\\') || relative.chars().any(char::is_control) {
        bail!("repository inventory contains a non-canonical path");
    }
    let path = Path::new(relative);
    if path.is_absolute() {
        bail!("repository inventory contains a non-canonical path");
    }
    for component in path.components() {
        let Component::Normal(name) = component else {
            bail!("repository inventory contains a non-canonical path");
        };
        let Some(name) = name.to_str() else {
            bail!("repository inventory path is not UTF-8");
        };
        if name.is_empty() || GENERATED_DIRECTORIES.contains(&name) {
            bail!("repository inventory contains a generated directory");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_generated_and_non_canonical_paths() {
        assert!(validate_relative_path("src/lib.rs").is_ok());
        assert!(validate_relative_path(".next/server/app.js").is_err());
        assert!(validate_relative_path("../outside.rs").is_err());
        assert!(validate_relative_path("src\\lib.rs").is_err());
    }
}
