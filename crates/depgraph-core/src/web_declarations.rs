//! Content witness for the confined installed declaration context used by Web analysis.
use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs,
    io::Read,
    path::{Path, PathBuf},
};

const MAX_ENTRIES: usize = 250_000;
const MAX_BYTES: u64 = 256 * 1024 * 1024;
const MAX_FILE_BYTES: u64 = 16 * 1024 * 1024;

/// Includes negative lookup boundaries, symlink identities, manifests and declaration bytes.
/// Runtime JS is never evaluated or read. All visited targets remain under `root`.
pub(crate) fn fingerprint(
    root: &Path,
    inventory: impl IntoIterator<Item = impl AsRef<str>>,
) -> Result<String> {
    let root = root.canonicalize()?;
    let mut roots = BTreeSet::from([root.join("node_modules")]);
    for relative in inventory {
        if !is_web_input(relative.as_ref()) {
            continue;
        }
        let mut directory = root.join(relative.as_ref());
        while directory.pop() && directory.starts_with(&root) {
            roots.insert(directory.join("node_modules"));
            if roots.len() > MAX_ENTRIES {
                bail!("external declaration lookup boundary limit exceeded");
            }
        }
    }
    let mut witness = Witness {
        root: &root,
        digest: Sha256::new(),
        visited: BTreeSet::new(),
        entries: 0,
        bytes: 0,
    };
    witness.digest.update(b"depgraph-web-declarations-v1\0");
    for directory in roots {
        witness.visit(&directory, 0)?;
    }
    Ok(format!("{:x}", witness.digest.finalize()))
}

fn is_web_input(relative: &str) -> bool {
    let name = Path::new(relative)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("");
    name == "package.json"
        || [
            ".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs", ".astro",
        ]
        .iter()
        .any(|suffix| name.ends_with(suffix))
}

struct Witness<'a> {
    root: &'a Path,
    digest: Sha256,
    visited: BTreeSet<PathBuf>,
    entries: usize,
    bytes: u64,
}

impl Witness<'_> {
    fn field(&mut self, value: &[u8]) {
        self.digest.update((value.len() as u64).to_be_bytes());
        self.digest.update(value);
    }

    fn visit(&mut self, candidate: &Path, depth: usize) -> Result<()> {
        self.entries += 1;
        if self.entries > MAX_ENTRIES || depth > 128 {
            bail!("external declaration witness exceeds entry/depth limit");
        }
        let relative = candidate
            .strip_prefix(self.root)
            .context("external declaration path outside root")?;
        self.field(relative.to_string_lossy().as_bytes());
        let metadata = match fs::symlink_metadata(candidate) {
            Ok(value) => value,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
                ) =>
            {
                self.field(b"absent");
                return Ok(());
            }
            Err(error) => return Err(error.into()),
        };
        if metadata.file_type().is_symlink() {
            self.field(b"symlink");
            let target = fs::read_link(candidate)?;
            if let Ok(relative) = target.strip_prefix(self.root) {
                self.field(b"root-relative-link");
                self.field(relative.to_string_lossy().as_bytes());
            } else {
                self.field(target.to_string_lossy().as_bytes());
            }
        }
        let canonical = match candidate.canonicalize() {
            Ok(value) if value.starts_with(self.root) => value,
            _ => {
                self.field(b"unavailable-or-outside-root");
                return Ok(());
            }
        };
        self.field(
            canonical
                .strip_prefix(self.root)?
                .to_string_lossy()
                .as_bytes(),
        );
        if !self.visited.insert(canonical.clone()) {
            self.field(b"already-visited");
            return Ok(());
        }
        let metadata = fs::metadata(&canonical)?;
        if metadata.is_dir() {
            self.field(b"directory");
            let mut children = fs::read_dir(&canonical)?
                .take(MAX_ENTRIES.saturating_sub(self.entries) + 1)
                .map(|entry| entry.map(|entry| entry.path()))
                .collect::<std::io::Result<Vec<_>>>()?;
            if children.len() > MAX_ENTRIES.saturating_sub(self.entries) {
                bail!("external declaration directory entry limit exceeded");
            }
            children.sort();
            for child in children {
                self.visit(&child, depth + 1)?;
            }
        } else if metadata.is_file() && is_input(&canonical) {
            self.read_input(&canonical, &metadata)?;
        } else {
            self.field(b"non-declaration");
        }
        Ok(())
    }

    fn read_input(&mut self, file: &Path, before: &fs::Metadata) -> Result<()> {
        self.bytes = self
            .bytes
            .checked_add(before.len())
            .context("external declaration byte count overflow")?;
        if before.len() > MAX_FILE_BYTES || self.bytes > MAX_BYTES {
            bail!("external declaration witness exceeds byte limit");
        }
        let mut content = Vec::new();
        fs::File::open(file)?
            .take(MAX_FILE_BYTES + 1)
            .read_to_end(&mut content)?;
        let after = fs::metadata(file)?;
        if content.len() as u64 != before.len()
            || before.len() != after.len()
            || before.modified()? != after.modified()?
        {
            bail!("external declaration changed during fingerprint");
        }
        self.field(b"input");
        self.field(&content);
        Ok(())
    }
}

fn is_input(file: &Path) -> bool {
    file.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| {
            name == "package.json"
                || name.ends_with(".d.ts")
                || name.ends_with(".d.mts")
                || name.ends_with(".d.cts")
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn declaration_content_and_absence_invalidate_without_runtime_content() -> Result<()> {
        let root = tempfile::tempdir()?;
        let absent = fingerprint(root.path(), ["src/index.ts"])?;
        let package = root.path().join("node_modules/library");
        fs::create_dir_all(&package)?;
        fs::write(package.join("package.json"), "{\"types\":\"index.d.ts\"}")?;
        fs::write(
            package.join("index.d.ts"),
            "export declare function create(): string;",
        )?;
        fs::write(package.join("index.js"), "throw new Error('never run');")?;
        let first = fingerprint(root.path(), ["src/index.ts"])?;
        assert_ne!(absent, first);
        fs::write(
            package.join("index.js"),
            "throw new Error('still never run');",
        )?;
        assert_eq!(first, fingerprint(root.path(), ["src/index.ts"])?);
        fs::write(
            package.join("index.d.ts"),
            "export declare function create(): number;",
        )?;
        assert_ne!(first, fingerprint(root.path(), ["src/index.ts"])?);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn confined_links_are_hashed_but_outside_bytes_are_not_read() -> Result<()> {
        let root = tempfile::tempdir()?;
        let outside = tempfile::tempdir()?;
        fs::create_dir_all(root.path().join("node_modules/.pnpm/library"))?;
        fs::write(
            root.path().join("node_modules/.pnpm/library/index.d.ts"),
            "export {};",
        )?;
        std::os::unix::fs::symlink(".pnpm/library", root.path().join("node_modules/library"))?;
        std::os::unix::fs::symlink(outside.path(), root.path().join("node_modules/outside"))?;
        let first = fingerprint(root.path(), ["index.ts"])?;
        fs::write(outside.path().join("secret.d.ts"), "secret")?;
        assert_eq!(first, fingerprint(root.path(), ["index.ts"])?);
        fs::write(
            root.path().join("node_modules/.pnpm/library/index.d.ts"),
            "export type T = string;",
        )?;
        assert_ne!(first, fingerprint(root.path(), ["index.ts"])?);
        Ok(())
    }
    #[test]
    fn directory_collection_respects_remaining_entry_budget() -> Result<()> {
        let root = tempfile::tempdir()?;
        fs::write(root.path().join("a.d.ts"), "export {};")?;
        fs::write(root.path().join("b.d.ts"), "export {};")?;
        let canonical = root.path().canonicalize()?;
        let mut witness = Witness {
            root: &canonical,
            digest: Sha256::new(),
            visited: BTreeSet::new(),
            entries: MAX_ENTRIES - 1,
            bytes: 0,
        };
        assert!(witness.visit(&canonical, 0).is_err());
        Ok(())
    }
}
