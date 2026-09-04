use std::{
    fs,
    io::Read as _,
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};
use walkdir::WalkDir;

pub(crate) fn host_target() -> Result<String> {
    let output = Command::new("rustc").arg("-vV").output()?;
    let text = String::from_utf8(output.stdout)?;
    text.lines()
        .find_map(|line| line.strip_prefix("host: ").map(ToOwned::to_owned))
        .context("rustc -vV did not report a host target")
}

pub(crate) fn cargo_target_dir() -> PathBuf {
    std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("target"))
}

pub(crate) fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask must be located directly under the workspace root")
        .to_path_buf()
}

pub(crate) fn executable_name(name: &str) -> String {
    if cfg!(windows) {
        format!("{name}.exe")
    } else {
        name.to_owned()
    }
}

pub(crate) fn pnpm_program() -> &'static str {
    if cfg!(windows) { "pnpm.cmd" } else { "pnpm" }
}

pub(crate) fn copy(source: &Path, destination: &Path) -> Result<()> {
    fs::copy(source, destination).with_context(|| {
        format!(
            "failed to copy {} to {}",
            source.display(),
            destination.display()
        )
    })?;
    Ok(())
}

pub(crate) fn read_lf_normalized_text(path: &Path) -> Result<String> {
    let bytes =
        fs::read(path).with_context(|| format!("failed to read text {}", path.display()))?;
    let text = String::from_utf8(bytes)
        .with_context(|| format!("text {} is not UTF-8", path.display()))?;
    Ok(text.replace("\r\n", "\n").replace('\r', "\n"))
}

pub(crate) fn copy_lf_normalized_text(source: &Path, destination: &Path) -> Result<()> {
    let normalized = read_lf_normalized_text(source)?;
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(destination, normalized).with_context(|| {
        format!(
            "failed to write LF-normalized release text {}",
            destination.display()
        )
    })?;
    Ok(())
}

pub(crate) fn copy_directory(source: &Path, destination: &Path) -> Result<()> {
    for entry in WalkDir::new(source).follow_links(false) {
        let entry = entry?;
        if entry.file_type().is_symlink() {
            bail!(
                "refusing symlink in runtime component: {}",
                entry.path().display()
            );
        }
        let relative = entry.path().strip_prefix(source)?;
        let target = destination.join(relative);
        if entry.file_type().is_dir() {
            fs::create_dir_all(&target)?;
        } else if entry.file_type().is_file() {
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent)?;
            }
            copy(entry.path(), &target)?;
            fs::set_permissions(&target, entry.metadata()?.permissions())?;
        } else {
            bail!(
                "unsupported runtime component entry: {}",
                entry.path().display()
            );
        }
    }
    Ok(())
}

pub(crate) fn relative_slash(root: &Path, path: &Path) -> Result<String> {
    Ok(path
        .strip_prefix(root)?
        .to_string_lossy()
        .replace('\\', "/"))
}

pub(crate) fn sha256_file(path: &Path) -> Result<String> {
    let mut input =
        fs::File::open(path).with_context(|| format!("failed to read {}", path.display()))?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = input
            .read(&mut buffer)
            .with_context(|| format!("failed to read {}", path.display()))?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(hex::encode(digest.finalize()))
}

pub(crate) fn read_bounded_file(
    path: &Path,
    maximum_bytes: u64,
    description: &str,
) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to stat {description} {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > maximum_bytes {
        bail!(
            "{description} must be a regular non-symlink file no larger than {maximum_bytes} bytes"
        );
    }

    let mut input = fs::File::open(path)
        .with_context(|| format!("failed to read {description} {}", path.display()))?;
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len())?);
    input
        .by_ref()
        .take(maximum_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .with_context(|| format!("failed to read {description} {}", path.display()))?;
    if u64::try_from(bytes.len())? != metadata.len() || metadata.len() > maximum_bytes {
        bail!("{description} changed while it was being read or exceeded its byte limit");
    }
    Ok(bytes)
}

pub(crate) fn sha256_tree(root: &Path) -> Result<String> {
    let mut entries = Vec::new();
    for entry in WalkDir::new(root).follow_links(false).min_depth(1) {
        let entry = entry?;
        if entry.file_type().is_symlink() {
            bail!(
                "refusing symlink in runtime component: {}",
                entry.path().display()
            );
        }
        if entry.file_type().is_file() {
            entries.push((
                relative_slash(root, entry.path())?,
                true,
                entry.path().to_path_buf(),
            ));
        } else if entry.file_type().is_dir() {
            entries.push((
                relative_slash(root, entry.path())?,
                false,
                entry.path().to_path_buf(),
            ));
        } else {
            bail!(
                "unsupported runtime component entry: {}",
                entry.path().display()
            );
        }
    }
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    if !entries.iter().any(|(_, is_file, _)| *is_file) {
        bail!("runtime component {} is empty", root.display());
    }
    let mut digest = Sha256::new();
    digest.update(b"depgraph-runtime-tree-v2\0");
    for (relative, is_file, path) in entries {
        digest.update([if is_file { b'f' } else { b'd' }]);
        let relative = relative.as_bytes();
        digest.update((relative.len() as u64).to_be_bytes());
        digest.update(relative);
        if is_file {
            let mut input = fs::File::open(&path)
                .with_context(|| format!("failed to read {}", path.display()))?;
            let declared_length = input
                .metadata()
                .with_context(|| format!("failed to stat {}", path.display()))?
                .len();
            digest.update(declared_length.to_be_bytes());

            let mut buffer = [0_u8; 64 * 1024];
            let mut actual_length = 0_u64;
            loop {
                let read = input
                    .read(&mut buffer)
                    .with_context(|| format!("failed to read {}", path.display()))?;
                if read == 0 {
                    break;
                }
                actual_length = actual_length
                    .checked_add(read as u64)
                    .context("runtime component file length overflow")?;
                digest.update(&buffer[..read]);
            }
            if actual_length != declared_length {
                bail!(
                    "runtime component file {} changed while hashing: declared length {}, read {}",
                    path.display(),
                    declared_length,
                    actual_length
                );
            }
        } else {
            digest.update(0_u64.to_be_bytes());
        }
    }
    Ok(hex::encode(digest.finalize()))
}

pub(crate) fn run(command: &mut Command) -> Result<()> {
    let display = format!("{command:?}");
    let status = command
        .status()
        .with_context(|| format!("failed to start {display}"))?;
    if !status.success() {
        bail!("{display} exited with {status}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_file_reader_accepts_the_limit_and_rejects_the_next_byte() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let path = temp.path().join("input");
        fs::write(&path, b"bounded")?;
        assert_eq!(read_bounded_file(&path, 7, "test input")?, b"bounded");
        assert!(read_bounded_file(&path, 6, "test input").is_err());
        Ok(())
    }
}
