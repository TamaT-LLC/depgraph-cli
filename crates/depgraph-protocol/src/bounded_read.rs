//! Repository-confined, size-bounded, symlink-rejecting file reads shared by
//! the depgraph core and the contract extractors.

use std::{
    fmt,
    fs::{self, File, Metadata},
    io::Read,
    path::{Component, Path, PathBuf},
};

#[cfg(not(unix))]
use std::fs::OpenOptions;

/// Why a bounded repository read was refused. `code` is the stable,
/// machine-readable reason; the message never echoes the requested path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BoundedReadError {
    pub code: &'static str,
    pub message: &'static str,
}

impl BoundedReadError {
    const fn new(code: &'static str, message: &'static str) -> Self {
        Self { code, message }
    }
}

impl fmt::Display for BoundedReadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for BoundedReadError {}

pub fn read_bounded_repository_file(
    repository_root: &Path,
    file: &Path,
    max_bytes: usize,
) -> Result<Vec<u8>, BoundedReadError> {
    let max_bytes = u64::try_from(max_bytes).map_err(|_| {
        BoundedReadError::new(
            "query_file_size_or_type_invalid",
            "query file byte limit is invalid",
        )
    })?;
    let read_limit = max_bytes.checked_add(1).ok_or_else(|| {
        BoundedReadError::new(
            "query_file_size_or_type_invalid",
            "query file byte limit is invalid",
        )
    })?;
    let root = fs::canonicalize(repository_root).map_err(|_| {
        BoundedReadError::new(
            "query_file_repository_boundary_unavailable",
            "query file repository boundary is unavailable",
        )
    })?;
    let candidate = confined_candidate(repository_root, &root, file)?;
    reject_symlink_components(&root, &candidate)?;
    let canonical = fs::canonicalize(&candidate).map_err(|_| {
        BoundedReadError::new("query_file_unavailable", "query file is unavailable")
    })?;
    if !canonical.starts_with(&root) {
        return Err(BoundedReadError::new(
            "query_file_outside_repository",
            "query file is outside the repository boundary",
        ));
    }

    let path_before = fs::symlink_metadata(&candidate).map_err(|_| {
        BoundedReadError::new("query_file_unavailable", "query file is unavailable")
    })?;
    if path_before.file_type().is_symlink() || !path_before.file_type().is_file() {
        return Err(BoundedReadError::new(
            "query_file_not_regular",
            "query file must be a non-symlink regular file",
        ));
    }

    let mut opened = open_query_file(&root, &candidate)?;
    let before = opened.file.metadata().map_err(|_| {
        BoundedReadError::new(
            "query_file_metadata_unavailable",
            "query file metadata is unavailable",
        )
    })?;
    if !before.file_type().is_file() || before.len() > max_bytes {
        return Err(BoundedReadError::new(
            "query_file_size_or_type_invalid",
            "query file type or size is invalid",
        ));
    }
    if !same_file_identity(&path_before, &before) {
        return Err(BoundedReadError::new(
            "query_file_changed_during_open",
            "query file changed while it was opened",
        ));
    }

    let capacity = usize::try_from(before.len()).map_err(|_| {
        BoundedReadError::new(
            "query_file_size_or_type_invalid",
            "query file type or size is invalid",
        )
    })?;
    let mut bytes = Vec::with_capacity(capacity);
    opened
        .file
        .by_ref()
        .take(read_limit)
        .read_to_end(&mut bytes)
        .map_err(|_| {
            BoundedReadError::new(
                "query_file_read_failed",
                "query file could not be read safely",
            )
        })?;
    let after = opened.file.metadata().map_err(|_| {
        BoundedReadError::new(
            "query_file_metadata_unavailable",
            "query file metadata is unavailable",
        )
    })?;
    let path_after = fs::symlink_metadata(&candidate).map_err(|_| {
        BoundedReadError::new(
            "query_file_changed_during_read",
            "query file changed while it was read",
        )
    })?;
    if !bounded_file_snapshot_is_stable(&before, &after, &path_after, bytes.len(), max_bytes) {
        return Err(BoundedReadError::new(
            "query_file_changed_during_read",
            "query file changed while it was read",
        ));
    }

    Ok(bytes)
}

fn confined_candidate(
    requested_root: &Path,
    canonical_root: &Path,
    query_file: &Path,
) -> Result<PathBuf, BoundedReadError> {
    if query_file
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(BoundedReadError::new(
            "query_file_parent_traversal",
            "query file path contains parent traversal",
        ));
    }
    let candidate = if query_file.is_absolute() {
        query_file
            .strip_prefix(requested_root)
            .map(|relative| canonical_root.join(relative))
            .unwrap_or_else(|_| query_file.to_path_buf())
    } else {
        canonical_root.join(query_file)
    };
    if !candidate.starts_with(canonical_root) {
        return Err(BoundedReadError::new(
            "query_file_outside_repository",
            "query file is outside the repository boundary",
        ));
    }
    Ok(candidate)
}

fn reject_symlink_components(root: &Path, candidate: &Path) -> Result<(), BoundedReadError> {
    let relative = candidate.strip_prefix(root).map_err(|_| {
        BoundedReadError::new(
            "query_file_outside_repository",
            "query file is outside the repository boundary",
        )
    })?;
    let mut current = root.to_path_buf();
    for component in relative.components() {
        match component {
            Component::Normal(name) => current.push(name),
            Component::CurDir => continue,
            _ => {
                return Err(BoundedReadError::new(
                    "query_file_path_invalid",
                    "query file path is invalid",
                ));
            }
        }
        let metadata = fs::symlink_metadata(&current).map_err(|_| {
            BoundedReadError::new("query_file_unavailable", "query file is unavailable")
        })?;
        if metadata.file_type().is_symlink() {
            return Err(BoundedReadError::new(
                "query_file_symlink_rejected",
                "query file path contains a symlink",
            ));
        }
    }
    Ok(())
}

struct OpenedQueryFile {
    file: File,
    #[cfg(windows)]
    _parent_directories: Vec<File>,
}

#[cfg(unix)]
fn open_query_file(root: &Path, path: &Path) -> Result<OpenedQueryFile, BoundedReadError> {
    use std::{
        ffi::CString,
        os::{
            fd::{AsRawFd as _, FromRawFd as _},
            unix::ffi::OsStrExt as _,
        },
    };

    let relative = path.strip_prefix(root).map_err(|_| {
        BoundedReadError::new(
            "query_file_outside_repository",
            "query file is outside the repository boundary",
        )
    })?;
    let names = relative
        .components()
        .filter_map(|component| match component {
            Component::Normal(name) => Some(name),
            Component::CurDir => None,
            _ => None,
        })
        .collect::<Vec<_>>();
    if names.is_empty() || names.len() != relative.components().count() {
        return Err(query_file_open_error());
    }

    let root_name =
        CString::new(root.as_os_str().as_bytes()).map_err(|_| query_file_open_error())?;
    // SAFETY: root_name is a valid NUL-terminated path and no ownership is
    // transferred through the open call.
    let root_fd = unsafe {
        libc::open(
            root_name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if root_fd < 0 {
        return Err(query_file_open_error());
    }
    // SAFETY: root_fd was returned uniquely by libc::open above.
    let mut directory = unsafe { File::from_raw_fd(root_fd) };
    let root_path_metadata = fs::metadata(root).map_err(|_| query_file_open_error())?;
    let root_handle_metadata = directory.metadata().map_err(|_| query_file_open_error())?;
    if !same_file_identity(&root_path_metadata, &root_handle_metadata) {
        return Err(query_file_open_error());
    }

    for (index, name) in names.iter().enumerate() {
        let name = CString::new(name.as_bytes()).map_err(|_| query_file_open_error())?;
        let is_file = index + 1 == names.len();
        let flags = libc::O_RDONLY
            | libc::O_CLOEXEC
            | libc::O_NOFOLLOW
            | if is_file { 0 } else { libc::O_DIRECTORY };
        // SAFETY: directory remains open for the call, name is NUL-terminated,
        // and openat returns a new owned descriptor on success.
        let descriptor = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags) };
        if descriptor < 0 {
            return Err(query_file_open_error());
        }
        // SAFETY: descriptor was returned uniquely by libc::openat above.
        let opened = unsafe { File::from_raw_fd(descriptor) };
        if is_file {
            return Ok(OpenedQueryFile { file: opened });
        }
        directory = opened;
    }
    Err(query_file_open_error())
}

#[cfg(windows)]
fn open_query_file(root: &Path, path: &Path) -> Result<OpenedQueryFile, BoundedReadError> {
    use std::os::windows::fs::{MetadataExt as _, OpenOptionsExt as _};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_SHARE_READ, FILE_SHARE_WRITE,
    };

    let relative = path.strip_prefix(root).map_err(|_| {
        BoundedReadError::new(
            "query_file_outside_repository",
            "query file is outside the repository boundary",
        )
    })?;
    let names = relative
        .components()
        .filter_map(|component| match component {
            Component::Normal(name) => Some(name),
            Component::CurDir => None,
            _ => None,
        })
        .collect::<Vec<_>>();
    if names.is_empty() || names.len() != relative.components().count() {
        return Err(query_file_open_error());
    }

    let mut parent_directories = Vec::with_capacity(names.len());
    let mut current = root.to_path_buf();
    let root_directory = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(&current)
        .map_err(|_| query_file_open_error())?;
    let root_metadata = root_directory
        .metadata()
        .map_err(|_| query_file_open_error())?;
    if root_metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || !root_metadata.is_dir()
    {
        return Err(query_file_open_error());
    }
    // Excluding FILE_SHARE_DELETE pins the repository root while descendants
    // are inspected and the final file is opened.
    parent_directories.push(root_directory);
    for name in &names[..names.len() - 1] {
        current.push(name);
        let directory = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&current)
            .map_err(|_| query_file_open_error())?;
        let metadata = directory.metadata().map_err(|_| query_file_open_error())?;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 || !metadata.is_dir() {
            return Err(query_file_open_error());
        }
        // Excluding FILE_SHARE_DELETE pins every opened ancestor against
        // rename or replacement until the final file has been opened.
        parent_directories.push(directory);
    }

    let file = OpenOptions::new()
        .read(true)
        .write(false)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|_| query_file_open_error())?;
    let metadata = file.metadata().map_err(|_| query_file_open_error())?;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(query_file_open_error());
    }
    Ok(OpenedQueryFile {
        file,
        _parent_directories: parent_directories,
    })
}

#[cfg(not(any(unix, windows)))]
fn open_query_file(root: &Path, path: &Path) -> Result<OpenedQueryFile, BoundedReadError> {
    let canonical = fs::canonicalize(path).map_err(|_| query_file_open_error())?;
    if !canonical.starts_with(root) {
        return Err(query_file_open_error());
    }
    OpenOptions::new()
        .read(true)
        .write(false)
        .open(&canonical)
        .map(|file| OpenedQueryFile { file })
        .map_err(|_| query_file_open_error())
}

fn query_file_open_error() -> BoundedReadError {
    BoundedReadError::new(
        "query_file_open_failed",
        "query file could not be opened safely",
    )
}

fn metadata_modified(metadata: &Metadata) -> Option<std::time::SystemTime> {
    metadata.modified().ok()
}

fn bounded_file_snapshot_is_stable(
    before: &Metadata,
    after: &Metadata,
    path_after: &Metadata,
    bytes_read: usize,
    max_bytes: u64,
) -> bool {
    u64::try_from(bytes_read).is_ok_and(|bytes_read| {
        bytes_read <= max_bytes
            && before.len() == after.len()
            && bytes_read == after.len()
            && same_file_identity(before, after)
            && same_file_identity(after, path_after)
            && metadata_modified(before) == metadata_modified(after)
    })
}

#[cfg(unix)]
fn same_file_identity(left: &Metadata, right: &Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(windows)]
fn same_file_identity(left: &Metadata, right: &Metadata) -> bool {
    use std::os::windows::fs::MetadataExt as _;

    // Rust 1.93 does not expose by-handle volume serial and file index
    // accessors on stable. Replacement is already prevented by the
    // non-delete-shared root/parent handles and the non-write/delete-shared
    // final handle, so this baseline-stable metadata comparison corroborates
    // the read snapshot without relying on a newer standard library.
    left.file_attributes() == right.file_attributes()
        && left.creation_time() == right.creation_time()
        && left.last_write_time() == right.last_write_time()
        && left.file_size() == right.file_size()
}

#[cfg(not(any(unix, windows)))]
fn same_file_identity(left: &Metadata, right: &Metadata) -> bool {
    left.len() == right.len() && metadata_modified(left) == metadata_modified(right)
}

#[cfg(test)]
mod tests {
    use std::{fs, path::Path};

    use super::{bounded_file_snapshot_is_stable, read_bounded_repository_file};

    const MAX_TEST_BYTES: u64 = 64 * 1024;

    #[test]
    fn snapshot_change_is_detected() {
        let first = tempfile::tempdir().unwrap();
        let file = first.path().join("race.depgraph");
        fs::write(&file, b"before").unwrap();
        let handle = fs::File::open(&file).unwrap();
        let before = handle.metadata().unwrap();
        handle
            .set_times(fs::FileTimes::new().set_modified(
                std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1),
            ))
            .unwrap();
        let after = handle.metadata().unwrap();
        assert!(!bounded_file_snapshot_is_stable(
            &before,
            &after,
            &after,
            after.len() as usize,
            MAX_TEST_BYTES,
        ));

        let replacement = first.path().join("replacement.depgraph");
        fs::write(&replacement, b"before").unwrap();
        let replacement_metadata = fs::metadata(&replacement).unwrap();
        assert!(!bounded_file_snapshot_is_stable(
            &after,
            &after,
            &replacement_metadata,
            after.len() as usize,
            MAX_TEST_BYTES,
        ));

        let growing = first.path().join("growing.depgraph");
        fs::write(&growing, b"before").unwrap();
        let handle = fs::File::open(&growing).unwrap();
        let before_growth = handle.metadata().unwrap();
        let mut append = fs::OpenOptions::new().append(true).open(&growing).unwrap();
        std::io::Write::write_all(&mut append, b"-after").unwrap();
        let after_growth = handle.metadata().unwrap();
        let path_after_growth = fs::metadata(&growing).unwrap();
        assert!(!bounded_file_snapshot_is_stable(
            &before_growth,
            &after_growth,
            &path_after_growth,
            before_growth.len() as usize,
            MAX_TEST_BYTES,
        ));
    }

    #[test]
    fn repository_file_reader_enforces_the_caller_byte_limit() {
        let repository = tempfile::tempdir().unwrap();
        let file = repository.path().join("bounded.bin");
        fs::write(&file, b"12345").unwrap();
        assert_eq!(
            read_bounded_repository_file(repository.path(), Path::new("bounded.bin"), 4)
                .unwrap_err()
                .code,
            "query_file_size_or_type_invalid"
        );
        assert_eq!(
            read_bounded_repository_file(repository.path(), Path::new("bounded.bin"), 5).unwrap(),
            b"12345"
        );
    }

    #[cfg(unix)]
    #[test]
    fn bounded_file_reader_rejects_swapped_parent_symlinks() {
        use std::os::unix::fs::symlink;

        let repository = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("outside.depgraph"), b"outside").unwrap();
        symlink(outside.path(), repository.path().join("swapped-parent")).unwrap();
        assert!(
            super::open_query_file(
                repository.path(),
                &repository.path().join("swapped-parent/outside.depgraph")
            )
            .is_err()
        );
    }
}
