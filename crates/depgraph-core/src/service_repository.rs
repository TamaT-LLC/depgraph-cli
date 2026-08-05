use std::{
    ffi::OsStr,
    fs::{self, File},
    io::{self, Read, Seek, Write},
    path::Path,
};

use crate::service::{
    DepgraphCapability, DepgraphService, DepgraphServiceError, DepgraphServiceErrorCategory,
    DepgraphServiceResult,
};

pub const MAX_REPOSITORY_PATH_BYTES: usize = 4_096;
pub const MAX_REPOSITORY_PATH_COMPONENTS: usize = 256;
pub const MAX_REPOSITORY_PATH_COMPONENT_BYTES: usize = 255;

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum RepositoryPathError {
    #[error("path must not be empty")]
    Empty,
    #[error("path contains a NUL byte")]
    Nul,
    #[error("path must be repository-relative")]
    Absolute,
    #[error("path contains a platform-specific prefix")]
    PlatformPrefix,
    #[error("path must use forward-slash separators")]
    PlatformSeparator,
    #[error("path must not select a platform-specific file stream")]
    PlatformStream,
    #[error("path component has a platform-specific trailing alias")]
    PlatformAlias,
    #[error("path component names a platform-specific device")]
    PlatformDevice,
    #[error("path contains an empty component")]
    EmptyComponent,
    #[error("path contains a dot component")]
    DotComponent,
    #[error("path contains a parent component")]
    ParentComponent,
    #[error("path exceeds the byte limit")]
    TooLong,
    #[error("path contains too many components")]
    TooManyComponents,
    #[error("path component exceeds the byte limit")]
    ComponentTooLong,
}

#[derive(Debug, thiserror::Error)]
pub enum RepositoryFileError {
    #[error("repository boundary validation failed")]
    BoundaryViolation,
    #[error("repository file was not found")]
    NotFound,
    #[error("repository output already exists")]
    AlreadyExists,
    #[error("repository file is not a regular file")]
    NotRegular,
    #[error("repository filesystem is unavailable")]
    Unavailable {
        #[source]
        source: io::Error,
    },
}

impl RepositoryFileError {
    pub(crate) const fn category(&self) -> DepgraphServiceErrorCategory {
        match self {
            Self::NotFound => DepgraphServiceErrorCategory::NotFound,
            Self::AlreadyExists => DepgraphServiceErrorCategory::Conflict,
            Self::BoundaryViolation | Self::NotRegular => DepgraphServiceErrorCategory::Integrity,
            Self::Unavailable { .. } => DepgraphServiceErrorCategory::Internal,
        }
    }
}

impl From<RepositoryPathError> for DepgraphServiceError {
    fn from(reason: RepositoryPathError) -> Self {
        Self::InvalidRepositoryPath { reason }
    }
}

impl From<RepositoryFileError> for DepgraphServiceError {
    fn from(reason: RepositoryFileError) -> Self {
        Self::RepositoryFile { reason }
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RepositoryRelativePath {
    normalized: String,
}

impl RepositoryRelativePath {
    pub fn parse(path: impl AsRef<str>) -> DepgraphServiceResult<Self> {
        let path = path.as_ref();
        validate_repository_path(path)?;
        Ok(Self {
            normalized: path.to_owned(),
        })
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.normalized
    }

    fn components(&self) -> impl Iterator<Item = &str> {
        self.normalized.split('/')
    }

    #[cfg(not(any(unix, windows)))]
    fn join_to(&self, root: &Path) -> std::path::PathBuf {
        let mut candidate = root.to_path_buf();
        candidate.extend(self.components());
        candidate
    }
}

impl std::fmt::Display for RepositoryRelativePath {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.normalized)
    }
}

impl std::str::FromStr for RepositoryRelativePath {
    type Err = DepgraphServiceError;

    fn from_str(path: &str) -> Result<Self, Self::Err> {
        Self::parse(path)
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RepositoryPathSelector {
    path: RepositoryRelativePath,
}

impl RepositoryPathSelector {
    pub fn parse(selector: impl AsRef<str>) -> DepgraphServiceResult<Self> {
        let path = selector
            .as_ref()
            .strip_prefix("path:")
            .ok_or(DepgraphServiceError::InvalidInput)?;
        Ok(Self {
            path: RepositoryRelativePath::parse(path)?,
        })
    }

    #[must_use]
    pub fn path(&self) -> &str {
        self.path.as_str()
    }
}

impl std::fmt::Display for RepositoryPathSelector {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "path:{}", self.path)
    }
}

#[derive(Debug)]
pub struct OpenedRepositoryFile {
    relative_path: RepositoryRelativePath,
    file: File,
}

impl OpenedRepositoryFile {
    #[must_use]
    pub fn relative_path(&self) -> &RepositoryRelativePath {
        &self.relative_path
    }

    #[must_use]
    pub const fn file(&self) -> &File {
        &self.file
    }

    pub fn file_mut(&mut self) -> &mut File {
        &mut self.file
    }

    #[must_use]
    pub fn into_file(self) -> File {
        self.file
    }
}

impl Read for OpenedRepositoryFile {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.file.read(buffer)
    }
}

impl Write for OpenedRepositoryFile {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.file.write(buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

impl Seek for OpenedRepositoryFile {
    fn seek(&mut self, position: io::SeekFrom) -> io::Result<u64> {
        self.file.seek(position)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RepositoryFileIdentity {
    namespace: u64,
    object: u64,
}

impl DepgraphService {
    pub fn normalize_repository_path(
        &self,
        path: impl AsRef<str>,
    ) -> DepgraphServiceResult<RepositoryRelativePath> {
        RepositoryRelativePath::parse(path)
    }

    pub fn normalize_path_selector(
        &self,
        selector: impl AsRef<str>,
    ) -> DepgraphServiceResult<RepositoryPathSelector> {
        RepositoryPathSelector::parse(selector)
    }

    pub fn open_repository_input(
        &self,
        path: impl AsRef<str>,
    ) -> DepgraphServiceResult<OpenedRepositoryFile> {
        let path = RepositoryRelativePath::parse(path)?;
        self.open_normalized_repository_input(&path)
    }

    pub fn open_normalized_repository_input(
        &self,
        path: &RepositoryRelativePath,
    ) -> DepgraphServiceResult<OpenedRepositoryFile> {
        let file = open_repository_input(self, path)?;
        Ok(OpenedRepositoryFile {
            relative_path: path.clone(),
            file,
        })
    }

    pub fn create_repository_output(
        &self,
        path: impl AsRef<str>,
    ) -> DepgraphServiceResult<OpenedRepositoryFile> {
        let path = RepositoryRelativePath::parse(path)?;
        if !self
            .config()
            .capabilities()
            .contains(DepgraphCapability::RepositoryWrite)
        {
            return Err(DepgraphServiceError::CapabilityDenied {
                required: DepgraphCapability::RepositoryWrite,
            });
        }
        let file = create_repository_output(self, &path)?;
        Ok(OpenedRepositoryFile {
            relative_path: path,
            file,
        })
    }
}

fn validate_repository_path(path: &str) -> Result<(), RepositoryPathError> {
    if path.is_empty() {
        return Err(RepositoryPathError::Empty);
    }
    if path.as_bytes().contains(&0) {
        return Err(RepositoryPathError::Nul);
    }
    if path.len() > MAX_REPOSITORY_PATH_BYTES {
        return Err(RepositoryPathError::TooLong);
    }
    if path.starts_with('/') {
        return Err(RepositoryPathError::Absolute);
    }
    let bytes = path.as_bytes();
    if path.starts_with('\\')
        || (bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':')
    {
        return Err(RepositoryPathError::PlatformPrefix);
    }
    if path.contains('\\') {
        return Err(RepositoryPathError::PlatformSeparator);
    }

    let mut component_count = 0_usize;
    for component in path.split('/') {
        component_count = component_count
            .checked_add(1)
            .ok_or(RepositoryPathError::TooManyComponents)?;
        if component_count > MAX_REPOSITORY_PATH_COMPONENTS {
            return Err(RepositoryPathError::TooManyComponents);
        }
        if component.is_empty() {
            return Err(RepositoryPathError::EmptyComponent);
        }
        if component == "." {
            return Err(RepositoryPathError::DotComponent);
        }
        if component == ".." {
            return Err(RepositoryPathError::ParentComponent);
        }
        // Keep the wire-level path grammar portable and prevent NTFS alternate
        // data stream selectors such as `public.txt:private` from reaching
        // Windows handle-relative opens.
        if component.contains(':') {
            return Err(RepositoryPathError::PlatformStream);
        }
        // Win32 strips trailing spaces and dots while resolving ordinary paths,
        // which could turn a lexically distinct component into `.` or `..`.
        if component.ends_with(' ') || component.ends_with('.') {
            return Err(RepositoryPathError::PlatformAlias);
        }
        // DOS devices remain reserved case-insensitively even when followed by
        // an extension (for example, `NUL.txt`). Reject them in the portable
        // wire grammar rather than relying on platform-specific open behavior.
        if is_windows_reserved_component(component) {
            return Err(RepositoryPathError::PlatformDevice);
        }
        if component.len() > MAX_REPOSITORY_PATH_COMPONENT_BYTES {
            return Err(RepositoryPathError::ComponentTooLong);
        }
    }
    Ok(())
}

fn is_windows_reserved_component(component: &str) -> bool {
    let stem = component
        .split_once('.')
        .map_or(component, |(stem, _extension)| stem)
        .trim_end_matches([' ', '.']);
    let stem = stem.to_ascii_uppercase();

    matches!(
        stem.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CLOCK$" | "CONIN$" | "CONOUT$"
    ) || ["COM", "LPT"].iter().any(|prefix| {
        stem.strip_prefix(prefix).is_some_and(|suffix| {
            matches!(
                suffix,
                "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
            )
        })
    })
}

#[cfg(not(any(unix, windows)))]
fn candidate_with_canonical_parent(
    service: &DepgraphService,
    path: &RepositoryRelativePath,
) -> DepgraphServiceResult<std::path::PathBuf> {
    let root = service.config().canonical_root();
    let candidate = path.join_to(root);
    let parent = candidate
        .parent()
        .ok_or(RepositoryFileError::BoundaryViolation)?;
    let canonical_parent = fs::canonicalize(parent).map_err(map_filesystem_error)?;
    if canonical_parent != parent || !canonical_parent.starts_with(root) {
        return Err(RepositoryFileError::BoundaryViolation.into());
    }
    Ok(candidate)
}

fn map_filesystem_error(source: io::Error) -> DepgraphServiceError {
    if source.kind() == io::ErrorKind::NotFound {
        RepositoryFileError::NotFound.into()
    } else {
        RepositoryFileError::Unavailable { source }.into()
    }
}

fn map_open_component_error(source: io::Error) -> DepgraphServiceError {
    #[cfg(unix)]
    if matches!(source.raw_os_error(), Some(libc::ELOOP | libc::ENOTDIR)) {
        return RepositoryFileError::BoundaryViolation.into();
    }
    #[cfg(windows)]
    if source.raw_os_error().is_some_and(|error| {
        use windows_sys::Win32::Foundation::{
            ERROR_CANT_ACCESS_FILE, ERROR_CANT_RESOLVE_FILENAME, ERROR_DIRECTORY,
            ERROR_INVALID_REPARSE_DATA, ERROR_REPARSE_POINT_ENCOUNTERED, ERROR_REPARSE_TAG_INVALID,
            ERROR_REPARSE_TAG_MISMATCH, ERROR_STOPPED_ON_SYMLINK,
        };

        [
            ERROR_CANT_ACCESS_FILE,
            ERROR_CANT_RESOLVE_FILENAME,
            ERROR_DIRECTORY,
            ERROR_INVALID_REPARSE_DATA,
            ERROR_REPARSE_POINT_ENCOUNTERED,
            ERROR_REPARSE_TAG_INVALID,
            ERROR_REPARSE_TAG_MISMATCH,
            ERROR_STOPPED_ON_SYMLINK,
        ]
        .contains(&(error as u32))
    }) {
        return RepositoryFileError::BoundaryViolation.into();
    }
    map_filesystem_error(source)
}

#[cfg(unix)]
fn validate_opened_regular_file(
    file: &File,
    parent: &File,
    name: &OsStr,
) -> DepgraphServiceResult<()> {
    let metadata = file.metadata().map_err(map_filesystem_error)?;
    if !metadata.file_type().is_file() {
        return Err(RepositoryFileError::NotRegular.into());
    }
    let path_handle = open_unix_at(parent, name, false)?;
    if identity_from_file(file)? != identity_from_file(&path_handle)? {
        return Err(RepositoryFileError::BoundaryViolation.into());
    }
    Ok(())
}

#[cfg(unix)]
pub(crate) fn repository_root_identity(
    canonical_root: &Path,
) -> DepgraphServiceResult<RepositoryFileIdentity> {
    let root = open_unix_root(canonical_root)?;
    let metadata = root.metadata().map_err(map_filesystem_error)?;
    if !metadata.is_dir() {
        return Err(RepositoryFileError::BoundaryViolation.into());
    }
    identity_from_file(&root)
}

#[cfg(unix)]
fn open_repository_input(
    service: &DepgraphService,
    path: &RepositoryRelativePath,
) -> DepgraphServiceResult<File> {
    open_unix_repository_input_after_root(service, path, || {})
}

#[cfg(unix)]
fn open_unix_repository_input_after_root(
    service: &DepgraphService,
    path: &RepositoryRelativePath,
    after_root_opened: impl FnOnce(),
) -> DepgraphServiceResult<File> {
    use std::os::fd::FromRawFd as _;

    let mut parent = open_unix_root(service.config().canonical_root())?;
    if identity_from_file(&parent)? != *service.config().root_identity() {
        return Err(RepositoryFileError::BoundaryViolation.into());
    }
    after_root_opened();
    let components = path.components().collect::<Vec<_>>();
    for component in &components[..components.len() - 1] {
        parent = open_unix_at(&parent, OsStr::new(component), true)?;
    }
    let final_name = OsStr::new(components.last().expect("validated path has a component"));
    let descriptor = open_unix_descriptor(
        &parent,
        final_name,
        libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        None,
    )?;
    // SAFETY: descriptor is newly owned after a successful openat call.
    let file = unsafe { File::from_raw_fd(descriptor) };
    validate_opened_regular_file(&file, &parent, final_name)?;
    Ok(file)
}

#[cfg(unix)]
fn create_repository_output(
    service: &DepgraphService,
    path: &RepositoryRelativePath,
) -> DepgraphServiceResult<File> {
    open_unix_repository_output_after_root(service, path, || {})
}

#[cfg(unix)]
fn open_unix_repository_output_after_root(
    service: &DepgraphService,
    path: &RepositoryRelativePath,
    after_root_opened: impl FnOnce(),
) -> DepgraphServiceResult<File> {
    use std::os::fd::FromRawFd as _;

    let mut parent = open_unix_root(service.config().canonical_root())?;
    if identity_from_file(&parent)? != *service.config().root_identity() {
        return Err(RepositoryFileError::BoundaryViolation.into());
    }
    after_root_opened();
    let components = path.components().collect::<Vec<_>>();
    for component in &components[..components.len() - 1] {
        parent = open_unix_at(&parent, OsStr::new(component), true)?;
    }
    let final_name = OsStr::new(components.last().expect("validated path has a component"));
    let descriptor = match open_unix_descriptor(
        &parent,
        final_name,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        Some(0o600),
    ) {
        Ok(descriptor) => descriptor,
        Err(DepgraphServiceError::RepositoryFile {
            reason: RepositoryFileError::Unavailable { source },
        }) if source.kind() == io::ErrorKind::AlreadyExists => {
            return classify_unix_existing_output(&parent, final_name);
        }
        Err(error) => return Err(error),
    };
    // SAFETY: descriptor is newly owned after a successful openat call.
    let file = unsafe { File::from_raw_fd(descriptor) };
    validate_opened_regular_file(&file, &parent, final_name)?;
    Ok(file)
}

#[cfg(unix)]
fn classify_unix_existing_output(parent: &File, name: &OsStr) -> DepgraphServiceResult<File> {
    use std::{ffi::CString, mem::MaybeUninit, os::fd::AsRawFd as _, os::unix::ffi::OsStrExt as _};

    let name = CString::new(name.as_bytes()).map_err(|_| RepositoryFileError::BoundaryViolation)?;
    let mut metadata = MaybeUninit::<libc::stat>::zeroed();
    // SAFETY: parent remains open, name is NUL-terminated, and metadata points
    // to writable storage. AT_SYMLINK_NOFOLLOW inspects the directory entry.
    let result = unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            metadata.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result != 0 {
        return Err(RepositoryFileError::BoundaryViolation.into());
    }
    // SAFETY: a successful fstatat call initialized the complete structure.
    let metadata = unsafe { metadata.assume_init() };
    if metadata.st_mode & libc::S_IFMT == libc::S_IFLNK {
        Err(RepositoryFileError::BoundaryViolation.into())
    } else {
        Err(RepositoryFileError::AlreadyExists.into())
    }
}

#[cfg(unix)]
fn open_unix_root(root: &Path) -> DepgraphServiceResult<File> {
    use std::{ffi::CString, os::fd::FromRawFd as _, os::unix::ffi::OsStrExt as _};

    let root = CString::new(root.as_os_str().as_bytes())
        .map_err(|_| RepositoryFileError::BoundaryViolation)?;
    // SAFETY: root is NUL-terminated and open returns a newly owned descriptor.
    let descriptor = unsafe {
        libc::open(
            root.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if descriptor < 0 {
        return Err(map_open_component_error(io::Error::last_os_error()));
    }
    // SAFETY: descriptor is newly owned after a successful open call.
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

#[cfg(unix)]
fn open_unix_at(parent: &File, name: &OsStr, directory: bool) -> DepgraphServiceResult<File> {
    use std::os::fd::FromRawFd as _;

    let flags = libc::O_RDONLY
        | libc::O_CLOEXEC
        | libc::O_NOFOLLOW
        | if directory { libc::O_DIRECTORY } else { 0 };
    let descriptor = open_unix_descriptor(parent, name, flags, None)?;
    // SAFETY: descriptor is newly owned after a successful openat call.
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

#[cfg(unix)]
fn open_unix_descriptor(
    parent: &File,
    name: &OsStr,
    flags: i32,
    mode: Option<libc::mode_t>,
) -> DepgraphServiceResult<i32> {
    use std::{ffi::CString, os::fd::AsRawFd as _, os::unix::ffi::OsStrExt as _};

    let name = CString::new(name.as_bytes())
        .map_err(|_| DepgraphServiceError::from(RepositoryFileError::BoundaryViolation))?;
    // SAFETY: parent is open for the call, name is NUL-terminated, and the
    // optional mode is supplied exactly when O_CREAT is present.
    let descriptor = unsafe {
        mode.map_or_else(
            || libc::openat(parent.as_raw_fd(), name.as_ptr(), flags),
            |mode| {
                libc::openat(
                    parent.as_raw_fd(),
                    name.as_ptr(),
                    flags,
                    libc::c_uint::from(mode),
                )
            },
        )
    };
    if descriptor < 0 {
        return Err(map_open_component_error(io::Error::last_os_error()));
    }
    Ok(descriptor)
}

#[cfg(unix)]
fn identity_from_file(file: &File) -> DepgraphServiceResult<RepositoryFileIdentity> {
    let metadata = file.metadata().map_err(map_filesystem_error)?;
    Ok(identity_from_metadata(&metadata))
}

#[cfg(unix)]
fn identity_from_metadata(metadata: &fs::Metadata) -> RepositoryFileIdentity {
    use std::os::unix::fs::MetadataExt as _;

    RepositoryFileIdentity {
        namespace: metadata.dev(),
        object: metadata.ino(),
    }
}

#[cfg(windows)]
pub(crate) fn repository_root_identity(
    canonical_root: &Path,
) -> DepgraphServiceResult<RepositoryFileIdentity> {
    let root = open_windows_directory(canonical_root, false)?;
    identity_from_file(&root)
}

#[cfg(windows)]
fn open_repository_input(
    service: &DepgraphService,
    path: &RepositoryRelativePath,
) -> DepgraphServiceResult<File> {
    open_windows_repository_input_after_root(service, path, || {})
}

#[cfg(windows)]
fn create_repository_output(
    service: &DepgraphService,
    path: &RepositoryRelativePath,
) -> DepgraphServiceResult<File> {
    open_windows_repository_output_after_root(service, path, || {})
}

#[cfg(windows)]
fn open_windows_repository_input_after_root(
    service: &DepgraphService,
    path: &RepositoryRelativePath,
    after_parents_opened: impl FnOnce(),
) -> DepgraphServiceResult<File> {
    use windows_sys::{
        Wdk::Storage::FileSystem::FILE_OPEN,
        Win32::Storage::FileSystem::{FILE_GENERIC_READ, FILE_SHARE_READ},
    };

    let traversal = open_windows_parent(service, path, false, after_parents_opened)?;
    validate_windows_directories(&traversal.directories)?;
    let file = open_windows_at(
        traversal.parent(),
        traversal.final_name,
        FILE_GENERIC_READ,
        FILE_SHARE_READ,
        FILE_OPEN,
        Some(false),
    )?;
    validate_opened_windows_regular_file(&file)?;
    validate_windows_directories(&traversal.directories)?;
    Ok(file)
}

#[cfg(windows)]
fn open_windows_repository_output_after_root(
    service: &DepgraphService,
    path: &RepositoryRelativePath,
    after_parents_opened: impl FnOnce(),
) -> DepgraphServiceResult<File> {
    use windows_sys::{
        Wdk::Storage::FileSystem::FILE_CREATE,
        Win32::Storage::FileSystem::{FILE_GENERIC_WRITE, FILE_SHARE_READ},
    };

    let traversal = open_windows_parent(service, path, true, after_parents_opened)?;
    validate_windows_directories(&traversal.directories)?;
    let file = match open_windows_at(
        traversal.parent(),
        traversal.final_name,
        FILE_GENERIC_WRITE,
        FILE_SHARE_READ,
        FILE_CREATE,
        Some(false),
    ) {
        Ok(file) => file,
        Err(DepgraphServiceError::RepositoryFile {
            reason: RepositoryFileError::Unavailable { source },
        }) if source.kind() == io::ErrorKind::AlreadyExists => {
            return classify_windows_existing_output(traversal.parent(), traversal.final_name);
        }
        Err(error) => return Err(error),
    };
    validate_opened_windows_regular_file(&file)?;
    validate_windows_directories(&traversal.directories)?;
    Ok(file)
}

#[cfg(windows)]
struct WindowsTraversal<'a> {
    directories: Vec<File>,
    final_name: &'a OsStr,
}

#[cfg(windows)]
impl WindowsTraversal<'_> {
    fn parent(&self) -> &File {
        self.directories
            .last()
            .expect("a traversal always retains its root handle")
    }
}

#[cfg(windows)]
fn open_windows_parent<'a>(
    service: &DepgraphService,
    path: &'a RepositoryRelativePath,
    create_output: bool,
    after_parents_opened: impl FnOnce(),
) -> DepgraphServiceResult<WindowsTraversal<'a>> {
    let root = service.config().canonical_root();
    let components = path.components().collect::<Vec<_>>();
    let root = open_windows_directory(root, create_output && components.len() == 1)?;
    if identity_from_file(&root)? != *service.config().root_identity() {
        return Err(RepositoryFileError::BoundaryViolation.into());
    }
    let mut directories = vec![root];
    for (index, component) in components[..components.len() - 1].iter().enumerate() {
        let directory = open_windows_directory_at(
            directories
                .last()
                .expect("a traversal always retains its root handle"),
            OsStr::new(component),
            create_output && index == components.len() - 2,
        )?;
        directories.push(directory);
    }
    after_parents_opened();
    let final_name = components
        .last()
        .copied()
        .expect("validated path has a component");
    Ok(WindowsTraversal {
        directories,
        final_name: OsStr::new(final_name),
    })
}

#[cfg(windows)]
fn open_windows_directory(path: &Path, create_child: bool) -> DepgraphServiceResult<File> {
    use std::os::windows::fs::{MetadataExt as _, OpenOptionsExt as _};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ADD_FILE, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE,
        FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TRAVERSE, SYNCHRONIZE,
    };

    let access = FILE_LIST_DIRECTORY
        | FILE_TRAVERSE
        | FILE_READ_ATTRIBUTES
        | SYNCHRONIZE
        | if create_child { FILE_ADD_FILE } else { 0 };
    let directory = fs::OpenOptions::new()
        .access_mode(access)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(map_open_component_error)?;
    let metadata = directory.metadata().map_err(map_filesystem_error)?;
    if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(RepositoryFileError::BoundaryViolation.into());
    }
    Ok(directory)
}

#[cfg(windows)]
fn open_windows_directory_at(
    parent: &File,
    name: &OsStr,
    create_child: bool,
) -> DepgraphServiceResult<File> {
    use windows_sys::{
        Wdk::Storage::FileSystem::FILE_OPEN,
        Win32::Storage::FileSystem::{
            FILE_ADD_FILE, FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE,
            FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TRAVERSE, SYNCHRONIZE,
        },
    };

    let access = FILE_LIST_DIRECTORY
        | FILE_TRAVERSE
        | FILE_READ_ATTRIBUTES
        | SYNCHRONIZE
        | if create_child { FILE_ADD_FILE } else { 0 };
    let directory = open_windows_at(
        parent,
        name,
        access,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN,
        Some(true),
    )?;
    validate_windows_directory(&directory)?;
    Ok(directory)
}

#[cfg(windows)]
fn validate_windows_directory(directory: &File) -> DepgraphServiceResult<()> {
    use std::os::windows::fs::MetadataExt as _;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

    let metadata = directory.metadata().map_err(map_filesystem_error)?;
    if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(RepositoryFileError::BoundaryViolation.into());
    }
    Ok(())
}

#[cfg(windows)]
fn validate_windows_directories(directories: &[File]) -> DepgraphServiceResult<()> {
    for directory in directories {
        validate_windows_directory(directory)?;
    }
    Ok(())
}

#[cfg(windows)]
fn open_windows_at(
    parent: &File,
    name: &OsStr,
    desired_access: u32,
    share_access: u32,
    create_disposition: u32,
    directory: Option<bool>,
) -> DepgraphServiceResult<File> {
    use std::{
        mem::{self, MaybeUninit},
        os::windows::{ffi::OsStrExt as _, io::AsRawHandle as _, io::FromRawHandle as _},
        ptr,
    };
    use windows_sys::{
        Wdk::{
            Foundation::OBJECT_ATTRIBUTES,
            Storage::FileSystem::{
                FILE_DIRECTORY_FILE, FILE_NON_DIRECTORY_FILE, FILE_OPEN_REPARSE_POINT,
                FILE_SYNCHRONOUS_IO_NONALERT, NtCreateFile,
            },
        },
        Win32::{
            Foundation::{OBJ_CASE_INSENSITIVE, RtlNtStatusToDosError, UNICODE_STRING},
            Storage::FileSystem::FILE_ATTRIBUTE_NORMAL,
            System::IO::IO_STATUS_BLOCK,
        },
    };

    let mut encoded_name = name.encode_wide().collect::<Vec<_>>();
    let byte_length = encoded_name
        .len()
        .checked_mul(mem::size_of::<u16>())
        .and_then(|length| u16::try_from(length).ok())
        .ok_or(RepositoryFileError::BoundaryViolation)?;
    let unicode_name = UNICODE_STRING {
        Length: byte_length,
        MaximumLength: byte_length,
        Buffer: encoded_name.as_mut_ptr(),
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: u32::try_from(mem::size_of::<OBJECT_ATTRIBUTES>())
            .expect("OBJECT_ATTRIBUTES size fits in u32"),
        RootDirectory: parent.as_raw_handle(),
        ObjectName: &unicode_name,
        Attributes: OBJ_CASE_INSENSITIVE,
        SecurityDescriptor: ptr::null(),
        SecurityQualityOfService: ptr::null(),
    };
    let mut handle = ptr::null_mut();
    let mut io_status = MaybeUninit::<IO_STATUS_BLOCK>::zeroed();
    let type_option = match directory {
        Some(true) => FILE_DIRECTORY_FILE,
        Some(false) => FILE_NON_DIRECTORY_FILE,
        None => 0,
    };
    // SAFETY: all pointers remain valid for the call, RootDirectory is an open
    // directory handle, and a successful call returns one newly owned handle.
    let status = unsafe {
        NtCreateFile(
            &mut handle,
            desired_access,
            &attributes,
            io_status.as_mut_ptr(),
            ptr::null(),
            FILE_ATTRIBUTE_NORMAL,
            share_access,
            create_disposition,
            type_option | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
            ptr::null(),
            0,
        )
    };
    if status < 0 {
        // SAFETY: converting an NTSTATUS does not require additional invariants.
        let error = unsafe { RtlNtStatusToDosError(status) };
        return Err(map_open_component_error(io::Error::from_raw_os_error(
            error as i32,
        )));
    }
    if handle.is_null() {
        return Err(RepositoryFileError::BoundaryViolation.into());
    }
    // SAFETY: a successful NtCreateFile call returned one newly owned handle.
    Ok(unsafe { File::from_raw_handle(handle) })
}

#[cfg(windows)]
fn identity_from_file(file: &File) -> DepgraphServiceResult<RepositoryFileIdentity> {
    use std::mem::MaybeUninit;
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
    };

    let mut information = MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::zeroed();
    // SAFETY: the raw handle remains owned by file and information points to
    // writable storage for the duration of the API call.
    let success =
        unsafe { GetFileInformationByHandle(file.as_raw_handle(), information.as_mut_ptr()) };
    if success == 0 {
        return Err(map_filesystem_error(io::Error::last_os_error()));
    }
    // SAFETY: a successful API call initialized the complete structure.
    let information = unsafe { information.assume_init() };
    Ok(RepositoryFileIdentity {
        namespace: u64::from(information.dwVolumeSerialNumber),
        object: (u64::from(information.nFileIndexHigh) << 32)
            | u64::from(information.nFileIndexLow),
    })
}

#[cfg(windows)]
fn validate_opened_windows_regular_file(file: &File) -> DepgraphServiceResult<()> {
    use std::os::windows::fs::MetadataExt as _;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

    let metadata = file.metadata().map_err(map_filesystem_error)?;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(RepositoryFileError::BoundaryViolation.into());
    }
    if !metadata.is_file() {
        return Err(RepositoryFileError::NotRegular.into());
    }
    Ok(())
}

#[cfg(windows)]
fn classify_windows_existing_output(parent: &File, name: &OsStr) -> DepgraphServiceResult<File> {
    use std::os::windows::fs::MetadataExt as _;
    use windows_sys::{
        Wdk::Storage::FileSystem::FILE_OPEN,
        Win32::Storage::FileSystem::{
            FILE_ATTRIBUTE_REPARSE_POINT, FILE_READ_ATTRIBUTES, FILE_SHARE_READ, FILE_SHARE_WRITE,
            SYNCHRONIZE,
        },
    };

    let existing = match open_windows_at(
        parent,
        name,
        FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_OPEN,
        None,
    ) {
        Ok(existing) => existing,
        Err(_) => return Err(RepositoryFileError::BoundaryViolation.into()),
    };
    let metadata = existing.metadata().map_err(map_filesystem_error)?;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        Err(RepositoryFileError::BoundaryViolation.into())
    } else {
        Err(RepositoryFileError::AlreadyExists.into())
    }
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn repository_root_identity(
    canonical_root: &Path,
) -> DepgraphServiceResult<RepositoryFileIdentity> {
    identity_from_path(canonical_root)
}

#[cfg(not(any(unix, windows)))]
fn open_repository_input(
    service: &DepgraphService,
    path: &RepositoryRelativePath,
) -> DepgraphServiceResult<File> {
    let candidate = candidate_with_canonical_parent(service, path)?;
    let canonical = fs::canonicalize(&candidate).map_err(map_filesystem_error)?;
    if canonical != candidate || !canonical.starts_with(service.config().canonical_root()) {
        return Err(RepositoryFileError::BoundaryViolation.into());
    }
    let file = File::open(&canonical).map_err(map_filesystem_error)?;
    if !file.metadata().map_err(map_filesystem_error)?.is_file() {
        return Err(RepositoryFileError::NotRegular.into());
    }
    Ok(file)
}

#[cfg(not(any(unix, windows)))]
fn create_repository_output(
    service: &DepgraphService,
    path: &RepositoryRelativePath,
) -> DepgraphServiceResult<File> {
    let candidate = candidate_with_canonical_parent(service, path)?;
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(candidate)
        .map_err(|source| {
            if source.kind() == io::ErrorKind::AlreadyExists {
                RepositoryFileError::AlreadyExists.into()
            } else {
                map_filesystem_error(source)
            }
        })
}

#[cfg(not(any(unix, windows)))]
fn identity_from_path(path: &Path) -> DepgraphServiceResult<RepositoryFileIdentity> {
    let metadata = fs::metadata(path).map_err(map_filesystem_error)?;
    let modified = metadata
        .modified()
        .ok()
        .and_then(|time| time.duration_since(std::time::SystemTime::UNIX_EPOCH).ok())
        .map_or(0, |duration| duration.as_nanos() as u64);
    Ok(RepositoryFileIdentity {
        namespace: metadata.len(),
        object: modified,
    })
}

#[cfg(not(any(unix, windows)))]
fn identity_from_file(file: &File) -> DepgraphServiceResult<RepositoryFileIdentity> {
    let metadata = file.metadata().map_err(map_filesystem_error)?;
    let modified = metadata
        .modified()
        .ok()
        .and_then(|time| time.duration_since(std::time::SystemTime::UNIX_EPOCH).ok())
        .map_or(0, |duration| duration.as_nanos() as u64);
    Ok(RepositoryFileIdentity {
        namespace: metadata.len(),
        object: modified,
    })
}

#[cfg(not(any(unix, windows)))]
fn identity_from_metadata(metadata: &fs::Metadata) -> RepositoryFileIdentity {
    let modified = metadata
        .modified()
        .ok()
        .and_then(|time| time.duration_since(std::time::SystemTime::UNIX_EPOCH).ok())
        .map_or(0, |duration| duration.as_nanos() as u64);
    RepositoryFileIdentity {
        namespace: metadata.len(),
        object: modified,
    }
}

#[cfg(test)]
mod tests {
    use std::{io::Read as _, path::Path};

    use super::*;
    use crate::service::{DepgraphCapabilitySet, DepgraphServiceConfig, DepgraphServiceLimits};

    fn read_only_service(root: &Path, store_path: &Path) -> DepgraphService {
        let config = DepgraphServiceConfig::new(
            root,
            store_path,
            DepgraphCapabilitySet::read_only(),
            DepgraphServiceLimits::default(),
        )
        .expect("test service configuration is valid");
        DepgraphService::new(config)
    }

    #[cfg(windows)]
    fn repository_write_service(root: &Path, store_path: &Path) -> DepgraphService {
        let capabilities = DepgraphCapabilitySet::try_new([
            DepgraphCapability::Read,
            DepgraphCapability::RepositoryWrite,
        ])
        .expect("test capabilities are valid");
        let config = DepgraphServiceConfig::new(
            root,
            store_path,
            capabilities,
            DepgraphServiceLimits::default(),
        )
        .expect("test service configuration is valid");
        DepgraphService::new(config)
    }

    #[cfg(unix)]
    #[test]
    fn unix_handle_relative_input_stays_with_root_across_enclosing_ancestor_swap() {
        let temporary = tempfile::tempdir().expect("temporary directory is available");
        let enclosing = temporary.path().join("enclosing");
        let moved_enclosing = temporary.path().join("moved-enclosing");
        let root = enclosing.join("repository");
        let cache = temporary.path().join("cache");
        fs::create_dir_all(root.join("nested")).expect("original repository is created");
        fs::create_dir_all(&cache).expect("cache directory is created");
        fs::write(root.join("nested/input.txt"), b"original").expect("original input is created");
        let service = read_only_service(&root, &cache.join("graph.db"));
        let path = RepositoryRelativePath::parse("nested/input.txt")
            .expect("test path is repository-relative");

        let mut file = open_unix_repository_input_after_root(&service, &path, || {
            fs::rename(&enclosing, &moved_enclosing).expect("enclosing ancestor can be moved");
            fs::create_dir_all(root.join("nested")).expect("replacement repository is created");
            fs::write(root.join("nested/input.txt"), b"replacement")
                .expect("replacement input is created");
        })
        .expect("handle-relative traversal remains rooted in the original repository");

        let mut contents = String::new();
        file.read_to_string(&mut contents)
            .expect("opened input is readable");
        assert_eq!(contents, "original");
        assert_eq!(
            fs::read(root.join("nested/input.txt")).expect("replacement input remains readable"),
            b"replacement"
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_handle_relative_input_stays_with_root_across_enclosing_ancestor_swap() {
        let temporary = tempfile::tempdir().expect("temporary directory is available");
        let enclosing = temporary.path().join("enclosing");
        let moved_enclosing = temporary.path().join("moved-enclosing");
        let root = enclosing.join("repository");
        let cache = temporary.path().join("cache");
        fs::create_dir_all(root.join("nested")).expect("original repository is created");
        fs::create_dir_all(&cache).expect("cache directory is created");
        fs::write(root.join("nested/input.txt"), b"original").expect("original input is created");
        let service = read_only_service(&root, &cache.join("graph.db"));
        let path = RepositoryRelativePath::parse("nested/input.txt")
            .expect("test path is repository-relative");

        let mut file = open_windows_repository_input_after_root(&service, &path, || {
            fs::rename(&enclosing, &moved_enclosing).expect("enclosing ancestor can be moved");
            fs::create_dir_all(root.join("nested")).expect("replacement repository is created");
            fs::write(root.join("nested/input.txt"), b"replacement")
                .expect("replacement input is created");
        })
        .expect("handle-relative traversal remains rooted in the original repository");

        let mut contents = String::new();
        file.read_to_string(&mut contents)
            .expect("opened input is readable");
        assert_eq!(contents, "original");
        assert_eq!(
            fs::read(root.join("nested/input.txt")).expect("replacement input remains readable"),
            b"replacement"
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_handle_relative_output_ignores_replacement_absolute_tree() {
        use std::io::Write as _;

        let temporary = tempfile::tempdir().expect("temporary directory is available");
        let enclosing = temporary.path().join("enclosing");
        let moved_enclosing = temporary.path().join("moved-enclosing");
        let root = enclosing.join("repository");
        let cache = temporary.path().join("cache");
        fs::create_dir_all(root.join("nested")).expect("original repository is created");
        fs::create_dir_all(&cache).expect("cache directory is created");
        let service = repository_write_service(&root, &cache.join("graph.db"));
        let path = RepositoryRelativePath::parse("nested/output.txt")
            .expect("test path is repository-relative");

        let mut file = open_windows_repository_output_after_root(&service, &path, || {
            fs::rename(&enclosing, &moved_enclosing).expect("enclosing ancestor can be moved");
            fs::create_dir_all(root.join("nested")).expect("replacement repository is created");
        })
        .expect("handle-relative creation remains rooted in the original repository");
        file.write_all(b"original output")
            .expect("opened output is writable");
        drop(file);

        assert_eq!(
            fs::read(moved_enclosing.join("repository/nested/output.txt"))
                .expect("output was created in the original repository"),
            b"original output"
        );
        assert!(!root.join("nested/output.txt").exists());
    }
}
