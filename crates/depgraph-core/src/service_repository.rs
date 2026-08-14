use std::{
    ffi::OsStr,
    fs::{self, File},
    io::{self, Read, Seek, Write},
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::service::{
    DepgraphCapability, DepgraphMutatingContext, DepgraphMutatingUseCase,
    DepgraphMutatingUseCaseKind, DepgraphService, DepgraphServiceError,
    DepgraphServiceErrorCategory, DepgraphServiceResult, OPERATION_JOURNAL_SUFFIX,
    RUNNER_PURGE_LOCK_SUFFIX,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RepositoryInitRequest {
    force: bool,
}

impl RepositoryInitRequest {
    #[must_use]
    pub const fn new(force: bool) -> Self {
        Self { force }
    }

    #[must_use]
    pub const fn force(self) -> bool {
        self.force
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepositoryInitResult {
    output_path: RepositoryRelativePath,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RepositoryOverwritePolicy {
    NoReplace,
    Overwrite,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum RepositoryOutputPrecondition {
    Missing,
    Regular {
        identity_sha256: String,
        output_bytes: u64,
        content_sha256: String,
    },
}

impl RepositoryOutputPrecondition {
    fn validate(&self) -> DepgraphServiceResult<()> {
        match self {
            Self::Missing => Ok(()),
            Self::Regular {
                identity_sha256,
                content_sha256,
                ..
            } if is_lower_sha256(identity_sha256) && is_lower_sha256(content_sha256) => Ok(()),
            Self::Regular { .. } => Err(DepgraphServiceError::Integrity),
        }
    }
}

#[derive(Clone, Debug)]
pub struct ExportFileRequest {
    graph: crate::service::GraphExportRequest,
    output_path: RepositoryRelativePath,
    overwrite: RepositoryOverwritePolicy,
    raw_compatible: bool,
    destination_precondition: Option<RepositoryOutputPrecondition>,
}

impl ExportFileRequest {
    #[must_use]
    pub const fn new(
        graph: crate::service::GraphExportRequest,
        output_path: RepositoryRelativePath,
        overwrite: RepositoryOverwritePolicy,
    ) -> Self {
        Self {
            graph,
            output_path,
            overwrite,
            raw_compatible: false,
            destination_precondition: None,
        }
    }

    #[must_use]
    pub const fn raw_compatible(
        graph: crate::service::GraphExportRequest,
        output_path: RepositoryRelativePath,
        overwrite: RepositoryOverwritePolicy,
    ) -> Self {
        Self {
            graph,
            output_path,
            overwrite,
            raw_compatible: true,
            destination_precondition: None,
        }
    }

    #[must_use]
    pub fn with_destination_precondition(
        mut self,
        destination_precondition: RepositoryOutputPrecondition,
    ) -> Self {
        self.destination_precondition = Some(destination_precondition);
        self
    }

    #[must_use]
    pub const fn graph(&self) -> &crate::service::GraphExportRequest {
        &self.graph
    }

    #[must_use]
    pub const fn output_path(&self) -> &RepositoryRelativePath {
        &self.output_path
    }

    #[must_use]
    pub const fn overwrite(&self) -> RepositoryOverwritePolicy {
        self.overwrite
    }

    #[must_use]
    pub const fn destination_precondition(&self) -> Option<&RepositoryOutputPrecondition> {
        self.destination_precondition.as_ref()
    }

    pub(crate) const fn is_raw_compatible(&self) -> bool {
        self.raw_compatible
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExportFileResult {
    output_path: RepositoryRelativePath,
    format: crate::service::GraphExportFormat,
    output_bytes: u64,
    content_sha256: String,
}

#[derive(Clone)]
pub struct DeferredExportFileCompletion {
    service: DepgraphService,
    staging_path: RepositoryRelativePath,
    result: ExportFileResult,
    snapshot_id: String,
    overwrite: RepositoryOverwritePolicy,
    destination_precondition: RepositoryOutputPrecondition,
}

pub struct DeferredExportFileRecovery<'a> {
    pub operation_id: &'a str,
    pub output_path: &'a RepositoryRelativePath,
    pub overwrite: RepositoryOverwritePolicy,
    pub format: crate::service::GraphExportFormat,
    pub output_bytes: u64,
    pub content_sha256: &'a str,
    pub destination_precondition: Option<&'a RepositoryOutputPrecondition>,
}

impl DeferredExportFileCompletion {
    #[must_use]
    pub const fn result(&self) -> &ExportFileResult {
        &self.result
    }

    #[must_use]
    pub fn snapshot_id(&self) -> &str {
        &self.snapshot_id
    }

    #[must_use]
    pub const fn destination_precondition(&self) -> &RepositoryOutputPrecondition {
        &self.destination_precondition
    }

    pub fn cancel(self) -> DepgraphServiceResult<()> {
        remove_staged_export_if_owned(&self.service, &self.staging_path, &self.result)
    }

    pub fn promote(self) -> DepgraphServiceResult<()> {
        let mut staging = open_repository_input(&self.service, &self.staging_path)?;
        let capacity = usize::try_from(self.result.output_bytes)
            .map_err(|_| DepgraphServiceError::Integrity)?;
        if capacity > self.service.config().limits().max_output_bytes() {
            return Err(DepgraphServiceError::Integrity);
        }
        let mut content = Vec::with_capacity(capacity);
        let bounded_bytes = self
            .result
            .output_bytes
            .checked_add(1)
            .ok_or(DepgraphServiceError::ResourceExhausted)?;
        Read::take(&mut staging, bounded_bytes)
            .read_to_end(&mut content)
            .map_err(map_filesystem_error)?;
        if content.len() != capacity
            || hex::encode(Sha256::digest(&content)) != self.result.content_sha256
        {
            return Err(RepositoryFileError::BoundaryViolation.into());
        }
        drop(staging);
        verify_repository_output_precondition(
            &self.service,
            &self.result.output_path,
            &self.destination_precondition,
            &crate::CancellationToken::new(),
        )?;
        write_repository_file_atomically(
            &self.service,
            &self.result.output_path,
            self.overwrite,
            Some(&self.destination_precondition),
            &crate::CancellationToken::new(),
            |file| file.write_all(&content).map_err(map_filesystem_error),
        )?;
        remove_staged_export(&self.service, &self.staging_path, &self.result)
    }
}

impl ExportFileResult {
    #[must_use]
    pub const fn output_path(&self) -> &RepositoryRelativePath {
        &self.output_path
    }

    #[must_use]
    pub const fn format(&self) -> crate::service::GraphExportFormat {
        self.format
    }

    #[must_use]
    pub const fn output_bytes(&self) -> u64 {
        self.output_bytes
    }

    #[must_use]
    pub fn content_sha256(&self) -> &str {
        &self.content_sha256
    }
}

impl RepositoryInitResult {
    #[must_use]
    pub const fn output_path(&self) -> &RepositoryRelativePath {
        &self.output_path
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RepositoryFileIdentity {
    namespace: u64,
    object: u64,
}

impl RepositoryFileIdentity {
    pub(crate) fn opaque_bytes(&self) -> [u8; 16] {
        let mut bytes = [0_u8; 16];
        bytes[..8].copy_from_slice(&self.namespace.to_le_bytes());
        bytes[8..].copy_from_slice(&self.object.to_le_bytes());
        bytes
    }
}

impl DepgraphService {
    pub fn recover_deferred_export_file_completion(
        &self,
        recovery: &DeferredExportFileRecovery<'_>,
    ) -> DepgraphServiceResult<()> {
        if !self
            .config()
            .capabilities()
            .contains(DepgraphCapability::RepositoryWrite)
        {
            return Err(DepgraphServiceError::CapabilityDenied {
                required: DepgraphCapability::RepositoryWrite,
            });
        }
        validate_repository_output_not_protected(self, recovery.output_path)?;
        if recovery.output_bytes == 0 {
            return Err(DepgraphServiceError::InvalidInput);
        }
        if recovery.output_bytes > self.config().limits().max_output_bytes() as u64 {
            return Err(DepgraphServiceError::ResourceExhausted);
        }
        if !is_lower_sha256(recovery.content_sha256) {
            return Err(DepgraphServiceError::Integrity);
        }
        let result = ExportFileResult {
            output_path: recovery.output_path.clone(),
            format: recovery.format,
            output_bytes: recovery.output_bytes,
            content_sha256: recovery.content_sha256.to_owned(),
        };
        let staging_path = export_staging_path(recovery.output_path, recovery.operation_id)?;
        validate_repository_output_not_persistent_state(self, &staging_path)?;
        let destination_precondition = match recovery.destination_precondition {
            Some(precondition) => {
                precondition.validate()?;
                precondition.clone()
            }
            None if recovery.overwrite == RepositoryOverwritePolicy::NoReplace => {
                RepositoryOutputPrecondition::Missing
            }
            None => return Err(DepgraphServiceError::Integrity),
        };
        match repository_file_matches(self, recovery.output_path, &result) {
            Ok(true) => remove_staged_export_if_owned(self, &staging_path, &result),
            Ok(false) if recovery.overwrite == RepositoryOverwritePolicy::Overwrite => {
                DeferredExportFileCompletion {
                    service: self.clone(),
                    staging_path,
                    result,
                    snapshot_id: String::new(),
                    overwrite: recovery.overwrite,
                    destination_precondition,
                }
                .promote()
            }
            Ok(false) => Err(DepgraphServiceError::Integrity),
            Err(DepgraphServiceError::RepositoryFile {
                reason: RepositoryFileError::NotFound,
            }) => DeferredExportFileCompletion {
                service: self.clone(),
                staging_path,
                result,
                snapshot_id: String::new(),
                overwrite: recovery.overwrite,
                destination_precondition,
            }
            .promote(),
            Err(error) => Err(error),
        }
    }

    pub fn export_file_deferred_for_operation(
        &self,
        request: &ExportFileRequest,
        operation_id: &str,
        cancellation: &crate::CancellationToken,
    ) -> DepgraphServiceResult<DeferredExportFileCompletion> {
        if !self
            .config()
            .capabilities()
            .contains(DepgraphCapability::RepositoryWrite)
        {
            return Err(DepgraphServiceError::CapabilityDenied {
                required: DepgraphCapability::RepositoryWrite,
            });
        }
        validate_repository_output_not_protected(self, request.output_path())?;
        let staging_path = export_staging_path(request.output_path(), operation_id)?;
        validate_repository_output_not_persistent_state(self, &staging_path)?;
        let destination_precondition = match request.destination_precondition() {
            Some(precondition) => {
                precondition.validate()?;
                verify_repository_output_precondition(
                    self,
                    request.output_path(),
                    precondition,
                    cancellation,
                )?;
                precondition.clone()
            }
            None => repository_output_precondition(self, request.output_path(), cancellation)?,
        };
        if request.overwrite() == RepositoryOverwritePolicy::NoReplace
            && destination_precondition != RepositoryOutputPrecondition::Missing
        {
            return Err(RepositoryFileError::AlreadyExists.into());
        }
        let rendered = if request.is_raw_compatible() {
            self.graph_export_raw_compatible(request.graph(), cancellation)?
        } else {
            self.graph_export(request.graph(), cancellation)?
        };
        if cancellation.is_cancelled() {
            return Err(DepgraphServiceError::Cancelled);
        }
        let result = ExportFileResult {
            output_path: request.output_path().clone(),
            format: rendered.format,
            output_bytes: rendered.output_bytes,
            content_sha256: rendered.content_sha256,
        };
        let mut staging = match create_repository_output(self, &staging_path) {
            Ok(staging) => staging,
            Err(DepgraphServiceError::RepositoryFile {
                reason: RepositoryFileError::AlreadyExists,
            }) => {
                return match repository_file_matches(self, &staging_path, &result) {
                    Ok(true) => Ok(DeferredExportFileCompletion {
                        service: self.clone(),
                        staging_path,
                        result,
                        snapshot_id: rendered.snapshot_id,
                        overwrite: request.overwrite(),
                        destination_precondition,
                    }),
                    Ok(false) => Err(DepgraphServiceError::Integrity),
                    Err(error) => Err(error),
                };
            }
            Err(error) => return Err(error),
        };
        if let Err(error) = staging
            .write_all(rendered.content.as_bytes())
            .map_err(map_filesystem_error)
            .and_then(|()| {
                staging
                    .sync_all()
                    .map_err(|source| RepositoryFileError::Unavailable { source }.into())
            })
        {
            drop(staging);
            let _ = remove_repository_entry(self, &staging_path);
            return Err(error);
        }
        drop(staging);
        sync_repository_parent(self, &staging_path)?;
        if cancellation.is_cancelled() {
            remove_staged_export(self, &staging_path, &result)?;
            return Err(DepgraphServiceError::Cancelled);
        }
        Ok(DeferredExportFileCompletion {
            service: self.clone(),
            staging_path,
            result,
            snapshot_id: rendered.snapshot_id,
            overwrite: request.overwrite(),
            destination_precondition,
        })
    }

    pub fn cancel_deferred_export_file_for_operation(
        &self,
        request: &ExportFileRequest,
        operation_id: &str,
        cancellation: &crate::CancellationToken,
    ) -> DepgraphServiceResult<()> {
        if !self
            .config()
            .capabilities()
            .contains(DepgraphCapability::RepositoryWrite)
        {
            return Err(DepgraphServiceError::CapabilityDenied {
                required: DepgraphCapability::RepositoryWrite,
            });
        }
        validate_repository_output_not_protected(self, request.output_path())?;
        let staging_path = export_staging_path(request.output_path(), operation_id)?;
        validate_repository_output_not_persistent_state(self, &staging_path)?;
        match open_repository_input(self, &staging_path) {
            Ok(staging) => drop(staging),
            Err(DepgraphServiceError::RepositoryFile {
                reason: RepositoryFileError::NotFound,
            }) => return Ok(()),
            Err(DepgraphServiceError::RepositoryFile {
                reason: RepositoryFileError::BoundaryViolation,
            }) => return Ok(()),
            Err(DepgraphServiceError::RepositoryFile {
                reason: RepositoryFileError::NotRegular,
            }) => return Ok(()),
            Err(error) => return Err(error),
        }
        let rendered = if request.is_raw_compatible() {
            self.graph_export_raw_compatible(request.graph(), cancellation)
        } else {
            self.graph_export(request.graph(), cancellation)
        }?;
        let result = ExportFileResult {
            output_path: request.output_path().clone(),
            format: rendered.format,
            output_bytes: rendered.output_bytes,
            content_sha256: rendered.content_sha256,
        };
        remove_staged_export_if_owned(self, &staging_path, &result)
    }

    pub fn export_file(
        &self,
        request: &ExportFileRequest,
        cancellation: &crate::CancellationToken,
    ) -> DepgraphServiceResult<ExportFileResult> {
        if !self
            .config()
            .capabilities()
            .contains(DepgraphCapability::RepositoryWrite)
        {
            return Err(DepgraphServiceError::CapabilityDenied {
                required: DepgraphCapability::RepositoryWrite,
            });
        }
        validate_repository_output_not_protected(self, request.output_path())?;
        let destination_precondition = match request.destination_precondition() {
            Some(precondition) => {
                precondition.validate()?;
                verify_repository_output_precondition(
                    self,
                    request.output_path(),
                    precondition,
                    cancellation,
                )?;
                precondition.clone()
            }
            None => repository_output_precondition(self, request.output_path(), cancellation)?,
        };
        if request.overwrite() == RepositoryOverwritePolicy::NoReplace
            && destination_precondition != RepositoryOutputPrecondition::Missing
        {
            return Err(RepositoryFileError::AlreadyExists.into());
        }
        let rendered = if request.is_raw_compatible() {
            self.graph_export_raw_compatible(request.graph(), cancellation)?
        } else {
            self.graph_export(request.graph(), cancellation)?
        };
        self.execute_mutating(ExportFilePublicationUseCase {
            service: self,
            output_path: request.output_path(),
            overwrite: request.overwrite(),
            content: rendered.content.as_bytes(),
            destination_precondition: Some(&destination_precondition),
            cancellation,
        })?;
        Ok(ExportFileResult {
            output_path: request.output_path().clone(),
            format: rendered.format,
            output_bytes: rendered.output_bytes,
            content_sha256: rendered.content_sha256,
        })
    }

    pub fn export_rendered_file(
        &self,
        output_path: &RepositoryRelativePath,
        overwrite: RepositoryOverwritePolicy,
        format: crate::service::GraphExportFormat,
        content: &[u8],
        cancellation: &crate::CancellationToken,
    ) -> DepgraphServiceResult<ExportFileResult> {
        if !self
            .config()
            .capabilities()
            .contains(DepgraphCapability::RepositoryWrite)
        {
            return Err(DepgraphServiceError::CapabilityDenied {
                required: DepgraphCapability::RepositoryWrite,
            });
        }
        if content.is_empty() {
            return Err(DepgraphServiceError::InvalidInput);
        }
        validate_repository_output_not_protected(self, output_path)?;
        if content.len() > self.config().limits().max_output_bytes() {
            return Err(DepgraphServiceError::ResourceExhausted);
        }
        self.execute_mutating(ExportFilePublicationUseCase {
            service: self,
            output_path,
            overwrite,
            content,
            destination_precondition: None,
            cancellation,
        })?;
        Ok(ExportFileResult {
            output_path: output_path.clone(),
            format,
            output_bytes: u64::try_from(content.len())
                .map_err(|_| DepgraphServiceError::ResourceExhausted)?,
            content_sha256: hex::encode(Sha256::digest(content)),
        })
    }

    pub fn repository_output_precondition(
        &self,
        path: &RepositoryRelativePath,
        cancellation: &crate::CancellationToken,
    ) -> DepgraphServiceResult<RepositoryOutputPrecondition> {
        if !self
            .config()
            .capabilities()
            .contains(DepgraphCapability::RepositoryWrite)
        {
            return Err(DepgraphServiceError::CapabilityDenied {
                required: DepgraphCapability::RepositoryWrite,
            });
        }
        repository_output_precondition(self, path, cancellation)
    }

    pub fn repository_init(
        &self,
        request: &RepositoryInitRequest,
        cancellation: &crate::CancellationToken,
    ) -> DepgraphServiceResult<RepositoryInitResult> {
        if cancellation.is_cancelled() {
            return Err(DepgraphServiceError::Cancelled);
        }
        self.execute_mutating(RepositoryInitUseCase {
            service: self,
            request: *request,
            cancellation,
        })
    }

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
        validate_repository_output_not_protected(self, &path)?;
        let file = create_repository_output(self, &path)?;
        Ok(OpenedRepositoryFile {
            relative_path: path,
            file,
        })
    }
}

struct ExportFilePublicationUseCase<'a> {
    service: &'a DepgraphService,
    output_path: &'a RepositoryRelativePath,
    overwrite: RepositoryOverwritePolicy,
    content: &'a [u8],
    destination_precondition: Option<&'a RepositoryOutputPrecondition>,
    cancellation: &'a crate::CancellationToken,
}

impl DepgraphMutatingUseCase for ExportFilePublicationUseCase<'_> {
    type Output = ();

    const KIND: DepgraphMutatingUseCaseKind = DepgraphMutatingUseCaseKind::Repository;

    fn execute(
        self,
        _context: &mut DepgraphMutatingContext<'_>,
    ) -> DepgraphServiceResult<Self::Output> {
        let destination_precondition = match self.destination_precondition {
            Some(precondition) => precondition.clone(),
            None => {
                repository_output_precondition(self.service, self.output_path, self.cancellation)?
            }
        };
        write_repository_file_atomically(
            self.service,
            self.output_path,
            self.overwrite,
            Some(&destination_precondition),
            self.cancellation,
            |file| file.write_all(self.content).map_err(map_filesystem_error),
        )
    }
}

struct RepositoryInitUseCase<'a> {
    service: &'a DepgraphService,
    request: RepositoryInitRequest,
    cancellation: &'a crate::CancellationToken,
}

impl DepgraphMutatingUseCase for RepositoryInitUseCase<'_> {
    type Output = RepositoryInitResult;

    const KIND: DepgraphMutatingUseCaseKind = DepgraphMutatingUseCaseKind::Repository;

    fn execute(
        self,
        _context: &mut DepgraphMutatingContext<'_>,
    ) -> DepgraphServiceResult<Self::Output> {
        let path = RepositoryRelativePath::parse(crate::config::CONFIG_FILE)?;
        let contents =
            crate::config::Config::render_default().map_err(|_| DepgraphServiceError::Internal)?;
        let destination_precondition =
            repository_output_precondition(self.service, &path, self.cancellation)?;
        write_repository_file_atomically(
            self.service,
            &path,
            if self.request.force {
                RepositoryOverwritePolicy::Overwrite
            } else {
                RepositoryOverwritePolicy::NoReplace
            },
            Some(&destination_precondition),
            self.cancellation,
            |file| {
                file.write_all(contents.as_bytes())
                    .map_err(map_filesystem_error)
            },
        )?;
        Ok(RepositoryInitResult { output_path: path })
    }
}

fn write_repository_file_atomically(
    service: &DepgraphService,
    path: &RepositoryRelativePath,
    overwrite: RepositoryOverwritePolicy,
    expected_precondition: Option<&RepositoryOutputPrecondition>,
    cancellation: &crate::CancellationToken,
    write_contents: impl FnOnce(&mut File) -> DepgraphServiceResult<()>,
) -> DepgraphServiceResult<()> {
    if cancellation.is_cancelled() {
        return Err(DepgraphServiceError::Cancelled);
    }
    validate_repository_output_not_protected(service, path)?;
    write_repository_file_atomically_platform(
        service,
        path,
        overwrite,
        expected_precondition,
        cancellation,
        write_contents,
    )
}

fn validate_repository_output_not_protected(
    service: &DepgraphService,
    path: &RepositoryRelativePath,
) -> DepgraphServiceResult<()> {
    validate_repository_output_not_persistent_state(service, path)?;
    if is_reserved_export_staging_path(path) {
        return Err(DepgraphServiceError::Integrity);
    }
    Ok(())
}

fn is_reserved_export_staging_path(path: &RepositoryRelativePath) -> bool {
    let name = path.as_str().rsplit('/').next().unwrap_or_default();
    const PREFIX: &[u8] = b".depgraph-export-";
    let bytes = name.as_bytes();
    if bytes.len() != PREFIX.len() + 64 || !bytes[..PREFIX.len()].eq_ignore_ascii_case(PREFIX) {
        return false;
    }
    bytes[PREFIX.len()..]
        .iter()
        .all(|byte| byte.is_ascii_hexdigit())
}

fn validate_repository_output_not_persistent_state(
    service: &DepgraphService,
    path: &RepositoryRelativePath,
) -> DepgraphServiceResult<()> {
    let output = service.config().canonical_root().join(path.as_str());
    for protected in protected_repository_state_paths(service) {
        if repository_paths_equal(&output, &protected)? {
            return Err(DepgraphServiceError::Integrity);
        }
    }
    Ok(())
}

fn protected_repository_state_paths(service: &DepgraphService) -> Vec<PathBuf> {
    let store = service.config().store_path().to_path_buf();
    let mut journal = store.as_os_str().to_os_string();
    journal.push(OPERATION_JOURNAL_SUFFIX);
    let journal = PathBuf::from(journal);
    let mut runner_purge_lock = journal.as_os_str().to_os_string();
    runner_purge_lock.push(RUNNER_PURGE_LOCK_SUFFIX);
    let mut paths = vec![
        store.clone(),
        journal.clone(),
        PathBuf::from(runner_purge_lock),
    ];
    for protected in [store, journal] {
        for suffix in ["-wal", "-shm", "-journal"] {
            let mut sidecar = protected.as_os_str().to_os_string();
            sidecar.push(suffix);
            paths.push(PathBuf::from(sidecar));
        }
    }
    paths
}

#[cfg(any(unix, windows))]
fn validate_opened_repository_output_not_persistent_state(
    service: &DepgraphService,
    parent: &File,
    final_name: &OsStr,
) -> DepgraphServiceResult<()> {
    let protected_parent = service
        .config()
        .store_path()
        .parent()
        .ok_or(DepgraphServiceError::Integrity)?;
    let protects_this_parent = match service.config().store_parent_identity() {
        Some(expected_identity) => identity_from_file(parent)? == *expected_identity,
        None => protected_parent.starts_with(service.config().canonical_root()),
    };
    if !protects_this_parent {
        return Ok(());
    }
    for protected in protected_repository_state_paths(service) {
        let protected_name = protected
            .file_name()
            .ok_or(DepgraphServiceError::Integrity)?;
        if repository_output_names_equal(final_name, protected_name)? {
            return Err(DepgraphServiceError::Integrity);
        }
    }
    Ok(())
}

#[cfg(unix)]
fn repository_output_names_equal(left: &OsStr, right: &OsStr) -> DepgraphServiceResult<bool> {
    Ok(repository_file_names_equivalent(left, right))
}

#[cfg(windows)]
fn repository_output_names_equal(left: &OsStr, right: &OsStr) -> DepgraphServiceResult<bool> {
    repository_paths_equal(Path::new(left), Path::new(right))
}

#[cfg(unix)]
fn repository_paths_equal(left: &Path, right: &Path) -> DepgraphServiceResult<bool> {
    use std::os::unix::fs::MetadataExt as _;

    if left == right {
        return Ok(true);
    }
    let metadata = |path: &Path| -> DepgraphServiceResult<Option<fs::Metadata>> {
        match fs::metadata(path) {
            Ok(metadata) => Ok(Some(metadata)),
            Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(source) => Err(RepositoryFileError::Unavailable { source }.into()),
        }
    };
    let left_metadata = metadata(left)?;
    let right_metadata = metadata(right)?;
    if matches!(
        (&left_metadata, &right_metadata),
        (Some(left), Some(right)) if left.dev() == right.dev() && left.ino() == right.ino()
    ) {
        return Ok(true);
    }

    let (Some(left_parent), Some(right_parent), Some(left_name), Some(right_name)) = (
        left.parent(),
        right.parent(),
        left.file_name(),
        right.file_name(),
    ) else {
        return Ok(false);
    };
    let (Some(left_parent), Some(right_parent)) = (metadata(left_parent)?, metadata(right_parent)?)
    else {
        return Ok(false);
    };
    Ok(left_parent.dev() == right_parent.dev()
        && left_parent.ino() == right_parent.ino()
        && repository_file_names_equivalent(left_name, right_name))
}

#[cfg(unix)]
fn repository_file_names_equivalent(left: &OsStr, right: &OsStr) -> bool {
    use std::os::unix::ffi::OsStrExt as _;

    match (left.to_str(), right.to_str()) {
        (Some(left), Some(right)) => caseless::canonical_caseless_match_str(left, right),
        _ => left.as_bytes().eq_ignore_ascii_case(right.as_bytes()),
    }
}

#[cfg(not(any(unix, windows)))]
fn repository_paths_equal(left: &Path, right: &Path) -> DepgraphServiceResult<bool> {
    Ok(left == right)
}

#[cfg(windows)]
fn repository_paths_equal(left: &Path, right: &Path) -> DepgraphServiceResult<bool> {
    use std::os::windows::ffi::OsStrExt as _;
    use windows_sys::Win32::Globalization::{CSTR_EQUAL, CompareStringOrdinal};

    let left = left.as_os_str().encode_wide().collect::<Vec<_>>();
    let right = right.as_os_str().encode_wide().collect::<Vec<_>>();
    let left_len = i32::try_from(left.len()).map_err(|_| DepgraphServiceError::Integrity)?;
    let right_len = i32::try_from(right.len()).map_err(|_| DepgraphServiceError::Integrity)?;
    // SAFETY: both pointers remain valid for their explicit UTF-16 lengths.
    let ordering =
        unsafe { CompareStringOrdinal(left.as_ptr(), left_len, right.as_ptr(), right_len, 1) };
    if ordering == 0 {
        return Err(DepgraphServiceError::Integrity);
    }
    Ok(ordering == CSTR_EQUAL)
}

fn export_staging_path(
    output_path: &RepositoryRelativePath,
    operation_id: &str,
) -> DepgraphServiceResult<RepositoryRelativePath> {
    if operation_id.is_empty()
        || operation_id.len() > 128
        || !operation_id
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err(DepgraphServiceError::InvalidInput);
    }
    let mut digest = Sha256::new();
    digest.update(b"depgraph-export-staging-v1\0");
    digest.update(operation_id.as_bytes());
    digest.update(b"\0");
    digest.update(output_path.as_str().as_bytes());
    let staging_name = format!(".depgraph-export-{}", hex::encode(digest.finalize()));
    let staging_path = output_path
        .as_str()
        .rsplit_once('/')
        .map_or(staging_name.clone(), |(parent, _)| {
            format!("{parent}/{staging_name}")
        });
    RepositoryRelativePath::parse(staging_path)
}

fn remove_staged_export(
    service: &DepgraphService,
    staging_path: &RepositoryRelativePath,
    result: &ExportFileResult,
) -> DepgraphServiceResult<()> {
    remove_staged_export_after_validation(service, staging_path, result, || {})
}

fn remove_staged_export_if_owned(
    service: &DepgraphService,
    staging_path: &RepositoryRelativePath,
    result: &ExportFileResult,
) -> DepgraphServiceResult<()> {
    match remove_staged_export(service, staging_path, result) {
        Ok(())
        | Err(DepgraphServiceError::RepositoryFile {
            reason:
                RepositoryFileError::NotFound
                | RepositoryFileError::BoundaryViolation
                | RepositoryFileError::NotRegular,
        })
        | Err(DepgraphServiceError::Integrity) => Ok(()),
        Err(error) => Err(error),
    }
}

fn remove_staged_export_after_validation(
    service: &DepgraphService,
    staging_path: &RepositoryRelativePath,
    result: &ExportFileResult,
    after_validation: impl FnOnce(),
) -> DepgraphServiceResult<()> {
    let mut staging = open_repository_input(service, staging_path)?;
    let expected_identity = identity_from_file(&staging)?;
    let metadata = staging.metadata().map_err(map_filesystem_error)?;
    if metadata.len() != result.output_bytes {
        return Err(RepositoryFileError::BoundaryViolation.into());
    }
    let digest = hash_exact_bounded(
        &mut staging,
        result.output_bytes,
        service.config().limits().max_output_bytes(),
        &crate::CancellationToken::new(),
    )?;
    if digest.as_deref() != Some(result.content_sha256.as_str()) {
        return Err(RepositoryFileError::BoundaryViolation.into());
    }
    after_validation();
    drop(staging);
    remove_repository_entry_if_identity(service, staging_path, &expected_identity)?;
    sync_repository_parent(service, staging_path)
}

fn repository_file_matches(
    service: &DepgraphService,
    path: &RepositoryRelativePath,
    result: &ExportFileResult,
) -> DepgraphServiceResult<bool> {
    let mut file = open_repository_input(service, path)?;
    if file.metadata().map_err(map_filesystem_error)?.len() != result.output_bytes {
        return Ok(false);
    }
    Ok(hash_exact_bounded(
        &mut file,
        result.output_bytes,
        service.config().limits().max_output_bytes(),
        &crate::CancellationToken::new(),
    )?
    .as_deref()
        == Some(result.content_sha256.as_str()))
}

fn hash_exact_bounded(
    reader: &mut impl Read,
    expected_bytes: u64,
    maximum_bytes: usize,
    cancellation: &crate::CancellationToken,
) -> DepgraphServiceResult<Option<String>> {
    let maximum_bytes =
        u64::try_from(maximum_bytes).map_err(|_| DepgraphServiceError::ResourceExhausted)?;
    if expected_bytes > maximum_bytes {
        return Err(DepgraphServiceError::ResourceExhausted);
    }
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 16 * 1024];
    let mut remaining = expected_bytes;
    while remaining != 0 {
        if cancellation.is_cancelled() {
            return Err(DepgraphServiceError::Cancelled);
        }
        let requested = usize::try_from(remaining.min(buffer.len() as u64))
            .map_err(|_| DepgraphServiceError::ResourceExhausted)?;
        let read = reader
            .read(&mut buffer[..requested])
            .map_err(map_filesystem_error)?;
        if read == 0 {
            return Ok(None);
        }
        remaining -= u64::try_from(read).map_err(|_| DepgraphServiceError::Integrity)?;
        digest.update(&buffer[..read]);
    }
    if cancellation.is_cancelled() {
        return Err(DepgraphServiceError::Cancelled);
    }
    let mut extra = [0_u8; 1];
    if reader.read(&mut extra).map_err(map_filesystem_error)? != 0 {
        return Ok(None);
    }
    Ok(Some(hex::encode(digest.finalize())))
}

fn repository_output_precondition(
    service: &DepgraphService,
    path: &RepositoryRelativePath,
    cancellation: &crate::CancellationToken,
) -> DepgraphServiceResult<RepositoryOutputPrecondition> {
    validate_repository_output_not_protected(service, path)?;
    let first = match repository_regular_file_precondition(service, path, cancellation) {
        Ok(precondition) => precondition,
        Err(DepgraphServiceError::RepositoryFile {
            reason: RepositoryFileError::NotFound,
        }) => return Ok(RepositoryOutputPrecondition::Missing),
        Err(error) => return Err(error),
    };
    let second = repository_regular_file_precondition(service, path, cancellation)?;
    if first == second {
        Ok(first)
    } else {
        Err(DepgraphServiceError::Integrity)
    }
}

fn repository_regular_file_precondition(
    service: &DepgraphService,
    path: &RepositoryRelativePath,
    cancellation: &crate::CancellationToken,
) -> DepgraphServiceResult<RepositoryOutputPrecondition> {
    let mut file = open_repository_input(service, path)?;
    repository_regular_file_precondition_from_file(service, path, &mut file, cancellation)
}

fn repository_regular_file_precondition_from_file(
    service: &DepgraphService,
    path: &RepositoryRelativePath,
    file: &mut File,
    cancellation: &crate::CancellationToken,
) -> DepgraphServiceResult<RepositoryOutputPrecondition> {
    repository_regular_file_precondition_from_file_after_metadata(
        service,
        path,
        file,
        cancellation,
        || {},
    )
}

#[cfg(test)]
fn repository_regular_file_precondition_from_file_after_metadata_for_test(
    service: &DepgraphService,
    path: &RepositoryRelativePath,
    file: &mut File,
    cancellation: &crate::CancellationToken,
    after_metadata: impl FnOnce(),
) -> DepgraphServiceResult<RepositoryOutputPrecondition> {
    repository_regular_file_precondition_from_file_after_metadata(
        service,
        path,
        file,
        cancellation,
        after_metadata,
    )
}

fn repository_regular_file_precondition_from_file_after_metadata(
    service: &DepgraphService,
    path: &RepositoryRelativePath,
    file: &mut File,
    cancellation: &crate::CancellationToken,
    after_metadata: impl FnOnce(),
) -> DepgraphServiceResult<RepositoryOutputPrecondition> {
    if cancellation.is_cancelled() {
        return Err(DepgraphServiceError::Cancelled);
    }
    let identity = identity_from_file(file)?;
    let metadata = file.metadata().map_err(map_filesystem_error)?;
    if !metadata.is_file() {
        return Err(RepositoryFileError::NotRegular.into());
    }
    let output_bytes = metadata.len();
    let maximum = u64::try_from(service.config().limits().max_output_bytes())
        .map_err(|_| DepgraphServiceError::ResourceExhausted)?;
    if output_bytes > maximum {
        return Err(DepgraphServiceError::ResourceExhausted);
    }
    after_metadata();
    file.rewind().map_err(map_filesystem_error)?;
    let content_digest = hash_exact_bounded(
        file,
        output_bytes,
        service.config().limits().max_output_bytes(),
        cancellation,
    )?
    .ok_or(DepgraphServiceError::Integrity)?;
    if file.metadata().map_err(map_filesystem_error)?.len() != output_bytes
        || identity_from_file(file)? != identity
    {
        return Err(DepgraphServiceError::Integrity);
    }
    let mut identity_digest = Sha256::new();
    identity_digest.update(b"depgraph-repository-output-identity-v1\0");
    identity_digest.update(service.config().root_identity().opaque_bytes());
    identity_digest.update(identity.opaque_bytes());
    identity_digest.update(b"\0");
    identity_digest.update(path.as_str().as_bytes());
    Ok(RepositoryOutputPrecondition::Regular {
        identity_sha256: hex::encode(identity_digest.finalize()),
        output_bytes,
        content_sha256: content_digest,
    })
}

fn verify_repository_output_precondition(
    service: &DepgraphService,
    path: &RepositoryRelativePath,
    expected: &RepositoryOutputPrecondition,
    cancellation: &crate::CancellationToken,
) -> DepgraphServiceResult<()> {
    expected.validate()?;
    if repository_output_precondition(service, path, cancellation)? == *expected {
        Ok(())
    } else {
        Err(DepgraphServiceError::Integrity)
    }
}

fn is_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(unix)]
fn remove_repository_entry(
    service: &DepgraphService,
    path: &RepositoryRelativePath,
) -> DepgraphServiceResult<()> {
    let (parent, final_name) = open_unix_repository_parent(service, path)?;
    classify_unix_publication_target(&parent, final_name, RepositoryOverwritePolicy::Overwrite)?;
    unlink_unix_at(&parent, final_name)
}

#[cfg(unix)]
fn remove_repository_entry_if_identity(
    service: &DepgraphService,
    path: &RepositoryRelativePath,
    expected_identity: &RepositoryFileIdentity,
) -> DepgraphServiceResult<()> {
    let (parent, final_name) = open_unix_repository_parent(service, path)?;
    match classify_unix_publication_target(
        &parent,
        final_name,
        RepositoryOverwritePolicy::Overwrite,
    )? {
        UnixPublicationTarget::Regular { identity, .. } if identity == *expected_identity => {
            unlink_unix_at(&parent, final_name)
        }
        UnixPublicationTarget::Missing | UnixPublicationTarget::Regular { .. } => {
            Err(DepgraphServiceError::Integrity)
        }
    }
}

#[cfg(unix)]
fn sync_repository_parent(
    service: &DepgraphService,
    path: &RepositoryRelativePath,
) -> DepgraphServiceResult<()> {
    let (parent, _) = open_unix_repository_parent(service, path)?;
    parent
        .sync_all()
        .map_err(|source| RepositoryFileError::Unavailable { source }.into())
}

#[cfg(windows)]
fn remove_repository_entry(
    service: &DepgraphService,
    path: &RepositoryRelativePath,
) -> DepgraphServiceResult<()> {
    use windows_sys::{
        Wdk::Storage::FileSystem::FILE_OPEN,
        Win32::Storage::FileSystem::{
            DELETE, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
            SYNCHRONIZE,
        },
    };

    let traversal = open_windows_parent(service, path, false, || {})?;
    validate_windows_directories(&traversal.directories)?;
    let file = open_windows_at(
        traversal.parent(),
        traversal.final_name,
        DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN,
        Some(false),
    )?;
    validate_opened_windows_regular_file(&file)?;
    delete_windows_file_handle(&file)?;
    drop(file);
    validate_windows_directories(&traversal.directories)
}

#[cfg(windows)]
fn remove_repository_entry_if_identity(
    service: &DepgraphService,
    path: &RepositoryRelativePath,
    expected_identity: &RepositoryFileIdentity,
) -> DepgraphServiceResult<()> {
    use windows_sys::{
        Wdk::Storage::FileSystem::FILE_OPEN,
        Win32::Storage::FileSystem::{
            DELETE, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
            SYNCHRONIZE,
        },
    };

    let traversal = open_windows_parent(service, path, false, || {})?;
    validate_windows_directories(&traversal.directories)?;
    let file = open_windows_at(
        traversal.parent(),
        traversal.final_name,
        DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN,
        Some(false),
    )?;
    validate_opened_windows_regular_file(&file)?;
    if identity_from_file(&file)? != *expected_identity {
        return Err(DepgraphServiceError::Integrity);
    }
    delete_windows_file_handle(&file)?;
    drop(file);
    validate_windows_directories(&traversal.directories)
}

#[cfg(not(any(unix, windows)))]
fn remove_repository_entry(
    service: &DepgraphService,
    path: &RepositoryRelativePath,
) -> DepgraphServiceResult<()> {
    if !service.config().repository_root_seal().matches_live_root() {
        return Err(RepositoryFileError::BoundaryViolation.into());
    }
    let candidate = path.join_to(service.config().canonical_root());
    let metadata = fs::symlink_metadata(&candidate).map_err(map_filesystem_error)?;
    if metadata.file_type().is_symlink() {
        return Err(RepositoryFileError::BoundaryViolation.into());
    }
    if !metadata.is_file() {
        return Err(RepositoryFileError::NotRegular.into());
    }
    fs::remove_file(candidate).map_err(map_filesystem_error)
}

#[cfg(not(any(unix, windows)))]
fn remove_repository_entry_if_identity(
    service: &DepgraphService,
    path: &RepositoryRelativePath,
    expected_identity: &RepositoryFileIdentity,
) -> DepgraphServiceResult<()> {
    let file = open_repository_input(service, path)?;
    if identity_from_file(&file)? != *expected_identity {
        return Err(DepgraphServiceError::Integrity);
    }
    drop(file);
    remove_repository_entry(service, path)
}

#[cfg(not(unix))]
fn sync_repository_parent(
    _service: &DepgraphService,
    _path: &RepositoryRelativePath,
) -> DepgraphServiceResult<()> {
    Ok(())
}

#[cfg(any(test, not(unix)))]
fn publication_policy_without_atomic_exchange(
    overwrite: RepositoryOverwritePolicy,
    expected_precondition: Option<&RepositoryOutputPrecondition>,
) -> DepgraphServiceResult<RepositoryOverwritePolicy> {
    // A check followed by unconditional replacement cannot bind a regular target's
    // content precondition to publication. Missing targets remain safe through the
    // platform's atomic no-replace primitive; existing targets fail closed.
    match (overwrite, expected_precondition) {
        (_, Some(RepositoryOutputPrecondition::Missing)) => {
            Ok(RepositoryOverwritePolicy::NoReplace)
        }
        (
            RepositoryOverwritePolicy::Overwrite,
            Some(RepositoryOutputPrecondition::Regular { .. }),
        ) => Err(DepgraphServiceError::Integrity),
        (RepositoryOverwritePolicy::Overwrite, None) => Err(DepgraphServiceError::Integrity),
        _ => Ok(overwrite),
    }
}

#[cfg(any(test, windows))]
const WINDOWS_FILE_SHARE_READ_ACCESS: u32 = 0x0000_0001;
#[cfg(any(test, windows))]
const WINDOWS_FILE_SHARE_WRITE_ACCESS: u32 = 0x0000_0002;
#[cfg(any(test, windows))]
const WINDOWS_FILE_SHARE_DELETE_ACCESS: u32 = 0x0000_0004;

#[cfg(any(test, windows))]
const fn windows_staging_share_access() -> u32 {
    // A private stage must not acquire a compatible reader that can keep a
    // legacy delete disposition alive after the writer closes. Publication
    // renames through the retained handle, so no shared access is required.
    0
}

#[cfg(any(test, windows))]
const fn windows_repository_input_share_access() -> u32 {
    WINDOWS_FILE_SHARE_READ_ACCESS
        | WINDOWS_FILE_SHARE_WRITE_ACCESS
        | WINDOWS_FILE_SHARE_DELETE_ACCESS
}

#[cfg(unix)]
struct UnixAtomicWriteHooks<BeforePrecondition, AfterClassification, BeforeRollback> {
    before_precondition: BeforePrecondition,
    after_classification: AfterClassification,
    before_rollback: BeforeRollback,
}

#[cfg(unix)]
fn write_repository_file_atomically_platform(
    service: &DepgraphService,
    path: &RepositoryRelativePath,
    overwrite: RepositoryOverwritePolicy,
    expected_precondition: Option<&RepositoryOutputPrecondition>,
    cancellation: &crate::CancellationToken,
    write_contents: impl FnOnce(&mut File) -> DepgraphServiceResult<()>,
) -> DepgraphServiceResult<()> {
    write_repository_file_atomically_platform_unix(
        service,
        path,
        overwrite,
        expected_precondition,
        cancellation,
        write_contents,
        UnixAtomicWriteHooks {
            before_precondition: || {},
            after_classification: || {},
            before_rollback: || {},
        },
    )
}

#[cfg(all(test, unix))]
fn write_repository_file_atomically_platform_before_precondition_for_test(
    service: &DepgraphService,
    path: &RepositoryRelativePath,
    overwrite: RepositoryOverwritePolicy,
    cancellation: &crate::CancellationToken,
    expected_precondition: &RepositoryOutputPrecondition,
    write_contents: impl FnOnce(&mut File) -> DepgraphServiceResult<()>,
    before_classification: impl FnOnce(),
) -> DepgraphServiceResult<()> {
    write_repository_file_atomically_platform_unix(
        service,
        path,
        overwrite,
        Some(expected_precondition),
        cancellation,
        write_contents,
        UnixAtomicWriteHooks {
            before_precondition: before_classification,
            after_classification: || {},
            before_rollback: || {},
        },
    )
}

#[cfg(all(test, unix))]
fn write_repository_file_atomically_platform_after_classification_for_test(
    service: &DepgraphService,
    path: &RepositoryRelativePath,
    overwrite: RepositoryOverwritePolicy,
    cancellation: &crate::CancellationToken,
    write_contents: impl FnOnce(&mut File) -> DepgraphServiceResult<()>,
    after_classification: impl FnOnce(),
) -> DepgraphServiceResult<()> {
    let expected_precondition = repository_output_precondition(service, path, cancellation)?;
    write_repository_file_atomically_platform_unix(
        service,
        path,
        overwrite,
        Some(&expected_precondition),
        cancellation,
        write_contents,
        UnixAtomicWriteHooks {
            before_precondition: || {},
            after_classification,
            before_rollback: || {},
        },
    )
}

#[cfg(unix)]
fn write_repository_file_atomically_platform_unix<
    BeforePrecondition,
    AfterClassification,
    BeforeRollback,
>(
    service: &DepgraphService,
    path: &RepositoryRelativePath,
    overwrite: RepositoryOverwritePolicy,
    expected_precondition: Option<&RepositoryOutputPrecondition>,
    cancellation: &crate::CancellationToken,
    write_contents: impl FnOnce(&mut File) -> DepgraphServiceResult<()>,
    hooks: UnixAtomicWriteHooks<BeforePrecondition, AfterClassification, BeforeRollback>,
) -> DepgraphServiceResult<()>
where
    BeforePrecondition: FnOnce(),
    AfterClassification: FnOnce(),
    BeforeRollback: FnOnce(),
{
    use std::{
        ffi::CString,
        os::fd::{AsRawFd as _, FromRawFd as _},
        os::unix::ffi::OsStrExt as _,
    };

    let UnixAtomicWriteHooks {
        before_precondition,
        after_classification,
        before_rollback,
    } = hooks;
    let (parent, final_name) = open_unix_repository_parent(service, path)?;
    let staging_name = format!(".depgraph-stage-{}", uuid::Uuid::new_v4().simple());
    let staging_name = OsStr::new(&staging_name);
    let descriptor = open_unix_descriptor(
        &parent,
        staging_name,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        Some(0o600),
    )?;
    // SAFETY: descriptor is newly owned after a successful openat call.
    let mut staging = unsafe { File::from_raw_fd(descriptor) };
    let staging_identity = identity_from_file(&staging)?;
    if let Err(error) = write_contents(&mut staging) {
        let _ = remove_owned_unix_staging(&parent, staging_name, staging_identity);
        return Err(error);
    }
    if cancellation.is_cancelled() {
        let _ = remove_owned_unix_staging(&parent, staging_name, staging_identity);
        return Err(DepgraphServiceError::Cancelled);
    }
    if let Err(source) = staging.sync_all() {
        let _ = remove_owned_unix_staging(&parent, staging_name, staging_identity);
        return Err(RepositoryFileError::Unavailable { source }.into());
    }
    if cancellation.is_cancelled() {
        let _ = remove_owned_unix_staging(&parent, staging_name, staging_identity);
        return Err(DepgraphServiceError::Cancelled);
    }

    before_precondition();
    if let Some(expected_precondition) = expected_precondition
        && let Err(error) = verify_repository_output_precondition(
            service,
            path,
            expected_precondition,
            cancellation,
        )
    {
        let _ = remove_owned_unix_staging(&parent, staging_name, staging_identity);
        return Err(error);
    }
    let classified = match classify_unix_publication_target(&parent, final_name, overwrite) {
        Ok(classified) => classified,
        Err(error) => {
            let _ = remove_owned_unix_staging(&parent, staging_name, staging_identity);
            return Err(error);
        }
    };
    after_classification();
    validate_unix_staging_path_identity(&parent, staging_name, staging_identity)?;
    let staging_c = CString::new(staging_name.as_bytes())
        .map_err(|_| RepositoryFileError::BoundaryViolation)?;
    let destination =
        CString::new(final_name.as_bytes()).map_err(|_| RepositoryFileError::BoundaryViolation)?;
    match classified {
        UnixPublicationTarget::Missing => {
            // SAFETY: both names are NUL-terminated and the retained directory
            // handle confines the hard-link publication to this exact parent.
            let publication = unsafe {
                libc::linkat(
                    parent.as_raw_fd(),
                    staging_c.as_ptr(),
                    parent.as_raw_fd(),
                    destination.as_ptr(),
                    0,
                )
            };
            if publication != 0 {
                let source = io::Error::last_os_error();
                let _ = remove_owned_unix_staging(&parent, staging_name, staging_identity);
                if source.kind() == io::ErrorKind::AlreadyExists {
                    return match classify_unix_publication_target(
                        &parent,
                        final_name,
                        RepositoryOverwritePolicy::Overwrite,
                    ) {
                        Ok(_) if overwrite == RepositoryOverwritePolicy::NoReplace => {
                            Err(RepositoryFileError::AlreadyExists.into())
                        }
                        Ok(_) => Err(DepgraphServiceError::Integrity),
                        Err(error) => Err(error),
                    };
                }
                return Err(RepositoryFileError::Unavailable { source }.into());
            }
            let published_identity =
                unix_entry_identity(&parent, final_name)?.ok_or(DepgraphServiceError::Integrity)?;
            if published_identity != staging_identity {
                quarantine_unix_entry(&parent, final_name, published_identity)?;
                return Err(DepgraphServiceError::Integrity);
            }
            let _ = remove_owned_unix_staging(&parent, staging_name, staging_identity);
        }
        UnixPublicationTarget::Regular {
            identity: expected_identity,
            mode: expected_mode,
        } => {
            let destination_still_matches = matches!(
                classify_unix_publication_target(
                    &parent,
                    final_name,
                    RepositoryOverwritePolicy::Overwrite,
                ),
                Ok(UnixPublicationTarget::Regular { identity, mode })
                    if identity == expected_identity && mode == expected_mode
            );
            if !destination_still_matches {
                let _ = remove_owned_unix_staging(&parent, staging_name, staging_identity);
                return Err(DepgraphServiceError::Integrity);
            }
            // Preserve access permission bits from the exact destination snapshot.
            // SAFETY: staging owns a live descriptor and expected_mode is bounded
            // to the portable access-bit mask captured by fstatat.
            if unsafe { libc::fchmod(staging.as_raw_fd(), expected_mode) } != 0 {
                let source = io::Error::last_os_error();
                let _ = remove_owned_unix_staging(&parent, staging_name, staging_identity);
                return Err(RepositoryFileError::Unavailable { source }.into());
            }
            if let Err(source) = staging.sync_all() {
                let _ = remove_owned_unix_staging(&parent, staging_name, staging_identity);
                return Err(RepositoryFileError::Unavailable { source }.into());
            }
            if cancellation.is_cancelled() {
                let _ = remove_owned_unix_staging(&parent, staging_name, staging_identity);
                return Err(DepgraphServiceError::Cancelled);
            }
            validate_unix_staging_path_identity(&parent, staging_name, staging_identity)?;
            let replacement_identity = staging_identity;
            if let Err(error) = exchange_unix_at(&parent, staging_name, final_name) {
                let _ = remove_owned_unix_staging(&parent, staging_name, staging_identity);
                return Err(error);
            }
            let published_identity =
                unix_entry_identity(&parent, final_name)?.ok_or(DepgraphServiceError::Integrity)?;
            if published_identity != replacement_identity {
                restore_unix_exchange_preserving_displaced(
                    &parent,
                    staging_name,
                    final_name,
                    expected_identity,
                    published_identity,
                )?;
                return Err(DepgraphServiceError::Integrity);
            }
            let publication_check = match classify_unix_publication_target(
                &parent,
                staging_name,
                RepositoryOverwritePolicy::Overwrite,
            ) {
                Ok(UnixPublicationTarget::Regular { identity, mode })
                    if identity == expected_identity && mode == expected_mode =>
                {
                    if let Some(expected_precondition) = expected_precondition {
                        match repository_output_precondition_unix_at(
                            service,
                            &parent,
                            staging_name,
                            path,
                            cancellation,
                        ) {
                            Ok(observed) if observed == *expected_precondition => Ok(()),
                            Ok(_) => Err(DepgraphServiceError::Integrity),
                            Err(error) => Err(error),
                        }
                    } else {
                        Ok(())
                    }
                }
                Ok(UnixPublicationTarget::Missing | UnixPublicationTarget::Regular { .. }) => {
                    Err(DepgraphServiceError::Integrity)
                }
                Err(error) => Err(error),
            };
            if let Err(error) = publication_check {
                before_rollback();
                restore_unix_exchange(
                    &parent,
                    staging_name,
                    final_name,
                    expected_identity,
                    expected_mode,
                    replacement_identity,
                )?;
                return Err(error);
            }
            let _ = remove_owned_unix_staging(&parent, staging_name, expected_identity);
        }
    }
    parent
        .sync_all()
        .map_err(|source| RepositoryFileError::Unavailable { source })?;
    Ok(())
}

#[cfg(unix)]
fn repository_output_precondition_unix_at(
    service: &DepgraphService,
    parent: &File,
    name: &OsStr,
    original_path: &RepositoryRelativePath,
    cancellation: &crate::CancellationToken,
) -> DepgraphServiceResult<RepositoryOutputPrecondition> {
    use std::os::fd::FromRawFd as _;

    let descriptor = open_unix_descriptor(
        parent,
        name,
        libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        None,
    )?;
    // SAFETY: descriptor is newly owned after a successful openat call.
    let mut file = unsafe { File::from_raw_fd(descriptor) };
    let first = repository_regular_file_precondition_from_file(
        service,
        original_path,
        &mut file,
        cancellation,
    )?;
    let second = repository_regular_file_precondition_from_file(
        service,
        original_path,
        &mut file,
        cancellation,
    )?;
    if first == second {
        Ok(first)
    } else {
        Err(DepgraphServiceError::Integrity)
    }
}

#[cfg(unix)]
fn restore_unix_exchange(
    parent: &File,
    staging_name: &OsStr,
    final_name: &OsStr,
    expected_original_identity: RepositoryFileIdentity,
    expected_mode: libc::mode_t,
    expected_replacement_identity: RepositoryFileIdentity,
) -> DepgraphServiceResult<()> {
    let staging_matches = matches!(
        classify_unix_publication_target(
            parent,
            staging_name,
            RepositoryOverwritePolicy::Overwrite,
        )?,
        UnixPublicationTarget::Regular { identity, mode }
            if identity == expected_original_identity && mode == expected_mode
    );
    let final_matches = matches!(
        classify_unix_publication_target(
            parent,
            final_name,
            RepositoryOverwritePolicy::Overwrite,
        )?,
        UnixPublicationTarget::Regular { identity, mode }
            if identity == expected_replacement_identity && mode == expected_mode
    );
    if !staging_matches || !final_matches {
        return Err(DepgraphServiceError::Integrity);
    }
    exchange_unix_at(parent, staging_name, final_name)?;
    let restored_final_matches = matches!(
        classify_unix_publication_target(
            parent,
            final_name,
            RepositoryOverwritePolicy::Overwrite,
        )?,
        UnixPublicationTarget::Regular { identity, mode }
            if identity == expected_original_identity && mode == expected_mode
    );
    let displaced_replacement_matches = matches!(
        classify_unix_publication_target(
            parent,
            staging_name,
            RepositoryOverwritePolicy::Overwrite,
        )?,
        UnixPublicationTarget::Regular { identity, mode }
            if identity == expected_replacement_identity && mode == expected_mode
    );
    if !restored_final_matches || !displaced_replacement_matches {
        return Err(DepgraphServiceError::Integrity);
    }
    remove_owned_unix_staging(parent, staging_name, expected_replacement_identity)?;
    parent
        .sync_all()
        .map_err(|source| RepositoryFileError::Unavailable { source }.into())
}

#[cfg(unix)]
fn restore_unix_exchange_preserving_displaced(
    parent: &File,
    staging_name: &OsStr,
    final_name: &OsStr,
    expected_original_identity: RepositoryFileIdentity,
    expected_displaced_identity: RepositoryFileIdentity,
) -> DepgraphServiceResult<()> {
    if unix_entry_identity(parent, staging_name)? != Some(expected_original_identity)
        || unix_entry_identity(parent, final_name)? != Some(expected_displaced_identity)
    {
        return Err(DepgraphServiceError::Integrity);
    }
    exchange_unix_at(parent, staging_name, final_name)?;
    if unix_entry_identity(parent, final_name)? != Some(expected_original_identity)
        || unix_entry_identity(parent, staging_name)? != Some(expected_displaced_identity)
    {
        return Err(DepgraphServiceError::Integrity);
    }
    parent
        .sync_all()
        .map_err(|source| RepositoryFileError::Unavailable { source }.into())
}

#[cfg(unix)]
fn exchange_unix_at(parent: &File, first: &OsStr, second: &OsStr) -> DepgraphServiceResult<()> {
    use std::{ffi::CString, os::fd::AsRawFd as _, os::unix::ffi::OsStrExt as _};

    let first = CString::new(first.as_bytes())
        .map_err(|_| DepgraphServiceError::from(RepositoryFileError::BoundaryViolation))?;
    let second = CString::new(second.as_bytes())
        .map_err(|_| DepgraphServiceError::from(RepositoryFileError::BoundaryViolation))?;
    #[cfg(target_os = "macos")]
    // SAFETY: both names are NUL-terminated and both directory descriptors
    // remain open for the atomic exchange call.
    let result = unsafe {
        libc::renameatx_np(
            parent.as_raw_fd(),
            first.as_ptr(),
            parent.as_raw_fd(),
            second.as_ptr(),
            libc::RENAME_SWAP,
        )
    };
    #[cfg(any(target_os = "linux", target_os = "android"))]
    // SAFETY: syscall arguments follow renameat2(2); names and retained parent
    // descriptors remain valid, and RENAME_EXCHANGE preserves both entries.
    let result = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            parent.as_raw_fd(),
            first.as_ptr(),
            parent.as_raw_fd(),
            second.as_ptr(),
            libc::RENAME_EXCHANGE,
        ) as libc::c_int
    };
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "android")))]
    let result = -1;
    if result == 0 {
        Ok(())
    } else {
        Err(RepositoryFileError::Unavailable {
            source: io::Error::last_os_error(),
        }
        .into())
    }
}

#[cfg(unix)]
fn open_unix_repository_parent<'a>(
    service: &DepgraphService,
    path: &'a RepositoryRelativePath,
) -> DepgraphServiceResult<(File, &'a OsStr)> {
    let mut parent = open_unix_root(service.config().canonical_root())?;
    if identity_from_file(&parent)? != *service.config().root_identity() {
        return Err(RepositoryFileError::BoundaryViolation.into());
    }
    let components = path.components().collect::<Vec<_>>();
    for component in &components[..components.len() - 1] {
        parent = open_unix_at(&parent, OsStr::new(component), true)?;
    }
    let final_name = OsStr::new(
        components
            .last()
            .copied()
            .expect("validated path has a component"),
    );
    validate_opened_repository_output_not_persistent_state(service, &parent, final_name)?;
    Ok((parent, final_name))
}

#[cfg(unix)]
enum UnixPublicationTarget {
    Missing,
    Regular {
        identity: RepositoryFileIdentity,
        mode: libc::mode_t,
    },
}

#[cfg(unix)]
fn rename_unix_at_no_replace(
    parent: &File,
    source: &OsStr,
    destination: &OsStr,
) -> DepgraphServiceResult<()> {
    use std::{ffi::CString, os::fd::AsRawFd as _, os::unix::ffi::OsStrExt as _};

    let source = CString::new(source.as_bytes())
        .map_err(|_| DepgraphServiceError::from(RepositoryFileError::BoundaryViolation))?;
    let destination = CString::new(destination.as_bytes())
        .map_err(|_| DepgraphServiceError::from(RepositoryFileError::BoundaryViolation))?;
    #[cfg(target_os = "macos")]
    // SAFETY: both names are NUL-terminated, the retained parent remains open,
    // and RENAME_EXCL guarantees that the private quarantine is not replaced.
    let result = unsafe {
        libc::renameatx_np(
            parent.as_raw_fd(),
            source.as_ptr(),
            parent.as_raw_fd(),
            destination.as_ptr(),
            libc::RENAME_EXCL,
        )
    };
    #[cfg(any(target_os = "linux", target_os = "android"))]
    // SAFETY: syscall arguments follow renameat2(2); RENAME_NOREPLACE keeps
    // both source and any unexpectedly existing destination intact on failure.
    let result = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            parent.as_raw_fd(),
            source.as_ptr(),
            parent.as_raw_fd(),
            destination.as_ptr(),
            libc::RENAME_NOREPLACE,
        ) as libc::c_int
    };
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "android")))]
    let result = -1;
    if result == 0 {
        Ok(())
    } else {
        Err(RepositoryFileError::Unavailable {
            source: io::Error::last_os_error(),
        }
        .into())
    }
}

#[cfg(unix)]
fn unix_stat_device_namespace(metadata: &libc::stat) -> DepgraphServiceResult<u64> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        Ok(metadata.st_dev)
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        u64::try_from(metadata.st_dev).map_err(|_| DepgraphServiceError::Integrity)
    }
}

#[cfg(unix)]
fn classify_unix_publication_target(
    parent: &File,
    name: &OsStr,
    overwrite: RepositoryOverwritePolicy,
) -> DepgraphServiceResult<UnixPublicationTarget> {
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
        let source = io::Error::last_os_error();
        return if source.kind() == io::ErrorKind::NotFound {
            Ok(UnixPublicationTarget::Missing)
        } else {
            Err(RepositoryFileError::Unavailable { source }.into())
        };
    }
    // SAFETY: a successful fstatat call initialized the complete structure.
    let metadata = unsafe { metadata.assume_init() };
    match metadata.st_mode & libc::S_IFMT {
        libc::S_IFLNK => Err(RepositoryFileError::BoundaryViolation.into()),
        libc::S_IFREG if overwrite == RepositoryOverwritePolicy::Overwrite => {
            Ok(UnixPublicationTarget::Regular {
                identity: RepositoryFileIdentity {
                    namespace: unix_stat_device_namespace(&metadata)?,
                    object: metadata.st_ino,
                },
                mode: metadata.st_mode & 0o777,
            })
        }
        libc::S_IFREG => Err(RepositoryFileError::AlreadyExists.into()),
        _ => Err(RepositoryFileError::NotRegular.into()),
    }
}

#[cfg(unix)]
fn unlink_unix_at(parent: &File, name: &OsStr) -> DepgraphServiceResult<()> {
    use std::{ffi::CString, os::fd::AsRawFd as _, os::unix::ffi::OsStrExt as _};

    let name = CString::new(name.as_bytes()).map_err(|_| RepositoryFileError::BoundaryViolation)?;
    // SAFETY: parent remains open and name is NUL-terminated. No flags means
    // only the named non-directory entry is removed.
    let result = unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), 0) };
    if result == 0 {
        Ok(())
    } else {
        Err(RepositoryFileError::Unavailable {
            source: io::Error::last_os_error(),
        }
        .into())
    }
}

#[cfg(unix)]
fn unix_entry_identity(
    parent: &File,
    name: &OsStr,
) -> DepgraphServiceResult<Option<RepositoryFileIdentity>> {
    use std::{ffi::CString, mem::MaybeUninit, os::fd::AsRawFd as _, os::unix::ffi::OsStrExt as _};

    let name = CString::new(name.as_bytes()).map_err(|_| RepositoryFileError::BoundaryViolation)?;
    let mut metadata = MaybeUninit::<libc::stat>::zeroed();
    // SAFETY: parent remains open, name is NUL-terminated, and metadata points
    // to writable storage. AT_SYMLINK_NOFOLLOW binds identity to the entry.
    let result = unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            metadata.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result != 0 {
        let source = io::Error::last_os_error();
        return if source.kind() == io::ErrorKind::NotFound {
            Ok(None)
        } else {
            Err(RepositoryFileError::Unavailable { source }.into())
        };
    }
    // SAFETY: a successful fstatat call initialized the complete structure.
    let metadata = unsafe { metadata.assume_init() };
    Ok(Some(RepositoryFileIdentity {
        namespace: unix_stat_device_namespace(&metadata)?,
        object: metadata.st_ino,
    }))
}

#[cfg(unix)]
fn validate_unix_staging_path_identity(
    parent: &File,
    staging_name: &OsStr,
    expected_identity: RepositoryFileIdentity,
) -> DepgraphServiceResult<()> {
    match classify_unix_publication_target(
        parent,
        staging_name,
        RepositoryOverwritePolicy::Overwrite,
    ) {
        Ok(UnixPublicationTarget::Regular { identity, .. }) if identity == expected_identity => {
            Ok(())
        }
        Ok(UnixPublicationTarget::Missing | UnixPublicationTarget::Regular { .. }) | Err(_) => {
            Err(DepgraphServiceError::Integrity)
        }
    }
}

#[cfg(unix)]
fn remove_owned_unix_staging(
    parent: &File,
    staging_name: &OsStr,
    expected_identity: RepositoryFileIdentity,
) -> DepgraphServiceResult<()> {
    remove_owned_unix_staging_with_hook(parent, staging_name, expected_identity, || {})
}

#[cfg(all(test, unix))]
fn remove_owned_unix_staging_after_identity_for_test(
    parent: &File,
    staging_name: &OsStr,
    expected_identity: RepositoryFileIdentity,
    after_identity: impl FnOnce(),
) -> DepgraphServiceResult<()> {
    remove_owned_unix_staging_with_hook(parent, staging_name, expected_identity, after_identity)
}

#[cfg(unix)]
fn remove_owned_unix_staging_with_hook(
    parent: &File,
    staging_name: &OsStr,
    expected_identity: RepositoryFileIdentity,
    after_identity: impl FnOnce(),
) -> DepgraphServiceResult<()> {
    match unix_entry_identity(parent, staging_name)? {
        Some(identity) if identity == expected_identity => {
            after_identity();
            let quarantine_name = format!(".depgraph-cleanup-{}", uuid::Uuid::new_v4().simple());
            let quarantine_name = OsStr::new(&quarantine_name);
            rename_unix_at_no_replace(parent, staging_name, quarantine_name)?;
            match unix_entry_identity(parent, quarantine_name)? {
                Some(identity) if identity == expected_identity => {
                    unlink_unix_at(parent, quarantine_name)?;
                    parent
                        .sync_all()
                        .map_err(|source| RepositoryFileError::Unavailable { source }.into())
                }
                Some(_) => {
                    // The original pathname was swapped after validation. Moving
                    // it first preserves the foreign entry; restore its name when
                    // still available, otherwise leave it quarantined.
                    let _ = rename_unix_at_no_replace(parent, quarantine_name, staging_name);
                    let _ = parent.sync_all();
                    Err(DepgraphServiceError::Integrity)
                }
                None => Err(DepgraphServiceError::Integrity),
            }
        }
        None => Ok(()),
        Some(_) => Err(DepgraphServiceError::Integrity),
    }
}

#[cfg(unix)]
fn quarantine_unix_entry(
    parent: &File,
    name: &OsStr,
    expected_identity: RepositoryFileIdentity,
) -> DepgraphServiceResult<()> {
    use std::{ffi::CString, os::fd::AsRawFd as _, os::unix::ffi::OsStrExt as _};

    if unix_entry_identity(parent, name)? != Some(expected_identity) {
        return Err(DepgraphServiceError::Integrity);
    }
    let quarantine = format!(".depgraph-rejected-{}", uuid::Uuid::new_v4().simple());
    let source =
        CString::new(name.as_bytes()).map_err(|_| RepositoryFileError::BoundaryViolation)?;
    let quarantine_c =
        CString::new(quarantine.as_bytes()).map_err(|_| RepositoryFileError::BoundaryViolation)?;
    // SAFETY: both names are NUL-terminated and the retained directory handle
    // confines the atomic rename to this exact parent.
    let result = unsafe {
        libc::renameat(
            parent.as_raw_fd(),
            source.as_ptr(),
            parent.as_raw_fd(),
            quarantine_c.as_ptr(),
        )
    };
    if result != 0 {
        return Err(RepositoryFileError::Unavailable {
            source: io::Error::last_os_error(),
        }
        .into());
    }
    if unix_entry_identity(parent, OsStr::new(&quarantine))? != Some(expected_identity) {
        return Err(DepgraphServiceError::Integrity);
    }
    parent
        .sync_all()
        .map_err(|source| RepositoryFileError::Unavailable { source }.into())
}

#[cfg(windows)]
fn write_repository_file_atomically_platform(
    service: &DepgraphService,
    path: &RepositoryRelativePath,
    overwrite: RepositoryOverwritePolicy,
    expected_precondition: Option<&RepositoryOutputPrecondition>,
    cancellation: &crate::CancellationToken,
    write_contents: impl FnOnce(&mut File) -> DepgraphServiceResult<()>,
) -> DepgraphServiceResult<()> {
    use windows_sys::{
        Wdk::Storage::FileSystem::FILE_CREATE,
        Win32::Storage::FileSystem::{DELETE, FILE_GENERIC_WRITE, FILE_READ_ATTRIBUTES},
    };

    let traversal = open_windows_parent(service, path, true, || {})?;
    validate_windows_directories(&traversal.directories)?;
    let staging_name = format!(".depgraph-stage-{}", uuid::Uuid::new_v4().simple());
    let mut staging = open_windows_at(
        traversal.parent(),
        OsStr::new(&staging_name),
        FILE_GENERIC_WRITE | FILE_READ_ATTRIBUTES | DELETE,
        windows_staging_share_access(),
        FILE_CREATE,
        Some(false),
    )?;
    if let Err(error) = validate_opened_windows_regular_file(&staging) {
        return Err(discard_windows_staging_handle_preserving_error(
            staging, error,
        ));
    }
    let staging_identity = match identity_from_file(&staging) {
        Ok(identity) => identity,
        Err(error) => {
            return Err(discard_windows_staging_handle_preserving_error(
                staging, error,
            ));
        }
    };
    let discard_staging = |staging, primary| {
        discard_windows_staging_preserving_error(
            traversal.parent(),
            OsStr::new(&staging_name),
            staging_identity,
            staging,
            primary,
        )
    };
    if let Err(error) = write_contents(&mut staging) {
        return Err(discard_staging(staging, error));
    }
    if cancellation.is_cancelled() {
        return Err(discard_staging(staging, DepgraphServiceError::Cancelled));
    }
    if let Err(source) = staging.sync_all() {
        return Err(discard_staging(
            staging,
            RepositoryFileError::Unavailable { source }.into(),
        ));
    }
    if cancellation.is_cancelled() {
        return Err(discard_staging(staging, DepgraphServiceError::Cancelled));
    }
    let publication_policy =
        match publication_policy_without_atomic_exchange(overwrite, expected_precondition) {
            Ok(policy) => policy,
            Err(error) => {
                return Err(discard_staging(staging, error));
            }
        };
    if let Some(expected_precondition) = expected_precondition
        && let Err(error) = verify_repository_output_precondition(
            service,
            path,
            expected_precondition,
            cancellation,
        )
    {
        return Err(discard_staging(staging, error));
    }
    if let Err(error) = classify_windows_publication_target(
        traversal.parent(),
        traversal.final_name,
        publication_policy,
    ) {
        return Err(discard_staging(staging, error));
    }
    if let Err(error) = validate_windows_directories(&traversal.directories) {
        return Err(discard_staging(staging, error));
    }
    if let Err(error) = rename_windows_file_handle(
        &staging,
        traversal.parent(),
        traversal.final_name,
        publication_policy == RepositoryOverwritePolicy::Overwrite,
    ) {
        return Err(discard_staging(staging, error));
    }
    validate_windows_directories(&traversal.directories)
}

#[cfg(not(any(unix, windows)))]
fn write_repository_file_atomically_platform(
    service: &DepgraphService,
    path: &RepositoryRelativePath,
    overwrite: RepositoryOverwritePolicy,
    expected_precondition: Option<&RepositoryOutputPrecondition>,
    cancellation: &crate::CancellationToken,
    write_contents: impl FnOnce(&mut File) -> DepgraphServiceResult<()>,
) -> DepgraphServiceResult<()> {
    if !service.config().repository_root_seal().matches_live_root() {
        return Err(RepositoryFileError::BoundaryViolation.into());
    }
    let mut destination = service.config().canonical_root().to_path_buf();
    destination.extend(path.components());
    let parent = destination
        .parent()
        .ok_or(RepositoryFileError::BoundaryViolation)?;
    let canonical_parent = fs::canonicalize(parent).map_err(map_filesystem_error)?;
    if canonical_parent != parent
        || !canonical_parent.starts_with(service.config().canonical_root())
    {
        return Err(RepositoryFileError::BoundaryViolation.into());
    }
    match fs::symlink_metadata(&destination) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(RepositoryFileError::BoundaryViolation.into());
        }
        Ok(metadata) if !metadata.is_file() => {
            return Err(RepositoryFileError::NotRegular.into());
        }
        Ok(_) if overwrite == RepositoryOverwritePolicy::NoReplace => {
            return Err(RepositoryFileError::AlreadyExists.into());
        }
        Ok(_) | Err(_) => {}
    }
    let mut temporary = tempfile::Builder::new()
        .prefix(".depgraph-stage-")
        .tempfile_in(parent)
        .map_err(|source| RepositoryFileError::Unavailable { source })?;
    write_contents(temporary.as_file_mut())?;
    if cancellation.is_cancelled() {
        return Err(DepgraphServiceError::Cancelled);
    }
    temporary
        .as_file()
        .sync_all()
        .map_err(|source| RepositoryFileError::Unavailable { source })?;
    if cancellation.is_cancelled() {
        return Err(DepgraphServiceError::Cancelled);
    }
    let publication_policy =
        publication_policy_without_atomic_exchange(overwrite, expected_precondition)?;
    if let Some(expected_precondition) = expected_precondition {
        verify_repository_output_precondition(service, path, expected_precondition, cancellation)?;
    }
    match publication_policy {
        RepositoryOverwritePolicy::NoReplace => temporary
            .persist_noclobber(destination)
            .map(|_| ())
            .map_err(|error| {
                RepositoryFileError::Unavailable {
                    source: error.error,
                }
                .into()
            }),
        RepositoryOverwritePolicy::Overwrite => {
            temporary.persist(destination).map(|_| ()).map_err(|error| {
                RepositoryFileError::Unavailable {
                    source: error.error,
                }
                .into()
            })
        }
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
        use windows_sys::Win32::Foundation::{ERROR_ALREADY_EXISTS, ERROR_FILE_EXISTS};

        [ERROR_ALREADY_EXISTS, ERROR_FILE_EXISTS].contains(&(error as u32))
    }) {
        return RepositoryFileError::AlreadyExists.into();
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
    validate_opened_repository_output_not_persistent_state(service, &parent, final_name)?;
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
        Wdk::Storage::FileSystem::FILE_OPEN, Win32::Storage::FileSystem::FILE_GENERIC_READ,
    };

    let traversal = open_windows_parent(service, path, false, after_parents_opened)?;
    validate_windows_directories(&traversal.directories)?;
    let file = open_windows_at(
        traversal.parent(),
        traversal.final_name,
        FILE_GENERIC_READ,
        windows_repository_input_share_access(),
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
        Win32::Storage::FileSystem::{FILE_GENERIC_WRITE, FILE_READ_ATTRIBUTES, FILE_SHARE_READ},
    };

    let traversal = open_windows_parent(service, path, true, after_parents_opened)?;
    validate_windows_directories(&traversal.directories)?;
    let file = match open_windows_at(
        traversal.parent(),
        traversal.final_name,
        FILE_GENERIC_WRITE | FILE_READ_ATTRIBUTES,
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
    if create_output {
        validate_opened_repository_output_not_persistent_state(
            service,
            directories
                .last()
                .expect("a traversal always retains its parent handle"),
            OsStr::new(final_name),
        )?;
    }
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
fn try_posix_delete_windows_file_handle(file: &File) -> DepgraphServiceResult<bool> {
    use std::{mem, os::windows::io::AsRawHandle as _};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_DISPOSITION_FLAG_DELETE, FILE_DISPOSITION_FLAG_POSIX_SEMANTICS,
        FILE_DISPOSITION_INFO_EX, FileDispositionInfoEx, SetFileInformationByHandle,
    };

    let extended = FILE_DISPOSITION_INFO_EX {
        Flags: FILE_DISPOSITION_FLAG_DELETE | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS,
    };
    // SAFETY: file retains ownership of the live handle for the call and the
    // pointer/size describe one initialized FILE_DISPOSITION_INFO_EX value.
    // POSIX disposition removes the private staging link when this handle
    // closes even if another compatible handle appeared meanwhile. Older
    // Windows versions and file systems can fall back to legacy disposition.
    let extended_success = unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle(),
            FileDispositionInfoEx,
            std::ptr::from_ref(&extended).cast(),
            u32::try_from(mem::size_of::<FILE_DISPOSITION_INFO_EX>())
                .expect("FILE_DISPOSITION_INFO_EX size fits in u32"),
        )
    };
    if extended_success != 0 {
        return Ok(true);
    }
    let extended_error = io::Error::last_os_error();
    let extended_is_unsupported = extended_error.raw_os_error().is_some_and(|error| {
        use windows_sys::Win32::Foundation::{
            ERROR_INVALID_FUNCTION, ERROR_INVALID_PARAMETER, ERROR_NOT_SUPPORTED,
        };

        [
            ERROR_INVALID_FUNCTION,
            ERROR_INVALID_PARAMETER,
            ERROR_NOT_SUPPORTED,
        ]
        .contains(&(error as u32))
    });
    if !extended_is_unsupported {
        return Err(RepositoryFileError::Unavailable {
            source: extended_error,
        }
        .into());
    }

    Ok(false)
}

#[cfg(windows)]
fn legacy_delete_windows_file_handle(file: &File) -> DepgraphServiceResult<()> {
    use std::{mem, os::windows::io::AsRawHandle as _};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_DISPOSITION_INFO, FileDispositionInfo, SetFileInformationByHandle,
    };

    let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
    // SAFETY: file retains ownership of the live handle for the call and the
    // pointer/size describe one initialized FILE_DISPOSITION_INFO value.
    let success = unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle(),
            FileDispositionInfo,
            std::ptr::from_ref(&disposition).cast(),
            u32::try_from(mem::size_of::<FILE_DISPOSITION_INFO>())
                .expect("FILE_DISPOSITION_INFO size fits in u32"),
        )
    };
    if success == 0 {
        Err(RepositoryFileError::Unavailable {
            source: io::Error::last_os_error(),
        }
        .into())
    } else {
        Ok(())
    }
}

#[cfg(windows)]
fn delete_windows_file_handle(file: &File) -> DepgraphServiceResult<()> {
    if try_posix_delete_windows_file_handle(file)? {
        Ok(())
    } else {
        legacy_delete_windows_file_handle(file)
    }
}

#[cfg(any(test, windows))]
fn delete_private_windows_staging_with(
    try_posix_delete: impl FnOnce() -> DepgraphServiceResult<bool>,
    sanitize: impl FnOnce() -> DepgraphServiceResult<()>,
    legacy_delete: impl FnOnce() -> DepgraphServiceResult<()>,
) -> DepgraphServiceResult<()> {
    let posix_result = try_posix_delete();
    if matches!(posix_result, Ok(true)) {
        return Ok(());
    }

    // Legacy disposition cannot unlink until every compatible handle closes.
    // Sanitize first so an unexpected metadata-only/kernel observer can at
    // most delay a zero-length delete-pending link. Always attempt deletion
    // even when sanitization fails; a successful delete-pending transition is
    // the stronger confidentiality boundary because private stages are opened
    // without share access.
    let sanitize_result = sanitize();
    let delete_result = legacy_delete();
    if delete_result.is_ok() {
        return Ok(());
    }
    if let Err(error) = posix_result {
        tracing::warn!(
            cleanup_category = ?error.category(),
            "private staging POSIX and legacy deletion both failed"
        );
    }
    if let Err(error) = sanitize_result {
        tracing::warn!(
            cleanup_category = ?error.category(),
            "private staging sanitization and legacy deletion both failed"
        );
    }
    delete_result
}

#[cfg(windows)]
fn delete_private_windows_staging_handle(staging: &File) -> DepgraphServiceResult<()> {
    delete_private_windows_staging_with(
        || try_posix_delete_windows_file_handle(staging),
        || {
            staging
                .set_len(0)
                .and_then(|()| staging.sync_all())
                .map_err(|source| RepositoryFileError::Unavailable { source }.into())
        },
        || legacy_delete_windows_file_handle(staging),
    )
}

#[cfg(windows)]
fn discard_windows_staging_handle(staging: File) -> DepgraphServiceResult<()> {
    let result = delete_private_windows_staging_handle(&staging);
    drop(staging);
    result
}

#[cfg(windows)]
fn discard_windows_staging(
    parent: &File,
    staging_name: &OsStr,
    expected_identity: RepositoryFileIdentity,
    staging: File,
) -> DepgraphServiceResult<()> {
    use windows_sys::{
        Wdk::Storage::FileSystem::FILE_OPEN,
        Win32::Storage::FileSystem::{FILE_READ_ATTRIBUTES, SYNCHRONIZE},
    };

    // The retained stage handle was identity-verified immediately after its
    // exclusive create and cannot be rebound to another file. Do not perform
    // fallible metadata work before cleanup: use that same handle directly so
    // every failure path reaches disposition. The legacy path sanitizes its
    // contents before last-close.
    let deletion = delete_private_windows_staging_handle(&staging);
    drop(staging);
    deletion?;

    let remaining = open_windows_at(
        parent,
        staging_name,
        FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        windows_repository_input_share_access(),
        FILE_OPEN,
        Some(false),
    );
    match remaining {
        Err(DepgraphServiceError::RepositoryFile {
            reason: RepositoryFileError::NotFound,
        }) => Ok(()),
        Err(error) => Err(error),
        Ok(remaining) if identity_from_file(&remaining)? == expected_identity => {
            Err(RepositoryFileError::Unavailable {
                source: io::Error::other(
                    "private staging deletion did not remove its namespace link",
                ),
            }
            .into())
        }
        Ok(_) => Err(DepgraphServiceError::Integrity),
    }
}

#[cfg(any(test, windows))]
fn preserve_primary_error_after_cleanup(
    primary: DepgraphServiceError,
    cleanup: DepgraphServiceResult<()>,
) -> DepgraphServiceError {
    if let Err(cleanup) = cleanup {
        tracing::warn!(
            primary_category = ?primary.category(),
            cleanup_category = ?cleanup.category(),
            "private staging cleanup failed after a repository write failure"
        );
    }
    primary
}

#[cfg(windows)]
fn discard_windows_staging_preserving_error(
    parent: &File,
    staging_name: &OsStr,
    expected_identity: RepositoryFileIdentity,
    staging: File,
    primary: DepgraphServiceError,
) -> DepgraphServiceError {
    let cleanup = discard_windows_staging(parent, staging_name, expected_identity, staging);
    preserve_primary_error_after_cleanup(primary, cleanup)
}

#[cfg(windows)]
fn discard_windows_staging_handle_preserving_error(
    staging: File,
    primary: DepgraphServiceError,
) -> DepgraphServiceError {
    let cleanup = discard_windows_staging_handle(staging);
    preserve_primary_error_after_cleanup(primary, cleanup)
}

#[cfg(windows)]
fn rename_windows_file_handle(
    file: &File,
    parent: &File,
    destination: &OsStr,
    replace_if_exists: bool,
) -> DepgraphServiceResult<()> {
    use std::{
        mem::{self, MaybeUninit},
        os::windows::{ffi::OsStrExt as _, io::AsRawHandle as _},
        ptr,
    };
    use windows_sys::{
        Wdk::Storage::FileSystem::{
            FILE_RENAME_INFORMATION, FILE_RENAME_POSIX_SEMANTICS, FILE_RENAME_REPLACE_IF_EXISTS,
            FileRenameInformation, FileRenameInformationEx, NtSetInformationFile,
        },
        Win32::{Foundation::RtlNtStatusToDosError, System::IO::IO_STATUS_BLOCK},
    };

    let encoded_name = destination.encode_wide().collect::<Vec<_>>();
    let name_bytes = encoded_name
        .len()
        .checked_mul(mem::size_of::<u16>())
        .and_then(|length| u32::try_from(length).ok())
        .ok_or(RepositoryFileError::BoundaryViolation)?;
    // Windows requires at least the complete fixed structure plus the encoded
    // name bytes for both FileRenameInfo and FileRenameInfoEx. The trailing
    // FileName member is not a C flexible array in the public Win32 ABI.
    let buffer_size = mem::size_of::<FILE_RENAME_INFORMATION>()
        .checked_add(name_bytes as usize)
        .ok_or(RepositoryFileError::BoundaryViolation)?;
    let word_count = buffer_size
        .checked_add(mem::size_of::<usize>() - 1)
        .ok_or(RepositoryFileError::BoundaryViolation)?
        / mem::size_of::<usize>();
    let mut storage = vec![0_usize; word_count];
    let information = storage.as_mut_ptr().cast::<FILE_RENAME_INFORMATION>();
    let buffer_size =
        u32::try_from(buffer_size).map_err(|_| RepositoryFileError::BoundaryViolation)?;
    let mut io_status = MaybeUninit::<IO_STATUS_BLOCK>::zeroed();
    // SAFETY: storage is pointer-aligned and large enough for the fixed header
    // plus every encoded destination code unit. All pointers remain valid for
    // NtSetInformationFile, which does not retain them. The source and parent
    // handles remain live and owned for each call.
    let mut status = unsafe {
        // Every caller supplies a simple leaf name under this retained parent.
        // Keeping RootDirectory explicit avoids resolving a relative name from
        // the process working directory and remains stable across ancestor moves.
        (*information).RootDirectory = parent.as_raw_handle();
        (*information).FileNameLength = name_bytes;
        ptr::copy_nonoverlapping(
            encoded_name.as_ptr(),
            ptr::addr_of_mut!((*information).FileName).cast::<u16>(),
            encoded_name.len(),
        );
        let information_class = if replace_if_exists {
            // POSIX replacement is defined only together with replace-existing.
            (*information).Anonymous.Flags =
                FILE_RENAME_POSIX_SEMANTICS | FILE_RENAME_REPLACE_IF_EXISTS;
            FileRenameInformationEx
        } else {
            (*information).Anonymous.ReplaceIfExists = false;
            FileRenameInformation
        };
        NtSetInformationFile(
            file.as_raw_handle(),
            io_status.as_mut_ptr(),
            information.cast(),
            buffer_size,
            information_class,
        )
    };
    if status >= 0 {
        return Ok(());
    }
    // SAFETY: converting an NTSTATUS does not require additional invariants.
    let mut source = io::Error::from_raw_os_error(unsafe { RtlNtStatusToDosError(status) } as i32);
    let extended_is_unsupported = source.raw_os_error().is_some_and(|error| {
        use windows_sys::Win32::Foundation::{
            ERROR_INVALID_FUNCTION, ERROR_INVALID_PARAMETER, ERROR_NOT_SUPPORTED,
        };

        [
            ERROR_INVALID_FUNCTION,
            ERROR_INVALID_PARAMETER,
            ERROR_NOT_SUPPORTED,
        ]
        .contains(&(error as u32))
    });
    if replace_if_exists && extended_is_unsupported {
        // SAFETY: the same initialized buffer and owned handles remain valid;
        // only the information class and union interpretation change. The IO
        // status block remains writable output storage for the fallback call.
        status = unsafe {
            (*information).Anonymous.ReplaceIfExists = replace_if_exists;
            NtSetInformationFile(
                file.as_raw_handle(),
                io_status.as_mut_ptr(),
                information.cast(),
                buffer_size,
                FileRenameInformation,
            )
        };
        if status >= 0 {
            return Ok(());
        }
        // SAFETY: converting an NTSTATUS does not require additional invariants.
        source = io::Error::from_raw_os_error(unsafe { RtlNtStatusToDosError(status) } as i32);
    }
    if source.kind() == io::ErrorKind::AlreadyExists {
        return classify_windows_existing_output(parent, destination).map(|_| ());
    }
    Err(RepositoryFileError::Unavailable { source }.into())
}

#[cfg(windows)]
fn classify_windows_publication_target(
    parent: &File,
    name: &OsStr,
    overwrite: RepositoryOverwritePolicy,
) -> DepgraphServiceResult<()> {
    use windows_sys::{
        Wdk::Storage::FileSystem::FILE_OPEN,
        Win32::Storage::FileSystem::{
            FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, SYNCHRONIZE,
        },
    };

    let existing = match open_windows_at(
        parent,
        name,
        FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN,
        None,
    ) {
        Ok(existing) => existing,
        Err(DepgraphServiceError::RepositoryFile {
            reason: RepositoryFileError::NotFound,
        }) => return Ok(()),
        Err(error) => return Err(error),
    };
    validate_opened_windows_regular_file(&existing)?;
    if overwrite == RepositoryOverwritePolicy::Overwrite {
        Ok(())
    } else {
        Err(RepositoryFileError::AlreadyExists.into())
    }
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
    use std::{
        io::{Read as _, Seek as _},
        path::Path,
    };

    #[cfg(unix)]
    use std::{cell::RefCell, path::PathBuf};

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

    #[cfg(windows)]
    #[test]
    fn windows_same_parent_file_rename_publishes_and_replaces() {
        use std::io::Write as _;
        use windows_sys::{
            Wdk::Storage::FileSystem::FILE_CREATE,
            Win32::Storage::FileSystem::{DELETE, FILE_GENERIC_WRITE, FILE_READ_ATTRIBUTES},
        };

        let temporary = tempfile::tempdir().expect("temporary directory is available");
        let root = temporary.path().join("repository");
        fs::create_dir_all(&root).expect("repository is created");
        let parent = open_windows_directory(&root, true)
            .expect("publication parent can be opened by handle");

        let create_source = |name: &str, contents: &[u8]| {
            let mut source = open_windows_at(
                &parent,
                OsStr::new(name),
                FILE_GENERIC_WRITE | FILE_READ_ATTRIBUTES | DELETE,
                windows_staging_share_access(),
                FILE_CREATE,
                Some(false),
            )
            .expect("staging file can be created by handle");
            source
                .write_all(contents)
                .expect("staging file is writable");
            source
        };

        let source = create_source("stage-create", b"created");
        rename_windows_file_handle(&source, &parent, OsStr::new("output.txt"), false)
            .expect("missing destination can be published by handle");
        drop(source);
        assert_eq!(
            fs::read(root.join("output.txt")).expect("published output is readable"),
            b"created"
        );

        let source = create_source("stage-replace", b"replaced");
        rename_windows_file_handle(&source, &parent, OsStr::new("output.txt"), true)
            .expect("existing destination can be replaced by handle");
        drop(source);
        assert_eq!(
            fs::read(root.join("output.txt")).expect("replaced output is readable"),
            b"replaced"
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_private_staging_rejects_readers_and_cleanup_removes_the_link() {
        use std::{io::Write as _, os::windows::fs::OpenOptionsExt as _};
        use windows_sys::{
            Wdk::Storage::FileSystem::FILE_CREATE,
            Win32::Storage::FileSystem::{DELETE, FILE_GENERIC_WRITE, FILE_READ_ATTRIBUTES},
        };

        let temporary = tempfile::tempdir().expect("temporary directory is available");
        let root = temporary.path().join("repository");
        fs::create_dir_all(&root).expect("repository is created");
        let parent = open_windows_directory(&root, true)
            .expect("publication parent can be opened by handle");
        let staging_name = OsStr::new(".depgraph-stage-exclusive");
        let staging_path = root.join(staging_name);
        let mut staging = open_windows_at(
            &parent,
            staging_name,
            FILE_GENERIC_WRITE | FILE_READ_ATTRIBUTES | DELETE,
            windows_staging_share_access(),
            FILE_CREATE,
            Some(false),
        )
        .expect("private staging file can be created");
        staging
            .write_all(b"private-stage-canary")
            .expect("private staging file is writable");
        let identity = identity_from_file(&staging).expect("staging identity is available");

        let observer = fs::OpenOptions::new()
            .read(true)
            .share_mode(windows_repository_input_share_access())
            .open(&staging_path);
        assert!(
            observer.is_err(),
            "a reader must not coexist with an unpublished private stage"
        );

        discard_windows_staging(&parent, staging_name, identity, staging)
            .expect("exclusive private staging cleanup succeeds");
        assert!(!staging_path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn unix_repository_file_name_comparison_is_unicode_canonical_caseless() {
        assert!(repository_file_names_equivalent(
            OsStr::new("Gráph.db-wal"),
            OsStr::new("GRÁPH.DB-wal")
        ));
        assert!(repository_file_names_equivalent(
            OsStr::new("Gráph.db-wal"),
            OsStr::new("Gra\u{301}ph.db-wal")
        ));
        assert!(!repository_file_names_equivalent(
            OsStr::new("graph.db-wal"),
            OsStr::new("graph.db-shm")
        ));
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

    #[cfg(unix)]
    #[test]
    fn unix_public_output_rejects_protected_parent_directory_rename_race() {
        let temporary = tempfile::tempdir().expect("temporary directory is available");
        let root = temporary.path().join("repository");
        let protected_parent = root.join(".depgraph");
        let safe_parent = root.join("artifacts");
        let moved_safe_parent = root.join("artifacts-safe");
        fs::create_dir_all(&protected_parent).expect("protected parent is created");
        fs::create_dir_all(&safe_parent).expect("safe parent is created");
        let store_path = protected_parent.join("graph.db");
        fs::write(&store_path, b"store-canary").expect("store canary is created");
        let capabilities = DepgraphCapabilitySet::try_new([
            DepgraphCapability::Read,
            DepgraphCapability::RepositoryWrite,
        ])
        .expect("test capabilities are valid");
        let service = DepgraphService::new(
            DepgraphServiceConfig::new(
                &root,
                &store_path,
                capabilities,
                DepgraphServiceLimits::default(),
            )
            .expect("test service configuration is valid"),
        );
        let path = RepositoryRelativePath::parse("artifacts/graph.db-wal")
            .expect("test path is repository-relative");
        validate_repository_output_not_protected(&service, &path)
            .expect("lexical path is safe before the race");
        let safe_control = RepositoryRelativePath::parse("artifacts/graph.db-shm")
            .expect("control path is repository-relative");
        drop(
            create_repository_output(&service, &safe_control)
                .expect("a protected leaf name remains valid under a distinct parent identity"),
        );
        fs::remove_file(root.join(safe_control.as_str())).expect("control output is removed");

        let result = open_unix_repository_output_after_root(&service, &path, || {
            fs::rename(&safe_parent, &moved_safe_parent).expect("safe parent can move aside");
            fs::rename(&protected_parent, &safe_parent)
                .expect("protected parent can move under the safe name");
        });
        fs::rename(&safe_parent, &protected_parent).expect("protected parent is restored");
        fs::rename(&moved_safe_parent, &safe_parent).expect("safe parent is restored");

        let error = result.unwrap_err();
        assert_eq!(error.category(), DepgraphServiceErrorCategory::Integrity);
        assert_eq!(
            fs::read(&store_path).expect("store canary remains readable"),
            b"store-canary"
        );
        assert!(!protected_parent.join("graph.db-wal").exists());

        fs::rename(&safe_parent, &moved_safe_parent).expect("safe parent can move aside again");
        fs::rename(&protected_parent, &safe_parent)
            .expect("protected parent can move under the safe name again");
        let atomic_result = write_repository_file_atomically(
            &service,
            &path,
            RepositoryOverwritePolicy::NoReplace,
            None,
            &crate::CancellationToken::new(),
            |file| {
                file.write_all(b"must-not-publish")
                    .map_err(|source| RepositoryFileError::Unavailable { source })?;
                Ok(())
            },
        );
        fs::rename(&safe_parent, &protected_parent).expect("protected parent is restored again");
        fs::rename(&moved_safe_parent, &safe_parent).expect("safe parent is restored again");

        let error = atomic_result.unwrap_err();
        assert_eq!(error.category(), DepgraphServiceErrorCategory::Integrity);
        assert!(!protected_parent.join("graph.db-wal").exists());
    }

    #[cfg(windows)]
    #[test]
    fn windows_retained_input_handles_block_enclosing_ancestor_swap() {
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
            let error = fs::rename(&enclosing, &moved_enclosing)
                .expect_err("retained descendant handles block an enclosing rename on Windows");
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        })
        .expect("input remains available after the rejected ancestor swap");

        let mut contents = String::new();
        file.read_to_string(&mut contents)
            .expect("opened input is readable");
        assert_eq!(contents, "original");
        assert!(!moved_enclosing.exists());
    }

    #[cfg(windows)]
    #[test]
    fn windows_retained_output_handles_block_enclosing_ancestor_swap() {
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
            let error = fs::rename(&enclosing, &moved_enclosing)
                .expect_err("retained descendant handles block an enclosing rename on Windows");
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        })
        .expect("output remains available after the rejected ancestor swap");
        file.write_all(b"original output")
            .expect("opened output is writable");
        drop(file);

        assert_eq!(
            fs::read(root.join("nested/output.txt")).expect("output was created in the repository"),
            b"original output"
        );
        assert!(!moved_enclosing.exists());
    }

    #[test]
    fn atomic_repository_write_keeps_existing_destination_when_writer_fails() {
        let temporary = tempfile::tempdir().expect("temporary directory is available");
        let root = temporary.path().join("repository");
        let cache = temporary.path().join("cache");
        fs::create_dir_all(&root).expect("repository is created");
        fs::create_dir_all(&cache).expect("cache is created");
        fs::write(root.join("output.txt"), b"existing-canary").expect("existing output is created");
        let service = {
            let capabilities = DepgraphCapabilitySet::try_new([
                DepgraphCapability::Read,
                DepgraphCapability::RepositoryWrite,
            ])
            .expect("test capabilities are valid");
            let config = DepgraphServiceConfig::new(
                &root,
                cache.join("graph.db"),
                capabilities,
                DepgraphServiceLimits::default(),
            )
            .expect("test service configuration is valid");
            DepgraphService::new(config)
        };
        let path =
            RepositoryRelativePath::parse("output.txt").expect("test path is repository-relative");

        let error = write_repository_file_atomically(
            &service,
            &path,
            RepositoryOverwritePolicy::Overwrite,
            None,
            &crate::CancellationToken::new(),
            |file| {
                file.write_all(b"partial")
                    .map_err(|source| RepositoryFileError::Unavailable { source })?;
                Err(DepgraphServiceError::Internal)
            },
        )
        .unwrap_err();

        assert_eq!(error.category(), DepgraphServiceErrorCategory::Internal);
        assert_eq!(
            fs::read(root.join("output.txt")).expect("existing output remains readable"),
            b"existing-canary"
        );
        let mut entries = fs::read_dir(&root)
            .expect("repository remains readable")
            .map(|entry| {
                entry
                    .expect("repository entry is readable")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect::<Vec<_>>();
        entries.sort();
        assert_eq!(entries, ["output.txt"]);
    }

    #[test]
    fn non_exchange_publication_never_uses_unconditional_durable_overwrite() {
        assert_eq!(
            publication_policy_without_atomic_exchange(
                RepositoryOverwritePolicy::Overwrite,
                Some(&RepositoryOutputPrecondition::Missing),
            )
            .unwrap(),
            RepositoryOverwritePolicy::NoReplace
        );
        assert!(matches!(
            publication_policy_without_atomic_exchange(
                RepositoryOverwritePolicy::Overwrite,
                Some(&RepositoryOutputPrecondition::Regular {
                    identity_sha256: "0".repeat(64),
                    output_bytes: 1,
                    content_sha256: "1".repeat(64),
                }),
            ),
            Err(DepgraphServiceError::Integrity)
        ));
        assert!(matches!(
            publication_policy_without_atomic_exchange(RepositoryOverwritePolicy::Overwrite, None,),
            Err(DepgraphServiceError::Integrity)
        ));
    }

    #[test]
    fn windows_publication_stage_is_exclusive_until_publish() {
        assert_eq!(windows_staging_share_access(), 0);
    }

    #[test]
    fn private_staging_delete_sanitizes_before_the_legacy_fallback() {
        let calls = std::cell::RefCell::new(Vec::new());
        let result = delete_private_windows_staging_with(
            || {
                calls.borrow_mut().push("posix");
                Ok(false)
            },
            || {
                calls.borrow_mut().push("sanitize");
                Err(DepgraphServiceError::Internal)
            },
            || {
                calls.borrow_mut().push("legacy");
                Ok(())
            },
        );
        assert!(result.is_ok());
        assert_eq!(*calls.borrow(), ["posix", "sanitize", "legacy"]);

        calls.borrow_mut().clear();
        delete_private_windows_staging_with(
            || {
                calls.borrow_mut().push("posix");
                Ok(true)
            },
            || panic!("POSIX deletion must not sanitize an unlinked stage"),
            || panic!("POSIX deletion must not invoke legacy disposition"),
        )
        .unwrap();
        assert_eq!(*calls.borrow(), ["posix"]);
    }

    #[test]
    fn private_staging_delete_still_cleans_up_after_a_posix_error() {
        let calls = std::cell::RefCell::new(Vec::new());
        delete_private_windows_staging_with(
            || {
                calls.borrow_mut().push("posix-error");
                Err(DepgraphServiceError::Internal)
            },
            || {
                calls.borrow_mut().push("sanitize");
                Ok(())
            },
            || {
                calls.borrow_mut().push("legacy");
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(*calls.borrow(), ["posix-error", "sanitize", "legacy"]);
    }

    #[test]
    fn private_staging_delete_reports_a_failed_legacy_disposition() {
        let error = delete_private_windows_staging_with(
            || Ok(false),
            || Ok(()),
            || Err(DepgraphServiceError::Integrity),
        )
        .unwrap_err();
        assert_eq!(error.category(), DepgraphServiceErrorCategory::Integrity);
    }

    #[test]
    fn windows_repository_inputs_allow_non_blocking_repository_updates() {
        assert_ne!(
            windows_repository_input_share_access() & WINDOWS_FILE_SHARE_WRITE_ACCESS,
            0
        );
        assert_ne!(
            windows_repository_input_share_access() & WINDOWS_FILE_SHARE_DELETE_ACCESS,
            0
        );
    }

    #[test]
    fn staging_cleanup_failure_preserves_the_primary_error_category() {
        let error = preserve_primary_error_after_cleanup(
            DepgraphServiceError::Cancelled,
            Err(RepositoryFileError::Unavailable {
                source: io::Error::other("cleanup failure"),
            }
            .into()),
        );

        assert_eq!(error.category(), DepgraphServiceErrorCategory::Cancelled);
    }

    #[test]
    fn repository_precondition_hashing_stops_after_expected_size_plus_one() {
        let temporary = tempfile::tempdir().expect("temporary directory is available");
        let root = temporary.path().join("repository");
        let cache = temporary.path().join("cache");
        fs::create_dir_all(&root).expect("repository is created");
        fs::create_dir_all(&cache).expect("cache is created");
        let output = root.join("output.txt");
        fs::write(&output, b"x").expect("initial output is created");
        let service = {
            let capabilities = DepgraphCapabilitySet::try_new([
                DepgraphCapability::Read,
                DepgraphCapability::RepositoryWrite,
            ])
            .expect("test capabilities are valid");
            let config = DepgraphServiceConfig::new(
                &root,
                cache.join("graph.db"),
                capabilities,
                DepgraphServiceLimits::default(),
            )
            .expect("test service configuration is valid");
            DepgraphService::new(config)
        };
        let path =
            RepositoryRelativePath::parse("output.txt").expect("test path is repository-relative");
        let mut file = open_repository_input(&service, &path).expect("output is opened safely");

        let error = repository_regular_file_precondition_from_file_after_metadata_for_test(
            &service,
            &path,
            &mut file,
            &crate::CancellationToken::new(),
            || {
                let replacement = fs::OpenOptions::new()
                    .write(true)
                    .open(&output)
                    .expect("same output can grow");
                replacement
                    .set_len(1024 * 1024)
                    .expect("same output can grow after metadata");
            },
        )
        .unwrap_err();

        assert_eq!(error.category(), DepgraphServiceErrorCategory::Integrity);
        assert!(
            file.stream_position().expect("position is available") <= 2,
            "bounded verification must read at most expected bytes plus one"
        );
    }

    #[cfg(unix)]
    #[test]
    fn owned_random_stage_cleanup_preserves_a_swap_after_identity_validation() {
        let temporary = tempfile::tempdir().expect("temporary directory is available");
        let root = temporary.path();
        let staging_name = OsStr::new(".depgraph-stage-owned");
        let staging = root.join(staging_name);
        let displaced = root.join("displaced-owned-stage");
        fs::write(&staging, b"owned-stage").expect("owned staging is created");
        let owned = File::open(&staging).expect("owned staging is opened");
        let owned_identity = identity_from_file(&owned).expect("owned identity is available");
        let parent = File::open(root).expect("parent directory is opened");

        let error = remove_owned_unix_staging_after_identity_for_test(
            &parent,
            staging_name,
            owned_identity,
            || {
                fs::rename(&staging, &displaced).expect("owned stage can be displaced");
                fs::write(&staging, b"foreign-stage").expect("foreign stage is installed");
            },
        )
        .unwrap_err();

        assert_eq!(error.category(), DepgraphServiceErrorCategory::Integrity);
        assert_eq!(fs::read(&staging).unwrap(), b"foreign-stage");
        assert_eq!(fs::read(&displaced).unwrap(), b"owned-stage");
    }

    #[cfg(unix)]
    #[test]
    fn staged_export_cleanup_rejects_a_post_validation_regular_file_swap() {
        let temporary = tempfile::tempdir().expect("temporary directory is available");
        let root = temporary.path().join("repository");
        let cache = temporary.path().join("cache");
        fs::create_dir_all(root.join("artifacts")).expect("artifact directory is created");
        fs::create_dir_all(&cache).expect("cache directory is created");
        let capabilities = DepgraphCapabilitySet::try_new([
            DepgraphCapability::Read,
            DepgraphCapability::RepositoryWrite,
        ])
        .expect("test capabilities are valid");
        let config = DepgraphServiceConfig::new(
            &root,
            cache.join("graph.db"),
            capabilities,
            DepgraphServiceLimits::default(),
        )
        .expect("test service configuration is valid");
        let service = DepgraphService::new(config);
        let staging_path = RepositoryRelativePath::parse("artifacts/.depgraph-export-owned")
            .expect("test path is repository-relative");
        let staging = root.join(staging_path.as_str());
        let displaced = root.join("artifacts/displaced-owned");
        fs::write(&staging, b"owned-stage").expect("owned staging is created");
        let result = ExportFileResult {
            output_path: RepositoryRelativePath::parse("artifacts/output.json")
                .expect("output path is repository-relative"),
            format: crate::service::GraphExportFormat::Json,
            output_bytes: 11,
            content_sha256: hex::encode(Sha256::digest(b"owned-stage")),
        };

        let error = remove_staged_export_after_validation(&service, &staging_path, &result, || {
            fs::rename(&staging, &displaced).expect("owned stage can be displaced");
            fs::write(&staging, b"foreign-stage").expect("foreign stage is installed");
        })
        .unwrap_err();

        assert_eq!(error.category(), DepgraphServiceErrorCategory::Integrity);
        assert_eq!(fs::read(&staging).unwrap(), b"foreign-stage");
        assert_eq!(fs::read(&displaced).unwrap(), b"owned-stage");
    }

    #[cfg(unix)]
    #[test]
    fn unix_atomic_publication_rejects_a_replaced_staging_path() {
        let temporary = tempfile::tempdir().expect("temporary directory is available");
        let root = temporary.path().join("repository");
        let cache = temporary.path().join("cache");
        fs::create_dir_all(&root).expect("repository is created");
        fs::create_dir_all(&cache).expect("cache is created");
        let capabilities = DepgraphCapabilitySet::try_new([
            DepgraphCapability::Read,
            DepgraphCapability::RepositoryWrite,
        ])
        .expect("test capabilities are valid");
        let service = DepgraphService::new(
            DepgraphServiceConfig::new(
                &root,
                cache.join("graph.db"),
                capabilities,
                DepgraphServiceLimits::default(),
            )
            .expect("test service configuration is valid"),
        );
        let path =
            RepositoryRelativePath::parse("output.txt").expect("test path is repository-relative");
        let displaced = root.join("displaced-owned-stage");
        let foreign_stage = RefCell::new(None::<PathBuf>);

        let error = write_repository_file_atomically_platform_after_classification_for_test(
            &service,
            &path,
            RepositoryOverwritePolicy::NoReplace,
            &crate::CancellationToken::new(),
            |file| file.write_all(b"owned-stage").map_err(map_filesystem_error),
            || {
                let stage = fs::read_dir(&root)
                    .expect("repository is readable")
                    .map(|entry| entry.expect("entry is readable").path())
                    .find(|entry| {
                        entry.file_name().is_some_and(|name| {
                            name.to_string_lossy().starts_with(".depgraph-stage-")
                        })
                    })
                    .expect("owned random stage exists");
                fs::rename(&stage, &displaced).expect("owned stage can be displaced");
                fs::write(&stage, b"foreign-stage").expect("foreign stage is installed");
                *foreign_stage.borrow_mut() = Some(stage);
            },
        )
        .unwrap_err();

        assert_eq!(error.category(), DepgraphServiceErrorCategory::Integrity);
        assert!(!root.join(path.as_str()).exists());
        assert_eq!(fs::read(&displaced).unwrap(), b"owned-stage");
        assert_eq!(
            fs::read(
                foreign_stage
                    .borrow()
                    .as_ref()
                    .expect("foreign stage path was recorded")
            )
            .unwrap(),
            b"foreign-stage"
        );
    }

    #[cfg(unix)]
    #[test]
    fn unix_atomic_overwrite_rejects_a_replaced_staging_path() {
        let temporary = tempfile::tempdir().expect("temporary directory is available");
        let root = temporary.path().join("repository");
        let cache = temporary.path().join("cache");
        fs::create_dir_all(&root).expect("repository is created");
        fs::create_dir_all(&cache).expect("cache is created");
        let output = root.join("output.txt");
        fs::write(&output, b"original-destination").expect("destination is created");
        let capabilities = DepgraphCapabilitySet::try_new([
            DepgraphCapability::Read,
            DepgraphCapability::RepositoryWrite,
        ])
        .expect("test capabilities are valid");
        let service = DepgraphService::new(
            DepgraphServiceConfig::new(
                &root,
                cache.join("graph.db"),
                capabilities,
                DepgraphServiceLimits::default(),
            )
            .expect("test service configuration is valid"),
        );
        let path =
            RepositoryRelativePath::parse("output.txt").expect("test path is repository-relative");
        let displaced = root.join("displaced-owned-stage");
        let foreign_stage = RefCell::new(None::<PathBuf>);

        let error = write_repository_file_atomically_platform_after_classification_for_test(
            &service,
            &path,
            RepositoryOverwritePolicy::Overwrite,
            &crate::CancellationToken::new(),
            |file| file.write_all(b"owned-stage").map_err(map_filesystem_error),
            || {
                let stage = fs::read_dir(&root)
                    .expect("repository is readable")
                    .map(|entry| entry.expect("entry is readable").path())
                    .find(|entry| {
                        entry.file_name().is_some_and(|name| {
                            name.to_string_lossy().starts_with(".depgraph-stage-")
                        })
                    })
                    .expect("owned random stage exists");
                fs::rename(&stage, &displaced).expect("owned stage can be displaced");
                fs::write(&stage, b"foreign-stage").expect("foreign stage is installed");
                *foreign_stage.borrow_mut() = Some(stage);
            },
        )
        .unwrap_err();

        assert_eq!(error.category(), DepgraphServiceErrorCategory::Integrity);
        assert_eq!(fs::read(&output).unwrap(), b"original-destination");
        assert_eq!(fs::read(&displaced).unwrap(), b"owned-stage");
        assert_eq!(
            fs::read(
                foreign_stage
                    .borrow()
                    .as_ref()
                    .expect("foreign stage path was recorded")
            )
            .unwrap(),
            b"foreign-stage"
        );
    }

    #[cfg(unix)]
    #[test]
    fn durable_atomic_overwrite_rechecks_content_precondition_after_staging() {
        let temporary = tempfile::tempdir().expect("temporary directory is available");
        let root = temporary.path().join("repository");
        let cache = temporary.path().join("cache");
        fs::create_dir_all(&root).expect("repository is created");
        fs::create_dir_all(&cache).expect("cache is created");
        let output = root.join("output.txt");
        fs::write(&output, b"expected-content").expect("existing output is created");
        let capabilities = DepgraphCapabilitySet::try_new([
            DepgraphCapability::Read,
            DepgraphCapability::RepositoryWrite,
        ])
        .expect("test capabilities are valid");
        let config = DepgraphServiceConfig::new(
            &root,
            cache.join("graph.db"),
            capabilities,
            DepgraphServiceLimits::default(),
        )
        .expect("test service configuration is valid");
        let service = DepgraphService::new(config);
        let path =
            RepositoryRelativePath::parse("output.txt").expect("test path is repository-relative");
        let precondition =
            repository_output_precondition(&service, &path, &crate::CancellationToken::new())
                .expect("existing destination precondition is captured");

        let error = write_repository_file_atomically_platform_before_precondition_for_test(
            &service,
            &path,
            RepositoryOverwritePolicy::Overwrite,
            &crate::CancellationToken::new(),
            &precondition,
            |file| file.write_all(b"replacement").map_err(map_filesystem_error),
            || {
                fs::write(&output, b"concurrent-content")
                    .expect("concurrent destination update succeeds");
            },
        )
        .unwrap_err();

        assert_eq!(error.category(), DepgraphServiceErrorCategory::Integrity);
        assert_eq!(fs::read(&output).unwrap(), b"concurrent-content");
        assert_eq!(fs::read_dir(&root).unwrap().count(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn durable_atomic_overwrite_restores_content_drift_at_publication_boundary() {
        let temporary = tempfile::tempdir().expect("temporary directory is available");
        let root = temporary.path().join("repository");
        let cache = temporary.path().join("cache");
        fs::create_dir_all(&root).expect("repository is created");
        fs::create_dir_all(&cache).expect("cache is created");
        let output = root.join("output.txt");
        fs::write(&output, b"expected-content").expect("existing output is created");
        let capabilities = DepgraphCapabilitySet::try_new([
            DepgraphCapability::Read,
            DepgraphCapability::RepositoryWrite,
        ])
        .expect("test capabilities are valid");
        let config = DepgraphServiceConfig::new(
            &root,
            cache.join("graph.db"),
            capabilities,
            DepgraphServiceLimits::default(),
        )
        .expect("test service configuration is valid");
        let service = DepgraphService::new(config);
        let path =
            RepositoryRelativePath::parse("output.txt").expect("test path is repository-relative");
        let precondition =
            repository_output_precondition(&service, &path, &crate::CancellationToken::new())
                .expect("existing destination precondition is captured");

        let error = write_repository_file_atomically_platform_unix(
            &service,
            &path,
            RepositoryOverwritePolicy::Overwrite,
            Some(&precondition),
            &crate::CancellationToken::new(),
            |file| file.write_all(b"replacement").map_err(map_filesystem_error),
            UnixAtomicWriteHooks {
                before_precondition: || {},
                after_classification: || {
                    fs::write(&output, b"concurrent-content")
                        .expect("concurrent destination update succeeds");
                },
                before_rollback: || {},
            },
        )
        .unwrap_err();

        assert_eq!(error.category(), DepgraphServiceErrorCategory::Integrity);
        assert_eq!(fs::read(&output).unwrap(), b"concurrent-content");
        assert_eq!(fs::read_dir(&root).unwrap().count(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn direct_atomic_overwrite_rejects_same_inode_content_drift_at_publication() {
        let temporary = tempfile::tempdir().expect("temporary directory is available");
        let root = temporary.path().join("repository");
        let cache = temporary.path().join("cache");
        fs::create_dir_all(&root).expect("repository is created");
        fs::create_dir_all(&cache).expect("cache is created");
        let output = root.join("output.txt");
        fs::write(&output, b"original-content").expect("existing output is created");
        let service = {
            let capabilities = DepgraphCapabilitySet::try_new([
                DepgraphCapability::Read,
                DepgraphCapability::RepositoryWrite,
            ])
            .expect("test capabilities are valid");
            let config = DepgraphServiceConfig::new(
                &root,
                cache.join("graph.db"),
                capabilities,
                DepgraphServiceLimits::default(),
            )
            .expect("test service configuration is valid");
            DepgraphService::new(config)
        };
        let path =
            RepositoryRelativePath::parse("output.txt").expect("test path is repository-relative");

        let error = write_repository_file_atomically_platform_after_classification_for_test(
            &service,
            &path,
            RepositoryOverwritePolicy::Overwrite,
            &crate::CancellationToken::new(),
            |file| file.write_all(b"replacement").map_err(map_filesystem_error),
            || {
                fs::write(&output, b"concurrent-data")
                    .expect("same-inode destination update succeeds");
            },
        )
        .unwrap_err();

        assert_eq!(error.category(), DepgraphServiceErrorCategory::Integrity);
        assert_eq!(fs::read(&output).unwrap(), b"concurrent-data");
    }

    #[cfg(unix)]
    #[test]
    fn failed_unix_rollback_never_exchanges_a_foreign_replacement_into_destination() {
        let temporary = tempfile::tempdir().expect("temporary directory is available");
        let root = temporary.path().join("repository");
        let cache = temporary.path().join("cache");
        fs::create_dir_all(&root).expect("repository is created");
        fs::create_dir_all(&cache).expect("cache is created");
        let output = root.join("output.txt");
        fs::write(&output, b"original-content").expect("existing output is created");
        let service = {
            let capabilities = DepgraphCapabilitySet::try_new([
                DepgraphCapability::Read,
                DepgraphCapability::RepositoryWrite,
            ])
            .expect("test capabilities are valid");
            let config = DepgraphServiceConfig::new(
                &root,
                cache.join("graph.db"),
                capabilities,
                DepgraphServiceLimits::default(),
            )
            .expect("test service configuration is valid");
            DepgraphService::new(config)
        };
        let path =
            RepositoryRelativePath::parse("output.txt").expect("test path is repository-relative");
        let precondition =
            repository_output_precondition(&service, &path, &crate::CancellationToken::new())
                .expect("destination precondition is captured");
        let foreign_stage = RefCell::new(None::<PathBuf>);

        let error = write_repository_file_atomically_platform_unix(
            &service,
            &path,
            RepositoryOverwritePolicy::Overwrite,
            Some(&precondition),
            &crate::CancellationToken::new(),
            |file| file.write_all(b"replacement").map_err(map_filesystem_error),
            UnixAtomicWriteHooks {
                before_precondition: || {},
                after_classification: || {
                    fs::write(&output, b"concurrent-data")
                        .expect("same-inode destination update succeeds");
                },
                before_rollback: || {
                    let staging = fs::read_dir(&root)
                        .expect("repository is readable")
                        .map(|entry| entry.expect("entry is readable").path())
                        .find(|path| {
                            path.file_name()
                                .and_then(|name| name.to_str())
                                .is_some_and(|name| name.starts_with(".depgraph-stage-"))
                        })
                        .expect("rollback staging exists");
                    fs::rename(&staging, root.join("displaced-original"))
                        .expect("validated old destination can be displaced");
                    fs::write(&staging, b"foreign-canary")
                        .expect("foreign staging replacement is installed");
                    *foreign_stage.borrow_mut() = Some(staging);
                },
            },
        )
        .unwrap_err();

        assert_eq!(error.category(), DepgraphServiceErrorCategory::Integrity);
        assert_eq!(fs::read(&output).unwrap(), b"replacement");
        let foreign_stage = foreign_stage
            .into_inner()
            .expect("foreign staging path was captured");
        assert_eq!(fs::read(foreign_stage).unwrap(), b"foreign-canary");
        assert_eq!(
            fs::read(root.join("displaced-original")).unwrap(),
            b"concurrent-data"
        );
    }

    #[cfg(unix)]
    #[test]
    fn unix_atomic_overwrite_restores_and_rejects_a_post_classification_symlink_swap() {
        use std::os::unix::fs::symlink;

        let temporary = tempfile::tempdir().expect("temporary directory is available");
        let root = temporary.path().join("repository");
        let cache = temporary.path().join("cache");
        let outside = temporary.path().join("outside.txt");
        fs::create_dir_all(&root).expect("repository is created");
        fs::create_dir_all(&cache).expect("cache is created");
        fs::write(root.join("output.txt"), b"existing-canary").expect("existing output is created");
        fs::write(&outside, b"outside-canary").expect("outside canary is created");
        let service = {
            let capabilities = DepgraphCapabilitySet::try_new([
                DepgraphCapability::Read,
                DepgraphCapability::RepositoryWrite,
            ])
            .expect("test capabilities are valid");
            let config = DepgraphServiceConfig::new(
                &root,
                cache.join("graph.db"),
                capabilities,
                DepgraphServiceLimits::default(),
            )
            .expect("test service configuration is valid");
            DepgraphService::new(config)
        };
        let path =
            RepositoryRelativePath::parse("output.txt").expect("test path is repository-relative");

        let error = write_repository_file_atomically_platform_after_classification_for_test(
            &service,
            &path,
            RepositoryOverwritePolicy::Overwrite,
            &crate::CancellationToken::new(),
            |file| file.write_all(b"replacement").map_err(map_filesystem_error),
            || {
                fs::rename(root.join("output.txt"), root.join("displaced.txt"))
                    .expect("classified destination can be displaced");
                symlink(&outside, root.join("output.txt"))
                    .expect("symlink race candidate is installed");
            },
        )
        .unwrap_err();

        assert_eq!(error.category(), DepgraphServiceErrorCategory::Integrity);
        assert!(
            root.join("output.txt")
                .symlink_metadata()
                .expect("raced symlink remains")
                .file_type()
                .is_symlink()
        );
        assert_eq!(fs::read(&outside).unwrap(), b"outside-canary");
        assert_eq!(
            fs::read(root.join("displaced.txt")).unwrap(),
            b"existing-canary"
        );
        assert_eq!(fs::read_dir(&root).unwrap().count(), 2);
    }
}
