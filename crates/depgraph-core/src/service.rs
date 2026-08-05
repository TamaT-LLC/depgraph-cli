use std::{
    collections::BTreeSet,
    fs, io,
    path::{Component, Path, PathBuf},
    sync::Arc,
};

use depgraph_store::Store;

pub const DEPGRAPH_SERVICE_LIMITS_VERSION: &str = "depgraph-service-limits-v1";
pub const DEFAULT_SERVICE_MAX_INLINE_INPUT_BYTES: usize = 1024 * 1024;
pub const DEFAULT_SERVICE_MAX_OUTPUT_BYTES: usize = 16 * 1024 * 1024;
pub const DEFAULT_SERVICE_PAGE_ITEMS: usize = 100;
pub const DEFAULT_SERVICE_MAX_PAGE_ITEMS: usize = 1_000;

pub type DepgraphServiceResult<T> = Result<T, DepgraphServiceError>;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum DepgraphCapability {
    Read,
    StoreWrite,
    RepositoryWrite,
    DaemonControl,
    ProjectExec,
}

impl DepgraphCapability {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::StoreWrite => "store_write",
            Self::RepositoryWrite => "repository_write",
            Self::DaemonControl => "daemon_control",
            Self::ProjectExec => "project_exec",
        }
    }
}

impl std::fmt::Display for DepgraphCapability {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DepgraphCapabilitySet {
    values: BTreeSet<DepgraphCapability>,
}

impl DepgraphCapabilitySet {
    pub fn try_new(
        capabilities: impl IntoIterator<Item = DepgraphCapability>,
    ) -> DepgraphServiceResult<Self> {
        let mut values = BTreeSet::new();
        for capability in capabilities {
            if !values.insert(capability) {
                return Err(
                    DepgraphServiceConfigurationError::DuplicateCapability { capability }.into(),
                );
            }
        }
        validate_capabilities(&values)?;
        Ok(Self { values })
    }

    #[must_use]
    pub fn read_only() -> Self {
        Self {
            values: BTreeSet::from([DepgraphCapability::Read]),
        }
    }

    #[must_use]
    pub fn contains(&self, capability: DepgraphCapability) -> bool {
        self.values.contains(&capability)
    }

    pub fn iter(&self) -> impl ExactSizeIterator<Item = DepgraphCapability> + '_ {
        self.values.iter().copied()
    }

    #[must_use]
    pub fn contains_all(&self, required: &[DepgraphCapability]) -> bool {
        required.iter().all(|capability| self.contains(*capability))
    }
}

fn validate_capabilities(values: &BTreeSet<DepgraphCapability>) -> DepgraphServiceResult<()> {
    if !values.contains(&DepgraphCapability::Read) {
        return Err(DepgraphServiceConfigurationError::MissingCapability {
            capability: DepgraphCapability::Read,
        }
        .into());
    }
    for capability in [
        DepgraphCapability::DaemonControl,
        DepgraphCapability::ProjectExec,
    ] {
        if values.contains(&capability) && !values.contains(&DepgraphCapability::StoreWrite) {
            return Err(
                DepgraphServiceConfigurationError::MissingCapabilityDependency {
                    capability,
                    requires: DepgraphCapability::StoreWrite,
                }
                .into(),
            );
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DepgraphServiceLimit {
    InlineInputBytes,
    OutputBytes,
    DefaultPageItems,
    MaxPageItems,
}

impl DepgraphServiceLimit {
    const fn as_str(self) -> &'static str {
        match self {
            Self::InlineInputBytes => "inline_input_bytes",
            Self::OutputBytes => "output_bytes",
            Self::DefaultPageItems => "default_page_items",
            Self::MaxPageItems => "max_page_items",
        }
    }
}

impl std::fmt::Display for DepgraphServiceLimit {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DepgraphServiceLimits {
    version: String,
    max_inline_input_bytes: usize,
    max_output_bytes: usize,
    default_page_items: usize,
    max_page_items: usize,
}

impl DepgraphServiceLimits {
    pub fn try_new(
        version: impl Into<String>,
        max_inline_input_bytes: usize,
        max_output_bytes: usize,
        default_page_items: usize,
        max_page_items: usize,
    ) -> DepgraphServiceResult<Self> {
        let version = version.into();
        if version != DEPGRAPH_SERVICE_LIMITS_VERSION {
            return Err(
                DepgraphServiceConfigurationError::UnsupportedLimitsVersion { version }.into(),
            );
        }
        for (limit, value) in [
            (
                DepgraphServiceLimit::InlineInputBytes,
                max_inline_input_bytes,
            ),
            (DepgraphServiceLimit::OutputBytes, max_output_bytes),
            (DepgraphServiceLimit::DefaultPageItems, default_page_items),
            (DepgraphServiceLimit::MaxPageItems, max_page_items),
        ] {
            if value == 0 {
                return Err(DepgraphServiceConfigurationError::ZeroLimit { limit }.into());
            }
        }
        if default_page_items > max_page_items {
            return Err(DepgraphServiceConfigurationError::InvalidPageLimits.into());
        }
        Ok(Self {
            version,
            max_inline_input_bytes,
            max_output_bytes,
            default_page_items,
            max_page_items,
        })
    }

    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }

    #[must_use]
    pub const fn max_inline_input_bytes(&self) -> usize {
        self.max_inline_input_bytes
    }

    #[must_use]
    pub const fn max_output_bytes(&self) -> usize {
        self.max_output_bytes
    }

    #[must_use]
    pub const fn default_page_items(&self) -> usize {
        self.default_page_items
    }

    #[must_use]
    pub const fn max_page_items(&self) -> usize {
        self.max_page_items
    }
}

impl Default for DepgraphServiceLimits {
    fn default() -> Self {
        Self {
            version: DEPGRAPH_SERVICE_LIMITS_VERSION.to_owned(),
            max_inline_input_bytes: DEFAULT_SERVICE_MAX_INLINE_INPUT_BYTES,
            max_output_bytes: DEFAULT_SERVICE_MAX_OUTPUT_BYTES,
            default_page_items: DEFAULT_SERVICE_PAGE_ITEMS,
            max_page_items: DEFAULT_SERVICE_MAX_PAGE_ITEMS,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DepgraphServiceConfig {
    canonical_root: PathBuf,
    store_path: PathBuf,
    capabilities: DepgraphCapabilitySet,
    limits: DepgraphServiceLimits,
}

impl DepgraphServiceConfig {
    pub fn new(
        root: impl AsRef<Path>,
        store_path: impl AsRef<Path>,
        capabilities: DepgraphCapabilitySet,
        limits: DepgraphServiceLimits,
    ) -> DepgraphServiceResult<Self> {
        validate_capabilities(&capabilities.values)?;
        let canonical_root = canonical_repository_root(root.as_ref())?;
        let store_path = fixed_store_path(store_path.as_ref())?;
        Ok(Self {
            canonical_root,
            store_path,
            capabilities,
            limits,
        })
    }

    #[must_use]
    pub fn canonical_root(&self) -> &Path {
        &self.canonical_root
    }

    #[must_use]
    pub fn store_path(&self) -> &Path {
        &self.store_path
    }

    #[must_use]
    pub const fn capabilities(&self) -> &DepgraphCapabilitySet {
        &self.capabilities
    }

    #[must_use]
    pub const fn limits(&self) -> &DepgraphServiceLimits {
        &self.limits
    }
}

fn canonical_repository_root(root: &Path) -> DepgraphServiceResult<PathBuf> {
    let canonical = root.canonicalize().map_err(|source| {
        DepgraphServiceError::from(DepgraphServiceConfigurationError::RootUnavailable { source })
    })?;
    let metadata = fs::metadata(&canonical).map_err(|source| {
        DepgraphServiceError::from(DepgraphServiceConfigurationError::RootUnavailable { source })
    })?;
    if !metadata.is_dir() {
        return Err(DepgraphServiceConfigurationError::RootNotDirectory.into());
    }
    Ok(canonical)
}

fn fixed_store_path(path: &Path) -> DepgraphServiceResult<PathBuf> {
    if !path.is_absolute() {
        return Err(DepgraphServiceConfigurationError::StorePathNotAbsolute.into());
    }
    if path
        .components()
        .any(|component| component == Component::ParentDir)
    {
        return Err(DepgraphServiceConfigurationError::StorePathContainsParentTraversal.into());
    }
    if path.file_name().is_none() {
        return Err(DepgraphServiceConfigurationError::StorePathInvalid.into());
    }

    let mut cursor = path;
    let mut missing_components = Vec::new();
    loop {
        match fs::symlink_metadata(cursor) {
            Ok(metadata) => {
                if missing_components.is_empty() && metadata.file_type().is_symlink() {
                    return Err(DepgraphServiceConfigurationError::StorePathIsSymlink.into());
                }
                let canonical = cursor.canonicalize().map_err(|source| {
                    DepgraphServiceError::from(
                        DepgraphServiceConfigurationError::StorePathUnavailable { source },
                    )
                })?;
                let canonical_metadata = fs::metadata(&canonical).map_err(|source| {
                    DepgraphServiceError::from(
                        DepgraphServiceConfigurationError::StorePathUnavailable { source },
                    )
                })?;
                if missing_components.is_empty() {
                    if !canonical_metadata.is_file() {
                        return Err(DepgraphServiceConfigurationError::StorePathNotFile.into());
                    }
                } else if !canonical_metadata.is_dir() {
                    return Err(
                        DepgraphServiceConfigurationError::StorePathAncestorNotDirectory.into(),
                    );
                }
                let mut fixed = canonical;
                for component in missing_components.iter().rev() {
                    fixed.push(component);
                }
                return Ok(fixed);
            }
            Err(source) if source.kind() == io::ErrorKind::NotFound => {
                let Some(component) = cursor.file_name() else {
                    return Err(DepgraphServiceConfigurationError::StorePathInvalid.into());
                };
                missing_components.push(component.to_owned());
                let Some(parent) = cursor.parent() else {
                    return Err(DepgraphServiceConfigurationError::StorePathInvalid.into());
                };
                cursor = parent;
            }
            Err(source) => {
                return Err(
                    DepgraphServiceConfigurationError::StorePathUnavailable { source }.into(),
                );
            }
        }
    }
}

#[derive(Clone)]
pub struct DepgraphService {
    config: Arc<DepgraphServiceConfig>,
}

impl DepgraphService {
    #[must_use]
    pub fn new(config: DepgraphServiceConfig) -> Self {
        Self {
            config: Arc::new(config),
        }
    }

    #[must_use]
    pub fn config(&self) -> &DepgraphServiceConfig {
        &self.config
    }

    #[must_use]
    pub fn read_store_factory(&self) -> RequestReadStoreFactory {
        RequestReadStoreFactory {
            config: Arc::clone(&self.config),
        }
    }

    pub fn execute_mutating<U>(&self, use_case: U) -> DepgraphServiceResult<U::Output>
    where
        U: DepgraphMutatingUseCase,
    {
        for required in U::KIND.required_capabilities() {
            if !self.config.capabilities.contains(*required) {
                return Err(DepgraphServiceError::CapabilityDenied {
                    required: *required,
                });
            }
        }
        let mut store = if U::KIND.opens_store() {
            Some(
                Store::open(&self.config.store_path)
                    .map_err(|source| DepgraphServiceError::MutatingStoreUnavailable { source })?,
            )
        } else {
            None
        };
        let mut context = DepgraphMutatingContext {
            config: &self.config,
            kind: U::KIND,
            store: store.as_mut(),
        };
        use_case.execute(&mut context)
    }
}

#[derive(Clone)]
pub struct RequestReadStoreFactory {
    config: Arc<DepgraphServiceConfig>,
}

impl RequestReadStoreFactory {
    pub fn open(&self) -> DepgraphServiceResult<RequestReadStore> {
        let store = Store::open_read_only(&self.config.store_path)
            .map_err(|source| DepgraphServiceError::ReadStoreUnavailable { source })?;
        Ok(RequestReadStore { store })
    }
}

pub struct RequestReadStore {
    store: Store,
}

impl RequestReadStore {
    /// Returns the request-owned store handle.
    ///
    /// Some legacy `Store` query APIs take `&mut self` for prepared-statement
    /// caches or best-effort persistent cache touches. This connection is
    /// opened with SQLite's read-only flag, so those persistent writes fail
    /// closed and cannot mutate the store.
    pub fn store(&mut self) -> &mut Store {
        &mut self.store
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DepgraphMutatingUseCaseKind {
    Store,
    Repository,
    Daemon,
    ProjectExecution,
}

impl DepgraphMutatingUseCaseKind {
    #[must_use]
    pub const fn required_capabilities(self) -> &'static [DepgraphCapability] {
        match self {
            Self::Store => &[DepgraphCapability::Read, DepgraphCapability::StoreWrite],
            Self::Repository => &[
                DepgraphCapability::Read,
                DepgraphCapability::RepositoryWrite,
            ],
            Self::Daemon => &[
                DepgraphCapability::Read,
                DepgraphCapability::StoreWrite,
                DepgraphCapability::DaemonControl,
            ],
            Self::ProjectExecution => &[
                DepgraphCapability::Read,
                DepgraphCapability::StoreWrite,
                DepgraphCapability::ProjectExec,
            ],
        }
    }

    const fn opens_store(self) -> bool {
        !matches!(self, Self::Repository)
    }
}

pub trait DepgraphMutatingUseCase {
    type Output;

    const KIND: DepgraphMutatingUseCaseKind;

    fn execute(
        self,
        context: &mut DepgraphMutatingContext<'_>,
    ) -> DepgraphServiceResult<Self::Output>;
}

pub struct DepgraphMutatingContext<'a> {
    config: &'a DepgraphServiceConfig,
    kind: DepgraphMutatingUseCaseKind,
    store: Option<&'a mut Store>,
}

impl DepgraphMutatingContext<'_> {
    #[must_use]
    pub const fn kind(&self) -> DepgraphMutatingUseCaseKind {
        self.kind
    }

    #[must_use]
    pub fn canonical_root(&self) -> &Path {
        self.config.canonical_root()
    }

    #[must_use]
    pub fn store_path(&self) -> &Path {
        self.config.store_path()
    }

    pub fn store(&mut self) -> Option<&mut Store> {
        self.store.as_deref_mut()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DepgraphServiceErrorCategory {
    Configuration,
    Authorization,
    Input,
    NotFound,
    Conflict,
    Resource,
    Cancelled,
    Store,
    Integrity,
    Internal,
}

#[derive(Debug, thiserror::Error)]
pub enum DepgraphServiceError {
    #[error("invalid service configuration: {reason}")]
    InvalidConfiguration {
        #[source]
        reason: DepgraphServiceConfigurationError,
    },
    #[error("required capability is not enabled: {required}")]
    CapabilityDenied { required: DepgraphCapability },
    #[error("invalid service input")]
    InvalidInput,
    #[error("requested service resource was not found")]
    NotFound,
    #[error("request conflicts with the current service state")]
    Conflict,
    #[error("request exhausted a service resource limit")]
    ResourceExhausted,
    #[error("request was cancelled")]
    Cancelled,
    #[error("read-only store is unavailable")]
    ReadStoreUnavailable {
        #[source]
        source: anyhow::Error,
    },
    #[error("mutating store is unavailable")]
    MutatingStoreUnavailable {
        #[source]
        source: anyhow::Error,
    },
    #[error("store operation failed")]
    StoreOperation {
        #[source]
        source: anyhow::Error,
    },
    #[error("service integrity validation failed")]
    Integrity,
    #[error("internal service failure")]
    Internal,
}

impl DepgraphServiceError {
    #[must_use]
    pub const fn category(&self) -> DepgraphServiceErrorCategory {
        match self {
            Self::InvalidConfiguration { .. } => DepgraphServiceErrorCategory::Configuration,
            Self::CapabilityDenied { .. } => DepgraphServiceErrorCategory::Authorization,
            Self::InvalidInput => DepgraphServiceErrorCategory::Input,
            Self::NotFound => DepgraphServiceErrorCategory::NotFound,
            Self::Conflict => DepgraphServiceErrorCategory::Conflict,
            Self::ResourceExhausted => DepgraphServiceErrorCategory::Resource,
            Self::Cancelled => DepgraphServiceErrorCategory::Cancelled,
            Self::ReadStoreUnavailable { .. }
            | Self::MutatingStoreUnavailable { .. }
            | Self::StoreOperation { .. } => DepgraphServiceErrorCategory::Store,
            Self::Integrity => DepgraphServiceErrorCategory::Integrity,
            Self::Internal => DepgraphServiceErrorCategory::Internal,
        }
    }

    pub fn store_operation(source: anyhow::Error) -> Self {
        Self::StoreOperation { source }
    }
}

impl From<DepgraphServiceConfigurationError> for DepgraphServiceError {
    fn from(reason: DepgraphServiceConfigurationError) -> Self {
        Self::InvalidConfiguration { reason }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DepgraphServiceConfigurationError {
    #[error("repository root is unavailable")]
    RootUnavailable {
        #[source]
        source: io::Error,
    },
    #[error("repository root is not a directory")]
    RootNotDirectory,
    #[error("store path must be absolute")]
    StorePathNotAbsolute,
    #[error("store path must not contain parent traversal")]
    StorePathContainsParentTraversal,
    #[error("store path is invalid")]
    StorePathInvalid,
    #[error("store path must not be a symbolic link")]
    StorePathIsSymlink,
    #[error("store path is not a regular file")]
    StorePathNotFile,
    #[error("an existing store path ancestor is not a directory")]
    StorePathAncestorNotDirectory,
    #[error("store path is unavailable")]
    StorePathUnavailable {
        #[source]
        source: io::Error,
    },
    #[error("capability {capability} is declared more than once")]
    DuplicateCapability { capability: DepgraphCapability },
    #[error("required capability {capability} is missing")]
    MissingCapability { capability: DepgraphCapability },
    #[error("capability {capability} requires {requires}")]
    MissingCapabilityDependency {
        capability: DepgraphCapability,
        requires: DepgraphCapability,
    },
    #[error("unsupported service limits version")]
    UnsupportedLimitsVersion { version: String },
    #[error("service limit {limit} must be greater than zero")]
    ZeroLimit { limit: DepgraphServiceLimit },
    #[error("default page items must not exceed maximum page items")]
    InvalidPageLimits,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn foundational_error_categories_are_selected_by_variant() {
        for (error, category) in [
            (
                DepgraphServiceError::InvalidInput,
                DepgraphServiceErrorCategory::Input,
            ),
            (
                DepgraphServiceError::NotFound,
                DepgraphServiceErrorCategory::NotFound,
            ),
            (
                DepgraphServiceError::Conflict,
                DepgraphServiceErrorCategory::Conflict,
            ),
            (
                DepgraphServiceError::ResourceExhausted,
                DepgraphServiceErrorCategory::Resource,
            ),
            (
                DepgraphServiceError::Cancelled,
                DepgraphServiceErrorCategory::Cancelled,
            ),
            (
                DepgraphServiceError::Integrity,
                DepgraphServiceErrorCategory::Integrity,
            ),
            (
                DepgraphServiceError::Internal,
                DepgraphServiceErrorCategory::Internal,
            ),
        ] {
            assert_eq!(error.category(), category);
        }
    }

    #[test]
    fn duplicate_capability_input_is_rejected_before_set_construction() {
        let error =
            DepgraphCapabilitySet::try_new([DepgraphCapability::Read, DepgraphCapability::Read])
                .unwrap_err();
        assert!(matches!(
            error,
            DepgraphServiceError::InvalidConfiguration {
                reason: DepgraphServiceConfigurationError::DuplicateCapability {
                    capability: DepgraphCapability::Read
                }
            }
        ));
    }
}
