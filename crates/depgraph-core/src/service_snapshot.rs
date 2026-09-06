use depgraph_store::AnalysisCoverageSummary;

use crate::CancellationToken;
use crate::service::{
    DepgraphService, DepgraphServiceError, DepgraphServiceResult, RequestReadStore,
};

const STABLE_SNAPSHOT_ID_PREFIX: &str = "snapshot:sha256:";
const ATTEMPT_SELECTOR_PREFIX: &str = "attempt:";
const MAX_SNAPSHOT_NAME_BYTES: usize = 64;
const MAX_ATTEMPT_ID_BYTES: usize = 256;

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SnapshotLocator {
    Current,
    Name(String),
    StableId(String),
    /// A terminal, non-promoted scan attempt.  This selector is intentionally
    /// separate from completed snapshot IDs: it reads the attempt's staged
    /// graph and never changes the completed-snapshot pointer.
    Attempt(String),
}

impl SnapshotLocator {
    pub fn parse(locator: impl AsRef<str>) -> DepgraphServiceResult<Self> {
        let locator = locator.as_ref();
        if locator.eq_ignore_ascii_case("current") {
            return Ok(Self::Current);
        }
        if locator.eq_ignore_ascii_case("latest") {
            return Err(DepgraphServiceError::InvalidInput);
        }
        if locator.starts_with(STABLE_SNAPSHOT_ID_PREFIX) {
            if !is_stable_snapshot_id(locator) {
                return Err(DepgraphServiceError::InvalidInput);
            }
            return Ok(Self::StableId(locator.to_owned()));
        }
        if let Some(attempt_id) = locator.strip_prefix(ATTEMPT_SELECTOR_PREFIX) {
            validate_attempt_id(attempt_id)?;
            return Ok(Self::Attempt(attempt_id.to_owned()));
        }
        validate_snapshot_name(locator)?;
        Ok(Self::Name(locator.to_owned()))
    }
}

impl std::str::FromStr for SnapshotLocator {
    type Err = DepgraphServiceError;

    fn from_str(locator: &str) -> Result<Self, Self::Err> {
        Self::parse(locator)
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ResolvedSnapshotId(String);

impl ResolvedSnapshotId {
    pub(crate) fn from_completed(value: String) -> DepgraphServiceResult<Self> {
        if is_stable_snapshot_id(&value) {
            Ok(Self(value))
        } else {
            Err(DepgraphServiceError::Integrity)
        }
    }

    pub(crate) fn from_attempt(scan_id: &str) -> DepgraphServiceResult<Self> {
        validate_attempt_id(scan_id)?;
        Ok(Self(format!("{ATTEMPT_SELECTOR_PREFIX}{scan_id}")))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn is_attempt(&self) -> bool {
        self.0.starts_with(ATTEMPT_SELECTOR_PREFIX)
    }

    #[must_use]
    pub fn attempt_id(&self) -> Option<&str> {
        self.0.strip_prefix(ATTEMPT_SELECTOR_PREFIX)
    }
}

impl std::fmt::Display for ResolvedSnapshotId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

pub struct SnapshotReadRequest {
    snapshot_id: ResolvedSnapshotId,
    scan_id: String,
    locator: SnapshotLocator,
    read_store: RequestReadStore,
    partial_metadata: Option<PartialSnapshotMetadata>,
}

/// Immutable metadata captured when a terminal partial attempt is pinned for
/// reading.  The graph itself remains in the Store's staging tables; this
/// value gives callers the identities needed to explain why the result is
/// incomplete without making a staged attempt look like a completed snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PartialSnapshotMetadata {
    attempt_id: String,
    status: String,
    root: String,
    started_at: String,
    completed_at: Option<String>,
    project_code_executed: bool,
    error: Option<String>,
    analysis_coverage: Option<AnalysisCoverageSummary>,
}

impl PartialSnapshotMetadata {
    #[must_use]
    pub fn attempt_id(&self) -> &str {
        &self.attempt_id
    }

    #[must_use]
    pub fn status(&self) -> &str {
        &self.status
    }

    #[must_use]
    pub fn root(&self) -> &str {
        &self.root
    }

    #[must_use]
    pub fn started_at(&self) -> &str {
        &self.started_at
    }

    #[must_use]
    pub fn completed_at(&self) -> Option<&str> {
        self.completed_at.as_deref()
    }

    #[must_use]
    pub const fn project_code_executed(&self) -> bool {
        self.project_code_executed
    }

    #[must_use]
    pub fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }

    #[must_use]
    pub const fn analysis_coverage(&self) -> Option<&AnalysisCoverageSummary> {
        self.analysis_coverage.as_ref()
    }
}

impl SnapshotReadRequest {
    #[must_use]
    pub const fn snapshot_id(&self) -> &ResolvedSnapshotId {
        &self.snapshot_id
    }

    #[must_use]
    pub fn scan_id(&self) -> &str {
        &self.scan_id
    }

    #[must_use]
    pub const fn locator(&self) -> &SnapshotLocator {
        &self.locator
    }

    #[must_use]
    pub const fn is_current(&self) -> bool {
        matches!(self.locator, SnapshotLocator::Current)
    }

    #[must_use]
    pub const fn is_partial(&self) -> bool {
        self.partial_metadata.is_some()
    }

    #[must_use]
    pub const fn partial_metadata(&self) -> Option<&PartialSnapshotMetadata> {
        self.partial_metadata.as_ref()
    }

    pub fn store(&mut self) -> &mut depgraph_store::Store {
        self.read_store.store()
    }
}

impl DepgraphService {
    pub fn start_snapshot_request(
        &self,
        locator: impl AsRef<str>,
    ) -> DepgraphServiceResult<SnapshotReadRequest> {
        let locator = SnapshotLocator::parse(locator)?;
        self.start_snapshot_request_at(&locator)
    }

    pub fn start_snapshot_request_at(
        &self,
        locator: &SnapshotLocator,
    ) -> DepgraphServiceResult<SnapshotReadRequest> {
        self.start_snapshot_request_at_cancellable(locator, &CancellationToken::new())
    }

    pub fn resolve_snapshot_id_cancellable(
        &self,
        locator: &SnapshotLocator,
        cancellation: &CancellationToken,
    ) -> DepgraphServiceResult<ResolvedSnapshotId> {
        self.start_snapshot_request_at_cancellable(locator, cancellation)
            .map(|request| request.snapshot_id)
    }

    pub fn start_snapshot_request_for_scan(
        &self,
        scan_id: &str,
        cancellation: &CancellationToken,
    ) -> DepgraphServiceResult<SnapshotReadRequest> {
        self.start_snapshot_request_for_scan_with_schema(scan_id, cancellation, false)
    }

    pub(crate) fn start_snapshot_request_for_scan_before_migration(
        &self,
        scan_id: &str,
        cancellation: &CancellationToken,
    ) -> DepgraphServiceResult<SnapshotReadRequest> {
        self.start_snapshot_request_for_scan_with_schema(scan_id, cancellation, true)
    }

    fn start_snapshot_request_for_scan_with_schema(
        &self,
        scan_id: &str,
        cancellation: &CancellationToken,
        migration_compatible: bool,
    ) -> DepgraphServiceResult<SnapshotReadRequest> {
        if scan_id.is_empty() || scan_id.len() > 256 || scan_id.chars().any(char::is_control) {
            return Err(DepgraphServiceError::InvalidInput);
        }
        if cancellation.is_cancelled() {
            return Err(DepgraphServiceError::Cancelled);
        }
        let mut read_store = if migration_compatible {
            self.read_store_factory().open_for_migration()?
        } else {
            self.read_store_factory().open()?
        };
        let cancellation_check = cancellation.clone();
        let resolved = read_store.store().interruptible_read(
            move || cancellation_check.is_cancelled(),
            |store| {
                let snapshot_id = store.snapshot_id_for_scan_selection(scan_id)?;
                let snapshot = snapshot_id
                    .as_deref()
                    .map(|snapshot_id| store.completed_snapshot(snapshot_id))
                    .transpose()?
                    .flatten();
                Ok((snapshot_id, snapshot))
            },
        );
        if cancellation.is_cancelled() {
            return Err(DepgraphServiceError::Cancelled);
        }
        let (snapshot_id, snapshot) = resolved.map_err(DepgraphServiceError::store_operation)?;
        let snapshot_id = snapshot_id.ok_or(DepgraphServiceError::NotFound)?;
        if !is_stable_snapshot_id(&snapshot_id) {
            return Err(DepgraphServiceError::Integrity);
        }
        let snapshot = snapshot.ok_or(DepgraphServiceError::Integrity)?;
        if snapshot.status != "completed" || snapshot.id != snapshot_id {
            return Err(DepgraphServiceError::Integrity);
        }
        Ok(SnapshotReadRequest {
            snapshot_id: ResolvedSnapshotId(snapshot_id),
            scan_id: snapshot.scan_id,
            locator: SnapshotLocator::StableId(snapshot.id),
            read_store,
            partial_metadata: None,
        })
    }

    pub fn start_snapshot_request_at_cancellable(
        &self,
        locator: &SnapshotLocator,
        cancellation: &CancellationToken,
    ) -> DepgraphServiceResult<SnapshotReadRequest> {
        self.start_snapshot_request_at_with_schema(locator, cancellation, false)
    }

    pub(crate) fn start_snapshot_request_at_before_migration(
        &self,
        locator: &SnapshotLocator,
        cancellation: &CancellationToken,
    ) -> DepgraphServiceResult<SnapshotReadRequest> {
        self.start_snapshot_request_at_with_schema(locator, cancellation, true)
    }

    fn start_snapshot_request_at_with_schema(
        &self,
        locator: &SnapshotLocator,
        cancellation: &CancellationToken,
        migration_compatible: bool,
    ) -> DepgraphServiceResult<SnapshotReadRequest> {
        validate_locator(locator)?;
        if cancellation.is_cancelled() {
            return Err(DepgraphServiceError::Cancelled);
        }
        let mut read_store = if migration_compatible {
            self.read_store_factory().open_for_migration()?
        } else {
            self.read_store_factory().open()?
        };

        if let SnapshotLocator::Attempt(attempt_id) = locator {
            // Partial attempts require the v19 ledger metadata.  The
            // migration-compatible read path is reserved for completed
            // snapshot inspection before an authorized migration and must not
            // accidentally treat an older staging schema as a partial result.
            if migration_compatible
                || read_store
                    .store()
                    .schema_version()
                    .map_err(DepgraphServiceError::store_operation)?
                    < depgraph_store::STORE_SCHEMA_VERSION
            {
                return Err(DepgraphServiceError::Integrity);
            }
            let scan = read_store
                .store()
                .scan(attempt_id)
                .map_err(DepgraphServiceError::store_operation)?
                .ok_or(DepgraphServiceError::NotFound)?;
            if scan.status == "staging" {
                return Err(DepgraphServiceError::Conflict);
            }
            if scan.status == "completed" {
                // Completed attempts must be addressed by their immutable
                // snapshot ID so callers cannot confuse two identities.
                return Err(DepgraphServiceError::InvalidInput);
            }
            if !matches!(
                scan.status.as_str(),
                "partial" | "failed" | "cancelled" | "policy_failed" | "security_failed"
            ) {
                return Err(DepgraphServiceError::Integrity);
            }
            let analysis_coverage = read_store
                .store()
                .analysis_coverage(attempt_id)
                .map_err(DepgraphServiceError::store_operation)?;
            let partial_metadata = PartialSnapshotMetadata {
                attempt_id: attempt_id.clone(),
                status: scan.status,
                root: scan.root,
                started_at: scan.started_at,
                completed_at: scan.completed_at,
                project_code_executed: scan.project_code_executed,
                error: scan.error,
                analysis_coverage,
            };
            let snapshot_id = ResolvedSnapshotId::from_attempt(attempt_id)?;
            return Ok(SnapshotReadRequest {
                snapshot_id,
                scan_id: attempt_id.clone(),
                locator: locator.clone(),
                read_store,
                partial_metadata: Some(partial_metadata),
            });
        }
        let cancellation_check = cancellation.clone();
        let resolved = read_store.store().interruptible_read(
            move || cancellation_check.is_cancelled(),
            |store| {
                let snapshot_id = match locator {
                    SnapshotLocator::Current => store.current_snapshot_id()?,
                    SnapshotLocator::Name(name) => store.snapshot_id_for_name(name)?,
                    SnapshotLocator::StableId(snapshot_id) => store
                        .completed_snapshot(snapshot_id)?
                        .map(|snapshot| snapshot.id),
                    SnapshotLocator::Attempt(_) => {
                        unreachable!("partial attempt selectors are handled before lookup")
                    }
                };
                let snapshot = snapshot_id
                    .as_deref()
                    .map(|snapshot_id| store.completed_snapshot(snapshot_id))
                    .transpose()?
                    .flatten();
                Ok((snapshot_id, snapshot))
            },
        );
        if cancellation.is_cancelled() {
            return Err(DepgraphServiceError::Cancelled);
        }
        let (snapshot_id, snapshot) = resolved.map_err(DepgraphServiceError::store_operation)?;
        let snapshot_id = snapshot_id.ok_or(DepgraphServiceError::NotFound)?;

        if !is_stable_snapshot_id(&snapshot_id) {
            return Err(DepgraphServiceError::Integrity);
        }
        let snapshot = snapshot.ok_or(DepgraphServiceError::Integrity)?;
        if snapshot.status != "completed" || snapshot.id != snapshot_id {
            return Err(DepgraphServiceError::Integrity);
        }

        Ok(SnapshotReadRequest {
            snapshot_id: ResolvedSnapshotId(snapshot_id),
            scan_id: snapshot.scan_id,
            locator: locator.clone(),
            read_store,
            partial_metadata: None,
        })
    }
}

fn validate_locator(locator: &SnapshotLocator) -> DepgraphServiceResult<()> {
    match locator {
        SnapshotLocator::Current => Ok(()),
        SnapshotLocator::Name(name) => validate_snapshot_name(name),
        SnapshotLocator::StableId(snapshot_id) if is_stable_snapshot_id(snapshot_id) => Ok(()),
        SnapshotLocator::StableId(_) => Err(DepgraphServiceError::InvalidInput),
        SnapshotLocator::Attempt(attempt_id) => validate_attempt_id(attempt_id),
    }
}

fn validate_attempt_id(attempt_id: &str) -> DepgraphServiceResult<()> {
    if attempt_id.is_empty()
        || attempt_id.len() > MAX_ATTEMPT_ID_BYTES
        || attempt_id.chars().any(char::is_control)
        || attempt_id.starts_with(ATTEMPT_SELECTOR_PREFIX)
    {
        return Err(DepgraphServiceError::InvalidInput);
    }
    Ok(())
}

fn validate_snapshot_name(name: &str) -> DepgraphServiceResult<()> {
    if name.is_empty()
        || name.len() > MAX_SNAPSHOT_NAME_BYTES
        || !name.is_ascii()
        || name.eq_ignore_ascii_case("current")
        || name.eq_ignore_ascii_case("latest")
        || name
            .get(..STABLE_SNAPSHOT_ID_PREFIX.len())
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(STABLE_SNAPSHOT_ID_PREFIX))
    {
        return Err(DepgraphServiceError::InvalidInput);
    }
    let mut bytes = name.bytes();
    let Some(first) = bytes.next() else {
        return Err(DepgraphServiceError::InvalidInput);
    };
    if !first.is_ascii_alphanumeric()
        || !bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(DepgraphServiceError::InvalidInput);
    }
    Ok(())
}

fn is_stable_snapshot_id(value: &str) -> bool {
    value
        .strip_prefix(STABLE_SNAPSHOT_ID_PREFIX)
        .is_some_and(|digest| {
            digest.len() == 64
                && digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
}
