use crate::CancellationToken;
use crate::service::{
    DepgraphService, DepgraphServiceError, DepgraphServiceResult, RequestReadStore,
};

const STABLE_SNAPSHOT_ID_PREFIX: &str = "snapshot:sha256:";
const MAX_SNAPSHOT_NAME_BYTES: usize = 64;

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SnapshotLocator {
    Current,
    Name(String),
    StableId(String),
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

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ResolvedSnapshotId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

pub struct SnapshotReadRequest {
    snapshot_id: ResolvedSnapshotId,
    locator: SnapshotLocator,
    read_store: RequestReadStore,
}

impl SnapshotReadRequest {
    #[must_use]
    pub const fn snapshot_id(&self) -> &ResolvedSnapshotId {
        &self.snapshot_id
    }

    #[must_use]
    pub const fn locator(&self) -> &SnapshotLocator {
        &self.locator
    }

    #[must_use]
    pub const fn is_current(&self) -> bool {
        matches!(self.locator, SnapshotLocator::Current)
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
        if scan_id.is_empty() || scan_id.len() > 256 || scan_id.chars().any(char::is_control) {
            return Err(DepgraphServiceError::InvalidInput);
        }
        if cancellation.is_cancelled() {
            return Err(DepgraphServiceError::Cancelled);
        }
        let mut read_store = self.read_store_factory().open()?;
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
            locator: SnapshotLocator::StableId(snapshot.id),
            read_store,
        })
    }

    pub fn start_snapshot_request_at_cancellable(
        &self,
        locator: &SnapshotLocator,
        cancellation: &CancellationToken,
    ) -> DepgraphServiceResult<SnapshotReadRequest> {
        validate_locator(locator)?;
        if cancellation.is_cancelled() {
            return Err(DepgraphServiceError::Cancelled);
        }
        let mut read_store = self.read_store_factory().open()?;
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
            locator: locator.clone(),
            read_store,
        })
    }
}

fn validate_locator(locator: &SnapshotLocator) -> DepgraphServiceResult<()> {
    match locator {
        SnapshotLocator::Current => Ok(()),
        SnapshotLocator::Name(name) => validate_snapshot_name(name),
        SnapshotLocator::StableId(snapshot_id) if is_stable_snapshot_id(snapshot_id) => Ok(()),
        SnapshotLocator::StableId(_) => Err(DepgraphServiceError::InvalidInput),
    }
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
