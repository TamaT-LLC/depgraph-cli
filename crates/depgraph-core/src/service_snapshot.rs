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
    read_store: RequestReadStore,
}

impl SnapshotReadRequest {
    #[must_use]
    pub const fn snapshot_id(&self) -> &ResolvedSnapshotId {
        &self.snapshot_id
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
        validate_locator(locator)?;
        let mut read_store = self.read_store_factory().open()?;
        let snapshot_id = match locator {
            SnapshotLocator::Current => read_store
                .store()
                .current_snapshot_id()
                .map_err(DepgraphServiceError::store_operation)?,
            SnapshotLocator::Name(name) => read_store
                .store()
                .snapshot_id_for_name(name)
                .map_err(DepgraphServiceError::store_operation)?,
            SnapshotLocator::StableId(snapshot_id) => read_store
                .store()
                .completed_snapshot(snapshot_id)
                .map_err(DepgraphServiceError::store_operation)?
                .map(|snapshot| snapshot.id),
        }
        .ok_or(DepgraphServiceError::NotFound)?;

        if !is_stable_snapshot_id(&snapshot_id) {
            return Err(DepgraphServiceError::Integrity);
        }
        let snapshot = read_store
            .store()
            .completed_snapshot(&snapshot_id)
            .map_err(DepgraphServiceError::store_operation)?
            .ok_or(DepgraphServiceError::Integrity)?;
        if snapshot.status != "completed" || snapshot.id != snapshot_id {
            return Err(DepgraphServiceError::Integrity);
        }

        Ok(SnapshotReadRequest {
            snapshot_id: ResolvedSnapshotId(snapshot_id),
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
