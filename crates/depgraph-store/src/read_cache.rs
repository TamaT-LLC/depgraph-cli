//! Process-local reuse of completed-snapshot reads for long-lived readers.
//!
//! A long-lived reader such as the MCP server opens a fresh read-only
//! connection per request. Without reuse, every request recomputes the
//! completed-snapshot storage seal over the whole snapshot closure and
//! reconstructs the whole snapshot from SQLite, which takes seconds on a large
//! store (Issue #599).
//!
//! Both kinds of reuse are bound to a [`StoreFileToken`]: the identity and
//! modification stamps of the store file and its WAL file, the first 100 bytes
//! of the database header (whose change counter moves on every commit in
//! rollback-journal mode) and the WAL-index header in the `-shm` file (whose
//! change counter and frame count move on every WAL commit). Any commit,
//! checkpoint, WAL reset, file replacement or out-of-band write changes the
//! token, so a cached result is never reused across a change to the store:
//!
//! * a storage seal recorded as verified is trusted only while the token equals
//!   the store state the verification read; and
//! * a reconstructed completed snapshot is reused only while the token equals
//!   the store state it was reconstructed from.
//!
//! The state a read saw is known in two ways. Outside a transaction, the token
//! must be unchanged before and after the work, so no commit landed between
//! its statements. Inside [`crate::Store::interruptible_read`], the token is
//! observed before `BEGIN`, a first read then fixes the transaction's read
//! snapshot, and the token is observed again; when both match, the whole
//! transaction reads exactly that state ([`pin_read`]). Any other open
//! transaction never uses the cache, because its read snapshot may predate the
//! files' current state.
//!
//! Reuse is off unless the process opts in with [`enable_read_cache`], and it
//! applies only to read-only connections on a file-backed store, so a writer
//! that changes rows inside an open transaction always recomputes the seal.

use std::{
    fs::File,
    io::Read,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicBool, Ordering},
    },
};

use rusqlite::{Connection, MAIN_DB};

use crate::GraphSnapshot;

/// Number of verified seals remembered per process. Each entry is small; the
/// bound only keeps a server that reads many snapshots from growing without
/// limit.
const MAX_VERIFIED_SEALS: usize = 32;

static ENABLED: AtomicBool = AtomicBool::new(false);
static CACHE: Mutex<ReadCache> = Mutex::new(ReadCache {
    seals: Vec::new(),
    snapshot: None,
});

/// Lets this process reuse verified seals and reconstructed completed
/// snapshots across read-only connections while the store files are unchanged.
///
/// Intended for long-lived read servers. At most one reconstructed snapshot is
/// kept, so the extra memory is bounded by the largest snapshot read.
pub fn enable_read_cache() {
    ENABLED.store(true, Ordering::Release);
}

#[cfg(test)]
thread_local! {
    static TEST_ENABLED: std::cell::Cell<Option<bool>> = const { std::cell::Cell::new(None) };
    static TEST_COUNTS: std::cell::Cell<ReadCacheCounts> = const {
        std::cell::Cell::new(ReadCacheCounts { seal_hits: 0, snapshot_hits: 0, snapshot_loads: 0 })
    };
}

/// Overrides [`enable_read_cache`] for the current test thread only, so unit
/// tests running in parallel never observe each other's setting.
#[cfg(test)]
pub(crate) fn set_read_cache_enabled_for_test(enabled: bool) {
    TEST_ENABLED.with(|cell| cell.set(Some(enabled)));
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct ReadCacheCounts {
    pub(crate) seal_hits: usize,
    pub(crate) snapshot_hits: usize,
    pub(crate) snapshot_loads: usize,
}

#[cfg(test)]
pub(crate) fn take_read_cache_counts_for_test() -> ReadCacheCounts {
    TEST_COUNTS.with(|cell| cell.replace(ReadCacheCounts::default()))
}

#[cfg(test)]
fn count(update: impl FnOnce(&mut ReadCacheCounts)) {
    TEST_COUNTS.with(|cell| {
        let mut counts = cell.get();
        update(&mut counts);
        cell.set(counts);
    });
}

#[cfg(not(test))]
fn count(_update: impl FnOnce(&mut ReadCacheCounts)) {}

fn enabled() -> bool {
    #[cfg(test)]
    if let Some(enabled) = TEST_ENABLED.with(std::cell::Cell::get) {
        return enabled;
    }
    ENABLED.load(Ordering::Acquire)
}

struct ReadCache {
    seals: Vec<VerifiedSeal>,
    snapshot: Option<CachedSnapshot>,
}

struct VerifiedSeal {
    path: PathBuf,
    snapshot_id: String,
    seal_sha256: String,
    token: StoreFileToken,
}

struct CachedSnapshot {
    path: PathBuf,
    snapshot_id: String,
    token: StoreFileToken,
    snapshot: Arc<GraphSnapshot>,
}

fn cache() -> MutexGuard<'static, ReadCache> {
    // The cache holds only immutable values, so a panic while it was locked
    // cannot leave a half-written entry behind.
    CACHE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Change stamp of one file: identity (where the platform exposes it), size
/// and modification time.
#[derive(Clone, Debug, PartialEq, Eq)]
struct FileStamp {
    identity: (u64, u64),
    size: u64,
    modified: std::time::Duration,
}

impl FileStamp {
    fn of(file: &File) -> std::io::Result<Self> {
        let metadata = file.metadata()?;
        #[cfg(unix)]
        let identity = {
            use std::os::unix::fs::MetadataExt as _;
            (metadata.dev(), metadata.ino())
        };
        #[cfg(not(unix))]
        let identity = (0, 0);
        let modified = metadata
            .modified()?
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(std::io::Error::other)?;
        Ok(Self {
            identity,
            size: metadata.len(),
            modified,
        })
    }
}

/// Observable state of a store's files; see the module documentation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct StoreFileToken {
    database: FileStamp,
    database_header: Vec<u8>,
    wal: Option<FileStamp>,
    wal_index_header: Option<Vec<u8>>,
}

impl StoreFileToken {
    fn observe(path: &Path) -> Option<Self> {
        let (database, database_header) = stamp_and_prefix(path, 100)?;
        let wal = sidecar(path, "-wal")
            .and_then(|path| stamp_and_prefix(&path, 32))
            .map(|(stamp, _)| stamp);
        // Both copies of the WAL-index header (2 x 48 bytes).
        let wal_index_header =
            sidecar(path, "-shm").and_then(|path| stamp_and_prefix(&path, 96).map(|(_, h)| h));
        Some(Self {
            database,
            database_header,
            wal,
            wal_index_header,
        })
    }
}

fn sidecar(path: &Path, suffix: &str) -> Option<PathBuf> {
    let mut name = path.file_name()?.to_os_string();
    name.push(suffix);
    Some(path.with_file_name(name))
}

fn stamp_and_prefix(path: &Path, length: u64) -> Option<(FileStamp, Vec<u8>)> {
    let file = File::open(path).ok()?;
    let stamp = FileStamp::of(&file).ok()?;
    let mut prefix = Vec::new();
    file.take(length).read_to_end(&mut prefix).ok()?;
    Some((stamp, prefix))
}

/// The store path of a connection that may use the cache, or `None` when the
/// cache is disabled, the store is in memory, or the connection can write.
fn cacheable_path(connection: &Connection) -> Option<PathBuf> {
    if !enabled() {
        return None;
    }
    if !connection.is_readonly(MAIN_DB).ok()? {
        return None;
    }
    let path = connection.path()?;
    if path.is_empty() {
        return None;
    }
    Some(PathBuf::from(path))
}

/// A read transaction whose SQLite read snapshot is known to be the store state
/// described by `token`.
struct PinnedRead {
    connection: usize,
    path: PathBuf,
    token: StoreFileToken,
}

thread_local! {
    static PINNED_READ: std::cell::RefCell<Option<PinnedRead>> =
        const { std::cell::RefCell::new(None) };
}

fn connection_key(connection: &Connection) -> usize {
    std::ptr::from_ref(connection) as usize
}

/// Store state observed just before a read transaction begins.
pub(crate) struct BeforeRead(Option<(PathBuf, StoreFileToken)>);

pub(crate) fn observe_before_read(connection: &Connection) -> BeforeRead {
    BeforeRead(cacheable_path(connection).and_then(|path| {
        let token = StoreFileToken::observe(&path)?;
        Some((path, token))
    }))
}

/// Marks the current thread's open read transaction on `connection` as pinned
/// to the observed store state until the guard is dropped.
pub(crate) struct PinnedReadGuard {
    previous: Option<PinnedRead>,
    active: bool,
}

impl Drop for PinnedReadGuard {
    fn drop(&mut self) {
        if self.active {
            let previous = self.previous.take();
            PINNED_READ.with(|pinned| *pinned.borrow_mut() = previous);
        }
    }
}

/// Called right after `BEGIN DEFERRED` on `connection`. A first read fixes the
/// transaction's read snapshot; if the store files are unchanged from `before`
/// across that read, the snapshot is exactly the state `before` describes, so
/// reuse keyed by that state is sound for the rest of the transaction.
pub(crate) fn pin_read(connection: &Connection, before: BeforeRead) -> PinnedReadGuard {
    let inactive = PinnedReadGuard {
        previous: None,
        active: false,
    };
    let Some((path, token)) = before.0 else {
        return inactive;
    };
    if connection
        .query_row("SELECT COUNT(*) FROM sqlite_master", [], |row| {
            row.get::<_, i64>(0)
        })
        .is_err()
        || StoreFileToken::observe(&path).as_ref() != Some(&token)
    {
        return inactive;
    }
    let previous = PINNED_READ.with(|pinned| {
        pinned.borrow_mut().replace(PinnedRead {
            connection: connection_key(connection),
            path,
            token,
        })
    });
    PinnedReadGuard {
        previous,
        active: true,
    }
}

/// The store state a cache lookup on `connection` may rely on.
struct ReadState {
    path: PathBuf,
    token: StoreFileToken,
    /// The connection reads inside a transaction pinned to `token`; otherwise
    /// each statement runs in its own transaction and the token must be
    /// observed again after the work.
    pinned: bool,
}

fn read_state(connection: &Connection) -> Option<ReadState> {
    let path = cacheable_path(connection)?;
    if !connection.is_autocommit() {
        // Inside a transaction the read snapshot may predate any token
        // observed now, so only a transaction pinned by `pin_read` qualifies.
        return PINNED_READ.with(|pinned| {
            let pinned = pinned.borrow();
            let pinned = pinned.as_ref()?;
            (pinned.connection == connection_key(connection) && pinned.path == path).then(|| {
                ReadState {
                    path,
                    token: pinned.token.clone(),
                    pinned: true,
                }
            })
        });
    }
    let token = StoreFileToken::observe(&path)?;
    Some(ReadState {
        path,
        token,
        pinned: false,
    })
}

impl ReadState {
    /// Whether work done since this state was taken saw exactly that state.
    fn still_current(&self) -> bool {
        self.pinned || StoreFileToken::observe(&self.path).as_ref() == Some(&self.token)
    }
}

/// Verifies a completed-snapshot seal with `verify`, unless the same stored
/// seal was already verified for this store and the store files have not
/// changed since.
pub(crate) fn verify_seal_with<F>(
    connection: &Connection,
    snapshot_id: &str,
    seal_sha256: &str,
    verify: F,
) -> anyhow::Result<()>
where
    F: FnOnce() -> anyhow::Result<()>,
{
    let Some(state) = read_state(connection) else {
        return verify();
    };
    if cache().seals.iter().any(|seal| {
        seal.path == state.path
            && seal.snapshot_id == snapshot_id
            && seal.seal_sha256 == seal_sha256
            && seal.token == state.token
    }) {
        count(|counts| counts.seal_hits += 1);
        return Ok(());
    }
    verify()?;
    if state.still_current() {
        let mut cache = cache();
        cache
            .seals
            .retain(|seal| !(seal.path == state.path && seal.snapshot_id == snapshot_id));
        if cache.seals.len() >= MAX_VERIFIED_SEALS {
            cache.seals.remove(0);
        }
        cache.seals.push(VerifiedSeal {
            path: state.path,
            snapshot_id: snapshot_id.to_owned(),
            seal_sha256: seal_sha256.to_owned(),
            token: state.token,
        });
    }
    Ok(())
}

/// Returns the reconstructed completed snapshot, reusing the one kept for this
/// store when the store files have not changed since it was reconstructed.
pub(crate) fn load_completed_snapshot_with<F>(
    connection: &Connection,
    snapshot_id: &str,
    load: F,
) -> anyhow::Result<Arc<GraphSnapshot>>
where
    F: FnOnce() -> anyhow::Result<GraphSnapshot>,
{
    let Some(state) = read_state(connection) else {
        return load().map(Arc::new);
    };
    let stale = {
        let mut cache = cache();
        if let Some(cached) = &cache.snapshot
            && cached.path == state.path
            && cached.snapshot_id == snapshot_id
            && cached.token == state.token
        {
            count(|counts| counts.snapshot_hits += 1);
            return Ok(Arc::clone(&cached.snapshot));
        }
        cache.snapshot.take()
    };
    // Release the kept copy (outside the lock) before reading another one so
    // that two full snapshots are not held at once.
    drop(stale);
    count(|counts| counts.snapshot_loads += 1);
    let snapshot = Arc::new(load()?);
    if state.still_current() {
        cache().snapshot = Some(CachedSnapshot {
            path: state.path,
            snapshot_id: snapshot_id.to_owned(),
            token: state.token,
            snapshot: Arc::clone(&snapshot),
        });
    }
    Ok(snapshot)
}
