//! Process-local reuse of completed-snapshot reads for long-lived readers.
//!
//! A long-lived reader such as the MCP server opens a fresh read-only
//! connection per request. Without reuse, every request recomputes the
//! completed-snapshot storage seal over the whole snapshot closure and
//! reconstructs the whole snapshot from SQLite, which takes seconds on a large
//! store (Issue #599).
//!
//! Both kinds of reuse are bound to a [`StoreFileToken`]: the `stat` stamps
//! (identity, size, modification and inode change times) of the store file and
//! its WAL file, and a commit generation read from `PRAGMA data_version` on a
//! read-only watcher connection kept open on the store. SQLite moves that
//! counter whenever any connection, in this process or another, commits. Any
//! commit, checkpoint, WAL reset, file replacement or out-of-band write
//! changes the token, so a cached result is never reused across a change to
//! the store. The token is only taken when the reading connection still has
//! the file its path names (`SQLITE_FCNTL_HAS_MOVED`), so a result read from a
//! renamed-away file is never recorded under the state of its replacement:
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
//! applies only to read-only connections on a file-backed store on Unix, so a
//! writer that changes rows inside an open transaction always recomputes the
//! seal.
//!
//! What this keeps from the per-read seal check: any change made through
//! SQLite, any replacement of the file, and any out-of-band write that moves
//! the file's size, modification time or inode change time is caught on the
//! next read. What it does not keep: an out-of-band rewrite of the database
//! body that leaves all of those unchanged, for example one landing within
//! the same timestamp tick as the read that verified the seal on a file
//! system with coarse timestamps, or a path switched to another device's file
//! that happens to have the same inode number (SQLite compares only inode
//! numbers for `SQLITE_FCNTL_HAS_MOVED`). The seal is an integrity check
//! stored in the same file, not a defence against a writer who can also
//! rewrite it, so a long-lived reader accepts this in exchange for not
//! hashing the whole snapshot on every request.

use std::{
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicBool, Ordering},
    },
};

use rusqlite::{Connection, MAIN_DB, OpenFlags, ffi};

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

/// Serializes the tests that enable the cache: the cache and the watcher are
/// process-wide, so another such test could change the generation under them.
#[cfg(test)]
pub(crate) static TEST_SERIAL: Mutex<()> = Mutex::new(());

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

/// Change stamp of one file, taken with `stat` alone: identity and inode
/// change time (where the platform exposes them), size and modification time.
///
/// The file is never opened here. On Unix, closing any descriptor of a file
/// releases every POSIX advisory lock this process holds on it, including the
/// locks SQLite connections on other threads rely on, so reading the store
/// files outside SQLite could let a writer or checkpointer change pages under
/// an open read transaction. The inode change time cannot be set back by
/// `touch` or `cp -p`, so an in-place rewrite that restores the modification
/// time still changes the stamp.
#[derive(Clone, Debug, PartialEq, Eq)]
struct FileStamp {
    identity: (u64, u64),
    changed: (i64, i64),
    size: u64,
    modified: std::time::Duration,
}

impl FileStamp {
    fn of(path: &Path) -> Option<Self> {
        let metadata = std::fs::metadata(path).ok()?;
        #[cfg(unix)]
        let (identity, changed) = {
            use std::os::unix::fs::MetadataExt as _;
            (
                (metadata.dev(), metadata.ino()),
                (metadata.ctime(), metadata.ctime_nsec()),
            )
        };
        #[cfg(not(unix))]
        let (identity, changed) = ((0, 0), (0, 0));
        let modified = metadata
            .modified()
            .ok()?
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?;
        Some(Self {
            identity,
            changed,
            size: metadata.len(),
            modified,
        })
    }
}

/// Observable state of a store; see the module documentation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct StoreFileToken {
    database: FileStamp,
    wal: Option<FileStamp>,
    /// Changes whenever the watcher connection observes a commit by any
    /// connection, in this process or another one.
    generation: u64,
}

impl StoreFileToken {
    /// Observes the store at `path` that `connection` reads.
    ///
    /// Returns `None` when the state cannot be tied to the file `connection`
    /// reads: the path was renamed or replaced under it, the file changed while
    /// being observed, or SQLite could not report its commit counter.
    fn observe(path: &Path, connection: &Connection) -> Option<Self> {
        let database = FileStamp::of(path)?;
        let wal = sidecar(path, "-wal").and_then(|path| FileStamp::of(&path));
        let generation = commit_generation(path)?;
        // The reading connection still has the file the path names, and the
        // path named the same file across the whole observation, so the
        // watcher, the stamps and `connection` all describe one file.
        if has_moved(connection)? || FileStamp::of(path).as_ref() != Some(&database) {
            return None;
        }
        Some(Self {
            database,
            wal,
            generation,
        })
    }
}

fn sidecar(path: &Path, suffix: &str) -> Option<PathBuf> {
    let mut name = path.file_name()?.to_os_string();
    name.push(suffix);
    Some(path.with_file_name(name))
}

/// A read-only connection kept open on one store to read `PRAGMA
/// data_version`, which changes between two reads on the same connection
/// whenever any other connection committed in between. SQLite tracks this
/// itself from the WAL-index or the database header, under its own locks.
struct Watcher {
    path: PathBuf,
    connection: Connection,
    data_version: i64,
    generation: u64,
}

struct WatchState {
    watcher: Option<Watcher>,
    last_generation: u64,
}

static WATCH: Mutex<WatchState> = Mutex::new(WatchState {
    watcher: None,
    last_generation: 0,
});

/// The commit generation of the store at `path`: unchanged between two calls
/// only if no connection committed to that store in between.
fn commit_generation(path: &Path) -> Option<u64> {
    let mut state = WATCH
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let state = &mut *state;
    let reusable = state.watcher.as_ref().is_some_and(|watcher| {
        watcher.path == path && has_moved(&watcher.connection) == Some(false)
    });
    if !reusable {
        // Closing a SQLite connection goes through SQLite's VFS, which keeps
        // the locks other connections in this process hold on the file.
        state.watcher = None;
        let connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .ok()?;
        // Never wait for a writer while holding the process-wide lock: a busy
        // store just bypasses the cache for this read.
        connection.busy_timeout(std::time::Duration::ZERO).ok()?;
        let data_version = data_version(&connection)?;
        if has_moved(&connection)? {
            return None;
        }
        state.last_generation += 1;
        state.watcher = Some(Watcher {
            path: path.to_owned(),
            connection,
            data_version,
            generation: state.last_generation,
        });
    }
    let watcher = state.watcher.as_mut()?;
    let Some(observed) = data_version(&watcher.connection) else {
        state.watcher = None;
        return None;
    };
    if observed != watcher.data_version {
        state.last_generation += 1;
        watcher.data_version = observed;
        watcher.generation = state.last_generation;
    }
    Some(watcher.generation)
}

fn data_version(connection: &Connection) -> Option<i64> {
    connection
        .query_row("PRAGMA data_version", [], |row| row.get(0))
        .ok()
}

/// Whether the file `connection` has open is no longer the one its path names
/// (`SQLITE_FCNTL_HAS_MOVED`), or `None` when SQLite cannot tell.
fn has_moved(connection: &Connection) -> Option<bool> {
    let mut moved: std::ffi::c_int = 0;
    // SAFETY: the handle stays valid while `connection` is borrowed, and the
    // connection is only used from this thread for the call. The database name
    // is NUL-terminated, and SQLITE_FCNTL_HAS_MOVED writes one int to the
    // pointer it is given.
    let status = unsafe {
        ffi::sqlite3_file_control(
            connection.handle(),
            c"main".as_ptr(),
            ffi::SQLITE_FCNTL_HAS_MOVED,
            (&raw mut moved).cast(),
        )
    };
    (status == ffi::SQLITE_OK).then_some(moved != 0)
}

/// The store path of a connection that may use the cache, or `None` when the
/// cache is disabled, the store is in memory, or the connection can write.
fn cacheable_path(connection: &Connection) -> Option<PathBuf> {
    // Tying a token to the file a connection reads needs the file identity and
    // `SQLITE_FCNTL_HAS_MOVED`, which only the Unix VFS provides.
    if !cfg!(unix) || !enabled() {
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
        let token = StoreFileToken::observe(&path, connection)?;
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
        || StoreFileToken::observe(&path, connection).as_ref() != Some(&token)
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
    let token = StoreFileToken::observe(&path, connection)?;
    Some(ReadState {
        path,
        token,
        pinned: false,
    })
}

impl ReadState {
    /// Whether work done on `connection` since this state was taken saw
    /// exactly that state.
    fn still_current(&self, connection: &Connection) -> bool {
        self.pinned || StoreFileToken::observe(&self.path, connection).as_ref() == Some(&self.token)
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
    if state.still_current(connection) {
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

/// Returns the kept reconstruction of `snapshot_id` when it is still current
/// for `connection`, without reading or replacing anything otherwise.
pub(crate) fn peek_completed_snapshot(
    connection: &Connection,
    snapshot_id: &str,
) -> Option<Arc<GraphSnapshot>> {
    let state = read_state(connection)?;
    let cache = cache();
    let cached = cache.snapshot.as_ref()?;
    (cached.path == state.path && cached.snapshot_id == snapshot_id && cached.token == state.token)
        .then(|| {
            count(|counts| counts.snapshot_hits += 1);
            Arc::clone(&cached.snapshot)
        })
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
    if state.still_current(connection) {
        cache().snapshot = Some(CachedSnapshot {
            path: state.path,
            snapshot_id: snapshot_id.to_owned(),
            token: state.token,
            snapshot: Arc::clone(&snapshot),
        });
    }
    Ok(snapshot)
}
