//! Process-wide memoization of toolchain attestation work.
//!
//! Hashing the toolchain executables dominates a toolchain probe: `cargo`
//! alone is tens of MB, and one scan used to stream the same files through
//! SHA-256 more than a dozen times. Both caches here are keyed by the on-disk
//! identity of every file the result depends on, so a replaced or modified
//! toolchain changes the key and forces recomputation even when the worker
//! scans many roots in one process.
//!
//! Without a usable identity (non-Unix platforms, unreadable metadata) nothing
//! is cached and callers fall back to the uncached computation.

use super::{RustToolchainSelection, safe_rustup_home};
use crate::metadata::resolve_safe_tool;
use std::{
    collections::HashMap,
    ffi::OsString,
    fs,
    hash::Hash,
    path::{Path, PathBuf},
    sync::{Mutex, OnceLock},
    time::SystemTime,
};

/// Bounds both caches; real scans touch a handful of tools, so reaching it
/// means many short-lived files (tests) and dropping everything is harmless.
const CACHE_CAPACITY: usize = 64;

/// The identity of one file as seen through an open handle (or a path for
/// directories). Any write, rename-over, `chmod` or `touch` changes `ctime`,
/// which user space cannot set back, so equal fingerprints mean the bytes a
/// digest was computed from are still the ones on disk.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(super) struct FileFingerprint {
    path: PathBuf,
    dev: u64,
    ino: u64,
    size: u64,
    mtime: (i64, i64),
    ctime: (i64, i64),
}

impl FileFingerprint {
    /// Fingerprints the file behind `metadata`, recorded under the canonical
    /// form of `path` so symlinked aliases (rustup proxies) share an entry.
    #[cfg(unix)]
    pub(super) fn from_metadata(path: &Path, metadata: &fs::Metadata) -> Option<Self> {
        use std::os::unix::fs::MetadataExt as _;

        Some(Self {
            path: path.canonicalize().ok()?,
            dev: metadata.dev(),
            ino: metadata.ino(),
            size: metadata.size(),
            mtime: (metadata.mtime(), metadata.mtime_nsec()),
            ctime: (metadata.ctime(), metadata.ctime_nsec()),
        })
    }

    #[cfg(not(unix))]
    pub(super) fn from_metadata(_path: &Path, _metadata: &fs::Metadata) -> Option<Self> {
        None
    }

    fn of_path(path: &Path) -> Option<Self> {
        Self::from_metadata(path, &fs::metadata(path).ok()?)
    }

    /// Whether the last change to the file happened clearly before `started`.
    ///
    /// A change in the same timestamp tick as a later rewrite would leave the
    /// fingerprint unchanged, so a digest is only cached once the file has
    /// been quiet for longer than the filesystem timestamp granularity
    /// (coarse kernel clocks lag by milliseconds; whole-second stamps mean a
    /// second- or two-second-granular filesystem).
    pub(super) fn settled_before(&self, started: SystemTime) -> bool {
        let (seconds, nanos) = self.ctime;
        let (Ok(seconds), Ok(nanos)) = (u64::try_from(seconds), u32::try_from(nanos)) else {
            return false;
        };
        let margin = if nanos == 0 {
            std::time::Duration::from_secs(2)
        } else {
            std::time::Duration::from_millis(100)
        };
        let changed = SystemTime::UNIX_EPOCH + std::time::Duration::new(seconds, nanos);
        changed
            .checked_add(margin)
            .is_some_and(|quiet| quiet <= started)
    }
}

struct BoundedCache<K, V>(Mutex<HashMap<K, V>>);

impl<K: Eq + Hash, V: Clone> BoundedCache<K, V> {
    fn new() -> Self {
        Self(Mutex::new(HashMap::new()))
    }

    fn get(&self, key: &K) -> Option<V> {
        self.0.lock().ok()?.get(key).cloned()
    }

    fn insert(&self, key: K, value: V) {
        if let Ok(mut entries) = self.0.lock() {
            if entries.len() >= CACHE_CAPACITY {
                entries.clear();
            }
            entries.insert(key, value);
        }
    }
}

fn digests() -> &'static BoundedCache<FileFingerprint, String> {
    static DIGESTS: OnceLock<BoundedCache<FileFingerprint, String>> = OnceLock::new();
    DIGESTS.get_or_init(BoundedCache::new)
}

pub(super) fn cached_digest(fingerprint: &FileFingerprint) -> Option<String> {
    digests().get(fingerprint)
}

pub(super) fn remember_digest(fingerprint: FileFingerprint, digest: String) {
    digests().insert(fingerprint, digest);
}

/// Everything outside the worker's own code that `probe_rust_toolchain` reads:
/// the scan root, the environment the probes inherit or derive from, the
/// files that sanitized-PATH resolution picks, and the Rustup state that
/// decides what a proxy or `rustup which` dispatches to.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(super) struct ProbeKey {
    root: PathBuf,
    environment: Vec<(&'static str, Option<OsString>)>,
    tools: Vec<(&'static str, Option<FileFingerprint>)>,
    rustup_state: Vec<(PathBuf, Option<FileFingerprint>)>,
}

impl ProbeKey {
    pub(super) fn capture(root: &Path) -> Option<Self> {
        if !cfg!(unix) {
            return None;
        }
        let environment = [
            "PATH",
            "RUSTUP_HOME",
            "HOME",
            "USERPROFILE",
            "LANG",
            "LC_ALL",
            "SystemRoot",
        ]
        .into_iter()
        .map(|key| (key, std::env::var_os(key)))
        .collect();
        let tools = ["rustc", "cargo", "rustup"]
            .into_iter()
            .map(|tool| {
                let fingerprint = resolve_safe_tool(tool, root)
                    .ok()
                    .and_then(|path| FileFingerprint::of_path(&path));
                (tool, fingerprint)
            })
            .collect();
        Some(Self {
            root: root.to_path_buf(),
            environment,
            tools,
            rustup_state: rustup_state(root),
        })
    }
}

/// Fingerprints the Rustup files that select a toolchain: the settings file
/// (default toolchain), the toolchains directory (installs, removals and
/// `rustup update` renames), and each toolchain's executables and library
/// directory, so an in-place toolchain update also invalidates the probe.
fn rustup_state(root: &Path) -> Vec<(PathBuf, Option<FileFingerprint>)> {
    let Some(rustup_home) = safe_rustup_home(root) else {
        return Vec::new();
    };
    let toolchains = rustup_home.join("toolchains");
    let mut paths = vec![rustup_home.join("settings.toml"), toolchains.clone()];
    let mut entries = fs::read_dir(&toolchains)
        .map(|entries| {
            entries
                .filter_map(|entry| entry.ok().map(|entry| entry.path()))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    entries.sort();
    for toolchain in entries {
        paths.push(toolchain.join("bin").join("rustc"));
        paths.push(toolchain.join("bin").join("cargo"));
        paths.push(toolchain.join("lib"));
        paths.push(toolchain);
    }
    paths
        .into_iter()
        .map(|path| {
            let fingerprint = FileFingerprint::of_path(&path);
            (path, fingerprint)
        })
        .collect()
}

fn probes() -> &'static BoundedCache<ProbeKey, RustToolchainSelection> {
    static PROBES: OnceLock<BoundedCache<ProbeKey, RustToolchainSelection>> = OnceLock::new();
    PROBES.get_or_init(BoundedCache::new)
}

pub(super) fn cached_probe(key: &ProbeKey) -> Option<RustToolchainSelection> {
    probes().get(key)
}

pub(super) fn remember_probe(key: ProbeKey, selection: RustToolchainSelection) {
    probes().insert(key, selection);
}
