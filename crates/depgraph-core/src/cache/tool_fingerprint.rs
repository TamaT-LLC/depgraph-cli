//! Scan-scoped memo of worker artifact digests and toolchain identities.
//!
//! Every analysis work item derives its checkpoint execution digest from the
//! worker artifact and toolchain identities. Hashing a multi-megabyte runtime
//! and probing its version once per unit dominated checkpoint validation, so
//! one scan memoizes them behind a file stamp: an entry is reused only while
//! the canonical artifact keeps the device, inode, size, modification time,
//! and status change time it had when it was fully read. A stamp is trusted
//! only once the file has been quiet for [`RACY_STAMP_WINDOW`], so a change
//! within one timestamp tick of the observation still forces a full read.
//!
//! The memo belongs to one scan; a later scan in the same process starts
//! from an empty memo and recomputes every identity.

use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    sync::{
        Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use sha2::{Digest, Sha256};

/// How long a file's last change must lie in the past before its stamp
/// stands in for its content (covers 2 s FAT timestamps).
const RACY_STAMP_WINDOW: Duration = Duration::from_secs(2);

/// Whether a toolchain identity may come from the memo or must re-run the
/// version probe.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum ToolOutputCheck {
    /// Reuse a probe output recorded for an unchanged tool artifact.
    Memoized,
    /// Re-run the version probe. A tool can select another toolchain without
    /// changing its own artifact (for example `GOTOOLCHAIN=auto`), so a
    /// checkpoint write compares the fresh probe output as before.
    Rerun,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(super) struct FileStamp {
    device: u64,
    inode: u64,
    length: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}

/// A full read of one canonical artifact. `stamp` is `None` when the stamp
/// cannot stand in for the content; callers then re-read the file.
#[derive(Debug, Clone, Copy)]
pub(super) struct ArtifactObservation {
    pub(super) digest: [u8; 32],
    pub(super) stamp: Option<FileStamp>,
}

#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub(super) struct ToolKey {
    pub(super) artifact: PathBuf,
    pub(super) program: PathBuf,
    pub(super) name: String,
    pub(super) arguments: Vec<String>,
}

#[derive(Debug, Clone)]
pub(super) struct ToolProbe {
    pub(super) stamp: FileStamp,
    pub(super) identity: String,
    pub(super) stdout: Vec<u8>,
}

/// Worker artifact and toolchain identities observed during one scan.
#[derive(Debug)]
pub(crate) struct ToolFingerprintMemo {
    enabled: bool,
    racy_window: Duration,
    artifacts: Mutex<HashMap<PathBuf, (FileStamp, [u8; 32])>>,
    tools: Mutex<HashMap<ToolKey, ToolProbe>>,
    full_reads: AtomicU64,
    tool_runs: AtomicU64,
}

impl Default for ToolFingerprintMemo {
    fn default() -> Self {
        Self::with_racy_window(true, RACY_STAMP_WINDOW)
    }
}

impl ToolFingerprintMemo {
    /// A memo that never records an observation: every call reads every
    /// artifact and runs every probe, exactly as without a memo.
    pub(crate) fn disabled() -> Self {
        Self::with_racy_window(false, RACY_STAMP_WINDOW)
    }

    fn with_racy_window(enabled: bool, racy_window: Duration) -> Self {
        Self {
            enabled,
            racy_window,
            artifacts: Mutex::new(HashMap::new()),
            tools: Mutex::new(HashMap::new()),
            full_reads: AtomicU64::new(0),
            tool_runs: AtomicU64::new(0),
        }
    }

    #[cfg(test)]
    pub(crate) fn without_racy_window() -> Self {
        Self::with_racy_window(true, Duration::ZERO)
    }

    #[cfg(test)]
    pub(crate) fn full_reads(&self) -> u64 {
        self.full_reads.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    pub(crate) fn tool_runs(&self) -> u64 {
        self.tool_runs.load(Ordering::Relaxed)
    }

    /// The stamp of `path` when it may stand in for the file content.
    pub(super) fn trusted_stamp(&self, path: &Path) -> Option<FileStamp> {
        if !self.enabled {
            return None;
        }
        file_stamp(path, self.racy_window)
    }

    /// The SHA-256 digest of a canonical artifact, from the memo while its
    /// stamp is unchanged and from a full read otherwise.
    pub(super) fn artifact_digest(&self, artifact: &Path) -> Result<ArtifactObservation, ()> {
        let before = self.trusted_stamp(artifact);
        if let Some(stamp) = before
            && let Some(digest) = self.artifacts.lock().ok().and_then(|artifacts| {
                artifacts
                    .get(artifact)
                    .filter(|(cached, _)| *cached == stamp)
                    .map(|(_, digest)| *digest)
            })
        {
            return Ok(ArtifactObservation {
                digest,
                stamp: Some(stamp),
            });
        }
        let bytes = fs::read(artifact).map_err(|_| ())?;
        self.full_reads.fetch_add(1, Ordering::Relaxed);
        let digest: [u8; 32] = Sha256::digest(&bytes).into();
        // A stamp observed on both sides of the read binds it to the content.
        let stamp = before.filter(|stamp| self.trusted_stamp(artifact) == Some(*stamp));
        if let Some(stamp) = stamp
            && let Ok(mut artifacts) = self.artifacts.lock()
        {
            artifacts.insert(artifact.to_owned(), (stamp, digest));
        }
        Ok(ArtifactObservation { digest, stamp })
    }

    /// Whether `artifact` still holds the content `observation` read.
    pub(super) fn artifact_unchanged(
        &self,
        artifact: &Path,
        observation: &ArtifactObservation,
    ) -> bool {
        match observation.stamp {
            Some(stamp) => self.trusted_stamp(artifact) == Some(stamp),
            None => {
                self.full_reads.fetch_add(1, Ordering::Relaxed);
                fs::read(artifact).is_ok_and(|bytes| {
                    <[u8; 32]>::from(Sha256::digest(&bytes)) == observation.digest
                })
            }
        }
    }

    pub(super) fn tool_probe(&self, key: &ToolKey) -> Option<(String, Vec<u8>)> {
        let stamp = self.trusted_stamp(&key.artifact)?;
        let tools = self.tools.lock().ok()?;
        tools
            .get(key)
            .filter(|probe| probe.stamp == stamp)
            .map(|probe| (probe.identity.clone(), probe.stdout.clone()))
    }

    pub(super) fn record_tool_run(&self) {
        self.tool_runs.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn remember_tool_probe(&self, key: ToolKey, probe: ToolProbe) {
        if let Ok(mut tools) = self.tools.lock() {
            tools.insert(key, probe);
        }
    }
}

#[cfg(unix)]
fn file_stamp(path: &Path, racy_window: Duration) -> Option<FileStamp> {
    use std::os::unix::fs::MetadataExt;

    let metadata = fs::metadata(path).ok()?;
    if !metadata.is_file() {
        return None;
    }
    let stamp = FileStamp {
        device: metadata.dev(),
        inode: metadata.ino(),
        length: metadata.len(),
        modified: (metadata.mtime(), metadata.mtime_nsec()),
        changed: (metadata.ctime(), metadata.ctime_nsec()),
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?;
    let latest = stamp.modified.max(stamp.changed);
    let latest = Duration::from_secs(u64::try_from(latest.0).ok()?)
        + Duration::from_nanos(u64::try_from(latest.1).ok()?);
    // A change in the same timestamp tick as this observation, or a clock
    // that runs behind the file system, would leave the stamp unchanged.
    (latest + racy_window < now).then_some(stamp)
}

#[cfg(not(unix))]
fn file_stamp(_path: &Path, _racy_window: Duration) -> Option<FileStamp> {
    None
}
