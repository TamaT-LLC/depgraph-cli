//! Disposable, atomic checkpoints for independently validated analysis units.
//!
//! These files are acceleration data, never a published Store snapshot or an
//! operation lease. Every read must pass the worker protocol validator again.

use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

const CONTRACT: &str = "depgraph-analysis-checkpoint-v1";
const MAX_ENTRIES: usize = 4_096;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct UnitCheckpointKey {
    pub unit_id: String,
    /// The static input witness the schedule derived from the discovery plan;
    /// for a source-batch unit it equals the request's `context_fingerprint`.
    pub input_digest: String,
    pub execution_digest: String,
    pub root_digest: String,
    /// The worker-reported reference closure a package-bounded semantic unit
    /// was type-checked against, folded in at dispatch.  Absent for every
    /// other unit, whose key digest therefore stays what it was before the
    /// field existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference_digest: Option<String>,
}

impl UnitCheckpointKey {
    fn digest(&self) -> Result<String> {
        Ok(format!("{:x}", Sha256::digest(serde_json::to_vec(self)?)))
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Checkpoint {
    contract: String,
    key: UnitCheckpointKey,
    payload_digest: String,
    events: Vec<Value>,
}

#[derive(Serialize)]
struct CheckpointRef<'a> {
    contract: &'static str,
    key: &'a UnitCheckpointKey,
    payload_digest: String,
    events: &'a [Value],
}

pub(crate) struct UnitCheckpointStore {
    directory: PathBuf,
    max_bytes: usize,
}

/// A serialized stream that is invisible to checkpoint readers until its
/// Store ingestion succeeds. Dropping it removes the private temporary file.
pub(crate) struct StagedUnitCheckpoint {
    file: tempfile::NamedTempFile,
    target: PathBuf,
}

impl UnitCheckpointStore {
    pub fn open(store_path: &Path, max_bytes: usize) -> Result<Self> {
        let parent = store_path
            .parent()
            .context("Store has no parent directory")?;
        let parent = parent
            .canonicalize()
            .context("Store directory is unavailable")?;
        let name = store_path.file_name().context("Store has no file name")?;
        let identity = format!("{:x}", Sha256::digest(name.as_encoded_bytes()));
        let base = parent.join(".depgraph");
        ensure_directory(&base)?;
        let base = base.join("analysis-checkpoints-v1");
        ensure_directory(&base)?;
        let directory = base.join(identity);
        ensure_directory(&directory)?;
        Ok(Self {
            directory,
            max_bytes,
        })
    }

    /// A missing, truncated, mismatched, or modified checkpoint is a cache miss.
    /// Callers additionally validate semantic/protocol contracts before reuse.
    pub fn read(&self, key: &UnitCheckpointKey) -> Result<Option<Vec<Value>>> {
        let path = self.directory.join(format!("{}.json", key.digest()?));
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.len() > self.max_bytes as u64
        {
            return Ok(None);
        }
        let file = open_checkpoint(&path)?;
        let mut bytes = Vec::new();
        file.take(self.max_bytes as u64 + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() > self.max_bytes {
            return Ok(None);
        }
        let Ok(checkpoint) = serde_json::from_slice::<Checkpoint>(&bytes) else {
            return Ok(None);
        };
        if checkpoint.contract != CONTRACT
            || checkpoint.key != *key
            || checkpoint.payload_digest != payload_digest(&checkpoint.events)?
            || !complete_stream(&checkpoint.events)
        {
            return Ok(None);
        }
        Ok(Some(checkpoint.events))
    }

    /// Stage a supervisor-validated stream without making it reusable yet.
    pub fn stage(
        &self,
        key: &UnitCheckpointKey,
        events: &[Value],
    ) -> Result<Option<StagedUnitCheckpoint>> {
        if !complete_stream(events) {
            bail!("cannot checkpoint an incomplete analysis unit");
        }
        let checkpoint = CheckpointRef {
            contract: CONTRACT,
            key,
            payload_digest: payload_digest(events)?,
            events,
        };
        let bytes = serde_json::to_vec(&checkpoint)?;
        if bytes.len() > self.max_bytes {
            return Ok(None);
        }
        // Tempfiles stay on the same filesystem; persist replaces one complete
        // generation atomically. A concurrent reader sees either generation.
        let mut file = tempfile::NamedTempFile::new_in(&self.directory)?;
        file.write_all(&bytes)?;
        file.as_file().sync_all()?;
        let target = self.directory.join(format!("{}.json", key.digest()?));
        Ok(Some(StagedUnitCheckpoint { file, target }))
    }

    /// Publish only after Store has accepted the complete unit atomically.
    pub fn commit(&self, staged: StagedUnitCheckpoint) -> Result<()> {
        staged
            .file
            .persist(staged.target)
            .map_err(|error| error.error)?;
        self.prune()?;
        Ok(())
    }

    #[cfg(test)]
    fn write(&self, key: &UnitCheckpointKey, events: &[Value]) -> Result<bool> {
        let Some(staged) = self.stage(key, events)? else {
            return Ok(false);
        };
        self.commit(staged)?;
        Ok(true)
    }

    fn prune(&self) -> Result<()> {
        let mut entries = Vec::new();
        let mut total = 0_u64;
        for entry in fs::read_dir(&self.directory)? {
            let entry = entry?;
            if entry.path().extension().and_then(|ext| ext.to_str()) != Some("json") {
                continue;
            }
            let metadata = fs::symlink_metadata(entry.path())?;
            if !metadata.is_file() || metadata.file_type().is_symlink() {
                continue;
            }
            total = total.saturating_add(metadata.len());
            entries.push((metadata.modified()?, entry.path(), metadata.len()));
        }
        entries.sort();
        let mut count = entries.len();
        let max_total = (self.max_bytes as u64).saturating_mul(8);
        for (_, path, size) in entries {
            if count <= MAX_ENTRIES && total <= max_total {
                break;
            }
            match fs::remove_file(path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
            total = total.saturating_sub(size);
            count -= 1;
        }
        Ok(())
    }
}

/// The Go build cache one scan shares across its package-scoped units.
///
/// `go list -export` of a package-bounded unit compiles the export data of
/// every dependency it references; without a shared cache each unit of the
/// same module recompiles the same dependencies.  The cache is acceleration
/// data for one scan only: it is created beside the checkpoints of the Store
/// (or in the system temporary directory when the Store has no directory or
/// lies inside the scan root, which the Go worker rejects), it is private to
/// the process, and it is removed when the scan's execution ends.
pub(crate) struct ScanBuildCache {
    directory: tempfile::TempDir,
}

impl ScanBuildCache {
    /// Open a fresh cache directory outside `root`.  Returns `None` when no
    /// admissible directory exists; the worker then keeps its private cache.
    pub fn open(store_path: Option<&Path>, root: &Path) -> Option<Self> {
        let root = root.canonicalize().ok()?;
        let mut bases = Vec::new();
        if let Some(parent) = store_path
            .and_then(Path::parent)
            .and_then(|parent| parent.canonicalize().ok())
        {
            let base = parent.join(".depgraph");
            if ensure_directory(&base).is_ok() {
                bases.push(base.join("go-build-cache-v1"));
            }
        }
        bases.push(std::env::temp_dir());
        bases.into_iter().find_map(|base| {
            ensure_directory(&base).ok()?;
            let base = base.canonicalize().ok()?;
            // The worker refuses a cache inside the scan root and a path that
            // could be smuggled into a path-list variable.
            if base.starts_with(&root)
                || base
                    .to_str()
                    .is_none_or(|text| text.contains(PATH_LIST_SEPARATOR))
            {
                return None;
            }
            tempfile::Builder::new()
                .prefix("depgraph-go-build-cache-")
                .tempdir_in(&base)
                .ok()
                .map(|directory| Self { directory })
        })
    }

    pub fn path(&self) -> &Path {
        self.directory.path()
    }
}

#[cfg(windows)]
const PATH_LIST_SEPARATOR: char = ';';
#[cfg(not(windows))]
const PATH_LIST_SEPARATOR: char = ':';

fn ensure_directory(path: &Path) -> Result<()> {
    match fs::create_dir(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("analysis checkpoint directory must be a real directory");
    }
    Ok(())
}

fn open_checkpoint(path: &Path) -> Result<fs::File> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    Ok(options.open(path)?)
}

fn payload_digest(events: &[Value]) -> Result<String> {
    Ok(format!("{:x}", Sha256::digest(serde_json::to_vec(events)?)))
}

fn complete_stream(events: &[Value]) -> bool {
    events.first().and_then(|event| event["event"].as_str()) == Some("scan_started")
        && events.last().and_then(|event| event["event"].as_str()) == Some("scan_completed")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn key() -> UnitCheckpointKey {
        UnitCheckpointKey {
            unit_id: "go:service".into(),
            input_digest: "input".into(),
            execution_digest: "toolchain".into(),
            root_digest: "root".into(),
            reference_digest: None,
        }
    }

    fn events() -> Vec<Value> {
        vec![
            json!({"event":"scan_started"}),
            json!({"event":"scan_completed"}),
        ]
    }

    #[test]
    fn reference_digest_extends_the_key_without_moving_existing_checkpoints() -> Result<()> {
        // Keys of units that bind no reference closure keep the digest they
        // had before the field existed, so their checkpoint files stay valid.
        let legacy = json!({"unit_id":"go:service","input_digest":"input",
            "execution_digest":"toolchain","root_digest":"root"});
        assert_eq!(
            key().digest()?,
            format!("{:x}", Sha256::digest(serde_json::to_vec(&legacy)?))
        );
        assert_eq!(serde_json::from_value::<UnitCheckpointKey>(legacy)?, key());
        let bound = UnitCheckpointKey {
            reference_digest: Some("closure-a".into()),
            ..key()
        };
        assert_ne!(bound.digest()?, key().digest()?);
        let temp = tempfile::tempdir()?;
        let store = UnitCheckpointStore::open(&temp.path().join("store"), 4096)?;
        assert!(store.write(&bound, &events())?);
        assert_eq!(store.read(&bound)?, Some(events()));
        assert_eq!(store.read(&key())?, None);
        assert_eq!(
            store.read(&UnitCheckpointKey {
                reference_digest: Some("closure-b".into()),
                ..key()
            })?,
            None
        );
        Ok(())
    }

    #[test]
    fn staged_output_is_not_reusable_until_accepted_and_committed() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let store = UnitCheckpointStore::open(&temp.path().join("store"), 4096)?;
        let staged = store.stage(&key(), &events())?.unwrap();
        assert_eq!(store.read(&key())?, None);
        drop(staged);
        assert_eq!(store.read(&key())?, None);
        assert_eq!(fs::read_dir(&store.directory)?.count(), 0);
        store.commit(store.stage(&key(), &events())?.unwrap())?;
        assert_eq!(store.read(&key())?, Some(events()));
        Ok(())
    }

    #[test]
    fn survives_reopen_and_rejects_changed_inputs_and_tampering() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let path = temp.path().join("scan.sqlite");
        let store = UnitCheckpointStore::open(&path, 4096)?;
        assert!(store.write(&key(), &events())?);
        let store = UnitCheckpointStore::open(&path, 4096)?;
        assert_eq!(store.read(&key())?, Some(events()));
        let mut changed = key();
        changed.input_digest = "changed dependency".into();
        assert_eq!(store.read(&changed)?, None);
        let file = store.directory.join(format!("{}.json", key().digest()?));
        let mut stored: Value = serde_json::from_slice(&fs::read(&file)?)?;
        stored["events"][0]["injected"] = json!(true);
        fs::write(file, serde_json::to_vec(&stored)?)?;
        assert_eq!(store.read(&key())?, None);
        Ok(())
    }

    #[test]
    fn incomplete_and_oversized_results_are_never_committed() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let store = UnitCheckpointStore::open(&temp.path().join("store"), 32)?;
        assert!(store.write(&key(), &events()[..1]).is_err());
        assert!(!store.write(&key(), &events())?);
        assert_eq!(store.read(&key())?, None);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn refuses_symlink_checkpoint_directory() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let outside = tempfile::tempdir()?;
        std::os::unix::fs::symlink(outside.path(), temp.path().join(".depgraph"))?;
        assert!(UnitCheckpointStore::open(&temp.path().join("store"), 4096).is_err());
        Ok(())
    }

    /// The shared build cache lives beside the checkpoints of a Store outside
    /// the scan root, moves to the system temporary directory when the Store
    /// is inside the root (the worker would reject it), and disappears with
    /// the scan's execution.
    #[test]
    fn scan_build_cache_stays_outside_the_root_and_is_removed_on_drop() -> Result<()> {
        let store_dir = tempfile::tempdir()?;
        let root = tempfile::tempdir()?;
        let store_path = store_dir.path().join("scan.sqlite");
        let cache = ScanBuildCache::open(Some(&store_path), root.path()).expect("cache");
        let path = cache.path().to_path_buf();
        assert!(path.starts_with(store_dir.path().canonicalize()?.join(".depgraph")));
        assert!(!path.starts_with(root.path().canonicalize()?));
        assert!(path.is_dir());
        drop(cache);
        assert!(!path.exists());

        let inside = ScanBuildCache::open(Some(&root.path().join("scan.sqlite")), root.path())
            .expect("fallback cache");
        assert!(!inside.path().starts_with(root.path().canonicalize()?));
        assert!(
            inside
                .path()
                .starts_with(std::env::temp_dir().canonicalize()?)
        );
        assert!(ScanBuildCache::open(None, root.path()).is_some());
        Ok(())
    }
}
