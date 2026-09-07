//! Disposable, atomic checkpoints of completed health execution ranges.
//!
//! A checkpoint stores the findings of one range so an interrupted health
//! request can resume from the ranges that already finished. Checkpoints are
//! acceleration data only: they are bound to the range plan digest, the
//! global-context digest, the analyzer and finding-contract versions, and a
//! payload digest, and any mismatch is a cache miss, never an error. Health
//! results are never published from a checkpoint alone; every range that is
//! missing is recomputed from the Store.

use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{HEALTH_ANALYZER_VERSION, HEALTH_FINDING_CONTRACT_VERSION, HealthFinding};

pub const HEALTH_RANGE_CHECKPOINT_CONTRACT_VERSION: &str = "depgraph-health-range-checkpoint-v1";
/// Upper bound of one checkpoint file. Findings are bounded per range by the
/// analyzer's finding cap, so a larger file is a sign of corruption.
pub const MAX_HEALTH_RANGE_CHECKPOINT_BYTES: usize = 64 * 1024 * 1024;
const MAX_ENTRIES: usize = 4_096;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HealthRangeCheckpointKey {
    pub plan_digest: String,
    pub first_subject_id: String,
    pub last_subject_id: String,
    pub global_context_digest: String,
    pub analyzer_version: String,
    pub finding_contract_version: String,
}

impl HealthRangeCheckpointKey {
    #[must_use]
    pub fn new(
        plan_digest: &str,
        first_subject_id: &str,
        last_subject_id: &str,
        global_context_digest: &str,
    ) -> Self {
        Self {
            plan_digest: plan_digest.to_owned(),
            first_subject_id: first_subject_id.to_owned(),
            last_subject_id: last_subject_id.to_owned(),
            global_context_digest: global_context_digest.to_owned(),
            analyzer_version: HEALTH_ANALYZER_VERSION.to_owned(),
            finding_contract_version: HEALTH_FINDING_CONTRACT_VERSION.to_owned(),
        }
    }

    fn digest(&self) -> Result<String> {
        Ok(format!("{:x}", Sha256::digest(serde_json::to_vec(self)?)))
    }
}

/// The result of one completed range.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HealthRangeCheckpointPayload {
    pub findings: Vec<HealthFinding>,
    pub subjects_analyzed: u64,
    pub work_used: u64,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Checkpoint {
    contract: String,
    key: HealthRangeCheckpointKey,
    payload_digest: String,
    payload: HealthRangeCheckpointPayload,
}

#[derive(Serialize)]
struct CheckpointRef<'a> {
    contract: &'static str,
    key: &'a HealthRangeCheckpointKey,
    payload_digest: String,
    payload: &'a HealthRangeCheckpointPayload,
}

/// Sidecar directory `<store parent>/.depgraph/health-range-checkpoints-v1/<store name digest>/`.
#[derive(Clone, Debug)]
pub struct HealthRangeCheckpointStore {
    directory: PathBuf,
    max_bytes: usize,
}

impl HealthRangeCheckpointStore {
    /// Open (creating if needed) the checkpoint directory next to `store_path`.
    ///
    /// Fails when the directory cannot be created or is not a real directory;
    /// callers treat that as "run without checkpoints".
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
        let base = base.join("health-range-checkpoints-v1");
        ensure_directory(&base)?;
        let directory = base.join(identity);
        ensure_directory(&directory)?;
        Ok(Self {
            directory,
            max_bytes,
        })
    }

    #[must_use]
    pub fn directory(&self) -> &Path {
        &self.directory
    }

    /// A missing, truncated, mismatched, or modified checkpoint is a miss.
    pub fn read(
        &self,
        key: &HealthRangeCheckpointKey,
    ) -> Result<Option<HealthRangeCheckpointPayload>> {
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
        if checkpoint.contract != HEALTH_RANGE_CHECKPOINT_CONTRACT_VERSION
            || checkpoint.key != *key
            || checkpoint.payload_digest != payload_digest(&checkpoint.payload)?
        {
            return Ok(None);
        }
        Ok(Some(checkpoint.payload))
    }

    /// Persist one completed range atomically. Returns `false` when the
    /// payload exceeds the size bound and was therefore not written.
    pub fn write(
        &self,
        key: &HealthRangeCheckpointKey,
        payload: &HealthRangeCheckpointPayload,
    ) -> Result<bool> {
        let checkpoint = CheckpointRef {
            contract: HEALTH_RANGE_CHECKPOINT_CONTRACT_VERSION,
            key,
            payload_digest: payload_digest(payload)?,
            payload,
        };
        let bytes = serde_json::to_vec(&checkpoint)?;
        if bytes.len() > self.max_bytes {
            return Ok(false);
        }
        // Tempfiles stay on the same filesystem; persist replaces one complete
        // generation atomically, so a concurrent reader sees either generation.
        let mut file = tempfile::NamedTempFile::new_in(&self.directory)?;
        file.write_all(&bytes)?;
        file.as_file().sync_all()?;
        let target = self.directory.join(format!("{}.json", key.digest()?));
        file.persist(target).map_err(|error| error.error)?;
        self.prune()?;
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

fn ensure_directory(path: &Path) -> Result<()> {
    match fs::create_dir(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("health range checkpoint directory must be a real directory");
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

fn payload_digest(payload: &HealthRangeCheckpointPayload) -> Result<String> {
    Ok(format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(payload)?)
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(range: &str) -> HealthRangeCheckpointKey {
        HealthRangeCheckpointKey::new("sha256:plan", range, range, "sha256:global")
    }

    fn payload() -> HealthRangeCheckpointPayload {
        HealthRangeCheckpointPayload {
            findings: Vec::new(),
            subjects_analyzed: 3,
            work_used: 42,
        }
    }

    #[test]
    fn checkpoint_round_trips_and_rejects_foreign_keys_and_tampering() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let store_path = dir.path().join("depgraph.sqlite");
        fs::write(&store_path, b"")?;
        let checkpoints =
            HealthRangeCheckpointStore::open(&store_path, MAX_HEALTH_RANGE_CHECKPOINT_BYTES)?;
        assert!(checkpoints.read(&key("a"))?.is_none());
        assert!(checkpoints.write(&key("a"), &payload())?);
        assert_eq!(checkpoints.read(&key("a"))?, Some(payload()));
        assert!(checkpoints.read(&key("b"))?.is_none());
        let mut other_plan = key("a");
        other_plan.plan_digest = "sha256:other".to_owned();
        assert!(checkpoints.read(&other_plan)?.is_none());

        let reopened =
            HealthRangeCheckpointStore::open(&store_path, MAX_HEALTH_RANGE_CHECKPOINT_BYTES)?;
        assert_eq!(reopened.read(&key("a"))?, Some(payload()));
        let path = reopened
            .directory()
            .join(format!("{}.json", key("a").digest()?));
        let mut text = fs::read_to_string(&path)?;
        text = text.replace("\"work_used\":42", "\"work_used\":43");
        fs::write(&path, text)?;
        assert!(reopened.read(&key("a"))?.is_none());
        Ok(())
    }

    #[test]
    fn oversized_payload_is_not_written_and_symlink_directory_is_rejected() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let store_path = dir.path().join("depgraph.sqlite");
        fs::write(&store_path, b"")?;
        let checkpoints = HealthRangeCheckpointStore::open(&store_path, 64)?;
        assert!(!checkpoints.write(&key("a"), &payload())?);
        assert!(checkpoints.read(&key("a"))?.is_none());

        #[cfg(unix)]
        {
            let other = tempfile::tempdir()?;
            let other_store = other.path().join("depgraph.sqlite");
            fs::write(&other_store, b"")?;
            std::os::unix::fs::symlink(dir.path(), other.path().join(".depgraph"))?;
            assert!(HealthRangeCheckpointStore::open(&other_store, 64).is_err());
        }
        Ok(())
    }
}
