use std::collections::BTreeMap;

use anyhow::{Context, Result, bail};
use chrono::{SecondsFormat, Utc};
use depgraph_protocol::stable_id_from_value;
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::{
    BuildAttemptRecord, BuildGraphDelta, CompletedScanSnapshot, CoverageRecord, DiagnosticRecord,
    SnapshotSource, Store, create_completed_snapshot, ensure_scan_staging,
    incremental::scan_is_semantic_noop_overlay, is_sha256_hex, load_diagnostics,
    promote_completed_snapshot, required_str, validate_build_union,
    validate_delta_attempt_metadata,
};

pub const CACHE_CONTRACT_VERSION: u32 = 2;
pub const COMPILER_PRECISE_CACHE_MAX_ENTRIES: usize = 32;
pub const COMPILER_PRECISE_CACHE_MAX_PAYLOAD_BYTES: usize = 64 * 1024 * 1024;
pub const COMPILER_PRECISE_CACHE_MAX_TOTAL_BYTES: usize = 512 * 1024 * 1024;
const COMPILER_PRECISE_CACHED_RUN_ID: &str = "compiler-precise-cache:canonical-run";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum CacheLayer {
    Syntax,
    Semantic,
    Build,
    #[serde(rename = "compiler-precise")]
    CompilerPrecise,
}

impl CacheLayer {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Syntax => "syntax",
            Self::Semantic => "semantic",
            Self::Build => "build",
            Self::CompilerPrecise => "compiler-precise",
        }
    }

    const fn table(self) -> &'static str {
        match self {
            Self::Syntax => "syntax_cache",
            Self::Semantic => "semantic_cache",
            Self::Build => "build_cache",
            Self::CompilerPrecise => "compiler_precise_cache",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CacheKey {
    pub layer: CacheLayer,
    pub contract_version: u32,
    pub key: String,
    pub dimensions: BTreeMap<String, String>,
}

impl CacheKey {
    pub fn new(layer: CacheLayer, dimensions: BTreeMap<String, String>) -> Self {
        let identity = json!({
            "schema": "depgraph-cache-key-v1",
            "contract_version": CACHE_CONTRACT_VERSION,
            "layer": layer.as_str(),
            "dimensions": dimensions,
        });
        Self {
            layer,
            contract_version: CACHE_CONTRACT_VERSION,
            key: stable_id_from_value("cache", &identity),
            dimensions,
        }
    }

    fn validate(&self) -> Result<()> {
        if self.contract_version != CACHE_CONTRACT_VERSION {
            bail!(
                "unsupported cache contract version {}; expected {}",
                self.contract_version,
                CACHE_CONTRACT_VERSION
            );
        }
        if self.dimensions.is_empty() {
            bail!("cache key must contain at least one dimension");
        }
        for (name, value) in &self.dimensions {
            if name.is_empty()
                || name.len() > 64
                || !name
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
            {
                bail!("cache dimension names must use bounded lowercase ASCII identifiers");
            }
            if value.trim().is_empty() || value.len() > 1_024 || value.chars().any(char::is_control)
            {
                bail!("cache dimension values must be bounded printable values");
            }
        }
        let expected = Self::new(self.layer, self.dimensions.clone());
        if self.key != expected.key {
            bail!("cache key does not match its canonical dimensions");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CacheLookupResult {
    pub layer: CacheLayer,
    pub cache_key: String,
    pub outcome: String,
    pub reason: String,
    pub snapshot_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CacheEventRecord {
    pub layer: CacheLayer,
    pub cache_key: Option<String>,
    pub outcome: String,
    pub reason: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct CacheEntryCounts {
    pub syntax: u64,
    pub semantic: u64,
    pub build: u64,
    pub compiler_precise: u64,
}

#[derive(Debug, Clone)]
pub struct ValidatedScanCacheHit {
    snapshot_id: String,
    data_version: i64,
    coverage: CoverageRecord,
    diagnostics: Vec<DiagnosticRecord>,
}

#[derive(Debug, Clone)]
pub struct BuildCacheLookup {
    pub result: CacheLookupResult,
    pub audit: Option<Value>,
    validated: Option<ValidatedBuildCacheHit>,
}

#[derive(Debug, Clone)]
pub struct CompilerPreciseCacheLookup {
    pub result: CacheLookupResult,
    pub payload: Option<Value>,
    pub audit: Option<Value>,
    validated: Option<ValidatedCompilerPreciseCacheHit>,
}

#[derive(Debug, Clone)]
struct ValidatedCompilerPreciseCacheHit {
    key: CacheKey,
    entry: StoredCompilerPreciseCacheEntry,
    payload: Value,
    audit: Value,
    data_version: i64,
}

#[derive(Debug, Clone)]
struct ValidatedBuildCacheHit {
    key: CacheKey,
    entry: StoredCacheEntry,
    attempt_id: String,
    data_version: i64,
}

impl ValidatedScanCacheHit {
    pub fn snapshot_id(&self) -> &str {
        &self.snapshot_id
    }

    pub fn coverage(&self) -> &CoverageRecord {
        &self.coverage
    }

    pub fn diagnostics(&self) -> &[DiagnosticRecord] {
        &self.diagnostics
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StoredCacheEntry {
    contract_version: u32,
    dimensions_json: String,
    snapshot_id: String,
    payload_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StoredCompilerPreciseCacheEntry {
    contract_version: u32,
    dimensions_json: String,
    source_snapshot_id: String,
    source_attempt_id: String,
    base_snapshot_id: String,
    payload_json: String,
    payload_digest: String,
}

impl Store {
    pub fn database_path(&self) -> Option<std::path::PathBuf> {
        self.connection.path().map(std::path::PathBuf::from)
    }

    pub fn cache_entry_counts(&self) -> Result<CacheEntryCounts> {
        Ok(CacheEntryCounts {
            syntax: table_count(&self.connection, CacheLayer::Syntax)?,
            semantic: table_count(&self.connection, CacheLayer::Semantic)?,
            build: table_count(&self.connection, CacheLayer::Build)?,
            compiler_precise: table_count(&self.connection, CacheLayer::CompilerPrecise)?,
        })
    }

    pub fn build_cache_base_snapshot_id(&self, base_scan_id: &str) -> Result<Option<String>> {
        let Some(current_id) = self.current_snapshot_id()? else {
            return Ok(None);
        };
        let current = self
            .completed_snapshot(&current_id)?
            .context("current completed snapshot disappeared")?;
        if current.scan_id != base_scan_id {
            return Ok(None);
        }
        match current.source_kind.as_str() {
            "scan" => Ok(Some(current.id)),
            "build" => {
                let attempt_id = current
                    .build_attempt_id
                    .as_deref()
                    .context("current build snapshot has no build attempt")?;
                Ok(self
                    .build_attempt(attempt_id)?
                    .and_then(|attempt| attempt.base_snapshot_id))
            }
            "runtime" => Ok(None),
            _ => Ok(None),
        }
    }

    pub fn cache_events_for_scan(&self, scan_id: &str) -> Result<Vec<CacheEventRecord>> {
        load_cache_events(
            &self.connection,
            "scan_id",
            scan_id,
            "ORDER BY created_at, id",
        )
    }

    pub fn recent_cache_events(&self, limit: usize) -> Result<Vec<CacheEventRecord>> {
        let limit = i64::try_from(limit.min(1_000)).unwrap_or(1_000);
        let mut statement = self.connection.prepare(
            "SELECT layer, cache_key, outcome, reason, created_at
               FROM cache_events ORDER BY created_at DESC, id DESC LIMIT ?1",
        )?;
        let rows = statement.query_map([limit], cache_event_from_row)?;
        let mut events = rows.collect::<std::result::Result<Vec<_>, _>>()?;
        events.reverse();
        Ok(events)
    }

    pub fn record_cache_event(
        &self,
        scan_id: Option<&str>,
        build_attempt_id: Option<&str>,
        layer: CacheLayer,
        cache_key: Option<&str>,
        outcome: &str,
        reason: &str,
    ) -> Result<()> {
        if !matches!(outcome, "hit" | "miss" | "reject" | "stored") {
            bail!("invalid cache event outcome {outcome}");
        }
        if reason.trim().is_empty() || reason.len() > 256 || reason.chars().any(char::is_control) {
            bail!("cache event reason must be a bounded printable value");
        }
        match (scan_id, build_attempt_id) {
            (Some(_), None) if matches!(layer, CacheLayer::Syntax | CacheLayer::Semantic) => {}
            (None, Some(_)) if matches!(layer, CacheLayer::Build | CacheLayer::CompilerPrecise) => {
            }
            _ => bail!(
                "cache event context does not match layer {}",
                layer.as_str()
            ),
        }
        self.connection.execute(
            "INSERT INTO cache_events(
                scan_id, build_attempt_id, layer, cache_key, outcome, reason, created_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                scan_id,
                build_attempt_id,
                layer.as_str(),
                cache_key,
                outcome,
                reason,
                now(),
            ],
        )?;
        Ok(())
    }

    pub fn lookup_snapshot_cache(
        &mut self,
        key: &CacheKey,
        scan_id: Option<&str>,
        build_attempt_id: Option<&str>,
    ) -> Result<CacheLookupResult> {
        key.validate()?;
        validate_context(key.layer, scan_id, build_attempt_id)?;
        let entry = load_cache_entry(&self.connection, key.layer, &key.key)?;
        let Some(entry) = entry else {
            self.record_cache_event(
                scan_id,
                build_attempt_id,
                key.layer,
                Some(&key.key),
                "miss",
                "not-found",
            )?;
            return Ok(cache_result(key, "miss", "not-found", None));
        };

        let rejection = self.cache_entry_rejection(key, &entry)?;
        if let Some(reason) = rejection {
            self.record_cache_event(
                scan_id,
                build_attempt_id,
                key.layer,
                Some(&key.key),
                "reject",
                &reason,
            )?;
            return Ok(cache_result(key, "reject", &reason, None));
        }

        let table = key.layer.table();
        self.connection.execute(
            &format!("UPDATE {table} SET last_used_at=?2, hit_count=hit_count+1 WHERE key=?1"),
            params![key.key, now()],
        )?;
        self.record_cache_event(
            scan_id,
            build_attempt_id,
            key.layer,
            Some(&key.key),
            "hit",
            "validated",
        )?;
        Ok(cache_result(
            key,
            "hit",
            "validated",
            Some(entry.snapshot_id),
        ))
    }

    pub fn lookup_build_cache(&mut self, key: &CacheKey) -> Result<BuildCacheLookup> {
        key.validate()?;
        if key.layer != CacheLayer::Build {
            bail!("build cache lookup requires the build layer");
        }
        let Some(entry) = load_cache_entry(&self.connection, key.layer, &key.key)? else {
            return Ok(BuildCacheLookup {
                result: cache_result(key, "miss", "not-found", None),
                audit: None,
                validated: None,
            });
        };
        if let Some(reason) = self.cache_entry_rejection(key, &entry)? {
            return Ok(BuildCacheLookup {
                result: cache_result(key, "reject", &reason, None),
                audit: None,
                validated: None,
            });
        }
        if self.current_snapshot_id()?.as_deref() != Some(entry.snapshot_id.as_str()) {
            return Ok(BuildCacheLookup {
                result: cache_result(key, "reject", "current-snapshot-mismatch", None),
                audit: None,
                validated: None,
            });
        }
        let snapshot = self
            .completed_snapshot(&entry.snapshot_id)?
            .context("validated build cache snapshot disappeared")?;
        let attempt_id = snapshot
            .build_attempt_id
            .as_deref()
            .context("validated build cache snapshot has no build attempt")?;
        let attempt = self
            .build_attempt(attempt_id)?
            .context("validated build cache attempt disappeared")?;
        if attempt.base_snapshot_id.as_deref()
            != key.dimensions.get("base_snapshot").map(String::as_str)
        {
            return Ok(BuildCacheLookup {
                result: cache_result(key, "reject", "base-binding-mismatch", None),
                audit: None,
                validated: None,
            });
        }
        let audit = match self.build_audit(&attempt.audit_run_id) {
            Ok(Some(audit)) if audit.outcome == "completed" => audit.audit,
            Ok(_) | Err(_) => {
                return Ok(BuildCacheLookup {
                    result: cache_result(key, "reject", "audit-integrity-failed", None),
                    audit: None,
                    validated: None,
                });
            }
        };
        let data_version = self
            .connection
            .query_row("PRAGMA data_version", [], |row| row.get(0))?;
        Ok(BuildCacheLookup {
            result: cache_result(key, "hit", "validated", Some(entry.snapshot_id.clone())),
            audit: Some(audit),
            validated: Some(ValidatedBuildCacheHit {
                key: key.clone(),
                entry,
                attempt_id: attempt_id.to_owned(),
                data_version,
            }),
        })
    }

    /// Publishes a build-cache hit only if the validated SQLite state and the
    /// caller's final external input proof still hold at the transaction's
    /// commit boundary.
    pub fn publish_validated_build_cache_hit_with_precommit(
        &mut self,
        lookup: &BuildCacheLookup,
        validate_before_commit: impl FnOnce() -> Result<()>,
    ) -> Result<()> {
        let hit = lookup
            .validated
            .as_ref()
            .context("build cache lookup is not a validated hit")?;
        let tx = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let observed_data_version: i64 =
            tx.query_row("PRAGMA data_version", [], |row| row.get(0))?;
        if observed_data_version != hit.data_version {
            bail!("build cache store changed after validation");
        }
        let current_snapshot_id: Option<String> = tx
            .query_row(
                "SELECT snapshot_id FROM current_completed_snapshot WHERE singleton=1",
                [],
                |row| row.get(0),
            )
            .optional()?;
        if current_snapshot_id.as_deref() != Some(hit.entry.snapshot_id.as_str()) {
            bail!("build cache current snapshot changed before publication");
        }
        let current_entry = load_cache_entry(&tx, CacheLayer::Build, &hit.key.key)?
            .context("validated build cache entry disappeared before publication")?;
        if current_entry != hit.entry {
            bail!("build cache entry changed before publication");
        }
        tx.execute(
            "UPDATE build_cache
                SET last_used_at=?2, hit_count=hit_count+1
              WHERE key=?1",
            params![hit.key.key, now()],
        )?;
        tx.execute(
            "INSERT INTO cache_events(
                build_attempt_id, layer, cache_key, outcome, reason, created_at
             ) VALUES (?1, 'build', ?2, 'hit', 'validated', ?3)",
            params![hit.attempt_id, hit.key.key, now()],
        )?;
        validate_before_commit().context("build cache hit pre-commit validation failed")?;
        tx.commit()?;
        Ok(())
    }

    pub fn lookup_compiler_precise_cache(
        &mut self,
        key: &CacheKey,
    ) -> Result<CompilerPreciseCacheLookup> {
        key.validate()?;
        if key.layer != CacheLayer::CompilerPrecise {
            bail!("compiler-precise cache lookup requires its dedicated layer");
        }
        let Some(entry) = load_compiler_precise_cache_entry(&self.connection, &key.key)? else {
            let reason = if table_count(&self.connection, CacheLayer::CompilerPrecise)? == 0 {
                "not-found"
            } else {
                "input-changed"
            };
            return Ok(CompilerPreciseCacheLookup {
                result: cache_result(key, "miss", reason, None),
                payload: None,
                audit: None,
                validated: None,
            });
        };
        if let Some(reason) = compiler_precise_entry_metadata_rejection(key, &entry)? {
            return Ok(CompilerPreciseCacheLookup {
                result: cache_result(key, "reject", &reason, None),
                payload: None,
                audit: None,
                validated: None,
            });
        }
        let payload: Value = match serde_json::from_str(&entry.payload_json) {
            Ok(payload) => payload,
            Err(_) => {
                return Ok(CompilerPreciseCacheLookup {
                    result: cache_result(key, "reject", "corrupt", None),
                    payload: None,
                    audit: None,
                    validated: None,
                });
            }
        };
        let rejection = self.compiler_precise_cache_payload_rejection(key, &entry, &payload)?;
        if let Some(reason) = rejection {
            return Ok(CompilerPreciseCacheLookup {
                result: cache_result(key, "reject", &reason, None),
                payload: None,
                audit: None,
                validated: None,
            });
        }
        let audit = self
            .build_audit(&entry.source_attempt_id)?
            .context("compiler-precise cache source audit disappeared")?
            .audit;
        let data_version = self
            .connection
            .query_row("PRAGMA data_version", [], |row| row.get(0))?;
        Ok(CompilerPreciseCacheLookup {
            result: cache_result(
                key,
                "hit",
                "validated",
                Some(entry.source_snapshot_id.clone()),
            ),
            payload: Some(payload.clone()),
            audit: Some(audit.clone()),
            validated: Some(ValidatedCompilerPreciseCacheHit {
                key: key.clone(),
                entry,
                payload,
                audit,
                data_version,
            }),
        })
    }

    pub fn store_compiler_precise_cache(
        &mut self,
        key: &CacheKey,
        source_attempt_id: &str,
        evidence: &Value,
    ) -> Result<CacheLookupResult> {
        key.validate()?;
        if key.layer != CacheLayer::CompilerPrecise {
            bail!("compiler-precise cache store requires its dedicated layer");
        }
        let attempt = self
            .build_attempt(source_attempt_id)?
            .context("compiler-precise cache source attempt was not found")?;
        if attempt.status != "completed"
            || attempt.base_snapshot_id.as_deref()
                != key.dimensions.get("base_snapshot").map(String::as_str)
        {
            bail!("compiler-precise cache source attempt is not a completed bound result");
        }
        let source_snapshot_id = self
            .snapshot_id_for_source("build", source_attempt_id)?
            .context("compiler-precise cache source snapshot was not found")?;
        if !self.verify_snapshot_integrity(&source_snapshot_id)?.valid {
            bail!("compiler-precise cache source snapshot failed integrity validation");
        }
        let raw_delta: String = self.connection.query_row(
            "SELECT delta_json FROM build_attempts WHERE id=?1 AND status='completed'",
            [source_attempt_id],
            |row| row.get(0),
        )?;
        let mut delta: BuildGraphDelta = serde_json::from_str(&raw_delta)
            .context("compiler-precise cache source delta is corrupt")?;
        rebind_build_delta_run_id(
            &mut delta,
            source_attempt_id,
            COMPILER_PRECISE_CACHED_RUN_ID,
        )?;
        let payload = json!({
            "schema_version": "depgraph-rust-compiler-precise-cache-payload-v1",
            "evidence": evidence,
            "graph_delta": delta,
        });
        let payload_json = serde_json::to_string(&payload)?;
        if payload_json.is_empty() || payload_json.len() > COMPILER_PRECISE_CACHE_MAX_PAYLOAD_BYTES
        {
            bail!("compiler-precise cache payload exceeds its bounded entry size");
        }
        let payload_digest = compiler_precise_payload_digest(&payload);
        if let Some(existing) = load_compiler_precise_cache_entry(&self.connection, &key.key)? {
            let existing_is_valid =
                if compiler_precise_entry_metadata_rejection(key, &existing)?.is_none() {
                    match serde_json::from_str(&existing.payload_json) {
                        Ok(existing_payload) => self
                            .compiler_precise_cache_payload_rejection(
                                key,
                                &existing,
                                &existing_payload,
                            )?
                            .is_none(),
                        Err(_) => false,
                    }
                } else {
                    false
                };
            if existing_is_valid && existing.payload_digest != payload_digest {
                self.record_cache_event(
                    None,
                    Some(source_attempt_id),
                    CacheLayer::CompilerPrecise,
                    Some(&key.key),
                    "reject",
                    "payload-conflict",
                )?;
                return Ok(cache_result(key, "reject", "payload-conflict", None));
            }
        }

        let timestamp = now();
        let dimensions_json = serde_json::to_string(&key.dimensions)?;
        let tx = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        tx.execute(
            "INSERT INTO compiler_precise_cache(
                key, contract_version, dimensions_json, source_snapshot_id, source_attempt_id,
                base_snapshot_id, payload_json, payload_digest, payload_bytes,
                created_at, last_used_at, hit_count
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?10, 0)
             ON CONFLICT(key) DO UPDATE SET
                contract_version=excluded.contract_version,
                dimensions_json=excluded.dimensions_json,
                source_snapshot_id=excluded.source_snapshot_id,
                source_attempt_id=excluded.source_attempt_id,
                base_snapshot_id=excluded.base_snapshot_id,
                payload_json=excluded.payload_json,
                payload_digest=excluded.payload_digest,
                payload_bytes=excluded.payload_bytes,
                last_used_at=excluded.last_used_at",
            params![
                key.key,
                key.contract_version,
                dimensions_json,
                source_snapshot_id,
                source_attempt_id,
                attempt.base_snapshot_id,
                payload_json,
                payload_digest,
                i64::try_from(payload_json.len()).unwrap_or(i64::MAX),
                timestamp,
            ],
        )?;
        gc_compiler_precise_cache(&tx, &key.key)?;
        tx.execute(
            "INSERT INTO cache_events(
                build_attempt_id, layer, cache_key, outcome, reason, created_at
             ) VALUES (?1, 'compiler-precise', ?2, 'stored', 'validated', ?3)",
            params![source_attempt_id, key.key, now()],
        )?;
        tx.commit()?;
        Ok(cache_result(
            key,
            "stored",
            "validated",
            Some(source_snapshot_id),
        ))
    }

    pub fn promote_validated_compiler_precise_cache_hit_with_precommit(
        &mut self,
        lookup: &CompilerPreciseCacheLookup,
        base_scan_id: &str,
        audit: &Value,
        validate_before_commit: impl FnOnce() -> Result<()>,
    ) -> Result<String> {
        let hit = lookup
            .validated
            .as_ref()
            .context("compiler-precise cache lookup is not a validated hit")?;
        validate_cached_hit_audit(&hit.audit, audit, &hit.payload)?;
        let run_id = required_str(audit, "run_id")?.to_owned();
        let started_at = required_str(audit, "started_at")?.to_owned();
        let finished_at = required_str(audit, "finished_at")?.to_owned();
        let output_digest = required_str(audit, "validated_output_digest")?.to_owned();
        let mut delta: BuildGraphDelta = serde_json::from_value(
            hit.payload
                .get("graph_delta")
                .cloned()
                .context("compiler-precise cache payload has no graph delta")?,
        )?;
        rebind_build_delta_run_id(&mut delta, COMPILER_PRECISE_CACHED_RUN_ID, &run_id)?;
        let attempt = BuildAttemptRecord {
            id: run_id.clone(),
            base_scan_id: base_scan_id.to_owned(),
            base_snapshot_id: Some(hit.entry.base_snapshot_id.clone()),
            audit_run_id: run_id.clone(),
            status: "staging".to_owned(),
            observer: required_str(audit, "adapter")?.to_owned(),
            observer_version: required_str(audit, "adapter_version")?.to_owned(),
            profile_id: required_str(audit, "profile_id")?.to_owned(),
            command_plan_digest: required_str(audit, "command_plan_digest")?.to_owned(),
            toolchain_executable_digest: required_str(audit, "toolchain_executable_digest")?
                .to_owned(),
            environment_key_set_digest: required_str(audit, "environment_key_set_digest")?
                .to_owned(),
            validated_output_digest: Some(output_digest.clone()),
            started_at: started_at.clone(),
            completed_at: None,
            error: None,
        };
        validate_delta_attempt_metadata(&delta, &attempt)?;
        let base = self.load_completed_snapshot(&hit.entry.base_snapshot_id)?;
        validate_build_union(&base, &delta, &attempt)?;
        let delta_json = serde_json::to_string(&delta)?;

        let tx = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let observed_data_version: i64 =
            tx.query_row("PRAGMA data_version", [], |row| row.get(0))?;
        if observed_data_version != hit.data_version {
            bail!("compiler-precise cache store changed after validation");
        }
        let current_entry = load_compiler_precise_cache_entry(&tx, &hit.key.key)?
            .context("validated compiler-precise cache entry disappeared")?;
        if current_entry != hit.entry {
            bail!("compiler-precise cache entry changed before promotion");
        }
        let current_scan_id: Option<String> = tx
            .query_row(
                "SELECT scan_id FROM current_successful WHERE singleton=1",
                [],
                |row| row.get(0),
            )
            .optional()?;
        let selected_safe_snapshot: Option<String> = tx
            .query_row(
                "SELECT snapshot_id FROM snapshot_sources
                  WHERE source_kind='scan' AND source_attempt_id=?1",
                [base_scan_id],
                |row| row.get(0),
            )
            .optional()?;
        if current_scan_id.as_deref() != Some(base_scan_id)
            || selected_safe_snapshot.as_deref() != Some(hit.entry.base_snapshot_id.as_str())
        {
            bail!("compiler-precise safe base snapshot changed before promotion");
        }
        let audit_json = serde_json::to_string(audit)?;
        tx.execute(
            "INSERT INTO build_audits(run_id, outcome, started_at, finished_at, audit_json)
             VALUES (?1, 'completed', ?2, ?3, ?4)",
            params![run_id, started_at, finished_at, audit_json],
        )?;
        tx.execute(
            "INSERT INTO build_attempts(
                id, base_scan_id, base_snapshot_id, audit_run_id, status, observer,
                observer_version, profile_id, command_plan_digest, toolchain_executable_digest,
                environment_key_set_digest, validated_output_digest, started_at,
                completed_at, delta_json
             ) VALUES (?1, ?2, ?3, ?1, 'completed', ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                run_id,
                base_scan_id,
                hit.entry.base_snapshot_id,
                attempt.observer,
                attempt.observer_version,
                attempt.profile_id,
                attempt.command_plan_digest,
                attempt.toolchain_executable_digest,
                attempt.environment_key_set_digest,
                output_digest,
                started_at,
                finished_at,
                delta_json,
            ],
        )?;
        let source_revision: Option<String> = tx.query_row(
            "SELECT source_revision FROM completed_snapshots WHERE id=?1",
            [&hit.entry.base_snapshot_id],
            |row| row.get(0),
        )?;
        let snapshot_id = create_completed_snapshot(
            &tx,
            SnapshotSource {
                source_kind: "build",
                source_attempt_id: &run_id,
                scan_id: base_scan_id,
                build_attempt_id: Some(&run_id),
                runtime_import_id: None,
                runtime_session_ids: &[],
                parent_snapshot_id: Some(&hit.entry.base_snapshot_id),
                source_revision: source_revision.as_deref(),
                created_at: &finished_at,
            },
        )?;
        tx.execute(
            "INSERT INTO current_build_successful(base_scan_id, attempt_id) VALUES (?1, ?2)
             ON CONFLICT(base_scan_id) DO UPDATE SET attempt_id=excluded.attempt_id",
            params![base_scan_id, run_id],
        )?;
        promote_completed_snapshot(&tx, &snapshot_id)?;
        tx.execute(
            "UPDATE compiler_precise_cache
                SET last_used_at=?2, hit_count=hit_count+1 WHERE key=?1",
            params![hit.key.key, now()],
        )?;
        tx.execute(
            "INSERT INTO cache_events(
                build_attempt_id, layer, cache_key, outcome, reason, created_at
             ) VALUES (?1, 'compiler-precise', ?2, 'hit', 'validated', ?3)",
            params![run_id, hit.key.key, now()],
        )?;
        validate_before_commit()
            .context("compiler-precise cache hit pre-commit validation failed")?;
        tx.commit()?;
        Ok(snapshot_id)
    }

    /// Validates a semantic scan-cache entry once and correlates its syntax
    /// provenance without re-hashing the same completed graph.
    ///
    /// The returned proof is bound to SQLite's connection data version. A
    /// different connection changing the store before promotion invalidates
    /// the proof instead of allowing a time-of-check/time-of-use cache replay.
    pub fn lookup_scan_cache(
        &mut self,
        syntax: &CacheKey,
        semantic: &CacheKey,
        scan_id: &str,
    ) -> Result<Option<ValidatedScanCacheHit>> {
        syntax.validate()?;
        semantic.validate()?;
        validate_context(syntax.layer, Some(scan_id), None)?;
        validate_context(semantic.layer, Some(scan_id), None)?;
        if syntax.layer != CacheLayer::Syntax
            || semantic.layer != CacheLayer::Semantic
            || semantic.dimensions.get("syntax_key") != Some(&syntax.key)
        {
            bail!("scan cache keys do not form a closed syntax/semantic pair");
        }

        let Some(semantic_entry) =
            load_cache_entry(&self.connection, CacheLayer::Semantic, &semantic.key)?
        else {
            let _ = self.lookup_snapshot_cache(syntax, Some(scan_id), None)?;
            self.record_cache_event(
                Some(scan_id),
                None,
                CacheLayer::Semantic,
                Some(&semantic.key),
                "miss",
                "not-found",
            )?;
            return Ok(None);
        };
        if let Some(reason) = self.cache_entry_metadata_rejection(semantic, &semantic_entry)? {
            let _ = self.lookup_snapshot_cache(syntax, Some(scan_id), None)?;
            self.record_cache_event(
                Some(scan_id),
                None,
                CacheLayer::Semantic,
                Some(&semantic.key),
                "reject",
                &reason,
            )?;
            return Ok(None);
        }
        if self
            .validate_snapshot_for_layer(CacheLayer::Semantic, &semantic_entry.snapshot_id)
            .is_err()
        {
            let _ = self.lookup_snapshot_cache(syntax, Some(scan_id), None)?;
            self.record_cache_event(
                Some(scan_id),
                None,
                CacheLayer::Semantic,
                Some(&semantic.key),
                "reject",
                "snapshot-integrity-failed",
            )?;
            return Ok(None);
        }
        let semantic_payload_digest =
            self.cache_payload_digest(CacheLayer::Semantic, &semantic_entry.snapshot_id)?;
        if semantic_payload_digest != semantic_entry.payload_digest {
            let _ = self.lookup_snapshot_cache(syntax, Some(scan_id), None)?;
            self.record_cache_event(
                Some(scan_id),
                None,
                CacheLayer::Semantic,
                Some(&semantic.key),
                "reject",
                "payload-integrity-failed",
            )?;
            return Ok(None);
        }
        let snapshot = self
            .completed_snapshot(&semantic_entry.snapshot_id)?
            .context("validated cache snapshot disappeared while loading its outcome")?;
        let (coverage, diagnostics) =
            if scan_is_semantic_noop_overlay(&self.connection, &snapshot.scan_id)? {
                let graph = self.load_completed_snapshot(&semantic_entry.snapshot_id)?;
                (graph.coverage, graph.diagnostics)
            } else {
                let coverage_json: String = self.connection.query_row(
                    "SELECT json FROM coverage WHERE scan_id=?1",
                    [&snapshot.scan_id],
                    |row| row.get(0),
                )?;
                (
                    serde_json::from_str(&coverage_json)
                        .context("cached scan coverage is not valid JSON")?,
                    load_diagnostics(&self.connection, &snapshot.scan_id)?,
                )
            };

        match load_cache_entry(&self.connection, CacheLayer::Syntax, &syntax.key)? {
            None => self.record_cache_event(
                Some(scan_id),
                None,
                CacheLayer::Syntax,
                Some(&syntax.key),
                "miss",
                "not-found",
            )?,
            Some(syntax_entry) => {
                let rejection = self
                    .cache_entry_metadata_rejection(syntax, &syntax_entry)?
                    .or_else(|| {
                        (syntax_entry.snapshot_id != semantic_entry.snapshot_id)
                            .then(|| "snapshot-mismatch".to_owned())
                    })
                    .or_else(|| {
                        self.cache_payload_digest(CacheLayer::Syntax, &syntax_entry.snapshot_id)
                            .map_or_else(
                                |_| Some("snapshot-integrity-failed".to_owned()),
                                |digest| {
                                    (digest != syntax_entry.payload_digest)
                                        .then(|| "payload-integrity-failed".to_owned())
                                },
                            )
                    });
                if let Some(reason) = rejection {
                    self.record_cache_event(
                        Some(scan_id),
                        None,
                        CacheLayer::Syntax,
                        Some(&syntax.key),
                        "reject",
                        &reason,
                    )?;
                } else {
                    self.touch_cache_entry(CacheLayer::Syntax, &syntax.key)?;
                    self.record_cache_event(
                        Some(scan_id),
                        None,
                        CacheLayer::Syntax,
                        Some(&syntax.key),
                        "hit",
                        "validated-by-semantic-cache",
                    )?;
                }
            }
        }
        self.touch_cache_entry(CacheLayer::Semantic, &semantic.key)?;
        self.record_cache_event(
            Some(scan_id),
            None,
            CacheLayer::Semantic,
            Some(&semantic.key),
            "hit",
            "validated",
        )?;
        let data_version = self
            .connection
            .query_row("PRAGMA data_version", [], |row| row.get(0))?;
        Ok(Some(ValidatedScanCacheHit {
            snapshot_id: semantic_entry.snapshot_id,
            data_version,
            coverage,
            diagnostics,
        }))
    }

    /// Publishes a cache hit by adding a source alias to the already validated,
    /// immutable completed snapshot. No repository-complete graph rows are
    /// cloned into the new scan attempt.
    pub fn promote_validated_scan_cache_hit(
        &mut self,
        scan_id: &str,
        hit: &ValidatedScanCacheHit,
    ) -> Result<()> {
        self.promote_validated_scan_cache_hit_with_precommit(scan_id, hit, || Ok(()))
    }

    /// Publishes a validated cache hit only if the caller's final external
    /// input proof still holds at the SQLite transaction's commit boundary.
    pub fn promote_validated_scan_cache_hit_with_precommit(
        &mut self,
        scan_id: &str,
        hit: &ValidatedScanCacheHit,
        validate_before_commit: impl FnOnce() -> Result<()>,
    ) -> Result<()> {
        let observed_data_version: i64 =
            self.connection
                .query_row("PRAGMA data_version", [], |row| row.get(0))?;
        if observed_data_version != hit.data_version {
            bail!("cache store changed after validation");
        }
        let source = self
            .completed_snapshot(&hit.snapshot_id)?
            .context("validated cache snapshot disappeared before promotion")?;
        if source.source_kind != "scan" || source.status != "completed" {
            bail!("validated cache snapshot is not a completed scan");
        }

        let tx = self.connection.transaction()?;
        ensure_scan_staging(&tx, scan_id)?;
        let (mutation_count, populated_tables): (i64, i64) = tx.query_row(
            "SELECT s.mutation_count,
                    (SELECT COUNT(*) FROM profiles WHERE scan_id=s.id)
                  + (SELECT COUNT(*) FROM nodes WHERE scan_id=s.id)
                  + (SELECT COUNT(*) FROM sites WHERE scan_id=s.id)
                  + (SELECT COUNT(*) FROM edges WHERE scan_id=s.id)
                  + (SELECT COUNT(*) FROM evidence WHERE scan_id=s.id)
                  + (SELECT COUNT(*) FROM diagnostics WHERE scan_id=s.id)
                  + (SELECT COUNT(*) FROM file_coverage WHERE scan_id=s.id)
                  + (SELECT COUNT(*) FROM coverage WHERE scan_id=s.id)
                  + (SELECT COUNT(*) FROM profile_coverage WHERE scan_id=s.id)
                  + (SELECT COUNT(*) FROM adapter_logs WHERE scan_id=s.id)
               FROM scans s WHERE s.id=?1",
            [scan_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        if mutation_count != 0 || populated_tables != 0 {
            bail!("cache target scan changed before promotion");
        }
        let source_project_code_executed: bool = tx.query_row(
            "SELECT project_code_executed FROM scans WHERE id=?1",
            [&source.scan_id],
            |row| row.get(0),
        )?;
        if source_project_code_executed {
            bail!("a scan that executed project code cannot be promoted in safe mode");
        }
        let completed_at = now();
        tx.execute(
            "UPDATE scans
                SET status='completed', completed_at=?2,
                    project_code_executed=?3
              WHERE id=?1",
            params![scan_id, completed_at, source_project_code_executed],
        )?;
        tx.execute(
            "INSERT INTO snapshot_sources(
                source_kind, source_attempt_id, snapshot_id, promoted_at
             ) VALUES ('scan', ?1, ?2, ?3)",
            params![scan_id, hit.snapshot_id, completed_at],
        )?;
        tx.execute(
            "INSERT INTO current_successful(singleton, scan_id) VALUES (1, ?1)
             ON CONFLICT(singleton) DO UPDATE SET scan_id=excluded.scan_id",
            [scan_id],
        )?;
        promote_completed_snapshot(&tx, &hit.snapshot_id)?;
        validate_before_commit().context("cache hit pre-commit validation failed")?;
        tx.commit()?;
        Ok(())
    }

    pub fn store_snapshot_cache(
        &mut self,
        key: &CacheKey,
        snapshot_id: &str,
        scan_id: Option<&str>,
        build_attempt_id: Option<&str>,
    ) -> Result<CacheLookupResult> {
        key.validate()?;
        validate_context(key.layer, scan_id, build_attempt_id)?;
        self.validate_snapshot_for_layer(key.layer, snapshot_id)?;
        self.store_validated_snapshot_cache(key, snapshot_id, scan_id, build_attempt_id)
    }

    pub fn store_completed_scan_snapshot_caches(
        &mut self,
        syntax: &CacheKey,
        semantic: Option<&CacheKey>,
        completed: &CompletedScanSnapshot,
    ) -> Result<Vec<CacheLookupResult>> {
        if syntax.layer != CacheLayer::Syntax {
            bail!("scan syntax cache key must use the syntax layer");
        }
        syntax.validate()?;
        validate_context(syntax.layer, Some(&completed.scan_id), None)?;
        if let Some(semantic) = semantic {
            if semantic.layer != CacheLayer::Semantic {
                bail!("scan semantic cache key must use the semantic layer");
            }
            semantic.validate()?;
            validate_context(semantic.layer, Some(&completed.scan_id), None)?;
        }
        // The unforgeable completion token was produced by validation and
        // content-addressed snapshot creation in the immediately preceding
        // promotion. Cache reads independently verify snapshot integrity, so
        // the optional cache write need not hash the same large graph again.
        let mut results = vec![self.store_validated_snapshot_cache(
            syntax,
            &completed.snapshot_id,
            Some(&completed.scan_id),
            None,
        )?];
        if let Some(semantic) = semantic {
            results.push(self.store_validated_snapshot_cache(
                semantic,
                &completed.snapshot_id,
                Some(&completed.scan_id),
                None,
            )?);
        }
        Ok(results)
    }

    fn store_validated_snapshot_cache(
        &mut self,
        key: &CacheKey,
        snapshot_id: &str,
        scan_id: Option<&str>,
        build_attempt_id: Option<&str>,
    ) -> Result<CacheLookupResult> {
        let payload_digest = self.cache_payload_digest(key.layer, snapshot_id)?;
        if let Some(existing) = load_cache_entry(&self.connection, key.layer, &key.key)?
            && self.cache_entry_rejection(key, &existing)?.is_none()
            && existing.payload_digest != payload_digest
        {
            self.record_cache_event(
                scan_id,
                build_attempt_id,
                key.layer,
                Some(&key.key),
                "reject",
                "payload-conflict",
            )?;
            return Ok(cache_result(key, "reject", "payload-conflict", None));
        }

        let timestamp = now();
        let dimensions_json = serde_json::to_string(&key.dimensions)?;
        let table = key.layer.table();
        self.connection.execute(
            &format!(
                "INSERT INTO {table}(
                    key, contract_version, dimensions_json, snapshot_id, payload_digest,
                    created_at, last_used_at, hit_count
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6, 0)
                 ON CONFLICT(key) DO UPDATE SET
                    contract_version=excluded.contract_version,
                    dimensions_json=excluded.dimensions_json,
                    snapshot_id=excluded.snapshot_id,
                    payload_digest=excluded.payload_digest,
                    last_used_at=excluded.last_used_at"
            ),
            params![
                key.key,
                key.contract_version,
                dimensions_json,
                snapshot_id,
                payload_digest,
                timestamp,
            ],
        )?;
        self.record_cache_event(
            scan_id,
            build_attempt_id,
            key.layer,
            Some(&key.key),
            "stored",
            "validated",
        )?;
        Ok(cache_result(
            key,
            "stored",
            "validated",
            Some(snapshot_id.to_owned()),
        ))
    }

    pub fn clone_completed_scan_into_staging(
        &mut self,
        snapshot_id: &str,
        target_scan_id: &str,
    ) -> Result<()> {
        self.validate_snapshot_for_layer(CacheLayer::Semantic, snapshot_id)?;
        let mut source = self
            .completed_snapshot(snapshot_id)?
            .context("validated cache snapshot disappeared")?;
        let mut overlay_scan_ids = Vec::new();
        while scan_is_semantic_noop_overlay(&self.connection, &source.scan_id)? {
            overlay_scan_ids.push(source.scan_id.clone());
            let parent_snapshot_id = source
                .parent_snapshot_id
                .as_deref()
                .context("semantic no-op cache snapshot has no parent")?;
            source = self
                .completed_snapshot(parent_snapshot_id)?
                .context("semantic no-op cache parent disappeared")?;
            if source.source_kind != "scan" {
                bail!("semantic cache overlay parent is not a completed scan snapshot");
            }
        }
        let source_scan_id = source.scan_id;
        let tx = self.connection.transaction()?;
        ensure_scan_staging(&tx, target_scan_id)?;
        let source_status: String = tx.query_row(
            "SELECT status FROM scans WHERE id=?1",
            [&source_scan_id],
            |row| row.get(0),
        )?;
        if source_status != "completed" {
            bail!("cache source scan is not completed");
        }

        tx.execute(
            "INSERT INTO profiles(scan_id, id, json)
             SELECT ?1, id, json FROM profiles WHERE scan_id=?2",
            params![target_scan_id, source_scan_id],
        )?;
        tx.execute(
            "INSERT INTO nodes(
                scan_id, id, kind, locator, display_name, properties_json, raw_json
             ) SELECT ?1, id, kind, locator, display_name, properties_json, raw_json
                 FROM nodes WHERE scan_id=?2",
            params![target_scan_id, source_scan_id],
        )?;
        tx.execute(
            "INSERT INTO sites(
                scan_id, id, source, kind, specifier, profile_id, resolution_status,
                precision, condition_json, target_ids_json, reason, raw_json
             ) SELECT ?1, id, source, kind, specifier, profile_id, resolution_status,
                      precision, condition_json, target_ids_json, reason, raw_json
                 FROM sites WHERE scan_id=?2",
            params![target_scan_id, source_scan_id],
        )?;
        tx.execute(
            "INSERT INTO edges(
                scan_id, id, site_id, source, target, kind, phase, environment, profile_id,
                resolution_status, precision, condition_json, generated, raw_json
             ) SELECT ?1, id, site_id, source, target, kind, phase, environment, profile_id,
                      resolution_status, precision, condition_json, generated, raw_json
                 FROM edges WHERE scan_id=?2",
            params![target_scan_id, source_scan_id],
        )?;
        tx.execute(
            "INSERT INTO evidence(
                scan_id, owner_type, owner_id, ordinal, kind, extractor, extractor_version,
                path, start_line, start_column, end_line, end_column, raw_json
             ) SELECT ?1, owner_type, owner_id, ordinal, kind, extractor, extractor_version,
                      path, start_line, start_column, end_line, end_column, raw_json
                 FROM evidence WHERE scan_id=?2",
            params![target_scan_id, source_scan_id],
        )?;
        tx.execute(
            "INSERT INTO diagnostics(
                scan_id, ordinal, id, severity, code, message, path, adapter, raw_json
             ) SELECT ?1, ordinal, id, severity, code, message, path, adapter, raw_json
                 FROM diagnostics WHERE scan_id=?2",
            params![target_scan_id, source_scan_id],
        )?;
        tx.execute(
            "INSERT INTO file_coverage(
                scan_id, path, discovered_sites, emitted_sites, skipped_sites, skipped,
                reason, adapter
             ) SELECT ?1, path, discovered_sites, emitted_sites, skipped_sites, skipped,
                      reason, adapter FROM file_coverage WHERE scan_id=?2",
            params![target_scan_id, source_scan_id],
        )?;
        tx.execute(
            "INSERT INTO coverage(scan_id, json)
             SELECT ?1, json FROM coverage WHERE scan_id=?2",
            params![target_scan_id, source_scan_id],
        )?;
        tx.execute(
            "INSERT INTO profile_coverage(scan_id, profile_id, json)
             SELECT ?1, profile_id, json FROM profile_coverage WHERE scan_id=?2",
            params![target_scan_id, source_scan_id],
        )?;
        tx.execute(
            "INSERT INTO adapter_logs(scan_id, adapter, stderr, truncated)
             SELECT ?1, adapter, stderr, truncated FROM adapter_logs WHERE scan_id=?2",
            params![target_scan_id, source_scan_id],
        )?;
        for overlay_scan_id in overlay_scan_ids.iter().rev() {
            tx.execute(
                "INSERT INTO nodes(
                    scan_id, id, kind, locator, display_name, properties_json, raw_json
                 ) SELECT ?1, id, kind, locator, display_name, properties_json, raw_json
                     FROM nodes WHERE scan_id=?2
                 ON CONFLICT(scan_id, id) DO UPDATE SET
                    kind=excluded.kind,
                    locator=excluded.locator,
                    display_name=excluded.display_name,
                    properties_json=excluded.properties_json,
                    raw_json=excluded.raw_json",
                params![target_scan_id, overlay_scan_id],
            )?;
            tx.execute(
                "INSERT INTO adapter_logs(scan_id, adapter, stderr, truncated)
                 SELECT ?1, adapter, stderr, truncated
                   FROM adapter_logs WHERE scan_id=?2
                 ON CONFLICT(scan_id, adapter) DO UPDATE SET
                    stderr=excluded.stderr,
                    truncated=excluded.truncated",
                params![target_scan_id, overlay_scan_id],
            )?;
        }
        tx.execute(
            "UPDATE scans
                SET project_code_executed=(SELECT project_code_executed FROM scans WHERE id=?2),
                    mutation_count=mutation_count+1
              WHERE id=?1",
            params![target_scan_id, source_scan_id],
        )?;
        tx.commit()?;
        Ok(())
    }

    fn cache_entry_rejection(
        &self,
        expected: &CacheKey,
        entry: &StoredCacheEntry,
    ) -> Result<Option<String>> {
        if let Some(reason) = self.cache_entry_metadata_rejection(expected, entry)? {
            return Ok(Some(reason));
        }
        if self
            .validate_snapshot_for_layer(expected.layer, &entry.snapshot_id)
            .is_err()
        {
            return Ok(Some("snapshot-integrity-failed".to_owned()));
        }
        let digest = self.cache_payload_digest(expected.layer, &entry.snapshot_id)?;
        if digest != entry.payload_digest {
            return Ok(Some("payload-integrity-failed".to_owned()));
        }
        Ok(None)
    }

    fn compiler_precise_cache_payload_rejection(
        &self,
        key: &CacheKey,
        entry: &StoredCompilerPreciseCacheEntry,
        payload: &Value,
    ) -> Result<Option<String>> {
        if compiler_precise_payload_digest(payload) != entry.payload_digest {
            return Ok(Some("corrupt".to_owned()));
        }
        if payload.get("schema_version").and_then(Value::as_str)
            != Some("depgraph-rust-compiler-precise-cache-payload-v1")
        {
            return Ok(Some("corrupt".to_owned()));
        }
        let Some(evidence) = payload.get("evidence") else {
            return Ok(Some("corrupt".to_owned()));
        };
        if evidence
            .get("effective_input_identity")
            .and_then(Value::as_str)
            != Some(key.key.as_str())
            || evidence.get("base_snapshot_id").and_then(Value::as_str)
                != Some(entry.base_snapshot_id.as_str())
        {
            return Ok(Some("input-changed".to_owned()));
        }
        let snapshot = match self.completed_snapshot(&entry.source_snapshot_id) {
            Ok(Some(snapshot)) => snapshot,
            Ok(None) | Err(_) => return Ok(Some("corrupt".to_owned())),
        };
        if snapshot.source_kind != "build"
            || snapshot.build_attempt_id.as_deref() != Some(entry.source_attempt_id.as_str())
            || !self
                .verify_snapshot_integrity(&entry.source_snapshot_id)
                .is_ok_and(|integrity| integrity.valid)
            || !self
                .verify_snapshot_integrity(&entry.base_snapshot_id)
                .is_ok_and(|integrity| integrity.valid)
        {
            return Ok(Some("corrupt".to_owned()));
        }
        let attempt = match self.build_attempt(&entry.source_attempt_id) {
            Ok(Some(attempt)) => attempt,
            Ok(None) | Err(_) => return Ok(Some("corrupt".to_owned())),
        };
        if attempt.status != "completed"
            || attempt.base_snapshot_id.as_deref() != Some(entry.base_snapshot_id.as_str())
            || attempt.validated_output_digest.as_deref()
                != evidence
                    .get("validated_output_digest")
                    .and_then(Value::as_str)
        {
            return Ok(Some("corrupt".to_owned()));
        }
        let audit = match self.build_audit(&entry.source_attempt_id) {
            Ok(Some(audit)) => audit,
            Ok(None) | Err(_) => return Ok(Some("corrupt".to_owned())),
        };
        if audit.outcome != "completed"
            || audit
                .audit
                .get("validated_output_digest")
                .and_then(Value::as_str)
                != attempt.validated_output_digest.as_deref()
        {
            return Ok(Some("corrupt".to_owned()));
        }
        let raw_delta: String = match self.connection.query_row(
            "SELECT delta_json FROM build_attempts WHERE id=?1 AND status='completed'",
            [&entry.source_attempt_id],
            |row| row.get(0),
        ) {
            Ok(delta) => delta,
            Err(_) => return Ok(Some("corrupt".to_owned())),
        };
        let mut delta: BuildGraphDelta = match serde_json::from_str(&raw_delta) {
            Ok(delta) => delta,
            Err(_) => return Ok(Some("corrupt".to_owned())),
        };
        if rebind_build_delta_run_id(
            &mut delta,
            &entry.source_attempt_id,
            COMPILER_PRECISE_CACHED_RUN_ID,
        )
        .is_err()
            || serde_json::to_value(delta).ok().as_ref() != payload.get("graph_delta")
        {
            return Ok(Some("corrupt".to_owned()));
        }
        Ok(None)
    }

    fn cache_entry_metadata_rejection(
        &self,
        expected: &CacheKey,
        entry: &StoredCacheEntry,
    ) -> Result<Option<String>> {
        if entry.contract_version != CACHE_CONTRACT_VERSION {
            return Ok(Some("unsupported-contract-version".to_owned()));
        }
        let dimensions: BTreeMap<String, String> =
            match serde_json::from_str(&entry.dimensions_json) {
                Ok(value) => value,
                Err(_) => return Ok(Some("invalid-dimensions".to_owned())),
            };
        let observed = CacheKey::new(expected.layer, dimensions);
        if observed.key != expected.key || observed.dimensions != expected.dimensions {
            return Ok(Some("identity-mismatch".to_owned()));
        }
        Ok(None)
    }

    fn touch_cache_entry(&self, layer: CacheLayer, key: &str) -> Result<()> {
        let table = layer.table();
        self.connection.execute(
            &format!("UPDATE {table} SET last_used_at=?2, hit_count=hit_count+1 WHERE key=?1"),
            params![key, now()],
        )?;
        Ok(())
    }

    fn validate_snapshot_for_layer(&self, layer: CacheLayer, snapshot_id: &str) -> Result<()> {
        let snapshot = self
            .completed_snapshot(snapshot_id)?
            .with_context(|| format!("cache snapshot {snapshot_id} was not found"))?;
        let expected_source = if matches!(layer, CacheLayer::Build | CacheLayer::CompilerPrecise) {
            "build"
        } else {
            "scan"
        };
        if snapshot.source_kind != expected_source {
            bail!(
                "cache snapshot source does not match layer {}",
                layer.as_str()
            );
        }
        let integrity = self.verify_snapshot_integrity(snapshot_id)?;
        if !integrity.valid {
            bail!("cache snapshot integrity failed");
        }
        Ok(())
    }

    fn cache_payload_digest(&self, layer: CacheLayer, snapshot_id: &str) -> Result<String> {
        let snapshot = self
            .completed_snapshot(snapshot_id)?
            .context("cache snapshot was not found")?;
        Ok(stable_id_from_value(
            "cache-payload-reference",
            &json!({
                "schema": "cache-payload-reference-v2",
                "contract_version": CACHE_CONTRACT_VERSION,
                "layer": layer.as_str(),
                "snapshot_id": snapshot.id,
                "source_kind": snapshot.source_kind,
                "status": snapshot.status,
            }),
        ))
    }
}

fn validate_context(
    layer: CacheLayer,
    scan_id: Option<&str>,
    build_attempt_id: Option<&str>,
) -> Result<()> {
    match (scan_id, build_attempt_id) {
        (Some(_), None) if matches!(layer, CacheLayer::Syntax | CacheLayer::Semantic) => Ok(()),
        (None, Some(_)) if matches!(layer, CacheLayer::Build | CacheLayer::CompilerPrecise) => {
            Ok(())
        }
        _ => bail!(
            "cache operation context does not match layer {}",
            layer.as_str()
        ),
    }
}

fn cache_result(
    key: &CacheKey,
    outcome: &str,
    reason: &str,
    snapshot_id: Option<String>,
) -> CacheLookupResult {
    CacheLookupResult {
        layer: key.layer,
        cache_key: key.key.clone(),
        outcome: outcome.to_owned(),
        reason: reason.to_owned(),
        snapshot_id,
    }
}

fn load_cache_entry(
    connection: &rusqlite::Connection,
    layer: CacheLayer,
    key: &str,
) -> Result<Option<StoredCacheEntry>> {
    if layer == CacheLayer::CompilerPrecise {
        bail!("compiler-precise entries require their dedicated payload reader");
    }
    let table = layer.table();
    connection
        .query_row(
            &format!(
                "SELECT contract_version, dimensions_json, snapshot_id, payload_digest
                   FROM {table} WHERE key=?1"
            ),
            [key],
            |row| {
                Ok(StoredCacheEntry {
                    contract_version: row.get(0)?,
                    dimensions_json: row.get(1)?,
                    snapshot_id: row.get(2)?,
                    payload_digest: row.get(3)?,
                })
            },
        )
        .optional()
        .context("failed to read cache entry")
}

fn load_compiler_precise_cache_entry(
    connection: &rusqlite::Connection,
    key: &str,
) -> Result<Option<StoredCompilerPreciseCacheEntry>> {
    connection
        .query_row(
            "SELECT contract_version, dimensions_json, source_snapshot_id, source_attempt_id,
                    base_snapshot_id, payload_json, payload_digest
               FROM compiler_precise_cache WHERE key=?1",
            [key],
            |row| {
                Ok(StoredCompilerPreciseCacheEntry {
                    contract_version: row.get(0)?,
                    dimensions_json: row.get(1)?,
                    source_snapshot_id: row.get(2)?,
                    source_attempt_id: row.get(3)?,
                    base_snapshot_id: row.get(4)?,
                    payload_json: row.get(5)?,
                    payload_digest: row.get(6)?,
                })
            },
        )
        .optional()
        .context("failed to read compiler-precise cache entry")
}

fn compiler_precise_entry_metadata_rejection(
    expected: &CacheKey,
    entry: &StoredCompilerPreciseCacheEntry,
) -> Result<Option<String>> {
    if entry.contract_version != CACHE_CONTRACT_VERSION {
        return Ok(Some("corrupt".to_owned()));
    }
    let dimensions: BTreeMap<String, String> = match serde_json::from_str(&entry.dimensions_json) {
        Ok(dimensions) => dimensions,
        Err(_) => return Ok(Some("corrupt".to_owned())),
    };
    let observed = CacheKey::new(CacheLayer::CompilerPrecise, dimensions);
    if observed.key != expected.key
        || observed.dimensions != expected.dimensions
        || expected.dimensions.get("base_snapshot") != Some(&entry.base_snapshot_id)
        || entry.payload_json.is_empty()
        || entry.payload_json.len() > COMPILER_PRECISE_CACHE_MAX_PAYLOAD_BYTES
    {
        return Ok(Some("corrupt".to_owned()));
    }
    Ok(None)
}

fn compiler_precise_payload_digest(payload: &Value) -> String {
    stable_id_from_value("compiler-precise-cache-payload", payload)
}

fn rebind_build_delta_run_id(delta: &mut BuildGraphDelta, from: &str, to: &str) -> Result<()> {
    let mut rebound = 0_usize;
    for node in &mut delta.nodes {
        let Some(provenance) = node
            .properties
            .get_mut("build_provenance")
            .and_then(Value::as_object_mut)
        else {
            continue;
        };
        if provenance.get("build_run_id").and_then(Value::as_str) == Some(from) {
            provenance.insert("build_run_id".to_owned(), Value::String(to.to_owned()));
            rebound += 1;
        }
    }
    for evidence in &mut delta.evidence {
        let Some(properties) = evidence.properties.as_object_mut() else {
            continue;
        };
        if properties.get("build_run_id").and_then(Value::as_str) == Some(from) {
            properties.insert("build_run_id".to_owned(), Value::String(to.to_owned()));
            rebound += 1;
        }
    }
    if rebound == 0 {
        bail!("compiler-precise cache graph delta has no bound build provenance");
    }
    Ok(())
}

fn validate_cached_hit_audit(cached: &Value, candidate: &Value, payload: &Value) -> Result<()> {
    if required_str(candidate, "outcome")? != "completed"
        || required_str(candidate, "run_id")? == required_str(cached, "run_id")?
    {
        bail!("compiler-precise cache hit audit is not a new completed attempt");
    }
    for field in [
        "schema_version",
        "adapter",
        "adapter_version",
        "profile_id",
        "command_program",
        "command_plan_digest",
        "logical_cwd",
        "source_root_digest",
        "toolchain_executable_digest",
        "environment_key_set_digest",
        "network_policy",
        "validated_output_digest",
    ] {
        if candidate.get(field) != cached.get(field) {
            bail!("compiler-precise cache hit audit changed {field}");
        }
    }
    let output_digest = required_str(candidate, "validated_output_digest")?;
    if !is_sha256_hex(output_digest)
        || payload
            .get("evidence")
            .and_then(|evidence| evidence.get("validated_output_digest"))
            .and_then(Value::as_str)
            != Some(output_digest)
    {
        bail!("compiler-precise cache hit output digest is invalid");
    }
    Ok(())
}

fn gc_compiler_precise_cache(tx: &rusqlite::Transaction<'_>, retained_key: &str) -> Result<()> {
    loop {
        let (count, total): (i64, i64) = tx.query_row(
            "SELECT COUNT(*), COALESCE(SUM(payload_bytes), 0) FROM compiler_precise_cache",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        if count <= i64::try_from(COMPILER_PRECISE_CACHE_MAX_ENTRIES).unwrap_or(i64::MAX)
            && total <= i64::try_from(COMPILER_PRECISE_CACHE_MAX_TOTAL_BYTES).unwrap_or(i64::MAX)
        {
            break;
        }
        let candidate: Option<String> = tx
            .query_row(
                "SELECT key FROM compiler_precise_cache
                  WHERE key!=?1 ORDER BY last_used_at, key LIMIT 1",
                [retained_key],
                |row| row.get(0),
            )
            .optional()?;
        let Some(candidate) = candidate else {
            bail!("compiler-precise cache payload exceeds the total cache bound");
        };
        tx.execute(
            "DELETE FROM compiler_precise_cache WHERE key=?1",
            [candidate],
        )?;
    }
    Ok(())
}

fn table_count(connection: &rusqlite::Connection, layer: CacheLayer) -> Result<u64> {
    let table = layer.table();
    let count: i64 = connection.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
        row.get(0)
    })?;
    Ok(u64::try_from(count).unwrap_or_default())
}

fn load_cache_events(
    connection: &rusqlite::Connection,
    column: &str,
    id: &str,
    order: &str,
) -> Result<Vec<CacheEventRecord>> {
    let mut statement = connection.prepare(&format!(
        "SELECT layer, cache_key, outcome, reason, created_at
           FROM cache_events WHERE {column}=?1 {order}"
    ))?;
    statement
        .query_map([id], cache_event_from_row)?
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("failed to read cache events")
}

fn cache_event_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<CacheEventRecord> {
    let layer = match row.get::<_, String>(0)?.as_str() {
        "syntax" => CacheLayer::Syntax,
        "semantic" => CacheLayer::Semantic,
        "build" => CacheLayer::Build,
        "compiler-precise" => CacheLayer::CompilerPrecise,
        _ => return Err(rusqlite::Error::InvalidQuery),
    };
    Ok(CacheEventRecord {
        layer,
        cache_key: row.get(1)?,
        outcome: row.get(2)?,
        reason: row.get(3)?,
        created_at: row.get(4)?,
    })
}

fn now() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn complete_fixture_scan(store: &mut Store, scan_id: &str, root: &std::path::Path) -> String {
        store.start_scan(scan_id, root, false).unwrap();
        let common = |event: &str, seq: u64| {
            json!({
                "event":event,
                "protocol_version":"1.0",
                "scan_id":scan_id,
                "adapter":"fixture",
                "adapter_version":"1.0",
                "seq":seq,
            })
        };
        let evidence = json!({
            "kind":"source",
            "extractor":"fixture",
            "extractor_version":"1.0",
            "path":"src/lib.rs",
            "start_line":1,
            "start_column":1,
            "end_line":1,
            "end_column":2,
            "properties":{}
        });
        let mut profile = common("profile_declared", 1);
        profile["profile"] = json!({
            "id":"fixture:default",
            "language":"fixture",
            "features":[],
            "environment":{},
            "properties":{}
        });
        let mut source = common("node_upsert", 2);
        source["node"] = json!({
            "id":"file:source",
            "kind":"file",
            "locator":"file:src/lib.rs",
            "display_name":"src/lib.rs",
            "properties":{"path":"src/lib.rs"},
            "evidence":[evidence.clone()]
        });
        let mut target = common("node_upsert", 3);
        target["node"] = json!({
            "id":"file:target",
            "kind":"file",
            "locator":"file:src/target.rs",
            "display_name":"src/target.rs",
            "properties":{"path":"src/target.rs"},
            "evidence":[evidence.clone()]
        });
        let mut site = common("dependency_site", 4);
        site["site"] = json!({
            "id":"site:fixture",
            "source":"file:source",
            "kind":"imports",
            "specifier":"target",
            "profile_id":"fixture:default",
            "resolution_status":"resolved",
            "precision":"exact",
            "condition":{"op":"all","conditions":[]},
            "target_ids":["file:target"],
            "evidence":[evidence.clone()]
        });
        let mut edge = common("edge_upsert", 5);
        edge["edge"] = json!({
            "id":"edge:fixture",
            "site_id":"site:fixture",
            "source":"file:source",
            "target":"file:target",
            "kind":"imports",
            "phase":"source",
            "environment":"any",
            "profile_id":"fixture:default",
            "resolution_status":"resolved",
            "precision":"exact",
            "condition":{"op":"all","conditions":[]},
            "generated":false,
            "evidence":[evidence]
        });
        let mut diagnostic = common("diagnostic", 6);
        diagnostic["diagnostic"] = json!({
            "id":"diagnostic:fixture",
            "severity":"info",
            "code":"fixture",
            "message":"fixture diagnostic"
        });
        let mut file = common("file_completed", 7);
        file["path"] = json!("src/lib.rs");
        file["discovered_sites"] = json!(1);
        file["emitted_sites"] = json!(1);
        file["skipped_sites"] = json!(0);
        file["skipped"] = json!(false);
        let coverage = json!({
            "profiles":1,
            "files_discovered":1,
            "files_analyzed":1,
            "files_skipped":0,
            "dependency_sites":1,
            "resolved":1,
            "candidates":0,
            "external":0,
            "unresolved":0,
            "unsupported_syntax":0,
            "project_code_executed":false,
            "completeness":["syntax-complete"],
            "reasons":[]
        });
        let mut profile_completed = common("profile_completed", 8);
        profile_completed["profile_id"] = json!("fixture:default");
        profile_completed["coverage"] = coverage.clone();
        let mut completed = common("scan_completed", 9);
        completed["coverage"] = coverage;
        for event in [
            profile,
            source,
            target,
            site,
            edge,
            diagnostic,
            file,
            profile_completed,
            completed,
        ] {
            store.ingest_event(&event).unwrap();
        }
        store
            .save_adapter_log(scan_id, "fixture", "fixture log", false)
            .unwrap();
        store.finish_scan(scan_id, "completed", None, true).unwrap();
        store
            .snapshot_id_for_source("scan", scan_id)
            .unwrap()
            .unwrap()
    }

    fn cache_key(layer: CacheLayer, input: &str) -> CacheKey {
        CacheKey::new(
            layer,
            BTreeMap::from([("input".to_owned(), input.to_owned())]),
        )
    }

    fn scan_cache_keys() -> (CacheKey, CacheKey) {
        let syntax = cache_key(CacheLayer::Syntax, "sha256:syntax");
        let semantic = CacheKey::new(
            CacheLayer::Semantic,
            BTreeMap::from([
                ("input".to_owned(), "sha256:semantic".to_owned()),
                ("syntax_key".to_owned(), syntax.key.clone()),
            ]),
        );
        (syntax, semantic)
    }

    #[test]
    fn cache_hit_clones_a_validated_completed_graph() {
        let root = tempfile::tempdir().unwrap();
        let mut store = Store::open_in_memory().unwrap();
        let snapshot_id = complete_fixture_scan(&mut store, "source", root.path());
        let syntax = cache_key(CacheLayer::Syntax, "sha256:syntax");
        let semantic = cache_key(CacheLayer::Semantic, "sha256:semantic");
        assert_eq!(
            store
                .store_snapshot_cache(&syntax, &snapshot_id, Some("source"), None)
                .unwrap()
                .outcome,
            "stored"
        );
        assert_eq!(
            store
                .store_snapshot_cache(&semantic, &snapshot_id, Some("source"), None)
                .unwrap()
                .outcome,
            "stored"
        );

        store.start_scan("target", root.path(), false).unwrap();
        let hit = store
            .lookup_snapshot_cache(&semantic, Some("target"), None)
            .unwrap();
        assert_eq!(hit.outcome, "hit");
        store
            .clone_completed_scan_into_staging(hit.snapshot_id.as_deref().unwrap(), "target")
            .unwrap();
        store.validate_scan("target").unwrap();
        store
            .finish_scan("target", "completed", None, true)
            .unwrap();

        let source = store.load_snapshot("source").unwrap();
        let target = store.load_snapshot("target").unwrap();
        assert_eq!(source.profiles, target.profiles);
        assert_eq!(source.nodes, target.nodes);
        assert_eq!(source.sites, target.sites);
        assert_eq!(source.edges, target.edges);
        assert_eq!(source.evidence, target.evidence);
        assert_eq!(source.diagnostics, target.diagnostics);
        assert_eq!(source.file_coverage, target.file_coverage);
        assert_eq!(source.adapter_logs, target.adapter_logs);
        assert_eq!(source.coverage, target.coverage);
        assert_eq!(
            store.cache_entry_counts().unwrap(),
            CacheEntryCounts {
                syntax: 1,
                semantic: 1,
                build: 0,
                compiler_precise: 0,
            }
        );
    }

    #[test]
    fn validated_scan_cache_hit_promotes_without_cloning_graph_rows() {
        let root = tempfile::tempdir().unwrap();
        let mut store = Store::open_in_memory().unwrap();
        let snapshot_id = complete_fixture_scan(&mut store, "source", root.path());
        let (syntax, semantic) = scan_cache_keys();
        store
            .store_snapshot_cache(&syntax, &snapshot_id, Some("source"), None)
            .unwrap();
        store
            .store_snapshot_cache(&semantic, &snapshot_id, Some("source"), None)
            .unwrap();

        store.start_scan("target", root.path(), false).unwrap();
        let hit = store
            .lookup_scan_cache(&syntax, &semantic, "target")
            .unwrap()
            .expect("semantic cache hit");
        assert_eq!(hit.snapshot_id(), snapshot_id);
        store
            .promote_validated_scan_cache_hit("target", &hit)
            .unwrap();

        let copied_rows: i64 = store
            .connection
            .query_row(
                "SELECT
                    (SELECT COUNT(*) FROM profiles WHERE scan_id='target')
                  + (SELECT COUNT(*) FROM nodes WHERE scan_id='target')
                  + (SELECT COUNT(*) FROM sites WHERE scan_id='target')
                  + (SELECT COUNT(*) FROM edges WHERE scan_id='target')
                  + (SELECT COUNT(*) FROM evidence WHERE scan_id='target')
                  + (SELECT COUNT(*) FROM diagnostics WHERE scan_id='target')
                  + (SELECT COUNT(*) FROM file_coverage WHERE scan_id='target')
                  + (SELECT COUNT(*) FROM coverage WHERE scan_id='target')
                  + (SELECT COUNT(*) FROM profile_coverage WHERE scan_id='target')
                  + (SELECT COUNT(*) FROM adapter_logs WHERE scan_id='target')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(copied_rows, 0);
        assert_eq!(
            store
                .snapshot_id_for_source("scan", "target")
                .unwrap()
                .as_deref(),
            Some(snapshot_id.as_str())
        );
        assert_eq!(
            store.latest_successful_id().unwrap().as_deref(),
            Some("target")
        );
        let source = store.load_snapshot("source").unwrap();
        let target = store.load_snapshot("target").unwrap();
        assert_eq!(source.profiles, target.profiles);
        assert_eq!(source.nodes, target.nodes);
        assert_eq!(source.sites, target.sites);
        assert_eq!(source.edges, target.edges);
        assert_eq!(source.evidence, target.evidence);
        assert_eq!(source.diagnostics, target.diagnostics);
        assert_eq!(source.file_coverage, target.file_coverage);
        assert_eq!(source.adapter_logs, target.adapter_logs);
        assert_eq!(source.coverage, target.coverage);
        let events = store.cache_events_for_scan("target").unwrap();
        assert!(events.iter().any(|event| {
            event.layer == CacheLayer::Syntax
                && event.outcome == "hit"
                && event.reason == "validated-by-semantic-cache"
        }));
        assert!(events.iter().any(|event| {
            event.layer == CacheLayer::Semantic
                && event.outcome == "hit"
                && event.reason == "validated"
        }));
    }

    #[test]
    fn cache_hit_precommit_failure_rolls_back_every_promotion_write() {
        let root = tempfile::tempdir().unwrap();
        let mut store = Store::open_in_memory().unwrap();
        let snapshot_id = complete_fixture_scan(&mut store, "source", root.path());
        let (syntax, semantic) = scan_cache_keys();
        store
            .store_snapshot_cache(&syntax, &snapshot_id, Some("source"), None)
            .unwrap();
        store
            .store_snapshot_cache(&semantic, &snapshot_id, Some("source"), None)
            .unwrap();

        store.start_scan("target", root.path(), false).unwrap();
        let hit = store
            .lookup_scan_cache(&syntax, &semantic, "target")
            .unwrap()
            .expect("semantic cache hit");
        let error = store
            .promote_validated_scan_cache_hit_with_precommit("target", &hit, || {
                anyhow::bail!("filesystem proof changed")
            })
            .unwrap_err();

        assert!(error.to_string().contains("pre-commit validation failed"));
        assert_eq!(store.scan("target").unwrap().unwrap().status, "staging");
        assert_eq!(
            store.snapshot_id_for_source("scan", "target").unwrap(),
            None
        );
        assert_eq!(
            store.current_snapshot_id().unwrap().as_deref(),
            Some(snapshot_id.as_str())
        );
    }

    #[test]
    fn validated_scan_cache_hit_rejects_an_intervening_database_write() {
        let root = tempfile::tempdir().unwrap();
        let database = root.path().join("cache-race.sqlite");
        let mut store = Store::open(&database).unwrap();
        let snapshot_id = complete_fixture_scan(&mut store, "source", root.path());
        let (syntax, semantic) = scan_cache_keys();
        store
            .store_snapshot_cache(&syntax, &snapshot_id, Some("source"), None)
            .unwrap();
        store
            .store_snapshot_cache(&semantic, &snapshot_id, Some("source"), None)
            .unwrap();

        store.start_scan("target", root.path(), false).unwrap();
        let hit = store
            .lookup_scan_cache(&syntax, &semantic, "target")
            .unwrap()
            .expect("semantic cache hit");
        let other = rusqlite::Connection::open(&database).unwrap();
        other
            .execute(
                "INSERT INTO cache_events(
                    scan_id, layer, cache_key, outcome, reason, created_at
                 ) VALUES ('target', 'semantic', NULL, 'miss', 'concurrent-write', ?1)",
                [now()],
            )
            .unwrap();

        let error = store
            .promote_validated_scan_cache_hit("target", &hit)
            .unwrap_err();
        assert!(error.to_string().contains("changed after validation"));
        assert_eq!(
            store.snapshot_id_for_source("scan", "target").unwrap(),
            None
        );
    }

    #[test]
    fn scan_cache_pair_rejects_corrupt_semantic_payload() {
        let root = tempfile::tempdir().unwrap();
        let mut store = Store::open_in_memory().unwrap();
        let snapshot_id = complete_fixture_scan(&mut store, "source", root.path());
        let (syntax, semantic) = scan_cache_keys();
        store
            .store_snapshot_cache(&syntax, &snapshot_id, Some("source"), None)
            .unwrap();
        store
            .store_snapshot_cache(&semantic, &snapshot_id, Some("source"), None)
            .unwrap();
        store
            .connection
            .execute(
                "UPDATE semantic_cache
                    SET payload_digest='cache-payload-reference:sha256:broken'
                  WHERE key=?1",
                [&semantic.key],
            )
            .unwrap();

        store
            .start_scan("corrupt-semantic", root.path(), false)
            .unwrap();
        assert!(
            store
                .lookup_scan_cache(&syntax, &semantic, "corrupt-semantic")
                .unwrap()
                .is_none()
        );
        let events = store.cache_events_for_scan("corrupt-semantic").unwrap();
        assert!(events.iter().any(|event| {
            event.layer == CacheLayer::Semantic
                && event.outcome == "reject"
                && event.reason == "payload-integrity-failed"
        }));
    }

    #[test]
    fn unknown_and_corrupt_cache_entries_fail_closed() {
        let root = tempfile::tempdir().unwrap();
        let mut store = Store::open_in_memory().unwrap();
        let snapshot_id = complete_fixture_scan(&mut store, "source", root.path());
        let key = cache_key(CacheLayer::Semantic, "sha256:semantic");
        store
            .store_snapshot_cache(&key, &snapshot_id, Some("source"), None)
            .unwrap();

        store
            .connection
            .execute(
                "UPDATE semantic_cache SET contract_version=999 WHERE key=?1",
                [&key.key],
            )
            .unwrap();
        store
            .start_scan("unknown-version", root.path(), false)
            .unwrap();
        let rejected = store
            .lookup_snapshot_cache(&key, Some("unknown-version"), None)
            .unwrap();
        assert_eq!(rejected.outcome, "reject");
        assert_eq!(rejected.reason, "unsupported-contract-version");

        store
            .connection
            .execute(
                "UPDATE semantic_cache
                    SET contract_version=?2, payload_digest='cache-payload:sha256:broken'
                  WHERE key=?1",
                params![key.key, CACHE_CONTRACT_VERSION],
            )
            .unwrap();
        store
            .start_scan("corrupt-payload", root.path(), false)
            .unwrap();
        let rejected = store
            .lookup_snapshot_cache(&key, Some("corrupt-payload"), None)
            .unwrap();
        assert_eq!(rejected.outcome, "reject");
        assert_eq!(rejected.reason, "payload-integrity-failed");

        let stale = cache_key(CacheLayer::Semantic, "sha256:changed-input");
        store.start_scan("stale-input", root.path(), false).unwrap();
        let miss = store
            .lookup_snapshot_cache(&stale, Some("stale-input"), None)
            .unwrap();
        assert_eq!(miss.outcome, "miss");
        assert_eq!(miss.reason, "not-found");
    }
}
