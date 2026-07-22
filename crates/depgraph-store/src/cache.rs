use std::collections::BTreeMap;

use anyhow::{Context, Result, bail};
use chrono::{SecondsFormat, Utc};
use depgraph_protocol::stable_id_from_value;
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::{Store, ensure_scan_staging};

pub const CACHE_CONTRACT_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum CacheLayer {
    Syntax,
    Semantic,
    Build,
}

impl CacheLayer {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Syntax => "syntax",
            Self::Semantic => "semantic",
            Self::Build => "build",
        }
    }

    const fn table(self) -> &'static str {
        match self {
            Self::Syntax => "syntax_cache",
            Self::Semantic => "semantic_cache",
            Self::Build => "build_cache",
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
}

#[derive(Debug)]
struct StoredCacheEntry {
    contract_version: u32,
    dimensions_json: String,
    snapshot_id: String,
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
        })
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
            (Some(_), None) if layer != CacheLayer::Build => {}
            (None, Some(_)) if layer == CacheLayer::Build => {}
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
        let payload_digest = self.cache_payload_digest(key.layer, snapshot_id)?;
        if let Some(existing) = load_cache_entry(&self.connection, key.layer, &key.key)?
            && existing.contract_version == CACHE_CONTRACT_VERSION
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
        let source_scan_id = self
            .completed_snapshot(snapshot_id)?
            .context("validated cache snapshot disappeared")?
            .scan_id;
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

    fn validate_snapshot_for_layer(&self, layer: CacheLayer, snapshot_id: &str) -> Result<()> {
        let snapshot = self
            .completed_snapshot(snapshot_id)?
            .with_context(|| format!("cache snapshot {snapshot_id} was not found"))?;
        let expected_source = if layer == CacheLayer::Build {
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
        if layer == CacheLayer::Syntax {
            let snapshot = self
                .completed_snapshot(snapshot_id)?
                .context("syntax cache snapshot was not found")?;
            return Ok(stable_id_from_value(
                "syntax-cache-payload",
                &json!({
                    "schema": "syntax-cache-provenance-v1",
                    "source_kind": snapshot.source_kind,
                    "status": snapshot.status,
                }),
            ));
        }
        let snapshot = self.load_completed_snapshot(snapshot_id)?;
        Ok(stable_id_from_value(
            "cache-payload",
            &json!({
                "schema": "cache-payload-v1",
                "profiles": snapshot.profiles,
                "nodes": snapshot.nodes,
                "sites": snapshot.sites,
                "edges": snapshot.edges,
                "evidence": snapshot.evidence,
                "diagnostics": snapshot.diagnostics,
                "file_coverage": snapshot.file_coverage,
                "coverage": snapshot.coverage,
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
        (Some(_), None) if layer != CacheLayer::Build => Ok(()),
        (None, Some(_)) if layer == CacheLayer::Build => Ok(()),
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
                build: 0
            }
        );
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
