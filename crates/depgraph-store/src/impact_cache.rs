use std::time::Duration;

use anyhow::{Context, Result, bail};
use chrono::{SecondsFormat, Utc};
use depgraph_protocol::stable_id_from_value;
use rusqlite::{Connection, OptionalExtension, Params, params};
use serde_json::Value;

use super::Store;

pub const IMPACT_QUERY_CACHE_CONTRACT_VERSION: u32 = 1;
pub const IMPACT_QUERY_CACHE_MAX_ENTRIES: usize = 128;
pub const IMPACT_QUERY_CACHE_MAX_PAYLOAD_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug)]
struct StoredImpactQuery {
    contract_version: u32,
    snapshot_id: String,
    payload_json: String,
    payload_digest: String,
}

impl Store {
    pub fn lookup_impact_query_cache(
        &mut self,
        key: &str,
        snapshot_id: &str,
    ) -> Result<Option<String>> {
        validate_cache_identity(key, snapshot_id)?;
        let stored = {
            let mut statement = self
                .connection
                .prepare_cached(
                    "SELECT contract_version, snapshot_id, payload_json, payload_digest
                       FROM impact_query_cache
                      WHERE key=?1",
                )
                .context("failed to prepare impact query cache lookup")?;
            statement
                .query_row([key], |row| {
                    Ok(StoredImpactQuery {
                        contract_version: row.get(0)?,
                        snapshot_id: row.get(1)?,
                        payload_json: row.get(2)?,
                        payload_digest: row.get(3)?,
                    })
                })
                .optional()
                .context("failed to look up impact query cache entry")?
        };
        let Some(stored) = stored else {
            return Ok(None);
        };

        let valid = stored.contract_version == IMPACT_QUERY_CACHE_CONTRACT_VERSION
            && stored.snapshot_id == snapshot_id
            && stored.payload_json.len() <= IMPACT_QUERY_CACHE_MAX_PAYLOAD_BYTES
            && payload_digest(&stored.payload_json)
                .is_ok_and(|digest| digest == stored.payload_digest);
        if !valid {
            // Deletion is cache maintenance, so a concurrent writer must not
            // make the product query fail. Match the observed row to avoid
            // deleting a valid replacement stored after this read.
            best_effort_cache_write(
                &self.connection,
                "DELETE FROM impact_query_cache
                  WHERE key=?1
                    AND contract_version=?2
                    AND snapshot_id=?3
                    AND payload_json=?4
                    AND payload_digest=?5",
                params![
                    key,
                    stored.contract_version,
                    stored.snapshot_id,
                    stored.payload_json,
                    stored.payload_digest,
                ],
            );
            return Ok(None);
        }

        // Touch metadata is best-effort and deliberately uses its own
        // autocommit write. A concurrent CLI writer may hold SQLite's single
        // writer lock; the already validated cached result remains usable.
        best_effort_cache_write(
            &self.connection,
            "UPDATE impact_query_cache
                SET last_used_at=?2,
                    last_used_sequence=(
                        SELECT COALESCE(MAX(last_used_sequence), 0) + 1
                          FROM impact_query_cache
                    ),
                    hit_count=hit_count+1
              WHERE key=?1
                AND contract_version=?3
                AND snapshot_id=?4
                AND payload_json=?5
                AND payload_digest=?6",
            params![
                key,
                now(),
                stored.contract_version,
                stored.snapshot_id,
                stored.payload_json,
                stored.payload_digest,
            ],
        );
        Ok(Some(stored.payload_json))
    }

    pub fn store_impact_query_cache(
        &mut self,
        key: &str,
        snapshot_id: &str,
        payload_json: &str,
    ) -> Result<bool> {
        validate_cache_identity(key, snapshot_id)?;
        if payload_json.len() > IMPACT_QUERY_CACHE_MAX_PAYLOAD_BYTES {
            return Ok(false);
        }
        let digest = payload_digest(payload_json)?;
        let timestamp = now();
        let tx = self.connection.transaction()?;
        tx.execute(
            "INSERT INTO impact_query_cache(
                key, contract_version, snapshot_id, payload_json, payload_digest,
                created_at, last_used_at, last_used_sequence, hit_count
             ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?6,
                (
                    SELECT COALESCE(MAX(last_used_sequence), 0) + 1
                      FROM impact_query_cache
                ),
                0
             )
             ON CONFLICT(key) DO UPDATE SET
                contract_version=excluded.contract_version,
                snapshot_id=excluded.snapshot_id,
                payload_json=excluded.payload_json,
                payload_digest=excluded.payload_digest,
                last_used_at=excluded.last_used_at,
                last_used_sequence=excluded.last_used_sequence",
            params![
                key,
                IMPACT_QUERY_CACHE_CONTRACT_VERSION,
                snapshot_id,
                payload_json,
                digest,
                timestamp,
            ],
        )
        .context("failed to store impact query cache entry")?;
        tx.execute(
            "DELETE FROM impact_query_cache
              WHERE key IN (
                SELECT key
                  FROM impact_query_cache
                 ORDER BY last_used_sequence DESC, key DESC
                 LIMIT -1 OFFSET ?1
              )",
            [IMPACT_QUERY_CACHE_MAX_ENTRIES as i64],
        )
        .context("failed to prune impact query cache entries")?;
        tx.commit()?;
        Ok(true)
    }

    pub fn impact_query_cache_entry_count(&self) -> Result<u64> {
        self.connection
            .query_row("SELECT COUNT(*) FROM impact_query_cache", [], |row| {
                row.get(0)
            })
            .context("failed to count impact query cache entries")
    }
}

fn validate_cache_identity(key: &str, snapshot_id: &str) -> Result<()> {
    let Some(digest) = key.strip_prefix("impact-query:sha256:") else {
        bail!("impact query cache key has an invalid prefix");
    };
    if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("impact query cache key has an invalid digest");
    }
    if snapshot_id.trim().is_empty()
        || snapshot_id.len() > 256
        || snapshot_id.chars().any(char::is_control)
    {
        bail!("impact query cache snapshot identity is invalid");
    }
    Ok(())
}

fn payload_digest(payload_json: &str) -> Result<String> {
    let value: Value =
        serde_json::from_str(payload_json).context("impact query cache payload is invalid JSON")?;
    Ok(stable_id_from_value("impact-query-result", &value))
}

fn best_effort_cache_write<P: Params>(connection: &Connection, sql: &str, params: P) {
    let Ok(previous_timeout_ms) =
        connection.query_row("PRAGMA busy_timeout", [], |row| row.get::<_, u64>(0))
    else {
        return;
    };
    if connection.busy_timeout(Duration::ZERO).is_err() {
        return;
    }
    let _ = connection.execute(sql, params);
    let _ = connection.busy_timeout(Duration::from_millis(previous_timeout_ms));
}

fn now() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    fn seeded_store() -> Result<Store> {
        let store = Store::open_in_memory()?;
        store.connection.execute(
            "INSERT INTO scans(
                id, root, status, strict, started_at, completed_at,
                project_code_executed, protocol_version, error
             ) VALUES ('scan', '/repo', 'completed', 0, '2026-01-01T00:00:00Z',
                       '2026-01-01T00:00:01Z', 0, '1.0', NULL)",
            [],
        )?;
        store.connection.execute(
            "INSERT INTO completed_snapshots(
                id, source_kind, source_attempt_id, scan_id, build_attempt_id,
                runtime_import_id, runtime_session_set_json, parent_snapshot_id,
                source_revision, profile_set_json, status, created_at
             ) VALUES (
                'snapshot:sha256:test', 'scan', 'scan', 'scan', NULL, NULL,
                '[]', NULL, NULL, '[]', 'completed', '2026-01-01T00:00:01Z'
             )",
            [],
        )?;
        Ok(store)
    }

    fn key(index: usize) -> String {
        format!("impact-query:sha256:{index:064x}")
    }

    #[test]
    fn impact_query_cache_round_trips_and_uses_the_primary_key_plan() -> Result<()> {
        let mut store = seeded_store()?;
        let payload = r#"{"complete":true,"impacts":[]}"#;
        assert!(store.store_impact_query_cache(&key(1), "snapshot:sha256:test", payload)?);
        assert_eq!(
            store.lookup_impact_query_cache(&key(1), "snapshot:sha256:test")?,
            Some(payload.to_owned())
        );
        let (hit_count, last_used): (u64, String) = store.connection.query_row(
            "SELECT hit_count, last_used_at FROM impact_query_cache WHERE key=?1",
            [key(1)],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        assert_eq!(hit_count, 1);
        assert!(!last_used.is_empty());

        let mut plan = store.connection.prepare(
            "EXPLAIN QUERY PLAN
             SELECT payload_json FROM impact_query_cache WHERE key=?1",
        )?;
        let details = plan
            .query_map([key(1)], |row| row.get::<_, String>(3))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        assert!(
            details
                .iter()
                .any(|detail| detail.contains("sqlite_autoindex_impact_query_cache_1")),
            "{details:?}"
        );
        Ok(())
    }

    #[test]
    fn invalid_cached_payload_is_discarded_and_recomputed() -> Result<()> {
        let mut store = seeded_store()?;
        assert!(store.store_impact_query_cache(
            &key(1),
            "snapshot:sha256:test",
            r#"{"complete":true}"#
        )?);
        store.connection.execute(
            "UPDATE impact_query_cache SET payload_json='{\"complete\":false}' WHERE key=?1",
            [key(1)],
        )?;
        assert_eq!(
            store.lookup_impact_query_cache(&key(1), "snapshot:sha256:test")?,
            None
        );
        assert_eq!(store.impact_query_cache_entry_count()?, 0);
        Ok(())
    }

    #[test]
    fn concurrent_writer_does_not_block_a_valid_cache_hit() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("concurrent.db");
        let mut store = Store::open(&path)?;
        store.connection.execute(
            "INSERT INTO scans(
                id, root, status, strict, started_at, completed_at,
                project_code_executed, protocol_version, error
             ) VALUES ('scan', '/repo', 'completed', 0, '2026-01-01T00:00:00Z',
                       '2026-01-01T00:00:01Z', 0, '1.0', NULL)",
            [],
        )?;
        store.connection.execute(
            "INSERT INTO completed_snapshots(
                id, source_kind, source_attempt_id, scan_id, build_attempt_id,
                runtime_import_id, runtime_session_set_json, parent_snapshot_id,
                source_revision, profile_set_json, status, created_at
             ) VALUES (
                'snapshot:sha256:test', 'scan', 'scan', 'scan', NULL, NULL,
                '[]', NULL, NULL, '[]', 'completed', '2026-01-01T00:00:01Z'
             )",
            [],
        )?;
        let payload = r#"{"complete":true,"impacts":[]}"#;
        assert!(store.store_impact_query_cache(&key(1), "snapshot:sha256:test", payload)?);

        let writer = Connection::open(&path)?;
        writer.execute_batch(
            "PRAGMA foreign_keys=ON;
             PRAGMA journal_mode=WAL;
             BEGIN IMMEDIATE;",
        )?;
        let started = Instant::now();
        assert_eq!(
            store.lookup_impact_query_cache(&key(1), "snapshot:sha256:test")?,
            Some(payload.to_owned())
        );
        assert!(started.elapsed() < Duration::from_millis(500));
        writer.execute_batch("ROLLBACK;")?;
        Ok(())
    }

    #[test]
    fn impact_query_cache_is_bounded_by_entry_count_and_payload_size() -> Result<()> {
        let mut store = seeded_store()?;
        for index in 0..IMPACT_QUERY_CACHE_MAX_ENTRIES {
            assert!(store.store_impact_query_cache(
                &key(index),
                "snapshot:sha256:test",
                &format!(r#"{{"index":{index}}}"#),
            )?);
        }
        assert_eq!(
            store.impact_query_cache_entry_count()?,
            IMPACT_QUERY_CACHE_MAX_ENTRIES as u64
        );
        assert!(
            store
                .lookup_impact_query_cache(&key(0), "snapshot:sha256:test")?
                .is_some()
        );
        assert!(store.store_impact_query_cache(
            &key(IMPACT_QUERY_CACHE_MAX_ENTRIES),
            "snapshot:sha256:test",
            r#"{"newest":true}"#,
        )?);
        let (recently_used, oldest): (u64, u64) = store.connection.query_row(
            "SELECT
                SUM(CASE WHEN key=?1 THEN 1 ELSE 0 END),
                SUM(CASE WHEN key=?2 THEN 1 ELSE 0 END)
               FROM impact_query_cache",
            params![key(0), key(1)],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        assert_eq!(recently_used, 1);
        assert_eq!(oldest, 0);
        let oversized = format!("\"{}\"", "x".repeat(IMPACT_QUERY_CACHE_MAX_PAYLOAD_BYTES));
        assert!(!store.store_impact_query_cache(
            &key(IMPACT_QUERY_CACHE_MAX_ENTRIES + 1),
            "snapshot:sha256:test",
            &oversized,
        )?);
        assert_eq!(
            store.impact_query_cache_entry_count()?,
            IMPACT_QUERY_CACHE_MAX_ENTRIES as u64
        );
        Ok(())
    }

    #[test]
    fn schema_twelve_migrates_transactionally_to_the_query_cache_contract() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("schema-12.db");
        let connection = Connection::open(&path)?;
        connection.execute_batch(
            "CREATE TABLE completed_snapshots(id TEXT PRIMARY KEY);
             INSERT INTO completed_snapshots(id) VALUES ('snapshot:sha256:test');
             PRAGMA user_version = 12;",
        )?;
        drop(connection);

        let mut store = Store::open(&path)?;
        assert_eq!(store.schema_version()?, 13);
        assert!(store.store_impact_query_cache(
            &key(1),
            "snapshot:sha256:test",
            r#"{"complete":true}"#,
        )?);
        assert_eq!(store.impact_query_cache_entry_count()?, 1);
        Ok(())
    }
}
